use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[derive(Debug, Serialize, Clone)]
pub struct PupFinding {
    pub category: String, // "hosts", "browser_extension", "shortcut", "registry", "proxy"
    pub description: String,
    pub location: String,
    pub auto_fixed: bool,
}

/// Motifs de dénomination fréquents chez les PUP (barres d'outils,
/// "optimiseurs", faux nettoyeurs) — liste volontairement large plutôt
/// qu'un moteur de signatures dédié, pour rester simple et transparent.
const PUP_NAME_PATTERNS: &[&str] = &[
    "coupon", "savings", "dealspot", "toolbar", "pcoptimizer", "driverupdater",
    "systemspeedup", "mypcbackup", "webdiscover", "searchprotect", "browserassistant",
];

/// Lance un nettoyage complet type AdwCleaner/Malwarebytes AdwCleaner :
/// hosts, navigateurs, raccourcis, registre. Chaque étape journalise ce
/// qu'elle a trouvé/corrigé ; rien n'est supprimé de façon irréversible
/// sans trace (voir `PupFinding.auto_fixed`).
pub async fn run_full_scan() -> Result<Vec<PupFinding>> {
    let mut findings = Vec::new();
    findings.extend(check_hosts_file().await.unwrap_or_default());
    findings.extend(scan_browser_extensions().await.unwrap_or_default());
    findings.extend(scan_shortcuts_for_hijack().await.unwrap_or_default());
    findings.extend(scan_pup_registry_entries().await.unwrap_or_default());
    findings.extend(check_proxy_hijack().await.unwrap_or_default());
    findings
        .iter()
        .for_each(|f| tracing::warn!(category = %f.category, location = %f.location, "PUP/adware: {}", f.description));
    Ok(findings)
}

/// Vérifie le fichier HOSTS pour des redirections malveillantes (technique
/// classique d'adware/hijacker pour rediriger des domaines de sécurité ou
/// des moteurs de recherche).
async fn check_hosts_file() -> Result<Vec<PupFinding>> {
    let hosts_path = PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts");
    let content = tokio::fs::read_to_string(&hosts_path).await.unwrap_or_default();
    let mut findings = Vec::new();
    let mut clean_lines = Vec::new();
    let mut modified = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            clean_lines.push(line.to_string());
            continue;
        }
        let is_suspicious = SECURITY_DOMAINS.iter().any(|d| trimmed.contains(d))
            || (trimmed.contains("google") && !trimmed.starts_with("127.0.0.1"))
            || (trimmed.contains("bing") && !trimmed.starts_with("127.0.0.1"));

        if is_suspicious {
            findings.push(PupFinding {
                category: "hosts".to_string(),
                description: format!("redirection suspecte neutralisée: {trimmed}"),
                location: hosts_path.display().to_string(),
                auto_fixed: true,
            });
            modified = true;
            // ligne commentée plutôt que supprimée : trace conservée
            clean_lines.push(format!("# [IronShield] neutralisé: {trimmed}"));
        } else {
            clean_lines.push(line.to_string());
        }
    }

    if modified {
        let _ = tokio::fs::write(&hosts_path, clean_lines.join("\n")).await;
    }

    Ok(findings)
}

const SECURITY_DOMAINS: &[&str] = &[
    "windowsupdate.com", "microsoft.com", "avast.com", "kaspersky.com",
    "malwarebytes.com", "virustotal.com", "wiseos.alwaysdata.net",
];

/// Scanne les extensions Chrome/Edge installées et signale celles qui
/// combinent permissions larges (`<all_urls>`, `webRequest`) et nom/éditeur
/// non renseigné — profil typique d'une extension adware.
async fn scan_browser_extensions() -> Result<Vec<PupFinding>> {
    let mut findings = Vec::new();
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
    if local_app_data.is_empty() {
        return Ok(findings);
    }

    let browser_ext_dirs = [
        (format!(r"{local_app_data}\Google\Chrome\User Data\Default\Extensions"), "Chrome"),
        (format!(r"{local_app_data}\Microsoft\Edge\User Data\Default\Extensions"), "Edge"),
    ];

    for (dir, browser) in browser_ext_dirs {
        let Ok(mut entries) = tokio::fs::read_dir(&dir).await else { continue };
        while let Ok(Some(ext_dir)) = entries.next_entry().await {
            let ext_id = ext_dir.file_name().to_string_lossy().to_string();
            if let Some(manifest) = find_manifest(&ext_dir.path()).await {
                if is_suspicious_manifest(&manifest) {
                    findings.push(PupFinding {
                        category: "browser_extension".to_string(),
                        description: format!("extension {browser} avec permissions larges et nom générique (ID {ext_id})"),
                        location: ext_dir.path().display().to_string(),
                        auto_fixed: false, // désinstallation laissée à l'utilisateur/admin (évite de casser un usage légitime)
                    });
                }
            }
        }
    }

    Ok(findings)
}

async fn find_manifest(ext_version_dir: &Path) -> Option<String> {
    let mut entries = tokio::fs::read_dir(ext_version_dir).await.ok()?;
    while let Ok(Some(version_dir)) = entries.next_entry().await {
        let manifest_path = version_dir.path().join("manifest.json");
        if let Ok(content) = tokio::fs::read_to_string(&manifest_path).await {
            return Some(content);
        }
    }
    None
}

fn is_suspicious_manifest(manifest: &str) -> bool {
    let lower = manifest.to_lowercase();
    let broad_permissions = lower.contains("\"<all_urls>\"") || lower.contains("webrequest");
    let generic_or_empty_name = !lower.contains("\"name\"")
        || lower.contains("\"name\": \"__msg_")
        || lower.contains("\"description\": \"\"");
    broad_permissions && generic_or_empty_name
}

/// Détecte les raccourcis (.lnk) détournés — cible modifiée pour ouvrir un
/// navigateur avec une URL/extension imposée, technique fréquente de
/// hijacking de moteur de recherche.
async fn scan_shortcuts_for_hijack() -> Result<Vec<PupFinding>> {
    let mut findings = Vec::new();
    let desktop = std::env::var("USERPROFILE").map(|u| format!(r"{u}\Desktop")).unwrap_or_default();
    if desktop.is_empty() {
        return Ok(findings);
    }

    let Ok(mut entries) = tokio::fs::read_dir(&desktop).await else { return Ok(findings) };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("lnk") {
            continue;
        }
        if let Some(target) = read_shortcut_target(&path).await {
            let lower = target.to_lowercase();
            let is_browser = ["chrome.exe", "msedge.exe", "firefox.exe"].iter().any(|b| lower.contains(b));
            let has_forced_url = lower.contains("http://") || lower.contains("https://");

            if is_browser && has_forced_url {
                findings.push(PupFinding {
                    category: "shortcut".to_string(),
                    description: format!("raccourci navigateur détourné avec une URL imposée: {target}"),
                    location: path.display().to_string(),
                    auto_fixed: false,
                });
            }
        }
    }

    Ok(findings)
}

/// Lit la cible d'un raccourci via PowerShell/COM (`WScript.Shell`) — seule
/// méthode fiable en user-space sans parser le format binaire `.lnk`.
async fn read_shortcut_target(path: &Path) -> Option<String> {
    let script = format!(
        "(New-Object -ComObject WScript.Shell).CreateShortcut('{}').TargetPath + ' ' + (New-Object -ComObject WScript.Shell).CreateShortcut('{}').Arguments",
        path.display(),
        path.display()
    );
    let output = Command::new("powershell").args(["-NoProfile", "-Command", &script]).output().await.ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// Recherche dans les clés de démarrage et la liste des programmes
/// installés des noms correspondant à des motifs PUP connus.
async fn scan_pup_registry_entries() -> Result<Vec<PupFinding>> {
    let mut findings = Vec::new();
    let output = Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "/s"])
        .output()
        .await;
    let Ok(output) = output else { return Ok(findings) };
    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();

    for pattern in PUP_NAME_PATTERNS {
        if text.contains(pattern) {
            findings.push(PupFinding {
                category: "registry".to_string(),
                description: format!("programme correspondant au motif PUP connu: '{pattern}'"),
                location: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".to_string(),
                auto_fixed: false, // désinstallation via le panneau de config, pas de suppression forcée de registre
            });
        }
    }

    Ok(findings)
}

/// Vérifie que les paramètres de proxy système n'ont pas été détournés
/// (technique adware pour intercepter/injecter du trafic HTTP).
async fn check_proxy_hijack() -> Result<Vec<PupFinding>> {
    let mut findings = Vec::new();
    let output = Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v", "ProxyEnable",
        ])
        .output()
        .await;

    if let Ok(output) = output {
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("0x1") {
            findings.push(PupFinding {
                category: "proxy".to_string(),
                description: "proxy système activé — à vérifier s'il n'a pas été configuré par un adware".to_string(),
                location: r"HKCU\...\Internet Settings\ProxyEnable".to_string(),
                auto_fixed: false, // désactivation automatique risquée si le proxy est légitime (entreprise)
            });
        }
    }

    Ok(findings)
}
