use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct HiddenFileFinding {
    pub path: PathBuf,
    pub reason: String,
}

/// Détecte les fichiers cachés dans des emplacements où ce n'est pas normal
/// (Téléchargements, Bureau, racine d'une clé USB) — technique fréquente
/// pour dissimuler un exécutable malveillant à l'utilisateur — ainsi que
/// les flux de données alternatifs NTFS (Alternate Data Streams), utilisés
/// pour cacher du contenu exécutable "attaché" à un fichier anodin.
pub async fn scan_hidden_files(root: &Path) -> Result<Vec<HiddenFileFinding>> {
    let mut findings = Vec::new();

    for entry in walkdir::WalkDir::new(root)
        .max_depth(6)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();

        if is_hidden(path).await && looks_suspicious(path) {
            findings.push(HiddenFileFinding {
                path: path.to_path_buf(),
                reason: "fichier caché dans un dossier utilisateur normal".to_string(),
            });
        }

        if let Some(streams) = list_alternate_data_streams(path).await {
            for stream in streams {
                findings.push(HiddenFileFinding {
                    path: path.to_path_buf(),
                    reason: format!("flux de données alternatif détecté: {stream}"),
                });
            }
        }
    }

    Ok(findings)
}

#[cfg(windows)]
async fn is_hidden(path: &Path) -> bool {
    use windows::Win32::Storage::FileSystem::{GetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, INVALID_FILE_ATTRIBUTES};
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let attrs = unsafe { GetFileAttributesW(windows::core::PCWSTR(wide.as_ptr())) };
    attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_HIDDEN.0) != 0
}

#[cfg(not(windows))]
async fn is_hidden(_path: &Path) -> bool {
    false
}

/// Un fichier caché n'est pas automatiquement malveillant (beaucoup de
/// fichiers système légitimes le sont). On ne signale que les cas où un
/// exécutable/script est caché dans un dossier destiné à l'utilisateur.
fn looks_suspicious(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let executable_ext = ["exe", "scr", "bat", "cmd", "vbs", "js", "ps1", "com"];
    if !executable_ext.contains(&ext.as_str()) {
        return false;
    }
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("\\desktop\\")
        || path_str.contains("\\downloads\\")
        || path_str.contains("\\documents\\")
        || is_removable_root(path)
}

fn is_removable_root(path: &Path) -> bool {
    // Racine d'un volume amovible: peu de composants dans le chemin.
    path.components().count() <= 2
}

/// Liste les flux de données alternatifs (`fichier.txt:stream`) via
/// `dir /r`, seule méthode fiable en user-space sans API NTFS bas niveau.
#[cfg(windows)]
async fn list_alternate_data_streams(path: &Path) -> Option<Vec<String>> {
    let output = Command::new("cmd")
        .args(["/C", "dir", "/r", &path.to_string_lossy()])
        .output()
        .await
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let streams: Vec<String> = text
        .lines()
        .filter(|l| l.contains(":$DATA") && !l.trim_end().ends_with(":$DATA")) // exclut le flux principal ::$DATA
        .map(|l| l.trim().to_string())
        .collect();

    if streams.is_empty() {
        None
    } else {
        Some(streams)
    }
}

#[cfg(not(windows))]
async fn list_alternate_data_streams(_path: &Path) -> Option<Vec<String>> {
    None
}
