use anyhow::Result;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

/// Surveille l'apparition de nouveaux volumes amovibles (clés USB, disques
/// externes) et notifie le canal fourni pour déclencher un scan complet.
///
/// Implémentation par sondage périodique des lettres de lecteur (simple et
/// fiable, fonctionne entièrement hors ligne). Une variante événementielle
/// via `RegisterDeviceNotification` est possible en évolution si une latence
/// plus faible est nécessaire.
pub fn watch_usb_insertions(tx: UnboundedSender<std::path::PathBuf>) {
    tokio::spawn(async move {
        let mut known = list_removable_drives();
        tracing::info!(count = known.len(), "surveillance USB démarrée");

        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let current = list_removable_drives();

            for drive in &current {
                if !known.contains(drive) {
                    tracing::warn!(drive = %drive.display(), "nouveau volume amovible détecté, scan déclenché");
                    let _ = tx.send(drive.clone());
                }
            }
            known = current;
        }
    });
}

#[cfg(windows)]
fn list_removable_drives() -> Vec<std::path::PathBuf> {
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;

    const DRIVE_REMOVABLE: u32 = 2;

    let mut drives = Vec::new();
    for letter in b'A'..=b'Z' {
        let root = format!("{}:\\", letter as char);
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(wide.as_ptr())) };
        if drive_type == DRIVE_REMOVABLE {
            drives.push(std::path::PathBuf::from(root));
        }
    }
    drives
}

#[cfg(not(windows))]
fn list_removable_drives() -> Vec<std::path::PathBuf> {
    Vec::new()
}

pub async fn scan_and_report(
    scanner: &crate::scanner::LocalScanner,
    quarantine: &crate::quarantine::Quarantine,
    audit: &crate::audit_log::AuditLog,
    response_mode: &crate::config::ResponseMode,
    root: &std::path::Path,
) -> Result<usize> {
    // 1. Neutralise tout autorun.inf (protection anti-ver en priorité,
    //    avant même le scan de contenu) — toujours actif, même en mode
    //    alerte seule : neutraliser un autorun.inf n'a aucun risque de
    //    faux positif dommageable (il n'a plus d'usage légitime).
    if let Ok(true) = crate::autorun_guard::AutorunGuard::scan_and_neutralize(root).await {
        tracing::warn!(volume = %root.display(), "autorun.inf neutralisé sur ce volume");
        audit.record(&crate::audit_log::AuditEntry {
            action: "autorun_neutralized".to_string(),
            target: root.display().to_string(),
            reason: "autorun.inf détecté sur support amovible".to_string(),
            response_mode: format!("{:?}", response_mode),
            timestamp: crate::audit_log::now_unix(),
        });
    }

    // 2. Scan de signatures classique (YARA + hashes).
    let results = scanner.scan_volume(root).await;
    let mut quarantined = 0;

    for r in &results {
        if !matches!(r.verdict, crate::scanner::Verdict::Clean) {
            let reason = match &r.verdict {
                crate::scanner::Verdict::KnownMalicious => "hash connu comme malveillant".to_string(),
                crate::scanner::Verdict::Suspicious(rule) => format!("règle YARA: {rule}"),
                crate::scanner::Verdict::Clean => unreachable!(),
            };

            if *response_mode == crate::config::ResponseMode::AlertOnly {
                audit.record(&crate::audit_log::AuditEntry {
                    action: "detection_alert_only".to_string(),
                    target: r.path.display().to_string(),
                    reason,
                    response_mode: "AlertOnly".to_string(),
                    timestamp: crate::audit_log::now_unix(),
                });
                continue;
            }

            if quarantine.quarantine_file(&r.path, &reason).await.is_ok() {
                quarantined += 1;
                audit.record(&crate::audit_log::AuditEntry {
                    action: "quarantine".to_string(),
                    target: r.path.display().to_string(),
                    reason,
                    response_mode: format!("{:?}", response_mode),
                    timestamp: crate::audit_log::now_unix(),
                });
            }
        }
    }

    // 3. Fichiers cachés suspects (exécutables dissimulés à la racine, ADS).
    if let Ok(hidden) = crate::hidden_files::scan_hidden_files(root).await {
        for finding in &hidden {
            tracing::warn!(path = %finding.path.display(), reason = %finding.reason, "fichier suspect détecté sur support amovible");
        }
    }

    tracing::info!(volume = %root.display(), scanned = results.len(), quarantined, "scan USB terminé");
    Ok(quarantined)
}
