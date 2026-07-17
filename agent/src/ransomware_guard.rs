use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

use crate::audit_log::{AuditEntry, AuditLog};
use crate::config::{Allowlist, ResponseMode};
use crate::firewall::FirewallManager;
use shared::{EventType, FileEvent, Severity};

/// Détection comportementale de ransomware par fichiers-leurres (honeypots)
/// et par débit anormal de modifications de fichiers — approche standard
/// des suites de sécurité (Kaspersky System Watcher, Windows Controlled
/// Folder Access fonctionnent sur le même principe), entièrement locale.
pub struct RansomwareGuard {
    canary_paths: Vec<PathBuf>,
    canary_hashes: HashMap<PathBuf, String>,
    /// Fenêtre glissante des modifications récentes pour détecter un débit
    /// anormal (signature typique d'un chiffrement de masse).
    recent_modifications: Vec<Instant>,
    response_mode: ResponseMode,
    allowlist: Allowlist,
    kill_window: Duration,
    audit: Arc<AuditLog>,
}

const BURST_THRESHOLD: usize = 20; // fichiers modifiés
const BURST_WINDOW: Duration = Duration::from_secs(10);

impl RansomwareGuard {
    /// Dépose des fichiers-leurres dans les dossiers surveillés (Documents,
    /// Bureau, etc.). Ils ont un nom neutre et un contenu factice ; un
    /// ransomware qui chiffre indistinctement un dossier les touchera en
    /// premier, révélant l'attaque avant qu'elle n'atteigne les vrais
    /// fichiers de l'utilisateur.
    pub async fn deploy_canaries(
        watched_dirs: &[PathBuf],
        response_mode: ResponseMode,
        allowlist: Allowlist,
        kill_window: Duration,
        audit: Arc<AuditLog>,
    ) -> Result<Self> {
        let mut canary_paths = Vec::new();
        let mut canary_hashes = HashMap::new();

        for dir in watched_dirs {
            if !dir.exists() {
                continue;
            }
            for i in 0..3 {
                let name = format!("~ironshield_{i:02}.docx");
                let path = dir.join(&name);
                let content = canary_content();
                if tokio::fs::write(&path, &content).await.is_ok() {
                    hide_file(&path).await.ok();
                    let hash = hash_bytes(&content);
                    canary_hashes.insert(path.clone(), hash);
                    canary_paths.push(path);
                }
            }
        }

        tracing::info!(count = canary_paths.len(), "fichiers-leurres anti-ransomware déployés");
        Ok(Self {
            canary_paths,
            canary_hashes,
            recent_modifications: Vec::new(),
            response_mode,
            allowlist,
            kill_window,
            audit,
        })
    }

    pub fn is_canary(&self, path: &Path) -> bool {
        self.canary_paths.iter().any(|c| c == path)
    }

    /// À appeler pour chaque événement FIM. Retourne `true` si une réponse
    /// d'urgence (verrouillage réseau + alerte critique) a été déclenchée.
    pub async fn record_event_and_check(&mut self, event: &FileEvent, alert_tx: &UnboundedSender<FileEvent>) -> bool {
        let path = Path::new(&event.path);

        // Un chemin explicitement en liste blanche (logiciel métier connu
        // pour déclencher des faux positifs) ne compte jamais comme signal,
        // même s'il touche un leurre par malchance de nommage.
        if self.allowlist.allows_path(&event.path) {
            return false;
        }

        // Cas 1 : un leurre a été touché = signal fort et quasi certain.
        if self.is_canary(path) {
            tracing::error!(path = %event.path, "fichier-leurre modifié — activité de type ransomware détectée");
            self.trigger_emergency_response(alert_tx, "fichier-leurre modifié").await;
            return true;
        }

        // Cas 2 : débit anormal de modifications, même sans toucher un leurre
        // (l'attaquant a pu cibler un dossier ne contenant pas de leurre).
        if matches!(event.event_type, EventType::Modified | EventType::Renamed) {
            let now = Instant::now();
            self.recent_modifications.push(now);
            self.recent_modifications.retain(|t| now.duration_since(*t) < BURST_WINDOW);

            if self.recent_modifications.len() >= BURST_THRESHOLD {
                tracing::error!(
                    count = self.recent_modifications.len(),
                    "débit de modification anormal détecté — verrouillage préventif"
                );
                self.trigger_emergency_response(alert_tx, "débit de modification anormal").await;
                self.recent_modifications.clear();
                return true;
            }
        }

        false
    }

    async fn trigger_emergency_response(&self, alert_tx: &UnboundedSender<FileEvent>, reason: &str) {
        let mode_str = format!("{:?}", self.response_mode);

        // Le mode par défaut (AlertOnly) ne fait QUE journaliser et
        // alerter : c'est le comportement voulu tant qu'un parc n'a pas
        // été validé sans faux positif. Un kill-switch automatique par
        // défaut sur un produit jamais testé en conditions réelles cause
        // plus de dégâts que le ransomware qu'il combat.
        self.audit.record(&AuditEntry {
            action: "ransomware_detected".to_string(),
            target: "N/A".to_string(),
            reason: reason.to_string(),
            response_mode: mode_str.clone(),
            timestamp: crate::audit_log::now_unix(),
        });

        if self.response_mode == ResponseMode::AlertOnly {
            tracing::warn!(reason, "détection ransomware en mode alerte seule — aucune action automatique");
        } else {
            // Coupe le réseau (empêche exfiltration de clé / C2), sans
            // bloquer l'alerte vers IronShield.
            match FirewallManager::emergency_lockdown("wiseshield.alwaysdata.net").await {
                Ok(_) => self.audit.record(&AuditEntry {
                    action: "network_lockdown".to_string(),
                    target: "all_outbound".to_string(),
                    reason: reason.to_string(),
                    response_mode: mode_str.clone(),
                    timestamp: crate::audit_log::now_unix(),
                }),
                Err(e) => tracing::warn!(error = %e, "échec du verrouillage réseau d'urgence (peut-être hors ligne)"),
            }
        }

        if self.response_mode == ResponseMode::Full {
            // Termine les processus suspects récents — la réponse
            // "musclée", en respectant la liste blanche du client.
            match crate::process_killer::kill_recent_suspicious_processes(self.kill_window, &self.allowlist).await {
                Ok(killed) if !killed.is_empty() => {
                    tracing::error!(processes = ?killed, "processus suspects terminés en réponse au ransomware");
                    for p in &killed {
                        self.audit.record(&AuditEntry {
                            action: "kill_process".to_string(),
                            target: p.clone(),
                            reason: reason.to_string(),
                            response_mode: mode_str.clone(),
                            timestamp: crate::audit_log::now_unix(),
                        });
                    }
                }
                Ok(_) => tracing::warn!("aucun processus récent à terminer"),
                Err(e) => tracing::error!(error = %e, "échec de la terminaison des processus suspects"),
            }
        }

        let alert = FileEvent {
            path: "RANSOMWARE_BEHAVIOR_DETECTED".to_string(),
            event_type: EventType::Modified,
            sha256: None,
            severity: Severity::Critical,
            timestamp: now_ts(),
        };
        let _ = alert_tx.send(alert);
    }

    /// Vérifie l'intégrité des leurres (à appeler périodiquement en
    /// complément de la surveillance événementielle, au cas où un
    /// événement aurait été manqué).
    pub async fn verify_canaries(&self) -> bool {
        for (path, expected_hash) in &self.canary_hashes {
            match tokio::fs::read(path).await {
                Ok(content) if hash_bytes(&content) != *expected_hash => return true,
                Err(_) => return true, // supprimé ou renommé
                _ => {}
            }
        }
        false
    }
}

fn canary_content() -> Vec<u8> {
    // Contenu factice mais réaliste (empreinte DOCX minimale n'est pas
    // nécessaire : seul le fait d'être touché compte pour la détection).
    b"IronShield FIM - fichier de detection - ne pas supprimer".to_vec()
}

fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(windows)]
async fn hide_file(path: &Path) -> Result<()> {
    use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM};
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        SetFileAttributesW(
            windows::core::PCWSTR(wide.as_ptr()),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        )?;
    }
    Ok(())
}

#[cfg(not(windows))]
async fn hide_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
