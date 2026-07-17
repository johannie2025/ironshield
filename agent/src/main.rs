mod api_client;
mod audit_log;
mod autorun_guard;
mod config;
mod firewall;
mod hasher;
mod hidden_files;
mod license;
mod offline_queue;
mod persistence_scan;
mod process_killer;
mod pup_cleaner;
mod quarantine;
mod ransomware_guard;
mod scanner;
mod self_protect;
mod usb_watcher;
mod watcher;

use anyhow::Result;
use api_client::ApiClient;
use config::AgentConfig;
use offline_queue::OfflineQueue;
use quarantine::Quarantine;
use scanner::LocalScanner;
use shared::FileEvent;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Mode watchdog : ce binaire peut aussi tourner en surveillant du
    // processus principal (voir self_protect.rs).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--watchdog") {
        let exe = std::env::current_exe()?;
        let pid_file = exe.with_extension("pid");
        return self_protect::run_watchdog_mode(exe, pid_file).await;
    }

    tracing::info!("IronShield FIM Agent démarrage — v{}", env!("CARGO_PKG_VERSION"));

    let mut cfg = AgentConfig::load_or_default()?;
    write_pid_file()?;

    let data_dir = agent_data_dir()?;
    let signatures_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&signatures_dir)?;

    // --- Journal d'audit : trace toute action automatique (support/litige) ---
    let audit = Arc::new(audit_log::AuditLog::open(data_dir.join("audit.db"))?);
    tracing::info!(mode = ?cfg.response_mode, "mode de réponse actif");

    // --- Moteur de scan local : opérationnel immédiatement, sans réseau ---
    let scanner = Arc::new(LocalScanner::load(&signatures_dir, cfg.allowlist.clone())?);

    let quarantine_key = derive_quarantine_key()?;
    let quarantine = Arc::new(Quarantine::open(data_dir.join("quarantine"), quarantine_key)?);

    // --- File d'événements locale : l'agent reste utile hors ligne ---
    let queue = Arc::new(OfflineQueue::open(data_dir.join("events.db"))?);

    // --- Auto-surveillance user-space (best effort, voir self_protect.rs) ---
    self_protect::spawn_watchdog(std::env::current_exe()?).await?;

    // --- Anti-ransomware : fichiers-leurres dans les dossiers surveillés ---
    let watched_dirs: Vec<PathBuf> = cfg.watched_paths.iter().map(PathBuf::from).collect();
    let ransomware_guard = Arc::new(tokio::sync::Mutex::new(
        ransomware_guard::RansomwareGuard::deploy_canaries(
            &watched_dirs,
            cfg.response_mode.clone(),
            cfg.allowlist.clone(),
            std::time::Duration::from_secs(cfg.ransomware_kill_window_secs),
            audit.clone(),
        )
        .await?,
    ));

    // --- Anti-ver : désactive l'autorun Windows (une fois, idempotent) ---
    if let Err(e) = autorun_guard::AutorunGuard::disable_system_autorun().await {
        tracing::warn!(error = %e, "désactivation autorun échouée (droits insuffisants ?)");
    }

    // --- Nettoyage PUP/adware type AdwCleaner : au démarrage puis toutes les 12h ---
    {
        let queue = queue.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));
            loop {
                match pup_cleaner::run_full_scan().await {
                    Ok(findings) if !findings.is_empty() => {
                        tracing::warn!(count = findings.len(), "éléments PUP/adware détectés");
                        for f in findings {
                            let event = FileEvent {
                                path: format!("{}: {}", f.category, f.location),
                                event_type: shared::EventType::Modified,
                                sha256: None,
                                severity: if f.auto_fixed { shared::Severity::Warning } else { shared::Severity::Info },
                                timestamp: unix_now(),
                            };
                            let _ = queue.enqueue(&event);
                        }
                    }
                    Ok(_) => tracing::info!("aucun PUP/adware détecté"),
                    Err(e) => tracing::debug!(error = %e, "scan PUP ignoré"),
                }
                interval.tick().await;
            }
        });
    }

    // --- Audit de persistance au démarrage (Run keys, tâches planifiées) ---
    {
        let queue = queue.clone();
        tokio::spawn(async move {
            match persistence_scan::scan_persistence().await {
                Ok(entries) => {
                    let suspicious: Vec<_> = entries.iter().filter(|e| e.suspicious).collect();
                    if !suspicious.is_empty() {
                        tracing::warn!(count = suspicious.len(), "entrées de démarrage suspectes détectées");
                    }
                    for entry in suspicious {
                        let event = FileEvent {
                            path: format!("{}: {}", entry.source, entry.name),
                            event_type: shared::EventType::Modified,
                            sha256: None,
                            severity: shared::Severity::Warning,
                            timestamp: unix_now(),
                        };
                        let _ = queue.enqueue(&event);
                    }
                }
                Err(e) => tracing::debug!(error = %e, "audit de persistance ignoré"),
            }
        });
    }

    // --- Client API : uniquement utilisé quand une connexion est dispo ---
    let client = ApiClient::new(cfg.api_base_url.clone());

    // L'activation de licence nécessite une première connexion ; une fois
    // le token obtenu, il est mis en cache et l'agent peut fonctionner
    // hors ligne indéfiniment pour la détection (seul l'envoi des
    // événements et les mises à jour de signatures nécessitent le réseau).
    let token = match license::ensure_activated(&mut cfg, &client).await {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::warn!(error = %e, "activation impossible (hors ligne ?) — l'agent démarre en mode détection locale uniquement");
            None
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<FileEvent>();

    for path in &cfg.watched_paths {
        let dir = PathBuf::from(path);
        if !dir.exists() {
            tracing::warn!(path = %dir.display(), "chemin surveillé introuvable, ignoré");
            continue;
        }
        watcher::watch_directory(dir.clone(), tx.clone())?;
        tracing::info!(path = %dir.display(), "surveillance démarrée");
    }

    // --- Scan USB automatique à l'insertion ---
    let (usb_tx, mut usb_rx) = mpsc::unbounded_channel::<PathBuf>();
    usb_watcher::watch_usb_insertions(usb_tx);
    {
        let scanner = scanner.clone();
        let quarantine = quarantine.clone();
        let audit = audit.clone();
        let response_mode = cfg.response_mode.clone();
        tokio::spawn(async move {
            while let Some(volume) = usb_rx.recv().await {
                let _ = usb_watcher::scan_and_report(&scanner, &quarantine, &audit, &response_mode, &volume).await;
            }
        });
    }

    // --- Sync réseau périodique (best effort, ne bloque jamais la détection locale) ---
    {
        let queue = queue.clone();
        let client = ApiClient::new(cfg.api_base_url.clone());
        let token_for_sync = token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let Some(token) = &token_for_sync else { continue };
                if let Err(e) = sync_pending_events(&queue, &client, token).await {
                    tracing::debug!(error = %e, "sync réseau indisponible, nouvelle tentative plus tard");
                }
                if let Err(e) = sync_remote_allowlist(&client, token).await {
                    tracing::debug!(error = %e, "sync de la config distante indisponible");
                }
            }
        });
    }

    drop(tx);

    // Canal dédié: les alertes d'urgence anti-ransomware sont journalisées
    // immédiatement dans la file locale, indépendamment du flux FIM normal.
    let (ransomware_alert_tx, mut ransomware_alert_rx) = mpsc::unbounded_channel::<FileEvent>();
    {
        let queue = queue.clone();
        tokio::spawn(async move {
            while let Some(event) = ransomware_alert_rx.recv().await {
                let _ = queue.enqueue(&event);
            }
        });
    }
    let tx_for_ransomware_alerts = ransomware_alert_tx;

    // --- Boucle principale: chaque événement FIM est scanné localement ---
    while let Some(mut event) = rx.recv().await {
        // Vérification anti-ransomware en priorité (avant même le scan de
        // signatures) : un comportement de chiffrement de masse doit
        // déclencher une réponse immédiate, peu importe si le fichier
        // correspond à une signature connue ou non (ransomware "zero-day").
        {
            let mut guard = ransomware_guard.lock().await;
            guard.record_event_and_check(&event, &tx_for_ransomware_alerts).await;
        }

        if !matches!(event.event_type, shared::EventType::Deleted) {
            if let Ok(h) = hasher::hash_file(std::path::Path::new(&event.path)).await {
                event.sha256 = Some(h.clone());
            }

            if let Ok(result) = scanner.scan_file(std::path::Path::new(&event.path)).await {
                if !matches!(result.verdict, scanner::Verdict::Clean) {
                    event.severity = shared::Severity::Critical;
                    let reason = format!("{:?}", result.verdict);
                    if cfg.response_mode != config::ResponseMode::AlertOnly {
                        if quarantine.quarantine_file(&result.path, &reason).await.is_ok() {
                            audit.record(&audit_log::AuditEntry {
                                action: "quarantine".to_string(),
                                target: result.path.display().to_string(),
                                reason: reason.clone(),
                                response_mode: format!("{:?}", cfg.response_mode),
                                timestamp: audit_log::now_unix(),
                            });
                        }
                    } else {
                        audit.record(&audit_log::AuditEntry {
                            action: "detection_alert_only".to_string(),
                            target: result.path.display().to_string(),
                            reason: reason.clone(),
                            response_mode: "AlertOnly".to_string(),
                            timestamp: audit_log::now_unix(),
                        });
                    }
                }
            }
        }

        // Toujours journalisé localement en premier : la détection et la
        // mise en quarantaine ne dépendent jamais de la disponibilité réseau.
        let _ = queue.enqueue(&event);
    }

    Ok(())
}

/// Récupère la liste blanche gérée côté support et la persiste dans
/// `config.toml`. Note honnête : la fusion s'applique à la configuration
/// persistée, pas encore à chaud dans le scanner/guard déjà en mémoire
/// (qui les ont capturés par valeur au démarrage) — une entrée ajoutée par
/// le support prend effet au prochain redémarrage de l'agent, pas
/// instantanément. Un rechargement à chaud complet nécessiterait de
/// passer le scanner/guard derrière un état partagé mutable (`RwLock`),
/// amélioration listée pour une itération suivante plutôt que bricolée
/// ici au risque d'introduire une race condition.
async fn sync_remote_allowlist(client: &ApiClient, token: &str) -> Result<()> {
    let remote = client.fetch_remote_config(token).await?;
    let mut cfg = AgentConfig::load_or_default()?;

    let mut changed = false;
    for path in remote.allowlist.paths {
        if !cfg.allowlist.paths.contains(&path) {
            cfg.allowlist.paths.push(path);
            changed = true;
        }
    }
    for name in remote.allowlist.process_names {
        if !cfg.allowlist.process_names.contains(&name) {
            cfg.allowlist.process_names.push(name);
            changed = true;
        }
    }
    for hash in remote.allowlist.hashes {
        if !cfg.allowlist.hashes.contains(&hash) {
            cfg.allowlist.hashes.push(hash);
            changed = true;
        }
    }

    if changed {
        cfg.save()?;
        tracing::info!("liste blanche mise à jour depuis le serveur (effective au prochain redémarrage)");
    }
    Ok(())
}

async fn sync_pending_events(queue: &OfflineQueue, client: &ApiClient, token: &str) -> Result<()> {
    let batch = queue.take_batch(200)?;
    if batch.is_empty() {
        return Ok(());
    }
    let ids: Vec<i64> = batch.iter().map(|(id, _)| *id).collect();
    let events: Vec<FileEvent> = batch.into_iter().map(|(_, e)| e).collect();

    client.send_events(token, events).await?;
    queue.mark_synced(&ids)?;
    tracing::info!(count = ids.len(), "événements en attente synchronisés");
    Ok(())
}

fn agent_data_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "WiseDesign", "IronShieldFIM")
        .ok_or_else(|| anyhow::anyhow!("répertoire de données introuvable"))?;
    let dir = dirs.data_dir().to_path_buf();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn write_pid_file() -> Result<()> {
    let exe = std::env::current_exe()?;
    let pid_file = exe.with_extension("pid");
    std::fs::write(pid_file, std::process::id().to_string())?;
    Ok(())
}

/// Dérive une clé de chiffrement AES-256 pour la quarantaine à partir d'un
/// secret local persistant (pas de dépendance réseau).
fn derive_quarantine_key() -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let dirs = directories::ProjectDirs::from("com", "WiseDesign", "IronShieldFIM")
        .ok_or_else(|| anyhow::anyhow!("répertoire introuvable"))?;
    let key_file = dirs.data_dir().join(".quarantine_key");

    if let Ok(existing) = std::fs::read(&key_file) {
        if existing.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&existing);
            return Ok(key);
        }
    }

    let mut rng_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rng_bytes);
    std::fs::create_dir_all(dirs.data_dir())?;
    std::fs::write(&key_file, rng_bytes)?;

    let mut hasher = Sha256::new();
    hasher.update(rng_bytes);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Ok(key)
}
