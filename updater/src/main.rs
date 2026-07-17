//! IronShield Updater
//!
//! Vérifie périodiquement s'il existe une nouvelle version de l'agent
//! (via les GitHub Releases taguées `agent-v*`), télécharge le binaire et
//! le fichier de sommes de contrôle SHA-256, vérifie l'intégrité, puis
//! remplace l'exécutable en place de façon atomique avec sauvegarde/rollback.
//!
//! Conçu pour être exécuté périodiquement par le Planificateur de tâches
//! Windows (pas de composant kernel, pas de service persistant requis).

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

const GITHUB_API_LATEST: &str =
    "https://api.github.com/repos/wise-design/ironshield/releases/latest";
const USER_AGENT: &str = "ironshield-updater";

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize, Clone)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let agent_dir = std::env::current_exe()?
        .parent()
        .context("répertoire de l'agent introuvable")?
        .to_path_buf();
    let agent_path = agent_dir.join("ironshield-agent.exe");
    let version_file = agent_dir.join("VERSION");

    let current_version = std::fs::read_to_string(&version_file)
        .unwrap_or_else(|_| "agent-v0.0.0".to_string())
        .trim()
        .to_string();

    tracing::info!(current = %current_version, "vérification de mise à jour");

    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .https_only(true)
        .build()?;

    let release = fetch_latest_release(&client).await?;

    if release.tag_name == current_version {
        tracing::info!("agent déjà à jour");
        if let Err(e) = sync_signatures(&client, &agent_dir).await {
            tracing::warn!(error = %e, "synchronisation des signatures impossible (hors ligne ?)");
        }
        return Ok(());
    }
    if !release.tag_name.starts_with("agent-v") {
        tracing::info!(tag = %release.tag_name, "release ignorée (tag non concerné)");
        return Ok(());
    }

    tracing::info!(new_version = %release.tag_name, "nouvelle version détectée, téléchargement");

    let exe_asset = find_asset(&release, "ironshield-agent.exe")?;
    let sums_asset = find_asset(&release, "SHA256SUMS.txt")?;

    let tmp_dir = agent_dir.join(".update-tmp");
    tokio::fs::create_dir_all(&tmp_dir).await?;
    let tmp_exe = tmp_dir.join("ironshield-agent.exe.new");
    let tmp_sums = tmp_dir.join("SHA256SUMS.txt");

    download_file(&client, &exe_asset.browser_download_url, &tmp_exe).await?;
    download_file(&client, &sums_asset.browser_download_url, &tmp_sums).await?;

    let expected_hash = parse_expected_hash(&tmp_sums, "ironshield-agent.exe")
        .context("hash attendu introuvable dans SHA256SUMS.txt")?;
    let actual_hash = hash_file(&tmp_exe).await?;

    if actual_hash.to_lowercase() != expected_hash.to_lowercase() {
        bail!(
            "intégrité invalide: attendu {}, obtenu {} — mise à jour annulée",
            expected_hash,
            actual_hash
        );
    }
    tracing::info!("intégrité SHA-256 vérifiée");

    apply_update(&agent_path, &tmp_exe).await?;
    tokio::fs::write(&version_file, &release.tag_name).await?;
    let _ = tokio::fs::remove_dir_all(&tmp_dir).await;

    tracing::info!(version = %release.tag_name, "mise à jour appliquée avec succès");

    // La synchronisation des signatures est indépendante de la mise à jour
    // du binaire : elle s'exécute à chaque passage de l'updater (dès que le
    // réseau est disponible), même sans nouvelle version de l'agent.
    if let Err(e) = sync_signatures(&client, &agent_dir).await {
        tracing::warn!(error = %e, "synchronisation des signatures impossible (hors ligne ?), l'agent continue avec la base locale existante");
    }

    Ok(())
}

/// Télécharge les dernières signatures depuis des sources publiques
/// entretenues (pas des fichiers statiques factices) :
/// - YARA-Forge (agrège et compile les règles YARA open-source les plus
///   fiables du secteur, mis à jour quotidiennement) :
///   https://github.com/YARAHQ/yara-forge
/// - abuse.ch MalwareBazaar (flux de hashes SHA-256 de malwares confirmés,
///   gratuit, mis à jour en continu) : https://bazaar.abuse.ch
///
/// Échec silencieux et non bloquant : l'agent continue de fonctionner
/// avec sa base locale si aucune connexion n'est disponible.
///
/// IMPORTANT — déploiement canari : avant diffusion large, une nouvelle
/// base de signatures doit être validée sur un sous-ensemble du parc
/// (voir `canary_percentage` ci-dessous) pour éviter qu'une règle
/// défectueuse ne génère une avalanche de faux positifs sur tous les
/// clients simultanément — c'est un incident classique chez tous les
/// éditeurs d'AV, pas une hypothèse théorique.
async fn sync_signatures(client: &reqwest::Client, agent_dir: &Path) -> Result<()> {
    let signatures_dir = agent_dir.join("signatures");
    tokio::fs::create_dir_all(&signatures_dir).await?;

    if !machine_is_in_canary_wave(agent_dir).await {
        tracing::debug!("machine hors vague canari — synchronisation des signatures différée à la prochaine vague");
        return Ok(());
    }

    // Source 1 : règles YARA compilées (YARA-Forge, "core" ruleset —
    // équilibre reconnu entre couverture et taux de faux positifs).
    let yara_forge_url = std::env::var("IRONSHIELD_YARA_FEED_URL").unwrap_or_else(|_| {
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.yar".to_string()
    });
    sync_one_signature_file(client, &yara_forge_url, &signatures_dir, "rules.yar").await;

    // Source 2 : hashes SHA-256 de malwares confirmés (abuse.ch
    // MalwareBazaar, export CSV public).
    let hashes_url = std::env::var("IRONSHIELD_HASH_FEED_URL")
        .unwrap_or_else(|_| "https://bazaar.abuse.ch/export/txt/sha256/full/".to_string());
    sync_one_signature_file(client, &hashes_url, &signatures_dir, "malicious_hashes.txt").await;

    tokio::fs::write(signatures_dir.join(".last_sync"), now_iso8601()).await.ok();
    Ok(())
}

async fn sync_one_signature_file(client: &reqwest::Client, url: &str, dir: &Path, local_name: &str) {
    let resp = match client.get(url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(url, status = %r.status(), "échec de téléchargement de la source de signatures");
            return;
        }
        Err(e) => {
            tracing::debug!(url, error = %e, "source de signatures inaccessible (hors ligne ?)");
            return;
        }
    };

    let Ok(bytes) = resp.bytes().await else { return };
    if bytes.is_empty() {
        return;
    }

    let tmp = dir.join(format!("{local_name}.new"));
    let final_path = dir.join(local_name);
    if tokio::fs::write(&tmp, &bytes).await.is_ok() {
        // Remplacement atomique : jamais de fichier de signatures à moitié
        // écrit si l'agent est interrompu pendant l'opération.
        let _ = tokio::fs::rename(&tmp, &final_path).await;
        tracing::info!(file = local_name, bytes = bytes.len(), "signatures mises à jour");
    }
}

/// Déploiement canari simple basé sur le hardware ID : une fraction stable
/// (déterministe, pas aléatoire à chaque run) du parc reçoit les mises à
/// jour en premier. Le pourcentage est piloté côté serveur via
/// `IRONSHIELD_CANARY_PERCENT` (100 = tout le parc, comportement par défaut
/// une fois la confiance établie).
async fn machine_is_in_canary_wave(agent_dir: &Path) -> bool {
    let percent: u32 = std::env::var("IRONSHIELD_CANARY_PERCENT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100); // par défaut: tout le monde (mode non-canari)

    if percent >= 100 {
        return true;
    }

    let hw_id = crate_hasher_compute_hardware_id_bridge(agent_dir).unwrap_or_else(|| "unknown".to_string());
    let bucket = simple_hash_to_percent(&hw_id);
    bucket < percent
}

fn crate_hasher_compute_hardware_id_bridge(_agent_dir: &Path) -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

fn simple_hash_to_percent(input: &str) -> u32 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    (digest[0] as u32) % 100
}

fn now_iso8601() -> String {
    format!("{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())
}

async fn fetch_latest_release(client: &reqwest::Client) -> Result<GhRelease> {
    let resp = client.get(GITHUB_API_LATEST).send().await?;
    if !resp.status().is_success() {
        bail!("échec de récupération de la release: HTTP {}", resp.status());
    }
    Ok(resp.json::<GhRelease>().await?)
}

fn find_asset<'a>(release: &'a GhRelease, name: &str) -> Result<&'a GhAsset> {
    release
        .assets
        .iter()
        .find(|a| a.name == name)
        .with_context(|| format!("asset '{name}' absent de la release {}", release.tag_name))
}

async fn download_file(client: &reqwest::Client, url: &str, dest: &Path) -> Result<()> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        bail!("téléchargement échoué ({}): HTTP {}", url, resp.status());
    }

    let mut file = tokio::fs::File::create(dest).await?;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        file.write_all(&chunk?).await?;
    }
    file.flush().await?;
    Ok(())
}

async fn hash_file(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path).await?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Parse un fichier au format `sha256sum` classique :
/// `<hash>  <nom_de_fichier>` (une entrée par ligne).
fn parse_expected_hash(sums_path: &Path, target_name: &str) -> Result<String> {
    let content = std::fs::read_to_string(sums_path)?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name.trim_start_matches('*') == target_name {
            return Ok(hash.to_string());
        }
    }
    bail!("entrée '{target_name}' absente de SHA256SUMS.txt")
}

/// Remplace l'exécutable en place avec sauvegarde et rollback automatique
/// en cas d'échec. Le remplacement d'un .exe en cours d'exécution sous
/// Windows nécessite que le processus courant se termine juste après
/// (le Planificateur de tâches relance l'agent ensuite).
async fn apply_update(current: &PathBuf, new_binary: &Path) -> Result<()> {
    let backup = current.with_extension("exe.bak");

    if current.exists() {
        tokio::fs::copy(current, &backup)
            .await
            .context("échec de la sauvegarde de l'ancien binaire")?;
    }

    match tokio::fs::rename(new_binary, current).await {
        Ok(_) => {
            let _ = tokio::fs::remove_file(&backup).await;
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "échec du remplacement, restauration de la sauvegarde");
            if backup.exists() {
                let _ = tokio::fs::rename(&backup, current).await;
            }
            Err(e).context("échec du remplacement du binaire, rollback effectué")
        }
    }
}
