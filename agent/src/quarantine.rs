use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Déplace un fichier détecté vers un dossier de quarantaine chiffré,
/// plutôt que de le supprimer directement. Une menace confirmée par erreur
/// (faux positif) reste restaurable ; l'utilisateur ou l'admin décide de la
/// suppression définitive depuis le dashboard.
pub struct Quarantine {
    dir: PathBuf,
    key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct QuarantineMeta {
    original_path: String,
    reason: String,
    nonce: [u8; 12],
    quarantined_at: i64,
}

impl Quarantine {
    pub fn open(dir: PathBuf, key: [u8; 32]) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, key })
    }

    /// Chiffre et déplace le fichier ; le fichier original est supprimé du
    /// disque (mais son contenu reste récupérable via `restore`).
    pub async fn quarantine_file(&self, path: &Path, reason: &str) -> Result<PathBuf> {
        let data = tokio::fs::read(path).await.context("lecture du fichier à mettre en quarantaine")?;

        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|e| anyhow::anyhow!("échec du chiffrement de quarantaine: {e}"))?;

        let id = uuid_like();
        let blob_path = self.dir.join(format!("{id}.qtn"));
        let meta_path = self.dir.join(format!("{id}.json"));

        tokio::fs::write(&blob_path, &ciphertext).await?;
        let meta = QuarantineMeta {
            original_path: path.to_string_lossy().to_string(),
            reason: reason.to_string(),
            nonce: nonce_bytes,
            quarantined_at: now(),
        };
        tokio::fs::write(&meta_path, serde_json::to_vec_pretty(&meta)?).await?;

        // Suppression du fichier original uniquement après confirmation
        // que la copie chiffrée est bien écrite sur disque.
        tokio::fs::remove_file(path)
            .await
            .context("échec de suppression du fichier original après mise en quarantaine")?;

        tracing::warn!(original = %path.display(), quarantine_id = %id, reason, "fichier mis en quarantaine");
        Ok(blob_path)
    }

    /// Restaure un fichier depuis la quarantaine vers son emplacement d'origine.
    pub async fn restore(&self, quarantine_id: &str) -> Result<PathBuf> {
        let blob_path = self.dir.join(format!("{quarantine_id}.qtn"));
        let meta_path = self.dir.join(format!("{quarantine_id}.json"));

        let meta: QuarantineMeta = serde_json::from_slice(&tokio::fs::read(&meta_path).await?)?;
        let ciphertext = tokio::fs::read(&blob_path).await?;

        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        let nonce = Nonce::from_slice(&meta.nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("échec du déchiffrement: {e}"))?;

        let restore_path = PathBuf::from(&meta.original_path);
        tokio::fs::write(&restore_path, plaintext).await?;
        tokio::fs::remove_file(&blob_path).await.ok();
        tokio::fs::remove_file(&meta_path).await.ok();

        tracing::info!(path = %restore_path.display(), "fichier restauré depuis la quarantaine");
        Ok(restore_path)
    }

    /// Purge définitivement un élément en quarantaine (action explicite, non automatique).
    pub async fn delete_permanently(&self, quarantine_id: &str) -> Result<()> {
        let blob_path = self.dir.join(format!("{quarantine_id}.qtn"));
        let meta_path = self.dir.join(format!("{quarantine_id}.json"));
        tokio::fs::remove_file(&blob_path).await.ok();
        tokio::fs::remove_file(&meta_path).await.ok();
        Ok(())
    }
}

fn uuid_like() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
