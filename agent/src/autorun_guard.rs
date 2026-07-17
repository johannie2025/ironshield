use anyhow::Result;
use std::path::Path;
use tokio::process::Command;

/// Protection contre les vers se propageant via `autorun.inf` sur clés USB
/// — vecteur historique majeur (Conficker, etc.), toujours actif sur les
/// parcs mal configurés. Deux volets, tous deux hors ligne :
/// 1. Désactive l'exécution automatique Windows au niveau système (une fois).
/// 2. Met en quarantaine tout `autorun.inf` détecté lors d'un scan USB.
pub struct AutorunGuard;

impl AutorunGuard {
    /// Désactive l'autorun pour tous les types de lecteurs via la stratégie
    /// de registre standard Microsoft (`NoDriveTypeAutoRun`). Idempotent.
    pub async fn disable_system_autorun() -> Result<()> {
        let output = Command::new("reg")
            .args([
                "add",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "/v", "NoDriveTypeAutoRun",
                "/t", "REG_DWORD",
                "/d", "0xFF", // désactive l'autorun pour tous les types de lecteurs
                "/f",
            ])
            .output()
            .await?;

        if output.status.success() {
            tracing::info!("autorun Windows désactivé au niveau système");
        } else {
            tracing::warn!("échec de désactivation de l'autorun (droits insuffisants ?)");
        }
        Ok(())
    }

    /// Recherche un `autorun.inf` à la racine d'un volume monté (typiquement
    /// une clé USB) et le neutralise s'il est présent — qu'il soit légitime
    /// ou non, un `autorun.inf` sur un support amovible n'a plus d'usage
    /// légitime sous Windows moderne.
    pub async fn scan_and_neutralize(volume_root: &Path) -> Result<bool> {
        let autorun_path = volume_root.join("autorun.inf");
        if !tokio::fs::try_exists(&autorun_path).await.unwrap_or(false) {
            return Ok(false);
        }

        tracing::warn!(path = %autorun_path.display(), "autorun.inf détecté sur support amovible, neutralisation");

        // Renommage plutôt que suppression immédiate : conserve une preuve
        // pour analyse, tout en désactivant l'exécution automatique.
        let neutralized = volume_root.join("autorun.inf.ironshield-quarantined");
        tokio::fs::rename(&autorun_path, &neutralized).await?;
        Ok(true)
    }
}
