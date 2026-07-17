use anyhow::{Context, Result};
use tokio::process::Command;

/// Pilote le pare-feu Windows natif via `netsh advfirewall`.
///
/// Volontairement PAS un driver WFP custom : Windows Defender Firewall est
/// déjà un pare-feu à filtrage de paquets certifié et présent sur toute
/// machine Windows. Le réinventer en driver kernel ajouterait une surface
/// d'attaque sans bénéfice réel — piloter le pare-feu existant est à la
/// fois plus sûr et suffisant pour bloquer l'exfiltration réseau d'un
/// processus identifié comme malveillant.
pub struct FirewallManager;

impl FirewallManager {
    /// Bloque tout trafic (entrant + sortant) pour un exécutable donné.
    /// Utilisé quand un processus est identifié comme malveillant mais que
    /// son fichier ne peut pas encore être supprimé (verrouillé en cours
    /// d'exécution) : on coupe d'abord ses communications réseau.
    pub async fn block_executable(exe_path: &str, rule_prefix: &str) -> Result<()> {
        let rule_out = format!("{rule_prefix}_out");
        let rule_in = format!("{rule_prefix}_in");

        run_netsh(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={rule_out}"), "dir=out", "action=block",
            &format!("program={exe_path}"), "enable=yes",
        ])
        .await
        .context("échec du blocage sortant")?;

        run_netsh(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={rule_in}"), "dir=in", "action=block",
            &format!("program={exe_path}"), "enable=yes",
        ])
        .await
        .context("échec du blocage entrant")?;

        tracing::warn!(exe = exe_path, "trafic réseau bloqué pour ce processus");
        Ok(())
    }

    /// Retire les règles de blocage associées à un préfixe (ex: après
    /// confirmation qu'il s'agissait d'un faux positif).
    pub async fn unblock(rule_prefix: &str) -> Result<()> {
        for suffix in ["_out", "_in"] {
            let name = format!("{rule_prefix}{suffix}");
            let _ = run_netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={name}")]).await;
        }
        Ok(())
    }

    /// Bloque tout le trafic sortant non essentiel pendant une réponse à
    /// incident (ex: ransomware actif détecté) — ne coupe pas la connexion
    /// vers le serveur IronShield lui-même pour permettre l'alerte.
    pub async fn emergency_lockdown(allow_host: &str) -> Result<()> {
        run_netsh(&[
            "advfirewall", "firewall", "add", "rule",
            "name=ironshield_lockdown_allow", "dir=out", "action=allow",
            &format!("remoteip={allow_host}"), "enable=yes",
        ])
        .await?;

        run_netsh(&[
            "advfirewall", "firewall", "add", "rule",
            "name=ironshield_lockdown_block_all", "dir=out", "action=block",
            "enable=yes",
        ])
        .await?;

        tracing::error!("verrouillage réseau d'urgence activé (activité ransomware détectée)");
        Ok(())
    }

    pub async fn lift_lockdown() -> Result<()> {
        let _ = run_netsh(&["advfirewall", "firewall", "delete", "rule", "name=ironshield_lockdown_block_all"]).await;
        let _ = run_netsh(&["advfirewall", "firewall", "delete", "rule", "name=ironshield_lockdown_allow"]).await;
        tracing::info!("verrouillage réseau levé");
        Ok(())
    }
}

async fn run_netsh(args: &[&str]) -> Result<()> {
    let output = Command::new("netsh").args(args).output().await?;
    if !output.status.success() {
        anyhow::bail!("netsh a échoué: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}
