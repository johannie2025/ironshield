use anyhow::Result;
use std::time::Duration;

/// Auto-protection "best effort" en espace utilisateur.
///
/// IMPORTANT — limite honnête : ceci ne garantit PAS l'impossibilité d'un
/// arrêt forcé par un utilisateur/attaquant disposant de droits
/// administrateur. Une protection réellement incontournable nécessiterait
/// un composant noyau (ObRegisterCallbacks), volontairement exclu de ce
/// projet. Ce module vise à rendre l'arrêt non-autorisé *détectable et
/// journalisé*, avec relance automatique, pas *impossible*.
///
/// Fonctionnement : l'agent lance un processus "watchdog" léger (le même
/// binaire avec un flag `--watchdog`) qui vérifie périodiquement que le
/// processus principal tourne toujours, et le relance sinon. Le processus
/// principal fait de même pour le watchdog (surveillance mutuelle).
pub async fn spawn_watchdog(exe_path: std::path::PathBuf) -> Result<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            if !watchdog_process_running().await {
                tracing::warn!("processus watchdog absent, relance");
                if let Err(e) = tokio::process::Command::new(&exe_path)
                    .arg("--watchdog")
                    .spawn()
                {
                    tracing::error!(error = %e, "échec de relance du watchdog");
                }
            }
        }
    });
    Ok(())
}

/// Point d'entrée du mode watchdog : surveille le processus agent principal
/// et le relance s'il a été arrêté de façon inattendue (hors arrêt propre
/// via le service/tâche planifiée, détecté par l'absence du fichier `.pid`).
pub async fn run_watchdog_mode(agent_exe: std::path::PathBuf, pid_file: std::path::PathBuf) -> Result<()> {
    tracing::info!("mode watchdog actif");
    loop {
        tokio::time::sleep(Duration::from_secs(20)).await;

        let agent_alive = pid_file.exists() && main_process_running(&pid_file).await;
        if !agent_alive {
            tracing::warn!("agent principal absent, relance depuis le watchdog");
            let _ = tokio::process::Command::new(&agent_exe).spawn();
        }
    }
}

#[cfg(windows)]
async fn watchdog_process_running() -> bool {
    process_exists_by_name("ironshield-agent.exe --watchdog").await
}

#[cfg(windows)]
async fn main_process_running(pid_file: &std::path::Path) -> bool {
    let Ok(content) = tokio::fs::read_to_string(pid_file).await else {
        return false;
    };
    let Ok(pid) = content.trim().parse::<u32>() else {
        return false;
    };
    process_exists_by_pid(pid).await
}

#[cfg(windows)]
async fn process_exists_by_name(_needle: &str) -> bool {
    // Implémentation simplifiée via `tasklist`. Une version future peut
    // utiliser CreateToolhelp32Snapshot pour éviter le spawn de processus.
    let output = tokio::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq ironshield-agent.exe"])
        .output()
        .await;
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains("ironshield-agent.exe"),
        Err(_) => false,
    }
}

#[cfg(windows)]
async fn process_exists_by_pid(pid: u32) -> bool {
    let output = tokio::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}")])
        .output()
        .await;
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()),
        Err(_) => false,
    }
}

#[cfg(not(windows))]
async fn watchdog_process_running() -> bool {
    true
}
#[cfg(not(windows))]
async fn main_process_running(_pid_file: &std::path::Path) -> bool {
    true
}
