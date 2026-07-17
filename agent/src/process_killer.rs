use anyhow::Result;
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

/// Réponse active en cas de ransomware confirmé : ne se contente plus de
/// couper le réseau, termine aussi les processus suspects récemment
/// démarrés. Approche volontairement "large" (kill switch) plutôt que
/// tenter une corrélation fine fichier↔processus (qui nécessiterait un
/// driver kernel ou ETW avancé) : en situation de ransomware actif, la
/// priorité est d'arrêter le chiffrement, quitte à terminer un peu plus
/// large que nécessaire — mieux vaut relancer une application légitime
/// que perdre des fichiers utilisateur.
const PROCESS_ALLOWLIST: &[&str] = &[
    "explorer.exe", "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "smss.exe", "system", "registry",
    "ironshield-agent.exe", "ironshield-updater.exe", "ironshield-gui.exe",
    "dwm.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
];

#[derive(Debug, Clone)]
pub struct RunningProcess {
    pub pid: u32,
    pub name: String,
    pub start_time_unix: Option<i64>,
}

/// Termine tous les processus non-système démarrés dans la fenêtre récente
/// donnée (par défaut 5 minutes), à l'exception de la liste blanche.
/// Utilisé uniquement en réponse à une détection de ransomware confirmée.
pub async fn kill_recent_suspicious_processes(
    window: Duration,
    allowlist: &crate::config::Allowlist,
) -> Result<Vec<String>> {
    let processes = list_processes_with_start_time().await?;
    let now = now_unix();
    let mut killed = Vec::new();

    for proc in processes {
        let name_lower = proc.name.to_lowercase();
        if PROCESS_ALLOWLIST.iter().any(|a| *a == name_lower) {
            continue;
        }
        if allowlist.allows_process(&proc.name) {
            tracing::info!(name = %proc.name, "processus épargné (liste blanche client)");
            continue;
        }

        let is_recent = match proc.start_time_unix {
            Some(start) => (now - start) <= window.as_secs() as i64,
            None => false, // impossible de déterminer l'âge = on ne tue pas par prudence
        };

        if is_recent {
            if kill_pid(proc.pid).await.is_ok() {
                tracing::error!(pid = proc.pid, name = %proc.name, "processus terminé (réponse anti-ransomware)");
                killed.push(format!("{} (PID {})", proc.name, proc.pid));
            }
        }
    }

    Ok(killed)
}

pub async fn kill_pid(pid: u32) -> Result<()> {
    let output = Command::new("taskkill").args(["/PID", &pid.to_string(), "/F", "/T"]).output().await?;
    if !output.status.success() {
        anyhow::bail!("taskkill a échoué pour le PID {pid}");
    }
    Ok(())
}

pub async fn kill_by_name(name: &str) -> Result<()> {
    let output = Command::new("taskkill").args(["/IM", name, "/F", "/T"]).output().await?;
    if !output.status.success() {
        anyhow::bail!("taskkill a échoué pour {name}");
    }
    Ok(())
}

/// Liste les processus avec leur heure de démarrage via WMIC (disponible
/// nativement sur Windows, aucune dépendance externe).
async fn list_processes_with_start_time() -> Result<Vec<RunningProcess>> {
    let output = Command::new("wmic")
        .args(["process", "get", "ProcessId,Name,CreationDate", "/format:csv"])
        .output()
        .await?;

    let text = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();
    let mut seen_pids = HashSet::new();

    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.trim().split(',').collect();
        // Format CSV wmic: Node,CreationDate,Name,ProcessId
        if fields.len() < 4 {
            continue;
        }
        let creation_date = fields[1].trim();
        let name = fields[2].trim().to_string();
        let Ok(pid) = fields[3].trim().parse::<u32>() else { continue };

        if name.is_empty() || !seen_pids.insert(pid) {
            continue;
        }

        let start_time_unix = parse_wmic_datetime(creation_date);
        processes.push(RunningProcess { pid, name, start_time_unix });
    }

    Ok(processes)
}

/// Parse le format de date WMIC: `20250714153045.123456+060`
fn parse_wmic_datetime(raw: &str) -> Option<i64> {
    if raw.len() < 14 {
        return None;
    }
    let year: i32 = raw[0..4].parse().ok()?;
    let month: u32 = raw[4..6].parse().ok()?;
    let day: u32 = raw[6..8].parse().ok()?;
    let hour: i64 = raw[8..10].parse().ok()?;
    let min: i64 = raw[10..12].parse().ok()?;
    let sec: i64 = raw[12..14].parse().ok()?;

    // Approximation suffisante pour une fenêtre "récent" en minutes : pas
    // besoin d'une conversion calendaire exacte, juste d'un ordre de
    // grandeur cohérent en secondes depuis une origine commune.
    let days_since_epoch = days_from_civil(year, month, day);
    Some(days_since_epoch * 86400 + hour * 3600 + min * 60 + sec)
}

/// Algorithme standard (Howard Hinnant) de conversion date civile -> jours
/// depuis l'epoch Unix, sans dépendance à une crate de dates.
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let mp = ((m as i64 + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
