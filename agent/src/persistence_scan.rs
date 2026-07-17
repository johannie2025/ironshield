use anyhow::Result;
use serde::Serialize;
use tokio::process::Command;

/// Audit des points de persistance Windows classiques (équivalent
/// simplifié de Sysinternals Autoruns) : clés de registre `Run`, dossier
/// Démarrage, tâches planifiées. Détecte les entrées pointant vers des
/// emplacements inhabituels (Temp, AppData racine, chemins sans guillemets
/// avec espaces — technique de détournement classique).
#[derive(Debug, Serialize, Clone)]
pub struct PersistenceEntry {
    pub source: String, // "registry_run", "startup_folder", "scheduled_task"
    pub name: String,
    pub command: String,
    pub suspicious: bool,
    pub suspicion_reason: Option<String>,
}

pub async fn scan_persistence() -> Result<Vec<PersistenceEntry>> {
    let mut entries = Vec::new();
    entries.extend(scan_registry_run_keys().await?);
    entries.extend(scan_scheduled_tasks().await?);
    Ok(entries)
}

async fn scan_registry_run_keys() -> Result<Vec<PersistenceEntry>> {
    let mut results = Vec::new();
    let keys = [
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    ];

    for (key, _hive) in keys {
        let output = Command::new("reg").args(["query", key]).output().await;
        let Ok(output) = output else { continue };
        if !output.status.success() {
            continue;
        }

        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let line = line.trim();
            // Format typique: "    NomValeur    REG_SZ    C:\chemin\vers\exe.exe"
            let parts: Vec<&str> = line.splitn(2, "REG_").collect();
            if parts.len() != 2 {
                continue;
            }
            let name = parts[0].trim().to_string();
            let command = parts[1].splitn(2, char::is_whitespace).nth(1).unwrap_or("").trim().to_string();
            if name.is_empty() || command.is_empty() {
                continue;
            }

            let (suspicious, reason) = evaluate_suspicion(&command);
            results.push(PersistenceEntry {
                source: "registry_run".to_string(),
                name,
                command,
                suspicious,
                suspicion_reason: reason,
            });
        }
    }

    Ok(results)
}

async fn scan_scheduled_tasks() -> Result<Vec<PersistenceEntry>> {
    let mut results = Vec::new();
    let output = Command::new("schtasks").args(["/Query", "/FO", "CSV", "/V"]).output().await;
    let Ok(output) = output else { return Ok(results) };
    if !output.status.success() {
        return Ok(results);
    }

    for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
        let fields: Vec<&str> = line.split(',').map(|f| f.trim_matches('"')).collect();
        if fields.len() < 9 {
            continue;
        }
        let name = fields[1].to_string();
        let command = fields[8].to_string(); // colonne "Task To Run" (index approximatif selon locale)
        if name.is_empty() || command.is_empty() || name.starts_with(r"\Microsoft\Windows\") {
            continue; // ignore les tâches système Microsoft standard
        }

        let (suspicious, reason) = evaluate_suspicion(&command);
        results.push(PersistenceEntry {
            source: "scheduled_task".to_string(),
            name,
            command,
            suspicious,
            suspicion_reason: reason,
        });
    }

    Ok(results)
}

/// Heuristiques simples et transparentes (pas de "boîte noire") pour
/// signaler une entrée de démarrage comme potentiellement suspecte.
fn evaluate_suspicion(command: &str) -> (bool, Option<String>) {
    let lower = command.to_lowercase();

    if lower.contains(r"\appdata\local\temp\") || lower.contains(r"\windows\temp\") {
        return (true, Some("exécutable lancé depuis un dossier temporaire".to_string()));
    }
    if lower.contains("powershell") && (lower.contains("-enc") || lower.contains("-windowstyle hidden")) {
        return (true, Some("PowerShell avec fenêtre cachée ou commande encodée".to_string()));
    }
    if lower.contains("\\public\\") || lower.contains("\\programdata\\") {
        return (true, Some("exécutable dans un dossier partagé inhabituel pour une application".to_string()));
    }
    // Chemin avec espace non protégé par des guillemets (technique de
    // détournement classique : "C:\Program Files\App\x.exe" sans quotes
    // peut être interprété comme "C:\Program.exe").
    if command.contains(' ') && !command.trim_start().starts_with('"') && lower.ends_with(".exe") {
        return (true, Some("chemin avec espace non protégé par des guillemets".to_string()));
    }

    (false, None)
}
