use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncReadExt;

/// Calcule le SHA-256 d'un fichier en streaming (évite de charger de gros
/// fichiers entièrement en mémoire).
pub async fn hash_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Calcule un identifiant matériel stable (SHA-256) à partir d'informations
/// non-volatiles de la machine (nom d'hôte + UUID système via WMI-like registre).
pub fn compute_hardware_id() -> Result<String> {
    let hostname = whoami_hostname();
    let machine_guid = read_machine_guid().unwrap_or_else(|| "unknown".to_string());

    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(b"|");
    hasher.update(machine_guid.as_bytes());

    Ok(format!("{:x}", hasher.finalize()))
}

fn whoami_hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown-host".to_string())
}

#[cfg(windows)]
fn read_machine_guid() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Cryptography")
        .ok()?;
    key.get_value::<String, _>("MachineGuid").ok()
}

#[cfg(not(windows))]
fn read_machine_guid() -> Option<String> {
    None
}
