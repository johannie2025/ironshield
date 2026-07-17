use anyhow::{Context, Result};
use shared::{EventType, FileEvent, Severity};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::UnboundedSender;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED,
    FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

/// Chemins jugés sensibles: toute modification y est remontée en "critical".
fn is_sensitive(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("system32") || lower.contains("drivers") || lower.ends_with(".exe") || lower.ends_with(".dll")
}

/// Lance la surveillance bloquante d'un répertoire dans un thread dédié.
/// Les événements détectés sont poussés dans `tx` (canal async).
pub fn watch_directory(dir: PathBuf, tx: UnboundedSender<FileEvent>) -> Result<()> {
    std::thread::Builder::new()
        .name(format!("watcher-{}", dir.display()))
        .spawn(move || {
            if let Err(e) = run_watch_loop(&dir, &tx) {
                tracing::error!(path = %dir.display(), error = %e, "watcher arrêté sur erreur");
            }
        })
        .context("impossible de démarrer le thread de surveillance")?;
    Ok(())
}

fn run_watch_loop(dir: &Path, tx: &UnboundedSender<FileEvent>) -> Result<()> {
    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle: HANDLE = unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            FILE_LIST_DIRECTORY.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .context("CreateFileW a échoué (droits insuffisants ou chemin invalide)")?;

    let mut buffer = [0u8; 65536];

    loop {
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            ReadDirectoryChangesW(
                handle,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                true, // récursif
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_SECURITY,
                Some(&mut bytes_returned),
                None,
                None,
            )
        };

        if ok.is_err() || bytes_returned == 0 {
            tracing::warn!("ReadDirectoryChangesW: aucune donnée, nouvelle tentative");
            continue;
        }

        parse_notifications(&buffer[..bytes_returned as usize], dir, tx);
    }
}

fn parse_notifications(buffer: &[u8], base_dir: &Path, tx: &UnboundedSender<FileEvent>) {
    let mut offset = 0usize;

    loop {
        if offset + std::mem::size_of::<FILE_NOTIFY_INFORMATION>() > buffer.len() {
            break;
        }

        let info = unsafe {
            &*(buffer.as_ptr().add(offset) as *const FILE_NOTIFY_INFORMATION)
        };

        let name_len = info.FileNameLength as usize / 2;
        let name_ptr = unsafe { info.FileName.as_ptr() };
        let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
        let name = String::from_utf16_lossy(name_slice);
        let full_path = base_dir.join(&name);
        let full_path_str = full_path.to_string_lossy().to_string();

        let event_type = match info.Action {
            FILE_ACTION_ADDED => Some(EventType::Created),
            FILE_ACTION_MODIFIED => Some(EventType::Modified),
            FILE_ACTION_REMOVED => Some(EventType::Deleted),
            FILE_ACTION_RENAMED_NEW_NAME => Some(EventType::Renamed),
            _ => None,
        };

        if let Some(event_type) = event_type {
            let severity = if is_sensitive(&full_path_str) {
                Severity::Critical
            } else {
                Severity::Info
            };

            let event = FileEvent {
                path: full_path_str,
                event_type,
                sha256: None, // calculé de façon asynchrone en aval (voir main.rs)
                severity,
                timestamp: chrono_now(),
            };

            let _ = tx.send(event);
        }

        if info.NextEntryOffset == 0 {
            break;
        }
        offset += info.NextEntryOffset as usize;
    }
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Ferme proprement un handle Windows (appelé au shutdown de l'agent).
pub fn close_handle(handle: HANDLE) {
    unsafe {
        let _ = CloseHandle(handle);
    }
}
