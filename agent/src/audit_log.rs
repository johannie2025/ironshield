use anyhow::Result;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;

/// Journal d'audit append-only : trace CHAQUE action automatique prise par
/// l'agent (quarantaine, kill de processus, verrouillage réseau,
/// neutralisation autorun/hosts). Séparé de la file d'événements FIM
/// (`offline_queue.rs`) car il a une finalité différente : preuve pour le
/// support/litige client, pas de la télémétrie de détection.
///
/// Sans ce journal, un client contestant "pourquoi mon logiciel a été
/// supprimé" est impossible à traiter sérieusement — c'était un vrai trou
/// du produit avant cet ajout.
pub struct AuditLog {
    conn: Mutex<Connection>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuditEntry {
    pub action: String,       // "quarantine", "kill_process", "network_lockdown", "autorun_neutralized", "hosts_cleaned"
    pub target: String,       // chemin, PID+nom, etc.
    pub reason: String,
    pub response_mode: String, // mode actif au moment de l'action
    pub timestamp: i64,
}

impl AuditLog {
    pub fn open(db_path: PathBuf) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT NOT NULL,
                response_mode TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn record(&self, entry: &AuditEntry) {
        let conn = self.conn.lock().unwrap();
        let result = conn.execute(
            "INSERT INTO audit_log (action, target, reason, response_mode, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![entry.action, entry.target, entry.reason, entry.response_mode, entry.timestamp],
        );
        if let Err(e) = result {
            tracing::error!(error = %e, "échec d'écriture dans le journal d'audit");
        }
        tracing::info!(
            action = %entry.action, target = %entry.target, reason = %entry.reason,
            "action journalisée (audit)"
        );
    }

    /// Exporte les N dernières entrées (pour support technique ou export
    /// vers le dashboard).
    pub fn recent(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT action, target, reason, response_mode, timestamp
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AuditEntry {
                action: row.get(0)?,
                target: row.get(1)?,
                reason: row.get(2)?,
                response_mode: row.get(3)?,
                timestamp: row.get(4)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
