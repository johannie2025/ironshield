use anyhow::Result;
use rusqlite::{params, Connection};
use shared::FileEvent;
use std::path::PathBuf;
use std::sync::Mutex;

/// File d'événements persistée sur disque (SQLite). Permet à l'agent de
/// continuer à détecter et journaliser des menaces même sans connexion
/// internet ; les événements sont envoyés au serveur dès que la
/// connectivité revient, puis marqués comme synchronisés.
pub struct OfflineQueue {
    conn: Mutex<Connection>,
}

impl OfflineQueue {
    pub fn open(db_path: PathBuf) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                synced INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_synced ON pending_events(synced)",
            [],
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn enqueue(&self, event: &FileEvent) -> Result<()> {
        let payload = serde_json::to_string(event)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pending_events (payload, created_at) VALUES (?1, ?2)",
            params![payload, event.timestamp],
        )?;
        Ok(())
    }

    /// Récupère un lot d'événements non synchronisés (les plus anciens en premier).
    pub fn take_batch(&self, limit: usize) -> Result<Vec<(i64, FileEvent)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, payload FROM pending_events WHERE synced = 0 ORDER BY id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let id: i64 = row.get(0)?;
            let payload: String = row.get(1)?;
            Ok((id, payload))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, payload) = row?;
            if let Ok(event) = serde_json::from_str::<FileEvent>(&payload) {
                out.push((id, event));
            }
        }
        Ok(out)
    }

    pub fn mark_synced(&self, ids: &[i64]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        for id in ids {
            conn.execute("UPDATE pending_events SET synced = 1 WHERE id = ?1", params![id])?;
        }
        // Purge les événements synchronisés depuis plus de 30 jours pour ne pas
        // faire grossir la base indéfiniment sur les postes rarement connectés.
        conn.execute(
            "DELETE FROM pending_events WHERE synced = 1 AND created_at < ?1",
            params![chrono_days_ago(30)],
        )?;
        Ok(())
    }

    pub fn pending_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM pending_events WHERE synced = 0",
            [],
            |r| r.get(0),
        )?)
    }
}

fn chrono_days_ago(days: i64) -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 - days * 86400)
        .unwrap_or(0)
}
