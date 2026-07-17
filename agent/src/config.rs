use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// Détecte, journalise, alerte — n'agit jamais automatiquement.
    /// Mode par défaut : un kill-switch automatique sur un parc jamais
    /// testé est plus dangereux que la menace elle-même.
    AlertOnly,
    /// Met en quarantaine les fichiers détectés, mais ne termine aucun
    /// processus automatiquement.
    QuarantineOnly,
    /// Comportement complet : quarantaine + verrouillage réseau + kill
    /// des processus suspects. À activer explicitement après une période
    /// pilote sans faux positif sur le parc concerné.
    Full,
}

impl Default for ResponseMode {
    fn default() -> Self {
        ResponseMode::AlertOnly
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Allowlist {
    /// Chemins de fichiers/dossiers jamais scannés ni mis en quarantaine
    /// (ex: logiciels métier maison connus pour déclencher des FP).
    pub paths: Vec<String>,
    /// Noms de processus jamais terminés par la réponse anti-ransomware.
    pub process_names: Vec<String>,
    /// Hashes SHA-256 explicitement marqués sains malgré une détection
    /// heuristique (ex: faux positif YARA confirmé par l'admin).
    pub hashes: Vec<String>,
}

impl Allowlist {
    pub fn allows_path(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        self.paths.iter().any(|p| lower.starts_with(&p.to_lowercase()))
    }

    pub fn allows_process(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.process_names.iter().any(|p| p.to_lowercase() == lower)
    }

    pub fn allows_hash(&self, hash: &str) -> bool {
        self.hashes.iter().any(|h| h.eq_ignore_ascii_case(hash))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    pub api_base_url: String,
    pub watched_paths: Vec<String>,
    pub license_key: Option<String>,
    pub activation_token: Option<String>,
    #[serde(default)]
    pub response_mode: ResponseMode,
    #[serde(default)]
    pub allowlist: Allowlist,
    /// Fenêtre de recherche de processus "récents" à terminer en cas de
    /// ransomware confirmé (secondes). Réglable par client selon son
    /// contexte (un poste avec beaucoup d'installations légitimes en
    /// cours peut vouloir une fenêtre plus courte).
    #[serde(default = "default_kill_window")]
    pub ransomware_kill_window_secs: u64,
}

fn default_kill_window() -> u64 {
    300
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            api_base_url: "https://wiseshield.alwaysdata.net/api".to_string(),
            watched_paths: vec![
                r"C:\Windows\System32\drivers".to_string(),
                r"C:\Program Files".to_string(),
            ],
            license_key: None,
            activation_token: None,
            response_mode: ResponseMode::default(),
            allowlist: Allowlist::default(),
            ransomware_kill_window_secs: default_kill_window(),
        }
    }
}

fn config_path() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "WiseDesign", "IronShieldFIM")
        .context("impossible de résoudre le répertoire de configuration")?;
    let dir = dirs.config_dir();
    std::fs::create_dir_all(dir)?;
    Ok(dir.join("config.toml"))
}

impl AgentConfig {
    pub fn load_or_default() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            let cfg = Self::default();
            cfg.save()?;
            return Ok(cfg);
        }
        let raw = std::fs::read_to_string(&path)?;
        Ok(toml::from_str(&raw)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        let raw = toml::to_string_pretty(self)?;
        std::fs::write(path, raw)?;
        Ok(())
    }
}
