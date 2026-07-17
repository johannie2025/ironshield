use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::hasher::hash_file;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: PathBuf,
    pub verdict: Verdict,
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious(String), // nom de la règle YARA déclenchée
    KnownMalicious,      // hash dans la liste noire locale
}

/// Moteur de scan local : ne nécessite aucune connexion internet.
/// Combine une liste de hashes malveillants connus (mise à jour lors des
/// connexions disponibles, mais utilisable indéfiniment hors ligne) et des
/// règles YARA compilées une fois au démarrage.
pub struct LocalScanner {
    rules: yara_x::Rules,
    malicious_hashes: HashSet<String>,
    allowlist: crate::config::Allowlist,
}

impl LocalScanner {
    /// Charge les règles YARA (`.yar`) et la liste de hashes depuis le
    /// répertoire de signatures local (`signatures/`), livré avec l'agent
    /// et mis à jour par l'updater quand la connexion est disponible.
    pub fn load(signatures_dir: &Path, allowlist: crate::config::Allowlist) -> Result<Self> {
        let rules_path = signatures_dir.join("rules.yar");
        let hashes_path = signatures_dir.join("malicious_hashes.txt");

        let rules_source = std::fs::read_to_string(&rules_path)
            .context("fichier de règles YARA introuvable — l'agent tourne en mode dégradé")
            .unwrap_or_default();

        let mut compiler = yara_x::Compiler::new();
        if !rules_source.is_empty() {
            compiler
                .add_source(rules_source.as_str())
                .context("échec de compilation des règles YARA")?;
        }
        let rules = compiler.build();

        let malicious_hashes = std::fs::read_to_string(&hashes_path)
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<HashSet<_>>();

        tracing::info!(
            hash_count = malicious_hashes.len(),
            "moteur de scan local chargé (fonctionne hors ligne)"
        );

        Ok(Self { rules, malicious_hashes, allowlist })
    }

    /// Analyse un fichier. Ne fait aucun appel réseau : entièrement local.
    pub async fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        if self.allowlist.allows_path(&path.to_string_lossy()) {
            return Ok(ScanResult { path: path.to_path_buf(), verdict: Verdict::Clean, matched_rule: None });
        }

        let hash = hash_file(path).await.unwrap_or_default();

        if self.allowlist.allows_hash(&hash) {
            return Ok(ScanResult { path: path.to_path_buf(), verdict: Verdict::Clean, matched_rule: None });
        }

        if self.malicious_hashes.contains(&hash) {
            return Ok(ScanResult {
                path: path.to_path_buf(),
                verdict: Verdict::KnownMalicious,
                matched_rule: None,
            });
        }

        let bytes = tokio::fs::read(path).await.unwrap_or_default();
        if bytes.is_empty() {
            return Ok(ScanResult { path: path.to_path_buf(), verdict: Verdict::Clean, matched_rule: None });
        }

        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan(&bytes).context("échec du scan YARA")?;

        if let Some(m) = results.matching_rules().next() {
            return Ok(ScanResult {
                path: path.to_path_buf(),
                verdict: Verdict::Suspicious(m.identifier().to_string()),
                matched_rule: Some(m.identifier().to_string()),
            });
        }

        Ok(ScanResult { path: path.to_path_buf(), verdict: Verdict::Clean, matched_rule: None })
    }

    /// Parcourt récursivement un volume (ex: clé USB) et scanne chaque fichier.
    pub async fn scan_volume(&self, root: &Path) -> Vec<ScanResult> {
        let mut results = Vec::new();
        for entry in walkdir::WalkDir::new(root)
            .max_depth(12)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            match self.scan_file(entry.path()).await {
                Ok(r) if r.verdict != Verdict::Clean => {
                    tracing::warn!(path = %entry.path().display(), verdict = ?r.verdict, "menace détectée");
                    results.push(r);
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(path = %entry.path().display(), error = %e, "scan ignoré"),
            }
        }
        results
    }
}
