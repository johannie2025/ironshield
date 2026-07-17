use anyhow::{bail, Result};
use serde::Deserialize;
use shared::{ActivationRequest, ActivationResponse, EventBatch, FileEvent};

#[derive(Debug, Deserialize)]
pub struct RemoteAllowlist {
    pub paths: Vec<String>,
    pub process_names: Vec<String>,
    pub hashes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RemoteConfigResponse {
    pub allowlist: RemoteAllowlist,
}

pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .https_only(true)
            .build()
            .expect("impossible de construire le client HTTP");
        Self { http, base_url }
    }

    pub async fn activate(&self, req: &ActivationRequest) -> Result<ActivationResponse> {
        let url = format!("{}/activate", self.base_url);
        let resp = self.http.post(&url).json(req).send().await?;

        if !resp.status().is_success() {
            bail!("activation échouée: HTTP {}", resp.status());
        }
        Ok(resp.json::<ActivationResponse>().await?)
    }

    pub async fn send_events(&self, token: &str, events: Vec<FileEvent>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let url = format!("{}/events", self.base_url);
        let batch = EventBatch { events };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&batch)
            .send()
            .await?;

        if !resp.status().is_success() {
            bail!("envoi des événements échoué: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// Récupère la liste blanche gérée côté serveur (traitement des faux
    /// positifs par le support sans intervention sur le poste). Échoue
    /// silencieusement si hors ligne : l'agent continue avec sa liste
    /// blanche locale (`config.toml`).
    pub async fn fetch_remote_config(&self, token: &str) -> Result<RemoteConfigResponse> {
        let url = format!("{}/config", self.base_url);
        let resp = self.http.get(&url).bearer_auth(token).send().await?;
        if !resp.status().is_success() {
            bail!("récupération de la config distante échouée: HTTP {}", resp.status());
        }
        Ok(resp.json::<RemoteConfigResponse>().await?)
    }
}
