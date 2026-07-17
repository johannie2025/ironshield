use crate::api_client::ApiClient;
use crate::config::AgentConfig;
use crate::hasher::compute_hardware_id;
use anyhow::{bail, Result};
use shared::ActivationRequest;

/// S'assure que l'agent possède un token d'activation valide.
/// Active auprès du serveur si nécessaire, puis persiste le token localement.
pub async fn ensure_activated(config: &mut AgentConfig, client: &ApiClient) -> Result<String> {
    if let Some(token) = &config.activation_token {
        return Ok(token.clone());
    }

    let license_key = config
        .license_key
        .clone()
        .unwrap_or_else(|| std::env::var("IRONSHIELD_LICENSE_KEY").unwrap_or_default());

    if license_key.is_empty() {
        bail!("aucune clé de licence configurée (config.toml ou IRONSHIELD_LICENSE_KEY)");
    }

    let hardware_id = compute_hardware_id()?;
    let req = ActivationRequest {
        license_key,
        hardware_id,
        hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
        os_version: std::env::consts::OS.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let resp = client.activate(&req).await?;
    if !resp.valid {
        bail!("licence invalide ou refusée par le serveur");
    }
    let token = resp.token.ok_or_else(|| anyhow::anyhow!("token manquant dans la réponse"))?;

    config.activation_token = Some(token.clone());
    config.save()?;

    tracing::info!(tier = ?resp.tier, "activation réussie");
    Ok(token)
}
