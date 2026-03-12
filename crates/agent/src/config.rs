use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub output: OutputConfig,
    #[serde(default)]
    pub collectors: HashMap<String, toml::Value>,
    #[serde(default)]
    pub detectors: HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    pub host_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OutputConfig {
    pub data_dir: String,
    #[serde(default = "default_true")]
    pub write_events: bool,
}

fn default_true() -> bool {
    true
}

pub fn load(path: &str) -> Result<Config> {
    let path = Path::new(path);
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;
    let config: Config =
        toml::from_str(&content).with_context(|| "failed to parse config")?;
    Ok(config)
}
