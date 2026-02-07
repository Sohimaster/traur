use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub thresholds: ThresholdConfig,
    #[serde(default)]
    pub whitelist: WhitelistConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ThresholdConfig {
    #[serde(default = "default_block_at")]
    pub block_at: String,
    #[serde(default = "default_warn_at")]
    pub warn_at: String,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            block_at: default_block_at(),
            warn_at: default_warn_at(),
        }
    }
}

fn default_block_at() -> String {
    "critical".to_string()
}

fn default_warn_at() -> String {
    "medium".to_string()
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub packages: Vec<String>,
}

/// Load config from ~/.config/traur/config.toml, falling back to defaults.
pub fn load_config() -> Config {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// Save config to ~/.config/traur/config.toml, creating directory if needed.
pub fn save_config(config: &Config) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
    }
    let toml_str =
        toml::to_string_pretty(config).map_err(|e| format!("Failed to serialize config: {e}"))?;
    std::fs::write(&path, toml_str).map_err(|e| format!("Failed to write config: {e}"))?;
    Ok(())
}

/// Add a package to the whitelist and persist to disk.
pub fn add_to_whitelist(package: &str) -> Result<(), String> {
    let mut config = load_config();
    if !config.whitelist.packages.contains(&package.to_string()) {
        config.whitelist.packages.push(package.to_string());
        config.whitelist.packages.sort();
    }
    save_config(&config)
}

/// Check if a package is whitelisted in the given config.
pub fn is_whitelisted_in(config: &Config, package: &str) -> bool {
    config.whitelist.packages.iter().any(|p| p == package)
}

pub fn config_path() -> std::path::PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        std::path::PathBuf::from(xdg).join("traur").join("config.toml")
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home)
            .join(".config")
            .join("traur")
            .join("config.toml")
    } else {
        std::path::PathBuf::from("/etc/traur/config.toml")
    }
}
