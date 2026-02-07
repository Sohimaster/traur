use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub thresholds: ThresholdConfig,
    #[serde(default)]
    pub whitelist: WhitelistConfig,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize, Default)]
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

fn config_path() -> std::path::PathBuf {
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
