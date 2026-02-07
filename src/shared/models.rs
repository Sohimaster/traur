use serde::Deserialize;

/// All data a feature needs to run its analysis.
pub struct PackageContext {
    pub name: String,
    pub metadata: Option<AurPackage>,
    pub pkgbuild_content: Option<String>,
    pub install_script_content: Option<String>,
    pub prior_pkgbuild_content: Option<String>,
    pub git_log: Vec<GitCommit>,
    pub maintainer_packages: Vec<AurPackage>,
}

/// Package metadata from AUR RPC API v5.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AurPackage {
    pub name: String,
    pub package_base: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    pub num_votes: u32,
    pub popularity: f64,
    pub out_of_date: Option<u64>,
    pub maintainer: Option<String>,
    pub first_submitted: u64,
    pub license: Option<Vec<String>>,
}

/// Lightweight entry from the AUR metadata dump (packages-meta-v1.json.gz).
#[derive(Debug, Deserialize)]
pub struct MetaDumpPackage {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "LastModified")]
    pub last_modified: u64,
    #[serde(rename = "PackageBase")]
    pub package_base: String,
}

/// A single git commit from the AUR package repo.
#[derive(Debug, Clone)]
pub struct GitCommit {
    pub author: String,
    pub timestamp: u64,
    pub diff: Option<String>,
}
