use crate::shared::local_scan::LocalSource;
use serde::Deserialize;

/// All data a feature needs to run its analysis.
#[derive(Debug)]
pub struct PackageContext {
    pub name: String,
    pub metadata: Option<AurPackage>,
    pub pkgbuild_content: Option<String>,
    pub install_script_content: Option<String>,
    pub prior_pkgbuild_content: Option<String>,
    pub git_log: Vec<GitCommit>,
    pub maintainer_packages: Vec<AurPackage>,
    pub github_stars: Option<u32>,
    pub github_not_found: bool,
    pub aur_comments: Vec<String>,
    /// Committed `source=()` files, read from disk when scanning a directory.
    /// Empty for a clone that has not downloaded sources yet: absence means
    /// "not analysed", never "clean".
    pub local_sources: Vec<LocalSource>,
    /// Directory the PKGBUILD was read from, for provenance in reports.
    pub source_path: Option<std::path::PathBuf>,
    /// Why the inputs are incomplete, if they are. When non-empty the scan
    /// reports `Unknown` rather than a verdict: an unreadable PKGBUILD or a
    /// missing install script means nothing was verified.
    pub incomplete: Vec<String>,
}

impl Default for PackageContext {
    fn default() -> Self {
        PackageContext {
            name: String::new(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: Vec::new(),
            maintainer_packages: Vec::new(),
            github_stars: None,
            github_not_found: false,
            aur_comments: Vec::new(),
            local_sources: vec![],
            source_path: None,
            incomplete: vec![],
        }
    }
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
    pub submitter: Option<String>,
    pub first_submitted: u64,
    #[allow(dead_code)]
    pub last_modified: u64,
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
