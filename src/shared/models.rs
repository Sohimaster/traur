use serde::Deserialize;

/// All data a feature needs to run its analysis.
pub struct PackageContext {
    pub name: String,
    pub metadata: Option<AurPackage>,
    pub pkgbuild_content: Option<String>,
    pub install_script_content: Option<String>,
    pub git_log: Vec<GitCommit>,
    pub maintainer_packages: Vec<AurPackage>,
}

/// Package metadata from AUR RPC API v5.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AurPackage {
    #[serde(rename = "ID")]
    pub id: u64,
    pub name: String,
    pub package_base: Option<String>,
    pub version: String,
    pub description: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    pub num_votes: u32,
    pub popularity: f64,
    pub out_of_date: Option<u64>,
    pub maintainer: Option<String>,
    pub first_submitted: u64,
    pub last_modified: u64,
    pub depends: Option<Vec<String>>,
    pub make_depends: Option<Vec<String>>,
    pub opt_depends: Option<Vec<String>>,
    pub check_depends: Option<Vec<String>>,
    pub conflicts: Option<Vec<String>>,
    pub provides: Option<Vec<String>>,
    pub replaces: Option<Vec<String>>,
    pub license: Option<Vec<String>>,
    pub keywords: Option<Vec<String>>,
}

/// A single git commit from the AUR package repo.
#[derive(Debug, Clone)]
pub struct GitCommit {
    pub hash: String,
    pub author: String,
    pub timestamp: u64,
    pub message: String,
    pub diff: Option<String>,
}
