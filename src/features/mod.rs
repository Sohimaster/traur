pub mod checksum_analysis;
pub mod git_history_analysis;
pub mod gtfobins_analysis;
pub mod install_script_analysis;
pub mod maintainer_analysis;
pub mod metadata_analysis;
pub mod name_analysis;
pub mod orphan_takeover_analysis;
pub mod pkgbuild_analysis;
pub mod shell_analysis;
pub mod source_url_analysis;

use crate::shared::models::PackageContext;
use crate::shared::scoring::Signal;

/// Trait implemented by every analysis feature.
/// Each feature receives a PackageContext and returns signals it detected.
pub trait Feature {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal>;
}

/// Returns all registered features.
pub fn all_features() -> Vec<Box<dyn Feature>> {
    vec![
        Box::new(pkgbuild_analysis::PkgbuildAnalysis),
        Box::new(install_script_analysis::InstallScriptAnalysis),
        Box::new(source_url_analysis::SourceUrlAnalysis),
        Box::new(checksum_analysis::ChecksumAnalysis),
        Box::new(metadata_analysis::MetadataAnalysis),
        Box::new(name_analysis::NameAnalysis),
        Box::new(maintainer_analysis::MaintainerAnalysis),
        Box::new(orphan_takeover_analysis::OrphanTakeoverAnalysis),
        Box::new(git_history_analysis::GitHistoryAnalysis),
        Box::new(shell_analysis::ShellAnalysis),
        Box::new(gtfobins_analysis::GtfobinsAnalysis),
    ]
}
