use crate::coordinator;
use crate::shared::aur_rpc;
use crate::shared::models::{AurPackage, PackageContext};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

pub const RPC_BATCH_SIZE: usize = 150;
pub const MAX_RETRIES: u32 = 3;
pub const RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

/// Fetch AUR metadata for a batch of package names via the RPC API.
pub fn batch_fetch_metadata(names: &[String]) -> HashMap<String, AurPackage> {
    let mut map = HashMap::new();

    for chunk in names.chunks(RPC_BATCH_SIZE) {
        let refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
        match aur_rpc::fetch_packages_info(&refs) {
            Ok(packages) => {
                for pkg in packages {
                    map.insert(pkg.name.clone(), pkg);
                }
            }
            Err(e) => {
                eprintln!("  Warning: batch metadata fetch failed: {e}");
            }
        }
    }

    map
}

/// Pre-fetch all maintainer package lists in parallel.
pub fn prefetch_maintainer_packages(
    metadata: &HashMap<String, AurPackage>,
) -> HashMap<String, Vec<AurPackage>> {
    let maintainers: Vec<&str> = metadata
        .values()
        .filter_map(|pkg| pkg.maintainer.as_deref())
        .collect::<HashSet<&str>>()
        .into_iter()
        .collect();

    eprintln!(
        "  Fetching maintainer data for {} unique maintainers...",
        maintainers.len()
    );

    maintainers
        .par_iter()
        .filter_map(|m| {
            aur_rpc::fetch_maintainer_packages(m)
                .ok()
                .map(|pkgs| (m.to_string(), pkgs))
        })
        .collect()
}

/// Clone repo with retry + exponential backoff. Returns PackageContext or error.
pub fn clone_with_retry(
    name: &str,
    metadata: AurPackage,
    maintainer_packages: Vec<AurPackage>,
) -> Result<PackageContext, String> {
    for attempt in 0..MAX_RETRIES {
        match coordinator::build_context_prefetched(name, metadata.clone(), maintainer_packages.clone())
        {
            Ok(ctx) => return Ok(ctx),
            Err(e) if attempt + 1 < MAX_RETRIES => {
                let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
                std::thread::sleep(delay);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}
