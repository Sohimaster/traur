use crate::shared::models::AurPackage;
use serde::Deserialize;

const AUR_RPC_BASE: &str = "https://aur.archlinux.org/rpc/v5";

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(rename = "resultcount")]
    result_count: u32,
    results: Vec<AurPackage>,
}

/// Fetch info for a single package from the AUR RPC API.
pub fn fetch_package_info(package_name: &str) -> Result<AurPackage, String> {
    let url = format!("{AUR_RPC_BASE}/info?arg[]={package_name}");
    let resp: RpcResponse = reqwest::blocking::get(&url)
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .json()
        .map_err(|e| format!("Failed to parse AUR response: {e}"))?;

    if resp.result_count == 0 {
        return Err(format!("Package '{package_name}' not found on AUR"));
    }

    resp.results
        .into_iter()
        .next()
        .ok_or_else(|| "Empty results".to_string())
}

/// Fetch info for multiple packages in a single request.
pub fn fetch_packages_info(names: &[&str]) -> Result<Vec<AurPackage>, String> {
    let args: String = names.iter().map(|n| format!("arg[]={n}")).collect::<Vec<_>>().join("&");
    let url = format!("{AUR_RPC_BASE}/info?{args}");
    let resp: RpcResponse = reqwest::blocking::get(&url)
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .json()
        .map_err(|e| format!("Failed to parse AUR response: {e}"))?;

    Ok(resp.results)
}

/// Fetch all packages maintained by a given user.
pub fn fetch_maintainer_packages(maintainer: &str) -> Result<Vec<AurPackage>, String> {
    let url = format!("{AUR_RPC_BASE}/search/{maintainer}?by=maintainer");
    let resp: RpcResponse = reqwest::blocking::get(&url)
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .json()
        .map_err(|e| format!("Failed to parse AUR response: {e}"))?;

    Ok(resp.results)
}
