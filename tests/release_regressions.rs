use traur::{coordinator, shared::models::PackageContext};

#[test]
fn recipe_digest_tracks_install_script() {
    let mut ctx = PackageContext { name: "example".into(), pkgbuild_content: Some("pkgname=example".into()), ..Default::default() };
    let first = coordinator::run_analysis(&ctx);
    ctx.install_script_content = Some("echo hello".into());
    let second = coordinator::run_analysis(&ctx);
    assert_ne!(first.provenance["scanned_recipe_sha256"], second.provenance["scanned_recipe_sha256"]);
    assert!(first.provenance["scanned_version"].is_null());
}

#[test]
fn printed_enable_command_is_not_persistence() {
    let ctx = PackageContext { name: "example".into(), pkgbuild_content: Some("pkgname=example".into()), install_script_content: Some("echo \"sudo systemctl enable --now example.timer\"".into()), ..Default::default() };
    assert!(!coordinator::run_analysis(&ctx).signals.iter().any(|s| s.id == "P-INSTALL-PERSISTENCE"));
    let ctx = PackageContext { install_script_content: Some("systemctl enable --now example.timer".into()), ..ctx };
    assert!(coordinator::run_analysis(&ctx).signals.iter().any(|s| s.id == "P-INSTALL-PERSISTENCE"));
}
