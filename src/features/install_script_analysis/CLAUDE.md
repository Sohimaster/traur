# Install Script Analysis

Analyzes `.install` files (pre/post install/upgrade/remove hooks) for suspicious behavior.

## What it detects

- **Network activity**: curl/wget in install hooks — install scripts should not download anything
- **Download-and-execute**: curl|bash in install context — override gate
- **Persistence**: systemd enable, cron jobs in install hooks
- **Profile modification**: Writing to .bashrc/.zshrc during install

## Signals emitted

All signals use `SignalCategory::Pkgbuild` (weight 0.45). See `data/patterns.toml` section `install_script_analysis`.

## Dependencies

- `shared/patterns.rs` — regex pattern matching
- `PackageContext.install_script_content` — the .install file content

## Known false positives

- `P-INSTALL-CURL` (+70): Some packages legitimately fetch post-install data (e.g., font caches, database updates). Rare but possible.
- `P-INSTALL-PERSISTENCE` (+45): Packages providing daemons legitimately enable their systemd service in post_install.
