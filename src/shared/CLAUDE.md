# Shared Components

Reusable modules consumed by features and the coordinator. Code goes here if it's used by 2+ features or by the coordinator.

## Modules

| Module | Purpose | Used by |
|--------|---------|---------|
| `models.rs` | `PackageContext`, `AurPackage` (with `submitter`, `last_modified`), `GitCommit` structs | All features |
| `aur_rpc.rs` | AUR RPC v5 API client (reqwest, blocking) | coordinator, metadata, maintainer, name features |
| `aur_git.rs` | Git clone/pull/diff/log operations | coordinator, pkgbuild, install_script, git_history features |
| `scoring.rs` | `Signal`, `SignalCategory`, `Tier`, `ScanResult`, `compute_score()` | coordinator |
| `patterns.rs` | Load TOML pattern rules, compile to regex | pkgbuild, install_script, source_url, gtfobins features |
| `cache.rs` | Cache directory management (XDG_CACHE_HOME) | aur_git, aur_rpc |
| `config.rs` | User config from ~/.config/traur/config.toml | coordinator |
| `output.rs` | Colored text + JSON formatters for ScanResult | coordinator (via main.rs) |
| `bulk.rs` | Batch metadata fetch, maintainer prefetch, clone-with-retry | bench, cmd_scan_all_installed |

## When to put code here vs in a feature

- **Here**: Generic utilities, API clients, data types, scoring logic
- **Feature**: Analysis logic specific to one concern (even if it calls shared code)
