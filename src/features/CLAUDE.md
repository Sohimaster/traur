# Features

Each subdirectory is a self-contained analysis feature implementing the `Feature` trait from `mod.rs`.

## Feature trait

```rust
pub trait Feature {
    fn name(&self) -> &str;
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal>;
}
```

Features receive a `PackageContext` (all collected data about a package) and return signals they detected. The coordinator runs all features and feeds signals to the scoring engine.

## Registered features

| Feature | What it detects | Signal category | Weight |
|---------|----------------|-----------------|--------|
| `pkgbuild_analysis` | Dangerous shell patterns in PKGBUILD | Pkgbuild | 0.45 |
| `install_script_analysis` | Suspicious code in .install files | Pkgbuild | 0.45 |
| `source_url_analysis` | Suspicious source URLs | Pkgbuild | 0.45 |
| `checksum_analysis` | Missing/weak/mismatched checksums | Pkgbuild | 0.45 |
| `metadata_analysis` | AUR metadata red flags | Metadata | 0.15 |
| `name_analysis` | Typosquatting and impersonation | Behavioral | 0.25 |
| `maintainer_analysis` | Maintainer reputation signals | Behavioral | 0.25 |
| `git_history_analysis` | Temporal signals from git history | Temporal | 0.15 |
| `shell_analysis` | Beyond-regex obfuscation (var concat, indirect exec, char-by-char, data blobs, binary download) | Pkgbuild | 0.45 |
| `gtfobins_analysis` | GTFOBins-derived patterns (reverse shells, pipe-to-interpreter, non-obvious exec) | Pkgbuild | 0.45 |

## Adding a new feature

1. Create a new directory under `src/features/`
2. Add `mod.rs` implementing the `Feature` trait
3. Add `CLAUDE.md` explaining what the feature detects
4. Register the feature in `all_features()` in this module's `mod.rs`
5. If using regex patterns, add them to `data/patterns.toml` under a section matching your feature name
