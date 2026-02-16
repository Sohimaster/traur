# traur - Pre-install Trust Scoring for AUR Packages

Scores AUR packages before you install them. ALPM hook for pre-install scanning.

## Architecture

Feature-based with coordinator pattern:

```
PackageContext (metadata + pkgbuild + git)
  -> Coordinator runs all Features
  -> Each Feature returns Vec<Signal>
  -> Scorer applies weights + override gates -> final score + tier
```

**Features** (`src/features/`): Self-contained analysis modules, each implementing the `Feature` trait. Each detects specific security signals.

**Shared** (`src/shared/`): Reusable components (AUR API client, GitHub API client, AUR comments scraper, git ops, scoring engine, pattern loader, cache, config, output).

**Coordinator** (`src/coordinator.rs`): Orchestrates features, collects signals, computes final score.

## Scoring

Trust score 0-100 (higher = more trusted) from 4 weighted categories:
```
risk = 0.15*metadata + 0.45*pkgbuild + 0.25*behavioral + 0.15*temporal
trust = 100 - risk
```

Tiers: TRUSTED (81-100), OK (61-80), SKETCHY (41-60), SUSPICIOUS (21-40), MALICIOUS (0-20).

Override gates: 47 signals across download-and-execute, reverse shells, GTFOBins binary abuse, and variable-concatenated exec escalate directly to MALICIOUS.

## Build

```bash
cargo build --release
```

Binaries: `target/release/traur` (CLI) and `target/release/traur-hook` (ALPM hook).

## Install hook

```bash
sudo install -Dm755 target/release/traur /usr/bin/traur
sudo install -Dm755 target/release/traur-hook /usr/bin/traur-hook
sudo install -Dm644 hook/traur.hook /usr/share/libalpm/hooks/traur.hook
```

## Adding a new feature

1. Create `src/features/your_feature/` with `mod.rs` and `CLAUDE.md`
2. Implement the `Feature` trait (return `Vec<Signal>` from `analyze()`)
3. Register in `src/features/mod.rs` (`all_features()`)
4. If pattern-based, add rules to `data/patterns.toml`

## Adding new detection patterns

Edit `data/patterns.toml`. Each pattern has: `id`, `pattern` (regex), `points`, `description`, `override_gate` (bool). Patterns are grouped by feature section name.

## Release

Use `/release <version>` in Claude Code to run the full release workflow (bump version, build, GitHub release, update sha256sums, push to both AUR repos).

## Key files

| File | Purpose |
|------|---------|
| `src/coordinator.rs` | Orchestrates features and scoring |
| `src/features/mod.rs` | Feature trait + registry |
| `src/shared/scoring.rs` | Score computation, tiers, override gates. Signal has `matched_line: Option<String>` for verbose output |
| `src/shared/aur_rpc.rs` | AUR RPC v5 API client |
| `src/shared/aur_git.rs` | Git clone/pull/diff operations |
| `src/shared/bulk.rs` | Batch metadata fetch, maintainer prefetch, clone-with-retry |
| `src/features/orphan_takeover_analysis/` | Submitter != maintainer detection, orphan takeover composite signal |
| `src/features/shell_analysis/` | Beyond-regex static analysis (var concat, indirect exec, char-by-char, data blobs, binary download) |
| `src/features/gtfobins_analysis/` | GTFOBins-derived patterns (117 patterns for legitimate binary abuse) |
| `src/features/bin_source_verification/` | -bin package source domain vs upstream URL mismatch detection |
| `src/features/pkgbuild_diff_analysis/` | PKGBUILD diff checking: new suspicious patterns, removed checksums, domain changes, major rewrites |
| `src/features/github_stars/` | GitHub stars checking: zero/low stars, repo not found |
| `src/features/aur_comments_analysis/` | AUR comments scanning for security-related keywords |
| `src/shared/github.rs` | GitHub API client (star count, repo existence) |
| `src/shared/aur_comments.rs` | AUR package page comment scraper |
| `src/shared/signal_registry.rs` | Central registry of all signal definitions (pattern + hardcoded) |
| `src/shared/config.rs` | User config: whitelist, ignored signals/categories |
| `data/patterns.toml` | Regex pattern database (239 patterns). Total signals: 279 (pattern + hardcoded) |
| `src/bench.rs` | Batch benchmark (parallel scan, retry, stats) |
| `hook/traur.hook` | ALPM hook definition |
| `hook/traur-hook.rs` | Hook binary (filters AUR pkgs, runs scans) |
