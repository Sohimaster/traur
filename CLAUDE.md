# traur - AUR Package Security Heuristic Scanner

Heuristic security scanner for AUR packages. ALPM hook integration for paru/yay.

## Architecture

Feature-based with coordinator pattern:

```
PackageContext (metadata + pkgbuild + git)
  -> Coordinator runs all Features
  -> Each Feature returns Vec<Signal>
  -> Scorer applies weights + override gates -> final score + tier
```

**Features** (`src/features/`): Self-contained analysis modules, each implementing the `Feature` trait. Each detects specific security signals.

**Shared** (`src/shared/`): Reusable components (AUR API client, git ops, scoring engine, pattern loader, cache, config, output).

**Coordinator** (`src/coordinator.rs`): Orchestrates features, collects signals, computes final score.

## Scoring

Composite score 0-100 from 4 weighted categories:
```
final = 0.15*metadata + 0.45*pkgbuild + 0.25*behavioral + 0.15*temporal
```

Tiers: LOW (0-19), MEDIUM (20-39), HIGH (40-59), CRITICAL (60-79), MALICIOUS (80-100).

Override gates: Certain signals (curl|bash, curl|python, reverse shells, Python exec+urlopen, variable-concatenated download-and-execute) escalate directly to MALICIOUS.

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

## Key files

| File | Purpose |
|------|---------|
| `src/coordinator.rs` | Orchestrates features and scoring |
| `src/features/mod.rs` | Feature trait + registry |
| `src/shared/scoring.rs` | Score computation, tiers, override gates |
| `src/shared/aur_rpc.rs` | AUR RPC v5 API client |
| `src/shared/aur_git.rs` | Git clone/pull/diff operations |
| `src/features/shell_analysis/` | Beyond-regex static analysis (var concat, indirect exec, char-by-char, data blobs, binary download) |
| `data/patterns.toml` | Regex pattern database |
| `src/bench.rs` | Batch benchmark (parallel scan, retry, stats) |
| `hook/traur.hook` | ALPM hook definition |
| `hook/traur-hook.rs` | Hook binary (filters AUR pkgs, runs scans) |
