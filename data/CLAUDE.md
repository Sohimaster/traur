# Data

External configuration files loaded at compile time or runtime.

## patterns.toml

Regex pattern database used by pattern-based features (pkgbuild_analysis, install_script_analysis, source_url_analysis).

### Format

```toml
[[section_name]]
id = "SIGNAL-ID"
pattern = 'regex_pattern'
points = 90
description = "Human-readable description"
override_gate = true  # optional, default false
```

- `section_name` must match the feature's name (e.g., `pkgbuild_analysis`)
- `pattern` is a Rust regex (ripgrep-compatible)
- `override_gate = true` means this signal bypasses weighted scoring and escalates directly to MALICIOUS tier
- Patterns are compiled once via `OnceLock` and reused

### Adding a new pattern

1. Add a `[[section_name]]` entry to patterns.toml
2. Use a descriptive `id` following the convention: `P-*` for Pkgbuild, `B-*` for Behavioral, etc.
3. Test the regex against known malicious and benign PKGBUILDs
4. Set `override_gate = true` only for patterns with near-zero false positive rates
