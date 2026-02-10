# Shell Analysis

Lightweight static analysis of PKGBUILD and install scripts that goes beyond regex pattern matching. Catches obfuscation techniques that regex fundamentally cannot detect. Runs all sub-analyzers on both `pkgbuild_content` and `install_script_content`.

## What it detects

### Variable Resolution (SA-VAR-CONCAT-EXEC, SA-VAR-CONCAT-CMD)
Tracks variable assignments (`VAR=value`) and resolves `$VAR`/`${VAR}` references. Detects when concatenated fragments form dangerous commands (e.g., `a=cu;b=rl;$a$b | bash`). Override gate fires for download-and-execute patterns.

### Indirect Execution (SA-INDIRECT-EXEC)
Detects variables holding dangerous command names (`bash`, `curl`, `python`, etc.) used in execution position (after `|`, at line start, after `;`/`&&`/`||`).

### Char-by-Char Construction (SA-CHARBYCHAR-CONSTRUCT)
Detects 3+ `$(printf '\xNN')` or `$(echo -e '\xNN')` subshells on a single line, indicating character-by-character command assembly.

### Data Blob Detection (SA-DATA-BLOB-HEX, SA-DATA-BLOB-BASE64, SA-HIGH-ENTROPY-HEREDOC)
Flags long hex strings (128+ chars, excluding checksums), long base64 strings (100+ chars), and heredocs with Shannon entropy > 5.0 bits/byte.

### Binary Download Heuristic (SA-BINARY-DOWNLOAD-NOCOMPILE)
Flags when a PKGBUILD downloads a file (`curl -o`/`wget -O`) and `chmod +x` it without any build commands (`make`, `cmake`, `cargo`, `gcc`, etc.).

## Signals emitted

| ID | Points | Override | Description |
|----|--------|----------|-------------|
| SA-VAR-CONCAT-EXEC | 85 | yes | Variable concat resolves to download-and-execute |
| SA-VAR-CONCAT-CMD | 55 | no | Variable concat resolves to dangerous command |
| SA-INDIRECT-EXEC | 70 | no | Variable with dangerous cmd in exec position |
| SA-CHARBYCHAR-CONSTRUCT | 75 | no | Printf/echo subshell char-by-char construction |
| SA-DATA-BLOB-HEX | 50 | no | Long hex string (encoded payload) |
| SA-DATA-BLOB-BASE64 | 50 | no | Long base64 string (encoded payload) |
| SA-HIGH-ENTROPY-HEREDOC | 55 | no | High-entropy heredoc content |
| SA-BINARY-DOWNLOAD-NOCOMPILE | 60 | no | Download + chmod +x, no compilation |

All signals use `SignalCategory::Pkgbuild` (weight 0.45). Install script signals use the same IDs with `IS-` prefix (e.g., `IS-SA-VAR-CONCAT-EXEC`).

## Design decisions

- **Single-pass variable resolution** — no recursive expansion (prevents infinite loops, catches common patterns)
- **PKGBUILD standard vars excluded** — prevents false positives on `$pkgname`, `$pkgver`, etc.
- **No overlap with regex feature** — only emits signals when obfuscation hides the pattern from literal matching
- **All regexes via `LazyLock`** — compiled once, zero per-invocation overhead

## Dependencies

- `PackageContext.pkgbuild_content` — the PKGBUILD content to analyze
- `PackageContext.install_script_content` — the .install file content to analyze
