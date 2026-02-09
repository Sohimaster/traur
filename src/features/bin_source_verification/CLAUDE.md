# Bin Source Verification

Cross-references a `-bin` package's declared upstream URL against its `source=()` download domains. Catches fork impersonation and attacker-controlled repos masquerading as official releases.

## What it detects

- **GitHub org mismatch** (B-BIN-GITHUB-ORG-MISMATCH, +50): Source downloads from a different GitHub org/user than the declared upstream. High-confidence indicator of fork impersonation.
- **Domain mismatch** (B-BIN-DOMAIN-MISMATCH, +30): Source downloads from an entirely different domain than the declared upstream.

## Scope

Only activates for packages whose name ends with `-bin`. Checks all `source=()` and architecture-specific `source_ARCH=()` arrays.

## Signals emitted

All signals use `SignalCategory::Behavioral` (weight 0.25). No override gates.

## Edge cases handled

- Resolves `${url}` / `$url` variables to the upstream URL before comparison
- Skips source entries with unresolvable variables (e.g. `$pkgver`, `$_owner`)
- Strips VCS prefixes (`git+https://`, `svn+https://`)
- Handles PKGBUILD rename syntax (`filename::url`)
- Normalizes domain prefixes (`www.`, `dl.`, `download.`)
- Deduplicates GitHub org mismatch signals (emits at most one)

## Dependencies

- `PackageContext.metadata.url` — upstream URL from AUR RPC
- `PackageContext.pkgbuild_content` — source arrays from PKGBUILD

## Known false positives

- `B-BIN-DOMAIN-MISMATCH` (~15%): Packages that legitimately download from CDNs or mirrors (e.g. upstream is `example.com` but binary hosted on `cdn.example.net`). Low points (30) reflect this.
- `B-BIN-GITHUB-ORG-MISMATCH` (~5%): Rare — packages where a different GitHub user/org hosts the binary releases on behalf of the upstream project.
