# Changelog

## 0.6.0

This release changes how signals are scored. It closes two silent bypasses, removes
the false positives reported against 0.5.0, and adds the measurement harness those
changes are verified against.

### Changed — score semantics (`schema_version: 2`)

- Signals now carry a **role**. `Fact` signals describe a package's declarations and
  normal AUR packaging conventions and no longer add risk; only `Capability`,
  `Composition` and override gates participate. `score`, `tier`, `signals[].id` and
  `override_gate_fired` remain stable, and the JSON gains `schema_version`, `status`
  and `reason`. Numeric scores move for most packages: a normal package that used to
  score 77 for shipping a systemd unit now scores 100.
- The report marks facts with `--` and says so, so a lifecycle convention is never
  read as a finding.

### Added

- **Local directory scans** (`traur scan --dir`, and `--pkgbuild` now analyses its
  directory). Committed `source=()` files and the `.install` script pacman executes
  are analysed, with reads confined to the package directory and size caps.
- **Composition detection**: `SA-PIPE-DOWNLOAD-EXEC`, `SA-PIPE-DECODE-EXEC` and
  `SA-EXFIL-PIPE` catch a download or decode flowing into an interpreter, and a
  credential store leaving over the network — including inside `$(...)`, which the
  line-oriented patterns missed.
- **`eval` classification**: `eval "$pkgver"` is a fact; `eval "$(curl … | base64 -d
  | bash)"` gates. `P-EVAL-VAR` is retained at zero points for compatibility.
- **`P-INSTALL-UNRESOLVED`**: an `install=` naming a file that cannot be read is now
  reported instead of silently analysing nothing.
- **Inconclusive scans**: missing input yields `UNSAFE-TO-CONCLUDE` (`"tier":
  "Unknown"`) with a reason, never `TRUSTED` and never `SUSPICIOUS`. The hook offers
  allow once, allow for this session, or stop; a session allow is root-owned, applies
  only to inconclusive scans, and expires on the next successful AUR fetch or reboot.
- **Offline corpus harness** (`tests/corpus/`, `tests/corpus_cases.rs`) with 46 real
  AUR packages and 7 incident-derived samples, plus `tests/bypass_regressions.rs`.

### Fixed

- **Credential exfiltration from `.install` scripts scored 89/100 TRUSTED.** The
  install script was only resolved from a literal `install=` prefix; spaced, variable
  and split-package forms were missed, and a failed read returned nothing. It is now
  resolved the way makepkg does, and the pipeline gates.
- **A committed `source=()` file containing `curl … | base64 -d | bash` scored
  100/100 TRUSTED.** Local sources are now analysed.
- **`P-SYSTEMD-CREATE` fired on `install -Dm644 foo.service "$pkgdir/usr/lib/systemd/"`
  (#13 class).** Packaging a unit is a fact; `llama.cpp-vulkan`, `dotool`,
  `voxtype-bin` and `whisper.cpp-vulkan` no longer score SKETCHY for it.
- **`B-TYPOSQUAT` fired on legitimate variants** (`slack-desktop-wayland`, `vim-git`,
  `proton-ge-custom-bin`). Recognised variant suffixes are no longer treated as
  impersonation, and a test that asserted the old behaviour was corrected.
- **`P-CHECKSUM-MISMATCH` counted comment lines as checksums** (`voxtype-bin`
  reported 10 sources against 145 "checksums").
- **Masking was private to one feature**, so the checksum and header-comment fixes
  (#27, #11, #12) kept recurring on other surfaces. All features now read one
  normalized view, and the checksum regex that stopped at the first `)` was replaced
  by region-based span masking.
- **`G-DOWNLOAD-NODE` matched declared build tooling** (`pnpm exec`).
- **`P-NPM-INSTALL-BUILDTIME` is now a conditional fact** when the toolchain is
  declared in `makedepends` and no remote tarball is present; the Atomic Arch
  coverage is unchanged.
- **Partial AUR outages silently skipped packages**: a failed batch is now `Unknown`,
  not "not on AUR".

### Known limitations

- A remote `source=()` file that has not been downloaded yet is not analysed. Absence
  is reported as "not analysed", never as clean.
- `-git` packages have no checksum to verify, so provenance for them reduces to the
  declared upstream URL.
- The malicious corpus is small and incident-derived; it is a recall floor, not a
  benchmark.

## 0.5.0

### Fixed

- **False SKETCHY on packages with long checksums** (#11, #27): the Monero branch of
  `P-CRYPTO-WALLET` had no word boundaries, so a 95-character run inside a `sha512sums`
  entry matched. `google-chrome` scored 60/100 with a phantom "cryptocurrency wallet"
  signal. The regex now requires word boundaries, and no pattern is matched against
  checksum arrays at all.
- **Quote-splitting bypassed the download-and-execute gate** (#23): `cu""rl ... | ba""sh`
  scored SKETCHY because patterns match literal text. Quote removal now runs before
  matching, so split command names resolve to `curl ... | bash` and fire `P-CURL-PIPE`.
  New `SA-QUOTE-SPLIT-EXEC` signal covers the shell-analysis path.
- **The hook silently allowed unscanned installs when the AUR was unreachable** (#24):
  an HTTP failure was indistinguishable from "not on the AUR", so every package was
  skipped and the transaction continued. The hook now blocks, with
  `TRAUR_ALLOW_OFFLINE=1` as an escape hatch for environments that isolate hook
  networking (CachyOS).
- **`source=("$file"::"$url")` counted as three entries** (#13): the `name::url` form
  produced a bogus `P-CHECKSUM-MISMATCH`. It now counts as one.
- **Heredoc entropy fired on generated shell scripts** (#13): byte entropy is high for
  any text using many distinct ASCII characters, so heredocs that write out bash
  wrappers looked like payloads. `SA-HIGH-ENTROPY-HEREDOC` now also requires a body
  that looks encoded (under 5% whitespace, over 85% base64-like characters).
- **`P-BASE64` fired on base64-encoded maintainer addresses** (#12): the leading
  comment block is skipped when matching, so `# Maintainer: x <$(echo ... | base64 -d)>`
  no longer scores 60 points. The same call in `build()` or `package()` still does.
- **AUR comment analysis returned nothing for every package**: the live page emits
  `<div id="comment-..." class="article-content">`, but the regex required `class` to
  come first. Contributed by @joaovitorbf (#15).
- **`traur clean <name>` could delete arbitrary directories**: the package name was
  joined onto the cache path unchecked, so `traur clean ../../../x` removed `x`. Names
  are now validated and the resolved path must stay inside the cache (PR #21).

### Added

- **Atomic Arch (2026) coverage** (#25): build-time `npm`/`bun`/`yarn`/`pnpm` installs,
  installs from remote tarball URLs, the `atomic-lockfile` and `js-digest` payload
  names (override gate), eBPF program loading and BPF filesystem writes, and access to
  `.aws`, `.docker`, `.npmrc`, `.netrc`, gh, kube and gcloud credential stores.
- **Published compromise list** (#17): packages on the shared list of compromised AUR
  packages score 0/100 through `B-MALICIOUS-LIST`. The list is cached for 12 hours and
  degrades to no signal when offline.
- **New dependency detection** in PKGBUILD diffs (`T-DIFF-NEW-DEP-NPM-BUN`, +50):
  contributed by @hirak99 (#20).
- **`traur clean [package]`**: removes one cached clone, or the whole git cache.
- **`traur scan --notify`** and a packaged `traur-scan.timer` for unattended daily
  scanning that only reports when something is flagged (#8).
- **`makepkg` wrapper** (`/usr/share/traur/makepkg-wrapper.sh`): scans the PKGBUILD
  before `build()` runs, for yay and paru, since the ALPM hook fires after the build
  (#16, #19).
- **CI release workflow** (`.github/workflows/release.yml`): release binaries are built
  from the tag on GitHub's runners and published with a `.sha256` file (#10).
  `CONTRIBUTING.md` documents how to verify a download.

### Changed

- Packaging sets the executable bit explicitly and adds `rust` to `makedepends` (#3).
- `.gitignore` covers makepkg output.

## 0.4.1

### Fixed
- **Hook fail-closed**: the ALPM hook now blocks the transaction when scans fail (git timeout, network error, etc.) instead of silently allowing unscanned packages through. Git clone/pull operations have a 30-second timeout to prevent indefinite hangs.

### Added
- **`-bin` source verification** (`bin_source_verification`): cross-references a `-bin` package's declared upstream URL against its `source=()` download domains. Detects fork impersonation when a package claims one GitHub org as upstream but downloads binaries from a different org. Emits `B-BIN-GITHUB-ORG-MISMATCH` (+50) and `B-BIN-DOMAIN-MISMATCH` (+30) behavioral signals.
- **Orphan takeover detection** (`orphan_takeover_analysis`): New feature that deserializes the `Submitter` field from AUR RPC and compares it against the current `Maintainer`. Emits `B-SUBMITTER-CHANGED` (+15, Behavioral) when they differ, and `B-ORPHAN-TAKEOVER` (+50, Behavioral) when combined with a git author change on an established package (>90 days). Detects the acroread-style attack vector where an attacker adopts an orphaned package and injects malicious code.
- `AurPackage` now deserializes `submitter` and `last_modified` from AUR RPC v5 responses.
