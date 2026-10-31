# Contributing to traur

Thanks for helping. This document covers how releases are produced, because
`traur-bin` ships prebuilt binaries and users need to be able to verify them.

## Development

```bash
cargo build --release
cargo test
```

Requirements: a recent stable Rust toolchain. Some features shell out to `git`,
and the ALPM hook binary reads `pacman` output, so an Arch system is needed for
end-to-end hook testing.

## Where things live

| Path | Purpose |
|------|---------|
| `src/features/` | One directory per feature, each implementing the `Feature` trait |
| `src/shared/` | AUR/git/HTTP clients, scoring engine, pattern loader, config |
| `data/patterns.toml` | Regex pattern database, embedded at compile time |
| `hook/` | ALPM hook definition and the `traur-hook` binary |
| `pkg/` | Source and binary PKGBUILDs, kept in sync with the AUR repos |
| `tests/` | Integration tests and PKGBUILD fixtures |

Adding a detection pattern is usually a `data/patterns.toml` entry plus a test.
See `CLAUDE.md` in each directory for the local conventions.

## Release process

Releases are built by CI, not on a developer machine. The workflow is
`.github/workflows/release.yml`.

1. Bump the version in `Cargo.toml`, `pkg/PKGBUILD` and `pkg/PKGBUILD-bin`.
2. Commit and push to `main`.
3. Create and push a tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. The `Release` workflow builds `traur` and `traur-hook` on `ubuntu-24.04`,
   runs `cargo test`, assembles `traur-X.Y.Z-x86_64.tar.gz` with exactly five
   flat entries (`traur`, `traur-hook`, `traur.hook`, `patterns.toml`,
   `LICENSE`), publishes it together with a `.sha256` file, and records the
   hash in the workflow run summary.

### Verifying a release

The attached `traur-X.Y.Z-x86_64.tar.gz.sha256` is produced by the same job that
built the archive. To check a download:

```bash
sha256sum -c traur-X.Y.Z-x86_64.tar.gz.sha256
```

To confirm the artifact really came from the tagged source rather than a local
build, rebuild it yourself and compare the binary's embedded pattern database:

```bash
git checkout vX.Y.Z
cargo build --release --locked
tar tzf traur-X.Y.Z-x86_64.tar.gz   # compare the file list
```

The pattern database is compiled into the binary (`include_str!`), so a binary
built from different source will not report the same `traur signals` output.
Building on a different toolchain or OS changes the bytes, so compare behaviour
rather than expecting a byte-identical binary.

### Publishing to the AUR

After the release artifacts exist, update and push both AUR repos. `pkg/` is the
source of truth; copy into `aur/` and `aur-bin/`, regenerate `.SRCINFO` with
`makepkg --printsrcinfo`, and push to `master` in both.

`pkg/PKGBUILD` uses the GitHub source tarball. `pkg/PKGBUILD-bin` uses the
release tarball, so its `sha256sums` line must match the published `.sha256`.

## Reporting issues

Include the output of `traur scan <package> -v`, your `traur --version`, and the
PKGBUILD if the package is not from the AUR. False positives are especially
useful: the trusted report should stay quiet for ordinary packages.
