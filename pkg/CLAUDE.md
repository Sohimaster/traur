# Package

AUR distribution files. Follows [Rust package guidelines](https://wiki.archlinux.org/title/Rust_package_guidelines).

## PKGBUILDs

- `PKGBUILD` — source package (`traur`). Uses `prepare()` with `--locked`, `build()` with `--frozen`, `check()` with `cargo test --frozen`.
- `PKGBUILD-bin` — binary package (`traur-bin`). Downloads prebuilt tarball from GitHub releases.

Both install LICENSE to `/usr/share/licenses/`.

## Release workflow

Run `/release <version>` in Claude Code. This automates:

1. Validate version, run tests, build release
2. Bump version in Cargo.toml and both PKGBUILDs (reset pkgrel=1)
3. Commit, tag, push to GitHub
4. Create release tarball and GitHub release
5. Update sha256sums, commit, push
6. Sync `aur/` and `aur-bin/` repos (copy PKGBUILD, generate .SRCINFO, push to AUR)

## AUR repos

Both live as subdirectories with their own git remotes:
- `aur/` → `ssh://aur@aur.archlinux.org/traur.git` (master branch)
- `aur-bin/` → `ssh://aur@aur.archlinux.org/traur-bin.git` (master branch)

## Installed files

| File | Path |
|------|------|
| CLI binary | `/usr/bin/traur` |
| Hook binary | `/usr/bin/traur-hook` |
| ALPM hook | `/usr/share/libalpm/hooks/traur.hook` |
| Pattern DB | `/usr/share/traur/patterns.toml` |
| License | `/usr/share/licenses/traur/LICENSE` |
