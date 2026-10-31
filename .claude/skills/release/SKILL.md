---
name: release
description: Full release workflow for traur. Bumps version, builds, creates GitHub release with binary tarball, updates sha256sums, and pushes to both AUR repos (traur and traur-bin).
disable-model-invocation: true
user-invocable: true
allowed-tools: Bash, Read, Edit, Write, Grep, Glob
argument-hint: <version e.g. 0.3.0>
---

# traur Release Workflow

Release version **$ARGUMENTS** — execute each step sequentially. **Stop immediately if any step fails.**

## Step 0: Validate

1. Confirm `$ARGUMENTS` matches semver format `X.Y.Z` (digits only). If invalid, print usage and stop.
2. Read `Cargo.toml` and extract the current version. Confirm `$ARGUMENTS` differs from it. If same, stop.
3. Run `git status --porcelain` and confirm the main repo working tree is clean. If dirty, show status and stop.
4. Run `git -C aur status --porcelain` and `git -C aur-bin status --porcelain` — both must be clean.

## Step 1: Run tests

```bash
cargo test
```

If any test fails, stop.

## Step 2: Bump versions

Edit these files, replacing the OLD version with `$ARGUMENTS`:

1. **`Cargo.toml`** — change `version = "OLD"` to `version = "$ARGUMENTS"`
2. **`pkg/PKGBUILD`** — change `pkgver=OLD` to `pkgver=$ARGUMENTS` AND set `pkgrel=1`
3. **`pkg/PKGBUILD-bin`** — change `pkgver=OLD` to `pkgver=$ARGUMENTS` AND set `pkgrel=1`

Run `cargo check` to verify Cargo.toml is valid.

## Step 3: Build release

```bash
cargo build --release
```

Verify both binaries exist:
```bash
ls -la target/release/traur target/release/traur-hook
```

## Step 4: Commit, tag, push to GitHub

```bash
git add Cargo.toml Cargo.lock pkg/PKGBUILD pkg/PKGBUILD-bin
git commit -m "bump v$ARGUMENTS"
git tag v$ARGUMENTS
git push origin main
git push origin v$ARGUMENTS
```

## Step 5: Create release tarball

Create a flat tarball (no directory prefix) with all release artifacts:

```bash
tar czf traur-$ARGUMENTS-x86_64.tar.gz \
  -C target/release traur traur-hook \
  -C ../../hook traur.hook traur-scan.service traur-scan.timer makepkg-wrapper.sh \
  -C ../data patterns.toml \
  -C .. LICENSE
```

Verify contents — must list exactly: `traur`, `traur-hook`, `traur.hook`, `traur-scan.service`, `traur-scan.timer`, `makepkg-wrapper.sh`, `patterns.toml`, `LICENSE`

```bash
tar tzf traur-$ARGUMENTS-x86_64.tar.gz
```

If the contents are wrong, delete the tarball and recreate it using absolute paths with `-C`:
```bash
tar czf traur-$ARGUMENTS-x86_64.tar.gz \
  -C "$(pwd)/target/release" traur traur-hook \
  -C "$(pwd)/hook" traur.hook \
  -C "$(pwd)/data" patterns.toml \
  -C "$(pwd)" LICENSE
```

## Step 6: Create GitHub release

```bash
gh release create v$ARGUMENTS \
  traur-$ARGUMENTS-x86_64.tar.gz \
  --title "v$ARGUMENTS" \
  --notes "Release v$ARGUMENTS"
```

Verify:
```bash
gh release view v$ARGUMENTS
```

## Step 7: Update sha256sums — source PKGBUILD

Download the GitHub-generated source tarball and compute its sha256:

```bash
curl -sL "https://github.com/Sohimaster/traur/archive/v$ARGUMENTS.tar.gz" | sha256sum | cut -d' ' -f1
```

Edit `pkg/PKGBUILD` — replace the old `sha256sums=('...')` value with the new hash.

## Step 8: Update sha256sums — binary PKGBUILD

Compute sha256 of the release tarball:

```bash
sha256sum traur-$ARGUMENTS-x86_64.tar.gz | cut -d' ' -f1
```

Edit `pkg/PKGBUILD-bin` — replace the old `sha256sums=('...')` value with the new hash.

## Step 9: Commit and push sha256 updates

```bash
git add pkg/PKGBUILD pkg/PKGBUILD-bin
git commit -m "update sha256sums for v$ARGUMENTS"
git push origin main
```

## Step 10: Push to AUR — source package (traur)

**Ask the user for confirmation before proceeding.**

```bash
cp pkg/PKGBUILD aur/PKGBUILD
cd aur && makepkg --printsrcinfo > .SRCINFO && cd ..
```

Read `aur/.SRCINFO` and verify it looks correct (version matches, deps are right).

```bash
cd aur && git add PKGBUILD .SRCINFO && git commit -m "update to v$ARGUMENTS" && git push origin master && cd ..
```

Note: AUR only accepts pushes to `master`. Verify with `git -C aur branch` first.

## Step 11: Push to AUR — binary package (traur-bin)

**Ask the user for confirmation before proceeding.**

```bash
cp pkg/PKGBUILD-bin aur-bin/PKGBUILD
cd aur-bin && makepkg --printsrcinfo > .SRCINFO && cd ..
```

Read `aur-bin/.SRCINFO` and verify it looks correct.

```bash
cd aur-bin && git add PKGBUILD .SRCINFO && git commit -m "update to v$ARGUMENTS" && git push origin master && cd ..
```

## Step 12: Cleanup and summary

Remove the local tarball:
```bash
rm traur-$ARGUMENTS-x86_64.tar.gz
```

Print summary:
```
Release v$ARGUMENTS complete:
  GitHub: https://github.com/Sohimaster/traur/releases/tag/v$ARGUMENTS
  AUR (traur): pushed
  AUR (traur-bin): pushed
```
