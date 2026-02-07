# Package

AUR distribution files.

## PKGBUILD

Standard Rust AUR package. Builds two binaries (`traur` and `traur-hook`), installs the ALPM hook and pattern database.

### Release workflow

1. Update `pkgver` in PKGBUILD and `Cargo.toml`
2. Create a git tag: `git tag v0.1.0`
3. Push tag to GitHub: `git push --tags`
4. Update `sha256sums` in PKGBUILD: `makepkg -g`
5. Test locally: `makepkg -si`
6. Update AUR repo:
   ```bash
   cd /path/to/aur/traur
   cp /path/to/traur/pkg/PKGBUILD .
   makepkg --printsrcinfo > .SRCINFO
   git add PKGBUILD .SRCINFO
   git commit -m "Update to v0.1.0"
   git push
   ```

### Installed files

| File | Path |
|------|------|
| CLI binary | `/usr/bin/traur` |
| Hook binary | `/usr/bin/traur-hook` |
| ALPM hook | `/usr/share/libalpm/hooks/traur.hook` |
| Pattern DB | `/usr/share/traur/patterns.toml` |
