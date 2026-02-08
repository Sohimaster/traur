# Hook

ALPM (pacman) hook integration for automatic pre-install scanning.

## Files

- `traur.hook` — ALPM hook definition, installed to `/usr/share/libalpm/hooks/`
- `traur-hook.rs` — Hook binary entry point, compiled as a separate binary

## How it works

1. pacman triggers the hook before any Install or Upgrade transaction
2. ALPM passes matched package names to `traur-hook` via stdin (one per line)
3. `traur-hook` filters out official repo packages using `pacman -Si`
4. Remaining AUR packages are scanned with `traur scan <pkg>`
5. If any package scores SUSPICIOUS or MALICIOUS, hook exits non-zero
6. `AbortOnFail` in the hook definition causes pacman to abort the transaction

## Installation

```bash
sudo install -Dm644 hook/traur.hook /usr/share/libalpm/hooks/traur.hook
```

The hook binary is installed as `/usr/bin/traur-hook` by the package.

## Design decisions

- **Fail open**: If `traur` binary is not found or scan errors out, the hook does NOT block the transaction. Only confirmed suspicious packages block.
- **Official repo skip**: `pacman -Si` is fast and reliable for filtering. AUR packages are not in sync databases.
