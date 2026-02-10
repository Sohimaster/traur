# Hook

ALPM (pacman) hook integration for automatic pre-install scanning.

## Files

- `traur.hook` — ALPM hook definition, installed to `/usr/share/libalpm/hooks/`
- `traur-hook.rs` — Hook binary entry point, compiled as a separate binary

## How it works

1. pacman triggers the hook before any Install or Upgrade transaction
2. ALPM passes matched package names to `traur-hook` via stdin (one per line)
3. `traur-hook` filters out official repo packages using `pacman -Sl`
4. Remaining AUR packages are scanned silently (progress indicator only)
5. After all scans, a tier summary is printed (counts per tier)
6. Decision logic:
   - **All TRUSTED/OK**: prints "All packages look clean.", exits 0 — no prompt
   - **SKETCHY or SUSPICIOUS**: prints detail for flagged packages, prompts [y/N]
   - **MALICIOUS**: prints detail, hard-blocks (exit 1), must whitelist to proceed
   - **Scan errors**: hard-blocks (exit 1), fail-closed
7. `AbortOnFail` in the hook definition causes pacman to abort on exit 1

## Installation

```bash
sudo install -Dm644 hook/traur.hook /usr/share/libalpm/hooks/traur.hook
```

The hook binary is installed as `/usr/bin/traur-hook` by the package.

## Design decisions

- **Silent on clean**: TRUSTED/OK packages produce only a summary count. Detail is shown only for SKETCHY+ packages. No prompt when all packages are clean.
- **Only MALICIOUS hard-blocks**: SKETCHY and SUSPICIOUS prompt the user [y/N] but don't require whitelisting. Only MALICIOUS packages force `traur allow` to proceed.
- **Fail closed**: If a scan errors out (git clone timeout, network failure, etc.), the hook blocks the transaction. Unscanned packages are not allowed through. Git operations have a 30-second timeout to prevent indefinite hangs.
- **Official repo skip**: `pacman -Sl` is fast and reliable for filtering. AUR packages are not in sync databases.
