//! Consent for inconclusive scans, and the `Unknown` state that produces them.
//!
//! When the AUR cannot be reached (CachyOS runs hooks without network access,
//! see issue #24) traur cannot judge a package. It must not guess in either
//! direction: reporting `TRUSTED` would pass an unverified install, and
//! reporting `SUSPICIOUS` would slander a package nobody looked at. The honest
//! answer is "unsure", and the user decides what to do about it.
//!
//! Repeated approvals during an outage are the reason #24 was painful, so the
//! prompt offers "allow for this session". That grant is deliberately narrow:
//!
//! - it applies **only** to `Unknown`. It can never bypass a scored
//!   SUSPICIOUS or MALICIOUS verdict, and it is not a package whitelist.
//! - it is stored root-owned, so an unprivileged user cannot forge consent.
//! - it expires when the condition does: the next successful AUR fetch clears
//!   it, and so does a reboot.
//!
//! Shell-level hooks run as root, so the file is the only state needed. A
//! non-interactive run with no grant blocks, because "nobody answered" is not
//! consent.

use std::path::{Path, PathBuf};

/// Where the session grant lives.
///
/// Under `/var/lib` because it is root state, not a user preference: the hook
/// runs as root and an unprivileged user must not be able to pre-approve a
/// transaction.
pub fn default_grant_path() -> PathBuf {
    PathBuf::from("/var/lib/traur/session-allow")
}

/// Outcome of reading the grant file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantState {
    /// No grant stored.
    None,
    /// A grant exists for the reason recorded with it.
    Active {
        reason: String,
        fingerprint: String,
    },
    /// A grant exists but could not be read; treat as absent, never as consent.
    Unreadable,
}

/// The user's answer to an `Unknown` prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineChoice {
    /// Continue this transaction only.
    AllowOnce,
    /// Continue until the next successful AUR fetch or reboot.
    AllowSession,
    /// Stop.
    Deny,
}

impl OfflineChoice {
    /// Parse a prompt answer. Enter (empty) is `Deny`: #6 asked for Enter to
    /// continue, and #6's answer was that making dismissal easier defeats the
    /// tool. The default stays safe.
    #[allow(dead_code)] // used by traur-hook
    pub fn parse(input: &str) -> OfflineChoice {
        let v = input.trim().to_lowercase();
        match v.as_str() {
            "o" | "once" | "1" => OfflineChoice::AllowOnce,
            "s" | "session" | "2" => OfflineChoice::AllowSession,
            _ => OfflineChoice::Deny,
        }
    }
}

/// Grant/prompt policy, factored out of `main` so it can be tested.
///
/// `interactive` is false when `/dev/tty` could not be opened.
pub fn decide(
    state: &GrantState,
    env_allow: bool,
    interactive: bool,
    ask: impl FnOnce() -> OfflineChoice,
) -> OfflineChoice {
    if env_allow {
        return OfflineChoice::AllowOnce;
    }
    if let GrantState::Active { .. } = state {
        return OfflineChoice::AllowSession;
    }
    if !interactive {
        return OfflineChoice::Deny;
    }
    ask()
}

/// Read the stored grant.
pub fn read_grant(path: &Path) -> GrantState {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let mut reason = String::new();
            let mut fingerprint = String::new();
            for line in contents.lines() {
                if let Some(v) = line.strip_prefix("reason=") {
                    reason = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("fingerprint=") {
                    fingerprint = v.trim().to_string();
                }
            }
            if reason.is_empty() {
                GrantState::Unreadable
            } else {
                GrantState::Active {
                    reason,
                    fingerprint,
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => GrantState::None,
        Err(_) => GrantState::Unreadable,
    }
}

/// Record a session grant. Returns the error if it could not be written, which
/// the caller must treat as "no grant" rather than silently continuing.
pub fn write_grant(path: &Path, reason: &str, fingerprint: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = format!("reason={reason}\nfingerprint={fingerprint}\n");
    std::fs::write(path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Root-only: the grant is consent from the privileged session.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Remove the grant. Called after a successful AUR fetch, because the
/// condition that justified the escape hatch no longer holds, and on `--clear`.
pub fn clear_grant(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Fingerprint of the evidence that was missing, so a grant given for one
/// outage is not silently reused for a different failure.
///
/// Deliberately simple and stable: the set of names whose inputs were missing
/// plus the reason category. Two runs during the same outage produce the same
/// value; a new failure mode produces a different one.
pub fn fingerprint(names: &[String], reason_class: &str) -> String {
    let mut sorted: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let joined = sorted.join(",");
    // Small, dependency-free hash. This is a cache key, not a security control.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in reason_class
        .as_bytes()
        .iter()
        .chain(std::iter::once(&b'|'))
        .chain(joined.as_bytes())
    {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "traur-grant-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("session-allow")
    }

    #[test]
    fn absent_grant_is_none() {
        let p = temp_path("absent");
        assert_eq!(read_grant(&p), GrantState::None);
    }

    #[test]
    fn grant_round_trips() {
        let p = temp_path("roundtrip");
        write_grant(&p, "network unreachable", "abcd").unwrap();
        assert_eq!(
            read_grant(&p),
            GrantState::Active {
                reason: "network unreachable".into(),
                fingerprint: "abcd".into()
            }
        );
        clear_grant(&p).unwrap();
        assert_eq!(read_grant(&p), GrantState::None);
    }

    #[test]
    fn grant_file_is_root_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = temp_path("perms");
            write_grant(&p, "r", "f").unwrap();
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "grant must not be world-writable");
        }
    }

    #[test]
    fn garbage_grant_is_not_consent() {
        let p = temp_path("garbage");
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, "garbage\n").unwrap();
        assert_eq!(read_grant(&p), GrantState::Unreadable);
    }

    #[test]
    fn clear_is_idempotent() {
        let p = temp_path("idem");
        clear_grant(&p).unwrap();
        clear_grant(&p).unwrap();
    }

    #[test]
    fn enter_denies() {
        assert_eq!(OfflineChoice::parse(""), OfflineChoice::Deny);
        assert_eq!(OfflineChoice::parse("n"), OfflineChoice::Deny);
        assert_eq!(OfflineChoice::parse("y"), OfflineChoice::Deny);
    }

    #[test]
    fn explicit_choices_parse() {
        assert_eq!(OfflineChoice::parse("o"), OfflineChoice::AllowOnce);
        assert_eq!(OfflineChoice::parse("once"), OfflineChoice::AllowOnce);
        assert_eq!(OfflineChoice::parse("s"), OfflineChoice::AllowSession);
        assert_eq!(OfflineChoice::parse("SESSION"), OfflineChoice::AllowSession);
    }

    #[test]
    fn active_grant_skips_the_prompt() {
        let state = GrantState::Active {
            reason: "network".into(),
            fingerprint: "x".into(),
        };
        let mut asked = false;
        let choice = decide(&state, false, true, || {
            asked = true;
            OfflineChoice::Deny
        });
        assert_eq!(choice, OfflineChoice::AllowSession);
        assert!(!asked, "a stored grant must not re-prompt");
    }

    #[test]
    fn non_interactive_without_grant_denies() {
        let choice = decide(&GrantState::None, false, false, || OfflineChoice::AllowSession);
        assert_eq!(choice, OfflineChoice::Deny);
    }

    #[test]
    fn unreadable_grant_still_prompts() {
        let mut asked = false;
        let choice = decide(&GrantState::Unreadable, false, true, || {
            asked = true;
            OfflineChoice::AllowOnce
        });
        assert_eq!(choice, OfflineChoice::AllowOnce);
        assert!(asked);
    }

    #[test]
    fn env_escape_hatch_wins() {
        let choice = decide(&GrantState::None, true, false, || OfflineChoice::Deny);
        assert_eq!(choice, OfflineChoice::AllowOnce);
    }

    #[test]
    fn fingerprint_is_order_independent_and_name_sensitive() {
        let a = fingerprint(&["a".into(), "b".into()], "network");
        let b = fingerprint(&["b".into(), "a".into()], "network");
        let c = fingerprint(&["a".into(), "c".into()], "network");
        let d = fingerprint(&["a".into(), "b".into()], "io");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }
}
