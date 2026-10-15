---
status: accepted
date: 2026-07-07
owner: "@lesault (Andy Younie)"
depends-on: >-
  0016 (agent daily-sync framework — its mechanism is reused for scheduling, Decision 3;
  a separate, independently-governed source from installed_software, even though its floor
  cadence ends up daily too)
related: >-
  0029 (CVE source catalog and ingestion — sibling document from the same split, no direct
  dependency in either direction; ADR-0028's own Relationship table below is the authoritative
  statement of that relationship). The CVE-matching engine that consumes this ADR's output
  is ADR-0023 (vuln correlation engine), `status: accepted` (merged via PR #1914).
  0018/0019 (server-authoritative vulnerability matching / tri-state findings — downstream
  consumer, language-ecosystem regime). 0024-software-licensing-entitlements (PR 1920, open —
  downstream consumer for license/entitlement matching). docs/roadmap.md Issue 18.5 ("SBOM
  Ingest" — companion, import-side of the same capability) and Issue 18.7 (this capability,
  generation-side; added to `docs/roadmap.md` Phase 18, status: Proposed, 2026-07-08).
  1005-headless-platform-use-case-engines (`status: accepted` since 2026-09-07, #4099; proposed when this ADR was written —
  this capability is mechanism under that ADR's Decision-2 test, and stays core/agent-side
  regardless of how the use-case-engine question resolves). The existing vuln_scan plugin
  (agents/plugins/vuln_scan/ — considered and rejected as a host for this capability, Decision 2;
  carries legacy agent-side matching code, cve_rules.hpp/config_checks.hpp, and a
  get_installed_apps()-based inventory action that duplicates installed_apps' richer collector,
  both pending an unscheduled retirement cleanup per ADR-0018). docs/agent-privilege-model.md
  (load-bearing for Decision 1 — the reason per-user-directory collection is rejected in favor
  of machine-scope-only: the agent is designed to run unprivileged, and both a broad and a
  narrow cross-user file-read grant were considered and rejected against that model). The
  filesystem plugin (agents/plugins/filesystem/ — the better precedent for this plugin's internal
  bounded-synchronous-walk conventions than installed_apps, per Decision 2; corrected from an
  earlier, false citation to tar's ProcStreamCollector during a fix pass, 2026-07-08 — this
  frontmatter line was the one place that fix pass missed, caught during governance re-review of
  the fix itself).
  docs/postgres-store-playbook.md and docs/postgres-migration-ladder.md (cited in Decision 8 for
  whoever designs the deferred store schema). docs/roadmap.md Issue 18.1 (Vulnerability Lifecycle
  — the named future home for findings-side history, Decision 7).
supersedes: >-
  docs/adr/0025-cve-matching-strategy.md (retired, uncommitted, never merged — its own Decision
  2b/Decision 3 content, using 0025's own now-unrecoverable section numbering, is split out
  here as this ADR's Decisions 1 and 3 respectively; its own Decision 1 content is proposed as
  an ADR-0023 amendment; its source-catalog content moves to 0029; number 0025 is abandoned,
  not reused, per a live external claim on it)
---

# 0028 — Agent-Side Component Inventory Collection (Bundled & Filesystem-Resident Dependencies)

> **Implementation status (2026-09-07 ADR reconciliation):** Accepted — deferred, not started. Zero `sync_source_component*` files in `agents/core/src`. Deferred, not started; agent-side mechanism — stays core under ADR-1005, not use-case-engine scope (#4099).

> **Naming note (resolved during grill-with-docs review, 2026-07-07):** this capability is called
> the **component inventory**, not "SBOM." **SBOM** (CycloneDX/SPDX) is a standardized *export/import
> document format* — a possible future projection of this data (Decision 6) — not the name of the
> internal collection capability or its storage format. See the `CONTEXT.md` glossary entries for
> both terms.

## Context

CVE-matching research (internal working notes, not committed to this repository) surfaced that a
large, modern CVE surface is invisible to today's collection model: dependencies **bundled inside
an installed application**
(Electron/Chromium embedded in Slack/Teams/Discord/VS Code, vendored `OpenSSL.dll`/`libcrypto.so`,
embedded JARs — the Log4Shell distribution vector, statically-linked libraries) and
**filesystem-resident language dependencies** (`node_modules`, Python venvs/site-packages, on-disk
JARs, Go/Rust module graphs) that no package manager or OS registry enumerates. ADR-0016's
`installed_software` source, by design, only sees what a package manager or OS registry already
lists as a discrete top-level product.

**Scope note (resolved during grill-with-docs review, 2026-07-07):** this ADR closes the
**machine-scope** half of that gap only — bundled libraries and embedded runtimes inside
machine-wide installed applications. It deliberately does **not** reach per-user language
dependencies (a developer's own `~/projects/*/node_modules`, per-user venvs/pip/cargo/go caches),
because doing so would require a new cross-user file-read privilege the agent's security model is
specifically designed to avoid granting (Decision 1). That remains a real, named, accepted gap —
see Decision 1's residual-gap note and `docs/agent-privilege-model.md`.

Closing that gap means recursively walking installed-application directories and known
interpreter/module-store locations and extracting per-component identity — producing a
**component inventory** for the endpoint: the same problem Syft solves for container images,
applied to a live, running host. This is functionally SBOM-*shaped* work, but this ADR does not
produce an SBOM document; "SBOM" is reserved for the standardized CycloneDX/SPDX export/import
artifact a future feature could project this data into or out of (Decision 6).

This was originally scoped as one piece of a larger monolithic CVE-matching ADR (0025, retired —
see `supersedes`). It is split out into its own ADR because:

1. **It has consumers beyond CVE matching.** License/entitlement tracking (the open ADR-0024
   Software Licensing & Entitlements proposal, PR #1920) needs exactly this per-component data;
   supply-chain/attack-surface visibility is a distinct, independently valuable use.
2. **It is *mechanism*, not *interpretation*, under ADR-1005's own test**
   (`docs/adr/1005-headless-platform-use-case-engines.md`, accepted 2026-09-07) — collection stays
   core/agent-side regardless of how the still-open use-case-engine relocation debate resolves for
   CVE-matching *interpretation*. This ADR is safe to accept and build independent of that outcome.
3. **It is a materially different collection posture** from registry/package-manager enumeration —
   deep recursive filesystem and binary introspection, with its own performance and privacy/DPIA
   questions — and deserves independent scrutiny rather than riding in on a CVE-matching decision
   that shouldn't have to resolve them to proceed.

`docs/roadmap.md` **Issue 18.5, "SBOM Ingest,"** already commits to *importing* externally-produced
CycloneDX/SPDX documents (e.g., from a customer's CI pipeline) for component-level vulnerability
linkage. This ADR is the **generation-side companion**: producing the same shape of data
first-party, for endpoints that never had a CI-produced SBOM to import.

## Decision

**Build a bounded, allowlisted filesystem/binary-introspection collection tier as a new agent
plugin, invoked on a new, separately-governed schedule (event-linked trigger plus a daily floor)
that reuses ADR-0016's sync mechanism —
not folded into `installed_software`, and not built as an extension of the existing `vuln_scan`
plugin.**

### 1. What is collected

- **(a) Bundled shared-library introspection.** Recursively scan each installed application's own
  directory tree for `*.dll` / `*.so` / `*.dylib`, reading each file's own identity: Windows
  VERSIONINFO; ELF soname + embedded version strings; and, on macOS, **two distinct paths, not
  one** (found during cross-platform review, 2026-07-07) — a bare `.dylib` has **no `Info.plist`**
  (that's bundle-resource metadata, not something a standalone dylib file carries), so its only
  reliable identity is Mach-O load-command data (`LC_ID_DYLIB`'s install name +
  `current_version`/`compatibility_version`), while a `.framework` bundle (`Contents/Info.plist` or
  `Versions/*/Resources/Info.plist`, `CFBundleShortVersionString`/`CFBundleVersion`) is read when
  the dependency ships as a framework, falling back to `LC_ID_DYLIB` if the plist is missing or
  stripped (increasingly common under the hardened runtime). A third-party app shipping its own
  `libcrypto.so`/`OpenSSL.dll`/`zlib1.dll` is then identified on the *bundled library's* own
  identity, not just the parent app's.
- **(b) Embedded-runtime (Electron/Chromium/Node) detection.** Detect Electron by `*.asar`
  archives inside `Contents/Resources/` (macOS) or the app's install root (Windows/Linux), **not**
  by a single fixed framework-bundle name — shipping apps commonly rename
  `Electron Framework.framework` to `<AppName> Framework.framework` specifically to avoid
  Gatekeeper/`CFBundleIdentifier` collisions across co-installed Electron apps (found during
  cross-platform review), so detection matches on the structural shape
  (`Contents/Frameworks/*Framework.framework/Versions/*/Resources/Info.plist`, which the walk must
  explicitly descend into `Contents/Frameworks/` to reach) or the `.asar` signal, never the literal
  default name alone. Extract the bundled Chromium and Node versions from the embedded release
  manifest. This is the single largest silent-false-negative class on a corporate fleet (Slack,
  Teams, Discord, VS Code) — the parent app's own version reflects none of the embedded runtime's
  CVE surface.
- **(c) Go/Rust static-binary buildinfo.** Extract embedded dependency graphs from Go binaries
  (`go version -m` / `debug/buildinfo`) and Rust binaries carrying a buildinfo section — a free,
  high-fidelity dependency inventory with no filesystem walk required, genuinely OS-agnostic for
  ELF/Mach-O/PE Go binaries. **Windows robustness note** (found during cross-platform review): this
  read can flake under antivirus/EDR file-lock contention on Windows specifically; a failed read
  here is an ordinary case for Decision 4's failure posture (UNKNOWN/needs-review), not a design
  change.
- **(d) Language manifest/lockfile + interpreter-store discovery — machine-wide locations only.**
  Under allowlisted, **machine-scope** roots only (a global Node/npm install's own `node_modules`,
  a system-wide Python `site-packages`, a machine-wide interpreter's module store), discover and
  parse dependency manifests/lockfiles (`package-lock.json`/`yarn.lock`,
  `requirements.txt`/`Pipfile.lock`/`poetry.lock`, `go.sum`, `Gemfile.lock`, `pom.xml`/on-disk JARs).
  **Per-user locations are explicitly out of scope** — see the scope note below. **Disambiguation
  (found during unhappy-path review, 2026-07-07):** a machine-wide installed application that
  bundles its *own* `node_modules` inside its install directory (a common Electron pattern —
  `<App>/Resources/app/node_modules`) is machine-scope by anchoring (Decision 1's item (2)/(3)) —
  it is walked as part of that app's own anchored root, exactly like item (a)'s bundled-library
  scan, and must **not** be excluded by any per-user-looking-path heuristic (e.g., pattern-matching
  on the literal string `node_modules`) that a future implementation might reach for. The per-user
  exclusion in this ADR is about *directory ownership/location* (a user's home directory), never
  about a directory *name* — an app-embedded `node_modules` under a machine-wide, root-owned
  install path is in scope precisely because of where it lives, not what it's called.

  **A genuine installation is recorded in full, including private/internal-source dependencies —
  no identity redaction or exclusion (resolved during grill-with-docs review, 2026-07-07).** A
  lockfile entry resolving to a private registry or internal git remote (a scoped internal npm
  package, a private PyPI/Maven artifact) will never match a public CVE source, but that is a
  reason it won't *appear in a vulnerability report* — not a reason to omit it from the component
  inventory. Excluding it would also cut against this ADR's own broader-than-CVE-matching
  rationale (Context, point 1: license/entitlement and supply-chain/attack-surface value) and
  against a plausible future capability: an internal, company-namespace vulnerability repository
  matching against exactly this data. **Deliberately deferred, not decided now:** if that future
  capability is ever built, any anonymization/redaction it needs is designed at that time, against
  a concrete consumer — not speculatively baked into collection today.

  **One narrow, unconditional safety net, independent of the above — an enumeration, explicitly
  acknowledged as incomplete rather than presented as exhaustive (re-scoped following hardening-round
  re-review, 2026-07-07).** Any resolved dependency URL is stripped of embedded userinfo/credentials
  (`user:token@...`) and of known auth query-string parameters before it is emitted, regardless of
  whether the source is public or private. The known-parameter list must cover both simple token
  params (`?token=`, `?api_key=`) **and common presigned-URL signature schemes**, which the original
  hardening pass missed: AWS SigV4 (`X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Security-Token`),
  Azure SAS (`sig`, `se`, `sp`, `sv`), and GCS (`X-Goog-Signature`, `X-Goog-Credential`). **This
  enumeration cannot be exhaustive** — it is a defense-in-depth denylist of currently-known
  conventions, not a proof that every possible URL-embedded credential scheme is covered, and should
  be extended as new conventions are identified rather than treated as a closed, completed list.
  This is not identity redaction — the package name, version, and source *are* recorded — it is a
  secrets-hygiene rule against literally copying a credential that happens to be embedded in a URL
  string into a central store, and it applies unconditionally rather than depending on a
  public/private classification being correct. **Explicitly not covered by this safety net** (a
  named residual, not an assumed-covered case): secrets configured outside the resolved URL
  entirely — `.npmrc`/`pip.conf`-style auth stored as separate config values — since those files are
  not part of this ADR's collection surface (per-user config locations in particular are already
  out of scope, per the scope note below) and should not be assumed covered by this URL-scoped rule.

  **Dependency-origin tag: public-registry-resolved vs. private/internal-source, on every
  lockfile-derived record** (renamed from an earlier "provenance tag" during governance review,
  2026-07-07 — "provenance" collided with an unrelated HIGH/MEDIUM/LOW source-reliability ranking
  used elsewhere in this workstream's matching design, not yet committed to any ADR at the time of
  this writing). Not for exclusion — for efficiency and forward-compatibility: the matching engine (ADR-0023) can skip a
  futile OSV/GHSA query for a private-source entry it already knows can't match, and the same tag
  is exactly the join key a future
  internal-vulnerability-repository capability would need. One tag, two consumers, decided now; the
  future consumer itself is not. **Known limitation, accepted rather than solved here** (found
  during unhappy-path review): this classification is a collection-time heuristic (resolved-host-
  based) with no reconciliation step — an enterprise pull-through mirror (Artifactory/Nexus-style)
  serving genuinely public packages under an internal-looking URL will be tagged
  `private_or_internal` and have its (real, matchable) public CVE exposure silently skipped by the
  matching engine's efficiency optimization above. Accepted as a known heuristic limitation for this
  ADR; a future refinement could re-check a `private_or_internal`-tagged package's bare name against
  the public ecosystem registry as a cheap disambiguation, but that is not designed here.

**Anchoring the walk to known install roots — not a blind machine-wide scan.** "Recursively scan
each installed application's own directory tree" (a) needs a starting point, and a generic
recursive walk under machine-wide roots (`Program Files`, `/opt`, `/usr/local`, `/Applications`)
bounded only by depth/size/time is both wasteful (re-scanning large swaths of disk every cycle) and
imprecise (a found library can't always be attributed to the app that shipped it). Verified against
`agents/plugins/installed_apps/src/`: it does not currently capture `InstallLocation`, `.app`
bundle paths, or use package-manager file-manifest queries — so this needs a small, explicit
addition, not an assumption:

1. **Linux (primary mechanism, not a walk at all):** query `dpkg -L <package>` / `rpm -ql <package>`
   for each already-known installed package — an **exact file manifest**, no directory walk needed,
   with unambiguous attribution (the manifest tells you which package a file belongs to). Use the
   **batch form** (`dpkg-query -L $(dpkg-query -W -f='${Package}\n')` / `rpm -qla`), not a naive
   per-package spawn loop — a full desktop image can carry thousands of packages, and per-package
   process/DB-read overhead adds up (found during cross-platform review). **Illustrative example
   only, not a literal implementation contract:** the command-substitution form shown isn't
   argv-length-safe on a host with a very large package count (risks `E2BIG`/truncation); the
   implementing PR should batch through the plugin's own dispatch rather than shell out with a full
   package-name list in one argv, matching the precedent `sync_source_installed_software.cpp`
   already sets. A truncated/failed batch degrades to UNKNOWN entries via this ADR's own collection-
   failure fallback (Decision 4), not silently wrong data, but should be avoided regardless. The manifest mixes
   directories with files and can be empty for virtual/meta packages; filter to regular files before
   checking extensions, and treat an empty manifest as "nothing bundled," not an error, for a
   package with zero files by design. A generic bounded directory walk under `/opt`/`/usr/local` is
   the **fallback only**, for non-packaged software with no package manifest (the same "hard tail"
   case this workstream's matching design elsewhere names) — and also the fallback for a
   **partially-installed package** (an interrupted `dpkg`/`rpm` transaction where the database says
   installed but files are missing/corrupted): a failed manifest query at the *package* level is
   itself emitted as UNKNOWN, per Decision 4, never silently treated as "no bundled libraries."
2. **Windows/macOS:** anchor each walk to the app's registry `InstallLocation` or `.app` bundle
   path — both are cheap, already-available-in-principle facts (the uninstall-key scan and the
   `/Applications` bundle scan already read the surrounding data), just not currently captured.
   **This is a small, essentially-free addition to `installed_apps`/`sync_source_installed_software`
   (ADR-0016's territory), not new expensive collection** — reading one more registry value or
   recording the bundle path already being iterated over. Extending it there (rather than
   re-querying independently inside `component_inventory`) also means both consumers benefit from
   one collection pass, consistent with Decision 5's shared-schema spirit. **`InstallLocation` is
   not always present or correct** (found during cross-platform review): it is commonly empty for
   NSIS/Inno installers that never set the property, can be stale after an in-place move, and is
   **structurally absent for MSIX-packaged apps**, which use a separate `Get-AppxPackage
   InstallLocation`/`PackageManager` enumeration, not the classic Uninstall registry key at all —
   MSIX anchoring is out of scope for this ADR (falls through to the residual walk, item 3, same as
   any other anchor-miss) rather than a mechanism this ADR designs.
3. A generic machine-wide directory walk (the original Decision 1 framing, depth/size/time-bounded)
   is the **residual fallback path**, not the default mechanism, for whatever (1) and (2) don't
   anchor.

**Symlink containment — a hard requirement, not an implementation detail (added following Gate 2
security review, 2026-07-07; mechanism sharpened following the 2026-07-07 hardening-round
re-review, which found the original wording named the requirement without naming a mechanism that
actually closes it).** Every anchored or fallback walk must **resolve and contain**: never traverse
a directory symlink whose resolved target escapes the walk's own anchored root (an app's install
directory, or the allowlisted machine-wide fallback root). Without this, a single symlink planted
inside an allowlisted app directory — accidentally or adversarially — and pointing at a per-user
home directory would let the walk read exactly the per-user data Decision 1's entire
rejected-privilege-grant argument assumes is unreachable, and would do so under whichever privileged
account currently runs this plugin (root on macOS, LocalSystem on Windows today — see the DPIA
posture note below), not the intended unprivileged account. This is not a hypothetical
implementation nicety: it is the specific mechanism by which this ADR's central machine-scope-only
safety claim could be silently false.

**Two implementation-level gaps in the original wording, closed here rather than left for code
review to discover:** (a) "resolve and contain" is not a TOCTOU-safe operation as a path-string
`realpath()`-then-open pattern — implementation must walk via directory file descriptors
(`openat()` with `O_NOFOLLOW` per path segment on Unix; the equivalent reparse-point-aware open on
Windows), never resolve a string path and separately open it, which leaves a race window between
check and use. (b) containment applies to **every intermediate path segment the walk descends
through**, not only the final component under inspection — an implementation that only checks
whether the last element of a path is a symlink, while silently following an escaping symlink two
levels up, satisfies the letter of "resolve and contain" while missing its point entirely.

**The reverse direction matters equally:** the walk's own anchored root (an `InstallLocation`, an
`.app` path, an allowlisted fallback root) must itself be verified as not being a symlink/junction
that resolves outside the expected machine-wide location before the walk begins — an app relocated
behind a redirect could otherwise smuggle a per-user path in as the walk's own starting point. **A
path excluded by containment is emitted as UNKNOWN/needs-review, exactly like any other unreadable
item under Decision 4 — never a silent skip.** Silently skipping a contained-off path would
reintroduce the identical class of false "clean" result Decision 4 exists to prevent, just via a
different unreadable-item pathway; legitimate machine-wide packaging that uses symlinks internally
(e.g., Linux's `/usr/lib` alternatives system, macOS Framework `Current ->` version links) needs
the containment check scoped to escapes of the anchored root, not to symlinks in general, so
ordinary in-root version symlinks are followed and resolved normally.

**Open cross-document dependency — must land before or alongside implementation, not after (raised
independently by three reviewers — architect, plugin-developer, unhappy-path — during the
2026-07-07 governance pass, converging on the same recommendation).** The `InstallLocation`/
bundle-path addition in (2) is a small change to ADR-0016's collection scope, but doesn't have a
clean home in the current three-document split (this ADR, the CVE-source-catalog ADR, and
ADR-0023) — it's collection enrichment for *existing* identity fields, not new
component-inventory collection. **Sequencing matters, not just ownership:** if `component_inventory`
implementation proceeds before this lands, the "fallback" generic walk (item 3) silently becomes the
*default* mechanism for every Windows/macOS endpoint, inheriting all of its named costs (wasteful,
imprecise attribution) as normal operation rather than an edge case — this is a real implementation
blocker, not a documentation nicety. **Recommended landing spot, per architect review:** a new dated
amendment section on ADR-0016 itself, following the exact precedent of ADR-0016's own `device_ci`
(2026-06-30) and blob-v2 (2026-07-02) in-place amendments — not a new standalone ADR, and not a bare
tracked issue with no document of record.

**Residual gaps, owned explicitly rather than hidden:**
1. **Statically-linked libraries** compiled directly into a single stripped binary remain largely
   unrecoverable by any general mechanism.
2. **Per-user language dependencies are not collected at all in this ADR** — a developer's own
   `~/projects/*/node_modules`, per-user Python venvs, and per-user `pip`/`npm`/`conda`/`cargo`
   installs are invisible to this tier, by deliberate design (see the scope note immediately
   below), not oversight. This is a materially larger gap than (1) and is the direct, accepted
   cost of not granting a new cross-user file-read privilege.

**Scope is machine-wide only — no new privilege grant, full stop.** `docs/agent-privilege-model.md`
is explicit that the agent is *designed* to run under a dedicated **unprivileged** account (`yuzu`
on Linux; the intended `NT SERVICE\YuzuAgent` on Windows, though currently LocalSystem only due to
a tracked bug, #1442) specifically so a compromised agent or plugin has a small, auditable blast
radius; macOS currently runs as root, which `docs/agent-privilege-model.md` itself flags as a state
the team wants to close, not a foundation to build on (that doc cites #1455 for this; verified during
adversarial review, 2026-07-08, that #1455's own scope is actually the macOS TAR Endpoint-Security
entitlement/notarization pipeline, not de-rooting the agent — the substantive claim here, that macOS
runs as root today and shouldn't be built on, holds regardless; `agent-privilege-model.md` is the
citation to correct, not this ADR's reliance on it). Reaching another logged-in user's home directory
(typically `700`/`750` permissions on Unix, owner-only) is not just a policy question but a
**technical one** — the unprivileged service account cannot read those bytes without a new grant.

Two options were considered and **both rejected**, in favor of machine-scope only:
- **A broad grant** (read access to every user's home directory) — an obvious non-starter; this is
  close to the maximum blast-radius outcome the entire privilege model exists to prevent, turning a
  compromised plugin into a fleet-wide arbitrary-file-read primitive.
- **A narrow grant scoped to named dependency-store paths** (`~/.npm`, `~/.cache/pip`, `~/.cargo`,
  `~/go/pkg`, `~/AppData/Roaming/npm`) — looks safer but isn't: those specific paths are
  disproportionately likely to hold **credentials**, not just dependency metadata (`~/.npmrc`
  commonly carries registry auth tokens; `~/.cargo/credentials.toml` literally stores crates.io API
  tokens; pip config can carry basic-auth index URLs). Scoping the *path* narrowly does not scope
  the *sensitivity* narrowly — this would grant cross-user read access precisely to the directories
  most likely to contain secrets, for the least coverage benefit. Rejected on the same "narrowest
  grant that works" principle the privilege model itself is built on — this isn't the narrowest
  grant that works, it's a grant that happens to look narrow.

**Consequence:** per-user language-dependency discovery is out of scope for this ADR, full stop —
not deferred pending a future privilege decision within this document, but explicitly punted to
a future ADR that would have to justify and design a fundamentally different architecture (see
Alternatives considered — a session-scoped helper running as the interactive user is the most
likely correct shape, not a service-account privilege grant) if the business ever decides the
coverage is worth pursuing. This ADR's value is preserved on the case that matters most for Yuzu's
actual customer base: enterprise-managed fleets overwhelmingly install software machine-wide via
MSI/management tooling, not per-user via individual developers' own package-manager invocations —
the machine-scope collection in (a)–(d) above covers that case fully.

**Reuse bound-checking primitives from the existing `filesystem` plugin — partial reuse, not full
reuse, and not free reuse (sharpened following Gate 3 plugin-architecture review, 2026-07-07).**
`agents/plugins/filesystem/src/filesystem_plugin.cpp` already implements the kind of
budget-respecting walk safety this tier needs, but **no shared home for these constants exists
today, and `filesystem`'s own values are inconsistent between actions** (`max_depth` clamped to 20
in one action, 10 in another — per-action local bounds, plain runtime `int`s clamped by an `if`
check, not `constexpr` as an earlier draft claimed (corrected following adversarial review,
2026-07-08) — not a single source of truth).
"Reuse" therefore requires a prerequisite step: extracting and reconciling `filesystem`'s clamps
into one real shared location (`sdk/include/yuzu/` or `agents/shared/`, not a plugin-to-plugin
`#include`, which would create exactly the awkward coupling this split is meant to avoid) and
re-testing `filesystem` against the reconciled values, *before* `component_inventory` can depend on
it. **What is shared, once that groundwork lands: the bound-checking constants/helpers** (depth
clamps, entry caps, size ceilings). **What is not shared: the walk's domain logic** — `filesystem`'s
actions are general-purpose, operator/forensics-facing primitives (`list_dir`, `find_by_hash`,
content search/replace) individually invoked for ad-hoc investigation; `component_inventory`'s walk
is a passive, domain-specific loop that decides *what to do* per entry (`*.asar` → Electron;
`package-lock.json` → parse as an npm lockfile; a `.dll`/`.so`/`.dylib` → read VERSIONINFO/soname/
Mach-O header) — that interpretation belongs in the new plugin, not composed out of `filesystem`'s
generic actions, for the same reason CVE-matching interpretation doesn't belong in `installed_apps`.
**Decompression-bomb ceilings are a distinct, additional budget this tier needs that `filesystem`'s
walk-bound constants don't cover at all** (found during Gate 2 security review): JARs are ZIP
archives (classic zip-bomb applicable) and a malformed `.asar` header can drive over-allocation even
though the format is nominally uncompressed — max-decompressed-size, max-entry-count, and a
compression-ratio ceiling for JAR/`.asar` parsing are named here as required budgets, alongside the
filesystem-walk depth/size/time budget, in Decision 8's deferred operational detail.

**New untrusted-input parsing surface — fuzz coverage is a ship precondition on all three
platforms, not a follow-up, and not only where the plugin runs privileged (broadened following
hardening-round re-review, 2026-07-07 — the original wording gated this only on privilege level).**
PE VERSIONINFO, ELF, Mach-O, `.asar`, and JAR-as-ZIP parsing are new parsers over
attacker-influenceable input (a malicious or merely malformed binary/archive sitting on an
endpoint), comparable in kind to what the recently-added ClusterFuzzLite harnesses (PR #1885)
already target for other untrusted-input paths in this codebase. This matters most acutely where
the plugin runs **in-process, privileged** today (root on macOS, LocalSystem on Windows, per the
DPIA posture note below) — a parser memory-safety bug there is a root/LocalSystem-level issue, not
a `yuzu`-scoped one — **but the same parser code also runs on Linux, where the agent is genuinely
unprivileged; a memory-safety bug there is still remote-code-execution inside the `yuzu` process,
a real credential-theft/lateral-movement risk per `docs/agent-privilege-model.md`, just not a
root-level one.** Gating the precondition only on the privileged platforms would let unfuzzed
parser code ship first on Linux. Whichever new build-graph dependency implementation adds for
PE/ELF/Mach-O/ZIP parsing should be named explicitly when Decision 8's implementation detail is
filled in, and fuzz-harness coverage for each new parser is a precondition for this plugin shipping
on **any** platform, not a "shortly after" follow-up and not conditional on privilege tier.

**DPIA posture, lightened by this reversal — with one residual risk named, not assumed away.**
Because collection stays machine-scope — the same class of location `installed_software` already
reads (`HKLM`-equivalent, `/Applications`, `/opt`, `/usr/local`, never a per-user profile) — this
tier does **not** reopen the co-determination question ADR-0016 §8 deliberately closed for
`installed_software`, unlike the `device_ci` precedent (which needed its own review because it
collects device-persistent identifiers, a different concern that machine-scope alone doesn't
resolve). **The symlink-containment requirement above exists precisely because this reasoning is
only as strong as the walk actually staying inside machine-scope roots** — and today, on macOS
(root) and Windows (LocalSystem, #1442), a containment gap would be exploited with root/LocalSystem
read access, not the intended unprivileged account (found during cross-platform review, sharpening
a risk this ADR already names for the *rejected per-user* question but had not yet stated for this
walk specifically). A lighter confirmatory security review is still warranted before shipping
(Decision 8) — recursive filesystem/binary introspection is still a new class of endpoint operation
even at machine scope, manifest/lockfile contents can still reveal a customer's internal dependency
naming (a distinct SOC 2 Confidentiality-criterion question, separate from the personal-data/
co-determination analysis above — see Decision 8), and this data's future retention/audit-defensibility
relationship to `docs/roadmap.md` Issue 18.1 is itself only partially resolved (Decision 7) — but
none of this is gated on a full works-council/co-determination sign-off, because the fact pattern
that would have required one (crossing into per-user data) has been designed out.

### 2. Where it lives: a new plugin (`component_inventory`), not an extension of `vuln_scan`

Every existing OS-specific collector in this codebase is a **plugin** behind the stable C ABI —
`installed_apps`, `msi_packages`, `hardware`, `vuln_scan` — with agent-core reduced to thin
scheduling/parsing glue. Confirmed directly in code: `sync_source_installed_software.cpp` does
**no** collection logic itself; it calls the `installed_apps` plugin in-process via
`LocalDispatcher`, invokes its `list_inventory` action, and parses the pipe-delimited result. This
ADR follows the same shape at the agent-core/plugin boundary: a new plugin, **`component_inventory`**,
does the actual filesystem walking, binary parsing, and Electron/buildinfo detection from Decision
1; a new, thin `sync_source_component_inventory.cpp` (agent-core) schedules it and reports results.

**Internal-conventions precedent: model this plugin's bounded-walk safety on `filesystem`, not on
`installed_apps` (corrected following Gate 3 plugin-architecture review, 2026-07-07; the citation
itself corrected following adversarial review, 2026-07-08, which found the original `tar`
citation below doesn't actually solve the problem it was cited for).** `installed_apps` is the
right precedent for the agent-core/plugin *boundary* shape above (thin sync-source glue calling
into a plugin action), but the wrong precedent for this plugin's *internal* conventions —
`installed_apps` is a simple buffer-and-return collector, while this plugin's actual engineering
risk is a `write_output` call that is synchronous with no progress/cancellation hook, so a
multi-thousand-file walk needs to fit inside whatever command-timeout budget applies. **`tar`'s
`ProcStreamCollector` (`docs/tar-module-loads.md`) does not solve this**, and is not the right
precedent for it: checked directly against `tar_proc_stream.hpp`, it is a persistent, event-driven
collector that runs continuously and is drained on a tick, never invoked synchronously inside one
command dispatch — the synchronous-timeout-budget problem this plugin actually faces doesn't arise
for it by construction. The right precedent is `filesystem_plugin.cpp`
(`agents/plugins/filesystem/src/`), which already does exactly this: a bounded, synchronous
recursive walk returning through `write_output` within depth/size/time budgets (see the
bound-checking-primitives reuse discussion above) — the shape this plugin's own walk needs, not
`tar`'s streaming model. Separately, `sync_source_installed_software.cpp`'s existing behavior of
dropping the **entire cycle** on capture-cap truncation (line ~306 in that file) is a materially
bigger risk here given this tier's higher cardinality and heterogeneity — a truncated
component-inventory cycle should not silently look like a small, complete one (see Decision 4's
failure posture, which now names this explicitly). Whoever implements Decision 8 should read
`filesystem`'s bounded-walk conventions before `installed_apps`'s simpler ones.

**Considered and rejected: extend the existing `vuln_scan` plugin instead of creating a new one.**
Domain proximity makes this the obvious first instinct — this data feeds CVE matching, same as
`vuln_scan`'s original purpose — but inspecting `agents/plugins/vuln_scan/src/` directly shows it
is the wrong foundation to build on right now:

- `vuln_scan_plugin.cpp` still `#include`s and actively calls into `cve_rules.hpp` (189 lines) and
  `config_checks.hpp` (503 lines) — the pre-ADR-0018 agent-side hardcoded-rule matcher and config
  checks, which ADR-0018 already decided must be retired ("the agent collects, never decides") but
  which the retirement cleanup (memory: "STILL OWED") has not yet removed from `dev`. Its
  registered actions today are `scan`, `cve_scan`, `config_scan`, `summary`, `inventory` — a mix
  that is itself mid-retirement, not a stable surface.
- Its existing **`inventory` action already duplicates, poorly, what `installed_apps` does
  better**: it calls a plugin-local `get_installed_apps()` and emits bare `name|version` pairs —
  no epoch, release, architecture, or source-package — while `installed_apps`' `list_inventory`
  (the one daily-sync actually uses, ADR-0016 §2026-07-02) emits the full 12-field blob. This
  `inventory` action is functionally dead weight, not a foundation to extend.
- Plugin boundaries in this codebase track **collection domain**, not "anything vulnerability-
  adjacent" — `installed_apps` owns registry/package-manager identity, `hardware` owns hardware
  facts, `msi_packages` owns MSI-specific detail. Component inventory (deep filesystem/binary
  introspection) is its own domain, distinct from `vuln_scan`'s original domain (rule-based
  matching, now stripped down and mid-cleanup) by the same logic that puts `installed_apps` and
  `hardware` in separate plugins rather than one "endpoint facts" mega-plugin.
- Building new, forward-looking, privacy-sensitive capability (Decision 8's open DPIA question)
  inside a plugin that is simultaneously carrying ~700 lines of code slated for deletion on an
  unscheduled timeline is unnecessary coupling — a future `vuln_scan` cleanup PR would need to be
  careful not to disturb the new capability, and vice versa, for no architectural benefit.
- A dedicated plugin can be **independently toggled**, which matters both pending Decision 8's
  confirmatory security review and — more durably — as a **permanent, standing customer control,
  not merely a temporary DPIA-pending gate** (strengthened following enterprise-readiness review,
  2026-07-07, which flagged the original framing as a gap: the existing `--inventory-disable` flag
  gates the *entire* daily-sync thread all-or-nothing, so a customer who wants `installed_software`/
  `device_ci` but not deep filesystem/lockfile introspection of internal dependency names has no
  lever today). **This ADR commits to a dedicated, permanent, documented disable flag scoped to
  `component_inventory` specifically**, independent of and in addition to `--inventory-disable` —
  this is the customer-assurance answer to Decision 1(d)'s affirmative full-recording decision, not
  an operator convenience. The exact flag name is Decision 8's implementation detail; that it exists,
  is permanent, and is documented (with an upgrade note — see Ratification) is decided here.
  Building this as its own plugin, rather than folding into `vuln_scan`, is also what makes that
  toggle possible without disturbing `vuln_scan`'s own, separately-tracked retirement.
- **A YAML `InstructionDefinition` is required for the on-demand action path, not optional (found
  during Gate 3 plugin-architecture review).** Confirmed against precedent: every operator-facing
  action in this codebase has a content-plane definition (`installed_apps`' `list`/`query`/
  `list_per_user` each have one in `content/definitions/installed_apps.yaml`; its sync-source-only
  `list_inventory` correctly has none, since it's never operator-invoked). Because Decision 2's
  on-demand path is explicitly operator/agentic-worker-invokable (`CommandRequest`/
  `execute_instruction`, Scope-targetable), it needs its own YAML definition and result-column list
  the same way `vuln_scan`'s on-demand actions do — this is a required deliverable of Issue 18.7,
  not an optional nicety, and depends on Decision 8's field-list/action-name detail before it can be
  authored.

**Resolution: `vuln_scan` survives as an operator-facing command name, with zero vestigial plugin
code, by retiring the plugin but re-pointing one of its instruction definitions (decided
2026-07-07; scope corrected following hardening-round re-review, 2026-07-07 — the original wording
addressed only 1 of `vuln_scan.yaml`'s 5 definitions and asserted schema compatibility it had not
actually checked).** @lesault (Andy Younie), this domain's owner (see Ownership, below), wants
`vuln_scan scan` to keep working as a familiar operator/agentic-worker entry point that kicks off a
fresh component inventory and feeds it to CVE matching — even though the `vuln_scan` *plugin* (the
C++ code carrying `cve_rules.hpp`/`config_checks.hpp`) is being retired, per Decision 2's own
reasoning above, as its own separately-scoped cleanup. The underlying mechanism is sound: an
instruction's operator-facing identity (`metadata.id`, e.g. `security.vuln_scan.scan`) is **already
fully decoupled** from which plugin/action it dispatches to (`spec.execution.plugin`/
`spec.execution.action`) — confirmed by precedent, since `installed_apps`' own definition id is
`crossplatform.software.inventory`, not `installed_apps.list`; the id namespace was never tied to
the plugin name. But that decoupling only covers the *execution target*, not the rest of the
definition, and `content/definitions/vuln_scan.yaml` needs more than a two-field edit:

1. **`vuln_scan.yaml` defines five `InstructionDefinition`s** (`scan`, `cve_scan`, `config_scan`,
   `summary`, `inventory`), each with `execution.plugin: vuln_scan` and
   `compatibility.requiredPlugins: [vuln_scan]` — not one. **Only `scan` is repointed and kept.**
   `cve_scan` and `config_scan` depend directly on the code being deleted
   (`cve_rules.hpp`/`config_checks.hpp`) and have no successor action to repoint to — they are
   **retired along with the plugin**, not repointed. `inventory` already duplicates, more crudely,
   what `installed_apps`' `list_inventory` does (Decision 2's rejection analysis above) and is
   likewise **retired**, not repointed. `summary` (which aggregates `cve_scan`+`config_scan`
   findings) has no remaining inputs once those two are retired and is **retired** with them. This
   is an explicit disposition for all five, not an assumption that "the plugin retirement" silently
   handles the other four.
2. **`result.columns` and the `visualization` block are not incidental metadata — they gate display
   and charting, not JSON parsing (re-attributed following adversarial review, 2026-07-08 — the
   original wording named the wrong mechanism).** `vuln_scan.yaml`'s `scan` definition currently
   declares a CVE-finding result shape (severity/category/title/detail-style columns, a
   severity-keyed pie chart). Checked directly against code: `server/core/src/result_envelope.cpp`'s
   `parse_result` parses agent output as **JSON** (a `{"columns":[...], "rows":[...]}` shape,
   falling back to wrapping non-JSON output into a single raw-text `output` column) and its
   `build_type_map` is consumed only by `validate_types` for post-hoc type checking — neither does
   positional delimited parsing, and `parse_result`'s only caller in the codebase is
   `policy_evaluator.cpp`, not any vuln_scan display path. The actual positional coupling lives in
   `server/core/src/visualization_engine.cpp`: `split_fields` splits the plugin's pipe-delimited
   output line-by-line, and `labelField`/`valueField` (and their siblings) index into the result **by
   numeric position** (`field_or_empty(fields, idx)`) — so a different field order silently breaks
   the chart. `component_inventory`'s actual output (Decision 2's `kind`/identity/
   `dependency_origin`-tagged component-record shape) does not match `vuln_scan.yaml`'s current
   schema or field order at all. **The repointed `scan` definition's `result.columns`
   (naming/typing/export) and `visualization` block (`labelField`/`valueField` positional indices)
   must both be fully rewritten to match `component_inventory`'s real field list, not left as-is** —
   this is tracked as part of Decision 8's deferred exact-field-list work, not a detail this ADR can
   defer past acknowledging it's required.
3. **`compatibility.requiredPlugins: [vuln_scan]` must also be updated to `[component_inventory]`**
   on the repointed `scan` definition — otherwise the definition nominally requires a plugin that
   no longer exists once retirement completes.
4. **RBAC re-audit before repointing, not an assumption that same-id implies same-risk-tier (found
   during hardening-round re-review).** Keeping `security.vuln_scan.scan`'s `metadata.id` unchanged
   preserves whatever RBAC grants currently exist against that id — but the capability it authorizes
   changes completely, from legacy rule-based scanning to a privileged (root/LocalSystem today),
   machine-wide filesystem/binary-introspection walk feeding a store that carries internal
   dependency-name data (a named SOC 2 Confidentiality-criterion concern, Decision 1 above). Any
   principal or role currently holding execute permission on the old id would silently inherit the
   new, materially more invasive capability with no re-review. **A one-time audit of which
   roles/principals hold execute permission on `security.vuln_scan.scan`, confirming the grant is
   still appropriate for the new capability, is part of the coordinated cleanup (phase (ii) below),
   not an assumption.**

**Fleet-rollout ordering — a real skew risk, not covered by calling this "one coordinated change"
(found during hardening-round re-review).** A server-side `InstructionDefinition` repoint takes
effect fleet-wide instantly (content plane); agent binary upgrades (which add or remove the
`component_inventory`/`vuln_scan` plugin binaries) roll out gradually (agent plane) — the same
version-skew class Decision 2's wire-format note already discusses for individual fields, but not
previously considered for an action's *existence*. Neither naive ordering is safe: repointing before
every agent has `component_inventory` dispatches to a plugin that doesn't exist yet on an
un-upgraded agent; retiring `vuln_scan`'s code before every agent has the repointed definition
leaves a lagging agent dispatching to a plugin that's gone. **This ADR commits to an explicit
three-phase rollout, not a single coordinated step:** (i) ship `component_inventory` fleet-wide
first, as its own release; (ii) once fleet-wide agent adoption is confirmed, repoint
`security.vuln_scan.scan`'s `execution`/`compatibility` fields server-side and retire the other four
definitions; (iii) only then remove `vuln_scan`'s legacy plugin code. This ordering, and the
requirement that phase (ii) not begin before phase (i)'s fleet adoption is confirmed, is a binding
condition on the implementation plan — see Ratification.

**Consequence:** the plugin's action(s) are reachable both on the new sync cadence (Decision 3) and
on-demand via `CommandRequest`/`execute_instruction` — the same dual-path `vuln_scan` itself
supports for an ad-hoc scan today — without duplicating the collection logic to get that
flexibility, and without inheriting `vuln_scan`'s current legacy baggage to get it. Because every
`CommandRequest`/`execute_instruction` dispatch in Yuzu already targets a **Scope** (an
expression-tree device subset — tags, OS, groups, prior result sets), the on-demand path is
**Scope-targetable for free**: an operator (or an agentic worker) can request a fresh component
inventory on an arbitrary subset of the fleet — e.g., "just the finance team's laptops" — without
this ADR inventing any new targeting mechanism. **The on-demand path needs the same ingest-side
dampening as the passive event trigger, for the same reason (found during hardening-round
re-review, 2026-07-07).** Decision 3 commits to a jitter/rate-cap requirement for the passive
event-linked trigger specifically because a synchronized fleet-wide firing would produce a
synchronized server-side ingest storm — but a Scope targeting a large or fleet-wide subset via this
on-demand path produces the identical storm shape, just operator-triggered instead of
event-triggered. **The same rate-cap/dampening requirement named in Decision 3 for the passive path
applies equally to a large-Scope on-demand request** — implementation should not treat "on-demand"
as exempt from the capacity concern just because it is deliberate rather than automatic.

**On-demand collection must be usable as a fresh input to CVE matching, not just a store update
that waits for the next scheduled correlation.** A concrete workflow this ADR must support: an
operator suspects exposure on a subset of assets, triggers a scoped on-demand component-inventory
refresh (whether by name via the retired-and-repointed `vuln_scan scan` instruction, Decision 2
above, or by any other entry point that dispatches the same action), and wants a *current*
vulnerability view for that subset — not one still keyed to last week's passive sync. This ADR
commits to the collection half of that: an on-demand result is ingested into the store as soon as
it arrives (the same "live scan uses the just-collected value" principle ADR-0018 already
established for distro-release), never gated behind the passive Decision-3 cadence. **It does not,
by itself, guarantee the matching engine re-evaluates that scope immediately** — that half is a
matching-side decision, which belongs in ADR-0023 alongside its existing feed-triggered
re-evaluation design, not in this collection-only ADR. **Sharpened trigger-keying
detail (following the `vuln_scan`-instruction-repointing discussion, Decision 2):** that trigger
should key off **the `component_inventory` action's completion for an agent/scope**, not off any
specific instruction-definition name or id. `vuln_scan.scan` is one operator-facing entry point that
happens to dispatch this action after Decision 2's repointing — it must not become the thing the
matching engine's trigger logic actually depends on, or every other legitimate entry point (an
agentic worker calling `execute_instruction` directly with a different instruction, or a future
operator-configured scheduled scan per Decision 3's out-of-scope note) would silently fail to get
the same automatic re-match. Flagged here as a required interface contract the matching document
must pick up for the end-to-end ad-hoc workflow to actually work — collection being fresh and
available is necessary but not sufficient without a matching-side trigger, keyed at the action
level, to consume it on the same schedule.

**Ordering guarantee against a concurrent passive sync — a real gap found during unhappy-path
review, 2026-07-07, and BLOCKING against this workflow's own stated purpose.** "Ingested as soon as
it arrives" is not, by itself, a same-agent ordering guarantee: an operator's on-demand refresh and
the daily-floor/event-linked passive sync (Decision 3) can both be in flight for the same agent at
once, and if the older, slower passive run's write completes *after* the on-demand write, the
fresher operator-triggered data is silently reverted to stale with no detection — directly
undermining the ad-hoc investigation workflow this section exists to support. **This ADR commits
to a monotonic sequence/timestamp check at the store write path: a write is applied only if its
collection timestamp is newer than the currently-stored value for that agent; an older write loses
silently (not an error, since it's a race, not a fault) rather than clobbering newer data.** The
same check also resolves the symmetric case of two passive-cadence triggers (event-linked and
daily-floor) firing close together for one agent (a related, lower-stakes instance of the same
missing-guarantee class) — no separate mechanism is needed for that case once the write path enforces
monotonicity.

**This must be an atomic conditional write, not an application-level check-then-act (sharpened
following Gate 2 re-review, 2026-07-08 — every prior description of this guard, including this
one, stated it as a "check," which under two genuinely concurrent writes for the same agent is a
SELECT-then-write race: last-committer-wins, not newest-timestamp-wins, silently reproducing the
exact stale-write-wins failure this guard exists to prevent).** The write must be a single atomic
conditional statement — e.g. `ON CONFLICT (agent_id) DO UPDATE ... WHERE stored.collection_ts <
excluded.collection_ts`, or an equivalent single-statement compare-and-swap — never a separate
read followed by a conditional write. This is the same class of anti-race idiom this codebase
already uses elsewhere (`complete_run`'s CAS, `claim_for_exec`'s execute-once claim) and is not
optional implementation detail: this ADR already pulled an equivalent correctness contract out of
Decision 8's deferral bucket once (the delete-then-insert-vs-upsert fix, Decision 7) specifically
because leaving a guarantee like this unspecified is how it silently breaks; the guard's atomicity
is the same class of thing and is decided here, not deferred.

**This ordering key is a different clock from Decision 7's `first_seen`/`last_seen`, and the two
must not be conflated (named following Gate 2 security re-review, 2026-07-08, of the Decision 7
fix).** The "collection timestamp" here is the **agent-supplied** time the walk ran — deliberately,
since this check exists to prefer a genuinely fresher write over one that merely *arrived* later,
which server-receipt-time ordering cannot distinguish. But an agent-supplied clock is also,
therefore, an agent-influenceable one: without a bound, a single transiently-compromised agent
could submit one future-dated write that permanently wins this monotonic guard against every
subsequent honest write, freezing the stored state past remediation. **This ordering key must
reject or clamp a collection timestamp that is implausibly far in the future — with a concrete
bound, not just a named principle (sharpened following Gate 2 re-review, 2026-07-08, which found
the requirement stated without a number is indistinguishable from no requirement at all).** This
ADR commits to the bound: **reject any collection timestamp more than 24 hours ahead of server
receipt time — reject, not clamp-to-boundary (sharpened following Gate 2 re-review, 2026-07-08,
which found "clamp" ambiguous between two materially different behaviors).** Clamping a rejected
timestamp *to* the 24-hour boundary would pin the malicious write at that boundary and make every
subsequent honest write lose the monotonic guard for a rolling ≤24h window while the attacker keeps
resubmitting — reject is unambiguous: the write is dropped (silently, per the existing "an older
write loses silently" posture — this is the same failure shape, just triggered by an implausible
future date instead of a genuinely stale one), and the currently-stored value stays authoritative
until a legitimately-timestamped write supersedes it. **A rejection this far in the future is itself
a compromise/clock-skew signal, not routine noise, and must not be silently absorbed — named as a
concrete observability requirement, not bare prose, following Gate 2 re-review, 2026-07-08, which
found "an audit or metrics event" too vague to implement consistently.** Implementation must emit
**both** a named audit event (`component_inventory.future_dated_rejected`, following the
`inventory.component.*` audit-verb convention this ADR already commits to for the read surface,
Ratification) and a Prometheus counter, per `docs/observability-conventions.md` — audit and metrics
serve different consumers here (a compliance-facing trail vs. an alertable signal), and a
compromise/clock-skew event plausibly needs both, not either. The exact 24-hour number is
implementation-tunable and is added to Decision 8's list of deferred constants (alongside the
decompression-bomb ceilings) — but unlike that earlier
omission, this one is named as deferred explicitly, not silently left unstated. **The cited precedent needed correcting too
(found during the same re-review): `software_inventory_store.cpp`'s migration v3 is a one-time,
zero-tolerance backfill clamp for pre-existing data, not an ongoing runtime bound for a live write
path — it does not structurally transfer to this check as directly as the original wording implied.
The real precedent this bound is consistent with is `app_perf_daily_store.cpp`'s `kFutureSlackDays`,
which clamps an agent-supplied value on every write, the same shape of problem this ordering key
has.** `first_seen`/`last_seen` themselves (Decision 7) are the opposite: **server receipt time**,
per this codebase's own hardened invariant (`software_inventory_store.cpp`, issue #1685 — "a
skewed/hostile agent must not hide a dark endpoint" by pinning a timestamp into the future). The two
clocks serve different purposes and must stay distinct: agent-collection-time orders writes against
a race, now with its own bound; server-receipt-time is the durable, agent-untrusted record of when
this store actually observed the component.

**The ordering guarantee must be completeness-aware, not recency-only — a compound risk the
recency fix itself creates, found during hardening-round re-review, 2026-07-07.** A pure
"newer-timestamp-wins" rule interacts badly with Decision 4's `truncated` flag: a fresher-but-
`truncated=true` walk (Decision 4) would, under recency alone, silently supersede an older but
*complete* stored result — a net data-quality regression that follows the ordering rule exactly as
written while defeating the very "get a current view" workflow this section exists to serve.
**The write-guard is therefore two-dimensional, not one:** recency alone governs between two
complete results; a `truncated=true` result **never** supersedes a stored complete result on
recency alone — it is written as a *parallel* needs-review signal (so the operator still learns the
on-demand attempt ran and was incomplete) without retiring the older complete data as the
authoritative current-state row until a complete result supersedes it.

**Wire format: one flat, FIXED-arity, honest-empty record shape with a `kind` discriminator — not
JSON.** Component inventory items are genuinely heterogeneous (a bundled library, an embedded
Electron/Chromium/Node runtime, a Go/Rust buildinfo dependency, a lockfile-derived package), but
this does not justify a new wire-format paradigm. `yuzu_ctx_write_output`/`write_output` is plain
`const char*`/`std::string_view` — every existing action (`installed_apps`, `device_ci`,
`hardware`) emits flat delimited text, never structured/nested output — and `installed_apps`
already proved the pattern this heterogeneity needs: one superset schema **at one fixed field
count**, a `kind` discriminator (its own `kind=app` vs package-managed split), and **honest-empty**
fields for whatever a given `kind` doesn't populate (ADR-0016 §2026-07-02's v2 blob — every row
carries all 12 fields; a field a given ecosystem doesn't have is `''`, the field is never *absent*).
`component_inventory` commits to the identical model — **fixed arity, not variable arity per
`kind`** (a self-contradiction in an earlier draft of this paragraph, caught during Gate 3
plugin-architecture review, 2026-07-07: "each `kind`'s own fields populated only where relevant"
must mean honest-empty-within-one-fixed-row-shape, not a row whose *field count* varies by `kind` —
variable arity would require agent-core to gain a kind-branching variable-arity parser it has never
needed, would invalidate the existing capture-cap sizing math tuned for `installed_software`'s
fixed-width rows, and doesn't fit a flat YAML `result.columns` list, which the on-demand action's
InstructionDefinition will need per Decision 8). Records are delimited the same way as
`installed_software` (`0x1F` between fields, `0x1E` terminating a record), with a `kind` field
taking values `bundled_lib` / `electron_runtime` / `go_buildinfo` / `lockfile_dep` / `unreadable`
(the fifth value, added below, for per-item unreadability); a shared
identity/attribution prefix (parent app or package identity, per Decision 1's anchoring); a
`dependency_origin` field (`public_registry` / `private_or_internal`, per Decision 1(d)) that is
honest-empty outside `kind=lockfile_dep`; and every other per-`kind` field present as an
honest-empty column on every row regardless of `kind` — mirroring `installed_software`'s convention
exactly, not a variant of it. This settles the wire-format *shape*; Decision 8 still defers the
exact field list and action name(s).

**A fifth `kind` value is required for per-item unreadability — a gap closed following adversarial
review, 2026-07-08.** Decision 4 commits that a symlink-contained-off path, or any other per-item
unreadable entry, is "emitted as UNKNOWN/needs-review, never a silent skip" — but the four-value
`kind` set above has no row shape for an item with no recoverable component identity at all (no
name, no version, nothing that fits `bundled_lib`/`electron_runtime`/`go_buildinfo`/`lockfile_dep`).
This ADR adds a fifth value, **`kind=unreadable`**, whose per-`kind` identity fields are
honest-empty except the shared identity/attribution prefix, which carries the anchoring/attribution
path only (the parent app, or the excluded/unreadable path itself) — giving Decision 4's per-item
commitment an actual row to land in, on the same fixed-arity shape as every other `kind`. This is a
different signal from the walk-level `truncated` flag below: `kind=unreadable` is a per-row fact
about one item; `truncated` is metadata about the sync report as a whole, and the two must not be
conflated (consistent with Decision 4's own truncated-vs-per-item distinction).

**This attribution path must be the logical, as-anchored path — never a resolved `realpath()`
target (a security gap closed following Gate 2 re-review, 2026-07-08).** For the
symlink-containment-exclusion case specifically, the whole point of containment (Decision 1) is
that an escaping symlink's *resolved target* may be exactly the per-user path that section exists
to keep uncollected. Logging that resolved target here — even as apparently-harmless diagnostic
value ("show what it pointed at") — would make this one row type the channel that silently ships
out-of-scope data into central storage, defeating containment's own guarantee. The
`openat()`/`O_NOFOLLOW`-per-segment walk mechanism Decision 1 already mandates holds both the
logical (as-anchored) and resolved paths at the point of rejection; this ADR commits to recording
only the former, here and anywhere else an anchoring path is captured (including `component_key`,
Decision 7 below).

**Version-skew/mixed-rollout contract (added following architect review, 2026-07-07).** ADR-0016
itself has an explicit mixed-version-rollout contract (old-server/new-agent and new-server/old-agent
windows, self-healing via the hash-skip/`need_full` mechanism) — this ADR's own wire format inherits
that same contract by construction, since it reuses the identical mechanism (Decision 3), but this
document should say so explicitly rather than leave it implicit: an old server encountering an
unrecognized `kind` value, or an old agent not yet emitting a newer field, degrades the same way
`installed_software`'s v1→v2 rollout did (older/missing fields honest-empty, no hard failure), and
the same is true for the flagged `InstallLocation`/bundle-path addition to `installed_apps` — an old
server simply doesn't parse the new fields until it upgrades, per that mechanism's existing
contract. **No proto or gateway `gpb` regeneration is implied** — per ADR-0016 §6/CLAUDE.md's own
routed-concern row, a new sync source is a new key in the existing `plugin_data`/`content_hashes`
maps, not a new proto field, and this ADR introduces no exception to that. **This includes Decision
3's chunk-reassembly metadata** (sequence number, total-chunk count, cycle id) — named here
explicitly following adversarial review, 2026-07-08, since chunking and "no proto change" are both
committed elsewhere in this document but were never previously linked: that metadata rides as
additional `plugin_data`/`content_hashes` map keys scoped to the sync cycle, not a new proto field,
consistent with this same mechanism.

### 3. How it is scheduled: a new, separately-governed sync source — and why this isn't a command-only capability

Reuse ADR-0016's *mechanism* (`SyncSource`/`SyncScheduler`, hash-skip protocol, full-floor,
phase-spread) — it is still the right transport pattern — but as its **own source**, not folded
into `installed_software`, because the cost/cardinality profile is different enough to break the
existing source's assumptions:

- **Cardinality.** A single endpoint's transitive dependency tree can run to thousands of rows,
  well past what `installed_software`'s caps (`kMaxEntries`, `kMaxBlobBytes`) were sized for.
- **Cost.** Bounded recursive filesystem walks and binary introspection are I/O- and CPU-heavy —
  a different resource-kindness problem than the network-kindness ADR-0016 was built to solve. This
  is a reason to give the walk its **own budget/governance**, independent of `installed_software`'s
  — not, on its own, a reason to poll less often (see cadence below).
- **Hash-skip economics invert.** `node_modules`/lockfiles change far more often than a
  workstation's top-level installed-app list; a fixed poll will frequently find real content
  changes and re-send in full. **Accepted as a known, deliberate cost** of the cadence decided
  below, not a reason to poll less often — freshness is worth more here than hash-skip's bandwidth
  saving.

**Cadence: event-linked trigger, with a daily floor — not a blind weekly poll.**
`installed_software`'s own daily sync already detects "something changed" via its content-hash
comparison — a new top-level app appearing or disappearing is exactly the moment a new bundled
Electron/OpenSSL/JAR or a new `node_modules` tree is most likely to have shown up. So: **(a)** an
`installed_software` hash-change schedules a component-inventory refresh as a low-priority
follow-on trigger, catching real change close to when it happens, rather than waiting for a fixed
clock; **(b)** independent of any trigger, a **daily** floor guarantees an upper bound on
staleness (tightened from an initial "weekly" instinct — the real target is daily at minimum,
matching `installed_software`'s own cadence, even though the walk itself is heavier per run). Own
phase-offset, own `KvStore` namespace, own store — a new sync source, following the
`device_ci`-class precedent (a new source added because the entity/cadence differs, not
because the mechanism does) — corrected following adversarial review, 2026-07-08: the
original citation was to a source class (`os_patch_state`) that does not exist anywhere in
this codebase; the three real agent-core sync sources today are `installed_software`,
`device_ci`, and `app_perf`, and `device_ci` is the closest real fit for this argument.

**The event-linked trigger needs its own dampening, distinct from the daily floor's phase-spread —
a real capacity gap found during Gate 6 SRE review, 2026-07-07, and BLOCKING as an architectural
commitment (hard to retrofit once the trigger/wire contract ships).** The daily floor is
phase-spread and bounded by construction (own phase-offset, above). The event-linked trigger is
not: it fires on an `installed_software` hash-change, and a fleet-wide software push (an MSI
rollout via management tooling) produces *synchronized*, not phase-spread, hash-changes across a
large fraction of the fleet simultaneously. "Low-priority follow-on trigger" was previously left
undefined as to whether it's jittered, rate-limited, or queued — it is not, as originally
written, and the real capacity risk is not the distributed per-endpoint walk cost but **synchronized
server-side ingest**: thousands of multi-thousand-row reports landing on the shared Postgres
substrate together. **This ADR commits to a jitter window (a bounded random delay before the
event-linked trigger fires, distinct from and in addition to the daily floor's fixed phase-offset)
on the event-linked path**, sized during implementation but decided as a requirement here, not left
to Decision 8 to discover only after the wire contract has shipped and jitter becomes a breaking
change to retrofit.

**Wire-size bound vs. the never-drop guarantee (Decision 4) are in tension and must be reconciled
explicitly, not left implicit (found during Gate 6 SRE review; the row-count math itself corrected
following adversarial review, 2026-07-08, which found it looser than the cited numbers support).**
ADR-0016's own numbers (`installed_software`'s ~20k-row/2.8MB blob) bound a single report under the
transport this ADR reuses, against two different ceilings that must not be conflated — and a third
correction, following adversarial review, 2026-07-08, which found the derived row-count figure
itself looser than the code's own binding constraint: the **actually-enforced, tighter** cap is
`kMaxEntries = 20,000` rows, enforced on both the agent and server seams — the codebase's own
comment names this as the deliberately-chosen binding constraint. The `kMaxBlobBytes` cap (3 MiB,
not the previously-stated "3.5MiB" — a second small inaccuracy corrected here) sits **above**
`kMaxEntries` as headroom (20k rows × ~140 bytes/row ≈ 2.8 MiB, reached before the 3 MiB byte
ceiling) — it is not itself the binding constraint. The looser, **unenforced** raw gRPC frame
ceiling (4 MiB) is where the "~30k rows" figure this section previously used actually comes from.
Decision 3 already states component-inventory cardinality runs "well past" the enforced cap;
Decision 4 commits to **never silently dropping** an item. A single endpoint whose transitive
dependency tree exceeds **20,000 rows (`kMaxEntries`)** — the tighter of the two enforced caps, and
the one this ADR's wire transport actually enforces — would blow the single-blob-per-report wire
model this ADR otherwise reuses unchanged from ADR-0016 — at that point it is not "reuse," it needs
a mechanism change. **This ADR resolves the
tension as follows, rather than leaving it to be discovered during implementation:** an oversized
inventory is sent as **multiple chunked reports** (a bounded sequence of blobs for one sync cycle,
reassembled server-side by sequence number), not as a single ever-larger blob and not as a silent
truncation — this is a distinct mechanism from the walk-level `truncated` flag in Decision 1/4
(that flag means "the walk itself hit its depth/size/time budget and stopped early"; chunking means
"the walk completed successfully and produced more rows than one report can carry"). The two must
not be conflated: a chunked-but-complete inventory is not the same signal to the matching engine as
a truncated-and-incomplete one.

**Chunk reassembly must not contradict the atomic-swap requirement below — an undesigned
interaction found during hardening-round re-review, 2026-07-07.** Read literally, "reassembled
server-side by sequence number" and "the store replace is a single atomic transaction" (below) are
incompatible unless the relationship between them is stated: naively applying each chunk as its own
atomic replace would let chunk N wipe chunk N-1's rows — a self-inflicted truncation worse than the
walk-level flag this ADR added specifically to prevent that class of result. **This ADR resolves it
as follows:** chunks for one sync cycle are staged (accumulated, not applied to the current-state
table) as they arrive; the atomic replace happens exactly once, after the final chunk in the
sequence is received, swapping the complete staged set in as the new current-state rows in a single
transaction. A cycle whose chunks stop arriving before the final sequence number (timeout,
connection loss) is treated the same as a walk-level truncation for that cycle — the prior
complete stored state is retained, not partially overwritten, and the incomplete cycle is
surfaced as needs-review, not silently discarded or silently half-applied. **Sibling-chunk
ordering:** the monotonic write-guard above applies once, at final-chunk reassembly time, to the
whole cycle's collection timestamp — not per-chunk — so chunks from two concurrent walks of the
same agent cannot interleave into one reassembled result; a second walk's chunks starting to arrive
before the first walk's reassembly completes are staged under that walk's own sequence and reconciled
by the same monotonic check once each completes.

**Store-write atomicity for the replace-on-change swap (found during unhappy-path review) —
required, not assumed. The correct mechanism, not an existing pattern to copy, corrected following
governance re-review of the Decision 7 fix, 2026-07-08.** Current-state-only, replace-on-change
retention (Decision 7) combined with this tier's cardinality means a single dependency change can
force a full multi-thousand-row resend (an accepted cost, above); the store-side replace of an
agent's prior rows with the new set must be a single atomic transaction — never a partial swap
visible mid-transaction, which would otherwise let a reader observe components from two different
points in time simultaneously if a transport interruption lands mid-replace. **This must NOT be
implemented as "matching `installed_software`/`device_ci`'s pattern of replacing all of an agent's
child rows"** — an earlier draft of this paragraph said exactly that, but `installed_software`'s
actual pattern (`software_inventory_store.cpp`) is an unconditional `DELETE FROM ... WHERE
agent_id=$1` followed by a bulk `INSERT`, and `device_ci` has no child-row pattern at all (a single
flat table, corrected in Decision 7 below). Implementing this swap as delete-then-bulk-insert would
silently defeat Decision 7's whole preserve-`first_seen` mechanism: `ON CONFLICT (agent_id,
component_key)` never fires against a row that was just deleted, so every component's `first_seen`
would silently reset to "now" on every sync cycle after the first, with no error surfaced. **The
correct shape, consistent with Decision 7's own upsert design:** a staged per-row `ON CONFLICT ...
DO UPDATE` (preserving `first_seen`, advancing `last_seen`) for every component in the new set,
plus a targeted `DELETE` scoped to components present in the prior stored set but absent from the
new one — all inside one transaction, so a reader never observes a partial mix, but the pre-existing
rows are updated in place rather than destroyed and recreated. This is the same atomic-replace step
the chunk-reassembly paragraph above triggers exactly once per completed cycle, not a separate
mechanism.

**Explicitly out of scope for this ADR: operator-configured scheduled scans** (e.g., "scan the
finance-team group every Monday at 20:00"). That is a future service-improvement feature —
presumably its own ADR, layering a schedule/target-group construct on top of the on-demand
trigger this ADR already provides (Decision 2) — not something this document designs. Noted here
only so the daily-floor-plus-event-trigger model above isn't mistaken for that future capability.

**Why this uses daily-sync's scheduling mechanism at all, rather than staying purely
command-triggered like `vuln_scan`'s historical model.** `vuln_scan` originally ran as an
on-demand `CommandRequest` action, not on a passive schedule — worth justifying explicitly why
component inventory does *not* follow that same command-only precedent. A command-only capability
only collects when something (an operator, a scheduled instruction) remembers to trigger it; a
newly-installed Electron app or a `pip install` done between triggers goes undetected until the
next manual scan, with no passive freshness guarantee. That silent-staleness failure mode is
exactly what ADR-0016's daily-sync framework exists to prevent for `installed_software`, and the
same argument applies here — a component inventory that only updates on request is a materially
weaker "definitive" input to CVE matching than one with a standing cadence. **Both paths are kept,
not one instead of the other:** the passive event-linked-trigger-plus-daily-floor cadence (this
decision) guarantees baseline freshness without operator action; the plugin's on-demand action
(Decision 2's consequence)
remains available for an operator or an automated `/auto` workflow that wants a fresh read
immediately (e.g., right after a suspected supply-chain incident) without waiting for the next
scheduled cycle.

### 4. Failure posture

Consistent with the recall-first design of the CVE-matching work this feeds: any field the
collector cannot read, and any item a bounded walk cannot fully enumerate within its budget, is
emitted as **UNKNOWN/needs-review — never silently dropped.** A silently-absent item is a false
negative that never even reaches downstream review. This posture explicitly covers a symlink-
containment exclusion (Decision 1): an excluded path is UNKNOWN/needs-review, never a silent skip.

**Walk-level truncation is a distinct failure signal from per-item unreadability, and both must be
surfaced (BLOCKING gap found during unhappy-path review, 2026-07-07).** The posture above covers an
individual unreadable *item*. It does not, as originally written, cover the walk itself hitting its
depth/size/time budget partway through a large tree (a monorepo-scale `node_modules`, for example):
a budget-exhausted partial walk emits some valid rows and stops, with nothing distinguishing that
result from a genuinely small, complete inventory — a structural false-negative surface the
per-item posture above does not reach, since every row it *did* emit reads as valid. **This ADR
commits to an explicit walk-level `truncated` flag** (a boolean/sentinel on the sync report,
distinct from any per-row field) whenever a walk stops due to budget exhaustion rather than natural
completion; the matching engine and any operator-facing surface must treat a `truncated=true`
report as needs-review for that agent, never as a clean/complete result. This is a different signal
from Decision 3's chunking mechanism (chunking means "more rows than one report can carry, but the
walk itself completed"; truncation means "the walk itself did not complete") — the two must not be
conflated in implementation.

**A named residual staleness gap in the cadence design, not fully closed here (found during
unhappy-path review).** Decision 3's event-linked trigger fires only off `installed_software`'s own
hash-change detection — but this tier's own named detection classes, specifically self-updating
Electron apps and self-updating Go/Rust binaries (Decision 1(b)/(c)), can change *in place* via
their own update mechanism without ever altering any package-manager-visible state at all. For
exactly the categories this ADR was built to close the blind spot on, the event trigger never
fires, and freshness silently degrades to daily-floor-only — worse than "catches real change close
to when it happens" implies for those specific classes. Named here as an accepted residual (the
daily floor still bounds the staleness), not a defect requiring a redesign; a future refinement
could add a file-mtime-based trigger scoped to the (b)/(c) install locations, but that is not
designed in this ADR.

### 5. Shared schema with roadmap Issue 18.5

The output schema is designed to be the **shared input** for both this capability's own consumer
(CVE matching — see ADR-0023) and Issue 18.5's externally-ingested SBOM
data. One schema, at least two producers (agent-generated vs. customer-CI-ingested), rather than
two divergent data models that both claim to describe "software on this endpoint." (Decision 6
below extends this to a three-way symmetry once export is added.)

### 6. Storage format: internal relational schema, not CycloneDX/SPDX natively — export/import are future projections

**The component inventory is stored in Yuzu's own normalized relational schema, consistent with
existing inventory stores. It is not stored natively as a CycloneDX or SPDX document.** CycloneDX
and SPDX export/import are explicitly anticipated as a **future, separate capability** built on top
of this schema — not designed here, and not the at-rest format.

**Why not store natively in CycloneDX/SPDX:**
- Both are **document-shaped formats** — a point-in-time tree meant to be generated once and
  shipped — not built for a live, incrementally-updated, queryable store. Every fleet-wide query
  ("which devices carry `openssl` 1.1.1k") would require parsing JSON at read time, or the document
  gets shredded into relational tables anyway — at which point it is a relational projection with
  CycloneDX as one serialization of it, not "CycloneDX storage."
- It would be an unexplained first exception to Yuzu's own established convention: ADR-0016
  explicitly rejected JSONB/GIN storage for inventory data for this exact reason (normalized
  relational rows "honor the migrate-off-Postgres-easily constraint").
- Pinning storage to an externally-governed, still-revising schema (CycloneDX is at 1.6/1.7 as of
  this writing, an Ecma standard under active extension) creates the same version-coupling risk
  already flagged for grype-db in ADR-0029 (§5) — our own schema is ours to evolve on our own
  schedule.

**Why export/import is still real future value, on top of the internal schema (not instead of it):**
- **A genuine three-way symmetry, not just the two-way one in Decision 5.** Roadmap Issue 18.5
  ("SBOM Ingest") already implies a "parse incoming CycloneDX/SPDX → internal representation" step
  to do component-level vuln linkage. If this ADR's schema *is* that internal representation:
  **generate** (this ADR) → schema ← **ingest** (Issue 18.5, parses external SBOMs in) → schema →
  **export** (future, on-demand projection out, not yet a numbered issue). One schema serves all
  three, computed at the boundary — the same principle ADR-0018 already applied to PURL ("computed
  only when interop needs it").
- **CycloneDX's native VEX (Vulnerability Exploitability eXchange) support maps closely onto a
  proposed four-state verdict model for this workstream** (FIXED/OPEN/NOT-APPLICABLE/UNKNOWN ≈
  VEX's fixed/affected/not_affected/under_investigation) — **not yet part of any merged ADR at the
  time of this writing** (ADR-0023 as merged still uses its own tri-state-plus-`potential` model).
  If a future matching engine ends up producing verdicts in that shape, a CycloneDX+VEX export
  becomes close to free — a real forward-compatibility argument for eventually building export, not
  for changing storage now, and not a claim that this mapping is available today.
- **CycloneDX and SPDX serve different downstream consumers Yuzu already has.** CycloneDX is the
  security/VEX-oriented standard (matches this CVE-matching workstream); SPDX 3.0's
  Security/Licensing profiles are the license-compliance-oriented standard (matches the open
  ADR-0024 SLE proposal). A future export feature likely wants to support **both**, for different
  audiences — this is a reason to keep the internal schema format-neutral, not a reason to pick one
  external format to store in.

**Scope of this decision:** commits to (i) the storage format being internal/relational, and (ii)
export/import as an anticipated, explicitly out-of-scope-here future capability sitting on top of
it. Does not design the export/import feature itself — **unlike this ADR's other deferred items,
export/import is not tracked under roadmap Issue 18.7** (see the "not yet a numbered issue" note
above); it remains unnumbered future work.

### 7. Retention: current-state-only — the component inventory has no history; discovered vulnerabilities will, but that's a separate future decision

**The component inventory itself is current-state-only, replace-on-change — no row-level history
kept centrally.** This follows the same precedent every other daily-sync store already
established: ADR-0016 explicitly rejected full version history for `installed_software` in central
Postgres ("history is TAR's edge concern," per ADR-0004's current-state-central /
history-on-edge boundary).

**Correcting an inaccurate precedent claim (found during adversarial review, 2026-07-08): no
existing store actually does what an earlier draft of this section claimed.** Checked directly
against the schema code: `device_ci` (`device_inventory_store.cpp`) is a single flat table,
`PRIMARY KEY (agent_id)`, written via a plain 1:1 `ON CONFLICT (agent_id) DO UPDATE` — not a
parent/child split at all. `app_perf_daily` (`app_perf_daily_store.cpp`) is genuinely historical,
`PRIMARY KEY (agent_id, app_name, version, day)`, pruned only past a per-agent TTL — the *opposite*
of "never row-level history." The real `inventory_state` parent/child pattern
(`agent_id, source, content_hash, first_seen, last_seen` parent + a typed child, `software_inventory_store.cpp`)
exists only for `installed_software`, and its child table carries **zero timestamp columns** —
`first_seen`/`last_seen` live only on the parent, at `(agent_id, source)` grain (one pair per agent
per sync source, answering "when did this agent's `installed_software` sync first/last land"),
never per individual software item. No store in this codebase preserves a per-component
`first_seen`/`last_seen` across a bulk child-row replace today.

**So a per-component `first_seen`/`last_seen` pair is a new mechanism this ADR must design
explicitly, not an existing pattern it can reuse unchanged.** The design is a standard
preserve-on-conflict upsert, not a novel invention — this codebase's existing stores simply don't
need it today, since none of them tracks freshness below the whole-sync grain: the component-table
write path is an `INSERT ... ON CONFLICT (agent_id, component_key) DO UPDATE` that refreshes every
column **except** `first_seen` (preserved from the existing row, `first_seen = <table>.first_seen`,
never overwritten) while `last_seen` always advances to **server receipt time** — a different clock
from the agent-supplied collection timestamp Decision 2's write-guard uses as its ordering key; see
that section for why the two must not be conflated. A component
genuinely absent from the current sync (not merely unwritten) is deleted in the same replace
transaction, consistent with the wholesale-replace-on-change posture above — its absence is not
itself a tracked row. This mechanism, not "reused precedent," is what Decision 8's deferred store
schema must actually implement.

**`component_key`'s required invariant, named as a constraint on Decision 8 rather than left
implicit (found during adversarial review, 2026-07-08).** The entire write-guard above — the
preserve-`first_seen` upsert, the delete-absent step, and Decision 2's monotonic write-guard — is
correct only if `component_key` is **stable across syncs and unique within an agent**; Decision 8
still defers its exact composition, but not this constraint. In particular, `component_key` must
incorporate the anchoring path (not just name+version), or two distinct co-named components (e.g.
two vendored `libcrypto.so` copies at different paths inside different apps) would collide and one
would silently overwrite the other's row.

**Two further constraints on that path component, sharpened following Gate 2/3 re-review,
2026-07-08 — sound in principle, underspecified enough in the original wording to reintroduce the
exact bug class this ADR exists to prevent.** (a) **The path must be the logical, as-anchored path,
never a resolved `realpath()`** — the same rule Decision 2's `kind=unreadable` value now states
explicitly, and it matters here for a different, equally real reason: Decision 1 already names two
*legitimate*, routinely-rotating in-root symlinks (Linux's `update-alternatives` system, macOS
Framework `Versions/Current ->` links) that are followed and resolved normally, not contained off.
If `component_key` used the resolved target, a routine package update through either mechanism would
silently change the key for every affected component — firing the "relocation resets `first_seen`"
trade-off below on **ordinary maintenance**, not the rare relocation case that trade-off was framed
around. The logical/as-anchored path stays stable across exactly this kind of routine retarget,
which is the intended behavior. (b) **The path component is the full, root-anchored path, not a
path relative to the component's own parent app (sharpened following Gate 3 re-review, 2026-07-08)**
— a relative path would let two different apps that happen to share an internal layout (e.g. two
Electron apps both bundling `Contents/Frameworks/Electron Framework.framework`) collide under an
otherwise-correct key; anchoring to the full path (or equivalently, the parent app's own identity
plus the within-app relative path) rules this out. (c) **The composition must be collision-safe, not
naive string concatenation, and a hash-based composition specifically must be collision-resistant at
this store's real scale, not just "a hash"** — `name + version + path` concatenated as plain text
risks an incidental (or adversarially-crafted) path segment producing the same byte string as a
different, genuinely-distinct component's key, silently merging two rows. **Preferred: a
length-prefixed field encoding**, which is collision-free by construction (injective), not merely
low-probability. If a hash of the structured `(name, version, path)` tuple is used instead, it must
have negligible collision probability at this ADR's own stated cardinality (thousands of rows per
agent, Decision 3) — an unqualified "a hash," with no stated strength requirement, is exactly the
kind of choice that could reintroduce engineered-collision risk in a document that already treats
path segments as adversarially-crafted input elsewhere (the naive-concatenation rejection just
above). The exact choice is still Decision 8's to make; "plain concatenation" and "an unqualified
hash with no stated collision bound" are both ruled out here, not left to be discovered as a bug
later.

The accepted trade-off this creates: an in-place relocation of a component to a genuinely new
anchoring path (not a routine symlink retarget, per (a) above) resets that component's `first_seen`,
since it becomes a new `component_key` rather than an update to the existing row — named here as a
known cost, not an oversight for Decision 8 to rediscover.

**Noted for Decision 8 to confirm, not resolved here:** a path whose `kind` changes across syncs
(e.g. a previously-readable component that becomes contained-off, or vice versa, at a stable
`component_key`) is expected to behave as an ordinary upsert — the row's `kind` and identity fields
update in place, `first_seen` is preserved — but this ADR does not design a dedicated test for that
transition; Decision 8's implementation should confirm it rather than discover a gap late.

**The walk-level `truncated` flag's storage location, left unstated until now (found during
adversarial review, 2026-07-08).** Decision 3 commits that a `truncated=true` result is written as
a *parallel* needs-review signal that does not retire an older, complete stored result — but the
one-row-per-component table described above, as stated, has no field to hold that signal alongside
retained rows. This ADR resolves it as a small, **agent-scoped walk-metadata sidecar** (a single row
per agent — not per component — recording the most recent sync cycle's `truncated` boolean and its
collection timestamp), a grain analogous to `installed_software`'s existing `inventory_state`
parent row. Decision 8 still designs this sidecar's exact columns; this ADR commits to its
existence and its per-agent (not per-component) grain, so Decision 3's and Decision 4's
already-decided commitments have a concrete place to be implemented.

**The sidecar's write path, restated as one coherent mechanism rather than patched case-by-case
(rewritten following two further rounds of Gate 2/3 re-review, 2026-07-08, after the first
decoupling fix itself introduced a fresh gap — the exact "narrow fix, new problem" pattern this
ADR's own review history repeatedly names).** An earlier draft coupled the sidecar to "the same
transaction as the component replace," which doesn't exist for a cycle that never fully reassembles.
A later draft decoupled it into "its own single-row upsert... exactly one of the two always fires
per cycle," which over-corrected: it dropped the transaction pairing for the case that *does* have
one, missed that a cycle can fully reassemble yet still lose Decision 3's monotonic write-guard (not
covered by either stated case), missed total silence (a cycle that never gets even its first chunk
to the server), and gave the sidecar the future-dating rejection rule but not the same monotonic-ordering
guard as the component table — reopening, on the sidecar, the identical stale-write-wins race the
component table's guard was built to close (a slow, stale cycle's timeout-write landing after a
fast cycle's success-write, reverting the sidecar to a stale `truncated=true` beside correct,
complete data). **The mechanism, stated once, covering every case:**

1. **A cycle that fully reassembles and wins the monotonic write-guard** (its collection timestamp
   is newer than the currently-stored value): the sidecar upsert (`truncated=false`) executes
   **inside the same transaction as the component replace** — that transaction genuinely exists for
   this case; there is no reason to split it, and splitting it is what reopened the inconsistent-read
   window.
2. **A cycle that fully reassembles but loses the monotonic write-guard** (a stale, out-of-order
   cycle relative to already-stored, newer data): this is a **non-event for the sidecar**, the same
   as it already is for the component table — Decision 2's write-guard already establishes "an older
   write loses silently... rather than clobbering newer data," and a losing cycle is, by definition,
   not the most current information for this agent. No sidecar write fires; the currently-stored
   sidecar row (from whichever cycle it last legitimately reflected) stays authoritative.
3. **A cycle that times out or otherwise fails reassembly before its final chunk arrives**: the
   sidecar upsert (`truncated=true`) is its own standalone atomic conditional write — the one case
   with no replace transaction to ride on — gated on the sidecar's **own** stored collection
   timestamp, not merely the future-dating rejection: `ON CONFLICT (agent_id) DO UPDATE ... WHERE
   sidecar.collection_ts < excluded.collection_ts`. **This must compare against the sidecar's own
   prior value, not only the component table's (sharpened following Gate 3 re-review, 2026-07-08 —
   comparing only against the component table closes an older timeout overwriting a newer success,
   but leaves a timeout-vs-timeout race open: two cycles that both fail reassembly, both newer than
   the last successful sync, where the older one's write lands second would otherwise regress the
   sidecar's own recorded timestamp even though its `truncated` boolean stays correct either way).**
   Exactly one of cases 1–3 fires for any cycle whose first chunk reaches the server.
4. **A cycle whose first chunk never reaches the server at all (agent crash, network failure before
   any chunk is sent) is explicitly NOT covered by this mechanism** — no reassembly is ever armed, so
   none of cases 1–3 fire, and the sidecar silently retains whatever it last held. This ADR does not
   claim otherwise: closing this gap is the job of the per-source freshness/staleness gauge already
   named as a Decision 8 deferral, not a case this sidecar design can detect on its own (a gauge
   observes "no report arrived in expected window" independent of what any single report's own
   metadata says).

The sidecar's own collection timestamp is agent-supplied and subject to the same future-dating
rejection rule as Decision 2's write-guard ordering key (above) in all cases that write it.

**This is a stronger case for current-state-only than `installed_software`'s own, not a weaker
one.** The same cardinality/cost reasoning that justified giving this its own sync source
(Decision 3) — an order of magnitude more rows per endpoint, changing more often than a
workstation's top-level app list — makes full history considerably more expensive here than the
option ADR-0016 already rejected for a smaller, slower-changing dataset.

**Discovered vulnerabilities (matching engine output, not this ADR's collection data) are a
different case and will have their own history — decided in a future ADR, not here.** A CVE
verdict against a component has a genuine lifecycle (open → remediated → re-opened; first-detected
vs. last-confirmed dates; SLA tracking) that the raw component inventory does not need and this
document does not design. That lifecycle question already has a plausible home: `docs/roadmap.md`
**Issue 18.1, "Vulnerability Lifecycle"** ("CVE → CVSS → owner → SLA → remediation tracking"). This
ADR's boundary: it feeds ADR-0023's matching engine a current-state component inventory; whatever
history that engine's *findings* need is that ADR's (or a future ADR's) decision, not a retention
requirement on the inventory itself.

**If genuine component-level historical/change-tracking is ever wanted** (a forensic "was this
component present two weeks ago" question, distinct from vulnerability history) — that remains a
TAR concern by the same boundary ADR-0016 already drew, plausibly a future `$ComponentInventory`
TAR source analogous to the existing `$Software` source, not a reason to add history to this ADR's
central store.

**Named limitation, not a defect: `first_seen`/`last_seen` alone cannot support a "we knew about
this by date X" evidence claim once findings-history exists (found during Gate 6 compliance
review).** The per-component `first_seen`/`last_seen` pair answers "was it present, and when did we
last confirm it" — adequate for this ADR's own scope. But current-state-only + replace-on-change
means a component that appeared and disappeared entirely between two sync cycles leaves no trace at
all; if an auditor's evidence question falls in that gap, it is unanswerable from this store alone.
This is correctly *not* a defect in this ADR's own retention scope (the inventory, not the
findings) — but it does mean Issue 18.1's findings-history is a hard evidentiary dependency, not
just a topical one: no "we detected this exposure by date X" claim is evidence-backed until that
history exists, and this ADR's boundary should not be read as implying otherwise.

### 8. Explicitly deferred (tracked as roadmap Issue 18.7, "Agent-Side Component Inventory Collection" — status: Proposed, added to `docs/roadmap.md` Phase 18 following adversarial review, 2026-07-08; it did not previously exist there, and this heading's earlier "tracked as" phrasing overclaimed a settled fact)

This ADR commits to the collection tier's existence, its plugin/mechanism placement, storage-format
principle, and shared-schema intent. It explicitly **does not** fully specify:

- The bounded-walk **allowlist policy** in operational detail (which roots, what depth/size/time
  budget, how it's tuned per OS).
- **A lighter confirmatory security review** than originally scoped, given Decision 1's reversal to
  machine-scope-only: pseudonymization posture (retention itself is settled — Decision 7,
  current-state-only). Lockfile/manifest redaction is also settled, not deferred — Decision 1(d):
  record genuine installations in full (no identity redaction/exclusion for private-source
  dependencies), with one unconditional embedded-credential-stripping safety net and a
  public/private dependency-origin tag. Not a works-council/co-determination gate — Decision 1 designed
  that trigger out by staying machine-scope.
- The dedicated **store schema** in relational detail (columns, indices) and read-surface
  (REST/MCP/dashboard) design — retention is settled (Decision 7), the schema's exact shape is not.
  **`component_key`'s exact column composition is likewise deferred** (added following docs
  re-review, 2026-07-08, so this bullet doesn't read as if the whole key were still open): its
  **uniqueness-within-agent, path-inclusion, logical-not-resolved-path, and collision-safe-encoding
  requirements are settled** (Decision 7) and constrain, not are designed by, this deferred work.
- **The CycloneDX/SPDX export/import projection feature** itself (Decision 6 commits only to the
  storage-format principle that makes it possible later, not its design). **Not covered by roadmap
  Issue 18.7** — unlike the other bullets in this list, this deferral is unnumbered future work
  (Decision 6's own scope note); listed here as a deferral of this ADR, not as an Issue-18.7 item.
- The **`component_inventory` plugin's exact action name(s) and full field list** (Decision 2 settles
  the wire-format *shape* — flat, delimited, honest-empty, `kind`-discriminated, matching
  `installed_software`'s convention — but not the specific action name or the complete per-`kind`
  field enumeration), and the **YAML `InstructionDefinition`** for its on-demand action (a required
  deliverable per Decision 2, not optional). **The `kind=unreadable` fifth value added tonight is
  part of this same enumeration and needs the same agent-emits/server-parses cross-check discipline
  this codebase already applies to published schema enums elsewhere** (e.g. the Guardian
  published-schema-enum ↔ per-type-support-array H2/G9 cross-check) — named here so it isn't added
  agent-side only, or server-side only, and drift silently.
- **The decompression-bomb ceilings** (max-decompressed-size, max-entry-count, compression-ratio)
  for JAR/`.asar` parsing named in Decision 2 as required budgets, alongside the filesystem-walk
  depth/size/time budget — the exact numbers are deferred, their necessity is not.
- **The future-dating rejection threshold's exact bound** (Decision 2's write-guard ordering key,
  and the matching bound on the Decision 7 walk-metadata sidecar's own timestamp) — this ADR commits
  to a 24-hour starting figure, that a violation is rejected (not clamped-to-boundary), and that
  crossing it emits **both** a named audit event (`component_inventory.future_dated_rejected`) and a
  Prometheus counter per `docs/observability-conventions.md`; final tuning of the number is
  implementation-stage work, same treatment as the decompression-bomb ceilings above. **This audit
  event is part of the same Ratification binding condition as the read-surface audit verb** (added
  following Gate 2 re-review, 2026-07-08, so it isn't left as unenforced prose) — see Ratification.
- **`component_key`'s path canonicalization** (Decision 7) — normalization of `.`/`..` segments,
  trailing separators, and OS-appropriate case handling before the path enters the key, so the
  same logical file doesn't produce two different key strings across syncs and spuriously reset
  `first_seen`. A data-quality concern, not a security one; exact rules are implementation-stage
  work.
- **Fuzz-harness coverage** for each new binary/archive parser (Decision 2) — named as a ship
  precondition, with the specific harnesses/targets left to implementation.
- The **prerequisite `filesystem`-plugin bound-checking-constants refactor** (Decision 2) —
  extracting and reconciling `filesystem`'s currently-inconsistent per-action clamps into one
  shared location before `component_inventory` can depend on them.
- **RBAC and audit-verb design for the future read surface** — Decision 8 names the store schema as
  deferred; the specific RBAC/audit posture is deferred with it, but per Gate 6 compliance review
  (2026-07-07), **this deferral is conditional, not open-ended**: see Ratification below, which
  makes the future implementation PR's merge conditional on this design landing as its own reviewed
  gate, not an assumption that it follows from the general reviewer bar.
- **A data-classification entry in the enterprise-readiness/SOC 2 data-inventory table** (per Gate 6
  compliance review) for the new store — classification, retention, purge status, and the
  Decision-2 opt-out flag's documentation — named here as an obligation for whoever implements
  Issue 18.7, so it isn't silently missed the way a comparable inventory-table gap has been missed
  before in this codebase.
- **`/readyz` inclusion and a freshness/staleness gauge for the new store** (per Gate 6 SRE review)
  — this codebase has a recurring, self-documented pattern (a new or newly-load-bearing store
  missing from the `/readyz` `stores_ok` conjunction) and a recurring pattern of a new sync source
  shipping without its own freshness gauge (`device_ci`'s own gauge extension is itself still a
  deferred follow-up per ADR-0016). Named here as a requirement so `component_inventory` doesn't
  repeat either pattern, not left to be rediscovered during implementation.
- **Store-rebuild recovery is explicitly agent-side-only** (per Gate 6 SRE review): because
  retention is current-state-only (Decision 7), the sole recovery path for a corrupted/rebuilt store
  is the next scheduled sync reporting against an absent hash and triggering `need_full` — riding
  the phase-spread daily-floor path (not the undampened event path, which is why Decision 3's
  jitter commitment matters for capacity but not for recovery correctness). Named explicitly here
  rather than left implicit, since there is no server-side reconstruction option for this store.
- Citing **`docs/postgres-store-playbook.md`** and **`docs/postgres-migration-ladder.md`** (per
  architect review) for whoever designs the deferred store schema — this ADR names the store's
  shape (current-state-only, with the new per-component preserve-on-conflict upsert designed in
  Decision 7 — not an existing `inventory_state`-style precedent, corrected following adversarial
  review, 2026-07-08) but does not walk through the playbook's own "decide up front" checklist
  (posture, schema name, secrets), which the implementation PR should do explicitly.
- **A first-activation rollout plan for existing large fleets, distinct from steady-state
  phase-offset** (per enterprise-readiness review) — Decision 3's phase-offset addresses ongoing
  cadence spread, not the one-time cost of an entire existing fleet gaining this capability on the
  same upgrade wave and running a first walk near-simultaneously; a staggered/incremental
  first-activation schedule is a named requirement, its shape is deferred.
- **A customer-facing upgrade note and disclosure**, covering the new collection class, the new
  permanent opt-out flag (Decision 2), and the private/internal-dependency-recording decision
  (Decision 1(d)) in plain terms — per enterprise-readiness review, this is the same deliverable as
  the opt-out flag's documentation, required before Issue 18.7 ships, not a separate nice-to-have.

**Acknowledged, not resolved: this store's core-vs-use-case-engine placement is contingent on its
non-CVE consumers actually materializing (per architect review, cross-referencing ADR-1005's own
"a store whose sole consumer is an interpretation layer moves out with that layer" principle).**
This ADR argues the store stays core-side because it names consumers beyond CVE matching (licensing/
ADR-0024, supply-chain visibility, Context point 1). If those consumers never materialize and
CVE-matching ends up the only real reader, the store's core placement is contingent on that fact,
not permanently settled by this ADR — worth re-checking if and when ADR-1005 is accepted.

## Consequences

**Gained:**
- Closes the single largest blind spot identified in the CVE-matching research (bundled/vendored
  dependencies, Log4Shell-class embedded JARs, Electron/Chromium) without compromising ADR-0016's
  existing daily identity-sync cadence or size envelope.
- Produces a reusable, first-party software-component inventory with value beyond CVE matching
  (licensing/entitlement, supply-chain visibility) instead of a private vuln-matching-only
  artifact.
- Positions Yuzu to close roadmap Issue 18.5 and this ADR's generation-side under one schema,
  avoiding two divergent "software on this endpoint" data models.
- Avoids coupling a clean, forward-looking capability to `vuln_scan`'s own unscheduled retirement
  cleanup, and gets a free on-demand trigger path as a side effect of being a proper plugin
  (Decision 2).

**Costs accepted:**
1. **A new plugin and a new, separately-cadenced collection mechanism must both be built** — this
   is not free even though it reuses ADR-0016's transport pattern and existing plugin conventions;
   a new plugin, a new scheduler cadence, a new store, and a bounded-walk safety design are real
   scope.
2. **Filesystem/binary introspection is a new class of endpoint operation** (recursive directory
   walks, binary parsing) with its own performance and correctness surface — not simply "one more
   sync source" in engineering weight, whatever its conceptual similarity to existing sources.
3. **Per-user language-dependency coverage is given up entirely, not partially** (Decision 1) — a
   developer workstation's own `node_modules`/venvs remain invisible to this capability. This is a
   deliberate trade against a new cross-user file-read privilege, not an oversight, but it is a
   real, larger-than-expected coverage gap that a future ADR would need its own architecture (not
   a service-account privilege grant) to close.
4. **Statically-linked libraries remain an accepted, unrecoverable residual gap** — this ADR
   narrows but does not close the bundled-dependency blind spot.
5. **The storage-format decision (6) commits to a principle, not a schema** — the actual relational
   schema is still deferred (Decision 8), so this cost isn't yet retired, only correctly located.
6. **`vuln_scan`'s own retirement cleanup remains a separate, still-unscheduled item** — rejecting
   it as a host for this capability (Decision 2) does not itself fix or schedule that cleanup; it
   only avoids making this ADR depend on it. Decision 2's instruction-definition repointing means
   this cleanup and the `component_inventory` rollout are coordinated, not independent, once
   scheduled.

**Ownership.** @lesault (Andy Younie) continues to own the vulnerability-scanning capability and its
quality bar end-to-end, matching the explicit ownership language already recorded in ADR-0018
("Andy owns the matching quality bar") and ADR-0019 ("Andy owns the finding-status taxonomy and
coverage-metric definition"). Retiring the `vuln_scan` *plugin*'s legacy code (Decision 2) is an
implementation-level change in where the code lives; it is not a change in who owns the capability
operators know as `vuln_scan` — which, per Decision 2's instruction-definition repointing, keeps
that exact name and keeps working from an operator's or agentic worker's perspective throughout the
transition. Eng owns the mechanics of the plugin split, the instruction repointing, and the
retirement PR itself.

## Alternatives considered

- **Omit or redact private/internal-source dependency entries from the component inventory.**
  Considered and rejected (Decision 1(d)) — a genuine installation should be recorded regardless of
  whether it will ever match a public CVE source; excluding it cuts against this ADR's own
  broader-than-CVE-matching value (licensing, supply-chain visibility) and against a plausible
  future internal-namespace vulnerability-matching capability. Replaced with a narrower,
  unconditional embedded-credential-stripping safety net (a secrets-hygiene rule, not identity
  redaction) plus a public/private dependency-origin tag; any further anonymization is deferred to
  whenever a concrete future consumer needs it, not decided speculatively here.
- **Fold this collection into `installed_software` v3.** Rejected — cardinality, cost, and
  hash-skip economics all argue against sharing the fast daily loop (Decision 3).
- **Extend the existing `vuln_scan` plugin instead of creating a new one.** Rejected (Decision 2) —
  `vuln_scan` currently carries ~700 lines of pre-ADR-0018 agent-side matching code pending an
  unscheduled retirement, and its existing `inventory` action already duplicates, with less detail,
  what `installed_apps` does today; building new capability there couples it to an unrelated
  cleanup for no architectural benefit.
- **Build this as agent-core code rather than a plugin.** Rejected (Decision 2) — every comparable
  OS-specific collector in this codebase (`installed_apps`, `msi_packages`, `hardware`) is a
  plugin behind the stable C ABI; agent-core stays thin scheduling/parsing glue by convention.
- **Make this a command-triggered-only capability, matching `vuln_scan`'s historical model, with no
  passive schedule.** Rejected (Decision 3) — a component inventory that only updates on request
  cannot give CVE matching a passively-fresh input, reintroducing the same staleness problem
  ADR-0016's daily-sync framework already solved for `installed_software`. Kept as a *complementary*
  on-demand path alongside the passive schedule, not as a replacement for it.
- **Build this as a private implementation detail of the CVE-matching engine, no shared schema, no
  roadmap linkage.** Rejected — throws away reusable value already anticipated by ADR-0018 and
  needed by the open ADR-0024 SLE proposal.
- **Wait for roadmap Issue 18.5 (import) and skip first-party generation.** Rejected as
  insufficient on its own — many endpoints have no CI-produced SBOM to import; generation is
  needed for those, and the two are complementary, not substitutes.
- **Store the component inventory natively as CycloneDX or SPDX documents.** Rejected (Decision 6)
  — both are document-shaped export formats, not built for a live queryable store; would be an
  unexplained exception to ADR-0016's no-JSONB convention; and couples storage to an externally-
  governed, still-revising schema. Export/import remain valuable as a future projection layer, just
  not as the storage format.
- **Grant the agent's service account a new privilege to read per-user directories, broadly (all
  users' home directories) or narrowly (named dependency-store paths like `~/.npm`, `~/.cargo`,
  `~/.cache/pip`).** Rejected (Decision 1) — broad is close to the maximum blast-radius outcome
  `docs/agent-privilege-model.md`'s entire unprivileged-by-design posture exists to prevent; narrow
  only *looks* safer, since those specific paths disproportionately carry credentials (npm/cargo/pip
  auth tokens), not just dependency metadata — scoping the path doesn't scope the sensitivity. Both
  directions also run against the grain of where every platform's privilege model is already
  heading (Linux/Windows unprivileged by design; macOS's current root exception and Windows's
  current LocalSystem bug are both flagged in that doc as states the team wants to close, not a
  foundation to build new privilege on).
- **A session-scoped helper process running as the interactive user, for per-user coverage — named
  as the likely-correct future architecture, not adopted here.** If per-user language-dependency
  coverage is ever pursued, the right shape is probably a small helper that runs in the logged-in
  user's own session and reports only what that user could already read themselves — no
  service-account privilege escalation at all, structurally different from "grant `yuzu` broader
  file-read." This is materially new engineering (a second process, a session-attach mechanism, its
  own lifecycle) and is explicitly left to a future ADR to design and justify, not folded into this
  one as a stopgap.
- **A blind, generic recursive walk under machine-wide roots as the primary discovery mechanism,
  with no anchoring to known install locations.** Rejected as the *primary* mechanism (Decision 1)
  — wasteful (re-scans large swaths of disk every cycle) and imprecise (can't reliably attribute a
  found library to its parent app). Kept only as the residual fallback for software that package
  managers and registry/bundle metadata don't already account for.

## Relationship to other ADRs

| ADR / doc | Relationship |
|---|---|
| 0016 (agent daily-sync framework) | Mechanism reused (SyncSource/scheduler/hash-skip); a new, separately-governed source (Decision 3) — independent budget/store even though its floor cadence is daily too, plus an event-linked trigger keyed to `installed_software`'s own change detection. **Open dependency (Decision 1):** `installed_apps`/`sync_source_installed_software` needs a small addition (capture `InstallLocation`/`.app` bundle path) to anchor this ADR's walk roots — must land before or alongside implementation (recommended: a dated ADR-0016 amendment section, matching the `device_ci`/blob-v2 precedent), not after. **Update (2026-09-21): PARTIALLY landed — the binding condition stays OPEN.** The operator `list` action now carries `install_location` + `bundle_id` (definition `crossplatform.software.inventory` 1.1.0); the `sync_source_installed_software`/blob-v3 addition Decision 1 names remains open and is deliberately NOT folded in, so a `component_inventory` PR that anchors on the daily-sync blob must either land that amendment first or amend Decision 1 to bless an in-process consumer of `list`. The columns are display-grade, not walk roots: `safe_output_field` is lossy (`\`→`/`, which on POSIX can synthesise `..` from a filename that contains `\`), REG_EXPAND_SZ is unexpanded, a macOS value can be `/Users/<account>/...` (a per-user root Decision 1 forbids), and the value is as reported by system_profiler/the registry — untrusted and non-canonical, and under a user's home controlled by that user (the text parser cannot exclude a line-injected record; tracked). The walker must canonicalise and validate every path before use. See the binding condition at :1458. |
| 0029 (CVE source catalog & ingestion) | **Sibling, not a dependency in either direction** (corrected during governance review, 2026-07-07 — an earlier draft of 0029 incorrectly claimed this ADR as its consumer). Neither document depends on the other; the actual consumer of both is ADR-0023's matching engine, routed by regime. |
| `vuln_scan` plugin (existing, not an ADR) | Considered and rejected as the host for this capability (Decision 2) — carries legacy pre-ADR-0018 code pending an unscheduled retirement; a new `component_inventory` plugin is built instead. **The name survives, the plugin doesn't:** the `security.vuln_scan.scan` instruction definition is kept and re-pointed at `component_inventory`'s action, so the operator-facing command an owner already associates with this capability keeps working through the plugin's retirement (Decision 2). |
| `filesystem` plugin (existing, not an ADR) | The better precedent for this plugin's *internal* bounded-synchronous-walk conventions (Decision 2, citation corrected following adversarial review, 2026-07-08) — `installed_apps` is the right precedent for the agent-core/plugin boundary shape only; `tar`'s `ProcStreamCollector` was incorrectly cited here in an earlier draft, but it is a persistent async collector, never invoked synchronously inside one command dispatch, so it doesn't address the command-timeout-budget/partial-result problem this plugin's walk actually faces. `filesystem_plugin.cpp`'s own bounded, synchronous walk is the real precedent for that. |
| 0018 / 0019 (server-authoritative matching / tri-state findings) | Downstream consumer — this ADR's output feeds the language-ecosystem regime of CVE matching. |
| ADR-0023 (vuln correlation engine, PR #1914, merged 2026-07-07, `status: accepted`) | Downstream consumer of this ADR's schema; that document does not re-specify collection, it assumes this ADR's output as an input. **Open interface contract (Decision 2):** that document still needs an on-demand re-match trigger, keyed off the `component_inventory` action's completion for an agent/scope (not off the `vuln_scan.scan` instruction name specifically) to complete the ad-hoc "refresh a subset, see current vulnerabilities" workflow this ADR's collection half already supports. |
| 1005 (headless platform / use-case engines, PR #1918/#1926 — merged the proposal text to `dev`; the ADR itself is `status: proposed`, not yet accepted) | This capability is *mechanism* under its Decision-2 test — unaffected by that ADR's outcome. |
| 0024 (SLE, PR #1920, open) | Downstream consumer — license/entitlement matching needs the same per-endpoint component data. |
| roadmap Issue 18.1 (Vulnerability Lifecycle) | Named future home (Decision 7) for the *findings*-side history (open→remediated→re-opened, SLA tracking) this ADR deliberately excludes from the component inventory itself. |
| roadmap Issue 18.5 (SBOM Ingest) | Companion, not duplicate — import-side of the same capability; shares one internal schema across generate/ingest/export (Decisions 5–6). |
| roadmap Issue 18.7 (`docs/roadmap.md` Phase 18, status: Proposed — entry added following adversarial review, 2026-07-08) | Tracks this ADR's deferred *collection/implementation* items only (Decision 8). Does **not** cover the export/import projection feature — Decision 6 explicitly keeps that as unnumbered future work, not part of Issue 18.7's scope. |

## Ratification

**Status: accepted** (2026-07-09, per @Tr3kkR's standing convention: an ADR submitted for review in
a PR carries `status: accepted` so `dev` shows the correct status once reviewed and merged).
Otherwise needs the same reviewer bar as ADR-0016/0018 for a new plugin touching endpoint filesystem
scanning — this status flip doesn't stand in for that review actually happening:

- **Maintainer** — @Tr3kkR (merge gate).
- **Platform lead** — @NathanDornbrook (storage/fleet-scale implications of a new, potentially
  large store; the event-trigger dampening and wire-size/chunking commitments in Decision 3).
- **Security architecture** — @Alex (the bounded-walk safety posture, symlink containment, and the
  lightened confirmatory security review, Decision 8; also the natural reviewer for Decision 1's
  rejected-privilege-grant reasoning, given its direct dependency on `docs/agent-privilege-model.md`;
  and fuzz-harness coverage for the new binary/archive parsers before this ships on any platform —
  not conditional on privilege tier, since the same parser code is an RCE surface on unprivileged
  Linux too).
- **Customer-assurance / enterprise-readiness reviewer** (added following Gate 6 enterprise-readiness
  review, 2026-07-07) — signs off specifically on the "no works-council review required" claim below
  and on the permanent customer opt-out flag / upgrade-note commitments (Decision 2, Decision 8),
  since these are exactly the kind of representation that ends up in a customer questionnaire or
  security whitepaper and this ADR's Ratification list previously had no reviewer with that
  authority.

**Binding condition on the future implementation PR (added following Gate 6 compliance review,
2026-07-07): the RBAC/audit-verb design for this store's read surface (Decision 8) MUST be reviewed
by security-guardian as its own explicit gate before that PR merges — it is not satisfied by
inheriting "the same reviewer bar as ADR-0016/0018" in general.** The concrete requirement: a named
`component_inventory`/`inventory.component.*`-style audit verb, wired through the existing
`authorize_list_read` (ADR-0017 World A) chokepoint for any list/fan-out read — never a bare
`require_permission`, which is inert for confined operators and fails open on a corrupt RBAC store.
This condition exists because every comparable behavioral-adjacent surface in this codebase
(`device_ci`, DEX, Guardian device-view) was built with this pattern from day one, not bolted on
under implementation time pressure, and a bare deferral to "Issue 18.7" risked exactly that outcome
without a named gate. **The same binding condition covers the write-path's own observability
(added following Gate 2 re-review, 2026-07-08):** the `component_inventory.future_dated_rejected`
audit event and its paired Prometheus counter (Decision 2/8) must exist before this store's
implementation PR merges, checked by the same security-guardian gate as the read-surface audit
verb above — a compromise/clock-skew signal that's merely described in prose, with no reviewer
checking it actually shipped, is the same unenforced-deferral risk this condition already exists
to close for the read surface.

**Binding condition: the `installed_apps`/`InstallLocation` sequencing dependency (Decision 1) MUST
be confirmed landed before `component_inventory`'s Windows/macOS anchoring goes live, not merely
documented as a strong recommendation (added following hardening-round re-review, 2026-07-07, which
found the original wording — "must land before or alongside implementation" — was never elevated
to an actual merge-blocking condition the way the RBAC/audit item above was).** The implementation
PR (or the coordinated set of PRs, if the ADR-0016 amendment and `component_inventory` ship
separately) must record, as part of its own change summary, that this dependency has landed —
"strongly worded in the ADR" is not itself a gate; a reviewer must affirmatively check it before
approving. The `installed_apps` `list` action now reports `install_location` and `bundle_id`; the
hashed `list_inventory` blob addition has not landed, so this condition stays open until it does
(see the status row above).

**Binding condition: the `vuln_scan` → `component_inventory` fleet rollout follows the three-phase
sequence in Decision 2 (ship fleet-wide → repoint + retire the other four definitions → remove
legacy plugin code), not a single "coordinated" step (added following hardening-round re-review,
2026-07-07).** Specifically, phase (ii) (repointing `security.vuln_scan.scan` and retiring
`cve_scan`/`config_scan`/`summary`/`inventory`) must not begin before phase (i)'s fleet-wide
`component_inventory` adoption is confirmed, and phase (iii) (removing `vuln_scan`'s legacy code)
must not begin before phase (ii)'s repoint is confirmed live fleet-wide — either phase run out of
order reproduces the dispatch-to-a-plugin-that-doesn't-exist failure this sequencing exists to
prevent. This includes the RBAC re-audit named in Decision 2's point 4, which is part of phase (ii).

No works-council/co-determination review is required — Decision 1's reversal to machine-scope-only
collection, with no new cross-user privilege grant, was specifically designed to avoid that
trigger. If a future ADR revisits per-user coverage (e.g., via the session-scoped-helper
architecture named in Alternatives considered), that decision would need to re-open this question
on its own terms.

Route via the normal review / `/governance` path. Record the accepting reviewer(s) + date here on
acceptance.
