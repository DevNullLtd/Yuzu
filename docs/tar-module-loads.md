# TAR Module / Image Load Capture Source (`$Module`)

**Status:** M1 shipped + M2 implemented (2026-06-16). M1: `$Module` schema, the `EventRing<T>` template, the `ImageStreamCollector` interface, the data-driven aggregator. **M2: the Windows ETW image-load collector** (`tar_module_etw.*`) — a dedicated session on Microsoft-Windows-Kernel-Process (IMAGE keyword), drain-time WinVerifyTrust signing + `module_dir` redaction, the §5 edge risk-filter, plugin wiring (`module_enabled`, on by default), and `tar.status` surfacing. The macOS-testable surface (pure mapping, redaction, risk-filter, signing-cache, typed insert) is unit-tested green; the **live ETW session is Windows-only and verified by the runbook in the M2 PR**, not unit tests (same bar as `tar_proc_etw`). macOS (M4/M5) and Linux (M6) collectors are next. §12 tracks the ladder; §13 records the carried-forward conditions.
**Audience:** TAR plugin maintainers, agent engineers, dashboard/SQL surface engineers.
**Owners:** `architect` (capture-source shape), `plugin-developer` (TAR action surface), `cross-platform` (per-OS mechanism + build gating), `cpp-safety` (ETW/ES callback lifetime + the templated ring), `security-guardian` (signing-verdict correctness), `docs-writer` (schema↔handler cross-check + dashboard nav).
**Related:** `docs/tar-dashboard.md` (the operator surface this source feeds), `agents/plugins/tar/src/tar_proc_stream.hpp` (the ring/collector idiom this source extends), `agents/plugins/tar/src/tar_proc_es.hpp` / `tar_proc_etw.hpp` (the streaming peers), `docs/darwin-compat.md` (macOS ES build/runtime gating).

---

## 1. Why a module/image-load source

The process source answers "what ran"; `$Module` answers "**what did it load**" — the activity class that turns a benign-looking process into an incident. It is the natural and cheapest Tier-1 extension of the process stream because the gap-free plumbing already exists: the **same Windows ETW session** and the **same macOS Endpoint Security client** that feed `process_live` can subscribe to image-load events with no new kernel session.

Threat model it covers:

- **DLL search-order / sideload hijack** — a legitimately-signed `app.exe` loading an unsigned `version.dll` from its own directory. The forensic signal is **path + signing status**, neither of which `$Process` carries.
- **Code injection** — unsigned or file-unbacked modules mapped into a running process.
- **Malicious drivers / kexts** — BYOVD (bring-your-own-vulnerable-driver) is the dominant kernel-attack pattern; a kernel image-load timeline is the detection surface.
- **LOLBins** — signed loaders pulling in attacker payloads.

The high-value field throughout is **signing status + signer** — the discriminator between "Microsoft loaded a Microsoft DLL" and "a signed process loaded an unsigned blob from `%TEMP%`."

This is an **activity-record** source (TAR's domain), distinct from DEX reliability signals (`dex_signal_catalog`) and Guardian desired-state guards. It must not duplicate either.

## 2. Per-OS mechanism

| OS | Mechanism | Stream / Poll | Reuses existing? | v1 status |
|---|---|---|---|---|
| **Windows** | `Microsoft-Windows-Kernel-Process` provider, **image keyword `0x40` (`WINEVENT_KEYWORD_IMAGE`), event ID 5 (`Image/Load`)** — the *same provider* TAR already subscribes for process start/stop. Driver loads surface as kernel image-loads (System pid). Signing verdicts overlaid from the **`Microsoft-Windows-CodeIntegrity/Operational`** log (events 3033/3034 = unsigned/blocked image load). | Stream | ✅ same ETW session | **Supported** |
| **macOS** | `es_subscribe` adds `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` / `ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD` (first-class) on the *same ES client*. User-space dylibs have **no first-class ES load event** — the realistic signal is `ES_EVENT_TYPE_NOTIFY_MMAP` filtered to file-backed executable pages, plus the code-signing fields ES already carries (cdhash, team_id, signing_id, `is_platform_binary`). | Stream | ✅ same ES client | **Supported** (kext) / **Constrained** (dylib via mmap) |
| **Linux** | Kernel modules via auditd `init_module`/`finit_module` syscall rules (or the `module:module_load` tracepoint) — clean, low-volume, no eBPF toolchain. Shared-object (`.so`) loads need eBPF (LSM `mmap_file` / `dlopen` uprobe) and are **explicitly deferred** to a separate track (§13). | Poll (audit feed) | partial (new collector) | **Constrained** (kmod only) / **Planned** (.so via eBPF) |

Mechanism notes that shape the implementation:

- **Windows reuse is the headline.** PR2 adds one keyword and one event-ID handler to the live `Microsoft-Windows-Kernel-Process` session — it does not stand up a second trace session. Exact event IDs are validated against the live provider manifest in the implementing PR.
- **macOS signing is free.** The ES message already carries the full code-signing identity, so the macOS path needs **no separate verification call** — unlike Windows, where signing must be verified out-of-band (§6).
- **Linux v1 is kernel-modules-only, by decision.** `.so` load coverage is real but requires the eBPF investment; shipping kmod-via-audit now delivers the BYOVD/rootkit signal cheaply and keeps the source live on all three OSes.

## 3. Event shape & the ring refactor

Module loads need a different value type than `ProcEvent`, but the bounded-ring backpressure idiom in `tar_proc_stream.hpp` is generic (a mutex-guarded vector + a drop counter). The refactor:

1. **Promote `ProcEventRing` to `EventRing<T>`** — a templated bounded ring; `using ProcEventRing = EventRing<ProcEvent>;` preserves the existing call sites and tests. The drop-counter / `push()`-never-blocks / `drain()`-empties contract is unchanged.
2. **Add a sibling `ImageStreamCollector` interface** alongside `ProcStreamCollector`, with the identical lifecycle contract (`start()` returns false → caller degrades; `drain()` moves buffered events out each fast tick; `dropped()` for NFR visibility; `method_name()` for the status field). The TAR plugin holds one per platform.

```cpp
// tar_module_stream.hpp (new)
struct ModuleEvent {
    int64_t      ts_unix{0};
    uint8_t      action{0};        // 0 loaded · 1 unloaded · 2 seed · 3 blocked
    uint32_t     pid{0};
    std::string  process_name;     // resolved at DRAIN (off the callback thread)
    std::string  module_name;      // basename of the loaded image
    std::string  module_dir;       // directory — the search-order-hijack signal (see §8)
    uint8_t      signed_state{0};  // 0 unknown · 1 signed · 2 unsigned · 3 invalid · 4 revoked
    std::string  signer;           // publisher (Windows) / team_id (macOS); "" otherwise
    bool         is_kernel{false}; // driver (Win) / kext (macOS) / kmod (Linux)
};
```

Resolution that can block (Windows `LookupAccountSid`-style signer lookup, `getpwuid`) happens at **drain**, off the kernel-serial ETW/ES callback thread — exactly the `sid→user-at-drain` idiom already documented on `ProcEvent`.

## 4. Schema — the `$Module` capture source

A new `CaptureSourceDef` in `tar_schema_registry.cpp`, same granularity ladder as `$Process`:

```
module_live    (row-count, default 100000 — but the §5 edge filter is the real bound)
  ts, snapshot_id, action, pid, process_name, module_name, module_dir,
  signed_state, signer, is_kernel

module_hourly  (time-based, 24h)
  hour_ts, module_name, signer, signed_state, is_kernel, load_count

module_daily   (time-based, 31d)
  day_ts, module_name, signer, signed_state, is_kernel, load_count

module_monthly (time-based, 12mo)
  month_ts, module_name, signer, signed_state, is_kernel, load_count
```

- `dollar_name = "Module"` → queryable as `$Module_Live` / `$Module_Hourly` / … through the existing `tar.sql` whitelist + `$`-name map. **No new agent action and no new REST route** — registry registration is sufficient.
- `os_support` records the §2 status/method per OS so the schema↔handler cross-check test (the H2/G9 pattern) binds the published capability to the actual collector.
- Rollups group by `(module_name, signer, signed_state, is_kernel)` with a `load_count`. Risky loads (unsigned/invalid/revoked/kernel/blocked) are also retained at full fidelity in `module_live` per §5.
- **`load_count` counts only `loaded` events.** `seed` / `blocked` / `unloaded` rows live at full fidelity in `module_live` but are excluded from the aggregate count — so a `blocked` BYOVD load is preserved for forensics yet never inflates a load rate. The trade-off: an operator must query `module_live` (not the rollups) to see blocked loads. M7 may add a dedicated `blocked_count` rollup column if the aggregate tier needs it.

## 5. Volume control — the crux

Module loads are **an order of magnitude noisier than process starts** (one browser launch loads 100+ DLLs). Naive capture-everything makes `module_live` unusable. The bound is an **edge risk-filter applied before the warehouse write**, in the same spirit as `netqual`'s "per-tick top-N cap is the real bound, row-count is the backstop":

- **Always full fidelity in `module_live`:** unsigned / invalid / revoked signatures, kernel driver/kext/kmod loads, and CodeIntegrity-`blocked` loads. Rare, high-signal.
- **First-seen-then-drop for the rest (M2 as-built):** for normally-signed platform/system modules, keep the first `(action, process_name, module_name, module_dir, signer, signed_state)` tuple per drain batch at full fidelity in `module_live`, then **drop** subsequent identical loads — they are neither retained nor counted. `module_dir` is in the key so a search-order-hijack (`version.dll` in an app dir vs System32) is not collapsed, and `action` is in the key so a signed `unloaded` is not folded into its `loaded` row.
  - **Count-folding is deferred to M7, not done in M2.** The end-state design is *first-seen-then-**count***: dropped duplicate signed loads fold into `module_hourly.load_count` so a DLL loaded 50× in a window reports `load_count = 50`. M2 does **not** implement that — `load_count` is computed only from the rows that survive into `module_live` (consistent with §4: `load_count` counts the surviving `loaded` rows). Until M7 lands, the aggregate count under-reports repeated normally-signed loads; high-signal events (unsigned/invalid/revoked/kernel/blocked) bypass dedup entirely and are unaffected.

The `module_live` row-count cap (100k) is the deterministic storage backstop, **not** the primary control — the filter is. A minimal version of this filter ships **with** the first high-volume collector (PR2) so the source is bounded from day one; thresholds — and the M7 count-fold above — are refined once real fleet volume is observable (PR7).

## 6. Signing verification

The signer/`signed_state` fields are the source's reason to exist, so a **wrong verdict is itself a security bug** — this path gets `security-guardian` review.

- **Windows:** verify out-of-band with `WinVerifyTrust` (Authenticode) at **drain**, never on the ETW callback thread. Cache by `(image_path, last-write-time)` so a hot DLL is verified once. **(M2 as-built)** The ETW `ImageName` is an NT device path (`\Device\HarddiskVolumeN\…`), which `WinVerifyTrust`/`GetFileAttributesEx` reject, so it is converted to `\\?\GLOBALROOT\Device\…` before verify/stat. Verification runs with `WTD_REVOKE_NONE` — **no online CRL/OCSP revocation check** (a per-load network fetch is unacceptable for a high-volume source), so a *revoked* image reads as `signed` here; the authoritative `revoked`/`blocked` verdict comes from the CodeIntegrity/Operational overlay (M3), which complements the userland check.
- **macOS:** signing identity is already on the ES message (cdhash, team_id, signing_id, `is_platform_binary`, codesigning flags) — **no verification call**. Map `is_platform_binary` / valid team id → `signed`, hard/invalid flags → `invalid`/`unsigned`.
- **Linux:** kernel modules carry no Authenticode-equivalent the agent can cheaply check; `signed_state` is `unknown` unless IMA/EVM measurement is present. Honest "unknown" beats a fabricated verdict.

## 7. Boot-gap seed

> **M2 status: deferred (not implemented).** M2 captures only loads that occur after the session starts; modules already loaded before then are not back-filled — exactly as the process collector's boot backfill was a separate slice. Tracked as a follow-up (see §13). Design intent below.

A live stream only sees loads after the agent starts. Parity with the process source's seed model:

- **Windows:** one-shot per-process module enumeration at startup (`CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` / `EnumProcessModules`), written `action=seed`.
- **Linux:** seed currently-loaded kernel modules from `/proc/modules` (`lsmod` equivalent), `action=seed`, `is_kernel=1`.
- **macOS:** kexts seedable via `kextstat`-equivalent enumeration; **user-space dylibs are not cleanly enumerable per-process**, so the macOS seed is kext-only — documented as a known gap, no worse than the live stream it precedes.

## 8. Config, privacy, retention

- **Toggle `module_enabled`, default `true`** (default off when this design was written, matching the `procperf` / `netqual` precedent given the volume; on by default since the v8 default-on change, where every capture source ships enabled). Once present it rides the existing `tar.configure` write path, the retention-paused-list machinery (#539), and per-source `*_enabled` / `*_paused_at` reporting **for free**.
- **`module_dir` is captured deliberately** (operator-confirmed 2026-06-16). This is a conscious divergence from the process source's strict names-only posture: for a module, the *directory* is the forensic signal (a `version.dll` in an app dir vs `System32`), whereas a process command line is gratuitous. We capture the directory, **not** a command line, and the existing TAR redaction patterns still apply to the path before serialization.
- **Retention** follows §4: row-count backstop on `module_live`, time-based TTL on the rollups, enforced by the existing `run_retention()` on the 15-min rollup tick.

## 9. Collect-tick wiring

The plugin holds one `ImageStreamCollector` (constructed per platform) and **drains it on the existing `collect_fast` tick (60 s)**, alongside the process stream — module loads correlate with process starts, so they share cadence and `snapshot_id` for join-ability. No new trigger. When `start()` returns false (wrong OS, missing entitlement/privilege, session-open failure), the source simply produces nothing — there is never silent partial loss, exactly as the process collector degrades.

## 10. Operator / query surface

- `$Module_*` is queryable via the TAR SQL frame the moment it's in the registry whitelist — the canonical "show me every unsigned DLL loaded by a signed process in the last 24h" query needs no new surface.
- The retention-paused list (`/fragments/tar/retention-paused`) picks up `module` as a fourth+ source automatically via the per-source machinery.
- **Process-tree integration (optional, deferred):** the tree viewer could render per-process module loads as a child detail pane; out of scope for the initial ladder, tracked as a follow-up.

## 11. Governance & test touchpoints

Per the project governance gates, the implementing PRs must clear:

- `cpp-safety` — ETW/ES callback lifetime, the templated `EventRing<T>`, the signing-cache concurrency, drain-thread ownership.
- `cross-platform` — 3-OS `#ifdef` gating, `YUZU_HAVE_ENDPOINT_SECURITY` + `-fblocks` (macOS), Windows-only ETW, the auditd feed (Linux). Loads `docs/darwin-compat.md`.
- `security-guardian` — the signing-verdict path (a false "signed" is exploitable), `module_dir` redaction.
- `docs-writer` — `docs/tar-dashboard.md` source list, this doc, and the schema↔handler cross-check unit test that binds `os_support` to the collector's per-type support (the H2/G9 invariant).
- Unit tests: pure `*_sample_to_module_event()` mappings (header-free, run on every platform), the `EventRing<T>` refactor regression, the §5 risk-filter logic, and a rollup-SQL round-trip.

Run the full `/governance` + `/test` pipeline on each code PR (mandatory, not optional).

## 12. PR ladder

Each PR compiles, is independently governable, and leaves the tree green. Tracer-bullet ordering: schema first (queryable-empty), then collectors per OS, then volume tuning and surface.

| PR | Scope | Leaves |
|---|---|---|
| **M1** | **Schema + ring refactor.** Promote `ProcEventRing`→`EventRing<T>`; add `ModuleEvent` + `ImageStreamCollector` interface (no concrete collector); register the `$Module` source (live/hourly/daily/monthly) + rollup SQL + migration; `module_enabled` config (default off); schema↔handler cross-check test. | `$Module_*` queryable, always empty (no feeder). |
| **M2** | **Windows ETW image-load stream (as-built).** A **dedicated** `Microsoft-Windows-Kernel-Process` session with the IMAGE keyword `0x40`, events 5/6 → `ModuleEvent` ring; drained on `collect_fast`. `WinVerifyTrust` + `CryptQueryObject` signing at drain (NT path → `\\?\GLOBALROOT`, `(path,mtime)` cache); `module_dir` redaction after signing; the minimal §5 risk-filter; `module_enabled` (default off then; on by default since the v8 default-on change) with **lazy start** (enable next-tick, auto-re-arm). Boot-gap seed **deferred** (§7). Windows `os_support` → Supported; live ETW verified by the PR runbook. | Windows module timeline live (runbook-gated). |
| **M3** | **Windows CodeIntegrity overlay.** Subscribe `Microsoft-Windows-CodeIntegrity/Operational` (3033/3034) → `action=blocked` / authoritative `signed_state`. | Kernel-enforced verdicts captured. |
| **M4** | **macOS kext stream.** Add `NOTIFY_KEXTLOAD`/`KEXTUNLOAD` to the existing ES client; signing straight from the message; `kextstat` seed; `is_kernel=1`. macOS (kext) `os_support` → Supported. | macOS driver loads live. |
| **M5** | **macOS dylib via `NOTIFY_MMAP`.** File-backed executable mmap → `ModuleEvent`, run hard through the §5 risk-filter; macOS (dylib) `os_support` → Constrained. | macOS user-space modules (filtered). |
| **M6** | **Linux kernel-module via auditd.** Parse `init_module`/`finit_module` (or `module:module_load`) → `ModuleEvent` (`is_kernel=1`); `/proc/modules` seed. Linux (kmod) `os_support` → Constrained. | Linux kmod loads live; `.so` deferred (§13). |
| **M7** | **Risk-filter + retention tuning.** Refine §5 thresholds against real fleet volume from M2/M4; finalize row caps and rollup grouping. | Bounded, tuned warehouse. |
| **M8** | **Dashboard polish + docs.** Surface module timeline on the TAR page; optional process-tree module pane; finalize `docs/tar-dashboard.md` + add the CLAUDE.md routed-concern pointer now that the source is wired. | Operator-facing, documented. |

## 13. Open / deferred

- **Linux `.so` loads via eBPF** — deliberately out of this ladder. Needs an eBPF toolchain + LSM/uprobe strategy decision; scope as its own design + issue once the kmod feed (M6) is proven. This is the single biggest remaining coverage gap and should be tracked explicitly so "Linux module loads" is never read as complete.
- **Process-tree module pane** (§10) — follow-up after M8.
- **Unload events** — captured where the stream offers them (Windows event ID 6, ES `KEXTUNLOAD`) but lower forensic value than loads; not a gating requirement.
- **`base_address` / image size** — useful for some injection analysis, high-churn; omitted from the warehouse in v1, revisit if a concrete query needs it.

### Carried forward from M1 governance

The M1 governance run (8 gates) cleared M1 with the BLOCKING dead-rollup fixed in-round (the aggregator is now data-driven). These SHOULD findings are explicitly deferred to the collector PRs — a collector PR that lands without addressing its row is incomplete:

- **M2/M4/M6 — `module_dir` redaction is BLOCKING for the collector.** `module_dir` is a filesystem path that can contain a user-profile prefix (`C:\Users\<name>`, `/home/<name>`, `/Users/<name>`) — personally identifying. The collector must scrub user-profile prefixes at the edge (the DEX edge-drop precedent) before the warehouse write, and the dashboard must `html_escape` it on render (stored-XSS). `security-guardian` gate on every collector PR.
- **M2 — `tar.status` must surface `module_capture_method` + `module_stream_dropped` unconditionally**, mirroring the `process_*` block exactly (emit `none`/`0` on no-stream platforms) so agentic consumers can read by key presence and ring-overflow loss is never silent.
- **M2/M5 — `module_enabled` must NOT default `true`** until both the §5 edge risk-filter and the rollup wiring are live (rollup is now wired as of M1; the risk-filter lands with the first high-volume collector). **Satisfied in M1 (review follow-up):** `CaptureSourceDef::default_enabled = false` is now the single source of truth threaded through `source_enabled()` / `do_status()` / retention / the `paused_at` transition (and applied to `procperf`/`netqual` too), so this default-off constraint was closed for `module`. **Superseded:** `module` now ships `default_enabled = true` like every other capture source (registry-wide invariant), with the stored-`false` values of installed agents reset once by the tar.db v8 migration.
- **Before EU-workforce deployment — works-council / SOC 2.** Add a `$Module_*` row to the data inventory in `docs/enterprise-readiness-soc2-first-customer.md` §3.5 and name `$Module` (specifically `module_dir`) alongside `procperf` as an EU co-determination trigger. File the `module_dir` divergence decision (operator-confirmed 2026-06-16) as a named decision record / issue.
- **M8 — discovery state + docs.** Surface "collector planned vs enabled vs no-data" so an empty `$Module_*` query is distinguishable from "not collecting" (architect); add `$Module` to `docs/tar-dashboard.md` + `docs/user-manual/tar.md`; update the CLAUDE.md TAR routed-concern row to list `tar_module_stream.*` and note the deliberate `module_dir` exception to "names-only".
- **Deferred test hardening.** A concurrent push-vs-drain `EventRing<T>` stress test under `-Db_sanitize=thread` (the ring is a cross-thread bridge; current coverage, like the process ring's, is single-threaded). The Windows MSVC leg is the real enforcement point for the `EventRing<ProcEvent>` explicit-instantiation + inline-in-header interaction.

### Carried forward from M2 governance (19-agent run, 2 HIGH fixed in-round)

Both HIGH findings (NT-device-path → `\\?\GLOBALROOT` conversion; `pid_name` blackout → clear-on-full) were fixed and re-reviewed in the M2 hardening round. The restart-to-enable limitation was also removed (collector now lazy-starts on the first enabled tick). Deferred items:

- **M7 (perf tuning) — `SigningCache` eviction + per-event `stat`.** The cache flushes wholesale at the cap; under high path-churn this degrades to a `WinVerifyTrust`-per-event drain. Replace with LRU / 2-segment eviction so the hot system-DLL working set stays cached. Also `GetFileAttributesEx` runs per event inside `collect_mu_` — cache the `mtime` per path within the drain loop.
- **M7 — risky-load per-drain cap.** Unsigned/invalid/kernel/blocked loads are intentionally uncapped; under a true storm `module_live` can grow past the 100k row-cap between the 15-min rollups. Add a per-`(process,module)` rate cap on risky loads with an overflow counter surfaced via `module_stream_dropped`-style telemetry.
- **Follow-up — boot-gap seed** (§7): enumerate already-loaded modules at start (`EnumProcessModulesEx`/Toolhelp), `action='seed'`, per-boot dedup like the process `.etl` backfill. `WinVerifyTrust` works on the seed (file still on disk).
- **Follow-up — `module_stream_dropped` as a Prometheus counter** (`yuzu_tar_module_stream_dropped_total`) — a pre-existing pattern gap shared with the process stream (only reachable via `tar.status` today). File once, covers both.
- **Operator docs (with the M8 doc pass)** — `docs/user-manual/tar.md`: the `WTD_REVOKE_NONE` no-revocation disclosure, the `$Module` OS-compatibility matrix (Windows supported; macOS/Linux planned M4/M5/M6 so a pilot operator knows why it's empty), and `module_live`'s row-count (not time-based) retention. The SOC 2 `$Module` data-inventory row (`docs/enterprise-readiness-soc2-first-customer.md` §3.5) is now due since data can flow on Windows.
- **Known limitation (documented in code) — `redact_module_dir`** does not catch 8.3 short names or redirected/roaming profile roots; `$Process_Live` is the authoritative cross-reference. `pid_name` is best-effort under PID reuse (same cross-reference).

## 14. Cross-references

- `docs/tar-dashboard.md` — operator surface + source list this extends.
- `agents/plugins/tar/src/tar_proc_stream.hpp` — the ring/collector idiom (`EventRing<T>` refactor target).
- `agents/plugins/tar/src/tar_proc_etw.hpp` / `tar_proc_es.hpp` — the streaming peers M2/M4 mirror.
- `agents/plugins/tar/src/tar_schema_registry.cpp` — where the `$Module` `CaptureSourceDef` lands.
- `docs/darwin-compat.md` — macOS ES build/runtime gating (`YUZU_HAVE_ENDPOINT_SECURITY`, entitlement, root).
- `docs/dex-signal-catalog.md` — the reliability-signal store this source must NOT duplicate.
</content>
</invoke>
