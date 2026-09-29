# Stage 0 baseline — DEX obs-stream parity referent

Captured 2026-07-05 on `feat/spark-rebuild` @ origin/dev (2294dfe0). Authority: `docs/adr/0021-spark-reflex-architecture.md`, Parity gate item 2.

## Finding: the existing collector test suites cover EXTRACTION parity, not DELIVERY parity — a real gap

The campaign plan called for "DEX obs stream capture on reference scenarios" as a live recording exercise. The DEX test files (`test_dex_linux_journal.cpp`, `test_dex_linux_proc.cpp`, `test_dex_macos.cpp`, etc.) are a strong, byte-exact referent for **extraction**: they feed captured journal JSON / synthetic `/proc` content / canned OSLog/IOKit payloads directly to the mapping logic and assert the exact `obs_type` + `detail_json` produced. A live 3-OS scenario run would only add environmental noise on top of that — so for extraction, the fixture suite is genuinely the better referent, and Stage 4 should treat it as spec (same mechanism as Stage 2's Guardian gate).

**But extraction is not what Stage 4 rebuilds.** Stage 4's job is moving the *watcher* — journal tail + cursor, `EvtSubscribe` + bookmark, poll-latch, the rate-cap/coalesce/privacy-drop wiring around it — into spark types. The fixture tests stub the watcher out by construction (they hand the extractor a pre-captured event; they never exercise a live journal tail or `EvtSubscribe` handle). Checked directly: **zero** DEX collector tests are env-gated/live (`grep -rn "\[live\]" tests/unit/test_dex_*.cpp` → no hits; contrast Guardian's `test_guard_systemd.cpp` which has exactly one, `YUZU_SYSTEMD_LIVE_UNIT`-gated). So today's baseline has **no delivery-path coverage to inherit** — a Stage-4 spark-type watcher that drops events, double-fires, or regresses a cursor would pass the entire 214-case suite unmodified while being broken.

**Consequence for Stage 4:**
1. Fixture suite = the **extraction**-parity gate (treat as spec, unmodified pass required) — this part of the original plan stands.
2. **New requirement: one env-gated live/integration test per watcher mechanism** (journal tail, `EvtSubscribe`, `/proc` poll, WER, disk/battery poll-latch) that drives a real or injected source through the *new* SparkEngine-based watcher and asserts the obs comes out the other side — assertion-based, not a recording, so it doesn't reintroduce the environmental-noise problem fixture tests avoid. Mirrors the pattern `test_guard_systemd.cpp`'s `YUZU_SYSTEMD_LIVE_UNIT` case already establishes for Guardian; DEX has no equivalent today and Stage 4 must add one per mechanism, not just port fixtures.
3. Only with (2) in place is "existing suite passes unmodified" a meaningful Stage-4 gate rather than a gate with a hole exactly where the plan's own Risks section flags the biggest schedule risk.

## DEX test inventory (Stage 4 spec surface)

| File | Cases | Platform | Covers |
|---|---:|---|---|
| `tests/unit/test_dex_signals.cpp` | 71 | cross-platform | Signal catalogue structure, rate caps, privacy-drop rules, uniform `detail_json` keys |
| `tests/unit/test_dex_linux_journal.cpp` | 31 | Linux | journald: coredump→`process.crashed`, unit-failed→`service.crashed`, watchdog→`service.hung`, chronyd→`os.time_unsynced`, OOM-kill→`memory.exhausted` (cgroup-v1 + v2), privacy (comm-only, never raw paths/kernel figures), forged-identifier rejection |
| `tests/unit/test_dex_linux_proc.cpp` | 23 | Linux | `/proc`-sourced signals |
| `tests/unit/test_dex_linux_sysfs.cpp` | 5 | Linux | sysfs-sourced signals |
| `tests/unit/test_dex_linux_kmsg.cpp` | 19 | Linux | kernel ring buffer signals |
| `tests/unit/test_dex_macos.cpp` | 31 | macOS | OSLog/IOKit/DiagnosticReports-sourced signals |
| `tests/unit/test_dex_win_poll.cpp` | 12 | Windows | disk/battery poll-and-latch (`latch_should_emit`), the exact logic Stage-1's `spark_disk.cpp` ports |
| `tests/unit/test_dex_perf_breach.cpp` | 18 | cross-platform | sustained perf-breach hysteresis → `perf.*` family |
| `tests/unit/test_dex_rate_limiter.cpp` | 4 | cross-platform | per-signal-type rate caps |

**Total: 214 cases** across 9 files — the Stage 4 preserved-spec set (agent-side; server-side DEX routes/models in `tests/unit/server/test_dex_*.cpp` are a separate, unaffected surface since DEX's server half doesn't change shape in this rebuild, only its ingestion source).

## Static catalogue snapshot (referent for coverage completeness, not behavior)

- **Windows: 116 catalogue entries** in `dex_signal_catalog.cpp` (Event Log/WER-sourced — the "110-signal catalogue" figure in prior memory was an earlier count; 116 is current).
- **Linux: 10 obs_types** found by source grep across `dex_linux_{journal,proc,sysfs,storage,kmsg}.cpp`: `disk.error`, `fs.corruption`, `hw.error`, `memory.exhausted`, `os.bugcheck`, `os.dirty_shutdown`, `os.time_unsynced`, `process.crashed`, `process.hung`, `service.crashed`, `service.hung`. (Grep-based — may undercount any obs_type built via a shared constant rather than a literal string; the 214-case test inventory above is the authoritative behavioral referent, this list is just a coverage sanity count.)
- **macOS: 19 obs_types** found the same way: `disk.smart_failure`, `fs.corruption`, `hw.cpu_throttled`, `hw.error`, `logon.no_dc`, `memory.exhausted`, `mgmt.mdm_error`, `network.wifi_drop`, `os.bugcheck`, `os.uptime_report`, `print.failed`, `process.crashed`, `process.hung`, `process.resource_limit`, `service.crashed`, `storage.low`, `update.failed` (17 distinct — some source files share a couple of these, hence 19 raw matches vs 17 unique).

Most Linux/macOS obs_types reuse the Windows vocabulary (per prior memory: "~16 obs_types reusing Windows types = ZERO server change" for macOS) — server-side DEX rendering is unaffected regardless of which OS a signal originates from.

## What's still deferred to Stage 11 (needs the physical rigs)

Three-OS **live** UAT (Windows VM, Linux laptop rig, macOS) exercising the disk-threshold Reflex end-to-end, and any collector behavior that only manifests under real timing/scheduling (e.g. actual ETW buffer pressure, actual ESF entitlement gating) — the fixture tests above intentionally can't catch those, by design (determinism over realism). This is consistent with the resource gate's own back-to-back-at-Stage-11 protocol (`stage0-resource-baseline.md`) — Stage 0 defines the referent and the protocol; Stage 11 is where physical-rig evidence gets captured once, not staggered across the campaign.
