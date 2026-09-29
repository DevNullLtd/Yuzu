# Stage 0 baseline — resource-gate protocol + premise validation

Captured 2026-07-05 on `feat/spark-rebuild` @ origin/dev (2294dfe0), before any Stage 1+ code change. Authority: `docs/adr/0021-spark-reflex-architecture.md` §11 (Resource gate).

## The plan text was wrong about tooling — corrected here

The campaign plan cites "the existing `/test` perf measure machinery" for the resource gate. That machinery (`scripts/test/perf-gate.sh`, `docs/perf-baseline-calibration-2026-05-03.md`) measures the **Erlang gateway's** throughput/latency (`perf_registration_ops_sec`, `perf_heartbeat_queue_ops_sec`, `perf_fanout_*_ms`, `perf_session_cleanup_ms_per_agent`) — not the agent process's idle CPU/wakeups/thread-count/RSS that the ADR's resource gate is actually about. There is no existing harness for the latter; one is scoped below rather than assumed.

## Protocol (defined now, executed at Stage 11 — not today)

**Do not freeze "old" numbers today and compare against "new" numbers captured weeks/months later.** Kernel version, background load, and hardware drift between captures would contaminate the comparison. `origin/dev` is a reproducible commit forever — the disciplined move is to capture **old and new back-to-back on one rig** at Stage 11, not stagger them.

- **Rig:** the Windows VM (per `project-windows-agent-test-rig` memory) is the primary rig — it's the only platform where BOTH `guard_registry`/`guard_file` (Windows-only, currently thread-per-instance) exercise, alongside the service guard and TriggerEngine. A Linux measurement (this doc's validation run, below) only exercises the cross-platform subset (TriggerEngine's 4 fixed worker threads + the systemd service guard).
- **Load profile:** idle-agent numbers are close to useless for this comparison — both old and new look small with zero rules armed. Measure **under a fixed armed load**: N registry guards + N file guards + N service guards + N interval triggers (same N old vs new, e.g. N=20 to match the validation run below), all actually armed via a real or synthetic Baseline/policy push.
- **Metrics:** thread count (`CreateToolhelp32Snapshot`/`Thread32First/Next` on Windows — see `tpwait_spike.cpp`'s `current_process_thread_count()`, a ready-made sampler; `/proc/self/status` `Threads:` on Linux), **handle/fd count** (`GetProcessHandleCount` on Windows; count `/proc/self/fd` entries on Linux — REQUIRED, not optional: the systemd service spark can collapse threads while keeping one bus connection + eventfd per unit, a partial win that thread count alone would hide; see the premise-validation section below), RSS (`GetProcessMemoryInfo().WorkingSetSize` / `/proc/self/status` `VmRSS:`), wakeups/sec (TP callback counter on Windows; `voluntary_ctxt_switches`+`nonvoluntary_ctxt_switches` delta as the Linux proxy), idle CPU% (process CPU time delta over a quiescent sampling window).
- **Gotcha:** a live agent's gRPC reconnect backoff loop adds wakeup noise to any idle sample if it can't reach a server — sample against a real (or absent-but-expected) server connection consistently between old and new, not ad hoc.

## Premise validation — done now, on real code, cheap

Before committing to the O(mechanisms)-vs-O(rules) thesis as Stage 1's core justification, checked whether it holds on the *old* code, on the piece I can exercise on this Linux box: `SystemdServiceGuard` (`agents/core/src/guard_systemd.cpp`, `agents/core/include/yuzu/agent/guard_systemd.hpp:189-192` — each instance owns a dedicated `std::thread thread_` + its own sd-bus connection).

**Method:** a temporary Catch2 case (hidden tag `[.]`, never part of the permanent suite — written, run, and reverted via `git checkout` in the same session; not committed) constructed 20 `SystemdServiceGuard`s against real running systemd units on the dev box (`accounts-daemon`, `avahi-daemon`, `bluetooth`, `chrony`, `colord`, `containerd`, `cron`, `cups`/`cups-browsed`, `dbus`, `docker`, `gdm`, `ModemManager`, `networkd-dispatcher`, `NetworkManager`, `nvidia-persistenced`, `polkit`, `power-profiles-daemon`, `rsyslog`, `rtkit-daemon`), sampling `/proc/self/status` `Threads:` before arming, after arming, and after `stop()`.

**Result:**

```
thread count before=1 after 20 guards=21 after stop=1
```

Exactly O(rules): +1 thread per armed guard, precisely 20 added for 20 guards, and a clean return to baseline on teardown (no leak). Windows `guard_registry`/`guard_file` are architecturally identical (`thread_ = std::thread(...)` per instance, confirmed by inspection) and expected to show the same scaling.

**What this does and does NOT prove.** It confirms the **problem** — the old model is genuinely O(rules) in threads (and, for systemd, O(rules) in bus connections + eventfds too; see below) — on real code, not just on paper. It does **NOT** confirm the **win**: SparkEngine collapsing N watches onto O(mechanisms) threads is still entirely unbuilt and unmeasured. Those are different claims; don't let "the premise is validated" read as "the fix delivers." The O(mechanisms) win remains **unvalidated until SparkEngine exists and is measured back-to-back at Stage 11**.

**The win is also not uniform across spark types, and for systemd it's a rewrite not a port.** `guard_systemd.cpp:244` calls `sd_bus_open_system(&bus)` **per guard** — one bus connection + one eventfd + one thread *each*. Collapsing N systemd unit-watches onto O(mechanisms) means multiplexing them onto a **single sd-bus connection with N match rules on one epoll loop** — a re-architecture, not the "port the watching" framing the trigger-inventory doc uses. Until that's designed, the service spark's collapse is not guaranteed: a naive port could collapse *threads* while leaving *one bus connection + eventfd per unit*, winning only part of the prize. **Therefore the Stage-11 resource gate must measure connection/handle/fd count alongside thread count** — thread count alone would over-report the win for the service spark. (Windows SCM `NotifyServiceStatusChange` has the analogous question: one registration path multiplexed vs one per service.)

**Contrast — TriggerEngine is already O(mechanisms), not O(rules).** Inspection of `trigger_engine.cpp:147-153` shows it spawns exactly 4 worker threads at `start()` regardless of how many triggers are registered (`interval_loop`, `file_watch_loop`, `service_watch_loop`, `registry_watch_loop` — one thread per *mechanism*, shared across all rules of that type). SparkEngine's thread win over TriggerEngine is therefore smaller than the win over Guardian's per-guard-instance model — worth noting in the Stage-11 report so the resource-gate narrative attributes the improvement to the right subsystem (mostly Guardian, TAR's five `register_trigger` calls notwithstanding since those already share TriggerEngine's 4 threads too).

## Stage-11 action items derived from this baseline

1. Run the back-to-back old-vs-new capture on the Windows VM per the protocol above — this is the canonical resource-gate evidence, not the Linux validation run (which stays in this doc as premise support only).
2. Reuse `tpwait_spike.cpp`'s sampling primitives (`current_process_thread_count`, `current_rss_bytes`) for the Windows side rather than writing a new sampler.
3. Report thread-count delta separately for "Guardian-attributable" (registry/file/service guards, per-instance today) vs "TriggerEngine-attributable" (already shared) so a reviewer can sanity-check the magnitude of the claimed win.
