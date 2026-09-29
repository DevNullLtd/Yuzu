# Stage 0 baseline — `yuzu_register_trigger` inventory (ABI-migration worklist)

Captured 2026-07-05 on `feat/spark-rebuild` @ origin/dev (2294dfe0), before any Stage 1+ code change. Authority: `docs/adr/0021-spark-reflex-architecture.md`.

## SDK surface (retires in Stage 5)

- `sdk/include/yuzu/plugin.h:299` — C ABI `yuzu_register_trigger(YuzuPluginContext*, const char* trigger_id, ...)`.
- `sdk/include/yuzu/plugin.hpp:162` — C++ wrapper `PluginContext::register_trigger(...)` (thin call-through).
- `agents/core/src/agent.cpp:422` — the ABI entry point implementation; requires `pctx->trigger_engine` in the per-plugin context (`agent.cpp:2423` wiring comment; the context field is set at `:554`).
- `agents/core/src/trigger_engine.{hpp,cpp}` — the engine itself; deletes in Stage 5.

## Plugin callers — grep across all 47 plugins found exactly ONE

**`agents/plugins/tar/src/tar_plugin.cpp`** — the only plugin calling `register_trigger`/`unregister_trigger`. Five interval-type triggers, all TAR pumps:

| Trigger ID | Type | Purpose | Runtime re-register site |
|---|---|---|---|
| `tar.fast` | interval | fast capture cadence | `tar_plugin.cpp:430`, dynamic re-register `:2573/:2577` |
| `tar.slow` | interval | slow capture cadence | `tar_plugin.cpp:435`, dynamic re-register `:2581/:2585` |
| `tar.perf` | interval | perf-tier capture | `tar_plugin.cpp:449` |
| `tar.software` | interval | software-inventory capture (config-tunable cadence, "0" disables — `tar.yaml:455`) | `tar_plugin.cpp:464`, dynamic re-register `:2592/:2597` |
| `tar.rollup` | interval | warehouse rollup | `tar_plugin.cpp:470` |

All five unregister on shutdown/reconfigure (`:736-740`). This is the entire Stage-5 "built-in schedules → shipped Reflex bindings" worklist — small and fully enumerated, not a discovery risk.

## Content-plane trigger vocabulary (server-side `TriggerConfig`, separate mechanism)

`content/definitions/trigger_templates.yaml` defines the InstructionDefinition-authored `triggerType` vocabulary — this is the exact set the Stage-1 spark-type file split (`spark_interval.cpp`, `spark_disk.cpp`, `spark_file.cpp`, `spark_service.cpp`, `spark_registry.cpp`) must cover, plus one that was missing from the original plan when this was captured (`spark_startup.cpp` — since landed on `dev`):

| `triggerType` | Template id | Maps to Stage-1 file |
|---|---|---|
| `interval` | `trigger.interval` | `spark_interval.cpp` |
| `file_change` | `trigger.file_change` | `spark_file.cpp` |
| `service_status` | `trigger.service_status` | `spark_service.cpp` |
| `registry_change` | `trigger.registry_change` | `spark_registry.cpp` |
| `agent_startup` | `trigger.agent_startup` | `spark_startup.cpp` — one-shot, fires once at agent boot, no watcher thread. **[Update: was flagged missing from the original Stage-1 file list when this baseline was captured 2026-07-05; `spark_startup.cpp` has since landed on `dev`.]** |

`spark_disk.cpp` (disk-threshold) has no content-plane `TriggerConfig` template today — it's DEX-only (`dex_win_poll.hpp` `latch_should_emit`), ported directly per the existing plan.

## Other trigger mentions (no code action needed)

`policy_management.yaml` and `tar.yaml` reference "trigger" only in prose/config-tunable descriptions of the above — no additional call sites.

## "Port" vs "rewrite" — the service spark is a rewrite, not a port

The Stage-1 framing "port the watching" (move detection logic from `guard_*.cpp` into `spark_*.cpp`) is accurate for the interval, disk, file, and registry sparks, but **understates the service spark**. Today each `SystemdServiceGuard` opens its OWN `sd_bus_open_system` connection + eventfd + thread per unit (`guard_systemd.cpp:244`); the Windows `ServiceGuard` similarly holds a per-service SCM `NotifyServiceStatusChange` registration. Achieving SparkEngine's O(mechanisms) collapse for `spark_service.cpp` means **multiplexing N unit-watches onto a single bus connection with N match rules on one epoll loop** (Linux) / a single multiplexed SCM notification path (Windows) — a re-architecture, not a lift-and-shift. Budget the service spark's Stage-1 effort accordingly, and see `stage0-resource-baseline.md` for why the resource gate must check connection/fd count (a naive port collapses threads but not connections — a partial win).

## Stage 5 action items derived from this inventory

1. ~~Port `agent_startup` as a spark type (missing from the original Stage-1 file list) — one-shot fire-at-boot, no persistent watcher.~~ **DONE — `spark_startup.cpp` landed on `dev`.**
2. Convert TAR's 5 interval triggers to shipped Reflex bindings (embedded content, per ADR §8) — `tar_plugin.cpp`'s `register_trigger`/`unregister_trigger` calls are replaced by SparkEngine subscription + Reflex binding lookup; the dynamic re-register-on-reconfigure paths (`:2573-2597`) need an equivalent "rebind on config change" path in the new engine.
3. Delete `yuzu_register_trigger`/`unregister_trigger` from the ABI (`plugin.h`, `plugin.hpp`), `trigger_engine.{hpp,cpp}`, and the `agent.cpp` wiring (`:422`, `:554`/`:2423` context field) once TAR is migrated — no other plugin depends on them.
