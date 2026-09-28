# Resource Ledger — #4666 PR-4 T_server dedicated async logger

This ledger lists every thread, queue buffer, sink, and lock the PR-4 diff introduces, with its
owner and release path, for `server/core/src/guardian_ingest.{hpp,cpp}` and the seam's one
installation site, `server/core/src/main.cpp`. A Resource Ledger is a policy-floor artifact
(CLAUDE.md standing rule 2), so it is a standalone file rather than a line in a PR description.
Format follows `docs/resource-ledgers/4666-log-handoff.md` (the PR-1 agent-side primitive this
logger deliberately mirrors, much more lightly).

## Scope, and why this is much smaller than PR-1's ledger

PR-1/PR-2 built and wired a general-purpose async hand-off for the AGENT's entire default
logger — every `spdlog::` call in that process, an unbounded set of call sites, with a teardown
watchdog (`ShutdownDeadlineGuard`) because the agent's shutdown sequence has to bound a wedged
pool join against real deadlines (systemd/SCM stop timeouts). PR-4 backs exactly ONE server log
line (`guardian_ingest.cpp`'s `"Guardian T_server ..."`, the Inserted/non-observation arm of
`ingest_guardian_response`) with its own tiny logger. No teardown watchdog is built here (MUST
#5 of the #4666 PR-4 spec) — an ACCEPTED exposure, not an eliminated one (corrected 2026-09-28
by adversarial review; an earlier draft of this ledger overstated the bound). The server's
`main.cpp` DOES have hard-exit machinery (`on_signal_hard_exit`), but it is signal-driven, not
self-armed: the FIRST `SIGINT`/`SIGTERM` takes the graceful `Server::stop()` path, and only a
**second** signal (or the deployment's external stop deadline — `TimeoutStopSec=210s` in
`deploy/systemd/yuzu-server.service`, `stop_grace_period: 210s` in
`deploy/docker/docker-compose.yml`) reaches `on_signal_hard_exit`. So a sink that stalls
mid-drain leaves this pool's exit-time worker join bounded by that second signal / 210s
deadline, not by "a plain SIGTERM" as such. This exit-time join is a genuinely NEW blocking
point this PR introduces — the pre-existing synchronous default logger owns no worker to join
at teardown — accepted because the 210s external bound already exists and because PR-4 removes
the ONE line that used to be additionally exposed at thread level (the
first per-event `info` line on a guardian-only agent's Subscribe read thread — see
`docs/spark-flip-gate.md` §7's `F14` precondition). No heartbeat/metrics surfacing is built
either (out of scope; the agent-side equivalent is tracked separately as #5024). This whole
logger is itself a temporary fixture, not a permanent addition to the server's steady-state
resource footprint: `T_server` is a benchmark diagnostic for the #4606 Spark cutover, and PR-7
in the `spark-4666-retire-synchronous-log-writes-DELIVERY-PLAN.md` ladder (gated on `gh issue
view 4606` closing) retires the line — and, with it, everything this ledger accounts for —
entirely.

## `server/core/src/guardian_ingest.{hpp,cpp}`

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `spdlog::details::thread_pool` (one 1024-slot queue + one worker thread) | Bundled into the returned `std::shared_ptr<spdlog::logger>` via a second control block whose deleter captures both the pool and the `async_logger` shared_ptrs (see the next row) — `spdlog::async_logger` itself holds only a `std::weak_ptr` back to its pool (verified against the vendored spdlog's `async_logger-inl.h`: `sink_it_()`/`flush_()` both do `if (auto pool_ptr = thread_pool_.lock()) ...`), so nothing else keeps the pool alive once `create_t_server_logger()` returns | `create_t_server_logger()`, constructed directly via `std::make_shared` — never `spdlog::init_thread_pool()`, matching `LogHandoff`'s own reasoning (a shared global pool would be a second, uncontrolled owner of a queue this logger needs to reason about alone) | Runs when the LAST strong reference to the returned logger handle drops — today that is whichever of `spdlog`'s registry entry (`spdlog::register_logger`, `main.cpp`) or `set_t_server_logger`'s own global slot (`guardian_ingest.cpp`) is released last, both installed together at boot and never explicitly torn down before process exit | A healthy sink drains in order and `~thread_pool()`'s worker join returns promptly. A wedged sink means that join simply does not return until a SECOND `SIGINT`/`SIGTERM` or the deployment's external stop deadline (210s, both shipped systemd/Compose configs) ends the process some other way — there is no dedicated watchdog around it (see "Scope" above); this exit-time join is a NEW blocking point this PR introduces (the pre-existing synchronous default logger owns no worker to join at teardown), accepted because that 210s external bound already exists. |
| **Fixed RSS cost of the pool's queue — not proportional to traffic.** `spdlog::details::circular_q` pre-allocates all `kTServerLogQueueCapacity + 1` (1025) slots **at `thread_pool` construction**, each slot a `spdlog::details::async_msg` (`sizeof == 408` bytes on x64 — the SAME vendored-spdlog measurement `agents/core/src/log_handoff.hpp`'s `static_assert(sizeof(spdlog::details::async_msg) == 408, ...)` already pins for this repo's spdlog version; not re-pinned a second time here, since a spdlog version bump that changed it would already fail that build-wide assertion first). | The `std::vector<async_msg>` inside `circular_q`, owned transitively by the pool | Same moment as the pool itself — paid in full up front, not a high-water mark | Same as the pool's own release | 1025 × 408 bytes = 418,200 bytes ≈ **408 KiB (≈418 KB)**, always, for the life of the process (this logger is constructed once, at boot, and never rebuilt). Roughly 1/8 of PR-1's 3.34 MB figure, proportional to the 8× smaller queue capacity (1024 vs 8192 — this backs one diagnostic line, not the whole process's logging). Payload bytes beyond the fixed per-slot allocation (the T_server line's own formatted text, well under 200 bytes) are additional and negligible at this volume. |
| **`overrun_oldest` eviction under sustained queue-full — genuinely UNCOUNTED, not merely unread (governance hardening round, 2026-09-28).** Distinct from `TServerErrorState` below, which counts and truncates an ERROR (a sink throw or formatter exception) but has nothing to do with a normal, non-throwing eviction under a full queue. spdlog's `thread_pool` itself exposes `overrun_counter()` (confirmed present in the vendored source), but `create_t_server_logger()` returns only the type-erased `shared_ptr<spdlog::logger>` bundle — no caller anywhere in this diff retains a handle to the `thread_pool` itself, so `overrun_counter()` is unreachable, not just unexposed. | spdlog's own `thread_pool` (internal `overrun_counter_`) | Incremented internally by spdlog on every `circular_q::push_back` eviction | Never read, by anything, anywhere in this diff | An operator has genuinely NO signal — not even an unread number — that T_server lines are being silently dropped under sustained load. Exposing this (e.g. `create_t_server_logger` returning a small struct bundling the pool alongside the logger, rather than the logger alone) is real follow-up work, not a docs fix; tracked as a #5024-adjacent follow-up, not built in this PR. |
| `spdlog::async_logger` (name `"guardian.t_server"`, `overrun_oldest`) | The `std::shared_ptr<spdlog::logger>` returned by `create_t_server_logger()`, held afterward by `spdlog::register_logger`'s registry entry and by `set_t_server_logger`'s file-local global (`guardian_ingest.cpp`, guarded by `g_t_server_logger_mu`) | `create_t_server_logger()`, immediately after the pool | Dropped when both the registry entry and the global slot release their copies (registry: process lifetime; global slot: only ever re-set by `main.cpp` at boot or by a test) | Holds only a `std::weak_ptr` back to the pool (never a cycle). `sink_it_`/`flush_` throwing (pool gone, formatter/allocation exception) routes to the error handler below, never escapes uncaught into `ingest_guardian_response`'s caller (spdlog's own `SPDLOG_LOGGER_CATCH`, plus the call site's own enclosing `catch (...)`, belt-and-braces). |
| Sink list (caller-supplied, unwrapped — no `StallObservableSink`-style stall-observing wrapper here, unlike `LogHandoff`) | The `async_logger`'s own `sinks_` member; `main.cpp` passes `spdlog::default_logger()->sinks()` **copies** (owned `shared_ptr`s — `logger::sinks()` returns `std::vector<sink_ptr>&`, so copying is safe and never dangling even if the default logger is later replaced) | Same construction call | Dropped with the `async_logger` | No stall-observability accessor is built for this logger (`in_write()`/`stalled_for()` have no equivalent here) — out of scope for this PR; a future consumer wanting that would extend this logger, not fork a second one. |
| Error handler state (`TServerErrorState`: a `std::mutex` guarding a count and a 256-byte-truncated last-message string — **no** stderr fallback, no rate-limit timestamp, no detached emit thread) | A `std::shared_ptr<TServerErrorState>` captured by value into the `set_error_handler` lambda | Same construction call | Ends when the `async_logger`'s own captured copy releases (i.e., with the logger) | Reached from the pool's one worker thread (a sink throw) or, in principle, a producer thread (a formatter/allocation exception, or "pool gone") — hence the plain `std::mutex`, matching `LogHandoff::ErrorState`'s own reasoning for the same concurrency shape. **Deliberately does NOT mirror `LogHandoff::ErrorState`'s rate-limited stderr fallback (#5023's own subject)**: that fallback exists to preserve an operator-visible signal that predates `LogHandoff` (spdlog's own default error handler always printed to stderr, and `LogHandoff` REPLACES the process default logger, so losing that signal silently would be a regression). This logger does not replace anything already stderr-visible — it backs exactly one diagnostic line that did not have its own error-handler-driven stderr behavior before this PR either (a plain `spdlog::info()` call on the default logger routes a THROW, if any, through spdlog's OWN default handler, unchanged elsewhere) — so no equivalent fallback is owed here. No production reader of the count/message today (matches `LogHandoff::log_errors_total()`'s own "no reader yet" note) — but the count itself DOES exist and increments correctly; this is "unread," not "uncounted." Do not conflate this with `overrun_oldest` eviction (the row above), which is a different, genuinely uncounted signal — an error-handler invocation and a queue-full eviction are disjoint events with no shared counter. |
| `g_t_server_logger_mu` / `g_t_server_logger` (mutex + `std::shared_ptr<spdlog::logger>`) — the seam `set_t_server_logger()`/`t_server_logger_snapshot()` operate on | File-local (`guardian_ingest.cpp`'s anonymous namespace), process-wide | First write via `set_t_server_logger()` — `main.cpp` at boot (or a test) | Never explicitly released; overwritten by a later `set_t_server_logger()` call (production: only ever at boot; tests: once per `TEST_CASE` via `TServerLoggerCapture`/the MUST-#10 non-blocking test, always restored to `nullptr` before the backing sink is destroyed) | Null-safe by construction: `t_server_logger_snapshot()` returns `nullptr` if never set (or already cleared), and the T_server call site skips logging and increments `g_t_server_log_skipped_total` instead of falling back to any other logger — falling back to the (synchronous) default logger would reintroduce the exact hazard this seam exists to close. |
| `g_t_server_log_skipped_total` (`std::atomic<std::uint64_t>`) | File-local, process-wide | Incremented at the T_server call site whenever `t_server_logger_snapshot()` returns `nullptr` | Never reset (cumulative for process lifetime) | Zero in a healthy running server (logger installed at boot before any Guardian traffic can arrive). Test-only reader (`t_server_log_skipped_total_for_test()`); no production consumer (out of scope for this PR, same posture as PR-1's own unread `log_errors_total()`/`stderr_emits_dropped()`). |

## `server/core/src/main.cpp` — the one installation site

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| The registered `"guardian.t_server"` entry in spdlog's process-wide logger registry (`spdlog::register_logger`) | spdlog's own `details::registry` singleton | Once, in the logging-setup block, between the default-logger-set step and the `set_formatter`/`set_pattern` calls (so a later runtime `--log-level` override — which only reaches ALREADY-REGISTERED loggers — reaches this one too) | Process lifetime; never explicitly deregistered | `spdlog::register_logger` throws on a duplicate name (unreachable today — `"guardian.t_server"` is a fixed, unique literal — but defensive, since a future refactor could plausibly call this twice). Caught locally in `main.cpp`, logged via `spdlog::warn` on the default logger, and the T_server seam is simply left unset — **never `EXIT_FAILURE`** (MUST #7 of the #4666 PR-4 spec: a diagnostic-only logger must be best-effort by construction). `create_t_server_logger()`'s own internal construction failure (thread creation refused) is caught the same way, one level down, and returns `nullptr` before `register_logger` is ever called. |

## Trigger rows and invariants this change was checked against

- **`common/include/` shared-header firewall (#2549) — NOT APPLICABLE.** This PR touches
  `server/core/src/` and `agents/core/src/log_handoff.hpp` only for reference/mirroring, and adds
  no file under `common/include/`.
- **Prometheus metrics / observability-conventions row — NOT APPLICABLE.** No metric, alert rule,
  or audit envelope changes; this is a diagnostic log line whose destination changes, not its
  content, format, or existence (unchanged format string, unchanged neutralised-id arguments,
  unchanged enclosing `catch (...)`).
- **C++ resource ownership and lifetime (`docs/cpp-conventions.md`) — APPLICABLE, addressed
  above.** The pool/logger bundling via a second control block (rather than a dedicated owning
  class, since MUST #8 of the spec contracts `create_t_server_logger()` to return a plain
  `std::shared_ptr<spdlog::logger>`) is the one non-obvious ownership decision in this diff; see
  the first table row and the function's own comment in `guardian_ingest.cpp` for the full
  reasoning (an `async_logger` holds only a `weak_ptr` to its pool, so something has to keep the
  pool alive for as long as the logger is used, and the aliasing-deleter trick is the standard
  way to bundle two independently-refcounted objects behind one returned handle without adding a
  new class).
