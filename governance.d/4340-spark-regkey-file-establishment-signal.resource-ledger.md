# Resource Ledger — #4340 (Registry/File establishment-readiness signal)

Companion to the governance run ledger `4340-spark-regkey-file-establishment-signal.KJlbJc.jsonl`.
Range `a9984d565..eb5c05b35` (plus docs-only `0c078fab9`). A Resource Ledger is required for a C++ diff
(policy floor); Gate 1's copy lived only in a session scratch file, so it is recorded here, together with
the deltas found by Gate 8.

## Production code (`agents/core/src/spark_registry.cpp`, `spark_file.cpp`, `spark_mechanism.hpp`)

No new fd, HANDLE, SOCKET, `FILE*`, sqlite handle, OpenSSL/BCrypt object, C string, mapped library, temp
path, subprocess or thread. New state, per mechanism (`RegistryMechanism`, `FileMechanism`):

| resource | owner | acquired | released | transfer | failure cleanup |
|---|---|---|---|---|---|
| `SparkEstablishedFn established_` (std::function callback context) | the mechanism, under `mu_` | `set_established_sink()` (before `start()`, moved in) | nulled in `stop()` AFTER the sweeper/worker thread is joined | none (moved in; read by reference, off-lock, by the sweeper/worker only) | std::function RAII; the single call site is inside `try{}catch(...)` |
| `bool sink_sealed_` | mechanism, `mu_` | set FIRST in `start()` | never cleared (engine is single-shot) | — | — |
| `RegWatch::{incarnation,coverage,coverage_at,coverage_report_due}`, `DirWatch::{coverage,coverage_at,coverage_report_due}`, `KeyBinding::incarnation` | the watch struct, under `mu_` | `mark_coverage_locked` (`noexcept`, three scalar writes) / adoption rebind | destroyed with the watch | — | scalars |
| `SweepWork::established` / `FilePassWork::established` (`std::vector<PendingEstablished>`; each entry owns a copy of the key string, File's also a `std::wstring dirkey`) | per-pass stack object | `push_back` in the sweep visit (Registry: capacity reserved at pass top; File: reserved per DirWatch inside the visit; the key copy can throw) | destroyed at pass end; on a throw `unwind_pass_locked` re-marks `coverage_report_due` for each entry (non-allocating `find`), then clears | — | re-mark under `mu_`, `noexcept`-safe |
| `std::atomic<uint64_t> established_failed_` | mechanism | — | — | — | — |
| first-drop `spdlog::warn` (fix round 1/2) | sweeper/worker thread, off-lock | in the sink `catch(...)`, once per mechanism (`established_failed_.fetch_add(1) == 0`) | — | — | nested `try{}catch(...){}`; formats the KEY (owned copy in the staged entry) |

Threads: none created. Touched: Registry TP_WAIT callback thread (`on_fire` marks under `mu_`), Registry
sweeper thread and File IOCP worker thread (stage under `mu_`, dispatch off-lock). Callback context:
`established_` is invoked only from `run_off_lock()` with `mu_` released (one call site per TU:
`spark_registry.cpp` ~1629, `spark_file.cpp` ~2579). The sink installed by the engine captures the engine
(`[this]`, `spark_engine.cpp` ~1482): `mechanisms_` is declared after the engine's `mu_`/`armed_`, so it is
destroyed first, and `~SparkEngine` joins the mechanisms before those members die — reordering
`mechanisms_` above `mu_` or `armed_` would open a use-after-free (same class as the existing emit/fault
callbacks).

## Test code (`tests/unit/test_spark_mechanism.cpp`, Windows-only `#ifdef _WIN32` region)

| resource | owner | release | notes |
|---|---|---|---|
| `std::unique_ptr<ISparkMechanism> mech` in RF-17 / FF-17 (sweeper or IOCP thread, Win32 handles, threadpool objects, detached probe workers, callback contexts) | the test's local `mech` | normal `~mech` join on every green run and every failure except a PROVEN wedge | **deliberate, intentional non-release**: `LeakIfWedged` calls `(void)m.release()` only when `wedged == true`, set solely when the sink's re-entry started and did not return within 10 s (`reentered && !reentry_done`); ownership passes to process lifetime |
| `std::shared_ptr<Race>` (log, flags, atomics, keys/params by value, `EstLog`) | `st` in the test frame plus by-value copies held by every closure the mechanism owns | freed when the last closure dies; on the leak path it is co-leaked with the mechanism | nothing a leaked sweeper/worker can reach lives on the test stack |
| `ScopeExit` guards (`open_occupy` etc.) | test frame, declared AFTER `mech` | open the parked-probe gates on unwind, before `~mech` | order: `LeakIfWedged` -> guards -> gates -> `~mech` -> `ScratchRegKey`/`ScratchDir` |
| `EstLog::stall` (borrowed pointer), `OpenGateOnExit` (borrowed reference) | borrowed from `Race` / the test frame | not owners | lifetime is bounded by `Race`/the frame, both declared before the mechanism that uses them |
| `ProbeGate` / `FileProbeGate` (atomic inside-count, bounded <= 10 s destructor wait) | the test frame (or `Race`) | destructor releases, then waits for the count to reach zero | known residual: a detached probe worker launched but not yet inside the hook can still touch a destroyed stack-owned gate (finding `g8-probegate-entry-window`, follow-up) |

**Adjudication of the deliberate leak (documented-impossibility exception, not self-granted):** adjudicated
by security-guardian (Gate 8 round 2) with cpp-safety and quality-engineer concurring, conditional on the
proven-wedge-only condition and the co-leaked state (satisfied in `eb5c05b35`). These are subagents of the
authoring session, so independence is asserted, not verified. Why it is acceptable: the alternative is
`~mech` -> `stop()` -> unbounded sweeper join on a sweeper wedged holding `mu_`, which hangs the whole test
binary; the leak is failure-only, test-only, and harmless because every reachable object is co-leaked.

## Addendum (ledger review): callback contexts stored in the test code

Found by the compliance-officer ledger review; each is a stored callback context whose captured state must
outlive the thread that calls it.

| callback context | captured state | owner / lifetime |
|---|---|---|
| `EstLog::sink()` and `EstLog::fault_sink()` closures (`[this]`, test_spark_mechanism.cpp ~4658) | the `EstLog` (its mutex, entries, `throw_if`, `stall`) | the `EstLog` lives in the `Race` block (RF-17/FF-17, held by `shared_ptr` in every closure) or is declared BEFORE the mechanism in the other cases (round-1 tst-lifetime fix), so it outlives the sweeper/worker that calls it |
| `Collector::handler()` (engine-level RF-2..RF-9 / FF-2..FF-9, ~line 58) | the `Collector` (pre-existing helper) | declared BEFORE `SparkEngine engine` after the round-2 hoist, so the engine joins its threads before the collector dies; the pre-existing baseline tests keep the old order (46 uses, follow-up) |
| `sweep_hook = [&passes]` in RF-9 (~line 5193) | a local `std::atomic<std::size_t> passes` | declared before the engine/mechanism (round-2 hoist) |
| `probe_hook` / `emit_bookkeeping_hook` closures installed via `set_*_test_controls_for_test` | the `Race` block (RF-17/FF-17) or gate objects declared before the mechanism | the controls REPLACE every hook on each call; the hook is a `shared_ptr` shared with detached probe jobs, which is the source of the known ProbeGate entry-window residual (finding `g8-probegate-entry-window`) |
