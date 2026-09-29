# Resource Ledger — #2818 subscription-death notification (PR-2d)

Run: `governance.d/2818-subscription-death-notification.Em6B8F.jsonl`
Range: `origin/dev..HEAD` (branch `fix/2818-subscription-death-notification`, 12 commits)

## Summary

This diff introduces **no new fd / HANDLE / SOCKET / `FILE*` / `sqlite3_stmt*` / `sqlite3*` /
OpenSSL object / BCrypt handle / allocated C string / mapped library / temp path / subprocess /
thread**. Every new piece of state is an ordinary value type under existing RAII and lock
discipline, or a thin addition to an already-audited resource this PR does not itself acquire
or release (`registry_mu_`, `mu_`, `mech_ops_mu_by_type_`, `outbox_mu_`, `ConvergenceScheduler`'s
own priority-lane thread). No policy-floor violation of the "manual cleanup in new C++ must be
RAII-wrapped" kind exists in this diff — there is no manual cleanup to wrap.

## Table 1 — new value-type state (no manual lifetime management required)

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `lost_ev` | `SparkEvent` (stack) | `SparkEngine::arm_impl` | function-local | Snapshot built under `mu_`, consumed by `deliver()` after `mu_`/`mech_ops_mu_by_type_` both release. Never escapes the frame. |
| `lost_subs` | `std::vector<Subscriber>` (stack) | `SparkEngine::arm_impl` | function-local | Same lifetime as `lost_ev`; a plain value copy of `Armed::subs`. |
| `stamped` | `SparkEvent` (stack) | `SparkEngine::deliver` | per-loop-iteration | Conditional copy (`needs_copy = kind != Fired`); never referenced past the iteration that creates it. |
| `ev` / `subs` | `SparkEvent` / `std::vector<Subscriber>` (stack) | `SparkEngine::report_fault` | function-local | Same snapshot-then-release-then-deliver pattern as `arm_impl`'s. |
| `w` (deferred `std::expected`) | stack | `SparkEngine::start` (pre-start-replay loop, Gate 3 fix) | function-local | Hoisted out of the newly-narrowed `ops`-locked block so `report_fault()` can run after `ops` releases; ordinary value type, no ownership transfer. |
| `snapshot` | `std::vector<std::pair<std::string, std::uint64_t>>` (stack) | `GuardianSparkRuntime::revalidate_subscriptions` | function-local | Built under `registry_mu_`, iterated with the lock released; each element consumed by a subsequent `on_subscription_lost` call that re-acquires the lock itself. |
| `rule_ids` | `std::vector<std::string>` (stack) | `GuardianSparkRuntime::on_subscription_lost` | function-local | Copy of `index_->rules_for(key)`, taken once (Gate 8 fix — was briefly taken twice before that fix) and consumed by the detach loop within the same lock scope. |
| `entries` | `std::vector<OutboxEntry>` (stack) | `GuardianSparkRuntime::on_subscription_faulted` | function-local | Built under `registry_mu_`, handed to `outbox_.enqueue_all(std::move(...))` (pre-existing, already-audited ownership transfer) within the same lock scope. |

## Table 2 — new counters / flags (no acquire/release semantics)

| Resource | Type | Owner | Notes |
|---|---|---|---|
| `subscription_lost_.{fetch_add,load}` | `std::atomic<std::uint64_t>` member | `SparkEngine` | Same pattern as four pre-existing sibling counters in the same class (`watch_faults_`, `arm_race_unwatch_failures_`, `disarm_unwatch_failures_`, `teardown_join_timeouts_`); no new synchronization primitive. |

## Table 3 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `mech_ops_mu_by_type_.at(type)` (`std::mutex`, per-type) | `SparkEngine` | Scope narrowed (Gate 3 fix) in `start()`'s pre-start-replay loop so `report_fault()` runs after release, not while held — closes a self-deadlock class. No new acquisition site added. |
| `registry_mu_` (`std::mutex`) | `GuardianSparkRuntime` | Three new call sites (`on_subscription_lost`, `on_subscription_faulted`, `revalidate_subscriptions`'s snapshot phase) acquire/release it using the exact same `std::lock_guard` idiom every existing method in this class already uses. |
| `backend_` (`std::shared_ptr<ISparkBackend>`) | `GuardianSparkRuntime` | Read-only copy of the `shared_ptr` in `revalidate_subscriptions`; assigned once at construction, never reassigned — no new thread-safety concern. |
| `ConvergenceScheduler`'s existing priority-lane `std::thread` | `ConvergenceScheduler` | One new `firewalled_sweep` call added to its existing tick; no new thread spawned. |
| Guardian lifecycle-journal on-disk records (`kv_`-backed) | `GuardianLifecycleJournal` | A pre-existing kind-validation allowlist (Gate 6 fix, `guardian_lifecycle_journal.cpp:1119`) widened from 2 to 3 accepted literal values. No new record shape, no new field, no new acquire/release — a pure string-comparison change to an existing validation gate. |

## Sanitizer coverage

- **TSan** (`[tsan]` + `[tsan-heavy]`): clean, including after the Gate 3 lock-scope fix — this is
  exactly the class of defect (a lock held across a caller boundary into now-callback-capable
  code) TSan's own deadlock/lock-order detection is positioned to catch, and the new regression
  test (`Pre-start replay fault delivery does not deadlock an inline self-disarm`) additionally
  proves it empirically via a real bounded-hang check under plain, TSan, and ASan.
- **ASan** (against the properly-instrumented `x64-linux-asan` triplet): clean, except a
  pre-existing flake class in `test_guardian_engine_spark_reconcile.cpp` — confirmed, via a
  dedicated re-verification pass (run after merging `origin/dev` into this branch, NOT
  after this PR's own merge - PR-2d has not yet been pushed or opened as a PR), to be
  `spark_spec_from_rule()`'s Service-type
  `service_name` param lookup (`guardian_spark_bridge.hpp:146-150`) intermittently reading
  back empty on ANY `make_service_rule(...)`-based test, ASan-only (10/10 clean on a plain
  build, ~1/3 failure rate under ASan), reproduced identically on an unmodified sibling test
  this PR never touched (`"a supported type arms via spark, never in legacy guards_"`), and
  NOT a caught ASan memory-safety violation (no `ERROR: AddressSanitizer` report ever
  printed across dozens of reproductions) — pointing to a logic-level race ASan's overhead
  makes more likely to manifest, not memory corruption ASan itself would catch. Filed as
  **#4067**; not introduced by this diff, not fixed here.
- No new resource type in this diff falls outside what plain + TSan + ASan already cover; no
  additional sanitizer configuration was needed.
