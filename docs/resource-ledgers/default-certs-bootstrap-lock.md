# Resource Ledger — default-cert bootstrap lock + first-boot key custody (`default_certs.cpp`)

This ledger documents every lease/lock/local-resource ownership boundary the default-cert
bootstrap machinery (`ensure_default_certs()` and its helpers, ADR-0053) introduces or moves, and
its guaranteed release/persistence path. Reviewers must verify that every code path (normal
return, every early `return false`, and every loop exit) releases or correctly hands off exactly
the listed resources. Moved here from `docs/adr/0053-ca-store-postgres-migration.md` (which now
points at this file) when that ADR's round-by-round governance sections were compacted into a
history table — a Resource Ledger is a policy-floor artifact (CLAUDE.md standing rule 2), not
process narrative, so it survives that compaction as a durable, standalone file rather than a
line in a history table.

---

## `e4c4d7cfc` — the bootstrap advisory-lock guard itself

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `auto lease` (`pg::PgPool::Lease`, `complete_default_cert_set_locked()`) | Local, RAII (existing `Lease` type) | `pool.try_acquire_for(kBootstrapLockAcquireTimeout)` against `ca_store->pool()` — a SEPARATE lease from `CaStore`'s own per-call leasing | Automatic, returns the connection to the pool at end of function scope | `!lease` (pool exhausted / timeout) logs and returns `false` before any lock attempt — no dangling lease, no lock ever requested |
| `DefaultCertsBootstrapLockGuard guard{lease.get()}` (wraps `pg::PgSessionAdvisoryLockGuard inner_`) | Local, RAII, non-copyable/non-movable (deleted ctors, mirrors `KekOpLockGuard`) | Constructed ONLY after `try_lock_default_certs_bootstrap()` returns `kAcquired` — never constructed on `kConflict`/`kError` | `pg_advisory_unlock` in `inner_`'s destructor; declared AFTER `lease` in the same scope so it destructs (releases the lock) BEFORE `lease`'s destructor returns the connection to the pool — releasing a lock on an already-recycled connection would be silently wrong | The bounded retry loop against `kBootstrapLockAcquireTimeout`/`kBootstrapLockRetryInterval` treats persistent `kConflict` as "another instance is completing its own bootstrap" (fails closed to "wait or bail", never proceeds unlocked); `kError` logs and returns `false` |
| `pg::PgResult res{PQexec(conn, sql.c_str())}` inside `try_lock_default_certs_bootstrap()` | Local, RAII (`PQclear` on destruction) | `PQexec` running the `pg_try_advisory_lock` SQL | Automatic, end of function scope | Guards the row read by construction (mirrors `try_lock_kek_op`'s own defensive shape) — `PQgetvalue`'s return is checked, not assumed non-null, before dereferencing `[0]` |
| `pg::PgPool& pool()` (`CaStore`, new `noexcept` const accessor) | Not owned — returns a reference to `CaStore`'s existing `pool_` member, whose lifetime is `CaStore`'s own | N/A — no acquisition, a plain reference return | N/A — `CaStore` owns `pool_` for its own lifetime, unaffected by callers reading the reference | `noexcept` is justified: the body is a single reference-returning member access, no allocation, no throwing operation reachable in it |

## `63cc22610` — the fencing check added on top

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `PGconn* lock_conn` (borrowed, `default_certs.cpp`'s new `complete_default_cert_set()` parameter) | Not owned by this function — real owner is `pg::PgPool::Lease` in `complete_default_cert_set_locked()` | Passed in by the caller (`lease.get()`); the no-`ca_store` fallback passes nothing, defaults to `nullptr` | Never released here — the caller's `Lease` releases it on scope exit, unchanged by this diff | `lock_conn == nullptr` skips the check entirely (no lock to verify); a live-but-dead connection is handled by `lock_connection_alive`'s own `PQstatus`/`PQexec` checks, never dereferenced unsafely |
| `pg::PgResult` inside `lock_connection_alive()` (new function) | Local, RAII (`PQclear` on destruction, existing `pg::PgResult` type, unchanged) | `PQexec(conn, "SELECT 1")` | Automatic, end of function scope | `PGRES_TUPLES_OK` check before use; no path leaves the result unowned |
| `https_key`/`server_key`/`gateway_key` (`std::string`, new in `try_use_existing_complete_set()`) | Local, RAII via `KeyZeroGuard` (this file's established wipe-on-scope-exit pattern) | `read_text_file()` on each leaf's `.key` path | `KeyZeroGuard` destructor zeroes on every exit from the enclosing `try` block (normal return, early `return false`, and the `catch`) | A read failure returns an empty string, which `pki::cert_matches_key` treats as a non-match (fails closed to "regenerate"), never a crash |

The `const_cast`-then-write UB cpp-safety also found in this same code (writing through a
`const_cast`-obtained reference to a genuinely `const`-qualified `auto` object — [dcl.type.cv]/4)
was fixed in the same round: the three declarations are non-`const`, matching this file's own
established `KeyZeroGuard leaf_zero{kc->private_key_pem}` idiom (no cast needed).

## `f60a150eb` — UP-3 self-heal poll loop + deferred `default-ca` key write

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `const std::string ca_key_ref` (`kp.path_for("default-ca").string()`) | Local value, not a handle — a pure path computation, no I/O, no custody to track | Computed once, before the race resolves | N/A — plain string, ordinary scope-exit destruction | None — `path_for()` cannot fail (no filesystem access) |
| `default-ca.key` on-disk file (via `kp.store_key("default-ca", *ca_key_pem)`) | `FileKeyProvider`'s existing temp+fsync+rename custody (unchanged internals); what changed is WHEN this function is called, not what it owns | **Deferred**: only called after `try_insert_root()` confirms this candidate is the CAS's sole winner (or, in the no-`ca_store` local-only fallback, immediately — no race to defer past) — never called speculatively before the race resolves, closing the pre-existing clobber window where multiple simultaneous candidates on a shared directory all wrote to this same fixed path and whichever write landed last silently won regardless of CAS outcome | The write itself is still the pre-existing atomic temp+fsync+rename (unchanged) | If the deferred write fails post-CAS-win: logs an error naming the now-orphaned `ca_key_ref` path and returns `false`. Residual, accepted: `ca_store` is left holding a root whose `key_ref` resolves to no file — indistinguishable from, and recovered via, the pre-existing "local key wiped/lost" path every other cause of key loss already uses (B-2 manual-recovery refusal, `restore from backup` / `clean re-root`) — not a new failure MODE, a new rare TRIGGER for an already-handled one. |
| `KeyZeroGuard ca_zero{*ca_key_pem}` (pre-existing, unaffected by this diff) | Local, RAII, unchanged | Constructed right after key generation, before the race | Zeroes on every exit from `ensure_default_certs`, including the new `return true;` inside the UP-3 poll loop (ordinary stack-unwind RAII — ownership boundary itself did not move, only the sequencing of a DIFFERENT resource, the on-disk key file above, changed) | N/A |

**A losing racer's poll loop (UP-3) holds no resource at all** — no Postgres connection, no lock,
no local write. It is a passive filesystem reader (`try_use_existing_complete_set`, pre-existing
and independently ledgered via its own `KeyZeroGuard` entries above) called repeatedly with a
`sleep_for` between attempts; the loop's own state is a `std::chrono::steady_clock::time_point`
deadline, a value type with no custody to track.

**Known residual (security-guardian, Gate 8 domain re-review of `f60a150eb`, MEDIUM, non-blocking,
accepted):** the window between `try_insert_root()` succeeding and the deferred key write landing
is new (pre-fix, the key file always existed before the DB row did). A *sibling* process reaching
the unrelated, pre-existing top-of-function B-2/UP-2 self-heal check during that exact window sees
`has_key(root.key_ref) == false` and falls straight to the manual-recovery refusal rather than
waiting — an availability-only, fail-closed, non-security-regressing effect (nothing anywhere in
the codebase treats "root exists in `ca_store`" as sufficient without also successfully loading
and cert/key-pairing the key — verified across every `kp.load_key(root->key_ref)` call site in
`server.cpp`). Not fixed: extending that unrelated check's own poll would delay a genuine
lost-key refusal by up to 15s on every established install hitting it, a worse trade than the rare
sibling-refusal it would prevent.
