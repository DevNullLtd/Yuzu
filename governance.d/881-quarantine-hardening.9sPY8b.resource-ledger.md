# Resource Ledger — `881-quarantine-hardening.9sPY8b`

Every owning boundary the C++ in `origin/dev..HEAD` acquires. Required by the
Gate 1 contract on any C++ diff; recorded here rather than only in the run
narrative so a later reader can check it against the code.

**This diff acquires exactly two fds, both through RAII stream owners** (rows
below). Nothing in it acquires a HANDLE, SOCKET, `sqlite3*`, `sqlite3_stmt*`,
OpenSSL or BCrypt object, allocated C string, or mapped library. The `TempFile`
used by the macOS pf write is pre-existing and already RAII-owned by
`yuzu::TempFile`.

An earlier revision of this ledger asserted "nothing in this diff acquires an
fd", which was false the moment `linux_ipv6_stack_present` was added — the
sibling `std::ofstream` was listed and its `std::ifstream` was not. Recorded
because a ledger's value is that the omission is visible, and this one was
caught by the omission being inconsistent with its own neighbouring row.

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| `std::timed_mutex` → **removed** | was `MutationGate` | — | — | — | Replaced wholesale by the ticket queue below; no site retains it |
| `MutationGate::m_` (`std::mutex`) | `MutationGate` member | `std::unique_lock` in `try_enter`; `std::lock_guard` in `leave` | scope exit | none — never leaves the function | RAII |
| **Queue ticket** (`std::uint64_t` in `waiting_`) | `MutationGate::waiting_` | `push_back` under `m_` in `try_enter` | `TicketGuard::~TicketGuard`, on **every** path incl. an exception escaping `cv_.wait_for` (which is not `noexcept`) | none | RAII scope guard. Was a hand-written erase on two paths — a throw between push and erase left a ticket nothing removes, wedging the gate for the process lifetime once it reached the head |
| **Gate hold** (`held_` flag) | `MutationGate` | set under `m_` on a successful `try_enter` | `MutationGate::leave()` from `Guard::~Guard` | move-only `Guard`, `std::exchange`-to-null; self-move guarded | RAII; a moved-from `Guard` releases nothing |
| `quarantine_snapshot_mtx_` (`std::mutex`) | `ServerImpl` member | `std::lock_guard` in `make_containment_gate` and in the refresher thread | scope exit | none | RAII. Never held across the store read or the metric increment |
| **Containment-read slot** (`std::counting_semaphore<kMaxConcurrentContainmentReads>`) | `ServerImpl::containment_read_slots_` | `try_acquire_for` in `make_containment_gate` (500ms) and in the snapshot refresher (2s) | `ServerImpl::ContainmentReadSlot` destructor — a class-scope type with an explicit ctor, deleted copy ops and **no move ops**, so there is no moved-from double-release | none | RAII, and that is load-bearing rather than incidental: the acquire→release window contains two `continue`s and, in the refresher, a body that CAN throw (see the row above). A guard is what makes those paths safe; an earlier revision of this row claimed there was no early return or throw in the window, which was false on both counts. A timeout acquires nothing, so `release()` can never exceed `LeastMaxValue` |
| `quarantine_snapshot_refresh_thread_` (`std::thread`) | `ServerImpl` member | spawned in `start()`, only when `quarantine_store_` exists | `join()` in `stop()`, **before** `quarantine_store_.reset()` and `pg_pool_.reset()` | none | Joined unconditionally if joinable. The body **can** throw — it allocates the id set, and `list_quarantined` returns `std::optional` and allocates internally — so the tick is wrapped in a per-tick `try`/`catch(...)`, because an exception escaping a `std::thread` entry is `std::terminate`. An earlier revision of this row asserted the body could not throw and was wrong on both counts |
| Subprocesses (`iptables`, `ip6tables`, `pfctl`, `netsh`) | `yuzu::agent::run_bounded_subprocess` (pre-existing, ADR-3002 rung 2) | per call | by the runner, deadline-bounded | none | Owned entirely by the runner; this diff adds call sites, not a spawn primitive |
| `std::ifstream` on `/proc/sys/net/ipv6/conf/all/disable_ipv6` | local in `linux_ipv6_stack_present` | `ifstream` ctor | destructor | none | RAII. `if (!f)` covers both non-existent and unopenable; an extraction failure yields `0` ("stack present"), which contains v6 rather than skipping it — the safe direction |
| `std::ofstream` on the pf ruleset temp file | local in `macos_load_ruleset` | `ofstream` ctor | explicit `close()`, then scope exit | none | RAII, and the close is **checked** — replaced an `fopen`/`fputs`/`fclose` trio that discarded both write and flush results |
| `yuzu::TempFile` (pf ruleset) | local in `macos_load_ruleset` | `TempFile::create` | destructor | move-only | Pre-existing RAII owner, unchanged |
| Plugin KV key `win.prior_firewall_policy` | agent plugin storage (durable, not an OS resource) | `store_prior_policy`, **before** the first mutating netsh call | `clear_prior_policy` on release | n/a | Write-once; a refused write leaves the previous record intact and is reported on both channels |
| `plugin_ctx_` (`YuzuPluginContext*`) | **non-owning** — the host owns it and outlives the plugin | cached in `init()` | never | n/a | Null-checked at all four accessors |
| `std::thread holder` / contender threads (tests) | `test_quarantine_serialization.cpp` | test body | `ReleaseAndJoin` destructor / explicit `join()` | none | RAII joiner covers exception unwind |

**Adjudications recorded:** none required — no manual cleanup in new C++ remains
after the `TicketGuard` change, so the "documented impossibility" exception is
not invoked anywhere in this diff.

**Sanitizer coverage.** No TSan leg exists in-tree for either new primitive.
Standalone TSan probes were run against `MutationGate` (12 threads x 3s, 1931
acquisitions: 0 mutual-exclusion violations, 0 TSan reports; 8-hogger
starvation scenario: 8/8 release wins, against 0/8 for the `timed_mutex` it
replaces; 16-waiter mass-timeout: gate re-acquires cleanly, no wedge) and
against the superseded lock-free slot counter (32 threads, 26,761 acquisitions,
peak in-flight 4, over-cap 0, residual 0, TSan clean). Adding a TSan leg for
these is not done here.
