# Resource Ledger — sam20 paced ad-hoc software sync

Range: `origin/dev..HEAD` (branch `feat/sam-20-adhoc-sync`)

## Summary

This diff adds **no thread, subprocess, socket, fd, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle,
mapped library or temp path**. The send loop stays synchronous in the request thread (as the other
uncapped fan-outs are), so the diff starts no worker; a stalled stream can still hold a request worker,
which is why the live-send count is bounded (R4). All new state is in-memory, per server process, and
owned by one `software_sync::Runner`: a mutex, a pacing ledger, a bounded key-state map and an RAII
reservation. The `--inventory-sync-cooldown` flag and its `Config` field are plain integers.

## Table 1 — new or changed owned state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `std::mutex mu_` (replaces the previous slot-lease state under the same mutex) | `Runner` member | constructed with the `Runner` | destroyed with the `Runner` | none; the `Runner` is not copyable | `std::lock_guard` at every use; each critical section is short and holds no call into `Env`: no lock is held across resolve, audit write, execution-record creation or dispatch, so a callback that re-enters `Runner::run` (the tests drive overlap this way) cannot deadlock |
| R2 | Pacing ledger `std::vector<LedgerEntry> ledger_` (rate and `ends_at` of each admitted run) | `Runner` member, guarded by `mu_` | `Reservation::take_locked`, in the same critical section that admits the run (admission and reservation are atomic) | expired entries are dropped on every use (`prune_ledger_locked`); `Reservation::~Reservation` erases the entry when the run is released (`sent == 0`, a failed audit write or record creation, an exception before the send began) | none | the entry is kept until `ends_at` when a send was attempted and cannot be proven to have sent nothing (a partial send, a throw out of dispatch), because the frames already armed still report inside that window |
| R3 | Key-state map `std::unordered_map<std::string, KeyState> keys_` (run key to run state plus cooldown stamp) | `Runner` member, guarded by `mu_` | `take_locked` (Pending), `begin_sending_locked` (Running), `stamp_locked` (a stamp for a run that reserved nothing) | `erase_key_if_mine_locked` on release or after a throw; expired entries evicted by `make_room_locked` | none | bounded at `kCooldownStateCap` (1024): expired entries go first, then the oldest stamp; an entry with a live run is never evicted. A request for a key that is Pending or Running joins or is refused (409) and never overwrites the state |
| R4 | Live-send count `int live_sends_` | `Runner` member, guarded by `mu_` | incremented by `take_locked` | decremented by `~Reservation` on every exit path | none | bounded at `kMaxLiveRuns` (3): the fourth concurrent send loop is refused 409 before any reservation is taken. This replaces the lease and takeover machinery and bounds the request workers a stalled agent stream can strand |
| R5 | `Runner::Reservation` (RAII for R2, R3 and R4 of one admitted run) | stack local of `run_impl` | constructed before admission; becomes live in `take_locked` | destructor takes `mu_` and gives back what the run did not settle | none; copy deleted | the destructor runs on every path, an exception thrown by the audit write, the record creation or the dispatch included; `settle_locked` (a send accepted at least one frame) keeps the ledger entry until `ends_at`, `forget_key` (a throw out of dispatch, any type) keeps the entry and drops the key's run state, `release_all` (nothing sent) gives everything back |
| R6 | Execution-tracker row of a run (`__sync__.now`) | `ExecutionTracker` (existing store), written through `Env.track` | `track.create` after the fail-closed audit row and before the send | `track.set_targeted` with the frames accepted after a send; `track.cancel` when the run sends nothing or dispatch throws | none | a record that cannot be created leaves the run untracked and the send goes on (logged); no other state depends on the row |
| R7 | The shared `std::shared_ptr<Runner> sync_runner_` and its `Env` closures | `ServerImpl` member (pre-existing); the same instance is handed to the REST routes and the MCP server | built on first use in `software_sync_runner()` | with the server | shared by `shared_ptr` with `HardwareRoutes` and `McpServer`; the closures capture `this` and read stores the server owns | unchanged ownership; the changed part is the `Env` (new `fleet_admin`, `last_seen`, `track`, `on_result` and `on_live_bound_refused` closures, a `cooldown_s` value copied from `Config`), none of which stores anything beyond the `Runner` state above |
| R8 | `std::function` locals in `software_sync_fleet_admin` (`FleetAdminFacts`) | stack local of the server method | per call | function exit | none | value type; the lambdas capture `this` and `sess` by reference for the duration of the call only and are not stored |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `send_system_reserved` per-frame stream write | `ServerImpl` / agent registry | `push_sync_now_confined`'s send lambda now wraps one send in `try`/`catch`, so a throwing stream counts as a frame not accepted and the loop goes on; no handle is acquired or released |
| `ExecutionTracker` | `ServerImpl` | one new read path (`GET /api/v1/hardware/sync/{execution_id}`) and the shared `create_execution_row` helper the v1 command creator now also calls; no new write site for the dispatcher column |
| `SoftwareInventoryStore::source_last_seen_bulk` | `ServerImpl` | read in chunks of 1000 ids; a degraded chunk fails the whole read (503, nothing sent) |

## Tests

The Runner tests drive every path through a fake `Env` with an injected clock; overlapping admissions
are produced by re-entering `Runner::run` from inside a fake audit or dispatch callback (no thread, no
sleep, no real time, file, process or network). The pacing and decision suites are pure functions.
