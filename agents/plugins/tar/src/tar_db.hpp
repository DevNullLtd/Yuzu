#pragma once

/**
 * tar_db.hpp -- SQLite-backed Timeline Activity Record database
 *
 * Stores timestamped events (process births/deaths, network connections,
 * service state changes, user sessions) with snapshot IDs for correlation.
 *
 * Schema:
 *   tar_state  — last-known state per collector for diff computation
 *   tar_config — key/value config (retention_days, redaction patterns, etc.)
 *   tar_cursor — last-persisted cursor JSON per cursor-model source
 *                (tar_cursor.hpp: power, removable — wave 2)
 *   plus the typed warehouse tiers generated from the schema registry.
 *
 * The legacy tar_events event log was retired by schema v3; it is neither
 * created nor queryable (#760 UP-8).
 *
 * Thread-safe: a std::mutex guards all sqlite3* operations. The ONE exception is
 * the `db_`/`query_db_` liveness probes (is_open / query_engine_available),
 * which read the handle without the mutex on purpose so a status query cannot
 * block behind a rollup; `db_` is atomic for that reason. See the member
 * declarations for why that is safe and what it does not promise.
 * Uses WAL mode, busy_timeout=5000, secure_delete=ON.
 */

#include <cstdint>
#include <expected>
#include <filesystem>
#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3; // Forward declaration

namespace yuzu::tar {

/**
 * Transaction-scoped handle passed to a `TarDatabase::checked_transaction`
 * operation. Wraps the live connection for the duration of ONE strict
 * transaction; never store it, never use it after the operation returns.
 *
 * `exec()` is the safe path: it refuses to touch SQLite once the handle is
 * already `poisoned()`, which is how "stop issuing statements once the
 * transaction has aborted" is enforced without every caller having to
 * remember to check first. A caller driving `raw()` directly (parameterized
 * prepare/bind/step, unavoidable for anything with bound values) owns that
 * same discipline itself: check `poisoned()` before issuing more SQL, and
 * call `fail()` on any non-success return so the failure is recorded even
 * though `exec()` never saw it.
 *
 * `poisoned()` is deliberately independent of the operation callback's own
 * return value. `checked_transaction` commits only when BOTH the callback
 * returned success AND the handle was never poisoned -- so a callback that
 * forgets to check one intermediate `raw()` step and returns success anyway
 * cannot erase that step's failure. That is the whole point of this type:
 * a later success must never be able to paper over an earlier one.
 */
class TransactionHandle {
public:
    TransactionHandle(const TransactionHandle&) = delete;
    TransactionHandle& operator=(const TransactionHandle&) = delete;

    /**
     * Run one complete SQL statement (no bound parameters -- use `raw()` for
     * those). No-ops and returns false immediately, without touching SQLite,
     * once the handle is already poisoned: a statement issued after an
     * aborted transaction would run as an autocommit the eventual ROLLBACK
     * cannot undo (the same hazard `execute_atomic_batch`'s doc comment
     * describes).
     */
    [[nodiscard]] bool exec(const std::string& sql);

    /**
     * The live connection, for prepare/bind/step call sites that need bound
     * parameters. The caller MUST call `fail()` on any non-success return
     * from that sequence -- `checked_transaction` only ever sees failures
     * reported through this handle, never SQLite return codes it didn't
     * witness itself.
     */
    [[nodiscard]] sqlite3* raw() const noexcept { return db_; }

    /**
     * Record a failure from a `raw()`-driven statement. Poisons the handle
     * exactly like a failed `exec()`. `reason` becomes the transaction's
     * reported error if this is the first failure recorded; keep it
     * diagnostic (the SQLite error text) and never include a bound
     * parameter's value -- this store holds usernames.
     */
    void fail(std::string reason);

    /// True once `exec()` or `fail()` has recorded a failure.
    [[nodiscard]] bool poisoned() const noexcept { return poisoned_; }

    [[nodiscard]] const std::string& error() const noexcept { return error_; }

private:
    friend class TarDatabase;
    explicit TransactionHandle(sqlite3* db) : db_(db) {}

    sqlite3* db_;
    bool poisoned_{false};
    std::string error_;
};

struct TarEvent {
    int64_t id{0};            // row id (0 for new events)
    int64_t timestamp{0};     // epoch seconds
    std::string event_type;   // process, network, service, user
    std::string event_action; // started, stopped, connected, disconnected, state_changed,
                              // login, logout
    std::string detail_json;  // JSON object with type-specific details
    int64_t snapshot_id{0};   // groups events from same collection cycle
};

// ── Typed event structs for warehouse tables ────────────────────────────────

struct ProcessEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // started, stopped
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string cmdline;
    std::string user;
};

struct NetworkEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // connected, disconnected
    std::string proto;
    std::string local_addr;
    int local_port{0};
    std::string remote_addr;
    std::string remote_host;
    int remote_port{0};
    std::string state;
    uint32_t pid{0};
    std::string process_name;
};

struct ServiceEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // started, stopped, state_changed
    std::string name;
    std::string display_name;
    std::string status;
    std::string prev_status;
    std::string startup_type;
    std::string prev_startup_type;
};

struct UserEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // login, logout
    std::string user;
    std::string domain;
    std::string logon_type;
    std::string session_id;
};

/// One software_live row — an install / uninstall / upgrade event derived by
/// diffing the installed-software inventory (Phase 8 Wave 1). Machine scope only
/// (HKLM Uninstall): a row is the host's software, never attributed to a Windows
/// profile, so it carries no per-user identity (#1620). `prev_version` is
/// populated only for 'upgraded'.
struct SoftwareEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // installed, removed, upgraded
    std::string name;
    std::string version;
    std::string prev_version;
    std::string publisher;
    std::string install_date;
};

/// One arp_live row (ADR-0015 — host ARP / neighbour table). One row per
/// appeared/removed transition of an (interface, ip_address, mac_address)
/// binding; `entry_type` is a value field, not part of the diff key.
struct ArpEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // appeared, removed
    std::string iface;  // NB: 'interface' is a Win32 COM macro under full <windows.h>
    std::string ip_address;
    std::string mac_address;
    std::string entry_type; // dynamic, static, incomplete, other, unknown
};

/// One dns_live row (ADR-0015 — host DNS resolver-cache state, NOT per-process
/// queries). One row per appeared/removed transition of a (name, record_type,
/// data) resolution; `ttl_remaining_s` is a value field, not part of the diff
/// key (it decrements every tick). `source` ∈ {cache, hosts_file, unknown}.
struct DnsEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // appeared, removed
    std::string name;
    std::string record_type; // A, AAAA, CNAME, PTR, ...
    std::string data;
    int64_t ttl_remaining_s{0};
    std::string source;
};

/// One mapdrive_live row (capability-map §3.8 — network-share mappings, both
/// directions). One row per appeared/removed transition of a (direction,
/// local_mount, remote_path, remote_host, username) mapping; `provider` is a
/// value field, not part of the diff key. `origin` ∈ {live, historical}:
/// `live` rows come from the snapshot-diff (action appeared/removed); `historical`
/// rows come from the one-time init backfill (action='historical', ts = the
/// source artifact's time or 0) and bypass the diff entirely.
struct MapDriveEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action;    // appeared, removed, historical
    std::string direction; // outbound, inbound
    std::string local_mount;
    std::string remote_path;
    std::string remote_host;
    std::string username;
    std::string provider;
    std::string origin;    // live, historical
};

/// One perf_live row (BRD A1 — continuous device performance sampling).
struct PerfRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    double cpu_pct{0.0};
    double mem_used_pct{0.0};
    double commit_pct{0.0};
    int64_t disk_read_bps{0};
    int64_t disk_write_bps{0};
    int64_t disk_read_lat_us{0};
    int64_t disk_write_lat_us{0};
    int64_t net_rx_bps{0};
    int64_t net_tx_bps{0};
};

/// One procperf_live row (BRD A2 — top-N per-application samples). One row
/// per (tick, app); `name` is the image name only (never a command line),
/// `version` the on-disk image file version ("" if unresolved / off-Windows).
struct ProcPerfRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string name;
    std::string version;
    int instances{0};
    double cpu_pct{0.0};
    int64_t ws_bytes{0};
    /// Kernel thread (Linux PF_KTHREAD) / Windows System process (pid 4) —
    /// see tar_proc_perf.hpp's "Kernel-thread marker" note. Recorded
    /// unfiltered here (this tier keeps kernel threads); the daily app-perf
    /// rollup (sync_source_app_perf.cpp) filters on it.
    bool is_kthread{false};
};

/// One module_live row (M2 — image/DLL/driver load capture). `action` and
/// `signed_state` hold the warehouse tokens (module_action_token /
/// module_signed_token from tar_module_stream.hpp); `module_dir` is already
/// redacted of any user-profile prefix by the collector (redact_module_dir).
/// `module_name` is the loaded image basename only (names-only posture; the
/// directory is the deliberate, narrow exception — the search-order-hijack
/// signal). `signer` is the code-signing publisher / team id, "" if unknown.
struct ModuleRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action;       // loaded / unloaded / seed / blocked
    uint32_t pid{0};
    std::string process_name;
    std::string module_name;
    std::string module_dir;
    std::string signed_state; // signed / unsigned / invalid / revoked / unknown
    std::string signer;
    bool is_kernel{false};
};

/// One netqual_live row — per-connection TCP quality sample for the /network
/// warehouse tier (BRD Workstream E). Linux-first via netlink INET_DIAG
/// TCP_INFO, joined to the connection's owning process. One row per
/// (tick, connection); co-sampled with the `tcp` source so it shares the
/// snapshot_id and joins to process/perf on `ts`.
///
/// SIGNAL DISCIPLINE — `lost` is the CURRENT-loss gauge (tcpi_lost: segments
/// lost and not yet recovered AT SAMPLE TIME) and is the only field that moves
/// with current network conditions, so it is the degraded driver. `retrans`
/// and `segs_out` are LIFETIME-CUMULATIVE context only: a fresh loss burst
/// barely moves their ratio (diluted by all the historical clean segments),
/// which is exactly why the earlier device-aggregate retransmit signal was
/// empirically disproven — do NOT rebuild a "current loss" signal from their
/// ratio. Per-tick degraded = fraction of a device's rows with current loss,
/// computed server-side as a query (a later slice), never a heartbeat boolean.
///
/// PRIVACY — only `remote_bucket` (a coarse destination CLASS: loopback /
/// private / public / unknown — see remote_bucket() in tar_netqual.hpp) leaves
/// the connection's destination on the row; the raw remote address / hostname is
/// NOT stored in this tier. Collection is gated by its own opt-in toggle and a
/// per-tick top-N cap (collector slice).
struct NetQualRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string proto;         // tcp, tcp6
    std::string remote_bucket; // destination class: loopback/private/public/unknown (never a raw IP)
    std::string process_name;  // owning process image name only
    int64_t rtt_us{0};         // smoothed RTT (tcpi_rtt), microseconds
    int64_t rtt_var_us{0};     // RTT variance / jitter (tcpi_rttvar), microseconds
    int64_t lost{0};           // CURRENT lost segments (tcpi_lost) — instantaneous degraded driver
    int64_t retrans{0};        // lifetime retransmits (tcpi_total_retrans) — context only
    int64_t segs_out{0};       // lifetime segments out (tcpi_segs_out) — context / denominator
    int64_t ca_state{0};       // tcpi_ca_state: 0=Open 1=Disorder 2=CWR 3=Recovery 4=Loss — a
                               // "struggling right now" gauge that HOLDS across a whole recovery
                               // episode (unlike tcpi_lost, which is gone within an RTT), so it
                               // survives a coarse poll cadence better. Captured to compare
                               // degraded-signal candidates before committing 4b.3's query.
};

/// One netqual_boot row (ADR-0020) — the per-boot RETROSPECTIVE baseline,
/// written once per boot at plugin init from cumulative-since-boot OS counters
/// (Windows: GetTcpStatisticsEx2 IPv4+IPv6 + GetIfTable2 non-loopback totals).
/// `window_s = ts - boot_ts` is the pre-TAR window the counters summarize:
/// "what was network quality like this boot, before TAR was running".
///
/// SIGNAL DISCIPLINE — these are since-boot cumulative TOTALS: one average over
/// the whole window, coarse retrospective CONTEXT only. Never derive a
/// current-loss verdict from their ratio (see NetQualRow above — the
/// device-aggregate live signal was empirically disproven). Host-wide, no
/// per-connection or per-process attribution, no addresses: nothing usage-class
/// on the row, but it ships under netqual's opt-in toggle regardless.
struct NetQualBootRow {
    int64_t ts{0};              // t_live: when TAR started observing this boot
    int64_t snapshot_id{0};
    int64_t boot_ts{0};         // epoch seconds of system boot
    int64_t window_s{0};        // ts - boot_ts (clamped >= 0)
    int64_t retrans_segs{0};    // TCP segments retransmitted since boot (v4+v6)
    int64_t segs_out{0};        // TCP segments sent since boot (v4+v6)
    int64_t estab_resets{0};    // established->reset transitions since boot
    int64_t if_in_errors{0};    // non-loopback interface totals since boot
    int64_t if_in_discards{0};
    int64_t if_out_errors{0};
    int64_t if_out_discards{0};
    int64_t if_in_octets{0};
    int64_t if_out_octets{0};
};

/// One netconn_live row (ADR-0020) — a single OS-logged connectivity
/// transition (network connect/disconnect, NCSI capability change, Wi-Fi
/// connect/fail/disconnect). `ts` is the EVENT's timestamp, not the read
/// time: backfilled rows carry timestamps from before TAR existed on the box.
///
/// PRIVACY — every TEXT field is a closed enum token produced by the
/// allow-list parser in tar_netconn.hpp; no SSID, BSSID, profile name,
/// interface GUID, MAC, or any other free-text event field is ever extracted
/// from the source event (test-pinned in test_tar_netconn.cpp).
struct NetConnRow {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action;     // connected/disconnected/wifi_connected/
                            // wifi_connect_failed/wifi_disconnected/capability_changed
    std::string channel;    // networkprofile/ncsi/wlan
    std::string category;   // public/private/domain ("" when n/a)
    std::string capability; // none/local/internet ("" when n/a)
    std::string iface_kind; // wifi ("" when unknown)
    int64_t reason_code{0}; // WLAN disconnect/fail reason or NCSI change reason
};

/// One power_live row (cursor-model seam, tar_cursor.hpp) -- a sleep/wake/
/// AC-power transition. FROZEN by the cursor seam: wave-2 collectors and the
/// schema registry consume this shape exactly; changing a field is a
/// contract change, not a refactor. `record_key` is the UNIQUE replay-
/// idempotence key (tar_cursor.hpp rule 3) -- a value-only field for every
/// OTHER purpose, never re-derived by a query.
struct PowerEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // sleep, wake, ac_attached, ac_detached, capture_gap
    std::string detail;
    std::string record_key; // UNIQUE — replay idempotence (INSERT OR IGNORE)
};

/// One removable_live row (cursor-model seam, tar_cursor.hpp) -- an
/// attach/detach transition of removable media, or a process observed
/// executing from removable media. FROZEN, same rationale as PowerEvent.
/// `image_path` + `pid` are TYPED identity-adjacent columns (P-004) added
/// specifically so `exec_from_removable` rows can be correlated to a running
/// process (ProcessInfo::exec_path, agents/core process_enum.hpp) — NOT
/// derived from `evidence`, which (like `record_key`) is a value/forensic
/// field only, never an identity carrier.
struct RemovableEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action; // attached, detached, present_at_baseline,
                        // exec_from_removable, capture_gap
    std::string device_key;
    std::string vendor;
    std::string product;
    std::string serial;
    std::string bus;
    std::string volume;
    int64_t size_bytes{0};
    std::string image_path; // typed identity column (P-004); "" when n/a
    int64_t pid{0};         // typed identity column (P-004); 0 when n/a
    std::string evidence;   // forensic/value field only — NOT identity
    std::string record_key; // UNIQUE — replay idempotence (INSERT OR IGNORE)
};

/// Row from an arbitrary SQL query (used by tar.sql action).
using QueryRow = std::vector<std::string>;

struct QueryResult {
    std::vector<std::string> columns; // column names
    std::vector<QueryRow> rows;
};

struct TarStats {
    int64_t record_count{0};
    int64_t oldest_timestamp{0};
    int64_t newest_timestamp{0};
    int64_t db_size_bytes{0};
    int retention_days{7};
};

/// Optional baseline write that commits atomically with a diff-source insert.
struct StateWrite {
    std::string collector;
    std::string json;
};

/// Optional knobs for `TarDatabase::open`. The all-defaults value reproduces the
/// production open exactly, so the production call site passes nothing.
struct TarOpenOptions {
    /// TEST-ONLY. Issue `PRAGMA synchronous=OFF` on the read-write connection
    /// before the WAL switch and schema DDL, so a unit test stops paying an
    /// fsync per commit (~17 per bare open, ~4k per tar suite run). It drops the
    /// durability guarantee of every commit on this connection, so it is ONLY
    /// for scratch databases that are deleted at the end of the test. NEVER set
    /// it for a store a real agent owns, nor in a test that exercises
    /// durability, crash, corruption, integrity-check/quarantine or WAL
    /// checkpoint behaviour. Default false == synchronous left at SQLite's
    /// default (FULL); a pin test asserts that (test_tar_store.cpp).
    bool relaxed_durability_for_tests{false};
};

class TarDatabase {
public:
    /**
     * Open (or create) the TAR database at the given path.
     * Creates tables if they don't exist. Sets WAL mode, busy_timeout,
     * and secure_delete pragmas. `opts` defaults to the production behaviour
     * (synchronous=FULL); see `TarOpenOptions`.
     */
    static std::expected<TarDatabase, std::string> open(const std::filesystem::path& path,
                                                        const TarOpenOptions& opts = {});

    ~TarDatabase();

    TarDatabase(TarDatabase&& other) noexcept;
    TarDatabase& operator=(TarDatabase&& other) noexcept;

    TarDatabase(const TarDatabase&) = delete;
    TarDatabase& operator=(const TarDatabase&) = delete;

    /**
     * Get database statistics.
     * Queries typed warehouse tables (process_live, tcp_live, etc.)
     */
    TarStats stats();

    // ── Snapshot state management ────────────────────────────────────────────

    /**
     * Get the last-known state JSON for a collector (e.g. "process", "network").
     * Returns empty string if no state is stored.
     */
    std::string get_state(const std::string& collector);

    /**
     * Store the last-known state JSON for a collector.
     * @return true on success; false if the write failed (e.g. SQLITE_BUSY /
     *         disk full / prepare error). Callers that must not proceed on a
     *         failed write (the #538 disable baseline-clear) check this;
     *         best-effort collector writes may ignore it.
     */
    /// The bool is load-bearing: callers must treat false as "baseline not saved".
    bool set_state(const std::string& collector, const std::string& json);

    // ── Cursor-model persistence (tar_cursor.hpp) ────────────────────────────

    /**
     * Get the last-persisted cursor JSON for a cursor-model source (e.g.
     * "power", "removable"). Returns std::nullopt if no cursor has ever been
     * persisted for that source -- distinct from an EMPTY string, so a
     * CursorSource can tell "never run" from "ran and persisted an empty
     * cursor" (tar_cursor.hpp rule 4: the cursor is always a versioned JSON
     * document, so a genuinely empty one is not expected, but the API stays
     * honest either way).
     *
     * A READ FAILURE is an error, never a nullopt. Collapsing the two would let
     * a transient SQLite failure look identical to "this source has never run":
     * the driver would hand nullopt to collect(), the source would treat the
     * tick as a first-ever baseline, and it would commit the CURRENT log
     * position -- silently skipping everything between the durable old cursor
     * and now, with no capture_gap, because nothing involved ever knew a cursor
     * existed. nullopt therefore means exactly one thing: the query succeeded
     * and matched no row.
     */
    std::expected<std::optional<std::string>, std::string> get_cursor(const std::string& source);

    /**
     * Why the atomic inserts do not return a bare bool.
     *
     * They can fail two ways that demand OPPOSITE responses, and a bool
     * collapses them:
     *
     *  - `Transient` — BEGIN/COMMIT/step failed (SQLITE_BUSY, I/O, disk full).
     *    Nothing is wrong with the batch. Rule 1 applies: retain the cursor and
     *    retry next tick, and the retry will eventually succeed.
     *
     *  - `KeyCollision` — a `record_key` in the batch names a row that already
     *    exists with a DIFFERENT payload, so accepting it would advance the
     *    cursor past an event that was never stored. This is a SOURCE DEFECT
     *    (rule 3(a): every persisted field must be deterministically
     *    re-derivable), and it is PERMANENT: the source re-derives the same
     *    poison batch every tick, the store refuses it every tick, the cursor
     *    never advances and the queue never drains. Capture is dead, and if the
     *    caller treats it as transient the only symptom is a repeating log line.
     *    A caller MUST NOT retry a KeyCollision indefinitely — surface it.
     */
    enum class CursorInsertError { Transient, KeyCollision };

    /**
     * Atomically persist a batch of power events AND the new cursor for the
     * "power" source in ONE transaction (BEGIN IMMEDIATE..COMMIT, mu_ held
     * for the whole batch — tar_cursor.hpp rule 6 / this header's
     * execute_atomic_batch doc above explains why a per-call-locked helper
     * cannot give this guarantee). Each event is inserted with INSERT OR
     * IGNORE on the record_key UNIQUE index (tar_cursor.hpp rule 3) so a
     * replayed event is a silent no-op, never a duplicate row. On ANY
     * statement failure the whole transaction rolls back — events and cursor
     * commit or fail together, never one without the other. `events` may be
     * empty (a tick that only advances the cursor, e.g. a Baseline collect
     * with nothing to report); the cursor is still persisted.
     * @return {} iff the transaction committed; otherwise the discriminant
     *         above, which the caller MUST act on differently.
     */
    std::expected<void, CursorInsertError> insert_power_events_and_cursor(
        const std::vector<PowerEvent>& events, const std::string& cursor_json);

    /** Same contract as insert_power_events_and_cursor, for "removable". */
    std::expected<void, CursorInsertError> insert_removable_events_and_cursor(
        const std::vector<RemovableEvent>& events, const std::string& cursor_json);

    // ── Config management ────────────────────────────────────────────────────

    /**
     * Get a config value by key, with an optional default.
     */
    std::string get_config(const std::string& key, const std::string& default_val = "");

    /**
     * Tri-state config read, for callers where "unreadable" and "unset" must not
     * mean the same thing.
     *
     * `get_config` above returns the caller's default for BOTH, which is fine
     * for a cosmetic setting and wrong for a control. The lookback privacy key
     * is the case that forced this: a transient SQLite failure would otherwise
     * turn an operator's `<name>_lookback_seconds=0` into the 7-day default and
     * read OS-retained history on a host where that is not lawful — the control
     * failing OPEN. Same shape, and same reason, as get_cursor's tri-state:
     * nullopt means the query SUCCEEDED and matched no row; an error means the
     * read failed and the caller must decide for itself, not inherit a default.
     */
    std::expected<std::optional<std::string>, std::string> try_get_config(const std::string& key);

    /**
     * Set a config value.
     */
    /// False once the store has failed closed -- either it never opened, or a
    /// wedged transaction forced `execute_atomic_batch` to close it. Callers that
    /// REPORT state (rather than just read it) must consult this: with the
    /// connection gone every getter returns its default, so an unguarded status
    /// surface describes a dead store as a healthy empty one (#2361 Gate 8).
    [[nodiscard]] bool is_open() const noexcept { return db_ != nullptr; }

    /// True while the read-only query connection (`tar sql`) is usable.
    /// DELIBERATELY independent of is_open(): the wedged-transaction close takes
    /// down the WRITE connection only, so historical data stays readable through
    /// this one. A status surface that PROMISES that read path must consult this
    /// rather than assume it -- the connection is optional at open time (a
    /// failure there is warned and tolerated, tar_db.cpp), and promising a read
    /// path that is not there is worse than admitting the store is dark.
    [[nodiscard]] bool query_engine_available() const noexcept { return query_db_ != nullptr; }

    /// Epoch at which THIS open() quarantined a corrupt tar.db; nullopt for a
    /// clean open. Drives only the tar.status db_health value — the durable
    /// record is tar_config `db_health_last_quarantine_*`.
    [[nodiscard]] std::optional<int64_t> quarantined_this_open() const noexcept {
        return quarantined_at_;
    }

    /// Returns false if the write did not persist. Retention's clock guard
    /// depends on this: a silently-dropped write leaves the guard with no
    /// comparison point on the next pass, forever, with nothing to report
    /// (#2361 Gate 8 / Sol). Most callers may still ignore the result.
    bool set_config(const std::string& key, const std::string& value);

    // ── Warehouse schema management ─────────────────────────────────────────

    /** Get the current schema version (0 = legacy-only, 2 = typed tables). */
    int schema_version();

    /** Create all typed warehouse tables from the schema registry. */
    bool create_warehouse_tables();

    // ── Typed inserts ───────────────────────────────────────────────────────
    //
    // The eight snapshot-diff inserts take an optional StateWrite: the
    // tar_state baseline UPSERT then commits in the SAME transaction as the
    // events, so a failed baseline save can never leave events durable with a
    // stale baseline (which would re-diff and double-emit). Any failure rolls
    // back both and returns false. With empty events + a StateWrite only the
    // state is written (one autocommit statement).

    bool insert_process_events(const std::vector<ProcessEvent>& events,
                             const std::optional<StateWrite>& state = std::nullopt);
    bool insert_network_events(const std::vector<NetworkEvent>& events,
                             const std::optional<StateWrite>& state = std::nullopt);
    bool insert_service_events(const std::vector<ServiceEvent>& events,
                             const std::optional<StateWrite>& state = std::nullopt);
    bool insert_user_events(const std::vector<UserEvent>& events,
                             const std::optional<StateWrite>& state = std::nullopt);
    bool insert_software_events(const std::vector<SoftwareEvent>& events,
                             const std::optional<StateWrite>& state = std::nullopt);
    bool insert_arp_events(const std::vector<ArpEvent>& events,
                             const std::optional<StateWrite>& state = std::nullopt);
    bool insert_dns_events(const std::vector<DnsEvent>& events,
                             const std::optional<StateWrite>& state = std::nullopt);
    bool insert_mapdrive_events(const std::vector<MapDriveEvent>& events,
                             const std::optional<StateWrite>& state = std::nullopt);
    bool insert_perf_sample(const PerfRow& row);
    bool insert_proc_perf_samples(const std::vector<ProcPerfRow>& rows);
    bool insert_netqual_samples(const std::vector<NetQualRow>& rows);
    bool insert_netqual_boot_row(const NetQualBootRow& row);
    bool insert_netconn_events(const std::vector<NetConnRow>& rows);
    bool insert_module_events(const std::vector<ModuleRow>& rows);

    /**
     * Return one row per unique (proto, local_addr, local_port, remote_addr,
     * remote_port, pid) ESTABLISHED connection observed at or after
     * `since_ts`. Each row's `ts` is set to MAX(ts) across observations of
     * that 5-tuple — i.e. the most recent time TAR saw the connection. Used
     * by `tar.fleet_snapshot` to widen the per-host viz from "currently
     * established at sample time" to "established within the rolling
     * window", so the viz draws blue tubes for connections that have
     * existed recently even if they're closed at the moment of the call.
     *
     * LISTEN / TIME_WAIT / CLOSE_WAIT / etc. are filtered out — they aren't
     * "this box talks to that box" edges.
     */
    std::expected<std::vector<NetworkEvent>, std::string>
    query_recent_tcp_connections(int64_t since_ts);

    // ── Generic SQL execution (for warehouse queries and aggregation) ────────

    /**
     * Execute TRUSTED, internally-constructed read-only SQL on the read-write
     * connection (NO authorizer). For internal callers ONLY — rollup / stats /
     * diff queries built from constants and integer-parsed values, never operator
     * or network input. For any UNTRUSTED operator SQL use execute_user_query
     * instead (#760). Enforces a maximum row limit to prevent agent DoS.
     */
    std::expected<QueryResult, std::string> execute_query(const std::string& sql,
                                                          int max_rows = 10000);

    /**
     * Execute UNTRUSTED operator SQL (the tar.sql action) in a sandbox: a
     * dedicated read-only SQLite connection with an authorizer that permits
     * only SELECT / READ of registry-known warehouse tables. Writes are
     * structurally impossible (read-only handle); non-SELECT statements,
     * ATTACH/PRAGMA, unknown tables, and trailing statements are rejected at
     * prepare time. Fails closed (returns an error) if the sandbox connection
     * is unavailable. Callers must still pre-validate via
     * validate_and_translate_sql — this is defence in depth, not a substitute.
     * Recovery: if the read-only connection cannot be opened at startup it stays
     * unavailable for the process lifetime (fail closed); restart the agent to
     * retry.
     */
    std::expected<QueryResult, std::string> execute_user_query(const std::string& sql,
                                                               int max_rows = 10000);

    /**
     * Execute arbitrary DDL/DML SQL (for rollup inserts, retention deletes).
     * Returns true on success.
     *
     * NOTE this takes `mu_` PER CALL. A caller that issues `BEGIN` through this
     * method does NOT own the transaction: another thread's write on this same
     * connection lands between statements and joins it, so a later ROLLBACK
     * discards that write too. Use `execute_atomic_batch` for anything
     * transactional.
     */
    bool execute_sql(const std::string& sql);

    /// Outcome of `execute_atomic_batch`.
    struct BatchResult {
        bool began{false};     ///< BEGIN IMMEDIATE succeeded
        bool committed{false}; ///< COMMIT succeeded (false => rolled back)
        /// Per-statement flags, sized to the input. `failed[i]` means statement
        /// i did not COMPLETE.
        ///
        /// READ THIS WITH `committed`, because the batch is NOT all-or-nothing:
        ///  - `committed == false`: the transaction rolled back, so every entry
        ///    is set and no statement had any effect.
        ///  - `committed == true`: statement i was skipped, and every OTHER
        ///    statement IS DURABLE. A statement whose error left the transaction
        ///    intact is flagged and stepped over so one broken table cannot stop
        ///    retention for the rest.
        ///
        /// So `failed[i] == 1` does NOT imply "no effect": a `RAISE(FAIL)`-style
        /// error can leave statement i partly applied and still flagged. Do not
        /// treat a set flag as a licence to re-run a non-idempotent statement.
        std::vector<char> failed;
    };

    /**
     * Run `statements` as ONE transaction while holding `mu_` for the whole
     * thing, so no other writer on this connection can join it.
     *
     * That isolation is the point (#2361 Gate 8 / Kimi). `execute_sql` releases
     * `mu_` between statements, so a caller-driven BEGIN/COMMIT silently
     * enrolled any concurrent collector INSERT or `set_config` write into the
     * transaction -- and once retention started rolling back on failure, that
     * rollback silently discarded those writes after their callers had already
     * been told they succeeded. `purge_source` already holds `mu_` across
     * `BEGIN IMMEDIATE`; this is the same pattern, exposed for reuse.
     *
     * On a statement error, whether the pass STOPS depends on the error:
     *  - Errors that abort the transaction themselves (SQLITE_FULL,
     *    SQLITE_IOERR, SQLITE_CORRUPT, SQLITE_BUSY, a RAISE(ROLLBACK) trigger)
     *    abandon the whole batch. Continuing would run the rest as autocommits
     *    the rollback cannot undo, or would commit onto a damaged database.
     *  - Errors that leave the transaction intact (a plain SQLITE_ERROR from a
     *    missing column, a corrupt index on ONE table, a RAISE(ABORT) trigger)
     *    flag that statement and CONTINUE. Stopping there meant one
     *    permanently-broken table rolled back every pass forever, so nothing was
     *    ever retained and tar.db grew without bound.
     *
     * The discriminator is `sqlite3_get_autocommit()` plus the error code -- see
     * the implementation. Callers MUST read `failed` together with `committed`;
     * see BatchResult.
     *
     * Cost: collectors and every other user of this connection block for the
     * batch's duration, so the CALLER must bound each statement. `run_retention`
     * caps every statement it queues, including the row-count prunes -- an
     * uncapped `DELETE` here would hold the lock for an unbounded time and stall
     * the whole plugin (#2361 Gate 8 / Sol). Same trade `purge_source` accepts,
     * but purge is operator-initiated and rare; this runs every 900 seconds.
     *
     * If a ROLLBACK fails with the transaction still OPEN, the connection is
     * CLOSED (`db_` nulled). Every write on a connection stuck inside a
     * transaction that will never commit would be reported durable and then lost
     * at restart, so failing all of them closed -- via the `if (!db_)` check
     * every method already has -- is the honest outcome. TAR storage is then
     * offline on that endpoint until the agent restarts.
     */
    BatchResult execute_atomic_batch(const std::vector<std::string>& statements);

    /**
     * Run `operation` as ONE strict, all-or-nothing transaction while holding
     * `mu_` for the whole thing -- same isolation rationale as
     * `execute_atomic_batch` above, but a STRONGER contract: there is no
     * per-statement-tolerant data segment here. `execute_atomic_batch`'s
     * tolerance (one broken table must not stop every other table's
     * retention) is deliberate and correct for that use; it is wrong for a
     * caller where a partial commit is a silent, permanent loss of the only
     * copy of something -- a consent-boundary marker, an identity-bearing
     * row's sole re-derivation state. Use `checked_transaction` for those;
     * leave `execute_atomic_batch`/`execute_atomic_batch_gated`-style callers
     * on the tolerant path they were built for.
     *
     * `operation` receives a `TransactionHandle` scoped to this transaction.
     * It must not call any OTHER `TarDatabase` method that takes `mu_` --
     * that would deadlock (`mu_` is not reentrant) -- and must not perform
     * collection, network calls, or any other external I/O while the
     * transaction is held open; drive it from already-materialized data.
     *
     * Commits iff `operation` returns a value AND the handle was never
     * poisoned (see `TransactionHandle`) AND `COMMIT` itself succeeds.
     * Rolls back on any other outcome, including an exception unwinding out
     * of `operation` -- caught here, never propagated, always converted to a
     * rollback. If `ROLLBACK` itself fails with the transaction still open,
     * this closes the connection exactly the way `execute_atomic_batch`
     * does (`db_` nulled under `mu_`, reusing the `if (!db_)` fail-closed
     * check every method already has) -- see that method's doc comment for
     * why that is the honest outcome rather than leaving a wedged
     * transaction for the next writer to silently join.
     *
     * There is no `CommittedResult` carried in the return type: a caller
     * that needs to report what it wrote should capture into a variable it
     * owns from inside `operation` and trust that variable only once this
     * call returns a value -- a `checked_transaction` success IS the
     * commit-happened signal. Keeping the primitive's own return type void
     * avoids coupling its contract to any one caller's result shape (the
     * first real user is Wave 7 PR7.2b's usage fold; it is not the last).
     *
     * @return {} iff the transaction committed; otherwise a diagnostic
     *         string (SQLite error text or `operation`'s own postcondition
     *         message) -- never a bound parameter's value, per
     *         `TransactionHandle::fail`.
     */
    [[nodiscard]] std::expected<void, std::string>
    checked_transaction(const std::function<std::expected<void, std::string>(TransactionHandle&)>&
                            operation);

    /**
     * Execute parameterized SQL with two int64 bind values.
     * Used by rollup engine for time-range-bounded aggregation.
     */
    bool execute_sql_range(const std::string& sql, int64_t from, int64_t to);

    /**
     * Purge ALL rows for a capture source across every warehouse tier
     * (`<source>_live/_hourly/_daily/_monthly`), with the tier tables resolved
     * from the schema registry (never hardcoded). Backs the `tar.purge_source`
     * action (retention-paused frame, Phase 15.A): it drops a deliberately
     * paused source's accumulated forensic data WITHOUT re-enabling collection.
     * All tiers are deleted in one transaction (all or none).
     * @return total rows deleted, or an error string (unknown source / SQL error).
     */
    std::expected<int, std::string> purge_source(const std::string& source);

private:
    explicit TarDatabase(sqlite3* db);

    /// tar_state UPSERT on an already-locked handle; shared by set_state() and
    /// the diff-source inserts (which run it inside their transaction).
    static bool upsert_state_locked(sqlite3* db, const std::string& collector,
                                    const std::string& json);

    /// Internal set_config that assumes caller already holds mu_.
    bool set_config_locked(const std::string& key, const std::string& value);

    // ATOMIC because it is written at RUNTIME, not only at open/close: the
    // wedged-rollback path in execute_atomic_batch nulls it under mu_ while
    // is_open() reads it WITHOUT mu_ from another thread (do_status runs on the
    // command-dispatch thread, the wedge on the rollup thread). Before that
    // runtime write existed the unlocked read was benign; adding it made this a
    // data race (#2361 governance Gate 2).
    //
    // Atomic rather than "lock mu_ in is_open()" on purpose: do_status
    // deliberately avoids taking rollup-scale locks so the diagnostic an
    // operator runs WHEN TAR IS MISBEHAVING cannot block behind a rollup pass
    // (see tar_plugin.cpp do_status). A lock-free probe keeps that property and
    // keeps is_open() const noexcept.
    //
    // The probe is still only a POINT-IN-TIME answer: a caller can see `true`
    // and have the connection close underneath it. That is safe because every
    // method re-tests `if (!db_)` under mu_ and fails closed, so the worst case
    // is one status reply that reports ok for a store that died microseconds
    // later -- self-correcting on the next call.
    std::atomic<sqlite3*> db_{nullptr};
    // Read-only, authorizer-sandboxed connection used only by execute_user_query
    // for untrusted operator SQL (#760). Null if it could not be opened, in
    // which case user queries fail closed. NOT atomic: unlike db_ it is never
    // written after construction publishes the object (no runtime close path),
    // so there is no concurrent writer to race with.
    sqlite3* query_db_{nullptr};
    std::optional<int64_t> quarantined_at_{};
    std::mutex mu_;
    std::mutex query_mu_;
};

} // namespace yuzu::tar
