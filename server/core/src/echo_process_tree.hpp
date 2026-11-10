#pragma once

/// @file echo_process_tree.hpp
/// The Echo process-tree viewer's PURE engine (no DB, no HTTP — so it is unit-testable
/// directly with synthetic rows). The route module (echo_tree_routes.cpp) dispatches a
/// canned, read-only `echo.sql` to ONE live host (the device-page "Get live info"
/// dispatch/poll seam) over the HOURLY roll-up tables (`$Process_Hourly`, `$TCP_Hourly`,
/// `$DNS_Hourly`, `$ARP_Hourly`), feeds the pipe-delimited output through the parsers
/// here, builds a name-level tree for ONE selected hour, and renders the HTMX fragments.
///
/// Data source is the agent's LOCAL echo.db ONLY (via `echo.sql`) — no live process
/// probe, no server-side mirror, no agent seed. Consequences baked into the model:
///   * Roll-up only: there are no process ids, command lines, paths or start/exit
///     times. A node is a process NAME (per user) with the counts the hour recorded.
///   * The parent link is by NAME only (`parent_name` carries no user), so two parents
///     sharing a name occupy one position; children attach to the one with the lowest user.
///   * The input is agent-controlled and the name graph has cycles and fan-in by
///     construction (bash under bash, svchost under svchost, cmd/conhost/cmd), so the
///     builder places every (name, user) node exactly once under one deterministic
///     parent and breaks any cycle. The result does not depend on row order.
///   * The agent forbids recursive CTEs, so the tree is built HERE in C++ from flat
///     rows, never in SQL.

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

/// One row out of `$Process_Hourly`. All string fields are agent-controlled →
/// HTML-escape at render. `abnormal_exit_count` is zero until the agent folds it.
struct EchoProcHourRow {
    std::int64_t hour_ts = 0; ///< bucket start, epoch seconds
    std::string name;         ///< image basename
    std::string parent_name;  ///< "" = unknown / none
    std::string user;
    std::int64_t start_count = 0;
    std::int64_t stop_count = 0;
    std::int64_t abnormal_exit_count = 0;
};

/// One row out of `$TCP_Hourly`. Joined to a process NODE by `process_name` (the hourly
/// tier has no pid). All string fields are agent-controlled → HTML-escape at render.
struct EchoTcpHourRow {
    std::int64_t hour_ts = 0;
    std::string remote_addr;
    int remote_port = 0;
    std::string proto;
    std::string process_name;
    std::int64_t connect_count = 0;
    std::int64_t disconnect_count = 0;
    std::int64_t failed_count = 0;
};

/// One row out of `$DNS_Hourly` — device DNS resolver-cache activity in an hour. The
/// cache carries NO process, so this is never joined to a node. Agent-controlled. Only the
/// appear / remove counts the agent measures are read: it does not write the "no such
/// name" count yet, so none is shown.
struct EchoDnsHourRow {
    std::int64_t hour_ts = 0;
    std::string name;
    std::string record_type;
    std::string data;
    std::int64_t appear_count = 0;
    std::int64_t remove_count = 0;
};

/// One row out of `$ARP_Hourly` — device ARP / neighbour activity in an hour. No process.
/// Agent-controlled. As with DNS, only the measured appear / remove counts are read (the
/// router role and MAC-rebind count are not written by the agent yet).
struct EchoArpHourRow {
    std::int64_t hour_ts = 0;
    std::string iface; ///< NB: 'interface' is a Win32 COM macro under full <windows.h>
    std::string ip_address;
    std::string mac_address;
    std::int64_t appear_count = 0;
    std::int64_t remove_count = 0;
};

/// One process NAME (per user) in the selected hour, addressed by a stable `node_id` =
/// its index in `EchoProcTree::nodes`. Children/parent are node_ids.
struct EchoProcNode {
    std::string name;
    std::string parent_name; ///< the parent name with the most starts (ties: lowest name); the link is `parent`
    std::string user;
    std::int64_t start_count = 0;
    std::int64_t stop_count = 0;
    std::int64_t abnormal_exit_count = 0;
    bool stops_exceed_starts = false; ///< stop_count > start_count (started before the hour)
    bool anomaly = false;             ///< abnormal exit, or a suspicious spawn by name
    std::string anomaly_evidence;
    std::size_t parent = kNoParent; ///< node_id of the parent, or kNoParent (a root)
    std::vector<std::size_t> children;

    static constexpr std::size_t kNoParent = static_cast<std::size_t>(-1);
};

/// The name-level tree for one host and one selected hour.
struct EchoProcTree {
    std::int64_t hour_ts = 0; ///< the selected bucket (0 = nothing selected)
    std::vector<EchoProcNode> nodes; ///< addressed by node_id (index)
    std::vector<std::size_t> roots;  ///< node_ids of roots (parent empty / unknown / self / cycle cut)
    int anomaly_count = 0;
    std::int64_t start_total = 0;
    std::int64_t abnormal_total = 0;
    bool truncated = false;    ///< hit the kEchoTreeMaxNodes cap
    bool depth_capped = false; ///< a branch is deeper than kEchoRenderDepthCap (display truncates)
};

/// Hard cap on tree nodes — a runaway/forged row stream must not OOM or produce an
/// unrenderable tree (design §5.5).
inline constexpr std::size_t kEchoTreeMaxNodes = 50000;

/// Render-time depth cap: branches deeper than this are collapsed with a
/// "… (depth capped)" leaf. Shared by the renderer and the count pass so the
/// honesty banner (`EchoProcTree::depth_capped`) and the display agree.
inline constexpr int kEchoRenderDepthCap = 256;

/// Defense-in-depth byte caps on the raw agent output handed to the parsers. gRPC
/// already bounds a single message (~4 MiB default), so these guard a future limit
/// bump / a non-gRPC path and bound the per-line `substr` scan independent of the
/// row-count cap. Enforced at the route call site (a compromised agent controls the
/// output), not inside the pure parsers.
inline constexpr std::size_t kMaxEchoProcOutputBytes = 16ull * 1024 * 1024; // 16 MiB
inline constexpr std::size_t kMaxEchoTcpOutputBytes = 4ull * 1024 * 1024;   //  4 MiB
/// Same 4 MiB ceiling as the TCP path, but a distinct name for the DNS/ARP device-net
/// fragment so a future change to either cap can't silently move the other (ADR-0015
/// review LOW-E).
inline constexpr std::size_t kMaxEchoDeviceNetOutputBytes = 4ull * 1024 * 1024; //  4 MiB
/// Byte cap for the capture-sources `echo status` reply (same 4 MiB family as the device-net
/// cap). Enforced at the route; a larger reply is refused with a note, never parsed.
inline constexpr std::size_t kMaxEchoStatusOutputBytes = 4ull * 1024 * 1024; //  4 MiB

/// Rows one `echo.sql` answer carries at most: the agent's `do_sql` passes no row limit, so
/// `EchoDatabase::execute_user_query` applies its default `max_rows` (echo_db.hpp:826) and
/// the answer is cut there whatever LIMIT the query text names. An answer at this count may
/// be incomplete and is never presented as complete.
inline constexpr std::size_t kEchoAgentRowCap = 10000;

/// Canonicalize a `preset` query token to one of the known window tokens
/// {1h, 24h, 7d, custom}, mapping any empty/unrecognized value to the `24h` default
/// (the same fallback `resolve_echo_window` applies). The output is a fixed allowlist,
/// so it is inherently safe to interpolate into a structured `k=v` audit detail (an
/// attacker-supplied `preset` can no longer forge an audit field). Pure + exposed for
/// unit tests.
std::string canonical_echo_preset(const std::string& preset);

/// Normalize an agent-reported OS string to one of {windows, linux, macos, ?}
/// (`?` for empty/unknown). Bounds the agent-controlled `os` to a closed set before
/// it reaches the `echo.process_tree.read` audit detail. Pure + exposed for unit tests.
std::string normalize_echo_os(const std::string& os);

// ── Parsers (defensive, mirroring parse_dex_perf_output's __schema__ contract) ──
// All expect the agent's `echo.sql` output: a `__schema__|col1|col2|…` header line
// (cell 0 is the literal marker, cells 1..N name the data columns) followed by
// pipe-delimited data rows and a `__total__|N` trailer. Columns are located BY NAME from
// the schema line, so a column reorder can't misalign fields. An `error|…` first line, a
// missing/wrong schema, rows whose cell count is not the schema's width, and out-of-range
// numbers are all skipped/rejected and COUNTED (`EchoParseStats::unreadable`), so a forged or
// damaged payload can shrink the result but never goes unreported.
//
// What the wire cannot protect: the agent writes each cell raw, joined by `|`, one row per
// line, with no escaping. A process name that itself contains `|` or a newline can therefore
// shift cells or forge a whole row, and a forged row whose cell count is exactly the schema
// width is indistinguishable from a real one. The server bounds the damage (a row with the
// wrong cell count is dropped and counted, splitting stops at width+1 cells so a pipe-heavy
// line cannot amplify memory) but a forged payload CAN mis-attribute cells until the agent
// escapes them.

/// Split `line` on `|` into at most `max_cells` cells; the last keeps the unsplit remainder, so
/// a caller that wants `width` cells passes width+1 and a line with more is recognisable as too
/// wide, while a pipe-heavy line costs one remainder copy rather than a string per pipe.
/// Pure + free so the bound is unit-testable.
std::vector<std::string> echo_split_pipe(const std::string& line, std::size_t max_cells);

/// What a parse could not use. Pass one to a parser to learn whether the answer was usable.
struct EchoParseStats {
    bool schema = false;          ///< a usable `__schema__` header with the required columns was found
    std::size_t unreadable = 0;   ///< data rows dropped: wrong cell count, or a required number that did not parse
};

/// Parse `$Process_Hourly` rows. Required columns: hour_ts, name, parent_name, user,
/// start_count, stop_count (abnormal_exit_count optional → 0). Bounded to `max_rows`
/// to bound work against a response-spam payload.
std::vector<EchoProcHourRow> parse_echo_process_hourly_output(const std::string& output,
                                                              std::size_t max_rows = 120000,
                                                              EchoParseStats* stats = nullptr);

/// Parse `$TCP_Hourly` rows. Required columns: hour_ts, process_name, remote_addr
/// (remote_port, proto, connect_count, disconnect_count, failed_count optional).
/// Bounded to `max_rows`.
std::vector<EchoTcpHourRow> parse_echo_tcp_hourly_output(const std::string& output,
                                                         std::size_t max_rows = 20000,
                                                         EchoParseStats* stats = nullptr);

/// Parse `$DNS_Hourly` rows (ADR-0015). Required columns: hour_ts, name, record_type
/// (data, appear_count, remove_count optional). Bounded to `max_rows`.
std::vector<EchoDnsHourRow> parse_echo_dns_hourly_output(const std::string& output,
                                                         std::size_t max_rows = 20000,
                                                         EchoParseStats* stats = nullptr);

/// Parse `$ARP_Hourly` rows (ADR-0015). Required columns: hour_ts, ip_address,
/// mac_address (interface, appear_count, remove_count optional). Bounded to `max_rows`.
std::vector<EchoArpHourRow> parse_echo_arp_hourly_output(const std::string& output,
                                                         std::size_t max_rows = 20000,
                                                         EchoParseStats* stats = nullptr);

/// The distinct hours of a `SELECT DISTINCT hour_ts …` answer, newest first (the Hour
/// selector's source). Bounded to kEchoMaxWindowHours.
std::vector<std::int64_t> parse_echo_hours_output(const std::string& output,
                                                  EchoParseStats* stats = nullptr);

/// Turn an agent's failure text (an `error|…` reply, or a command's error detail) into the
/// sentence shown to the operator. An agent that predates the roll-up tables answers with a
/// SQLite "no such column" / "no such table" or the registry's "unknown table"; that gets
/// the one actionable instruction instead of the raw text. Plain text: the caller escapes.
std::string echo_agent_error_note(const std::string& agent_text);

/// What a read could not give the operator, shown beside (or instead of) the rows.
struct EchoReadNotes {
    std::string error;          ///< plain text: the read failed, no rows are shown
    std::size_t unreadable = 0; ///< rows the parser dropped
    bool cut = false;           ///< the answer reached kEchoAgentRowCap, so rows may be missing
};

/// The warning banners for `notes.unreadable` and `notes.cut` (empty when neither is set;
/// `notes.error` is rendered by its caller). `subject` / `row_noun` name what was read
/// ("Results" / "rows", or "Connection results" / "connection rows").
std::string render_echo_read_notes(const EchoReadNotes& notes, const std::string& subject = "Results",
                                   const std::string& row_noun = "rows");

// ── Window + tree ───────────────────────────────────────────────────────────

/// A window of whole hourly buckets: `[from_ts, to_ts]` are the FIRST and LAST bucket
/// starts (epoch seconds, hour-aligned), both inclusive.
struct EchoWindow {
    std::int64_t from_ts = 0;
    std::int64_t to_ts = 0;
};

/// Most hourly buckets one window may span (7 days) — keeps the fetched row count and
/// the hour selector bounded for a wide custom range.
inline constexpr int kEchoMaxWindowHours = 168;

/// Resolve a preset token (`1h`/`24h`/`7d`/`custom`) + optional custom from/to (epoch
/// seconds; ≤0 = unset) into whole hourly buckets. `now` is injected for testability.
/// The presets end at the last COMPLETE hour (the hour before the one `now` is in);
/// a garbage preset → the `24h` default. For `custom`, `from`/`to` are floored to their
/// hour, an unset `to` → the last complete hour, an unset `from` → 23 hours before `to`;
/// `to` is clamped to be ≥ `from` (a reversed range collapses to a single bucket at
/// `from`) and the span to kEchoMaxWindowHours (the newest hours are kept).
EchoWindow resolve_echo_window(const std::string& preset, std::int64_t custom_from,
                               std::int64_t custom_to, std::int64_t now);

/// Parse a `from`/`to` query value: either epoch-seconds (all digits) or a
/// datetime-local value `YYYY-MM-DDTHH:MM[:SS]` interpreted as UTC. Returns 0 for
/// empty/invalid/out-of-range input (callers treat 0 as "unset"). Overflow-guarded:
/// an oversized digit string or an absurd year yields 0, never signed-overflow UB.
/// The day is range-checked as 1..31 only, so a day beyond the month length (2026-02-31)
/// rolls into the next month; operator-supplied windows go through `parse_ts_param_strict`.
/// Pure + free so it is unit-testable without the HTTP layer.
std::int64_t parse_ts_param(const std::string& s);

/// Strict twin of `parse_ts_param` for the operator-supplied `from`/`to` window (#4644). Empty is
/// absent (0). Anything else must be all digits (at most 18) or exactly `YYYY-MM-DDTHH:MM[:SS]`
/// with every field in range; otherwise `std::nullopt`, so a caller can refuse the request
/// instead of silently rendering an unbounded or shifted window. Never throws.
std::optional<std::int64_t> parse_ts_param_strict(const std::string& s);

/// Build the name-level tree for `hour_ts` from `rows` (rows of other hours are
/// ignored). Nodes are keyed (name, user), summing the counts of rows that share the key.
/// A node's parent NAME is the one its rows name with the most summed starts (ties: the
/// lowest name; a name other than the node's own is preferred, an empty one is ignored), and
/// the link goes to the node of that name with the lowest user. A node is a root when that
/// name is empty, unknown or its own, and a cycle (a under b, b under a) is cut at its
/// lowest (name, user) member, so every node is placed exactly once, the walk terminates on
/// any input, and the result does not depend on row order. Every row is checked for a
/// suspicious spawn by its own parent name, whatever the placement. Always the FULL tree —
/// anomalies-only and text filtering is a client-side display concern (each rendered row
/// carries data-anom). Cap-guarded.
EchoProcTree build_echo_process_tree(const std::vector<EchoProcHourRow>& rows, std::int64_t hour_ts);

/// True if a `parent_name → child_name` pair is a suspicious spawn (case-insensitive
/// basename match against the static LOLBin/shell denylist). On a hit, `*evidence`
/// (when non-null) is set to a short human reason. Pure + exposed for unit tests.
bool echo_is_suspicious_spawn(const std::string& parent_name, const std::string& child_name,
                              std::string* evidence = nullptr);

// ── Render (pure, server-side, token-themed, CSP-safe — no JS in the markup) ──
// Co-located with the engine (like dex_routes' render_* helpers) so the HTML-escape
// of agent-controlled fields is unit-testable without the HTTP sink.

/// Work counters a caller can ask render_echo_tree_fragment to fill (tests only): the net
/// cell of a process name is built once and reused by every node bearing that name.
struct EchoRenderStats {
    std::size_t net_cells_built = 0;
    std::size_t net_cells_reused = 0;
};

/// Render the tree fragment: the banner + the nested `<details>/<summary>` tree. Every
/// node is rendered (no server-side filtering); each row carries `data-anom` so the
/// toolbar's client-side filters (Anomalies-only, text) can show/hide without a
/// round-trip, plus an inline network summary (remote IP:port) joined from `conns` by
/// process NAME (`conns` is the selected hour's `$TCP_Hourly` rows). Each row hx-gets
/// `/fragments/echo/process-tree/detail?token=…&node=…` into `#echo-tree-detail`.
/// `token` keys the reconstruction cache the detail route reads.
std::string render_echo_tree_fragment(const EchoProcTree& tree, const std::vector<EchoTcpHourRow>& conns,
                                      const std::string& token, EchoRenderStats* stats = nullptr);

/// Render one node's detail panel — name, parent name, user, the hour's start / stop /
/// abnormal-exit counts, anomaly evidence, and the connections recorded under the same
/// name (`conns` is already filtered to this node's name and hour).
std::string render_echo_proc_detail(const EchoProcNode& node, const std::vector<EchoTcpHourRow>& conns);

/// Render the device DNS-cache activity panel (ADR-0015) for `hour_ts` — a collapsible
/// `<details>` with a compact table of the rows of that hour (appeared / removed counts).
/// Device-level, NOT per process. Agent fields are HTML-escaped. `notes.error` replaces the
/// table with an in-panel error (a failed read is never shown as "nothing recorded");
/// `notes.unreadable` / `notes.cut` add their banners. Pure (no DB/HTTP) so it is
/// unit-testable directly.
std::string render_echo_dns_panel(const std::vector<EchoDnsHourRow>& rows, std::int64_t hour_ts,
                                  const EchoReadNotes& notes = {});

/// Render the device ARP-table activity panel (ADR-0015) for `hour_ts`: appeared /
/// removed counts per interface, IP and MAC. Notes as for the DNS panel.
std::string render_echo_arp_panel(const std::vector<EchoArpHourRow>& rows, std::int64_t hour_ts,
                                  const EchoReadNotes& notes = {});

/// Render the Capture-sources cards (ADR-0015) from a device's `echo status` output
/// (per-source `<src>_enabled` / `<src>_rows` / `<src>_oldest_ts`). A status that carries a
/// source's `<src>_live_rows` but not its `<src>_rows` comes from an agent without the
/// roll-up tables: that count is NOT shown (a dash), and one note above the cards says to
/// upgrade the agent. Produces the filter chips + one card per
/// reported source with staged (not-yet-pushed) toggles + the push/discard bar — the
/// page JS handles staging and the Push dispatch. Category, always-on classification,
/// the hourly `$`-name and the kept tiers are presentation metadata held here (the
/// agent's schema registry is not linked into the server). Pure (no DB/HTTP) so it is
/// unit-testable directly. All agent-controlled values are HTML-escaped.
std::string render_echo_capture_sources(const std::string& device, const std::string& status_output);

} // namespace yuzu::server
