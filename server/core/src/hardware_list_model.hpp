#pragma once

/// @file hardware_list_model.hpp
/// PURE model for the /hardware Configuration-Item (CI) list and record — search,
/// filter, sort, pagination, KPIs, and the JSON shapes shared verbatim by the HTMX
/// fragment, the REST v1 twin, and the MCP twin (the "one builder" the twin recipe
/// mandates, docs/api-twin-recipe.md §1). No gRPC, and nothing in THIS file calls
/// into httplib — every function here is a pure transform over already-fetched
/// data (roster/query in, page/JSON out). Its row types come from the store-free
/// `*_types.hpp` headers (ADR-0031 seam closure, #6558), so no store header is reachable
/// from THIS HEADER (held by the MCP registry lane of the seam-closure gate; httplib is
/// likewise not reachable today, but nothing gates that half): it must stay includable from
/// a plain unit test with zero network/store dependencies and from the MCP registry lane.
/// That is a statement about includes, not linkage: `hardware_list_model.cpp` includes `tag_store.hpp` for
/// `TagStore::validate_key`, so the object file still links the store.
///
/// Roster rows are `InventoryDeviceRow`s (declared in inventory_types.hpp), built by
/// server.cpp's `build_hw_roster` (endpoint_state + device_ci join); this header only
/// orders, filters, and paginates that roster — it never fetches it.

#include "authz_model.hpp"                // authz::VisibleSet
#include "device_containment_render.hpp" // kContainmentUi
#include "device_inventory_types.hpp"    // DeviceCiRecord, CiReadError
#include "digest_fn.hpp"                 // DigestFn (the verify seam; no OpenSSL here)
#include "inventory_types.hpp"           // InventoryDeviceRow
#include "offline_endpoint_types.hpp"    // OfflineEndpoint, PresenceReadError, OfflineRosterRead
#include "software_inventory_types.hpp"  // SoftwareEntry
#include "tag_types.hpp"                 // DeviceTag, TagReadError

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server {

/// Whitelisted sort keys for the Hardware CI list. Never accept an arbitrary column
/// name from the wire — `parse_hw_sort_key` is the sole entry point and returns
/// `nullopt` for anything outside this set, which both the fragment and the REST
/// twin turn into a 400 (a crafted/stale URL is the only realistic way to hit it).
enum class HwSortKey {
    Name,
    Os,
    Status,
    LastSeen,
    Manufacturer,
    Model,
    Serial,
    Cpu,
    Ram,
    OsVersion,
    Version, // agent_version — round-3 merge; NOT DEX (see hardware_kpis' doc note)
    Ip,
};

[[nodiscard]] std::optional<HwSortKey> parse_hw_sort_key(std::string_view token);
[[nodiscard]] std::string_view hw_sort_token(HwSortKey key);

/// Raw query as read off the wire (query-string values, unvalidated). Pass through
/// `normalise_hardware_query` before using — this struct alone makes no promises.
struct HardwareListQuery {
    std::string q;
    std::string os{"all"};      // all | windows | linux | macos
    std::string status{"all"};  // all | online | offline
    std::string sort{"name"};   // one of the HwSortKey tokens
    bool desc{false};
    std::size_t offset{0};
    std::size_t limit{50};
    /// "" = no tag filter. "key" = any value; "key=value" = exact value match.
    /// The key half is validated against TagStore::validate_key by
    /// normalise_hardware_query — an invalid key is a 400, same as a bad sort token.
    std::string tag;
};

/// Validates and clamps a raw query. Returns `nullopt` when `os`/`status`/`sort` is
/// an unrecognised token (the ONLY rejection case) — `limit`/`offset` are clamped,
/// never rejected, and empty `os`/`status`/`q` normalise to "all"/"all"/"".
[[nodiscard]] std::optional<HardwareListQuery> normalise_hardware_query(HardwareListQuery raw);

/// Strict-typed parse of an MCP `tools/call` arguments object into a RAW `HardwareListQuery`
/// (the transport-specific half of the shared list core; the REST twin's counterpart is
/// `query_from_request`). Unlike the REST query string, a JSON argument has a type, so this
/// refuses what REST would coerce or clamp (#4644 strictness):
///   * `arguments` must be an object; unknown keys are ignored (REST parity);
///   * `q`/`tag`: strings of at most 256 bytes; `os`/`status`/`sort`/`dir`: strings that are
///     exactly one of the documented lowercase tokens (`dir` is asc|desc);
///   * `limit`: an integer in [1, 200]; `offset`: an integer >= 0. A string ("50"), a float,
///     a bool, null, a negative or an out-of-range value is a refusal, never a default or a
///     clamp.
/// Returns nullopt on any refusal (the MCP handler answers `kInvalidParams`); `why`, when
/// non-null, receives a short caller-safe reason naming the argument. The result is still RAW:
/// the caller passes it through `normalise_hardware_query`, which also validates the tag key.
[[nodiscard]] std::optional<HardwareListQuery> hardware_query_from_args(const nlohmann::json& args,
                                                                         std::string* why = nullptr);

/// Assemble the operator-visible roster: the UNFILTERED roster from the RosterFn, scope-
/// filtered by the FleetReadGate's own scope (the SOLE filter, never double up with a second
/// scope predicate). Returns the filtered roster and the number of rows dropped (the
/// `devices_omitted` count). Shared by the REST/fragment handlers and the MCP twin.
[[nodiscard]] std::pair<std::vector<InventoryDeviceRow>, std::size_t>
scoped_roster(const InventoryDevicesResult& all, const authz::VisibleSet& scope);

/// Audit-trail floor for a device id taken raw from a URL or an argument: a device id reaches
/// `target_id` on every audit row these surfaces write and on the permission-denial audit, so
/// an id over `auth::kMaxAgentIdLength` bytes or carrying a byte below 0x20 (CR/LF) is refused
/// before any audit write. Mirrors viz_routes.cpp's agent_id floor.
[[nodiscard]] bool id_is_audit_safe(const std::string& id);

/// Lowercased, whitespace-split, deduplicated-by-position search tokens, capped at 8.
[[nodiscard]] std::vector<std::string> hw_search_tokens(std::string_view q);

/// True iff `row` matches every token in `tokens` (AND, substring, case-folded), the
/// `os`/`status` facet, AND the tag facet. `os`/`status`/`tag` are assumed
/// already-normalised ("all"/a specific value, and "" or "key"/"key=value") — call
/// `normalise_hardware_query` first. Empty `tag` = no tag filter.
[[nodiscard]] bool hw_row_matches(const InventoryDeviceRow& row, const std::vector<std::string>& tokens,
                                  std::string_view os, std::string_view status, std::string_view tag);

/// Median installed memory over the rows that have a synced, positive RAM figure, in GiB.
/// nullopt when no row has one (the readout is hidden, never "0 GB"). `count` receives the
/// number of devices the median is over.
[[nodiscard]] std::optional<double> median_ram_gb(const std::vector<InventoryDeviceRow>& rows,
                                                  std::size_t* count = nullptr);

/// Device counts per manufacturer (case-folded, whitespace-trimmed), highest first; rows
/// with no synced manufacturer are not counted. At most `top_n` entries, the remainder
/// summed into a final "Other" entry. Empty when nothing has synced.
[[nodiscard]] std::vector<std::pair<std::string, std::size_t>>
count_by_manufacturer(const std::vector<InventoryDeviceRow>& rows, std::size_t top_n = 8);

struct HardwareKpis {
    std::size_t total{0};
    std::optional<double> median_ram_gb;  ///< see median_ram_gb(); nullopt = hidden
    std::size_t ram_devices{0};           ///< devices the median is over
    std::vector<std::pair<std::string, std::size_t>> by_manufacturer; ///< top 8 + Other
    std::size_t online{0};
    std::size_t offline{0}; // non-online, including stale
    std::size_t stale{0};
    std::size_t with_ci{0}; // non-blank serial or model
};

/// Computed over the SCOPED roster, BEFORE q/os/status narrowing — the KPI strip
/// always describes "your fleet", not "your current filter".
[[nodiscard]] HardwareKpis hardware_kpis(const std::vector<InventoryDeviceRow>& roster);

struct HardwareListPage {
    std::vector<InventoryDeviceRow> rows; // the page slice only
    std::size_t total_matching{0};        // after q/os/status, before paging
    HardwareKpis kpis;                    // see hardware_kpis()
    HardwareListQuery query;              // the normalised, canonical echo
    // Quarantine state for the page's rows ONLY (never the whole roster): ids whose
    // active record the caller may read. `quarantine_degraded` = the read or a
    // per-record authz check failed, so absence of a pill proves nothing.
    std::unordered_set<std::string> quarantined_ids;
    bool quarantine_degraded{false};
    /// Render the Quarantined pill, row link, degrade banner and panel placeholder. The routes
    /// copy it from HardwareRoutes::Deps; the default is the compile-time kContainmentUi.
    bool containment_ui{kContainmentUi};
};

/// Filters, sorts, and paginates `roster` per `normalised` (already validated —
/// pass the output of `normalise_hardware_query`, never a raw query). `roster` is
/// consumed by value since the sort is in-place.
[[nodiscard]] HardwareListPage build_hardware_list_page(std::vector<InventoryDeviceRow> roster,
                                                        const HardwareListQuery& normalised);

// ── Shared JSON builders — REST and MCP call exactly these; the HTML fragment
// renders the same structs directly, so all three surfaces agree by construction.

/// One CI row. String `ci_*` sentinels ("" or "unknown") normalise to JSON `null` —
/// the JSON reader has no `ci_disp()`, so "not yet synced" must be explicit.
[[nodiscard]] nlohmann::json hardware_row_json(const InventoryDeviceRow& row);

[[nodiscard]] nlohmann::json hardware_list_json(const HardwareListPage& page, bool ci_degraded,
                                                std::size_t devices_omitted, bool tags_degraded = false);

/// What a `CiDetailFn` caller asks the record composition to read (#7162; it replaced a
/// `bool with_sections`). `WithSections` reads the v2 per-section statuses and rows in the SAME
/// snapshot as the record; ONLY the REST record route and the MCP tool `get_hardware_ci` ask for
/// it. `RecordOnly` (the dashboard fragment, its sync-now poll, the actions lens) leaves
/// `HardwareCiDetail::ci_sections` NOT READ.
enum class CiRead : std::uint8_t { RecordOnly, WithSections };

/// The full CI record composition — identity + CI blob + installed software + tags.
/// Each optional/expected member independently distinguishes "degraded" from
/// "absent" (ADR-0016 §7): a store failure must never render as "this device has no
/// software" or "this device has no CI record".
struct HardwareCiDetail {
    std::optional<InventoryDeviceRow> identity; // nullopt = not in the last-30d roster (or see identity_degraded)
    /// The offline-roster identity fallback FAILED (#5531): identity is nullopt
    /// but the device may exist.
    bool identity_degraded{false};
    std::expected<std::optional<DeviceCiRecord>, CiReadError> ci{std::unexpected(CiReadError::kDegraded)};
    /// The v2 per-section statuses and list rows, in registry order, read in the SAME
    /// REPEATABLE READ snapshot as `ci` (`DeviceInventoryStore::get_device_ci_with_sections`; see
    /// `apply_ci_with_sections_read`). THREE states, which the type keeps apart (#7162):
    ///  - `std::nullopt` = NOT READ: the caller asked for `CiRead::RecordOnly` (the dashboard
    ///    fragment and the actions lens do), or the record read itself failed so none was made.
    ///    This is the default-constructed state.
    ///  - a value holding a vector = READ. An EMPTY vector means "no section stored" (a v1 agent,
    ///    a record that carries none, or no record), never "the device has none".
    ///  - a value holding an error = the sections read itself FAILED. Both the REST route (503) and
    ///    the MCP tool (a retryable error) answer it via `classify_hardware_ci_read`
    ///    (`HardwareCiRead::SectionsUnreadable`) and withhold the record, never an empty list.
    /// `hardware_ci_json` renders NOT READ as `sections_state` "degraded" with `ci.sections` null,
    /// never as "absent" (a claim that the sections were read and none stored): no served path
    /// reaches that rendering, because the two record-serving surfaces always ask for sections.
    std::optional<std::expected<std::vector<DeviceCiSection>, CiReadError>> ci_sections{};
    std::optional<std::vector<SoftwareEntry>> software; // nullopt = store degraded/unwired
    bool software_truncated{false};                     // capped at kHwSoftwareCap
    std::optional<std::vector<DeviceTag>> tags;          // nullopt = tag store degraded/unwired
    /// The live session's self-reported agent_version; nullopt = no live session.
    std::optional<std::string> agent_version;
    /// `inventory_state.last_seen` (server receipt epoch-secs) for the
    /// installed_software source; nullopt = store degraded/unwired, 0 = never synced.
    std::optional<std::int64_t> software_last_seen;
};

/// The reason token a section carries when its stored child rows disagree with the row count
/// persisted beside its status row (`device_ci_section.row_count`, migration v3).
inline constexpr std::string_view kSectionRowCountMismatchReason = "server:row_count_mismatch";

/// The level and reason a section is SERVED with, after reconciling its status row with the
/// number of child rows actually read (up-2: a child table emptied out of band, e.g. a partial
/// single-table restore or a manual DELETE, must never read as a complete section).
///
/// The count half of the served decision (`verify_section_content` below is the function every
/// serving path calls and composes this with the content digest). Pure (no store, no PG). Rules:
///  - `row_count == nullopt` (a status-only kind, or a row written before migration v3): the
///    section is served exactly as stored - never verified, never downgraded.
///  - `rows.size() == *row_count`: exactly as stored.
///  - otherwise (fewer rows, or - impossible by construction, still handled - more) the section
///    is DOWNGRADED, never upgraded: `ok` -> `constrained`, and `server:row_count_mismatch` is
///    appended to the reason (`;`-joined, the same convention as `server_cap:<n>`). An already
///    `constrained` section keeps its level and its existing reason tokens (the agent's or
///    `server_cap:<n>`); the mismatch token is appended after them so the loss is not hidden.
///    The rows that WERE read are still served (a constrained section serves its rows).
///  - `unavailable`, `permission_denied`, an unknown level and a blank level are never touched:
///    by contract they serve no rows, so there is nothing to reconcile.
///
/// `fault` is the PURE cause of the downgrade this server applied (None when it applied none: an
/// agent-reported `constrained` stays None). It is the one source for both the served token and
/// the `yuzu_hardware_section_integrity_total` counter label (`record_section_integrity`); both
/// read it from `served_section_verdict`, so they name the same cause for the same rows (see the
/// intermittent-provider caveat there).
enum class SectionFault : std::uint8_t { None, RowCount, Content, Unverifiable };
struct SectionVerdict {
    std::string level;
    std::string reason;
    SectionFault fault{SectionFault::None};
};
[[nodiscard]] SectionVerdict verify_section_row_count(const DeviceCiSection& section);

/// The reason token a section carries when the rows read back do not hash to the content digest
/// persisted beside its status row (`device_ci_section.content_digest`, migration v3): the child
/// rows were edited, swapped for another generation's, or otherwise changed out of band - a
/// change the row count alone cannot see when the number of rows is unchanged.
inline constexpr std::string_view kSectionContentDigestMismatchReason = "server:content_digest_mismatch";

/// The reason token a section carries when the server could NOT compute the digest to compare
/// (the digest provider failed - `EVP_Digest` returned an error - which is a fault of THIS SERVER,
/// not of the device or its stored rows). Served with level `constrained`, rows served, exactly as
/// the two mismatch tokens; it is a distinct token so an operator does not chase the device.
inline constexpr std::string_view kSectionContentDigestUnverifiableReason =
    "server:content_digest_unverifiable";

/// The reason token a downgrade of kind `fault` is served with; empty for `SectionFault::None`.
[[nodiscard]] std::string_view section_fault_token(SectionFault fault) noexcept;

/// The `reason` label `yuzu_hardware_section_integrity_total` counts `fault` under
/// (`row_count_mismatch` / `content_digest_mismatch` / `digest_unverifiable`); empty for None.
[[nodiscard]] std::string_view section_fault_label(SectionFault fault) noexcept;

/// The level and reason a table-backed section is SERVED with: `verify_section_row_count` first,
/// then the content digest. Serving paths call it through `served_section_verdict`, which adds the
/// registered/table-backed guard; anything that serves raw `get_device_ci_sections` levels must
/// call one of the two.
///
/// Pure. Rules, on top of the row-count rules above:
///  - `content_digest == nullopt` (a status-only kind, or a row written before migration v3):
///    not verifiable, served as the row-count rule left it. So is a WELL-FORMED digest of a
///    different layout version (`classify_stored_digest` == `kOtherLayout`, e.g. `v2:...`; the
///    version is one to six digits): this
///    build cannot recompute it. Any other non-NULL value that is not the current `v1:` form (an
///    empty or whitespace value, `V1:`, bare hex, garbage, a malformed version, `v2:` with nothing
///    after it) is a MISMATCH, never unverified: a damaged column must not let an edit through.
///  - `unavailable`, `permission_denied`, an unknown or blank level: never touched (no rows by
///    contract).
///  - If the row count already disagrees, that verdict is returned alone: the count token is the
///    more specific report of the same loss, and a lost row always changes the digest too, so a
///    second token would only repeat it.
///  - Otherwise the digest of the rows read (`section_content_digest`, the writer's own function)
///    is compared with the stored one; any difference DOWNGRADES `ok` to `constrained` and appends
///    `server:content_digest_mismatch` to the reason (`;`-joined, idempotent). A digest the server
///    cannot compute (the provider failed) downgrades the same way but appends
///    `server:content_digest_unverifiable` instead: that is a fault of this server, not of the
///    stored rows (owner ruling 2026-11-09). An already `constrained` section keeps its level
///    and tokens.
///  - The rows that were read are STILL SERVED (as for the count mismatch). On a digest mismatch
///    they are NOT the generation the agent reported: they may be edited or swapped values, so a
///    consumer must not treat them as the device's reported hardware.
/// Scope: an integrity check against accident and non-malicious drift. Anyone who can write the
/// child tables can also rewrite the digest, so this is not tamper resistance. The digest covers
/// the rows only, not the level or reason columns.
[[nodiscard]] SectionVerdict verify_section_content(const DeviceCiSection& section);

/// The same function with an injectable digest provider (#7163). The one-argument form above
/// passes `sha256_hex`; only a test passes anything else, to drive the "provider failed" branch.
[[nodiscard]] SectionVerdict verify_section_content(const DeviceCiSection& section,
                                                    DigestFn digest);

/// THE serving predicate: the level and reason `section` is served with, as one function both
/// the response body (`ci_sections_json`) and the integrity counter
/// (`record_section_integrity`, hardware_section_integrity.hpp) call. A kind that is not in the
/// section registry, or is registered but not table-backed (status-only), is served exactly as
/// stored with `fault == None` - even if it carries a stored `row_count` or digest, which are
/// never compared for such a kind. A table-backed kind goes through `verify_section_content`
/// (which itself leaves a level other than `ok`/`constrained` untouched). `digest` nullptr means
/// `sha256_hex`.
///
/// One function and the same rows, but two CALLS per read (once for the body, once for the
/// counter): an INTERMITTENT digest-provider failure between them could make the counted label
/// differ from the served token. That is documented and accepted; carrying a precomputed verdict
/// from the first call to the second would create a second serving path.
[[nodiscard]] SectionVerdict served_section_verdict(const DeviceCiSection& section,
                                                    DigestFn digest = nullptr);

inline constexpr std::size_t kHwSoftwareCap = 2000;

/// Sync-on-demand (`__sync__.now`) shipped in the 0.13.1 dev line; a release
/// 0.13.0 agent answers the command with "plugin not found". True iff the
/// `major.minor.patch` prefix of `agent_version` is >= 0.13.1 — the `+build`
/// suffix (kFullVersionString = "@PROJECT_VERSION@+@YUZU_BUILD_NUMBER@") is
/// ignored, missing components read as 0, and anything empty / non-numeric /
/// pre-release-tagged fails CLOSED (false).
inline constexpr std::array<int, 3> kSyncNowMinAgentVersion{0, 13, 1};
[[nodiscard]] bool agent_supports_sync_now(std::string_view agent_version) noexcept;

/// Hardware roster read window and stale threshold: the list and the record fallback must
/// agree, or a listed device's record reads "not found".
inline constexpr std::chrono::hours kHardwareRosterWindow{24 * 30};
inline constexpr std::int64_t kHardwareStaleAfterMs = 2LL * 24 * 60 * 60 * 1000;

// ── #5531: the store-to-bit mappings, pure so a revert is visible to a unit test ──

/// Failed read -> `roster_degraded` + `ci_degraded` + `tags_degraded` (no enrichment of an
/// unknown roster) and returns false; a healthy read touches nothing and returns true.
[[nodiscard]] bool apply_roster_read(InventoryDevicesResult& result, const OfflineRosterRead& eps);

/// `agent_id -> (key -> value)` bulk tag read (`TagStore::get_values_for_keys`).
using TagValuesRead =
    std::expected<std::unordered_map<std::string, std::unordered_map<std::string, std::string>>,
                  TagReadError>;
using TagValuesReader = std::function<TagValuesRead(const std::vector<std::string>&)>;

/// Fills `result.rows[*].tags` from the bulk tag read, or sets `tags_degraded`. A failed KEY read
/// degrades without calling `read_values` (an empty key list would otherwise read back as an
/// authoritative blank); a failed VALUES read degrades; a healthy read — including an empty key
/// list or a device with no tags — leaves `tags_degraded` false.
void apply_tag_read(InventoryDevicesResult& result,
                    const std::expected<std::vector<std::string>, TagReadError>& keys,
                    const TagValuesReader& read_values);

/// One device's identity from an offline-roster read: the error is propagated (a failed read
/// is never "not in the roster"); a healthy read yields the matching row (online=false, stale
/// past 2 days) or nullopt when the agent is absent.
[[nodiscard]] std::expected<std::optional<InventoryDeviceRow>, PresenceReadError>
offline_identity_row(const OfflineRosterRead& eps, std::string_view agent_id, std::int64_t now_ms,
                     std::string (*human_age)(std::int64_t));

/// Identity read -> `identity` on success (nullopt = absent), `identity_degraded` on error.
void apply_identity_read(HardwareCiDetail& detail,
                         std::expected<std::optional<InventoryDeviceRow>, PresenceReadError> ident);

/// Record+sections read (`DeviceInventoryStore::get_device_ci_with_sections`, ONE snapshot) ->
/// `ci` and `ci_sections`. A failed read: `ci` is the error and `ci_sections` is reset to NOT READ
/// (`std::nullopt`; no sections read was made). Success: `ci` is the record (nullopt when absent)
/// and, for a v2 record only, its sections are MOVED into `ci_sections` (`ci->sections` is left
/// empty - one home for the rows); a v1 record or no record leaves `ci_sections` READ and empty.
/// `sections_failed` keeps the error in `ci_sections` (never an empty list) while `ci` stays the
/// record.
void apply_ci_with_sections_read(HardwareCiDetail& detail,
                                 std::expected<DeviceCiWithSections, CiReadError> read);

/// How a `HardwareCiDetail` reads for a single-record request, decided ONCE for every
/// transport (REST maps it to 200/404/503, the MCP twin to success/not-found/store fault).
/// Out-of-scope is NOT decided here: the caller checks `authz::in_scope` BEFORE it fetches the
/// detail and answers the same "not found" as `NotFound`, so a hidden device and a nonexistent
/// one stay indistinguishable (the existence-oracle closure).
enum class HardwareCiRead {
    Found,              ///< something is known about the device (identity, CI, software or tags)
    NotFound,           ///< nothing is known and no read failed: a genuinely absent id
    RosterUnreadable,   ///< nothing is known AND the identity fallback failed (#5531): never a 404
    SectionsUnreadable, ///< the record was read but its v2 sections read FAILED: never a 200 (H.7)
};

/// "Nothing known" is: no identity, a CI read that ANSWERED (not degraded) with no record, and
/// software and tag lists that are each absent (unwired or degraded) or empty. A degraded CI
/// read therefore keeps the record `Found` (the body's `ci_state` says "degraded"), while a
/// degraded software or tag read counts as empty, exactly as the REST handler has always
/// treated them. Only a failed identity fallback (`identity_degraded`) turns an otherwise empty
/// record into `RosterUnreadable`.
///
/// PRECEDENCE, stated once for every transport: RosterUnreadable > NotFound >
/// SectionsUnreadable > Found. #6228's future arm for a failed software or tag read slots BEFORE
/// NotFound, which keeps that a one-arm addition. SectionsUnreadable after NotFound is byte-safe:
/// a failed sections read only arises when the record read returned a record, so such a detail is
/// never "nothing known". A sections state of NOT READ (`std::nullopt`) is never unreadable.
[[nodiscard]] HardwareCiRead classify_hardware_ci_read(const HardwareCiDetail& detail);

/// True iff the v2 sections read FAILED (not merely "nothing stored" or "not read"). Prefer
/// `classify_hardware_ci_read`, which carries this as `SectionsUnreadable` in its fixed order;
/// this predicate is what that arm is built from.
[[nodiscard]] inline bool hardware_ci_sections_unreadable(const HardwareCiDetail& detail) noexcept {
    return detail.ci_sections.has_value() && !detail.ci_sections->has_value();
}

/// `ci_state`, `sections_state` and `identity_state` in the output are each one of "found" |
/// "absent" | "degraded" — never inferred by the reader from a blank field. `sections_state` is
/// "degraded" when the sections read failed OR `ci` could not be read (so none was attempted)
/// OR the sections were not read (below),
/// "absent" when sections were READ and nothing is stored (a v1 agent: NOT "the device has
/// none"), else "found". A detail whose sections were NOT READ (`ci_sections` is `std::nullopt`)
/// also renders "degraded" with `ci.sections` null; it is never "absent".
/// Inside `ci`, `sections` is an array in registry order of `{kind, status, reason, source,
/// complete, rows}`; `complete` is true only for status `ok`, and a section whose status is
/// anything but `ok`/`constrained` carries its reason and NO rows.
[[nodiscard]] nlohmann::json hardware_ci_json(const HardwareCiDetail& detail, std::int64_t now_secs);

} // namespace yuzu::server
