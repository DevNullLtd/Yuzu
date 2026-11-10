#include "software_list_model.hpp"

#include "data_export.hpp"
#include "list_keyset.hpp"
#include "model_param_helpers.hpp"
#include "software_catalog_rules.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/log_token.hpp>

#include <algorithm>
#include <initializer_list>
#include <unordered_set>
#include <utility>

namespace yuzu::server::software_list {

namespace sc = software_catalog;
namespace swc = software_catalogue;

namespace {

using model_detail::first_param;
using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::length_prefixed;
using model_detail::parse_nonneg;
using model_detail::read_length_prefixed;
using model_detail::split;
using model_detail::valid_text;
using ::yuzu::server::keyset::b64url_decode;
using ::yuzu::server::keyset::b64url_encode;

std::string get(const Params& p, const char* k) {
    const auto* v = first_param(p, k);
    return v ? *v : std::string{};
}

void tail(std::string& out, std::string_view key, const std::string& v) {
    if (!v.empty()) {
        out += ';';
        out += key;
        out += '=';
        out += ::yuzu::log_token(v);
    }
}

std::string_view match_name(NameMatch m) {
    return m == NameMatch::kExact ? "exact" : m == NameMatch::kPrefix ? "prefix" : "contains";
}

// match= / status= / the version-range fields, shared by both parsers. nullopt = clean.
struct CommonFilters {
    NameMatch match{NameMatch::kExact};
    std::string status;
    std::string version_min;
    std::string version_max;
};

std::expected<CommonFilters, std::string> parse_common(const Params& p) {
    CommonFilters c;
    const std::string match = get(p, "match");
    if (match.empty() || match == "exact")
        c.match = NameMatch::kExact;
    else if (match == "prefix")
        c.match = NameMatch::kPrefix;
    else if (match == "contains")
        c.match = NameMatch::kContains;
    else
        return std::unexpected("invalid match (expected exact, prefix or contains)");
    c.status = get(p, "status");
    if (!c.status.empty() && c.status != "current" && c.status != "unconfirmed" &&
        c.status != "disabled")
        return std::unexpected("invalid status (expected current, unconfirmed or disabled)");
    c.version_min = get(p, "version_min");
    c.version_max = get(p, "version_max");
    if (!valid_text(c.version_min) || !valid_text(c.version_max))
        return std::unexpected("invalid parameter encoding");
    if (c.version_min.size() > swc::kNameMaxBytes || c.version_max.size() > swc::kNameMaxBytes)
        return std::unexpected("parameter too long");
    return c;
}

// The version-filter rule: version_min / version_max need `name` with match=exact (a range of
// "any title" or of a title pattern has no single comparator order); a bare exact `version` is a
// plain equality predicate as it always was and needs no name. The exact form cannot be mixed
// with a range.
std::optional<std::string> version_rule_error(bool has_version, const CommonFilters& c,
                                              const std::string& name) {
    const bool has_range = !c.version_min.empty() || !c.version_max.empty();
    if (c.match != NameMatch::kExact && name.empty())
        return std::string("match requires name");
    if (has_range && (name.empty() || c.match != NameMatch::kExact))
        return std::string("version_min and version_max require name with match=exact");
    if (has_version && has_range)
        return std::string("version cannot be combined with version_min or version_max");
    return std::nullopt;
}

} // namespace

// ── Status ───────────────────────────────────────────────────────────────────

std::string_view derive_status(std::string_view facet_status, bool facet_enabled) noexcept {
    if (!facet_enabled || facet_status == "disabled")
        return "disabled";
    if (facet_status == "full" || facet_status == "delta")
        return "current";
    return "unconfirmed";
}

// ── Parameters ───────────────────────────────────────────────────────────────

std::expected<ListRequest, std::string> parse_list_params(const Params& p) {
    auto base = swc::parse_devices_params(p);
    if (!base)
        return std::unexpected(base.error());
    auto common = parse_common(p);
    if (!common)
        return std::unexpected(common.error());
    if (const auto bad =
            version_rule_error(base->query.version.has_value(), *common, base->query.name))
        return std::unexpected(*bad);
    ListRequest r;
    r.base = std::move(*base);
    r.base.query.match = common->match;
    r.base.query.status = common->status;
    r.version_min = std::move(common->version_min);
    r.version_max = std::move(common->version_max);
    return r;
}

std::expected<ComponentsRequest, std::string> parse_components_params(const Params& p) {
    auto common = parse_common(p);
    if (!common)
        return std::unexpected(common.error());
    ComponentsRequest r;
    SoftwareComponentQuery& q = r.query;
    q.kind = get(p, "kind");
    q.name = get(p, "name");
    q.agent_id = get(p, "agent_id");
    q.match = common->match;
    q.status = common->status;
    std::string search = get(p, "q");
    if (const auto* v = first_param(p, "version"))
        r.version = *v;
    r.cursor = get(p, "cursor");
    r.format = get(p, "format");
    const std::string limit = get(p, "limit");
    const std::string no_version;
    const std::string& version = r.version ? *r.version : no_version;
    if (auto bad = swc::text_error({&q.kind, &q.name, &q.agent_id, &search, &version, &r.cursor},
                                   {&q.kind, &q.agent_id}, {&q.name, &version}))
        return std::unexpected(*bad);
    q.q = sc::clamp_utf8(search, sc::kSearchMaxBytes);
    if (!r.format.empty() && r.format != "json" && r.format != "csv")
        return std::unexpected("invalid format (expected json or csv)");
    if (r.cursor.size() > swc::kCursorMaxBytes)
        return std::unexpected("invalid cursor");
    if (const auto bad = version_rule_error(r.version.has_value(), *common, q.name))
        return std::unexpected(*bad);
    r.version_min = std::move(common->version_min);
    r.version_max = std::move(common->version_max);
    if (r.version)
        q.versions = std::vector<std::string>{*r.version};
    const bool export_mode = !r.format.empty();
    const auto lim = swc::read_limit(limit, export_mode ? swc::kExportCap : swc::kCatalogueDefaultLimit,
                                     export_mode ? swc::kExportCap : swc::kCataloguePageMax);
    if (!lim)
        return std::unexpected(lim.error());
    q.limit = static_cast<int>(*lim);
    return r;
}

// ── Version range ────────────────────────────────────────────────────────────

std::expected<std::vector<std::string>, std::string>
resolve_version_range(const std::vector<std::string>& distinct_versions, std::string_view version_min,
                      std::string_view version_max) {
    if (distinct_versions.size() >= static_cast<std::size_t>(kCatalogRowCap))
        return std::unexpected(std::string(kRangeNotResolvable));
    std::vector<std::string> out;
    for (const auto& v : distinct_versions) {
        if (v.empty())
            continue; // no known version: never inside a bounded range
        if (!version_min.empty() && sc::catalog_version_compare(v, version_min) < 0)
            continue;
        if (!version_max.empty() && sc::catalog_version_compare(v, version_max) > 0)
            continue;
        out.push_back(v);
    }
    return out;
}

std::optional<std::vector<std::string>> scope_ids(const authz::VisibleSet& scope) {
    if (!scope)
        return std::nullopt;
    return std::vector<std::string>(scope->begin(), scope->end());
}

// ── Fingerprints, audit targets, cursors ─────────────────────────────────────

std::string list_fingerprint(const ListRequest& rq) {
    std::string fp = swc::devices_fingerprint(rq.base.query);
    if (!rq.has_range())
        return fp; // byte-identical to the pre-range fingerprint
    fp += '\x1e';
    fp += length_prefixed({&rq.version_min, &rq.version_max});
    return fnv1a_hex16(fp);
}

std::string components_fingerprint(const ComponentsRequest& rq) {
    static const std::string kNone;
    const auto& q = rq.query;
    const std::string match(match_name(q.match));
    return fnv1a_hex16(std::string(1, rq.version ? '1' : '0') +
                       length_prefixed({&q.kind, &q.name, &match, &q.agent_id, &q.q, &q.status,
                                        rq.version ? &*rq.version : &kNone, &rq.version_min,
                                        &rq.version_max}));
}

std::string audit_target(const ListRequest& rq) {
    std::string out = swc::audit_target(rq.base.query);
    const auto& q = rq.base.query;
    if (q.match != NameMatch::kExact)
        out += ";match=" + std::string(match_name(q.match));
    tail(out, "status", q.status);
    tail(out, "version_min", rq.version_min);
    tail(out, "version_max", rq.version_max);
    return out;
}

std::string audit_target(const ComponentsRequest& rq) {
    const auto& q = rq.query;
    std::string out = "components:";
    out += !q.name.empty()       ? "name=" + ::yuzu::log_token(q.name)
           : !q.agent_id.empty() ? "agent=" + ::yuzu::log_token(q.agent_id)
                                 : std::string("fleet");
    if (!q.name.empty())
        tail(out, "agent", q.agent_id);
    if (q.match != NameMatch::kExact)
        out += ";match=" + std::string(match_name(q.match));
    tail(out, "kind", q.kind);
    if (rq.version)
        out += ";version=" + ::yuzu::log_token(*rq.version);
    tail(out, "version_min", rq.version_min);
    tail(out, "version_max", rq.version_max);
    tail(out, "q", q.q);
    tail(out, "status", q.status);
    return out;
}

std::string encode_components_cursor(const SoftwareComponentCursor& after, std::int64_t skip,
                                     std::string_view fp) {
    const std::string s = std::to_string(skip);
    std::string out = "c2:";
    out += fp;
    out += ':';
    out += b64url_encode(length_prefixed({&after.name, &after.agent_id, &after.kind,
                                          &after.path_hash, &s}));
    return out;
}

std::expected<std::pair<SoftwareComponentCursor, std::int64_t>, swc::CursorError>
decode_components_cursor(std::string_view token, std::string_view fp) {
    const auto parts = split(token, ':');
    if (parts.size() != 3 || parts[0] != "c2" || !is_lower_hex16(parts[1]))
        return std::unexpected(swc::CursorError::kMalformed);
    const auto payload = b64url_decode(parts[2]);
    if (!payload)
        return std::unexpected(swc::CursorError::kMalformed);
    const auto fields = read_length_prefixed(*payload, 5);
    if (!fields)
        return std::unexpected(swc::CursorError::kMalformed);
    const auto skip = parse_nonneg((*fields)[4]);
    // The decoded text is bound as SQL parameters: strict UTF-8 and no NUL, like the parsers.
    if (!skip || !valid_text((*fields)[0]) || !valid_text((*fields)[1]) ||
        !valid_text((*fields)[2]) || !valid_text((*fields)[3]))
        return std::unexpected(swc::CursorError::kMalformed);
    if (parts[1] != fp)
        return std::unexpected(swc::CursorError::kFilterMismatch);
    return std::pair{SoftwareComponentCursor{std::string((*fields)[0]), std::string((*fields)[1]),
                                             std::string((*fields)[2]), std::string((*fields)[3])},
                     *skip};
}

std::expected<swc::DevicesPage, std::optional<swc::CursorError>>
read_list_page(const swc::DevicesReader& read, const ListRequest& rq, const authz::VisibleSet& scope) {
    return swc::read_scoped_page<swc::DevicesOps>(read, rq.base.query, rq.base.cursor,
                                                  list_fingerprint(rq), scope);
}

std::expected<ComponentsPage, std::optional<swc::CursorError>>
read_components_page(const ComponentsReader& read, const ComponentsRequest& rq,
                     const authz::VisibleSet& scope) {
    return swc::read_scoped_page<ComponentsOps>(read, rq.query, rq.cursor, components_fingerprint(rq),
                                                scope);
}

// ── Per-page device facts ────────────────────────────────────────────────────

std::optional<DeviceFacts> load_device_facts(const FactsReads& io, const std::vector<std::string>& ids) {
    DeviceFacts f;
    if (ids.empty())
        return f;
    if (io.last_seen) {
        auto seen = io.last_seen(ids);
        if (!seen)
            return std::nullopt;
        f.last_seen = std::move(*seen);
    }
    if (io.hostnames) {
        const std::unordered_set<std::string> want(ids.begin(), ids.end());
        // A roster row with a blank hostname (`endpoints.hostname` defaults to '') reads as
        // unknown, the same as the dashboard's devices table and the crypto model: null, not "".
        for (auto& [id, host] : io.hostnames())
            if (!host.empty() && want.contains(id))
                f.hostname.emplace(id, std::move(host));
    }
    return f;
}

// ── Totals ───────────────────────────────────────────────────────────────────

TotalsDecision totals_decision(bool admit_all, const SoftwareFleetQuery& q) {
    if (!admit_all)
        return {false, kOmittedScope};
    const bool exact_name = !q.name.empty() && q.match == NameMatch::kExact;
    const bool other = !q.agent_id.empty() || !q.q.empty() || !q.status.empty() ||
                       !q.ecosystem.empty() || !q.source.empty() || !q.kind.empty();
    return exact_name && !other ? TotalsDecision{true, {}}
                                : TotalsDecision{false, kOmittedFilters};
}

TotalsDecision totals_decision(bool admit_all, const SoftwareComponentQuery& q) {
    if (!admit_all)
        return {false, kOmittedScope};
    const bool exact_name = !q.name.empty() && q.match == NameMatch::kExact;
    const bool other = !q.agent_id.empty() || !q.q.empty() || !q.status.empty();
    return exact_name && !other ? TotalsDecision{true, {}}
                                : TotalsDecision{false, kOmittedFilters};
}

namespace {
// A rollup row and its refresh epoch are read on separate pool leases, so a refresh committing
// between the two would pair the new generation's counts with the old as_of. The same bracket as
// software_catalogue_model's page read: epoch, row, epoch again; a moved epoch is read once more
// against the new one, a second move is kDegraded (a 503, never a mismatched pair). The epoch is
// the refresh transaction's start time at one-second resolution, so two refreshes committing
// inside one second read as one; unreachable at the hourly cadence, noted so nobody shortens it.
template <class MetaFn, class RowFn>
TotalsOutcome read_rollup_totals(const MetaFn& meta_fn, const RowFn& row_fn) {
    TotalsOutcome out;
    const auto meta = meta_fn();
    if (!meta)
        return out;
    auto gen = meta->refreshed_at;
    if (gen == 0) {
        out.status = TotalsStatus::kBuilding;
        return out;
    }
    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto t = row_fn();
        if (!t)
            return out;
        const auto after = meta_fn();
        if (!after)
            return out;
        if (after->refreshed_at == gen) {
            out.status = TotalsStatus::kServed;
            out.totals = *t;
            out.as_of = gen;
            return out;
        }
        gen = after->refreshed_at;
    }
    return out; // kDegraded
}
} // namespace

TotalsOutcome read_application_totals(const TotalsReads& io, const SoftwareFleetQuery& q) {
    TotalsOutcome out;
    std::vector<std::string> single;
    const std::vector<std::string>* set = q.versions ? &*q.versions : nullptr;
    if (!set && q.version) {
        single.push_back(*q.version);
        set = &single;
    }
    if (set) {
        // A version filter is a live exact aggregate over the set: installs = rows, devices =
        // distinct (a device on two selected versions counts once).
        const auto t = io.version_set_totals(q.name, *set);
        if (!t)
            return out; // kDegraded
        out.status = TotalsStatus::kServed;
        out.totals = *t;
        return out;
    }
    return read_rollup_totals(io.catalog_meta, [&] { return io.title_totals(q.name); });
}

TotalsOutcome read_component_totals(const TotalsReads& io, const SoftwareComponentQuery& q) {
    if (!q.kind.empty() && !q.versions)
        return read_rollup_totals(io.component_meta, [&] {
            return io.component_totals(q.kind, q.name, std::nullopt);
        });
    TotalsOutcome out;
    const auto t = io.component_totals(q.kind, q.name, q.versions);
    if (!t)
        return out;
    out.status = TotalsStatus::kServed;
    out.totals = *t;
    return out;
}

void set_totals(nlohmann::json& body, const TotalsOutcome& t, bool components) {
    nlohmann::json& j = body["totals"] = nlohmann::json::object();
    j[components ? "instances" : "installs"] = t.totals.installs;
    j["devices"] = t.totals.devices;
    if (components)
        j["devices_unconfirmed"] = t.totals.devices_unconfirmed;
    j["as_of"] = t.as_of ? nlohmann::json(*t.as_of) : nlohmann::json(nullptr);
}

void set_totals_omitted(nlohmann::json& body, std::string_view reason) {
    body["totals"] = nullptr;
    body["totals_omitted"] = std::string(reason);
}

// ── JSON / CSV ───────────────────────────────────────────────────────────────

namespace {

nlohmann::json host_or_null(const DeviceFacts& f, const std::string& agent_id) {
    const auto it = f.hostname.find(agent_id);
    return it == f.hostname.end() ? nlohmann::json(nullptr) : nlohmann::json(it->second);
}
std::int64_t last_seen_of(const DeviceFacts& f, const std::string& agent_id) {
    const auto it = f.last_seen.find(agent_id);
    return it == f.last_seen.end() ? 0 : it->second;
}
nlohmann::json epoch_or_null(std::int64_t v) {
    return v > 0 ? nlohmann::json(v) : nlohmann::json(nullptr);
}
std::string host_text(const DeviceFacts& f, const std::string& agent_id) {
    const auto it = f.hostname.find(agent_id);
    return it == f.hostname.end() ? std::string{} : it->second;
}
std::string epoch_text(std::int64_t v) { return v > 0 ? std::to_string(v) : std::string{}; }

void append_row(std::string& out, std::initializer_list<std::string> cells) {
    bool first = true;
    for (const auto& c : cells) {
        if (!first)
            out += ',';
        first = false;
        out += data_export::csv_escape(c);
    }
    out += '\n';
}

} // namespace

nlohmann::json list_row_json(const SoftwareFleetRow& r, const DeviceFacts& facts) {
    auto j = swc::device_row_json(r);
    const auto& e = r.entry;
    j["hostname"] = host_or_null(facts, r.agent_id);
    j["last_seen"] = epoch_or_null(last_seen_of(facts, r.agent_id));
    j["status"] = std::string(derive_status(r.facet_status, r.facet_enabled));
    j["last_confirmed_at"] = epoch_or_null(r.last_confirmed_at);
    j["install_type"] = e.install_type;
    j["install_scope"] = e.install_scope;
    j["install_location"] = e.install_location;
    j["instance_key"] = e.instance_key;
    return j;
}

nlohmann::json component_row_json(const SoftwareComponentRow& r, const DeviceFacts& facts) {
    return nlohmann::json{
        {"agent_id", r.agent_id},
        {"hostname", host_or_null(facts, r.agent_id)},
        {"last_seen", epoch_or_null(last_seen_of(facts, r.agent_id))},
        {"kind", r.kind},
        {"name", r.name},
        {"version", r.version},
        {"version_source", r.version_source},
        {"path", r.path},
        {"anchor_app", r.anchor_app},
        {"first_seen", r.first_seen},
        {"status", std::string(derive_status(r.facet_status, r.facet_enabled))},
        {"component_last_confirmed_at", epoch_or_null(r.last_confirmed_at)},
    };
}

namespace {
template <class Row, class RowJson>
nlohmann::json page_json(const char* key, const std::vector<Row>& rows, RowJson row_json,
                         std::string_view next_cursor, std::int64_t devices_omitted,
                         bool truncated_by_cap) {
    auto arr = nlohmann::json::array();
    for (const auto& r : rows)
        arr.push_back(row_json(r));
    nlohmann::json out{
        {key, std::move(arr)},
        {"count", rows.size()},
        {"next_cursor", next_cursor.empty() ? nlohmann::json(nullptr)
                                            : nlohmann::json(std::string(next_cursor))},
        {"devices_omitted", devices_omitted},
    };
    if (truncated_by_cap)
        out["result_truncated_by_cap"] = true;
    return out;
}
} // namespace

nlohmann::json list_response_json(const std::vector<SoftwareFleetRow>& rows, const DeviceFacts& facts,
                                  std::string_view next_cursor, std::int64_t devices_omitted,
                                  bool truncated_by_cap) {
    return page_json("software", rows,
                     [&](const SoftwareFleetRow& r) { return list_row_json(r, facts); },
                     next_cursor, devices_omitted, truncated_by_cap);
}

nlohmann::json components_response_json(const std::vector<SoftwareComponentRow>& rows,
                                        const DeviceFacts& facts, std::string_view next_cursor,
                                        std::int64_t devices_omitted, bool truncated_by_cap) {
    return page_json("components", rows,
                     [&](const SoftwareComponentRow& r) { return component_row_json(r, facts); },
                     next_cursor, devices_omitted, truncated_by_cap);
}

std::string list_csv(const std::vector<SoftwareFleetRow>& rows, const DeviceFacts& facts) {
    std::string out(kListCsvHeader);
    out += '\n';
    for (const auto& r : rows) {
        const auto& e = r.entry;
        append_row(out, {r.agent_id, e.name, e.version, e.publisher, e.install_date, e.kind,
                         e.ecosystem, e.epoch, e.release, e.arch, e.signature_status, e.distro_id,
                         e.distro_version, e.source, host_text(facts, r.agent_id),
                         epoch_text(last_seen_of(facts, r.agent_id)),
                         std::string(derive_status(r.facet_status, r.facet_enabled)),
                         epoch_text(r.last_confirmed_at), e.install_type, e.install_scope,
                         e.install_location, e.instance_key});
    }
    return out;
}

std::string components_csv(const std::vector<SoftwareComponentRow>& rows, const DeviceFacts& facts) {
    std::string out(kComponentsCsvHeader);
    out += '\n';
    for (const auto& r : rows)
        append_row(out, {r.agent_id, host_text(facts, r.agent_id),
                         epoch_text(last_seen_of(facts, r.agent_id)), r.kind, r.name, r.version,
                         r.version_source, r.path, r.anchor_app, std::to_string(r.first_seen),
                         std::string(derive_status(r.facet_status, r.facet_enabled)),
                         epoch_text(r.last_confirmed_at)});
    return out;
}

} // namespace yuzu::server::software_list
