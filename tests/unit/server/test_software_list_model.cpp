/**
 * test_software_list_model.cpp - pure coverage for software_list_model.hpp (SAM-17): the lookup
 * list parameters, the version-range resolution, the totals admission rule and its reads, the
 * status derivation, the row/CSV shaping and the components cursor and scoped page. No store, no
 * libpq, no clock, no network: every store read is a fake.
 */

#include <catch2/catch_test_macros.hpp>

#include "software_list_model.hpp"

#include <algorithm>
#include <tuple>
#include <unordered_set>
#include <string>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::software_list;
using yuzu::server::authz::VisibleSet;
namespace swc = yuzu::server::software_catalogue;

namespace {

Params params(std::initializer_list<std::pair<const std::string, std::string>> kv) {
    return Params(kv);
}

SoftwareFleetRow fleet_row(std::string name, std::string agent, std::int64_t id) {
    SoftwareFleetRow r;
    r.agent_id = std::move(agent);
    r.entry.name = std::move(name);
    r.entry.version = "1.2";
    r.entry.source = "installed_apps.list_inventory";
    r.install_id = id;
    return r;
}

SoftwareComponentRow comp_row(std::string name, std::string agent, std::string path_hash) {
    SoftwareComponentRow r;
    r.agent_id = std::move(agent);
    r.kind = "library";
    r.name = std::move(name);
    r.path_hash = std::move(path_hash);
    r.version = "3.0";
    return r;
}

} // namespace

TEST_CASE("parse_list_params: match defaults exact; prefix and contains are accepted",
          "[server][software_list_model]") {
    auto r = parse_list_params(params({{"name", "git"}}));
    REQUIRE(r);
    CHECK(r->base.query.match == NameMatch::kExact);
    r = parse_list_params(params({{"name", "git"}, {"match", "prefix"}}));
    REQUIRE(r);
    CHECK(r->base.query.match == NameMatch::kPrefix);
    r = parse_list_params(params({{"name", "git"}, {"match", "contains"}}));
    REQUIRE(r);
    CHECK(r->base.query.match == NameMatch::kContains);
    CHECK_FALSE(parse_list_params(params({{"name", "git"}, {"match", "regex"}})));
    // A non-exact match without a name has nothing to match.
    CHECK_FALSE(parse_list_params(params({{"match", "prefix"}})));
}

TEST_CASE("parse_list_params: a version range requires name with match=exact; a bare version does not",
          "[server][software_list_model]") {
    for (const char* key : {"version_min", "version_max"}) {
        CAPTURE(key);
        CHECK_FALSE(parse_list_params(params({{key, "1.0"}})));
        CHECK_FALSE(parse_list_params(params({{"name", "git"}, {"match", "prefix"}, {key, "1.0"}})));
        auto ok = parse_list_params(params({{"name", "git"}, {key, "1.0"}}));
        REQUIRE(ok);
    }
    // A bare exact `version` is the plain equality predicate it was before the range filters:
    // still accepted without a name (the route's pre-existing contract), with a non-exact match,
    // and as the present-empty bucket.
    auto bare = parse_list_params(params({{"version", "2.0"}}));
    REQUIRE(bare);
    REQUIRE(bare->base.query.version.has_value());
    CHECK(*bare->base.query.version == "2.0");
    CHECK(parse_list_params(params({{"name", "git"}, {"match", "prefix"}, {"version", "2.0"}})));
    auto empty = parse_list_params(params({{"version", ""}}));
    REQUIRE(empty);
    REQUIRE(empty->base.query.version.has_value());
    CHECK(empty->base.query.version->empty());
    // An exact version cannot be combined with a range.
    CHECK_FALSE(parse_list_params(params({{"name", "git"}, {"version", "1"}, {"version_min", "0"}})));
}

TEST_CASE("parse_list_params: status is a closed set and the defaults add no filter",
          "[server][software_list_model]") {
    auto none = parse_list_params(params({{"name", "git"}}));
    REQUIRE(none);
    CHECK(none->base.query.status.empty()); // never defaulted
    for (const char* s : {"current", "unconfirmed", "disabled"})
        CHECK(parse_list_params(params({{"status", s}})));
    CHECK_FALSE(parse_list_params(params({{"status", "stale"}})));
}

TEST_CASE("resolve_version_range: inclusive bounds under the catalogue comparator",
          "[server][software_list_model]") {
    const std::vector<std::string> versions{"1.9", "1.10", "2.0-rc1", "2.0", "", "1.0"};
    auto r = resolve_version_range(versions, "1.9", "2.0-rc1");
    REQUIRE(r);
    std::ranges::sort(*r);
    // 1.9 < 1.10 numerically, and 2.0-rc1 < 2.0; both bounds are inclusive; '' never matches.
    CHECK(*r == std::vector<std::string>{"1.10", "1.9", "2.0-rc1"});
    r = resolve_version_range(versions, "2.0", "");
    REQUIRE(r);
    CHECK(*r == std::vector<std::string>{"2.0"});
    r = resolve_version_range(versions, "", "1.0");
    REQUIRE(r);
    CHECK(*r == std::vector<std::string>{"1.0"});
    r = resolve_version_range(versions, "5", "6"); // nothing inside: an empty set, not an error
    REQUIRE(r);
    CHECK(r->empty());
}

TEST_CASE("resolve_version_range: a read that filled the cap is refused, wording neutral",
          "[server][software_list_model]") {
    std::vector<std::string> many;
    for (int i = 0; i < kCatalogRowCap; ++i)
        many.push_back(std::to_string(i));
    const auto r = resolve_version_range(many, "1", "2");
    REQUIRE_FALSE(r);
    CHECK(r.error() == kRangeNotResolvable);
    CHECK(r.error().find("2000") == std::string::npos); // names no count and no title
    many.pop_back();
    CHECK(resolve_version_range(many, "1", "2"));
}

TEST_CASE("totals_decision: scoped admission never serves; global admission serves an exact name",
          "[server][software_list_model][security]") {
    SoftwareFleetQuery exact;
    exact.name = "git";
    // AdmitScoped: omit(scope) for every filter set.
    CHECK(totals_decision(false, exact).omitted == "scope");
    CHECK_FALSE(totals_decision(false, exact).serve);
    SoftwareFleetQuery with_agent = exact;
    with_agent.agent_id = "a";
    CHECK(totals_decision(false, with_agent).omitted == "scope");
    CHECK(totals_decision(false, SoftwareFleetQuery{}).omitted == "scope");

    // AdmitAll + exact name (+ one version filter) serves.
    CHECK(totals_decision(true, exact).serve);
    SoftwareFleetQuery one_version = exact;
    one_version.version = "1.0";
    CHECK(totals_decision(true, one_version).serve);
    SoftwareFleetQuery range = exact;
    range.versions = std::vector<std::string>{"1.0", "1.1"};
    CHECK(totals_decision(true, range).serve);

    // AdmitAll but not a plain exact-name lookup: omit(filters).
    SoftwareFleetQuery bad;
    bad.name = "git";
    bad.agent_id = "a";
    CHECK(totals_decision(true, bad).omitted == "filters");
    bad = exact;
    bad.q = "x";
    CHECK(totals_decision(true, bad).omitted == "filters");
    bad = exact;
    bad.status = "current";
    CHECK(totals_decision(true, bad).omitted == "filters");
    bad = exact;
    bad.ecosystem = "deb";
    CHECK(totals_decision(true, bad).omitted == "filters");
    bad = exact;
    bad.source = "x.y";
    CHECK(totals_decision(true, bad).omitted == "filters");
    bad = exact;
    bad.match = NameMatch::kPrefix;
    CHECK(totals_decision(true, bad).omitted == "filters");
    bad = exact;
    bad.match = NameMatch::kContains;
    CHECK(totals_decision(true, bad).omitted == "filters");
    CHECK(totals_decision(true, SoftwareFleetQuery{}).omitted == "filters"); // no name at all
    // A bare `version` (accepted without a name) is a filter on the whole fleet: never a total.
    bad = SoftwareFleetQuery{};
    bad.version = "2.0";
    CHECK(totals_decision(true, bad).omitted == "filters");

    // Components: kind is permitted.
    SoftwareComponentQuery c;
    c.name = "libfoo";
    c.kind = "library";
    CHECK(totals_decision(true, c).serve);
    CHECK(totals_decision(false, c).omitted == "scope");
    c.match = NameMatch::kPrefix;
    CHECK(totals_decision(true, c).omitted == "filters");
    c.match = NameMatch::kExact;
    c.status = "current";
    CHECK(totals_decision(true, c).omitted == "filters");
}

TEST_CASE("derive_status truth table", "[server][software_list_model]") {
    CHECK(derive_status("full", true) == "current");
    CHECK(derive_status("delta", true) == "current");
    CHECK(derive_status("constrained", true) == "unconfirmed");
    CHECK(derive_status("timeout", true) == "unconfirmed");
    CHECK(derive_status("not_collected", true) == "unconfirmed");
    CHECK(derive_status("oversize", true) == "unconfirmed");
    CHECK(derive_status("disabled", false) == "disabled");
    CHECK(derive_status("disabled", true) == "disabled");
    CHECK(derive_status("full", false) == "disabled");  // a switched-off facet wins over a stale full
    CHECK(derive_status("", true) == "unconfirmed");    // no state row
}

TEST_CASE("list_row_json carries the lookup keys and leaves device_row_json untouched",
          "[server][software_list_model]") {
    auto r = fleet_row("git", "a1", 7);
    r.entry.install_type = "package_manager";
    r.entry.install_scope = "machine";
    r.entry.install_location = "/usr/bin";
    r.entry.instance_key = "abc";
    r.facet_status = "full";
    r.last_confirmed_at = 0;
    DeviceFacts facts;
    facts.hostname["a1"] = "host-1";
    facts.last_seen["a1"] = 1700000000;

    const auto base = swc::device_row_json(r);
    const auto j = list_row_json(r, facts);
    for (const auto& [k, v] : base.items()) {
        CAPTURE(k);
        REQUIRE(j.contains(k));
        CHECK(j[k] == v); // the 14 original keys are byte-for-byte what device_row_json emits
    }
    CHECK(j.size() == base.size() + 8);
    CHECK(j["hostname"] == "host-1");
    CHECK(j["last_seen"] == 1700000000);
    CHECK(j["status"] == "current");
    CHECK(j["last_confirmed_at"].is_null()); // 0 -> null
    CHECK(j["install_type"] == "package_manager");
    CHECK(j["install_scope"] == "machine");
    CHECK(j["install_location"] == "/usr/bin");
    CHECK(j["instance_key"] == "abc");

    // An unknown device and a never-synced one are null, not blank or zero.
    const auto unknown = list_row_json(r, DeviceFacts{});
    CHECK(unknown["hostname"].is_null());
    CHECK(unknown["last_seen"].is_null());
    r.last_confirmed_at = 1700000500;
    CHECK(list_row_json(r, facts)["last_confirmed_at"] == 1700000500);
}

TEST_CASE("totals JSON: served shape, each omitted reason, building", "[server][software_list_model]") {
    TotalsOutcome t;
    t.status = TotalsStatus::kServed;
    t.totals = {5, 3, 1};
    t.as_of = 1700000000;
    nlohmann::json app = nlohmann::json::object();
    set_totals(app, t, false);
    CHECK(app["totals"] == nlohmann::json({{"installs", 5}, {"devices", 3}, {"as_of", 1700000000}}));
    CHECK_FALSE(app.contains("totals_omitted"));

    nlohmann::json comp = nlohmann::json::object();
    t.as_of.reset(); // computed live
    set_totals(comp, t, true);
    CHECK(comp["totals"] == nlohmann::json({{"instances", 5},
                                            {"devices", 3},
                                            {"devices_unconfirmed", 1},
                                            {"as_of", nullptr}}));

    for (const char* reason : {"scope", "filters", "building"}) {
        nlohmann::json o = nlohmann::json::object();
        set_totals_omitted(o, reason);
        CAPTURE(reason);
        CHECK(o["totals"].is_null());
        CHECK(o["totals_omitted"] == reason);
    }
}

namespace {
struct FakeTotals {
    std::int64_t refreshed_at{1700000000};
    bool ok{true};
    int title_reads{0};
    int set_reads{0};
    int comp_reads{0};
    std::vector<std::string> last_set;
    bool last_had_versions{false};
    TotalsReads reads() {
        TotalsReads io;
        io.catalog_meta = [this]() -> std::optional<CatalogRollupMeta> {
            if (!ok)
                return std::nullopt;
            CatalogRollupMeta m;
            m.refreshed_at = refreshed_at;
            return m;
        };
        io.component_meta = [this]() -> std::optional<ComponentRollupMeta> {
            if (!ok)
                return std::nullopt;
            return ComponentRollupMeta{refreshed_at};
        };
        io.title_totals = [this](std::string_view) -> std::optional<SoftwareTotals> {
            ++title_reads;
            if (!ok)
                return std::nullopt;
            return SoftwareTotals{10, 4, 0};
        };
        io.version_set_totals = [this](std::string_view,
                                       const std::vector<std::string>& v) -> std::optional<SoftwareTotals> {
            ++set_reads;
            last_set = v;
            if (!ok)
                return std::nullopt;
            return SoftwareTotals{7, 2, 0};
        };
        io.component_totals = [this](std::string_view, std::string_view,
                                     const std::optional<std::vector<std::string>>& v)
            -> std::optional<SoftwareTotals> {
            ++comp_reads;
            last_had_versions = v.has_value();
            if (!ok)
                return std::nullopt;
            return SoftwareTotals{9, 3, 2};
        };
        return io;
    }
};
} // namespace

TEST_CASE("read_application_totals: rollup row without a version filter, live set with one",
          "[server][software_list_model]") {
    FakeTotals f;
    SoftwareFleetQuery q;
    q.name = "git";
    auto t = read_application_totals(f.reads(), q);
    CHECK(t.status == TotalsStatus::kServed);
    CHECK(t.totals.installs == 10);
    CHECK(t.totals.devices == 4);
    REQUIRE(t.as_of.has_value());
    CHECK(*t.as_of == 1700000000);
    CHECK(f.set_reads == 0);

    // One exact version: a live aggregate over {version}.
    q.version = "1.0";
    t = read_application_totals(f.reads(), q);
    CHECK(t.status == TotalsStatus::kServed);
    CHECK(f.set_reads == 1);
    CHECK(f.last_set == std::vector<std::string>{"1.0"});
    CHECK_FALSE(t.as_of.has_value());

    // A resolved range: the whole set goes to ONE aggregate (never a sum of per-version counts).
    q.version.reset();
    q.versions = std::vector<std::string>{"1.0", "1.1", "1.2"};
    t = read_application_totals(f.reads(), q);
    CHECK(f.set_reads == 2);
    CHECK(f.last_set.size() == 3);
    CHECK(t.totals.devices == 2);
}

TEST_CASE("read_application_totals: building before the first refresh; a failed read is degraded",
          "[server][software_list_model]") {
    FakeTotals f;
    f.refreshed_at = 0;
    SoftwareFleetQuery q;
    q.name = "git";
    auto t = read_application_totals(f.reads(), q);
    CHECK(t.status == TotalsStatus::kBuilding);
    CHECK(f.title_reads == 0); // nothing read from a never-built rollup

    f.refreshed_at = 1;
    f.ok = false;
    CHECK(read_application_totals(f.reads(), q).status == TotalsStatus::kDegraded);
    q.version = "1";
    CHECK(read_application_totals(f.reads(), q).status == TotalsStatus::kDegraded);
}

TEST_CASE("read_component_totals: kind without a version filter uses the rollup; else live",
          "[server][software_list_model]") {
    FakeTotals f;
    SoftwareComponentQuery q;
    q.name = "libfoo";
    q.kind = "library";
    auto t = read_component_totals(f.reads(), q);
    CHECK(t.status == TotalsStatus::kServed);
    CHECK(t.totals.devices_unconfirmed == 2);
    REQUIRE(t.as_of.has_value());
    CHECK_FALSE(f.last_had_versions);

    q.versions = std::vector<std::string>{"3.0"};
    t = read_component_totals(f.reads(), q);
    CHECK(f.last_had_versions);
    CHECK_FALSE(t.as_of.has_value());

    q.versions.reset();
    q.kind.clear(); // no kind: live, distinct devices do not add across kinds
    t = read_component_totals(f.reads(), q);
    CHECK_FALSE(t.as_of.has_value());

    f.refreshed_at = 0;
    q.kind = "library";
    CHECK(read_component_totals(f.reads(), q).status == TotalsStatus::kBuilding);
    f.ok = false;
    f.refreshed_at = 5;
    CHECK(read_component_totals(f.reads(), q).status == TotalsStatus::kDegraded);
}

TEST_CASE("components cursor: round trip; another filter set and a devices cursor are refused",
          "[server][software_list_model]") {
    auto rq = parse_components_params(params({{"name", "libfoo"}}));
    REQUIRE(rq);
    const std::string fp = components_fingerprint(*rq);
    const SoftwareComponentCursor at{"libfoo", "agent-1", "library", "deadbeef"};
    const auto tok = encode_components_cursor(at, 3, fp);
    const auto back = decode_components_cursor(tok, fp);
    REQUIRE(back);
    CHECK(back->first.name == "libfoo");
    CHECK(back->first.agent_id == "agent-1");
    CHECK(back->first.kind == "library");
    CHECK(back->first.path_hash == "deadbeef");
    CHECK(back->second == 3);

    auto other = parse_components_params(params({{"name", "libbar"}}));
    REQUIRE(other);
    const auto mismatch = decode_components_cursor(tok, components_fingerprint(*other));
    REQUIRE_FALSE(mismatch);
    CHECK(mismatch.error() == swc::CursorError::kFilterMismatch);

    // d1:/d2: and garbage are malformed, never a mismatch.
    for (const char* bad : {"d2:0123456789abcdef:AAAA", "c1:0123456789abcdef:AAAA", "c2:zz:AAAA", ""}) {
        CAPTURE(bad);
        const auto e = decode_components_cursor(bad, fp);
        REQUIRE_FALSE(e);
        CHECK(e.error() == swc::CursorError::kMalformed);
    }
}

TEST_CASE("devices_fingerprint: a default-filter request keeps its pre-SAM-17 value (in-flight cursors stay valid)",
          "[server][software_list_model]") {
    // Golden values computed independently from the pre-change algorithm (FNV-1a over '0' then
    // the seven length-prefixed fields agent_id, name, version, q, kind, ecosystem, source).
    CHECK(swc::devices_fingerprint(SoftwareFleetQuery{}) == "23d08d803d5d56c2");
    SoftwareFleetQuery named;
    named.name = "git";
    CHECK(swc::devices_fingerprint(named) == "5b6c14bc7e221013");
    // Only a non-default new filter moves it.
    SoftwareFleetQuery prefix = named;
    prefix.match = NameMatch::kPrefix;
    CHECK(swc::devices_fingerprint(prefix) != swc::devices_fingerprint(named));
    SoftwareFleetQuery status = named;
    status.status = "current";
    CHECK(swc::devices_fingerprint(status) != swc::devices_fingerprint(named));
}

TEST_CASE("list_fingerprint: a default request keeps the pre-SAM-17 fingerprint; the new filters bind",
          "[server][software_list_model]") {
    auto plain = parse_list_params(params({{"name", "git"}}));
    REQUIRE(plain);
    CHECK(list_fingerprint(*plain) == swc::devices_fingerprint(plain->base.query));

    auto prefix = parse_list_params(params({{"name", "git"}, {"match", "prefix"}}));
    auto status = parse_list_params(params({{"name", "git"}, {"status", "current"}}));
    auto range = parse_list_params(params({{"name", "git"}, {"version_min", "1.0"}}));
    REQUIRE(prefix);
    REQUIRE(status);
    REQUIRE(range);
    const std::unordered_set<std::string> fps{list_fingerprint(*plain), list_fingerprint(*prefix),
                                              list_fingerprint(*status), list_fingerprint(*range)};
    CHECK(fps.size() == 4);
    // The resolved version set is derived data and does not enter the fingerprint.
    auto with_set = *range;
    with_set.base.query.versions = std::vector<std::string>{"1.0", "1.1"};
    CHECK(list_fingerprint(with_set) == list_fingerprint(*range));
}

namespace {
struct FakeComponents {
    std::vector<SoftwareComponentRow> rows;
    int reads{0};
    SoftwareComponentQuery seen;
    ComponentsReader reader() {
        return [this](const SoftwareComponentQuery& q) -> std::optional<std::vector<SoftwareComponentRow>> {
            ++reads;
            seen = q;
            std::vector<SoftwareComponentRow> out;
            std::int64_t to_skip = q.skip;
            for (const auto& r : rows) {
                if (q.after && !(std::tie(r.name, r.agent_id, r.kind, r.path_hash) >
                                 std::tie(q.after->name, q.after->agent_id, q.after->kind,
                                          q.after->path_hash)))
                    continue;
                if (to_skip > 0) {
                    --to_skip;
                    continue;
                }
                if (static_cast<int>(out.size()) == q.limit)
                    break;
                out.push_back(r);
            }
            return out;
        };
    }
};

VisibleSet wide_scope(std::string in_scope_id) {
    std::unordered_set<std::string> big{std::move(in_scope_id)};
    for (std::size_t i = 0; i <= swc::kScopePushdownMaxIds; ++i)
        big.insert("agent-" + std::to_string(i));
    return VisibleSet{std::move(big)};
}
} // namespace

TEST_CASE("read_components_page: push-down, wide path counts distinct dropped devices, cursor is clean",
          "[server][software_list_model][security]") {
    FakeComponents f;
    f.rows = {comp_row("libfoo", "a", "01"), comp_row("libfoo", "b", "02"),
              comp_row("libfoo", "b", "03"), comp_row("libfoo", "c", "04")};
    auto rq = parse_components_params(params({{"name", "libfoo"}, {"limit", "3"}}));
    REQUIRE(rq);

    SECTION("a bounded scope is pushed into the query") {
        VisibleSet v = std::unordered_set<std::string>{"a", "c"};
        auto page = read_components_page(f.reader(), *rq, v);
        REQUIRE(page);
        REQUIRE(f.seen.agent_ids.has_value());
        CHECK(f.seen.agent_ids->size() == 2);
        CHECK(page->devices_omitted == 0);
    }
    SECTION("engaged-empty is deny-all in the query") {
        auto page = read_components_page(f.reader(), *rq, authz::deny_all());
        REQUIRE(page);
        REQUIRE(f.seen.agent_ids.has_value());
        CHECK(f.seen.agent_ids->empty());
    }
    SECTION("wide path: out-of-scope devices are dropped, counted once, and absent from the cursor") {
        // Page size 1 forces a cursor; the only in-scope device is "a".
        auto small = parse_components_params(params({{"name", "libfoo"}, {"limit", "1"}}));
        REQUIRE(small);
        auto page = read_components_page(f.reader(), *small, wide_scope("a"));
        REQUIRE(page);
        REQUIRE(page->rows.size() == 1);
        CHECK(page->rows[0].agent_id == "a");
        REQUIRE_FALSE(page->next_cursor.empty());
        // The cursor decodes to the last IN-SCOPE row served, never a dropped row's key.
        const auto cur = decode_components_cursor(page->next_cursor, components_fingerprint(*small));
        REQUIRE(cur);
        CHECK(cur->first.agent_id == "a");
        CHECK(cur->first.path_hash == "01");
    }
    SECTION("a scoped-out agent_id is reported as a denied target") {
        auto named = parse_components_params(params({{"name", "libfoo"}, {"agent_id", "zzz"}}));
        REQUIRE(named);
        VisibleSet v = std::unordered_set<std::string>{"a"};
        auto page = read_components_page(f.reader(), *named, v);
        REQUIRE(page);
        CHECK(page->target_denied);
        CHECK(swc::denied_detail(*page) == "scope: agent_id outside the caller's scope");
    }
}

TEST_CASE("CSV: 22-column installs header; quoting; the components header", "[server][software_list_model]") {
    // The first 14 columns are the existing installs header, byte for byte.
    CHECK(kListCsvHeader.substr(0, swc::kInstallsCsvHeader.size()) == swc::kInstallsCsvHeader);
    CHECK(std::ranges::count(kListCsvHeader, ',') + 1 == static_cast<long>(kListCsvColumns));
    CHECK(kListCsvColumns == 22);
    CHECK(std::ranges::count(kComponentsCsvHeader, ',') + 1 == static_cast<long>(kComponentsCsvColumns));

    auto r = fleet_row("a,b\nc", "a1", 1); // comma and newline in a cell
    DeviceFacts facts;
    const auto csv = list_csv({r}, facts);
    CHECK(csv.starts_with(std::string(kListCsvHeader) + "\n"));
    CHECK(csv.find("\"a,b\nc\"") != std::string::npos);
    // Data row: the quoted newline stays inside one record; 22 cells are written.
    const auto body = csv.substr(kListCsvHeader.size() + 1);
    std::size_t commas = 0;
    bool quoted = false;
    for (char c : body) {
        if (c == '"')
            quoted = !quoted;
        else if (c == ',' && !quoted)
            ++commas;
    }
    CHECK(commas == kListCsvColumns - 1);

    const auto ccsv = components_csv({comp_row("libfoo", "a1", "01")}, facts);
    CHECK(ccsv.starts_with(std::string(kComponentsCsvHeader) + "\n"));
}

TEST_CASE("parse_components_params: rules, limits and the export cap", "[server][software_list_model]") {
    CHECK_FALSE(parse_components_params(params({{"version_min", "1"}})));       // needs name
    CHECK_FALSE(parse_components_params(
        params({{"name", "x"}, {"match", "contains"}, {"version_min", "1"}}))); // needs match=exact
    auto v = parse_components_params(params({{"name", "x"}, {"version", "1"}}));
    REQUIRE(v);
    REQUIRE(v->query.versions.has_value());
    CHECK(*v->query.versions == std::vector<std::string>{"1"});
    // A bare exact version is a plain equality predicate and needs no name.
    auto bare = parse_components_params(params({{"version", "1"}}));
    REQUIRE(bare);
    REQUIRE(bare->query.versions.has_value());
    CHECK(*bare->query.versions == std::vector<std::string>{"1"});
    auto page = parse_components_params(params({{"limit", "5000"}}));
    REQUIRE(page);
    CHECK(page->query.limit == static_cast<int>(swc::kCataloguePageMax));
    auto csv = parse_components_params(params({{"format", "csv"}}));
    REQUIRE(csv);
    CHECK(csv->query.limit == static_cast<int>(swc::kExportCap));
    CHECK_FALSE(parse_components_params(params({{"format", "xml"}})));
    CHECK_FALSE(parse_components_params(params({{"limit", "abc"}})));
    CHECK_FALSE(parse_components_params(params({{"status", "stale"}})));
}
