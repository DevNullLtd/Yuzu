/**
 * test_software_catalogue_model.cpp — pure coverage for software_catalogue_model.hpp: parameter
 * parsing, the scope push-down rule, audit targets, the opaque cursor codecs, the
 * one-consistent-read orchestration and its generation-skew handling (with fake readers), KPI
 * derivation and the JSON/CSV shaping. No store, no libpq, no clock, no network.
 */

#include <catch2/catch_test_macros.hpp>

#include "software_catalogue_model.hpp"

#include <algorithm>
#include <functional>
#include <unordered_set>
#include <string>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::software_catalogue;
using yuzu::server::authz::VisibleSet;

namespace {

Params params(std::initializer_list<std::pair<const std::string, std::string>> kv) {
    return Params(kv);
}

SoftwareCatalogRow row(std::string name, std::int64_t installs, std::string newest = "1.0") {
    SoftwareCatalogRow r;
    r.name = std::move(name);
    r.publisher = "Acme";
    r.device_count = installs;
    r.version_count = 2;
    r.ecosystems = "brew,deb";
    r.kinds = "pkg";
    r.newest_version = std::move(newest);
    return r;
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

const std::string kHeadFp = "0123456789abcdef";

std::string b64url_of(std::string_view in) {
    // Test-side encoder, independent of the model's, over the same RFC 4648 §5 alphabet.
    static constexpr char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (unsigned char c : in) {
        acc = (acc << 8) | c;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out += tbl[(acc >> bits) & 63];
        }
    }
    if (bits > 0)
        out += tbl[(acc << (6 - bits)) & 63];
    return out;
}

} // namespace

TEST_CASE("parse_catalogue_params: defaults / clamps / refusals", "[server][software_catalogue_model]") {
    SECTION("defaults") {
        auto r = parse_catalogue_params(params({}));
        REQUIRE(r);
        CHECK(r->query.limit == 100);
        CHECK(r->format == "json");
        CHECK(r->query.q.empty());
        CHECK(r->query.versions_min == 0);
        CHECK(r->cursor.empty());
    }
    SECTION("limit is clamped in int64 before narrowing") {
        CHECK(parse_catalogue_params(params({{"limit", "-5"}}))->query.limit == 1);
        CHECK(parse_catalogue_params(params({{"limit", "99999999999"}}))->query.limit == 1000);
        CHECK(parse_catalogue_params(params({{"limit", "250"}}))->query.limit == 250);
    }
    SECTION("csv limit is the TOTAL export cap, default and ceiling 10000") {
        auto d = parse_catalogue_params(params({{"format", "csv"}}));
        REQUIRE(d);
        CHECK(d->query.limit == 10000);
        auto c = parse_catalogue_params(params({{"format", "csv"}, {"limit", "2"}}));
        CHECK(c->query.limit == 2);
        CHECK(parse_catalogue_params(params({{"format", "csv"}, {"limit", "99999999"}}))->query.limit ==
              10000);
    }
    SECTION("non-integer or malformed values are a 400") {
        CHECK_FALSE(parse_catalogue_params(params({{"limit", "12abc"}})));
        CHECK_FALSE(parse_catalogue_params(params({{"versions_min", "abc"}})));
        CHECK_FALSE(parse_catalogue_params(params({{"versions_min", "-1"}})));
        CHECK_FALSE(parse_catalogue_params(params({{"format", "xml"}})));
        CHECK_FALSE(parse_catalogue_params(params({{"cursor", std::string(2049, 'a')}})));
        CHECK_FALSE(parse_catalogue_params(params({{"limit", "x"}})).error().empty());
    }
    SECTION("a cursor with format=csv is a 400, never silently dropped") {
        auto r = parse_catalogue_params(params({{"format", "csv"}, {"cursor", "garbage"}}));
        REQUIRE_FALSE(r);
        CHECK(r.error() == "cursor is not accepted with format=csv");
        // a json page still takes one
        CHECK(parse_catalogue_params(params({{"format", "json"}, {"cursor", "garbage"}})));
    }
    SECTION("a repeated key is a 400 naming the key") {
        auto r = parse_catalogue_params(params({{"kind", "app"}, {"kind", "pkg"}}));
        REQUIRE_FALSE(r);
        CHECK(r.error() == "repeated query parameter kind");
    }
    SECTION("empty dimension filters mean no filter; unknown keys are ignored") {
        auto r = parse_catalogue_params(params({{"kind", ""}, {"ecosystem", ""}, {"source", ""},
                                            {"nope", "1"}}));
        REQUIRE(r);
        CHECK(r->query.kind.empty());
        CHECK(r->query.ecosystem.empty());
        CHECK(r->query.source.empty());
    }
    SECTION("q is clamped to 128 bytes at a UTF-8 boundary") {
        std::string q(127, 'a');
        q += "\xC3\xA9\xC3\xA9"; // two 2-byte code points straddling the 128-byte mark
        auto r = parse_catalogue_params(params({{"q", q}}));
        REQUIRE(r);
        CHECK(r->query.q.size() == 127);
    }
    SECTION("a q the clamp would empty is a 400, a long valid q clamps non-empty") {
        // 200 stray continuation bytes: clamp_utf8 walks back to 0 and would run unfiltered.
        auto bad = parse_catalogue_params(params({{"q", std::string(200, '\x80')}}));
        REQUIRE_FALSE(bad);
        CHECK(bad.error() == "invalid parameter encoding");
        std::string good;
        while (good.size() < 200)
            good += "caf\xC3\xA9";
        auto r = parse_catalogue_params(params({{"q", good}}));
        REQUIRE(r);
        CHECK_FALSE(r->query.q.empty());
        CHECK(r->query.q.size() <= 128);
    }
    SECTION("invalid UTF-8 or an embedded NUL is a 400 on every text field") {
        const std::string nul("a\0b", 3);
        for (const char* key : {"q", "kind", "ecosystem", "source", "agent_id", "cursor"}) {
            for (const std::string& bad : {std::string("a\xFF"), nul}) {
                INFO(key);
                auto r = parse_catalogue_params(params({{key, bad}}));
                REQUIRE_FALSE(r);
                CHECK(r.error() == "invalid parameter encoding");
            }
        }
    }
    SECTION("kind / ecosystem / source / agent_id are capped at kSourceMaxBytes") {
        for (const char* key : {"kind", "ecosystem", "source", "agent_id"}) {
            INFO(key);
            CHECK(parse_catalogue_params(params({{key, std::string(kSourceMaxBytes, 'a')}})));
            auto r = parse_catalogue_params(params({{key, std::string(kSourceMaxBytes + 1, 'a')}}));
            REQUIRE_FALSE(r);
            CHECK(r.error() == "parameter too long");
        }
    }
}

TEST_CASE("parse_versions_params", "[server][software_catalogue_model]") {
    CHECK_FALSE(parse_versions_params(params({})));
    CHECK(parse_versions_params(params({{"name", ""}})).error() == "name is required");
    auto r = parse_versions_params(params({{"name", "git"}, {"ecosystem", "brew"}, {"agent_id", "a1"}}));
    REQUIRE(r);
    CHECK(r->query.name == "git");
    CHECK(r->query.ecosystem == "brew");
    CHECK(r->query.agent_id == "a1");
    CHECK(r->query.limit == 200);
    CHECK_FALSE(parse_versions_params(params({{"name", "a"}, {"name", "b"}})));
    CHECK(parse_versions_params(params({{"name", "a"}, {"limit", "9999"}}))->query.limit == 1000);
}

TEST_CASE("parse_versions_params: encoding and length bounds", "[server][software_catalogue_model]") {
    const std::string nul("a\0b", 3);
    for (const char* key : {"name", "kind", "ecosystem", "source", "agent_id"}) {
        for (const std::string& bad : {std::string("a\xFF"), nul}) {
            INFO(key);
            auto r = std::string_view(key) == "name"
                         ? parse_versions_params(params({{"name", bad}}))
                         : parse_versions_params(params({{"name", "git"}, {key, bad}}));
            REQUIRE_FALSE(r);
            CHECK(r.error() == "invalid parameter encoding");
        }
    }
    for (const char* key : {"kind", "ecosystem", "source", "agent_id"}) {
        INFO(key);
        CHECK(parse_versions_params(params({{"name", "git"}, {key, std::string(kSourceMaxBytes, 'a')}})));
        auto r = parse_versions_params(
            params({{"name", "git"}, {key, std::string(kSourceMaxBytes + 1, 'a')}}));
        REQUIRE_FALSE(r);
        CHECK(r.error() == "parameter too long");
    }
    CHECK(parse_versions_params(params({{"name", std::string(1024, 'a')}})));
    auto r = parse_versions_params(params({{"name", std::string(1025, 'a')}}));
    REQUIRE_FALSE(r);
    CHECK(r.error() == "parameter too long");
}

TEST_CASE("parse_devices_params: legacy first-value semantics", "[server][software_catalogue_model]") {
    SECTION("present-empty version is the exact empty bucket; absent is any") {
        auto a = parse_devices_params(params({{"version", ""}}));
        REQUIRE(a);
        REQUIRE(a->query.version.has_value());
        CHECK(a->query.version->empty());
        CHECK_FALSE(parse_devices_params(params({}))->query.version.has_value());
    }
    SECTION("export mode caps at 10000 and defaults to it; page caps at 1000") {
        auto e = parse_devices_params(params({{"format", "csv"}}));
        CHECK_FALSE(e->format.empty());
        CHECK(e->query.limit == 10000);
        CHECK(parse_devices_params(params({{"format", "json"}, {"limit", "50000"}}))->query.limit ==
              10000);
        CHECK(parse_devices_params(params({}))->format.empty());
        CHECK(parse_devices_params(params({{"limit", "50000"}}))->query.limit == 1000);
        CHECK(parse_devices_params(params({}))->query.limit == 100);
        CHECK(parse_devices_params(params({{"limit", "-3"}}))->query.limit == 1);
    }
    SECTION("limit parses with full consume; format must be json or csv") {
        auto bad = parse_devices_params(params({{"limit", "12abc"}}));
        REQUIRE_FALSE(bad);
        CHECK(bad.error() == "invalid limit (expected integer)");
        CHECK_FALSE(parse_devices_params(params({{"format", "xml"}})));
    }
    SECTION("a repeated key keeps the FIRST value") {
        auto r = parse_devices_params(params({{"name", "first"}, {"name", "second"}}));
        REQUIRE(r);
        CHECK(r->query.name == "first");
    }
    SECTION("the filters and the cursor are read") {
        auto r = parse_devices_params(params({{"agent_id", "a1"},
                                              {"kind", "app"},
                                              {"ecosystem", "brew"},
                                              {"source", "s.a"},
                                              {"q", "git"},
                                              {"cursor", "d1:x"}}));
        REQUIRE(r);
        CHECK(r->query.agent_id == "a1");
        CHECK(r->query.kind == "app");
        CHECK(r->query.ecosystem == "brew");
        CHECK(r->query.source == "s.a");
        CHECK(r->query.q == "git");
        CHECK(r->cursor == "d1:x");
    }
}

TEST_CASE("parse_devices_params: encoding and length bounds", "[server][software_catalogue_model]") {
    const std::string nul("a\0b", 3);
    for (const char* key : {"agent_id", "name", "version", "q", "kind", "ecosystem", "source", "cursor"}) {
        for (const std::string& bad : {std::string("a\xFF"), nul}) {
            INFO(key);
            auto r = parse_devices_params(params({{key, bad}}));
            REQUIRE_FALSE(r);
            CHECK(r.error() == "invalid parameter encoding");
        }
    }
    for (const char* key : {"agent_id", "kind", "ecosystem", "source"}) {
        INFO(key);
        CHECK(parse_devices_params(params({{key, std::string(kSourceMaxBytes, 'a')}})));
        auto r = parse_devices_params(params({{key, std::string(kSourceMaxBytes + 1, 'a')}}));
        REQUIRE_FALSE(r);
        CHECK(r.error() == "parameter too long");
    }
    for (const char* key : {"name", "version"}) {
        INFO(key);
        CHECK(parse_devices_params(params({{key, std::string(1024, 'a')}})));
        CHECK_FALSE(parse_devices_params(params({{key, std::string(1025, 'a')}})));
    }
    CHECK_FALSE(parse_devices_params(params({{"cursor", std::string(kCursorMaxBytes + 1, 'a')}})));
}

namespace {

DevicesRequest dreq(int limit, std::string cursor = {}) {
    DevicesRequest r;
    r.query.limit = limit;
    r.cursor = std::move(cursor);
    return r;
}

// A fake store read: records the query it was handed and answers a fixed row set.
struct FakeDevices {
    std::vector<SoftwareFleetRow> rows;
    bool ok{true};
    int reads{0};
    SoftwareFleetQuery seen;
    DevicesReader reader() {
        return [this](const SoftwareFleetQuery& q) -> std::optional<std::vector<SoftwareFleetRow>> {
            ++reads;
            seen = q;
            if (!ok)
                return std::nullopt;
            return rows;
        };
    }
};

VisibleSet wide_scope(std::string in_scope_id) {
    std::unordered_set<std::string> big{std::move(in_scope_id)};
    for (std::size_t i = 0; i <= kScopePushdownMaxIds; ++i)
        big.insert("agent-" + std::to_string(i));
    return VisibleSet{std::move(big)};
}

} // namespace

TEST_CASE("read_devices_page: scope push-down and the post-filter", "[server][software_catalogue_model]") {
    FakeDevices f;
    f.rows = {fleet_row("git", "a", 1), fleet_row("git", "b", 2)};
    SECTION("TOP reads unfiltered and hides nothing") {
        auto page = read_devices_page(f.reader(), dreq(5), std::nullopt);
        REQUIRE(page);
        CHECK_FALSE(f.seen.agent_ids.has_value());
        CHECK(page->rows.size() == 2);
        CHECK(page->devices_omitted == 0);
        CHECK_FALSE(page->hit_cap);
        CHECK(page->next_cursor.empty());
    }
    SECTION("engaged-empty is deny-all in the query") {
        auto page = read_devices_page(f.reader(), dreq(5), authz::deny_all());
        REQUIRE(page);
        REQUIRE(f.seen.agent_ids.has_value());
        CHECK(f.seen.agent_ids->empty());
    }
    SECTION("engaged within the bound is pushed down and rows are NOT re-filtered") {
        VisibleSet v = std::unordered_set<std::string>{"a", "c"};
        auto page = read_devices_page(f.reader(), dreq(5), v);
        REQUIRE(page);
        REQUIRE(f.seen.agent_ids.has_value());
        auto ids = *f.seen.agent_ids;
        std::ranges::sort(ids);
        CHECK(ids == std::vector<std::string>{"a", "c"});
        CHECK(page->rows.size() == 2); // the store already narrowed; nothing is hidden here
        CHECK(page->devices_omitted == 0);
    }
    SECTION("beyond the bound the query stays wide and the rows are post-filtered") {
        f.rows = {fleet_row("git", "a", 1), fleet_row("git", "b", 2), fleet_row("git", "b", 3)};
        auto page = read_devices_page(f.reader(), dreq(3), wide_scope("a"));
        REQUIRE(page);
        CHECK_FALSE(f.seen.agent_ids.has_value());
        REQUIRE(page->rows.size() == 1);
        CHECK(page->rows[0].agent_id == "a");
        CHECK(page->devices_omitted == 1); // the DISTINCT dropped device, counted once
        // The cap was hit BEFORE filtering, and the cursor is the last SCANNED row (id 3, dropped)
        // so the next page advances past it.
        CHECK(page->hit_cap);
        const auto cur = decode_devices_cursor(page->next_cursor, devices_fingerprint(dreq(3).query));
        REQUIRE(cur);
        CHECK(cur->install_id == 3);
        CHECK(cur->agent_id == "b");
    }
}

TEST_CASE("read_devices_page: cursor and degrade outcomes", "[server][software_catalogue_model]") {
    FakeDevices f;
    f.rows = {fleet_row("git", "a", 1)};
    SECTION("a continuation hands the decoded keyset position to the read") {
        const auto fp = devices_fingerprint(dreq(1).query);
        const auto tok = encode_devices_cursor(fleet_row("git", "a", 1), fp);
        auto page = read_devices_page(f.reader(), dreq(1, tok), std::nullopt);
        REQUIRE(page);
        REQUIRE(f.seen.after.has_value());
        CHECK(f.seen.after->name == "git");
        CHECK(f.seen.after->install_id == 1);
        CHECK(page->hit_cap);
        CHECK_FALSE(page->next_cursor.empty());
    }
    SECTION("a refused cursor never reaches the store") {
        auto bad = read_devices_page(f.reader(), dreq(1, "garbage"), std::nullopt);
        REQUIRE_FALSE(bad);
        CHECK(bad.error() == CursorError::kMalformed);
        DevicesRequest other = dreq(1);
        other.query.kind = "app";
        const auto tok = encode_devices_cursor(fleet_row("git", "a", 1), devices_fingerprint(other.query));
        auto mismatch = read_devices_page(f.reader(), dreq(1, tok), std::nullopt);
        REQUIRE_FALSE(mismatch);
        CHECK(mismatch.error() == CursorError::kFilterMismatch);
        CHECK(f.reads == 0);
    }
    SECTION("a nullopt read is a degrade, never an empty page") {
        f.ok = false;
        auto page = read_devices_page(f.reader(), dreq(1), std::nullopt);
        REQUIRE_FALSE(page);
        CHECK_FALSE(page.error());
    }
}

TEST_CASE("strict_args_error: MCP refuses what REST clamps", "[server][software_catalogue_model]") {
    using nlohmann::json;
    CHECK_FALSE(strict_args_error(json::object()));
    CHECK_FALSE(strict_args_error(json{{"limit", 1000}, {"versions_min", 0}, {"kind", "pkg"},
                                       {"ecosystem", "brew"}, {"q", "git"}, {"name", "git"}}));
    CHECK(strict_args_error(json{{"limit", 0}}));
    CHECK(strict_args_error(json{{"limit", 1001}}));
    CHECK(strict_args_error(json{{"limit", "5"}}));
    CHECK(strict_args_error(json{{"limit", 2.5}}));
    CHECK(strict_args_error(json{{"versions_min", -1}}));
    CHECK(strict_args_error(json{{"versions_min", 100001}}));
    CHECK(strict_args_error(json{{"kind", "nope"}}));
    CHECK(strict_args_error(json{{"kind", ""}})); // the enum has no empty member
    CHECK(strict_args_error(json{{"ecosystem", "nope"}}));
    CHECK(strict_args_error(json{{"q", 5}}));
    CHECK(strict_args_error(json{{"q", std::string(129, 'a')}}));
    CHECK(strict_args_error(json{{"source", std::string(257, 'a')}}));
    CHECK(strict_args_error(json{{"cursor", std::string(2049, 'a')}}));
    for (const char* eco : {"rpm", "deb", "apk", "pacman", "windows", "macos", "macos_pkgutil",
                            "brew", "optional_feature"})
        CHECK_FALSE(strict_args_error(json{{"ecosystem", eco}}));
}

TEST_CASE("read_versions: the rollup gate applies to the unfiltered fleet drill only",
          "[server][software_catalogue_model]") {
    struct Fake {
        std::optional<std::int64_t> refreshed_at{10}; // nullopt: the meta read degrades
        bool versions_ok{true};
        int meta_reads{0}, version_reads{0};
        VersionsReads io() {
            return {[this]() -> std::optional<CatalogRollupMeta> {
                        ++meta_reads;
                        if (!refreshed_at)
                            return std::nullopt;
                        CatalogRollupMeta m;
                        m.refreshed_at = *refreshed_at;
                        return m;
                    },
                    [this](const SoftwareVersionsQuery&) -> std::optional<std::vector<SoftwareVersionCount>> {
                        ++version_reads;
                        if (!versions_ok)
                            return std::nullopt;
                        return std::vector<SoftwareVersionCount>{SoftwareVersionCount{"1.0", 3, true}};
                    }};
        }
    };
    SoftwareVersionsQuery q;
    q.name = "git";
    SECTION("unfiltered: meta is read first and rows are served once built") {
        Fake f;
        const auto r = read_versions(f.io(), q);
        REQUIRE(r);
        CHECK(r->size() == 1);
        CHECK(f.meta_reads == 1);
    }
    SECTION("unfiltered: a never-refreshed rollup is building and reads no rows") {
        Fake f;
        f.refreshed_at = 0;
        const auto r = read_versions(f.io(), q);
        REQUIRE_FALSE(r);
        CHECK(r.error() == VersionsError::kBuilding);
        CHECK(f.version_reads == 0);
    }
    SECTION("unfiltered: a degraded meta read is a degrade") {
        Fake f;
        f.refreshed_at = std::nullopt;
        const auto r = read_versions(f.io(), q);
        REQUIRE_FALSE(r);
        CHECK(r.error() == VersionsError::kDegraded);
        CHECK(f.version_reads == 0);
    }
    SECTION("a degraded rows read is a degrade") {
        Fake f;
        f.versions_ok = false;
        const auto r = read_versions(f.io(), q);
        REQUIRE_FALSE(r);
        CHECK(r.error() == VersionsError::kDegraded);
    }
    SECTION("every filtered or per-device drill skips the meta read entirely") {
        for (auto mutate : std::vector<std::function<void(SoftwareVersionsQuery&)>>{
                 [](auto& v) { v.kind = "app"; }, [](auto& v) { v.ecosystem = "brew"; },
                 [](auto& v) { v.source = "s"; }, [](auto& v) { v.agent_id = "a"; }}) {
            Fake f;
            f.refreshed_at = std::nullopt; // would degrade if it were read
            SoftwareVersionsQuery filtered = q;
            mutate(filtered);
            const auto r = read_versions(f.io(), filtered);
            REQUIRE(r);
            CHECK(f.meta_reads == 0);
        }
    }
}

TEST_CASE("audit_target: fixed field order", "[server][software_catalogue_model]") {
    SoftwareCatalogQuery c;
    CHECK(audit_target(c) == "fleet");
    c.agent_id = "dev-1";
    c.source = "s.a";
    c.kind = "app";
    c.q = "git";
    c.versions_min = 3;
    c.ecosystem = "brew";
    CHECK(audit_target(c) == "agent=dev-1;kind=app;ecosystem=brew;source=s.a;q=git;versions_min=3");

    SoftwareVersionsQuery v;
    v.name = "git";
    v.ecosystem = "brew";
    CHECK(audit_target(v) == "name=git;ecosystem=brew");

    SoftwareFleetQuery f;
    CHECK(audit_target(f) == "fleet");
    f.agent_id = "dev-1";
    CHECK(audit_target(f) == "agent=dev-1");
    f.name = "git";
    CHECK(audit_target(f) == "name=git");
    f.version = "";
    f.q = "x";
    CHECK(audit_target(f) == "name=git;version=;q=x");
}

TEST_CASE("audit_target neutralises forged k=v fields in caller text",
          "[server][software_catalogue_model]") {
    SoftwareCatalogQuery c;
    c.q = "a;kind=admin b\nc";
    const auto t = audit_target(c);
    CHECK(t.find('\n') == std::string::npos);
    CHECK(t.find(' ') == std::string::npos);
    CHECK(t.find("kind=admin") == std::string::npos); // '=' inside the value is neutralised
    CHECK(t == "fleet;q=a;kind_admin_b_c");
}

TEST_CASE("fingerprints are stable and sensitive to every field and blind to paging",
          "[server][software_catalogue_model]") {
    SoftwareCatalogQuery a;
    const auto base = filter_fingerprint(a);
    CHECK(base.size() == 16);
    CHECK(filter_fingerprint(a) == base);
    for (auto mutate : std::vector<std::function<void(SoftwareCatalogQuery&)>>{
             [](auto& q) { q.kind = "app"; }, [](auto& q) { q.ecosystem = "brew"; },
             [](auto& q) { q.source = "s"; }, [](auto& q) { q.q = "x"; },
             [](auto& q) { q.agent_id = "a"; }, [](auto& q) { q.versions_min = 2; }}) {
        SoftwareCatalogQuery b;
        mutate(b);
        CHECK(filter_fingerprint(b) != base);
    }
    a.limit = 5;
    a.after = SoftwareCatalogCursor{3, "x"};
    CHECK(filter_fingerprint(a) == base);

    // A field value holding the old 0x1F separator cannot shift a boundary between two fields.
    SoftwareCatalogQuery c1, c2;
    c1.kind = "a\x1f";
    c1.ecosystem = "b";
    c2.kind = "a";
    c2.ecosystem = "\x1f" "b";
    CHECK(filter_fingerprint(c1) != filter_fingerprint(c2));
}

TEST_CASE("devices fingerprint: every filter; present-empty version; blind to paging and scope",
          "[server][software_catalogue_model]") {
    SoftwareFleetQuery f;
    const auto base = devices_fingerprint(f);
    CHECK(base.size() == 16);
    for (auto mutate : std::vector<std::function<void(SoftwareFleetQuery&)>>{
             [](auto& q) { q.agent_id = "a"; }, [](auto& q) { q.name = "n"; },
             [](auto& q) { q.version = "1"; }, [](auto& q) { q.q = "x"; },
             [](auto& q) { q.kind = "app"; }, [](auto& q) { q.ecosystem = "brew"; },
             [](auto& q) { q.source = "s"; }}) {
        SoftwareFleetQuery b;
        mutate(b);
        CHECK(devices_fingerprint(b) != base);
    }
    SoftwareFleetQuery empty_version;
    empty_version.version = ""; // present-empty differs from absent
    CHECK(devices_fingerprint(empty_version) != base);
    f.limit = 7;
    f.agent_ids = std::vector<std::string>{"a"};
    f.after = SoftwareCursor{"n", "a", 1};
    CHECK(devices_fingerprint(f) == base);

    // Length-prefixed: a value holding the separator cannot shift a boundary between two fields.
    SoftwareFleetQuery c1, c2;
    c1.agent_id = "a\x1f";
    c1.name = "b";
    c2.agent_id = "a";
    c2.name = "\x1f" "b";
    CHECK(devices_fingerprint(c1) != devices_fingerprint(c2));
}

TEST_CASE("catalogue cursor round trip", "[server][software_catalogue_model]") {
    const std::string fp = filter_fingerprint({});
    for (const std::string& name : std::vector<std::string>{"plain", "has:colon", std::string("sep\x1f" "inside"), "eq=/+", "caf\xC3\xA9", ""}) {
        const auto tok = encode_catalogue_cursor(row(name, 42), fp, 1700000000);
        auto cur = decode_catalogue_cursor(tok, fp, 1700000000);
        REQUIRE(cur);
        CHECK(cur->installs == 42);
        CHECK(cur->name == name);
    }
    // Known answer: the rest-api.md example token. "Mx9naXQ" is RFC 4648 section 5 base64url of
    // "3\x1fgit", so a wire-format change cannot silently re-break the documented example.
    const std::string doc_fp = "9a1c0e5d7b3f2a68";
    constexpr const char* kDocToken = "c1:9a1c0e5d7b3f2a68:1790000000:Mx9naXQ";
    CHECK(encode_catalogue_cursor(row("git", 3), doc_fp, 1790000000) == kDocToken);
    auto doc = decode_catalogue_cursor(kDocToken, doc_fp, 1790000000);
    REQUIRE(doc);
    CHECK(doc->installs == 3);
    CHECK(doc->name == "git");
}

TEST_CASE("worst-case cursors stay within kCursorMaxBytes", "[server][software_catalogue_model]") {
    const std::string name(1024, '\xFF'); // ingest allows 1024-byte names
    const std::string agent(256, 'z');
    SoftwareCatalogRow r = row(name, INT64_MAX);
    CHECK(encode_catalogue_cursor(r, kHeadFp, INT64_MAX).size() <= kCursorMaxBytes);
    SoftwareFleetRow f = fleet_row(name, agent, INT64_MAX);
    CHECK(encode_devices_cursor(f, kHeadFp).size() <= kCursorMaxBytes);
}

TEST_CASE("catalogue cursor decoder refusals", "[server][software_catalogue_model]") {
    const std::string fp = filter_fingerprint({});
    const std::string good = encode_catalogue_cursor(row("t", 5), fp, 100);
    REQUIRE(decode_catalogue_cursor(good, fp, 100));

    auto code = [&](std::string_view tok, std::string_view f = {}, std::int64_t gen = 100) {
        auto r = decode_catalogue_cursor(tok, f.empty() ? std::string_view(fp) : f, gen);
        REQUIRE_FALSE(r);
        return r.error();
    };
    const std::string payload = b64url_of(std::string("5\x1f") + "t");
    SECTION("malformed shapes") {
        CHECK(code("x1:" + fp + ":100:" + payload) == CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100") == CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100:" + payload + ":extra") == CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100:" + payload + "=") == CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100:" + payload + "+") == CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100:A") == CursorError::kMalformed); // too short to carry the 0x1F separator
        // The strict decoder's two rules, each pinned alone on an otherwise-valid 4-char payload:
        CHECK(code("c1:" + fp + ":100:" + payload + "A") == CursorError::kMalformed); // tail length 1 mod 4 only
        CHECK(code("c1:" + fp + ":100:NR9=") == CursorError::kMalformed); // non-alphabet byte only, valid length
        CHECK(code("c1:ABCDEF0123456789:100:" + payload) == CursorError::kMalformed); // uppercase
        CHECK(code("c1:" + fp + ":1x0:" + payload) == CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100:" + b64url_of("nosep")) == CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100:" + b64url_of("abc\x1f" "t")) == CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100:" + b64url_of("-1\x1f" "t")) == CursorError::kMalformed);
    }
    SECTION("a payload name that is not valid UTF-8 or holds a NUL is malformed") {
        CHECK(code("c1:" + fp + ":100:" + b64url_of(std::string("5\x1f") + "\xFF")) ==
              CursorError::kMalformed);
        CHECK(code("c1:" + fp + ":100:" + b64url_of(std::string("5\x1f") + std::string("a\0b", 3))) ==
              CursorError::kMalformed);
        // before the filter / generation checks
        CHECK(code("c1:" + fp + ":999:" + b64url_of(std::string("5\x1f") + "\xFF")) ==
              CursorError::kMalformed);
    }
    SECTION("filter mismatch and staleness") {
        CHECK(code(good, "ffffffffffffffff") == CursorError::kFilterMismatch);
        CHECK(code(good, {}, 101) == CursorError::kStale);
        // order: filter before stale
        CHECK(code(good, "ffffffffffffffff", 101) == CursorError::kFilterMismatch);
    }
    SECTION("a hand-made head cursor is ACCEPTED (opaque, not authenticated)") {
        const auto head = "c1:" + fp + ":100:" + b64url_of("9223372036854775807\x1f");
        auto r = decode_catalogue_cursor(head, fp, 100);
        REQUIRE(r);
        CHECK(r->installs == INT64_MAX);
        CHECK(r->name.empty());
    }
}

TEST_CASE("devices cursor round trip and refusals", "[server][software_catalogue_model]") {
    const std::string fp = devices_fingerprint({});
    const auto row = fleet_row(std::string("na\x1f" "me"), "agent:1", 77);
    const auto tok = encode_devices_cursor(row, fp);
    auto cur = decode_devices_cursor(tok, fp);
    REQUIRE(cur);
    CHECK(cur->name == row.entry.name);
    CHECK(cur->agent_id == "agent:1");
    CHECK(cur->install_id == 77);

    CHECK(decode_devices_cursor(tok, "ffffffffffffffff").error() == CursorError::kFilterMismatch);
    CHECK(decode_devices_cursor("c1:" + fp + ":x", fp).error() == CursorError::kMalformed);
    CHECK(decode_devices_cursor("d1:" + fp, fp).error() == CursorError::kMalformed);
    CHECK(decode_devices_cursor("d1:" + fp + ":" + b64url_of("onlyone"), fp).error() ==
          CursorError::kMalformed);
    CHECK(decode_devices_cursor("d1:" + fp + ":" + b64url_of("n\x1f" "a\x1f" "x"), fp).error() ==
          CursorError::kMalformed);
    CHECK(decode_devices_cursor("d1:" + fp + ":" + b64url_of("n\x1f" "a\x1f" "1") + "=", fp).error() ==
          CursorError::kMalformed);
    // The decoded name and agent id are bound as SQL parameters: invalid UTF-8 or a NUL is
    // malformed, and is refused before the filter check.
    const std::string nul("a\0b", 3);
    for (const std::string& bad : {std::string("\xFF"), nul}) {
        CHECK(decode_devices_cursor("d1:" + fp + ":" + b64url_of(bad + "\x1f" "a\x1f" "1"), fp).error() ==
              CursorError::kMalformed);
        CHECK(decode_devices_cursor("d1:" + fp + ":" + b64url_of("n\x1f" + bad + "\x1f" "1"), fp).error() ==
              CursorError::kMalformed);
        CHECK(decode_devices_cursor("d1:" + fp + ":" + b64url_of(bad + "\x1f" "a\x1f" "1"),
                                    "ffffffffffffffff")
                  .error() == CursorError::kMalformed);
    }
    // hand-made head: name "", agent "", id 0 - ACCEPTED (opaque, not authenticated)
    CHECK(decode_devices_cursor("d1:" + fp + ":" + b64url_of(std::string("\x1f\x1f") + "0"), fp));
}

TEST_CASE("derive_kpis maps every figure", "[server][software_catalogue_model]") {
    CatalogRollupMeta m;
    m.refreshed_at = 1700000000;
    m.total_titles = 8;
    m.total_devices = 4;
    m.total_publishers = 3;
    m.total_installs = 20;
    m.installs_windows = 10;
    m.installs_macos = 5;
    m.installs_linux = 4;
    m.installs_other = 1;
    m.current_installs = 6;
    m.current_total = 9;
    m.current_titles = 7;
    m.sprawl_titles = 1;
    m.rpm_total = 2;
    m.rpm_unsigned = 1;
    const auto k = derive_kpis(m, Coverage{12, std::nullopt});
    CHECK_FALSE(k.building);
    CHECK(k.windows_pct == 50);
    CHECK(k.macos_pct == 25);
    CHECK(k.linux_pct == 20);
    CHECK(k.other_pct == 5);
    REQUIRE(k.stay_current_pct.has_value());
    CHECK(*k.stay_current_pct == 67);
    CHECK(k.sprawl_pct == 12.5);
    CHECK(k.avg_installs_per_device == 5);

    const auto j = kpis_json(k);
    CHECK(j["titles"] == 8);
    CHECK(j["publishers"] == 3);
    CHECK(j["installs"] == 20);
    CHECK(j["installs_by_os"]["macos"] == 5);
    CHECK(j["os_pct"]["windows"] == 50);
    CHECK(j["stay_current"]["current_installs"] == 6);
    CHECK(j["stay_current"]["total_installs"] == 9);
    CHECK(j["stay_current"]["titles"] == 7);
    CHECK(j["stay_current"]["pct"] == 67);
    CHECK(j["sprawl"]["titles"] == 1);
    CHECK(j["rpm"]["unsigned"] == 1);
    CHECK(j["coverage"]["reporting"] == 4);
    CHECK(j["coverage"]["connected"] == 12);
    CHECK(j["coverage"]["stale"].is_null());
    CHECK_FALSE(j["coverage"].contains("pct")); // no honest ratio exists
    CHECK(j["avg_installs_per_device"] == 5);
    CHECK(j["refreshed_at"] == 1700000000);
    CHECK(j["building"] == false);
}

TEST_CASE("derive_kpis zero guards and the building state", "[server][software_catalogue_model]") {
    const auto k = derive_kpis(CatalogRollupMeta{}, Coverage{});
    CHECK(k.building);
    CHECK(k.windows_pct == 0);
    CHECK_FALSE(k.stay_current_pct.has_value());
    CHECK(k.sprawl_pct == 0.0);
    CHECK(k.avg_installs_per_device == 0);
    const auto j = kpis_json(k);
    CHECK(j["stay_current"]["pct"].is_null());
    CHECK(j["coverage"]["connected"].is_null());
    CHECK(j["building"] == true);
}

TEST_CASE("catalogue/versions JSON shaping", "[server][software_catalogue_model]") {
    const auto git = catalogue_row_json(row("git", 9), false);
    CHECK(git["installs"] == 9);
    CHECK(git["ecosystems"] == nlohmann::json::array({"brew", "deb"}));
    CHECK(git["newest_version"] == "1.0");
    CHECK(catalogue_row_json(row("git", 9), true)["newest_version"] == "");
    SoftwareCatalogRow none = row("x", 1);
    none.ecosystems.clear();
    CHECK(catalogue_row_json(none, false)["ecosystems"].empty());

    const SoftwareCatalogTotals t{30, 99};
    auto full = catalogue_response_json({row("a", 2)}, t, std::nullopt, "tok", false, 0);
    CHECK(full["next_cursor"] == "tok");
    CHECK(full["totals"]["installs"] == 99);
    CHECK(full["kpis"].is_null());
    CHECK(full["devices_omitted"] == 0);
    CHECK_FALSE(full.contains("newest_omitted"));
    auto last = catalogue_response_json({}, t, std::nullopt, "", true, 1);
    CHECK(last["next_cursor"].is_null());
    CHECK(last["newest_omitted"] == true);
    CHECK(last["devices_omitted"] == 1);

    SoftwareVersionCount v;
    v.version = "2.0";
    v.device_count = 4;
    v.newest = true;
    CHECK(version_row_json(v, false)["newest"] == true);
    CHECK(version_row_json(v, true)["newest"] == false);
    auto vr = versions_response_json("git", {v}, true, true, 1);
    CHECK(vr["truncated"] == true);
    CHECK(vr["newest_omitted"] == true);
    CHECK(vr["count"] == 1);
    CHECK(vr["devices_omitted"] == 1);
    const auto plain = versions_response_json("git", {v}, false, false, 0);
    CHECK_FALSE(plain.contains("newest_omitted"));
    CHECK(plain["devices_omitted"] == 0);
}

TEST_CASE("devices JSON shaping", "[server][software_catalogue_model]") {
    const auto dr = device_row_json(fleet_row("git", "a1", 3));
    CHECK(dr.size() == 14);
    CHECK(dr["source"] == "installed_apps.list_inventory");
    auto dj = devices_response_json({fleet_row("git", "a1", 3)}, "", 2, true);
    CHECK(dj["count"] == 1);
    CHECK(dj["next_cursor"].is_null());
    CHECK(dj["devices_omitted"] == 2);
    CHECK(dj["result_truncated_by_cap"] == true);
    auto page = devices_response_json({}, "c", 0, false);
    CHECK(page["next_cursor"] == "c");
    CHECK_FALSE(page.contains("result_truncated_by_cap"));
}

TEST_CASE("installs_csv", "[server][software_catalogue_model]") {
    auto fr = fleet_row("=cmd", "a,1", 1);
    fr.entry.publisher = "Ac\"me";
    const auto csv = installs_csv({fr});
    CHECK(csv.starts_with(std::string(kInstallsCsvHeader) + "\n"));
    CHECK(csv.find("a1") == std::string::npos);
    CHECK(csv.find("\"a,1\"") != std::string::npos);  // comma -> quoted
    CHECK(csv.find("'=cmd") != std::string::npos);    // formula neutralised
    CHECK(csv.find("\"Ac\"\"me\"") != std::string::npos);
    CHECK(installs_csv({}) == std::string(kInstallsCsvHeader) + "\n");
}

TEST_CASE("titles_csv", "[server][software_catalogue_model]") {
    SoftwareCatalogRow r = row("caf\xC3\xA9", 3);
    const auto titles = titles_csv({r}, false);
    CHECK(titles == std::string(kTitlesCsvHeader) + "\ncaf\xC3\xA9,Acme,3,2,brew;deb,pkg,1.0\n");
    CHECK(titles_csv({r}, true).ends_with(",pkg,\n"));

    SoftwareCatalogRow hostile = row("=cmd", 1);
    hostile.publisher = "Ac\"me,Inc";
    const auto h = titles_csv({hostile}, false);
    CHECK(h.find("'=cmd") != std::string::npos);            // formula neutralised
    CHECK(h.find("\"Ac\"\"me,Inc\"") != std::string::npos); // quote doubled, comma quoted
}

TEST_CASE("titles_export: cap / truncation / degrade", "[server][software_catalogue_model]") {
    std::vector<SoftwareCatalogRow> all;
    for (int i = 0; i < 7; ++i)
        all.push_back(row("t" + std::to_string(i), 100 - i));
    int reads = 0;
    CatalogueReader fake = [&](const SoftwareCatalogQuery& q) -> std::optional<std::vector<SoftwareCatalogRow>> {
        ++reads;
        REQUIRE(q.limit <= kCatalogRowCap);
        std::vector<SoftwareCatalogRow> out;
        for (const auto& r : all) {
            if (q.after && !(r.device_count < q.after->installs ||
                             (r.device_count == q.after->installs && r.name > q.after->name)))
                continue;
            out.push_back(r);
            if (static_cast<int>(out.size()) == q.limit)
                break;
        }
        return out;
    };
    auto cut = titles_export(fake, {}, 3, false);
    REQUIRE(cut);
    CHECK(cut->truncated);
    CHECK(cut->rows == 3);
    CHECK(std::ranges::count(cut->csv, '\n') == 4); // header + 3 rows
    auto whole = titles_export(fake, {}, 10, false);
    REQUIRE(whole);
    CHECK_FALSE(whole->truncated);
    CHECK(whole->rows == 7);
    CHECK(std::ranges::count(whole->csv, '\n') == 8);

    // rows counts titles, not newlines: a quoted cell holding '\n' must not inflate it
    all = {row("multi\nline", 5)};
    auto quoted = titles_export(fake, {}, 10, false);
    REQUIRE(quoted);
    CHECK(quoted->rows == 1);

    CatalogueReader failing = [](const SoftwareCatalogQuery&) { return std::nullopt; };
    CHECK_FALSE(titles_export(failing, {}, 5, false).has_value());
}

TEST_CASE("titles_export: a walk longer than one store read pages with the keyset cursor",
          "[server][software_catalogue_model]") {
    // 4,001 titles with distinct install counts: reads of 2000 + 2000 + 1 (the short one ends it).
    std::vector<SoftwareCatalogRow> all;
    for (int i = 0; i < 4001; ++i)
        all.push_back(row("t" + std::to_string(i), 10000 - i));
    int reads = 0;
    CatalogueReader fake = [&](const SoftwareCatalogQuery& q) -> std::optional<std::vector<SoftwareCatalogRow>> {
        ++reads;
        REQUIRE(q.limit <= kCatalogRowCap);
        std::vector<SoftwareCatalogRow> out;
        for (const auto& r : all) {
            if (q.after && r.device_count >= q.after->installs)
                continue; // strictly after the cursor (installs are distinct here)
            out.push_back(r);
            if (static_cast<int>(out.size()) == q.limit)
                break;
        }
        return out;
    };
    const auto ex = titles_export(fake, {}, kExportCap, false);
    REQUIRE(ex);
    CHECK(reads == 3);
    CHECK(ex->rows == 4001);
    CHECK_FALSE(ex->truncated);
    CHECK(std::ranges::count(ex->csv, '\n') == 4002); // header + 4001 rows, none repeated
    CHECK(ex->csv.find("\nt4000,") != std::string::npos);
}

namespace {

struct FakeIo {
    std::vector<std::int64_t> gens; // successive refreshed_at readings
    std::size_t gen_i{0};
    std::size_t meta_nullopt_at{static_cast<std::size_t>(-1)}; // nth meta reading that degrades
    std::size_t meta_reads{0};
    bool rows_ok{true}, totals_ok{true};
    std::vector<SoftwareCatalogRow> rows;
    int rows_reads{0};
    // `stale` is always wired (as in production); the registry count only when asked.
    bool wire_connected{false};
    std::int64_t connected_n{0};
    std::optional<std::int64_t> stale_n;
    int connected_calls{0}, stale_calls{0};
    std::int64_t cutoff_seen{-1};
    CatalogueReads io() {
        CatalogueReads r{
            [this]() -> std::optional<CatalogRollupMeta> {
                if (meta_reads++ == meta_nullopt_at)
                    return std::nullopt;
                CatalogRollupMeta m;
                m.refreshed_at = gens[std::min(gen_i++, gens.size() - 1)];
                return m;
            },
            [this](const SoftwareCatalogQuery&) -> std::optional<std::vector<SoftwareCatalogRow>> {
                ++rows_reads;
                if (!rows_ok)
                    return std::nullopt;
                return rows;
            },
            [this](const SoftwareCatalogQuery&) -> std::optional<SoftwareCatalogTotals> {
                if (!totals_ok)
                    return std::nullopt;
                return SoftwareCatalogTotals{static_cast<std::int64_t>(rows.size()), 5};
            },
            [this](std::int64_t cutoff) {
                ++stale_calls;
                cutoff_seen = cutoff;
                return stale_n;
            }};
        if (wire_connected)
            r.connected = [this] {
                ++connected_calls;
                return connected_n;
            };
        return r;
    }
};

constexpr std::int64_t kNow = 1'000'000;

CatalogueRequest req(int limit, std::string cursor = {}) {
    CatalogueRequest r;
    r.query.limit = limit;
    r.cursor = std::move(cursor);
    return r;
}

} // namespace

TEST_CASE("read_catalogue_page: stable generation", "[server][software_catalogue_model]") {
    FakeIo f;
    f.gens = {10};
    f.rows = {row("a", 3), row("b", 2)};
    auto page = read_catalogue_page(f.io(), req(2), kNow);
    REQUIRE(page);
    CHECK(page->rows.size() == 2);
    CHECK(page->totals.installs == 5);
    REQUIRE(page->meta.has_value());
    // full page -> a cursor bound to generation 10 that the same filters accept
    REQUIRE_FALSE(page->next_cursor.empty());
    CHECK(decode_catalogue_cursor(page->next_cursor, filter_fingerprint({}), 10));
    // short page -> no cursor
    auto shorter = read_catalogue_page(f.io(), req(5), kNow);
    REQUIRE(shorter);
    CHECK(shorter->next_cursor.empty());
}

TEST_CASE("read_catalogue_page: a refresh landing mid-read", "[server][software_catalogue_model]") {
    SECTION("first page retries ONCE and carries the new generation") {
        FakeIo f;
        f.gens = {10, 11, 11, 11}; // before, after (moved) -> retry: before, after (stable)
        f.rows = {row("a", 3)};
        f.wire_connected = true;
        auto page = read_catalogue_page(f.io(), req(1), kNow);
        REQUIRE(page);
        CHECK(f.rows_reads == 2);
        CHECK(decode_catalogue_cursor(page->next_cursor, filter_fingerprint({}), 11));
        // the re-read does not repeat the coverage reads, and the KPIs carry the returned page's
        // generation
        CHECK(f.connected_calls == 1);
        CHECK(f.stale_calls == 1);
        REQUIRE(page->kpis.has_value());
        CHECK(page->kpis->meta.refreshed_at == 11);
    }
    SECTION("moving twice is a degrade, never a third read") {
        FakeIo f;
        f.gens = {10, 11, 11, 12};
        f.rows = {row("a", 3)};
        auto page = read_catalogue_page(f.io(), req(1), kNow);
        REQUIRE_FALSE(page);
        CHECK_FALSE(page.error());
        CHECK(f.rows_reads == 2);
    }
    SECTION("a continuation page never re-pages an old keyset over a new snapshot") {
        const auto tok = encode_catalogue_cursor(row("a", 3), filter_fingerprint({}), 10);
        FakeIo f;
        f.gens = {10, 11};
        f.rows = {row("b", 2)};
        auto page = read_catalogue_page(f.io(), req(1, tok), kNow);
        REQUIRE_FALSE(page);
        CHECK(page.error() == CursorError::kStale);
        CHECK(f.rows_reads == 1);
        // Two meta reads only (before, after): without the continuation branch the moved
        // generation would trigger a retry whose re-read of meta is a third.
        CHECK(f.gen_i == 2);
    }
}

TEST_CASE("read_catalogue_page: cursor and degrade outcomes", "[server][software_catalogue_model]") {
    SECTION("a cursor from an older generation is stale before any row read") {
        const auto tok = encode_catalogue_cursor(row("a", 3), filter_fingerprint({}), 9);
        FakeIo f;
        f.gens = {10};
        auto page = read_catalogue_page(f.io(), req(1, tok), kNow);
        REQUIRE_FALSE(page);
        CHECK(page.error() == CursorError::kStale);
        CHECK(f.rows_reads == 0);
    }
    SECTION("a cursor for other filters or garbage is a bad cursor") {
        SoftwareCatalogQuery other;
        other.kind = "app";
        const auto tok = encode_catalogue_cursor(row("a", 3), filter_fingerprint(other), 10);
        FakeIo f;
        f.gens = {10};
        auto mismatch = read_catalogue_page(f.io(), req(1, tok), kNow);
        REQUIRE_FALSE(mismatch);
        CHECK(mismatch.error() == CursorError::kFilterMismatch);
        auto garbage = read_catalogue_page(f.io(), req(1, "garbage"), kNow);
        REQUIRE_FALSE(garbage);
        CHECK(garbage.error() == CursorError::kMalformed);
    }
    SECTION("any nullopt read is a degrade") {
        FakeIo rows_down;
        rows_down.gens = {10};
        rows_down.rows_ok = false;
        auto a = read_catalogue_page(rows_down.io(), req(1), kNow);
        REQUIRE_FALSE(a);
        CHECK_FALSE(a.error());
        FakeIo totals_down;
        totals_down.gens = {10};
        totals_down.totals_ok = false;
        auto b = read_catalogue_page(totals_down.io(), req(1), kNow);
        REQUIRE_FALSE(b);
        CHECK_FALSE(b.error());
    }
    SECTION("the host path reads no meta and uses generation 0") {
        FakeIo f;
        f.gens = {10};
        f.rows = {row("a", 1)};
        auto rq = req(1);
        rq.query.agent_id = "dev-1";
        auto page = read_catalogue_page(f.io(), rq, kNow);
        REQUIRE(page);
        CHECK_FALSE(page->meta.has_value());
        CHECK(f.gen_i == 0);
        CHECK(decode_catalogue_cursor(page->next_cursor, filter_fingerprint(rq.query), 0));
    }
}

TEST_CASE("read_catalogue_page: KPIs and coverage", "[server][software_catalogue_model]") {
    SECTION("a first fleet page derives them once, with the cutoff and the wired counts") {
        FakeIo f;
        f.gens = {10};
        f.rows = {row("a", 3)};
        f.wire_connected = true;
        f.connected_n = 7;
        f.stale_n = 3;
        auto page = read_catalogue_page(f.io(), req(1), kNow);
        REQUIRE(page);
        REQUIRE(page->kpis.has_value());
        CHECK(page->kpis->coverage.connected == 7);
        CHECK(page->kpis->coverage.stale == 3);
        CHECK(page->kpis->meta.refreshed_at == 10);
        CHECK(f.cutoff_seen == kNow - kStaleWindowSecs);
    }
    SECTION("an unwired registry and a degraded stale count are honest nulls") {
        FakeIo f;
        f.gens = {10};
        f.rows = {row("a", 3)};
        // stale_n is nullopt: the bounded count degraded
        auto page = read_catalogue_page(f.io(), req(1), kNow);
        REQUIRE(page);
        REQUIRE(page->kpis.has_value());
        CHECK_FALSE(page->kpis->coverage.connected.has_value());
        CHECK_FALSE(page->kpis->coverage.stale.has_value());
    }
    SECTION("no KPIs on a continuation, the host path, or a failed read") {
        FakeIo f;
        f.gens = {10};
        f.rows = {row("b", 2)};
        f.wire_connected = true;
        const auto tok = encode_catalogue_cursor(row("a", 3), filter_fingerprint({}), 10);
        auto cont = read_catalogue_page(f.io(), req(1, tok), kNow);
        REQUIRE(cont);
        CHECK_FALSE(cont->kpis.has_value());
        auto host_rq = req(1);
        host_rq.query.agent_id = "dev-1";
        auto host = read_catalogue_page(f.io(), host_rq, kNow);
        REQUIRE(host);
        CHECK_FALSE(host->kpis.has_value());
        f.rows_ok = false;
        CHECK_FALSE(read_catalogue_page(f.io(), req(1), kNow));
        CHECK(f.connected_calls == 0);
        CHECK(f.stale_calls == 0);
    }
}

TEST_CASE("read_catalogue_page: limit 0 on an empty page yields no cursor and no back() on empty",
          "[server][software_catalogue_model]") {
    FakeIo f;
    f.gens = {10};
    auto page = read_catalogue_page(f.io(), req(0), kNow);
    REQUIRE(page);
    CHECK(page->rows.empty());
    CHECK(page->next_cursor.empty());
}

TEST_CASE("the second generation read degrades like the first", "[server][software_catalogue_model]") {
    SECTION("a page") {
        FakeIo f;
        f.gens = {10};
        f.meta_nullopt_at = 1; // the bracketing read after rows + totals
        f.rows = {row("a", 3)};
        auto page = read_catalogue_page(f.io(), req(1), kNow);
        REQUIRE_FALSE(page);
        CHECK_FALSE(page.error());
        CHECK(f.rows_reads == 1);
    }
    SECTION("an export") {
        auto rq = req(10);
        rq.format = "csv";
        FakeIo f;
        f.gens = {10};
        f.meta_nullopt_at = 1;
        f.rows = {row("a", 3)};
        CHECK_FALSE(read_titles_export(f.io(), rq, false).has_value());
    }
}

TEST_CASE("read_titles_export brackets the walk by the generation",
          "[server][software_catalogue_model]") {
    auto rq = req(100);
    rq.format = "csv";
    rq.query.limit = 10;
    SECTION("stable") {
        FakeIo f;
        f.gens = {10};
        f.rows = {row("a", 3)};
        auto ex = read_titles_export(f.io(), rq, false);
        REQUIRE(ex);
        CHECK(ex->csv.find("a,Acme,3") != std::string::npos);
        CHECK(ex->rows == 1);
    }
    SECTION("moved once restarts, moved twice degrades") {
        FakeIo once;
        once.gens = {10, 11, 11, 11};
        once.rows = {row("a", 3)};
        CHECK(read_titles_export(once.io(), rq, false));
        FakeIo twice;
        twice.gens = {10, 11, 11, 12};
        twice.rows = {row("a", 3)};
        auto ex = read_titles_export(twice.io(), rq, false);
        CHECK_FALSE(ex);
    }
    SECTION("a never-built rollup is `building`: no rows are read, no empty file is produced") {
        FakeIo f;
        f.gens = {0};
        f.rows = {row("a", 3)};
        auto ex = read_titles_export(f.io(), rq, false);
        REQUIRE(ex);
        CHECK(ex->building);
        CHECK(ex->csv.empty());
        CHECK(ex->rows == 0);
        CHECK(f.rows_reads == 0);
        CHECK(f.meta_reads == 1);
    }
    SECTION("the host path reads no meta, so it is never `building`") {
        FakeIo f;
        f.gens = {0};
        f.rows = {row("a", 3)};
        auto host = rq;
        host.query.agent_id = "dev-1";
        auto ex = read_titles_export(f.io(), host, false);
        REQUIRE(ex);
        CHECK_FALSE(ex->building);
        CHECK(f.meta_reads == 0);
        CHECK(ex->rows == 1);
    }
    SECTION("a stable build has building false") {
        FakeIo f;
        f.gens = {10};
        f.rows = {row("a", 3)};
        auto ex = read_titles_export(f.io(), rq, false);
        REQUIRE(ex);
        CHECK_FALSE(ex->building);
    }
    SECTION("a degraded read never yields a partial body") {
        FakeIo f;
        f.gens = {10};
        f.rows_ok = false;
        auto ex = read_titles_export(f.io(), rq, false);
        CHECK_FALSE(ex);
    }
}
