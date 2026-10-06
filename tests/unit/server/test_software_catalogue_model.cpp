/**
 * test_software_catalogue_model.cpp — pure coverage for software_catalogue_model.hpp: parameter
 * parsing, audit targets, the opaque cursor codecs, the one-consistent-read orchestration and its
 * generation-skew handling (with fake readers), KPI derivation and the JSON/CSV shaping. No
 * store, no libpq, no clock, no network.
 */

#include <catch2/catch_test_macros.hpp>

#include "software_catalogue_model.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::software_catalogue;

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
    SoftwareCatalogRow r = row(name, INT64_MAX);
    CHECK(encode_catalogue_cursor(r, kHeadFp, INT64_MAX).size() <= kCursorMaxBytes);
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
    auto vr = versions_response_json("git", {v}, true, true);
    CHECK(vr["truncated"] == true);
    CHECK(vr["newest_omitted"] == true);
    CHECK(vr["count"] == 1);
    CHECK_FALSE(versions_response_json("git", {v}, false, false).contains("newest_omitted"));
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
        REQUIRE(q.limit <= kCatalogReadMax);
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

namespace {

struct FakeIo {
    std::vector<std::int64_t> gens; // successive refreshed_at readings
    std::size_t gen_i{0};
    bool rows_ok{true}, totals_ok{true};
    std::vector<SoftwareCatalogRow> rows;
    int rows_reads{0};
    CatalogueReads io() {
        return {[this]() -> std::optional<CatalogRollupMeta> {
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
                }};
    }
};

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
    auto page = read_catalogue_page(f.io(), req(2));
    REQUIRE(page);
    CHECK(page->rows.size() == 2);
    CHECK(page->totals.installs == 5);
    REQUIRE(page->meta.has_value());
    // full page -> a cursor bound to generation 10 that the same filters accept
    REQUIRE_FALSE(page->next_cursor.empty());
    CHECK(decode_catalogue_cursor(page->next_cursor, filter_fingerprint({}), 10));
    // short page -> no cursor
    auto shorter = read_catalogue_page(f.io(), req(5));
    REQUIRE(shorter);
    CHECK(shorter->next_cursor.empty());
}

TEST_CASE("read_catalogue_page: a refresh landing mid-read", "[server][software_catalogue_model]") {
    SECTION("first page retries ONCE and carries the new generation") {
        FakeIo f;
        f.gens = {10, 11, 11, 11}; // before, after (moved) -> retry: before, after (stable)
        f.rows = {row("a", 3)};
        auto page = read_catalogue_page(f.io(), req(1));
        REQUIRE(page);
        CHECK(f.rows_reads == 2);
        CHECK(decode_catalogue_cursor(page->next_cursor, filter_fingerprint({}), 11));
    }
    SECTION("moving twice is a degrade, never a third read") {
        FakeIo f;
        f.gens = {10, 11, 11, 12};
        f.rows = {row("a", 3)};
        auto page = read_catalogue_page(f.io(), req(1));
        REQUIRE_FALSE(page);
        CHECK_FALSE(page.error());
        CHECK(f.rows_reads == 2);
    }
    SECTION("a continuation page never re-pages an old keyset over a new snapshot") {
        const auto tok = encode_catalogue_cursor(row("a", 3), filter_fingerprint({}), 10);
        FakeIo f;
        f.gens = {10, 11};
        f.rows = {row("b", 2)};
        auto page = read_catalogue_page(f.io(), req(1, tok));
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
        auto page = read_catalogue_page(f.io(), req(1, tok));
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
        auto mismatch = read_catalogue_page(f.io(), req(1, tok));
        REQUIRE_FALSE(mismatch);
        CHECK(mismatch.error() == CursorError::kFilterMismatch);
        auto garbage = read_catalogue_page(f.io(), req(1, "garbage"));
        REQUIRE_FALSE(garbage);
        CHECK(garbage.error() == CursorError::kMalformed);
    }
    SECTION("any nullopt read is a degrade") {
        FakeIo rows_down;
        rows_down.gens = {10};
        rows_down.rows_ok = false;
        auto a = read_catalogue_page(rows_down.io(), req(1));
        REQUIRE_FALSE(a);
        CHECK_FALSE(a.error());
        FakeIo totals_down;
        totals_down.gens = {10};
        totals_down.totals_ok = false;
        auto b = read_catalogue_page(totals_down.io(), req(1));
        REQUIRE_FALSE(b);
        CHECK_FALSE(b.error());
    }
    SECTION("the host path reads no meta and uses generation 0") {
        FakeIo f;
        f.gens = {10};
        f.rows = {row("a", 1)};
        auto rq = req(1);
        rq.query.agent_id = "dev-1";
        auto page = read_catalogue_page(f.io(), rq);
        REQUIRE(page);
        CHECK_FALSE(page->meta.has_value());
        CHECK(f.gen_i == 0);
        CHECK(decode_catalogue_cursor(page->next_cursor, filter_fingerprint(rq.query), 0));
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
    SECTION("a degraded read never yields a partial body") {
        FakeIo f;
        f.gens = {10};
        f.rows_ok = false;
        auto ex = read_titles_export(f.io(), rq, false);
        CHECK_FALSE(ex);
    }
}
