/**
 * test_software_export_stream.cpp - the pure core of the streamed installed-software export
 * (software_export_stream.hpp): request parsing, JSONL and CSV chunk formatting, and the clamp on
 * the concurrency flag (the cap itself is a StreamBudget lease, tested with the route).
 *
 * Pure: no store, no socket, no clock, no sleeps. Rows are fixtures.
 */

#include <catch2/catch_test_macros.hpp>

#include "software_export_stream.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <sstream>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace swe = yuzu::server::software_export;
namespace swl = yuzu::server::software_list;
using json = nlohmann::json;

namespace {

swl::Params params(std::initializer_list<std::pair<const std::string, std::string>> kv) {
    return swl::Params(kv.begin(), kv.end());
}

SoftwareFleetRow row(const std::string& agent, std::int64_t install_id, const std::string& name,
                     const std::string& publisher = "Acme") {
    SoftwareFleetRow r;
    r.agent_id = agent;
    r.install_id = install_id;
    r.entry.name = name;
    r.entry.version = "1." + std::to_string(install_id);
    r.entry.publisher = publisher;
    r.entry.kind = "package";
    r.facet_status = "full";
    return r;
}

// RFC 4180: split CSV text into records of cells (quoted cells may hold commas, quotes, newlines).
std::vector<std::vector<std::string>> parse_csv(const std::string& text) {
    std::vector<std::vector<std::string>> out;
    std::vector<std::string> rec;
    std::string cell;
    bool quoted = false;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (quoted) {
            if (c == '"' && i + 1 < text.size() && text[i + 1] == '"') {
                cell += '"';
                ++i;
            } else if (c == '"') {
                quoted = false;
            } else {
                cell += c;
            }
        } else if (c == '"') {
            quoted = true;
        } else if (c == ',') {
            rec.push_back(std::move(cell));
            cell.clear();
        } else if (c == '\n') {
            rec.push_back(std::move(cell));
            cell.clear();
            out.push_back(std::move(rec));
            rec.clear();
        } else {
            cell += c;
        }
    }
    return out;
}

} // namespace

TEST_CASE("export params: format is required and must be jsonl or csv; cursor and limit are refused",
          "[software_export][stream]") {
    SECTION("format is required") {
        const auto none = swe::parse_export_params(params({{"name", "pkg"}}));
        REQUIRE_FALSE(none);
        CHECK(none.error().find("format is required") != std::string::npos);
        CHECK_FALSE(swe::parse_export_params(params({{"format", ""}})));
    }
    SECTION("only jsonl and csv") {
        for (const char* bad : {"json", "JSONL", "xlsx", "pdf", "ndjson", " csv"})
            CHECK_FALSE(swe::parse_export_params(params({{"format", bad}})));
        const auto j = swe::parse_export_params(params({{"format", "jsonl"}}));
        const auto c = swe::parse_export_params(params({{"format", "csv"}}));
        REQUIRE(j);
        REQUIRE(c);
        CHECK(j->format == swe::ExportFormat::jsonl);
        CHECK(c->format == swe::ExportFormat::csv);
    }
    SECTION("cursor and limit are refused, even present-empty") {
        for (const char* key : {"cursor", "limit"}) {
            const auto r = swe::parse_export_params(params({{"format", "csv"}, {key, ""}}));
            REQUIRE_FALSE(r);
            CHECK(r.error().find("cursor and limit") != std::string::npos);
        }
        CHECK_FALSE(swe::parse_export_params(params({{"format", "csv"}, {"limit", "5"}})));
    }
    SECTION("the list filters pass through and the page size is fixed") {
        const auto r = swe::parse_export_params(
            params({{"format", "csv"}, {"name", "openssl"}, {"kind", "package"}}));
        REQUIRE(r);
        CHECK(r->list.base.query.name == "openssl");
        CHECK(r->list.base.query.kind == "package");
        CHECK(r->list.base.query.limit == swe::kPageRows);
        CHECK(r->list.base.cursor.empty());
        CHECK(r->list.base.format.empty()); // the buffered json|csv selector never reaches the list
    }
    SECTION("a bad list filter is the list parser's 400") {
        CHECK_FALSE(swe::parse_export_params(
            params({{"format", "csv"}, {"version_min", "1.0"}}))); // a range needs an exact name
        CHECK_FALSE(swe::parse_export_params(params({{"format", "csv"}, {"purl", "nope"}})));
    }
}

TEST_CASE("export chunk: JSONL is one list_row_json object per line", "[software_export][stream]") {
    swl::DeviceFacts facts;
    facts.hostname = {{"a-1", "host-one"}};
    facts.last_seen = {{"a-1", 1'700'000'000}};
    const std::vector<SoftwareFleetRow> rows{row("a-1", 1, "pkg"), row("a-2", 2, "pkg")};

    const auto text = swe::format_chunk(rows, facts, swe::ExportFormat::jsonl, true);
    REQUIRE_FALSE(text.empty());
    CHECK(text.back() == '\n');
    std::istringstream in(text);
    std::string line;
    std::size_t i = 0;
    while (std::getline(in, line)) {
        REQUIRE(i < rows.size());
        const auto parsed = json::parse(line);
        CHECK(parsed == swl::list_row_json(rows[i], facts));
        ++i;
    }
    CHECK(i == rows.size());

    SECTION("the first-chunk flag changes nothing for JSONL") {
        CHECK(swe::format_chunk(rows, facts, swe::ExportFormat::jsonl, false) == text);
    }
    SECTION("no rows is an empty chunk") {
        CHECK(swe::format_chunk({}, facts, swe::ExportFormat::jsonl, true).empty());
    }
}

TEST_CASE("export chunk: CSV carries the header once, in the first chunk",
          "[software_export][stream]") {
    const swl::DeviceFacts facts;
    const std::vector<SoftwareFleetRow> rows{row("a-1", 1, "pkg"), row("a-2", 2, "pkg")};

    const auto first = swe::format_chunk(rows, facts, swe::ExportFormat::csv, true);
    const auto next = swe::format_chunk(rows, facts, swe::ExportFormat::csv, false);
    const auto recs = parse_csv(first);
    REQUIRE(recs.size() == 3); // header + two rows
    CHECK(first.starts_with(std::string(swl::kListCsvHeader) + "\n"));
    for (const auto& r : recs)
        CHECK(r.size() == swl::kListCsvColumns);
    CHECK(next.find(std::string(swl::kListCsvHeader)) == std::string::npos);
    CHECK(parse_csv(next).size() == 2);
    CHECK(first == std::string(swl::kListCsvHeader) + "\n" + next);

    SECTION("an empty first chunk is the header alone, a later one is empty") {
        CHECK(swe::format_chunk({}, facts, swe::ExportFormat::csv, true) ==
              std::string(swl::kListCsvHeader) + "\n");
        CHECK(swe::format_chunk({}, facts, swe::ExportFormat::csv, false).empty());
    }
}

TEST_CASE("export chunk: CSV neutralises formula cells and escapes quotes and newlines",
          "[software_export][stream]") {
    const swl::DeviceFacts facts;
    auto r = row("a-1", 1, "=HYPERLINK(\"http://x\")", "Acme, \"Inc\"\nLine2");
    r.entry.install_location = "+cmd";
    const auto recs = parse_csv(swe::format_chunk({r}, facts, swe::ExportFormat::csv, false));
    REQUIRE(recs.size() == 1);
    REQUIRE(recs[0].size() == swl::kListCsvColumns);
    CHECK(recs[0][1] == "'=HYPERLINK(\"http://x\")"); // name: a leading '=' is defused
    CHECK(recs[0][3] == "Acme, \"Inc\"\nLine2");       // publisher: comma, quote, newline round-trip
    CHECK(recs[0][20] == "'+cmd");                     // install_location
}

TEST_CASE("export cap: the flag is clamped to the accepted range, never to 0 (which the budget "
          "reads as unlimited)",
          "[software_export][stream][budget]") {
    CHECK(swe::clamp_concurrency(0) == 1);
    CHECK(swe::clamp_concurrency(-4) == 1);
    CHECK(swe::clamp_concurrency(1) == 1);
    CHECK(swe::clamp_concurrency(7) == 7);
    CHECK(swe::clamp_concurrency(16) == 16);
    CHECK(swe::clamp_concurrency(99) == 16);
    CHECK(swe::clamp_concurrency(swe::kDefaultConcurrency) ==
          static_cast<std::size_t>(swe::kDefaultConcurrency));
}
