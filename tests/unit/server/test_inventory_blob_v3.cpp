/**
 * test_inventory_blob_v3.cpp — pure coverage for inventory_blob_v3.hpp (the blob-v3 grammar)
 * and install_type_rules.hpp (the install-type table). No store, no libpq, no clock, no
 * protobuf: every case feeds literal wire bytes to the parser.
 */

#include <catch2/catch_test_macros.hpp>

#include "install_type_rules.hpp"
#include "inventory_blob_v3.hpp"
#include "software_catalog_rules.hpp"

#include <cstddef>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr char kFs = '\x1f'; // field separator
constexpr char kRs = '\x1e'; // record terminator

// One record: fields 0x1F-joined, 0x1E-terminated.
std::string rec(std::initializer_list<std::string_view> fields) {
    std::string out;
    bool first = true;
    for (const auto f : fields) {
        if (!first)
            out += kFs;
        out += f;
        first = false;
    }
    return out + kRs;
}

std::string header() {
    return std::string(kV3Header);
}

// `S` record. duration/bytes are strings so a test can feed junk.
std::string sec(std::string_view facet, std::string_view status, std::string_view base = "",
                std::string_view token = "", std::string_view dur = "0",
                std::string_view bytes = "0") {
    return rec({"S", facet, status, base, token, dur, bytes});
}

// `+` record with the 16 row slots (slot 14 is the reserved uninstall_string).
std::string plus(std::string_view name, std::string_view source,
                 std::string_view install_location = "", std::string_view slot14 = "",
                 std::string_view version = "1.0") {
    return rec({"+", name, version, "Pub", "2026-01-01", "app", "windows", "", "", "x64", "", "",
                "", install_location, slot14, "pkg-id", source});
}

constexpr std::string_view kApps = "installed_apps.list_inventory";

const V3Section* find(const V3Report& r, std::string_view facet) {
    for (const auto& s : r.sections) {
        if (s.facet == facet)
            return &s;
    }
    return nullptr;
}

V3Report parse_ok(const std::string& blob) {
    auto r = parse_v3_blob(blob);
    REQUIRE(r.has_value());
    return std::move(*r);
}

} // namespace

TEST_CASE("v3 header detection: only the exact header bytes make a blob v3",
          "[server][inventory_blob_v3]") {
    CHECK(is_v3_blob(header()));
    CHECK(is_v3_blob(header() + sec(kApps, "full")));
    // A v2 blob whose first product is literally named "v3" is still v2.
    CHECK_FALSE(is_v3_blob(std::string("v3") + kFs + "1.0" + kFs + "Pub" + kFs + "2026" + kRs));
    CHECK_FALSE(is_v3_blob(std::string("v3") + kRs));
    CHECK_FALSE(is_v3_blob(std::string(1, kFs) + "v3"));        // header without its terminator
    CHECK_FALSE(is_v3_blob(std::string(1, kFs) + "v30" + kRs)); // a different version token
    CHECK_FALSE(is_v3_blob(""));
    // A non-v3 blob is refused by the parser, not misread.
    auto r = parse_v3_blob(std::string("v3") + kFs + "1.0" + kRs);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == V3ParseErrorKind::kNotV3);
    // The header alone names no section: refused, so no caller can mistake it for a stored report.
    auto none = parse_v3_blob(header());
    REQUIRE_FALSE(none.has_value());
    CHECK(none.error() == V3ParseErrorKind::kBadSectionHeader);
}

TEST_CASE("v3 parses every record kind", "[server][inventory_blob_v3]") {
    const std::string h1(64, 'a');
    std::string blob = header();
    blob += sec(kApps, "full", "", "tok", "1234", "5678");
    blob += plus("Alpha", kApps, "C:\\Program Files\\Alpha\\", "uninstall.exe /x");
    blob += plus("Beta", kApps);
    blob += sec("pkg_inventory.packages", "delta", "basehash");
    blob += rec({"-", h1});
    blob += plus("Gamma", "pkg_inventory.packages");
    blob += sec("component_inventory", "full");
    blob += rec({"comp", "jar", "log4j-core", "2.14.1", "pom", "/opt/app/log4j-core.jar", "1048576",
                 "1700000000", "AcmeApp"});
    blob += sec("runtimes.python", "constrained", "", "windows:runtimes:registry_unreadable");
    blob += sec("middleware.ibm_mq", "disabled");

    const V3Report r = parse_ok(blob);
    REQUIRE(r.sections.size() == 5);

    const auto* apps = find(r, kApps);
    REQUIRE(apps != nullptr);
    CHECK(apps->refusal == V3Refusal::kNone);
    CHECK(apps->status == V3Status::kFull);
    CHECK(apps->token == "tok");
    CHECK(apps->duration_ms == 1234);
    CHECK(apps->bytes_read == 5678);
    REQUIRE(apps->rows.size() == 2);
    // Slot 13 is stored; slot 14 (the uninstall string) is consumed and dropped.
    CHECK(apps->rows[0].name == "Alpha");
    CHECK(apps->rows[0].install_location == "C:\\Program Files\\Alpha\\");
    CHECK(apps->rows[0].package_id == "pkg-id");
    CHECK(apps->rows[0].source == kApps);
    CHECK(apps->rows[1].install_location.empty());

    const auto* pk = find(r, "pkg_inventory.packages");
    REQUIRE(pk != nullptr);
    CHECK(pk->status == V3Status::kDelta);
    CHECK(pk->base == "basehash");
    REQUIRE(pk->deletions.size() == 1);
    CHECK(pk->deletions[0] == h1);
    CHECK(pk->rows.size() == 1);

    const auto* comp = find(r, kComponentInventoryFacet);
    REQUIRE(comp != nullptr);
    CHECK(comp->refusal == V3Refusal::kNone);
    REQUIRE(comp->components.size() == 1);
    CHECK(comp->components[0].name == "log4j-core");
    CHECK(comp->components[0].version_source == "pom");
    CHECK(comp->components[0].size == 1048576);
    CHECK(comp->components[0].mtime == 1700000000);
    CHECK(comp->components[0].anchor_app == "AcmeApp");

    const auto* py = find(r, "runtimes.python");
    REQUIRE(py != nullptr);
    CHECK(py->status == V3Status::kConstrained);
    CHECK(py->token == "windows:runtimes:registry_unreadable");
    CHECK(py->rows.empty());

    const auto* mq = find(r, "middleware.ibm_mq");
    REQUIRE(mq != nullptr);
    CHECK(mq->status == V3Status::kDisabled);
    CHECK(mq->refusal == V3Refusal::kNone);
}

TEST_CASE("v3 status vocabulary round-trips and only full/delta carry rows",
          "[server][inventory_blob_v3]") {
    for (const auto name :
         {"full", "delta", "constrained", "timeout", "oversize", "not_collected", "disabled"}) {
        const auto st = v3_status_parse(name);
        REQUIRE(st.has_value());
        CHECK(v3_status_name(*st) == name);
        CHECK(v3_status_carries_rows(*st) ==
              (std::string_view(name) == "full" || std::string_view(name) == "delta"));
    }
    CHECK_FALSE(v3_status_parse("").has_value());
    CHECK_FALSE(v3_status_parse("FULL").has_value());
    CHECK_FALSE(v3_status_parse("partial").has_value());
}

TEST_CASE("v3 grammar refusals isolate to the section", "[server][inventory_blob_v3]") {
    struct Case {
        const char* name;
        std::string body; // the section under test, then a clean section follows
        V3Refusal expect;
    };
    const std::string h(64, 'f');
    const std::vector<Case> cases = {
        {"rows in a status-only section", sec(kApps, "constrained") + plus("A", kApps),
         V3Refusal::kRowsInStatusOnly},
        {"a deletion in a status-only section", sec(kApps, "timeout") + rec({"-", h}),
         V3Refusal::kRowsInStatusOnly},
        {"a - record in a full section", sec(kApps, "full") + rec({"-", h}),
         V3Refusal::kDeleteInFull},
        {"source differs from the facet", sec(kApps, "full") + plus("A", "pkg_inventory.packages"),
         V3Refusal::kSourceMismatch},
        {"empty source", sec(kApps, "full") + plus("A", ""), V3Refusal::kSourceMismatch},
        {"unknown status", sec(kApps, "partial") + plus("A", kApps), V3Refusal::kUnknownStatus},
        {"empty status", sec(kApps, "") + plus("A", kApps), V3Refusal::kUnknownStatus},
        {"unknown facet", sec("made_up.source", "full"), V3Refusal::kUnknownFacet},
        {"unknown record kind", sec(kApps, "full") + rec({"?", "x"}), V3Refusal::kUnknownRecord},
        {"a malformed row hash", sec(kApps, "delta", "b") + rec({"-", "not-a-hash"}),
         V3Refusal::kBadRowHash},
        {"an uppercase row hash", sec(kApps, "delta", "b") + rec({"-", std::string(64, 'F')}),
         V3Refusal::kBadRowHash},
        {"a + record in component_inventory",
         sec(kComponentInventoryFacet, "full") + plus("A", kComponentInventoryFacet),
         V3Refusal::kWrongRecordForFacet},
        {"a comp record outside component_inventory",
         sec(kApps, "full") + rec({"comp", "jar", "x", "1", "pom", "/p", "1", "1", ""}),
         V3Refusal::kWrongRecordForFacet},
        {"an unknown comp version_source",
         sec(kComponentInventoryFacet, "full") +
             rec({"comp", "jar", "x", "1", "guess", "/p", "1", "1", ""}),
         V3Refusal::kBadVersionSource},
        {"a comp record with no name",
         sec(kComponentInventoryFacet, "full") + rec({"comp", "jar", "", "1", "pom"}),
         V3Refusal::kBadRecord},
        {"a NUL inside a row field", sec(kApps, "full") + plus(std::string("A\0B", 3), kApps),
         V3Refusal::kNulByte},
        {"a NUL in a row's install location",
         sec(kApps, "full") + plus("A", kApps, std::string("C:\\x\0y", 6)), V3Refusal::kNulByte},
        {"a NUL in the section header token", sec(kApps, "full", "", std::string("t\0k", 3)),
         V3Refusal::kNulByte},
        {"a NUL in a comp record",
         sec(kComponentInventoryFacet, "full") +
             rec({"comp", "jar", "x", "1", "pom", std::string("/p\0q", 4), "1", "1", ""}),
         V3Refusal::kNulByte},
        {"a NUL in a record of a status-only section",
         sec(kApps, "constrained") + plus(std::string("A\0", 2), kApps), V3Refusal::kNulByte},
        {"a duplicate facet",
         sec(kApps, "full") + plus("A", kApps) + sec(kApps, "full") + plus("B", kApps),
         V3Refusal::kDuplicateFacet},
    };
    for (const auto& c : cases) {
        CAPTURE(c.name);
        const std::string clean =
            sec("pkg_inventory.packages", "full") + plus("Good", "pkg_inventory.packages");
        const V3Report r = parse_ok(header() + c.body + clean);
        // The clean section after the bad one always survives.
        const auto* good = find(r, "pkg_inventory.packages");
        REQUIRE(good != nullptr);
        CHECK(good->refusal == V3Refusal::kNone);
        REQUIRE(good->rows.size() == 1);
        CHECK(good->rows[0].name == "Good");
        // The refused section is present (so it can be nacked by facet), cleared, and named.
        const V3Section* bad = nullptr;
        for (const auto& s : r.sections) {
            if (s.refusal != V3Refusal::kNone)
                bad = &s;
        }
        REQUIRE(bad != nullptr);
        CHECK(bad->refusal == c.expect);
        CHECK(bad->rows.empty());
        CHECK(bad->deletions.empty());
        CHECK(bad->components.empty());
        CHECK_FALSE(v3_refusal_name(c.expect).empty());
    }
}

TEST_CASE("v3 duplicate facet: the first occurrence applies, only the later one is refused",
          "[server][inventory_blob_v3]") {
    const V3Report r = parse_ok(header() + sec(kApps, "full") + plus("First", kApps) +
                                sec(kApps, "full") + plus("Second", kApps));
    REQUIRE(r.sections.size() == 2);
    CHECK(r.sections[0].refusal == V3Refusal::kNone);
    REQUIRE(r.sections[0].rows.size() == 1);
    CHECK(r.sections[0].rows[0].name == "First");
    CHECK(r.sections[1].refusal == V3Refusal::kDuplicateFacet);
    CHECK(r.sections[1].rows.empty());
}

TEST_CASE(
    "v3 refusal stops at the section boundary: later records of a refused section are skipped",
    "[server][inventory_blob_v3]") {
    // The first bad record refuses the section; the rows after it must not resurrect it.
    const V3Report r = parse_ok(header() + sec(kApps, "full") + plus("A", kApps) +
                                plus("Bad", "pkg_inventory.packages") + plus("C", kApps));
    REQUIRE(r.sections.size() == 1);
    CHECK(r.sections[0].refusal == V3Refusal::kSourceMismatch);
    CHECK(r.sections[0].rows.empty());
}

TEST_CASE("v3 unattributable defects fail the whole blob", "[server][inventory_blob_v3]") {
    SECTION("a record before any section") {
        auto r = parse_v3_blob(header() + plus("A", kApps));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == V3ParseErrorKind::kRecordBeforeSection);
    }
    SECTION("a section header with no facet") {
        auto r = parse_v3_blob(header() + rec({"S", "", "full"}));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == V3ParseErrorKind::kBadSectionHeader);
    }
    SECTION("a section header whose facet is outside the label charset") {
        for (const char* bad : {"Installed_Apps", "a b", "a:b", "a/b", "x\xc3\xa9"}) {
            CAPTURE(bad);
            auto r = parse_v3_blob(header() + rec({"S", bad, "full"}));
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == V3ParseErrorKind::kBadSectionHeader);
        }
        auto r = parse_v3_blob(header() + rec({"S", std::string(kV3MaxFacetLen + 1, 'a'), "full"}));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == V3ParseErrorKind::kBadSectionHeader);
    }
    SECTION("a bare S record") {
        auto r = parse_v3_blob(header() + rec({"S"}));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == V3ParseErrorKind::kBadSectionHeader);
    }
}

TEST_CASE("v3 caps: sections, rows and blob bytes", "[server][inventory_blob_v3]") {
    SECTION("exactly kV3MaxSections sections parse; one more fails the whole blob") {
        std::string blob = header();
        for (std::size_t i = 0; i < kV3MaxSections; ++i)
            blob += sec("unknown_" + std::to_string(i), "full");
        const V3Report r = parse_ok(blob);
        CHECK(r.sections.size() == kV3MaxSections);
        blob += sec("unknown_over", "full");
        auto over = parse_v3_blob(blob);
        REQUIRE_FALSE(over.has_value());
        CHECK(over.error() == V3ParseErrorKind::kTooManySections);
    }
    SECTION("rows: kV3MaxRows in one section parse; the next row refuses its section only") {
        std::string rows;
        for (std::size_t i = 0; i < kV3MaxRows; ++i)
            rows += plus("n" + std::to_string(i), kApps);
        const std::string tail = sec("pkg_inventory.packages", "constrained");
        {
            const V3Report r = parse_ok(header() + sec(kApps, "full") + rows + tail);
            REQUIRE(r.sections.size() == 2);
            CHECK(r.sections[0].refusal == V3Refusal::kNone);
            CHECK(r.sections[0].rows.size() == kV3MaxRows);
        }
        {
            const V3Report r =
                parse_ok(header() + sec(kApps, "full") + rows + plus("one-too-many", kApps) + tail);
            REQUIRE(r.sections.size() == 2);
            CHECK(r.sections[0].refusal == V3Refusal::kRowCap);
            CHECK(r.sections[0].rows.empty());
            // The status-only section after it still parses.
            CHECK(r.sections[1].refusal == V3Refusal::kNone);
            CHECK(r.sections[1].status == V3Status::kConstrained);
        }
    }
    SECTION("rows are counted across sections in one call") {
        std::string a;
        for (std::size_t i = 0; i < kV3MaxRows; ++i)
            a += plus("n" + std::to_string(i), kApps);
        const V3Report r =
            parse_ok(header() + sec(kApps, "full") + a + sec("pkg_inventory.packages", "full") +
                     plus("Late", "pkg_inventory.packages"));
        REQUIRE(r.sections.size() == 2);
        CHECK(r.sections[0].refusal == V3Refusal::kNone);
        CHECK(r.sections[1].refusal == V3Refusal::kRowCap);
    }
    SECTION("a blob over kV3MaxBlobBytes is oversize") {
        std::string blob = header() + sec(kApps, "full");
        blob.append(kV3MaxBlobBytes - blob.size() + 1, 'x');
        REQUIRE(blob.size() == kV3MaxBlobBytes + 1);
        auto r = parse_v3_blob(blob);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == V3ParseErrorKind::kOversize);
    }
}

TEST_CASE("v3 field scrub and clamp match the v2 parser's contract",
          "[server][inventory_blob_v3]") {
    // Same vector as the agent/v2 drift guards (test_inventory_sync.cpp kScrubVectorRaw/Expected,
    // test_software_inventory_store.cpp): invalid UTF-8 becomes U+FFFD byte for byte.
    const std::string raw = std::string("X") + "\xc0\x80" + "\xed\xa0\x80" + "\xf4\x90\x80\x80" +
                            "\xc3\xa9" + "\xf0\x9f\x98\x80" + "\xf5";
    const std::string expected = std::string("X") + "\xef\xbf\xbd\xef\xbf\xbd" +
                                 "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" +
                                 "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" + "\xc3\xa9" +
                                 "\xf0\x9f\x98\x80" + "\xef\xbf\xbd";
    const auto name_of = [](const std::string& name) {
        const V3Report r = parse_ok(header() + sec(kApps, "full") + plus(name, kApps));
        REQUIRE(r.sections.size() == 1);
        REQUIRE(r.sections[0].rows.size() == 1);
        return r.sections[0].rows[0].name;
    };
    CHECK(name_of(raw) == expected);
    CHECK(name_of("Caf\xe9") == std::string("Caf\xef\xbf\xbd")); // cp1252 byte, the v2 UP-IN1 case

    // Clamp on a codepoint boundary, never mid-sequence: 1023 'a' + e-acute (2 bytes) is 1025.
    CHECK(name_of(std::string(1023, 'a') + "\xc3\xa9") == std::string(1023, 'a'));
    // Scrub BEFORE clamp: 400 invalid bytes scrub to 1200 bytes, then clamp to 1023 (341 x 3).
    const std::string clamped = name_of(std::string(400, '\xff'));
    CHECK(clamped.size() == 1023);
    CHECK(clamped.substr(0, 3) == "\xef\xbf\xbd");
    // An under-cap field is untouched.
    CHECK(name_of(std::string(kV3MaxFieldLen, 'b')) == std::string(kV3MaxFieldLen, 'b'));
    // The section header fields are scrubbed the same way.
    const V3Report r = parse_ok(header() + sec(kApps, "constrained", "", "tok\xe9"));
    CHECK(r.sections[0].token == std::string("tok\xef\xbf\xbd"));
}

TEST_CASE("v3 numeric diagnostics read as zero when they are not plain digits",
          "[server][inventory_blob_v3]") {
    // std::string, not const char*: a char pointer cannot carry an embedded NUL, and a NUL is the
    // one byte the digit loop and from_chars could both stop at.
    const std::vector<std::string> junk = {
        "", "-5", "+5", "1.5", "12x", "abc", " 7", "99999999999999999999",
    };
    for (const std::string& j : junk) {
        CAPTURE(j.size(), j);
        const V3Report r = parse_ok(header() + sec(kApps, "constrained", "", "", j, j));
        CHECK(r.sections[0].duration_ms == 0);
        CHECK(r.sections[0].bytes_read == 0);
        CHECK(r.sections[0].refusal == V3Refusal::kNone);
    }
    // A NUL anywhere in the header record refuses the section (the numerics read as zero).
    const std::vector<std::string> nul_junk = {
        std::string("12\0"
                    "3",
                    4),        // a NUL between digits
        std::string("\0", 1),  // a lone NUL
        std::string("5\0", 2), // a trailing NUL
        std::string("\0"
                    "5",
                    2), // a leading NUL
    };
    for (const std::string& j : nul_junk) {
        CAPTURE(j.size(), j);
        const V3Report r = parse_ok(header() + sec(kApps, "constrained", "", "", j, j));
        CHECK(r.sections[0].duration_ms == 0);
        CHECK(r.sections[0].bytes_read == 0);
        CHECK(r.sections[0].refusal == V3Refusal::kNulByte);
    }
}

TEST_CASE("v3 embedded NUL: a facet name fails the blob, a field of a record refuses its section",
          "[server][inventory_blob_v3]") {
    // A NUL inside a facet is outside the facet charset, so it is an unattributable defect (the
    // whole blob is refused) before the known-facet check could name it: it never reaches a
    // need_full string or a metric label.
    const std::string nul_mid = std::string("installed_apps") + '\0' + ".list_inventory";
    for (const std::string& bad : {nul_mid, std::string(1, '\0')}) {
        CAPTURE(bad.size());
        auto r = parse_v3_blob(header() + sec(bad, "full"));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == V3ParseErrorKind::kBadSectionHeader);
    }
    // A NUL inside a `+` field is valid UTF-8 and survives the scrub, but the store cannot keep
    // it (the text bound to Postgres has no NUL) while the hashes were taken over it, so the
    // section is refused (V3Refusal::kNulByte); the agent writer must never emit one.
    const std::string with_nul("A\0"
                               "B",
                               3);
    const V3Report r = parse_ok(header() + sec(kApps, "full") + plus(with_nul, kApps));
    REQUIRE(r.sections.size() == 1);
    CHECK(r.sections[0].refusal == V3Refusal::kNulByte);
    CHECK(r.sections[0].rows.empty());
}

TEST_CASE("v3 drops a 17th token and a nameless row", "[server][inventory_blob_v3]") {
    // A newer agent's extra token is dropped (as the v2 parser does); a nameless record is not a
    // row. A record short of the source slot fails the source check instead.
    std::string longer = plus("A", kApps);
    longer.pop_back();
    longer += kFs;
    longer += "extra";
    longer += kRs;
    std::string shorter = rec({"+", "B", "1"});
    const V3Report r = parse_ok(header() + sec(kApps, "full") + longer + plus("", kApps));
    REQUIRE(r.sections.size() == 1);
    CHECK(r.sections[0].refusal == V3Refusal::kNone);
    REQUIRE(r.sections[0].rows.size() == 1); // the nameless row is not a row
    CHECK(r.sections[0].rows[0].name == "A");
    CHECK(r.sections[0].rows[0].source == kApps);

    const V3Report s2 = parse_ok(header() + sec(kApps, "full") + shorter);
    REQUIRE(s2.sections.size() == 1);
    CHECK(s2.sections[0].refusal == V3Refusal::kSourceMismatch);
}

TEST_CASE("v3 empty records are skipped and a trailing record needs no terminator",
          "[server][inventory_blob_v3]") {
    std::string blob = header() + sec(kApps, "full");
    blob += kRs; // an empty record
    std::string last = plus("A", kApps);
    last.pop_back(); // unterminated final record
    const V3Report r = parse_ok(blob + last);
    REQUIRE(r.sections.size() == 1);
    CHECK(r.sections[0].rows.size() == 1);
}

TEST_CASE("v3 NUL: the refused section is cleared and later sections still apply",
          "[server][inventory_blob_v3]") {
    // Two names that differ only by a NUL would hash apart and store alike once the NUL is
    // dropped on the way to Postgres, so the whole section is refused instead.
    const V3Report r = parse_ok(header() + sec(kApps, "full") + plus("AB", kApps) +
                                plus(std::string("A\0B", 3), kApps) + sec("pkg_inventory.packages", "full") +
                                plus("Good", "pkg_inventory.packages"));
    REQUIRE(r.sections.size() == 2);
    CHECK(r.sections[0].refusal == V3Refusal::kNulByte);
    CHECK(r.sections[0].rows.empty()); // the clean row of the same section goes with it
    CHECK(v3_refusal_name(V3Refusal::kNulByte) == "nul_byte");
    CHECK(r.sections[1].refusal == V3Refusal::kNone);
    REQUIRE(r.sections[1].rows.size() == 1);
}

TEST_CASE("install_type_for: the source table is total over kSoftwareSources",
          "[server][install_type]") {
    for (const auto& src : software_catalog::kSoftwareSources) {
        CAPTURE(src.value);
        const auto t = install_type_for(src.value, "");
        CHECK_FALSE(t.empty());
        CHECK(is_install_type(t));
        // The source wins over a contradicting ecosystem.
        CHECK(install_type_for(src.value, "rpm") == t);
    }
    CHECK(install_type_for("installed_apps.list_inventory", "") == "installer");
    CHECK(install_type_for("pkg_inventory.managers", "") == "package_manager");
    CHECK(install_type_for("pkg_inventory.packages", "") == "package_manager");
    CHECK(install_type_for("pkg_inventory.store_packages", "") == "store");
    CHECK(install_type_for("windows_optional_features.list", "") == "optional_feature");
    CHECK(install_type_for("msi_packages.list_inventory", "") == "msi");
    CHECK(install_type_for("runtimes.python", "") == "runtime");
    CHECK(install_type_for("middleware.ibm_mq", "") == "middleware");
}

TEST_CASE("install_type_for: an empty or unknown source falls back by ecosystem",
          "[server][install_type]") {
    struct Row {
        const char* ecosystem;
        const char* expect;
    };
    for (const auto& r :
         {Row{"msi", "msi"}, Row{"optional_feature", "optional_feature"}, Row{"python", "runtime"},
          Row{"ibm_mq", "middleware"}, Row{"snap", "store"}, Row{"flatpak", "store"},
          Row{"brew", "package_manager"}, Row{"rpm", "package_manager"},
          Row{"deb", "package_manager"}, Row{"apk", "package_manager"},
          Row{"pacman", "package_manager"}, Row{"windows", "installer"}, Row{"macos", "installer"},
          Row{"macos_pkgutil", "installer"}, Row{"", ""}, Row{"made_up", ""}}) {
        CAPTURE(r.ecosystem);
        CHECK(install_type_for("", r.ecosystem) == r.expect);
        CHECK(install_type_for("some.future_source", r.ecosystem) == r.expect);
    }
}
