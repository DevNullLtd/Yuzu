// Pure tests for the software-title alias pack parser (SAM.4): header directive,
// edition-bearing alias keys, validation errors, and the embedded seed contract.
// No database, no I/O.

#include <catch2/catch_test_macros.hpp>

#include "software_normalization_pack.hpp"

#include <algorithm>
#include <string>

using namespace yuzu::server;

namespace {

// A syntactically valid pack body of `rows` distinct rows (the parser's row floor is
// kMinSeedRows), plus any extra lines appended by the caller.
std::string pack(const std::string& version_line, const std::string& extra = {},
                 std::size_t rows = kMinSeedRows) {
    std::string out = version_line + "\n";
    for (std::size_t i = 0; i < rows; ++i)
        out += "rpm,filler" + std::string(1, static_cast<char>('a' + i / 26)) +
               std::string(1, static_cast<char>('a' + i % 26)) +
               ",,Acme,Filler,,other,\n";
    return out + extra;
}

const std::string kV = "#pack_version: 2026.11.1";

} // namespace

TEST_CASE("parse accepts the header directive and eight fields and normalises keys",
          "[normalization][pack]") {
    const auto p = parse_normalization_pack(
        pack(kV, "windows,7-Zip 23.01 (x64),Igor Pavlov Inc.,Igor Pavlov,7-Zip,,other,7-zip\n"));
    REQUIRE(p.has_value());
    CHECK(p->pack_version == "2026.11.1");
    CHECK(p->sha256.size() == 64);
    const auto it = std::find_if(p->rows.begin(), p->rows.end(),
                                 [](const PackRow& r) { return r.raw_name == "7-zip"; });
    REQUIRE(it != p->rows.end());
    CHECK(it->ecosystem == "windows");
    CHECK(it->raw_publisher == normalize_vendor("Igor Pavlov Inc."));
    CHECK(it->vendor == "igor pavlov");
    CHECK(it->title == "7-zip");
    CHECK(it->cpe_product == "7-zip");
    CHECK(it->norm_key == "igor pavlov:7-zip");
}

TEST_CASE("parse derives an edition-bearing alias key and alias_key is idempotent",
          "[normalization][pack]") {
    const auto p = parse_normalization_pack(pack(
        kV, "windows,Microsoft SQL Server 2019 Standard (x64),,Microsoft,SQL Server,,database,\n"
            "windows,Microsoft SQL Server 2017 Enterprise,,Microsoft,SQL Server,,database,\n"));
    REQUIRE(p.has_value());
    const auto find = [&](const std::string& key) {
        return std::find_if(p->rows.begin(), p->rows.end(),
                            [&](const PackRow& r) { return r.raw_name == key; });
    };
    const auto std_row = find("microsoft sql server standard");
    const auto ent_row = find("microsoft sql server enterprise");
    REQUIRE(std_row != p->rows.end());
    REQUIRE(ent_row != p->rows.end());
    CHECK(std_row->edition == "standard");
    CHECK(std_row->norm_key == "microsoft:sql server:standard");
    CHECK(ent_row->norm_key == "microsoft:sql server:enterprise"); // distinct SKUs, distinct products

    // Idempotence: re-normalising a key reproduces it.
    for (const auto& r : p->rows) {
        CAPTURE(r.raw_name);
        CHECK(alias_key(normalize_title(r.raw_name)) == r.raw_name);
    }
}

TEST_CASE("parse rejects an edition column that contradicts raw_name and accepts an editionless "
          "raw_name with an edition column",
          "[normalization][pack]") {
    const auto bad = parse_normalization_pack(
        pack(kV, "windows,Microsoft SQL Server 2019 Standard,,Microsoft,SQL Server,enterprise,"
                 "database,\n"));
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().find("edition contradicts raw_name") != std::string::npos);

    const auto ok = parse_normalization_pack(
        pack(kV, "windows,Microsoft Office,,Microsoft,Office,professional,other,\n"));
    REQUIRE(ok.has_value());
    const auto it = std::find_if(ok->rows.begin(), ok->rows.end(),
                                 [](const PackRow& r) { return r.raw_name == "microsoft office"; });
    REQUIRE(it != ok->rows.end());
    CHECK(it->edition == "professional");
    CHECK(it->norm_key == "microsoft:office:professional");

    const auto not_edition = parse_normalization_pack(
        pack(kV, "windows,Foo,,Acme,Foo,gold,other,\n"));
    CHECK_FALSE(not_edition.has_value());
}

TEST_CASE("parse rejects a missing or malformed pack_version directive", "[normalization][pack]") {
    CHECK_FALSE(parse_normalization_pack(pack("# no directive")).has_value());
    CHECK_FALSE(parse_normalization_pack(pack("#pack_version: 2026.1.1")).has_value());
    CHECK_FALSE(parse_normalization_pack(pack("#pack_version: v1")).has_value());
    const auto twice = parse_normalization_pack(pack(kV, "#pack_version: 2026.11.2\n"));
    REQUIRE_FALSE(twice.has_value());
    CHECK(twice.error().find("duplicate") != std::string::npos);
}

TEST_CASE("parse rejects a row with the wrong field count", "[normalization][pack]") {
    const auto few = parse_normalization_pack(pack(kV, "windows,Foo,,Acme,Foo,,other\n"));
    REQUIRE_FALSE(few.has_value());
    CHECK(few.error().find("8 fields") != std::string::npos);
    CHECK_FALSE(
        parse_normalization_pack(pack(kV, "windows,Foo,,Acme,Foo,,other,x,extra\n")).has_value());
    CHECK_FALSE(
        parse_normalization_pack(pack(kV, "windows,\"Foo\",,Acme,Foo,,other,\n")).has_value());
}

TEST_CASE("parse rejects an unknown category and an unknown ecosystem", "[normalization][pack]") {
    CHECK_FALSE(parse_normalization_pack(pack(kV, "windows,Foo,,Acme,Foo,,gadget,\n")).has_value());
    CHECK_FALSE(parse_normalization_pack(pack(kV, "plan9,Foo,,Acme,Foo,,other,\n")).has_value());
    CHECK_FALSE(parse_normalization_pack(pack(kV, "windows,Foo,,Acme,Foo,,other,BAD TOKEN\n"))
                    .has_value());
    // An empty category defaults to other.
    const auto ok = parse_normalization_pack(pack(kV, "windows,Foo,,Acme,Foo,,,\n"));
    REQUIRE(ok.has_value());
    CHECK(ok->rows.back().category == "other");
}

TEST_CASE("parse rejects a duplicate normalised key", "[normalization][pack]") {
    const auto dup = parse_normalization_pack(
        pack(kV, "windows,Foo 1.0,,Acme,Foo,,other,\nwindows,Foo 2.0 (x64),,Acme,Foo,,other,\n"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(dup.error().find("duplicate") != std::string::npos);
    // Same name under another ecosystem or publisher is a different key.
    CHECK(parse_normalization_pack(
              pack(kV, "windows,Foo,,Acme,Foo,,other,\nmacos,Foo,,Acme,Foo,,other,\n"
                       "windows,Foo,Acme,Acme,Foo,,other,\n"))
              .has_value());
}

TEST_CASE("parse rejects fewer than kMinSeedRows rows", "[normalization][pack]") {
    const auto thin = parse_normalization_pack(pack(kV, {}, kMinSeedRows - 1));
    REQUIRE_FALSE(thin.has_value());
    CHECK(thin.error().find("kMinSeedRows") != std::string::npos);
    CHECK(parse_normalization_pack(pack(kV, {}, kMinSeedRows)).has_value());
}

TEST_CASE("purl_type_for maps package ecosystems and leaves app ecosystems empty",
          "[normalization][pack]") {
    CHECK(purl_type_for("rpm") == "rpm");
    CHECK(purl_type_for("deb") == "deb");
    CHECK(purl_type_for("apk") == "apk");
    CHECK(purl_type_for("pacman") == "alpm");
    CHECK(purl_type_for("brew") == "brew");
    for (const char* eco : {"windows", "msi", "macos", "macos_pkgutil", "snap", "flatpak",
                            "optional_feature", ""})
        CHECK(purl_type_for(eco).empty());
}

TEST_CASE("the embedded seed parses with the shipped version and every key in normal form",
          "[normalization][pack]") {
    const auto p = parse_normalization_pack(kSoftwareNormalizationSeed);
    REQUIRE(p.has_value());
    CHECK(p->pack_version == "2026.11.1");
    CHECK(p->rows.size() >= kMinSeedRows);
    for (const auto& r : p->rows) {
        CAPTURE(r.raw_name);
        CHECK(alias_key(normalize_title(r.raw_name)) == r.raw_name); // keys are in normal form
    }
}
