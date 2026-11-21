// product_normalize tests (ADR-0024 Decisions 6/7): deterministic title and
// vendor normalisation, the canonical norm_key shape, the strictly ordered
// match tiers (exact_norm → title_vendor → token_set → birth — no fuzzy
// matching), the effective-licence-state lapse derivation over the closed
// §3.2 vocabularies, and the expiry-alert constants.

#include <catch2/catch_test_macros.hpp>

#include "product_normalize.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

using yuzu::server::MatchResult;
using yuzu::server::MatchTier;
using yuzu::server::NormalizedTitle;
using yuzu::server::ProductCandidate;
using yuzu::server::effective_license_state;
using yuzu::server::is_lapsed;
using yuzu::server::kExpiryAlertBuckets;
using yuzu::server::kExpiryWarnDays;
using yuzu::server::kRearmSecs;
using yuzu::server::make_norm_key;
using yuzu::server::match_confidence;
using yuzu::server::match_product;
using yuzu::server::norm_key;
using yuzu::server::normalize_edition;
using yuzu::server::normalize_title;
using yuzu::server::normalize_vendor;

TEST_CASE("normalize_title lowercases, collapses whitespace, strips version/arch tokens",
          "[normalize]") {
    SECTION("ASCII lowercase + whitespace collapse") {
        CHECK(normalize_title("Microsoft Office").title == "microsoft office");
        CHECK(normalize_title("  Google\t\tChrome  ").title == "google chrome");
        CHECK(normalize_title("").title == "");
    }

    SECTION("standalone version-ish tokens are stripped") {
        CHECK(normalize_title("Microsoft Office 2019").title == "microsoft office");
        CHECK(normalize_title("Acme Tool 16.0.1").title == "acme tool");
        CHECK(normalize_title("Thing v2.1").title == "thing");
        CHECK(normalize_title("Python 3").title == "python");
    }

    SECTION("embedded digits are NOT version tokens") {
        CHECK(normalize_title("7-Zip 23.01").title == "7-zip");
        CHECK(normalize_title("Notepad++ 8.6").title == "notepad++");
        // a bare 'v' carries no digits and is kept
        CHECK(normalize_title("v").title == "v");
    }

    SECTION("architecture tokens are stripped, wrapping punctuation tolerated") {
        CHECK(normalize_title("Google Chrome x64").title == "google chrome");
        CHECK(normalize_title("Acme App (64-bit)").title == "acme app");
        CHECK(normalize_title("Tool amd64 arm64 x86_64").title == "tool");
        CHECK(normalize_title("Editor 32-bit i686").title == "editor");
    }

    SECTION("no edition token → empty edition") {
        CHECK(normalize_title("Google Chrome x64").edition == "");
    }
}

TEST_CASE("normalize_title returns the first stripped version token as version", "[normalize]") {
    CHECK(normalize_title("7-Zip 23.01 (x64)").version == "23.01");
    CHECK(normalize_title("Visual Studio v2.1 2019").version == "2.1");
    CHECK(normalize_title("Mozilla Firefox 120.0.1").title == "mozilla firefox");
}

TEST_CASE("normalize_title leaves version empty when the title carries none", "[normalize]") {
    CHECK(normalize_title("Mozilla Firefox").version.empty());
    CHECK(normalize_title("v").version.empty());
}

TEST_CASE("normalize_title extracts edition tokens", "[normalize]") {
    SECTION("edition is removed from the title and returned separately") {
        const NormalizedTitle nt = normalize_title("Microsoft Office Professional 2019 (64-bit)");
        CHECK(nt.title == "microsoft office");
        CHECK(nt.edition == "professional");
    }

    SECTION("each vocabulary token is recognised") {
        CHECK(normalize_title("Visual Studio Community 2022").edition == "community");
        CHECK(normalize_title("Windows 11 Pro").edition == "pro");
        CHECK(normalize_title("Windows Server 2022 Datacenter").edition == "datacenter");
        CHECK(normalize_title("SQL Server 2019 Express").edition == "express");
    }

    SECTION("the FIRST edition token wins; later ones are dropped from the title") {
        const NormalizedTitle nt = normalize_title("SQL Server Standard Enterprise");
        CHECK(nt.title == "sql server");
        CHECK(nt.edition == "standard");
    }
}

TEST_CASE("normalize_title passes non-ASCII bytes through untouched", "[normalize]") {
    const NormalizedTitle jp = normalize_title("一太郎 2024");
    CHECK(jp.title == "一太郎");
    CHECK(jp.edition == "");

    // ASCII letters still lowercase around multi-byte sequences.
    const NormalizedTitle mixed = normalize_title("Café Suite PRO x64");
    CHECK(mixed.title == "café suite");
    CHECK(mixed.edition == "pro");
}

TEST_CASE("normalize_vendor strips legal suffixes and applies aliases", "[normalize]") {
    SECTION("legal-suffix stripping") {
        CHECK(normalize_vendor("Microsoft Corporation") == "microsoft");
        CHECK(normalize_vendor("Adobe Inc.") == "adobe");
        CHECK(normalize_vendor("Example Software Ltd.") == "example");
        CHECK(normalize_vendor("Mozilla Foundation") == "mozilla");
        CHECK(normalize_vendor("Acme Technologies LLC") == "acme");
        CHECK(normalize_vendor("Beispiel GmbH") == "beispiel");
    }

    SECTION("comma trimming + suffix + alias compose") {
        CHECK(normalize_vendor("Oracle America, Inc.") == "oracle");
        CHECK(normalize_vendor("VMware, Inc.") == "vmware");
    }

    SECTION("alias table maps well-known forms to one canonical vendor") {
        CHECK(normalize_vendor("Adobe Systems Incorporated") == "adobe");
        CHECK(normalize_vendor("JetBrains s.r.o.") == "jetbrains");
        CHECK(normalize_vendor("VMware by Broadcom") == "vmware");
    }

    SECTION("unlisted vendors pass through lowercased/collapsed") {
        CHECK(normalize_vendor("Igor Pavlov") == "igor pavlov");
        CHECK(normalize_vendor("  Some   Vendor  ") == "some vendor");
    }
}

TEST_CASE("an agent origin label (via:<ecosystem>) is no vendor", "[normalize][vendor]") {
    CHECK(yuzu::server::kOriginLabelPrefix == "via:");
    SECTION("normalize_vendor returns empty for every label") {
        for (const char* label : {"via:brew", "via:snap", "via:flatpak", "via:deb", "via:rpm",
                                  "via:macos_pkgutil", "via:", "via:Microsoft"})
            CHECK(normalize_vendor(label).empty());
    }
    SECTION("a labelled title keys exactly like a vendorless one") {
        CHECK(norm_key("Foo", "via:snap") == norm_key("Foo", ""));
        CHECK(norm_key("Foo", "via:brew") == norm_key("Foo", "via:snap"));
        // ...and not like one with a real vendor
        CHECK(norm_key("Foo", "via:snap") != norm_key("Foo", "Acme"));
    }
    SECTION("only a RAW prefix counts: case-sensitive, exact, at byte 0") {
        // the agent emits the label in lower case, so these are vendors and normalise as such
        CHECK(normalize_vendor("VIA:Acme") == "via:acme");
        CHECK(normalize_vendor("Via:Acme") == "via:acme");
        // a vendor merely containing "via:" is not a label
        CHECK(normalize_vendor("Acme via:brew") == "acme via:brew");
        CHECK(normalize_vendor(" via:brew") == "via:brew"); // leading blank: not the raw prefix
        CHECK(normalize_vendor("via") == "via");
        CHECK(normalize_vendor("Viacom Inc.") == "viacom");
    }
}

TEST_CASE("norm_key is deterministic and stable across raw form variants", "[normalize]") {
    // Key shape: <vendor>:<title> with an optional :<edition> suffix.
    const std::string k =
        norm_key("Microsoft Office Professional 2019 x64", "Microsoft Corporation");
    CHECK(k == "microsoft:microsoft office:professional");

    SECTION("different raw spellings of the same product mint the same key") {
        CHECK(norm_key("Microsoft  Office  Professional v16.0 (64-bit)",
                       "MICROSOFT CORPORATION") == k);
    }

    SECTION("no edition → no suffix") {
        CHECK(norm_key("Google Chrome 119 x64", "Google LLC") == "google:google chrome");
    }

    SECTION("repeated calls agree") {
        CHECK(norm_key("7-Zip 23.01", "Igor Pavlov") == norm_key("7-Zip 23.01", "Igor Pavlov"));
    }

    SECTION("make_norm_key owns the shape norm_key ends in") {
        CHECK(make_norm_key("microsoft", "microsoft office", "professional") == k);
        CHECK(make_norm_key("google", "google chrome", "") == "google:google chrome");
    }
}

namespace {
// Shared candidate fixture: two editions of one product plus an unrelated
// vendor's row.
std::vector<ProductCandidate> candidates() {
    return {
        {"microsoft:microsoft office:professional", "microsoft office", "microsoft"},
        {"microsoft:microsoft office:standard", "microsoft office", "microsoft"},
        {"adobe:acrobat", "acrobat", "adobe"},
    };
}
} // namespace

TEST_CASE("match_product evaluates tiers in strict order", "[normalize]") {
    const auto cands = candidates();

    SECTION("tier 1: exact_norm on the full norm_key, confidence 1.0") {
        const MatchResult r =
            match_product("Microsoft Office Professional 2019", "Microsoft Corporation", cands);
        CHECK(r.tier == MatchTier::exact_norm);
        CHECK(r.norm_key == "microsoft:microsoft office:professional");
        CHECK(r.confidence == 1.0);
    }

    SECTION("tier 2: title_vendor relates editions of one product, confidence 0.9") {
        // "ultimate" mints a key no candidate carries; title+vendor still match.
        const MatchResult r =
            match_product("Microsoft Office Ultimate 2019", "Microsoft Corporation", cands);
        CHECK(r.tier == MatchTier::title_vendor);
        CHECK(r.norm_key == "microsoft:microsoft office:professional"); // lexicographic tie-break
        CHECK(r.confidence == 0.9);
    }

    SECTION("tier 3: token_set is order-insensitive, confidence 0.8") {
        // Equal token multisets in a different order: not tier 2, matches tier 3.
        const MatchResult r = match_product("Office Microsoft", "Microsoft Corporation", cands);
        CHECK(r.tier == MatchTier::token_set);
        CHECK(r.norm_key == "microsoft:microsoft office:professional");
        CHECK(r.confidence == 0.8);
    }

    SECTION("tier 3: subset works in both directions") {
        // Raw superset of the candidate tokens…
        CHECK(match_product("Microsoft Office Plus", "Microsoft Corporation", cands).tier ==
              MatchTier::token_set);
        // …and raw subset of a candidate's tokens.
        const std::vector<ProductCandidate> wide = {
            {"adobe:adobe acrobat reader dc", "adobe acrobat reader dc", "adobe"}};
        CHECK(match_product("Acrobat Reader", "Adobe Inc.", wide).tier == MatchTier::token_set);
    }

    SECTION("token_set requires the SAME vendor") {
        CHECK(match_product("Microsoft Office Plus", "Adobe Inc.", cands).tier ==
              MatchTier::birth);
    }

    SECTION("birth: no candidate matches → empty key, confidence 0.0") {
        const MatchResult r = match_product("Blender", "Blender Foundation", cands);
        CHECK(r.tier == MatchTier::birth);
        CHECK(r.norm_key == "");
        CHECK(r.confidence == 0.0);
    }

    SECTION("an empty normalised title never matches by token_set") {
        // The raw title normalises to nothing (version + arch only).
        CHECK(match_product("2019 x64", "Microsoft Corporation", cands).tier ==
              MatchTier::birth);
    }

    SECTION("empty candidate set → birth") {
        CHECK(match_product("Anything", "Anyone", {}).tier == MatchTier::birth);
    }
}

TEST_CASE("match_product tie-break is deterministic regardless of candidate order",
          "[normalize]") {
    const ProductCandidate first{"microsoft:microsoft office:professional", "microsoft office",
                                 "microsoft"};
    const ProductCandidate second{"microsoft:microsoft office:standard", "microsoft office",
                                  "microsoft"};

    const MatchResult fwd =
        match_product("Microsoft Office Plus", "Microsoft Corporation", {first, second});
    const MatchResult rev =
        match_product("Microsoft Office Plus", "Microsoft Corporation", {second, first});
    CHECK(fwd.tier == MatchTier::token_set);
    CHECK(fwd.norm_key == rev.norm_key);
    CHECK(fwd.norm_key == "microsoft:microsoft office:professional");

    SECTION("a stronger tier always beats a weaker one, whatever the order") {
        // `second` would match tier 2 for this raw form; an exact key match on
        // `first` must win even when listed last.
        const MatchResult r = match_product("Microsoft Office Professional",
                                            "Microsoft Corporation", {second, first});
        CHECK(r.tier == MatchTier::exact_norm);
        CHECK(r.norm_key == "microsoft:microsoft office:professional");
    }
}

TEST_CASE("match_confidence covers all four tiers", "[normalize]") {
    CHECK(match_confidence(MatchTier::exact_norm) == 1.0);
    CHECK(match_confidence(MatchTier::title_vendor) == 0.9);
    CHECK(match_confidence(MatchTier::token_set) == 0.8);
    CHECK(match_confidence(MatchTier::birth) == 0.0);
}

TEST_CASE("effective_license_state derives lapse against server-now", "[normalize]") {
    SECTION("subscription_active past expiry → expired") {
        CHECK(effective_license_state("subscription_active", "subscription", 100, 200) ==
              "expired");
        CHECK(effective_license_state("subscription_active", "subscription", 300, 200) ==
              "subscription_active");
    }

    SECTION("expiry boundary: exactly-now counts as passed") {
        CHECK(effective_license_state("subscription_active", "subscription", 200, 200) ==
              "expired");
    }

    SECTION("grace past expiry → expired") {
        CHECK(effective_license_state("grace", "volume", 100, 200) == "expired");
        CHECK(effective_license_state("grace", "volume", 300, 200) == "grace");
    }

    SECTION("trial past expiry → expired") {
        CHECK(effective_license_state("trial", "trial", 100, 200) == "expired");
    }

    SECTION("any state with a passed expiry lapses — including licensed") {
        CHECK(effective_license_state("licensed", "retail", 100, 200) == "expired");
    }

    SECTION("expiry 0 never lapses: licensed / perpetual stay put") {
        CHECK(effective_license_state("licensed", "retail", 0, 200) == "licensed");
        CHECK(effective_license_state("licensed", "perpetual", 0, 9'000'000'000) == "licensed");
    }

    SECTION("terminal states pass through") {
        CHECK(effective_license_state("expired", "subscription", 0, 0) == "expired");
        CHECK(effective_license_state("unlicensed", "unknown", 0, 0) == "unlicensed");
    }

    SECTION("unknown-preserving: unknown stays unknown even past expiry") {
        CHECK(effective_license_state("unknown", "unknown", 100, 200) == "unknown");
    }

    SECTION("inputs outside the closed vocabulary → unknown (case-sensitive)") {
        CHECK(effective_license_state("banana", "perpetual", 0, 0) == "unknown");
        CHECK(effective_license_state("Licensed", "retail", 0, 0) == "unknown");
        CHECK(effective_license_state("", "", 0, 0) == "unknown");
    }

    SECTION("lapse rule: effective state ∈ {expired, unlicensed}") {
        CHECK(is_lapsed("expired"));
        CHECK(is_lapsed("unlicensed"));
        CHECK_FALSE(is_lapsed("licensed"));
        CHECK_FALSE(is_lapsed("grace"));
        CHECK_FALSE(is_lapsed("unknown"));
    }
}

TEST_CASE("expiry alert constants", "[normalize]") {
    CHECK(kExpiryWarnDays == 30);
    CHECK(kExpiryAlertBuckets == std::array<int, 4>{30, 14, 7, 1});
    CHECK(kRearmSecs == 7 * 24 * 3600);
    CHECK(kRearmSecs == 604800);
}

// -- SAM-51: the normaliser defects found by the S-2 proxy -----------------------------------
//
// tests/unit/fixtures/software-estate/normaliser/s2_cases.tsv holds the real titles and vendors
// (provenance.txt next to it says where each came from) with the output each must give. A row
// per defect 1 to 7 plus controls for the neighbouring forms that must not move.

namespace {

struct S2Row {
    std::string kind; ///< "title" or "vendor"
    std::string input;
    std::string want; ///< the normalised title, or the normalised vendor
    std::string want_edition;
    std::string want_version;
    int defect{};     ///< 1 to 7, or 0 for a control
    std::size_t line{};
};

// kind, input, want, want_edition, want_version, defect; `#` lines and blank lines are skipped.
const std::vector<S2Row>& s2_rows() {
    static const std::vector<S2Row> rows = [] {
        std::vector<S2Row> out;
        const auto path = std::filesystem::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" /
                          "normaliser" / "s2_cases.tsv";
        std::ifstream in(path);
        REQUIRE(in.is_open());
        std::string line;
        std::size_t n = 0;
        while (std::getline(in, line)) {
            ++n;
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (line.empty() || line.front() == '#')
                continue;
            std::vector<std::string> f;
            std::size_t pos = 0;
            for (;;) {
                const auto tab = line.find('\t', pos);
                f.push_back(line.substr(pos, tab == std::string::npos ? tab : tab - pos));
                if (tab == std::string::npos)
                    break;
                pos = tab + 1;
            }
            REQUIRE(f.size() == 6);
            REQUIRE((f[0] == "title" || f[0] == "vendor"));
            out.push_back({f[0], f[1], f[2], f[3], f[4], std::stoi(f[5]), n});
        }
        return out;
    }();
    return rows;
}

} // namespace

TEST_CASE("every S-2 fixture row normalises to its expected title, edition, version or vendor",
          "[normalize][s2]") {
    for (const auto& r : s2_rows()) {
        CAPTURE(r.line, r.input, r.defect);
        if (r.kind == "title") {
            const NormalizedTitle nt = normalize_title(r.input);
            CHECK(nt.title == r.want);
            CHECK(nt.edition == r.want_edition);
            CHECK(nt.version == r.want_version);
        } else {
            CHECK(normalize_vendor(r.input) == r.want);
        }
    }
}

TEST_CASE("the S-2 fixture holds a row for each of the defects 1 to 7 and for the controls",
          "[normalize][s2]") {
    std::set<int> defects;
    for (const auto& r : s2_rows())
        defects.insert(r.defect);
    for (int d = 0; d <= 7; ++d)
        CHECK(defects.count(d) == 1);
    CHECK(s2_rows().size() >= 30);
}

TEST_CASE("normalize_title is idempotent on its own output for every S-2 title row",
          "[normalize][s2]") {
    for (const auto& r : s2_rows()) {
        if (r.kind != "title")
            continue;
        CAPTURE(r.line, r.input);
        const std::string once = normalize_title(r.input).title;
        CHECK(normalize_title(once).title == once);
    }
}

TEST_CASE("normalize_vendor never returns empty for a non-empty input that is not an origin "
          "label",
          "[normalize][s2]") {
    std::vector<std::string> inputs;
    for (const auto& r : s2_rows())
        if (r.kind == "vendor")
            inputs.push_back(r.input);
    // Names made only of legal-suffix words: the last token is never stripped.
    for (const char* v : {"Inc.", "Software", "Ltd. Inc.", "Corp Corporation", "Foundation",
                          "Co.", "Company Technologies Software Systems"})
        inputs.emplace_back(v);
    for (const auto& v : inputs) {
        CAPTURE(v);
        CHECK_FALSE(normalize_vendor(v).empty());
    }
    // An origin label is still no vendor, and blank input stays blank.
    CHECK(normalize_vendor("via:brew").empty());
    CHECK(normalize_vendor("   ").empty());
}

TEST_CASE("an edition word is an edition only after a title word", "[normalize][s2]") {
    SECTION("after a kept token it is still an edition") {
        const NormalizedTitle nt = normalize_title("Windows 11 Pro");
        CHECK(nt.title == "windows");
        CHECK(nt.edition == "pro");
    }
    SECTION("a leading edition word is a title word and never leaves the title empty") {
        for (const char* raw : {"Home", "Pro", "Professional", "Express 2019 (x64)", "STANDARD"}) {
            CAPTURE(raw);
            const NormalizedTitle nt = normalize_title(raw);
            CHECK_FALSE(nt.title.empty());
            CHECK(nt.edition.empty());
        }
    }
    SECTION("the first edition word after a title word wins; a later one is dropped") {
        const NormalizedTitle nt = normalize_title("Home Pro Enterprise");
        CHECK(nt.title == "home");
        CHECK(nt.edition == "pro");
    }
    SECTION("the word 'edition' is dropped only right after an architecture or edition word") {
        CHECK(normalize_title("Studio Pro Edition").title == "studio");
        CHECK(normalize_title("Studio (64-bit edition)").title == "studio");
        CHECK(normalize_title("Collector's Edition Pack").title == "collector's edition pack");
    }
}

TEST_CASE("a standalone dash is dropped and a dashed word is kept", "[normalize][s2]") {
    CHECK(normalize_title("Tool - Extras").title == "tool extras");
    CHECK(normalize_title("Tool - 1.2").title == "tool");
    CHECK(normalize_title("-").title.empty());
    CHECK(normalize_title("7-Zip e-mail x-ray").title == "7-zip e-mail x-ray");
}

TEST_CASE("name@version sets the version only when none was seen earlier", "[normalize][s2]") {
    SECTION("a formula token keeps its name and supplies the version") {
        const NormalizedTitle nt = normalize_title("openssl@3");
        CHECK(nt.title == "openssl");
        CHECK(nt.version == "3");
        CHECK(normalize_title("Node@v18.2").version == "18.2");
    }
    SECTION("an earlier version wins, a later one is dropped") {
        const NormalizedTitle nt = normalize_title("Acme 2.0 tool@3");
        CHECK(nt.title == "acme tool");
        CHECK(nt.version == "2.0");
        CHECK(normalize_title("tool@3 2.0").version == "3");
    }
    SECTION("an @ without a version-shaped tail, or with two @, is left alone") {
        CHECK(normalize_title("user@example.com").title == "user@example.com");
        CHECK(normalize_title("a@b@3").title == "a@b@3");
        CHECK(normalize_title("name@").title == "name@");
        CHECK(normalize_title("@3").title == "@3");
    }
    SECTION("the name part is classified like any token, so the result is idempotent") {
        for (const char* raw : {"x64@3", "pro@3", "foo pro@3", "1@2", "(openssl@3)"}) {
            CAPTURE(raw);
            const std::string once = normalize_title(raw).title;
            CHECK(normalize_title(once).title == once);
        }
    }
}

TEST_CASE("a year range stays in the title and is never the version", "[normalize][s2]") {
    const NormalizedTitle nt = normalize_title("Microsoft Visual C++ 2015-2022 Redistributable (x64)");
    CHECK(nt.title == "microsoft visual c++ 2015-2022 redistributable");
    CHECK(nt.version.empty());
    CHECK(normalize_title("Foo 2015-2022 Bar").version.empty());
    // A single year still reads as the version (filed, not changed here).
    CHECK(normalize_title("Microsoft Visual C++ 2013 Redistributable").version == "2013");
}

TEST_CASE("only a trailing run of legal-suffix words is stripped and the last token survives",
          "[normalize][s2]") {
    CHECK(normalize_vendor("Example Software Foundation Inc.") == "example");
    CHECK(normalize_vendor("Software Inc.") == "software");
    CHECK(normalize_vendor("Inc. Ltd.") == "inc.");
    CHECK(normalize_vendor("Acme Technologies Software Systems") == "acme");
    CHECK(normalize_vendor("Systems Acme") == "systems acme"); // a leading suffix word is a name
    CHECK(normalize_vendor("Example L.L.C.") == "example");
    // The alias table is still consulted on the stripped form.
    CHECK(normalize_vendor("Oracle America, Inc.") == "oracle");
}

TEST_CASE("compound legal forms are not reduced; kg, co and & are not suffix words",
          "[normalize][s2]") {
    CHECK(normalize_vendor("Example Software GmbH & Co. KG") == "example software gmbh & co. kg");
    CHECK(normalize_vendor("Example KG") == "example kg");
    CHECK(normalize_vendor("Example Co") == "example co");
    CHECK(normalize_vendor("Example S.A.S.") == "example s.a.s.");
}

TEST_CASE("normalize_edition reads an edition column and refuses any other word",
          "[normalize][s2]") {
    CHECK(normalize_edition("Standard") == "standard");
    CHECK(normalize_edition("  PRO ") == "pro");
    CHECK(normalize_edition("Home") == "home");
    CHECK(normalize_edition("Enterprise x64") == "enterprise");
    CHECK(normalize_edition("2019 Standard") == "standard");
    CHECK(normalize_edition("standard enterprise") == "standard"); // the first wins
    CHECK(normalize_edition("").empty());
    CHECK(normalize_edition("   ").empty());
    CHECK(normalize_edition("2019").empty());
    CHECK(normalize_edition("gold").empty());
    CHECK(normalize_edition("Standard Edition").empty());
    CHECK(normalize_edition("Pro Display").empty());
}
