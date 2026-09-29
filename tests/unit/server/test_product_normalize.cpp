// product_normalize tests (ADR-0024 Decisions 6/7): deterministic title and
// vendor normalisation, the canonical norm_key shape, the strictly ordered
// match tiers (exact_norm → title_vendor → token_set → birth — no fuzzy
// matching), the effective-licence-state lapse derivation over the closed
// §3.2 vocabularies, and the expiry-alert constants.

#include <catch2/catch_test_macros.hpp>

#include "product_normalize.hpp"

#include <array>
#include <string>
#include <vector>

using yuzu::server::MatchResult;
using yuzu::server::MatchTier;
using yuzu::server::NormalizedTitle;
using yuzu::server::ProductCandidate;
using yuzu::server::effective_license_state;
using yuzu::server::is_lapsed;
using yuzu::server::kExpiryAlertBuckets;
using yuzu::server::kExpiryWarnDays;
using yuzu::server::kRearmSecs;
using yuzu::server::match_confidence;
using yuzu::server::match_product;
using yuzu::server::norm_key;
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
