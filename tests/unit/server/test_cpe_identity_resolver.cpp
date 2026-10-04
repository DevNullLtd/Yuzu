/// @file test_cpe_identity_resolver.cpp
/// PURE unit tests for PR 3 — CpeIdentityResolver + cpe_normalize primitives.
/// Every test uses the explicit-CSV test-seam ctor (no embed / no IO / no PG)
/// or exercises the header-only cpe_normalize helpers directly. Tag: [cpe].

#include "cpe_identity_resolver.hpp"
#include "cpe_normalize.hpp"
#include "software_inventory_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

using namespace yuzu::server;

namespace {

// The 13 seed rows — every test-seam resolver must carry at least
// kMinCuratedRows (13) valid rows or the fail-closed ctor throws. Tests that
// need extra rows append them to this base.
constexpr std::string_view kSeed =
    ",,openssl,openssl,openssl\n"
    ",,openssh-server,openbsd,openssh\n"
    ",,openssh-client,openbsd,openssh\n"
    ",,curl,curl,curl\n"
    ",,libssl3,openssl,openssl\n"
    ",,libssl1.1,openssl,openssl\n"
    ",,libcurl4,curl,curl\n"
    ",,bash,gnu,bash\n"
    ",,glibc,gnu,glibc\n"
    ",,libc6,gnu,glibc\n"
    ",,sudo,sudo_project,sudo\n"
    ",,nginx,nginx,nginx\n"
    ",,wget,gnu,wget\n";

std::string seed_plus(std::string_view extra) {
    std::string s(kSeed);
    s += extra;
    return s;
}

// The seed minus its last row (wget) — exactly kMinCuratedRows - 1 = 12 rows.
constexpr std::string_view kTwelveRows =
    ",,openssl,openssl,openssl\n"
    ",,openssh-server,openbsd,openssh\n"
    ",,openssh-client,openbsd,openssh\n"
    ",,curl,curl,curl\n"
    ",,libssl3,openssl,openssl\n"
    ",,libssl1.1,openssl,openssl\n"
    ",,libcurl4,curl,curl\n"
    ",,bash,gnu,bash\n"
    ",,glibc,gnu,glibc\n"
    ",,libc6,gnu,glibc\n"
    ",,sudo,sudo_project,sudo\n"
    ",,nginx,nginx,nginx\n";

SoftwareEntry pkg(std::string name, std::string version, std::string eco,
                  std::string distro_id = "", std::string kind = "package") {
    SoftwareEntry e;
    e.name = std::move(name);
    e.version = std::move(version);
    e.ecosystem = std::move(eco);
    e.distro_id = std::move(distro_id);
    e.kind = std::move(kind);
    return e;
}

} // namespace

TEST_CASE("os-native lanes are not-assessed with no identity work", "[cpe]") {
    CpeIdentityResolver r{kSeed};

    SoftwareEntry win = pkg("Google Chrome", "120.0", "windows", "", "app");
    SoftwareEntry mac = pkg("Safari", "17.0", "macos", "", "app");
    SoftwareEntry brew = pkg("wget", "1.21", "brew", "", "pkg");
    SoftwareEntry cask = pkg("iterm2", "3.5", "brew", "", "app");
    SoftwareEntry receipt = pkg("com.apple.pkg.CLTools_Executables", "15.0", "macos_pkgutil", "", "pkg");
    SoftwareEntry feat = pkg("NetFx3", "enabled", "optional_feature", "", "feat");

    for (const SoftwareEntry* e : {&win, &mac, &brew, &cask, &receipt, &feat}) {
        auto id = r.resolve(*e);
        REQUIRE(id.outcome == IdentityOutcome::NotAssessed);
        REQUIRE(id.not_assessed_reason == std::string(kReasonOsNative));
        REQUIRE(id.cpe_product.empty());
        REQUIRE(id.cpe_vendor.empty());
        REQUIRE_FALSE(id.exact_product);
    }
}

TEST_CASE("unsupported ecosystem is not-assessed", "[cpe]") {
    CpeIdentityResolver r{kSeed};

    auto empty_eco = r.resolve(pkg("openssl", "1.1.1", ""));
    REQUIRE(empty_eco.outcome == IdentityOutcome::NotAssessed);
    REQUIRE(empty_eco.not_assessed_reason == std::string(kReasonUnsupportedEcosystem));

    auto pypi = r.resolve(pkg("requests", "2.0", "pypi"));
    REQUIRE(pypi.outcome == IdentityOutcome::NotAssessed);
    REQUIRE(pypi.not_assessed_reason == std::string(kReasonUnsupportedEcosystem));
}

TEST_CASE("empty name is no-identity", "[cpe]") {
    CpeIdentityResolver r{kSeed};
    auto id = r.resolve(pkg("", "1.0", "deb"));
    REQUIRE(id.outcome == IdentityOutcome::NoIdentity);
    REQUIRE(id.not_assessed_reason == std::string(kReasonNoIdentity));
}

TEST_CASE("empty version is no-version, checked before the curated map", "[cpe]") {
    CpeIdentityResolver r{kSeed};
    // A curated `openssl` with an empty version must NOT resolve to a High hit.
    auto id = r.resolve(pkg("openssl", "", "rpm"));
    REQUIRE(id.outcome == IdentityOutcome::NoVersion);
    REQUIRE(id.not_assessed_reason == std::string(kReasonNoVersion));
    REQUIRE(id.cpe_product.empty());
}

TEST_CASE("curated hit resolves to exact product, high confidence", "[cpe]") {
    CpeIdentityResolver r{kSeed};

    auto rpm_openssl = r.resolve(pkg("openssl", "1.1.1", "rpm"));
    REQUIRE(rpm_openssl.outcome == IdentityOutcome::Resolved);
    REQUIRE(rpm_openssl.cpe_product == "openssl");
    REQUIRE(rpm_openssl.exact_product);
    REQUIRE(rpm_openssl.confidence == Confidence::High);

    auto deb_libssl3 = r.resolve(pkg("libssl3", "3.0.2", "deb"));
    REQUIRE(deb_libssl3.outcome == IdentityOutcome::Resolved);
    REQUIRE(deb_libssl3.cpe_product == "openssl");
    REQUIRE(deb_libssl3.exact_product);
    REQUIRE(deb_libssl3.confidence == Confidence::High);
}

TEST_CASE("curated hit carries a display-only vendor", "[cpe]") {
    // The vendor is metadata (provenance/display). Documented contract: a
    // downstream CpeQuery MUST set vendor="" and match on cpe_product only.
    CpeIdentityResolver r{kSeed};
    auto id = r.resolve(pkg("curl", "7.68.0", "deb"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    REQUIRE(id.cpe_product == "curl");
    REQUIRE(id.cpe_vendor == "curl"); // present as metadata only
    REQUIRE(id.exact_product);
}

TEST_CASE("global curated row resolves across ecosystems (S1)", "[cpe]") {
    CpeIdentityResolver r{kSeed};
    // The GLOBAL libssl3 row (empty eco+distro) must hit for BOTH apk and deb.
    auto apk = r.resolve(pkg("libssl3", "3.0.2", "apk"));
    auto deb = r.resolve(pkg("libssl3", "3.0.2", "deb"));
    REQUIRE(apk.outcome == IdentityOutcome::Resolved);
    REQUIRE(apk.cpe_product == "openssl");
    REQUIRE(deb.outcome == IdentityOutcome::Resolved);
    REQUIRE(deb.cpe_product == "openssl");
}

TEST_CASE("distro-scoped row overrides the global row", "[cpe]") {
    std::string csv = seed_plus("deb,,foo,v1,p1\ndeb,ubuntu,foo,v2,p2\n");
    CpeIdentityResolver r{csv};

    auto ubuntu = r.resolve(pkg("foo", "1.0", "deb", "ubuntu"));
    REQUIRE(ubuntu.outcome == IdentityOutcome::Resolved);
    REQUIRE(ubuntu.cpe_product == "p2"); // most-specific wins

    auto rhel = r.resolve(pkg("foo", "1.0", "deb", "rhel"));
    REQUIRE(rhel.outcome == IdentityOutcome::Resolved);
    REQUIRE(rhel.cpe_product == "p1"); // falls back to the global row
}

TEST_CASE("uncurated name resolves low-confidence via normalization", "[cpe]") {
    CpeIdentityResolver r{kSeed};
    auto id = r.resolve(pkg("openssl-dev", "1.1.1", "deb"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    REQUIRE(id.cpe_product == "openssl");
    REQUIRE_FALSE(id.exact_product);
    REQUIRE(id.confidence == Confidence::Low);
    REQUIRE(id.cpe_vendor.empty());
}

TEST_CASE("uncurated dotted-lib name dot-strips through the full resolve() path",
          "[cpe]") {
    // The libssl-dot fix (cpe_normalize.hpp step 4, lib-branch consuming a
    // trailing `[0-9.]` run) is otherwise only exercised via normalize_product()
    // directly, or via the curated `libssl1.1`/`libssl3` rows — which short-
    // circuit at the curated lookup BEFORE normalize runs. This drives an
    // UNCURATED dotted-lib name (`libssl9.9`, not in the seed) through the real
    // low-confidence decision path, proving the dot-strip runs there.
    CpeIdentityResolver r{kSeed};
    auto id = r.resolve(pkg("libssl9.9", "1.0", "deb"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    CHECK(id.confidence == Confidence::Low);
    CHECK_FALSE(id.exact_product);
    CHECK(id.cpe_product == "libssl"); // dotted soname tail stripped, no dead dot
}

TEST_CASE("normalize_product low-confidence table", "[cpe]") {
    CHECK(normalize_product("openssl-dev") == "openssl");
    CHECK(normalize_product("python3-requests") == "requests");
    CHECK(normalize_product("libfoo5") == "libfoo");
    CHECK(normalize_product("gcc-12") == "gcc");
    CHECK(normalize_product("nginx-common") == "nginx");
    CHECK(normalize_product("bash") == "bash");
    CHECK(normalize_product("LIBCURL4") == "libcurl");
    CHECK(normalize_product("  openssl  ") == "openssl");
    CHECK(normalize_product("-dev") == "");
    CHECK(normalize_product("sqlite3") == "sqlite3"); // no bare-digit strip
    // Prefix strips first (`python3-`), then no SAFE suffix remains on the bare
    // `dev` token, so it is NOT re-examined as a `-dev` suffix — surprising but
    // correct under the single-pass fixed order.
    CHECK(normalize_product("python3-dev") == "dev");
}

TEST_CASE("normalize_product order-dependence is single-pass (S3)", "[cpe]") {
    // Single pass, fixed order: the trailing version tail is stripped once, so
    // `-dev` survives (it is not re-examined as a suffix after the tail strip).
    CHECK(normalize_product("foo-dev-12") == "foo-dev");
    // Prefix + suffix both fire (once each), then no version tail remains.
    CHECK(normalize_product("python3-foo-dev") == "foo");
}

TEST_CASE("normalized names below the prefix floor are no-identity", "[cpe]") {
    CpeIdentityResolver r{kSeed};

    auto below = r.resolve(pkg("xy", "1.0", "deb")); // normalizes to len 2
    REQUIRE(below.outcome == IdentityOutcome::NoIdentity);
    REQUIRE(below.not_assessed_reason == std::string(kReasonBelowPrefixFloor));

    auto at = r.resolve(pkg("abc", "1.0", "deb")); // len 3 -> Low
    REQUIRE(at.outcome == IdentityOutcome::Resolved);
    REQUIRE(at.confidence == Confidence::Low);
    REQUIRE(at.cpe_product == "abc");
}

TEST_CASE("dangerous suffixes are not stripped (real stems)", "[cpe]") {
    // -server / -data are real product stems, excluded from the SAFE allowlist.
    CHECK(normalize_product("foo-server") == "foo-server");
    CHECK(normalize_product("foo-data") == "foo-data");

    CpeIdentityResolver r{kSeed};
    auto id = r.resolve(pkg("foo-server", "1.0", "deb")); // uncurated
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    REQUIRE(id.cpe_product == "foo-server");
    REQUIRE(id.confidence == Confidence::Low);
}

TEST_CASE("empty or short curated map fails closed", "[cpe]") {
    // 0 rows.
    REQUIRE_THROWS_AS(CpeIdentityResolver{std::string_view{""}}, std::runtime_error);
    // all-comment CSV -> 0 data rows.
    REQUIRE_THROWS_AS(CpeIdentityResolver{std::string_view{"# just a comment\n# another\n"}},
                      std::runtime_error);
    // below-floor (fewer than 13 valid rows).
    REQUIRE_THROWS_AS(CpeIdentityResolver{std::string_view{",,openssl,openssl,openssl\n"}},
                      std::runtime_error);
}

TEST_CASE("csv parse skips comments and blanks", "[cpe]") {
    std::string csv = "# header comment\n\n" + std::string(kSeed) + "\n   \n# trailing comment\n";
    CpeIdentityResolver r{csv};
    REQUIRE(r.curated_entry_count() == 13); // exactly the 13 data rows

    // Malformed (wrong field count) rows are dropped defensively.
    auto parsed = parse_curated_csv("a,b,c\n,,openssl,openssl,openssl\nx,y,z,w,v,u\n");
    REQUIRE(parsed.size() == 1);
    REQUIRE(parsed[0].name == "openssl");
}

TEST_CASE("resolver exposes but does not apply the low-confidence gate", "[cpe]") {
    // A Low-confidence resolve still returns Resolved — the resolver never
    // demotes a Low clean to not-assessed; that is the PR-4 engine's job.
    CpeIdentityResolver r{kSeed};
    auto id = r.resolve(pkg("someuncuratedpkg", "1.0", "deb"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    REQUIRE(id.confidence == Confidence::Low);
    REQUIRE_FALSE(id.exact_product);
    REQUIRE(id.not_assessed_reason.empty()); // Resolved carries no reason
}

// ===========================================================================
// ADVERSARIAL — Attack angle 1: normalize_product order-dependence & strips
// ===========================================================================

TEST_CASE("ADVERSARIAL: lib-prefixed dotted version tail leaves a trailing dot",
          "[cpe]") {
    // The lib-prefixed branch (cpe_normalize.hpp step 4) strips a trailing RUN OF
    // DIGITS only — it never consumes a '.'. A bare-digit tail (libc6, libfoo5)
    // strips cleanly, but any lib-prefixed name whose version is glued on with a
    // dot (no dash separator) leaves a mangled trailing '.' in the product token.
    CHECK(normalize_product("libc6") == "libc");   // sanity: bare-digit path is fine
    CHECK(normalize_product("libfoo5") == "libfoo"); // sanity: from the existing table
    CHECK(normalize_product("libssl1.1") == "libssl"); // real package name (uncurated path)
    CHECK(normalize_product("libssl3.0") == "libssl");
}

TEST_CASE("ADVERSARIAL: interpreter-prefix strip can misidentify a product whose "
          "own name starts with the prefix token",
          "[cpe]") {
    // "node-red" is a real, well-known product (Node-RED, CVE-bearing). Stripping
    // the "node-" interpreter prefix collapses it to the generic token "red" —
    // exactly the kind of silent product-identity corruption the curated map
    // exists to prevent, except this happens in the UNCURATED low-confidence
    // fallback, which the curated map cannot shield (node-red is not seeded).
    CHECK(normalize_product("node-red") == "red");
}

TEST_CASE("ADVERSARIAL: two suffix-shaped tails only ever strip one (single-pass)",
          "[cpe]") {
    // "-common-dev": the fixed-order suffix scan hits "-dev" (checked before
    // "-common" is reachable again) and stops after ONE strip, per the documented
    // single-pass contract. Left as "-common" (leading dash retained) — not a
    // crash, but worth pinning down since it is a genuinely odd-looking output.
    CHECK(normalize_product("-common-dev") == "-common");
}

// ===========================================================================
// ADVERSARIAL — Attack angle 2: lane gate bypass / contradictory records
// ===========================================================================

TEST_CASE("ADVERSARIAL: kind=app wins over a lane-1 ecosystem on a contradictory "
          "record",
          "[cpe]") {
    CpeIdentityResolver r{kSeed};
    SoftwareEntry e = pkg("openssl", "1.1.1", "rpm");
    e.kind = "app"; // contradictory: kind says GUI app, ecosystem says rpm package
    auto id = r.resolve(e);
    REQUIRE(id.outcome == IdentityOutcome::NotAssessed);
    CHECK(id.not_assessed_reason == std::string(kReasonOsNative));
}

TEST_CASE("REGRESSION GUARD: ecosystem lane checks are case-INSENSITIVE "
          "(uppercase RPM is recognized as lane1)",
          "[cpe]") {
    // is_lane1/is_os_native lowercase the ecosystem before comparing, consistent
    // with curated_key() lowercasing both sides. A producer that emits "RPM" must
    // route to Lane 1 (and resolve via the curated map), NOT fall through to
    // unsupported-ecosystem. Real producers emit lowercase today, but the gate is
    // defensively case-insensitive.
    CpeIdentityResolver r{kSeed};
    auto id = r.resolve(pkg("openssl", "1.1.1", "RPM"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    CHECK(id.exact_product);                        // curated High hit
    CHECK(id.cpe_product == "openssl");
}

TEST_CASE("ADVERSARIAL: empty kind and empty ecosystem together is "
          "unsupported-ecosystem, not a crash",
          "[cpe]") {
    CpeIdentityResolver r{kSeed};
    SoftwareEntry e;
    e.name = "openssl";
    e.version = "1.1.1";
    e.kind = "";
    e.ecosystem = "";
    auto id = r.resolve(e);
    REQUIRE(id.outcome == IdentityOutcome::NotAssessed);
    CHECK(id.not_assessed_reason == std::string(kReasonUnsupportedEcosystem));
}

// ===========================================================================
// ADVERSARIAL — Attack angle 3: curated key precedence & cross-ecosystem
// ===========================================================================

TEST_CASE("ADVERSARIAL: duplicate curated key — first writer in file order wins",
          "[cpe]") {
    std::string csv = seed_plus("deb,,dup,vendor-a,product-a\ndeb,,dup,vendor-b,product-b\n");
    CpeIdentityResolver r{csv};
    auto id = r.resolve(pkg("dup", "1.0", "deb"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    CHECK(id.cpe_product == "product-a");
    CHECK(id.cpe_vendor == "vendor-a");
}

TEST_CASE("ADVERSARIAL: curated CSV fields are lowercased and trimmed on both "
          "write and lookup",
          "[cpe]") {
    std::string csv = seed_plus(" DEB , Ubuntu , FooBar , Vend , Prod \n");
    CpeIdentityResolver r{csv};
    auto id = r.resolve(pkg("foobar", "1.0", "deb", "ubuntu"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    CHECK(id.cpe_product == "prod");
    CHECK(id.cpe_vendor == "vend");
}

// ===========================================================================
// ADVERSARIAL — Attack angle 4: CSV parsing robustness
// ===========================================================================

TEST_CASE("ADVERSARIAL: malformed field counts and embedded commas are dropped, "
          "never corrupt the map",
          "[cpe]") {
    auto four = parse_curated_csv(",,onlyfourfields,vendor\n");
    CHECK(four.empty());
    auto six = parse_curated_csv(",,six,fields,here,extra\n");
    CHECK(six.empty());
    // A field value containing a literal comma splits into 6 fields and the
    // whole row is dropped rather than silently truncated/misaligned.
    auto embedded_comma = parse_curated_csv(",,openssl,openssl,open,ssl\n");
    CHECK(embedded_comma.empty());
}

TEST_CASE("ADVERSARIAL: CRLF endings, whitespace-only lines, and a missing final "
          "newline are all handled",
          "[cpe]") {
    std::string csv = std::string(kSeed) + "   \r\n" + "# mid-file comment\r\n" +
                       "deb,,crlf,v,p\r\n" + "deb,,notrail,v2,p2"; // no trailing \n
    CpeIdentityResolver r{csv};
    auto crlf = r.resolve(pkg("crlf", "1.0", "deb"));
    REQUIRE(crlf.outcome == IdentityOutcome::Resolved);
    CHECK(crlf.cpe_product == "p");
    auto notrail = r.resolve(pkg("notrail", "1.0", "deb"));
    REQUIRE(notrail.outcome == IdentityOutcome::Resolved);
    CHECK(notrail.cpe_product == "p2");
}

TEST_CASE("REGRESSION GUARD: a curated row with an empty product (or name) field "
          "is DROPPED, never a High-confidence empty-product hit",
          "[cpe]") {
    // parse_curated_csv rejects a structurally-complete-but-useless row (empty
    // name or empty cpe_product) — an authoring slip (trailing comma / a shifted
    // column) must NOT ship a High-confidence hit carrying nothing to match on.
    // With the row dropped, `blankprod` is not in the curated map and falls to the
    // low-confidence normalize path (a real, matchable prefix product).
    std::string csv = seed_plus(",,blankprod,vendor,\n"); // product field empty → dropped
    CpeIdentityResolver r{csv};
    auto id = r.resolve(pkg("blankprod", "1.0", "deb"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    CHECK_FALSE(id.exact_product);                 // NOT a curated exact hit
    CHECK(id.confidence == Confidence::Low);
    CHECK(id.cpe_product == "blankprod");           // normalize passthrough, non-empty
}

// ===========================================================================
// ADVERSARIAL — Attack angle 5: fail-closed guard boundaries
// ===========================================================================

TEST_CASE("ADVERSARIAL: fail-closed floor is an exact boundary at kMinCuratedRows",
          "[cpe]") {
    REQUIRE_THROWS_AS(CpeIdentityResolver(kTwelveRows), std::runtime_error); // 12 < 13
    REQUIRE_NOTHROW(CpeIdentityResolver(kSeed));                             // 13 == 13, ok
}

TEST_CASE("ADVERSARIAL: 13 raw non-comment lines that parse to ZERO valid rows "
          "still fail closed at runtime",
          "[cpe]") {
    // This is the runtime half of a two-part finding. server/core/meson.build's
    // configure-time probe counts raw non-blank/non-comment LINES (a `wc -l`
    // style check), NOT successfully-parsed 5-field rows, and its error message
    // claims to "enforce the same floor ... so the failure surfaces at configure
    // time too." A CSV with 13 lines that are all malformed (e.g. wrong field
    // count) satisfies the configure-time line-count probe but parses to 0 valid
    // rows here — the claimed configure-time/runtime parity does not hold; only
    // the runtime ctor actually catches this case.
    std::string thirteen_malformed;
    for (int i = 0; i < 13; ++i)
        thirteen_malformed += "a,b,c\n"; // 3 fields, not 5 — dropped by the parser
    auto parsed = parse_curated_csv(thirteen_malformed);
    CHECK(parsed.empty());
    REQUIRE_THROWS_AS(CpeIdentityResolver(std::string_view{thirteen_malformed}),
                      std::runtime_error);
}

// ===========================================================================
// ADVERSARIAL — integration: the REAL production ctor + REAL build-embedded CSV
// ===========================================================================

TEST_CASE("ADVERSARIAL: production ctor parses the real build-embedded curated "
          "map (no test-seam CSV)",
          "[cpe]") {
    // Every other test in this file uses the explicit-CSV test-seam ctor. This is
    // the only case exercising the zero-arg production ctor against the REAL
    // build-embedded `kCuratedCpeMap` (server/core/meson.build's cpe_map_embed
    // custom_target -> embed_binary.py), i.e. the actual shipped artifact.
    CpeIdentityResolver r;
    REQUIRE(r.curated_entry_count() >= kMinCuratedRows);
    auto id = r.resolve(pkg("openssl", "1.1.1", "rpm"));
    REQUIRE(id.outcome == IdentityOutcome::Resolved);
    CHECK(id.cpe_product == "openssl");
    CHECK(id.exact_product);
}

TEST_CASE("REGRESSION GUARD: every published (kind, ecosystem) pair routes to Lane 1 or "
          "Lane 3, never unsupported-ecosystem",
          "[cpe]") {
    CpeIdentityResolver r{kSeed};

    for (const char* eco : {"rpm", "deb", "apk", "pacman"}) {
        auto id = r.resolve(pkg("openssl", "1.1.1", eco, "", "package"));
        INFO(eco);
        REQUIRE(id.outcome == IdentityOutcome::Resolved);
        CHECK(id.cpe_product == "openssl");
    }

    const std::pair<const char*, const char*> lane3[] = {
        {"app", "windows"}, {"app", "macos"},           {"pkg", "macos_pkgutil"},
        {"pkg", "brew"},    {"app", "brew"},            {"feat", "optional_feature"},
    };
    for (const auto& [kind, eco] : lane3) {
        auto id = r.resolve(pkg("x", "1", eco, "", kind));
        INFO(kind << "/" << eco);
        REQUIRE(id.outcome == IdentityOutcome::NotAssessed);
        CHECK(id.not_assessed_reason == std::string(kReasonOsNative));
    }
}

TEST_CASE("REGRESSION GUARD: the retired `homebrew` value is unsupported-ecosystem, not "
          "os-native; pkg is not a kind-level Lane-3 trigger",
          "[cpe]") {
    CpeIdentityResolver r{kSeed};

    auto retired = r.resolve(pkg("wget", "1.21", "homebrew", "", "package"));
    REQUIRE(retired.outcome == IdentityOutcome::NotAssessed);
    CHECK(retired.not_assessed_reason == std::string(kReasonUnsupportedEcosystem));

    auto bare_pkg = r.resolve(pkg("wget", "1.21", "", "", "pkg"));
    REQUIRE(bare_pkg.outcome == IdentityOutcome::NotAssessed);
    CHECK(bare_pkg.not_assessed_reason == std::string(kReasonUnsupportedEcosystem));
}
