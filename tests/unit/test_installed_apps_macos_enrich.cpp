/**
 * test_installed_apps_macos_enrich.cpp — installed_apps_macos_enrich.hpp's
 * signed/unsigned discrimination (Wave 4 PR4.3a, gate-1 remediation).
 *
 * REGRESSION TARGET. The first cut of enrich_app() set
 * signature_status = "signed" whenever SecCodeCopySigningInformation returned
 * errSecSuccess. Measured on macOS 26: that call ALSO succeeds for a bundle
 * `codesign -dv` calls "code object is not signed at all" — it just returns a
 * dictionary with no signing keys, and errSecCSUnsigned never appears on this
 * path. Every enriched app therefore reported "signed", a false positive on a
 * field installed_apps_inventory.hpp itself calls security-posture-relevant.
 * kSecCodeInfoIdentifier presence is the real discriminator.
 *
 * TEST-EFFICIENCY JUSTIFICATION (CLAUDE.md unit-suite discipline, which asks
 * for one whenever a test touches disk): this case cannot be reached from a
 * pure-function seam — the behaviour under test IS Security.framework's
 * verdict on a real on-disk bundle, so a fixture string would re-assert the
 * very assumption that was wrong. Cost is bounded and tiny: one temp dir, two
 * small files, no subprocess (no `codesign` spawn), no network, no clock, no
 * compiler. The bundle's executable is a shell script precisely so the test
 * needs no build step of its own.
 *
 * NOT covered here, deliberately: the ad-hoc-signed → "signed" case. Producing
 * an ad-hoc signature requires spawning `codesign`, which the unit suites
 * forbid. It was verified out-of-band during the gate-1 fix (identifier
 * present, 0 certs, → "signed", no publisher) and is documented at the fix
 * site in installed_apps_macos_enrich.hpp.
 */

// Included ABOVE the platform guard so this TU is never EMPTY off-Darwin:
// `warning_level=3` maps to -Wpedantic, and an empty translation unit is an
// ISO C++ diagnostic. Matches the sibling no-op TUs
// (test_installed_apps_actions.cpp, test_msi_packages_actions.cpp,
// test_bitlocker_local_dispatcher.cpp).
#include <catch2/catch_test_macros.hpp>

#if defined(__APPLE__)

#include "installed_apps_macos_enrich.hpp"

#include "test_helpers.hpp"

#include <filesystem>
#include <fstream>

namespace {

// Build a minimal, genuinely unsigned .app bundle under `root`. `with_identifier`
// false omits CFBundleIdentifier from the Info.plist (a bundle with no identifier).
std::filesystem::path make_unsigned_bundle(const std::filesystem::path& root,
                                           bool with_identifier = true) {
    const auto app = root / "YuzuUnsigned.app";
    const auto macos_dir = app / "Contents" / "MacOS";
    std::filesystem::create_directories(macos_dir);

    std::ofstream plist(app / "Contents" / "Info.plist");
    plist << R"(<?xml version="1.0" encoding="UTF-8"?>)"
          << R"(<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" )"
          << R"("http://www.apple.com/DTDs/PropertyList-1.0.dtd">)"
          << R"(<plist version="1.0"><dict>)";
    if (with_identifier)
        plist << R"(<key>CFBundleIdentifier</key><string>com.yuzu.test.unsigned</string>)";
    plist << R"(<key>CFBundleName</key><string>YuzuUnsigned</string>)"
          << R"(<key>CFBundleExecutable</key><string>yuzu_unsigned</string>)"
          << R"(</dict></plist>)" << '\n';
    plist.close();

    const auto exe = macos_dir / "yuzu_unsigned";
    std::ofstream sh(exe);
    sh << "#!/bin/sh\nexit 0\n";
    sh.close();
    std::filesystem::permissions(exe, std::filesystem::perms::owner_all |
                                          std::filesystem::perms::group_read |
                                          std::filesystem::perms::group_exec |
                                          std::filesystem::perms::others_read |
                                          std::filesystem::perms::others_exec);
    return app;
}

} // namespace

TEST_CASE("macOS enrich: an unsigned bundle is reported unsigned, never signed",
          "[installed_apps][macos]") {
    yuzu::test::TempDir dir("yuzu_test_enrich_");
    std::filesystem::create_directories(dir.path);

    const auto app = make_unsigned_bundle(dir.path);
    const auto res = yuzu::installed_apps::macos_enrich::enrich_app(app.string());

#ifdef YUZU_HAVE_SECURITY_FRAMEWORK
    // The regression assertion: this bundle carries no signature at all, so
    // the one thing this must never say is "signed".
    CHECK(res.signature_status != "signed");
    CHECK(res.signature_status == "unsigned");
    // An unsigned bundle has no leaf certificate, so no publisher may be
    // fabricated for it.
    CHECK(res.publisher.empty());
    // The bundle identifier is read by CFBundle and is independent of signing.
    CHECK(res.bundle_id == "com.yuzu.test.unsigned");
#else
    // No Security framework at build time: the header compiles its honest
    // no-op and every field stays empty (never a fabricated verdict).
    CHECK(res.signature_status.empty());
    CHECK(res.publisher.empty());
    CHECK(res.bundle_id.empty());
#endif
}

// bundle_id_for(): the single CFBundle read behind the `list` action's
// bundle_id column (ADR-0028 binding condition). Same cost class as the case
// above: one temp dir, two small files, no subprocess.
TEST_CASE("macOS enrich: bundle_id_for reads CFBundleIdentifier, empty for a non-bundle path",
          "[installed_apps][macos]") {
    yuzu::test::TempDir dir("yuzu_test_bundle_id_");
    std::filesystem::create_directories(dir.path);

    const auto app = make_unsigned_bundle(dir.path);
    const auto missing = (dir.path / "DoesNotExist.app").string();

#ifdef YUZU_HAVE_SECURITY_FRAMEWORK
    using yuzu::installed_apps::macos_enrich::bundle_id_for;
    CHECK(bundle_id_for(app.string()) == "com.yuzu.test.unsigned");
    // Non-existent path: honest-empty, never a fabricated id.
    CHECK(bundle_id_for(missing).empty());
    CHECK(bundle_id_for("").empty());

    // A bundle with no CFBundleIdentifier: honest-empty, never fabricated
    // (mutation: returning a placeholder from bundle_id_for_url on a null
    // identifier fails here).
    std::filesystem::create_directories(dir.path / "anon");
    const auto anon = make_unsigned_bundle(dir.path / "anon", /*with_identifier=*/false);
    CHECK(bundle_id_for(anon.string()).empty());

    // enrich_app shares the same bundle-id read.
    CHECK(yuzu::installed_apps::macos_enrich::enrich_app(app.string()).bundle_id ==
          bundle_id_for(app.string()));
#else
    // No Security framework at build time: the honest no-op.
    CHECK(yuzu::installed_apps::macos_enrich::bundle_id_for(app.string()).empty());
    CHECK(yuzu::installed_apps::macos_enrich::bundle_id_for(missing).empty());
#endif
}

#endif // __APPLE__
