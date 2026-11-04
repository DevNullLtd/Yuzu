/**
 * test_installed_apps_inventory.cpp -- pure parse/format vectors for the
 * `list_inventory` action's helpers (installed_apps_inventory.hpp, software-
 * inventory blob contract v2, ADR-0016).
 *
 * Everything here runs against fixture strings -- no dpkg/rpm/pacman/apk on the
 * test host -- because the helpers are pure by design (same header-for-
 * testability pattern as installed_apps_registry_utf8.hpp / #1662). The vectors
 * pin the v2 honesty contract: fields an ecosystem does not store come out
 * EMPTY, never synthesised (no "-0" release, no "-" placeholder).
 */

#include <catch2/catch_test_macros.hpp>

#include "installed_apps_inventory.hpp"

#include <algorithm>
#include <string>

using namespace yuzu::installed_apps::inventory;

TEST_CASE("split_deb_version handles epoch/upstream/revision shapes", "[installed_apps][inventory]") {
    SECTION("full epoch:upstream-revision") {
        const auto p = split_deb_version("1:1.2.3-4ubuntu5");
        CHECK(p.epoch == "1");
        CHECK(p.version == "1.2.3");
        CHECK(p.release == "4ubuntu5");
    }
    SECTION("native package: no revision, release stays empty") {
        const auto p = split_deb_version("5.0");
        CHECK(p.epoch.empty());
        CHECK(p.version == "5.0");
        CHECK(p.release.empty()); // never synthesise "-0"
    }
    SECTION("epoch without revision") {
        const auto p = split_deb_version("2:5.0");
        CHECK(p.epoch == "2");
        CHECK(p.version == "5.0");
        CHECK(p.release.empty());
    }
    SECTION("hyphenated upstream version: revision is after the LAST dash") {
        const auto p = split_deb_version("1.0-2-3");
        CHECK(p.epoch.empty());
        CHECK(p.version == "1.0-2");
        CHECK(p.release == "3");
    }
    SECTION("non-numeric prefix before colon is not an epoch") {
        const auto p = split_deb_version("v1:2.0-1");
        CHECK(p.epoch.empty());
        CHECK(p.version == "v1:2.0");
        CHECK(p.release == "1");
    }
    SECTION("empty input") {
        const auto p = split_deb_version("");
        CHECK(p.epoch.empty());
        CHECK(p.version.empty());
        CHECK(p.release.empty());
    }
}

TEST_CASE("split_pacman_version mirrors the [epoch:]pkgver-pkgrel shape", "[installed_apps][inventory]") {
    SECTION("epoch:pkgver-pkgrel") {
        const auto p = split_pacman_version("2:1.19.2-1");
        CHECK(p.epoch == "2");
        CHECK(p.version == "1.19.2");
        CHECK(p.release == "1");
    }
    SECTION("pkgver-pkgrel, no epoch") {
        const auto p = split_pacman_version("1.19.2-1");
        CHECK(p.epoch.empty());
        CHECK(p.version == "1.19.2");
        CHECK(p.release == "1");
    }
    SECTION("missing pkgrel tolerated: release stays empty") {
        const auto p = split_pacman_version("1.19.2");
        CHECK(p.epoch.empty());
        CHECK(p.version == "1.19.2");
        CHECK(p.release.empty());
    }
    SECTION("dotted pkgrel") {
        const auto p = split_pacman_version("6.0-1.1");
        CHECK(p.version == "6.0");
        CHECK(p.release == "1.1");
    }
}

TEST_CASE("split_apk_line splits name-pkgver-rN", "[installed_apps][inventory]") {
    SECTION("hyphenated package name") {
        const auto p = split_apk_line("openssl-dev-3.1.4-r5");
        CHECK(p.name == "openssl-dev");
        CHECK(p.version == "3.1.4");
        CHECK(p.release == "5"); // 'r' is apk display decoration, not pkgrel
    }
    SECTION("simple name") {
        const auto p = split_apk_line("musl-1.2.4-r2");
        CHECK(p.name == "musl");
        CHECK(p.version == "1.2.4");
        CHECK(p.release == "2");
    }
    SECTION("missing -rN tail tolerated: last segment becomes the version") {
        const auto p = split_apk_line("foo-1.2.3");
        CHECK(p.name == "foo");
        CHECK(p.version == "1.2.3");
        CHECK(p.release.empty());
    }
    SECTION("tail that only looks like a release (non-numeric) is a version") {
        const auto p = split_apk_line("foo-rc1");
        CHECK(p.name == "foo");
        CHECK(p.version == "rc1");
        CHECK(p.release.empty());
    }
    SECTION("no dash at all: whole line is the name, version empty") {
        const auto p = split_apk_line("busybox");
        CHECK(p.name == "busybox");
        CHECK(p.version.empty());
        CHECK(p.release.empty());
    }
    SECTION("version-rN with no name segment: name empty (caller drops row)") {
        const auto p = split_apk_line("1.2.3-r0");
        CHECK(p.name.empty());
        CHECK(p.version == "1.2.3");
        CHECK(p.release == "0");
    }
}

TEST_CASE("map_rpm_none maps the literal (none) to honest-empty", "[installed_apps][inventory]") {
    CHECK(map_rpm_none("(none)").empty());
    CHECK(map_rpm_none("x86_64") == "x86_64");
    CHECK(map_rpm_none("").empty());
    CHECK(map_rpm_none("(None)") == "(None)"); // rpm emits lowercase; don't over-match
}

TEST_CASE("parse_os_release extracts ID / VERSION_ID", "[installed_apps][inventory]") {
    const std::string content = "# a comment line\n"
                                "NAME=\"Ubuntu\"\r\n"
                                "ID=ubuntu\n"
                                "VERSION_ID=\"24.04\"\n"
                                "PRETTY='Single Quoted'\n"
                                "\n"
                                "  INDENTED=ok\n";
    SECTION("unquoted value") {
        CHECK(parse_os_release(content, "ID") == "ubuntu");
    }
    SECTION("double-quoted value") {
        CHECK(parse_os_release(content, "VERSION_ID") == "24.04");
    }
    SECTION("single-quoted value") {
        CHECK(parse_os_release(content, "PRETTY") == "Single Quoted");
    }
    SECTION("CRLF line ending stripped") {
        CHECK(parse_os_release(content, "NAME") == "Ubuntu");
    }
    SECTION("leading whitespace tolerated") {
        CHECK(parse_os_release(content, "INDENTED") == "ok");
    }
    SECTION("missing key is empty") {
        CHECK(parse_os_release(content, "VARIANT_ID").empty());
    }
    SECTION("comment lines never match") {
        CHECK(parse_os_release("#ID=nope\n", "ID").empty());
    }
    SECTION("key must match exactly, not by prefix") {
        CHECK(parse_os_release("VERSION_ID=1\n", "VERSION").empty());
        CHECK(parse_os_release("VERSION=2\n", "VERSION_ID").empty());
    }
    SECTION("empty content") {
        CHECK(parse_os_release("", "ID").empty());
    }
}

TEST_CASE("parse_dpkg_inv_line keeps installed+held, drops the rest (matches PR #1804's "
          "Status-Abbrev 2nd-char check exactly)",
          "[installed_apps][inventory]") {
    SECTION("installed package, full EVR (\"ii\": want=install, status=installed)") {
        const auto r = parse_dpkg_inv_line("bash\tii\t1:5.2.21-2ubuntu4\tamd64\tUbuntu "
                                           "Developers <ubuntu-devel-discuss@lists.ubuntu.com>");
        REQUIRE(r.has_value());
        CHECK(r->name == "bash");
        CHECK(r->epoch == "1");
        CHECK(r->version == "5.2.21");
        CHECK(r->release == "2ubuntu4");
        CHECK(r->arch == "amd64");
        CHECK(r->publisher ==
              "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>");
        CHECK(r->kind == "package");
        CHECK(r->ecosystem == "deb");
        CHECK(r->signature_status.empty()); // deb stores no signature -- honest-empty
        CHECK(r->install_date.empty());
    }
    SECTION("held package is kept (\"hi\": want=hold, status=installed)") {
        const auto r = parse_dpkg_inv_line("linux-image\thi\t6.8.0-31.31\tamd64\tX");
        REQUIRE(r.has_value());
        CHECK(r->version == "6.8.0");
        CHECK(r->release == "31.31");
    }
    SECTION("config-files residue is dropped (\"rc\": status=config-files, not installed)") {
        CHECK_FALSE(parse_dpkg_inv_line("old-pkg\trc\t1.0-1\tamd64\tX").has_value());
    }
    SECTION("unknown want-state is dropped (\"un\")") {
        CHECK_FALSE(parse_dpkg_inv_line("stray-pkg\tun\t1.0-1\tamd64\tX").has_value());
    }
    SECTION("native package: empty release") {
        const auto r = parse_dpkg_inv_line("mytool\tii\t5.0\tall\tMe <me@x>");
        REQUIRE(r.has_value());
        CHECK(r->version == "5.0");
        CHECK(r->release.empty());
    }
    SECTION("malformed (single-char or empty) status token is dropped") {
        CHECK_FALSE(parse_dpkg_inv_line("bash\ti\t1.0-1\tamd64\tX").has_value());
        CHECK_FALSE(parse_dpkg_inv_line("bash\t\t1.0-1\tamd64\tX").has_value());
    }
    SECTION("wrong token count is dropped") {
        CHECK_FALSE(parse_dpkg_inv_line("bash\tii\t1.0-1").has_value());
        CHECK_FALSE(parse_dpkg_inv_line("").has_value());
    }
}

TEST_CASE("rpm_sig_present treats only a real stored-tag value as present",
          "[installed_apps][inventory]") {
    CHECK(rpm_sig_present("abcdef0123456789")); // a real (fake-shaped) sig blob
    CHECK_FALSE(rpm_sig_present("(none)"));      // unset tag
    CHECK_FALSE(rpm_sig_present(""));            // empty
    CHECK_FALSE(rpm_sig_present("%{SIGPGP}"));   // rpm too old to know the tag: unexpanded literal
    CHECK_FALSE(rpm_sig_present("%{RSAHEADER}"));
}

TEST_CASE("parse_rpm_inv_line maps (none) and pins signature values (matches PR #1804's "
          "rpm_sig_present exactly)",
          "[installed_apps][inventory]") {
    SECTION("fully populated, payload+header both signed") {
        const auto r = parse_rpm_inv_line(
            "bash\t0\t5.2.21\t3.fc40\tx86_64\tFedora Project\tMon 01 Jan 2026\tsigpgpblob\trsahdrblob\tFedora Project");
        REQUIRE(r.has_value());
        CHECK(r->name == "bash");
        CHECK(r->epoch == "0");
        CHECK(r->version == "5.2.21");
        CHECK(r->release == "3.fc40");
        CHECK(r->arch == "x86_64");
        CHECK(r->publisher == "Fedora Project");
        CHECK(r->install_date == "Mon 01 Jan 2026");
        CHECK(r->signature_status == "signed");
        CHECK(r->kind == "package");
        CHECK(r->ecosystem == "rpm");
    }
    SECTION("header-signed only (SIGPGP (none)) still reads signed -- the modern RHEL/Fedora case") {
        const auto r = parse_rpm_inv_line(
            "openssl\t1\t3.1.4\t1.fc40\tx86_64\tFedora Project\td\t(none)\trsahdrblob\tFedora Project");
        REQUIRE(r.has_value());
        CHECK(r->signature_status == "signed");
    }
    SECTION("payload-signed only (RSAHEADER (none)) still reads signed") {
        const auto r =
            parse_rpm_inv_line("openssl\t1\t3.1.4\t1.fc40\tx86_64\tFedora Project\td\tsigpgpblob\t(none)\tFedora Project");
        REQUIRE(r.has_value());
        CHECK(r->signature_status == "signed");
    }
    SECTION("both tags absent reads unsigned") {
        const auto r =
            parse_rpm_inv_line("openssl\t1\t3.1.4\t1.fc40\tx86_64\tFedora Project\td\t(none)\t(none)\tFedora Project");
        REQUIRE(r.has_value());
        CHECK(r->signature_status == "unsigned");
    }
    SECTION("old-rpm literal %{...} echo on both tags reads unsigned, never a false positive") {
        const auto r = parse_rpm_inv_line(
            "openssl\t1\t3.1.4\t1.fc40\tx86_64\tFedora Project\td\t%{SIGPGP}\t%{RSAHEADER}\tFedora Project");
        REQUIRE(r.has_value());
        CHECK(r->signature_status == "unsigned");
    }
    SECTION("(none) epoch/arch/packager map to honest-empty") {
        const auto r = parse_rpm_inv_line(
            "gpg-pubkey\t(none)\tabc123\t4f2a6fd2\t(none)\t(none)\tTue 02 Jan 2026\t(none)\t(none)\t(none)");
        REQUIRE(r.has_value());
        CHECK(r->epoch.empty());
        CHECK(r->arch.empty());
        CHECK(r->publisher.empty());
        CHECK(r->signature_status == "unsigned");
    }
    SECTION("publisher is the declared VENDOR; PACKAGER (a person) only when VENDOR is unset") {
        // Shape of a Rocky Linux 9 row (rpm 4.16): PACKAGER is the build system's address, VENDOR the org.
        const auto rocky = parse_rpm_inv_line(
            "libgcc\t(none)\t11.4.1\t2.1.el9\taarch64\tRocky Linux Build System (Peridot) "
            "<releng@rockylinux.org>\tSun Nov 19 22:25:36 2023\t(none)\t89024a04\t"
            "Rocky Enterprise Software Foundation");
        REQUIRE(rocky.has_value());
        CHECK(rocky->publisher == "Rocky Enterprise Software Foundation");
        // VENDOR (none), PACKAGER set: the fallback keeps the packager rather than going empty.
        const auto fallback = parse_rpm_inv_line(
            "gpg-pubkey\t(none)\tabc123\t4f2a6fd2\t(none)\tFedora (43) Signing\td\t(none)\t(none)\t(none)");
        REQUIRE(fallback.has_value());
        CHECK(fallback->publisher == "Fedora (43) Signing");
        // both unset: empty, the agent core labels it via:rpm
        const auto none = parse_rpm_inv_line("p\t0\t1\t1\tnoarch\t(none)\td\t(none)\t(none)\t(none)");
        REQUIRE(none.has_value());
        CHECK(none->publisher.empty());
    }
    SECTION("wrong token count is dropped") {
        CHECK_FALSE(parse_rpm_inv_line("bash\t0\t5.2.21").has_value());
        CHECK_FALSE(parse_rpm_inv_line("p\t0\t1\t1\tnoarch\tX\td\tonly-eight-tokens").has_value());
        // the nine-token row of an agent that predates the VENDOR column is a different shape: dropped
        CHECK_FALSE(parse_rpm_inv_line("p\t0\t1\t1\tnoarch\tX\td\t(none)\t(none)").has_value());
        CHECK_FALSE(parse_rpm_inv_line("p\t0\t1\t1\tnoarch\tX\td\t(none)\t(none)\tV\textra").has_value());
    }
}

TEST_CASE("parse_pacman_inv_line splits name and EVR", "[installed_apps][inventory]") {
    SECTION("epoch:pkgver-pkgrel") {
        const auto r = parse_pacman_inv_line("systemd 2:255.4-2");
        REQUIRE(r.has_value());
        CHECK(r->name == "systemd");
        CHECK(r->epoch == "2");
        CHECK(r->version == "255.4");
        CHECK(r->release == "2");
        CHECK(r->kind == "package");
        CHECK(r->ecosystem == "pacman");
        CHECK(r->arch.empty()); // -Q does not expose arch -- honest-empty
    }
    SECTION("no space means no record") {
        CHECK_FALSE(parse_pacman_inv_line("garbage").has_value());
        CHECK_FALSE(parse_pacman_inv_line(" 1.0-1").has_value());
    }
}

TEST_CASE("parse_apk_inv_line wraps split_apk_line", "[installed_apps][inventory]") {
    SECTION("normal line") {
        const auto r = parse_apk_inv_line("openssl-dev-3.1.4-r5");
        REQUIRE(r.has_value());
        CHECK(r->name == "openssl-dev");
        CHECK(r->version == "3.1.4");
        CHECK(r->release == "5");
        CHECK(r->kind == "package");
        CHECK(r->ecosystem == "apk");
    }
    SECTION("empty or nameless lines are dropped") {
        CHECK_FALSE(parse_apk_inv_line("").has_value());
        CHECK_FALSE(parse_apk_inv_line("1.2.3-r0").has_value());
    }
}

TEST_CASE("pipe_safe deletes framing/separator bytes", "[installed_apps][inventory]") {
    CHECK(pipe_safe("Vendor | Inc.") == "Vendor  Inc.");
    CHECK(pipe_safe("a\tb\rc\nd") == "abcd");
    CHECK(pipe_safe("clean") == "clean");
    CHECK(pipe_safe("").empty());
}

TEST_CASE("format_inv_row owns the 13-token layout", "[installed_apps][inventory]") {
    InvRecord r;
    r.name = "bash";
    r.version = "5.2.21";
    r.publisher = "Fedora Project";
    r.install_date = "Mon 01 Jan 2026";
    r.kind = "package";
    r.ecosystem = "rpm";
    r.epoch = "0";
    r.release = "3.fc40";
    r.arch = "x86_64";
    r.signature_status = "signed";
    r.distro_id = "fedora";
    r.distro_version = "40";
    CHECK(format_inv_row(r) ==
          "inv|bash|5.2.21|Fedora Project|Mon 01 Jan 2026|package|rpm|0|3.fc40|x86_64|signed|"
          "fedora|40");

    SECTION("empty fields stay empty tokens -- no placeholder synthesis") {
        InvRecord app;
        app.name = "Google Chrome";
        app.version = "126.0";
        app.publisher = "Google LLC";
        app.kind = "app";
        app.ecosystem = "windows";
        CHECK(format_inv_row(app) == "inv|Google Chrome|126.0|Google LLC||app|windows||||||");
    }
    SECTION("pipe in a value cannot shift fields") {
        InvRecord bad;
        bad.name = "Evil|App";
        bad.kind = "app";
        bad.ecosystem = "windows";
        const std::string row = format_inv_row(bad);
        CHECK(row == "inv|EvilApp||||app|windows||||||");
        // Exactly 12 separators after the prefix regardless of input bytes.
        CHECK(std::count(row.begin(), row.end(), '|') == 12);
    }
}
