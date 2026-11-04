/**
 * test_purl_compose.cpp — pure coverage for purl_compose.hpp. No store, no libpq, no clock.
 * The vectors are the build cases of the purl-spec test suite (tests/types/{alpm,apk,brew,deb,
 * rpm}-test.json, purl-spec main at 856b0939f) mapped onto SoftwareEntry fields; where the
 * spec case carries a `distro` qualifier we cannot derive (a codename such as `jessie`) the
 * case is restated with this composer's `<id>-<version_id>` distro and says so.
 */

#include <catch2/catch_test_macros.hpp>

#include "purl_compose.hpp"

#include <array>
#include <string>
#include <string_view>

using namespace yuzu::server;

namespace {

SoftwareEntry entry(std::string_view ecosystem, std::string_view name, std::string_view version,
                    std::string_view release = {}, std::string_view epoch = {},
                    std::string_view arch = {}, std::string_view distro_id = {},
                    std::string_view distro_version = {}) {
    SoftwareEntry e;
    e.ecosystem = std::string(ecosystem);
    e.name = std::string(name);
    e.version = std::string(version);
    e.release = std::string(release);
    e.epoch = std::string(epoch);
    e.arch = std::string(arch);
    e.distro_id = std::string(distro_id);
    e.distro_version = std::string(distro_version);
    return e;
}

} // namespace

TEST_CASE("purl: alpm vectors", "[purl_compose]") {
    CHECK(compose_purl(entry("pacman", "pacman", "6.0.1", "1", "", "x86_64", "arch")) ==
          "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64");
    CHECK(compose_purl(entry("pacman", "python-pip", "21.0", "1", "", "any", "arch")) ==
          "pkg:alpm/arch/python-pip@21.0-1?arch=any");
    CHECK(compose_purl(entry("pacman", "containers-common", "0.47.4", "4", "1", "x86_64", "arch")) ==
          "pkg:alpm/arch/containers-common@1:0.47.4-4?arch=x86_64");
    // rolling: a distro version is never a qualifier (the type defines only `arch`)
    CHECK(compose_purl(entry("pacman", "pacman", "6.0.1", "1", "", "x86_64", "arch", "20241201")) ==
          "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64");
}

TEST_CASE("purl: apk vectors", "[purl_compose]") {
    CHECK(compose_purl(entry("apk", "curl", "7.83.0", "0", "", "x86", "alpine")) ==
          "pkg:apk/alpine/curl@7.83.0-r0?arch=x86");
    CHECK(compose_purl(entry("apk", "apk", "2.12.9", "3", "", "x86", "alpine")) ==
          "pkg:apk/alpine/apk@2.12.9-r3?arch=x86");
    // not a spec vector: the distro qualifier when the release is known
    CHECK(compose_purl(entry("apk", "curl", "7.83.0", "0", "", "x86", "alpine", "3.16.0")) ==
          "pkg:apk/alpine/curl@7.83.0-r0?arch=x86&distro=alpine-3.16.0");
    // no pkgrel: no suffix
    CHECK(compose_purl(entry("apk", "curl", "7.83.0", "", "", "", "alpine")) ==
          "pkg:apk/alpine/curl@7.83.0");
}

TEST_CASE("purl: brew vectors", "[purl_compose]") {
    auto formula = [](std::string_view name, std::string_view version) {
        auto e = entry("brew", name, version);
        e.kind = "pkg";
        e.source = "pkg_inventory.packages";
        return e;
    };
    CHECK(compose_purl(formula("sqlite", "3.43.2")) == "pkg:brew/sqlite@3.43.2");
    CHECK(compose_purl(formula("SQLite", "3.43.2")) == "pkg:brew/sqlite@3.43.2"); // lowercased
    CHECK(compose_purl(formula("postgresql@12", "12.17")) == "pkg:brew/postgresql%4012@12.17");
    CHECK(compose_purl(formula("node@20", "20.10.0")) == "pkg:brew/node%4020@20.10.0");

    auto cask = entry("brew", "firefox", "120.0");
    cask.kind = "app";
    cask.source = "pkg_inventory.packages";
    CHECK(compose_purl(cask) == "pkg:brew/homebrew/cask/firefox@120.0");

    // the Homebrew presence row is the manager itself, not a package
    auto manager = entry("brew", "homebrew", "4.4.0");
    manager.kind = "app";
    manager.source = "pkg_inventory.managers";
    CHECK(compose_purl(manager).empty());
}

TEST_CASE("purl: deb vectors", "[purl_compose]") {
    // spec: pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie (codename restated as id-version)
    CHECK(compose_purl(entry("deb", "curl", "7.50.3", "1", "", "i386", "debian", "8")) ==
          "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=debian-8");
    CHECK(compose_purl(entry("deb", "dpkg", "1.19.0.4", "", "", "amd64", "ubuntu")) ==
          "pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64");
    CHECK(compose_purl(entry("deb", "attr", "2.4.47", "2", "1", "source", "debian")) ==
          "pkg:deb/debian/attr@1:2.4.47-2?arch=source");
    CHECK(compose_purl(entry("deb", "attr", "2.4.47", "2+b1", "1", "amd64", "debian")) ==
          "pkg:deb/debian/attr@1:2.4.47-2%2Bb1?arch=amd64");
    CHECK(compose_purl(entry("deb", "Curl", "7.88.1", "10", "", "amd64", "debian", "12")) ==
          "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12"); // name lowercased
}

TEST_CASE("purl: rpm vectors", "[purl_compose]") {
    CHECK(compose_purl(entry("rpm", "curl", "7.50.3", "1.fc25", "", "i386", "fedora", "25")) ==
          "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25");
    // qualifiers sort by key: arch, distro, epoch (the spec build vector)
    CHECK(compose_purl(entry("rpm", "centerim", "4.22.10", "1.el6", "1", "i686", "fedora", "25")) ==
          "pkg:rpm/fedora/centerim@4.22.10-1.el6?arch=i686&distro=fedora-25&epoch=1");
    // the rpm name is case sensitive; the namespace and the distro id are lowercased
    CHECK(compose_purl(entry("rpm", "GConf2", "3.2.6", "8.el7", "", "x86_64", "RHEL", "7.9")) ==
          "pkg:rpm/rhel/GConf2@3.2.6-8.el7?arch=x86_64&distro=rhel-7.9");
}

TEST_CASE("purl: ecosystems with no registered type compose nothing", "[purl_compose]") {
    for (const std::string_view eco : {"windows", "macos", "macos_pkgutil", "msi", "snap",
                                       "flatpak", "optional_feature", "python", "ibm_mq", ""}) {
        INFO(eco);
        CHECK(compose_purl(entry(eco, "name", "1.0", "1", "", "x86_64", "debian", "12")).empty());
    }
}

TEST_CASE("purl: required parts missing yields empty, never an invented value", "[purl_compose]") {
    CHECK(compose_purl(entry("deb", "curl", "1.0", "1", "", "amd64", "")).empty()); // no namespace
    CHECK(compose_purl(entry("rpm", "curl", "1.0", "1", "", "x86_64", "")).empty());
    CHECK(compose_purl(entry("apk", "curl", "1.0", "1", "", "x86", "")).empty());
    CHECK(compose_purl(entry("pacman", "curl", "1.0", "1", "", "x86_64", "")).empty());
    CHECK(compose_purl(entry("deb", "", "1.0", "", "", "", "debian")).empty());   // no name
    CHECK(compose_purl(entry("deb", "curl", "", "", "", "", "debian")).empty());  // no version
    CHECK(compose_purl(entry("brew", "go", "")).empty()); // spec allows pkg:brew/go; we do not
}

TEST_CASE("purl: encoding follows spec 5.4", "[purl_compose]") {
    // '+' '@' '/' ' ' '?' '#' and non-ASCII are encoded (uppercase hex); ':' ~ . - _ are not
    CHECK(compose_purl(entry("rpm", "a+b c", "1:2~3", "r/1", "", "x86_64", "o/s", "1")) ==
          "pkg:rpm/o%2Fs/a%2Bb%20c@1:2~3-r%2F1?arch=x86_64&distro=o%2Fs-1");
    CHECK(compose_purl(entry("deb", "caf\xC3\xA9", "1.0", "", "", "", "debian")) ==
          "pkg:deb/debian/caf%C3%A9@1.0");
    CHECK(compose_purl(entry("deb", "a?b#c@d", "1", "", "", "", "debian")) ==
          "pkg:deb/debian/a%3Fb%23c%40d@1");
}

TEST_CASE("purl: empty qualifiers are dropped and the result is deterministic", "[purl_compose]") {
    const auto e = entry("rpm", "curl", "7.50.3", "1", "", "", "fedora", "");
    CHECK(compose_purl(e) == "pkg:rpm/fedora/curl@7.50.3-1");
    CHECK(compose_purl(e) == compose_purl(e));
    // a distro version without an id never reaches a qualifier (the id is the namespace)
    CHECK(compose_purl(entry("deb", "curl", "1", "", "", "amd64", "debian", "")) ==
          "pkg:deb/debian/curl@1?arch=amd64");
}

TEST_CASE("purl: total on hostile bytes and capped without truncation", "[purl_compose]") {
    using namespace std::string_literals;
    const auto nul = compose_purl(entry("deb", "a\0b"s, "1\0"s, "", "", "", "debian"));
    CHECK(nul == "pkg:deb/debian/a%00b@1%00"); // never throws, never drops a byte

    // over the cap: '' (never a cut purl)
    const std::string big(kMaxPurlBytes, 'a');
    CHECK(compose_purl(entry("deb", big, "1", "", "", "", "debian")).empty());
    // just under the cap survives intact
    const std::string fits(kMaxPurlBytes - std::string("pkg:deb/debian/@1").size(), 'a');
    const auto ok = compose_purl(entry("deb", fits, "1", "", "", "", "debian"));
    CHECK(ok.size() == kMaxPurlBytes);
    CHECK(ok.ends_with("@1"));
}

TEST_CASE("purl: every ecosystem with a type composes, and only those", "[purl_compose]") {
    // pins purl_type_for against the composer: a new type must come with a composer rule
    for (const std::string_view eco : {"rpm", "deb", "apk", "pacman", "brew"}) {
        INFO(eco);
        auto e = entry(eco, "pkg", "1.0", "1", "", "x", "distro", "1");
        e.kind = "pkg";
        e.source = "pkg_inventory.packages";
        CHECK(compose_purl(e).starts_with("pkg:" + std::string(purl_type_for(eco)) + "/"));
    }
}
