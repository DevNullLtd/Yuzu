/**
 * test_device_identity_macos.cpp — pure `dsconfigad -show` parser
 * (device_identity_macos.hpp). The FIRST unit tests for the device_identity
 * plugin (Wave 3 / #2380 / ADR-3002 promotion) — it previously had zero.
 *
 * VERIFICATION GAP: this build host is not AD-bound, so the fixtures below
 * are SYNTHETIC specimens matching Apple's documented `dsconfigad -show`
 * field layout, not captured real-world samples — same caveat
 * hardware_disks_macos.hpp's SATA path already carries for the identical
 * reason (see that header's own doc comment).
 *
 * This header is platform-agnostic (not __APPLE__-gated) so these tests
 * compile and run on every host, matching the hardware_disks_macos.hpp /
 * test_hardware_disks_macos.cpp precedent.
 */

#include "device_identity_macos.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::device_identity::macos;

TEST_CASE("parse_dsconfigad_show: AD-bound, domain + organizational unit present",
          "[device_identity][macos]") {
    // Synthetic fixture matching Apple's documented `dsconfigad -show` layout.
    static constexpr const char* kText = R"(Active Directory Domain    = example.com
Computer Account            = WORKSTATION01$
Advanced Options - User Experience
  Create mobile account at login  = Disabled
  Warn user before creating a mobile account = Enabled
  Require confirmation                        = Disabled
  Force home to local drive                   = Disabled
Advanced Options - Mappings
  Mapping UID to attribute        = <not used>
  Mapping user GID to attribute   = <not used>
  Mapping group GID to attribute  = <not used>
Advanced Options - Administrative
  Preferred Domain Controller    =
  Allowed admin groups           =
  Authentication from any domain = Enabled
  Packet signing                 = allow
  Packet encryption               = allow
  Password change interval        = 14
  Restrict Dynamic DNS updates    =
  Namespace                       = forest
  Local home                      = Network
  Protocol support                = <all>
Organizational Unit             = OU=Workstations,DC=example,DC=com
)";
    auto info = parse_dsconfigad_show(kText);
    CHECK(info.ad_bound);
    CHECK(info.domain == "example.com");
    CHECK(info.ou == "OU=Workstations,DC=example,DC=com");
}

TEST_CASE("parse_dsconfigad_show: not AD-bound -> empty output entirely",
          "[device_identity][macos]") {
    // `dsconfigad -show` prints nothing (empty stdout, exit 0) when the Mac
    // is not bound to any directory.
    auto info = parse_dsconfigad_show("");
    CHECK_FALSE(info.ad_bound);
    CHECK(info.domain.empty());
    CHECK(info.ou.empty());
}

TEST_CASE("parse_dsconfigad_show: AD-bound but no Organizational Unit line",
          "[device_identity][macos]") {
    static constexpr const char* kText = "Active Directory Domain    = example.com\n"
                                         "Computer Account            = WORKSTATION01$\n";
    auto info = parse_dsconfigad_show(kText);
    CHECK(info.ad_bound);
    CHECK(info.domain == "example.com");
    CHECK(info.ou.empty());
}

TEST_CASE("parse_dsconfigad_show: garbage/unrelated text -> not bound, empty fields",
          "[device_identity][macos]") {
    auto info = parse_dsconfigad_show("dsconfigad: command not found\n");
    CHECK_FALSE(info.ad_bound);
    CHECK(info.domain.empty());
    CHECK(info.ou.empty());
}

TEST_CASE("parse_dsconfigad_show: value trimmed to end-of-line, trailing \\r\\n excluded",
          "[device_identity][macos]") {
    static constexpr const char* kText =
        "Active Directory Domain    = example.com\r\nOrganizational Unit             = "
        "OU=Workstations,DC=example,DC=com\r\nNext Field = ignored\r\n";
    auto info = parse_dsconfigad_show(kText);
    CHECK(info.ad_bound);
    CHECK(info.domain == "example.com");
    CHECK(info.ou == "OU=Workstations,DC=example,DC=com");
}

TEST_CASE("parse_dsconfigad_show: label present but no '=' -> field not extracted",
          "[device_identity][macos]") {
    auto info = parse_dsconfigad_show("Active Directory Domain\nOrganizational Unit\n");
    CHECK_FALSE(info.ad_bound);
    CHECK(info.domain.empty());
    CHECK(info.ou.empty());
}

TEST_CASE("parse_dsconfigad_show: '=' present but value is blank -> NOT treated as bound "
          "(CDX BR-009)",
          "[device_identity][macos]") {
    // A malformed/transient dsconfigad read (or a field present with an
    // empty value) must not be read as proof of an AD bind -- an engaged-
    // but-empty domain is not a real join.
    auto info = parse_dsconfigad_show("Active Directory Domain =\nComputer Account = X\n");
    CHECK_FALSE(info.ad_bound);
    CHECK(info.domain.empty());
}
