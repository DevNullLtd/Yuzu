/**
 * test_licensing_parsers.cpp — pure-parser coverage for the license_scan
 * plugin (SLE roadmap §5 PR1 test matrix; ADR-0024 Decision 2).
 *
 * Everything here runs against fixture strings — no WMI, registry, rpm or
 * filesystem on the test host — because licensing_parsers.hpp and
 * licensing_record.hpp are pure by design (header-for-testability pattern:
 * #1662 / installed_apps). The vectors pin:
 *   - the SLP LicenseStatus mapping including EVERY grace code,
 *   - the channel / SPDX / DEP-5 / Office-release classifiers
 *     (unknown-preserving, closed-vocabulary discipline, §3.2),
 *   - the FlexLM INCREMENT parser (dates, permanent, uncounted, malformed),
 *   - key_hint derivation NEVER echoing raw key material (ADR-0024 D2),
 *   - grace countdown → ABSOLUTE midnight-epoch conversion (blob stability, D3),
 *   - the expires_at wire encoding (UTC-midnight epoch decimal, §3.1 pins),
 *   - the §3.3 layer-1 record sanitiser (byte set + 1024 B clamp),
 *   - a non-ASCII fixture round-tripping through render intact (R17).
 */

#include <catch2/catch_test_macros.hpp>

#include "licensing_parsers.hpp"
#include "licensing_record.hpp"

#include <string>
#include <vector>

using namespace yuzu::license_scan;

namespace {

std::vector<std::string> split_pipe(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t pos = 0;
    while (pos <= line.size()) {
        std::size_t bar = line.find('|', pos);
        if (bar == std::string::npos)
            bar = line.size();
        fields.emplace_back(line.substr(pos, bar - pos));
        if (bar == line.size())
            break;
        pos = bar + 1;
    }
    return fields;
}

} // namespace

// ── SLP LicenseStatus mapping ───────────────────────────────────────────────

TEST_CASE("SLP LicenseStatus maps every documented code", "[licensing][parsers]") {
    CHECK(slp_status_to_status(0) == "unlicensed");
    CHECK(slp_status_to_status(1) == "licensed");
    SECTION("every grace code maps to grace") {
        CHECK(slp_status_to_status(2) == "grace"); // OOB grace
        CHECK(slp_status_to_status(3) == "grace"); // OOT grace
        CHECK(slp_status_to_status(4) == "grace"); // non-genuine grace
        CHECK(slp_status_to_status(6) == "grace"); // extended grace
    }
    SECTION("notification (5) is the post-grace unlicensed nag state") {
        CHECK(slp_status_to_status(5) == "unlicensed");
    }
    SECTION("unknown codes stay unknown — never guessed") {
        CHECK(slp_status_to_status(7) == "unknown");
        CHECK(slp_status_to_status(-1) == "unknown");
        CHECK(slp_status_to_status(42) == "unknown");
    }
    SECTION("every mapping is inside the §3.2 closed status vocabulary") {
        for (long code = -3; code <= 12; ++code)
            CHECK(is_valid_status(slp_status_to_status(code)));
    }
}

// ── channel classifier ──────────────────────────────────────────────────────

TEST_CASE("channel classifier: ProductKeyChannel forms", "[licensing][parsers]") {
    CHECK(classify_channel("Volume:GVLK", "") == "kms");
    CHECK(classify_channel("Volume:CSVLK", "") == "kms"); // KMS host key
    CHECK(classify_channel("Volume:MAK", "") == "mak");
    CHECK(classify_channel("OEM:DM", "") == "oem");
    CHECK(classify_channel("OEM:SLP", "") == "oem");
    CHECK(classify_channel("OEM:NONSLP", "") == "oem");
    CHECK(classify_channel("Retail", "") == "retail");
}

TEST_CASE("channel classifier: description fallback", "[licensing][parsers]") {
    CHECK(classify_channel("", "Windows(R) Operating System, VOLUME_KMSCLIENT channel") == "kms");
    CHECK(classify_channel("", "Windows(R) Operating System, VOLUME_MAK channel") == "mak");
    CHECK(classify_channel("", "Windows(R) Operating System, OEM_SLP channel") == "oem");
    CHECK(classify_channel("", "Windows(R) Operating System, RETAIL channel") == "retail");
}

TEST_CASE("channel classifier is unknown-preserving and closed", "[licensing][parsers]") {
    CHECK(classify_channel("", "").empty());
    CHECK(classify_channel("Banana", "fruit channel").empty());
    for (const char* pkc : {"Volume:GVLK", "Volume:MAK", "OEM:DM", "Retail", "junk", ""})
        CHECK(is_valid_channel(classify_channel(pkc, "")));
}

// ── declared-licence classification (SPDX / rpm %{LICENSE}) ────────────────

TEST_CASE("licence-string classifier: open source markers", "[licensing][parsers]") {
    CHECK(classify_license_string("GPLv2+") == "open_source");
    CHECK(classify_license_string("GPL-2.0-or-later") == "open_source");
    CHECK(classify_license_string("MIT") == "open_source");
    CHECK(classify_license_string("BSD-3-Clause") == "open_source");
    CHECK(classify_license_string("Apache-2.0") == "open_source");
    CHECK(classify_license_string("MPL-2.0") == "open_source");
    CHECK(classify_license_string("Public Domain") == "open_source");
    CHECK(classify_license_string("LGPLv2.1 and BSD") == "open_source");
}

TEST_CASE("licence-string classifier: freeware and unknown", "[licensing][parsers]") {
    CHECK(classify_license_string("Freeware") == "freeware");
    CHECK(classify_license_string("Free for personal use") == "freeware");
    CHECK(classify_license_string("Commercial") == "unknown");
    CHECK(classify_license_string("Proprietary") == "unknown");
    CHECK(classify_license_string("") == "unknown");
    SECTION("short tokens need word boundaries — no substring false positives") {
        CHECK(classify_license_string("committed to quality") == "unknown"); // no "mit" hit
        CHECK(classify_license_string("discovery tooling") == "unknown");    // no "isc" hit
    }
    SECTION("closed-vocabulary discipline") {
        for (const char* s : {"GPL", "Freeware", "Commercial", "", "garbage \x01\x02"})
            CHECK(is_valid_license_type(classify_license_string(s)));
    }
}

// ── DEP-5 detection ─────────────────────────────────────────────────────────

TEST_CASE("DEP-5 copyright header detection and licence extraction", "[licensing][parsers]") {
    const std::string dep5 =
        "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
        "Upstream-Name: foo\n"
        "Source: https://example.org/foo\n"
        "\n"
        "Files: *\n"
        "Copyright: 2020 Jane Doe\n"
        "License: GPL-2.0+\n";
    CHECK(is_dep5_copyright(dep5));
    CHECK(dep5_first_license(dep5) == "GPL-2.0+");
    CHECK(classify_license_string(dep5_first_license(dep5)) == "open_source");

    SECTION("plain prose copyright files do not detect as DEP-5") {
        CHECK_FALSE(is_dep5_copyright("This package was debianized by someone in 1999.\n"
                                      "It may be redistributed under the terms of the GPL.\n"));
        CHECK_FALSE(is_dep5_copyright(""));
    }
    SECTION("missing License field extracts empty") {
        CHECK(dep5_first_license("Format: something/copyright-format/1.0\n").empty());
    }
}

// ── FlexLM INCREMENT parser ─────────────────────────────────────────────────

TEST_CASE("FlexLM INCREMENT: dated feature", "[licensing][parsers]") {
    const auto inc = parse_flexlm_increment(
        "INCREMENT MATLAB MLM 46 31-dec-2026 100 HOSTID=ANY SIGN=\"00A1 B2C3\"");
    REQUIRE(inc.has_value());
    CHECK(inc->feature == "MATLAB");
    CHECK(inc->vendor_daemon == "MLM");
    CHECK(inc->version == "46");
    CHECK(inc->seats == 100);
    CHECK(expiry_wire_from_epoch(inc->expiry_epoch) == "1798675200"); // 2026-12-31 UTC midnight
}

TEST_CASE("FlexLM INCREMENT: permanent forms map to 0", "[licensing][parsers]") {
    SECTION("literal permanent") {
        const auto inc =
            parse_flexlm_increment("INCREMENT survival VENDORD 1.0 permanent uncounted SIGN=AA");
        REQUIRE(inc.has_value());
        CHECK(inc->expiry_epoch == 0);
        CHECK(inc->seats == 0); // uncounted
    }
    SECTION("year-zero date forms") {
        for (const char* date : {"1-jan-0", "01-jan-0000", "1-JAN-0"}) {
            const auto inc = parse_flexlm_increment(std::string("INCREMENT f v 1.0 ") + date +
                                                    " 5 SIGN=AA");
            REQUIRE(inc.has_value());
            CHECK(inc->expiry_epoch == 0);
            CHECK(inc->seats == 5);
        }
    }
}

TEST_CASE("FlexLM INCREMENT: FEATURE keyword and case-insensitive months",
          "[licensing][parsers]") {
    const auto inc = parse_flexlm_increment("FEATURE ansys ansyslmd 2026.1 01-Jan-2027 25");
    REQUIRE(inc.has_value());
    CHECK(inc->feature == "ansys");
    CHECK(expiry_wire_from_epoch(inc->expiry_epoch) == "1798761600"); // 2027-01-01 UTC midnight
    CHECK(inc->seats == 25);
}

TEST_CASE("FlexLM INCREMENT: malformed lines are rejected, never guessed",
          "[licensing][parsers]") {
    CHECK_FALSE(parse_flexlm_increment("INCREMENT foo").has_value());          // too few fields
    CHECK_FALSE(parse_flexlm_increment("").has_value());
    CHECK_FALSE(parse_flexlm_increment("SERVER lichost 0011223344 27000").has_value());
    CHECK_FALSE(parse_flexlm_increment("# INCREMENT comment MLM 1 31-dec-2026 1").has_value());
    CHECK_FALSE(
        parse_flexlm_increment("INCREMENT f v 1.0 31-foo-2026 5").has_value()); // bad month
    CHECK_FALSE(
        parse_flexlm_increment("INCREMENT f v 1.0 xx-dec-2026 5").has_value()); // bad day
    CHECK_FALSE(
        parse_flexlm_increment("INCREMENT f v 1.0 31-dec-2026 five").has_value()); // bad count
}

TEST_CASE("FlexLM continuation lines join into one logical line", "[licensing][parsers]") {
    const std::string text = "INCREMENT MATLAB MLM 46 \\\n    31-dec-2026 100 SIGN=AA\n";
    const std::string joined = join_flexlm_continuations(text);
    CHECK(joined.find('\\') == std::string::npos);
    const auto inc = parse_flexlm_increment(joined.substr(0, joined.find('\n')));
    REQUIRE(inc.has_value());
    CHECK(inc->seats == 100);
}

// ── key_hint derivation ─────────────────────────────────────────────────────

TEST_CASE("key_hint never echoes raw key material", "[licensing][parsers]") {
    const std::string raw = "XXXXX-YYYYY-ZZZZZ-AAAAA-BBBBB";
    const std::string hint = derive_key_hint("", raw);
    REQUIRE(hint.size() == 12);
    for (char c : hint)
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))); // hex only
    CHECK(raw.find(hint) == std::string::npos);
    CHECK(hint.find("XXXXX") == std::string::npos);
    SECTION("deterministic and input-sensitive") {
        CHECK(derive_key_hint("", raw) == hint);
        CHECK(derive_key_hint("", raw + "1") != hint);
    }
    SECTION("OS partial key passes through verbatim (already partial)") {
        CHECK(derive_key_hint("3V66T", raw) == "3V66T");
    }
    SECTION("no material at all -> empty") { CHECK(derive_key_hint("", "").empty()); }
    SECTION("local SHA-256 matches the NIST 'abc' vector") {
        CHECK(sha256_hex12("abc") == "ba7816bf8f01");
    }
}

// ── grace countdown → absolute date (blob stability) ───────────────────────

TEST_CASE("grace countdown converts to a stable absolute midnight-epoch",
          "[licensing][parsers]") {
    const long long collection = epoch_from_civil(2026, 1, 1); // 2026-01-01T00:00Z
    SECTION("expected date math (midnight-epoch wire values)") {
        CHECK(grace_expiry_date(collection, 10 * 24 * 60) == "1768089600"); // 2026-01-11 midnight
        CHECK(grace_expiry_date(collection, 1) == "1767225600"); // truncated to the collection day
    }
    SECTION("two calls with the same collection_time are identical — a ticking "
            "counter must not change the record day-to-day") {
        CHECK(grace_expiry_date(collection, 43200) == grace_expiry_date(collection, 43200));
    }
    SECTION("no remaining time -> no expiry claim") {
        CHECK(grace_expiry_date(collection, 0).empty());
        CHECK(grace_expiry_date(collection, -5).empty());
    }
}

// ── date helpers ────────────────────────────────────────────────────────────

TEST_CASE("expires_at wire encoding: UTC-midnight epoch decimal string",
          "[licensing][parsers]") {
    CHECK(expiry_wire_from_epoch(0).empty());     // FlexLM permanent sentinel
    CHECK(expiry_wire_from_epoch(-100).empty());
    CHECK(expiry_wire_from_epoch(86399) == "0");  // 1970-01-01 23:59:59 truncates to epoch 0
    // An already-midnight epoch renders as itself; a mid-day epoch truncates.
    CHECK(expiry_wire_from_epoch(epoch_from_civil(2026, 1, 1)) ==
          std::to_string(epoch_from_civil(2026, 1, 1)));
    CHECK(expiry_wire_from_epoch(epoch_from_civil(2024, 2, 29)) ==
          std::to_string(epoch_from_civil(2024, 2, 29))); // leap day
    CHECK(expiry_wire_from_epoch(1798675200 + 3600) == "1798675200"); // any time-of-day → midnight
    // Pinned wire vector — the encoding must not silently drift again.
    CHECK(expiry_wire_from_epoch(epoch_from_civil(2026, 12, 31)) == "1798675200"); // 2026-12-31
}

TEST_CASE("WMI CIM_DATETIME parses to a midnight-epoch expiry", "[licensing][parsers]") {
    CHECK(parse_wmi_datetime_to_expiry("20261231000000.000000+000") == "1798675200"); // 2026-12-31
    SECTION("the 1601 'unset' sentinel and junk map to empty") {
        CHECK(parse_wmi_datetime_to_expiry("16010101000000.000000-000").empty());
        CHECK(parse_wmi_datetime_to_expiry("").empty());
        CHECK(parse_wmi_datetime_to_expiry("not-a-date").empty());
        CHECK(parse_wmi_datetime_to_expiry("2026123").empty()); // too short
        CHECK(parse_wmi_datetime_to_expiry("20261399000000").empty()); // month 13
    }
}

TEST_CASE("openssl -enddate output parses in both date formats", "[licensing][parsers]") {
    CHECK(parse_openssl_enddate("notAfter=2027-03-04 12:00:00Z") == "1804118400");    // 2027-03-04
    CHECK(parse_openssl_enddate("notAfter=Mar  4 12:00:00 2027 GMT") == "1804118400"); // 2027-03-04
    CHECK(parse_openssl_enddate("notBefore=2020-01-01 00:00:00Z").empty());
    CHECK(parse_openssl_enddate("garbage").empty());
    CHECK(parse_openssl_enddate("notAfter=banana").empty());
}

// ── Office ClickToRun release-id classifier ────────────────────────────────

TEST_CASE("Office C2R release ids classify by SKU family", "[licensing][parsers]") {
    // O365*Retail is a subscription SKU despite the Retail suffix.
    CHECK(classify_office_release_id("O365ProPlusRetail") == "subscription");
    CHECK(classify_office_release_id("M365BusinessRetail") == "subscription");
    CHECK(classify_office_release_id("ProPlus2021Volume") == "volume");
    CHECK(classify_office_release_id("HomeBusiness2019Retail") == "retail");
    CHECK(classify_office_release_id("SomethingElse") == "unknown");
    for (const char* id : {"O365ProPlusRetail", "ProPlus2021Volume", "X", ""})
        CHECK(is_valid_license_type(classify_office_release_id(id)));
}

// ── plist reader (macOS identity) ──────────────────────────────────────────

TEST_CASE("plist string values extract from XML plists", "[licensing][parsers]") {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<plist version=\"1.0\"><dict>\n"
        "  <key>CFBundleName</key>\n"
        "  <string>Fun &amp; Games</string>\n"
        "  <key>CFBundleShortVersionString</key>\n"
        "  <string>2.1.0</string>\n"
        "</dict></plist>\n";
    CHECK(plist_string_value(xml, "CFBundleName") == "Fun & Games");
    CHECK(plist_string_value(xml, "CFBundleShortVersionString") == "2.1.0");
    CHECK(plist_string_value(xml, "CFBundleIdentifier").empty());
    SECTION("a key whose value is not the adjacent string never leaks") {
        const std::string tricky = "<key>A</key><integer>3</integer>"
                                   "<key>B</key><string>bee</string>";
        CHECK(plist_string_value(tricky, "A").empty());
        CHECK(plist_string_value(tricky, "B") == "bee");
    }
}

// ── §3.3 layer-1 sanitiser ─────────────────────────────────────────────────

TEST_CASE("record sanitiser strips the §3.3 byte set", "[licensing][record]") {
    const std::string dirty = std::string("a|b\rc\nd") + '\x1F' + "e" + '\x1E' + "f" +
                              std::string(1, '\0') + "g";
    CHECK(sanitize_field(dirty) == "abcdefg");
}

TEST_CASE("record sanitiser clamps to 1024 bytes on a UTF-8 boundary", "[licensing][record]") {
    SECTION("plain ASCII clamps at exactly 1024") {
        CHECK(sanitize_field(std::string(2000, 'a')).size() == 1024);
    }
    SECTION("a multi-byte character is never torn at the clamp") {
        std::string s(1023, 'a');
        s += "\xC3\xA9"; // é — 2 bytes, straddles the 1024 limit
        const std::string out = sanitize_field(s);
        CHECK(out.size() == 1023); // backed up over the split sequence
        CHECK(out == std::string(1023, 'a'));
    }
    SECTION("scrub runs BEFORE the clamp") {
        // 1500 'a' with 600 pipes interleaved: stripping first leaves 1500,
        // clamping to 1024; clamp-first would keep stripped-to-~724.
        std::string s;
        for (int i = 0; i < 1500; ++i) {
            s += 'a';
            if (i < 600)
                s += '|';
        }
        CHECK(sanitize_field(s).size() == 1024);
    }
}

// ── record rendering ────────────────────────────────────────────────────────

TEST_CASE("lic record renders 14 wire fields in §3.1 order", "[licensing][record]") {
    LicRecord r;
    r.product = "WinRAR";
    r.vendor = "win.rar GmbH";
    r.version = "6.24";
    r.license_type = "retail";
    r.channel = "";
    r.status = "licensed";
    r.expires_at = "";
    r.source = "license_file";
    r.confidence = "probable";
    r.key_hint = "ba7816bf8f01";
    r.exe_hints = "winrar.exe";
    r.user_scope = "machine";
    r.user_ref = "";
    const auto fields = split_pipe(render_lic_line(r));
    REQUIRE(fields.size() == 14);
    CHECK(fields[0] == "lic");
    CHECK(fields[1] == "WinRAR");
    CHECK(fields[2] == "win.rar GmbH");
    CHECK(fields[3] == "6.24");
    CHECK(fields[4] == "retail");
    CHECK(fields[5].empty());
    CHECK(fields[6] == "licensed");
    CHECK(fields[7].empty());
    CHECK(fields[8] == "license_file");
    CHECK(fields[9] == "probable");
    CHECK(fields[10] == "ba7816bf8f01");
    CHECK(fields[11] == "winrar.exe");
    CHECK(fields[12] == "machine");
    CHECK(fields[13].empty());
}

TEST_CASE("non-ASCII product/vendor round-trip through render intact (R17)",
          "[licensing][record]") {
    LicRecord r;
    r.product = "Софтуер за счетоводство";      // Cyrillic
    r.vendor = "株式会社ソフトウェア";            // CJK
    r.version = "v2·1";                          // interpunct
    r.status = "licensed";
    r.user_scope = "user";
    r.user_ref = "aléx";                         // accented profile name
    const auto fields = split_pipe(render_lic_line(r));
    REQUIRE(fields.size() == 14);
    CHECK(fields[1] == "Софтуер за счетоводство");
    CHECK(fields[2] == "株式会社ソフトウェア");
    CHECK(fields[3] == "v2·1");
    CHECK(fields[13] == "aléx");
}

TEST_CASE("field injection cannot forge extra wire fields", "[licensing][record]") {
    LicRecord r;
    r.product = "Evil|Product\nlic|forged";
    r.status = "licensed";
    const auto fields = split_pipe(render_lic_line(r));
    REQUIRE(fields.size() == 14); // the | and LF were stripped, not split
    CHECK(fields[1] == "EvilProductlicforged");
}

TEST_CASE("probe_status lines render ok and error shapes", "[licensing][record]") {
    CHECK(render_probe_status_line({"slp_wmi", true, 7, {}}) == "probe_status|slp_wmi|ok|7");
    CHECK(render_probe_status_line({"per_user_hives", false, 0, "privilege_missing"}) ==
          "probe_status|per_user_hives|error|privilege_missing");
    SECTION("error messages are sanitised too") {
        CHECK(render_probe_status_line({"s", false, 0, "bad|msg\r\n"}) ==
              "probe_status|s|error|badmsg");
    }
}

// ── closed-vocabulary discipline (§3.2) ─────────────────────────────────────

TEST_CASE("default-constructed records are honest unknowns", "[licensing][record]") {
    const LicRecord r;
    CHECK(r.license_type == "unknown");
    CHECK(r.status == "unknown");
    CHECK(r.user_scope == "machine");
    CHECK(is_valid_license_type(r.license_type));
    CHECK(is_valid_status(r.status));
    CHECK(is_valid_source(r.source));
    CHECK(is_valid_confidence(r.confidence));
}

TEST_CASE("vocabulary helpers pin the §3.2 sets exactly", "[licensing][record]") {
    for (auto v : kLicenseTypes)
        CHECK(is_valid_license_type(v));
    for (auto v : kStatuses)
        CHECK(is_valid_status(v));
    for (auto v : kSources)
        CHECK(is_valid_source(v));
    for (auto v : kConfidences)
        CHECK(is_valid_confidence(v));
    CHECK_FALSE(is_valid_status("active"));           // not in the vocabulary
    CHECK_FALSE(is_valid_license_type("commercial")); // ditto
    CHECK_FALSE(is_valid_source("wmi"));              // ditto
    CHECK_FALSE(is_valid_confidence("certain"));      // ditto
}

// ── entitlement_certs_outcome (pure decision seam, Wave 4 PR4.3b gate-3) ───

TEST_CASE("entitlement_certs_outcome: a budget-exhausted scan is never clean",
          "[licensing][entitlement_certs]") {
    // Whatever was parsed before the deadline is kept as real data (the
    // `rows` count), but the outcome must never read as a completed scan --
    // certs were left unexamined.
    auto o = entitlement_certs_outcome(/*budget_exhausted=*/true, /*emitted=*/3,
                                       /*any_parse_failure=*/false);
    CHECK_FALSE(o.ok);
    CHECK(o.rows == 3);
    CHECK(o.error == "cert_scan_budget_exhausted");

    // Budget exhaustion wins even alongside a parse failure -- one reason is
    // reported, not both, and it's the one that stopped the scan.
    auto o2 = entitlement_certs_outcome(true, 1, true);
    CHECK_FALSE(o2.ok);
    CHECK(o2.error == "cert_scan_budget_exhausted");
}

TEST_CASE("entitlement_certs_outcome: every cert failing is total failure, not partial",
          "[licensing][entitlement_certs]") {
    auto o = entitlement_certs_outcome(/*budget_exhausted=*/false, /*emitted=*/0,
                                       /*any_parse_failure=*/true);
    CHECK_FALSE(o.ok);
    CHECK(o.rows == 0);
    CHECK(o.error == "cert_parse_failed");
}

TEST_CASE("entitlement_certs_outcome: a mix of parsed and unreadable certs is never clean",
          "[licensing][entitlement_certs]") {
    // THE regression this function exists to prevent: at least one cert
    // parsed AND at least one failed used to report a clean success, so the
    // corrupt/lapsed cert vanished from this authoritative compliance
    // surface with no trace.
    auto o = entitlement_certs_outcome(/*budget_exhausted=*/false, /*emitted=*/2,
                                       /*any_parse_failure=*/true);
    CHECK_FALSE(o.ok);
    CHECK(o.rows == 2);
    CHECK(o.error == "cert_parse_partial");
    // Distinct from the total-failure reason -- an operator needs to tell
    // "some certs unreadable" from "couldn't read any of them".
    CHECK(o.error != "cert_parse_failed");
}

TEST_CASE("entitlement_certs_outcome: every cert parsing cleanly is a genuine success",
          "[licensing][entitlement_certs]") {
    auto o = entitlement_certs_outcome(/*budget_exhausted=*/false, /*emitted=*/5,
                                       /*any_parse_failure=*/false);
    CHECK(o.ok);
    CHECK(o.rows == 5);
    CHECK(o.error.empty());

    // Zero certs found (no failure, nothing to fail) is also clean --
    // structurally a successful probe of an empty surface (ADR-0024 D3).
    auto o2 = entitlement_certs_outcome(false, 0, false);
    CHECK(o2.ok);
    CHECK(o2.rows == 0);
}
