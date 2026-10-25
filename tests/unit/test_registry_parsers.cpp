/**
 * test_registry_parsers.cpp -- the registry plugin's pure layer (registry_parsers.hpp): value
 * encoders, validators, token mapping and the audit-line renderer. OS-free: no registry, file,
 * process or clock, so it runs on every host in the agent suite. The expected bytes are written out literally (UTF-16LE
 * little-endian), never recomputed with the code under test.
 *
 * Win32 sources behind the non-obvious rules: RegSetValueExW's cbData includes the terminating NUL
 * of a string type; registry element size limits are 255 characters per key name and 16,383 per
 * value name (learn.microsoft.com/windows/win32/sysinfo/registry-element-size-limits).
 */
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

#include "registry_parsers.hpp"

using namespace yuzu::registry;
using yuzu::profiles::kRegBinary;
using yuzu::profiles::kRegDword;
using yuzu::profiles::kRegExpandSz;
using yuzu::profiles::kRegMultiSz;
using yuzu::profiles::kRegQword;
using yuzu::profiles::kRegSz;
using Bytes = std::vector<std::uint8_t>;

namespace {

Bytes B(std::initializer_list<int> v) {
    Bytes out;
    for (const int x : v) out.push_back(static_cast<std::uint8_t>(x));
    return out;
}

} // namespace

TEST_CASE("registry parse_reg_type: the six writable names; case-sensitive; nothing else",
          "[registry][parsers]") {
    CHECK(parse_reg_type("REG_SZ") == kRegSz);
    CHECK(parse_reg_type("REG_EXPAND_SZ") == kRegExpandSz);
    CHECK(parse_reg_type("REG_BINARY") == kRegBinary);
    CHECK(parse_reg_type("REG_DWORD") == kRegDword);
    CHECK(parse_reg_type("REG_MULTI_SZ") == kRegMultiSz);
    CHECK(parse_reg_type("REG_QWORD") == kRegQword);
    for (const char* bad : {"reg_sz", "Reg_Sz", "REG_LINK", "REG_NONE", "REG_DWORD_BIG_ENDIAN",
                            "REG_UNKNOWN", "", "garbage", "REG_SZ ", " REG_SZ"})
        CHECK_FALSE(parse_reg_type(bad).has_value());
    CHECK(is_writable_type(kRegSz));
    CHECK_FALSE(is_writable_type(0));  // REG_NONE
    CHECK_FALSE(is_writable_type(6));  // REG_LINK
    CHECK_FALSE(is_writable_type(5));  // REG_DWORD_BIG_ENDIAN
}

TEST_CASE("registry encode REG_DWORD / REG_QWORD: decimal digits only; range-checked",
          "[registry][parsers]") {
    SECTION("accepted values, little-endian") {
        CHECK(encode_value(kRegDword, "0", {}, false).bytes == B({0, 0, 0, 0}));
        CHECK(encode_value(kRegDword, "4294967295", {}, false).bytes == B({0xff, 0xff, 0xff, 0xff}));
        CHECK(encode_value(kRegDword, "16909060", {}, false).bytes == B({0x04, 0x03, 0x02, 0x01}));
        CHECK(encode_value(kRegQword, "18446744073709551615", {}, false).bytes ==
              B({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));
        CHECK(encode_value(kRegQword, "4294967296", {}, false).bytes == B({0, 0, 0, 0, 1, 0, 0, 0}));
    }
    SECTION("out of range is value_overflow") {
        CHECK(encode_value(kRegDword, "4294967296", {}, false).error == kTokValueOverflow);
        CHECK(encode_value(kRegQword, "18446744073709551616", {}, false).error == kTokValueOverflow);
        CHECK(encode_value(kRegDword, "99999999999999999999999999", {}, false).error == kTokValueOverflow);
    }
    SECTION("any other shape is invalid_data") {
        for (const char* bad : {"", "-1", "+1", "1 ", " 1", "0x10", "1.5", "12abc", "abc", "1e3", "\t7"})
            CHECK(encode_value(kRegDword, bad, {}, false).error == kTokInvalidData);
        CHECK(encode_value(kRegQword, "-1", {}, false).error == kTokInvalidData);
        CHECK(encode_value(kRegQword, "", {}, false).error == kTokInvalidData);
    }
    SECTION("data_hex must be exactly 4 / 8 bytes") {
        CHECK(encode_value(kRegDword, {}, "01000000", true).bytes == B({1, 0, 0, 0}));
        CHECK(encode_value(kRegDword, {}, "010000", true).error == kTokInvalidData);
        CHECK(encode_value(kRegDword, {}, "0100000000", true).error == kTokInvalidData);
        CHECK(encode_value(kRegQword, {}, "0100000000000000", true).bytes == B({1, 0, 0, 0, 0, 0, 0, 0}));
        CHECK(encode_value(kRegQword, {}, "01000000", true).error == kTokInvalidData);
    }
}

TEST_CASE("registry encode REG_SZ / REG_EXPAND_SZ: strict UTF-8 to UTF-16LE plus the terminating NUL",
          "[registry][parsers]") {
    for (const auto type : {kRegSz, kRegExpandSz}) {
        CHECK(encode_value(type, "", {}, false).bytes == B({0, 0})); // empty: one NUL wchar, cbData 2
        CHECK(encode_value(type, "a", {}, false).bytes == B({0x61, 0, 0, 0}));
        CHECK(encode_value(type, "\xC3\xA9", {}, false).bytes == B({0xE9, 0, 0, 0}));       // U+00E9
        CHECK(encode_value(type, "\xE2\x82\xAC", {}, false).bytes == B({0xAC, 0x20, 0, 0})); // U+20AC
        // U+1F600 -> the surrogate pair D83D DE00
        CHECK(encode_value(type, "\xF0\x9F\x98\x80", {}, false).bytes == B({0x3D, 0xD8, 0x00, 0xDE, 0, 0}));
        CHECK(encode_value(type, "\xC3", {}, false).error == kTokInvalidData);          // truncated
        CHECK(encode_value(type, "\xC0\x80", {}, false).error == kTokInvalidData);      // overlong NUL
        CHECK(encode_value(type, "\xED\xA0\x80", {}, false).error == kTokInvalidData);  // surrogate
        CHECK(encode_value(type, std::string_view{"a\0b", 3}, {}, false).error == kTokInvalidData);
    }
    SECTION("the 1 MiB write cap is on the encoded bytes") {
        const std::string fits(kMaxWriteBytes / 2 - 1, 'x'); // + NUL = exactly kMaxWriteBytes bytes
        CHECK(encode_value(kRegSz, fits, {}, false).bytes.size() == kMaxWriteBytes);
        const std::string over(kMaxWriteBytes / 2, 'x');
        CHECK(encode_value(kRegSz, over, {}, false).error == kTokValueOverflow);
    }
    SECTION("data_hex needs an even count ending in a NUL code unit") {
        CHECK(encode_value(kRegSz, {}, "61000000", true).bytes == B({0x61, 0, 0, 0}));
        CHECK(encode_value(kRegSz, {}, "0000", true).bytes == B({0, 0}));
        CHECK(encode_value(kRegSz, {}, "6100", true).error == kTokInvalidData);  // no terminator
        CHECK(encode_value(kRegSz, {}, "610000", true).error == kTokInvalidData); // odd byte count
        CHECK(encode_value(kRegSz, {}, "", true).error == kTokInvalidData);       // present but empty
    }
}

TEST_CASE("registry encode REG_MULTI_SZ: LF-separated records; empty text is the lone double NUL",
          "[registry][parsers]") {
    CHECK(encode_value(kRegMultiSz, "", {}, false).bytes == B({0, 0, 0, 0}));
    CHECK(encode_value(kRegMultiSz, "a", {}, false).bytes == B({0x61, 0, 0, 0, 0, 0}));
    CHECK(encode_value(kRegMultiSz, "a\nb", {}, false).bytes == B({0x61, 0, 0, 0, 0x62, 0, 0, 0, 0, 0}));
    for (const char* bad : {"a\n\nb", "a\n", "\n", "\na"})
        CHECK(encode_value(kRegMultiSz, bad, {}, false).error == kTokInvalidData);
    CHECK(encode_value(kRegMultiSz, std::string_view{"a\0b", 3}, {}, false).error == kTokInvalidData);
    SECTION("the 1 MiB cap holds on the text and on the encoded bytes") {
        // mutants: the text-size check removed; the encoded-size check removed
        CHECK(encode_value(kRegMultiSz, std::string(kMaxWriteBytes + 1, 'x'), {}, false).error == kTokValueOverflow);
        // 600,000 ASCII characters are within the text bound but encode to 1,200,004 bytes (UTF-16, a record NUL
        // and the list NUL): over the cap.
        CHECK(encode_value(kRegMultiSz, std::string(600000, 'x'), {}, false).error == kTokValueOverflow);
        // The edge: 524,286 characters encode to exactly kMaxWriteBytes, one more to two bytes over.
        CHECK(encode_value(kRegMultiSz, std::string(524286, 'x'), {}, false).bytes.size() == kMaxWriteBytes);
        CHECK(encode_value(kRegMultiSz, std::string(524287, 'x'), {}, false).error == kTokValueOverflow);
    }
    SECTION("data_hex") {
        CHECK(encode_value(kRegMultiSz, {}, "610000000000", true).bytes == B({0x61, 0, 0, 0, 0, 0}));
        CHECK(encode_value(kRegMultiSz, {}, "00000000", true).bytes == B({0, 0, 0, 0}));
        CHECK(encode_value(kRegMultiSz, {}, "61000000", true).error == kTokInvalidData); // single NUL only
        CHECK(encode_value(kRegMultiSz, {}, "6100000000", true).error == kTokInvalidData); // odd count
        CHECK(encode_value(kRegMultiSz, {}, "0000", true).error == kTokInvalidData);       // too short
    }
}

TEST_CASE("registry encode REG_BINARY: value is hex; empty is zero bytes", "[registry][parsers]") {
    CHECK(encode_value(kRegBinary, "", {}, false).bytes.empty());
    CHECK(encode_value(kRegBinary, "", {}, false).error.empty());
    CHECK(encode_value(kRegBinary, "0102ff", {}, false).bytes == B({1, 2, 0xff}));
    CHECK(encode_value(kRegBinary, "ABcd", {}, false).bytes == B({0xab, 0xcd}));
    CHECK(encode_value(kRegBinary, "abc", {}, false).error == kTokInvalidData);
    CHECK(encode_value(kRegBinary, "zz", {}, false).error == kTokInvalidData);
    CHECK(encode_value(kRegBinary, "0x", {}, false).error == kTokInvalidData);
    SECTION("the 1 MiB boundary") {
        const std::string fits(kMaxWriteBytes * 2, 'a');
        CHECK(encode_value(kRegBinary, fits, {}, false).bytes.size() == kMaxWriteBytes);
        const std::string over(kMaxWriteBytes * 2 + 2, 'a');
        CHECK(encode_value(kRegBinary, over, {}, false).error == kTokValueOverflow);
        CHECK(encode_value(kRegBinary, {}, over, true).error == kTokValueOverflow);
    }
}

TEST_CASE("registry data_hex precedence: present wins and value must then be empty",
          "[registry][parsers]") {
    CHECK(encode_value(kRegBinary, {}, "0a0b", true).bytes == B({0x0a, 0x0b}));
    CHECK(encode_value(kRegBinary, "0102", "0a0b", true).error == kTokInvalidData); // both provided
    // A present-but-empty data_hex (a JSON "data_hex": "") is the zero-byte form: a BINARY restore.
    const auto zero = encode_value(kRegBinary, {}, "", true);
    CHECK(zero.error.empty());
    CHECK(zero.bytes.empty());
    CHECK(encode_value(kRegBinary, "0102", "", true).error == kTokInvalidData);
    CHECK(encode_value(kRegDword, {}, "", true).error == kTokInvalidData);
    CHECK(encode_value(6, "x", {}, false).error == kTokInvalidType); // a non-writable type
}

TEST_CASE("registry render_hex: cap and the ~<total> marker are byte-exact", "[registry][parsers]") {
    const Bytes b = B({0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
    CHECK(render_hex(b, 4, b.size()) == "00010203~10");
    CHECK(render_hex(b, 10, b.size()) == "00010203040506070809");
    CHECK(render_hex({}, 4, 0).empty());
    // The caller's own capture cap counts too: 4 bytes kept of a 5000-byte value.
    CHECK(render_hex(B({0xde, 0xad, 0xbe, 0xef}), 256, 5000) == "deadbeef~5000");
}

TEST_CASE("registry validate_key_path: boundaries and refusals", "[registry][parsers]") {
    CHECK(validate_key_path("Software").empty());
    CHECK(validate_key_path("Software\\Vendor\\App").empty());
    CHECK(validate_key_path(std::string(255, 'a')).empty());
    CHECK(validate_key_path(std::string(256, 'a')) == kTokInvalidKeyPath);
    SECTION("component count") {
        std::string k32, k33;
        for (int i = 0; i < 32; ++i) k32 += (i ? "\\k" : "k");
        for (int i = 0; i < 33; ++i) k33 += (i ? "\\k" : "k");
        CHECK(validate_key_path(k32).empty());
        CHECK(validate_key_path(k33) == kTokInvalidKeyPath);
    }
    SECTION("empty, dot and separators") {
        for (const char* bad : {"", "\\A", "A\\", "A\\\\B", "\\", ".", "..", "A\\.\\B", "A\\..\\B", "A\\.", "..\\A"})
            CHECK(validate_key_path(bad) == kTokInvalidKeyPath);
    }
    SECTION("a hive alias as the first component") {
        for (const char* bad : {"HKLM", "hklm\\Software", "HKCU\\X", "HKCR\\X", "HKU\\X", "HKCC\\X",
                                "HKEY_LOCAL_MACHINE\\SOFTWARE", "hkey_users\\S-1", "HKEY_CURRENT_USER\\X",
                                "HKEY_CLASSES_ROOT\\X", "HKEY_CURRENT_CONFIG\\X"})
            CHECK(validate_key_path(bad) == kTokInvalidKeyPath);
        CHECK(validate_key_path("Software\\HKLM").empty()); // only the FIRST component is an alias
        CHECK(validate_key_path("HKLMX\\a").empty());
    }
    SECTION("control bytes and invalid UTF-8") {
        CHECK(validate_key_path(std::string_view{"A\0B", 3}) == kTokInvalidKeyPath);
        for (const char* bad : {"A\rB", "A\nB", "A\tB", "A\x01" "B", "A\x7F" "B"})
            CHECK(validate_key_path(bad) == kTokInvalidKeyPath);
        CHECK(validate_key_path("A\xC3") == kTokInvalidKeyPath);
        CHECK(validate_key_path("A\xC0\x80") == kTokInvalidKeyPath);
        CHECK(validate_key_path("A\xFF") == kTokInvalidKeyPath);
        CHECK(validate_key_path("Caf\xC3\xA9\\\xE2\x82\xAC").empty());
    }
    SECTION("a forward slash is ordinary key-name text") {
        CHECK(validate_key_path("MIME\\Database\\Content Type\\application/pdf").empty());
    }
}

TEST_CASE("registry validate_value_name: boundaries and refusals", "[registry][parsers]") {
    CHECK(validate_value_name("").empty()); // the key's default value
    CHECK(validate_value_name("Version").empty());
    CHECK(validate_value_name(std::string(16383, 'n')).empty());
    CHECK(validate_value_name(std::string(16384, 'n')) == kTokInvalidValueName);
    CHECK(validate_value_name(std::string_view{"a\0b", 3}) == kTokInvalidValueName);
    for (const char* bad : {"a\rb", "a\nb", "a\tb", "a\x1F" "b", "a\x7F" "b", "a\xC3", "a\xFF"})
        CHECK(validate_value_name(bad) == kTokInvalidValueName);
    CHECK(validate_value_name("a\\b").empty()); // a value name may contain a backslash
    CHECK(validate_value_name("\xC3\xA9").empty());
}


TEST_CASE("registry rc_token: write-error vocabulary", "[registry][parsers]") {
    CHECK(rc_token(0, Missing::key).empty());
    CHECK(rc_token(5, Missing::key) == "access_denied");
    CHECK(rc_token(2, Missing::key) == "key_not_found");
    CHECK(rc_token(3, Missing::key) == "key_not_found");
    CHECK(rc_token(2, Missing::value) == "value_not_found");
    CHECK(rc_token(3, Missing::value) == "value_not_found");
    CHECK(rc_token(1018, Missing::key) == "concurrent_change");
    CHECK(rc_token(32, Missing::value) == "win32:32");
}

TEST_CASE("registry audit_token: neutralises everything that could forge a field or a line",
          "[registry][parsers]") {
    CHECK(audit_token("a|result=ok|b") == "a_result_ok_b");
    CHECK(audit_token("line1\nline2\rx") == "line1_line2_x");
    CHECK(audit_token("a b,c=d") == "a_b_c_d");
    CHECK(audit_token("") == "-");
    CHECK(audit_token(std::string_view{"a\0b", 3}) == "a?b");                 // NUL cannot cross the C-string ABI
    CHECK(audit_token("ok\xFF" "bad") == "ok?bad");                       // invalid UTF-8 never reaches the wire
    CHECK(audit_token("SOFTWARE\\Acme") == "SOFTWARE\\Acme");             // a backslash inside the token is kept
    // A trailing backslash would read as an escaped separator to the server's splitter and merge two cells.
    CHECK(audit_token("dir\\") == "dir_");
    CHECK(audit_token("\\") == "_");
    CHECK(audit_token("a\\b\\") == "a\\b_");
    CHECK(audit_token("Caf\xC3\xA9") == "Caf\xC3\xA9");                   // valid UTF-8 survives
    SECTION("over the cap: cut on a character boundary, with ~<length>") {
        CHECK(audit_token(std::string(300, 'k')) == std::string(256, 'k') + "~300");
        CHECK(audit_token(std::string(256, 'k')) == std::string(256, 'k')); // exactly the cap: whole
        // 255 ASCII bytes then a 2-byte character: the cut at 256 would split it, so it backs up.
        std::string s(255, 'k');
        s += "\xC3\xA9";
        s += "tail";
        const auto t = audit_token(s);
        CHECK(t == std::string(255, 'k') + "~" + std::to_string(s.size()));
    }
}

TEST_CASE("registry render_audit_line: byte-exact grammar", "[registry][parsers]") {
    AuditRecord r;
    r.op = "set_value";
    r.hive = "HKLM";
    r.key = "SOFTWARE\\Acme";
    r.name = "Ver";
    r.type_name = "REG_DWORD";
    r.len = 4;
    r.result = "ok";
    r.verify = "ok";
    r.created = 2;
    r.old_state = "present";
    r.old_type = "REG_DWORD";
    r.old_bytes = B({1, 0, 0, 0});
    r.old_total = 4;
    r.has_old = true;
    r.new_bytes = B({2, 0, 0, 0});
    r.new_total = 4;
    r.has_new = true;
    CHECK(render_audit_line(r) ==
          "audit|op=set_value|hive=HKLM|result=ok|reason=-|verify=ok|key=SOFTWARE\\Acme|name=Ver|"
          "type=REG_DWORD|len=4|dry_run=-|counted_keys=-|counted_values=-|capped=-|created=2|sid=-|"
          "old_state=present|old_type=REG_DWORD|old=01000000|new=02000000");

    SECTION("a refusal carries its reason and nothing it did not do") {
        AuditRecord x;
        x.op = "delete_value";
        x.hive = "HKCU";
        x.key = "Software\\X";
        x.result = "refused";
        x.reason = "value_not_found";
        x.old_state = "absent";
        CHECK(render_audit_line(x) ==
              "audit|op=delete_value|hive=HKCU|result=refused|reason=value_not_found|verify=-|"
              "key=Software\\X|name=-|type=-|len=-|dry_run=-|counted_keys=-|counted_values=-|capped=-|created=-|sid=-|"
              "old_state=absent|old_type=-|old=-|new=-");
    }
    SECTION("delete_key counts, dry_run and the sid column") {
        AuditRecord x;
        x.op = "delete_key";
        x.hive = "HKU";
        x.key = "k";
        x.result = "ok";
        x.verify = "ok";
        x.dry_run = 1;
        x.counted_keys = 3;
        x.counted_values = 7;
        x.capped = 0;
        x.created = 0;
        x.sid = "S-1-5-21-1-2-3-1001";
        CHECK(render_audit_line(x) ==
              "audit|op=delete_key|hive=HKU|result=ok|reason=-|verify=ok|key=k|name=-|type=-|len=-|"
              "dry_run=1|counted_keys=3|counted_values=7|capped=0|created=0|sid=S-1-5-21-1-2-3-1001|"
              "old_state=-|old_type=-|old=-|new=-");
    }
    SECTION("old and new are capped at 256 raw bytes with ~<total>") {
        AuditRecord x = r;
        x.old_bytes.assign(300, 0xaa);
        x.old_total = 5000;
        x.new_bytes.assign(257, 0xcd);
        x.new_total = 257;
        const auto line = render_audit_line(x);
        CHECK(line.find("|old=" + std::string(512, 'a') + "~5000|new=") != std::string::npos);
        CHECK(line.ends_with("~257"));
    }
    SECTION("every type carries old= and new= as raw hex of the bytes (owner risk acceptance: no redaction)") {
        // mutants: a digest or any masking of a string / list / binary value; the hex dropped for one type
        AuditRecord x = r;
        x.type_name = "REG_SZ"; // "hunter2" as UTF-16LE with its NUL
        x.old_type = "REG_SZ";
        x.old_bytes = B({0x68, 0, 0x75, 0, 0x6e, 0, 0x74, 0, 0x65, 0, 0x72, 0, 0x32, 0, 0, 0});
        x.old_total = x.old_bytes.size();
        x.new_bytes = B({0x61, 0, 0, 0});
        x.new_total = 4;
        CHECK(render_audit_line(x).ends_with("|old=680075006e0074006500720032000000|new=61000000"));
        x.type_name = "REG_MULTI_SZ";
        x.old_type = "REG_MULTI_SZ";
        x.old_bytes = B({0x61, 0, 0, 0, 0, 0});
        x.old_total = 6;
        x.new_bytes = B({0x62, 0, 0, 0, 0, 0});
        x.new_total = 6;
        CHECK(render_audit_line(x).ends_with("|old=610000000000|new=620000000000"));
    }
    SECTION("a REG_BINARY past the 256-byte cap shows 256 raw bytes and ~<total>, a REG_SZ the same") {
        AuditRecord x = r;
        x.type_name = "REG_BINARY";
        x.old_type = "REG_BINARY";
        x.old_bytes.assign(kCaptureValueCap, 0x11); // what capture_old keeps of a 1 MiB value
        x.old_total = 1048576;
        x.new_bytes.assign(5000, 0x22); // the encoder holds the whole value
        x.new_total = 5000;
        CHECK(render_audit_line(x).ends_with("|old=" + std::string(512, '1') + "~1048576|new=" + std::string(512, '2') +
                                             "~5000"));
        x.type_name = "REG_SZ";
        x.old_type = "REG_SZ";
        CHECK(render_audit_line(x).ends_with("|old=" + std::string(512, '1') + "~1048576|new=" + std::string(512, '2') +
                                             "~5000"));
        x.new_bytes.assign(256, 0x22); // exactly the cap: no marker
        x.new_total = 256;
        CHECK(render_audit_line(x).ends_with("|new=" + std::string(512, '2')));
    }
    SECTION("a value name ending in a backslash cannot read as an escaped separator") {
        AuditRecord x = r;
        x.name = "dir\\";
        const auto line = render_audit_line(x);
        CHECK(line.find("|name=dir_|type=REG_DWORD|") != std::string::npos);
        CHECK(line.find("\\|") == std::string::npos);
    }
    SECTION("a 16,383-character name cannot push the mandatory fields past the 4 KiB extractor cap") {
        AuditRecord x = r;
        x.name = std::string(16383, 'n');
        x.key = std::string(255, 'k');
        x.old_bytes.assign(256, 0xff);
        x.old_total = 4096;
        x.new_bytes.assign(256, 0xee);
        x.new_total = 4096;
        const auto line = render_audit_line(x);
        CHECK(line.size() < 2048);
        CHECK(line.starts_with("audit|op=set_value|hive=HKLM|result=ok|reason=-|verify=ok|key="));
        CHECK(line.find("|name=" + std::string(256, 'n') + "~16383|type=REG_DWORD|len=4|dry_run=-|") != std::string::npos);
        CHECK(line.find("|old_state=present|old_type=REG_DWORD|old=") != std::string::npos);
    }
    SECTION("hostile key and name cannot forge a field or a line") {
        AuditRecord x = r;
        x.key = "a|result=ok\naudit|op=x";
        x.name = "n|verify=ok";
        const auto line = render_audit_line(x);
        CHECK(line.find('\n') == std::string::npos);
        CHECK(line.find("|key=a_result_ok_audit_op_x|name=n_verify_ok|") != std::string::npos);
        CHECK(std::count(line.begin(), line.end(), '|') == 19); // the grammar's 20 parts, nothing extra
    }
}

TEST_CASE("registry audit producer contract: no pipe LF or CR survives and the field grammar holds",
          "[registry][parsers]") {
    const std::string hostile = std::string{"a|b\nc\rd=e,f g\t\x1b"} + "\xC3\x28" + std::string{"\0z", 2};
    AuditRecord r;
    r.op = hostile;
    r.hive = hostile;
    r.key = hostile;
    r.name = hostile;
    r.type_name = hostile;
    r.reason = hostile;
    r.sid = hostile;
    r.result = "failed";
    r.verify = "mismatch";
    r.len = 12;
    r.dry_run = 0;
    r.counted_keys = 1;
    r.counted_values = 2;
    r.capped = 0;
    r.created = 0;
    r.old_state = "present";
    r.old_type = "REG_SZ";
    r.old_bytes = B({0x7c, 0x0a, 0x0d});
    r.old_total = 3;
    r.has_old = true;
    r.new_bytes = B({0x3d, 0x2c});
    r.new_total = 2;
    r.has_new = true;
    const std::string line = render_audit_line(r);

    CHECK(line.find('\n') == std::string::npos);
    CHECK(line.find('\r') == std::string::npos);
    for (const char c : line) CHECK(static_cast<unsigned char>(c) >= 0x20); // no control byte at all
    // 20 pipe-separated parts: the tag, then the 19 fields in the published order, each `name=value`.
    std::vector<std::string> parts;
    for (std::size_t pos = 0; pos <= line.size();) {
        const std::size_t bar = std::min(line.find('|', pos), line.size());
        parts.push_back(line.substr(pos, bar - pos));
        pos = bar + 1;
    }
    constexpr std::string_view kOrder[] = {"op",   "hive",     "result",         "reason",         "verify",
                                           "key",  "name",     "type",           "len",            "dry_run",
                                           "counted_keys", "counted_values", "capped", "created", "sid",
                                           "old_state", "old_type", "old",       "new"};
    REQUIRE(parts.size() == 1 + std::size(kOrder));
    CHECK(parts[0] == "audit");
    for (std::size_t i = 0; i < std::size(kOrder); ++i) {
        INFO(kOrder[i]);
        const std::string& part = parts[i + 1];
        CHECK(part.starts_with(std::string{kOrder[i]} + "="));
        CHECK(std::count(part.begin(), part.end(), '=') == 1); // '=' inside a value would read as a second field
    }
    // The server reads `result=` anywhere in the line, but a line over its byte bound loses its tail.
    CHECK(line.find("|result=") < line.find("|key="));
    CHECK(line.find("|reason=") < line.find("|key="));
    CHECK(line.find("|verify=") < line.find("|key="));
    SECTION("maximum-size caller input stays under 2 KiB and the result stays near the front") {
        AuditRecord x = r;
        x.key = std::string(255, 'k');
        x.name = std::string(16383, 'n');
        x.op = "delete_value";
        x.hive = "HKLM";
        x.reason = std::string(300, 'r');
        x.type_name = "REG_MULTI_SZ";
        x.sid = "-";
        x.old_bytes.assign(256, 0xff);
        x.old_total = 1 << 20;
        x.new_bytes.assign(256, 0xee);
        x.new_total = 1 << 20;
        const std::string big = render_audit_line(x);
        CHECK(big.size() < 2048);
        CHECK(big.find("|key=") < 200);
    }
}

TEST_CASE("registry exception_audit_line: one fixed 19-field literal per mutating action", "[registry][parsers]") {
    // The literal is what render_audit_line makes of a record that knows only the op, the failure and its reason.
    for (const char* op : {"set_value", "delete_value", "delete_key"}) {
        INFO(op);
        AuditRecord x;
        x.op = op;
        x.result = "failed";
        x.reason = "exception";
        const auto literal = exception_audit_line(op);
        REQUIRE_FALSE(literal.empty());
        CHECK(literal == render_audit_line(x));
        CHECK(std::count(literal.begin(), literal.end(), '|') == 19); // the tag and 19 fields
        CHECK(literal.starts_with(std::string{"audit|op="} + op + "|hive=-|result=failed|reason=exception|verify=-|key=-|"));
        CHECK(literal.ends_with("|old_state=-|old_type=-|old=-|new=-"));
    }
    SECTION("a read action, an unknown one and the empty name have none") {
        for (const char* action : {"get_value", "key_exists", "enumerate_keys", "enumerate_values", "get_user_value",
                                   "list_profiles", "", "Set_Value", "set_value "})
            CHECK(exception_audit_line(action).empty());
    }
}
