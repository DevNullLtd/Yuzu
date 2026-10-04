/**
 * test_filesystem_acl_parsers.cpp -- filesystem_acl_parsers.hpp: Linux
 * posix_acl xattr decoder, macOS acl_to_text parser, Windows ACE formatters.
 *
 * Linux bytes and macOS text are REAL captures under
 * tests/unit/fixtures/wave11/filesystem_acl/ (see the *.provenance.txt files).
 * The Windows formatters take plain integers, so their tables and the
 * object-ACE offset arithmetic are pinned directly (no fabricated ACE blobs).
 * The syscall-backed macOS cases at the bottom run on __APPLE__ only.
 */

#include <catch2/catch_test_macros.hpp>

#include "filesystem_acl_parsers.hpp"
#include "test_helpers.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if defined(__APPLE__)
#include <membership.h>
#include <sys/acl.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <iostream>
#include <memory>
#include <type_traits>
#endif

namespace fs = std::filesystem;
using namespace yuzu::filesystem::acl;

namespace {

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

std::string read_fixture(const std::string& os, const std::string& name) {
    const auto path = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave11" / "filesystem_acl" / os / name;
    INFO("fixture path: " << path.string());
    REQUIRE(fs::exists(path));
    REQUIRE(fs::exists(fs::path{path.string() + ".provenance.txt"}));
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// `0x0200...` on one line -> raw bytes.
std::string hex_bytes(const std::string& text) {
    std::string out;
    auto p = text.find("0x");
    REQUIRE(p != std::string::npos);
    for (p += 2; p + 1 < text.size() && std::isxdigit(static_cast<unsigned char>(text[p])); p += 2)
        out.push_back(static_cast<char>(std::stoi(text.substr(p, 2), nullptr, 16)));
    return out;
}

std::vector<std::string> rows(const std::vector<PosixAclEntry>& v, bool is_default) {
    std::vector<std::string> out;
    for (const auto& e : v)
        out.push_back(format_posix_ace(e, "", is_default));
    return out;
}

}  // namespace

// ── row_field ───────────────────────────────────────────────────────────────

TEST_CASE("row_field: folds CR/LF and a trailing backslash, keeps interior backslashes",
          "[filesystem][acl]") {
    CHECK(row_field("a\r\nb") == "a  b");
    CHECK(row_field("BUILTIN\\Users") == "BUILTIN\\Users");
    CHECK(row_field("name\\") == "name/");
    CHECK(row_field("a|b") == "a\\|b");
    CHECK(row_field("") == "");
}

// ── Linux ───────────────────────────────────────────────────────────────────

TEST_CASE("decode_posix_acl_xattr: access fixture decodes to the getfacl entries",
          "[filesystem][acl][linux]") {
    auto acl = decode_posix_acl_xattr(hex_bytes(read_fixture("linux", "posix_acl_access.hex")));
    REQUIRE(acl.has_value());
    REQUIRE(acl->size() == 6);
    CHECK(acl->at(0).tag == kAclUserObj);
    CHECK(acl->at(1).tag == kAclUser);
    CHECK(acl->at(1).id == 1001);
    CHECK(acl->at(3).tag == kAclGroup);
    CHECK(acl->at(3).id == 1002);
    CHECK(acl->at(4).tag == kAclMask);
    CHECK(acl->at(5).tag == kAclOther);
    CHECK(acl->at(0).id == kPosixAclUndefinedId);

    // getfacl -n: user::rw- user:1001:rw- group::r-- group:1002:r-x mask::rwx other::r--
    CHECK(format_posix_ace(acl->at(0), "", false) == "ace|user|-|rw-|-");
    CHECK(format_posix_ace(acl->at(1), "1001", false) == "ace|user|1001|rw-|-");
    CHECK(format_posix_ace(acl->at(2), "", false) == "ace|group|-|r--|-");
    CHECK(format_posix_ace(acl->at(3), "1002", false) == "ace|group|1002|r-x|-");
    CHECK(format_posix_ace(acl->at(4), "", false) == "ace|mask|-|rwx|-");
    CHECK(format_posix_ace(acl->at(5), "", false) == "ace|other|-|r--|-");
}

TEST_CASE("decode_posix_acl_xattr: default fixture rows end in |default", "[filesystem][acl][linux]") {
    auto acl = decode_posix_acl_xattr(hex_bytes(read_fixture("linux", "posix_acl_default.hex")));
    REQUIRE(acl.has_value());
    REQUIRE(acl->size() == 6);
    // getfacl -n: default:user::rwx user:1001:rwx group::r-x group:1002:r-x mask::rwx other::r-x
    CHECK(rows(*acl, true) == std::vector<std::string>{
                                  "ace|user|-|rwx|default", "ace|user|1001|rwx|default",
                                  "ace|group|-|r-x|default", "ace|group|1002|r-x|default",
                                  "ace|mask|-|rwx|default", "ace|other|-|r-x|default"});
}

TEST_CASE("decode_posix_acl_xattr: bad input is nullopt, never partial", "[filesystem][acl][linux]") {
    const std::string good = hex_bytes(read_fixture("linux", "posix_acl_access.hex"));
    CHECK_FALSE(decode_posix_acl_xattr("").has_value());
    CHECK_FALSE(decode_posix_acl_xattr(std::string_view{good}.substr(0, 3)).has_value());
    CHECK_FALSE(decode_posix_acl_xattr(std::string_view{good}.substr(0, good.size() - 5)).has_value());
    CHECK_FALSE(decode_posix_acl_xattr(good + std::string(5, '\0')).has_value());
    std::string bad_version = good;
    bad_version[0] = 0x01;
    CHECK_FALSE(decode_posix_acl_xattr(bad_version).has_value());
    // header only: valid, zero entries
    auto empty = decode_posix_acl_xattr(std::string_view{good}.substr(0, 4));
    REQUIRE(empty.has_value());
    CHECK(empty->empty());
}

TEST_CASE("format_posix_ace: numeric fallback and unknown tag", "[filesystem][acl][linux]") {
    CHECK(format_posix_ace({kAclUser, 6, 1001}, "", false) == "ace|user|1001|rw-|-");
    CHECK(format_posix_ace({kAclGroup, 5, 7}, "wheel", true) == "ace|group|wheel|r-x|default");
    CHECK(format_posix_ace({0x40, 0, 0}, "", false) == "ace|other|-|---|-");
}

// ── macOS ───────────────────────────────────────────────────────────────────

TEST_CASE("parse_acl_to_text: captured fixture", "[filesystem][acl][macos]") {
    auto acl = parse_acl_to_text(read_fixture("macos", "acl_to_text.txt"));
    REQUIRE(acl.has_value());
    CHECK(acl->acl_flags.empty());
    REQUIRE(acl->entries.size() >= 4);
    // Fixture order is libSystem's canonical order: deny entries first.
    const auto& deny = acl->entries[0];
    CHECK(deny.kind == "group");
    CHECK(deny.name == "staff");
    CHECK(deny.id == "20");
    CHECK_FALSE(deny.allow);
    CHECK(deny.flags == std::vector<std::string>{"limit_inherit"});
    CHECK(deny.perms == std::vector<std::string>{"write"});
    CHECK(format_macos_ace(deny) == "ace|deny|group:staff|write|limit_inherit");

    const auto& allow = acl->entries[1];
    CHECK(allow.kind == "user");
    CHECK(allow.name == "_user");
    CHECK(allow.id == "501");
    CHECK(allow.allow);
    CHECK(allow.flags == std::vector<std::string>{"file_inherit", "directory_inherit", "only_inherit"});
    CHECK(format_macos_ace(allow) ==
          "ace|allow|user:_user|read|file_inherit,directory_inherit,only_inherit");

    // Unresolved principals: UUID is the only identity and stays distinct.
    std::vector<std::string> principals;
    for (std::size_t i = 2; i < acl->entries.size(); ++i) {
        const auto& e = acl->entries[i];
        CHECK(e.name.empty());
        CHECK(e.id.empty());
        CHECK(e.uuid.size() == 36);
        auto row = format_macos_ace(e);
        CHECK(row == "ace|allow|user:" + e.uuid + "|read|-");
        principals.push_back(row);
    }
    CHECK(principals.size() >= 2);
    CHECK(principals[0] != principals[1]);
}

TEST_CASE("parse_acl_to_text: header flags, inherited, malformed", "[filesystem][acl][macos]") {
    auto acl = parse_acl_to_text("!#acl 1 no_inherit,defer_inherit\n"
                                 "user:85E6C1E9-58CF-44B9-B988-C43D934BF026:u:501:allow,inherited:read,write\n");
    REQUIRE(acl.has_value());
    CHECK(acl->acl_flags == std::vector<std::string>{"no_inherit", "defer_inherit"});
    REQUIRE(acl->entries.size() == 1);
    CHECK(acl->entries[0].flags == std::vector<std::string>{"inherited"});
    CHECK(format_macos_ace(acl->entries[0]) == "ace|allow|user:u|read,write|inherited");

    CHECK_FALSE(parse_acl_to_text("user:UUID:u:501:allow:read\n").has_value());  // no header
    CHECK_FALSE(parse_acl_to_text("").has_value());
    CHECK_FALSE(parse_acl_to_text("!#acl 12\n").has_value());
    CHECK_FALSE(parse_acl_to_text("!#acl 1\nuser:UUID:u:501:allow\n").has_value());  // 5 fields
    CHECK_FALSE(parse_acl_to_text("!#acl 1\nuser:UUID:u:501:maybe:read\n").has_value());
    auto none = parse_acl_to_text("!#acl 1\n");
    REQUIRE(none.has_value());
    CHECK(none->entries.empty());
}

TEST_CASE("format_macos_ace: principal rule", "[filesystem][acl][macos]") {
    MacosAclEntry e{"user", "U-1", "", "77", true, {}, {"read"}};
    CHECK(format_macos_ace(e) == "ace|allow|user:#77|read|-");
    e.id.clear();
    CHECK(format_macos_ace(e) == "ace|allow|user:U-1|read|-");
    e.perms.clear();
    CHECK(format_macos_ace(e) == "ace|allow|user:U-1|-|-");
}

// ── Windows ─────────────────────────────────────────────────────────────────

TEST_CASE("windows ACE name tables", "[filesystem][acl][windows]") {
    CHECK(win_ace_type_name(0x0) == "allow");
    CHECK(win_ace_type_name(0x1) == "deny");
    CHECK(win_ace_type_name(0x5) == "allow_object");
    CHECK(win_ace_type_name(0x6) == "deny_object");
    CHECK(win_ace_type_name(0x9) == "allow_conditional");
    CHECK(win_ace_type_name(0xA) == "deny_conditional");
    CHECK(win_ace_type_name(0x2) == "other");
    CHECK(win_ace_type_name(0xFF) == "other");

    CHECK(win_ace_flags(0) == "-");
    CHECK(win_ace_flags(0x13) == "object_inherit,container_inherit,inherited");
    CHECK(win_ace_flags(0x0C) == "no_propagate,inherit_only");

    CHECK(win_control_flags(0) == "-");
    CHECK(win_control_flags(0x1400) == "protected,auto_inherited");
    CHECK(win_control_flags(0x1000) == "protected");
    CHECK(win_control_flags(0x0400) == "auto_inherited");
    CHECK(format_control_row(0x1400) == "control|protected,auto_inherited");
}

TEST_CASE("format_win_ace: keeps the legacy four-field prefix", "[filesystem][acl][windows]") {
    CHECK(format_win_ace(0, 0x10, "BUILTIN\\Users", 0x001200a9) ==
          "ace|allow|BUILTIN\\Users|0x001200a9|inherited");
    CHECK(format_win_ace(1, 0, "a|b", 0x1) == "ace|deny|a\\|b|0x00000001|-");
    CHECK(format_win_ace(0x42, 0, "x", 0) == "ace|other|x|0x00000000|-");
}

TEST_CASE("win_object_ace_sid_offset: 12 + 16 per present GUID", "[filesystem][acl][windows]") {
    const std::pair<std::uint32_t, std::size_t> cases[] = {{0, 12}, {1, 28}, {2, 28}, {3, 44}};
    for (auto [flags, off] : cases) {
        CAPTURE(flags);
        CHECK(win_object_ace_sid_offset(flags, static_cast<std::uint16_t>(off + 8)) == off);
        CHECK_FALSE(win_object_ace_sid_offset(flags, static_cast<std::uint16_t>(off + 7)).has_value());
    }
}

// ── macOS real syscalls ─────────────────────────────────────────────────────

#if defined(__APPLE__)
namespace {

using AclPtr = std::unique_ptr<std::remove_pointer_t<acl_t>, int (*)(void*)>;
using TextPtr = std::unique_ptr<char, int (*)(void*)>;

// Sets a file ACL of allow/read entries for the given qualifier UUIDs and returns
// the acl_to_text() round trip.
std::string roundtrip(const fs::path& file, const std::vector<uuid_t*>& quals) {
    AclPtr acl{acl_init(static_cast<int>(quals.size())), acl_free};
    REQUIRE(acl);
    for (auto* q : quals) {
        acl_entry_t entry = nullptr;
        acl_t raw = acl.release();
        const int rc = acl_create_entry(&raw, &entry);
        acl.reset(raw);
        REQUIRE(rc == 0);
        REQUIRE(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0);
        REQUIRE(acl_set_qualifier(entry, q) == 0);
        acl_permset_t perms = nullptr;
        REQUIRE(acl_get_permset(entry, &perms) == 0);
        REQUIRE(acl_add_perm(perms, ACL_READ_DATA) == 0);
    }
    REQUIRE(acl_set_file(file.c_str(), ACL_TYPE_EXTENDED, acl.get()) == 0);
    AclPtr got{acl_get_file(file.c_str(), ACL_TYPE_EXTENDED), acl_free};
    REQUIRE(got);
    TextPtr text{acl_to_text(got.get(), nullptr), acl_free};
    REQUIRE(text);
    return text.get();
}

fs::path make_file(const yuzu::test::TempDir& d) {
    fs::create_directories(d.path);
    auto f = d.path / "f";
    std::ofstream{f} << "x";
    return f;
}

}  // namespace

TEST_CASE("acl_to_text round trip: resolved principal", "[filesystem][acl][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_acl_"};
    uuid_t www;
    REQUIRE(mbr_uid_to_uuid(70, www) == 0);  // _www
    auto text = roundtrip(make_file(dir), {&www});
    auto acl = parse_acl_to_text(text);
    REQUIRE(acl.has_value());
    REQUIRE(acl->entries.size() == 1);
    CHECK(format_macos_ace(acl->entries[0]) == "ace|allow|user:_www|read|-");
}

TEST_CASE("acl_to_text round trip: unresolved principals keep distinct UUIDs",
          "[filesystem][acl][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_acl_"};
    uuid_t a, b;
    uuid_generate_random(a);
    uuid_generate_random(b);
    auto text = roundtrip(make_file(dir), {&a, &b});
    std::cout << "CAPTURED acl_to_text:\n" << text << std::flush;
    auto acl = parse_acl_to_text(text);
    REQUIRE(acl.has_value());
    REQUIRE(acl->entries.size() == 2);
    std::vector<std::string> principals;
    for (const auto& e : acl->entries) {
        CHECK(e.name.empty());
        CHECK(e.id.empty());
        CHECK(format_macos_ace(e) == "ace|allow|user:" + e.uuid + "|read|-");
        principals.push_back(format_macos_ace(e));
    }
    CHECK(principals[0] != principals[1]);
}
#endif
