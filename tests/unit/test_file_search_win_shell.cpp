/**
 * test_file_search_win_shell.cpp -- the Windows shell of the file_search plugin (file_search_win.cpp) over a
 * salted yuzu_test_ temp tree: the leg's listing, root check and facts, the two ioctls, the volume reader, the
 * name rule, the cursor key, the profile roots and the worker environment. Every DECISION it relies on is
 * unit-tested portably in test_file_search_win_rules.cpp; this file proves the binding.
 *
 * The body is Windows-only. One always-run case elsewhere keeps the TU from being empty on POSIX hosts.
 *
 * Cases that need NTFS (ids, resident and sparse extents, compression, external backing) say so and skip with
 * a message elsewhere; none passes by skipping silently.
 */
#include <catch2/catch_test_macros.hpp>

#include "file_search_execute.hpp"
#include "file_search_test_support.hpp"
#include "file_search_win_rules.hpp"
#include "test_helpers.hpp"
#include "win_junction_test_support.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// AFTER <windows.h>: these depend on the base Windows types.
#include <aclapi.h>
#include <winioctl.h> // FSCTL_SET_SPARSE, FSCTL_SET_COMPRESSION, FSCTL_SET_EXTERNAL_BACKING, WOF_EXTERNAL_INFO

#include <win_profiles.hpp>
#include <win_str.hpp>
#endif

namespace fs = std::filesystem;
using namespace yuzu::file_search;
using yuzu::file_search_test::Fixture;
namespace wr = yuzu::file_search::win_rules;

#if !defined(_WIN32)

TEST_CASE("file_search windows shell: the body is Windows-only", "[file_search][file_search_win_shell]") {
    SUCCEED("the Windows shell cases run on a Windows host");
}

#else

namespace {

constexpr DWORD kShareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// An owning HANDLE for the test's own fixture work (never the code under test).
struct Owned {
    HANDLE h{INVALID_HANDLE_VALUE};
    explicit Owned(HANDLE x) : h(x) {}
    ~Owned() {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
    Owned(const Owned&) = delete;
    Owned& operator=(const Owned&) = delete;
    [[nodiscard]] bool ok() const { return h != INVALID_HANDLE_VALUE; }
};

void write_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << content;
}

/// The canonical label of a Windows path, as the rows spell it.
std::string label_of(const fs::path& p) {
    const auto label = wr::normalise_windows_root(p.string());
    REQUIRE(label.has_value());
    return *label;
}

/// The one planned unit of `root`, from the real volume reader and the unchanged plan.
Unit unit_for(const fs::path& root) {
    const std::string label = label_of(root);
    const auto table = os_read_mounts(label);
    REQUIRE(table.has_value());
    const VolumePlan plan = build_plan(*table, label, Os::windows);
    REQUIRE(plan.valid);
    REQUIRE(plan.units.size() == 1);
    return plan.units[0];
}

bool on_ntfs(const Unit& u) {
    return u.fstype == "NTFS";
}

const ci::DirEntry* entry_named(const ci::ListResult& r, const std::string& name) {
    for (const auto& e : r.entries)
        if (e.name == name)
            return &e;
    return nullptr;
}

/// Facts of `name` in the directory `dir_label`, through a leg listed first (the driver's order).
struct Probe {
    UnitLeg leg;
    std::string dir;
    Probe(const Unit& u, const std::string& dir_label) : leg(os_make_leg(u)), dir(dir_label) {}
    [[nodiscard]] FileFacts facts(const std::string& name) {
        const ci::ListResult listed = leg.ops.list(dir, 1000);
        REQUIRE_FALSE(listed.error);
        const ci::DirEntry* e = entry_named(listed, name);
        REQUIRE(e != nullptr);
        return leg.facts(dir, *e);
    }
};

/// A file written through the Win32 API, for the cases that need a flag set before or between writes.
struct RawFile {
    Owned h;
    explicit RawFile(const fs::path& p)
        : h(CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE, kShareAll, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                        nullptr)) {}
    bool control(DWORD code, void* in = nullptr, DWORD in_len = 0) const {
        DWORD returned = 0;
        return DeviceIoControl(h.h, code, in, in_len, nullptr, 0, &returned, nullptr) != 0;
    }
    bool write_at(std::uint64_t offset, std::size_t bytes) const {
        LARGE_INTEGER to{};
        to.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(h.h, to, nullptr, FILE_BEGIN))
            return false;
        const std::string data(bytes, 'x');
        DWORD written = 0;
        return WriteFile(h.h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) && written == data.size();
    }
    bool set_length(std::uint64_t length) const {
        LARGE_INTEGER to{};
        to.QuadPart = static_cast<LONGLONG>(length);
        return SetFilePointerEx(h.h, to, nullptr, FILE_BEGIN) && SetEndOfFile(h.h);
    }
    /// NTFS gives a sparse or compressed stream its clusters when the cache is written out, not at WriteFile
    /// (measured: 2 runs unflushed, 80 flushed), so a case that reads physical layout flushes before it probes.
    bool flush() const { return FlushFileBuffers(h.h) != 0; }
};

} // namespace

TEST_CASE("file_search windows shell: the leg is allocation only, and a volume that does not exist answers an error, never a throw",
          "[file_search][file_search_win_shell]") {
    Unit u;
    u.mount_point = "/Volume{00000000-0000-0000-0000-000000000000}";
    u.walk_root = u.mount_point;
    u.root_field = "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\";
    u.fstype = "NTFS";
    UnitLeg leg = os_make_leg(u); // no system call: this returns for any unit
    const auto state = leg.root_state(u.walk_root);
    CHECK((state == ci::RootState::not_found || state == ci::RootState::other));
    const ci::ListResult listed = leg.ops.list(u.walk_root, 10);
    CHECK(listed.error);
    ci::DirEntry e;
    e.name = "x";
    const FileFacts f = leg.facts(u.walk_root, e);
    CHECK_FALSE(f.facts.opened);
    CHECK(f.extents.state == ExtentsState::failed);
}

TEST_CASE("file_search windows shell: a listing names its entries and types, has a device, and ids on NTFS",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_list_"};
    write_file(fx.root / "a.txt", "alpha");
    write_file(fx.root / "b.txt", "");
    write_file(fx.root / "sub" / "inner.txt", "x");
    const Unit u = unit_for(fx.root);
    const std::string label = label_of(fx.root);
    UnitLeg leg = os_make_leg(u);
    const ci::ListResult top = leg.ops.list(label, 100);
    REQUIRE_FALSE(top.error);
    CHECK(top.dev != 0);
    REQUIRE(top.entries.size() == 3);
    REQUIRE(entry_named(top, "a.txt") != nullptr);
    CHECK(entry_named(top, "a.txt")->type == ci::DirEntry::Type::file);
    CHECK(entry_named(top, "sub")->type == ci::DirEntry::Type::dir);
    for (const auto& e : top.entries)
        CHECK_FALSE(e.gap.has_value());
    if (!on_ntfs(u)) {
        WARN("ids skipped: the temp volume is not NTFS (ids read 0 off NTFS)");
        for (const auto& e : top.entries)
            CHECK(e.file_id == 0);
        return;
    }
    for (const auto& e : top.entries)
        CHECK(e.file_id != 0);
    // the id a parent's listing gives a sub-directory is the id list() reports for that sub-directory itself
    // (the listing id against the FileIdInfo low half)
    const ci::ListResult sub = leg.ops.list(label + "/sub", 100);
    REQUIRE_FALSE(sub.error);
    CHECK(sub.file_id == entry_named(top, "sub")->file_id);
    CHECK(sub.dev == top.dev);
}

TEST_CASE("file_search windows shell: a name that cannot round-trip UTF-8 lists as a name_too_long gap, beside an ordinary one",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_badname_"};
    write_file(fx.root / "ordinary.txt", "x");
    // A lone high surrogate cannot round-trip through UTF-8, and NTFS does not validate UTF-16, so a file with
    // this name is creatable without admin. Composed as a std::filesystem::path (its native form on Windows
    // is std::wstring) so the code unit survives untouched, as test_confined_fs_win.cpp builds it.
    const std::wstring bad_name = L"x" + std::wstring(1, static_cast<wchar_t>(0xD800));
    const RawFile bad(fx.root / fs::path(bad_name));
    if (!bad.h.ok())
        SKIP("a lone-surrogate file name cannot be created on this volume");
    const Unit u = unit_for(fx.root);
    UnitLeg leg = os_make_leg(u);
    const ci::ListResult top = leg.ops.list(label_of(fx.root), 100);
    REQUIRE_FALSE(top.error);
    REQUIRE(top.entries.size() == 2);
    const ci::DirEntry* ordinary = entry_named(top, "ordinary.txt");
    REQUIRE(ordinary != nullptr);
    CHECK_FALSE(ordinary->gap.has_value());
    const auto lossy = std::ranges::find_if(top.entries, [](const ci::DirEntry& e) { return e.gap.has_value(); });
    REQUIRE(lossy != top.entries.end());
    CHECK(*lossy->gap == fsr::GapCause::name_too_long); // never searched: its lossy name may equal a real sibling
    CHECK(lossy->type == ci::DirEntry::Type::file);
}

TEST_CASE("file_search windows shell: a junction lists as a link and is never entered, and a root through it is a link",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_junc_"};
    write_file(fx.root / "target" / "inner.txt", "x");
    REQUIRE(yuzu::test::create_junction(fx.root / "junc", fx.root / "target"));
    yuzu::test::JunctionCleanup cleanup{fx.root / "junc"};
    const Unit u = unit_for(fx.root);
    const std::string label = label_of(fx.root);
    UnitLeg leg = os_make_leg(u);
    const ci::ListResult top = leg.ops.list(label, 100);
    REQUIRE_FALSE(top.error);
    REQUIRE(entry_named(top, "junc") != nullptr);
    CHECK(entry_named(top, "junc")->type == ci::DirEntry::Type::link);
    CHECK_FALSE(entry_named(top, "junc")->gap.has_value());
    CHECK(leg.ops.list(label + "/junc", 100).error); // never entered
    Unit through = u;
    through.walk_root = label + "/junc";
    CHECK(os_make_leg(through).root_state(through.walk_root) == ci::RootState::is_link);
}

TEST_CASE("file_search windows shell: the root check says ok, not_found, not_a_directory",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_root_"};
    write_file(fx.root / "file.txt", "x");
    fs::create_directories(fx.root / "dir");
    const Unit u = unit_for(fx.root);
    const std::string label = label_of(fx.root);
    const auto state = [&](const std::string& walk_root) {
        Unit v = u;
        v.walk_root = walk_root;
        return os_make_leg(v).root_state(walk_root);
    };
    CHECK(state(label) == ci::RootState::ok);
    CHECK(state(label + "/dir") == ci::RootState::ok);
    CHECK(state(label + "/nope") == ci::RootState::not_found);
    CHECK(state(label + "/file.txt") == ci::RootState::not_a_directory);
}

TEST_CASE("file_search windows shell: facts read size and time from the handle, with real, resident and sparse extents",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_facts_"};
    const Unit u = unit_for(fx.root);
    const std::string label = label_of(fx.root);
    write_file(fx.root / "big.bin", std::string(8 * 1024 * 1024, 'b'));
    write_file(fx.root / "tiny.txt", "tiny");
    Probe probe(u, label);

    const FileFacts big = probe.facts("big.bin");
    CHECK(big.facts.opened);
    CHECK(big.facts.size == 8u * 1024 * 1024);
    REQUIRE(big.facts.mtime.has_value()); // nullopt != 0 would pass
    CHECK(*big.facts.mtime != 0);
    CHECK(big.extents.state == ExtentsState::ok);
    CHECK(big.extents.note.empty());
    CHECK_FALSE(big.extents.extents.empty());

    if (!on_ntfs(u)) {
        WARN("resident and sparse extents skipped: the temp volume is not NTFS");
        return;
    }
    const FileFacts tiny = probe.facts("tiny.txt");
    CHECK(tiny.facts.size == 4);
    CHECK(tiny.extents.state == ExtentsState::ok);
    REQUIRE(tiny.extents.extents.size() == 1);
    CHECK((tiny.extents.extents[0].flags & kResident) != 0);

    {
        RawFile sparse(fx.root / "sparse.bin");
        REQUIRE(sparse.h.ok());
        REQUIRE(sparse.control(FSCTL_SET_SPARSE));
        REQUIRE(sparse.set_length(4u * 1024 * 1024)); // wholly sparse: success with one lcn -1 run
        REQUIRE(sparse.flush());
    }
    const FileFacts hole = probe.facts("sparse.bin");
    CHECK(hole.extents.state == ExtentsState::ok);
    REQUIRE(hole.extents.extents.size() == 1);
    CHECK((hole.extents.extents[0].flags & kUnallocated) != 0);
    CHECK((hole.extents.extents[0].flags & kResident) == 0);
}

TEST_CASE("file_search windows shell: a file with 40 separated allocated ranges lists 32 extents and reads at least 33",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_many_"};
    const Unit u = unit_for(fx.root);
    if (!on_ntfs(u)) {
        SKIP("skipped: sparse granularity is an NTFS property and the temp volume is not NTFS");
    }
    {
        RawFile sparse(fx.root / "many.bin");
        REQUIRE(sparse.h.ok());
        REQUIRE(sparse.control(FSCTL_SET_SPARSE));
        // NTFS sparse granularity is 64 KiB: a 64 KiB stride has no holes, so the stride is 256 KiB
        for (std::uint64_t i = 0; i < 40; ++i)
            REQUIRE(sparse.write_at(i * 256 * 1024, 4096));
        REQUIRE(sparse.set_length(40u * 256 * 1024));
        REQUIRE(sparse.flush());
    }
    Probe probe(u, label_of(fx.root));
    const FileFacts f = probe.facts("many.bin");
    CHECK(f.extents.state == ExtentsState::ok);
    CHECK(f.extents.extents.size() == kMaxExtents);
    CHECK(f.extents.total >= kMaxExtents + 1); // ERROR_MORE_DATA: a lower bound
    CHECK_FALSE(f.extents.total_exact);
    CHECK(format_extents_row({1, 2}, f.extents).find("|>=33|") != std::string::npos);
}

TEST_CASE("file_search windows shell: a file given external backing lists as a plain file and reads wof_external_backing",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_wof_"};
    const Unit u = unit_for(fx.root);
    write_file(fx.root / "wof.bin", std::string(256 * 1024, 'w'));
    struct WofBacking {
        WOF_EXTERNAL_INFO wof;
        FILE_PROVIDER_EXTERNAL_INFO_V1 file;
    };
    WofBacking in{};
    in.wof.Version = WOF_CURRENT_VERSION;
    in.wof.Provider = WOF_PROVIDER_FILE;
    in.file.Version = FILE_PROVIDER_CURRENT_VERSION;
    in.file.Algorithm = FILE_PROVIDER_COMPRESSION_XPRESS4K;
    bool backed = false;
    {
        Owned h(CreateFileW((fx.root / "wof.bin").c_str(), GENERIC_READ | GENERIC_WRITE, kShareAll, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        REQUIRE(h.ok());
        DWORD returned = 0;
        backed = DeviceIoControl(h.h, FSCTL_SET_EXTERNAL_BACKING, &in, sizeof(in), nullptr, 0, &returned, nullptr) != 0;
    }
    if (!backed)
        SKIP("external backing is refused on this volume");
    Probe probe(u, label_of(fx.root));
    const ci::ListResult listed = probe.leg.ops.list(probe.dir, 100);
    REQUIRE(entry_named(listed, "wof.bin") != nullptr);
    CHECK(entry_named(listed, "wof.bin")->type == ci::DirEntry::Type::file); // a plain file: no reparse attribute
    const FileFacts f = probe.leg.facts(probe.dir, *entry_named(listed, "wof.bin"));
    CHECK(f.facts.opened);
    CHECK(f.extents.state == ExtentsState::unsupported);
    CHECK(f.extents.note == "wof_external_backing");
    CHECK(f.extents.extents.empty()); // never an extent list
}

TEST_CASE("file_search windows shell: an NTFS-compressed file carries the compressed flag on every extent",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_lznt_"};
    const Unit u = unit_for(fx.root);
    if (!on_ntfs(u)) {
        SKIP("skipped: compression is an NTFS property and the temp volume is not NTFS");
    }
    {
        RawFile file(fx.root / "lznt.bin");
        REQUIRE(file.h.ok());
        USHORT format = COMPRESSION_FORMAT_DEFAULT;
        if (!file.control(FSCTL_SET_COMPRESSION, &format, sizeof(format)))
            SKIP("compression is refused on this volume");
        REQUIRE(file.write_at(0, 1024 * 1024));
        REQUIRE(file.flush());
    }
    Probe probe(u, label_of(fx.root));
    const FileFacts f = probe.facts("lznt.bin");
    CHECK(f.extents.state == ExtentsState::ok);
    REQUIRE_FALSE(f.extents.extents.empty());
    for (const auto& e : f.extents.extents)
        CHECK((e.flags & kCompressed) != 0);
}

TEST_CASE("file_search windows shell: a directory with a deny ACL is a permission_denied listing and nothing below it is read",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_deny_"};
    write_file(fx.root / "locked" / "secret.txt", "x");
    const Unit u = unit_for(fx.root);
    const fs::path locked = fx.root / "locked";

    // a DENY entry for the current user over listing the directory
    HANDLE raw_token = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token));
    Owned token(raw_token);
    DWORD size = 0;
    GetTokenInformation(token.h, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> user(size);
    REQUIRE(GetTokenInformation(token.h, TokenUser, user.data(), size, &size));
    EXPLICIT_ACCESSW deny{};
    deny.grfAccessPermissions = FILE_LIST_DIRECTORY;
    deny.grfAccessMode = DENY_ACCESS;
    deny.grfInheritance = NO_INHERITANCE;
    deny.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    deny.Trustee.TrusteeType = TRUSTEE_IS_USER;
    deny.Trustee.ptstrName = reinterpret_cast<LPWSTR>(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid);
    PACL acl = nullptr;
    REQUIRE(SetEntriesInAclW(1, &deny, nullptr, &acl) == ERROR_SUCCESS);
    const DWORD set = SetNamedSecurityInfoW(const_cast<LPWSTR>(locked.c_str()), SE_FILE_OBJECT,
                                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                            nullptr, acl, nullptr);
    LocalFree(acl);
    // restores access whatever happens below, so the fixture can be removed
    struct Restore {
        std::wstring path;
        ~Restore() {
            SetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                  nullptr, nullptr);
        }
    } restore{locked.wstring()};
    REQUIRE(set == ERROR_SUCCESS);

    UnitLeg leg = os_make_leg(u);
    const ci::ListResult listed = leg.ops.list(label_of(fx.root) + "/locked", 100);
    CHECK(listed.error);
    CHECK(listed.cause == ci::ListError::permission_denied);
    CHECK(listed.entries.empty());
}

TEST_CASE("file_search windows shell: the name rule is windows_upcase_v1 and folds ASCII and non-ASCII case",
          "[file_search][file_search_win_shell]") {
    const fsr::NameSemantics sem = os_name_semantics();
    CHECK(sem.id == "windows_upcase_v1");
    CHECK(sem.canon("Report.docx") == "REPORT.DOCX");
    CHECK(sem.canon("caf\xC3\xA9") == "CAF\xC3\x89");           // e acute -> E acute
    CHECK(sem.canon("caf\xC3\x89") == sem.canon("caf\xC3\xA9")); // either spelling compares equal
    CHECK(sem.canon("\xCE\xB1\xCE\xB2") == "\xCE\x91\xCE\x92");  // Greek alpha beta
    const std::string broken = "a\xC3";
    CHECK(sem.canon(broken) == broken); // not well-formed UTF-8: the bytes it is
    CHECK(sem.canon("").empty());
}

TEST_CASE("file_search windows shell: the cursor key draws non-zero, fresh bytes on every draw, and init succeeds on every call",
          "[file_search][file_search_win_shell]") {
    CursorKey a{};
    REQUIRE(os_draw_cursor_key(a));
    CHECK(std::ranges::any_of(a, [](unsigned char c) { return c != 0; }));
    CursorKey b{};
    REQUIRE(os_draw_cursor_key(b));
    CHECK(a != b); // each draw is fresh random bytes
    CHECK(init_cursor_key());
    CHECK(init_cursor_key());
}

TEST_CASE("file_search windows shell: the volume reader answers one entry for the temp drive and no_volume for an unused letter",
          "[file_search][file_search_win_shell]") {
    Fixture fx{"yuzu_test_fs_win_mounts_"};
    const std::string label = label_of(fx.root);
    const auto table = os_read_mounts(label);
    REQUIRE(table.has_value());
    REQUIRE(table->entries.size() == 1);
    const auto& e = table->entries[0];
    CHECK(e.mount_point == "/" + wr::split_label(label)->volume);
    CHECK(e.root.starts_with("\\\\?\\Volume{")); // the volume GUID path, so a re-pointed letter ends the search
    CHECK(e.root.back() == '\\');
    CHECK(e.source == e.root);
    CHECK_FALSE(e.fstype.empty());

    // Asked again for the same healthy volume it answers again: a query that returned is never recorded as blocked.
    const auto again = os_read_mounts(label);
    REQUIRE(again.has_value());
    CHECK(again->entries.size() == 1);

    // The same volume reached by its GUID path is the same volume: equal root, type and serial, so the key
    // an abandoned worker is recorded under (label, root, type) is one key for both spellings.
    const auto guid_label = wr::normalise_windows_root(e.root);
    REQUIRE(guid_label.has_value());
    const auto by_guid = os_read_mounts(*guid_label);
    REQUIRE(by_guid.has_value());
    REQUIRE(by_guid->entries.size() == 1);
    const auto& g = by_guid->entries[0];
    CHECK(g.mount_point == *guid_label);
    CHECK(g.mount_point != e.mount_point);
    CHECK(g.root == e.root);
    CHECK(g.fstype == e.fstype);
    CHECK(g.dev_minor == e.dev_minor);

    const DWORD letters = GetLogicalDrives();
    char unused = 0;
    for (char c = 'Z'; c >= 'D'; --c)
        if ((letters & (1u << (c - 'A'))) == 0) {
            unused = c;
            break;
        }
    if (unused == 0) {
        WARN("unused-letter case skipped: every letter D to Z is in use");
        return;
    }
    const auto none = os_read_mounts(std::string("/") + unused + ":");
    REQUIRE(none.has_value());
    REQUIRE(none->entries.size() == 1);
    CHECK(none->entries[0].fstype == "no_volume");
    CHECK(none->entries[0].root == "-");
}

TEST_CASE("file_search windows shell: a profile of the volume is a root in the unit's own label namespace, in either label form",
          "[file_search][file_search_win_shell]") {
    // The host's own non-system profiles, from the same registry list the shell reads.
    const auto listing = yuzu::win::enumerate_profile_list();
    std::wstring path, mount, guid;
    for (const auto& rec : listing.records) {
        if (yuzu::profiles::is_system_sid(rec.sid) || yuzu::profiles::is_profile_backup_entry(rec.sid) ||
            rec.profile_image_path.empty())
            continue;
        const std::wstring candidate = yuzu::win::to_wide(rec.profile_image_path);
        wchar_t root[MAX_PATH + 1] = {}, vol[64] = {};
        if (GetVolumePathNameW(candidate.c_str(), root, MAX_PATH) == 0 ||
            GetVolumeNameForVolumeMountPointW(root, vol, 64) == 0)
            continue;
        const std::wstring mounted(root);
        if (mounted.size() != 3 || mounted[1] != L':') // a drive-letter volume, for the drive-letter form
            continue;
        path = candidate;
        mount = mounted;
        guid = vol;
        break;
    }
    if (path.empty()) {
        SKIP("skipped: this host has no non-system profile on a drive-letter volume");
    }
    const std::string mount_utf8 = yuzu::win::from_wide(mount.c_str());
    const std::string path_utf8 = yuzu::win::from_wide(path.c_str());
    const std::string guid_path = yuzu::win::from_wide(guid.c_str());
    const std::string guid_volume = guid_path.substr(4, guid_path.size() - 5); // `Volume{...}`

    Unit by_letter;
    by_letter.mount_point = std::string("/") + static_cast<char>(std::toupper(static_cast<unsigned char>(mount[0]))) + ":";
    by_letter.root_field = guid_path;
    const auto letter_roots = os_user_roots(by_letter);
    const auto want_letter = wr::profile_root_label(by_letter.mount_point, mount_utf8, path_utf8);
    REQUIRE(want_letter.has_value());
    CHECK(std::ranges::find(letter_roots, *want_letter) != letter_roots.end());

    Unit by_guid;
    by_guid.mount_point = "/" + guid_volume;
    by_guid.root_field = guid_path;
    const auto guid_roots = os_user_roots(by_guid);
    const auto want_guid = wr::profile_root_label(by_guid.mount_point, mount_utf8, path_utf8);
    REQUIRE(want_guid.has_value());
    CHECK(std::ranges::find(guid_roots, *want_guid) != guid_roots.end());

    Unit elsewhere = by_letter; // a unit of another volume: this profile is no root of it
    elsewhere.root_field = "\\\\?\\Volume{ffffffff-ffff-ffff-ffff-ffffffffffff}\\";
    const auto other_roots = os_user_roots(elsewhere);
    CHECK(std::ranges::find(other_roots, *want_letter) == other_roots.end());
}

TEST_CASE("file_search windows shell: run_on_worker runs the work inside the worker environment and returns its value",
          "[file_search][file_search_win_shell]") {
    auto errors_suppressed = std::make_shared<bool>(false);
    const auto out = run_on_worker(std::chrono::seconds{60}, [errors_suppressed]() -> WorkResult {
        *errors_suppressed = (GetThreadErrorMode() & SEM_FAILCRITICALERRORS) != 0;
        WorkResult w;
        w.rows = {"ran"};
        return w;
    });
    REQUIRE(out.status == RunStatus::completed);
    REQUIRE(out.value.has_value());
    CHECK(out.value->rows == std::vector<std::string>{"ran"});
    CHECK(*errors_suppressed); // hard-error dialogs are suppressed for the worker thread
}

TEST_CASE("file_search windows shell: the work function runs in background mode",
          "[file_search][file_search_win_shell]") {
    // Background mode is a per-thread setting made with a bare number, so a wrong one would run fleet searches
    // at normal CPU and I/O priority with nothing to show it. Read it back from inside the work function by the
    // documented probe: beginning it again on a thread already in it fails with this code. The value is handed
    // out as a plain DWORD (Catch2 assertions are made on the test's own thread).
    const auto probe = std::make_shared<DWORD>(ERROR_SUCCESS);
    const auto out = run_on_worker(std::chrono::seconds{60}, [probe]() -> WorkResult {
        if (::SetThreadPriority(::GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) == 0)
            *probe = ::GetLastError();
        return WorkResult{};
    });
    REQUIRE(out.status == RunStatus::completed);
    REQUIRE(out.value.has_value());
    CHECK_FALSE(out.value->threw);
    CHECK(*probe == ERROR_THREAD_MODE_ALREADY_BACKGROUND);
}

TEST_CASE("file_search windows shell: the worker environment suppresses hard-error dialogs and runs in background mode around the body only",
          "[file_search][file_search_win_shell]") {
    // On a thread of its own, joined, so the thread's modes can be read after the call without touching the
    // test's thread. The error mode is cleared first so the restore is observable.
    DWORD inside = 0;
    DWORD after = ~DWORD{0};
    BOOL background_ended = FALSE;
    std::thread worker([&] {
        ::SetThreadErrorMode(0, nullptr);
        os_in_worker_environment([&] { inside = ::GetThreadErrorMode(); });
        after = ::GetThreadErrorMode();
        // Background mode ended with the body: beginning it again succeeds (it fails with
        // ERROR_THREAD_MODE_ALREADY_BACKGROUND while it is still on), and that second one is ended here.
        background_ended = ::SetThreadPriority(::GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
        if (background_ended != FALSE)
            (void)::SetThreadPriority(::GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
    });
    worker.join();
    CHECK((inside & SEM_FAILCRITICALERRORS) != 0);
    CHECK(after == 0);
    CHECK(background_ended != FALSE);
}

#endif // _WIN32
