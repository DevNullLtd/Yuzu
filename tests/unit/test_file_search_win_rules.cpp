// Portable tests of every pure Windows decision of the file_search plugin (file_search_win_rules.hpp): the
// root normaliser and label, the entry classifier with the MEASURED attribute and tag values, the extents
// decision and the readings of the two ioctls, the one id policy, the volume tokens and the refusal maps.
// No OS header, no filesystem: this file runs on every OS.

#include "file_search_win_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::file_search;
using namespace yuzu::file_search::win_rules;
namespace cfs = yuzu::agent::confined_fs;
namespace fsr = yuzu::shared::file_search;
using Type = yuzu::component_inventory::DirEntry::Type;

namespace {

constexpr const char* kGuid = "0f1E2d3c-1111-2222-3333-44445555aaBB";
constexpr const char* kGuidLower = "0f1e2d3c-1111-2222-3333-44445555aabb";

std::string ok(std::string_view raw) {
    const auto r = normalise_windows_root(raw);
    REQUIRE(r.has_value());
    return *r;
}

RequestError err(std::string_view raw) {
    const auto r = normalise_windows_root(raw);
    REQUIRE_FALSE(r.has_value());
    return r.error();
}

} // namespace

// ---- the root ----

TEST_CASE("windows root: accepted forms are canonicalised to the label", "[file_search][win_rules]") {
    CHECK(ok("C:\\") == "/C:");
    CHECK(ok("c:\\Users\\x\\") == "/C:/Users/x");
    CHECK(ok("C:/Users/x") == "/C:/Users/x");
    CHECK(ok("C:\\Users/x") == "/C:/Users/x");
    CHECK(ok("z:/Mixed Case/Dir") == "/Z:/Mixed Case/Dir"); // components keep their case and their spaces
    CHECK(ok(std::string("\\\\?\\Volume{") + kGuid + "}\\") == std::string("/Volume{") + kGuidLower + "}");
    CHECK(ok(std::string("\\\\?\\volume{") + kGuid + "}\\dir") == std::string("/Volume{") + kGuidLower + "}/dir");
    CHECK(ok(std::string("\\\\?\\VOLUME{") + kGuid + "}") == std::string("/Volume{") + kGuidLower + "}");
    CHECK(ok("C:\\caf\xc3\xa9\\") == "/C:/caf\xc3\xa9");
    CHECK(ok("C:\\\xef\xbf\xbd") == "/C:/\xef\xbf\xbd"); // a literal U+FFFD component is well-formed UTF-8
}

TEST_CASE("windows root: a UNC or network root is root_unc", "[file_search][win_rules]") {
    CHECK(err("\\\\srv\\share") == RequestError::root_unc);
    CHECK(err("//srv/share") == RequestError::root_unc);
    CHECK(err("\\\\?\\UNC\\srv\\share") == RequestError::root_unc);
    CHECK(err("\\\\?\\unc\\srv\\share") == RequestError::root_unc);
    CHECK(err("\\\\srv") == RequestError::root_unc);
}

TEST_CASE("windows root: any other device or NT-namespace form is root_device_path", "[file_search][win_rules]") {
    CHECK(err("\\\\.\\C:\\") == RequestError::root_device_path);
    CHECK(err("\\\\?\\C:\\x") == RequestError::root_device_path);
    CHECK(err("\\\\?\\GLOBALROOT\\x") == RequestError::root_device_path);
    CHECK(err("\\??\\C:\\") == RequestError::root_device_path);
    CHECK(err("\\\\?\\Volume{not-a-guid}\\") == RequestError::root_device_path);
    CHECK(err("\\\\?\\Volume{0f1e2d3c-1111-2222-3333-44445555aabg}\\") == RequestError::root_device_path); // not hex
    CHECK(err(std::string("\\\\?\\Volume{") + kGuid + "}x") == RequestError::root_device_path); // glued suffix
}

TEST_CASE("windows root: anything not absolute is root_not_absolute", "[file_search][win_rules]") {
    for (const char* raw : {"C:", "C:foo", "\\foo", "/foo", "foo", "1:\\x", "Users\\x"})
        CHECK(err(raw) == RequestError::root_not_absolute);
    CHECK(err("") == RequestError::missing_root);
}

TEST_CASE("windows root: a component the OS could misread is root_bad_component", "[file_search][win_rules]") {
    for (const char* raw : {"C:\\a\\..\\b", "C:\\..", "C:\\.", "C:\\a\\\\b", "C:\\\\", "C:\\a.", "C:\\a ", "C:\\a:b",
                            "C:\\x::$DATA", "C:\\a*", "C:\\a?b", "C:\\a<b", "C:\\a>b", "C:\\a|b", "C:\\a\"b",
                            "C:\\a\x01"})
        CHECK(err(raw) == RequestError::root_bad_component);
    CHECK(err(std::string("C:\\a\0b", 6)) == RequestError::root_bad_component);
    CHECK(err(std::string("\\\\?\\Volume{") + kGuid + "}\\a\\\\b") == RequestError::root_bad_component);
    CHECK(err("C:" + std::string(kMaxRootBytes, 'a')) == RequestError::root_too_long);
}

TEST_CASE("windows root: bytes that are not well-formed UTF-8 are refused", "[file_search][win_rules]") {
    for (const std::string& bad : {std::string("C:\\a\x80"),                  // a stray continuation byte
                                   std::string("C:\\a\xc3"),                  // a truncated sequence
                                   std::string("C:\\a\xc0\xaf"),              // an overlong form
                                   std::string("C:\\a\xed\xa0\x80"),          // an encoded surrogate
                                   std::string("C:\\a\xf4\x90\x80\x80")})     // above U+10FFFF
        CHECK(err(bad) == RequestError::root_bad_component);
}

TEST_CASE("windows root: label split, volume root path and profile root labels", "[file_search][win_rules]") {
    const auto drive = split_label("/C:/Users/x");
    REQUIRE(drive.has_value());
    CHECK(drive->volume == "C:");
    CHECK(drive->components == std::vector<std::string>{"Users", "x"});
    const auto guid = split_label(std::string("/Volume{") + kGuidLower + "}");
    REQUIRE(guid.has_value());
    CHECK(guid->volume == std::string("Volume{") + kGuidLower + "}");
    CHECK(guid->components.empty());
    CHECK_FALSE(split_label("C:/x").has_value());
    CHECK_FALSE(split_label("/").has_value());
    CHECK_FALSE(split_label("/C:/").has_value());
    CHECK_FALSE(split_label("/C://x").has_value());

    CHECK(volume_root_path("C:") == "C:\\");
    CHECK(volume_root_path(std::string("Volume{") + kGuidLower + "}") ==
          std::string("\\\\?\\Volume{") + kGuidLower + "}\\");
    CHECK(volume_root_path("nonsense").empty());

    CHECK(profile_root_label("/C:", "Users\\alice") == "/C:/Users/alice");
    CHECK(profile_root_label("/C:", "\\Users/alice\\") == "/C:/Users/alice");
    const std::string vol = std::string("/Volume{") + kGuidLower + "}";
    CHECK(profile_root_label(vol, "Users\\alice") == vol + "/Users/alice");
    CHECK_FALSE(profile_root_label("/C:", "Users\\..\\x").has_value()); // a refused component gives none
    CHECK_FALSE(profile_root_label("/C:", "Users\\a:b").has_value());
    CHECK_FALSE(profile_root_label("/C:", "").has_value());             // never the whole volume
    CHECK_FALSE(profile_root_label("/C:", "\\").has_value());
}

// ---- the classifier, with the measured values ----

TEST_CASE("classify: links, special files, plain entries", "[file_search][win_rules]") {
    const auto at = [](std::uint32_t attrs, std::uint32_t tag) { return classify(attrs, tag); };
    for (const std::uint32_t tag : {kTagSymlink, kTagMountPoint, kTagLxSymlink}) {
        CHECK(at(0x410, tag).type == Type::link);
        CHECK(at(0x420, tag).type == Type::link);
        CHECK_FALSE(at(0x410, tag).gap.has_value());
    }
    for (const std::uint32_t tag : {kTagAfUnix, kTagLxFifo, kTagLxChr, kTagLxBlk})
        CHECK(at(0x420, tag).type == Type::other);
    CHECK(at(0x20, 0).type == Type::file);
    CHECK(at(0x10, 0).type == Type::dir);
    CHECK_FALSE(at(0x10, 0).gap.has_value());
    CHECK(at(0x20, 0).family == TagFamily::none);
}

TEST_CASE("classify: WOF, dedup and app-exec files are files with their family; directories and unknown tags are gaps",
          "[file_search][win_rules]") {
    CHECK(classify(0x420, kTagWof).type == Type::file);
    CHECK(classify(0x420, kTagWof).family == TagFamily::wof);
    CHECK(classify(0x420, kTagDedup).family == TagFamily::dedup);
    CHECK(classify(0x420, kTagAppExecLink).family == TagFamily::app_exec); // measured: 0x420 with 0x8000001B
    for (const std::uint32_t tag : {kTagWof, kTagDedup, kTagAppExecLink}) {
        const Listed d = classify(0x410, tag);
        CHECK(d.type == Type::dir);
        REQUIRE(d.gap.has_value());
        CHECK(*d.gap == fsr::GapCause::reparse_unknown);
    }
    const Listed unknown_file = classify(0x420, 0x80000099);
    REQUIRE(unknown_file.gap.has_value());
    CHECK(*unknown_file.gap == fsr::GapCause::reparse_unknown);
    CHECK(classify(0x410, 0x12345678).gap == fsr::GapCause::reparse_unknown);
}

TEST_CASE("classify: an untagged directory or file with a recall or offline bit", "[file_search][win_rules]") {
    for (const std::uint32_t bit : {0x40000u, 0x400000u, 0x1000u}) {
        const Listed d = classify(0x10 | bit, 0);
        CHECK(d.type == Type::dir);
        REQUIRE(d.gap.has_value());
        CHECK(*d.gap == fsr::GapCause::dataless); // never opened
        const Listed f = classify(0x20 | bit, 0);
        CHECK(f.type == Type::file); // a file is a file; extents_decision keeps it unopened
        CHECK_FALSE(f.gap.has_value());
    }
}

TEST_CASE("classify: cloud directories with the measured values", "[file_search][win_rules]") {
    // populated folders: no gap, family cloud, entered
    for (const auto& [attrs, tag] : {std::pair<std::uint32_t, std::uint32_t>{0x410, 0x9000601A},
                                     {0x410, 0x9000201A},
                                     {0x430, 0x9000701A}}) {
        const Listed d = classify(attrs, tag);
        CHECK(d.type == Type::dir);
        CHECK(d.family == TagFamily::cloud);
        CHECK_FALSE(d.gap.has_value());
    }
    // not populated: dataless gap
    for (const std::uint32_t tag : {0x9000001Au, 0x9000401Au}) {
        const Listed d = classify(0x401410, tag);
        CHECK(d.type == Type::dir);
        CHECK(d.family == TagFamily::cloud);
        REQUIRE(d.gap.has_value());
        CHECK(*d.gap == fsr::GapCause::dataless);
    }
    // each recall or offline bit alone on a cloud directory is a dataless gap
    for (const std::uint32_t bit : {0x40000u, 0x400000u, 0x1000u}) {
        const Listed d = classify(0x410 | bit, 0x9000601A);
        REQUIRE(d.gap.has_value());
        CHECK(*d.gap == fsr::GapCause::dataless);
    }
    // a cloud file is a file of that family, whatever its state (the extents decision opens or not)
    CHECK(classify(0x420, 0x9000601A).type == Type::file);
    CHECK(classify(0x420, 0x9000601A).family == TagFamily::cloud);
    CHECK(classify(0x401620, 0x9000001A).family == TagFamily::cloud);
    // the family is the mask: every state nibble, and the neighbours are not
    for (std::uint32_t nibble = 0; nibble < 16; ++nibble)
        CHECK(classify(0x420, 0x9000001A | (nibble << 12)).family == TagFamily::cloud);
    for (const std::uint32_t tag : {0x9000001Bu, 0x8000001Au, 0x9001001Au}) {
        const Listed d = classify(0x410, tag);
        REQUIRE(d.gap.has_value());
        CHECK(*d.gap == fsr::GapCause::reparse_unknown);
    }
}

// ---- extents ----

TEST_CASE("extents_decision: placeholders are never opened, families say why they are not asked",
          "[file_search][win_rules]") {
    // each recall or offline bit, with and without a visible tag; the measured unhydrated values among them
    for (const std::uint32_t attrs : {0x401620u, 0x481620u, 0x501620u, 0x40000u | 0x20u, 0x400000u | 0x20u, 0x1000u | 0x20u}) {
        for (const TagFamily family : {TagFamily::none, TagFamily::cloud}) {
            const ExtentsDecision d = extents_decision(attrs, family);
            CHECK_FALSE(d.open);
            CHECK_FALSE(d.ioctl);
            CHECK(d.note == "placeholder");
        }
    }
    const auto wof = extents_decision(0x20, TagFamily::wof);
    CHECK(wof.open);
    CHECK_FALSE(wof.ioctl);
    CHECK(wof.note == "wof_external_backing");
    CHECK(extents_decision(0x20, TagFamily::dedup).note == "dedup_external_backing");
    const auto alias = extents_decision(0x420, TagFamily::app_exec);
    CHECK(alias.open);
    CHECK_FALSE(alias.ioctl);
    CHECK(alias.note == "app_exec_alias");
    const auto cloud = extents_decision(0x420, TagFamily::cloud); // a fully local cloud file (measured 0x420)
    CHECK(cloud.open);
    CHECK(cloud.ioctl);
    CHECK(cloud.note == "cloud");
    const auto plain = extents_decision(0x20, TagFamily::none);
    CHECK(plain.open);
    CHECK(plain.ioctl);
    CHECK(plain.note.empty());
}

TEST_CASE("handle_decision: the entry is judged again from its opened handle", "[file_search][win_rules]") {
    CHECK(handle_decision(0x20, 0)->ioctl);
    CHECK(handle_decision(0x420, 0x9000601A)->note == "cloud");
    CHECK_FALSE(handle_decision(0x401620, 0x9000001A)->open);       // became a placeholder
    CHECK_FALSE(handle_decision(0x420, kTagMountPoint).has_value()); // became a link
    CHECK_FALSE(handle_decision(0x410, kTagSymlink).has_value());
    CHECK_FALSE(handle_decision(0x10, 0).has_value());               // became a directory
    CHECK_FALSE(handle_decision(0x420, 0x80000099).has_value());     // an unknown tag
}

TEST_CASE("external_backing_of reads the answer of FSCTL_GET_EXTERNAL_BACKING", "[file_search][win_rules]") {
    CHECK(external_backing_of(0) == Backing::backed);
    for (const std::uint32_t code : {342u, 1u, 50u, 87u})
        CHECK(external_backing_of(code) == Backing::not_backed);
    for (const std::uint32_t code : {5u, 122u, 234u, 6u, 999u})
        CHECK(external_backing_of(code) == Backing::unknown);
}

namespace {

constexpr std::uint64_t kCluster = 4096;

FileExtents map(std::uint32_t err, std::vector<Run> runs, std::uint64_t size = 100000, std::uint32_t attrs = 0x20,
                std::uint64_t cluster = kCluster, std::uint64_t start = 0) {
    return map_retrieval_pointers({err, start, runs, cluster, size, attrs});
}

} // namespace

TEST_CASE("map_retrieval_pointers: runs, holes, compression, encryption", "[file_search][win_rules]") {
    const auto one = map(0, {{8, 100}});
    CHECK(one.state == ExtentsState::ok);
    REQUIRE(one.extents.size() == 1);
    CHECK(one.extents[0] == Extent{0, 100 * kCluster, 8 * kCluster, 0});
    CHECK(one.total == 1);
    CHECK(one.total_exact);

    const auto two = map(0, {{4, 100}, {10, 500}});
    REQUIRE(two.extents.size() == 2);
    CHECK(two.extents[1] == Extent{4 * kCluster, 500 * kCluster, 6 * kCluster, 0});

    const auto hole = map(0, {{4, 100}, {8, -1}, {12, 300}});
    REQUIRE(hole.extents.size() == 3);
    CHECK(hole.extents[1].flags == kUnallocated);
    CHECK(hole.extents[1].physical == 0);
    CHECK(hole.extents[2].physical == 300 * kCluster);

    const auto compressed = map(0, {{4, 100}}, 100000, 0x820);
    CHECK(compressed.extents[0].flags == kCompressed);
    const auto encrypted = map(0, {{4, 100}}, 100000, 0x4020); // unit level only: no real EFS file was measured
    CHECK(encrypted.extents[0].flags == kEncrypted);
}

TEST_CASE("map_retrieval_pointers: the measured shapes", "[file_search][win_rules]") {
    // a wholly sparse file answers success with ONE lcn -1 run: one unallocated extent, not resident
    const auto sparse = map(0, {{16, -1}}, 65536);
    CHECK(sparse.state == ExtentsState::ok);
    REQUIRE(sparse.extents.size() == 1);
    CHECK(sparse.extents[0].flags == kUnallocated);
    CHECK(sparse.extents[0].flags != kResident);
    // the LZNT1 shape: data runs alternating with lcn -1 runs under attribute 0x820
    const auto lznt = map(0, {{4, 100}, {16, -1}, {20, 300}, {32, -1}}, 131072, 0x820);
    REQUIRE(lznt.extents.size() == 4);
    CHECK(lznt.extents[0].flags == kCompressed);
    CHECK(lznt.extents[1].flags == (kCompressed | kUnallocated));
    CHECK(lznt.extents[2].flags == kCompressed);
    CHECK(lznt.extents[3].flags == (kCompressed | kUnallocated));
}

TEST_CASE("map_retrieval_pointers: end of file, unsupported codes and every failure", "[file_search][win_rules]") {
    // ERROR_HANDLE_EOF: a resident file, a 0-byte file
    const auto resident = map(38, {}, 500);
    CHECK(resident.state == ExtentsState::ok);
    REQUIRE(resident.extents.size() == 1);
    CHECK(resident.extents[0] == Extent{0, 0, 500, kResident});
    const auto empty = map(38, {}, 0);
    CHECK(empty.state == ExtentsState::ok);
    CHECK(empty.extents.empty());
    CHECK(empty.total == 0);
    // the three unsupported codes
    for (const std::uint32_t code : {1u, 50u, 87u})
        CHECK(map(code, {}).state == ExtentsState::unsupported);
    // everything else fails, ERROR_INSUFFICIENT_BUFFER among it
    for (const std::uint32_t code : {5u, 122u, 6u, 4390u})
        CHECK(map(code, {{4, 100}}).state == ExtentsState::failed);
    CHECK(map(0, {}).state == ExtentsState::failed);                     // success with no run
    CHECK(map(234, {}).state == ExtentsState::failed);                   // more data with no run
    CHECK(map(0, {{4, 100}}, 1000, 0x20, 0).state == ExtentsState::failed); // a zero cluster size
    CHECK(map(38, {}, 500, 0x20, 0).state == ExtentsState::failed);
    CHECK(map(0, {{4, 100}, {4, 200}}).state == ExtentsState::failed);   // a non-increasing vcn
    CHECK(map(0, {{4, 100}, {2, 200}}).state == ExtentsState::failed);
    CHECK(map(0, {{4, 100}}, 1000, 0x20, kCluster, 4).state == ExtentsState::failed); // not past the starting vcn
    CHECK(map(0, {{4, -2}}).state == ExtentsState::failed);              // not a hole, not a cluster
    // overflow: a vcn or an lcn that cannot be multiplied by the cluster size
    CHECK(map(0, {{~std::uint64_t{0} / 2, 100}}).state == ExtentsState::failed);
    CHECK(map(0, {{4, std::int64_t{0x7fffffffffffffff}}}).state == ExtentsState::failed);
}

TEST_CASE("map_retrieval_pointers: a full buffer is exact, more data is a lower bound", "[file_search][win_rules]") {
    std::vector<Run> runs;
    for (std::uint64_t i = 0; i < kMaxExtents; ++i)
        runs.push_back({(i + 1) * 4, static_cast<std::int64_t>(1000 + i * 10)});
    const auto exact = map(0, runs);
    CHECK(exact.state == ExtentsState::ok);
    CHECK(exact.extents.size() == kMaxExtents);
    CHECK(exact.total == kMaxExtents);
    CHECK(exact.total_exact);
    const auto more = map(234, runs); // ERROR_MORE_DATA: the buffer was filled and the file has more
    CHECK(more.state == ExtentsState::ok);
    CHECK(more.extents.size() == kMaxExtents);
    CHECK(more.total == kMaxExtents + 1);
    CHECK_FALSE(more.total_exact);
    FileExtents shown = more;
    CHECK(format_extents_row({1, 2}, shown).find("|>=33|") != std::string::npos);
}

TEST_CASE("format_extents_row prints the note after the state and leaves existing rows byte-identical",
          "[file_search][win_rules]") {
    FileExtents placeholder;
    placeholder.state = ExtentsState::unsupported;
    placeholder.note = "placeholder";
    CHECK(format_extents_row({1, 2}, placeholder) == "extents|0000000000000001:0000000000000002|unsupported:placeholder|0|-");
    FileExtents cloud;
    cloud.state = ExtentsState::ok;
    cloud.note = "cloud";
    cloud.add({0, 4096, 4096, 0});
    CHECK(format_extents_row({1, 2}, cloud) == "extents|0000000000000001:0000000000000002|ok:cloud|1|0:4096:4096:-");
    FileExtents plain = cloud;
    plain.note = {};
    CHECK(format_extents_row({1, 2}, plain) == "extents|0000000000000001:0000000000000002|ok|1|0:4096:4096:-");
    FileExtents failed;
    failed.state = ExtentsState::failed;
    CHECK(format_extents_row({1, 2}, failed) == "extents|0000000000000001:0000000000000002|failed|0|-");
}

// ---- identity ----

TEST_CASE("ids: NTFS only, by name, and an id that is not a stable 64-bit value reads 0", "[file_search][win_rules]") {
    CHECK(fs_has_stable_ids("NTFS"));
    for (const char* name : {"ReFS", "FAT", "FAT32", "exFAT", "ntfs", "", "unreadable"})
        CHECK_FALSE(fs_has_stable_ids(name));
    // the measured NON-ZERO FAT listing ids are never reported
    for (const std::uint64_t fat_id : {0x400080ULL, 0x3b0a0ULL, 0x33140ULL})
        for (const char* name : {"FAT", "FAT32", "exFAT", "ReFS"})
            CHECK(stable_id(fs_has_stable_ids(name), fat_id, 0) == 0);
    CHECK(stable_id(true, 0x0003000000001234ULL, 0) == 0x0003000000001234ULL);
    CHECK(stable_id(true, 0x1234, 1) == 0);                // a non-zero high half
    CHECK(stable_id(true, 0, 0) == 0);                     // zero
    CHECK(stable_id(true, ~std::uint64_t{0}, 0) == 0);     // all ones
    CHECK(stable_id(false, 0x1234, 0) == 0);
}

// ---- volumes ----

TEST_CASE("fstype_token: the allow-list holds the filesystems and no drive-type token", "[file_search][win_rules]") {
    CHECK(fstype_token(kDriveFixed, "NTFS", true, true) == "NTFS");
    CHECK(fstype_token(kDriveFixed, "ReFS", true, true) == "ReFS");
    CHECK(fstype_token(kDriveFixed, "exFAT", true, true) == "exFAT");
    CHECK(fstype_token(kDriveFixed, "", true, false) == "unreadable");
    CHECK(fstype_token(kDriveFixed, "NTFS", false, true) == "not_a_volume"); // a SUBST drive
    CHECK(fstype_token(kDriveRemovable, "NTFS", true, true) == "removable");
    CHECK(fstype_token(kDriveCdrom, "CDFS", true, true) == "cdrom");
    CHECK(fstype_token(kDriveRamdisk, "NTFS", true, true) == "ramdisk");
    CHECK(fstype_token(kDriveRemote, "NTFS", false, false) == kWindowsRemoteDrive);
    CHECK(fstype_token(kDriveNoRootDir, "", false, false) == "no_volume");
    CHECK(fstype_token(kDriveUnknown, "", false, false) == "unknown");
    CHECK(fstype_token(99, "", false, false) == "unknown");
    for (const char* ok_name : {"NTFS", "ReFS", "FAT", "FAT32", "exFAT"})
        CHECK(yuzu::shared::is_searchable_local_fstype(ok_name));
    for (const char* token : {"unreadable", "not_a_volume", "removable", "cdrom", "ramdisk", "remote", "no_volume", "unknown"})
        CHECK_FALSE(yuzu::shared::is_searchable_local_fstype(token));
}

// ---- the refusal maps ----

TEST_CASE("root_state_of and list_error_of read the primitive's refusals", "[file_search][win_rules]") {
    using R = cfs::Reason;
    using S = yuzu::component_inventory::RootState;
    using L = yuzu::component_inventory::ListError;
    // a cloud-family tag is no link; a link tag, or no tag, is
    CHECK(root_state_of(R::ReparseRejected, 0, 0x9000701A) == S::other);
    CHECK(root_state_of(R::ReparseRejected, 0, 0x9000201A) == S::other);
    CHECK(root_state_of(R::ReparseRejected, 0, kTagMountPoint) == S::is_link);
    CHECK(root_state_of(R::ReparseRejected, 0, kTagSymlink) == S::is_link);
    CHECK(root_state_of(R::ReparseRejected, 0, 0) == S::is_link);
    CHECK(root_state_of(R::OsError, 2, 0) == S::not_found);
    CHECK(root_state_of(R::OsError, 3, 0) == S::not_found);
    CHECK(root_state_of(R::OsError, 267, 0) == S::not_a_directory);
    CHECK(root_state_of(R::OsError, 5, 0) == S::other);
    CHECK(root_state_of(R::DeviceBoundary, 0, 0) == S::other);
    CHECK(root_state_of(R::Unsupported, 0, 0) == S::other);
    CHECK(root_state_of(R::None, 0, 0) == S::ok);

    CHECK(list_error_of(R::ReparseRejected, 0, 0x9000701A) == L::dataless);
    CHECK(list_error_of(R::ReparseRejected, 0, kTagMountPoint) == L::unreadable);
    CHECK(list_error_of(R::ReparseRejected, 0, 0) == L::unreadable);
    CHECK(list_error_of(R::OsError, 362, 0) == L::dataless); // the provider is not running
    CHECK(list_error_of(R::OsError, 5, 0) == L::permission_denied);
    CHECK(list_error_of(R::OsError, 2, 0) == L::unreadable);
    CHECK(list_error_of(R::DeviceBoundary, 0, 0) == L::unreadable);
}

TEST_CASE("windows user profile rule in both label forms", "[file_search][win_rules]") {
    const std::string vol = std::string("/Volume{") + kGuidLower + "}";
    for (const std::string& base : {std::string("/C:"), vol}) {
        INFO(base);
        CHECK(is_user_profile_path(base + "/Users/alice", Os::windows));
        CHECK(is_user_profile_path(base + "/Users/alice/Documents/x.txt", Os::windows));
        CHECK(is_user_profile_path(base + "/users/ALICE", Os::windows));
        for (const char* shared : {"Public", "Default", "Default User", "All Users", "public", "ALL USERS"})
            CHECK_FALSE(is_user_profile_path(base + "/Users/" + shared, Os::windows));
        CHECK_FALSE(is_user_profile_path(base + "/Users", Os::windows));
        CHECK_FALSE(is_user_profile_path(base + "/Windows/System32", Os::windows));
        CHECK_FALSE(is_user_profile_path(base + "/Usersx/alice", Os::windows));
    }
    CHECK(is_user_profile_path("/c:/users/ALICE", Os::windows));
    CHECK_FALSE(is_user_profile_path("/Users/alice", Os::windows)); // no volume component: not a label
    CHECK_FALSE(is_user_profile_path("/C:", Os::windows));
}
