/**
 * test_execution_artifacts_parsers.cpp — pure parser tests for
 * execution_artifacts_parsers.hpp: ShimCache, Amcache, and Prefetch.
 *
 * Fixtures live under tests/unit/fixtures/wave7/execution_artifacts/ and
 * are REQUIRE(exists) — never SKIP, per this package's spec. Every
 * REAL-CAPTURE fixture used here is A1's the-rig capture (2026-09-06); see
 * each fixture's own `.provenance.txt` sibling.
 *
 * PREFETCH VERSION BANNER: every real .pf.decompressed fixture on the-rig
 * parses as format version 31 (Windows 10/11) — the-rig has NO real
 * fixture for versions 23, 26, or 30; those are exercised here only
 * through hand-built RECONSTRUCTION buffers for the version-dispatch branch
 * and the negative cases, never asserted as a positive real-world result.
 * Version 17 (XP/2003) is deliberately UNSUPPORTED, not merely unfixtured —
 * see is_supported_prefetch_version's comment in execution_artifacts_parsers.hpp
 * — so its only test here is the negative case proving it is rejected.
 * The-rig also has no real UNCOMPRESSED (non-MAM) .pf file — every real
 * capture on this hardware is MAM-compressed, since NTFS/Prefetch
 * compression has been the default since Windows 8. Direct (non-MAM)
 * parse_prefetch is exercised on this file's synthetic buffer only.
 */

#include "execution_artifacts_legs.hpp"
#include "execution_artifacts_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::execution_artifacts;
namespace fs = std::filesystem;

namespace {

fs::path fixture_dir() {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave7" / "execution_artifacts";
}

std::vector<uint8_t> read_fixture_bytes(const fs::path& path) {
    REQUIRE(fs::exists(path));
    std::ifstream f(path, std::ios::binary);
    REQUIRE(f.is_open());
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    return data;
}

// Little helper for building synthetic ShimCache/Prefetch buffers for the
// negative-path tests (never used to fabricate a POSITIVE real-artifact
// result — every positive assertion below runs against a real fixture).
void put_u16(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    if (buf.size() < off + 2)
        buf.resize(off + 2, 0);
    std::memcpy(buf.data() + off, &v, 2);
}
void put_u32(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    if (buf.size() < off + 4)
        buf.resize(off + 4, 0);
    std::memcpy(buf.data() + off, &v, 4);
}
void put_u64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    if (buf.size() < off + 8)
        buf.resize(off + 8, 0);
    std::memcpy(buf.data() + off, &v, 8);
}
void put_bytes(std::vector<uint8_t>& buf, size_t off, std::string_view s) {
    if (buf.size() < off + s.size())
        buf.resize(off + s.size(), 0);
    std::memcpy(buf.data() + off, s.data(), s.size());
}

// A single well-formed Win10 ShimCache entry ("10ts" + unknown DWORD +
// entry_size + path_len + path + FILETIME + data_size), used as the base
// for the negative-path mutation tests below.
std::vector<uint8_t> build_valid_shimcache_blob() {
    std::vector<uint8_t> buf;
    put_u32(buf, 0, 0x34); // header size / scheme sniff
    const size_t entry_off = 0x34;
    put_bytes(buf, entry_off, "10ts");
    put_u32(buf, entry_off + 4, 0); // unknown
    const std::string path = "C:\\Windows\\System32\\cmd.exe";
    std::string path_utf16;
    for (char c : path) {
        path_utf16.push_back(c);
        path_utf16.push_back('\0');
    }
    const uint16_t path_len = static_cast<uint16_t>(path_utf16.size());
    const uint32_t entry_size =
        static_cast<uint32_t>(4 + 4 + 4 + 2 + path_len + 8 + 4); // no trailing data
    put_u32(buf, entry_off + 8, entry_size);
    put_u16(buf, entry_off + 12, path_len);
    put_bytes(buf, entry_off + 14, path_utf16);
    put_u64(buf, entry_off + 14 + path_len, 0); // last_modified FILETIME (zeroed -> epoch 0)
    put_u32(buf, entry_off + 14 + path_len + 8, 0); // data_size
    return buf;
}

// A minimal but structurally valid v31 prefetch header, used as the base
// for the negative-path mutation tests. Real positive assertions never use
// this — they run against A1's real .pf.decompressed fixtures.
std::vector<uint8_t> build_valid_prefetch_v31_blob() {
    std::vector<uint8_t> buf(0x200, 0);
    put_u32(buf, kPrefetchVersionOffset, 31);
    put_bytes(buf, kPrefetchSignatureOffset, "SCCA");
    put_u32(buf, kPrefetchFileSizeOffset, static_cast<uint32_t>(buf.size()));
    std::string exe_utf16;
    for (char c : std::string{"TEST.EXE"}) {
        exe_utf16.push_back(c);
        exe_utf16.push_back('\0');
    }
    put_bytes(buf, kPrefetchExeNameOffset, exe_utf16);
    put_u32(buf, kPrefetchHashOffset, 0xDEADBEEF);
    put_u32(buf, kFileInfoVolumesInfoCountOffset, 0); // 0 volumes: skip file_ref_count walk
    put_u32(buf, kFileInfoV26V30V31RunCountOffset, 1);
    put_u64(buf, kFileInfoV26V30V31LastRunOffset, 0); // no real runs recorded
    return buf;
}

// build_valid_prefetch_v31_blob() plus N well-formed volume entries at the
// real v31 stride (kVolumeEntryStrideV30V31), each with its own
// self-consistent refs sub-block ([version=3][count][u64 unknown], no
// reference array contents needed -- the parser never reads past the
// declared count/size), laid out back-to-back inside the volumes-info
// block. Mirrors the real two-volume fixtures' layout (OUTPUT.EXE/
// REG.EXE) closely enough to exercise entry 1+ specifically, with small
// buffer-local offsets instead of the real files' offsets thousands of
// bytes in. vol_info_size and file_size are both stamped to the exact,
// consistent final extent -- every SECTION below that wants a negative
// case mutates ONE field afterward rather than hand-building an
// inconsistent blob from scratch.
std::vector<uint8_t> build_valid_prefetch_v31_blob_with_volumes(
    const std::vector<uint32_t>& refs_counts) {
    auto buf = build_valid_prefetch_v31_blob();
    constexpr size_t kVolInfoOff = 0x100;
    constexpr size_t kEntryStride = kVolumeEntryStrideV30V31;
    const size_t entries_bytes = refs_counts.size() * kEntryStride;

    put_u32(buf, kFileInfoVolumesInfoCountOffset, static_cast<uint32_t>(refs_counts.size()));
    put_u32(buf, kFileInfoVolumesInfoOffsetField, static_cast<uint32_t>(kVolInfoOff));

    size_t cursor = entries_bytes; // refs sub-blocks start right after every entry
    for (size_t i = 0; i < refs_counts.size(); ++i) {
        const size_t entry = i * kEntryStride;
        const size_t refs_block_size =
            kFileRefsBlockHeaderBytes + static_cast<size_t>(refs_counts[i]) * 8;
        put_u32(buf, kVolInfoOff + entry + kVolumeEntryFileRefsOffsetField,
                static_cast<uint32_t>(cursor));
        put_u32(buf, kVolInfoOff + entry + kVolumeEntryFileRefsSizeField,
                static_cast<uint32_t>(refs_block_size));
        put_u32(buf, kVolInfoOff + cursor, 3); // refs sub-block "version" -- unvalidated by the parser
        put_u32(buf, kVolInfoOff + cursor + 4, refs_counts[i]);
        cursor += refs_block_size;
    }
    put_u32(buf, kFileInfoVolumesInfoSizeField, static_cast<uint32_t>(cursor));
    // The declared block extent (kVolInfoOff + cursor) can run past
    // whatever buf.size() happens to be so far -- the puts above only grow
    // buf far enough to write each field, never far enough to cover a
    // large refs_count's full (unwritten, and never read past count/size
    // by the parser) reference array. Pad explicitly so file_size, stamped
    // from the REAL buf.size() below, is never smaller than what this
    // function itself just declared.
    if (buf.size() < kVolInfoOff + cursor)
        buf.resize(kVolInfoOff + cursor, 0);
    // Puts above may have grown buf (e.g. a large refs_count) -- re-stamp
    // file_size to the buffer's FINAL extent, always last.
    put_u32(buf, kPrefetchFileSizeOffset, static_cast<uint32_t>(buf.size()));
    return buf;
}

// Single-entry convenience wrapper -- most negative SECTIONs below only
// need to mutate the one entry.
std::vector<uint8_t> build_valid_prefetch_v31_blob_with_volume(uint32_t refs_count) {
    return build_valid_prefetch_v31_blob_with_volumes({refs_count});
}

// A minimal but structurally valid v23 prefetch header, isolating the
// `is_v23` dispatch branch: its single last-run FILETIME slot and run-count
// field live at kFileInfoV23LastRunOffset/kFileInfoV23RunCountOffset, not
// the v26/30/31 offsets build_valid_prefetch_v31_blob() above uses. A
// distinguishing sentinel is also placed at the v26/30/31 run-count offset
// and at the second v26/30/31-style FILETIME slot, so a version-dispatch
// bug that reads the wrong constants (or loops 8 times instead of 1) is
// caught rather than accidentally passing.
//
// `version` is a parameter only so the truncated-vs-full v17 negative test
// below can reuse this exact byte layout with version DWORD 17 to prove
// version 17 is rejected BEFORE offset dispatch, never so it can be used to
// assert a positive v17 result -- v17 is deliberately unsupported (see
// is_supported_prefetch_version's comment) since its real offsets are 8
// bytes earlier than v23's and have never been verified against a capture.
std::vector<uint8_t> build_valid_prefetch_v23_blob(uint32_t version) {
    std::vector<uint8_t> buf(0x200, 0);
    put_u32(buf, kPrefetchVersionOffset, version);
    put_bytes(buf, kPrefetchSignatureOffset, "SCCA");
    put_u32(buf, kPrefetchFileSizeOffset, static_cast<uint32_t>(buf.size()));
    std::string exe_utf16;
    for (char c : std::string{"TEST23.EXE"}) {
        exe_utf16.push_back(c);
        exe_utf16.push_back('\0');
    }
    put_bytes(buf, kPrefetchExeNameOffset, exe_utf16);
    put_u32(buf, kPrefetchHashOffset, 0xCAFEF00D);
    put_u32(buf, kFileInfoVolumesInfoCountOffset, 0); // 0 volumes: skip file_ref_count walk
    put_u64(buf, kFileInfoV23LastRunOffset, 132000000000000000ull); // v23's one real slot
    put_u64(buf, kFileInfoV23LastRunOffset + 8, 999999999999999ull); // sentinel: 2nd v26/30/31-style slot
    put_u32(buf, kFileInfoV23RunCountOffset, 3);         // the correct v23 offset (0x98)
    put_u32(buf, kFileInfoV26V30V31RunCountOffset, 777); // sentinel: must NOT be read for v23
    return buf;
}

// build_valid_prefetch_v23_blob(version) plus N well-formed volume entries at
// the DOCUMENTATION-DERIVED v23/v26 stride (kVolumeEntryStrideV23V26, 0x68 --
// libscca, unpinned by any real capture in this repo, per that constant's own
// comment). Otherwise an exact mirror of
// build_valid_prefetch_v31_blob_with_volumes above (same field layout, same
// refs sub-block shape, same file_size/vol_info_size re-stamping discipline)
// with the 96-byte v30/v31 stride swapped for the 104-byte v23/v26 one --
// see that function's own comments for the parts not repeated here.
std::vector<uint8_t> build_valid_prefetch_v23_blob_with_volumes(
    uint32_t version, const std::vector<uint32_t>& refs_counts) {
    auto buf = build_valid_prefetch_v23_blob(version);
    constexpr size_t kVolInfoOff = 0x100;
    constexpr size_t kEntryStride = kVolumeEntryStrideV23V26;
    const size_t entries_bytes = refs_counts.size() * kEntryStride;

    put_u32(buf, kFileInfoVolumesInfoCountOffset, static_cast<uint32_t>(refs_counts.size()));
    put_u32(buf, kFileInfoVolumesInfoOffsetField, static_cast<uint32_t>(kVolInfoOff));

    size_t cursor = entries_bytes;
    for (size_t i = 0; i < refs_counts.size(); ++i) {
        const size_t entry = i * kEntryStride;
        const size_t refs_block_size =
            kFileRefsBlockHeaderBytes + static_cast<size_t>(refs_counts[i]) * 8;
        put_u32(buf, kVolInfoOff + entry + kVolumeEntryFileRefsOffsetField,
                static_cast<uint32_t>(cursor));
        put_u32(buf, kVolInfoOff + entry + kVolumeEntryFileRefsSizeField,
                static_cast<uint32_t>(refs_block_size));
        put_u32(buf, kVolInfoOff + cursor, 3);
        put_u32(buf, kVolInfoOff + cursor + 4, refs_counts[i]);
        cursor += refs_block_size;
    }
    put_u32(buf, kFileInfoVolumesInfoSizeField, static_cast<uint32_t>(cursor));
    if (buf.size() < kVolInfoOff + cursor)
        buf.resize(kVolInfoOff + cursor, 0);
    put_u32(buf, kPrefetchFileSizeOffset, static_cast<uint32_t>(buf.size()));
    return buf;
}

} // namespace

// ─────────────────────────────────────────────────────────── ShimCache ────

TEST_CASE("parse_shimcache: A1's real capture parses to >0 entries with a plausible first path",
          "[execution_artifacts][shimcache]") {
    const auto bytes = read_fixture_bytes(fixture_dir() / "shimcache.bin");

    Result<ShimCacheResult> r{ShimCacheResult{}};
    REQUIRE_NOTHROW(r = parse_shimcache(bytes));
    REQUIRE(r.has_value());
    const auto& result = *r;

    CHECK(result.scheme == "win10");
    REQUIRE(result.rows.size() > 0);
    const auto& first = result.rows.front();
    // Plausible: an absolute Windows path (drive letter + backslash).
    CHECK(first.path.size() > 3);
    CHECK(first.path[1] == ':');
    CHECK(first.path[2] == '\\');
    CHECK(ShimCacheRow::insert_flag == "-");
}

TEST_CASE("parse_shimcache: six negatives all return typed errors, none throw",
          "[execution_artifacts][shimcache][negative]") {
    const auto real_bytes = read_fixture_bytes(fixture_dir() / "shimcache.bin");

    SECTION("truncated at 0x20 -- shorter than the header size itself") {
        std::vector<uint8_t> truncated(real_bytes.begin(),
                                       real_bytes.begin() + std::min<size_t>(0x20, real_bytes.size()));
        Result<ShimCacheResult> r{ShimCacheResult{}};
        REQUIRE_NOTHROW(r = parse_shimcache(truncated));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_header");
    }

    SECTION("header claims an unrecognised scheme (0x99)") {
        auto buf = build_valid_shimcache_blob();
        put_u32(buf, 0, 0x99);
        Result<ShimCacheResult> r{ShimCacheResult{}};
        REQUIRE_NOTHROW(r = parse_shimcache(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "unknown_version");
    }

    SECTION("entry_size is 0xFFFFFFFF") {
        auto buf = build_valid_shimcache_blob();
        put_u32(buf, 0x34 + 8, 0xFFFFFFFFu);
        Result<ShimCacheResult> r{ShimCacheResult{}};
        REQUIRE_NOTHROW(r = parse_shimcache(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "oversize_count");
    }

    SECTION("path_len extends beyond the buffer") {
        auto buf = build_valid_shimcache_blob();
        put_u16(buf, 0x34 + 12, 60000); // exceeds the 32 KiB cap (kShimCacheMaxPathLen)
        Result<ShimCacheResult> r{ShimCacheResult{}};
        REQUIRE_NOTHROW(r = parse_shimcache(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "bad_path_length");
    }

    SECTION("entry_size declares far more than the buffer has left (SYN-04)") {
        // Reproduces the exact empirically-verified overrun: a 90-byte
        // buffer whose entry_size (5042) is under the 64 KiB hard cap but
        // claims 48+5042 == 5090 bytes total, vastly more than the 90 the
        // buffer actually holds. Before the fix this parsed successfully
        // (one row, cursor advanced straight past the end of the buffer,
        // loop exit on the out-of-range offset) with no truncation signal
        // at all -- entry_size was checked against the hard cap only, never
        // against the actual remaining bytes.
        std::vector<uint8_t> buf;
        put_u32(buf, 0, 0x30); // header_size = 48
        const size_t entry_off = 0x30;
        put_bytes(buf, entry_off, "10ts");
        put_u32(buf, entry_off + 4, 0);    // unknown
        put_u32(buf, entry_off + 8, 5042); // entry_size -- far past what's left
        buf.resize(90, 0);
        REQUIRE(buf.size() == 90);

        Result<ShimCacheResult> r{ShimCacheResult{}};
        REQUIRE_NOTHROW(r = parse_shimcache(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_entry");
    }
    SECTION("entry_size (10) undercuts what this entry actually needs (~80 bytes)") {
        auto buf = build_valid_shimcache_blob();
        put_u32(buf, 0x34 + 8, 10);
        auto r = parse_shimcache(buf);
        CHECK((!r.has_value() && r.error().token == "truncated_entry"));
    }
}

// ────────────────────────────────────────────────────────────  AmCache  ────

namespace {

// The "small reg-export reader" this package's spec calls for -- lives in
// the test, not in production code, since parse_amcache_inventory_
// application_file's input contract is already-decoded text (this package's
// spec: pure text->row mapping, no registry I/O of its own). Parses A1's
// real `reg query`-style export: UTF-16LE with BOM, one blank-line-
// separated block per subkey, each starting with an "HKEY_LOCAL_MACHINE..."
// line and followed by "    <Name>    <REG_TYPE>    <Value>" lines.
std::string utf16le_file_to_utf8(const fs::path& path) {
    REQUIRE(fs::exists(path));
    std::ifstream f(path, std::ios::binary);
    REQUIRE(f.is_open());
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    size_t start = 0;
    if (raw.size() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        start = 2; // UTF-16LE BOM
    std::string out;
    for (size_t i = start; i + 1 < raw.size(); i += 2) {
        uint16_t unit = static_cast<uint16_t>(raw[i]) | (static_cast<uint16_t>(raw[i + 1]) << 8);
        if (unit == 0)
            continue;
        if (unit <= 0x7F) {
            out.push_back(static_cast<char>(unit));
        } else if (unit <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | (unit >> 6)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (unit >> 12)));
            out.push_back(static_cast<char>(0x80 | ((unit >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        }
    }
    return out;
}

std::string trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
        ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        --e;
    return std::string{s.substr(b, e - b)};
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        if (nl == std::string::npos) {
            lines.push_back(text.substr(start));
            break;
        }
        lines.push_back(text.substr(start, nl - start));
        start = nl + 1;
    }
    return lines;
}

// name, type, value -- value may itself contain internal spaces (e.g.
// LinkDate "05/20/2026 18:40:00"), so only the first TWO whitespace runs
// are treated as delimiters.
bool split_reg_value_line(const std::string& raw_line, std::string& name, std::string& value) {
    std::string line = trim(raw_line);
    if (line.empty())
        return false;
    size_t p1 = line.find_first_of(" \t");
    if (p1 == std::string::npos)
        return false;
    name = line.substr(0, p1);
    size_t p2 = line.find_first_not_of(" \t", p1);
    if (p2 == std::string::npos)
        return false;
    size_t p3 = line.find_first_of(" \t", p2);
    if (p3 == std::string::npos)
        return false;
    size_t p4 = line.find_first_not_of(" \t", p3);
    if (p4 == std::string::npos) {
        value.clear();
        return true;
    }
    value = line.substr(p4);
    return true;
}

std::vector<std::pair<std::string, std::map<std::string, std::string>>>
parse_reg_export_subkeys(const std::string& text) {
    std::vector<std::pair<std::string, std::map<std::string, std::string>>> out;
    for (const auto& raw_line : split_lines(text)) {
        std::string line = trim(raw_line);
        if (line.rfind("HKEY_LOCAL_MACHINE", 0) == 0) {
            out.emplace_back(line, std::map<std::string, std::string>{});
            continue;
        }
        if (out.empty() || line.empty())
            continue;
        std::string name, value;
        if (split_reg_value_line(raw_line, name, value))
            out.back().second[name] = value;
    }
    return out;
}

} // namespace

TEST_CASE("parse_amcache_inventory_application_file: A1's 5 real subkeys map correctly, all "
          "well-formed FileIds normalise to 40-hex sha1",
          "[execution_artifacts][amcache]") {
    const auto text = utf16le_file_to_utf8(fixture_dir() / "amcache_inventory_application_file.txt");
    const auto subkeys = parse_reg_export_subkeys(text);
    REQUIRE(subkeys.size() == 5);

    AmCacheResult result;
    REQUIRE_NOTHROW(result = parse_amcache_inventory_application_file(subkeys));
    REQUIRE(result.rows.size() == 5);
    CHECK(result.malformed_fields == 0); // every real FileId is well-formed

    for (const auto& row : result.rows) {
        INFO("path: " << row.lower_case_long_path);
        CHECK_FALSE(row.lower_case_long_path.empty());
        REQUIRE(row.sha1.size() == 40);
        for (char c : row.sha1)
            CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
        CHECK_FALSE(row.size.empty());
        CHECK_FALSE(row.publisher.empty());
        CHECK_FALSE(row.binary_type.empty());
    }

    // First subkey's known-good fields (crossdevicesettingshost.exe), pinned
    // against the real fixture text read above.
    const auto& first = result.rows.front();
    CHECK(first.lower_case_long_path.find("crossdevicesettingshost.exe") != std::string::npos);
    CHECK(first.sha1 == "8dceb0eefac1501cb512270fa7cd4b906e44c70b");
    CHECK(first.binary_type == "pe64_amd64");
}

TEST_CASE("parse_amcache_inventory_application_file: malformed FileId -> '-' + "
          "malformed_fields; missing values -> empty",
          "[execution_artifacts][amcache][negative]") {
    std::vector<std::pair<std::string, std::map<std::string, std::string>>> subkeys;

    // Malformed: wrong prefix (not "0000").
    subkeys.push_back({"HKEY_LOCAL_MACHINE\\...\\bad1",
                       {{"FileId", "1234deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
                        {"LowerCaseLongPath", "c:\\bad1.exe"}}});
    // Malformed: non-hex character.
    subkeys.push_back({"HKEY_LOCAL_MACHINE\\...\\bad2",
                       {{"FileId", "0000zzzzeefac1501cb512270fa7cd4b906e44c70b"},
                        {"LowerCaseLongPath", "c:\\bad2.exe"}}});
    // Missing FileId entirely, and missing several other fields.
    subkeys.push_back({"HKEY_LOCAL_MACHINE\\...\\bad3", {{"LowerCaseLongPath", "c:\\bad3.exe"}}});

    AmCacheResult result;
    REQUIRE_NOTHROW(result = parse_amcache_inventory_application_file(subkeys));
    REQUIRE(result.rows.size() == 3);
    CHECK(result.malformed_fields == 2); // bad1 + bad2, NOT bad3 (missing is not malformed)

    CHECK(result.rows[0].sha1 == "-");
    CHECK(result.rows[1].sha1 == "-");
    CHECK(result.rows[2].sha1 == "-"); // missing -> "-" too, just not counted as malformed
    CHECK(result.rows[2].publisher.empty());
    CHECK(result.rows[2].link_date.empty());
}

// ────────────────────────────────────────────────────────────  Prefetch  ───

namespace {

struct RealPrefetchCapture {
    std::string basename;   // e.g. "DOSKEY.EXE-DDFD0A8D"
    std::string exe_prefix; // "DOSKEY.EXE"
    std::string hash_suffix; // "DDFD0A8D"
    uint32_t volume_count;  // byte-verified against the real file-information block
    uint32_t file_ref_count; // SUM across every declared volume entry (not just entry 0)
};

const std::vector<RealPrefetchCapture>& real_prefetch_captures() {
    // volume_count/file_ref_count independently re-derived by walking each
    // real file's raw bytes at the documented offsets (this file's own
    // kVolumeEntryFileRefsOffsetField comment has the full per-entry
    // evidence) -- DOSKEY has 1 volume with 15 refs; OUTPUT and REG.EXE
    // each have 2 volumes, whose per-entry refs counts (7+16 and 3+29
    // respectively) the round-2 review found this parser previously never
    // read past entry 0 for.
    static const std::vector<RealPrefetchCapture> v = {
        {"DOSKEY.EXE-DDFD0A8D", "DOSKEY.EXE", "DDFD0A8D", 1, 15},
        {"OUTPUT.EXE-EE9CBC0B", "OUTPUT.EXE", "EE9CBC0B", 2, 23},
        {"REG.EXE-6A8B6960", "REG.EXE", "6A8B6960", 2, 32},
    };
    return v;
}

// A1's real captures were all written on 2026-09-06 (the-rig's local
// LastWriteTime, per prefetch_selected.txt) -- a +-1 day UTC window absorbs
// any timezone the-rig might be in without parsing its LastWriteTime string
// as a specific zone.
constexpr int64_t kCaptureWindowStartMs = 1788480000000; // 2026-09-04T00:00:00Z
constexpr int64_t kCaptureWindowEndMs = 1788912000000;   // 2026-09-09T00:00:00Z

} // namespace

TEST_CASE("is_mam_compressed + mam_uncompressed_size: A1's three real .pf files are MAM, and "
          "the claimed size matches the real .pf.decompressed size exactly",
          "[execution_artifacts][prefetch]") {
    for (const auto& cap : real_prefetch_captures()) {
        INFO("capture: " << cap.basename);
        const auto compressed = read_fixture_bytes(fixture_dir() / (cap.basename + ".pf"));
        const auto decompressed =
            read_fixture_bytes(fixture_dir() / (cap.basename + ".pf.decompressed"));

        CHECK(is_mam_compressed(compressed));

        Result<uint32_t> size_result{0};
        REQUIRE_NOTHROW(size_result = mam_uncompressed_size(compressed));
        REQUIRE(size_result.has_value());
        CHECK(*size_result == decompressed.size());
    }
}

TEST_CASE("parse_prefetch: A1's three real .pf.decompressed payloads pin exe_name/hash/"
          "run_count/last_run against the filename and capture window",
          "[execution_artifacts][prefetch]") {
    for (const auto& cap : real_prefetch_captures()) {
        INFO("capture: " << cap.basename);
        const auto decompressed =
            read_fixture_bytes(fixture_dir() / (cap.basename + ".pf.decompressed"));

        Result<PrefetchResult> result{PrefetchResult{}};
        REQUIRE_NOTHROW(result = parse_prefetch(decompressed));
        REQUIRE(result.has_value());

        // Real Windows 10/11 captures parse as version 31, not 30 -- see
        // this package's parsers header for the byte-level evidence.
        CHECK(result->version == 31);
        CHECK(result->exe_name == cap.exe_prefix);
        CHECK(result->hash_hex == cap.hash_suffix);
        CHECK(result->run_count >= 1);
        // Exact, per-capture, byte-verified volume_count and SUMMED
        // file_ref_count (kVolumeEntryFileRefsOffsetField's doc comment
        // above has the full per-entry evidence) -- for OUTPUT and
        // REG.EXE this is the multi-volume walk actually exercised
        // against real data (each has a real, non-trivial entry 1 the
        // parser previously never read), not just bounded in the
        // mutation fuzz below.
        CHECK(result->volume_count == cap.volume_count);
        CHECK(result->file_ref_count == cap.file_ref_count);
        REQUIRE_FALSE(result->last_runs_epoch_ms.empty());
        CHECK(result->last_runs_epoch_ms.size() <= kPrefetchMaxLastRuns);
        for (int64_t ts : result->last_runs_epoch_ms) {
            CHECK(ts >= kCaptureWindowStartMs);
            CHECK(ts <= kCaptureWindowEndMs);
        }
        CHECK(result->volume_count <= kPrefetchMaxVolumes);
        CHECK(result->file_ref_count <= kPrefetchMaxFileRefs);
    }

    // REG.EXE was invoked 8+ times before capture (A1's provenance) --
    // exactly the shape that fills all 8 last-run slots.
    const auto reg_bytes = read_fixture_bytes(fixture_dir() / "REG.EXE-6A8B6960.pf.decompressed");
    auto reg_result = parse_prefetch(reg_bytes);
    REQUIRE(reg_result.has_value());
    CHECK(reg_result->run_count >= 8);
    CHECK(reg_result->last_runs_epoch_ms.size() == 8);
}

TEST_CASE("parse_prefetch: direct (non-MAM) parse on a synthetic buffer, no real uncompressed "
          "capture exists on the-rig",
          "[execution_artifacts][prefetch]") {
    const auto buf = build_valid_prefetch_v31_blob();
    auto result = parse_prefetch(buf);
    REQUIRE(result.has_value());
    CHECK(result->exe_name == "TEST.EXE");
    CHECK(result->hash_hex == "DEADBEEF");
    CHECK(result->run_count == 1);
    CHECK(result->last_runs_epoch_ms.empty()); // FILETIME zeroed -> no recorded run
}

TEST_CASE("parse_prefetch: v23 file-information offsets are distinct from v26/30/31 and are "
          "actually wired up -- RECONSTRUCTION only, the-rig has no real fixture for this "
          "version",
          "[execution_artifacts][prefetch]") {
    const auto buf = build_valid_prefetch_v23_blob(23u);
    auto result = parse_prefetch(buf);
    REQUIRE(result.has_value());
    CHECK(result->version == 23u);
    // Must come from kFileInfoV23RunCountOffset (0x98), not the
    // v26/30/31 offset (0xC8) -- a transposed/mis-selected offset would
    // read the 777 sentinel planted there instead.
    CHECK(result->run_count == 3);
    // Only ONE last-run FILETIME slot is read for v23, not eight -- a
    // wrongly-dispatched n_last_runs==8 would also pick up the non-zero
    // sentinel planted in the second v26/30/31-style slot.
    REQUIRE(result->last_runs_epoch_ms.size() == 1);
    CHECK(result->last_runs_epoch_ms.front() > 0);
}

TEST_CASE("parse_prefetch: version 17 (XP/2003) is rejected, not silently misparsed with v23's "
          "offsets",
          "[execution_artifacts][prefetch][negative]") {
    // v17 is deliberately excluded from is_supported_prefetch_version --
    // its real layout offsets last-run-time/run-count 8 bytes earlier than
    // v23 (0x78/0x90 vs 0x80/0x98) and that offset pair has never been
    // verified against a real capture, unlike every other supported
    // version in this file. Before the fix this same v17-tagged buffer
    // parsed "successfully" by reusing v23's offsets; it must now report
    // unknown_version instead.
    const auto buf = build_valid_prefetch_v23_blob(17u);
    auto result = parse_prefetch(buf);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().token == "unknown_version");
}

TEST_CASE("parse_prefetch: RECONSTRUCTION-only negatives -- truncated header, unknown version, "
          "oversize run count, undersized file_size",
          "[execution_artifacts][prefetch][negative]") {
    SECTION("truncated header") {
        std::vector<uint8_t> tiny(2, 0); // shorter than the version DWORD itself
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(tiny));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_header");
    }

    SECTION("version 99 -- no supported layout has ever used this") {
        auto buf = build_valid_prefetch_v31_blob();
        put_u32(buf, kPrefetchVersionOffset, 99);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "unknown_version");
    }

    SECTION("run count 0xFFFFFFFF") {
        auto buf = build_valid_prefetch_v31_blob();
        put_u32(buf, kFileInfoV26V30V31RunCountOffset, 0xFFFFFFFFu);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "oversize_count");
    }

    SECTION("MAM header claims 1 GiB uncompressed -- rejected before any allocation is sized "
            "off it") {
        std::vector<uint8_t> mam_header = {'M', 'A', 'M', 0x04};
        put_u32(mam_header, 4, 1024u * 1024u * 1024u);
        Result<uint32_t> r{0};
        REQUIRE_NOTHROW(r = mam_uncompressed_size(mam_header));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "oversize_count");
    }
    SECTION("file_size undercuts this version's required fields (through run_count)") {
        auto buf = build_valid_prefetch_v31_blob();
        put_u32(buf, kPrefetchFileSizeOffset, 100);
        auto r = parse_prefetch(buf);
        CHECK((!r.has_value() && r.error().token == "truncated_entry"));
    }

    // The nested volume_count > 0 file_ref_count walk used to default
    // file_ref_count to 0 and still return success on any of these
    // failures -- indistinguishable from "this file genuinely references
    // zero volumes' worth of files". Each must now fail the whole parse
    // with a named reason, matching the sibling run_count/volume_count
    // reads immediately above it. Round-2 review finding: an earlier
    // revision of both this parser and these tests only ever validated
    // volume entry 0 -- every SECTION below that says "entry 1" is new,
    // added specifically to prove the walk actually visits every declared
    // entry, not just the first.
    SECTION("volume_count > 0 but the refs-block offset stored inside the (single) volume "
            "entry points past the volumes-info block") {
        auto buf = build_valid_prefetch_v31_blob_with_volume(3);
        put_u32(buf, 0x100 + kVolumeEntryFileRefsOffsetField, 0xFFFFFF00u);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_entry");
    }

    SECTION("volume_count > 0 but the refs-block's declared byte size is smaller than its own "
            "declared count needs (16 + count*8 > refs_size)") {
        auto buf = build_valid_prefetch_v31_blob_with_volume(3);
        // A well-formed refs_size for count=3 is 16+3*8=40; shrink it below
        // that without touching the count field itself.
        put_u32(buf, 0x100 + kVolumeEntryFileRefsSizeField, 20u);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "oversize_count");
    }

    SECTION("volume_count * stride exceeds the volumes-info block's own declared byte size") {
        auto buf = build_valid_prefetch_v31_blob_with_volume(3);
        // The one entry's stride is kVolumeEntryStrideV30V31 (0x60) -- a
        // declared block size smaller than that can't hold even entry 0's
        // fixed fields, regardless of what its refs sub-block claims.
        put_u32(buf, kFileInfoVolumesInfoSizeField, 0x10u);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_entry");
    }

    SECTION("the volumes-info block's own declared extent (offset + size) runs past file_size") {
        auto buf = build_valid_prefetch_v31_blob_with_volume(3);
        put_u32(buf, kFileInfoVolumesInfoSizeField, 0xFFFFFF00u);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_entry");
    }

    SECTION("volume_count > 0 and every offset resolves, but the refs count exceeds "
            "kPrefetchMaxFileRefs") {
        auto buf = build_valid_prefetch_v31_blob_with_volume(kPrefetchMaxFileRefs + 1);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "oversize_count");
    }

    SECTION("volume_count > 0, every bound/size check passes, but the refs sub-block's own "
            "version dword is not the byte-verified constant 3 -- the semantic anchor added "
            "for the round-3 review's stride-overclaim finding (#4467) must itself be "
            "load-bearing, not just present") {
        auto buf = build_valid_prefetch_v31_blob_with_volume(5);
        // The refs sub-block for a single entry at stride kVolumeEntryStrideV30V31 (96)
        // starts right where the entries region ends -- kVolInfoOff(0x100) + 96 -- and its
        // version dword is the first 4 bytes of that sub-block.
        put_u32(buf, 0x100 + kVolumeEntryStrideV30V31, 99u);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_entry");
    }

    SECTION("two volumes, each individually well under kPrefetchMaxFileRefs, but their SUM "
            "exceeds it -- the running total_refs cap is a separate check from each entry's "
            "own per-entry cap, and mutation-testing confirmed removing it left every existing "
            "test green (neither entry alone ever tripped oversize_count)") {
        auto buf = build_valid_prefetch_v31_blob_with_volumes({40000, 30000});
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "oversize_count");
    }

    SECTION("two volumes: entry 0 is well-formed, entry 1's refs-block offset is corrupted -- "
            "the walk must fail on entry 1, not silently stop after entry 0") {
        auto buf = build_valid_prefetch_v31_blob_with_volumes({5, 7});
        constexpr size_t kEntry1 = kVolumeEntryStrideV30V31; // entry 1 starts one stride in
        put_u32(buf, 0x100 + kEntry1 + kVolumeEntryFileRefsOffsetField, 0xFFFFFF00u);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_entry");
    }

    SECTION("two volumes: entry 0 is well-formed, entry 1's refs count exceeds the cap -- the "
            "cap applies to every entry, not just the first") {
        auto buf = build_valid_prefetch_v31_blob_with_volumes({5, 7});
        // Per the builder: 2 entries at stride 0x60 = 0xC0 (192) bytes of
        // entries, so entry 0's refs sub-block (16 + 5*8 = 56 bytes) starts
        // at block-relative 0xC0 and entry 1's starts right after it, at
        // 0xC0 + 56 = 0xF8 (248). The count DWORD is 4 bytes into a refs
        // sub-block (after the version DWORD).
        constexpr uint32_t kEntry1RefsBlockOff = 0xC0 + 16 + 5 * 8; // 248
        put_u32(buf, 0x100 + kEntry1RefsBlockOff + 4,
                static_cast<uint32_t>(kPrefetchMaxFileRefs) + 1);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "oversize_count");
    }

    SECTION("volume_count > 0 with a well-formed nested refs chain succeeds with the exact "
            "count -- proves the walk isn't ALWAYS an error after the fix above") {
        auto buf = build_valid_prefetch_v31_blob_with_volume(5);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE(r.has_value());
        CHECK(r->volume_count == 1);
        CHECK(r->file_ref_count == 5);
    }

    SECTION("two volumes with well-formed nested refs chains succeed with the SUMMED count -- "
            "this is the exact shape the round-2 review found unvalidated (entry 1 silently "
            "unread)") {
        auto buf = build_valid_prefetch_v31_blob_with_volumes({5, 7});
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE(r.has_value());
        CHECK(r->volume_count == 2);
        CHECK(r->file_ref_count == 12);
    }

    // The three SECTIONs below are new coverage for the v23/v26 stride
    // (kVolumeEntryStrideV23V26, 0x68/104) -- documentation-derived (libscca),
    // never pinned against a real capture in this repo (no v23/v26 fixture
    // exists; every real .pf.decompressed this repo has is v31). Before these,
    // no test ever gave a v23 or v26 blob a nonzero volume_count at all, so
    // the stride-selection branch had zero exercise.
    //
    // Mutation-tested (2026-09-17): hardcoding the stride to the pinned
    // kVolumeEntryStrideV30V31 (96) regardless of version reddens the v26
    // two-volume SECTION below -- entry 1 is then read 8 bytes short of
    // where it actually starts, landing in an unwritten (zero) region of
    // entry 0's own tail, so refs_off/refs_size both read back as 0 and the
    // parse fails instead of returning the correct summed count. That is
    // real, load-bearing proof the 104-byte stride is actually used. The
    // single-volume positive is NOT discriminating for stride -- entry 0's
    // own position never depends on it (i*stride is 0 for i=0 regardless of
    // stride's value) -- it only proves the v23 header-field dispatch (the
    // is_v23 branch) reaches the volume walk at all. The entry-1-corruption
    // negative is ALSO not stride-discriminating: under the same wrong-
    // stride mutation, the corrupted bytes are simply never read (the wrong
    // offset lands on a different, unwritten zero region instead), and
    // reading that zero region still trips the refs_block_size<16 floor via
    // a different path -- so it coincidentally still returns truncated_entry
    // either way. It is kept because it is still a genuine, real negative
    // (a corrupted entry 1 in a v23 multi-volume file must fail the parse,
    // full stop) -- just not proof of which stride was used.
    SECTION("v23 with a single volume succeeds with the true count -- proves the version-23 "
            "header-field dispatch reaches the volume walk at all") {
        auto buf = build_valid_prefetch_v23_blob_with_volumes(23u, {9});
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE(r.has_value());
        CHECK(r->version == 23u);
        CHECK(r->volume_count == 1);
        CHECK(r->file_ref_count == 9);
    }

    SECTION("v26 two volumes succeed with the SUMMED count -- the discriminating proof that "
            "entry 1 is actually read at the 104-byte stride (mutation-verified above), and "
            "that the dispatch isn't hardcoded to the literal 23") {
        auto buf = build_valid_prefetch_v23_blob_with_volumes(26u, {5, 7});
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE(r.has_value());
        CHECK(r->version == 26u);
        CHECK(r->volume_count == 2);
        CHECK(r->file_ref_count == 12);
    }

    SECTION("v23 two volumes succeed via well-formed bytes at the CODE'S ASSUMED 104-byte "
            "offset -- the permanent, accepted 'constructed coincidence' residual both "
            "reviewers of PR #4444's round-3 review independently reproduced (issue #4467), "
            "kept here as a locked-in regression rather than something this parser can ever "
            "close") {
        // This is the SAME construction as the v26 two-volume test above, not a
        // materially different byte layout -- and that is exactly the point.
        // build_valid_prefetch_v23_blob_with_volumes places entry 1's refs
        // sub-block at whatever offset kVolumeEntryStrideV23V26 (104) computes,
        // then the parser reads entry 1 back from that SAME assumed offset --
        // so this test, and every other v23/v26 two-volume positive above,
        // IS the "wrong-stride-but-well-formed" scenario: nothing in
        // parse_prefetch (bounds, refs_size/count consistency, or the version-
        // field anchor added in response to this finding) can distinguish
        // "entry 1 genuinely starts at 104" from "entry 1 does not really
        // start there, but well-formed refs-sub-block bytes happen to be
        // present anyway" -- both reviewers independently proved this by
        // hand-constructing exactly this shape. A NATURALLY wrong stride
        // (see the two SECTIONs above and the mutation test they cite)
        // reads unwritten zero bytes and fails closed; only a DELIBERATE
        // construction like this one -- indistinguishable, from inside the
        // parser, from a genuinely well-formed file -- produces a false
        // success. See execution_artifacts_parsers.hpp's file_ref_count
        // doc comment and README.md caveat 1 for the full reasoning on why
        // this is accepted as permanent, not something to chase further.
        auto buf = build_valid_prefetch_v23_blob_with_volumes(23u, {3, 4});
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE(r.has_value());
        CHECK(r->version == 23u);
        CHECK(r->volume_count == 2);
        CHECK(r->file_ref_count == 7);
    }

    SECTION("v23 two volumes: entry 0 is well-formed, entry 1's refs-block offset is corrupted "
            "-- a malformed entry 1 in a v23 multi-volume file still fails the whole parse, "
            "not just entry 0 (not itself stride-discriminating -- see the comment above)") {
        auto buf = build_valid_prefetch_v23_blob_with_volumes(23u, {5, 7});
        constexpr size_t kEntry1 = kVolumeEntryStrideV23V26; // entry 1 starts one stride in
        put_u32(buf, 0x100 + kEntry1 + kVolumeEntryFileRefsOffsetField, 0xFFFFFF00u);
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(buf));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().token == "truncated_entry");
    }
}

// ============================================================================
// execution_artifacts_legs.hpp row-formatter escaping -- the "never surface
// raw file contents, only escaped metadata" guarantee this plugin's spec
// requires. Every formatter argument that carries untrusted OS text
// (paths, publisher/product strings, exe names) goes through the SDK's
// shared yuzu::util::safe_output_field, which folds '\' -> '/', CR/LF -> ' '
// and then escapes '|' -> "\|" (see string_utils.hpp's doc comment: this
// grammar has no newline escape, so CR/LF must never survive as a literal
// row separator). sha1/hash_hex are the one deliberate exception -- both
// are validated to a fixed hex-digit alphabet upstream (normalise_file_id /
// the prefetch parser's "8 uppercase hex digits" contract) before they ever
// reach these formatters, so they are emitted verbatim.
// ============================================================================

TEST_CASE("format_shimcache_row: normal input -- a real Windows path folds its backslashes",
          "[execution_artifacts][legs][formatter]") {
    auto row = format_shimcache_row("C:\\Windows\\System32\\cmd.exe", 1699999999000, 289280);
    CHECK(row == "shimcache|C:/Windows/System32/cmd.exe|1699999999000|289280|-");
    CHECK_FALSE(row.ends_with('\n'));
}

TEST_CASE("format_shimcache_row: a delimiter character in the path is escaped exactly like the "
          "SDK's own safe_output_field -- never a raw pass-through that would corrupt the "
          "downstream field count",
          "[execution_artifacts][legs][formatter]") {
    const std::string path = "C:\\Program Files\\Weird|App\\thing.exe";
    const auto expected_path = yuzu::util::safe_output_field(path);
    auto row = format_shimcache_row(path, 0, 0);
    CHECK(row == "shimcache|" + expected_path + "|0|0|-");
}

TEST_CASE("format_shimcache_row: embedded CR/LF never survive as a literal newline -- this "
          "grammar's row separator has no escape, so a raw one would fabricate a second row "
          "downstream; other control bytes outside safe_output_field's substitution set pass "
          "through unmolested (documented behaviour, not a defect)",
          "[execution_artifacts][legs][formatter]") {
    const std::string path =
        std::string("C:\\evil\r\ninjected") + "\x01" + "\x1f" + "\\cmd.exe";
    auto row = format_shimcache_row(path, 1, 2);
    CHECK(row == "shimcache|" + yuzu::util::safe_output_field(path) + "|1|2|-");
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find('\r') == std::string::npos);
    CHECK(row.find('\x01') != std::string::npos);
}

TEST_CASE("format_shimcache_row: non-UTF-8 bytes pass through unchanged -- safe_output_field "
          "escapes this grammar's own delimiters only, it does not sanitize text encoding "
          "(yuzu::util::sanitize_utf8 is the separate function for that, not called by any "
          "formatter here)",
          "[execution_artifacts][legs][formatter]") {
    const std::string path = std::string("C:\\Users\\") + "\xff\xfe" + "\\cmd.exe";
    auto row = format_shimcache_row(path, 3, 4);
    CHECK(row == "shimcache|" + yuzu::util::safe_output_field(path) + "|3|4|-");
    CHECK(row.find('\xff') != std::string::npos);
}

TEST_CASE("format_amcache_row: normal input, every field present",
          "[execution_artifacts][legs][formatter]") {
    auto row = format_amcache_row("c:\\windows\\system32\\cmd.exe",
                                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "289280",
                                  "133456789000000000", "Microsoft Corporation",
                                  "PE32+ executable", "Microsoft Windows Operating System",
                                  "10.0.19041.1");
    CHECK(row == "amcache|c:/windows/system32/cmd.exe|"
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|289280|133456789000000000|"
                 "Microsoft Corporation|PE32+ executable|"
                 "Microsoft Windows Operating System|10.0.19041.1");
}

TEST_CASE("format_amcache_row: every escaped field has its own independent call site -- a "
          "delimiter in ANY one of path/size/link_date/publisher/binary_type/product_name/"
          "product_version is escaped without disturbing the others",
          "[execution_artifacts][legs][formatter]") {
    const std::string path = "c:\\weird|path\\a.exe";
    const std::string size = "12|34";
    const std::string link_date = "13|00";
    const std::string publisher = "Weird|Publisher";
    const std::string binary_type = "PE|32";
    const std::string product_name = "Product|Name";
    const std::string product_version = "1|0";
    const std::string sha1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    auto row = format_amcache_row(path, sha1, size, link_date, publisher, binary_type,
                                  product_name, product_version);
    CHECK(row == "amcache|" + yuzu::util::safe_output_field(path) + "|" + sha1 + "|" +
                     yuzu::util::safe_output_field(size) + "|" +
                     yuzu::util::safe_output_field(link_date) + "|" +
                     yuzu::util::safe_output_field(publisher) + "|" +
                     yuzu::util::safe_output_field(binary_type) + "|" +
                     yuzu::util::safe_output_field(product_name) + "|" +
                     yuzu::util::safe_output_field(product_version));
}

TEST_CASE("format_amcache_row: sha1 is emitted verbatim, never escaped -- safe by construction "
          "because normalise_file_id (execution_artifacts_parsers.hpp) already rejects anything "
          "that is not exactly 40 lowercase hex characters before a row is ever formatted; this "
          "pins the CURRENT pass-through behaviour so a future caller that stops validating "
          "upstream does not silently inherit an escaping guarantee that was never wired up",
          "[execution_artifacts][legs][formatter]") {
    // A pipe here can never happen in production (normalise_file_id would
    // have mapped it to "-" already), but the formatter itself has no
    // opinion on its sha1 argument -- pin that explicitly.
    auto row = format_amcache_row("c:\\a.exe", "not-a-real-sha1|with-a-pipe", "1", "2", "3", "4",
                                  "5", "6");
    CHECK(row == "amcache|c:/a.exe|not-a-real-sha1|with-a-pipe|1|2|3|4|5|6");
}

TEST_CASE("format_amcache_row: embedded control bytes and non-UTF-8 bytes in an escaped field "
          "behave exactly as safe_output_field defines, CR/LF folded and pipes escaped",
          "[execution_artifacts][legs][formatter]") {
    const std::string publisher = std::string("Evil\r\nCorp") + "\xff" + "|Ltd";
    auto row = format_amcache_row("c:\\a.exe", "cccccccccccccccccccccccccccccccccccccccc", "1",
                                  "2", publisher, "4", "5", "6");
    CHECK(row == "amcache|c:/a.exe|cccccccccccccccccccccccccccccccccccccccc|1|2|" +
                     yuzu::util::safe_output_field(publisher) + "|4|5|6");
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find('\r') == std::string::npos);
}

TEST_CASE("format_prefetch_row: normal input, multiple run timestamps rendered as a CSV field",
          "[execution_artifacts][legs][formatter]") {
    auto row = format_prefetch_row("CMD.EXE", "DDFD0A8D", 31, 5,
                                   {1699999999000, 1699999998000}, 2, 3);
    CHECK(row == "prefetch|CMD.EXE|DDFD0A8D|31|5|1699999999000,1699999998000|2|3");
}

TEST_CASE("format_prefetch_row: an empty run-history list still leaves an EMPTY field, not a "
          "collapsed one -- the delimiter grammar must hold even when the CSV column is empty",
          "[execution_artifacts][legs][formatter]") {
    auto row = format_prefetch_row("a.exe", "AAAAAAAA", 1, 0, {}, 0, 0);
    CHECK(row == "prefetch|a.exe|AAAAAAAA|1|0||0|0");
}

TEST_CASE("format_prefetch_row: a delimiter/control character in exe_name is escaped via "
          "safe_output_field; hash_hex is emitted verbatim (pre-validated to 8 uppercase hex "
          "digits by the prefetch parser, same rationale as amcache's sha1)",
          "[execution_artifacts][legs][formatter]") {
    const std::string exe_name = "Evil|Name\r\n.exe";
    auto row = format_prefetch_row(exe_name, "DEADBEEF", 31, 1, {1}, 1, 1);
    CHECK(row == "prefetch|" + yuzu::util::safe_output_field(exe_name) + "|DEADBEEF|31|1|1|1|1");
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find('\r') == std::string::npos);
}

TEST_CASE("format_prefetch_row: non-UTF-8 bytes in exe_name pass through the escaper unchanged, "
          "same guarantee as format_shimcache_row's non-UTF-8 case",
          "[execution_artifacts][legs][formatter]") {
    const std::string exe_name = std::string("bad") + "\xfe\xff" + "name.exe";
    auto row = format_prefetch_row(exe_name, "CAFEBABE", 26, 0, {}, 0, 0);
    CHECK(row == "prefetch|" + yuzu::util::safe_output_field(exe_name) + "|CAFEBABE|26|0||0|0");
}

// ============================================================================
// MUTATION FUZZ -- deterministic byte/map-level sweeps over the REAL CAPTURE
// fixtures, one TEST_CASE per PRODUCTION parser boundary (this package's
// spec, adjudication P9: fuzz the function the shell actually calls, never a
// test-only decoder). Tag: [execution_artifacts][fuzz].
//
// SEED: a fixed 32-bit LCG (Numerical Recipes constants, state' = state *
// 1664525 + 1013904223), always re-seeded from 0x5eed7b01 at the start of
// each sweep, so every run of this binary flips/generates exactly the same
// bytes -- a fuzz finding here is always reproducible from the seed alone,
// never from wall-clock or PID entropy.
//
// SWEEP RULES:
//   TRUNCATION  -- every cut length 0..N-1 in steps of 1 when the real
//                  fixture is <= 8192 bytes, else every 16th length. Applied
//                  to (A) below.
//   BYTE-FLIP   -- 512 positions chosen by the LCG (mod the buffer size),
//                  each set to 0x00 / 0xFF / 0x7F in round-robin. Applied to
//                  (A) below.
//   FIELD-PATCH -- the four documented Prefetch count/offset u32 fields, each
//                  patched to 0 / 1 / 0x7FFFFFFF / 0xFFFFFFFF. Applied only
//                  to parse_prefetch (Prefetch has no other numeric fields
//                  this package's spec calls out).
//
// BOUNDARIES EXERCISED (one production entry point per TEST_CASE below):
//   (A) parse_shimcache                                   -- shimcache.bin
//   (A) parse_prefetch                                    -- *.pf.decompressed
//   (A) is_mam_compressed / mam_uncompressed_size          -- *.pf (compressed)
//   (B) parse_amcache_inventory_application_file (map-level, never the
//       test-only parse_reg_export_subkeys text decoder above)
// ============================================================================

namespace {

constexpr uint32_t kFuzzSeed = 0x5eed7b01u;

uint32_t lcg_next(uint32_t& state) {
    state = state * 1664525u + 1013904223u;
    return state;
}

// Every cut length 0..real.size()-1: step 1 when real.size() <= 8192, else
// every 16th length (this package's spec sweep rule).
void run_truncation_sweep(const std::vector<uint8_t>& real,
                          const std::function<void(const std::vector<uint8_t>&)>& check) {
    const size_t n = real.size();
    const size_t step = (n <= 8192) ? 1 : 16;
    for (size_t cut = 0; cut < n; cut += step) {
        std::vector<uint8_t> truncated(real.begin(), real.begin() + cut);
        check(truncated);
    }
}

// 512 single-byte flips at LCG-chosen positions, values 0x00/0xFF/0x7F
// round-robin (this package's spec sweep rule).
void run_byte_flip_sweep(const std::vector<uint8_t>& real,
                         const std::function<void(const std::vector<uint8_t>&)>& check) {
    if (real.empty())
        return;
    uint32_t state = kFuzzSeed;
    static constexpr uint8_t kFlipValues[3] = {0x00, 0xFF, 0x7F};
    for (int i = 0; i < 512; ++i) {
        const size_t pos = lcg_next(state) % real.size();
        std::vector<uint8_t> mutated = real;
        mutated[pos] = kFlipValues[i % 3];
        check(mutated);
    }
}

} // namespace

TEST_CASE("parse_shimcache: mutation fuzz over the real capture -- truncation sweep and byte "
          "flips never throw, and always either bound rows to kShimCacheMaxEntries or return a "
          "typed, in-range error",
          "[execution_artifacts][fuzz]") {
    const auto real = read_fixture_bytes(fixture_dir() / "shimcache.bin");

    auto check = [](const std::vector<uint8_t>& mutated) {
        Result<ShimCacheResult> r{ShimCacheResult{}};
        REQUIRE_NOTHROW(r = parse_shimcache(mutated));
        if (r.has_value()) {
            CHECK(r->rows.size() <= kShimCacheMaxEntries);
        } else {
            CHECK_FALSE(r.error().token.empty());
            // ParseError::offset is "for diagnostics only" (execution_artifacts_parsers.hpp) --
            // a fixed field offset the read attempted, not bounded by the (possibly truncated)
            // buffer size, so it is not asserted here beyond being non-empty above.
        }
    };

    run_truncation_sweep(real, check);
    run_byte_flip_sweep(real, check);
}

TEST_CASE("parse_prefetch: mutation fuzz over A1's three real .pf.decompressed captures -- "
          "truncation, byte flips, and the five documented count/offset field patches never "
          "throw, and a successful parse only ever reports a version "
          "is_supported_prefetch_version already accepts, with every count bounded",
          "[execution_artifacts][fuzz]") {
    auto check = [](const std::vector<uint8_t>& mutated) {
        Result<PrefetchResult> r{PrefetchResult{}};
        REQUIRE_NOTHROW(r = parse_prefetch(mutated));
        if (r.has_value()) {
            CHECK(is_supported_prefetch_version(r->version));
            CHECK(r->volume_count <= kPrefetchMaxVolumes);
            CHECK(r->file_ref_count <= kPrefetchMaxFileRefs);
            CHECK(r->last_runs_epoch_ms.size() <= kPrefetchMaxLastRuns);
        } else {
            CHECK_FALSE(r.error().token.empty());
            // Same rationale as parse_shimcache's fuzz case above.
        }
    };

    // These five patch positions are used as ABSOLUTE file offsets below, which
    // is exactly right for the first three and kPrefetchFileSizeOffset -- they
    // are genuinely top-level file-information-block header fields. It is only
    // approximately right for kVolumeEntryFileRefsOffsetField (0x14): that
    // constant is documented as BLOCK-relative (an offset *within* a volume
    // entry, added to kFileInfoVolumesInfoOffsetField's value elsewhere in this
    // file), so patching absolute byte 0x14 here actually corrupts an unrelated
    // header field that happens to share the same small numeric value, not the
    // volume entry's own refs-offset field. That's still a legitimate generic
    // robustness case for this test's own invariants (never throws, bounded
    // counts, typed error) -- corrupting ANY byte must hold those -- so it is
    // kept rather than removed, but it is not a substitute for a targeted test
    // of that field's own validation branch. That targeted coverage (plus its
    // sibling kVolumeEntryFileRefsSizeField, deliberately NOT added here for
    // the same absolute-vs-relative reason) lives in the "RECONSTRUCTION-only
    // negatives" TEST_CASE above, which computes each field's real absolute
    // position inside a synthetic multi-entry blob before patching it.
    static constexpr size_t kDocumentedFields[] = {
        kFileInfoVolumesInfoCountOffset,
        kFileInfoVolumesInfoOffsetField,
        kFileInfoVolumesInfoSizeField,
        kVolumeEntryFileRefsOffsetField,
        kPrefetchFileSizeOffset,
    };
    static constexpr uint32_t kFieldValues[] = {0u, 1u, 0x7FFFFFFFu, 0xFFFFFFFFu};

    for (const auto& cap : real_prefetch_captures()) {
        INFO("capture: " << cap.basename);
        const auto real = read_fixture_bytes(fixture_dir() / (cap.basename + ".pf.decompressed"));

        run_truncation_sweep(real, check);
        run_byte_flip_sweep(real, check);

        for (size_t field_off : kDocumentedFields) {
            for (uint32_t v : kFieldValues) {
                auto mutated = real;
                put_u32(mutated, field_off, v);
                check(mutated);
            }
        }
    }
}

TEST_CASE("is_mam_compressed / mam_uncompressed_size: mutation fuzz over A1's three real "
          "compressed .pf captures -- truncation and byte flips never throw, and a claimed "
          "uncompressed size is always bounded by kMamMaxUncompressedSize",
          "[execution_artifacts][fuzz]") {
    auto check = [](const std::vector<uint8_t>& mutated) {
        REQUIRE_NOTHROW(is_mam_compressed(mutated));
        Result<uint32_t> size_result{0};
        REQUIRE_NOTHROW(size_result = mam_uncompressed_size(mutated));
        if (size_result.has_value()) {
            CHECK(*size_result <= kMamMaxUncompressedSize);
        } else {
            CHECK_FALSE(size_result.error().token.empty());
            // mam_uncompressed_size only ever uses offsets 0/4, always in-bounds here in
            // practice, but dropped for the same documented-contract reason as above.
        }
    };

    for (const auto& cap : real_prefetch_captures()) {
        INFO("capture: " << cap.basename);
        const auto real = read_fixture_bytes(fixture_dir() / (cap.basename + ".pf"));

        run_truncation_sweep(real, check);
        run_byte_flip_sweep(real, check);
    }
}

namespace {

using Subkeys = std::vector<std::pair<std::string, std::map<std::string, std::string>>>;

constexpr std::array<std::string_view, 8> kAmcacheKeys = {
    "LowerCaseLongPath", "FileId",      "Size",         "LinkDate",
    "Publisher",         "BinaryType",  "ProductName",  "ProductVersion",
};

// A printable, deterministic byte (0-9a-zA-Z) from the LCG -- used for
// oversize-value filler where the byte content itself doesn't matter, only
// its length reaching the parser unmodified.
char lcg_printable(uint32_t& state) {
    static constexpr char kAlphabet[] =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    return kAlphabet[lcg_next(state) % (sizeof(kAlphabet) - 1)];
}

// A byte guaranteed OUTSIDE the lower-hex alphabet ("g".."z", uppercase
// letters that aren't A-F, punctuation) -- used to force a FileId candidate
// non-hex so its malformed-ness is deterministic, not LCG-luck-dependent.
char lcg_non_hex(uint32_t& state) {
    static constexpr char kAlphabet[] = "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ!@#$%^&*";
    return kAlphabet[lcg_next(state) % (sizeof(kAlphabet) - 1)];
}

std::string lcg_string(uint32_t& state, size_t length, bool non_hex) {
    std::string out;
    out.reserve(length);
    for (size_t i = 0; i < length; ++i)
        out.push_back(non_hex ? lcg_non_hex(state) : lcg_printable(state));
    return out;
}

} // namespace

TEST_CASE("parse_amcache_inventory_application_file: map-level mutation fuzz over A1's real "
          "subkey vector -- dropped keys, malformed/oversized FileId and value shapes, an empty "
          "vector, and 20,001 identical subkeys, asserted directly against the production "
          "std::vector<std::pair<std::string,std::map<std::string,std::string>>> boundary "
          "(parsers.hpp:370), never the test-only reg-export text decoder above",
          "[execution_artifacts][fuzz]") {
    const auto text = utf16le_file_to_utf8(fixture_dir() / "amcache_inventory_application_file.txt");
    const Subkeys real_subkeys = parse_reg_export_subkeys(text);
    REQUIRE(real_subkeys.size() == 5);
    // Every real FileId is well-formed (pinned by the positive TEST_CASE
    // above), so every mutation below that doesn't itself touch FileId keeps
    // malformed_fields at 0 -- letting each SECTION assert an exact count
    // rather than a fuzzy bound.

    SECTION("dropping each of the eight read keys from every map in turn never throws, never "
            "changes the row count, and produces no malformed FileIds (a MISSING field is not a "
            "malformed one, per parse_amcache_inventory_application_file's own contract)") {
        for (auto key : kAmcacheKeys) {
            INFO("dropped key: " << key);
            Subkeys mutated = real_subkeys;
            for (auto& [name, values] : mutated) {
                (void)name;
                values.erase(std::string{key});
            }
            AmCacheResult result;
            REQUIRE_NOTHROW(result = parse_amcache_inventory_application_file(mutated));
            CHECK(result.rows.size() == mutated.size());
            CHECK(result.malformed_fields == 0);
            if (key == "FileId") {
                for (const auto& row : result.rows)
                    CHECK(row.sha1 == "-");
            }
        }
    }

    SECTION("FileId length sweep 0..60 via the LCG, plus the four named shapes (non-hex bytes, "
            "uppercase hex, a missing 0000 prefix, and the correct 44-char value) -- "
            "malformed_fields exactly matches the malformed FileIds injected and sha1 is '-' for "
            "every one of them") {
        uint32_t state = kFuzzSeed;
        for (size_t len = 0; len <= 60; ++len) {
            // Non-hex alphabet forces malformed-ness deterministically for
            // every length except 0 (empty -> "-", not malformed, per
            // normalise_file_id's contract).
            const std::string file_id = lcg_string(state, len, /*non_hex=*/true);
            Subkeys mutated = {{"HKEY_LOCAL_MACHINE\\...\\fuzz",
                                {{"FileId", file_id}, {"LowerCaseLongPath", "c:\\fuzz.exe"}}}};
            AmCacheResult result;
            REQUIRE_NOTHROW(result = parse_amcache_inventory_application_file(mutated));
            REQUIRE(result.rows.size() == 1);
            const size_t expect_malformed = (len == 0) ? 0 : 1;
            CHECK(result.malformed_fields == expect_malformed);
            CHECK(result.rows.front().sha1 == "-");
        }

        auto run_named = [](const std::string& file_id, size_t expect_malformed,
                            const std::string& expect_sha1) {
            Subkeys mutated = {{"HKEY_LOCAL_MACHINE\\...\\fuzz",
                                {{"FileId", file_id}, {"LowerCaseLongPath", "c:\\fuzz.exe"}}}};
            AmCacheResult result;
            REQUIRE_NOTHROW(result = parse_amcache_inventory_application_file(mutated));
            REQUIRE(result.rows.size() == 1);
            CHECK(result.malformed_fields == expect_malformed);
            CHECK(result.rows.front().sha1 == expect_sha1);
        };

        // Uppercase hex -- valid shape, lowercased and accepted (not
        // malformed): normalise_file_id lowercases before validating.
        run_named("0000" + std::string(40, 'A'), 0, std::string(40, 'a'));
        // Missing "0000" prefix -- 44 hex characters, wrong prefix.
        run_named(std::string(44, 'a'), 1, "-");
        // The correct 44-char value pinned against A1's real fixture.
        run_named("00008dceb0eefac1501cb512270fa7cd4b906e44c70b", 0,
                  "8dceb0eefac1501cb512270fa7cd4b906e44c70b");
        // 44 bytes but containing a non-hex character after a valid prefix.
        run_named("0000" + std::string(39, 'a') + "z", 1, "-");
    }

    SECTION("one 512-byte and one 64 KiB oversized value per key never throws and is passed "
            "through unmodified (or, for FileId, correctly counted malformed since neither size "
            "is the required 44)") {
        for (auto key : kAmcacheKeys) {
            for (size_t size : {size_t{512}, size_t{64 * 1024}}) {
                INFO("key: " << key << " size: " << size);
                uint32_t state = kFuzzSeed;
                const std::string value = lcg_string(state, size, /*non_hex=*/false);
                Subkeys mutated = real_subkeys;
                mutated.front().second[std::string{key}] = value;
                AmCacheResult result;
                REQUIRE_NOTHROW(result = parse_amcache_inventory_application_file(mutated));
                REQUIRE(result.rows.size() == mutated.size());
                if (key == "FileId") {
                    CHECK(result.malformed_fields == 1);
                    CHECK(result.rows.front().sha1 == "-");
                } else {
                    CHECK(result.malformed_fields == 0);
                }
            }
        }
    }

    SECTION("an empty subkey vector never throws and produces zero rows") {
        AmCacheResult result;
        REQUIRE_NOTHROW(result = parse_amcache_inventory_application_file({}));
        CHECK(result.rows.empty());
        CHECK(result.malformed_fields == 0);
    }

    SECTION("20,001 identical well-formed subkeys never throws and maps one row per subkey -- "
            "kAmcacheMaxSubkeys is enforced by the impure Windows shell before this parser is "
            "ever called, never inside this pure map->rows function, so this boundary correctly "
            "has no cap of its own") {
        Subkeys mutated(20001, real_subkeys.front());
        AmCacheResult result;
        REQUIRE_NOTHROW(result = parse_amcache_inventory_application_file(mutated));
        CHECK(result.rows.size() == 20001);
        CHECK(result.malformed_fields == 0);
    }
}

TEST_CASE("prefetch_absence_token: nullopt/0/1-3/other map to the three distinct tokens",
          "[execution_artifacts][parsers][prefetch]") {
    static_assert(kPrefetchDisabled != kPrefetchEvidenceAbsent);
    static_assert(kPrefetchDisabled != kPrefetchStateUnknown);
    static_assert(kPrefetchEvidenceAbsent != kPrefetchStateUnknown);
    CHECK(kPrefetchDisabled == "prefetch_disabled");
    CHECK(kPrefetchEvidenceAbsent == "prefetch_evidence_absent");
    CHECK(kPrefetchStateUnknown == "prefetch_state_unknown");

    SECTION("nullopt (registry unreadable) -> prefetch_state_unknown") {
        CHECK(prefetch_absence_token(std::nullopt) == kPrefetchStateUnknown);
    }

    SECTION("0 (prefetcher off) -> prefetch_disabled") {
        CHECK(prefetch_absence_token(uint32_t{0}) == kPrefetchDisabled);
    }

    SECTION("1, 2, 3 (documented on-settings) -> prefetch_evidence_absent") {
        for (uint32_t v : {1u, 2u, 3u}) {
            INFO("EnablePrefetcher: " << v);
            CHECK(prefetch_absence_token(v) == kPrefetchEvidenceAbsent);
        }
    }

    SECTION("4, 7, 0xFFFFFFFF (undocumented values) -> prefetch_state_unknown") {
        for (uint32_t v : {4u, 7u, 0xFFFFFFFFu}) {
            INFO("EnablePrefetcher: " << v);
            CHECK(prefetch_absence_token(v) == kPrefetchStateUnknown);
        }
    }
}
