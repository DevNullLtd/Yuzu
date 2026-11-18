/**
 * test_binary_header_macho.cpp -- agents/shared/binary_header_macho.hpp: the bounded Mach-O thin
 * and universal header and load-command reader. Pure logic over in-memory bytes from a small
 * in-test builder, plus two REAL CAPTURE fixtures (macho_thin.bin, macho_fat.bin; loaded via
 * YUZU_TEST_FIXTURE_DIR, and a missing fixture FAILS the test, never skips it).
 */

#include <catch2/catch_test_macros.hpp>

#include "binary_header_test_util.hpp"

#include <binary_header_macho.hpp>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::shared::binary_header;

namespace {

using Bytes = std::string;
using bhtest::Probe;

constexpr std::uint32_t kArm64 = 0x0100000C;  // CPU_TYPE_ARM64
constexpr std::uint32_t kX8664 = 0x01000007;  // CPU_TYPE_X86_64
constexpr std::uint32_t kPpc = 18;            // CPU_TYPE_POWERPC
constexpr std::uint32_t kLcSegment64 = 0x19;  // LC_SEGMENT_64, an ignored command
constexpr std::uint32_t kMaxU32 = std::numeric_limits<std::uint32_t>::max();

void put(Bytes& b, std::uint64_t v, std::size_t n, std::endian o) {
    for (std::size_t i = 0; i < n; ++i) {
        const std::size_t shift = o == std::endian::little ? i : n - 1 - i;
        b.push_back(static_cast<char>((v >> (8 * shift)) & 0xFF));
    }
}

// One load command: cmd, the cmdsize FIELD as given (not computed), then the payload as given.
Bytes cmd_raw(std::endian o, std::uint32_t cmd, std::uint32_t cmdsize, const Bytes& payload) {
    Bytes b;
    put(b, cmd, 4, o);
    put(b, cmdsize, 4, o);
    b += payload;
    return b;
}

Bytes cmd_padded(std::endian o, std::uint32_t cmd, Bytes payload, std::size_t align = 4,
                 char pad = '\0') {
    while ((8 + payload.size()) % align != 0)
        payload.push_back(pad);
    return cmd_raw(o, cmd, static_cast<std::uint32_t>(8 + payload.size()), payload);
}

Bytes lc_id_dylib(std::endian o, std::string_view name, std::uint32_t ts, std::uint32_t cur,
                  std::uint32_t compat, bool nul = true, std::uint32_t name_off = 24) {
    Bytes p;
    put(p, name_off, 4, o);
    put(p, ts, 4, o);
    put(p, cur, 4, o);
    put(p, compat, 4, o);
    p += name;
    if (nul)
        p.push_back('\0');
    return cmd_padded(o, 0x0D, p, 8, nul ? '\0' : 'A'); // LC_ID_DYLIB
}

Bytes lc_uuid(std::endian o, std::uint8_t seed) {
    Bytes p;
    for (int i = 0; i < 16; ++i)
        p.push_back(static_cast<char>(seed + i));
    return cmd_padded(o, 0x1B, p); // LC_UUID
}

Bytes lc_build_version(std::endian o, std::uint32_t platform, std::uint32_t minos,
                       std::uint32_t sdk, std::uint32_t ntools = 0, std::size_t tool_bytes = 0) {
    Bytes p;
    put(p, platform, 4, o);
    put(p, minos, 4, o);
    put(p, sdk, 4, o);
    put(p, ntools, 4, o);
    p.append(tool_bytes, '\0'); // the tool entries the command carries
    return cmd_padded(o, 0x32, p); // LC_BUILD_VERSION
}

Bytes lc_version_min(std::endian o, std::uint32_t cmd, std::uint32_t version, std::uint32_t sdk) {
    Bytes p;
    put(p, version, 4, o);
    put(p, sdk, 4, o);
    return cmd_padded(o, cmd, p);
}

Bytes lc_source_version(std::endian o, std::uint64_t v) {
    Bytes p;
    put(p, v, 8, o);
    return cmd_padded(o, 0x2A, p); // LC_SOURCE_VERSION
}

Bytes lc_skipped(std::endian o, std::size_t total) {
    return cmd_padded(o, kLcSegment64, Bytes(total - 8, 'x'));
}

struct ThinSpec {
    bool is64{true};
    std::endian order{std::endian::little};
    std::uint32_t cpu{kArm64};
    std::uint32_t sub{0};
    std::uint32_t ftype{6}; // MH_DYLIB
    std::uint32_t flags{0x85};
    std::vector<Bytes> cmds;
    std::optional<std::uint32_t> ncmds;      // override the header field
    std::optional<std::uint32_t> sizeofcmds; // override the header field
};

Bytes thin(const ThinSpec& s) {
    Bytes area;
    for (const auto& c : s.cmds)
        area += c;
    Bytes b;
    put(b, s.is64 ? 0xFEEDFACF : 0xFEEDFACE, 4, s.order); // MH_MAGIC_64 / MH_MAGIC
    put(b, s.cpu, 4, s.order);
    put(b, s.sub, 4, s.order);
    put(b, s.ftype, 4, s.order);
    put(b, s.ncmds.value_or(static_cast<std::uint32_t>(s.cmds.size())), 4, s.order);
    put(b, s.sizeofcmds.value_or(static_cast<std::uint32_t>(area.size())), 4, s.order);
    put(b, s.flags, 4, s.order);
    if (s.is64)
        put(b, 0, 4, s.order); // reserved
    return b + area;
}

struct Arch {
    std::uint32_t cpu{0};
    std::uint32_t sub{0};
    std::uint64_t offset{0};
    std::uint64_t size{0};
};

// fat_header + the arch table, nothing after it.
Bytes fat_table(bool is64, const std::vector<Arch>& archs, std::uint32_t nfat_field) {
    Bytes b;
    put(b, is64 ? 0xCAFEBABF : 0xCAFEBABE, 4, std::endian::big);
    put(b, nfat_field, 4, std::endian::big);
    for (const auto& a : archs) {
        put(b, a.cpu, 4, std::endian::big);
        put(b, a.sub, 4, std::endian::big);
        put(b, a.offset, is64 ? 8 : 4, std::endian::big);
        put(b, a.size, is64 ? 8 : 4, std::endian::big);
        put(b, 4, 4, std::endian::big); // align 2^4
        if (is64)
            put(b, 0, 4, std::endian::big); // reserved
    }
    return b;
}

// A universal image with the slices packed back to back at 16-byte alignment.
Bytes fat(bool is64, const std::vector<std::pair<std::uint32_t, Bytes>>& slices) {
    const std::size_t table = 8 + slices.size() * (is64 ? 32 : 20);
    std::vector<Arch> archs;
    std::size_t at = (table + 15) / 16 * 16;
    for (const auto& [cpu, body] : slices) {
        archs.push_back(Arch{cpu, 0, at, body.size()});
        at = (at + body.size() + 15) / 16 * 16;
    }
    Bytes b = fat_table(is64, archs, static_cast<std::uint32_t>(slices.size()));
    for (std::size_t i = 0; i < slices.size(); ++i) {
        b.resize(archs[i].offset, '\0');
        b += slices[i].second;
    }
    return b;
}

constexpr std::uint32_t kV123 = 0x00010203;
constexpr std::uint32_t kV100 = 0x00010000;
constexpr std::string_view kName = "@rpath/libsynth.1.dylib";

ThinSpec spec64(std::uint32_t cpu = kArm64) {
    ThinSpec s;
    s.cpu = cpu;
    const auto o = s.order;
    s.cmds = {lc_skipped(o, 72), lc_id_dylib(o, kName, 2, kV123, kV100), lc_uuid(o, 0x10),
              lc_build_version(o, 1, 0x000E0000, 0x000E0400), lc_source_version(o, 0x0123456789ABCDEF)};
    return s;
}

// Canonical builder images (also the fuzz seeds).
Bytes canon_thin64() { return thin(spec64()); }

Bytes canon_thin32be() {
    ThinSpec s;
    s.is64 = false;
    s.order = std::endian::big;
    s.cpu = kPpc;
    s.sub = 3;
    s.ftype = 2; // MH_EXECUTE
    s.flags = 1;
    const auto o = s.order;
    s.cmds = {lc_id_dylib(o, "libbe.dylib", 7, 0x00020304, 0x00020000),
              lc_version_min(o, 0x24, 0x000A0600, 0x000A0800), lc_skipped(o, 40)}; // LC_VERSION_MIN_MACOSX
    return thin(s);
}

Bytes canon_fat() { return fat(false, {{kArm64, thin(spec64(kArm64))}, {kX8664, thin(spec64(kX8664))}}); }
Bytes canon_fat64() { return fat(true, {{kArm64, thin(spec64(kArm64))}, {kX8664, thin(spec64(kX8664))}}); }

std::expected<MachoInfo, ParseError> parse(const Bytes& b, const MachoLimits& lim = {},
                                          ReadBudget budget = {}) {
    const std::span<const std::byte> sp(reinterpret_cast<const std::byte*>(b.data()), b.size());
    return read_macho(span_source(sp), lim, budget);
}

void require_dylib(const MachoSlice& s, std::string_view name, std::uint32_t ts, std::uint32_t cur,
                   std::uint32_t compat) {
    REQUIRE(s.id_dylib.has_value());
    CHECK(s.id_dylib->name == name);
    CHECK(s.id_dylib->timestamp == ts);
    CHECK(s.id_dylib->current_version == cur);
    CHECK(s.id_dylib->compatibility_version == compat);
}

void check_canon_slice64(const MachoSlice& s, std::uint32_t cpu) {
    CHECK_FALSE(s.error.has_value());
    CHECK(s.is64);
    CHECK(s.byte_order == std::endian::little);
    CHECK(s.cpu_type == cpu);
    CHECK(s.cpu_subtype == 0);
    CHECK(s.file_type == 6);
    CHECK(s.flags == 0x85);
    CHECK(s.load_command_count == 5);
    require_dylib(s, kName, 2, kV123, kV100);
    REQUIRE(s.uuid.has_value());
    for (std::size_t i = 0; i < 16; ++i)
        CHECK((*s.uuid)[i] == 0x10 + i);
    REQUIRE(s.build_version.has_value());
    CHECK(s.build_version->platform == 1);
    CHECK(s.build_version->minos == 0x000E0000);
    CHECK(s.build_version->sdk == 0x000E0400);
    REQUIRE(s.source_version.has_value());
    CHECK(*s.source_version == 0x0123456789ABCDEFull);
}

// A universal image of two slices where `a` and `b` are the slice bodies; returns table + bodies
// at the explicit offsets given by the caller via `archs`.
Bytes fat_at(const std::vector<Arch>& archs, std::size_t total, const std::vector<std::pair<std::size_t, Bytes>>& bodies,
             bool is64 = false) {
    Bytes b = fat_table(is64, archs, static_cast<std::uint32_t>(archs.size()));
    b.resize(total, '\0');
    for (const auto& [at, body] : bodies)
        b.replace(at, body.size(), body);
    return b;
}

} // namespace

TEST_CASE("macho: format_dylib_version unpacks 16.8.8", "[binary_header][macho]") {
    CHECK(format_dylib_version(0x00010203) == "1.2.3");
    CHECK(format_dylib_version(0x00010000) == "1.0.0");
    CHECK(format_dylib_version(0) == "0.0.0");
    CHECK(format_dylib_version(0xFFFFFFFF) == "65535.255.255");
}

TEST_CASE("macho: thin 64-bit little-endian image yields exact fields and commands",
          "[binary_header][macho]") {
    const auto r = parse(canon_thin64());
    REQUIRE(r.has_value());
    CHECK_FALSE(r->fat);
    REQUIRE(r->slices.size() == 1);
    CHECK(r->slices[0].offset == 0);
    CHECK(r->slices[0].size == canon_thin64().size());
    check_canon_slice64(r->slices[0], kArm64);
}

TEST_CASE("macho: thin 32-bit big-endian image yields exact fields and the version_min mapping",
          "[binary_header][macho]") {
    const auto r = parse(canon_thin32be());
    REQUIRE(r.has_value());
    CHECK_FALSE(r->fat);
    REQUIRE(r->slices.size() == 1);
    const auto& s = r->slices[0];
    CHECK_FALSE(s.error.has_value());
    CHECK_FALSE(s.is64);
    CHECK(s.byte_order == std::endian::big);
    CHECK(s.cpu_type == kPpc);
    CHECK(s.cpu_subtype == 3);
    CHECK(s.file_type == 2);
    CHECK(s.flags == 1);
    CHECK(s.load_command_count == 3);
    require_dylib(s, "libbe.dylib", 7, 0x00020304, 0x00020000);
    CHECK_FALSE(s.uuid.has_value());
    CHECK_FALSE(s.source_version.has_value());
    REQUIRE(s.build_version.has_value());
    CHECK(s.build_version->platform == 1);
    CHECK(s.build_version->minos == 0x000A0600);
    CHECK(s.build_version->sdk == 0x000A0800);
}

TEST_CASE("macho: an LC_BUILD_VERSION whose tool count does not fit its command is malformed",
          "[binary_header][macho]") {
    ThinSpec fits;
    fits.cmds = {lc_build_version(fits.order, 1, 5, 6, 1, 8)}; // one 8-byte tool entry, present
    const auto ok = parse(thin(fits));
    REQUIRE(ok.has_value());
    CHECK(ok->slices[0].build_version->platform == 1);
    for (const std::uint32_t ntools : {1u, 100u, 0xFFFFFFFFu}) {
        ThinSpec s;
        s.cmds = {lc_build_version(s.order, 1, 5, 6, ntools, 0)}; // the entries are missing
        const auto r = parse(thin(s));
        INFO("ntools " << ntools);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::malformed);
    }
}

TEST_CASE("macho: each LC_VERSION_MIN_* maps to its platform and the first of LC_BUILD_VERSION / "
          "LC_VERSION_MIN_* wins",
          "[binary_header][macho]") {
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> kinds = {
        {0x24, 1}, {0x25, 2}, {0x2F, 3}, {0x30, 4}}; // MACOSX, IPHONEOS, TVOS, WATCHOS
    for (const auto& [cmd, platform] : kinds) {
        ThinSpec s;
        s.cmds = {lc_version_min(s.order, cmd, 0x000B0000, 0x000C0000)};
        const auto r = parse(thin(s));
        REQUIRE(r.has_value());
        REQUIRE(r->slices[0].build_version.has_value());
        CHECK(r->slices[0].build_version->platform == platform);
        CHECK(r->slices[0].build_version->minos == 0x000B0000);
        CHECK(r->slices[0].build_version->sdk == 0x000C0000);
    }
    ThinSpec both;
    both.cmds = {lc_build_version(both.order, 2, 5, 6), lc_version_min(both.order, 0x24, 7, 8)};
    const auto r = parse(thin(both));
    REQUIRE(r.has_value());
    CHECK(r->slices[0].build_version->platform == 2); // first wins
}

TEST_CASE("macho: a repeated command keeps the first of its kind", "[binary_header][macho]") {
    ThinSpec s;
    s.order = std::endian::big;
    const auto o = s.order;
    s.cmds = {lc_id_dylib(o, "first.dylib", 1, 1, 1), lc_id_dylib(o, "second.dylib", 2, 2, 2),
              lc_uuid(o, 0x10),                       lc_uuid(o, 0x80),
              lc_source_version(o, 0x0123456789ABCDEF), lc_source_version(o, 2),
              lc_build_version(o, 2, 5, 6),           lc_build_version(o, 3, 7, 8),
              lc_version_min(o, 0x24, 9, 10)};
    const auto r = parse(thin(s));
    REQUIRE(r.has_value());
    const auto& m = r->slices[0];
    CHECK(m.is64);
    CHECK(m.byte_order == std::endian::big);
    CHECK(m.cpu_type == kArm64);
    CHECK(m.file_type == 6);
    CHECK(m.flags == 0x85);
    CHECK(m.load_command_count == 9);
    require_dylib(m, "first.dylib", 1, 1, 1);
    REQUIRE(m.uuid.has_value());
    CHECK((*m.uuid)[0] == 0x10);
    CHECK((*m.uuid)[15] == 0x1F);
    REQUIRE(m.source_version.has_value());
    CHECK(*m.source_version == 0x0123456789ABCDEFull);
    REQUIRE(m.build_version.has_value());
    CHECK(m.build_version->platform == 2);
    CHECK(m.build_version->minos == 5);
    CHECK(m.build_version->sdk == 6);
    ThinSpec rev; // the reverse order: the first of either kind still wins
    rev.cmds = {lc_version_min(rev.order, 0x25, 7, 8), lc_build_version(rev.order, 1, 5, 6)};
    const auto rr = parse(thin(rev));
    REQUIRE(rr.has_value());
    REQUIRE(rr->slices[0].build_version.has_value());
    CHECK(rr->slices[0].build_version->platform == 2);
    CHECK(rr->slices[0].build_version->minos == 7);
    CHECK(rr->slices[0].build_version->sdk == 8);
}

TEST_CASE("macho: universal images (fat_arch and fat_arch_64) parse two error-free slices",
          "[binary_header][macho]") {
    for (const bool is64 : {false, true}) {
        const Bytes img = is64 ? canon_fat64() : canon_fat();
        const auto r = parse(img);
        REQUIRE(r.has_value());
        CHECK(r->fat);
        REQUIRE(r->slices.size() == 2);
        const std::uint32_t cpus[2] = {kArm64, kX8664};
        for (std::size_t i = 0; i < 2; ++i) {
            check_canon_slice64(r->slices[i], cpus[i]);
            CHECK(r->slices[i].offset % 16 == 0);
            CHECK(r->slices[i].offset > 0);
            CHECK(r->slices[i].size == thin(spec64(cpus[i])).size());
            CHECK(r->slices[i].offset + r->slices[i].size <= img.size());
        }
    }
}

TEST_CASE("macho: a slice may be big-endian 32-bit inside a universal file", "[binary_header][macho]") {
    const auto r = parse(fat(false, {{kPpc, canon_thin32be()}, {kArm64, canon_thin64()}}));
    REQUIRE(r.has_value());
    REQUIRE(r->slices.size() == 2);
    CHECK_FALSE(r->slices[0].error.has_value());
    CHECK(r->slices[0].byte_order == std::endian::big);
    CHECK_FALSE(r->slices[0].is64);
    CHECK_FALSE(r->slices[1].error.has_value());
    CHECK(r->slices[1].byte_order == std::endian::little);
}

TEST_CASE("macho: the real thin capture reports the fixture's dylib id, versions, uuid and platform",
          "[binary_header][macho][real]") {
    const Bytes data = bhtest::load_fixture("macho_thin.bin");
    const auto r = parse(data);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->fat);
    REQUIRE(r->slices.size() == 1);
    const auto& s = r->slices[0];
    CHECK_FALSE(s.error.has_value());
    CHECK(s.is64);
    CHECK(s.byte_order == std::endian::little);
    CHECK(s.cpu_type == kArm64);
    CHECK(s.file_type == 6); // MH_DYLIB
    REQUIRE(s.id_dylib.has_value());
    CHECK(s.id_dylib->name == "@rpath/libyuzu_fixture.1.dylib");
    CHECK(format_dylib_version(s.id_dylib->current_version) == "1.2.3");
    CHECK(format_dylib_version(s.id_dylib->compatibility_version) == "1.0.0");
    CHECK(s.uuid.has_value());
    CHECK(s.build_version.has_value());
}

TEST_CASE("macho: the real universal capture reports two slices of different cpu_type with one id",
          "[binary_header][macho][real]") {
    const Bytes data = bhtest::load_fixture("macho_fat.bin");
    const auto r = parse(data);
    REQUIRE(r.has_value());
    CHECK(r->fat);
    REQUIRE(r->slices.size() == 2);
    CHECK(r->slices[0].cpu_type != r->slices[1].cpu_type);
    for (const auto& s : r->slices) {
        CHECK_FALSE(s.error.has_value());
        CHECK(s.offset > 0);
        CHECK(s.offset + s.size <= data.size());
        REQUIRE(s.id_dylib.has_value());
        CHECK(s.id_dylib->name == "@rpath/libyuzu_fixture.1.dylib");
        CHECK(format_dylib_version(s.id_dylib->current_version) == "1.2.3");
        CHECK(format_dylib_version(s.id_dylib->compatibility_version) == "1.0.0");
        CHECK(s.uuid.has_value());
    }
    CHECK(r->slices[0].id_dylib->name == r->slices[1].id_dylib->name);
}

TEST_CASE("macho: not-this-format inputs", "[binary_header][macho]") {
    SECTION("a Java class file header is not a universal file") {
        const Bytes java("\xCA\xFE\xBA\xBE\x00\x00\x00\x34", 8);
        const auto r = parse(java);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::not_this_format);
    }
    SECTION("a Java class file that is padded out is still refused") {
        Bytes java("\xCA\xFE\xBA\xBE\x00\x00\x00\x34", 8);
        java.resize(300, '\x01');
        const auto r = parse(java);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::not_this_format);
        const auto wide = parse(java, MachoLimits{.max_fat_archs = 64}); // not the caller's cap either
        REQUIRE_FALSE(wide.has_value());
        CHECK(wide.error() == ParseError::not_this_format);
        java[7] = '\x2D'; // word 45 (minor 0, major 45): the lowest a class file can carry
        const auto low = parse(java, MachoLimits{.max_fat_archs = 64});
        REQUIRE_FALSE(low.has_value());
        CHECK(low.error() == ParseError::not_this_format);
    }
    SECTION("unknown magic") {
        const auto r = parse(Bytes(64, 'A'));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::not_this_format);
    }
    SECTION("shorter than a magic") {
        for (std::size_t n = 0; n < 4; ++n) {
            const auto r = parse(Bytes(n, '\xCA'));
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == ParseError::not_this_format);
        }
    }
    SECTION("a universal header cut inside its first 8 bytes is truncated") {
        const auto r = parse(Bytes("\xCA\xFE\xBA\xBE\x00\x00", 6));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::truncated);
    }
}

TEST_CASE("macho: fat and command caps are refused past the limit and accepted at it",
          "[binary_header][macho]") {
    const MachoLimits def;
    SECTION("nfat_arch 0 and max+1") {
        const auto zero = parse(fat_table(false, {}, 0) + Bytes(20 * 20, '\0'));
        REQUIRE_FALSE(zero.has_value());
        CHECK(zero.error() == ParseError::not_this_format);
        // Over the cap but below the class-file word: a universal binary the caller will not read,
        // reported as a limit, as the PE and ELF readers report theirs.
        for (const std::uint32_t n : {static_cast<std::uint32_t>(def.max_fat_archs + 1), 44u}) {
            const auto over = parse(fat_table(false, {}, n) + Bytes(64 * 20, '\0'));
            REQUIRE_FALSE(over.has_value());
            CHECK(over.error() == ParseError::limit_exceeded);
        }
        // 45 and up is the class-file word, whatever the cap.
        const auto java = parse(fat_table(false, {}, 45) + Bytes(64 * 20, '\0'), MachoLimits{.max_fat_archs = 64});
        REQUIRE_FALSE(java.has_value());
        CHECK(java.error() == ParseError::not_this_format);
        const auto huge = parse(fat_table(true, {}, kMaxU32) + Bytes(64, '\0'));
        REQUIRE_FALSE(huge.has_value());
        CHECK(huge.error() == ParseError::not_this_format);
    }
    SECTION("nfat_arch at the limit is accepted, one over is refused") {
        MachoLimits lim;
        lim.max_fat_archs = 2;
        CHECK(parse(canon_fat(), lim).has_value());
        lim.max_fat_archs = 1;
        const auto r = parse(canon_fat(), lim);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::limit_exceeded);
        lim.max_fat_archs = 64; // 44 is the most any cap admits (45 is a class-file word)
        const auto top = parse(fat_table(false, {}, 44) + Bytes(44 * 20, '\0'), lim);
        REQUIRE(top.has_value());
        CHECK(top->slices.size() == 44);
    }
    SECTION("a universal table that runs past the file is truncated") {
        const auto r = parse(fat_table(false, {}, 16)); // header only, 16 entries declared
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::truncated);
    }
    SECTION("ncmds max+1 and sizeofcmds max+1 are limit_exceeded") {
        ThinSpec a = spec64();
        a.ncmds = static_cast<std::uint32_t>(def.max_load_commands + 1);
        const auto ra = parse(thin(a));
        REQUIRE_FALSE(ra.has_value());
        CHECK(ra.error() == ParseError::limit_exceeded);
        ThinSpec b = spec64();
        b.sizeofcmds = static_cast<std::uint32_t>(def.max_commands_bytes + 1);
        const auto rb = parse(thin(b));
        REQUIRE_FALSE(rb.has_value());
        CHECK(rb.error() == ParseError::limit_exceeded);
        ThinSpec c = spec64();
        c.ncmds = kMaxU32;
        c.sizeofcmds = kMaxU32;
        const auto rc = parse(thin(c));
        REQUIRE_FALSE(rc.has_value());
        CHECK(rc.error() == ParseError::limit_exceeded);
    }
    SECTION("ncmds and sizeofcmds accept their limit value") {
        const Bytes img = canon_thin64(); // 5 commands, 32-byte header
        MachoLimits lim;
        lim.max_load_commands = 5;
        lim.max_commands_bytes = img.size() - 32;
        CHECK(parse(img, lim).has_value());
        lim.max_load_commands = 4;
        {
            const auto r = parse(img, lim);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == ParseError::limit_exceeded);
        }
        lim.max_load_commands = 5;
        lim.max_commands_bytes = img.size() - 32 - 1;
        const auto r = parse(img, lim);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::limit_exceeded);
    }
    SECTION("a limit hit inside a universal slice is that slice's error") {
        MachoLimits lim;
        lim.max_load_commands = 4;
        const auto r = parse(canon_fat(), lim);
        REQUIRE(r.has_value());
        REQUIRE(r->slices.size() == 2);
        for (const auto& s : r->slices) {
            REQUIRE(s.error.has_value());
            CHECK(*s.error == ParseError::limit_exceeded);
        }
    }
    SECTION("the dylib name cap accepts its length and refuses one more") {
        MachoLimits lim;
        lim.max_string_bytes = kName.size();
        CHECK(parse(canon_thin64(), lim).has_value());
        lim.max_string_bytes = kName.size() - 1;
        const auto r = parse(canon_thin64(), lim);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::limit_exceeded);
    }
}

TEST_CASE("macho: bad universal slices carry their own error and never fail the siblings",
          "[binary_header][macho]") {
    const Bytes good = thin(spec64());
    SECTION("offset + size past the end of the file") {
        const Bytes img = fat_at({Arch{kArm64, 0, 64, good.size()}, Arch{kX8664, 0, 64, 100000}},
                                 64 + good.size(), {{64, good}});
        const auto r = parse(img);
        REQUIRE(r.has_value());
        REQUIRE(r->slices.size() == 2);
        CHECK_FALSE(r->slices[0].error.has_value());
        REQUIRE(r->slices[1].error.has_value());
        CHECK(*r->slices[1].error == ParseError::truncated);
        CHECK(r->slices[1].cpu_type == kX8664);
    }
    SECTION("offset + size overflowing u64") {
        const Bytes img =
            fat_at({Arch{kArm64, 0, 96, good.size()}, Arch{kX8664, 0, UINT64_MAX - 3, 16}},
                   96 + good.size(), {{96, good}}, true);
        const auto r = parse(img);
        REQUIRE(r.has_value());
        REQUIRE(r->slices.size() == 2);
        CHECK_FALSE(r->slices[0].error.has_value());
        REQUIRE(r->slices[1].error.has_value());
        CHECK(*r->slices[1].error == ParseError::truncated);
    }
    SECTION("a slice starting at the end of the file, and a zero-size slice") {
        const Bytes img = fat_at({Arch{kArm64, 0, 64, good.size()}, Arch{kX8664, 0, 64 + good.size(), 0}},
                                 64 + good.size(), {{64, good}});
        const auto r = parse(img);
        REQUIRE(r.has_value());
        CHECK_FALSE(r->slices[0].error.has_value());
        REQUIRE(r->slices[1].error.has_value());
        CHECK(*r->slices[1].error == ParseError::truncated);
    }
    SECTION("a nested universal slice is malformed") {
        const Bytes nested = canon_fat();
        const Bytes img = fat_at({Arch{kArm64, 0, 64, good.size()}, Arch{kX8664, 0, 64 + good.size(), nested.size()}},
                                 64 + good.size() + nested.size(), {{64, good}, {64 + good.size(), nested}});
        const auto r = parse(img);
        REQUIRE(r.has_value());
        CHECK_FALSE(r->slices[0].error.has_value());
        REQUIRE(r->slices[1].error.has_value());
        CHECK(*r->slices[1].error == ParseError::malformed);
    }
    SECTION("a slice of unknown magic is not_this_format") {
        const Bytes junk(48, 'J');
        const Bytes img = fat_at({Arch{kArm64, 0, 64, good.size()}, Arch{kX8664, 0, 64 + good.size(), junk.size()}},
                                 64 + good.size() + junk.size(), {{64, good}, {64 + good.size(), junk}});
        const auto r = parse(img);
        REQUIRE(r.has_value());
        CHECK_FALSE(r->slices[0].error.has_value());
        REQUIRE(r->slices[1].error.has_value());
        CHECK(*r->slices[1].error == ParseError::not_this_format);
    }
    SECTION("a bad first slice does not fail the second") {
        const Bytes junk(48, 'J');
        const auto r = parse(fat(false, {{kArm64, junk}, {kX8664, good}}));
        REQUIRE(r.has_value());
        REQUIRE(r->slices[0].error.has_value());
        CHECK_FALSE(r->slices[1].error.has_value());
        CHECK(r->slices[1].id_dylib.has_value());
    }
}

TEST_CASE("macho: a slice cannot be completed from its neighbour's bytes", "[binary_header][macho]") {
    // Slice 0's header declares one command byte more than the slice holds, so the missing byte
    // would be slice 1's first byte if any read crossed the boundary.
    ThinSpec a;
    a.cmds = {lc_uuid(a.order, 0x20)};
    a.sizeofcmds = static_cast<std::uint32_t>(a.cmds[0].size() + 1);
    const Bytes slice0 = thin(a);
    const Bytes slice1 = thin(spec64(kX8664));
    constexpr std::size_t kS0 = 8 + 2 * 20; // directly after the table
    const std::size_t s0_end = kS0 + slice0.size();
    Probe p;
    p.bytes = fat_at({Arch{kArm64, 0, kS0, slice0.size()}, Arch{kX8664, 0, s0_end, slice1.size()}},
                    s0_end + slice1.size(), {{kS0, slice0}, {s0_end, slice1}});
    const auto r = read_macho(p.source());
    REQUIRE(r.has_value());
    REQUIRE(r->slices.size() == 2);
    REQUIRE(r->slices[0].error.has_value());
    CHECK(*r->slices[0].error == ParseError::truncated);
    CHECK_FALSE(r->slices[1].error.has_value());
    check_canon_slice64(r->slices[1], kX8664);

    bool touched_slice0 = false;
    for (const auto& [off, len] : p.reads) {
        if (off >= kS0 && off < s0_end) {
            touched_slice0 = true;
            CHECK(off + len <= s0_end); // never starts inside slice 0 and ends past it
        }
    }
    CHECK(touched_slice0);
    CHECK_FALSE(p.beyond_visible());
}

TEST_CASE("macho: malformed load commands", "[binary_header][macho]") {
    const auto o = std::endian::little;
    const auto bad = [&](std::vector<Bytes> cmds, std::optional<std::uint32_t> ncmds = std::nullopt) {
        ThinSpec s;
        s.cmds = std::move(cmds);
        s.ncmds = ncmds;
        return parse(thin(s));
    };
    const auto expect_malformed = [](const std::expected<MachoInfo, ParseError>& r) {
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::malformed);
    };
    SECTION("cmdsize below 8") {
        expect_malformed(bad({cmd_raw(o, kLcSegment64, 4, Bytes(8, 'x'))}));
        expect_malformed(bad({cmd_raw(o, kLcSegment64, 0, Bytes(8, 'x'))}));
    }
    SECTION("cmdsize not a multiple of 4") {
        expect_malformed(bad({cmd_raw(o, kLcSegment64, 10, Bytes(8, 'x'))}));
    }
    SECTION("cmdsize past the command area") {
        expect_malformed(bad({cmd_raw(o, kLcSegment64, 0x1000, Bytes(8, 'x'))}));
        expect_malformed(bad({lc_skipped(o, 16), cmd_raw(o, kLcSegment64, 24, Bytes(8, 'x'))}));
    }
    SECTION("fewer commands than ncmds, and a stray tail shorter than a command head") {
        expect_malformed(bad({lc_skipped(o, 16)}, 2));
        expect_malformed(bad({lc_skipped(o, 16), Bytes(4, '\0')})); // 2 declared, 4 bytes left
    }
    SECTION("commands shorter than their fixed part") {
        expect_malformed(bad({cmd_raw(o, 0x0D, 16, Bytes(8, '\0'))}));  // LC_ID_DYLIB
        expect_malformed(bad({cmd_raw(o, 0x1B, 16, Bytes(8, '\0'))}));  // LC_UUID
        expect_malformed(bad({cmd_raw(o, 0x32, 16, Bytes(8, '\0'))}));  // LC_BUILD_VERSION
        expect_malformed(bad({cmd_raw(o, 0x24, 12, Bytes(4, '\0'))}));  // LC_VERSION_MIN_MACOSX
        expect_malformed(bad({cmd_raw(o, 0x2A, 12, Bytes(4, '\0'))}));  // LC_SOURCE_VERSION
    }
    SECTION("LC_ID_DYLIB name offset outside the command") {
        expect_malformed(bad({lc_id_dylib(o, "abc", 0, 0, 0, true, 8)}));    // inside the fixed part
        expect_malformed(bad({lc_id_dylib(o, "abc", 0, 0, 0, true, 23)}));
        expect_malformed(bad({lc_id_dylib(o, "abc", 0, 0, 0, true, 32)}));   // == cmdsize
        expect_malformed(bad({lc_id_dylib(o, "abc", 0, 0, 0, true, 4096)}));
        expect_malformed(bad({lc_id_dylib(o, "abc", 0, 0, 0, true, kMaxU32)}));
    }
    SECTION("LC_ID_DYLIB name without a NUL inside the command") {
        expect_malformed(bad({lc_id_dylib(o, "abcdefgh", 0, 0, 0, false)}));
        // The NUL exists, but only in the NEXT command: the walk must not read past cmdsize.
        expect_malformed(bad({lc_id_dylib(o, "abcdefgh", 0, 0, 0, false), lc_skipped(o, 16)}));
    }
    SECTION("a malformed command in a universal slice is that slice's error") {
        ThinSpec s;
        s.cmds = {cmd_raw(o, kLcSegment64, 4, Bytes(8, 'x'))};
        const auto r = parse(fat(false, {{kArm64, thin(s)}, {kX8664, canon_thin64()}}));
        REQUIRE(r.has_value());
        REQUIRE(r->slices[0].error.has_value());
        CHECK(*r->slices[0].error == ParseError::malformed);
        CHECK_FALSE(r->slices[1].error.has_value());
    }
}

TEST_CASE("macho: a 32-bit header that is exactly 28 bytes parses with zero commands",
          "[binary_header][macho]") {
    ThinSpec s;
    s.is64 = false;
    const auto r = parse(thin(s));
    REQUIRE(r.has_value());
    CHECK(r->slices[0].load_command_count == 0);
}

namespace {
// Reads `img` cut at every length: no read crosses the cut, the budget holds, and `check` sees
// each result. The Probe copies the image once; the prefix is a visible length.
template <typename Check>
void sweep_prefixes(const Bytes& img, Check check) {
    const ReadBudget budget{};
    Probe p;
    p.bytes = img;
    for (std::size_t n = 0; n < img.size(); ++n) {
        p.reset();
        p.visible = n;
        const auto r = read_macho(p.source());
        INFO("prefix " << n);
        CHECK_FALSE(p.beyond_visible());
        CHECK(p.calls <= budget.max_reads);
        CHECK(p.total <= budget.max_bytes);
        check(r, n);
    }
}

// Error or value is fine; every slice that parsed lies inside the prefix.
void check_slices_inside(const std::expected<MachoInfo, ParseError>& r, std::size_t n) {
    if (!r)
        return;
    for (const auto& s : r->slices) {
        if (!s.error)
            CHECK(s.offset + s.size <= n);
    }
}
} // namespace

TEST_CASE("macho: every prefix of the canonical images is handled without a value for a thin cut",
          "[binary_header][macho]") {
    for (const Bytes& img : {canon_thin64(), canon_thin32be()}) {
        sweep_prefixes(img, [](const auto& r, std::size_t n) {
            REQUIRE_FALSE(r.has_value());
            // The image ends with its last command, so any cut that keeps the magic is truncated.
            CHECK(r.error() == (n < 4 ? ParseError::not_this_format : ParseError::truncated));
        });
        CHECK(parse(img).has_value());
    }
    for (const Bytes& img : {canon_fat(), canon_fat64()})
        sweep_prefixes(img, check_slices_inside);
}

TEST_CASE("macho: every prefix of the real captures is bounded", "[binary_header][macho]") {
    for (const char* name : {"macho_thin.bin", "macho_fat.bin"}) {
        INFO(name);
        sweep_prefixes(bhtest::load_fixture(name), check_slices_inside);
    }
}

TEST_CASE("macho: read_at nullopt surfaces as io", "[binary_header][macho]") {
    const auto failing = [](std::uint64_t from, const Bytes& data) {
        return Source{[from, data](std::uint64_t off, std::size_t len) -> std::optional<std::string> {
                          if (off >= from)
                              return std::nullopt;
                          if (off >= data.size())
                              return std::string{};
                          return data.substr(static_cast<std::size_t>(off), len);
                      },
                      data.size()};
    };
    SECTION("thin: the function's error") {
        const Bytes img = canon_thin64();
        const auto r = read_macho(failing(0, img));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::io);
        const auto r2 = read_macho(failing(32, img)); // header ok, command area fails
        REQUIRE_FALSE(r2.has_value());
        CHECK(r2.error() == ParseError::io);
    }
    SECTION("universal header and table: the function's error") {
        const auto r = read_macho(failing(0, canon_fat()));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::io);
        const auto r2 = read_macho(failing(8, canon_fat()));
        REQUIRE_FALSE(r2.has_value());
        CHECK(r2.error() == ParseError::io);
    }
    SECTION("universal slice: that slice's error") {
        const Bytes img = canon_fat();
        const auto probe = parse(img);
        REQUIRE(probe.has_value());
        const auto r = read_macho(failing(probe->slices[1].offset, img));
        REQUIRE(r.has_value());
        CHECK_FALSE(r->slices[0].error.has_value());
        REQUIRE(r->slices[1].error.has_value());
        CHECK(*r->slices[1].error == ParseError::io);
    }
    SECTION("a Source with no read_at") {
        const auto r = read_macho(Source{nullptr, 64});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::io);
    }
}

TEST_CASE("macho: the read budget is honoured and a thin parse costs two reads",
          "[binary_header][macho]") {
    const Bytes img = canon_thin64();
    SECTION("exact budget succeeds") {
        Probe p;
        p.bytes = img;
        const auto r = read_macho(p.source(), {}, ReadBudget{img.size(), 2});
        REQUIRE(r.has_value());
        CHECK(p.calls == 2);
        CHECK(p.total == img.size());
    }
    SECTION("one read too few") {
        Probe p;
        p.bytes = img;
        const auto r = read_macho(p.source(), {}, ReadBudget{img.size(), 1});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::limit_exceeded);
        CHECK(p.calls == 1);
    }
    SECTION("one byte too few") {
        Probe p;
        p.bytes = img;
        const auto r = read_macho(p.source(), {}, ReadBudget{img.size() - 1, 2});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::limit_exceeded);
        CHECK(p.total <= img.size() - 1);
    }
    SECTION("a starved universal parse marks the slices, and never exceeds the budget") {
        Probe p;
        p.bytes = canon_fat();
        const auto r = read_macho(p.source(), {}, ReadBudget{4096, 3}); // head, table, slice 0 head
        REQUIRE(r.has_value());
        REQUIRE(r->slices.size() == 2);
        for (const auto& s : r->slices) {
            REQUIRE(s.error.has_value());
            CHECK(*s.error == ParseError::limit_exceeded);
        }
        CHECK(p.calls == 3);
    }
}

TEST_CASE("macho: a deterministic 20,000-mutation sweep never crosses the file, the budget or a slice",
          "[binary_header][macho]") {
    const std::vector<Bytes> bases = {canon_thin64(),
                                      canon_thin32be(),
                                      canon_fat(),
                                      canon_fat64(),
                                      bhtest::load_fixture("macho_thin.bin"),
                                      bhtest::load_fixture("macho_fat.bin")};
    const ReadBudget budget{};
    std::uint64_t rng = 0x9E3779B97F4A7C15ull;
    constexpr std::array<std::uint8_t, 6> kInteresting = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF};
    for (int iter = 0; iter < 20000; ++iter) {
        Probe p;
        p.bytes = bases[bhtest::xorshift(rng) % bases.size()];
        const std::size_t edits = 1 + bhtest::xorshift(rng) % 4;
        for (std::size_t e = 0; e < edits; ++e) {
            const std::size_t at = bhtest::xorshift(rng) % p.bytes.size();
            const std::uint64_t v = bhtest::xorshift(rng);
            p.bytes[at] = static_cast<char>(v % 3 == 0 ? kInteresting[(v >> 8) % kInteresting.size()]
                                                       : static_cast<std::uint8_t>(v >> 16));
        }
        if (bhtest::xorshift(rng) % 8 == 0)
            p.bytes.resize(bhtest::xorshift(rng) % p.bytes.size());
        const auto r = read_macho(p.source());
        const bool ok = !p.beyond_visible() && p.calls <= budget.max_reads && p.total <= budget.max_bytes;
        if (!ok) {
            INFO("iteration " << iter);
            REQUIRE(ok);
        }
        if (!r)
            continue;
        if (!r->fat) {
            REQUIRE(r->slices.size() == 1);
            REQUIRE_FALSE(r->slices[0].error.has_value());
        }
        REQUIRE(r->slices.size() <= MachoLimits{}.max_fat_archs);
        for (const auto& s : r->slices) {
            if (!s.error) {
                REQUIRE(s.offset + s.size <= p.bytes.size());
                REQUIRE(s.load_command_count <= MachoLimits{}.max_load_commands);
            }
        }
    }
}
