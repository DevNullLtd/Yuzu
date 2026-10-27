/**
 * test_smbios_parsers.cpp -- unit coverage for agents/shared/smbios_parsers.hpp (the shared,
 * bounds-checked SMBIOS walker: types 0 1 2 3 4 17, RSMB and headerless framings) and for the
 * firmware_posture adapter that now sits on it. Pure bytes in, no OS header, no I/O beyond reading
 * two committed fixtures: runs on every OS.
 * Input provenance:
 *   - synthetic tables: RECONSTRUCTIONS built by S/cat()/rsmb() from the DMTF DSP0134 layouts.
 *   - hardware-estate/smbios/kingsley-rsmb.bin: REAL CAPTURE (kingsley, SMBIOS 3.5), identifier
 *     slots overwritten in place (see its .provenance.txt).
 *   - wave8/firmware_posture/windows/rsmb.bin: REAL CAPTURE (the-rig), trimmed to type 0 + 127.
 *   - legacy_parse_smbios_type0: the pre-hoist firmware_posture parser frozen VERBATIM from commit
 *     931842654, the oracle for the byte-identical differential below.
 */
#include <catch2/catch_test_macros.hpp>

#include "firmware_posture_parsers.hpp"
#include <smbios_parsers.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace sm = yuzu::shared::smbios;
namespace fp = yuzu::firmware_posture;
namespace fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;

namespace {

// ---------------------------------------------------------------------------------------------
// Frozen oracle: the type-0 parser exactly as it stood at 931842654 (helpers + body, verbatim;
// only the function name and the enclosing namespace differ).
// ---------------------------------------------------------------------------------------------
namespace legacy {
using fp::Field;
using fp::Smbios0;
using fp::Smbios0Result;
namespace detail {
inline std::string rtrim(std::string_view s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' ||
                          s.back() == '\r' || s.back() == '\0'))
        s.remove_suffix(1);
    return std::string{s};
}

inline constexpr std::size_t kRsmbHeader = 8; // Used20CallingMethod, Major, Minor, Dmi, u32 Length

inline std::uint32_t le32(std::span<const std::uint8_t> b, std::size_t o) noexcept {
    return static_cast<std::uint32_t>(b[o]) | static_cast<std::uint32_t>(b[o + 1]) << 8 |
           static_cast<std::uint32_t>(b[o + 2]) << 16 | static_cast<std::uint32_t>(b[o + 3]) << 24;
}
inline std::uint16_t le16(std::span<const std::uint8_t> b, std::size_t o) noexcept {
    return static_cast<std::uint16_t>(b[o] | b[o + 1] << 8);
}

/// 1-based SMBIOS string index into the string-set at [start, end) (end = one past the final
/// double NUL). nullopt = index runs past the set (malformed).
inline std::optional<std::string> smbios_string(std::span<const std::uint8_t> t, std::size_t start,
                                                std::size_t end, unsigned idx) {
    std::size_t p = start;
    for (unsigned i = 1;; ++i) {
        if (p >= end || t[p] == 0) return std::nullopt; // ran out of strings
        std::size_t q = p;
        while (q < end && t[q] != 0) ++q;
        if (i == idx) {
            return rtrim(std::string_view{reinterpret_cast<const char*>(t.data() + p), q - p});
        }
        p = q + 1;
    }
}
} // namespace detail

[[nodiscard]] inline Smbios0Result legacy_parse_smbios_type0(std::span<const std::uint8_t> raw) {
    using detail::le16;
    using detail::le32;
    Smbios0Result res;
    auto bad = [&](std::string_view tok) {
        res.constrained = true;
        res.token = std::string{tok};
        res.data = {};
        return res;
    };
    if (raw.size() < detail::kRsmbHeader) return bad("smbios:truncated");
    const std::uint32_t claimed = le32(raw, 4);
    if (raw.size() - detail::kRsmbHeader < claimed) return bad("smbios:truncated");
    const auto t = raw.subspan(detail::kRsmbHeader, claimed);

    std::size_t off = 0;
    while (off < t.size()) {
        if (t.size() - off < 4) return bad("smbios:truncated");
        const std::uint8_t type = t[off];
        const std::size_t len = t[off + 1];
        if (len < 4) return bad("smbios:malformed");
        if (t.size() - off < len) return bad("smbios:truncated");
        const std::size_t sstart = off + len;
        // String-set: NUL-terminated strings ended by one extra NUL (two NULs when empty).
        std::size_t p = sstart;
        for (;; ++p) {
            if (p + 1 >= t.size()) return bad("smbios:truncated");
            if (t[p] == 0 && t[p + 1] == 0) break;
        }
        const std::size_t send = p + 2;
        if (type == 127) return bad("smbios:no_type0"); // end-of-table before any type 0
        if (type != 0) {
            off = send;
            continue;
        }
        if (len < 0x12) return bad("smbios:malformed");
        Smbios0 d;
        auto str = [&](std::size_t at, Field& f) {
            const unsigned idx = t[off + at];
            if (idx == 0) return true; // no string: absent
            auto s = detail::smbios_string(t, sstart, send, idx);
            if (!s) return false;
            if (!s->empty()) f.value = std::move(*s);
            return true;
        };
        if (!str(4, d.vendor) || !str(5, d.version) || !str(8, d.release_date))
            return bad("smbios:malformed");
        const unsigned rom = t[off + 9];
        if (rom != 0xFF) {
            d.rom_size_bytes = static_cast<std::uint64_t>(rom + 1) * 64ull * 1024ull;
        } else if (len >= 0x1A) { // SMBIOS 3.1+: Extended BIOS ROM Size, bits 15:14 = unit
            const std::uint16_t ext = le16(t, off + 0x18);
            const unsigned unit = ext >> 14;
            const std::uint64_t n = ext & 0x3FFFu;
            if (unit == 0) d.rom_size_bytes = n * 1024ull * 1024ull;
            else if (unit == 1) d.rom_size_bytes = n * 1024ull * 1024ull * 1024ull;
            // units 2/3 are reserved: leave unset (unmodelled, not guessed)
        }
        if (len >= 0x18) { // SMBIOS 2.4+: 0xFF in a release byte = not specified
            auto rel = [&](std::size_t at) -> std::optional<unsigned> {
                const unsigned v = t[off + at];
                return v == 0xFF ? std::nullopt : std::optional<unsigned>{v};
            };
            d.bios_major = rel(0x14);
            d.bios_minor = rel(0x15);
            d.ec_major = rel(0x16);
            d.ec_minor = rel(0x17);
        }
        res.data = std::move(d);
        return res;
    }
    return bad("smbios:no_type0");
}
} // namespace legacy

// ---------------------------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------------------------
Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// One structure: `len` formatted bytes (type, len, handle, then zeros) + a string set.
struct S {
    Bytes b;
    std::vector<std::string> strs;
    S(unsigned type, std::size_t len) : b(len, 0) {
        b.at(0) = static_cast<std::uint8_t>(type);
        b.at(1) = static_cast<std::uint8_t>(len);
    }
    // A field past the formatted area is a no-op, so one builder serves every layout length.
    S& u8(std::size_t o, unsigned v) {
        if (o < b.size()) b[o] = static_cast<std::uint8_t>(v);
        return *this;
    }
    S& u16(std::size_t o, unsigned v) { return u8(o, v & 0xFF).u8(o + 1, v >> 8); }
    S& u32(std::size_t o, std::uint32_t v) { return u16(o, v & 0xFFFF).u16(o + 2, v >> 16); }
    S& set(std::initializer_list<const char*> s) {
        strs.assign(s.begin(), s.end());
        return *this;
    }
    Bytes bytes() const {
        Bytes o = b;
        if (strs.empty()) {
            o.push_back(0);
        } else {
            for (const auto& s : strs) {
                o.insert(o.end(), s.begin(), s.end());
                o.push_back(0);
            }
        }
        o.push_back(0);
        return o;
    }
    // The same structure with its final string-set NUL cut off (an unterminated set).
    Bytes unterminated() const {
        Bytes o = bytes();
        o.pop_back();
        return o;
    }
};

Bytes end_marker() { return S(127, 4).bytes(); }

Bytes rsmb(const Bytes& table, unsigned major = 3, unsigned minor = 5) {
    Bytes blob{0, static_cast<std::uint8_t>(major), static_cast<std::uint8_t>(minor), 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) blob[4 + i] = static_cast<std::uint8_t>(table.size() >> (8 * i));
    blob.insert(blob.end(), table.begin(), table.end());
    return blob;
}

// The RSMB header's own Length claim rewritten to `table_len`.
Bytes with_claim(Bytes blob, std::size_t table_len) {
    for (int i = 0; i < 4; ++i) blob[4 + i] = static_cast<std::uint8_t>(table_len >> (8 * i));
    return blob;
}

S bios(std::size_t len = 0x1A) {
    S s(0, len);
    s.u8(4, 1).u8(5, 2).u8(8, 3).u8(9, 0x0F);
    if (len >= 0x18) s.u8(0x14, 1).u8(0x15, 20).u8(0x16, 0xFF).u8(0x17, 0xFF);
    return s.set({"Acme Firmware", "v1.2.3", "03/14/2024"});
}
S system(std::size_t len = 0x1B) {
    S s(1, len);
    s.u8(4, 1).u8(5, 2).u8(6, 3).u8(7, 4);
    if (len >= 0x19)
        for (unsigned i = 0; i < 16; ++i) s.u8(8 + i, i + 1);
    if (len >= 0x1B) s.u8(0x19, 5).u8(0x1A, 6);
    return s.set({"Acme", "Box", "1.0", "SN-1", "SKU-1", "Fam"});
}
S board(std::size_t len = 0x0F) {
    S s(2, len);
    s.u8(4, 1).u8(5, 2).u8(6, 3).u8(7, 4);
    if (len >= 9) s.u8(8, 5);
    return s.set({"BoardCo", "B1", "r2", "BSN", "BTAG"});
}
S chassis(std::size_t len = 0x16, unsigned type_byte = 0x23) {
    S s(3, len);
    s.u8(4, 1).u8(5, type_byte).u8(6, 2).u8(7, 3);
    if (len >= 9) s.u8(8, 4);
    return s.set({"ChCo", "cv", "CSN", "CTAG"});
}
S cpu(std::size_t len = 0x30) {
    S s(4, len);
    s.u8(4, 1).u8(6, 0x6B).u8(0x18, 0x41);
    for (unsigned i = 0; i < 8; ++i) s.u8(8 + i, 0xA0 + i);
    if (len >= 0x26) s.u8(0x23, 8).u8(0x24, 8).u8(0x25, 16);
    if (len >= 0x30) s.u16(0x28, 0x6B).u16(0x2A, 8).u16(0x2C, 8).u16(0x2E, 16);
    return s.set({"SOCKET0"});
}
S dimm(std::size_t len = 0x5C) {
    S s(17, len);
    s.u16(0x0C, 0x2000).u8(0x0E, 0x0D).u8(0x10, 1).u8(0x11, 2).u8(0x12, 0x22);
    if (len >= 0x17) s.u16(0x15, 4800);
    if (len >= 0x1B) s.u8(0x17, 3).u8(0x18, 4).u8(0x1A, 5);
    if (len >= 0x22) s.u16(0x20, 4400);
    return s.set({"DIMM 0", "BANK 0", "MemCo", "MSN", "PN-1"});
}

// ---------------------------------------------------------------------------------------------
// Dumps (a complete textual image of a decoded entry, for equality and for the prefix property)
// ---------------------------------------------------------------------------------------------
template <class T> std::string o(const std::optional<T>& v) {
    if (!v) return "-";
    if constexpr (std::is_same_v<T, std::string>) return "'" + *v + "'";
    else return std::to_string(*v);
}
std::string st(sm::Status s) { return std::to_string(static_cast<int>(s)); }
std::string dump(const sm::Entry<sm::Type0>& e) {
    const auto& d = e.data;
    return st(e.status) + "|" + o(d.vendor) + o(d.version) + o(d.release_date) + o(d.rom_size_bytes) +
           o(d.bios_major) + o(d.bios_minor) + o(d.ec_major) + o(d.ec_minor);
}
std::string dump(const sm::Entry<sm::Type1>& e) {
    const auto& d = e.data;
    std::string u = "-";
    if (d.uuid) {
        u.clear();
        for (auto b : *d.uuid) u += std::to_string(b) + ",";
    }
    return st(e.status) + "|" + o(d.manufacturer) + o(d.product) + o(d.version) + o(d.serial) +
           o(d.sku) + o(d.family) + u;
}
std::string dump(const sm::Entry<sm::Type2>& e) {
    const auto& d = e.data;
    return st(e.status) + "|" + o(d.manufacturer) + o(d.product) + o(d.version) + o(d.serial) +
           o(d.asset_tag);
}
std::string dump(const sm::Entry<sm::Type3>& e) {
    const auto& d = e.data;
    return st(e.status) + "|" + o(d.manufacturer) + o(d.version) + o(d.serial) + o(d.asset_tag) +
           std::to_string(d.chassis_type);
}
std::string dump(const sm::Entry<sm::Type4>& e) {
    const auto& d = e.data;
    std::string id;
    for (auto b : d.processor_id) id += std::to_string(b) + ",";
    return st(e.status) + "|" + o(d.socket_designation) + id + std::to_string(d.family) +
           (d.populated ? "P" : "p") + o(d.core_count) + o(d.thread_count);
}
std::string dump(const sm::Entry<sm::Type17>& e) {
    const auto& d = e.data;
    return st(e.status) + "|" + o(d.size_bytes) + (d.populated ? "P" : "p") + o(d.locator) +
           o(d.bank_locator) + o(d.manufacturer) + o(d.serial) + o(d.part_number) +
           std::to_string(d.form_factor) + "," + std::to_string(d.memory_type) + o(d.speed_mts) +
           o(d.configured_speed_mts);
}
template <class T> std::string dump_all(const std::vector<sm::Entry<T>>& v) {
    std::string out;
    for (const auto& e : v) out += dump(e) + ";";
    return out;
}

// The decoded entries of two tables are equal (error/version are compared separately).
void require_same_entries(const sm::SmbiosTable& a, const sm::SmbiosTable& b) {
    CHECK(dump(a.bios) == dump(b.bios));
    CHECK(dump(a.system) == dump(b.system));
    CHECK(dump(a.baseboard) == dump(b.baseboard));
    CHECK(dump(a.chassis) == dump(b.chassis));
    CHECK(dump_all(a.processors) == dump_all(b.processors));
    CHECK(dump_all(a.memory_devices) == dump_all(b.memory_devices));
}

// Every entry of a (prefix) result is either absent or exactly the full table's: never a partial
// ENTRY. Vectors are a leading run of the full vector.
void require_prefix_of(const sm::SmbiosTable& r, const sm::SmbiosTable& full) {
    auto single = [](auto& e, auto& f) { return e.status == sm::Status::absent || dump(e) == dump(f); };
    CHECK(single(r.bios, full.bios));
    CHECK(single(r.system, full.system));
    CHECK(single(r.baseboard, full.baseboard));
    CHECK(single(r.chassis, full.chassis));
    REQUIRE(r.processors.size() <= full.processors.size());
    REQUIRE(r.memory_devices.size() <= full.memory_devices.size());
    for (std::size_t i = 0; i < r.processors.size(); ++i)
        CHECK(dump(r.processors[i]) == dump(full.processors[i]));
    for (std::size_t i = 0; i < r.memory_devices.size(); ++i)
        CHECK(dump(r.memory_devices[i]) == dump(full.memory_devices[i]));
}

Bytes read_file(const fs::path& p) {
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    return Bytes{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
Bytes kingsley() {
    return read_file(fs::path{YUZU_TEST_FIXTURE_DIR} / "hardware-estate" / "smbios" / "kingsley-rsmb.bin");
}
Bytes the_rig() {
    return read_file(fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "firmware_posture" / "windows" / "rsmb.bin");
}

Bytes full_table() {
    return cat({bios().bytes(), system().bytes(), board().bytes(), chassis().bytes(), cpu().bytes(),
                dimm().bytes(), dimm().u16(0x0C, 0).bytes(), end_marker()});
}

} // namespace

namespace {
using View = std::span<const std::uint8_t>;

void require_no_entries(const sm::SmbiosTable& r) {
    CHECK(r.bios.status == sm::Status::absent);
    CHECK(r.system.status == sm::Status::absent);
    CHECK(r.baseboard.status == sm::Status::absent);
    CHECK(r.chassis.status == sm::Status::absent);
    CHECK(r.processors.empty());
    CHECK(r.memory_devices.empty());
}

// A scrubbed identifier slot of the kingsley capture: only the SCRUB pattern, never the original.
bool is_scrub(const std::optional<std::string>& s) {
    if (!s || s->empty()) return false;
    for (std::size_t i = 0; i < s->size(); ++i)
        if ((*s)[i] != "SCRUB"[i % 5]) return false;
    return true;
}

sm::Entry<sm::Type17> one_dimm(const S& s) {
    const auto r = sm::parse_table(cat({s.bytes(), end_marker()}));
    REQUIRE_FALSE(r.error);
    REQUIRE(r.memory_devices.size() == 1);
    return r.memory_devices[0];
}
sm::Entry<sm::Type4> one_cpu(const S& s) {
    const auto r = sm::parse_table(cat({s.bytes(), end_marker()}));
    REQUIRE_FALSE(r.error);
    REQUIRE(r.processors.size() == 1);
    return r.processors[0];
}
} // namespace

TEST_CASE("smbios framing: RSMB header faults and the headerless equivalent", "[smbios]") {
    CHECK(sm::parse_rsmb(View{}).error == sm::Error::truncated);
    const Bytes t = cat({bios().bytes(), end_marker()});
    const Bytes blob = rsmb(t);
    CHECK(sm::parse_rsmb(View(blob.data(), 7)).error == sm::Error::truncated);
    CHECK(sm::parse_rsmb(with_claim(blob, t.size() + 1)).error == sm::Error::truncated);
    require_no_entries(sm::parse_rsmb(View(blob.data(), 7)));

    const auto a = sm::parse_rsmb(blob);
    const auto h = sm::parse_table(t); // the walker never requires the RSMB header
    REQUIRE_FALSE(a.error);
    REQUIRE_FALSE(h.error);
    CHECK(a.version == std::pair<unsigned, unsigned>{3, 5});
    CHECK_FALSE(h.version.has_value());
    CHECK(a.bios.status == sm::Status::ok);
    require_same_entries(a, h);
    // The claim bounds the walk: bytes past it are never read.
    const auto cut = sm::parse_rsmb(with_claim(blob, bios().bytes().size()));
    CHECK_FALSE(cut.error);
    CHECK(cut.bios.status == sm::Status::ok);
}

TEST_CASE("smbios framing: structure faults stop the walk with the right error", "[smbios]") {
    SECTION("fewer than 4 bytes left for a header") {
        const auto r = sm::parse_table(Bytes{1, 8, 0});
        CHECK(r.error == sm::Error::truncated);
        require_no_entries(r);
    }
    SECTION("Length below 4") {
        const auto r = sm::parse_table(Bytes{1, 3, 0, 0, 0, 0});
        CHECK(r.error == sm::Error::malformed);
        require_no_entries(r);
    }
    SECTION("Length past the end") {
        const auto r = sm::parse_table(Bytes{1, 0x20, 0, 0, 0, 0});
        CHECK(r.error == sm::Error::truncated);
        require_no_entries(r);
    }
    SECTION("unterminated string set") {
        const auto r = sm::parse_table(system().unterminated());
        CHECK(r.error == sm::Error::truncated);
        require_no_entries(r);
    }
    SECTION("empty table is a clean walk of nothing") {
        const auto r = sm::parse_table(View{});
        CHECK_FALSE(r.error);
        require_no_entries(r);
    }
}

TEST_CASE("smbios framing: a fault keeps the entries decoded before it", "[smbios]") {
    const Bytes good = cat({bios().bytes(), system().bytes(), dimm().bytes()});
    SECTION("unterminated string set") {
        const auto r = sm::parse_table(cat({good, board().unterminated()}));
        CHECK(r.error == sm::Error::truncated);
        CHECK(r.bios.status == sm::Status::ok);
        CHECK(r.system.status == sm::Status::ok);
        CHECK(r.memory_devices.size() == 1);
        CHECK(r.baseboard.status == sm::Status::absent); // the faulting structure is not an entry
    }
    SECTION("Length below 4") {
        const auto r = sm::parse_table(cat({good, Bytes{2, 3, 0, 0, 0, 0}, chassis().bytes()}));
        CHECK(r.error == sm::Error::malformed);
        CHECK(r.bios.status == sm::Status::ok);
        CHECK(r.system.status == sm::Status::ok);
        CHECK(r.memory_devices.size() == 1);
        CHECK(r.chassis.status == sm::Status::absent);
    }
    SECTION("through the RSMB entry point too") {
        const auto r = sm::parse_rsmb(rsmb(cat({good, board().unterminated()})));
        CHECK(r.error == sm::Error::truncated);
        CHECK(r.version == std::pair<unsigned, unsigned>{3, 5});
        CHECK(r.bios.status == sm::Status::ok);
    }
}

TEST_CASE("smbios framing: every strict prefix is a clean boundary or a faulted keep-prefix",
          "[smbios][fuzz]") {
    const Bytes t = full_table();
    const auto full = sm::parse_table(t);
    REQUIRE_FALSE(full.error);
    // Structure boundaries of the table.
    std::vector<std::size_t> boundary{0};
    for (const auto& s : {bios(), system(), board(), chassis(), cpu(), dimm()})
        boundary.push_back(boundary.back() + s.bytes().size());
    boundary.push_back(boundary.back() + dimm().bytes().size());
    for (std::size_t n = 0; n < t.size(); ++n) {
        INFO("headerless prefix " << n);
        const auto r = sm::parse_table(View(t.data(), n));
        const bool on_boundary = std::find(boundary.begin(), boundary.end(), n) != boundary.end();
        CHECK(r.error.has_value() == !on_boundary);
        require_prefix_of(r, full);
    }
    const Bytes blob = rsmb(t);
    for (std::size_t n = 0; n < blob.size(); ++n) {
        INFO("rsmb prefix " << n); // claim longer than the buffer: never walked
        const auto r = sm::parse_rsmb(View(blob.data(), n));
        CHECK(r.error == sm::Error::truncated);
        require_no_entries(r);
    }
    for (std::size_t n = 8; n < blob.size(); ++n) {
        INFO("self-consistent rsmb prefix " << n); // claim rewritten: the walk itself decides
        const Bytes cut = with_claim(Bytes(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(n)), n - 8);
        require_prefix_of(sm::parse_rsmb(cut), full);
    }
}

TEST_CASE("smbios type 0: layouts and units", "[smbios]") {
    auto walk = [](const S& s) { return sm::parse_table(cat({s.bytes(), end_marker()})); };
    SECTION("2.0 layout 0x12: ROM byte only, no release bytes") {
        const auto r = walk(bios(0x12));
        REQUIRE(r.bios.status == sm::Status::ok);
        CHECK(r.bios.data.vendor == "Acme Firmware");
        CHECK(r.bios.data.version == "v1.2.3");
        CHECK(r.bios.data.release_date == "03/14/2024");
        CHECK(r.bios.data.rom_size_bytes == 16ull * 64 * 1024);
        CHECK_FALSE(r.bios.data.bios_major.has_value());
        CHECK_FALSE(r.bios.data.ec_major.has_value());
    }
    SECTION("2.4 layout 0x18: release bytes, 0xFF is not specified") {
        const auto r = walk(bios(0x18));
        REQUIRE(r.bios.status == sm::Status::ok);
        CHECK(r.bios.data.bios_major == 1u);
        CHECK(r.bios.data.bios_minor == 20u);
        CHECK_FALSE(r.bios.data.ec_major.has_value());
        CHECK_FALSE(r.bios.data.ec_minor.has_value());
        // 0xFF ROM byte but no extended word in this layout: unknown, not guessed.
        CHECK_FALSE(walk(bios(0x18).u8(9, 0xFF)).bios.data.rom_size_bytes.has_value());
    }
    SECTION("3.1 layout 0x1A: extended ROM size units") {
        auto rom = [&](unsigned ext) { return walk(bios(0x1A).u8(9, 0xFF).u16(0x18, ext)).bios.data.rom_size_bytes; };
        CHECK(rom(0x0020) == 32ull << 20);        // unit 0 = MiB
        CHECK(rom(0x4002) == 2ull << 30);         // unit 1 = GiB
        CHECK_FALSE(rom(0x8001).has_value());     // unit 2 reserved
        CHECK_FALSE(rom(0xC001).has_value());     // unit 3 reserved
    }
    SECTION("string index 0 is no string; past the set marks the entry malformed") {
        const auto r0 = walk(bios().u8(5, 0));
        REQUIRE(r0.bios.status == sm::Status::ok);
        CHECK_FALSE(r0.bios.data.version.has_value());
        const auto bad = walk(bios().u8(8, 9));
        CHECK(bad.bios.status == sm::Status::malformed);
        CHECK_FALSE(bad.bios.data.vendor.has_value()); // data reset
        CHECK_FALSE(bad.error);                         // a per-type fault is not a framing fault
    }
    SECTION("shorter than the 2.0 minimum is malformed") {
        CHECK(walk(bios(0x10)).bios.status == sm::Status::malformed);
    }
}

TEST_CASE("smbios type 1: layouts and the UUID rules", "[smbios]") {
    auto walk = [](const S& s) { return sm::parse_table(cat({s.bytes(), end_marker()})).system; };
    SECTION("2.0 layout 0x08: strings only") {
        const auto e = walk(system(0x08));
        REQUIRE(e.status == sm::Status::ok);
        CHECK(e.data.manufacturer == "Acme");
        CHECK(e.data.product == "Box");
        CHECK(e.data.version == "1.0");
        CHECK(e.data.serial == "SN-1");
        CHECK_FALSE(e.data.uuid.has_value());
        CHECK_FALSE(e.data.sku.has_value());
        CHECK_FALSE(e.data.family.has_value());
    }
    SECTION("2.1 layout 0x19: raw UUID bytes") {
        const auto e = walk(system(0x19));
        REQUIRE(e.status == sm::Status::ok);
        REQUIRE(e.data.uuid.has_value());
        for (unsigned i = 0; i < 16; ++i) CHECK((*e.data.uuid)[i] == i + 1);
        CHECK_FALSE(e.data.sku.has_value());
    }
    SECTION("2.4 layout 0x1B: SKU and family") {
        const auto e = walk(system(0x1B));
        CHECK(e.data.sku == "SKU-1");
        CHECK(e.data.family == "Fam");
    }
    SECTION("all-00 and all-FF UUIDs are not UUIDs") {
        S zero = system();
        S ones = system();
        for (unsigned i = 0; i < 16; ++i) zero.u8(8 + i, 0x00), ones.u8(8 + i, 0xFF);
        CHECK_FALSE(walk(zero).data.uuid.has_value());
        CHECK_FALSE(walk(ones).data.uuid.has_value());
        S one_off = ones;
        one_off.u8(23, 0xFE);
        CHECK(walk(one_off).data.uuid.has_value());
    }
    SECTION("below the minimum or a bad index is malformed") {
        CHECK(walk(system(0x07)).status == sm::Status::malformed);
        CHECK(walk(system().u8(0x19, 9)).status == sm::Status::malformed);
    }
}

TEST_CASE("smbios types 2 and 3", "[smbios]") {
    auto walk = [](const S& s) { return sm::parse_table(cat({s.bytes(), end_marker()})); };
    SECTION("type 2: 0x08 has no asset tag, 0x0F has one") {
        const auto a = walk(board(0x08)).baseboard;
        REQUIRE(a.status == sm::Status::ok);
        CHECK(a.data.serial == "BSN");
        CHECK_FALSE(a.data.asset_tag.has_value());
        const auto b = walk(board(0x0F)).baseboard;
        CHECK(b.data.manufacturer == "BoardCo");
        CHECK(b.data.product == "B1");
        CHECK(b.data.version == "r2");
        CHECK(b.data.asset_tag == "BTAG");
        CHECK(walk(board(0x07)).baseboard.status == sm::Status::malformed);
    }
    SECTION("type 3: the chassis-lock bit is masked off the type") {
        const auto c = walk(chassis(0x16, 0xA3)).chassis;
        REQUIRE(c.status == sm::Status::ok);
        CHECK(c.data.chassis_type == 35u);
        CHECK(c.data.manufacturer == "ChCo");
        CHECK(c.data.version == "cv");
        CHECK(c.data.serial == "CSN");
        CHECK(c.data.asset_tag == "CTAG");
        CHECK(walk(chassis(0x08)).chassis.status == sm::Status::malformed);
    }
}

TEST_CASE("smbios type 4: layouts populated bit family and ids", "[smbios]") {
    SECTION("2.0 layout 0x1A has no counts") {
        const auto e = one_cpu(cpu(0x1A));
        REQUIRE(e.status == sm::Status::ok);
        CHECK(e.data.socket_designation == "SOCKET0");
        CHECK_FALSE(e.data.core_count.has_value());
        CHECK_FALSE(e.data.thread_count.has_value());
        CHECK(e.data.family == 0x6Bu);
        CHECK(e.data.populated);
        for (unsigned i = 0; i < 8; ++i) CHECK(e.data.processor_id[i] == 0xA0 + i); // verbatim
    }
    SECTION("2.5 layout 0x28 has byte counts") {
        const auto e = one_cpu(cpu(0x28));
        CHECK(e.data.core_count == 8u);
        CHECK(e.data.thread_count == 16u);
    }
    SECTION("3.0 layout 0x30: 0xFF defers to the word counts") {
        const auto e = one_cpu(cpu(0x30).u8(0x23, 0xFF).u8(0x25, 0xFF).u16(0x2A, 64).u16(0x2E, 128));
        CHECK(e.data.core_count == 64u);
        CHECK(e.data.thread_count == 128u);
    }
    SECTION("populated is status bit 6") {
        CHECK_FALSE(one_cpu(cpu().u8(0x18, 0x01)).data.populated); // bit 0 alone is not it
        CHECK(one_cpu(cpu().u8(0x18, 0x41)).data.populated);
        CHECK_FALSE(one_cpu(cpu().u8(0x18, 0x00)).data.populated);
    }
    SECTION("family 0xFE is Family 2 when the layout has it") {
        CHECK(one_cpu(cpu(0x30).u8(6, 0xFE).u16(0x28, 0x0123)).data.family == 0x0123u);
        CHECK(one_cpu(cpu(0x28).u8(6, 0xFE)).data.family == 0xFEu);
    }
    SECTION("two sockets are two entries in table order") {
        const auto r = sm::parse_table(cat({cpu().bytes(), cpu().u8(8, 0x01).bytes(), end_marker()}));
        REQUIRE(r.processors.size() == 2);
        CHECK(r.processors[0].data.processor_id[0] == 0xA0);
        CHECK(r.processors[1].data.processor_id[0] == 0x01);
    }
}

TEST_CASE("smbios type 4 unknown and reserved counts are nullopt", "[smbios]") {
    SECTION("byte 0 is unknown") {
        const auto e = one_cpu(cpu().u8(0x23, 0).u8(0x25, 0));
        CHECK_FALSE(e.data.core_count.has_value());
        CHECK_FALSE(e.data.thread_count.has_value());
    }
    SECTION("0xFF with no word in the layout is unknown") {
        const auto e = one_cpu(cpu(0x28).u8(0x23, 0xFF).u8(0x25, 0xFF));
        CHECK_FALSE(e.data.core_count.has_value());
        CHECK_FALSE(e.data.thread_count.has_value());
    }
    SECTION("0xFF with word 0 or 0xFFFF is unknown/reserved; 0x0040 is 64") {
        auto cores = [&](unsigned w) { return one_cpu(cpu().u8(0x23, 0xFF).u16(0x2A, w)).data.core_count; };
        auto threads = [&](unsigned w) { return one_cpu(cpu().u8(0x25, 0xFF).u16(0x2E, w)).data.thread_count; };
        CHECK_FALSE(cores(0x0000).has_value());
        CHECK_FALSE(cores(0xFFFF).has_value());
        CHECK(cores(0x0040) == 64u);
        CHECK_FALSE(threads(0x0000).has_value());
        CHECK_FALSE(threads(0xFFFF).has_value());
        CHECK(threads(0x0040) == 64u);
    }
}

TEST_CASE("smbios type 17: size units and layouts", "[smbios]") {
    SECTION("size 0 is an empty slot") {
        const auto e = one_dimm(dimm().u16(0x0C, 0));
        CHECK_FALSE(e.data.populated);
        CHECK(e.data.size_bytes == 0u);
    }
    SECTION("size 0xFFFF is populated with unknown size") {
        const auto e = one_dimm(dimm().u16(0x0C, 0xFFFF));
        CHECK(e.data.populated);
        CHECK_FALSE(e.data.size_bytes.has_value());
    }
    SECTION("MiB, and KiB when bit 15 is set") {
        CHECK(one_dimm(dimm().u16(0x0C, 0x2000)).data.size_bytes == (0x2000ull << 20));
        CHECK(one_dimm(dimm().u16(0x0C, 0x8400)).data.size_bytes == (0x400ull << 10));
    }
    SECTION("0x7FFF uses the extended size when the layout has it") {
        auto size = [&](std::size_t len, std::uint32_t ext) {
            return one_dimm(dimm(len).u16(0x0C, 0x7FFF).u32(0x1C, ext)).data.size_bytes;
        };
        CHECK(size(0x5C, 0x4000) == (0x4000ull << 20));
        CHECK(size(0x5C, 0x80004000) == (0x4000ull << 20)); // bit 31 reserved: masked off
        CHECK_FALSE(size(0x5C, 0).has_value());              // extended 0 = unknown
        CHECK_FALSE(size(0x5C, 0x80000000).has_value());
        CHECK(size(0x1F, 0) == (0x7FFFull << 20));           // before 2.7 it is a plain MiB count
    }
    SECTION("layouts 0x15 0x1C 0x22 0x5C") {
        const auto a = one_dimm(dimm(0x15));
        CHECK(a.data.locator == "DIMM 0");
        CHECK(a.data.bank_locator == "BANK 0");
        CHECK(a.data.form_factor == 0x0Du);
        CHECK(a.data.memory_type == 0x22u);
        CHECK_FALSE(a.data.speed_mts.has_value());
        CHECK_FALSE(a.data.manufacturer.has_value());
        const auto b = one_dimm(dimm(0x1C));
        CHECK(b.data.speed_mts == 4800u);
        CHECK(b.data.manufacturer == "MemCo");
        CHECK(b.data.serial == "MSN");
        CHECK(b.data.part_number == "PN-1");
        CHECK_FALSE(b.data.configured_speed_mts.has_value());
        CHECK(one_dimm(dimm(0x22)).data.configured_speed_mts == 4400u);
        CHECK(one_dimm(dimm(0x5C)).data.configured_speed_mts == 4400u);
        CHECK(one_dimm(dimm(0x14).u16(0x0C, 1)).status == sm::Status::malformed);
    }
    SECTION("speed 0 is unknown") {
        CHECK_FALSE(one_dimm(dimm().u16(0x15, 0)).data.speed_mts.has_value());
        CHECK_FALSE(one_dimm(dimm().u16(0x20, 0)).data.configured_speed_mts.has_value());
    }
    SECTION("two devices one empty") {
        const auto r = sm::parse_table(cat({dimm().bytes(), dimm().u16(0x0C, 0).bytes(), end_marker()}));
        REQUIRE(r.memory_devices.size() == 2);
        CHECK(r.memory_devices[0].data.populated);
        CHECK_FALSE(r.memory_devices[1].data.populated);
    }
}

TEST_CASE("smbios type 17 extended speed masks the reserved high bit", "[smbios]") {
    auto speed = [&](std::size_t len, std::uint32_t ext) {
        return one_dimm(dimm(len).u16(0x15, 0xFFFF).u32(0x54, ext)).data.speed_mts;
    };
    auto configured = [&](std::size_t len, std::uint32_t ext) {
        return one_dimm(dimm(len).u16(0x20, 0xFFFF).u32(0x58, ext)).data.configured_speed_mts;
    };
    CHECK(speed(0x5C, 0x80001F40) == 8000u);
    CHECK_FALSE(speed(0x5C, 0x80000000).has_value());
    CHECK_FALSE(speed(0x5C, 0x00000000).has_value());
    CHECK(speed(0x5C, 0x00001F40) == 8000u);
    CHECK_FALSE(speed(0x57, 0x1F40).has_value()); // layout too short for the dword
    CHECK(configured(0x5C, 0x80001F40) == 8000u);
    CHECK_FALSE(configured(0x5C, 0x80000000).has_value());
    CHECK_FALSE(configured(0x5C, 0x00000000).has_value());
    CHECK_FALSE(configured(0x5B, 0x1F40).has_value());
}

TEST_CASE("smbios walk: per-type faults are isolated to their entry", "[smbios]") {
    SECTION("a type 3 with a bad string index leaves its neighbours decoded") {
        const auto r = sm::parse_table(
            cat({bios().bytes(), system().bytes(), board().bytes(), chassis().u8(7, 9).bytes(), end_marker()}));
        CHECK_FALSE(r.error);
        CHECK(r.bios.status == sm::Status::ok);
        CHECK(r.system.status == sm::Status::ok);
        CHECK(r.baseboard.status == sm::Status::ok);
        CHECK(r.chassis.status == sm::Status::malformed);
    }
    SECTION("a short type 4 is malformed and a later one still decodes") {
        const auto r = sm::parse_table(cat({cpu(0x18).bytes(), cpu().bytes(), end_marker()}));
        REQUIRE(r.processors.size() == 2);
        CHECK(r.processors[0].status == sm::Status::malformed);
        CHECK(r.processors[1].status == sm::Status::ok);
    }
}

TEST_CASE("smbios walk: first wins for 0 to 3 and type 127 ends the table", "[smbios]") {
    SECTION("two type 1 structures report the first") {
        const auto r = sm::parse_table(cat({system().bytes(), system().set({"X", "Y", "Z", "SN-2"}).bytes(), end_marker()}));
        CHECK(r.system.data.manufacturer == "Acme");
        CHECK(r.system.data.serial == "SN-1");
    }
    SECTION("a malformed first type 0 is not replaced by a later good one") {
        const auto r = sm::parse_table(cat({bios(0x10).bytes(), bios().bytes(), end_marker()}));
        CHECK(r.bios.status == sm::Status::malformed);
    }
    SECTION("nothing after type 127 is decoded and the walk is clean") {
        const auto r = sm::parse_table(cat({system().bytes(), end_marker(), bios().bytes(), Bytes{1}}));
        CHECK_FALSE(r.error);
        CHECK(r.system.status == sm::Status::ok);
        CHECK(r.bios.status == sm::Status::absent);
    }
}

TEST_CASE("smbios walk: unknown types are stepped over", "[smbios]") {
    const Bytes plain = cat({bios().bytes(), system().bytes(), end_marker()});
    const Bytes noisy = cat({bios().bytes(),
                             S(8, 9).set({"J1A1", "PS2Mouse"}).bytes(),
                             S(9, 17).set({"J6B2"}).bytes(),
                             S(11, 5).set({"a", "b", "c"}).bytes(),
                             system().bytes(),
                             S(41, 11).set({" Onboard IGD"}).bytes(),
                             end_marker()});
    const auto a = sm::parse_table(plain);
    const auto b = sm::parse_table(noisy);
    CHECK_FALSE(b.error);
    require_same_entries(a, b);
}

TEST_CASE("smbios walk: entry cap and the allocation bound", "[smbios]") {
    SECTION("257 minimal memory devices cap at 256") {
        Bytes t;
        for (int i = 0; i < 257; ++i) {
            const Bytes d = S(17, 0x15).bytes();
            t.insert(t.end(), d.begin(), d.end());
        }
        const auto r = sm::parse_table(t);
        CHECK_FALSE(r.error);
        CHECK(r.memory_devices.size() == sm::kMaxEntriesPerType);
        CHECK(r.entry_cap_hit);
    }
    SECTION("exactly 256 does not trip the flag") {
        Bytes t;
        for (int i = 0; i < 256; ++i) {
            const Bytes d = S(4, 0x1A).bytes();
            t.insert(t.end(), d.begin(), d.end());
        }
        const auto r = sm::parse_table(t);
        CHECK(r.processors.size() == 256);
        CHECK_FALSE(r.entry_cap_hit);
    }
    SECTION("every string field aliasing one 1 KiB string copies it once per field") {
        // Hostile aliasing: five string fields of one structure all index the same string.
        const std::string big(1024, 'A');
        S d(17, 0x5C);
        d.u16(0x0C, 1).u8(0x10, 1).u8(0x11, 1).u8(0x17, 1).u8(0x18, 1).u8(0x1A, 1);
        S set = d;
        set.strs = {big};
        Bytes t;
        for (int i = 0; i < 256; ++i) {
            const Bytes b = set.bytes();
            t.insert(t.end(), b.begin(), b.end());
        }
        const auto r = sm::parse_table(t);
        REQUIRE_FALSE(r.error);
        REQUIRE(r.memory_devices.size() == 256);
        std::size_t out_bytes = 0;
        for (const auto& e : r.memory_devices) {
            REQUIRE(e.status == sm::Status::ok);
            for (const auto* f : {&e.data.locator, &e.data.bank_locator, &e.data.manufacturer,
                                  &e.data.serial, &e.data.part_number}) {
                REQUIRE(f->has_value());
                CHECK((*f)->size() == 1024);
                out_bytes += (*f)->size();
            }
        }
        CHECK(out_bytes <= 6 * t.size()); // the banner's bound: 6 string fields x input bytes
        CHECK(out_bytes == 256u * 5u * 1024u);
    }
}

TEST_CASE("smbios is_placeholder: exact case-insensitive table plus empty", "[smbios]") {
    // The literal oracle: a table edit in the header must be mirrored here on purpose. The five
    // false-positive entries "Standard", "Default", "Family", "Empty" and "NULL" were removed
    // deliberately (each can be a real value), so re-adding one fails the equality below.
    constexpr std::string_view table[] = {
        "Default string", "To Be Filled By O.E.M.", "None", "Not Specified", "Not Available",
        "N/A", "Unknown", "Undefined", "System Serial Number", "System Product Name",
        "System manufacturer", "System Version", "Base Board", "Chassis Serial Number",
        "Chassis Version", "Chassis Manufacture", "Asset Tag", "No Asset Tag",
        "No Asset Information", "Not Applicable", "OEM", "0123456789", "1234567890", "SKU",
        "x.x", "Type1ProductConfigId"};
    CHECK(std::ranges::equal(sm::kPlaceholders, table));
    for (const std::string_view p : table) {
        INFO(p);
        CHECK(sm::is_placeholder(p));
        CHECK(sm::is_placeholder(std::string{p} + "  "));
        std::string up{p}, lo{p};
        for (char& c : up) c = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
        for (char& c : lo) c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
        CHECK(sm::is_placeholder(up));
        CHECK(sm::is_placeholder(lo));
    }
    CHECK(sm::is_placeholder(""));
    CHECK(sm::is_placeholder("   "));
    for (const char* real : {"Dell Inc.", "CT16G4SFRA32A.C8FE", "0123456789A", "Default strin", "Defaults",
                             "SN-1", "American Megatrends International, LLC."}) {
        INFO(real);
        CHECK_FALSE(sm::is_placeholder(real));
    }
}

TEST_CASE("smbios kingsley REAL CAPTURE: decoded facts and headerless equivalence", "[smbios]") {
    const Bytes raw = kingsley();
    REQUIRE(raw.size() == 2307);
    const auto r = sm::parse_rsmb(raw);
    REQUIRE_FALSE(r.error);
    CHECK(r.version == std::pair<unsigned, unsigned>{3, 5});

    REQUIRE(r.bios.status == sm::Status::ok);
    CHECK(r.bios.data.vendor == "American Megatrends International, LLC.");
    CHECK(r.bios.data.version == "1.06");
    CHECK(r.bios.data.release_date == "11/10/2025");
    CHECK(r.bios.data.rom_size_bytes == (32ull << 20)); // ROM byte 0xFF, extended word 0x0020 MiB
    CHECK(r.bios.data.bios_major == 5u);
    CHECK(r.bios.data.bios_minor == 29u);
    CHECK(r.bios.data.ec_major == 0u);
    CHECK(r.bios.data.ec_minor == 2u);

    REQUIRE(r.system.status == sm::Status::ok);
    CHECK(r.system.data.manufacturer == "Micro Computer (HK) Tech Limited");
    CHECK(r.system.data.product == "EliteMini Series");
    CHECK(r.system.data.sku == "MGHPBSD");
    CHECK(r.system.data.family == "EliteMini");
    REQUIRE(r.system.data.uuid.has_value()); // scrubbed to 00 11 22 .. FF
    for (unsigned i = 0; i < 16; ++i) CHECK((*r.system.data.uuid)[i] == i * 0x11);
    CHECK(is_scrub(r.system.data.serial));

    REQUIRE(r.baseboard.status == sm::Status::ok);
    CHECK(r.baseboard.data.product == "HPBSD");
    CHECK(is_scrub(r.baseboard.data.serial));
    CHECK(is_scrub(r.baseboard.data.asset_tag));

    REQUIRE(r.chassis.status == sm::Status::ok);
    CHECK(r.chassis.data.chassis_type == 35u);
    CHECK(is_scrub(r.chassis.data.serial));
    CHECK(is_scrub(r.chassis.data.asset_tag));

    REQUIRE(r.processors.size() == 1);
    const auto& p = r.processors[0].data;
    CHECK(p.populated);
    CHECK((p.processor_id[0] & 0x0F) == 2);
    CHECK(p.socket_designation == "FP8");
    CHECK(p.core_count == 8u);
    CHECK(p.thread_count == 16u);

    REQUIRE(r.memory_devices.size() == 2);
    const auto& m0 = r.memory_devices[0].data;
    const auto& m1 = r.memory_devices[1].data;
    CHECK(m0.populated);
    CHECK(m0.size_bytes == (32768ull << 20)); // size word 0x7FFF, extended size 32768 MiB
    CHECK(m0.speed_mts == 5600u);
    CHECK(m0.configured_speed_mts == 5600u);
    CHECK(m0.manufacturer == "Micron Technology");
    CHECK(is_scrub(m0.serial));
    CHECK_FALSE(m1.populated);
    CHECK(m1.size_bytes == 0u);
    CHECK_FALSE(r.entry_cap_hit);

    // Headerless DMI-table equivalence: the same bytes without the 8-byte RSMB header.
    const auto h = sm::parse_table(View(raw.data() + sm::kRsmbHeader, raw.size() - sm::kRsmbHeader));
    REQUIRE_FALSE(h.error);
    require_same_entries(r, h);

    // Every strict prefix is either a clean boundary or a faulted keep-prefix of the full walk.
    for (std::size_t n = 0; n < raw.size() - sm::kRsmbHeader; ++n) {
        INFO("prefix " << n);
        const auto pr = sm::parse_table(View(raw.data() + sm::kRsmbHeader, n));
        require_prefix_of(pr, h);
    }
    for (std::size_t n = 0; n < raw.size(); ++n) { // raw prefixes: the claim is longer than the buffer
        const auto pr = sm::parse_rsmb(View(raw.data(), n));
        REQUIRE(pr.error == sm::Error::truncated);
    }
}

// ---------------------------------------------------------------------------------------------
// firmware_posture: byte-identical differential against the frozen pre-hoist parser
// ---------------------------------------------------------------------------------------------
namespace {
bool same_field(const fp::Field& a, const fp::Field& b) {
    return a.value == b.value && a.unreadable == b.unreadable;
}
bool same_result(const fp::Smbios0Result& a, const fp::Smbios0Result& b) {
    return a.constrained == b.constrained && a.token == b.token &&
           same_field(a.data.vendor, b.data.vendor) && same_field(a.data.version, b.data.version) &&
           same_field(a.data.release_date, b.data.release_date) &&
           a.data.rom_size_bytes == b.data.rom_size_bytes && a.data.bios_major == b.data.bios_major &&
           a.data.bios_minor == b.data.bios_minor && a.data.ec_major == b.data.ec_major &&
           a.data.ec_minor == b.data.ec_minor;
}
void require_equivalent(const Bytes& blob, const char* what) {
    const auto want = legacy::legacy_parse_smbios_type0(blob);
    const auto got = fp::parse_smbios_type0(blob);
    INFO(what << ", blob size " << blob.size() << ", legacy token '" << want.token << "' adapter token '"
              << got.token << "'");
    REQUIRE(same_result(want, got));
}
// The blob as-is, every raw prefix, and every self-consistent prefix (claim rewritten).
void sweep(const Bytes& blob, const char* what) {
    require_equivalent(blob, what);
    for (std::size_t n = 0; n < blob.size(); ++n) {
        require_equivalent(Bytes(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(n)), what);
        if (n >= 8)
            require_equivalent(
                with_claim(Bytes(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(n)), n - 8), what);
    }
}
Bytes type0_blob(unsigned rom, unsigned ext, std::size_t len0, bool filler_first) {
    S b = bios(len0).u8(9, rom);
    if (len0 >= 0x1A) b.u16(0x18, ext);
    return rsmb(filler_first ? cat({system(0x08).bytes(), b.bytes(), end_marker()})
                             : cat({b.bytes(), end_marker()}),
                3, 3);
}
} // namespace

TEST_CASE("firmware_posture adapter is byte-identical to the frozen parser on synthetic tables",
          "[smbios][firmware_posture]") {
    for (std::size_t len0 : {std::size_t{0x12}, std::size_t{0x18}, std::size_t{0x1A}, std::size_t{0x10}})
        for (bool filler : {false, true})
            for (auto re : {std::pair<unsigned, unsigned>{0x0F, 0}, {0xFF, 0x0020}, {0xFF, 0x4001},
                            {0xFF, 0x8000}, {0xFF, 0xC000}, {0x00, 0}})
                sweep(type0_blob(re.first, re.second, len0, filler), "synthetic");
}

TEST_CASE("firmware_posture adapter: single-byte mutation sweep matches the frozen parser",
          "[smbios][firmware_posture][fuzz]") {
    const Bytes base = rsmb(cat({bios(0x12).bytes(), S(8, 9).set({"J1"}).bytes(), end_marker()}));
    for (std::size_t i = 0; i < base.size(); ++i)
        for (unsigned v : {0u, 0xFFu, static_cast<unsigned>(base[i]) + 1u}) {
            Bytes m = base;
            m[i] = static_cast<std::uint8_t>(v);
            INFO("byte " << i << " -> " << v);
            require_equivalent(m, "mutation");
        }
}

TEST_CASE("firmware_posture adapter matches the frozen parser on both real captures",
          "[smbios][firmware_posture]") {
    sweep(the_rig(), "the-rig");
    sweep(kingsley(), "kingsley");
}

TEST_CASE("firmware_posture adapter: the former early-return is preserved", "[smbios][firmware_posture]") {
    SECTION("type 0 followed by an unterminated structure is NOT constrained") {
        const auto r = fp::parse_smbios_type0(rsmb(cat({bios().bytes(), system().unterminated()})));
        CHECK_FALSE(r.constrained);
        CHECK(r.data.vendor.value == "Acme Firmware");
        CHECK(r.data.version.value == "v1.2.3");
        CHECK(r.data.release_date.value == "03/14/2024");
        CHECK(r.data.rom_size_bytes.has_value());
        CHECK(r.data.bios_major == 1u);
        CHECK(r.data.bios_minor == 20u);
        CHECK_FALSE(r.data.ec_major.has_value());
    }
    SECTION("type 0 with len 0x10 followed by truncation is malformed") {
        const auto r = fp::parse_smbios_type0(rsmb(cat({bios(0x10).bytes(), system().unterminated()})));
        CHECK(r.constrained);
        CHECK(r.token == "smbios:malformed");
    }
    SECTION("an unterminated string set before any type 0 is truncated") {
        const auto r = fp::parse_smbios_type0(rsmb(cat({system().unterminated()})));
        CHECK(r.constrained);
        CHECK(r.token == "smbios:truncated");
    }
    SECTION("Length below 4 before any type 0 is malformed") {
        const auto r = fp::parse_smbios_type0(rsmb(Bytes{1, 3, 0, 0, 0, 0}));
        CHECK(r.constrained);
        CHECK(r.token == "smbios:malformed");
    }
    SECTION("type 127 before type 0 is no_type0") {
        const auto r = fp::parse_smbios_type0(rsmb(cat({system().bytes(), end_marker(), bios().bytes()})));
        CHECK(r.constrained);
        CHECK(r.token == "smbios:no_type0");
    }
    SECTION("a table that ends without type 0 or 127 is no_type0") {
        const auto r = fp::parse_smbios_type0(rsmb(system().bytes()));
        CHECK(r.constrained);
        CHECK(r.token == "smbios:no_type0");
    }
    SECTION("a blank string is an absent field") {
        const auto r = fp::parse_smbios_type0(rsmb(cat({bios().set({"   ", "v1", "03/14/2024"}).bytes(), end_marker()})));
        CHECK_FALSE(r.constrained);
        CHECK_FALSE(r.data.vendor.value.has_value());
        CHECK(r.data.version.value == "v1");
    }
}
