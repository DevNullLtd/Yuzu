/**
 * test_component_native_parsers.cpp -- tests for the bounded ELF and Mach-O readers behind the
 * component_inventory `native` action (agents/plugins/component_inventory/src/component_native_parsers.hpp).
 *
 * Every fixture is a byte array laid out here by explicit little- or big-endian stores: no binary
 * file is committed. This TU includes only the parsers header, Catch2 and the standard library, so
 * it also builds alone under ASan + UBSan (the sanitizer replay named in the PR's verification).
 *
 * The reader every case uses (Rd) CHECKS each request against the buffer: a request that is not
 * wholly inside it sets `bad`, and every case asserts `bad` stayed false. A parser that read outside
 * the file, or outside a fat slice's window, fails here even though the buffer would have satisfied
 * the read.
 *
 * MUTATION NOTES (each assertion FAILS if the named wiring is removed):
 *  - slice window: running the thin parser over the whole-file reader instead of the rebased one
 *    returns the NEIGHBOUR's install name in the adjacent-slice cases (asserted directly by the
 *    "unwindowed" check in those cases) and fails the window assertion on the counting reader.
 *  - program-header / dynamic / load-command ceilings: removing any one fails its bounds row (each
 *    fixture holds the bytes the ceiling refuses, so the file-size check cannot stand in for it).
 *  - ELF program-header entry size: a check that only refuses a size BELOW the format's (56 / 32)
 *    fails the stride row, whose table sits at that larger stride and parses at the format's own.
 *  - Mach-O name cap: copying the whole command tail instead of the cap plus its NUL still passes
 *    the boundary rows (it is result-equivalent); the rows pin the 255 / 256 edge itself.
 *  - overflow-safe arithmetic: replacing range_ok / add_ok with a plain offset + len compare fails the
 *    wrap-around rows.
 *  - not_library vs unreadable: collapsing the two fails the magic / file-type rows.
 */
#include <catch2/catch_test_macros.hpp>

#include "component_native_parsers.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::component_inventory;

namespace {

// ---- byte layout helpers ----

void put(std::string& b, std::size_t pos, std::uint64_t v, unsigned n, bool big) {
    if (b.size() < pos + n)
        b.resize(pos + n, '\0');
    for (unsigned i = 0; i < n; ++i) {
        const auto shift = big ? 8 * (n - 1 - i) : 8 * i;
        b[pos + i] = static_cast<char>((v >> shift) & 0xFF);
    }
}

std::size_t align8(std::size_t v) { return (v + 7) & ~std::size_t{7}; }

// ---- a reader that checks every request ----

struct Rd {
    const std::string* buf;
    bool bad{false};            // a request not wholly inside the buffer
    std::size_t calls{0};
    std::optional<std::size_t> fail_call; // this call returns nullopt
    std::optional<std::size_t> short_call; // this call returns one byte fewer than asked
    struct Req {
        std::uint64_t off;
        std::size_t len;
    };
    std::vector<Req> reqs;

    explicit Rd(const std::string& b) : buf(&b) {}
    [[nodiscard]] ReadAt fn() {
        return [this](std::uint64_t off, std::size_t len) -> std::optional<std::string> {
            const auto n = calls++;
            reqs.push_back({off, len});
            if (off > buf->size() || len > buf->size() - off) {
                bad = true;
                return std::nullopt;
            }
            if (fail_call && *fail_call == n)
                return std::nullopt;
            if (short_call && *short_call == n && len > 0)
                return buf->substr(static_cast<std::size_t>(off), len - 1);
            return buf->substr(static_cast<std::size_t>(off), len);
        };
    }
};

// ---- ELF fixture ----

struct Elf {
    std::string b;
    bool is64{true}, big{false};
    std::size_t ph_off{0}, phent{0}, dyn_off{0}, str_off{0}, load_ph{0}, dyn_ph{0};
    // field positions inside the dynamic section, for patching
    std::size_t soname_val{0}, strtab_val{0}, strsz_val{0};
    static constexpr std::uint64_t kBase = 0x400000;
};

/// ET_DYN with one PT_LOAD covering the whole file at kBase and one PT_DYNAMIC; `soname` nullopt
/// leaves out DT_SONAME. `raw_strtab` replaces the string table's bytes (for unterminated names).
Elf make_elf(bool is64, bool big, std::optional<std::string> soname, std::optional<std::string> raw_strtab = {}) {
    Elf e;
    e.is64 = is64;
    e.big = big;
    const std::size_t ehdr = is64 ? 64 : 52;
    e.phent = is64 ? 56 : 32;
    e.ph_off = ehdr;
    e.dyn_off = ehdr + 2 * e.phent;
    const std::size_t dent = is64 ? 16 : 8;
    const unsigned w = is64 ? 8 : 4;
    const std::size_t ndyn = (soname ? 1 : 0) + 3; // SONAME, STRTAB, STRSZ, NULL
    const std::size_t dyn_size = ndyn * dent;
    e.str_off = e.dyn_off + dyn_size;
    const std::string strtab = raw_strtab ? *raw_strtab : std::string(1, '\0') + soname.value_or("") + '\0';
    const std::size_t total = e.str_off + strtab.size();

    e.b.assign(total, '\0');
    e.b[0] = '\x7f';
    e.b[1] = 'E';
    e.b[2] = 'L';
    e.b[3] = 'F';
    e.b[4] = is64 ? 2 : 1;
    e.b[5] = big ? 2 : 1;
    e.b[6] = 1;
    put(e.b, 16, 3, 2, big); // ET_DYN
    put(e.b, is64 ? 32 : 28, e.ph_off, is64 ? 8 : 4, big);
    put(e.b, is64 ? 54 : 42, e.phent, 2, big);
    put(e.b, is64 ? 56 : 44, 2, 2, big);

    const auto phdr = [&](std::size_t at, std::uint64_t type, std::uint64_t off, std::uint64_t vaddr, std::uint64_t filesz) {
        put(e.b, at, type, 4, big);
        if (is64) {
            put(e.b, at + 8, off, 8, big);
            put(e.b, at + 16, vaddr, 8, big);
            put(e.b, at + 32, filesz, 8, big);
            put(e.b, at + 40, filesz, 8, big);
        } else {
            put(e.b, at + 4, off, 4, big);
            put(e.b, at + 8, vaddr, 4, big);
            put(e.b, at + 16, filesz, 4, big);
            put(e.b, at + 20, filesz, 4, big);
        }
    };
    e.load_ph = e.ph_off;
    e.dyn_ph = e.ph_off + e.phent;
    phdr(e.load_ph, 1, 0, Elf::kBase, total);
    phdr(e.dyn_ph, 2, e.dyn_off, Elf::kBase + e.dyn_off, dyn_size);

    std::size_t at = e.dyn_off;
    if (soname) {
        put(e.b, at, 14, w, big);
        e.soname_val = at + w;
        put(e.b, e.soname_val, 1, w, big);
        at += dent;
    }
    put(e.b, at, 5, w, big);
    e.strtab_val = at + w;
    put(e.b, e.strtab_val, Elf::kBase + e.str_off, w, big);
    at += dent;
    put(e.b, at, 10, w, big);
    e.strsz_val = at + w;
    put(e.b, e.strsz_val, strtab.size(), w, big);
    e.b.replace(e.str_off, strtab.size(), strtab);
    return e;
}

template <class T>
void expect_error(const T& r, NativeError want) {
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == want);
}

std::expected<std::optional<std::string>, NativeError> run_elf(const std::string& b, Rd* out = nullptr) {
    Rd rd(b);
    auto r = elf_soname(rd.fn(), b.size());
    if (out)
        *out = rd;
    CHECK_FALSE(rd.bad);
    return r;
}

// ---- Mach-O fixture ----

/// One thin dylib: header, an optional filler command, then LC_ID_DYLIB.
struct MachoSpec {
    bool is64{true}, big{false};
    std::string name{"@rpath/libfoo.1.dylib"};
    std::uint32_t current{0x00010203};
    bool filler{true};
    bool with_id{true};
    std::uint32_t filetype{6};
};

std::string make_macho(const MachoSpec& s) {
    const std::size_t hdr = s.is64 ? 32 : 28;
    std::string cmds;
    std::uint32_t n = 0;
    if (s.filler) {
        put(cmds, 0, 0x2A /* LC_SOURCE_VERSION */, 4, s.big);
        put(cmds, 4, 16, 4, s.big);
        cmds.resize(16, '\0');
        ++n;
    }
    if (s.with_id) {
        const std::size_t at = cmds.size();
        const std::size_t size = align8(24 + s.name.size() + 1);
        put(cmds, at, 0xD, 4, s.big);
        put(cmds, at + 4, size, 4, s.big);
        put(cmds, at + 8, 24, 4, s.big);
        put(cmds, at + 12, 2, 4, s.big);
        put(cmds, at + 16, s.current, 4, s.big);
        put(cmds, at + 20, s.current, 4, s.big);
        cmds.resize(at + size, '\0');
        cmds.replace(at + 24, s.name.size(), s.name);
        ++n;
    }
    std::string b(hdr, '\0');
    put(b, 0, s.is64 ? 0xFEEDFACFU : 0xFEEDFACEU, 4, s.big);
    put(b, 4, 0x01000007, 4, s.big);
    put(b, 12, s.filetype, 4, s.big);
    put(b, 16, n, 4, s.big);
    put(b, 20, cmds.size(), 4, s.big);
    return b + cmds;
}

/// Slices placed back to back after the fat header; `offsets` receives each slice's file offset.
std::string make_fat(const std::vector<std::string>& slices, bool fat64, std::vector<std::size_t>* offsets = nullptr) {
    const std::size_t arch = fat64 ? 32 : 20;
    std::string b;
    put(b, 0, fat64 ? 0xCAFEBABFU : 0xCAFEBABEU, 4, true);
    put(b, 4, slices.size(), 4, true);
    std::size_t at = 8 + slices.size() * arch;
    b.resize(at, '\0');
    for (std::size_t i = 0; i < slices.size(); ++i) {
        const std::size_t a = 8 + i * arch;
        put(b, a, 0x01000007, 4, true);
        if (fat64) {
            put(b, a + 8, at, 8, true);
            put(b, a + 16, slices[i].size(), 8, true);
        } else {
            put(b, a + 8, at, 4, true);
            put(b, a + 12, slices[i].size(), 4, true);
        }
        if (offsets)
            offsets->push_back(at);
        b += slices[i];
        at += slices[i].size();
    }
    return b;
}

std::expected<std::optional<DylibId>, NativeError> run_macho(const std::string& b, Rd* out = nullptr) {
    Rd rd(b);
    auto r = macho_dylib_id(rd.fn(), b.size());
    if (out)
        *out = rd;
    CHECK_FALSE(rd.bad);
    return r;
}

} // namespace

// ---- ELF ----

TEST_CASE("elf_soname: ELF64 and ELF32, both byte orders, find the SONAME through PT_DYNAMIC and PT_LOAD",
          "[component_native][component_inventory]") {
    for (const bool is64 : {true, false})
        for (const bool big : {false, true}) {
            const auto e = make_elf(is64, big, "libfoo.so.1");
            const auto r = run_elf(e.b);
            INFO("is64=" << is64 << " big=" << big);
            REQUIRE(r.has_value());
            REQUIRE(r->has_value());
            CHECK(**r == "libfoo.so.1");
        }
}

TEST_CASE("elf_soname: no DT_SONAME is an empty answer; a non-ET_DYN file and a wrong magic are not libraries",
          "[component_native][component_inventory]") {
    const auto none = run_elf(make_elf(true, false, std::nullopt).b);
    REQUIRE(none.has_value());
    CHECK_FALSE(none->has_value());

    auto exec = make_elf(true, false, "libfoo.so.1");
    put(exec.b, 16, 2, 2, false); // ET_EXEC
    expect_error(run_elf(exec.b), NativeError::not_library);

    auto magic = make_elf(true, false, "libfoo.so.1");
    magic.b[1] = 'X';
    expect_error(run_elf(magic.b), NativeError::not_library);
    expect_error(run_elf(std::string("tiny")), NativeError::not_library);
    expect_error(run_elf(std::string{}), NativeError::not_library);

    auto cls = make_elf(true, false, "libfoo.so.1");
    cls.b[4] = 3; // right magic, impossible class
    expect_error(run_elf(cls.b), NativeError::unreadable);
}

TEST_CASE("elf_soname: the ELF magic on 4 to 15 bytes is unreadable (one read, a file-name row); under 4 bytes is not a library",
          "[component_native][component_inventory]") {
    const auto full = make_elf(true, false, "libfoo.so.1").b;
    for (std::size_t n = 4; n <= 15; ++n) {
        INFO("length " << n);
        const auto cut = full.substr(0, n);
        Rd rd(cut);
        expect_error(run_elf(cut, &rd), NativeError::unreadable);
        REQUIRE(rd.reqs.size() == 1); // one read, clamped to the file: never past its end
        CHECK(rd.reqs[0].off == 0);
        CHECK(rd.reqs[0].len == n);

        Rd named(cut);
        const auto d = describe_linux_file("libfoo.so.1", named.fn(), cut.size());
        REQUIRE(d.has_value()); // recognisable but unparseable: a row from the file name
        CHECK(d->name == "libfoo");
        CHECK(d->version == "1");
        CHECK(d->version_source == NativeVersionSource::filename);

        Rd unversioned(cut);
        const auto u = describe_linux_file("libfoo.so", unversioned.fn(), cut.size());
        REQUIRE(u.has_value());
        CHECK(u->version.empty());
        CHECK(u->version_source == NativeVersionSource::unreadable);
    }
    for (std::size_t n = 0; n <= 3; ++n) {
        INFO("length " << n);
        const auto cut = full.substr(0, n);
        expect_error(run_elf(cut), NativeError::not_library);
        Rd rd(cut);
        CHECK_FALSE(describe_linux_file("libfoo.so.1", rd.fn(), cut.size()).has_value());
    }
    // a 4-15 byte file that does not carry the magic stays not a library
    auto wrong = full.substr(0, 10);
    wrong[1] = 'X';
    expect_error(run_elf(wrong), NativeError::not_library);
}

TEST_CASE("elf_soname: every bound is unreadable and nothing reads outside the file",
          "[component_native][component_inventory]") {
    for (const bool is64 : {true, false}) {
        INFO("is64=" << is64);
        const unsigned w = is64 ? 8 : 4;
        const auto base = make_elf(is64, false, "libfoo.so.1");

        { // program-header count past 128: the file holds all 129 entries (and 128 parse to a
          // value), so only the ceiling refuses it
            auto e = base;
            e.b.resize(16 * 1024, '\0');
            put(e.b, is64 ? 56 : 44, 128, 2, false);
            const auto at_ceiling = run_elf(e.b);
            REQUIRE(at_ceiling.has_value());
            REQUIRE(at_ceiling->has_value());
            CHECK(**at_ceiling == "libfoo.so.1");
            put(e.b, is64 ? 56 : 44, 129, 2, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // program-header entry size above the format's own (56 / 32): the table sits at the end
          // of the file at that stride, and the same entries parse to a value at the format's own
          // size, so only the exact-size rule refuses it
            for (const std::size_t stride : {base.phent, base.phent + 8}) {
                auto e = base;
                const std::size_t tbl = e.b.size();
                e.b.resize(tbl + 2 * stride, '\0');
                for (std::size_t i = 0; i < 2; ++i)
                    e.b.replace(tbl + i * stride, e.phent,
                                base.b.substr(e.ph_off + i * e.phent, e.phent));
                put(e.b, is64 ? 32 : 28, tbl, w, false);
                put(e.b, is64 ? 54 : 42, stride, 2, false);
                INFO("stride=" << stride);
                if (stride == e.phent) {
                    const auto r = run_elf(e.b);
                    REQUIRE(r.has_value());
                    REQUIRE(r->has_value());
                    CHECK(**r == "libfoo.so.1");
                } else {
                    expect_error(run_elf(e.b), NativeError::unreadable);
                }
            }
        }
        { // program-header table past the end of the file
            auto e = base;
            put(e.b, is64 ? 32 : 28, e.b.size() - 8, w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // offset arithmetic that would wrap: phoff near the top of the range
            auto e = base;
            put(e.b, is64 ? 32 : 28, is64 ? ~std::uint64_t{0} - 4 : 0xFFFFFFFCULL, w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // program-header entries too small to hold the fields
            auto e = base;
            put(e.b, is64 ? 54 : 42, 8, 2, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // PT_DYNAMIC past 64 KiB (the file is big enough that only the ceiling refuses it)
            auto e = base;
            e.b.resize(200 * 1024, '\0');
            put(e.b, e.dyn_ph + (is64 ? 32 : 16), 64 * 1024 + 1, w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // PT_DYNAMIC offset plus size past the file
            auto e = base;
            put(e.b, e.dyn_ph + (is64 ? 32 : 16), e.b.size(), w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // PT_DYNAMIC offset that would wrap
            auto e = base;
            put(e.b, e.dyn_ph + (is64 ? 8 : 4), is64 ? ~std::uint64_t{0} - 8 : 0xFFFFFFF8ULL, w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // string offset past DT_STRSZ
            auto e = base;
            put(e.b, e.soname_val, 4096, w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // string table address outside every PT_LOAD
            auto e = base;
            put(e.b, e.strtab_val, 0x10, w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // string table address whose mapped offset would wrap: a PT_LOAD at the top of the range
            auto e = base;
            put(e.b, e.load_ph + (is64 ? 8 : 4), is64 ? ~std::uint64_t{0} - 2 : 0xFFFFFFFDULL, w, false);
            put(e.b, e.load_ph + (is64 ? 32 : 16), is64 ? ~std::uint64_t{0} : 0xFFFFFFFFULL, w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // name offset plus table offset past the file
            auto e = base;
            put(e.b, e.load_ph + (is64 ? 8 : 4), e.b.size() - 2, w, false);
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // no DT_STRTAB although DT_SONAME is present
            auto e = base;
            put(e.b, e.strtab_val - w, 99, w, false); // retag DT_STRTAB as an unknown tag
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // an unterminated name: the table holds the name and no NUL
            const auto e = make_elf(is64, false, "x", std::string("\0libfoo.so.1", 12));
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
        { // a name longer than the 255-byte cap
            const auto e = make_elf(is64, false, std::string(300, 'a'));
            expect_error(run_elf(e.b), NativeError::unreadable);
        }
    }
}

// ---- Mach-O thin ----

TEST_CASE("macho_dylib_id: thin 64 and 32 bit, either byte order, give the install name and version",
          "[component_native][component_inventory]") {
    for (const bool is64 : {true, false})
        for (const bool big : {false, true}) {
            MachoSpec s;
            s.is64 = is64;
            s.big = big;
            const auto r = run_macho(make_macho(s));
            INFO("is64=" << is64 << " big=" << big);
            REQUIRE(r.has_value());
            REQUIRE(r->has_value());
            CHECK((*r)->install_name == "@rpath/libfoo.1.dylib");
            CHECK((*r)->current_version == 0x00010203);
        }
}

TEST_CASE("macho_dylib_id: no LC_ID_DYLIB is an empty answer; other file types and magics are not libraries",
          "[component_native][component_inventory]") {
    MachoSpec none;
    none.with_id = false;
    const auto r = run_macho(make_macho(none));
    REQUIRE(r.has_value());
    CHECK_FALSE(r->has_value());

    MachoSpec exec;
    exec.filetype = 2; // MH_EXECUTE
    expect_error(run_macho(make_macho(exec)), NativeError::not_library);
    expect_error(run_macho(std::string("not a mach-o file at all")), NativeError::not_library);
    expect_error(run_macho(std::string{}), NativeError::not_library);
}

TEST_CASE("macho_dylib_id: every bound is unreadable and nothing reads outside the file",
          "[component_native][component_inventory]") {
    const MachoSpec spec;
    const auto base = make_macho(spec);
    const std::size_t hdr = 32;
    const std::size_t id_at = hdr + 16; // the LC_ID_DYLIB command (after the 16-byte filler)

    { // sizeofcmds past 256 KiB: the file holds the whole region (and exactly 256 KiB parses to a
      // value), so only the ceiling refuses it
        auto b = base;
        b.resize(hdr + 256 * 1024 + 1, '\0');
        put(b, 20, 256 * 1024, 4, false);
        const auto at_ceiling = run_macho(b);
        REQUIRE(at_ceiling.has_value());
        REQUIRE(at_ceiling->has_value());
        CHECK((*at_ceiling)->install_name == "@rpath/libfoo.1.dylib");
        put(b, 20, 256 * 1024 + 1, 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // sizeofcmds past the end of the file
        auto b = base;
        put(b, 20, base.size(), 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // more than 4,096 load commands
        auto b = base;
        put(b, 16, 4097, 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // more commands declared than the region holds (no LC_ID_DYLIB to stop the walk early)
        MachoSpec s;
        s.with_id = false;
        auto b = make_macho(s);
        put(b, 16, 5, 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // cmdsize 0 (an unbounded loop if trusted)
        auto b = base;
        put(b, hdr + 4, 0, 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // cmdsize past the load-command region
        auto b = base;
        put(b, id_at + 4, 4096, 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // cmdsize that would wrap
        auto b = base;
        put(b, id_at + 4, 0xFFFFFFFFULL, 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // name offset outside its command
        auto b = base;
        put(b, id_at + 8, 4096, 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // name offset inside the fixed part of the command
        auto b = base;
        put(b, id_at + 8, 8, 4, false);
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // a name with no NUL inside its command
        MachoSpec s;
        s.name = std::string(8, 'a'); // 24 + 8 + NUL = 33 -> padded to 40; overwrite the pad and NUL
        auto b = make_macho(s);
        for (std::size_t i = id_at + 24; i < b.size(); ++i)
            b[i] = 'a';
        expect_error(run_macho(b), NativeError::unreadable);
    }
    { // the name cap is 255 bytes: 255 is returned, 256 and 300 are unreadable
        for (const std::size_t len : {std::size_t{255}, std::size_t{256}, std::size_t{300}}) {
            MachoSpec s;
            s.name = std::string(len, 'a');
            INFO("name length=" << len);
            if (len <= 255) {
                const auto r = run_macho(make_macho(s));
                REQUIRE(r.has_value());
                REQUIRE(r->has_value());
                CHECK((*r)->install_name == s.name);
            } else {
                expect_error(run_macho(make_macho(s)), NativeError::unreadable);
            }
        }
    }
    { // header shorter than the fixed header
        expect_error(run_macho(base.substr(0, 20)), NativeError::unreadable);
    }
}

// ---- Mach-O fat ----

TEST_CASE("macho_dylib_id: fat and fat64 read the first slice inside the file",
          "[component_native][component_inventory]") {
    for (const bool fat64 : {false, true}) {
        INFO("fat64=" << fat64);
        MachoSpec a, b;
        a.name = "/usr/lib/libfirst.dylib";
        b.name = "/usr/lib/libsecond.dylib";
        const auto fat = make_fat({make_macho(a), make_macho(b)}, fat64);
        const auto r = run_macho(fat);
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        CHECK((*r)->install_name == "/usr/lib/libfirst.dylib");
        CHECK((*r)->current_version == 0x00010203);
    }
}

TEST_CASE("macho_dylib_id: fat bounds are unreadable; a slice outside the file is skipped, not read",
          "[component_native][component_inventory]") {
    for (const bool fat64 : {false, true}) {
        INFO("fat64=" << fat64);
        const std::size_t arch = fat64 ? 32 : 20;
        const auto one = make_macho({});
        {
            std::vector<std::string> many(17, one);
            expect_error(run_macho(make_fat(many, fat64)), NativeError::unreadable);
        }
        {
            auto fat = make_fat({one}, fat64);
            put(fat, 4, 0, 4, true); // no slices
            expect_error(run_macho(fat), NativeError::unreadable);
        }
        { // the only slice lies past the file
            auto fat = make_fat({one}, fat64);
            put(fat, 8 + (fat64 ? 16 : 12), one.size() + 1, fat64 ? 8 : 4, true);
            expect_error(run_macho(fat), NativeError::unreadable);
        }
        { // slice offset plus size that would wrap
            auto fat = make_fat({one}, fat64);
            if (fat64) {
                put(fat, 8 + 8, ~std::uint64_t{0} - 4, 8, true);
            } else {
                put(fat, 8 + 8, 0xFFFFFFFCULL, 4, true);
            }
            expect_error(run_macho(fat), NativeError::unreadable);
        }
        { // the architecture table runs past the file
            auto fat = make_fat({one}, fat64);
            fat.resize(8 + arch - 1);
            expect_error(run_macho(fat), NativeError::unreadable);
        }
        { // the first slice is outside the file, the second is inside: the second is read
            MachoSpec b;
            b.name = "/usr/lib/libsecond.dylib";
            auto fat = make_fat({one, make_macho(b)}, fat64);
            put(fat, 8 + (fat64 ? 16 : 12), 1u << 20, fat64 ? 8 : 4, true);
            const auto r = run_macho(fat);
            REQUIRE(r.has_value());
            REQUIRE(r->has_value());
            CHECK((*r)->install_name == "/usr/lib/libsecond.dylib");
        }
    }
}

namespace {

/// Slice 0 is a Mach-O header plus a 24-byte LC_ID_DYLIB stub that ends exactly at its own end; slice
/// 1 follows at once and holds a valid LC_ID_DYLIB named "second". Slice 0's fields are then set so
/// that a parser bounded by the WHOLE file (not slice 0) walks into slice 1 and returns "second".
struct Adjacent {
    std::string fat;
    std::size_t off0{0}, len0{0}, off1{0};
    std::size_t id0{0};     // slice-relative position of slice 0's LC_ID_DYLIB command
    std::size_t reach{0};   // command-relative offset of "second" inside slice 1
};

Adjacent make_adjacent(bool fat64) {
    MachoSpec second;
    second.name = "second";
    second.filler = false;
    const std::string s1 = make_macho(second);

    MachoSpec first;
    first.filler = false;
    first.name = "x";
    std::string s0 = make_macho(first);
    s0.resize(32 + 24); // header + the fixed 24 bytes of the command: the slice ends at the name
    Adjacent a;
    a.id0 = 32;
    std::vector<std::size_t> offs;
    a.fat = make_fat({s0, s1}, fat64, &offs);
    a.off0 = offs[0];
    a.len0 = s0.size();
    a.off1 = offs[1];
    a.reach = (a.off1 + 32 + 24) - (a.off0 + a.id0); // slice 1's name, from slice 0's command start
    return a;
}

/// What a parser bounded by the whole file, not the slice, would say about slice 0.
std::expected<std::optional<DylibId>, NativeError> unwindowed(const Adjacent& a) {
    const std::string* buf = &a.fat;
    const ReadAt rd = [buf, off = a.off0](std::uint64_t o, std::size_t n) -> std::optional<std::string> {
        if (off + o > buf->size() || n > buf->size() - off - o)
            return std::nullopt;
        return buf->substr(static_cast<std::size_t>(off + o), n);
    };
    return macho_thin_dylib_id(rd, a.fat.size() - a.off0);
}

} // namespace

TEST_CASE("macho_dylib_id: a fat slice cannot reach into the next slice (fat and fat64)",
          "[component_native][component_inventory]") {
    for (const bool fat64 : {false, true}) {
        INFO("fat64=" << fat64);
        const std::size_t arch_end = 8 + 2 * (fat64 ? 32 : 20);

        struct Variant {
            const char* what;
            std::function<void(Adjacent&, std::string&)> corrupt;
            bool unwindowed_escapes; // the whole-file parser would return "second"
        };
        const std::vector<Variant> variants = {
            {"sizeofcmds, cmdsize and the name offset all reach into slice 1",
             [](Adjacent& a, std::string& f) {
                 put(f, a.off0 + 16, 1, 4, false);                 // ncmds
                 put(f, a.off0 + 20, a.reach + 8, 4, false);      // sizeofcmds
                 put(f, a.off0 + a.id0 + 4, a.reach + 8, 4, false); // cmdsize
                 put(f, a.off0 + a.id0 + 8, a.reach, 4, false);    // name offset
             },
             true},
            {"cmdsize alone reaches into slice 1",
             [](Adjacent& a, std::string& f) {
                 put(f, a.off0 + 16, 1, 4, false);
                 put(f, a.off0 + 20, 24, 4, false);
                 put(f, a.off0 + a.id0 + 4, a.reach + 8, 4, false);
                 put(f, a.off0 + a.id0 + 8, a.reach, 4, false);
             },
             false},
            {"the name offset alone reaches into slice 1",
             [](Adjacent& a, std::string& f) {
                 put(f, a.off0 + 16, 1, 4, false);
                 put(f, a.off0 + 20, 24, 4, false);
                 put(f, a.off0 + a.id0 + 4, 24, 4, false);
                 put(f, a.off0 + a.id0 + 8, a.reach, 4, false);
             },
             false},
        };

        for (const auto& v : variants) {
            INFO(v.what);
            auto a = make_adjacent(fat64);
            v.corrupt(a, a.fat);

            if (v.unwindowed_escapes) { // the fixture really is an escape: unbounded, it finds the neighbour
                const auto bare = unwindowed(a);
                REQUIRE(bare.has_value());
                REQUIRE(bare->has_value());
                CHECK((*bare)->install_name == "second");
            }

            Rd rd(a.fat);
            const auto r = macho_dylib_id(rd.fn(), a.fat.size());
            CHECK_FALSE(rd.bad);
            expect_error(r, NativeError::unreadable);
            // Every read after the fat header lies inside slice 0's window.
            for (const auto& q : rd.reqs) {
                if (q.off + q.len <= arch_end)
                    continue;
                CHECK(q.off >= a.off0);
                CHECK(q.off + q.len <= a.off0 + a.len0);
            }
        }
    }
}

// ---- reads that fail ----

TEST_CASE("a read_at that fails or comes up short at any call is unreadable, never a crash",
          "[component_native][component_inventory]") {
    MachoSpec ms;
    const std::vector<std::pair<const char*, std::string>> files = {
        {"elf64", make_elf(true, false, "libfoo.so.1").b},
        {"elf32be", make_elf(false, true, "libfoo.so.1").b},
        {"macho", make_macho(ms)},
        {"fat", make_fat({make_macho(ms)}, false)},
        {"fat64", make_fat({make_macho(ms)}, true)},
    };
    for (const auto& [what, bytes] : files) {
        INFO(what);
        const bool elf = std::string_view{what}.starts_with("elf");
        const auto parse = [&](Rd& rd) -> std::optional<NativeError> {
            if (elf) {
                const auto r = elf_soname(rd.fn(), bytes.size());
                return r ? std::nullopt : std::optional{r.error()};
            }
            const auto r = macho_dylib_id(rd.fn(), bytes.size());
            return r ? std::nullopt : std::optional{r.error()};
        };
        Rd clean(bytes);
        REQUIRE_FALSE(parse(clean).has_value());
        REQUIRE(clean.calls >= 3);
        for (std::size_t k = 0; k < clean.calls; ++k) {
            Rd failing(bytes);
            failing.fail_call = k;
            CHECK(parse(failing) == std::optional{NativeError::unreadable});
            Rd shorting(bytes);
            shorting.short_call = k;
            CHECK(parse(shorting) == std::optional{NativeError::unreadable});
            CHECK_FALSE(failing.bad);
            CHECK_FALSE(shorting.bad);
        }
    }
}

// ---- names, versions, candidates ----

TEST_CASE("candidate predicates: .so, .so.<n>, .dylib and near misses", "[component_native][component_inventory]") {
    for (const char* ok : {"libfoo.so", "libfoo.so.1", "libfoo.so.1.2.3", "libssl.so.3.0.13", "a.so"})
        CHECK(is_linux_native_candidate(ok));
    for (const char* no : {".so", "so", "libfoo.so.", "libfoo.so.x", "libfoo.so.1a", "libfoo.so.1.", "libfoo.so..1",
                           "libfoo.sol", "libfooso", "libfoo.so.1.so.2", "libfoo.dylib", "libfoo.SO", ""})
        CHECK_FALSE(is_linux_native_candidate(no));
    for (const char* ok : {"libfoo.dylib", "libfoo.1.2.dylib", "a.dylib"})
        CHECK(is_macos_native_candidate(ok));
    for (const char* no : {".dylib", "dylib", "libfoo.dylib.bak", "libfoo.DYLIB", "libfoo.so", "libfoo.dyli", ""})
        CHECK_FALSE(is_macos_native_candidate(no));
}

TEST_CASE("describe_linux: name from the SONAME stem, version from the file name, else the SONAME",
          "[component_native][component_inventory]") {
    {
        const auto d = describe_linux("libssl.so.3.0.13", "libssl.so.3");
        CHECK(d.name == "libssl");
        CHECK(d.version == "3.0.13");
        CHECK(d.version_source == NativeVersionSource::filename);
    }
    {
        const auto d = describe_linux("libfoo.so", "libfoo.so.2");
        CHECK(d.name == "libfoo");
        CHECK(d.version == "2");
        CHECK(d.version_source == NativeVersionSource::elf);
    }
    {
        const auto d = describe_linux("libfoo.so", std::nullopt);
        CHECK(d.name == "libfoo");
        CHECK(d.version.empty());
        CHECK(d.version_source == NativeVersionSource::unreadable);
    }
    {
        const auto d = describe_linux("libfoo.so.1", std::nullopt);
        CHECK(d.name == "libfoo");
        CHECK(d.version == "1");
        CHECK(d.version_source == NativeVersionSource::filename);
    }
    { // a plain libfoo.so with a SONAME that carries no version
        const auto d = describe_linux("libfoo.so", "libfoo.so");
        CHECK(d.name == "libfoo");
        CHECK(d.version_source == NativeVersionSource::unreadable);
    }
    { // hostile bytes in a SONAME never reach a name
        const auto d = describe_linux("libfoo.so", std::string("lib\x01\xff|x.so.1"));
        CHECK(d.name == "lib??|x");
    }
}

TEST_CASE("describe_macos: install-name leaf, current_version unless 0.0.0, else the file name",
          "[component_native][component_inventory]") {
    {
        const auto d = describe_macos("libfoo.1.dylib", DylibId{"@rpath/libfoo.1.dylib", 0x00010203});
        CHECK(d.name == "libfoo");
        CHECK(d.version == "1.2.3");
        CHECK(d.version_source == NativeVersionSource::macho);
    }
    { // 1234.255.7 packs as (1234 << 16) | (255 << 8) | 7
        const auto d = describe_macos("libbar.dylib", DylibId{"/usr/lib/libbar.dylib", (1234u << 16) | (255u << 8) | 7u});
        CHECK(d.version == "1234.255.7");
    }
    { // current_version 0.0.0 falls back to the file name's infix
        const auto d = describe_macos("libbar.4.5.dylib", DylibId{"/usr/lib/libbar.4.5.dylib", 0});
        CHECK(d.name == "libbar");
        CHECK(d.version == "4.5");
        CHECK(d.version_source == NativeVersionSource::filename);
    }
    { // no LC_ID_DYLIB, no infix: named, version unreadable
        const auto d = describe_macos("libbaz.dylib", std::nullopt);
        CHECK(d.name == "libbaz");
        CHECK(d.version.empty());
        CHECK(d.version_source == NativeVersionSource::unreadable);
    }
    { // a digit that is part of the name is not an infix
        const auto d = describe_macos("libz3.dylib", std::nullopt);
        CHECK(d.name == "libz3");
    }
}

TEST_CASE("describe_*_file: not a library gives no row; an unreadable library is named by its file",
          "[component_native][component_inventory]") {
    const auto good = make_elf(true, false, "libfoo.so.1").b;
    Rd rd(good);
    const auto d = describe_linux_file("libfoo.so.1", rd.fn(), good.size());
    REQUIRE(d.has_value());
    CHECK(d->name == "libfoo");

    const std::string text = "#!/bin/sh\necho not elf\n";
    Rd rd2(text);
    CHECK_FALSE(describe_linux_file("libfoo.so", rd2.fn(), text.size()).has_value());

    auto cut = good;
    cut.resize(40); // right magic, truncated header
    Rd rd3(cut);
    const auto u = describe_linux_file("libfoo.so.2", rd3.fn(), cut.size());
    REQUIRE(u.has_value());
    CHECK(u->name == "libfoo");
    CHECK(u->version == "2");
    CHECK_FALSE(rd3.bad);

    const std::string junk = "garbage";
    Rd rd4(junk);
    CHECK_FALSE(describe_macos_file("libfoo.dylib", rd4.fn(), junk.size()).has_value());
}

// ---- the deterministic sweep (the sanitizer net) ----

TEST_CASE("sweep: every truncation and every damaged header byte is a value or unreadable, never an outside read",
          "[component_native][component_inventory][sweep]") {
    MachoSpec thin;
    MachoSpec thin32;
    thin32.is64 = false;
    thin32.big = true;
    const std::vector<std::pair<const char*, std::string>> fixtures = {
        {"elf64", make_elf(true, false, "libfoo.so.1").b},
        {"elf32", make_elf(false, true, "libfoo.so.1").b},
        {"thin", make_macho(thin)},
        {"thin32be", make_macho(thin32)},
        {"fat", make_fat({make_macho(thin), make_macho(thin32)}, false)},
        {"fat64", make_fat({make_macho(thin), make_macho(thin32)}, true)},
    };
    const auto run_both = [](const std::string& bytes) {
        Rd a(bytes);
        (void)elf_soname(a.fn(), bytes.size());
        Rd b(bytes);
        (void)macho_dylib_id(b.fn(), bytes.size());
        return !a.bad && !b.bad;
    };
    for (const auto& [what, bytes] : fixtures) {
        INFO(what);
        bool clean = true;
        for (std::size_t len = 0; len <= bytes.size(); ++len)
            clean = run_both(bytes.substr(0, len)) && clean;
        CHECK(clean);
        for (std::size_t i = 0; i < std::min<std::size_t>(512, bytes.size()); ++i)
            for (const unsigned char v : {0x00, 0x7f, 0x80, 0xff}) {
                auto m = bytes;
                m[i] = static_cast<char>(v);
                clean = run_both(m) && clean;
            }
        CHECK(clean);
    }
}
