/**
 * test_component_native_parsers.cpp -- tests for the adapter over the shared binary_header readers
 * and the name and version rules of the component_inventory `native` action
 * (agents/plugins/component_inventory/src/component_native_parsers.hpp).
 *
 * The readers' own parsing, bounds and fuzz fixtures live with the shared readers; these cases pin
 * what the plugin adds: the mapping of their results onto value / not_library / unreadable, the
 * universal-file slice choice, the 4 to 15 byte ELF rule, string sanitising, no exception out of a
 * read, and the rules that turn a declared name into a row. Fixtures are byte arrays laid out here
 * by explicit little- or big-endian stores: no binary file is committed.
 *
 * The reader every case uses (Rd) CHECKS each request against the buffer: a request not wholly
 * inside it sets `bad`, and every case asserts `bad` stayed false.
 */
#include <catch2/catch_test_macros.hpp>

#include "component_native_parsers.hpp"

#include <cstdint>
#include <stdexcept>
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
    auto r = native_elf(rd.fn(), b.size());
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
    auto r = native_macho(rd.fn(), b.size());
    if (out)
        *out = rd;
    CHECK_FALSE(rd.bad);
    return r;
}

} // namespace

// ---- ELF outcome mapping ----

TEST_CASE("native_elf: ELF64 and ELF32, both byte orders, give the SONAME",
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

TEST_CASE("native_elf: no SONAME is a value of nothing; a non-ET_DYN file and a wrong magic are not libraries",
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
}

TEST_CASE("native_elf: a reader fault, a bound and an unreadable dynamic section are unreadable, never a value",
          "[component_native][component_inventory]") {
    auto cls = make_elf(true, false, "libfoo.so.1");
    cls.b[4] = 3; // right magic, impossible class: malformed
    expect_error(run_elf(cls.b), NativeError::unreadable);

    auto many = make_elf(true, false, "libfoo.so.1");
    put(many.b, 56, 200, 2, false); // phnum past the reader's ceiling: limit_exceeded
    expect_error(run_elf(many.b), NativeError::unreadable);

    auto cut = make_elf(true, false, "libfoo.so.1");
    cut.b.resize(100); // header present, program-header table past the end: truncated
    expect_error(run_elf(cut.b), NativeError::unreadable);

    // the string table lies outside every PT_LOAD: the reader flags dynamic_unreadable
    auto dyn = make_elf(true, false, "libfoo.so.1");
    put(dyn.b, dyn.strtab_val, 0x10, 8, false);
    expect_error(run_elf(dyn.b), NativeError::unreadable);

    // a name over the plugin's 255-byte cap
    expect_error(run_elf(make_elf(true, false, std::string(300, 'a')).b), NativeError::unreadable);
}

TEST_CASE("native_elf: the ELF magic on 4 to 15 bytes is unreadable (a file-name row); under 4 bytes is not a library",
          "[component_native][component_inventory]") {
    const auto full = make_elf(true, false, "libfoo.so.1").b;
    for (std::size_t n = 4; n <= 15; ++n) {
        INFO("length " << n);
        const auto cut = full.substr(0, n);
        Rd rd(cut);
        expect_error(run_elf(cut, &rd), NativeError::unreadable);
        REQUIRE(rd.reqs.size() == 1); // the magic read only: never past the file's end
        CHECK(rd.reqs[0].off == 0);
        CHECK(rd.reqs[0].len == 4);

        Rd named(cut);
        const auto d = describe_linux_file("libfoo.so.1", named.fn(), cut.size());
        REQUIRE(d.has_value());
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
    auto wrong = full.substr(0, 10);
    wrong[1] = 'X';
    expect_error(run_elf(wrong), NativeError::not_library);
}

TEST_CASE("native_elf: a SONAME is sanitised before it leaves the adapter",
          "[component_native][component_inventory]") {
    const auto e = make_elf(true, false, std::string("lib\x01\xff|x.so.1"));
    const auto r = run_elf(e.b);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK(**r == "lib??|x.so.1");
}

// ---- Mach-O outcome mapping ----

TEST_CASE("native_macho: thin 64 and 32 bit, either byte order, give the install name and version",
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

TEST_CASE("native_macho: no LC_ID_DYLIB is a value of nothing; other file types and magics are not libraries",
          "[component_native][component_inventory]") {
    MachoSpec none;
    none.with_id = false;
    const auto r = run_macho(make_macho(none));
    REQUIRE(r.has_value());
    CHECK_FALSE(r->has_value());

    MachoSpec exec;
    exec.filetype = 2; // MH_EXECUTE
    expect_error(run_macho(make_macho(exec)), NativeError::not_library);
    expect_error(run_macho(std::string("garbage!")), NativeError::not_library);
    expect_error(run_macho(std::string("ab")), NativeError::not_library);
}

TEST_CASE("native_macho: a damaged thin file is unreadable", "[component_native][component_inventory]") {
    MachoSpec s;
    auto cut = make_macho(s);
    cut.resize(cut.size() - 8); // load commands run past the end
    expect_error(run_macho(cut), NativeError::unreadable);

    auto many = make_macho(s);
    put(many, 16, 5000, 4, false); // ncmds past the reader's ceiling
    expect_error(run_macho(many), NativeError::unreadable);
}

TEST_CASE("native_macho: a universal file uses the first good dylib slice; a slice error is never a value",
          "[component_native][component_inventory]") {
    for (const bool fat64 : {false, true}) {
        INFO("fat64=" << fat64);
        MachoSpec a, b;
        a.name = "/usr/lib/libfirst.dylib";
        b.name = "/usr/lib/libsecond.dylib";
        { // both good: the first
            const auto r = run_macho(make_fat({make_macho(a), make_macho(b)}, fat64));
            REQUIRE(r.has_value());
            REQUIRE(r->has_value());
            CHECK((*r)->install_name == "/usr/lib/libfirst.dylib");
        }
        { // first slice errored (commands past its end): the second is the one read
            auto bad = make_macho(a);
            put(bad, 16, 5000, 4, false);
            const auto r = run_macho(make_fat({bad, make_macho(b)}, fat64));
            REQUIRE(r.has_value());
            REQUIRE(r->has_value());
            CHECK((*r)->install_name == "/usr/lib/libsecond.dylib");
        }
        { // first slice is not a dylib: skipped
            MachoSpec x = a;
            x.filetype = 2;
            const auto r = run_macho(make_fat({make_macho(x), make_macho(b)}, fat64));
            REQUIRE(r.has_value());
            REQUIRE(r->has_value());
            CHECK((*r)->install_name == "/usr/lib/libsecond.dylib");
        }
        { // every slice errored: unreadable, never a value
            auto bad = make_macho(a);
            put(bad, 16, 5000, 4, false);
            expect_error(run_macho(make_fat({bad, bad}, fat64)), NativeError::unreadable);
        }
        { // every slice good and none a dylib: not a library
            MachoSpec x = a;
            x.filetype = 2;
            expect_error(run_macho(make_fat({make_macho(x), make_macho(x)}, fat64)), NativeError::not_library);
        }
        { // one errored, the rest good and not dylibs: the error is not hidden
            MachoSpec x = a;
            x.filetype = 2;
            auto bad = make_macho(a);
            put(bad, 16, 5000, 4, false);
            expect_error(run_macho(make_fat({bad, make_macho(x)}, fat64)), NativeError::unreadable);
        }
    }
}

TEST_CASE("native_macho: an install name is sanitised and capped before it leaves the adapter",
          "[component_native][component_inventory]") {
    MachoSpec s;
    s.name = std::string("/usr/lib/lib\x01\xff.dylib");
    const auto r = run_macho(make_macho(s));
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK((*r)->install_name == "/usr/lib/lib??.dylib");

    MachoSpec big;
    big.name = std::string(300, 'a');
    expect_error(run_macho(make_macho(big)), NativeError::unreadable);
}

// ---- obligations on every read ----

TEST_CASE("a read_at that fails or comes up short at any call is unreadable, never a crash",
          "[component_native][component_inventory]") {
    MachoSpec ms;
    const std::vector<std::pair<const char*, std::string>> files = {
        {"elf64", make_elf(true, false, "libfoo.so.1").b},
        {"elf32be", make_elf(false, true, "libfoo.so.1").b},
        {"macho", make_macho(ms)},
        {"fat", make_fat({make_macho(ms)}, false)},
    };
    for (const auto& [what, bytes] : files) {
        INFO(what);
        const bool elf = std::string_view{what}.starts_with("elf");
        const auto parse = [&](Rd& rd) -> bool { // true when it came back as a value
            if (elf)
                return native_elf(rd.fn(), bytes.size()).has_value();
            return native_macho(rd.fn(), bytes.size()).has_value();
        };
        Rd clean(bytes);
        REQUIRE(parse(clean));
        REQUIRE(clean.calls >= 2);
        for (std::size_t k = 0; k < clean.calls; ++k) {
            Rd failing(bytes);
            failing.fail_call = k;
            CHECK_FALSE(parse(failing)); // a fault is never read as a (possibly empty) value
            Rd shorting(bytes);
            shorting.short_call = k;
            CHECK_FALSE(parse(shorting));
            CHECK_FALSE(failing.bad);
            CHECK_FALSE(shorting.bad);
        }
    }
}

TEST_CASE("an exception out of a read never crosses the adapter: it is unreadable",
          "[component_native][component_inventory]") {
    const auto elf = make_elf(true, false, "libfoo.so.1").b;
    const auto macho = make_macho(MachoSpec{});
    for (const auto* bytes : {&elf, &macho}) {
        Rd rd(*bytes);
        auto inner = rd.fn();
        const ReadAt throwing = [inner, n = std::size_t{0}](std::uint64_t off, std::size_t len) mutable
            -> std::optional<std::string> {
            if (n++ == 1)
                throw std::runtime_error("boom");
            return inner(off, len);
        };
        const auto r = bytes == &elf ? native_elf(throwing, bytes->size()).error_or(NativeError::not_library)
                                     : native_macho(throwing, bytes->size()).error_or(NativeError::not_library);
        CHECK(r == NativeError::unreadable);
        const auto d = bytes == &elf ? describe_linux_file("libfoo.so.1", throwing, bytes->size())
                                     : describe_macos_file("libfoo.dylib", throwing, bytes->size());
        REQUIRE(d.has_value()); // a file-name row, not an abort
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

// ---- fuzz-style sweep over the adapter ----

TEST_CASE("sweep: every truncation and damaged header byte is an outcome, never an outside read",
          "[component_native][component_inventory][sweep]") {
    MachoSpec thin;
    MachoSpec thin32;
    thin32.is64 = false;
    thin32.big = true;
    const std::vector<std::pair<const char*, std::string>> fixtures = {
        {"elf64", make_elf(true, false, "libfoo.so.1").b},
        {"elf32", make_elf(false, true, "libfoo.so.1").b},
        {"thin", make_macho(thin)},
        {"fat", make_fat({make_macho(thin), make_macho(thin32)}, false)},
        {"fat64", make_fat({make_macho(thin), make_macho(thin32)}, true)},
    };
    const auto run_both = [](const std::string& bytes) {
        Rd a(bytes);
        (void)native_elf(a.fn(), bytes.size());
        Rd b(bytes);
        (void)native_macho(b.fn(), bytes.size());
        return !a.bad && !b.bad;
    };
    for (const auto& [what, bytes] : fixtures) {
        INFO(what);
        bool clean = true;
        for (std::size_t len = 0; len <= bytes.size(); ++len)
            clean = run_both(bytes.substr(0, len)) && clean;
        for (std::size_t i = 0; i < std::min<std::size_t>(512, bytes.size()); ++i)
            for (const unsigned char v : {0x00, 0x7f, 0x80, 0xff}) {
                auto m = bytes;
                m[i] = static_cast<char>(v);
                clean = run_both(m) && clean;
            }
        CHECK(clean);
    }
}
