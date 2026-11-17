/**
 * test_binary_header_elf.cpp - bounded ELF header, program-header, note and DT_SONAME reader
 * (binary_header_elf.hpp).
 *
 * Pure header, no I/O except one real capture: synthesised images come from the builder below
 * (ELF32-LE, ELF64-LE and ELF64-BE), the real elf_shared.bin is loaded through
 * YUZU_TEST_FIXTURE_DIR and its case FAILS when the file is absent. Adjacent-byte cases use a
 * recording Source to prove no byte outside the enclosing region was requested.
 */

#include "binary_header_elf.hpp"

#include "binary_header_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace bh = yuzu::shared::binary_header;

namespace {

using Bytes = std::vector<std::uint8_t>;
using bhtest::Probe;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr u64 kBase = 0x10000; // vaddr of the canonical PT_LOAD (file offset 0)

struct Shape {
    const char* name;
    bool is64;
    std::endian order;
    u16 machine;
};
const std::array<Shape, 3> kShapes{{{"elf32le", false, std::endian::little, 3},
                                    {"elf64le", true, std::endian::little, 62},
                                    {"elf64be", true, std::endian::big, 21}}};

void put(Bytes& b, std::size_t off, u64 v, std::size_t width, std::endian order) {
    for (std::size_t i = 0; i < width; ++i) {
        const std::size_t shift = order == std::endian::little ? i : width - 1 - i;
        b.at(off + i) = static_cast<std::uint8_t>(v >> (8 * shift));
    }
}

struct Seg {
    u32 type{0};
    u32 flags{0};
    u64 off{0};
    u64 vaddr{0};
    u64 filesz{0};
    u64 memsz{0};
    u64 align{0};
};
struct Blob {
    u64 off;
    Bytes bytes;
};
struct Spec {
    bool is64{true};
    std::endian order{std::endian::little};
    std::uint8_t os_abi{3};
    u16 type{3};
    u16 machine{62};
    u64 entry{0x1040};
    std::vector<Seg> phs;
    std::vector<Blob> blobs;
    std::optional<u16> phentsize; // header-field overrides
    std::optional<u16> phnum;
    std::optional<u64> phoff;
    u64 min_size{0};
};

Bytes build(const Spec& s) {
    const std::size_t ehsz = s.is64 ? 64 : 52;
    const std::size_t phent = s.is64 ? 56 : 32;
    const u64 phoff = s.phoff.value_or(ehsz);
    u64 total = std::max<u64>(s.min_size, ehsz + s.phs.size() * phent);
    for (const auto& b : s.blobs)
        total = std::max<u64>(total, b.off + b.bytes.size());
    Bytes out(static_cast<std::size_t>(total), 0);
    const auto o = s.order;
    out[0] = 0x7F;
    out[1] = 'E';
    out[2] = 'L';
    out[3] = 'F';
    out[4] = s.is64 ? 2 : 1;
    out[5] = o == std::endian::little ? 1 : 2;
    out[6] = 1;
    out[7] = s.os_abi;
    put(out, 16, s.type, 2, o);
    put(out, 18, s.machine, 2, o);
    put(out, 20, 1, 4, o);
    const u16 pe = s.phentsize.value_or(static_cast<u16>(phent));
    const u16 pn = s.phnum.value_or(static_cast<u16>(s.phs.size()));
    if (s.is64) {
        put(out, 24, s.entry, 8, o);
        put(out, 32, phoff, 8, o);
        put(out, 52, 64, 2, o);
        put(out, 54, pe, 2, o);
        put(out, 56, pn, 2, o);
    } else {
        put(out, 24, s.entry, 4, o);
        put(out, 28, phoff, 4, o);
        put(out, 40, 52, 2, o);
        put(out, 42, pe, 2, o);
        put(out, 44, pn, 2, o);
    }
    for (std::size_t i = 0; i < s.phs.size(); ++i) {
        const auto& p = s.phs[i];
        const std::size_t at = ehsz + i * phent;
        put(out, at, p.type, 4, o);
        if (s.is64) {
            put(out, at + 4, p.flags, 4, o);
            put(out, at + 8, p.off, 8, o);
            put(out, at + 16, p.vaddr, 8, o);
            put(out, at + 24, p.vaddr, 8, o);
            put(out, at + 32, p.filesz, 8, o);
            put(out, at + 40, p.memsz, 8, o);
            put(out, at + 48, p.align, 8, o);
        } else {
            put(out, at + 4, p.off, 4, o);
            put(out, at + 8, p.vaddr, 4, o);
            put(out, at + 12, p.vaddr, 4, o);
            put(out, at + 16, p.filesz, 4, o);
            put(out, at + 20, p.memsz, 4, o);
            put(out, at + 24, p.flags, 4, o);
            put(out, at + 28, p.align, 4, o);
        }
    }
    for (const auto& b : s.blobs)
        std::copy(b.bytes.begin(), b.bytes.end(), out.begin() + static_cast<std::ptrdiff_t>(b.off));
    return out;
}

Bytes dyn_blob(const Spec& s, const std::vector<std::pair<u64, u64>>& entries) {
    const std::size_t w = s.is64 ? 8 : 4;
    Bytes out(entries.size() * 2 * w, 0);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        put(out, i * 2 * w, entries[i].first, w, s.order);
        put(out, i * 2 * w + w, entries[i].second, w, s.order);
    }
    return out;
}

// One complete note record: name gets its NUL; the descriptor and the end of the record sit on
// `align` boundaries of the record's own start (the gABI aligns positions, not name lengths).
Bytes note_rec(std::endian o, std::string_view name, u32 type, const Bytes& desc,
               std::size_t align = 4) {
    const std::size_t namesz = name.size() + 1;
    const auto up = [align](std::size_t n) { return (n + align - 1) / align * align; };
    const std::size_t desc_at = up(12 + namesz);
    Bytes out(up(desc_at + desc.size()), 0);
    put(out, 0, namesz, 4, o);
    put(out, 4, desc.size(), 4, o);
    put(out, 8, type, 4, o);
    std::copy(name.begin(), name.end(), out.begin() + 12);
    std::copy(desc.begin(), desc.end(), out.begin() + static_cast<std::ptrdiff_t>(desc_at));
    return out;
}

// A bare 12-byte note header declaring sizes the segment need not back.
Bytes note_hdr(std::endian o, u32 namesz, u32 descsz, u32 type) {
    Bytes out(12, 0);
    put(out, 0, namesz, 4, o);
    put(out, 4, descsz, 4, o);
    put(out, 8, type, 4, o);
    return out;
}

Bytes cat(Bytes a, const Bytes& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

Bytes build_id_desc() {
    Bytes d(20);
    for (std::size_t i = 0; i < d.size(); ++i)
        d[i] = static_cast<std::uint8_t>(0xA0 + i);
    return d;
}
constexpr const char* kBuildIdHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3";

// The same two records as an 8-aligned PT_NOTE, laid out by hand from the gABI rather than by
// note_rec: "GNU" (namesz 4, 20-byte build id) has its descriptor at 16 and ends at 40, then "a"
// (namesz 2, 3-byte desc) has its name at 52, descriptor at 56 and ends at 64.
Bytes note_pair_8_aligned(std::endian o) {
    Bytes b(64, 0);
    put(b, 0, 4, 4, o);
    put(b, 4, 20, 4, o);
    put(b, 8, 3, 4, o);
    std::copy_n("GNU", 4, b.begin() + 12);
    const Bytes id = build_id_desc();
    std::copy(id.begin(), id.end(), b.begin() + 16);
    put(b, 40, 2, 4, o);
    put(b, 44, 3, 4, o);
    put(b, 48, 7, 4, o);
    b[52] = 'a';
    b[56] = 1;
    b[57] = 2;
    b[58] = 3;
    return b;
}
constexpr const char* kInterp = "/lib/ld.so.1";
constexpr const char* kSoname = "libt.so.1";

// Canonical image: PT_LOAD (whole file at kBase), PT_INTERP, PT_NOTE (GNU build id), PT_DYNAMIC
// (STRTAB, STRSZ, SONAME, NULL). Each blob sits in a roomy slot so a test can swap its bytes.
enum Idx : std::size_t { kLoad = 0, kInterpSeg = 1, kNoteSeg = 2, kDynSeg = 3 };
enum BlobIdx : std::size_t { bInterp = 0, bNote = 1, bDynstr = 2, bDyn = 3 };

struct Canon {
    Spec spec;
    u64 interp{0}, note{0}, dynstr{0}, dyn{0}, strsz{0};
    std::size_t es{0};
};

std::vector<std::pair<u64, u64>> canon_dyn(const Canon& c) {
    return {{5, kBase + c.dynstr}, {10, c.strsz}, {14, 1}, {0, 0}};
}

void set_dyn(Canon& c, const std::vector<std::pair<u64, u64>>& e) {
    c.spec.blobs[bDyn].bytes = dyn_blob(c.spec, e);
    c.spec.phs[kDynSeg].filesz = c.spec.phs[kDynSeg].memsz = c.spec.blobs[bDyn].bytes.size();
}

void set_notes(Canon& c, const Bytes& b, u64 align = 4) {
    REQUIRE(b.size() <= 256);
    c.spec.blobs[bNote].bytes = b;
    c.spec.phs[kNoteSeg].filesz = c.spec.phs[kNoteSeg].memsz = b.size();
    c.spec.phs[kNoteSeg].align = align;
}

Canon canonical(const Shape& sh) {
    Canon c;
    auto& s = c.spec;
    s.is64 = sh.is64;
    s.order = sh.order;
    s.machine = sh.machine;
    const u64 ehsz = sh.is64 ? 64 : 52, phent = sh.is64 ? 56 : 32;
    c.es = sh.is64 ? 16 : 8;
    c.interp = (ehsz + 4 * phent + 7) / 8 * 8;
    c.note = c.interp + 32;
    c.dynstr = c.note + 256;
    c.dyn = c.dynstr + 64;
    s.min_size = c.dyn + 256;

    const std::string interp = std::string(kInterp) + '\0';
    Bytes dynstr{0};
    for (const char ch : std::string(kSoname) + '\0')
        dynstr.push_back(static_cast<std::uint8_t>(ch));
    c.strsz = dynstr.size();

    s.phs.resize(4);
    s.phs[kLoad] = {1, 5, 0, kBase, s.min_size, s.min_size + 0x100, 0x1000};
    s.phs[kInterpSeg] = {3, 4, c.interp, kBase + c.interp, interp.size(), interp.size(), 1};
    s.phs[kNoteSeg] = {4, 4, c.note, kBase + c.note, 0, 0, 4};
    s.phs[kDynSeg] = {2, 6, c.dyn, kBase + c.dyn, 0, 0, 8};
    s.blobs.resize(4);
    s.blobs[bInterp] = {c.interp, Bytes(interp.begin(), interp.end())};
    s.blobs[bNote] = {c.note, {}};
    s.blobs[bDynstr] = {c.dynstr, dynstr};
    s.blobs[bDyn] = {c.dyn, {}};
    set_notes(c, note_rec(sh.order, "GNU", 3, build_id_desc()));
    set_dyn(c, canon_dyn(c));
    return c;
}

bh::Source src_of(const Bytes& b) {
    return bh::span_source(std::as_bytes(std::span<const std::uint8_t>(b)));
}

Bytes load_shared() {
    const auto s = bhtest::load_fixture("elf_shared.bin");
    return Bytes(s.begin(), s.end());
}

// Every read stays inside the visible prefix and inside the default budget.
void check_reads(const Probe& p) {
    const bh::ReadBudget budget;
    CHECK(p.reads.size() <= budget.max_reads);
    CHECK(p.total <= budget.max_bytes);
    CHECK_FALSE(p.beyond_visible());
}

bh::ElfInfo must_read(const Bytes& b, const bh::ElfLimits& lim = {}) {
    auto r = bh::read_elf(src_of(b), lim);
    INFO("error: " << (r ? "" : std::string(bh::to_token(r.error()))));
    REQUIRE(r.has_value());
    return *r;
}

void expect_err(const Bytes& b, bh::ParseError e, const bh::ElfLimits& lim = {}) {
    auto r = bh::read_elf(src_of(b), lim);
    INFO("expected " << bh::to_token(e));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == e);
}

// A degraded-but-valid result: the header and program headers still come back.
void expect_unreadable_dynamic(const Bytes& b, const bh::ElfLimits& lim = {}) {
    const auto i = must_read(b, lim);
    CHECK(i.soname.empty());
    CHECK(i.dynamic_unreadable);
    CHECK(i.program_headers.size() == 4);
}

} // namespace

TEST_CASE("elf: canonical images give exact fields", "[binary_header][elf]") {
    for (const auto& sh : kShapes) {
        INFO(sh.name);
        const auto c = canonical(sh);
        const auto img = build(c.spec);
        const auto i = must_read(img);
        CHECK(i.is64 == sh.is64);
        CHECK(i.byte_order == sh.order);
        CHECK(i.os_abi == 3);
        CHECK(i.type == 3);
        CHECK(i.machine == sh.machine);
        CHECK(i.entry == 0x1040);
        REQUIRE(i.program_headers.size() == 4);
        for (std::size_t k = 0; k < 4; ++k) {
            const auto& want = c.spec.phs[k];
            const auto& got = i.program_headers[k];
            INFO("phdr " << k);
            CHECK(got.type == want.type);
            CHECK(got.flags == want.flags);
            CHECK(got.offset == want.off);
            CHECK(got.vaddr == want.vaddr);
            CHECK(got.filesz == want.filesz);
            CHECK(got.memsz == want.memsz);
            CHECK(got.align == want.align);
        }
        CHECK(i.interpreter == kInterp);
        CHECK(i.soname == kSoname);
        CHECK(i.build_id == kBuildIdHex);
        REQUIRE(i.notes.size() == 1);
        CHECK(i.notes[0].owner == "GNU");
        CHECK(i.notes[0].type == 3);
        CHECK(i.notes[0].desc.size() == 20);
        CHECK_FALSE(i.notes_truncated);
        CHECK_FALSE(i.dynamic_unreadable);
    }
}

TEST_CASE("elf: no program headers is a plain header", "[binary_header][elf]") {
    for (const auto& sh : kShapes) {
        INFO(sh.name);
        auto c = canonical(sh);
        c.spec.phnum = 0;
        c.spec.phentsize = 7; // ignored when there is nothing to read
        const auto i = must_read(build(c.spec));
        CHECK(i.program_headers.empty());
        CHECK(i.interpreter.empty());
        CHECK(i.soname.empty());
        CHECK(i.type == 3);
        CHECK_FALSE(i.dynamic_unreadable);
    }
}

TEST_CASE("elf: not-this-format and header faults", "[binary_header][elf]") {
    const auto c = canonical(kShapes[1]);
    const auto img = build(c.spec);
    for (std::size_t n = 0; n < 4; ++n)
        expect_err(Bytes(img.begin(), img.begin() + static_cast<std::ptrdiff_t>(n)),
                   bh::ParseError::not_this_format);
    auto bad_magic = img;
    bad_magic[1] = 'X';
    expect_err(bad_magic, bh::ParseError::not_this_format);
    for (const std::uint8_t v : {0, 3, 255}) {
        auto bad_class = img;
        bad_class[4] = v;
        expect_err(bad_class, bh::ParseError::malformed);
        auto bad_data = img;
        bad_data[5] = v;
        expect_err(bad_data, bh::ParseError::malformed);
    }
}

TEST_CASE("elf: program-header count, size and table placement", "[binary_header][elf]") {
    for (const auto& sh : kShapes) {
        INFO(sh.name);
        const std::size_t phent = sh.is64 ? 56 : 32;
        {
            auto c = canonical(sh);
            c.spec.phnum = 0xFFFF; // PN_XNUM
            expect_err(build(c.spec), bh::ParseError::limit_exceeded);
            c.spec.phnum = 129; // one over the default cap
            expect_err(build(c.spec), bh::ParseError::limit_exceeded);
        }
        {
            bh::ElfLimits tight;
            tight.max_program_headers = 3;
            expect_err(build(canonical(sh).spec), bh::ParseError::limit_exceeded, tight);
        }
        for (const std::size_t wrong : {std::size_t{0}, phent - 1, phent + 1, std::size_t{56 + 32 - phent}}) {
            auto c = canonical(sh);
            c.spec.phentsize = static_cast<u16>(wrong);
            expect_err(build(c.spec), bh::ParseError::malformed);
        }
        { // table starts inside the file but runs past its end
            auto c = canonical(sh);
            const auto img = build(c.spec);
            c.spec.phoff = img.size() - phent;
            expect_err(build(c.spec), bh::ParseError::truncated);
        }
        { // phoff + phnum * phentsize overflows
            auto c = canonical(sh);
            c.spec.phoff = UINT64_MAX - 4;
            expect_err(build(c.spec), bh::ParseError::truncated);
        }
        { // image cut inside the table
            const auto img = build(canonical(sh).spec);
            const std::size_t ehsz = sh.is64 ? 64 : 52;
            expect_err(Bytes(img.begin(), img.begin() + static_cast<std::ptrdiff_t>(ehsz + phent)),
                       bh::ParseError::truncated);
        }
    }
}

TEST_CASE("elf: interpreter degrades, never fails the file", "[binary_header][elf]") {
    for (const auto& sh : kShapes) {
        INFO(sh.name);
        { // string cap below the length: no NUL inside the cap
            bh::ElfLimits lim;
            lim.max_string_bytes = 5;
            const auto i = must_read(build(canonical(sh).spec), lim);
            CHECK(i.interpreter.empty());
        }
        { // offset past everything, and an offset whose length overflows
            auto c = canonical(sh);
            c.spec.phs[kInterpSeg].off = UINT64_MAX;
            CHECK(must_read(build(c.spec)).interpreter.empty());
            c.spec.phs[kInterpSeg].off = UINT64_MAX - 3;
            CHECK(must_read(build(c.spec)).interpreter.empty());
        }
        { // [offset, offset + filesz) runs past the end of the file even though a NUL is in it
            auto c = canonical(sh);
            const auto img = build(c.spec);
            c.spec.phs[kInterpSeg].filesz = img.size() - c.interp + 1;
            CHECK(must_read(img).interpreter == kInterp);
            CHECK(must_read(build(c.spec)).interpreter.empty());
        }
        { // the terminator lies one byte after p_filesz: degraded, and that byte is never read
            auto c = canonical(sh);
            const std::size_t len = std::string_view(kInterp).size();
            c.spec.phs[kInterpSeg].filesz = len;
            const auto img = build(c.spec);
            Probe log(img);
            auto r = bh::read_elf(log.source());
            REQUIRE(r.has_value());
            CHECK(r->interpreter.empty());
            CHECK_FALSE(log.touched(c.interp + len));
            CHECK(r->soname == kSoname);
        }
        { // zero-length segment
            auto c = canonical(sh);
            c.spec.phs[kInterpSeg].filesz = 0;
            CHECK(must_read(build(c.spec)).interpreter.empty());
        }
    }
}

TEST_CASE("elf: notes, alignment and truncation", "[binary_header][elf]") {
    for (const auto& sh : kShapes) {
        INFO(sh.name);
        const auto o = sh.order;
        const Bytes desc3{1, 2, 3};
        { // 8-aligned PT_NOTE, laid out by hand: descriptors at 16 and 56, records end at 40, 64
            auto c = canonical(sh);
            set_notes(c, note_pair_8_aligned(o), 8);
            const auto i = must_read(build(c.spec));
            REQUIRE(i.notes.size() == 2);
            CHECK(i.notes[0].owner == "GNU");
            CHECK(i.notes[0].type == 3);
            CHECK(i.notes[0].desc.size() == 20);
            CHECK(i.build_id == kBuildIdHex);
            CHECK(i.notes[1].owner == "a");
            CHECK(i.notes[1].type == 7);
            CHECK(i.notes[1].desc == std::string("\x01\x02\x03", 3));
            CHECK_FALSE(i.notes_truncated);
        }
        { // the builder agrees with the hand-laid bytes
            CHECK(cat(note_rec(o, "GNU", 3, build_id_desc(), 8), note_rec(o, "a", 7, desc3, 8)) ==
                  note_pair_8_aligned(o));
        }
        { // 8-aligned records read back through the builder too
            auto c = canonical(sh);
            set_notes(c,
                      cat(note_rec(o, "a", 7, desc3, 8),
                          note_rec(o, "GNU", 3, build_id_desc(), 8)),
                      8);
            const auto i = must_read(build(c.spec));
            REQUIRE(i.notes.size() == 2);
            CHECK(i.notes[0].owner == "a");
            CHECK(i.notes[1].owner == "GNU");
            CHECK(i.build_id == kBuildIdHex);
            CHECK_FALSE(i.notes_truncated);
        }
        { // the same 4-aligned bytes read with align 4 give the same two notes
            auto c = canonical(sh);
            set_notes(c, cat(note_rec(o, "a", 7, desc3), note_rec(o, "GNU", 3, build_id_desc())));
            const auto i = must_read(build(c.spec));
            CHECK(i.notes.size() == 2);
            CHECK_FALSE(i.notes_truncated);
        }
        { // a non-build-id GNU note does not set build_id
            auto c = canonical(sh);
            set_notes(c, note_rec(o, "GNU", 1, build_id_desc()));
            const auto i = must_read(build(c.spec));
            CHECK(i.notes.size() == 1);
            CHECK(i.build_id.empty());
        }
        { // over-size segment: skipped whole
            bh::ElfLimits lim;
            lim.max_note_segment_bytes = 16;
            const auto i = must_read(build(canonical(sh).spec), lim);
            CHECK(i.notes.empty());
            CHECK(i.notes_truncated);
            CHECK(i.build_id.empty());
            CHECK(i.soname == kSoname);
        }
        { // over-cap namesz keeps the earlier note
            auto c = canonical(sh);
            set_notes(c, cat(note_rec(o, "GNU", 3, build_id_desc()), note_hdr(o, 65, 4, 1)));
            const auto i = must_read(build(c.spec));
            CHECK(i.notes.size() == 1);
            CHECK(i.notes_truncated);
            CHECK(i.build_id == kBuildIdHex);
        }
        { // over-cap descsz keeps the earlier note
            auto c = canonical(sh);
            set_notes(c, cat(note_rec(o, "GNU", 3, build_id_desc()), note_hdr(o, 4, 4097, 1)));
            const auto i = must_read(build(c.spec));
            CHECK(i.notes.size() == 1);
            CHECK(i.notes_truncated);
        }
        { // a record whose desc runs past the end of its segment
            auto c = canonical(sh);
            set_notes(c, cat(cat(note_rec(o, "GNU", 3, build_id_desc()), note_hdr(o, 4, 100, 1)),
                             Bytes{'Y', 'u', 'z', 0, 9, 9}));
            const auto i = must_read(build(c.spec));
            CHECK(i.notes.size() == 1);
            CHECK(i.notes_truncated);
        }
        { // trailing bytes too short for a header
            auto c = canonical(sh);
            set_notes(c, cat(note_rec(o, "GNU", 3, build_id_desc()), Bytes{1, 2, 3}));
            const auto i = must_read(build(c.spec));
            CHECK(i.notes.size() == 1);
            CHECK(i.notes_truncated);
        }
        { // more notes than max_notes
            auto c = canonical(sh);
            set_notes(c, cat(note_rec(o, "GNU", 3, build_id_desc()), note_rec(o, "b", 1, desc3)));
            bh::ElfLimits lim;
            lim.max_notes = 1;
            const auto i = must_read(build(c.spec), lim);
            CHECK(i.notes.size() == 1);
            CHECK(i.notes_truncated);
        }
        { // segment offset past the end of the file: degraded, header still returned
            auto c = canonical(sh);
            c.spec.phs[kNoteSeg].off = UINT64_MAX - 7;
            const auto i = must_read(build(c.spec));
            CHECK(i.notes.empty());
            CHECK(i.notes_truncated);
            CHECK(i.program_headers.size() == 4);
        }
    }
}

TEST_CASE("elf: DT_SONAME is bounded by the dynamic segment and the string table",
          "[binary_header][elf]") {
    for (const auto& sh : kShapes) {
        INFO(sh.name);
        { // no DT_NULL inside the segment
            auto c = canonical(sh);
            auto e = canon_dyn(c);
            e.pop_back();
            set_dyn(c, e);
            expect_unreadable_dynamic(build(c.spec));
        }
        { // no DT_NULL inside max_dynamic_entries
            bh::ElfLimits lim;
            lim.max_dynamic_entries = 2;
            expect_unreadable_dynamic(build(canonical(sh).spec), lim);
        }
        { // DT_NULL exactly at the cap is accepted
            bh::ElfLimits lim;
            lim.max_dynamic_entries = 4;
            CHECK(must_read(build(canonical(sh).spec), lim).soname == kSoname);
        }
        { // DT_NULL just past p_filesz: never read
            auto c = canonical(sh);
            const auto full = c.spec.phs[kDynSeg].filesz;
            c.spec.phs[kDynSeg].filesz = c.spec.phs[kDynSeg].memsz = full - c.es;
            const auto img = build(c.spec);
            Probe log(img);
            auto r = bh::read_elf(log.source());
            REQUIRE(r.has_value());
            CHECK(r->soname.empty());
            CHECK(r->dynamic_unreadable);
            CHECK_FALSE(log.touched(c.dyn + full - c.es));
        }
        { // DT_STRTAB in no PT_LOAD
            auto c = canonical(sh);
            auto e = canon_dyn(c);
            e[0].second = 0xDEADBEEF;
            set_dyn(c, e);
            expect_unreadable_dynamic(build(c.spec));
            e[0].second = sh.is64 ? UINT64_MAX : 0xFFFFFFFFull;
            set_dyn(c, e);
            expect_unreadable_dynamic(build(c.spec));
        }
        { // DT_SONAME offset beyond DT_STRSZ
            auto c = canonical(sh);
            auto e = canon_dyn(c);
            e[2].second = c.strsz;
            set_dyn(c, e);
            expect_unreadable_dynamic(build(c.spec));
            e[2].second = 0xFFFFFFFF;
            set_dyn(c, e);
            expect_unreadable_dynamic(build(c.spec));
        }
        { // DT_STRSZ absurd or zero
            auto c = canonical(sh);
            auto e = canon_dyn(c);
            e[1].second = sh.is64 ? UINT64_MAX : 0xFFFFFFFFull;
            set_dyn(c, e);
            expect_unreadable_dynamic(build(c.spec));
            e[1].second = 0;
            set_dyn(c, e);
            expect_unreadable_dynamic(build(c.spec));
        }
        { // DT_STRTAB or DT_STRSZ absent while DT_SONAME is present
            auto c = canonical(sh);
            auto e = canon_dyn(c);
            set_dyn(c, {e[1], e[2], e[3]});
            expect_unreadable_dynamic(build(c.spec));
            set_dyn(c, {e[0], e[2], e[3]});
            expect_unreadable_dynamic(build(c.spec));
        }
        { // a terminated table with no DT_SONAME is not a fault
            auto c = canonical(sh);
            auto e = canon_dyn(c);
            set_dyn(c, {e[0], e[1], e[3]});
            const auto i = must_read(build(c.spec));
            CHECK(i.soname.empty());
            CHECK_FALSE(i.dynamic_unreadable);
        }
        { // no PT_DYNAMIC at all is not a fault
            auto c = canonical(sh);
            c.spec.phs[kDynSeg].type = 0;
            const auto i = must_read(build(c.spec));
            CHECK(i.soname.empty());
            CHECK_FALSE(i.dynamic_unreadable);
        }
        { // segment placed so that offset + size overflows, and one that is too short for an entry
            auto c = canonical(sh);
            c.spec.phs[kDynSeg].off = UINT64_MAX - 4;
            expect_unreadable_dynamic(build(c.spec));
            c = canonical(sh);
            c.spec.phs[kDynSeg].filesz = c.es - 1;
            expect_unreadable_dynamic(build(c.spec));
        }
        { // a decoy PT_LOAD that does not hold the table is skipped for one that does
            auto c = canonical(sh);
            // Swap in place (a fifth header would grow the table over the blobs): the decoy first,
            // the real PT_LOAD second.
            c.spec.phs[kInterpSeg] = c.spec.phs[kLoad];
            c.spec.phs[kLoad] = Seg{1, 4, 0, 0x90000000, 16, 16, 0x1000};
            CHECK(must_read(build(c.spec)).soname == kSoname);
        }
        { // SONAME terminator is the first byte AFTER the string table: degraded, byte untouched
            auto c = canonical(sh);
            auto e = canon_dyn(c);
            e[1].second = c.strsz - 1; // table now ends before the name's NUL
            set_dyn(c, e);
            const auto img = build(c.spec);
            Probe log(img);
            auto r = bh::read_elf(log.source());
            REQUIRE(r.has_value());
            CHECK(r->soname.empty());
            CHECK(r->dynamic_unreadable);
            CHECK_FALSE(log.touched(c.dynstr + c.strsz - 1));
        }
        { // DT_STRSZ runs one byte past the PT_LOAD's file-backed part
            auto c = canonical(sh);
            c.spec.phs[kLoad].filesz = c.dynstr + c.strsz - 1;
            const auto img = build(c.spec);
            Probe log(img);
            auto r = bh::read_elf(log.source());
            REQUIRE(r.has_value());
            CHECK(r->soname.empty());
            CHECK(r->dynamic_unreadable);
            CHECK_FALSE(log.touched(c.dynstr + c.strsz - 1));
            // the exact fit is accepted
            c.spec.phs[kLoad].filesz = c.dynstr + c.strsz;
            CHECK(must_read(build(c.spec)).soname == kSoname);
        }
        { // soname longer than max_string_bytes
            bh::ElfLimits lim;
            lim.max_string_bytes = 4;
            expect_unreadable_dynamic(build(canonical(sh).spec), lim);
        }
    }
}

TEST_CASE("elf: read_at failures: mandatory reads surface as io, derived reads degrade",
          "[binary_header][elf]") {
    const auto c = canonical(kShapes[1]);
    const auto img = build(c.spec);
    {
        bh::Source s{[](u64, std::size_t) -> std::optional<std::string> { return std::nullopt; },
                     img.size()};
        auto r = bh::read_elf(s);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == bh::ParseError::io);
    }
    {
        bh::Source s{nullptr, img.size()};
        auto r = bh::read_elf(s);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == bh::ParseError::io);
    }
    { // the program-header table is mandatory: its read failing is an io error
        bh::Source inner = src_of(img);
        bh::Source s{[inner](u64 off, std::size_t len) -> std::optional<std::string> {
                         if (off == 64)
                             return std::nullopt;
                         return inner.read_at(off, len);
                     },
                     inner.size};
        auto r = bh::read_elf(s);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == bh::ParseError::io);
    }
    // Header and table read fine, then each derived region fails in turn: the failure degrades that
    // one field (flag set where one exists) and keeps everything parsed before and after it.
    enum Region { kInterpReg, kNoteReg, kDynstrReg, kDynReg };
    const u64 kEnd = UINT64_MAX;
    const std::array<std::tuple<Region, u64, u64>, 4> regions{{{kInterpReg, c.interp, c.note},
                                                               {kNoteReg, c.note, c.dynstr},
                                                               {kDynstrReg, c.dynstr, c.dyn},
                                                               {kDynReg, c.dyn, kEnd}}};
    for (const auto& [reg, lo, hi] : regions) {
        INFO("fails in [" << lo << ", " << hi << ")");
        bh::Source inner = src_of(img);
        bh::Source s{[inner, lo = lo, hi = hi](u64 off, std::size_t len) -> std::optional<std::string> {
                         if (off >= lo && off < hi)
                             return std::nullopt;
                         return inner.read_at(off, len);
                     },
                     inner.size};
        auto r = bh::read_elf(s);
        REQUIRE(r.has_value());
        CHECK(r->is64);
        CHECK(r->program_headers.size() == 4);
        CHECK(r->interpreter == (reg == kInterpReg ? "" : kInterp));
        CHECK(r->notes_truncated == (reg == kNoteReg));
        CHECK(r->notes.empty() == (reg == kNoteReg));
        CHECK(r->build_id.empty() == (reg == kNoteReg));
        const bool dyn_lost = reg == kDynstrReg || reg == kDynReg;
        CHECK(r->dynamic_unreadable == dyn_lost);
        CHECK(r->soname.empty() == dyn_lost);
    }
}

TEST_CASE("elf: read budget is honoured and degrades", "[binary_header][elf]") {
    for (const auto& sh : kShapes) {
        INFO(sh.name);
        const auto img = build(canonical(sh).spec);
        Probe log(img);
        auto full = bh::read_elf(log.source());
        REQUIRE(full.has_value());
        CHECK(full->soname == kSoname);
        const u64 total = log.total;
        const std::size_t reads = log.reads.size();
        CHECK(reads >= 4);

        { // exact budget: identical result
            auto r = bh::read_elf(src_of(img), {}, bh::ReadBudget{total, reads});
            REQUIRE(r.has_value());
            CHECK(r->soname == kSoname);
            CHECK(r->interpreter == kInterp);
            CHECK_FALSE(r->dynamic_unreadable);
        }
        { // one read fewer: the last read (the soname string) is refused and the result degrades
            Probe l2(img);
            auto r = bh::read_elf(l2.source(), {}, bh::ReadBudget{total, reads - 1});
            REQUIRE(r.has_value());
            CHECK(r->soname.empty());
            CHECK(r->dynamic_unreadable);
            CHECK(l2.reads.size() == reads - 1);
            CHECK(l2.total <= total);
        }
        { // a single read: the program-header table is refused BEFORE read_at is called
            Probe l3(img);
            auto r = bh::read_elf(l3.source(), {}, bh::ReadBudget{total, 1});
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == bh::ParseError::limit_exceeded);
            CHECK(l3.reads.size() == 1);
        }
        { // byte budget covering only header + table
            // the first read is always min(size, 64) bytes, whatever the class
            const std::size_t phent = sh.is64 ? 56 : 32, covered = 64 + 4 * phent;
            Probe l4(img);
            auto r = bh::read_elf(l4.source(), {}, bh::ReadBudget{covered, 4096});
            REQUIRE(r.has_value());
            CHECK(r->interpreter.empty());
            CHECK(r->notes.empty());
            CHECK(r->soname.empty());
            CHECK(r->dynamic_unreadable);
            CHECK(l4.reads.size() == 2);
            CHECK(l4.total == covered);
        }
    }
}

TEST_CASE("elf: truncation sweep", "[binary_header][elf]") {
    for (const auto& sh : kShapes) {
        INFO(sh.name);
        const auto img = build(canonical(sh).spec);
        const std::size_t ehsz = sh.is64 ? 64 : 52, phent = sh.is64 ? 56 : 32;
        const std::size_t table_end = ehsz + 4 * phent;
        Probe p(img);
        for (std::size_t n = 0; n <= img.size(); ++n) {
            p.reset();
            p.visible = n;
            auto r = bh::read_elf(p.source());
            INFO("prefix " << n);
            check_reads(p);
            if (n < 4) {
                REQUIRE_FALSE(r.has_value());
                CHECK(r.error() == bh::ParseError::not_this_format);
            } else if (n < table_end) {
                REQUIRE_FALSE(r.has_value());
                CHECK(r.error() == bh::ParseError::truncated);
            } else {
                REQUIRE(r.has_value()); // everything past the table degrades, never fails
                CHECK(r->program_headers.size() == 4);
                CHECK(r->soname.size() <= bh::ElfLimits{}.max_string_bytes);
                if (r->dynamic_unreadable)
                    CHECK(r->soname.empty());
                if (n == img.size()) {
                    CHECK(r->soname == kSoname);
                    CHECK(r->build_id == kBuildIdHex);
                }
            }
        }
    }
}

TEST_CASE("elf: real capture truncation sweep", "[binary_header][elf]") {
    const Bytes img = load_shared();
    Probe p(img);
    for (std::size_t n = 0; n <= img.size(); ++n) {
        p.reset();
        p.visible = n;
        auto r = bh::read_elf(p.source());
        INFO("prefix " << n);
        check_reads(p);
        if (r) { // a value or an error is fine; a value must stay inside the limits
            CHECK(r->program_headers.size() <= bh::ElfLimits{}.max_program_headers);
            CHECK(r->soname.size() <= bh::ElfLimits{}.max_string_bytes);
            if (r->dynamic_unreadable)
                CHECK(r->soname.empty());
        }
        if (n == img.size()) {
            REQUIRE(r.has_value());
            CHECK(r->soname == "libyuzu_fixture.so.1");
        }
    }
}

TEST_CASE("elf: deterministic mutation sweep", "[binary_header][elf]") {
    std::vector<Bytes> images;
    std::vector<std::size_t> hdr_ends;
    for (const auto& sh : kShapes) {
        images.push_back(build(canonical(sh).spec));
        hdr_ends.push_back((sh.is64 ? 64 : 52) + 4 * (sh.is64 ? 56 : 32));
    }
    { // the real 64-bit little-endian capture: header plus its program-header table (e_phnum at 56)
        images.push_back(load_shared());
        hdr_ends.push_back(64 + 56 * (images.back()[56] | (images.back()[57] << 8)));
    }
    u64 state = 0x9E3779B97F4A7C15ull;
    const auto next = [&state]() { return bhtest::xorshift(state); };
    const bh::ElfLimits lim;
    const bh::ReadBudget budget;
    std::size_t ok = 0, failed_invariant = 0, first_bad = 0;
    constexpr std::size_t kMutations = 20000;
    for (std::size_t iter = 0; iter < kMutations; ++iter) {
        const std::size_t which = iter % images.size();
        Bytes img = images[which];
        const std::size_t flips = 1 + next() % 4;
        for (std::size_t f = 0; f < flips; ++f) {
            const std::size_t span_len = next() % 2 ? hdr_ends[which] : img.size();
            const std::size_t pos = next() % span_len;
            switch (next() % 4) {
            case 0: img[pos] = static_cast<std::uint8_t>(next()); break;
            case 1: img[pos] = 0xFF; break;
            case 2: img[pos] = 0; break;
            default: // saturate a whole 8-byte field so every sum is pushed toward overflow
                for (std::size_t k = 0; k < 8 && pos + k < img.size(); ++k)
                    img[pos + k] = 0xFF;
            }
        }
        Probe log(img);
        auto r = bh::read_elf(log.source());
        bool good = log.reads.size() <= budget.max_reads && log.total <= budget.max_bytes &&
                    !log.beyond_visible();
        if (r) {
            ++ok;
            good = good && r->program_headers.size() <= lim.max_program_headers &&
                   r->interpreter.size() <= lim.max_string_bytes &&
                   r->soname.size() <= lim.max_string_bytes && r->notes.size() <= lim.max_notes &&
                   r->build_id.size() <= 2 * lim.max_note_desc_bytes &&
                   (!r->dynamic_unreadable || r->soname.empty());
        }
        if (!good && failed_invariant++ == 0)
            first_bad = iter;
    }
    INFO("first violated iteration " << first_bad);
    CHECK(failed_invariant == 0);
    CHECK(ok > kMutations / 10); // the sweep must reach the derived-field code, not only reject
}

TEST_CASE("elf: real capture elf_shared.bin", "[binary_header][elf]") {
    const auto i = must_read(load_shared());
    CHECK(i.is64);
    CHECK(i.byte_order == std::endian::little);
    CHECK(i.type == 3); // ET_DYN
    CHECK(i.soname == "libyuzu_fixture.so.1");
    CHECK(i.build_id.size() == 40);
    CHECK(std::all_of(i.build_id.begin(), i.build_id.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    }));
    CHECK_FALSE(i.dynamic_unreadable);
    CHECK_FALSE(i.notes_truncated);
}
