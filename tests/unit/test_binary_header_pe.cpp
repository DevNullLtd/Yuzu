/**
 * test_binary_header_pe.cpp -- agents/shared/binary_header_pe.hpp, the bounded PE version-resource
 * reader. Pure logic over in-memory bytes: an in-test builder synthesises PE32 and PE32+ images, and
 * the real capture under tests/unit/fixtures/binary_headers/ (YUZU_TEST_FIXTURE_DIR) is asserted
 * against the strings and versions recorded in its provenance.txt. The capture test FAILS when the
 * file is missing; it never skips.
 */

#include <catch2/catch_test_macros.hpp>

#include "binary_header_test_util.hpp"

#include <binary_header_pe.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::shared::binary_header;

namespace {

using bhtest::Probe;

using Result = std::expected<PeVersionInfo, ParseError>;
using Pair = std::pair<std::u16string, std::u16string>;

// ---- byte helpers ----------------------------------------------------------------------------

void put16(std::string& s, std::uint32_t v) {
    s.push_back(static_cast<char>(v & 0xFF));
    s.push_back(static_cast<char>((v >> 8) & 0xFF));
}
void put32(std::string& s, std::uint32_t v) {
    put16(s, v & 0xFFFF);
    put16(s, v >> 16);
}
void set16(std::string& s, std::size_t off, std::uint32_t v) {
    s[off] = static_cast<char>(v & 0xFF);
    s[off + 1] = static_cast<char>((v >> 8) & 0xFF);
}
void set32(std::string& s, std::size_t off, std::uint32_t v) {
    set16(s, off, v & 0xFFFF);
    set16(s, off + 2, v >> 16);
}
void pad4(std::string& s) {
    while (s.size() % 4 != 0)
        s.push_back('\0');
}
std::string units(std::u16string_view u, bool nul) {
    std::string s;
    for (const char16_t c : u)
        put16(s, c);
    if (nul)
        put16(s, 0);
    return s;
}
std::span<const std::byte> as_span(const std::string& s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}
std::string ascii(std::u16string_view u) {
    std::string s;
    for (const char16_t c : u)
        s.push_back(static_cast<char>(c));
    return s;
}

// ---- VS_VERSIONINFO builder --------------------------------------------------------------------

struct TableSpec {
    std::uint16_t lang{0x409};
    std::uint16_t cp{1200};
    std::vector<Pair> strings;
};

struct VerSpec {
    bool fixed{true};
    std::array<std::uint16_t, 4> fv{1, 2, 3, 4};
    std::array<std::uint16_t, 4> pv{5, 6, 7, 8};
    std::vector<TableSpec> tables;
    std::vector<std::array<std::uint16_t, 2>> translations; // {language, code page}
    bool no_nul_first_string{false}; // first String's text has no NUL inside its node
};

std::string node(std::u16string_view key, std::uint16_t type, std::string_view value,
                 std::size_t wvalue_len, std::string_view children) {
    std::string n;
    put16(n, 0);
    put16(n, static_cast<std::uint32_t>(wvalue_len));
    put16(n, type);
    n += units(key, true);
    pad4(n);
    n += value;
    if (!children.empty()) {
        pad4(n);
        n += children;
    }
    set16(n, 0, static_cast<std::uint32_t>(n.size()));
    return n;
}

std::string join(const std::vector<std::string>& nodes) {
    std::string out;
    for (const auto& n : nodes) {
        if (!out.empty())
            pad4(out);
        out += n;
    }
    return out;
}

std::string build_version(const VerSpec& v) {
    std::vector<std::string> kids;
    if (!v.tables.empty()) {
        std::vector<std::string> tabs;
        for (const auto& t : v.tables) {
            std::vector<std::string> strs;
            bool first = true;
            for (const auto& [k, val] : t.strings) {
                const bool nonul = v.no_nul_first_string && first;
                first = false;
                strs.push_back(node(k, 1, units(val, !nonul), val.size() + (nonul ? 0 : 1), ""));
            }
            std::u16string key;
            for (const char c : std::format("{:04x}{:04x}", t.lang, t.cp))
                key.push_back(static_cast<char16_t>(c));
            tabs.push_back(node(key, 1, "", 0, join(strs)));
        }
        kids.push_back(node(u"StringFileInfo", 1, "", 0, join(tabs)));
    }
    if (!v.translations.empty()) {
        std::string bytes;
        for (const auto& [lang, cp] : v.translations) {
            put16(bytes, lang);
            put16(bytes, cp);
        }
        kids.push_back(node(u"VarFileInfo", 1, "", 0, node(u"Translation", 0, bytes, bytes.size(), "")));
    }
    std::string fixed;
    if (v.fixed) {
        put32(fixed, 0xFEEF04BDu);
        put32(fixed, 0x10000);
        put32(fixed, (std::uint32_t{v.fv[0]} << 16) | v.fv[1]);
        put32(fixed, (std::uint32_t{v.fv[2]} << 16) | v.fv[3]);
        put32(fixed, (std::uint32_t{v.pv[0]} << 16) | v.pv[1]);
        put32(fixed, (std::uint32_t{v.pv[2]} << 16) | v.pv[3]);
        while (fixed.size() < 52)
            put32(fixed, 0x3F);
    }
    return node(u"VS_VERSION_INFO", 0, fixed, fixed.size(), join(kids));
}

const std::vector<Pair> kRcStrings = {
    {u"CompanyName", u"Yuzu Fixture Co"},
    {u"FileDescription", u"Yuzu binary header fixture"},
    {u"FileVersion", u"1.2.3.4"},
    {u"InternalName", u"yuzu_fixture"},
    {u"OriginalFilename", u"yuzu_fixture.dll"},
    {u"ProductName", u"Yuzu Fixture"},
    {u"ProductVersion", u"5.6.7.8"},
    {u"LegalCopyright", u"(c) Yuzu Fixture"},
};

VerSpec canonical_spec() {
    VerSpec v;
    v.tables.push_back({0x409, 1200, kRcStrings});
    v.translations.push_back({0x409, 1200});
    return v;
}

// ---- PE image builder -----------------------------------------------------------------------------

struct ImageSpec {
    bool plus{false};
    bool rsrc{true};              // false: no resource directory at all
    std::uint32_t rt_id{16};      // the root's only ID entry
    std::string blob;             // the version data
    std::size_t extra_sections{0}; // empty sections ahead of .rsrc
    std::size_t trailer{0};       // bytes after the .rsrc raw data, still inside the file
};

struct Layout {
    std::size_t lfanew{0x40};
    std::size_t coff{0x44};
    std::size_t opt{0x58};
    std::size_t opt_size{0};
    std::size_t sec_table{0};
    std::size_t rsrc_hdr{0};
    std::size_t raw{0};
    std::size_t dd2{0};
    std::size_t nsec{0};
    std::uint32_t rva{0x3000};
    std::uint32_t res_size{0};
    // file offsets of the fixed three-level resource layout
    std::size_t root_hdr{0}, root_entry{0}, l2_hdr{0}, l2_entry{0}, l3_hdr{0}, l3_entry{0},
        data_entry{0}, blob{0};
};

struct Image {
    std::string bytes;
    Layout L;
};

Image build_image(const ImageSpec& s) {
    Layout L;
    const std::size_t nrva_off = s.plus ? 108 : 92;
    const std::size_t dirs_off = nrva_off + 4;
    L.opt_size = dirs_off + 16 * 8;
    L.nsec = s.extra_sections + (s.rsrc ? 1 : 0);
    L.sec_table = L.opt + L.opt_size;
    L.rsrc_hdr = L.sec_table + s.extra_sections * 40;
    L.raw = (L.sec_table + L.nsec * 40 + 0x1FF) & ~std::size_t{0x1FF};
    L.dd2 = L.opt + dirs_off + 16;
    L.root_hdr = L.raw;
    L.root_entry = L.raw + 16;
    L.l2_hdr = L.raw + 24;
    L.l2_entry = L.raw + 40;
    L.l3_hdr = L.raw + 48;
    L.l3_entry = L.raw + 64;
    L.data_entry = L.raw + 72;
    L.blob = L.raw + 88;
    L.res_size = static_cast<std::uint32_t>(88 + s.blob.size());

    std::string img(64, '\0');
    img[0] = 'M';
    img[1] = 'Z';
    set32(img, 0x3C, 0x40);
    img.append("PE\0\0", 4);
    put16(img, s.plus ? 0x8664 : 0x14C);
    put16(img, static_cast<std::uint32_t>(L.nsec));
    put32(img, 0);
    put32(img, 0);
    put32(img, 0);
    put16(img, static_cast<std::uint32_t>(L.opt_size));
    put16(img, 0x2000);
    std::string opt(L.opt_size, '\0');
    set16(opt, 0, s.plus ? 0x20B : 0x10B);
    set32(opt, nrva_off, 16);
    if (s.rsrc) {
        set32(opt, dirs_off + 16, L.rva);
        set32(opt, dirs_off + 20, L.res_size);
    }
    img += opt;
    const auto section = [&](std::uint32_t va, std::uint32_t raw_size, std::uint32_t raw_ptr) {
        std::string h(8, '\0');
        put32(h, raw_size);
        put32(h, va);
        put32(h, raw_size);
        put32(h, raw_ptr);
        h.resize(40, '\0');
        img += h;
    };
    for (std::size_t i = 0; i < s.extra_sections; ++i)
        section(static_cast<std::uint32_t>(0x100000 + i * 0x1000), 0, 0);
    if (s.rsrc)
        section(L.rva, L.res_size, static_cast<std::uint32_t>(L.raw));
    img.resize(L.raw, '\0');
    if (s.rsrc) {
        const auto dir_hdr = [&](std::uint32_t named, std::uint32_t ids) {
            put32(img, 0);
            put32(img, 0);
            put32(img, 0);
            put16(img, named);
            put16(img, ids);
        };
        dir_hdr(0, 1);
        put32(img, s.rt_id);
        put32(img, 0x80000000u | 24);
        dir_hdr(0, 1);
        put32(img, 1);
        put32(img, 0x80000000u | 48);
        dir_hdr(0, 1);
        put32(img, 0x409);
        put32(img, 72);
        put32(img, L.rva + 88);
        put32(img, static_cast<std::uint32_t>(s.blob.size()));
        put32(img, 0);
        put32(img, 0);
        img += s.blob;
    }
    img.append(s.trailer, 'A');
    return {std::move(img), L};
}

Image canonical_image(bool plus) {
    ImageSpec s;
    s.plus = plus;
    s.blob = build_version(canonical_spec());
    return build_image(s);
}

Result parse(const std::string& img, const PeLimits& lim = {}, ReadBudget b = {}) {
    return read_pe_version(span_source(as_span(img)), lim, b);
}

ParseError error_of(const Result& r) {
    REQUIRE(!r.has_value());
    return r.error();
}

// Offset of the node whose key is `key`: its 6-byte header sits just before the key.
std::size_t node_off(const std::string& blob, std::u16string_view key) {
    const auto at = blob.find(units(key, true));
    REQUIRE(at != std::string::npos);
    return at - 6;
}
std::size_t wlen_of(const std::string& blob, std::size_t off) {
    const auto lo = static_cast<std::uint8_t>(blob[off]);
    const auto hi = static_cast<std::uint8_t>(blob[off + 1]);
    return static_cast<std::size_t>(lo) | (static_cast<std::size_t>(hi) << 8);
}

std::vector<std::pair<std::string, std::string>> expected_pairs() {
    std::vector<std::pair<std::string, std::string>> v;
    for (const auto& [k, val] : kRcStrings)
        v.emplace_back(ascii(k), ascii(val));
    return v;
}

void check_canonical_values(const PeVersionInfo& v) {
    CHECK(v.has_version);
    CHECK(v.has_fixed);
    CHECK(v.file_version == std::array<std::uint16_t, 4>{1, 2, 3, 4});
    CHECK(v.product_version == std::array<std::uint16_t, 4>{5, 6, 7, 8});
    REQUIRE(v.string_tables.size() == 1);
    CHECK(v.string_tables[0].language == 0x409);
    CHECK(v.string_tables[0].code_page == 1200);
    auto got = v.string_tables[0].strings;
    auto want = expected_pairs();
    CHECK(got.size() == 8);
    std::sort(got.begin(), got.end());
    std::sort(want.begin(), want.end());
    CHECK(got == want);
    REQUIRE(v.translations.size() == 1);
    CHECK(v.translations[0] == std::pair{std::uint16_t{0x409}, std::uint16_t{1200}});
}

} // namespace

// ---- UTF-16 -> UTF-8 -------------------------------------------------------------------------------------

TEST_CASE("binary_header_pe: utf16_to_utf8", "[binary_header][pe]") {
    CHECK(utf16_to_utf8(u"abc") == "abc");
    CHECK(utf16_to_utf8(u"é") == "\xC3\xA9");
    CHECK(utf16_to_utf8(u"€") == "\xE2\x82\xAC");
    CHECK(utf16_to_utf8(u"\U0001F600") == "\xF0\x9F\x98\x80");
    CHECK(utf16_to_utf8(std::u16string{char16_t{0xD800}}) == "\xEF\xBF\xBD");               // lone high
    CHECK(utf16_to_utf8(std::u16string{char16_t{0xDC00}}) == "\xEF\xBF\xBD");               // lone low
    CHECK(utf16_to_utf8(std::u16string{char16_t{0xD800}, u'a'}) == "\xEF\xBF\xBD" "a"); // high then text
    CHECK(utf16_to_utf8(std::u16string{char16_t{0xDC00}, char16_t{0xD800}}) == "\xEF\xBF\xBD\xEF\xBF\xBD");
    CHECK(utf16_to_utf8(u"").empty());
}

// ---- synthesised images -------------------------------------------------------------------------------

TEST_CASE("binary_header_pe: PE32 and PE32+ builder images parse to the exact values",
          "[binary_header][pe]") {
    for (const bool plus : {false, true}) {
        INFO("pe32_plus=" << plus);
        const auto img = canonical_image(plus);
        auto r = parse(img.bytes);
        REQUIRE(r.has_value());
        CHECK(r->pe32_plus == plus);
        CHECK(r->machine == (plus ? 0x8664 : 0x14C));
        check_canonical_values(*r);
    }
}

TEST_CASE("binary_header_pe: strings are UTF-8 and an unpaired surrogate becomes U+FFFD",
          "[binary_header][pe]") {
    VerSpec v;
    v.fixed = false;
    v.tables.push_back({0x407, 1252,
                        {{u"A", std::u16string{u'é', char16_t{0xD83D}, char16_t{0xDE00}}},
                         {u"B", std::u16string{char16_t{0xDC00}}}}});
    ImageSpec s;
    s.blob = build_version(v);
    auto r = parse(build_image(s).bytes);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->has_fixed);
    REQUIRE(r->string_tables.size() == 1);
    CHECK(r->string_tables[0].language == 0x407);
    CHECK(r->string_tables[0].code_page == 1252);
    REQUIRE(r->string_tables[0].strings.size() == 2);
    CHECK(r->string_tables[0].strings[0].second == "\xC3\xA9\xF0\x9F\x98\x80");
    CHECK(r->string_tables[0].strings[1].second == "\xEF\xBF\xBD");
}

TEST_CASE("binary_header_pe: several tables, translations and an empty value", "[binary_header][pe]") {
    VerSpec v;
    v.tables.push_back({0x409, 1200, {{u"K1", u"v1"}, {u"K2", u""}}});
    v.tables.push_back({0x407, 1252, {{u"K3", u"v3"}}});
    v.translations = {{0x409, 1200}, {0x407, 1252}};
    ImageSpec s;
    s.blob = build_version(v);
    auto r = parse(build_image(s).bytes);
    REQUIRE(r.has_value());
    REQUIRE(r->string_tables.size() == 2);
    CHECK(r->string_tables[0].strings[1] == std::pair<std::string, std::string>{"K2", ""});
    CHECK(r->string_tables[1].language == 0x407);
    CHECK(r->translations.size() == 2);
    CHECK(r->translations[1] == std::pair{std::uint16_t{0x407}, std::uint16_t{1252}});
}

TEST_CASE("binary_header_pe: no resource directory, or no RT_VERSION, is a value",
          "[binary_header][pe]") {
    for (const bool plus : {false, true}) {
        ImageSpec none;
        none.plus = plus;
        none.rsrc = false;
        auto a = parse(build_image(none).bytes);
        REQUIRE(a.has_value());
        CHECK_FALSE(a->has_version);
        CHECK(a->pe32_plus == plus);

        ImageSpec icon;
        icon.plus = plus;
        icon.rt_id = 3; // RT_ICON, not RT_VERSION
        icon.blob = build_version(canonical_spec());
        auto b = parse(build_image(icon).bytes);
        REQUIRE(b.has_value());
        CHECK_FALSE(b->has_version);
        CHECK(b->string_tables.empty());
    }
}

TEST_CASE("binary_header_pe: not a PE, and an MZ file cut before its PE header",
          "[binary_header][pe]") {
    CHECK(error_of(parse("")) == ParseError::not_this_format);
    CHECK(error_of(parse("M")) == ParseError::not_this_format);
    CHECK(error_of(parse("MZ")) == ParseError::truncated);
    CHECK(error_of(parse(canonical_image(false).bytes.substr(0, 0x40))) == ParseError::truncated);
    CHECK(error_of(parse(std::string(64, 'x'))) == ParseError::not_this_format);
    auto img = canonical_image(false).bytes;
    img[0x40] = 'X'; // MZ but no PE signature
    CHECK(error_of(parse(img)) == ParseError::not_this_format);
    auto bad_magic = canonical_image(false);
    set16(bad_magic.bytes, bad_magic.L.opt, 0x107);
    CHECK(error_of(parse(bad_magic.bytes)) == ParseError::malformed);
}

TEST_CASE("binary_header_pe: a String's wValueLength is ignored: the value is the NUL-terminated "
          "text inside wLength",
          "[binary_header][pe]") {
    const std::string blob = build_version(canonical_spec());
    ImageSpec base;
    base.blob = blob;
    const auto want = parse(build_image(base).bytes);
    REQUIRE(want.has_value());
    for (const std::uint32_t v : {0u, 16u, 32u, 0xFFFFu}) {
        INFO(v);
        ImageSpec s;
        s.blob = blob;
        set16(s.blob, node_off(s.blob, u"CompanyName") + 2, v);
        const auto got = parse(build_image(s).bytes);
        REQUIRE(got.has_value());
        CHECK(got->string_tables[0].strings == want->string_tables[0].strings);
    }
}

TEST_CASE("binary_header_pe: competing resource entries select the first ID entry 16 and each "
          "level's first entry",
          "[binary_header][pe]") {
    constexpr std::uint32_t kSub = 0x80000000u;
    const std::string ver = build_version(canonical_spec());
    std::string pre; // after the fixed 88 bytes: level 2 at 88, level 3 at 120, data entry at 152
    for (const std::uint32_t w : {0u, 0u, 0u, 2u << 16, 1u, kSub | 120, 2u, 72u, // level 2
                                  0u, 0u, 0u, 2u << 16, 0x409u, 152u, 0x407u, kSub | 88,
                                  Layout{}.rva + 168, static_cast<std::uint32_t>(ver.size()), 0u,
                                  0u})
        put32(pre, w);
    ImageSpec s;
    s.blob = pre + ver;
    auto img = build_image(s);
    set16(img.bytes, img.L.root_hdr + 12, 1); // one named + three ID entries, 16 at slot 0 named
    set16(img.bytes, img.L.root_hdr + 14, 3);
    std::string root;
    for (const std::uint32_t w : {16u, 72u, 3u, kSub | 0x7FFFFFF0u, 16u, kSub | 88, 16u,
                                  kSub | 0x7FFFFFF0u})
        put32(root, w);
    img.bytes.replace(img.L.root_entry, root.size(), root);
    const auto r = parse(img.bytes);
    REQUIRE(r.has_value());
    check_canonical_values(*r);
}

// ---- the real capture ------------------------------------------------------------------------------------

TEST_CASE("binary_header_pe: the real capture pe_version.bin", "[binary_header][pe]") {
    const auto bytes = bhtest::load_fixture("pe_version.bin");
    auto r = parse(bytes);
    REQUIRE(r.has_value());
    CHECK(r->machine == 0x8664);
    CHECK(r->pe32_plus);
    check_canonical_values(*r);
}

// ---- caps: at the limit accepted, one over limit_exceeded ----------------------------------------

TEST_CASE("binary_header_pe: every cap is exact", "[binary_header][pe]") {
    const auto img = canonical_image(false);
    const auto want = [&](PeLimits l, bool ok) {
        const auto r = parse(img.bytes, l);
        if (ok)
            CHECK(r.has_value());
        else {
            REQUIRE(!r.has_value());
            CHECK(r.error() == ParseError::limit_exceeded);
        }
    };

    SECTION("sections") {
        PeLimits l;
        l.max_sections = 1;
        want(l, true);
        l.max_sections = 0;
        want(l, false);

        ImageSpec s;
        s.blob = build_version(canonical_spec());
        s.extra_sections = 95; // 96 sections in all
        CHECK(parse(build_image(s).bytes).has_value());
        s.extra_sections = 96; // 97
        CHECK(error_of(parse(build_image(s).bytes)) == ParseError::limit_exceeded);
    }
    SECTION("directory entries") {
        PeLimits l;
        l.max_dir_entries = 1;
        want(l, true);
        l.max_dir_entries = 0;
        want(l, false);
        // Named + ID entries are summed: 4096 passes the cap (and then fails the size check),
        // 4097 is over it.
        auto at = img;
        set16(at.bytes, at.L.root_hdr + 12, 4095);
        CHECK(error_of(parse(at.bytes)) == ParseError::malformed);
        set16(at.bytes, at.L.root_hdr + 12, 4096);
        CHECK(error_of(parse(at.bytes)) == ParseError::limit_exceeded);
    }
    SECTION("version bytes") {
        PeLimits l;
        l.max_version_bytes = build_version(canonical_spec()).size();
        want(l, true);
        --l.max_version_bytes;
        want(l, false);
    }
    SECTION("nodes") {
        // root + StringFileInfo + table + 8 strings + VarFileInfo + Translation
        PeLimits l;
        l.max_nodes = 13;
        want(l, true);
        l.max_nodes = 12;
        want(l, false);
    }
    SECTION("string tables and strings per table") {
        VerSpec v = canonical_spec();
        v.tables.push_back({0x407, 1252, {{u"K", u"v"}}});
        ImageSpec s;
        s.blob = build_version(v);
        const auto two = build_image(s);
        PeLimits l;
        l.max_string_tables = 2;
        CHECK(parse(two.bytes, l).has_value());
        l.max_string_tables = 1;
        CHECK(error_of(parse(two.bytes, l)) == ParseError::limit_exceeded);

        PeLimits p;
        p.max_strings_per_table = 8;
        want(p, true);
        p.max_strings_per_table = 7;
        want(p, false);
    }
    SECTION("key and value length") {
        std::size_t longest_key = std::string_view("VS_VERSION_INFO").size();
        std::size_t longest_value = 0;
        for (const auto& [k, val] : kRcStrings) {
            longest_key = std::max(longest_key, k.size());
            longest_value = std::max(longest_value, val.size());
        }
        PeLimits l;
        l.max_key_units = longest_key;
        want(l, true);
        l.max_key_units = longest_key - 1;
        want(l, false);
        PeLimits p;
        p.max_value_units = longest_value;
        want(p, true);
        p.max_value_units = longest_value - 1;
        want(p, false);
    }
    SECTION("read budget") {
        const auto r1 = parse(img.bytes, {}, ReadBudget{4ull * 1024 * 1024, 1});
        REQUIRE(!r1.has_value());
        CHECK(r1.error() == ParseError::limit_exceeded);
        const auto r2 = parse(img.bytes, {}, ReadBudget{64, 4096});
        REQUIRE(!r2.has_value());
        CHECK(r2.error() == ParseError::limit_exceeded);
    }
}

// ---- hostile offsets and sizes ---------------------------------------------------------------------

TEST_CASE("binary_header_pe: offsets and sizes near UINT32_MAX never read out of range",
          "[binary_header][pe]") {
    const auto good = canonical_image(false);
    struct Case {
        const char* name;
        std::function<void(Image&)> patch;
        ParseError expect;
    };
    const std::uint32_t max32 = 0xFFFFFFFFu;
    // A SizeOfOptionalHeader past the end of the file is truncated whether or not the image has a
    // resource directory; with none, the early "no version" return must not hide it.
    for (const bool rsrc : {false, true}) {
        ImageSpec spec;
        spec.rsrc = rsrc;
        auto img = build_image(spec);
        set16(img.bytes, img.L.coff + 16, 0xFFFF);
        INFO("resource directory present: " << rsrc);
        const auto r = parse(img.bytes);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ParseError::truncated);
    }
    const std::vector<Case> cases = {
        {"e_lfanew", [&](Image& i) { set32(i.bytes, 0x3C, max32); }, ParseError::truncated},
        {"sections count", [&](Image& i) { set16(i.bytes, i.L.coff + 2, 0xFFFF); },
         ParseError::limit_exceeded},
        {"optional header size", [&](Image& i) { set16(i.bytes, i.L.coff + 16, 0xFFFF); },
         ParseError::truncated},
        {"RVA in no section", [&](Image& i) { set32(i.bytes, i.L.dd2, 0xFFFFFFF0u); },
         ParseError::malformed},
        {"RVA below every section", [&](Image& i) { set32(i.bytes, i.L.dd2, 0x10); },
         ParseError::malformed},
        {"directory size UINT32_MAX", [&](Image& i) { set32(i.bytes, i.L.dd2 + 4, max32); },
         ParseError::malformed},
        {"directory RVA and size UINT32_MAX",
         [&](Image& i) {
             set32(i.bytes, i.L.dd2, max32);
             set32(i.bytes, i.L.dd2 + 4, max32);
         },
         ParseError::malformed},
        {"PointerToRawData UINT32_MAX", [&](Image& i) { set32(i.bytes, i.L.rsrc_hdr + 20, max32); },
         ParseError::truncated},
        {"entry points outside the directory",
         [&](Image& i) { set32(i.bytes, i.L.root_entry + 4, 0x80000000u | 0x7FFFFFFFu); },
         ParseError::malformed},
        {"level 2 entry outside", [&](Image& i) { set32(i.bytes, i.L.l2_entry + 4, 0x80000000u | 0x10000u); },
         ParseError::malformed},
        {"level 3 entry outside", [&](Image& i) { set32(i.bytes, i.L.l3_entry + 4, 0x7FFFFFFFu); },
         ParseError::malformed},
        {"data RVA UINT32_MAX", [&](Image& i) { set32(i.bytes, i.L.data_entry, max32); },
         ParseError::malformed},
        {"data size UINT32_MAX", [&](Image& i) { set32(i.bytes, i.L.data_entry + 4, max32); },
         ParseError::limit_exceeded},
        {"data size 0", [&](Image& i) { set32(i.bytes, i.L.data_entry + 4, 0); }, ParseError::malformed},
        {"level 1 entry is a data entry", [&](Image& i) { set32(i.bytes, i.L.root_entry + 4, 72); },
         ParseError::malformed},
        {"level 2 entry is a data entry", [&](Image& i) { set32(i.bytes, i.L.l2_entry + 4, 72); },
         ParseError::malformed},
        {"level 3 entry is a subdirectory",
         [&](Image& i) { set32(i.bytes, i.L.l3_entry + 4, 0x80000000u | 24); }, ParseError::malformed},
        {"level 2 has no entry", [&](Image& i) { set16(i.bytes, i.L.l2_hdr + 14, 0); },
         ParseError::malformed},
        {"level 3 has no entry", [&](Image& i) { set16(i.bytes, i.L.l3_hdr + 14, 0); },
         ParseError::malformed},
    };
    for (const auto& c : cases) {
        INFO(c.name);
        Image img = good;
        c.patch(img);
        Probe p(img.bytes);
        const auto r = read_pe_version(p.source());
        REQUIRE(!r.has_value());
        CHECK(r.error() == c.expect);
        CHECK(p.max_end <= img.bytes.size());
    }
}

TEST_CASE("binary_header_pe: version tree grammar violations are malformed", "[binary_header][pe]") {
    const auto good = canonical_image(false);
    const std::size_t b = good.L.blob;
    struct Case {
        const char* name;
        std::function<void(Image&)> patch;
    };
    const std::vector<Case> cases = {
        {"root wLength past the data",
         [&](Image& i) { set16(i.bytes, b, static_cast<std::uint32_t>(i.bytes.size())); }},
        {"root wLength under a header", [&](Image& i) { set16(i.bytes, b, 4); }},
        {"root key", [&](Image& i) { set16(i.bytes, b + 6, 'X'); }},
        {"fixed signature", [&](Image& i) { set32(i.bytes, b + 40, 0x12345678u); }},
        {"fixed length under 52", [&](Image& i) { set16(i.bytes, b + 2, 20); }},
        {"fixed length past the root", [&](Image& i) { set16(i.bytes, b + 2, 0xFFFF); }},
        {"Translation length past its node",
         [&](Image& i) { set16(i.bytes, node_off(i.bytes, u"Translation") + 2, 0xFFFF); }},
        {"child wLength under a header", [&](Image& i) { set16(i.bytes, b + 92, 4); }},
        {"child wLength past the parent", [&](Image& i) { set16(i.bytes, b + 92, 0xFFFF); }},
    };
    for (const auto& c : cases) {
        INFO(c.name);
        Image img = good;
        c.patch(img);
        CHECK(error_of(parse(img.bytes)) == ParseError::malformed);
    }
}

// Each fixture shortens one node's wLength by 4 so its LAST child ends past the parent but inside the
// grandparent and the version buffer; nothing else is wrong, and no sibling follows the parent that
// could turn a whole-buffer check into an error by accident. Confinement to the immediate parent is
// the only thing that rejects these.
TEST_CASE("binary_header_pe: a child crossing only its immediate parent is malformed",
          "[binary_header][pe]") {
    struct Case {
        const char* name;
        bool var_info;                  // append a VarFileInfo sibling after StringFileInfo
        std::u16string_view parent_key; // the node whose wLength is shortened
        std::u16string_view child_key;  // its last child, which then crosses the parent's end
    };
    const Case cases[] = {
        {"String past its StringTable", true, u"040704e4", u"K4"},
        {"StringTable past its StringFileInfo", false, u"StringFileInfo", u"040704e4"},
        {"Var past its VarFileInfo", true, u"VarFileInfo", u"Translation"},
    };
    for (const auto& c : cases) {
        INFO(c.name);
        VerSpec v;
        v.tables.push_back({0x409, 1200, {{u"K1", u"v1"}, {u"K2", u"v2"}}});
        v.tables.push_back({0x407, 1252, {{u"K3", u"v3"}, {u"K4", u"v4"}}});
        if (c.var_info)
            v.translations = {{0x409, 1200}};
        ImageSpec s;
        s.blob = build_version(v);
        REQUIRE(parse(build_image(s).bytes).has_value()); // the unmodified tree is fine

        const auto parent = node_off(s.blob, c.parent_key);
        const auto child = node_off(s.blob, c.child_key);
        const auto parent_end = parent + wlen_of(s.blob, parent);
        const auto child_end = child + wlen_of(s.blob, child);
        REQUIRE(child_end == parent_end); // the child is the parent's last, ending exactly with it
        set16(s.blob, parent, static_cast<std::uint32_t>(parent_end - parent - 4));
        // The child now ends 4 bytes past its parent, still inside the version buffer.
        REQUIRE(child_end > parent + wlen_of(s.blob, parent));
        REQUIRE(child_end <= s.blob.size());
        CHECK(error_of(parse(build_image(s).bytes)) == ParseError::malformed);
    }
}

// ---- adjacent bytes ----------------------------------------------------------------------------------------

TEST_CASE("binary_header_pe: a version Size one byte past its section is malformed and unread",
          "[binary_header][pe]") {
    ImageSpec s;
    s.blob = build_version(canonical_spec());
    s.trailer = 64; // bytes exist in the file after the section: a file-bound-only reader would use them
    auto img = build_image(s);
    set32(img.bytes, img.L.data_entry + 4, static_cast<std::uint32_t>(s.blob.size() + 1));
    Probe p(img.bytes);
    const auto r = read_pe_version(p.source());
    REQUIRE(!r.has_value());
    CHECK(r.error() == ParseError::malformed);
    CHECK(p.max_end <= img.L.blob); // the version data was never read
}

TEST_CASE("binary_header_pe: a directory entry straddling the declared size is malformed and unread",
          "[binary_header][pe]") {
    ImageSpec s;
    s.blob = build_version(canonical_spec());
    s.trailer = 64;
    {
        auto img = build_image(s);
        set32(img.bytes, img.L.dd2 + 4, 20); // header (16) fits; the entry's 8 bytes would end at 24
        Probe p(img.bytes);
        const auto r = read_pe_version(p.source());
        REQUIRE(!r.has_value());
        CHECK(r.error() == ParseError::malformed);
        CHECK(p.max_end <= img.L.raw + 16);
    }
    {
        auto img = build_image(s);
        // A level 2 header that starts 8 bytes before the declared end.
        set32(img.bytes, img.L.root_entry + 4, 0x80000000u | (img.L.res_size - 8));
        Probe p(img.bytes);
        const auto r = read_pe_version(p.source());
        REQUIRE(!r.has_value());
        CHECK(r.error() == ParseError::malformed);
        CHECK(p.max_end <= img.L.raw + 24);
    }
}

TEST_CASE("binary_header_pe: a String with no NUL inside its node is malformed", "[binary_header][pe]") {
    VerSpec v;
    v.no_nul_first_string = true;
    v.tables.push_back({0x409, 1200, {{u"A", u"abc"}, {u"B", u"def"}}});
    ImageSpec s;
    s.blob = build_version(v);
    s.trailer = 64;
    const auto img = build_image(s);
    Probe p(img.bytes);
    const auto r = read_pe_version(p.source());
    REQUIRE(!r.has_value());
    CHECK(r.error() == ParseError::malformed);
    // The padding after the unterminated text is zero bytes inside the file: it must not terminate it.
    REQUIRE(!p.reads.empty());
    CHECK(p.reads.back() == std::pair<std::uint64_t, std::size_t>{img.L.blob, s.blob.size()});
    CHECK(p.max_end <= img.L.blob + s.blob.size());
}

// A String whose node ends exactly where its value would begin carries no NUL at all. It is not the
// same as an empty String, which is a lone NUL (two value bytes).
TEST_CASE("binary_header_pe: a String with zero value bytes is malformed, a lone NUL is empty",
          "[binary_header][pe]") {
    for (const bool zero_bytes : {true, false}) {
        INFO((zero_bytes ? "zero value bytes" : "lone NUL"));
        VerSpec v;
        v.no_nul_first_string = zero_bytes; // with an empty value this leaves no value bytes at all
        v.tables.push_back({0x409, 1200, {{u"A", u""}, {u"B", u"def"}}});
        ImageSpec s;
        s.blob = build_version(v);
        s.trailer = 64;
        const auto img = build_image(s);
        // The first String's node ends exactly at its padded value offset (header 6 + "A\0" -> 12).
        const auto a = node_off(s.blob, u"A");
        CHECK(wlen_of(s.blob, a) == (zero_bytes ? 12u : 14u));
        const auto r = parse(img.bytes);
        if (zero_bytes) {
            CHECK(error_of(r) == ParseError::malformed);
        } else {
            REQUIRE(r.has_value());
            REQUIRE(r->string_tables.size() == 1);
            REQUIRE(r->string_tables[0].strings.size() == 2);
            CHECK(r->string_tables[0].strings[0] == std::pair<std::string, std::string>{"A", ""});
            CHECK(r->string_tables[0].strings[1] == std::pair<std::string, std::string>{"B", "def"});
        }
    }
}

// ---- read_at failures -------------------------------------------------------------------------------------

TEST_CASE("binary_header_pe: read_at returning nullopt at any call index surfaces as io",
          "[binary_header][pe]") {
    const auto img = canonical_image(false);
    Probe count(img.bytes);
    REQUIRE(read_pe_version(count.source()).has_value());
    REQUIRE(count.calls > 5);
    for (std::size_t k = 0; k < count.calls; ++k) {
        INFO("failing call " << k);
        Probe p(img.bytes);
        p.fail_at = k;
        const auto r = read_pe_version(p.source());
        REQUIRE(!r.has_value());
        CHECK(r.error() == ParseError::io);
    }
}

// ---- sweeps ------------------------------------------------------------------------------------------------

namespace {

std::vector<std::pair<std::string, std::string>> sweep_fixtures() {
    return {{"synth-pe32", canonical_image(false).bytes},
            {"synth-pe32plus", canonical_image(true).bytes},
            {"real", bhtest::load_fixture("pe_version.bin")}};
}

} // namespace

TEST_CASE("binary_header_pe: truncation sweep", "[binary_header][pe]") {
    const ReadBudget budget;
    for (const auto& [name, bytes] : sweep_fixtures()) {
        INFO(name);
        std::size_t over_prefix = 0, over_budget = 0;
        Probe p(bytes);
        for (std::size_t len = 0; len <= bytes.size(); ++len) {
            p.reset();
            p.visible = len;
            (void)read_pe_version(p.source());
            if (p.beyond_visible())
                ++over_prefix;
            if (p.total > budget.max_bytes || p.calls > budget.max_reads)
                ++over_budget;
        }
        CHECK(over_prefix == 0);
        CHECK(over_budget == 0);
        Probe whole(bytes);
        CHECK(read_pe_version(whole.source()).has_value());
    }
}

TEST_CASE("binary_header_pe: mutation sweep", "[binary_header][pe]") {
    const ReadBudget budget;
    std::uint64_t rng = 0x9E3779B97F4A7C15ull;
    // 20,000 mutations in total, round-robin over the fixtures.
    const auto fixtures = sweep_fixtures();
    std::size_t over_budget = 0, out_of_range = 0;
    const std::array<char, 4> favourites = {'\x00', '\xFF', '\x80', '\x7F'};
    for (std::size_t i = 0; i < 20000; ++i) {
        std::string m = fixtures[i % fixtures.size()].second;
        const int edits = 1 + static_cast<int>(bhtest::xorshift(rng) % 2);
        for (int e = 0; e < edits; ++e) {
            const std::size_t pos = static_cast<std::size_t>(bhtest::xorshift(rng) % m.size());
            const std::uint64_t pick = bhtest::xorshift(rng);
            m[pos] = (pick & 3) == 0 ? static_cast<char>(pick >> 8) : favourites[(pick >> 8) & 3];
        }
        Probe p(std::move(m));
        (void)read_pe_version(p.source());
        if (p.total > budget.max_bytes || p.calls > budget.max_reads)
            ++over_budget;
        if (p.beyond_visible())
            ++out_of_range;
    }
    CHECK(over_budget == 0);
    CHECK(out_of_range == 0);
}
