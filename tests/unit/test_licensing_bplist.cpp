/**
 * test_licensing_bplist.cpp -- licensing_bplist.hpp (SAM.10), the bounded
 * top-level string lookup that lets the license_scan macOS leg read the
 * identity of a binary (bplist00) Info.plist.
 *
 * Sections, each labelled by what its inputs are:
 *   1. REAL CAPTURES: three Info.plist files copied byte-for-byte from this
 *      Mac (tests/unit/fixtures/software-estate/license_scan/macos/README.md
 *      records host, date, command and the `plutil -extract` values the
 *      expectations below equal).
 *   2. SYNTHETIC images built by the helpers below. Labelled SYNTHETIC: they
 *      prove the decoder over widths and string kinds the three captures do not
 *      cover, not what Apple's writer emits.
 *   3. HOSTILE corpus: every structural defect must give nullopt for the
 *      WHOLE lookup, never a partial answer.
 *   4. WRAP vectors (peer review R2): every attacker-controlled u64 (offset,
 *      count, length, reference, table position) set to values near UINT64_MAX
 *      or 2^63, placed so a naive `start + length <= end` check would wrap and
 *      pass. All must be nullopt; they are the cases the sanitizer legs watch.
 *   5. BOUNDARY (mutation-proof) cases: exactly-at-cap accepted, one past
 *      rejected, so loosening or tightening a cap by one turns a test red.
 *   6. A deterministic byte-flip / truncation sweep over a real capture:
 *      no crash, and anything returned is well-formed UTF-8.
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <licensing_bplist.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using yuzu::license_scan::bplist_string_for_key;
using yuzu::license_scan::kBplistMaxObjects;
using yuzu::license_scan::kBplistMaxStringBytes;

namespace {

using Bytes = std::vector<std::uint8_t>;
constexpr std::uint64_t kMax64 = ~std::uint64_t{0};
constexpr std::uint64_t kBit63 = std::uint64_t{1} << 63;

// ── real fixtures ──────────────────────────────────────────────────────────

Bytes read_fixture(const char* name) {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "license_scan" /
                       "macos" / name;
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    Bytes out((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    REQUIRE_FALSE(out.empty());
    return out;
}

std::optional<std::string> lookup(const Bytes& b, std::string_view key) {
    return bplist_string_for_key(std::span<const std::uint8_t>{b.data(), b.size()}, key);
}

// ── SYNTHETIC image builder ────────────────────────────────────────────────

Bytes be(std::uint64_t v, std::size_t n) {
    Bytes out(n);
    for (std::size_t i = 0; i < n; ++i)
        out[n - 1 - i] = static_cast<std::uint8_t>(v >> (8 * i));
    return out;
}

void append(Bytes& dst, const Bytes& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

// An int object (marker 0x1N + 2^N big-endian bytes), narrowest width.
Bytes int_obj(std::uint64_t v) {
    Bytes out;
    if (v < 0x100) {
        out.push_back(0x10);
        append(out, be(v, 1));
    } else if (v < 0x10000) {
        out.push_back(0x11);
        append(out, be(v, 2));
    } else if (v < 0x100000000ULL) {
        out.push_back(0x12);
        append(out, be(v, 4));
    } else {
        out.push_back(0x13);
        append(out, be(v, 8));
    }
    return out;
}

// Marker for `kind` (5 ASCII, 6 UTF-16, 0xD dict) with `count`, extended via an
// int object when count >= 15.
Bytes sized(std::uint8_t kind, std::uint64_t count) {
    if (count < 15)
        return {static_cast<std::uint8_t>((kind << 4) | count)};
    Bytes out{static_cast<std::uint8_t>((kind << 4) | 0x0F)};
    append(out, int_obj(count));
    return out;
}

// Same, but the extended count is forced to an 8-byte int (hostile values).
Bytes sized8(std::uint8_t kind, std::uint64_t count) {
    Bytes out{static_cast<std::uint8_t>((kind << 4) | 0x0F), 0x13};
    append(out, be(count, 8));
    return out;
}

Bytes ascii(std::string_view s) {
    Bytes out = sized(0x5, s.size());
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

Bytes utf16(std::u16string_view s) {
    Bytes out = sized(0x6, s.size());
    for (const char16_t u : s)
        append(out, be(u, 2));
    return out;
}

Bytes dict(const std::vector<std::uint64_t>& keys, const std::vector<std::uint64_t>& vals,
           std::size_t ref_size) {
    Bytes out = sized(0xD, keys.size());
    for (const auto k : keys)
        append(out, be(k, ref_size));
    for (const auto v : vals)
        append(out, be(v, ref_size));
    return out;
}

Bytes finish(Bytes img, std::size_t offset_size, std::size_t ref_size, std::uint64_t num_objects,
             std::uint64_t top, std::uint64_t table_off) {
    for (int i = 0; i < 5; ++i)
        img.push_back(0); // unused
    img.push_back(0);      // sort version
    img.push_back(static_cast<std::uint8_t>(offset_size));
    img.push_back(static_cast<std::uint8_t>(ref_size));
    append(img, be(num_objects, 8));
    append(img, be(top, 8));
    append(img, be(table_off, 8));
    return img;
}

Bytes header() {
    return {'b', 'p', 'l', 'i', 's', 't', '0', '0'};
}

Bytes make_image(const std::vector<Bytes>& objs, std::size_t offset_size, std::size_t ref_size,
                 std::uint64_t top = 0) {
    Bytes img = header();
    std::vector<std::uint64_t> offs;
    for (const auto& o : objs) {
        offs.push_back(img.size());
        append(img, o);
    }
    const std::uint64_t table_off = img.size();
    for (const auto off : offs) {
        if (offset_size < 8)
            REQUIRE(off < (std::uint64_t{1} << (8 * offset_size))); // builder misuse guard
        append(img, be(off, offset_size));
    }
    return finish(std::move(img), offset_size, ref_size, objs.size(), top, table_off);
}

// The standard SYNTHETIC plist: DisplayName (UTF-16, "Café 中"), Name (ASCII),
// ShortVersionString (ASCII) and a non-string IntKey -> int.
Bytes std_image(std::size_t offset_size, std::size_t ref_size) {
    const std::vector<Bytes> objs = {
        dict({1, 3, 5, 7}, {2, 4, 6, 8}, ref_size),
        ascii("CFBundleDisplayName"),
        utf16(u"Café 中"),
        ascii("CFBundleName"),
        ascii("Cafe"),
        ascii("CFBundleShortVersionString"),
        ascii("1.2.3"),
        ascii("IntKey"),
        {0x10, 0x07},
    };
    return make_image(objs, offset_size, ref_size);
}

// {dict{1->2}, key object, value object}; the positive control for every
// hostile value/key object below.
Bytes kv_image(const Bytes& key_obj, const Bytes& value_obj) {
    return make_image({dict({1}, {2}, 1), key_obj, value_obj}, 1, 1);
}
Bytes kv_image_value(const Bytes& value_obj) {
    return kv_image(ascii("CFBundleName"), value_obj);
}

std::size_t trailer_pos(const Bytes& img) {
    return img.size() - 32;
}
std::uint64_t table_off_of(const Bytes& img) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i)
        v = (v << 8) | img[trailer_pos(img) + 24 + i];
    return v;
}
void patch_be(Bytes& img, std::size_t pos, std::uint64_t v, std::size_t n) {
    const Bytes b = be(v, n);
    for (std::size_t i = 0; i < n; ++i)
        img[pos + i] = b[i];
}

struct Case {
    std::string name;
    Bytes bytes;
};

// Every case must be nullopt for `key`, and a valid control must not be.
void expect_all_rejected(const std::vector<Case>& cases, std::string_view key) {
    for (const auto& c : cases) {
        INFO("case: " << c.name);
        CHECK_FALSE(lookup(c.bytes, key).has_value());
    }
}

bool valid_utf8(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<std::uint8_t>(s[i]);
        std::size_t extra = 0;
        std::uint32_t cp = 0;
        if (c < 0x80) {
            ++i;
            continue;
        } else if (c >= 0xC2 && c <= 0xDF) {
            extra = 1;
            cp = c & 0x1F;
        } else if (c >= 0xE0 && c <= 0xEF) {
            extra = 2;
            cp = c & 0x0F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            extra = 3;
            cp = c & 0x07;
        } else {
            return false;
        }
        if (s.size() - i <= extra)
            return false;
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto cc = static_cast<std::uint8_t>(s[i + k]);
            if ((cc & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        const std::uint32_t min = extra == 1 ? 0x80 : extra == 2 ? 0x800 : 0x10000;
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        i += extra + 1;
    }
    return true;
}

} // namespace

// ── 1. REAL CAPTURES ───────────────────────────────────────────────────────

TEST_CASE("bplist real capture: WhatsApp (UTF-16 DisplayName with a leading U+200E)",
          "[licensing][bplist]") {
    const Bytes b = read_fixture("WhatsApp.Info.plist");
    REQUIRE(std::string(b.begin(), b.begin() + 8) == "bplist00");
    // U+200E LEFT-TO-RIGHT MARK (E2 80 8E) then "WhatsApp": the one real UTF-16 value on the host.
    CHECK(lookup(b, "CFBundleDisplayName") == std::string("\xE2\x80\x8E" "WhatsApp"));
    CHECK(lookup(b, "CFBundleName") == "WhatsApp");
    CHECK(lookup(b, "CFBundleShortVersionString") == "26.41.28");
}

TEST_CASE("bplist real capture: Pages Creator Studio (DisplayName differs from Name)",
          "[licensing][bplist]") {
    const Bytes b = read_fixture("Pages-Creator-Studio.Info.plist");
    CHECK(lookup(b, "CFBundleDisplayName") == "Pages Creator Studio");
    CHECK(lookup(b, "CFBundleName") == "Pages"); // the caller prefers DisplayName; both are returned
    CHECK(lookup(b, "CFBundleShortVersionString") == "15.1.1");
}

TEST_CASE("bplist real capture: Spotify (smallest binary Info.plist on the host)",
          "[licensing][bplist]") {
    const Bytes b = read_fixture("Spotify.Info.plist");
    CHECK(lookup(b, "CFBundleName") == "Spotify");
    CHECK(lookup(b, "CFBundleDisplayName") == "Spotify");
    CHECK(lookup(b, "CFBundleShortVersionString") == "1.3.5.3058");
    CHECK_FALSE(lookup(b, "NoSuchKey").has_value()); // absent key
    CHECK_FALSE(lookup(b, "CFBundleDisplayNam").has_value()); // a prefix of a key is not the key
    CHECK_FALSE(lookup(b, "CFBundleDisplayNameX").has_value());
    CHECK_FALSE(lookup(b, "").has_value());
}

// ── 2. SYNTHETIC ───────────────────────────────────────────────────────────

TEST_CASE("bplist SYNTHETIC: round-trips for every offset width x reference width",
          "[licensing][bplist]") {
    const std::size_t offset_size = GENERATE(1, 2, 4, 8);
    const std::size_t ref_size = GENERATE(1, 2, 4, 8);
    INFO("offset_size=" << offset_size << " ref_size=" << ref_size);
    const Bytes img = std_image(offset_size, ref_size);
    // "Café 中": U+00E9 -> C3 A9 (2 bytes), U+4E2D -> E4 B8 AD (3 bytes), hand-computed.
    CHECK(lookup(img, "CFBundleDisplayName") == std::string("Caf\xC3\xA9 \xE4\xB8\xAD"));
    CHECK(lookup(img, "CFBundleName") == "Cafe");
    CHECK(lookup(img, "CFBundleShortVersionString") == "1.2.3");
    CHECK_FALSE(lookup(img, "IntKey").has_value()); // non-string value
    CHECK_FALSE(lookup(img, "Absent").has_value());
}

TEST_CASE("bplist SYNTHETIC: UTF-16 to UTF-8 at every encoded length (hand-computed)",
          "[licensing][bplist]") {
    // 1 byte: 'A'. 2 bytes: U+00E9. 3 bytes: U+20AC (EURO SIGN) and U+FFFD.
    // 4 bytes: U+1F600 as the surrogate pair D83D DE00 -> F0 9F 98 80, and U+10000 (D800 DC00)
    // -> F0 90 80 80, and U+10FFFF (DBFF DFFF) -> F4 8F BF BF.
    CHECK(lookup(kv_image_value(utf16(u"A")), "CFBundleName") == "A");
    CHECK(lookup(kv_image_value(utf16(u"é")), "CFBundleName") == "\xC3\xA9");
    CHECK(lookup(kv_image_value(utf16(u"€")), "CFBundleName") == "\xE2\x82\xAC");
    CHECK(lookup(kv_image_value(utf16(u"�")), "CFBundleName") == "\xEF\xBF\xBD");
    CHECK(lookup(kv_image_value(utf16(u"\U0001F600")), "CFBundleName") == "\xF0\x9F\x98\x80");
    CHECK(lookup(kv_image_value(utf16(u"\U00010000")), "CFBundleName") == "\xF0\x90\x80\x80");
    CHECK(lookup(kv_image_value(utf16(u"\U0010FFFF")), "CFBundleName") == "\xF4\x8F\xBF\xBF");
    // A string longer than 14 units uses the extended (0xF) count.
    CHECK(lookup(kv_image_value(utf16(u"0123456789abcdef")), "CFBundleName") == "0123456789abcdef");
    CHECK(lookup(kv_image_value(ascii("0123456789abcdef")), "CFBundleName") == "0123456789abcdef");
    // Empty string is a string.
    CHECK(lookup(kv_image_value(ascii("")), "CFBundleName") == "");
}

TEST_CASE("bplist SYNTHETIC: a UTF-16 key is matched without materialising it",
          "[licensing][bplist]") {
    CHECK(lookup(kv_image(utf16(u"CFBundleName"), ascii("Cafe")), "CFBundleName") == "Cafe");
    // A different UTF-16 string of the same length does not match.
    CHECK_FALSE(lookup(kv_image(utf16(u"CFBundleNamX"), ascii("Cafe")), "CFBundleName").has_value());
    // A non-zero high byte can never equal an ASCII key character.
    CHECK_FALSE(lookup(kv_image(utf16(u"CFBundleNšme"), ascii("Cafe")), "CFBundleName").has_value());
}

TEST_CASE("bplist SYNTHETIC: a non-string value for the key is nullopt",
          "[licensing][bplist]") {
    const std::vector<Bytes> values = {
        {0x10, 0x2A},                // int
        {0x09},                      // true
        {0x08},                      // false
        {0x00},                      // null
        {0x23, 0, 0, 0, 0, 0, 0, 0, 0}, // real (8 bytes)
        {0x41, 0xAA},                // data(1)
        {0xA1, 0x00},                // array of one ref
        {0x80, 0x01},                // uid
    };
    for (const auto& v : values) {
        INFO("marker 0x" << std::hex << int(v[0]));
        CHECK_FALSE(lookup(kv_image_value(v), "CFBundleName").has_value());
    }
}

TEST_CASE("bplist SYNTHETIC: the first of a repeated key wins", "[licensing][bplist]") {
    const std::vector<Bytes> objs = {
        dict({1, 1}, {2, 3}, 1), ascii("CFBundleName"), ascii("first"), ascii("second")};
    CHECK(lookup(make_image(objs, 1, 1), "CFBundleName") == "first");
}

// ── 3. HOSTILE corpus ──────────────────────────────────────────────────────

TEST_CASE("bplist hostile: the positive controls the corpus mutates do decode",
          "[licensing][bplist]") {
    CHECK(lookup(std_image(1, 1), "CFBundleName") == "Cafe");
    CHECK(lookup(kv_image_value(ascii("ok")), "CFBundleName") == "ok");
    CHECK(lookup(kv_image_value(utf16(u"ok")), "CFBundleName") == "ok");
}

TEST_CASE("bplist hostile: trailer and table structure defects are nullopt", "[licensing][bplist]") {
    const Bytes good = std_image(1, 1);
    const std::size_t tp = trailer_pos(good);
    const std::uint64_t toff = table_off_of(good);
    std::vector<Case> cases;
    const auto mutated = [&](const char* name, auto&& fn) {
        Bytes b = good;
        fn(b);
        cases.push_back({name, std::move(b)});
    };

    cases.push_back({"empty", {}});
    cases.push_back({"39 bytes", Bytes(39, 0)});
    {
        Bytes b = header();
        b.resize(39, 0);
        cases.push_back({"39 bytes with magic", std::move(b)});
    }
    mutated("magic bplist01", [](Bytes& b) { b[7] = '1'; });
    mutated("magic xplist00", [](Bytes& b) { b[0] = 'x'; });
    mutated("offset_size 0", [&](Bytes& b) { b[tp + 6] = 0; });
    mutated("offset_size 3", [&](Bytes& b) { b[tp + 6] = 3; });
    mutated("offset_size 16", [&](Bytes& b) { b[tp + 6] = 16; });
    mutated("ref_size 0", [&](Bytes& b) { b[tp + 7] = 0; });
    mutated("ref_size 3", [&](Bytes& b) { b[tp + 7] = 3; });
    mutated("num_objects 0", [&](Bytes& b) { patch_be(b, tp + 8, 0, 8); });
    mutated("num_objects larger than the table", [&](Bytes& b) { patch_be(b, tp + 8, 200, 8); });
    mutated("num_objects kBplistMaxObjects+1 on a tiny file",
            [&](Bytes& b) { patch_be(b, tp + 8, kBplistMaxObjects + 1, 8); });
    mutated("offset table starts at the trailer + 1",
            [&](Bytes& b) { patch_be(b, tp + 24, tp + 1, 8); });
    mutated("offset table starts past EOF", [&](Bytes& b) { patch_be(b, tp + 24, b.size(), 8); });
    mutated("offset table starts inside the header", [&](Bytes& b) { patch_be(b, tp + 24, 7, 8); });
    mutated("offset table overlaps the trailer",
            [&](Bytes& b) { patch_be(b, tp + 24, tp - 1, 8); });
    mutated("top_object == num_objects", [&](Bytes& b) { patch_be(b, tp + 16, 9, 8); });
    mutated("top_object is a string, not a dict", [&](Bytes& b) { patch_be(b, tp + 16, 1, 8); });
    mutated("object 0 offset < 8 (inside the header)", [&](Bytes& b) { b[toff] = 4; });
    mutated("object 0 offset == offset table start",
            [&](Bytes& b) { b[toff] = static_cast<std::uint8_t>(toff); });
    mutated("object 0 offset past the table",
            [&](Bytes& b) { b[toff] = static_cast<std::uint8_t>(toff + 1); });
    mutated("key object offset points at the header", [&](Bytes& b) { b[toff + 3] = 0; });
    // The header bytes "bplist00" READ AS OBJECTS: 'b' (0x62) is a 2-unit UTF-16 string and 'l'
    // (0x6C) a 12-unit one, so a value offset below 8 would decode to garbage if it were accepted.
    mutated("value object offset 0 (header reads as a UTF-16 string)",
            [&](Bytes& b) { b[toff + 4] = 0; });
    mutated("value object offset 2 (header reads as a UTF-16 string)",
            [&](Bytes& b) { b[toff + 4] = 2; });
    mutated("value object offset past EOF", [&](Bytes& b) { b[toff + 4] = 0xFF; });
    expect_all_rejected(cases, "CFBundleName");
}

TEST_CASE("bplist hostile: dictionary shape defects are nullopt", "[licensing][bplist]") {
    std::vector<Case> cases;
    // count > num_objects.
    cases.push_back({"dict count 14 with 3 objects",
                     make_image({[] { Bytes d = {0xDE}; d.resize(1 + 28, 0); return d; }(),
                                 ascii("CFBundleName"), ascii("x")},
                                1, 1)});
    // count <= num_objects but the reference block overruns the object region.
    {
        std::vector<Bytes> objs;
        objs.push_back({0xD9, 1, 2, 3, 4}); // claims 9 entries (18 ref bytes), supplies 4
        for (int i = 0; i < 9; ++i)
            objs.push_back({0x00});
        cases.push_back({"dict refs overrun the object region", make_image(objs, 1, 1)});
    }
    // 0xF count with an 8-byte int far beyond the region / num_objects.
    for (const std::uint64_t n : {std::uint64_t{1} << 40, kBit63, kMax64}) {
        Bytes d = sized8(0xD, n);
        append(d, Bytes{0x01, 0x02});
        cases.push_back({"dict extended count " + std::to_string(n),
                         make_image({d, ascii("CFBundleName"), ascii("x")}, 1, 1)});
    }
    // 0xF count followed by something that is not a 1/2/4/8-byte int.
    cases.push_back({"dict 0xF then a string marker",
                     make_image({Bytes{0xDF, 0x50}, ascii("CFBundleName"), ascii("x")}, 1, 1)});
    // A 16-byte count (marker 0x14) is outside the 1/2/4/8-byte widths. Its low 8 bytes are 1 and
    // the two reference bytes {1,2} follow, so it would be a VALID one-entry dict if the width were
    // accepted: only the width check rejects it.
    cases.push_back({"dict 0xF then a 16-byte int marker",
                     make_image({Bytes{0xDF, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2},
                                 ascii("CFBundleName"), ascii("x")},
                                1, 1)});
    cases.push_back({"dict 0xF then end of region", make_image({Bytes{0xDF}}, 1, 1)});
    cases.push_back({"dict 0xF then a truncated int",
                     make_image({Bytes{0xDF, 0x13, 0, 0, 0}}, 1, 1)});
    // References.
    cases.push_back({"key ref >= num_objects",
                     make_image({dict({99}, {2}, 1), ascii("CFBundleName"), ascii("x")}, 1, 1)});
    cases.push_back({"value ref >= num_objects",
                     make_image({dict({1}, {99}, 1), ascii("CFBundleName"), ascii("x")}, 1, 1)});
    cases.push_back({"value ref points at the dict itself (cyclic)",
                     make_image({dict({1}, {0}, 1), ascii("CFBundleName")}, 1, 1)});
    cases.push_back({"key ref points at the dict itself (cyclic)",
                     make_image({dict({0}, {1}, 1), ascii("CFBundleName")}, 1, 1)});
    // An earlier malformed key makes the WHOLE lookup nullopt, even though a later key matches.
    cases.push_back({"malformed earlier key ref poisons the lookup",
                     make_image({dict({99, 1}, {2, 2}, 1), ascii("CFBundleName"), ascii("x")}, 1, 1)});
    // Top object is not a dict.
    cases.push_back({"top object is an array",
                     make_image({Bytes{0xA1, 0x00}}, 1, 1)});
    expect_all_rejected(cases, "CFBundleName");
}

TEST_CASE("bplist hostile: string defects are nullopt", "[licensing][bplist]") {
    std::vector<Case> cases;
    // Truncated mid-string: the length claims more than the region holds.
    cases.push_back({"ASCII claims 10 bytes, 3 present", kv_image_value(Bytes{0x5A, 'a', 'b', 'c'})});
    cases.push_back({"UTF-16 claims 2 units, 3 bytes present",
                     kv_image_value(Bytes{0x62, 0x00, 0x41, 0x00})});
    cases.push_back({"UTF-16 claims 1 unit, 1 byte present", kv_image_value(Bytes{0x61, 0x00})});
    cases.push_back({"ASCII with no payload at all", kv_image_value(Bytes{0x51})});
    // Unpaired surrogates.
    cases.push_back({"lone high surrogate", kv_image_value(utf16(u"\xD83D"))});
    cases.push_back({"high surrogate then a non-surrogate", kv_image_value(utf16(u"\xD83D" u"A"))});
    cases.push_back({"high surrogate then a high surrogate",
                     kv_image_value(utf16(u"\xD83D\xD83D"))});
    cases.push_back({"low surrogate first", kv_image_value(utf16(u"\xDE00\xD83D"))});
    cases.push_back({"lone low surrogate", kv_image_value(utf16(u"\xDE00"))});
    cases.push_back({"high surrogate last", kv_image_value(utf16(u"A\xD83D"))});
    // A high byte in an "ASCII" string would be invalid UTF-8 on the wire.
    cases.push_back({"ASCII string with a 0x80 byte", kv_image_value(Bytes{0x52, 'a', 0x80})});
    cases.push_back({"ASCII string with a 0xFF byte", kv_image_value(Bytes{0x52, 0xFF, 'a'})});
    // Same defects on the KEY object: nothing matches, so the lookup fails.
    cases.push_back({"key truncated mid-string", kv_image(Bytes{0x5C, 'C', 'F'}, ascii("x"))});
    expect_all_rejected(cases, "CFBundleName");
}

// ── 4. WRAP vectors (R2) ───────────────────────────────────────────────────

TEST_CASE("bplist wrap: offset table position / object count near UINT64_MAX", "[licensing][bplist]") {
    std::vector<Case> cases;
    const Bytes one_obj = [] {
        Bytes b = header();
        b.push_back(0xD0); // empty dict
        return b;
    }();
    cases.push_back({"table at UINT64_MAX-16, 1 object, 8-byte offsets",
                     finish(one_obj, 8, 1, 1, 0, kMax64 - 16)});
    cases.push_back({"table at UINT64_MAX-100, max objects, 8-byte offsets",
                     finish(one_obj, 8, 1, kBplistMaxObjects, 0, kMax64 - 100)});
    cases.push_back({"table at UINT64_MAX, 1 object", finish(one_obj, 8, 1, 1, 0, kMax64)});
    cases.push_back({"table at 2^63, 1 object", finish(one_obj, 8, 1, 1, 0, kBit63)});
    // A table that fits only if `start + bytes` were allowed to wrap: start near the end of the
    // address space, bytes large enough to carry past 2^64.
    cases.push_back({"table at UINT64_MAX-3, max objects x 8",
                     finish(one_obj, 8, 1, kBplistMaxObjects, 0, kMax64 - 3)});
    cases.push_back({"num_objects UINT64_MAX", finish(one_obj, 8, 1, kMax64, 0, 9)});
    cases.push_back({"num_objects 2^63", finish(one_obj, 8, 1, kBit63, 0, 9)});
    cases.push_back({"num_objects 2^32+1", finish(one_obj, 8, 1, (std::uint64_t{1} << 32) + 1, 0, 9)});
    cases.push_back({"top_object UINT64_MAX on a valid image", [] {
                         Bytes b = std_image(1, 1);
                         patch_be(b, trailer_pos(b) + 16, kMax64, 8);
                         return b;
                     }()});
    cases.push_back({"top_object 2^63 on a valid image", [] {
                         Bytes b = std_image(1, 1);
                         patch_be(b, trailer_pos(b) + 16, kBit63, 8);
                         return b;
                     }()});
    expect_all_rejected(cases, "CFBundleName");
}

TEST_CASE("bplist wrap: object offsets, counts and references near UINT64_MAX", "[licensing][bplist]") {
    std::vector<Case> cases;
    // An 8-byte object offset of UINT64_MAX / 2^63 (valid table position, hostile entry).
    for (const std::uint64_t off : {kMax64, kMax64 - 7, kBit63, kBit63 + 1}) {
        Bytes body = header();
        body.push_back(0xD0);
        const std::uint64_t table_off = body.size();
        append(body, be(off, 8));
        cases.push_back({"8-byte object offset " + std::to_string(off),
                         finish(body, 8, 1, 1, 0, table_off)});
    }
    // Dict count via an 8-byte int of 2^63 / UINT64_MAX / UINT64_MAX-1 (wraps 2*count*ref_size).
    for (const std::uint64_t n : {kBit63, kMax64, kMax64 - 1, (std::uint64_t{1} << 62) + 3}) {
        Bytes body = header();
        append(body, sized8(0xD, n));
        const std::uint64_t table_off = body.size();
        append(body, be(8, 1));
        cases.push_back({"dict count 8-byte int " + std::to_string(n),
                         finish(body, 1, 8, 1, 0, table_off)});
    }
    // 8-byte key / value references of UINT64_MAX.
    {
        const std::vector<Bytes> objs = {dict({kMax64}, {1}, 8), ascii("CFBundleName")};
        cases.push_back({"key ref UINT64_MAX", make_image(objs, 1, 8)});
    }
    {
        const std::vector<Bytes> objs = {dict({1}, {kMax64}, 8), ascii("CFBundleName")};
        cases.push_back({"value ref UINT64_MAX", make_image(objs, 1, 8)});
    }
    {
        const std::vector<Bytes> objs = {dict({1}, {kBit63}, 8), ascii("CFBundleName")};
        cases.push_back({"value ref 2^63", make_image(objs, 1, 8)});
    }
    expect_all_rejected(cases, "CFBundleName");
}

TEST_CASE("bplist wrap: 0xF string lengths that would wrap `start + length`", "[licensing][bplist]") {
    // The value (or key) object is the LAST object, so its payload begins a few bytes before the
    // offset table; a length of UINT64_MAX-k makes `payload + length` wrap to a small value that a
    // naive `<= region_end` test would accept.
    const std::vector<std::uint64_t> lengths = {
        kMax64,       kMax64 - 1,     kMax64 - 7,     kMax64 - 15,     kBit63,
        kBit63 + 1,   kBit63 - 1,     std::uint64_t{1} << 32,
        (std::uint64_t{1} << 32) + 5, std::uint64_t{0xFFFFFFFF},       kBplistMaxStringBytes + 1,
    };
    std::vector<Case> cases;
    for (const std::uint64_t len : lengths) {
        for (const std::uint8_t kind : {std::uint8_t{0x5}, std::uint8_t{0x6}}) {
            const std::string tag = (kind == 0x5 ? "ASCII len " : "UTF-16 len ") + std::to_string(len);
            Bytes value = sized8(kind, len);
            append(value, Bytes{'a', 'b'}); // a couple of real bytes, nowhere near len
            cases.push_back({"value " + tag, kv_image_value(value)});
            // Same hostile object as the KEY: it cannot equal the key, so the lookup fails.
            cases.push_back({"key " + tag, kv_image(value, ascii("x"))});
        }
    }
    // 4-byte extended count of 0xFFFFFFFF (an int object of width 4).
    cases.push_back({"ASCII 4-byte len 0xFFFFFFFF",
                     kv_image_value(Bytes{0x5F, 0x12, 0xFF, 0xFF, 0xFF, 0xFF, 'a'})});
    expect_all_rejected(cases, "CFBundleName");
}

// ── 5. BOUNDARY (mutation proofs) ──────────────────────────────────────────

TEST_CASE("bplist boundary: exactly kBplistMaxObjects objects is accepted, one more is not",
          "[licensing][bplist]") {
    const auto image_with = [](std::size_t n) {
        std::vector<Bytes> objs;
        objs.reserve(n);
        objs.push_back(dict({1}, {2}, 2));
        objs.push_back(ascii("CFBundleName"));
        objs.push_back(ascii("Cafe"));
        while (objs.size() < n)
            objs.push_back({0x00});
        return make_image(objs, 4, 2);
    };
    CHECK(lookup(image_with(kBplistMaxObjects), "CFBundleName") == "Cafe");
    CHECK_FALSE(lookup(image_with(kBplistMaxObjects + 1), "CFBundleName").has_value());
}

TEST_CASE("bplist boundary: a string of exactly kBplistMaxStringBytes is accepted, +1 is not",
          "[licensing][bplist]") {
    const std::string at_cap(kBplistMaxStringBytes, 'a');
    const std::string over(kBplistMaxStringBytes + 1, 'a');
    CHECK(lookup(kv_image_value(ascii(at_cap)), "CFBundleName") == at_cap);
    CHECK_FALSE(lookup(kv_image_value(ascii(over)), "CFBundleName").has_value());

    // UTF-16: the cap is in BYTES, so half as many units.
    const std::u16string units_at_cap(kBplistMaxStringBytes / 2, u'a');
    const std::u16string units_over(kBplistMaxStringBytes / 2 + 1, u'a');
    CHECK(lookup(kv_image_value(utf16(units_at_cap)), "CFBundleName") ==
          std::string(kBplistMaxStringBytes / 2, 'a'));
    CHECK_FALSE(lookup(kv_image_value(utf16(units_over)), "CFBundleName").has_value());
}

TEST_CASE("bplist boundary: a dictionary of exactly num_objects entries is accepted",
          "[licensing][bplist]") {
    // 1 dict + N-1 key/value strings can't all be distinct objects in 3 slots; reuse refs: a
    // 3-object plist whose dict has 3 entries (count == num_objects) all pointing at objects 1/2.
    const std::vector<Bytes> objs = {dict({1, 1, 1}, {2, 2, 2}, 1), ascii("CFBundleName"),
                                     ascii("Cafe")};
    CHECK(lookup(make_image(objs, 1, 1), "CFBundleName") == "Cafe");
    // count == num_objects + 1 is rejected before any reference is read.
    const std::vector<Bytes> over = {dict({1, 1, 1, 1}, {2, 2, 2, 2}, 1), ascii("CFBundleName"),
                                     ascii("Cafe")};
    CHECK_FALSE(lookup(make_image(over, 1, 1), "CFBundleName").has_value());
}

// ── 6. Deterministic byte-flip / truncation sweep ──────────────────────────

TEST_CASE("bplist sweep: every single-byte corruption and every truncation of a real capture "
          "is crash-free and yields only well-formed UTF-8",
          "[licensing][bplist]") {
    const Bytes real = read_fixture("WhatsApp.Info.plist");
    const char* const keys[] = {"CFBundleDisplayName", "CFBundleName", "CFBundleShortVersionString"};
    std::size_t lookups = 0;
    std::size_t malformed_results = 0;
    const auto probe = [&](const Bytes& b) {
        for (const char* k : keys) {
            ++lookups;
            if (const auto r = lookup(b, k); r && !valid_utf8(*r))
                ++malformed_results;
        }
    };
    Bytes work = real;
    for (std::size_t i = 0; i < work.size(); ++i) {
        const std::uint8_t original = work[i];
        for (const std::uint8_t v : {std::uint8_t{0x00}, std::uint8_t{0x7F}, std::uint8_t{0x80},
                                     std::uint8_t{0xFF}}) {
            work[i] = v;
            probe(work);
        }
        work[i] = original;
    }
    for (std::size_t len = 0; len < real.size(); ++len)
        probe(Bytes(real.begin(), real.begin() + static_cast<std::ptrdiff_t>(len)));
    CHECK(lookups > 0);
    CHECK(malformed_results == 0);
}
