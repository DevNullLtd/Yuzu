/**
 * test_component_zip.cpp - bounded ZIP central-directory reader
 * (zip_directory.hpp).
 *
 * Pure header, no I/O: every fixture is a byte array built here. Archives are
 * assembled by a small writer so each test states only what it varies.
 */

#include "zip_directory.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace yuzu::component_inventory;

namespace {

using Bytes = std::vector<std::byte>;

void put16(Bytes& b, std::uint16_t v) {
    b.push_back(static_cast<std::byte>(v & 0xFF));
    b.push_back(static_cast<std::byte>(v >> 8));
}
void put32(Bytes& b, std::uint32_t v) {
    put16(b, static_cast<std::uint16_t>(v & 0xFFFF));
    put16(b, static_cast<std::uint16_t>(v >> 16));
}
void put_str(Bytes& b, const std::string& s) {
    for (char c : s)
        b.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
}

struct Item {
    std::string name;
    std::uint16_t method{0};
    std::string data; // stored bytes (also used as the "compressed" bytes)
    std::uint16_t flags{0};
};

void put_local(Bytes& out, const Item& it, std::uint16_t extra_len) {
    put32(out, 0x04034b50U);
    put16(out, 20);
    put16(out, it.flags);
    put16(out, it.method);
    put32(out, 0); // time/date
    put32(out, 0); // crc
    put32(out, static_cast<std::uint32_t>(it.data.size()));
    put32(out, static_cast<std::uint32_t>(it.data.size()));
    put16(out, static_cast<std::uint16_t>(it.name.size()));
    put16(out, extra_len);
    put_str(out, it.name);
    out.insert(out.end(), extra_len, std::byte{0});
    put_str(out, it.data);
}

void put_central(Bytes& cd, const Item& it, std::uint32_t local_off, std::uint16_t extra_len = 0,
                 std::uint16_t comment_len = 0) {
    put32(cd, 0x02014b50U);
    put16(cd, 20);
    put16(cd, 20);
    put16(cd, it.flags);
    put16(cd, it.method);
    put32(cd, 0); // time/date
    put32(cd, 0); // crc
    put32(cd, static_cast<std::uint32_t>(it.data.size()));
    put32(cd, static_cast<std::uint32_t>(it.data.size()));
    put16(cd, static_cast<std::uint16_t>(it.name.size()));
    put16(cd, extra_len);
    put16(cd, comment_len);
    put16(cd, 0); // disk start
    put16(cd, 0); // internal attrs
    put32(cd, 0); // external attrs
    put32(cd, local_off);
    put_str(cd, it.name);
    cd.insert(cd.end(), static_cast<std::size_t>(extra_len) + comment_len, std::byte{0});
}

void put_eocd(Bytes& out, std::uint16_t entries, std::uint32_t cd_size, std::uint32_t cd_off,
              const std::string& comment = "") {
    put32(out, 0x06054b50U);
    put16(out, 0);
    put16(out, 0);
    put16(out, entries);
    put16(out, entries);
    put32(out, cd_size);
    put32(out, cd_off);
    put16(out, static_cast<std::uint16_t>(comment.size()));
    put_str(out, comment);
}

struct Built {
    Bytes file;
    std::size_t cd_off{0};
    std::size_t cd_size{0};
    std::size_t entries{0};
};

Built build(const std::vector<Item>& items, const std::string& comment = "") {
    Built b;
    Bytes cd;
    for (const auto& it : items) {
        const auto off = static_cast<std::uint32_t>(b.file.size());
        put_local(b.file, it, 0);
        put_central(cd, it, off);
    }
    b.cd_off = b.file.size();
    b.cd_size = cd.size();
    b.entries = items.size();
    b.file.insert(b.file.end(), cd.begin(), cd.end());
    put_eocd(b.file, static_cast<std::uint16_t>(items.size()), static_cast<std::uint32_t>(cd.size()),
             static_cast<std::uint32_t>(b.cd_off), comment);
    return b;
}

std::span<const std::byte> view(const Bytes& b, std::size_t off, std::size_t len) {
    return std::span<const std::byte>(b).subspan(off, len);
}

// Tail the way a caller reads it: the last min(file_size, kMaxTailBytes) bytes.
std::expected<ZipTail, ZipError> find(const Bytes& file) {
    const std::size_t n = std::min(file.size(), kMaxTailBytes);
    return find_central_directory(view(file, file.size() - n, n), file.size());
}

} // namespace

TEST_CASE("zip: a small archive yields its entries with offsets and sizes", "[component_zip]") {
    const auto b = build({{"META-INF/MANIFEST.MF", 0, "Manifest-Version: 1.0\r\n"},
                          {"lib/a.class", 8, "xyz"}});
    const auto tail = find(b.file);
    REQUIRE(tail.has_value());
    CHECK(tail->entries == 2);
    CHECK(tail->cd_offset == b.cd_off);
    CHECK(tail->cd_size == b.cd_size);

    std::vector<ZipEntry> seen;
    auto r = for_each_central_entry(view(b.file, b.cd_off, b.cd_size), tail->entries,
                                    [&](const ZipEntry& e) {
                                        seen.push_back(e);
                                        return true;
                                    });
    REQUIRE(r.has_value());
    REQUIRE(seen.size() == 2);
    CHECK(seen[0].name == "META-INF/MANIFEST.MF");
    CHECK(seen[0].method == 0);
    CHECK(seen[0].comp_size == 23);
    CHECK(seen[0].uncomp_size == 23);
    CHECK(seen[0].local_header_offset == 0);
    CHECK(seen[1].name == "lib/a.class");
    CHECK(seen[1].method == 8);
    CHECK(seen[1].comp_size == 3);
    CHECK(seen[1].local_header_offset == 30 + 20 + 23);
}

TEST_CASE("zip: an empty archive (end record only) has no entries", "[component_zip]") {
    Bytes f;
    put_eocd(f, 0, 0, 0);
    const auto tail = find(f);
    REQUIRE(tail.has_value());
    CHECK(tail->entries == 0);
    CHECK(tail->cd_size == 0);
    int n = 0;
    CHECK(for_each_central_entry({}, 0, [&](const ZipEntry&) { ++n; return true; }).has_value());
    CHECK(n == 0);
}

TEST_CASE("zip: truncating the tail at every boundary is an error, never a read overrun",
          "[component_zip]") {
    const auto b = build({{"a.txt", 0, "hello"}, {"b/c.txt", 0, "world!"}});
    for (std::size_t n = 0; n < b.file.size(); ++n) {
        // Both a prefix as the whole file and a prefix as a tail of the real file.
        CHECK_FALSE(find_central_directory(view(b.file, 0, n), n).has_value());
        CHECK_FALSE(find_central_directory(view(b.file, 0, n), b.file.size()).has_value());
    }
    CHECK(find(b.file).has_value());
}

TEST_CASE("zip: truncating the directory at every boundary is an error", "[component_zip]") {
    const auto b = build({{"a.txt", 0, "hello"}, {"b/c.txt", 0, "world!"}});
    for (std::size_t n = 0; n < b.cd_size; ++n) {
        auto r = for_each_central_entry(view(b.file, b.cd_off, n), 2,
                                        [](const ZipEntry&) { return true; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::truncated);
    }
}

TEST_CASE("zip: a directory above the cap is refused from the end record alone",
          "[component_zip]") {
    Bytes f; // only the 22-byte end record is in hand; no directory byte exists
    put_eocd(f, 1, static_cast<std::uint32_t>(kMaxCdBytes + 1), 0);
    auto r = find_central_directory(f, 64ULL * 1024 * 1024);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ZipError::directory_too_large);

    // Exactly at the cap is accepted (it is then read, in full, by the caller).
    Bytes g;
    put_eocd(g, 1, static_cast<std::uint32_t>(kMaxCdBytes), 0);
    CHECK(find_central_directory(g, 64ULL * 1024 * 1024).has_value());
}

TEST_CASE("zip: a directory that runs past the end record is refused", "[component_zip]") {
    Bytes f;
    put_eocd(f, 1, 100, 0); // 100 directory bytes claimed, file is only the end record
    auto r = find_central_directory(f, f.size());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ZipError::bad_record);

    Bytes wrap; // cd_offset + cd_size must not wrap
    put_eocd(wrap, 1, 0x10, 0xFFFFFFF0U);
    CHECK_FALSE(find_central_directory(wrap, wrap.size()).has_value());
}

TEST_CASE("zip: 60000 entries are visited one at a time", "[component_zip]") {
    constexpr std::uint32_t kN = 60000;
    Bytes cd;
    for (std::uint32_t i = 0; i < kN; ++i) {
        Item it;
        it.name = "e" + std::to_string(i);
        put_central(cd, it, i);
    }
    std::uint32_t count = 0;
    std::string first, last;
    std::uint64_t last_off = 0;
    auto r = for_each_central_entry(cd, kN, [&](const ZipEntry& e) {
        if (count == 0)
            first = std::string(e.name);
        last = std::string(e.name);
        last_off = e.local_header_offset;
        ++count;
        return true;
    });
    REQUIRE(r.has_value());
    CHECK(count == kN);
    CHECK(first == "e0");
    CHECK(last == "e59999");
    CHECK(last_off == 59999);
}

TEST_CASE("zip: the visitor can stop early without an error", "[component_zip]") {
    const auto b = build({{"a", 0, ""}, {"b", 0, ""}, {"c", 0, ""}});
    int n = 0;
    auto r = for_each_central_entry(view(b.file, b.cd_off, b.cd_size), 3, [&](const ZipEntry&) {
        return ++n < 2;
    });
    CHECK(r.has_value());
    CHECK(n == 2);
}

TEST_CASE("zip: more declared entries than records is truncated", "[component_zip]") {
    const auto b = build({{"a", 0, ""}});
    auto r = for_each_central_entry(view(b.file, b.cd_off, b.cd_size), 2,
                                    [](const ZipEntry&) { return true; });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ZipError::truncated);
}

TEST_CASE("zip: ZIP64 markers are refused", "[component_zip]") {
    SECTION("sentinel cd_offset") {
        Bytes f;
        put_eocd(f, 1, 46, 0xFFFFFFFFU);
        auto r = find_central_directory(f, f.size());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::zip64_unsupported);
    }
    SECTION("sentinel cd_size") {
        Bytes f;
        put_eocd(f, 1, 0xFFFFFFFFU, 0);
        CHECK(find_central_directory(f, f.size()).error() == ZipError::zip64_unsupported);
    }
    SECTION("sentinel entry count") {
        Bytes f;
        put_eocd(f, 0xFFFF, 0, 0);
        CHECK(find_central_directory(f, f.size()).error() == ZipError::zip64_unsupported);
    }
    SECTION("ZIP64 locator before the end record") {
        Bytes f;
        put32(f, 0x07064b50U);
        f.insert(f.end(), 16, std::byte{0});
        put_eocd(f, 0, 0, 0);
        auto r = find_central_directory(f, f.size());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::zip64_unsupported);
    }
    SECTION("sentinel in a directory record") {
        Item it{"a", 0, "x"};
        Bytes cd;
        put_central(cd, it, 0xFFFFFFFFU);
        auto r = for_each_central_entry(cd, 1, [](const ZipEntry&) { return true; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::zip64_unsupported);
    }
}

TEST_CASE("zip: a fake end signature in the archive comment does not redirect the parse",
          "[component_zip]") {
    // The comment is a valid-looking end record claiming a directory far
    // outside the file, with a comment length that does not reach the buffer end.
    Bytes fake;
    put_eocd(fake, 1, 0x1000, 0x7000, "");
    std::string comment;
    for (auto c : fake)
        comment.push_back(static_cast<char>(c));
    comment += "tail";
    const auto b = build({{"a.txt", 0, "hello"}}, comment);
    const auto tail = find(b.file);
    REQUIRE(tail.has_value());
    CHECK(tail->cd_offset == b.cd_off);
    CHECK(tail->cd_size == b.cd_size);
    CHECK(tail->cd_offset + tail->cd_size <= b.file.size());

    // A planted record whose length does land on the buffer end is still
    // bounds-checked against the file, so it cannot point outside it.
    Bytes only_fake;
    put_eocd(only_fake, 1, 0x1000, 0x7000, "");
    auto r = find_central_directory(only_fake, only_fake.size());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ZipError::bad_record);
}

TEST_CASE("zip: record validation", "[component_zip]") {
    SECTION("bad central signature") {
        Item it{"a", 0, ""};
        Bytes cd;
        put_central(cd, it, 0);
        cd[0] = std::byte{0};
        auto r = for_each_central_entry(cd, 1, [](const ZipEntry&) { return true; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::bad_record);
    }
    SECTION("name longer than the cap") {
        Item it{std::string(kMaxEntryNameLen + 1, 'n'), 0, ""};
        Bytes cd;
        put_central(cd, it, 0);
        auto r = for_each_central_entry(cd, 1, [](const ZipEntry&) { return true; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::bad_record);
    }
    SECTION("name at the cap is accepted") {
        Item it{std::string(kMaxEntryNameLen, 'n'), 0, ""};
        Bytes cd;
        put_central(cd, it, 0);
        CHECK(for_each_central_entry(cd, 1, [](const ZipEntry&) { return true; }).has_value());
    }
    SECTION("extra and comment lengths run past the span") {
        Item it{"a", 0, ""};
        Bytes cd;
        put_central(cd, it, 0, 4, 4);
        cd.resize(cd.size() - 1);
        auto r = for_each_central_entry(cd, 1, [](const ZipEntry&) { return true; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::truncated);
    }
    SECTION("extra and comment bytes are skipped to the next record") {
        Bytes cd;
        put_central(cd, Item{"a", 0, ""}, 0, 7, 5);
        put_central(cd, Item{"b", 0, ""}, 0);
        std::vector<std::string> names;
        auto r = for_each_central_entry(cd, 2, [&](const ZipEntry& e) {
            names.emplace_back(e.name);
            return true;
        });
        REQUIRE(r.has_value());
        CHECK(names == std::vector<std::string>{"a", "b"});
    }
    SECTION("encrypted entry is refused") {
        Item it{"a", 0, "", 0x0001};
        Bytes cd;
        put_central(cd, it, 0);
        auto r = for_each_central_entry(cd, 1, [](const ZipEntry&) { return true; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::bad_record);
    }
    SECTION("multi-disk end record is refused") {
        Bytes f;
        put32(f, 0x06054b50U);
        put16(f, 1); // this disk
        put16(f, 0);
        put16(f, 0);
        put16(f, 0);
        put32(f, 0);
        put32(f, 0);
        put16(f, 0);
        auto r = find_central_directory(f, f.size());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::bad_record);
    }
}

TEST_CASE("zip: no end record is not_zip", "[component_zip]") {
    Bytes junk(100, std::byte{0x41});
    auto r = find_central_directory(junk, junk.size());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ZipError::not_zip);
    CHECK(find_central_directory({}, 0).error() == ZipError::not_zip);
}

TEST_CASE("zip: local_data_offset reads the local lengths, not the central ones",
          "[component_zip]") {
    Item it{"lib/a.class", 8, "abc"};
    Bytes local;
    put_local(local, it, 6); // 6 extra bytes in the local header only
    ZipEntry e;
    e.method = 8;
    e.local_header_offset = 1000;

    auto off = local_data_offset(local, e);
    REQUIRE(off.has_value());
    CHECK(*off == 1000 + 30 + it.name.size() + 6);

    // Header bytes alone suffice (the caller need not read the data).
    CHECK(local_data_offset(view(local, 0, 30), e).has_value());

    for (std::size_t n = 0; n < 30; ++n) {
        auto r = local_data_offset(view(local, 0, n), e);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ZipError::truncated);
    }

    Bytes bad = local;
    bad[3] = std::byte{0};
    CHECK(local_data_offset(bad, e).error() == ZipError::bad_record);

    ZipEntry far;
    far.local_header_offset = UINT64_MAX - 10;
    CHECK(local_data_offset(local, far).error() == ZipError::bad_record);
}
