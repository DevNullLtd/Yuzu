/**
 * test_rpmdb_parsers.cpp -- the rpm header-blob parser, the C-locale date formatter and the ndb
 * and Berkeley DB hash container readers (agents/shared/rpmdb_parsers.hpp, SAM-45).
 *
 * The readers are pure over an injected ByteSource, so every case runs on every host with no
 * rpm, no process and no network. The sqlite container is read in the plugin shell
 * (test_installed_apps_pkgdb.cpp); here sqlite only SUPPLIES real header blobs to the parser.
 *
 * Fixture provenance (tests/unit/fixtures/software-estate/pkgdb/provenance.txt has the commands):
 *   - "real capture": the databases under pkgdb/<capture>/ are real rpm databases from the S-7
 *     captures (Fedora 41 and AlmaLinux 9 sqlite, AlmaLinux 8 Berkeley DB on arm64 AND on s390x,
 *     openSUSE Leap 15.6 and Tumbleweed ndb), trimmed to a handful of packages with `rpm -e
 *     --justdb` + `rpm --rebuilddb` run by real rpm. inventory.tsv beside each is that rpm's own
 *     `--queryformat` output (the exact format the plugin's old path used), the independent oracle.
 *   - "edited real": a real blob or file with a few bytes changed in memory. Every hostile case
 *     is built this way and says so in its name; nothing is hand-assembled from imagination.
 */

#include <catch2/catch_test_macros.hpp>

#include <rpmdb_parsers.hpp>

#include <sqlite3.h>

#include "test_helpers.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::shared;
namespace fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;

namespace {

fs::path pkgdb_fixture(std::string_view capture, std::string_view file) {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "pkgdb" / capture / file;
}

Bytes read_bytes(const fs::path& p) {
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    REQUIRE(f.is_open());
    return Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

std::vector<std::string> oracle_lines(std::string_view capture) {
    const auto b = read_bytes(pkgdb_fixture(capture, "inventory.tsv"));
    std::istringstream ss(std::string(b.begin(), b.end()));
    std::vector<std::string> out;
    std::string line;
    while (std::getline(ss, line))
        if (!line.empty())
            out.push_back(line);
    return out;
}

std::vector<std::string> split_tabs(const std::string& s) {
    std::vector<std::string> out;
    std::size_t p = 0;
    for (;;) {
        const std::size_t t = s.find('\t', p);
        if (t == std::string::npos) {
            out.push_back(s.substr(p));
            return out;
        }
        out.push_back(s.substr(p, t - p));
        p = t + 1;
    }
}

std::tm utc_tm(std::int64_t t) {
    std::tm out{};
    const std::time_t tt = static_cast<std::time_t>(t);
#ifdef _WIN32
    gmtime_s(&out, &tt);
#else
    gmtime_r(&tt, &out);
#endif
    return out;
}

PkgDbBudget generous() {
    PkgDbBudget b;
    b.rows_left = 50000;
    b.bytes_left = 1ull << 30;
    b.max_item_bytes = 32ull << 20;
    return b;
}

// ── real blobs from each container ──────────────────────────────────────────

std::vector<Bytes> blobs_of_ndb(const Bytes& file) {
    auto b = generous();
    std::vector<Bytes> out;
    const auto r = read_rpm_ndb(memory_source(file), b, [&out](std::span<const std::uint8_t> blob) -> PkgDbVoid {
        out.emplace_back(blob.begin(), blob.end());
        return {};
    });
    REQUIRE(r.has_value());
    return out;
}

std::vector<Bytes> blobs_of_bdb(const Bytes& file) {
    auto b = generous();
    std::vector<Bytes> out;
    const auto r = read_rpm_bdb(memory_source(file), b, [&out](std::span<const std::uint8_t> blob) -> PkgDbVoid {
        out.emplace_back(blob.begin(), blob.end());
        return {};
    });
    REQUIRE(r.has_value());
    return out;
}

// Header blobs out of a sqlite rpmdb, through the sqlite API on a COPY in a temp dir (a copy so no
// sidecar is ever created in the source tree). Read-write open on the copy keeps this portable.
std::vector<Bytes> blobs_of_sqlite(std::string_view capture) {
    yuzu::test::TempDir dir{"yuzu_test_rpmdb_"};
    fs::create_directories(dir.path);
    const fs::path copy = dir.path / "rpmdb.sqlite";
    fs::copy_file(pkgdb_fixture(capture, "rpmdb.sqlite"), copy);
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(copy.string().c_str(), &db) == SQLITE_OK);
    sqlite3_stmt* st = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, "SELECT blob FROM Packages", -1, &st, nullptr) == SQLITE_OK);
    std::vector<Bytes> out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(st, 0));
        out.emplace_back(p, p + sqlite3_column_bytes(st, 0));
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return out;
}

struct Capture {
    const char* name;
    const char* file;
    enum Kind { sqlite, ndb, bdb } kind;
};
constexpr Capture kCaptures[] = {
    {"fedora41", "rpmdb.sqlite", Capture::sqlite}, {"alma9", "rpmdb.sqlite", Capture::sqlite},
    {"leap156", "Packages.db", Capture::ndb},      {"tumbleweed", "Packages.db", Capture::ndb},
    {"alma8", "Packages", Capture::bdb},           {"alma8-s390x", "Packages", Capture::bdb},
};

std::vector<Bytes> blobs_of(const Capture& c) {
    switch (c.kind) {
    case Capture::sqlite: return blobs_of_sqlite(c.name);
    case Capture::ndb: return blobs_of_ndb(read_bytes(pkgdb_fixture(c.name, c.file)));
    case Capture::bdb: return blobs_of_bdb(read_bytes(pkgdb_fixture(c.name, c.file)));
    }
    return {};
}

RpmPackage package_of(const Bytes& blob) {
    auto h = RpmHeader::parse(blob);
    REQUIRE(h.has_value());
    auto p = rpm_package_from_header(*h);
    REQUIRE(p.has_value());
    return std::move(*p);
}

// ── blob / file editing (big-endian header fields, either-endian container fields) ────────

void put_be32(Bytes& b, std::size_t off, std::uint32_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 24);
    b[off + 1] = static_cast<std::uint8_t>(v >> 16);
    b[off + 2] = static_cast<std::uint8_t>(v >> 8);
    b[off + 3] = static_cast<std::uint8_t>(v);
}
std::uint32_t get_be32(const Bytes& b, std::size_t off) {
    return std::uint32_t{b[off]} << 24 | std::uint32_t{b[off + 1]} << 16 |
           std::uint32_t{b[off + 2]} << 8 | std::uint32_t{b[off + 3]};
}
void put32(Bytes& b, std::size_t off, std::uint32_t v, bool be) {
    if (be) {
        put_be32(b, off, v);
        return;
    }
    b[off] = static_cast<std::uint8_t>(v);
    b[off + 1] = static_cast<std::uint8_t>(v >> 8);
    b[off + 2] = static_cast<std::uint8_t>(v >> 16);
    b[off + 3] = static_cast<std::uint8_t>(v >> 24);
}
std::uint32_t get32(const Bytes& b, std::size_t off, bool be) {
    return be ? get_be32(b, off)
              : std::uint32_t{b[off + 3]} << 24 | std::uint32_t{b[off + 2]} << 16 |
                    std::uint32_t{b[off + 1]} << 8 | std::uint32_t{b[off]};
}
void put16(Bytes& b, std::size_t off, std::uint16_t v, bool be) {
    if (be) {
        b[off] = static_cast<std::uint8_t>(v >> 8);
        b[off + 1] = static_cast<std::uint8_t>(v);
    } else {
        b[off] = static_cast<std::uint8_t>(v);
        b[off + 1] = static_cast<std::uint8_t>(v >> 8);
    }
}
std::uint16_t get16(const Bytes& b, std::size_t off, bool be) {
    return be ? static_cast<std::uint16_t>(b[off] << 8 | b[off + 1])
              : static_cast<std::uint16_t>(b[off + 1] << 8 | b[off]);
}

// Byte offset of the index entry for `tag` in a header blob, or 0.
std::size_t entry_of(const Bytes& blob, std::uint32_t tag) {
    const std::uint32_t il = get_be32(blob, 0);
    for (std::uint32_t i = 0; i < il; ++i)
        if (get_be32(blob, 8 + 16ull * i) == tag)
            return 8 + 16ull * i;
    return 0;
}

// The first real blob of `c` carrying `tag` (for example an EPOCH).
Bytes blob_with(const Capture& c, std::uint32_t tag) {
    for (auto& b : blobs_of(c))
        if (entry_of(b, tag) != 0)
            return b;
    FAIL("no blob with tag " << tag << " in " << c.name);
    return {};
}

} // namespace

// ── header parser on real blobs ─────────────────────────────────────────────

TEST_CASE("rpm header: every real blob of every capture parses to rpm's own queryformat output",
          "[rpmdb][pkgdb]") {
    for (const auto& c : kCaptures) {
        INFO(c.name);
        const auto blobs = blobs_of(c);
        // NAME EPOCH VERSION RELEASE ARCH INSTALLTIME:date SIGPGP RSAHEADER VENDOR PACKAGER
        auto oracle = oracle_lines(c.name);
        REQUIRE(blobs.size() == oracle.size());
        std::multimap<std::string, std::vector<std::string>> by_key;
        for (const auto& line : oracle) {
            auto f = split_tabs(line);
            REQUIRE(f.size() == 10);
            by_key.emplace(f[0] + "\t" + f[2] + "\t" + f[3], std::move(f));
        }
        for (const auto& blob : blobs) {
            const RpmPackage p = package_of(blob);
            const auto it = by_key.find(p.name + "\t" + p.version + "\t" + p.release);
            REQUIRE(it != by_key.end());
            const auto& f = it->second;
            const auto none = [](const std::string& v) { return v == "(none)" ? std::string{} : v; };
            CHECK(p.epoch.has_value() == (f[1] != "(none)"));
            if (p.epoch)
                CHECK(std::to_string(*p.epoch) == f[1]);
            CHECK(p.arch == none(f[4]));
            REQUIRE(p.install_time.has_value());
            CHECK(rpm_date_c_locale(utc_tm(*p.install_time)) == f[5]); // the containers ran in UTC
            CHECK(p.sigpgp == (f[6] != "(none)"));
            CHECK(p.rsaheader == (f[7] != "(none)"));
            CHECK(p.vendor == none(f[8]));
            CHECK(p.packager == none(f[9]));
            by_key.erase(it);
        }
        CHECK(by_key.empty());
    }
}

TEST_CASE("rpm header: the real captures cover an epoch and a header over 8 KB", "[rpmdb][pkgdb]") {
    // The fixture selection is the coverage claim: assert it, so a re-trim cannot silently drop it.
    for (const auto& c : kCaptures) {
        INFO(c.name);
        bool large = false;
        for (const auto& b : blobs_of(c))
            large = large || b.size() > 8192;
        CHECK(large);
    }
    for (const char* name : {"fedora41", "alma9", "alma8"}) {
        const Capture* cap = nullptr;
        for (const auto& c : kCaptures)
            if (std::string_view{c.name} == name)
                cap = &c;
        REQUIRE(cap != nullptr);
        bool epoch = false;
        for (const auto& b : blobs_of(*cap))
            epoch = epoch || package_of(b).epoch.has_value();
        CHECK(epoch);
    }
}

TEST_CASE("rpm header: gpg-pubkey has no arch, no signature and a packager", "[rpmdb][pkgdb]") {
    for (const auto& c : kCaptures) {
        INFO(c.name);
        bool seen = false;
        for (const auto& blob : blobs_of(c)) {
            const RpmPackage p = package_of(blob);
            if (p.name != "gpg-pubkey")
                continue;
            seen = true;
            CHECK(p.arch.empty());
            CHECK_FALSE(p.sigpgp);
            CHECK_FALSE(p.rsaheader);
            CHECK_FALSE(p.packager.empty());
        }
        CHECK(seen);
    }
}

// ── date formatter ──────────────────────────────────────────────────────────

TEST_CASE("rpm date: C-locale %c with a space-padded day, from a tm the caller supplies",
          "[rpmdb][pkgdb]") {
    // SYNTHETIC (the only synthetic input in this file): a single-digit day of month. The real
    // captures' install times are covered by the header case above, which compares every one with
    // rpm's own text.
    std::tm t{};
    t.tm_year = 2026 - 1900;
    t.tm_mon = 10; // November
    t.tm_mday = 5;
    t.tm_hour = 7;
    t.tm_min = 4;
    t.tm_sec = 9;
    t.tm_wday = 4; // Thursday
    CHECK(rpm_date_c_locale(t) == "Thu Nov  5 07:04:09 2026");
    t.tm_mday = 15;
    CHECK(rpm_date_c_locale(t) == "Thu Nov 15 07:04:09 2026");
    // 1 Jan 1970 00:00:00 UTC is a Thursday.
    CHECK(rpm_date_c_locale(utc_tm(0)) == "Thu Jan  1 00:00:00 1970");
    // The 32-bit maximum, as rpm stores INSTALLTIME.
    CHECK(rpm_date_c_locale(utc_tm(0xFFFFFFFFll)) == "Sun Feb  7 06:28:15 2106");
    // A tm with an out-of-range weekday or month renders empty instead of indexing past the tables.
    std::tm bad = t;
    bad.tm_wday = 7;
    CHECK(rpm_date_c_locale(bad).empty());
    bad = t;
    bad.tm_mon = -1;
    CHECK(rpm_date_c_locale(bad).empty());
}

// ── header hostile (edited real blob) ───────────────────────────────────────

TEST_CASE("rpm header hostile: edited real blob with a bad il, dl, offset, string or count",
          "[rpmdb][pkgdb]") {
    const Capture& alma9 = kCaptures[1];
    const Bytes good = blob_with(alma9, rpm_tag::kEpoch);
    REQUIRE(RpmHeader::parse(good).has_value());
    const auto parse_err = [](const Bytes& b) {
        const auto h = RpmHeader::parse(b);
        REQUIRE_FALSE(h.has_value());
        return h.error();
    };
    const auto package_err = [](const Bytes& b) {
        const auto h = RpmHeader::parse(b);
        REQUIRE(h.has_value());
        const auto p = rpm_package_from_header(*h);
        REQUIRE_FALSE(p.has_value());
        return p.error();
    };

    SECTION("edited il = 0") {
        Bytes b = good;
        put_be32(b, 0, 0);
        CHECK(parse_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited il = 0xFFFFFFFF (a 32-bit 16 * il would wrap)") {
        Bytes b = good;
        put_be32(b, 0, 0xFFFFFFFFu);
        CHECK(parse_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited il one past the real count") {
        Bytes b = good;
        put_be32(b, 0, get_be32(good, 0) + 1);
        CHECK(parse_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited dl one short and one long") {
        Bytes b = good;
        put_be32(b, 4, get_be32(good, 4) - 1);
        CHECK(parse_err(b) == PkgDbCause::corrupt);
        put_be32(b, 4, get_be32(good, 4) + 1);
        CHECK(parse_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited dl above the 256 MiB structural cap is oversized") {
        Bytes b = good;
        put_be32(b, 4, 0x7FFFFFFFu);
        CHECK(parse_err(b) == PkgDbCause::oversized);
    }
    SECTION("edited NAME offset past dl") {
        Bytes b = good;
        put_be32(b, entry_of(good, rpm_tag::kName) + 8, get_be32(good, 4) + 100);
        CHECK(package_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited data store with no NUL anywhere: a string without a terminator") {
        Bytes b = good;
        const std::size_t data = 8 + 16ull * get_be32(good, 0);
        std::fill(b.begin() + static_cast<std::ptrdiff_t>(data), b.end(), std::uint8_t{'A'});
        CHECK(package_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited NAME type: a string tag that is not a string") {
        Bytes b = good;
        put_be32(b, entry_of(good, rpm_tag::kName) + 4, rpm_type::kInt32);
        CHECK(package_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited EPOCH count = 0") {
        Bytes b = good;
        put_be32(b, entry_of(good, rpm_tag::kEpoch) + 12, 0);
        CHECK(package_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited EPOCH offset so the int32 runs past dl") {
        Bytes b = good;
        put_be32(b, entry_of(good, rpm_tag::kEpoch) + 8, get_be32(good, 4) - 2);
        CHECK(package_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited RSAHEADER count past dl") {
        Bytes b = good;
        const std::size_t e = entry_of(good, rpm_tag::kRsaHeader);
        REQUIRE(e != 0);
        put_be32(b, e + 12, get_be32(good, 4) + 1);
        CHECK(package_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited NAME tag renamed away: no NAME is corrupt, never an empty row") {
        Bytes b = good;
        put_be32(b, entry_of(good, rpm_tag::kName), 99999);
        CHECK(package_err(b) == PkgDbCause::corrupt);
    }
    SECTION("edited blob cut at every length: a prefix never parses") {
        // Every prefix of the first 512 bytes, then a stride across the rest (including size - 1).
        for (std::size_t n = 0; n < std::min<std::size_t>(512, good.size()); ++n)
            REQUIRE_FALSE(RpmHeader::parse(std::span<const std::uint8_t>(good).first(n)).has_value());
        for (std::size_t n = 512; n < good.size(); n += 97)
            REQUIRE_FALSE(RpmHeader::parse(std::span<const std::uint8_t>(good).first(n)).has_value());
        REQUIRE_FALSE(RpmHeader::parse(std::span<const std::uint8_t>(good).first(good.size() - 1)).has_value());
        // And one byte too many.
        Bytes longer = good;
        longer.push_back(0);
        REQUIRE_FALSE(RpmHeader::parse(longer).has_value());
    }
}

// ── memory source ───────────────────────────────────────────────────────────

TEST_CASE("memory_source: serves in-range reads and refuses out-of-range ones", "[rpmdb][pkgdb]") {
    const Bytes data{1, 2, 3, 4, 5};
    const ByteSource s = memory_source(data);
    CHECK(s.size == 5);
    Bytes out(3);
    CHECK(s.read_at(1, out));
    CHECK(out == Bytes{2, 3, 4});
    CHECK(s.read_at(5, std::span<std::uint8_t>{}));
    CHECK_FALSE(s.read_at(3, out));
    CHECK_FALSE(s.read_at(6, std::span<std::uint8_t>{}));
    CHECK_FALSE(s.read_at(~std::uint64_t{0}, out));
}

// ── ndb ─────────────────────────────────────────────────────────────────────

namespace {

std::multiset<std::string> names_of(const std::vector<Bytes>& blobs) {
    std::multiset<std::string> out;
    for (const auto& b : blobs)
        out.insert(package_of(b).name);
    return out;
}

std::multiset<std::string> oracle_names(std::string_view capture) {
    std::multiset<std::string> out;
    for (const auto& line : oracle_lines(capture))
        out.insert(split_tabs(line)[0]);
    return out;
}

PkgDbVoid run_ndb(const Bytes& file, PkgDbBudget& b, std::size_t* delivered = nullptr) {
    return read_rpm_ndb(memory_source(file), b, [delivered](std::span<const std::uint8_t>) -> PkgDbVoid {
        if (delivered)
            ++*delivered;
        return {};
    });
}
PkgDbVoid run_bdb(const Bytes& file, PkgDbBudget& b, std::size_t* delivered = nullptr) {
    return read_rpm_bdb(memory_source(file), b, [delivered](std::span<const std::uint8_t>) -> PkgDbVoid {
        if (delivered)
            ++*delivered;
        return {};
    });
}

// Offset of the first OCCUPIED ndb slot (pkgidx != 0), and its decoded block fields.
struct NdbSlot {
    std::size_t slot = 0;
    std::uint64_t blk_start = 0;
    std::uint64_t blk_len = 0;
};
NdbSlot first_ndb_slot(const Bytes& f) {
    const std::uint32_t slotnpages = get32(f, 12, false);
    for (std::size_t off = 32; off < slotnpages * 4096ull; off += 16)
        if (get32(f, off + 4, false) != 0)
            return {off, get32(f, off + 8, false) * 16ull, get32(f, off + 12, false) * 16ull};
    FAIL("no occupied ndb slot");
    return {};
}

} // namespace

TEST_CASE("ndb: leap156 and tumbleweed real captures give rpm's own package names, empty slots skipped",
          "[rpmdb][pkgdb]") {
    for (const char* name : {"leap156", "tumbleweed"}) {
        INFO(name);
        const Bytes file = read_bytes(pkgdb_fixture(name, "Packages.db"));
        const auto blobs = blobs_of_ndb(file);
        CHECK(names_of(blobs) == oracle_names(name));
        // The slot table is larger than the package count: empty slots exist and are skipped.
        const std::uint32_t slotnpages = get32(file, 12, false);
        std::size_t slots = 0;
        for (std::size_t off = 32; off < slotnpages * 4096ull; off += 16)
            ++slots;
        CHECK(slots > blobs.size());
    }
}

TEST_CASE("ndb hostile: edited real file with a bad magic, version, slot count, block or trailer",
          "[rpmdb][pkgdb]") {
    const Bytes good = read_bytes(pkgdb_fixture("leap156", "Packages.db"));
    {
        auto b = generous();
        REQUIRE(run_ndb(good, b).has_value());
    }
    const auto cause = [](const Bytes& f, PkgDbBudget b = generous()) {
        const auto r = run_ndb(f, b);
        REQUIRE_FALSE(r.has_value());
        return r.error();
    };
    const NdbSlot s = first_ndb_slot(good);

    SECTION("edited header magic") {
        Bytes f = good;
        f[0] = 'X';
        CHECK(cause(f) == PkgDbCause::unsupported_format);
    }
    SECTION("edited version = 1") {
        Bytes f = good;
        put32(f, 4, 1, false);
        CHECK(cause(f) == PkgDbCause::unsupported_format);
    }
    SECTION("edited slotnpages past the file") {
        Bytes f = good;
        put32(f, 12, static_cast<std::uint32_t>(good.size() / 4096 + 1), false);
        CHECK(cause(f) == PkgDbCause::truncated);
        put32(f, 12, 0xFFFFFFFFu, false); // 4096 * 2^32 would wrap a 32-bit product
        CHECK(cause(f) == PkgDbCause::truncated);
    }
    SECTION("edited slotnpages = 0") {
        Bytes f = good;
        put32(f, 12, 0, false);
        CHECK(cause(f) == PkgDbCause::corrupt);
    }
    SECTION("edited slot magic") {
        Bytes f = good;
        f[s.slot] = 'X';
        CHECK(cause(f) == PkgDbCause::corrupt);
    }
    SECTION("edited block offset past the file") {
        Bytes f = good;
        put32(f, s.slot + 8, static_cast<std::uint32_t>(good.size() / 16 + 100), false);
        CHECK(cause(f) == PkgDbCause::truncated);
        put32(f, s.slot + 8, 0xFFFFFFFFu, false);
        CHECK(cause(f) == PkgDbCause::truncated);
    }
    SECTION("edited block count too small for a blob head and tail") {
        Bytes f = good;
        put32(f, s.slot + 12, 1, false);
        CHECK(cause(f) == PkgDbCause::corrupt);
    }
    SECTION("edited blob magic") {
        Bytes f = good;
        f[s.blk_start] = 'X';
        CHECK(cause(f) == PkgDbCause::corrupt);
    }
    SECTION("edited blob pkgidx not equal to its slot's") {
        Bytes f = good;
        put32(f, s.blk_start + 4, get32(good, s.blk_start + 4, false) + 1, false);
        CHECK(cause(f) == PkgDbCause::corrupt);
    }
    SECTION("edited blob length over the per-header cap is oversized") {
        Bytes f = good;
        put32(f, s.blk_start + 12, 0x7FFFFFFFu, false);
        CHECK(cause(f) == PkgDbCause::oversized);
        // A cap below the real header size trips the same cause on the unedited file.
        auto small = generous();
        small.max_item_bytes = 100;
        CHECK(cause(good, small) == PkgDbCause::oversized);
    }
    SECTION("edited blob length that does not fit its blocks") {
        Bytes f = good;
        put32(f, s.blk_start + 12, static_cast<std::uint32_t>(s.blk_len), false);
        CHECK(cause(f) == PkgDbCause::corrupt);
    }
    SECTION("edited trailer length mismatch") {
        Bytes f = good;
        const std::size_t tail = s.blk_start + s.blk_len - 12;
        put32(f, tail + 4, get32(good, tail + 4, false) + 1, false);
        CHECK(cause(f) == PkgDbCause::corrupt);
    }
    SECTION("edited trailer magic") {
        Bytes f = good;
        f[s.blk_start + s.blk_len - 1] = 'X';
        CHECK(cause(f) == PkgDbCause::corrupt);
    }
    SECTION("edited file cut at every length: a truncated file never reads as complete") {
        // The last block ends at `last_end`; any shorter file must fail.
        std::uint64_t last_end = 0;
        const std::uint32_t slotnpages = get32(good, 12, false);
        for (std::size_t off = 32; off < slotnpages * 4096ull; off += 16)
            if (get32(good, off + 4, false) != 0)
                last_end = std::max<std::uint64_t>(last_end, (get32(good, off + 8, false) + get32(good, off + 12, false)) * 16ull);
        for (std::uint64_t n = 0; n < last_end; n += (n < 128 ? 1 : 509)) {
            auto b = generous();
            const Bytes cut(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(n));
            REQUIRE_FALSE(run_ndb(cut, b).has_value());
        }
        auto b = generous();
        const Bytes cut(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(last_end - 1));
        REQUIRE_FALSE(run_ndb(cut, b).has_value());
    }
}

// ── Berkeley DB hash ────────────────────────────────────────────────────────

TEST_CASE("bdb: alma8 little-endian and alma8-s390x big-endian give rpm's own package names, the "
          "counter record skipped",
          "[rpmdb][pkgdb]") {
    for (const char* name : {"alma8", "alma8-s390x"}) {
        INFO(name);
        const Bytes file = read_bytes(pkgdb_fixture(name, "Packages"));
        // The two files differ in byte order: the meta page magic reads 0x00061561 one way each.
        const bool be = std::string_view{name} == "alma8-s390x";
        CHECK(get32(file, 12, be) == 0x00061561u);
        CHECK(get32(file, 12, !be) != 0x00061561u);
        const auto blobs = blobs_of_bdb(file);
        CHECK(names_of(blobs) == oracle_names(name));
        // rpm's counter record (the all-zero key) is not a header; had it been delivered, its
        // 4-byte data would have failed the header parser and blobs_of_bdb's REQUIRE.
        CHECK(blobs.size() == oracle_names(name).size());
    }
}

namespace {

// What the bdb hostile cases need to know about a real file.
struct BdbView {
    bool be = false;
    std::uint32_t pagesize = 0;
    std::uint32_t last_pgno = 0;
    std::size_t off_page_page = 0;      // page number of the first hash page with an off-page data item
    std::size_t item_off = 0;           // byte offset of that item within the page
    std::uint32_t first_overflow = 0;   // pgno of the first overflow page of its chain
    std::uint32_t second_overflow = 0;  // pgno of the second (0 if the chain has one page)
    std::uint32_t total_len = 0;
};

BdbView view_of(const Bytes& f) {
    BdbView v;
    v.be = get32(f, 12, false) != 0x00061561u;
    v.pagesize = get32(f, 20, v.be);
    v.last_pgno = get32(f, 32, v.be);
    for (std::uint32_t pg = 1; pg <= v.last_pgno; ++pg) {
        const std::size_t base = std::size_t{pg} * v.pagesize;
        if (f[base + 25] != 13)
            continue;
        const std::size_t n = get16(f, base + 20, v.be);
        for (std::size_t i = 1; i < n; i += 2) {
            const std::size_t item = get16(f, base + 26 + 2 * i, v.be);
            if (f[base + item] != 3)
                continue;
            v.off_page_page = pg;
            v.item_off = item;
            v.first_overflow = get32(f, base + item + 4, v.be);
            v.total_len = get32(f, base + item + 8, v.be);
            v.second_overflow = get32(f, std::size_t{v.first_overflow} * v.pagesize + 16, v.be);
            return v;
        }
    }
    FAIL("no off-page item in the bdb fixture");
    return v;
}

} // namespace

TEST_CASE("bdb hostile: edited real file with a bad magic, version, page size, count, offset or chain",
          "[rpmdb][pkgdb]") {
    for (const char* name : {"alma8", "alma8-s390x"}) {
        INFO(name);
        const Bytes good = read_bytes(pkgdb_fixture(name, "Packages"));
        const BdbView v = view_of(good);
        REQUIRE(v.first_overflow >= 1);
        REQUIRE(v.second_overflow != 0); // the chain has at least two pages (a header over 4 KB)
        const bool be = v.be;
        const std::size_t page_base = v.off_page_page * std::size_t{v.pagesize};
        const std::size_t first_base = std::size_t{v.first_overflow} * v.pagesize;
        const std::size_t second_base = std::size_t{v.second_overflow} * v.pagesize;
        {
            auto b = generous();
            REQUIRE(run_bdb(good, b).has_value());
        }
        const auto cause = [](const Bytes& f, PkgDbBudget b = generous()) {
            const auto r = run_bdb(f, b);
            REQUIRE_FALSE(r.has_value());
            return r.error();
        };

        SECTION("edited meta magic") {
            Bytes f = good;
            f[12] ^= 0xFF;
            f[15] ^= 0xFF;
            CHECK(cause(f) == PkgDbCause::unsupported_format);
        }
        SECTION("edited hash version 8, and 10") {
            Bytes f = good;
            put32(f, 16, 8, be);
            CHECK(cause(f) == PkgDbCause::unsupported_format);
            put32(f, 16, 10, be);
            CHECK(cause(f) == PkgDbCause::unsupported_format);
        }
        SECTION("edited encryption byte") {
            Bytes f = good;
            f[24] = 1;
            CHECK(cause(f) == PkgDbCause::unsupported_format);
        }
        SECTION("edited page size 0, 3000, 256 and 1 MiB") {
            for (std::uint32_t ps : {0u, 3000u, 256u, 1u << 20}) {
                Bytes f = good;
                put32(f, 20, ps, be);
                CHECK(cause(f) == PkgDbCause::corrupt);
            }
        }
        SECTION("edited meta type byte") {
            Bytes f = good;
            f[25] = 9;
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited last_pgno past the file is truncated, even at 0xFFFFFFFF") {
            Bytes f = good;
            put32(f, 32, v.last_pgno + 1, be);
            CHECK(cause(f) == PkgDbCause::truncated);
            put32(f, 32, 0xFFFFFFFFu, be);
            CHECK(cause(f) == PkgDbCause::truncated);
        }
        SECTION("edited odd entry count on a hash page") {
            Bytes f = good;
            put16(f, page_base + 20, static_cast<std::uint16_t>(get16(good, page_base + 20, be) + 1), be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited entry count that overruns the page") {
            Bytes f = good;
            put16(f, page_base + 20, static_cast<std::uint16_t>(v.pagesize), be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited item offsets: outside the page, into the offset array, and not decreasing") {
            Bytes f = good;
            put16(f, page_base + 26, static_cast<std::uint16_t>(v.pagesize), be); // == page size
            CHECK(cause(f) == PkgDbCause::corrupt);
            f = good;
            put16(f, page_base + 26, 0xFFFF, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
            f = good;
            put16(f, page_base + 26, 4, be); // inside the page header
            CHECK(cause(f) == PkgDbCause::corrupt);
            f = good;
            put16(f, page_base + 28, get16(good, page_base + 26, be), be); // equal to the previous
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited item type 2 (duplicate) and 4 (off-page duplicate) are not decoded") {
            Bytes f = good;
            f[page_base + v.item_off] = 2;
            CHECK(cause(f) == PkgDbCause::unsupported_format);
            f[page_base + v.item_off] = 4;
            CHECK(cause(f) == PkgDbCause::unsupported_format);
            f[page_base + v.item_off] = 7; // an unknown type
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited off-page first pgno outside [1, last_pgno]") {
            Bytes f = good;
            put32(f, page_base + v.item_off + 4, 0, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
            put32(f, page_base + v.item_off + 4, v.last_pgno + 1, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited overflow chain: a page that points at itself") {
            Bytes f = good;
            put32(f, first_base + 16, v.first_overflow, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited overflow chain: a two-page loop") {
            Bytes f = good;
            put32(f, second_base + 16, v.first_overflow, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited overflow chain: next page past last_pgno") {
            Bytes f = good;
            put32(f, first_base + 16, v.last_pgno + 1, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited overflow chain: an overflow page of the wrong type") {
            Bytes f = good;
            f[first_base + 25] = 13;
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited overflow chain: bytes used of 0 and past the page") {
            Bytes f = good;
            put16(f, first_base + 22, 0, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
            put16(f, first_base + 22, static_cast<std::uint16_t>(v.pagesize), be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited total length over the per-header cap is oversized") {
            Bytes f = good;
            put32(f, page_base + v.item_off + 8, 0x7FFFFFFFu, be);
            CHECK(cause(f) == PkgDbCause::oversized);
            auto small = generous();
            small.max_item_bytes = 100;
            CHECK(cause(good, small) == PkgDbCause::oversized);
        }
        SECTION("edited total length larger than the file is corrupt, never an allocation") {
            Bytes f = good;
            put32(f, page_base + v.item_off + 8, static_cast<std::uint32_t>(good.size() + 1), be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited total length: a chain shorter than its length, a chain longer, and zero") {
            Bytes f = good;
            put32(f, page_base + v.item_off + 8, v.total_len + 1, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
            put32(f, page_base + v.item_off + 8, v.total_len - 1, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
            put32(f, page_base + v.item_off + 8, 0, be);
            CHECK(cause(f) == PkgDbCause::corrupt);
        }
        SECTION("edited file cut at every length: a truncated file is truncated") {
            for (std::size_t n = 0; n < good.size(); n += (n < 600 ? 1 : 997)) {
                auto b = generous();
                const Bytes cut(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(n));
                const auto r = run_bdb(cut, b);
                REQUIRE_FALSE(r.has_value());
                CHECK(r.error() == PkgDbCause::truncated);
            }
            auto b = generous();
            const Bytes cut(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(good.size() - 1));
            const auto r = run_bdb(cut, b);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == PkgDbCause::truncated);
        }
        SECTION("edited unreadable source: a read failure is unreadable, not a guess") {
            ByteSource flaky = memory_source(good);
            flaky.read_at = [](std::uint64_t, std::span<std::uint8_t>) { return false; };
            auto b = generous();
            const auto r = read_rpm_bdb(flaky, b, [](std::span<const std::uint8_t>) -> PkgDbVoid { return {}; });
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == PkgDbCause::unreadable);
        }
    }
}

// ── budget ──────────────────────────────────────────────────────────────────

TEST_CASE("budget: byte cap, row cap and an expired clock each stop ndb and bdb with the named cause",
          "[rpmdb][pkgdb]") {
    const Bytes ndb = read_bytes(pkgdb_fixture("leap156", "Packages.db"));
    const Bytes bdb = read_bytes(pkgdb_fixture("alma8", "Packages"));
    struct Reader {
        const char* label;
        const Bytes* file;
        PkgDbVoid (*run)(const Bytes&, PkgDbBudget&, std::size_t*);
    };
    for (const Reader& r : {Reader{"ndb", &ndb, run_ndb}, Reader{"bdb", &bdb, run_bdb}}) {
        INFO(r.label);
        std::size_t delivered = 0;
        {
            auto b = generous();
            b.rows_left = 1; // the files hold more than one package
            const auto res = r.run(*r.file, b, &delivered);
            REQUIRE_FALSE(res.has_value());
            CHECK(res.error() == PkgDbCause::row_cap);
            CHECK(delivered == 1); // the one admitted row was delivered, the next refused
        }
        {
            auto b = generous();
            b.bytes_left = 100; // smaller than any header
            delivered = 0;
            const auto res = r.run(*r.file, b, &delivered);
            REQUIRE_FALSE(res.has_value());
            CHECK(res.error() == PkgDbCause::byte_cap);
            CHECK(delivered == 0);
        }
        {
            auto b = generous();
            b.expired = [] { return true; };
            delivered = 0;
            const auto res = r.run(*r.file, b, &delivered);
            REQUIRE_FALSE(res.has_value());
            CHECK(res.error() == PkgDbCause::timeout);
            CHECK(delivered == 0);
        }
        {
            // An exact fill is admitted: rows_left == package count reads clean.
            auto b = generous();
            std::size_t count = 0;
            REQUIRE(r.run(*r.file, b, &count).has_value());
            auto exact = generous();
            exact.rows_left = count;
            CHECK(r.run(*r.file, exact, nullptr).has_value());
        }
        {
            // A callback failure stops the walk and is returned as is.
            auto b = generous();
            const auto res = std::string_view{r.label} == "ndb"
                                 ? read_rpm_ndb(memory_source(*r.file), b, [](std::span<const std::uint8_t>) -> PkgDbVoid { return std::unexpected(PkgDbCause::corrupt); })
                                 : read_rpm_bdb(memory_source(*r.file), b, [](std::span<const std::uint8_t>) -> PkgDbVoid { return std::unexpected(PkgDbCause::corrupt); });
            REQUIRE_FALSE(res.has_value());
            CHECK(res.error() == PkgDbCause::corrupt);
        }
    }
}

TEST_CASE("budget: the cause vocabulary is closed and delimiter-free", "[rpmdb][pkgdb]") {
    const PkgDbCause all[] = {PkgDbCause::unreadable,  PkgDbCause::symlink_refused,
                              PkgDbCause::not_regular, PkgDbCause::oversized,
                              PkgDbCause::corrupt,     PkgDbCause::truncated,
                              PkgDbCause::unsupported_format, PkgDbCause::locked,
                              PkgDbCause::changed_during_read, PkgDbCause::row_cap,
                              PkgDbCause::byte_cap,    PkgDbCause::timeout,
                              PkgDbCause::busy};
    std::set<std::string> seen;
    for (const PkgDbCause c : all) {
        const std::string t{pkgdb_cause_token(c)};
        CHECK_FALSE(t.empty());
        CHECK(t.find_first_not_of("abcdefghijklmnopqrstuvwxyz_") == std::string::npos);
        CHECK(seen.insert(t).second);
    }
    CHECK(seen.size() == 13);
}
