#pragma once

/**
 * rpmdb_parsers.hpp -- pure readers for the rpm package database containers and
 * the rpm header blob they all store.
 *
 * Every rpm database format keeps the same thing: one whole rpm HEADER BLOB per
 * installed package (sqlite `Packages(hnum, blob)`, ndb `Packages.db` slots, Berkeley DB
 * hash records), so ONE header parser serves all three and each container needs only a small
 * reader that hands over one blob at a time. The sqlite container is read through the sqlite
 * API in the plugin shell (it needs a connection, not a byte source); this header holds
 * the two containers that are plain bytes:
 *
 *   read_rpm_ndb  -- the SUSE `Packages.db` slot file (little-endian)
 *   read_rpm_bdb  -- the RHEL 7/8 family Berkeley DB hash `Packages` file (either byte
 *                    order, page sizes 512 to 65536, hash version 9)
 *
 * Header-only, no I/O of its own: both read through an injected ByteSource (a
 * pread over a descriptor in production, a span in a test), one blob in memory at
 * a time, so peak memory is one header and never the whole file.
 *
 * Hostile-input contract (the database is root-owned but the bytes are not
 * trusted; a bad record must never become a memory error in every agent):
 *   - every length, count and offset is checked in 64-bit arithmetic against the
 *     file size, the per-item cap and the byte budget BEFORE anything is
 *     allocated or read from it;
 *   - every loop is bounded (slot count, page count, a step counter on overflow
 *     chains) and polls the budget's clock;
 *   - no function throws on input; failures are a PkgDbCause (pkgdb_budget.hpp)
 *     and a failure yields no partial result.
 *
 * Layouts were read off real captures (little-endian arm64 and big-endian s390x
 * Berkeley DB, ndb from two SUSE releases) and are stated at each reader.
 * Proven on real data: 4096-byte pages and hash version 9. The reader accepts other
 * power-of-two page sizes by construction, but ONLY version 9 is decoded; any other
 * version answers unsupported_format rather than guessing.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <expected>
#include <format>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pkgdb_budget.hpp"

namespace yuzu::shared {

// ── random-access source ────────────────────────────────────────────────────

/// A read-only random-access view of one database file. `read_at` fills `out`
/// completely or returns false (I/O error or short read); the reader checks the
/// range against `size` first, so a source never sees an out-of-file request.
struct ByteSource {
    std::uint64_t size = 0;
    std::function<bool(std::uint64_t off, std::span<std::uint8_t> out)> read_at;
};

namespace rpmdb_detail {

/// The single integer-load helper of this header (byte order explicit). Callers
/// bounds-check first; an out-of-range request here returns 0 instead of reading
/// past the span, so a missed check degrades to a failed structure test, never UB.
[[nodiscard]] inline std::uint32_t load_u32(std::span<const std::uint8_t> s, std::size_t off,
                                            bool big_endian) noexcept {
    if (off > s.size() || s.size() - off < 4)
        return 0;
    const std::uint8_t* p = s.data() + off;
    return big_endian ? (std::uint32_t{p[0]} << 24 | std::uint32_t{p[1]} << 16 |
                         std::uint32_t{p[2]} << 8 | std::uint32_t{p[3]})
                      : (std::uint32_t{p[3]} << 24 | std::uint32_t{p[2]} << 16 |
                         std::uint32_t{p[1]} << 8 | std::uint32_t{p[0]});
}

[[nodiscard]] inline std::uint16_t load_u16(std::span<const std::uint8_t> s, std::size_t off,
                                            bool big_endian) noexcept {
    if (off > s.size() || s.size() - off < 2)
        return 0;
    const std::uint8_t* p = s.data() + off;
    return big_endian ? static_cast<std::uint16_t>(p[0] << 8 | p[1])
                      : static_cast<std::uint16_t>(p[1] << 8 | p[0]);
}

} // namespace rpmdb_detail

// ── the rpm header blob ─────────────────────────────────────────────────────

/// Tag numbers read from a header. Verified against every S-7 capture (the tag
/// number, its type and the value all reproduce `rpm -qa --queryformat` output).
namespace rpm_tag {
inline constexpr std::uint32_t kName = 1000;
inline constexpr std::uint32_t kVersion = 1001;
inline constexpr std::uint32_t kRelease = 1002;
inline constexpr std::uint32_t kEpoch = 1003;
inline constexpr std::uint32_t kInstallTime = 1008;
inline constexpr std::uint32_t kVendor = 1011;
inline constexpr std::uint32_t kPackager = 1015;
inline constexpr std::uint32_t kArch = 1022;
inline constexpr std::uint32_t kSigPgp = 259;
inline constexpr std::uint32_t kRsaHeader = 268;
} // namespace rpm_tag

/// rpm tag data types (rpmtd.h) used here.
namespace rpm_type {
inline constexpr std::uint32_t kInt32 = 4;
inline constexpr std::uint32_t kString = 6;
inline constexpr std::uint32_t kBin = 7;
} // namespace rpm_type

/// One header blob as stored by the database (no magic): `il` (index entries)
/// and `dl` (data bytes) as big-endian u32, then `il` 16-byte index entries
/// (tag, type, offset, count; big-endian), then `dl` data bytes. The structure is
/// validated once in parse(); an accessor then validates only the one entry it
/// reads, so a header with a bad tag nobody reads is still readable, and a bad
/// tag somebody reads fails the whole record (never a guessed value).
class RpmHeader {
public:
    static constexpr std::uint32_t kMaxIndexEntries = 65535;

    /// Borrows `blob`; it must outlive the header.
    [[nodiscard]] static std::expected<RpmHeader, PkgDbCause>
    parse(std::span<const std::uint8_t> blob) {
        if (blob.size() < 8)
            return std::unexpected(PkgDbCause::corrupt);
        const std::uint32_t il = rpmdb_detail::load_u32(blob, 0, true);
        const std::uint32_t dl = rpmdb_detail::load_u32(blob, 4, true);
        if (il < 1 || il > kMaxIndexEntries)
            return std::unexpected(PkgDbCause::corrupt);
        if (dl > kPkgDbMaxItemBytes)
            return std::unexpected(PkgDbCause::oversized);
        // 64-bit: 8 + 16 * 65535 + 256 MiB cannot overflow it, and a 32-bit sum could wrap.
        const std::uint64_t expect = 8ull + 16ull * il + dl;
        if (expect != blob.size())
            return std::unexpected(PkgDbCause::corrupt);
        return RpmHeader{blob, il, dl};
    }

    /// A type-6 string tag. nullopt = tag absent; an error = present but malformed.
    [[nodiscard]] std::expected<std::optional<std::string>, PkgDbCause>
    string(std::uint32_t tag) const {
        const auto e = find(tag);
        if (!e)
            return std::optional<std::string>{};
        if (e->type != rpm_type::kString || e->offset >= dl_)
            return std::unexpected(PkgDbCause::corrupt);
        const std::uint8_t* d = data_.data() + e->offset;
        const std::size_t room = dl_ - e->offset;
        const void* nul = std::memchr(d, 0, room);
        if (nul == nullptr)
            return std::unexpected(PkgDbCause::corrupt); // not NUL-terminated inside the data
        const auto len = static_cast<std::size_t>(static_cast<const std::uint8_t*>(nul) - d);
        // uint8_t -> char is a permitted aliasing cast; the length is bounded by the memchr over
        // `room` above (so d + len stays inside the data region) and the bytes are copied out, so
        // nothing here outlives data_.
        return std::optional<std::string>{std::string(reinterpret_cast<const char*>(d), len)};
    }

    /// A type-4 (int32) tag: the first value. nullopt = absent.
    [[nodiscard]] std::expected<std::optional<std::uint32_t>, PkgDbCause>
    int32(std::uint32_t tag) const {
        const auto e = find(tag);
        if (!e)
            return std::optional<std::uint32_t>{};
        if (e->type != rpm_type::kInt32 || e->count < 1 ||
            std::uint64_t{e->offset} + 4ull * e->count > dl_)
            return std::unexpected(PkgDbCause::corrupt);
        return std::optional<std::uint32_t>{rpmdb_detail::load_u32(data_, e->offset, true)};
    }

    /// A type-7 (binary) tag. nullopt = absent; an empty span = present with no bytes.
    [[nodiscard]] std::expected<std::optional<std::span<const std::uint8_t>>, PkgDbCause>
    bin(std::uint32_t tag) const {
        const auto e = find(tag);
        if (!e)
            return std::optional<std::span<const std::uint8_t>>{};
        if (e->type != rpm_type::kBin || std::uint64_t{e->offset} + e->count > dl_)
            return std::unexpected(PkgDbCause::corrupt);
        return std::optional<std::span<const std::uint8_t>>{data_.subspan(e->offset, e->count)};
    }

private:
    struct Entry {
        std::uint32_t type;
        std::uint32_t offset;
        std::uint32_t count;
    };

    RpmHeader(std::span<const std::uint8_t> blob, std::uint32_t il, std::uint32_t dl)
        : blob_(blob), il_(il), dl_(dl), data_(blob.subspan(8 + 16ull * il)) {}

    /// First index entry with `tag`. The index is `il_` entries and parse() proved it
    /// lies inside the blob, so the walk is a bounded linear scan.
    [[nodiscard]] std::optional<Entry> find(std::uint32_t tag) const {
        for (std::uint32_t i = 0; i < il_; ++i) {
            const std::size_t at = 8 + 16ull * i;
            if (rpmdb_detail::load_u32(blob_, at, true) != tag)
                continue;
            return Entry{rpmdb_detail::load_u32(blob_, at + 4, true),
                         rpmdb_detail::load_u32(blob_, at + 8, true),
                         rpmdb_detail::load_u32(blob_, at + 12, true)};
        }
        return std::nullopt;
    }

    std::span<const std::uint8_t> blob_;
    std::uint32_t il_;
    std::uint32_t dl_;
    std::span<const std::uint8_t> data_;
};

/// The fields a package row needs, lifted out of one header.
struct RpmPackage {
    std::string name;
    std::string version;
    std::string release;
    std::string arch;
    std::string vendor;
    std::string packager;
    std::optional<std::uint32_t> epoch;
    std::optional<std::uint32_t> install_time; ///< seconds since the Unix epoch (u32, as rpm reads it)
    bool sigpgp = false;                       ///< a non-empty SIGPGP (payload signature) tag
    bool rsaheader = false;                    ///< a non-empty RSAHEADER (header signature) tag
};

/// Lifts a RpmPackage out of a parsed header. No NAME is `corrupt`; every other
/// absent tag reads empty / nullopt / false (the honest-empty contract); a tag that
/// is present but malformed fails the record.
[[nodiscard]] inline std::expected<RpmPackage, PkgDbCause>
rpm_package_from_header(const RpmHeader& h) {
    RpmPackage p;
    const auto str = [&h](std::uint32_t tag, std::string& into) -> PkgDbVoid {
        auto v = h.string(tag);
        if (!v)
            return std::unexpected(v.error());
        if (*v)
            into = std::move(**v);
        return {};
    };
    if (auto r = str(rpm_tag::kName, p.name); !r)
        return std::unexpected(r.error());
    if (p.name.empty())
        return std::unexpected(PkgDbCause::corrupt);
    const std::array<std::pair<std::uint32_t, std::string*>, 5> texts{{
        {rpm_tag::kVersion, &p.version},
        {rpm_tag::kRelease, &p.release},
        {rpm_tag::kArch, &p.arch},
        {rpm_tag::kVendor, &p.vendor},
        {rpm_tag::kPackager, &p.packager},
    }};
    for (const auto& [tag, into] : texts) {
        if (auto r = str(tag, *into); !r)
            return std::unexpected(r.error());
    }
    if (auto e = h.int32(rpm_tag::kEpoch); e)
        p.epoch = *e;
    else
        return std::unexpected(e.error());
    if (auto t = h.int32(rpm_tag::kInstallTime); t)
        p.install_time = *t;
    else
        return std::unexpected(t.error());
    const std::array<std::pair<std::uint32_t, bool*>, 2> sigs{{
        {rpm_tag::kSigPgp, &p.sigpgp},
        {rpm_tag::kRsaHeader, &p.rsaheader},
    }};
    for (const auto& [tag, flag] : sigs) {
        auto b = h.bin(tag);
        if (!b)
            return std::unexpected(b.error());
        *flag = b->has_value() && !(*b)->empty();
    }
    return p;
}

/// rpm's `%{INSTALLTIME:date}` in the C locale: strftime "%a %b %e %H:%M:%S %Y"
/// with fixed English day and month names and a space-padded day of month. The
/// tm is the caller's (localtime in production, gmtime in a test), so the
/// formatter has no locale, timezone or clock of its own. A tm whose weekday or
/// month is out of range renders empty rather than indexing past the tables.
[[nodiscard]] inline std::string rpm_date_c_locale(const std::tm& t) {
    static constexpr std::array<const char*, 7> kDays = {"Sun", "Mon", "Tue", "Wed",
                                                         "Thu", "Fri", "Sat"};
    static constexpr std::array<const char*, 12> kMonths = {"Jan", "Feb", "Mar", "Apr",
                                                            "May", "Jun", "Jul", "Aug",
                                                            "Sep", "Oct", "Nov", "Dec"};
    if (t.tm_wday < 0 || t.tm_wday > 6 || t.tm_mon < 0 || t.tm_mon > 11)
        return {};
    return std::format("{} {} {:>2} {:02}:{:02}:{:02} {}", kDays[static_cast<std::size_t>(t.tm_wday)],
                       kMonths[static_cast<std::size_t>(t.tm_mon)], t.tm_mday, t.tm_hour,
                       t.tm_min, t.tm_sec, 1900 + t.tm_year);
}

/// Receives one header blob at a time; the span is valid only for the call.
using RpmBlobFn = std::function<PkgDbVoid(std::span<const std::uint8_t>)>;

// ── ndb (SUSE Packages.db) ──────────────────────────────────────────────────

/**
 * Walks an rpm ndb `Packages.db`. Layout (little-endian u32, verified on three captures):
 *
 *   offset 0   'RpmP', version (must be 0), generation, slotnpages, nextpkgidx
 *   offset 32  the slot table, 16-byte slots, up to slotnpages * 4096:
 *                 'Slot', pkgidx (0 = empty), blkoff, blkcnt
 *   blkoff*16  the package blob: 'BlbS', pkgidx (must match the slot), generation, length,
 *              then `length` header bytes; the LAST 12 bytes of the slot's blkcnt*16 bytes
 *              are  checksum, length (must equal), 'BlbE'.
 *
 * The Adler-32 checksum is NOT verified: the header parser's exact-length rule and the
 * caller's before/after change stamp catch a torn or short read, and a checksum would add
 * nothing against a hostile file (its author writes a matching one).
 * `Index.db` is never opened; a full listing needs only the slot table.
 */
[[nodiscard]] inline PkgDbVoid read_rpm_ndb(const ByteSource& src, PkgDbBudget& budget,
                                            const RpmBlobFn& on_blob) {
    using rpmdb_detail::load_u32;
    constexpr std::uint64_t kPage = 4096;
    constexpr std::size_t kHeaderBytes = 32;
    constexpr std::size_t kSlotBytes = 16;
    constexpr std::uint64_t kBlobHead = 16;
    constexpr std::uint64_t kBlobTail = 12;

    if (src.size < kHeaderBytes)
        return std::unexpected(PkgDbCause::truncated);
    std::vector<std::uint8_t> page(kPage);
    if (!src.read_at(0, std::span<std::uint8_t>(page.data(), kHeaderBytes)))
        return std::unexpected(PkgDbCause::unreadable);
    if (std::memcmp(page.data(), "RpmP", 4) != 0 || load_u32(page, 4, false) != 0)
        return std::unexpected(PkgDbCause::unsupported_format);
    const std::uint32_t slotnpages = load_u32(page, 12, false);
    if (slotnpages == 0)
        return std::unexpected(PkgDbCause::corrupt);
    const std::uint64_t slot_end = std::uint64_t{slotnpages} * kPage;
    if (slot_end > src.size)
        return std::unexpected(PkgDbCause::truncated);

    std::vector<std::uint8_t> blob;
    for (std::uint32_t pg = 0; pg < slotnpages; ++pg) {
        if (auto t = budget.check_time(); !t)
            return t;
        if (!src.read_at(std::uint64_t{pg} * kPage, page))
            return std::unexpected(PkgDbCause::unreadable);
        for (std::size_t s = (pg == 0 ? kHeaderBytes : 0); s + kSlotBytes <= kPage; s += kSlotBytes) {
            if (std::memcmp(page.data() + s, "Slot", 4) != 0)
                return std::unexpected(PkgDbCause::corrupt);
            const std::uint32_t pkgidx = load_u32(page, s + 4, false);
            if (pkgidx == 0)
                continue; // empty slot
            const std::uint64_t blk_start = std::uint64_t{load_u32(page, s + 8, false)} * 16;
            const std::uint64_t blk_len = std::uint64_t{load_u32(page, s + 12, false)} * 16;
            if (blk_len < kBlobHead + kBlobTail)
                return std::unexpected(PkgDbCause::corrupt);
            const std::uint64_t blk_end = blk_start + blk_len; // < 2^37: cannot wrap
            if (blk_end > src.size)
                return std::unexpected(PkgDbCause::truncated);

            std::array<std::uint8_t, kBlobHead> head{};
            if (!src.read_at(blk_start, head))
                return std::unexpected(PkgDbCause::unreadable);
            if (std::memcmp(head.data(), "BlbS", 4) != 0 || load_u32(head, 4, false) != pkgidx)
                return std::unexpected(PkgDbCause::corrupt);
            const std::uint64_t length = load_u32(head, 12, false);
            if (length > budget.max_item_bytes)
                return std::unexpected(PkgDbCause::oversized);
            if (kBlobHead + length + kBlobTail > blk_len)
                return std::unexpected(PkgDbCause::corrupt);
            std::array<std::uint8_t, kBlobTail> tail{};
            if (!src.read_at(blk_end - kBlobTail, tail))
                return std::unexpected(PkgDbCause::unreadable);
            if (std::memcmp(tail.data() + 8, "BlbE", 4) != 0 || load_u32(tail, 4, false) != length)
                return std::unexpected(PkgDbCause::corrupt);

            if (auto r = budget.charge_row(); !r)
                return r;
            if (auto r = budget.charge_bytes(length); !r)
                return r;
            blob.resize(static_cast<std::size_t>(length)); // <= max_item_bytes and inside the file
            if (!src.read_at(blk_start + kBlobHead, blob))
                return std::unexpected(PkgDbCause::unreadable);
            if (auto r = on_blob(blob); !r)
                return r;
        }
    }
    return {};
}

// ── Berkeley DB hash (RHEL 7/8 family Packages) ─────────────────────────────

/**
 * Walks a Berkeley DB hash database holding rpm's `Packages` table. Verified on arm64
 * (little-endian) and s390x (big-endian) AlmaLinux 8 captures:
 *
 *   meta page 0   magic u32 at 12 = 0x00061561 in file byte order, version at 16 (must be 9),
 *                 page size at 20 (power of two, 512..65536), encryption byte at 24 (zero), type
 *                 byte at 25 (8 = hash meta), last_pgno at 32
 *   hash page     (type byte 25 = 13) entries u16 at 20, then u16 item offsets from byte 26; items
 *                 are packed from the page end downward, so offsets strictly DECREASE and an item
 *                 ends where the previous one starts (the first ends at the page size)
 *   item          first byte = type: 1 inline (data follows), 3 off-page {pgno u32 at +4, total
 *                 length u32 at +8}; 2 (duplicate) and 4 (off-page duplicate) are not decoded
 *   overflow page (type 7) next page u32 at 16, bytes used u16 at 22, data from byte 26
 *
 * Items come in (key, data) pairs; a key is a 4-byte inline record number and the all-zero key is
 * rpm's own counter record, which is skipped. Pages 1..last_pgno are scanned in order and only
 * hash pages are read, so bucket and overflow-bucket pages need no chain walk of their own. A page
 * of type 2 (P_HASH_UNSORTED, the pre-sort layout an in-place upgrade of an older file can leave
 * inside a version 9 file) holds real key/data pairs this reader does not decode, so it answers
 * `unsupported_format` rather than being skipped: a shorter roster must never pass as complete.
 * Every other non-hash page type holds no package record and is skipped. An overflow chain is
 * followed with a step counter bounded by last_pgno, so a self-loop or a two-page loop ends as
 * `corrupt`, never as a hang.
 */
[[nodiscard]] inline PkgDbVoid read_rpm_bdb(const ByteSource& src, PkgDbBudget& budget,
                                            const RpmBlobFn& on_blob) {
    using rpmdb_detail::load_u16;
    using rpmdb_detail::load_u32;
    constexpr std::uint32_t kHashMagic = 0x00061561;
    constexpr std::size_t kMetaRead = 512; // the smallest legal page, so always inside a legal file
    constexpr std::size_t kPageOverhead = 26;
    constexpr std::uint8_t kPageHash = 13;
    constexpr std::uint8_t kPageHashUnsorted = 2;
    constexpr std::uint8_t kPageOverflow = 7;
    constexpr std::uint8_t kPageHashMeta = 8;
    constexpr std::uint8_t kItemKeyData = 1;
    constexpr std::uint8_t kItemDuplicate = 2;
    constexpr std::uint8_t kItemOffPage = 3;
    constexpr std::uint8_t kItemOffDup = 4;

    if (src.size < kMetaRead)
        return std::unexpected(PkgDbCause::truncated);
    std::array<std::uint8_t, kMetaRead> meta{};
    if (!src.read_at(0, meta))
        return std::unexpected(PkgDbCause::unreadable);
    bool be;
    if (load_u32(meta, 12, false) == kHashMagic)
        be = false;
    else if (load_u32(meta, 12, true) == kHashMagic)
        be = true;
    else
        return std::unexpected(PkgDbCause::unsupported_format);
    if (load_u32(meta, 16, be) != 9 || meta[24] != 0)
        return std::unexpected(PkgDbCause::unsupported_format); // another hash version, or encrypted
    const std::uint32_t pagesize = load_u32(meta, 20, be);
    if (pagesize < 512 || pagesize > 65536 || (pagesize & (pagesize - 1)) != 0)
        return std::unexpected(PkgDbCause::corrupt);
    if (meta[25] != kPageHashMeta)
        return std::unexpected(PkgDbCause::corrupt);
    const std::uint32_t last_pgno = load_u32(meta, 32, be);
    if ((std::uint64_t{last_pgno} + 1) * pagesize > src.size)
        return std::unexpected(PkgDbCause::truncated);

    std::vector<std::uint8_t> page(pagesize);
    std::vector<std::uint8_t> opage(pagesize);
    std::vector<std::uint8_t> chain;
    std::vector<std::size_t> off;

    // Spends one row and the bytes of one header, then hands it over.
    const auto deliver = [&](std::span<const std::uint8_t> bytes) -> PkgDbVoid {
        if (auto r = budget.charge_row(); !r)
            return r;
        if (auto r = budget.charge_bytes(bytes.size()); !r)
            return r;
        return on_blob(bytes);
    };

    for (std::uint32_t pg = 1; pg <= last_pgno; ++pg) {
        if ((pg & 0xFFu) == 1)
            if (auto t = budget.check_time(); !t)
                return t;
        if (!src.read_at(std::uint64_t{pg} * pagesize, page))
            return std::unexpected(PkgDbCause::unreadable);
        if (page[25] == kPageHashUnsorted)
            return std::unexpected(PkgDbCause::unsupported_format); // records we cannot decode
        if (page[25] != kPageHash)
            continue;

        const std::size_t n = load_u16(page, 20, be);
        if ((n & 1u) != 0 || kPageOverhead + 2 * n > pagesize)
            return std::unexpected(PkgDbCause::corrupt);
        // Item offsets: inside the item area of the page and strictly decreasing.
        off.resize(n);
        for (std::size_t j = 0; j < n; ++j) {
            off[j] = load_u16(page, kPageOverhead + 2 * j, be);
            if (off[j] < kPageOverhead + 2 * n || off[j] >= pagesize ||
                (j > 0 && off[j] >= off[j - 1]))
                return std::unexpected(PkgDbCause::corrupt);
        }
        const auto item_end = [&](std::size_t j) { return j == 0 ? std::size_t{pagesize} : off[j - 1]; };

        for (std::size_t i = 0; i < n; i += 2) { // n is even, so i + 1 < n
            const std::uint8_t ktype = page[off[i]];
            const std::uint8_t dtype = page[off[i + 1]];
            if (ktype == kItemDuplicate || ktype == kItemOffDup || dtype == kItemDuplicate ||
                dtype == kItemOffDup)
                return std::unexpected(PkgDbCause::unsupported_format);
            if (ktype != kItemKeyData || item_end(i) - off[i] != 5)
                return std::unexpected(PkgDbCause::corrupt); // not a 4-byte inline key
            if (load_u32(page, off[i] + 1, false) == 0)
                continue; // rpm's counter record

            const std::size_t dlen = item_end(i + 1) - off[i + 1];
            if (dtype == kItemKeyData) {
                if (dlen - 1 > budget.max_item_bytes)
                    return std::unexpected(PkgDbCause::oversized);
                if (auto r = deliver(std::span<const std::uint8_t>(page).subspan(off[i + 1] + 1, dlen - 1)); !r)
                    return r;
                continue;
            }
            if (dtype != kItemOffPage || dlen < 12)
                return std::unexpected(PkgDbCause::corrupt);

            const std::uint32_t first = load_u32(page, off[i + 1] + 4, be);
            const std::uint64_t total = load_u32(page, off[i + 1] + 8, be);
            if (total > budget.max_item_bytes)
                return std::unexpected(PkgDbCause::oversized);
            if (total == 0 || total > src.size)
                return std::unexpected(PkgDbCause::corrupt); // a chain cannot hold more than the file
            if (first < 1 || first > last_pgno)
                return std::unexpected(PkgDbCause::corrupt);
            if (total > budget.bytes_left) // the byte check stays ahead of the allocation
                return std::unexpected(PkgDbCause::byte_cap);

            chain.clear();
            chain.reserve(static_cast<std::size_t>(total)); // <= max_item_bytes and <= file size
            std::uint32_t next = first;
            std::uint64_t steps = 0;
            while (next != 0) {
                if (next > last_pgno || ++steps > last_pgno)
                    return std::unexpected(PkgDbCause::corrupt); // out of range, or a loop
                if ((steps & 0x3FFu) == 0)
                    if (auto t = budget.check_time(); !t)
                        return t;
                if (!src.read_at(std::uint64_t{next} * pagesize, opage))
                    return std::unexpected(PkgDbCause::unreadable);
                if (opage[25] != kPageOverflow)
                    return std::unexpected(PkgDbCause::corrupt);
                const std::size_t used = load_u16(opage, 22, be);
                if (used == 0 || used > pagesize - kPageOverhead)
                    return std::unexpected(PkgDbCause::corrupt);
                if (chain.size() + used > total)
                    return std::unexpected(PkgDbCause::corrupt); // the chain runs past its length
                chain.insert(chain.end(), opage.begin() + kPageOverhead,
                             opage.begin() + kPageOverhead + static_cast<std::ptrdiff_t>(used));
                next = load_u32(opage, 16, be);
            }
            if (chain.size() != total)
                return std::unexpected(PkgDbCause::corrupt); // the chain ends short of its length
            if (auto r = deliver(chain); !r)
                return r;
        }
    }
    return {};
}

} // namespace yuzu::shared
