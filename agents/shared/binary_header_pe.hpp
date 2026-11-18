/**
 * binary_header_pe.hpp -- bounded, portable reader for the VS_VERSIONINFO resource of a PE image.
 * STL only, no OS header, no Windows API: it parses the file bytes the same way on every host.
 *
 * Every offset, count and length in a PE is attacker-chosen. All reads go through the shared
 * Reader (binary_header_reader.hpp); this file adds only the PE-specific decisions:
 *   - an RVA maps to a file offset only as a RANGE that lies wholly inside one section's raw
 *     data, so no read runs into the next section even when those bytes are inside the file;
 *   - the resource directory is walked as exactly three fixed levels (no recursion, so no cycle),
 *     every header and entry wholly inside the directory's declared size;
 *   - the version data is read once into one buffer and the node tree is parsed inside it.
 */

#pragma once

#include "binary_header_reader.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::shared::binary_header {

struct PeLimits {
    std::size_t max_sections{96};
    std::size_t max_dir_entries{4096};
    std::size_t max_version_bytes{256 * 1024};
    std::size_t max_nodes{512};
    std::size_t max_string_tables{16};
    std::size_t max_strings_per_table{128};
    std::size_t max_key_units{128};
    std::size_t max_value_units{4096};
};

struct PeStringTable {
    std::uint16_t language{0};
    std::uint16_t code_page{0};
    // Not sanitised: control and bidi characters in the resource pass through to both strings.
    std::vector<std::pair<std::string, std::string>> strings; // UTF-8 key and value, resource order
};

struct PeVersionInfo {
    std::uint16_t machine{0};
    bool pe32_plus{false};
    bool has_version{false};
    bool has_fixed{false};
    std::array<std::uint16_t, 4> file_version{};
    std::array<std::uint16_t, 4> product_version{};
    std::vector<PeStringTable> string_tables;
    std::vector<std::pair<std::uint16_t, std::uint16_t>> translations;
};

// Portable UTF-16 -> UTF-8. An unpaired surrogate becomes U+FFFD.
[[nodiscard]] inline std::string utf16_to_utf8(std::u16string_view in) {
    std::string out;
    out.reserve(in.size());
    const auto put = [&out](char32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    };
    for (std::size_t i = 0; i < in.size(); ++i) {
        const char32_t u = in[i];
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (i + 1 < in.size() && in[i + 1] >= 0xDC00 && in[i + 1] <= 0xDFFF) {
                put(0x10000 + ((u - 0xD800) << 10) + (static_cast<char32_t>(in[i + 1]) - 0xDC00));
                ++i;
            } else {
                put(0xFFFD);
            }
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            put(0xFFFD);
        } else {
            put(u);
        }
    }
    return out;
}

namespace pe_detail {

inline constexpr auto kLE = std::endian::little;

struct Section {
    std::uint32_t va{0};
    std::uint32_t raw_size{0};
    std::uint32_t raw_ptr{0};
};

// [rva, rva + len) -> file offset, only when the whole range lies in ONE section's raw data.
[[nodiscard]] inline std::expected<std::uint64_t, ParseError>
map_range(const std::vector<Section>& secs, std::uint64_t rva, std::uint64_t len) {
    for (const auto& s : secs) {
        if (rva < s.va)
            continue;
        const std::uint64_t delta = rva - s.va;
        if (delta > s.raw_size || len > s.raw_size - delta)
            continue;
        const auto off = checked_add(s.raw_ptr, delta);
        if (!off)
            return std::unexpected(ParseError::malformed);
        return *off;
    }
    return std::unexpected(ParseError::malformed);
}

constexpr std::size_t align4(std::size_t x) noexcept { return (x + 3) & ~static_cast<std::size_t>(3); }

[[nodiscard]] inline bool key_is(const std::u16string& key, std::string_view ascii) {
    if (key.size() != ascii.size())
        return false;
    for (std::size_t i = 0; i < key.size(); ++i)
        if (key[i] != static_cast<char16_t>(static_cast<unsigned char>(ascii[i])))
            return false;
    return true;
}

[[nodiscard]] inline int hex_digit(char16_t c) noexcept {
    if (c >= u'0' && c <= u'9')
        return c - u'0';
    if (c >= u'a' && c <= u'f')
        return c - u'a' + 10;
    if (c >= u'A' && c <= u'F')
        return c - u'A' + 10;
    return -1;
}

using Result = std::expected<void, ParseError>;

// Parses the VS_VERSIONINFO tree inside one buffer; nothing is read outside it. Every node's
// wLength is bounded by its parent's end, so the tree can only shrink as it is descended.
class VersionParser {
public:
    VersionParser(std::string_view v, const PeLimits& lim, PeVersionInfo& out)
        : v_(v), lim_(lim), out_(out) {}

    [[nodiscard]] Result run() {
        auto root = head(0, v_.size());
        if (!root)
            return std::unexpected(root.error());
        if (!key_is(root->key, "VS_VERSION_INFO"))
            return std::unexpected(ParseError::malformed);
        std::size_t child_from = root->value_off;
        if (root->value_len != 0) {
            // VS_FIXEDFILEINFO: 52 bytes, signature first.
            if (root->value_len < 52 || root->value_len > root->end - root->value_off)
                return std::unexpected(ParseError::malformed);
            if (u32(root->value_off) != 0xFEEF04BDu)
                return std::unexpected(ParseError::malformed);
            const auto at = root->value_off;
            const auto fms = u32(at + 8), fls = u32(at + 12), pms = u32(at + 16), pls = u32(at + 20);
            out_.file_version = {static_cast<std::uint16_t>(fms >> 16), static_cast<std::uint16_t>(fms),
                                 static_cast<std::uint16_t>(fls >> 16), static_cast<std::uint16_t>(fls)};
            out_.product_version = {static_cast<std::uint16_t>(pms >> 16), static_cast<std::uint16_t>(pms),
                                    static_cast<std::uint16_t>(pls >> 16), static_cast<std::uint16_t>(pls)};
            out_.has_fixed = true;
            child_from = at + root->value_len;
        }
        auto r = for_children(child_from, root->end, [&](const Node& n) -> Result {
            if (key_is(n.key, "StringFileInfo"))
                return string_file_info(n);
            if (key_is(n.key, "VarFileInfo"))
                return var_file_info(n);
            return {}; // unknown block: skipped, still bounded and counted
        });
        if (!r)
            return r;
        out_.has_version = true;
        return {};
    }

private:
    struct Node {
        std::size_t end{0};
        std::size_t value_off{0};
        std::size_t value_len{0}; // raw wValueLength; only the fixed-info and Var readers use it
        std::u16string key;
    };

    // Callers only pass offsets already proven to lie inside v_.
    [[nodiscard]] std::uint16_t u16(std::size_t off) const noexcept {
        return load<std::uint16_t>(v_, off, kLE).value_or(0);
    }
    [[nodiscard]] std::uint32_t u32(std::size_t off) const noexcept {
        return load<std::uint32_t>(v_, off, kLE).value_or(0);
    }

    [[nodiscard]] std::expected<Node, ParseError> head(std::size_t off, std::size_t parent_end) {
        if (++nodes_ > lim_.max_nodes)
            return std::unexpected(ParseError::limit_exceeded);
        if (off > parent_end || parent_end - off < 6)
            return std::unexpected(ParseError::malformed);
        Node n;
        const std::size_t wlen = u16(off);
        n.value_len = u16(off + 2);
        if (wlen < 6 || wlen > parent_end - off)
            return std::unexpected(ParseError::malformed);
        n.end = off + wlen;
        std::size_t pos = off + 6;
        for (std::size_t i = 0;; ++i) {
            if (n.end - pos < 2) // no NUL inside the node
                return std::unexpected(ParseError::malformed);
            const char16_t unit = u16(pos);
            pos += 2;
            if (unit == 0)
                break;
            if (i >= lim_.max_key_units)
                return std::unexpected(ParseError::limit_exceeded);
            n.key.push_back(unit);
        }
        n.value_off = align4(pos);
        if (n.value_off > n.end)
            return std::unexpected(ParseError::malformed);
        return n;
    }

    // Children of a node, each bounded by `end`. Trailing bytes too short for a node header are
    // alignment padding. Every iteration consumes >= 6 bytes and counts a node, so it terminates.
    template <class F> [[nodiscard]] Result for_children(std::size_t from, std::size_t end, F&& f) {
        std::size_t off = align4(from);
        while (off <= end && end - off >= 6) {
            auto n = head(off, end);
            if (!n)
                return std::unexpected(n.error());
            if (auto r = f(*n); !r)
                return r;
            off = align4(n->end);
        }
        return {};
    }

    [[nodiscard]] Result string_file_info(const Node& sfi) {
        return for_children(sfi.value_off, sfi.end, [&](const Node& t) -> Result {
            if (out_.string_tables.size() >= lim_.max_string_tables)
                return std::unexpected(ParseError::limit_exceeded);
            if (t.key.size() != 8)
                return std::unexpected(ParseError::malformed);
            std::uint32_t id = 0;
            for (const char16_t c : t.key) {
                const int d = hex_digit(c);
                if (d < 0)
                    return std::unexpected(ParseError::malformed);
                id = (id << 4) | static_cast<std::uint32_t>(d);
            }
            PeStringTable table;
            table.language = static_cast<std::uint16_t>(id >> 16);
            table.code_page = static_cast<std::uint16_t>(id);
            auto r = for_children(t.value_off, t.end, [&](const Node& s) -> Result {
                if (table.strings.size() >= lim_.max_strings_per_table)
                    return std::unexpected(ParseError::limit_exceeded);
                return string_value(s, table);
            });
            if (!r)
                return r;
            out_.string_tables.push_back(std::move(table));
            return {};
        });
    }

    // The value is the NUL-terminated UTF-16LE text after the padded key, bounded by the node's
    // wLength. wValueLength is not consulted: toolchains disagree on bytes versus units. The
    // terminating NUL must lie inside the node: a node with no value bytes at all, or text running
    // to the node end, is malformed (an empty string is a lone NUL). head() guarantees
    // value_off <= end.
    [[nodiscard]] Result string_value(const Node& s, PeStringTable& table) {
        std::u16string value;
        std::size_t pos = s.value_off;
        for (std::size_t i = 0;; ++i) {
            if (s.end - pos < 2)
                return std::unexpected(ParseError::malformed);
            const char16_t unit = u16(pos);
            pos += 2;
            if (unit == 0)
                break;
            if (i >= lim_.max_value_units)
                return std::unexpected(ParseError::limit_exceeded);
            value.push_back(unit);
        }
        table.strings.emplace_back(utf16_to_utf8(s.key), utf16_to_utf8(value));
        return {};
    }

    [[nodiscard]] Result var_file_info(const Node& vfi) {
        return for_children(vfi.value_off, vfi.end, [&](const Node& var) -> Result {
            if (!key_is(var.key, "Translation"))
                return {};
            if (var.value_len > var.end - var.value_off)
                return std::unexpected(ParseError::malformed);
            for (std::size_t at = var.value_off; var.value_len - (at - var.value_off) >= 4; at += 4)
                out_.translations.emplace_back(u16(at), u16(at + 2));
            return {};
        });
    }

    std::string_view v_;
    const PeLimits& lim_;
    PeVersionInfo& out_;
    std::size_t nodes_{0};
};

} // namespace pe_detail

// not_this_format: no MZ header or no PE signature. truncated: an MZ file that ends before
// e_lfanew or before the PE header it names. A PE with no resource directory or no
// RT_VERSION entry is a VALUE with has_version == false. The version resource is the first
// language of the first RT_VERSION entry.
[[nodiscard]] inline std::expected<PeVersionInfo, ParseError>
read_pe_version(const Source& src, const PeLimits& lim = {}, ReadBudget budget = {}) {
    using namespace pe_detail;
    const auto fail = [](ParseError e) { return std::unexpected(e); };
    Reader rd(src, budget);

    // DOS header: "MZ" and e_lfanew at 0x3C.
    if (src.size < 2)
        return fail(ParseError::not_this_format);
    const std::uint64_t dos_len = src.size < 64 ? src.size : 64;
    auto dos = rd.read(0, static_cast<std::size_t>(dos_len));
    if (!dos)
        return fail(dos.error());
    if ((*dos)[0] != 'M' || (*dos)[1] != 'Z')
        return fail(ParseError::not_this_format);
    const auto lfanew = load<std::uint32_t>(*dos, 0x3C, kLE);
    if (!lfanew)
        return fail(ParseError::truncated);

    // "PE\0\0" + COFF header (20 bytes).
    auto coff = rd.read(*lfanew, 24);
    if (!coff)
        return fail(coff.error());
    if (coff->compare(0, 4, std::string_view("PE\0\0", 4)) != 0)
        return fail(ParseError::not_this_format);
    PeVersionInfo info;
    info.machine = *load<std::uint16_t>(*coff, 4, kLE);
    const std::size_t num_sections = *load<std::uint16_t>(*coff, 6, kLE);
    const std::size_t opt_size = *load<std::uint16_t>(*coff, 20, kLE);
    if (num_sections > lim.max_sections)
        return fail(ParseError::limit_exceeded);

    // Optional header: magic, NumberOfRvaAndSizes, data directory index 2 (resources).
    if (opt_size < 2)
        return fail(ParseError::malformed);
    const auto opt_off = checked_add(*lfanew, 24);
    if (!opt_off)
        return fail(ParseError::truncated);
    constexpr std::size_t kMaxOptRead = 112 + 16 * 8; // PE32+ fixed part + 16 directory entries
    auto opt = rd.read(*opt_off, opt_size < kMaxOptRead ? opt_size : kMaxOptRead);
    if (!opt)
        return fail(opt.error());
    const std::uint16_t magic = *load<std::uint16_t>(*opt, 0, kLE);
    if (magic != 0x10b && magic != 0x20b)
        return fail(ParseError::malformed);
    info.pe32_plus = magic == 0x20b;
    const std::size_t nrva_off = info.pe32_plus ? 108 : 92;
    const std::size_t dirs_off = nrva_off + 4;
    if (opt_size < dirs_off)
        return fail(ParseError::malformed);
    const auto nrva = load<std::uint32_t>(*opt, nrva_off, kLE);
    if (!nrva)
        return fail(ParseError::truncated);
    if (*nrva <= 2)
        return info; // no resource directory slot
    if (opt_size < dirs_off + 24) // data directory index 2 must lie inside the optional header
        return fail(ParseError::malformed);
    const auto res_rva = load<std::uint32_t>(*opt, dirs_off + 16, kLE);
    const auto res_size = load<std::uint32_t>(*opt, dirs_off + 20, kLE);
    if (!res_rva || !res_size)
        return fail(ParseError::truncated);
    if (*res_rva == 0 || *res_size == 0)
        return info; // no resource directory

    // Section table.
    const auto sec_off = checked_add(*opt_off, opt_size);
    if (!sec_off)
        return fail(ParseError::truncated);
    std::vector<Section> secs;
    if (num_sections != 0) {
        auto table = rd.read(*sec_off, num_sections * 40);
        if (!table)
            return fail(table.error());
        for (std::size_t i = 0; i < num_sections; ++i) {
            const std::size_t at = i * 40;
            secs.push_back({*load<std::uint32_t>(*table, at + 12, kLE),
                            *load<std::uint32_t>(*table, at + 16, kLE),
                            *load<std::uint32_t>(*table, at + 20, kLE)});
        }
    }

    // The resource directory as one range; every read below stays inside its declared size.
    if (auto m = map_range(secs, *res_rva, *res_size); !m)
        return fail(m.error());
    const std::uint64_t dir_size = *res_size;
    // A read of `len` bytes at `at` inside the directory, mapped again as a range.
    const auto read_dir = [&](std::uint64_t at, std::uint64_t len) -> std::expected<std::string, ParseError> {
        const auto end = checked_add(at, len);
        if (!end || *end > dir_size)
            return std::unexpected(ParseError::malformed);
        const auto m = map_range(secs, static_cast<std::uint64_t>(*res_rva) + at, len);
        if (!m)
            return std::unexpected(m.error());
        return rd.read(*m, static_cast<std::size_t>(len));
    };
    struct DirHeader {
        std::uint64_t named{0};
        std::uint64_t entries{0};
        std::string table; // the entry array
    };
    // Header (16) plus the whole entry array, each entry wholly inside the declared size.
    const auto read_dir_header = [&](std::uint64_t at) -> std::expected<DirHeader, ParseError> {
        auto h = read_dir(at, 16);
        if (!h)
            return std::unexpected(h.error());
        DirHeader d;
        d.named = *load<std::uint16_t>(*h, 12, kLE);
        d.entries = d.named + *load<std::uint16_t>(*h, 14, kLE);
        if (d.entries > lim.max_dir_entries)
            return std::unexpected(ParseError::limit_exceeded);
        if (d.entries == 0)
            return d;
        auto t = read_dir(at + 16, d.entries * 8);
        if (!t)
            return std::unexpected(t.error());
        d.table = std::move(*t);
        return d;
    };
    // Entry `i` of a header: {name/id, offset-to-data}.
    const auto entry = [](const DirHeader& d, std::uint64_t i) {
        return std::pair{*load<std::uint32_t>(d.table, i * 8, kLE),
                         *load<std::uint32_t>(d.table, i * 8 + 4, kLE)};
    };
    constexpr std::uint32_t kSubdir = 0x80000000u;

    // Level 1: the ID entry 16 (RT_VERSION), which must be a subdirectory. Named entries come
    // first in the array and are skipped.
    auto root = read_dir_header(0);
    if (!root)
        return fail(root.error());
    std::optional<std::uint32_t> version_dir;
    for (std::uint64_t i = root->named; i < root->entries; ++i) {
        const auto [id, off] = entry(*root, i);
        if (id == 16) {
            if ((off & kSubdir) == 0)
                return fail(ParseError::malformed);
            version_dir = off & ~kSubdir;
            break;
        }
    }
    if (!version_dir)
        return info; // resources but no RT_VERSION

    // Levels 2 and 3: the FIRST entry. Level 2 must be a subdirectory, level 3 a data entry.
    auto lang_dir = read_dir_header(*version_dir);
    if (!lang_dir)
        return fail(lang_dir.error());
    if (lang_dir->entries == 0)
        return fail(ParseError::malformed);
    const std::uint32_t lang_off = entry(*lang_dir, 0).second;
    if ((lang_off & kSubdir) == 0)
        return fail(ParseError::malformed);
    auto leaf_dir = read_dir_header(lang_off & ~kSubdir);
    if (!leaf_dir)
        return fail(leaf_dir.error());
    if (leaf_dir->entries == 0)
        return fail(ParseError::malformed);
    const std::uint32_t leaf_off = entry(*leaf_dir, 0).second;
    if ((leaf_off & kSubdir) != 0)
        return fail(ParseError::malformed);
    auto data_entry = read_dir(leaf_off, 16);
    if (!data_entry)
        return fail(data_entry.error());
    const std::uint32_t data_rva = *load<std::uint32_t>(*data_entry, 0, kLE);
    const std::uint32_t data_size = *load<std::uint32_t>(*data_entry, 4, kLE);
    if (data_size > lim.max_version_bytes)
        return fail(ParseError::limit_exceeded);
    if (data_size < 6)
        return fail(ParseError::malformed);

    // The version data as one range, read once.
    const auto data_off = map_range(secs, data_rva, data_size);
    if (!data_off)
        return fail(data_off.error());
    auto blob = rd.read(*data_off, data_size);
    if (!blob)
        return fail(blob.error());
    if (auto r = VersionParser(*blob, lim, info).run(); !r)
        return fail(r.error());
    return info;
}

} // namespace yuzu::shared::binary_header
