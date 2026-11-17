/**
 * component_native_parsers.hpp -- the bounded readers behind the `native` action of the
 * component_inventory plugin: the SONAME of an ELF shared object and the install name and current
 * version of a Mach-O dynamic library, plus the name and version rules built on them.
 *
 * Pure header, standard library only: no OS header, no I/O of its own, no dependency on the rest of
 * the plugin, so the fuzz target and the sanitizer replay of the unit test include it alone. Every
 * byte comes through a ReadAt (the signature of FileView::read_at), so a test feeds it a buffer, a
 * counting reader or a reader that fails at any call.
 *
 * TRUST BOUNDARY. A library under /opt or /Applications is a file any local account may have
 * planted, and the agent may read it as root. Every count, offset and length below is therefore
 * attacker-chosen. The rules, applied to all of it:
 *  - no struct is cast over file bytes: each field is read with an explicit little- or big-endian load;
 *  - every offset plus length is checked against the file size (inside a fat file, the slice size)
 *    with overflow-safe arithmetic BEFORE the read is issued;
 *  - every count and size has a fixed ceiling (the constants below); a value past one is
 *    NativeError::unreadable, never a partial answer;
 *  - a read that returns fewer bytes than asked, or nothing, is unreadable.
 *
 * FAT FILES. The thin Mach-O parser takes a reader and a size and knows nothing of fat files. For a
 * fat or fat64 file the selected slice's (offset, size) is checked against the file, and the thin
 * parser then runs over a WINDOWED reader rebased to the slice start, with the slice size as its
 * file size. The Mach-O header, the load-command region, each cmdsize and the LC_ID_DYLIB name are
 * thereby bounded by the selected slice: a slice whose commands or name run past its own end is
 * unreadable even when the bytes that follow belong to another, valid slice. There is one copy of
 * the load-command walk.
 *
 * RESULT. The three outcomes of a parse are kept apart so the scan can tell them from each other:
 *   a value                  the name the file declares (or nullopt: a library that declares none);
 *   NativeError::not_library the magic or file type says this is not a shared library: no row;
 *   NativeError::unreadable  it is one (or claims to be) but cannot be read inside the bounds: a row
 *                            with what the file name offers, an item-level gap.
 */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::component_inventory {

/// nullopt = I/O error; fewer bytes than asked only at end of file (FileView::read_at).
using ReadAt = std::function<std::optional<std::string>(std::uint64_t offset, std::size_t len)>;

enum class NativeError { not_library, unreadable };

// ---- ceilings ----

inline constexpr std::size_t kMaxPhdrs = 128;             ///< ELF program headers read
inline constexpr std::size_t kMaxDynamicBytes = 64 * 1024; ///< PT_DYNAMIC read
inline constexpr std::size_t kMaxNativeNameBytes = 255;   ///< SONAME / install name read
inline constexpr std::size_t kMaxFatSlices = 16;
inline constexpr std::size_t kMaxLoadCommands = 4096;
inline constexpr std::size_t kMaxLoadCommandBytes = 256 * 1024;

struct DylibId {
    std::string install_name;
    std::uint32_t current_version{0}; ///< packed xxxx.yy.zz as LC_ID_DYLIB stores it
};

namespace native_detail {

[[nodiscard]] constexpr bool range_ok(std::uint64_t offset, std::uint64_t len, std::uint64_t size) noexcept {
    return offset <= size && len <= size - offset;
}

[[nodiscard]] constexpr bool add_ok(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
    if (b > UINT64_MAX - a)
        return false;
    out = a + b;
    return true;
}

/// Bytes [offset, offset+len) of a file of `size` bytes, exactly: nullopt for a range outside the
/// file (no read is issued), an I/O error or a short read.
[[nodiscard]] inline std::optional<std::string> read_exact(const ReadAt& rd, std::uint64_t size, std::uint64_t offset,
                                                           std::uint64_t len) {
    if (!range_ok(offset, len, size))
        return std::nullopt;
    if (len == 0)
        return std::string{};
    auto s = rd(offset, static_cast<std::size_t>(len));
    if (!s || s->size() != len)
        return std::nullopt;
    return s;
}

/// `n` bytes of `b` at `pos` as an unsigned integer. The caller has checked pos + n <= b.size().
[[nodiscard]] inline std::uint64_t load(const std::string& b, std::size_t pos, unsigned n, bool big) noexcept {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) {
        const auto byte = static_cast<std::uint64_t>(static_cast<unsigned char>(b[pos + i]));
        v |= big ? byte << (8 * (n - 1 - i)) : byte << (8 * i);
    }
    return v;
}

/// The NUL-terminated name at the start of `b` (at most kMaxNativeNameBytes of it): nullopt when no
/// NUL lies inside `b` or the name is over the cap.
[[nodiscard]] inline std::optional<std::string> c_string(const std::string& b) {
    const auto nul = b.find('\0');
    if (nul == std::string::npos || nul > kMaxNativeNameBytes)
        return std::nullopt;
    return b.substr(0, nul);
}

} // namespace native_detail

// ---- ELF ----

/**
 * The DT_SONAME of the ELF shared object in a file of `file_size` bytes. A value of nullopt is a
 * shared object that declares no SONAME (or an empty one).
 */
[[nodiscard]] inline std::expected<std::optional<std::string>, NativeError>
elf_soname(const ReadAt& rd, std::uint64_t file_size) {
    using namespace native_detail;
    constexpr auto bad = [] { return std::unexpected(NativeError::unreadable); };
    constexpr auto none = [] { return std::unexpected(NativeError::not_library); };

    if (file_size < 16)
        return none();
    const auto ident = read_exact(rd, file_size, 0, 16);
    if (!ident)
        return bad();
    if ((*ident)[0] != '\x7f' || (*ident)[1] != 'E' || (*ident)[2] != 'L' || (*ident)[3] != 'F')
        return none();
    const auto cls = static_cast<unsigned char>((*ident)[4]);
    const auto data = static_cast<unsigned char>((*ident)[5]);
    if ((cls != 1 && cls != 2) || (data != 1 && data != 2))
        return bad();
    const bool is64 = cls == 2;
    const bool big = data == 2;

    const std::uint64_t ehdr_size = is64 ? 64 : 52;
    const auto eh = read_exact(rd, file_size, 0, ehdr_size);
    if (!eh)
        return bad();
    if (load(*eh, 16, 2, big) != 3 /* ET_DYN */)
        return none();
    const std::uint64_t phoff = is64 ? load(*eh, 32, 8, big) : load(*eh, 28, 4, big);
    const std::uint64_t phentsize = load(*eh, is64 ? 54 : 42, 2, big);
    const std::uint64_t phnum = load(*eh, is64 ? 56 : 44, 2, big);

    if (phnum > kMaxPhdrs)
        return bad();
    if (phnum == 0)
        return std::optional<std::string>{};
    // The loader's own rule for each class: the entry size is exactly the format's, so the table
    // read below is at most 128 x 56 bytes (7 KiB), never a size the file chooses.
    if (phentsize != (is64 ? 56U : 32U))
        return bad();
    const auto phdrs = read_exact(rd, file_size, phoff, phnum * phentsize);
    if (!phdrs)
        return bad();

    struct Load {
        std::uint64_t vaddr, offset, filesz;
    };
    std::vector<Load> loads;
    std::optional<std::pair<std::uint64_t, std::uint64_t>> dynamic; // offset, filesz
    for (std::uint64_t i = 0; i < phnum; ++i) {
        const auto at = static_cast<std::size_t>(i * phentsize);
        const auto type = load(*phdrs, at, 4, big);
        const std::uint64_t p_offset = is64 ? load(*phdrs, at + 8, 8, big) : load(*phdrs, at + 4, 4, big);
        const std::uint64_t p_vaddr = is64 ? load(*phdrs, at + 16, 8, big) : load(*phdrs, at + 8, 4, big);
        const std::uint64_t p_filesz = is64 ? load(*phdrs, at + 32, 8, big) : load(*phdrs, at + 16, 4, big);
        if (type == 1 /* PT_LOAD */)
            loads.push_back({p_vaddr, p_offset, p_filesz});
        else if (type == 2 /* PT_DYNAMIC */ && !dynamic)
            dynamic.emplace(p_offset, p_filesz);
    }
    if (!dynamic)
        return std::optional<std::string>{};
    if (dynamic->second > kMaxDynamicBytes)
        return bad();
    const auto dyn = read_exact(rd, file_size, dynamic->first, dynamic->second);
    if (!dyn)
        return bad();

    const std::size_t dyn_ent = is64 ? 16 : 8;
    const unsigned word = is64 ? 8 : 4;
    std::optional<std::uint64_t> soname, strtab, strsz;
    for (std::size_t pos = 0; pos + dyn_ent <= dyn->size(); pos += dyn_ent) {
        const auto tag = load(*dyn, pos, word, big);
        const auto val = load(*dyn, pos + word, word, big);
        if (tag == 0 /* DT_NULL */)
            break;
        if (tag == 14 && !soname)
            soname = val;
        else if (tag == 5 && !strtab)
            strtab = val;
        else if (tag == 10 && !strsz)
            strsz = val;
    }
    if (!soname)
        return std::optional<std::string>{};
    if (!strtab || !strsz || *soname >= *strsz)
        return bad();

    // Map the string table's address to a file offset through the PT_LOAD that holds it.
    std::optional<std::uint64_t> tab_off;
    for (const auto& l : loads) {
        if (*strtab >= l.vaddr && *strtab - l.vaddr < l.filesz) {
            std::uint64_t o = 0;
            if (add_ok(l.offset, *strtab - l.vaddr, o))
                tab_off = o;
            break;
        }
    }
    if (!tab_off)
        return bad();
    std::uint64_t name_off = 0;
    if (!add_ok(*tab_off, *soname, name_off) || name_off >= file_size)
        return bad();
    const std::uint64_t len =
        std::min<std::uint64_t>({kMaxNativeNameBytes + 1, *strsz - *soname, file_size - name_off});
    const auto raw = read_exact(rd, file_size, name_off, len);
    if (!raw)
        return bad();
    auto name = c_string(*raw);
    if (!name)
        return bad(); // unterminated inside the table, the file or the cap
    if (name->empty())
        return std::optional<std::string>{};
    return std::optional<std::string>{std::move(*name)};
}

// ---- Mach-O ----

/**
 * The LC_ID_DYLIB of a THIN Mach-O file (32 or 64 bit, either byte order) of `size` bytes. A value
 * of nullopt is a dylib with no LC_ID_DYLIB command. Knows nothing of fat files.
 */
[[nodiscard]] inline std::expected<std::optional<DylibId>, NativeError>
macho_thin_dylib_id(const ReadAt& rd, std::uint64_t size) {
    using namespace native_detail;
    constexpr auto bad = [] { return std::unexpected(NativeError::unreadable); };
    constexpr auto none = [] { return std::unexpected(NativeError::not_library); };

    if (size < 4)
        return none();
    const auto magic_bytes = read_exact(rd, size, 0, 4);
    if (!magic_bytes)
        return bad();
    const auto m = load(*magic_bytes, 0, 4, false);
    bool is64 = false, big = false;
    switch (m) {
    case 0xFEEDFACEU: break;
    case 0xFEEDFACFU: is64 = true; break;
    case 0xCEFAEDFEU: big = true; break;
    case 0xCFFAEDFEU: is64 = big = true; break;
    default: return none();
    }
    const std::uint64_t hdr = is64 ? 32 : 28;
    const auto h = read_exact(rd, size, 0, hdr);
    if (!h)
        return bad();
    if (load(*h, 12, 4, big) != 6 /* MH_DYLIB */)
        return none();
    const auto ncmds = load(*h, 16, 4, big);
    const auto sizeofcmds = load(*h, 20, 4, big);
    if (ncmds > kMaxLoadCommands || sizeofcmds > kMaxLoadCommandBytes)
        return bad();
    const auto cmds = read_exact(rd, size, hdr, sizeofcmds);
    if (!cmds)
        return bad();

    std::uint64_t pos = 0;
    for (std::uint64_t i = 0; i < ncmds; ++i) {
        if (!range_ok(pos, 8, sizeofcmds))
            return bad();
        const auto cmd = load(*cmds, static_cast<std::size_t>(pos), 4, big);
        const auto cmdsize = load(*cmds, static_cast<std::size_t>(pos) + 4, 4, big);
        if (cmdsize < 8 || !range_ok(pos, cmdsize, sizeofcmds))
            return bad();
        if (cmd == 0xD /* LC_ID_DYLIB */) {
            if (cmdsize < 24)
                return bad();
            const auto name_off = load(*cmds, static_cast<std::size_t>(pos) + 8, 4, big);
            if (name_off < 24 || name_off >= cmdsize)
                return bad();
            const auto cur = static_cast<std::uint32_t>(load(*cmds, static_cast<std::size_t>(pos) + 16, 4, big));
            // At most the name cap plus its NUL is copied out of the command buffer, as for ELF.
            const auto room = std::min<std::uint64_t>(cmdsize - name_off, kMaxNativeNameBytes + 1);
            const auto name = c_string(cmds->substr(static_cast<std::size_t>(pos + name_off),
                                                    static_cast<std::size_t>(room)));
            if (!name)
                return bad();
            return std::optional<DylibId>{DylibId{*name, cur}};
        }
        pos += cmdsize;
    }
    return std::optional<DylibId>{};
}

/**
 * The LC_ID_DYLIB of a Mach-O file: thin, fat or fat64. A fat file's FIRST slice that lies inside
 * the file is read through a reader rebased to the slice, so nothing the slice declares can reach
 * its neighbour.
 */
[[nodiscard]] inline std::expected<std::optional<DylibId>, NativeError>
macho_dylib_id(const ReadAt& rd, std::uint64_t file_size) {
    using namespace native_detail;
    if (file_size < 4)
        return std::unexpected(NativeError::not_library);
    const auto mb = read_exact(rd, file_size, 0, 4);
    if (!mb)
        return std::unexpected(NativeError::unreadable);
    const auto m = load(*mb, 0, 4, true);
    if (m != 0xCAFEBABEU && m != 0xCAFEBABFU)
        return macho_thin_dylib_id(rd, file_size);

    const bool fat64 = m == 0xCAFEBABFU;
    const auto fh = read_exact(rd, file_size, 4, 4);
    if (!fh)
        return std::unexpected(NativeError::unreadable);
    const auto nfat = load(*fh, 0, 4, true);
    if (nfat == 0 || nfat > kMaxFatSlices)
        return std::unexpected(NativeError::unreadable);
    const std::uint64_t arch_size = fat64 ? 32 : 20;
    const auto archs = read_exact(rd, file_size, 8, nfat * arch_size);
    if (!archs)
        return std::unexpected(NativeError::unreadable);
    for (std::uint64_t i = 0; i < nfat; ++i) {
        const auto at = static_cast<std::size_t>(i * arch_size);
        const std::uint64_t off = fat64 ? load(*archs, at + 8, 8, true) : load(*archs, at + 8, 4, true);
        const std::uint64_t len = fat64 ? load(*archs, at + 16, 8, true) : load(*archs, at + 12, 4, true);
        if (len == 0 || !range_ok(off, len, file_size))
            continue; // a slice outside the file is not the one read
        const ReadAt window = [&rd, off, len](std::uint64_t o, std::size_t n) -> std::optional<std::string> {
            if (!range_ok(o, n, len))
                return std::nullopt;
            return rd(off + o, n); // off + o <= off + len <= file_size: no overflow
        };
        return macho_thin_dylib_id(window, len);
    }
    return std::unexpected(NativeError::unreadable);
}

// ---- candidates, names and versions ----

namespace native_detail {

/// "1", "3.0.13": digits separated by single dots, neither end a dot.
[[nodiscard]] constexpr bool is_dotted_numeric(std::string_view s) noexcept {
    if (s.empty() || s.front() == '.' || s.back() == '.')
        return false;
    char prev = '.';
    for (const char c : s) {
        const bool digit = c >= '0' && c <= '9';
        if (!digit && c != '.')
            return false;
        if (c == '.' && prev == '.')
            return false;
        prev = c;
    }
    return true;
}

/// The position of the ".so" that opens a shared-object suffix (".so" at the end, or ".so." and a
/// dotted-numeric version to the end); npos when the name has none. The stem before it is non-empty.
[[nodiscard]] constexpr std::size_t so_suffix_at(std::string_view leaf) noexcept {
    if (leaf.size() > 3 && leaf.ends_with(".so"))
        return leaf.size() - 3;
    const auto p = leaf.find(".so.");
    if (p != std::string_view::npos && p > 0 && is_dotted_numeric(leaf.substr(p + 4)))
        return p;
    return std::string_view::npos;
}

/// After `stem` loses its extension: the trailing ".<digits>" groups, without their leading dot
/// ("libfoo.1.2" -> base "libfoo", tail "1.2"). tail is empty when there are none.
struct NumericTail {
    std::string_view base;
    std::string_view tail;
};
[[nodiscard]] constexpr NumericTail split_numeric_tail(std::string_view stem) noexcept {
    std::size_t cut = stem.size();
    for (;;) {
        const auto dot = stem.substr(0, cut).rfind('.');
        if (dot == std::string_view::npos || dot == 0 || dot + 1 >= cut)
            break;
        const auto group = stem.substr(dot + 1, cut - dot - 1);
        if (!std::ranges::all_of(group, [](char c) { return c >= '0' && c <= '9'; }))
            break;
        cut = dot;
    }
    if (cut == stem.size())
        return {stem, {}};
    return {stem.substr(0, cut), stem.substr(cut + 1)};
}

[[nodiscard]] inline std::string printable(std::string_view s) {
    std::string out(s.substr(0, kMaxNativeNameBytes));
    for (char& c : out)
        if (c < 0x20 || c > 0x7E)
            c = '?';
    return out;
}

[[nodiscard]] constexpr std::string_view leaf_of(std::string_view path) noexcept {
    const auto i = path.rfind('/');
    return i == std::string_view::npos ? path : path.substr(i + 1);
}

} // namespace native_detail

/// Candidates: a Linux shared object is `<stem>.so` or `<stem>.so.<digits and dots>`; a macOS dynamic
/// library is `<stem>.dylib`. (Extension-less framework binaries are not read: a stated limit.)
[[nodiscard]] constexpr bool is_linux_native_candidate(std::string_view leaf) noexcept {
    return native_detail::so_suffix_at(leaf) != std::string_view::npos;
}
[[nodiscard]] constexpr bool is_macos_native_candidate(std::string_view leaf) noexcept {
    return leaf.size() > 6 && leaf.ends_with(".dylib");
}

enum class NativeVersionSource { filename, elf, macho, unreadable };

[[nodiscard]] constexpr std::string_view to_token(NativeVersionSource s) noexcept {
    switch (s) {
    case NativeVersionSource::filename: return "filename";
    case NativeVersionSource::elf: return "elf";
    case NativeVersionSource::macho: return "macho";
    case NativeVersionSource::unreadable: return "unreadable";
    }
    return "unreadable";
}

struct NativeDescription {
    std::string name;
    std::string version; ///< '' when no source gives one
    NativeVersionSource version_source{NativeVersionSource::unreadable};
};

/// Linux name and version. `soname` is the file's declared SONAME, when it has one.
[[nodiscard]] inline NativeDescription describe_linux(std::string_view leaf, const std::optional<std::string>& soname) {
    using namespace native_detail;
    const auto stem_of = [](std::string_view s) {
        const auto p = so_suffix_at(s);
        return p == std::string_view::npos ? s : s.substr(0, p);
    };
    const auto version_of = [](std::string_view s) -> std::string_view {
        const auto p = so_suffix_at(s);
        if (p == std::string_view::npos || p + 3 >= s.size())
            return {};
        return s.substr(p + 4);
    };

    NativeDescription d;
    std::string_view name = soname ? stem_of(*soname) : stem_of(leaf);
    if (name.empty())
        name = stem_of(leaf).empty() ? leaf : stem_of(leaf);
    d.name = printable(name);
    if (const auto v = version_of(leaf); !v.empty()) {
        d.version = std::string(v);
        d.version_source = NativeVersionSource::filename;
    } else if (soname) {
        if (const auto sv = version_of(*soname); !sv.empty()) {
            d.version = std::string(sv);
            d.version_source = NativeVersionSource::elf;
        }
    }
    return d;
}

/// macOS name and version. `id` is the file's LC_ID_DYLIB, when it has one.
[[nodiscard]] inline NativeDescription describe_macos(std::string_view leaf, const std::optional<DylibId>& id) {
    using namespace native_detail;
    const auto stem_of = [](std::string_view s) {
        return s.ends_with(".dylib") ? s.substr(0, s.size() - 6) : s;
    };
    NativeDescription d;
    std::string_view base = split_numeric_tail(stem_of(id ? leaf_of(id->install_name) : leaf)).base;
    if (base.empty())
        base = stem_of(leaf);
    d.name = printable(base);
    if (id && id->current_version != 0) {
        const auto v = id->current_version;
        d.version = std::to_string(v >> 16) + '.' + std::to_string((v >> 8) & 0xFF) + '.' + std::to_string(v & 0xFF);
        d.version_source = NativeVersionSource::macho;
    } else if (const auto tail = split_numeric_tail(stem_of(leaf)).tail; !tail.empty()) {
        d.version = std::string(tail);
        d.version_source = NativeVersionSource::filename;
    }
    return d;
}

/// What the scan asks of a file: its description, or nullopt when it is not a shared library (no
/// row). A library that cannot be read inside the bounds is described by its file name alone, with
/// version_source unreadable unless the name carries a version.
[[nodiscard]] inline std::optional<NativeDescription> describe_linux_file(std::string_view leaf, const ReadAt& rd,
                                                                           std::uint64_t size) {
    const auto r = elf_soname(rd, size);
    if (!r && r.error() == NativeError::not_library)
        return std::nullopt;
    return describe_linux(leaf, r ? *r : std::optional<std::string>{});
}

[[nodiscard]] inline std::optional<NativeDescription> describe_macos_file(std::string_view leaf, const ReadAt& rd,
                                                                           std::uint64_t size) {
    const auto r = macho_dylib_id(rd, size);
    if (!r && r.error() == NativeError::not_library)
        return std::nullopt;
    return describe_macos(leaf, r ? *r : std::optional<DylibId>{});
}

} // namespace yuzu::component_inventory
