/**
 * component_native_parsers.hpp -- the adapter and the name and version rules behind the `native`
 * action of the component_inventory plugin.
 *
 * PARSING IS NOT DONE HERE. The ELF SONAME and the Mach-O LC_ID_DYLIB come from the shared, bounded,
 * fuzz-tested readers in agents/shared (binary_header_elf.hpp, binary_header_macho.hpp). This header
 * only (a) turns a ReadAt (the signature of FileView::read_at) into the shared Source, (b) maps the
 * readers' results onto the three outcomes the scan needs, and (c) holds the pure rules that turn a
 * declared name into a row.
 *
 * RESULT. The three outcomes of a parse are kept apart so the scan can tell them from each other:
 *   a value                  the name the file declares (or nullopt: a library that declares none);
 *   NativeError::not_library the magic or file type says this is not a shared library: no row;
 *   NativeError::unreadable  it is one (or claims to be) but cannot be read inside the bounds: a row
 *                            with what the file name offers, an item-level gap.
 * Mapping: ParseError::not_this_format is not a library; io, truncated, malformed and limit_exceeded
 * are unreadable (a bound violation is never a partial answer), and so is an ELF whose dynamic
 * section the reader flagged dynamic_unreadable. An ELF is a library only when its
 * type is ET_DYN; a Mach-O only through the FIRST slice that has no error and is an MH_DYLIB, and a
 * slice that errored is never read as a value. The ELF magic on 4 to 15 bytes is unreadable (a
 * file-name row); under 4 bytes or another magic is not a library.
 *
 * CONSUMER OBLIGATIONS of the shared readers, kept here: the caller checks FileView::unchanged()
 * after the parse (scan_native does); the ReadAt it passes is deadline-aware (scan_native wraps it);
 * one catch(...) per file read keeps every exception inside the plugin; and every string taken from
 * a reader goes through printable() before it reaches a row. A name or version a file declares is
 * the file's own claim: nothing here checks a signature.
 */
#pragma once

#include <binary_header_elf.hpp>   // yuzu::shared::binary_header::read_elf (agents/shared)
#include <binary_header_macho.hpp> // yuzu::shared::binary_header::read_macho (agents/shared)

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::component_inventory {

/// nullopt = I/O error; fewer bytes than asked only at end of file (FileView::read_at).
using ReadAt = std::function<std::optional<std::string>(std::uint64_t offset, std::size_t len)>;

enum class NativeError { not_library, unreadable };

inline constexpr std::size_t kMaxNativeNameBytes = 255; ///< SONAME / install name kept

struct DylibId {
    std::string install_name;
    std::uint32_t current_version{0}; ///< packed xxxx.yy.zz as LC_ID_DYLIB stores it
};

namespace native_detail {

[[nodiscard]] inline std::string printable(std::string_view s) {
    std::string out(s.substr(0, kMaxNativeNameBytes));
    for (char& c : out)
        if (c < 0x20 || c > 0x7E)
            c = '?';
    return out;
}

[[nodiscard]] inline std::unexpected<NativeError> from_parse_error(shared::binary_header::ParseError e) {
    return std::unexpected(e == shared::binary_header::ParseError::not_this_format ? NativeError::not_library
                                                                                  : NativeError::unreadable);
}

} // namespace native_detail

/// The DT_SONAME of the ELF shared object in `size` bytes read through `rd`, printable. A value of
/// nullopt is a shared object that declares none (or an empty one). Never throws.
[[nodiscard]] inline std::expected<std::optional<std::string>, NativeError> native_elf(const ReadAt& rd,
                                                                                        std::uint64_t size) {
    namespace bh = yuzu::shared::binary_header;
    using namespace native_detail;
    try {
        // Under 4 bytes cannot carry the magic. The right magic on 4 to 15 bytes is a library that
        // cannot be parsed (unreadable); the shared reader calls that file not_this_format.
        if (size < 4)
            return std::unexpected(NativeError::not_library);
        const auto magic = rd(0, 4);
        if (!magic)
            return std::unexpected(NativeError::unreadable);
        if (*magic != "\x7f"
                      "ELF")
            return std::unexpected(NativeError::not_library);
        if (size < 16)
            return std::unexpected(NativeError::unreadable);
        const auto info = bh::read_elf(bh::Source{rd, size});
        if (!info)
            return from_parse_error(info.error());
        if (info->type != 3 /* ET_DYN */)
            return std::unexpected(NativeError::not_library);
        // The reader degrades a dynamic section it could not read to an empty soname plus this
        // flag; that must not read as "declares none".
        if (info->dynamic_unreadable)
            return std::unexpected(NativeError::unreadable);
        if (info->soname.empty())
            return std::optional<std::string>{};
        if (info->soname.size() > kMaxNativeNameBytes)
            return std::unexpected(NativeError::unreadable);
        return std::optional<std::string>{printable(info->soname)};
    } catch (...) {
        return std::unexpected(NativeError::unreadable);
    }
}

/// The LC_ID_DYLIB of a Mach-O file (thin, fat or fat64): the first slice with no error that is an
/// MH_DYLIB. nullopt is a dylib with no LC_ID_DYLIB. Never throws.
[[nodiscard]] inline std::expected<std::optional<DylibId>, NativeError> native_macho(const ReadAt& rd,
                                                                                      std::uint64_t size) {
    namespace bh = yuzu::shared::binary_header;
    using namespace native_detail;
    try {
        const auto info = bh::read_macho(bh::Source{rd, size});
        if (!info)
            return from_parse_error(info.error());
        bool slice_error = false;
        for (const auto& s : info->slices) {
            if (s.error) {
                slice_error = true;
                continue;
            }
            if (s.file_type != 6 /* MH_DYLIB */)
                continue;
            if (!s.id_dylib)
                return std::optional<DylibId>{};
            if (s.id_dylib->name.size() > kMaxNativeNameBytes)
                return std::unexpected(NativeError::unreadable);
            return std::optional<DylibId>{DylibId{printable(s.id_dylib->name), s.id_dylib->current_version}};
        }
        return std::unexpected(slice_error ? NativeError::unreadable : NativeError::not_library);
    } catch (...) {
        return std::unexpected(NativeError::unreadable);
    }
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
    const auto r = native_elf(rd, size);
    if (!r && r.error() == NativeError::not_library)
        return std::nullopt;
    return describe_linux(leaf, r ? *r : std::optional<std::string>{});
}

[[nodiscard]] inline std::optional<NativeDescription> describe_macos_file(std::string_view leaf, const ReadAt& rd,
                                                                           std::uint64_t size) {
    const auto r = native_macho(rd, size);
    if (!r && r.error() == NativeError::not_library)
        return std::nullopt;
    return describe_macos(leaf, r ? *r : std::optional<DylibId>{});
}

} // namespace yuzu::component_inventory
