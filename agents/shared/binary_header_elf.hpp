/**
 * binary_header_elf.hpp -- bounded ELF header, program-header, note and DT_SONAME reader. Pure:
 * STL plus binary_header_reader.hpp only, no OS header (the constants below are plain numbers, the
 * precedent is is_pseudo_fs_magic in filesystem_find_by_hash.hpp), no I/O of its own, nothing
 * thrown by design (allocation aside).
 *
 * Every field of an ELF file is attacker-chosen. Both classes (ELF32/ELF64) and both byte orders
 * are read through load(); every read of the file goes through Reader, and the range checks made
 * in this file are overflow-safe (subtraction form, checked_add / checked_mul, or capped sums).
 * No section headers, symbols, DT_NEEDED or relocations are read, and no file content is hashed.
 *
 * Error policy. A fault in the ELF header or the program-header table (including an I/O error
 * reading them) is an error. Everything derived from the segments DEGRADES instead of failing the
 * file, an I/O error from the Source included: the field comes back empty and, where one exists,
 * a flag says why (interpreter_unreadable, notes_truncated, dynamic_unreadable); the rest is kept.
 */

#pragma once

#include "binary_header_reader.hpp"

#include <algorithm>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::shared::binary_header {

struct ElfLimits {
    std::size_t max_program_headers{128};
    std::size_t max_notes{64};
    std::size_t max_note_segment_bytes{64 * 1024};
    std::size_t max_note_name_bytes{64};
    std::size_t max_note_desc_bytes{4096};
    std::size_t max_dynamic_entries{4096};
    // The NUL counts toward this cap (longest interpreter or soname 1023); Mach-O's excludes it.
    std::size_t max_string_bytes{1024};
};

struct ElfProgramHeader {
    std::uint32_t type{0};
    std::uint32_t flags{0};
    std::uint64_t offset{0};
    std::uint64_t vaddr{0};
    std::uint64_t filesz{0};
    std::uint64_t memsz{0};
    std::uint64_t align{0};
};

struct ElfNote {
    std::string owner;
    std::uint32_t type{0};
    std::string desc;
};

struct ElfInfo {
    bool is64{false};
    std::endian byte_order{std::endian::little};
    std::uint8_t os_abi{0};
    std::uint16_t type{0};
    std::uint16_t machine{0};
    std::uint64_t entry{0};
    std::vector<ElfProgramHeader> program_headers;
    // Not sanitised: the bytes of the file, control characters included.
    std::string interpreter;
    std::string soname;
    std::string build_id;
    std::vector<ElfNote> notes;
    bool notes_truncated{false};
    bool dynamic_unreadable{false};
    bool interpreter_unreadable{false}; // a PT_INTERP exists but gave no string
};

namespace elf_detail {

// Plain numbers from the ELF gABI, named here instead of including the system ELF header.
inline constexpr std::uint8_t kClass32 = 1;       // ELFCLASS32
inline constexpr std::uint8_t kClass64 = 2;       // ELFCLASS64
inline constexpr std::uint8_t kDataLsb = 1;       // ELFDATA2LSB
inline constexpr std::uint8_t kDataMsb = 2;       // ELFDATA2MSB
inline constexpr std::size_t kIdentSize = 16;     // EI_NIDENT
inline constexpr std::size_t kEhdr32 = 52;        // sizeof(Elf32_Ehdr)
inline constexpr std::size_t kEhdr64 = 64;        // sizeof(Elf64_Ehdr)
inline constexpr std::size_t kPhent32 = 32;       // sizeof(Elf32_Phdr)
inline constexpr std::size_t kPhent64 = 56;       // sizeof(Elf64_Phdr)
inline constexpr std::uint16_t kPnXnum = 0xFFFF;  // PN_XNUM: real count lives in a section header
inline constexpr std::uint32_t kPtLoad = 1;       // PT_LOAD
inline constexpr std::uint32_t kPtDynamic = 2;    // PT_DYNAMIC
inline constexpr std::uint32_t kPtInterp = 3;     // PT_INTERP
inline constexpr std::uint32_t kPtNote = 4;       // PT_NOTE
inline constexpr std::uint64_t kDtNull = 0;       // DT_NULL
inline constexpr std::uint64_t kDtStrtab = 5;     // DT_STRTAB
inline constexpr std::uint64_t kDtStrsz = 10;     // DT_STRSZ
inline constexpr std::uint64_t kDtSoname = 14;    // DT_SONAME
inline constexpr std::size_t kNoteHeader = 12;    // namesz, descsz, type: three u32 in both classes
inline constexpr std::uint32_t kNtGnuBuildId = 3; // NT_GNU_BUILD_ID

// A read of bytes whose range the caller has already bounded by the file header or a size
// check: a short answer is a programming error, not attacker input, so it reads as 0 rather
// than throwing.
template <std::unsigned_integral T>
[[nodiscard]] constexpr T ld(std::string_view b, std::size_t off, std::endian order) noexcept {
    return load<T>(b, off, order).value_or(T{0});
}

[[nodiscard]] constexpr std::uint64_t align_up(std::uint64_t v, std::uint64_t a) noexcept {
    return (v + a - 1) / a * a; // v is bounded by the note segment (below 2^17 at the default limit); a in {4, 8}
}

[[nodiscard]] inline std::string to_hex(std::string_view bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const char c : bytes) {
        const auto u = static_cast<unsigned char>(c);
        out.push_back(kDigits[u >> 4]);
        out.push_back(kDigits[u & 0x0F]);
    }
    return out;
}

// First PT_INTERP. Its [offset, offset + filesz) must lie in the file and the NUL in its first
// min(max_string_bytes, filesz) bytes; empty on any fault, an I/O error included.
[[nodiscard]] inline std::string read_interpreter(Reader& r,
                                                  const std::vector<ElfProgramHeader>& phs,
                                                  const ElfLimits& lim) {
    for (const auto& ph : phs) {
        if (ph.type != kPtInterp)
            continue;
        const auto end = checked_add(ph.offset, ph.filesz);
        if (ph.filesz == 0 || !end || *end > r.size())
            return {};
        const std::size_t cap =
            static_cast<std::size_t>(std::min<std::uint64_t>(lim.max_string_bytes, ph.filesz));
        auto s = r.read_c_string(ph.offset, cap);
        return s ? std::move(*s) : std::string{};
    }
    return {};
}

// Appends the notes of one PT_NOTE segment; sets notes_truncated and stops the segment at its first
// inconsistency (an unreadable segment included), keeping what was parsed before it.
inline void read_note_segment(Reader& r, const ElfProgramHeader& ph, std::endian order,
                              const ElfLimits& lim, ElfInfo& info) {
    if (ph.filesz == 0)
        return;
    if (ph.filesz > lim.max_note_segment_bytes) {
        info.notes_truncated = true;
        return;
    }
    auto seg = r.read(ph.offset, static_cast<std::size_t>(ph.filesz));
    if (!seg) {
        info.notes_truncated = true;
        return;
    }
    const std::uint64_t align = ph.align == 8 ? 8 : 4;
    const std::uint64_t size = seg->size();
    std::uint64_t pos = 0;
    while (pos < size) {
        if (size - pos < kNoteHeader || info.notes.size() >= lim.max_notes) {
            info.notes_truncated = true;
            return;
        }
        const std::size_t p = static_cast<std::size_t>(pos);
        const auto namesz = ld<std::uint32_t>(*seg, p, order);
        const auto descsz = ld<std::uint32_t>(*seg, p + 4, order);
        const auto type = ld<std::uint32_t>(*seg, p + 8, order);
        if (namesz > lim.max_note_name_bytes || descsz > lim.max_note_desc_bytes) {
            info.notes_truncated = true;
            return;
        }
        // The descriptor and the next record start on `align` boundaries of the segment (the ELF
        // gABI aligns positions, not the name length); pos is always a multiple of `align`.
        // Both sizes are capped above, so none of this arithmetic can overflow.
        const std::uint64_t name_off = pos + kNoteHeader;
        const std::uint64_t desc_off = align_up(name_off + namesz, align);
        if (name_off + namesz > size || desc_off + descsz > size) {
            info.notes_truncated = true;
            return;
        }
        ElfNote n;
        n.owner = std::string(seg->data() + name_off, namesz);
        if (const auto nul = n.owner.find('\0'); nul != std::string::npos)
            n.owner.resize(nul);
        n.type = type;
        n.desc.assign(seg->data() + desc_off, descsz);
        info.notes.push_back(std::move(n));
        pos = align_up(desc_off + descsz, align);
    }
}

// DT_SONAME of the first PT_DYNAMIC into info.soname; any inconsistency (an I/O error included)
// leaves it empty and sets dynamic_unreadable. A DT_NULL-terminated table with no DT_SONAME is not
// a fault.
inline void read_soname(Reader& r, const std::vector<ElfProgramHeader>& phs, bool is64,
                        std::endian order, const ElfLimits& lim, ElfInfo& info) {
    const ElfProgramHeader* dyn = nullptr;
    for (const auto& ph : phs) {
        if (ph.type == kPtDynamic) {
            dyn = &ph;
            break;
        }
    }
    if (!dyn)
        return;

    const auto unreadable = [&info] {
        info.soname.clear();
        info.dynamic_unreadable = true;
    };

    const std::size_t es = is64 ? 16 : 8;
    const std::uint64_t scan = std::min<std::uint64_t>(dyn->filesz / es, lim.max_dynamic_entries);
    if (scan == 0)
        return unreadable();
    // Only [p_offset, p_offset + scan * es) is read, and scan * es <= p_filesz.
    auto seg = r.read(dyn->offset, static_cast<std::size_t>(scan * es));
    if (!seg)
        return unreadable();

    std::optional<std::uint64_t> strtab, strsz, soname_off;
    bool have_null = false;
    for (std::uint64_t i = 0; i < scan && !have_null; ++i) {
        const std::size_t p = static_cast<std::size_t>(i * es);
        const std::uint64_t tag = is64 ? ld<std::uint64_t>(*seg, p, order)
                                       : ld<std::uint32_t>(*seg, p, order);
        const std::uint64_t val = is64 ? ld<std::uint64_t>(*seg, p + 8, order)
                                       : ld<std::uint32_t>(*seg, p + 4, order);
        if (tag == kDtNull) {
            have_null = true;
        } else if (tag == kDtStrtab && !strtab) {
            strtab = val;
        } else if (tag == kDtStrsz && !strsz) {
            strsz = val;
        } else if (tag == kDtSoname && !soname_off) {
            soname_off = val;
        }
    }
    // Cap or segment end reached without a DT_NULL: the table is not provably complete.
    if (!have_null)
        return unreadable();
    if (!soname_off)
        return;
    if (!strtab || !strsz || *soname_off >= *strsz)
        return unreadable();

    // The whole string-table range must sit in one PT_LOAD's file-backed part.
    const ElfProgramHeader* load_seg = nullptr;
    std::uint64_t delta = 0;
    for (const auto& ph : phs) {
        if (ph.type != kPtLoad || *strtab < ph.vaddr)
            continue;
        const std::uint64_t d = *strtab - ph.vaddr;
        if (d <= ph.filesz && *strsz <= ph.filesz - d) {
            load_seg = &ph;
            delta = d;
            break;
        }
    }
    if (!load_seg)
        return unreadable();
    const auto table_off = checked_add(load_seg->offset, delta);
    const auto table_end = table_off ? checked_add(*table_off, *strsz) : std::nullopt;
    if (!table_end || *table_end > r.size())
        return unreadable();

    // Capped at the end of the table: a name with no NUL before it is never completed from the
    // bytes that follow.
    const std::size_t cap = static_cast<std::size_t>(
        std::min<std::uint64_t>(lim.max_string_bytes, *strsz - *soname_off));
    auto name = r.read_c_string(*table_off + *soname_off, cap);
    if (!name)
        return unreadable();
    info.soname = std::move(*name);
}

} // namespace elf_detail

[[nodiscard]] inline std::expected<ElfInfo, ParseError>
read_elf(const Source& src, const ElfLimits& lim = {}, ReadBudget budget = {}) {
    using namespace elf_detail;
    if (src.size < 4)
        return std::unexpected(ParseError::not_this_format);

    Reader r(src, budget);
    auto head = r.read(0, static_cast<std::size_t>(std::min<std::uint64_t>(src.size, kEhdr64)));
    if (!head)
        return std::unexpected(head.error());
    if (head->compare(0, 4, "\x7f"
                            "ELF",
                      4) != 0)
        return std::unexpected(ParseError::not_this_format);
    if (head->size() < kIdentSize)
        return std::unexpected(ParseError::truncated);

    const auto cls = static_cast<std::uint8_t>((*head)[4]);
    const auto data = static_cast<std::uint8_t>((*head)[5]);
    if ((cls != kClass32 && cls != kClass64) || (data != kDataLsb && data != kDataMsb))
        return std::unexpected(ParseError::malformed);
    ElfInfo info;
    info.is64 = cls == kClass64;
    info.byte_order = data == kDataLsb ? std::endian::little : std::endian::big;
    if (head->size() < (info.is64 ? kEhdr64 : kEhdr32))
        return std::unexpected(ParseError::truncated);

    const std::endian order = info.byte_order;
    info.os_abi = static_cast<std::uint8_t>((*head)[7]);
    info.type = ld<std::uint16_t>(*head, 16, order);
    info.machine = ld<std::uint16_t>(*head, 18, order);
    std::uint64_t phoff = 0;
    std::uint16_t phentsize = 0, phnum = 0;
    if (info.is64) {
        info.entry = ld<std::uint64_t>(*head, 24, order);
        phoff = ld<std::uint64_t>(*head, 32, order);
        phentsize = ld<std::uint16_t>(*head, 54, order);
        phnum = ld<std::uint16_t>(*head, 56, order);
    } else {
        info.entry = ld<std::uint32_t>(*head, 24, order);
        phoff = ld<std::uint32_t>(*head, 28, order);
        phentsize = ld<std::uint16_t>(*head, 42, order);
        phnum = ld<std::uint16_t>(*head, 44, order);
    }

    if (phnum == 0)
        return info;
    if (phnum == kPnXnum || phnum > lim.max_program_headers)
        return std::unexpected(ParseError::limit_exceeded);
    if (phentsize != (info.is64 ? kPhent64 : kPhent32))
        return std::unexpected(ParseError::malformed);

    // phnum <= max_program_headers and phentsize in {32, 56}: the product is small, but the
    // table's end still goes through Reader's checked_add against the file size.
    const auto table_bytes = checked_mul(phnum, phentsize);
    if (!table_bytes)
        return std::unexpected(ParseError::limit_exceeded);
    auto table = r.read(phoff, static_cast<std::size_t>(*table_bytes));
    if (!table)
        return std::unexpected(table.error());

    info.program_headers.reserve(phnum);
    for (std::size_t i = 0; i < phnum; ++i) {
        const std::size_t p = i * phentsize;
        ElfProgramHeader ph;
        ph.type = ld<std::uint32_t>(*table, p, order);
        if (info.is64) {
            ph.flags = ld<std::uint32_t>(*table, p + 4, order);
            ph.offset = ld<std::uint64_t>(*table, p + 8, order);
            ph.vaddr = ld<std::uint64_t>(*table, p + 16, order);
            ph.filesz = ld<std::uint64_t>(*table, p + 32, order);
            ph.memsz = ld<std::uint64_t>(*table, p + 40, order);
            ph.align = ld<std::uint64_t>(*table, p + 48, order);
        } else {
            ph.offset = ld<std::uint32_t>(*table, p + 4, order);
            ph.vaddr = ld<std::uint32_t>(*table, p + 8, order);
            ph.filesz = ld<std::uint32_t>(*table, p + 16, order);
            ph.memsz = ld<std::uint32_t>(*table, p + 20, order);
            ph.flags = ld<std::uint32_t>(*table, p + 24, order);
            ph.align = ld<std::uint32_t>(*table, p + 28, order);
        }
        info.program_headers.push_back(ph);
    }

    info.interpreter = read_interpreter(r, info.program_headers, lim);
    info.interpreter_unreadable = info.interpreter.empty() && std::ranges::any_of(
        info.program_headers, [](const auto& p) { return p.type == kPtInterp; });
    // Read before the notes: PT_NOTE reads repeat per segment, so they may starve only themselves.
    read_soname(r, info.program_headers, info.is64, order, lim, info);

    for (const auto& ph : info.program_headers) {
        if (ph.type == kPtNote)
            read_note_segment(r, ph, order, lim, info);
    }
    for (const auto& n : info.notes) {
        if (n.owner == "GNU" && n.type == kNtGnuBuildId) {
            info.build_id = to_hex(n.desc);
            break;
        }
    }

    return info;
}

} // namespace yuzu::shared::binary_header
