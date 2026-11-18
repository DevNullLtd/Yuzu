// libFuzzer harness for agents/shared/binary_header_elf.hpp - the bounded ELF header,
// program-header, note and DT_SONAME reader. Every byte of an ELF file is attacker-chosen
// (any file under a scanned root), so read_elf must be total: no crash, no out-of-bounds read,
// no unbounded work, whatever the input and whatever the limits.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh - keep the two in sync
// when adding sources.

#include "../../agents/shared/binary_header_elf.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace bh = yuzu::shared::binary_header;
    const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);

    // 1. Default limits and budget over the honest source.
    (void)bh::read_elf(bh::span_source(bytes));

    // 2. Tight limits and budget: every cap and the degrade paths become reachable from
    //    small inputs.
    bh::ElfLimits tight;
    tight.max_program_headers = 4;
    tight.max_notes = 2;
    tight.max_note_segment_bytes = 64;
    tight.max_note_name_bytes = 8;
    tight.max_note_desc_bytes = 32;
    tight.max_dynamic_entries = 4;
    tight.max_string_bytes = 16;
    (void)bh::read_elf(bh::span_source(bytes), tight, bh::ReadBudget{256, 4});

    // 3. A medium that fails: the first input byte picks the offset from which read_at
    //    reports an I/O error, so the degrade path of derived reads is exercised too.
    const std::uint64_t fail_from = size == 0 ? 0 : data[0];
    bh::Source honest = bh::span_source(bytes);
    bh::Source flaky{[honest, fail_from](std::uint64_t off,
                                         std::size_t len) -> std::optional<std::string> {
                         if (off >= fail_from && fail_from != 0)
                             return std::nullopt;
                         return honest.read_at(off, len);
                     },
                     honest.size};
    (void)bh::read_elf(flaky);
    return 0;
}
