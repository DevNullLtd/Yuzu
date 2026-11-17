// libFuzzer harness for agents/shared/binary_header_macho.hpp - the bounded Mach-O thin and
// universal header and load-command reader. Every byte of a scanned file is attacker-chosen, so
// read_macho must be total: no crash, no out-of-bounds read, no unbounded work.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh - keep the two in sync when
// adding sources.

#include "../../agents/shared/binary_header_macho.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace bh = yuzu::shared::binary_header;
    const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);
    const bh::Source src = bh::span_source(bytes);

    // 1. Defaults.
    (void)bh::read_macho(src);

    // 2. Tight caps: every limit_exceeded exit is one byte away.
    bh::MachoLimits tight;
    tight.max_fat_archs = 2;
    tight.max_load_commands = 4;
    tight.max_commands_bytes = 256;
    tight.max_string_bytes = 16;
    (void)bh::read_macho(src, tight);

    // 3. A starved budget: the budget exits are reachable for any input.
    bh::ReadBudget starved;
    starved.max_bytes = 96;
    starved.max_reads = 3;
    (void)bh::read_macho(src, {}, starved);
    return 0;
}
