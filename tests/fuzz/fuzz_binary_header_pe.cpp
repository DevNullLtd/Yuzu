// libFuzzer harness for agents/shared/binary_header_pe.hpp - the bounded PE
// version-resource reader. Every byte of a PE is attacker-chosen (any file under
// a scanned root), so read_pe_version must be total: no crash, no out-of-bounds
// read, no unbounded work.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh - keep
// the two in sync when adding sources.

#include "../../agents/shared/binary_header_pe.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace bh = yuzu::shared::binary_header;
    const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);
    const bh::Source src = bh::span_source(bytes);

    // 1. Default limits and budget.
    (void)bh::read_pe_version(src);

    // 2. Tiny limits and a tiny budget: every cap and the budget are reachable on small inputs.
    bh::PeLimits tiny;
    tiny.max_sections = 2;
    tiny.max_dir_entries = 4;
    tiny.max_version_bytes = 256;
    tiny.max_nodes = 4;
    tiny.max_string_tables = 1;
    tiny.max_strings_per_table = 2;
    tiny.max_key_units = 4;
    tiny.max_value_units = 8;
    (void)bh::read_pe_version(src, tiny, bh::ReadBudget{512, 8});
    return 0;
}
