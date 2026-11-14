// libFuzzer harness for agents/plugins/component_inventory/src/zip_directory.hpp
// - the pure, bounded ZIP central-directory reader. Every byte of an archive
// is attacker-chosen (any file under a scanned root), so all three entry
// points must be total: no crash, no out-of-bounds read, no unbounded work.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh - keep
// the two in sync when adding sources.

#include "../../agents/plugins/component_inventory/src/zip_directory.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace ci = yuzu::component_inventory;
    const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);

    // 1. End-record search: the input as the tail, with the honest file size
    //    and a larger one (the real file is bigger than its tail).
    (void)ci::find_central_directory(bytes, size);
    (void)ci::find_central_directory(bytes, static_cast<std::uint64_t>(size) + (1ULL << 24));

    // 2. Directory walk: first four bytes pick the declared count, the rest is
    //    the directory. A visitor that stops early exercises the other exit.
    if (size >= 4) {
        std::uint32_t declared = 0;
        for (std::size_t i = 0; i < 4; ++i)
            declared |= static_cast<std::uint32_t>(data[i]) << (8 * i);
        const auto cd = bytes.subspan(4);
        std::size_t seen = 0;
        (void)ci::for_each_central_entry(cd, declared, [&](const ci::ZipEntry& e) {
            seen += e.name.size();
            return true;
        });
        (void)ci::for_each_central_entry(cd, declared, [&](const ci::ZipEntry& e) {
            // Feed each entry back into local_data_offset with the same bytes.
            (void)ci::local_data_offset(cd, e);
            return false;
        });
        (void)seen;
    }

    // 3. Local header: the input directly, against an entry whose offset is
    //    near the 64-bit ceiling so the overflow check is reachable.
    ci::ZipEntry far_entry;
    far_entry.local_header_offset = UINT64_MAX - std::min<std::uint64_t>(size, 70000);
    (void)ci::local_data_offset(bytes, far_entry);
    ci::ZipEntry near_entry;
    (void)ci::local_data_offset(bytes, near_entry);
    return 0;
}
