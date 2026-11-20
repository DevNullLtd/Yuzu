// libFuzzer harness for agents/plugins/component_inventory/src/component_native_parsers.hpp
// - the adapter over the shared binary_header readers and the naming rules behind the `native`
// action. The readers have their own fuzz targets; this one covers what the plugin adds. Every byte
// of a library is attacker-chosen (any file under a scanned root), so every entry point must be
// total: no crash, no out-of-bounds read, no unbounded work, no read outside the input.
//
// The first input byte picks the entry point; the rest is the file:
//   0  native_elf                  1  native_macho (thin or fat)
// and the naming rules run over whatever the adapter returned, so they see hostile names too.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh - keep the two in sync when
// adding sources.

#include "../../agents/plugins/component_inventory/src/component_native_parsers.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace ci = yuzu::component_inventory;
    if (size == 0)
        return 0;
    const std::string file(reinterpret_cast<const char*>(data) + 1, size - 1);

    // A reader bounded to the input: a request outside it aborts the run, which is the bug.
    const ci::ReadAt rd = [&file](std::uint64_t off, std::size_t len) -> std::optional<std::string> {
        if (off > file.size() || len > file.size() - off)
            __builtin_trap();
        return file.substr(static_cast<std::size_t>(off), len);
    };

    if (data[0] % 2 == 0) {
        const auto r = ci::native_elf(rd, file.size());
        (void)ci::describe_linux("libfuzz.so.1", r ? *r : std::optional<std::string>{});
        (void)ci::describe_linux_file("libfuzz.so", rd, file.size());
    } else {
        const auto r = ci::native_macho(rd, file.size());
        (void)ci::describe_macos("libfuzz.1.dylib", r ? *r : std::optional<ci::DylibId>{});
        (void)ci::describe_macos_file("libfuzz.dylib", rd, file.size());
    }

    // The candidate predicates over the input as a file name.
    const std::string_view name(reinterpret_cast<const char*>(data) + 1, size - 1);
    (void)ci::is_linux_native_candidate(name);
    (void)ci::is_macos_native_candidate(name);
    return 0;
}
