// libFuzzer harness for agents/plugins/component_inventory/src/component_native_parsers.hpp
// - the bounded ELF SONAME and Mach-O LC_ID_DYLIB readers behind the `native` action. Every byte
// of a library is attacker-chosen (any file under a scanned root), so every entry point must be
// total: no crash, no out-of-bounds read, no unbounded work, no read outside the input.
//
// The first input byte picks the entry point; the rest is the file:
//   0  elf_soname                  1  macho_thin_dylib_id          2  macho_dylib_id (fat or thin)
// and the naming rules run over whatever the readers returned, so they see hostile names too.
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

    switch (data[0] % 3) {
    case 0: {
        const auto r = ci::elf_soname(rd, file.size());
        (void)ci::describe_linux("libfuzz.so.1", r ? *r : std::optional<std::string>{});
        (void)ci::describe_linux_file("libfuzz.so", rd, file.size());
        break;
    }
    case 1: {
        const auto r = ci::macho_thin_dylib_id(rd, file.size());
        (void)ci::describe_macos("libfuzz.dylib", r ? *r : std::optional<ci::DylibId>{});
        break;
    }
    default: {
        const auto r = ci::macho_dylib_id(rd, file.size());
        (void)ci::describe_macos("libfuzz.1.dylib", r ? *r : std::optional<ci::DylibId>{});
        (void)ci::describe_macos_file("libfuzz.dylib", rd, file.size());
        break;
    }
    }

    // The candidate predicates over the input as a file name.
    const std::string_view name(reinterpret_cast<const char*>(data) + 1, size - 1);
    (void)ci::is_linux_native_candidate(name);
    (void)ci::is_macos_native_candidate(name);
    return 0;
}
