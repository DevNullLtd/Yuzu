// libFuzzer harness for agents/shared/file_search_query.hpp - the leaf-name pattern compiler and
// matcher of the on-demand file search. Pattern and name are both attacker-influenced (the pattern
// from the request, the name from any file on disk), so compile and matches must be total.
//
// Not registered yet: this target is added to tests/fuzz/meson.build and .clusterfuzzlite/build.sh
// separately, after this harness lands -- keep the two in sync when adding it.

#include "../../agents/shared/file_search_query.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace fs = yuzu::shared::file_search;
    if (size == 0)
        return 0;
    // First byte splits the rest into pattern and name.
    const std::size_t rest = size - 1;
    const std::size_t split = data[0] % (rest + 1);
    const std::string_view pattern(reinterpret_cast<const char*>(data + 1), split);
    const std::string_view name(reinterpret_cast<const char*>(data + 1) + split, rest - split);
    for (const auto& sem : {fs::byte_exact(), fs::ascii_case_fold()}) {
        if (auto p = fs::Pattern::compile(pattern, sem))
            (void)p->matches(name);
    }
    return 0;
}
