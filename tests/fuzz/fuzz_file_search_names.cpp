// libFuzzer harness for agents/shared/file_search_names.hpp -- the reversible name encoding,
// file identity and match row of the on-demand file search. Input is attacker-influenced (file
// names come from an untrusted volume), so the whole surface must be total and the encoding must
// stay one-to-one.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh -- keep the two in sync when
// adding sources.

#include "../../agents/shared/file_search_names.hpp"
#include "../../agents/shared/wire_utf8.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace fsr = yuzu::shared::file_search;

namespace {

void require(bool ok) {
    if (!ok)
        std::abort();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view in(reinterpret_cast<const char*>(data), size);

    // Encode is total and reversible; the output is clean wire text.
    const std::string enc = fsr::encode_name(in);
    const auto back = fsr::decode_name(enc);
    require(back && *back == in);
    require(yuzu::shared::count_invalid_wire_bytes(enc) == 0);
    require(std::none_of(enc.begin(), enc.end(), [](char ch) {
        const auto c = static_cast<unsigned char>(ch);
        return c < 0x20 || c == 0x7F || c == '|' || c == '\\';
    }));

    // Decode is total; whatever it accepts is the one canonical spelling.
    if (const auto d = fsr::decode_name(in))
        require(fsr::encode_name(*d) == in);

    // Identity: parse is total and accepts only what format produces.
    if (const auto id = fsr::parse_file_identity(in))
        require(fsr::format_file_identity(*id) == in);

    // A row built from arbitrary bytes keeps exactly three delimiters.
    const auto half = size / 2;
    const std::string row = fsr::format_match_row(in.substr(0, half), size % 2 ? fsr::EntryKind::file : fsr::EntryKind::directory,
                                                  {static_cast<std::uint64_t>(size), half});
    require(std::count(row.begin(), row.end(), '|') == 3);
    return 0;
}
