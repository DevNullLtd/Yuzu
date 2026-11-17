// libFuzzer harness for agents/shared/file_search_cursor.hpp (and the position type it carries) --
// the caller-supplied resume token of the on-demand file search. The token is wholly attacker
// controlled, so the decoder must be total, and every accepted token must be the canonical
// spelling of what it decodes to (the harness aborts otherwise).
//
// Not registered yet: this target is added to tests/fuzz/meson.build and .clusterfuzzlite/build.sh
// separately, after this harness lands -- keep the two in sync when adding it.

#include "../../agents/shared/base64.hpp"
#include "../../agents/shared/file_search_cursor.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>

namespace fsr = yuzu::shared::file_search;

namespace {

void require(bool ok) {
    if (!ok)
        std::abort();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view token(reinterpret_cast<const char*>(data), size);

    // The expected hash is lifted from the token's own body (bytes 1..16) when it has one, so
    // mutations reach the field parser instead of dying at query_mismatch.
    fsr::QueryHash expected{};
    if (token.starts_with(fsr::kCursorPrefix))
        if (const auto body = yuzu::shared::base64_decode(token.substr(fsr::kCursorPrefix.size())))
            if (body->size() >= 1 + expected.size())
                for (std::size_t i = 0; i < expected.size(); ++i)
                    expected[i] = static_cast<std::uint8_t>((*body)[1 + i]);

    const auto r = fsr::decode_cursor(token, expected);
    if (!r) {
        (void)fsr::decode_cursor(token, fsr::QueryHash{}); // total whatever the expected hash is
        return 0;
    }
    require(fsr::valid_position(r->position));
    require(fsr::encode_cursor(*r) == token); // canonical by proof
    const auto again = fsr::decode_cursor(fsr::encode_cursor(*r), r->query_hash);
    require(again && *again == *r);

    // Exercise the transition builder and validator on whatever was accepted.
    const auto later = fsr::next_cursor(*r, r->position, false, size);
    require(!fsr::strictly_advances(*r, later)); // an equal position never advances
    const auto restarted = fsr::next_cursor(*r, fsr::Position{}, true, 0);
    require(fsr::strictly_advances(*r, restarted) == (r->generation != UINT32_MAX && r->sequence != UINT64_MAX));
    (void)fsr::walk_order(r->position, restarted.position);
    return 0;
}
