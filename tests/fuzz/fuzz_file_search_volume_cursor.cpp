// libFuzzer harness for agents/plugins/file_search/src/file_search_volumes.hpp -- the fsv1 volume
// cursor that carries an on-demand file search across mounts (fsv1.<index>.<units hash>.<refused
// hash>.<fs1 token>.<mac>), and the transition rule that decides whether one cursor may follow another.
// The token is wholly caller controlled, so the decoder must be total, and every accepted token must
// be the canonical spelling of what it decodes to (the harness aborts otherwise).
//
// THE MAC. A mutation of the raw input almost never carries a valid mac, so it would die at the mac
// check and the inner decoder would never be reached. Each input is therefore decoded twice: as it
// came (it must be refused unless it happens to be a token this harness's key signed), and re-signed,
// with everything after its last dot replaced by the mac of everything before it, so a mutation of any
// other field reaches the field checks and the inner decoder. The mac is computed here from the HMAC
// primitive, not by the codec, so the harness is an independent check of what the codec signs.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh - keep the two in sync when
// adding sources.

#include "../../agents/plugins/file_search/src/file_search_volumes.hpp"
#include "../../agents/shared/base64.hpp"
#include "../../agents/shared/hmac_sha256.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>

namespace fs = yuzu::file_search;
namespace fsr = yuzu::shared::file_search;

namespace {

void require(bool ok) {
    if (!ok)
        std::abort();
}

/// A 16-hex hash with its first digit changed to a different hex digit.
std::string flipped(std::string hash) {
    hash[0] = hash[0] == '0' ? '1' : '0';
    return hash;
}

fs::CursorKey key_of(unsigned char fill) {
    fs::CursorKey k{};
    k.fill(fill);
    return k;
}

/// `body` + "." + the first 16 bytes (32 hex digits) of HMAC-SHA-256 of `body` under `key`.
std::string sign(const fs::CursorKey& key, std::string_view body) {
    const std::string_view k(reinterpret_cast<const char*>(key.data()), key.size());
    return std::string(body) + "." + yuzu::shared::hmac_sha256_hex(k, body).substr(0, fs::kCursorMacHexBytes);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const fs::CursorKey kKey = key_of(0x5a);
    static const fs::CursorKey kOtherKey = key_of(0xa5);

    const std::string_view raw(reinterpret_cast<const char*>(data), size);
    // As it came: total, and never accepted without a valid mac (which a mutation cannot make).
    if (const auto as_is = fs::decode_volume_cursor(raw, fsr::QueryHash{}, kKey))
        require(fs::encode_volume_cursor(*as_is, kKey) == raw);

    // Re-signed: everything after the last dot is replaced by the mac of everything before it.
    const auto last_dot = raw.rfind('.');
    const std::string resigned =
        last_dot == std::string_view::npos ? std::string(raw) : sign(kKey, raw.substr(0, last_dot));
    const std::string_view token = resigned;

    // The expected query hash is lifted from the inner fs1 token's own body (bytes 1..16) when the
    // token has six well-formed fields, so mutations reach the inner decoder instead of dying at
    // query_mismatch.
    fsr::QueryHash expected{};
    if (const auto fields = fs::split_volume_cursor(token)) {
        const std::string_view inner{fields->inner};
        if (inner.starts_with(fsr::kCursorPrefix))
            if (const auto body = yuzu::shared::base64_decode(inner.substr(fsr::kCursorPrefix.size())))
                if (body->size() >= 1 + expected.size())
                    for (std::size_t i = 0; i < expected.size(); ++i)
                        expected[i] = static_cast<std::uint8_t>((*body)[1 + i]);
    }

    const auto r = fs::decode_volume_cursor(token, expected, kKey);
    if (!r) {
        (void)fs::decode_volume_cursor(token, fsr::QueryHash{}, kKey); // total whatever the expected hash is
        return 0;
    }
    // A token signed under one key is nothing under another.
    require(!fs::decode_volume_cursor(token, expected, kOtherKey));
    require(r->index < fs::kMaxVolumes);
    require(fs::encode_volume_cursor(*r, kKey) == token); // canonical by proof

    // The transition validator, on whatever was accepted. A cursor never advances to itself.
    require(!fs::volume_advances(*r, *r));

    // The move to the next unit: index + 1, a fresh position, the same generation and units hash.
    fs::VolumeCursor next = *r;
    next.index = r->index + 1;
    next.inner = fsr::next_cursor(r->inner, fsr::Position{}, false, size);
    const bool may_step = r->inner.sequence != (std::numeric_limits<std::uint64_t>::max)();
    require(fs::volume_advances(*r, next) == may_step);

    // A changed refused hash is not a change (refused mounts only come and go); a changed units hash
    // always is one and ends the search.
    fs::VolumeCursor other_refused = next;
    other_refused.refused_hash = flipped(next.refused_hash);
    require(fs::volume_advances(*r, other_refused) == fs::volume_advances(*r, next));
    fs::VolumeCursor other_units = next;
    other_units.units_hash = flipped(next.units_hash);
    require(!fs::volume_advances(*r, other_units));

    // A skipped index is never an advance.
    fs::VolumeCursor skipped = next;
    skipped.index = r->index + 2;
    require(!fs::volume_advances(*r, skipped));
    return 0;
}
