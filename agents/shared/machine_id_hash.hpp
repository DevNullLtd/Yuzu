/**
 * machine_id_hash.hpp -- the cross-OS contract for the `machine_id` value the hardware plugin
 * ships: an application-specific HMAC of the OS machine identifier, never the identifier itself.
 *
 * WHY. machine-id(5) says the raw id is confidential and must not be exposed to untrusted
 * environments; it recommends deriving an application-specific value with a keyed hash
 * (`sd_id128_get_machine_app_specific`). The record that carries this value is stored and
 * served to every operator surface, so the raw id never leaves the host.
 *
 * WHAT THE KEY IS (and is not). The key is a FIXED, PUBLIC, versioned label. It is not a secret.
 * It binds the digest to this application and this purpose (the same raw id hashes differently
 * for another consumer), and it keeps the digest STABLE across an agent reinstall, a key-value
 * wipe and an OS reinstall that preserves the id -- a per-agent random secret would change on
 * each of those and defeat the column's purpose, which is identity. The consequence, stated
 * plainly: anyone who already holds the raw id can recompute the digest. The hash protects the
 * raw id from disclosure through Yuzu; it does not protect against a party that already has it.
 *
 * CROSS-OS CONTRACT. H.11 (Linux, /etc/machine-id) and any later leg call hash_machine_id with
 * the same label and algorithm string so one machine's digest is comparable across legs that
 * read the same id. The label and algorithm token are pinned by tests/unit/test_machine_id_hash
 * (inside test_hmac_sha256.cpp); changing either is a coordinated change of every stored value.
 *
 * NORMALISATION. The input is trimmed of ASCII whitespace, stripped of one pair of surrounding
 * braces and lowercased, so `{ABCD-...}` and `abcd-...` hash identically. Windows stores
 * MachineGuid as lowercase without braces; the normalisation exists so a future reader that
 * formats it differently cannot silently fork the digest.
 */
#pragma once

#include "hmac_sha256.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace yuzu::shared {

/// The HMAC key. Public by design; see the file banner.
inline constexpr std::string_view kMachineIdHashKey = "yuzu.machine-id.v1";

/// The value of the `algorithm` column of the machine_id row.
inline constexpr std::string_view kMachineIdHashAlgorithm = "hmac-sha256-app-v1";

/// Trim ASCII whitespace, drop one surrounding `{...}` pair, lowercase. Empty when nothing is
/// left (an id of only whitespace or braces is no id).
[[nodiscard]] inline std::string normalise_machine_id(std::string_view raw) {
    auto is_ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\0'; };
    auto trim = [&](std::string_view& v) {
        while (!v.empty() && is_ws(v.front()))
            v.remove_prefix(1);
        while (!v.empty() && is_ws(v.back()))
            v.remove_suffix(1);
    };
    trim(raw);
    if (raw.size() >= 2 && raw.front() == '{' && raw.back() == '}') {
        raw.remove_prefix(1);
        raw.remove_suffix(1);
        trim(raw); // "{ }" must not survive as a lone space
    }
    std::string out{raw};
    for (char& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return out;
}

/// Lowercase-hex HMAC of the normalised id, or nullopt when there is no id to hash. The raw id
/// is not retained.
[[nodiscard]] inline std::optional<std::string> hash_machine_id(std::string_view raw) {
    const std::string n = normalise_machine_id(raw);
    if (n.empty())
        return std::nullopt;
    return hmac_sha256_hex(kMachineIdHashKey, n);
}

} // namespace yuzu::shared
