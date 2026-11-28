#pragma once

/**
 * digest_fn.hpp - the narrow seam type for a SHA-256 hex provider.
 *
 * A plain function pointer on purpose (not std::function): no allocation, no process-global
 * state, trivially copyable, and the default argument at each use is the address of the inline
 * `sha256_hex` (sha256_hex.hpp), never a lambda in a default argument (MSVC-hostile). This header
 * carries ONLY the alias so a widely included header (hardware_list_model.hpp,
 * device_inventory_store.hpp) can name the type without pulling in OpenSSL.
 *
 * Production callers never name it: every consumer defaults to `sha256_hex`. A test passes a
 * failing provider (one returning std::nullopt, as `sha256_hex` does when `EVP_Digest` fails) to
 * reach the "digest provider failed" branches (#7163).
 */

#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

using DigestFn = std::optional<std::string> (*)(std::string_view data);

} // namespace yuzu::server
