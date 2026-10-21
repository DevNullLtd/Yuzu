#pragma once

// Staged SHA-256 driver shared by the platform digest providers in oidc_provider.cpp.
//
// The provider calls (OpenSSL EVP on POSIX, CNG on Windows) are not injectable, so the
// sequencing and the failure handling live here, behind an `Ops` type that a test can fake.
// This header has no platform or crypto includes on purpose.
//
// Contract for `Ops` (every stage returns true on success):
//   open()            acquire the provider or context
//   create()          create the hash object
//   update(input)     feed `input` to the hash
//   finish(out)       write exactly 32 bytes into `out` (already sized to 32)
//
// `sha256_via_ops` runs the stages in that order and stops at the first one that returns
// false. It THROWS std::runtime_error("SHA-256 failed") in that case and never returns a
// value for a failed digest. `Ops` owns every handle it opens through RAII members, so a
// handle is released on the throw path as on the success path. Members must be declared so
// that the hash handle is destroyed before the algorithm handle (reverse declaration order).

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace yuzu::server::oidc::detail {

template <class Ops>
std::vector<uint8_t> sha256_via_ops(Ops& ops, const std::string& input) {
    std::vector<uint8_t> hash(32);
    if (!ops.open() || !ops.create() || !ops.update(input) || !ops.finish(hash))
        throw std::runtime_error("SHA-256 failed");
    return hash;
}

} // namespace yuzu::server::oidc::detail
