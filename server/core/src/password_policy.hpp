#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

/// @file password_policy.hpp
/// The ONE local-account password length policy (#5342).
///
/// Before this header the 12-byte minimum was hand-copied at three sites
/// (`AuthManager::first_run_setup` twice, `AuthManager::upsert_user`) and no
/// maximum existed anywhere: `/login` and every user-management route
/// inherited only the pre-routing 4 MiB body cap, so a single request could
/// make the server run PBKDF2 over megabytes of attacker-chosen input. Every
/// password-SETTING site (create, self-change, admin reset, first-run setup)
/// and the password-VERIFYING `/login` path now consult these two constants.
///
/// Both bounds are BYTES, not characters — `std::string::size()`, exactly what
/// the historical `< 12` checks measured. A multi-byte UTF-8 passphrase is
/// therefore measured by its encoded length; that is deliberate (PBKDF2 hashes
/// bytes, and a byte bound cannot be defeated by a combining-character
/// payload).
///
/// The maximum is far above any human-chosen passphrase and any password
/// manager default, and exists only to bound the PBKDF2 input. At `/login`
/// an over-max password is answered EXACTLY like a wrong password (same
/// generic 401, same lockout accounting) without running PBKDF2 — it can
/// never match a stored hash, because no setting site accepts one.
///
/// Pure: no I/O, no store or wire types. Never log, audit, or echo a
/// password or its length — callers report only the `PasswordPolicyVerdict`.
namespace yuzu::server::auth {

/// Minimum accepted password length in bytes (G2-SEC-A1-003).
inline constexpr std::size_t kMinPasswordBytes = 12;

/// Maximum accepted password length in bytes (#5342) — bounds PBKDF2 input.
inline constexpr std::size_t kMaxPasswordBytes = 1024;

static_assert(kMinPasswordBytes < kMaxPasswordBytes, "password policy bounds are inverted");

/// Outcome of checking a candidate NEW password against the policy.
enum class PasswordPolicyVerdict : std::uint8_t {
    kOk,
    kTooShort, ///< fewer than `kMinPasswordBytes` bytes
    kTooLong,  ///< more than `kMaxPasswordBytes` bytes
};

/// Check a candidate password a caller is about to SET. `noexcept`, pure.
[[nodiscard]] constexpr PasswordPolicyVerdict
check_password_policy(std::string_view password) noexcept {
    if (password.size() < kMinPasswordBytes)
        return PasswordPolicyVerdict::kTooShort;
    if (password.size() > kMaxPasswordBytes)
        return PasswordPolicyVerdict::kTooLong;
    return PasswordPolicyVerdict::kOk;
}

/// True when a SUPPLIED password (one being verified, not set) is longer than
/// any password the policy could ever have accepted, so the verifier may
/// reject it without running PBKDF2. Shorter-than-minimum inputs are NOT
/// short-circuited here: legacy accounts predating the minimum may exist, and
/// a short guess costs the attacker the same PBKDF2 as any other guess.
[[nodiscard]] constexpr bool password_exceeds_max(std::string_view password) noexcept {
    return password.size() > kMaxPasswordBytes;
}

} // namespace yuzu::server::auth
