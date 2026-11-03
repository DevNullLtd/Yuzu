#pragma once

// RFC 6238 TOTP + RFC 4648 base32 + otpauth:// URI builder.
//
// SOC 2 CC6.6 (privileged access) MFA primitive — used by MfaStore for
// per-user TOTP enrollment, login challenge, and step-up authentication.
// See docs/auth-mfa-design.md.
//
// The 30-second time step, 6-digit code, and HMAC-SHA1 algorithm are the
// RFC 6238 defaults — also what every shipping authenticator app (Google
// Authenticator, Authy, 1Password, Microsoft Authenticator) expects out
// of an `otpauth://` URI with no `algorithm`/`digits`/`period` overrides.

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "secure_random.hpp"

namespace yuzu::server::mfa {

inline constexpr int kTotpStepSeconds = 30;
inline constexpr int kTotpDigits = 6;
inline constexpr int kTotpSecretBytes = 20; // RFC 4226 §4 R6
inline constexpr int kTotpSkewSteps = 1;    // ±1 step (90 s effective window)

/// RFC 4648 base32 alphabet, used by every TOTP authenticator app.
/// Encoding emits no padding ('=') to keep otpauth URIs compact — the
/// authenticator side accepts either; the decoder tolerates both.
[[nodiscard]] std::string base32_encode(std::string_view bytes);

/// Decode base32 (RFC 4648). Returns nullopt on any character outside
/// the alphabet (including '=' anywhere except trailing positions).
/// Case-insensitive. Whitespace stripped before decode.
[[nodiscard]] std::optional<std::vector<uint8_t>> base32_decode(std::string_view encoded);

/// floor(unix_seconds / kTotpStepSeconds). Exposed so the verifier and
/// the test suite can agree on the counter for a given fake clock.
[[nodiscard]] int64_t current_counter(std::chrono::system_clock::time_point now) noexcept;

/// Generate a TOTP code for `counter` against `secret_bytes`.
/// Returns a 0-padded 6-digit string. `secret_bytes` is the raw secret
/// (not base32); callers usually feed it the decoded bytes that were
/// rendered to base32 for the otpauth URI.
[[nodiscard]] std::string generate(std::string_view secret_bytes, int64_t counter);

/// Verify a presented `code` against `secret_bytes` within ±skew_steps of
/// `current`. Returns the matched counter on success (caller persists it
/// as `mfa_last_counter` to defeat replay within the same step) or
/// nullopt on no match.
///
/// Replay rule: if `min_counter_exclusive` is non-negative, any matched
/// counter <= `min_counter_exclusive` is rejected (so a code can be used
/// at most once per step window even across the ±skew accommodation).
/// Pass -1 for first-enrollment verification where no prior counter
/// exists.
[[nodiscard]] std::optional<int64_t> verify_window(std::string_view secret_bytes,
                                                   std::string_view code, int64_t current,
                                                   int64_t min_counter_exclusive = -1,
                                                   int skew_steps = kTotpSkewSteps);

/// Build the otpauth URI the authenticator app renders as a QR.
/// `secret_base32` is already-encoded; `issuer` and `account` are
/// percent-encoded by this function. Format documented at
/// https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
[[nodiscard]] std::string otpauth_uri(std::string_view issuer, std::string_view account,
                                      std::string_view secret_base32);

/// Generate a freshly random kTotpSecretBytes-byte secret from the shared
/// checked CSPRNG helper (`yuzu::server::fill_random`: OpenSSL `RAND_bytes`
/// on Unix, `BCryptGenRandom` on Windows).
///
/// FAIL CLOSED (#4763): a CSPRNG failure returns `SecureRandomError`, never a
/// zero-filled or partially-filled secret. A constant secret would be a
/// publicly-known TOTP key (a complete second-factor bypass that still reports
/// as enrolled). The caller MUST refuse the enrollment and persist nothing.
[[nodiscard]] std::expected<std::vector<uint8_t>, SecureRandomError> random_secret();

/// Generate a single recovery code: 16 base32 characters (80 bits) grouped
/// 4-4-4-4 with '-' separators for human readability. Caller PBKDF2-hashes
/// the value before persisting; the raw form is shown to the user exactly once.
///
/// FAIL CLOSED (#4763): a CSPRNG failure returns `SecureRandomError`; no code
/// is ever derived from unwritten bytes. The caller MUST NOT issue or persist
/// a partial set.
[[nodiscard]] std::expected<std::string, SecureRandomError> random_recovery_code();

} // namespace yuzu::server::mfa
