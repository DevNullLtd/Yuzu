/**
 * test_totp.cpp — RFC 6238 TOTP + RFC 4648 base32 unit tests.
 *
 * Covers:
 *   - base32 round-trip (RFC 4648 §10 vectors, no padding)
 *   - current_counter math
 *   - generate() — RFC 6238 Appendix B SHA-1 vectors (truncated to 6 digits)
 *   - verify_window() — drift tolerance and replay protection
 *   - otpauth_uri() — shape + percent-encoding
 *   - random_secret() / random_recovery_code() — success shape and fail-closed
 *     on a CSPRNG failure (#4763)
 */

#include "../../../server/core/src/secure_random.hpp"
#include "../../../server/core/src/totp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::server::mfa;

TEST_CASE("base32 round-trips RFC 4648 vectors", "[mfa][totp][base32]") {
    // RFC 4648 §10 — we emit no-padding form.
    REQUIRE(base32_encode("") == "");
    REQUIRE(base32_encode("f") == "MY");
    REQUIRE(base32_encode("fo") == "MZXQ");
    REQUIRE(base32_encode("foo") == "MZXW6");
    REQUIRE(base32_encode("foob") == "MZXW6YQ");
    REQUIRE(base32_encode("fooba") == "MZXW6YTB");
    REQUIRE(base32_encode("foobar") == "MZXW6YTBOI");

    // Decode round-trips all of the above.
    auto roundtrip = [](std::string s) {
        auto bytes = base32_decode(base32_encode(s));
        REQUIRE(bytes.has_value());
        std::string out(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        REQUIRE(out == s);
    };
    roundtrip("");
    roundtrip("f");
    roundtrip("foobar");
    roundtrip(std::string("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10));
}

TEST_CASE("base32 decode tolerates padding and case", "[mfa][totp][base32]") {
    auto a = base32_decode("MZXW6YTBOI");
    auto b = base32_decode("MZXW6YTBOI======");
    auto c = base32_decode("mzxw6ytboi");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(c.has_value());
    REQUIRE(*a == *b);
    REQUIRE(*a == *c);
}

TEST_CASE("base32 decode rejects garbage", "[mfa][totp][base32]") {
    REQUIRE_FALSE(base32_decode("MZXW6YTBOI!").has_value());
    REQUIRE_FALSE(base32_decode("MZXW9YTB").has_value()); // '9' is not in alphabet
    REQUIRE_FALSE(base32_decode("=MZXW").has_value());    // leading padding
}

TEST_CASE("current_counter floors to 30-second windows", "[mfa][totp][counter]") {
    using namespace std::chrono;
    REQUIRE(current_counter(system_clock::time_point{seconds{59}}) == 1);
    REQUIRE(current_counter(system_clock::time_point{seconds{29}}) == 0);
    REQUIRE(current_counter(system_clock::time_point{seconds{60}}) == 2);
    REQUIRE(current_counter(system_clock::time_point{seconds{1111111109}}) == 37037036);
    REQUIRE(current_counter(system_clock::time_point{seconds{1111111111}}) == 37037037);
    REQUIRE(current_counter(system_clock::time_point{seconds{1234567890}}) == 41152263);
}

TEST_CASE("generate matches RFC 6238 Appendix B SHA-1 vectors", "[mfa][totp][generate]") {
    // RFC 6238 §Appendix B — the published 8-digit SHA-1 column truncated
    // to the low 6 digits (mod 10^6).
    const std::string secret = "12345678901234567890";

    struct V {
        int64_t counter;
        const char* code;
    };
    V vectors[] = {
        {1, "287082"},          // T=59 → 94287082
        {37037036, "081804"},   // T=1111111109 → 07081804
        {37037037, "050471"},   // T=1111111111 → 14050471
        {41152263, "005924"},   // T=1234567890 → 89005924
        {66666666, "279037"},   // T=2000000000 → 69279037
        {666666666, "353130"},  // T=20000000000 → 65353130
    };
    for (const auto& v : vectors) {
        auto produced = generate(secret, v.counter);
        REQUIRE(produced == v.code);
    }
}

TEST_CASE("verify_window accepts current and ±1 step", "[mfa][totp][verify]") {
    const std::string secret = "12345678901234567890";
    // counter=37037037 produces "050471"; ±1 windows are 37037036 ("081804")
    // and 37037038 (different code we don't need to know).
    REQUIRE(verify_window(secret, "050471", 37037037, -1) == 37037037);
    REQUIRE(verify_window(secret, "081804", 37037037, -1) == 37037036);
    REQUIRE(verify_window(secret, "287082", 37037037, -1) == std::nullopt); // out of skew window
}

TEST_CASE("verify_window enforces replay floor", "[mfa][totp][replay]") {
    const std::string secret = "12345678901234567890";
    // The current step is 37037037 with code "050471"; once we record that
    // counter, the same code (or any code at counter <= 37037037) is rejected.
    auto first = verify_window(secret, "050471", 37037037, /*min_counter_exclusive=*/-1);
    REQUIRE(first == 37037037);
    auto replay = verify_window(secret, "050471", 37037037, /*min_counter_exclusive=*/37037037);
    REQUIRE_FALSE(replay.has_value());
    // The previous step's code is also rejected.
    auto prev_replay =
        verify_window(secret, "081804", 37037037, /*min_counter_exclusive=*/37037037);
    REQUIRE_FALSE(prev_replay.has_value());
}

TEST_CASE("verify_window rejects malformed codes", "[mfa][totp][verify]") {
    const std::string secret = "12345678901234567890";
    REQUIRE(verify_window(secret, "12345", 1, -1) == std::nullopt);    // too short
    REQUIRE(verify_window(secret, "1234567", 1, -1) == std::nullopt);  // too long
    REQUIRE(verify_window(secret, "abcdef", 1, -1) == std::nullopt);   // non-numeric
    REQUIRE(verify_window(secret, "", 1, -1) == std::nullopt);
}

TEST_CASE("otpauth_uri formats correctly", "[mfa][totp][uri]") {
    auto uri = otpauth_uri("Yuzu", "alice@example.com", "JBSWY3DPEHPK3PXP");
    REQUIRE(uri.starts_with("otpauth://totp/Yuzu:"));
    REQUIRE(uri.find("alice%40example.com") != std::string::npos);
    REQUIRE(uri.find("secret=JBSWY3DPEHPK3PXP") != std::string::npos);
    REQUIRE(uri.find("issuer=Yuzu") != std::string::npos);
    REQUIRE(uri.find("algorithm=SHA1") != std::string::npos);
    REQUIRE(uri.find("digits=6") != std::string::npos);
    REQUIRE(uri.find("period=30") != std::string::npos);
}

TEST_CASE("random_secret has the right length", "[mfa][totp][secret]") {
    auto s = random_secret();
    REQUIRE(s.has_value());
    REQUIRE(s->size() == 20);
    // Two consecutive calls should differ with overwhelming probability.
    auto s2 = random_secret();
    REQUIRE(s2.has_value());
    REQUIRE(*s != *s2);
}

TEST_CASE("random_secret is never all-zero on success (#4763)", "[mfa][totp][secret]") {
    // P(20 uniform bytes all zero) = 2^-160. A zero vector is exactly what the
    // pre-fix Windows path returned when BCryptGenRandom failed.
    for (int i = 0; i < 50; ++i) {
        auto s = random_secret();
        REQUIRE(s.has_value());
        REQUIRE(std::any_of(s->begin(), s->end(), [](uint8_t b) { return b != 0; }));
    }
}

TEST_CASE("random_secret fails closed on a CSPRNG failure (#4763)", "[mfa][totp][secret]") {
    yuzu::server::test_hooks::force_next_failure_for_this_thread();
    auto s = random_secret();
    REQUIRE_FALSE(s.has_value());
    REQUIRE(s.error() == yuzu::server::SecureRandomError::prng_failure);
    // One-shot: the hook is consumed, so the next call succeeds.
    REQUIRE_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());
    REQUIRE(random_secret().has_value());
}

TEST_CASE("random_recovery_code formatted 4-4-4-4 (80 bits)", "[mfa][totp][recovery]") {
    auto minted = random_recovery_code();
    REQUIRE(minted.has_value());
    const auto& code = *minted;
    REQUIRE(code.size() == 19); // 4 + '-' + 4 + '-' + 4 + '-' + 4
    REQUIRE(code[4] == '-');
    REQUIRE(code[9] == '-');
    REQUIRE(code[14] == '-');
    for (std::size_t i = 0; i < code.size(); ++i) {
        if (i == 4 || i == 9 || i == 14)
            continue;
        char c = code[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
        REQUIRE(ok);
    }
}

TEST_CASE("random_recovery_code fails closed on a CSPRNG failure (#4763)",
          "[mfa][totp][recovery]") {
    yuzu::server::test_hooks::force_next_failure_for_this_thread();
    auto code = random_recovery_code();
    REQUIRE_FALSE(code.has_value());
    REQUIRE(code.error() == yuzu::server::SecureRandomError::prng_failure);
    REQUIRE(random_recovery_code().has_value()); // hook was one-shot
}

TEST_CASE("random_recovery_code: consecutive codes are distinct (#4763)",
          "[mfa][totp][recovery]") {
    // The pre-fix failure mode read the same uninitialised stack slot for all
    // ten codes of a set; a healthy CSPRNG never repeats an 80-bit code.
    std::set<std::string> seen;
    for (int i = 0; i < 10; ++i) {
        auto code = random_recovery_code();
        REQUIRE(code.has_value());
        seen.insert(*code);
    }
    REQUIRE(seen.size() == 10);
}
