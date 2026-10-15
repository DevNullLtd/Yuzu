/**
 * test_gateway_peer_policy.cpp: the pure half of gateway-upstream peer
 * authorization. No gRPC, no sockets. Table-driven.
 *
 *   [cert]    spki_sha256_hex / parse_cert_facts against fixed vectors
 *   [pinset]  parse_pin_hex / split_pin_list / parse_pin_file / PinSet / load_boot_pins
 *   [policy]  the decision table, one row per closed DenyReason
 *
 * The wire half (real mTLS, the guard) is test_gateway_peer_guard.cpp.
 */

#include <catch2/catch_test_macros.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "gateway_peer_cert.hpp"
#include "gateway_peer_pinset.hpp"
#include "gateway_peer_policy.hpp"
#include "gateway_peer_test_pki.hpp"
#include "x509_ca.hpp"
#include "../test_helpers.hpp"

namespace gp = yuzu::server::gateway_peer;
namespace gwt = yuzu::test::gwpeer;
namespace pki = yuzu::server::pki;
using std::chrono::milliseconds;
using std::chrono::seconds;
using SysTime = std::chrono::system_clock::time_point;

namespace {

// A self-signed P-256 certificate generated once with the openssl CLI, then digested with the
// documented pin pipeline:
//
//   openssl x509 -in c.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
//   -> 2189d5e1cc22bdba4fb5b64171ff1980c01aa5276cf9d3a614711bea91b55b6c
//
// The same SubjectPublicKeyInfo with only the subjectPublicKey BIT STRING hashed (what
// X509_pubkey_digest and therefore pki::issuer_key_id digest) is a DIFFERENT value:
//   d43ec85c3fc836195b9a9a90bf4769be9df41471111b6ac06d3017c438a28635
// The certificate carries no extendedKeyUsage extension.
constexpr const char* kVectorPem = R"(-----BEGIN CERTIFICATE-----
MIIBqDCCAU+gAwIBAgIUAP/LoOCBgwOpiDh5NJvO1AeiW/swCgYIKoZIzj0EAwIw
KTEUMBIGA1UEAwwLc3BraS12ZWN0b3IxETAPBgNVBAoMCFl1enVUZXN0MCAXDTI2
MTAwNDIyMjQzOVoYDzIxMjYwOTEwMjIyNDM5WjApMRQwEgYDVQQDDAtzcGtpLXZl
Y3RvcjERMA8GA1UECgwIWXV6dVRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARGpDZUsSuJ7RLop0KJW8PbY9ZmZ78OUBveGFxArtWEykO2uTyXSPYSmYvrO2Zy
YJVruwbk4nlz3QwhcvWER3eQo1MwUTAdBgNVHQ4EFgQU/a3QbrhpB395jBqm+Jjq
LDO/7UUwHwYDVR0jBBgwFoAU/a3QbrhpB395jBqm+JjqLDO/7UUwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBkXn6vIQW7ezBsw9ddXIO0zEVAw3r4
9sBDo5wXz4R3jAIgOxAeHu5RtK2u8fFgNbmP4iQ7Q5P/iQ7ZbFe5L3FVA4A=
-----END CERTIFICATE-----
)";
constexpr const char* kVectorSpki =
    "2189d5e1cc22bdba4fb5b64171ff1980c01aa5276cf9d3a614711bea91b55b6c";
constexpr const char* kVectorBitStringDigest =
    "d43ec85c3fc836195b9a9a90bf4769be9df41471111b6ac06d3017c438a28635";

// gwt::kYear9999Pem: valid 2026-01-01T00:00:00Z .. 9999-12-31T23:59:59Z, serverAuth + clientAuth.
constexpr const char* kYear9999Spki =
    "d32903dc072355af13c2ba2e847257b892cf9eee083bb8006a3e7eaeb89660c7";
constexpr std::int64_t kYear9999NotAfterEpoch = 253402300799;
constexpr std::int64_t kYear9999NotBeforeEpoch = 1767225600;

constexpr const char* kBadCertPem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

std::int64_t epoch_seconds(gp::CertInstant t) {
    return t.time_since_epoch().count();
}

std::string strip_colons_lower(const std::string& s) {
    std::string out;
    for (const char c : s) {
        if (c != ':')
            out += static_cast<char>((c >= 'A' && c <= 'F') ? c - 'A' + 'a' : c);
    }
    return out;
}

/// SPKI digest through an independent OpenSSL path (EVP_PKEY -> i2d_PUBKEY), so agreement with
/// spki_sha256_hex is not one code path agreeing with itself.
std::string independent_spki_hex(const std::string& pem) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio{
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free};
    REQUIRE(bio);
    std::unique_ptr<X509, decltype(&X509_free)> x{
        PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free};
    REQUIRE(x);
    EVP_PKEY* pk = X509_get0_pubkey(x.get());
    REQUIRE(pk);
    struct OpensslFree {
        void operator()(unsigned char* p) const noexcept { OPENSSL_free(p); }
    };
    unsigned char* raw_der = nullptr;
    const int n = i2d_PUBKEY(pk, &raw_der);
    std::unique_ptr<unsigned char, OpensslFree> der{raw_der};
    REQUIRE(n > 0);
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned int md_len = 0;
    REQUIRE(EVP_Digest(der.get(), static_cast<std::size_t>(n), md.data(), &md_len, EVP_sha256(),
                       nullptr) == 1);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < md_len; ++i) {
        out += kHex[md[i] >> 4];
        out += kHex[md[i] & 0xF];
    }
    return out;
}

std::string pin_of(const std::string& pem) {
    const auto p = gp::spki_sha256_hex(std::string_view{pem});
    REQUIRE(p.has_value());
    return *p;
}

/// The i-th distinct, well-formed pin.
std::string pin_n(unsigned i) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s(gp::kPinHexLen, '0');
    for (std::size_t k = 0; k < 8; ++k)
        s[gp::kPinHexLen - 1 - k] = kHex[(i >> (4 * k)) & 0xF];
    return s;
}

std::string hex_lines(unsigned first, unsigned count) {
    std::string s;
    for (unsigned i = 0; i < count; ++i)
        s += pin_n(first + i) + "\n";
    return s;
}

std::shared_ptr<const gp::PinSet> pins_of(const std::vector<std::string>& pins) {
    return std::make_shared<const gp::PinSet>(pins);
}

gp::PeerEvidence evidence(const std::string& pem, bool authenticated = true, bool ctx = true) {
    gp::PeerEvidence e;
    e.context_present = ctx;
    e.peer_authenticated = authenticated;
    e.cert_pem = pem;
    return e;
}

/// An in-memory file system for load_boot_pins; records every path it is asked for.
struct FakeFs {
    std::map<std::string, gp::FileReadResult> files;
    std::vector<std::string> reads;
    bool throws{false};

    void put(const std::string& path, std::string content) {
        files[path] = gp::FileReadResult{gp::FileReadResult::Status::Ok, std::move(content)};
    }
    void put_status(const std::string& path, gp::FileReadResult::Status st) {
        files[path] = gp::FileReadResult{st, {}};
    }
    gp::FileReader reader() {
        return [this](const std::string& path, std::size_t) {
            reads.push_back(path);
            if (throws)
                throw std::runtime_error("disk on fire");
            const auto it = files.find(path);
            if (it == files.end())
                return gp::FileReadResult{gp::FileReadResult::Status::Missing, {}};
            return it->second;
        };
    }
};

/// Runs `fn` on a worker thread and waits up to `limit` for it. Returns its result, or nullopt
/// if it had not finished within `limit`: a regression that blocks must FAIL the test, not pass.
/// `on_timeout` runs once after the limit, to unblock the worker. The worker is ALWAYS joined
/// before this returns and is never detached, so a worker that stays blocked even after
/// `on_timeout` shows as the meson test timeout (a hang), not as a leaked thread running past the
/// end of the test. `fn` must capture by value and must not use Catch macros (assertions are not
/// made off the test thread).
template <class Fn>
auto run_bounded(Fn fn, std::chrono::milliseconds limit,
                 const std::function<void()>& on_timeout = {}) -> std::optional<decltype(fn())> {
    using R = decltype(fn());
    auto promise = std::make_shared<std::promise<R>>();
    auto future = promise->get_future();
    std::thread worker([promise, fn = std::move(fn)]() mutable {
        try {
            promise->set_value(fn());
        } catch (...) {
            promise->set_exception(std::current_exception());
        }
    });
    const bool in_time = future.wait_for(limit) == std::future_status::ready;
    if (!in_time && on_timeout)
        on_timeout();
    worker.join();
    if (!in_time)
        return std::nullopt; // finished only after the bound (or after on_timeout unblocked it)
    return future.get();
}

#ifndef _WIN32
/// Replaces the process's stdin with the read end of a pipe that nothing writes to, so a call
/// that PROMPTS (reads a passphrase from stdin) blocks instead of failing fast on EOF, which is
/// what lets a test tell "refused" from "asked". `release()` closes the write end (EOF) to
/// unblock a reader that did ask. Restores the real stdin on destruction. If stdin cannot be
/// duplicated (it is closed), the swap is skipped: `swapped()` is false, a prompt would then fail
/// fast on EOF instead of blocking, and the caller's refusal assertion still runs.
class BlockedStdin {
public:
    BlockedStdin() {
        // Every descriptor is owned locally until the last step, so a failed REQUIRE (which
        // throws) closes them; only then are they released into the members, with no assertion
        // after that point.
        struct Owned {
            int fd{-1};
            Owned() = default;
            explicit Owned(int f) : fd(f) {}
            Owned(const Owned&) = delete;
            Owned& operator=(const Owned&) = delete;
            ~Owned() {
                if (fd >= 0)
                    ::close(fd);
            }
            int release() {
                const int f = fd;
                fd = -1;
                return f;
            }
        };
        Owned saved(::dup(0));
        if (saved.fd < 0)
            return; // stdin is closed: skip the swap
        int fds[2] = {-1, -1};
        REQUIRE(::pipe(fds) == 0);
        Owned read_end(fds[0]);
        Owned write_end(fds[1]);
        REQUIRE(::dup2(read_end.fd, 0) >= 0);
        saved_ = saved.release();
        write_end_ = write_end.release();
    }
    BlockedStdin(const BlockedStdin&) = delete;
    BlockedStdin& operator=(const BlockedStdin&) = delete;
    bool swapped() const { return saved_ >= 0; }
    void release() {
        if (write_end_ >= 0) {
            ::close(write_end_);
            write_end_ = -1;
        }
    }
    ~BlockedStdin() {
        release();
        if (saved_ >= 0) {
            ::dup2(saved_, 0);
            ::close(saved_);
        }
    }

private:
    int saved_{-1};
    int write_end_{-1};
};
#endif

std::string to_crlf(const std::string& s) {
    std::string out;
    for (const char c : s) {
        if (c == '\n')
            out += '\r';
        out += c;
    }
    return out;
}

/// A CERTIFICATE block whose PEM header says its body is passphrase-encrypted. OpenSSL asks for
/// the passphrase when it reads one; the body is never decrypted (it is 32 zero bytes).
const std::string kEncryptedPem =
    "-----BEGIN CERTIFICATE-----\n"
    "Proc-Type: 4,ENCRYPTED\n"
    "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n"
    "\n" +
    std::string(43, 'A') + "=\n"
    "-----END CERTIFICATE-----\n";

std::string repeat_pem(const std::string& pem, std::size_t n) {
    std::string s;
    for (std::size_t i = 0; i < n; ++i)
        s += pem;
    return s;
}

} // namespace

// -- [cert] ---------------------------------------------------------------------

TEST_CASE("gateway_peer_cert: SPKI pin of a fixed certificate equals the openssl CLI pipeline value",
          "[gateway_peer][cert]") {
    const auto got = gp::spki_sha256_hex(std::string_view{kVectorPem});
    REQUIRE(got.has_value());
    CHECK(*got == kVectorSpki);
    CHECK(got->size() == 64);
}

TEST_CASE("gateway_peer_cert: the pin is the full SPKI DER digest, not the subjectPublicKey digest",
          "[gateway_peer][cert]") {
    const auto got = gp::spki_sha256_hex(std::string_view{kVectorPem});
    REQUIRE(got.has_value());
    CHECK(*got != kVectorBitStringDigest);
    const auto ik = pki::issuer_key_id(kVectorPem);
    REQUIRE(ik.has_value());
    CHECK(strip_colons_lower(*ik) == kVectorBitStringDigest); // the fixture's claim, checked
    CHECK(*got != strip_colons_lower(*ik));
}

TEST_CASE("gateway_peer_cert: agrees with an independent OpenSSL path; a same-key reissue keeps "
          "the pin and a new key changes it",
          "[gateway_peer][cert]") {
    const auto ca = gwt::make_ca("Policy Test CA");
    const auto first = gwt::make_gateway_leaf(ca);
    const auto renewed = gwt::reissue_same_key(ca, first, "Renewed Gateway", true, true);
    const auto other = gwt::make_gateway_leaf(ca);
    REQUIRE(first.cert_pem != renewed.cert_pem);
    CHECK(pin_of(first.cert_pem) == independent_spki_hex(first.cert_pem));
    CHECK(pin_of(first.cert_pem) == pin_of(renewed.cert_pem));
    CHECK(pin_of(first.cert_pem) != pin_of(other.cert_pem));
}

TEST_CASE("gateway_peer_cert: failure is nullopt, never a success carrying an empty hash",
          "[gateway_peer][cert]") {
    std::string truncated = kVectorPem;
    truncated.resize(truncated.size() / 2);
    const std::vector<std::pair<const char*, std::string>> bad{
        {"empty", ""},
        {"not a certificate", "not a certificate"},
        {"garbage body", kBadCertPem},
        {"truncated real certificate", truncated},
        {"larger than the parser bound", std::string(gp::kMaxCertPemBytes + 1, 'A')},
    };
    for (const auto& [name, pem] : bad) {
        INFO(name);
        CHECK_FALSE(gp::spki_sha256_hex(std::string_view{pem}).has_value());
        CHECK_FALSE(gp::parse_cert_facts(pem).has_value());
    }
    CHECK_FALSE(gp::spki_sha256_hex(static_cast<const x509_st*>(nullptr)).has_value());
}

TEST_CASE("gateway_peer_cert: a passphrase-protected PEM block is refused, never prompted for",
          "[gateway_peer][cert]") {
    // A block with `Proc-Type: 4,ENCRYPTED` makes OpenSSL ask for a passphrase; with no password
    // callback it prompts on the terminal or stdin and blocks the calling thread. A pin file or a
    // presented certificate must be refused instead. On POSIX stdin is a pipe nothing writes to,
    // so a regression BLOCKS (and the bounded wait fails the test) rather than failing fast on EOF.
#ifndef _WIN32
    BlockedStdin stdin_guard;
    if (!stdin_guard.swapped()) {
        WARN("stdin is closed, so the blocking-stdin swap was skipped: this run cannot tell a "
             "refused passphrase prompt from one that was asked and then hit EOF");
    }
#endif
    const std::string pem = kEncryptedPem;
    const auto result = run_bounded(
        [pem] {
            const auto spki = gp::spki_sha256_hex(std::string_view{pem});
            const auto facts = gp::parse_cert_facts(pem);
            const auto file = gp::parse_pin_file(pem);
            return std::make_tuple(spki.has_value(), facts.has_value(), file.state, file.pins.size());
        },
        std::chrono::seconds(10), [&] {
#ifndef _WIN32
            stdin_guard.release();
#endif
        });
    REQUIRE(result.has_value()); // nullopt: a call blocked waiting for a passphrase
    CHECK_FALSE(std::get<0>(*result));
    CHECK_FALSE(std::get<1>(*result));
    CHECK(std::get<2>(*result) == gp::PinFileState::Malformed);
    CHECK(std::get<3>(*result) == 0);
}

TEST_CASE("gateway_peer_cert: EKU facts: serverAuth listed, clientAuth-only, and absent",
          "[gateway_peer][cert]") {
    const auto ca = gwt::make_ca("Policy Test CA");
    struct Row {
        const char* name;
        std::string pem;
        bool server_auth;
    };
    const std::vector<Row> rows{
        {"gateway (serverAuth+clientAuth)", gwt::make_gateway_leaf(ca).cert_pem, true},
        {"agent (clientAuth only)", gwt::make_agent_leaf(ca).cert_pem, false},
        {"no EKU extension at all", kVectorPem, false},
    };
    for (const auto& r : rows) {
        INFO(r.name);
        const auto f = gp::parse_cert_facts(r.pem);
        REQUIRE(f.has_value());
        CHECK(f->has_server_auth_eku == r.server_auth);
        CHECK(f->not_before < f->not_after);
    }
}

TEST_CASE("gateway_peer_cert: validity instants, including a certificate valid until 9999-12-31",
          "[gateway_peer][cert][validity]") {
    const auto ca = gwt::make_ca("Policy Test CA");
    const auto expired = gwt::make_leaf(ca, "Old", true, true, gwt::expired_validity());
    const auto ef = gp::parse_cert_facts(expired.cert_pem);
    REQUIRE(ef.has_value());
    const auto now = std::chrono::floor<seconds>(std::chrono::system_clock::now());
    CHECK(ef->not_after < now);
    CHECK(ef->not_after > now - std::chrono::hours(25));

    const auto f = gp::parse_cert_facts(gwt::kYear9999Pem);
    REQUIRE(f.has_value());
    CHECK(f->spki_sha256_hex == kYear9999Spki);
    CHECK(f->has_server_auth_eku);
    CHECK(epoch_seconds(f->not_after) == kYear9999NotAfterEpoch);
    CHECK(epoch_seconds(f->not_before) == kYear9999NotBeforeEpoch);
}

// -- [pinset] -------------------------------------------------------------------

TEST_CASE("gateway_peer_pinset: parse_pin_hex accepts exactly 64 hex characters",
          "[gateway_peer][pinset]") {
    const std::string lower = pin_n(0xABCDEF);
    std::string upper = lower;
    for (auto& c : upper)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    struct Row {
        const char* name;
        std::string in;
        std::optional<std::string> want;
    };
    const std::vector<Row> rows{
        {"lowercase", lower, lower},
        {"uppercase is lowercased", upper, lower},
        {"surrounding whitespace trimmed", " \t" + lower + "\r\n", lower},
        {"empty", "", std::nullopt},
        {"63 characters", lower.substr(1), std::nullopt},
        {"65 characters", lower + "0", std::nullopt},
        {"an 8-hex prefix is never a pin", lower.substr(0, 8), std::nullopt},
        {"non-hex character", lower.substr(0, 63) + "g", std::nullopt},
        {"embedded space", lower.substr(0, 10) + " " + lower.substr(11), std::nullopt},
        {"0x prefix", "0x" + lower.substr(2), std::nullopt},
        {"colon separated", "ab:cd", std::nullopt},
    };
    for (const auto& r : rows) {
        INFO(r.name);
        CHECK(gp::parse_pin_hex(r.in) == r.want);
    }
}

TEST_CASE("gateway_peer_pinset: split_pin_list trims, skips empties and does not validate",
          "[gateway_peer][pinset]") {
    using V = std::vector<std::string>;
    const std::vector<std::pair<std::string, V>> rows{
        {"", V{}},
        {",", V{}},
        {"a", V{"a"}},
        {"a,b", V{"a", "b"}},
        {" a , b ,", V{"a", "b"}},
        {"a,,b", V{"a", "b"}},
        {"notahexpin,b", V{"notahexpin", "b"}},
    };
    for (const auto& [in, want] : rows) {
        INFO(in);
        CHECK(gp::split_pin_list(in) == want);
    }
}

TEST_CASE("gateway_peer_pinset: parse_pin_file, hex form", "[gateway_peer][pinset]") {
    using S = gp::PinFileState;
    const std::string a = pin_n(1);
    const std::string b = pin_n(2);
    struct Row {
        const char* name;
        std::string content;
        S state;
        std::vector<std::string> pins;
    };
    const std::vector<Row> rows{
        {"one pin", a + "\n", S::Loaded, {a}},
        {"no trailing newline", a, S::Loaded, {a}},
        {"comments, blanks and CRLF",
         "# gateway\r\n\r\n" + a + "\r\n  # again\r\n" + b + "\r\n", S::Loaded, {a, b}},
        {"duplicates collapse, order kept", b + "\n" + a + "\n" + b + "\n", S::Loaded, {b, a}},
        {"UTF-8 BOM tolerated", "\xEF\xBB\xBF" + a + "\n", S::Loaded, {a}},
        {"empty", "", S::Empty, {}},
        {"whitespace only", " \n\t\n", S::Empty, {}},
        {"comments only", "# nothing here\n", S::Empty, {}},
        {"BOM only", "\xEF\xBB\xBF", S::Empty, {}},
        {"a short line", a + "\n" + a.substr(1) + "\n", S::Malformed, {}},
        {"a non-hex line", "hello\n", S::Malformed, {}},
        {"a trailing comment on a pin line is malformed", a + " # gw\n", S::Malformed, {}},
        {"NUL byte", a + std::string(1, '\0') + "\n", S::Malformed, {}},
        {"32 pins is the bound", hex_lines(10, 32), S::Loaded, {}},
        {"33 pins is over it", hex_lines(10, 33), S::OverCount, {}},
    };
    for (const auto& r : rows) {
        INFO(r.name);
        const auto p = gp::parse_pin_file(r.content);
        CHECK(p.state == r.state);
        if (!r.pins.empty())
            CHECK(p.pins == r.pins);
        if (r.state != S::Loaded)
            CHECK(p.pins.empty());
    }
    CHECK(gp::parse_pin_file(hex_lines(10, 32)).pins.size() == 32);
}

TEST_CASE("gateway_peer_pinset: parse_pin_file, UTF-16 and size bound fail closed",
          "[gateway_peer][pinset]") {
    // UTF-16LE with a byte order mark: every other byte is NUL.
    std::string utf16 = "\xFF\xFE";
    for (const char c : pin_n(1) + "\n") {
        utf16 += c;
        utf16 += '\0';
    }
    CHECK(gp::parse_pin_file(utf16).state == gp::PinFileState::Malformed);

    CHECK(gp::parse_pin_file(std::string(gp::kMaxPinFileBytes + 1, '#')).state ==
          gp::PinFileState::TooLarge);
    // Exactly the bound is read (one long comment line holds no pins).
    CHECK(gp::parse_pin_file(std::string(gp::kMaxPinFileBytes, '#')).state ==
          gp::PinFileState::Empty);
}

TEST_CASE("gateway_peer_pinset: parse_pin_file, PEM form", "[gateway_peer][pinset]") {
    using S = gp::PinFileState;
    const auto ca = gwt::make_ca("Pinset CA");
    const auto gw1 = gwt::make_gateway_leaf(ca, "gw1");
    const auto gw2 = gwt::make_gateway_leaf(ca, "gw2");
    const auto agent = gwt::make_agent_leaf(ca);
    const std::string p1 = pin_of(gw1.cert_pem);
    const std::string p2 = pin_of(gw2.cert_pem);

    SECTION("one block, and EVERY block contributes its pin") {
        const auto one = gp::parse_pin_file(gw1.cert_pem);
        CHECK(one.state == S::Loaded);
        CHECK(one.pins == std::vector<std::string>{p1});
        const auto two = gp::parse_pin_file(gw1.cert_pem + "\n" + gw2.cert_pem);
        CHECK(two.state == S::Loaded);
        CHECK(two.pins == (std::vector<std::string>{p1, p2}));
        CHECK(two.pins_without_server_auth == 0);
    }
    SECTION("a block without serverAuth still pins and is counted") {
        const auto r = gp::parse_pin_file(gw1.cert_pem + agent.cert_pem);
        CHECK(r.state == S::Loaded);
        CHECK(r.pins.size() == 2);
        CHECK(r.pins_without_server_auth == 1);
    }
    SECTION("a UTF-8 BOM, CRLF line endings, and both together are tolerated") {
        const std::string crlf = to_crlf(gw1.cert_pem);
        REQUIRE(crlf.find("\r\n") != std::string::npos);
        for (const auto& content : {"\xEF\xBB\xBF" + gw1.cert_pem, crlf, "\xEF\xBB\xBF" + crlf,
                                    crlf + to_crlf(gw2.cert_pem)}) {
            const auto r = gp::parse_pin_file(content);
            CHECK(r.state == S::Loaded);
            CHECK(!r.pins.empty());
            CHECK(r.pins.front() == p1);
        }
        CHECK(gp::parse_pin_file(crlf + to_crlf(gw2.cert_pem)).pins ==
              (std::vector<std::string>{p1, p2}));
    }
    SECTION("a duplicate block that lacks serverAuth is counted once") {
        const auto r = gp::parse_pin_file(agent.cert_pem + agent.cert_pem);
        CHECK(r.state == S::Loaded);
        CHECK(r.pins.size() == 1);
        CHECK(r.pins_without_server_auth == 1);
    }
    SECTION("duplicate blocks collapse, 32 blocks are the bound, 33 are over it") {
        CHECK(gp::parse_pin_file(repeat_pem(gw1.cert_pem, 32)).pins.size() == 1);
        CHECK(gp::parse_pin_file(repeat_pem(gw1.cert_pem, 33)).state == S::OverCount);
    }
    SECTION("anything not a complete CERTIFICATE file is malformed") {
        const std::vector<std::pair<const char*, std::string>> bad{
            {"hex mixed with PEM (hex first)", pin_n(1) + "\n" + gw1.cert_pem},
            {"hex mixed with PEM (hex last)", gw1.cert_pem + pin_n(1) + "\n"},
            {"a private key block", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"},
            {"stray text between blocks", gw1.cert_pem + "stray\n" + gw2.cert_pem},
            {"an unterminated block", "-----BEGIN CERTIFICATE-----\nAAAA\n"},
            {"a block whose body does not parse", kBadCertPem},
            {"one good and one bad block", gw1.cert_pem + kBadCertPem},
        };
        for (const auto& [name, content] : bad) {
            INFO(name);
            const auto r = gp::parse_pin_file(content);
            CHECK(r.state == S::Malformed);
            CHECK(r.pins.empty());
        }
    }
}

TEST_CASE("gateway_peer_pinset: PinSet is an immutable set probed by string_view",
          "[gateway_peer][pinset]") {
    const gp::PinSet empty;
    CHECK(empty.empty());
    CHECK(empty.size() == 0);
    CHECK_FALSE(empty.contains(pin_n(1)));

    const gp::PinSet s{{pin_n(1), pin_n(2), pin_n(1)}, 3};
    CHECK(s.size() == 2);
    CHECK_FALSE(s.empty());
    CHECK(s.pins_without_server_auth() == 3);
    CHECK(s.contains(pin_n(1)));
    CHECK(s.contains(std::string_view{pin_n(2)}));
    CHECK_FALSE(s.contains(pin_n(3)));
    // Whole-value equality only: a prefix of a pin is not a pin.
    CHECK_FALSE(s.contains(pin_n(1).substr(0, 8)));
    CHECK_FALSE(s.contains(""));
}

TEST_CASE("gateway_peer_pinset: load_boot_pins builds the union of explicit sources",
          "[gateway_peer][pinset][boot]") {
    FakeFs fs;
    const auto ca = gwt::make_ca("Boot CA");
    const auto gw = gwt::make_gateway_leaf(ca);
    fs.put("/pins/a", "# a\n" + pin_n(2) + "\n" + pin_n(3) + "\n");
    fs.put("/pins/b.pem", gw.cert_pem);

    SECTION("hex plus two files, de-duplicated across sources") {
        const auto r = gp::load_boot_pins({pin_n(1), pin_n(2)}, {"/pins/a", "/pins/b.pem"},
                                          "/auto/default.pem", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->size() == 4); // 1, 2 (dup), 3, gateway key
        for (const auto& p : {pin_n(1), pin_n(2), pin_n(3), pin_of(gw.cert_pem)})
            CHECK(r->contains(p));
    }
    SECTION("upper-case hex is normalised") {
        std::string up = pin_n(0xABC);
        for (auto& c : up)
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        const auto r = gp::load_boot_pins({up}, {}, "", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->contains(pin_n(0xABC)));
    }
    SECTION("the pins-without-serverAuth count reaches the set") {
        fs.put("/pins/agent.pem", gwt::make_agent_leaf(ca).cert_pem);
        const auto r = gp::load_boot_pins({}, {"/pins/agent.pem"}, "", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->pins_without_server_auth() == 1);
    }
    SECTION("exactly kMaxPins across two files is allowed, one more is an error") {
        fs.put("/pins/c", hex_lines(100, 32));
        fs.put("/pins/d", hex_lines(200, 32));
        fs.put("/pins/e", hex_lines(300, 1));
        const auto ok = gp::load_boot_pins({}, {"/pins/c", "/pins/d"}, "", fs.reader());
        REQUIRE(ok.has_value());
        CHECK(ok->size() == gp::kMaxPins);
        const auto over = gp::load_boot_pins({}, {"/pins/c", "/pins/d", "/pins/e"}, "", fs.reader());
        CHECK_FALSE(over.has_value());
    }
}

TEST_CASE("gateway_peer_pinset: load_boot_pins uses the auto-pin only when nothing explicit was given",
          "[gateway_peer][pinset][boot]") {
    FakeFs fs;
    const auto ca = gwt::make_ca("Boot CA");
    const auto gw = gwt::make_gateway_leaf(ca);
    fs.put("/auto/default-gateway.pem", gw.cert_pem);

    SECTION("no explicit source: the auto-pin file is the set") {
        const auto r = gp::load_boot_pins({}, {}, "/auto/default-gateway.pem", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->size() == 1);
        CHECK(r->contains(pin_of(gw.cert_pem)));
    }
    SECTION("an explicit hex pin replaces it, and the auto file is never read") {
        const auto r = gp::load_boot_pins({pin_n(1)}, {}, "/auto/default-gateway.pem", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->size() == 1);
        CHECK_FALSE(r->contains(pin_of(gw.cert_pem)));
        CHECK(fs.reads.empty());
    }
    SECTION("a missing auto-pin file is an error naming the file") {
        const auto r = gp::load_boot_pins({}, {}, "/auto/absent.pem", fs.reader());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("/auto/absent.pem") != std::string::npos);
    }
    SECTION("nothing at all is an error, not an empty set") {
        CHECK_FALSE(gp::load_boot_pins({}, {}, "", fs.reader()).has_value());
    }
}

TEST_CASE("gateway_peer_pinset: a broken explicit source is an error and NEVER falls back to the "
          "auto-pin",
          "[gateway_peer][pinset][boot]") {
    using St = gp::FileReadResult::Status;
    FakeFs fs;
    const auto ca = gwt::make_ca("Boot CA");
    const std::string good_auto = gwt::make_gateway_leaf(ca).cert_pem;
    fs.put("/auto/default-gateway.pem", good_auto);
    fs.put("/pins/malformed", "hello\n");
    fs.put("/pins/empty", "# nothing\n");
    fs.put("/pins/over", hex_lines(1, 33));
    fs.put("/pins/utf16", std::string("\xFF\xFE" "a\0b\0", 6));
    fs.put_status("/pins/unreadable", St::Unreadable);
    fs.put_status("/pins/big", St::TooLarge);

    const std::vector<std::pair<const char*, std::string>> broken{
        {"missing", "/pins/missing"},       {"malformed", "/pins/malformed"},
        {"empty", "/pins/empty"},           {"over the per-file count", "/pins/over"},
        {"UTF-16", "/pins/utf16"},          {"unreadable", "/pins/unreadable"},
        {"too large", "/pins/big"},         {"an empty path", ""},
    };
    for (const auto& [name, path] : broken) {
        INFO(name);
        const auto r = gp::load_boot_pins({}, {path}, "/auto/default-gateway.pem", fs.reader());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("pin") != std::string::npos);
        for (const auto& read : fs.reads)
            CHECK(read != "/auto/default-gateway.pem");
        fs.reads.clear();
    }

    SECTION("one broken file poisons a union that also has a good file and a good hex pin") {
        fs.put("/pins/good", pin_n(7) + "\n");
        CHECK_FALSE(gp::load_boot_pins({pin_n(1)}, {"/pins/good", "/pins/malformed"},
                                       "/auto/default-gateway.pem", fs.reader())
                        .has_value());
    }
    SECTION("a throwing reader is an error, not a crash") {
        fs.throws = true;
        CHECK_FALSE(gp::load_boot_pins({}, {"/pins/good"}, "", fs.reader()).has_value());
    }
    SECTION("a malformed hex pin is an error that does not echo the whole value") {
        const std::string bad = pin_n(1).substr(0, 63) + "z";
        const auto r = gp::load_boot_pins({bad}, {}, "/auto/default-gateway.pem", fs.reader());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find(bad) == std::string::npos);
        CHECK(r.error().find(bad.substr(0, 8)) != std::string::npos);
    }
    SECTION("a malformed hex pin next to a good one is still an error") {
        CHECK_FALSE(gp::load_boot_pins({pin_n(1), "abc"}, {}, "", fs.reader()).has_value());
    }
}

TEST_CASE("gateway_peer_pinset: the default filesystem reader is bounded and regular-file only",
          "[gateway_peer][pinset][boot]") {
    yuzu::test::TempDir dir{"yuzu_test_gwpeer_pins_"};
    std::filesystem::create_directories(dir.path);
    const auto write = [&](const char* name, const std::string& content) {
        const auto p = dir.path / name;
        std::ofstream(p, std::ios::binary) << content;
        return p.string();
    };
    const std::string good = write("good", pin_n(1) + "\n");
    const std::string big = write("big", std::string(gp::kMaxPinFileBytes + 1, '#'));
    using St = gp::FileReadResult::Status;

    CHECK(gp::read_file_bounded(good, gp::kMaxPinFileBytes).status == St::Ok);
    CHECK(gp::read_file_bounded(good, gp::kMaxPinFileBytes).content == pin_n(1) + "\n");
    CHECK(gp::read_file_bounded(good, 10).status == St::TooLarge);
    CHECK(gp::read_file_bounded(big, gp::kMaxPinFileBytes).status == St::TooLarge);
    CHECK(gp::read_file_bounded((dir.path / "absent").string(), 100).status == St::Missing);
    CHECK(gp::read_file_bounded(dir.path.string(), 100).status == St::Unreadable);

    // End to end through the real reader (null FileReader).
    const auto r = gp::load_boot_pins({}, {good}, "");
    REQUIRE(r.has_value());
    CHECK(r->contains(pin_n(1)));
    CHECK_FALSE(gp::load_boot_pins({}, {big}, "").has_value());
    CHECK_FALSE(gp::load_boot_pins({}, {(dir.path / "absent").string()}, "").has_value());
}

TEST_CASE("gateway_peer_pinset: the default reader decides from one open and never blocks on a "
          "non-regular file",
          "[gateway_peer][pinset][boot]") {
    yuzu::test::TempDir dir{"yuzu_test_gwpeer_reader_"};
    std::filesystem::create_directories(dir.path);
    using St = gp::FileReadResult::Status;
    const auto write = [&](const char* name, const std::string& content) {
        const auto p = dir.path / name;
        std::ofstream(p, std::ios::binary) << content;
        return p.string();
    };

    SECTION("the bound is exact: max_bytes is read, one byte more is TooLarge") {
        const std::string exact = write("exact", std::string(100, 'x'));
        const auto at = gp::read_file_bounded(exact, 100);
        CHECK(at.status == St::Ok);
        CHECK(at.content.size() == 100);
        CHECK(gp::read_file_bounded(exact, 99).status == St::TooLarge);
    }
    SECTION("an empty file is Ok with no content, and a multi-chunk file is returned whole") {
        const auto empty = gp::read_file_bounded(write("empty", ""), 100);
        CHECK(empty.status == St::Ok);
        CHECK(empty.content.empty());
        std::string big;
        for (int i = 0; i < 10000; ++i)
            big += static_cast<char>('a' + (i % 26));
        const auto r = gp::read_file_bounded(write("big", big), 20000);
        CHECK(r.status == St::Ok);
        CHECK(r.content == big);
    }
    SECTION("an unbounded max is refused instead of allocating") {
        CHECK(gp::read_file_bounded(write("any", "x"), std::size_t{1} << 30).status == St::Unreadable);
    }
    SECTION("a path component that is a file is Missing, like an absent path") {
        const std::string f = write("plain", "x");
        CHECK(gp::read_file_bounded(f + "/child", 100).status == St::Missing);
    }
#ifndef _WIN32
    SECTION("a symlink to a regular file is followed (secret mounts present files that way)") {
        const std::string target = write("target", pin_n(5) + "\n");
        const auto link = dir.path / "link";
        std::filesystem::create_symlink(target, link);
        const auto r = gp::read_file_bounded(link.string(), gp::kMaxPinFileBytes);
        CHECK(r.status == St::Ok);
        CHECK(r.content == pin_n(5) + "\n");
        // ... and the target is held to the same bound.
        CHECK(gp::read_file_bounded(link.string(), 3).status == St::TooLarge);
    }
    SECTION("a dangling symlink is Missing") {
        const auto link = dir.path / "dangling";
        std::filesystem::create_symlink(dir.path / "nowhere", link);
        CHECK(gp::read_file_bounded(link.string(), 100).status == St::Missing);
    }
    SECTION("a FIFO is refused promptly, with no writer to wait for") {
        const auto fifo = (dir.path / "fifo").string();
        REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
        const auto r = run_bounded([fifo] { return gp::read_file_bounded(fifo, 100).status; },
                                   std::chrono::seconds(10), [fifo] {
                                       // Unblock a reader that did wait: open the write end.
                                       // Owned by a scope guard so every path closes it.
                                       struct FdCloser {
                                           int fd;
                                           ~FdCloser() {
                                               if (fd >= 0)
                                                   ::close(fd);
                                           }
                                       } writer{::open(fifo.c_str(), O_WRONLY | O_NONBLOCK)};
                                   });
        REQUIRE(r.has_value()); // nullopt: the read blocked on the FIFO
        CHECK(*r == St::Unreadable);
    }
    SECTION("a character device is refused, not read") {
        if (!std::filesystem::exists("/dev/zero"))
            SKIP("no /dev/zero on this host");
        CHECK(gp::read_file_bounded("/dev/zero", 100).status == St::Unreadable);
    }
    SECTION("a file whose fstat size is 0 but whose read yields more than the bound is TooLarge") {
        // The size pre-check cannot catch this (st_size is 0 for a procfs file), so only the
        // post-read bound stops it being returned truncated as Ok.
        const char* const proc_file = "/proc/self/status";
        struct stat sb{};
        if (::stat(proc_file, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size != 0)
            SKIP("no zero-size regular /proc/self/status on this host");
        const auto over = gp::read_file_bounded(proc_file, 16);
        CHECK(over.status == St::TooLarge);
        CHECK(over.content.empty());
        // Control: with a generous bound the same file reads fine, so the line above is the bound
        // being enforced and not an unreadable file.
        const auto roomy = gp::read_file_bounded(proc_file, gp::kMaxPinFileBytes);
        CHECK(roomy.status == St::Ok);
        CHECK(roomy.content.size() > 16);
    }
#endif
}

TEST_CASE("gateway_peer_pinset: a supplied hex pin option with no pin in it is an error, not "
          "'not supplied'",
          "[gateway_peer][pinset][boot]") {
    FakeFs fs;
    const auto ca = gwt::make_ca("Boot CA");
    fs.put("/auto/default-gateway.pem", gwt::make_gateway_leaf(ca).cert_pem);

    for (const char* blank : {"", " ", " \t ", "\n"}) {
        INFO("blank value: [" << blank << "]");
        // Alone, next to a good pin, and with a perfectly good auto-pin file available: never a
        // silent fall-through to the auto-pin.
        for (const auto& hex : {std::vector<std::string>{blank},
                                std::vector<std::string>{pin_n(1), blank}}) {
            const auto r = gp::load_boot_pins(hex, {}, "/auto/default-gateway.pem", fs.reader());
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == "gateway peer pin option supplied but contains no pin");
        }
    }
    CHECK(fs.reads.empty()); // refused before any file was read
}

TEST_CASE("gateway_peer_pinset: the pins-without-serverAuth count is of DISTINCT pins with no "
          "serverAuth source",
          "[gateway_peer][pinset][boot]") {
    FakeFs fs;
    const auto ca = gwt::make_ca("Boot CA");
    const auto agent = gwt::make_agent_leaf(ca);
    const auto gateway = gwt::make_gateway_leaf(ca);
    const std::string agent_pin = pin_of(agent.cert_pem);
    fs.put("/pins/agent2x.pem", agent.cert_pem + agent.cert_pem);
    fs.put("/pins/agent.pem", agent.cert_pem);
    fs.put("/pins/agent-hex", agent_pin + "\n");
    fs.put("/pins/gw.pem", gateway.cert_pem);

    SECTION("the same certificate twice, in one file or two, is one pin and one count") {
        auto r = gp::load_boot_pins({}, {"/pins/agent2x.pem"}, "", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->size() == 1);
        CHECK(r->pins_without_server_auth() == 1);
        r = gp::load_boot_pins({}, {"/pins/agent.pem", "/pins/agent2x.pem"}, "", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->size() == 1);
        CHECK(r->pins_without_server_auth() == 1);
    }
    SECTION("a bare hex pin carries no extended key usage, so it is never counted") {
        const auto r = gp::load_boot_pins({agent_pin}, {}, "", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->pins_without_server_auth() == 0);
    }
    SECTION("a key that ANY source supplies as usable is not counted, in either order") {
        for (const auto& files : {std::vector<std::string>{"/pins/agent.pem", "/pins/agent-hex"},
                                  std::vector<std::string>{"/pins/agent-hex", "/pins/agent.pem"}}) {
            const auto r = gp::load_boot_pins({}, files, "", fs.reader());
            REQUIRE(r.has_value());
            CHECK(r->size() == 1);
            CHECK(r->pins_without_server_auth() == 0);
        }
        const auto via_hex_pin = gp::load_boot_pins({agent_pin}, {"/pins/agent.pem"}, "", fs.reader());
        REQUIRE(via_hex_pin.has_value());
        CHECK(via_hex_pin->pins_without_server_auth() == 0);
    }
    SECTION("a mixed set counts only the pin that lacks serverAuth") {
        const auto r = gp::load_boot_pins({}, {"/pins/agent.pem", "/pins/gw.pem"}, "", fs.reader());
        REQUIRE(r.has_value());
        CHECK(r->size() == 2);
        CHECK(r->pins_without_server_auth() == 1);
    }
}

TEST_CASE("gateway_peer_pinset: sorted_pins is stable and complete", "[gateway_peer][pinset]") {
    const gp::PinSet s{{pin_n(3), pin_n(1), pin_n(2)}};
    CHECK(s.sorted_pins() == (std::vector<std::string>{pin_n(1), pin_n(2), pin_n(3)}));
    CHECK(gp::PinSet{}.sorted_pins().empty());
}

// -- [policy] -------------------------------------------------------------------

TEST_CASE("gateway_peer_policy: the closed reason set and its label literals",
          "[gateway_peer][policy]") {
    const std::vector<std::pair<gp::DenyReason, std::string_view>> expected{
        {gp::DenyReason::NullContext, "null_context"},
        {gp::DenyReason::NotAuthenticated, "not_authenticated"},
        {gp::DenyReason::NoCert, "no_cert"},
        {gp::DenyReason::BadCert, "bad_cert"},
        {gp::DenyReason::NoServerAuthEku, "no_server_auth_eku"},
        {gp::DenyReason::NotPinned, "not_pinned"},
        {gp::DenyReason::OutsideValidity, "outside_validity"},
        {gp::DenyReason::InternalError, "internal_error"},
    };
    REQUIRE(gp::kAllDenyReasons.size() == 8);
    REQUIRE(expected.size() == gp::kAllDenyReasons.size());
    std::set<std::string_view> labels;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        CHECK(gp::kAllDenyReasons[i] == expected[i].first);
        CHECK(gp::to_label(expected[i].first) == expected[i].second);
        labels.insert(gp::to_label(expected[i].first));
    }
    CHECK(labels.size() == 8);
    // The sentinel counts the reasons and is itself none of them.
    CHECK(static_cast<std::size_t>(gp::DenyReason::kCount) == gp::kAllDenyReasons.size());
    for (const auto r : gp::kAllDenyReasons)
        CHECK(r != gp::DenyReason::kCount);
    CHECK(gp::kNotBeforeLeeway == std::chrono::minutes(5));
    CHECK_FALSE(gp::Decision{}.allowed);
}

TEST_CASE("gateway_peer_policy: decision table, one row per reason and the allow",
          "[gateway_peer][policy]") {
    const auto ca = gwt::make_ca("Policy Test CA");
    const auto gateway = gwt::make_gateway_leaf(ca);
    const auto agent = gwt::make_agent_leaf(ca);
    const auto expired = gwt::make_leaf(ca, "Old Gateway", true, true, gwt::expired_validity());
    const auto future = gwt::make_leaf(ca, "Future Gateway", true, true,
                                       gwt::not_yet_valid_validity());
    const auto renewed = gwt::reissue_same_key(ca, gateway, "Renewed", true, true);
    const auto any_eku = gwt::make_leaf_with_eku(ca, "Any EKU", "anyExtendedKeyUsage");
    const SysTime now = std::chrono::system_clock::now();
    const SysTime nb9999{seconds{kYear9999NotBeforeEpoch}};

    const auto good = pins_of({pin_of(gateway.cert_pem)});
    const auto none = pins_of({});

    struct Row {
        const char* name;
        gp::PeerEvidence ev;
        std::shared_ptr<const gp::PinSet> pins;
        SysTime at;
        std::optional<gp::DenyReason> deny; ///< nullopt = allow
    };
    using R = gp::DenyReason;
    const std::vector<Row> rows{
        {"allow: pinned serverAuth leaf inside its window", evidence(gateway.cert_pem), good, now,
         std::nullopt},
        {"allow: same-key reissue", evidence(renewed.cert_pem), good, now, std::nullopt},
        {"allow: never-expiring pinned certificate", evidence(gwt::kYear9999Pem),
         pins_of({kYear9999Spki}), now, std::nullopt},
        {"null context", evidence(gateway.cert_pem, true, false), good, now, R::NullContext},
        {"not authenticated, PEM present", evidence(gateway.cert_pem, false), good, now,
         R::NotAuthenticated},
        {"not authenticated, no PEM", evidence("", false), good, now, R::NotAuthenticated},
        {"authenticated, no certificate property", evidence(""), good, now, R::NoCert},
        {"unparseable certificate", evidence("garbage"), good, now, R::BadCert},
        {"certificate with a garbage body", evidence(kBadCertPem), good, now, R::BadCert},
        {"clientAuth-only leaf whose key IS pinned", evidence(agent.cert_pem),
         pins_of({pin_of(agent.cert_pem)}), now, R::NoServerAuthEku},
        {"no EKU extension at all, pinned", evidence(kVectorPem), pins_of({kVectorSpki}), now,
         R::NoServerAuthEku},
        {"serverAuth leaf, key not pinned", evidence(gateway.cert_pem),
         pins_of({pin_of(agent.cert_pem)}), now, R::NotPinned},
        {"clientAuth-only leaf, key NOT pinned: the EKU check comes first", evidence(agent.cert_pem),
         good, now, R::NoServerAuthEku},
        {"anyExtendedKeyUsage-only leaf, key pinned: not serverAuth", evidence(any_eku.cert_pem),
         pins_of({pin_of(any_eku.cert_pem)}), now, R::NoServerAuthEku},
        {"pinned, expired", evidence(expired.cert_pem), pins_of({pin_of(expired.cert_pem)}), now,
         R::OutsideValidity},
        {"pinned, not yet valid", evidence(future.cert_pem), pins_of({pin_of(future.cert_pem)}),
         now, R::OutsideValidity},
        {"pinned, 301 s before notBefore", evidence(gwt::kYear9999Pem), pins_of({kYear9999Spki}),
         nb9999 - seconds(301), R::OutsideValidity},
        {"an empty pin set denies even a perfect certificate", evidence(gateway.cert_pem), none,
         now, R::InternalError},
    };
    std::set<R> seen;
    for (const auto& r : rows) {
        INFO(r.name);
        const gp::Decision d = gp::decide(r.ev, *r.pins, r.at);
        CHECK(d.allowed == !r.deny.has_value());
        if (r.deny) {
            CHECK(d.reason == *r.deny);
            seen.insert(*r.deny);
        }
    }
    CHECK(seen.size() == gp::kAllDenyReasons.size()); // every closed reason has a row
}

TEST_CASE("gateway_peer_policy: a reason that proves an authenticated certificate holder is "
          "never produced for anyone else",
          "[gateway_peer][policy]") {
    // reason_proves_authenticated_cert_holder() is what lets the guard offer an audit row only to
    // a caller that is expensive to impersonate. Pin it against decide() itself: sweep every
    // combination of the evidence and require that a "proving" reason is only ever returned for a
    // transport-authenticated peer whose certificate parsed.
    const auto ca = gwt::make_ca("Policy Test CA");
    const auto gateway = gwt::make_gateway_leaf(ca);
    const auto agent = gwt::make_agent_leaf(ca);
    const auto expired = gwt::make_leaf(ca, "Old", true, true, gwt::expired_validity());
    const SysTime now = std::chrono::system_clock::now();
    const std::vector<std::shared_ptr<const gp::PinSet>> pin_sets{
        pins_of({}), pins_of({pin_of(gateway.cert_pem)}),
        pins_of({pin_of(gateway.cert_pem), pin_of(agent.cert_pem), pin_of(expired.cert_pem)})};
    const std::vector<std::pair<std::string, bool>> pems{
        {"", false}, {"garbage", false}, {kBadCertPem, false}, {gateway.cert_pem, true},
        {agent.cert_pem, true}, {expired.cert_pem, true}};

    std::set<gp::DenyReason> proving_seen;
    for (const bool ctx : {false, true}) {
        for (const bool authenticated : {false, true}) {
            for (const auto& [pem, parses] : pems) {
                for (const auto& pins : pin_sets) {
                    const auto d = gp::decide(evidence(pem, authenticated, ctx), *pins, now);
                    if (d.allowed || !gp::reason_proves_authenticated_cert_holder(d.reason))
                        continue;
                    proving_seen.insert(d.reason);
                    INFO("ctx=" << ctx << " authenticated=" << authenticated
                                << " reason=" << gp::to_label(d.reason));
                    CHECK(ctx);
                    CHECK(authenticated);
                    CHECK(parses);
                }
            }
        }
    }
    // The sweep reaches every proving reason, so the predicate is not vacuously satisfied.
    CHECK(proving_seen == std::set<gp::DenyReason>{gp::DenyReason::NoServerAuthEku,
                                                   gp::DenyReason::NotPinned,
                                                   gp::DenyReason::OutsideValidity});
    // The predicate's own table: exactly those three.
    for (const auto r : gp::kAllDenyReasons)
        CHECK(gp::reason_proves_authenticated_cert_holder(r) == proving_seen.contains(r));
}

TEST_CASE("gateway_peer_policy: the validity window opens 5 minutes early and closes strictly",
          "[gateway_peer][policy][validity]") {
    const auto pins = pins_of({kYear9999Spki});
    const SysTime nb{seconds{kYear9999NotBeforeEpoch}};
    const auto at = [&](milliseconds off) {
        return gp::decide(evidence(gwt::kYear9999Pem), *pins, nb + off).allowed;
    };
    CHECK(at(std::chrono::minutes(1)));
    CHECK(at(milliseconds(0)));
    CHECK(at(-std::chrono::minutes(4)));
    CHECK(at(-seconds(300))); // exactly the leeway: still valid
    CHECK_FALSE(at(-seconds(301)));
    CHECK_FALSE(at(-milliseconds(300'500))); // `now` is judged by the whole second it falls in
    CHECK(at(-milliseconds(299'500)));

    const auto ca = gwt::make_ca("Policy Test CA");
    const auto leaf = gwt::make_gateway_leaf(ca);
    const auto facts = gp::parse_cert_facts(leaf.cert_pem);
    REQUIRE(facts.has_value());
    const auto lpins = pins_of({facts->spki_sha256_hex});
    const SysTime na{seconds{epoch_seconds(facts->not_after)}};
    const auto end = [&](milliseconds off) {
        return gp::decide(evidence(leaf.cert_pem), *lpins, na + off);
    };
    CHECK(end(-seconds(1)).allowed);
    CHECK(end(seconds(0)).allowed);        // the expiry second itself is inside
    CHECK(end(milliseconds(999)).allowed); // judged by the whole second
    const auto gone = end(seconds(1));
    CHECK_FALSE(gone.allowed);
    CHECK(gone.reason == gp::DenyReason::OutsideValidity);
}

TEST_CASE("gateway_peer_policy: only the leaf's own key counts; a chain and CA membership never "
          "substitute",
          "[gateway_peer][policy]") {
    const auto root = gwt::make_ca("Policy Root");
    const auto inter = gwt::make_intermediate(root, "Policy Intermediate");
    const auto leaf = gwt::make_gateway_leaf(inter);
    const SysTime now = std::chrono::system_clock::now();

    // leaf + intermediate presented together: judged on the leaf (the first certificate).
    const std::string chain = leaf.cert_pem + inter.cert_pem;
    CHECK(gp::decide(evidence(chain), *pins_of({pin_of(leaf.cert_pem)}), now).allowed);
    // Pinning the issuing CA's key (or the root's) does not admit what it signed.
    for (const auto& ca_pem : {inter.cert_pem, root.cert_pem}) {
        const auto d = gp::decide(evidence(chain), *pins_of({pin_of(ca_pem)}), now);
        CHECK_FALSE(d.allowed);
        CHECK(d.reason == gp::DenyReason::NotPinned);
    }
}

TEST_CASE("gateway_peer_policy: a decision carries the peer's key once its certificate parsed",
          "[gateway_peer][policy]") {
    const auto ca = gwt::make_ca("Policy Test CA");
    const auto gateway = gwt::make_gateway_leaf(ca);
    const auto agent = gwt::make_agent_leaf(ca);
    const std::string gw_pin = pin_of(gateway.cert_pem);
    const std::string agent_pin = pin_of(agent.cert_pem);
    const SysTime now = std::chrono::system_clock::now();
    const auto good = pins_of({gw_pin});

    // The allow and each denial AFTER the parse name the certificate's key ...
    CHECK(gp::decide(evidence(gateway.cert_pem), *good, now).spki_sha256_hex == gw_pin);
    CHECK(gp::decide(evidence(agent.cert_pem), *good, now).spki_sha256_hex == agent_pin);
    const auto np = gp::decide(evidence(gateway.cert_pem), *pins_of({agent_pin}), now);
    CHECK(np.reason == gp::DenyReason::NotPinned);
    CHECK(np.spki_sha256_hex == gw_pin);
    // ... a denial BEFORE it has no key to report.
    CHECK(gp::decide(evidence("x", true, false), *good, now).spki_sha256_hex.empty());
    CHECK(gp::decide(evidence(gateway.cert_pem, false), *good, now).spki_sha256_hex.empty());
    CHECK(gp::decide(evidence(""), *good, now).spki_sha256_hex.empty());
    CHECK(gp::decide(evidence("garbage"), *good, now).spki_sha256_hex.empty());
}

TEST_CASE("gateway_peer_policy: GatewayPeerPolicy binds the pin set and the clock and contains "
          "failures",
          "[gateway_peer][policy]") {
    const auto ca = gwt::make_ca("Policy Test CA");
    const auto gateway = gwt::make_gateway_leaf(ca);
    const auto expired = gwt::make_leaf(ca, "Old", true, true, gwt::expired_validity());
    const auto pins = pins_of({pin_of(gateway.cert_pem), pin_of(expired.cert_pem)});

    SECTION("the default clock is the wall clock") {
        const gp::GatewayPeerPolicy p{pins};
        CHECK(p.decide(evidence(gateway.cert_pem)).allowed);
        const auto d = p.decide(evidence(expired.cert_pem));
        CHECK_FALSE(d.allowed);
        CHECK(d.reason == gp::DenyReason::OutsideValidity);
    }
    SECTION("an injected clock is what validity is judged against") {
        const gp::GatewayPeerPolicy p{
            pins, [] { return std::chrono::system_clock::now() - std::chrono::hours(36); }};
        CHECK(p.decide(evidence(expired.cert_pem)).allowed);
    }
    SECTION("a throwing clock denies with internal_error and does not propagate") {
        const gp::GatewayPeerPolicy p{
            pins, []() -> SysTime { throw std::runtime_error("clock down"); }};
        const auto d = p.decide(evidence(gateway.cert_pem));
        CHECK_FALSE(d.allowed);
        CHECK(d.reason == gp::DenyReason::InternalError);
    }
    SECTION("a null or empty pin set denies with internal_error") {
        for (const auto& bad : {std::shared_ptr<const gp::PinSet>{}, pins_of({})}) {
            const gp::GatewayPeerPolicy p{bad};
            const auto d = p.decide(evidence(gateway.cert_pem));
            CHECK_FALSE(d.allowed);
            CHECK(d.reason == gp::DenyReason::InternalError);
        }
    }
}
