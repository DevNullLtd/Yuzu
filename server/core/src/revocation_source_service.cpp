#include "revocation_source_service.hpp"

#include "oidc_egress_policy.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/log_token.hpp>

// OpenSSL is an unconditional server dependency on every platform. bounded_resolver.hpp defines
// WIN32_LEAN_AND_MEAN and NOMINMAX before winsock2.h (idempotently), which keeps wincrypt.h - the
// header that redefines X509_NAME as a macro - out of any <windows.h> it pulls in. Do not include
// <windows.h> in this TU without those macros.
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "bounded_resolver.hpp"
#include "nat64_discovery.hpp"
#include "nat64_probe.hpp"

#include <spdlog/spdlog.h>

#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
// clang-format on
#pragma comment(lib, "iphlpapi.lib")
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <array>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <string_view>

namespace yuzu::server::revocation_source {

namespace eg = ::yuzu::server::oidc::egress;

namespace {

using Kind = ServiceError::Kind;

std::unexpected<ServiceError> invalid(std::string param, std::string message) {
    return std::unexpected(ServiceError{Kind::kInvalidParams, std::move(message), std::move(param), 0});
}

std::unexpected<ServiceError> map_store_error(const RevocationSourceStoreError& e) {
    using SK = RevocationSourceStoreError::Kind;
    switch (e.kind) {
    case SK::kNotFound:
        return std::unexpected(ServiceError{Kind::kNotFound, "no such revocation source", "", 0});
    case SK::kConflict:
        return std::unexpected(ServiceError{
            Kind::kConflict, "a source for this CA is already registered; update it instead", "",
            e.existing_id});
    case SK::kLimitReached:
        return std::unexpected(ServiceError{
            Kind::kConflict,
            "the limit of " + std::to_string(RevocationSourceStore::kMaxSources) +
                " registered sources is reached; remove one first with "
                "DELETE /api/v1/crypto/revocation-sources/{id}",
            "", 0});
    case SK::kSubjectChanged:
        return invalid("ca_certificates",
                       "the CA certificates name a different subject than the registered source; "
                       "a source is one CA - register the other CA as its own source");
    case SK::kVersionConflict:
        return std::unexpected(ServiceError{
            Kind::kVersionConflict,
            "the source's config_version is " + std::to_string(e.existing_id) +
                ", not the expected one; another change was applied since you read it. Read the "
                "source and resend against its current config_version",
            "expected_config_version", e.existing_id});
    case SK::kBadResetTime:
        return invalid("reset_at", "reset_at must be no later than the server clock");
    case SK::kInvalidInput:
        return invalid("", "the request cannot be stored");
    case SK::kOutcomeUnknown:
        return std::unexpected(ServiceError{
            Kind::kOutcomeUnknown,
            "the change may or may not have been applied; read the source to check", "", 0});
    case SK::kNotOpen:
    case SK::kPoolAcquireTimeout:
    case SK::kQueryError:
        break;
    }
    return std::unexpected(
        ServiceError{Kind::kUnavailable, "revocation source store unavailable", "", 0});
}

// ---------------------------------------------------------------------------------------------
// Strict body parsing.

// A name is free text rendered in the UI and audit rows: refuse C0/DEL controls, the C1 block
// (U+0080..U+009F), the bidi controls (U+202A..U+202E, U+2066..U+2069, U+200E/F), zero-width and
// invisible characters (U+200B..U+200D, U+2060, U+FEFF) and a name with no visible character.
bool has_control(std::string_view s) {
    bool visible = false;
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x20 || c == 0x7f)
            return true;
        if (c < 0x80) {
            visible = visible || c != ' ';
            ++i;
            continue;
        }
        // Valid UTF-8 was checked by the caller; decode the code point.
        std::uint32_t cp = 0;
        std::size_t len = 1;
        if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
        else { cp = c & 0x07; len = 4; }
        for (std::size_t k = 1; k < len && i + k < s.size(); ++k)
            cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
        i += len;
        if ((cp >= 0x80 && cp <= 0x9F) || (cp >= 0x200B && cp <= 0x200F) ||
            (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2060 && cp <= 0x2064) ||
            (cp >= 0x2066 && cp <= 0x2069) || cp == 0xFEFF || cp == 0x00A0 || cp == 0x3000 ||
            cp == 0x2028 || cp == 0x2029 || cp == 0x061C || cp == 0x180E ||
            (cp >= 0x2000 && cp <= 0x200A) || cp == 0x202F || cp == 0x205F || cp == 0x1680 ||
            cp == 0x3164 || cp == 0x115F || cp == 0x1160 || cp == 0xFFA0 || cp == 0x2800 ||
            cp == 0x034F || cp == 0x17B4 || cp == 0x17B5 || cp == 0x2065)
            return true;
        visible = true;
    }
    return !visible;
}

std::expected<void, ServiceError> only_keys(const nlohmann::json& obj, std::string_view where,
                                            std::initializer_list<std::string_view> allowed) {
    for (const auto& [k, v] : obj.items()) {
        if (std::ranges::find(allowed, std::string_view(k)) == allowed.end())
            return invalid(k, std::string(where) + " has an unknown key");
    }
    return {};
}

// ---------------------------------------------------------------------------------------------
// OpenSSL RAII.

struct BioFree {
    void operator()(BIO* b) const { BIO_free(b); }
};
struct X509Free {
    void operator()(X509* x) const { X509_free(x); }
};
struct OsslFree {
    void operator()(unsigned char* p) const { OPENSSL_free(p); }
};
struct BcFree {
    void operator()(BASIC_CONSTRAINTS* b) const { BASIC_CONSTRAINTS_free(b); }
};

std::string hex_lower(const unsigned char* p, std::size_t n) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(kDigits[p[i] >> 4]);
        out.push_back(kDigits[p[i] & 0x0f]);
    }
    return out;
}

std::optional<std::string> sha256_hex(const unsigned char* p, std::size_t n) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(p, n, md, &len, EVP_sha256(), nullptr) != 1 || len != 32)
        return std::nullopt;
    return hex_lower(md, len);
}

struct ParsedCa {
    RevocationSourceKey key;
    std::string subject_sha256;
};

bool all_space(std::string_view s) {
    return std::ranges::all_of(s, [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    });
}

std::expected<ParsedCa, ServiceError> parse_ca_pem(const std::string& pem, std::size_t index) {
    const std::string param = "ca_certificates[" + std::to_string(index) + "]";
    if (pem.empty() || pem.size() > kMaxPemBytes)
        return invalid(param, "each PEM certificate must be 1.." + std::to_string(kMaxPemBytes) +
                                  " bytes");
    // The PEM must BEGIN with a CERTIFICATE block: no leading text, no private key, no bundle.
    std::size_t first = 0;
    while (first < pem.size() && (pem[first] == ' ' || pem[first] == '\t' || pem[first] == '\r' ||
                                  pem[first] == '\n'))
        ++first;
    if (pem.compare(first, 27, "-----BEGIN CERTIFICATE-----") != 0)
        return invalid(param, "must be one PEM CERTIFICATE block");
    std::unique_ptr<BIO, BioFree> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio)
        return std::unexpected(ServiceError{Kind::kUnavailable, "certificate parser unavailable", "", 0});
    std::unique_ptr<X509, X509Free> x(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!x) {
        ERR_clear_error();
        return invalid(param, "is not a parseable PEM certificate");
    }
    // Exactly one certificate: anything left over (a second block, a key) is refused.
    std::string rest(256, '\0');
    std::string leftover;
    for (;;) {
        const int n = BIO_read(bio.get(), rest.data(), static_cast<int>(rest.size()));
        if (n <= 0)
            break;
        leftover.append(rest.data(), static_cast<std::size_t>(n));
        if (leftover.size() > 4096)
            break;
    }
    if (!all_space(leftover))
        return invalid(param, "must hold exactly one certificate and nothing else");
    ERR_clear_error();

    // A CA: basicConstraints cA=TRUE, and cRLSign if a key usage extension is present.
    std::unique_ptr<BASIC_CONSTRAINTS, BcFree> bc(static_cast<BASIC_CONSTRAINTS*>(
        X509_get_ext_d2i(x.get(), NID_basic_constraints, nullptr, nullptr)));
    if (!bc || !bc->ca)
        return invalid(param, "is not a CA certificate (basicConstraints cA=TRUE is required)");
    const std::uint32_t ku = X509_get_key_usage(x.get());
    if (ku != UINT32_MAX && (ku & KU_CRL_SIGN) == 0)
        return invalid(param, "has a key usage extension without cRLSign");

    ParsedCa out;
    // Whole-certificate DER.
    {
        unsigned char* der = nullptr;
        const int len = i2d_X509(x.get(), &der);
        if (len <= 0 || der == nullptr)
            return invalid(param, "is not a parseable PEM certificate");
        std::unique_ptr<unsigned char, OsslFree> guard(der);
        if (static_cast<std::size_t>(len) > RevocationSourceStore::kMaxCertDerBytes)
            return invalid(param, "certificate is too large");
        out.key.cert_der.assign(reinterpret_cast<const char*>(der), static_cast<std::size_t>(len));
        auto h = sha256_hex(der, static_cast<std::size_t>(len));
        if (!h)
            return std::unexpected(ServiceError{Kind::kUnavailable, "digest unavailable", "", 0});
        out.key.cert_sha256 = std::move(*h);
    }
    // Subject Name DER.
    {
        unsigned char* der = nullptr;
        const int len = i2d_X509_NAME(X509_get_subject_name(x.get()), &der);
        if (len <= 0 || der == nullptr)
            return invalid(param, "has no subject name");
        std::unique_ptr<unsigned char, OsslFree> guard(der);
        auto h = sha256_hex(der, static_cast<std::size_t>(len));
        if (!h)
            return std::unexpected(ServiceError{Kind::kUnavailable, "digest unavailable", "", 0});
        out.subject_sha256 = std::move(*h);
    }
    // SubjectPublicKeyInfo DER.
    {
        unsigned char* der = nullptr;
        const int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x.get()), &der);
        if (len <= 0 || der == nullptr)
            return invalid(param, "has no public key");
        std::unique_ptr<unsigned char, OsslFree> guard(der);
        auto h = sha256_hex(der, static_cast<std::size_t>(len));
        if (!h)
            return std::unexpected(ServiceError{Kind::kUnavailable, "digest unavailable", "", 0});
        out.key.spki_sha256 = std::move(*h);
    }
    if (const ASN1_OCTET_STRING* ski = X509_get0_subject_key_id(x.get());
        ski != nullptr && ASN1_STRING_length(ski) > 0)
        out.key.ski = hex_lower(ASN1_STRING_get0_data(ski),
                                static_cast<std::size_t>(ASN1_STRING_length(ski)));
    return out;
}

// ---------------------------------------------------------------------------------------------
// URL syntax.

struct UrlParts {
    std::string host; ///< lowercase, no brackets
    bool bracketed{false};
};

bool host_label_ok(std::string_view l) {
    if (l.empty() || l.size() > 63)
        return false;
    return std::ranges::all_of(l, [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    });
}

std::expected<UrlParts, std::string> parse_url_syntax(const std::string& url) {
    if (url.empty() || url.size() > RevocationSourceStore::kMaxUrlBytes)
        return std::unexpected("must be 1.." + std::to_string(RevocationSourceStore::kMaxUrlBytes) +
                               " bytes");
    // Printable ASCII only: no space, control, backslash or non-ASCII byte anywhere (an IDN host
    // is given as punycode).
    if (std::ranges::any_of(url, [](unsigned char c) { return c < 0x21 || c > 0x7e || c == '\\'; }))
        return std::unexpected("must be printable ASCII without spaces or backslashes "
                               "(give an internationalised host as punycode)");
    if (url.find('#') != std::string::npos)
        return std::unexpected("must not contain a fragment");
    const auto sep = url.find("://");
    if (sep == std::string::npos)
        return std::unexpected("must be an absolute http or https URL");
    std::string scheme = url.substr(0, sep);
    std::ranges::transform(scheme, scheme.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (scheme != "http" && scheme != "https")
        return std::unexpected("scheme must be http or https");
    const std::string rest = url.substr(sep + 3);
    const auto end = rest.find_first_of("/?");
    const std::string authority = rest.substr(0, end);
    if (authority.empty())
        return std::unexpected("must have a host");
    if (authority.find('@') != std::string::npos)
        return std::unexpected("must not carry userinfo");
    UrlParts parts;
    std::string host;
    std::string port;
    bool has_port = false;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string::npos)
            return std::unexpected("has an unterminated IPv6 literal");
        host = authority.substr(1, close - 1);
        const std::string tail = authority.substr(close + 1);
        if (!tail.empty()) {
            if (tail.front() != ':')
                return std::unexpected("has text after the IPv6 literal");
            port = tail.substr(1);
            has_port = true;
        }
        if (host.empty() || host.find('%') != std::string::npos || !eg::parse_ipv6(host))
            return std::unexpected("has an invalid IPv6 literal");
        parts.bracketed = true;
    } else {
        const auto colon = authority.rfind(':');
        host = authority.substr(0, colon);
        if (colon != std::string::npos) {
            port = authority.substr(colon + 1);
            has_port = true;
            if (host.find(':') != std::string::npos)
                return std::unexpected("has an IPv6 literal without brackets");
        }
        if (host.empty() || host.size() > 253)
            return std::unexpected("must have a host");
        std::ranges::transform(host, host.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::size_t pos = 0;
        while (pos <= host.size()) {
            const auto dot = host.find('.', pos);
            const std::string_view label =
                std::string_view(host).substr(pos, dot == std::string::npos ? std::string::npos
                                                                            : dot - pos);
            if (!host_label_ok(label))
                return std::unexpected("has an invalid host name");
            if (dot == std::string::npos)
                break;
            pos = dot + 1;
        }
    }
    if (has_port) {
        // Digits only (no sign, no space), 1..65535.
        if (port.empty() || port.size() > 5 ||
            !std::ranges::all_of(port, [](unsigned char c) { return c >= '0' && c <= '9'; }) ||
            std::stoi(port) < 1 || std::stoi(port) > 65535)
            return std::unexpected("has an invalid port");
    }
    parts.host = std::move(host);
    return parts;
}

// ---------------------------------------------------------------------------------------------
// Addresses.

struct Addr {
    std::array<std::uint8_t, 16> b{};
    bool v4{false};
    friend auto operator<=>(const Addr& a, const Addr& c) {
        if (auto r = a.v4 <=> c.v4; r != 0)
            return r;
        return a.b <=> c.b;
    }
};

// A numeric address (the resolver's output or a literal), zone stripped. An IPv4-mapped IPv6
// address is normalised to the IPv4 address so it compares equal to a local IPv4 address.
std::optional<Addr> parse_addr(std::string s) {
    if (const auto pct = s.find('%'); pct != std::string::npos)
        s.resize(pct);
    Addr a;
    if (s.find(':') != std::string::npos) {
        const auto v6 = eg::parse_ipv6(s);
        if (!v6)
            return std::nullopt;
        const bool mapped =
            std::all_of(v6->begin(), v6->begin() + 10, [](std::uint8_t x) { return x == 0; }) &&
            (*v6)[10] == 0xff && (*v6)[11] == 0xff;
        if (mapped) {
            a.v4 = true;
            std::copy(v6->begin() + 12, v6->end(), a.b.begin());
        } else {
            std::copy(v6->begin(), v6->end(), a.b.begin());
        }
        return a;
    }
    const auto v4 = eg::parse_ipv4(s);
    if (!v4)
        return std::nullopt;
    a.v4 = true;
    std::copy(v4->begin(), v4->end(), a.b.begin());
    return a;
}

eg::AddressClass classify_addr(const Addr& a) {
    if (a.v4)
        return eg::classify_ipv4(eg::Ipv4{a.b[0], a.b[1], a.b[2], a.b[3]});
    return eg::classify_ipv6(a.b);
}

bool confirmable(std::string_view name) {
    return std::ranges::find(kConfirmableClasses, name) != std::end(kConfirmableClasses);
}

// Per-request validation context. The own-address set is computed ONCE per request (lazily, on
// first use) and the whole request shares one name-resolution budget, so a body with eight slow
// hosts cannot hold a worker for eight times the per-lookup bound.
constexpr std::chrono::milliseconds kPerLookupBudget{5000};
constexpr std::chrono::milliseconds kRequestBudget{15000};

struct Ctx {
    const EgressEnv& env;
    std::chrono::steady_clock::time_point deadline{std::chrono::steady_clock::now() + kRequestBudget};
    bool own_loaded{false};
    std::set<Addr> own;
    bool discovery_loaded{false};
    std::vector<eg::Nat64Prefix> discovered; ///< RFC 7050, shared never-shrink cache; kept apart from the declared ones
    bool classified_degraded{false};         ///< a stale (not fresh) discovery set was used: recorded in the audit row

    /// Load the RFC 7050 prefixes (once per request). The cache NEVER shrinks, so a failed refresh
    /// still yields everything ever learned. Refused (retryable 503) when the set overflowed its
    /// bound or when no lookup has EVER answered: "unknown" must not read as "no translator", or a
    /// metadata address behind an unlearned prefix would classify public.
    std::expected<void, ServiceError> load_discovery();

    void degrade(std::string_view reason) const {
        if (env.note_degrade)
            env.note_degrade(reason);
    }
};

std::unexpected<ServiceError> unavailable(std::string message) {
    return std::unexpected(ServiceError{Kind::kUnavailable, std::move(message), "", 0});
}

std::expected<void, ServiceError> Ctx::load_discovery() {
    if (discovery_loaded)
        return {};
    discovery_loaded = true;
    if (!env.discover_nat64)
        return {};
    const auto now = std::chrono::steady_clock::now();
    const auto remaining =
        now >= deadline ? std::chrono::milliseconds{0}
                        : std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    // Clamped to the request's remaining budget, so validation stays inside the documented 15 s.
    const auto d = env.discover_nat64(std::min<std::chrono::milliseconds>(kPerLookupBudget, remaining));
    if (d.overflowed) {
        degrade("nat64_discovery_overflow");
        // The overflow lasts until the set is replaced by an answer that fits or the server is
        // restarted: a long retry hint is the honest one.
        auto e = unavailable("the network advertises more NAT64 prefixes than this server tracks; "
                             "IPv6 destinations cannot be classified safely until it is restarted "
                             "or the network stops advertising them");
        e.error().retry_after_ms = 60000;
        return e;
    }
    if (!d.ever_answered) {
        degrade("nat64_discovery_unavailable");
        auto e = unavailable("the network's NAT64 prefixes (RFC 7050) could not be discovered, so an "
                             "IPv6 address cannot be classified safely; retry");
        // Matches the negative cache: the next real lookup happens when it expires.
        e.error().retry_after_ms = static_cast<std::int64_t>(d.retry_after.count());
        return e;
    }
    if (d.stale) {
        degrade("nat64_discovery_stale"); // refresh failed: classified with everything learned before
        classified_degraded = true;
    }
    discovered = d.prefixes;
    return {};
}

// IPv4 addresses an IPv6 address stands for: IPv4-mapped (::ffff:a.b.c.d), NAT64 (the well-known
// 64:ff9b::/96 and every configured prefix) and 6to4 (2002::/16, the next 32 bits). Used to compare
// a resolved address with this server's own IPv4 addresses.
std::vector<Addr> embedded_v4(const Addr& a, std::span<const eg::Nat64Prefix> prefixes) {
    std::vector<Addr> out;
    if (a.v4)
        return out;
    const auto push = [&](const eg::Ipv4& v) {
        Addr e;
        e.v4 = true;
        std::copy(v.begin(), v.end(), e.b.begin());
        out.push_back(e);
    };
    if (a.b[0] == 0x20 && a.b[1] == 0x02) // 6to4
        push(eg::Ipv4{a.b[2], a.b[3], a.b[4], a.b[5]});
    eg::Ipv6 raw{};
    std::copy(a.b.begin(), a.b.end(), raw.begin());
    const eg::Nat64Prefix wk{{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 96};
    if (const auto v = eg::embedded_ipv4(raw, wk))
        push(*v);
    for (const auto& p : prefixes)
        if (const auto v = eg::embedded_ipv4(raw, p))
            push(*v);
    return out;
}

// The server's own addresses, or a retryable refusal: a partial set would let a registration name
// the server itself, so an enumeration failure FAILS CLOSED.
std::expected<void, ServiceError> load_own(Ctx& ctx) {
    if (ctx.own_loaded)
        return {};
    std::optional<std::vector<std::string>> addrs;
    if (ctx.env.local_addresses) {
        const auto now = std::chrono::steady_clock::now();
        const auto remaining =
            now >= ctx.deadline
                ? std::chrono::milliseconds{0}
                : std::chrono::duration_cast<std::chrono::milliseconds>(ctx.deadline - now);
        addrs = ctx.env.local_addresses(remaining);
    }
    if (!addrs) {
        spdlog::error("revocation source: this server's own addresses could not be determined "
                      "(interface enumeration or a listen host failed); refusing registrations "
                      "until it can");
        ctx.degrade("own_addresses_unavailable");
        return unavailable("this server's own addresses could not be determined; retry");
    }
    for (const auto& t : *addrs)
        if (const auto a = parse_addr(t))
            ctx.own.insert(*a);
    ctx.own_loaded = true;
    return {};
}

// The classes a host's addresses fall in, or the reason it cannot be registered. Loopback, the
// always-refused tier and the server's own addresses are refused with no override.
std::expected<std::set<std::string>, ServiceError>
host_classes(const UrlParts& parts, Ctx& ctx, const std::string& param) {
    std::vector<std::string> texts;
    if (parts.bracketed || eg::classify_literal(parts.host).has_value()) {
        texts.push_back(parts.host);
    } else {
        const auto now = std::chrono::steady_clock::now();
        if (now >= ctx.deadline) {
            ctx.degrade("dns_budget_exhausted");
            return unavailable("name resolution for this request ran out of time; retry with "
                               "fewer URLs");
        }
        const auto budget = std::min<std::chrono::milliseconds>(
            kPerLookupBudget,
            std::chrono::duration_cast<std::chrono::milliseconds>(ctx.deadline - now));
        EgressEnv::Resolved r;
        if (ctx.env.resolve)
            r = ctx.env.resolve(parts.host, budget);
        if (r.status == EgressEnv::ResolveStatus::kUnavailable ||
            r.status == EgressEnv::ResolveStatus::kTimeout ||
            r.status == EgressEnv::ResolveStatus::kBusy) {
            ctx.degrade(r.status == EgressEnv::ResolveStatus::kTimeout ? "dns_timeout"
                        : r.status == EgressEnv::ResolveStatus::kBusy  ? "dns_busy"
                                                                        : "dns_unavailable");
            return unavailable("name resolution is unavailable or timed out; retry");
        }
        if (r.status != EgressEnv::ResolveStatus::kOk || r.addresses.empty())
            return invalid(param, "the host does not resolve; only a host the server can resolve "
                                  "now can be registered");
        if (r.addresses.size() > kMaxResolvedAddresses)
            return invalid(param, "the host resolves to more than " +
                                      std::to_string(kMaxResolvedAddresses) + " addresses");
        texts = std::move(r.addresses);
    }
    if (auto o = load_own(ctx); !o)
        return std::unexpected(o.error());
    std::set<std::string> classes;
    for (const auto& t : texts) {
        const auto a = parse_addr(t);
        if (!a)
            return invalid(param, "the host resolved to an address that cannot be classified");
        if (!a->v4)
            if (auto d = ctx.load_discovery(); !d)
                return std::unexpected(d.error());
        const auto& declared = ctx.env.nat64_prefixes;
        // Declared and discovered prefixes are judged SEPARATELY, never merged into one list: a
        // declared prefix is an operator assertion that may relax a class, but a prefix the
        // NETWORK advertises must not (a discovered ULA /96 would otherwise turn unique-local
        // into "public" and skip the confirmation). Embedded-IPv4 own-address checks use both.
        std::vector<eg::Nat64Prefix> both = declared;
        both.insert(both.end(), ctx.discovered.begin(), ctx.discovered.end());
        bool own = ctx.own.contains(*a);
        for (const auto& e : embedded_v4(*a, both))
            own = own || ctx.own.contains(e);
        if (own)
            return invalid(param, "the host resolves to an address this server is bound to or "
                                  "listening on; that is always refused");
        std::vector<eg::AddressClass> yielded;
        if (a->v4) {
            yielded.push_back(classify_addr(*a));
        } else {
            yielded.push_back(eg::classify_ipv6(a->b, std::span<const eg::Nat64Prefix>(declared)));
            yielded.push_back(
                eg::classify_ipv6(a->b, std::span<const eg::Nat64Prefix>(ctx.discovered)));
        }
        for (const auto c : yielded) {
            if (c == eg::AddressClass::Loopback || eg::detail::never_allowed(c))
                return invalid(param, std::string("the host resolves to a ") + eg::class_name(c) +
                                          " address; that class is always refused");
            classes.insert(eg::class_name(c)); // every class EITHER view yields must be confirmed
        }
    }
    return classes;
}

std::expected<NewRevocationSource::Url, ServiceError>
validate_url_entry(const nlohmann::json& entry, std::size_t index, Ctx& ctx) {
    const std::string at = "crl_urls[" + std::to_string(index) + "]";
    if (!entry.is_object())
        return invalid(at, "each entry must be an object {url, confirmed_address_classes?}");
    if (auto k = only_keys(entry, at, {"url", "confirmed_address_classes"}); !k)
        return std::unexpected(k.error());
    const auto uit = entry.find("url");
    if (uit == entry.end() || !uit->is_string())
        return invalid(at + ".url", "url must be a string");
    const std::string url = uit->get<std::string>();
    const auto parts = parse_url_syntax(url);
    if (!parts)
        return invalid(at + ".url", "url " + parts.error());

    std::set<std::string> confirmed;
    if (const auto cit = entry.find("confirmed_address_classes"); cit != entry.end()) {
        if (!cit->is_array() || cit->size() > std::size(kConfirmableClasses))
            return invalid(at + ".confirmed_address_classes",
                           "must be an array of address-class names");
        for (const auto& c : *cit) {
            if (!c.is_string() || !confirmable(c.get<std::string>()))
                return invalid(at + ".confirmed_address_classes",
                               "each class must be one of: public, private, carrier-grade-nat, "
                               "unique-local, non-global");
            confirmed.insert(c.get<std::string>());
        }
    }

    const auto classes = host_classes(*parts, ctx, at + ".url");
    if (!classes)
        return std::unexpected(classes.error());
    // EVERY class the host resolved to must be confirmed (a round-robin answer that mixes classes
    // needs all of them), and the classes STORED are the ones observed, so the fetcher's rule
    // "an address outside the stored classes is refused" is exactly what was shown.
    std::string missing;
    for (const auto& c : *classes)
        if (!confirmed.contains(c))
            missing += (missing.empty() ? "" : ", ") + c;
    if (!missing.empty()) {
        std::string all;
        for (const auto& c : *classes)
            all += (all.empty() ? "\"" : ", \"") + c + "\"";
        return invalid(at + ".confirmed_address_classes",
                       "the host resolves to address class(es) [" + missing +
                           "]; to confirm that this server may fetch from there, resend with "
                           "confirmed_address_classes: [" +
                           all + "]");
    }
    NewRevocationSource::Url out;
    out.url = url;
    out.host = parts->host;
    out.confirmed_address_classes.assign(classes->begin(), classes->end());
    return out;
}

// ---------------------------------------------------------------------------------------------
// The system resolver and interface enumeration.

EgressEnv::Resolved system_resolve(const std::string& host, std::chrono::milliseconds budget) {
    auto r = net::bounded_resolve(host, budget);
    EgressEnv::Resolved out;
    switch (r.status) {
    case net::ResolveStatus::kOk:
        out.status = EgressEnv::ResolveStatus::kOk;
        out.addresses = std::move(r.addresses);
        break;
    case net::ResolveStatus::kNotFound:
        out.status = EgressEnv::ResolveStatus::kNotFound;
        break;
    case net::ResolveStatus::kTemporary:
        out.status = EgressEnv::ResolveStatus::kUnavailable;
        break;
    case net::ResolveStatus::kTimeout:
        out.status = EgressEnv::ResolveStatus::kTimeout;
        break;
    case net::ResolveStatus::kBusy:
        out.status = EgressEnv::ResolveStatus::kBusy;
        break;
    }
    return out;
}

// Every unicast address on every local interface, or nullopt when the OS could not say.
std::optional<std::vector<std::string>> interface_addresses() {
    std::vector<std::string> out;
    char buf[INET6_ADDRSTRLEN];
    const auto add = [&](const sockaddr* sa, std::size_t len) {
        // Copy into a local of the right type (length-checked): the OS buffer's alignment is its
        // own business, so no pointer is cast to sockaddr_in / sockaddr_in6.
        if (sa == nullptr)
            return;
        if (sa->sa_family == AF_INET && len >= sizeof(sockaddr_in)) {
            sockaddr_in v{};
            std::memcpy(&v, sa, sizeof(v));
            if (::inet_ntop(AF_INET, &v.sin_addr, buf, sizeof(buf)) != nullptr)
                out.emplace_back(buf);
        } else if (sa->sa_family == AF_INET6 && len >= sizeof(sockaddr_in6)) {
            sockaddr_in6 v{};
            std::memcpy(&v, sa, sizeof(v));
            if (::inet_ntop(AF_INET6, &v.sin6_addr, buf, sizeof(buf)) != nullptr)
                out.emplace_back(buf);
        }
    };
#ifdef _WIN32
    // Start at 16 KiB and retry on a size race (the adapter list can grow between the sizing call
    // and the fill), as agents/core/src/network_interfaces.cpp does.
    // The buffer is a vector of the OS struct itself, so the cast the API requires has a stated
    // alignment basis (operator new storage for IP_ADAPTER_ADDRESSES), not a byte array's.
    ULONG size = 16 * 1024;
    std::vector<IP_ADAPTER_ADDRESSES> mem;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        mem.assign((size + sizeof(IP_ADAPTER_ADDRESSES) - 1) / sizeof(IP_ADAPTER_ADDRESSES),
                   IP_ADAPTER_ADDRESSES{});
        size = static_cast<ULONG>(mem.size() * sizeof(IP_ADAPTER_ADDRESSES));
        rc = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, mem.data(), &size);
    }
    if (rc != NO_ERROR)
        return std::nullopt;
    for (auto* a = mem.data(); a != nullptr; a = a->Next)
        for (auto* u = a->FirstUnicastAddress; u != nullptr; u = u->Next)
            add(u->Address.lpSockaddr, u->Address.iSockaddrLength > 0
                                           ? static_cast<std::size_t>(u->Address.iSockaddrLength)
                                           : 0U);
#else
    struct ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0)
        return std::nullopt;
    std::unique_ptr<struct ifaddrs, decltype(&::freeifaddrs)> guard(list, ::freeifaddrs);
    // ifa_addr points at a sockaddr_in / sockaddr_in6 / sockaddr_dl chosen by sa_family; its
    // length is sa_len on the BSDs and implied by the family on Linux, so `add` is handed the
    // minimum the family requires after reading sa_family from the base type.
    for (const struct ifaddrs* i = list; i != nullptr; i = i->ifa_next) {
        if (i->ifa_addr == nullptr)
            continue;
        const std::size_t len = i->ifa_addr->sa_family == AF_INET    ? sizeof(sockaddr_in)
                                : i->ifa_addr->sa_family == AF_INET6 ? sizeof(sockaddr_in6)
                                                                     : 0U;
        add(i->ifa_addr, len);
    }
#endif
    return out;
}

// "host", "host:port", "[v6]:port" or a bare IPv6 literal -> the host part.
std::string spec_host(std::string spec) {
    if (!spec.empty() && spec.front() == '[') {
        const auto close = spec.find(']');
        return close == std::string::npos ? spec.substr(1) : spec.substr(1, close - 1);
    }
    const auto first = spec.find(':');
    if (first == std::string::npos)
        return spec;
    if (spec.find(':', first + 1) != std::string::npos)
        return spec; // a bare IPv6 literal
    return spec.substr(0, first);
}

bool is_wildcard(const std::string& host) { return host.empty() || host == "0.0.0.0" || host == "::"; }


} // namespace

net::Nat64Discovery discover_nat64(std::chrono::milliseconds budget, net::LookupFn lookup,
                                   net::Nat64DiscoveryCache& cache,
                                   std::shared_ptr<net::ResolverPool> pool) {
    if (!pool)
        pool = net::nat64_probe_pool(); // the cap-1 discovery pool, shared with the OIDC probe
    // RFC 7050 through the ONE shared cache (nat64_discovery.hpp), which the OIDC client also
    // fills and reads. This function only supplies the lookup (ipv4only.arpa through the bounded
    // resolver) and maps its result to the shared four-state outcome. A resolver "not found" is an
    // ANSWER (no DNS64 here, a normal network), exactly as the OIDC client now treats NXDOMAIN.
    // A busy pool, or a timeout under a budget CLAMPED below a full lookup, is inconclusive: this
    // call fails, but nothing is written to the cache another consumer reads.
    const bool clamped = budget < kPerLookupBudget;
    return net::discover_nat64_prefixes_cached(
        [&](std::vector<eg::Ipv6>& out) {
            const auto r = net::bounded_resolve(net::kNat64ProbeName, budget, lookup, pool);
            return net::nat64_outcome_from_resolve(r, clamped, out); // the ONE mapping, shared with OIDC
        },
        cache, budget);
}

EgressEnv make_system_egress_env(std::vector<std::string> listen_specs,
                                 std::vector<eg::Nat64Prefix> nat64_prefixes) {
    EgressEnv env;
    env.resolve = [](const std::string& host, std::chrono::milliseconds budget) {
        return system_resolve(host, budget);
    };
    env.nat64_prefixes = std::move(nat64_prefixes);
    env.discover_nat64 = [](std::chrono::milliseconds budget) {
        return discover_nat64(budget, {}, net::process_nat64_cache());
    };
    env.local_addresses = [specs = std::move(listen_specs)](std::chrono::milliseconds budget)
        -> std::optional<std::vector<std::string>> {
        const auto until = std::chrono::steady_clock::now() + budget;
        std::vector<std::string> out;
        std::optional<std::vector<std::string>> ifaces; // read once, only if a wildcard needs it
        for (const auto& spec : specs) {
            if (spec.empty())
                continue; // a disabled listener (for example no gateway upstream address)
            const std::string host = spec_host(spec);
            if (is_wildcard(host)) {
                // A wildcard bind is every address on every local interface.
                if (!ifaces)
                    ifaces = interface_addresses();
                if (!ifaces)
                    return std::nullopt;
                out.insert(out.end(), ifaces->begin(), ifaces->end());
            } else if (eg::classify_literal(host).has_value()) {
                out.push_back(host);
            } else {
                // A listen host that is a name: its addresses are the server's own. If it cannot be
                // resolved the set is incomplete, so the answer is "unknown", never "fewer".
                // Inside the request's budget: a slow listen-host lookup cannot stretch validation.
                const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    until - std::chrono::steady_clock::now());
                if (left <= std::chrono::milliseconds{0})
                    return std::nullopt;
                const auto r = net::bounded_resolve(host, std::min(kPerLookupBudget, left));
                if (r.status != net::ResolveStatus::kOk)
                    return std::nullopt;
                out.insert(out.end(), r.addresses.begin(), r.addresses.end());
            }
        }
        return out;
    };
    return env;
}

std::optional<std::int64_t> parse_source_id(std::string_view s) {
    if (s.empty() || s.size() > 18 || s.front() == '0')
        return std::nullopt;
    std::int64_t v = 0;
    for (const unsigned char c : s) {
        if (c < '0' || c > '9')
            return std::nullopt;
        v = v * 10 + (c - '0');
    }
    return v;
}

std::string rfc3339_utc(std::int64_t epoch_seconds) {
    const std::time_t t = static_cast<std::time_t>(epoch_seconds);
    std::tm tm{};
#ifdef _WIN32
    const bool ok = static_cast<std::int64_t>(t) == epoch_seconds && gmtime_s(&tm, &t) == 0;
#else
    const bool ok = static_cast<std::int64_t>(t) == epoch_seconds && gmtime_r(&t, &tm) != nullptr;
#endif
    char buf[32];
    if (!ok || std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
        return "1970-01-01T00:00:00Z";
    return buf;
}

// ---------------------------------------------------------------------------------------------
// Validation and the operations.

namespace {
// At most this many registrations resolve names at once: DNS runs on the request thread of the
// shared HTTP pool, and a slow resolver must not starve /livez and /readyz.
constexpr int kMaxConcurrentValidations = 4;
std::atomic<int>& validations_in_flight() {
    static std::atomic<int>& n = *new std::atomic<int>(0);
    return n;
}
struct ValidationSlot {
    bool held{false};
    ValidationSlot() {
        auto& n = validations_in_flight();
        if (n.fetch_add(1) < kMaxConcurrentValidations)
            held = true;
        else
            n.fetch_sub(1);
    }
    ~ValidationSlot() {
        if (held)
            validations_in_flight().fetch_sub(1);
    }
    ValidationSlot(const ValidationSlot&) = delete;
    ValidationSlot& operator=(const ValidationSlot&) = delete;
};
} // namespace

std::expected<NewRevocationSource, ServiceError>
RevocationSourceService::validate_registration(const nlohmann::json& body, BodyMode mode) const {
    if (!body.is_object())
        return invalid("", "the body must be a JSON object");
    const bool update = mode == BodyMode::kUpdate;
    if (update) {
        if (auto k = only_keys(body, "the body",
                               {"name", "ca_certificates", "crl_urls", "expected_config_version"});
            !k)
            return std::unexpected(k.error());
    } else if (auto k = only_keys(body, "the body", {"name", "ca_certificates", "crl_urls"}); !k) {
        return std::unexpected(k.error());
    }

    NewRevocationSource out;
    if (const auto vit = body.find("expected_config_version"); vit != body.end()) {
        if (!vit->is_number_integer() || vit->get<std::int64_t>() < 1)
            return invalid("expected_config_version",
                           "expected_config_version must be an integer >= 1 (the source's "
                           "config_version as you last read it)");
        out.expected_config_version = vit->get<std::int64_t>();
    } else if (update) {
        return invalid("expected_config_version",
                       "expected_config_version is required: read the source and pass its "
                       "config_version, so an approved call cannot silently revert a newer "
                       "configuration");
    }
    const auto nit = body.find("name");
    if (nit == body.end() || !nit->is_string())
        return invalid("name", "name is required and must be a string");
    out.name = nit->get<std::string>();
    if (out.name.empty() || out.name.size() > RevocationSourceStore::kMaxNameBytes)
        return invalid("name", "name must be 1.." + std::to_string(RevocationSourceStore::kMaxNameBytes) +
                                   " bytes");
    if (sanitize_utf8_strict(out.name) != out.name || has_control(out.name))
        return invalid("name", "name must be valid UTF-8 with at least one visible character and no control, bidi or zero-width characters");

    const auto cit = body.find("ca_certificates");
    if (cit == body.end() || !cit->is_array() || cit->empty() ||
        cit->size() > RevocationSourceStore::kMaxCaKeys)
        return invalid("ca_certificates",
                       "ca_certificates must be an array of 1.." +
                           std::to_string(RevocationSourceStore::kMaxCaKeys) + " PEM certificates");
    std::set<std::string> seen_certs;
    for (std::size_t i = 0; i < cit->size(); ++i) {
        const auto& e = (*cit)[i];
        if (!e.is_string())
            return invalid("ca_certificates[" + std::to_string(i) + "]",
                           "each entry must be a PEM string");
        auto ca = parse_ca_pem(e.get<std::string>(), i);
        if (!ca)
            return std::unexpected(ca.error());
        if (out.ca_subject_name_sha256.empty())
            out.ca_subject_name_sha256 = ca->subject_sha256;
        else if (out.ca_subject_name_sha256 != ca->subject_sha256)
            return invalid("ca_certificates[" + std::to_string(i) + "]",
                           "every certificate must share one subject Name: a source is one CA "
                           "(register another CA as its own source)");
        if (!seen_certs.insert(ca->key.cert_sha256).second)
            return invalid("ca_certificates[" + std::to_string(i) + "]",
                           "duplicate certificate");
        out.keys.push_back(std::move(ca->key));
    }

    const auto uit = body.find("crl_urls");
    if (uit == body.end() || !uit->is_array() || uit->empty() ||
        uit->size() > RevocationSourceStore::kMaxUrls)
        return invalid("crl_urls", "crl_urls must be an array of 1.." +
                                       std::to_string(RevocationSourceStore::kMaxUrls) +
                                       " objects {url, confirmed_address_classes?}");
    std::set<std::string> seen_urls;
    ValidationSlot slot;
    if (!slot.held) {
        if (env_.note_degrade)
            env_.note_degrade("validation_busy");
        return unavailable("other registrations are resolving names right now; retry shortly");
    }
    Ctx ctx{env_};
    for (std::size_t i = 0; i < uit->size(); ++i) {
        auto u = validate_url_entry((*uit)[i], i, ctx);
        if (!u)
            return std::unexpected(u.error());
        if (!seen_urls.insert(u->url).second)
            return invalid("crl_urls[" + std::to_string(i) + "].url", "duplicate url");
        out.urls.push_back(std::move(*u));
    }
    out.classified_degraded = ctx.classified_degraded;
    return out;
}

std::expected<ListResult, ServiceError> RevocationSourceService::list() {
    auto rows = store_.list();
    if (!rows)
        return map_store_error(rows.error());
    auto past = store_.crl_past_next_update_count();
    if (!past)
        return map_store_error(past.error());
    return ListResult{std::move(*rows), *past};
}

std::expected<RevocationSourceRecord, ServiceError> RevocationSourceService::get(std::int64_t id) {
    auto r = store_.get(id);
    if (!r)
        return map_store_error(r.error());
    return std::move(*r);
}

std::expected<RevocationSourceRecord, ServiceError>
RevocationSourceService::register_source(const nlohmann::json& body, const std::string& created_by) {
    auto v = validate_registration(body, BodyMode::kRegister);
    if (!v)
        return std::unexpected(v.error());
    return register_validated(*v, created_by);
}

std::expected<RevocationSourceRecord, ServiceError>
RevocationSourceService::register_validated(const NewRevocationSource& v,
                                            const std::string& created_by) {
    auto id = store_.create(v, created_by);
    if (!id)
        return map_store_error(id.error());
    auto r = store_.get(*id);
    if (!r)
        return map_store_error(r.error());
    return std::move(*r);
}

std::expected<RevocationSourceUpdate, ServiceError>
RevocationSourceService::update_source(std::int64_t id, const nlohmann::json& body) {
    auto v = validate_registration(body, BodyMode::kUpdate);
    if (!v)
        return std::unexpected(v.error());
    return update_validated(id, *v);
}

std::expected<RevocationSourceUpdate, ServiceError>
RevocationSourceService::update_validated(std::int64_t id, const NewRevocationSource& v) {
    auto r = store_.replace(id, v);
    if (!r)
        return map_store_error(r.error());
    return std::move(*r);
}

std::expected<void, ServiceError> RevocationSourceService::remove(std::int64_t id) {
    auto r = store_.remove(id);
    if (!r)
        return map_store_error(r.error());
    return {};
}

namespace {

// YYYY-MM-DDTHH:MM:SS[.f{1,9}]Z, a REAL calendar time (no February 31st, leap years honoured)
// from 1970-01-01 on. UTC only: a numeric offset is refused so the floor is unambiguous.
bool valid_rfc3339_utc(const std::string& s) {
    const auto digits = [&](std::size_t from, std::size_t n) {
        if (from + n > s.size())
            return false;
        for (std::size_t i = from; i < from + n; ++i)
            if (s[i] < '0' || s[i] > '9')
                return false;
        return true;
    };
    if (s.size() < 20 || !digits(0, 4) || s[4] != '-' || !digits(5, 2) || s[7] != '-' ||
        !digits(8, 2) || s[10] != 'T' || !digits(11, 2) || s[13] != ':' || !digits(14, 2) ||
        s[16] != ':' || !digits(17, 2))
        return false;
    std::size_t p = 19;
    if (s[p] == '.') {
        std::size_t q = p + 1;
        while (q < s.size() && s[q] >= '0' && s[q] <= '9')
            ++q;
        if (q == p + 1 || q - p - 1 > 9)
            return false;
        p = q;
    }
    if (p + 1 != s.size() || s[p] != 'Z')
        return false;
    const int year = std::stoi(s.substr(0, 4)), mon = std::stoi(s.substr(5, 2)),
              day = std::stoi(s.substr(8, 2)), hour = std::stoi(s.substr(11, 2)),
              min = std::stoi(s.substr(14, 2)), sec = std::stoi(s.substr(17, 2));
    if (year < 1970 || mon < 1 || mon > 12 || hour > 23 || min > 59 || sec > 59)
        return false;
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    static constexpr int kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const int dim = (mon == 2 && leap) ? 29 : kDays[mon - 1];
    return day >= 1 && day <= dim;
}

} // namespace

namespace {
struct ResetArgs {
    std::string reset_at;
    std::string pin;
};
std::expected<ResetArgs, ServiceError> parse_reset(const nlohmann::json& body) {
    if (!body.is_object())
        return invalid("", "the body must be a JSON object");
    if (auto k = only_keys(body, "the body", {"reset_at", "pin_crl_sha256"}); !k)
        return std::unexpected(k.error());
    ResetArgs out;
    if (const auto it = body.find("reset_at"); it != body.end()) {
        if (!it->is_string() || !valid_rfc3339_utc(it->get<std::string>()))
            return invalid("reset_at", "reset_at must be a real RFC 3339 UTC time from 1970 on, "
                                       "such as 2026-10-23T09:00:00Z");
        out.reset_at = it->get<std::string>();
    }
    if (const auto it = body.find("pin_crl_sha256"); it != body.end()) {
        const auto ok = it->is_string() && it->get<std::string>().size() == 64 &&
                        std::ranges::all_of(it->get<std::string>(), [](char c) {
                            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                        });
        if (!ok)
            return invalid("pin_crl_sha256", "pin_crl_sha256 must be 64 lowercase hex characters "
                                             "(the SHA-256 of the first CRL to accept)");
        out.pin = it->get<std::string>();
    }
    return out;
}
} // namespace

std::expected<void, ServiceError>
RevocationSourceService::validate_reset(const nlohmann::json& body) const {
    auto r = parse_reset(body);
    if (!r)
        return std::unexpected(r.error());
    return {};
}

std::expected<HighWaterReset, ServiceError>
RevocationSourceService::reset_high_water(std::int64_t id, const nlohmann::json& body) {
    auto args = parse_reset(body);
    if (!args)
        return std::unexpected(args.error());
    auto r = store_.reset_high_water(id, args->reset_at, args->pin);
    if (!r)
        return map_store_error(r.error());
    return *r;
}

// ---------------------------------------------------------------------------------------------
// Views.

namespace {

nlohmann::json opt_time(const std::optional<std::int64_t>& t) {
    return t ? nlohmann::json(rfc3339_utc(*t)) : nlohmann::json(nullptr);
}

nlohmann::json fetch_status_json(const RevocationFetchStatus& f) {
    // "never fetched" until the fetcher (2b-1b) has made an attempt.
    std::string state = "never_fetched";
    if (f.present && f.last_attempt_at)
        state = f.last_failure_cause ? "failing" : "ok";
    nlohmann::json j;
    j["state"] = state;
    j["last_attempt_at"] = opt_time(f.last_attempt_at);
    j["last_success_at"] = opt_time(f.last_success_at);
    j["last_failure_cause"] = f.last_failure_cause ? nlohmann::json(*f.last_failure_cause)
                                                    : nlohmann::json(nullptr);
    j["consecutive_failures"] = f.consecutive_failures;
    j["next_attempt_at"] = opt_time(f.next_attempt_at);
    return j;
}

} // namespace

nlohmann::json source_json(const RevocationSourceRecord& r) {
    nlohmann::json j;
    j["id"] = r.id;
    j["name"] = r.name;
    j["ca_subject_name_sha256"] = r.ca_subject_name_sha256;
    j["config_version"] = r.config_version;
    j["created_by"] = r.created_by;
    j["created_at"] = rfc3339_utc(r.created_at);
    j["updated_at"] = rfc3339_utc(r.updated_at);
    j["held_crl_count"] = r.held_crl_count;
    j["crl_status"] = r.held_crl_count == 0 ? "no_crl_fetched" : "crl_held";
    // The CA's anti-rollback state, so a reset whose outcome was unknown can be checked by reading
    // the source: reset_at is null until the first reset and is never cleared.
    j["high_water"] = {{"reset_at", opt_time(r.reset_at)},
                       {"pinned_crl_sha256", r.pinned_crl_sha256 ? nlohmann::json(*r.pinned_crl_sha256)
                                                                  : nlohmann::json(nullptr)}};
    j["ca_certificates"] = nlohmann::json::array();
    for (const auto& k : r.keys) {
        nlohmann::json kj;
        kj["cert_sha256"] = k.cert_sha256;
        kj["ski"] = k.ski ? nlohmann::json(*k.ski) : nlohmann::json(nullptr);
        kj["spki_sha256"] = k.spki_sha256;
        j["ca_certificates"].push_back(std::move(kj));
    }
    j["crl_urls"] = nlohmann::json::array();
    for (const auto& u : r.urls) {
        nlohmann::json uj;
        uj["id"] = u.id;
        uj["url"] = u.url;
        uj["host"] = u.host;
        uj["confirmed_address_classes"] = u.confirmed_address_classes;
        uj["fetch_status"] = fetch_status_json(u.fetch);
        j["crl_urls"].push_back(std::move(uj));
    }
    return j;
}

nlohmann::json list_json(const ListResult& l) {
    nlohmann::json j;
    j["sources"] = nlohmann::json::array();
    for (const auto& s : l.sources)
        j["sources"].push_back(source_json(s));
    j["total"] = l.sources.size();
    j["max_sources"] = RevocationSourceStore::kMaxSources;
    j["crl_past_next_update"] = l.crl_past_next_update;
    return j;
}

nlohmann::json update_json(const RevocationSourceUpdate& u) {
    nlohmann::json j = source_json(u.source);
    j["changed"] = u.changed;
    j["dropped_urls"] = u.dropped_urls;
    j["dropped_ca_certificates"] = u.dropped_keys;
    j["crls_deleted"] = u.crls_deleted;
    return j;
}

nlohmann::json reset_json(const HighWaterReset& r) {
    nlohmann::json j;
    j["reset_at"] = rfc3339_utc(r.reset_at);
    j["crls_deleted"] = r.crls_deleted;
    // The window the reset opened: a CRL that verifies and is dated at or after this time is
    // accepted again, whatever its number.
    j["replay_window_opens_at"] = rfc3339_utc(r.reset_at);
    j["pinned"] = r.pinned;
    return j;
}

// ---------------------------------------------------------------------------------------------
// Audit text.

namespace {
// MCP has no per-call correlation id to stamp here (its error envelope mints its own), so an
// empty id reads "cid=none" rather than a dangling "cid=".
std::string cid_part(std::string_view cid) {
    return "cid=" + (cid.empty() ? std::string("none") : ::yuzu::log_token(cid));
}
} // namespace

std::string audit_detail_list(std::string_view cid, std::size_t count) {
    return cid_part(cid) + " count=" + std::to_string(count);
}

std::string audit_detail_view(std::string_view cid) { return cid_part(cid); }

std::string audit_detail_config(std::string_view cid, const NewRevocationSource& n) {
    std::string out = cid_part(cid) + " name=" + ::yuzu::log_token(n.name) +
                      " ca_certificates=" + std::to_string(n.keys.size()) +
                      " crl_urls=" + std::to_string(n.urls.size()) + " urls=";
    for (std::size_t i = 0; i < n.urls.size(); ++i) {
        if (i)
            out += '|';
        out += ::yuzu::log_token(n.urls[i].url);
        // The classes the administrator confirmed (and the server stored) are what authorises the
        // fetch, so they belong in the evidence next to the URL.
        out += "[classes=";
        for (std::size_t c = 0; c < n.urls[i].confirmed_address_classes.size(); ++c)
            out += (c ? "+" : "") + ::yuzu::log_token(n.urls[i].confirmed_address_classes[c]);
        out += ']';
    }
    if (n.classified_degraded)
        out += " nat64=stale"; // classification used the last learned prefixes: the refresh failed
    if (n.expected_config_version)
        out += " expected_config_version=" + std::to_string(*n.expected_config_version);
    return out;
}

std::string audit_detail_source(std::string_view cid, const RevocationSourceRecord& r) {
    return cid_part(cid) + " source_id=" + std::to_string(r.id) +
           " config_version=" + std::to_string(r.config_version) +
           " name=" + ::yuzu::log_token(r.name);
}

std::string audit_detail_update(std::string_view cid, const RevocationSourceUpdate& u) {
    return audit_detail_source(cid, u.source) + " changed=" + (u.changed ? "true" : "false") +
           " dropped_urls=" + std::to_string(u.dropped_urls) +
           " dropped_ca_certificates=" + std::to_string(u.dropped_keys) +
           " crls_deleted=" + std::to_string(u.crls_deleted);
}

std::string audit_detail_reset(std::string_view cid, const nlohmann::json& body) {
    std::string out = cid_part(cid);
    if (body.is_object())
        if (const auto it = body.find("reset_at"); it != body.end() && it->is_string())
            out += " reset_at=" + ::yuzu::log_token(it->get<std::string>());
    if (body.is_object())
        if (const auto it = body.find("pin_crl_sha256"); it != body.end() && it->is_string())
            out += " pin_crl_sha256=" + ::yuzu::log_token(it->get<std::string>());
    return out;
}

std::string audit_detail_reset_result(std::string_view cid, const HighWaterReset& r) {
    return cid_part(cid) + " reset_at=" + rfc3339_utc(r.reset_at) +
           " crls_deleted=" + std::to_string(r.crls_deleted);
}

std::string audit_detail_error(std::string_view cid, const ServiceError& e) {
    std::string out = cid_part(cid);
    if (!e.param.empty())
        out += " param=" + ::yuzu::log_token(e.param);
    out += " reason=" + ::yuzu::log_token(e.message);
    return out;
}

} // namespace yuzu::server::revocation_source
