#pragma once

/// @file healthcheck_rules.hpp
/// Pure decisions behind `yuzu-server --healthcheck` (#5906): which listener to
/// probe, which trust anchor to verify it against, what counts as healthy, and
/// the one diagnostic line printed on failure. Header-only and httplib-free so
/// the unit suite exercises every branch with no socket, file or process; the
/// transport lives in healthcheck_probe.cpp.
///
/// TARGET RULES (mirror the server's own listener choice, never read
/// yuzu-server.cfg):
///   - HTTPS on (the default) -> https://<host>:<https_port>, verified against
///     ONLY a trust anchor: `<ca_dir|default_cert_dir>/default-ca.pem` in
///     default-certs mode (server.cpp's `https_needs` branch), or the
///     first certificate in the `--https-cert` file (the server certificate
///     itself), as a partial-chain anchor, in operator mode. Never the system
///     trust store; hostname is not checked (for a wildcard bind the probe dials
///     loopback, an address the operator certificate was never issued for).
///   - `--no-https` -> http://<host>:<web_port>, no anchor.
///   - A build without CPPHTTPLIB_OPENSSL_SUPPORT serves plain HTTP on web_port
///     even when https_enabled (server.cpp, start_web_server), so the probe does
///     the same (`tls_supported` input).
///
/// Exit verdict: 0 only for HTTP 200. A redirect, 503, transport failure or TLS
/// verification failure is 1.

#include <yuzu/log_token.hpp>
#include <yuzu/server/server.hpp>

#include <filesystem>
#include <string>
#include <string_view>

namespace yuzu::server::healthcheck {

struct HealthcheckTarget {
    bool tls{false};
    std::string host;
    int port{0};
    std::string path;
    std::filesystem::path trust_anchor; // empty for a plain-HTTP target
    bool partial_chain{false};          // operator mode: the leaf itself is the anchor
};

struct HealthcheckOutcome {
    int status{0};     // 0 = no HTTP response was received
    std::string error; // transport / TLS reason when status == 0
};

/// A wildcard bind is probed over loopback; anything else is dialled as given.
[[nodiscard]] inline std::string probe_host_for(std::string_view bind_address) {
    if (bind_address.empty() || bind_address == "0.0.0.0")
        return "127.0.0.1";
    if (bind_address == "::")
        return "::1";
    return std::string{bind_address};
}

/// The first `BEGIN CERTIFICATE`..`END CERTIFICATE` block of a PEM bundle, markers and a
/// closing newline included; empty when there is none (or the block is unterminated), when
/// a certificate block under another label (`X509 CERTIFICATE`, `TRUSTED CERTIFICATE`) comes
/// ahead of it, or when the text between the markers holds another `BEGIN`: skipping an alias
/// block would anchor the probe on a LATER certificate, the issuing CA behind the leaf, and
/// marker text in a comment ahead of one would return the leaf AND that CA together. Operator
/// mode anchors the probe on this block only (#5906): a full-chain `--https-cert` file also
/// carries the issuing intermediate, and trusting that would let any sibling leaf under it pass,
/// with hostname checking off.
///
/// Matches OpenSSL's reader, which the server's own chain loader uses on the same file:
/// OpenSSL accepts a BEGIN line only at the start of a line (after an optional UTF-8 BOM on the
/// first), so a marker in mid-line text is not the first certificate and returns empty; and a
/// block carrying a PEM header (`Proc-Type`, `DEK-Info`) is refused, because OpenSSL would
/// prompt for a pass phrase. OpenSSL also reads in 254-byte line chunks, and its file reader
/// (`fgets` + `strlen`, what the server's chain loader uses) cuts a chunk at a NUL while the
/// memory reader httplib uses counts bytes, so a block holding a NUL is refused: the two
/// readers would decode different text from it. The BOM this block drops moves where a
/// 251-254 byte first line is chunked, so the readers can still disagree on whether such a
/// block loads, never on which certificate. It may return empty where OpenSSL would
/// load a certificate, never a different certificate than the one the server presents.
[[nodiscard]] inline std::string first_pem_certificate(std::string_view pem) {
    constexpr std::string_view kBegin = "-----BEGIN CERTIFICATE-----";
    constexpr std::string_view kEnd = "-----END CERTIFICATE-----";
    const auto b = pem.find(kBegin);
    if (b == std::string_view::npos)
        return {};
    if (b != 0 && pem[b - 1] != '\n' && !(b == 3 && pem.starts_with("\xEF\xBB\xBF")))
        return {};
    if (pem.substr(0, b).find("CERTIFICATE-----") != std::string_view::npos)
        return {};
    const auto e = pem.find(kEnd, b + kBegin.size());
    if (e == std::string_view::npos)
        return {};
    const auto block = pem.substr(b, e + kEnd.size() - b);
    // One block only: httplib loads every certificate in the text it is handed (stepping over a
    // TRUSTED one), so marker text in a comment or PEM header must not widen what is returned.
    if (block.find("-----BEGIN ", kBegin.size()) != std::string_view::npos)
        return {};
    // A base64 body holds neither ':' (a PEM header does: `Proc-Type: 4,ENCRYPTED`) nor a NUL.
    // OpenSSL's file reader (fgets + strlen, what the server's chain loader uses) cuts a line at
    // a NUL while the memory reader httplib uses counts bytes, so the two would decode different
    // text from the same block. `block` is a counted view: the NUL reaches this test intact.
    if (block.find_first_of(std::string_view{":\0", 2}) != std::string_view::npos)
        return {};
    return std::string{block} + '\n';
}

/// `default_cert_dir` and `tls_supported` are injected so a test never touches
/// auth::default_cert_dir() or the build's OpenSSL state.
[[nodiscard]] inline HealthcheckTarget
resolve_healthcheck_target(const Config& cfg, std::string_view path,
                           const std::filesystem::path& default_cert_dir, bool tls_supported) {
    HealthcheckTarget t;
    t.tls = cfg.https_enabled && tls_supported;
    t.host = probe_host_for(cfg.web_address);
    t.port = t.tls ? cfg.https_port : cfg.web_port;
    t.path = std::string{path};
    if (!t.tls)
        return t;
    if (!cfg.https_cert_path.empty()) {
        t.trust_anchor = cfg.https_cert_path;
        t.partial_chain = true;
    } else {
        t.trust_anchor = (cfg.ca_dir.empty() ? default_cert_dir : cfg.ca_dir) / "default-ca.pem";
    }
    return t;
}

[[nodiscard]] inline std::string healthcheck_url(const HealthcheckTarget& t) {
    const bool v6 = t.host.find(':') != std::string::npos;
    return std::string{t.tls ? "https://" : "http://"} + (v6 ? "[" + t.host + "]" : t.host) +
           ":" + std::to_string(t.port) + t.path;
}

[[nodiscard]] inline int healthcheck_exit_code(const HealthcheckOutcome& o) {
    return o.status == 200 ? 0 : 1;
}

/// Empty on success, otherwise ONE line. Names the target, the status or the
/// transport/TLS reason, and the trust anchor; never the private-key path and
/// never any response body.
[[nodiscard]] inline std::string healthcheck_diagnostic(const HealthcheckTarget& t,
                                                        const HealthcheckOutcome& o) {
    if (healthcheck_exit_code(o) == 0)
        return {};
    // Each operator- or peer-influenced field goes through log_key_token (control bytes ->
    // '_'), so none can split the line; the scaffolding around them stays literal.
    return "healthcheck: GET " + ::yuzu::log_key_token(healthcheck_url(t)) + " -> " +
           ::yuzu::log_key_token(o.status != 0
                                     ? std::to_string(o.status)
                                     : (o.error.empty() ? std::string{"no response"} : o.error)) +
           " (trust anchor: " +
           ::yuzu::log_key_token(t.trust_anchor.empty() ? std::string{"none"}
                                                        : t.trust_anchor.string()) +
           ")";
}

} // namespace yuzu::server::healthcheck
