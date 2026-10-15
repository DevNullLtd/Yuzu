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
///     `--https-cert` file itself, as a partial-chain anchor, in operator mode.
///     Never the system trust store; hostname is not checked (the probe dials a
///     loopback address the operator certificate was never issued for).
///   - `--no-https` -> http://<host>:<web_port>, no anchor.
///   - A build without CPPHTTPLIB_OPENSSL_SUPPORT serves plain HTTP on web_port
///     even when https_enabled (server.cpp, start_web_server), so the probe does
///     the same (`tls_supported` input).
///
/// Exit verdict: 0 only for HTTP 200. A redirect, 503, transport failure or TLS
/// verification failure is 1.

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
    return "healthcheck: GET " + healthcheck_url(t) + " -> " +
           (o.status != 0 ? std::to_string(o.status)
                          : (o.error.empty() ? std::string{"no response"} : o.error)) +
           " (trust anchor: " +
           (t.trust_anchor.empty() ? std::string{"none"} : t.trust_anchor.string()) + ")";
}

} // namespace yuzu::server::healthcheck
