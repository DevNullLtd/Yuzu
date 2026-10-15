#pragma once

/// @file healthcheck_probe.hpp
/// The httplib transport behind `yuzu-server --healthcheck` (#5906). All
/// decisions (target, verdict, diagnostic) are pure and live in
/// healthcheck_rules.hpp; this shell runs ONE GET and reports what came back.

#include "healthcheck_rules.hpp"

#include <httplib.h>

#include <iosfwd>
#include <memory>
#include <string_view>

namespace yuzu::server::healthcheck {

struct HealthcheckDeadlines {
    int connect_sec{1};
    int write_sec{1};
    int read_sec{2};
    /// Whole-request ceiling handed to httplib::set_max_timeout.
    int max_total_ms{3000};
};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
/// The configure half of the TLS probe, exposed so a test can inspect the
/// client's trust store after a connect. Loads the anchor via
/// set_ca_cert_path only (never the system store); verification on, hostname
/// check off, redirects not followed.
[[nodiscard]] std::unique_ptr<httplib::SSLClient> make_tls_client(const HealthcheckTarget& target);
#endif

/// One GET against `target`. Never throws; a transport or TLS failure is
/// reported as status 0 plus a reason.
[[nodiscard]] HealthcheckOutcome probe_once(const HealthcheckTarget& target,
                                            const HealthcheckDeadlines& deadlines);

/// Entry point for `yuzu-server --healthcheck`. Writes one diagnostic line to
/// `diag` on failure and nothing on success; returns the process exit code.
[[nodiscard]] int run_healthcheck(const Config& cfg, std::string_view path, std::ostream& diag);

} // namespace yuzu::server::healthcheck
