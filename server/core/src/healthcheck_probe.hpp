#pragma once

/// @file healthcheck_probe.hpp
/// The httplib transport behind `yuzu-server --healthcheck` (#5906). All
/// decisions (target, verdict, diagnostic) are pure and live in
/// healthcheck_rules.hpp; this shell runs ONE GET and reports what came back.

#include "healthcheck_rules.hpp"

#include <httplib.h>

#include <chrono>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string_view>

namespace yuzu::server::healthcheck {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
/// The configure half of the TLS probe, exposed so a test can inspect the
/// client's trust store after a connect. Loads the anchor via
/// set_ca_cert_path only (never the system store); verification on, hostname
/// check off, redirects not followed. Returns nullptr when the target has no
/// trust anchor: an empty CA path would make httplib fall back to the OS store.
[[nodiscard]] std::unique_ptr<httplib::SSLClient> make_tls_client(const HealthcheckTarget& target);
#endif

/// One GET against `target`. Never throws; a transport or TLS failure is
/// reported as status 0 plus a reason. `max_total_ms` is the request-phase
/// ceiling handed to httplib::set_max_timeout; it does not cover name
/// resolution or the TLS handshake (see probe_bounded).
[[nodiscard]] HealthcheckOutcome probe_once(const HealthcheckTarget& target,
                                            int max_total_ms = 3000);

/// Runs `probe` on a worker thread and waits up to `deadline` for it. Returns
/// its outcome if it finished, or nullopt if the deadline came first, in which
/// case the worker is detached: it is blocked inside httplib/OpenSSL, which
/// offers no cancellation. The caller must not return into code that tears
/// down process state (exit via std::_Exit); the worker owns everything it
/// touches, so abandoning it is safe until then.
[[nodiscard]] std::optional<HealthcheckOutcome>
probe_bounded(std::chrono::milliseconds deadline, std::function<HealthcheckOutcome()> probe);

/// Entry point for `yuzu-server --healthcheck`. Writes one diagnostic line to
/// `diag` on failure and nothing on success; returns the process exit code. The
/// whole probe is cut off at 4 s (a timeout exits the process directly).
[[nodiscard]] int run_healthcheck(const Config& cfg, std::string_view path, std::ostream& diag);

} // namespace yuzu::server::healthcheck
