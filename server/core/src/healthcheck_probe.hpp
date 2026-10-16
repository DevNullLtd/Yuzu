#pragma once

/// @file healthcheck_probe.hpp
/// The httplib transport behind `yuzu-server --healthcheck` (#5906). All
/// decisions (target, verdict, diagnostic) are pure and live in
/// healthcheck_rules.hpp; this shell runs ONE GET and reports what came back.

#include "healthcheck_rules.hpp"

#include <httplib.h>

#include <chrono>
#include <cstdlib>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string_view>

namespace yuzu::server::healthcheck {

/// Absolute cap over the whole `--healthcheck` probe, name resolution and TLS handshake
/// included. 1 s of headroom under the documented 5 s healthcheck timeout (Compose's own
/// default is 30 s) covers exec, CLI parse, the diagnostic write and exit; published verbatim
/// in the server-admin "Time" row, together with the per-phase bounds below.
inline constexpr std::chrono::milliseconds kProbeDeadline{4000};
static_assert(kProbeDeadline < std::chrono::seconds(5),
              "must stay under the documented 5 s healthcheck timeout");
inline constexpr int kConnectSec = 1;   ///< TCP connect
inline constexpr int kWriteSec = 1;     ///< socket write
inline constexpr int kReadSec = 2;      ///< socket read
inline constexpr int kRequestMs = 3000; ///< whole-request ceiling (probe_once default)

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
/// The configure half of the TLS probe, exposed so a test can inspect the
/// client's trust store after a connect. Loads the anchor from the CA file or a PEM
/// block only (never the system store); verification on, hostname
/// check off, redirects not followed. Operator mode (`partial_chain`) anchors on the first
/// certificate of the anchor file only (first_pem_certificate). Returns nullptr when the
/// target has no trust anchor: an empty CA path would make httplib fall back to the OS store.
/// Throws std::runtime_error when OpenSSL cannot create a client context, and in operator mode
/// when the anchor file is missing, unreadable, over 64 KiB, or yields no usable first
/// certificate or one that does not decode (the file is never loaded whole). `SSL certificate
/// loading failed` leads that message.
[[nodiscard]] std::unique_ptr<httplib::SSLClient> make_tls_client(const HealthcheckTarget& target);
#endif

/// One GET against `target`. A transport or TLS failure is reported as status 0
/// plus a reason; an exception escaping httplib (0.37.1 reserves the response
/// body on a peer-claimed Content-Length before its payload ceiling applies) is
/// translated by run_healthcheck, never propagated. `max_total_ms` is the request-phase
/// ceiling handed to httplib::set_max_timeout; it does not cover name
/// resolution or the TLS handshake (see probe_bounded).
[[nodiscard]] HealthcheckOutcome probe_once(const HealthcheckTarget& target,
                                            int max_total_ms = kRequestMs);

/// Runs `probe` on a worker thread and waits up to `deadline` for it. Returns
/// its outcome if it finished, or nullopt if the deadline came first, in which
/// case the worker is detached: it is blocked inside httplib/OpenSSL, which
/// offers no cancellation. The caller must not return into code that tears
/// down process state (exit via std::_Exit); the worker owns everything it
/// touches, so abandoning it is safe until then. May throw: what `probe` threw
/// is stored by the packaged_task and rethrown here once the worker is joined (one
/// thrown after the deadline stays in the abandoned shared state, never terminate),
/// and starting the worker throws std::system_error when a thread limit is hit.
[[nodiscard]] std::optional<HealthcheckOutcome>
probe_bounded(std::chrono::milliseconds deadline, std::function<HealthcheckOutcome()> probe);

/// Entry point for `yuzu-server --healthcheck`. Writes one diagnostic line to
/// `diag` on failure and nothing on success; returns the process exit code. The
/// whole probe is cut off at `deadline` (a timeout calls `hard_exit`, which does
/// not return in production). An exception thrown by `probe`, or a failure to start
/// the probe thread, is reported as a failure (exit 1, one line naming it). The three
/// trailing parameters are the injection points a test drives; the defaults ARE
/// production: `probe_once`, `kProbeDeadline` and `std::_Exit`. On POSIX it also sets
/// SIGPIPE to ignored before the first socket write (see healthcheck_probe.cpp). `std::_Exit` is
/// the same primitive ServerImpl::stop() uses to force-exit past a wedged web thread: the
/// abandoned worker captures state that normal teardown would destroy under it.
[[nodiscard]] int run_healthcheck(
    const Config& cfg, std::string_view path, std::ostream& diag,
    std::function<HealthcheckOutcome(const HealthcheckTarget&)> probe =
        [](const HealthcheckTarget& t) { return probe_once(t); },
    std::chrono::milliseconds deadline = kProbeDeadline, void (*hard_exit)(int) = std::_Exit);

} // namespace yuzu::server::healthcheck
