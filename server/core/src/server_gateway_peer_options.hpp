#pragma once

/// @file server_gateway_peer_options.hpp
///
/// CLI/env registration for the gateway-upstream peer authorization knobs, split
/// out of `main.cpp` so a test can reach it (same reason and same shape as
/// `server_ota_options.hpp`).
///
/// The flag names and env spellings are defined in `gateway_peer_flags.hpp`; they and the
/// defaults here are contract: they appear in `docs/user-manual/server-admin.md`, in the boot
/// refusal messages (`gateway_peer_resolution.cpp`) and in every shipped rig.
/// `test_server_gateway_peer_options.cpp` pins them, so a default cannot silently revert.
///
/// Raw values land in `Config`; `normalize_gateway_peer_options` must run once
/// after parsing. The cross-flag decision (which of these combinations may boot)
/// is NOT made here: it needs the live TLS posture and is made after certificate
/// bootstrap by `gateway_peer::resolve_gateway_peer_authz`.

#include <CLI/CLI.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/server/server.hpp>

#include "gateway_peer_flags.hpp"
#include "gateway_peer_pinset.hpp"

namespace yuzu::server {

/// Register the gateway-upstream peer authorization options onto `app`, bound to `cfg`.
///
/// `--insecure-gateway-peer` is bound to the `bool` itself, NOT to an `->each()`
/// callback that sets it: CLI11 runs `each` for an environment value as well, so
/// `YUZU_INSECURE_GATEWAY_PEER=0` or `=false` would still switch the
/// acknowledgement ON. Bound to the bool, the environment value is parsed as a
/// boolean and `0`/`false` leave it off.
inline void register_gateway_peer_options(CLI::App& app, Config& cfg) {
    // Comma-splitting happens ONCE, in normalize_gateway_peer_options (via
    // gateway_peer::split_pin_list). Do NOT add CLI11 `->delimiter(',')` here: the
    // value would be split twice.
    app.add_option(std::string{kGatewayPeerPinFlag}, cfg.gateway_peer_pins,
                   "SHA-256 of a gateway certificate's SubjectPublicKeyInfo (64 hex characters) "
                   "that may use the gateway-upstream service. Repeatable; the environment form "
                   "is comma-separated. Pins identify a KEY, so a reissued certificate over the "
                   "same key keeps matching.")
        ->envname(std::string{kGatewayPeerPinEnv});
    app.add_option(std::string{kGatewayPeerPinFileFlag}, cfg.gateway_peer_pin_files,
                   "File of gateway pins: one or more PEM CERTIFICATE blocks (no other text), or hex "
                   "pins one per line. Repeatable; the environment form is a single path. Read "
                   "ONCE at boot: changing the pins means restarting the server.")
        ->envname(std::string{kGatewayPeerPinFileEnv});
    app.add_flag(std::string{kInsecureGatewayPeerFlag}, cfg.insecure_gateway_peer,
                 "Run the gateway-upstream service with peer authorization DISABLED. The only way "
                 "to use --gateway-upstream with --no-tls, or without pins. Refused together with "
                 "any --gateway-peer-pin / --gateway-peer-pin-file. Development rigs only.")
        ->envname(std::string{kInsecureGatewayPeerEnv});
}

/// Flatten comma-separated pin tokens, so every surface reports what the server will actually
/// use. Call once after parsing. Tokens are NOT validated here (`load_boot_pins` rejects a
/// malformed one).
inline void normalize_gateway_peer_options(Config& cfg) {
    std::vector<std::string> flat;
    for (const auto& token : cfg.gateway_peer_pins) {
        for (auto& part : gateway_peer::split_pin_list(token))
            flat.push_back(std::move(part));
    }
    cfg.gateway_peer_pins = std::move(flat);
}

} // namespace yuzu::server
