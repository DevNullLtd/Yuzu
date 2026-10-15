#include "gateway_peer_resolution.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <utility>

#include "gateway_peer_flags.hpp"

namespace yuzu::server::gateway_peer {

namespace {

// The last stage strips openssl's "SHA2-256(stdin)= " prefix so the output is the bare hex.
constexpr std::string_view kPinCommand =
    "openssl x509 -pubkey -noout -in <gateway.pem> | openssl pkey -pubin -outform DER | "
    "openssl dgst -sha256 | awk '{print $NF}'";

std::string flag(std::string_view f) { return std::string{f}; }

std::string pin_flags() {
    return flag(kGatewayPeerPinFlag) + " <64-hex> or " + flag(kGatewayPeerPinFileFlag) +
           " <pem-or-hex-file> (compute the 64-hex pin with: " + std::string{kPinCommand} + ")";
}

std::string pin_remedy() { return "Pin the gateway certificate's key with " + pin_flags() + "."; }

std::string ack_remedy() {
    return "To run with gateway peer authorization DISABLED instead (development rigs only), pass " +
           flag(kInsecureGatewayPeerFlag) + " (env " + std::string{kInsecureGatewayPeerEnv} + "=1).";
}

/// The way out for an install that has no gateway at all: the shipped service unit carries
/// --gateway-upstream unconditionally, so such an install reaches these refusals too.
std::string no_gateway_remedy() {
    return "If this server runs no gateway, omit --gateway-upstream instead.";
}

} // namespace

Resolution resolve_gateway_peer_authz(const ResolutionInputs& in) noexcept {
    Resolution r; // mode defaults to Refuse
    try {
        const bool explicit_pins = !in.hex_pins.empty() || !in.pin_files.empty();

        if (!in.service_enabled) {
            r.mode = AuthzMode::Disabled;
            if (in.insecure_ack)
                r.warnings.push_back(flag(kInsecureGatewayPeerFlag) +
                                     " has no effect: --gateway-upstream is not set, so the "
                                     "gateway-upstream service is not enabled.");
            if (explicit_pins)
                r.warnings.push_back("Gateway peer pins are configured but ignored: "
                                     "--gateway-upstream is not set, so the gateway-upstream "
                                     "service is not enabled.");
            return r;
        }

        if (in.insecure_ack) {
            if (explicit_pins) {
                r.refusal = flag(kInsecureGatewayPeerFlag) + " was given together with " +
                            flag(kGatewayPeerPinFlag) + " / " + flag(kGatewayPeerPinFileFlag) +
                            ", which contradict each other: the acknowledgement would silently "
                            "disable the configured pins. Refusing to start. Remove the "
                            "acknowledgement to enforce the pins, or remove the pins to run with "
                            "peer authorization disabled.";
                return r;
            }
            const bool tls_with_ca = in.tls_enabled && in.ca_present;
            r.mode = tls_with_ca ? AuthzMode::InsecureAckTls : AuthzMode::InsecureAck;
            r.alarm = "GATEWAY PEER AUTHORIZATION IS DISABLED (" + flag(kInsecureGatewayPeerFlag) +
                      "): the gateway-upstream service will serve any caller that can reach it. "
                      "Development rigs only; do not use in production.";
            if (tls_with_ca)
                r.warnings.push_back("TLS and a client CA are configured, so gateway peer pinning "
                                     "is available: remove " +
                                     flag(kInsecureGatewayPeerFlag) + " to enforce it.");
            return r;
        }

        if (!in.tls_enabled) {
            r.refusal = "The gateway-upstream service is enabled (--gateway-upstream) but TLS is "
                        "off (--no-tls), so no gateway certificate can be verified and --no-tls "
                        "is not an acknowledgement. Refusing to start. "
                        "Enable TLS and pin the gateway certificate's key with " + pin_flags() + ". " +
                        ack_remedy() + " " + no_gateway_remedy();
            return r;
        }
        if (!in.ca_present) {
            r.refusal = "The gateway-upstream service is enabled but its listener has no client CA "
                        "(--insecure-skip-client-verify without --ca-cert), so it never requests a "
                        "client certificate and no gateway pin can ever match. Refusing to start. "
                        "Supply --ca-cert (or --management-ca-cert when the management listener is "
                        "overridden). " +
                        ack_remedy() + " " + no_gateway_remedy();
            return r;
        }

        if (explicit_pins) {
            r.mode = AuthzMode::Enforce;
        } else if (in.grpc_creds_are_default) {
            if (in.default_gateway_cert_path.empty()) {
                r.refusal = "The gateway-upstream service is enabled on the built-in default "
                            "certificates but the default gateway certificate path is unknown, so "
                            "the automatic pin cannot be derived. Refusing to start. " +
                            pin_remedy();
                return r;
            }
            r.mode = AuthzMode::Enforce;
            r.auto_pin = true;
            r.auto_pin_file = in.default_gateway_cert_path;
        } else {
            r.refusal = "The gateway-upstream service is enabled with operator-supplied "
                        "certificates and no gateway peer pin is configured. Refusing to start. " +
                        pin_remedy() + " " + ack_remedy() + " " + no_gateway_remedy();
            return r;
        }

        if (!in.cert_group.empty() && (r.auto_pin || in.grpc_creds_are_default)) {
            r.warnings.push_back(
                "--cert-group is set: any process in that group holds gateway authority; "
                "production installs should issue a gateway-only certificate with a 0600 key and "
                "pin it explicitly (" +
                flag(kGatewayPeerPinFlag) + " / " + flag(kGatewayPeerPinFileFlag) + ").");
        }
        return r;
    } catch (...) {
        Resolution fail; // Refuse
        fail.refusal = "Internal error while resolving gateway peer authorization. Refusing to "
                       "start.";
        return fail;
    }
}

std::expected<BootPins, std::string> build_boot_pins(const ResolutionInputs& in,
                                                     const Resolution& res,
                                                     const FileReader& reader) {
    if (res.mode != AuthzMode::Enforce)
        return std::unexpected("internal error: pins requested for a mode that does not enforce them");

    // The auto-pin file is handed to the loader only for an auto-pin resolution, and the loader
    // reads it only when no explicit source exists, so the two are never mixed.
    const std::string auto_file = res.auto_pin ? res.auto_pin_file : std::string{};
    const std::vector<std::string> no_pins;
    // `load_boot_pins` returns an error for an empty union, so a success is never an empty set.
    auto loaded = res.auto_pin ? load_boot_pins(no_pins, no_pins, auto_file, reader)
                               : load_boot_pins(in.hex_pins, in.pin_files, auto_file, reader);
    // The loader's messages are clauses with no terminating period; add one so the log reads as
    // two sentences ("...does not exist. Refusing to start.").
    const auto refuse = [&res](std::string cause) {
        if (cause.empty() || cause.back() != '.')
            cause += '.';
        std::string msg = "Gateway peer pin configuration is invalid: " + cause + " Refusing to start. ";
        msg += res.auto_pin ? "This is the automatic pin of the default gateway certificate: "
                              "restore the file, or configure an explicit pin (" +
                                  flag(kGatewayPeerPinFlag) + " / " + flag(kGatewayPeerPinFileFlag) + ")."
                            : "Fix the pin source, or supply " + pin_flags() + ".";
        return std::unexpected(std::move(msg));
    };
    if (!loaded)
        return refuse(loaded.error());
    // A set whose every pin is known to lack serverAuth denies every call (the policy requires
    // serverAuth even of a pinned certificate): refuse rather than boot a gateway-upstream service
    // that can never admit anyone. A set with only SOME such pins keeps the warning below, and a
    // hex-only pin is never counted (it carries no extended key usage to inspect).
    if (loaded->size() > 0 && loaded->pins_without_server_auth() >= loaded->size())
        return refuse("every configured gateway peer pin lacks the serverAuth extended key usage, "
                      "so every call would be denied; pin the gateway's own certificate (not a CA "
                      "certificate)");
    BootPins out;
    out.pins = std::make_shared<const PinSet>(std::move(*loaded));
    if (out.pins->pins_without_server_auth() > 0)
        out.warnings.push_back("Gateway peer pin source lists " +
                               std::to_string(out.pins->pins_without_server_auth()) +
                               " certificate(s) without serverAuth; the policy will deny them.");
    return out;
}

std::string format_pin_prefixes(const PinSet& pins) {
    const std::vector<std::string> all = pins.sorted_pins();
    if (all.empty())
        return "pin prefixes (first 16 hex): none";
    std::string out = "pin prefixes (first 16 hex): ";
    const std::size_t shown = std::min(all.size(), kBootLogMaxPinPrefixes);
    for (std::size_t i = 0; i < shown; ++i) {
        if (i > 0)
            out += ',';
        out += all[i].substr(0, kBootLogPinPrefixChars);
    }
    if (all.size() > shown)
        out += ", ... and " + std::to_string(all.size() - shown) + " more";
    return out;
}

std::string enforce_boot_line(const PinSet& pins, std::size_t hex_values, std::size_t pin_files) {
    return "gateway peer authorization: enforcing " + std::to_string(pins.size()) + " pin(s) from " +
           std::to_string(hex_values) + " " + flag(kGatewayPeerPinFlag) + " value(s) and " +
           std::to_string(pin_files) + " pin file(s); pins are fixed until restart; " +
           format_pin_prefixes(pins);
}

} // namespace yuzu::server::gateway_peer
