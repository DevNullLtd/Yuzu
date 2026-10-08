#pragma once

/// @file gateway_peer_resolution.hpp
/// The boot decision for gateway-upstream peer authorization: given the live TLS
/// posture and the operator's flags, which of {nothing, enforce, acknowledged
/// insecure, refuse to start} applies, and where the pins come from.
///
/// WHO DECIDES. `resolve_gateway_peer_authz` is the single place that maps
/// configuration to a mode. `ServerImpl::run` calls it AFTER certificate bootstrap
/// (so the effective listener credentials are known) and BEFORE any listener is
/// built, and exits non-zero on `Refuse`. It is pure: no I/O, no globals, no
/// logging. The caller prints `refusal` and `warnings`.
///
/// DECISION TABLE (first matching row wins):
///   | service enabled | ack  | explicit pins | TLS on | client CA | default gRPC creds | result |
///   | no              | any  | any           | any    | any       | any                | Disabled (warns if ack or pins were given) |
///   | yes             | yes  | yes           | any    | any       | any                | Refuse: contradictory |
///   | yes             | yes  | no            | yes    | yes       | any                | InsecureAckTls (alarm, mode gauge, boot audit row) |
///   | yes             | yes  | no            | other  | other     | any                | InsecureAck (alarm, mode gauge, boot audit row) |
///   | yes             | no   | any           | no     | any       | any                | Refuse: `--no-tls` is not an acknowledgement |
///   | yes             | no   | any           | yes    | no        | any                | Refuse: no client CA, so no pin can ever match |
///   | yes             | no   | yes           | yes    | yes       | any                | Enforce, explicit pins (they always win) |
///   | yes             | no   | no            | yes    | yes       | yes                | Enforce, AUTO-PIN of the default gateway certificate |
///   | yes             | no   | no            | yes    | yes       | no                 | Refuse: operator certificates need an explicit pin |
/// "Default gRPC creds" means the credentials the gateway-upstream listener
/// actually uses are the generated default set. It is NOT `using_default_certs`:
/// HTTPS can be on defaults while gRPC uses operator certificates, and then the
/// deployed gateway does not necessarily present the default gateway certificate.
/// The caller computes it from the same inputs that choose the listener credentials.
///
/// Gaps in the written matrix, decided here: an acknowledgement combined with TLS
/// on is allowed (it is the operator's explicit choice, with a warning that pins
/// are available); a refusal for TLS-off or no-CA is raised even when pins are
/// configured, because the pins could never match; pins with the service disabled
/// are ignored with a warning, not an error.
///
/// TWO ACKNOWLEDGED MODES. `InsecureAck` is the plaintext or no-client-CA rig, where there
/// is nothing to pin against. `InsecureAckTls` is the same acknowledgement while TLS AND a
/// client CA are in force: a production-shaped configuration in which the operator has
/// switched off a control that would work, which is what an alert should single out. Both
/// carry `Resolution::alarm` (the ONE loud "disabled" line the server logs at error level) and
/// make the server write one `server.gateway_peer_authz_disabled` audit row at boot.
///
/// "Zero resolvable pins at boot" is not decidable from flags alone (a pin file
/// may be unreadable), so it is `build_boot_pins`'s job and is also a refusal.
/// No path falls back from a broken explicit configuration to the automatic pin.
/// The pins are fixed at boot: nothing here reloads, ages out or revokes a pin.

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "gateway_peer_pinset.hpp"

namespace yuzu::server::gateway_peer {

/// Facts about the credentials the gateway-upstream listener will actually use,
/// read from the post-bootstrap configuration. `derive_listener_posture` turns them
/// into the two booleans `ResolutionInputs` needs.
struct ListenerFacts {
    bool tls_enabled{false};
    /// ANY surface on the generated defaults, HTTPS included. Carried so a test can
    /// show the decision ignores it: HTTPS on defaults says nothing about what the
    /// gRPC listener, or the deployed gateway, presents.
    bool using_default_certs{false};
    bool using_default_agent_certs{false}; ///< the gRPC agent listener is on the default set
    bool mgmt_override{false};     ///< --management-cert/-key/-ca-cert: any one set
    bool agent_ca_present{false};  ///< the agent-listener client CA (--ca-cert or default) is set
    bool mgmt_ca_present{false};   ///< --management-ca-cert is set
    /// The agent listener's server certificate AND client CA are exactly the
    /// generated default files (not merely "defaults were bootstrapped").
    bool agent_creds_are_default_files{false};
};

struct ListenerPosture {
    bool ca_present{false};              ///< the listener requests and verifies client certificates
    bool grpc_creds_are_default{false};  ///< the listener credentials ARE the generated default set
};

/// Mirrors the credential choice in `ServerImpl::run` for the gateway-upstream
/// listener: a management override wins (its own CA), otherwise the listener is
/// strict on the default set, otherwise it reuses the operator agent credentials.
/// `grpc_creds_are_default` keys on `using_default_agent_certs` and the exact
/// default files, NEVER on `using_default_certs`.
[[nodiscard]] constexpr ListenerPosture derive_listener_posture(const ListenerFacts& f) noexcept {
    ListenerPosture p;
    if (!f.tls_enabled)
        return p; // plaintext: no CA, no certificates
    p.ca_present = f.mgmt_override ? f.mgmt_ca_present : f.agent_ca_present;
    p.grpc_creds_are_default = f.using_default_agent_certs && !f.mgmt_override &&
                               f.agent_creds_are_default_files;
    return p;
}

struct ResolutionInputs {
    bool service_enabled{false};          ///< `gateway_upstream_address` is non-empty
    bool tls_enabled{false};              ///< gRPC TLS is on (`--no-tls` absent)
    bool ca_present{false};               ///< the listener verifies client certificates against a CA
    bool grpc_creds_are_default{false};   ///< the listener credentials ARE the generated default set
    std::vector<std::string> hex_pins;    ///< explicit hex pins, already comma-split
    std::vector<std::string> pin_files;   ///< explicit pin files
    bool insecure_ack{false};             ///< `--insecure-gateway-peer`
    std::string cert_group;               ///< `--cert-group`; non-empty shares default keys by group
    std::string default_gateway_cert_path; ///< default-gateway.pem, for the auto-pin; empty if unknown
};

enum class AuthzMode : std::uint8_t {
    Disabled,    ///< the gateway-upstream service is not enabled
    Enforce,     ///< the guard enforces the pin set
    InsecureAck, ///< the guard admits every caller by explicit acknowledgement (plaintext / no CA)
    InsecureAckTls, ///< the same acknowledgement while TLS and a client CA are in force
    Refuse,      ///< do not start
};

/// The gauge the `mode` label below belongs to: ONE name, used by the server wherever it
/// describes or sets the gauge.
inline constexpr std::string_view kAuthzModeMetric = "yuzu_server_gateway_peer_authz_mode";

/// The `mode` label of `yuzu_server_gateway_peer_authz_mode`. `Refuse` has no
/// series (the process exits); it returns "refused" only so a caller can log it.
[[nodiscard]] constexpr std::string_view to_label(AuthzMode m) {
    switch (m) {
    case AuthzMode::Disabled:
        return "disabled";
    case AuthzMode::Enforce:
        return "enforce";
    case AuthzMode::InsecureAck:
        return "insecure_ack";
    case AuthzMode::InsecureAckTls:
        return "insecure_ack_tls";
    case AuthzMode::Refuse:
        return "refused";
    }
    return "refused";
}

/// The closed label set pre-seeded on the mode gauge (every mode that can run).
inline constexpr std::array<AuthzMode, 4> kRunnableAuthzModes{
    AuthzMode::Enforce, AuthzMode::InsecureAck, AuthzMode::InsecureAckTls, AuthzMode::Disabled};

struct Resolution {
    AuthzMode mode{AuthzMode::Refuse}; ///< a default-constructed Resolution refuses
    bool auto_pin{false};              ///< Enforce only: the pin is derived from the default certificate
    std::string auto_pin_file;         ///< set iff `auto_pin`
    std::string refusal;               ///< set iff `mode == Refuse`: actionable, names the flag and remedy
    /// Set iff the mode is `InsecureAck` or `InsecureAckTls`: the single "peer authorization is
    /// DISABLED" wording. The caller logs it ONCE, at error level; it is deliberately not repeated
    /// in `warnings`.
    std::string alarm;
    std::vector<std::string> warnings; ///< each to be logged at warn level at boot
};

/// See the file banner. Never throws.
[[nodiscard]] Resolution resolve_gateway_peer_authz(const ResolutionInputs& in) noexcept;

/// What `build_boot_pins` hands back on success.
struct BootPins {
    std::shared_ptr<const PinSet> pins; ///< never null, never empty
    std::vector<std::string> warnings;  ///< boot-time problems that did not make the set empty
};

/// Build the boot pin set for an `Enforce` resolution (`load_boot_pins`). The sources are
/// exactly the explicit ones, or the auto-pin file when `res.auto_pin` (never both, never a
/// fallback from one to the other). Returns an error string, suitable for the boot log, when a
/// hex pin or a pin file is malformed, missing or empty, a supplied pin option holds no pin at
/// all (blank), the union is empty, or EVERY pin is known to lack serverAuth (every call would be
/// denied: the pin is of a CA or an agent-shaped certificate). A set in which only SOME pins lack
/// serverAuth gets a warning (the policy will deny those certificates). `reader` is injectable
/// for tests (null selects the real filesystem reader).
[[nodiscard]] std::expected<BootPins, std::string>
build_boot_pins(const ResolutionInputs& in, const Resolution& res, const FileReader& reader = {});

/// How many pin prefixes the boot line lists; the rest are summarised as "... and K more".
inline constexpr std::size_t kBootLogMaxPinPrefixes = 8;
/// How many leading hex characters of a pin the boot line shows (the same width as the `spki=`
/// field of a denial log line and audit detail, so the two can be compared by eye).
inline constexpr std::size_t kBootLogPinPrefixChars = 16;

/// The `pin prefixes (first 16 hex): p1,p2,...` clause of the boot line: the pins sorted, each
/// cut to `kBootLogPinPrefixChars`, at most `kBootLogMaxPinPrefixes` listed and then
/// `, ... and K more`. A prefix is half of a public-key hash, not a secret; it exists so an
/// operator can compare the pins in force with the `spki=` of a denial. Empty set: "none".
[[nodiscard]] std::string format_pin_prefixes(const PinSet& pins);

/// The one INFO line `ServerImpl` logs when it enforces explicit pins:
/// `gateway peer authorization: enforcing N pin(s) from A --gateway-peer-pin value(s) and B pin
/// file(s); pins are fixed until restart; pin prefixes (first 16 hex): ...`. Pure, so a test can
/// pin the whole string (operators and shell tests match on it).
[[nodiscard]] std::string enforce_boot_line(const PinSet& pins, std::size_t hex_values,
                                            std::size_t pin_files);

} // namespace yuzu::server::gateway_peer
