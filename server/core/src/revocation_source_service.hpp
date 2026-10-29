#pragma once

/// @file revocation_source_service.hpp
/// The ONE seam behind the revocation-source REST routes and MCP tools (ADR-0070 R1/D12;
/// `docs/crypto-slice2-certificate-design.md`, "R1: registered-CRL revocation"). REST and MCP both
/// call this, so the two twins accept exactly the same bodies and refuse them with the same
/// words: parsing, PEM validation, URL validation, the registration-time address check and the
/// JSON views all live here, once. Transport concerns (the gate, the audit rows, the HTTP / A4
/// shape) stay in `revocation_source_routes.cpp` and `mcp_server.cpp`.
///
/// REGISTRATION (the design's "Registration"):
///   - `name` 1..128 bytes of UTF-8 without control characters (free text; escaped on render);
///   - `ca_certificates` 1..8 PEM certificates, each parsed, `cA=TRUE`, `cRLSign` if a key usage
///     extension is present, ONE subject Name across the set (a source is one CA; several keys let
///     a CA renewal keep verifying). The store keeps each DER, SKI and SPKI hash;
///   - `crl_urls` 1..8 objects `{url, confirmed_address_classes?}`: `http`/`https`, a host, no
///     userinfo, no fragment, at most 2,048 bytes, ASCII only (IDNs as punycode). The host is
///     resolved HERE and every address classified. Refused outright with no override: the
///     always-refused tier (unspecified, link-local, cloud metadata, multicast, reserved),
///     loopback, and every address the server itself is bound to or listening on. Any other
///     class must be named in `confirmed_address_classes` - the administrator is shown the
///     classes in the 400 and resends with them - and is stored; the fetcher (2b-1b) refuses an
///     address outside the confirmed classes on every fetch.
///
/// The address classifier is `oidc_egress_policy.hpp`'s, included as is (a pure header with no
/// OIDC state), not copied. The resolver and the "own addresses" set are injected (`EgressEnv`)
/// so tests never touch DNS or the host's interfaces.
///
/// DISCLOSED LIMITS: in an HA deployment the own-address refusal covers only the REGISTERING
/// replica's addresses; resolution at registration is one lookup, and the fetcher re-resolves and
/// pins on every fetch. Registration runs one blocking DNS lookup per URL (bounded by a resolver
/// timeout on POSIX) on the request thread.

#include "revocation_source_store.hpp"

#include "bounded_resolver.hpp"
#include "nat64_discovery.hpp"
#include "oidc_egress_policy.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::revocation_source {

/// Pre-auth body cap for POST / PUT on `/api/v1/crypto/revocation-sources` (mirrored by
/// `body_cap_policy.hpp`; a static_assert in the routes TU pins the pair).
inline constexpr std::size_t kBodyMaxBytes = 192 * 1024;
inline constexpr std::size_t kMaxPemBytes = 16 * 1024;
inline constexpr std::size_t kMaxResolvedAddresses = 32;

/// D10's sentence, carried by every certificate and revocation-source description (0070:831-832).
inline constexpr std::string_view kFactsOnlySentence =
    "facts only; the only built-in checks are D13's named rules and windows, each shown with its "
    "criterion";

/// Closed set of address-class names an administrator may confirm (the others are refused).
inline constexpr std::string_view kConfirmableClasses[] = {
    "public", "private", "carrier-grade-nat", "unique-local", "non-global"};

struct ServiceError {
    enum class Kind {
        kInvalidParams, ///< 400 invalid_params; `param` names the parameter
        kNotFound,      ///< 404 not_found
        kConflict,      ///< 409 conflict; `existing_id` names the registered source (register), 0 at the cap
        kVersionConflict, ///< 409: expected_config_version is stale; `existing_id` = the current config_version
        kUnavailable,   ///< 503, retryable: the store is degraded or admission shed
        kOutcomeUnknown ///< 503: a write may or may not have committed - re-read, then retry
    };
    Kind kind{Kind::kUnavailable};
    std::string message;
    std::string param; ///< kInvalidParams: the parameter the message is about
    std::int64_t existing_id{0};
    /// kUnavailable only: the honest retry hint in ms; 0 = the transport's default (5000).
    std::int64_t retry_after_ms{0};
};

/// The administrator decision both transports act on (see `revocation_source_admin_gate.hpp`,
/// which computes it). A plain struct so the routes TU needs no store header.
struct AdminDecision {
    enum class Outcome { kAdmin, kDenied, kUnavailable };
    Outcome outcome{Outcome::kUnavailable};
    std::string audit_reason; ///< the `denied` row's detail
    std::string message;      ///< the response text
};

/// The audit `result` for a failed operation, shared by both transports so the labels cannot drift:
/// a refusal the caller caused (bad body, unknown id, conflict) is `denied`; a fault of ours or an
/// unknown outcome is `failure`.
[[nodiscard]] inline const char* audit_result_for(const ServiceError& e) {
    return (e.kind == ServiceError::Kind::kUnavailable ||
            e.kind == ServiceError::Kind::kOutcomeUnknown)
               ? "failure"
               : "denied";
}

/// Resolver and own-address set. All injected, so tests never touch DNS or the host's interfaces.
struct EgressEnv {
    /// kNotFound = the resolver answered "no such name" (a caller problem, 400). kUnavailable = a
    /// transient resolver failure (EAI_AGAIN / EAI_FAIL), kTimeout = no answer in the budget,
    /// kBusy = no resolver capacity; all three are a retryable 503, counted by their own reason.
    enum class ResolveStatus { kOk, kNotFound, kUnavailable, kTimeout, kBusy };
    struct Resolved {
        ResolveStatus status{ResolveStatus::kNotFound};
        std::vector<std::string> addresses; ///< numeric text, kOk only
    };
    /// Resolve `host` within `budget`.
    std::function<Resolved(const std::string& host, std::chrono::milliseconds budget)> resolve;
    /// Every address the server is bound to or listening on, with a wildcard bind expanded to every
    /// address on every local interface; `budget` bounds any listen-host name lookups (the total, not
    /// per host). nullopt = it could NOT be determined (interface
    /// enumeration failed, or a listen host did not resolve): registration then FAILS CLOSED with a
    /// retryable 503, never proceeds on a partial set.
    std::function<std::optional<std::vector<std::string>>(std::chrono::milliseconds budget)>
        local_addresses;
    /// NAT64 prefixes (RFC 6052) the operator declared (`--oidc-nat64-prefix`): an IPv6 address
    /// inside one is classified, and compared with this server's own addresses, by the IPv4 address
    /// embedded in it. The well-known 64:ff9b::/96 and 6to4 2002::/16 are always decoded.
    std::vector<::yuzu::server::oidc::egress::Nat64Prefix> nat64_prefixes;
    /// RFC 7050 discovery of the network's NAT64 prefixes, through the process-wide never-shrink
    /// cache shared with the OIDC client (nat64_discovery.hpp). Empty function = no discovery.
    std::function<net::Nat64Discovery(std::chrono::milliseconds budget)> discover_nat64;
    /// Counted once per degrade, with a closed `reason` (own_addresses_unavailable, dns_unavailable, dns_timeout, dns_busy,
    /// dns_budget_exhausted, validation_busy, nat64_discovery_unavailable, nat64_discovery_stale, nat64_discovery_overflow). Empty = not counted (tests).
    std::function<void(std::string_view reason)> note_degrade;
};

/// RFC 7050 for the registration check: resolve `ipv4only.arpa` through the bounded resolver
/// (`lookup` empty = system DNS) into the SHARED discovered-prefix cache `cache`.
[[nodiscard]] net::Nat64Discovery
discover_nat64(std::chrono::milliseconds budget, net::LookupFn lookup,
               net::Nat64DiscoveryCache& cache = net::process_nat64_cache(),
               std::shared_ptr<net::ResolverPool> pool = {});

/// The production environment. `listen_specs` are the configured listener addresses
/// ("host", "host:port" or "[v6]:port"; an empty spec is a disabled listener and is skipped);
/// a wildcard host expands to every interface address.
[[nodiscard]] EgressEnv make_system_egress_env(
    std::vector<std::string> listen_specs,
    std::vector<::yuzu::server::oidc::egress::Nat64Prefix> nat64_prefixes = {});

struct ListResult {
    std::vector<RevocationSourceRecord> sources;
    std::int64_t crl_past_next_update{0};
};

class RevocationSourceService {
public:
    RevocationSourceService(RevocationSourceStore& store, EgressEnv env)
        : store_(store), env_(std::move(env)) {}

    [[nodiscard]] std::expected<ListResult, ServiceError> list();
    [[nodiscard]] std::expected<RevocationSourceRecord, ServiceError> get(std::int64_t id);
    /// POST body -> the registered source (`validate_registration`, then `register_validated`).
    [[nodiscard]] std::expected<RevocationSourceRecord, ServiceError>
    register_source(const nlohmann::json& body, const std::string& created_by);
    /// PUT body (the same shape as POST) -> the source after the replace.
    [[nodiscard]] std::expected<RevocationSourceUpdate, ServiceError>
    update_source(std::int64_t id, const nlohmann::json& body);
    /// The write halves, for a transport that validates first (so it can write its `attempted`
    /// audit row between validation and the mutation) without resolving every host twice.
    [[nodiscard]] std::expected<RevocationSourceRecord, ServiceError>
    register_validated(const NewRevocationSource& v, const std::string& created_by);
    [[nodiscard]] std::expected<RevocationSourceUpdate, ServiceError>
    update_validated(std::int64_t id, const NewRevocationSource& v);
    [[nodiscard]] std::expected<void, ServiceError> remove(std::int64_t id);
    /// Body `{}` or `{"reset_at": "<RFC 3339 UTC>", "pin_crl_sha256": "<64 hex>"}`.
    [[nodiscard]] std::expected<HighWaterReset, ServiceError>
    reset_high_water(std::int64_t id, const nlohmann::json& body);
    /// Validate a reset body without touching the store (so a transport can reject it BEFORE
    /// writing its `attempted` audit row).
    [[nodiscard]] std::expected<void, ServiceError> validate_reset(const nlohmann::json& body) const;

    /// Parse and fully validate a registration body (shape, PEM, URLs, addresses) without
    /// touching the store. Public so the validation is testable on its own.
    /// `kRegister`: POST body. `kUpdate`: PUT body, which REQUIRES `expected_config_version` on
    /// both transports (a body, and on MCP an approval, can be days old, so it must prove which
    /// configuration it was read from; a body equal to the stored one is still a no-op success).
    enum class BodyMode { kRegister, kUpdate };
    [[nodiscard]] std::expected<NewRevocationSource, ServiceError>
    validate_registration(const nlohmann::json& body, BodyMode mode = BodyMode::kRegister) const;

private:
    RevocationSourceStore& store_;
    EgressEnv env_;
};

/// A path id: decimal digits only, 1..18 of them, not zero. nullopt otherwise.
[[nodiscard]] std::optional<std::int64_t> parse_source_id(std::string_view s);

/// Epoch seconds as RFC 3339 UTC ("1970-01-01T00:00:00Z" for an unrepresentable value).
[[nodiscard]] std::string rfc3339_utc(std::int64_t epoch_seconds);

// JSON views, shared by both transports. Registration state is real; the fetch-status fields are
// present from the first read and read "never fetched" / null until the fetcher (2b-1b) writes
// them.
[[nodiscard]] nlohmann::json source_json(const RevocationSourceRecord& r);
[[nodiscard]] nlohmann::json list_json(const ListResult& l);
[[nodiscard]] nlohmann::json update_json(const RevocationSourceUpdate& u);
[[nodiscard]] nlohmann::json reset_json(const HighWaterReset& r);

// Audit text, shared by both transports. Every operator-supplied value passes `log_token`.
inline constexpr std::string_view kAuditList = "crypto.revocation_source.list";
inline constexpr std::string_view kAuditView = "crypto.revocation_source.view";
inline constexpr std::string_view kAuditRegister = "crypto.revocation_source.register";
inline constexpr std::string_view kAuditUpdate = "crypto.revocation_source.update";
inline constexpr std::string_view kAuditRemove = "crypto.revocation_source.remove";
inline constexpr std::string_view kAuditResetHighWater = "crypto.revocation_source.reset_high_water";
inline const std::string kAuditTargetType = "RevocationSource";

[[nodiscard]] std::string audit_detail_list(std::string_view correlation_id, std::size_t count);
[[nodiscard]] std::string audit_detail_view(std::string_view correlation_id);
/// The detail of the `requested` row of register / update: name, key and URL counts, the URLs.
[[nodiscard]] std::string audit_detail_config(std::string_view correlation_id,
                                              const NewRevocationSource& n);
[[nodiscard]] std::string audit_detail_source(std::string_view correlation_id,
                                              const RevocationSourceRecord& r);
[[nodiscard]] std::string audit_detail_update(std::string_view correlation_id,
                                              const RevocationSourceUpdate& u);
[[nodiscard]] std::string audit_detail_reset(std::string_view correlation_id,
                                             const nlohmann::json& body);
[[nodiscard]] std::string audit_detail_reset_result(std::string_view correlation_id,
                                                    const HighWaterReset& r);
[[nodiscard]] std::string audit_detail_error(std::string_view correlation_id, const ServiceError& e);

} // namespace yuzu::server::revocation_source
