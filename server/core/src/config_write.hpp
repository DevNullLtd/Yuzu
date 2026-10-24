#pragma once

/// @file config_write.hpp
/// The transport-free core of the Runtime Configuration API (7.3), shared by every surface that
/// reads or writes `RuntimeConfigStore` overrides: the legacy `GET /api/config` and
/// `PUT /api/config/{key}`, their v1 twins `GET /api/v1/config` and `PUT /api/v1/config/{key}`
/// (config_routes.cpp), and the MCP tools `get_runtime_config` / `set_runtime_config`
/// (mcp_server.cpp). Each surface keeps only what is genuinely its own: the gate call, the
/// audit call, and the envelope. The decisions live HERE, once:
///
///   - `write_refusal`   which caller may write which key (`RuntimeConfigStore::write_class` +
///                       `authz::admin_gate_verdict`). EXTEND this, never copy the switch: a
///                       second copy is how an MCP-tier token reached a key whose Settings route
///                       is administrator-only before #6379.
///   - `validate_value`  integer-typed keys are checked BEFORE anything is persisted, so a value
///                       the live `Config` cannot take never lands in the store (no ghost write).
///   - `write_and_apply` the store write, then the in-memory apply of the integer keys.
///   - `build_config_view` the effective values, the stored overrides (secrets reported as
///                       `is_set`, never a value), `allowed_keys` and `read_only_keys`. Given a
///                       viewing session it also withholds the value of every key that session
///                       could not write (see its comment).
///
/// No httplib, no audit sink, no envelope: the callers shape those.

#include <yuzu/server/auth.hpp>

#include <nlohmann/json.hpp>

#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {
struct Config;
class RuntimeConfigStore;
namespace auth {
class AutoApproveEngine;
}
} // namespace yuzu::server

namespace yuzu::server::config {

/// What the shared core reads and writes. Bound once at registration time and never reseated.
/// `cfg` is MUTABLE: `write_and_apply` assigns the integer keys into the live `Config` the
/// instant the store write succeeds.
struct Backing {
    Config* cfg{nullptr};
    const auth::AutoApproveEngine* auto_approve{nullptr};
    RuntimeConfigStore* store{nullptr};
};

/// True when the store, the live config and the auto-approve engine are all wired and the store is
/// open. Every surface answers 503 otherwise.
[[nodiscard]] bool store_ready(const Backing& b) noexcept;

/// A refusal of a write that has nothing to do with the value.
struct WriteRefusal {
    /// RouteOwned: the key has its own writer (400, no audit row). Denied: the caller is not
    /// allowed to write this key (403 with a `config.update`/`denied` audit row).
    enum class Kind { RouteOwned, Denied };
    Kind kind;
    std::string message;
    std::string remediation;
    /// Denied only: the `detail` of the `denied` audit row.
    std::string audit_detail;
};

/// Decides whether `session` may write `key` through a generic single-key write. Empty means
/// admitted; an unknown key has no class and is admitted here, and refused by the caller's
/// unknown-key check (`RuntimeConfigStore::is_allowed_key`).
///
/// A route-owned key is refused outright. A key whose own settings route is administrator-only
/// needs `authz::admin_gate_verdict` to admit (service-scoped and MCP-tier tokens never do,
/// whatever their creator's role); the `oidc_*` keys additionally refuse an elevation, because
/// they decide who becomes an administrator at an SSO login: the caller's OWN role must be admin.
[[nodiscard]] std::optional<WriteRefusal> write_refusal(const std::string& key,
                                                        const auth::Session& session);

/// Checks `value` for `key`. Integer-typed keys (`heartbeat_timeout`, `response_retention_days`,
/// `audit_retention_days`, `guardian_event_retention_days`) must be a non-negative integer; the
/// parsed number is returned for `write_and_apply`. Any other key returns 0 and accepts the
/// value (the store validates the rest). The error is operator-facing text.
[[nodiscard]] std::expected<int, std::string> validate_value(std::string_view key,
                                                             std::string_view value);

/// Why a write failed. `Rejected`: the store refused the value (a caller-input problem, 400);
/// the message is operator-written text. `StoreFault`: a database or crypto failure (503); the
/// message is generic and never carries the internal detail.
struct WriteFault {
    enum class Kind { Rejected, StoreFault };
    Kind kind;
    std::string message;
    /// The `detail` for the `failure` audit row. A store fault may have committed before the
    /// acknowledgement was lost, so it never claims "not applied".
    std::string audit_detail;
};

/// Persists `key=value` as `username`, then applies an integer key to the live `Config`
/// (`log_level` is applied inside `RuntimeConfigStore::set`). `parsed_int` is `validate_value`'s
/// result. The caller has already checked `store_ready`, `write_refusal` and the key.
[[nodiscard]] std::expected<void, WriteFault> write_and_apply(const Backing& b,
                                                              const std::string& key,
                                                              const std::string& value,
                                                              int parsed_int,
                                                              const std::string& username);

/// The `detail` of the `success` audit row. NOT the raw value for a secret key: an audit detail
/// is durable and readable by every role seeded AuditLog:Read.
[[nodiscard]] std::string success_audit_detail(const std::string& key, const std::string& value);

/// The body of a successful write. A secret key's value is never echoed.
[[nodiscard]] nlohmann::json applied_json(const std::string& key, const std::string& value);

/// Why a read failed: the store is not open or could not be read. A degraded store must NOT read
/// as "nothing is configured": the presence of a secret key and its `is_set` are how an operator
/// answers "is the OIDC secret set here?" before deciding whether to rotate a disclosed one.
struct ViewFault {};

/// The effective values, the stored overrides, `allowed_keys` and `read_only_keys` (the allowed
/// keys the generic write refuses because they have their own route).
///
/// `viewer` selects the audience. Null (the legacy `GET /api/config`, kept byte-identical) shows
/// every override to every caller that passed the `Infrastructure:Read` gate. A session (the v1
/// route and the MCP tool) is shown only the values it could WRITE: for every key
/// `write_refusal` would deny it, the stored override is dropped and, for `audit_retention_days`,
/// so is the effective value; the response then carries `withheld_keys`, the sorted keys withheld
/// from this caller, so a client can tell "not set" from "not shown to you". This keeps a
/// readonly-tier MCP token, which `tier_allows` bars from `OidcConfig:Read`, from reading the
/// `oidc_*` overrides (`oidc_admin_group` is authorization topology) through the generic view.
[[nodiscard]] std::expected<nlohmann::json, ViewFault> build_config_view(
    const Backing& b, const auth::Session* viewer = nullptr);

} // namespace yuzu::server::config
