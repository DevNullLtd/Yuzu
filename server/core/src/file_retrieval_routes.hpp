#pragma once

/// @file file_retrieval_routes.hpp
/// REST surface for the PR1.6a one-time upload grant + authenticated
/// chunked receive protocol (CC-06 server-side fix). See
/// `upload_grant_parsers.hpp`'s file header for the frozen wire protocol
/// this implements verbatim, and `docs/adr/3004-artifact-blob-storage.md`
/// for the design rationale.
///
/// Two trust domains on one surface:
///   * Operator routes (mint/list/revoke) — `AuthFn`/`PermFn`-gated exactly
///     like every other REST securable (`UploadGrant:Write/Read/Delete`).
///   * Agent routes (session open/chunk/status/commit/cancel) — there is NO
///     authenticated agent REST transport (see the parsers header's WHY THE
///     DESIGN CHANGED note), so these gate on the grant/session BEARER
///     CREDENTIAL alone, never `AuthFn`/`PermFn`. `Deps` therefore carries
///     NO agent-identity resolver — agent identity is a server-side fact
///     recorded on the grant row at mint time and never asserted by the
///     client on any of these five routes.
///
/// `Deps` intentionally has no `RbacStore*`/`ManagementGroupStore*` member:
/// `list_read_fn` decouples this header from those stores exactly the way
/// `DexRoutes::VisibleSetFn` does (dex_routes.hpp) — the caller wires it to
/// `RbacStore::authorize_list_read` in server.cpp; this header only needs
/// the resulting 3-way decision shape.

#include "upload_grant_store.hpp"

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// Mirrors `RbacStore::ListReadDecision` (rbac_store.hpp) without including
/// that header — see the file-header note on why this surface stays
/// decoupled from RbacStore/ManagementGroupStore.
enum class UploadGrantListDecision {
    kDenyAll,     ///< no grant anywhere — 403
    kAdmitAll,    ///< global UploadGrant:Read, or RBAC disabled — unfiltered list
    kAdmitScoped, ///< management-group-confined — list ONLY visible_agents
};

struct UploadGrantListAuthorization {
    UploadGrantListDecision decision{UploadGrantListDecision::kDenyAll}; // fail-closed default
    std::vector<std::string> visible_agents; ///< engaged only for kAdmitScoped
};

/// Dependencies for `register_file_retrieval_routes`. Passed by value (small
/// struct of pointers/functions) — same "one Deps, both overloads/callers
/// take it by value" shape `WorkflowRoutes::Deps` established
/// (workflow_routes.hpp).
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// `UploadGrant:Read` list-admit resolver (ADR-0017) — routes the
    /// `GET /api/v1/upload-grants` list handler through
    /// `RbacStore::authorize_list_read` at the server.cpp call site. Unlike
    /// `AuthFn`/`PermFn` this does NOT take (and must NOT write to) the
    /// response — it is a pure resolve, the SAME shape as
    /// `DexRoutes::VisibleSetFn` (dex_routes.hpp); the route itself is the
    /// only thing that turns `kDenyAll` into the actual 403 body. Unwired
    /// (empty) fails closed (`kDenyAll`).
    using ListReadFn = std::function<UploadGrantListAuthorization(const std::string& username)>;
    /// Same shape as `DexRoutes::AuditFn` (dex_routes.hpp) — bool-returning
    /// so a dropped audit row is visible to the caller, not silently eaten.
    /// Called on every state-changing operator AND agent transition (mint,
    /// revoke, session-open success/failure, commit success/failure,
    /// cancel) — deliberately NOT on every chunk PUT (the per-chunk volume
    /// would make the audit log noise, not signal; the session-open and
    /// commit/cancel rows already bracket every upload's lifecycle).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Injectable clock (epoch seconds) — every expiry/redemption decision
    /// in `upload_grant_parsers.hpp` takes `now` explicitly; this is the
    /// ONE place production code reads the wall clock, so a test can pin
    /// it. Empty (the production default) reads `system_clock::now()`.
    using ClockFn = std::function<std::int64_t()>;

    AuthFn auth_fn;
    PermFn perm_fn;
    ListReadFn list_read_fn;
    AuditFn audit_fn;
    UploadGrantStore* store{nullptr};

    /// Root directory blobs are written under; a committed upload lands at
    /// `blob_root / destination_key` (destination_key is server-derived
    /// ONLY — see `upload_grant::derive_destination_key`). server.cpp wires
    /// this from `cfg_.db_dir() / "upload-blobs"` or equivalent — this
    /// header takes no position on the exact path, only that it is a
    /// directory the server process can write.
    std::filesystem::path blob_root;

    /// Deployment-level fact (mirrors `cfg_.https_enabled`): the server
    /// picks ONE listener mode (HTTP or HTTPS) for its whole process
    /// lifetime (server.cpp `start_web_server`), so this is a plain bool
    /// set once at wiring time, not a per-request probe — the vendored
    /// httplib here exposes no `Request::is_secure` to check per-connection
    /// even if it were meaningful to. `false` -> every agent route (session
    /// open onward — TLS is REQUIRED there, not on the operator mint/list/
    /// revoke routes, which already sit behind the standard auth session
    /// cookie/token transport) returns 400 tls_required.
    bool tls_enabled{false};

    ClockFn now_fn;
};

/// Register the upload-grant + chunked-receive REST surface. A free
/// function (not a class method) — the frozen deliverable signature;
/// server.cpp constructs one `Deps` and calls this once.
void register_file_retrieval_routes(HttpRouteSink& sink, Deps deps);

/// Live entry count of the process-static per-upload write-lock map.
///
/// A test seam, and deliberately the only window onto that map: the map is
/// keyed by a client-supplied path segment, so "does an unauthenticated
/// request leave an entry behind" is a property no route response can
/// express — the request is rejected either way, and only the map size
/// distinguishes a bounded implementation from an unbounded one. Read-only
/// and side-effect-free, so exposing it costs production nothing.
[[nodiscard]] std::size_t upload_write_lock_count_for_test();

} // namespace yuzu::server
