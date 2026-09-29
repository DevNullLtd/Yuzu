#pragma once

/// @file ca_routes.hpp
/// Internal-CA REST surface (PKI PR4): `/api/v1/ca/*`.
///
/// - `GET  /api/v1/ca/root`   — PUBLIC. The CA root certificate (PEM). Clients
///   and browsers need it to trust the install; it is public by definition.
/// - `GET  /api/v1/ca/crl`    — PUBLIC. The current CRL (DER). Revocation
///   distribution must be reachable by every client.
/// - `GET  /api/v1/ca/issued` — `Security:Read`. Issued-cert inventory (JSON).
/// - `POST /api/v1/ca/revoke` — `Security:Delete`. Revoke a serial; republishes
///   the CRL.
/// - `POST /api/v1/ca/issue-code-signing` — `Security:Write`. Code-signing leaf
///   issuance (gap-matrix #10) via CSR custody: the operator holds the private
///   key and submits a CSR; the server returns only the signed leaf + chain.
///   See `IssueCodeSigningFn`/`CodeSigningIssuance` below for the full contract.
///
/// `POST /api/v1/ca/issue` (general operator-chosen-CN signing, ANY EKU) is
/// deliberately STILL NOT exposed: an operator-issued CLIENT-auth leaf whose CN
/// collides with an agent_id could impersonate that agent at the #1118 identity
/// gate, so a general client/server-auth issue route remains a tracked
/// follow-up. `POST /api/v1/ca/issue-code-signing` sidesteps that risk for ONE
/// narrow, non-agent-impersonating case ONLY: usage is HARD-PINNED to
/// `pki::LeafUsage{.code_signing=true}` (the mTLS SSL_CLIENT purpose check
/// rejects a codeSigning-only leaf, so it can never reach the agent-identity
/// gate), the subject CN is the operator's own `label` — never an agent-style
/// `yuzu://…/agent/…` URI SAN, and `label` is strictly validated
/// (`is_valid_code_signing_label`, `^[A-Za-z0-9._-]{1,64}$`).
///
/// The crypto (CRL build, CA-key access) is injected as a callback so this module
/// links no `x509_ca`/`key_provider`; it only reads `CaStore` + calls back.

#include <yuzu/server/auth.hpp>

#include "ca_store.hpp"
#include "http_route_sink.hpp"

#include <httplib.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// Strict validator for the code-signing `label` (used verbatim as the issued
/// leaf's subject CN). `^[A-Za-z0-9._-]{1,64}$` — no whitespace or DN
/// metacharacters. This is defense-in-depth, NOT the primary control against
/// #1118 agent impersonation: the actual control is that this leaf's usage is
/// hard-pinned to `codeSigning`-only (rejected outright by the mTLS
/// `SSL_CLIENT` purpose check, so it can never reach the agent-identity gate
/// regardless of its CN) and its SAN is left empty — never an agent-style
/// `yuzu://…/agent/…` URI SAN (see this header's file comment). The regex
/// only keeps the CN itself well-formed and unambiguous. Pure / no crypto dep
/// so the REST route (ca_routes.cpp) and ServerImpl's defense-in-depth
/// re-check (server.cpp, where the value is actually placed in the
/// certificate) share exactly one definition rather than two
/// hand-kept-in-sync regexes.
[[nodiscard]] constexpr bool is_valid_code_signing_label(std::string_view label) noexcept {
    if (label.empty() || label.size() > 64)
        return false;
    for (char c : label) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

/// Derives the `ca.cert.*` audit `target_type` from a serial's OWN recorded
/// `IssuedCertRecord::purpose` — "agent" -> "AgentCertificate", "code-signing"
/// -> "CodeSigningCertificate", anything else (including a genuine store-read
/// failure or an unknown serial — those are already carried by the caller's
/// own outcome classification, e.g. `RevokeOutcome::StoreError`/`NotFound`)
/// falls back to the neutral "Certificate". Pure / no crypto dep, so the REST
/// revoke path (`ca_routes.cpp`'s `revoke_core`) and the MCP `revoke_certificate`
/// handler (`mcp_server.cpp`) share exactly ONE definition rather than two
/// hand-kept-in-sync copies — mirrors `is_valid_code_signing_label` above.
/// Before this helper existed, the MCP path hardcoded "AgentCertificate" and
/// durably mis-audited every code-signing revocation (gov HIGH-1).
[[nodiscard]] std::string derive_cert_audit_target_type(CaStore& ca_store,
                                                        const std::string& serial_hex);

/// Prefix on `IssueCodeSigningFn`'s `unexpected()` when the failure is a
/// caller-attributable business refusal — no CA root to issue from — rather
/// than a genuine crypto/store failure. The REST handler maps this to 409 +
/// audit result="denied" (mirrors `CaRoutes::ImportOutcome::NoRoot`'s
/// classification for the sibling subordinate-CA import surface). Any OTHER
/// `unexpected()` string not carrying `kCodeSigningBadCsrPrefix` either is a
/// genuine 5xx failure (key-load failure, `sign_csr` internal error,
/// `record_issued` store failure) — result="failure".
inline constexpr const char* kCodeSigningNoRootPrefix = "no_root: ";

/// Prefix when the operator-submitted CSR itself is the problem — oversize,
/// unparseable, or fails `pki::sign_csr`'s own proof-of-possession check.
/// Caller-attributable, mapped to 400 + audit result="denied".
inline constexpr const char* kCodeSigningBadCsrPrefix = "bad_csr: ";

/// gov B1: the CSR's subject public key fails
/// `pki::subject_key_meets_code_signing_floor` (sub-2048-bit RSA, an
/// unapproved EC curve, or an unrecognised key type) — a DISTINCT refusal
/// from `kCodeSigningBadCsrPrefix` so the caller sees "signing key too weak",
/// never the generic "csr_pem invalid" message. Caller-attributable, mapped
/// to 400 + audit result="denied".
inline constexpr const char* kCodeSigningWeakKeyPrefix = "weak_key: ";

/// gov F6/UP-5/UP-7: the requested `validity_days` is out of range, or the CA
/// itself is at/past expiry so no positive validity window can be computed —
/// a business refusal, NOT a malformed CSR. Caller-attributable, mapped to
/// 400 + audit result="denied". The text after the prefix is already
/// caller-safe and is surfaced verbatim by the REST/MCP handlers.
inline constexpr const char* kCodeSigningBadValidityPrefix = "bad_validity: ";

/// Result of a successful code-signing leaf issuance (gap-matrix #10). The
/// CSR-custody model: the operator holds the private key, the server never
/// sees it. `chain_pem` is the issuer chain the operator needs to build an
/// `openssl cms -sign -certfile` bundle (the issuing cert plus, in
/// subordinate/imported-chain mode, the parent chain above it).
struct CodeSigningIssuance {
    std::string certificate_pem;
    std::string chain_pem;
    std::string serial_hex;
    std::string not_after; ///< RFC 3339 / ISO 8601 UTC.
};

/// Sign a code-signing leaf from an operator-submitted CSR. Implemented by
/// ServerImpl (holds the CA key). Usage is HARD-PINNED to
/// `pki::LeafUsage{.code_signing=true}` and the subject CN is `label` — see
/// this header's file comment for why that combination is safe to expose
/// without the #1118 agent-impersonation risk. `unexpected()` carries a
/// caller-safe reason string (never raw DB/PQerrorMessage text) classified by
/// the two prefixes above for the REST handler's status/audit mapping.
using IssueCodeSigningFn = std::function<std::expected<CodeSigningIssuance, std::string>(
    const std::string& csr_pem, const std::string& label, std::optional<int> validity_days,
    const std::string& issued_by)>;

class CaRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    // Returns false if the audit row could not be persisted (caller surfaces the
    // evidence-chain gap via `Sec-Audit-Failed`). Matches the canonical
    // bool-returning audit contract used across the other route modules so a
    // privileged revoke can observe an audit-persistence failure (#1240).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Build (and record a new version of) the current CRL over all revoked
    /// serials, signed by the CA. Returns the DER, or nullopt on failure / no CA.
    /// Implemented by ServerImpl (which holds the CA key); keeps this module free
    /// of crypto deps.
    using PublishCrlFn = std::function<std::optional<std::vector<std::uint8_t>>()>;

    // ── Subordinate-CA (PR6) ──────────────────────────────────────────────────

    /// Export the install CA's CSR (PKCS#10 PEM) over its EXISTING key, for an
    /// enterprise root to sign into a subordinate-CA intermediate. nullopt on no
    /// CA / key-load failure. Implemented by ServerImpl (holds the CA key).
    using ExportCsrFn = std::function<std::optional<std::string>()>;

    /// Outcome of an import-chain attempt. The handler maps these to HTTP status
    /// + audit detail; the ServerImpl impl performs the crypto validation and the
    /// `set_root` swap.
    enum class ImportOutcome {
        Ok,              ///< Validated + issuing identity switched to subordinate.
        NoRoot,          ///< No existing CA to subordinate (generate defaults first).
        BadIntermediate, ///< Intermediate PEM unparseable.
        NotCa,           ///< Intermediate lacks basicConstraints CA:TRUE.
        KeyMismatch,     ///< Intermediate does not carry OUR CA public key.
        ChainInvalid,    ///< Intermediate does not verify to the uploaded parent chain.
        StoreError,      ///< Validated but persistence (set_root) failed.
    };

    /// Validate an enterprise-signed intermediate (carries our key + is a CA +
    /// chains to `parent_chain_pem`) and, on success, switch the issuing identity
    /// to subordinate mode. Implemented by ServerImpl (holds the CA key + dir).
    using ImportChainFn = std::function<ImportOutcome(const std::string& intermediate_pem,
                                                      const std::string& parent_chain_pem)>;

    /// Production overload — wraps `svr` in an HttplibRouteSink and delegates.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         CaStore* ca_store, PublishCrlFn publish_crl_fn,
                         ExportCsrFn export_csr_fn = {}, ImportChainFn import_chain_fn = {},
                         IssueCodeSigningFn issue_code_signing_fn = {});

    /// Testable overload — register against an in-process sink (no socket).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         CaStore* ca_store, PublishCrlFn publish_crl_fn,
                         ExportCsrFn export_csr_fn = {}, ImportChainFn import_chain_fn = {},
                         IssueCodeSigningFn issue_code_signing_fn = {});

    /// Operator-declared external origins for the CSRF same-site gate (#2537),
    /// already normalised by `normalise_trusted_origins` at boot. Set BEFORE
    /// `register_routes` — the handlers capture `this` and read the member per
    /// request, so a later call would not reach an already-registered route.
    ///
    /// A setter rather than another `register_routes` parameter because both
    /// overloads are already long, and because the miss-case is safe: leaving it
    /// unset means same-host only, which is the pre-#2537 behaviour and refuses a
    /// proxied browser POST. Forgetting degrades to fail-closed.
    void set_csrf_trusted_origins(std::vector<std::string> origins) {
        csrf_trusted_origins_ = std::move(origins);
    }

private:
    std::vector<std::string> csrf_trusted_origins_;
};

} // namespace yuzu::server
