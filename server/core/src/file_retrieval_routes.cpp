#include "file_retrieval_routes.hpp"

#include "body_cap_policy.hpp" // kBodyCapTable binding assert below
#include "evp_raii.hpp"
#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error — operator-route A4 envelope
#include "rest_audit.hpp" // detail::emit_behavioral_audit (Sec-Audit-Failed, #1647)
#include "upload_grant_parsers.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

// The pre-auth body cap for this surface lives in `kBodyCapTable`
// (body_cap_policy.hpp, the single per-route chokepoint — routed-concern
// #2407) — never a parallel pre-routing branch here. This assert binds the
// table row's cap to the protocol's own per-chunk maximum so the two cannot
// drift: a chunk the protocol admits must never be refused at the transport,
// and a body the transport admits must never exceed what the handler allows.
static_assert([] {
    for (const auto& e : kBodyCapTable)
        if (e.path_class == std::string_view{"upload_session"})
            return e.max_body_bytes ==
                   static_cast<std::size_t>(upload_grant::kDefaultChunkMaxBytes);
    return false; // no upload_session row at all — also a drift
}(), "kBodyCapTable's upload_session cap must equal upload_grant::kDefaultChunkMaxBytes");

namespace {

using upload_grant::Reason;

std::int64_t real_now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t resolve_now(const Deps& deps) {
    return deps.now_fn ? deps.now_fn() : real_now_epoch();
}

/// Generic (non-closed-set) error body for the operator routes and plain
/// input/availability failures — the frozen `reason` set (see
/// upload_grant_parsers.hpp) is scoped to the agent-facing grant/session
/// protocol; a mint-validation 400 or a 503 "database unavailable" is not
/// one of those ten outcomes, so it gets the standard A4 envelope
/// (`detail::a4_error`, `rest_a4_envelope_http.hpp`) rather than inventing
/// an eleventh reason — matching the repo-standard error shape used
/// everywhere else outside this protocol's ten reasons (e.g. auth_routes.cpp).
/// `send_reason`/`upload_grant::error_envelope` below is the DISTINCT, frozen
/// agent-facing wire shape and must NOT be folded into this helper.
void send_generic(httplib::Response& res, int status, const std::string& message) {
    res.status = status;
    res.set_content(detail::a4_error(res, message), "application/json");
}

void send_reason(httplib::Response& res, Reason r, const std::string& message,
                 const nlohmann::json& extra = nlohmann::json::object()) {
    res.status = upload_grant::reason_http_status(r);
    res.set_content(upload_grant::error_envelope(r, message, extra), "application/json");
}

/// Deployment-level TLS gate (see Deps::tls_enabled's doc comment for why
/// this is a plain bool, not a per-request probe). Applies to every AGENT
/// route (session open onward) — the operator mint/list/revoke routes sit
/// behind the ordinary auth session transport and are not gated here.
bool require_tls(const Deps& deps, httplib::Response& res) {
    if (deps.tls_enabled)
        return true;
    send_reason(res, Reason::kTlsRequired, "TLS is required for the upload transport");
    return false;
}

bool require_store(const Deps& deps, httplib::Response& res) {
    if (deps.store != nullptr)
        return true;
    send_generic(res, 503, "upload grant store unavailable");
    return false;
}

/// Fails CLOSED (403) when `deps.perm_fn` itself is unwired — an unset
/// `PermFn` must never read as "no gate configured, allow", the same
/// posture `require_tls`/`require_store` already take for their own
/// missing-dependency case.
bool require_permission(const Deps& deps, const httplib::Request& req, httplib::Response& res,
                        const std::string& securable_type, const std::string& operation) {
    if (!deps.perm_fn) {
        send_generic(res, 403, "permission denied");
        return false;
    }
    return deps.perm_fn(req, res, securable_type, operation); // perm_fn writes its own denial body
}

/// Route through the repo's shared behavioural-audit kernel (rest_audit.hpp,
/// #1647) rather than silently dropping a persist failure: a throwing or
/// false-returning `audit_fn` is logged and flips the `Sec-Audit-Failed`
/// response header, so a dropped audit row for a credential mint/redeem/
/// commit/cancel is visible on the wire, not invisible. These routes already
/// completed their state change before this call (mint/redeem/commit/cancel
/// are not re-orderable behind the audit write without a deeper store/route
/// redesign), so the response itself still reports the operation's own
/// outcome — the header is the failure signal, matching the established
/// "proceed, but flag" posture for state-already-changed operations.
void audit(const Deps& deps, const httplib::Request& req, httplib::Response& res,
          const std::string& action, const std::string& result, const std::string& target_id,
          const std::string& detail = {}) {
    (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, action, result, "UploadGrant",
                                        target_id, detail);
}

/// M9 (review finding): the `attempted` -> mutate -> `success`/`failure`
/// posture `plugin_config_routes.cpp`'s `audit_or_503`/`audit_outcome` pair
/// established for BR-006, applied here to `revoke` — the one upload-grant
/// mutation whose target_id (`grant_id`) is known from the URL BEFORE the
/// store call, exactly like a plugin-config delete. `mint` does NOT get
/// this treatment: its only real identity, the grant_id, is GENERATED by
/// the store and does not exist until after `mint()` returns, so there is
/// no request-derived target_id to record an `attempted` row against with
/// the same identity the eventual outcome row would use — inventing one
/// would desynchronize the two rows rather than pair them. Mint's existing
/// mutate-then-audit posture is deliberate and, on inspection, still
/// honest: unlike the pre-fix BR-006 defect it does not ever record
/// `success` before the mutation has actually happened — a dropped audit
/// write there is a MISSING row, never a FALSE one.
///
/// Fails CLOSED like the plugin-config original: refuses the mutation if
/// this row will not persist.
[[nodiscard]] bool audit_or_503(const Deps& deps, const httplib::Request& req,
                                httplib::Response& res, const std::string& action,
                                const std::string& target_id, const std::string& detail_str) {
    const bool persisted = detail::emit_behavioral_audit(deps.audit_fn, req, res, action,
                                                          "attempted", "UploadGrant", target_id,
                                                          detail_str);
    if (!persisted) {
        send_generic(res, 503,
                    "the audit record could not be persisted, so the operation was NOT "
                    "performed; retry once the audit store recovers");
        return false;
    }
    return true;
}

/// Pairs with `audit_or_503` above — records what the store ACTUALLY did,
/// after it answered. Deliberately not fail-closed (the mutation has
/// already happened by the time this runs) and deliberately
/// `[[nodiscard]]`-free, matching `plugin_config_routes.cpp`'s twin exactly.
void audit_outcome(const Deps& deps, const httplib::Request& req, httplib::Response& res,
                   const std::string& action, bool ok, const std::string& target_id,
                   const std::string& detail_str) {
    if (!detail::emit_behavioral_audit(deps.audit_fn, req, res, action, ok ? "success" : "failure",
                                       "UploadGrant", target_id, detail_str)) {
        spdlog::warn("upload_grant: {} outcome row ({}) could not be persisted for {}; the "
                     "'attempted' row stands and the outcome is unrecorded",
                     action, ok ? "success" : "failure", target_id);
    }
}

/// Extract a string field from a parsed JSON body, treating "wrong type" the
/// same as "missing" (empty). nlohmann's typed `.value(key, default)`
/// THROWS a `type_error` when the key is present with an incompatible type
/// rather than falling back to the default — an uncaught throw here would
/// escape as a 500 (or a torn connection, depending on httplib's exception
/// handling) instead of the frozen 400. Every mint/commit string field goes
/// through this so a malformed body always maps to a clean rejection.
std::string string_field(const nlohmann::json& body, const char* key) {
    auto it = body.find(key);
    if (it == body.end() || !it->is_string())
        return {};
    return it->get<std::string>();
}

/// Streaming SHA-256 over an already-written blob (never loads the whole
/// file into memory — 64 KiB read buffer). Computed FRESH at commit time by
/// reading the file back, rather than maintained as in-memory state across
/// the many separate chunk PUT requests that build the file — this store's
/// commit verification is therefore correct even across a server restart
/// mid-upload (the partial bytes on disk are the only durable truth; the
/// next chunk after a restart still checks start==recorded_offset against
/// the DB, and a restart mid-write cannot leave a false digest cached
/// anywhere since none is ever cached).
std::optional<std::string> compute_file_sha256_hex(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return std::nullopt;

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx)
        return std::nullopt;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        return std::nullopt;

    std::vector<char> buf(64 * 1024);
    bool ok = true;
    while (ok && f) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const auto got = f.gcount();
        if (got > 0 && EVP_DigestUpdate(ctx.get(), buf.data(), static_cast<std::size_t>(got)) != 1)
            ok = false;
    }
    if (f.bad())
        ok = false;

    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int out_len = 0;
    ok = ok && EVP_DigestFinal_ex(ctx.get(), digest, &out_len) == 1 &&
         out_len == SHA256_DIGEST_LENGTH;
    if (!ok)
        return std::nullopt;

    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char b : digest) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

/// Best-effort discard of a partial/failed blob. Never surfaced as an error
/// to the caller — a stray leftover file is a hygiene issue for a later
/// retention sweep, never a reason to fail the (already-failing) request
/// that triggered it — but a removal failure IS logged, so it is at least
/// operable (a silent leftover blob on a retention-sensitive class would
/// otherwise be invisible until someone goes looking for it).
void discard_blob(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::remove(path, ec) && ec)
        spdlog::warn("upload: failed to discard blob {}: {}", path.string(), ec.message());
}

/// Per-upload_id serialization for the chunk write critical section
/// (offset check -> file write -> offset CAS). The Postgres CAS on
/// `recorded_offset` makes the OFFSET TRANSITION itself race-safe, but the
/// file bytes are written to disk BEFORE that CAS — two same-process callers
/// racing the SAME upload_id at the same offset could both write the same
/// byte range and only one would win the CAS, leaving the persisted bytes
/// belonging to whichever wrote last, independent of the CAS winner
/// (`verify_commit`'s hash check is the safety net that catches this if it
/// ever happens). This lock closes that same-process race. Cross-process
/// concurrent chunk delivery for one upload_id — the frozen protocol assumes
/// a single-writer-per-session client, so this is a narrower residual gap,
/// not the common case — would need a distributed lock (a genuine
/// architecture decision, out of this package's scope).
///
/// The map is REFCOUNT-EVICTED rather than grow-only. It is a process-static
/// keyed by a client-supplied path segment, so a grow-only map is unbounded
/// memory reachable by anyone who can name well-formed upload ids — and the
/// natural lifetime of a slot is exactly "while someone holds it". `Guard`
/// below releases the mutex and then drops the map entry when this holder was
/// the last reference: `use_count() == 1` is evaluated under `map_mu_`, which
/// is the same lock `acquire` takes before handing a slot out, so no concurrent
/// acquirer can be mid-way between reading the slot and copying the
/// `shared_ptr` when the check runs.
class UploadWriteLocks {
public:
    /// RAII holder: unlocks, then evicts the map entry if nobody else holds it.
    class Guard {
    public:
        Guard(UploadWriteLocks& owner, std::string upload_id, std::shared_ptr<std::mutex> m)
            : owner_(&owner), upload_id_(std::move(upload_id)), m_(std::move(m)), lock_(*m_) {}
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
        Guard(Guard&&) = delete;
        Guard& operator=(Guard&&) = delete;
        ~Guard() {
            lock_.unlock();
            owner_->release(upload_id_, m_);
        }

    private:
        UploadWriteLocks* owner_;
        std::string upload_id_;
        std::shared_ptr<std::mutex> m_;
        std::unique_lock<std::mutex> lock_;
    };

    [[nodiscard]] Guard acquire(const std::string& upload_id) {
        std::shared_ptr<std::mutex> m;
        {
            std::lock_guard<std::mutex> g(map_mu_);
            auto& slot = locks_[upload_id];
            if (!slot)
                slot = std::make_shared<std::mutex>();
            m = slot;
        }
        return Guard(*this, upload_id, std::move(m));
    }

    [[nodiscard]] std::size_t size_for_test() {
        std::lock_guard<std::mutex> g(map_mu_);
        return locks_.size();
    }

private:
    void release(const std::string& upload_id, std::shared_ptr<std::mutex>& m) {
        std::lock_guard<std::mutex> g(map_mu_);
        auto it = locks_.find(upload_id);
        // The map holds one reference and this Guard holds the other, so a
        // use_count of 2 means no other holder or waiter exists. Compare the
        // stored pointer too: an erase-and-reinsert between this Guard's
        // acquire and its release would otherwise let it evict a slot that is
        // not the one it took.
        if (it != locks_.end() && it->second == m && m.use_count() == 2)
            locks_.erase(it);
        m.reset();
    }

    std::mutex map_mu_;
    std::unordered_map<std::string, std::shared_ptr<std::mutex>> locks_;
};

UploadWriteLocks& upload_write_locks() {
    static UploadWriteLocks locks;
    return locks;
}

nlohmann::json grant_row_json(const UploadGrantRow& g) {
    return {{"grant_id", g.grant_id},
           {"agent_id", g.agent_id},
           {"source_path", g.source_path},
           {"declared_max_size", g.declared_max_size},
           {"expected_sha256", g.expected_sha256},
           {"retention_class", g.retention_class},
           {"destination_key", g.destination_key},
           {"state", g.state},
           {"minted_by", g.minted_by},
           {"created_at", g.created_at},
           {"expires_at", g.expires_at}};
}

// ── Operator routes: mint / list / revoke ───────────────────────────────

void register_mint(HttpRouteSink& sink, Deps deps) {
    sink.Post("/api/v1/upload-grants", [deps](const httplib::Request& req, httplib::Response& res) {
        auto session = deps.auth_fn ? deps.auth_fn(req, res) : std::nullopt;
        if (!session)
            return; // auth_fn already wrote the 401
        if (!require_permission(deps, req, res, "UploadGrant", "Write"))
            return; // perm_fn (or the fail-closed default) already wrote the 403
        if (!require_store(deps, res))
            return;

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) {
            send_generic(res, 400, "invalid JSON body");
            return;
        }

        UploadGrantMintParams params;
        params.agent_id = string_field(body, "agent_id");
        params.source_path = string_field(body, "source_path");
        params.expected_sha256 = string_field(body, "expected_sha256");
        params.retention_class = string_field(body, "retention_class");
        params.minted_by = session->username;
        if (auto it = body.find("declared_max_size"); it != body.end() && it->is_number_integer())
            params.declared_max_size = it->get<std::int64_t>();
        if (auto it = body.find("ttl_secs"); it != body.end() && it->is_number_integer())
            params.requested_ttl_secs = it->get<std::int64_t>();

        // The MCP twin enforces `^[0-9a-f]{64}$` on this field through its
        // input schema; REST accepted anything and persisted it verbatim.
        // That is not cosmetic: a stored non-hash is non-empty, so
        // `verify_commit`'s grant-expected leg runs and can never match, and
        // a commit mismatch cancels the session and deletes the blob after
        // the grant is already redeemed — a typo at mint time silently
        // yields a grant that can never be used, with no retry. Mint is the
        // only point where the operator can still fix it.
        if (!upload_grant::is_valid_expected_sha256(params.expected_sha256)) {
            send_generic(res, 400,
                         "expected_sha256 must be 64 lowercase hex characters, or omitted");
            return;
        }

        const auto now = resolve_now(deps);
        auto minted = deps.store->mint(params, now);
        if (!minted) {
            audit(deps, req, res, "upload_grant.mint", "failure", params.agent_id,
                 minted.error().message);
            // Infrastructure/entropy failures are the SERVER's fault (503,
            // retryable); invalid input is the OPERATOR's (400) — collapsing
            // both onto 400 would make a transient DB outage look like a
            // non-retryable bad request.
            const int status = minted.error().kind == MintError::kUnavailable ? 503 : 400;
            send_generic(res, status, minted.error().message);
            return;
        }

        audit(deps, req, res, "upload_grant.mint", "success", minted->grant_id,
             "agent_id=" + params.agent_id);
        nlohmann::json out = {{"grant_id", minted->grant_id},
                              {"grant_secret", minted->grant_secret},
                              {"expires_at", minted->expires_at},
                              {"destination_key", minted->destination_key}};
        res.status = 201;
        res.set_content(out.dump(), "application/json");
    });
}

void register_list(HttpRouteSink& sink, Deps deps) {
    sink.Get("/api/v1/upload-grants", [deps](const httplib::Request& req, httplib::Response& res) {
        auto session = deps.auth_fn ? deps.auth_fn(req, res) : std::nullopt;
        if (!session)
            return;
        if (!require_store(deps, res))
            return;

        // UploadGrant:Read list-admit gate — routed through
        // RbacStore::authorize_list_read at the server.cpp wiring site
        // (ADR-0017), NOT a bare perm_fn check.
        UploadGrantListAuthorization authz =
            deps.list_read_fn ? deps.list_read_fn(session->username) : UploadGrantListAuthorization{};
        if (authz.decision == UploadGrantListDecision::kDenyAll) {
            send_generic(res, 403, "permission denied");
            return;
        }

        // No client-selected agent_id filter — the frozen protocol forbids
        // any client-supplied agent_id on this surface, on any path, ever.
        // Always list every admitted row and let the visibility loop below
        // (kAdmitScoped) do the actual confinement.
        auto rows = deps.store->list_for_agent();
        if (!rows) {
            send_generic(res, 503, rows.error());
            return;
        }

        nlohmann::json arr = nlohmann::json::array();
        for (const auto& g : *rows) {
            if (authz.decision == UploadGrantListDecision::kAdmitScoped &&
                std::find(authz.visible_agents.begin(), authz.visible_agents.end(), g.agent_id) ==
                    authz.visible_agents.end())
                continue;
            arr.push_back(grant_row_json(g));
        }
        nlohmann::json out = {{"data", arr}, {"meta", {{"api_version", "v1"}}}};
        res.set_content(out.dump(), "application/json");
    });
}

void register_revoke(HttpRouteSink& sink, Deps deps) {
    sink.Delete(R"(/api/v1/upload-grants/([a-f0-9]+))",
               [deps](const httplib::Request& req, httplib::Response& res) {
                   auto session = deps.auth_fn ? deps.auth_fn(req, res) : std::nullopt;
                   if (!session)
                       return;
                   if (!require_permission(deps, req, res, "UploadGrant", "Delete"))
                       return;
                   if (!require_store(deps, res))
                       return;

                   const auto grant_id = req.matches[1].str();
                   if (!audit_or_503(deps, req, res, "upload_grant.revoke", grant_id, ""))
                       return;
                   auto result = deps.store->revoke(grant_id);
                   if (!result) {
                       audit_outcome(deps, req, res, "upload_grant.revoke", /*ok=*/false, grant_id,
                                    result.error());
                       send_generic(res, 503, result.error());
                       return;
                   }
                   if (!*result) {
                       audit_outcome(deps, req, res, "upload_grant.revoke", /*ok=*/false, grant_id,
                                    "not found or not revocable");
                       send_generic(res, 404, "grant not found or not revocable");
                       return;
                   }
                   audit_outcome(deps, req, res, "upload_grant.revoke", /*ok=*/true, grant_id, "");
                   res.status = 204;
               });
}

// ── Agent routes: session open / chunk / status / commit / cancel ──────

/// Parse `X-Yuzu-Upload-Session: <upload_id>.<secret>` AND require the URL's
/// `{upload_id}` capture to match the credential's own id — a cheap
/// consistency check against a copy-paste/confused-deputy bug (the actual
/// authorization decision is the secret compare inside
/// `UploadGrantStore::authenticate_session`, not this match). A mismatch or
/// any grammar violation collapses to the same `session_unknown` the store
/// itself would report for an unknown id, per the wire-collapse rule.
std::optional<upload_grant::Credential> parse_session_credential(const httplib::Request& req,
                                                                  const std::string& url_upload_id) {
    auto cred = upload_grant::parse_credential(req.get_header_value("X-Yuzu-Upload-Session"));
    if (!cred || cred->id != url_upload_id)
        return std::nullopt;
    return cred;
}

/// Map a NON-`kOk` `SessionAuthOutcome` to its wire reason. Callers only
/// invoke this after already handling `kOk` themselves.
void send_session_auth_error(httplib::Response& res, SessionAuthOutcome outcome) {
    switch (outcome) {
    case SessionAuthOutcome::kSessionUnknown:
        send_reason(res, Reason::kSessionUnknown, "session unknown or invalid credential");
        return;
    case SessionAuthOutcome::kSessionTerminal:
        send_reason(res, Reason::kSessionTerminal, "session is already terminal");
        return;
    case SessionAuthOutcome::kExpired:
        send_reason(res, Reason::kExpired, "session expired");
        return;
    case SessionAuthOutcome::kOk:
    case SessionAuthOutcome::kUnavailable:
        send_generic(res, 503, "upload grant store unavailable");
        return;
    }
}

/// Admission gate run BEFORE `upload_write_locks().acquire(...)` on every
/// handler that takes the write lock. The lock map is keyed by a value the
/// CLIENT supplies, so acquiring first and authenticating second let an
/// unauthenticated caller both create map entries and contend the mutex a
/// legitimate uploader is using. Refcount eviction bounds the memory; this
/// bounds who can reach the lock at all.
///
/// M3 (review finding): admits ONLY on an outcome that proves a real
/// credential — `kOk`, `kExpired`, `kSessionTerminal`. `kSessionUnknown`
/// (collapsing "no such upload_id" and "the secret did not match") and
/// `kUnavailable` are BOTH refused here. An earlier revision of this gate
/// admitted on anything other than `kSessionUnknown`, reasoning that
/// `kUnavailable` was rare enough not to matter — but a degraded store is
/// exactly the condition under which admitting unproven credentials is
/// worst: every well-formed-but-unauthenticated (upload_id, secret) pair
/// would allocate/contend a lock AND drive a second authenticate call once
/// inside it, doubling load on a pool/query path that is already failing.
/// Refusing immediately here, before the lock is even touched, is the
/// correct fail-closed answer — the same posture `require_store` already
/// takes for a null store. The in-critical-section `authenticate_session`
/// remains the authoritative read for the three admitted outcomes: expiry
/// and terminal state carry mutations that must happen under the lock, and
/// `kOk` is re-validated there against the state the lock now protects.
[[nodiscard]] bool admit_to_write_lock(const Deps& deps, const std::string& upload_id,
                                       const std::string& secret, httplib::Response& res) {
    const auto outcome = deps.store->authenticate_session(upload_id, secret, resolve_now(deps)).outcome;
    switch (outcome) {
    case SessionAuthOutcome::kOk:
    case SessionAuthOutcome::kExpired:
    case SessionAuthOutcome::kSessionTerminal:
        return true;
    case SessionAuthOutcome::kSessionUnknown:
    case SessionAuthOutcome::kUnavailable:
        send_session_auth_error(res, outcome);
        return false;
    }
    // Exhaustive switch above covers every SessionAuthOutcome enumerator;
    // reachable only if the enum grows without this switch being updated —
    // fail closed rather than fall through with no response written.
    send_generic(res, 503, "upload grant store unavailable");
    return false;
}

void register_session_open(HttpRouteSink& sink, Deps deps) {
    sink.Post("/api/v1/uploads", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!require_tls(deps, res))
            return;
        if (!require_store(deps, res))
            return;

        auto cred = upload_grant::parse_credential(req.get_header_value("X-Yuzu-Upload-Grant"));
        if (!cred) {
            audit(deps, req, res, "upload_grant.session_open", "failure", "", "malformed credential");
            send_reason(res, Reason::kGrantUnknown, "invalid or missing grant credential");
            return;
        }

        const auto now = resolve_now(deps);
        auto opened = deps.store->open_session(cred->id, cred->secret, now);
        switch (opened.outcome) {
        case OpenSessionOutcome::kOpened: {
            audit(deps, req, res, "upload_grant.session_open", "success", cred->id,
                 "upload_id=" + opened.session.upload_id);
            nlohmann::json out = {{"upload_id", opened.session.upload_id},
                                  {"session_secret", opened.session.session_secret},
                                  {"chunk_max_bytes", opened.session.chunk_max_bytes},
                                  {"offset", opened.session.offset},
                                  {"expires_at", opened.session.expires_at}};
            res.status = 201;
            res.set_content(out.dump(), "application/json");
            return;
        }
        case OpenSessionOutcome::kGrantUnknown:
            audit(deps, req, res, "upload_grant.session_open", "failure", cred->id, "grant_unknown");
            send_reason(res, Reason::kGrantUnknown, "grant unknown or invalid credential");
            return;
        case OpenSessionOutcome::kAlreadyRedeemed:
            audit(deps, req, res, "upload_grant.session_open", "failure", cred->id,
                 "grant_already_redeemed");
            send_reason(res, Reason::kGrantAlreadyRedeemed, "grant already redeemed");
            return;
        case OpenSessionOutcome::kExpired:
            audit(deps, req, res, "upload_grant.session_open", "failure", cred->id, "expired");
            send_reason(res, Reason::kExpired, "grant expired");
            return;
        case OpenSessionOutcome::kUnavailable:
            send_generic(res, 503, "upload grant store unavailable");
            return;
        }
    });
}

void register_chunk(HttpRouteSink& sink, Deps deps) {
    sink.Put(R"(/api/v1/uploads/([a-f0-9]+)/chunk)",
            [deps](const httplib::Request& req, httplib::Response& res) {
                if (!require_tls(deps, res))
                    return;
                if (!require_store(deps, res))
                    return;

                const auto url_upload_id = req.matches[1].str();
                auto cred = parse_session_credential(req, url_upload_id);
                if (!cred) {
                    send_reason(res, Reason::kSessionUnknown, "session unknown or invalid credential");
                    return;
                }

                // Authenticate BEFORE touching the lock map — it is keyed by a
                // client-supplied path segment, so acquiring first would let an
                // unauthenticated caller create entries and contend a legitimate
                // uploader's mutex. The in-lock authenticate below stays the
                // authoritative read.
                if (!admit_to_write_lock(deps, url_upload_id, cred->secret, res))
                    return;

                // Serialize the whole write critical section (authenticate ->
                // offset check -> file write -> offset CAS) per upload_id —
                // see UploadWriteLocks' doc comment for why the DB CAS alone
                // does not make the FILE bytes race-safe.
                auto write_lock = upload_write_locks().acquire(url_upload_id);

                const auto now = resolve_now(deps);
                auto ar = deps.store->authenticate_session(url_upload_id, cred->secret, now);
                if (ar.outcome == SessionAuthOutcome::kExpired) {
                    // Frozen protocol: any request after expiry discards the
                    // partial and reports 410, even a chunk carrying valid
                    // bytes. Only discard the blob if THIS call actually won
                    // the expire_now transition (never on a store error, and
                    // never when a concurrent transition — e.g. a commit that
                    // beat this request — already terminated the session, so
                    // a blob it may now own is never deleted out from under
                    // it).
                    auto expired = deps.store->expire_now(url_upload_id);
                    if (expired && *expired)
                        discard_blob(deps.blob_root / ar.info.destination_key);
                    else if (!expired)
                        spdlog::warn("upload {}: expire_now failed: {}", url_upload_id,
                                    expired.error());
                    audit(deps, req, res, "upload_grant.chunk", "failure", url_upload_id, "expired");
                    send_reason(res, Reason::kExpired, "session expired");
                    return;
                }
                if (ar.outcome != SessionAuthOutcome::kOk) {
                    send_session_auth_error(res, ar.outcome);
                    return;
                }
                const auto& info = ar.info;

                auto cr = upload_grant::parse_content_range(req.get_header_value("Content-Range"));
                if (!cr) {
                    send_generic(res, 400, "missing or malformed Content-Range header");
                    return;
                }
                const auto chunk_len = upload_grant::content_range_length(*cr);

                const auto offset_check = upload_grant::check_offset(info.recorded_offset, cr->start);
                if (!offset_check.ok) {
                    send_reason(res, Reason::kOffsetMismatch, "offset mismatch",
                               {{"offset", offset_check.authoritative_offset}});
                    return;
                }
                if (upload_grant::chunk_exceeds_max(chunk_len, upload_grant::kDefaultChunkMaxBytes)) {
                    send_reason(res, Reason::kChunkTooLarge, "chunk exceeds the maximum chunk size");
                    return;
                }
                if (static_cast<std::int64_t>(req.body.size()) != chunk_len) {
                    send_generic(res, 400, "request body length does not match Content-Range");
                    return;
                }
                // The chunk's own asserted Content-Range total is a CAP
                // against the grant's declared size (never authoritative for
                // the cumulative-bytes gate below — see
                // `total_exceeds_declared`'s doc comment): a client cannot
                // assert a total the grant never admitted.
                const bool size_exceeded =
                    upload_grant::total_exceeds_declared(cr->total, info.declared_max_size) ||
                    upload_grant::cumulative_exceeds_declared(info.recorded_offset, chunk_len,
                                                               info.declared_max_size);
                if (size_exceeded) {
                    // terminates — partial discarded. Only discard the blob
                    // if this call actually won the cancel CAS: a concurrent
                    // commit that already terminated the session first must
                    // keep its blob (see the kExpired branch's comment
                    // above for the same reasoning); the chunk itself is
                    // rejected either way.
                    auto cancelled = deps.store->cancel_session(url_upload_id);
                    if (cancelled && *cancelled)
                        discard_blob(deps.blob_root / info.destination_key);
                    else if (!cancelled)
                        spdlog::warn("upload {}: cancel_session (size_exceeded) failed: {}",
                                    url_upload_id, cancelled.error());
                    audit(deps, req, res, "upload_grant.chunk", "failure", url_upload_id,
                         "size_exceeded");
                    send_reason(res, Reason::kSizeExceeded, "upload exceeds the grant's declared size");
                    return;
                }

                // Path computed ONCE, from server-side facts only
                // (info.destination_key — never anything client-supplied),
                // and never re-resolved between here and the write below.
                const auto path = deps.blob_root / info.destination_key;
                std::error_code ec;
                std::filesystem::create_directories(path.parent_path(), ec);

                // The destination is opened EXACTLY ONCE for this chunk and
                // every byte streams through this SAME RAII handle — no
                // separate seek-probe-then-write pair, no second path
                // lookup between the open below and the write that follows it.
                std::fstream f;
                if (cr->start == 0)
                    f.open(path, std::ios::binary | std::ios::out | std::ios::trunc);
                else
                    f.open(path, std::ios::binary | std::ios::in | std::ios::out);
                if (!f.is_open()) {
                    send_generic(res, 500, "failed to open upload destination");
                    return;
                }
                f.seekp(cr->start, std::ios::beg);
                f.write(req.body.data(), static_cast<std::streamsize>(req.body.size()));
                const bool write_ok = f.good();
                f.close();
                if (!write_ok) {
                    send_generic(res, 500, "failed to write chunk");
                    return;
                }

                const auto new_offset = info.recorded_offset + chunk_len;
                auto advanced = deps.store->advance_offset(url_upload_id, info.recorded_offset,
                                                            new_offset);
                if (!advanced) {
                    send_generic(res, 503, advanced.error());
                    return;
                }
                if (!*advanced) {
                    // CAS missed — a concurrent chunk (or a state change) already
                    // moved past what we validated against. Re-authenticate to
                    // report the CURRENT authoritative state rather than assert
                    // a success this call did not actually win.
                    auto recheck = deps.store->authenticate_session(url_upload_id, cred->secret, now);
                    if (recheck.outcome == SessionAuthOutcome::kOk) {
                        send_reason(res, Reason::kOffsetMismatch, "offset mismatch",
                                   {{"offset", recheck.info.recorded_offset}});
                    } else {
                        send_session_auth_error(res, recheck.outcome);
                    }
                    return;
                }

                nlohmann::json out = {{"offset", new_offset}};
                res.status = 200;
                res.set_content(out.dump(), "application/json");
            });
}

void register_status(HttpRouteSink& sink, Deps deps) {
    sink.Get(R"(/api/v1/uploads/([a-f0-9]+))",
            [deps](const httplib::Request& req, httplib::Response& res) {
                if (!require_tls(deps, res))
                    return;
                if (!require_store(deps, res))
                    return;

                const auto url_upload_id = req.matches[1].str();
                auto cred = parse_session_credential(req, url_upload_id);
                if (!cred) {
                    send_reason(res, Reason::kSessionUnknown, "session unknown or invalid credential");
                    return;
                }

                // Review finding (#3135): this handler used to call
                // authenticate_session directly, with no
                // upload_write_locks().acquire(...) anywhere in the
                // function — the sole exception among the four handlers
                // that can reach expire_now+discard_blob. A concurrent
                // chunk write in flight on a session whose expires_at has
                // just passed could have its partial blob unlinked out
                // from under it by a racing status poll. Same admission +
                // lock + re-authenticate-in-critical-section shape as
                // register_chunk/register_commit/register_cancel now.
                if (!admit_to_write_lock(deps, url_upload_id, cred->secret, res))
                    return;

                auto write_lock = upload_write_locks().acquire(url_upload_id);

                const auto now = resolve_now(deps);
                auto ar = deps.store->authenticate_session(url_upload_id, cred->secret, now);
                switch (ar.outcome) {
                case SessionAuthOutcome::kOk:
                case SessionAuthOutcome::kSessionTerminal: {
                    nlohmann::json out = {{"state", ar.info.state},
                                          {"offset", ar.info.recorded_offset},
                                          {"expires_at", ar.info.expires_at}};
                    res.set_content(out.dump(), "application/json");
                    return;
                }
                case SessionAuthOutcome::kExpired: {
                    // Frozen protocol (ADR-3004): any touch after expiry discards
                    // the partial and reports 410 — INCLUDING this read-only
                    // status poll. It is tempting to reason that a pure status
                    // read never wrote the blob so has nothing to discard, and
                    // that was this branch's original comment; it is wrong.
                    // `expire_now` transitions the session to `expired`, so if
                    // the status poll is the FIRST touch after expiry, no later
                    // request ever reaches an expiry arm again — chunk, commit
                    // and cancel all fail earlier on the terminal state. The
                    // partial would then be orphaned on disk permanently, and
                    // there is no sweep to collect it. Discard on the same
                    // condition the other three expiry handlers use — now
                    // under the SAME write lock those three take, so this
                    // discard cannot race a concurrent chunk write.
                    auto expired = deps.store->expire_now(url_upload_id);
                    if (expired && *expired)
                        discard_blob(deps.blob_root / ar.info.destination_key);
                    else if (!expired)
                        spdlog::warn("upload {}: expire_now (status) failed: {}", url_upload_id,
                                    expired.error());
                    send_reason(res, Reason::kExpired, "session expired");
                    return;
                }
                case SessionAuthOutcome::kSessionUnknown:
                case SessionAuthOutcome::kUnavailable:
                    send_session_auth_error(res, ar.outcome);
                    return;
                }
            });
}

void register_commit(HttpRouteSink& sink, Deps deps) {
    sink.Post(R"(/api/v1/uploads/([a-f0-9]+)/commit)",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!require_tls(deps, res))
                     return;
                 if (!require_store(deps, res))
                     return;

                 const auto url_upload_id = req.matches[1].str();
                 auto cred = parse_session_credential(req, url_upload_id);
                 if (!cred) {
                     send_reason(res, Reason::kSessionUnknown,
                                "session unknown or invalid credential");
                     return;
                 }

                 // Authenticate BEFORE touching the lock map — it is keyed by a
                 // client-supplied path segment, so acquiring first would let an
                 // unauthenticated caller create entries and contend a legitimate
                 // uploader's mutex. The in-lock authenticate below stays the
                 // authoritative read.
                 if (!admit_to_write_lock(deps, url_upload_id, cred->secret, res))
                     return;

                 // Same per-upload serialization as the chunk route — commit
                 // reads the blob back (compute_file_sha256_hex), which must
                 // never race an in-flight chunk write for the same upload.
                 auto write_lock = upload_write_locks().acquire(url_upload_id);

                 const auto now = resolve_now(deps);
                 auto ar = deps.store->authenticate_session(url_upload_id, cred->secret, now);
                 if (ar.outcome == SessionAuthOutcome::kExpired) {
                     auto expired = deps.store->expire_now(url_upload_id);
                     if (expired && *expired)
                         discard_blob(deps.blob_root / ar.info.destination_key);
                     else if (!expired)
                         spdlog::warn("upload {}: expire_now (commit) failed: {}", url_upload_id,
                                     expired.error());
                     audit(deps, req, res, "upload_grant.commit", "failure", url_upload_id,
                          "expired");
                     send_reason(res, Reason::kExpired, "session expired");
                     return;
                 }
                 if (ar.outcome != SessionAuthOutcome::kOk) {
                     send_session_auth_error(res, ar.outcome);
                     return;
                 }
                 const auto& info = ar.info;

                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 const std::string client_sha256 =
                     (!body.is_discarded() && body.is_object()) ? string_field(body, "sha256") : "";
                 if (client_sha256.empty()) {
                     send_generic(res, 400, "sha256 is required");
                     return;
                 }

                 const auto path = deps.blob_root / info.destination_key;
                 std::error_code ec;
                 const auto actual_size =
                     static_cast<std::int64_t>(std::filesystem::file_size(path, ec));
                 auto computed = ec ? std::nullopt : compute_file_sha256_hex(path);
                 if (!computed) {
                     send_generic(res, 500, "failed to verify uploaded blob");
                     return;
                 }

                 const auto check = upload_grant::verify_commit(
                     actual_size, info.declared_max_size, *computed, client_sha256,
                     info.expected_sha256);
                 if (check == upload_grant::CommitCheck::kMismatch) {
                     // Attempt the terminal transition FIRST and check whether
                     // THIS call actually won it before touching the blob — a
                     // concurrent commit that already succeeded must keep its
                     // blob; deleting it here (as the original ordering did)
                     // would destroy a file a completed_uploads row now
                     // references.
                     auto cancelled = deps.store->cancel_session(url_upload_id);
                     if (!cancelled) {
                         send_generic(res, 503, cancelled.error());
                         return;
                     }
                     if (!*cancelled) {
                         // Lost the CAS — some other transition already
                         // terminated this session (most likely a concurrent
                         // commit). Report the CURRENT authoritative state
                         // instead of asserting our own hash_mismatch.
                         auto recheck =
                             deps.store->authenticate_session(url_upload_id, cred->secret, now);
                         send_session_auth_error(
                             res, recheck.outcome == SessionAuthOutcome::kOk
                                      ? SessionAuthOutcome::kSessionTerminal
                                      : recheck.outcome);
                         return;
                     }
                     discard_blob(path);
                     audit(deps, req, res, "upload_grant.commit", "failure", url_upload_id,
                          "hash_mismatch");
                     send_reason(res, Reason::kHashMismatch, "commit verification failed");
                     return;
                 }

                 auto committed = deps.store->commit_session(url_upload_id, actual_size, *computed,
                                                              now);
                 if (!committed) {
                     send_generic(res, 503, committed.error());
                     return;
                 }
                 if (!*committed) {
                     auto recheck = deps.store->authenticate_session(url_upload_id, cred->secret, now);
                     send_session_auth_error(
                         res, recheck.outcome == SessionAuthOutcome::kOk
                                  ? SessionAuthOutcome::kSessionTerminal
                                  : recheck.outcome);
                     return;
                 }

                 audit(deps, req, res, "upload_grant.commit", "success", url_upload_id,
                      "size=" + std::to_string(actual_size));
                 nlohmann::json out = {
                     {"state", "committed"}, {"actual_size", actual_size}, {"sha256", *computed}};
                 res.set_content(out.dump(), "application/json");
             });
}

void register_cancel(HttpRouteSink& sink, Deps deps) {
    sink.Delete(R"(/api/v1/uploads/([a-f0-9]+))",
               [deps](const httplib::Request& req, httplib::Response& res) {
                   if (!require_tls(deps, res))
                       return;
                   if (!require_store(deps, res))
                       return;

                   const auto url_upload_id = req.matches[1].str();
                   auto cred = parse_session_credential(req, url_upload_id);
                   if (!cred) {
                       send_reason(res, Reason::kSessionUnknown,
                                  "session unknown or invalid credential");
                       return;
                   }

                   // Authenticate BEFORE touching the lock map — it is keyed by a
                   // client-supplied path segment, so acquiring first would let an
                   // unauthenticated caller create entries and contend a legitimate
                   // uploader's mutex. The in-lock authenticate below stays the
                   // authoritative read.
                   if (!admit_to_write_lock(deps, url_upload_id, cred->secret, res))
                       return;

                   // Same per-upload serialization as chunk/commit — cancel
                   // must never discard a blob a concurrent in-flight chunk
                   // write (or commit) still owns.
                   auto write_lock = upload_write_locks().acquire(url_upload_id);

                   const auto now = resolve_now(deps);
                   auto ar = deps.store->authenticate_session(url_upload_id, cred->secret, now);
                   if (ar.outcome == SessionAuthOutcome::kExpired) {
                       auto expired = deps.store->expire_now(url_upload_id);
                       if (expired && *expired)
                           discard_blob(deps.blob_root / ar.info.destination_key);
                       else if (!expired)
                           spdlog::warn("upload {}: expire_now (cancel) failed: {}", url_upload_id,
                                       expired.error());
                       audit(deps, req, res, "upload_grant.cancel", "failure", url_upload_id,
                            "expired");
                       send_reason(res, Reason::kExpired, "session expired");
                       return;
                   }
                   if (ar.outcome != SessionAuthOutcome::kOk) {
                       send_session_auth_error(res, ar.outcome);
                       return;
                   }

                   // Attempt the terminal transition FIRST — only discard the
                   // blob once THIS call has actually won the CAS, so a
                   // concurrent transition (e.g. a commit that beat this
                   // cancel) never has its blob deleted out from under it.
                   auto cancelled = deps.store->cancel_session(url_upload_id);
                   if (!cancelled) {
                       send_generic(res, 503, cancelled.error());
                       return;
                   }
                   if (!*cancelled) {
                       send_reason(res, Reason::kSessionTerminal, "session is already terminal");
                       return;
                   }
                   discard_blob(deps.blob_root / ar.info.destination_key);

                   audit(deps, req, res, "upload_grant.cancel", "success", url_upload_id, "");
                   res.status = 204;
               });
}

} // namespace

void register_file_retrieval_routes(HttpRouteSink& sink, Deps deps) {
    register_mint(sink, deps);
    register_list(sink, deps);
    register_revoke(sink, deps);
    register_session_open(sink, deps);
    register_chunk(sink, deps);
    register_status(sink, deps);
    register_commit(sink, deps);
    register_cancel(sink, deps);
}

std::size_t upload_write_lock_count_for_test() { return upload_write_locks().size_for_test(); }

} // namespace yuzu::server
