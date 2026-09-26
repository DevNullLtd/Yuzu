#include "agent_registry.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "custom_properties_store.hpp"
#include "dex_perf_rules.hpp"
#include "guardian_health_fleet_tags.hpp" // Guardian M1 health-stream fleet telemetry table (#2298 gate 3, item 6d)
#include "guardian_arm_fleet_tags.hpp" // Guardian arm-ledger fleet telemetry table (rung 9c PR-3)
#include "guardian_io_ceiling_fleet_tags.hpp" // Guardian io-ceiling fleet telemetry table (rung 9c PR-3)
#include "guardian_journal_fleet_tags.hpp" // Guardian journal fleet telemetry table (#2298 gate 3)
#include "network_perf_rules.hpp"
#include "offline_endpoint_store.hpp" // HA WS-5 presence merge (ADR-2002 §7a)
#include "spark_fleet_tags.hpp" // SparkEngine fleet telemetry keys + count parse (rung 1)
#include "result_set_store.hpp"
#include "device_token_store.hpp"
#include "service_scope_policy.hpp" // authz::is_service_tag_key — #3295
#include "tag_store.hpp"
#include "web_utils.hpp"

namespace yuzu::server::detail {

// Bring html_escape into scope for the HTML rendering methods.
using yuzu::server::html_escape;

// -- AgentRegistry ------------------------------------------------------------

AgentRegistry::AgentRegistry(EventBus& bus, yuzu::MetricsRegistry& metrics)
    : bus_(bus), metrics_(metrics) {}

void AgentRegistry::set_device_token_store(DeviceTokenStore* store) {
    // Take mu_ so a concurrent register_agent cannot observe a half-written
    // pointer. In practice this setter is called once during startup wiring,
    // but the lock costs nothing under that pattern and removes a footgun.
    std::lock_guard lock(mu_);
    device_token_store_ = store;
}

void AgentRegistry::set_register_agent_interleave_hook_for_test(std::function<void()> hook) {
    register_agent_interleave_hook_for_test_ = std::move(hook);
}

std::expected<std::shared_ptr<AgentSession>, std::string>
AgentRegistry::register_agent(const pb::AgentInfo& info) {
    auto session = std::make_shared<AgentSession>();
    session->agent_id = info.agent_id();
    session->hostname = info.hostname();
    session->os = info.platform().os();
    session->arch = info.platform().arch();
    session->agent_version = info.agent_version();
    // Ingest filter (#3295): validated and non-service, mirroring TagStore's
    // own sync_agent_tags gate (tag_store.cpp) so a service claim or an
    // oversized/malformed key never reaches scope-DSL evaluation via the
    // in-memory fallback below, regardless of TagStore sync outcome.
    for (const auto& [k, v] : info.scopable_tags()) {
        if (authz::is_service_tag_key(k)) {
            spdlog::info("AgentRegistry::register_agent({}): dropping self-reported "
                         "'service' tag from session scopable_tags (#3295)",
                         info.agent_id());
            // Gate 6 hardening: the store-side purge (tag_store.cpp,
            // sync_agent_tags) has yuzu_server_tag_store_agent_service_purge_total;
            // this session-level drop is the ONLY signal for a gateway-proxied
            // agent (ProxyRegister never calls sync_agent_tags, so the store-side
            // counter never fires for that population).
            metrics_.counter("yuzu_server_agent_registry_service_tag_dropped_total")
                .increment();
            continue;
        }
        if (!TagStore::validate_key(k) || !TagStore::validate_value(v)) {
            spdlog::info("AgentRegistry::register_agent({}): dropping invalid scopable_tag "
                         "'{}' at ingest",
                         info.agent_id(), k);
            continue;
        }
        session->scopable_tags[k] = v;
    }
    for (const auto& p : info.plugins()) {
        session->plugin_names.push_back(p.name());
        PluginMeta pm;
        pm.name = p.name();
        pm.version = p.version();
        pm.description = p.description();
        for (const auto& cap : p.capabilities()) {
            pm.actions.push_back(cap);
        }
        session->plugin_meta.push_back(std::move(pm));
    }

    // Phase 1 (under mu_): snapshot the CURRENT session for this agent_id (not just whether one
    // exists) and the device-token store pointer. Only this read is guarded by mu_ (matches
    // set_device_token_store's "guarded by mu_" contract) — the revoke call itself, a blocking
    // Postgres round-trip, runs OFF the lock below. Holding the shared_ptr (not a bool) keeps
    // phase 2's identity compare ABA-safe: as long as this call holds a strong ref, no other
    // session can be allocated at the same address.
    std::shared_ptr<AgentSession> prior_session;
    DeviceTokenStore* store = nullptr;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(info.agent_id());
        if (it != agents_.end())
            prior_session = it->second;
        store = device_token_store_;
    }
    const bool prior_exists = (prior_session != nullptr);

    // W1.5 / #823, corrected by #3401: re-registration revokes any device tokens bound to this
    // agent_id BEFORE the new session is installed, so an attacker who briefly held this
    // identity (mTLS-disabled flow, #779) cannot keep replaying a token issued to the legitimate
    // agent. First-time registrations (no prior entry above) skip the revoke, preserving the
    // operator workflow of pre-issuing a token for an agent_id that has not registered yet.
    // `revoke_by_device` (not `revoke_by_principal` — #3401: REST issuance never writes the
    // agent_id into `principal_id`) is the sweep bound to the column `validate_token` actually
    // enforces the presenter against.
    //
    // Runs OFF `mu_` — precedent `sweep_revoked` below. The invariant #823 needs is "the revoke
    // commits before the new session is installed", which holds here regardless of lock
    // discipline (phase 2 below only runs after this call returns); holding `mu_` across the
    // call bought nothing (nothing else in this class reads `device_auth_tokens`) while
    // serializing every unrelated `register_agent` / `send_to` / `evaluate_scope` / `get_session`
    // caller behind this store's pool-acquire latency (up to kWriteTimeout=4s) plus a possible
    // additional FOR-UPDATE lock-wait (lock_timeout_ms, 10s default) if a concurrent
    // `validate_token` holds the row lock — the same acquire-vs-lock-wait distinction ADR-0052's
    // "Capacity note" documents for kValidateTimeout.
    //
    // Fails CLOSED (ADR-0012 §1, #3401 Gap 2): a genuine revoke failure REFUSES the registration
    // — no session installed, no management-group membership, no topology invalidation — rather
    // than installing a session the sweep could not clear stale tokens for. Both gRPC callers
    // (agent_service_impl.cpp, gateway_service_impl.cpp) must surface this as a retryable
    // grpc::Status, never `accepted=false` (the latter is the agent's PERMANENT give-up signal).
    if (prior_exists && store) {
        auto revoked = store->revoke_by_device(info.agent_id());
        if (!revoked) {
            spdlog::error("AgentRegistry::register_agent: device token revoke-by-device failed "
                          "for '{}', refusing registration: {}",
                          info.agent_id(), revoked.error());
            metrics_
                .counter("yuzu_agents_registration_refused_total",
                         {{"reason", "device_token_revoke_failed"}})
                .increment();
            return std::unexpected("device token revoke failed: " + revoked.error());
        }
    }

    // Test-only interleave seam (Gate 5 CH-1a): fires once, synchronously, in this exact window
    // — after the revoke, before phase 2 re-locks. A test callback that itself calls
    // register_agent again for the same agent_id deterministically exercises the supersede path
    // just below, without real threads. No-op (nullptr) in production.
    if (register_agent_interleave_hook_for_test_) {
        auto hook = std::move(register_agent_interleave_hook_for_test_);
        register_agent_interleave_hook_for_test_ = nullptr;
        hook();
    }

    // Phase 2 (under mu_): install the new session. Re-fetches the CURRENT entry rather than
    // reusing phase 1's snapshot, then compares it BY POINTER against that snapshot before
    // touching anything.
    //
    // Because the revoke above runs off mu_, a second register_agent call for this SAME
    // agent_id can run its own phase 1 + revoke + phase 2 to completion entirely within this
    // call's revoke window (e.g. its revoke hits an empty pool queue while this one waits behind
    // a FOR-UPDATE lock). Under the OLD single-locked implementation this could not happen —
    // holding mu_ across the whole call serialized both calls end to end, so install order always
    // matched arrival order. Splitting the lock restores that ordering explicitly here instead of
    // getting it for free: if the entry we see now is not the SAME object phase 1 saw, a newer
    // registration already won and installed — this call yields rather than overwrite it (its
    // own revoke already committed, so the #823 guarantee for its identity is satisfied
    // regardless; only the session install is skipped). An entry that has instead been REMOVED
    // (`it == end()` — e.g. the prior session's stream tore down independently) is NOT
    // "superseded": there is nothing live to protect, so this call installs normally.
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(info.agent_id());
        if (it != agents_.end() && it->second != prior_session) {
            spdlog::warn("AgentRegistry::register_agent: superseded by a concurrent "
                         "registration for '{}', not installing (this call's revoke already "
                         "committed)",
                         info.agent_id());
            metrics_
                .counter("yuzu_agents_registration_refused_total",
                         {{"reason", "superseded_by_concurrent_registration"}})
                .increment();
            return std::unexpected("superseded by a concurrent registration for this agent_id");
        }
        if (it != agents_.end() && !it->second->session_id.empty())
            session_to_agent_.erase(it->second->session_id);
        agents_[info.agent_id()] = session;
    }
    metrics_.counter("yuzu_agents_registered_total").increment();
    metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
    bus_.publish("agent-online", info.agent_id());
    spdlog::info("Agent registered: id={}, hostname={}, plugins={}", info.agent_id(),
                 info.hostname(), info.plugins_size());
    return session;
}

void AgentRegistry::set_stream(
    const std::string& agent_id,
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream,
    grpc::ServerContext* context, const std::string& peer_cert_pem) {
    std::lock_guard lock(mu_);
    auto it = agents_.find(agent_id);
    if (it != agents_.end()) {
        std::lock_guard slock(it->second->stream_mu);
        it->second->stream = stream;
        it->second->server_context = context;
        it->second->peer_cert_pem = peer_cert_pem; // PR3 H-1: for the revocation sweep
        it->second->last_activity_epoch_ms.store(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count(),
            std::memory_order_relaxed);
    }
}

void AgentRegistry::clear_stream(const std::string& agent_id) {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end())
            return;
        session = it->second;
    }
    {
        std::lock_guard slock(session->stream_mu);
        session->stream = nullptr;
        session->server_context = nullptr;
        session->peer_cert_pem.clear(); // PR3 H-1: stream gone → nothing to sweep
    }
}

void AgentRegistry::touch_activity(const std::string& agent_id) {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end())
            return;
        session = it->second;
    }
    session->last_activity_epoch_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::steady_clock::now().time_since_epoch())
                                              .count(),
                                          std::memory_order_relaxed);
}

void AgentRegistry::reap_stale_sessions(std::chrono::seconds timeout) {
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count();
    auto timeout_ms = std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count();

    // Collect shared_ptrs (not raw pointers) to keep sessions alive during TryCancel.
    std::vector<std::pair<std::string, std::shared_ptr<AgentSession>>> stale;
    {
        std::lock_guard lock(mu_);
        for (auto& [id, session] : agents_) {
            auto last = session->last_activity_epoch_ms.load(std::memory_order_relaxed);
            if ((now_ms - last) > timeout_ms) {
                stale.emplace_back(id, session);
            }
        }
    }

    for (auto& [id, session] : stale) {
        // Acquire stream_mu and re-check context is still valid before cancelling.
        std::lock_guard slock(session->stream_mu);
        if (session->server_context) {
            spdlog::warn("Session timeout: cancelling Subscribe stream for agent {} "
                         "(no activity for >{}s)",
                         id, timeout.count());
            session->server_context->TryCancel();
        }
    }
}

std::vector<std::string>
AgentRegistry::sweep_revoked(const std::function<bool(const std::string&)>& is_revoked) {
    std::vector<std::string> cancelled;
    if (!is_revoked)
        return cancelled;

    // Snapshot every session (shared_ptrs keep them alive across the off-lock
    // revocation check + TryCancel, mirroring reap_stale_sessions).
    std::vector<std::shared_ptr<AgentSession>> sessions;
    {
        std::lock_guard lock(mu_);
        sessions.reserve(agents_.size());
        for (auto& [id, s] : agents_)
            sessions.push_back(s);
    }

    for (auto& session : sessions) {
        // Capture the presented leaf under the stream lock; skip sessions with no
        // live stream or no client cert (nothing to revoke).
        std::string pem;
        {
            std::lock_guard slock(session->stream_mu);
            if (!session->server_context || session->peer_cert_pem.empty())
                continue;
            pem = session->peer_cert_pem;
        }
        // Evaluate revocation OFF stream_mu — is_revoked() reads ca_store under its
        // own mutex, and holding a per-session lock across a cross-store query is
        // the lock-discipline footgun gov #1117 forbids.
        if (!is_revoked(pem))
            continue;
        // Re-acquire and re-verify the cert is unchanged before teardown, so a
        // reconnection that swapped in a fresh (non-revoked) leaf between capture
        // and now is not cancelled by mistake.
        std::lock_guard slock(session->stream_mu);
        if (session->server_context && session->peer_cert_pem == pem) {
            spdlog::warn("Revocation sweep: cancelling Subscribe stream for agent {} "
                         "(client cert revoked)",
                         session->agent_id);
            session->server_context->TryCancel();
            // Clear the stashed leaf so a subsequent tick does not re-detect and
            // re-cancel the SAME stream (and re-increment the counter / re-log)
            // during the window between TryCancel and the Subscribe handler
            // returning to call clear_stream_if_session. One cancel + one metric
            // per revocation event. The handler-exit cleanup (or the stale-session
            // reaper, if the cancel is somehow not observed) still tears the
            // session down fully.
            session->peer_cert_pem.clear();
            metrics_
                .counter("yuzu_grpc_revoked_cert_total",
                         {{"event", "security"}, {"rpc", "stream_sweep"}})
                .increment();
            cancelled.push_back(session->agent_id);
        }
    }
    return cancelled;
}

void AgentRegistry::remove_agent(const std::string& agent_id) {
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it != agents_.end()) {
            // Clean up session_to_agent_ to prevent leak
            if (!it->second->session_id.empty()) {
                session_to_agent_.erase(it->second->session_id);
            }
            agents_.erase(it);
        }
    }
    metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
    bus_.publish("agent-offline", agent_id);
    spdlog::info("Agent removed: id={}", agent_id);
}

bool AgentRegistry::remove_agent_if_session(const std::string& agent_id,
                                            const std::string& session_id) {
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end() || it->second->session_id != session_id) {
            // Session doesn't match — a newer connection has taken over; do nothing
            spdlog::debug("Cleanup skipped: session mismatch for agent {} (old={}, current={})",
                          agent_id, session_id,
                          it != agents_.end() ? it->second->session_id : "<gone>");
            return false;
        }
        session_to_agent_.erase(session_id);
        agents_.erase(it);
    }
    metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
    bus_.publish("agent-offline", agent_id);
    spdlog::info("Agent removed: id={} (session={})", agent_id, session_id);
    return true;
}

void AgentRegistry::remove_agent_if_same(const std::string& agent_id,
                                         const std::shared_ptr<AgentSession>& installed) {
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end() || it->second != installed) {
            // Superseded (a concurrent register_agent already installed a different session) or
            // gone (already torn down some other way) — nothing of OURS to clean up; do not touch
            // whatever is (or isn't) there now.
            spdlog::debug("Rollback cleanup skipped: superseded/gone for agent {}", agent_id);
            return;
        }
        if (!it->second->session_id.empty())
            session_to_agent_.erase(it->second->session_id);
        agents_.erase(it);
    }
    metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
    bus_.publish("agent-offline", agent_id);
    spdlog::info("Agent registration rolled back: id={}", agent_id);
}

void AgentRegistry::clear_stream_if_session(const std::string& agent_id,
                                            const std::string& session_id) {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end() || it->second->session_id != session_id)
            return;
        session = it->second;
    }
    {
        std::lock_guard slock(session->stream_mu);
        session->stream = nullptr;
        session->server_context = nullptr;
        session->peer_cert_pem.clear(); // PR3 H-1: stream gone → nothing to sweep
        // PLAN item 5: a stream that's gone has nothing live to route a
        // dispatch-tagged command through, gateway or not — clear the
        // advertised-capability set alongside the other connection-lifetime
        // fields so a later reconnect starts from a clean slate rather than
        // inheriting a prior connection's advertisement.
        session->gateway_wire_capabilities.clear();
    }
}

bool AgentRegistry::set_gateway_route(const std::string& agent_id, const std::string& session_id,
                                      const std::string& node,
                                      std::vector<std::string> capabilities,
                                      std::string stream_home_id,
                                      std::string cluster_id) {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end() || it->second->session_id != session_id)
            return false;
        session = it->second;
    }
    // M1 (review finding): `gateway_node` and `gateway_wire_capabilities` used
    // to be TWO setters, TWO lock domains — this one wrote `node` under `mu_`
    // only, while `send_to`/`send_to_all` read it under `stream_mu` (a data
    // race), and CONNECTED published the two fields in two separate calls (an
    // observable intermediate state: node present, capabilities not yet
    // replaced, which the gateway-capability gate could read as a false
    // deny). Both fields are published together, under the SAME lock
    // `send_to`/`send_to_all` already read them under, so there is exactly
    // one lock domain and no publish step in between for a reader to land in.
    // HA WS-4 #4324: `stream_home_id` joins the same atomic publish for the
    // same reason — folding it into a second lock acquisition would
    // reintroduce exactly the M1 hazard this comment describes, one field
    // later.
    std::lock_guard slock(session->stream_mu);
    session->gateway_node = node;
    // PLAN item 5: a full REPLACE, never a merge — a reconnect behind an
    // upgraded (or downgraded) gateway build must not keep stacking
    // capabilities a prior connection advertised but this one does not.
    session->gateway_wire_capabilities =
        std::unordered_set<std::string>(capabilities.begin(), capabilities.end());
    session->gateway_stream_home_id = std::move(stream_home_id);
    // HA WS-4 4.3: same atomic publish, same reason — see AgentSession::
    // cluster_id's comment.
    session->cluster_id = std::move(cluster_id);
    return true;
}

bool AgentRegistry::unpublish_gateway_route(const std::string& agent_id,
                                            const std::string& session_id) {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end() || it->second->session_id != session_id)
            return false;
        session = it->second;
    }
    // Same lock domain as set_gateway_route, for the same M1 reason: a
    // reader (send_to/send_to_all) must never observe a torn intermediate
    // state between clearing these four fields.
    std::lock_guard slock(session->stream_mu);
    session->gateway_node.clear();
    session->gateway_wire_capabilities.clear();
    session->gateway_stream_home_id.clear();
    session->cluster_id.clear();
    return true;
}

std::optional<std::string>
AgentRegistry::gateway_stream_home_id(const std::string& agent_id,
                                      const std::string& session_id) const {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end() || it->second->session_id != session_id)
            return std::nullopt;
        session = it->second;
    }
    std::lock_guard slock(session->stream_mu);
    return session->gateway_stream_home_id;
}

void AgentRegistry::clear_gateway_wire_capabilities(const std::string& agent_id) {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end())
            return;
        session = it->second;
    }
    std::lock_guard slock(session->stream_mu);
    session->gateway_wire_capabilities.clear();
}

bool AgentRegistry::gateway_has_wire_capability(const std::string& agent_id,
                                                std::string_view capability) const {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end())
            return false;
        session = it->second;
    }
    std::lock_guard slock(session->stream_mu);
    return session->gateway_wire_capabilities.contains(std::string(capability));
}

void AgentRegistry::sweep_and_publish_trusted_gateway_locked() {
    // Caller MUST hold trusted_gateway_mu_.
    const auto now = std::chrono::steady_clock::now();

    // Pass 1: drop anything past the TTL window.
    for (auto it = trusted_gateway_peer_ips_.begin(); it != trusted_gateway_peer_ips_.end();) {
        if (now - it->second > kTrustedGatewayTtl) {
            it = trusted_gateway_peer_ips_.erase(it);
        } else {
            ++it;
        }
    }

    // Pass 2: if at cap, evict the single oldest entry to make room.
    // We're called from `note_trusted_gateway_peer` BEFORE the insert,
    // so being AT the cap means the imminent insert would push over —
    // drop one now. Linear scan is fine: the map is bounded at
    // kTrustedGatewayCap, and this only runs on the (rare) insert path.
    if (trusted_gateway_peer_ips_.size() >= kTrustedGatewayCap) {
        auto oldest = trusted_gateway_peer_ips_.begin();
        for (auto it = std::next(oldest); it != trusted_gateway_peer_ips_.end(); ++it) {
            if (it->second < oldest->second) {
                oldest = it;
            }
        }
        if (oldest != trusted_gateway_peer_ips_.end()) {
            trusted_gateway_peer_ips_.erase(oldest);
        }
    }

    metrics_.gauge("yuzu_trusted_gateway_peer_set_size")
        .set(static_cast<double>(trusted_gateway_peer_ips_.size()));
}

void AgentRegistry::note_trusted_gateway_peer(std::string_view peer_ip) {
    // #826: defence-in-depth — never record an empty string. An empty
    // peer IP would later satisfy `is_trusted_gateway_peer("")` and
    // re-create the bypass we're trying to close.
    if (peer_ip.empty())
        return;
    std::lock_guard lock(trusted_gateway_mu_);

    // W1.3 R2 / UP-2: opportunistic sweep + cap enforcement BEFORE the
    // insert so a fresh entry never causes the map to exceed
    // kTrustedGatewayCap. Sweep also refreshes the published gauge,
    // which is important so an operator sees the set shrinking as TTL
    // expirations land — without the sweep, a quiet system would show
    // a stale max-size gauge until the next insert hit cap.
    sweep_and_publish_trusted_gateway_locked();

    // Insert OR refresh — repeat ProxyRegisters from the same gateway
    // update last_seen so an active gateway stays trusted indefinitely.
    trusted_gateway_peer_ips_[std::string(peer_ip)] = std::chrono::steady_clock::now();

    metrics_.gauge("yuzu_trusted_gateway_peer_set_size")
        .set(static_cast<double>(trusted_gateway_peer_ips_.size()));
}

bool AgentRegistry::is_trusted_gateway_peer(std::string_view peer_ip) const {
    // #826: empty is NEVER trusted. Without this guard a caller that
    // failed to extract the peer IP from the gRPC context would pass
    // an empty string and the check would pass spuriously.
    if (peer_ip.empty())
        return false;
    std::lock_guard lock(trusted_gateway_mu_);
    auto it = trusted_gateway_peer_ips_.find(std::string(peer_ip));
    if (it == trusted_gateway_peer_ips_.end())
        return false;
    // W1.3 R2 / UP-3: stale entries do not satisfy the trusted check.
    // We do not erase here (const method, would require shared→unique
    // upgrade); the next `note_trusted_gateway_peer` sweep evicts it.
    const auto age = std::chrono::steady_clock::now() - it->second;
    return age <= kTrustedGatewayTtl;
}

std::size_t AgentRegistry::trusted_gateway_peer_count() const {
    std::lock_guard lock(trusted_gateway_mu_);
    return trusted_gateway_peer_ips_.size();
}

void AgentRegistry::expire_trusted_gateway_for_test(std::chrono::seconds offset) {
    std::lock_guard lock(trusted_gateway_mu_);
    for (auto& [ip, last_seen] : trusted_gateway_peer_ips_) {
        last_seen -= offset;
    }
    metrics_.gauge("yuzu_trusted_gateway_peer_set_size")
        .set(static_cast<double>(trusted_gateway_peer_ips_.size()));
}

namespace {

/// PLAN item 3 (belt-and-braces): the TYPE invariant (private
/// `ClassifiedCommand` constructor, `ServerImpl`-only friend) is what
/// actually stops a hand-built `pb::CommandRequest` from reaching either send
/// path — this is a SEPARATE, defensive runtime check that the tag a
/// `ClassifiedCommand` carries still decodes, counted apart from the
/// gateway-capability denial below so the two failure modes are
/// distinguishable on a dashboard. Shared by `send_to`/`send_to_all` so the
/// two cannot drift on what "malformed" means.
bool tag_is_valid(const pb::CommandRequest& cmd, yuzu::MetricsRegistry& metrics,
                  const std::string& agent_id) {
    if (yuzu::server::decode_dispatch_tag(cmd.dispatch_tag()))
        return true;
    metrics.counter("yuzu_server_dispatch_tag_invalid_total").increment();
    spdlog::error("send_to: ClassifiedCommand for agent {} carries an unparseable dispatch_tag "
                 "'{}' — refusing to send (defensive check)",
                 agent_id, cmd.dispatch_tag());
    return false;
}

/// PLAN item 5 (CC-03): true iff `session` is routed through a gateway that
/// has NOT proven — via its most recent CONNECTED advertisement — that it
/// forwards `CommandRequest.dispatch_tag` untouched. Every dispatch reaching
/// this point already carries a non-empty tag (only `ClassifiedCommand`
/// reaches `send_to`/`send_to_all`, and `build_classified_command` always
/// stamps one), so this check applies unconditionally on the gateway-routed
/// arm — never silently downgraded to "send anyway, tag be damned".
///
/// DECISION (CC-03, adversarial review): the `session.gateway_node.empty()`
/// early-return is DEFENSIVE, not the decision point, and is deliberately
/// left as an allow. Both callers only enter the gateway arm when
/// `gateway_node` is non-empty, so an empty node never reaches this check in
/// production — flipping it to deny would change nothing and would misstate
/// where the real hazard lives.
///
/// The real hazard is upstream and is a DELIVERY problem, not a gate-posture
/// one. `gateway_node` (and `gateway_wire_capabilities` with it) is written
/// only by `NotifyStreamStatus`'s CONNECTED arm, which the gateway delivers
/// as an Erlang `gen_server:cast` (`yuzu_gw_upstream.erl`) that is dropped
/// with no retry when the circuit is open or ≥10 notifies are in flight. A
/// proxied agent whose arming notification was dropped therefore sits with
/// `gateway_node == ""`, `send_to` takes the DIRECT-STREAM branch, and the
/// command is written into the gateway's proxy Subscribe stream and never
/// reaches the agent — the #1004 black-hole the `gateway_node`-first
/// ordering exists to prevent. Hardening this check cannot see that state,
/// because the state it would need to observe was never delivered.
///
/// What ships here instead: the two deny counters are PRE-REGISTERED at boot
/// (server.cpp's metrics seed block), so "the check ran and passed" (zero)
/// is distinguishable from "the check never ran" (absent) — which is exactly
/// the blind state a dropped arming message produces. Making the arming
/// delivery itself reliable or reconcilable is a gateway-side change with
/// its own wire implications and is deliberately NOT folded in here.
bool gateway_capability_missing(const AgentSession& session, yuzu::MetricsRegistry& metrics,
                                const std::string& agent_id) {
    if (session.gateway_node.empty())
        return false; // direct agent — no gateway hop to prove anything about.
    if (session.gateway_wire_capabilities.contains(
            std::string(kGatewayWireCapabilityDispatchTagV1)))
        return false;
    metrics
        .counter("yuzu_server_gateway_capability_denied_total",
                 {{"capability", std::string(kGatewayWireCapabilityDispatchTagV1)}})
        .increment();
    spdlog::warn("send_to: refusing to route a dispatch-tagged command to agent {} via gateway "
                 "node '{}' — gateway has not advertised '{}'",
                 agent_id, session.gateway_node, kGatewayWireCapabilityDispatchTagV1);
    return true;
}

} // namespace

bool AgentRegistry::send_to(const std::string& agent_id, const ClassifiedCommand& cmd) {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end())
            return false;
        session = it->second;
    }
    if (!tag_is_valid(cmd.wire(), metrics_, agent_id))
        return false;
    std::lock_guard slock(session->stream_mu);
    // #1004: prefer the gateway-pending path when `gateway_node` is set.
    // The canonical fanout path for gateway-routed agents is
    // forward_gateway_pending() → ManagementService.SendCommand, not the
    // Subscribe stream — `--gateway-mode` relaxes peer validation so a
    // gateway may also hold a Subscribe stream as proxy, but that stream
    // is not the wire the gateway uses to deliver commands to its
    // connected agents. Checking gateway_node first prevents the silent
    // black-hole where the command is Write()-en into the gateway's
    // Subscribe stream and never reaches the agent.
    if (!session->gateway_node.empty()) {
        // PLAN item 5: DENY, counted and logged, never silently downgraded —
        // checked under stream_mu, which already guards
        // gateway_wire_capabilities (set/cleared under the same lock).
        if (gateway_capability_missing(*session, metrics_, agent_id))
            return false;
        // HA WS-4 4.3: stamp the session's own cluster_id (published by
        // set_gateway_route under this same stream_mu) so
        // forward_gateway_pending dials the owning cluster instead of always
        // the single legacy stub. Empty -> nullopt, matching how
        // GatewayRouteStore::RoutableRoute already treats an empty/absent
        // cluster as non-routable.
        std::optional<std::string> cluster_id =
            session->cluster_id.empty() ? std::nullopt : std::make_optional(session->cluster_id);
        std::lock_guard glock(gw_pending_mu_);
        gw_pending_.push_back({agent_id, cmd.wire(), std::move(cluster_id)});
        return true;
    }
    if (session->stream)
        return session->stream->Write(cmd.wire(), grpc::WriteOptions());
    return false;
}

int AgentRegistry::send_to_all(const ClassifiedCommand& cmd) {
    std::vector<std::shared_ptr<AgentSession>> snapshot;
    {
        std::lock_guard lock(mu_);
        snapshot.reserve(agents_.size());
        for (auto& s : agents_ | std::views::values) {
            snapshot.push_back(s);
        }
    }
    if (!tag_is_valid(cmd.wire(), metrics_, "<broadcast>"))
        return 0;
    int count = 0;
    for (auto& s : snapshot) {
        std::lock_guard slock(s->stream_mu);
        // #1004: mirror send_to() — gateway-pending path wins over any
        // Subscribe stream the gateway may also hold for the agent.
        if (!s->gateway_node.empty()) {
            // PLAN item 5: an individual recipient's missing advertisement
            // excludes only that agent from the count — it is not an error
            // for the rest of the broadcast, mirroring how a dead Subscribe
            // stream already excludes a direct agent without aborting the loop.
            if (gateway_capability_missing(*s, metrics_, s->agent_id))
                continue;
            // HA WS-4 4.3: see send_to()'s matching comment.
            std::optional<std::string> cluster_id =
                s->cluster_id.empty() ? std::nullopt : std::make_optional(s->cluster_id);
            std::lock_guard glock(gw_pending_mu_);
            gw_pending_.push_back({s->agent_id, cmd.wire(), std::move(cluster_id)});
            ++count;
        } else if (s->stream && s->stream->Write(cmd.wire(), grpc::WriteOptions())) {
            ++count;
        }
    }
    return count;
}

bool AgentRegistry::send_via_directory(const std::string& agent_id, const ClassifiedCommand& cmd,
                                       const std::string& cluster_id) {
    // Same defensive belt-and-braces check `send_to`/`send_to_all` apply —
    // this path has no session to have already validated anything, so it is
    // the ONLY check this method makes before queuing.
    if (!tag_is_valid(cmd.wire(), metrics_, agent_id))
        return false;
    std::lock_guard glock(gw_pending_mu_);
    gw_pending_.push_back({agent_id, cmd.wire(), cluster_id});
    return true;
}

std::vector<AgentRegistry::GatewayPendingCmd> AgentRegistry::drain_gateway_pending() {
    std::lock_guard lock(gw_pending_mu_);
    auto result = std::move(gw_pending_);
    gw_pending_.clear();
    return result;
}

bool AgentRegistry::has_any() const {
    std::lock_guard lock(mu_);
    return !agents_.empty();
}

bool AgentRegistry::has_any_reachable() const {
    if (has_any())
        return true;
    // Local fleet looks empty — check presence before declaring genuinely
    // nothing reachable. live_presence() is the same short-TTL cache
    // all_ids()/evaluate_scope() already share, so this costs nothing beyond
    // has_any()'s own lock in the common (non-empty) case above, and at most
    // one cached-or-fresh presence read otherwise.
    return !live_presence().empty();
}

std::string AgentRegistry::display_name(const std::string& agent_id) const {
    std::lock_guard lock(mu_);
    auto it = agents_.find(agent_id);
    if (it != agents_.end() && !it->second->hostname.empty())
        return it->second->hostname;
    if (agent_id.size() > 12)
        return agent_id.substr(0, 12);
    return agent_id;
}

nlohmann::json AgentRegistry::to_json_obj() const {
    std::lock_guard lock(mu_);

    nlohmann::json arr = nlohmann::json::array();
    for (const auto& s : agents_ | std::views::values) {
        arr.push_back({{"agent_id", s->agent_id},
                       {"hostname", s->hostname},
                       {"os", s->os},
                       {"arch", s->arch},
                       {"agent_version", s->agent_version}});
    }
    return arr;
}

std::string AgentRegistry::to_json() const {
    return to_json_obj().dump();
}

const std::unordered_map<std::string, std::string>& AgentRegistry::action_descriptions() {
    static const std::unordered_map<std::string, std::string> m = {
        // example
        {"example.ping", "Returns a 'pong' response"},
        {"example.echo", "Echoes back the supplied message parameter"},
        // status
        {"status.version", "Agent version, build number, and git commit hash"},
        {"status.info", "Platform OS, architecture, and hostname"},
        {"status.health", "Uptime, current timestamp, and memory RSS"},
        {"status.plugins", "Installed plugins with version and description"},
        {"status.modules", "Loaded modules with version and status"},
        {"status.connection", "Server address, TLS status, debug and verbose settings"},
        {"status.switch", "Switch address, session ID, connected since, reconnect count"},
        {"status.config", "Full agent configuration dump"},
        // processes
        {"processes.list", "Enumerate all running processes (PID and name)"},
        {"processes.query", "Filter processes by case-insensitive name match"},
        // hardware
        {"hardware.manufacturer", "System manufacturer string"},
        {"hardware.model", "System model / product name"},
        {"hardware.bios", "BIOS/UEFI vendor, version, and release date"},
        {"hardware.processors", "Installed CPUs with model, cores, threads, clock speed"},
        {"hardware.memory", "Installed memory modules (DIMMs) with size and type"},
        {"hardware.disks", "Physical disk drives with size and media type"},
        {"hardware.drivers", "Installed device drivers with version, date, provider, class"},
        // os_info
        {"os_info.os_name", "Full OS product name"},
        {"os_info.os_version", "OS version string"},
        {"os_info.os_build", "OS build identifier"},
        {"os_info.os_arch", "CPU architecture"},
        {"os_info.uptime", "System uptime in seconds and human-readable form"},
        // services
        {"services.list", "Installed services with name, status, and startup type"},
        {"services.running", "Only currently running services"},
        {"services.set_start_mode", "Change a service's startup type (automatic/manual/disabled)"},
        // users
        {"users.logged_on", "Currently logged-on users"},
        {"users.sessions", "Active interactive sessions"},
        {"users.local_users", "Enumerate local user accounts"},
        {"users.local_admins", "Members of the local Administrators group"},
        {"users.group_members", "Members of a specified local group"},
        {"users.primary_user", "Primary user (most frequent login)"},
        {"users.session_history", "Historical login/logout session records"},
        // tags
        {"tags.set", "Set a tag key-value pair"},
        {"tags.get", "Get a tag value by key"},
        {"tags.get_all", "Get all tags"},
        {"tags.delete", "Delete a tag by key"},
        {"tags.check", "Check if a tag key exists"},
        {"tags.clear", "Clear all tags"},
        {"tags.count", "Count total tags"},
        // registry
        {"registry.get_value", "Read a Windows registry value"},
        {"registry.set_value", "Write a Windows registry value"},
        {"registry.delete_value", "Delete a Windows registry value"},
        {"registry.delete_key", "Delete a Windows registry key"},
        {"registry.key_exists", "Check if a registry key exists"},
        {"registry.enumerate_keys", "List subkeys under a registry key"},
        {"registry.enumerate_values", "List values in a registry key"},
        {"registry.get_user_value", "Get a registry value from a specific user's hive (by username or SID)"},
        {"registry.list_profiles", "List local user profiles (SID, name, path, hive-load state)"},
        // rdp_control
        {"rdp_control.set_state",
         "Enable or disable Remote Desktop (registry + firewall group + TermService)"},
        {"rdp_control.status",
         "Remote Desktop posture: registry, firewall group, service, derived rdp on/off"},
        // filesystem
        {"filesystem.exists", "Check if a path exists, report type and size"},
        {"filesystem.list_dir", "List directory contents (max 1000 entries)"},
        {"filesystem.file_hash", "Compute SHA-256 (or SHA-1) hash of a file"},
        {"filesystem.create_temp", "Create a secure temporary file (owner-only permissions)"},
        {"filesystem.create_temp_dir",
         "Create a secure temporary directory (owner-only permissions)"},
        // content_dist
        {"content_dist.stage", "Download a file to staging directory with hash verification"},
        {"content_dist.execute_staged", "Execute a previously staged file"},
        {"content_dist.list_staged", "List files in the staging directory"},
        {"content_dist.cleanup", "Remove staged files older than N hours"},
        // script_exec
        {"script_exec.exec", "Execute a command with arguments (no shell interpretation)"},
        {"script_exec.powershell", "Run a PowerShell script (Windows only)"},
        {"script_exec.bash", "Run a bash script (Linux/macOS only)"},
        // windows_updates
        {"windows_updates.installed", "List recently installed updates or packages"},
        {"windows_updates.missing", "List available updates or packages not yet installed"},
        // agent_logging
        {"agent_logging.get_log", "Return the last N lines of the agent log file"},
        {"agent_logging.get_key_files",
         "List important agent files with sizes and modification times"},
        // installed_apps
        {"installed_apps.list", "List all installed applications"},
        {"installed_apps.query", "Search for an application by name (partial match)"},
        // network_config
        {"network_config.adapters", "Network adapters with MAC, speed, and status"},
        {"network_config.ip_addresses", "Assigned IP addresses with subnet and gateway"},
        {"network_config.dns_servers", "Configured DNS servers per adapter"},
        {"network_config.proxy", "System proxy configuration"},
        // network_actions
        {"network_actions.flush_dns", "Flush the DNS resolver cache"},
        {"network_actions.ping", "Ping a host (params: host, count)"},
        // netstat
        {"netstat.netstat_list",
         "Active TCP/UDP connections and listening sockets with owning PID"},
        {"netstat.attribution",
         "Active TCP/UDP connections and listening sockets with owning process name and path "
         "(folds the retired sockwho plugin in, #3403)"},
        // netprobe
        {"netprobe.icmp", "ICMP round-trip time, jitter, and loss to targets"},
        {"netprobe.tcp", "TCP connect-time RTT, jitter, and loss to targets (default port 443)"},
        {"netprobe.dns", "DNS resolution timing per name"},
        // device_identity
        {"device_identity.device_name", "Machine hostname"},
        {"device_identity.domain", "DNS/AD domain and join status"},
        {"device_identity.ou", "Active Directory organizational unit path"},
        // discovery
        {"discovery.scan_subnet", "ARP scan + ping sweep of a subnet to find live hosts"},
        // firewall
        {"firewall.state", "Firewall state per profile/backend"},
        {"firewall.rules", "List firewall rules (summary)"},
        // certificates
        {"certificates.list", "List certificates in system stores"},
        {"certificates.details", "Get details for a certificate by thumbprint"},
        {"certificates.delete", "Delete a certificate by thumbprint from a given store"},
        // event_logs
        {"event_logs.errors", "Recent error events from a specified log"},
        {"event_logs.query", "Search events by keyword"},
        // wmi
        {"wmi.query", "Run a WQL SELECT query"},
        {"wmi.get_instance", "Get all properties of a WMI class instance"},
        // bitlocker
        {"bitlocker.state", "BitLocker / LUKS / FileVault status per volume"},
        // antivirus
        {"antivirus.products", "List installed antivirus products"},
        {"antivirus.status", "Detailed antivirus status (Windows Defender / macOS XProtect)"},
        {"antivirus.av_exclusions",
         "Windows Defender exclusion lists (paths/processes/extensions)"},
        // http_client
        {"http_client.download", "Download a file from URL with optional hash verification"},
        {"http_client.get", "HTTP GET a URL, return status and body"},
        {"http_client.head", "HTTP HEAD a URL, return status and headers"},
        // chargen
        {"chargen.chargen_start", "Begin generating rotating ASCII character lines (RFC 864)"},
        {"chargen.chargen_stop", "Stop all running chargen sessions"},
        // ioc
        {"ioc.check", "Check indicators of compromise against local endpoint state"},
        // quarantine
        {"quarantine.quarantine", "Isolate device from network, whitelisting management server"},
        {"quarantine.unquarantine", "Remove quarantine firewall rules and restore network access"},
        {"quarantine.status", "Check whether quarantine rules are currently active"},
        {"quarantine.whitelist", "Add or remove IPs from an active quarantine whitelist"},
        // agent_actions
        {"agent_actions.set_log_level", "Change the spdlog log level at runtime"},
        {"agent_actions.info", "Return agent runtime info from config context"},
        // software_actions
        {"software_actions.list_upgradable", "List packages/apps that can be upgraded (read-only)"},
        {"software_actions.installed_count", "Quick count of installed packages or apps"},
        // network_diag
        {"network_diag.listening", "List listening TCP ports"},
        {"network_diag.connections", "List established TCP connections"},
        // msi_packages
        {"msi_packages.list", "List installed packages (Windows MSI / macOS pkgutil receipts)"},
        {"msi_packages.product_codes",
         "Compact list of installed package identifiers (Windows MSI GUIDs / macOS pkgutil "
         "reverse-domain IDs)"},
        // windows_optional_features
        {"windows_optional_features.list", "List Windows optional OS features with enabled/disabled/pending state (DISM)"},
        {"windows_optional_features.info", "Describe one Windows optional feature: display name, state, restart requirement (DISM)"},
        // app_control
        {"app_control.wdac_policy", "Report the configured WDAC (Code Integrity) application-control policy posture (Windows, read-only)"},
        {"app_control.applocker_policy", "Report AppLocker rule-collection enforcement mode and rule count (Windows, read-only)"},
        // platform_security
        {"platform_security.secure_boot", "Report Secure Boot and setup-mode state (efivars on Linux, SecureBoot registry state on Windows; unsupported on macOS)"},
        {"platform_security.code_integrity", "Report code-signing enforcement posture (Linux LSM and lockdown, macOS Gatekeeper and SIP, Windows CI policy and Device Guard)"},
        // system_hardening
        {"system_hardening.posture", "Report exploit-mitigation and kernel-hardening posture per allowlisted key (value, absent or unreadable)"},
        // sccm
        // peripherals
        {"peripherals.usb", "List attached USB devices (vendor/product ids, class, names, serial, hub flag)"},
        {"peripherals.pci", "List PCI devices (vendor/device/class codes, driver)"},
        {"peripherals.thunderbolt", "List Thunderbolt/USB4 controllers and attached devices"},
        // pkg_inventory
        {"pkg_inventory.managers",
         "List package managers present on the host with manager-level config facts "
         "(macOS Homebrew prefixes with tap/formula/cask counts; read-only, no subprocess; "
         "macOS only today, Linux and Windows report unsupported)"},
        {"pkg_inventory.packages",
         "List macOS Homebrew formulae and casks by name, version and kind (macOS only "
         "today; the Linux package roster is owned by installed_apps)"},
        {"sccm.client_version", "Check if SCCM client is installed and report version"},
        {"sccm.site", "Get SCCM site assignment info"},
        // firmware_posture
        {"firmware_posture.firmware", "Report BIOS/firmware vendor, version, release date and update-pending posture"},
        // runtimes
        {"runtimes.dotnet",
         "List installed .NET (Core/5+) shared frameworks and SDKs by flavour, version and "
         "install path (Linux only; standard roots only, directory walk, no subprocess)"},
        {"runtimes.jvm",
         "List installed JVMs by image type, version, home and vendor from each home's "
         "release file (Linux only; standard roots only, no subprocess)"},
        // storage
        {"storage.set", "Store a key-value pair in persistent storage"},
        {"storage.get", "Retrieve a value by key from persistent storage"},
        {"storage.delete", "Delete a key from persistent storage"},
        {"storage.list", "List keys matching a prefix"},
        {"storage.clear", "Delete all keys for this plugin"},
        // interaction
        {"interaction.notify", "Show a desktop notification/toast message"},
        {"interaction.message_box", "Show a modal message dialog, return button clicked"},
        {"interaction.input", "Show a text input dialog, return entered text"},
        {"interaction.survey", "Show a multi-question survey form, collect responses"},
        {"interaction.set_dnd", "Enable or disable Do Not Disturb mode"},
        // asset_tags
        {"asset_tags.sync", "Push current structured tags from server; detect changes"},
        {"asset_tags.status", "Report locally cached tags and sync metadata"},
        {"asset_tags.get", "Get a specific structured tag value by category key"},
        {"asset_tags.changes", "Report the change log (what changed and when)"},
        // procfetch
        {"procfetch.procfetch_fetch", "Enumerate processes with PID, name, path, and SHA-1 hash"},
        // wol
        {"wol.wake", "Send a Wake-on-LAN magic packet to a MAC address"},
        {"wol.check", "Ping a host to verify it responded to WoL wake"},
        // vuln_scan
        {"vuln_scan.scan", "Full vulnerability scan (CVE + configuration checks)"},
        {"vuln_scan.cve_scan", "CVE-only: match installed software against known CVEs"},
        {"vuln_scan.config_scan", "Configuration and compliance checks only"},
        {"vuln_scan.summary", "Quick severity counts from a full vulnerability scan"},
        // wifi
        {"wifi.list_networks", "Scan for visible WiFi networks (SSID, signal, security)"},
        {"wifi.connected", "Currently connected WiFi network info"},
        // diagnostics
        {"diagnostics.log_level", "Read current agent log level from config"},
        {"diagnostics.certificates", "List TLS certificate paths and whether they exist"},
        {"diagnostics.connection_info",
         "Server address, TLS, session, channel state, latency, uptime"},
        // tar (Timeline Activity Record)
        {"tar.status", "Current TAR collection status, event counts, and DB size"},
        {"tar.query", "Query recorded timeline events by type and time range"},
        {"tar.snapshot", "Trigger an immediate full-state snapshot"},
        {"tar.export", "Export timeline events as structured data"},
        {"tar.configure", "Update TAR collection intervals and retention settings"},
        {"tar.collect_fast", "Run fast collectors (processes + network connections)"},
        {"tar.collect_slow", "Run slow collectors (services + users)"},
        {"tar.collect_perf", "Record one device performance sample (CPU/memory/disk/network)"},
        {"tar.collect_software",
         "Scan installed software and record install/uninstall/upgrade events"},
    };
    return m;
}

std::string AgentRegistry::help_json() const {
    std::lock_guard lock(mu_);

    // Deduplicate plugins by name (take the richest action list)
    std::unordered_map<std::string, const PluginMeta*> best;
    for (const auto& s : agents_ | std::views::values) {
        for (const auto& pm : s->plugin_meta) {
            auto it = best.find(pm.name);
            if (it == best.end() || pm.actions.size() > it->second->actions.size()) {
                best[pm.name] = &pm;
            }
        }
    }

    // Sort by plugin name
    std::vector<const PluginMeta*> sorted;
    sorted.reserve(best.size());
    for (const auto* pm : best | std::views::values)
        sorted.push_back(pm);
    std::ranges::sort(sorted,
                      [](const PluginMeta* a, const PluginMeta* b) { return a->name < b->name; });

    const auto& descs = action_descriptions();
    nlohmann::json plugins_arr = nlohmann::json::array();
    nlohmann::json commands_arr = nlohmann::json::array();

    for (const auto* pm : sorted) {
        nlohmann::json pj;
        pj["name"] = pm->name;
        pj["version"] = pm->version;
        pj["description"] = pm->description;

        // Build actions as objects with name + description
        nlohmann::json actions_arr = nlohmann::json::array();
        for (const auto& act : pm->actions) {
            nlohmann::json aj;
            aj["name"] = act;
            auto it = descs.find(pm->name + "." + act);
            aj["description"] = it != descs.end() ? it->second : "";
            actions_arr.push_back(std::move(aj));
        }
        pj["actions"] = std::move(actions_arr);

        plugins_arr.push_back(std::move(pj));

        // Build command strings: bare plugin name + plugin action
        commands_arr.push_back(pm->name);
        for (const auto& act : pm->actions) {
            commands_arr.push_back(pm->name + " " + act);
        }
    }

    return nlohmann::json({{"plugins", plugins_arr}, {"commands", commands_arr}}).dump();
}

std::string AgentRegistry::help_html(std::string_view filter) const {
    std::lock_guard lock(mu_);

    std::unordered_map<std::string, const PluginMeta*> best;
    for (const auto& s : agents_ | std::views::values)
        for (const auto& pm : s->plugin_meta) {
            auto it = best.find(pm.name);
            if (it == best.end() || pm.actions.size() > it->second->actions.size())
                best[pm.name] = &pm;
        }

    std::vector<const PluginMeta*> sorted;
    sorted.reserve(best.size());
    for (const auto* pm : best | std::views::values)
        sorted.push_back(pm);
    std::ranges::sort(sorted,
                      [](const PluginMeta* a, const PluginMeta* b) { return a->name < b->name; });

    if (!filter.empty()) {
        std::erase_if(sorted, [&](const PluginMeta* pm) { return pm->name != filter; });
    }

    const auto& descs = action_descriptions();
    auto esc = [](std::string_view s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            default:
                out += c;
            }
        }
        return out;
    };

    std::string html;
    int row_count = 0;

    for (const auto* pm : sorted) {
        if (pm->actions.empty()) {
            html +=
                "<tr class=\"result-row\" onclick=\"toggleDetail(this)\">"
                "<td class=\"col-agent\" title=\"" +
                esc(pm->name) + "\">" + esc(pm->name) +
                "</td>"
                "<td title=\"\u2014\">\u2014</td>"
                "<td title=\"" +
                esc(pm->description) + "\">" + esc(pm->description) +
                "</td></tr>"
                "<tr class=\"result-detail\"><td colspan=\"3\"><div class=\"detail-content\">"
                "<div class=\"detail-label\">Plugin</div><div class=\"detail-value\">" +
                esc(pm->name) +
                "</div>"
                "<div class=\"detail-label\">Action</div><div class=\"detail-value\">\u2014</div>"
                "<div class=\"detail-label\">Description</div><div class=\"detail-value\">" +
                esc(pm->description) +
                "</div>"
                "</div></td></tr>";
            ++row_count;
        } else {
            for (const auto& act : pm->actions) {
                auto key = pm->name + "." + act;
                auto it = descs.find(key);
                std::string desc = it != descs.end() ? it->second : "";
                html +=
                    "<tr class=\"result-row\" onclick=\"toggleDetail(this)\">"
                    "<td class=\"col-agent\" title=\"" +
                    esc(pm->name) + "\">" + esc(pm->name) +
                    "</td>"
                    "<td title=\"" +
                    esc(act) + "\">" + esc(act) +
                    "</td>"
                    "<td title=\"" +
                    esc(desc) + "\">" + esc(desc) +
                    "</td></tr>"
                    "<tr class=\"result-detail\"><td colspan=\"3\"><div class=\"detail-content\">"
                    "<div class=\"detail-label\">Plugin</div><div class=\"detail-value\">" +
                    esc(pm->name) +
                    "</div>"
                    "<div class=\"detail-label\">Action</div><div class=\"detail-value\">" +
                    esc(act) +
                    "</div>"
                    "<div class=\"detail-label\">Description</div><div class=\"detail-value\">" +
                    esc(desc) +
                    "</div>"
                    "</div></td></tr>";
                ++row_count;
            }
        }
    }

    // Return data rows FIRST, OOB elements AFTER.
    // The swap target is #results-tbody (innerHTML).  If <span> OOB
    // elements appear before <tr> rows, the browser's parser rejects the
    // <span> inside <tbody> and the subsequent <tr> rows are lost.
    std::string context =
        filter.empty() ? "help \u2014 all plugins" : "help " + std::string(filter);
    std::string result;
    // Primary swap content: <tr> rows (valid inside <tbody>)
    result += html;
    // OOB side-effects: context label + row count (extracted by HTMX
    // regardless of position, won't break the tbody parse context)
    result += "<span id=\"result-context\" hx-swap-oob=\"innerHTML\" "
              "style=\"font-size:0.75rem;color:#8b949e\">" +
              esc(context) + "</span>";
    result +=
        "<span id=\"row-count\" hx-swap-oob=\"innerHTML\">" + std::to_string(row_count) + "</span>";
    // OOB: set the thead to Plugin/Action/Description for help display
    result += "<thead id=\"results-thead\" hx-swap-oob=\"innerHTML\">"
              "<tr><th class=\"col-agent\">Plugin</th><th>Action</th><th>Description</th></tr>"
              "</thead>";
    return result;
}

std::string AgentRegistry::autocomplete_html(std::string_view query) const {
    std::lock_guard lock(mu_);

    std::string q{query};
    std::ranges::transform(q, q.begin(), ::tolower);

    std::unordered_map<std::string, const PluginMeta*> best;
    for (const auto& s : agents_ | std::views::values)
        for (const auto& pm : s->plugin_meta) {
            auto it = best.find(pm.name);
            if (it == best.end() || pm.actions.size() > it->second->actions.size())
                best[pm.name] = &pm;
        }

    const auto& descs = action_descriptions();
    auto esc = [](std::string_view s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            default:
                out += c;
            }
        }
        return out;
    };

    // Build sorted command list with descriptions
    struct CmdEntry {
        std::string cmd;
        std::string desc;
    };
    std::vector<CmdEntry> all_cmds;

    // "help" pseudo-command
    all_cmds.push_back({"help", "List all plugins and actions"});

    for (const auto& [name, pm] : best) {
        all_cmds.push_back({pm->name, pm->description});
        for (const auto& act : pm->actions) {
            auto key = pm->name + "." + act;
            auto it = descs.find(key);
            all_cmds.push_back(
                {pm->name + " " + act, it != descs.end() ? it->second : pm->description});
        }
    }

    // Filter by prefix
    std::vector<const CmdEntry*> matches;
    for (const auto& e : all_cmds) {
        if (e.cmd.starts_with(q) && e.cmd != q)
            matches.push_back(&e);
    }
    std::ranges::sort(matches,
                      [](const CmdEntry* a, const CmdEntry* b) { return a->cmd < b->cmd; });
    if (matches.size() > 15)
        matches.resize(15);

    std::string html;
    for (const auto* m : matches) {
        html += "<div class=\"ac-item\" data-cmd=\"" + esc(m->cmd) +
                "\">"
                "<span>" +
                esc(m->cmd) + "</span>";
        if (!m->desc.empty())
            html += "<span class=\"ac-desc\">" + esc(m->desc) + "</span>";
        html += "</div>";
    }
    return html;
}

std::string AgentRegistry::palette_html(std::string_view query) const {
    std::lock_guard lock(mu_);

    std::string q{query};
    std::ranges::transform(q, q.begin(), ::tolower);

    std::unordered_map<std::string, const PluginMeta*> best;
    for (const auto& s : agents_ | std::views::values)
        for (const auto& pm : s->plugin_meta) {
            auto it = best.find(pm.name);
            if (it == best.end() || pm.actions.size() > it->second->actions.size())
                best[pm.name] = &pm;
        }

    const auto& descs = action_descriptions();
    auto esc = [](std::string_view s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            default:
                out += c;
            }
        }
        return out;
    };

    struct Entry {
        std::string name;
        std::string desc;
        std::string plugin;
        std::string action;
    };
    std::vector<Entry> results;
    std::unordered_set<std::string> seen_plugins;

    for (const auto& [pname, pm] : best) {
        for (const auto& act : pm->actions) {
            auto key = pm->name + "." + act;
            auto it = descs.find(key);
            std::string desc = it != descs.end() ? it->second : pm->description;
            std::string full = pm->name + " " + act;
            std::string full_lower = full;
            std::ranges::transform(full_lower, full_lower.begin(), ::tolower);
            std::string desc_lower = desc;
            std::ranges::transform(desc_lower, desc_lower.begin(), ::tolower);
            if (full_lower.find(q) != std::string::npos ||
                desc_lower.find(q) != std::string::npos) {
                results.push_back({full, desc, pm->name, act});
                seen_plugins.insert(pm->name);
            }
        }
        // Also match just plugin name
        std::string pname_lower = pm->name;
        std::ranges::transform(pname_lower, pname_lower.begin(), ::tolower);
        if (pname_lower.find(q) != std::string::npos && !pm->actions.empty() &&
            !seen_plugins.contains(pm->name)) {
            auto& first_act = pm->actions.front();
            auto key = pm->name + "." + first_act;
            auto it = descs.find(key);
            std::string desc = it != descs.end() ? it->second : pm->description;
            results.push_back({pm->name + " " + first_act, desc, pm->name, first_act});
        }
    }

    std::ranges::sort(results, [](const Entry& a, const Entry& b) { return a.name < b.name; });
    if (results.size() > 8)
        results.resize(8);

    std::string html;
    if (!results.empty()) {
        html += "<div class=\"cmd-section-header\">Instructions</div>";
    }
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        html += "<div class=\"cmd-result\" data-index=\"" + std::to_string(i) +
                "\""
                " data-type=\"instruction\" data-plugin=\"" +
                esc(r.plugin) +
                "\""
                " data-action=\"" +
                esc(r.action) +
                "\">"
                "<span class=\"cmd-result-name\">" +
                esc(r.name) +
                "</span>"
                "<span class=\"cmd-result-desc\">" +
                esc(r.desc) +
                "</span>"
                "<span class=\"cmd-result-type badge badge-info\">Instruction</span>"
                "</div>";
    }
    return html;
}

std::vector<std::string> AgentRegistry::all_ids() const {
    // HA WS-5: live_presence() is cached (kPresenceCacheTtl) and runs OFF
    // mu_ — the same rule the evaluate_scope preloads follow, never holding
    // the registry lock across Postgres I/O. A null presence_store_
    // (unconfigured) makes this call cost nothing beyond the pointer check;
    // a configured one (the production default — see live_presence()'s own
    // doc comment for why this is NOT gated behind an HA-only signal) costs
    // at most one cached-or-fresh read, never a bare per-call round trip.
    std::vector<PresenceIdentity> presence = live_presence();

    std::lock_guard lock(mu_);
    std::vector<std::string> ids;
    ids.reserve(agents_.size() + presence.size());
    for (const auto& id : agents_ | std::views::keys) {
        ids.push_back(id);
    }
    // Local always wins: a presence row for an id this replica already knows
    // locally adds nothing (and must not duplicate it).
    for (const auto& p : presence) {
        if (!agents_.contains(p.agent_id))
            ids.push_back(p.agent_id);
    }
    return ids;
}

std::size_t AgentRegistry::local_agent_count() const {
    std::lock_guard lock(mu_);
    return agents_.size();
}

bool AgentRegistry::has_remote_presence(const std::vector<std::string>& ids) const {
    std::lock_guard lock(mu_);
    for (const auto& id : ids)
        if (!agents_.contains(id))
            return true;
    return false;
}

void AgentRegistry::configure_presence(OfflineEndpointStore* store, std::chrono::seconds ttl) {
    presence_store_ = store;
    presence_ttl_ = ttl;
}

std::vector<PresenceIdentity> AgentRegistry::live_presence() const {
    if (!presence_store_)
        return {};
    std::lock_guard lock(presence_cache_mu_);
    const auto now = std::chrono::steady_clock::now();
    // `presence_cache_at_{}` (default-constructed epoch) is always stale on
    // the first call, so this always fetches at least once before serving a
    // cached copy.
    if (now - presence_cache_at_ >= kPresenceCacheTtl) {
        presence_cache_ = presence_store_->query_live_ids(presence_ttl_);
        presence_cache_at_ = now;
    }
    return presence_cache_; // copy out under the cache lock, never mu_
}

std::string AgentRegistry::find_agent_by_stream(
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) const {
    std::lock_guard lock(mu_);
    for (const auto& [id, s] : agents_) {
        std::lock_guard slock(s->stream_mu);
        if (s->stream == stream)
            return id;
    }
    return {};
}

std::size_t AgentRegistry::agent_count() const {
    std::lock_guard lock(mu_);
    return agents_.size();
}

void AgentRegistry::map_session(const std::string& session_id, const std::string& agent_id) {
    std::lock_guard lock(mu_);
    session_to_agent_[session_id] = agent_id;
    auto it = agents_.find(agent_id);
    if (it != agents_.end()) {
        it->second->session_id = session_id;
    }
}

std::shared_ptr<AgentSession> AgentRegistry::find_by_session(std::string_view session_id) const {
    std::lock_guard lock(mu_);
    auto sit = session_to_agent_.find(std::string(session_id));
    if (sit == session_to_agent_.end())
        return nullptr;
    auto ait = agents_.find(sit->second);
    return ait != agents_.end() ? ait->second : nullptr;
}

std::shared_ptr<AgentSession> AgentRegistry::get_session(const std::string& agent_id) const {
    std::lock_guard lock(mu_);
    auto it = agents_.find(agent_id);
    return it != agents_.end() ? it->second : nullptr;
}

std::unordered_set<std::string> AgentRegistry::ids_missing_plugin(std::string_view plugin) const {
    std::unordered_set<std::string> missing;
    std::lock_guard lock(mu_);
    for (const auto& [id, s] : agents_) {
        if (s->plugin_names.empty())
            continue; // no reported inventory -- unknown, not absent; fail open
        if (std::ranges::find(s->plugin_names, plugin) == s->plugin_names.end())
            missing.insert(id);
    }
    return missing;
}

// Collect every from_result_set:<id> reference in a scope expression so the
// resolver can preload owner-checked membership once per set. The scope AST is
// a variant of Condition | Combinator (scope_engine.hpp); walk it recursively.
static void collect_result_set_ids(const yuzu::scope::Expression& expr,
                                   std::vector<std::string>& out) {
    if (const auto* cond = std::get_if<yuzu::scope::Condition>(&expr)) {
        if (cond->attribute.starts_with("from_result_set:"))
            out.push_back(cond->attribute.substr(16));
    } else if (const auto* comb =
                   std::get_if<std::unique_ptr<yuzu::scope::Combinator>>(&expr)) {
        if (*comb)
            for (const auto& child : (*comb)->children)
                collect_result_set_ids(child, out);
    }
}

// props.<key> and tag:<key> collection both use the shared
// yuzu::scope::collect_attribute_suffixes (scope_engine.hpp) — added with
// ADR-0050 for exactly this preload pattern. Folding props onto it (Gate 7,
// governance DSL-3/arch-F1) also FIXED a pre-existing defect: the local
// collector this replaced matched the raw attribute, so `LEN(props.x)` /
// `STARTSWITH(props.x, …)` (synthetic `__len:`/`__startswith:` encodings)
// never contributed `x` to the preload and those atoms resolved against
// nothing. collect_result_set_ids above stays local — it is shape-different
// (id extraction, not a prefix-suffix walk) and from_result_set: has no
// synthetic interplay worth encoding.

std::optional<std::vector<std::string>>
AgentRegistry::evaluate_scope(const yuzu::scope::Expression& expr, const TagStore* tag_store,
                              const CustomPropertiesStore* props_store, ResultSetStore* rs_store,
                              std::string_view principal) const {
    // Preload owner-checked membership for every from_result_set:<id> the
    // expression references — once per set, before the agent loop, rather than a
    // store query per agent while holding mu_ (review finding F). The owner join
    // in member_set_owned is the authorization gate: a set `principal` does not
    // own yields an empty membership and therefore never matches, so an operator
    // cannot target another operator's set by id (review finding B1). Aliases
    // are not resolved here; callers that accept aliases pre-resolve them.
    std::unordered_map<std::string, std::unordered_set<std::string>> rs_members;
    {
        // B2 fail-closed (2026-07-26 hardening round; widened per governance
        // H1, 2026-07-29): a scope that references from_result_set: can only
        // be evaluated when BOTH a store and a principal are available to
        // owner-resolve against. Missing either one is the SAME fail-open
        // shape as a degraded preload: an unresolvable from_result_set: atom
        // would otherwise resolve "" (no match) for every agent, and under a
        // NOT combinator that INVERTS to "matches every agent" — a
        // fleet-wide match reachable without any DB error at all. The
        // original guard lived inside `if (rs_store)`, so the callers that
        // pass NO store (e.g. the Guardian push paths) skipped it entirely
        // and silently evaluated the atom false — exactly the inversion
        // hazard, and for a Guardian rule that arms an enforcing guard, a
        // fleet-wide arm. Abort rather than silently no-match. NARROW by
        // construction: a scope with no from_result_set: atom is completely
        // unaffected.
        std::vector<std::string> refs;
        collect_result_set_ids(expr, refs);
        if (!refs.empty() && (rs_store == nullptr || principal.empty())) {
            spdlog::error("AgentRegistry::evaluate_scope: scope references from_result_set: but "
                          "{} — aborting scope evaluation",
                          rs_store == nullptr ? "no ResultSetStore is wired to resolve it"
                                              : "no principal was supplied to owner-resolve "
                                                "against");
            return std::nullopt;
        }
        if (rs_store && !principal.empty()) {
            const std::string owner(principal);
            for (const auto& rsid : refs) {
                if (rs_members.contains(rsid))
                    continue;
                auto mem = rs_store->member_set_owned(rsid, owner);
                if (!mem) {
                    // ADR-0036 fail-closed contract: a Postgres error mid-preload
                    // ABORTS the whole evaluation — never proceed with a partial
                    // membership map. Under a NOT combinator, an atom missing from
                    // rs_members would resolve "" (no match) and INVERT to "matches
                    // every agent" — the concrete fleet-wide fail-open this guards
                    // against (a degraded/transient DB blip must never silently
                    // expand a scope to the entire fleet).
                    spdlog::error("AgentRegistry::evaluate_scope: member_set_owned degraded for "
                                  "result-set '{}' (owner={}) — aborting scope evaluation",
                                  rsid, owner);
                    return std::nullopt;
                }
                // Touch only sets we actually own (non-empty owned membership): keeps
                // a set actively used as scope from being GC'd mid-investigation
                // (review finding I), and never extends another operator's set TTL.
                if (!mem->empty())
                    rs_store->touch(rsid);
                rs_members.emplace(rsid, std::move(*mem));
            }
        }
    }

    // Preload every props.<key> value the expression references, ONE bulk
    // query across all agents rather than a per-agent CustomPropertiesStore
    // round-trip inside the loop below (which would also mean N sequential
    // blocking Postgres calls held under mu_, the exact anti-pattern the
    // from_result_set: preload above was already rewritten to avoid).
    //
    // ADR-0036 fail-closed contract, same shape as the from_result_set:
    // preload: a store/pool/query error here ABORTS the whole evaluation
    // (nullopt) rather than resolving every props.<key> atom to "" (no
    // match) for every agent — under a NOT combinator or `!=`, that silent
    // empty INVERTS to "matches every agent", the identical fleet-wide
    // fail-open ADR-0036 closed for from_result_set:. A caller passing no
    // props_store (a scope with no props.<key> atom, or a call site that
    // doesn't wire one) is unaffected — the preload only runs when the
    // expression actually references props.<key>.
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> props_values;
    {
        std::vector<std::string> prop_keys;
        yuzu::scope::collect_attribute_suffixes(expr, "props.", prop_keys);
        if (!prop_keys.empty()) {
            if (props_store == nullptr) {
                spdlog::error("AgentRegistry::evaluate_scope: scope references props.<key> but no "
                              "CustomPropertiesStore is wired to resolve it — aborting scope "
                              "evaluation");
                return std::nullopt;
            }
            auto preload = props_store->get_values_for_keys(prop_keys);
            if (!preload) {
                spdlog::error("AgentRegistry::evaluate_scope: get_values_for_keys degraded — "
                              "aborting scope evaluation");
                return std::nullopt;
            }
            props_values = std::move(*preload);
        }
    }

    // Preload every tag:<key> value the expression references, ONE bulk query
    // across all agents — mirrors the props.<key> preload directly above
    // (ADR-0050; the pre-migration resolver queried TagStore per agent inside
    // the loop below, and its degraded read collapsed to "" — the silent
    // under/over-target of the #2500 family this migration closes). Same
    // ADR-0036 fail-closed contract: a store/pool/query error ABORTS the
    // whole evaluation (nullopt), never resolves tag:<key> to "no match"
    // (which a NOT combinator inverts to "matches every agent").
    //
    // DELIBERATE ASYMMETRY vs the props preload: a NULL tag_store with a
    // tag: atom does NOT abort. Tags have an in-memory FALLBACK source —
    // session->scopable_tags, consulted only when the store has no row for
    // that (agent, key) (#3295 — the store, any source, wins when present;
    // see the resolver below) — that legitimately answers tag: atoms without
    // any store; props have no such source, so a props.<key> atom without a
    // store is unresolvable and must abort. In production the store cannot
    // be null post-migration (a failed TagStore open is a fatal startup
    // error); a null store here is a test/embedded configuration running on
    // in-memory tags alone.
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> tag_values;
    {
        std::vector<std::string> tag_keys;
        yuzu::scope::collect_attribute_suffixes(expr, "tag:", tag_keys);
        if (!tag_keys.empty() && tag_store != nullptr) {
            auto preload = tag_store->get_values_for_keys(tag_keys);
            if (!preload) {
                spdlog::error("AgentRegistry::evaluate_scope: tag preload degraded — aborting "
                              "scope evaluation");
                return std::nullopt;
            }
            tag_values = std::move(*preload);
        }
    }

    // HA WS-5 (ADR-2002 §7a): preload cross-replica presence OFF mu_, same
    // rule as the from_result_set:/props./tag: preloads above — merged
    // below (after the local loop) for ids this replica has no local
    // session for; local always wins. Cached (live_presence(),
    // kPresenceCacheTtl) so the policy-evaluator's N-policies-per-tick
    // sweep issues one Postgres read per cache window, not N.
    std::vector<PresenceIdentity> presence_rows = live_presence();

    std::vector<std::string> matched;
    std::lock_guard lock(mu_);
    for (const auto& [id, session] : agents_) {
        // DRIFT CONTRACT: every branch below MUST have a matching entry in
        // scope_kind_catalog() (declared just after this class in
        // agent_registry.hpp) — that catalog backs GET /api/v1/discover/scope-kinds
        // and its CROSS-CHECK test. Add the branch AND the catalog entry together.
        // HA WS-5 (governance Gate 3 cpp-expert finding, 2026-09-22): the
        // presence-only resolver a little further down (search "extend the
        // iteration domain with presence") duplicates this lambda's
        // ostype/hostname/arch/agent_version/tag:/props./from_result_set:
        // branches against a PresenceIdentity instead of an AgentSession.
        // The catalog cross-check test does NOT exercise that second copy —
        // a new scope-kind branch added HERE without also updating THAT one
        // silently under-matches presence-only (cross-replica) agents, with
        // no test failure to catch it. Update both together.
        auto resolver = [&](std::string_view attr) -> std::string {
            auto key = std::string(attr);
            // from_result_set:<id> — composable-scope membership (capability
            // §30). EXISTS-semantics: "true" iff this device is an owner-checked
            // member of the preloaded set.
            if (key.starts_with("from_result_set:")) {
                auto it = rs_members.find(key.substr(16));
                return (it != rs_members.end() && it->second.contains(id)) ? "true" : "";
            }
            if (key == "ostype")
                return session->os;
            if (key == "hostname")
                return session->hostname;
            if (key == "arch")
                return session->arch;
            if (key == "agent_version")
                return session->agent_version;
            // tag:X lookups — STORE-FIRST (#3295): the bulk preload above (never
            // a per-agent store query here; see the preload block's
            // fail-closed contract) wins when it has a row for this agent,
            // matching the DEX cohort precedent (server.cpp — "a rogue agent
            // must not self-assign" — same rationale here for dispatch
            // targeting). in-memory scopable_tags is a FALLBACK only, for
            // agents the store has no row for at all (gateway-proxied agents
            // never sync — ProxyRegister has no TagStore call; tracked as
            // #3372). scopable_tags is validated
            // and 'service'-filtered at register_agent ingest, so no
            // additional validation is needed here.
            if (key.starts_with("tag:")) {
                auto tag_key = key.substr(4);
                if (auto agent_it = tag_values.find(id); agent_it != tag_values.end()) {
                    if (auto tag_it = agent_it->second.find(tag_key);
                        tag_it != agent_it->second.end())
                        return tag_it->second;
                }
                auto it = session->scopable_tags.find(tag_key);
                if (it != session->scopable_tags.end())
                    return it->second;
                return {};
            }
            // props.X lookups (custom properties, Phase 7.6) — served from the
            // bulk preload above, never a per-agent store query (see the
            // preload block's comment for the fail-closed contract).
            if (key.starts_with("props.")) {
                auto prop_key = key.substr(6);
                auto agent_it = props_values.find(id);
                if (agent_it != props_values.end()) {
                    auto prop_it = agent_it->second.find(prop_key);
                    if (prop_it != agent_it->second.end())
                        return prop_it->second;
                }
                return {};
            }
            return {};
        };
        if (yuzu::scope::evaluate(expr, resolver)) {
            matched.push_back(id);
        }
    }

    // HA WS-5: extend the iteration domain with presence for ids NOT in the
    // local registry (an id in both wins via the loop above and is never
    // considered twice). tag:/props. already resolve correctly for these
    // ids — tag_values/props_values are id-keyed bulk preloads from
    // Postgres, not scoped to local agents_ — so only
    // ostype/hostname/arch/agent_version need a presence-sourced stand-in
    // (no AgentSession exists for a remote-only id). scopable_tags has no
    // presence-backed fallback (that field is agent-self-reported, kept only
    // in-memory on the replica the agent is actually connected to; the
    // store-first tag_values preload above is the one source presence-only
    // ids can resolve tag: through).
    for (const auto& p : presence_rows) {
        if (agents_.contains(p.agent_id))
            continue;
        auto resolver = [&](std::string_view attr) -> std::string {
            auto key = std::string(attr);
            if (key.starts_with("from_result_set:")) {
                auto it = rs_members.find(key.substr(16));
                return (it != rs_members.end() && it->second.contains(p.agent_id)) ? "true" : "";
            }
            if (key == "ostype")
                return p.os;
            if (key == "hostname")
                return p.hostname;
            if (key == "arch")
                return p.arch;
            if (key == "agent_version")
                return p.agent_version;
            if (key.starts_with("tag:")) {
                auto tag_key = key.substr(4);
                if (auto agent_it = tag_values.find(p.agent_id); agent_it != tag_values.end()) {
                    if (auto tag_it = agent_it->second.find(tag_key);
                        tag_it != agent_it->second.end())
                        return tag_it->second;
                }
                return {};
            }
            if (key.starts_with("props.")) {
                auto prop_key = key.substr(6);
                auto agent_it = props_values.find(p.agent_id);
                if (agent_it != props_values.end()) {
                    auto prop_it = agent_it->second.find(prop_key);
                    if (prop_it != agent_it->second.end())
                        return prop_it->second;
                }
                return {};
            }
            return {};
        };
        if (yuzu::scope::evaluate(expr, resolver)) {
            matched.push_back(p.agent_id);
        }
    }
    return matched;
}

const std::vector<ScopeKindInfo>& scope_kind_catalog() {
    static const std::vector<ScopeKindInfo> catalog = {
        {"from_result_set:<id>", "from_result_set:<id>", "from_result_set:rs_01H8X3ZQK7YB2",
         "Owner-checked membership of a previously-saved result set (composable "
         "scope, docs/scope-walking-design.md). A set the caller does not own "
         "resolves to no match."},
        {"ostype", "ostype <op> <value>", R"(ostype == "windows")",
         "Agent-reported OS family (windows/linux/darwin)."},
        {"hostname", "hostname <op> <value>", R"(hostname LIKE "WIN-%")",
         "Agent-reported hostname."},
        {"arch", "arch <op> <value>", R"(arch == "x86_64")", "Agent-reported CPU architecture."},
        {"agent_version", "agent_version <op> <value>", R"(agent_version == "0.12.0")",
         "Agent daemon version string."},
        {"tag:<key>", "tag:<key> <op> <value>", R"(tag:department == "finance")",
         "Scopable tag value — the persistent TagStore first, falling back to "
         "a connected agent's self-report only when the store has no row "
         "('service' never falls back; see docs/asset-tagging-guide.md)."},
        {"props.<key>", "props.<key> <op> <value>", R"(props.owner == "jdoe")",
         "Custom property value from the CustomPropertiesStore."},
    };
    return catalog;
}

// -- AgentHealthStore ---------------------------------------------------------

void AgentHealthStore::upsert(const std::string& agent_id,
                              const google::protobuf::Map<std::string, std::string>& tags) {
    std::lock_guard lock(mu_);
    auto& snap = snapshots_[agent_id];
    snap.agent_id = agent_id;
    snap.status_tags.clear();
    for (const auto& [k, v] : tags) {
        snap.status_tags[k] = v;
    }
    snap.last_seen = std::chrono::steady_clock::now();
}

void AgentHealthStore::remove(const std::string& agent_id) {
    std::lock_guard lock(mu_);
    snapshots_.erase(agent_id);
}

std::vector<AgentHealthSnapshot>
AgentHealthStore::perf_snapshot(std::chrono::seconds staleness) const {
    std::lock_guard lock(mu_);
    const auto now = std::chrono::steady_clock::now();
    std::vector<AgentHealthSnapshot> out;
    out.reserve(snapshots_.size());
    for (const auto& [id, snap] : snapshots_) {
        if ((now - snap.last_seen) > staleness)
            continue; // same staleness contract recompute_metrics prunes by
        // Copy ONLY the perf tags (G3 performance S1): the full status_tags
        // map is ~12 entries × 2 strings per agent, and this copy runs under
        // the SAME mutex every heartbeat upsert needs — at 10k agents a full
        // deep copy stalls the heartbeat path for tens of milliseconds.
        AgentHealthSnapshot s;
        s.agent_id = snap.agent_id;
        s.last_seen = snap.last_seen;
        for (const char* k : {kPerfTagCpuPct, kPerfTagCommitPct, kPerfTagDiskLatMs}) {
            if (auto it = snap.status_tags.find(k); it != snap.status_tags.end())
                s.status_tags.emplace(it->first, it->second);
        }
        out.push_back(std::move(s));
    }
    return out;
}

std::vector<AgentHealthSnapshot>
AgentHealthStore::net_snapshot(std::chrono::seconds staleness) const {
    std::lock_guard lock(mu_);
    const auto now = std::chrono::steady_clock::now();
    std::vector<AgentHealthSnapshot> out;
    out.reserve(snapshots_.size());
    for (const auto& [id, snap] : snapshots_) {
        if ((now - snap.last_seen) > staleness)
            continue; // same staleness contract recompute_metrics prunes by
        AgentHealthSnapshot s;
        s.agent_id = snap.agent_id;
        s.last_seen = snap.last_seen;
        // Network facts + the perf tags the co-occurrence pressure check reads
        // (same minimal-copy-under-mutex discipline as perf_snapshot).
        for (const char* k : {kNetTagRttP50Ms, kNetTagRetransPct, kNetTagThroughputBps,
                              kNetTagDegraded, kPerfTagCpuPct, kPerfTagCommitPct,
                              kPerfTagDiskLatMs}) {
            if (auto it = snap.status_tags.find(k); it != snap.status_tags.end())
                s.status_tags.emplace(it->first, it->second);
        }
        out.push_back(std::move(s));
    }
    return out;
}

void AgentHealthStore::recompute_metrics(yuzu::MetricsRegistry& metrics,
                                         std::chrono::seconds staleness) {
    std::lock_guard lock(mu_);
    auto now = std::chrono::steady_clock::now();

    // Prune stale entries
    std::erase_if(snapshots_,
                  [&](const auto& pair) { return (now - pair.second.last_seen) > staleness; });

    // Clear labeled gauge families before rebuilding
    metrics.clear_gauge_family("yuzu_fleet_agents_by_os");
    metrics.clear_gauge_family("yuzu_fleet_agents_by_arch");
    metrics.clear_gauge_family("yuzu_fleet_agents_by_version");
    // A4 perf families cleared too: when no agent reports a metric this cycle
    // the series go ABSENT, never a fabricated/stale 0 (the no-mock-data rule).
    metrics.clear_gauge_family("yuzu_fleet_perf_cpu_pct");
    metrics.clear_gauge_family("yuzu_fleet_perf_commit_pct");
    metrics.clear_gauge_family("yuzu_fleet_perf_disk_lat_ms");
    // Network families (slice 3) — same absent-not-zero rule as perf.
    metrics.clear_gauge_family("yuzu_fleet_net_rtt_ms");
    metrics.clear_gauge_family("yuzu_fleet_net_retrans_pct");
    metrics.clear_gauge_family("yuzu_fleet_net_throughput_bps");
    // Cleared so it goes ABSENT when no agent reports the (retired) net_degraded
    // tag — a permanent flatline-0 reads as "0 degraded = healthy", the exact
    // absent-as-zero anti-pattern this rollup forbids (gov happy-path/sre/UP-8).
    metrics.clear_gauge_family("yuzu_fleet_net_degraded");
    // The net gauges are os-labelled (per-OS, never a cross-OS blend), so the
    // reporting denominators must clear too — otherwise an OS that stops reporting
    // leaves a stale {os=...} series.
    metrics.clear_gauge_family("yuzu_fleet_net_reporting");
    metrics.clear_gauge_family("yuzu_fleet_net_retrans_reporting");
    // SparkEngine fleet telemetry (ADR-0021 rung 1) — same absent-not-zero rule:
    // an OS/mechanism that stops reporting goes ABSENT, never a fabricated stale 0
    // (a flatline-0 on a should-stay-0 counter like quarantined reads as "healthy").
    metrics.clear_gauge_family("yuzu_fleet_spark_reporting");
    metrics.clear_gauge_family("yuzu_fleet_spark_disabled");
    metrics.clear_gauge_family("yuzu_fleet_spark_failed");
    metrics.clear_gauge_family("yuzu_fleet_spark_mechanisms");
    metrics.clear_gauge_family("yuzu_fleet_spark_armed_faulted");
    metrics.clear_gauge_family("yuzu_fleet_spark_watch_faults");
    metrics.clear_gauge_family("yuzu_fleet_spark_queued_dropped");
    metrics.clear_gauge_family("yuzu_fleet_spark_consumer_errors");
    metrics.clear_gauge_family("yuzu_fleet_spark_watch_rejected");
    metrics.clear_gauge_family("yuzu_fleet_spark_quarantined");
    metrics.clear_gauge_family("yuzu_fleet_spark_slow_op");
    metrics.clear_gauge_family("yuzu_fleet_spark_unsupported"); // F7, #2298 rung 2
    // Guardian durable lifecycle-journal telemetry (#2298 gate 3). Same rule, and it
    // bites hardest here: the writer is sparse (a 0 counter ships no tag), so on a
    // healthy or inert fleet NOBODY reports and every family must be ABSENT. A
    // fabricated 0 on e.g. _evicted_no_send_evidence would read as "checked, no audit
    // records lost" on a fleet whose journal is not even running.
    for (const auto& m : kGuardianJournalMetrics)
        metrics.clear_gauge_family(m.gauge);
    // The journal AGE family (item 6 + #2364) clears on the same rule. Doubly so, in
    // fact: its staleness gauges are emitted every heartbeat INCLUDING 0 by a LIVE
    // worker, so a stale retained series here would misreport a fleet whose workers
    // all went dark as "fresh forever".
    for (const auto& m : kGuardianJournalAgeMetrics)
        metrics.clear_gauge_family(m.gauge);
    // Guardian M1 health-stream telemetry (#2298 gate 3, item 6d; #2993 added a 4th
    // family, #4783 added the 5th/6th/7th - legacy-sink loss visibility) - same
    // absent-not-zero rule and same reason it bites hardest here: the writer is
    // sparse, so a healthy fleet must see all 7 families ABSENT, never a fabricated
    // 0; an inert (prefer_spark off) fleet still reports the 3 legacy_sink_* families
    // live (they don't depend on the Spark flip - see guardian_health_fleet_tags.hpp).
    for (const auto& m : kGuardianHealthMetrics)
        metrics.clear_gauge_family(m.gauge);
    // rung 9c PR-3: the arm-ledger re-statable-gauge pair (Decision 1) and the
    // io-ceiling monitor-only counter (Decision 3, Option B). Same absent-not-
    // zero rule: on a fleet where no agent is running spark (prefer_spark_ off
    // fleet-wide, today's default), the writer never emits either family at all,
    // so both must go fully ABSENT here, never a fabricated 0 that would read as
    // "spark arming, healthy".
    for (const auto& m : kGuardianArmMetrics)
        metrics.clear_gauge_family(m.gauge);
    for (const auto& m : kGuardianIoCeilingMetrics)
        metrics.clear_gauge_family(m.gauge);

    // Aggregate
    std::unordered_map<std::string, int> os_counts;
    std::unordered_map<std::string, int> arch_counts;
    std::unordered_map<std::string, int> version_counts;
    double total_commands = 0.0;
    int healthy_count = 0;
    int dex_observer_disarmed = 0;
    double total_dex_observed = 0.0;
    // A4: per-agent device-utilization samples from the heartbeat perf tags.
    std::vector<double> perf_cpu, perf_commit, perf_disk_lat;
    // C-S2: the reporting population counts agents contributing ANY of the
    // three metrics — the same reports_any definition DexPerfFleetNow uses,
    // so the gauge and the Performance tab's Reporting card agree.
    int perf_reporting = 0;
    // C1: the SAME samples, additionally bucketed by normalize_os so
    // recompute_perf_os_gauges can export per-OS families — parallel maps,
    // not a restructure of the flat vectors above (the existing four
    // yuzu_fleet_perf_* families stay on their original, untouched path).
    std::unordered_map<std::string, std::vector<double>> perf_cpu_os, perf_commit_os,
        perf_disk_lat_os;
    std::unordered_map<std::string, int> perf_reporting_os;
    // Network heartbeat facts (slice 3) — same shared validators as the
    // /network read model (per-device parity); the dashboard is OS-blended while
    // these gauges are per-OS, so a mixed-fleet aggregate differs by design.
    // Per-OS so the fleet net gauges are never a cross-OS blend: a Windows
    // interval retransmit rate (system-wide, loopback-inclusive, biased low — see
    // network.md/#1465) and a Linux per-connection rate must not average into one
    // number an alert can't decompose (gov sre/consistency/UP-2). Keyed by the
    // agent's `yuzu.os` ("unknown" if unreported), matching yuzu_fleet_agents_by_os.
    std::unordered_map<std::string, std::vector<double>> net_rtt_os, net_retrans_os, net_tput_os;
    std::unordered_map<std::string, int> net_reporting_os, net_degraded_os, net_degraded_reporting_os;
    // The interval retransmit RATE is gauge-eligible only on OSes whose signal is
    // loss-validated. Linux is validated (netem). The Windows rate is system-wide
    // (loopback-inclusive), biased low, and UNVALIDATED (#1465) — so it is WITHHELD
    // from the alerting gauge (it still shows on the /network page + REST, caveated)
    // until validated. RTT is Linux-only anyway; throughput is a real counter on
    // every OS — both stay eligible. Flip this when #1465 validates Windows.
    // NOTE this is DATA HYGIENE (keep an honest Windows agent's biased signal out of
    // the alerting gauge), NOT an authz control: `os` is an enrolled agent's
    // self-reported tag, so a spoofed os="linux" is the same accepted risk as any
    // heartbeat-sourced gauge — the trust boundary is enrollment, not this tag.
    auto retrans_gauge_eligible = [](const std::string& os) { return os == "linux"; };
    // SparkEngine fleet telemetry (ADR-0021 rung 1) — per-OS, and per-{OS,mechanism}
    // for the type-scoped counters. `spark_reporting_os` counts agents running the
    // engine (denominator); `spark_mech_os[os][mechanism]` counts agents whose
    // capability includes that mechanism (from the spark_mechs CSV). The counter
    // maps accumulate the fleet SUM of each cumulative agent counter (a snapshot; an
    // absent {os}/{os,mechanism} series means no agent reported it — 0 by absence).
    std::unordered_map<std::string, int> spark_reporting_os;
    /// Agents that ARE rung-1+ but are not running spark, split by cause:
    /// `disabled` = deliberate (--spark-disable); `failed` = boot-time instantiation
    /// threw and the agent degraded to no-spark. A FAILED agent is the one that must
    /// never hide — see the rollup below (Gate-4 consistency + UP-10).
    std::unordered_map<std::string, int> spark_disabled_os, spark_failed_os;
    std::unordered_map<std::string, std::unordered_map<std::string, int>> spark_mech_os;
    std::unordered_map<std::string, double> spark_armed_faulted_os, spark_watch_faults_os,
        spark_queued_dropped_os, spark_consumer_errors_os;
    std::unordered_map<std::string, std::unordered_map<std::string, double>> spark_watch_rejected_om,
        spark_quarantined_om, spark_slow_op_om, spark_unsupported_om;
    // Per-{mechanism,metric} spark tag keys are loop-invariant across agents AND
    // cycles — build the 3×4 once, not per agent per 15s sweep (gov perf-S1). Indexed
    // [mechanism][metric] in kSparkMechTokens / kSparkMetricTokens order. Function-
    // static: recompute_metrics is single-threaded, and static-local init is
    // thread-safe regardless.
    //
    // Sizes are DERIVED from the token arrays, never hardcoded. spark_fleet_tags.hpp
    // instructs future authors to extend kSparkMechTokens "in lockstep" when a new
    // mechanism lands (e.g. a macOS FSEvents `file` mechanism) — but with a literal 3
    // here, doing exactly that compiled clean and the new token was NEVER READ,
    // silently reproducing the zero-reporting drift the instruction exists to prevent.
    // (governance Gate-3: found independently by cpp-expert and cross-platform.)
    static constexpr std::size_t kNMech = std::size(kSparkMechTokens);
    static constexpr std::size_t kNMetric = std::size(kSparkMetricTokens);
    static const std::array<std::array<std::string, kNMetric>, kNMech> spark_mech_metric_keys = [] {
        std::array<std::array<std::string, kNMetric>, kNMech> keys;
        for (std::size_t mi = 0; mi < kNMech; ++mi)
            for (std::size_t ki = 0; ki < kNMetric; ++ki)
                keys[mi][ki] = spark_type_metric_tag(kSparkMechTokens[mi], kSparkMetricTokens[ki]);
        return keys;
    }();
    // Guardian durable lifecycle-journal telemetry (#2298 gate 3). Table-driven off
    // kGuardianJournalMetrics so the clear (above), the accumulate (in the loop) and
    // the publish (below) can never drift out of step with each other or with the
    // describe() block in server.cpp - adding a signal is ONE table row.
    //
    // UNLABELLED fleet sums: these are integrity/loss signals, so the question is "did
    // ANY endpoint lose a record", which a flat sum answers. No `os` split (contrast
    // the net/spark families) means no agent-controlled label and so no cardinality
    // exposure at all.
    //
    // `reported` is tracked SEPARATELY from the sum rather than inferring "sum > 0 ->
    // somebody reported". They differ in exactly one case: a non-conforming agent that
    // emits an explicit "0" (the real writer is sparse and never does). That IS a
    // report of zero and publishing 0 is the honest reading; inferring from the sum
    // would suppress it and misreport a reporting fleet as absent.
    std::array<double, kNGuardianJournalMetrics> gj_sum{};
    std::array<bool, kNGuardianJournalMetrics> gj_reported{};
    // The AGE family accumulates as MAX, never SUM - the first non-SUM fleet rollup in
    // this function, so stated plainly: a fleet SUM of ages is meaningless (two agents
    // 30 s stale would read as one agent 60 s stale), and the fleet question these
    // answer is "how bad is the WORST endpoint". The op lives here in the consumer
    // because the row struct deliberately has no op field (see the table's comment in
    // guardian_journal_fleet_tags.hpp). `reported` gates publish exactly like the SUM
    // family: MAX over an empty set is absence, never a fabricated 0.
    std::array<double, kNGuardianJournalAgeMetrics> gja_max{};
    std::array<bool, kNGuardianJournalAgeMetrics> gja_reported{};
    // Meta-signals ABOUT the rollup (guardian_journal_fleet_tags.hpp). Published
    // unconditionally, including at 0, unlike the 32 - they are server-owned counts
    // that always have a true value, so 0 is a measurement, not a fabricated zero.
    // `gj_reporting` is the coverage denominator absence otherwise hides; without it a
    // dark telemetry pipeline is indistinguishable from a healthy quiet fleet.
    // `gj_tag_rejected` makes the forged-value parse's drop visible: a rejected value
    // used to vanish silently, and if the rejected agent were the only reporter its
    // family went absent, which reads as clean (governance Gate-4 UP-16 / Gate-5 CH-6).
    int gj_reporting = 0;
    int gj_tag_rejected = 0;
    // std::string twins of the table's C-string tag keys: get_view takes
    // const std::string&, so passing the char* directly would heap-construct a
    // temporary key per lookup - 32 per agent per sweep. Built once (same pattern,
    // and the same governance finding, as spark_mech_metric_keys above). It IS
    // registered for static destruction (non-trivial destructor), which is safe only
    // because health_recompute_thread_ - the sole production reader - is joined in
    // ServerImpl::stop() before exit; there is no std::exit/abort shutdown path.
    static const std::array<std::string, kNGuardianJournalMetrics> gj_keys = [] {
        std::array<std::string, kNGuardianJournalMetrics> keys;
        for (std::size_t i = 0; i < kNGuardianJournalMetrics; ++i)
            keys[i] = kGuardianJournalMetrics[i].tag;
        return keys;
    }();
    // Same static-destruction-safety rationale as gj_keys directly above.
    static const std::array<std::string, kNGuardianJournalAgeMetrics> gja_keys = [] {
        std::array<std::string, kNGuardianJournalAgeMetrics> keys;
        for (std::size_t i = 0; i < kNGuardianJournalAgeMetrics; ++i)
            keys[i] = kGuardianJournalAgeMetrics[i].tag;
        return keys;
    }();
    // Guardian M1 health-stream telemetry (#2298 gate 3, item 6d) - table-driven off
    // kGuardianHealthMetrics exactly like the journal family above: unlabelled fleet
    // SUM (no os split, no agent-controlled cardinality), `reported` tracked
    // separately from the sum for the same non-conforming-explicit-"0" reason.
    std::array<double, kNGuardianHealthMetrics> gh_sum{};
    std::array<bool, kNGuardianHealthMetrics> gh_reported{};
    // rung 9c PR-3: the arm-ledger pair (Decision 1). SUM accumulate - same
    // mechanical shape as the 32-row journal counter family (gj_sum above)
    // despite being RE-STATABLE gauges rather than monotonic counters on the
    // agent side: this reader only ever sees one CURRENT value per agent per
    // sweep either way, so "sum the current values" is correct regardless of
    // whether the agent-side field is cumulative or re-statable.
    std::array<double, kNGuardianArmMetrics> ga_sum{};
    std::array<bool, kNGuardianArmMetrics> ga_reported{};
    int ga_reporting = 0;
    int ga_tag_rejected = 0;
    static const std::array<std::string, kNGuardianArmMetrics> ga_keys = [] {
        std::array<std::string, kNGuardianArmMetrics> keys;
        for (std::size_t i = 0; i < kNGuardianArmMetrics; ++i)
            keys[i] = kGuardianArmMetrics[i].tag;
        return keys;
    }();
    // rung 9c PR-3 (Decision 3, Option B): the io-ceiling monitor-only counter.
    // Genuinely cumulative on the agent side, same SUM shape as the journal
    // family mechanically AND semantically.
    std::array<double, kNGuardianIoCeilingMetrics> gioc_sum{};
    std::array<bool, kNGuardianIoCeilingMetrics> gioc_reported{};
    int gioc_reporting = 0;
    int gioc_tag_rejected = 0;
    static const std::array<std::string, kNGuardianIoCeilingMetrics> gioc_keys = [] {
        std::array<std::string, kNGuardianIoCeilingMetrics> keys;
        for (std::size_t i = 0; i < kNGuardianIoCeilingMetrics; ++i)
            keys[i] = kGuardianIoCeilingMetrics[i].tag;
        return keys;
    }();
    int gh_reporting = 0;
    int gh_tag_rejected = 0;
    // Same static-destruction-safety rationale as gj_keys above.
    static const std::array<std::string, kNGuardianHealthMetrics> gh_keys = [] {
        std::array<std::string, kNGuardianHealthMetrics> keys;
        for (std::size_t i = 0; i < kNGuardianHealthMetrics; ++i)
            keys[i] = kGuardianHealthMetrics[i].tag;
        return keys;
    }();
    // `yuzu.os` is an agent-CONTROLLED heartbeat tag; using it raw as a metric
    // label lets a malicious/buggy agent spray unbounded {os=...} series (a
    // Prometheus cardinality DoS). Allowlist it to the values a real agent emits
    // (kAgentOs: windows/linux/darwin) before it becomes a label — anything else
    // collapses to "other", empty to "unknown". Bounds cardinality to 5 values.
    // (by_arch/by_version carry the same raw-tag exposure — broader fix incl. a
    // registry per-family series cap tracked in #1472.)
    auto normalize_os = [](const std::string& os) -> std::string {
        if (os == "windows" || os == "linux" || os == "darwin")
            return os;
        return os.empty() ? "unknown" : "other";
    };

    int ota_signature_refusing = 0;

    for (const auto& [id, snap] : snapshots_) {
        ++healthy_count;

        auto get = [&](const std::string& key) -> std::string {
            auto it = snap.status_tags.find(key);
            return it != snap.status_tags.end() ? it->second : "";
        };

        // Read via find() rather than get(): the comment below explains that get()
        // memcpy's every value it touches, on every agent, on every sweep. We need
        // only "is this non-zero", so compare in place and copy nothing.
        if (auto it = snap.status_tags.find("yuzu.ota_signature_refused");
            it != snap.status_tags.end() && !it->second.empty() && it->second != "0")
            ++ota_signature_refusing;

        // Non-copying accessor. Every tag VALUE is fully agent-controlled and bounded only
        // by the 4 MB gRPC frame, so `get()` above memcpy's it on every lookup, on every
        // agent, on every 15s sweep — under mu_, the lock heartbeat ingest and every
        // dashboard/REST fleet read also take. The spark CSV's 64-byte cap does NOT close
        // that: it removes the SCAN, not the COPY, because the copy happens before the cap
        // is ever tested (governance Gate-2 security).
        //
        // Used by the spark rollup below so spark contributes no copy. The pre-existing
        // consumers still use `get()` — converting them is a wider change, and the REAL fix
        // is an INGEST bound (AgentHealthStore::upsert still deep-copies the entire tag map
        // with no key-count or value-length cap), which benefits every tag family at once
        // and is tracked as the heartbeat-tag ingest-bound follow-up (issue drafted at
        // governance; number assigned at filing). Do not read this as "the ingest DoS
        // is closed".
        //
        // Safe: mu_ is held for the whole of recompute_metrics (lock at the top of the
        // function), so snap.status_tags is stable and the view outlives every use here.
        auto get_view = [&](const std::string& key) -> std::string_view {
            auto it = snap.status_tags.find(key);
            return it != snap.status_tags.end() ? std::string_view{it->second} : std::string_view{};
        };
        // std::string twins of the fixed kSparkTag* C-string keys: get_view takes
        // const std::string&, so passing the char* constants directly would heap-
        // construct a temporary key per lookup, per spark-reporting agent, per sweep
        // (7 lookups x agents x 4/min). Function-static: built once, same pattern as
        // spark_mech_metric_keys above. (governance Gate-3 cpp-expert N-2.)
        static const std::string kKeySparkRunning{kSparkTagRunning};
        static const std::string kKeySparkMechs{kSparkTagMechs};
        static const std::string kKeySparkArmedFaulted{kSparkTagArmedFaulted};
        static const std::string kKeySparkWatchFaults{kSparkTagWatchFaults};
        static const std::string kKeySparkQueuedDropped{kSparkTagQueuedDropped};
        static const std::string kKeySparkConsumerErrors{kSparkTagConsumerErrors};
        static const std::string kKeySparkDisabled{kSparkTagDisabled};

        auto os_val = get("yuzu.os");
        if (!os_val.empty())
            os_counts[normalize_os(os_val)]++;

        auto arch_val = get("yuzu.arch");
        if (!arch_val.empty())
            arch_counts[arch_val]++;

        auto ver_val = get("yuzu.agent_version");
        if (!ver_val.empty())
            version_counts[ver_val]++;

        // std::stod does NOT throw on "inf"/"nan" — it returns the non-finite value,
        // which a single (rogue/buggy) agent could use to poison a fleet-wide gauge for
        // every operator until it ages out. Accept only finite, non-negative counts.
        auto add_finite_count = [](double& acc, const std::string& s) {
            try {
                double v = std::stod(s);
                if (std::isfinite(v) && v >= 0.0)
                    acc += v;
            } catch (...) {}
        };

        auto cmd_val = get("yuzu.commands_executed");
        if (!cmd_val.empty())
            add_finite_count(total_commands, cmd_val);

        // DEX signal observer: a Windows agent (DEX enabled) reporting "0" failed to
        // arm (or a channel went deaf at runtime). The tag is only emitted by such
        // agents (see agent heartbeat), so absent / other values are correctly not
        // counted as a fault.
        if (get("yuzu.dex_observer_armed") == "0")
            ++dex_observer_disarmed;

        auto dex_val = get("yuzu.dex_observed");
        if (!dex_val.empty())
            add_finite_count(total_dex_observed, dex_val);

        // A4 perf tags — validation rules live in dex_perf_rules.hpp, SHARED
        // with the F2a /dex Performance read model so the Prometheus gauges
        // and the in-product view can never disagree on the same sample.
        // C1: each sample also feeds the *_os twin (same normalize_os the net
        // families use) for recompute_perf_os_gauges — one parse, two pushes.
        const std::string perf_os = normalize_os(os_val);
        bool perf_reported_any = false;
        if (auto v = parse_perf_cpu_pct(get(kPerfTagCpuPct))) {
            perf_cpu.push_back(*v);
            perf_cpu_os[perf_os].push_back(*v);
            perf_reported_any = true;
        }
        if (auto v = parse_perf_commit_pct(get(kPerfTagCommitPct))) {
            perf_commit.push_back(*v);
            perf_commit_os[perf_os].push_back(*v);
            perf_reported_any = true;
        }
        if (auto v = parse_perf_disk_lat_ms(get(kPerfTagDiskLatMs))) {
            perf_disk_lat.push_back(*v);
            perf_disk_lat_os[perf_os].push_back(*v);
            perf_reported_any = true;
        }
        if (perf_reported_any) {
            ++perf_reporting;
            ++perf_reporting_os[perf_os];
        }

        // Network facts — validators shared with network_perf_model.cpp; bucketed
        // by the agent's OS so the rollup stays per-OS (never a cross-OS blend).
        const std::string net_os = normalize_os(os_val);
        bool net_reported_any = false;
        if (auto v = parse_net_rtt_ms(get(kNetTagRttP50Ms))) {
            net_rtt_os[net_os].push_back(*v);
            net_reported_any = true;
        }
        if (auto v = parse_net_retrans_pct(get(kNetTagRetransPct))) {
            // Device DID report a retransmit fact (counts toward net_reporting and
            // shows on the page/REST), but only validated-OS rates feed the gauge.
            if (retrans_gauge_eligible(net_os))
                net_retrans_os[net_os].push_back(*v);
            net_reported_any = true;
        }
        if (auto v = parse_net_throughput_bps(get(kNetTagThroughputBps))) {
            net_tput_os[net_os].push_back(*v);
            net_reported_any = true;
        }
        if (net_reported_any) {
            ++net_reporting_os[net_os];
            // Count degraded only for devices that reported a metric (a forged
            // net_degraded=1 with no valid metric must not exceed the reporting
            // denominator — UP-9). `net_degraded_reporting_os` tracks whether ANY
            // agent of an OS emitted the tag at all, so the gauge can go absent
            // (not 0) when none do — the steady state (the tag is retired; only old
            // agents mid-rolling-upgrade still emit it).
            if (auto d = parse_net_degraded(get(kNetTagDegraded))) {
                ++net_degraded_reporting_os[net_os];
                if (*d)
                    ++net_degraded_os[net_os];
            }
        }

        // SparkEngine fleet telemetry (ADR-0021 rung 1). Bucketed by the same normalized
        // `net_os` (never a cross-OS blend). spark_running is the reporting denominator;
        // spark_mechs (CSV of registered AND FUNCTIONAL mechanism types) gives the
        // per-{os,mechanism} capability; the counters are sparse (absent == 0, never a
        // fabricated 0).
        //
        // NOTE --spark-disable does NOT omit all spark tags — an earlier comment here said
        // so, and that WAS the behaviour, which is exactly why a fleet-wide spark BOOT
        // FAILURE used to be invisible (it emitted nothing, identical to a deliberate
        // opt-out). A disabled agent now reports running=0 + disabled=1; see the else-if
        // below. (governance Gate-3 architect.)
        //
        // Reads go through get_view() — no copy of an agent-controlled value.
        // STRICT parse: only the exact tokens "1" and "0" mean anything. Anything else —
        // "true", " 1", "01", a value from a future rung an old server does not know — is
        // NotReported and contributes to NOTHING. Bucketing unknown values as not-running
        // would drop them into yuzu_fleet_spark_failed{os}, the one gauge documented
        // "alert on it" (Gate-4 UP-6 / consistency C-2).
        const SparkRunState spark_state = parse_spark_running(get_view(kKeySparkRunning));
        if (spark_state == SparkRunState::Running) {
            ++spark_reporting_os[net_os];
            // Capability: split the mechs CSV, bucket each recognised token so the
            // fleet sees which mechanisms this OS supports (and, by absence of a
            // {os,mechanism} series, which it does not).
            for (const auto& tok : spark_mechs_from_csv(get_view(kKeySparkMechs)))
                ++spark_mech_os[net_os][tok];
            // Engine-level cumulative counters (absent == 0).
            if (auto v = parse_spark_count(get_view(kKeySparkArmedFaulted)))
                spark_armed_faulted_os[net_os] += *v;
            if (auto v = parse_spark_count(get_view(kKeySparkWatchFaults)))
                spark_watch_faults_os[net_os] += *v;
            if (auto v = parse_spark_count(get_view(kKeySparkQueuedDropped)))
                spark_queued_dropped_os[net_os] += *v;
            if (auto v = parse_spark_count(get_view(kKeySparkConsumerErrors)))
                spark_consumer_errors_os[net_os] += *v;
            // Per-mechanism-type health counters. Keys are the precomputed
            // loop-invariants (perf-S1), read by the NAMED indices in
            // spark_fleet_tags.hpp (kSparkMetricIdx*), each pinned to its
            // kSparkMetricTokens slot by a static_assert there - a future reorder
            // or insertion fails to compile here rather than silently misattributing
            // one health signal's fleet sum into another gauge family (governance
            // finding, F7/#2298: consistency-auditor C1 / architect). The first
            // three back the fleet alerts and are agent-side CUMULATIVE counters
            // (only grow until agent restart), so their fleet sum can only grow
            // too. unsupported (F7, #2298 rung 2) is a CURRENT gauge instead -
            // GuardianEngine reports a live snapshot each heartbeat, not a running
            // total, so its fleet sum can genuinely decrease. set_mech_gauge below
            // (.set(), never delta-accumulated across sweeps) is identical for all
            // four either way; the distinction is purely in what the agent-reported
            // VALUE means, not in how the server publishes it.
            for (std::size_t mi = 0; mi < kNMech; ++mi) {
                const char* mech = kSparkMechTokens[mi];
                if (auto v = parse_spark_count(
                        get_view(spark_mech_metric_keys[mi][kSparkMetricIdxWatchRejected])))
                    spark_watch_rejected_om[net_os][mech] += *v;
                if (auto v = parse_spark_count(
                        get_view(spark_mech_metric_keys[mi][kSparkMetricIdxQuarantined])))
                    spark_quarantined_om[net_os][mech] += *v;
                if (auto v = parse_spark_count(
                        get_view(spark_mech_metric_keys[mi][kSparkMetricIdxSlowOp])))
                    spark_slow_op_om[net_os][mech] += *v;
                if (auto v = parse_spark_count(
                        get_view(spark_mech_metric_keys[mi][kSparkMetricIdxUnsupported])))
                    spark_unsupported_om[net_os][mech] += *v;
            }
        } else if (spark_state == SparkRunState::NotRunning) {
            // running == "0" — the agent IS rung-1+ and is NOT running spark. Split the
            // deliberate opt-out from a boot FAILURE: without this, a fleet-wide spark
            // boot failure is invisible (it emits nothing distinguishable from an agent
            // that was never asked to run it), which defeats rung 1's stated purpose of
            // proving the engine runs at rest. The DEX sibling already reports
            // enabled-but-deaf as `dex_observer_armed=0` rather than going quiet.
            // (governance Gate-4 consistency + UP-10.)
            // Strict split: a non-conforming spark_disabled value (e.g. "01"/"true" from a
            // forked build) is Unknown → counted in NEITHER bucket, so it can never fabricate
            // a FAILED alert. Same forged-value posture as parse_spark_running (Gate-4 UP-3).
            switch (parse_spark_disabled(get_view(kKeySparkDisabled))) {
            case SparkDisabledState::Disabled:
                ++spark_disabled_os[net_os];
                break;
            case SparkDisabledState::NotDisabled:
                ++spark_failed_os[net_os];
                break;
            case SparkDisabledState::Unknown:
                break; // garbage discriminator — page on neither
            }
        }

        // Guardian durable lifecycle-journal telemetry (#2298 gate 3). Unconditional -
        // unlike spark there is no posture/denominator tag to gate on: the writer is
        // sparse, so simply having a key IS the report. Reads go through get_view() so
        // an agent-controlled value is never copied, and every value goes through the
        // forged-value-safe parse (non-finite is impossible for an integer parse;
        // negative, overlong, garbage and implausible all become "did not report",
        // never 0 - one rogue agent must not poison a fleet integrity gauge).
        bool journal_reported_any = false;
        for (std::size_t i = 0; i < kNGuardianJournalMetrics; ++i) {
            const auto raw = get_view(gj_keys[i]);
            // An ABSENT tag is the sparse writer's "nothing to report" and is not a
            // rejection; a PRESENT value that fails the parse is. The parse returns
            // nullopt for both, so the emptiness test is what separates them - do not
            // collapse these two branches.
            //
            // ONE GAP, ACCEPTED: get_view returns an empty view for a missing key AND
            // for a key present with an empty value, so an agent shipping
            // `"yuzu.guardian_journal_stage_dropped": ""` lands here and is counted as
            // neither reporting nor rejected. Closing it needs a find()-based presence
            // test. Not worth it: an empty value buys a hostile agent exactly what
            // omitting the tag buys (invisible either way), so it opens no evasion the
            // heartbeat trust boundary does not already concede.
            if (raw.empty())
                continue;
            if (auto v = parse_guardian_journal_count(raw)) {
                gj_sum[i] += *v;
                gj_reported[i] = true;
                journal_reported_any = true;
            } else {
                ++gj_tag_rejected;
            }
        }
        if (journal_reported_any)
            ++gj_reporting;
        // AGE family (item 6 + #2364): MAX accumulate. Same parse (an age in seconds
        // sits far below the 1e9 plausibility ceiling for ~31 years of staleness; a
        // forged value beyond it is rejected, not clamped - one rogue agent must not
        // own the fleet MAX forever). Rejections fold into gj_tag_rejected - it counts
        // "journal tags present but unparseable", which these are. DELIBERATELY not
        // fed into journal_reported_any/gj_reporting: that meta-gauge's documented
        // meaning is the COUNTER family's coverage, and quietly widening it would
        // change a reviewed HELP string's truth. Absence composes with MAX exactly as
        // with SUM: an absent tag is skipped and simply does not contend.
        for (std::size_t i = 0; i < kNGuardianJournalAgeMetrics; ++i) {
            const auto raw = get_view(gja_keys[i]);
            if (raw.empty())
                continue;
            if (auto v = parse_guardian_journal_count(raw)) {
                gja_max[i] = std::max(gja_max[i], *v);
                gja_reported[i] = true;
            } else {
                ++gj_tag_rejected;
            }
        }

        // Guardian M1 health-stream telemetry (#2298 gate 3, item 6d). Same
        // absent-vs-rejected split as the journal accumulate above: an empty view is
        // the sparse writer's "nothing to report", not a rejection; a present value
        // that fails the parse is.
        bool health_reported_any = false;
        for (std::size_t i = 0; i < kNGuardianHealthMetrics; ++i) {
            const auto raw = get_view(gh_keys[i]);
            if (raw.empty())
                continue;
            if (auto v = parse_guardian_health_count(raw)) {
                gh_sum[i] += *v;
                gh_reported[i] = true;
                health_reported_any = true;
            } else {
                ++gh_tag_rejected;
            }
        }
        if (health_reported_any)
            ++gh_reporting;

        // rung 9c PR-3 (Decision 1): arm-ledger pair. Same absent-vs-rejected
        // split as every family above - an empty view means this agent did not
        // report (dormant/non-spark, per the writer's own Check A gate), never a
        // rejection.
        bool arm_reported_any = false;
        for (std::size_t i = 0; i < kNGuardianArmMetrics; ++i) {
            const auto raw = get_view(ga_keys[i]);
            if (raw.empty())
                continue;
            if (auto v = parse_guardian_arm_count(raw)) {
                ga_sum[i] += *v;
                ga_reported[i] = true;
                arm_reported_any = true;
            } else {
                ++ga_tag_rejected;
            }
        }
        if (arm_reported_any)
            ++ga_reporting;

        // rung 9c PR-3 (Decision 3, Option B): io-ceiling counter.
        bool io_ceiling_reported_any = false;
        for (std::size_t i = 0; i < kNGuardianIoCeilingMetrics; ++i) {
            const auto raw = get_view(gioc_keys[i]);
            if (raw.empty())
                continue;
            if (auto v = parse_guardian_io_ceiling_count(raw)) {
                gioc_sum[i] += *v;
                gioc_reported[i] = true;
                io_ceiling_reported_any = true;
            } else {
                ++gioc_tag_rejected;
            }
        }
        if (io_ceiling_reported_any)
            ++gioc_reporting;
    }

    // OTA signature refusals (#416/#3807). Counts AGENTS currently reporting a
    // non-zero refusal total, not the refusals themselves — one wedged agent
    // retrying every six hours would otherwise dominate the number and hide how
    // many endpoints are affected, which is the question an operator actually
    // has. This is the only server-side surface for that state: the update path
    // has no status-report RPC and the agent has no /metrics endpoint, so
    // without this the refusal is invisible outside a per-endpoint log.
    metrics.gauge("yuzu_fleet_ota_signature_refusing_agents")
        .set(static_cast<double>(ota_signature_refusing));
    metrics.gauge("yuzu_fleet_agents_healthy").set(static_cast<double>(healthy_count));
    metrics.gauge("yuzu_fleet_agents_dex_observer_disarmed")
        .set(static_cast<double>(dex_observer_disarmed));
    metrics.gauge("yuzu_fleet_dex_observed_total").set(total_dex_observed);

    for (const auto& [os, count] : os_counts) {
        metrics.gauge("yuzu_fleet_agents_by_os", {{"os", os}}).set(static_cast<double>(count));
    }
    for (const auto& [arch, count] : arch_counts) {
        metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", arch}})
            .set(static_cast<double>(count));
    }
    for (const auto& [ver, count] : version_counts) {
        metrics.gauge("yuzu_fleet_agents_by_version", {{"version", ver}})
            .set(static_cast<double>(count));
    }
    metrics.gauge("yuzu_fleet_commands_executed_total").set(total_commands);

    // A4 fleet perf rollup: avg + nearest-rank p50/p90 + max per metric, with a
    // {stat} label (the summary-quantile idiom). The families were cleared above,
    // so a metric nobody reported is ABSENT this cycle — Prometheus consumers see
    // a gap, not a fake zero. `yuzu_fleet_perf_reporting` carries the population
    // size so an "avg" over 3 devices is never misread as fleet-wide.
    auto set_stats = [&](const char* family, std::vector<double>& vals) {
        if (vals.empty())
            return;
        std::sort(vals.begin(), vals.end());
        const auto n = vals.size();
        double sum = 0.0;
        for (double v : vals)
            sum += v;
        metrics.gauge(family, {{"stat", "avg"}}).set(sum / static_cast<double>(n));
        metrics.gauge(family, {{"stat", "p50"}}).set(nearest_rank(vals, 0.50));
        metrics.gauge(family, {{"stat", "p90"}}).set(nearest_rank(vals, 0.90));
        metrics.gauge(family, {{"stat", "max"}}).set(vals.back());
    };
    metrics.gauge("yuzu_fleet_perf_reporting").set(static_cast<double>(perf_reporting));
    set_stats("yuzu_fleet_perf_cpu_pct", perf_cpu);
    set_stats("yuzu_fleet_perf_commit_pct", perf_commit);
    set_stats("yuzu_fleet_perf_disk_lat_ms", perf_disk_lat);
    recompute_perf_os_gauges(metrics, perf_reporting_os, perf_cpu_os, perf_commit_os,
                             perf_disk_lat_os);

    // Network rollup: per-OS {stat,os} distributions + per-OS reporting
    // denominators — never a cross-OS blend (gov sre/consistency/UP-2). Families
    // cleared above → an (os,metric) nobody reported is ABSENT, never a fake zero.
    // `net_retrans_reporting{os}` is the retransmit-rate population (a subset of
    // net_reporting{os} — a device can report RTT while its RetransWindow warms),
    // so an SRE can tell "healthy, low loss" from "collection broken/absent" per
    // OS. `net_degraded{os}` is emitted ONLY when some agent of that OS reported
    // the (retired) tag — otherwise absent, not 0.
    auto set_stats_os = [&](const char* family, const std::string& os,
                            std::vector<double>& vals) {
        if (vals.empty())
            return;
        std::sort(vals.begin(), vals.end());
        const auto n = vals.size();
        double sum = 0.0;
        for (double v : vals)
            sum += v;
        metrics.gauge(family, {{"stat", "avg"}, {"os", os}}).set(sum / static_cast<double>(n));
        metrics.gauge(family, {{"stat", "p50"}, {"os", os}}).set(nearest_rank(vals, 0.50));
        metrics.gauge(family, {{"stat", "p90"}, {"os", os}}).set(nearest_rank(vals, 0.90));
        metrics.gauge(family, {{"stat", "max"}, {"os", os}}).set(vals.back());
    };
    for (auto& [os, n] : net_reporting_os)
        metrics.gauge("yuzu_fleet_net_reporting", {{"os", os}}).set(static_cast<double>(n));
    for (auto& [os, vals] : net_retrans_os)
        metrics.gauge("yuzu_fleet_net_retrans_reporting", {{"os", os}})
            .set(static_cast<double>(vals.size()));
    for (auto& [os, n] : net_degraded_reporting_os)
        if (n > 0)
            metrics.gauge("yuzu_fleet_net_degraded", {{"os", os}})
                .set(static_cast<double>(net_degraded_os[os]));
    for (auto& [os, vals] : net_rtt_os)
        set_stats_os("yuzu_fleet_net_rtt_ms", os, vals);
    for (auto& [os, vals] : net_retrans_os)
        set_stats_os("yuzu_fleet_net_retrans_pct", os, vals);
    for (auto& [os, vals] : net_tput_os)
        set_stats_os("yuzu_fleet_net_throughput_bps", os, vals);

    // SparkEngine fleet telemetry (ADR-0021 rung 1). Only non-empty maps emit, so an
    // OS/mechanism that reported nothing this cycle stays ABSENT (never a stale 0).
    for (auto& [os, n] : spark_reporting_os)
        metrics.gauge("yuzu_fleet_spark_reporting", {{"os", os}}).set(static_cast<double>(n));
    // The two not-running postures, kept SEPARATE. `disabled` is an operator decision
    // and is expected to be non-zero; `failed` means the engine threw at boot and the
    // agent degraded to no-spark — it is the one that must never hide inside the
    // reporting denominator's absence. Alert on `failed`, not on `disabled`.
    for (auto& [os, n] : spark_disabled_os)
        metrics.gauge("yuzu_fleet_spark_disabled", {{"os", os}}).set(static_cast<double>(n));
    for (auto& [os, n] : spark_failed_os)
        metrics.gauge("yuzu_fleet_spark_failed", {{"os", os}}).set(static_cast<double>(n));
    for (auto& [os, mm] : spark_mech_os)
        for (auto& [mech, n] : mm)
            metrics.gauge("yuzu_fleet_spark_mechanisms", {{"os", os}, {"mechanism", mech}})
                .set(static_cast<double>(n));
    for (auto& [os, v] : spark_armed_faulted_os)
        metrics.gauge("yuzu_fleet_spark_armed_faulted", {{"os", os}}).set(v);
    for (auto& [os, v] : spark_watch_faults_os)
        metrics.gauge("yuzu_fleet_spark_watch_faults", {{"os", os}}).set(v);
    for (auto& [os, v] : spark_queued_dropped_os)
        metrics.gauge("yuzu_fleet_spark_queued_dropped", {{"os", os}}).set(v);
    for (auto& [os, v] : spark_consumer_errors_os)
        metrics.gauge("yuzu_fleet_spark_consumer_errors", {{"os", os}}).set(v);
    auto set_mech_gauge = [&](const char* family,
                              std::unordered_map<std::string,
                                                 std::unordered_map<std::string, double>>& m) {
        for (auto& [os, mm] : m)
            for (auto& [mech, v] : mm)
                metrics.gauge(family, {{"os", os}, {"mechanism", mech}}).set(v);
    };
    set_mech_gauge("yuzu_fleet_spark_watch_rejected", spark_watch_rejected_om);
    set_mech_gauge("yuzu_fleet_spark_quarantined", spark_quarantined_om);
    set_mech_gauge("yuzu_fleet_spark_slow_op", spark_slow_op_om);
    set_mech_gauge("yuzu_fleet_spark_unsupported", spark_unsupported_om); // F7, #2298 rung 2

    // Guardian journal rollup (#2298 gate 3). Families were cleared at the top, so a
    // signal NOBODY reported this cycle stays ABSENT - never a fabricated 0. On a
    // healthy, quiescent or inert fleet that is ALL 30, which is the correct reading:
    // the journal has nothing to report, and "nothing to report" must not be
    // presentable as "checked and clean".
    for (std::size_t i = 0; i < kNGuardianJournalMetrics; ++i)
        if (gj_reported[i])
            metrics.gauge(kGuardianJournalMetrics[i].gauge).set(gj_sum[i]);
    // AGE family: the fleet MAX (worst endpoint), same absent-when-unreported rule.
    // Post-flip a live fleet publishes the two staleness gauges every sweep (their
    // writer emits them including 0); pre-flip all three stay absent - dormancy is the
    // writer's nullopt, and nothing here may fabricate a value for it.
    for (std::size_t i = 0; i < kNGuardianJournalAgeMetrics; ++i)
        if (gja_reported[i])
            metrics.gauge(kGuardianJournalAgeMetrics[i].gauge).set(gja_max[i]);
    // The two meta-signals publish ALWAYS, including 0 - that is the point of them.
    // Not cleared above either: a family that is always written never goes stale.
    metrics.gauge(kGuardianJournalReportingGauge).set(static_cast<double>(gj_reporting));
    metrics.gauge(kGuardianJournalTagRejectedGauge)
        .set(static_cast<double>(gj_tag_rejected));

    // rung 9c PR-3: arm-ledger pair (Decision 1) + io-ceiling counter (Decision 3,
    // Option B). Same absent-when-unreported rule as every family above - on a
    // fleet where nothing is running spark this cycle, both stay ABSENT entirely,
    // and the two "reporting" meta-signals below read 0 honestly rather than
    // fabricating a healthy zero for the gauges themselves.
    for (std::size_t i = 0; i < kNGuardianArmMetrics; ++i)
        if (ga_reported[i])
            metrics.gauge(kGuardianArmMetrics[i].gauge).set(ga_sum[i]);
    metrics.gauge(kGuardianArmReportingGauge).set(static_cast<double>(ga_reporting));
    metrics.gauge(kGuardianArmTagRejectedGauge).set(static_cast<double>(ga_tag_rejected));
    for (std::size_t i = 0; i < kNGuardianIoCeilingMetrics; ++i)
        if (gioc_reported[i])
            metrics.gauge(kGuardianIoCeilingMetrics[i].gauge).set(gioc_sum[i]);
    metrics.gauge(kGuardianIoCeilingReportingGauge).set(static_cast<double>(gioc_reporting));
    metrics.gauge(kGuardianIoCeilingTagRejectedGauge)
        .set(static_cast<double>(gioc_tag_rejected));

    // Guardian M1 health-stream rollup (#2298 gate 3, item 6d). Same absent-not-zero
    // rule as the journal family: cleared at the top, so a signal nobody reported this
    // cycle stays ABSENT.
    for (std::size_t i = 0; i < kNGuardianHealthMetrics; ++i)
        if (gh_reported[i])
            metrics.gauge(kGuardianHealthMetrics[i].gauge).set(gh_sum[i]);
    metrics.gauge(kGuardianHealthReportingGauge).set(static_cast<double>(gh_reporting));
    metrics.gauge(kGuardianHealthTagRejectedGauge)
        .set(static_cast<double>(gh_tag_rejected));
}

void AgentHealthStore::recompute_perf_os_gauges(
    yuzu::MetricsRegistry& metrics, std::unordered_map<std::string, int>& reporting_os,
    std::unordered_map<std::string, std::vector<double>>& cpu_os,
    std::unordered_map<std::string, std::vector<double>>& commit_os,
    std::unordered_map<std::string, std::vector<double>>& disk_lat_os) {
    // Absent-not-zero: clear every sweep so an OS that stops reporting leaves
    // no stale series, mirroring the yuzu_fleet_net_*{os} precedent.
    metrics.clear_gauge_family("yuzu_fleet_perf_os_reporting");
    metrics.clear_gauge_family("yuzu_fleet_perf_os_cpu_pct");
    metrics.clear_gauge_family("yuzu_fleet_perf_os_commit_pct");
    metrics.clear_gauge_family("yuzu_fleet_perf_os_disk_lat_ms");
    for (auto& [os, n] : reporting_os)
        metrics.gauge("yuzu_fleet_perf_os_reporting", {{"os", os}}).set(static_cast<double>(n));
    auto set_stats_os = [&](const char* family, const std::string& os,
                            std::vector<double>& vals) {
        if (vals.empty())
            return;
        std::sort(vals.begin(), vals.end());
        double sum = 0.0;
        for (double v : vals)
            sum += v;
        metrics.gauge(family, {{"stat", "avg"}, {"os", os}})
            .set(sum / static_cast<double>(vals.size()));
        metrics.gauge(family, {{"stat", "p50"}, {"os", os}}).set(nearest_rank(vals, 0.50));
        metrics.gauge(family, {{"stat", "p90"}, {"os", os}}).set(nearest_rank(vals, 0.90));
        metrics.gauge(family, {{"stat", "max"}, {"os", os}}).set(vals.back());
    };
    for (auto& [os, vals] : cpu_os)
        set_stats_os("yuzu_fleet_perf_os_cpu_pct", os, vals);
    for (auto& [os, vals] : commit_os)
        set_stats_os("yuzu_fleet_perf_os_commit_pct", os, vals);
    for (auto& [os, vals] : disk_lat_os)
        set_stats_os("yuzu_fleet_perf_os_disk_lat_ms", os, vals);
}

} // namespace yuzu::server::detail
