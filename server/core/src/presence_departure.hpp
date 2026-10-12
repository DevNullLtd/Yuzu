#pragma once

// The ONE departure -> durable-presence mirror shared by both disconnect paths
// (direct Subscribe teardown in agent_service_impl.cpp and the gateway
// DISCONNECTED handler in gateway_service_impl.cpp). Pure: no I/O, templated
// on the store so a unit test drives it with a fake.
//
// HA WS-5 (ADR-2002 §7a) + #5678: a graceful disconnect CLEARS the durable
// row's session_id (OfflineEndpointStore::remove_if_session) so the agent
// drops out of scope-evaluation presence, while the row itself stays for the
// offline-inclusive /hardware roster.
//
// Gated on `removed_current_session` (the return of
// AgentRegistry::remove_agent_if_session): the durable row's session_id is
// heartbeat-driven, not registration-driven, so on an ordinary same-replica
// reconnect (S1 superseded locally by an S2 that has not heartbeated yet) the
// row can still read S1's session_id. An ungated clear would drop a LIVE
// agent from presence. A false gate means this disconnect notice is stale and
// must not touch the durable row at all.

#include <string_view>

namespace yuzu::server {

template <class PresenceStore>
bool mirror_departure_to_presence(bool removed_current_session, PresenceStore* store,
                                  std::string_view agent_id, std::string_view session_id) {
    if (!removed_current_session || store == nullptr)
        return false;
    return store->remove_if_session(agent_id, session_id);
}

} // namespace yuzu::server
