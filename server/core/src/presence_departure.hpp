#pragma once

// The ONE departure -> durable-presence mirror shared by both disconnect paths
// (direct Subscribe teardown in agent_service_impl.cpp and the gateway
// DISCONNECTED handler in gateway_service_impl.cpp). Pure, templated on the
// store so a unit test drives it with a fake.
//
// A graceful disconnect clears the durable row's session_id
// (OfflineEndpointStore::remove_if_session); the row stays for the offline
// /hardware roster (#5678). Gate rationale: AgentRegistry::remove_agent_if_session
// doc, agent_registry.hpp.
//
// Returns true only when the durable session was actually cleared: the gate was
// open, a store is wired, and remove_if_session matched the stored session. A
// false return (gate closed, no store, session mismatch or a best-effort store
// failure) is never an error the caller must act on.

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
