#pragma once

/**
 * test_provenance_fake.hpp -- a command-record source for ingest harnesses that have no Postgres.
 *
 * Since #4990 a response frame's plugin comes from the SERVER's dispatch record, not from the
 * command id the agent echoes, and a service with neither a tracker nor a record source labels every
 * frame unverified (Forensics-tier). A harness that only wants "this frame came from plugin X"
 * installs this fake: it answers every command id with a record whose plugin is the id's own
 * prefix (the text before the first `-`) and no execution id. That is the pre-#4990 labelling, used
 * here as a TEST DOUBLE for a dispatch record that was written for that plugin; it is exactly the
 * rule production no longer uses, so it must never appear outside tests (the wiring gate
 * tests/test_forensics_tier_wiring_lexical.py pins that server.cpp never calls the override).
 *
 * A harness that exercises the real record (a `TrackerScope`) clears the fake: `TrackerScope`'s
 * constructor does it, so a test that wires a tracker reads the tracker's records and nothing else.
 */

#include <optional>
#include <string>
#include <utility>

#include "agent_service_impl.hpp"
#include "response_provenance.hpp"

namespace yuzu::test {

[[nodiscard]] inline yuzu::server::CommandRecordLookupFn prefix_provenance_lookup() {
    return [](const std::string& command_id,
              std::string* /*degrade_reason*/) -> std::optional<yuzu::server::CommandRecord> {
        const auto dash = command_id.find('-');
        std::string plugin = dash == std::string::npos ? command_id : command_id.substr(0, dash);
        if (plugin.empty())
            return std::nullopt;
        return yuzu::server::CommandRecord{std::move(plugin), std::string{}};
    };
}

inline void use_prefix_provenance(yuzu::server::detail::AgentServiceImpl& svc) {
    svc.override_command_record_lookup(prefix_provenance_lookup());
}

} // namespace yuzu::test
