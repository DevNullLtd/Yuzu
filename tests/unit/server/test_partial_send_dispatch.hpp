#pragma once

// A confined dispatch whose send sink throws on the Nth send, run through the REAL arm code
// (resolve_and_dispatch_confined -> dispatch_confined_arms) and the REAL instrument_sink
// (dispatch_send_progress.hpp), so the partial count a caller reads from its SendProgressScope is
// the one the production sink would report. Shared by the instruction-execute core tests, the
// production-ports [pg] test and the POST /api/v1/commands tests.

#include "dispatch_confined_arms.hpp"
#include "dispatch_scope_ladder.hpp"
#include "dispatch_send_progress.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace yuzu::test {

/// Sends to `ids` (the Ids arm, unfiltered visible set, containment off). Send number
/// `throw_on_nth` (1-based) throws; 0 = never throws. Must be called inside a SendProgressScope
/// for the count to be recorded, exactly like production.
inline yuzu::server::ConfinedDispatchOutcome
dispatch_throwing_on_nth_send(const std::vector<std::string>& ids, int throw_on_nth) {
    int calls = 0;
    yuzu::server::ConfinedDispatchSink raw;
    raw.send_to = [&calls, throw_on_nth](const std::string&) {
        if (++calls == throw_on_nth)
            throw std::runtime_error("send boom");
        return true;
    };
    raw.send_to_all_unfiltered = [] { return 0; };
    raw.known_agent_ids = [] { return std::vector<std::string>{}; };
    const auto sink = yuzu::server::instrument_sink(std::move(raw));
    const yuzu::server::DispatchResolvers resolvers;
    const auto gate = yuzu::server::ContainmentGate::exempt_control_plugin();
    return yuzu::server::resolve_and_dispatch_confined(ids, /*scope_expr=*/"", std::nullopt,
                                                       /*broadcast_on_none=*/false, gate,
                                                       resolvers, sink);
}

} // namespace yuzu::test
