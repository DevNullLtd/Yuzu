// Pins the agent-side CommandResponse.action stamp (agents/core/src/command_frames.hpp).
// This TU includes the SAME helper agent.cpp builds its frames with, so a change to the helper is
// caught here; the server-side ingest tests stamp the action by hand and cannot see an agent-side
// revert. The call sites in agent.cpp that feed the helper are pinned separately, by
// tests/test_audit_action_stamp_wiring_lexical.py.

#include <catch2/catch_test_macros.hpp>

#include <string>

#include "command_frames.hpp"

using Resp = ::yuzu::agent::v1::CommandResponse;

TEST_CASE("agent command frames: an output frame carries the dispatched action",
          "[agent][command_frames]") {
    const Resp resp =
        yuzu::agent::make_output_frame("cmd-1", "set_value", "audit|op=set_value\nstatus|ok");

    CHECK(resp.command_id() == "cmd-1");
    CHECK(resp.status() == Resp::RUNNING);
    CHECK(resp.output() == "audit|op=set_value\nstatus|ok");
    CHECK(resp.action() == "set_value");
    // `plugin` routes the reserved "__guard__" side channel on the server: it must stay unset.
    CHECK(resp.plugin().empty());
}

TEST_CASE("agent command frames: the final frame carries the action and the exit code",
          "[agent][command_frames]") {
    const Resp ok = yuzu::agent::make_final_frame("cmd-3", "delete_key", 0);
    CHECK(ok.command_id() == "cmd-3");
    CHECK(ok.status() == Resp::SUCCESS);
    CHECK(ok.exit_code() == 0);
    CHECK(ok.action() == "delete_key");
    CHECK(ok.plugin().empty());

    const Resp bad = yuzu::agent::make_final_frame("cmd-4", "delete_value", 1);
    CHECK(bad.status() == Resp::FAILURE);
    CHECK(bad.exit_code() == 1);
    CHECK(bad.action() == "delete_value");

    // An empty action is the proto3 default: nothing is stamped on either frame kind.
    const Resp none_out = yuzu::agent::make_output_frame("cmd-5", "", "line");
    const Resp none_fin = yuzu::agent::make_final_frame("cmd-5", "", 0);
    CHECK(none_out.action().empty());
    CHECK(none_fin.action().empty());
}
