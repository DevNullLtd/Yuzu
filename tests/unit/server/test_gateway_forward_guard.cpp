// test_gateway_forward_guard.cpp -- the spawn/setup guard around
// ServerImpl::forward_gateway_pending's per-command body (gateway_forward_guard.hpp).
//
// The guard exists because the body allocates and spawns a thread, either of which can throw
// under resource pressure, and an escape would unwind the drain loop and destroy every
// not-yet-forwarded command with no terminal response. These tests drive it with a recording
// resolver and recording loggers, so no gateway stub, thread spawn or AgentServiceImpl is needed.
//
// The body in these tests mimics the real one's observable shape: it copies the ids into the
// ForwardAttempt, then MOVES the drained entry away (as the real body does when it captures the
// entry into the worker closure), so a handler that read the entry after that point would see
// empty strings and the "hoisted copies, not the fallback" assertions would catch it.

#include "gateway_forward_guard.hpp"

#include <catch2/catch_test_macros.hpp>

#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using yuzu::server::ForwardAttempt;
using yuzu::server::guarded_forward;
using yuzu::server::kGatewayForwardSpawnFailedDetail;
using yuzu::server::kGatewayForwardSpawnFailedReason;
using yuzu::server::resolve_with_flag;

namespace {

struct Entry {
    std::string cmd_id;
    std::string agent_id;
};

struct ResolveCall {
    std::string agent_id;
    std::string cmd_id;
    std::string reason;
    std::string detail;
};

struct SetupLogCall {
    std::string agent_id;
    std::string cmd_id;
    bool resolved;
};

// Recorders plus switches that make each injected callable throw.
struct Harness {
    std::vector<ResolveCall> resolves;
    std::vector<SetupLogCall> setup_logs;
    std::vector<std::string> not_retried_logs;
    int fallback_cmd_calls = 0;
    int fallback_agent_calls = 0;
    bool resolver_throws = false;
    bool setup_logger_throws = false;
    bool not_retried_logger_throws = false;

    template <class Body> void run(ForwardAttempt& attempt, Entry& entry, Body&& body) {
        guarded_forward(
            attempt, std::forward<Body>(body),
            [&]() -> const std::string& {
                ++fallback_cmd_calls;
                return entry.cmd_id;
            },
            [&]() -> const std::string& {
                ++fallback_agent_calls;
                return entry.agent_id;
            },
            [&](const std::string& aid, const std::string& cid, std::string_view reason,
                std::string_view detail) {
                if (resolver_throws)
                    throw std::bad_alloc();
                resolves.push_back({aid, cid, std::string(reason), std::string(detail)});
            },
            [&](const std::string& aid, const std::string& cid, bool resolved) {
                if (setup_logger_throws)
                    throw std::runtime_error("logger");
                setup_logs.push_back({aid, cid, resolved});
            },
            [&](const std::string& cid) {
                if (not_retried_logger_throws)
                    throw std::runtime_error("logger");
                not_retried_logs.push_back(cid);
            });
    }
};

// What the real body does between "copy the ids" and "spawn the worker": take hoisted copies,
// then move the entry into the worker (here: a sink) so it is left moved-from.
void take_ids_and_move(ForwardAttempt& attempt, Entry& entry, std::vector<Entry>& worker_sink) {
    attempt.cmd_id = entry.cmd_id;
    attempt.agent_id = entry.agent_id;
    worker_sink.push_back(std::move(entry));
    entry.cmd_id.clear();
    entry.agent_id.clear();
}

} // namespace

TEST_CASE("gateway forward guard: the no-throw path resolves and logs nothing",
          "[gateway_forward_guard]") {
    Harness h;
    ForwardAttempt attempt;
    Entry e{"cmd-1", "agent-1"};
    std::vector<Entry> sink;
    int body_calls = 0;
    h.run(attempt, e, [&](ForwardAttempt& a) {
        ++body_calls;
        take_ids_and_move(a, e, sink);
    });
    CHECK(body_calls == 1);
    CHECK(sink.size() == 1);
    CHECK(h.resolves.empty());
    CHECK(h.setup_logs.empty());
    CHECK(h.not_retried_logs.empty());
    // The fallbacks are lazy: nothing reads the entry unless the handler runs.
    CHECK(h.fallback_cmd_calls == 0);
    CHECK(h.fallback_agent_calls == 0);
}

TEST_CASE("gateway forward guard: a throw before the ids are assigned falls back to the entry",
          "[gateway_forward_guard]") {
    Harness h;
    ForwardAttempt attempt;
    Entry e{"cmd-fallback", "agent-fallback"};
    h.run(attempt, e, [&](ForwardAttempt&) { throw std::bad_alloc(); });
    REQUIRE(h.resolves.size() == 1);
    CHECK(h.resolves[0].cmd_id == "cmd-fallback");
    CHECK(h.resolves[0].agent_id == "agent-fallback");
    CHECK(h.resolves[0].reason == "gateway_forward_spawn_failed");
    CHECK(h.resolves[0].reason == kGatewayForwardSpawnFailedReason);
    CHECK(h.resolves[0].detail == kGatewayForwardSpawnFailedDetail);
    REQUIRE(h.setup_logs.size() == 1);
    CHECK(h.setup_logs[0].cmd_id == "cmd-fallback");
    CHECK(h.setup_logs[0].agent_id == "agent-fallback");
    CHECK(h.setup_logs[0].resolved);
    CHECK(h.not_retried_logs.empty());
}

TEST_CASE("gateway forward guard: the stored detail text is pinned byte for byte",
          "[gateway_forward_guard]") {
    // This text is persisted (behind "[gateway_forward_spawn_failed] ") as the command's error
    // detail; it moved out of server.cpp verbatim and must not drift.
    CHECK(std::string(kGatewayForwardSpawnFailedReason) == "gateway_forward_spawn_failed");
    CHECK(std::string(kGatewayForwardSpawnFailedDetail) ==
          "The server could not set up or start the thread that forwards this command to the "
          "gateway (resource exhaustion), command not delivered");
}

TEST_CASE("gateway forward guard: a throw after the ids are assigned uses the hoisted copies",
          "[gateway_forward_guard]") {
    Harness h;
    ForwardAttempt attempt;
    Entry e{"cmd-hoisted", "agent-hoisted"};
    std::vector<Entry> sink;
    h.run(attempt, e, [&](ForwardAttempt& a) {
        take_ids_and_move(a, e, sink);
        throw std::runtime_error("after the entry was moved");
    });
    // The entry is moved-from; a handler reading it would resolve "" / "".
    REQUIRE(e.cmd_id.empty());
    REQUIRE(h.resolves.size() == 1);
    CHECK(h.resolves[0].cmd_id == "cmd-hoisted");
    CHECK(h.resolves[0].agent_id == "agent-hoisted");
    CHECK(h.fallback_cmd_calls == 0);
    CHECK(h.fallback_agent_calls == 0);
    REQUIRE(h.setup_logs.size() == 1);
    CHECK(h.setup_logs[0].cmd_id == "cmd-hoisted");
    CHECK(h.setup_logs[0].agent_id == "agent-hoisted");
}

TEST_CASE("gateway forward guard: a throw at the spawn point resolves the command once",
          "[gateway_forward_guard]") {
    // Ids assigned, flag still false: this is the std::thread constructor throwing
    // std::system_error after the worker closure captured the entry.
    Harness h;
    ForwardAttempt attempt;
    Entry e{"cmd-spawn", "agent-spawn"};
    std::vector<Entry> sink;
    h.run(attempt, e, [&](ForwardAttempt& a) {
        take_ids_and_move(a, e, sink);
        throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));
    });
    REQUIRE(h.resolves.size() == 1);
    CHECK(h.resolves[0].cmd_id == "cmd-spawn");
    CHECK(h.resolves[0].agent_id == "agent-spawn");
    CHECK(h.not_retried_logs.empty());
}

TEST_CASE(
    "gateway forward guard: resolve_with_flag raises the flag after the build, before the apply",
    "[gateway_forward_guard]") {
    ForwardAttempt attempt;
    bool flag_during_build = true;
    bool flag_during_apply = false;
    int applied_value = 0;
    resolve_with_flag(
        attempt,
        [&] {
            flag_during_build = attempt.resolve_attempted;
            return 42;
        },
        [&](const int& v) {
            flag_during_apply = attempt.resolve_attempted;
            applied_value = v;
        });
    CHECK_FALSE(flag_during_build);
    CHECK(flag_during_apply);
    CHECK(applied_value == 42);
    CHECK(attempt.resolve_attempted);
}

TEST_CASE("gateway forward guard: a throwing build leaves the flag down, so the handler resolves",
          "[gateway_forward_guard]") {
    Harness h;
    ForwardAttempt attempt;
    Entry e{"cmd-build", "agent-build"};
    int apply_calls = 0;
    h.run(attempt, e, [&](ForwardAttempt& a) {
        a.cmd_id = e.cmd_id;
        a.agent_id = e.agent_id;
        resolve_with_flag(
            a, []() -> int { throw std::bad_alloc(); }, [&](const int&) { ++apply_calls; });
    });
    CHECK(apply_calls == 0);
    CHECK_FALSE(attempt.resolve_attempted);
    REQUIRE(h.resolves.size() == 1);
    CHECK(h.resolves[0].cmd_id == "cmd-build");
    CHECK(h.not_retried_logs.empty());
}

TEST_CASE("gateway forward guard: a throwing apply is NOT retried and is logged",
          "[gateway_forward_guard]") {
    // process_gateway_response is not idempotent: once the flag is up, a partial failure of the
    // apply must never produce a second terminal write.
    Harness h;
    ForwardAttempt attempt;
    Entry e{"cmd-apply", "agent-apply"};
    h.run(attempt, e, [&](ForwardAttempt& a) {
        a.cmd_id = e.cmd_id;
        a.agent_id = e.agent_id;
        resolve_with_flag(
            a, [] { return 1; }, [](const int&) { throw std::runtime_error("apply half-failed"); });
    });
    CHECK(attempt.resolve_attempted);
    CHECK(h.resolves.empty());
    CHECK(h.setup_logs.empty());
    REQUIRE(h.not_retried_logs.size() == 1);
    CHECK(h.not_retried_logs[0] == "cmd-apply");
}

TEST_CASE("gateway forward guard: a resolver that throws is reported, not propagated",
          "[gateway_forward_guard]") {
    Harness h;
    h.resolver_throws = true;
    ForwardAttempt attempt;
    Entry e{"cmd-r", "agent-r"};
    REQUIRE_NOTHROW(h.run(attempt, e, [&](ForwardAttempt&) { throw std::bad_alloc(); }));
    CHECK(h.resolves.empty());
    REQUIRE(h.setup_logs.size() == 1);
    // "the terminal write ALSO failed" arm of the log line.
    CHECK_FALSE(h.setup_logs[0].resolved);
    CHECK(h.setup_logs[0].cmd_id == "cmd-r");
}

TEST_CASE("gateway forward guard: a logger that throws is swallowed on both arms",
          "[gateway_forward_guard]") {
    SECTION("setup-failed arm") {
        Harness h;
        h.setup_logger_throws = true;
        ForwardAttempt attempt;
        Entry e{"cmd-l1", "agent-l1"};
        REQUIRE_NOTHROW(h.run(attempt, e, [&](ForwardAttempt&) { throw std::bad_alloc(); }));
        CHECK(h.resolves.size() == 1);
    }
    SECTION("not-retried arm") {
        Harness h;
        h.not_retried_logger_throws = true;
        ForwardAttempt attempt;
        Entry e{"cmd-l2", "agent-l2"};
        REQUIRE_NOTHROW(h.run(attempt, e, [&](ForwardAttempt& a) {
            a.cmd_id = e.cmd_id;
            a.agent_id = e.agent_id;
            a.resolve_attempted = true;
            throw std::bad_alloc();
        }));
        CHECK(h.resolves.empty());
    }
    SECTION("resolver and logger both throw") {
        Harness h;
        h.resolver_throws = true;
        h.setup_logger_throws = true;
        ForwardAttempt attempt;
        Entry e{"cmd-l3", "agent-l3"};
        REQUIRE_NOTHROW(h.run(attempt, e, [&](ForwardAttempt&) { throw std::bad_alloc(); }));
        CHECK(h.resolves.empty());
        CHECK(h.setup_logs.empty());
    }
}

TEST_CASE("gateway forward guard: a throw on command 2 leaves commands 1 and 3 untouched",
          "[gateway_forward_guard]") {
    Harness h;
    ForwardAttempt attempt; // one attempt reused across the loop, like the real drain loop
    std::vector<Entry> drained{{"cmd-1", "agent-1"}, {"cmd-2", "agent-2"}, {"cmd-3", "agent-3"}};
    std::vector<Entry> sink;
    int bodies_completed = 0;
    for (auto& e : drained) {
        h.run(attempt, e, [&](ForwardAttempt& a) {
            take_ids_and_move(a, e, sink);
            if (a.cmd_id == "cmd-2")
                throw std::runtime_error("spawn failed");
            ++bodies_completed;
        });
    }
    CHECK(bodies_completed == 2);
    REQUIRE(h.resolves.size() == 1);
    CHECK(h.resolves[0].cmd_id == "cmd-2");
    CHECK(h.resolves[0].agent_id == "agent-2");
    CHECK(sink.size() == 3);
}

TEST_CASE("gateway forward guard: state from one command never leaks into the next",
          "[gateway_forward_guard]") {
    // Command 1 throws from the apply with the flag up and ids set. Command 2 throws before it
    // assigns anything: it must resolve against ITS OWN entry with the flag down, not inherit
    // command 1's ids or its "resolve already attempted" flag.
    Harness h;
    ForwardAttempt attempt;
    Entry e1{"cmd-1", "agent-1"};
    Entry e2{"cmd-2", "agent-2"};
    h.run(attempt, e1, [&](ForwardAttempt& a) {
        a.cmd_id = e1.cmd_id;
        a.agent_id = e1.agent_id;
        resolve_with_flag(
            a, [] { return 0; }, [](const int&) { throw std::runtime_error("apply"); });
    });
    REQUIRE(h.not_retried_logs.size() == 1);
    REQUIRE(h.resolves.empty());
    h.run(attempt, e2, [&](ForwardAttempt&) { throw std::bad_alloc(); });
    REQUIRE(h.resolves.size() == 1);
    CHECK(h.resolves[0].cmd_id == "cmd-2");
    CHECK(h.resolves[0].agent_id == "agent-2");
    CHECK(h.not_retried_logs.size() == 1);
}

TEST_CASE("gateway forward guard: reset clears every field", "[gateway_forward_guard]") {
    ForwardAttempt a;
    a.cmd_id = "c";
    a.agent_id = "a";
    a.resolve_attempted = true;
    a.reset();
    CHECK(a.cmd_id.empty());
    CHECK(a.agent_id.empty());
    CHECK_FALSE(a.resolve_attempted);
}
