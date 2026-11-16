// #5678: the one departure -> durable-presence mirror both disconnect paths
// share (presence_departure.hpp), driven with a fake store. The call-site wiring
// pin is tests/test_presence_departure_wiring_lexical.py (source text is gated in
// Python, not C++); the gateway path also has a behavioural test in
// test_gateway_route_wiring.cpp.

#include <catch2/catch_test_macros.hpp>

#include "presence_departure.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

using yuzu::server::mirror_arrival_to_presence;
using yuzu::server::mirror_departure_to_presence;

namespace {

struct FakeStore {
    std::vector<std::pair<std::string, std::string>> calls;
    bool result = true;
    bool remove_if_session(std::string_view agent, std::string_view session) {
        calls.emplace_back(std::string(agent), std::string(session));
        return result;
    }
    std::vector<std::pair<std::string, std::string>> arrivals;
    bool clear_plugins_of_other_sessions(std::string_view agent, std::string_view session) {
        arrivals.emplace_back(std::string(agent), std::string(session));
        return result;
    }
};

} // namespace

TEST_CASE("mirror_departure_to_presence gates on removed_current_session", "[presence]") {
    FakeStore store;

    SECTION("a stale disconnect (gate false) never touches the store") {
        CHECK_FALSE(mirror_departure_to_presence(false, &store, "a", "s"));
        CHECK(store.calls.empty());
    }
    SECTION("a null store is a no-op") {
        CHECK_FALSE(mirror_departure_to_presence<FakeStore>(true, nullptr, "a", "s"));
    }
    SECTION("gate true forwards exactly one call and returns the store's result") {
        CHECK(mirror_departure_to_presence(true, &store, "agent-1", "sess-1"));
        REQUIRE(store.calls.size() == 1);
        CHECK(store.calls[0].first == "agent-1");
        CHECK(store.calls[0].second == "sess-1");
        store.result = false;
        CHECK_FALSE(mirror_departure_to_presence(true, &store, "agent-1", "sess-1"));
        CHECK(store.calls.size() == 2);
    }
}

TEST_CASE("mirror_arrival_to_presence forwards the new session and refuses empty input",
          "[presence]") {
    FakeStore store;
    CHECK_FALSE(mirror_arrival_to_presence<FakeStore>(nullptr, "a", "s")); // no store: no-op
    CHECK_FALSE(mirror_arrival_to_presence(&store, "", "s"));
    CHECK_FALSE(mirror_arrival_to_presence(&store, "a", ""));
    CHECK(store.arrivals.empty());
    CHECK(mirror_arrival_to_presence(&store, "agent-1", "sess-2"));
    REQUIRE(store.arrivals.size() == 1);
    CHECK(store.arrivals[0].first == "agent-1");
    CHECK(store.arrivals[0].second == "sess-2");
    store.result = false; // a store failure is reported, never thrown
    CHECK_FALSE(mirror_arrival_to_presence(&store, "agent-1", "sess-2"));
}
