// #5678: the one departure -> durable-presence mirror both disconnect paths
// share (presence_departure.hpp). Pure helper cases drive it with a fake store;
// the wiring case source-scans the two production call sites for the EXACT
// call text (the direct Subscribe path has no unit harness, so this pin is its
// coverage; the gateway path also has a behavioural test in
// test_gateway_route_wiring.cpp). Mechanism: test_store_wiring_order.cpp.

#include <catch2/catch_test_macros.hpp>

#include "presence_departure.hpp"

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using yuzu::server::mirror_departure_to_presence;

namespace {

struct FakeStore {
    std::vector<std::pair<std::string, std::string>> calls;
    bool result = true;
    bool remove_if_session(std::string_view agent, std::string_view session) {
        calls.emplace_back(std::string(agent), std::string(session));
        return result;
    }
};

// Strip `//` comments, then collapse every whitespace run to one space.
std::string normalised_code(const fs::path& file) {
    std::ifstream in(file, std::ios::binary);
    REQUIRE(in.good());
    std::ostringstream out;
    std::string line;
    bool pending_space = false;
    while (std::getline(in, line)) {
        if (const auto c = line.find("//"); c != std::string::npos)
            line.erase(c);
        for (const char ch : line) {
            if (ch == ' ' || ch == '\t' || ch == '\r') {
                pending_space = true;
            } else {
                if (pending_space && out.tellp() > 0)
                    out << ' ';
                pending_space = false;
                out << ch;
            }
        }
        pending_space = true;
    }
    return out.str();
}

std::size_t count_of(const std::string& hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
        ++n;
    return n;
}

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

TEST_CASE("both disconnect paths call the helper with the real gate and no raw remove_if_session",
          "[presence][wiring_order]") {
    // The gateway gate also admits the route directory's deregister result (HA WS-5 slice 2:
    // a non-owning replica removes no local session, so the directory is its only proof).
    struct Site {
        const char* file;
        std::string_view gate;
    };
    for (const Site& site : {Site{"agent_service_impl.cpp", "removed_current_session"},
                             Site{"gateway_service_impl.cpp", "removed_current_session || store_removed"}}) {
        INFO(site.file);
        const auto code = normalised_code(fs::path(YUZU_SERVER_SRC_DIR) / site.file);
        const std::string call = "mirror_departure_to_presence(" + std::string(site.gate) +
                                 ", heartbeat_ingestion_ ? heartbeat_ingestion_->offline_endpoint_store() "
                                 ": nullptr, agent_id, session_id);";
        CHECK(count_of(code, call) == 1);
        CHECK(count_of(code, "->remove_if_session(") == 0);
        CHECK(count_of(code, ".remove_if_session(") == 0);
    }
}
