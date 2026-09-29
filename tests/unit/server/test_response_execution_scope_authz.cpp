#include "response_store.hpp"
#include "test_response_execution_authz_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

httplib::Request bearer_request(const std::string& token) {
    httplib::Request req;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif

// #2542 PR-11: reads response_routes.cpp (the extracted owner file), not
// server.cpp — the 3-route legacy pre-v1 Responses API moved from
// server.cpp's inline `web_server_->` registrations onto the HttpRouteSink
// seam (`sink.Get`, `deps.fleet_read_fn`/`deps.store`/`deps.audit_fn`
// replacing the bare `require_fleet_read`/`response_store_`/`audit_log`
// calls). Handler bodies are otherwise byte-identical (verified against the
// pre-move source before this update); mirrors
// test_legacy_executions_scope_authz.cpp's identical #2542 PR-7 adaptation.
std::string read_response_routes_cpp() {
    std::ifstream input(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "response_routes.cpp");
    REQUIRE(input.is_open());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string read_source_file(const std::string& filename) {
    std::ifstream input(std::filesystem::path(YUZU_SERVER_SRC_DIR) / filename);
    REQUIRE(input.is_open());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string route_block(const std::string& source, const std::string& marker) {
    const auto begin = source.find(marker);
    REQUIRE(begin != std::string::npos);
    // #2542 PR-11: end-of-block sentinel updated from server.cpp's
    // `web_server_->` receiver to response_routes.cpp's `sink.` receiver.
    const auto end = source.find("sink.", begin + marker.size());
    return source.substr(begin, (end == std::string::npos ? source.size() : end) - begin);
}

// Generic route-block extractor for files that don't share server.cpp's
// `web_server_->` end-of-function idiom: bounded by an explicit end marker
// instead (the next route registration, or a function-tail sentinel string).
std::string route_block_bounded(const std::string& source, const std::string& start_marker,
                                const std::string& end_marker) {
    const auto begin = source.find(start_marker);
    REQUIRE(begin != std::string::npos);
    const auto end = source.find(end_marker, begin + start_marker.size());
    REQUIRE(end != std::string::npos);
    return source.substr(begin, end - begin);
}

} // namespace

TEST_CASE("legacy response list: real fleet-read scope excludes Alice's response row",
          "[pg][response][scope][1634]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    yuzu::test::ResponseExecutionAuthzPgRig rig{db.dsn()};
    auto req = bearer_request(rig.mint_bob());
    httplib::Response res;
    auto authority = rig.auth_routes->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(authority.has_value());

    std::vector<StoredResponse> responses(2);
    responses[0].agent_id = "bob-agent";
    responses[0].output = "bob-output";
    responses[1].agent_id = "alice-agent";
    responses[1].output = "alice-output";

    std::vector<StoredResponse> visible;
    for (auto& response : responses) {
        if (authz::in_scope(authority->visible_for_query(), response.agent_id))
            visible.push_back(std::move(response));
    }
    REQUIRE(visible.size() == 1);
    CHECK(visible[0].agent_id == "bob-agent");
    CHECK(visible[0].output == "bob-output");
}

TEST_CASE("legacy response routes retain the fleet gate and pre-serve scope filters",
          "[response][scope][1634][source_tripwire]") {
    const auto source = read_response_routes_cpp();
    const auto aggregate = route_block(source, R"(/api/responses/([^/]+)/aggregate)");
    const auto export_route = route_block(source, R"(/api/responses/([^/]+)/export)");
    const auto list = route_block(source, R"(/api/responses/(.+))");

    for (const auto* block : {&aggregate, &export_route, &list}) {
        CHECK(block->find("deps.fleet_read_fn(req, res, \"Response\", \"Read\")") !=
              std::string::npos);
        CHECK(block->find("deps.perm_fn(req, res, \"Response\", \"Read\")") == std::string::npos);
        CHECK(block->find("authz::in_scope") != std::string::npos);
    }
    CHECK(aggregate.find("deps.store->aggregate") != std::string::npos);
    CHECK(aggregate.find("agg_scope") < aggregate.find("deps.store->aggregate"));
    CHECK(list.find(R"({"count", arr.size()})") != std::string::npos);
}

// #1634 (Doomgoose review finding, important): the SSE per-event scope
// projection (`classify_execution_event_for_scope`/
// `sanitize_execution_event_for_scope`) is enforced only inside two
// httplib route-registration lambdas — server.cpp's route family gets the
// tripwire above, but these two never did. Deleting either call left the
// whole suite green before this test existed: unit tests exercise the
// classifier function directly (test_execution_event_bus.cpp), never the
// actual SSE handler's use of it. This pins the call site, not the
// function's own logic.
TEST_CASE("REST /api/v1/events: scope projection call sites are present in source",
          "[source_tripwire][1634][scope]") {
    const auto source = read_source_file("rest_api_v1.cpp");
    const auto block = route_block_bounded(source, R"d(sink.Get("/api/v1/events")d",
                                           "registered all routes at /api/v1/*");
    CHECK(block.find("classify_execution_event_for_scope(ev, scope)") != std::string::npos);
    CHECK(block.find("sanitize_execution_event_for_scope(ev)") != std::string::npos);
    CHECK(block.find("ExecutionEventVerdict::kDrop") != std::string::npos);
    CHECK(block.find("ExecutionEventVerdict::kSanitize") != std::string::npos);
}

TEST_CASE("Dashboard SSE /sse/executions/{id}: scope projection call sites are present in source",
          "[source_tripwire][1634][scope]") {
    const auto source = read_source_file("workflow_routes.cpp");
    const auto block =
        route_block_bounded(source, R"d(sink.Get(R"(/sse/executions/([A-Za-z0-9_-]{1,128}))")d",
                            R"d(sink.Get("/fragments/schedules")d");
    CHECK(block.find("classify_execution_event_for_scope(ev, scope)") != std::string::npos);
    CHECK(block.find("sanitize_execution_event_for_scope(ev)") != std::string::npos);
    CHECK(block.find("ExecutionEventVerdict::kDrop") != std::string::npos);
    CHECK(block.find("ExecutionEventVerdict::kSanitize") != std::string::npos);
}
