// #4990 wave A: the paths that carry Forensics-tier plugin output OUTSIDE the stored-response
// read seam. Each case drives the real ingest (AgentServiceImpl::process_gateway_response) or the
// real consumer and asserts the exact observable output, with an ordinary-plugin control so a
// filter that silenced everything would fail too.
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "event_bus.hpp"
#include "test_forensics_tier_fixture.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
using yuzu::server::detail::SseEvent;
namespace apb = ::yuzu::agent::v1;

namespace {

constexpr const char* kMarker = "marker-4990-live-row";

apb::CommandResponse running_frame(const std::string& command_id, const std::string& output) {
    apb::CommandResponse r;
    r.set_command_id(command_id);
    r.set_status(apb::CommandResponse::RUNNING);
    r.set_output(output);
    return r;
}

/// A service with a subscriber on the shared event bus (the bus the legacy `/events` stream and
/// every dashboard session read). No stores: the live-row publish is unconditional.
struct LiveBusHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry, bus, /*require_client_identity=*/false, auth_mgr, auto_approve,
                         metrics, /*gateway_mode=*/false};
    std::vector<SseEvent> seen;
    std::size_t sub{};

    LiveBusHarness() {
        sub = bus.subscribe([this](const SseEvent& e) { seen.push_back(e); });
    }
    ~LiveBusHarness() { bus.unsubscribe(sub); }

    std::vector<SseEvent> output_events() const {
        std::vector<SseEvent> out;
        std::ranges::copy_if(seen, std::back_inserter(out),
                             [](const SseEvent& e) { return e.event_type == "output"; });
        return out;
    }
    std::size_t marker_count() const {
        std::size_t n = 0;
        for (const auto& e : seen)
            if (e.data.find(kMarker) != std::string::npos)
                ++n;
        return n;
    }
};

} // namespace

TEST_CASE("live output bus: a Forensics-tier plugin's rows are never published",
          "[server][forensics_tier][security]") {
    LiveBusHarness h;
    h.svc.set_forensics_plugin_set(&test::forensics_plugin_set());

    SECTION("ordinary plugin control: the row reaches the bus") {
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0001", kMarker));
        const auto out = h.output_events();
        REQUIRE(out.size() == 1);
        CHECK(out[0].data.find(kMarker) != std::string::npos);
    }
    SECTION("every Forensics plugin, in any ASCII case, publishes nothing") {
        for (const auto& plugin : test::forensics_plugin_set().names()) {
            h.svc.process_gateway_response("agent-1", running_frame(plugin + "-0001", kMarker));
            std::string upper = plugin;
            for (auto& c : upper)
                if (c >= 'a' && c <= 'z')
                    c = static_cast<char>(c - 'a' + 'A');
            h.svc.process_gateway_response("agent-1", running_frame(upper + "-0002", kMarker));
        }
        CHECK(h.output_events().empty());
        CHECK(h.marker_count() == 0);
    }
    SECTION("a mixed batch: only the ordinary plugin's frame publishes") {
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kForensicsPlugin} + "-0001", kMarker));
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0002", kMarker));
        CHECK(h.output_events().size() == 1);
        CHECK(h.marker_count() == 1);
    }
}

TEST_CASE("live output bus: an unwired plugin set publishes no output row at all",
          "[server][forensics_tier][security]") {
    LiveBusHarness h; // set_forensics_plugin_set deliberately not called
    h.svc.process_gateway_response(
        "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0001", kMarker));
    h.svc.process_gateway_response(
        "agent-1", running_frame(std::string{test::kForensicsPlugin} + "-0002", kMarker));
    CHECK(h.output_events().empty());
    CHECK(h.marker_count() == 0);

    // Wiring the set turns the control back on: the silence above was the unwired state, not a
    // harness that never publishes.
    h.svc.set_forensics_plugin_set(&test::forensics_plugin_set());
    h.svc.process_gateway_response(
        "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0003", kMarker));
    CHECK(h.output_events().size() == 1);
}
