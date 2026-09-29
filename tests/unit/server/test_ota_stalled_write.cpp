/**
 * test_ota_stalled_write.cpp — the load-bearing claim behind #911 UP-101:
 * that `ServerContext::TryCancel()`, fired from the watchdog's sweeper thread,
 * actually unblocks a SYNCHRONOUS `grpc::ServerWriter::Write` that has stalled
 * on a collapsed HTTP/2 receive window.
 *
 * WHY THIS TEST HAD TO EXIST. Everything else about the watchdog is covered
 * deterministically in `test_ota_transfer_watchdog.cpp` with an injected clock
 * and a flag standing in for the cancel. But that leaves the one thing the whole
 * mechanism rests on unproven: those tests would pass identically if
 * `TryCancel` did nothing to a blocked write. A gate-1 review flagged exactly
 * that. gRPC's sync API has no per-write deadline and keepalive does not detect
 * this case — a peer with a zero receive window keeps answering pings — so if
 * this claim were false, `DownloadUpdate` would pin a server thread forever and
 * the P0 would be unfixed while every other test stayed green.
 *
 * HOW IT AVOIDS NEEDING A PACKAGE ON DISK. The production handler streams from
 * an `UpdateRegistry`, which needs a `PgPool`. This test instead stands up a
 * test-local service that derives from the SAME `pb::AgentService::Service` and
 * overrides `DownloadUpdate` to stream from memory through a REAL
 * `OtaTransferWatchdog` with its REAL sweeper thread. No proto change, no
 * production test-seam, no Postgres. What it proves is the MECHANISM; that the
 * production handler wires that mechanism the same way is covered by
 * `test_ota_download_bound.cpp` and by reading the handler.
 *
 * The stall is produced honestly: the client starts the call and then never
 * calls `Read()`. Its receive window fills, it stops issuing window updates, and
 * the server's `Write` blocks with no way out but cancellation.
 */

#include "ota_transfer_watchdog.hpp"

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>

#include "agent.grpc.pb.h"

using yuzu::server::OtaTransferWatchdog;

namespace {

namespace apb = ::yuzu::agent::v1;

// A safety ceiling on how much we will push before declaring the test itself
// broken. If the write never blocks, something about the transport's flow
// control changed and this test is no longer measuring what it claims — that is
// a failure, not a pass.
constexpr int kMaxChunksBeforeGivingUp = 2000; // x 64 KiB = 128 MiB

struct StallHarness {
    // Real sweeper thread on a brisk interval, and a short transfer deadline:
    // together they bound how long the blocked write stays blocked.
    OtaTransferWatchdog wd{std::chrono::milliseconds(50)};
    std::chrono::seconds transfer_deadline{2};

    // Resolved by the handler when it returns, so the test waits on a FUTURE
    // rather than sleeping and polling.
    std::promise<int> handler_status;
    std::atomic<bool> handler_saw_cancel{false};
    std::atomic<int> chunks_written{0};
    std::atomic<bool> hit_safety_ceiling{false};

    struct Service final : apb::AgentService::Service {
        StallHarness* h;
        explicit Service(StallHarness* harness) : h(harness) {}

        grpc::Status DownloadUpdate(grpc::ServerContext* context,
                                    const apb::DownloadUpdateRequest*,
                                    grpc::ServerWriter<apb::DownloadUpdateChunk>* writer) override {
            auto reg = h->wd.register_transfer(
                [context] { context->TryCancel(); },
                std::chrono::steady_clock::now() + h->transfer_deadline);

            const std::string payload(64 * 1024, 'x');
            apb::DownloadUpdateChunk chunk;
            chunk.set_data(payload);

            for (;;) {
                if (!writer->Write(chunk)) {
                    // This is the moment under test: Write returned because the
                    // watchdog cancelled the call, not because we asked it to.
                    h->handler_saw_cancel.store(reg.cancelled());
                    h->handler_status.set_value(
                        static_cast<int>(grpc::StatusCode::DEADLINE_EXCEEDED));
                    return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, "stalled");
                }
                if (h->chunks_written.fetch_add(1) > kMaxChunksBeforeGivingUp) {
                    h->hit_safety_ceiling.store(true);
                    h->handler_status.set_value(static_cast<int>(grpc::StatusCode::OK));
                    return grpc::Status::OK;
                }
            }
        }
    };

    Service svc{this};
    std::unique_ptr<grpc::Server> server;
    int port = 0;
    std::unique_ptr<apb::AgentService::Stub> stub;

    StallHarness() {
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&svc);
        server = builder.BuildAndStart();
        REQUIRE(server != nullptr);
        REQUIRE(port != 0);
        stub = apb::AgentService::NewStub(
            grpc::CreateChannel("127.0.0.1:" + std::to_string(port),
                                grpc::InsecureChannelCredentials()));
    }

    ~StallHarness() {
        if (!server)
            return;
        // FINITE deadline, deliberately. A deadline-free Shutdown() waits
        // indefinitely for in-flight synchronous handlers and does not forcibly
        // terminate a running streaming handler — so on the very regression this
        // file exists to catch (a TryCancel that stops working), the REQUIRE
        // below would unwind into a destructor that blocks forever and the suite
        // would hang to its outer CI timeout instead of failing in ~30s.
        // Production makes the same choice for the same reason: see
        // server.cpp's agent_server_->Shutdown(deadline).
        server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    }
};

} // namespace

TEST_CASE("OTA stalled write: the watchdog unblocks a Write stalled on a zero receive window",
          "[ota][stall][grpc]") {
    StallHarness h;
    auto done = h.handler_status.get_future();

    apb::DownloadUpdateRequest req;
    req.set_agent_id("stalled-agent");
    req.set_version("1.0.0");

    grpc::ClientContext ctx;
    auto reader = h.stub->DownloadUpdate(&ctx, req);

    // DELIBERATELY never call reader->Read(). The client's receive window fills,
    // it stops granting the server more credit, and the server's Write blocks —
    // the exact condition keepalive cannot see and the sync API cannot time out.

    const auto started = std::chrono::steady_clock::now();
    // Bounded wait on a future, not a sleep-and-poll loop. A regression that
    // leaves the write genuinely wedged fails here attributably instead of
    // hanging the whole suite.
    const auto ready = done.wait_for(std::chrono::seconds(30));
    const auto elapsed = std::chrono::steady_clock::now() - started;

    // Release the client side BEFORE any assertion that can unwind, so the
    // destructor is never left waiting on a stream this test still holds.
    ctx.TryCancel();

    REQUIRE(ready == std::future_status::ready);

    // If this trips, the write never blocked, so the test proved nothing about
    // cancellation — surface it as a failure rather than a silent pass.
    CHECK_FALSE(h.hit_safety_ceiling.load());

    // The handler ended because OUR watchdog cancelled it.
    CHECK(h.handler_saw_cancel.load());
    CHECK(done.get() == static_cast<int>(grpc::StatusCode::DEADLINE_EXCEEDED));

    // And it was bounded by the deadline rather than by the client giving up.
    // Generous upper bound (deadline 2s + 50ms sweep + slack) so this is not a
    // tight timing assertion on a loaded shared runner.
    CHECK(elapsed < std::chrono::seconds(25));

    // It really did stall mid-stream rather than failing immediately — proving
    // the write path was exercised, not short-circuited.
    CHECK(h.chunks_written.load() > 0);

    reader->Finish();
}

TEST_CASE("OTA stalled write: a transfer well inside its deadline is never cancelled",
          "[ota][stall][grpc]") {
    // The complement, and the case that would catch a watchdog that cancels
    // indiscriminately: a client that DOES read should stream freely and the
    // watchdog must leave it alone. Without this, a watchdog that cancelled
    // every transfer would still pass the case above.
    StallHarness h;
    h.transfer_deadline = std::chrono::seconds(60);
    auto done = h.handler_status.get_future();

    apb::DownloadUpdateRequest req;
    req.set_agent_id("healthy-agent");
    grpc::ClientContext ctx;
    auto reader = h.stub->DownloadUpdate(&ctx, req);

    // Read enough to prove the stream flows, then stop the handler ourselves via
    // the safety ceiling rather than via any watchdog action.
    apb::DownloadUpdateChunk chunk;
    int read_count = 0;
    while (read_count < 32 && reader->Read(&chunk))
        ++read_count;

    CHECK(read_count == 32);
    CHECK_FALSE(h.handler_saw_cancel.load());

    ctx.TryCancel();
    reader->Finish();
    // Let the handler observe the client-side cancel and unwind.
    CHECK(done.wait_for(std::chrono::seconds(30)) == std::future_status::ready);
}
