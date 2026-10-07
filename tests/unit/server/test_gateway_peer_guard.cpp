/**
 * test_gateway_peer_guard.cpp: GatewayPeerGuardedService over a REAL mTLS wire.
 *
 * One in-process gRPC server, built from ONE builder, listens on two loopback ports at once:
 * a listener that REQUESTS a client certificate without requiring one, and a listener that
 * REQUIRES one. The guard is the only registered gateway-upstream service; a recording
 * delegate stands in for the real handlers, so "exactly one delegation on allow, zero on
 * deny" is observed directly and no database is involved.
 *
 * Every deny assertion is made on the delegate's call counts as well as the returned status,
 * so a guard that refuses but still delegates cannot pass.
 *
 *   [guard]   the wire tests and the direct-invocation tests
 *   [audit]   which denials write a row, and how the rows are bounded
 *   [budget]  DenialAuditBudget unit tests
 *
 * What is NOT proven here: the real handlers' behaviour (their own suites) and the production
 * wiring in server.cpp (`setup_gateway_peer_guard` and the single registration site); that is
 * covered by tests/shell/test_gateway_peer_boot_refusal.sh and
 * tests/test_gateway_peer_registration_lexical.py.
 */

#include <catch2/catch_test_macros.hpp>

#include <google/protobuf/descriptor.h>
#include <grpc/grpc_security.h>
#include <grpcpp/generic/generic_stub.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <yuzu/metrics.hpp>

#include "agent.grpc.pb.h"
#include "audit_store.hpp"
#include "bounded_audit_budget.hpp"
#include "gateway.grpc.pb.h"
#include "gateway_peer_cert.hpp"
#include "gateway_peer_guard.hpp"
#include "gateway_peer_pinset.hpp"
#include "gateway_peer_policy.hpp"
#include "gateway_peer_test_pki.hpp"
#include "gateway_service_impl.hpp"
#include "grpc_peer_evidence.hpp"
#include "management.grpc.pb.h"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

namespace gp = yuzu::server::gateway_peer;
namespace gwt = yuzu::test::gwpeer;
namespace gw = ::yuzu::gateway::v1;
namespace apb = ::yuzu::agent::v1;
namespace det = yuzu::server::detail;
using yuzu::server::AuditEvent;
using yuzu::server::DenialAuditBudget;
using det::GatewayPeerGuardedService;
using AuditSinkFn = GatewayPeerGuardedService::AuditSink;
using det::kGatewayPeerDeniedMessage;

namespace {

constexpr int kRpcCount = 5;
/// The proto method names (what the generated descriptor and a generic call carry).
constexpr std::array<const char*, kRpcCount> kRpcNames{"ProxyRegister", "BatchHeartbeat",
                                                       "ProxyInventory", "NotifyStreamStatus",
                                                       "ForwardGuardianMessage"};
/// The `rpc` metric label and audit value for each method: snake_case, same order.
constexpr std::array<const char*, kRpcCount> kRpcLabels{"proxy_register", "batch_heartbeat",
                                                        "proxy_inventory", "notify_stream_status",
                                                        "forward_guardian_message"};

/// Counts calls and captures the fields each RPC carried and the transport evidence the call
/// arrived with, returning a distinctive response so pass-through on the allow path is observable.
class RecordingDelegate final : public gw::GatewayUpstream::Service {
public:
    std::array<std::atomic<int>, kRpcCount> calls{};
    std::mutex mu;
    std::string register_agent_id, heartbeat_session, inventory_session, stream_agent,
        guardian_agent;
    std::vector<yuzu::server::grpc_peer::PeerCertEvidence> evidence;

    int total() const {
        int t = 0;
        for (const auto& c : calls)
            t += c.load();
        return t;
    }

    void note(grpc::ServerContext* ctx) {
        if (!ctx)
            return;
        auto e = yuzu::server::grpc_peer::read_peer_cert_evidence(*ctx);
        std::lock_guard lk(mu);
        evidence.push_back(std::move(e));
    }

    grpc::Status ProxyRegister(grpc::ServerContext* ctx, const apb::RegisterRequest* req,
                               apb::RegisterResponse* resp) override {
        ++calls[0];
        note(ctx);
        {
            std::lock_guard lk(mu);
            register_agent_id = req->info().agent_id();
        }
        resp->set_session_id("recorded-session");
        resp->set_accepted(true);
        return grpc::Status::OK;
    }
    grpc::Status BatchHeartbeat(grpc::ServerContext* ctx, const gw::BatchHeartbeatRequest* req,
                                gw::BatchHeartbeatResponse* resp) override {
        ++calls[1];
        note(ctx);
        {
            std::lock_guard lk(mu);
            if (req->heartbeats_size() > 0)
                heartbeat_session = req->heartbeats(0).session_id();
        }
        resp->set_acknowledged_count(7);
        return grpc::Status::OK;
    }
    grpc::Status ProxyInventory(grpc::ServerContext* ctx, const apb::InventoryReport* req,
                                apb::InventoryAck* resp) override {
        ++calls[2];
        note(ctx);
        {
            std::lock_guard lk(mu);
            inventory_session = req->session_id();
        }
        resp->set_received(true);
        return grpc::Status::OK;
    }
    grpc::Status NotifyStreamStatus(grpc::ServerContext* ctx,
                                    const gw::StreamStatusNotification* req,
                                    gw::StreamStatusAck* resp) override {
        ++calls[3];
        note(ctx);
        {
            std::lock_guard lk(mu);
            stream_agent = req->agent_id();
        }
        resp->set_acknowledged(true);
        return grpc::Status::OK;
    }
    grpc::Status ForwardGuardianMessage(grpc::ServerContext* ctx,
                                        const gw::ForwardGuardianRequest* req,
                                        gw::ForwardGuardianAck* resp) override {
        ++calls[4];
        note(ctx);
        {
            std::lock_guard lk(mu);
            guardian_agent = req->agent_id();
        }
        resp->set_acknowledged(true);
        return grpc::Status::OK;
    }
};

struct AuditCollector {
    std::mutex mu;
    std::vector<AuditEvent> rows;
    std::atomic<bool> fail{false};
    std::atomic<bool> throws{false};

    bool operator()(const AuditEvent& e) {
        if (throws.load())
            throw std::runtime_error("audit sink exploded");
        if (fail.load())
            return false;
        std::lock_guard lk(mu);
        rows.push_back(e);
        return true;
    }
    std::size_t size() {
        std::lock_guard lk(mu);
        return rows.size();
    }
};

std::string pin_of(const std::string& cert_pem) {
    const auto p = gp::spki_sha256_hex(std::string_view{cert_pem});
    REQUIRE(p.has_value());
    return *p;
}

const std::string kUnrelatedPin = "00" + std::string(62, 'a');

/// The injected clock's skew: the guard judges validity at wall-clock now + this many seconds,
/// while the TLS handshake (which has its own clock) sees real time.
struct Skew {
    std::atomic<std::int64_t> seconds{0};
};

struct GuardHarness {
    yuzu::MetricsRegistry metrics;
    RecordingDelegate delegate;
    AuditCollector audit;
    Skew skew;
    std::shared_ptr<DenialAuditBudget> budget;
    std::shared_ptr<DenialAuditBudget> log_budget;
    std::unique_ptr<GatewayPeerGuardedService> guard;
    det::ManagementServiceImpl mgmt;

    gwt::TestCa ca = gwt::make_ca("Guard Test CA");
    gwt::TestLeaf server_leaf = gwt::make_gateway_leaf(ca, "localhost");
    int optional_port = 0;
    int required_port = 0;
    std::unique_ptr<grpc::Server> server;

    explicit GuardHarness(
        std::shared_ptr<DenialAuditBudget> b = std::make_shared<DenialAuditBudget>(1000, 60'000),
        std::shared_ptr<DenialAuditBudget> lb = std::make_shared<DenialAuditBudget>(1000, 60'000))
        : budget(std::move(b)), log_budget(std::move(lb)) {}

    /// Builds the enforcing guard over `pins` (already-normalised hex).
    void use(const std::vector<std::string>& pins) {
        guard = std::make_unique<GatewayPeerGuardedService>(
            delegate,
            gp::GatewayPeerPolicy(std::make_shared<const gp::PinSet>(pins),
                                  [this] {
                                      return std::chrono::system_clock::now() +
                                             std::chrono::seconds(skew.seconds.load());
                                  }),
            [this](const AuditEvent& e) { return audit(e); }, &metrics, budget, log_budget);
    }

    /// Builds the acknowledged-insecure guard.
    void use_acknowledged() {
        guard = std::make_unique<GatewayPeerGuardedService>(
            delegate, GatewayPeerGuardedService::AcknowledgedInsecure{}, &metrics);
    }

    void listen() {
        REQUIRE(guard != nullptr);
        auto make_creds = [&](grpc_ssl_client_certificate_request_type mode) {
            grpc::SslServerCredentialsOptions opts(mode);
            opts.pem_root_certs = ca.cert_pem;
            opts.pem_key_cert_pairs.push_back({server_leaf.key_pem, server_leaf.cert_pem});
            return grpc::SslServerCredentials(opts);
        };
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0",
                                 make_creds(GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY),
                                 &optional_port);
        builder.AddListeningPort(
            "127.0.0.1:0", make_creds(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY),
            &required_port);
        builder.RegisterService(guard.get());
        builder.RegisterService(&mgmt);
        server = builder.BuildAndStart();
        REQUIRE(server != nullptr);
        REQUIRE(optional_port != 0);
        REQUIRE(required_port != 0);
    }

    /// The common case: an enforcing guard pinning `pins`, listening on both ports.
    void start(const std::vector<std::string>& pins) {
        use(pins);
        listen();
    }

    ~GuardHarness() {
        if (server)
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    }

    /// `client` null means an anonymous TLS channel (server trusted, no client cert). `extra` may
    /// add channel arguments (the session cache test).
    std::shared_ptr<grpc::Channel> channel(int port, const gwt::TestLeaf* client,
                                           const std::string& trust_pem,
                                           const grpc::ChannelArguments* extra = nullptr) const {
        grpc::SslCredentialsOptions opts;
        opts.pem_root_certs = trust_pem;
        if (client) {
            opts.pem_private_key = client->key_pem;
            opts.pem_cert_chain = client->cert_pem;
        }
        grpc::ChannelArguments args;
        if (extra)
            args = *extra;
        args.SetSslTargetNameOverride("localhost");
        return grpc::CreateCustomChannel("127.0.0.1:" + std::to_string(port),
                                         grpc::SslCredentials(opts), args);
    }

    double denied(const char* rpc, const char* reason) {
        return metrics
            .counter("yuzu_server_gateway_peer_denied_total",
                     {{"rpc", rpc}, {"reason", reason}, {"event", "security"}})
            .value();
    }
    /// The count for `reason` summed over the five rpcs.
    double denied_reason(const char* reason) {
        double t = 0;
        for (const char* rpc : kRpcLabels)
            t += denied(rpc, reason);
        return t;
    }
    double denied_total_all() {
        double t = 0;
        for (const auto r : gp::kAllDenyReasons)
            t += denied_reason(std::string{gp::to_label(r)}.c_str());
        return t;
    }
    double suppressed() {
        return metrics.counter("yuzu_server_gateway_peer_denial_audit_suppressed_total", {})
            .value();
    }
};

std::unique_ptr<grpc::ClientContext> ctx_with_deadline() {
    auto c = std::make_unique<grpc::ClientContext>();
    c->set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(15));
    return c;
}

/// Calls RPC `idx` with a payload carrying the fields the real handler acts on, and returns the
/// status. It contains NO Catch2 assertion (assertions are not thread-safe in this build), so it is
/// the variant worker threads use. When the call succeeds, `payload_ok` (if given) is cleared if the
/// response body is not the one the recording delegate returns.
grpc::Status call_rpc_status(gw::GatewayUpstream::Stub& stub, int idx, bool* payload_ok = nullptr) {
    const auto expect = [payload_ok](bool cond) {
        if (payload_ok != nullptr && !cond)
            *payload_ok = false;
    };
    auto ctx = ctx_with_deadline();
    switch (idx) {
    case 0: {
        apb::RegisterRequest req;
        req.mutable_info()->set_agent_id("agent-under-test");
        req.mutable_info()->set_hostname("test-host");
        req.mutable_info()->mutable_platform()->set_os("linux");
        req.set_enrollment_token("token-under-test");
        req.set_csr_pem("csr-under-test");
        apb::RegisterResponse resp;
        auto st = stub.ProxyRegister(ctx.get(), req, &resp);
        if (st.ok()) {
            expect(resp.session_id() == "recorded-session");
            expect(resp.accepted());
        }
        return st;
    }
    case 1: {
        gw::BatchHeartbeatRequest req;
        req.set_gateway_node("gw-under-test");
        auto* hb = req.add_heartbeats();
        hb->set_session_id("session-under-test");
        (*hb->mutable_status_tags())["k"] = "v";
        gw::BatchHeartbeatResponse resp;
        auto st = stub.BatchHeartbeat(ctx.get(), req, &resp);
        if (st.ok())
            expect(resp.acknowledged_count() == 7);
        return st;
    }
    case 2: {
        apb::InventoryReport req;
        req.set_session_id("session-under-test");
        (*req.mutable_plugin_data())["installed_software"] = "payload";
        apb::InventoryAck resp;
        auto st = stub.ProxyInventory(ctx.get(), req, &resp);
        if (st.ok())
            expect(resp.received());
        return st;
    }
    case 3: {
        gw::StreamStatusNotification req;
        req.set_agent_id("agent-under-test");
        req.set_session_id("session-under-test");
        req.set_event(gw::StreamStatusNotification::CONNECTED);
        req.set_gateway_node("gw-under-test");
        gw::StreamStatusAck resp;
        auto st = stub.NotifyStreamStatus(ctx.get(), req, &resp);
        if (st.ok())
            expect(resp.acknowledged());
        return st;
    }
    default: {
        gw::ForwardGuardianRequest req;
        req.set_agent_id("agent-under-test");
        req.mutable_response()->set_command_id("");
        req.mutable_response()->set_plugin("__guard__");
        gw::ForwardGuardianAck resp;
        auto st = stub.ForwardGuardianMessage(ctx.get(), req, &resp);
        if (st.ok())
            expect(resp.acknowledged());
        return st;
    }
    }
}

/// Single-thread form: the status of `call_rpc_status` plus a CHECK that a successful call carried
/// the expected response body. Do NOT call this from a worker thread.
grpc::Status call_rpc(gw::GatewayUpstream::Stub& stub, int idx) {
    bool payload_ok = true;
    auto st = call_rpc_status(stub, idx, &payload_ok);
    CHECK(payload_ok);
    return st;
}

/// Every RPC over `stub` must be refused with the fixed UNAUTHENTICATED answer.
void expect_denied_everywhere(gw::GatewayUpstream::Stub& stub, const char* where = "") {
    for (int i = 0; i < kRpcCount; ++i) {
        INFO("rpc " << kRpcNames[i] << " " << where);
        const auto st = call_rpc(stub, i);
        CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(st.error_message() == std::string{kGatewayPeerDeniedMessage});
    }
}

/// Generic, descriptor-driven unary call with an empty body.
grpc::Status generic_unary(const std::shared_ptr<grpc::Channel>& ch, const std::string& method) {
    grpc::GenericStub stub(ch);
    grpc::CompletionQueue cq;
    auto ctx = ctx_with_deadline();
    grpc::Slice empty;
    grpc::ByteBuffer req(&empty, 1);
    grpc::ByteBuffer resp;
    auto reader = stub.PrepareUnaryCall(ctx.get(), method, req, &cq);
    reader->StartCall();
    grpc::Status st;
    reader->Finish(&resp, &st, reinterpret_cast<void*>(1));
    void* tag = nullptr;
    bool ok = false;
    REQUIRE(cq.Next(&tag, &ok));
    cq.Shutdown();
    while (cq.Next(&tag, &ok)) {
    }
    return st;
}

/// Calls every method with a null ServerContext, directly on the guard.
std::array<grpc::Status, kRpcCount> call_all_with_null_context(GatewayPeerGuardedService& g) {
    apb::RegisterRequest r0;
    apb::RegisterResponse p0;
    gw::BatchHeartbeatRequest r1;
    gw::BatchHeartbeatResponse p1;
    apb::InventoryReport r2;
    apb::InventoryAck p2;
    gw::StreamStatusNotification r3;
    gw::StreamStatusAck p3;
    gw::ForwardGuardianRequest r4;
    gw::ForwardGuardianAck p4;
    return {g.ProxyRegister(nullptr, &r0, &p0), g.BatchHeartbeat(nullptr, &r1, &p1),
            g.ProxyInventory(nullptr, &r2, &p2), g.NotifyStreamStatus(nullptr, &r3, &p3),
            g.ForwardGuardianMessage(nullptr, &r4, &p4)};
}

} // namespace

// -- anonymous callers -----------------------------------------------------------

TEST_CASE("gateway_peer_guard: an anonymous caller on the cert-optional listener is denied on "
          "every RPC as not_authenticated, with no audit row",
          "[gateway_peer][guard][grpc][mtls]") {
    GuardHarness h;
    h.start({kUnrelatedPin}); // pins exist; the caller simply has no certificate
    auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, nullptr, h.ca.cert_pem));

    expect_denied_everywhere(*stub);
    CHECK(h.delegate.total() == 0);
    for (const char* rpc : kRpcLabels) {
        INFO("rpc " << rpc);
        CHECK(h.denied(rpc, "not_authenticated") == 1);
    }
    CHECK(h.denied_total_all() == kRpcCount);
    CHECK(h.audit.size() == 0); // no key, no row
}

TEST_CASE("gateway_peer_guard: an anonymous TLS channel is refused at the handshake on the "
          "cert-required listener",
          "[gateway_peer][guard][grpc][mtls]") {
    GuardHarness h;
    h.start({kUnrelatedPin});
    auto stub = gw::GatewayUpstream::NewStub(h.channel(h.required_port, nullptr, h.ca.cert_pem));
    for (int i = 0; i < kRpcCount; ++i) {
        INFO("rpc " << kRpcNames[i]);
        CHECK(call_rpc(*stub, i).error_code() == grpc::StatusCode::UNAVAILABLE);
    }
    CHECK(h.delegate.total() == 0);
    CHECK(h.denied_total_all() == 0); // never reached the guard
}

TEST_CASE("gateway_peer_guard: a leaf the listener's CA does not vouch for fails the handshake "
          "and reaches nothing",
          "[gateway_peer][guard][grpc][mtls]") {
    GuardHarness h;
    const auto other_ca = gwt::make_ca("Unrelated CA");
    const auto foreign = gwt::make_gateway_leaf(other_ca, "Test Gateway");
    h.start({pin_of(foreign.cert_pem)}); // even a pinned key cannot get past the handshake
    for (const int port : {h.optional_port, h.required_port}) {
        auto stub = gw::GatewayUpstream::NewStub(h.channel(port, &foreign, h.ca.cert_pem));
        for (int i = 0; i < kRpcCount; ++i) {
            INFO("rpc " << kRpcNames[i] << " port " << port);
            CHECK(call_rpc(*stub, i).error_code() == grpc::StatusCode::UNAVAILABLE);
        }
    }
    CHECK(h.delegate.total() == 0);
    CHECK(h.denied_total_all() == 0);
}

// -- certificate holders: one row per case, per listener, per RPC ---------------------

TEST_CASE("gateway_peer_guard: a clientAuth-only leaf is denied as no_server_auth_eku even when "
          "its KEY is pinned",
          "[gateway_peer][guard][grpc][mtls][eku]") {
    GuardHarness h;
    const auto agent = gwt::make_agent_leaf(h.ca, "agent-1");
    h.start({pin_of(agent.cert_pem)}); // pinned by mistake: the EKU is still required

    for (const int port : {h.optional_port, h.required_port}) {
        auto stub = gw::GatewayUpstream::NewStub(h.channel(port, &agent, h.ca.cert_pem));
        expect_denied_everywhere(*stub, port == h.optional_port ? "optional" : "required");
    }
    CHECK(h.delegate.total() == 0);
    CHECK(h.denied_reason("no_server_auth_eku") == 2 * kRpcCount);
    CHECK(h.denied_reason("not_pinned") == 0); // the EKU check precedes the pin check
    CHECK(h.denied_total_all() == 2 * kRpcCount);
}

TEST_CASE("gateway_peer_guard: a gateway-shaped leaf whose key is not pinned is denied as "
          "not_pinned on both listeners",
          "[gateway_peer][guard][grpc][mtls]") {
    GuardHarness h;
    const auto pinned = gwt::make_gateway_leaf(h.ca, "pinned-gw");
    const auto other = gwt::make_gateway_leaf(h.ca, "other-gw"); // same CA, same EKU, other key
    h.start({pin_of(pinned.cert_pem)});
    for (const int port : {h.optional_port, h.required_port}) {
        auto stub = gw::GatewayUpstream::NewStub(h.channel(port, &other, h.ca.cert_pem));
        expect_denied_everywhere(*stub);
    }
    CHECK(h.delegate.total() == 0);
    CHECK(h.denied_reason("not_pinned") == 2 * kRpcCount);
}

TEST_CASE("gateway_peer_guard: a pinned gateway leaf is admitted on both listeners, exactly one "
          "delegation per call",
          "[gateway_peer][guard][grpc][mtls]") {
    GuardHarness h;
    const auto gateway = gwt::make_gateway_leaf(h.ca);
    h.start({pin_of(gateway.cert_pem)});

    for (const int port : {h.optional_port, h.required_port}) {
        auto stub = gw::GatewayUpstream::NewStub(h.channel(port, &gateway, h.ca.cert_pem));
        for (int i = 0; i < kRpcCount; ++i) {
            INFO("rpc " << kRpcNames[i] << " port " << port);
            const int before = h.delegate.calls[static_cast<std::size_t>(i)].load();
            const int total_before = h.delegate.total();
            CHECK(call_rpc(*stub, i).ok());
            CHECK(h.delegate.calls[static_cast<std::size_t>(i)].load() == before + 1);
            CHECK(h.delegate.total() == total_before + 1);
        }
    }
    CHECK(h.denied_total_all() == 0);
    CHECK(h.audit.size() == 0);
    std::lock_guard lk(h.delegate.mu);
    CHECK(h.delegate.register_agent_id == "agent-under-test");
    CHECK(h.delegate.heartbeat_session == "session-under-test");
    CHECK(h.delegate.inventory_session == "session-under-test");
    CHECK(h.delegate.stream_agent == "agent-under-test");
    CHECK(h.delegate.guardian_agent == "agent-under-test");
}

TEST_CASE("gateway_peer_guard: a same-key reissue of the pinned gateway is admitted",
          "[gateway_peer][guard][grpc][mtls]") {
    GuardHarness h;
    const auto original = gwt::make_gateway_leaf(h.ca);
    const auto renewed = gwt::reissue_same_key(h.ca, original, "Renewed Gateway", true, true);
    h.start({pin_of(original.cert_pem)});
    auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &renewed, h.ca.cert_pem));
    for (int i = 0; i < kRpcCount; ++i) {
        INFO("rpc " << kRpcNames[i]);
        CHECK(call_rpc(*stub, i).ok());
    }
    CHECK(h.delegate.total() == kRpcCount);
}

TEST_CASE("gateway_peer_guard: a pinned leaf outside its validity window is denied as "
          "outside_validity (injected clock)",
          "[gateway_peer][guard][grpc][mtls][validity]") {
    GuardHarness h;
    const auto gateway = gwt::make_gateway_leaf(h.ca); // valid for one day from now
    h.start({pin_of(gateway.cert_pem)});
    auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &gateway, h.ca.cert_pem));

    REQUIRE(call_rpc(*stub, 1).ok()); // inside the window
    CHECK(h.delegate.total() == 1);

    SECTION("expired: the guard's clock is past notAfter") {
        h.skew.seconds = 3 * 24 * 3600;
        expect_denied_everywhere(*stub);
    }
    SECTION("not yet valid: the guard's clock is before notBefore minus the leeway") {
        h.skew.seconds = -3 * 24 * 3600;
        expect_denied_everywhere(*stub);
    }
    CHECK(h.delegate.total() == 1); // nothing delegated after the first call
    CHECK(h.denied_reason("outside_validity") == kRpcCount);
    // A pinned peer with the right EKU whose clock check failed is an authenticated holder: keyed.
    REQUIRE(h.audit.size() >= 1);
    std::lock_guard lk(h.audit.mu);
    CHECK(h.audit.rows.front().detail.rfind("reason=outside_validity ", 0) == 0);
}

TEST_CASE("gateway_peer_guard: a leaf presented with its intermediate is judged on the leaf",
          "[gateway_peer][guard][grpc][mtls][intermediate]") {
    GuardHarness h; // h.ca is the root the listeners trust
    const auto inter = gwt::make_intermediate(h.ca, "Install Intermediate");
    const auto gateway = gwt::make_gateway_leaf(inter, "chain-gw");
    const gwt::TestLeaf chain{gateway.key_pem, gateway.cert_pem + inter.cert_pem};

    SECTION("the leaf's key is pinned: admitted on every RPC") {
        h.start({pin_of(gateway.cert_pem)});
        auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &chain, h.ca.cert_pem));
        for (int i = 0; i < kRpcCount; ++i) {
            INFO("rpc " << kRpcNames[i]);
            CHECK(call_rpc(*stub, i).ok());
        }
        CHECK(h.delegate.total() == kRpcCount);
        CHECK(h.denied_total_all() == 0);
    }
    SECTION("only the intermediate's key is pinned: denied, the chain does not widen the pin") {
        h.start({pin_of(inter.cert_pem)});
        auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &chain, h.ca.cert_pem));
        expect_denied_everywhere(*stub);
        CHECK(h.delegate.total() == 0);
        CHECK(h.denied_reason("not_pinned") == kRpcCount);
    }
}

// -- direct invocation -------------------------------------------------------------

TEST_CASE("gateway_peer_guard: a null ServerContext is denied on every method, with no exemption "
          "and no audit row",
          "[gateway_peer][guard]") {
    GuardHarness h; // no server needed: the guard is invoked directly
    const auto gateway = gwt::make_gateway_leaf(h.ca);
    h.use({pin_of(gateway.cert_pem)});

    const auto results = call_all_with_null_context(*h.guard);
    for (int i = 0; i < kRpcCount; ++i) {
        INFO("rpc " << kRpcNames[i]);
        CHECK(results[static_cast<std::size_t>(i)].error_code() ==
              grpc::StatusCode::UNAUTHENTICATED);
        CHECK(results[static_cast<std::size_t>(i)].error_message() ==
              std::string{kGatewayPeerDeniedMessage});
        CHECK(h.denied(kRpcLabels[static_cast<std::size_t>(i)], "null_context") == 1);
    }
    CHECK(h.delegate.total() == 0);
    CHECK(h.audit.size() == 0);
}

TEST_CASE("gateway_peer_guard: a ServerContext with no transport security is denied",
          "[gateway_peer][guard]") {
    GuardHarness h;
    h.use({kUnrelatedPin});
    grpc::ServerContext sc;
    apb::RegisterRequest req;
    apb::RegisterResponse resp;
    const auto st = h.guard->ProxyRegister(&sc, &req, &resp);
    CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(st.error_message() == std::string{kGatewayPeerDeniedMessage});
    CHECK(h.delegate.total() == 0);
    CHECK(h.denied_total_all() == 1);
    // A context that was never attached to a call carries an auth context that is not
    // authenticated: exactly that one reason fires, and no other series moves.
    CHECK(h.denied("proxy_register", "not_authenticated") == 1);
    CHECK(h.denied_reason("not_authenticated") == 1);
    for (const auto r : gp::kAllDenyReasons) {
        if (r == gp::DenyReason::NotAuthenticated)
            continue;
        INFO("reason " << gp::to_label(r));
        CHECK(h.denied_reason(std::string{gp::to_label(r)}.c_str()) == 0);
    }
    CHECK(h.audit.size() == 0);
}

// -- descriptor-driven inventory ----------------------------------------------

TEST_CASE("gateway_peer_guard: every gateway-upstream method is unary, known, and denies an "
          "anonymous generic call",
          "[gateway_peer][guard][grpc][mtls][tripwire]") {
    const auto* pool = google::protobuf::DescriptorPool::generated_pool();
    const auto* svc = pool->FindServiceByName(gw::GatewayUpstream::service_full_name());
    REQUIRE(svc != nullptr);

    std::set<std::string> expected(kRpcNames.begin(), kRpcNames.end());
    std::set<std::string> actual;
    for (int i = 0; i < svc->method_count(); ++i) {
        const auto* m = svc->method(i);
        INFO("method " << m->name());
        // A streaming method needs its own override and its own wire test: fail loudly.
        CHECK_FALSE(m->client_streaming());
        CHECK_FALSE(m->server_streaming());
        actual.insert(std::string{m->name()});
    }
    // A method added to the proto must be added to the guard, to kGatewayUpstreamRpcNames and to
    // kRpcNames / kRpcLabels here, in the same change.
    CHECK(actual == expected);
    CHECK(det::kGatewayUpstreamRpcNames.size() == static_cast<std::size_t>(svc->method_count()));
    // Every method has exactly one rpc label, in proto order: the snake_case of the method name.
    for (int i = 0; i < svc->method_count(); ++i) {
        INFO("method " << svc->method(i)->name());
        std::string snake;
        for (const char c : std::string{svc->method(i)->name()}) {
            if (c >= 'A' && c <= 'Z') {
                if (!snake.empty())
                    snake += '_';
                snake += static_cast<char>(c - 'A' + 'a');
            } else {
                snake += c;
            }
        }
        CHECK(std::string{det::kGatewayUpstreamRpcNames[static_cast<std::size_t>(i)]} == snake);
    }

    GuardHarness h;
    h.start({kUnrelatedPin});
    auto optional_channel = h.channel(h.optional_port, nullptr, h.ca.cert_pem);
    for (int i = 0; i < svc->method_count(); ++i) {
        const auto* m = svc->method(i);
        const std::string path =
            std::string("/") + std::string{svc->full_name()} + "/" + std::string{m->name()};
        INFO("generic call " << path);
        const auto st = generic_unary(optional_channel, path);
        CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(st.error_message() == std::string{kGatewayPeerDeniedMessage});
    }
    CHECK(h.delegate.total() == 0);
}

TEST_CASE("gateway_peer_guard: the management service placeholder answers UNIMPLEMENTED to "
          "anonymous calls on every method",
          "[gateway_peer][guard][grpc][mtls][tripwire]") {
    // The placeholder is registered on the same builder as the guard. Its first real RPC has to be
    // put behind a guard before it answers, so any change to its method set must be looked at:
    // this walks the generated descriptor and asserts each method, streaming or not, is still
    // unimplemented.
    const auto* pool = google::protobuf::DescriptorPool::generated_pool();
    const auto* svc =
        pool->FindServiceByName(yuzu::server::v1::ManagementService::service_full_name());
    REQUIRE(svc != nullptr);
    REQUIRE(svc->method_count() > 0);

    GuardHarness h;
    h.start({kUnrelatedPin});
    auto optional_channel = h.channel(h.optional_port, nullptr, h.ca.cert_pem);
    for (int i = 0; i < svc->method_count(); ++i) {
        const auto* m = svc->method(i);
        const std::string path =
            std::string("/") + std::string{svc->full_name()} + "/" + std::string{m->name()};
        INFO("generic call " << path);
        CHECK(generic_unary(optional_channel, path).error_code() ==
              grpc::StatusCode::UNIMPLEMENTED);
    }
    CHECK(h.delegate.total() == 0);
}

// -- what the transport reports -----------------------------------------------------

namespace {
/// Records what read_peer_cert_evidence sees. Registered WITHOUT the guard, on its own server, so
/// the observation is of the transport and not of a decision.
class EvidenceProbe final : public gw::GatewayUpstream::Service {
public:
    std::mutex mu;
    std::vector<yuzu::server::grpc_peer::PeerCertEvidence> seen;

    grpc::Status BatchHeartbeat(grpc::ServerContext* ctx, const gw::BatchHeartbeatRequest*,
                                gw::BatchHeartbeatResponse* resp) override {
        std::lock_guard lk(mu);
        seen.push_back(yuzu::server::grpc_peer::read_peer_cert_evidence(*ctx));
        resp->set_acknowledged_count(7);
        return grpc::Status::OK;
    }
};
} // namespace

TEST_CASE("gateway_peer_guard: transport evidence on a request-but-not-require listener, "
          "anonymous and with a chain",
          "[gateway_peer][guard][grpc][mtls][evidence]") {
    const auto root = gwt::make_ca("Evidence Root");
    const auto inter = gwt::make_intermediate(root, "Evidence Intermediate");
    const auto server_leaf = gwt::make_gateway_leaf(root, "localhost");
    const auto client = gwt::make_agent_leaf(inter, "client-1");
    const gwt::TestLeaf chain{client.key_pem, client.cert_pem + inter.cert_pem};

    EvidenceProbe probe;
    grpc::SslServerCredentialsOptions opts(GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY);
    opts.pem_root_certs = root.cert_pem;
    opts.pem_key_cert_pairs.push_back({server_leaf.key_pem, server_leaf.cert_pem});
    int port = 0;
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0", grpc::SslServerCredentials(opts), &port);
    builder.RegisterService(&probe);
    auto server = builder.BuildAndStart();
    REQUIRE(server);

    auto beat = [&](const gwt::TestLeaf* c) {
        grpc::SslCredentialsOptions co;
        co.pem_root_certs = root.cert_pem;
        if (c) {
            co.pem_private_key = c->key_pem;
            co.pem_cert_chain = c->cert_pem;
        }
        grpc::ChannelArguments args;
        args.SetSslTargetNameOverride("localhost");
        auto stub = gw::GatewayUpstream::NewStub(grpc::CreateCustomChannel(
            "127.0.0.1:" + std::to_string(port), grpc::SslCredentials(co), args));
        return call_rpc(*stub, 1);
    };
    REQUIRE(beat(nullptr).ok());
    REQUIRE(beat(&chain).ok());
    server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));

    std::lock_guard lk(probe.mu);
    REQUIRE(probe.seen.size() == 2);
    // Anonymous: the peer is not authenticated and no certificate property is present.
    CHECK_FALSE(probe.seen[0].authenticated);
    CHECK(probe.seen[0].pem.empty());
    // With a certificate and an intermediate: authenticated, and the property is the leaf alone.
    CHECK(probe.seen[1].authenticated);
    CHECK(probe.seen[1].pem == client.cert_pem);
}

// -- TLS session reuse ---------------------------------------------------------------

namespace {
struct SessionCacheDeleter {
    void operator()(grpc_ssl_session_cache* c) const noexcept { grpc_ssl_session_cache_destroy(c); }
};
} // namespace

TEST_CASE("gateway_peer_guard: two sequential channels sharing an LRU session cache give identical "
          "evidence and identical decisions",
          "[gateway_peer][guard][grpc][mtls][session]") {
    // NOTE on what this shows. Whether the second handshake RESUMED the first session is not
    // observable from gRPC's public API, so this test does not and cannot prove that reuse
    // happened. It shows that with the cache configured on both channels, the evidence the guard
    // reads and the decision it takes are the same on the first and the second connection, for a
    // pinned and for an unpinned leaf.
    //
    // One cache PER client identity. A session cache is the client's own state and is keyed by
    // the target. In a first draft of this test one cache was shared by the pinned and the
    // unpinned identity, and the unpinned leaf was then ADMITTED: consistent with its channel
    // resuming the pinned identity's session, so that the guard judged the certificate the
    // session restored (resumption itself was not separately confirmed). A real caller cannot
    // do that without the pinned peer's own session state, so it is not a way past the guard,
    // but it means a shared cache would make this test say nothing about the unpinned leaf.
    GuardHarness h;
    const auto pinned = gwt::make_gateway_leaf(h.ca, "pinned-gw");
    const auto unpinned = gwt::make_gateway_leaf(h.ca, "unpinned-gw");
    h.start({pin_of(pinned.cert_pem)});

    const auto two_connections = [&](int port, const gwt::TestLeaf& leaf,
                                     const std::function<void(const grpc::Status&)>& check) {
        std::unique_ptr<grpc_ssl_session_cache, SessionCacheDeleter> cache{
            grpc_ssl_session_cache_create_lru(16)};
        REQUIRE(cache != nullptr);
        // grpc_ssl_session_cache_create_channel_arg supplies the pointer and its vtable for
        // GRPC_SSL_SESSION_CACHE_ARG; the arg does not take ownership of `cache`.
        const grpc_arg cache_arg = grpc_ssl_session_cache_create_channel_arg(cache.get());
        REQUIRE(std::string{cache_arg.key} == GRPC_SSL_SESSION_CACHE_ARG);
        grpc::ChannelArguments cache_args;
        cache_args.SetPointerWithVtable(GRPC_SSL_SESSION_CACHE_ARG, cache_arg.value.pointer.p,
                                        cache_arg.value.pointer.vtable);
        for (int round = 0; round < 2; ++round) {
            INFO("port " << port << " round " << round);
            // Each channel is destroyed before the next, so the second one is a new connection.
            auto stub =
                gw::GatewayUpstream::NewStub(h.channel(port, &leaf, h.ca.cert_pem, &cache_args));
            check(call_rpc(*stub, 1));
        }
    };

    for (const int port : {h.optional_port, h.required_port}) {
        two_connections(port, pinned, [](const grpc::Status& st) { CHECK(st.ok()); });
        two_connections(port, unpinned, [](const grpc::Status& st) {
            CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
            CHECK(st.error_message() == std::string{kGatewayPeerDeniedMessage});
        });
    }
    CHECK(h.delegate.total() == 4);
    CHECK(h.denied("batch_heartbeat", "not_pinned") == 4);
    CHECK(h.denied_total_all() == 4);
    std::lock_guard lk(h.delegate.mu);
    REQUIRE(h.delegate.evidence.size() == 4);
    for (const auto& e : h.delegate.evidence) {
        CHECK(e.authenticated);
        CHECK(e.pem == pinned.cert_pem); // the same leaf, every time
    }
}

// -- the fixed refusal and the closed vocabularies --------------------------------------

TEST_CASE("gateway_peer_guard: every deny reason produces the same code and the same message, "
          "which names no reason",
          "[gateway_peer][guard][grpc][mtls]") {
    GuardHarness h;
    const auto gateway = gwt::make_gateway_leaf(h.ca, "gw");
    const auto agent = gwt::make_agent_leaf(h.ca, "agent");
    const auto other = gwt::make_gateway_leaf(h.ca, "other");
    h.start({pin_of(gateway.cert_pem)});

    std::set<std::string> messages;
    auto record = [&](const grpc::Status& st) {
        CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        messages.insert(st.error_message());
    };
    apb::RegisterRequest req;
    apb::RegisterResponse resp;
    record(h.guard->ProxyRegister(nullptr, &req, &resp)); // null_context
    for (const gwt::TestLeaf* leaf : {static_cast<const gwt::TestLeaf*>(nullptr), &agent, &other}) {
        auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, leaf, h.ca.cert_pem));
        record(call_rpc(*stub, 0)); // not_authenticated, no_server_auth_eku, not_pinned
    }
    h.skew.seconds = 3 * 24 * 3600;
    {
        auto stub =
            gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &gateway, h.ca.cert_pem));
        record(call_rpc(*stub, 0)); // outside_validity
    }
    CHECK(messages == std::set<std::string>{std::string{kGatewayPeerDeniedMessage}});
    CHECK(std::string{kGatewayPeerDeniedMessage} == "gateway peer not authorized");
    for (const auto r : gp::kAllDenyReasons)
        CHECK(std::string{kGatewayPeerDeniedMessage}.find(std::string{gp::to_label(r)}) ==
              std::string::npos);
    CHECK(h.denied_total_all() == 5);
    CHECK(h.delegate.total() == 0);
}

TEST_CASE("gateway_peer_guard: the denial counter family is pre-seeded as exactly 5 rpcs x 8 "
          "reasons",
          "[gateway_peer][guard]") {
    GuardHarness h;
    h.use({kUnrelatedPin});
    const std::string text = h.metrics.serialize();
    CHECK(gp::kAllDenyReasons.size() == 8);
    CHECK(det::kGatewayUpstreamRpcNames.size() == 5);

    std::size_t series = 0;
    const std::string prefix = "yuzu_server_gateway_peer_denied_total{";
    for (auto at = text.find(prefix); at != std::string::npos; at = text.find(prefix, at + 1))
        ++series;
    CHECK(series == 5 * 8);

    for (const char* rpc : kRpcLabels) {
        for (const auto reason : gp::kAllDenyReasons) {
            const std::string line = "yuzu_server_gateway_peer_denied_total{rpc=\"" +
                                     std::string{rpc} + "\",reason=\"" +
                                     std::string{gp::to_label(reason)} + "\",event=\"security\"} 0";
            INFO(line);
            CHECK(text.find(line) != std::string::npos);
        }
    }
    // The suppression counter exists at 0 with HELP/TYPE before anything is denied.
    CHECK(text.find("# HELP yuzu_server_gateway_peer_denial_audit_suppressed_total ") !=
          std::string::npos);
    CHECK(text.find("# TYPE yuzu_server_gateway_peer_denial_audit_suppressed_total counter") !=
          std::string::npos);
    CHECK(text.find("yuzu_server_gateway_peer_denial_audit_suppressed_total 0") !=
          std::string::npos);
}

TEST_CASE("gateway_peer_guard: the closed vocabularies are pinned to their literals",
          "[gateway_peer][guard][literals]") {
    const std::array<std::pair<gp::DenyReason, const char*>, 8> reasons{{
        {gp::DenyReason::NullContext, "null_context"},
        {gp::DenyReason::NotAuthenticated, "not_authenticated"},
        {gp::DenyReason::NoCert, "no_cert"},
        {gp::DenyReason::BadCert, "bad_cert"},
        {gp::DenyReason::NoServerAuthEku, "no_server_auth_eku"},
        {gp::DenyReason::NotPinned, "not_pinned"},
        {gp::DenyReason::OutsideValidity, "outside_validity"},
        {gp::DenyReason::InternalError, "internal_error"},
    }};
    CHECK(reasons.size() == gp::kAllDenyReasons.size());
    for (std::size_t i = 0; i < reasons.size(); ++i) {
        INFO("reason " << reasons[i].second);
        CHECK(std::string{gp::to_label(reasons[i].first)} == reasons[i].second);
        CHECK(gp::kAllDenyReasons[i] == reasons[i].first);
    }

    using det::GatewayUpstreamRpc;
    const std::array<std::pair<GatewayUpstreamRpc, const char*>, 5> rpcs{{
        {GatewayUpstreamRpc::ProxyRegister, "proxy_register"},
        {GatewayUpstreamRpc::BatchHeartbeat, "batch_heartbeat"},
        {GatewayUpstreamRpc::ProxyInventory, "proxy_inventory"},
        {GatewayUpstreamRpc::NotifyStreamStatus, "notify_stream_status"},
        {GatewayUpstreamRpc::ForwardGuardianMessage, "forward_guardian_message"},
    }};
    for (const auto& [rpc, label] : rpcs) {
        INFO("rpc " << label);
        CHECK(std::string{det::to_label(rpc)} == label);
    }

    CHECK(std::string{det::kGatewayPeerDeniedMessage} == "gateway peer not authorized");
    CHECK(std::string{det::kGatewayPeerDeniedMetric} == "yuzu_server_gateway_peer_denied_total");
    CHECK(std::string{det::kGatewayPeerDeniedAuditAction} == "session.gateway_peer_denied");
    CHECK(std::string{det::kGatewayPeerDenialSuppressedMetric} ==
          "yuzu_server_gateway_peer_denial_audit_suppressed_total");
}

// -- audit: which denials write a row ---------------------------------------------------

TEST_CASE("gateway_peer_guard: only the four reasons an authenticated holder can reach may carry "
          "an audit row",
          "[gateway_peer][guard][audit]") {
    const std::array<std::pair<gp::DenyReason, bool>, 8> table{{
        {gp::DenyReason::NullContext, false},
        {gp::DenyReason::NotAuthenticated, false},
        {gp::DenyReason::NoCert, false},
        {gp::DenyReason::BadCert, false},
        {gp::DenyReason::NoServerAuthEku, true},
        {gp::DenyReason::NotPinned, true},
        {gp::DenyReason::OutsideValidity, true},
        {gp::DenyReason::InternalError, true},
    }};
    CHECK(table.size() == gp::kAllDenyReasons.size());
    for (const auto& [reason, writes] : table) {
        INFO("reason " << gp::to_label(reason));
        CHECK(det::denial_may_carry_audit_row(reason) == writes);
    }
    // The audit-eligible set is DERIVED from the policy's one "proves an authenticated holder"
    // predicate (plus internal_error, which can occur at any stage and so also needs a key), not a
    // second list: cross-check the literal table above against it, both directions.
    for (const auto r : gp::kAllDenyReasons) {
        INFO("reason " << gp::to_label(r));
        CHECK(det::denial_may_carry_audit_row(r) ==
              (gp::reason_proves_authenticated_cert_holder(r) ||
               r == gp::DenyReason::InternalError));
    }
}

TEST_CASE("gateway_peer_guard: a denial of a certificate holder writes one row carrying the "
          "peer's key, for each reason it can be denied for",
          "[gateway_peer][guard][grpc][mtls][audit]") {
    GuardHarness h;
    const auto gateway = gwt::make_gateway_leaf(h.ca, "Gateway Subject CN");
    const auto agent = gwt::make_agent_leaf(h.ca, "no-eku");
    const gwt::TestLeaf* client = &gateway;
    std::string expected_reason;
    std::vector<std::string> pins;

    SECTION("no_server_auth_eku") {
        pins = {pin_of(gateway.cert_pem)};
        client = &agent;
        expected_reason = "no_server_auth_eku";
    }
    SECTION("not_pinned") {
        pins = {kUnrelatedPin};
        expected_reason = "not_pinned";
    }
    SECTION("outside_validity") {
        pins = {pin_of(gateway.cert_pem)};
        h.skew.seconds = 3 * 24 * 3600;
        expected_reason = "outside_validity";
    }
    SECTION("internal_error with a computable key (an empty pin set is a wiring defect)") {
        pins = {};
        expected_reason = "internal_error";
    }
    h.use(pins);
    h.listen();
    auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, client, h.ca.cert_pem));
    CHECK(call_rpc(*stub, 1).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(h.delegate.total() == 0);
    REQUIRE(h.audit.size() == 1);

    const std::string spki = pin_of(client->cert_pem);
    std::lock_guard lk(h.audit.mu);
    const auto& row = h.audit.rows.front();
    INFO("reason " << expected_reason);
    CHECK(row.action == "session.gateway_peer_denied");
    CHECK(row.result == "denied");
    CHECK(row.principal == "gateway-peer:" + spki.substr(0, 8));
    // The peer authenticated at TLS but was refused: it is not labelled a gateway.
    CHECK(row.principal_role == "unverified_peer");
    CHECK(row.principal_class.empty());
    CHECK(row.target_type == "GatewayRpc");
    CHECK(row.target_id == "batch_heartbeat");
    CHECK(row.source_ip == "127.0.0.1");
    CHECK(row.detail ==
          "reason=" + expected_reason + " rpc=batch_heartbeat spki=" + spki.substr(0, 16));
    // Hex digits and closed labels only: no certificate text, subject name or line break.
    CHECK(row.detail.find("BEGIN") == std::string::npos);
    CHECK(row.detail.find("Gateway Subject CN") == std::string::npos);
    CHECK(row.detail.find_first_of("\r\n") == std::string::npos);
    CHECK(row.principal.find("Gateway Subject CN") == std::string::npos);
}

TEST_CASE("gateway_peer_guard: denials with no key (null context, unauthenticated) write no row "
          "however many arrive, and spend no audit budget",
          "[gateway_peer][guard][grpc][mtls][audit]") {
    std::int64_t now_ms = 0;
    auto budget = std::make_shared<DenialAuditBudget>(2, 60'000, [&] { return now_ms; });
    GuardHarness h(budget);
    const auto other = gwt::make_gateway_leaf(h.ca, "other");
    h.start({kUnrelatedPin});

    // 20 anonymous denials over the wire, 20 null-context denials direct.
    auto anon = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, nullptr, h.ca.cert_pem));
    apb::RegisterRequest req;
    apb::RegisterResponse resp;
    for (int i = 0; i < 20; ++i) {
        CHECK(call_rpc(*anon, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(h.guard->ProxyRegister(nullptr, &req, &resp).error_code() ==
              grpc::StatusCode::UNAUTHENTICATED);
    }
    CHECK(h.audit.size() == 0);
    CHECK(h.denied("proxy_register", "not_authenticated") == 20);
    CHECK(h.denied("proxy_register", "null_context") == 20);
    CHECK(h.suppressed() == 0);
    CHECK(budget->suppressed_total() == 0);
    CHECK(budget->live_keys() == 0);

    // A certificate holder's first denial still gets its row: the flood spent nothing.
    auto holder = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &other, h.ca.cert_pem));
    CHECK(call_rpc(*holder, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(h.audit.size() == 1);
}

TEST_CASE("gateway_peer_guard: audit rows are bounded per key by the budget, the counter is not",
          "[gateway_peer][guard][grpc][mtls][audit][budget]") {
    std::int64_t now_ms = 0;
    auto budget = std::make_shared<DenialAuditBudget>(2, 60'000, [&] { return now_ms; });
    GuardHarness h(budget);
    const auto other_a = gwt::make_gateway_leaf(h.ca, "other-a");
    const auto other_b = gwt::make_gateway_leaf(h.ca, "other-b");
    h.start({kUnrelatedPin});
    auto stub_a = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &other_a, h.ca.cert_pem));
    auto stub_b = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &other_b, h.ca.cert_pem));

    yuzu::test::LogCapture cap;
    for (int i = 0; i < 5; ++i)
        CHECK(call_rpc(*stub_a, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(h.denied_total_all() == 5); // unsampled
    CHECK(h.audit.size() == 2);       // bounded
    CHECK(h.suppressed() == 3);       // exported
    CHECK(budget->suppressed_total() == 3);

    // Another peer is keyed separately and still gets its own rows.
    CHECK(call_rpc(*stub_b, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(call_rpc(*stub_b, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(call_rpc(*stub_b, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(h.audit.size() == 4);
    CHECK(h.suppressed() == 4);
    CHECK(h.delegate.total() == 0);

    // The window closes; the next denial reports the closed window once, in one aggregate line.
    now_ms += 60'001;
    CHECK(call_rpc(*stub_a, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(call_rpc(*stub_a, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    cap.stop();
    const std::string text = cap.text();
    const std::string needle = "4 denial audit rows suppressed in the last window";
    const auto first = text.find(needle);
    REQUIRE(first != std::string::npos);
    CHECK(text.find(needle, first + 1) == std::string::npos);
}

TEST_CASE("gateway_peer_guard: past the key bound, one reason's flood does not use up another "
          "reason's overflow rows",
          "[gateway_peer][guard][grpc][mtls][audit][budget]") {
    // One tracked key in total, two rows per key: every later key falls into its reason's
    // overflow bucket.
    std::int64_t now_ms = 0;
    auto budget = std::make_shared<DenialAuditBudget>(2, 60'000, [&] { return now_ms; },
                                                      /*max_keys=*/1);
    GuardHarness h(budget);
    std::vector<gwt::TestLeaf> unpinned; // denied as not_pinned
    std::vector<gwt::TestLeaf> agents;   // denied as no_server_auth_eku
    for (int i = 0; i < 4; ++i)
        unpinned.push_back(gwt::make_gateway_leaf(h.ca, "unpinned-" + std::to_string(i)));
    for (int i = 0; i < 3; ++i)
        agents.push_back(gwt::make_agent_leaf(h.ca, "agent-" + std::to_string(i)));
    h.start({kUnrelatedPin});

    const auto deny_with = [&](const gwt::TestLeaf& leaf) {
        auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &leaf, h.ca.cert_pem));
        CHECK(call_rpc(*stub, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    };
    // unpinned[0] takes the one tracked key. unpinned[1..3] are three new keys for one reason:
    // 2 overflow rows, 1 refused.
    for (const auto& leaf : unpinned)
        deny_with(leaf);
    // Three new keys for ANOTHER reason: that reason's own overflow bucket, 2 rows, 1 refused.
    for (const auto& leaf : agents)
        deny_with(leaf);

    std::size_t not_pinned_rows = 0;
    std::size_t eku_rows = 0;
    {
        std::lock_guard lk(h.audit.mu);
        for (const auto& row : h.audit.rows) {
            if (row.detail.rfind("reason=not_pinned ", 0) == 0)
                ++not_pinned_rows;
            if (row.detail.rfind("reason=no_server_auth_eku ", 0) == 0)
                ++eku_rows;
        }
    }
    CHECK(not_pinned_rows == 3); // 1 tracked + 2 overflow
    CHECK(eku_rows == 2);        // not starved by the not_pinned flood
    CHECK(h.suppressed() == 2);
    CHECK(h.denied("proxy_register", "not_pinned") == 4); // the counter stayed complete
    CHECK(h.denied("proxy_register", "no_server_auth_eku") == 3);
}

TEST_CASE("gateway_peer_guard: key-less denials log through their own bounded budget",
          "[gateway_peer][guard][audit][budget]") {
    std::int64_t now_ms = 0;
    auto log_budget = std::make_shared<DenialAuditBudget>(2, 60'000, [&] { return now_ms; });
    GuardHarness h(std::make_shared<DenialAuditBudget>(1000, 60'000), log_budget);
    h.use({kUnrelatedPin});

    yuzu::test::LogCapture cap;
    apb::RegisterRequest req;
    apb::RegisterResponse resp;
    for (int i = 0; i < 6; ++i)
        CHECK(h.guard->ProxyRegister(nullptr, &req, &resp).error_code() ==
              grpc::StatusCode::UNAUTHENTICATED);
    cap.stop();
    const std::string text = cap.text();
    // A null context has no peer address: the line says `unknown` rather than omitting the field.
    const std::string needle =
        "gateway peer denied: rpc=proxy_register reason=null_context peer=unknown";
    std::size_t lines = 0;
    for (auto at = text.find(needle); at != std::string::npos; at = text.find(needle, at + 1))
        ++lines;
    CHECK(lines == 2);                                  // bounded
    CHECK(h.denied("proxy_register", "null_context") == 6); // the counter is complete
    CHECK(h.audit.size() == 0);
}

TEST_CASE("gateway_peer_guard: an anonymous caller's warning carries the peer address",
          "[gateway_peer][guard][grpc][mtls][audit]") {
    GuardHarness h;
    h.start({kUnrelatedPin});
    auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, nullptr, h.ca.cert_pem));
    yuzu::test::LogCapture cap;
    CHECK(call_rpc(*stub, 1).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    cap.stop();
    // The only attribution an unauthenticated caller has is where it connected from.
    CHECK(cap.text().find("gateway peer denied: rpc=batch_heartbeat reason=not_authenticated "
                          "peer=127.0.0.1") != std::string::npos);
}

TEST_CASE("gateway_peer_guard: an internal_error with no computable key writes NO row and counts "
          "exactly once",
          "[gateway_peer][guard][audit]") {
    // A null pin set, and a policy clock that throws, both end as `internal_error` BEFORE any
    // certificate is parsed, so there is no key to attribute: the counter moves once and the audit
    // sink (which is wired and would accept the row) is never called.
    RecordingDelegate delegate;
    AuditCollector audit;
    yuzu::MetricsRegistry metrics;
    const AuditSinkFn sink = [&audit](const AuditEvent& e) { return audit(e); };
    apb::RegisterRequest req;
    apb::RegisterResponse resp;

    SECTION("a null pin set") {
        GatewayPeerGuardedService guard(delegate, gp::GatewayPeerPolicy(nullptr), sink, &metrics);
        CHECK(guard.ProxyRegister(nullptr, &req, &resp).error_code() ==
              grpc::StatusCode::UNAUTHENTICATED);
    }
    SECTION("a policy clock that throws") {
        GatewayPeerGuardedService guard(
            delegate,
            gp::GatewayPeerPolicy(
                std::make_shared<const gp::PinSet>(std::vector<std::string>{kUnrelatedPin}),
                []() -> std::chrono::system_clock::time_point {
                    throw std::runtime_error("clock");
                }),
            sink, &metrics);
        CHECK(guard.ProxyRegister(nullptr, &req, &resp).error_code() ==
              grpc::StatusCode::UNAUTHENTICATED);
    }
    const double internal =
        metrics
            .counter("yuzu_server_gateway_peer_denied_total",
                     {{"rpc", "proxy_register"}, {"reason", "internal_error"}, {"event", "security"}})
            .value();
    CHECK(internal == 1);
    CHECK(audit.size() == 0);
    CHECK(delegate.total() == 0);
}

TEST_CASE("gateway_peer_guard: concurrent denials over the wire keep the counter complete and the "
          "rows bounded",
          "[gateway_peer][guard][grpc][mtls][audit][budget][threads]") {
    // Four threads of keyed denials (one certificate holder, not_pinned) and four of key-less ones
    // (anonymous), 25 calls each, against one guard. The budget is fixed at 5 rows per key for the
    // whole run (a constant clock), so the totals are exact: every call is counted, exactly 5 rows
    // are written, and every other keyed denial is counted as suppressed.
    constexpr int kThreadsPerKind = 4;
    constexpr int kCallsPerThread = 25;
    constexpr int kKeyedCalls = kThreadsPerKind * kCallsPerThread;
    constexpr std::size_t kRowBudget = 5;
    auto budget = std::make_shared<DenialAuditBudget>(kRowBudget, 60'000, [] { return 0; });
    auto log_budget = std::make_shared<DenialAuditBudget>(2, 60'000, [] { return 0; });
    GuardHarness h(budget, log_budget);
    const auto holder = gwt::make_gateway_leaf(h.ca, "holder");
    h.start({kUnrelatedPin});
    const auto keyed = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &holder, h.ca.cert_pem));
    const auto anon = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, nullptr, h.ca.cert_pem));

    std::atomic<int> wrong_status{0};
    std::vector<std::thread> threads;
    yuzu::test::ScopeExit join_all([&] {
        for (auto& th : threads)
            if (th.joinable())
                th.join();
    });
    const auto worker = [&](gw::GatewayUpstream::Stub* stub) {
        for (int i = 0; i < kCallsPerThread; ++i) {
            const auto st = call_rpc_status(*stub, 1);
            if (st.error_code() != grpc::StatusCode::UNAUTHENTICATED ||
                st.error_message() != std::string{kGatewayPeerDeniedMessage})
                wrong_status.fetch_add(1);
        }
    };
    for (int t = 0; t < kThreadsPerKind; ++t) {
        threads.emplace_back(worker, keyed.get());
        threads.emplace_back(worker, anon.get());
    }
    for (auto& th : threads)
        th.join();

    CHECK(wrong_status.load() == 0);
    CHECK(h.delegate.total() == 0);
    CHECK(h.denied("batch_heartbeat", "not_pinned") == kKeyedCalls);
    CHECK(h.denied("batch_heartbeat", "not_authenticated") == kKeyedCalls);
    CHECK(h.denied_total_all() == 2 * kKeyedCalls); // the counter is complete
    CHECK(h.audit.size() == kRowBudget);            // rows bounded, and only keyed denials write
    CHECK(h.suppressed() == kKeyedCalls - kRowBudget);
    CHECK(budget->suppressed_total() == kKeyedCalls - kRowBudget);
    CHECK(log_budget->suppressed_total() == kKeyedCalls - 2u); // the anonymous warnings are bounded too
    // Teardown is the harness destructor: Shutdown with in-flight work finished must not hang.
}

// -- telemetry can never flip a deny -------------------------------------------------------

TEST_CASE("gateway_peer_guard: telemetry failure never turns a deny into an allow or escapes",
          "[gateway_peer][guard][grpc][mtls]") {
    GuardHarness h;
    const auto other = gwt::make_gateway_leaf(h.ca, "other");
    h.start({kUnrelatedPin});
    apb::RegisterRequest req;
    apb::RegisterResponse resp;
    auto stub = gw::GatewayUpstream::NewStub(h.channel(h.optional_port, &other, h.ca.cert_pem));

    SECTION("the audit sink reports failure") {
        h.audit.fail = true;
        CHECK(call_rpc(*stub, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    }
    SECTION("the audit sink throws") {
        h.audit.throws = true;
        CHECK(call_rpc(*stub, 0).error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(call_rpc(*stub, 3).error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(h.denied("notify_stream_status", "not_pinned") == 1);
    }
    SECTION("the audit sink throws on a null-context denial too") {
        h.audit.throws = true;
        CHECK(h.guard->ProxyRegister(nullptr, &req, &resp).error_code() ==
              grpc::StatusCode::UNAUTHENTICATED);
    }
    CHECK(h.delegate.total() == 0);
    CHECK(h.denied("proxy_register", "not_pinned") + h.denied("proxy_register", "null_context") >=
          1); // counted before the audit step

    // The policy's clock throws: the decision is an internal_error deny.
    RecordingDelegate bare;
    GatewayPeerGuardedService throwing_clock(
        bare,
        gp::GatewayPeerPolicy(
            std::make_shared<const gp::PinSet>(std::vector<std::string>{kUnrelatedPin}),
            []() -> std::chrono::system_clock::time_point { throw std::runtime_error("clock"); }),
        GatewayPeerGuardedService::AuditSink{}, nullptr);
    const auto results = call_all_with_null_context(throwing_clock);
    for (const auto& st : results)
        CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);

    // No metrics registry and no audit sink at all: still a plain deny.
    GatewayPeerGuardedService bare_guard(
        bare,
        gp::GatewayPeerPolicy(
            std::make_shared<const gp::PinSet>(std::vector<std::string>{kUnrelatedPin})),
        GatewayPeerGuardedService::AuditSink{}, nullptr);
    CHECK(bare_guard.ProxyRegister(nullptr, &req, &resp).error_code() ==
          grpc::StatusCode::UNAUTHENTICATED);
    CHECK(bare.total() == 0);

    // A null pin set is a deny, never an allow.
    GatewayPeerGuardedService no_pins(bare, gp::GatewayPeerPolicy(nullptr),
                                      GatewayPeerGuardedService::AuditSink{}, nullptr);
    CHECK(no_pins.ProxyRegister(nullptr, &req, &resp).error_code() ==
          grpc::StatusCode::UNAUTHENTICATED);
    CHECK(bare.total() == 0);
}

// -- the explicit acknowledgement ------------------------------------------------------------

TEST_CASE("gateway_peer_guard: the acknowledged-insecure guard admits every caller on every port "
          "and writes nothing",
          "[gateway_peer][guard][grpc][mtls][ack]") {
    GuardHarness h;
    const auto agent = gwt::make_agent_leaf(h.ca, "agent-1");
    h.use_acknowledged();
    h.listen();

    // Directly, with no ServerContext at all: admitted (this mode has no policy).
    apb::RegisterRequest rq;
    apb::RegisterResponse rs;
    CHECK(h.guard->ProxyRegister(nullptr, &rq, &rs).ok());
    CHECK(h.delegate.calls[0].load() == 1);

    // Anonymous on the optional port, and a clientAuth-only leaf on both: one delegation per RPC.
    int expected = 1;
    const std::array<std::pair<int, const gwt::TestLeaf*>, 3> callers{
        {{h.optional_port, nullptr}, {h.optional_port, &agent}, {h.required_port, &agent}}};
    for (const auto& [port, leaf] : callers) {
        auto stub = gw::GatewayUpstream::NewStub(h.channel(port, leaf, h.ca.cert_pem));
        for (int i = 0; i < kRpcCount; ++i) {
            INFO("rpc " << kRpcNames[i] << " port " << port);
            CHECK(call_rpc(*stub, i).ok());
            ++expected;
        }
    }
    CHECK(h.delegate.total() == expected);

    // Nothing was denied, so no series moved and no row was written.
    CHECK(h.denied_total_all() == 0);
    CHECK(h.audit.size() == 0);
    CHECK(h.suppressed() == 0);
}

TEST_CASE("gateway_peer_guard: the acknowledged-insecure guard also serves a plaintext listener",
          "[gateway_peer][guard][grpc][ack]") {
    yuzu::MetricsRegistry metrics;
    RecordingDelegate delegate;
    GatewayPeerGuardedService guard(delegate, GatewayPeerGuardedService::AcknowledgedInsecure{},
                                    &metrics);
    int port = 0;
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
    builder.RegisterService(&guard);
    auto server = builder.BuildAndStart();
    REQUIRE(server != nullptr);
    REQUIRE(port != 0);
    auto stub = gw::GatewayUpstream::NewStub(grpc::CreateChannel(
        "127.0.0.1:" + std::to_string(port), grpc::InsecureChannelCredentials()));
    for (int i = 0; i < kRpcCount; ++i) {
        INFO("rpc " << kRpcNames[i]);
        CHECK(call_rpc(*stub, i).ok());
    }
    server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    CHECK(delegate.total() == kRpcCount);
}

// -- DenialAuditBudget -------------------------------------------------------------------------

TEST_CASE("DenialAuditBudget: admits max_rows per key per window, then refuses, then reopens",
          "[gateway_peer][budget]") {
    std::int64_t now_ms = 1000;
    DenialAuditBudget b(3, 1000, [&] { return now_ms; });
    CHECK(b.try_admit("k").admitted);
    CHECK(b.try_admit("k").admitted);
    CHECK(b.try_admit("k").admitted);
    CHECK_FALSE(b.try_admit("k").admitted);
    CHECK_FALSE(b.try_admit("k").admitted);
    CHECK(b.suppressed_total() == 2);

    now_ms = 1999; // still inside the window that opened at 1000
    CHECK_FALSE(b.try_admit("k").admitted);
    now_ms = 2000; // window elapsed
    CHECK(b.try_admit("k").admitted);
    CHECK(b.try_admit("k").admitted);
    CHECK(b.try_admit("k").admitted);
    CHECK_FALSE(b.try_admit("k").admitted);
}

TEST_CASE("DenialAuditBudget: keys are budgeted independently", "[gateway_peer][budget]") {
    std::int64_t now_ms = 0;
    DenialAuditBudget b(2, 10'000, [&] { return now_ms; });
    // One key floods; another key's rows are untouched.
    for (int i = 0; i < 50; ++i)
        (void)b.try_admit("not_pinned|aaaaaaaa");
    CHECK(b.suppressed_total() == 48);
    CHECK(b.try_admit("not_pinned|a1b2c3d4").admitted);
    CHECK(b.try_admit("not_pinned|a1b2c3d4").admitted);
    CHECK_FALSE(b.try_admit("not_pinned|a1b2c3d4").admitted);
    CHECK(b.try_admit("not_pinned|99999999").admitted); // a different key again
}

TEST_CASE("DenialAuditBudget: a key is truncated to kAuditMaxKeyBytes before use",
          "[gateway_peer][budget]") {
    std::int64_t now_ms = 0;
    DenialAuditBudget b(1, 10'000, [&] { return now_ms; });
    const std::string prefix(yuzu::server::kAuditMaxKeyBytes, 'k');
    // Two keys that differ only AFTER the bound are the same key: the second is refused.
    CHECK(b.try_admit(prefix + "A").admitted);
    CHECK_FALSE(b.try_admit(prefix + "B").admitted);
    CHECK(b.live_keys() == 1);
    // A key that differs inside the bound is a different key.
    std::string inside = prefix;
    inside[yuzu::server::kAuditMaxKeyBytes - 1] = 'z';
    CHECK(b.try_admit(inside + "A").admitted);
    CHECK(b.live_keys() == 2);
    // The overflow key is truncated the same way: a 10 kB name cannot grow the table.
    DenialAuditBudget tiny(1, 10'000, [&] { return now_ms; }, /*max_keys=*/1);
    (void)tiny.try_admit("first", "g");
    for (int i = 0; i < 50; ++i)
        (void)tiny.try_admit("n" + std::to_string(i), std::string(10'000, 'g') + std::to_string(i));
    CHECK(tiny.live_keys() <= 3);
}

TEST_CASE("DenialAuditBudget: distinct keys are bounded, the excess shares one overflow key",
          "[gateway_peer][budget]") {
    std::int64_t now_ms = 0;
    DenialAuditBudget b(2, 10'000, [&] { return now_ms; }, /*max_keys=*/3);
    for (int i = 0; i < 3; ++i)
        CHECK(b.try_admit("key" + std::to_string(i)).admitted);
    CHECK(b.live_keys() == 3);

    // Keys beyond the bound share ONE overflow budget of max_rows.
    CHECK(b.try_admit("key3").admitted);
    CHECK(b.try_admit("key4").admitted);
    CHECK_FALSE(b.try_admit("key5").admitted);
    CHECK_FALSE(b.try_admit("key6").admitted);
    CHECK(b.live_keys() == 4); // 3 keys + the overflow bucket, however many more arrive

    // A key that was already live keeps its own budget after the bound is reached.
    CHECK(b.try_admit("key0").admitted);

    for (int i = 0; i < 1000; ++i)
        (void)b.try_admit("flood" + std::to_string(i));
    CHECK(b.live_keys() == 4);

    // A new window forgets every key, so memory does not accumulate across windows.
    now_ms = 10'000;
    CHECK(b.try_admit("fresh").admitted);
    CHECK(b.live_keys() == 1);
}

TEST_CASE("DenialAuditBudget: an overflow flood of one group does not starve another group's "
          "overflow",
          "[gateway_peer][budget]") {
    std::int64_t now_ms = 0;
    DenialAuditBudget b(2, 10'000, [&] { return now_ms; }, /*max_keys=*/3);
    // Fill the tracked-key table so every later key lands in an overflow bucket.
    CHECK(b.try_admit("not_pinned|aaaaaaa0", "not_pinned|*").admitted);
    CHECK(b.try_admit("not_pinned|aaaaaaa1", "not_pinned|*").admitted);
    CHECK(b.try_admit("not_pinned|aaaaaaa2", "not_pinned|*").admitted);

    // A flood of new keys for one reason spends THAT reason's overflow budget only.
    int admitted_a = 0;
    for (int i = 0; i < 500; ++i)
        if (b.try_admit("not_pinned|flood" + std::to_string(i), "not_pinned|*").admitted)
            ++admitted_a;
    CHECK(admitted_a == 2);

    // Another reason's new keys still get theirs.
    CHECK(b.try_admit("outside_validity|bbbbbbb0", "outside_validity|*").admitted);
    CHECK(b.try_admit("outside_validity|bbbbbbb1", "outside_validity|*").admitted);
    CHECK_FALSE(b.try_admit("outside_validity|bbbbbbb2", "outside_validity|*").admitted);

    // An already-tracked key keeps its own budget, untouched by either flood.
    CHECK(b.try_admit("not_pinned|aaaaaaa0", "not_pinned|*").admitted);

    // Memory stays bounded: the tracked keys plus one overflow bucket per reason seen.
    CHECK(b.live_keys() == 3 + 2);

    // A call that names no overflow key shares the one default bucket.
    CHECK(b.try_admit("x1").admitted);
    CHECK(b.try_admit("x2").admitted);
    CHECK_FALSE(b.try_admit("x3").admitted);
}

TEST_CASE("DenialAuditBudget: overflow buckets are themselves bounded", "[gateway_peer][budget]") {
    std::int64_t now_ms = 0;
    DenialAuditBudget b(1, 10'000, [&] { return now_ms; }, /*max_keys=*/2);
    (void)b.try_admit("k0", "g0");
    (void)b.try_admit("k1", "g1");
    // Unlimited distinct overflow keys cannot grow the table without bound.
    for (int i = 0; i < 5000; ++i)
        (void)b.try_admit("n" + std::to_string(i), "group" + std::to_string(i));
    CHECK(b.live_keys() <= 2 * 2 + 1);
}

TEST_CASE("DenialAuditBudget: concurrent callers stay within the per-key bounds",
          "[gateway_peer][budget][threads]") {
    constexpr std::size_t kMaxRows = 3;
    constexpr std::size_t kMaxKeys = 8;
    constexpr int kThreads = 6;
    constexpr int kCalls = 400;
    std::atomic<std::int64_t> now_ms{0}; // one window for the whole run
    DenialAuditBudget b(kMaxRows, 60'000, [&] { return now_ms.load(); }, kMaxKeys);

    std::atomic<std::uint64_t> admitted{0};
    std::vector<std::thread> threads;
    yuzu::test::ScopeExit join_all([&] {
        for (auto& th : threads)
            if (th.joinable())
                th.join();
    });
    const char* reasons[] = {"no_server_auth_eku", "not_pinned", "outside_validity",
                             "internal_error"};
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < kCalls; ++i) {
                const std::string reason = reasons[(t + i) % 4];
                // Many distinct keys per reason, so the key table fills and overflows.
                const std::string key = reason + "|" + std::to_string((t * 31 + i) % 40);
                if (b.try_admit(key, reason + "|*").admitted)
                    admitted.fetch_add(1);
                if (i % 50 == 0)
                    (void)b.live_keys();
            }
        });
    }
    for (auto& th : threads)
        th.join();

    const std::uint64_t calls = static_cast<std::uint64_t>(kThreads) * kCalls;
    // Every call is either admitted or counted as suppressed: nothing is lost under contention.
    CHECK(admitted.load() + b.suppressed_total() == calls);
    // At most kMaxKeys tracked keys plus one overflow bucket per reason, kMaxRows rows each.
    CHECK(admitted.load() <= kMaxRows * (kMaxKeys + 4));
    CHECK(b.live_keys() <= kMaxKeys + 4);
}

TEST_CASE("DenialAuditBudget: the call that opens a new window reports the closed window's "
          "suppressions once",
          "[gateway_peer][budget]") {
    std::int64_t now_ms = 0;
    DenialAuditBudget b(1, 1000, [&] { return now_ms; });
    CHECK(b.try_admit("k").admitted);
    for (int i = 0; i < 4; ++i)
        CHECK_FALSE(b.try_admit("k").admitted);
    CHECK(b.try_admit("k2").closed_window_suppressed == 0); // same window: nothing closed yet

    now_ms = 1000;
    const auto reopened = b.try_admit("k");
    CHECK(reopened.admitted);
    CHECK(reopened.closed_window_suppressed == 4);
    CHECK(b.try_admit("k2").closed_window_suppressed == 0); // reported once

    // A window that suppressed nothing reports nothing.
    now_ms = 2000;
    const auto quiet = b.try_admit("k3");
    CHECK(quiet.admitted);
    CHECK(quiet.closed_window_suppressed == 0);
}

TEST_CASE("DenialAuditBudget: a clock that steps backwards cannot reopen a spent window",
          "[gateway_peer][budget]") {
    std::int64_t now_ms = 5000;
    DenialAuditBudget b(1, 1000, [&] { return now_ms; });
    CHECK(b.try_admit("k").admitted);
    now_ms = 100;
    CHECK_FALSE(b.try_admit("k").admitted);
}

TEST_CASE("DenialAuditBudget: zero rows never admits, a non-positive window is sanitized",
          "[gateway_peer][budget]") {
    std::int64_t now_ms = 0;
    DenialAuditBudget none(0, 1000, [&] { return now_ms; });
    CHECK_FALSE(none.try_admit("k").admitted);

    DenialAuditBudget odd(1, -5, [&] { return now_ms; });
    CHECK(odd.try_admit("k").admitted);
    CHECK_FALSE(odd.try_admit("k").admitted);
    now_ms = 1;
    CHECK(odd.try_admit("k").admitted);
}

TEST_CASE("DenialAuditBudget: defaults and the real clock path", "[gateway_peer][budget]") {
    CHECK(yuzu::server::kDefaultAuditMaxRows == 10);
    CHECK(yuzu::server::kDefaultAuditWindowMs == 10'000);
    CHECK(yuzu::server::kDefaultAuditMaxKeys == 64);
    DenialAuditBudget real; // steady_clock, default sizing
    for (std::size_t i = 0; i < yuzu::server::kDefaultAuditMaxRows; ++i)
        CHECK(real.try_admit("k").admitted);
    CHECK_FALSE(real.try_admit("k").admitted);
}
