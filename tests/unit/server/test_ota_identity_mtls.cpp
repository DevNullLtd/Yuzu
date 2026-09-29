/**
 * test_ota_identity_mtls.cpp — the OTA identity-deny audit bound, over a REAL
 * mTLS wire with real certificates.
 *
 * WHY THIS FILE EXISTS, and it is not a nice-to-have. The audit rate limiter has
 * now shipped broken twice, and the second break was invisible: a gate-8 mutation
 * reverting its key to the caller's `claimed_agent_id` left the entire server
 * suite green — 42,326 assertions, zero failures. `test_ota_download_bound.cpp`
 * cannot reach the limiter at all, because an insecure channel presents no
 * certificate and every rejection it can provoke is `no_client_identity`, which
 * short-circuits before the limiter is consulted.
 *
 * So this file issues real certificates from a real in-memory CA and connects
 * over real mTLS. It is the only place the bound is observable.
 *
 * WHAT IT PROVES:
 *   1. A peer varying its claimed agent_id per request gets ONE bucket, not one
 *      per claim. This is the mutation that survived.
 *   2. A foreign-CA peer spoofing CN=<victim> lands in a DIFFERENT bucket from
 *      the victim, so it cannot spend the victim's allowance and silence the
 *      victim's audit rows.
 *
 * WHY NO POSTGRES. `AuditStore` needs a `PgPool`, which would put this file in
 * the `[pg]` shard. The limiter is deliberately consulted before the store is
 * checked (see the handler), and its suppression is published as
 * `yuzu_ota_identity_audit_suppressed_total`, so the bound is observable without
 * a store. What is NOT proven here is the row-writing itself.
 */

#include "agent_service_impl.hpp"

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>

#include <chrono>
#include <memory>
#include <string>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "x509_ca.hpp"

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;

namespace {

namespace apb = ::yuzu::agent::v1;
namespace ca = yuzu::server::pki;

struct Pki {
    std::string ca_key, ca_cert;
    std::string leaf_key, leaf_cert;
};

/// A CA plus one leaf under it. `client_auth` picks the EKU.
Pki make_pki(const std::string& ca_cn, const std::string& leaf_cn, bool client_auth) {
    Pki p;
    auto ca_key = ca::generate_private_key(ca::KeyAlgo::EcP384);
    REQUIRE(ca_key.has_value());
    p.ca_key = *ca_key;

    ca::CaParams cap;
    cap.subject.common_name = ca_cn;
    cap.subject.organization = "YuzuTest";
    cap.validity = ca::validity_days_from_now(2);
    auto ca_cert = ca::self_sign_ca(p.ca_key, cap);
    REQUIRE(ca_cert.has_value());
    p.ca_cert = *ca_cert;

    ca::LeafParams lp;
    lp.subject.common_name = leaf_cn;
    lp.subject.organization = "YuzuTest";
    lp.validity = ca::validity_days_from_now(1);
    lp.usage.client_auth = client_auth;
    lp.usage.server_auth = !client_auth;
    if (!client_auth) {
        lp.san.dns.push_back("localhost");
        lp.san.ips.push_back("127.0.0.1");
    }
    auto leaf = ca::issue_leaf(p.ca_cert, p.ca_key, ca::KeyAlgo::EcP256, lp);
    REQUIRE(leaf.has_value());
    p.leaf_key = leaf->private_key_pem;
    p.leaf_cert = leaf->cert_pem;
    return p;
}

/// Real gRPC server over mTLS. Member order is load-bearing for the same reason
/// as OtaHarness: `svc` borrows references into the members above it.
struct MtlsHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};

    std::unique_ptr<grpc::Server> server_;
    int port_ = 0;

    /// `trust_bundle` may hold more than one CA — that IS the scenario the
    /// foreign-CA case exists for.
    void start(const Pki& server_pki, const std::string& trust_bundle) {
        grpc::SslServerCredentialsOptions opts(
            GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
        opts.pem_root_certs = trust_bundle;
        opts.pem_key_cert_pairs.push_back({server_pki.leaf_key, server_pki.leaf_cert});

        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::SslServerCredentials(opts), &port_);
        builder.RegisterService(&svc);
        server_ = builder.BuildAndStart();
        REQUIRE(server_ != nullptr);
        REQUIRE(port_ != 0);
    }

    std::unique_ptr<apb::AgentService::Stub> connect(const std::string& root,
                                                     const std::string& client_key,
                                                     const std::string& client_cert) const {
        grpc::SslCredentialsOptions opts;
        opts.pem_root_certs = root;
        opts.pem_private_key = client_key;
        opts.pem_cert_chain = client_cert;
        grpc::ChannelArguments args;
        args.SetSslTargetNameOverride("localhost");
        auto channel = grpc::CreateCustomChannel("127.0.0.1:" + std::to_string(port_),
                                                 grpc::SslCredentials(opts), args);
        return apb::AgentService::NewStub(channel);
    }

    ~MtlsHarness() {
        if (server_)
            server_->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    }
};

grpc::Status check(apb::AgentService::Stub& stub, const std::string& claimed) {
    apb::CheckForUpdateRequest req;
    req.set_agent_id(claimed);
    req.set_current_version("0.0.1");
    req.mutable_platform()->set_os("linux");
    req.mutable_platform()->set_arch("x86_64");

    apb::CheckForUpdateResponse resp;
    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
    return stub.CheckForUpdate(&ctx, req, &resp);
}

grpc::Status register_agent(apb::AgentService::Stub& stub, const std::string& agent_id) {
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(agent_id);
    req.mutable_info()->set_hostname("test-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");

    apb::RegisterResponse resp;
    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
    return stub.Register(&ctx, req, &resp);
}

double suppressed(const yuzu::MetricsRegistry& m, const char* reason) {
    return const_cast<yuzu::MetricsRegistry&>(m)
        .counter("yuzu_ota_identity_audit_suppressed_total",
                 {{"rpc", "check_for_update"}, {"reason", reason}})
        .value();
}

} // namespace

TEST_CASE("OTA audit bound: a peer varying its claim still gets ONE bucket",
          "[ota][identity][mtls]") {
    // THE MUTATION THAT SURVIVED GATE 8. Key the limiter on the claimed agent_id
    // and every one of these calls mints a fresh, always-admitting bucket, so
    // nothing is ever suppressed. Key it on the peer and they all land in one.
    const Pki server_pki = make_pki("Yuzu Test CA", "localhost", /*client_auth=*/false);
    Pki client = make_pki("unused", "unused", true);
    // Re-issue the client leaf under the SERVER's CA so both are one trust root.
    ca::LeafParams lp;
    lp.subject.common_name = "agent-1";
    lp.subject.organization = "YuzuTest";
    lp.validity = ca::validity_days_from_now(1);
    lp.usage.client_auth = true;
    auto leaf = ca::issue_leaf(server_pki.ca_cert, server_pki.ca_key, ca::KeyAlgo::EcP256, lp);
    REQUIRE(leaf.has_value());

    MtlsHarness h;
    h.svc.set_require_positive_ota_identity(true);
    h.start(server_pki, server_pki.ca_cert);
    auto stub = h.connect(server_pki.ca_cert, leaf->private_key_pem, leaf->cert_pem);

    const double before = suppressed(h.metrics, "agent_id_mismatch");

    // Every call claims a DIFFERENT agent_id — the shape that defeated the
    // original keying. The certificate says agent-1 throughout.
    constexpr int kCalls = 10;
    for (int i = 0; i < kCalls; ++i) {
        auto st = check(*stub, "victim-" + std::to_string(i));
        CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
    }

    // The bucket holds 2 tokens and refills at 2/s; these calls run far faster
    // than that, so most must be suppressed. Asserting ">= half" rather than an
    // exact count keeps this from being a timing assertion.
    const double after = suppressed(h.metrics, "agent_id_mismatch");
    CHECK(after - before >= kCalls / 2);
}

TEST_CASE("OTA audit bound: a foreign-CA impostor cannot spend the victim's allowance",
          "[ota][identity][mtls]") {
    // The multi-CA trust bundle is a supported configuration, and in it
    // ota_admission_key reports mode="cert" for ANY accepted certificate — it
    // does not consult the recognizer. So an impostor holding a cert from the
    // OTHER CA can present CN=agent-1 and arrive with a byte-identical peer key
    // to the real agent-1. Only the REASON separates them.
    const Pki server_pki = make_pki("Yuzu Test CA", "localhost", /*client_auth=*/false);
    const Pki foreign = make_pki("Some Other CA", "agent-1", /*client_auth=*/true);

    ca::LeafParams lp;
    lp.subject.common_name = "agent-1";
    lp.subject.organization = "YuzuTest";
    lp.validity = ca::validity_days_from_now(1);
    lp.usage.client_auth = true;
    auto genuine = ca::issue_leaf(server_pki.ca_cert, server_pki.ca_key, ca::KeyAlgo::EcP256, lp);
    REQUIRE(genuine.has_value());

    MtlsHarness h;
    h.svc.set_require_positive_ota_identity(true);
    // Only certificates issued by OUR CA are agent identities. A crude recognizer
    // is enough here: the production one checks the issuer chain, and what this
    // test needs is only that the foreign cert takes the foreign_ca branch.
    const std::string genuine_pem = genuine->cert_pem;
    h.svc.set_peer_cert_recognizer(
        [genuine_pem](const std::string& pem) { return !pem.empty() && pem == genuine_pem; });

    // BOTH CAs in the trust bundle — that is the whole scenario.
    h.start(server_pki, server_pki.ca_cert + foreign.ca_cert);

    auto impostor_stub = h.connect(server_pki.ca_cert, foreign.leaf_key, foreign.leaf_cert);

    const double victim_before = suppressed(h.metrics, "agent_id_mismatch");
    const double foreign_before = suppressed(h.metrics, "foreign_ca");

    // The impostor floods, spending its own bucket dry.
    for (int i = 0; i < 10; ++i) {
        auto st = check(*impostor_stub, "agent-1");
        CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
    }
    CHECK(suppressed(h.metrics, "foreign_ca") - foreign_before > 0);

    // The victim's own bucket is untouched: its first denial is still audited,
    // which is exactly what the impostor was trying to prevent.
    CHECK(suppressed(h.metrics, "agent_id_mismatch") - victim_before == 0);

    auto victim_stub =
        h.connect(server_pki.ca_cert, genuine->private_key_pem, genuine->cert_pem);
    auto st = check(*victim_stub, "somebody-else");
    CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(suppressed(h.metrics, "agent_id_mismatch") - victim_before == 0);
}

TEST_CASE("gap-matrix #10: a code-signing-only leaf under the trusted CA is refused before "
          "Register (mTLS purpose check)",
          "[ota][identity][mtls][code-signing]") {
    // The whole security argument for exposing POST /api/v1/ca/issue-code-signing
    // without reopening the #1118 agent-impersonation deferral rests on ONE
    // empirical fact: a leaf whose EKU is code_signing ONLY (no client_auth)
    // can never complete the mTLS handshake as a CLIENT certificate, so it can
    // never reach Register/CheckForUpdate/Subscribe at all — regardless of
    // what its CN says. Prove that fact directly rather than assuming it: mint
    // a code_signing-only leaf under the server's own trusted CA with
    // CN=<a real agent_id>, present it as the client cert, and confirm the
    // connection itself is refused (TLS handshake failure surfaces to the
    // client as UNAVAILABLE — grpc never lets the RPC reach the server, so
    // Register's own logic is never even entered).
    const Pki server_pki = make_pki("Yuzu Test CA", "localhost", /*client_auth=*/false);

    ca::LeafParams lp;
    lp.subject.common_name = "agent-1"; // a real, existing agent_id
    lp.subject.organization = "YuzuTest";
    lp.validity = ca::validity_days_from_now(1);
    lp.usage.code_signing = true; // HARD-PINNED shape — no client_auth, no server_auth
    auto leaf = ca::issue_leaf(server_pki.ca_cert, server_pki.ca_key, ca::KeyAlgo::EcP256, lp);
    REQUIRE(leaf.has_value());
    // Confirm the fixture actually produced the shape under test — a mistake
    // here would make the rest of this test vacuous.
    REQUIRE_FALSE(lp.usage.client_auth);
    REQUIRE_FALSE(lp.usage.server_auth);

    MtlsHarness h;
    h.start(server_pki, server_pki.ca_cert);
    auto stub = h.connect(server_pki.ca_cert, leaf->private_key_pem, leaf->cert_pem);

    // Register — the exact RPC the #1118 identity gate lives on the far side
    // of — never gets a chance to run: the channel itself fails.
    auto st = register_agent(*stub, "agent-1");
    CHECK(st.error_code() == grpc::StatusCode::UNAVAILABLE);

    // Same refusal on CheckForUpdate, for good measure: this is a TLS-layer
    // rejection, not something specific to one RPC.
    auto st2 = check(*stub, "agent-1");
    CHECK(st2.error_code() == grpc::StatusCode::UNAVAILABLE);

    // Control: the SAME CA, SAME CN, but a conforming client_auth leaf DOES
    // complete the handshake and reach the server — isolating the refusal
    // above to the EKU shape, not e.g. a CN/CA mismatch in this fixture.
    ca::LeafParams client_lp;
    client_lp.subject.common_name = "agent-1";
    client_lp.subject.organization = "YuzuTest";
    client_lp.validity = ca::validity_days_from_now(1);
    client_lp.usage.client_auth = true;
    auto conforming =
        ca::issue_leaf(server_pki.ca_cert, server_pki.ca_key, ca::KeyAlgo::EcP256, client_lp);
    REQUIRE(conforming.has_value());
    auto conforming_stub =
        h.connect(server_pki.ca_cert, conforming->private_key_pem, conforming->cert_pem);
    auto ok_st = check(*conforming_stub, "agent-1");
    CHECK(ok_st.error_code() != grpc::StatusCode::UNAVAILABLE);
}
