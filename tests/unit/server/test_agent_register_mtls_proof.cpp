/**
 * test_agent_register_mtls_proof.cpp - WP01: the DIRECT path's only proof input, over a REAL mTLS
 * wire with real certificates and a real Postgres-backed enrollment store.
 *
 * Every other WP01 handler test supplies the direct path's "the presented certificate proves this
 * agent id" through the override_cert_proof_for_test seam. That leaves the real derivation
 * (AgentServiceImpl::Register: the auth-context peer identities, the recognizer, the CN match, the
 * revocation checker -> cert_proves_identity) unexercised, and a mutation that sets
 * cert_proves_identity = true, or turns off the revocation check or the CN match, would leave the
 * suite green. This file drives Register through a real grpc::Server with an
 * enforce-mode gate and a live-leaf fake leaf-state, and asserts the outcome per case.
 *
 * Rows: real leaf (admitted); a foreign-CA leaf carrying the victim's CN (refused); a revoked leaf
 * (refused); a CN mismatch (refused); no certificate (refused); no certificate + a single-use token
 * (admitted through the token path).
 */

#include "agent_service_impl.hpp"

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>

#include <chrono>
#include <memory>
#include <set>
#include <string>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "x509_ca.hpp"

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;

namespace {

namespace apb = ::yuzu::agent::v1;
namespace ca = yuzu::server::pki;

struct Ca {
    std::string key, cert;
};

Ca make_ca(const std::string& cn) {
    auto key = ca::generate_private_key(ca::KeyAlgo::EcP384);
    REQUIRE(key.has_value());
    ca::CaParams cap;
    cap.subject.common_name = cn;
    cap.subject.organization = "YuzuTest";
    cap.validity = ca::validity_days_from_now(2);
    auto cert = ca::self_sign_ca(*key, cap);
    REQUIRE(cert.has_value());
    return {*key, *cert};
}

struct Leaf {
    std::string key, cert;
};

Leaf make_leaf(const Ca& issuer, const std::string& cn, bool server = false) {
    ca::LeafParams lp;
    lp.subject.common_name = cn;
    lp.subject.organization = "YuzuTest";
    lp.validity = ca::validity_days_from_now(1);
    lp.usage.client_auth = !server;
    lp.usage.server_auth = server;
    if (server) {
        lp.san.dns.push_back("localhost");
        lp.san.ips.push_back("127.0.0.1");
    }
    auto leaf = ca::issue_leaf(issuer.cert, issuer.key, ca::KeyAlgo::EcP256, lp);
    REQUIRE(leaf.has_value());
    return {leaf->private_key_pem, leaf->cert_pem};
}

struct Harness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::test::AuthDbPgShared auth_db;
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry, bus, /*require_client_identity=*/true, auth_mgr, auto_approve,
                         metrics, /*gateway_mode=*/false};
    std::unique_ptr<grpc::Server> server;
    int port = 0;
    std::set<std::string> revoked_pems;
    std::set<std::string> superseded_pems; // revoked pems the SERVER superseded (reenrolled)

    Harness() { auth_mgr.set_auth_db(auth_db.get()); }

    // `our_ca` signs the server leaf; the trust bundle holds every CA a client may use. The
    // listener REQUESTS but does not require a client certificate, like the default-cert agent
    // listener, so a certless client still reaches Register.
    void start(const Ca& our_ca, const std::string& bundle) {
        const Leaf server_leaf = make_leaf(our_ca, "localhost", /*server=*/true);
        grpc::SslServerCredentialsOptions opts(GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY);
        opts.pem_root_certs = bundle;
        opts.pem_key_cert_pairs.push_back({server_leaf.key, server_leaf.cert});
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::SslServerCredentials(opts), &port);
        builder.RegisterService(&svc);
        server = builder.BuildAndStart();
        REQUIRE(server != nullptr);
    }

    std::unique_ptr<apb::AgentService::Stub> connect(const Ca& our_ca, const Leaf* client) const {
        grpc::SslCredentialsOptions opts;
        opts.pem_root_certs = our_ca.cert;
        if (client) {
            opts.pem_private_key = client->key;
            opts.pem_cert_chain = client->cert;
        }
        grpc::ChannelArguments args;
        args.SetSslTargetNameOverride("localhost");
        return apb::AgentService::NewStub(grpc::CreateCustomChannel(
            "127.0.0.1:" + std::to_string(port), grpc::SslCredentials(opts), args));
    }

    ~Harness() {
        if (server)
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    }
};

struct Outcome {
    grpc::Status status;
    apb::RegisterResponse resp;
};

Outcome register_as(apb::AgentService::Stub& stub, const std::string& id,
                    const std::string& token = {}) {
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(id);
    req.mutable_info()->set_hostname("h");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    if (!token.empty())
        req.set_enrollment_token(token);
    Outcome o;
    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
    o.status = stub.Register(&ctx, req, &o.resp);
    return o;
}

// Wire the production-shaped pieces: recognizer = chains to OUR CA; revocation = a PEM set; the
// gate in enforce mode over a fake "this id holds a live leaf" state.
void wire(Harness& h, const Ca& our_ca, std::shared_ptr<yuzu::server::AgentIdentityHooks>& hooks) {
    h.svc.set_peer_cert_recognizer([our_ca](const std::string& pem) {
        return !pem.empty() && ca::verify_chain(pem, our_ca.cert);
    });
    h.svc.set_revocation_checker(
        [&h](const std::string& pem) { return h.revoked_pems.count(pem) != 0; });
    h.svc.set_superseded_checker(
        [&h](const std::string& pem) { return h.superseded_pems.count(pem) != 0; });
    hooks = std::make_shared<yuzu::server::AgentIdentityHooks>();
    hooks->leaf_state = [](const std::string&) -> std::expected<yuzu::server::AgentLeafState, std::string> {
        return yuzu::server::AgentLeafState{.has_live = true, .has_revoked_unexpired = false};
    };
    hooks->supersede_older_leaves = [](const std::string&, const std::string&) { return true; };
    h.svc.set_agent_cert_signer([](const std::string&, const std::string& id,
                                   yuzu::server::CertIssuanceSource)
                                    -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair("LEAF-" + id, "CHAIN");
    });
    h.svc.set_agent_identity_hooks(hooks);
    h.svc.set_reregistration_proof_mode(yuzu::server::ReregistrationProofMode::Enforce);
}

void enroll(Harness& h, const std::string& id) {
    REQUIRE(h.auth_mgr.add_pending_agent(id, "h", "linux", "x86_64", "1").value());
    REQUIRE(h.auth_mgr.approve_pending_agent(id, "admin").value() ==
            yuzu::server::auth::PendingTransitionOutcome::changed);
}

} // namespace

TEST_CASE("WP01 direct path over real mTLS: only a real, unrevoked, CN-matching leaf from our CA proves "
          "the agent id",
          "[pg][agent_service][register][wp01][mtls_proof]") {
    const Ca ours = make_ca("Yuzu Install CA");
    const Ca foreign = make_ca("Corporate CA");
    Harness h;
    std::shared_ptr<yuzu::server::AgentIdentityHooks> hooks;
    wire(h, ours, hooks);
    h.start(ours, ours.cert + foreign.cert); // BOTH CAs trusted: the multi-CA bundle scenario
    enroll(h, "agent-real");

    SECTION("a real leaf for this id is admitted") {
        const Leaf leaf = make_leaf(ours, "agent-real");
        auto stub = h.connect(ours, &leaf);
        auto o = register_as(*stub, "agent-real");
        CHECK(o.status.ok());
        CHECK(o.resp.accepted());
    }
    SECTION("a foreign-CA leaf carrying the victim's CN is refused (m9a/recognizer)") {
        const Leaf leaf = make_leaf(foreign, "agent-real");
        auto stub = h.connect(ours, &leaf);
        auto o = register_as(*stub, "agent-real");
        CHECK(o.status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK_FALSE(o.resp.accepted());
        CHECK(h.registry.agent_count() == 0);
    }
    SECTION("a revoked leaf is refused (m9b)") {
        const Leaf leaf = make_leaf(ours, "agent-real");
        h.revoked_pems.insert(leaf.cert);
        auto stub = h.connect(ours, &leaf);
        auto o = register_as(*stub, "agent-real");
        CHECK(o.status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(h.registry.agent_count() == 0);
    }
    SECTION("a leaf for ANOTHER agent id does not prove this one (m9c)") {
        const Leaf leaf = make_leaf(ours, "agent-other");
        auto stub = h.connect(ours, &leaf);
        auto o = register_as(*stub, "agent-real");
        CHECK(o.status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(h.registry.agent_count() == 0);
    }
    SECTION("no certificate and no token: refused, nothing registered (m9a)") {
        auto stub = h.connect(ours, nullptr);
        auto o = register_as(*stub, "agent-real");
        CHECK(o.status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK_FALSE(o.resp.accepted());
        CHECK(h.registry.agent_count() == 0);
    }
    SECTION("no certificate + a fresh single-use token re-enrols through the token path") {
        auto created = h.auth_mgr.create_enrollment_token("recover", 1, std::chrono::hours(1), "test-admin");
        REQUIRE(created.has_value());
        auto stub = h.connect(ours, nullptr);
        auto o = register_as(*stub, "agent-real", created->raw_token);
        CHECK(o.status.ok());
        CHECK(o.resp.accepted());
    }
    SECTION("option 2: a leaf the SERVER superseded + a fresh single-use token re-enrols (the replaced "
            "agent is not wedged)") {
        const Leaf leaf = make_leaf(ours, "agent-real");
        h.revoked_pems.insert(leaf.cert);
        h.superseded_pems.insert(leaf.cert);
        auto created = h.auth_mgr.create_enrollment_token("recover", 1, std::chrono::hours(1), "test-admin");
        REQUIRE(created.has_value());
        auto stub = h.connect(ours, &leaf);
        auto o = register_as(*stub, "agent-real", created->raw_token);
        CHECK(o.status.ok());
        CHECK(o.resp.accepted());
        // The TOKEN path really ran (kills a mutant that lets the revoked presenter count as
        // proof: it would be admitted by the leaf and never consume the token or issue a leaf).
        auto toks = h.auth_mgr.list_enrollment_tokens();
        REQUIRE(toks.has_value());
        REQUIRE(toks->size() == 1);
        CHECK((*toks)[0].use_count == 1);
        CHECK(o.resp.issued_certificate().empty()); // no CSR was sent: nothing issued...
    }
    SECTION("option 2: with a CSR the token path issues a new leaf") {
        const Leaf leaf = make_leaf(ours, "agent-real");
        h.revoked_pems.insert(leaf.cert);
        h.superseded_pems.insert(leaf.cert);
        auto created = h.auth_mgr.create_enrollment_token("recover", 1, std::chrono::hours(1), "test-admin");
        REQUIRE(created.has_value());
        auto stub = h.connect(ours, &leaf);
        apb::RegisterRequest req;
        req.mutable_info()->set_agent_id("agent-real");
        req.mutable_info()->set_hostname("h");
        req.set_enrollment_token(created->raw_token);
        req.set_csr_pem("CSR");
        apb::RegisterResponse resp;
        grpc::ClientContext ctx;
        REQUIRE(stub->Register(&ctx, req, &resp).ok());
        CHECK(resp.accepted());
        CHECK(resp.issued_certificate() == "LEAF-agent-real");
        auto toks = h.auth_mgr.list_enrollment_tokens();
        REQUIRE(toks.has_value());
        CHECK((*toks)[0].use_count == 1);
    }
    SECTION("option 2: a superseded leaf + a BOGUS token is refused (not admitted on the leaf)") {
        const Leaf leaf = make_leaf(ours, "agent-real");
        h.revoked_pems.insert(leaf.cert);
        h.superseded_pems.insert(leaf.cert);
        auto stub = h.connect(ours, &leaf);
        auto o = register_as(*stub, "agent-real", std::string(64, 'f'));
        CHECK(o.status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK_FALSE(o.resp.accepted());
        CHECK(h.registry.agent_count() == 0);
    }
    SECTION("option 2: a superseded leaf WITHOUT a token stays refused") {
        const Leaf leaf = make_leaf(ours, "agent-real");
        h.revoked_pems.insert(leaf.cert);
        h.superseded_pems.insert(leaf.cert);
        auto stub = h.connect(ours, &leaf);
        auto o = register_as(*stub, "agent-real");
        CHECK(o.status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(h.registry.agent_count() == 0);
    }
    SECTION("option 2: an OPERATOR-revoked leaf stays refused even with a single-use token") {
        const Leaf leaf = make_leaf(ours, "agent-real");
        h.revoked_pems.insert(leaf.cert); // revoked, NOT superseded
        auto created = h.auth_mgr.create_enrollment_token("recover", 1, std::chrono::hours(1), "test-admin");
        REQUIRE(created.has_value());
        auto stub = h.connect(ours, &leaf);
        auto o = register_as(*stub, "agent-real", created->raw_token);
        CHECK(o.status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
        CHECK(h.registry.agent_count() == 0);
    }
}
