/**
 * test_grpc_tls_policy.cpp -- TLS 1.2 floor + cipher allow-list over REAL
 * handshakes against the PRODUCTION credential builders (#4722 Part A).
 *
 * WHY: the floor/cipher policy is a process environment variable plus a
 * library default that nothing else in the tree observes. The pin runs
 * during this executable's static initialisation because gRPC's
 * ConfigVars snapshots the environment on first use -- the same ordering
 * main.cpp enforces at its own call site. This executable's pin is its
 * OWN: it does not (and cannot) observe main.cpp's ordering. The
 * production-entrypoint check -- that main.cpp's call site actually runs
 * before gRPC's first use in the real binary -- is the manual smoke
 * recorded in the PR body until roadmap PR 1 wires an automated
 * integration-test.sh assertion.
 */

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "agent.grpc.pb.h"
#include "grpc_tls_credentials.hpp"
#include "x509_ca.hpp"

#include "../test_helpers.hpp"
#include "../tls_probe.hpp"

#include <yuzu/tls_policy.hpp>

namespace apb = ::yuzu::agent::v1;
namespace ca = yuzu::server::pki;
namespace gtls = yuzu::test::tls;

// Static-init pin: this executable's OWN pin, independent of main.cpp's.
// See the file header for why that independence is deliberate and what it
// does NOT prove.
static const bool kEnvPinnedBeforeMain = yuzu::tls::pin_grpc_cipher_env();

namespace {

struct Pki {
    std::string ca_key, ca_cert;
    std::string leaf_key, leaf_cert;
};

/// Copied from test_ota_identity_mtls.cpp:57-88 (the shared shape); `client_auth`
/// picks the EKU, server leaves get SAN localhost + 127.0.0.1.
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

/// A second leaf minted under an EXISTING CA (client_pki shares server_pki's
/// CA; the wrong-CA cases mint their own separate CA via make_pki instead).
Pki issue_sibling_leaf(const Pki& ca_owner, const std::string& leaf_cn, bool client_auth) {
    Pki p;
    p.ca_key = ca_owner.ca_key;
    p.ca_cert = ca_owner.ca_cert;

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

struct PkiPaths {
    std::filesystem::path ca, cert, key;
};

PkiPaths write_pki(const std::filesystem::path& dir, const Pki& pki, const std::string& stem) {
    std::filesystem::create_directories(dir);
    PkiPaths out{dir / (stem + "-ca.pem"), dir / (stem + "-cert.pem"), dir / (stem + "-key.pem")};
    {
        std::ofstream f(out.ca, std::ios::binary | std::ios::trunc);
        f << pki.ca_cert;
    }
    {
        std::ofstream f(out.cert, std::ios::binary | std::ios::trunc);
        f << pki.leaf_cert;
    }
    {
        std::ofstream f(out.key, std::ios::binary | std::ios::trunc);
        f << pki.leaf_key;
    }
#ifndef _WIN32
    std::filesystem::permissions(out.key, std::filesystem::perms::owner_read |
                                              std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
#endif
    return out;
}

/// Whether a failed handshake was genuinely REFUSED BY THE PEER, as opposed
/// to a local probe misconfiguration. Two forms are both genuine peer
/// verdicts, empirically confirmed against this exact OpenSSL 3.6.1 build
/// linked into gRPC (both directions -- inbound server refusal and outbound
/// client refusal): a received TLS alert record, OR the peer closing the
/// TCP connection outright after our ClientHello/Certificate was already on
/// the wire (SSL_R_UNEXPECTED_EOF_WHILE_READING) -- gRPC's TLS stack does
/// not always emit an alert record before closing on a certificate-
/// verification failure or an incompatible legacy protocol version; a
/// silent close is a real, observed refusal, not a hang or a local error.
/// `connect_ok` (checked separately by every caller) is what rules out "the
/// probe never reached the peer at all".
bool refused_by_peer(const gtls::ProbeResult& r) {
    return r.alert_received != -1 || r.err_reason == SSL_R_UNEXPECTED_EOF_WHILE_READING;
}

/// Event-driven wait for a channel to reach TRANSIENT_FAILURE, so a refused
/// handshake is observed within milliseconds instead of burning a
/// WaitForConnected-style deadline.
bool wait_for_transient_failure(const std::shared_ptr<grpc::Channel>& channel,
                                std::chrono::system_clock::time_point deadline) {
    auto st = channel->GetState(/*try_to_connect=*/true);
    while (st != GRPC_CHANNEL_TRANSIENT_FAILURE && std::chrono::system_clock::now() < deadline) {
        if (!channel->WaitForStateChange(st, deadline))
            break;
        st = channel->GetState(false);
    }
    return st == GRPC_CHANNEL_TRANSIENT_FAILURE;
}

/// Real server over the PRODUCTION inbound credential builder, with the
/// generated no-op AgentService as its registered service (a service-free
/// ServerBuilder returns nullptr -- "at least one of the completion queues
/// must be frequently polled" -- every BuildAndStart under tests/unit
/// registers a service; do not replace this with a hand-rolled
/// grpc::Service subclass, which has no sync methods and reintroduces the
/// same failure).
struct PolicyHarness {
    yuzu::test::TempDir dir{"yuzu_test_tlspol-"};
    Pki server_pki = make_pki("Yuzu Test CA", "localhost", /*client_auth=*/false);
    Pki client_pki = issue_sibling_leaf(server_pki, "test-client", /*client_auth=*/true);
    Pki foreign_pki = make_pki("Some Other CA", "intruder", /*client_auth=*/true);

    PkiPaths server_paths = write_pki(dir.path, server_pki, "server");
    PkiPaths client_paths = write_pki(dir.path, client_pki, "client");
    PkiPaths foreign_paths = write_pki(dir.path, foreign_pki, "foreign");

    apb::AgentService::Service noop_svc;
    std::shared_ptr<grpc::ServerCredentials> creds =
        yuzu::server::detail::build_server_tls_credentials(
            server_paths.cert, server_paths.key, server_paths.ca,
            /*insecure_skip_client_verify=*/false, /*require_client_cert=*/true,
            "test agent listener");
    std::unique_ptr<grpc::Server> server;
    int port = 0;

    PolicyHarness() {
        REQUIRE(creds);
        grpc::ServerBuilder b;
        b.AddListeningPort("127.0.0.1:0", creds, &port);
        b.RegisterService(&noop_svc);
        server = b.BuildAndStart();
        REQUIRE(server);
        REQUIRE(port != 0);
    }

    ~PolicyHarness() {
        if (server)
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    }
};

/// Plaintext twin (InsecureServerCredentials) -- the positive control proving
/// the plaintext probe can recognise a REAL plaintext HTTP/2 server.
struct PlaintextHarness {
    apb::AgentService::Service noop_svc;
    std::unique_ptr<grpc::Server> server;
    int port = 0;

    PlaintextHarness() {
        grpc::ServerBuilder b;
        b.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        b.RegisterService(&noop_svc);
        server = b.BuildAndStart();
        REQUIRE(server);
        REQUIRE(port != 0);
    }

    ~PlaintextHarness() {
        if (server)
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    }
};

std::shared_ptr<grpc::Channel> channel_via_production_builder(const std::filesystem::path& ca,
                                                               const std::filesystem::path& cert,
                                                               const std::filesystem::path& key,
                                                               int port) {
    auto creds = yuzu::server::detail::build_mtls_client_credentials(ca, cert, key, "test client");
    if (!creds)
        return nullptr;
    grpc::ChannelArguments args;
    args.SetSslTargetNameOverride("localhost");
    return grpc::CreateCustomChannel("127.0.0.1:" + std::to_string(port), creds, args);
}

} // namespace

// ── Env pin ──────────────────────────────────────────────────────────────────

TEST_CASE("grpc tls policy: env pin is in place before any gRPC use", "[tls][handshake]") {
    REQUIRE(kEnvPinnedBeforeMain);
    const char* v = std::getenv(yuzu::tls::kGrpcCipherSuitesEnvVar.data());
    REQUIRE(v != nullptr);
    CHECK(std::string(v) == yuzu::tls::kTls12CipherList);
}

// ── Positive inbound cases ───────────────────────────────────────────────────

TEST_CASE("grpc tls policy: positive TLS 1.2 via a suite outside gRPC's default",
          "[tls][handshake]") {
    PolicyHarness h;
    gtls::ProbeOptions opt;
    opt.min_version = opt.max_version = TLS1_2_VERSION;
    opt.cipher_list = "ECDHE-ECDSA-CHACHA20-POLY1305";
    opt.client_cert_pem = h.client_pki.leaf_cert;
    opt.client_key_pem = h.client_pki.leaf_key;

    auto r = gtls::raw_tls_probe(h.port, opt);
    REQUIRE(r.ctx_setup_ok);
    REQUIRE(r.connect_ok);
    CHECK(r.handshake_ok);
    CHECK(r.version == "TLSv1.2");
    CHECK(r.cipher == "ECDHE-ECDSA-CHACHA20-POLY1305");
}

TEST_CASE("grpc tls policy: positive TLS 1.3 with the suite asserted", "[tls][handshake]") {
    PolicyHarness h;
    gtls::ProbeOptions opt;
    opt.min_version = opt.max_version = TLS1_3_VERSION;
    opt.client_cert_pem = h.client_pki.leaf_cert;
    opt.client_key_pem = h.client_pki.leaf_key;

    auto r = gtls::raw_tls_probe(h.port, opt);
    REQUIRE(r.ctx_setup_ok);
    REQUIRE(r.connect_ok);
    CHECK(r.handshake_ok);
    CHECK(r.version == "TLSv1.3");
    CHECK((r.cipher == "TLS_AES_256_GCM_SHA384" || r.cipher == "TLS_CHACHA20_POLY1305_SHA256" ||
          r.cipher == "TLS_AES_128_GCM_SHA256"));
}

TEST_CASE("grpc tls policy: full round-trip through the production mTLS client builder",
          "[tls][handshake]") {
    PolicyHarness h;
    auto channel = channel_via_production_builder(h.server_paths.ca, h.client_paths.cert,
                                                  h.client_paths.key, h.port);
    REQUIRE(channel);
    CHECK(channel->WaitForConnected(std::chrono::system_clock::now() + std::chrono::seconds(10)));
}

// ── Negative: legacy protocol versions ───────────────────────────────────────

TEST_CASE("grpc tls policy: negative TLS 1.0 only", "[tls][handshake]") {
    PolicyHarness h;
    gtls::ProbeOptions opt;
    opt.security_level = 0;
    opt.min_version = opt.max_version = TLS1_VERSION;
    opt.cipher_list = "ALL:@SECLEVEL=0";
    opt.client_cert_pem = h.client_pki.leaf_cert;
    opt.client_key_pem = h.client_pki.leaf_key;

    auto r = gtls::raw_tls_probe(h.port, opt);
    REQUIRE(r.ctx_setup_ok);
    REQUIRE(r.connect_ok);
    CHECK_FALSE(r.handshake_ok);
    CHECK_FALSE(r.timed_out);
    CHECK(r.version.empty());
    INFO("alert=" << r.alert_received << " reason=" << r.err_reason << " text=" << r.err_text);
    CHECK(refused_by_peer(r));

    // Positive control: the SAME harness accepts TLS 1.2, isolating the
    // refusal above to the offered protocol version rather than something
    // else about the probe/harness.
    gtls::ProbeOptions control = opt;
    control.security_level = -1;
    control.min_version = control.max_version = TLS1_2_VERSION;
    control.cipher_list.clear();
    auto rc = gtls::raw_tls_probe(h.port, control);
    CHECK(rc.handshake_ok);
    CHECK(rc.version == "TLSv1.2");
}

TEST_CASE("grpc tls policy: negative TLS 1.1 only", "[tls][handshake]") {
    PolicyHarness h;
    gtls::ProbeOptions opt;
    opt.security_level = 0;
    opt.min_version = opt.max_version = TLS1_1_VERSION;
    opt.cipher_list = "ALL:@SECLEVEL=0";
    opt.client_cert_pem = h.client_pki.leaf_cert;
    opt.client_key_pem = h.client_pki.leaf_key;

    auto r = gtls::raw_tls_probe(h.port, opt);
    REQUIRE(r.ctx_setup_ok);
    REQUIRE(r.connect_ok);
    CHECK_FALSE(r.handshake_ok);
    CHECK_FALSE(r.timed_out);
    CHECK(r.version.empty());
    INFO("alert=" << r.alert_received << " reason=" << r.err_reason << " text=" << r.err_text);
    CHECK(refused_by_peer(r));

    // Positive control: same shape as the TLS 1.0 case above.
    gtls::ProbeOptions control = opt;
    control.security_level = -1;
    control.min_version = control.max_version = TLS1_2_VERSION;
    control.cipher_list.clear();
    auto rc = gtls::raw_tls_probe(h.port, control);
    CHECK(rc.handshake_ok);
    CHECK(rc.version == "TLSv1.2");
}

// ── Negative: non-allow-listed cipher ────────────────────────────────────────

TEST_CASE("grpc tls policy: negative non-allow-listed but ECDSA-compatible ciphers",
          "[tls][handshake]") {
    PolicyHarness h;
    gtls::ProbeOptions opt;
    opt.max_version = TLS1_2_VERSION;
    opt.cipher_list = "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA";
    opt.client_cert_pem = h.client_pki.leaf_cert;
    opt.client_key_pem = h.client_pki.leaf_key;

    auto r = gtls::raw_tls_probe(h.port, opt);
    REQUIRE(r.ctx_setup_ok);
    REQUIRE(r.connect_ok);
    CHECK_FALSE(r.handshake_ok);
    INFO("alert=" << r.alert_received << " reason=" << r.err_reason << " text=" << r.err_text);
    CHECK(refused_by_peer(r));

    // Same-shape control: an allow-listed cipher on the SAME ECDSA leaf must
    // succeed, isolating the refusal above to the cipher choice.
    gtls::ProbeOptions control = opt;
    control.cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256";
    auto rc = gtls::raw_tls_probe(h.port, control);
    REQUIRE(rc.ctx_setup_ok);
    REQUIRE(rc.connect_ok);
    CHECK(rc.handshake_ok);
    CHECK(rc.cipher == "ECDHE-ECDSA-AES128-GCM-SHA256");
}

// ── Negative: certless client (REQUIRE semantics) ────────────────────────────

TEST_CASE("grpc tls policy: negative certless client is refused", "[tls][handshake]") {
    PolicyHarness h;
    gtls::ProbeOptions opt;
    opt.max_version = TLS1_2_VERSION;
    // No client_cert_pem/client_key_pem set.

    auto r = gtls::raw_tls_probe(h.port, opt);
    REQUIRE(r.ctx_setup_ok);
    REQUIRE(r.connect_ok);
    CHECK_FALSE(r.handshake_ok);
    INFO("alert=" << r.alert_received << " reason=" << r.err_reason << " text=" << r.err_text);
    CHECK(refused_by_peer(r));

    gtls::ProbeOptions control = opt;
    control.client_cert_pem = h.client_pki.leaf_cert;
    control.client_key_pem = h.client_pki.leaf_key;
    auto rc = gtls::raw_tls_probe(h.port, control);
    REQUIRE(rc.ctx_setup_ok);
    REQUIRE(rc.connect_ok);
    CHECK(rc.handshake_ok);
}

// ── Negative: plaintext client ───────────────────────────────────────────────

TEST_CASE("grpc tls policy: negative plaintext client on the TLS listener",
          "[tls][handshake]") {
    PolicyHarness h;
    auto r = gtls::raw_plaintext_probe(h.port);
    REQUIRE(r.connect_ok);
    REQUIRE(r.wrote_all);
    CHECK_FALSE(r.timed_out);
    CHECK_FALSE(r.saw_h2_settings);
    CHECK((r.saw_tls_alert || r.closed));

    // Positive control: the SAME probe against a real plaintext HTTP/2
    // server must recognise its SETTINGS frame, proving the refusal above
    // is distinguishable from "the probe can't tell either way".
    PlaintextHarness plain;
    auto rp = gtls::raw_plaintext_probe(plain.port);
    CHECK(rp.saw_h2_settings);
}

// ── Negative: wrong-CA client cert ───────────────────────────────────────────

TEST_CASE("grpc tls policy: negative wrong-CA client certificate", "[tls][handshake]") {
    PolicyHarness h;
    // Pinned to TLS 1.2 so the server's verdict arrives inside the
    // handshake, not on first read as TLS 1.3 client-auth would.
    gtls::ProbeOptions opt;
    opt.max_version = TLS1_2_VERSION;
    opt.client_cert_pem = h.foreign_pki.leaf_cert;
    opt.client_key_pem = h.foreign_pki.leaf_key;

    auto r = gtls::raw_tls_probe(h.port, opt);
    REQUIRE(r.ctx_setup_ok);
    REQUIRE(r.connect_ok);
    CHECK_FALSE(r.handshake_ok);
    INFO("alert=" << r.alert_received << " reason=" << r.err_reason << " text=" << r.err_text);
    CHECK(refused_by_peer(r));

    gtls::ProbeOptions control = opt;
    control.client_cert_pem = h.client_pki.leaf_cert;
    control.client_key_pem = h.client_pki.leaf_key;
    auto rc = gtls::raw_tls_probe(h.port, control);
    CHECK(rc.handshake_ok);

    // gRPC twin: the production client credentials with the foreign leaf
    // must land the channel in TRANSIENT_FAILURE.
    auto channel = channel_via_production_builder(h.server_paths.ca, h.foreign_paths.cert,
                                                  h.foreign_paths.key, h.port);
    REQUIRE(channel);
    CHECK(wait_for_transient_failure(channel, std::chrono::system_clock::now() +
                                                  std::chrono::seconds(5)));
}

// ── Negative: wrong-CA gateway impersonator (outbound) ───────────────────────

TEST_CASE("grpc tls policy: negative wrong-CA gateway impersonator (outbound)",
          "[tls][handshake]") {
    PolicyHarness h; // reuse for its trusted CA/client material
    Pki foreign_server = make_pki("Impersonator CA", "localhost", /*client_auth=*/false);

    gtls::RawTlsServer server(foreign_server.leaf_cert, foreign_server.leaf_key, "",
                              /*require_client_cert=*/false, TLS1_2_VERSION);
    REQUIRE(server.port() != 0);
    server.start();

    auto channel = channel_via_production_builder(h.server_paths.ca, h.server_paths.cert,
                                                  h.server_paths.key, server.port());
    REQUIRE(channel);
    CHECK(wait_for_transient_failure(channel, std::chrono::system_clock::now() +
                                                  std::chrono::seconds(5)));
    server.stop();
    CHECK_FALSE(server.observed.handshake_ok);
    INFO("alert=" << server.observed.alert_received << " reason=" << server.observed.err_reason
                  << " text=" << server.observed.err_text);
    CHECK(refused_by_peer(server.observed));

    // Positive control: the real server pki (trusted CA) must complete.
    gtls::RawTlsServer good(h.server_pki.leaf_cert, h.server_pki.leaf_key, "", false,
                            TLS1_2_VERSION);
    REQUIRE(good.port() != 0);
    good.start();
    auto good_channel = channel_via_production_builder(h.server_paths.ca, h.server_paths.cert,
                                                       h.server_paths.key, good.port());
    REQUIRE(good_channel);
    // Never asserted on the channel's final state (raw server speaks no
    // HTTP/2) -- only the raw server's own observation matters here.
    good_channel->GetState(true);
    CHECK(good.wait_for_handshake(std::chrono::seconds(5)));
    good.stop();
    CHECK(good.observed.handshake_ok);
}

// ── Positive/negative: outbound builder forced onto specific policies ───────

TEST_CASE("grpc tls policy: positive outbound builder forced to TLS 1.2 on a pinned-only suite",
          "[tls][handshake]") {
    PolicyHarness h;
    gtls::RawTlsServer server(h.server_pki.leaf_cert, h.server_pki.leaf_key, "", false,
                              TLS1_2_VERSION, "ECDHE-ECDSA-CHACHA20-POLY1305");
    REQUIRE(server.port() != 0);
    REQUIRE(server.cipher_ctx_ok());
    server.start();

    auto channel = channel_via_production_builder(h.server_paths.ca, h.server_paths.cert,
                                                  h.server_paths.key, server.port());
    REQUIRE(channel);
    channel->GetState(true);
    CHECK(server.wait_for_handshake(std::chrono::seconds(5)));
    server.stop();

    CHECK(server.observed.handshake_ok);
    CHECK(server.observed.version == "TLSv1.2");
    CHECK(server.observed.cipher == "ECDHE-ECDSA-CHACHA20-POLY1305");
}

TEST_CASE("grpc tls policy: negative outbound builder against a non-allow-listed-only server",
          "[tls][handshake]") {
    PolicyHarness h;
    gtls::RawTlsServer server(h.server_pki.leaf_cert, h.server_pki.leaf_key, "", false,
                              TLS1_2_VERSION, "ECDHE-ECDSA-AES128-SHA256");
    REQUIRE(server.port() != 0);
    REQUIRE(server.cipher_ctx_ok());
    server.start();

    auto channel = channel_via_production_builder(h.server_paths.ca, h.server_paths.cert,
                                                  h.server_paths.key, server.port());
    REQUIRE(channel);
    CHECK(wait_for_transient_failure(channel, std::chrono::system_clock::now() +
                                                  std::chrono::seconds(5)));
    server.stop();
    CHECK_FALSE(server.observed.handshake_ok);
    CHECK(server.observed.err_reason == SSL_R_NO_SHARED_CIPHER);
}
