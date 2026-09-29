/**
 * test_updater_signature.cpp — the OTA signature gate, driven end to end
 * through Updater::check_and_apply over a real gRPC channel.
 *
 * WHY THIS EXISTS AND WHY IT IS NOT A UNIT TEST. A mutation that deletes the
 * signature check from `check_and_apply` outright — `if (false)` around the
 * whole block — left the entire agent suite green, because nothing anywhere
 * drove the download path. Verifying the verifier in isolation proves the
 * primitive works; it does not prove the updater calls it, and that gap is the
 * one that actually ships an unverified binary.
 *
 * So this stands up a test-local AgentService serving a small payload plus a
 * real detached CMS signature over it, and asserts on what check_and_apply
 * DOES. The payload is a few bytes, the server is reached over gRPC's
 * in-process channel (no socket, no port), and no update is ever applied to
 * anything but a temp file.
 *
 * These cases are POSIX-only — see the linkage note above `#ifndef _WIN32`
 * below for why they cannot be correct in this binary on Windows (#3957).
 */

#include <yuzu/agent/updater.hpp>

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <string>

#include "agent.grpc.pb.h"
#include <openssl/evp.h>

#include "cms_test_fixtures.hpp"
#include "test_helpers.hpp"

using yuzu::agent::UpdateConfig;
using yuzu::agent::Updater;
using namespace yuzu::test::cms;

// ── THE gRPC-DRIVEN CASES BELOW DO NOT BUILD/RUN ON WINDOWS (see #3957) ──────
//
// NOT a workaround for a flaky test: these cases cannot be correct on Windows
// as this binary is linked, and they crashed the MSVC debug leg on six
// consecutive runs before that was understood.
//
// yuzu_agent_core is a shared_library (a DLL on Windows), while
// yuzu_server_core -- whose test binary hosts the sibling gRPC harnesses that
// have never crashed -- is a static_library. yuzu_agent_tests links BOTH the
// agent DLL AND agent_test_proto_dep, and vcpkg's Windows triplet links
// grpc/protobuf STATICALLY (triplets/x64-windows.cmake, see CLAUDE.md), so the
// EXE and the DLL each get their OWN protobuf/gRPC runtime and descriptor pool
// in one process. These cases then build a pb::AgentService::Stub with the
// EXE's copy and hand it as void* to Updater::check_and_apply, which lives in
// the DLL and casts it back to ITS OWN Stub class -- a polymorphic object
// across a boundary where each side has its own vtable and statics. It faults
// on first use, which is exactly what every crash report showed: always this
// file, always at or just after the stub/channel is created, at a site that
// wandered with ordering (34 to 694 cases in) because the first cross-boundary
// touch does.
//
// This is a TEST-LINKAGE defect, not a product one: the shipped agent
// executable links only the DLL, never proto, so it has a single runtime.
//
// What is lost here is Windows coverage of "the updater actually CALLS the
// verifier" -- the reason this file exists. Windows keeps the verifier's own
// coverage ([cms]/[signature], no gRPC) and the config predicate below, and
// Linux and macOS keep the end-to-end cases. Restoring Windows needs the
// linkage fixed (one protobuf runtime in this binary), not an edit here.
#ifndef _WIN32
namespace {

namespace pb = ::yuzu::agent::v1;

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

/// Hex SHA-256 of `data`, or "" if OpenSSL fails.
///
/// DELIBERATELY ASSERTION-FREE, and this is load-bearing — it must stay that
/// way. This runs on a gRPC HANDLER THREAD: FakeUpdateService::CheckForUpdate
/// below calls it while the main test thread is running its own assertions.
/// Catch2's REQUIRE/CHECK macros are NOT thread-safe — they mutate the run
/// context's assertion counters and its expression-capture state with no
/// synchronisation — so an assertion evaluated off the main thread corrupts
/// that state and the process dies at whatever unrelated assertion the main
/// thread reaches next.
///
/// Four REQUIREs did live here, reached from the handler on every
/// CheckForUpdate — a sweep of the test tree found this was the only handler
/// anywhere reaching a Catch2 macro. Removing them dropped this file's
/// assertion count by exactly 36 (9 invocations x 4), which is direct proof
/// they were running off the main thread and mutating Catch2's global counter.
///
/// Being honest about what that did NOT explain: this was investigated as the
/// cause of the Windows SIGSEGV and it was not, so do not read the above as
/// the crash's history. That was the linkage problem described at the top of
/// this file. In particular, Catch2's `{Unknown expression after the reported
/// line}` in those crash reports is NOT evidence of corrupted assertion state
/// — it is what its fatal-SIGNAL handler always prints, since it cannot know
/// the expression — and an early diagnosis here leaned on it wrongly.
///
/// The rule stands on its own regardless: Catch2's macros are not thread-safe,
/// so a handler must not reach one. An OpenSSL failure here returns "" rather
/// than asserting. Nothing is silently swallowed: the empty hash cannot match
/// the payload, so the agent refuses the update and the test fails on the MAIN
/// thread with its own assertion.
std::string sha256_hex_of(const std::string& data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    ssl_ptr<EVP_MD_CTX> ctx{EVP_MD_CTX_new()};
    if (!ctx)
        return {};
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        return {};
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
        return {};
    if (EVP_DigestFinal_ex(ctx.get(), md, &len) != 1)
        return {};
    std::string hex;
    static const char* k = "0123456789abcdef";
    for (unsigned i = 0; i < len; ++i) {
        hex += k[md[i] >> 4];
        hex += k[md[i] & 0x0F];
    }
    return hex;
}

/// Serves one fixed payload, with a signature the test chooses.
///
/// NO CATCH2 MACRO MAY BE REACHED FROM THESE HANDLERS, directly or through a
/// helper they call. They execute on gRPC handler threads while the main test
/// thread is asserting, and Catch2's assertion state is not synchronised — see
/// the note on sha256_hex_of above for why. Validate on the
/// main thread instead: return a wrong/empty value from the handler and assert
/// on the observed outcome in the TEST_CASE body.
class FakeUpdateService final : public pb::AgentService::Service {
  public:
    std::string payload;
    std::string signature; // empty = the package is unsigned
    std::string version{"9.9.9"};

    grpc::Status CheckForUpdate(grpc::ServerContext*, const pb::CheckForUpdateRequest*,
                                pb::CheckForUpdateResponse* resp) override {
        resp->set_update_available(true);
        resp->set_latest_version(version);
        resp->set_sha256(sha256_hex_of(payload));
        resp->set_mandatory(false);
        resp->set_eligible(true);
        resp->set_file_size(static_cast<int64_t>(payload.size()));
        if (!signature.empty())
            resp->set_update_signature(signature);
        return grpc::Status::OK;
    }

    grpc::Status DownloadUpdate(grpc::ServerContext*, const pb::DownloadUpdateRequest*,
                                grpc::ServerWriter<pb::DownloadUpdateChunk>* writer) override {
        pb::DownloadUpdateChunk chunk;
        chunk.set_data(payload);
        chunk.set_offset(0);
        chunk.set_total_size(static_cast<int64_t>(payload.size()));
        writer->Write(chunk);
        return grpc::Status::OK;
    }
};

struct Harness {
    FakeUpdateService svc;
    std::unique_ptr<grpc::Server> server;
    std::unique_ptr<pb::AgentService::Stub> stub;

    /// NO LISTENING PORT AND NO TCP CHANNEL — this is deliberate, and it is
    /// what stopped the Windows MSVC debug leg crashing. Do not "restore" a
    /// loopback port here.
    ///
    /// This harness used to bind 127.0.0.1:0 and dial it back with
    /// grpc::CreateChannel. That leg died with SIGSEGV (0xc0000005) on five
    /// consecutive runs, always inside this file, always immediately after the
    /// last assertion this function evaluates — i.e. in the TCP
    /// CreateChannel/NewStub statement itself. (Catch2 attributes a fatal
    /// signal to the last assertion it saw and prints `{Unknown expression
    /// after the reported line}`; that string is its boilerplate for a caught
    /// signal, NOT evidence about the expression, so the statement AFTER the
    /// reported line is the one that faulted.) It reproduced with a server per
    /// TEST_CASE and with one shared server, after anywhere from 34 to 694
    /// cases — the socket path was the invariant, not the lifecycle.
    ///
    /// InProcessChannel keeps the test honest: a real generated stub, a real
    /// registered service, a real RPC through gRPC's own machinery — the whole
    /// point of this file, since verifying the verifier in isolation never
    /// proved the updater calls it. It just does not involve a socket, an
    /// ephemeral port, or the Windows IOCP path, none of which this file is
    /// testing. It also cannot recreate the fd collision a shared server
    /// caused in test_subprocess_runner.cpp, because it opens no descriptors.
    void start() {
        grpc::ServerBuilder b;
        b.RegisterService(&svc);
        server = b.BuildAndStart();
        REQUIRE(server);
        stub = pb::AgentService::NewStub(server->InProcessChannel(grpc::ChannelArguments{}));
        REQUIRE(stub);
    }
    ~Harness() {
        // Teardown order: drop the client channel before the server (no
        // in-flight RPC should be left addressing a server about to go away),
        // then Shutdown()+Wait() (Shutdown only *initiates* shutdown and
        // returns once its deadline passes; Wait() is what actually blocks
        // until handler threads have returned), then destroy the server
        // explicitly while `svc` is still alive — the server holds a raw
        // pointer to the registered service, so the service must outlive it.
        stub.reset();
        if (server) {
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
            server->Wait();
            server.reset();
        }
    }
};

// A HARNESS IS PER-TEST_CASE, AND MUST STAY THAT WAY — do not hoist it into a
// process-lifetime static to save the setup cost. That was tried, and it broke
// `test_subprocess_runner.cpp`'s "does not leak an inherited non-CLOEXEC fd"
// case on Linux: a server and client channel held open for the rest of the run
// leave gRPC's event-engine descriptors live, that test `dup2`s over a
// HARDCODED fd number (21) to plant a non-CLOEXEC fd, and it ends up stealing
// the number from gRPC — which reopens it with FD_CLOEXEC set, failing the
// case's own precondition assert. Building and dropping the server inside each
// TEST_CASE keeps those descriptors out of the rest of the binary's fd space.
//
// What made per-case servers safe on Windows is the gRPC init reference taken
// in start() — see the note there. Two DISTINCT bugs were confounded here and
// each masked the other: the cross-thread Catch2 assertion documented on
// sha256_hex_of (which crashed the runs that shared one server) and the
// library shutdown/re-init cycle (which crashed the runs that did not).

/// A throwaway "installed agent binary" for the updater to replace.
struct FakeExe {
    fs::path dir;
    fs::path path;
    FakeExe() {
        dir = yuzu::test::unique_temp_path("yuzu_test_upd_sig_");
        fs::create_directories(dir);
        path = dir / "yuzu-agent-fake";
        std::ofstream(path, std::ios::binary) << "old-binary";
    }
    ~FakeExe() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

UpdateConfig cfg_with(const fs::path& bundle, bool require,
                      yuzu::MetricsRegistry* m = nullptr) {
    UpdateConfig c;
    c.enabled = true;
    c.signature_trust_bundle = bundle;
    c.require_signature = require;
    c.metrics = m;
    return c;
}

double refused(yuzu::MetricsRegistry& m, const char* reason) {
    return m.counter("yuzu_agent_ota_signature_refused_total", {{"reason", reason}}).value();
}

} // namespace

TEST_CASE("updater: a correctly signed package is applied", "[updater][signing][grpc]") {
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file);
    h.svc.signature = read_file(f.sig_file);
    h.start();

    Updater updater(cfg_with(f.trust_bundle, /*require=*/true), "test-agent", "0.1.0", "linux",
                    "x86_64", exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE(r.has_value());
    CHECK(*r); // applied → the caller restarts
}

TEST_CASE("updater: a package signed by a FOREIGN CA is refused", "[updater][signing][grpc]") {
    // THE MUTATION THIS FILE EXISTS FOR. With the signature check removed from
    // check_and_apply, this package applies happily: its SHA-256 matches, because
    // the server computed the hash over the bytes it served. Only the signature
    // distinguishes it.
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file);
    h.svc.signature = read_file(f.sig_file);
    h.start();

    // Same package, same valid signature — but the agent trusts a different CA.
    yuzu::MetricsRegistry metrics;
    Updater updater(cfg_with(f.other_trust_bundle, /*require=*/false, &metrics), "test-agent",
                    "0.1.0", "linux", "x86_64", exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE_FALSE(r.has_value());
    CHECK(read_file(exe.path) == "old-binary"); // untouched
    // The refusal must be visible to something other than a local log line —
    // with no status RPC on this path, this counter is all an operator gets.
    CHECK(refused(metrics, "untrusted") == 1.0);
}

TEST_CASE("updater: a present-but-invalid signature is refused in BOTH modes",
          "[updater][signing][grpc]") {
    // THE CONTRACT THE DOCS ASSERT ON FIVE SURFACES: --update-require-signature
    // governs only whether an ABSENT signature is tolerated. A signature that is
    // PRESENT and does not verify is refused either way.
    //
    // Every other invalid-signature case here ran with require=false, so nothing
    // would have failed if require=true had bypassed verification entirely — a
    // gap an external reviewer found, not this suite.
    auto f = build_signing_fixtures();

    for (const bool require : {false, true}) {
        FakeExe exe;
        Harness h;
        h.svc.payload = read_file(f.artifact_file);
        h.svc.signature = read_file(f.sig_file);
        h.start();

        yuzu::MetricsRegistry metrics;
        // Signature is valid, but the agent trusts a different CA.
        Updater updater(cfg_with(f.other_trust_bundle, require, &metrics), "test-agent", "0.1.0",
                        "linux", "x86_64", exe.path);
        auto r = updater.check_and_apply(h.stub.get());
        INFO("require_signature=" << require);
        REQUIRE_FALSE(r.has_value());
        CHECK(read_file(exe.path) == "old-binary");
        CHECK(refused(metrics, "untrusted") == 1.0);
    }
}

TEST_CASE("updater: a tampered payload increments the INVALID refusal counter",
          "[updater][signing][grpc]") {
    // The `invalid` label had no assertion anywhere — only `missing` and
    // `untrusted` did — so the reason an operator would see for the commonest
    // real failure (a signature over different bytes) was unverified.
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file) + "-tampered";
    h.svc.signature = read_file(f.sig_file);
    h.start();

    yuzu::MetricsRegistry metrics;
    Updater updater(cfg_with(f.trust_bundle, /*require=*/true, &metrics), "test-agent", "0.1.0",
                    "linux", "x86_64", exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE_FALSE(r.has_value());
    CHECK(refused(metrics, "invalid") == 1.0);
    CHECK(refused(metrics, "untrusted") == 0.0); // classified, not lumped together
}

TEST_CASE("updater: a tampered payload is refused even with a real signature",
          "[updater][signing][grpc]") {
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file) + "-tampered";
    h.svc.signature = read_file(f.sig_file); // signature covers the ORIGINAL bytes
    h.start();

    Updater updater(cfg_with(f.trust_bundle, false), "test-agent", "0.1.0", "linux", "x86_64",
                    exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE_FALSE(r.has_value());
    CHECK(read_file(exe.path) == "old-binary");
}

TEST_CASE("updater: an unsigned package is refused only when require is set",
          "[updater][signing][grpc]") {
    auto f = build_signing_fixtures();

    SECTION("require on → refused") {
        FakeExe exe;
        Harness h;
        h.svc.payload = read_file(f.artifact_file);
        h.svc.signature.clear();
        h.start();
        yuzu::MetricsRegistry metrics;
        Updater updater(cfg_with(f.trust_bundle, /*require=*/true, &metrics), "test-agent", "0.1.0",
                        "linux", "x86_64", exe.path);
        auto r = updater.check_and_apply(h.stub.get());
        REQUIRE_FALSE(r.has_value());
        CHECK(read_file(exe.path) == "old-binary");
        CHECK(refused(metrics, "missing") == 1.0);
    }

    SECTION("require off → applied, transitional mode") {
        FakeExe exe;
        Harness h;
        h.svc.payload = read_file(f.artifact_file);
        h.svc.signature.clear();
        h.start();
        Updater updater(cfg_with(f.trust_bundle, /*require=*/false), "test-agent", "0.1.0", "linux",
                        "x86_64", exe.path);
        auto r = updater.check_and_apply(h.stub.get());
        REQUIRE(r.has_value());
        CHECK(*r);
    }
}

TEST_CASE("updater: with no trust bundle configured, signatures are not checked at all",
          "[updater][signing][grpc]") {
    // The default posture. A package carrying a signature from an unrelated CA
    // still applies, because the operator has not opted in — this pins that
    // "unset bundle" really does mean off, rather than accidentally enforcing.
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file);
    h.svc.signature = read_file(f.sig_file);
    h.start();

    Updater updater(cfg_with(fs::path{}, /*require=*/false), "test-agent", "0.1.0", "linux",
                    "x86_64", exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE(r.has_value());
    CHECK(*r);
}

#endif // !_WIN32 — see the linkage note above (#3957)

// Runs on EVERY platform: it needs no gRPC, so the linkage problem above does
// not reach it.
TEST_CASE("updater config: require without a bundle is a fail-OPEN configuration",
          "[updater][signing]") {
    // The predicate main() refuses to start on. It exists as a predicate because
    // main.cpp is in no test target, so the guard itself was unproven — two
    // external reviewers flagged that independently, and a manual probe is not a
    // regression test.
    UpdateConfig bad;
    bad.require_signature = true;
    bad.signature_trust_bundle.clear();
    CHECK(bad.would_fail_open()); // enforcement set, nothing reads it

    UpdateConfig ok;
    ok.require_signature = true;
    ok.signature_trust_bundle = "/etc/yuzu-agent/certs/update-trust-bundle.pem";
    CHECK_FALSE(ok.would_fail_open());

    UpdateConfig permissive;
    permissive.require_signature = false;
    permissive.signature_trust_bundle.clear();
    CHECK_FALSE(permissive.would_fail_open()); // checking off entirely is legitimate

    UpdateConfig transitional;
    transitional.require_signature = false;
    transitional.signature_trust_bundle = "/etc/yuzu-agent/certs/update-trust-bundle.pem";
    CHECK_FALSE(transitional.would_fail_open());
}
