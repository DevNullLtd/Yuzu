/**
 * test_content_dist_actions.cpp -- LocalDispatcher round-trip coverage for
 * `content_dist`'s `execute_staged` action, same shape as
 * test_users_posix_actions.cpp: loads the ACTUAL built content_dist plugin
 * (content_dist.dylib/.so, the same artifact the agent daemon loads in
 * production) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher.
 *
 * HONEST COVERAGE SPLIT (read before extending this file):
 *
 *   - THIS FILE covers only the pre-runner dispatch gates that are actually
 *     reachable through LocalDispatcher WITHOUT the plugin having been
 *     init()'d: missing-filename parameter validation, unsafe-filename
 *     rejection, and the file-not-staged check. `do_execute` beyond that
 *     point is gated on a hash re-verification read from agent KV (#808),
 *     and `content_dist_plugin.cpp`'s `PluginContext`/KV plumbing only
 *     becomes live once `init()` sets its module-global `g_ctx` from a REAL
 *     `PluginContextImpl` -- which is anonymous-namespace TU-local in
 *     agent.cpp (dispatch_with_capture, the shim LocalDispatcher::run calls
 *     into, invokes `descriptor->execute` directly and never
 *     `descriptor->init`). There is no legitimate way to drive a staged,
 *     hash-verified `execute_staged` end to end at the unit level, so this
 *     file does not attempt one -- proving these three gates already proves
 *     dispatch plumbing works and that a migrated action still reaches real
 *     validation code, without spawning anything. The same KV-hash-gate
 *     wall also puts the Linux shebang-payload rejection (CDX-002) out of
 *     this file's reach: it runs AFTER the hash re-verification passes, so
 *     it is covered instead by pure fixture tests on `is_shebang_payload`
 *     in test_content_dist_exec_parsers.cpp, not here.
 *   - The RUNNER-FACING mapping (what SubprocessOptions execute_staged runs
 *     with, and how a completed run's SubprocessResult becomes the
 *     status|/exit_code|/output| wire lines) is covered by pure fixture
 *     tests over constructed values in test_content_dist_exec_parsers.cpp --
 *     no plugin load, no process spawn.
 *   - The runner itself (yuzu::agent::run_bounded_subprocess's actual
 *     fork/exec/reap machinery) is covered by the core suite,
 *     test_subprocess_runner.cpp.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"
#include "scoped_env.hpp"
#include "test_helpers.hpp"

#include <openssl/evp.h>

#include <yuzu/agent/scoped_fd.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at
// content_dist's own build output. Empty path (never a hard failure) when
// not found, so a build without agent plugins skips rather than fails.
fs::path find_content_dist_plugin() {
    const std::string lib_name = std::string{"content_dist"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "content_dist" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "content_dist" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "content_dist" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "content_dist" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "content_dist" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_content_dist_plugin() {
    auto plugin_path = find_content_dist_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

} // namespace

TEST_CASE("content_dist plugin: execute_staged rejects a missing filename parameter",
          "[agent][content_dist][posix_actions]") {
    auto plugin = load_content_dist_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // No "filename" param at all -- exercises do_execute's first guard,
    // reachable before the plugin's KV/hash machinery is ever touched.
    auto result = dispatcher.run(plugin->descriptor, "execute_staged");
    CHECK(result.rc != 0);
    CHECK(result.captured.find("error|missing required parameter: filename") !=
          std::string::npos);
}

TEST_CASE("content_dist plugin: execute_staged rejects an unsafe filename",
          "[agent][content_dist][posix_actions]") {
    auto plugin = load_content_dist_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // Path traversal attempt -- is_safe_filename() rejects it before
    // do_execute ever touches the staging directory or agent KV.
    std::vector<YuzuParam> params{{"filename", "../../etc/passwd"}};
    auto result = dispatcher.run(plugin->descriptor, "execute_staged", params);
    CHECK(result.rc != 0);
    CHECK(result.captured.find("error|invalid filename") != std::string::npos);
}

TEST_CASE("content_dist plugin: execute_staged reports file-not-staged for a well-formed "
          "filename that was never staged",
          "[agent][content_dist][posix_actions]") {
    auto plugin = load_content_dist_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // A syntactically valid filename (passes is_safe_filename) that this
    // test never staged first -- proves the fs::exists() gate in
    // `do_execute` runs, and that dispatch reaches it without the plugin
    // ever having been init()'d (LocalDispatcher's dispatch_with_capture
    // shim calls descriptor->execute directly, never descriptor->init --
    // see this file's header comment). A random-ish name avoids colliding
    // with a file another test or a real agent run happened to stage in
    // the same shared staging directory. (The same reasoning excludes the
    // Linux shebang pre-check added for CDX-002 from this file: it sits
    // AFTER the KV hash gate in `do_execute`, so it is unreachable here too
    // -- covered instead by pure fixture tests on `is_shebang_payload` in
    // test_content_dist_exec_parsers.cpp.)
    std::vector<YuzuParam> params{
        {"filename", "test-content-dist-actions-nonexistent-payload.bin"}};
    auto result = dispatcher.run(plugin->descriptor, "execute_staged", params);
    CHECK(result.rc != 0);
    CHECK(result.captured.find("error|file not staged: "
                               "test-content-dist-actions-nonexistent-payload.bin") !=
          std::string::npos);
}

TEST_CASE("content_dist plugin: cleanup bounds a huge hours value instead of wrapping the "
          "cutoff into the future",
          "[agent][content_dist][posix_actions]") {
    auto plugin = load_content_dist_plugin();
    REQUIRE(plugin.has_value());

    // An un-init()'d plugin stages under temp_directory_path()/"yuzu-staged";
    // point TMPDIR at a private dir so the sweep cannot touch a shared one.
    yuzu::test::TempDir tmp{"yuzu_test_cd_cleanup_"};
    const auto staged = tmp.path / "yuzu-staged";
    fs::create_directories(staged);
    yuzu::test::ScopedEnv scoped_tmpdir{"TMPDIR", tmp.path.string()};
    yuzu::agent::LocalDispatcher dispatcher;

    // Positive control: a file two hours old IS removed by hours=1, so a
    // sweep that does not reach `staged` (changed staging convention) fails
    // here instead of leaving the checks below to pass on an empty directory.
    const auto old_file = staged / "old.bin";
    { std::ofstream{old_file} << "x"; }
    fs::last_write_time(old_file, fs::file_time_type::clock::now() - std::chrono::hours(2));
    {
        std::vector<YuzuParam> params{{"hours", "1"}};
        auto result = dispatcher.run(plugin->descriptor, "cleanup", params);
        REQUIRE(result.rc == 0);
        REQUIRE(result.captured.find("removed|1") != std::string::npos);
        REQUIRE_FALSE(fs::exists(old_file));
    }

    // A fresh file must survive a huge value, whatever its magnitude or sign
    // handling in the parser: hours=2000000000 once wrapped the cutoff into
    // the future on libstdc++ and removed everything.
    const auto recent = staged / "recent.bin";
    { std::ofstream{recent} << "x"; }
    for (const char* hours : {"2000000000", "99999999999999999999"}) {
        std::vector<YuzuParam> params{{"hours", hours}};
        auto result = dispatcher.run(plugin->descriptor, "cleanup", params);
        CHECK(result.rc == 0);
        CHECK(result.captured.find("removed|0") != std::string::npos);
        CHECK(fs::exists(recent));
    }
}

namespace {

// Hex SHA-256 of `bytes` (test-local; the plugin's own sha256_file is TU-private).
std::string wp14a_sha256_hex(const std::string& bytes) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    REQUIRE(EVP_Digest(bytes.data(), bytes.size(), md, &md_len, EVP_sha256(), nullptr) == 1);
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < md_len; ++i) {
        out.push_back(hex[md[i] >> 4]);
        out.push_back(hex[md[i] & 0xF]);
    }
    return out;
}

// A loopback HTTP/1.1 server on a raw socket (no httplib, so this TU needs no new dependency).
// Answers each of its first `max_requests` connections with `Content-Encoding: br` and `body`,
// then closes. The accept loop polls so the destructor never depends on shutdown() waking a
// blocked accept() (it does not on macOS).
class BrotliLoopbackServer {
public:
    explicit BrotliLoopbackServer(std::string body, int max_requests = 1)
        : body_(std::move(body)), max_requests_(max_requests) {
        listen_fd_.reset(::socket(AF_INET, SOCK_STREAM, 0));
        REQUIRE(listen_fd_.valid());
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        REQUIRE(::bind(listen_fd_.get(), reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0);
        socklen_t len = sizeof addr;
        REQUIRE(::getsockname(listen_fd_.get(), reinterpret_cast<sockaddr*>(&addr), &len) == 0);
        port_ = ntohs(addr.sin_port);
        REQUIRE(::listen(listen_fd_.get(), 4) == 0);
        thread_ = std::thread([this] { serve(); });
    }
    ~BrotliLoopbackServer() {
        stop_.store(true);
        if (thread_.joinable())
            thread_.join();
    }
    BrotliLoopbackServer(const BrotliLoopbackServer&) = delete;
    BrotliLoopbackServer& operator=(const BrotliLoopbackServer&) = delete;
    [[nodiscard]] int port() const noexcept { return port_; }

private:
    void serve() {
        for (int served = 0; served < max_requests_ && !stop_.load();) {
            pollfd pfd{listen_fd_.get(), POLLIN, 0};
            const int pr = ::poll(&pfd, 1, 100);
            if (pr < 0 && errno == EINTR)
                continue;
            if (pr <= 0)
                continue;
            yuzu::agent::ScopedFd conn{::accept(listen_fd_.get(), nullptr, nullptr)};
            if (!conn.valid())
                continue;
#ifdef SO_NOSIGPIPE
            const int one = 1;
            ::setsockopt(conn.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
            handle(conn.get());
            ++served;
        }
    }

    void handle(int fd) const {
#ifdef MSG_NOSIGNAL
        constexpr int kFlags = MSG_NOSIGNAL;
#else
        constexpr int kFlags = 0;
#endif
        std::string req;
        char buf[1024];
        while (req.find("\r\n\r\n") == std::string::npos) {
            const auto n = ::recv(fd, buf, sizeof buf, 0);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            req.append(buf, static_cast<std::size_t>(n));
        }
        const std::string head = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                                 "Content-Encoding: br\r\nContent-Length: " +
                                 std::to_string(body_.size()) + "\r\nConnection: close\r\n\r\n";
        const std::string resp = head + body_;
        std::size_t off = 0;
        while (off < resp.size()) {
            const auto n = ::send(fd, resp.data() + off, resp.size() - off, kFlags);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            off += static_cast<std::size_t>(n);
        }
    }

    std::string body_;
    int max_requests_;
    yuzu::agent::ScopedFd listen_fd_;
    int port_{0};
    std::atomic<bool> stop_{false};
    std::thread thread_; // last: started in the constructor body, joined first
};

// A VALID Brotli stream (one uncompressed meta-block + the final empty block) for `plain`:
// the decoder accepts it and yields `plain`, while the wire bytes differ from `plain`.
// Hand-built so the test needs no encoder. WBITS=16 (1 bit), ISLAST=0, MNIBBLES=4,
// MLEN-1 (16 bits), ISUNCOMPRESSED=1, pad to a byte; then the bytes; then ISLAST+ISLASTEMPTY.
std::string wp14a_brotli_stored(const std::string& plain) {
    REQUIRE(!plain.empty());
    REQUIRE(plain.size() <= 65536);
    const std::uint32_t hdr = (static_cast<std::uint32_t>(plain.size() - 1) << 4) | (1u << 20);
    std::string out;
    out.push_back(static_cast<char>(hdr & 0xFF));
    out.push_back(static_cast<char>((hdr >> 8) & 0xFF));
    out.push_back(static_cast<char>((hdr >> 16) & 0xFF));
    out += plain;
    out.push_back(static_cast<char>(0x03));
    return out;
}

} // namespace

TEST_CASE("content_dist plugin: stage hashes the RAW bytes on the wire, never a Brotli-decoded "
          "body",
          "[agent][content_dist][posix_actions][wp14a]") {
    auto plugin = load_content_dist_plugin();
    REQUIRE(plugin.has_value());

    const std::string plain = "yuzu-wp14a-plain-payload";
    const std::string wire = wp14a_brotli_stored(plain);
    REQUIRE(wire != plain);
    const std::string wire_hash = wp14a_sha256_hex(wire);
    const std::string plain_hash = wp14a_sha256_hex(plain);
    REQUIRE(wire_hash != plain_hash);

    // Un-init()'d plugin stages under temp_directory_path()/"yuzu-staged": private TMPDIR.
    yuzu::test::TempDir tmp{"yuzu_test_cd_br_"};
    fs::create_directories(tmp.path);
    yuzu::test::ScopedEnv scoped_tmpdir{"TMPDIR", tmp.path.string()};
    yuzu::agent::LocalDispatcher dispatcher;

    BrotliLoopbackServer server{wire, 2};
    const std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/payload.bin";
    // The operator pins the hash of the DECODED content. A client that decoded Brotli would
    // hash `plain` and match; the hash is of bytes written to disk, so it must hash `wire`.
    std::vector<YuzuParam> params{
        {"url", url.c_str()}, {"filename", "wp14a-br.bin"}, {"sha256", plain_hash.c_str()}};
    auto result = dispatcher.run(plugin->descriptor, "stage", params);

    CHECK(result.rc != 0);
    CHECK(result.captured.find("error|hash mismatch: expected=" + plain_hash +
                               ", got=" + wire_hash) != std::string::npos);
    CHECK(result.captured.find("status|ok") == std::string::npos);
    // The mismatched download is removed, never left staged.
    CHECK_FALSE(fs::exists(tmp.path / "yuzu-staged" / "wp14a-br.bin"));

    // Positive control: the hash of the bytes ON THE WIRE passes the hash gate. (The un-init()'d
    // plugin then has no KV store to record the hash in, so the run still ends in an error, but
    // never a hash mismatch.)
    std::vector<YuzuParam> ok_params{
        {"url", url.c_str()}, {"filename", "wp14a-br-ok.bin"}, {"sha256", wire_hash.c_str()}};
    auto ok = dispatcher.run(plugin->descriptor, "stage", ok_params);
    CHECK(ok.captured.find("hash mismatch") == std::string::npos);
}

#endif // !_WIN32
