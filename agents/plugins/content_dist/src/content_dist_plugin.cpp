/**
 * content_dist_plugin.cpp — Content staging plugin for Yuzu
 *
 * Actions:
 *   "stage"          — Download a file to staging dir with hash verification.
 *   "execute_staged" — Execute a previously staged file.
 *   "list_staged"    — List files in the staging directory.
 *   "cleanup"        — Remove staged files older than N hours.
 *   "upload_file"    — Upload a local file to the Yuzu server via the
 *                       one-time upload-grant + authenticated chunked
 *                       receive protocol (PR1.6, CC-06).
 *
 * Security: uses cpp-httplib for downloads/uploads (no shell invocation).
 *           execute_staged runs the staged file via
 *           yuzu::agent::run_bounded_subprocess (no shell interpretation).
 *           Args validated to block shell metacharacters.
 */

#include <yuzu/plugin.hpp>

#include "content_dist_exec_parsers.hpp"
#include "content_dist_exec_seam.hpp"
#include "content_dist_upload_parsers.hpp"

#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure (ABI4 result-status seam, ADR-3002)
#include <yuzu/agent/subprocess_runner.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <win_str.hpp> // yuzu::win::from_wide (agents/shared, #1681)
#else
#include <openssl/evp.h>
#endif

#include <httplib.h>

namespace fs = std::filesystem;
namespace up = yuzu::content_dist::upload;

namespace {

YuzuPluginContext* g_ctx = nullptr;

fs::path staging_dir() {
    yuzu::PluginContext pctx{g_ctx};
    auto data_dir = pctx.get_config("agent.data_dir");
    fs::path dir = data_dir.empty() ? fs::temp_directory_path() / "yuzu-staged"
                                    : fs::path{std::string{data_dir}} / "staged";
    std::error_code ec;
    fs::create_directories(dir, ec);
#ifndef _WIN32
    // Restrict staging directory permissions to owner only
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
#endif
    return dir;
}

// Incremental SHA-256: `update()` any number of times over buffers fed to it
// in order, `finalize()` once at the end. Extracted out of what used to be a
// single whole-stream `sha256_stream()` so `do_upload` (below) can feed it
// the EXACT buffer just transmitted, immediately once the server has
// acknowledged it — binding the committed digest to bytes actually sent
// over the wire rather than a second, independent re-read of the file after
// the fact (#P7-003: a second read pass cannot see a write that lands, via
// another handle, in the gap between "chunk sent" and "file re-read").
#ifdef _WIN32
class IncrementalSha256 {
public:
    IncrementalSha256() { init(); }
    ~IncrementalSha256() { destroy(); }
    IncrementalSha256(const IncrementalSha256&) = delete;
    IncrementalSha256& operator=(const IncrementalSha256&) = delete;

    /// Restart the digest so it covers nothing. An incremental hash cannot be
    /// REWOUND, so this is how `do_upload` repairs its digest when a server
    /// resync moves the acknowledged offset (see `rehash_prefix` there).
    void reset() {
        destroy();
        init();
    }

    /// False once ANY crypto call has failed. Every subsequent operation
    /// no-ops and `finalize()` yields nullopt, so a provider/allocation
    /// failure surfaces as a controlled upload error instead of hashing
    /// through invalid handles (governance: fail closed, never a silent
    /// wrong digest).
    [[nodiscard]] bool ok() const noexcept { return valid_; }

    void update(const char* data, std::size_t len) {
        if (!valid_)
            return;
        if (!BCRYPT_SUCCESS(BCryptHashData(hash_, reinterpret_cast<PUCHAR>(const_cast<char*>(data)),
                                           static_cast<ULONG>(len), 0)))
            valid_ = false;
    }

    [[nodiscard]] std::optional<std::string> finalize() {
        if (!valid_)
            return std::nullopt;
        std::vector<UCHAR> digest(hash_len_);
        if (!BCRYPT_SUCCESS(BCryptFinishHash(hash_, digest.data(), hash_len_, 0))) {
            valid_ = false;
            return std::nullopt;
        }
        std::string hex;
        for (auto b : digest)
            hex += std::format("{:02x}", b);
        return hex;
    }

private:
    void init() {
        valid_ = true;
        if (!BCRYPT_SUCCESS(
                BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
            valid_ = false;
            return;
        }
        DWORD result_len = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg_, BCRYPT_HASH_LENGTH,
                                              reinterpret_cast<PUCHAR>(&hash_len_),
                                              sizeof(hash_len_), &result_len, 0))) {
            valid_ = false;
            return;
        }
        if (!BCRYPT_SUCCESS(BCryptCreateHash(alg_, &hash_, nullptr, 0, nullptr, 0, 0)))
            valid_ = false;
    }
    void destroy() {
        if (hash_) {
            BCryptDestroyHash(hash_);
            hash_ = nullptr;
        }
        if (alg_) {
            BCryptCloseAlgorithmProvider(alg_, 0);
            alg_ = nullptr;
        }
    }

    BCRYPT_ALG_HANDLE alg_{nullptr};
    BCRYPT_HASH_HANDLE hash_{nullptr};
    DWORD hash_len_{0};
    bool valid_{false};
};
#else
class IncrementalSha256 {
public:
    IncrementalSha256() { init(); }
    ~IncrementalSha256() { destroy(); }
    IncrementalSha256(const IncrementalSha256&) = delete;
    IncrementalSha256& operator=(const IncrementalSha256&) = delete;

    /// Restart the digest so it covers nothing. An incremental hash cannot be
    /// REWOUND, so this is how `do_upload` repairs its digest when a server
    /// resync moves the acknowledged offset (see `rehash_prefix` there).
    void reset() {
        destroy();
        init();
    }

    /// False once ANY crypto call has failed. Every subsequent operation
    /// no-ops and `finalize()` yields nullopt, so an allocation/init failure
    /// surfaces as a controlled upload error instead of hashing through a
    /// null context (governance: fail closed, never a silent wrong digest).
    [[nodiscard]] bool ok() const noexcept { return valid_; }

    void update(const char* data, std::size_t len) {
        if (!valid_)
            return;
        if (EVP_DigestUpdate(ctx_, data, len) != 1)
            valid_ = false;
    }

    [[nodiscard]] std::optional<std::string> finalize() {
        if (!valid_)
            return std::nullopt;
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        if (EVP_DigestFinal_ex(ctx_, digest, &len) != 1) {
            valid_ = false;
            return std::nullopt;
        }
        std::string hex;
        for (unsigned i = 0; i < len; ++i)
            hex += std::format("{:02x}", digest[i]);
        return hex;
    }

private:
    void init() {
        ctx_ = EVP_MD_CTX_new();
        valid_ = ctx_ != nullptr && EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) == 1;
    }
    void destroy() {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

    EVP_MD_CTX* ctx_{nullptr};
    bool valid_{false};
};
#endif

// SHA-256 over an already-open, positioned ifstream, reading from its
// CURRENT position to EOF — never opens or closes the handle itself.
std::string sha256_stream(std::ifstream& file) {
    IncrementalSha256 hasher;
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0)
        hasher.update(buf, static_cast<std::size_t>(file.gcount()));
    // Matches sha256_file's existing fail-empty convention below — a crypto
    // provider failure here reads the same as an unopenable file.
    return hasher.finalize().value_or(std::string{});
}

std::string sha256_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};
    return sha256_stream(file);
}

bool is_safe_filename(std::string_view name) {
    if (name.empty() || name.find("..") != std::string_view::npos)
        return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_')
            return false;
    }
    return true;
}

// ── URL parsing (same as http_client) ───────────────────────────────────────

struct ParsedUrl {
    bool is_https = false;
    std::string host;
    int port = 0;
    std::string path;
};

bool parse_url(std::string_view url, ParsedUrl& out) {
    if (url.starts_with("https://")) {
        out.is_https = true;
        url.remove_prefix(8);
    } else if (url.starts_with("http://")) {
        out.is_https = false;
        url.remove_prefix(7);
    } else {
        return false;
    }

    auto slash_pos = url.find('/');
    std::string_view authority;
    if (slash_pos != std::string_view::npos) {
        authority = url.substr(0, slash_pos);
        out.path = std::string(url.substr(slash_pos));
    } else {
        authority = url;
        out.path = "/";
    }

    auto colon_pos = authority.rfind(':');
    auto bracket_pos = authority.find(']');
    if (colon_pos != std::string_view::npos &&
        (bracket_pos == std::string_view::npos || colon_pos > bracket_pos)) {
        out.host = std::string(authority.substr(0, colon_pos));
        auto port_str = authority.substr(colon_pos + 1);
        try {
            out.port = std::stoi(std::string(port_str));
        } catch (...) {
            out.port = 0;
        }
    } else {
        out.host = std::string(authority);
        out.port = 0;
    }

    if (out.port == 0) {
        out.port = out.is_https ? 443 : 80;
    }

    return !out.host.empty();
}

// Download via httplib — no shell invocation
int download_file(std::string_view url, const fs::path& dest, std::string& error) {
    ParsedUrl parsed;
    if (!parse_url(url, parsed)) {
        error = "invalid URL";
        return 1;
    }

    std::ofstream ofs(dest, std::ios::binary);
    if (!ofs) {
        error = "failed to open destination file";
        return 1;
    }

    auto content_receiver = [&](const char* data, size_t len) {
        ofs.write(data, static_cast<std::streamsize>(len));
        return true;
    };

    httplib::Result res;
    if (parsed.is_https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient cli(parsed.host, parsed.port);
        cli.set_connection_timeout(30);
        cli.set_read_timeout(300);
        cli.enable_server_certificate_verification(true);
        res = cli.Get(parsed.path, content_receiver);
#else
        ofs.close();
        error = "HTTPS not supported (OpenSSL not available)";
        return 1;
#endif
    } else {
        httplib::Client cli(parsed.host, parsed.port);
        cli.set_connection_timeout(30);
        cli.set_read_timeout(300);
        res = cli.Get(parsed.path, content_receiver);
    }

    ofs.close();
    if (!res || res->status < 200 || res->status >= 400) {
        error = "download failed: HTTP " + (res ? std::to_string(res->status) : "connection error");
        return 1;
    }

    return 0;
}

// BR-006 (whole-branch review round 2): is_safe_arg/split_args moved to
// content_dist_exec_parsers.hpp (yuzu::content_dist::exec) -- pure, no-I/O
// string functions belong in the *_parsers.hpp pure decision layer, not
// this TU's anonymous namespace, and moving them there is what let
// content_dist_exec_seam.hpp's execute_verified_payload() (see do_execute
// below) call them without duplicating a second copy.

// ── Safe process execution (no shell) ───────────────────────────────────────
//
// The plugin's former OS-specific direct-argv spawn helpers (a Windows
// child-process launcher and a POSIX child-process launcher, each with its
// own pipe/capture/reap plumbing) are replaced by one cross-platform call to
// yuzu::agent::run_bounded_subprocess (agents/core/src/subprocess_runner.cpp)
// in `do_execute` below — the runner already provides no-shell argv exec, a
// bounded output capture, a deadline, and (on Linux) B6 TOCTOU-safe exec; it
// also takes the process-wide child-launch serialization lock internally, so
// this plugin no longer links against that lock at all. `build_execution_options`/
// `map_execution_result` (content_dist_exec_parsers.hpp) are the pure
// decision layer around that call.

// ── ABI4 per-OS capability declaration (#2204) ──────────────────────────────
//
// `rung` is the ADR-3002 ACQUISITION rung (docs/adr/3002-acquisition-ladder.md:66-73):
// 1 = native OS interface (zero subprocesses), 2 = argv via a runner (no
// shell), 3 = shell/interpreter payload. One row per `actions()` entry,
// same order, same names — capmatrix-gen hard-errors on any mismatch.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "stage",
        // httplib download over a socket this plugin opens itself — zero
        // subprocesses, rung 1 on every OS. HTTPS is a build-time REQUIRED
        // OpenSSL dependency on Linux/macOS (content_dist/meson.build:
        // `dependency('openssl', required: true, ...)`) but only
        // best-effort on Windows (`required: false`) — CPPHTTPLIB_OPENSSL_SUPPORT
        // is conditionally undefined there (see `download_file`'s #else
        // branch above), so Windows is CONSTRAINED, not SUPPORTED.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "httplib_tls", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "httplib_tls", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "httplib_tls",
         "requires OpenSSL to be found at build time; HTTPS unavailable if absent"},
    },
    {
        /* .action      = */ "execute_staged",
        // Spawns the staged binary directly from a pre-split argv via
        // yuzu::agent::run_bounded_subprocess — never a shell (see
        // `do_execute`/content_dist_exec_seam.hpp): rung 2 on every OS,
        // same token convention as filesystem_plugin.cpp's runner-based legs.
        //
        // BR-004 (whole-branch review round 2): Linux is CONSTRAINED, not
        // unconditionally SUPPORTED -- the CDX-002 gate in
        // content_dist_exec_seam.hpp's execute_verified_payload() rejects
        // every shebang-interpreted staged payload on Linux (B6 exec_verify's
        // fd-exec primitive, execveat with O_CLOEXEC, is structurally
        // incompatible with the kernel's binfmt_script re-open), which the
        // deleted pre-migration POSIX launcher (a plain execvp()) never did.
        // Declaring this leg unconditionally SUPPORTED was truthful about
        // the migration's happy path but silently omitted a real, migration-
        // introduced compatibility break for any staged `#!`-interpreted
        // script; the constraint string exists so this ABI4 descriptor
        // itself carries that disclosure, not just a code comment.
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "subprocess_runner:staged_payload",
         "shebang-interpreted (#!) staged payloads are rejected -- B6 fd-exec "
         "(execveat O_CLOEXEC) is incompatible with the kernel's binfmt_script "
         "re-open; native executables only"},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "subprocess_runner:staged_payload", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "subprocess_runner:staged_payload", nullptr},
    },
    {
        /* .action      = */ "list_staged",
        // std::filesystem directory iteration — in-process, rung 1.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
    },
    {
        /* .action      = */ "cleanup",
        // std::filesystem removal — in-process, rung 1.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
    },
    {
        /* .action      = */ "upload_file",
        // Same httplib-socket transport as `stage`, same Windows OpenSSL
        // caveat.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "httplib_tls", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "httplib_tls", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "httplib_tls",
         "requires OpenSSL to be found at build time; HTTPS unavailable if absent"},
    },
};

} // namespace

class ContentDistPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "content_dist"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Content staging — download, verify, execute, and manage staged files (no "
               "shell-out)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"stage",   "execute_staged", "list_staged",
                                     "cleanup", "upload_file",    nullptr};
        return acts;
    }

    [[nodiscard]] const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    [[nodiscard]] size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();
        return {};
    }
    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "stage")
            return do_stage(ctx, params);
        if (action == "execute_staged")
            return do_execute(ctx, params);
        if (action == "list_staged")
            return do_list(ctx);
        if (action == "cleanup")
            return do_cleanup(ctx, params);
        if (action == "upload_file")
            return do_upload(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    int do_stage(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto url = params.get("url");
        auto filename = params.get("filename");
        auto expected = params.get("sha256");
        if (url.empty() || filename.empty() || expected.empty()) {
            ctx.write_output("error|missing required parameters: url, filename, sha256");
            return 1;
        }
        if (!is_safe_filename(filename)) {
            ctx.write_output(
                "error|invalid filename (alphanumeric, dots, hyphens, underscores only)");
            return 1;
        }

        auto dest = staging_dir() / std::string{filename};
        std::string error;
        if (download_file(url, dest, error) != 0) {
            ctx.write_output(std::format("error|{}", error));
            return 1;
        }

        auto hash = sha256_file(dest);
        if (hash != expected) {
            std::error_code ec;
            fs::remove(dest, ec);
            ctx.write_output(
                std::format("error|hash mismatch: expected={}, got={}", expected, hash));
            return 1;
        }

        // #808: persist the verified hash in agent KV so `do_execute` has an
        // authoritative source of truth for re-verification. KV lives in a
        // separate SQLite DB outside the staging directory, so an attacker
        // who can swap a staged file (the TOCTOU window) cannot also rewrite
        // its expected hash. Key namespace `staged_hash:<filename>`.
        yuzu::PluginContext pctx{g_ctx};
        if (!pctx.storage_set(std::string{"staged_hash:"} + std::string{filename}, hash)) {
            std::error_code ec;
            fs::remove(dest, ec);
            ctx.write_output("error|failed to persist staged hash to agent KV");
            return 1;
        }

        ctx.write_output("status|ok");
        ctx.write_output(std::format("staged_path|{}", dest.string()));
        return 0;
    }

    int do_execute(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto filename = params.get("filename");
        if (filename.empty()) {
            ctx.write_output("error|missing required parameter: filename");
            return 1;
        }
        if (!is_safe_filename(filename)) {
            ctx.write_output("error|invalid filename");
            return 1;
        }

        auto path = staging_dir() / std::string{filename};
        if (!fs::exists(path)) {
            ctx.write_output(std::format("error|file not staged: {}", filename));
            return 1;
        }

        // #808: hash re-verification is MANDATORY and the expected hash MUST
        // come from agent KV (persisted by `do_stage` at the moment of
        // download verification). The previous design read `expected_hash`
        // from caller-provided params and skipped verification entirely when
        // the param was absent — a local attacker who could write to the
        // staging directory between stage and execute would then run
        // arbitrary code. By sourcing the hash from KV (a separate SQLite
        // DB outside the staging tree) we eliminate both the skip path and
        // the trust-the-caller-hash oracle.
        yuzu::PluginContext pctx{g_ctx};
        auto kv_key = std::string{"staged_hash:"} + std::string{filename};
        auto trusted_hash = pctx.storage_get(kv_key);
        if (trusted_hash.empty()) {
            // No KV entry — either the file was placed in the staging dir by
            // something other than `do_stage`, or KV was wiped. Either way
            // we have no source of truth, so we refuse.
            ctx.write_output(std::format("error|no trusted hash on record for staged file '{}'; "
                                         "stage the file via the `stage` action first",
                                         filename));
            return 1;
        }
        auto actual = sha256_file(path);
        if (actual != trusted_hash) {
            ctx.write_output(
                std::format("error|hash re-verification failed (file tampered post-stage?): "
                            "expected={}, got={}",
                            trusted_hash, actual));
            return 1;
        }
        // Optional caller-provided `expected_hash` is still honoured if
        // present — but only to detect orchestration drift (caller's idea of
        // the hash diverged from what we staged). Failure here is NOT a
        // security event, just a config mismatch.
        auto caller_hash = params.get("expected_hash");
        if (!caller_hash.empty() && std::string{caller_hash} != trusted_hash) {
            ctx.write_output(
                std::format("error|caller-provided expected_hash does not match the hash "
                            "recorded at stage time: caller={}, staged={}",
                            caller_hash, trusted_hash));
            return 1;
        }

#ifdef __linux__
        constexpr bool kIsLinux = true;
#else
        constexpr bool kIsLinux = false;
#endif
#ifdef _WIN32
        constexpr bool kIsWindows = true;
#else
        constexpr bool kIsWindows = false;
#endif

        // BR-006 (whole-branch review round 2): everything past this point
        // -- the CDX-002 Linux shebang gate, the args safety check, the
        // POSIX chmod, argv assembly, and the actual
        // build_execution_options/run_bounded_subprocess/map_execution_result
        // call sequence -- is content_dist_exec_seam.hpp's
        // execute_verified_payload(), extracted so it is directly unit-
        // testable against a real staged file without content_dist's KV/
        // init machinery (g_ctx) ever entering the picture. `path` here is
        // already hash-verified by the #808 KV re-verification above,
        // exactly as execute_verified_payload's own contract requires.
        //
        // CDX-001 RESIDUAL RISK (accepted, documented -- not fixed here,
        // and not moved into the seam header since it is about THIS
        // hash-verification step, not the seam's own logic): the trusted
        // SHA-256 above (#808 KV re-verification) is computed against
        // `path`, and the seam's B6 exec_verify independently OPENS that
        // same path and fd-execs it. The fd-exec closes only the
        // fstat-to-exec race (TOCTOU between the runner's own permission
        // check and the exec syscall); nothing binds the digest just
        // checked to the exact fd the runner ends up executing, so a
        // hash-time-to-open-time swap window remains AT THE PRIMITIVE
        // LEVEL. This is ACCEPTED, not closed, because: staging_dir()
        // enforces an agent-owned 0700 directory on POSIX, so any actor
        // able to swap the staged file in that window already holds
        // agent-uid or root -- capabilities that already subsume whatever
        // the swap would gain them; and exec_verify.expected_size (set
        // inside the seam) further pins the exec'd fd to the hash-verified
        // file's exact size, narrowing a same-size-swap window rather than
        // leaving it fully open. Full closure requires the runner itself to
        // accept a caller-supplied digest and verify it against its own
        // already-opened fd before execveat -- a frozen-contract change to
        // subprocess_runner's B6 exec_verify, deferred to a follow-up
        // runner package (reference: CDX-001). Do not attempt a plugin-
        // local open/fstat/execveat workaround here to close this gap --
        // that would duplicate (and diverge from) the runner's own B6
        // logic; the fix belongs in the runner, not this caller.
        auto outcome = yuzu::content_dist::exec::execute_verified_payload(
            path, params.get("args"), kIsLinux, kIsWindows);
        // BR-001: forward a runner-level failure through the ABI4 CC-07
        // result-status seam BEFORE the wire lines below -- same one-line
        // pattern every other migrated mutating plugin uses (services_
        // plugin.cpp, network_actions_plugin.cpp, interaction_plugin.cpp),
        // and required end-to-end by ADR-3002's "Honest termination
        // reporting" precondition for a mutating site. Only set on the
        // ordinary run_bounded_subprocess path -- an early shebang/args
        // rejection never reaches the runner, so there is nothing to
        // forward.
        if (outcome.run)
            yuzu::agent::forward_runner_failure(ctx, *outcome.run);
        for (const auto& line : outcome.lines)
            ctx.write_output(line);
        return outcome.rc;
    }

    int do_list(yuzu::CommandContext& ctx) {
        auto dir = staging_dir();
        std::error_code ec;
        int count = 0;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (!entry.is_regular_file())
                continue;
            auto size = entry.file_size(ec);
            auto hash = sha256_file(entry.path());
            ctx.write_output(
                std::format("file|{}|{}|{}", entry.path().filename().string(), size, hash));
            ++count;
        }
        ctx.write_output(std::format("count|{}", count));
        return 0;
    }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    // Sends the grant/session credential's DELETE (cancel) so a
    // server-side partial blob is discarded, then surfaces `error_msg`.
    // Never itself an error — a cancel failure is not this command's
    // failure to report, the upload's own failure already is. Only
    // declared when SSLClient exists at all (see `do_upload`'s matching
    // build guard below) — TLS is mandatory for this transport, so there
    // is no non-SSL variant to guard against.
    void abort_upload(httplib::SSLClient& client, const std::string& cancel_path,
                      const std::string& session_header, yuzu::CommandContext& ctx,
                      const std::string& error_msg) {
        httplib::Headers cancel_headers = {{"X-Yuzu-Upload-Session", session_header}};
        client.Delete(cancel_path, cancel_headers);
        ctx.write_output(std::format("error|{}", error_msg));
    }
#endif

    // ", reason=<name>" when present, empty otherwise — pulled out of the
    // several error-message call sites below so none of them has to juggle
    // a mixed string_view/const-char* ternary.
    static std::string describe_reason(std::optional<up::Reason> reason) {
        if (!reason)
            return {};
        return std::string{", reason="} + std::string{up::reason_string(*reason)};
    }

    int do_upload(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path_str = params.get("path");
        auto grant_id = params.get("grant_id");
        auto grant_secret = params.get("grant_secret");
        if (path_str.empty() || grant_id.empty() || grant_secret.empty()) {
            ctx.write_output(
                "error|missing required parameters: path, grant_id, grant_secret");
            return 1;
        }
        // #3136 minor: local grammar precheck. The server already fails
        // closed (grant_unknown) on a malformed credential, so this only
        // improves the error the caller sees before a doomed round-trip.
        if (!up::is_valid_credential_parts(grant_id, grant_secret)) {
            ctx.write_output("error|grant_id/grant_secret do not match the expected credential "
                             "shape (32/64 lowercase hex)");
            return 1;
        }

        fs::path file_path{std::string{path_str}};
        std::error_code ec;
        if (!fs::exists(file_path, ec) || !fs::is_regular_file(file_path, ec)) {
            ctx.write_output("error|file does not exist or is not a regular file");
            return 1;
        }

        // Canonicalize path to resolve symlinks and prevent traversal
        auto canon = fs::canonical(file_path, ec);
        if (ec) {
            ctx.write_output("error|failed to resolve path");
            return 1;
        }
        file_path = canon;

        // Enforce base_dir restriction if provided
        auto base_dir = params.get("base_dir");
        if (!base_dir.empty()) {
            auto canon_base = fs::canonical(fs::path{std::string{base_dir}}, ec);
            if (ec) {
                ctx.write_output("error|invalid base_dir");
                return 1;
            }
            auto file_str = file_path.string();
            auto base_str = canon_base.string();
            // #3136 minor: a base_dir that IS the filesystem root (e.g. "/")
            // canonicalizes to a string already ending in a separator, so
            // requiring file_str[base_str.size()] to ALSO be a separator
            // rejected every child path — index base_str.size() lands one
            // character past the separator base_str already carries. Strip
            // one trailing separator first so the boundary check below is
            // uniform regardless of whether the base itself ends in one.
            if (!base_str.empty() && (base_str.back() == '/' || base_str.back() == '\\'))
                base_str.pop_back();
            if (file_str.size() < base_str.size() ||
                file_str.compare(0, base_str.size(), base_str) != 0 ||
                (file_str.size() > base_str.size() && file_str[base_str.size()] != '/' &&
                 file_str[base_str.size()] != '\\')) {
                ctx.write_output("error|path is outside allowed base directory");
                return 1;
            }
        }

        std::error_code size_ec;
        const auto file_size = static_cast<std::int64_t>(fs::file_size(file_path, size_ec));
        if (size_ec || file_size <= 0) {
            ctx.write_output("error|failed to determine file size, or file is empty");
            return 1;
        }

        int max_mb = 100;
        auto max_str = params.get("max_size_mb", "100");
        try {
            max_mb = std::stoi(std::string{max_str});
        } catch (...) {}
        // #3136 minor: clamp to the [1,1000] range t2_capabilities.yaml
        // declares for this parameter. The server's own declared-size
        // enforcement is authoritative regardless, but a caller bypassing
        // YAML validation should still get a locally-consistent precheck
        // rather than an unbounded or non-positive local cap.
        max_mb = std::clamp(max_mb, 1, 1000);
        if (static_cast<std::uintmax_t>(file_size) > static_cast<std::uintmax_t>(max_mb) * 1024 * 1024) {
            ctx.write_output(
                std::format("error|file too large ({} bytes, max {} MB)", file_size, max_mb));
            return 1;
        }

        // The base URL comes ONLY from the agent's own configured server
        // transport (agent.server_web_url) — this action no longer accepts
        // an operator-supplied URL parameter at all (CC-06), and no request
        // below ever carries a self-declared agent id: identity is entirely
        // a server-side fact tied to the grant. TLS is mandatory —
        // an explicit http:// value is a hard configuration error, never
        // silently used or upgraded; a bare host (no scheme) defaults to
        // https, matching this plugin's pre-existing bare-host convention.
        yuzu::PluginContext pctx{g_ctx};
        auto configured = pctx.get_config("agent.server_web_url");
        if (configured.empty()) {
            ctx.write_output(
                "error|agent.server_web_url is not configured; cannot reach the upload endpoint");
            return 1;
        }
        if (configured.starts_with("http://")) {
            ctx.write_output("error|agent.server_web_url must not be http://; TLS is mandatory");
            return 1;
        }
        std::string url_to_parse = configured.starts_with("https://")
                                       ? std::string{configured}
                                       : ("https://" + std::string{configured});
        ParsedUrl base;
        if (!parse_url(url_to_parse, base) || !base.is_https) {
            ctx.write_output("error|agent.server_web_url is not a valid host or URL");
            return 1;
        }

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
        ctx.write_output("error|HTTPS not supported in this build (OpenSSL not available)");
        return 1;
#else
        httplib::SSLClient client(base.host, base.port);
        client.set_connection_timeout(30);
        client.set_read_timeout(300);
        client.enable_server_certificate_verification(true);

        // The destination is opened EXACTLY ONCE for this upload. Every
        // chunk below reads its bytes via `seekg` on THIS SAME ifstream
        // handle, and the commit hash is accumulated incrementally from the
        // SAME buffer each chunk transmits, the moment the server
        // acknowledges it — never by reopening the file or independently
        // re-reading it through a second pass — so the committed digest
        // can never describe different bytes than were actually streamed
        // to the server (#P7-003).
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            ctx.write_output("error|failed to open file");
            return 1;
        }

        // ── Session open ─────────────────────────────────────────────
        const std::string grant_header = std::string{grant_id} + "." + std::string{grant_secret};
        httplib::Headers open_headers = {{"X-Yuzu-Upload-Grant", grant_header}};

        std::optional<up::SessionOpenResponse> session;
        for (int attempt = 1;; ++attempt) {
            auto open_res = client.Post("/api/v1/uploads", open_headers);
            const int status = open_res ? open_res->status : 0;
            if (open_res && status == 201) {
                session = up::parse_session_open_response(open_res->body);
                if (!session) {
                    ctx.write_output("error|malformed session-open response from server");
                    return 1;
                }
                break;
            }
            std::optional<up::Reason> reason;
            if (open_res)
                reason = up::parse_error_envelope(open_res->body).reason;
            auto decision = up::decide_next_action(status, reason, attempt);
            if (decision.action != up::UploadDecision::kRetry) {
                ctx.write_output(std::format("error|failed to open upload session (HTTP {}{})",
                                             status, describe_reason(reason)));
                return 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(decision.backoff_ms));
        }

        if (session->chunk_max_bytes <= 0) {
            ctx.write_output("error|server returned an invalid chunk_max_bytes");
            return 1;
        }
        // #3136 minor: same local grammar precheck as the grant credential
        // above, applied to the server-returned session credential before
        // it's used to build every subsequent request's session header.
        if (!up::is_valid_credential_parts(session->upload_id, session->session_secret)) {
            ctx.write_output("error|server returned a session credential of unexpected shape");
            return 1;
        }

        const std::string session_header = session->upload_id + "." + session->session_secret;
        const std::string chunk_path = "/api/v1/uploads/" + session->upload_id + "/chunk";
        const std::string commit_path = "/api/v1/uploads/" + session->upload_id + "/commit";
        const std::string cancel_path = "/api/v1/uploads/" + session->upload_id;

        ctx.report_progress(5);

        // ── Chunk streaming ──────────────────────────────────────────
        // The commit digest is built INCREMENTALLY, and the invariant that
        // makes it correct is positional, not response-shaped: `hasher`
        // must cover EXACTLY `[0, hashed_to)` of the local file at all
        // times, and `hashed_to` must equal `offset` before the next chunk
        // is planned. The ordinary path keeps that invariant by feeding
        // `hasher` the exact buffer just transmitted the moment the server
        // acknowledges it (never a later, independent re-read — see the
        // RAII-handle comment above, #P7-003). Two situations cannot do
        // that because the bytes were never in THIS process's memory or
        // this hasher's history: a RESUMED session's already-uploaded
        // prefix, and a `kResync` response whose authoritative offset jumps
        // PAST what this hasher has hashed (the chunk landed on the server
        // but this process never saw the success response, so it never
        // called `update()` for it). Both repair the SAME way — read the
        // missing range from the SAME open handle and hash it — via one
        // shared helper so the two call sites cannot drift.
        IncrementalSha256 hasher;
        std::int64_t hashed_to = 0;

        // Advance `hasher` to cover `[hashed_to, target)`, reading from the
        // same `file` handle. `plan_resync_rehash` (the pure decision this
        // wraps — content_dist_upload_parsers.hpp) says whether there is
        // anything to do; a `nullopt` covers the ordinary post-chunk case
        // where `hashed_to` already equals the new offset. Returns false on
        // a read or crypto failure, having already written the
        // operator-facing error.
        auto rehash_to = [&](std::int64_t target) -> bool {
            auto range = up::plan_resync_rehash(hashed_to, target);
            if (!range)
                return true;
            file.clear();
            file.seekg(range->start, std::ios::beg);
            std::vector<char> prefix_buf(64 * 1024);
            std::int64_t remaining = range->end - range->start;
            while (remaining > 0) {
                const auto want = static_cast<std::streamsize>(
                    std::min<std::int64_t>(remaining, static_cast<std::int64_t>(prefix_buf.size())));
                file.read(prefix_buf.data(), want);
                if (file.gcount() != want) {
                    ctx.write_output("error|failed to read local file while hashing "
                                     "already-acknowledged bytes");
                    return false;
                }
                hasher.update(prefix_buf.data(), static_cast<std::size_t>(want));
                if (!hasher.ok()) {
                    ctx.write_output("error|digest computation failed while hashing "
                                     "already-acknowledged bytes");
                    return false;
                }
                remaining -= want;
            }
            hashed_to = target;
            return true;
        };

        if (session->offset > 0 && !rehash_to(session->offset)) {
            return 1;
        }

        std::int64_t offset = session->offset;
        std::int64_t last_progress_offset = -1;
        int attempt = 1;
        std::vector<char> buf;

        while (offset < file_size) {
            if (offset > last_progress_offset) {
                last_progress_offset = offset;
                attempt = 1;
            }

            auto spec = up::plan_next_chunk(offset, file_size, session->chunk_max_bytes);
            if (!spec) {
                abort_upload(client, cancel_path, session_header, ctx,
                            "internal chunk-planning error");
                return 1;
            }
            const auto chunk_len = spec->end - spec->start + 1;
            buf.resize(static_cast<std::size_t>(chunk_len));
            file.clear();
            file.seekg(spec->start, std::ios::beg);
            file.read(buf.data(), static_cast<std::streamsize>(chunk_len));
            if (file.gcount() != static_cast<std::streamsize>(chunk_len)) {
                abort_upload(client, cancel_path, session_header, ctx,
                            "failed to read local file while streaming");
                return 1;
            }

            httplib::Headers chunk_headers = {
                {"X-Yuzu-Upload-Session", session_header},
                {"Content-Range", std::format("bytes {}-{}/{}", spec->start, spec->end, spec->total)},
            };
            auto res = client.Put(chunk_path, chunk_headers, std::string(buf.data(), buf.size()),
                                  "application/octet-stream");
            const int status = res ? res->status : 0;

            if (res && status == 200) {
                auto ack = up::parse_chunk_ack_offset(res->body);
                // The only valid ack is EXACTLY `spec->end + 1` — the agent
                // already knows what a successful write of THIS chunk must
                // produce, so a missing or disagreeing offset is a
                // malformed/inconsistent response, not new state to adopt
                // (#P7-004).
                auto validated = up::validate_chunk_ack(ack, spec->end + 1, file_size);
                if (!validated) {
                    abort_upload(client, cancel_path, session_header, ctx,
                                "server returned a missing or inconsistent chunk offset "
                                "acknowledgement");
                    return 1;
                }
                // Hash the SAME buffer just transmitted, now that the
                // server has confirmed receipt of exactly this range.
                // `spec->start == hashed_to` always holds here: either the
                // previous iteration advanced both together, or the resync
                // branch below called `rehash_to` before looping back.
                hasher.update(buf.data(), buf.size());
                if (!hasher.ok()) {
                    abort_upload(client, cancel_path, session_header, ctx,
                                "digest computation failed");
                    return 1;
                }
                offset = *validated;
                hashed_to = offset;
                ctx.report_progress(
                    5 + static_cast<int>(offset * 90 / file_size)); // 5..95 while streaming
                continue;
            }

            std::optional<up::Reason> reason;
            if (res)
                reason = up::parse_error_envelope(res->body).reason;
            auto decision = up::decide_next_action(status, reason, attempt);
            switch (decision.action) {
            case up::UploadDecision::kResync: {
                auto authoritative = res ? up::parse_error_envelope(res->body).offset
                                         : std::nullopt;
                auto resynced = authoritative
                                    ? up::reconcile_resume_offset(*authoritative, file_size)
                                    : std::nullopt;
                if (!resynced) {
                    abort_upload(client, cancel_path, session_header, ctx,
                                "server reported offset_mismatch without a usable offset");
                    return 1;
                }
                // A FORWARD resync means the server accepted a chunk whose
                // success response this process never saw — those bytes
                // are in the file but never reached `hasher`. Repair the
                // digest's coverage before adopting the new offset, or the
                // eventual commit hash silently omits them (they were
                // uploaded and are part of the file the server has; the
                // committed digest must include them too).
                if (*resynced > hashed_to && !rehash_to(*resynced)) {
                    return 1;
                }
                if (*resynced <= offset) {
                    // No forward progress — without a bounded budget here a
                    // server that keeps handing back a non-advancing
                    // offset would drive an unbounded resend loop
                    // (#P7-006). Reuses the SAME attempt/backoff budget as
                    // an ordinary retry; a resync that DOES advance resets
                    // it via the `offset > last_progress_offset` check at
                    // the top of the loop, same as any other progress.
                    if (up::attempts_exhausted(attempt)) {
                        abort_upload(client, cancel_path, session_header, ctx,
                                    "offset_mismatch resync made no forward progress after "
                                    "repeated attempts");
                        return 1;
                    }
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(up::backoff_delay_ms(attempt)));
                    ++attempt;
                }
                offset = *resynced;
                continue;
            }
            case up::UploadDecision::kRetry:
                ++attempt;
                std::this_thread::sleep_for(std::chrono::milliseconds(decision.backoff_ms));
                continue;
            case up::UploadDecision::kAbort:
                abort_upload(client, cancel_path, session_header, ctx,
                            std::format("chunk upload failed (HTTP {}{})", status,
                                        describe_reason(reason)));
                return 1;
            }
        }

        auto finalized_hash = hasher.finalize();
        if (!finalized_hash) {
            abort_upload(client, cancel_path, session_header, ctx,
                        "failed to compute upload hash");
            return 1;
        }
        const std::string computed_hash = *finalized_hash;

        // ── Commit ───────────────────────────────────────────────────
        // Bounded retry loop mirroring session-open's, driven by the SAME
        // `decide_next_action` (#P7-002: a transient commit failure used to
        // cancel the upload outright instead of honouring the retry
        // policy). A `session_terminal` reason on commit specifically, or a
        // pure connection-level/unreasoned failure once the retry budget is
        // exhausted, is outcome-AMBIGUOUS: the server may already have
        // committed THIS exact upload from an earlier attempt whose
        // response never reached the agent (`file_retrieval_routes.cpp`'s
        // commit handler races itself by design — a concurrent winner
        // reports `session_terminal` to the loser). The status route
        // answers 200 with the current state even for a terminal session,
        // so that ambiguity is resolved there BEFORE declaring failure or
        // sending a cancel that would otherwise be pointless or misleading.
        httplib::Headers commit_headers = {{"X-Yuzu-Upload-Session", session_header}};
        const std::string commit_body = "{\"sha256\":\"" + computed_hash + "\"}";

        std::optional<up::CommitResponse> commit_result;
        for (int commit_attempt = 1;; ++commit_attempt) {
            auto commit_res =
                client.Post(commit_path, commit_headers, commit_body, "application/json");
            const int commit_status = commit_res ? commit_res->status : 0;
            if (commit_res && commit_status == 200) {
                commit_result = up::parse_commit_response(commit_res->body);
                if (!commit_result) {
                    ctx.write_output("error|malformed commit response from server");
                    return 1;
                }
                break;
            }

            std::optional<up::Reason> reason;
            if (commit_res)
                reason = up::parse_error_envelope(commit_res->body).reason;
            auto decision = up::decide_next_action(commit_status, reason, commit_attempt);

            const bool ambiguous = reason == up::Reason::kSessionTerminal ||
                                   (decision.action != up::UploadDecision::kRetry &&
                                    up::is_transient_no_reason(commit_status, reason));
            if (ambiguous) {
                auto status_res = client.Get(
                    cancel_path, httplib::Headers{{"X-Yuzu-Upload-Session", session_header}});
                if (status_res && status_res->status == 200) {
                    auto st = up::parse_status_response(status_res->body);
                    if (st && st->state == "committed") {
                        // Reported response values are our own locally
                        // transmitted state — the server's commit ONLY
                        // succeeds with the sha256 this exact run posted
                        // (`upload_grant::verify_commit`), so these are the
                        // values that committed, whichever attempt won.
                        commit_result = up::CommitResponse{"committed", file_size, computed_hash};
                        break;
                    }
                }
            }

            if (decision.action == up::UploadDecision::kRetry) {
                std::this_thread::sleep_for(std::chrono::milliseconds(decision.backoff_ms));
                continue;
            }

            abort_upload(client, cancel_path, session_header, ctx,
                        std::format("commit failed (HTTP {}{})", commit_status,
                                    describe_reason(reason)));
            return 1;
        }

        // The server's own reported size/hash must agree with what this
        // run computed and transmitted — a 200 naming different metadata
        // is a server-contract violation, not a result to trust (#P7-009).
        if (!up::commit_matches(*commit_result, file_size, computed_hash)) {
            ctx.write_output(std::format(
                "error|commit response does not match the uploaded file (expected size={} "
                "sha256={}, server reported size={} sha256={})",
                file_size, computed_hash, commit_result->actual_size, commit_result->sha256));
            return 1;
        }

        ctx.report_progress(100);
        ctx.write_output("status|ok");
        ctx.write_output(std::format("sha256|{}", commit_result->sha256));
        ctx.write_output(std::format("size|{}", commit_result->actual_size));
        ctx.write_output(std::format("upload_id|{}", session->upload_id));
        return 0;
#endif
    }

    int do_cleanup(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto hours_str = params.get("hours");
        int hours = 24;
        if (!hours_str.empty()) {
            try {
                hours = std::stoi(std::string{hours_str});
            } catch (...) {}
        }

        auto dir = staging_dir();
        auto cutoff = fs::file_time_type::clock::now() - std::chrono::hours(hours);
        std::error_code ec;
        int removed = 0;
        yuzu::PluginContext pctx{g_ctx};
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (entry.is_regular_file() && entry.last_write_time(ec) < cutoff) {
                auto fname = entry.path().filename().string();
                fs::remove(entry.path(), ec);
                // #808: also evict the staged-hash KV entry so an entry
                // can't outlive the file it describes (would leak storage
                // and confuse a future `do_execute` that fails on
                // "file not staged" rather than the more useful
                // "no trusted hash on record" message — but the file
                // doesn't exist anyway, so either is correct).
                pctx.storage_delete(std::string{"staged_hash:"} + fname);
                ++removed;
            }
        }
        ctx.write_output(std::format("removed|{}", removed));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(ContentDistPlugin)
