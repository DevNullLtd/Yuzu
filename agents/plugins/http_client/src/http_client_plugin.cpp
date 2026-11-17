/**
 * http_client_plugin.cpp — HTTP client plugin for Yuzu
 *
 * Actions:
 *   "download" — Download a file from URL to local path with optional hash verification.
 *                Params: url (required), path (required), expected_hash (optional SHA256).
 *   "get"      — HTTP GET a URL, return status + body.
 *                Params: url (required).
 *   "head"     — HTTP HEAD a URL, return status + headers.
 *                Params: url (required).
 *
 * Output: pipe-delimited via write_output()
 *
 * Security: uses cpp-httplib directly — no shell invocation, no command injection.
 *           SSRF protection: the host is resolved ONCE, every returned address must be a public
 *           address (agents/shared/outbound_address_policy.hpp), and the connection is pinned to
 *           the address that was vetted (cpp-httplib's hostname-to-address map, which keeps the
 *           Host header and TLS SNI/verification on the name) — there is no second lookup to
 *           rebind (F17).
 *           Download: the body is held in memory (capped), verified against expected_hash, and only
 *           then atomically written over the destination; a failed, non-2xx, over-cap or
 *           unverified transfer writes NOTHING (F18). A destination on a network/device path is
 *           refused (F65).
 */

#include <yuzu/plugin.hpp>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <httplib.h>

#include <atomic_file_write.hpp>      // yuzu::shared::write_file_atomic (F18)
#include <local_path_policy.hpp>      // refuse a UNC / device / network-mount destination (F65)
#include <outbound_address_policy.hpp> // resolve-once address vetting (F17)
#include <sha256.hpp>                  // incremental SHA-256 over the in-memory body (F18)

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxDownloadSize = 100 * 1024 * 1024; // 100 MiB

YuzuPluginContext* g_ctx = nullptr;

bool is_valid_url(std::string_view url) {
    return url.starts_with("http://") || url.starts_with("https://");
}

// ── SSRF protection: resolve once, vet every address, connect to the vetted one ─────────────

// One getaddrinfo for `host`; every answer as raw bytes plus its numeric text (inet_ntop).
std::vector<yuzu::shared::outbound::ResolvedAddress> resolve_all(const std::string& host,
                                                                 std::vector<std::string>& texts) {
    std::vector<yuzu::shared::outbound::ResolvedAddress> out;
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || !result)
        return out; // empty = resolution failed: the caller fails closed
    for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
        yuzu::shared::outbound::ResolvedAddress a;
        char text[INET6_ADDRSTRLEN]{};
        if (rp->ai_family == AF_INET) {
            const auto* sa = reinterpret_cast<const struct sockaddr_in*>(rp->ai_addr);
            std::memcpy(a.bytes.data(), &sa->sin_addr, 4);
            inet_ntop(AF_INET, &sa->sin_addr, text, sizeof(text));
        } else if (rp->ai_family == AF_INET6) {
            const auto* sa = reinterpret_cast<const struct sockaddr_in6*>(rp->ai_addr);
            a.is_v6 = true;
            std::memcpy(a.bytes.data(), &sa->sin6_addr, 16);
            inet_ntop(AF_INET6, &sa->sin6_addr, text, sizeof(text));
        } else {
            continue;
        }
        out.push_back(a);
        texts.emplace_back(text);
    }
    freeaddrinfo(result);
    return out;
}

// Resolve `host` ONCE and judge every answer. On success `vetted_ip` is the numeric address the
// caller must connect to (and must NOT re-resolve the name); on refusal or a failed lookup the
// destination is blocked (fail closed).
bool vet_destination(const std::string& host, std::string& vetted_ip) {
    std::vector<std::string> texts;
    std::vector<yuzu::shared::outbound::ResolvedAddress> answers;
    const auto verdict = yuzu::shared::outbound::vet_host(
        [&] { return resolve_all(host, texts); }, answers);
    if (verdict.status != yuzu::shared::outbound::VetStatus::ok || verdict.index >= texts.size())
        return false;
    vetted_ip = texts[verdict.index];
    return true;
}

constexpr const char* kSsrfBlocked = "SSRF blocked: URL resolves to a private/internal IP address";

// Parse a URL into scheme, host, port, path components
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

    // Split host from path
    auto slash_pos = url.find('/');
    std::string_view authority;
    if (slash_pos != std::string_view::npos) {
        authority = url.substr(0, slash_pos);
        out.path = std::string(url.substr(slash_pos));
    } else {
        authority = url;
        out.path = "/";
    }

    // Split host from port
    auto colon_pos = authority.rfind(':');
    // Handle IPv6 addresses in brackets
    auto bracket_pos = authority.find(']');
    if (colon_pos != std::string_view::npos &&
        (bracket_pos == std::string_view::npos || colon_pos > bracket_pos)) {
        out.host = std::string(authority.substr(0, colon_pos));
        auto port_str = authority.substr(colon_pos + 1);
        try { out.port = std::stoi(std::string(port_str)); } catch (...) { out.port = 0; }
    } else {
        out.host = std::string(authority);
        out.port = 0;
    }

    if (out.port == 0) {
        out.port = out.is_https ? 443 : 80;
    }

    return !out.host.empty();
}

// ── Safe HTTP operations using cpp-httplib ───────────────────────────────────

// Fetch a file body into `body` (no shell, no command injection). Nothing touches the filesystem
// here: only a 2xx answer is accepted (the response handler aborts the transfer for any other
// status, so an error page is never buffered as "the download"), and the body is capped.
int download_url(std::string_view url, std::string& body, std::string& error) {
    ParsedUrl parsed;
    if (!parse_url(url, parsed)) {
        error = "invalid URL";
        return 1;
    }

    // SSRF check: resolve once; the connection below is pinned to the vetted address.
    std::string vetted_ip;
    if (!vet_destination(parsed.host, vetted_ip)) {
        error = kSsrfBlocked;
        return 1;
    }

    bool size_exceeded = false;
    body.clear();

    auto response_handler = [](const httplib::Response& r) {
        return r.status >= 200 && r.status < 300;
    };
    auto content_receiver = [&](const char* data, size_t len) {
        if (body.size() + len > kMaxDownloadSize) {
            size_exceeded = true;
            return false; // abort download
        }
        body.append(data, len);
        return true;
    };

    httplib::Result res;
    if (parsed.is_https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient cli(parsed.host, parsed.port);
        cli.set_hostname_addr_map({{parsed.host, vetted_ip}});
        cli.set_connection_timeout(30);
        cli.set_read_timeout(300);
        cli.enable_server_certificate_verification(true);
        res = cli.Get(parsed.path, response_handler, content_receiver);
#else
        error = "HTTPS not supported (OpenSSL not available)";
        return 1;
#endif
    } else {
        httplib::Client cli(parsed.host, parsed.port);
        cli.set_hostname_addr_map({{parsed.host, vetted_ip}});
        cli.set_connection_timeout(30);
        cli.set_read_timeout(300);
        res = cli.Get(parsed.path, response_handler, content_receiver);
    }

    if (size_exceeded) {
        body.clear();
        error = "download aborted: exceeded maximum size limit (100 MB)";
        return 1;
    }

    if (!res || res->status < 200 || res->status >= 300) {
        body.clear();
        error = "download failed: HTTP " + (res ? std::to_string(res->status) : "connection error");
        return 1;
    }

    return 0;
}

// HTTP GET via httplib (no shell, no command injection)
std::string http_get(std::string_view url, int& status_code) {
    ParsedUrl parsed;
    if (!parse_url(url, parsed)) {
        status_code = 0;
        return "invalid URL";
    }

    // SSRF check: resolve once; the connection below is pinned to the vetted address.
    std::string vetted_ip;
    if (!vet_destination(parsed.host, vetted_ip)) {
        status_code = 0;
        return kSsrfBlocked;
    }

    httplib::Result res;
    if (parsed.is_https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient cli(parsed.host, parsed.port);
        cli.set_hostname_addr_map({{parsed.host, vetted_ip}});
        cli.set_connection_timeout(30);
        cli.set_read_timeout(60);
        cli.enable_server_certificate_verification(true);
        res = cli.Get(parsed.path);
#else
        status_code = 0;
        return "HTTPS not supported (OpenSSL not available)";
#endif
    } else {
        httplib::Client cli(parsed.host, parsed.port);
        cli.set_hostname_addr_map({{parsed.host, vetted_ip}});
        cli.set_connection_timeout(30);
        cli.set_read_timeout(60);
        res = cli.Get(parsed.path);
    }

    if (!res) {
        status_code = 0;
        return "connection failed";
    }
    status_code = res->status;
    if (res->body.size() > kMaxDownloadSize) {
        return "response body exceeds maximum size limit";
    }
    return res->body;
}

// HTTP HEAD via httplib (no shell, no command injection)
std::string http_head(std::string_view url, int& status_code) {
    ParsedUrl parsed;
    if (!parse_url(url, parsed)) {
        status_code = 0;
        return "invalid URL";
    }

    // SSRF check: resolve once; the connection below is pinned to the vetted address.
    std::string vetted_ip;
    if (!vet_destination(parsed.host, vetted_ip)) {
        status_code = 0;
        return kSsrfBlocked;
    }

    httplib::Result res;
    if (parsed.is_https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient cli(parsed.host, parsed.port);
        cli.set_hostname_addr_map({{parsed.host, vetted_ip}});
        cli.set_connection_timeout(30);
        cli.set_read_timeout(60);
        cli.enable_server_certificate_verification(true);
        res = cli.Head(parsed.path);
#else
        status_code = 0;
        return "HTTPS not supported (OpenSSL not available)";
#endif
    } else {
        httplib::Client cli(parsed.host, parsed.port);
        cli.set_hostname_addr_map({{parsed.host, vetted_ip}});
        cli.set_connection_timeout(30);
        cli.set_read_timeout(60);
        res = cli.Head(parsed.path);
    }

    if (!res) {
        status_code = 0;
        return "connection failed";
    }
    status_code = res->status;

    // Response headers come back in the order the server sent them (cpp-httplib 0.59 keeps
    // insertion order); before the 0.59 bump the order was unspecified (hash order, differing
    // by platform).
    std::string headers_str;
    for (const auto& [k, v] : res->headers) {
        headers_str += k + ": " + v + "\n";
    }
    return headers_str;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Every action goes through cpp-httplib's native, in-process socket client
// (getaddrinfo + socket()/connect(), no shell, no subprocess) on every
// platform — rung 1 throughout. SHA-256 hashing (download) is likewise
// native, via BCrypt on Windows and OpenSSL EVP elsewhere.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "download",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
    },
    {
        /* .action      = */ "get",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
    },
    {
        /* .action      = */ "head",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "cpp-httplib (native sockets)", nullptr},
    },
};

} // namespace

class HttpClientPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "http_client"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "HTTP client — download files, GET/HEAD requests with hash verification (no shell-out)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"download", "get", "head", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();
        return {};
    }

    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "download") return do_download(ctx, params);
        if (action == "get")      return do_get(ctx, params);
        if (action == "head")     return do_head(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    int do_download(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto url = params.get("url");
        auto path = params.get("path");
        if (url.empty() || path.empty()) {
            ctx.write_output("error|missing required parameters: url, path");
            return 1;
        }
        if (!is_valid_url(url)) {
            ctx.write_output("error|only http:// and https:// URLs are allowed");
            return 1;
        }

        // A destination on a UNC / device / network-mount path is refused before any filesystem
        // call (F65): fs::canonical below would otherwise reach out to the named host.
        if (const auto refusal = yuzu::shared::local_path::local_path_refusal(path);
            yuzu::shared::local_path::refused(refusal)) {
            ctx.write_output(std::format("error|{}",
                                         yuzu::shared::local_path::refusal_token(refusal)));
            return 1;
        }

        // Path traversal protection: reject paths with ".." components
        fs::path dest{std::string{path}};
        {
            std::error_code ec;
            auto parent = dest.parent_path();
            if (parent.empty()) parent = fs::current_path(ec);
            auto canonical_parent = fs::canonical(parent, ec);
            if (ec) {
                ctx.write_output(std::format("error|invalid download path: parent directory does not exist"));
                return 1;
            }
            // A symlink / junction in the parent can resolve to a network location: judge the
            // resolved parent too.
            if (const auto refusal =
                    yuzu::shared::local_path::local_path_refusal(canonical_parent.string());
                yuzu::shared::local_path::refused(refusal)) {
                ctx.write_output(std::format("error|{}",
                                             yuzu::shared::local_path::refusal_token(refusal)));
                return 1;
            }
            dest = canonical_parent / dest.filename();
            // Reject if any component is ".."
            for (const auto& component : fs::path{std::string{path}}) {
                if (component == "..") {
                    ctx.write_output("error|path traversal not allowed (contains '..')");
                    return 1;
                }
            }
        }

        // F18: fetch into memory, verify, and only then atomically replace the destination. A
        // failed, non-2xx, over-cap or hash-mismatched transfer leaves the existing destination
        // (or its absence) exactly as it was: nothing unverified ever sits at `dest`.
        std::string body;
        std::string error;
        if (download_url(url, body, error) != 0) {
            ctx.write_output(std::format("error|{}", error));
            return 1;
        }

        yuzu::shared::Sha256 hasher;
        hasher.update(body.data(), body.size());
        const std::string hash = hasher.hex_digest();

        // expected_hash is hex: compare case-insensitively (the plugin emits lowercase).
        std::string expected{params.get("expected_hash")};
        for (auto& c : expected)
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (!expected.empty() && hash != expected) {
            ctx.write_output(std::format("error|hash mismatch: expected={}, got={}", expected, hash));
            return 1;
        }

        // 0666 & ~umask like the previous ofstream, carrying an existing file's rwx bits.
        const auto written =
            yuzu::shared::write_file_atomic(dest, body, {.owner_only_mode = false});
        if (!written) {
            ctx.write_output(std::format("error|failed to write destination: {}",
                                         written.error().message));
            return 1;
        }
        const auto size = static_cast<std::uintmax_t>(body.size());

        ctx.write_output("status|ok");
        ctx.write_output(std::format("path|{}", dest.string()));
        ctx.write_output(std::format("size|{}", size));
        ctx.write_output(std::format("hash|{}", hash));
        return 0;
    }

    int do_get(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto url = params.get("url");
        if (url.empty()) { ctx.write_output("error|missing required parameter: url"); return 1; }
        if (!is_valid_url(url)) { ctx.write_output("error|only http:// and https:// URLs allowed"); return 1; }

        int status = 0;
        auto body = http_get(url, status);
        ctx.write_output(std::format("status|{}", status));
        ctx.write_output(std::format("body|{}", body));
        return status >= 200 && status < 400 ? 0 : 1;
    }

    int do_head(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto url = params.get("url");
        if (url.empty()) { ctx.write_output("error|missing required parameter: url"); return 1; }
        if (!is_valid_url(url)) { ctx.write_output("error|only http:// and https:// URLs allowed"); return 1; }

        int status = 0;
        auto headers = http_head(url, status);
        ctx.write_output(std::format("status|{}", status));
        ctx.write_output(std::format("headers|{}", headers));
        return status >= 200 && status < 400 ? 0 : 1;
    }
};

YUZU_PLUGIN_EXPORT(HttpClientPlugin)
