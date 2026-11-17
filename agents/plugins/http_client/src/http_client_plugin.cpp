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
 *           rebind.
 *           Download: the body is held in memory (capped), verified against expected_hash, and only
 *           then atomically written over the destination; a failed, non-2xx, over-cap or
 *           unverified transfer writes NOTHING. A destination on a network/device path is
 *           refused.
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

#include "http_client_download.hpp" // completeness / finalize rules (pure; unit-tested)
#include <local_path_policy.hpp>      // refuse a UNC / device / network-mount destination
#include <outbound_address_policy.hpp> // resolve-once address vetting

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
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

// ── SSRF protection: resolve once, vet every address, connect to a vetted one ───────────────

struct AddrInfoDeleter {
    void operator()(struct addrinfo* p) const noexcept {
        if (p != nullptr)
            freeaddrinfo(p);
    }
};
using AddrInfoPtr = std::unique_ptr<struct addrinfo, AddrInfoDeleter>;

// One getaddrinfo for `host`; every answer as raw bytes. The list is owned by AddrInfoPtr from the
// moment getaddrinfo returns, so an exception from the loop below cannot leak it. Empty = the
// lookup failed (the caller fails closed).
std::vector<yuzu::shared::outbound::ResolvedAddress> resolve_all(const std::string& host) {
    std::vector<yuzu::shared::outbound::ResolvedAddress> out;
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* raw = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &raw) != 0 || raw == nullptr)
        return out;
    const AddrInfoPtr list{raw};
    for (const struct addrinfo* rp = list.get(); rp != nullptr; rp = rp->ai_next) {
        yuzu::shared::outbound::ResolvedAddress a;
        // The sockaddr is copied into a local of the right type, length-checked, rather than cast
        // from ai_addr, whose alignment is the resolver's business.
        if (rp->ai_family == AF_INET && rp->ai_addr != nullptr &&
            static_cast<std::size_t>(rp->ai_addrlen) >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in sa{};
            std::memcpy(&sa, rp->ai_addr, sizeof(sa));
            std::memcpy(a.bytes.data(), &sa.sin_addr, 4);
        } else if (rp->ai_family == AF_INET6 && rp->ai_addr != nullptr &&
                   static_cast<std::size_t>(rp->ai_addrlen) >= sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 sa{};
            std::memcpy(&sa, rp->ai_addr, sizeof(sa));
            a.is_v6 = true;
            std::memcpy(a.bytes.data(), &sa.sin6_addr, 16);
        } else {
            continue;
        }
        out.push_back(a);
    }
    return out;
}

// Numeric text of one vetted address (the cpp-httplib address-map value).
std::string address_text(const yuzu::shared::outbound::ResolvedAddress& a) {
    char buf[INET6_ADDRSTRLEN]{};
    if (a.is_v6) {
        struct in6_addr x{};
        std::memcpy(&x, a.bytes.data(), 16);
        inet_ntop(AF_INET6, &x, buf, sizeof(buf));
    } else {
        struct in_addr x{};
        std::memcpy(&x, a.bytes.data(), 4);
        inet_ntop(AF_INET, &x, buf, sizeof(buf));
    }
    return buf;
}

// Resolve `host` ONCE and judge every answer. Returns the vetted addresses as numeric text in
// connect order (IPv4 first); the caller connects to those and must NOT re-resolve the name. Empty
// means the destination is blocked (refused, or the lookup failed: fail closed).
std::vector<std::string> vet_destination(const std::string& host) {
    namespace ob = yuzu::shared::outbound;
    const auto outcome = ob::vet_host([&] { return resolve_all(host); });
    std::vector<std::string> ips;
    if (outcome.verdict.status != ob::VetStatus::ok)
        return ips;
    for (const auto& a : ob::connect_order(outcome.answers))
        ips.push_back(address_text(a));
    return ips;
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

constexpr std::chrono::seconds kDownloadTotalTimeout{600}; // whole transfer, not per recv
constexpr std::chrono::seconds kRequestTotalTimeout{120};

// Run one request through a client pinned to `ip` (the host name stays the Host header and the TLS
// name). `request` is called with the configured client (Client or SSLClient). An https URL on a
// build without OpenSSL sets `https_unsupported` and runs nothing.
template <class Fn>
httplib::Result run_pinned(const ParsedUrl& parsed, const std::string& ip, int read_timeout_s,
                           std::chrono::seconds total_timeout, bool& https_unsupported,
                           Fn&& request) {
    const auto setup = [&](auto& cli) {
        cli.set_hostname_addr_map({{parsed.host, ip}});
        cli.set_connection_timeout(30);
        cli.set_read_timeout(read_timeout_s);
        // A total deadline for the whole exchange: the per-recv timeouts alone let a server that
        // trickles one byte at a time hold a worker (and, for a download, a growing buffer).
        cli.set_max_timeout(total_timeout);
    };
    if (parsed.is_https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient cli(parsed.host, parsed.port);
        setup(cli);
        cli.enable_server_certificate_verification(true);
        return request(cli);
#else
        https_unsupported = true;
        return {};
#endif
    }
    httplib::Client cli(parsed.host, parsed.port);
    setup(cli);
    return request(cli);
}

// Try each vetted address in turn (IPv4 first) until one connects: a host that answers both
// families keeps its dual-stack fallback without a second lookup of the name.
template <class Fn>
httplib::Result try_vetted(const ParsedUrl& parsed, const std::vector<std::string>& ips,
                           int read_timeout_s, std::chrono::seconds total_timeout,
                           bool& https_unsupported, Fn&& request) {
    httplib::Result res;
    for (const auto& ip : ips) {
        res = run_pinned(parsed, ip, read_timeout_s, total_timeout, https_unsupported, request);
        if (res || https_unsupported)
            break;
    }
    return res;
}

// Fetch a file body into `body` (no shell, no command injection). Nothing touches the filesystem
// here: only a 2xx answer is accepted (the response handler aborts the transfer for any other
// status, so an error page is never buffered as "the download"), the body is capped, and it must be
// COMPLETE: an `expected_hash` verifies completeness itself, otherwise the response must declare
// its length (Content-Length, or chunked framing that httplib verifies) and the body must match it
// (a close-delimited body cut short would otherwise look like a finished download).
int download_url(std::string_view url, std::string& body, bool hash_will_verify, std::string& error) {
    ParsedUrl parsed;
    if (!parse_url(url, parsed)) {
        error = "invalid URL";
        return 1;
    }

    // SSRF check: resolve once; the connection below is pinned to a vetted address.
    const auto ips = vet_destination(parsed.host);
    if (ips.empty()) {
        error = kSsrfBlocked;
        return 1;
    }

    bool size_exceeded = false;
    int rejected_status = 0;
    bool has_length = false;
    bool chunked = false;
    std::uint64_t declared_length = 0;
    body.clear();

    auto response_handler = [&](const httplib::Response& r) {
        if (r.status < 200 || r.status >= 300) {
            rejected_status = r.status;
            return false;
        }
        chunked = r.get_header_value("Transfer-Encoding").find("chunked") != std::string::npos;
        if (r.has_header("Content-Length")) {
            const auto v = r.get_header_value("Content-Length");
            const auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), declared_length);
            has_length = ec == std::errc{} && ptr == v.data() + v.size();
            if (has_length && declared_length > kMaxDownloadSize) {
                size_exceeded = true;
                return false;
            }
            if (has_length)
                body.reserve(static_cast<std::size_t>(declared_length)); // one allocation, no doubling
        }
        return true;
    };
    auto content_receiver = [&](const char* data, size_t len) {
        if (body.size() + len > kMaxDownloadSize) {
            size_exceeded = true;
            return false; // abort download
        }
        body.append(data, len);
        return true;
    };

    yuzu::http_client::DownloadObservation obs;
    obs.hash_will_verify = hash_will_verify;
    httplib::Result res;
    try {
        res = try_vetted(parsed, ips, 300, kDownloadTotalTimeout, obs.https_unsupported,
                         [&](auto& cli) {
                             body.clear();
                             return cli.Get(parsed.path, response_handler, content_receiver);
                         });
    } catch (const std::bad_alloc&) {
        obs.out_of_memory = true;
        body.clear();
        body.shrink_to_fit();
    }
    obs.size_exceeded = size_exceeded;
    obs.rejected_status = rejected_status;
    obs.transport_ok = static_cast<bool>(res);
    obs.final_status = res ? res->status : 0;
    obs.has_length = has_length;
    obs.chunked = chunked;
    obs.declared_length = declared_length;
    obs.body_size = body.size();

    error = yuzu::http_client::download_failure(obs);
    if (!error.empty()) {
        body.clear();
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

    // SSRF check: resolve once; the connection below is pinned to a vetted address.
    const auto ips = vet_destination(parsed.host);
    if (ips.empty()) {
        status_code = 0;
        return kSsrfBlocked;
    }

    bool https_unsupported = false;
    auto res = try_vetted(parsed, ips, 60, kRequestTotalTimeout, https_unsupported,
                          [&](auto& cli) { return cli.Get(parsed.path); });
    if (https_unsupported) {
        status_code = 0;
        return "HTTPS not supported (OpenSSL not available)";
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

    // SSRF check: resolve once; the connection below is pinned to a vetted address.
    const auto ips = vet_destination(parsed.host);
    if (ips.empty()) {
        status_code = 0;
        return kSsrfBlocked;
    }

    bool https_unsupported = false;
    auto res = try_vetted(parsed, ips, 60, kRequestTotalTimeout, https_unsupported,
                          [&](auto& cli) { return cli.Head(parsed.path); });
    if (https_unsupported) {
        status_code = 0;
        return "HTTPS not supported (OpenSSL not available)";
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
        // call: fs::canonical below would otherwise reach out to the named host.
        const yuzu::shared::local_path::LocalPathGuard path_guard; // one mount-table snapshot
        if (const auto refusal = path_guard.refusal(path);
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
            if (const auto refusal = path_guard.refusal(canonical_parent.string());
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

        // fetch into memory, verify, and only then atomically replace the destination. A
        // failed, non-2xx, over-cap or hash-mismatched transfer leaves the existing destination
        // (or its absence) exactly as it was: nothing unverified ever sits at `dest`.
        std::string body;
        std::string error;
        const std::string_view expected_param = params.get("expected_hash");
        if (download_url(url, body, /*hash_will_verify=*/!expected_param.empty(), error) != 0) {
            ctx.write_output(std::format("error|{}", error));
            return 1;
        }

        const auto done = yuzu::http_client::finalize_download(body, params.get("expected_hash"), dest);
        if (done.status == yuzu::http_client::FinalizeStatus::hash_mismatch) {
            std::string expected{params.get("expected_hash")};
            for (auto& c : expected)
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            ctx.write_output(std::format("error|hash mismatch: expected={}, got={}", expected, done.hash));
            return 1;
        }
        if (done.status == yuzu::http_client::FinalizeStatus::write_failed) {
            ctx.write_output(std::format("error|failed to write destination: {}", done.message));
            return 1;
        }
        const std::string& hash = done.hash;
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
