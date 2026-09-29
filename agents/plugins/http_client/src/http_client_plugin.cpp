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
 *           SSRF protection: blocks requests to private/internal IP ranges.
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
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#endif

#include <httplib.h>

#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>

namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxDownloadSize = 100 * 1024 * 1024; // 100 MiB

YuzuPluginContext* g_ctx = nullptr;

bool is_valid_url(std::string_view url) {
    return url.starts_with("http://") || url.starts_with("https://");
}

// ── SSRF protection: reject private/internal IP addresses ───────────────────

bool is_private_ipv4(const struct sockaddr_in* addr) {
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    // 127.0.0.0/8
    if ((ip >> 24) == 127) return true;
    // 10.0.0.0/8
    if ((ip >> 24) == 10) return true;
    // 172.16.0.0/12
    if ((ip >> 20) == (172 << 4 | 1)) return true;  // 172.16-31.x.x
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((ip >> 16) == (192 << 8 | 168)) return true;
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    // 169.254.0.0/16 (link-local)
    if ((ip >> 16) == (169 << 8 | 254)) return true;
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return true;
    // 100.64.0.0/10 (carrier-grade NAT / RFC 6598)
    if ((ip & 0xFFC00000) == 0x64400000) return true;
    // 198.18.0.0/15 (benchmarking / RFC 2544)
    if ((ip & 0xFFFE0000) == 0xC6120000) return true;
    // 0.0.0.0
    if (ip == 0) return true;
    return false;
}

bool is_private_ipv6(const struct sockaddr_in6* addr) {
    const uint8_t* b = addr->sin6_addr.s6_addr;
    // ::1 (loopback)
    static const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (std::memcmp(b, loopback, 16) == 0) return true;
    // :: (unspecified)
    static const uint8_t unspec[16] = {0};
    if (std::memcmp(b, unspec, 16) == 0) return true;
    // fd00::/8 (unique local)
    if (b[0] == 0xfd) return true;
    // fc00::/7 (unique local, broader)
    if ((b[0] & 0xfe) == 0xfc) return true;
    // fe80::/10 (link-local)
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return true;
    // ::ffff:0:0/96 (IPv4-mapped) — check the embedded IPv4
    static const uint8_t v4mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (std::memcmp(b, v4mapped_prefix, 12) == 0) {
        struct sockaddr_in sa4{};
        sa4.sin_family = AF_INET;
        std::memcpy(&sa4.sin_addr.s_addr, b + 12, 4);
        return is_private_ipv4(&sa4);
    }
    return false;
}

bool hostname_resolves_to_private(const std::string& hostname) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (rc != 0 || !result) return true; // fail-closed: block on resolution failure

    bool is_private = false;
    for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            if (is_private_ipv4(reinterpret_cast<struct sockaddr_in*>(rp->ai_addr))) {
                is_private = true;
                break;
            }
        } else if (rp->ai_family == AF_INET6) {
            if (is_private_ipv6(reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr))) {
                is_private = true;
                break;
            }
        }
    }

    freeaddrinfo(result);
    return is_private;
}

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

// ── SHA-256 file hashing ────────────────────────────────────────────────────

std::string sha256_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    DWORD hash_len = 0, result_len = 0;
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &result_len, 0);
    BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);

    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf), static_cast<ULONG>(file.gcount()), 0);
    }

    std::vector<UCHAR> digest(hash_len);
    BCryptFinishHash(hash, digest.data(), hash_len, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    std::string hex;
    for (auto b : digest) hex += std::format("{:02x}", b);
    return hex;
#else
    auto* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(file.gcount()));
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);

    std::string hex;
    for (unsigned i = 0; i < len; ++i) hex += std::format("{:02x}", digest[i]);
    return hex;
#endif
}

// ── Safe HTTP operations using cpp-httplib ───────────────────────────────────

// Download a file via httplib (no shell, no command injection)
int download_url(std::string_view url, const fs::path& dest, std::string& error) {
    ParsedUrl parsed;
    if (!parse_url(url, parsed)) {
        error = "invalid URL";
        return 1;
    }

    // SSRF check
    if (hostname_resolves_to_private(parsed.host)) {
        error = "SSRF blocked: URL resolves to a private/internal IP address";
        return 1;
    }

    std::string origin = (parsed.is_https ? "https://" : "http://") + parsed.host + ":" + std::to_string(parsed.port);

    std::ofstream ofs(dest, std::ios::binary);
    if (!ofs) {
        error = "failed to open destination file for writing";
        return 1;
    }

    size_t total_bytes = 0;
    bool size_exceeded = false;

    auto content_receiver = [&](const char* data, size_t len) {
        total_bytes += len;
        if (total_bytes > kMaxDownloadSize) {
            size_exceeded = true;
            return false; // abort download
        }
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

    if (size_exceeded) {
        std::error_code ec;
        std::filesystem::remove(dest, ec);
        error = "download aborted: exceeded maximum size limit (100 MB)";
        return 1;
    }

    if (!res || res->status < 200 || res->status >= 400) {
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

    // SSRF check
    if (hostname_resolves_to_private(parsed.host)) {
        status_code = 0;
        return "SSRF blocked: URL resolves to a private/internal IP address";
    }

    httplib::Result res;
    if (parsed.is_https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient cli(parsed.host, parsed.port);
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

    // SSRF check
    if (hostname_resolves_to_private(parsed.host)) {
        status_code = 0;
        return "SSRF blocked: URL resolves to a private/internal IP address";
    }

    httplib::Result res;
    if (parsed.is_https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient cli(parsed.host, parsed.port);
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
        cli.set_connection_timeout(30);
        cli.set_read_timeout(60);
        res = cli.Head(parsed.path);
    }

    if (!res) {
        status_code = 0;
        return "connection failed";
    }
    status_code = res->status;

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
            dest = canonical_parent / dest.filename();
            // Reject if any component is ".."
            for (const auto& component : fs::path{std::string{path}}) {
                if (component == "..") {
                    ctx.write_output("error|path traversal not allowed (contains '..')");
                    return 1;
                }
            }
        }
        std::string error;
        if (download_url(url, dest, error) != 0) {
            ctx.write_output(std::format("error|{}", error));
            return 1;
        }

        std::error_code ec;
        auto size = fs::file_size(dest, ec);
        auto hash = sha256_file(dest);

        auto expected = params.get("expected_hash");
        if (!expected.empty() && hash != expected) {
            fs::remove(dest, ec);
            ctx.write_output(std::format("error|hash mismatch: expected={}, got={}", expected, hash));
            return 1;
        }

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
