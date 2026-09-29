#include <yuzu/agent/cert_discovery.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <span>
#include <string>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h> // geteuid()
#endif

namespace yuzu::agent {

namespace {

struct CertKeyPair {
    const char* cert;
    const char* key;
    const char* source;
};

std::string getenv_string(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || !value)
        return {};

    std::string result{value};
    free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value ? std::string{value} : std::string{};
#endif
}

bool file_exists_and_readable(const std::filesystem::path& p) {
    std::error_code ec;
    auto status = std::filesystem::status(p, ec);
    if (ec)
        return false;
    return std::filesystem::is_regular_file(status);
}

} // anonymous namespace

std::optional<DiscoveredCert> discover_client_cert() {
    // 1. Environment variables (all platforms)
    auto env_cert = getenv_string("YUZU_CLIENT_CERT");
    auto env_key = getenv_string("YUZU_CLIENT_KEY");
    if (!env_cert.empty() && !env_key.empty()) {
        std::filesystem::path cert_path{env_cert};
        std::filesystem::path key_path{env_key};
        if (file_exists_and_readable(cert_path) && file_exists_and_readable(key_path)) {
            spdlog::info("Auto-discovered client cert from environment: {}", cert_path.string());
            return DiscoveredCert{.cert_path = std::move(cert_path),
                                  .key_path = std::move(key_path),
                                  .source = "env"};
        }
        spdlog::debug("YUZU_CLIENT_CERT/KEY set but files not readable");
    }

#ifndef _WIN32
    // 2-4. Well-known paths (Linux/macOS only)
    static constexpr std::array<CertKeyPair, 3> kConventionPaths = {{
        // Yuzu-specific path (works with FreeIPA certmonger provisioning)
        {"/etc/yuzu/agent.pem", "/etc/yuzu/agent-key.pem", "convention:/etc/yuzu"},
        // RHEL / CentOS / Fedora (standard PKI paths, works with certmonger)
        {"/etc/pki/tls/certs/yuzu-agent.pem", "/etc/pki/tls/private/yuzu-agent.pem",
         "convention:/etc/pki"},
        // Debian / Ubuntu
        {"/etc/ssl/certs/yuzu-agent.pem", "/etc/ssl/private/yuzu-agent.pem", "convention:/etc/ssl"},
    }};

    for (const auto& pair : kConventionPaths) {
        std::filesystem::path cert_path{pair.cert};
        std::filesystem::path key_path{pair.key};

        if (file_exists_and_readable(cert_path) && file_exists_and_readable(key_path)) {
            spdlog::info("Auto-discovered client cert at {}", cert_path.string());
            return DiscoveredCert{.cert_path = std::move(cert_path),
                                  .key_path = std::move(key_path),
                                  .source = pair.source};
        }
        spdlog::debug("Cert discovery: {} not found", pair.cert);
    }
#else
    spdlog::debug("Cert discovery: skipping filesystem paths on Windows (use --cert-store)");
#endif

    return std::nullopt;
}

namespace {

bool is_nonempty_regular_file(const std::filesystem::path& p) {
    std::error_code ec;
    // Reject a symlink at the leaf (#1314 M-2, defense-in-depth): the trust anchor
    // must be a real file. The shared cert volume is not agent-writable in the
    // reference topology, but if it were ever loosened, a planted symlink to an
    // attacker-controlled CA must not be silently adopted. symlink_status does NOT
    // follow the link, so a symlinked default-ca.pem is treated as not-a-file.
    auto link_status = std::filesystem::symlink_status(p, ec);
    if (ec || std::filesystem::is_symlink(link_status) ||
        !std::filesystem::is_regular_file(link_status))
        return false;
    auto size = std::filesystem::file_size(p, ec);
    return !ec && size > 0;
}

} // anonymous namespace

std::optional<std::filesystem::path>
discover_install_ca_path(std::span<const std::filesystem::path> candidates) {
    for (const auto& p : candidates) {
        if (is_nonempty_regular_file(p))
            return p;
    }
    return std::nullopt;
}

std::optional<std::filesystem::path> discover_install_ca_path() {
#if defined(__APPLE__)
    // macOS has two legitimate install locations. /etc/yuzu/certs is the
    // packaged/privileged-install convention shared with Linux, and is the
    // only candidate for a root agent (a LaunchDaemon, or the _yuzu service
    // account, which has no writable $HOME to speak of). A non-root agent
    // (dev/UAT rigs) also checks the per-user Application Support path that
    // server::auth::default_cert_dir() falls back to for a non-root native
    // server run, since /etc/yuzu is root-owned. Gated on euid, not just
    // __APPLE__: macOS sudo preserves $HOME by default, so an unqualified
    // $HOME candidate would let a root agent adopt a CA from an unprivileged
    // user's home as its pinned trust anchor. Built at call time (not a
    // static array) because the second candidate depends on $HOME — both are
    // still trusted, code-controlled paths, not operator input.
    std::vector<std::filesystem::path> candidates = {
        std::filesystem::path{"/etc/yuzu/certs/default-ca.pem"},
    };
    if (::geteuid() != 0) {
        if (const char* home = std::getenv("HOME")) {
            candidates.push_back(std::filesystem::path(home) /
                                  "Library/Application Support/Yuzu/certs/default-ca.pem");
        }
    }
    return discover_install_ca_path(candidates);
#else
    static const std::array<std::filesystem::path, 1> kInstallCaPaths = {{
#ifdef _WIN32
        std::filesystem::path{"C:/ProgramData/Yuzu/certs/default-ca.pem"},
#else
        std::filesystem::path{"/etc/yuzu/certs/default-ca.pem"},
#endif
    }};
    return discover_install_ca_path(std::span<const std::filesystem::path>{kInstallCaPaths});
#endif
}

} // namespace yuzu::agent