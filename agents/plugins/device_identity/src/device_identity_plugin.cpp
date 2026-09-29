/**
 * device_identity_plugin.cpp — Device identity plugin for Yuzu
 *
 * Actions:
 *   "device_name" — Returns the machine hostname.
 *   "domain"      — Returns DNS/AD domain and join status.
 *   "ou"          — Returns Active Directory organizational unit path.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <fstream>
#include <unistd.h>

#include <spdlog/spdlog.h>
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess/probe_tool_path (Wave 3, ADR-3002)
#endif

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
#include <cstdint>

#include <systemd/sd-bus.h>
#endif

#ifdef __APPLE__
#include <netdb.h>
#include <sys/socket.h>

#include <icmp_probe.hpp> // yuzu::shared::AddrInfoGuard (move-only RAII owner for addrinfo*)

#include "device_identity_macos.hpp"
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define SECURITY_WIN32
#include <windows.h>
#include <lm.h>       // NetGetJoinInformation, NetApiBufferFree
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <security.h> // GetComputerObjectNameA
#endif

namespace {

// ── Linux: bounded sd-bus InfoPipe ListDomains (do_domain's AD-join check) ──
// Wave 3 (#2380/ADR-3002 promotion): rung 1 -- a single bounded D-Bus call to
// sssd's InfoPipe, tried before falling back to `realm list` (do_ou's
// already-unprivileged call site to the same binary; see do_domain()'s
// Linux leg and BR-011) rather than unconditionally shelling out to it. Call
// shape
// mirrors agents/core/src/guardian_state_reader.cpp's read_service_blocking()
// exactly: sd_bus_open_system(), then sd_bus_set_method_call_timeout(bus,
// budget) BEFORE the call (this function makes only ONE sd-bus call, so no
// budget re-arm is needed -- guardian_state_reader.cpp's second
// sd_bus_set_method_call_timeout call site only applies when a second
// sequential call follows the first).
#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
constexpr const char* kSssdInfoPipeDest = "org.freedesktop.sssd.infopipe";
constexpr const char* kSssdInfoPipePath = "/org/freedesktop/sssd/infopipe";
constexpr const char* kSssdInfoPipeIface = "org.freedesktop.sssd.infopipe";
// device_identity's do_domain read is a single, short, read-only query --
// generous relative to guardian_state_reader.cpp's 5s (which splits its
// budget across TWO sequential calls); this call makes only one.
constexpr std::uint64_t kSdBusBudgetUs = 3'000'000; // 3s

// Returns the sssd-known domain list on success; std::nullopt on ANY
// error/timeout/absence (bus unreachable, sssd not installed, InfoPipe not
// registered, method-call timeout). The caller MUST fall through
// unconditionally to the existing sssd.conf ifstream parse on nullopt --
// never treat an sd-bus failure as "not joined".
std::optional<std::vector<std::string>> sssd_list_domains_via_sdbus() {
    sd_bus* bus = nullptr;
    int r = sd_bus_open_system(&bus);
    if (r < 0 || bus == nullptr)
        return std::nullopt;
    // BR-012 (found in /adversarial-review, Codex): raw-pointer owners MUST
    // delete copy construction/assignment -- a copy of any of these would
    // double-release the underlying sd-bus object (matches the shape of
    // guardian_state_reader.cpp's SdBusErrorGuard/SdBusMessageGuard, which
    // already do this; that file's own BusGuard is still copyable -- a
    // pre-existing gap in a file this PR doesn't otherwise touch, not fixed
    // here).
    struct BusGuard {
        sd_bus* b;
        explicit BusGuard(sd_bus* bus_ptr) : b(bus_ptr) {}
        ~BusGuard() {
            if (b)
                sd_bus_flush_close_unref(b);
        }
        BusGuard(const BusGuard&) = delete;
        BusGuard& operator=(const BusGuard&) = delete;
    } bus_guard{bus};

    sd_bus_set_method_call_timeout(bus, kSdBusBudgetUs);

    sd_bus_error err = SD_BUS_ERROR_NULL;
    struct ErrGuard {
        sd_bus_error* e;
        explicit ErrGuard(sd_bus_error* err_ptr) : e(err_ptr) {}
        ~ErrGuard() { sd_bus_error_free(e); }
        ErrGuard(const ErrGuard&) = delete;
        ErrGuard& operator=(const ErrGuard&) = delete;
    } err_guard{&err};
    sd_bus_message* reply = nullptr;
    r = sd_bus_call_method(bus, kSssdInfoPipeDest, kSssdInfoPipePath, kSssdInfoPipeIface,
                           "ListDomains", &err, &reply, "");
    struct MsgGuard {
        sd_bus_message* m;
        explicit MsgGuard(sd_bus_message* msg_ptr) : m(msg_ptr) {}
        ~MsgGuard() {
            if (m)
                sd_bus_message_unref(m);
        }
        MsgGuard(const MsgGuard&) = delete;
        MsgGuard& operator=(const MsgGuard&) = delete;
    } msg_guard{reply};
    if (r < 0 || !reply)
        return std::nullopt;

    // ListDomains returns an array of OBJECT PATHS ("ao"), one per configured
    // domain (e.g. "/org/freedesktop/sssd/infopipe/Domains/example_2ecom") --
    // NOT an array of domain-name strings ("as"). Reading "s" against an "ao"
    // reply fails the container read on every conforming SSSD host, silently
    // sending every real join through the sssd.conf fallback. This caller
    // only needs "is the array non-empty" (the do_domain AD-join signal), so
    // the path values themselves are never decoded into domain names.
    if (sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "o") < 0)
        return std::nullopt;
    std::vector<std::string> domains;
    const char* path = nullptr;
    int rr;
    while ((rr = sd_bus_message_read(reply, "o", &path)) > 0) {
        if (path)
            domains.emplace_back(path);
    }
    sd_bus_message_exit_container(reply);
    if (rr < 0)
        return std::nullopt; // malformed reply mid-array -- honest failure, never a partial list
    return domains;
}
#endif // __linux__ && YUZU_HAVE_LIBSYSTEMD

// ── macOS: native FQDN (do_domain's hostname-suffix fallback) ──────────────
// Wave 3: gethostname() + getaddrinfo(AI_CANONNAME) (rung 1) instead of
// popen(hostname -f). Returns "" on any failure (matches the empty-string
// contract the prior popen call had on failure).
#ifdef __APPLE__
std::string local_fqdn() {
    char host[256]{};
    if (gethostname(host, sizeof(host)) != 0)
        return {};
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;
    struct addrinfo* raw_res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &raw_res) != 0 || raw_res == nullptr)
        return {};
    // Adopt immediately -- a std::string allocation that throws between a
    // successful getaddrinfo() and a manual freeaddrinfo() would otherwise
    // leak the resolver's result list.
    yuzu::shared::AddrInfoGuard res_guard(raw_res);
    return res_guard.p->ai_canonname ? res_guard.p->ai_canonname : host;
}
#endif

// ── device_name action ─────────────────────────────────────────────────────

int do_device_name(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__)
    char hostname[256]{};
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        ctx.write_output(std::format("device_name|{}", hostname));
    } else {
        ctx.write_output("device_name|unknown");
    }

#elif defined(_WIN32)
    DWORD size = 0;
    GetComputerNameExA(ComputerNamePhysicalDnsHostname, nullptr, &size);
    if (size > 0) {
        std::string buf(size, '\0');
        if (GetComputerNameExA(ComputerNamePhysicalDnsHostname, buf.data(), &size)) {
            buf.resize(size);
            ctx.write_output(std::format("device_name|{}", buf));
        } else {
            ctx.write_output("device_name|unknown");
        }
    } else {
        ctx.write_output("device_name|unknown");
    }

#else
    ctx.write_output("device_name|unknown");
#endif
    return 0;
}

// ── domain action ──────────────────────────────────────────────────────────

#ifdef __linux__
int do_domain(yuzu::CommandContext& ctx) {
    // Try /etc/resolv.conf for DNS domain
    std::string domain;
    {
        std::ifstream resolv("/etc/resolv.conf");
        std::string line;
        while (std::getline(resolv, line)) {
            // "domain example.com" or "search example.com other.com"
            if (line.starts_with("domain ") || line.starts_with("search ")) {
                auto pos = line.find(' ');
                if (pos != std::string::npos) {
                    auto val_start = line.find_first_not_of(' ', pos);
                    if (val_start != std::string::npos) {
                        // For "search", take the first entry
                        auto val_end = line.find_first_of(" \t", val_start);
                        domain = line.substr(val_start, val_end == std::string::npos
                                                            ? std::string::npos
                                                            : val_end - val_start);
                    }
                }
                if (line.starts_with("domain "))
                    break; // prefer "domain" over "search"
            }
        }
    }

    if (domain.empty()) {
        domain = "N/A";
    }
    ctx.write_output(std::format("domain|{}", domain));

    // Check AD join via sssd's InfoPipe over sd-bus (rung 1) instead of
    // shelling out to `realm list`. On ANY sd-bus error/timeout/absence
    // (sssd not installed, InfoPipe not registered, no libsystemd at build
    // time), fall through unconditionally -- never treat an sd-bus failure
    // as "not joined".
    //
    // BR-011 (found in /adversarial-review, cross-checked against SSSD's own
    // docs): InfoPipe's `allowed_uids` defaults to "0 (only the root user is
    // allowed to access the InfoPipe responder)" (sssd-ifp(5)), and
    // /etc/sssd/sssd.conf ships root:root mode 0600 (sssd.io's AD-provider
    // and not-root-sssd design docs). Yuzu's own agent-privilege-model.md
    // runs the Linux agent as the unprivileged `yuzu` account with no
    // InfoPipe/D-Bus grant -- so on a stock, default-configured SSSD/AD host
    // the sd-bus call is denied AND the sssd.conf fallback can't open,
    // and a genuinely joined host would silently report "not joined". The
    // pre-migration code never had this gap: it read `realm list`'s output
    // directly (unprivileged, confirmed by do_ou's identical, still-live
    // call a few lines below). Restore that as the fallback ahead of the
    // sssd.conf read, using the same bounded-runner call site do_ou already
    // uses (device_identity/do_ou#1 in docs/agent-spawn-sink-manifest.md --
    // this is that same site, a second call from a second action, not a new
    // spawn site) rather than only the file read that shares its 0600 fate.
    bool joined = false;
    bool resolved = false;
#if defined(YUZU_HAVE_LIBSYSTEMD)
    if (auto domains = sssd_list_domains_via_sdbus()) {
        joined = !domains->empty();
        resolved = true;
    }
#endif
    if (!resolved) {
        auto realm_path = yuzu::agent::probe_tool_path({"/usr/sbin/realm", "/usr/bin/realm"});
        if (!realm_path.empty()) {
            auto res = yuzu::agent::run_bounded_subprocess(
                {realm_path, "list"},
                yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(10)});
            if (res.tool_ran && !res.timed_out && !res.output_truncated &&
                res.exit_code == 0 && !res.output.empty()) {
                joined = true;
                resolved = true;
            } else if (!res.tool_ran || res.timed_out || res.output_truncated ||
                       res.exit_code != 0) {
                spdlog::warn("device_identity: degraded shell-out (timed_out={}, "
                             "tool_ran={}, truncated={}, exit_code={}): {} list",
                             res.timed_out, res.tool_ran, res.output_truncated,
                             res.exit_code, realm_path);
            }
        }
    }
    if (!resolved) {
        std::ifstream sssd("/etc/sssd/sssd.conf");
        if (sssd.good()) {
            std::string line;
            while (std::getline(sssd, line)) {
                if (line.find("ad_domain") != std::string::npos) {
                    joined = true;
                    break;
                }
            }
        }
    }
    ctx.write_output(std::format("joined|{}", joined ? "true" : "false"));
    return 0;
}
#endif

#ifdef __APPLE__
int do_domain(yuzu::CommandContext& ctx) {
    // device_identity/do_domain#1 — dsconfigad -show, read-only, no operator
    // input; rung 2 SHIPPED FLOOR via the bounded runner instead of a raw
    // popen (docs/agent-spawn-sink-manifest.md). An OpenDirectory .mm native
    // implementation is explicitly deferred here (coordinated with a
    // parallel Wave-2 effort doing the same OpenDirectory novelty
    // elsewhere) — this ships the runner-argv floor cleanly.
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/usr/sbin/dsconfigad", "-show"},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(10)});
    // A killed-at-deadline or truncated capture can leave tool_ran=true over
    // partial/garbled text; treat that the same as a failed run (falls
    // through to the hostname-suffix fallback below) rather than trusting a
    // truncated dsconfigad parse.
    if (!res.tool_ran || res.timed_out || res.output_truncated || res.exit_code != 0) {
        spdlog::warn("device_identity: degraded shell-out (timed_out={}, tool_ran={}, "
                     "truncated={}, exit_code={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, res.exit_code,
                     "/usr/sbin/dsconfigad -show");
    }
    if (res.tool_ran && !res.timed_out && !res.output_truncated && res.exit_code == 0) {
        auto info = yuzu::device_identity::macos::parse_dsconfigad_show(res.output);
        if (info.ad_bound) {
            ctx.write_output(std::format("domain|{}", info.domain));
            ctx.write_output("joined|true");
            return 0;
        }
    }

    // Fall back to hostname domain suffix -- native gethostname() +
    // getaddrinfo(AI_CANONNAME) (rung 1) instead of popen(hostname -f).
    auto fqdn = local_fqdn();
    auto dot = fqdn.find('.');
    if (dot != std::string::npos) {
        ctx.write_output(std::format("domain|{}", fqdn.substr(dot + 1)));
    } else {
        ctx.write_output("domain|N/A");
    }
    ctx.write_output("joined|false");
    return 0;
}
#endif

#ifdef _WIN32
int do_domain(yuzu::CommandContext& ctx) {
    LPWSTR name_buf = nullptr;
    NETSETUP_JOIN_STATUS join_status{};

    auto status = NetGetJoinInformation(nullptr, &name_buf, &join_status);
    if (status == NERR_Success && name_buf) {
        // Convert wide string to narrow
        std::string domain = yuzu::win::from_wide(name_buf); // (#1681) -1 convert, NUL dropped
        NetApiBufferFree(name_buf);

        ctx.write_output(std::format("domain|{}", domain.empty() ? "N/A" : domain));
        ctx.write_output(
            std::format("joined|{}", join_status == NetSetupDomainName ? "true" : "false"));
    } else {
        ctx.write_output("domain|N/A");
        ctx.write_output("joined|false");
    }
    return 0;
}
#endif

// ── ou action ──────────────────────────────────────────────────────────────

#ifdef __linux__
int do_ou(yuzu::CommandContext& ctx) {
    // device_identity/do_ou#1 — realm list, unprivileged, no operator input;
    // rung 2 via probe_tool_path + run_bounded_subprocess instead of a raw
    // popen (docs/agent-spawn-sink-manifest.md). InfoPipe has no OU surface,
    // so (unlike do_domain's sd-bus swap) this site stays on the realm CLI.
    auto realm_path = yuzu::agent::probe_tool_path({"/usr/sbin/realm", "/usr/bin/realm"});
    std::string realm_out;
    if (!realm_path.empty()) {
        auto res = yuzu::agent::run_bounded_subprocess(
            {realm_path, "list"},
            yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(10)});
        // A killed-at-deadline or truncated capture can leave tool_ran=true
        // over partial/garbled text; treat that the same as a failed run
        // (falls through to the sssd.conf fallback below) rather than
        // risking a truncated OU match. A nonzero exit is rejected too
        // (found in /governance Gate 4, unhappy-path): `realm list` prints
        // diagnostics to stdout on some degraded/error states, so a bare
        // tool_ran/timed_out/output_truncated gate could read that text as
        // a real OU match.
        if (res.tool_ran && !res.timed_out && !res.output_truncated && res.exit_code == 0) {
            realm_out = res.output;
        } else {
            spdlog::warn("device_identity: degraded shell-out (timed_out={}, tool_ran={}, "
                         "truncated={}, exit_code={}): {} list",
                         res.timed_out, res.tool_ran, res.output_truncated, res.exit_code,
                         realm_path);
        }
    }
    // Try realm list for OU
    if (!realm_out.empty()) {
        // Look for "computer-ou:" line
        auto pos = realm_out.find("computer-ou:");
        if (pos != std::string::npos) {
            auto val_start = realm_out.find_first_not_of(" \t:", pos + 12);
            if (val_start != std::string::npos) {
                auto val_end = realm_out.find_first_of("\r\n", val_start);
                auto ou =
                    realm_out.substr(val_start, val_end == std::string::npos ? std::string::npos
                                                                             : val_end - val_start);
                ctx.write_output(std::format("ou|{}", ou));
                return 0;
            }
        }
    }

    // Try sssd.conf for ldap_default_bind_dn or krb5_realm
    std::ifstream sssd("/etc/sssd/sssd.conf");
    if (sssd.good()) {
        std::string line;
        while (std::getline(sssd, line)) {
            if (line.find("ldap_default_bind_dn") != std::string::npos) {
                auto eq = line.find('=');
                if (eq != std::string::npos) {
                    auto val = line.substr(eq + 1);
                    // Trim leading whitespace
                    auto start = val.find_first_not_of(" \t");
                    if (start != std::string::npos)
                        val = val.substr(start);
                    ctx.write_output(std::format("ou|{}", val));
                    return 0;
                }
            }
        }
    }

    ctx.write_output("ou|N/A");
    return 0;
}
#endif

#ifdef __APPLE__
int do_ou(yuzu::CommandContext& ctx) {
    // device_identity/do_ou#2 — dsconfigad -show, same call shape as
    // do_domain#1 above (separate action, separate audit-relevant call
    // site); rung 2 SHIPPED FLOOR via the bounded runner instead of raw
    // popen (docs/agent-spawn-sink-manifest.md).
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/usr/sbin/dsconfigad", "-show"},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(10)});
    // Same completeness gate as do_domain's dsconfigad call above.
    if (!res.tool_ran || res.timed_out || res.output_truncated || res.exit_code != 0) {
        spdlog::warn("device_identity: degraded shell-out (timed_out={}, tool_ran={}, "
                     "truncated={}, exit_code={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, res.exit_code,
                     "/usr/sbin/dsconfigad -show");
    }
    if (res.tool_ran && !res.timed_out && !res.output_truncated && res.exit_code == 0) {
        auto info = yuzu::device_identity::macos::parse_dsconfigad_show(res.output);
        if (!info.ou.empty()) {
            ctx.write_output(std::format("ou|{}", info.ou));
            return 0;
        }
    }
    ctx.write_output("ou|N/A");
    return 0;
}
#endif

#ifdef _WIN32
int do_ou(yuzu::CommandContext& ctx) {
    // GetComputerObjectNameA with NameFullyQualifiedDN returns the full DN,
    // e.g. "CN=WORKSTATION01,OU=Workstations,DC=corp,DC=example,DC=com"
    // We extract the OU components from the DN.
    DWORD size = 0;
    GetComputerObjectNameA(NameFullyQualifiedDN, nullptr, &size);
    if (size > 0) {
        std::string dn(size, '\0');
        if (GetComputerObjectNameA(NameFullyQualifiedDN, dn.data(), &size)) {
            dn.resize(size);
            // Extract OU= components from the DN
            // Find first OU= after the CN= prefix
            auto ou_start = dn.find("OU=");
            if (ou_start != std::string::npos) {
                ctx.write_output(std::format("ou|{}", dn.substr(ou_start)));
                return 0;
            }
        }
    }
    ctx.write_output("ou|N/A");
    return 0;
}
#endif

// ABI4 capability declarations (#2204). "device_name" is a native call on
// every OS. Wave 3 (#2380/ADR-3002 promotion): "domain"'s Linux AD-join
// check moved onto a bounded sd-bus call to sssd's InfoPipe (rung 1, no
// subprocess at all) with the sssd.conf fallback preserved unconditionally;
// "ou"'s Linux realm-list call and both macOS "domain"/"ou" dsconfigad calls
// moved onto the bounded runner (rung 2) instead of raw popen — dsconfigad
// stays at rung 2 as the SHIPPED FLOOR (an OpenDirectory .mm native
// implementation is explicitly deferred, coordinated with a parallel Wave-2
// effort), and InfoPipe has no OU surface so "ou" on Linux stays on the
// realm CLI rather than following "domain" onto sd-bus. Windows uses only
// native NetGetJoinInformation / GetComputerObjectNameA — rung 1.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "device_name",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "gethostname(3)", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "gethostname(3)", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetComputerNameExA", nullptr},
    },
    {
        /* .action      = */ "domain",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/etc/resolv.conf read + sd-bus org.freedesktop.sssd.infopipe ListDomains "
         "[fallback: run_bounded_subprocess(realm list); further fallback: "
         "/etc/sssd/sssd.conf read]",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "run_bounded_subprocess(dsconfigad -show) + native parser "
         "(device_identity_macos.hpp) [fallback: gethostname(3) + getaddrinfo(AI_CANONNAME)]",
         nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "NetGetJoinInformation", nullptr},
    },
    {
        /* .action      = */ "ou",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "run_bounded_subprocess(realm list) [fallback: /etc/sssd/sssd.conf read]", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "run_bounded_subprocess(dsconfigad -show) + native parser "
         "(device_identity_macos.hpp)",
         nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetComputerObjectNameA", nullptr},
    },
};

} // namespace

class DeviceIdentityPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "device_identity"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports device hostname, domain membership, and AD organizational unit";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"device_name", "domain", "ou", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "device_name")
            return do_device_name(ctx);
        if (action == "domain")
            return do_domain(ctx);
        if (action == "ou")
            return do_ou(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(DeviceIdentityPlugin)
