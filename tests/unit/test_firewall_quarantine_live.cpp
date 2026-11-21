/**
 * test_firewall_quarantine_live.cpp -- the BUILT firewall plugin's containment
 * actions, driven through its descriptor. Two kinds of case live here:
 *
 *  - "action boundary" cases, tagged [agent][firewall_quarantine]: they run in the
 *    normal agent suite on every OS, need no privilege and never reach the host
 *    firewall -- each one dispatches along a path the plugin refuses (or answers)
 *    BEFORE its first OS call, over a fresh KV store. They prove the action
 *    routing, parameter checks, record read and result emission of the real
 *    plugin, which the pure-core tests cannot. Every `quarantine` dispatch in
 *    them carries a probe_target that does not parse, so none can reach the OS.
 *  - live cases, tagged [.][firewall_quarantine_live]: HIDDEN, so the shard
 *    partition never selects them; they change the firewall of the machine they
 *    run on and need root / Administrator, or the agent account (see "Who runs
 *    it"). The rest of this comment is about those.
 *
 * Running the live tag WITHOUT YUZU_FIREWALL_QUARANTINE_LIVE=1 skips every case
 * and Catch2 then exits 4 (all tests skipped), not 0: a harness that checks for
 * rc == 0 must set the variable first (rc 4 means the environment is unset, or an
 * OS filter matched nothing).
 *
 * Who runs it: root / Administrator, OR the agent account after
 * `scripts/install-agent-user.sh --check` is clean on the host. The agent account reaches the
 * host firewall the way the agent does, through the sudo grants the installer wrote (`sudo -n --`
 * with the fixed lines and the root-owned helper), so a non-root run proves those grants work
 * and every read below goes through them; the Linux snapshot is the helper's `snapshot` word,
 * and the pf reads are the exact granted pfctl lines. Two things a non-root account cannot do
 * (`pfctl -d`, a read of the nftables dump over netlink) are skipped or answered honestly, with
 * the reason named. The environment is passed explicitly with `env` (`sudo -u <account> env
 * NAME=value ... yuzu_agent_tests`): sudo-rs ignores -E.
 *
 * The control endpoint (YUZU_FQ_SERVER_ADDRESS) must be on ANOTHER host. A containment whose own
 * control endpoint is the host itself is refused (`refused|self_host`), so a one-host run ends
 * there by design; the case for that refusal runs with this host's own address.
 *
 * Run (on a disposable or operator-attended host):
 *   YUZU_FIREWALL_QUARANTINE_LIVE=1 \
 *   YUZU_FQ_SERVER_ADDRESS=<ip:port reachable control endpoint on another host> \
 *   YUZU_FQ_PROBE_TARGET=<ip:port reachable BEFORE the quarantine> \
 *   [YUZU_FQ_STREAM_TARGET=<ip:port of an HTTP server, for the pre-established-stream case>] \
 *     (the control-stream case opens a stream to YUZU_FQ_SERVER_ADDRESS the same way and
 *     SKIPs when that endpoint is not an HTTP server; both stream cases drain the first reply
 *     to its Content-Length and SKIP when the server does not frame its reply, or closes after
 *     it) \
 *   [YUZU_FQ_OPERATOR_EXCEPTION=<addr[:port][/proto][/dir], e.g. 10.0.0.5:22/tcp/in>] \
 *   yuzu_agent_tests '[firewall_quarantine_live]'
 *
 * A host that is quarantined over SSH loses the session unless the operator's
 * source is passed as YUZU_FQ_OPERATOR_EXCEPTION. A 120 s watchdog releases the
 * quarantine if a case hangs (the standalone harness has no trigger engine, so
 * the plugin's own TTL trigger cannot fire here).
 *
 * "Restored" is an identity comparison of two readable snapshots (firewall_restore_compare.hpp):
 * every read that did not complete is written `[failed]` whoever ran it, so a case can never pass
 * on two failed reads, and an unreadable baseline fails the case before anything is applied.
 *
 * Loads the BUILT plugin (firewall.dll / firewall.so / firewall.dylib) the way
 * the agent does and drives it through LocalDispatcher. With
 * YUZU_FIREWALL_QUARANTINE_LIVE=1 set, a plugin that cannot be loaded is a hard
 * FAILURE, never a skip: a live run that silently tested nothing is the failure
 * mode this guard exists for.
 *
 * macOS: the pf sub-anchor leg runs for real here and ONLY here: this TU is
 * hidden and gated on YUZU_FIREWALL_QUARANTINE_LIVE=1, and the live capture is
 * taken on a disposable macOS VM (never on a shared build host), because the
 * apply flushes every pf state on the machine and the cases below switch pf off
 * and on behind the plugin's back to prove the repair and the token handling.
 */

#include <catch2/catch_test_macros.hpp>

#include "firewall_parsers.hpp"
#include "firewall_quarantine_parsers.hpp"
#include "firewall_restore_compare.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/network_interfaces.hpp>
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>

#include <icmp_probe.hpp>
#ifndef _WIN32
#include <sudo_argv.hpp> // the agent's own `sudo -n --` wrapper (a no-op for root)
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace fq = yuzu::firewall::quarantine;
namespace fr = yuzu::test::fwrestore;
namespace fs = std::filesystem;

namespace {

using namespace std::chrono_literals;

[[nodiscard]] std::string env_or(const char* name) {
    const char* v = std::getenv(name);
    return v ? v : "";
}

[[nodiscard]] bool live_enabled() { return env_or("YUZU_FIREWALL_QUARANTINE_LIVE") == "1"; }

#if defined(_WIN32)
constexpr const char* kPluginFile = "firewall.dll";
#elif defined(__APPLE__)
constexpr const char* kPluginFile = "firewall.dylib";
#else
constexpr const char* kPluginFile = "firewall.so";
#endif

/// The built plugin file, wherever this test binary was started from; nullopt when
/// no candidate exists (a partial build with no agent plugins).
std::optional<fs::path> find_firewall_plugin_file() {
    std::vector<fs::path> dirs{
        fs::path{"agents"} / "plugins" / "firewall",
        fs::path{".."} / "agents" / "plugins" / "firewall",
        fs::path{"builddir"} / "agents" / "plugins" / "firewall",
    };
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        dirs.push_back(fs::path{root} / "agents" / "plugins" / "firewall");
    for (const char* os_dir : {"build-macos", "build-linux", "build-windows"})
        dirs.push_back(fs::path{os_dir} / "agents" / "plugins" / "firewall");
    for (const auto& d : dirs) {
        std::error_code ec;
        const auto candidate = d / kPluginFile;
        if (fs::exists(candidate, ec) && !ec)
            return candidate;
    }
    return std::nullopt;
}

std::expected<yuzu::agent::PluginHandle, yuzu::agent::LoadError> load_firewall() {
    if (const auto file = find_firewall_plugin_file())
        return yuzu::agent::PluginHandle::load(*file);
    return yuzu::agent::PluginHandle::load(fs::path{"agents"} / "plugins" / "firewall" / kPluginFile);
}

[[nodiscard]] std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> rows;
    std::size_t pos = 0;
    while (pos < captured.size()) {
        const auto nl = captured.find('\n', pos);
        auto line = captured.substr(pos, nl == std::string::npos ? nl : nl - pos);
        if (!line.empty())
            rows.push_back(std::move(line));
        if (nl == std::string::npos)
            break;
        pos = nl + 1;
    }
    return rows;
}

[[nodiscard]] bool has_row(const std::string& captured, const std::string& row) {
    for (const auto& r : rows_of(captured))
        if (r == row)
            return true;
    return false;
}

[[nodiscard]] bool has_prefix(const std::string& captured, const std::string& prefix) {
    for (const auto& r : rows_of(captured))
        if (r.rfind(prefix, 0) == 0)
            return true;
    return false;
}

/// The remainder of the first `<key>|...` row, or nullopt when there is none.
[[nodiscard]] std::optional<std::string> row_value(const std::string& captured, const std::string& key) {
    const auto prefix = key + "|";
    for (const auto& r : rows_of(captured))
        if (r.rfind(prefix, 0) == 0)
            return r.substr(prefix.size());
    return std::nullopt;
}

[[nodiscard]] std::size_t count_prefixed(const std::string& captured, const std::string& prefix) {
    std::size_t n = 0;
    for (const auto& r : rows_of(captured))
        n += r.rfind(prefix, 0) == 0 ? 1 : 0;
    return n;
}

[[nodiscard, maybe_unused]] bool is_integer(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
}

/// The number of non-empty lines of a snapshot's section, or nullopt when it has none.
[[nodiscard, maybe_unused]] std::optional<std::size_t> section_lines(const std::string& snapshot,
                                                                     std::string_view name) {
    const auto body = fr::section(snapshot, name);
    if (!body)
        return std::nullopt;
    return rows_of(*body).size();
}

/// Runs a tool and returns the whole result, stderr merged unless asked otherwise. A caller that
/// must tell "it ran and printed nothing" from "it did not run, timed out, was clipped or failed"
/// needs the exit code and the flags, which capture() drops.
[[nodiscard]] yuzu::agent::SubprocessResult capture_result(const std::vector<std::string>& argv,
                                                           std::chrono::milliseconds deadline = 60s,
                                                           bool merge_stderr = true) {
    return yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = deadline, .merge_stderr = merge_stderr});
}

/// Runs a tool and returns its combined output ("" when it did not run). For a caller that only
/// needs the text; a read the verdict depends on goes through capture_result().
[[nodiscard, maybe_unused]] std::string capture(const std::vector<std::string>& argv) {
    auto res = capture_result(argv);
    return res.tool_ran ? res.output : std::string{};
}

/// A privileged tool run the way the agent account runs it: `sudo -n --` in front of one of the
/// granted lines or the helper, and nothing at all when this process is root.
[[nodiscard, maybe_unused]] std::vector<std::string> harness_sudo(std::vector<std::string> argv) {
#ifdef _WIN32
    return argv;
#else
    return yuzu::shared::sudo_wrap(std::move(argv));
#endif
}

[[nodiscard, maybe_unused]] bool running_as_root() {
#ifdef _WIN32
    return true; // the live Windows run is Administrator
#else
    return ::geteuid() == 0;
#endif
}

#ifdef _WIN32
/// `netsh advfirewall firewall show rule` prints `Enabled:  Yes|No`; the column
/// padding varies, so look at the value after the label, not at the spacing.
[[nodiscard]] std::optional<bool> netsh_rule_enabled(const std::string& text) {
    const auto at = text.find("Enabled:");
    if (at == std::string::npos)
        return std::nullopt;
    const auto eol = text.find('\n', at);
    const auto line = text.substr(at, eol == std::string::npos ? eol : eol - at);
    return line.find("Yes") != std::string::npos;
}
#endif

#if defined(_WIN32)
constexpr fr::Os kThisOs = fr::Os::win;
#elif defined(__APPLE__)
constexpr fr::Os kThisOs = fr::Os::mac;
#else
constexpr fr::Os kThisOs = fr::Os::lin;
#endif

/// A snapshot whose one read failed: it can never compare equal to anything, itself included.
[[nodiscard, maybe_unused]] std::string failed_snapshot() {
    std::string out;
    fr::write_section(out, "snapshot", false, "");
    fr::finish(out);
    return out;
}

/// The anchor read, decided by fr::pf_anchor_absent from the subprocess result.
[[nodiscard, maybe_unused]] bool pf_anchor_absent(bool main_reads_complete,
                                                  const yuzu::agent::SubprocessResult& anchor) {
    return fr::pf_anchor_absent(main_reads_complete,
                                anchor.tool_ran && !anchor.timed_out && !anchor.output_truncated,
                                anchor.exit_code, anchor.output);
}

/// The host firewall as sectioned text (firewall_restore_compare.hpp), for the restore check.
/// Every section is written by fr::write_section from the completeness of ITS read, so a read that
/// did not run, timed out, was clipped or exited non-zero is `[failed]` here whoever ran it.
[[nodiscard]] std::string firewall_snapshot() {
#if defined(_WIN32)
    // One PowerShell command, ASCII only, as -EncodedCommand so no quoting rule can change it. The
    // script sets $ErrorActionPreference = 'Stop' first: a failing cmdlet exits non-zero and the
    // whole read is `[failed]`, never a shorter list. Standard error is NOT merged into the output.
    const auto res = capture_result(
        {"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoProfile", "-NonInteractive",
         "-EncodedCommand", fr::utf16le_base64(fr::windows_snapshot_script())},
        180s, /*merge_stderr=*/false);
    return yuzu::firewall::subprocess_complete(res) ? res.output : failed_snapshot();
#elif defined(__linux__)
    if (!running_as_root()) {
        // The agent account: the helper's read-only `snapshot` word, through the sudo grant the
        // installer wrote. Its text is the snapshot, used only when the call completed.
        // stderr is NOT merged: classic sudo's `unable to resolve host` warning would otherwise land
        // ahead of the first header, and the helper already drops its tools' stderr.
        const auto res = capture_result(harness_sudo({std::string{fq::kFwHelperPath}, "snapshot"}), 60s,
                                        /*merge_stderr=*/false);
        return yuzu::firewall::subprocess_complete(res) ? res.output : failed_snapshot();
    }
    // Root: the same three tools with the helper's labels and arguments. A tool that is not
    // executable is `[absent]`.
    struct Tool {
        std::string_view label;
        std::string_view path;
        std::vector<std::string> args;
    };
    const Tool tools[] = {{fr::label::kNft, fq::kNftPath, {"-a", "list", "ruleset"}},
                          {fr::label::kIptables, fq::kIptablesPath, {"-S"}},
                          {fr::label::kIp6tables, fq::kIp6tablesPath, {"-S"}}};
    std::string out;
    for (const auto& t : tools) {
        if (::access(std::string{t.path}.c_str(), X_OK) != 0) {
            fr::write_absent(out, t.label);
            continue;
        }
        std::vector<std::string> argv{std::string{t.path}};
        argv.insert(argv.end(), t.args.begin(), t.args.end());
        const auto res = capture_result(argv);
        fr::write_section(out, t.label, yuzu::firewall::subprocess_complete(res), res.output);
    }
    fr::finish(out);
    return out;
#else
    // macOS: the four granted pfctl lines (a root run needs no sudo). The Status line is recorded
    // raw, never as a derived Enabled/Disabled: a state that could not be read has no such line,
    // and the snapshot is then unreadable.
    const auto pf = [](std::vector<std::string> args) {
        args.insert(args.begin(), "/sbin/pfctl");
        return capture_result(harness_sudo(std::move(args)));
    };
    std::string out;
    const auto rules = pf({"-s", "rules"});
    fr::write_section(out, fr::label::kPfRules, yuzu::firewall::subprocess_complete(rules), rules.output);
    const auto info = pf({"-s", "info"});
    fr::write_section(out, fr::label::kPfStatus, yuzu::firewall::subprocess_complete(info),
                      fr::pf_status_line(info.output));
    const auto refs = pf({"-s", "References"});
    fr::write_section(out, fr::label::kPfReferences, yuzu::firewall::subprocess_complete(refs), refs.output);
    // The yuzu anchor is simply not loaded on a clean host and after a release: pfctl then exits
    // non-zero for it, which is an EMPTY section (the plugin reads it as "no anchor" the same way),
    // never `[failed]`. Anything else that did not complete stays `[failed]`.
    const auto anchor = pf({"-a", std::string{fq::kPfAnchor}, "-s", "rules"});
    const bool main_complete =
        yuzu::firewall::subprocess_complete(rules) && yuzu::firewall::subprocess_complete(info);
    if (yuzu::firewall::subprocess_complete(anchor))
        fr::write_section(out, fr::label::kYuzuAnchor, true, anchor.output);
    else
        fr::write_section(out, fr::label::kYuzuAnchor, pf_anchor_absent(main_complete, anchor), "");
    fr::finish(out);
    return out;
#endif
}

/// The snapshot taken BEFORE a case changes anything: it must be readable, or the case stops
/// here (a restore check against an unreadable baseline proves nothing).
[[nodiscard]] std::string baseline_snapshot() {
    auto text = firewall_snapshot();
    INFO("baseline snapshot:\n" << text.substr(0, 2000));
    REQUIRE(fr::readable(kThisOs, text));
    return text;
}

/// The restore check: the baseline must be readable, the snapshot taken now must be readable, and
/// nothing may differ (counters and handles normalised away, Store package churn reported and
/// never failing). Replaces every byte-for-byte comparison of two dumps.
void check_restored(const std::string& before) {
    REQUIRE(fr::readable(kThisOs, before));
    const auto verdict = fr::compare(kThisOs, before, firewall_snapshot());
    INFO(fr::describe(verdict));
    CHECK(verdict.restored);
}

/// A read a verdict depends on: its output only when the tool ran to completion (it started, was
/// not killed or clipped, and exited 0). capture() cannot say that: it merges stderr and drops the
/// exit code, so sudo's refusal or a tool's error text would pass for a listing.
[[nodiscard, maybe_unused]] std::optional<std::string> read_complete(const std::vector<std::string>& argv) {
    const auto res = capture_result(argv);
    if (!yuzu::firewall::subprocess_complete(res))
        return std::nullopt;
    return res.output;
}

/// The rules the containment put in force, as text, for "this address is (not) in the live
/// ruleset". Read the way the agent account reads them: our nft table through the granted
/// `nft list table` line, the iptables generation through the helper, our pf anchor through the
/// granted anchor line. Only reads that completed contribute; nullopt when none did.
[[nodiscard, maybe_unused]] std::optional<std::string> contained_rules_text() {
#if defined(__APPLE__)
    return read_complete(harness_sudo({"/sbin/pfctl", "-a", std::string{fq::kPfAnchor}, "-s", "rules"}));
#elif defined(__linux__)
    std::optional<std::string> out;
    const auto keep = [&out](const std::optional<std::string>& part) {
        if (part)
            out = out.value_or(std::string{}) + *part;
    };
    keep(read_complete(harness_sudo(fq::nft_list_argv())));
    for (const auto tool : {fq::kIptablesPath, fq::kIp6tablesPath}) {
        const fq::Argv plan{std::string{tool}, "-S"};
        if (running_as_root()) {
            keep(read_complete(plan));
        } else if (const auto helper = fq::iptables_helper_argv(plan)) {
            keep(read_complete(harness_sudo(*helper)));
        }
    }
    return out;
#else
    auto text = firewall_snapshot(); // the failed form of a read is an unreadable snapshot
    if (!fr::readable(kThisOs, text))
        return std::nullopt;
    return text;
#endif
}

/// The listed rules mention `needle`, or do not, with the containment's own listing known to have
/// been read: an absence proves nothing from a read that failed or that listed something else.
/// Every caller runs while the host is contained, so a completed read must show the containment.
void check_listed(std::string_view needle, bool expect_present) {
    const auto text = contained_rules_text();
    REQUIRE(text.has_value()); // at least one read of the containment's listing completed
#if defined(__linux__)
    // The nft table or an iptables generation chain is the containment itself.
    REQUIRE((text->find(fq::kNftTable) != std::string::npos ||
             text->find(fq::kIptablesChainPrefix) != std::string::npos));
#endif
    CHECK((text->find(needle) != std::string::npos) == expect_present);
}

#if defined(__linux__)
/// Another actor deleting our nft table: the granted `nft delete table` line.
void tamper_delete_nft_table() { (void)capture(harness_sudo(fq::nft_delete_argv())); }

/// Another actor removing our iptables jump: through the helper, or the tool itself as root.
void tamper_remove_ipt_jump(std::uint32_t generation) {
    const fq::Argv plan{std::string{fq::kIptablesPath}, "-D", "INPUT", "-j", fq::ipt_chain(generation)};
    if (running_as_root())
        (void)capture(plan);
    else if (const auto helper = fq::iptables_helper_argv(plan))
        (void)capture(harness_sudo(*helper));
}
#endif

#if defined(__APPLE__)
/// Another actor emptying our pf anchor (`what` is `rules` or `nat`): the granted anchor flushes.
void tamper_flush_anchor(const char* what) {
    (void)capture(harness_sudo({"/sbin/pfctl", "-a", std::string{fq::kPfAnchor}, "-F", what}));
}
#endif

// ── a tiny portable TCP client (probe + pre-established stream) ─────────────

#ifdef _WIN32
struct WinsockOnce {
    WSADATA data{};
    bool ok = WSAStartup(MAKEWORD(2, 2), &data) == 0;
};
[[nodiscard]] bool net_init() {
    static const WinsockOnce w;
    return w.ok;
}
using SockT = SOCKET;
constexpr SockT kBadSock = INVALID_SOCKET;
void close_sock(SockT s) { ::closesocket(s); }
#else
[[nodiscard]] bool net_init() { return true; }
using SockT = int;
constexpr SockT kBadSock = -1;
void close_sock(SockT s) { ::close(s); }
#endif

[[nodiscard]] std::optional<std::pair<std::string, int>> split_endpoint(const std::string& s) {
    const auto ip = fq::parse_probe_target(s);
    if (!ip)
        return std::nullopt;
    return std::make_pair(fq::format_ip(ip->ip), ip->port);
}

/// The address and port of an `ip:port` endpoint, or nullopt when it does not parse or resolve.
[[nodiscard]] std::optional<yuzu::shared::Resolved> resolve_endpoint(const std::string& endpoint) {
    const auto ep = split_endpoint(endpoint);
    if (!ep || !net_init())
        return std::nullopt;
    auto dst = yuzu::shared::resolve_first(ep->first, AF_UNSPEC);
    if (dst)
        yuzu::shared::set_port(*dst, ep->second);
    return dst;
}

/// One TCP connect to ip:port with a bounded wait; the tri-state outcome.
[[nodiscard]] fq::ProbeOutcome probe(const std::string& endpoint, int timeout_ms = 3000) {
    const auto dst = resolve_endpoint(endpoint);
    if (!dst)
        return fq::ProbeOutcome::timeout;
    const auto r = yuzu::shared::tcp_sample(*dst, timeout_ms);
    return r.rtt_ms ? fq::ProbeOutcome::connected
                    : (r.refused ? fq::ProbeOutcome::refused : fq::ProbeOutcome::timeout);
}

/// The address this host would use to reach `endpoint`: a UDP socket connected to it, asked for its
/// own name. A UDP connect sends nothing (it only picks the route), so this learns the address
/// without touching the network. nullopt when it cannot be learned.
[[nodiscard]] std::optional<std::string> own_address_toward(const std::string& endpoint) {
    const auto dst = resolve_endpoint(endpoint);
    if (!dst)
        return std::nullopt;
    yuzu::shared::SocketGuard sock{::socket(dst->family, SOCK_DGRAM, IPPROTO_UDP)};
    if (!sock.ok())
        return std::nullopt;
    std::optional<std::string> out;
    if (::connect(sock.s, reinterpret_cast<const sockaddr*>(&dst->addr), dst->addr_len) == 0) {
        sockaddr_storage name{};
#ifdef _WIN32
        int len = sizeof(name);
#else
        socklen_t len = sizeof(name);
#endif
        if (::getsockname(sock.s, reinterpret_cast<sockaddr*>(&name), &len) == 0) {
            char text[INET6_ADDRSTRLEN]{};
            if (name.ss_family == AF_INET &&
                ::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&name)->sin_addr, text, sizeof(text)))
                out = text;
            else if (name.ss_family == AF_INET6 &&
                     ::inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&name)->sin6_addr, text,
                                 sizeof(text)))
                out = text;
        }
    }
    return out;
}

/// What the bytes read so far say about one HTTP reply (headers to CRLFCRLF, a case-insensitive
/// Content-Length, the body length reached). `unframed` covers a reply whose length the client
/// cannot know, and a server that closes after it: no Content-Length, an HTTP/1.0 status line
/// without `Connection: keep-alive`, any `Connection: close`. A server that closes after its reply
/// proves nothing about whether the stream survived, so such a reply cannot back the stream cases.
enum class HttpReply { need_more, complete, unframed };

[[nodiscard]] HttpReply http_reply_state(std::string_view buf) {
    const auto end = buf.find("\r\n\r\n");
    if (end == std::string_view::npos)
        return HttpReply::need_more;
    const auto head = buf.substr(0, end);
    const auto body_len = buf.size() - (end + 4);

    const auto lower = [](std::string_view in) {
        std::string out;
        for (const char c : in)
            out += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        return out;
    };

    const auto status_end = head.find("\r\n");
    const bool http10 = head.substr(0, status_end).starts_with("HTTP/1.0");
    std::optional<std::size_t> content_length;
    bool bad_length = false, keep_alive = false, close = false;
    std::size_t pos = status_end == std::string_view::npos ? head.size() : status_end + 2;
    while (pos < head.size()) {
        const auto next = head.find("\r\n", pos);
        const auto line = head.substr(pos, next == std::string_view::npos ? next : next - pos);
        pos = next == std::string_view::npos ? head.size() : next + 2;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        const auto name = lower(fq::detail::trim(line.substr(0, colon)));
        const auto value = lower(fq::detail::trim(line.substr(colon + 1)));
        if (name == "content-length") {
            if (value.empty() || value.size() > 15 ||
                value.find_first_not_of("0123456789") != std::string::npos)
                bad_length = true;
            else
                content_length = static_cast<std::size_t>(std::stoull(value));
        } else if (name == "connection") {
            close = close || value.find("close") != std::string::npos;
            keep_alive = keep_alive || value.find("keep-alive") != std::string::npos;
        }
    }
    if (close || (http10 && !keep_alive) || bad_length || !content_length)
        return HttpReply::unframed;
    return body_len >= *content_length ? HttpReply::complete : HttpReply::need_more;
}

/// How the first request on a kept stream went.
enum class FirstReply { complete, unframed, silent, ended };

/// What a request on a stream that predates the apply got: any byte back, nothing before the
/// receive timeout, or the stream ending (EOF, a reset or a failed send).
enum class StreamReply { answered, silent, ended };

/// A kept-open HTTP/1.1 connection: proves whether an ESTABLISHED stream survives.
class KeptStream {
public:
    KeptStream() = default;
    KeptStream(const KeptStream&) = delete;
    KeptStream& operator=(const KeptStream&) = delete;
    ~KeptStream() {
        if (s_ != kBadSock)
            close_sock(s_);
    }
    [[nodiscard]] bool open(const std::string& endpoint) {
        const auto dst = resolve_endpoint(endpoint);
        if (!dst)
            return false;
        s_ = ::socket(dst->family, SOCK_STREAM, IPPROTO_TCP);
        if (s_ == kBadSock)
            return false;
#if defined(SO_NOSIGPIPE)
        const int on = 1; // a send on a stream the peer ended is a failed send, not a signal
        ::setsockopt(s_, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
        set_timeouts(5000);
        return ::connect(s_, reinterpret_cast<const sockaddr*>(&dst->addr), dst->addr_len) == 0;
    }

    /// Sends one request and reads the reply to its Content-Length, so nothing of it is left in
    /// the socket to be mistaken for a later answer. `unframed` when the server's reply cannot
    /// back a stream case (see http_reply_state); `silent` when no complete reply came in time.
    [[nodiscard]] FirstReply first_reply(int wait_ms) {
        set_timeouts(wait_ms);
        if (!send_request())
            return FirstReply::ended;
        std::string got;
        char buf[1024];
        for (;;) {
            const auto n = ::recv(s_, buf, static_cast<int>(sizeof(buf)), 0);
            if (n > 0) {
                got.append(buf, static_cast<std::size_t>(n));
                switch (http_reply_state(got)) {
                case HttpReply::complete:
                    return FirstReply::complete;
                case HttpReply::unframed:
                    return FirstReply::unframed;
                case HttpReply::need_more:
                    break;
                }
                if (got.size() > 65536)
                    return FirstReply::unframed;
                continue;
            }
            if (n == 0) {
                end_reason_ = "the peer closed the stream";
                return FirstReply::ended;
            }
            return was_timeout() ? FirstReply::silent : ended_by_error();
        }
    }

    /// Sends one more request on the same stream and reports what came back.
    [[nodiscard]] StreamReply request(int wait_ms) {
        set_timeouts(wait_ms);
        if (!send_request())
            return StreamReply::ended;
        char buf[256];
        const auto n = ::recv(s_, buf, static_cast<int>(sizeof(buf)), 0);
        if (n > 0)
            return StreamReply::answered;
        if (n == 0) {
            end_reason_ = "the peer closed the stream";
            return StreamReply::ended;
        }
        if (was_timeout())
            return StreamReply::silent;
        (void)ended_by_error();
        return StreamReply::ended;
    }

    /// Why the last call ended the stream, for the log.
    [[nodiscard]] const std::string& end_reason() const noexcept { return end_reason_; }

private:
    [[nodiscard]] bool send_request() {
        static const char kReq[] = "GET / HTTP/1.1\r\nHost: yuzu-live\r\nConnection: keep-alive\r\n\r\n";
#if defined(MSG_NOSIGNAL)
        constexpr int kFlags = MSG_NOSIGNAL;
#else
        constexpr int kFlags = 0;
#endif
        if (::send(s_, kReq, static_cast<int>(sizeof(kReq) - 1), kFlags) > 0)
            return true;
        end_reason_ = "the send failed (" + last_error_text() + ")";
        return false;
    }
    [[nodiscard]] static std::string last_error_text() {
#ifdef _WIN32
        return "winsock error " + std::to_string(::WSAGetLastError());
#else
        return "errno " + std::to_string(errno);
#endif
    }
    [[nodiscard]] static bool was_timeout() {
#ifdef _WIN32
        return ::WSAGetLastError() == WSAETIMEDOUT;
#else
        return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
    }
    FirstReply ended_by_error() {
        end_reason_ = "the receive failed (" + last_error_text() + ")";
        return FirstReply::ended;
    }
    void set_timeouts(int ms) {
#ifdef _WIN32
        const DWORD t = static_cast<DWORD>(ms);
        ::setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
        ::setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
#else
        timeval tv{ms / 1000, (ms % 1000) * 1000};
        ::setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    }
    SockT s_ = kBadSock;
    std::string end_reason_;
};

/// Releases a quarantine the test left behind if a case hangs or throws: the
/// standalone harness has no trigger engine, so the plugin's TTL cannot do it.
class Watchdog {
public:
    template <class Fn> explicit Watchdog(std::chrono::seconds after, Fn&& release)
        : thread_([this, after, release = std::forward<Fn>(release)] {
              std::unique_lock lk(m_);
              if (!cv_.wait_for(lk, after, [this] { return done_; }))
                  release();
          }) {}
    ~Watchdog() {
        {
            std::lock_guard lk(m_);
            done_ = true;
        }
        cv_.notify_all();
        thread_.join();
    }
    Watchdog(const Watchdog&) = delete;
    Watchdog& operator=(const Watchdog&) = delete;

private:
    std::mutex m_;
    std::condition_variable cv_;
    bool done_ = false;
    std::thread thread_;
};

/// The plugin, loaded and init()-ed over a real KV store, the way the agent does.
/// Teardown shuts the plugin down and nothing else: the action-boundary cases use
/// this directly because they must never reach the OS (a `release` here would).
struct PluginRig {
    yuzu::test::TempDbFile db{"yuzu_test_fq_"};
    yuzu::test::TempDir data_dir{"yuzu_test_fq_data_"}; // agent.data_dir: the private staging dir lives here
    std::optional<yuzu::agent::KvStore> kv;
    std::optional<yuzu::agent::PluginHandle> plugin;
    std::unique_ptr<yuzu::agent::StandalonePluginContext> ctx;
    yuzu::agent::LocalDispatcher dispatcher;

    PluginRig(const std::string& server_address, const std::string& resolved_ip) {
        std::error_code mk_ec;
        fs::create_directories(data_dir.path, mk_ec);
        REQUIRE_FALSE(mk_ec);
        auto opened = yuzu::agent::KvStore::open(db.path);
        REQUIRE(opened.has_value());
        kv.emplace(std::move(*opened));
        auto loaded = load_firewall();
        // Hard FAIL, not a skip: with the live flag set a missing plugin means the run tested nothing.
        REQUIRE(loaded.has_value());
        plugin.emplace(std::move(*loaded));
        ctx = std::make_unique<yuzu::agent::StandalonePluginContext>(
            "firewall",
            std::unordered_map<std::string, std::string>{
                {"agent.server_address", server_address},
                {"agent.server_address_resolved", resolved_ip},
                {"agent.data_dir", data_dir.path.string()}},
            &*kv);
        REQUIRE(plugin->descriptor()->init(ctx->get()) == 0);
    }
    ~PluginRig() {
        if (plugin && ctx)
            plugin->descriptor()->shutdown(ctx->get());
    }
    PluginRig(const PluginRig&) = delete;
    PluginRig& operator=(const PluginRig&) = delete;

    /// Re-runs the plugin's init() the way an agent restart does.
    void restart() {
        plugin->descriptor()->shutdown(ctx->get());
        REQUIRE(plugin->descriptor()->init(ctx->get()) == 0);
    }
    yuzu::agent::LocalDispatcher::Result
    run(const char* action, std::vector<std::pair<std::string, std::string>> params = {}) {
        std::vector<YuzuParam> raw;
        raw.reserve(params.size());
        for (const auto& [k, v] : params)
            raw.push_back({k.c_str(), v.c_str()});
        return dispatcher.run(plugin->descriptor(), action, raw);
    }
    [[nodiscard]] std::optional<fq::QuarantineState> record() {
        auto v = kv->get("firewall", std::string{fq::kStateKey});
        return v ? fq::parse_state(*v) : std::nullopt;
    }
    void put_record(const fq::QuarantineState& s) {
        REQUIRE(kv->set("firewall", std::string{fq::kStateKey}, fq::serialize_state(s)));
    }
    /// `status|<token>` for a containment that is in force, `active` or `active_unproven`.
    /// This harness (StandalonePluginContext) has no trigger engine, so the repair trigger
    /// can never register and a contained host answers `partial|repair_unregistered` where
    /// the daemon answers `active`: the containment is what `active` says, plus the
    /// unregistered self-check. That one reason is accepted and read back to the verdict the
    /// record's own proof gives (`verified...` is `active`, anything else `active_unproven`);
    /// every other `partial` is a failure here, as it is everywhere.
    [[nodiscard]] bool has_status(const std::string& captured, std::string_view token) {
        if (has_row(captured, "status|" + std::string{token}))
            return true;
        if (!has_row(captured, "status|partial|repair_unregistered"))
            return false;
        const auto rec = record();
        return rec && token == (rec->last_verify.starts_with("verified") ? "active" : "active_unproven");
    }
};

/// The live rig: releases whatever a case left applied, then shuts the plugin down.
struct LiveRig : PluginRig {
    using PluginRig::PluginRig;
    ~LiveRig() {
        if (plugin && ctx)
            (void)run("release");
    }
};

struct LiveEnv {
    std::string server = env_or("YUZU_FQ_SERVER_ADDRESS");
    std::string probe_target = env_or("YUZU_FQ_PROBE_TARGET");
    std::string stream_target = env_or("YUZU_FQ_STREAM_TARGET");
    std::string operator_exception = env_or("YUZU_FQ_OPERATOR_EXCEPTION");

    [[nodiscard]] std::string server_ip() const { return yuzu::agent::extract_server_host(server); }
    [[nodiscard]] bool complete() const { return !server.empty() && !probe_target.empty(); }
    [[nodiscard]] std::vector<std::pair<std::string, std::string>>
    quarantine_params(bool with_probe = true) const {
        std::vector<std::pair<std::string, std::string>> p;
        if (with_probe)
            p.emplace_back("probe_target", probe_target);
        if (!operator_exception.empty())
            p.emplace_back("exceptions", operator_exception);
        return p;
    }
};

/// Common gate for every live case.
#define LIVE_OR_SKIP(env)                                                                          \
    if (!live_enabled())                                                                           \
        SKIP("set YUZU_FIREWALL_QUARANTINE_LIVE=1 to run against this host's firewall");           \
    LiveEnv env;                                                                                   \
    if (!env.complete())                                                                           \
        FAIL("YUZU_FQ_SERVER_ADDRESS and YUZU_FQ_PROBE_TARGET are required under "                 \
             "YUZU_FIREWALL_QUARANTINE_LIVE=1")

/// Is the built plugin in this tree? Under `meson test` (MESON_BUILD_ROOT set) the
/// agent shards depend on the plugin build, so a missing file is a defect and FAILS:
/// a green skip there would let a partial build pass the action-boundary cases without
/// running one. A bare run of the test binary outside meson has no such guarantee and
/// skips, like the neighbouring local-dispatcher tests.
[[nodiscard]] bool firewall_plugin_built() {
    if (!find_firewall_plugin_file()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("firewall plugin not found under MESON_BUILD_ROOT: the agent shards depend on "
                 "its build, so it must exist");
        return false;
    }
    // The file is THERE: a load failure is a defect, never a green skip.
    const auto loaded = load_firewall();
    REQUIRE(loaded.has_value());
    return true;
}

#define PLUGIN_RIG_AT_OR_RETURN(rig, server, resolved)                                             \
    if (!firewall_plugin_built()) {                                                                \
        WARN("firewall plugin not found in the build tree -- skipping (build with "                \
             "-Dbuild_agent=true)");                                                               \
        SUCCEED();                                                                                 \
        return;                                                                                    \
    }                                                                                              \
    PluginRig rig(server, resolved)

#define PLUGIN_RIG_OR_RETURN(rig) PLUGIN_RIG_AT_OR_RETURN(rig, "203.0.113.7:50051", "203.0.113.7")

/// A refusal as the plugin reports it: rc 1, `status|refused|<reason>` plus the
/// `refused|<reason>` row, and the typed result UNAVAILABLE / PARTIAL.
void check_refused(const yuzu::agent::LocalDispatcher::Result& r, const std::string& reason) {
    INFO(r.captured);
    CHECK(r.rc == 1);
    CHECK(has_row(r.captured, "status|refused|" + reason));
    CHECK(has_row(r.captured, "refused|" + reason));
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "firewall:refused");
}

} // namespace

// ── the built plugin's action boundary: runs in the normal suite, never reaches the OS ──
//
// Every dispatch below is refused (or answered) before the plugin's first call
// into the host firewall: the checks precede the OS leg's construction, or the
// record they read is absent. The success and failure DECISIONS of an update are
// pinned on the pure core (test_firewall_quarantine_parsers.cpp); what only the
// built plugin can show is that the action is routed, its parameters are checked,
// the KV record is read and the result is emitted.

TEST_CASE("quarantine_allow: the plugin action refuses bad input and an inactive host",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_OR_RETURN(rig);

    SECTION("an unknown or missing op") {
        check_refused(rig.run("quarantine_allow", {{"op", "bogus"}, {"exceptions", "198.18.0.9"}}),
                      "op_invalid");
        check_refused(rig.run("quarantine_allow", {{"exceptions", "198.18.0.9"}}), "op_invalid");
        check_refused(rig.run("quarantine_allow", {{"op", "ADD"}, {"exceptions", "198.18.0.9"}}),
                      "op_invalid");
    }
    SECTION("exceptions that do not parse") {
        const auto r = rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", "garbage"}});
        INFO(r.captured);
        CHECK(r.rc == 1);
        CHECK(has_prefix(r.captured, "status|refused|exceptions_invalid:"));
        CHECK(has_prefix(r.captured, "refused|exceptions_invalid:"));
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        // one bad entry spoils the whole list: nothing is half-applied
        const auto mixed = rig.run("quarantine_allow",
                                   {{"op", "add"}, {"exceptions", "198.18.0.9:22/tcp/in,garbage"}});
        CHECK(has_prefix(mixed.captured, "status|refused|exceptions_invalid:"));
    }
    SECTION("no exceptions at all") {
        check_refused(rig.run("quarantine_allow", {{"op", "add"}}), "exceptions_required");
        check_refused(rig.run("quarantine_allow", {{"op", "remove"}, {"exceptions", ""}}),
                      "exceptions_required");
    }
    SECTION("a valid add or remove on a host that is not contained") {
        // This is the case that tells a working handler from one that refuses everything:
        // op, exceptions, the KV read and the record check all pass, and only the missing
        // containment refuses.
        check_refused(
            rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", "198.18.0.9:22/tcp/in"}}),
            "not_active");
        check_refused(
            rig.run("quarantine_allow", {{"op", "remove"}, {"exceptions", "198.18.0.9:22/tcp/in"}}),
            "not_active");
        CHECK_FALSE(rig.record().has_value()); // a refusal writes nothing
    }
    SECTION("a record that is not active is not contained either") {
        // phase=applying and phase=releasing are both "an operation in progress": no update
        fq::QuarantineState st;
        st.phase = fq::Phase::releasing;
        st.generation = 3;
        st.backend = fq::BackendKind::nft;
        st.allow = *fq::build_allow_set("203.0.113.7", "203.0.113.7:50051", {}, {});
        rig.put_record(st);
        const auto r = rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", "198.18.0.9"}});
        // a record always selects its leg (Linux: the recorded nft/iptables backend, built without
        // consulting which tools the host has; Windows and macOS: their one platform leg), so
        // `containment.leg` is never null here on any OS and fq::update answers not_active for a
        // non-active phase on every host. The `unsupported_platform` arm in do_quarantine_allow is
        // defensive only: a stored record cannot reach it today.
        CHECK(has_row(r.captured, "status|refused|not_active"));
        const auto after = rig.record();
        REQUIRE(after.has_value());
        CHECK(after->phase == fq::Phase::releasing); // untouched
        CHECK(after->generation == 3);
    }
}

TEST_CASE("quarantine: the plugin action checks its parameters before it touches anything",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_OR_RETURN(rig);

    // ttl_seconds is validated before anything is probed or written: a value outside
    // 60..2592000 (or not a number) is refused with no record started. Only refused
    // values are run here, never a valid one, which would reach the OS.
    for (const char* v : {"5", "59", "2592001", "soon", "0", "-5"})
        check_refused(rig.run("quarantine", {{"ttl_seconds", v}}), "ttl_out_of_bounds");
    const auto bad = rig.run("quarantine", {{"exceptions", "garbage"}});
    CHECK(has_prefix(bad.captured, "status|refused|exceptions_invalid:"));
    CHECK(bad.rc == 1);
    CHECK_FALSE(rig.record().has_value()); // no recovery record was even started
}

TEST_CASE("release if_ttl_expired: with nothing contained, the trigger's firing is a clean no-op",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_OR_RETURN(rig);

    // this is what the TTL interval trigger dispatches every 30 s; with no record it
    // must answer inactive and touch nothing (a bare `release` would run the OS undo)
    const auto r = rig.run("release", {{"if_ttl_expired", "1"}});
    INFO(r.captured);
    CHECK(r.rc == 0);
    CHECK(has_row(r.captured, "status|inactive"));
    CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(r.result_provenance == "firewall:inactive");
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("quarantine repair=1: with nothing contained, the self-check's firing is a clean no-op",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_OR_RETURN(rig);

    // what the repair trigger dispatches every 60 s (`repair=1` and nothing else): with no
    // record it answers inactive, touches nothing and starts nothing (it never builds an
    // allow set)
    const auto r = rig.run("quarantine", {{"repair", "1"}});
    INFO(r.captured);
    CHECK(r.rc == 0);
    CHECK(has_row(r.captured, "status|inactive"));
    CHECK(has_row(r.captured, "note|repair_tick=1"));
    CHECK(has_row(r.captured, "note|nothing_to_repair=1"));
    CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(r.result_provenance == "firewall:inactive");
    CHECK_FALSE(rig.record().has_value()); // a trigger that outlives a release never re-contains the host

    // an unreadable record is never read as "no record": degraded, nothing touched
    REQUIRE(rig.kv->set("firewall", std::string{fq::kStateKey}, "not a record"));
    const auto bad = rig.run("quarantine", {{"repair", "1"}});
    CHECK(has_row(bad.captured, "status|degraded|state_unreadable"));
    CHECK(bad.result_provenance == "firewall:degraded");
}

TEST_CASE("quarantine repair=1: a dispatch that also names containment parameters is refused, not repaired",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_OR_RETURN(rig);

    // The plugin cannot tell the repair trigger from an operator's server dispatch, so a
    // `repair=1` that carries a containment parameter is refused: an operator who meant to
    // contain must not read `inactive nothing_to_repair` rc 0. Each parameter alone is
    // enough, valid or not; nothing is read, started or written.
    for (const auto& [key, value] : std::vector<std::pair<const char*, const char*>>{
             {"ttl_seconds", "soon"}, {"ttl_seconds", "3600"}, {"exceptions", "garbage"},
             {"exceptions", "198.18.0.9:22/tcp/in"}, {"probe_target", "nope"}}) {
        INFO(key << "=" << value);
        check_refused(rig.run("quarantine", {{"repair", "1"}, {key, value}}),
                      "repair_with_containment_parameters");
        CHECK_FALSE(rig.record().has_value());
    }
    // all three at once, as a server dispatch of a full containment request would
    check_refused(rig.run("quarantine", {{"repair", "1"}, {"ttl_seconds", "3600"},
                                         {"exceptions", "198.18.0.9"}, {"probe_target", "198.18.0.1:443"}}),
                  "repair_with_containment_parameters");
    CHECK_FALSE(rig.record().has_value());
    // and `repair` other than `1` is no repair at all: the ordinary parameter checks apply
    check_refused(rig.run("quarantine", {{"repair", "0"}, {"ttl_seconds", "soon"}}), "ttl_out_of_bounds");
}

TEST_CASE("quarantine: a control endpoint that is this host's own loopback is refused self_host",
          "[agent][firewall_quarantine]") {
    // A server on 127.0.0.1 or ::1 is always this host, so a loopback control address is
    // refused whatever the read of this host's addresses returned. The refusal comes before
    // the privilege check, the staging check and any apply, on every OS and for an
    // unprivileged run, so this is what the built plugin answers here. Every `quarantine`
    // dispatch in this suite carries a probe_target that does not parse (`nope`): with the
    // check intact the answer is still self_host, and if the check ever regresses the
    // dispatch ends in a parse refusal and a clean test failure instead of a real apply
    // on a root runner.
    {
        PLUGIN_RIG_AT_OR_RETURN(rig, "127.0.0.1:50051", "127.0.0.1");
        check_refused(rig.run("quarantine", {{"probe_target", "nope"}}), "self_host");
        CHECK_FALSE(rig.record().has_value()); // a refusal stores no record
    }
    {
        PLUGIN_RIG_AT_OR_RETURN(rig, "[::1]:50051", "::1");
        check_refused(rig.run("quarantine", {{"probe_target", "nope"}}), "self_host");
        // valid optional parameters do not change the answer
        check_refused(rig.run("quarantine", {{"probe_target", "nope"},
                                             {"ttl_seconds", "3600"},
                                             {"exceptions", "198.18.0.9:22/tcp/in"}}),
                      "self_host");
        CHECK_FALSE(rig.record().has_value());
    }
}

TEST_CASE("quarantine repair=1: a loopback rig still answers inactive, repair never checks self_host",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_AT_OR_RETURN(rig, "127.0.0.1:50051", "127.0.0.1");
    // A stored record is always re-applied and always releasable: the repair route is
    // answered before the self-host check is reached.
    const auto r = rig.run("quarantine", {{"repair", "1"}});
    INFO(r.captured);
    CHECK(r.rc == 0);
    CHECK(has_row(r.captured, "status|inactive"));
    CHECK(has_row(r.captured, "note|nothing_to_repair=1"));
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("quarantine: a control endpoint at one of this host's own addresses is refused self_host",
          "[agent][firewall_quarantine]") {
    // The wiring of the own-address read: the first non-loopback, non-link-local IPv4 this
    // host answers to, used as the rig's server, must be refused. A host with no such
    // address has nothing to measure here.
    std::string own_ip;
    if (const auto own = yuzu::agent::enumerate_own_addresses()) {
        for (const auto& a : *own) {
            if (a.find(':') == std::string::npos && !a.starts_with("127.") && !a.starts_with("169.254.")) {
                own_ip = a;
                break;
            }
        }
    }
    if (own_ip.empty()) {
        WARN("this host has no non-loopback IPv4 address -- skipping");
        SUCCEED();
        return;
    }
    PLUGIN_RIG_AT_OR_RETURN(rig, own_ip + ":50051", own_ip);
    check_refused(rig.run("quarantine", {{"probe_target", "nope"}}), "self_host");
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("quarantine: the self_host check is skipped for a device whose own record is already active",
          "[agent][firewall_quarantine]") {
    // An apply to a device whose record is active only keeps or repairs the STORED set, and
    // its answer is what tells the server the requested set was not applied; a refusal
    // there would let the server confirm a record whose set the device never applied. Any
    // other record (applying, releasing) is checked. The probe_target does not parse, so
    // no case here reaches the OS: apply_and_verify refuses it before it loads the store.
    PLUGIN_RIG_AT_OR_RETURN(rig, "127.0.0.1:50051", "127.0.0.1");
    const auto stored = [&](fq::Phase phase) {
        fq::QuarantineState st;
        st.phase = phase;
        st.generation = 3;
        st.backend = fq::BackendKind::nft;
        st.allow = *fq::build_allow_set("203.0.113.7", "203.0.113.7:50051", {},
                                        *fq::parse_exceptions_csv("203.0.113.10"));
        return st;
    };
    const auto raw_record = [&] { return rig.kv->get("firewall", std::string{fq::kStateKey}); };

    for (const auto phase : {fq::Phase::applying, fq::Phase::releasing}) {
        INFO(fq::to_string(phase));
        rig.put_record(stored(phase));
        const auto before = raw_record();
        REQUIRE(before.has_value());
        check_refused(rig.run("quarantine", {{"probe_target", "nope"}}), "self_host");
        CHECK(raw_record() == before); // the refusal leaves the record as it was
    }

    rig.put_record(stored(fq::Phase::active));
    const auto before = raw_record();
    REQUIRE(before.has_value());
    const auto r = rig.run("quarantine", {{"probe_target", "nope"}, {"exceptions", "203.0.113.20"}});
    INFO(r.captured);
    CHECK(r.rc == 1);
    CHECK(has_prefix(r.captured, "status|refused|")); // the apply was answered, not skipped
    CHECK_FALSE(has_row(r.captured, "status|refused|self_host"));
    CHECK_FALSE(has_row(r.captured, "status|refused|own_addresses_unreadable"));
    CHECK(raw_record() == before);
}

TEST_CASE("release and quarantine_allow: a loopback rig never answers self_host",
          "[agent][firewall_quarantine]") {
    // Only an apply is checked: a device with a loopback control endpoint can still be
    // released, and its allow set still answers from the record (nothing is contained).
    PLUGIN_RIG_AT_OR_RETURN(rig, "127.0.0.1:50051", "127.0.0.1");
    const auto rel = rig.run("release", {{"if_ttl_expired", "1"}});
    INFO(rel.captured);
    CHECK(rel.rc == 0);
    CHECK(has_row(rel.captured, "status|inactive"));
    check_refused(rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", "198.18.0.9:22/tcp/in"}}),
                  "not_active");
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("live harness: http_reply_state frames a reply by its Content-Length or calls it unframed",
          "[agent][firewall_quarantine]") {
    const auto state = [](std::string_view reply) { return http_reply_state(reply); };
    const std::string headers = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n";

    // a complete reply: headers and exactly the declared body, and more than it (a pipelined byte)
    CHECK(state(headers + "hello") == HttpReply::complete);
    CHECK(state(headers + "hello!") == HttpReply::complete);
    CHECK(state("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n") == HttpReply::complete);
    // more is needed: headers only, a short body, a header split mid-way, no header end yet
    CHECK(state(headers) == HttpReply::need_more);
    CHECK(state(headers + "hel") == HttpReply::need_more);
    CHECK(state("HTTP/1.1 200 OK\r\nContent-Len") == HttpReply::need_more);
    CHECK(state("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n") == HttpReply::need_more);
    CHECK(state("") == HttpReply::need_more);
    // the header name is case-insensitive
    CHECK(state("HTTP/1.1 200 OK\r\ncontent-LENGTH:5\r\n\r\nhello") == HttpReply::complete);
    CHECK(state("HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 5 \r\n\r\nhel") == HttpReply::need_more);

    // no Content-Length: the client cannot know where the reply ends
    CHECK(state("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n") == HttpReply::unframed);
    CHECK(state("HTTP/1.1 200 OK\r\n\r\nbody") == HttpReply::unframed);
    CHECK(state("HTTP/1.1 200 OK\r\nContent-Length: five\r\n\r\nhello") == HttpReply::unframed);
    CHECK(state("HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n") == HttpReply::unframed);

    // HTTP/1.0 closes after the reply unless it says keep-alive
    CHECK(state("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello") == HttpReply::unframed);
    CHECK(state("HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello") == HttpReply::complete);
    CHECK(state("HTTP/1.0 200 OK\r\nContent-Length: 5\r\nconnection: Keep-Alive\r\n\r\nhel") == HttpReply::need_more);

    // Connection: close in any letter case, however well framed, is a close after the reply
    for (const char* close : {"Connection: close", "connection: CLOSE", "CONNECTION: Close", "Connection: keep-alive, close"})
        CHECK(state(std::string{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"} + close + "\r\n\r\nhello") == HttpReply::unframed);
}

TEST_CASE("agent core: enumerate_own_addresses answers a non-empty list of literals",
          "[agent][firewall_quarantine]") {
    // The shell of the self-host check reads this; nullopt would make every quarantine refuse
    // own_addresses_unreadable. Loopback is kept, so a host with any interface answers.
    const auto own = yuzu::agent::enumerate_own_addresses();
    REQUIRE(own.has_value());
    CHECK_FALSE(own->empty());
    for (const auto& lit : *own) {
        INFO("own address literal: " << lit);
        CHECK(fq::parse_ip(lit).has_value());
    }
    // enumerate_local_ips() is the same walk with the loopback and link-local scopes left out (the
    // Echo snapshot reads it): every address it names is one the host answers to, and none is
    // loopback (127.0.0.0/8, ::1) or link-local (169.254.0.0/16, fe80::/10).
    for (const auto& lit : yuzu::agent::enumerate_local_ips()) {
        INFO("local ip: " << lit);
        CHECK(std::find(own->begin(), own->end(), lit) != own->end());
        CHECK_FALSE(lit.starts_with("127."));
        CHECK_FALSE(lit.starts_with("169.254."));
        CHECK(lit != "::1");
        const bool v6_link_local = lit.size() > 3 && lit.starts_with("fe") &&
                                   (lit[2] == '8' || lit[2] == '9' || lit[2] == 'a' || lit[2] == 'b');
        CHECK_FALSE(v6_link_local);
    }
}

TEST_CASE("live: apply, verify the block, release restores the host byte-identical",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = baseline_snapshot();
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(probe(env.probe_target) != fq::ProbeOutcome::timeout); // reachable before
    const auto q = rig.run("quarantine", env.quarantine_params());
    INFO(q.captured);
    CHECK(q.rc == 0);
    CHECK(rig.has_status(q.captured, "active"));
    CHECK(has_row(q.captured, "verify|control=ok|probe=blocked"));
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout); // blocked by the host itself

    const auto st = rig.run("quarantine_status");
    CHECK(rig.has_status(st.captured, "active"));

    const auto rel = rig.run("release");
    INFO(rel.captured);
    CHECK(has_row(rel.captured, "status|inactive"));
    CHECK(probe(env.probe_target) != fq::ProbeOutcome::timeout); // reachable again
    check_restored(before);                                      // nothing left behind, nothing lost
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("live: a pre-established prohibited stream stops carrying data on apply",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto target = env.stream_target.empty() ? env.probe_target : env.stream_target;
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    KeptStream stream;
    if (!stream.open(target))
        SKIP("YUZU_FQ_STREAM_TARGET (or the probe target) did not accept a connection");
    // The first reply is drained to its Content-Length, so no byte of it is left to be read as an
    // answer after the apply.
    switch (stream.first_reply(3000)) {
    case FirstReply::complete:
        break;
    case FirstReply::unframed:
        SKIP("the stream target's reply is not length-framed (no Content-Length, HTTP/1.0 without "
             "keep-alive, or Connection: close): a close after the reply proves nothing about the stream");
    case FirstReply::silent:
        SKIP("the stream target did not answer a keep-alive request in time");
    case FirstReply::ended:
        SKIP("the stream target closed the stream after (or instead of) its first reply");
    }

    const auto q = rig.run("quarantine", env.quarantine_params());
    REQUIRE(rig.has_status(q.captured, "active"));
    // The stream was ESTABLISHED before the apply; a second request on it must go unanswered.
    // Only a receive timeout is proof: a stream that ended (EOF, a reset, a failed send) cannot
    // tell the containment from the server closing it, which is a SKIP with its reason, not a pass.
    const auto after = stream.request(3000);
    INFO("stream end: " << stream.end_reason());
    if (after == StreamReply::ended)
        SKIP("the stream ended instead of going silent, so this case cannot tell the containment "
             "from the server closing it: " + stream.end_reason());
    CHECK(after == StreamReply::silent); // an answer fails the case
}

#ifdef _WIN32
TEST_CASE("live: an unrelated enabled allow rule is disabled for the duration and restored",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto ep = split_endpoint(env.probe_target);
    REQUIRE(ep.has_value());
    const std::string netsh = "C:\\Windows\\System32\\netsh.exe";
    const std::string rule = "yuzu_test_fq_unrelated_allow";
    // An explicit Allow rule for exactly the probe target: a profile default-block alone would leave it live.
    (void)capture({netsh, "advfirewall", "firewall", "delete", "rule", "name=" + rule});
    REQUIRE(capture({netsh, "advfirewall", "firewall", "add", "rule", "name=" + rule, "dir=out",
                     "action=allow", "protocol=tcp", "remoteip=" + ep->first,
                     "remoteport=" + std::to_string(ep->second)})
                .find("Ok.") != std::string::npos);
    struct Cleanup {
        std::string netsh, rule;
        ~Cleanup() { (void)capture({netsh, "advfirewall", "firewall", "delete", "rule", "name=" + rule}); }
    } cleanup{netsh, rule};

    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });
    REQUIRE(probe(env.probe_target) != fq::ProbeOutcome::timeout);
    const auto q = rig.run("quarantine", env.quarantine_params());
    INFO(q.captured);
    CHECK((rig.has_status(q.captured, "active") || has_row(q.captured, "status|partial")));
    // blocked although an Allow rule names it: the rule was disabled
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);
    CHECK(netsh_rule_enabled(capture({netsh, "advfirewall", "firewall", "show", "rule",
                                      "name=" + rule})) == std::optional<bool>{false});

    (void)rig.run("release");
    CHECK(probe(env.probe_target) != fq::ProbeOutcome::timeout);
    CHECK(netsh_rule_enabled(capture({netsh, "advfirewall", "firewall", "show", "rule",
                                      "name=" + rule})) == std::optional<bool>{true});
}
#endif

TEST_CASE("live: a control-channel stream open before the apply keeps carrying data across the flush",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    KeptStream stream;
    if (!stream.open(env.server))
        SKIP("the control endpoint did not accept a connection");
    switch (stream.first_reply(3000)) {
    case FirstReply::complete:
        break;
    case FirstReply::unframed:
        SKIP("the control endpoint's reply is not length-framed (no Content-Length, HTTP/1.0 without "
             "keep-alive, or Connection: close)");
    case FirstReply::silent:
        SKIP("the control endpoint is not an HTTP server that answers a keep-alive request");
    case FirstReply::ended:
        SKIP("the control endpoint closed the stream after (or instead of) its first reply");
    }

    const auto q = rig.run("quarantine", env.quarantine_params());
    REQUIRE(rig.has_status(q.captured, "active"));
    // The stream predates the apply and, on macOS, the `pfctl -F states` that follows the load.
    // The control rules are stateless in both directions, so the flush cannot touch it: no
    // reconnect, the reply still arrives. (A rebuilt state would lose the TCP window scale.) This
    // case expects the stream to survive, so only an answer passes it.
    INFO("stream end: " << stream.end_reason());
    CHECK(stream.request(3000) == StreamReply::answered);
}

TEST_CASE("live: a control channel that cannot be reached rolls the apply back",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = baseline_snapshot();
    // Both inputs name a TEST-NET address nothing answers on: the verify's control check must fail.
    LiveRig rig("203.0.113.1:50051", "203.0.113.1");
    const auto q = rig.run("quarantine", env.quarantine_params());
    INFO(q.captured);
    CHECK(q.rc == 1);
    CHECK(has_row(q.captured, "rolled_back|control_unreachable"));
    CHECK_FALSE(rig.record().has_value());
    check_restored(before);
}

TEST_CASE("live: quarantine_allow adds and removes an exception through the plugin action",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(rig.has_status(rig.run("quarantine", env.quarantine_params()).captured, "active"));
    REQUIRE(rig.record().has_value());
    const auto gen0 = rig.record()->generation;
    const std::string exception = "198.18.0.9:22/tcp/in";
    check_listed("198.18.0.9", false);

    const auto add = rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", exception}});
    INFO(add.captured);
    CHECK(add.rc == 0);
    CHECK(rig.has_status(add.captured, "active"));
    CHECK(has_prefix(add.captured, "allow|exception|198.18.0.9"));
    REQUIRE(rig.record().has_value());
    CHECK(rig.record()->generation == gen0 + 1);
    CHECK(rig.record()->phase == fq::Phase::active);
    check_listed("198.18.0.9", true); // live, not just recorded
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);           // still contained

    const auto rm = rig.run("quarantine_allow", {{"op", "remove"}, {"exceptions", exception}});
    INFO(rm.captured);
    CHECK(rm.rc == 0);
    CHECK(rig.has_status(rm.captured, "active"));
    CHECK_FALSE(has_prefix(rm.captured, "allow|exception|198.18.0.9"));
    REQUIRE(rig.record().has_value());
    CHECK(rig.record()->generation == gen0 + 2);
    check_listed("198.18.0.9", false);
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);

    CHECK(has_row(rig.run("release").captured, "status|inactive"));
}

TEST_CASE("live: quarantine_status shapes", "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    CHECK(has_row(rig.run("quarantine_status").captured, "status|inactive"));

    // no probe target: contained, but the block is reported as not proven
    const auto q = rig.run("quarantine", env.quarantine_params(/*with_probe=*/false));
    CHECK(rig.has_status(q.captured, "active_unproven"));
    CHECK(has_row(q.captured, "verify|control=ok|probe=unproven"));
    CHECK(rig.has_status(rig.run("quarantine_status").captured, "active_unproven"));

    // a record that remembers rules the policy store refused to disable is partial, never active
    auto rec = rig.record();
    REQUIRE(rec.has_value());
    auto partial = *rec;
    partial.os.rules_not_disabled = 2;
    rig.put_record(partial);
    CHECK(has_row(rig.run("quarantine_status").captured, "status|partial|rules_not_disabled"));
    rig.put_record(*rec);

    // the OS no longer enforces what the record says: degraded
#if defined(__linux__)
    tamper_delete_nft_table();
    tamper_remove_ipt_jump(rec->os.ipt_gen);
#elif defined(_WIN32)
    (void)capture({"C:\\Windows\\System32\\netsh.exe", "advfirewall", "set", "allprofiles",
                   "firewallpolicy", "blockinbound,allowoutbound"});
#elif defined(__APPLE__)
    tamper_flush_anchor("rules");
#endif
    const auto degraded = rig.run("quarantine_status");
    CHECK(has_prefix(degraded.captured, "status|degraded|"));
}

TEST_CASE("live: init completes an interrupted release and re-applies a lost containment",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = baseline_snapshot();
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(rig.has_status(rig.run("quarantine", env.quarantine_params()).captured, "active"));
    auto rec = rig.record();
    REQUIRE(rec.has_value());

    // an agent that died half-way through a release: phase `releasing`, rules still present
    auto releasing = *rec;
    releasing.phase = fq::Phase::releasing;
    rig.put_record(releasing);
    rig.restart();
    CHECK_FALSE(rig.record().has_value());
    check_restored(before);

    // a reboot: the record says active, the OS lost the rules; init restores them before any dispatch
    REQUIRE(rig.has_status(rig.run("quarantine", env.quarantine_params()).captured, "active"));
    rec = rig.record();
    REQUIRE(rec.has_value());
#if defined(__linux__)
    tamper_delete_nft_table();
#elif defined(_WIN32)
    (void)capture({"C:\\Windows\\System32\\netsh.exe", "advfirewall", "set", "allprofiles",
                   "firewallpolicy", "blockinbound,allowoutbound"});
#elif defined(__APPLE__)
    // the anchor is gone and pf is off while our (same-boot) token is still on record:
    // the repair path -- release the dead token, take a fresh one, reload. `pfctl -d` is not a
    // line the agent account is granted, so only a root run switches pf off; the anchor flushes
    // alone still lose the containment.
    tamper_flush_anchor("rules");
    tamper_flush_anchor("nat");
    if (running_as_root())
        (void)capture({"/sbin/pfctl", "-d"});
#endif
    rig.restart();
    CHECK(rig.has_status(rig.run("quarantine_status").captured, "active"));
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);

    // A record that carries a time limit, then a restart: init retries both triggers
    // (the standalone harness has no trigger engine, so each fails again,
    // deterministically) and the failures are recorded as residue. This is the only
    // place the init-time retry line executes against the built plugin.
    REQUIRE(rig.has_status(rig.run("quarantine_status").captured, "active"));
    rec = rig.record();
    REQUIRE(rec.has_value());
    auto timed = *rec;
    timed.ttl_expires = static_cast<std::int64_t>(std::time(nullptr)) + 3600;
    rig.put_record(timed);
    rig.restart();
    // Both triggers are refused in this harness: the first residue in the fixed order
    // names the status, and both notes ride the summary.
    const auto recovered = rig.run("quarantine_status").captured;
    CHECK(has_prefix(recovered, "note|init_recovery=partial:ttl_unregistered,"));
    CHECK(recovered.find("ttl_trigger_unregistered=1") != std::string::npos);
    CHECK(recovered.find("repair_trigger_unregistered=1") != std::string::npos);
    rec = rig.record();
    REQUIRE(rec.has_value());
    CHECK(rec->ttl_expires > 0);
    CHECK(rec->os.ttl_unregistered); // recorded: every later status reads it

    // The start-time note describes a containment still in force: once the host is
    // released it is history, not status. Pins the `inactive` guard in
    // do_quarantine_status (a dispatch of quarantine_status reads the host firewall on
    // every leg, so this half cannot run in the normal suite).
    CHECK(has_row(rig.run("release").captured, "status|inactive"));
    const auto released = rig.run("quarantine_status").captured;
    CHECK(has_row(released, "status|inactive"));
    CHECK_FALSE(has_prefix(released, "note|init_recovery="));
}

TEST_CASE("live: the repair self-check re-applies a containment the host lost, from the stored set",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(rig.has_status(rig.run("quarantine", env.quarantine_params()).captured, "active"));
    const auto stored = rig.record();
    REQUIRE(stored.has_value());

    // a healthy host: the tick only reads (no new generation, no repair)
    const auto healthy = rig.run("quarantine", {{"repair", "1"}});
    INFO(healthy.captured);
    CHECK(has_row(healthy.captured, "note|repair_tick=1"));
    CHECK_FALSE(has_row(healthy.captured, "note|repaired=1"));
    REQUIRE(rig.record().has_value());
    CHECK(rig.record()->generation == stored->generation);

    // another actor undoes the containment
#if defined(__linux__)
    tamper_delete_nft_table();
#elif defined(_WIN32)
    (void)capture({"C:\\Windows\\System32\\netsh.exe", "advfirewall", "set", "allprofiles",
                   "firewallpolicy", "blockinbound,allowoutbound"});
#elif defined(__APPLE__)
    tamper_flush_anchor("rules");
    tamper_flush_anchor("nat");
#endif
    CHECK(probe(env.probe_target) != fq::ProbeOutcome::timeout); // honestly uncontained

    // the tick notices and re-applies the STORED set. `repair=1` is bare: do_quarantine refuses
    // it together with containment parameters (repair_with_containment_parameters), so the
    // stored set is the only thing it can apply.
    const auto fixed = rig.run("quarantine", {{"repair", "1"}});
    INFO(fixed.captured);
    CHECK(fixed.rc == 0);
    CHECK(has_row(fixed.captured, "note|repair_tick=1"));
    CHECK(has_row(fixed.captured, "note|repaired=1"));
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);
    check_listed("198.18.0.9", false);
    const auto after = rig.record();
    REQUIRE(after.has_value());
    CHECK(after->phase == fq::Phase::active);
    CHECK(after->allow == stored->allow);
    CHECK(after->generation == stored->generation + 1);
    CHECK(after->repairs == 1);
    CHECK(after->repaired_at > 0);
    // quarantine_status shows the repair
    CHECK(has_prefix(rig.run("quarantine_status").captured, "note|repairs=1"));

    CHECK(has_row(rig.run("release").captured, "status|inactive"));
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("live: a ttl release is a no-op before expiry and releases after",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    // The time limit is written onto the record directly: the standalone harness has no
    // trigger engine, so a real `ttl_seconds` could never be enforced here, but its
    // tick (what the trigger would dispatch) is driven by hand below.
    REQUIRE(rig.has_status(rig.run("quarantine", env.quarantine_params()).captured, "active"));
    auto rec = rig.record();
    REQUIRE(rec.has_value());
    rec->ttl_expires = static_cast<std::int64_t>(std::time(nullptr)) + 3600;
    rig.put_record(*rec);

    const auto early = rig.run("release", {{"if_ttl_expired", "1"}});
    CHECK(has_row(early.captured, "note|ttl_not_expired=1"));
    CHECK(rig.record().has_value());

    auto expired = *rec;
    expired.ttl_expires = 1; // long past
    rig.put_record(expired);
    const auto late = rig.run("release", {{"if_ttl_expired", "1"}});
    CHECK(has_row(late.captured, "status|inactive"));
    CHECK(has_row(late.captured, "note|ttl_expired=1")); // the expiry is a visible, logged event
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("live: quarantine is refused self_host when the control endpoint is this host's own address",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    // This host's own address, learned by a UDP connect to the probe target (nothing is sent). It
    // is the control endpoint the plugin is told about, so the refusal comes before anything else.
    const auto own = own_address_toward(env.probe_target);
    if (!own)
        SKIP("this host's own address toward the probe target could not be learned");
    if (own->rfind("127.", 0) == 0 || *own == "::1")
        SKIP("the route to the probe target is the loopback: no non-loopback own address to use");
    const auto before = baseline_snapshot();
    const std::string server = (own->find(':') != std::string::npos ? "[" + *own + "]" : *own) + ":50051";
    LiveRig rig(server, *own);
    const auto q = rig.run("quarantine", env.quarantine_params());
    check_refused(q, "self_host"); // rc 1, the refusal rows, UNAVAILABLE / PARTIAL / firewall:refused
    CHECK_FALSE(rig.record().has_value());
    // The release of a device that was never contained: the REST manual says it answers `inactive`
    // (docs/user-manual/rest-api.md, Quarantine). This is where that sentence is measured, per OS;
    // an OS that answers otherwise changes the manual to the measured answer.
    const auto rel = rig.run("release");
    INFO(rel.captured);
    CHECK(has_row(rel.captured, "status|inactive"));
    check_restored(before);
}

TEST_CASE("live: state reports what the OS tool reports, and the host is left as it was",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = baseline_snapshot();
    PluginRig rig(env.server, env.server_ip());
    const auto r = rig.run("state");
    INFO(r.captured);
    REQUIRE(r.rc == 0);
    const auto ruleset = row_value(r.captured, "ruleset");
    REQUIRE(ruleset.has_value()); // every terminal state carries a count row, `unknown` when it could not be read

#if defined(_WIN32)
    // Three profile rows that agree with the snapshot, and the true rule count. The snapshot is read
    // again after the action and the count may match either: the Store app-package rules churn.
    const auto after = firewall_snapshot();
    REQUIRE(fr::readable(kThisOs, after));
    const auto profiles = fr::section(before, fr::label::kProfiles).value_or("");
    for (const char* name : {"Domain", "Private", "Public"}) {
        const auto row = row_value(r.captured, std::string{"profile|"} + name);
        INFO(name);
        REQUIRE(row.has_value());
        const auto line = profiles.find(std::string{name} + "|enabled=");
        REQUIRE(line != std::string::npos);
        const bool snapshot_on = profiles.compare(line + std::string_view{name}.size() + 9, 4, "True") == 0;
        CHECK(*row == (snapshot_on ? "enabled" : "disabled"));
    }
    if (*ruleset != "unknown") {
        const auto n = static_cast<std::size_t>(std::stoull(*ruleset));
        CHECK((n == section_lines(before, fr::label::kRules) || n == section_lines(after, fr::label::kRules)));
    } else {
        CHECK(has_prefix(r.captured, "error|rules_count:"));
    }
#elif defined(__linux__)
    const auto backend = row_value(r.captured, "backend");
    REQUIRE(backend.has_value());
    const auto state = row_value(r.captured, "state");
    REQUIRE(state.has_value());
    CHECK((*state == "active" || *state == "inactive" || *state == "unknown" || *state == "running"));
    CHECK((*state != "unknown" || *ruleset == "unknown")); // an unknown state never carries a count
    if (running_as_root() && *backend == "nftables") {
        const auto nft = fr::section(before, fr::label::kNft);
        REQUIRE(nft.has_value());
        CHECK(*ruleset == std::to_string(fr::count_nft_rules(*nft)));
        // a root run on a quiet host: nothing was torn and no generation moved
        CHECK_FALSE(has_prefix(r.captured, "fallthrough|nftables:"));
        CHECK_FALSE(has_prefix(r.captured, "error|nftables:"));
    } else if (running_as_root() && *backend == "iptables") {
        const auto ipt = fr::section(before, fr::label::kIptables);
        REQUIRE(ipt.has_value());
        std::size_t appended = 0;
        for (const auto& line : rows_of(*ipt))
            appended += line.rfind("-A ", 0) == 0 ? 1 : 0;
        CHECK(*ruleset == std::to_string(appended));
    } else if (!running_as_root() && *state == "unknown") {
        // The agent account cannot read the ruleset itself (netlink dumps and iptables need root):
        // an honest unknown is the right answer, and it must say why, unless the backend that
        // answered is one whose refusal is a silent exit status (iptables, ufw) or none answered.
        CHECK((has_prefix(r.captured, "error|") || has_prefix(r.captured, "fallthrough|") ||
               *backend == "iptables" || *backend == "ufw" || *backend == "none"));
    }
#else
    // macOS: the Application Firewall state is an unprivileged read, run here directly.
    const auto alf = capture_result({"/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"});
    REQUIRE(yuzu::firewall::subprocess_complete(alf));
    const auto want = yuzu::firewall::parse_alf_global_state(alf.output);
    CHECK(row_value(r.captured, "state") == std::string{yuzu::firewall::to_string(want.state)});
    CHECK(has_row(r.captured, "mode|block_all") == want.block_all);
    // pf needs root: unreadable is `unknown` plus the row that says why, readable is the tool's word
    const auto pf = row_value(r.captured, "pf");
    REQUIRE(pf.has_value());
    CHECK((*pf == "unknown") == has_prefix(r.captured, "error|pf:info:"));
    CHECK((*ruleset == "unknown") == has_prefix(r.captured, "error|pf:rules:"));
    if (running_as_root()) {
        const auto status = fr::section(before, fr::label::kPfStatus).value_or("");
        CHECK(*pf == (status.find("Status: Enabled") != std::string::npos ? "enabled" : "disabled"));
        CHECK(ruleset == std::to_string(fr::count_pf_rule_lines(
                             fr::section(before, fr::label::kPfRules).value_or(""))));
    }
#endif
    check_restored(before); // a read changes nothing
}

TEST_CASE("live: rules lists what the OS tool lists, and the host is left as it was",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = baseline_snapshot();
    PluginRig rig(env.server, env.server_ip());
    const auto r = rig.run("rules");
    INFO(r.captured);
    REQUIRE(r.rc == 0);
    const auto ruleset = row_value(r.captured, "ruleset");
    REQUIRE(ruleset.has_value());

#if defined(_WIN32)
    // At most 100 rule rows; `ruleset|100` and `truncated|true` exactly when the host has more.
    const auto rule_rows = count_prefixed(r.captured, "rule|");
    CHECK(rule_rows <= 100);
    const auto after = firewall_snapshot();
    REQUIRE(fr::readable(kThisOs, after));
    const auto host_rules = std::max(section_lines(before, fr::label::kRules).value_or(0),
                                     section_lines(after, fr::label::kRules).value_or(0));
    if (*ruleset != "unknown") {
        CHECK(*ruleset == std::to_string(rule_rows));
        if (host_rules > 100) {
            CHECK(rule_rows == 100);
            CHECK(has_row(r.captured, "truncated|true"));
        } else {
            CHECK_FALSE(has_row(r.captured, "truncated|true"));
        }
    } else {
        CHECK(has_prefix(r.captured, "error|enum_next:"));
    }
#elif defined(__linux__)
    const auto backend = row_value(r.captured, "backend");
    REQUIRE(backend.has_value());
    if (running_as_root() && *backend == "nftables") {
        const auto nft = fr::section(before, fr::label::kNft);
        REQUIRE(nft.has_value());
        const auto n = fr::count_nft_rules(*nft);
        CHECK(*ruleset == std::to_string(n));
        CHECK(count_prefixed(r.captured, "rule|nftables|") >= n); // the rule handles, plus the base chains
    } else if (!running_as_root()) {
        CHECK((*ruleset == "unknown" || is_integer(*ruleset))); // honest, never a fabricated count
    }
#else
    // macOS: the app list is an unprivileged read, run here directly
    const auto listed = capture_result({"/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps"});
    REQUIRE(yuzu::firewall::subprocess_complete(listed));
    CHECK(count_prefixed(r.captured, "app|") == yuzu::firewall::parse_alf_listapps(listed.output).size());
    CHECK((*ruleset == "unknown") == has_prefix(r.captured, "error|pf:rules:"));
    if (running_as_root())
        CHECK(*ruleset == std::to_string(fr::count_pf_rule_lines(
                              fr::section(before, fr::label::kPfRules).value_or(""))));
#endif
    check_restored(before);
}

#if defined(__linux__)
TEST_CASE("live (linux, agent account): the helper's snapshot word answers through sudo -n and refuses an argument",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    if (running_as_root())
        SKIP("runs as the agent account: a root run does not go through the helper");
    const auto snap = capture_result(harness_sudo({std::string{fq::kFwHelperPath}, "snapshot"}), 60s,
                                     /*merge_stderr=*/false);
    INFO(snap.output.substr(0, 2000));
    REQUIRE(yuzu::firewall::subprocess_complete(snap));
    CHECK(snap.output.size() <= 1048576);
    CHECK(fr::readable(fr::Os::lin, snap.output)); // headed sections and the == end trailer

    // the word takes no argument: with one it is refused (exit 64) and prints no listing
    const auto extra = capture_result(harness_sudo({std::string{fq::kFwHelperPath}, "snapshot", "extra"}));
    INFO(extra.output);
    CHECK(extra.tool_ran);
    CHECK(extra.exit_code == 64);
    CHECK(extra.output.find("== ") == std::string::npos);
}
#endif

#if defined(__linux__) || defined(__APPLE__)
namespace {

/// Real nft / pfctl, real staged files, but every ruleset load after the first fails:
/// a runner forced to fail in the middle of an update. A load is `nft -f <file>` or
/// `pfctl -a <anchor> -f <file>` (an agent that is root), or the helper's `nft load <file>` /
/// `pf load <file>` (the agent account). Every other call goes through `sudo -n --` for a
/// non-root run, as the plugin's own runner does.
struct FlakyLoadRunner {
    int loads = 0;
    int fail_from_load = 2;
    fq::Runner fn() {
        return [this](const fq::Argv& argv, std::chrono::milliseconds budget) {
            const bool is_load = argv.size() > 1 && (argv[1] == "-f" || (argv.size() == 5 && argv[3] == "-f") ||
                                                     (argv.size() == 4 && (argv[1] == "nft" || argv[1] == "pf") &&
                                                      argv[2] == "load"));
            if (is_load && ++loads >= fail_from_load) {
                fq::ToolResult t;
                t.ran = true;
                t.exit_code = 1;
                t.output = "Error: forced failure";
                return t;
            }
            auto res = yuzu::agent::run_bounded_subprocess(
                harness_sudo(argv), yuzu::agent::SubprocessOptions{.deadline = budget, .merge_stderr = true});
            fq::ToolResult t;
            t.ran = res.tool_ran;
            t.exit_code = res.exit_code;
            t.timed_out = res.timed_out;
            t.truncated = res.output_truncated;
            t.output = std::move(res.output);
            return t;
        };
    }
};

struct MemStore final : fq::StateStore {
    std::optional<fq::QuarantineState> s;
    fq::StateLoad load() override {
        fq::StateLoad l;
        if (s) {
            l.kind = fq::StateLoad::Kind::ok;
            l.state = *s;
        }
        return l;
    }
    bool save(const fq::QuarantineState& st) override {
        s = st;
        return true;
    }
    bool erase() override {
        s.reset();
        return true;
    }
};

/// How a leg built directly by a test reaches the privileged tool: itself as root, the helper
/// as the agent account (the same decision the plugin makes from the euid).
[[nodiscard]] fq::ToolAccess harness_access() {
    return running_as_root() ? fq::ToolAccess::direct : fq::ToolAccess::helper;
}

/// A private `<TempDir>/firewall-staging` (mode 0700, a real directory) and a Stage that writes
/// each ruleset into it as `yuzu-fwq-<random>.<suffix>`: the shape the helper's path check
/// accepts, which a file in the system temp directory is not.
struct StagingDir {
    yuzu::test::TempDir root{"yuzu_test_fq_stage_"};
    std::string dir;
    StagingDir() {
        std::error_code ec;
        const auto path = (root.path / "firewall-staging").lexically_normal();
        fs::create_directories(path, ec);
        REQUIRE_FALSE(ec);
        fs::permissions(path, fs::perms::owner_all, fs::perm_options::replace, ec);
        REQUIRE_FALSE(ec);
        dir = path.string();
    }
    [[nodiscard]] fq::Stage stage() const {
        return [dir = dir](std::string_view stem, std::string_view suffix,
                           std::string_view contents) -> std::optional<fq::StagedFile> {
            auto tmp = yuzu::TempFile::create(stem, suffix, dir);
            if (!tmp)
                return std::nullopt;
            {
                std::ofstream f(tmp->path(), std::ios::binary | std::ios::trunc);
                f.write(contents.data(), static_cast<std::streamsize>(contents.size()));
            }
            auto holder = std::make_shared<yuzu::TempFile>(std::move(*tmp));
            return fq::StagedFile{holder->path(), holder, dir};
        };
    }
};

} // namespace
#endif

#if defined(__linux__)
TEST_CASE("live (linux nft): a failed update keeps the previous generation in force",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    if (::access("/usr/sbin/nft", X_OK) != 0)
        SKIP("nft is not installed on this host");
    FlakyLoadRunner runner;
    // Root runs nft itself; the agent account loads through the helper, from a staging directory
    // the helper's path check accepts.
    StagingDir staging;
    fq::NftLeg leg(runner.fn(), staging.stage(), harness_access());
    MemStore store;
    fq::Env fenv{leg, store,
                 [](const std::string& ip, int port, std::chrono::milliseconds t) {
                     return probe(ip + ":" + std::to_string(port), static_cast<int>(t.count()));
                 },
                 [] { return static_cast<std::int64_t>(std::time(nullptr)); }};
    const auto exceptions =
        env.operator_exception.empty() ? std::vector<fq::Endpoint>{} : *fq::parse_exceptions_csv(env.operator_exception);
    auto allow = fq::build_allow_set(env.server_ip(), env.server, {}, exceptions);
    REQUIRE(allow.has_value());

    Watchdog dog(120s, [&] {
        fq::Deadline dl;
        (void)fq::release(fenv, fq::ReleaseRequest{}, dl);
    });
    fq::Deadline dl;
    fq::ApplyRequest req;
    req.allow = *allow;
    req.probe_target = env.probe_target;
    const auto applied = fq::apply_and_verify(fenv, req, dl);
    REQUIRE((applied.status == "active"));
    // Both reads must have completed: two identical failed reads (sudo's refusal, a tool error)
    // would otherwise compare equal and pass for "nothing changed".
    const auto table_before = capture_result(harness_sudo(fq::nft_list_argv()));
    REQUIRE(yuzu::firewall::subprocess_complete(table_before));

    fq::Deadline dl2;
    const auto upd = fq::update(fenv, true, {*fq::parse_exception("198.18.0.9:22/tcp/in")}, dl2);
    CHECK(upd.status == "update_failed");
    const auto table_after = capture_result(harness_sudo(fq::nft_list_argv()));
    REQUIRE(yuzu::firewall::subprocess_complete(table_after));
    CHECK(table_after.output == table_before.output);
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout); // still blocked
    REQUIRE(store.s.has_value());
    CHECK(store.s->phase == fq::Phase::active);

    fq::Deadline dl3;
    CHECK(fq::release(fenv, fq::ReleaseRequest{}, dl3).status == "inactive");
}
#endif

#if defined(__APPLE__)
namespace {

/// The same value the plugin reads in-process, for a PfLeg built directly by a test.
std::optional<std::string> live_boot_time() {
    struct timeval tv{};
    size_t len = sizeof(tv);
    if (::sysctlbyname("kern.boottime", &tv, &len, nullptr, 0) != 0 || len != sizeof(tv))
        return std::nullopt;
    return std::to_string(static_cast<long long>(tv.tv_sec)) + "." +
           std::to_string(static_cast<long long>(tv.tv_usec));
}

/// One listing of our pf anchor as a whole result: a caller whose verdict rests on it checks
/// subprocess_complete() first.
[[nodiscard]] yuzu::agent::SubprocessResult pf_anchor_capture(const char* what) {
    return capture_result(harness_sudo({"/sbin/pfctl", "-a", std::string{fq::kPfAnchor}, "-s", what}));
}

/// One listing of the main pf ruleset (`rules`, `info`) as a whole result.
[[nodiscard]] yuzu::agent::SubprocessResult pf_main_capture(const char* what) {
    return capture_result(harness_sudo({"/sbin/pfctl", "-s", what}));
}

} // namespace

TEST_CASE("live (macOS pf): the sub-anchor loads, sorts first, and release restores pf byte-identical",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = baseline_snapshot();
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    const auto q = rig.run("quarantine", env.quarantine_params());
    INFO(q.captured);
    // `active` means pfctl accepted the whole anchor, `no nat all` and `no rdr all` included
    REQUIRE(rig.has_status(q.captured, "active"));

    // Captured for the PR narrative: design-note open questions 3 (References layout),
    // 6 (Anchors layout) and 7 (a flush of an anchor that does not exist).
    const auto anchors = capture(harness_sudo({"/sbin/pfctl", "-a", "com.apple", "-s", "Anchors"}));
    INFO("-a com.apple -s Anchors:\n" << anchors);
    INFO("-s References:\n" << capture(harness_sudo({"/sbin/pfctl", "-s", "References"})));
    INFO("anchor -s rules:\n" << pf_anchor_capture("rules").output);
    INFO("anchor -s nat:\n" << pf_anchor_capture("nat").output);
    CHECK(anchors.find(std::string{fq::kPfAnchorLeaf}) != std::string::npos);
    CHECK(fq::pf_siblings_before(anchors).empty()); // nothing is evaluated before us
    CHECK(fq::pf_anchor_referenced(capture(harness_sudo({"/sbin/pfctl", "-s", "rules"}))));
    CHECK(fq::pf_anchor_enforcing(pf_anchor_capture("rules").output));
    CHECK(rig.has_status(rig.run("quarantine_status").captured, "active"));

    const auto rel = rig.run("release");
    INFO(rel.captured);
    CHECK(has_row(rel.captured, "status|inactive"));
    // main ruleset, Status line (by its state word) and reference lines equal their
    // pre-quarantine values, and our anchor holds nothing
    check_restored(before);
    // our anchor is empty, not merely unreferenced
    // An absence needs a read that completed, or the anchor's own absence (pfctl exits non-zero for
    // an anchor that is not loaded) seen after the two main reads completed.
    const auto emptied = pf_anchor_capture("rules");
    const bool main_complete = yuzu::firewall::subprocess_complete(pf_main_capture("rules")) &&
                               yuzu::firewall::subprocess_complete(pf_main_capture("info"));
    REQUIRE((yuzu::firewall::subprocess_complete(emptied) || pf_anchor_absent(main_complete, emptied)));
    CHECK_FALSE(fq::pf_anchor_enforcing(emptied.output));
}

TEST_CASE("live (macOS pf): pf switched off behind the plugin's back is reported, then repaired",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    // `pfctl -d` is not one of the lines the agent account is granted: only root can be the
    // "other actor" that switches pf off.
    if (!running_as_root())
        SKIP("pfctl -d is not granted to the agent account, so only a root run can switch pf off");
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(rig.has_status(rig.run("quarantine", env.quarantine_params()).captured, "active"));
    const auto old_token = rig.record() ? rig.record()->os.pf_token : std::string{};
    REQUIRE_FALSE(old_token.empty());

    (void)capture({"/sbin/pfctl", "-d"}); // another actor
    const auto st = rig.run("quarantine_status");
    INFO(st.captured);
    CHECK(has_row(st.captured, "status|degraded|pf_disabled"));
    CHECK(probe(env.probe_target) != fq::ProbeOutcome::timeout); // honestly uncontained

    const auto fixed = rig.run("quarantine", env.quarantine_params());
    INFO(fixed.captured);
    CHECK(rig.has_status(fixed.captured, "active"));
    CHECK(has_row(fixed.captured, "note|repaired=1"));
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);
    REQUIRE(rig.record().has_value());
    CHECK(rig.record()->os.pf_token != old_token); // a fresh reference, recorded

    CHECK(has_row(rig.run("release").captured, "status|inactive"));
}

TEST_CASE("live (macOS pf): a failed update keeps the previous generation in force",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    FlakyLoadRunner runner;
    // Root runs pfctl itself; the agent account loads through the helper, from a staging
    // directory the helper's path check accepts.
    StagingDir staging;
    fq::PfLeg leg(runner.fn(), staging.stage(), live_boot_time, harness_access());
    MemStore store;
    fq::Env fenv{leg, store,
                 [](const std::string& ip, int port, std::chrono::milliseconds t) {
                     return probe(ip + ":" + std::to_string(port), static_cast<int>(t.count()));
                 },
                 [] { return static_cast<std::int64_t>(std::time(nullptr)); }};
    const auto exceptions =
        env.operator_exception.empty() ? std::vector<fq::Endpoint>{} : *fq::parse_exceptions_csv(env.operator_exception);
    auto allow = fq::build_allow_set(env.server_ip(), env.server, {}, exceptions);
    REQUIRE(allow.has_value());

    Watchdog dog(120s, [&] {
        fq::Deadline dl;
        (void)fq::release(fenv, fq::ReleaseRequest{}, dl);
    });
    fq::Deadline dl;
    fq::ApplyRequest req;
    req.allow = *allow;
    req.probe_target = env.probe_target;
    REQUIRE(fq::apply_and_verify(fenv, req, dl).status == "active");
    // Both reads must have completed: two identical failed reads would otherwise compare equal.
    const auto rules_before = pf_anchor_capture("rules");
    REQUIRE(yuzu::firewall::subprocess_complete(rules_before));

    fq::Deadline dl2;
    const auto upd = fq::update(fenv, true, {*fq::parse_exception("198.18.0.9:22/tcp/in")}, dl2);
    CHECK(upd.status == "update_failed");
    const auto rules_after = pf_anchor_capture("rules");
    REQUIRE(yuzu::firewall::subprocess_complete(rules_after));
    CHECK(rules_after.output == rules_before.output); // the anchor load is atomic: nothing changed
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout); // still blocked
    REQUIRE(store.s.has_value());
    CHECK(store.s->phase == fq::Phase::active);

    fq::Deadline dl3;
    CHECK(fq::release(fenv, fq::ReleaseRequest{}, dl3).status == "inactive");
}
#endif
