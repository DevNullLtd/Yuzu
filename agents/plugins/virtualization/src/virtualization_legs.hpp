/**
 * virtualization_legs.hpp -- shared seam between the virtualization plugin TU and its three
 * per-OS leg TUs (mgmt_posture_legs.hpp shape).
 *
 * Holds (a) the per-OS entry-point declarations, (b) report, the SINGLE owner of every
 * `status|<action>|...` row (no leg and no parser writes one), pairing each status with its result
 * status/completeness (report_host is its `host` form), (c) execute_action, the plugin's whole
 * execute() body (dispatch over the Legs table + ABI containment), and (d) `decide`, the OS-free
 * pairing of the pure classifiers with the status decision for `host`. The leg TUs keep only the
 * OS shell: they read, fill a Facts and call report_host(ctx, decide(facts)). The `wsl` action's
 * decision lives in virtualization_wsl_parsers.hpp (decide_wsl).
 *
 * Reason propagation, one rule: every failed-read token (and the permanent `cpuid:unavailable`
 * limitation, when it is why the kind is unknown) goes into one ConstraintAccumulator; the
 * status is `constrained` iff the accumulator is non-empty and its joined string is the status
 * row's reason. Each entry point is a READ and returns 0: a degraded read is not a failed
 * command.
 */
#pragma once

#include "virtualization_parsers.hpp"
#include "virtualization_runtime_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::virtualization {

int run_windows(yuzu::CommandContext& ctx);
int run_linux(yuzu::CommandContext& ctx);
int run_macos(yuzu::CommandContext& ctx);
int run_windows_wsl(yuzu::CommandContext& ctx);
int run_linux_wsl(yuzu::CommandContext& ctx);
int run_macos_wsl(yuzu::CommandContext& ctx);
int run_windows_runtime_posture(yuzu::CommandContext& ctx);
int run_linux_runtime_posture(yuzu::CommandContext& ctx);
int run_macos_runtime_posture(yuzu::CommandContext& ctx);

/// The operator's `agent.runtime_endpoint`, stashed by the plugin's init() and read by the Linux
/// leg. Empty (the default) means the action never opens a socket. Guarded: init() and a worker
/// thread's execute() are not ordered by the plugin ABI.
inline std::mutex g_runtime_endpoint_mutex;
inline std::string g_runtime_endpoint;
inline void set_runtime_endpoint(std::string_view v) {
    std::lock_guard<std::mutex> lk(g_runtime_endpoint_mutex);
    g_runtime_endpoint = std::string{v};
}
inline std::string runtime_endpoint() {
    std::lock_guard<std::mutex> lk(g_runtime_endpoint_mutex);
    return g_runtime_endpoint;
}

enum class StatusState { supported, constrained, unsupported };

inline std::string_view status_token(StatusState s) {
    switch (s) {
    case StatusState::supported:
        return "supported";
    case StatusState::constrained:
        return "constrained";
    case StatusState::unsupported:
        return "unsupported";
    }
    return "unsupported";
}

inline std::string format_status_row(std::string_view action, StatusState s,
                                     std::string_view reason) {
    std::string r = "status|";
    r += action;
    r += '|';
    r += status_token(s);
    r += '|';
    r += reason.empty() ? std::string{"-"} : yuzu::util::safe_output_field(reason);
    return r;
}

/// What a leg decided: the status, its reason token(s), and the data rows.
struct Posture {
    StatusState status = StatusState::supported;
    std::string reason;
    std::vector<std::string> rows;
};

/// Writes the status row FIRST, then the data rows, then the paired result status.
/// `unsupported` (a leg that read nothing) pairs with UNAVAILABLE/UNKNOWN.
inline void report(yuzu::CommandContext& ctx, std::string_view action, const Posture& p) {
    ctx.write_output(format_status_row(action, p.status, p.reason));
    for (const auto& r : p.rows)
        ctx.write_output(r);
    switch (p.status) {
    case StatusState::constrained:
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              p.reason);
        break;
    case StatusState::unsupported:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                              p.reason);
        break;
    case StatusState::supported:
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        break;
    }
}

inline void report_host(yuzu::CommandContext& ctx, const Posture& p) { report(ctx, "host", p); }

/// A leg that read nothing: ONE `unsupported` status row carrying the token.
/// Callers: execute_action's catch arm (`<os>:leg:exception`), the non-Windows `wsl` legs and the
/// macOS/Windows `runtime_posture` legs.
inline void report_unavailable(yuzu::CommandContext& ctx, std::string_view action,
                               std::string_view token) {
    report(ctx, action, Posture{StatusState::unsupported, std::string{token}, {}});
}

/// The OS-free decision: classify the host and the container, accumulate every constraint token.
inline Posture decide(const Facts& f) {
    const Classification host = classify(f);
    const ContainerVerdict container = classify_container(f);

    yuzu::shared::ConstraintAccumulator acc;
    for (const auto& t : host.tokens)
        acc.add_failure(t);
    if (container.read_failed)
        acc.add_failure(container.evidence);
    // A marker hit hides a failed cgroup read from the verdict; the status still reports it.
    if (f.container.mode == ContainerInputs::Mode::linux_read && !f.container.reason.empty())
        acc.add_failure(f.container.reason);

    Posture p;
    p.status = acc.any_failure() ? StatusState::constrained : StatusState::supported;
    p.reason = acc.reason();
    p.rows.push_back(format_host_row(host));
    p.rows.push_back(format_container_row(container));
    return p;
}

// ---------------------------------------------------------------------------
// runtime_posture: the OS-free seam over injected boundaries
// ---------------------------------------------------------------------------

namespace runtime {

constexpr std::chrono::seconds kActionDeadline{20};

struct TransportResult {
    Outcome outcome = Outcome::other;
    int http_status = 0;
    std::string body;
};

/// One request over the endpoint, bounded by `budget` (the time left of the action deadline, never
/// below 1 ms). The real one is an httplib AF_UNIX client in virtualization_linux.cpp.
using Transport = std::function<TransportResult(const Request&, std::chrono::milliseconds budget)>;
using Clock = std::function<std::chrono::steady_clock::time_point()>;

/// The filesystem and process boundaries of the action. Functions are the I/O, the data members are
/// facts the shell read once per dispatch. A unit test fills all of them with fakes.
struct RuntimeFs {
    std::function<StatResult(const std::string&)> stat;          ///< follows links
    std::function<FieldRead(const std::string&, std::size_t)> read; ///< bounded regular-file read
    /// open(O_PATH|O_NOFOLLOW) + fstat of the endpoint. The shell keeps the descriptor open for the
    /// whole run and its Transport connects through it, so the object checked is the object used.
    std::function<StatResult(const std::string&)> open_endpoint;
    std::vector<std::string> network_mounts; ///< network-filesystem mount points (mountinfo)
    bool mountinfo_unreadable = false;
    std::uint32_t egid = 0;
    std::vector<std::uint32_t> groups; ///< effective + supplementary groups
};

/// `status|runtime_posture|constrained|...busy` and nothing else, or the result of `body`. A
/// process-wide flag held for the whole run: the agent's dispatch pool has no per-action
/// serialisation, so repeated dispatch against a trickling peer would otherwise pin the pool.
template <class Body>
Posture single_flight(std::atomic<bool>& flag, Body&& body) {
    bool expected = false;
    if (!flag.compare_exchange_strong(expected, true)) {
        Posture busy;
        busy.status = StatusState::constrained;
        busy.reason = rt_token("busy");
        return busy;
    }
    struct Release {
        std::atomic<bool>& f;
        ~Release() { f.store(false); }
    } release{flag};
    return body();
}

inline std::atomic<bool>& runtime_posture_flight() {
    static std::atomic<bool> flag{false};
    return flag;
}

namespace detail {

inline bool errno_absent(int e) { return e == ENOENT || e == ENOTDIR; }

} // namespace detail

/// The whole action over injected boundaries (mgmt_posture_legs.hpp shape). No exception is
/// expected to escape; execute_action holds the one try/catch at the ABI seam regardless.
inline Posture runtime_posture_linux(const RuntimeFs& fs, const Transport& transport,
                                     const Clock& clock, std::string_view endpoint) {
    yuzu::shared::ConstraintAccumulator acc;
    const auto deadline = clock() + kActionDeadline;

    // ---- 1. detection: stat of sockets, configs and data roots (no endpoint needed) -----------
    struct Detected {
        std::string name;
        std::string socket_field = "absent";
        std::string config_field = "absent";
        bool any = false;
    };
    std::vector<Detected> detected;
    std::vector<StatResult> default_stats; // present-or-not stat of each default socket path
    std::vector<ConfigRow> docker_config;
    bool docker_config_malformed = false;

    if (fs.mountinfo_unreadable)
        acc.add_failure(rt_token("mountinfo:unreadable"));

    for (const auto& spec : runtime_specs()) {
        Detected d;
        d.name = std::string{spec.name};
        bool socket_unreadable = false;
        for (const auto path : spec.sockets) {
            const StatResult st = fs.stat(std::string{path});
            default_stats.push_back(st);
            if (st.ok()) {
                if (d.socket_field == "absent")
                    d.socket_field = socket_present_field(st);
                d.any = true;
                if (socket_overprivileged(st, fs.groups))
                    acc.add_failure(rt_token(d.name + ":overprivileged"));
            } else if (!detail::errno_absent(st.err)) {
                socket_unreadable = true;
                acc.add_failure(rt_token(d.name + ":socket:" + errno_token(st.err)));
            }
        }
        if (d.socket_field == "absent" && socket_unreadable)
            d.socket_field = "unreadable";

        bool config_unreadable = false;
        for (const auto path : spec.configs) {
            if (spec.name == "docker") { // daemon.json is read and parsed, not just stat'd
                const FieldRead r = fs.read(std::string{path}, kDaemonJsonCap);
                if (r.state == ReadState::ok) {
                    d.config_field = "present";
                    d.any = true;
                    ConfigRows dj = parse_daemon_json(r.value);
                    if (dj.malformed) {
                        docker_config_malformed = true;
                        acc.add_failure(rt_token("daemon_json:malformed"));
                    }
                    docker_config = std::move(dj.rows); // the well-typed keys still report
                } else if (r.state == ReadState::unreadable) {
                    config_unreadable = true;
                    acc.add_failure(rt_token("daemon_json:" + r.cause));
                }
                continue;
            }
            const StatResult st = fs.stat(std::string{path});
            if (st.ok()) {
                d.config_field = "present";
                d.any = true;
            } else if (!detail::errno_absent(st.err)) {
                config_unreadable = true;
                acc.add_failure(rt_token(d.name + ":config:" + errno_token(st.err)));
            }
        }
        if (d.config_field == "absent" && config_unreadable)
            d.config_field = "unreadable";

        // The data root: stat'd only when it is not on, under or containing a network mount (a
        // stat on a dead network mount has no deadline). A skipped root reads absent.
        const std::string root{spec.data_root};
        bool on_network = false;
        for (const auto& m : fs.network_mounts)
            if (path_touches_mount(root, m)) {
                on_network = true;
                break;
            }
        if (on_network) {
            acc.add_failure(rt_token(d.name + ":network_fs_skipped"));
        } else {
            const StatResult st = fs.stat(root);
            if (st.ok())
                d.any = true;
            else if (!detail::errno_absent(st.err))
                acc.add_failure(rt_token(d.name + ":data_root:" + errno_token(st.err)));
        }
        detected.push_back(std::move(d));
    }

    // ---- 2. the endpoint ------------------------------------------------------------------------
    EndpointStatus ep_status = EndpointStatus::unset;
    std::string ep_reason = "-";
    Dialect dialect = Dialect::none;
    VersionInfo version;
    std::vector<ConfigRow> info_rows;
    std::vector<ContainerRow> containers;

    const EndpointDecision decision = parse_endpoint(endpoint);
    EndpointVerdict verdict = decision.verdict;
    if (verdict == EndpointVerdict::ok) {
        // The Transport is never invoked unless every check below passes.
        const StatResult leaf = fs.open_endpoint(decision.path);
        verdict = check_endpoint_leaf(leaf, fs.egid, default_stats);
        if (verdict == EndpointVerdict::ok) {
            for (const auto& dir : ancestors_of(decision.path)) {
                const EndpointVerdict v = check_endpoint_ancestor(fs.stat(dir));
                if (v != EndpointVerdict::ok) {
                    verdict = v;
                    break;
                }
            }
        }
    }
    if (verdict != EndpointVerdict::ok) {
        ep_status = endpoint_status_for(verdict);
        ep_reason = std::string{endpoint_reason_token(verdict)};
        // A configured endpoint that was refused or is not there is a failed read: the status says
        // so (`endpoint:<cause>`) and the endpoint row says which. `unset` is not a failure.
        if (const std::string cause = endpoint_failure_cause(verdict); !cause.empty())
            acc.add_failure(rt_token("endpoint:" + cause));
    } else {
        // Request budget: remaining time of the action deadline, never zero or negative. A
        // sub-millisecond remainder stops the action rather than reaching the client's "no limit".
        // The budget is also enforced HERE, whatever the Transport does with it: a request that
        // comes back at or past its budget reads `timeout`, so an overrun can never end `supported`
        // (a peer that is always readable defeats the HTTP client's own total timeout).
        const auto send = [&](const Request& req) -> std::optional<TransportResult> {
            const auto t0 = clock();
            const auto ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - t0);
            if (ms.count() < 1) {
                acc.add_failure(rt_token("deadline_exhausted")); // deduped by the accumulator
                return std::nullopt;
            }
            TransportResult r = transport(req, ms);
            r.outcome = budget_outcome(
                r.outcome, std::chrono::duration_cast<std::chrono::milliseconds>(clock() - t0), ms);
            return r;
        };

        ep_status = EndpointStatus::ok;
        bool proceed = true;

        // /version: the endpoint's liveness and dialect.
        if (const auto req = build_request(Verb::version)) {
            const auto r = send(*req);
            if (!r) {
                proceed = false;
            } else if (r->outcome != Outcome::ok) {
                // The endpoint row says what the endpoint is; the token says the read failed (a
                // trickling peer is `version:timeout`, an oversized reply `version:response_oversized`).
                ep_status = endpoint_status_for(r->outcome);
                acc.add_failure(rt_token("version:" + failure_cause(r->outcome)));
                proceed = false;
            } else if (r->http_status != 200) {
                acc.add_failure(rt_token("version:" + http_cause(r->http_status)));
            } else {
                const ParsedJson pj = parse_limited(r->body);
                if (!pj.ok && !pj.too_deep) {
                    ep_status = EndpointStatus::not_http; // 200 but no JSON: not a runtime API
                    acc.add_failure(rt_token("version:not_http"));
                    proceed = false;
                } else {
                    if (pj.ok)
                        version = parse_version(pj.value);
                    else
                        version.malformed = true; // nested past the limit
                    if (version.malformed)
                        acc.add_failure(rt_token("version:malformed"));
                    dialect = version.dialect;
                }
            }
        }

        // One verb after /version: a failure is its own token and later verbs still run.
        const auto fetch = [&](Verb verb, std::string_view source,
                               std::string_view id = {}) -> std::optional<ParsedJson> {
            const auto req = build_request(verb, id);
            if (!req)
                return std::nullopt;
            const auto r = send(*req);
            if (!r)
                return std::nullopt;
            if (r->outcome != Outcome::ok) {
                acc.add_failure(rt_token(std::string{source} + ":" + failure_cause(r->outcome)));
                return std::nullopt;
            }
            if (r->http_status != 200) {
                acc.add_failure(rt_token(std::string{source} + ":" + http_cause(r->http_status)));
                return std::nullopt;
            }
            ParsedJson pj = parse_limited(r->body);
            if (!pj.ok) {
                acc.add_failure(rt_token(std::string{source} + ":malformed"));
                return std::nullopt;
            }
            return pj;
        };

        if (proceed) {
            if (const auto info = fetch(Verb::info, "info")) {
                ConfigRows ir = parse_info(info->value);
                if (ir.malformed)
                    acc.add_failure(rt_token("info:malformed"));
                info_rows = std::move(ir.rows);
            }
            if (const auto list = fetch(Verb::containers_list, "list")) {
                ContainerList cl = containers_from_list(list->value);
                if (cl.malformed)
                    acc.add_failure(rt_token("list:malformed"));
                if (cl.skipped > 0)
                    acc.add_failure(rt_token("list:entries_skipped"));
                if (cl.rows_capped)
                    acc.add_failure(rt_token("rows_capped"));
                containers = std::move(cl.rows);
            }
        }
        if (!containers.empty()) {
            if (containers.size() > kMaxInspections)
                acc.add_failure(rt_token("inspect_capped"));
            std::size_t failed = 0;
            std::size_t answered = 0;
            std::size_t not_found = 0;
            const std::size_t n = std::min(containers.size(), kMaxInspections);
            for (std::size_t i = 0; i < n; ++i) {
                const auto req = build_request(Verb::container_inspect, containers[i].id);
                if (!req)
                    continue;
                const auto r = send(*req);
                if (!r)
                    break;
                ++answered;
                if (r->outcome == Outcome::ok && r->http_status == 404) {
                    ++not_found; // removed between list and inspect: expected churn, no constraint
                    continue;
                }
                if (r->outcome != Outcome::ok || r->http_status != 200) {
                    ++failed;
                    continue;
                }
                const ParsedJson pj = parse_limited(r->body);
                if (!pj.ok || !apply_inspect(containers[i], pj.value))
                    ++failed;
            }
            if (failed > 0)
                acc.add_failure(rt_token("inspect:failed:" + std::to_string(failed)));
            // Churn is some containers going away; EVERY inspection answering 404 is an endpoint
            // that admits the list but not the inspect (a proxy denying it), which must not read
            // as a clean supported with unknown rows.
            if (answered > 0 && not_found == answered)
                acc.add_failure(rt_token("inspect:not_found:" + std::to_string(not_found)));
        }
    }

    // ---- 3. rows --------------------------------------------------------------------------------
    Posture p;
    p.status = acc.any_failure() ? StatusState::constrained : StatusState::supported;
    p.reason = acc.reason();

    p.rows.push_back(format_endpoint_row(ep_status, ep_reason, dialect));
    for (const auto& d : detected) {
        const bool served = ep_status == EndpointStatus::ok && dialect_token(dialect) == d.name;
        p.rows.push_back(format_runtime_row(d.name, decide_runtime(d.any, served), d.socket_field,
                                            d.config_field, served ? version.version : "-",
                                            served ? version.api_version : "-"));
    }
    for (const auto& c : docker_config)
        p.rows.push_back(format_config_row("docker", c.key, c.value));
    if (docker_config_malformed)
        p.rows.push_back(format_config_row("docker", "daemon_json", "malformed"));
    for (const auto& c : info_rows)
        p.rows.push_back(format_config_row(dialect_token(dialect), c.key, c.value));
    for (const auto& c : containers)
        p.rows.push_back(format_container_row(dialect_token(dialect), c));
    return p;
}

} // namespace runtime

using LegFn = int (*)(yuzu::CommandContext&);

/// The per-OS leg of each action.
struct Legs {
    LegFn host;
    LegFn wsl;
    LegFn runtime_posture;
};

/// The WHOLE body of the plugin's execute(): dispatch and the single ABI containment.
/// Status-row contract: one status row per dispatch, with three exceptions. (1) An unknown
/// action writes ONE non-status line (`unknown action: <name>`, invalid UTF-8 replaced and the
/// rest escaped) and returns 1: no status row. (2) A leg that throws AFTER report already
/// wrote its row gets the catch arm's `unsupported` row appended, so there are TWO and the LAST
/// status row wins; it is named for the leg's action, or `host` when the throw came before the
/// action was recognised. (3) The recovery itself allocates, so it is
/// guarded too: if it throws as well, the dispatch returns 1 rather than unwinding across the
/// plugin ABI.
inline int execute_action(yuzu::CommandContext& ctx, std::string_view action, const Legs& legs,
                          std::string_view leg_exception_token) {
    std::string_view known = "host";
    try {
        LegFn leg = nullptr;
        if (action == "host") {
            leg = legs.host;
        } else if (action == "wsl") {
            leg = legs.wsl;
            known = "wsl";
        } else if (action == "runtime_posture") {
            leg = legs.runtime_posture;
            known = "runtime_posture";
        } else {
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(
                                 yuzu::util::sanitize_utf8(std::string{action})));
            return 1;
        }
        return leg(ctx);
    } catch (...) {
        try {
            report_unavailable(ctx, known, leg_exception_token);
        } catch (...) {
            return 1;
        }
        return 0;
    }
}

} // namespace yuzu::virtualization
