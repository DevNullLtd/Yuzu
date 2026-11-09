#pragma once

// virtualization_runtime_parsers.hpp -- the pure core of the `runtime_posture` action
// (docs/virtualization-runtime-posture-design.md, the binding statements in sections 2 to 8). No
// file, socket, clock or OS header here: the Linux shell injects every boundary through
// virtualization_legs.hpp, so these decisions run unchanged in the agent test binary on every host.
//
// WHAT IS HERE.
//   * The verb table. Requests are built from an enum index, never from a string, by ONE
//     constructor (build_request); there is no fifth verb and no other way to make a Request.
//   * parse_endpoint (lexical) and the endpoint object checks over injected stat facts: default
//     socket refusal by path, by inode, socket type / owner / group / mode, ancestor walk.
//   * The JSON readers. Every body is parsed through parse_limited (non-throwing, comments
//     ignored, nesting over kMaxJsonDepth discarded as it starts) and read only through accessors
//     that tolerate a wrong type. Each reader touches an allow-list of keys and nothing else:
//     /version (Version, ApiVersion, Components[].Name), /info (CgroupDriver, SecurityOptions),
//     the list reply (Id, Names, Image, State), the inspect reply (HostConfig.Privileged,
//     HostConfig.NetworkMode, Mounts[].Source), daemon.json (a fixed key list).
//   * Per-field character allow-lists (section 8): a field that comes from a peer or a config file
//     is admitted only when every byte is in its set, otherwise it reads `invalid`; the check runs
//     BEFORE truncation and before wire_field. The set bounds the characters; the cap (256 bytes,
//     64 for network_mode and versions) is applied by truncation afterwards.
//   * Row formatters (all through wire_field) and the token grammar.
//
// TOKEN GRAMMAR: linux:virtualization:runtime_posture:<source>[:<cause>...], every segment
// [a-z0-9_]+ (the plugin's existing grammar, virtualization_parsers.hpp). An HTTP status in a token
// is emitted only when numeric and 100-599, otherwise the cause is http_other.

#include "virtualization_parsers.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::virtualization::runtime {

// ---------------------------------------------------------------------------
// Bounds (design note section 5)
// ---------------------------------------------------------------------------

inline constexpr int kMaxJsonDepth = 32;
inline constexpr std::size_t kMaxBodyBytes = 1024 * 1024;
inline constexpr std::size_t kMaxContainerRows = 256;
inline constexpr std::size_t kMaxInspections = 64;
inline constexpr std::size_t kDaemonJsonCap = 256 * 1024;
inline constexpr std::size_t kFieldCap = 256;
inline constexpr std::size_t kShortFieldCap = 64;
inline constexpr std::size_t kMaxSocketPath = 107; // sun_path is 108 bytes including the NUL
/// Every request carries `Connection: close`; the shell sets exactly this value.
inline constexpr std::string_view kConnectionHeaderValue = "close";

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// `linux:virtualization:runtime_posture:<tail>`; `tail` is `[a-z0-9_]+(:[a-z0-9_]+)*`.
inline std::string rt_token(std::string_view tail) {
    return "linux:virtualization:runtime_posture:" + std::string{tail};
}

/// An HTTP status as a token cause: `http_<n>` for 100-599, else `http_other`.
inline std::string http_cause(int status) {
    if (status >= 100 && status <= 599)
        return "http_" + std::to_string(status);
    return "http_other";
}

// ---------------------------------------------------------------------------
// Verb table (section 2)
// ---------------------------------------------------------------------------

enum class Verb : std::size_t { version, info, containers_list, container_inspect, count };

struct VerbRow {
    std::string_view method;
    std::string_view path_template;
};

inline constexpr std::array<VerbRow, 4> kVerbs{{
    {"GET", "/version"},
    {"GET", "/info"},
    {"GET", "/containers/json?all=1"},
    {"GET", "/containers/{id}/json"},
}};
static_assert(kVerbs.size() == static_cast<std::size_t>(Verb::count),
              "every Verb has exactly one row in kVerbs");

struct Request {
    Verb verb = Verb::version;
    std::string method;
    std::string path;
};

/// `^[0-9a-f]{12,64}$`.
inline bool valid_container_id(std::string_view id) {
    if (id.size() < 12 || id.size() > 64)
        return false;
    for (const char c : id)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

/// THE constructor of a Request. An id is accepted only for container_inspect and only when it
/// matches ^[0-9a-f]{12,64}$; anything else yields no request.
inline std::optional<Request> build_request(Verb verb, std::string_view container_id = {}) {
    const auto index = static_cast<std::size_t>(verb);
    if (index >= kVerbs.size())
        return std::nullopt;
    const VerbRow& row = kVerbs[index];
    Request r;
    r.verb = verb;
    r.method = std::string{row.method};
    if (verb == Verb::container_inspect) {
        if (!valid_container_id(container_id))
            return std::nullopt;
        r.path = "/containers/" + std::string{container_id} + "/json";
        return r;
    }
    if (!container_id.empty())
        return std::nullopt;
    r.path = std::string{row.path_template};
    return r;
}

// ---------------------------------------------------------------------------
// Stat facts and the endpoint decision (section 4)
// ---------------------------------------------------------------------------

/// What one stat (or one fstat of an O_PATH descriptor) reported. `err` is an errno, 0 = ok.
struct StatResult {
    int err = 0;
    std::uint32_t mode = 0; // full st_mode
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint64_t dev = 0;
    std::uint64_t ino = 0;

    bool ok() const { return err == 0; }
    std::uint32_t type() const { return mode & 0170000u; }
    bool is_socket() const { return ok() && type() == 0140000u; }
    bool is_dir() const { return ok() && type() == 0040000u; }
    bool is_link() const { return ok() && type() == 0120000u; }
    std::uint32_t perm() const { return mode & 07777u; }
};

inline constexpr std::array<std::string_view, 4> kDefaultSockets{
    "/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock",
    "/run/containerd/containerd.sock"};

/// Collapses repeated '/', drops "." segments and a trailing '/'. A ".." segment is KEPT (this
/// never resolves anything); parse_endpoint refuses it first.
inline std::string normalise_path(std::string_view p) {
    const bool absolute = !p.empty() && p.front() == '/';
    std::string out = absolute ? "/" : "";
    std::size_t pos = 0;
    bool first = true;
    while (pos <= p.size()) {
        const auto slash = p.find('/', pos);
        const auto end = slash == std::string_view::npos ? p.size() : slash;
        const std::string_view seg = p.substr(pos, end - pos);
        if (!seg.empty() && seg != ".") {
            if (!first)
                out += '/';
            out += seg;
            first = false;
        }
        if (slash == std::string_view::npos)
            break;
        pos = slash + 1;
    }
    return out;
}

inline bool has_dotdot_segment(std::string_view p) {
    std::size_t pos = 0;
    while (pos <= p.size()) {
        const auto slash = p.find('/', pos);
        const auto end = slash == std::string_view::npos ? p.size() : slash;
        if (p.substr(pos, end - pos) == "..")
            return true;
        if (slash == std::string_view::npos)
            break;
        pos = slash + 1;
    }
    return false;
}

/// Every refusal reason, plus `unset` (no endpoint), `ok` and `absent` (ENOENT: the endpoint is not
/// there, which the endpoint row reports as `unreachable`, never as a refusal).
enum class EndpointVerdict {
    unset,
    ok,
    absent,
    relative,
    dotdot,
    too_long,
    default_socket,
    same_inode,
    not_socket,
    symlink,
    owner,
    group,
    mode,
    insecure_ancestor,
    stat_error,
};

inline std::string_view endpoint_reason_token(EndpointVerdict v) {
    switch (v) {
    case EndpointVerdict::relative:
        return "relative";
    case EndpointVerdict::dotdot:
        return "dotdot";
    case EndpointVerdict::too_long:
        return "too_long";
    case EndpointVerdict::default_socket:
        return "default_socket";
    case EndpointVerdict::same_inode:
        return "same_inode";
    case EndpointVerdict::not_socket:
        return "not_socket";
    case EndpointVerdict::symlink:
        return "symlink";
    case EndpointVerdict::owner:
        return "owner";
    case EndpointVerdict::group:
        return "group";
    case EndpointVerdict::mode:
        return "mode";
    case EndpointVerdict::insecure_ancestor:
        return "insecure_ancestor";
    case EndpointVerdict::stat_error:
        return "stat_error";
    default:
        return "-";
    }
}

inline bool is_refusal(EndpointVerdict v) {
    return v != EndpointVerdict::unset && v != EndpointVerdict::ok && v != EndpointVerdict::absent;
}

struct EndpointDecision {
    EndpointVerdict verdict = EndpointVerdict::unset;
    std::string path; // normalised; set when the lexical checks passed
};

/// The lexical half: empty is `unset`; a relative path, a `..` segment, a normalised path over
/// 107 bytes, or one of the four default sockets (after normalisation) is a refusal.
inline EndpointDecision parse_endpoint(std::string_view raw) {
    EndpointDecision d;
    if (raw.empty())
        return d;
    if (raw.front() != '/') {
        d.verdict = EndpointVerdict::relative;
        return d;
    }
    if (has_dotdot_segment(raw)) {
        d.verdict = EndpointVerdict::dotdot;
        return d;
    }
    std::string norm = normalise_path(raw);
    if (norm.size() > kMaxSocketPath) {
        d.verdict = EndpointVerdict::too_long;
        return d;
    }
    for (const auto s : kDefaultSockets)
        if (norm == s) {
            d.verdict = EndpointVerdict::default_socket;
            return d;
        }
    d.verdict = EndpointVerdict::ok;
    d.path = std::move(norm);
    return d;
}

/// The checks over the object the shell OPENED (open(O_PATH|O_NOFOLLOW) + fstat), in the order the
/// note fixes: a stat error other than ENOENT refuses (never read as absent); a link refuses as
/// `symlink`; a non-socket refuses; the same (dev, ino) as a present default socket refuses as
/// `same_inode` (BEFORE owner/group/mode, so a bind mount of a default socket is named for what it
/// is); then owner uid 0, group == the agent's effective gid, mode exactly 0660.
inline EndpointVerdict check_endpoint_leaf(const StatResult& leaf, std::uint32_t egid,
                                           const std::vector<StatResult>& default_socket_stats) {
    if (leaf.err == ENOENT)
        return EndpointVerdict::absent;
    if (!leaf.ok())
        return EndpointVerdict::stat_error;
    if (leaf.is_link())
        return EndpointVerdict::symlink;
    if (!leaf.is_socket())
        return EndpointVerdict::not_socket;
    for (const auto& d : default_socket_stats)
        if (d.is_socket() && d.dev == leaf.dev && d.ino == leaf.ino)
            return EndpointVerdict::same_inode;
    if (leaf.uid != 0)
        return EndpointVerdict::owner;
    if (leaf.gid != egid)
        return EndpointVerdict::group;
    if (leaf.perm() != 0660u)
        return EndpointVerdict::mode;
    return EndpointVerdict::ok;
}

/// One ancestor directory: ENOENT is `absent`, any other stat error `stat_error`, and a directory
/// that is not owned by uid 0 or is writable by group or other is `insecure_ancestor`.
inline EndpointVerdict check_endpoint_ancestor(const StatResult& dir) {
    if (dir.err == ENOENT)
        return EndpointVerdict::absent;
    if (!dir.ok())
        return EndpointVerdict::stat_error;
    if (!dir.is_dir() || dir.uid != 0 || (dir.perm() & 0022u) != 0)
        return EndpointVerdict::insecure_ancestor;
    return EndpointVerdict::ok;
}

/// "/run/yuzu-agent/runtime.sock" -> {"/run/yuzu-agent", "/run", "/"}. `p` is normalised.
inline std::vector<std::string> ancestors_of(std::string_view p) {
    std::vector<std::string> out;
    std::string cur{p};
    while (cur.size() > 1) {
        const auto slash = cur.rfind('/');
        if (slash == std::string::npos)
            break;
        cur = slash == 0 ? std::string{"/"} : cur.substr(0, slash);
        out.push_back(cur);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Endpoint and runtime statuses (section 7)
// ---------------------------------------------------------------------------

enum class EndpointStatus { unset, ok, endpoint_refused, permission_denied, unreachable, not_http };

inline std::string_view endpoint_status_token(EndpointStatus s) {
    switch (s) {
    case EndpointStatus::unset:
        return "unset";
    case EndpointStatus::ok:
        return "ok";
    case EndpointStatus::endpoint_refused:
        return "endpoint_refused";
    case EndpointStatus::permission_denied:
        return "permission_denied";
    case EndpointStatus::unreachable:
        return "unreachable";
    case EndpointStatus::not_http:
        return "not_http";
    }
    return "unreachable";
}

/// How one request ended at the transport. `other` is any connect-time failure that is not one of
/// the named errnos; it reads `unreachable`.
enum class Outcome { ok, eacces, enoent, econnrefused, timeout, oversized, not_http, other };

/// The endpoint state a FAILED first exchange maps to (decide_endpoint's transport half).
inline EndpointStatus endpoint_status_for(Outcome o) {
    switch (o) {
    case Outcome::ok:
        return EndpointStatus::ok;
    case Outcome::eacces:
        return EndpointStatus::permission_denied;
    case Outcome::not_http:
    case Outcome::oversized:
        return EndpointStatus::not_http;
    case Outcome::enoent:
    case Outcome::econnrefused:
    case Outcome::timeout:
    case Outcome::other:
        return EndpointStatus::unreachable;
    }
    return EndpointStatus::unreachable;
}

/// The endpoint state for a lexical or object verdict.
inline EndpointStatus endpoint_status_for(EndpointVerdict v) {
    switch (v) {
    case EndpointVerdict::unset:
        return EndpointStatus::unset;
    case EndpointVerdict::ok:
        return EndpointStatus::ok;
    case EndpointVerdict::absent:
        return EndpointStatus::unreachable;
    default:
        return EndpointStatus::endpoint_refused;
    }
}

/// The cause segment of a token for a request that failed AFTER the endpoint answered once.
inline std::string failure_cause(Outcome o) {
    switch (o) {
    case Outcome::eacces:
        return "permission_denied";
    case Outcome::timeout:
        return "timeout";
    case Outcome::oversized:
        return "response_oversized";
    case Outcome::not_http:
        return "not_http";
    default:
        return "unreachable";
    }
}

enum class RuntimeDetection { not_detected, detected, served };

inline std::string_view detection_token(RuntimeDetection d) {
    switch (d) {
    case RuntimeDetection::not_detected:
        return "not_detected";
    case RuntimeDetection::detected:
        return "detected";
    case RuntimeDetection::served:
        return "served";
    }
    return "not_detected";
}

/// `served` when the endpoint's /version identified this runtime, else `detected` when any
/// standard-path artefact exists, else `not_detected`. An endpoint failure never reaches here.
inline RuntimeDetection decide_runtime(bool any_artefact, bool served) {
    if (served)
        return RuntimeDetection::served;
    return any_artefact ? RuntimeDetection::detected : RuntimeDetection::not_detected;
}

// ---------------------------------------------------------------------------
// The runtimes' standard paths (section 6)
// ---------------------------------------------------------------------------

struct RuntimeSpec {
    std::string_view name;
    std::vector<std::string_view> sockets;
    std::vector<std::string_view> configs;
    std::string_view data_root;
};

inline const std::array<RuntimeSpec, 3>& runtime_specs() {
    static const std::array<RuntimeSpec, 3> specs{{
        {"docker",
         {"/run/docker.sock", "/var/run/docker.sock"},
         {"/etc/docker/daemon.json"},
         "/var/lib/docker"},
        {"podman",
         {"/run/podman/podman.sock"},
         {"/etc/containers/containers.conf", "/etc/containers/storage.conf",
          "/etc/containers/registries.conf"},
         "/var/lib/containers"},
        {"containerd",
         {"/run/containerd/containerd.sock"},
         {"/etc/containerd/config.toml"},
         "/var/lib/containerd"},
    }};
    return specs;
}

/// `present:<mode>:<uid>:<gid>` for the socket field of a runtime row.
inline std::string socket_present_field(const StatResult& s) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%04o", static_cast<unsigned>(s.perm()));
    return "present:" + std::string{buf} + ":" + std::to_string(s.uid) + ":" +
           std::to_string(s.gid);
}

/// `p` is `m`, is under `m`, or contains `m` (the mount table speaks in mount points).
inline bool path_touches_mount(std::string_view p, std::string_view m) {
    if (m == "/" || p == "/")
        return true;
    const auto under = [](std::string_view a, std::string_view b) {
        return a == b || (a.size() > b.size() && a.substr(0, b.size()) == b &&
                          a[b.size()] == '/');
    };
    return under(p, m) || under(m, p);
}

/// The agent can connect to this present default socket without the operator proxy: a group the
/// agent holds with the group-write bit, or other-write.
inline bool socket_overprivileged(const StatResult& s, const std::vector<std::uint32_t>& groups) {
    if (!s.is_socket())
        return false;
    if ((s.perm() & 0002u) != 0)
        return true;
    if ((s.perm() & 0020u) == 0)
        return false;
    for (const auto g : groups)
        if (g == s.gid)
            return true;
    return false;
}

// ---------------------------------------------------------------------------
// JSON: depth-limited, non-throwing, accessor-based
// ---------------------------------------------------------------------------

struct ParsedJson {
    nlohmann::json value;
    bool ok = false;       ///< parsed to a value
    bool too_deep = false; ///< the nesting limit was breached (the whole reply reads malformed)
};

/// Parses with no exceptions, comments ignored, and a callback that discards any container that
/// starts at nesting depth >= kMaxJsonDepth (so the over-deep part is never built) and records the
/// breach. Bodies and parse-error text are never logged anywhere.
inline ParsedJson parse_limited(std::string_view text) {
    ParsedJson out;
    bool too_deep = false;
    const auto cb = [&too_deep](int depth, nlohmann::json::parse_event_t event,
                                nlohmann::json& /*parsed*/) {
        if ((event == nlohmann::json::parse_event_t::object_start ||
             event == nlohmann::json::parse_event_t::array_start) &&
            depth >= kMaxJsonDepth) {
            too_deep = true;
            return false;
        }
        return true;
    };
    nlohmann::json j = nlohmann::json::parse(text.begin(), text.end(), cb,
                                             /*allow_exceptions=*/false,
                                             /*ignore_comments=*/true);
    out.too_deep = too_deep;
    if (too_deep || j.is_discarded())
        return out;
    out.value = std::move(j);
    out.ok = true;
    return out;
}

inline const nlohmann::json* member(const nlohmann::json& j, const char* key) {
    if (!j.is_object())
        return nullptr;
    const auto it = j.find(key);
    return it == j.end() ? nullptr : &*it;
}

inline const nlohmann::json* member_of_type(const nlohmann::json& j, const char* key,
                                            nlohmann::json::value_t t) {
    const auto* m = member(j, key);
    return (m && m->type() == t) ? m : nullptr;
}

// ---------------------------------------------------------------------------
// Per-field allow-lists (section 8)
// ---------------------------------------------------------------------------

inline constexpr std::string_view kInvalid = "invalid";

inline bool is_ascii_alnum(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/// The first byte is [A-Za-z0-9], every other byte is [A-Za-z0-9] or in `extra`. Checked over the
/// WHOLE value; the length cap is applied by the caller after.
inline bool charset_ok(std::string_view v, std::string_view extra) {
    if (v.empty() || !is_ascii_alnum(v.front()))
        return false;
    for (const char c : v)
        if (!is_ascii_alnum(c) && extra.find(c) == std::string_view::npos)
            return false;
    return true;
}

/// Charset check first, truncation second. A miss is the literal `invalid`.
inline std::string checked_field(std::string_view v, std::string_view extra, std::size_t cap) {
    if (!charset_ok(v, extra))
        return std::string{kInvalid};
    return std::string{v.substr(0, cap)};
}

inline std::string checked_name(std::string_view v) { return checked_field(v, "_.-", kFieldCap); }
inline std::string checked_image(std::string_view v) {
    return checked_field(v, "._:/@+-", kFieldCap);
}
inline std::string checked_network_mode(std::string_view v) {
    return checked_field(v, "_.:-", kShortFieldCap);
}
inline std::string checked_version(std::string_view v) {
    return checked_field(v, "._+-", kShortFieldCap);
}
inline std::string checked_config_string(std::string_view v) {
    return checked_field(v, "/._:@+-", kFieldCap);
}

/// The closed docker state enum; anything else reads `invalid`.
inline std::string checked_state(std::string_view v) {
    for (const std::string_view s :
         {"created", "running", "paused", "restarting", "removing", "exited", "dead"})
        if (v == s)
            return std::string{v};
    return std::string{kInvalid};
}

// ---------------------------------------------------------------------------
// /version
// ---------------------------------------------------------------------------

enum class Dialect { none, docker, podman };

inline std::string_view dialect_token(Dialect d) {
    switch (d) {
    case Dialect::docker:
        return "docker";
    case Dialect::podman:
        return "podman";
    case Dialect::none:
        return "-";
    }
    return "-";
}

struct VersionInfo {
    bool valid = false; ///< the reply was a JSON object
    Dialect dialect = Dialect::none;
    std::string version = "-";
    std::string api_version = "-";
};

/// `Components[].Name == "Podman Engine"` means podman; a docker-shaped or component-less object
/// means docker. A non-object reply is not valid (dialect none).
inline VersionInfo parse_version(const nlohmann::json& j) {
    VersionInfo v;
    if (!j.is_object())
        return v;
    v.valid = true;
    v.dialect = Dialect::docker;
    if (const auto* comps = member_of_type(j, "Components", nlohmann::json::value_t::array)) {
        for (const auto& c : *comps)
            if (const auto* n = member_of_type(c, "Name", nlohmann::json::value_t::string))
                if (n->get_ref<const std::string&>() == "Podman Engine")
                    v.dialect = Dialect::podman;
    }
    if (const auto* s = member_of_type(j, "Version", nlohmann::json::value_t::string))
        v.version = checked_version(s->get_ref<const std::string&>());
    if (const auto* s = member_of_type(j, "ApiVersion", nlohmann::json::value_t::string))
        v.api_version = checked_version(s->get_ref<const std::string&>());
    return v;
}

// ---------------------------------------------------------------------------
// /info: exactly three config rows, nothing else read (section 6)
// ---------------------------------------------------------------------------

struct ConfigRow {
    std::string key;
    std::string value;
};

inline std::vector<ConfigRow> parse_info(const nlohmann::json& j) {
    std::vector<ConfigRow> rows;
    if (!j.is_object())
        return rows;
    const auto* so = member_of_type(j, "SecurityOptions", nlohmann::json::value_t::array);
    if (so) {
        bool rootless = false;
        for (const auto& e : *so)
            if (e.is_string()) {
                const auto& s = e.get_ref<const std::string&>();
                if (s == "name=rootless" || s.rfind("name=rootless,", 0) == 0)
                    rootless = true;
            }
        rows.push_back({"rootless", rootless ? "yes" : "no"});
    }
    if (const auto* cg = member_of_type(j, "CgroupDriver", nlohmann::json::value_t::string))
        rows.push_back({"cgroup_driver", checked_config_string(cg->get_ref<const std::string&>())});
    if (so)
        rows.push_back({"security_options_count", std::to_string(so->size())});
    return rows;
}

// ---------------------------------------------------------------------------
// daemon.json: a fixed key allow-list (section 6)
// ---------------------------------------------------------------------------

struct DaemonJson {
    std::vector<ConfigRow> rows;
    bool malformed = false;
};

inline DaemonJson parse_daemon_json(std::string_view text) {
    DaemonJson out;
    const ParsedJson p = parse_limited(text);
    if (!p.ok || !p.value.is_object()) {
        out.malformed = true;
        return out;
    }
    const auto& j = p.value;
    for (const char* key : {"live-restore", "userns-remap", "no-new-privileges", "icc", "iptables",
                            "tls", "tlsverify", "data-root", "log-driver", "storage-driver",
                            "selinux-enabled", "userland-proxy"}) {
        const auto* m = member(j, key);
        if (!m)
            continue;
        if (m->is_boolean())
            out.rows.push_back({key, m->get<bool>() ? "yes" : "no"});
        else if (m->is_string()) {
            const std::string_view k{key};
            if (k == "userns-remap" || k == "data-root" || k == "log-driver" ||
                k == "storage-driver")
                out.rows.push_back({key, checked_config_string(m->get_ref<const std::string&>())});
        }
        // a value of any other type is skipped, never rendered
    }
    if (const auto* hosts = member_of_type(j, "hosts", nlohmann::json::value_t::array)) {
        bool tcp = false;
        for (const auto& h : *hosts)
            if (h.is_string() && h.get_ref<const std::string&>().rfind("tcp://", 0) == 0)
                tcp = true;
        out.rows.push_back({"hosts", std::to_string(hosts->size())});
        out.rows.push_back({"hosts_tcp", tcp ? "yes" : "no"});
    }
    for (const char* key : {"insecure-registries", "registry-mirrors"})
        if (const auto* a = member_of_type(j, key, nlohmann::json::value_t::array))
            out.rows.push_back({key, std::to_string(a->size())});
    return out;
}

// ---------------------------------------------------------------------------
// Containers (list + inspect)
// ---------------------------------------------------------------------------

struct ContainerRow {
    std::string id;   ///< the full validated id (never emitted; used for the inspect request)
    std::string id12; ///< its first 12 characters
    std::string name = "-";
    std::string image = "-";
    std::string state = std::string{kInvalid};
    Tri privileged = Tri::unknown;
    std::string network_mode = "unknown";
    Tri socket_mounted = Tri::unknown;
};

struct ContainerList {
    std::vector<ContainerRow> rows;
    bool malformed = false;       ///< the reply was not a JSON array
    bool rows_capped = false;     ///< more than kMaxContainerRows entries
    std::size_t skipped = 0;      ///< entries that were not objects or carried no valid Id
};

/// Reads Id, Names, Image and State of each entry and nothing else (Command, Labels, Mounts and
/// Ports are never read). At most kMaxContainerRows rows are kept.
inline ContainerList containers_from_list(const nlohmann::json& j) {
    ContainerList out;
    if (!j.is_array()) {
        out.malformed = true;
        return out;
    }
    for (const auto& e : j) {
        const auto* id = member_of_type(e, "Id", nlohmann::json::value_t::string);
        if (!id || !valid_container_id(id->get_ref<const std::string&>())) {
            ++out.skipped;
            continue;
        }
        if (out.rows.size() >= kMaxContainerRows) {
            out.rows_capped = true;
            break;
        }
        ContainerRow r;
        r.id = id->get_ref<const std::string&>();
        r.id12 = r.id.substr(0, 12);
        if (const auto* names = member_of_type(e, "Names", nlohmann::json::value_t::array);
            names && !names->empty() && names->front().is_string()) {
            std::string_view n = names->front().get_ref<const std::string&>();
            if (!n.empty() && n.front() == '/')
                n.remove_prefix(1);
            r.name = checked_name(n);
        }
        if (const auto* img = member_of_type(e, "Image", nlohmann::json::value_t::string))
            r.image = checked_image(img->get_ref<const std::string&>());
        if (const auto* st = member_of_type(e, "State", nlohmann::json::value_t::string))
            r.state = checked_state(st->get_ref<const std::string&>());
        out.rows.push_back(std::move(r));
    }
    return out;
}

/// `s` (normalised) is one of the default sockets or a directory that contains one.
inline bool mount_exposes_runtime_socket(std::string_view source) {
    const std::string s = normalise_path(source);
    if (s.empty() || s.front() != '/')
        return false;
    for (const auto d : kDefaultSockets) {
        if (s == d || s == "/")
            return true;
        if (d.size() > s.size() && d.substr(0, s.size()) == s && d[s.size()] == '/')
            return true;
    }
    return false;
}

/// Applies one inspect reply. Returns false (the row is left untouched) when the reply has no
/// object HostConfig, which is how a failed or wrong-typed inspect reads.
inline bool apply_inspect(ContainerRow& row, const nlohmann::json& j) {
    const auto* hc = member_of_type(j, "HostConfig", nlohmann::json::value_t::object);
    if (!hc)
        return false;
    if (const auto* p = member_of_type(*hc, "Privileged", nlohmann::json::value_t::boolean))
        row.privileged = p->get<bool>() ? Tri::yes : Tri::no;
    if (const auto* nm = member_of_type(*hc, "NetworkMode", nlohmann::json::value_t::string))
        row.network_mode = checked_network_mode(nm->get_ref<const std::string&>());
    const auto* mounts = member(j, "Mounts");
    if (mounts && mounts->is_null()) {
        row.socket_mounted = Tri::no;
    } else if (mounts && mounts->is_array()) {
        bool exposed = false;
        for (const auto& m : *mounts)
            if (const auto* src = member_of_type(m, "Source", nlohmann::json::value_t::string))
                if (mount_exposes_runtime_socket(src->get_ref<const std::string&>()))
                    exposed = true;
        row.socket_mounted = exposed ? Tri::yes : Tri::no;
    }
    // no Mounts key, or one of another type, leaves socket_mounted unknown: never rendered as no
    return true;
}

// ---------------------------------------------------------------------------
// Row formatters (every field through wire_field)
// ---------------------------------------------------------------------------

inline std::string join_row(std::initializer_list<std::string_view> fields) {
    std::string r;
    bool first = true;
    for (const auto f : fields) {
        if (!first)
            r += '|';
        r += wire_field(f);
        first = false;
    }
    return r;
}

inline std::string format_endpoint_row(EndpointStatus s, std::string_view reason,
                                       Dialect dialect) {
    return join_row({"endpoint", endpoint_status_token(s), reason, dialect_token(dialect)});
}

inline std::string format_runtime_row(std::string_view runtime, RuntimeDetection d,
                                      std::string_view socket_field, std::string_view config_field,
                                      std::string_view version, std::string_view api_version) {
    return join_row({"runtime", runtime, detection_token(d), socket_field, config_field, version,
                     api_version});
}

inline std::string format_config_row(std::string_view runtime, std::string_view key,
                                     std::string_view value) {
    return join_row({"config", runtime, key, value});
}

inline std::string format_container_row(std::string_view runtime, const ContainerRow& c) {
    return join_row({"container", runtime, c.id12, c.name, c.image, c.state, tri_token(c.privileged),
                     c.network_mode, tri_token(c.socket_mounted)});
}

} // namespace yuzu::virtualization::runtime
