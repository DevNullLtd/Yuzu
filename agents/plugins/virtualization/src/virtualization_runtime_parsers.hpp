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
//     that tolerate a wrong type. ONE rule for every reader (typed_member): a key it reads that is
//     absent omits its row or leaves the field unknown; a key present with another type, or a read
//     element of another type, makes that reader `malformed` (the caller adds the token) and
//     contributes nothing, while the well-typed keys still report. Each reader touches an
//     allow-list of keys and nothing else:
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
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
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

class Request;
inline std::optional<Request> build_request(Verb verb, std::string_view container_id = {});

/// One request the plugin may send. There is no way to make one outside the verb table: the
/// constructor is private and only build_request (below) uses it, so a test or a later change cannot
/// hand the transport a hand-written method or path.
class Request {
public:
    Verb verb() const { return verb_; }
    const std::string& method() const { return method_; }
    const std::string& path() const { return path_; }

private:
    Request(Verb verb, std::string method, std::string path)
        : verb_{verb}, method_{std::move(method)}, path_{std::move(path)} {}
    friend std::optional<Request> build_request(Verb, std::string_view);

    Verb verb_;
    std::string method_;
    std::string path_;
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
inline std::optional<Request> build_request(Verb verb, std::string_view container_id) {
    const auto index = static_cast<std::size_t>(verb);
    if (index >= kVerbs.size())
        return std::nullopt;
    const VerbRow& row = kVerbs[index];
    if (verb == Verb::container_inspect) {
        if (!valid_container_id(container_id))
            return std::nullopt;
        return Request{verb, std::string{row.method},
                       "/containers/" + std::string{container_id} + "/json"};
    }
    if (!container_id.empty())
        return std::nullopt;
    return Request{verb, std::string{row.method}, std::string{row.path_template}};
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

/// True iff some '/'-delimited segment of `p` is exactly "..". Bracketing `p` with '/' turns the
/// first and last segments into delimited ones, so "/../" occurs iff a ".." segment does (an empty
/// segment, as in "a//../b", hides nothing; "..." and "a..b" are not "..").
inline bool has_dotdot_segment(std::string_view p) {
    return ("/" + std::string{p} + "/").find("/../") != std::string::npos;
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

/// The cause segment of the `endpoint:<cause>` constraint token for an endpoint that could not be
/// used: its refusal reason, or `unreachable` for an endpoint path that is not there. Empty for
/// `unset` (the operator chose no endpoint) and `ok`: neither is a failed read.
inline std::string endpoint_failure_cause(EndpointVerdict v) {
    switch (v) {
    case EndpointVerdict::unset:
    case EndpointVerdict::ok:
        return {};
    case EndpointVerdict::absent:
        return "unreachable";
    default:
        return std::string{endpoint_reason_token(v)};
    }
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
/// the named errnos (a refused connection included); it reads `unreachable`.
enum class Outcome { ok, eacces, enoent, timeout, oversized, not_http, other };

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

/// How long before the read timeout still counts as the timeout having fired.
inline constexpr std::chrono::milliseconds kReadTimeoutSlack{50};

/// httplib reports an expired read timer as a plain read error, so the elapsed time tells a read that
/// ran out of time (`timeout`) from a peer that closed or spoke something that is not HTTP
/// (`not_http`). The shell supplies the two durations; this is the one timing decision.
inline Outcome classify_read_error(std::chrono::milliseconds elapsed,
                                   std::chrono::milliseconds read_timeout) {
    return elapsed >= read_timeout - kReadTimeoutSlack ? Outcome::timeout : Outcome::not_http;
}

/// The detection column: `served` when the endpoint's /version identified this runtime, else
/// `detected` when any standard-path artefact exists, else `not_detected`. An endpoint failure
/// never reaches here.
inline std::string_view decide_runtime(bool any_artefact, bool served) {
    return served ? "served" : any_artefact ? "detected" : "not_detected";
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
    return std::format("present:{:04o}:{}:{}", s.perm(), s.uid, s.gid);
}

/// `a` is `b` or lies under it, on a '/' boundary (`/ab` is not under `/a`). Callers special-case
/// `b` == "/".
inline bool path_is_or_under(std::string_view a, std::string_view b) {
    return a == b || (a.size() > b.size() && a.substr(0, b.size()) == b && a[b.size()] == '/');
}

/// `p` is `m`, is under `m`, or contains `m` (the mount table speaks in mount points).
inline bool path_touches_mount(std::string_view p, std::string_view m) {
    if (m == "/" || p == "/")
        return true;
    return path_is_or_under(p, m) || path_is_or_under(m, p);
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

/// The typed read every JSON reader below uses for a key it reads. Absent: nullptr and nothing
/// recorded (the row is omitted or stays unknown; a missing key is never wrong-typed). Present with
/// another type, null included: nullptr and `malformed` set, so the reader reports a token beside
/// whatever well-typed keys it still read. `malformed` is only ever set here, never cleared.
inline const nlohmann::json* typed_member(const nlohmann::json& j, const char* key,
                                          nlohmann::json::value_t t, bool& malformed) {
    const auto* m = member(j, key);
    if (m && m->type() != t) {
        malformed = true;
        return nullptr;
    }
    return m;
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
    /// The reply was not a JSON object, or a key read below was present with another type
    /// (Version, ApiVersion, Components, a Components element, an element's Name).
    bool malformed = false;
    Dialect dialect = Dialect::none;
    std::string version = "-";
    std::string api_version = "-";
};

/// `Components[].Name == "Podman Engine"` means podman; a docker-shaped or component-less object
/// means docker. The dialect comes from a well-typed Components only: a malformed Components, and a
/// non-object reply, give Dialect::none. A wrong-typed Version or ApiVersion stays `-` and the
/// reply is malformed; the dialect is unaffected by them.
inline VersionInfo parse_version(const nlohmann::json& j) {
    VersionInfo v;
    if (!j.is_object()) {
        v.malformed = true;
        return v;
    }
    bool comps_malformed = false;
    bool podman = false;
    if (const auto* comps =
            typed_member(j, "Components", nlohmann::json::value_t::array, comps_malformed)) {
        for (const auto& c : *comps) {
            if (!c.is_object()) {
                comps_malformed = true;
                continue;
            }
            if (const auto* n =
                    typed_member(c, "Name", nlohmann::json::value_t::string, comps_malformed))
                podman = podman || n->get_ref<const std::string&>() == "Podman Engine";
        }
    }
    v.malformed = comps_malformed;
    v.dialect = comps_malformed ? Dialect::none : (podman ? Dialect::podman : Dialect::docker);
    if (const auto* s = typed_member(j, "Version", nlohmann::json::value_t::string, v.malformed))
        v.version = checked_version(s->get_ref<const std::string&>());
    if (const auto* s =
            typed_member(j, "ApiVersion", nlohmann::json::value_t::string, v.malformed))
        v.api_version = checked_version(s->get_ref<const std::string&>());
    return v;
}

// ---------------------------------------------------------------------------
// /info: at most three config rows, nothing else read (section 6)
// ---------------------------------------------------------------------------

struct ConfigRow {
    std::string key;
    std::string value;
};

/// What a config parser returns: the rows it admitted, and whether the source was malformed.
struct ConfigRows {
    std::vector<ConfigRow> rows;
    bool malformed = false;
};

/// malformed: the reply was not an object, or SecurityOptions (or one of its elements) or
/// CgroupDriver was present with the wrong type. A wrong-typed SecurityOptions contributes no row
/// at all (a non-string element means "rootless" cannot be told, never `no`); a key that is simply
/// absent omits its row and is not malformed (same visibility as a key missing from daemon.json).
inline ConfigRows parse_info(const nlohmann::json& j) {
    ConfigRows out;
    if (!j.is_object()) {
        out.malformed = true;
        return out;
    }
    const auto* so =
        typed_member(j, "SecurityOptions", nlohmann::json::value_t::array, out.malformed);
    bool rootless = false;
    if (so) {
        for (const auto& e : *so) {
            if (!e.is_string()) {
                out.malformed = true;
                so = nullptr;
                break;
            }
            const auto& s = e.get_ref<const std::string&>();
            if (s == "name=rootless" || s.rfind("name=rootless,", 0) == 0)
                rootless = true;
        }
    }
    if (so)
        out.rows.push_back({"rootless", rootless ? "yes" : "no"});
    if (const auto* cg =
            typed_member(j, "CgroupDriver", nlohmann::json::value_t::string, out.malformed))
        out.rows.push_back({"cgroup_driver", checked_config_string(cg->get_ref<const std::string&>())});
    if (so)
        out.rows.push_back({"security_options_count", std::to_string(so->size())});
    return out;
}

// ---------------------------------------------------------------------------
// daemon.json: a fixed key allow-list (section 6)
// ---------------------------------------------------------------------------

/// malformed: the text is not a JSON object, or an allow-listed key is present with the wrong type
/// (or a `hosts` element is not a string). The well-typed keys still report; the wrong-typed one
/// contributes no row, never a row read through another type's path.
inline ConfigRows parse_daemon_json(std::string_view text) {
    ConfigRows out;
    const ParsedJson p = parse_limited(text);
    if (!p.ok || !p.value.is_object()) {
        out.malformed = true;
        return out;
    }
    const auto& j = p.value;
    // One list, each key admitted only through its own type: a boolean on a string key (or a string
    // on a boolean one) is withheld and the file reads malformed. Row order follows this list.
    struct Key {
        const char* name;
        nlohmann::json::value_t type;
    };
    constexpr auto kBool = nlohmann::json::value_t::boolean;
    constexpr auto kString = nlohmann::json::value_t::string;
    for (const Key& k : {Key{"live-restore", kBool}, Key{"userns-remap", kString},
                         Key{"no-new-privileges", kBool}, Key{"icc", kBool},
                         Key{"iptables", kBool}, Key{"tls", kBool}, Key{"tlsverify", kBool},
                         Key{"data-root", kString}, Key{"log-driver", kString},
                         Key{"storage-driver", kString}, Key{"selinux-enabled", kBool},
                         Key{"userland-proxy", kBool}}) {
        const auto* m = typed_member(j, k.name, k.type, out.malformed);
        if (!m)
            continue; // absent: omitted; of another type: omitted and malformed
        if (k.type == kBool)
            out.rows.push_back({k.name, m->get<bool>() ? "yes" : "no"});
        else
            out.rows.push_back({k.name, checked_config_string(m->get_ref<const std::string&>())});
    }
    if (const auto* hosts =
            typed_member(j, "hosts", nlohmann::json::value_t::array, out.malformed)) {
        bool tcp = false;
        bool all_strings = true;
        for (const auto& h : *hosts) {
            if (!h.is_string()) {
                all_strings = false;
                break;
            }
            if (h.get_ref<const std::string&>().rfind("tcp://", 0) == 0)
                tcp = true;
        }
        if (all_strings) {
            out.rows.push_back({"hosts", std::to_string(hosts->size())});
            out.rows.push_back({"hosts_tcp", tcp ? "yes" : "no"});
        } else {
            out.malformed = true; // `hosts_tcp no` over an unreadable element would be a guess
        }
    }
    for (const char* key : {"insecure-registries", "registry-mirrors"})
        if (const auto* a = typed_member(j, key, nlohmann::json::value_t::array, out.malformed))
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
    /// The reply was not a JSON array, or a key read from an entry (Names, its first element,
    /// Image, State) was present with another type. The rows are kept; the field reads `-` /
    /// `invalid`.
    bool malformed = false;
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
        if (const auto* names =
                typed_member(e, "Names", nlohmann::json::value_t::array, out.malformed);
            names && !names->empty()) {
            if (names->front().is_string()) {
                std::string_view n = names->front().get_ref<const std::string&>();
                if (!n.empty() && n.front() == '/')
                    n.remove_prefix(1);
                r.name = checked_name(n);
            } else {
                out.malformed = true;
            }
        }
        if (const auto* img =
                typed_member(e, "Image", nlohmann::json::value_t::string, out.malformed))
            r.image = checked_image(img->get_ref<const std::string&>());
        if (const auto* st =
                typed_member(e, "State", nlohmann::json::value_t::string, out.malformed))
            r.state = checked_state(st->get_ref<const std::string&>());
        out.rows.push_back(std::move(r));
    }
    return out;
}

/// `source` (normalised) is one of the default sockets or a directory that contains one.
inline bool mount_exposes_runtime_socket(std::string_view source) {
    const std::string s = normalise_path(source);
    if (s.empty() || s.front() != '/')
        return false;
    for (const auto d : kDefaultSockets)
        if (s == "/" || path_is_or_under(d, s))
            return true;
    return false;
}

/// Applies one inspect reply, all or nothing. Returns false (the row is left untouched, so its
/// three inspect fields stay unknown) when the reply has no object HostConfig or any key read is
/// wrong-typed: HostConfig.Privileged, HostConfig.NetworkMode, Mounts (neither null nor an array),
/// a Mounts element that is not an object, or a Mounts[].Source that is present and not a string.
/// A missing key leaves its field unknown, never `no`; a mount object without Source (tmpfs)
/// mounts no host path.
inline bool apply_inspect(ContainerRow& row, const nlohmann::json& j) {
    const auto* hc = member_of_type(j, "HostConfig", nlohmann::json::value_t::object);
    if (!hc)
        return false;
    bool bad = false;
    Tri privileged = row.privileged;
    std::string network_mode = row.network_mode;
    Tri socket_mounted = row.socket_mounted;
    if (const auto* p = typed_member(*hc, "Privileged", nlohmann::json::value_t::boolean, bad))
        privileged = p->get<bool>() ? Tri::yes : Tri::no;
    if (const auto* nm = typed_member(*hc, "NetworkMode", nlohmann::json::value_t::string, bad))
        network_mode = checked_network_mode(nm->get_ref<const std::string&>());
    if (const auto* mounts = member(j, "Mounts")) {
        if (mounts->is_null()) {
            socket_mounted = Tri::no;
        } else if (mounts->is_array()) {
            bool exposed = false;
            for (const auto& m : *mounts) {
                if (!m.is_object()) {
                    bad = true;
                    break;
                }
                if (const auto* src =
                        typed_member(m, "Source", nlohmann::json::value_t::string, bad))
                    exposed = exposed ||
                              mount_exposes_runtime_socket(src->get_ref<const std::string&>());
            }
            socket_mounted = exposed ? Tri::yes : Tri::no;
        } else {
            bad = true;
        }
    }
    // no Mounts key leaves socket_mounted unknown: never rendered as no
    if (bad)
        return false;
    row.privileged = privileged;
    row.network_mode = std::move(network_mode);
    row.socket_mounted = socket_mounted;
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

inline std::string format_runtime_row(std::string_view runtime, std::string_view detection,
                                      std::string_view socket_field, std::string_view config_field,
                                      std::string_view version, std::string_view api_version) {
    return join_row({"runtime", runtime, detection, socket_field, config_field, version,
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
