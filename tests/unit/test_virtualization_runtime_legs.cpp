/**
 * test_virtualization_runtime_legs.cpp -- tests for the OS-free `runtime_posture_linux` seam: every
 * boundary (stat, bounded read, the endpoint open, the transport and the clock) is a canned fake,
 * so no socket is opened, no file is read and no time passes. The recording transport is the point:
 * it proves WHICH requests the action can send, and that it sends none when it must not.
 *
 * Fixture provenance: every JSON body is SYNTHETIC, shaped from the documented docker engine and
 * podman compatibility replies.
 */
#include <catch2/catch_test_macros.hpp>

#include "virtualization_legs.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <format>
#include <initializer_list>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::virtualization;
using namespace yuzu::virtualization::runtime;

namespace {

constexpr const char* kEndpoint = "/run/yuzu-agent/runtime.sock";
constexpr std::uint32_t kEgid = 998;
using std::chrono::milliseconds;
using std::chrono::seconds;

StatResult sock(std::uint32_t uid, std::uint32_t gid, std::uint32_t perm, std::uint64_t ino) {
    StatResult s;
    s.mode = 0140000u | perm;
    s.uid = uid;
    s.gid = gid;
    s.dev = 1;
    s.ino = ino;
    return s;
}
StatResult dir(std::uint32_t uid = 0, std::uint32_t perm = 0755) {
    StatResult s;
    s.mode = 0040000u | perm;
    s.uid = uid;
    return s;
}
StatResult regular() {
    StatResult s;
    s.mode = 0100644u;
    return s;
}
StatResult errno_stat(int e) {
    StatResult s;
    s.err = e;
    return s;
}
std::string id(char c) { return std::string(64, c); }

TransportResult http(int status, std::string body) {
    TransportResult r;
    r.outcome = Outcome::ok;
    r.http_status = status;
    r.body = std::move(body);
    return r;
}
TransportResult fail(Outcome o) {
    TransportResult r;
    r.outcome = o;
    return r;
}

const std::string kDockerVersion =
    R"({"Version":"27.3.1","ApiVersion":"1.47","Components":[{"Name":"Engine","Version":"27.3.1"}]})";
const std::string kPodmanVersion =
    R"({"Version":"5.2.0","ApiVersion":"1.41","Components":[{"Name":"Podman Engine","Version":"5.2.0"}]})";
const std::string kInfo =
    R"({"CgroupDriver":"systemd","SecurityOptions":["name=seccomp,profile=builtin"],"Name":"leaky-host"})";

std::string list_of(std::initializer_list<char> ids) {
    std::string out = "[";
    bool first = true;
    for (const char c : ids) {
        if (!first)
            out += ',';
        first = false;
        out += R"({"Id":")" + id(c) + R"(","Names":["/c-)" + std::string(1, c) +
               R"("],"Image":"img:1","State":"running","Command":"x","Labels":{"a":"b"}})";
    }
    return out + "]";
}
std::string inspect_body(bool privileged, const std::string& mount = "/data") {
    return std::string(R"({"HostConfig":{"Privileged":)") + (privileged ? "true" : "false") +
           R"(,"NetworkMode":"bridge"},"Mounts":[{"Source":")" + mount +
           R"("}],"Config":{"Env":["TOKEN=leak"]}})";
}

/// All boundaries canned. A path missing from `stats` reads ENOENT; a request path missing from
/// `replies` reads as a connect refusal.
struct Fake {
    std::map<std::string, StatResult> stats;
    std::map<std::string, FieldRead> reads;
    StatResult endpoint_leaf = sock(0, kEgid, 0660, 500);
    std::map<std::string, TransportResult> replies;
    std::vector<std::string> default_socket_paths_present;
    std::vector<std::string> network_mounts;
    bool mountinfo_unreadable = false;
    std::vector<std::uint32_t> groups{kEgid};

    // recordings
    std::vector<Request> calls;
    std::vector<milliseconds> budgets;
    std::vector<std::string> stat_calls;
    std::vector<std::string> opened;

    // clock: each transport call advances it by `step`, or by `path_step[path]` when that has an entry
    // (a fake peer that took that long to answer, whatever budget it was given)
    std::chrono::steady_clock::time_point now{std::chrono::steady_clock::time_point{} + seconds{1000}};
    milliseconds step{0};
    std::map<std::string, milliseconds> path_step;

    Fake() {
        for (const char* d : {"/run/yuzu-agent", "/run", "/"})
            stats[d] = dir();
    }

    void with_docker_socket() { stats["/run/docker.sock"] = sock(0, 999, 0660, 100); }
    void reply(const std::string& path, TransportResult r) { replies[path] = std::move(r); }
    void happy_version() { reply("/version", http(200, kDockerVersion)); }

    Posture run(std::string_view endpoint) {
        RuntimeFs fs;
        fs.stat = [this](const std::string& p) {
            stat_calls.push_back(p);
            const auto it = stats.find(p);
            return it == stats.end() ? errno_stat(ENOENT) : it->second;
        };
        fs.read = [this](const std::string& p, std::size_t) {
            const auto it = reads.find(p);
            return it == reads.end() ? FieldRead{} : it->second;
        };
        fs.open_endpoint = [this](const std::string& p) {
            opened.push_back(p);
            return endpoint_leaf;
        };
        fs.network_mounts = network_mounts;
        fs.mountinfo_unreadable = mountinfo_unreadable;
        fs.egid = kEgid;
        fs.groups = groups;
        const Transport transport = [this](const Request& req, milliseconds budget) {
            calls.push_back(req);
            budgets.push_back(budget);
            const auto slow = path_step.find(req.path());
            now += slow == path_step.end() ? step : slow->second;
            const auto it = replies.find(req.path());
            return it == replies.end() ? fail(Outcome::other) : it->second;
        };
        const Clock clock = [this] { return now; };
        return runtime_posture_linux(fs, transport, clock, endpoint);
    }
};

bool starts_with(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }

std::vector<std::string> rows_with(const Posture& p, const std::string& prefix) {
    std::vector<std::string> out;
    for (const auto& r : p.rows)
        if (starts_with(r, prefix))
            out.push_back(r);
    return out;
}

bool has_token(const Posture& p, const std::string& tail) {
    return p.reason.find(rt_token(tail)) != std::string::npos;
}

const std::set<std::string> kAllowedPaths{"/version", "/info", "/containers/json?all=1"};
bool allowed_path(const std::string& path) {
    static const std::regex inspect{"^/containers/[0-9a-f]{12,64}/json$"};
    return kAllowedPaths.count(path) == 1 || std::regex_match(path, inspect);
}

} // namespace

TEST_CASE("runtime seam: no endpoint means the transport is never invoked and detection still reports",
          "[virtualization][runtime][seam]") {
    Fake f;
    f.with_docker_socket();
    f.stats["/etc/containerd/config.toml"] = regular();
    f.reads["/etc/docker/daemon.json"] = FieldRead{ReadState::ok, R"({"live-restore":true})", ""};
    const Posture p = f.run("");

    CHECK(f.calls.empty());
    CHECK(f.opened.empty()); // not even the endpoint is opened
    CHECK(p.status == StatusState::supported);
    CHECK(p.reason.empty());
    REQUIRE(p.rows.size() >= 5);
    CHECK(p.rows[0] == "endpoint|unset|-|-");
    CHECK(p.rows[1] == "runtime|docker|detected|present:0660:0:999|present|-|-");
    CHECK(p.rows[2] == "runtime|podman|not_detected|absent|absent|-|-");
    CHECK(p.rows[3] == "runtime|containerd|detected|absent|present|-|-");
    CHECK(rows_with(p, "runtime|").size() == 3);
    CHECK(rows_with(p, "config|docker|live-restore|yes").size() == 1);
    CHECK(rows_with(p, "container|").empty());
}

TEST_CASE("runtime seam: a default socket as the endpoint is refused by path and by inode with no "
          "connect, and no runtime row changes",
          "[virtualization][runtime][seam]") {
    Fake base;
    base.with_docker_socket();
    const Posture unset = base.run("");

    for (const char* ep : {"/var/run/docker.sock", "/run/docker.sock", "//run//docker.sock",
                           "/run/./docker.sock", "/run/podman/podman.sock",
                           "/run/containerd/containerd.sock"}) {
        Fake f;
        f.with_docker_socket();
        const Posture p = f.run(ep);
        INFO(ep);
        CHECK(f.calls.empty());
        CHECK(f.opened.empty()); // refused lexically, before anything is opened
        REQUIRE_FALSE(p.rows.empty());
        CHECK(p.rows[0] == "endpoint|endpoint_refused|default_socket|-");
        CHECK(std::vector<std::string>(p.rows.begin() + 1, p.rows.end()) ==
              std::vector<std::string>(unset.rows.begin() + 1, unset.rows.end()));
        // a configured endpoint that was refused is a failed read: constrained, with its cause named
        CHECK(p.status == StatusState::constrained);
        CHECK(has_token(p, "endpoint:default_socket"));
    }
    CHECK(unset.status == StatusState::supported); // ... while no endpoint at all is not

    // an alias: another path whose inode IS the default socket's (bind mount, hard link)
    Fake alias;
    alias.with_docker_socket();
    alias.endpoint_leaf = sock(0, 999, 0660, 100); // same (dev, ino) as /run/docker.sock
    const Posture a = alias.run(kEndpoint);
    CHECK(alias.calls.empty());
    CHECK(a.rows[0] == "endpoint|endpoint_refused|same_inode|-");
    CHECK(a.status == StatusState::constrained);
    CHECK(has_token(a, "endpoint:same_inode"));

    // a symlink leaf is a refusal of its own kind
    Fake link;
    StatResult l;
    l.mode = 0120777u;
    link.endpoint_leaf = l;
    const Posture l_run = link.run(kEndpoint);
    CHECK(l_run.rows[0] == "endpoint|endpoint_refused|symlink|-");
    CHECK(has_token(l_run, "endpoint:symlink"));
    CHECK(link.calls.empty());
}

TEST_CASE("runtime seam: every endpoint property refuses before the transport", "[virtualization][runtime][seam]") {
    const auto refused = [](Fake& f, const char* ep, const char* reason) {
        const Posture p = f.run(ep);
        INFO(reason);
        CHECK(f.calls.empty());
        REQUIRE_FALSE(p.rows.empty());
        CHECK(p.rows[0] == std::string{"endpoint|endpoint_refused|"} + reason + "|-");
        CHECK(p.status == StatusState::constrained);
        CHECK(has_token(p, std::string{"endpoint:"} + reason));
    };
    {
        Fake f;
        refused(f, "relative.sock", "relative");
    }
    {
        Fake f;
        refused(f, "/run/../etc/x", "dotdot");
    }
    {
        Fake f;
        refused(f, ("/" + std::string(120, 'a')).c_str(), "too_long");
    }
    {
        Fake f;
        f.endpoint_leaf = sock(1000, kEgid, 0660, 500);
        refused(f, kEndpoint, "owner");
    }
    {
        Fake f;
        f.endpoint_leaf = sock(0, 4, 0660, 500);
        refused(f, kEndpoint, "group");
    }
    {
        Fake f;
        f.endpoint_leaf = sock(0, kEgid, 0666, 500);
        refused(f, kEndpoint, "mode");
    }
    {
        Fake f;
        f.endpoint_leaf = dir();
        refused(f, kEndpoint, "not_socket");
    }
    {
        Fake f;
        f.endpoint_leaf = errno_stat(EACCES); // any stat error but ENOENT refuses
        refused(f, kEndpoint, "stat_error");
    }
    {
        Fake f;
        f.stats["/run/yuzu-agent"] = dir(1000, 0755); // an agent-owned directory
        refused(f, kEndpoint, "insecure_ancestor");
    }
    {
        Fake f;
        f.stats["/run"] = dir(0, 0777);
        refused(f, kEndpoint, "insecure_ancestor");
    }
    {
        Fake f;
        f.stats["/"] = errno_stat(EACCES);
        refused(f, kEndpoint, "stat_error");
    }
    {
        // ENOENT on the endpoint is not a refusal: it is `unreachable`
        Fake f;
        f.endpoint_leaf = errno_stat(ENOENT);
        const Posture p = f.run(kEndpoint);
        CHECK(f.calls.empty());
        CHECK(p.rows[0] == "endpoint|unreachable|-|-");
        CHECK(p.status == StatusState::constrained); // ... but it is a failed read all the same
        CHECK(has_token(p, "endpoint:unreachable"));
    }
}

TEST_CASE("runtime seam: an endpoint whose descriptor cannot be checked is a failed read, not a clean one",
          "[virtualization][runtime][seam]") {
    // fstat of the opened descriptor refused (EACCES): refused as stat_error, constrained, no connect
    Fake f;
    f.with_docker_socket();
    f.endpoint_leaf = errno_stat(EACCES);
    const Posture p = f.run(kEndpoint);
    CHECK(f.calls.empty());
    CHECK(p.status == StatusState::constrained);
    CHECK(p.reason == rt_token("endpoint:stat_error"));
    CHECK(p.rows[0] == "endpoint|endpoint_refused|stat_error|-");
    CHECK(p.rows[1] == "runtime|docker|detected|present:0660:0:999|absent|-|-"); // runtimes untouched
}

TEST_CASE("runtime seam: a configured endpoint answers; every request is a GET on an allowlisted path",
          "[virtualization][runtime][seam]") {
    Fake f;
    f.with_docker_socket();
    f.happy_version();
    f.reply("/info", http(200, kInfo));
    f.reply("/containers/json?all=1", http(200, list_of({'a', 'b', 'c'})));
    f.reply("/containers/" + id('a') + "/json", http(200, inspect_body(true)));
    f.reply("/containers/" + id('b') + "/json", http(200, inspect_body(false)));
    f.reply("/containers/" + id('c') + "/json", http(200, inspect_body(false, "/var/run")));
    const Posture p = f.run(kEndpoint);

    CHECK(f.opened == std::vector<std::string>{kEndpoint});
    REQUIRE(f.calls.size() == 6); // version, info, list and exactly three inspections
    for (const auto& c : f.calls) {
        CHECK(c.method() == "GET");
        CHECK(allowed_path(c.path()));
    }
    CHECK(p.status == StatusState::supported);
    CHECK(p.reason.empty());

    CHECK(p.rows[0] == "endpoint|ok|-|docker");
    CHECK(p.rows[1] == "runtime|docker|served|present:0660:0:999|absent|27.3.1|1.47");
    CHECK(p.rows[2] == "runtime|podman|not_detected|absent|absent|-|-");
    CHECK(p.rows[3] == "runtime|containerd|not_detected|absent|absent|-|-");
    CHECK(rows_with(p, "config|docker|rootless|no").size() == 1);
    CHECK(rows_with(p, "config|docker|cgroup_driver|systemd").size() == 1);
    CHECK(rows_with(p, "config|docker|security_options_count|1").size() == 1);
    const auto containers = rows_with(p, "container|");
    REQUIRE(containers.size() == 3);
    CHECK(containers[0] == "container|docker|aaaaaaaaaaaa|c-a|img:1|running|yes|bridge|no");
    CHECK(containers[1] == "container|docker|bbbbbbbbbbbb|c-b|img:1|running|no|bridge|no");
    CHECK(containers[2] == "container|docker|cccccccccccc|c-c|img:1|running|no|bridge|yes");

    // nothing from outside the reader allow-lists reaches the output
    std::string all;
    for (const auto& r : p.rows)
        all += r + "\n";
    for (const char* leak : {"leaky-host", "TOKEN", "leak", "Labels"})
        CHECK(all.find(leak) == std::string::npos);

    // every inspection carried a positive budget
    for (const auto b : f.budgets)
        CHECK(b.count() >= 1);
}

TEST_CASE("runtime seam: a podman answer marks podman served, not docker", "[virtualization][runtime][seam]") {
    Fake f;
    f.with_docker_socket();
    f.reply("/version", http(200, kPodmanVersion));
    f.reply("/info", http(200, kInfo));
    f.reply("/containers/json?all=1", http(200, "[]"));
    const Posture p = f.run(kEndpoint);
    CHECK(p.rows[0] == "endpoint|ok|-|podman");
    CHECK(p.rows[1] == "runtime|docker|detected|present:0660:0:999|absent|-|-");
    CHECK(p.rows[2] == "runtime|podman|served|absent|absent|5.2.0|1.41");
    CHECK(rows_with(p, "config|podman|rootless|no").size() == 1);
    CHECK(f.calls.size() == 3); // an empty list needs no inspection
}

TEST_CASE("runtime seam: endpoint failures own the endpoint row and change no runtime row",
          "[virtualization][runtime][seam]") {
    Fake base;
    base.with_docker_socket();
    const Posture unset = base.run("");
    const std::vector<std::string> runtimes(unset.rows.begin() + 1, unset.rows.begin() + 4);

    struct Case {
        Outcome outcome;
        const char* row;
        const char* token; // the failed /version read, which constrains the status
    };
    for (const auto& c : {Case{Outcome::eacces, "endpoint|permission_denied|-|-", "version:permission_denied"},
                          Case{Outcome::enoent, "endpoint|unreachable|-|-", "version:unreachable"},
                          // a peer that never completes /version inside the budget: unreachable, with
                          // the cause named so the status cannot read as a clean answer
                          Case{Outcome::timeout, "endpoint|unreachable|-|-", "version:timeout"},
                          Case{Outcome::other, "endpoint|unreachable|-|-", "version:unreachable"},
                          Case{Outcome::not_http, "endpoint|not_http|-|-", "version:not_http"},
                          Case{Outcome::oversized, "endpoint|not_http|-|-",
                               "version:response_oversized"}}) {
        Fake f;
        f.with_docker_socket();
        f.reply("/version", fail(c.outcome));
        const Posture p = f.run(kEndpoint);
        INFO(c.row);
        CHECK(f.calls.size() == 1); // the first failure stops the action
        CHECK(p.rows[0] == c.row);
        CHECK(std::vector<std::string>(p.rows.begin() + 1, p.rows.begin() + 4) == runtimes);
        CHECK(rows_with(p, "container|").empty());
        CHECK(p.status == StatusState::constrained);
        CHECK(p.reason == rt_token(c.token)); // exactly this cause, and nothing else
    }

    // a 200 with a body that is not JSON: connected, but not a runtime API (a containerd socket)
    Fake f;
    f.reply("/version", http(200, "\x00\x00\x12\x04 not json"));
    const Posture p = f.run(kEndpoint);
    CHECK(p.rows[0] == "endpoint|not_http|-|-");
    CHECK(f.calls.size() == 1);
    CHECK(p.status == StatusState::constrained);
    CHECK(p.reason == rt_token("version:not_http"));
}

TEST_CASE("runtime seam: per-response recovery keeps earlier rows and runs later verbs",
          "[virtualization][runtime][seam]") {
    SECTION("a 403 on the list keeps the endpoint and the version row") {
        Fake f;
        f.with_docker_socket();
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(403, "denied"));
        const Posture p = f.run(kEndpoint);
        CHECK(p.status == StatusState::constrained);
        CHECK(has_token(p, "list:http_403"));
        CHECK(p.rows[0] == "endpoint|ok|-|docker");
        CHECK(p.rows[1] == "runtime|docker|served|present:0660:0:999|absent|27.3.1|1.47");
        CHECK(rows_with(p, "container|").empty());
        CHECK(f.calls.size() == 3);
    }
    SECTION("a 403 on /version still lets the later verbs run, with no dialect") {
        Fake f;
        f.reply("/version", http(403, ""));
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "version:http_403"));
        CHECK(p.rows[0] == "endpoint|ok|-|-");
        CHECK(f.calls.size() == 3);
        for (const auto& r : rows_with(p, "runtime|"))
            CHECK(r.find("|served|") == std::string::npos);
        CHECK(rows_with(p, "config|-|cgroup_driver|systemd").size() == 1);
    }
    SECTION("a /version that names no runtime identifies none: no served row, `-` rows, no token") {
        for (const char* body : {"{}", R"({"message":"ok"})", R"({"Version":"27.3.1"})"}) {
            Fake f;
            f.with_docker_socket();
            f.reply("/version", http(200, body));
            f.reply("/info", http(200, kInfo));
            f.reply("/containers/json?all=1", http(200, list_of({'a'})));
            f.reply("/containers/" + id('a') + "/json", http(200, inspect_body(false)));
            const Posture p = f.run(kEndpoint);
            INFO(body);
            // the endpoint answered, and a well-typed reply that names nothing is not a misread
            CHECK(p.status == StatusState::supported);
            CHECK(p.reason.empty());
            CHECK(p.rows[0] == "endpoint|ok|-|-");
            CHECK(p.rows[1] == "runtime|docker|detected|present:0660:0:999|absent|-|-");
            for (const auto& r : p.rows)
                CHECK(r.find("|served|") == std::string::npos);
            CHECK(rows_with(p, "config|-|cgroup_driver|systemd").size() == 1);
            CHECK(rows_with(p, "container|-|aaaaaaaaaaaa|c-a|img:1|running|no|bridge|no").size() == 1);
            CHECK(f.calls.size() == 4); // the later verbs still ran
        }
    }
    SECTION("a malformed /info keeps going: token, no info rows, list and inspections run") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, "{oops"));
        f.reply("/containers/json?all=1", http(200, list_of({'a'})));
        f.reply("/containers/" + id('a') + "/json", http(200, inspect_body(false)));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "info:malformed"));
        CHECK(p.status == StatusState::constrained);
        CHECK(rows_with(p, "config|").empty());
        CHECK(rows_with(p, "container|").size() == 1);
        CHECK(f.calls.size() == 4);
    }
    SECTION("an /info that is not an object is malformed and the list still runs") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, "[]"));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "info:malformed"));
        CHECK(p.status == StatusState::constrained);
        CHECK(rows_with(p, "config|").empty());
        CHECK(f.calls.size() == 3); // version, info and the list all ran
    }
    SECTION("a wrong-typed /info key is malformed; the well-typed key still reports") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, R"({"CgroupDriver":"systemd","SecurityOptions":5})"));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "info:malformed"));
        CHECK(p.status == StatusState::constrained);
        CHECK(rows_with(p, "config|docker|cgroup_driver|systemd").size() == 1);
        CHECK(rows_with(p, "config|docker|rootless|").empty()); // unknown is never rendered as no
    }
    SECTION("a non-string SecurityOptions element is malformed: no rootless row, never `rootless no`") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, R"({"CgroupDriver":"systemd","SecurityOptions":[5]})"));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "info:malformed"));
        CHECK(p.status == StatusState::constrained);
        CHECK(rows_with(p, "config|docker|cgroup_driver|systemd").size() == 1);
        CHECK(rows_with(p, "config|docker|rootless|").empty());
        CHECK(rows_with(p, "config|docker|security_options_count|").empty());
    }
    SECTION("a missing /info key only omits its row") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, R"({"CgroupDriver":"systemd"})"));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        CHECK(p.status == StatusState::supported);
        CHECK(p.reason.empty());
        CHECK(rows_with(p, "config|docker|cgroup_driver|systemd").size() == 1);
        CHECK(rows_with(p, "config|docker|security_options_count|").empty());
    }
    SECTION("a wrong-typed list is malformed, not thrown on") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, R"({"Id":"x"})"));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "list:malformed"));
        CHECK(rows_with(p, "container|").empty());
    }
    SECTION("an oversized list reply yields a token and no container rows") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", fail(Outcome::oversized));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "list:response_oversized"));
        CHECK(p.status == StatusState::constrained);
        CHECK(rows_with(p, "container|").empty());
        CHECK(p.rows[0] == "endpoint|ok|-|docker");
    }
    SECTION("a wrong-typed list entry key keeps the row and constrains with list:malformed") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1",
                http(200, R"([{"Id":")" + id('a') + R"(","Names":["/c-a"],"Image":5,"State":"running"}])"));
        f.reply("/containers/" + id('a') + "/json", http(200, inspect_body(false)));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "list:malformed"));
        CHECK(p.status == StatusState::constrained);
        CHECK(rows_with(p, "container|docker|" + id('a').substr(0, 12) + "|c-a|-|running|no|bridge|no").size() == 1);
    }
    SECTION("a wrong-typed inspect key is a failed inspection: fields unknown, counted") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, list_of({'a', 'b'})));
        f.reply("/containers/" + id('a') + "/json",
                http(200, R"({"HostConfig":{"Privileged":"yes"},"Mounts":[]})"));
        f.reply("/containers/" + id('b') + "/json",
                http(200, R"({"HostConfig":{"Privileged":true},"Mounts":[5]})"));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "inspect:failed:2"));
        CHECK(p.status == StatusState::constrained);
        CHECK(rows_with(p, "container|docker|" + id('a').substr(0, 12) +
                               "|c-a|img:1|running|unknown|unknown|unknown")
                  .size() == 1);
        CHECK(rows_with(p, "container|docker|" + id('b').substr(0, 12) +
                               "|c-b|img:1|running|unknown|unknown|unknown")
                  .size() == 1);
        CHECK(f.calls.size() == 5); // version, info, list and both inspections still ran
    }
    SECTION("a /version with a wrong-typed key is malformed, never a clean OK") {
        Fake f;
        f.reply("/version", http(200, R"({"Version":27,"ApiVersion":"1.47"})"));
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "version:malformed"));
        CHECK(p.status == StatusState::constrained);
        // no component names an engine, but the string ApiVersion identifies docker; the wrong-typed
        // Version stays `-`
        CHECK(p.rows[0] == "endpoint|ok|-|docker");
        CHECK(rows_with(p, "runtime|docker|served|").size() == 1);
        CHECK(rows_with(p, "runtime|docker|served|")[0].find("|-|1.47") != std::string::npos);
        CHECK(f.calls.size() == 3); // later verbs still run
    }
    SECTION("a /version whose Components is malformed identifies no runtime; later verbs run with -") {
        for (const char* body : {R"({"Version":"1","Components":"x"})",
                                 R"({"Version":"1","Components":[1]})",
                                 R"({"Version":"1","Components":[{"Name":5},{"Name":"Podman Engine"}]})"}) {
            Fake f;
            f.reply("/version", http(200, body));
            f.reply("/info", http(200, kInfo));
            f.reply("/containers/json?all=1", http(200, "[]"));
            const Posture p = f.run(kEndpoint);
            INFO(body);
            CHECK(has_token(p, "version:malformed"));
            CHECK(p.status == StatusState::constrained);
            CHECK(p.rows[0] == "endpoint|ok|-|-");
            for (const auto& r : rows_with(p, "runtime|"))
                CHECK(r.find("|served|") == std::string::npos);
            CHECK(rows_with(p, "config|-|cgroup_driver|systemd").size() == 1);
            CHECK(f.calls.size() == 3);
        }
    }
    SECTION("a /version missing a key (or with a Components element lacking Name) is not malformed") {
        Fake f;
        f.reply("/version", http(200, R"({"Version":"5.2.0","Components":[{"Name":"Podman Engine"},{"x":1}]})"));
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        CHECK(p.status == StatusState::supported);
        CHECK(p.reason.empty());
        CHECK(p.rows[0] == "endpoint|ok|-|podman");
    }
    SECTION("a /version nested past 32 levels reads malformed, endpoint still answered") {
        Fake f;
        f.reply("/version", http(200, std::string(40, '[') + std::string(40, ']')));
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "version:malformed"));
        CHECK(p.rows[0] == "endpoint|ok|-|-");
    }
    SECTION("a 404 between list and inspect is churn: unknown fields, no constraint") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, list_of({'a', 'b', 'c'})));
        f.reply("/containers/" + id('a') + "/json", http(200, inspect_body(true)));
        f.reply("/containers/" + id('b') + "/json", http(404, "gone"));
        f.reply("/containers/" + id('c') + "/json", http(200, inspect_body(false)));
        const Posture p = f.run(kEndpoint);
        CHECK(p.status == StatusState::supported);
        CHECK(p.reason.empty());
        const auto c = rows_with(p, "container|");
        REQUIRE(c.size() == 3);
        CHECK(c[1] == "container|docker|bbbbbbbbbbbb|c-b|img:1|running|unknown|unknown|unknown");
        CHECK(c[0].find("|yes|bridge|no") != std::string::npos);
        CHECK(c[2].find("|no|bridge|no") != std::string::npos);
        CHECK(f.calls.size() == 6); // the remaining inspection still ran
    }
    SECTION("a 500 on one inspect is a failed inspection: counted, the rest continue") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, list_of({'a', 'b', 'c'})));
        f.reply("/containers/" + id('a') + "/json", http(500, "boom"));
        f.reply("/containers/" + id('b') + "/json", http(200, "not json"));
        f.reply("/containers/" + id('c') + "/json", http(200, inspect_body(false)));
        const Posture p = f.run(kEndpoint);
        CHECK(p.status == StatusState::constrained);
        CHECK(has_token(p, "inspect:failed:2"));
        const auto c = rows_with(p, "container|");
        REQUIRE(c.size() == 3);
        CHECK(c[0].find("|unknown|unknown|unknown") != std::string::npos);
        CHECK(c[1].find("|unknown|unknown|unknown") != std::string::npos);
        CHECK(c[2].find("|no|bridge|no") != std::string::npos);
        CHECK(f.calls.size() == 6);
    }
}

TEST_CASE("runtime seam: the inspection cap leaves the rest unknown and says so",
          "[virtualization][runtime][seam]") {
    Fake f;
    f.happy_version();
    f.reply("/info", http(200, kInfo));
    std::string list = "[";
    for (int i = 0; i < 70; ++i) {
        const std::string cid = std::format("{:016x}", i) + std::string(48, 'a');
        if (i)
            list += ',';
        list += R"({"Id":")" + cid + R"(","Names":["/c"],"Image":"i","State":"running"})";
        f.reply("/containers/" + cid + "/json", http(200, inspect_body(false)));
    }
    list += "]";
    f.reply("/containers/json?all=1", http(200, list));
    const Posture p = f.run(kEndpoint);

    CHECK(f.calls.size() == 3 + kMaxInspections);
    CHECK(has_token(p, "inspect_capped"));
    CHECK(p.status == StatusState::constrained);
    const auto c = rows_with(p, "container|");
    REQUIRE(c.size() == 70);
    for (std::size_t i = 0; i < c.size(); ++i) {
        INFO("row " << i);
        if (i < kMaxInspections)
            CHECK(c[i].find("|no|bridge|no") != std::string::npos);
        else
            CHECK(c[i].find("|unknown|unknown|unknown") != std::string::npos); // each, individually
    }
}

TEST_CASE("runtime seam: the list cap is reported", "[virtualization][runtime][seam]") {
    Fake f;
    f.happy_version();
    f.reply("/info", http(200, kInfo));
    std::string list = "[";
    for (int i = 0; i < 300; ++i) {
        if (i)
            list += ',';
        list += R"({"Id":")" + std::format("{:016x}", i) + std::string(48, 'a') +
                R"(","Names":["/c"],"Image":"i","State":"running"})";
    }
    list += "]";
    f.reply("/containers/json?all=1", http(200, list));
    const Posture p = f.run(kEndpoint);
    CHECK(has_token(p, "rows_capped"));
    CHECK(rows_with(p, "container|").size() == kMaxContainerRows);
}

TEST_CASE("runtime seam: the action deadline is checked before every request",
          "[virtualization][runtime][deadline]") {
    SECTION("6 s per call: the budgets shrink and the action stops after the first inspection") {
        Fake f;
        f.step = milliseconds{6000};
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, list_of({'a', 'b', 'c'})));
        f.reply("/containers/" + id('a') + "/json", http(200, inspect_body(true)));
        const Posture p = f.run(kEndpoint);

        // 20 s deadline: budgets are 20 s, 14 s, 8 s, 2 s, then nothing is left
        REQUIRE(f.calls.size() == 4);
        CHECK(f.budgets == std::vector<milliseconds>{milliseconds{20000}, milliseconds{14000},
                                                     milliseconds{8000}, milliseconds{2000}});
        CHECK(has_token(p, "deadline_exhausted"));
        CHECK(p.status == StatusState::constrained);
        // every completed row survives; the first inspection took 6 s of a 2 s budget, so its
        // answer is not read and no inspection stays anything but unknown
        CHECK(p.rows[0] == "endpoint|ok|-|docker");
        CHECK(has_token(p, "inspect:failed:1"));
        const auto c = rows_with(p, "container|");
        REQUIRE(c.size() == 3);
        for (const auto& row : c)
            CHECK(row.find("|unknown|unknown|unknown") != std::string::npos);
        CHECK(rows_with(p, "config|docker|cgroup_driver|systemd").size() == 1);
    }
    SECTION("a call that consumes exactly its budget is a timeout, not an answer") {
        Fake f;
        f.step = seconds{20};
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        const Posture p = f.run(kEndpoint);
        CHECK(f.calls.size() == 1); // the failed /version stops the action
        CHECK(has_token(p, "version:timeout"));
        CHECK(p.rows[0] == "endpoint|unreachable|-|-");
        CHECK(p.status == StatusState::constrained);
    }
    SECTION("under one millisecond left is not passed on as a zero (unbounded) budget") {
        Fake f;
        f.step = milliseconds{19999}; // 1 ms left after the first call
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, "[]"));
        const Posture p = f.run(kEndpoint);
        REQUIRE(f.calls.size() >= 1);
        for (const auto b : f.budgets)
            CHECK(b.count() >= 1);
        CHECK(f.calls.size() == 2); // the second request still fits in 1 ms ...
        CHECK(has_token(p, "info:timeout")); // ... and takes 19.999 s of it ...
        CHECK(has_token(p, "deadline_exhausted")); // ... so the third does not go out
        CHECK(rows_with(p, "config|").empty()); // the late /info body (cgroup driver) is not read
        CHECK(p.status == StatusState::constrained);
    }
}

TEST_CASE("runtime seam: a reply that arrives after its budget is never read, whatever the transport did",
          "[virtualization][runtime][deadline]") {
    // The fake answers 200 with valid JSON, as a peer that streams `100 Continue` until the last
    // moment and then answers would make the HTTP client do past its own total timeout.
    SECTION("/version answering after 25 s: one call, version:timeout, no endpoint answer") {
        Fake f;
        f.path_step["/version"] = seconds{25};
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        const Posture p = f.run(kEndpoint);
        REQUIRE(f.calls.size() == 1);
        CHECK(has_token(p, "version:timeout"));
        CHECK(p.status == StatusState::constrained);
        CHECK(p.rows[0] == "endpoint|unreachable|-|-"); // not ok, and the dialect is not read
        CHECK(rows_with(p, "container|").empty());
        CHECK(rows_with(p, "config|").empty());
    }
    SECTION("the last inspection answering 200 after 25 s never reads supported") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, list_of({'a', 'b', 'c'})));
        f.reply("/containers/" + id('a') + "/json", http(200, inspect_body(true)));
        f.reply("/containers/" + id('b') + "/json", http(200, inspect_body(false)));
        f.reply("/containers/" + id('c') + "/json", http(200, inspect_body(true)));
        f.path_step["/containers/" + id('c') + "/json"] = seconds{25};
        const Posture p = f.run(kEndpoint);
        CHECK(f.calls.size() == 6);
        CHECK(p.status == StatusState::constrained);
        CHECK(has_token(p, "inspect:failed:1"));
        CHECK(p.rows[0] == "endpoint|ok|-|docker");
        const auto c = rows_with(p, "container|");
        REQUIRE(c.size() == 3);
        CHECK(c[0].find("|yes|bridge|no") != std::string::npos);
        CHECK(c[1].find("|no|bridge|no") != std::string::npos);
        CHECK(c[2].find("|unknown|unknown|unknown") != std::string::npos); // the late answer is dropped
    }
    SECTION("a late list is a timeout and the container rows are empty") {
        Fake f;
        f.happy_version();
        f.reply("/info", http(200, kInfo));
        f.reply("/containers/json?all=1", http(200, list_of({'a'})));
        f.path_step["/containers/json?all=1"] = seconds{21};
        const Posture p = f.run(kEndpoint);
        CHECK(has_token(p, "list:timeout"));
        CHECK(rows_with(p, "container|").empty());
        CHECK(p.status == StatusState::constrained);
        CHECK(f.calls.size() == 3); // no list, so no inspection is ever built
    }
}

TEST_CASE("runtime seam: daemon.json reads are typed, not guessed", "[virtualization][runtime][config]") {
    SECTION("a refused read is a constraint token and the config is not reported absent") {
        Fake f;
        f.reads["/etc/docker/daemon.json"] = FieldRead{ReadState::unreadable, "", "permission_denied"};
        const Posture p = f.run("");
        CHECK(p.status == StatusState::constrained);
        CHECK(has_token(p, "daemon_json:permission_denied"));
        CHECK(p.rows[1] == "runtime|docker|not_detected|absent|unreadable|-|-");
    }
    SECTION("an absent file is silent") {
        Fake f;
        const Posture p = f.run("");
        CHECK(p.status == StatusState::supported);
        CHECK(p.reason.empty());
        CHECK(p.rows[1] == "runtime|docker|not_detected|absent|absent|-|-");
    }
    SECTION("a wrong-typed key keeps the well-typed rows beside the malformed row and the token") {
        Fake f;
        f.reads["/etc/docker/daemon.json"] =
            FieldRead{ReadState::ok, R"({"icc":true,"data-root":true,"hosts":["fd://",5]})", ""};
        const Posture p = f.run("");
        CHECK(p.status == StatusState::constrained);
        CHECK(has_token(p, "daemon_json:malformed"));
        CHECK(rows_with(p, "config|docker|icc|yes").size() == 1);
        CHECK(rows_with(p, "config|docker|data-root|").empty());
        CHECK(rows_with(p, "config|docker|hosts").empty()); // hosts and hosts_tcp: unknown, withheld
        CHECK(rows_with(p, "config|docker|daemon_json|malformed").size() == 1);
        CHECK(p.rows[1] == "runtime|docker|detected|absent|present|-|-");
    }
    SECTION("oversized and malformed files are tokens, malformed also a row") {
        Fake f;
        f.reads["/etc/docker/daemon.json"] = FieldRead{ReadState::unreadable, "", "oversized"};
        CHECK(has_token(f.run(""), "daemon_json:oversized"));

        Fake g;
        g.reads["/etc/docker/daemon.json"] = FieldRead{ReadState::ok, "{not json", ""};
        const Posture p = g.run("");
        CHECK(has_token(p, "daemon_json:malformed"));
        CHECK(rows_with(p, "config|docker|daemon_json|malformed").size() == 1);
        CHECK(p.status == StatusState::constrained);
    }
}

TEST_CASE("runtime seam: detection facts, with and without a refused stat (no endpoint, no connect)",
          "[virtualization][runtime][detection]") {
    SECTION("a default socket that cannot be stat'd reads unreadable and constrains, and is no detection") {
        Fake f;
        f.stats["/run/podman/podman.sock"] = errno_stat(EACCES);
        const Posture p = f.run("");
        CHECK(f.calls.empty());
        CHECK(p.rows[2] == "runtime|podman|not_detected|unreadable|absent|-|-");
        CHECK(p.status == StatusState::constrained);
        CHECK(p.reason == rt_token("podman:socket:permission_denied"));
    }
    SECTION("a config file that cannot be stat'd reads unreadable and constrains") {
        Fake f;
        f.stats["/etc/containerd/config.toml"] = errno_stat(EACCES);
        const Posture p = f.run("");
        CHECK(p.rows[3] == "runtime|containerd|not_detected|absent|unreadable|-|-");
        CHECK(p.status == StatusState::constrained);
        CHECK(p.reason == rt_token("containerd:config:permission_denied"));
    }
    SECTION("a data root that cannot be stat'd constrains and does not change the detection") {
        Fake f;
        f.stats["/var/lib/docker"] = errno_stat(EIO);
        const Posture p = f.run("");
        CHECK(p.rows[1] == "runtime|docker|not_detected|absent|absent|-|-");
        CHECK(p.status == StatusState::constrained);
        CHECK(p.reason == rt_token("docker:data_root:eio"));

        Fake with_socket; // another artefact still detects the runtime
        with_socket.with_docker_socket();
        with_socket.stats["/var/lib/docker"] = errno_stat(EIO);
        CHECK(with_socket.run("").rows[1] ==
              "runtime|docker|detected|present:0660:0:999|absent|-|-");
    }
    SECTION("a podman config on its own detects podman") {
        Fake f;
        f.stats["/etc/containers/storage.conf"] = regular();
        const Posture p = f.run("");
        CHECK(p.rows[2] == "runtime|podman|detected|absent|present|-|-");
        CHECK(p.status == StatusState::supported);
        CHECK(p.reason.empty());
    }
    SECTION("a data root on its own detects the runtime, with the socket and config absent") {
        Fake f;
        f.stats["/var/lib/containerd"] = dir();
        const Posture p = f.run("");
        CHECK(p.rows[3] == "runtime|containerd|detected|absent|absent|-|-");
        CHECK(p.status == StatusState::supported);
    }
    SECTION("ENOTDIR on a path reads absent, like ENOENT, with no token") {
        Fake f;
        f.stats["/run/docker.sock"] = errno_stat(ENOTDIR);
        f.stats["/var/run/docker.sock"] = errno_stat(ENOTDIR);
        f.stats["/etc/containers/containers.conf"] = errno_stat(ENOTDIR);
        f.stats["/var/lib/containerd"] = errno_stat(ENOTDIR);
        const Posture p = f.run("");
        CHECK(p.rows[1] == "runtime|docker|not_detected|absent|absent|-|-");
        CHECK(p.rows[2] == "runtime|podman|not_detected|absent|absent|-|-");
        CHECK(p.rows[3] == "runtime|containerd|not_detected|absent|absent|-|-");
        CHECK(p.status == StatusState::supported);
        CHECK(p.reason.empty());
    }
}

TEST_CASE("runtime seam: a data root on a network mount is never stat'd", "[virtualization][runtime][mounts]") {
    Fake f;
    f.network_mounts = {"/var/lib/docker"};
    const Posture p = f.run("");
    CHECK(has_token(p, "docker:network_fs_skipped"));
    CHECK(p.status == StatusState::constrained);
    CHECK(std::count(f.stat_calls.begin(), f.stat_calls.end(), "/var/lib/docker") == 0);
    CHECK(std::count(f.stat_calls.begin(), f.stat_calls.end(), "/var/lib/containers") == 1);
    CHECK(std::count(f.stat_calls.begin(), f.stat_calls.end(), "/var/lib/containerd") == 1);

    Fake root;
    root.network_mounts = {"/var"}; // a mount that CONTAINS the data roots
    const Posture r = root.run("");
    for (const char* rt : {"docker", "podman", "containerd"})
        CHECK(has_token(r, std::string{rt} + ":network_fs_skipped"));

    Fake unreadable;
    unreadable.mountinfo_unreadable = true;
    const Posture u = unreadable.run("");
    CHECK(has_token(u, "mountinfo:unreadable"));
    CHECK(std::count(unreadable.stat_calls.begin(), unreadable.stat_calls.end(), "/var/lib/docker") ==
          1); // with no table the roots are stat'd anyway
}

TEST_CASE("runtime seam: a default socket the agent could connect to is reported, never probed",
          "[virtualization][runtime][overprivileged]") {
    Fake f;
    f.stats["/run/docker.sock"] = sock(0, 27, 0660, 100); // root:docker 0660
    f.groups = {kEgid, 27};                               // a SupplementaryGroups=docker drop-in
    const Posture p = f.run("");
    CHECK(has_token(p, "docker:overprivileged"));
    CHECK(p.status == StatusState::constrained);
    CHECK(f.calls.empty()); // the check is a stat comparison, never a connect

    Fake safe;
    safe.stats["/run/docker.sock"] = sock(0, 27, 0660, 100);
    CHECK(safe.run("").status == StatusState::supported); // the agent is not in that group

    Fake world;
    world.stats["/run/podman/podman.sock"] = sock(0, 0, 0666, 101);
    CHECK(has_token(world.run(""), "podman:overprivileged"));
}

TEST_CASE("runtime seam: single flight returns busy without touching anything",
          "[virtualization][runtime][busy]") {
    std::atomic<bool> flag{false};
    int ran = 0;
    const auto body = [&] {
        ++ran;
        return Posture{};
    };
    CHECK(single_flight(flag, body).status == StatusState::supported);
    CHECK(ran == 1);
    CHECK_FALSE(flag.load()); // released

    flag.store(true);
    const Posture busy = single_flight(flag, body);
    CHECK(ran == 1); // the body did not run
    CHECK(busy.status == StatusState::constrained);
    CHECK(busy.reason == "linux:virtualization:runtime_posture:busy");
    CHECK(busy.rows.empty()); // no row but the status row (written by report)
    CHECK(flag.load());       // the holder's flag is untouched

    flag.store(false);
    try {
        single_flight(flag, []() -> Posture { throw 1; });
    } catch (int) {
    }
    CHECK_FALSE(flag.load()); // released on an exception too
}
