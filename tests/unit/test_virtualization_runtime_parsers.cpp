/**
 * test_virtualization_runtime_parsers.cpp -- pure tests for the `runtime_posture` core
 * (virtualization_runtime_parsers.hpp): the verb table, the endpoint decision, the JSON readers and
 * their key allow-lists, the per-field character allow-lists, the status tables and the row
 * formatters. Portable, no I/O.
 *
 * Fixture provenance: every JSON specimen is SYNTHETIC, shaped from the documented docker engine
 * and podman compatibility API replies; no real image, host or account name appears. The real
 * captures are taken on a Linux host after the gates settle and recorded in the PR.
 */
#include <catch2/catch_test_macros.hpp>

#include "virtualization_runtime_parsers.hpp"

#include <cerrno>
#include <cstdint>
#include <regex>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::virtualization;
using namespace yuzu::virtualization::runtime;
using nlohmann::json;

namespace {

constexpr const char* kEndpointOk = "/run/yuzu-agent/runtime.sock";

StatResult socket_stat(std::uint32_t uid, std::uint32_t gid, std::uint32_t perm, std::uint64_t dev,
                       std::uint64_t ino) {
    StatResult s;
    s.mode = 0140000u | perm;
    s.uid = uid;
    s.gid = gid;
    s.dev = dev;
    s.ino = ino;
    return s;
}

StatResult dir_stat(std::uint32_t uid, std::uint32_t perm) {
    StatResult s;
    s.mode = 0040000u | perm;
    s.uid = uid;
    return s;
}

std::string id(char c, std::size_t n = 64) { return std::string(n, c); }

} // namespace

// ---------------------------------------------------------------------------------------------
// verb table
// ---------------------------------------------------------------------------------------------

TEST_CASE("runtime verbs: every index builds a GET on one of exactly four allowlisted paths",
          "[virtualization][runtime][verbs]") {
    const std::set<std::string> allowed{"/version", "/info", "/containers/json?all=1"};
    const std::regex inspect{"^/containers/[0-9a-f]{12,64}/json$"};
    std::size_t built = 0;
    for (std::size_t i = 0; i < static_cast<std::size_t>(Verb::count); ++i) {
        const auto verb = static_cast<Verb>(i);
        const auto req = verb == Verb::container_inspect ? build_request(verb, id('a'))
                                                         : build_request(verb);
        REQUIRE(req.has_value());
        CHECK(req->method == "GET");
        CHECK((allowed.count(req->path) == 1 || std::regex_match(req->path, inspect)));
        CHECK(req->verb == verb);
        ++built;
    }
    CHECK(built == 4);
    CHECK(kVerbs.size() == 4);
    CHECK_FALSE(build_request(Verb::count).has_value());
}

TEST_CASE("runtime verbs: an inspect id must be 12 to 64 lowercase hex and nothing else builds "
          "a request",
          "[virtualization][runtime][verbs]") {
    CHECK(build_request(Verb::container_inspect, id('a', 12)).has_value());
    CHECK(build_request(Verb::container_inspect, id('0', 64)).has_value());
    CHECK_FALSE(build_request(Verb::container_inspect, id('A')).has_value());   // uppercase
    CHECK_FALSE(build_request(Verb::container_inspect, "ab/../../etc/passwd0").has_value());
    CHECK_FALSE(build_request(Verb::container_inspect, "../aaaaaaaaaaaaaa").has_value());
    CHECK_FALSE(build_request(Verb::container_inspect, id('a', 11)).has_value());
    CHECK_FALSE(build_request(Verb::container_inspect, id('a', 65)).has_value());
    CHECK_FALSE(build_request(Verb::container_inspect, "").has_value());
    CHECK_FALSE(build_request(Verb::container_inspect, id('g')).has_value()); // not hex
    // an id handed to a verb that takes none
    CHECK_FALSE(build_request(Verb::version, id('a')).has_value());
    CHECK_FALSE(build_request(Verb::info, id('a')).has_value());
    CHECK_FALSE(build_request(Verb::containers_list, id('a')).has_value());
}

// ---------------------------------------------------------------------------------------------
// endpoint
// ---------------------------------------------------------------------------------------------

TEST_CASE("runtime endpoint: lexical decision", "[virtualization][runtime][endpoint]") {
    CHECK(parse_endpoint("").verdict == EndpointVerdict::unset);
    const auto ok = parse_endpoint(kEndpointOk);
    CHECK(ok.verdict == EndpointVerdict::ok);
    CHECK(ok.path == kEndpointOk);
    CHECK(parse_endpoint("run/x.sock").verdict == EndpointVerdict::relative);
    CHECK(parse_endpoint("./x.sock").verdict == EndpointVerdict::relative);
    CHECK(parse_endpoint("/run/../x").verdict == EndpointVerdict::dotdot);
    CHECK(parse_endpoint("/run/yuzu-agent/..").verdict == EndpointVerdict::dotdot);
    CHECK(parse_endpoint("/..").verdict == EndpointVerdict::dotdot);
    CHECK(parse_endpoint("/x/..").verdict == EndpointVerdict::dotdot);
    // an empty segment hides nothing
    CHECK(parse_endpoint("/run//../x").verdict == EndpointVerdict::dotdot);
    // a name that merely contains dots is not a `..` segment
    CHECK(parse_endpoint("/run/yuzu..agent/a.sock").verdict == EndpointVerdict::ok);
    CHECK(parse_endpoint("/...").verdict == EndpointVerdict::ok);
    CHECK(parse_endpoint("/a..b").verdict == EndpointVerdict::ok);

    for (const auto s : kDefaultSockets)
        CHECK(parse_endpoint(s).verdict == EndpointVerdict::default_socket);
    // lexical normalisation: the same four paths in other spellings
    CHECK(parse_endpoint("/run/./docker.sock").verdict == EndpointVerdict::default_socket);
    CHECK(parse_endpoint("//run//docker.sock").verdict == EndpointVerdict::default_socket);
    CHECK(parse_endpoint("/var/run/docker.sock/").verdict == EndpointVerdict::default_socket);
    CHECK(parse_endpoint("/run/podman/./podman.sock").verdict == EndpointVerdict::default_socket);
    CHECK(parse_endpoint("/run/containerd//containerd.sock").verdict ==
          EndpointVerdict::default_socket);

    // the 107-byte sun_path bound, measured on the normalised path
    const std::string at_limit = "/" + std::string(kMaxSocketPath - 1, 'a');
    CHECK(at_limit.size() == kMaxSocketPath);
    CHECK(parse_endpoint(at_limit).verdict == EndpointVerdict::ok);
    CHECK(parse_endpoint(at_limit + "a").verdict == EndpointVerdict::too_long);
    CHECK(parse_endpoint("//" + at_limit).verdict == EndpointVerdict::ok); // collapses to the limit
}

TEST_CASE("runtime endpoint: a `..` segment is exactly a whole segment, wherever it sits",
          "[virtualization][runtime][endpoint]") {
    for (const char* p : {"..", "/..", "../x", "a/..", "../..", "a//../b", "/./../x"})
        CHECK(has_dotdot_segment(p));
    for (const char* p : {"", "/", ".", "...", "/.../", "a..b", "..a", "a..", "/a/.b/c.."})
        CHECK_FALSE(has_dotdot_segment(p));
    const std::string with_nul{"/a\0/..", 6};
    CHECK(has_dotdot_segment(with_nul)); // an embedded NUL is not a separator and hides nothing
}

TEST_CASE("runtime endpoint: normalise_path never resolves a dotdot", "[virtualization][runtime][endpoint]") {
    CHECK(normalise_path("/a//b/./c/") == "/a/b/c");
    CHECK(normalise_path("/") == "/");
    CHECK(normalise_path("///") == "/");
    CHECK(normalise_path("/a/../b") == "/a/../b");
    CHECK(normalise_path("a//b") == "a/b");
    CHECK(ancestors_of("/run/yuzu-agent/runtime.sock") ==
          std::vector<std::string>{"/run/yuzu-agent", "/run", "/"});
    CHECK(ancestors_of("/x.sock") == std::vector<std::string>{"/"});
}

TEST_CASE("runtime endpoint: object checks run in the note's order", "[virtualization][runtime][endpoint]") {
    constexpr std::uint32_t kEgid = 998;
    const std::vector<StatResult> defaults{socket_stat(0, 999, 0660, 7, 100)};
    const auto verdict = [&](const StatResult& s) { return check_endpoint_leaf(s, kEgid, defaults); };

    CHECK(verdict(socket_stat(0, kEgid, 0660, 7, 200)) == EndpointVerdict::ok);

    StatResult enoent;
    enoent.err = ENOENT;
    CHECK(verdict(enoent) == EndpointVerdict::absent); // the only error that is not a refusal
    for (const int e : {EACCES, ELOOP, ENAMETOOLONG, ENOTDIR, EIO}) {
        StatResult s;
        s.err = e;
        CHECK(verdict(s) == EndpointVerdict::stat_error);
    }

    StatResult link;
    link.mode = 0120777u; // O_PATH|O_NOFOLLOW on a symlink hands back the link itself
    CHECK(verdict(link) == EndpointVerdict::symlink);
    StatResult dir = dir_stat(0, 0755);
    CHECK(verdict(dir) == EndpointVerdict::not_socket);
    StatResult reg;
    reg.mode = 0100660u;
    CHECK(verdict(reg) == EndpointVerdict::not_socket);

    // a bind mount or hard link of a default socket: same (dev, ino), named before the owner,
    // group and mode checks (the real socket is root:docker, which would read as `group`)
    CHECK(verdict(socket_stat(0, 999, 0660, 7, 100)) == EndpointVerdict::same_inode);
    CHECK(verdict(socket_stat(0, kEgid, 0660, 8, 100)) == EndpointVerdict::ok); // other device
    CHECK(verdict(socket_stat(0, kEgid, 0660, 7, 101)) == EndpointVerdict::ok); // other inode

    CHECK(verdict(socket_stat(1000, kEgid, 0660, 7, 200)) == EndpointVerdict::owner);
    CHECK(verdict(socket_stat(0, 4, 0660, 7, 200)) == EndpointVerdict::group);
    CHECK(verdict(socket_stat(0, kEgid, 0666, 7, 200)) == EndpointVerdict::mode);
    CHECK(verdict(socket_stat(0, kEgid, 0600, 7, 200)) == EndpointVerdict::mode);
    CHECK(verdict(socket_stat(0, kEgid, 0664, 7, 200)) == EndpointVerdict::mode);
}

TEST_CASE("runtime endpoint: ancestor directories", "[virtualization][runtime][endpoint]") {
    CHECK(check_endpoint_ancestor(dir_stat(0, 0755)) == EndpointVerdict::ok);
    CHECK(check_endpoint_ancestor(dir_stat(0, 0700)) == EndpointVerdict::ok);
    CHECK(check_endpoint_ancestor(dir_stat(1000, 0755)) == EndpointVerdict::insecure_ancestor);
    CHECK(check_endpoint_ancestor(dir_stat(0, 0775)) == EndpointVerdict::insecure_ancestor);
    CHECK(check_endpoint_ancestor(dir_stat(0, 0757)) == EndpointVerdict::insecure_ancestor);
    CHECK(check_endpoint_ancestor(dir_stat(0, 01777)) == EndpointVerdict::insecure_ancestor);
    StatResult file;
    file.mode = 0100644u;
    CHECK(check_endpoint_ancestor(file) == EndpointVerdict::insecure_ancestor);
    StatResult gone;
    gone.err = ENOENT;
    CHECK(check_endpoint_ancestor(gone) == EndpointVerdict::absent);
    StatResult denied;
    denied.err = EACCES;
    CHECK(check_endpoint_ancestor(denied) == EndpointVerdict::stat_error);
}

TEST_CASE("runtime endpoint: status tables (decide_endpoint)", "[virtualization][runtime][status]") {
    CHECK(endpoint_status_for(EndpointVerdict::unset) == EndpointStatus::unset);
    CHECK(endpoint_status_for(EndpointVerdict::ok) == EndpointStatus::ok);
    CHECK(endpoint_status_for(EndpointVerdict::absent) == EndpointStatus::unreachable);
    for (const auto v : {EndpointVerdict::relative, EndpointVerdict::dotdot, EndpointVerdict::too_long,
                         EndpointVerdict::default_socket, EndpointVerdict::same_inode,
                         EndpointVerdict::not_socket, EndpointVerdict::symlink, EndpointVerdict::owner,
                         EndpointVerdict::group, EndpointVerdict::mode,
                         EndpointVerdict::insecure_ancestor, EndpointVerdict::stat_error}) {
        CHECK(endpoint_status_for(v) == EndpointStatus::endpoint_refused);
        CHECK(endpoint_reason_token(v) != "-");
    }
    // no reason for a verdict that is not a refusal: the endpoint row prints it as-is
    for (const auto v : {EndpointVerdict::unset, EndpointVerdict::ok, EndpointVerdict::absent})
        CHECK(endpoint_reason_token(v) == "-");

    CHECK(endpoint_status_for(Outcome::ok) == EndpointStatus::ok);
    CHECK(endpoint_status_for(Outcome::eacces) == EndpointStatus::permission_denied);
    for (const auto o : {Outcome::enoent, Outcome::timeout, Outcome::other})
        CHECK(endpoint_status_for(o) == EndpointStatus::unreachable);
    CHECK(endpoint_status_for(Outcome::not_http) == EndpointStatus::not_http);
    CHECK(endpoint_status_for(Outcome::oversized) == EndpointStatus::not_http);
}

TEST_CASE("runtime status: detection is about standard paths and an endpoint failure changes none",
          "[virtualization][runtime][status]") {
    CHECK(decide_runtime(false, false) == "not_detected");
    CHECK(decide_runtime(true, false) == "detected");
    CHECK(decide_runtime(false, true) == "served");
    CHECK(decide_runtime(true, true) == "served");
    // the endpoint state is not an input of decide_runtime at all: nothing to change.
}

TEST_CASE("runtime status: overprivileged default socket needs a held group with write, or other-write",
          "[virtualization][runtime][status]") {
    const std::vector<std::uint32_t> groups{998, 27};
    CHECK(socket_overprivileged(socket_stat(0, 27, 0660, 1, 1), groups));  // supplementary group
    CHECK(socket_overprivileged(socket_stat(0, 998, 0660, 1, 1), groups)); // effective group
    CHECK(socket_overprivileged(socket_stat(0, 4, 0666, 1, 1), groups));   // other-write
    CHECK_FALSE(socket_overprivileged(socket_stat(0, 4, 0660, 1, 1), groups)); // a group not held
    CHECK_FALSE(socket_overprivileged(socket_stat(0, 27, 0640, 1, 1), groups)); // no group write
    CHECK_FALSE(socket_overprivileged(dir_stat(0, 0777), groups));              // not a socket
    StatResult gone;
    gone.err = ENOENT;
    CHECK_FALSE(socket_overprivileged(gone, groups));
}

TEST_CASE("runtime mounts: a path touches a network mount when on, under or containing it",
          "[virtualization][runtime][status]") {
    CHECK(path_touches_mount("/var/lib/docker", "/var/lib/docker"));
    CHECK(path_touches_mount("/var/lib/docker", "/var/lib"));       // under
    CHECK(path_touches_mount("/var/lib/docker", "/var/lib/docker/overlay2")); // contains
    CHECK(path_touches_mount("/var/lib/docker", "/"));
    CHECK_FALSE(path_touches_mount("/var/lib/docker", "/var/lib/dockerx"));
    CHECK_FALSE(path_touches_mount("/var/lib/docker", "/srv/data"));
}

TEST_CASE("runtime rows: a default socket field reports mode, uid and gid", "[virtualization][runtime][rows]") {
    CHECK(socket_present_field(socket_stat(0, 998, 0660, 1, 1)) == "present:0660:0:998");
    CHECK(socket_present_field(socket_stat(0, 0, 0600, 1, 1)) == "present:0600:0:0");
}

// ---------------------------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------------------------

TEST_CASE("runtime json: nesting over 32 is discarded as it starts and reads malformed",
          "[virtualization][runtime][json]") {
    const auto nested = [](int levels) {
        std::string s;
        for (int i = 0; i < levels; ++i)
            s += "[";
        for (int i = 0; i < levels; ++i)
            s += "]";
        return s;
    };
    const auto at32 = parse_limited(nested(32));
    CHECK(at32.ok);
    CHECK_FALSE(at32.too_deep);
    const auto at33 = parse_limited(nested(33));
    CHECK_FALSE(at33.ok);
    CHECK(at33.too_deep);
    // a deep body is bounded work, not a crash
    const auto deep = parse_limited(nested(100000));
    CHECK_FALSE(deep.ok);
    CHECK(deep.too_deep);
    // malformed text: no exception, not ok, not too_deep
    const auto bad = parse_limited("{\"a\":");
    CHECK_FALSE(bad.ok);
    CHECK_FALSE(bad.too_deep);
    CHECK_FALSE(parse_limited("").ok);
    // comments are ignored
    CHECK(parse_limited("{/* c */\"a\":1}").ok);
}

TEST_CASE("runtime daemon.json: only allowlisted keys, arrays as counts, hosts_tcp",
          "[virtualization][runtime][config]") {
    const auto r = parse_daemon_json(R"({
        // a comment is ignored
        "live-restore": true, "userns-remap": "default", "no-new-privileges": false,
        "icc": true, "iptables": false, "tls": true, "tlsverify": true,
        "data-root": "/var/lib/docker", "log-driver": "json-file", "storage-driver": "overlay2",
        "selinux-enabled": false, "userland-proxy": true,
        "hosts": ["fd://", "tcp://0.0.0.0:2375"],
        "insecure-registries": ["a:5000", "b:5000", "c:5000"],
        "registry-mirrors": ["https://m.example"],
        "auth": {"user": "u", "password": "hunter2"},
        "proxies": {"http-proxy": "http://user:pw@proxy"},
        "tlscert": "/etc/docker/cert.pem"
    })");
    REQUIRE_FALSE(r.malformed);
    std::vector<std::string> keys;
    std::string all;
    for (const auto& c : r.rows) {
        keys.push_back(c.key);
        all += c.key + "=" + c.value + ";";
    }
    CHECK(keys == std::vector<std::string>{"live-restore", "userns-remap", "no-new-privileges", "icc",
                                           "iptables", "tls", "tlsverify", "data-root", "log-driver",
                                           "storage-driver", "selinux-enabled", "userland-proxy",
                                           "hosts", "hosts_tcp", "insecure-registries",
                                           "registry-mirrors"});
    CHECK(all.find("live-restore=yes;") != std::string::npos);
    CHECK(all.find("no-new-privileges=no;") != std::string::npos);
    CHECK(all.find("hosts=2;hosts_tcp=yes;") != std::string::npos);
    CHECK(all.find("insecure-registries=3;registry-mirrors=1;") != std::string::npos);
    // nothing that looks like a credential, a proxy or a certificate path is emitted
    for (const char* leak : {"hunter2", "password", "pw@", "tlscert", "cert.pem"})
        CHECK(all.find(leak) == std::string::npos);
    // no key is emitted twice
    CHECK(std::set<std::string>(keys.begin(), keys.end()).size() == keys.size());
}

TEST_CASE("runtime daemon.json: wrong types and bad text never throw and never render",
          "[virtualization][runtime][config]") {
    const auto wrong = parse_daemon_json(R"({"icc":[1],"data-root":7,"live-restore":"yes",
                                             "hosts":"tcp://x","log-driver":"a b\u001b[31m",
                                             "userns-remap":["x"]})");
    REQUIRE_FALSE(wrong.malformed);
    // icc, data-root, live-restore, hosts and userns-remap are skipped; log-driver is `invalid`
    REQUIRE(wrong.rows.size() == 1);
    CHECK(wrong.rows[0].key == "log-driver");
    CHECK(wrong.rows[0].value == "invalid");

    const auto tcp_no = parse_daemon_json(R"({"hosts":["unix:///var/run/docker.sock"]})");
    REQUIRE(tcp_no.rows.size() == 2);
    CHECK(tcp_no.rows[1].value == "no");

    for (const char* text : {"{not json", "[1,2]", "\"s\"", "", "{\"a\":"})
        CHECK(parse_daemon_json(text).malformed);
    // nesting over the limit reads malformed, no field of it is read
    std::string deep = R"({"icc":true,"x":)";
    for (int i = 0; i < 40; ++i)
        deep += "[";
    for (int i = 0; i < 40; ++i)
        deep += "]";
    deep += "}";
    const auto d = parse_daemon_json(deep);
    CHECK(d.malformed);
    CHECK(d.rows.empty());
}

TEST_CASE("runtime /version: the dialect comes from Components, wrong types are tolerated",
          "[virtualization][runtime][version]") {
    const auto podman = parse_version(json::parse(
        R"({"Version":"5.2.0","ApiVersion":"1.41","Components":[{"Name":"Podman Engine","Version":"5.2.0"}]})"));
    CHECK(podman.valid);
    CHECK(podman.dialect == Dialect::podman);
    CHECK(podman.version == "5.2.0");
    CHECK(podman.api_version == "1.41");

    const auto docker = parse_version(json::parse(
        R"({"Version":"27.3.1","ApiVersion":"1.47","Components":[{"Name":"Engine"}]})"));
    CHECK(docker.dialect == Dialect::docker);

    const auto bare = parse_version(json::parse(R"({"Version":"27.3.1"})"));
    CHECK(bare.valid);
    CHECK(bare.dialect == Dialect::docker);
    CHECK(bare.version == "27.3.1");
    CHECK(bare.api_version == "-");

    const auto odd = parse_version(json::parse(R"({"Version":27,"ApiVersion":null,"Components":"x"})"));
    CHECK(odd.valid);
    CHECK(odd.dialect == Dialect::docker);
    CHECK(odd.version == "-");
    CHECK(odd.api_version == "-");

    const auto wrong_comp = parse_version(json::parse(R"({"Components":[1,{"Name":5},{"Name":"Podman Engine"}]})"));
    CHECK(wrong_comp.dialect == Dialect::podman);

    CHECK_FALSE(parse_version(json::parse("[1]")).valid);
    CHECK(parse_version(json::parse("[1]")).dialect == Dialect::none);
    CHECK(parse_version(json::parse(R"({"Version":"1.0\u001b"})")).version == "invalid");
}

TEST_CASE("runtime /info: exactly three rows, no other key is read", "[virtualization][runtime][info]") {
    const auto rows = parse_info(json::parse(R"({
        "CgroupDriver":"systemd",
        "SecurityOptions":["name=seccomp,profile=builtin","name=rootless"],
        "RegistryConfig":{"Auth":"x"}, "Name":"host", "DockerRootDir":"/var/lib/docker",
        "HttpProxy":"http://u:p@h"})"));
    REQUIRE(rows.size() == 3);
    CHECK(rows[0].key == "rootless");
    CHECK(rows[0].value == "yes");
    CHECK(rows[1].key == "cgroup_driver");
    CHECK(rows[1].value == "systemd");
    CHECK(rows[2].key == "security_options_count");
    CHECK(rows[2].value == "2");

    const auto rootful = parse_info(json::parse(R"({"CgroupDriver":"cgroupfs","SecurityOptions":["name=seccomp"]})"));
    REQUIRE(rootful.size() == 3);
    CHECK(rootful[0].value == "no");

    // wrong types: skipped, never thrown on
    CHECK(parse_info(json::parse(R"({"CgroupDriver":3,"SecurityOptions":"x"})")).empty());
    CHECK(parse_info(json::parse("[]")).empty());
    const auto bad_driver = parse_info(json::parse(R"({"CgroupDriver":"a\u001b"})"));
    REQUIRE(bad_driver.size() == 1);
    CHECK(bad_driver[0].value == "invalid");
}

// ---------------------------------------------------------------------------------------------
// containers
// ---------------------------------------------------------------------------------------------

TEST_CASE("runtime list: docker-shaped and podman-shaped entries become rows with unknown inspect "
          "fields",
          "[virtualization][runtime][containers]") {
    const std::string docker_list = R"([
        {"Id":")" + id('a') + R"(","Names":["/web"],"Image":"registry.example/app:1.2",
         "State":"running","Command":"secret-cmd","Labels":{"k":"leak"},"Mounts":[{"Source":"/x"}],
         "Ports":[{"PrivatePort":80}]},
        {"Id":")" + id('b') + R"(","Names":["/db","/web/db"],"Image":"sha256:0123abcd","State":"exited"}])";
    const auto l = containers_from_list(json::parse(docker_list));
    REQUIRE(l.rows.size() == 2);
    CHECK_FALSE(l.malformed);
    CHECK(l.skipped == 0);
    CHECK(l.rows[0].id12 == id('a', 12));
    CHECK(l.rows[0].name == "web"); // leading slash stripped
    CHECK(l.rows[0].image == "registry.example/app:1.2");
    CHECK(l.rows[0].state == "running");
    CHECK(l.rows[0].privileged == Tri::unknown);
    CHECK(l.rows[0].network_mode == "unknown");
    CHECK(l.rows[0].socket_mounted == Tri::unknown);
    CHECK(l.rows[1].name == "db");
    // the list reply's Command/Labels/Mounts/Ports are never read: nothing of them is in a row
    const std::string line = format_container_row("docker", l.rows[0]);
    for (const char* leak : {"secret-cmd", "leak", "Labels", "PrivatePort"})
        CHECK(line.find(leak) == std::string::npos);

    // podman's compatibility list reply has the same four keys
    const auto p = containers_from_list(json::parse(
        R"([{"Id":")" + id('c') + R"(","Names":["pod-app"],"Image":"localhost/app:latest","State":"running"}])"));
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].name == "pod-app");
}

TEST_CASE("runtime list: caps, skips and wrong types never throw", "[virtualization][runtime][containers]") {
    json big = json::array();
    for (int i = 0; i < 300; ++i) {
        char hex[17];
        std::snprintf(hex, sizeof(hex), "%016x", i);
        big.push_back({{"Id", std::string(hex) + std::string(48, 'a')}, {"Names", {"/n"}},
                       {"Image", "i"}, {"State", "running"}});
    }
    const auto capped = containers_from_list(big);
    CHECK(capped.rows.size() == kMaxContainerRows);
    CHECK(capped.rows_capped);

    const auto exact = [&] {
        json a = json::array();
        for (std::size_t i = 0; i < kMaxContainerRows; ++i)
            a.push_back({{"Id", id('a')}, {"State", "running"}});
        return containers_from_list(a);
    }();
    CHECK(exact.rows.size() == kMaxContainerRows);
    CHECK_FALSE(exact.rows_capped); // exactly at the cap is not capped

    const auto not_array = containers_from_list(json::parse(R"({"Id":"x"})"));
    CHECK(not_array.malformed);
    CHECK(not_array.rows.empty());

    const auto mixed = containers_from_list(json::parse(
        R"([{"Id":7},{"Id":"short"},"str",null,{"Id":")" + id('d') + R"(","Names":"notarray","Image":5,"State":[]}])"));
    CHECK(mixed.skipped == 4);
    REQUIRE(mixed.rows.size() == 1);
    CHECK(mixed.rows[0].name == "-");
    CHECK(mixed.rows[0].image == "-");
    CHECK(mixed.rows[0].state == "invalid");
}

TEST_CASE("runtime fields: the charset check runs before truncation and a miss reads invalid",
          "[virtualization][runtime][fields]") {
    // a 1000-byte name made of allowed characters is truncated to 256 bytes
    CHECK(checked_name(std::string(1000, 'a')).size() == kFieldCap);
    CHECK(checked_image(std::string(1000, 'a')).size() == kFieldCap);
    CHECK(checked_network_mode(std::string(1000, 'a')).size() == kShortFieldCap);
    CHECK(checked_version(std::string(1000, '1')).size() == kShortFieldCap);
    // ... but a bad byte anywhere, even past the cap, is invalid, not silently cut off
    CHECK(checked_name(std::string(1000, 'a') + "\x1b") == "invalid");
    CHECK(checked_name("a\x1b[31mred") == "invalid");           // ESC passes wire_field; not this
    CHECK(checked_name("a\xe2\x80\xae" "gnp") == "invalid");    // bidi override
    CHECK(checked_name("a|b") == "invalid");
    CHECK(checked_name("a\\b") == "invalid");
    CHECK(checked_name("a\nb") == "invalid");
    CHECK(checked_name("-leading") == "invalid"); // first byte must be alphanumeric
    CHECK(checked_name("") == "invalid");
    CHECK(checked_name("ok_name-1.2") == "ok_name-1.2");
    CHECK(checked_image("reg.example:5000/team/app@sha256:ab+c") == "reg.example:5000/team/app@sha256:ab+c");
    CHECK(checked_image("a b") == "invalid");
    CHECK(checked_network_mode("container:abc") == "container:abc");
    CHECK(checked_network_mode("host") == "host");
    CHECK(checked_network_mode("a/b") == "invalid");
    // the state is a closed enum
    for (const char* s : {"created", "running", "paused", "restarting", "removing", "exited", "dead"})
        CHECK(checked_state(s) == s);
    CHECK(checked_state("configured") == "invalid"); // a podman-only state is not guessed at
    CHECK(checked_state("Running") == "invalid");
    CHECK(checked_state("") == "invalid");
}

TEST_CASE("runtime inspect: privileged, network mode and the host-socket mount flag",
          "[virtualization][runtime][containers]") {
    const auto make = [] {
        ContainerRow r;
        r.id = id('a');
        r.id12 = id('a', 12);
        return r;
    };

    ContainerRow priv = make();
    REQUIRE(apply_inspect(priv, json::parse(R"({"HostConfig":{"Privileged":true,"NetworkMode":"host"},
                                                "Mounts":[{"Source":"/data"}],
                                                "Config":{"Env":["SECRET=1"]}})")));
    CHECK(priv.privileged == Tri::yes);
    CHECK(priv.network_mode == "host");
    CHECK(priv.socket_mounted == Tri::no);

    // a mount source that IS a default socket, or a directory that CONTAINS one
    for (const char* src : {"/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock",
                            "/run/containerd/containerd.sock", "/run", "/var/run", "/var", "/",
                            "/run/podman", "/run/containerd", "//run//", "/run/./"}) {
        ContainerRow r = make();
        REQUIRE(apply_inspect(r, json{{"HostConfig", {{"Privileged", false}, {"NetworkMode", "bridge"}}},
                                      {"Mounts", json::array({{{"Source", src}}})}}));
        INFO(src);
        CHECK(r.socket_mounted == Tri::yes);
        CHECK(r.privileged == Tri::no);
    }
    // unrelated mounts, and a path that merely shares a prefix
    for (const char* src : {"/data", "/run/dockerx", "/var/lib/docker", "/runx", "/run/user/1000",
                            "/home/jsmith", "relative/run"}) {
        ContainerRow r = make();
        REQUIRE(apply_inspect(r, json{{"HostConfig", json::object()},
                                      {"Mounts", json::array({{{"Source", src}}})}}));
        INFO(src);
        CHECK(r.socket_mounted == Tri::no);
    }
    // no mounts at all (null or empty) mounts no socket; an absent or wrong-typed Mounts is unknown
    ContainerRow none = make();
    REQUIRE(apply_inspect(none, json::parse(R"({"HostConfig":{},"Mounts":null})")));
    CHECK(none.socket_mounted == Tri::no);
    ContainerRow empty = make();
    REQUIRE(apply_inspect(empty, json::parse(R"({"HostConfig":{},"Mounts":[]})")));
    CHECK(empty.socket_mounted == Tri::no);
    ContainerRow absent = make();
    REQUIRE(apply_inspect(absent, json::parse(R"({"HostConfig":{}})")));
    CHECK(absent.socket_mounted == Tri::unknown);
    ContainerRow wrong = make();
    REQUIRE(apply_inspect(wrong, json::parse(R"({"HostConfig":{"Privileged":"yes","NetworkMode":5},"Mounts":"x"})")));
    CHECK(wrong.privileged == Tri::unknown);
    CHECK(wrong.network_mode == "unknown");
    CHECK(wrong.socket_mounted == Tri::unknown);
    // a mount whose Source is not a string is skipped, not thrown on
    ContainerRow odd = make();
    REQUIRE(apply_inspect(odd, json::parse(R"({"HostConfig":{},"Mounts":[{"Source":3},5,{"Source":"/data"}]})")));
    CHECK(odd.socket_mounted == Tri::no);

    // no HostConfig object: the row is untouched and the caller counts a failed inspection
    ContainerRow untouched = make();
    CHECK_FALSE(apply_inspect(untouched, json::parse(R"({"Mounts":[]})")));
    CHECK_FALSE(apply_inspect(untouched, json::parse("[]")));
    CHECK(untouched.privileged == Tri::unknown);
    CHECK(untouched.socket_mounted == Tri::unknown);
}

// ---------------------------------------------------------------------------------------------
// rows and tokens
// ---------------------------------------------------------------------------------------------

TEST_CASE("runtime rows: every field goes through wire_field", "[virtualization][runtime][rows]") {
    ContainerRow c;
    c.id12 = id('a', 12);
    c.name = "a|b\\";    // a pipe and a trailing backslash can neither open a field nor eat a delimiter
    c.image = "x\ny";
    c.state = "running";
    const std::string row = format_container_row("docker", c);
    std::size_t unescaped_pipes = 0;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|')
            ++i;
        else if (row[i] == '|')
            ++unescaped_pipes;
    }
    CHECK(unescaped_pipes == 8); // exactly the nine fields' separators
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.rfind("container|docker|aaaaaaaaaaaa|", 0) == 0);
    const std::string tail = "|unknown|unknown|unknown"; // privileged, network_mode, socket flag
    REQUIRE(row.size() > tail.size());
    CHECK(row.substr(row.size() - tail.size()) == tail);

    CHECK(format_endpoint_row(EndpointStatus::unset, "-", Dialect::none) == "endpoint|unset|-|-");
    CHECK(format_endpoint_row(EndpointStatus::endpoint_refused, "default_socket", Dialect::none) ==
          "endpoint|endpoint_refused|default_socket|-");
    CHECK(format_endpoint_row(EndpointStatus::ok, "", Dialect::podman) == "endpoint|ok|-|podman");
    CHECK(format_runtime_row("docker", "served", "present:0660:0:998", "present",
                             "27.3.1", "1.47") ==
          "runtime|docker|served|present:0660:0:998|present|27.3.1|1.47");
    CHECK(format_config_row("docker", "live-restore", "yes") == "config|docker|live-restore|yes");
}

TEST_CASE("runtime tokens: every token matches the plugin grammar", "[virtualization][runtime][tokens]") {
    const std::regex grammar{"^linux:virtualization:runtime_posture(:[a-z0-9_]+)+$"};
    for (const char* tail : {"busy", "deadline_exhausted", "rows_capped", "inspect_capped",
                             "daemon_json:malformed", "docker:overprivileged", "version:http_403",
                             "inspect:failed:3", "docker:network_fs_skipped", "mountinfo:unreadable"})
        CHECK(std::regex_match(rt_token(tail), grammar));
    CHECK(http_cause(403) == "http_403");
    CHECK(http_cause(100) == "http_100");
    CHECK(http_cause(599) == "http_599");
    CHECK(http_cause(99) == "http_other");
    CHECK(http_cause(600) == "http_other");
    CHECK(http_cause(-1) == "http_other");
    CHECK(http_cause(0) == "http_other");
    CHECK(std::regex_match(rt_token("x:" + http_cause(70000)), grammar));
    for (const auto o : {Outcome::eacces, Outcome::enoent, Outcome::timeout, Outcome::oversized,
                         Outcome::not_http, Outcome::other})
        CHECK(std::regex_match(rt_token("info:" + failure_cause(o)), grammar));
}
