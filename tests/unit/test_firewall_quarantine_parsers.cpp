/**
 * test_firewall_quarantine_parsers.cpp -- the pure core of the firewall
 * plugin's containment actions (firewall_quarantine_parsers.hpp, PRQ.1).
 *
 * Everything here runs on every host with no process, socket or file: the
 * drivers are exercised through fakes (a nft world, an iptables world, an
 * in-memory state store, a scripted TCP probe, a fake clock). The crash tests
 * stop a driver after every possible runner call -- before AND after that
 * call's effect -- then run the boot-time recovery and assert the one property
 * that matters: never an unrestricted host with an `active` record, never
 * unrecorded rules.
 */

#include "firewall_quarantine_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/trigger_engine.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::firewall::quarantine;
using namespace std::chrono_literals;

namespace {

Endpoint ex(std::string_view s) {
    auto e = parse_exception(s);
    INFO("exception: " << s);
    REQUIRE(e.has_value());
    return *e;
}

AllowSet make_set(std::vector<std::string> resolvers = {"203.0.113.53"},
                  std::vector<Endpoint> exceptions = {}) {
    auto b = build_allow_set("198.51.100.7", "198.51.100.7:50051", resolvers, exceptions);
    REQUIRE(b.has_value());
    return *b;
}

bool contains(const std::vector<std::string>& v, std::string_view s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

std::string join(const Argv& a) {
    std::string s;
    for (const auto& t : a) {
        if (!s.empty())
            s += ' ';
        s += t;
    }
    return s;
}

// ── fakes ───────────────────────────────────────────────────────────────────

struct CrashSim {};

struct FakeClock {
    std::chrono::steady_clock::time_point t = std::chrono::steady_clock::time_point{} + 1h;
    Deadline::NowFn fn() {
        return [this] { return t; };
    }
    void advance(std::chrono::milliseconds d) { t += d; }
};

struct FakeStore final : StateStore {
    std::string raw;          // empty: absent
    bool fail_save = false;
    bool fail_erase = false;  // the record cannot be deleted (a locked or read-only store)
    int fail_save_after = -1; // >= 0: every save after this many successes fails
    int saves = 0;
    StateLoad load() override {
        StateLoad l;
        if (raw.empty())
            return l;
        const auto p = parse_state(raw);
        if (!p) {
            l.kind = StateLoad::Kind::unreadable;
            return l;
        }
        l.kind = StateLoad::Kind::ok;
        l.state = *p;
        return l;
    }
    bool save(const QuarantineState& s) override {
        if (fail_save || (fail_save_after >= 0 && saves >= fail_save_after))
            return false;
        ++saves;
        raw = serialize_state(s);
        return true;
    }
    bool erase() override {
        if (fail_erase)
            return false;
        raw.clear();
        return true;
    }
    std::optional<QuarantineState> state() const { return parse_state(raw); }
};

ToolResult done(int code, std::string out = {}) {
    ToolResult r;
    r.ran = true;
    r.exit_code = code;
    r.output = std::move(out);
    return r;
}

/// Counts runner calls and can stop the process before or after the effect of
/// call number `crash_at`.
struct Crash {
    int calls = 0;
    int crash_at = -1;
    bool after_effect = false;
};

struct NftWorld {
    FakeClock* clock = nullptr;
    std::chrono::milliseconds per_call{0};
    bool table = false;
    std::string text;
    std::map<std::string, std::string> files;
    int next_file = 0;
    bool fail_load = false;
    bool fail_delete = false; // the table cannot be removed (a refused sudo, say)
    bool legacy = false;
    Crash crash;
    std::vector<Argv> log;
    std::function<void(const Argv&)> on_call; // runs before each call's effect (a test hook)

    ToolResult effect(const Argv& a) {
        if (on_call)
            on_call(a);
        if (a[0] == "/usr/sbin/iptables")
            return done(0, legacy ? "-P INPUT ACCEPT\n-N yuzu-quarantine\n" : "-P INPUT ACCEPT\n");
        if (a[1] == "-f") {
            if (fail_load)
                return done(1, "Error: syntax error, unexpected word");
            table = true;
            text = files[a[2]];
            return done(0);
        }
        if (a[1] == "delete") {
            if (fail_delete)
                return done(1, "sudo: a password is required");
            if (!table)
                return done(1, "Error: No such file or directory");
            table = false;
            text.clear();
            return done(0);
        }
        if (a[1] == "list") {
            if (!table)
                return done(1, "Error: No such file or directory");
            std::string out = "table inet yuzu_quarantine {\n";
            for (const char* c : {"input", "output", "forward"})
                out += std::string("\tchain ") + c + " {\n\t\ttype filter hook " + c +
                       " priority filter - 100; policy drop;\n\t}\n";
            return done(0, out + "}\n");
        }
        return done(1);
    }

    Runner runner() {
        return [this](const Argv& a, std::chrono::milliseconds) {
            ++crash.calls;
            log.push_back(a);
            if (clock)
                clock->advance(per_call);
            if (crash.calls == crash.crash_at && !crash.after_effect)
                throw CrashSim{};
            auto r = effect(a);
            if (crash.calls == crash.crash_at && crash.after_effect)
                throw CrashSim{};
            return r;
        };
    }
    Stage stage() {
        return [this](std::string_view, std::string_view suffix,
                      std::string_view contents) -> std::optional<StagedFile> {
            const auto path = std::format("/tmp/yuzu-fwq-{}{}", ++next_file, suffix);
            files[path] = std::string{contents};
            return StagedFile{path, nullptr};
        };
    }
};

struct IptFamily {
    std::set<std::string> chains;
    std::map<std::string, std::vector<std::string>> rules;
    std::map<std::string, std::vector<std::string>> builtin{
        {"INPUT", {}}, {"OUTPUT", {}}, {"FORWARD", {}}};
};

struct IptWorld {
    FakeClock* clock = nullptr;
    std::chrono::milliseconds per_call{0};
    std::map<std::string, IptFamily> fam; // by tool path
    std::function<bool(const std::string&)> fail_on;
    bool legacy = false;
    Crash crash;
    std::vector<Argv> log;
    int pre_existing_calls = 0;

    ToolResult effect(const Argv& a) {
        auto& f = fam[a[0]];
        const auto cmd = join(a);
        if (fail_on && fail_on(cmd))
            return done(1, "iptables: Resource temporarily unavailable");
        const auto& op = a[1];
        if (op == "-S") {
            std::string out = "-P INPUT ACCEPT\n";
            if (legacy)
                out += "-N yuzu-quarantine\n";
            for (const auto& c : f.chains)
                out += "-N " + c + "\n";
            for (const auto& [b, targets] : f.builtin)
                for (const auto& t : targets)
                    out += "-A " + b + " -j " + t + "\n";
            return done(0, out);
        }
        if (op == "-N") {
            if (f.chains.count(a[2]))
                return done(1, "Chain already exists");
            f.chains.insert(a[2]);
            return done(0);
        }
        if (op == "-A") {
            if (!f.chains.count(a[2]))
                return done(1, "No chain/target/match by that name");
            f.rules[a[2]].push_back(join(Argv(a.begin() + 3, a.end())));
            return done(0);
        }
        if (op == "-I") {
            f.builtin[a[2]].insert(f.builtin[a[2]].begin(), a[5]);
            return done(0);
        }
        if (op == "-D") {
            auto& v = f.builtin[a[2]];
            const auto it = std::find(v.begin(), v.end(), a[4]);
            if (it == v.end())
                return done(1, "Bad rule (does a matching rule exist in that chain?)");
            v.erase(it);
            return done(0);
        }
        if (op == "-F") {
            if (!f.chains.count(a[2]))
                return done(1, "No chain/target/match by that name");
            f.rules[a[2]].clear();
            return done(0);
        }
        if (op == "-X") {
            if (!f.chains.count(a[2]))
                return done(1, "No chain/target/match by that name");
            for (const auto& [b, targets] : f.builtin)
                if (std::find(targets.begin(), targets.end(), a[2]) != targets.end())
                    return done(1, "Too many links");
            f.chains.erase(a[2]);
            f.rules.erase(a[2]);
            return done(0);
        }
        return done(1);
    }

    Runner runner() {
        return [this](const Argv& a, std::chrono::milliseconds) {
            ++crash.calls;
            log.push_back(a);
            if (clock)
                clock->advance(per_call);
            if (crash.calls == crash.crash_at && !crash.after_effect)
                throw CrashSim{};
            auto r = effect(a);
            if (crash.calls == crash.crash_at && crash.after_effect)
                throw CrashSim{};
            return r;
        };
    }
    [[nodiscard]] std::set<std::string> live_chains(const std::string& tool) {
        return fam[tool].chains;
    }
};

/// Scripted probe: the control channel answers while `control_up`; the probe
/// target answers until `blocked` flips (set by the test from the world).
struct Probe {
    std::function<bool()> blocked = [] { return false; };
    bool control_up = true;
    ProbeOutcome blocked_result = ProbeOutcome::timeout;
    std::vector<std::string> asked;
    TcpProbe fn() {
        return [this](const std::string& ip, int port, std::chrono::milliseconds) {
            asked.push_back(std::format("{}:{}", ip, port));
            if (ip == "198.51.100.7")
                return control_up ? ProbeOutcome::connected : ProbeOutcome::timeout;
            return blocked() ? blocked_result : ProbeOutcome::connected;
        };
    }
};

/// A leg whose answers a test scripts: the Windows leg's decisions (a switched-off
/// profile, a stale-generation residue) are COM calls the pure core never sees,
/// so what the DRIVER does with each answer is pinned through this fake.
struct ScriptedLeg final : Leg {
    BackendKind k = BackendKind::windows;
    std::optional<std::string> refuse;     // preflight
    std::function<StepResult(OsPayload&)> on_apply = [](OsPayload&) { return StepResult::success(); };
    LegStatus status = [] {
        LegStatus l;
        l.state = OsState::enforcing;
        return l;
    }();
    int applies = 0;
    int removes = 0;
    BackendKind kind() const override { return k; }
    std::optional<std::string> preflight(Deadline&) override { return refuse; }
    StepResult apply(const AllowSet&, std::uint32_t, std::uint32_t, OsPayload& os, Deadline&,
                     const PersistOs&) override {
        ++applies;
        return on_apply(os);
    }
    StepResult remove(OsPayload&, Deadline&) override {
        ++removes;
        return StepResult::success();
    }
    LegStatus read_status(const OsPayload&, Deadline&) override { return status; }
};

constexpr const char* kProbeTarget = "192.0.2.80:443";

} // namespace

// ── token safety and addresses ──────────────────────────────────────────────

TEST_CASE("token safety: only the strict charset passes", "[agent][firewall_quarantine]") {
    CHECK(is_safe_token("10.0.0.1/8"));
    CHECK(is_safe_token("2001:db8::1"));
    CHECK(is_safe_token("yuzu-fwq-3_f"));
    for (const char* bad : {"", "a b", "a;b", "a\"b", "a'b", "a\nb", "a$b", "a`b", "a|b", "a&b",
                            "a#b", "a\\b", "a\tb", "a>b", "a(b"})
        CHECK_FALSE(is_safe_token(bad));
    CHECK_FALSE(is_safe_token(std::string(129, 'a')));
    // ruleset lines add the structural characters of our own templates, nothing else
    CHECK(is_safe_ruleset_line("type filter hook input priority -100; policy drop;"));
    CHECK(is_safe_ruleset_line("icmpv6 type { a, b } accept"));
    for (const char* bad : {"a\"b", "a$b", "a`b", "a|b", "a&b", "a#b", "a\\b", "a\tb", "a\nb"})
        CHECK_FALSE(is_safe_ruleset_line(bad));
    CHECK(is_safe_ruleset_text("a\nb\n"));
    CHECK_FALSE(is_safe_ruleset_text("a\nb;\nc\"d\n"));
}

TEST_CASE("ip literals: v4 strictness and v6 forms round-trip", "[agent][firewall_quarantine]") {
    CHECK(parse_ipv4("10.0.0.1"));
    for (const char* bad : {"10.0.0", "10.0.0.256", "10.0.0.01", "10.0.0.1.1", "a.b.c.d", " 1.1.1.1"})
        CHECK_FALSE(parse_ipv4(bad));
    for (const auto& [in, out] : std::vector<std::pair<std::string, std::string>>{
             {"2001:db8::1", "2001:db8::1"},
             {"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
             {"::1", "::1"},
             {"::", "::"},
             {"fe80::1:0:0:2", "fe80::1:0:0:2"},
             {"::ffff:1.2.3.4", "::ffff:102:304"},
             {"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"}}) {
        INFO(in);
        const auto ip = parse_ip(in);
        REQUIRE(ip);
        CHECK(format_ip(*ip) == out);
    }
    for (const char* bad : {"2001:db8:::1", "1::2::3", "12345::1", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
                            "g::1", ":1::2", "1::2:", "::1.2.3"})
        CHECK_FALSE(parse_ipv6(bad));
    CHECK(is_loopback(*parse_ip("127.8.8.8")));
    CHECK(is_loopback(*parse_ip("::1")));
    CHECK_FALSE(is_loopback(*parse_ip("::2")));
}

// ── exception grammar ───────────────────────────────────────────────────────

TEST_CASE("exception grammar: forms and defaults", "[agent][firewall_quarantine]") {
    const auto host = ex("10.0.0.5");
    CHECK(host.prefix == -1);
    CHECK(host.port == 0);
    CHECK(host.proto == Proto::both);
    CHECK(host.dir == Dir::out);

    const auto full = ex("10.0.0.5:22/tcp/in");
    CHECK(full.port == 22);
    CHECK(full.proto == Proto::tcp);
    CHECK(full.dir == Dir::in);

    const auto cidr = ex("10.1.2.3/8:443/udp");
    CHECK(cidr.prefix == 8);
    CHECK(addr_text(cidr) == "10.0.0.0/8"); // host bits zeroed
    CHECK(cidr.port == 443);
    CHECK(cidr.proto == Proto::udp);

    const auto v6 = ex("[2001:db8::1]:22/tcp/in");
    CHECK(v6.ip.v6);
    CHECK(v6.port == 22);
    const auto v6net = ex("2001:db8:1::/48/out");
    CHECK(v6net.prefix == 48);
    CHECK(v6net.port == 0);
    const auto v6prefix_port = ex("[2001:db8::]/32:443");
    CHECK(v6prefix_port.prefix == 32);
    CHECK(v6prefix_port.port == 443);

    // direction/protocol are order-insensitive
    CHECK(ex("10.0.0.5/in/tcp") == ex("10.0.0.5/tcp/in"));
    // canonical form round-trips
    for (const char* s : {"10.0.0.5", "10.0.0.5:22/tcp/in", "10.1.0.0/16:53/udp", "[2001:db8::1]:22/tcp/in",
                          "[2001:db8::]/32:443/out"})
        CHECK(ex(canonical(ex(s))) == ex(s));
}

TEST_CASE("exception grammar: rejections", "[agent][firewall_quarantine]") {
    const std::vector<std::pair<std::string, std::string>> cases{
        {"", "empty"},
        {"example.com", "bad_addr"},
        {"example.com:443", "bad_addr"},
        {"10.0.0.5:0", "bad_port"},
        {"10.0.0.5:70000", "bad_port"},
        {"10.0.0.5:abc", "bad_port"},
        {"10.0.0.5/33", "bad_prefix"},
        {"2001:db8::/129", "bad_prefix"},
        {"10.0.0.5/tcp/udp", "duplicate_proto"},
        {"10.0.0.5/in/out", "duplicate_dir"},
        {"10.0.0.5/icmp", "bad_field"},
        {"10.0.0.5:22/8:80", "duplicate_port"},
        {"10.0.0.0/8/9", "bad_prefix"},
        {"10.0.0.5//tcp", "bad_field"},
        {"10.0.0.5 /tcp", "unsafe_token"},
        {"10.0.0.5;reboot", "unsafe_token"},
        {"10.0.0.5\"", "unsafe_token"},
        {"10.0.0.5\n", "unsafe_token"},
        {"2001:db8::1:22", "bad_addr"}, // unbracketed v6 cannot carry a port: the last group is not a port
    };
    for (const auto& [text, why] : cases) {
        INFO(text);
        const auto e = parse_exception(text);
        // the last case parses as a (different) valid v6 literal -- it must simply not yield port 22
        if (text == "2001:db8::1:22") {
            REQUIRE(e);
            CHECK(e->port == 0);
            continue;
        }
        REQUIRE_FALSE(e.has_value());
        CHECK(e.error() == why);
    }
    // 46+ character address
    CHECK_FALSE(parse_exception("[" + std::string(46, '1') + "]"));
    CHECK(parse_exception(std::string(97, '1')).error() == "too_long");
}

TEST_CASE("exception csv: dedupe, caps and bad entries", "[agent][firewall_quarantine]") {
    auto r = parse_exceptions_csv("10.0.0.5,10.0.0.5:22/tcp/in,10.0.0.5");
    REQUIRE(r);
    CHECK(r->size() == 2);
    CHECK(parse_exceptions_csv("").value().empty());
    CHECK(parse_exceptions_csv("10.0.0.5,,10.0.0.6").error() == "empty_entry");
    CHECK(parse_exceptions_csv("10.0.0.5,nope").error() == "bad_addr");
    std::string big;
    for (int i = 1; i <= 65; ++i)
        big += std::format("10.0.{}.1,", i);
    big.pop_back();
    CHECK(parse_exceptions_csv(big).error() == "too_many_exceptions");
    CHECK(parse_exceptions_csv(std::string(9000, '1')).error() == "exceptions_too_long");
}

// ── allow set ───────────────────────────────────────────────────────────────

TEST_CASE("allow set: mandatory entries, caps and refusals", "[agent][firewall_quarantine]") {
    auto set = build_allow_set("198.51.100.7,2001:db8::7", "198.51.100.7:50051",
                               {"203.0.113.53", "2001:4860:4860::8888", "203.0.113.53", "bogus"},
                               {});
    REQUIRE(set);
    CHECK(set->control.size() == 2);
    CHECK(set->control[0].port == 50051);
    CHECK(set->control[0].proto == Proto::tcp);
    CHECK(set->resolvers.size() == 2);
    CHECK(contains(set->notes, "resolvers_invalid=1"));

    const auto flat = flatten(*set);
    auto count = [&](RuleKind k) {
        return std::count_if(flat.begin(), flat.end(), [&](const FlatRule& r) { return r.kind == k; });
    };
    CHECK(count(RuleKind::loopback) == 1);
    CHECK(count(RuleKind::control) == 2);
    CHECK(count(RuleKind::dhcp) == 1);
    CHECK(count(RuleKind::dns) == 4); // 2 resolvers x udp+tcp
    CHECK(count(RuleKind::nd) == 1);
    for (const auto& r : flat)
        if (r.kind == RuleKind::dhcp) {
            CHECK(r.svc_port == 67);
            CHECK(r.local_port == 68);
            CHECK(r.l4 == Proto::udp);
        }

    // a ninth resolver is dropped with a note
    std::vector<std::string> nine;
    for (int i = 1; i <= 9; ++i)
        nine.push_back(std::format("203.0.113.{}", i));
    auto capped = build_allow_set("198.51.100.7", "198.51.100.7:50051", nine, {});
    REQUIRE(capped);
    CHECK(capped->resolvers.size() == 8);
    CHECK(contains(capped->notes, "resolvers_dropped=1"));

    // an empty control set, a missing port and a hostname-only server are refused
    CHECK(build_allow_set("", "server.example.com:50051", {}, {}).error() == "control_set_empty");
    CHECK(build_allow_set("198.51.100.7", "198.51.100.7", {}, {}).error() == "control_port_missing");
    CHECK(build_allow_set("not-an-ip", "server.example.com:50051", {}, {}).error() ==
          "control_set_empty");
    // a literal server host is enough even when the resolved list is empty
    auto literal = build_allow_set("", "[2001:db8::7]:50051", {}, {});
    REQUIRE(literal);
    CHECK(literal->control.size() == 1);
    CHECK(literal->control[0].ip.v6);
}

TEST_CASE("allow set: the exception cap is cumulative across adds", "[agent][firewall_quarantine]") {
    auto set = make_set();
    for (int batch = 0; batch < 4; ++batch) {
        std::vector<Endpoint> add;
        for (int i = 1; i <= 16; ++i)
            add.push_back(ex(std::format("10.{}.{}.1", batch, i)));
        auto r = add_exceptions(set, add);
        REQUIRE(r);
        set = *r;
    }
    CHECK(set.exceptions.size() == 64);
    CHECK(add_exceptions(set, {ex("10.9.9.9")}).error() == "exception_cap_exceeded");
    // re-adding an existing entry is a no-op, not a cap breach
    CHECK(add_exceptions(set, {ex("10.0.1.1")}).has_value());
}

TEST_CASE("allow set: remove never removes a mandatory allowance", "[agent][firewall_quarantine]") {
    auto set = make_set({"203.0.113.53"}, {ex("10.0.0.5:22/tcp/in")});
    for (const char* mandatory : {"127.0.0.1", "::1", "198.51.100.7:50051/tcp", "203.0.113.53:53",
                                  "0.0.0.0/0:67/udp", "0.0.0.0/0:68/udp"}) {
        INFO(mandatory);
        const auto r = remove_exceptions(set, {ex(mandatory)});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "mandatory_allowance");
    }
    // the same host on a different port is an ordinary exception, not the control channel
    auto other = add_exceptions(set, {ex("198.51.100.7:22/tcp/in")});
    REQUIRE(other);
    auto removed = remove_exceptions(*other, {ex("198.51.100.7:22/tcp/in")});
    REQUIRE(removed);
    CHECK(removed->removed == 1);
    // an operator exception goes; an absent one is a counted no-op
    auto r = remove_exceptions(set, {ex("10.0.0.5:22/tcp/in"), ex("10.9.9.9")});
    REQUIRE(r);
    CHECK(r->removed == 1);
    CHECK(r->set.exceptions.empty());
    // ND has no ICMP form in the grammar, so it cannot be named, let alone removed
    CHECK_FALSE(parse_exception("ff02::1/icmpv6"));
}

// ── ports are service ports, per direction, on every leg ────────────────────

TEST_CASE("direction-aware ports: out is the remote port, in is the local port",
          "[agent][firewall_quarantine]") {
    const auto set = make_set({}, {ex("10.0.0.5:22/tcp/in"), ex("10.0.0.6:443/tcp/out")});

    // Windows: inbound -> LocalPorts, outbound -> RemotePorts
    const auto specs = win_rule_specs(set, 1);
    int checked = 0;
    for (const auto& s : specs) {
        if (s.remote_addrs == "10.0.0.5") {
            CHECK(s.dir == Dir::in);
            CHECK(s.local_ports == "22");
            CHECK(s.remote_ports.empty());
            ++checked;
        }
        if (s.remote_addrs == "10.0.0.6") {
            CHECK(s.dir == Dir::out);
            CHECK(s.remote_ports == "443");
            CHECK(s.local_ports.empty());
            ++checked;
        }
    }
    CHECK(checked == 2);

    // nft: request direction carries dport, the reply path carries sport
    const auto nft = nft_ruleset_text(set);
    CHECK(nft.find("ip saddr 10.0.0.5 tcp dport 22 accept") != nft.npos);  // input
    CHECK(nft.find("ip daddr 10.0.0.5 tcp sport 22 accept") != nft.npos);  // output reply
    CHECK(nft.find("ip daddr 10.0.0.6 tcp dport 443 accept") != nft.npos); // output
    CHECK(nft.find("ip saddr 10.0.0.6 tcp sport 443 accept") != nft.npos); // input reply

    // iptables
    const auto plan = iptables_build_plan(set, kIptablesPath, 1, false);
    std::vector<std::string> lines;
    for (const auto& a : plan)
        lines.push_back(join(a));
    CHECK(contains(lines, "/usr/sbin/iptables -A yuzu-fwq-1 -s 10.0.0.5 -p tcp --dport 22 -j ACCEPT"));
    CHECK(contains(lines, "/usr/sbin/iptables -A yuzu-fwq-1 -d 10.0.0.5 -p tcp --sport 22 -j ACCEPT"));
    CHECK(contains(lines, "/usr/sbin/iptables -A yuzu-fwq-1 -d 10.0.0.6 -p tcp --dport 443 -j ACCEPT"));

    // pf
    const auto pf = pf_anchor_ruleset(set);
    CHECK(pf.find("pass in quick inet proto tcp from 10.0.0.5 to any port 22 keep state") != pf.npos);
    CHECK(pf.find("pass out quick inet proto tcp from any to 10.0.0.6 port 443 keep state") != pf.npos);
}

TEST_CASE("both protocols: an exception without a protocol opens tcp AND udp",
          "[agent][firewall_quarantine]") {
    const auto set = make_set({}, {ex("10.0.0.5:53")});
    const auto nft = nft_ruleset_text(set);
    CHECK(nft.find("ip daddr 10.0.0.5 tcp dport 53 accept") != nft.npos);
    CHECK(nft.find("ip daddr 10.0.0.5 udp dport 53 accept") != nft.npos);
    const auto bare = nft_ruleset_text(make_set({}, {ex("10.0.0.7/udp")}));
    CHECK(bare.find("ip daddr 10.0.0.7 meta l4proto udp accept") != bare.npos);
    CHECK(bare.find("10.0.0.7 meta l4proto tcp") == bare.npos);
}

// ── verify / rollback decision ──────────────────────────────────────────────

TEST_CASE("verify decision matrix over tri-state probes", "[agent][firewall_quarantine]") {
    using P = ProbeOutcome;
    using V = VerifyOutcome;
    // connected or refused before, timeout after: verified
    CHECK(decide_verify(true, P::connected, P::timeout) == V::verified);
    CHECK(decide_verify(true, P::refused, P::timeout) == V::verified);
    // no probe target: unproven, never "verified"
    CHECK(decide_verify(true, std::nullopt, std::nullopt) == V::unproven);
    // control channel down beats everything
    CHECK(decide_verify(false, P::connected, P::timeout) == V::control_unreachable);
    CHECK(decide_verify(false, std::nullopt, std::nullopt) == V::control_unreachable);
    // reachable after: connected OR refused (an RST means the packet arrived)
    CHECK(decide_verify(true, P::connected, P::connected) == V::probe_still_reachable);
    CHECK(decide_verify(true, P::connected, P::refused) == V::probe_still_reachable);
    // unreachable before the mutation: nothing to prove against
    CHECK(decide_verify(true, P::timeout, P::timeout) == V::probe_unreachable_before_apply);

    using A = VerifyAction;
    using M = VerifyMode;
    // a verified or unproven apply is kept, never undone
    CHECK(verify_action(V::verified, M::initial) == A::keep);
    CHECK(verify_action(V::unproven, M::initial) == A::keep);
    CHECK(verify_action(V::control_unreachable, M::initial) == A::rollback_to_absence);
    CHECK(verify_action(V::probe_still_reachable, M::initial) == A::rollback_to_absence);
    CHECK(verify_action(V::control_unreachable, M::update) == A::revert_to_previous);
    CHECK(verify_action(V::probe_still_reachable, M::update) == A::revert_to_previous);
    // boot-time re-apply never undoes anything on an unreachable server
    CHECK(verify_action(V::control_unreachable, M::reapply) == A::keep);
    CHECK(verify_action(V::probe_still_reachable, M::reapply) == A::keep);
    CHECK(verify_action(V::probe_unreachable_before_apply, M::initial) == A::refuse);

    CHECK(verify_row(true, P::connected, P::timeout) == "verify|control=ok|probe=blocked");
    CHECK(verify_row(true, P::connected, P::connected) == "verify|control=ok|probe=reachable");
    CHECK(verify_row(true, P::connected, P::refused) == "verify|control=ok|probe=refused");
    CHECK(verify_row(false, std::nullopt, std::nullopt) == "verify|control=fail|probe=unproven");
}

TEST_CASE("probe target must be an IP literal", "[agent][firewall_quarantine]") {
    CHECK(parse_probe_target("192.0.2.80:443"));
    CHECK(parse_probe_target("[2001:db8::80]:443"));
    CHECK(parse_probe_target("example.com:443").error() == "probe_target_not_literal");
    CHECK(parse_probe_target("192.0.2.80").error() == "probe_target_bad_port");
    CHECK(parse_probe_target("192.0.2.80:0").error() == "probe_target_bad_port");
    CHECK(parse_probe_target("127.0.0.1:443").error() == "probe_target_loopback");
    CHECK(parse_probe_target("[::1]:443").error() == "probe_target_loopback");
    CHECK(parse_probe_target("").error() == "probe_target_not_literal");
    CHECK(parse_probe_target("192.0.2.80:443")->text() == "192.0.2.80:443");
    CHECK(parse_probe_target("[2001:db8::80]:443")->text() == "[2001:db8::80]:443");
}

// ── TTL ─────────────────────────────────────────────────────────────────────

TEST_CASE("ttl: bounds, parameter parsing and expiry", "[agent][firewall_quarantine]") {
    CHECK_FALSE(validate_ttl(59));
    CHECK(validate_ttl(60));
    CHECK(validate_ttl(2'592'000));
    CHECK_FALSE(validate_ttl(2'592'001));
    CHECK(parse_ttl_param("").value() == 0);
    CHECK(parse_ttl_param("120").value() == 120);
    for (const char* bad : {"59", "2592001", "abc", "-5", "1e3", " 90"})
        CHECK(parse_ttl_param(bad).error() == "ttl_out_of_bounds");

    QuarantineState s;
    s.ttl_expires = 1000;
    CHECK_FALSE(ttl_expired(s, 999));
    CHECK(ttl_expired(s, 1000)); // expires at the boundary
    CHECK(ttl_expired(s, 5000));
    s.ttl_expires = 0; // no TTL never expires
    CHECK_FALSE(ttl_expired(s, 9'000'000'000));
}

// ── state record ────────────────────────────────────────────────────────────

TEST_CASE("state record: round trip and strict parsing", "[agent][firewall_quarantine]") {
    QuarantineState s;
    s.phase = Phase::active;
    s.generation = 7;
    s.prev_generation = 6;
    s.applied_at = 1'700'000'000;
    s.ttl_expires = 1'700'003'600;
    s.probe_target = "192.0.2.80:443";
    s.backend = BackendKind::iptables;
    s.allow = make_set({"203.0.113.53", "2001:4860:4860::8888"},
                       {ex("10.0.0.5:22/tcp/in"), ex("[2001:db8::]/32:443/out")});
    s.os.pf_token = "3665316113424588829";
    s.os.boot_time = "1699999999.123456";
    s.os.ipt_gen = 5;
    s.os.ipt_v6 = true;
    s.os.rules_not_disabled = 3;
    s.os.stale_rules_left = 2;
    s.os.state_flush_failed = true;
    s.last_verify = "verified control_ok probe_blocked";
    const auto text = serialize_state(s);
    const auto back = parse_state(text);
    REQUIRE(back);
    CHECK(back->phase == Phase::active);
    CHECK(back->generation == 7);
    CHECK(back->prev_generation == 6);
    CHECK(back->applied_at == s.applied_at);
    CHECK(back->ttl_expires == s.ttl_expires);
    CHECK(back->probe_target == s.probe_target);
    CHECK(back->backend == BackendKind::iptables);
    CHECK(back->allow == s.allow);
    CHECK(back->os == s.os);
    CHECK(back->last_verify == s.last_verify);

    for (const auto phase : {Phase::applying, Phase::releasing}) {
        s.phase = phase;
        CHECK(parse_state(serialize_state(s))->phase == phase);
    }

    // corrupt or version-mismatched records are unreadable, never silently dropped
    auto replace = [&](std::string t, std::string_view a, std::string_view b) {
        const auto at = t.find(a);
        REQUIRE(at != t.npos);
        return t.replace(at, a.size(), b);
    };
    CHECK_FALSE(parse_state(""));
    CHECK_FALSE(parse_state("garbage"));
    CHECK_FALSE(parse_state(replace(text, "v=1", "v=2")));
    CHECK_FALSE(parse_state(replace(text, "phase=active", "phase=sideways")));
    CHECK_FALSE(parse_state(replace(text, "backend=iptables", "backend=carrier-pigeon")));
    CHECK_FALSE(parse_state(replace(text, "gen=7", "gen=zero")));
    CHECK_FALSE(parse_state(replace(text, "probe=192.0.2.80:443", "probe=example.com:443")));
    CHECK_FALSE(parse_state(text + "mystery=1\n"));
    CHECK_FALSE(parse_state(text + "gen=8\n")); // duplicate scalar
    CHECK_FALSE(parse_state(text + "stale_left=1\n"));
    CHECK_FALSE(parse_state(text + "flush_failed=1\n"));
    CHECK_FALSE(parse_state(replace(text, "flush_failed=1", "flush_failed=0")));
    CHECK_FALSE(parse_state(replace(text, "stale_left=2", "stale_left=many")));
    // a clean record carries none of the residue keys
    QuarantineState clean = s;
    clean.os.rules_not_disabled = 0;
    clean.os.stale_rules_left = 0;
    clean.os.state_flush_failed = false;
    const auto clean_text = serialize_state(clean);
    CHECK(clean_text.find("stale_left") == std::string::npos);
    CHECK(clean_text.find("flush_failed") == std::string::npos);
    CHECK_FALSE(has_residue(parse_state(clean_text)->os));
    CHECK(residue_reason(back->os) == "rules_not_disabled");
    CHECK_FALSE(parse_state(replace(text, "exc=10.0.0.5:22/tcp/in", "exc=10.0.0.5;rm")));
    // no control endpoint: not a record we could ever have written
    std::string no_ctl;
    for (const auto line : detail::split(text, '\n'))
        if (!line.starts_with("ctl="))
            no_ctl += std::string{line} + "\n";
    CHECK_FALSE(parse_state(no_ctl));
    CHECK_FALSE(parse_state(std::string(kMaxStateBytes + 1, 'x')));
}

TEST_CASE("status of an unreadable record is degraded|state_unreadable, never dropped",
          "[agent][firewall_quarantine]") {
    NftWorld w;
    FakeStore store;
    store.raw = "not a record";
    Probe probe;
    NftLeg leg(w.runner(), w.stage());
    Env env{leg, store, probe.fn(), [] { return 1'000; }};
    Deadline dl;
    const auto o = report_status(env, dl);
    CHECK(o.status == "degraded");
    CHECK(o.reason == "state_unreadable");
    // recovery leaves the OS alone rather than guessing
    const auto r = recover_at_init(env, dl);
    CHECK(r.status == "degraded");
    CHECK(w.crash.calls == 1); // only the status read's nft list
}

// ── Windows pure pieces ─────────────────────────────────────────────────────

TEST_CASE("windows rule specs: names, group, directions", "[agent][firewall_quarantine]") {
    const auto set = make_set({"203.0.113.53"}, {ex("10.0.0.5:22/tcp/in")});
    const auto specs = win_rule_specs(set, 3);
    REQUIRE_FALSE(specs.empty());
    std::set<std::string> names;
    for (const auto& s : specs) {
        CHECK(s.name.starts_with("YuzuFirewall_Quarantine_3_"));
        CHECK_FALSE(is_legacy_marker(s.name));
        CHECK_FALSE(s.name.starts_with(kLegacyWinRulePrefix));
        CHECK(names.insert(s.name).second); // unique
    }
    CHECK(kWinGroup == "Yuzu Firewall Quarantine");
    // control channel: outbound tcp to the server port, RemotePorts only
    const auto ctl = std::find_if(specs.begin(), specs.end(),
                                  [](const WinRuleSpec& s) { return s.remote_addrs == "198.51.100.7"; });
    REQUIRE(ctl != specs.end());
    CHECK(ctl->dir == Dir::out);
    CHECK(ctl->protocol == 6);
    CHECK(ctl->remote_ports == "50051");
    // the inbound exception sets LocalPorts only (P3)
    const auto in = std::find_if(specs.begin(), specs.end(),
                                 [](const WinRuleSpec& s) { return s.remote_addrs == "10.0.0.5"; });
    REQUIRE(in != specs.end());
    CHECK(in->dir == Dir::in);
    CHECK(in->local_ports == "22");
    CHECK(in->remote_ports.empty());
    // DHCP both ways, ND icmpv6 both ways, no loopback rule
    int dhcp = 0, nd = 0;
    for (const auto& s : specs) {
        dhcp += s.protocol == 17 && s.local_ports == "68" && s.remote_ports == "67";
        nd += s.protocol == 58 && s.icmp_types.find("133:*") != std::string::npos;
    }
    CHECK(dhcp == 2);
    CHECK(nd == 2);
    // a different generation shares no names
    for (const auto& s : win_rule_specs(set, 4))
        CHECK(names.count(s.name) == 0);
    CHECK(is_legacy_marker("YuzuQuarantine_allow_1"));
    CHECK_FALSE(is_legacy_marker("YuzuFirewall_Quarantine_1_1"));
}

TEST_CASE("windows: every enabled rule outside our group is disabled", "[agent][firewall_quarantine]") {
    const std::vector<WinRuleInfo> rules{
        {"CoreNet-DHCP-Out", "Core Networking", true},
        {"Remote Desktop - User Mode (TCP-In)", "Remote Desktop", true},
        {"Disabled already", "Misc", false},
        {"YuzuFirewall_Quarantine_1_1", "Yuzu Firewall Quarantine", true},
        {"YuzuFirewall_Quarantine_1_2", "", true}, // ours by prefix even without the group
        {"No group at all", "", true},
    };
    const auto off = win_rules_to_disable(rules);
    REQUIRE(off.size() == 3);
    CHECK(off[0] == "CoreNet-DHCP-Out");
    CHECK(off[1] == "Remote Desktop - User Mode (TCP-In)");
    CHECK(off[2] == "No group at all");
    for (const auto& n : off)
        CHECK_FALSE(n.starts_with(kWinRulePrefix));
    // the one "is ours" test: our group, or our name prefix without the group
    CHECK(is_our_win_rule("anything", kWinGroup));
    CHECK(is_our_win_rule("YuzuFirewall_Quarantine_1_2", ""));
    CHECK_FALSE(is_our_win_rule("YuzuQuarantine_allow_1", "")); // the legacy plugin's
    CHECK_FALSE(is_our_win_rule("No group at all", ""));
}

TEST_CASE("windows: prior policy image and the write-once decision", "[agent][firewall_quarantine]") {
    WinPriorPolicy p{};
    for (auto& x : p)
        x = {WinAction::block, WinAction::allow};
    p[2] = {WinAction::block, WinAction::block};
    const auto text = serialize_prior_policy(p);
    const auto back = parse_prior_policy(text);
    REQUIRE(back);
    CHECK(*back == p);
    CHECK(is_complete_prior_policy(p));
    CHECK_FALSE(is_quarantine_shaped(p));

    // an incomplete image is never replayed
    CHECK_FALSE(parse_prior_policy("v=1\ndomain.in=allow\n"));
    CHECK_FALSE(parse_prior_policy(text + "public.in=allow\n")); // duplicate
    CHECK_FALSE(parse_prior_policy("v=2\n"));
    CHECK_FALSE(parse_prior_policy(std::string(text).replace(text.find("allow"), 5, "maybe")));
    WinPriorPolicy partial = p;
    partial[1].out = WinAction::unknown;
    CHECK_FALSE(is_complete_prior_policy(partial));

    WinPriorPolicy blocked{};
    for (auto& x : blocked)
        x = {WinAction::block, WinAction::block};
    CHECK(is_quarantine_shaped(blocked));
    // existing image always wins
    CHECK(decide_prior_store(true, false, p) == PriorStore::keep_existing);
    CHECK(decide_prior_store(true, true, blocked) == PriorStore::keep_existing);
    CHECK(decide_prior_store(false, false, partial) == PriorStore::refuse_incomplete);
    // block/block is refused ONLY when our own group is already present...
    CHECK(decide_prior_store(false, true, blocked) == PriorStore::refuse_unrestorable);
    // ...it is a legitimate hardened posture on an untouched host
    CHECK(decide_prior_store(false, false, blocked) == PriorStore::store);
    CHECK(decide_prior_store(false, false, p) == PriorStore::store);
}

TEST_CASE("windows: disabled-rule list round trip and update plan", "[agent][firewall_quarantine]") {
    const std::vector<std::string> names{"Plain", "With|pipe", "back\\slash", "multi\nline",
                                         "unicode \xC3\xA9"};
    const auto back = parse_disabled_rules(serialize_disabled_rules(names));
    REQUIRE(back);
    CHECK(*back == names);
    CHECK_FALSE(parse_disabled_rules("no header"));
    CHECK_FALSE(parse_disabled_rules("v=1\nbad\\x\n"));
    CHECK(parse_disabled_rules("v=1\n")->empty());

    const auto set = make_set({}, {ex("10.0.0.5:22/tcp/in")});
    const auto g1 = win_rule_specs(set, 1);
    const auto g2 = win_rule_specs(set, 2);
    std::vector<std::string> existing;
    for (const auto& s : g1)
        existing.push_back(s.name);
    // an update adds the new generation's rules first and removes stale ones last
    auto plan = win_update_plan(existing, g2);
    CHECK(plan.add.size() == g2.size());
    CHECK(plan.remove == existing);
    // the same generation again is a no-op (idempotent re-apply, no duplicates)
    auto again = win_update_plan(existing, g1);
    CHECK(again.add.empty());
    CHECK(again.remove.empty());
    // converges from a crash mid-add
    std::vector<std::string> half(existing.begin(), existing.begin() + 2);
    auto resume = win_update_plan(half, g1);
    CHECK(resume.add.size() == g1.size() - 2);
    CHECK(resume.remove.empty());
}

TEST_CASE("windows: the disabled-rule list is written on the first apply and only ever grows",
          "[agent][firewall_quarantine]") {
    SECTION("the first apply always writes the list, even an empty one") {
        const auto m = win_merge_disabled_list({}, {}, /*list_exists=*/false);
        CHECK(m.grew);
        CHECK(m.list.empty());
        CHECK_FALSE(m.over_cap);
    }
    SECTION("the first apply stores what it disables") {
        const auto m = win_merge_disabled_list({}, {"RDP", "SMB"}, false);
        CHECK(m.grew);
        CHECK(m.list == std::vector<std::string>{"RDP", "SMB"});
    }
    SECTION("a later apply with nothing new writes nothing") {
        const auto m = win_merge_disabled_list({"RDP", "SMB"}, {"SMB"}, true);
        CHECK_FALSE(m.grew);
        CHECK(m.list == std::vector<std::string>{"RDP", "SMB"});
        // an empty stored list that exists is not rewritten either
        CHECK_FALSE(win_merge_disabled_list({}, {}, true).grew);
    }
    SECTION("a later apply appends only the names it has not seen, in order") {
        const auto m = win_merge_disabled_list({"RDP", "SMB"}, {"SMB", "WinRM", "RDP", "Print"}, true);
        CHECK(m.grew);
        CHECK(m.list == std::vector<std::string>{"RDP", "SMB", "WinRM", "Print"});
    }
    SECTION("a name enabled again during the quarantine is never dropped from the list") {
        const auto m = win_merge_disabled_list({"RDP", "SMB"}, {}, true);
        CHECK(m.list == std::vector<std::string>{"RDP", "SMB"});
    }
    SECTION("the cap refuses the apply") {
        std::vector<std::string> at_cap;
        for (std::size_t i = 0; i < kMaxDisabledRules; ++i)
            at_cap.push_back(std::format("rule-{}", i));
        CHECK_FALSE(win_merge_disabled_list(at_cap, {"rule-3"}, true).over_cap); // nothing new
        const auto over = win_merge_disabled_list(at_cap, {"one-more"}, true);
        CHECK(over.over_cap);
        CHECK(over.grew);
        CHECK(win_merge_disabled_list({}, at_cap, false).over_cap == false);
    }
}

TEST_CASE("windows: release restores the captured policy; the default applies only without an image",
          "[agent][firewall_quarantine]") {
    WinPriorPolicy image{};
    image[0] = {WinAction::allow, WinAction::allow};
    image[1] = {WinAction::block, WinAction::block};
    image[2] = {WinAction::block, WinAction::allow};
    for (std::size_t i = 0; i < image.size(); ++i)
        CHECK(win_release_policy(image, i) == image[i]);

    // no image: Windows' own default, inbound block and outbound allow, on every profile
    for (std::size_t i = 0; i < 3; ++i) {
        const auto d = win_release_policy(std::nullopt, i);
        CHECK(d.in == WinAction::block);
        CHECK(d.out == WinAction::allow);
    }
    // a hardened image is restored as captured, never replaced by the default
    WinPriorPolicy hardened{};
    for (auto& x : hardened)
        x = {WinAction::block, WinAction::block};
    CHECK(win_release_policy(hardened, 1) == WinProfilePolicy{WinAction::block, WinAction::block});
    // an unknown action (parse_prior_policy never yields one) restores on the safe side
    WinPriorPolicy odd{};
    odd[0] = {WinAction::unknown, WinAction::unknown};
    CHECK(win_release_policy(odd, 0) == WinProfilePolicy{WinAction::block, WinAction::block});
    // an index outside the three profiles reads as no image
    CHECK(win_release_policy(image, 3) == WinProfilePolicy{WinAction::block, WinAction::allow});
}

TEST_CASE("windows: a profile with the firewall switched off, or unreadable, refuses containment",
          "[agent][firewall_quarantine]") {
    using K = WinSwitchVerdict::Kind;
    const WinSwitchReading on{true, true, true};
    CHECK(win_firewall_switch_verdict(on).kind == K::ok);
    CHECK(win_firewall_switch_token(win_firewall_switch_verdict(on)).empty());

    for (std::size_t i = 0; i < on.size(); ++i) {
        INFO("profile " << kWinProfileLabels[i]);
        auto off = on;
        off[i] = false;
        const auto d = win_firewall_switch_verdict(off);
        CHECK(d.kind == K::disabled);
        CHECK(d.profile == i);
        const auto dt = win_firewall_switch_token(d);
        CHECK(dt == "firewall_disabled:" + std::string{kWinProfileLabels[i]});
        CHECK(is_safe_token(dt));

        auto unreadable = on;
        unreadable[i] = std::nullopt; // S_FALSE or an error: never a guess
        const auto u = win_firewall_switch_verdict(unreadable);
        CHECK(u.kind == K::unreadable);
        CHECK(u.profile == i);
        const auto ut = win_firewall_switch_token(u);
        CHECK(ut == "firewall_state_unreadable:" + std::string{kWinProfileLabels[i]});
        CHECK(is_safe_token(ut));
    }

    // every shape: the first disabled profile wins, and a definite "off" outranks
    // an unreadable profile that sorts before it
    CHECK(win_firewall_switch_verdict({false, false, false}).profile == 0);
    const auto mixed = win_firewall_switch_verdict({std::nullopt, true, false});
    CHECK(mixed.kind == K::disabled);
    CHECK(mixed.profile == 2);
    const auto two_unreadable = win_firewall_switch_verdict({true, std::nullopt, std::nullopt});
    CHECK(two_unreadable.kind == K::unreadable);
    CHECK(two_unreadable.profile == 1);
}

TEST_CASE("windows: the switch verdict settles the status read the same way on every host",
          "[agent][firewall_quarantine]") {
    // on everywhere: nothing settled, the read goes on and the status is untouched
    LegStatus on;
    on.state = OsState::enforcing;
    CHECK_FALSE(win_switch_status(win_firewall_switch_verdict({true, true, true}), on));
    CHECK(on.state == OsState::enforcing);
    CHECK(on.reapply_helps);
    CHECK(on.reason.empty());
    CHECK(on.notes.empty());

    // switched off: not enforcing, and a re-apply cannot help (it refuses the same way)
    LegStatus off;
    CHECK(win_switch_status(win_firewall_switch_verdict({true, false, true}), off));
    CHECK(off.state == OsState::not_enforcing);
    CHECK(off.reason == "firewall_disabled");
    CHECK_FALSE(off.reapply_helps);
    CHECK(off.notes == std::vector<std::string>{"firewall_profile=Private"});

    // unreadable: never a guess either way; a note names the profile, nothing is claimed
    LegStatus unread;
    unread.state = OsState::enforcing; // a stale optimistic value must not survive
    CHECK(win_switch_status(win_firewall_switch_verdict({true, true, std::nullopt}), unread));
    CHECK(unread.state == OsState::unreadable);
    CHECK(unread.reason.empty());
    CHECK(unread.reapply_helps);
    CHECK(unread.notes == std::vector<std::string>{"firewall_profile=Public"});
}

TEST_CASE("windows: a stale generation's rules that survive removal are residue",
          "[agent][firewall_quarantine]") {
    const auto set = make_set({}, {ex("10.0.0.5:22/tcp/in")});
    const auto g1 = win_rule_specs(set, 1);
    const auto g2 = win_rule_specs(set, 2);
    auto names = [](const std::vector<WinRuleSpec>& v) {
        std::vector<std::string> out;
        for (const auto& s : v)
            out.push_back(s.name);
        return out;
    };
    // a clean removal leaves exactly the current generation: no residue
    CHECK(win_update_plan(names(g2), g2).remove.empty());
    // an old rule that would not delete is residue; the current generation never is
    auto left = names(g2);
    left.push_back(names(g1)[1]);
    CHECK(win_update_plan(left, g2).remove == std::vector<std::string>{names(g1)[1]});
    // a second generation's leftover is counted beside the first's (recomputed per apply)
    left.push_back(names(g1)[2]);
    CHECK(win_update_plan(left, g2).remove.size() == 2);
    // nothing of the current generation, even when it is all that is left
    CHECK(win_update_plan(names(g1), g1).remove.empty());
}

// ── nftables ────────────────────────────────────────────────────────────────

TEST_CASE("nft ruleset text: atomic idiom, drop chains, safe lines", "[agent][firewall_quarantine]") {
    const auto set = make_set({"203.0.113.53", "2001:4860:4860::8888"},
                              {ex("10.0.0.5:22/tcp/in"), ex("[2001:db8::]/32:443/out")});
    const auto t = nft_ruleset_text(set);
    // one transaction: create-if-absent, flush, then the full table
    const auto first = t.find("table inet yuzu_quarantine {}\n");
    const auto flush = t.find("flush table inet yuzu_quarantine\n");
    const auto full = t.find("table inet yuzu_quarantine {\n");
    REQUIRE(first != t.npos);
    REQUIRE(flush != t.npos);
    REQUIRE(full != t.npos);
    CHECK(first < flush);
    CHECK(flush < full);
    for (const char* c : {"input", "output", "forward"}) {
        const auto want = std::format("type filter hook {} priority -100; policy drop;", c);
        INFO(want);
        CHECK(t.find(want) != t.npos);
    }
    // exact allowances
    CHECK(t.find("iif lo accept") != t.npos);
    CHECK(t.find("oif lo accept") != t.npos);
    CHECK(t.find("ip daddr 198.51.100.7 tcp dport 50051 accept") != t.npos);
    CHECK(t.find("ip saddr 198.51.100.7 tcp sport 50051 accept") != t.npos);
    CHECK(t.find("udp sport 68 udp dport 67 accept") != t.npos);
    CHECK(t.find("udp sport 67 udp dport 68 accept") != t.npos);
    CHECK(t.find("ip daddr 203.0.113.53 udp dport 53 accept") != t.npos);
    CHECK(t.find("ip6 daddr 2001:4860:4860::8888 tcp dport 53 accept") != t.npos);
    CHECK(t.find("icmpv6 type { nd-router-solicit") != t.npos);
    // neighbour discovery is 133-136 on every leg: redirect (137) is not allowed
    CHECK(t.find("nd-redirect") == t.npos);
    CHECK(t.find("ip6 daddr 2001:db8::/32 tcp dport 443 accept") != t.npos);
    // stateless: no established accept
    CHECK(t.find("established") == t.npos);
    CHECK(t.find("ct state") == t.npos);
    // the forward chain has no accept at all
    const auto fwd = t.find("chain forward");
    REQUIRE(fwd != t.npos);
    CHECK(t.substr(fwd).find("accept") == t.npos);
    // every line is clean
    CHECK(is_safe_ruleset_text(t));
    // no line repeated within a chain
    CHECK(nft_ruleset_text(set) == t);

    CHECK(join(nft_apply_argv("/tmp/yuzu-fwq-1.nft")) == "/usr/sbin/nft -f /tmp/yuzu-fwq-1.nft");
    CHECK(join(nft_delete_argv()) == "/usr/sbin/nft delete table inet yuzu_quarantine");
    CHECK(join(nft_list_argv()) == "/usr/sbin/nft list table inet yuzu_quarantine");
    for (const auto& a : {nft_apply_argv("/tmp/x.nft"), nft_delete_argv(), nft_list_argv()})
        CHECK(all_tokens_safe(a));
}

TEST_CASE("nft list parser: all three chains at drop vs partial", "[agent][firewall_quarantine]") {
    const std::string good =
        "table inet yuzu_quarantine {\n"
        "\tchain input {\n\t\ttype filter hook input priority filter - 100; policy drop;\n\t\tiif \"lo\" accept\n\t}\n"
        "\tchain output {\n\t\ttype filter hook output priority filter - 100; policy drop;\n\t}\n"
        "\tchain forward {\n\t\ttype filter hook forward priority filter - 100; policy drop;\n\t}\n"
        "}\n";
    auto l = parse_nft_list_table(good);
    CHECK(l.found);
    CHECK(l.chains.size() == 3);
    CHECK(nft_listing_enforcing(l));

    auto accept = good;
    accept.replace(accept.find("policy drop", accept.find("chain output")), 11, "policy accept");
    CHECK_FALSE(nft_listing_enforcing(parse_nft_list_table(accept)));

    const std::string missing =
        "table inet yuzu_quarantine {\n\tchain input {\n\t\ttype filter hook input priority -100; policy drop;\n\t}\n}\n";
    CHECK_FALSE(nft_listing_enforcing(parse_nft_list_table(missing)));
    CHECK_FALSE(nft_listing_enforcing(parse_nft_list_table("")));
    CHECK_FALSE(parse_nft_list_table("table inet filter {\n}\n").found);
    CHECK(nft_output_means_absent("Error: No such file or directory"));
    CHECK_FALSE(nft_output_means_absent("Error: Operation not permitted"));
}

// ── iptables ────────────────────────────────────────────────────────────────

TEST_CASE("iptables generation plan: chains, families, forward, no established",
          "[agent][firewall_quarantine]") {
    const auto set = make_set({"203.0.113.53", "2001:4860:4860::8888"},
                              {ex("10.0.0.5:22/tcp/in"), ex("[2001:db8::]/32:443/out")});
    const auto v4 = iptables_build_plan(set, kIptablesPath, 4, false);
    const auto v6 = iptables_build_plan(set, kIp6tablesPath, 4, true);
    std::vector<std::string> l4, l6;
    for (const auto& a : v4)
        l4.push_back(join(a));
    for (const auto& a : v6)
        l6.push_back(join(a));
    CHECK(l4.front() == "/usr/sbin/iptables -N yuzu-fwq-4");
    CHECK(contains(l4, "/usr/sbin/iptables -A yuzu-fwq-4 -i lo -j ACCEPT"));
    CHECK(contains(l4, "/usr/sbin/iptables -A yuzu-fwq-4 -j DROP"));
    CHECK(contains(l4, "/usr/sbin/iptables -N yuzu-fwq-4-f"));
    CHECK(contains(l4, "/usr/sbin/iptables -A yuzu-fwq-4-f -j DROP"));
    CHECK(contains(l4, "/usr/sbin/iptables -A yuzu-fwq-4 -p udp --sport 68 --dport 67 -j ACCEPT"));
    CHECK(contains(l4, "/usr/sbin/iptables -A yuzu-fwq-4 -d 203.0.113.53 -p udp --dport 53 -j ACCEPT"));
    // each family gets only its own addresses; ND is v6-only; DHCP is v4-only
    CHECK_FALSE(contains(l4, "/usr/sbin/iptables -A yuzu-fwq-4 -d 2001:db8::/32 -p tcp --dport 443 -j ACCEPT"));
    CHECK(contains(l6, "/usr/sbin/ip6tables -A yuzu-fwq-4 -d 2001:db8::/32 -p tcp --dport 443 -j ACCEPT"));
    CHECK(contains(l6, "/usr/sbin/ip6tables -A yuzu-fwq-4 -p icmpv6 --icmpv6-type 135 -j ACCEPT"));
    CHECK_FALSE(contains(l4, "/usr/sbin/iptables -A yuzu-fwq-4 -p icmpv6 --icmpv6-type 135 -j ACCEPT"));
    CHECK_FALSE(contains(l6, "/usr/sbin/ip6tables -A yuzu-fwq-4 -p udp --sport 68 --dport 67 -j ACCEPT"));
    for (const auto& l : l4)
        CHECK(l.find("ESTABLISHED") == l.npos);
    for (const auto& a : v4)
        CHECK(all_tokens_safe(a));
    for (const auto& a : v6)
        CHECK(all_tokens_safe(a));

    const auto act = iptables_activate_plan(kIptablesPath, 4);
    REQUIRE(act.size() == 3);
    CHECK(join(act[0]) == "/usr/sbin/iptables -I INPUT 1 -j yuzu-fwq-4");
    CHECK(join(act[1]) == "/usr/sbin/iptables -I OUTPUT 1 -j yuzu-fwq-4");
    CHECK(join(act[2]) == "/usr/sbin/iptables -I FORWARD 1 -j yuzu-fwq-4-f");
}

TEST_CASE("iptables listing and removal plan", "[agent][firewall_quarantine]") {
    const std::string listing =
        "-P INPUT ACCEPT\n-N yuzu-fwq-2\n-N yuzu-fwq-2-f\n-N yuzu-fwq-3\n-N yuzu-fwq-3-f\n-N DOCKER\n"
        "-A INPUT -j yuzu-fwq-3\n-A INPUT -j yuzu-fwq-2\n-A OUTPUT -j yuzu-fwq-3\n"
        "-A FORWARD -j yuzu-fwq-3-f\n-A FORWARD -j DOCKER\n-A yuzu-fwq-3 -j DROP\n";
    const auto l = parse_iptables_listing(listing);
    CHECK(l.chains.size() == 4);
    CHECK(l.jumps.size() == 4);
    CHECK(l.max_gen == 3);
    CHECK_FALSE(l.legacy_chain);
    CHECK(parse_iptables_listing("-N yuzu-quarantine\n").legacy_chain);

    // keep generation 3: only generation 2 goes, jumps before chains
    const auto plan = iptables_remove_plan(kIptablesPath, l, 3);
    std::vector<std::string> lines;
    for (const auto& a : plan)
        lines.push_back(join(a));
    REQUIRE(lines.size() == 5);
    CHECK(lines[0] == "/usr/sbin/iptables -D INPUT -j yuzu-fwq-2");
    CHECK(lines[1] == "/usr/sbin/iptables -F yuzu-fwq-2");
    CHECK(lines[2] == "/usr/sbin/iptables -X yuzu-fwq-2");
    CHECK(lines.back() == "/usr/sbin/iptables -X yuzu-fwq-2-f");
    // keep nothing: every jump, flush and delete
    CHECK(iptables_remove_plan(kIptablesPath, l, 0).size() == 4 + 8);
}

TEST_CASE("iptables worst case stays inside the operation budget as counted calls",
          "[agent][firewall_quarantine]") {
    std::vector<Endpoint> many;
    for (int i = 0; i < 64; ++i)
        many.push_back(ex(std::format("10.{}.{}.1:{}/in", i / 16, i % 16, 1000 + i)));
    const auto set = make_set({"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4",
                               "2001:4860:4860::1", "2001:4860:4860::2", "2001:4860:4860::3",
                               "2001:4860:4860::4"},
                              many);
    const auto v4 = iptables_build_plan(set, kIptablesPath, 9, false);
    const auto v6 = iptables_build_plan(set, kIp6tablesPath, 9, true);
    // 64 exceptions x 2 protocols x 2 paths, plus mandatory: bounded by construction
    const auto total = v4.size() + v6.size() + 2 * 3 /*activate*/ + 2 * 12 /*remove old*/ + 2 /*list*/;
    CHECK(total < 700);
    // even at 50 ms a call, the whole plan fits in the 60 s operation budget
    CHECK(std::chrono::milliseconds(50) * static_cast<long long>(total) < kOperationBudget);
}

// ── macOS pure pieces ───────────────────────────────────────────────────────

TEST_CASE("pf anchor ruleset: no nat/rdr, lo0, stateless control channel, block last",
          "[agent][firewall_quarantine]") {
    const auto set = make_set({"203.0.113.53"}, {ex("10.0.0.5:22/tcp/in")});
    const auto text = pf_anchor_ruleset(set);
    std::vector<std::string> lines;
    for (const auto l : detail::split(text, '\n'))
        if (!l.empty())
            lines.emplace_back(l);
    REQUIRE(lines.size() > 6);
    // translation rules come first (a pf file must order them before filter rules)
    CHECK(lines[0] == "no nat all");
    CHECK(lines[1] == "no rdr all");
    CHECK(lines[2] == "pass quick on lo0 all no state");
    CHECK(lines.back() == "block drop quick all");
    for (const auto& l : lines) {
        INFO(l);
        CHECK((l.find("quick") != l.npos || l.starts_with("no ")));
        CHECK(is_safe_ruleset_line(l));
    }
    CHECK(text.find("set skip") == text.npos);

    // the control channel is STATELESS in both directions: a state rebuilt from a
    // mid-stream packet loses the TCP window scale and would stall the live stream
    CHECK(text.find("pass out quick inet proto tcp from any to 198.51.100.7 port 50051 no state\n") !=
          text.npos);
    CHECK(text.find("pass in quick inet proto tcp from 198.51.100.7 port 50051 to any no state\n") !=
          text.npos);
    CHECK(text.find("flags") == text.npos); // no `flags any` anywhere
    for (const auto& l : lines)
        if (l.find("198.51.100.7") != l.npos) {
            INFO(l);
            CHECK(l.find("keep state") == l.npos);
        }

    // DHCP leaves only toward the broadcast address; the reply direction is inbound only
    CHECK(text.find("pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67 "
                    "keep state") != text.npos);
    CHECK(text.find("to any port 67") == text.npos);
    CHECK(text.find("pass in quick inet proto udp from any port 67 to any port 68 keep state") !=
          text.npos);
    // DNS and exceptions keep state; ports are service ports per direction
    CHECK(text.find("to 203.0.113.53 port 53 keep state") != text.npos);
    CHECK(text.find("pass in quick inet proto tcp from 10.0.0.5 to any port 22 keep state") != text.npos);
    // neighbour discovery 133-136; redirect (137) is not allowed
    CHECK(text.find("icmp6-type { 133, 134, 135, 136 } no state") != text.npos);
    CHECK(text.find("137") == text.npos);

    // an IPv6 control endpoint gets the same stateless pair
    auto v6 = build_allow_set("2001:db8::7", "[2001:db8::7]:50051", {}, {});
    REQUIRE(v6);
    const auto v6text = pf_anchor_ruleset(*v6);
    CHECK(v6text.find("pass out quick inet6 proto tcp from any to 2001:db8::7 port 50051 no state") !=
          v6text.npos);
    CHECK(v6text.find("pass in quick inet6 proto tcp from 2001:db8::7 port 50051 to any no state") !=
          v6text.npos);
}

TEST_CASE("pfctl argv: the anchor sorts first, flush is scoped to our anchor, nothing global",
          "[agent][firewall_quarantine]") {
    // pf evaluates com.apple/* sub-anchors in name order; 200.AirDrop and
    // 250.ApplicationFirewall ship with the OS, and `0` sorts before `2`
    CHECK(kPfAnchor == "com.apple/000.yuzu_quarantine");
    CHECK(kPfAnchorLeaf < std::string_view{"200.AirDrop"});
    CHECK(kPfAnchorLeaf < std::string_view{"250.ApplicationFirewall"});
    CHECK(is_safe_token(kPfAnchor));

    CHECK(join(pfctl_load_argv("/tmp/x.pf")) == "/sbin/pfctl -a com.apple/000.yuzu_quarantine -f /tmp/x.pf");
    CHECK(join(pfctl_flush_states_argv()) == "/sbin/pfctl -F states");
    CHECK(join(pfctl_references_argv()) == "/sbin/pfctl -s References");
    CHECK(join(pfctl_release_argv("123456")) == "/sbin/pfctl -X 123456");
    CHECK(join(pfctl_enable_argv()) == "/sbin/pfctl -E");
    // `-a X -F all` would also flush the GLOBAL state table and counters; rules + nat only
    CHECK(join(pfctl_flush_anchor_rules_argv()) == "/sbin/pfctl -a com.apple/000.yuzu_quarantine -F rules");
    CHECK(join(pfctl_flush_anchor_nat_argv()) == "/sbin/pfctl -a com.apple/000.yuzu_quarantine -F nat");
    CHECK(join(pfctl_info_argv()) == "/sbin/pfctl -s info");
    CHECK(join(pfctl_rules_argv()) == "/sbin/pfctl -s rules");
    CHECK(join(pfctl_anchor_rules_argv()) == "/sbin/pfctl -a com.apple/000.yuzu_quarantine -s rules");
    CHECK(join(pfctl_siblings_argv()) == "/sbin/pfctl -a com.apple -s Anchors");
    for (const auto& a : {pfctl_load_argv("/tmp/x.pf"), pfctl_flush_states_argv(), pfctl_references_argv(),
                          pfctl_release_argv("123456"), pfctl_enable_argv(),
                          pfctl_flush_anchor_rules_argv(), pfctl_flush_anchor_nat_argv(), pfctl_info_argv(),
                          pfctl_rules_argv(), pfctl_anchor_rules_argv(), pfctl_siblings_argv()})
        CHECK(all_tokens_safe(a));
}

TEST_CASE("pf parsers: token, references, anchor reference, siblings, enabled, enable plan",
          "[agent][firewall_quarantine]") {
    CHECK(parse_pfctl_token("pfctl: Use of -f option, could result in flushing of rules\nToken : 3665316113424588829\n")
              .value() == "3665316113424588829");
    CHECK(parse_pfctl_token("Token: 42").value() == "42");
    CHECK_FALSE(parse_pfctl_token("No ALTQ support in kernel\n"));
    CHECK_FALSE(parse_pfctl_token("Token : 12abc"));
    CHECK_FALSE(parse_pfctl_token("Token : "));

    // pfctl(8): "pid/name of enabler, token, timestamp" -- the column order is unverified,
    // so a line counts once when any field is a token-sized decimal
    const auto refs = parse_pf_references("PID NAME TOKEN TIMESTAMP\n"
                                          "321 com.apple.alf 3665316113424588829 1700000000\n"
                                          "  1122334455667788  yuzu\n"
                                          "noise 12345\n");
    REQUIRE(refs.size() == 2);
    CHECK(refs[0] == "3665316113424588829");
    CHECK(refs[1] == "1122334455667788");
    CHECK(parse_pf_references("").empty());

    // the reference must be the WHOLE unqualified line; a prefix match is not enough
    CHECK(pf_anchor_referenced("scrub-anchor \"com.apple/*\" all fragment\nanchor \"com.apple/*\" all\n"));
    CHECK(pf_anchor_referenced("  anchor \"com.apple/000.yuzu_quarantine\" all  \n"));
    CHECK_FALSE(pf_anchor_referenced("scrub-anchor \"com.apple/*\" all fragment\nblock all\n"));
    CHECK_FALSE(pf_anchor_referenced("anchor \"com.apple/*\" on en0 all\n")); // one interface only
    CHECK_FALSE(pf_anchor_referenced("anchor \"com.apple/*\" all label x\n"));
    CHECK_FALSE(pf_anchor_referenced("anchor \"com.apple/yuzu_quarantine\" all\n")); // the old name
    CHECK_FALSE(pf_anchor_referenced("nat-anchor \"com.apple/*\" all\n"));
    CHECK_FALSE(pf_anchor_referenced(""));

    CHECK(pf_anchor_enforcing("pass quick on lo0 all no state\nblock drop quick all\n"));
    CHECK_FALSE(pf_anchor_enforcing(""));
    CHECK_FALSE(pf_anchor_enforcing("pass quick on lo0 all no state\n"));

    // siblings that pf evaluates before ours: direct children sorting below 000.yuzu_quarantine
    CHECK(pf_siblings_before("   com.apple/200.AirDrop\n   com.apple/250.ApplicationFirewall\n"
                             "   com.apple/000.yuzu_quarantine\n")
              .empty());
    const auto early = pf_siblings_before("com.apple/000.aaa\n000.aab\ncom.apple/200.AirDrop\n"
                                          "com.apple/000.yuzu_quarantine\n");
    REQUIRE(early.size() == 2);
    CHECK(early[0] == "000.aaa");
    // a banner, a deeper path or an unsafe token never flags a healthy host
    CHECK(pf_siblings_before("No ALTQ support in kernel\ncom.apple/000.a/deeper\n  \n000.a;b\n").empty());
    CHECK(pf_siblings_before("").empty());

    CHECK(pf_enabled("Status: Enabled for 0 days 00:00:04           Debug: Urgent\n"));
    CHECK_FALSE(pf_enabled("Status: Disabled\n"));

    OsPayload os;
    constexpr auto boot = "1699999999.123456";
    CHECK(pf_enable_plan(os, boot, false) == PfEnablePlan::enable); // nothing stored: fresh -E
    CHECK(pf_enable_plan(os, boot, true) == PfEnablePlan::enable);  // pf on for someone else: still ours to take
    os.pf_token = "123456";
    os.boot_time = boot;
    CHECK(pf_enable_plan(os, boot, true) == PfEnablePlan::reuse);   // same boot, pf on: no second -E
    CHECK(pf_enable_plan(os, boot, false) == PfEnablePlan::repair); // pf -d behind our back: dead token
    CHECK(pf_enable_plan(os, "1700000500.000001", true) == PfEnablePlan::enable);  // new boot: refcount reset
    CHECK(pf_enable_plan(os, "1700000500.000001", false) == PfEnablePlan::enable); // and no -X of a stale token

    CHECK(detail::pf_error_line("pfctl: Use of -f option, could result in flushing of rules\n"
                                "present in the main ruleset added by the system at startup.\n"
                                "See /etc/pf.conf for further details.\n\n"
                                "/tmp/x.pf:3: syntax error\n") == "/tmp/x.pf:3: syntax error");
    CHECK(detail::pf_error_line("").empty());
}

// ── resolvers ───────────────────────────────────────────────────────────────

TEST_CASE("resolv.conf parser and the stub chain", "[agent][firewall_quarantine]") {
    const std::string conf =
        "# Generated\nsearch example.com\nnameserver 192.0.2.53\nnameserver   2001:db8::53   # v6\n"
        "; comment\nnameserver 192.0.2.53\nnameserverx 9.9.9.9\nnameserver\noptions edns0\n";
    const auto r = parse_resolv_conf(conf);
    REQUIRE(r.size() == 2);
    CHECK(r[0] == "192.0.2.53");
    CHECK(r[1] == "2001:db8::53");

    // a systemd-resolved stub forwards from the host: follow it to the upstream list
    const std::string stub = "nameserver 127.0.0.53\noptions edns0 trust-ad\n";
    const std::string upstream = "# upstream\nnameserver 10.1.1.1\nnameserver 10.1.1.2\nnameserver 127.0.0.1\n";
    const auto chain = resolver_chain(stub, upstream);
    REQUIRE(chain.size() == 3);
    CHECK(chain[0] == "127.0.0.53"); // the stub itself stays (loopback is allowed anyway)
    CHECK(chain[1] == "10.1.1.1");
    CHECK(chain[2] == "10.1.1.2");
    // no stub: the upstream file is not consulted
    CHECK(resolver_chain(conf, upstream).size() == 2);
    // capped at eight
    std::string many = "nameserver 127.0.0.53\n";
    std::string up;
    for (int i = 1; i <= 12; ++i)
        up += std::format("nameserver 10.1.1.{}\n", i);
    CHECK(resolver_chain(many, up).size() == 8);
}

// ── drivers over the nft leg ────────────────────────────────────────────────

namespace {

struct NftRig {
    FakeClock clock;
    NftWorld world;
    FakeStore store;
    Probe probe;
    NftLeg leg;
    std::int64_t now = 1'700'000'000;
    Env env;

    NftRig()
        : leg(world.runner(), world.stage()),
          env{leg, store, probe.fn(), [this] { return now; }} {
        world.clock = &clock;
        probe.blocked = [this] { return world.table; };
    }
    Deadline dl() { return Deadline(kOperationBudget, clock.fn()); }
    ApplyRequest request(std::string target = kProbeTarget, std::int64_t ttl = 0) {
        ApplyRequest r;
        r.allow = make_set();
        r.probe_target = std::move(target);
        r.ttl_seconds = ttl;
        return r;
    }
};

} // namespace

TEST_CASE("quarantine: apply, verify, record -- and release restores the host",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl);
    CHECK(o.status == "active");
    REQUIRE(o.verify);
    CHECK(*o.verify == "verify|control=ok|probe=blocked");
    CHECK(rig.world.table);
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->generation == 1);
    CHECK(rig.store.state()->ttl_expires == rig.now + 120);
    CHECK(rig.store.state()->backend == BackendKind::nft);
    // the record was written (applying) BEFORE the ruleset was loaded
    CHECK(rig.store.saves >= 2);

    const auto rows = render_rows(o);
    CHECK(rows.front() == "status|active");
    CHECK(contains(rows, "verify|control=ok|probe=blocked"));
    CHECK(contains(rows, "allow|control|198.51.100.7:50051/tcp/out"));
    CHECK(contains(rows, "allow|resolver|203.0.113.53"));
    CHECK(contains(rows, "note|backend=nft"));
    CHECK(result_kind(o).provenance == "firewall:active");

    // already active: the live table is read, but nothing is mutated
    const auto calls = rig.world.crash.calls;
    const auto again = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(again.status == "active");
    CHECK(contains(again.notes, "already_active=1"));
    CHECK(std::none_of(rig.world.log.begin() + calls, rig.world.log.end(), [](const Argv& a) {
        return a.size() > 1 && (a[1] == "-f" || a[1] == "delete");
    }));

    const auto rel = release(rig.env, ReleaseRequest{}, dl);
    CHECK(rel.status == "inactive");
    CHECK_FALSE(rig.world.table);
    CHECK(rig.store.raw.empty());
    // release is idempotent
    const auto rel2 = release(rig.env, ReleaseRequest{}, dl);
    CHECK(rel2.status == "inactive");
}

TEST_CASE("quarantine: no probe target means the block is reported unproven",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(""), dl);
    CHECK(o.status == "active_unproven");
    CHECK(*o.verify == "verify|control=ok|probe=unproven");
    CHECK(rig.world.table);
    CHECK(result_kind(o).partial);
}

TEST_CASE("quarantine: refusals happen before any mutation", "[agent][firewall_quarantine]") {
    {
        NftRig rig;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request("example.com:443"), dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "probe_target_not_literal");
        CHECK(rig.world.crash.calls == 0);
        CHECK(rig.store.raw.empty());
        CHECK(render_rows(o)[1] == "refused|probe_target_not_literal");
    }
    {
        NftRig rig;
        auto dl = rig.dl();
        auto req = rig.request();
        req.allow.control.clear();
        CHECK(apply_and_verify(rig.env, req, dl).reason == "control_set_empty");
        CHECK(rig.world.crash.calls == 0);
    }
    {
        NftRig rig;
        auto dl = rig.dl();
        CHECK(apply_and_verify(rig.env, rig.request(kProbeTarget, 30), dl).reason ==
              "ttl_out_of_bounds");
        CHECK(rig.world.crash.calls == 0);
    }
    {
        // a legacy quarantine is in force: refuse, touch nothing
        NftRig rig;
        rig.world.legacy = true;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "legacy_quarantine_active");
        CHECK_FALSE(rig.world.table);
        CHECK(rig.store.raw.empty());
    }
    {
        // the probe target does not answer BEFORE the mutation: nothing to prove against
        NftRig rig;
        rig.probe.blocked = [] { return true; };
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "probe_unreachable_before_apply");
        CHECK(rig.world.crash.calls == 1); // only the legacy preflight read
        CHECK(rig.store.raw.empty());
    }
    {
        // no recovery record, no mutation (the opposite posture to the legacy plugin)
        NftRig rig;
        rig.store.fail_save = true;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "state_not_persisted");
        CHECK_FALSE(rig.world.table);
        CHECK(rig.world.crash.calls == 1); // the preflight read, never the nft load
    }
}

TEST_CASE("quarantine: an initial apply rolls back to absence", "[agent][firewall_quarantine]") {
    SECTION("control channel unreachable after the apply") {
        NftRig rig;
        rig.probe.control_up = false;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(o.reason == "control_unreachable");
        CHECK_FALSE(rig.world.table);
        CHECK(rig.store.raw.empty());
        CHECK(*o.verify == "verify|control=fail|probe=blocked");
        const auto rows = render_rows(o);
        CHECK(rows[0] == "status|rolled_back|control_unreachable");
        CHECK(rows[1] == "rolled_back|control_unreachable");
        CHECK(o.rc() == 1);
    }
    SECTION("the probe target is still reachable (connected)") {
        NftRig rig;
        rig.probe.blocked = [] { return false; };
        auto dl = rig.dl();
        // before: connected, after: connected
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(o.reason == "probe_still_reachable");
        CHECK_FALSE(rig.world.table);
        CHECK(rig.store.raw.empty());
    }
    SECTION("an RST after the apply means the packet got through") {
        NftRig rig;
        rig.probe.blocked = [&] { return rig.world.table; };
        rig.probe.blocked_result = ProbeOutcome::refused;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(o.reason == "probe_still_reachable");
        CHECK(*o.verify == "verify|control=ok|probe=refused");
    }
    SECTION("the ruleset fails to load") {
        NftRig rig;
        rig.world.fail_load = true;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(o.reason == "apply_failed:nft_load_failed");
        CHECK_FALSE(rig.world.table);
        CHECK(rig.store.raw.empty());
        CHECK(contains(o.notes, "detail=Error: syntax error, unexpected word"));
    }
}

TEST_CASE("rollback: the release intent is saved before the rules come out",
          "[agent][firewall_quarantine]") {
    SECTION("`releasing` is on the record by the time the removal runs") {
        NftRig rig;
        rig.probe.control_up = false;
        std::optional<Phase> at_delete;
        rig.world.on_call = [&](const Argv& a) {
            if (a.size() > 1 && a[1] == "delete" && rig.store.state())
                at_delete = rig.store.state()->phase;
        };
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        REQUIRE(at_delete);
        CHECK(*at_delete == Phase::releasing);
        CHECK_FALSE(o.state);
        CHECK(rig.store.raw.empty());
        CHECK_FALSE(rig.world.table);
    }
    SECTION("an intent write that fails does not stop the removal") {
        NftRig rig;
        rig.probe.control_up = false;
        rig.store.fail_save_after = 1; // the `applying` record landed; nothing after it does
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK_FALSE(rig.world.table); // undoing the failed containment is never skipped
        CHECK(rig.store.raw.empty());
        CHECK_FALSE(contains(o.notes, "state_not_persisted=1")); // no record left to be stale
    }
    SECTION("both writes failing leaves the stale record and says so") {
        NftRig rig;
        rig.probe.control_up = false;
        rig.store.fail_save_after = 1;
        rig.store.fail_erase = true;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK_FALSE(rig.world.table);
        CHECK(contains(o.notes, "state_not_persisted=1"));
        CHECK(contains(o.notes, "state_not_erased=1"));
    }
    SECTION("a failed erase keeps `releasing`; the next start finishes the release and never re-applies") {
        NftRig rig;
        rig.probe.control_up = false;
        rig.store.fail_erase = true;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(contains(o.notes, "state_not_erased=1"));
        CHECK_FALSE(rig.world.table);
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::releasing);
        REQUIRE(o.state);
        CHECK(o.state->phase == Phase::releasing);
        CHECK(report_status(rig.env, dl).reason == "release_incomplete");

        rig.store.fail_erase = false;
        const auto mark = rig.world.log.size();
        const auto r = recover_at_init(rig.env, dl);
        CHECK(r.status == "inactive");
        CHECK(rig.store.raw.empty());
        CHECK_FALSE(rig.world.table);
        CHECK(std::none_of(rig.world.log.begin() + mark, rig.world.log.end(),
                           [](const Argv& a) { return a.size() > 1 && a[1] == "-f"; }));
    }
    SECTION("a removal that fails keeps `releasing` too") {
        NftRig rig;
        rig.probe.control_up = false;
        rig.world.fail_delete = true;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(contains(o.notes, "rollback_incomplete=1"));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::releasing);

        rig.world.fail_delete = false;
        CHECK(recover_at_init(rig.env, dl).status == "inactive");
        CHECK_FALSE(rig.world.table);
        CHECK(rig.store.raw.empty());
    }
}

TEST_CASE("quarantine_allow: update keeps the previous generation on failure",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto before_text = rig.world.text;
    const auto before_state = *rig.store.state();

    SECTION("a successful add is a new generation") {
        const auto o = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(o.status == "active");
        CHECK(rig.world.text.find("ip saddr 10.0.0.5 tcp dport 22 accept") != std::string::npos);
        CHECK(rig.store.state()->generation == 2);
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->allow.exceptions.size() == 1);
        // and removing it again
        const auto r = update(rig.env, false, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(r.status == "active");
        CHECK(rig.store.state()->generation == 3);
        CHECK(rig.store.state()->allow.exceptions.empty());
    }
    SECTION("an unchanged set is a no-op") {
        const auto calls = rig.world.crash.calls;
        const auto o = update(rig.env, false, {ex("10.9.9.9")}, dl);
        CHECK(o.status == "active");
        CHECK(contains(o.notes, "exceptions_unchanged=1"));
        CHECK(rig.world.crash.calls == calls);
        CHECK(rig.store.state()->generation == 1);
    }
    SECTION("a ruleset that will not load leaves the previous generation in force") {
        rig.world.fail_load = true;
        const auto o = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(o.status == "update_failed");
        CHECK(o.reason == "nft_load_failed");
        CHECK(o.rc() == 1);
        CHECK(rig.world.table);
        CHECK(rig.world.text == before_text);
        CHECK(rig.store.state()->generation == before_state.generation);
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->allow == before_state.allow);
        REQUIRE(o.state);
        CHECK(o.state->allow == before_state.allow); // the previous allow set is what is reported
    }
    SECTION("a verify failure reverts to the previous generation, never to absence") {
        rig.probe.control_up = false;
        const auto o = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(o.status == "update_failed");
        CHECK(o.reason == "control_unreachable");
        CHECK(rig.world.table); // still contained
        CHECK(rig.world.text.find("10.0.0.5") == std::string::npos);
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->allow.exceptions.empty());
    }
    SECTION("refusals") {
        CHECK(update(rig.env, true, {}, dl).status == "active"); // nothing to add: no-op
        CHECK(update(rig.env, false, {ex("198.51.100.7:50051/tcp")}, dl).reason ==
              "mandatory_allowance");
        rig.store.fail_save = true;
        const auto o = update(rig.env, true, {ex("10.0.0.5")}, dl);
        CHECK(o.reason == "state_not_persisted");
        CHECK(rig.world.text == before_text);
    }
}

TEST_CASE("quarantine_allow requires an active quarantine", "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    const auto o = update(rig.env, true, {ex("10.0.0.5")}, dl);
    CHECK(o.status == "refused");
    CHECK(o.reason == "not_active");
}

TEST_CASE("release: ttl-driven release is a no-op before expiry", "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl).status == "active");
    ReleaseRequest due;
    due.if_ttl_expired = true;

    rig.now += 119;
    auto early = release(rig.env, due, dl);
    CHECK(early.status == "active");
    CHECK(contains(early.notes, "ttl_not_expired=1"));
    CHECK(rig.world.table);

    rig.now += 1; // exactly at the boundary
    auto late = release(rig.env, due, dl);
    CHECK(late.status == "inactive");
    CHECK_FALSE(rig.world.table);
    CHECK(rig.store.raw.empty());

    // a trigger-driven call with nothing recorded touches nothing
    const auto calls = rig.world.crash.calls;
    CHECK(release(rig.env, due, dl).status == "inactive");
    CHECK(rig.world.crash.calls == calls);
}

TEST_CASE("release is never blocked by the record", "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.store.fail_save = true;
    auto o = release(rig.env, ReleaseRequest{}, dl);
    CHECK(o.status == "inactive");
    CHECK(contains(o.notes, "state_not_persisted=1"));
    CHECK_FALSE(rig.world.table);

    // a damaged record does not stop the OS being cleaned
    NftRig bad;
    bad.world.table = true;
    bad.store.raw = "corrupt";
    auto dl2 = bad.dl();
    o = release(bad.env, ReleaseRequest{}, dl2);
    CHECK(o.status == "inactive");
    CHECK_FALSE(bad.world.table);
    CHECK(bad.store.raw.empty());
}

TEST_CASE("status shapes: inactive, active, active_unproven, partial, degraded",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    CHECK(report_status(rig.env, dl).status == "inactive");

    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    CHECK(report_status(rig.env, dl).status == "active");

    // the table vanished under us (a reboot, a flush): the record says active, the OS disagrees
    rig.world.table = false;
    auto o = report_status(rig.env, dl);
    CHECK(o.status == "degraded");
    CHECK(o.reason == "policy_not_blocking");
    rig.world.table = true;

    // rules present but no record
    rig.store.raw.clear();
    o = report_status(rig.env, dl);
    CHECK(o.status == "degraded");
    CHECK(o.reason == "state_missing_rules_present");

    // unproven (no probe target)
    NftRig bare;
    auto dl2 = bare.dl();
    REQUIRE(apply_and_verify(bare.env, bare.request(""), dl2).status == "active_unproven");
    CHECK(report_status(bare.env, dl2).status == "active_unproven");

    // an interrupted operation
    auto st = *bare.store.state();
    st.phase = Phase::applying;
    bare.store.save(st);
    o = report_status(bare.env, dl2);
    CHECK(o.status == "partial");
    CHECK(o.reason == "operation_in_progress");
    st.phase = Phase::releasing;
    bare.store.save(st);
    CHECK(report_status(bare.env, dl2).reason == "release_incomplete");

    // rules the policy store refused to disable keep the quarantine "partial", never "active"
    st.phase = Phase::active;
    st.os.rules_not_disabled = 4;
    bare.store.save(st);
    o = report_status(bare.env, dl2);
    CHECK(o.status == "partial");
    CHECK(o.reason == "rules_not_disabled");
    CHECK(contains(o.notes, "rules_not_disabled=4"));
}

TEST_CASE("status reads our table over netlink first, then falls back to nft list",
          "[agent][firewall_quarantine]") {
    NftWorld w;
    FakeStore store;
    Probe probe;
    NftTableListing good;
    good.found = true;
    good.chains = {{"input", "input", "drop"}, {"output", "output", "drop"}, {"forward", "forward", "drop"}};
    int netlink_reads = 0;
    std::optional<NftTableListing> answer = good;
    NftLeg leg(w.runner(), w.stage(), [&]() -> std::optional<NftTableListing> {
        ++netlink_reads;
        return answer;
    });
    Deadline dl;
    CHECK(leg.read_status({}, dl).state == OsState::enforcing);
    CHECK(netlink_reads == 1);
    CHECK(w.crash.calls == 0); // no subprocess when netlink answered

    // netlink refused (no CAP_NET_ADMIN): sudo nft list table
    answer.reset();
    w.table = true;
    CHECK(leg.read_status({}, dl).state == OsState::enforcing);
    CHECK(w.crash.calls == 1);
    w.table = false;
    CHECK(leg.read_status({}, dl).state == OsState::not_enforcing);
}

// ── recovery at init ────────────────────────────────────────────────────────

TEST_CASE("recover_at_init completes an interrupted release", "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    auto st = *rig.store.state();
    st.phase = Phase::releasing;
    rig.store.save(st);
    const auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "inactive");
    CHECK_FALSE(rig.world.table);
    CHECK(rig.store.raw.empty());
}

TEST_CASE("recover_at_init re-applies an applying record as a generation update",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    auto st = *rig.store.state();
    st.phase = Phase::applying;
    rig.store.save(st);
    rig.world.table = false; // the apply never happened
    rig.world.text.clear();
    const auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "active");
    CHECK(rig.world.table);
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->generation == st.generation + 1);
    CHECK(contains(o.notes, "reapplied=1"));
}

TEST_CASE("recover_at_init: a reboot re-applies; an enforcing OS is only verified",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");

    // still enforcing: no mutation, last_verify refreshed
    auto calls = rig.world.crash.calls;
    auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "active");
    CHECK_FALSE(contains(o.notes, "reapplied=1"));
    CHECK(std::none_of(rig.world.log.begin() + calls, rig.world.log.end(),
                       [](const Argv& a) { return a.size() > 1 && a[1] == "-f"; }));

    // reboot: the nft table is gone, the record remains
    rig.world.table = false;
    rig.world.text.clear();
    o = recover_at_init(rig.env, dl);
    CHECK(o.status == "active");
    CHECK(rig.world.table);
    CHECK(contains(o.notes, "reapplied=1"));
}

TEST_CASE("recover_at_init never rolls back or releases on an unreachable server",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.world.table = false;
    rig.probe.control_up = false; // the server is unreachable at boot
    const auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "active_unproven");
    CHECK(*o.verify == "verify|control=fail|probe=blocked");
    CHECK(rig.world.table);  // still contained
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->last_verify.find("control_unreachable") != std::string::npos);
    // and a probe that is still reachable changes nothing either
    rig.probe.control_up = true;
    rig.probe.blocked = [] { return false; };
    CHECK(recover_at_init(rig.env, dl).status != "rolled_back");
    CHECK(rig.world.table);
}

TEST_CASE("recover_at_init: a failed re-apply puts an active record back and status reads the host",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto generation = rig.store.state()->generation;
    rig.world.table = false;
    rig.world.fail_load = true;
    const auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "degraded");
    CHECK(o.reason == "reapply_failed:nft_load_failed");
    // The attempt finished and nothing of its generation is in force: the record is
    // what it was, not an operation in progress.
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->generation == generation);
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "degraded");
    CHECK(st.reason == "policy_not_blocking");
    // the next start still re-applies
    rig.world.fail_load = false;
    CHECK(recover_at_init(rig.env, dl).status == "active");
    CHECK(report_status(rig.env, dl).status == "active");
}

TEST_CASE("recover_at_init with no record does nothing", "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    const auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "inactive");
    CHECK(rig.world.crash.calls == 0);
}

// ── what the driver does with a leg's Windows-shaped answers ────────────────

namespace {

/// A scripted leg, the store and a probe that is blocked once the leg applied.
struct ScriptRig {
    ScriptedLeg leg;
    FakeStore store;
    Probe probe;
    std::int64_t now = 1'700'000'000;
    Env env;
    ScriptRig() : env{leg, store, probe.fn(), [this] { return now; }} {
        probe.blocked = [this] { return leg.applies > 0; };
    }
    ApplyRequest request(std::string target = kProbeTarget) {
        ApplyRequest r;
        r.allow = make_set();
        r.probe_target = std::move(target);
        return r;
    }
};

} // namespace

TEST_CASE("a switched-off Windows profile refuses before anything is touched, and is never re-applied over",
          "[agent][firewall_quarantine]") {
    SECTION("preflight refusal") {
        ScriptRig rig;
        rig.leg.refuse = "firewall_disabled:Public";
        Deadline dl;
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "firewall_disabled:Public");
        CHECK(rig.leg.applies == 0);
        CHECK(rig.store.raw.empty());
        CHECK(render_rows(o)[1] == "refused|firewall_disabled:Public");
    }
    SECTION("an apply that finds the switch off (init re-apply, update) fails with the same token") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto before = rig.store.state();
        rig.leg.on_apply = [](OsPayload&) { return StepResult::fail("firewall_disabled:Domain"); };
        const auto u = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(u.status == "update_failed");
        CHECK(u.reason == "firewall_disabled:Domain");
        CHECK(rig.store.state()->allow == before->allow); // the previous generation stays
        // and an init re-apply reports it instead of claiming containment
        rig.leg.status.state = OsState::not_enforcing;
        const auto r = recover_at_init(rig.env, dl);
        CHECK(r.status == "degraded");
        CHECK(r.reason == "reapply_failed:firewall_disabled:Domain");
    }
    SECTION("a failed boot re-apply leaves the record active: status reads the switch") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.leg.on_apply = [](OsPayload&) { return StepResult::fail("firewall_disabled:Domain"); };
        rig.leg.status.state = OsState::not_enforcing;
        rig.leg.status.reason = "firewall_disabled";
        rig.leg.status.reapply_helps = false;
        rig.leg.status.notes.emplace_back("firewall_profile=Domain");

        const auto r = recover_at_init(rig.env, dl);
        CHECK(r.status == "degraded");
        CHECK(r.reason == "reapply_failed:firewall_disabled:Domain");
        CHECK(rig.store.state()->phase == Phase::active);

        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "degraded");
        CHECK(st.reason == "firewall_disabled"); // never operation_in_progress
        CHECK(contains(st.notes, "firewall_profile=Domain"));
    }
    SECTION("a crashed applying record whose boot re-apply fails stays in progress") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        auto crashed = *rig.store.state();
        crashed.phase = Phase::applying;
        rig.store.save(crashed);
        rig.leg.on_apply = [](OsPayload&) { return StepResult::fail("firewall_disabled:Domain"); };
        rig.leg.status.state = OsState::not_enforcing;
        rig.leg.status.reason = "firewall_disabled";
        rig.leg.status.reapply_helps = false;

        const auto r = recover_at_init(rig.env, dl);
        CHECK(r.status == "degraded");
        CHECK(rig.store.state()->phase == Phase::applying);
        CHECK(rig.store.state()->generation == crashed.generation);
        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "partial");
        CHECK(st.reason == "operation_in_progress");
    }
    SECTION("status reads degraded|firewall_disabled; a retried quarantine reports it and does not re-apply") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.leg.status.state = OsState::not_enforcing;
        rig.leg.status.reason = "firewall_disabled";
        rig.leg.status.reapply_helps = false;
        rig.leg.status.notes.emplace_back("firewall_profile=Private");

        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "degraded");
        CHECK(st.reason == "firewall_disabled");
        CHECK(contains(st.notes, "firewall_profile=Private"));

        const auto applies = rig.leg.applies;
        const auto again = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(again.status == "degraded");
        CHECK(again.reason == "firewall_disabled");
        CHECK(rig.leg.applies == applies);
    }
    SECTION("a profile that cannot be read is os_unreadable, never a guess") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.leg.status.state = OsState::unreadable;
        rig.leg.status.notes.emplace_back("firewall_profile=Domain");
        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "degraded");
        CHECK(st.reason == "os_unreadable");
    }
}

TEST_CASE("a retried quarantine answers what quarantine_status would, never active over a gap",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    Deadline dl;
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto applies = rig.leg.applies;
    // one ladder: whatever the retry answers, quarantine_status answers the same
    const auto agrees = [&](const Outcome& retry) {
        const auto st = report_status(rig.env, dl);
        return retry.status == st.status && retry.reason == st.reason;
    };

    SECTION("recorded residue") {
        auto st = *rig.store.state();
        st.os.rules_not_disabled = 4;
        rig.store.save(st);
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "partial");
        CHECK(o.reason == "rules_not_disabled");
        CHECK(contains(o.notes, "rules_not_disabled=4"));
        CHECK(contains(o.notes, "already_active=1"));
        CHECK(agrees(o));
        CHECK(rig.leg.applies == applies); // nothing a re-apply would repair
    }
    SECTION("a gap the leg itself reports") {
        rig.leg.status.partial = true;
        rig.leg.status.reason = "stale_state_entries";
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "partial");
        CHECK(o.reason == "stale_state_entries");
        CHECK(agrees(o));
        CHECK(rig.leg.applies == applies);
    }
    SECTION("an unreadable host is degraded, and nothing is applied over it") {
        rig.leg.status.state = OsState::unreadable;
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "degraded");
        CHECK(o.reason == "os_unreadable");
        CHECK_FALSE(contains(o.notes, "already_active=1"));
        CHECK(agrees(o));
        CHECK(rig.leg.applies == applies);
    }
    SECTION("an apply that could not prove the block stays active_unproven") {
        auto st = *rig.store.state();
        st.last_verify = "unproven control_ok probe_none";
        rig.store.save(st);
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "active_unproven");
        CHECK(contains(o.notes, "already_active=1"));
        CHECK(agrees(o));
        CHECK(rig.leg.applies == applies);
    }
    SECTION("a clean record is still already_active") {
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "active");
        CHECK(contains(o.notes, "already_active=1"));
        CHECK(agrees(o));
        CHECK(rig.leg.applies == applies);
    }
}

TEST_CASE("windows stale-generation residue is partial, persisted, and recomputed by every generation",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    Deadline dl;
    // the first generation: the removal pass left two of a previous generation's rules
    rig.leg.on_apply = [](OsPayload& os) {
        os.stale_rules_left = 2;
        auto r = StepResult::success();
        r.partial = true;
        r.notes.emplace_back("stale_rules_left=2");
        return r;
    };
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "partial");
    CHECK(contains(o.notes, "stale_rules_left=2"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->os.stale_rules_left == 2);

    // later statuses read it from the record, not from the apply that saw it
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "stale_rules_left");
    CHECK(contains(st.notes, "stale_rules_left=2"));
    CHECK(result_kind(st).partial);

    // an update that removes them clears it
    rig.leg.on_apply = [](OsPayload& os) {
        os.stale_rules_left = 0;
        return StepResult::success();
    };
    const auto u = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
    CHECK(u.status == "active");
    CHECK(rig.store.state()->os.stale_rules_left == 0);
    CHECK(report_status(rig.env, dl).status == "active");

    // and a boot-time re-apply that leaves some behind says so too
    rig.leg.status.state = OsState::not_enforcing;
    rig.leg.on_apply = [](OsPayload& os) {
        os.stale_rules_left = 1;
        return StepResult::success();
    };
    const auto r = recover_at_init(rig.env, dl);
    CHECK(r.status == "partial");
    CHECK(rig.store.state()->os.stale_rules_left == 1);
}

// ── TTL enforcement through the trigger registry ───────────────────────────

namespace {

/// The agent's trigger engine as a fake: records what the core registers and can
/// refuse (the standalone harness has none, so registration there always fails).
struct FakeTriggers final : TriggerRegistry {
    struct Reg {
        std::string id, type, json;
    };
    bool accept = true;
    std::vector<Reg> registered;
    std::vector<std::string> unregistered;
    bool register_trigger(std::string_view id, std::string_view type,
                          std::string_view config_json) override {
        if (!accept)
            return false;
        registered.push_back({std::string{id}, std::string{type}, std::string{config_json}});
        return true;
    }
    bool unregister_trigger(std::string_view id) override {
        unregistered.emplace_back(id);
        return true;
    }
};

} // namespace

TEST_CASE("ttl trigger: the registration the core emits is what the engine's own parser accepts",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl);
    REQUIRE(o.status == "active");
    FakeTriggers trig;
    settle_ttl(o, trig);

    REQUIRE(trig.registered.size() == 1);
    CHECK(trig.unregistered.empty());
    const auto& reg = trig.registered[0];
    CHECK(reg.id == kTtlTriggerId);
    CHECK(reg.id == "firewall.quarantine.ttl");
    CHECK(reg.type == "interval");
    // a successful registration changes nothing about the result
    CHECK(o.status == "active");
    CHECK_FALSE(contains(o.notes, "ttl_trigger_unregistered=1"));

    // the contract with the trigger engine, proven against the engine's own parser
    const auto cfg = yuzu::agent::parse_trigger_config(reg.id, reg.type, reg.json);
    REQUIRE(cfg.has_value());
    CHECK(cfg->id == "firewall.quarantine.ttl");
    CHECK(cfg->type == yuzu::agent::TriggerType::Interval);
    CHECK(cfg->plugin == "firewall");
    CHECK(cfg->action == "release");
    CHECK(cfg->interval_seconds == kTtlPollSeconds);
    CHECK(cfg->interval_seconds >= 30); // the engine's floor
    REQUIRE(cfg->parameters.size() == 1);
    CHECK(cfg->parameters.at("if_ttl_expired") == "1");
    // and the action it fires is the no-op-until-expiry release
    CHECK(reg.json == ttl_trigger_config());
}

TEST_CASE("ttl trigger: a failed registration keeps the quarantine and says PARTIAL",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    FakeTriggers trig;
    trig.accept = false; // what the standalone harness (no trigger engine) answers

    auto verified = apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl);
    REQUIRE(verified.status == "active");
    settle_ttl(verified, trig);
    CHECK(verified.status == "partial");
    CHECK(contains(verified.notes, "ttl_trigger_unregistered=1"));
    CHECK(contains(render_rows(verified), "status|partial"));
    CHECK(contains(render_rows(verified), "note|ttl_trigger_unregistered=1"));
    CHECK(result_kind(verified).partial);
    // the containment itself is untouched: still applied, record still active
    CHECK(rig.world.table);
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::active);

    // unproven contained stays contained too, and is partial
    Outcome unproven;
    unproven.status = "active_unproven";
    unproven.state = rig.store.state();
    settle_ttl(unproven, trig);
    CHECK(unproven.status == "partial");
    CHECK(contains(unproven.notes, "ttl_trigger_unregistered=1"));

    // a status that is already worse than active is not improved, only annotated
    Outcome degraded;
    degraded.status = "degraded";
    degraded.reason = "reapply_failed:nft_load_failed";
    degraded.state = rig.store.state();
    settle_ttl(degraded, trig);
    CHECK(degraded.status == "degraded");
    CHECK(contains(degraded.notes, "ttl_trigger_unregistered=1"));
}

TEST_CASE("ttl trigger: no ttl registers nothing; a completed release unregisters",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    FakeTriggers trig;

    auto no_ttl = apply_and_verify(rig.env, rig.request(), dl);
    REQUIRE(no_ttl.status == "active");
    settle_ttl(no_ttl, trig);
    CHECK(trig.registered.empty());
    CHECK(trig.unregistered.empty());
    CHECK(no_ttl.status == "active");

    // a ttl'd quarantine, then released: the trigger goes with it
    REQUIRE(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
    auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 90), dl);
    REQUIRE(o.status == "active");
    settle_ttl(o, trig);
    CHECK(trig.registered.size() == 1);
    auto rel = release(rig.env, ReleaseRequest{}, dl);
    REQUIRE(rel.status == "inactive");
    settle_ttl(rel, trig);
    REQUIRE(trig.unregistered.size() == 1);
    CHECK(trig.unregistered[0] == kTtlTriggerId);
    CHECK(trig.registered.size() == 1); // not re-registered

    // a refused action leaves the trigger alone
    auto refused_o = refused("op_invalid");
    settle_ttl(refused_o, trig);
    CHECK(trig.registered.size() == 1);
    CHECK(trig.unregistered.size() == 1);
}

TEST_CASE("ttl trigger: a release that did not complete keeps the trigger; the expiry path releases",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl).status == "active");
    FakeTriggers trig;

    // a release the OS refuses is partial and the record (with its ttl) stays: keep firing
    rig.world.fail_delete = true;
    auto failed = release(rig.env, ReleaseRequest{}, dl);
    REQUIRE(failed.status == "partial");
    settle_ttl(failed, trig);
    CHECK(trig.registered.size() == 1);
    CHECK(trig.unregistered.empty());
    rig.world.fail_delete = false;

    // the trigger's own firing: release if_ttl_expired=1, a no-op before the deadline
    // and the real release after it, which then takes the trigger away
    ReleaseRequest due;
    due.if_ttl_expired = true;
    rig.now += 119;
    auto early = release(rig.env, due, dl);
    CHECK(contains(early.notes, "ttl_not_expired=1"));
    CHECK(rig.world.table);
    rig.now += 2;
    auto late = release(rig.env, due, dl);
    REQUIRE(late.status == "inactive");
    CHECK_FALSE(rig.world.table);
    settle_ttl(late, trig);
    CHECK(trig.unregistered.size() == 1);
}

TEST_CASE("ttl trigger: a boot-time recovery re-registers it, and retries a failed registration",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    FakeTriggers trig;
    trig.accept = false;
    auto first = apply_and_verify(rig.env, rig.request(kProbeTarget, 600), dl);
    settle_ttl(first, trig);
    REQUIRE(first.status == "partial"); // registration failed at quarantine time

    // agent restart: the OS still enforces, the record says active with a ttl
    trig.accept = true;
    auto boot = recover_at_init(rig.env, dl);
    REQUIRE(boot.state);
    CHECK(boot.state->ttl_expires > 0);
    settle_ttl(boot, trig);
    REQUIRE(trig.registered.size() == 1);
    CHECK(trig.registered[0].id == kTtlTriggerId);
    CHECK(boot.status == "active"); // registered this time: nothing partial left to say

    // a reboot with a failed re-apply (degraded) still keeps the ttl bounded
    FakeTriggers again;
    rig.world.table = false;
    rig.world.fail_load = true;
    auto failed = recover_at_init(rig.env, dl);
    REQUIRE(failed.status == "degraded");
    settle_ttl(failed, again);
    CHECK(again.registered.size() == 1);
    CHECK(failed.status == "degraded");
}

// ── crash safety ────────────────────────────────────────────────────────────

TEST_CASE("crash at every runner call during apply: never unrestricted with an active record",
          "[agent][firewall_quarantine]") {
    // number of runner calls in a clean run
    int clean_calls = 0;
    {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        clean_calls = rig.world.crash.calls;
    }
    REQUIRE(clean_calls >= 2);

    for (int n = 1; n <= clean_calls; ++n) {
        for (const bool after : {false, true}) {
            INFO("crash at call " << n << (after ? " (after its effect)" : " (before its effect)"));
            NftRig rig;
            rig.world.crash.crash_at = n;
            rig.world.crash.after_effect = after;
            auto dl = rig.dl();
            bool crashed = false;
            try {
                (void)apply_and_verify(rig.env, rig.request(), dl);
            } catch (const CrashSim&) {
                crashed = true;
            }
            CHECK(crashed);

            // never unrestricted-with-a-record, never unrecorded rules, at the crash point
            const auto rec = rig.store.state();
            if (rig.world.table)
                CHECK(rec.has_value());
            if (rec && rec->phase == Phase::active)
                CHECK(rig.world.table);

            // restart: the boot-time recovery converges
            rig.world.crash.crash_at = -1;
            (void)recover_at_init(rig.env, dl);
            const auto after_rec = rig.store.state();
            if (after_rec) {
                CHECK(after_rec->phase == Phase::active);
                CHECK(rig.world.table);
            } else {
                CHECK_FALSE(rig.world.table);
            }
        }
    }
}

TEST_CASE("crash at every runner call during release", "[agent][firewall_quarantine]") {
    int clean_calls = 0;
    {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto base = rig.world.crash.calls;
        REQUIRE(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
        clean_calls = rig.world.crash.calls - base;
    }
    for (int n = 1; n <= clean_calls; ++n) {
        for (const bool after : {false, true}) {
            INFO("crash at release call " << n << (after ? " after" : " before"));
            NftRig rig;
            auto dl = rig.dl();
            REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
            rig.world.crash.crash_at = rig.world.crash.calls + n;
            rig.world.crash.after_effect = after;
            try {
                (void)release(rig.env, ReleaseRequest{}, dl);
            } catch (const CrashSim&) {
            }
            rig.world.crash.crash_at = -1;
            (void)recover_at_init(rig.env, dl);
            // a release interrupted anywhere finishes at the next start
            CHECK_FALSE(rig.world.table);
            CHECK(rig.store.raw.empty());
        }
    }
}

TEST_CASE("crash at every runner call during a rollback: the next start finishes the release, never re-applies",
          "[agent][firewall_quarantine]") {
    auto is_load = [](const Argv& a) { return a.size() > 1 && a[1] == "-f"; };
    std::size_t apply_calls = 0, total = 0;
    {
        NftRig rig;
        rig.probe.control_up = false;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "rolled_back");
        total = rig.world.log.size();
        for (std::size_t i = 0; i < rig.world.log.size(); ++i)
            if (is_load(rig.world.log[i]))
                apply_calls = i + 1;
    }
    REQUIRE(apply_calls > 0);
    REQUIRE(total > apply_calls);

    for (std::size_t n = apply_calls + 1; n <= total; ++n) {
        for (const bool after : {false, true}) {
            INFO("crash at rollback call " << n << (after ? " (after its effect)" : " (before its effect)"));
            NftRig rig;
            rig.probe.control_up = false;
            rig.world.crash.crash_at = static_cast<int>(n);
            rig.world.crash.after_effect = after;
            auto dl = rig.dl();
            bool crashed = false;
            try {
                (void)apply_and_verify(rig.env, rig.request(), dl);
            } catch (const CrashSim&) {
                crashed = true;
            }
            CHECK(crashed);
            // the intent was durable before the first rule came out
            const auto rec = rig.store.state();
            REQUIRE(rec);
            CHECK(rec->phase == Phase::releasing);

            rig.world.crash.crash_at = -1;
            const auto mark = rig.world.log.size();
            (void)recover_at_init(rig.env, dl);
            CHECK_FALSE(rig.world.table);
            CHECK(rig.store.raw.empty());
            CHECK(std::none_of(rig.world.log.begin() + mark, rig.world.log.end(), is_load));
        }
    }
}

// ── drivers over the iptables leg ───────────────────────────────────────────

namespace {

struct IptRig {
    FakeClock clock;
    IptWorld world;
    FakeStore store;
    Probe probe;
    IptablesLeg leg;
    std::int64_t now = 1'700'000'000;
    Env env;

    explicit IptRig(V6Mode v6 = V6Mode::cover)
        : leg(world.runner(), v6), env{leg, store, probe.fn(), [this] { return now; }} {
        world.clock = &clock;
        probe.blocked = [this] { return !world.fam[std::string{kIptablesPath}].builtin["OUTPUT"].empty(); };
    }
    Deadline dl() { return Deadline(kOperationBudget, clock.fn()); }
    ApplyRequest request() {
        ApplyRequest r;
        r.allow = make_set({"203.0.113.53"}, {ex("10.0.0.5:22/tcp/in")});
        r.probe_target = kProbeTarget;
        return r;
    }
    std::set<std::string> chains(std::string_view tool) { return world.live_chains(std::string{tool}); }
    std::vector<std::string> jumps(std::string_view tool, const std::string& builtin) {
        return world.fam[std::string{tool}].builtin[builtin];
    }
};

} // namespace

TEST_CASE("iptables: apply builds a generation, jumps in, release removes every trace",
          "[agent][firewall_quarantine]") {
    IptRig rig;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "active");
    for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
        CHECK(rig.chains(tool) == std::set<std::string>{"yuzu-fwq-1", "yuzu-fwq-1-f"});
        CHECK(rig.jumps(tool, "INPUT") == std::vector<std::string>{"yuzu-fwq-1"});
        CHECK(rig.jumps(tool, "OUTPUT") == std::vector<std::string>{"yuzu-fwq-1"});
        CHECK(rig.jumps(tool, "FORWARD") == std::vector<std::string>{"yuzu-fwq-1-f"});
    }
    CHECK(rig.store.state()->os.ipt_gen == 1);
    CHECK(report_status(rig.env, dl).status == "active");

    CHECK(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
    for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
        CHECK(rig.chains(tool).empty());
        for (const char* b : {"INPUT", "OUTPUT", "FORWARD"})
            CHECK(rig.jumps(tool, b).empty());
    }
    CHECK(report_status(rig.env, dl).status == "inactive");
}

TEST_CASE("iptables: a v4-only host never touches ip6tables", "[agent][firewall_quarantine]") {
    IptRig rig(V6Mode::v4_only);
    auto dl = rig.dl();
    CHECK(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    CHECK(std::none_of(rig.world.log.begin(), rig.world.log.end(),
                       [](const Argv& a) { return a[0] == "/usr/sbin/ip6tables"; }));
}

TEST_CASE("iptables: a host with the ip6tables binary but no IPv6 stack still releases and reports",
          "[agent][firewall_quarantine]") {
    // Apply covered v4 only (no IPv6 stack then); the binary exists, `ip6tables -S` fails.
    IptRig rig(V6Mode::v4_only);
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    CHECK_FALSE(rig.store.state()->os.ipt_v6);

    // The status/release leg is built with v6 = "the binary exists", as the plugin does.
    IptablesLeg later(rig.world.runner(), V6Mode::cover);
    Env later_env{later, rig.store, rig.probe.fn(), [] { return std::int64_t{1'700'000'100}; }};
    rig.world.fail_on = [](const std::string& cmd) { return cmd.starts_with("/usr/sbin/ip6tables"); };
    CHECK(report_status(later_env, dl).status == "active");
    CHECK(release(later_env, ReleaseRequest{}, dl).status == "inactive");
    CHECK(rig.chains(kIptablesPath).empty());
}

TEST_CASE("iptables: when the apply covered ip6tables, losing its jumps is degraded",
          "[agent][firewall_quarantine]") {
    IptRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    CHECK(rig.store.state()->os.ipt_v6);
    rig.world.fam[std::string{kIp6tablesPath}].builtin["FORWARD"].clear();
    const auto o = report_status(rig.env, dl);
    CHECK(o.status == "degraded");
    CHECK(o.reason == "policy_not_blocking");
}

TEST_CASE("iptables: an update inserts the new jumps before deleting the old ones",
          "[agent][firewall_quarantine]") {
    IptRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto base = rig.world.log.size();
    const auto o = update(rig.env, true, {ex("10.0.0.9:443/tcp/in")}, dl);
    CHECK(o.status == "active");
    for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
        CHECK(rig.chains(tool) == std::set<std::string>{"yuzu-fwq-2", "yuzu-fwq-2-f"});
        CHECK(rig.jumps(tool, "INPUT") == std::vector<std::string>{"yuzu-fwq-2"});
    }
    // order of the v4 swap: build -> insert new jumps -> delete old jumps -> delete old chains
    std::vector<std::string> v4;
    for (std::size_t i = base; i < rig.world.log.size(); ++i)
        if (rig.world.log[i][0] == "/usr/sbin/iptables")
            v4.push_back(join(rig.world.log[i]));
    auto idx = [&](const std::string& s) {
        const auto it = std::find(v4.begin(), v4.end(), s);
        REQUIRE(it != v4.end());
        return it - v4.begin();
    };
    const auto build_done = idx("/usr/sbin/iptables -A yuzu-fwq-2-f -j DROP");
    const auto ins_new = idx("/usr/sbin/iptables -I INPUT 1 -j yuzu-fwq-2");
    const auto del_old = idx("/usr/sbin/iptables -D INPUT -j yuzu-fwq-1");
    const auto rm_old = idx("/usr/sbin/iptables -X yuzu-fwq-1");
    CHECK(build_done < ins_new);
    CHECK(ins_new < del_old);
    CHECK(del_old < rm_old);
    CHECK(rig.store.state()->os.ipt_gen == 2);
}

TEST_CASE("iptables: a failure while building the new chain leaves the previous generation",
          "[agent][firewall_quarantine]") {
    IptRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto before = rig.chains(kIptablesPath);
    const auto before_state = *rig.store.state();

    rig.world.fail_on = [](const std::string& cmd) {
        return cmd.find("-A yuzu-fwq-2 ") != std::string::npos &&
               cmd.find("10.0.0.9") != std::string::npos;
    };
    const auto o = update(rig.env, true, {ex("10.0.0.9:443/tcp/in")}, dl);
    CHECK(o.status == "update_failed");
    CHECK(o.reason == "iptables_command_failed");
    // the half-built generation is gone, the old one governs
    for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
        CHECK(rig.chains(tool) == before);
        CHECK(rig.jumps(tool, "INPUT") == std::vector<std::string>{"yuzu-fwq-1"});
        CHECK(rig.jumps(tool, "FORWARD") == std::vector<std::string>{"yuzu-fwq-1-f"});
    }
    CHECK(rig.store.state()->generation == before_state.generation);
    CHECK(rig.store.state()->allow == before_state.allow);
    CHECK(rig.store.state()->phase == Phase::active);
}

TEST_CASE("iptables: a failure while activating removes the new jumps and chains",
          "[agent][firewall_quarantine]") {
    IptRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.world.fail_on = [](const std::string& cmd) {
        return cmd.find("-I FORWARD 1 -j yuzu-fwq-2-f") != std::string::npos;
    };
    const auto o = update(rig.env, true, {ex("10.0.0.9:443/tcp/in")}, dl);
    CHECK(o.status == "update_failed");
    for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
        CHECK(rig.chains(tool) == std::set<std::string>{"yuzu-fwq-1", "yuzu-fwq-1-f"});
        CHECK(rig.jumps(tool, "INPUT") == std::vector<std::string>{"yuzu-fwq-1"});
        CHECK(rig.jumps(tool, "OUTPUT") == std::vector<std::string>{"yuzu-fwq-1"});
    }
}

TEST_CASE("iptables: exhausting the operation deadline is a failure that keeps the previous generation",
          "[agent][firewall_quarantine]") {
    IptRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    std::vector<Endpoint> many;
    for (int i = 0; i < 40; ++i)
        many.push_back(ex(std::format("10.2.{}.1:{}/in", i, 2000 + i)));
    // every call now takes 1 s of the 60 s budget: the build cannot finish
    rig.world.per_call = 1000ms;
    auto slow = rig.dl();
    const auto o = update(rig.env, true, many, slow);
    CHECK(o.status == "update_failed");
    CHECK(o.reason == "deadline_exceeded");
    for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
        const auto c = rig.chains(tool);
        CHECK(c.count("yuzu-fwq-1") == 1);
        CHECK(c.count("yuzu-fwq-1-f") == 1);
        CHECK(rig.jumps(tool, "INPUT") == std::vector<std::string>{"yuzu-fwq-1"});
    }
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->allow.exceptions.size() == 1);
}

TEST_CASE("iptables: an interrupted attempt never reuses a chain name", "[agent][firewall_quarantine]") {
    IptRig rig;
    auto dl = rig.dl();
    // a previous run died after building generation 3 but before jumping to it
    for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
        auto& f = rig.world.fam[std::string{tool}];
        f.chains = {"yuzu-fwq-3", "yuzu-fwq-3-f"};
    }
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "active");
    CHECK(rig.store.state()->os.ipt_gen == 4);
    CHECK(rig.chains(kIptablesPath) == std::set<std::string>{"yuzu-fwq-4", "yuzu-fwq-4-f"});
}

TEST_CASE("iptables: a legacy chain is refused; release removes strays", "[agent][firewall_quarantine]") {
    IptRig rig;
    rig.world.legacy = true;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "refused");
    CHECK(o.reason == "legacy_quarantine_active");
    CHECK(rig.chains(kIptablesPath).empty());
}

TEST_CASE("iptables v6 plan: the tool and the stack are separate facts", "[agent][firewall_quarantine]") {
    constexpr std::optional<bool> unknown = std::nullopt;
    // tool x stack
    CHECK(iptables_v6_plan(true, true) == V6Mode::cover);
    CHECK(iptables_v6_plan(true, false) == V6Mode::v4_only);
    CHECK(iptables_v6_plan(true, unknown) == V6Mode::cover); // `ip6tables -S` decides
    CHECK(iptables_v6_plan(false, true) == V6Mode::refuse_tool_missing);
    CHECK(iptables_v6_plan(false, false) == V6Mode::v4_only); // IPv6 proven off: IPv4 is the host
    CHECK(iptables_v6_plan(false, unknown) == V6Mode::refuse_stack_unknown); // unknown is not absent

    CHECK(v6_refusal(V6Mode::cover).empty());
    CHECK(v6_refusal(V6Mode::v4_only).empty());
    CHECK(v6_refusal(V6Mode::refuse_tool_missing) == "ip6tables_missing");
    CHECK(v6_refusal(V6Mode::refuse_stack_unknown) == "ipv6_stack_unknown");
    CHECK(is_safe_token(v6_refusal(V6Mode::refuse_tool_missing)));
    CHECK(is_safe_token(v6_refusal(V6Mode::refuse_stack_unknown)));
}

TEST_CASE("iptables: a host that may route IPv6 with no ip6tables is refused, not contained over IPv4 only",
          "[agent][firewall_quarantine]") {
    const std::pair<V6Mode, std::string_view> cases[] = {
        {V6Mode::refuse_tool_missing, "ip6tables_missing"},
        {V6Mode::refuse_stack_unknown, "ipv6_stack_unknown"},
    };
    for (const auto& [mode, token] : cases) {
        INFO("mode token " << token);
        SECTION("quarantine refuses through preflight before any command runs: " + std::string{token}) {
            IptRig rig(mode);
            auto dl = rig.dl();
            const auto o = apply_and_verify(rig.env, rig.request(), dl);
            CHECK(o.status == "refused");
            CHECK(o.reason == token);
            CHECK(rig.world.crash.calls == 0);
            CHECK(rig.store.raw.empty());
            CHECK(rig.chains(kIptablesPath).empty());
            CHECK(render_rows(o)[1] == std::format("refused|{}", token));
        }
        SECTION("an init re-apply and an update do not pass preflight, and fail the same way: " +
                std::string{token}) {
            IptRig rig; // applied while ip6tables was usable
            auto dl = rig.dl();
            REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
            const auto before = *rig.store.state();

            IptablesLeg refusing(rig.world.runner(), mode);
            Env renv{refusing, rig.store, rig.probe.fn(), [] { return std::int64_t{1'700'000'100}; }};

            const auto u = update(renv, true, {ex("10.0.0.9:443/tcp/in")}, dl);
            CHECK(u.status == "update_failed");
            CHECK(u.reason == token);
            CHECK(rig.store.state()->allow == before.allow);
            CHECK(rig.chains(kIptablesPath) == std::set<std::string>{"yuzu-fwq-1", "yuzu-fwq-1-f"});

            // a reboot: the chains are gone, the record remains; the re-apply must not build a v4-only table
            rig.world.fam.clear();
            const auto mark = rig.world.log.size();
            const auto r = recover_at_init(renv, dl);
            CHECK(r.status == "degraded");
            CHECK(r.reason == "reapply_failed:" + std::string{token});
            CHECK(std::none_of(rig.world.log.begin() + mark, rig.world.log.end(), [](const Argv& a) {
                return a.size() > 1 && (a[1] == "-N" || a[1] == "-A" || a[1] == "-I");
            }));
        }
    }
}

TEST_CASE("iptables: idempotent re-apply leaves one generation, no duplicates",
          "[agent][firewall_quarantine]") {
    IptRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    for (int i = 0; i < 3; ++i) {
        rig.world.fam[std::string{kIptablesPath}].builtin["INPUT"].clear(); // simulate a lost jump
        (void)recover_at_init(rig.env, dl);
        CHECK(rig.chains(kIptablesPath).size() == 2);
        CHECK(rig.jumps(kIptablesPath, "INPUT").size() == 1);
        CHECK(rig.jumps(kIptablesPath, "OUTPUT").size() == 1);
    }
}

TEST_CASE("crash at every runner call during an iptables update", "[agent][firewall_quarantine]") {
    int clean_calls = 0;
    {
        IptRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto base = rig.world.crash.calls;
        REQUIRE(update(rig.env, true, {ex("10.0.0.9:443/tcp/in")}, dl).status == "active");
        clean_calls = rig.world.crash.calls - base;
    }
    REQUIRE(clean_calls > 10);
    // sample every call (before and after its effect)
    for (int n = 1; n <= clean_calls; ++n) {
        for (const bool after : {false, true}) {
            INFO("crash at update call " << n << (after ? " after" : " before"));
            IptRig rig;
            auto dl = rig.dl();
            REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
            rig.world.crash.crash_at = rig.world.crash.calls + n;
            rig.world.crash.after_effect = after;
            try {
                (void)update(rig.env, true, {ex("10.0.0.9:443/tcp/in")}, dl);
            } catch (const CrashSim&) {
            }
            rig.world.crash.crash_at = -1;
            // at no point between the crash and recovery is the host unrestricted
            for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
                CHECK_FALSE(rig.jumps(tool, "INPUT").empty());
                CHECK_FALSE(rig.jumps(tool, "OUTPUT").empty());
                CHECK_FALSE(rig.jumps(tool, "FORWARD").empty());
            }
            (void)recover_at_init(rig.env, dl);
            CHECK(rig.store.state()->phase == Phase::active);
            for (const auto tool : {kIptablesPath, kIp6tablesPath}) {
                // exactly one live generation after recovery
                std::set<std::string> gens;
                for (const auto& c : rig.chains(tool))
                    gens.insert(c.substr(0, c.size() - (c.ends_with("-f") ? 2 : 0)));
                CHECK(gens.size() == 1);
                CHECK(rig.jumps(tool, "INPUT").size() == 1);
            }
        }
    }
}

// ── drivers over the pf leg ─────────────────────────────────────────────────

namespace {

constexpr const char* kPfBoot1 = "1699999999.123456";
constexpr const char* kPfBoot2 = "1700000500.000001";
constexpr const char* kPfAnchorName = "com.apple/000.yuzu_quarantine";

/// A macOS pf world: the enable reference table, the one anchor we own, the main
/// ruleset's wildcard reference, sibling anchors and the global state table.
struct PfWorld {
    FakeClock* clock = nullptr;
    std::chrono::milliseconds per_call{0};
    std::function<std::string()> record; // the durable record as text, peeked at each effect
    std::function<void()> on_enable;     // runs when `-E` lands (a test hook)

    bool pf_on = false;
    std::vector<std::string> tokens;     // enable references, oldest first
    std::string next_token = "3665316113424588000";
    bool anchor_exists = false;
    std::string anchor_text;
    bool referenced = true;              // the main ruleset carries anchor "com.apple/*"
    std::vector<std::string> siblings{"com.apple/200.AirDrop", "com.apple/250.ApplicationFirewall"};
    std::string boot = kPfBoot1;
    std::map<std::string, std::string> files;
    int next_file = 0;

    int flush_states = 0;
    int enables = 0;
    int fail_flush_states = 0;           // fail the next N `-F states`
    bool fail_load = false;
    bool fail_enable = false;
    bool fail_info = false;
    bool flush_fails_when_absent = false;
    bool fail_flush_anchor = false;      // the anchor flush is refused outright
    bool disable_clears_refs = false;    // what `pfctl -d` does to the references (unverified on xnu)
    std::string record_at_enable, record_at_load, record_at_flush;
    Crash crash;
    std::vector<Argv> log;

    void external_disable() { // someone ran `pfctl -d`
        pf_on = false;
        if (disable_clears_refs)
            tokens.clear();
    }
    void reboot() { // pf starts disabled with no references and no dynamic anchors
        pf_on = false;
        tokens.clear();
        anchor_exists = false;
        anchor_text.clear();
        boot = kPfBoot2;
    }
    [[nodiscard]] bool enforcing() const { return pf_on && anchor_exists; }

    ToolResult effect(const Argv& a) {
        const auto cmd = join(a);
        const std::string anchor_flag = std::string("-a ") + kPfAnchorName;
        if (cmd == "/sbin/pfctl -s info") {
            if (fail_info)
                return done(1, "pfctl: /dev/pf: Permission denied");
            return done(0, pf_on ? "Status: Enabled for 0 days 00:00:04           Debug: Urgent\n"
                                 : "Status: Disabled\n");
        }
        if (cmd == "/sbin/pfctl -s rules")
            return done(0, referenced ? "scrub-anchor \"com.apple/*\" all fragment reassemble\n"
                                        "anchor \"com.apple/*\" all\n"
                                      : "block drop all\n");
        if (cmd == "/sbin/pfctl " + anchor_flag + " -s rules") {
            if (!anchor_exists)
                return done(1, "pfctl: DIOCGETRULES: Invalid argument");
            std::string out;
            for (const auto l : detail::split(anchor_text, '\n'))
                if (!l.empty() && !l.starts_with("no "))
                    out += std::string{l} + "\n";
            return done(0, out);
        }
        if (cmd == "/sbin/pfctl -a com.apple -s Anchors") {
            std::string out;
            for (const auto& s : siblings)
                out += "   " + s + "\n";
            if (anchor_exists)
                out += std::string("   ") + kPfAnchorName + "\n";
            return done(0, out);
        }
        if (cmd == "/sbin/pfctl -s References") {
            std::string out = "PID   NAME             TOKEN                TIMESTAMP\n";
            for (const auto& t : tokens)
                out += "321   holder           " + t + "  1700000000\n";
            return done(0, out);
        }
        if (cmd == "/sbin/pfctl -E") {
            if (fail_enable)
                return done(1, "pfctl: pf not enabled");
            ++enables;
            record_at_enable = record ? record() : std::string{};
            next_token = std::to_string(std::stoull(next_token) + 1);
            tokens.push_back(next_token);
            pf_on = true;
            if (on_enable)
                on_enable();
            return done(0, "pfctl: Use of -f option, could result in flushing of rules\n"
                           "No ALTQ support in kernel\nToken : " + next_token + "\n");
        }
        if (a.size() == 3 && a[1] == "-X") {
            const auto it = std::find(tokens.begin(), tokens.end(), a[2]);
            if (it == tokens.end())
                return done(1, "pfctl: Unable to release the reference: Invalid argument");
            tokens.erase(it);
            if (tokens.empty())
                pf_on = false;
            return done(0);
        }
        if (cmd == "/sbin/pfctl -F states") {
            record_at_flush = record ? record() : std::string{};
            ++flush_states;
            if (fail_flush_states > 0) {
                --fail_flush_states;
                return done(1, "pfctl: DIOCCLRSTATES: Operation not permitted");
            }
            return done(0, "0 states cleared\n");
        }
        if (cmd == "/sbin/pfctl " + anchor_flag + " -F rules" ||
            cmd == "/sbin/pfctl " + anchor_flag + " -F nat") {
            if (fail_flush_anchor)
                return done(1, "sudo: a password is required");
            if (flush_fails_when_absent && !anchor_exists)
                return done(1, "pfctl: DIOCXBEGIN: Invalid argument");
            anchor_text.clear();
            anchor_exists = false;
            return done(0);
        }
        if (a.size() == 5 && a[1] == "-a" && a[2] == kPfAnchorName && a[3] == "-f") {
            record_at_load = record ? record() : std::string{};
            if (fail_load)
                return done(1, "pfctl: Use of -f option, could result in flushing of rules\n"
                               "present in the main ruleset added by the system at startup.\n"
                               "See /etc/pf.conf for further details.\n\n" + a[4] + ":3: syntax error");
            anchor_text = files[a[4]];
            anchor_exists = true;
            return done(0, "pfctl: Use of -f option, could result in flushing of rules\n"
                           "present in the main ruleset added by the system at startup.\n"
                           "See /etc/pf.conf for further details.\n");
        }
        return done(1, "unexpected argv: " + cmd);
    }

    Runner runner() {
        return [this](const Argv& a, std::chrono::milliseconds) {
            ++crash.calls;
            log.push_back(a);
            if (clock)
                clock->advance(per_call);
            if (crash.calls == crash.crash_at && !crash.after_effect)
                throw CrashSim{};
            auto r = effect(a);
            if (crash.calls == crash.crash_at && crash.after_effect)
                throw CrashSim{};
            return r;
        };
    }
    Stage stage() {
        return [this](std::string_view, std::string_view suffix,
                      std::string_view contents) -> std::optional<StagedFile> {
            const auto path = std::format("/tmp/yuzu-fwq-pf-{}{}", ++next_file, suffix);
            files[path] = std::string{contents};
            return StagedFile{path, nullptr};
        };
    }
    [[nodiscard]] bool ran(std::string_view needle) const {
        return std::any_of(log.begin(), log.end(),
                           [&](const Argv& a) { return join(a).find(needle) != std::string::npos; });
    }
    [[nodiscard]] int count(std::string_view needle, std::size_t from = 0) const {
        int n = 0;
        for (std::size_t i = from; i < log.size(); ++i)
            n += join(log[i]).find(needle) != std::string::npos ? 1 : 0;
        return n;
    }
};

struct PfRig {
    FakeClock clock;
    PfWorld world;
    FakeStore store;
    Probe probe;
    bool boot_readable = true;
    PfLeg leg;
    std::int64_t now = 1'700'000'000;
    Env env;

    PfRig()
        : leg(world.runner(), world.stage(),
              [this]() -> std::optional<std::string> {
                  if (!boot_readable)
                      return std::nullopt;
                  return world.boot;
              }),
          env{leg, store, probe.fn(), [this] { return now; }} {
        world.clock = &clock;
        world.record = [this] { return store.raw; };
        probe.blocked = [this] { return world.enforcing(); };
    }
    Deadline dl() { return Deadline(kOperationBudget, clock.fn()); }
    ApplyRequest request(std::string target = kProbeTarget, std::int64_t ttl = 0) {
        ApplyRequest r;
        r.allow = make_set();
        r.probe_target = std::move(target);
        r.ttl_seconds = ttl;
        return r;
    }
    [[nodiscard]] std::string token() const { return store.state() ? store.state()->os.pf_token : ""; }
};

} // namespace

TEST_CASE("pf: apply order -- reference, siblings, load, then the state flush; token recorded first",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl);
    CHECK(o.status == "active");
    CHECK(*o.verify == "verify|control=ok|probe=blocked");
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->backend == BackendKind::pf);
    CHECK(rig.world.enforcing());
    REQUIRE(rig.world.tokens.size() == 1);
    CHECK(rig.store.state()->os.pf_token == rig.world.tokens[0]);
    CHECK(rig.store.state()->os.boot_time == kPfBoot1);

    // the exact order of the privileged calls
    std::vector<std::string> cmds;
    for (const auto& a : rig.world.log)
        cmds.push_back(join(a));
    const std::vector<std::string> want{
        "/sbin/pfctl -s info",
        "/sbin/pfctl -E",
        "/sbin/pfctl -s rules",
        "/sbin/pfctl -a com.apple -s Anchors",
        std::string("/sbin/pfctl -a ") + kPfAnchorName + " -f /tmp/yuzu-fwq-pf-1.pf",
        "/sbin/pfctl -F states",
    };
    REQUIRE(cmds.size() >= want.size());
    CHECK(std::vector<std::string>(cmds.begin(), cmds.begin() + static_cast<long>(want.size())) == want);

    // no OS mutation without a recovery record, and the token is durable BEFORE the
    // anchor is loaded or the states are flushed
    CHECK(rig.world.record_at_enable.find("phase=applying") != std::string::npos);
    CHECK(rig.world.record_at_enable.find("pf_token=") == std::string::npos); // no token exists yet
    CHECK(rig.world.record_at_load.find("pf_token=" + rig.world.tokens[0]) != std::string::npos);
    CHECK(rig.world.record_at_load.find("phase=applying") != std::string::npos);
    CHECK(rig.world.record_at_flush.find("pf_token=" + rig.world.tokens[0]) != std::string::npos);

    // the staged ruleset is the one the pure core builds, and it is clean
    CHECK(rig.world.anchor_text == pf_anchor_ruleset(make_set()));
    for (const auto& a : rig.world.log)
        CHECK(all_tokens_safe(a));
    // never a main-ruleset load, never `-d`
    CHECK_FALSE(rig.world.ran("pfctl -f"));
    CHECK_FALSE(rig.world.ran(" -d"));
    CHECK_FALSE(rig.world.ran("/etc/pf.conf"));

    // an update is one anchor reload plus one state flush and takes no second reference
    const auto before_calls = rig.world.log.size();
    const auto upd = update(rig.env, true, {ex("10.0.0.9:22/tcp/in")}, dl);
    CHECK(upd.status == "active");
    CHECK(rig.world.flush_states == 2);
    CHECK(rig.world.count(" -f ", before_calls) == 1);
    CHECK(rig.world.count("pfctl -E", before_calls) == 0);
    CHECK(rig.world.tokens.size() == 1);
}

TEST_CASE("pf: a failed state flush is a failed apply, never active", "[agent][firewall_quarantine]") {
    SECTION("one failure is retried") {
        PfRig rig;
        rig.world.fail_flush_states = 1;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "active");
        CHECK(rig.world.flush_states == 2);
    }
    SECTION("two failures roll an initial apply back to absence") {
        PfRig rig;
        rig.world.fail_flush_states = 2;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(o.reason == "apply_failed:state_flush_failed");
        CHECK(rig.world.flush_states == 2);
        // the anchor is emptied, the reference given back, pf is off again, no record
        CHECK_FALSE(rig.world.anchor_exists);
        CHECK(rig.world.tokens.empty());
        CHECK_FALSE(rig.world.pf_on);
        CHECK(rig.store.raw.empty());
    }
    SECTION("a failed update flush reports the generation that is in force, partial") {
        // No external disable: the enable plan is `reuse`, so the failure is the flush alone.
        PfRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto gen_before = rig.store.state()->generation;
        rig.world.fail_flush_states = 2;
        const auto added = ex("10.0.0.9:22/tcp/in");
        const auto o = update(rig.env, true, {added}, dl);
        // the anchor load already committed the new set; the record and the output say so
        auto want = make_set();
        want.exceptions.push_back(added);
        CHECK(rig.world.anchor_text == pf_anchor_ruleset(want));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->allow == want);
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->generation == gen_before + 1);
        CHECK(o.status == "partial");
        CHECK(contains(o.notes, "state_flush_failed=1"));
        REQUIRE(o.state);
        CHECK(o.state->allow == want);
        CHECK(rig.world.flush_states == 3); // the apply's one, then the update's two attempts
        // a later successful update builds on what is in force
        const auto again = update(rig.env, false, {added}, dl);
        CHECK(again.status == "active");
        CHECK(rig.world.anchor_text == pf_anchor_ruleset(make_set()));
        CHECK(rig.store.state()->allow == make_set());
    }
    SECTION("a failed flush on a remove is partial too") {
        PfRig rig;
        auto dl = rig.dl();
        const auto kept = ex("10.0.0.9:22/tcp/in");
        REQUIRE(apply_and_verify(rig.env, [&] {
                    auto r = rig.request();
                    r.allow = make_set({"203.0.113.53"}, {kept});
                    return r;
                }(), dl).status == "active");
        rig.world.fail_flush_states = 2;
        const auto o = update(rig.env, false, {kept}, dl);
        CHECK(o.status == "partial");
        CHECK(contains(o.notes, "state_flush_failed=1"));
        CHECK(rig.world.anchor_text == pf_anchor_ruleset(make_set()));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->allow == make_set());
    }
    SECTION("a failed update that also took a fresh reference records it") {
        PfRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.world.external_disable(); // the next apply must take a fresh reference
        rig.world.fail_flush_states = 2;
        const auto o = update(rig.env, true, {ex("10.0.0.9:22/tcp/in")}, dl);
        CHECK(o.status == "partial");
        CHECK(contains(o.notes, "state_flush_failed=1"));
        // the record carries the reference the attempt took, so it can be released
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::active);
        REQUIRE(rig.world.tokens.size() == 1);
        CHECK(rig.store.state()->os.pf_token == rig.world.tokens[0]);
        CHECK(rig.world.pf_on);
        CHECK(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
        CHECK(rig.world.tokens.empty());
    }
}

TEST_CASE("pf: a load failure gives back the reference taken in this call", "[agent][firewall_quarantine]") {
    PfRig rig;
    rig.world.fail_load = true;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "rolled_back");
    CHECK(o.reason == "apply_failed:pf_load_failed");
    REQUIRE(contains(o.notes, "detail=/tmp/yuzu-fwq-pf-1.pf:3: syntax error")); // not the -f boilerplate
    CHECK(rig.world.flush_states == 0); // no state is disturbed for a ruleset that never loaded
    CHECK(rig.world.tokens.empty());
    CHECK_FALSE(rig.world.pf_on);
    CHECK(rig.store.raw.empty());
}

TEST_CASE("pf: a dangling anchor is refused before anything is loaded or flushed",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    rig.world.referenced = false;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "rolled_back");
    CHECK(o.reason == "apply_failed:anchor_not_referenced");
    CHECK_FALSE(rig.world.ran(" -f "));
    CHECK(rig.world.flush_states == 0);
    CHECK(rig.world.tokens.empty());
    CHECK_FALSE(rig.world.pf_on);
    CHECK(rig.store.raw.empty());
}

TEST_CASE("pf: an unreadable boot time refuses to guess a token's age", "[agent][firewall_quarantine]") {
    PfRig rig;
    rig.boot_readable = false;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "rolled_back");
    CHECK(o.reason == "apply_failed:boot_time_unreadable");
    CHECK_FALSE(rig.world.ran(" -E"));    // no reference taken, nothing loaded or flushed
    CHECK_FALSE(rig.world.ran(" -f "));
    CHECK(rig.world.flush_states == 0);
    CHECK(rig.store.raw.empty());
}

TEST_CASE("pf: a sibling anchor that sorts first makes the result partial, then degraded",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    rig.world.siblings.push_back("com.apple/000.aaa");
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "partial");
    CHECK(contains(o.notes, "anchor_not_first=1"));
    CHECK(rig.world.anchor_exists); // contained as far as this anchor can, and said so
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "degraded");
    CHECK(st.reason == "anchor_not_first");

    // re-applying cannot fix a sibling, so a retry neither flushes the states again nor says "active"
    const auto flushes = rig.world.flush_states;
    const auto again = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(again.status == "degraded");
    CHECK(again.reason == "anchor_not_first");
    CHECK(rig.world.flush_states == flushes);

    // the sibling goes away: healthy
    rig.world.siblings.pop_back();
    CHECK(report_status(rig.env, dl).status == "active");
}

TEST_CASE("pf: pf disabled by someone else with our token stored is repaired with a fresh -E",
          "[agent][firewall_quarantine]") {
    for (const bool clears : {false, true}) {
        INFO("pfctl -d clears references: " << clears);
        PfRig rig;
        rig.world.disable_clears_refs = clears;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto old_token = rig.token();

        rig.world.external_disable();
        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "degraded");
        CHECK(st.reason == "pf_disabled");
        CHECK(contains(st.notes, "pf_token_dead=1"));
        CHECK(rig.store.state()->phase == Phase::active); // status never mutates

        // the shared driver repairs an `active` record whose OS no longer enforces it
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "active");
        CHECK(contains(o.notes, "repaired=1"));
        CHECK(rig.world.pf_on);
        CHECK(rig.world.enforcing());
        // the dead token was released best-effort (it may be gone), a fresh one taken and recorded
        CHECK(rig.world.ran("-X " + old_token));
        REQUIRE(rig.world.tokens.size() == 1);
        CHECK(rig.world.tokens[0] != old_token);
        CHECK(rig.token() == rig.world.tokens[0]);
        CHECK(report_status(rig.env, dl).status == "active");
    }
}

TEST_CASE("pf: boot-time recovery repairs a disabled pf and re-applies after a reboot",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    auto dl = rig.dl();

    SECTION("a disabled pf is repaired in place; a reboot re-applies with a fresh reference") {
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto first = rig.token();

        // same boot, still enforcing: verified only -- no -E, no load, no flush
        const auto calls = rig.world.log.size();
        CHECK(recover_at_init(rig.env, dl).status == "active");
        CHECK(rig.world.count("pfctl -E", calls) == 0);
        CHECK(rig.world.count(" -f ", calls) == 0);
        CHECK(rig.world.flush_states == 1);

        // same boot, pf switched off: repaired
        rig.world.external_disable();
        const auto o = recover_at_init(rig.env, dl);
        CHECK(o.status == "active");
        CHECK(contains(o.notes, "reapplied=1"));
        CHECK(rig.world.enforcing());
        CHECK(rig.token() != first);

        // a reboot: no references, no anchor, a new boot time. A fresh -E, and the stale
        // token is NOT released (the kernel's count reset; the token means nothing now)
        const auto stale = rig.token();
        rig.world.reboot();
        CHECK(report_status(rig.env, dl).status == "degraded");
        const auto before = rig.world.log.size();
        CHECK(recover_at_init(rig.env, dl).status == "active");
        CHECK(rig.world.enforcing());
        CHECK(rig.world.count("-X " + stale, before) == 0);
        CHECK(rig.store.state()->os.boot_time == kPfBoot2);
        CHECK(rig.token() != stale);
        CHECK(rig.world.tokens.size() == 1);
    }

    SECTION("a reboot whose re-apply cannot flush states reports partial, and update clears it") {
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto gen_before = rig.store.state()->generation;
        const auto flushes = rig.world.flush_states;

        // After a reboot the anchor is empty, so no earlier generation flushed the
        // states opened since boot. The anchor load still committed the new
        // generation and init never rolls back: it is in force, recorded, partial.
        rig.world.reboot();
        rig.world.fail_flush_states = 2;
        const auto o = recover_at_init(rig.env, dl);
        CHECK(o.status == "partial");
        CHECK(contains(o.notes, "reapplied=1"));
        CHECK(contains(o.notes, "state_flush_failed=1"));
        CHECK(rig.world.enforcing());
        CHECK(rig.world.flush_states == flushes + 2); // the attempt and its one retry
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->generation == gen_before + 1);
        CHECK(rig.store.state()->os.boot_time == kPfBoot2);

        // The remedy the note names: the next update flushes again.
        const auto added = ex("10.0.0.9:22/tcp/in");
        CHECK(update(rig.env, true, {added}, dl).status == "active");
        CHECK(rig.world.flush_states == flushes + 3);
    }
}

TEST_CASE("pf: a failed state flush is recorded on the state record; status stays partial until a flush succeeds",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    CHECK_FALSE(rig.store.state()->os.state_flush_failed);

    rig.world.fail_flush_states = 2;
    const auto added = ex("10.0.0.9:22/tcp/in");
    const auto o = update(rig.env, true, {added}, dl);
    CHECK(o.status == "partial");
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->os.state_flush_failed);
    CHECK(rig.store.raw.find("flush_failed=1") != std::string::npos);

    // the NEXT status, read from the record: partial with the reason named, not active
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "state_flush_failed");
    CHECK(contains(st.notes, "state_flush_failed=1"));
    CHECK(result_kind(st).partial);

    // a restart that finds the anchor enforcing does not flush, so the gap stays visible
    const auto mark = rig.world.log.size();
    const auto rec = recover_at_init(rig.env, dl);
    CHECK(rec.status == "partial");
    CHECK(rig.world.count("-F states", mark) == 0);
    CHECK(rig.store.state()->os.state_flush_failed);
    CHECK(report_status(rig.env, dl).status == "partial");

    // a failed flush on a later update leaves it set; a successful one clears it
    rig.world.fail_flush_states = 2;
    CHECK(update(rig.env, false, {added}, dl).status == "partial");
    CHECK(rig.store.state()->os.state_flush_failed);
    const auto again = update(rig.env, true, {added}, dl);
    CHECK(again.status == "active");
    CHECK_FALSE(rig.store.state()->os.state_flush_failed);
    CHECK(rig.store.raw.find("flush_failed") == std::string::npos);
    CHECK(report_status(rig.env, dl).status == "active");
}

TEST_CASE("pf: a reboot re-apply whose flush fails is partial in the NEXT status too",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.world.reboot();
    rig.world.fail_flush_states = 2;
    const auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "partial");
    CHECK(rig.world.enforcing());
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->os.state_flush_failed);

    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "state_flush_failed");
}

TEST_CASE("pf: converging an interrupted INITIAL apply is an update, so the record follows the anchor",
          "[agent][firewall_quarantine]") {
    // A crashed first apply left `applying`, gen 1, no previous generation, set A.
    auto crashed_initial = [&](PfRig& rig) {
        QuarantineState a;
        a.phase = Phase::applying;
        a.generation = 1;
        a.applied_at = rig.now;
        a.probe_target = kProbeTarget;
        a.backend = BackendKind::pf;
        a.allow = make_set();
        REQUIRE(rig.store.save(a));
    };
    auto set_b = [] { return make_set({"203.0.113.53"}, {ex("10.0.0.9:22/tcp/in")}); };

    SECTION("a retried quarantine with a changed set, both state flushes failing") {
        PfRig rig;
        crashed_initial(rig);
        rig.world.fail_flush_states = 2;
        auto req = rig.request();
        req.allow = set_b();
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, req, dl);
        CHECK(contains(o.notes, "incomplete_apply_converged=1"));
        // the pf leg reports partial (not a failed initial apply), so the record is
        // set B -- the set the anchor holds -- not the restored set A
        CHECK(o.status == "partial");
        CHECK(contains(o.notes, "state_flush_failed=1"));
        CHECK(rig.world.anchor_text == pf_anchor_ruleset(set_b()));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->allow == set_b());
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->os.state_flush_failed);
        CHECK(report_status(rig.env, dl).status == "partial");
    }
    SECTION("boot-time recovery of the same record") {
        PfRig rig;
        crashed_initial(rig);
        rig.world.fail_flush_states = 2;
        auto dl = rig.dl();
        const auto o = recover_at_init(rig.env, dl);
        CHECK(o.status == "partial");
        CHECK(contains(o.notes, "state_flush_failed=1"));
        CHECK(rig.world.anchor_text == pf_anchor_ruleset(make_set()));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->allow == make_set());
        CHECK(rig.store.state()->os.state_flush_failed);
        CHECK(report_status(rig.env, dl).reason == "state_flush_failed");
    }
}

TEST_CASE("pf: a crash between -E and the token write leaks one reference, visible, never silent",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    // crash right after -E lands (call 2: info, -E)
    rig.world.crash.crash_at = 2;
    rig.world.crash.after_effect = true;
    auto dl = rig.dl();
    CHECK_THROWS_AS(apply_and_verify(rig.env, rig.request(), dl), CrashSim);
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::applying); // the recovery record exists
    CHECK(rig.store.state()->os.pf_token.empty());       // the token never reached it
    CHECK(rig.world.tokens.size() == 1);                 // and the host holds the reference

    // the next start converges; the orphan reference is the documented residual
    rig.world.crash.crash_at = -1;
    CHECK(recover_at_init(rig.env, dl).status == "active");
    CHECK(rig.world.tokens.size() == 2);
    const auto st = report_status(rig.env, dl);
    CHECK(contains(st.notes, "pf_references=2")); // visible to the operator

    // release gives back ours; the orphan remains until reboot (and is named, not hidden)
    const auto rel = release(rig.env, ReleaseRequest{}, dl);
    CHECK(rel.status == "inactive");
    CHECK(contains(rel.notes, "pf_references=1"));
}

TEST_CASE("pf: a token that cannot be recorded is released at once", "[agent][firewall_quarantine]") {
    PfRig rig;
    rig.world.on_enable = [&] { rig.store.fail_save = true; }; // the record write after -E fails
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "rolled_back");
    CHECK(o.reason == "apply_failed:state_not_persisted");
    CHECK(rig.world.tokens.empty());
    CHECK_FALSE(rig.world.pf_on);
    CHECK_FALSE(rig.world.anchor_exists);
}

TEST_CASE("pf: release is a true undo of the rules and the enable state, and touches nothing global",
          "[agent][firewall_quarantine]") {
    SECTION("pf was off before") {
        PfRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto flushes = rig.world.flush_states;
        const auto calls = rig.world.log.size();
        const auto rel = release(rig.env, ReleaseRequest{}, dl);
        CHECK(rel.status == "inactive");
        // pre-quarantine comparison: the main ruleset, the Status line, the reference count
        CHECK_FALSE(rig.world.anchor_exists);
        CHECK_FALSE(rig.world.pf_on);
        CHECK(rig.world.tokens.empty());
        CHECK(rig.store.raw.empty());
        CHECK(contains(rel.notes, "pf_references=0"));
        // release is exactly: our anchor's rules, our anchor's nat, our token -- no global flush
        CHECK(rig.world.flush_states == flushes);
        CHECK(rig.world.count("-F rules", calls) == 1);
        CHECK(rig.world.count("-F nat", calls) == 1);
        CHECK(rig.world.count("-F all", calls) == 0);
        CHECK(rig.world.count("-F states", calls) == 0);
        CHECK(rig.world.count(" -f ", calls) == 0);
        CHECK(rig.world.count(" -d", calls) == 0);
        CHECK(rig.world.count("-X ", calls) == 1);
        // idempotent
        CHECK(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
    }
    SECTION("another holder's reference is untouched and pf stays on") {
        PfRig rig;
        rig.world.pf_on = true;
        rig.world.tokens.push_back("1111111111111111111"); // e.g. the Application Firewall
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        CHECK(rig.world.tokens.size() == 2);
        CHECK(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
        CHECK(rig.world.pf_on);
        REQUIRE(rig.world.tokens.size() == 1);
        CHECK(rig.world.tokens[0] == "1111111111111111111");
    }
}

TEST_CASE("pf: release tolerates a token pf no longer knows, and an anchor that is already gone",
          "[agent][firewall_quarantine]") {
    SECTION("vanished token") {
        PfRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.world.tokens.clear(); // `pfctl -d` cleared the references, say
        const auto rel = release(rig.env, ReleaseRequest{}, dl);
        CHECK(rel.status == "inactive");
        CHECK(contains(rel.notes, "pf_token_release_failed=1"));
        CHECK_FALSE(rig.world.anchor_exists);
        CHECK(rig.store.raw.empty());
    }
    SECTION("a flush that errors on an anchor that does not exist is a clean release") {
        PfRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.world.reboot();
        rig.world.flush_fails_when_absent = true;
        const auto rel = release(rig.env, ReleaseRequest{}, dl);
        CHECK(rel.status == "inactive");
        CHECK(rig.store.raw.empty());
    }
    SECTION("a flush that fails on an anchor that IS enforcing is a failed release") {
        PfRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.world.fail_flush_anchor = true; // refused, and the anchor still holds the block
        const auto rel = release(rig.env, ReleaseRequest{}, dl);
        CHECK(rel.status == "partial");
        CHECK(rel.reason.rfind("release_failed:", 0) == 0);
        CHECK(rig.store.state()->phase == Phase::releasing); // finished at the next start
    }
    SECTION("no token on record: pf is left as found, and said so") {
        PfRig rig;
        rig.world.pf_on = true; // someone else's reference
        rig.world.tokens.push_back("1111111111111111111");
        auto dl = rig.dl();
        const auto rel = release(rig.env, ReleaseRequest{}, dl);
        CHECK(rel.status == "inactive");
        CHECK(contains(rel.notes, "pf_left_enabled_no_token=1"));
        CHECK_FALSE(rig.world.ran("-X"));
        CHECK(rig.world.pf_on);
    }
}

TEST_CASE("pf: status shapes", "[agent][firewall_quarantine]") {
    PfRig rig;
    auto dl = rig.dl();
    CHECK(report_status(rig.env, dl).status == "inactive");

    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    auto st = report_status(rig.env, dl);
    CHECK(st.status == "active");
    CHECK(contains(st.notes, "pf_references=1"));
    CHECK(std::none_of(rig.world.log.begin(), rig.world.log.end(), [](const Argv& a) {
        return a.size() > 1 && (a[1] == "-d" || a[1] == "-f");
    }));

    rig.world.referenced = false; // a customer ruleset with no Apple wildcard
    st = report_status(rig.env, dl);
    CHECK(st.status == "degraded");
    CHECK(st.reason == "anchor_not_referenced");
    // re-applying cannot fix a missing reference: reported, not re-flushed on every retry
    const auto flushes = rig.world.flush_states;
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "degraded");
    CHECK(o.reason == "anchor_not_referenced");
    CHECK(rig.world.flush_states == flushes);
    rig.world.referenced = true;

    rig.world.anchor_text.clear(); // someone flushed our anchor
    rig.world.anchor_exists = false;
    st = report_status(rig.env, dl);
    CHECK(st.status == "degraded");
    CHECK(st.reason == "policy_not_blocking");
    CHECK(contains(st.notes, "pf_anchor_read_failed=1"));

    rig.world.fail_info = true; // pfctl itself is unreadable
    st = report_status(rig.env, dl);
    CHECK(st.status == "degraded");
    CHECK(st.reason == "os_unreadable");
}

TEST_CASE("pf: a crash at every runner call during apply or release converges at the next start",
          "[agent][firewall_quarantine]") {
    int clean_apply = 0, clean_release = 0;
    {
        PfRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        clean_apply = rig.world.crash.calls;
        const auto base = rig.world.crash.calls;
        REQUIRE(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
        clean_release = rig.world.crash.calls - base;
    }
    for (int n = 1; n <= clean_apply; ++n) {
        for (const bool after : {false, true}) {
            INFO("apply: crash at call " << n << (after ? " (after its effect)" : " (before its effect)"));
            PfRig rig;
            rig.world.crash.crash_at = n;
            rig.world.crash.after_effect = after;
            auto dl = rig.dl();
            bool crashed = false;
            try {
                (void)apply_and_verify(rig.env, rig.request(), dl);
            } catch (const CrashSim&) {
                crashed = true;
            }
            CHECK(crashed);
            const auto rec = rig.store.state();
            if (rig.world.anchor_exists)
                CHECK(rec.has_value()); // never unrecorded rules
            if (rec && rec->phase == Phase::active)
                CHECK(rig.world.enforcing());
            rig.world.crash.crash_at = -1;
            (void)recover_at_init(rig.env, dl);
            const auto after_rec = rig.store.state();
            if (after_rec) {
                CHECK(after_rec->phase == Phase::active);
                CHECK(rig.world.enforcing());
            } else {
                CHECK_FALSE(rig.world.anchor_exists);
            }
        }
    }
    for (int n = 1; n <= clean_release; ++n) {
        for (const bool after : {false, true}) {
            INFO("release: crash at call " << n << (after ? " after" : " before"));
            PfRig rig;
            auto dl = rig.dl();
            REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
            rig.world.crash.crash_at = rig.world.crash.calls + n;
            rig.world.crash.after_effect = after;
            try {
                (void)release(rig.env, ReleaseRequest{}, dl);
            } catch (const CrashSim&) {
            }
            rig.world.crash.crash_at = -1;
            (void)recover_at_init(rig.env, dl);
            CHECK_FALSE(rig.world.anchor_exists);
            CHECK(rig.world.tokens.empty());
            CHECK(rig.store.raw.empty());
        }
    }
}

TEST_CASE("nft: an active record the table no longer backs is re-applied from the stored set",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 0), dl).status == "active");
    const auto stored = rig.store.state()->allow;
    rig.world.table = false; // another actor deleted our table
    rig.world.text.clear();

    // a different request must not rewrite the stored allow set
    auto req = rig.request();
    req.allow = make_set({"203.0.113.99"}, {ex("10.9.9.9:22/tcp/in")});
    const auto o = apply_and_verify(rig.env, req, dl);
    CHECK(o.status == "active");
    CHECK(contains(o.notes, "repaired=1"));
    CHECK(contains(o.notes, "allow_set_unchanged_use_quarantine_allow=1"));
    CHECK(rig.world.table);
    CHECK(rig.store.state()->allow == stored);
    CHECK(rig.store.state()->generation == 2);
}

TEST_CASE("quarantine on an active record says when a new ttl_seconds was ignored",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl).status == "active");
    const auto expires = rig.store.state()->ttl_expires;
    REQUIRE(expires == rig.now + 120);

    rig.now += 30;
    const auto retry = apply_and_verify(rig.env, rig.request(kProbeTarget, 600), dl);
    CHECK(retry.status == "active");
    CHECK(contains(retry.notes, "already_active=1"));
    CHECK(contains(retry.notes, "ttl_unchanged_release_then_quarantine=1"));
    CHECK(rig.store.state()->ttl_expires == expires); // a retry never rewrites a contained host's expiry

    // no ttl requested: nothing to say
    const auto quiet = apply_and_verify(rig.env, rig.request(kProbeTarget, 0), dl);
    CHECK_FALSE(contains(quiet.notes, "ttl_unchanged_release_then_quarantine=1"));

    // the repaired branch (the table vanished) says it too
    rig.world.table = false;
    rig.world.text.clear();
    const auto repaired = apply_and_verify(rig.env, rig.request(kProbeTarget, 600), dl);
    CHECK(contains(repaired.notes, "repaired=1"));
    CHECK(contains(repaired.notes, "ttl_unchanged_release_then_quarantine=1"));
}

// ── output rows ─────────────────────────────────────────────────────────────

TEST_CASE("output rows and result kinds", "[agent][firewall_quarantine]") {
    Outcome o;
    o.status = "refused";
    o.reason = "state_not_persisted";
    auto rows = render_rows(o);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "status|refused|state_not_persisted");
    CHECK(rows[1] == "refused|state_not_persisted");
    CHECK(o.rc() == 1);
    CHECK(result_kind(o).kind == ResultKind::Kind::unavailable);

    Outcome busy;
    busy.status = "busy";
    CHECK(render_rows(busy)[0] == "status|busy");
    CHECK(busy.rc() == 1);

    Outcome part;
    part.status = "partial";
    part.notes.push_back("rules_not_disabled=2");
    CHECK(part.rc() == 0);
    CHECK(result_kind(part).kind == ResultKind::Kind::constrained);
    CHECK(result_kind(part).partial);
    CHECK(render_rows(part).back() == "note|rules_not_disabled=2");

    Outcome inactive;
    inactive.status = "inactive";
    CHECK(result_kind(inactive).kind == ResultKind::Kind::ok);
    CHECK_FALSE(result_kind(inactive).partial);
    CHECK(result_kind(inactive).provenance == "firewall:inactive");

    // every emitted row survives the pipe-delimited protocol: no stray separators in values
    NftRig rig;
    auto dl = rig.dl();
    const auto applied = apply_and_verify(rig.env, rig.request(), dl);
    for (const auto& r : render_rows(applied))
        CHECK(r.find('\n') == std::string::npos);
}

TEST_CASE("every argv and ruleset line the core emits is clean", "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    auto req = rig.request();
    req.allow = make_set({"203.0.113.53", "2001:4860:4860::8888"},
                         {ex("10.0.0.5:22/tcp/in"), ex("[2001:db8::]/32:443/out"), ex("172.16.0.0/12/udp")});
    REQUIRE(apply_and_verify(rig.env, req, dl).status == "active");
    for (const auto& a : rig.world.log)
        CHECK(all_tokens_safe(a));
    for (const auto& [path, text] : rig.world.files)
        CHECK(is_safe_ruleset_text(text));

    IptRig ipt;
    auto dl2 = ipt.dl();
    auto req2 = ipt.request();
    req2.allow = req.allow;
    REQUIRE(apply_and_verify(ipt.env, req2, dl2).status == "active");
    for (const auto& a : ipt.world.log)
        CHECK(all_tokens_safe(a));
}
