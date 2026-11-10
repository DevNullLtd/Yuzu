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

// Disable-list entries from bare keys. `sole_carrier` is the flag win_rules_to_disable
// records when a key is listed; the tests that need the real flag build the list from a
// before-snapshot instead.
std::vector<WinListedRule> flagged_keys(std::initializer_list<std::string> keys,
                                        bool sole_carrier) {
    std::vector<WinListedRule> out;
    for (const auto& k : keys)
        out.push_back({k, sole_carrier});
    return out;
}
std::vector<WinListedRule> sole_keys(std::initializer_list<std::string> keys) {
    return flagged_keys(keys, true);
}
std::vector<WinListedRule> shared_keys(std::initializer_list<std::string> keys) {
    return flagged_keys(keys, false);
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
    bool fault = false;       // the KV store cannot ANSWER (BUSY, closed): what the shell reports as unreadable
    StateLoad load() override {
        StateLoad l;
        if (fault) {
            l.kind = StateLoad::Kind::unreadable;
            return l;
        }
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
    /// What a failing delete / list prints. The default is sudo's text; a test swaps in
    /// the loader's or nft's own words.
    std::string delete_failure = "sudo: a password is required";
    std::optional<std::string> list_failure; // set: `nft list table` fails with this text
    bool load_times_out = false; // `nft -f` COMMITS the table, then overruns its budget
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
            if (load_times_out) {
                auto r = done(-1);
                r.timed_out = true; // the commit landed; the tool did not return in time
                return r;
            }
            return done(0);
        }
        if (a[1] == "delete") {
            if (fail_delete)
                return done(1, delete_failure);
            if (!table) // what nft prints for a delete of an absent table
                return done(1, "Error: Could not process rule: No such file or directory\n"
                               "delete table inet yuzu_quarantine\n"
                               "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
            table = false;
            text.clear();
            return done(0);
        }
        if (a[1] == "list") {
            if (list_failure)
                return done(1, *list_failure);
            if (!table) // what nft prints for a list of an absent table
                return done(1, "Error: No such file or directory\n"
                               "list table inet yuzu_quarantine\n"
                               "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
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
            return StagedFile{path, nullptr, "/tmp"};
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
    std::function<StepResult(OsPayload&)> on_remove = [](OsPayload&) { return StepResult::success(); };
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
    StepResult remove(OsPayload& os, Deadline&) override {
        ++removes;
        return on_remove(os);
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

    // nft: request direction carries dport, the reply path carries sport and refuses
    // a bare SYN (a peer must not open a NEW connection from its service port)
    const auto nft = nft_ruleset_text(set);
    CHECK(nft.find("ip saddr 10.0.0.5 tcp dport 22 accept") != nft.npos);  // input
    CHECK(nft.find("ip daddr 10.0.0.5 tcp sport 22 tcp flags & (syn|ack) != syn accept") != nft.npos);  // output reply
    CHECK(nft.find("ip daddr 10.0.0.6 tcp dport 443 accept") != nft.npos); // output
    CHECK(nft.find("ip saddr 10.0.0.6 tcp sport 443 tcp flags & (syn|ack) != syn accept") != nft.npos); // input reply

    // iptables
    const auto plan = iptables_build_plan(set, kIptablesPath, 1, false);
    std::vector<std::string> lines;
    for (const auto& a : plan)
        lines.push_back(join(a));
    CHECK(contains(lines, "/usr/sbin/iptables -A yuzu-fwq-1 -s 10.0.0.5 -p tcp --dport 22 -j ACCEPT"));
    // the reply path is two positive rules (ACK set, or RST set): a bare SYN matches neither
    CHECK(contains(lines, "/usr/sbin/iptables -A yuzu-fwq-1 -d 10.0.0.5 -p tcp --sport 22 --tcp-flags ACK ACK -j ACCEPT"));
    CHECK(contains(lines, "/usr/sbin/iptables -A yuzu-fwq-1 -d 10.0.0.5 -p tcp --sport 22 --tcp-flags RST RST -j ACCEPT"));
    CHECK_FALSE(contains(lines, "/usr/sbin/iptables -A yuzu-fwq-1 -d 10.0.0.5 -p tcp --sport 22 -j ACCEPT"));
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
    s.os.repair_unregistered = true;
    s.repairs = 4;
    s.repaired_at = 1'700'000'900;
    s.last_verify = "verified control_ok probe_blocked";
    const auto text = serialize_state(s);
    const auto back = parse_state(text);
    REQUIRE(back);
    CHECK(back->repairs == 4);
    CHECK(back->repaired_at == 1'700'000'900);
    CHECK(back->os.repair_unregistered);
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
    // a key a newer build wrote is skipped, not fatal (a downgrade must still read the record)
    {
        const auto future = parse_state(text + "mystery=1\n");
        REQUIRE(future);
        CHECK(future->generation == parse_state(text)->generation);
        CHECK(future->allow == parse_state(text)->allow);
    }
    CHECK_FALSE(parse_state(text + "gen=8\n")); // duplicate scalar
    CHECK_FALSE(parse_state(text + "stale_left=1\n"));
    CHECK_FALSE(parse_state(text + "flush_failed=1\n"));
    CHECK_FALSE(parse_state(replace(text, "flush_failed=1", "flush_failed=0")));
    CHECK_FALSE(parse_state(replace(text, "stale_left=2", "stale_left=many")));
    CHECK_FALSE(parse_state(text + "repairs=5\n")); // duplicate keys of this round
    CHECK_FALSE(parse_state(text + "repaired_at=1\n"));
    CHECK_FALSE(parse_state(text + "repair_unreg=1\n"));
    CHECK_FALSE(parse_state(replace(text, "repair_unreg=1", "repair_unreg=yes")));
    CHECK_FALSE(parse_state(replace(text, "repairs=4", "repairs=lots")));
    CHECK_FALSE(parse_state(replace(text, "repaired_at=1700000900", "repaired_at=-1")));
    // a clean record carries none of the residue keys
    QuarantineState clean = s;
    clean.os.rules_not_disabled = 0;
    clean.os.stale_rules_left = 0;
    clean.os.state_flush_failed = false;
    clean.os.repair_unregistered = false;
    clean.repairs = 0;
    clean.repaired_at = 0;
    const auto clean_text = serialize_state(clean);
    CHECK(clean_text.find("stale_left") == std::string::npos);
    CHECK(clean_text.find("flush_failed") == std::string::npos);
    CHECK(clean_text.find("repair") == std::string::npos);
    CHECK_FALSE(has_residue(parse_state(clean_text)->os));
    // a record written before this round (none of its keys) still loads, with none of them set
    CHECK(parse_state(clean_text)->repairs == 0);
    // a Group Policy host is refused, never recorded: a `gpo=1` key (no build writes one) is
    // an unknown key, skipped, and sets no residue
    {
        const auto legacy = parse_state(clean_text + "gpo=1\n");
        REQUIRE(legacy);
        CHECK_FALSE(has_residue(legacy->os));
        CHECK(legacy->os == parse_state(clean_text)->os);
    }
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
    // a key is name|direction|profiles|protocol|action|local ports|remote ports|program|service
    // (none read in this fixture: 0|0|0|-1 and four empty text fields)
    CHECK(off[0].key == "CoreNet-DHCP-Out|0|0|0|-1||||");
    CHECK(off[1].key == "Remote Desktop - User Mode (TCP-In)|0|0|0|-1||||");
    CHECK(off[2].key == "No group at all|0|0|0|-1||||");
    for (const auto& n : off) {
        CHECK_FALSE(n.key.starts_with(kWinRulePrefix));
        CHECK(n.sole_carrier); // each of these names carries its identity alone
    }
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
    const std::vector<WinListedRule> names{{"Plain", true},
                                           {"With|pipe", false},
                                           {"back\\slash", true},
                                           {"multi\nline", false},
                                           {"unicode \xC3\xA9", true}};
    const auto text = serialize_disabled_rules(names);
    CHECK(text.starts_with("v=3\n1|Plain\n0|With|pipe\n"));
    const auto back = parse_disabled_rules(text);
    REQUIRE(back);
    CHECK(*back == names); // keys AND flags survive
    CHECK_FALSE(parse_disabled_rules("no header"));
    CHECK_FALSE(parse_disabled_rules("v=3\n1|bad\\x\n"));
    CHECK(parse_disabled_rules("v=3\n")->empty());
    CHECK(serialize_disabled_rules({}).starts_with("v=3\n"));
    // a list of another version is never read: a v=1 list (name|direction|profiles keys) would
    // re-enable a disabled twin, and a v=2 list (no flag) has no record of which keys were
    // their identity's only carrier. Each is `disabled_list_unreadable`, not an empty list.
    CHECK_FALSE(parse_disabled_rules("v=1\n"));
    CHECK_FALSE(parse_disabled_rules("v=1\nPlain|1|2\n"));
    CHECK_FALSE(parse_disabled_rules("v=2\n"));
    CHECK_FALSE(parse_disabled_rules("v=2\nPlain|1|2|6|1|80|*||\n"));
    // a v=3 line without the flag never parses as eligible: the list is unreadable
    CHECK_FALSE(parse_disabled_rules("v=3\nPlain|1|2|6|1|80|*||\n"));
    CHECK_FALSE(parse_disabled_rules("v=3\n1|ok||||||\nPlain|1|2|6|1|80|*||\n"));
    CHECK_FALSE(parse_disabled_rules("v=3\n2|Plain\n"));
    CHECK_FALSE(parse_disabled_rules("v=3\n1Plain\n"));
    CHECK_FALSE(parse_disabled_rules("v=3\n1\n"));
    CHECK_FALSE(parse_disabled_rules("v=3\n|Plain\n"));
    // the flag is read from the first two characters only: a '1|' inside the key stays key text
    const auto inner = parse_disabled_rules("v=3\n0|1|x\n");
    REQUIRE(inner);
    REQUIRE(inner->size() == 1);
    CHECK((*inner)[0] == WinListedRule{"1|x", false});

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
        const auto m = win_merge_disabled_list({}, sole_keys({"RDP", "SMB"}), false);
        CHECK(m.grew);
        CHECK(m.list == sole_keys({"RDP", "SMB"}));
    }
    SECTION("a later apply with nothing new writes nothing") {
        const auto m = win_merge_disabled_list(sole_keys({"RDP", "SMB"}), sole_keys({"SMB"}), true);
        CHECK_FALSE(m.grew);
        CHECK(m.list == sole_keys({"RDP", "SMB"}));
        // an empty stored list that exists is not rewritten either
        CHECK_FALSE(win_merge_disabled_list({}, {}, true).grew);
    }
    SECTION("a later apply appends only the names it has not seen, in order") {
        const auto m = win_merge_disabled_list(sole_keys({"RDP", "SMB"}),
                                               sole_keys({"SMB", "WinRM", "RDP", "Print"}), true);
        CHECK(m.grew);
        CHECK(m.list == sole_keys({"RDP", "SMB", "WinRM", "Print"}));
    }
    SECTION("a name enabled again during the quarantine is never dropped from the list") {
        const auto m = win_merge_disabled_list(sole_keys({"RDP", "SMB"}), {}, true);
        CHECK(m.list == sole_keys({"RDP", "SMB"}));
    }
    SECTION("a key already stored keeps the flag it was first listed with") {
        // the flag is the state at the moment the key was first listed: a later generation that
        // sees the identity shared (or alone) does not rewrite it, and a rewrite alone is no growth
        auto m = win_merge_disabled_list(sole_keys({"RDP"}), shared_keys({"RDP", "SMB"}), true);
        CHECK(m.grew);
        CHECK(m.list == std::vector<WinListedRule>{{"RDP", true}, {"SMB", false}});
        m = win_merge_disabled_list(shared_keys({"RDP"}), sole_keys({"RDP"}), true);
        CHECK_FALSE(m.grew);
        CHECK(m.list == shared_keys({"RDP"}));
    }
    SECTION("the cap refuses the apply") {
        std::vector<WinListedRule> at_cap;
        for (std::size_t i = 0; i < kMaxDisabledRules; ++i)
            at_cap.push_back({std::format("rule-{}", i), true});
        // nothing new
        CHECK_FALSE(win_merge_disabled_list(at_cap, sole_keys({"rule-3"}), true).over_cap);
        const auto over = win_merge_disabled_list(at_cap, sole_keys({"one-more"}), true);
        CHECK(over.over_cap);
        CHECK(over.grew);
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
    const WinGpoReading none{false, false, false}; // no Group Policy on any profile
    CHECK(win_firewall_switch_verdict(on, none, false).kind == K::ok);
    CHECK(win_firewall_switch_token(win_firewall_switch_verdict(on, none, false)).empty());

    for (std::size_t i = 0; i < on.size(); ++i) {
        INFO("profile " << kWinProfileLabels[i]);
        auto off = on;
        off[i] = false;
        const auto d = win_firewall_switch_verdict(off, none, false);
        CHECK(d.kind == K::disabled);
        CHECK(d.profile == i);
        const auto dt = win_firewall_switch_token(d);
        CHECK(dt == "firewall_disabled:" + std::string{kWinProfileLabels[i]});
        CHECK(is_safe_token(dt));

        auto unreadable = on;
        unreadable[i] = std::nullopt; // S_FALSE or an error: never a guess
        const auto u = win_firewall_switch_verdict(unreadable, none, false);
        CHECK(u.kind == K::unreadable);
        CHECK(u.profile == i);
        const auto ut = win_firewall_switch_token(u);
        CHECK(ut == "firewall_state_unreadable:" + std::string{kWinProfileLabels[i]});
        CHECK(is_safe_token(ut));
    }

    // every shape: the first disabled profile wins, and a definite "off" outranks
    // an unreadable profile that sorts before it
    CHECK(win_firewall_switch_verdict({false, false, false}, none, false).profile == 0);
    const auto mixed = win_firewall_switch_verdict({std::nullopt, true, false}, none, false);
    CHECK(mixed.kind == K::disabled);
    CHECK(mixed.profile == 2);
    const auto two_unreadable = win_firewall_switch_verdict({true, std::nullopt, std::nullopt}, none, false);
    CHECK(two_unreadable.kind == K::unreadable);
    CHECK(two_unreadable.profile == 1);
}

TEST_CASE("windows: the switch verdict settles the status read the same way on every host",
          "[agent][firewall_quarantine]") {
    const WinGpoReading none{false, false, false};
    // on everywhere: nothing settled, the read goes on and the status is untouched
    LegStatus on;
    on.state = OsState::enforcing;
    CHECK_FALSE(win_switch_status(win_firewall_switch_verdict({true, true, true}, none, false), on));
    CHECK(on.state == OsState::enforcing);
    CHECK(on.reapply_helps);
    CHECK(on.reason.empty());
    CHECK(on.notes.empty());

    // switched off: not enforcing, and a re-apply cannot help (it refuses the same way)
    LegStatus off;
    CHECK(win_switch_status(win_firewall_switch_verdict({true, false, true}, none, false), off));
    CHECK(off.state == OsState::not_enforcing);
    CHECK(off.reason == "firewall_disabled");
    CHECK_FALSE(off.reapply_helps);
    CHECK(off.notes == std::vector<std::string>{"firewall_profile=Private"});

    // unreadable: never a guess either way; a note names the profile, nothing is claimed
    LegStatus unread;
    unread.state = OsState::enforcing; // a stale optimistic value must not survive
    CHECK(win_switch_status(win_firewall_switch_verdict({true, true, std::nullopt}, none, false), unread));
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
    CHECK(t.find("ip saddr 198.51.100.7 tcp sport 50051 tcp flags & (syn|ack) != syn accept") != t.npos);
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
    // two writes: `applying`, then `active`. (That the record is written BEFORE the
    // ruleset loads is pinned where a fake peeks at the record at the moment of the
    // load: the pf cases' record_at_load, and the crash-at-every-call tests.)
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
        // no mutation: a no-op quarantine_allow answers what quarantine_status would, so the one
        // runner call is the live read the answer is built from
        CHECK(rig.world.crash.calls == calls + 1);
        CHECK(rig.world.log.back()[1] == "list");
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

/// A `quarantine_allow` that changes nothing, over a record carrying residue, answers
/// what `quarantine_status` would (partial, the residue named) and still mutates
/// nothing: no store write, no new generation, the stored record byte-identical. Both
/// no-op shapes are driven: an add of an exception already present and a removal of
/// one that is not.
template <class Rig>
void check_noop_update_reports_residue(Rig& rig, Deadline& dl, const Endpoint& present,
                                       const Endpoint& absent, std::string_view reason,
                                       std::string_view note) {
    const auto raw = rig.store.raw;
    const auto saves = rig.store.saves;
    const auto generation = rig.store.state()->generation;
    const auto check = [&](const Outcome& o) {
        CHECK(o.status == "partial");
        CHECK(o.reason == reason);
        CHECK(contains(o.notes, note));
        CHECK(contains(o.notes, "exceptions_unchanged=1"));
        CHECK(rig.store.raw == raw);
        CHECK(rig.store.saves == saves);
        CHECK(rig.store.state()->generation == generation);
    };
    check(update(rig.env, true, {present}, dl));
    check(update(rig.env, false, {absent}, dl));
}

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
    SECTION("a no-op quarantine_allow reads the leg: degraded|firewall_disabled, mutating nothing") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto raw = rig.store.raw;
        const auto saves = rig.store.saves;
        const int applies = rig.leg.applies;
        // a profile was switched off after the quarantine: the record is clean, the host is not
        rig.leg.status.state = OsState::not_enforcing;
        rig.leg.status.reason = "firewall_disabled";
        rig.leg.status.reapply_helps = false;
        rig.leg.status.notes.emplace_back("firewall_profile=Public");

        const auto check = [&](const Outcome& o) {
            CHECK(o.status == "degraded");
            CHECK(o.reason == "firewall_disabled");
            CHECK(contains(o.notes, "firewall_profile=Public"));
            CHECK(contains(o.notes, "exceptions_unchanged=1"));
            CHECK(rig.leg.applies == applies);
            CHECK(rig.store.raw == raw);
            CHECK(rig.store.saves == saves);
        };
        check(update(rig.env, false, {ex("10.9.9.9")}, dl)); // a removal of an exception never listed
        check(update(rig.env, true, rig.store.state()->allow.exceptions, dl)); // an add of none new
        // the same answer quarantine_status gives
        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "degraded");
        CHECK(st.reason == "firewall_disabled");
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
        CHECK(contains(again.notes, "firewall_profile=Private")); // the same notes status carries
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

TEST_CASE("recover_at_init: a failed re-apply keeps what the attempt learned, and says when the put-back fails",
          "[agent][firewall_quarantine]") {
    SECTION("a fact the failed attempt set (a pf token) survives in the store and the answer") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        REQUIRE(rig.store.state()->os.pf_token.empty());
        rig.leg.on_apply = [](OsPayload& os) {
            os.pf_token = "3665316113424588829"; // the host holds it; the record is the way to release it
            return StepResult::fail("pf_load_failed");
        };
        rig.leg.status.state = OsState::not_enforcing;

        const auto o = recover_at_init(rig.env, dl);
        CHECK(o.status == "degraded");
        CHECK(o.reason == "reapply_failed:pf_load_failed");
        CHECK_FALSE(contains(o.notes, "state_restore_failed=1"));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->os.pf_token == "3665316113424588829");
        REQUIRE(o.state);
        CHECK(o.state->os.pf_token == "3665316113424588829");
    }
    SECTION("a put-back that cannot be saved is reported and leaves the record in progress") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.leg.on_apply = [](OsPayload&) { return StepResult::fail("firewall_disabled:Domain"); };
        rig.leg.status.state = OsState::not_enforcing;
        // the attempt's own `applying` record saves; the put-back after it does not
        rig.store.fail_save_after = rig.store.saves + 1;

        const auto o = recover_at_init(rig.env, dl);
        CHECK(o.status == "degraded");
        CHECK(o.reason == "reapply_failed:firewall_disabled:Domain");
        CHECK(contains(o.notes, "state_restore_failed=1"));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::applying);
        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "partial");
        CHECK(st.reason == "operation_in_progress");
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
    SECTION("live-leg notes come before residue notes, as in quarantine_status") {
        auto st = *rig.store.state();
        st.os.rules_not_disabled = 4;
        rig.store.save(st);
        rig.leg.status.notes.emplace_back("leg_note=1");
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        const auto s = report_status(rig.env, dl);
        const auto at = [](const Outcome& r, std::string_view n) {
            return std::ranges::find(r.notes, n) - r.notes.begin();
        };
        CHECK(at(o, "leg_note=1") < at(o, "rules_not_disabled=4"));
        CHECK(at(s, "leg_note=1") < at(s, "rules_not_disabled=4"));
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
    SECTION("not enforcing with no reason named falls back to policy_not_blocking") {
        rig.leg.status.state = OsState::not_enforcing;
        rig.leg.status.reapply_helps = false; // a re-apply would not help; reason stays empty
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "degraded");
        CHECK(o.reason == "policy_not_blocking");
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

TEST_CASE("windows: a no-op quarantine_allow over stale-generation residue answers partial, mutating nothing",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    Deadline dl;
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    // the update that produces the residue: it commits, but two old rules will not delete
    rig.leg.on_apply = [](OsPayload& os) {
        os.stale_rules_left = 2;
        auto r = StepResult::success();
        r.partial = true;
        r.notes.emplace_back("stale_rules_left=2");
        return r;
    };
    const auto present = ex("10.0.0.5:22/tcp/in");
    CHECK(update(rig.env, true, {present}, dl).status == "partial");
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->os.stale_rules_left == 2);

    const auto applies = rig.leg.applies;
    const auto removes = rig.leg.removes;
    check_noop_update_reports_residue(rig, dl, present, ex("10.9.9.9"), "stale_rules_left",
                                      "stale_rules_left=2");
    CHECK(rig.leg.applies == applies); // no leg write, no probe-driven converge
    CHECK(rig.leg.removes == removes);

    // and it is the answer quarantine_status gives
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "stale_rules_left");
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
    [[nodiscard]] std::size_t count(std::string_view id) const {
        return static_cast<std::size_t>(std::count_if(
            registered.begin(), registered.end(), [&](const Reg& r) { return r.id == id; }));
    }
    [[nodiscard]] const Reg* find(std::string_view id) const {
        for (const auto& r : registered)
            if (r.id == id)
                return &r;
        return nullptr;
    }
    [[nodiscard]] std::size_t unregistered_count(std::string_view id) const {
        return static_cast<std::size_t>(std::count(unregistered.begin(), unregistered.end(), id));
    }
};

} // namespace

TEST_CASE("triggers: the registrations the core emits are what the engine's own parser accepts",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl);
    REQUIRE(o.status == "active");
    FakeTriggers trig;
    settle_triggers(o, trig, rig.store);

    // a time-limited containment arms BOTH: the time-limit tick and the repair self-check
    REQUIRE(trig.registered.size() == 2);
    CHECK(trig.unregistered.empty());
    REQUIRE(trig.count(kTtlTriggerId) == 1);
    REQUIRE(trig.count(kRepairTriggerId) == 1);
    // a successful registration changes nothing about the result
    CHECK(o.status == "active");
    CHECK_FALSE(contains(o.notes, "ttl_trigger_unregistered=1"));
    CHECK_FALSE(contains(o.notes, "repair_trigger_unregistered=1"));

    // the contract with the trigger engine, proven against the engine's own parser
    const auto& reg = *trig.find(kTtlTriggerId);
    CHECK(reg.id == "firewall.quarantine.ttl");
    CHECK(reg.type == "interval");
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

    // the repair trigger fires `quarantine` with only `repair=1`: the plugin routes that
    // to repair(), and refuses a `repair=1` that also carries a containment parameter
    const auto& rep = *trig.find(kRepairTriggerId);
    CHECK(rep.id == "firewall.quarantine.repair");
    CHECK(rep.type == "interval");
    const auto rcfg = yuzu::agent::parse_trigger_config(rep.id, rep.type, rep.json);
    REQUIRE(rcfg.has_value());
    CHECK(rcfg->id == "firewall.quarantine.repair");
    CHECK(rcfg->type == yuzu::agent::TriggerType::Interval);
    CHECK(rcfg->plugin == "firewall");
    CHECK(rcfg->action == "quarantine");
    CHECK(rcfg->interval_seconds == kRepairPollSeconds);
    CHECK(rcfg->interval_seconds == 60);
    CHECK(rcfg->interval_seconds >= 30);
    REQUIRE(rcfg->parameters.size() == 1);
    CHECK(rcfg->parameters.at("repair") == "1");
    CHECK(rep.json == repair_trigger_config());
}

TEST_CASE("ttl trigger: a failed registration keeps the quarantine and says PARTIAL",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    FakeTriggers trig;
    trig.accept = false; // what the standalone harness (no trigger engine) answers

    auto verified = apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl);
    REQUIRE(verified.status == "active");
    settle_triggers(verified, trig, rig.store);
    CHECK(verified.status == "partial");
    CHECK(contains(verified.notes, "ttl_trigger_unregistered=1"));
    CHECK(contains(verified.notes, "repair_trigger_unregistered=1")); // the self-check is missing too
    CHECK(contains(render_rows(verified), "status|partial|ttl_unregistered"));
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
    settle_triggers(unproven, trig, rig.store);
    CHECK(unproven.status == "partial");
    CHECK(contains(unproven.notes, "ttl_trigger_unregistered=1"));

    // a status that is already worse than active is not improved, only annotated
    Outcome degraded;
    degraded.status = "degraded";
    degraded.reason = "reapply_failed:nft_load_failed";
    degraded.state = rig.store.state();
    settle_triggers(degraded, trig, rig.store);
    CHECK(degraded.status == "degraded");
    CHECK(contains(degraded.notes, "ttl_trigger_unregistered=1"));
}

TEST_CASE("triggers: no ttl registers only the repair check; a completed release unregisters both",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    FakeTriggers trig;

    auto no_ttl = apply_and_verify(rig.env, rig.request(), dl);
    REQUIRE(no_ttl.status == "active");
    settle_triggers(no_ttl, trig, rig.store);
    CHECK(trig.registered.size() == 1); // the repair self-check watches every record
    CHECK(trig.count(kRepairTriggerId) == 1);
    CHECK(trig.count(kTtlTriggerId) == 0); // there is no time limit to enforce
    CHECK(trig.unregistered.empty());
    CHECK(no_ttl.status == "active");

    // a ttl'd quarantine, then released: both triggers go with it
    REQUIRE(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
    auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 90), dl);
    REQUIRE(o.status == "active");
    settle_triggers(o, trig, rig.store);
    CHECK(trig.count(kTtlTriggerId) == 1);
    CHECK(trig.registered.size() == 3);
    auto rel = release(rig.env, ReleaseRequest{}, dl);
    REQUIRE(rel.status == "inactive");
    settle_triggers(rel, trig, rig.store);
    CHECK(trig.unregistered_count(kTtlTriggerId) == 1);
    CHECK(trig.unregistered_count(kRepairTriggerId) == 1);
    CHECK(trig.registered.size() == 3); // not re-registered

    // a refused action leaves the triggers alone
    auto refused_o = refused("op_invalid");
    settle_triggers(refused_o, trig, rig.store);
    CHECK(trig.registered.size() == 3);
    CHECK(trig.unregistered.size() == 2);
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
    settle_triggers(failed, trig, rig.store);
    CHECK(trig.count(kTtlTriggerId) == 1);
    CHECK(trig.count(kRepairTriggerId) == 1);
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
    settle_triggers(late, trig, rig.store);
    CHECK(trig.unregistered_count(kTtlTriggerId) == 1);
    CHECK(trig.unregistered_count(kRepairTriggerId) == 1);
}

TEST_CASE("ttl trigger: a boot-time recovery re-registers it, and retries a failed registration",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    FakeTriggers trig;
    trig.accept = false;
    auto first = apply_and_verify(rig.env, rig.request(kProbeTarget, 600), dl);
    settle_triggers(first, trig, rig.store);
    REQUIRE(first.status == "partial"); // registration failed at quarantine time

    // agent restart: the OS still enforces, the record says active with a ttl
    trig.accept = true;
    auto boot = recover_at_init(rig.env, dl);
    REQUIRE(boot.state);
    CHECK(boot.state->ttl_expires > 0);
    settle_triggers(boot, trig, rig.store);
    REQUIRE(trig.registered.size() == 2);
    CHECK(trig.count(kTtlTriggerId) == 1);
    CHECK(trig.count(kRepairTriggerId) == 1);
    CHECK(boot.status == "active"); // registered this time: nothing partial left to say

    // a reboot with a failed re-apply (degraded) still keeps the ttl bounded
    FakeTriggers again;
    rig.world.table = false;
    rig.world.fail_load = true;
    auto failed = recover_at_init(rig.env, dl);
    REQUIRE(failed.status == "degraded");
    settle_triggers(failed, again, rig.store);
    CHECK(again.count(kTtlTriggerId) == 1);
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
    std::string stage_dir = "/tmp";      // the private staging directory the Stage reports
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
            const auto path = std::format("{}/yuzu-fwq-pf-{}{}", stage_dir, ++next_file, suffix);
            files[path] = std::string{contents};
            return StagedFile{path, nullptr, stage_dir};
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

TEST_CASE("pf: a no-op quarantine_allow after a failed state flush answers partial, mutating nothing",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    // the update that produces the residue: the anchor load commits, both flushes fail
    rig.world.fail_flush_states = 2;
    const auto present = ex("10.0.0.9:22/tcp/in");
    CHECK(update(rig.env, true, {present}, dl).status == "partial");
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->os.state_flush_failed);

    const auto mark = rig.world.log.size();
    check_noop_update_reports_residue(rig, dl, present, ex("10.9.9.9"), "state_flush_failed",
                                      "state_flush_failed=1");
    // the two no-ops read the leg (the live half of the answer) and write nothing: every
    // pfctl call since is a `-s` show
    CHECK(rig.world.log.size() > mark);
    for (auto i = mark; i < rig.world.log.size(); ++i) {
        INFO(join(rig.world.log[i]));
        CHECK(contains(rig.world.log[i], "-s"));
    }

    // and it is the answer quarantine_status gives
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "state_flush_failed");
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

// ═══════════════════════════════════════════════════════════════════════════
// Governance gate 3 (round 1): the correctness floor. Every case below pins the
// behaviour a BLOCKING finding asked for through the same fakes the drivers
// already run on; CH-1..CH-4 are the chaos plan's fake-leg halves.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// A minimal, valid record for a driver test that never runs a real leg.
QuarantineState make_record(Phase phase = Phase::active, BackendKind be = BackendKind::windows) {
    QuarantineState s;
    s.phase = phase;
    s.generation = 1;
    s.applied_at = 1'700'000'000;
    s.backend = be;
    s.allow = make_set();
    s.last_verify = "verified control_ok probe_blocked";
    return s;
}

} // namespace

TEST_CASE("packaged Linux: a non-root agent under no_new_privs is refused, nothing else is",
          "[agent][firewall_quarantine]") {
    // The unit runs as yuzu-agent with NoNewPrivileges=true and no sudoers grant: sudo
    // cannot elevate, so the action is refused BEFORE any record or tool call.
    const auto why = linux_privilege_refusal(false, 1);
    REQUIRE(why);
    CHECK(*why == "privilege_unavailable");
    CHECK_FALSE(linux_privilege_refusal(true, 1));   // root under no_new_privs still runs the tool
    CHECK_FALSE(linux_privilege_refusal(true, 0));
    CHECK_FALSE(linux_privilege_refusal(false, 0));  // sudo can elevate
    CHECK_FALSE(linux_privilege_refusal(false, -1)); // unreadable is not a refusal: sudo will say so
}

TEST_CASE("kv presence: only 0 and 1 are answers; a fault is never 'absent'",
          "[agent][firewall_quarantine]") {
    CHECK(kv_presence(0) == KvPresence::present);
    CHECK(kv_presence(1) == KvPresence::absent);
    for (const int rc : {-1, -2, -3, 2})
        CHECK(kv_presence(rc) == KvPresence::unknown);
}

TEST_CASE("staged path: a space in the data directory is safe; anything outside the directory is not",
          "[agent][firewall_quarantine]") {
    const std::string dir = "/Library/Application Support/Yuzu/firewall-staging";
    CHECK(is_safe_staged_path(dir + "/yuzu-fwq-AbC123.pf", dir));
    CHECK(is_safe_staged_path("/tmp/yuzu-fwq-1.nft", "/tmp"));
    CHECK_FALSE(is_safe_staged_path("/tmp/x.nft", ""));
    CHECK_FALSE(is_safe_staged_path("relative/x.nft", "relative"));
    CHECK_FALSE(is_safe_staged_path("/other/yuzu-fwq-1.pf", dir));
    CHECK_FALSE(is_safe_staged_path(dir + "/../x.pf", dir));
    CHECK_FALSE(is_safe_staged_path(dir + "/sub/x.pf", dir)); // directly under it, one level
    CHECK_FALSE(is_safe_staged_path(dir + "/x y.pf", dir));   // the file name is a plain token
    CHECK_FALSE(is_safe_staged_path(dir + "/x\n.pf", dir));
    CHECK_FALSE(is_safe_staged_path(dir + "/x;.pf", dir));
    CHECK_FALSE(is_safe_staged_path(dir + "/", dir));
    CHECK_FALSE(is_safe_staged_path("/tmp/../etc/x.pf", "/tmp/../etc"));
    CHECK_FALSE(is_safe_staged_path("/tmp//x.pf", "/tmp/")); // a directory with a trailing slash
    // the strict token charset (every OTHER token) is unchanged: a space still fails it
    CHECK_FALSE(is_safe_token(dir + "/yuzu-fwq-1.pf"));
}

TEST_CASE("pf: a staging directory with a space applies; an unusable staged path fails before -E",
          "[agent][firewall_quarantine]") {
    SECTION("the packaged macOS data directory contains a space") {
        PfRig rig;
        rig.world.stage_dir = "/Library/Application Support/Yuzu/firewall-staging";
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "active");
        CHECK(rig.world.anchor_exists);
        bool loaded = false;
        for (const auto& a : rig.world.log)
            if (a.size() == 5 && a[3] == "-f") {
                loaded = true;
                CHECK(a[4].starts_with("/Library/Application Support/Yuzu/firewall-staging/"));
            }
        CHECK(loaded); // the spaced path travelled as ONE argv element
    }
    SECTION("a staged path outside its directory is refused before pfctl -E takes a reference") {
        PfWorld w;
        FakeStore store;
        Probe probe;
        const Stage bad = [](std::string_view, std::string_view,
                             std::string_view) -> std::optional<StagedFile> {
            return StagedFile{"/etc/passwd", nullptr, "/tmp"};
        };
        PfLeg leg(w.runner(), bad, [&]() -> std::optional<std::string> { return w.boot; });
        Deadline dl;
        OsPayload os;
        const auto r = leg.apply(make_set(), 1, 0, os, dl, [](const OsPayload&) { return true; });
        CHECK_FALSE(r.ok);
        CHECK(r.reason == "unsafe_argv");
        CHECK(w.crash.calls == 0); // not even `pfctl -s info`: nothing ran, no reference was taken
        CHECK(w.tokens.empty());
    }
}

TEST_CASE("nft: only nft's own 'table absent' line reads as absent", "[agent][firewall_quarantine]") {
    // nft's own words, for a list and for a delete
    CHECK(nft_output_means_absent("Error: No such file or directory\n"
                                  "list table inet yuzu_quarantine\n^^^^^^^^^^^^^^\n"));
    CHECK(nft_output_means_absent("Error: Could not process rule: No such file or directory\n"
                                  "delete table inet yuzu_quarantine\n^^^^^^^^^^^^^^\n"));
    CHECK(nft_output_means_absent("Error: table 'yuzu_quarantine' does not exist"));
    // text that merely CONTAINS the words: the loader's, sudo's, and a misplaced one
    CHECK_FALSE(nft_output_means_absent(
        "/usr/sbin/nft: error while loading shared libraries: libnftables.so.1: cannot open "
        "shared object file: No such file or directory"));
    CHECK_FALSE(nft_output_means_absent(
        "error while loading shared libraries: libnftables.so.1: cannot open shared object "
        "file: No such file or directory"));
    CHECK_FALSE(nft_output_means_absent("sudo: unable to execute /usr/sbin/nft: No such file or directory"));
    CHECK_FALSE(nft_output_means_absent("sudo: a password is required"));
    CHECK_FALSE(nft_output_means_absent("Error: Operation not permitted"));
    CHECK_FALSE(nft_output_means_absent("  Error: x\nNo such file or directory"));
    CHECK_FALSE(nft_output_means_absent(""));
}

TEST_CASE("CH-1: a release that cannot reach nft never answers inactive or erases the record",
          "[agent][firewall_quarantine]") {
    const std::vector<std::string> broken{
        "sudo: a password is required",
        "/usr/sbin/nft: error while loading shared libraries: libnftables.so.1: cannot open "
        "shared object file: No such file or directory",
        "sudo: unable to execute /usr/sbin/nft: No such file or directory"};
    for (const auto& text : broken) {
        INFO(text);
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");

        rig.world.fail_delete = true;
        rig.world.delete_failure = text;
        const auto o = release(rig.env, ReleaseRequest{}, dl);
        CHECK(o.status == "partial");
        CHECK(o.reason == "release_failed:nft_delete_failed");
        CHECK(rig.world.table); // still in force
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::releasing); // the record is kept

        // the host's own words: status says so, never inactive
        rig.world.list_failure = text;
        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "partial");
        CHECK(st.reason == "release_incomplete");
        // a retried quarantine reports the stuck release instead of wedging or re-applying
        const auto again = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(again.status == "refused");
        CHECK(again.reason == "release_in_progress");

        // privilege restored: the release completes and the host can be contained again
        rig.world.fail_delete = false;
        rig.world.list_failure.reset();
        CHECK(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
        CHECK_FALSE(rig.world.table);
        CHECK_FALSE(rig.store.state());
        CHECK(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    }
    // with NO record, an unreadable list is unreadable -- not inactive; nft's own line is inactive
    NftRig bare;
    auto dl = bare.dl();
    bare.world.list_failure = broken[1];
    const auto unread = report_status(bare.env, dl);
    CHECK(unread.status == "degraded");
    CHECK(unread.reason == "os_unreadable");
    bare.world.list_failure.reset();
    CHECK(report_status(bare.env, dl).status == "inactive");
}

TEST_CASE("the stateless reply path refuses a bare SYN; the ruleset line charset admits only that literal",
          "[agent][firewall_quarantine]") {
    const auto set = make_set({"203.0.113.53"}, {ex("10.0.0.5:22/tcp/in"), ex("172.16.0.9:123/udp/out")});
    const auto nft = nft_ruleset_text(set);
    const std::string flags{kNftReplyFlagsMatch};
    // the control channel (an outbound TCP request): the peer's reply is not a bare SYN
    CHECK(nft.find("ip saddr 198.51.100.7 tcp sport 50051 " + flags + " accept") != nft.npos);
    // an inbound TCP exception: OUR reply (SYN-ACK, data) leaves, a bare SYN from us does not
    CHECK(nft.find("ip daddr 10.0.0.5 tcp sport 22 " + flags + " accept") != nft.npos);
    // the REQUEST lines are unrestricted (the peer / we start the connection there)
    CHECK(nft.find("ip saddr 10.0.0.5 tcp dport 22 accept") != nft.npos);
    CHECK(nft.find("ip daddr 198.51.100.7 tcp dport 50051 accept") != nft.npos);
    // UDP replies stay stateless: no flags clause on any udp line
    for (const auto line : detail::split(nft, '\n'))
        if (line.find("udp") != line.npos)
            CHECK(line.find("flags") == line.npos);
    CHECK(is_safe_ruleset_text(nft));

    // the charset: the literal passes, anything shaped like it does not
    CHECK(is_safe_ruleset_line("ip saddr 1.2.3.4 tcp sport 22 " + flags + " accept"));
    CHECK_FALSE(is_safe_ruleset_line("ip saddr 1.2.3.4 tcp sport 22 tcp flags & (syn|ack) == syn accept"));
    CHECK_FALSE(is_safe_ruleset_line("ip saddr 1.2.3.4 tcp flags & syn accept"));
    CHECK_FALSE(is_safe_ruleset_line("a | b"));
    CHECK_FALSE(is_safe_ruleset_line("a & b"));
    CHECK_FALSE(is_safe_ruleset_line("a != b"));
    CHECK_FALSE(is_safe_ruleset_line("accept # drop"));

    // iptables: `!` cannot be an argv token, so the same set is two positive rules
    const auto plan = iptables_build_plan(set, kIptablesPath, 1, false);
    std::vector<std::string> lines;
    for (const auto& a : plan) {
        lines.push_back(join(a));
        CHECK(all_tokens_safe(a));
    }
    const std::string pre = "/usr/sbin/iptables -A yuzu-fwq-1 ";
    CHECK(contains(lines, pre + "-s 198.51.100.7 -p tcp --sport 50051 --tcp-flags ACK ACK -j ACCEPT"));
    CHECK(contains(lines, pre + "-s 198.51.100.7 -p tcp --sport 50051 --tcp-flags RST RST -j ACCEPT"));
    CHECK_FALSE(contains(lines, pre + "-s 198.51.100.7 -p tcp --sport 50051 -j ACCEPT"));
    CHECK(contains(lines, pre + "-s 10.0.0.5 -p tcp --dport 22 -j ACCEPT")); // the request: open
    CHECK(contains(lines, pre + "-d 10.0.0.5 -p tcp --sport 22 --tcp-flags ACK ACK -j ACCEPT"));
    // UDP: one plain rule each way, no flags
    CHECK(contains(lines, pre + "-s 172.16.0.9 -p udp --sport 123 -j ACCEPT"));
    for (const auto& l : lines)
        if (l.find("-p udp") != std::string::npos)
            CHECK(l.find("--tcp-flags") == std::string::npos);
}

TEST_CASE("windows: the DHCP allowances are scoped to the DHCP client service",
          "[agent][firewall_quarantine]") {
    const auto specs = win_rule_specs(make_set({"203.0.113.53"}, {ex("10.0.0.5:22/tcp/in")}), 1);
    int dhcp = 0;
    for (const auto& s : specs) {
        if (s.protocol == 17 && s.local_ports == "68" && s.remote_ports == "67") {
            ++dhcp;
            CHECK(s.service_name == "dhcp");
        } else {
            CHECK(s.service_name.empty()); // no other allowance is service-scoped
        }
    }
    CHECK(dhcp == 2); // out and in
}

TEST_CASE("windows: a stock rule is told apart by name, direction and profile", "[agent][firewall_quarantine]") {
    // Windows ships rules that share a NAME and differ by profile or direction, one on
    // and one off: the release must never switch on the one that was off.
    const std::vector<WinRuleInfo> rules{
        {"File and Printer Sharing (SMB-In)", "File and Printer Sharing", true, 1, 2},  // private: on
        {"File and Printer Sharing (SMB-In)", "File and Printer Sharing", false, 1, 4}, // public: OFF
        {"WinRM (HTTP-In)", "Windows Remote Management", true, 1, 4},
        {"WinRM (HTTP-In)", "Windows Remote Management", true, 1, 2},
    };
    const auto off = win_rules_to_disable(rules);
    REQUIRE(off.size() == 3);
    CHECK(off[0].key == "File and Printer Sharing (SMB-In)|1|2|0|-1||||");
    CHECK(off[1].key == "WinRM (HTTP-In)|1|4|0|-1||||");
    CHECK(off[2].key == "WinRM (HTTP-In)|1|2|0|-1||||");
    // the profile mask is part of the identity, so each of these is its identity's only carrier
    for (const auto& n : off)
        CHECK(n.sole_carrier);
    // the public twin was off: its key is not in the list, so the release leaves it off
    CHECK(std::none_of(off.begin(), off.end(),
                       [&](const WinListedRule& n) { return n.key == win_rule_key(rules[1]); }));
    CHECK(win_rule_key(rules[1]) != win_rule_key(rules[0]));
    CHECK(win_rule_key(WinRuleInfo{.name = "x", .direction = 1, .profiles = 7}) !=
          win_rule_key(WinRuleInfo{.name = "x", .direction = 2, .profiles = 7})); // direction too
    // the cross-generation merge works on the same keys
    const auto merged = win_merge_disabled_list({off[0]}, off, true);
    CHECK(merged.list.size() == 3);
    CHECK(merged.grew);
    // the round trip through the stored list keeps a '|'-bearing key intact
    const auto parsed = parse_disabled_rules(serialize_disabled_rules(off));
    REQUIRE(parsed);
    CHECK(*parsed == off);
}

TEST_CASE("windows: a disabled twin differing only by protocol, ports, program, service or action is never re-enabled",
          "[agent][firewall_quarantine]") {
    // Same name, direction and profiles; the twin is OFF and differs by exactly one property.
    // Before the key carried every property, the enabled rule's key matched the twin's and
    // the release switched the twin on.
    WinRuleInfo on{.name = "Remote Assistance (TCP-In)", .group = "Remote Assistance", .enabled = true,
                   .direction = 1, .profiles = 7, .protocol = 6, .action = 1,
                   .local_ports = "3389", .remote_ports = "*", .application = "C:\\Windows\\a.exe",
                   .service = "TermService"};
    const auto differ = [&](auto mutate) {
        auto twin = on;
        twin.enabled = false;
        mutate(twin);
        return twin;
    };
    const std::vector<WinRuleInfo> twins{
        differ([](WinRuleInfo& r) { r.protocol = 17; }),
        differ([](WinRuleInfo& r) { r.action = 0; }),
        differ([](WinRuleInfo& r) { r.local_ports = "3390"; }),
        differ([](WinRuleInfo& r) { r.remote_ports = "443"; }),
        differ([](WinRuleInfo& r) { r.application = "C:\\Windows\\b.exe"; }),
        differ([](WinRuleInfo& r) { r.service = "Other"; }),
    };
    std::vector<WinRuleInfo> rules{on};
    rules.insert(rules.end(), twins.begin(), twins.end());

    // only the enabled rule is listed, and no twin's key is in the list the release matches on
    const auto off = win_rules_to_disable(rules);
    REQUIRE(off.size() == 1);
    CHECK(off[0].key == win_rule_key(on));
    // the six off twins share its name, direction and profiles: not its identity's only carrier
    CHECK_FALSE(off[0].sole_carrier);
    for (const auto& t : twins) {
        INFO(win_rule_key(t));
        CHECK(win_rule_key(t) != win_rule_key(on));
        CHECK(std::none_of(off.begin(), off.end(),
                           [&](const WinListedRule& n) { return n.key == win_rule_key(t); }));
    }
    // all the twins differ from each other too
    std::set<std::string> keys;
    for (const auto& r : rules)
        keys.insert(win_rule_key(r));
    CHECK(keys.size() == rules.size());

    // an unreadable property is the same default on both sides, so a rule still matches itself
    WinRuleInfo unread{.name = "x", .enabled = true};
    CHECK(win_rule_key(unread) == win_rule_key(WinRuleInfo{.name = "x", .enabled = false}));

    // every field survives the stored list
    const auto parsed = parse_disabled_rules(serialize_disabled_rules(off));
    REQUIRE(parsed);
    CHECK(*parsed == off);
}

TEST_CASE("windows: a GPO-locked rule is a note on a completed release; a leftover is not",
          "[agent][firewall_quarantine]") {
    WinReleaseTally t;
    CHECK_FALSE(win_release_decision(t).incomplete);

    t.not_reenabled = 2; // a rule a GPO will not let us switch back on is the GPO's
    auto d = win_release_decision(t);
    CHECK_FALSE(d.incomplete);
    REQUIRE(d.notes.size() == 1);
    CHECK(d.notes[0] == "rules_not_reenabled=2");

    // everything that leaves OUR block, rules, a default action or a stale image stays incomplete
    WinReleaseTally u;
    u.policy_restore_failed = 1;
    CHECK(win_release_decision(u).incomplete);
    WinReleaseTally v;
    v.our_rules_left = true;
    CHECK(win_release_decision(v).incomplete);
    WinReleaseTally w;
    w.reenable_unread = true;
    CHECK(win_release_decision(w).incomplete);
    WinReleaseTally x;
    x.images_not_deleted = true; // a surviving image would be reused and its release restore an old policy
    d = win_release_decision(x);
    CHECK(d.incomplete);
    CHECK(contains(d.notes, "images_not_deleted=1"));
}

TEST_CASE("windows release over the driver: a GPO-locked rule completes; a stuck image keeps the record releasing",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    Deadline dl;
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");

    rig.leg.on_remove = [](OsPayload&) {
        auto r = StepResult::success();
        r.notes.emplace_back("rules_not_reenabled=2");
        return r;
    };
    const auto done_o = release(rig.env, ReleaseRequest{}, dl);
    CHECK(done_o.status == "inactive");
    CHECK(contains(done_o.notes, "rules_not_reenabled=2"));
    CHECK_FALSE(rig.store.state()); // erased: the next quarantine is not wedged behind release_in_progress

    // a restore image that will not delete: the release is incomplete, the record stays
    ScriptRig stuck;
    REQUIRE(apply_and_verify(stuck.env, stuck.request(), dl).status == "active");
    stuck.leg.on_remove = [](OsPayload&) {
        auto r = StepResult::fail("release_incomplete");
        r.notes.emplace_back("images_not_deleted=1");
        return r;
    };
    const auto o = release(stuck.env, ReleaseRequest{}, dl);
    CHECK(o.status == "partial");
    CHECK(o.reason == "release_failed:release_incomplete");
    CHECK(contains(o.notes, "images_not_deleted=1"));
    REQUIRE(stuck.store.state());
    CHECK(stuck.store.state()->phase == Phase::releasing);
    CHECK(apply_and_verify(stuck.env, stuck.request(), dl).reason == "release_in_progress");
    stuck.leg.on_remove = [](OsPayload&) { return StepResult::success(); };
    CHECK(release(stuck.env, ReleaseRequest{}, dl).status == "inactive");
}

namespace {
WinRuleInfo stock_rule(std::string name, bool enabled, std::string program = "C:\\Windows\\a.exe") {
    return WinRuleInfo{.name = std::move(name), .group = "Stock", .enabled = enabled, .direction = 1,
                       .profiles = 7, .protocol = 6, .action = 1, .local_ports = "3389",
                       .remote_ports = "*", .application = std::move(program), .service = "svc"};
}
} // namespace

TEST_CASE("windows release: the identity a stored key was built from is recoverable from the key",
          "[agent][firewall_quarantine]") {
    auto r = stock_rule("Remote Desktop (TCP-In)", true);
    CHECK(win_key_identity(win_rule_key(r)) == win_rule_identity(r));
    CHECK(win_rule_identity(r) == "Remote Desktop (TCP-In)|1|7");
    // a name with a bar in it does not move the split, and an unreadable property (empty) does not either
    auto bar = stock_rule("a|b|c", true, "");
    bar.service.clear();
    CHECK(win_key_identity(win_rule_key(bar)) == win_rule_identity(bar));
    // the identity ignores every edited property, and nothing else
    auto edited = r;
    edited.application = "C:\\other.exe";
    edited.local_ports = "1";
    edited.action = 0;
    CHECK(win_rule_key(edited) != win_rule_key(r));
    CHECK(win_rule_identity(edited) == win_rule_identity(r));
    edited.profiles = 1;
    CHECK(win_rule_identity(edited) != win_rule_identity(r));
    // text that is not a key is returned whole, so it never equals a rule's identity
    CHECK(win_key_identity("not|a|key") == "not|a|key");
    CHECK(win_key_identity("").empty());
}

TEST_CASE("windows release: an exact key match comes back on, and nothing else does",
          "[agent][firewall_quarantine]") {
    const auto a = stock_rule("Rule A", false);
    const auto b = stock_rule("Rule B", false, "C:\\b.exe");
    auto twin = stock_rule("Rule A", false); // off before the quarantine, differs by a port
    twin.local_ports = "3390";
    const auto already_off = stock_rule("Rule C", false);
    const std::vector<WinRuleInfo> rules{a, b, twin, already_off};

    const auto plan = win_release_plan(sole_keys({win_rule_key(a), win_rule_key(b)}), rules);
    CHECK(plan.reenable == std::vector<std::size_t>{0, 1}); // the twin and Rule C stay off
    CHECK(plan.by_identity == 0);
    CHECK(plan.unmatched == 0);
    CHECK(plan.unmatched_keys.empty());

    // a listed key duplicated by hand counts once; the rules of ours are never candidates
    auto ours = stock_rule("YuzuFirewall_Quarantine_1", false);
    ours.group = std::string{kWinGroup};
    const auto dup = win_release_plan(
        sole_keys({win_rule_key(a), win_rule_key(a), win_rule_key(ours)}), {a, ours});
    CHECK(dup.reenable == std::vector<std::size_t>{0});
    CHECK(dup.unmatched == 1); // the listed key of ours matches no candidate and no identity
}

TEST_CASE("windows release: a retried release finds the rules a first attempt already switched on",
          "[agent][firewall_quarantine]") {
    const auto a = stock_rule("Rule A", true); // back on since the first attempt
    const auto b = stock_rule("Rule B", false, "C:\\b.exe");
    const auto plan = win_release_plan(sole_keys({win_rule_key(a), win_rule_key(b)}), {a, b});
    CHECK(plan.reenable == std::vector<std::size_t>{1});
    CHECK(plan.unmatched == 0); // a listed rule that is on again is accounted for, not unmatched
}

TEST_CASE("windows release: a retry after the identity fallback finds the edited rule already on",
          "[agent][firewall_quarantine]") {
    const auto before = stock_rule("Rule A", true, "C:\\old.exe");
    const auto listed = win_rule_key(before);
    auto edited = before; // the program changed between the disable and the release
    edited.enabled = false;
    edited.application = "C:\\new.exe";

    // first attempt: the fallback switches the edited rule back on, a guess it reports
    auto plan = win_release_plan(sole_keys({listed}), {edited});
    CHECK(plan.reenable == std::vector<std::size_t>{0});
    CHECK(plan.by_identity == 1);

    // the first attempt was left incomplete and the record kept the same list: the rule is on
    // now, so the retry has nothing to switch and nothing it cannot account for
    edited.enabled = true;
    plan = win_release_plan(sole_keys({listed}), {edited});
    CHECK(plan.reenable.empty());
    CHECK(plan.by_identity == 0);
    CHECK(plan.accounted_enabled == 1); // counted, so the reply still says the key was not found
    CHECK(plan.unmatched == 0);
    CHECK(plan.unmatched_keys.empty());

    // two enabled rules carry the identity: cannot be told from a deletion, so it is reported
    auto other = edited;
    other.application = "C:\\third.exe";
    plan = win_release_plan(sole_keys({listed}), {edited, other});
    CHECK(plan.reenable.empty());
    CHECK(plan.unmatched == 1);

    // two listed keys of one identity, one enabled carrier left: one of the two original rules
    // is gone, so the carrier accounts for one key and the other is reported (not both counted)
    auto gone = before;
    gone.application = "C:\\gone.exe";
    plan = win_release_plan(sole_keys({listed, win_rule_key(gone)}), {edited});
    CHECK(plan.reenable.empty());
    CHECK(plan.by_identity == 0);
    CHECK(plan.accounted_enabled == 1);
    CHECK(plan.unmatched == 1);
    CHECK(plan.unmatched_keys == std::vector<std::string>{win_rule_key(gone)});

    // an untouched twin that an exact key accounts for is still a second carrier of the
    // identity: the edited rule cannot be told from a deletion beside it, so it is reported
    // (a retry reads the same as the first attempt, and nothing is switched on for it)
    const auto twin = stock_rule("Rule A", true, "C:\\twin.exe");
    plan = win_release_plan(sole_keys({listed, win_rule_key(twin)}), {edited, twin});
    CHECK(plan.reenable.empty());
    CHECK(plan.by_identity == 0);
    CHECK(plan.accounted_enabled == 0);
    CHECK(plan.unmatched == 1);

    // an enabled and a disabled rule of the identity: two carriers, so the disabled one is
    // NOT guessed to be ours (it may have been off before the quarantine)
    auto off = edited;
    off.enabled = false;
    off.application = "C:\\fourth.exe";
    plan = win_release_plan(sole_keys({listed}), {edited, off});
    CHECK(plan.reenable.empty());
    CHECK(plan.by_identity == 0);
    CHECK(plan.unmatched == 1);
}

TEST_CASE("windows release: an edited rule falls back to its identity only when exactly one rule in total carries it",
          "[agent][firewall_quarantine]") {
    const auto before = stock_rule("Rule A", true, "C:\\old.exe");
    const auto listed = win_rule_key(before);
    auto edited = before; // the program changed between the disable and the release
    edited.enabled = false;
    edited.application = "C:\\new.exe";

    // program changed -> the fallback switches it back on, and says it guessed
    auto plan = win_release_plan(sole_keys({listed}), {edited});
    CHECK(plan.reenable == std::vector<std::size_t>{0});
    CHECK(plan.by_identity == 1);
    CHECK(plan.unmatched == 0);

    // an enabled rule with the same identity is a second carrier: the disabled one may have
    // been off before the quarantine, so neither is touched
    auto enabled_twin = edited;
    enabled_twin.enabled = true;
    plan = win_release_plan(sole_keys({listed}), {enabled_twin, edited});
    CHECK(plan.reenable.empty());
    CHECK(plan.by_identity == 0);
    CHECK(plan.unmatched == 1);

    // two disabled candidates: no way to tell which was ours, so neither is touched
    auto other = edited;
    other.application = "C:\\third.exe";
    plan = win_release_plan(sole_keys({listed}), {edited, other});
    CHECK(plan.reenable.empty());
    CHECK(plan.by_identity == 0);
    CHECK(plan.unmatched == 1);
    REQUIRE(plan.unmatched_keys.size() == 1);
    CHECK(plan.unmatched_keys[0] == listed);

    // no rule with that identity at all (deleted, or renamed): unmatched, nothing switched on
    plan = win_release_plan(sole_keys({listed}), {stock_rule("Unrelated", false)});
    CHECK(plan.reenable.empty());
    CHECK(plan.unmatched == 1);

    // an untouched twin that an exact match has claimed still counts as a carrier: two
    // same-named rules were disabled, one was edited, the other is untouched. The twin comes
    // back by its key; the edited one cannot be told from a deletion and stays off, reported
    const auto second = stock_rule("Rule A", true, "C:\\second.exe");
    plan = win_release_plan(sole_keys({listed, win_rule_key(second)}),
                            {edited, [&] { auto r = second; r.enabled = false; return r; }()});
    CHECK(plan.reenable == std::vector<std::size_t>{1});
    CHECK(plan.by_identity == 0);
    CHECK(plan.unmatched == 1);

    // two keys, one candidate: the rule is switched on once and the other key is unmatched
    auto sibling = before;
    sibling.application = "C:\\sibling.exe";
    plan = win_release_plan(sole_keys({listed, win_rule_key(sibling)}), {edited});
    CHECK(plan.reenable == std::vector<std::size_t>{0});
    CHECK(plan.by_identity == 1);
    CHECK(plan.unmatched == 1);
}

TEST_CASE("windows release: the twin protection still holds beside the fallback",
          "[agent][firewall_quarantine]") {
    // A rule that was OFF before the quarantine (never listed) is not switched on because an
    // enabled twin of it was listed and is still present: the exact match accounts for the key,
    // so the fallback never runs.
    const auto on = stock_rule("Remote Assistance (TCP-In)", false);
    auto off_before = on;
    off_before.local_ports = "3390";
    auto enabled_before = on;
    enabled_before.enabled = true;
    const auto plan = win_release_plan(sole_keys({win_rule_key(enabled_before)}), {on, off_before});
    CHECK(plan.reenable == std::vector<std::size_t>{0});
    CHECK(plan.by_identity == 0);
    CHECK(plan.unmatched == 0);
}

TEST_CASE("windows release: the fallback never switches on a rule that was off before the quarantine",
          "[agent][firewall_quarantine]") {
    // A listed rule A (port 3389) was on and was disabled. Another rule B of the same name,
    // direction and profile (port 81) was already OFF before the quarantine and is not listed.
    // The list is built from the before-snapshot, as the apply builds it, so A's key is
    // flagged as sharing its identity with B.
    const auto a = stock_rule("Admin rule", true);
    auto b = a;
    b.local_ports = "81";
    b.enabled = false;
    const auto list = win_rules_to_disable({a, b});
    REQUIRE(list.size() == 1);
    CHECK_FALSE(list[0].sole_carrier);
    auto edited = a; // someone edits A's port during the quarantine
    edited.local_ports = "8080";

    SECTION("A is edited and switched back on by hand: B is not guessed to be A") {
        edited.enabled = true;
        const auto plan = win_release_plan(list, {edited, b});
        CHECK(plan.reenable.empty()); // B stays off: it was off before
        CHECK(plan.by_identity == 0);
        CHECK(plan.accounted_enabled == 0);
        CHECK(plan.unmatched == 1);
    }
    SECTION("A is edited, then a later apply disables it again and lists its new key") {
        // generation 2 reads the ruleset as it is then: the edited rule is on, B is off
        auto on_again = edited;
        on_again.enabled = true;
        const auto merged =
            win_merge_disabled_list(list, win_rules_to_disable({on_again, b}), true);
        REQUIRE(merged.list.size() == 2);
        CHECK_FALSE(merged.list[1].sole_carrier); // B still shares the identity
        edited.enabled = false;
        const auto plan = win_release_plan(merged.list, {edited, b});
        CHECK(plan.reenable == std::vector<std::size_t>{0}); // the edited rule, by its exact key
        CHECK(plan.by_identity == 0);                        // and B is not switched on beside it
        CHECK(plan.unmatched == 1);
    }
}

TEST_CASE("windows release: a rule edited out of an identity it shared at disable never switches on its sibling",
          "[agent][firewall_quarantine]") {
    // The case that fell through the release-time-only fallback: A (on, listed) and B (off before
    // the quarantine, different port and action) share name, direction and profiles. During the
    // quarantine A's rename, direction or profile edit moves it out of that identity, leaving B
    // the only carrier of A's old one. B must not be taken for A.
    const auto a = stock_rule("Admin rule", true);
    auto b = a;
    b.local_ports = "81";
    b.action = 0;
    b.enabled = false;
    const auto list = win_rules_to_disable({a, b});
    REQUIRE(list.size() == 1);
    CHECK_FALSE(list[0].sole_carrier);
    // through the stored form, as the release reads it
    const auto stored = parse_disabled_rules(serialize_disabled_rules(list));
    REQUIRE(stored);
    CHECK(*stored == list);

    const auto check_unmatched = [&](const WinRuleInfo& moved) {
        auto off = moved;
        off.enabled = false; // the quarantine's disable still holds
        const auto plan = win_release_plan(*stored, {off, b});
        CHECK(plan.reenable.empty()); // B stays off
        CHECK(plan.by_identity == 0);
        CHECK(plan.accounted_enabled == 0);
        CHECK(plan.unmatched == 1);
        REQUIRE(plan.unmatched_keys.size() == 1);
        CHECK(plan.unmatched_keys[0] == win_rule_key(a));
        // the same read with the moved rule switched on by hand: still nothing for B
        auto on = moved;
        on.enabled = true;
        const auto again = win_release_plan(*stored, {on, b});
        CHECK(again.reenable.empty());
        CHECK(again.by_identity == 0);
        CHECK(again.unmatched == 1);
    };
    SECTION("renamed") {
        auto moved = a;
        moved.name = "Admin rule (renamed)";
        check_unmatched(moved);
    }
    SECTION("profile mask edited") {
        auto moved = a;
        moved.profiles = 2;
        check_unmatched(moved);
    }
    SECTION("direction edited") {
        auto moved = a;
        moved.direction = 2;
        check_unmatched(moved);
    }
    SECTION("port edited beside B: two carriers now, and not flagged to begin with") {
        auto moved = a;
        moved.local_ports = "8080";
        moved.enabled = false;
        const auto plan = win_release_plan(*stored, {moved, b});
        CHECK(plan.reenable.empty());
        CHECK(plan.by_identity == 0);
        CHECK(plan.unmatched == 1);
    }
}

TEST_CASE("windows release: a key flagged sole-carrier at disable is still found by identity after an edit",
          "[agent][firewall_quarantine]") {
    const auto a = stock_rule("Admin rule", true);
    const auto unrelated = stock_rule("Unrelated", false);
    const auto list = win_rules_to_disable({a, unrelated});
    REQUIRE(list.size() == 1);
    CHECK(list[0].sole_carrier);
    const auto stored = parse_disabled_rules(serialize_disabled_rules(list));
    REQUIRE(stored);

    // a sole carrier edited (port): still re-enabled, and the guess is reported
    auto edited = a;
    edited.enabled = false;
    edited.local_ports = "8080";
    auto plan = win_release_plan(*stored, {edited, unrelated});
    CHECK(plan.reenable == std::vector<std::size_t>{0});
    CHECK(plan.by_identity == 1);
    CHECK(plan.unmatched == 0);

    // renamed out of its identity: nothing carries it now, so it is unmatched, never guessed
    auto renamed = edited;
    renamed.name = "Admin rule (renamed)";
    plan = win_release_plan(*stored, {renamed, unrelated});
    CHECK(plan.reenable.empty());
    CHECK(plan.by_identity == 0);
    CHECK(plan.unmatched == 1);

    // a rule of that identity that appeared during the quarantine beside the original
    // (two carriers at release) is not guessed either
    auto created = edited;
    created.application = "C:\\created.exe";
    plan = win_release_plan(*stored, {edited, created});
    CHECK(plan.reenable.empty());
    CHECK(plan.unmatched == 1);
}

TEST_CASE("windows release: a sole carrier that left its identity beside one rule that entered it is the disclosed residual",
          "[agent][firewall_quarantine]") {
    // A was its identity's only carrier when listed and LEFT it during the quarantine (here
    // deleted; the rename swap below is the other shape); a rule C of the same name, direction
    // and profiles entered it meanwhile (created, or renamed or re-profiled into it) and is off.
    // C reads as an edit of A and is switched on.
    const auto a = stock_rule("Admin rule", true);
    const auto list = win_rules_to_disable({a});
    REQUIRE(list.size() == 1);
    CHECK(list[0].sole_carrier);
    auto c = a;
    c.enabled = false;
    c.local_ports = "9999";
    c.application = "C:\\c.exe";
    auto plan = win_release_plan(list, {c});
    CHECK(plan.reenable == std::vector<std::size_t>{0});
    CHECK(plan.by_identity == 1); // reported, so the reply says it was a guess
    // and accounted for when C is on
    c.enabled = true;
    plan = win_release_plan(list, {c});
    CHECK(plan.reenable.empty());
    CHECK(plan.accounted_enabled == 1);
    CHECK(plan.unmatched == 0);

    // The same residual by a rename swap, with nothing deleted: A is renamed out of its identity
    // while B, off before the quarantine under another name (so not listed), is renamed into it.
    // B is the one carrier left, reads as an edit of A, and is switched on although it was off
    // before the quarantine.
    {
        const auto admin = stock_rule("Admin rule", true);
        auto other = admin;
        other.name = "Other rule";
        other.local_ports = "81";
        other.enabled = false;
        const auto swap_list = win_rules_to_disable({admin, other});
        REQUIRE(swap_list.size() == 1);
        CHECK(swap_list[0].sole_carrier);
        auto admin_out = admin;
        admin_out.name = "Admin rule (renamed)";
        admin_out.enabled = false; // the quarantine's disable still holds
        auto other_in = other;
        other_in.name = "Admin rule";
        const auto swapped = win_release_plan(swap_list, {admin_out, other_in});
        CHECK(swapped.reenable == std::vector<std::size_t>{1}); // B, off before the quarantine
        CHECK(swapped.by_identity == 1);
        CHECK(swapped.unmatched == 0);
    }
}

TEST_CASE("windows release: a key that was not flagged sole-carrier never falls back to its identity",
          "[agent][firewall_quarantine]") {
    // the flag is the only door to the fallback: an unflagged key whose identity has exactly one
    // switched-off carrier at release is unmatched, and nothing is switched on
    const auto before = stock_rule("Rule A", true, "C:\\old.exe");
    auto carrier = before;
    carrier.enabled = false;
    carrier.application = "C:\\new.exe";
    auto plan = win_release_plan(shared_keys({win_rule_key(before)}), {carrier});
    CHECK(plan.reenable.empty());
    CHECK(plan.by_identity == 0);
    CHECK(plan.accounted_enabled == 0);
    CHECK(plan.unmatched == 1);
    CHECK(plan.unmatched_keys == std::vector<std::string>{win_rule_key(before)});
    // already on: not accounted for either (the fallback never ran)
    carrier.enabled = true;
    plan = win_release_plan(shared_keys({win_rule_key(before)}), {carrier});
    CHECK(plan.accounted_enabled == 0);
    CHECK(plan.unmatched == 1);
    // the exact match does not need the flag
    auto exact = before;
    exact.enabled = false;
    plan = win_release_plan(shared_keys({win_rule_key(before)}), {exact});
    CHECK(plan.reenable == std::vector<std::size_t>{0});
    CHECK(plan.unmatched == 0);
}

TEST_CASE("windows: the sole-carrier flag counts every non-ours rule of the identity, on or off",
          "[agent][firewall_quarantine]") {
    const auto a = stock_rule("Rule A", true);
    SECTION("alone") {
        const auto off = win_rules_to_disable({a});
        REQUIRE(off.size() == 1);
        CHECK(off[0].sole_carrier);
    }
    SECTION("a disabled sibling is a second carrier") {
        auto b = a;
        b.enabled = false;
        b.local_ports = "81";
        const auto off = win_rules_to_disable({a, b});
        REQUIRE(off.size() == 1); // only the enabled rule is listed
        CHECK_FALSE(off[0].sole_carrier);
    }
    SECTION("two enabled siblings are both listed, neither alone") {
        auto b = a;
        b.local_ports = "81";
        const auto off = win_rules_to_disable({a, b});
        REQUIRE(off.size() == 2);
        CHECK_FALSE(off[0].sole_carrier);
        CHECK_FALSE(off[1].sole_carrier);
    }
    SECTION("exact twins share a key and neither is alone") {
        const auto off = win_rules_to_disable({a, a});
        REQUIRE(off.size() == 2);
        CHECK(off[0] == off[1]);
        CHECK_FALSE(off[0].sole_carrier);
    }
    SECTION("a rule of another identity is not a carrier") {
        auto other_profile = a;
        other_profile.profiles = 2;
        auto other_direction = a;
        other_direction.direction = 2;
        auto other_name = a;
        other_name.name = "Rule B";
        const auto off = win_rules_to_disable({a, other_profile, other_direction, other_name});
        REQUIRE(off.size() == 4);
        for (const auto& n : off)
            CHECK(n.sole_carrier);
    }
    SECTION("a rule of ours is not a carrier") {
        auto ours = a;
        ours.enabled = false;
        ours.group = std::string{kWinGroup};
        const auto off = win_rules_to_disable({a, ours});
        REQUIRE(off.size() == 1);
        CHECK(off[0].sole_carrier);
    }
}

TEST_CASE("windows release: unmatched is a note on a completed, partial release; the fallback is only a note",
          "[agent][firewall_quarantine]") {
    WinReleaseTally t;
    t.reenabled_by_identity = 1;
    auto d = win_release_decision(t);
    CHECK_FALSE(d.incomplete); // a guess that was taken completes the release
    CHECK_FALSE(d.partial);    // and is reported, not a reason to call it partial
    REQUIRE(d.notes.size() == 1);
    CHECK(d.notes[0] == "rules_reenabled_by_identity=1");

    t.unmatched = 2;
    d = win_release_decision(t);
    CHECK_FALSE(d.incomplete); // must never be incomplete: no retry can match it, the record would wedge
    CHECK(d.partial);
    CHECK(contains(d.notes, "rules_unmatched=2"));
    CHECK(contains(d.notes, "rules_reenabled_by_identity=1"));

    // a listed rule whose sole same-identity rule is already on is an informational note,
    // never partial and never incomplete
    WinReleaseTally accounted;
    accounted.accounted_enabled = 2;
    d = win_release_decision(accounted);
    CHECK_FALSE(d.incomplete);
    CHECK_FALSE(d.partial);
    REQUIRE(d.notes.size() == 1);
    CHECK(d.notes[0] == "rules_accounted_enabled=2");

    WinReleaseTally clean;
    CHECK_FALSE(win_release_decision(clean).partial);
}

TEST_CASE("windows release over the driver: an unmatched rule completes the release as partial and drops the record",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    Deadline dl;
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    FakeTriggers trig;

    rig.leg.on_remove = [](OsPayload&) {
        auto r = StepResult::success();
        r.partial = true;
        r.notes.emplace_back("rules_unmatched=1");
        return r;
    };
    auto o = release(rig.env, ReleaseRequest{}, dl);
    CHECK(o.status == "partial");
    CHECK(o.reason == "rules_unmatched");
    CHECK(contains(o.notes, "rules_unmatched=1"));
    CHECK(o.rc() == 0);
    CHECK_FALSE(rig.store.state()); // erased: the next quarantine is not wedged behind release_in_progress
    CHECK_FALSE(o.state);
    // the record is gone like an `inactive` release's, so are its triggers
    settle_triggers(o, trig, rig.store);
    CHECK(trig.unregistered_count(kRepairTriggerId) == 1);
    CHECK(trig.unregistered_count(kTtlTriggerId) == 1);
}

TEST_CASE("rollback over the driver: what the removal learned rides the rolled_back outcome",
          "[agent][firewall_quarantine]") {
    Deadline dl;
    SECTION("a removal that completed with a partial answer is a rolled_back that says so") {
        ScriptRig rig;
        rig.probe.control_up = false; // the apply fails its own control check
        rig.leg.on_remove = [](OsPayload&) {
            auto r = StepResult::success();
            r.partial = true;
            r.notes.emplace_back("rules_unmatched=1");
            r.notes.emplace_back("rules_reenabled_by_identity=1");
            return r;
        };
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back"); // the token is unchanged: the result kind keys on it
        CHECK(o.reason == "control_unreachable");
        CHECK(contains(o.notes, "rules_unmatched=1"));
        CHECK(contains(o.notes, "rules_reenabled_by_identity=1"));
        CHECK(contains(o.notes, "rollback_partial=1"));
        CHECK_FALSE(contains(o.notes, "rollback_incomplete=1"));
        CHECK_FALSE(rig.store.state()); // the removal completed, so the record is erased
        CHECK_FALSE(o.state);
    }
    SECTION("a removal that failed keeps its own notes and detail, and the record") {
        ScriptRig rig;
        rig.probe.control_up = false;
        rig.leg.on_remove = [](OsPayload&) {
            auto r = StepResult::fail("release_incomplete", "policy store busy");
            r.notes.emplace_back("images_not_deleted=1");
            return r;
        };
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(contains(o.notes, "rollback_incomplete=1"));
        CHECK(contains(o.notes, "images_not_deleted=1"));
        CHECK(contains(o.notes, "rollback_detail=policy store busy"));
        CHECK_FALSE(contains(o.notes, "rollback_partial=1"));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::releasing);
    }
    SECTION("a clean removal adds no rollback note") {
        ScriptRig rig;
        rig.probe.control_up = false;
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK_FALSE(contains(o.notes, "rollback_partial=1"));
        CHECK_FALSE(contains(o.notes, "rollback_incomplete=1"));
        CHECK(std::none_of(o.notes.begin(), o.notes.end(),
                           [](const std::string& n) { return n.starts_with("rollback_detail="); }));
    }
}

TEST_CASE("triggers: teardown follows the record, not the reason of a stateless partial",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    Deadline dl;
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");

    // a failed release with nothing stored (the record erased by an earlier release) has no
    // quarantine left to bound: both triggers go, whatever the reason string says
    const auto record = rig.store.raw;
    rig.store.raw.clear();
    rig.leg.on_remove = [](OsPayload&) { return StepResult::fail("os_busy"); };
    auto gone = release(rig.env, ReleaseRequest{}, dl);
    REQUIRE(gone.status == "partial");
    REQUIRE(gone.reason.starts_with("release_failed"));
    REQUIRE_FALSE(gone.state);
    FakeTriggers trig;
    settle_triggers(gone, trig, rig.store);
    CHECK(trig.unregistered_count(kRepairTriggerId) == 1);
    CHECK(trig.unregistered_count(kTtlTriggerId) == 1);
    CHECK(trig.registered.empty());

    // the same stateless partial over a store that cannot ANSWER is not "gone": the safeguard
    // stays registered (a bookkeeping failure never lifts containment)
    rig.store.fault = true;
    Outcome unknown;
    unknown.status = "partial";
    unknown.reason = "release_failed:os_busy";
    FakeTriggers kept;
    settle_triggers(unknown, kept, rig.store);
    CHECK(kept.unregistered.empty());
    CHECK(kept.registered.empty());

    // and so is one over a record that still exists but was not attached to the outcome
    rig.store.fault = false;
    rig.store.raw = record;
    REQUIRE(rig.store.state());
    FakeTriggers present;
    settle_triggers(unknown, present, rig.store);
    CHECK(present.unregistered.empty());
}

TEST_CASE("windows release: a default action that will not restore names its profile",
          "[agent][firewall_quarantine]") {
    // the leg's note for the release_incomplete cause that used to name nothing
    for (const auto label : kWinProfileLabels)
        CHECK(is_safe_token(label)); // the value the leg appends to `policy_restore_failed=`
    ScriptRig rig;
    Deadline dl;
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.leg.on_remove = [](OsPayload&) {
        auto r = StepResult::fail("release_incomplete");
        r.notes.emplace_back("policy_restore_failed=Private");
        return r;
    };
    const auto o = release(rig.env, ReleaseRequest{}, dl);
    CHECK(o.status == "partial");
    CHECK(o.reason == "release_failed:release_incomplete");
    CHECK(contains(o.notes, "policy_restore_failed=Private"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::releasing);
}

TEST_CASE("iptables: our jump must be FIRST in every built-in chain; a Docker re-insert is repaired",
          "[agent][firewall_quarantine]") {
    const auto l = parse_iptables_listing("-P INPUT ACCEPT\n-N yuzu-fwq-1\n-A INPUT -j yuzu-fwq-1\n"
                                          "-A OUTPUT -j yuzu-fwq-1\n"
                                          "-A FORWARD -i docker0 -j DOCKER-USER\n"
                                          "-A FORWARD -j yuzu-fwq-1-f\n");
    CHECK(l.first_is_ours(0));
    CHECK(l.first_is_ours(1));
    CHECK_FALSE(l.first_is_ours(2)); // present, but behind Docker's
    CHECK(l.first_target[2] == "DOCKER-USER");
    // a first rule with no jump at all is not ours either
    CHECK_FALSE(parse_iptables_listing("-A INPUT -m state --state ESTABLISHED\n-A INPUT -j yuzu-fwq-1\n")
                    .first_is_ours(0));

    IptRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    CHECK(report_status(rig.env, dl).status == "active");

    auto& fwd = rig.world.fam[std::string{kIptablesPath}].builtin["FORWARD"];
    fwd.insert(fwd.begin(), "DOCKER-USER"); // dockerd restarts and re-inserts its jump at position 1
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "degraded");
    CHECK(st.reason == "policy_not_blocking");

    const auto fixed = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(fixed.status == "active");
    CHECK(contains(fixed.notes, "repaired=1"));
    CHECK(rig.jumps(kIptablesPath, "FORWARD").front() == "yuzu-fwq-2-f");
    CHECK(report_status(rig.env, dl).status == "active");
}

TEST_CASE("Exec: a call that ran and timed out is call_timed_out; one refused for the deadline never ran",
          "[agent][firewall_quarantine]") {
    int ran = 0;
    const Runner run = [&](const Argv&, std::chrono::milliseconds) {
        ++ran;
        ToolResult r;
        r.ran = true;
        r.timed_out = true;
        return r;
    };
    Deadline dl;
    detail::Exec ex1(run, dl);
    CHECK_FALSE(ex1.call({"/usr/sbin/nft", "list"}));
    CHECK(ex1.reason() == "call_timed_out"); // it RAN: the OS state is unknown
    CHECK(ran == 1);

    FakeClock clock;
    Deadline spent(std::chrono::milliseconds{1}, clock.fn());
    clock.advance(5ms);
    detail::Exec ex2(run, spent);
    CHECK_FALSE(ex2.call({"/usr/sbin/nft", "list"}));
    CHECK(ex2.reason() == "deadline_exceeded"); // before the call: nothing ran
    CHECK(ran == 1);

    detail::Exec ex3(run, dl);
    CHECK_FALSE(ex3.call({"/usr/sbin/nft", "list;"}));
    CHECK(ex3.reason() == "unsafe_argv");
    CHECK(ran == 1);
}

TEST_CASE("ambiguous commit: a tool that committed and then overran its budget is never read as a clean failure",
          "[agent][firewall_quarantine]") {
    SECTION("an update keeps its candidate record, applying, and the retry converges") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto exc = ex("10.0.0.5:22/tcp/in");
        rig.world.load_times_out = true; // `nft -f` commits the new set, then overruns
        const auto o = update(rig.env, true, {exc}, dl);
        CHECK(o.status == "update_failed");
        CHECK(o.reason == "commit_unknown");
        CHECK(o.rc() == 1);
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::applying); // NOT the previous record put back
        CHECK(rig.store.state()->generation == 2);
        CHECK(rig.store.state()->allow.exceptions.size() == 1); // the set the kernel holds
        CHECK(rig.world.text.find("dport 22") != std::string::npos);
        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "partial");
        CHECK(st.reason == "operation_in_progress");

        // the retry (the same request a retried quarantine carries) converges the full set
        rig.world.load_times_out = false;
        auto req = rig.request();
        req.allow = make_set({"203.0.113.53"}, {exc});
        const auto fixed = apply_and_verify(rig.env, req, dl);
        CHECK(fixed.status == "active");
        CHECK(contains(fixed.notes, "incomplete_apply_converged=1"));
        CHECK(rig.store.state()->phase == Phase::active);
        CHECK(rig.store.state()->generation == 3);
    }
    SECTION("an initial apply is rolled back (the removal is idempotent)") {
        NftRig rig;
        rig.world.load_times_out = true;
        auto dl = rig.dl();
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(o.reason == "apply_failed:call_timed_out");
        CHECK_FALSE(rig.world.table); // the committed table was taken out again
        CHECK_FALSE(rig.store.state());
    }
    SECTION("a boot re-apply says commit_unknown") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.world.table = false;
        rig.world.load_times_out = true;
        const auto o = recover_at_init(rig.env, dl);
        CHECK(o.status == "degraded");
        CHECK(o.reason == "reapply_failed:commit_unknown");
    }
}

TEST_CASE("CH-2: a proof that failed never reads active again -- recovery, status, a no-op update, the ttl tick",
          "[agent][firewall_quarantine]") {
    auto token = [](std::string v) {
        QuarantineState s;
        s.last_verify = std::move(v);
        return std::string{detail::active_token(s)};
    };
    CHECK(token("verified control_ok probe_blocked") == "active");
    CHECK(token("unproven control_ok probe_unproven") == "active_unproven");
    CHECK(token("control_unreachable control_fail probe_blocked") == "active_unproven");
    CHECK(token("probe_still_reachable control_ok probe_reachable") == "active_unproven");
    CHECK(token("probe_unreachable_before_apply control_ok probe_unproven") == "active_unproven");
    CHECK(token("") == "active_unproven");
    // and every text the core itself writes: only `verified` earns `active`
    for (const auto outcome : {VerifyOutcome::verified, VerifyOutcome::unproven,
                               VerifyOutcome::control_unreachable, VerifyOutcome::probe_still_reachable,
                               VerifyOutcome::probe_unreachable_before_apply}) {
        detail::VerifyResult v;
        v.outcome = outcome;
        INFO(detail::verify_text(v));
        CHECK(token(detail::verify_text(v)) ==
              (outcome == VerifyOutcome::verified ? "active" : "active_unproven"));
    }

    const auto read_everywhere = [](NftRig& rig, Deadline& dl) {
        CHECK(report_status(rig.env, dl).status == "active_unproven");
        const auto noop = update(rig.env, true, {}, dl);
        CHECK(noop.status == "active_unproven");
        CHECK(contains(noop.notes, "exceptions_unchanged=1"));
        ReleaseRequest due;
        due.if_ttl_expired = true;
        const auto tick = release(rig.env, due, dl); // the 30 s tick reads no leg at all
        CHECK(tick.status == "active_unproven");
        CHECK(contains(tick.notes, "ttl_not_expired=1"));
    };

    SECTION("the probe target is still reachable after a boot re-apply") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 3600), dl).status == "active");
        rig.world.table = false;                       // the reboot
        rig.probe.blocked = [] { return false; };      // and the target answers anyway
        const auto o = recover_at_init(rig.env, dl);
        CHECK(o.status == "active_unproven");
        CHECK(rig.store.state()->last_verify.starts_with("probe_still_reachable"));
        read_everywhere(rig, dl);
    }
    SECTION("the control set did not answer at boot") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 3600), dl).status == "active");
        rig.world.table = false;
        rig.probe.control_up = false;
        const auto o = recover_at_init(rig.env, dl);
        CHECK(o.status == "active_unproven");
        CHECK(rig.store.state()->last_verify == "control_unreachable control_fail probe_blocked");
        read_everywhere(rig, dl);
    }
}

TEST_CASE("the ttl tick answers from the record: residue, an operation in progress, never active over a gap",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    Deadline dl;
    ReleaseRequest due;
    due.if_ttl_expired = true;
    auto rec = make_record();
    rec.ttl_expires = rig.now + 3600;

    SECTION("residue") {
        rec.os.stale_rules_left = 2;
        REQUIRE(rig.store.save(rec));
        const auto o = release(rig.env, due, dl);
        CHECK(o.status == "partial");
        CHECK(o.reason == "stale_rules_left");
        CHECK(contains(o.notes, "stale_rules_left=2"));
        CHECK(contains(o.notes, "ttl_not_expired=1"));
    }
    SECTION("applying and releasing") {
        for (const auto phase : {Phase::applying, Phase::releasing}) {
            rec.phase = phase;
            REQUIRE(rig.store.save(rec));
            const auto o = release(rig.env, due, dl);
            CHECK(o.status == "partial");
            CHECK(o.reason == "operation_in_progress");
        }
    }
    SECTION("a failed proof") {
        rec.last_verify = "probe_still_reachable control_ok probe_reachable";
        REQUIRE(rig.store.save(rec));
        CHECK(release(rig.env, due, dl).status == "active_unproven");
    }
    CHECK(rig.leg.removes == 0);
}

TEST_CASE("a TTL release defers to a legacy containment that appeared underneath",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    auto rec = make_record();
    rec.ttl_expires = rig.now - 1; // the limit has lapsed
    REQUIRE(rig.store.save(rec));
    ReleaseRequest due;
    due.if_ttl_expired = true;
    Deadline dl;

    rig.leg.refuse = "legacy_quarantine_active"; // quarantine.quarantine ran since
    const auto o = release(rig.env, due, dl);
    CHECK(o.status == "partial");
    CHECK(o.reason == "legacy_quarantine_active");
    CHECK(contains(o.notes, "ttl_deferred_legacy=1"));
    CHECK(rig.leg.removes == 0); // nothing restored underneath the legacy containment
    CHECK(rig.store.state()->phase == Phase::active); // the next tick retries

    // any OTHER preflight answer must not stop a lapsed limit from ending
    rig.leg.refuse = "firewall_disabled:Public";
    const auto lifted = release(rig.env, due, dl);
    CHECK(lifted.status == "inactive");
    CHECK(rig.leg.removes == 1);

    // and a manual release is the dispatch gate's business, not this tick's
    REQUIRE(rig.store.save(rec));
    rig.leg.refuse = "legacy_quarantine_active";
    CHECK(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
}

TEST_CASE("recover_at_init releases a record whose time limit already lapsed instead of re-applying it",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl).status == "active");
    rig.world.table = false; // the agent was down across a reboot
    rig.now += 600;          // ... and past the expiry
    const auto calls = rig.world.crash.calls;
    const auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "inactive");
    CHECK_FALSE(rig.world.table);
    CHECK_FALSE(rig.store.state());
    CHECK(std::none_of(rig.world.log.begin() + calls, rig.world.log.end(),
                       [](const Argv& a) { return a.size() > 1 && a[1] == "-f"; })); // never re-applied
}

TEST_CASE("recover_at_init: an initial apply that never completed is not promoted without a control channel",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    // A crash after the load and before the verification: `applying`, no proof recorded.
    auto rec = make_record(Phase::applying, BackendKind::nft);
    rec.last_verify.clear();
    rec.probe_target = kProbeTarget;
    REQUIRE(rig.store.save(rec));
    rig.probe.control_up = false; // wrong control set / server unreachable at boot

    const auto o = recover_at_init(rig.env, dl);
    CHECK(o.status == "partial");
    CHECK(o.reason == "operation_in_progress");
    CHECK(contains(o.notes, "control_unreachable_unproven=1"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::applying); // NOT promoted to active
    CHECK(report_status(rig.env, dl).reason == "operation_in_progress");
    CHECK(rig.world.table); // still contained: rolling back at boot stays excluded

    // the next retried quarantine converges and verifies it
    rig.probe.control_up = true;
    const auto retry = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(retry.status == "active");
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->last_verify.starts_with("verified"));

    // with the control set answering at boot the same kind of record IS promoted
    NftRig ok;
    auto dl2 = ok.dl();
    auto rec2 = make_record(Phase::applying, BackendKind::nft);
    rec2.last_verify.clear();
    REQUIRE(ok.store.save(rec2));
    CHECK(recover_at_init(ok.env, dl2).status == "active_unproven"); // no probe target: unproven, not failed
    CHECK(ok.store.state()->phase == Phase::active);
}

TEST_CASE("a probe target an operator exception already admits is refused before any mutation",
          "[agent][firewall_quarantine]") {
    const auto t = parse_probe_target(kProbeTarget).value();
    const auto covered = [&](const char* e) {
        return exception_covers_probe_target(make_set({"203.0.113.53"}, {ex(e)}), t);
    };
    CHECK(covered("192.0.2.80:443/tcp/out"));
    CHECK(covered("192.0.2.0/24:443/out"));      // a prefix, both protocols
    CHECK(covered("192.0.2.80/out"));            // any port
    CHECK_FALSE(covered("192.0.2.0/24:80/out")); // another port
    CHECK_FALSE(covered("192.0.2.80:443/udp/out"));
    CHECK_FALSE(covered("192.0.2.80:443/in"));   // inbound admits no outbound connect
    CHECK_FALSE(covered("198.51.100.0/24/out")); // another network
    CHECK_FALSE(covered("[2001:db8::]/32/out")); // another family

    SECTION("quarantine") {
        NftRig rig;
        auto dl = rig.dl();
        auto req = rig.request();
        req.allow = make_set({"203.0.113.53"}, {ex("192.0.2.0/24:443/out")});
        const auto o = apply_and_verify(rig.env, req, dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "probe_target_covered_by_exception");
        CHECK(rig.world.crash.calls == 0);
        CHECK(rig.store.raw.empty());
    }
    SECTION("quarantine_allow add") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto raw = rig.store.raw;
        const auto calls = rig.world.crash.calls;
        const auto o = update(rig.env, true, {ex("192.0.2.0/24:443/out")}, dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "probe_target_covered_by_exception");
        CHECK(rig.world.crash.calls == calls); // no mutation, no revert, no second flush
        CHECK(rig.store.raw == raw);
        // an exception that does not cover it still applies
        CHECK(update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl).status == "active");
    }
}

TEST_CASE("retrying quarantine over an incomplete apply takes the request's time limit and probe target",
          "[agent][firewall_quarantine]") {
    SECTION("both are applied, the new probe target is proven reachable first") {
        NftRig rig;
        auto dl = rig.dl();
        auto rec = make_record(Phase::applying, BackendKind::nft); // a throw / failed save before the proof
        rec.last_verify.clear();
        REQUIRE(rig.store.save(rec));
        const auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl);
        CHECK(o.status == "active");
        CHECK(contains(o.notes, "ttl_from_retry=1"));
        CHECK(contains(o.notes, "probe_from_retry=1"));
        CHECK(contains(o.notes, "incomplete_apply_converged=1"));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->ttl_expires == rig.now + 120);
        CHECK(rig.store.state()->probe_target == kProbeTarget);
        CHECK(*o.verify == "verify|control=ok|probe=blocked");
    }
    SECTION("a dead new probe target refuses before anything is touched") {
        NftRig rig;
        auto dl = rig.dl();
        auto rec = make_record(Phase::applying, BackendKind::nft);
        rec.last_verify.clear();
        REQUIRE(rig.store.save(rec));
        const auto raw = rig.store.raw;
        rig.probe.blocked = [] { return true; }; // the target does not answer before the apply
        const auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 0), dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "probe_unreachable_before_apply");
        CHECK(rig.world.crash.calls == 0);
        CHECK(rig.store.raw == raw);
    }
    SECTION("an ACTIVE record's expiry is still never rewritten by a retry") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl).status == "active");
        const auto expiry = rig.store.state()->ttl_expires;
        rig.now += 30;
        const auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 3600), dl);
        CHECK(contains(o.notes, "ttl_unchanged_release_then_quarantine=1"));
        CHECK(rig.store.state()->ttl_expires == expiry);
    }
}

TEST_CASE("CH-3: a failed ttl registration is residue on the record until a settle succeeds",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    FakeTriggers trig;
    trig.accept = false; // the trigger table is full
    auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 600), dl);
    REQUIRE(o.status == "active");
    settle_triggers(o, trig, rig.store);
    CHECK(o.status == "partial");
    CHECK(o.reason == "ttl_unregistered");
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->os.ttl_unregistered);
    // it survives the record's text form
    const auto round = parse_state(serialize_state(*rig.store.state()));
    REQUIRE(round);
    CHECK(round->os.ttl_unregistered);

    // every later read says so instead of `active` over a limit nothing enforces
    auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "ttl_unregistered");
    CHECK(contains(st.notes, "ttl_unregistered=1"));
    const auto noop = update(rig.env, true, {}, dl);
    CHECK(noop.status == "partial");
    CHECK(noop.reason == "ttl_unregistered");
    ReleaseRequest due;
    due.if_ttl_expired = true;
    CHECK(release(rig.env, due, dl).reason == "ttl_unregistered");

    // a registration that finally succeeds clears it
    trig.accept = true;
    settle_triggers(st, trig, rig.store);
    CHECK(st.status == "active");
    CHECK(st.reason.empty());
    CHECK_FALSE(contains(st.notes, "ttl_unregistered=1"));
    CHECK_FALSE(rig.store.state()->os.ttl_unregistered);
    CHECK(report_status(rig.env, dl).status == "active");

    // a no-op poll never re-registers (it logs a replace and a fire every 30 s otherwise)
    FakeTriggers quiet;
    auto tick = release(rig.env, due, dl);
    settle_triggers(tick, quiet, rig.store);
    CHECK(quiet.registered.empty());
}

TEST_CASE("CH-3: a throw out of an action is degraded|exception, never refused, and still arms the ttl",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    // the process dies (a throw) right after `nft -f` committed: the `applying` record exists
    rig.world.crash.crash_at = 2;
    rig.world.crash.after_effect = true;
    CHECK_THROWS_AS(apply_and_verify(rig.env, rig.request(kProbeTarget, 600), dl), CrashSim);
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::applying);

    auto o = exception_outcome(rig.store.load());
    CHECK(o.status == "degraded");
    CHECK(o.reason == "exception");
    CHECK(o.rc() == 1);
    REQUIRE(o.state);
    CHECK(o.state->phase == Phase::applying);
    FakeTriggers trig;
    settle_triggers(o, trig, rig.store); // the triggers of a time-limited applying record are registered
    CHECK(trig.count(kTtlTriggerId) == 1);
    CHECK(trig.count(kRepairTriggerId) == 1);

    const auto rows = render_rows(o);
    CHECK(rows.front() == "status|degraded|exception");
    CHECK(std::none_of(rows.begin(), rows.end(),
                       [](const std::string& r) { return r.starts_with("refused|"); }));
    const auto kind = result_kind(o);
    CHECK(kind.provenance == "firewall:degraded"); // consumers key on this: refused means nothing changed
    CHECK(kind.kind == ResultKind::Kind::constrained);
    CHECK(kind.partial);

    // no record: nothing to attach, and nothing registered
    StateLoad none;
    auto bare = exception_outcome(none);
    CHECK_FALSE(bare.state);
    FakeTriggers quiet;
    FakeStore store;
    settle_triggers(bare, quiet, store);
    CHECK(quiet.registered.empty());
}

TEST_CASE("CH-4: a store fault is never read as an absent record -- nothing is started, kept, re-applied or unregistered",
          "[agent][firewall_quarantine]") {
    PfRig rig; // the record carries the pf enable token
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 600), dl).status == "active");
    const auto raw = rig.store.raw;
    const auto token = rig.token();
    REQUIRE_FALSE(token.empty());
    const auto calls = rig.world.crash.calls;

    rig.store.fault = true; // SQLITE_BUSY / a closed handle: exists() cannot answer

    // quarantine: refused, NOT a fresh generation-1 record over the stored one
    const auto q = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(q.status == "refused");
    CHECK(q.reason == "state_unreadable");
    // the ttl tick: degraded, and the trigger is kept (never unregistered over a fault)
    ReleaseRequest due;
    due.if_ttl_expired = true;
    auto tick = release(rig.env, due, dl);
    CHECK(tick.status == "degraded");
    CHECK(tick.reason == "state_unreadable");
    FakeTriggers trig;
    settle_triggers(tick, trig, rig.store);
    CHECK(trig.unregistered.empty());
    CHECK(trig.registered.empty());
    // start recovery and an update: nothing re-applied, nothing changed
    const auto boot = recover_at_init(rig.env, dl);
    CHECK(boot.status == "degraded");
    CHECK(boot.reason == "state_unreadable");
    CHECK(update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl).reason == "state_unreadable");
    CHECK(rig.world.crash.calls == calls); // not one tool call

    // the fault clears: the record, the token and the containment are exactly as they were
    rig.store.fault = false;
    CHECK(rig.store.raw == raw);
    CHECK(rig.token() == token);
    CHECK(rig.world.enforcing());
    CHECK(report_status(rig.env, dl).status == "active");
}

TEST_CASE("a record with a key a newer build wrote still releases the pf token",
          "[agent][firewall_quarantine]") {
    PfRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    REQUIRE_FALSE(rig.token().empty());
    rig.store.raw += "future_key=1\n"; // the agent was downgraded across this record
    const auto o = release(rig.env, ReleaseRequest{}, dl);
    CHECK(o.status == "inactive");
    CHECK(rig.world.tokens.empty()); // a strict parser would have released with an empty payload and leaked it
    CHECK_FALSE(rig.world.pf_on);
}

// ── result truth: the branches a mutant could flip without a test noticing ───

TEST_CASE("update_failed|revert_failed: the failed generation is in force and the record says so",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    int loads = 0;
    rig.world.on_call = [&](const Argv& a) {
        if (a.size() > 1 && a[1] == "-f" && ++loads == 2) // the update commits; its REVERT fails
            rig.world.fail_load = true;
    };
    rig.probe.blocked = [] { return false; }; // the new generation's verification fails
    const auto o = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
    CHECK(o.status == "update_failed");
    CHECK(o.reason.starts_with("revert_failed:"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::applying); // boot recovery retries
    CHECK(rig.store.state()->allow.exceptions.size() == 1); // the generation that IS in force
    CHECK(rig.world.text.find("dport 22") != std::string::npos);
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "operation_in_progress");
}

TEST_CASE("a store write that fails at the end of an operation is partial, never a clean result",
          "[agent][firewall_quarantine]") {
    SECTION("release: the OS is lifted but the record could not be erased") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.store.fail_erase = true;
        const auto o = release(rig.env, ReleaseRequest{}, dl);
        CHECK(o.status == "partial");
        CHECK(o.reason == "state_not_erased");
        CHECK_FALSE(rig.world.table); // lifting is never blocked by the record
        CHECK(rig.store.state()->phase == Phase::releasing);
    }
    SECTION("apply: contained, but the `active` record could not be written") {
        NftRig rig;
        auto dl = rig.dl();
        rig.store.fail_save_after = 1; // the applying record lands, the final one does not
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "partial");
        CHECK(contains(o.notes, "state_not_persisted=1"));
        CHECK(rig.world.table);
        CHECK(rig.store.state()->phase == Phase::applying); // boot recovery re-applies and verifies
    }
    SECTION("update: the new generation is in force but its record could not be written") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.store.fail_save_after = rig.store.saves + 1; // the candidate lands, the final does not
        const auto o = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(o.status == "partial");
        CHECK(contains(o.notes, "state_not_persisted=1"));
        CHECK(rig.store.state()->phase == Phase::applying);
    }
}

TEST_CASE("pf: the enable token is never lost across a failed update or a failed rollback",
          "[agent][firewall_quarantine]") {
    SECTION("a failed update keeps the token the record already held") {
        PfRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto held = rig.token();
        REQUIRE_FALSE(held.empty());
        rig.world.external_disable(); // pf off behind our back: the token is dead
        rig.world.fail_load = true;   // the repair takes a fresh reference, then the load fails
        const auto o = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(o.status == "update_failed");
        CHECK(rig.token() == held);          // the record still names what it held
        CHECK(rig.world.tokens.empty());     // the fresh reference was given back
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::active);
    }
    SECTION("a rollback whose anchor flush fails keeps the token on the `releasing` record") {
        PfRig rig;
        auto dl = rig.dl();
        rig.world.fail_flush_anchor = true; // the removal cannot empty the anchor
        rig.probe.control_up = false;       // the apply fails its own control check
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(contains(o.notes, "rollback_incomplete=1"));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::releasing);
        CHECK_FALSE(rig.token().empty()); // the record is the only way to release it
        rig.world.fail_flush_anchor = false;
        CHECK(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
        CHECK(rig.world.tokens.empty());
    }
}

TEST_CASE("a reply that names residue carries its reason; repair notes appear only when the repair worked",
          "[agent][firewall_quarantine]") {
    SECTION("a partial apply answers partial|<residue>, in the reply and not only later") {
        ScriptRig rig;
        rig.leg.on_apply = [](OsPayload& os) {
            os.rules_not_disabled = 2;
            auto r = StepResult::success();
            r.partial = true;
            r.notes.emplace_back("rules_not_disabled=2");
            return r;
        };
        Deadline dl;
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "partial");
        CHECK(o.reason == "rules_not_disabled");
        CHECK(render_rows(o).front() == "status|partial|rules_not_disabled");
        // the same on an update (a converged generation)
        const auto u = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(u.status == "partial");
        CHECK(u.reason == "rules_not_disabled");
    }
    SECTION("repaired=1 and incomplete_apply_converged=1 are not claimed over a failed attempt") {
        NftRig rig;
        auto dl = rig.dl();
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.world.table = false; // someone deleted the table
        rig.world.fail_load = true;
        const auto failed = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(failed.status == "update_failed");
        CHECK_FALSE(contains(failed.notes, "repaired=1"));
        rig.world.fail_load = false;
        const auto fixed = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(fixed.status == "active");
        CHECK(contains(fixed.notes, "repaired=1"));

        NftRig crashed;
        auto dl2 = crashed.dl();
        auto rec = make_record(Phase::applying, BackendKind::nft);
        REQUIRE(crashed.store.save(rec));
        crashed.world.fail_load = true;
        const auto bad = apply_and_verify(crashed.env, crashed.request(), dl2);
        CHECK(bad.status == "update_failed");
        CHECK_FALSE(contains(bad.notes, "incomplete_apply_converged=1"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Governance gate 7, round 2: the owner's three decisions (a time limit that
// works and says what it cannot promise; a Group Policy-managed Windows host
// that is contained and reported partial; an unattended self-check) and the
// test-only folds (con-5, qe-1, qe-2).
// ═══════════════════════════════════════════════════════════════════════════

// ── the time limit: honest about the two things it cannot promise ───────────

TEST_CASE("ttl: an expiry release says so, and the one logged line it leaves carries the note",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 120), dl).status == "active");
    ReleaseRequest due;
    due.if_ttl_expired = true;

    // before the deadline: a no-op that logs nothing (it would log every 30 s otherwise)
    rig.now += 119;
    const auto early = release(rig.env, due, dl);
    CHECK(contains(early.notes, "ttl_not_expired=1"));
    CHECK_FALSE(contains(early.notes, "ttl_expired=1"));
    CHECK(log_level("release", early) == LogLevel::none);

    // the expiry itself: inactive, the note, and an info line that reads like this
    rig.now += 2;
    const auto late = release(rig.env, due, dl);
    REQUIRE(late.status == "inactive");
    CHECK(contains(late.notes, "ttl_expired=1"));
    CHECK(log_level("release", late) == LogLevel::info);
    CHECK(log_line("release", late) == "firewall: release -> inactive ttl_expired=1");

    SECTION("a limit that lapsed while the agent was down is released at start with the same note") {
        NftRig down;
        auto d2 = down.dl();
        REQUIRE(apply_and_verify(down.env, down.request(kProbeTarget, 120), d2).status == "active");
        down.now += 500;
        const auto boot = recover_at_init(down.env, d2);
        CHECK(boot.status == "inactive");
        CHECK(contains(boot.notes, "ttl_expired=1"));
        CHECK(log_line("start recovery", boot) == "firewall: start recovery -> inactive ttl_expired=1");
    }
    SECTION("a manual release is not an expiry") {
        NftRig manual;
        auto d3 = manual.dl();
        REQUIRE(apply_and_verify(manual.env, manual.request(kProbeTarget, 120), d3).status == "active");
        CHECK_FALSE(contains(release(manual.env, ReleaseRequest{}, d3).notes, "ttl_expired=1"));
    }
    SECTION("a lapsed limit deferred to a legacy containment has not expired anything yet") {
        ScriptRig script;
        auto rec = make_record();
        rec.ttl_expires = script.now - 1;
        REQUIRE(script.store.save(rec));
        script.leg.refuse = "legacy_quarantine_active";
        const auto deferred = release(script.env, due, dl);
        CHECK(contains(deferred.notes, "ttl_deferred_legacy=1"));
        CHECK_FALSE(contains(deferred.notes, "ttl_expired=1"));
    }
}

TEST_CASE("ttl: a wall clock stepped behind the apply time is reported, and adds no way to expire",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(kProbeTarget, 3600), dl).status == "active");
    const auto applied = rig.store.state()->applied_at;
    REQUIRE(applied == rig.now);

    CHECK_FALSE(contains(report_status(rig.env, dl).notes, "clock_before_apply=1")); // clock as it was
    rig.now = applied + 100;
    CHECK_FALSE(contains(report_status(rig.env, dl).notes, "clock_before_apply=1")); // forward is normal

    // NTP is blocked by the containment: a clock that steps back is the host's own
    rig.now = applied - 10;
    const auto st = report_status(rig.env, dl);
    CHECK(contains(st.notes, "clock_before_apply=1"));
    CHECK(st.status == "active"); // said, never acted on
    CHECK(contains(render_rows(st), "note|clock_before_apply=1"));

    // and the limit cannot fire while the clock is behind: no new exit, by construction
    QuarantineState s = *rig.store.state();
    CHECK_FALSE(ttl_expired(s, applied - 10));
    CHECK_FALSE(ttl_expired(s, applied));
    ReleaseRequest due;
    due.if_ttl_expired = true;
    const auto tick = release(rig.env, due, dl);
    CHECK(contains(tick.notes, "ttl_not_expired=1"));
    CHECK(rig.world.table);

    // a containment with no time limit has no clock to be behind
    NftRig plain;
    auto dl2 = plain.dl();
    REQUIRE(apply_and_verify(plain.env, plain.request(), dl2).status == "active");
    plain.now -= 1000;
    CHECK_FALSE(contains(report_status(plain.env, dl2).notes, "clock_before_apply=1"));
}

TEST_CASE("log: what is logged for an outcome, at which level; the ticks stay quiet unless they did something",
          "[agent][firewall_quarantine]") {
    struct Row {
        const char* action;
        const char* status;
        const char* reason;
        std::vector<std::string> notes;
        LogLevel level;
        const char* line; // nullptr: not logged, so not compared
    };
    const std::vector<Row> rows{
        {"quarantine", "active", "", {}, LogLevel::info, "firewall: quarantine -> active"},
        {"release", "inactive", "", {"ttl_expired=1"}, LogLevel::info,
         "firewall: release -> inactive ttl_expired=1"},
        {"quarantine_status", "active", "", {}, LogLevel::none, nullptr},
        {"quarantine_status", "partial", "state_flush_failed", {"state_flush_failed=1"}, LogLevel::warn,
         "firewall: quarantine_status -> partial:state_flush_failed state_flush_failed=1"},
        {"quarantine", "rolled_back", "control_unreachable", {}, LogLevel::warn,
         "firewall: quarantine -> rolled_back:control_unreachable"},
        {"quarantine", "refused", "ttl_out_of_bounds", {}, LogLevel::warn,
         "firewall: quarantine -> refused:ttl_out_of_bounds"},
        {"containment", "busy", "", {}, LogLevel::warn, "firewall: containment -> busy"},
        {"containment", "degraded", "exception", {}, LogLevel::error,
         "firewall: containment threw; outcome degraded:exception"},
        // the 30 s time-limit poll: silent whatever the record carries
        {"release", "active", "", {"ttl_not_expired=1"}, LogLevel::none, nullptr},
        {"release", "partial", "stale_rules_left", {"stale_rules_left=2", "ttl_not_expired=1"},
         LogLevel::none, nullptr},
        // the 60 s repair tick
        {"repair", "active", "", {"repair_tick=1"}, LogLevel::none, nullptr},
        {"repair", "active_unproven", "", {"repair_tick=1"}, LogLevel::none, nullptr},
        {"repair", "inactive", "", {"repair_tick=1", "nothing_to_repair=1"}, LogLevel::none, nullptr},
        {"repair", "partial", "rules_not_disabled", {"repair_tick=1", "rules_not_disabled=2"},
         LogLevel::none, nullptr}, // a residue the record already carries
        {"repair", "partial", "operation_in_progress", {"repair_tick=1", "repair_skipped=1"},
         LogLevel::none, nullptr},
        {"repair", "active", "", {"repair_tick=1", "repaired=1", "repairs=1"}, LogLevel::info,
         "firewall: repair -> active repair_tick=1 repaired=1 repairs=1"},
        {"repair", "partial", "legacy_quarantine_active", {"repair_tick=1", "repair_deferred_legacy=1"},
         LogLevel::warn, "firewall: repair -> partial:legacy_quarantine_active repair_tick=1 repair_deferred_legacy=1"},
        {"repair", "degraded", "policy_not_blocking", {"repair_tick=1"}, LogLevel::warn,
         "firewall: repair -> degraded:policy_not_blocking repair_tick=1"},
        {"repair", "degraded", "state_unreadable", {"repair_tick=1"}, LogLevel::warn,
         "firewall: repair -> degraded:state_unreadable repair_tick=1"},
        {"repair", "update_failed", "nft_load_failed", {"repair_tick=1"}, LogLevel::warn,
         "firewall: repair -> update_failed:nft_load_failed repair_tick=1"},
    };
    for (const auto& r : rows) {
        INFO(r.action << " " << r.status << " " << r.reason);
        Outcome o;
        o.status = r.status;
        o.reason = r.reason;
        o.notes = r.notes;
        CHECK(log_level(r.action, o) == r.level);
        if (r.line)
            CHECK(log_line(r.action, o) == r.line);
    }
}

// ── Windows hosts under Group Policy: refused, never contained in part ──────
//
// Owner decision 2026-11-10: where Group Policy controls ANY profile the quarantine relies on
// (all three: it writes default-block on each) a rule or default written locally takes no
// effect there, so the leg REFUSES (`gpo_override:<Profile>`, nothing written) and reads
// `degraded|gpo_override` if the policy arrives mid-quarantine. Never partial, never active,
// and no repair loop. The per-profile reading comes from the policy store (a profile that is
// not the current one is invisible to INetFwPolicy2::LocalPolicyModifyState); the COM state
// stays as a second signal that names no profile.

TEST_CASE("gpo_override: what the policy store holds for one profile decides whether it is controlled",
          "[agent][firewall_quarantine]") {
    // nothing set: no Group Policy on this profile
    CHECK_FALSE(win_gpo_profile_overridden({}));
    // local rules merge (AllowLocalPolicyMerge=1) and no default is set by policy: not controlled
    CHECK_FALSE(win_gpo_profile_overridden({1u, std::nullopt, std::nullopt}));
    // local rules do NOT merge: our allowances would never apply, the host would be block/block
    CHECK(win_gpo_profile_overridden({0u, std::nullopt, std::nullopt}));
    // a default action set by policy, whatever its value (allow or block), makes ours inert
    for (const std::uint32_t v : {0u, 1u}) {
        INFO("value " << v);
        CHECK(win_gpo_profile_overridden({std::nullopt, v, std::nullopt}));
        CHECK(win_gpo_profile_overridden({std::nullopt, std::nullopt, v}));
        CHECK(win_gpo_profile_overridden({1u, v, v}));
    }
}

TEST_CASE("gpo_override: Group Policy and the MDM store fold into one reading per profile",
          "[agent][firewall_quarantine]") {
    using R = std::optional<bool>;
    const R yes = true, no = false, unread = std::nullopt;
    // an override in the MDM store alone controls the profile
    CHECK(win_policy_stores_overridden(no, yes) == yes);
    CHECK(win_policy_stores_overridden(yes, no) == yes);
    // a definite override outranks an unreadable sibling store, in either order
    CHECK(win_policy_stores_overridden(yes, unread) == yes);
    CHECK(win_policy_stores_overridden(unread, yes) == yes);
    // an unreadable store keeps the profile unreadable: never read as no policy
    CHECK(win_policy_stores_overridden(unread, no) == unread);
    CHECK(win_policy_stores_overridden(no, unread) == unread);
    CHECK(win_policy_stores_overridden(unread, unread) == unread);
    // no policy in either store is the only way to read false
    CHECK(win_policy_stores_overridden(no, no) == no);

    // through the verdict: an MDM-only override (local rules do not merge) refuses and names
    // whichever profile it is
    const WinSwitchReading on{true, true, true};
    const R clean = win_gpo_profile_overridden({});
    const R mdm_locked = win_gpo_profile_overridden({0u, std::nullopt, std::nullopt});
    REQUIRE(mdm_locked == yes);
    for (std::size_t i = 0; i < kWinProfileLabels.size(); ++i) {
        INFO("profile " << kWinProfileLabels[i]);
        WinGpoReading gpo{false, false, false};
        gpo[i] = win_policy_stores_overridden(clean, mdm_locked);
        const auto v = win_firewall_switch_verdict(on, gpo, false);
        CHECK(v.kind == WinSwitchVerdict::Kind::gpo_override);
        CHECK(v.profile == i);
        CHECK(win_firewall_switch_token(v) == "gpo_override:" + std::string{kWinProfileLabels[i]});
    }
    // Group Policy controlled plus an unreadable MDM store still refuses as an override
    const auto mixed = win_policy_stores_overridden(true, std::nullopt);
    CHECK(win_firewall_switch_verdict(on, {false, mixed, false}, false).kind ==
          WinSwitchVerdict::Kind::gpo_override);
    // an unreadable MDM store beside clean Group Policy is unreadable, not a pass
    const auto unclear = win_policy_stores_overridden(false, std::nullopt);
    CHECK(win_firewall_switch_verdict(on, {false, unclear, false}, false).kind ==
          WinSwitchVerdict::Kind::unreadable);
    // both stores absent: no policy
    CHECK(win_firewall_switch_verdict(on, {false, false, false}, false).kind == WinSwitchVerdict::Kind::ok);
}

TEST_CASE("gpo_override: the verdict, its token and the status read are one decision",
          "[agent][firewall_quarantine]") {
    using K = WinSwitchVerdict::Kind;
    const WinSwitchReading on{true, true, true};
    const WinGpoReading none{false, false, false};

    // Group Policy on ONE profile refuses and names it, whichever profile it is and
    // whatever the COM (current-profile) state says: a non-current profile is the case the
    // COM state cannot see
    for (std::size_t i = 0; i < none.size(); ++i) {
        INFO("profile " << kWinProfileLabels[i]);
        auto gpo = none;
        gpo[i] = true;
        for (const bool com : {false, true}) {
            const auto v = win_firewall_switch_verdict(on, gpo, com);
            CHECK(v.kind == K::gpo_override);
            CHECK(v.profile == i);
            CHECK(v.profile_named);
            const auto token = win_firewall_switch_token(v);
            CHECK(token == "gpo_override:" + std::string{kWinProfileLabels[i]});
            CHECK(is_safe_token(token));
        }
    }
    // the first controlled profile is the one named
    CHECK(win_firewall_switch_verdict(on, {false, true, true}, false).profile == 1);

    // the COM reading on its own refuses too, and names no profile
    const auto com_only = win_firewall_switch_verdict(on, none, true);
    CHECK(com_only.kind == K::gpo_override);
    CHECK_FALSE(com_only.profile_named);
    const auto bare = win_firewall_switch_token(com_only);
    CHECK(bare == "gpo_override");
    CHECK(is_safe_token(bare));

    // override outranks a switched-off or unreadable profile (it is what no local action
    // can change), from either signal
    CHECK(win_firewall_switch_verdict({false, true, true}, {false, false, true}, false).kind == K::gpo_override);
    CHECK(win_firewall_switch_verdict({std::nullopt, true, true}, none, true).kind == K::gpo_override);
    CHECK(win_firewall_switch_verdict({true, true, true}, {std::nullopt, true, false}, false).profile == 1);

    // absent everywhere is no override: the other kinds are unchanged
    CHECK(win_firewall_switch_verdict(on, none, false).kind == K::ok);
    CHECK(win_firewall_switch_verdict({true, false, true}, none, false).kind == K::disabled);

    // a policy-store reading that FAILED is unreadable and names the profile, never "no policy"
    for (std::size_t i = 0; i < none.size(); ++i) {
        INFO("profile " << kWinProfileLabels[i]);
        auto gpo = none;
        gpo[i] = std::nullopt;
        const auto u = win_firewall_switch_verdict(on, gpo, false);
        CHECK(u.kind == K::unreadable);
        CHECK(u.profile == i);
        CHECK(u.profile_named);
        const auto ut = win_firewall_switch_token(u);
        CHECK(ut == "firewall_state_unreadable:" + std::string{kWinProfileLabels[i]});
        CHECK(is_safe_token(ut));
    }
    // a definite "off" still outranks an unreadable policy store, as it does an unreadable switch
    const auto off_beats_unread = win_firewall_switch_verdict({true, true, false}, {std::nullopt, false, false}, false);
    CHECK(off_beats_unread.kind == K::disabled);
    CHECK(off_beats_unread.profile == 2);

    // the status read: not enforcing, a re-apply cannot help, and a named profile is a note
    const auto named = win_firewall_switch_verdict(on, {true, false, false}, false);
    LegStatus ls;
    ls.state = OsState::enforcing; // a stale optimistic value must not survive
    CHECK(win_switch_status(named, ls));
    CHECK(ls.state == OsState::not_enforcing);
    CHECK(ls.reason == "gpo_override");
    CHECK_FALSE(ls.reapply_helps);
    CHECK(ls.notes == std::vector<std::string>{"firewall_profile=Domain"});

    LegStatus com_ls;
    CHECK(win_switch_status(com_only, com_ls));
    CHECK(com_ls.state == OsState::not_enforcing);
    CHECK(com_ls.reason == "gpo_override");
    CHECK_FALSE(com_ls.reapply_helps);
    CHECK(com_ls.notes.empty());

    // over an active record the ladder answers degraded|gpo_override, never partial or active
    const auto rec = make_record();
    Outcome o;
    detail::status_from_record(o, rec, ls);
    CHECK(o.status == "degraded");
    CHECK(o.reason == "gpo_override");
    CHECK(render_rows(o).front() == "status|degraded|gpo_override");
    CHECK(result_kind(o).partial);

    // and the self-check tick over that LegStatus does not converge (reapply_helps=false)
    ScriptRig rig;
    Deadline dl;
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.leg.status = ls;
    const int applies = rig.leg.applies;
    const auto saves = rig.store.saves;
    const auto tick = repair(rig.env, dl);
    CHECK(tick.status == "degraded");
    CHECK(tick.reason == "gpo_override");
    CHECK(rig.leg.applies == applies);
    CHECK(rig.store.saves == saves);
    CHECK(log_level("repair", tick) == LogLevel::warn); // visible, but a re-apply is not attempted
}

TEST_CASE("gpo_override: a Group Policy host is refused before anything is touched, and never re-applied over",
          "[agent][firewall_quarantine]") {
    SECTION("the initial quarantine is refused: no record, no apply") {
        ScriptRig rig;
        rig.leg.refuse = "gpo_override:Domain"; // preflight's token for a profile that is not the current one
        Deadline dl;
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "refused");
        CHECK(o.reason == "gpo_override:Domain");
        CHECK(render_rows(o)[1] == "refused|gpo_override:Domain");
        CHECK(rig.leg.applies == 0);
        CHECK(rig.store.raw.empty());
    }
    SECTION("a policy that arrives mid-quarantine: status degrades, nothing is re-applied, an update fails whole") {
        ScriptRig rig;
        Deadline dl;
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        const auto before = rig.store.state();
        const int applies = rig.leg.applies;
        rig.leg.status.state = OsState::not_enforcing;
        rig.leg.status.reason = "gpo_override";
        rig.leg.status.reapply_helps = false;
        rig.leg.status.notes = {"firewall_profile=Domain"};

        const auto st = report_status(rig.env, dl);
        CHECK(st.status == "degraded");
        CHECK(st.reason == "gpo_override");
        CHECK(contains(st.notes, "firewall_profile=Domain"));

        // a retried quarantine answers what status would, and never re-applies
        const auto again = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(again.status == "degraded");
        CHECK(again.reason == "gpo_override");
        CHECK(rig.leg.applies == applies);

        // a no-op quarantine_allow answers what quarantine_status would: it reads the leg too,
        // so it is never `active` over the gap
        const auto noop = update(rig.env, false, {ex("10.9.9.9")}, dl);
        CHECK(noop.status == "degraded");
        CHECK(noop.reason == "gpo_override");
        CHECK(contains(noop.notes, "exceptions_unchanged=1"));
        CHECK(rig.leg.applies == applies);

        // a quarantine_allow that changes the set reaches the leg, whose step 0 refuses:
        // update_failed with the token, the previous generation stays in the record
        rig.leg.on_apply = [](OsPayload&) { return StepResult::fail("gpo_override:Domain"); };
        const auto u = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
        CHECK(u.status == "update_failed");
        CHECK(u.reason == "gpo_override:Domain");
        CHECK(rig.store.state()->allow == before->allow);
        CHECK(rig.store.state()->generation == before->generation);

        // the boot re-apply takes the same failed path and leaves the record active
        const auto boot = recover_at_init(rig.env, dl);
        CHECK(boot.status == "degraded");
        CHECK(boot.reason == "reapply_failed:gpo_override:Domain");
        CHECK(rig.store.state()->phase == Phase::active);
    }
}

// ── the unattended self-check ───────────────────────────────────────────────

TEST_CASE("repair: a host flushed behind our back is re-applied from the STORED set, counted, and visible",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto stored = rig.store.state()->allow;
    CHECK(rig.store.state()->repairs == 0);

    rig.world.table = false; // an external flush
    rig.now += 90;
    const auto o = repair(rig.env, dl);
    CHECK(o.status == "active");
    CHECK(contains(o.notes, "repair_tick=1"));
    CHECK(contains(o.notes, "repaired=1"));
    CHECK(rig.world.table); // the table is back
    const auto rec = rig.store.state();
    REQUIRE(rec);
    CHECK(rec->phase == Phase::active);
    CHECK(rec->generation == 2); // the same converge a retried quarantine uses
    CHECK(rec->allow == stored); // never a fresh or caller-supplied set
    CHECK(rec->repairs == 1);
    CHECK(rec->repaired_at == rig.now);
    CHECK(log_level("repair", o) == LogLevel::info);

    // quarantine_status shows the repairs, on every read
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "active");
    CHECK(contains(st.notes, "repairs=1"));
    CHECK(contains(st.notes, std::format("last_repair_at={}", rig.now)));

    // a second flush is a second repair
    rig.world.table = false;
    rig.now += 60;
    CHECK(repair(rig.env, dl).status == "active");
    CHECK(rig.store.state()->repairs == 2);
    CHECK(rig.store.state()->repaired_at == rig.now);
}

TEST_CASE("repair: a healthy host is only read; nothing is applied, saved or logged",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto calls = rig.world.log.size();
    const auto saves = rig.store.saves;
    const auto raw = rig.store.raw;

    const auto o = repair(rig.env, dl);
    CHECK(o.status == "active");
    CHECK(contains(o.notes, "repair_tick=1"));
    CHECK_FALSE(contains(o.notes, "repaired=1"));
    CHECK(rig.store.saves == saves);
    CHECK(rig.store.raw == raw);
    // one leg read per tick (nft list), never a load or a delete
    REQUIRE(rig.world.log.size() == calls + 1);
    CHECK(rig.world.log.back()[1] == "list");
    CHECK(log_level("repair", o) == LogLevel::none);
}

TEST_CASE("repair: an unreadable store is never acted on; no record means nothing to repair",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.world.table = false; // a repairable gap ...
    const auto calls = rig.world.log.size();
    const auto raw = rig.store.raw;

    rig.store.fault = true; // ... but the store cannot ANSWER: a fault is not "no record"
    const auto o = repair(rig.env, dl);
    CHECK(o.status == "degraded");
    CHECK(o.reason == "state_unreadable");
    CHECK(contains(o.notes, "repair_tick=1"));
    CHECK(rig.world.log.size() == calls); // not one tool call: the leg was not read, let alone applied
    CHECK(log_level("repair", o) == LogLevel::warn);
    rig.store.fault = false;
    CHECK(rig.store.raw == raw);
    CHECK_FALSE(rig.world.table);

    // a release since: no record, nothing to repair, and the tick says inactive so both
    // triggers can be removed
    REQUIRE(release(rig.env, ReleaseRequest{}, dl).status == "inactive");
    const auto before = rig.world.log.size();
    auto none = repair(rig.env, dl);
    CHECK(none.status == "inactive");
    CHECK(contains(none.notes, "nothing_to_repair=1"));
    CHECK(rig.world.log.size() == before);
    FakeTriggers trig;
    settle_triggers(none, trig, rig.store);
    CHECK(trig.unregistered_count(kRepairTriggerId) == 1);
    CHECK(trig.unregistered_count(kTtlTriggerId) == 1);
    CHECK(trig.registered.empty());
}

TEST_CASE("repair: never over a record that is not active, a read that cannot help, or a legacy containment",
          "[agent][firewall_quarantine]") {
    ScriptRig rig;
    Deadline dl;
    rig.leg.status.state = OsState::not_enforcing; // a repairable gap, every time below
    rig.leg.status.reason = "policy_not_blocking";

    SECTION("an operation in progress is skipped, never converged") {
        for (const auto phase : {Phase::applying, Phase::releasing}) {
            REQUIRE(rig.store.save(make_record(phase)));
            const auto o = repair(rig.env, dl);
            CHECK(o.status == "partial");
            CHECK(o.reason == (phase == Phase::applying ? "operation_in_progress" : "release_incomplete"));
            CHECK(contains(o.notes, "repair_skipped=1"));
            CHECK(contains(o.notes, "repair_tick=1"));
            CHECK(log_level("repair", o) == LogLevel::none);
        }
        CHECK(rig.leg.applies == 0);
        CHECK(rig.store.state()->phase == Phase::releasing); // untouched
    }
    SECTION("a gap a re-apply cannot fix is reported, not re-applied every minute") {
        REQUIRE(rig.store.save(make_record()));
        rig.leg.status.reapply_helps = false;
        rig.leg.status.reason = "firewall_disabled";
        const auto o = repair(rig.env, dl);
        CHECK(o.status == "degraded");
        CHECK(o.reason == "firewall_disabled");
        CHECK(rig.leg.applies == 0);
        CHECK(log_level("repair", o) == LogLevel::warn);
    }
    SECTION("an unreadable host changes nothing") {
        REQUIRE(rig.store.save(make_record()));
        rig.leg.status.state = OsState::unreadable;
        const auto o = repair(rig.env, dl);
        CHECK(o.status == "degraded");
        CHECK(o.reason == "os_unreadable");
        CHECK(rig.leg.applies == 0);
    }
    SECTION("a legacy containment that appeared underneath defers, with no mutation") {
        REQUIRE(rig.store.save(make_record()));
        const auto raw = rig.store.raw;
        rig.leg.refuse = "legacy_quarantine_active";
        const auto o = repair(rig.env, dl);
        CHECK(o.status == "partial");
        CHECK(o.reason == "legacy_quarantine_active");
        CHECK(contains(o.notes, "repair_deferred_legacy=1"));
        CHECK(rig.leg.applies == 0);
        CHECK(rig.store.raw == raw);
        CHECK(log_level("repair", o) == LogLevel::warn);

        // any OTHER preflight answer must not stop a repair: the converge re-checks it itself
        rig.leg.refuse = "firewall_disabled:Public";
        const auto fixed = repair(rig.env, dl);
        CHECK(fixed.status != "partial");
        CHECK(rig.leg.applies == 1);
        CHECK(contains(fixed.notes, "repaired=1"));
    }
}

TEST_CASE("repair: a failed repair is never counted, and says so",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.world.table = false;
    rig.world.fail_load = true; // the re-apply cannot load
    const auto o = repair(rig.env, dl);
    CHECK(o.status == "update_failed");
    CHECK_FALSE(contains(o.notes, "repaired=1"));
    CHECK(contains(o.notes, "repair_tick=1"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->repairs == 0);
    CHECK(rig.store.state()->repaired_at == 0);
    CHECK(log_level("repair", o) == LogLevel::warn);
    // the next tick, with the cause gone, repairs it
    rig.world.fail_load = false;
    CHECK(repair(rig.env, dl).status == "active");
    CHECK(rig.store.state()->repairs == 1);
}

TEST_CASE("repair: a retried quarantine that re-applies counts too, so status shows every repair",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    rig.world.table = false;
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(contains(o.notes, "repaired=1"));
    CHECK(rig.store.state()->repairs == 1);
    CHECK(contains(report_status(rig.env, dl).notes, "repairs=1"));
}

TEST_CASE("triggers: a refused repair registration is residue until a settle succeeds; a tick never re-registers",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    auto o = apply_and_verify(rig.env, rig.request(), dl);
    REQUIRE(o.status == "active");
    FakeTriggers trig;
    trig.accept = false; // the trigger table is full
    settle_triggers(o, trig, rig.store);
    CHECK(o.status == "partial");
    CHECK(o.reason == "repair_unregistered");
    CHECK(contains(o.notes, "repair_trigger_unregistered=1"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->os.repair_unregistered);
    CHECK(rig.store.state()->os.ttl_unregistered == false); // no time limit, so no TTL flag
    const auto round = parse_state(serialize_state(*rig.store.state()));
    REQUIRE(round);
    CHECK(round->os.repair_unregistered);
    CHECK(rig.store.raw.find("repair_unreg=1") != std::string::npos);

    // every later read says so instead of `active` over a self-check nothing runs
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "repair_unregistered");
    CHECK(contains(st.notes, "repair_unregistered=1"));
    const auto noop = update(rig.env, true, {}, dl);
    CHECK(noop.status == "partial");
    CHECK(noop.reason == "repair_unregistered");

    // the repair tick itself leaves the flag alone and registers nothing
    FakeTriggers quiet;
    auto tick = repair(rig.env, dl);
    CHECK(tick.status == "partial");
    CHECK(tick.reason == "repair_unregistered");
    CHECK(log_level("repair", tick) == LogLevel::none); // a residue the record already carries
    settle_triggers(tick, quiet, rig.store);
    CHECK(quiet.registered.empty());
    CHECK(rig.store.state()->os.repair_unregistered);

    // a registration that finally succeeds clears it
    FakeTriggers works;
    auto again = report_status(rig.env, dl);
    settle_triggers(again, works, rig.store);
    CHECK(works.count(kRepairTriggerId) == 1);
    CHECK(again.status == "active");
    CHECK(again.reason.empty());
    CHECK_FALSE(contains(again.notes, "repair_unregistered=1"));
    CHECK_FALSE(rig.store.state()->os.repair_unregistered);
    CHECK(report_status(rig.env, dl).status == "active");
}

TEST_CASE("triggers: two refused registrations name the first residue; clearing one names the other",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    auto dl = rig.dl();
    auto o = apply_and_verify(rig.env, rig.request(kProbeTarget, 600), dl);
    REQUIRE(o.status == "active");
    FakeTriggers none;
    none.accept = false;
    settle_triggers(o, none, rig.store);
    CHECK(o.status == "partial");
    CHECK(o.reason == "ttl_unregistered"); // the first residue in the fixed order
    CHECK(rig.store.state()->os.ttl_unregistered);
    CHECK(rig.store.state()->os.repair_unregistered);

    // only the repair trigger registers this time: the time limit's gap is what is left
    struct OnlyRepair final : TriggerRegistry {
        FakeTriggers inner;
        bool register_trigger(std::string_view id, std::string_view t, std::string_view c) override {
            return id == kRepairTriggerId && inner.register_trigger(id, t, c);
        }
        bool unregister_trigger(std::string_view id) override { return inner.unregister_trigger(id); }
    } only_repair;
    auto st = report_status(rig.env, dl);
    REQUIRE(st.reason == "ttl_unregistered");
    settle_triggers(st, only_repair, rig.store);
    CHECK(st.status == "partial");
    CHECK(st.reason == "ttl_unregistered");
    CHECK_FALSE(rig.store.state()->os.repair_unregistered);
    CHECK(rig.store.state()->os.ttl_unregistered);

    // and the reverse: the time limit registers, the repair trigger does not
    struct OnlyTtl final : TriggerRegistry {
        FakeTriggers inner;
        bool register_trigger(std::string_view id, std::string_view t, std::string_view c) override {
            return id == kTtlTriggerId && inner.register_trigger(id, t, c);
        }
        bool unregister_trigger(std::string_view id) override { return inner.unregister_trigger(id); }
    } only_ttl;
    auto s2 = report_status(rig.env, dl);
    settle_triggers(s2, only_ttl, rig.store);
    CHECK(s2.status == "partial");
    CHECK(s2.reason == "repair_unregistered");
    CHECK_FALSE(rig.store.state()->os.ttl_unregistered);
    CHECK(rig.store.state()->os.repair_unregistered);
}

// ── con-5: every status token the core can answer, in one table ─────────────

TEST_CASE("con-5: every status token maps to one typed result, one first row, one return code",
          "[agent][firewall_quarantine]") {
    using K = ResultKind::Kind;
    struct Row {
        const char* status;
        const char* reason;
        K kind;
        bool partial;
        int rc;
    };
    // The complete set the drivers and the shell produce, with the reasons that change a
    // verdict: degraded|exception is the one `degraded` that is also a failed action.
    const std::vector<Row> table{
        {"active", "", K::ok, false, 0},
        {"inactive", "", K::ok, false, 0},
        {"active_unproven", "", K::ok, true, 0},
        {"partial", "", K::constrained, true, 0},
        {"partial", "gpo_override", K::constrained, true, 0},
        {"partial", "repair_unregistered", K::constrained, true, 0},
        {"partial", "operation_in_progress", K::constrained, true, 0},
        {"degraded", "", K::constrained, true, 0},
        {"degraded", "state_unreadable", K::constrained, true, 0},
        {"degraded", "exception", K::constrained, true, 1},
        {"refused", "ttl_out_of_bounds", K::unavailable, true, 1},
        {"rolled_back", "control_unreachable", K::unavailable, true, 1},
        {"update_failed", "commit_unknown", K::unavailable, true, 1},
        {"busy", "", K::unavailable, true, 1},
    };
    for (const auto& row : table) {
        INFO(row.status << "|" << row.reason);
        Outcome o;
        o.status = row.status;
        o.reason = row.reason;
        const auto rk = result_kind(o);
        CHECK(rk.kind == row.kind);
        CHECK(rk.partial == row.partial);
        CHECK(rk.provenance == std::string{"firewall:"} + row.status);
        CHECK(o.rc() == row.rc);
        const auto rows = render_rows(o);
        REQUIRE_FALSE(rows.empty());
        CHECK(rows.front() == (std::string{"status|"} + row.status +
                               (o.reason.empty() ? std::string{} : "|" + o.reason)));
    }
    // a token this build does not know is unavailable and partial, never ok
    Outcome unknown;
    unknown.status = "something_new";
    CHECK(result_kind(unknown).kind == K::unavailable);
    CHECK(result_kind(unknown).partial);
}

// ── qe-1 / qe-2: facts that must survive every re-save of the record ────────

TEST_CASE("qe-1: revert_failed, a failed erase and a failed final save are all pinned",
          "[agent][firewall_quarantine]") {
    // These three live beside the cases that drive them: the update that cannot be
    // reverted, the release whose record will not erase, and the apply/update whose
    // final save fails. This case drives the one combination none of them reaches: a
    // revert that fails AND a store that then refuses the record.
    NftRig rig;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    int loads = 0;
    rig.world.on_call = [&](const Argv& a) {
        if (a.size() > 1 && a[1] == "-f" && ++loads == 2)
            rig.world.fail_load = true; // the update commits; its REVERT cannot load
    };
    rig.probe.blocked = [] { return false; }; // the new generation fails verification
    rig.store.fail_save_after = rig.store.saves + 1; // the candidate lands, nothing after it
    const auto o = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
    CHECK(o.status == "update_failed");
    CHECK(o.reason.starts_with("revert_failed:"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::applying); // boot recovery retries what IS in force
    rig.store.fail_save_after = -1;
    const auto st = report_status(rig.env, dl);
    CHECK(st.status == "partial");
    CHECK(st.reason == "operation_in_progress");
}

TEST_CASE("qe-2: the pf token and the failed-flush fact survive converge's put-back, give_back and the rollback re-save",
          "[agent][firewall_quarantine]") {
    // An update that left a pf state flush failed, then a crash left the record `applying`.
    const auto applying_with_flush_gap = [](PfRig& rig, Deadline& dl) {
        REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
        rig.world.fail_flush_states = 2;
        REQUIRE(update(rig.env, true, {ex("10.0.0.9:22/tcp/in")}, dl).status == "partial");
        auto st = *rig.store.state();
        REQUIRE(st.os.state_flush_failed);
        st.phase = Phase::applying;
        st.prev_generation = st.generation;
        REQUIRE(rig.store.save(st));
        return st.os;
    };

    SECTION("converge's put-back (back.os = cand.os) after a load that fails") {
        PfRig rig;
        auto dl = rig.dl();
        const auto held = applying_with_flush_gap(rig, dl);
        rig.world.fail_load = true;
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "update_failed");
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::applying); // the previous record, put back
        CHECK(rig.store.state()->os.pf_token == held.pf_token);
        CHECK(rig.store.state()->os.boot_time == held.boot_time);
        CHECK(rig.store.state()->os.state_flush_failed);
    }
    SECTION("give_back: a fresh reference taken for a failed attempt is released, the old facts are put back") {
        PfRig rig;
        auto dl = rig.dl();
        const auto held = applying_with_flush_gap(rig, dl);
        rig.world.external_disable(); // pf off behind our back: the held token is dead
        rig.world.fail_load = true;   // the repair takes a fresh reference, then the load fails
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "update_failed");
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->os.pf_token == held.pf_token); // what the record held, not the fresh one
        CHECK(rig.store.state()->os.state_flush_failed);
        CHECK(rig.world.tokens.empty()); // the fresh reference was given back
    }
    SECTION("the rollback re-save keeps the token on the releasing record and invents no flush fact") {
        PfRig rig;
        auto dl = rig.dl();
        rig.world.fail_flush_anchor = true; // the removal cannot empty the anchor
        rig.probe.control_up = false;       // the first apply fails its own control check
        const auto o = apply_and_verify(rig.env, rig.request(), dl);
        CHECK(o.status == "rolled_back");
        CHECK(contains(o.notes, "rollback_incomplete=1"));
        REQUIRE(rig.store.state());
        CHECK(rig.store.state()->phase == Phase::releasing);
        CHECK_FALSE(rig.store.state()->os.pf_token.empty());
        CHECK_FALSE(rig.store.state()->os.state_flush_failed);
    }
}

// ── UP-8: the control set follows the server address the agent really uses ──

TEST_CASE("live peer: only an address literal that parses is an endpoint", "[agent][firewall_quarantine]") {
    const auto e = parse_live_peer("203.0.113.99:50051");
    REQUIRE(e);
    CHECK(format_ip(e->ip) == "203.0.113.99");
    CHECK(e->port == 50051);
    CHECK(e->proto == Proto::tcp);
    CHECK(e->dir == Dir::out);
    const auto v6 = parse_live_peer("[2001:db8::99]:8443");
    REQUIRE(v6);
    CHECK(v6->ip.v6);
    CHECK(v6->port == 8443);
    // a name is never resolved here, a bare address has no port to allow, nothing else passes
    for (const char* bad : {"", "server.example.com:50051", "203.0.113.99", "203.0.113.99:0",
                            "203.0.113.99:70000", "203.0.113.999:50051", "garbage", ":50051",
                            "[2001:db8::99]", "203.0.113.99:50051;rm"})
        CHECK_FALSE(parse_live_peer(bad));
}

TEST_CASE("live peer: it leads the control set, deduplicated, and never empties or overflows it",
          "[agent][firewall_quarantine]") {
    const std::vector<std::string> res{"203.0.113.53"};
    const auto at = [](const AllowSet& s, std::size_t i) { return format_ip(s.control.at(i).ip); };

    SECTION("a peer outside the start-resolved set is admitted first") {
        const auto b = build_allow_set("198.51.100.7", "198.51.100.7:50051", res, {}, "203.0.113.99:50051");
        REQUIRE(b);
        REQUIRE(b->control.size() == 2);
        CHECK(at(*b, 0) == "203.0.113.99");
        CHECK(b->control[0].port == 50051);
        CHECK(at(*b, 1) == "198.51.100.7");
        CHECK(contains(b->notes, "control_live_peer=203.0.113.99:50051"));
        CHECK_FALSE(contains(b->notes, "live_peer_invalid=1"));
    }
    SECTION("a peer the start-resolved set already carries moves to the front, never twice") {
        const auto b = build_allow_set("198.51.100.7,198.51.100.8", "198.51.100.7:50051", res, {},
                                       "198.51.100.8:50051");
        REQUIRE(b);
        REQUIRE(b->control.size() == 2);
        CHECK(at(*b, 0) == "198.51.100.8");
        CHECK(at(*b, 1) == "198.51.100.7");
    }
    SECTION("the live peer's own port is the one allowed, a v6 peer included") {
        const auto b = build_allow_set("198.51.100.7", "198.51.100.7:50051", res, {}, "[2001:db8::99]:8443");
        REQUIRE(b);
        CHECK(b->control.front().ip.v6);
        CHECK(b->control.front().port == 8443);
        CHECK(contains(b->notes, "control_live_peer=[2001:db8::99]:8443"));
        CHECK(b->control.back().port == 50051); // the configured port keeps governing the listed set
    }
    SECTION("a literal that does not parse is dropped with a note, the set is what it was") {
        for (const char* bad : {"server.example.com:50051", "garbage", "203.0.113.99"}) {
            const auto b = build_allow_set("198.51.100.7", "198.51.100.7:50051", res, {}, bad);
            REQUIRE(b);
            CHECK(b->control.size() == 1);
            CHECK(contains(b->notes, "live_peer_invalid=1"));
            CHECK_FALSE(std::any_of(b->notes.begin(), b->notes.end(), [](const std::string& n) {
                return n.starts_with("control_live_peer=");
            }));
        }
    }
    SECTION("no live peer: exactly the old behaviour") {
        const auto none = build_allow_set("198.51.100.7", "198.51.100.7:50051", res, {});
        const auto empty = build_allow_set("198.51.100.7", "198.51.100.7:50051", res, {}, "");
        REQUIRE(none);
        REQUIRE(empty);
        CHECK(none->control == empty->control);
        CHECK(none->notes.empty());
    }
    SECTION("an empty start-resolved set with a live peer is no longer control_set_empty") {
        // a hostname that did not resolve at start: before, nothing could be allowed
        const auto before = build_allow_set("", "server.example.com:50051", res, {});
        REQUIRE_FALSE(before);
        CHECK(before.error() == "control_set_empty");
        const auto b = build_allow_set("", "server.example.com:50051", res, {}, "203.0.113.99:50051");
        REQUIRE(b);
        REQUIRE(b->control.size() == 1);
        CHECK(at(*b, 0) == "203.0.113.99");
        // an unparsable peer does not rescue it
        const auto bad = build_allow_set("", "server.example.com:50051", res, {}, "garbage");
        REQUIRE_FALSE(bad);
        CHECK(bad.error() == "control_set_empty");
    }
    SECTION("the configured-port and cap rules are unchanged") {
        const auto no_port = build_allow_set("198.51.100.7", "198.51.100.7", res, {}, "203.0.113.99:50051");
        REQUIRE_FALSE(no_port);
        CHECK(no_port.error() == "control_port_missing");
        std::string many;
        for (std::size_t i = 1; i <= kMaxControlIps; ++i)
            many += (many.empty() ? "" : ",") + std::format("198.51.100.{}", i);
        REQUIRE(build_allow_set(many, "198.51.100.1:50051", res, {}));
        const auto over = build_allow_set(many, "198.51.100.1:50051", res, {}, "203.0.113.99:50051");
        REQUIRE_FALSE(over);
        CHECK(over.error() == "control_set_too_large");
    }
}

namespace {

/// A probe whose control endpoints answer only while the network path exists AND the loaded
/// table lets the packet out: `up` is what the network would answer, `allowed` what the
/// contained host's own rules admit. The probe target answers until the table is loaded.
struct PeerProbe {
    std::set<std::string> up;
    NftWorld* world = nullptr;
    std::vector<std::string> asked;
    TcpProbe fn() {
        return [this](const std::string& ip, int port, std::chrono::milliseconds) {
            const auto key = std::format("{}:{}", ip, port);
            asked.push_back(key);
            if (key == kProbeTarget)
                return world->table ? ProbeOutcome::timeout : ProbeOutcome::connected;
            const bool let_out = !world->table || world->text.find(ip) != std::string::npos;
            return up.count(key) != 0 && let_out ? ProbeOutcome::connected : ProbeOutcome::timeout;
        };
    }
    [[nodiscard]] bool asked_for(std::string_view key) const {
        return std::find(asked.begin(), asked.end(), key) != asked.end();
    }
};

} // namespace

TEST_CASE("live peer: a peer outside the start-resolved set is admitted first and is what verify connects to",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"203.0.113.99:50051"}; // the server moved: only its NEW address answers
    rig.env.probe = net.fn();
    const auto allow = build_allow_set("198.51.100.7", "198.51.100.7:50051", {"203.0.113.53"}, {},
                                       "203.0.113.99:50051");
    REQUIRE(allow);
    rig.env.live_control = parse_live_peer("203.0.113.99:50051");
    ApplyRequest req;
    req.allow = *allow;
    req.probe_target = kProbeTarget;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, req, dl);
    CHECK(o.status == "active");
    CHECK(contains(o.notes, "control_proved=live"));
    CHECK_FALSE(contains(o.notes, "control_live_peer=203.0.113.99:50051")); // the allow set's note, added by the shell
    CHECK(net.asked_for("203.0.113.99:50051"));
    CHECK_FALSE(net.asked_for("198.51.100.7:50051")); // the listed (dead) endpoint is never the proof
    REQUIRE(rig.store.state());
    CHECK(format_ip(rig.store.state()->allow.control.front().ip) == "203.0.113.99");
    CHECK(rig.world.text.find("203.0.113.99") != std::string::npos); // and the ruleset really admits it
    CHECK(rig.store.state()->last_verify.starts_with("verified")); // proof text keeps its shape

    // a quarantine_allow update proves the live peer too
    const auto up = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
    CHECK(up.status == "active");
    CHECK(contains(up.notes, "control_proved=live"));
}

TEST_CASE("live peer: a listed endpoint that answers while the live peer does not is control_unreachable",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"198.51.100.7:50051"}; // the stale listed address still answers; the live one does not
    rig.env.probe = net.fn();
    const auto allow = build_allow_set("198.51.100.7", "198.51.100.7:50051", {"203.0.113.53"}, {},
                                       "203.0.113.99:50051");
    REQUIRE(allow);
    rig.env.live_control = parse_live_peer("203.0.113.99:50051");
    ApplyRequest req;
    req.allow = *allow;
    req.probe_target = kProbeTarget;
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, req, dl);
    CHECK(o.status == "rolled_back");
    CHECK(o.reason == "control_unreachable");
    CHECK(contains(o.notes, "control_proved=live"));
    CHECK_FALSE(net.asked_for("198.51.100.7:50051")); // the listed scan would have called this green
    CHECK_FALSE(rig.store.state()); // rolled back to absence
    CHECK_FALSE(rig.world.table);
}

TEST_CASE("live peer: with none known the listed scan is the proof, as at agent start",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"198.51.100.7:50051"};
    rig.env.probe = net.fn();
    CHECK_FALSE(rig.env.live_control);
    auto dl = rig.dl();
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "active");
    CHECK(contains(o.notes, "control_proved=listed"));
    CHECK_FALSE(contains(o.notes, "control_proved=live"));
    CHECK(net.asked_for("198.51.100.7:50051"));

    // agent start re-checks the stored set before any Register: nothing live to prove
    rig.world.table = false; // a reboot
    const auto boot = recover_at_init(rig.env, dl);
    CHECK(boot.status == "active");
    CHECK(contains(boot.notes, "control_proved=listed"));
}

TEST_CASE("live peer: a server re-addressed AFTER containment still strands the host, and verify says so",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"198.51.100.7:50051", "203.0.113.200:50051"};
    rig.env.probe = net.fn();
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");

    // the server moves; the agent learns the new address (a Register over some other path)
    rig.env.live_control = parse_live_peer("203.0.113.200:50051");
    const auto gen = rig.store.state()->generation;
    const auto o = update(rig.env, true, {ex("10.0.0.5:22/tcp/in")}, dl);
    // the new address is not in the stored set: the host's own rules block it, the update is
    // refused by its verification and the previous generation is put back (README caveat 2:
    // the control set follows the peer at QUARANTINE time, never one that appears later)
    CHECK(o.status == "update_failed");
    CHECK(o.reason == "control_unreachable");
    CHECK(contains(o.notes, "control_proved=live"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->phase == Phase::active);
    CHECK(rig.store.state()->allow.exceptions.empty());
    CHECK(rig.store.state()->generation == gen + 2); // the revert is itself a generation
}

TEST_CASE("repair: a live control peer missing from the stored set is admitted, and the proof is of it",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"198.51.100.7:50051", "203.0.113.200:50051"};
    rig.env.probe = net.fn();
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto stored = rig.store.state()->allow;

    // the server moved after the quarantine; the agent learned the new address over another
    // path; the table is flushed. Re-applying the stored set alone would block the channel
    // the proof connects to, so the repair admits the live peer (published by agents/core).
    rig.env.live_control = parse_live_peer("203.0.113.200:50051");
    rig.world.table = false;
    const auto o = repair(rig.env, dl);
    CHECK(o.status == "active");
    CHECK(contains(o.notes, "repaired=1"));
    CHECK(contains(o.notes, "control_live_peer=203.0.113.200:50051"));
    CHECK(contains(o.notes, "control_proved=live"));
    const auto rec = rig.store.state();
    REQUIRE(rec);
    CHECK(rec->phase == Phase::active);
    CHECK(rec->generation == 2); // one convergence, no revert generation
    REQUIRE(rec->allow.control.size() == stored.control.size() + 1);
    CHECK(rec->allow.control.front() == *rig.env.live_control);
    CHECK(rec->allow.resolvers == stored.resolvers); // nothing else is rewritten
    CHECK(rec->allow.exceptions == stored.exceptions);
    CHECK(rig.world.text.find("203.0.113.200") != std::string::npos); // the host's table admits it
    CHECK(rec->last_verify.starts_with("verified"));
    CHECK(report_status(rig.env, dl).status == "active");

    // a peer already first in the set changes nothing and says nothing
    rig.world.table = false;
    const auto again = repair(rig.env, dl);
    CHECK(again.status == "active");
    CHECK_FALSE(contains(again.notes, "control_live_peer=203.0.113.200:50051"));
    CHECK(rig.store.state()->allow.control == rec->allow.control);
}

TEST_CASE("repair: a retried quarantine over a host that stopped enforcing admits the live peer too",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"198.51.100.7:50051", "203.0.113.200:50051"};
    rig.env.probe = net.fn();
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");
    const auto stored = rig.store.state()->allow;

    // the server moved after the quarantine and the agent learned the new address over another
    // path; the table is flushed. The retried `quarantine` takes the same converge as the tick:
    // it re-applies the STORED set and admits the live peer, which the proof connects to.
    rig.env.live_control = parse_live_peer("203.0.113.200:50051");
    rig.world.table = false;
    const auto o = apply_and_verify(rig.env, rig.request(), dl);
    CHECK(o.status == "active");
    CHECK(contains(o.notes, "repaired=1"));
    CHECK(contains(o.notes, "control_live_peer=203.0.113.200:50051"));
    CHECK(contains(o.notes, "control_proved=live"));
    const auto rec = rig.store.state();
    REQUIRE(rec);
    CHECK(rec->phase == Phase::active);
    CHECK(rec->repairs == 1);
    CHECK(rec->generation == 2); // one convergence, no revert generation
    REQUIRE(rec->allow.control.size() == stored.control.size() + 1);
    CHECK(rec->allow.control.front() == *rig.env.live_control);
    CHECK(rec->allow.resolvers == stored.resolvers); // nothing else is rewritten
    CHECK(rec->allow.exceptions == stored.exceptions);
    CHECK(rig.world.text.find("203.0.113.200") != std::string::npos); // the host's table admits it
}

TEST_CASE("repair: a live peer that would push the control set past the cap is left out, and said",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"198.51.100.1:50051"};
    rig.env.probe = net.fn();
    std::string many;
    for (std::size_t i = 1; i <= kMaxControlIps; ++i)
        many += (many.empty() ? "" : ",") + std::format("198.51.100.{}", i);
    const auto full = build_allow_set(many, "198.51.100.1:50051", {"203.0.113.53"}, {});
    REQUIRE(full);
    ApplyRequest req;
    req.allow = *full;
    req.probe_target = kProbeTarget;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, req, dl).status == "active");

    rig.env.live_control = parse_live_peer("203.0.113.200:50051");
    rig.world.table = false;
    const auto o = repair(rig.env, dl);
    CHECK(contains(o.notes, "control_live_peer_over_cap=1"));
    CHECK_FALSE(contains(o.notes, "control_live_peer=203.0.113.200:50051"));
    REQUIRE(rig.store.state());
    CHECK(rig.store.state()->allow.control == full->control); // never past the cap
    CHECK(rig.world.table);                                  // the repair still re-applied
}

TEST_CASE("repair: a live peer already listed but not first is left where it is -- no note, no reorder",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"198.51.100.7:50051", "198.51.100.8:50051"};
    rig.env.probe = net.fn();
    const auto two = build_allow_set("198.51.100.7,198.51.100.8", "198.51.100.7:50051", {"203.0.113.53"}, {});
    REQUIRE(two);
    REQUIRE(two->control.size() == 2);
    ApplyRequest req;
    req.allow = *two;
    req.probe_target = kProbeTarget;
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, req, dl).status == "active");
    const auto stored = rig.store.state()->allow;

    // the agent is connected through the SECOND listed endpoint; the table is flushed
    rig.env.live_control = parse_live_peer("198.51.100.8:50051");
    REQUIRE(rig.env.live_control);
    REQUIRE(stored.control[1] == *rig.env.live_control);
    rig.world.table = false;
    const auto o = repair(rig.env, dl);
    CHECK(o.status == "active");
    CHECK(contains(o.notes, "repaired=1"));
    CHECK(contains(o.notes, "control_proved=live")); // the proof connects to it wherever it sits
    CHECK_FALSE(contains(o.notes, "control_live_peer=198.51.100.8:50051"));
    CHECK_FALSE(contains(o.notes, "control_live_peer_over_cap=1"));
    const auto rec = rig.store.state();
    REQUIRE(rec);
    CHECK(rec->allow.control == stored.control); // byte-identical, order included
    CHECK(rec->allow.resolvers == stored.resolvers);
    CHECK(rec->generation == 2); // advanced by the repair itself, nothing else
    CHECK(rig.world.table);
}

TEST_CASE("repair: a failed proof keeps what it applied -- one load, no revert, never `active`",
          "[agent][firewall_quarantine]") {
    NftRig rig;
    PeerProbe net;
    net.world = &rig.world;
    net.up = {"198.51.100.7:50051"}; // the live peer below does not answer
    rig.env.probe = net.fn();
    auto dl = rig.dl();
    REQUIRE(apply_and_verify(rig.env, rig.request(), dl).status == "active");

    rig.env.live_control = parse_live_peer("203.0.113.200:50051");
    rig.world.table = false;
    const auto loads = [&] {
        return std::count_if(rig.world.log.begin(), rig.world.log.end(),
                             [](const Argv& a) { return a.size() > 1 && a[1] == "-f"; });
    };
    const auto loads_before = loads();
    const auto o = repair(rig.env, dl);
    CHECK(o.status == "active_unproven");
    CHECK(contains(o.notes, "repaired=1"));
    CHECK(loads() == loads_before + 1); // one apply: a revert would be a second flush per tick
    const auto rec = rig.store.state();
    REQUIRE(rec);
    CHECK(rec->phase == Phase::active);
    CHECK(rec->generation == 2); // no revert generation
    CHECK(rig.world.table);
    // a FRESH proof text, never the stale `verified` the previous generation carried
    CHECK(rec->last_verify.starts_with("control_unreachable"));
    CHECK_FALSE(rec->last_verify.starts_with("verified"));
    CHECK(rec->repairs == 1);

    // the next tick reads the host as enforcing and does nothing: no second load, no save
    const auto saves = rig.store.saves;
    const auto next = repair(rig.env, dl);
    CHECK(next.status == "active_unproven");
    CHECK(loads() == loads_before + 1);
    CHECK(rig.store.saves == saves);
    CHECK(report_status(rig.env, dl).status == "active_unproven");
}
