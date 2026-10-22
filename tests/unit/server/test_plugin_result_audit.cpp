/**
 * test_plugin_result_audit.cpp -- `registry.write` audit rows from the registry plugin's
 * mutating-action output frames (server/core/src/plugin_result_audit.hpp): the pure extractor,
 * event shape and BINDING, then the live ingest on both ingress paths, the per-agent row budget and
 * the weakly held store (Postgres-backed, skipped without YUZU_TEST_POSTGRES_DSN like every store
 * test).
 */
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "audit_store.hpp"
#include "bounded_audit_budget.hpp"
#include "capability_fragments.hpp"
#include "command_capability.hpp"
#include "event_bus.hpp"
#include "execution_event_bus.hpp"
#include "execution_tracker.hpp"
#include "grpc_audit_signal.hpp"
#include "pg/pg_pool.hpp"
#include "plugin_result_audit.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_principal_lock_gate.hpp"
#include "test_tracker_scope.hpp"
#include "web_utils.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
namespace apb = ::yuzu::agent::v1;

namespace {

constexpr std::string_view kOkLine =
    "audit|op=set_value|hive=HKLM|key=SOFTWARE\\Acme|name=Ver|type=REG_DWORD|len=4|result=ok|"
    "reason=-|"
    "verify=ok|dry_run=-|counted_keys=-|counted_values=-|capped=-|sid=-|old_state=present|"
    "old_type=REG_DWORD|old=01000000|new=02000000";

// A space and a non-ASCII byte: only log_id_token maps both, so a sink that printed the raw id or
// used the looser log_token would log a different agent.
const std::string kOddAgent = "agent \xC3\xA9";

/// A command id of the shape the server mints for a command: `<plugin>-<16 hex>`
/// (command_routes.cpp). `plugin` keeps whatever spelling the operator typed.
std::string rid(unsigned n, std::string_view plugin = "registry") {
    return std::string{plugin} + "-" + std::format("{:016x}", n);
}

/// ... and the `<plugin>-<32 hex>` shape dispatch_confined and the scheduled enqueue mint.
std::string rid32(unsigned n) {
    return "registry-" + std::string(16, '0') + rid(n).substr(9);
}

std::size_t count_of(const std::string& text, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = text.find(needle); at != std::string::npos; at = text.find(needle, at + 1))
        ++n;
    return n;
}

std::string line_with_result(std::string_view result, std::string_view dry_run = "-") {
    return "audit|op=delete_key|hive=HKLM|key=K|name=-|type=-|len=-|result=" + std::string{result} +
           "|reason=-|verify=-|dry_run=" + std::string{dry_run} +
           "|counted_keys=1|counted_values=0|capped=0|sid=-|old_state=-|old_type=-|old=-|new=-";
}

/// The one line `text` extracts to.
RegistryAuditLine only_line(std::string_view text) {
    auto r = extract_registry_audit_lines(text);
    REQUIRE(r.lines.size() == 1);
    return std::move(r.lines[0]);
}

} // namespace

// ── extraction ───────────────────────────────────────────────────────────

TEST_CASE("registry audit: only audit| lines are extracted and byte-exact",
          "[server][registry_audit]") {
    const std::string output = "status|ok\n" + std::string{kOkLine} +
                               "\nwarning|something\nnot-audit|x\n audit|leading space\n"
                               "auditx|no pipe after the word\naudit\n";
    const auto r = extract_registry_audit_lines(output);
    REQUIRE(r.lines.size() == 1);
    CHECK(r.lines[0].text == kOkLine);
    CHECK(r.lines[0].ok);
    CHECK_FALSE(r.lines[0].cut);
    CHECK_FALSE(r.truncated);
}

TEST_CASE("registry audit: per-frame bounds and neutralisation", "[server][registry_audit]") {
    SECTION("301 lines give 300 and report that the rest were dropped") {
        std::string output;
        for (int i = 0; i < 301; ++i)
            output += "audit|op=x" + std::to_string(i) + "\n";
        const auto r = extract_registry_audit_lines(output);
        CHECK(r.lines.size() == kMaxRegistryAuditLinesPerFrame);
        CHECK(r.lines.back().text == "audit|op=x299");
        CHECK(r.truncated);
    }
    SECTION("exactly 300 lines, or 300 followed by other text, is not truncation") {
        std::string output;
        for (int i = 0; i < 300; ++i)
            output += "audit|op=x" + std::to_string(i) + "\n";
        CHECK(extract_registry_audit_lines(output).lines.size() == 300);
        CHECK_FALSE(extract_registry_audit_lines(output).truncated);
        output += "status|ok\nnot-audit|x\n";
        CHECK(extract_registry_audit_lines(output).lines.size() == 300);
        CHECK_FALSE(extract_registry_audit_lines(output).truncated);
    }
    SECTION("literal line bounds: 4096 bytes is kept whole and 4097 is cut to exactly 4096") {
        const std::string at_limit = "audit|" + std::string(4090, 'k');
        REQUIRE(at_limit.size() == 4096);
        const auto kept = only_line(at_limit);
        CHECK(kept.text.size() == 4096);
        CHECK_FALSE(kept.cut);
        const auto cut = only_line(at_limit + "k");
        CHECK(cut.text.size() == 4096);
        CHECK(cut.cut);
    }
    SECTION("the cut never lands inside a multi-byte character of 2, 3 or 4 bytes") {
        struct Straddle {
            std::string character;
            std::size_t bytes_before_the_bound;
        };
        const std::vector<Straddle> cases{
            {"\xC3\xA9", 1},         {"\xE2\x82\xAC", 1},     {"\xE2\x82\xAC", 2},
            {"\xF0\x9F\x98\x80", 1}, {"\xF0\x9F\x98\x80", 2}, {"\xF0\x9F\x98\x80", 3}};
        for (const auto& c : cases) {
            INFO("a " << c.character.size() << "-byte character with " << c.bytes_before_the_bound
                      << " byte(s) before the bound");
            const std::size_t start = kMaxRegistryAuditLineBytes - c.bytes_before_the_bound;
            const auto l = only_line("audit|" + std::string(start - 6, 'k') + c.character + "tail");
            CHECK(l.text.size() == start); // the whole character is dropped, none of it is kept
            CHECK(l.cut);
        }
    }
    SECTION("bytes that are not UTF-8 are cut at the bound and not walked back") {
        // Continuation bytes with no lead byte, and a lead byte followed by FOUR continuation bytes
        // (no UTF-8 sequence has that many): the cut is at the bound itself in both.
        const std::string run(kMaxRegistryAuditLineBytes - 5, '\x80');
        const auto bare = only_line("audit|" + run + "tail");
        CHECK(bare.text == "audit|" + run.substr(0, kMaxRegistryAuditLineBytes - 6));
        const auto four = only_line("audit|" + std::string(kMaxRegistryAuditLineBytes - 10, 'k') +
                                    "\xF0\x80\x80\x80\x80tail");
        CHECK(four.text.size() == kMaxRegistryAuditLineBytes);
        CHECK(four.cut);
    }
    SECTION("each of 0x00-0x1F except LF, and 0x7F, becomes '_'; every printable ASCII byte and "
            "UTF-8 is kept") {
        for (int b = 0; b < 0x80; ++b) {
            if (b == 0x0A)
                continue; // the line separator
            std::string out = "audit|x";
            out.push_back(static_cast<char>(b));
            out += "y";
            const bool control = b < 0x20 || b == 0x7F;
            INFO("byte 0x" << std::hex << b);
            const auto l = only_line(out);
            CHECK(l.text == std::string{"audit|x"} + (control ? '_' : static_cast<char>(b)) + "y");
        }
        CHECK(only_line("audit|caf\xC3\xA9 bar").text == "audit|caf\xC3\xA9 bar");
    }
}

TEST_CASE("registry audit: arbitrary endpoint bytes never break the extractor's bounds",
          "[server][registry_audit]") {
    // A seeded, deterministic property check over bytes an endpoint controls. Even frames are
    // random bytes with a rare LF, so a line can pass the byte bound; odd frames are many short
    // audit lines, so a frame can pass the line cap. Whatever arrives: at most 300 lines, none
    // longer than 4096 bytes, each an `audit|` line with no control byte left. The run must also
    // have REACHED both bounds, or the checks pass without testing anything.
    std::mt19937 rng(0x5eed);
    bool ok = true;
    std::size_t cut_lines = 0;
    std::size_t capped_frames = 0;
    for (int i = 0; i < 60 && ok; ++i) {
        std::string out;
        if (i % 2 == 0) {
            for (unsigned parts = 1 + rng() % 4; parts > 0; --parts) {
                if (rng() % 3 != 0)
                    out += "audit|";
                for (unsigned n = rng() % 12000; n > 0; --n) {
                    const char c = static_cast<char>(rng() & 0xFF);
                    out.push_back(rng() % 8192 == 0 ? '\n' : (c == '\n' ? '\r' : c));
                }
                out.push_back('\n');
            }
        } else {
            for (unsigned n = 250 + rng() % 150; n > 0; --n)
                out += "audit|op=" + std::to_string(rng()) + "\n";
        }
        const auto r = extract_registry_audit_lines(out);
        capped_frames += r.truncated ? 1U : 0U;
        ok = r.lines.size() <= kMaxRegistryAuditLinesPerFrame;
        for (const auto& l : r.lines) {
            cut_lines += l.cut ? 1U : 0U;
            ok = ok && l.text.size() <= kMaxRegistryAuditLineBytes &&
                 l.text.starts_with("audit|") &&
                 std::ranges::none_of(l.text,
                                      [](unsigned char c) { return c < 0x20 || c == 0x7F; });
        }
    }
    CHECK(ok);
    CHECK(cut_lines > 0);
    CHECK(capped_frames > 0);
}

TEST_CASE("registry audit: result comes from result= and never from dry_run=",
          "[server][registry_audit]") {
    const auto ev = [](const std::string& l) {
        return make_registry_audit_event("agent-1", rid(77), only_line(l), 1000);
    };
    CHECK(ev(std::string{kOkLine}).result == "success");
    CHECK(ev(line_with_result("ok", "1")).result == "success"); // a dry run that was fine
    CHECK(ev(line_with_result("refused", "1")).result ==
          "failure"); // a refused dry run is a failure
    CHECK(ev(line_with_result("refused", "0")).result == "failure");
    CHECK(ev(line_with_result("failed", "0")).result == "failure");
    CHECK(ev("audit|op=x").result == "failure"); // no result= field: not a success
    CHECK(ev("audit|op=x|result=ok").result == "success"); // result= as the last field
    CHECK(ev("audit|op=x|result=").result == "failure");   // present but empty
    SECTION("the token is matched exactly") {
        CHECK(ev("audit|op=x|result=okay").result == "failure");
        CHECK(ev("audit|op=x|result=OK").result == "failure");
        CHECK(ev("audit|op=x|result=ok_").result == "failure"); // a CR scrubbed to '_'
    }
    SECTION("the delimiter is `|result=`: a value that merely contains result=ok does not count") {
        CHECK(ev("audit|op=set_value|name=result=ok|result=refused").result == "failure");
    }
    SECTION("the FIRST |result= decides, which is why a producer must never emit a `|` in a field") {
        // This pins today's rule, not that input (plugin_result_audit.hpp, FIELD CONTRACT).
        CHECK(ev("audit|op=x|result=refused|reason=a|result=ok").result == "failure");
    }
    SECTION("the result is read from the WHOLE line: a result= past the byte bound is honoured") {
        const std::string line =
            "audit|op=set_value|key=" + std::string(5000, 'k') + "|result=ok|reason=-";
        const auto e = ev(line);
        CHECK(e.result == "success");
        CHECK(e.detail.starts_with("agent=agent-1 cut=1 audit|op=set_value|key=kkk"));
        CHECK(e.detail.find("result=") == std::string::npos); // the tail itself is gone
    }
}

TEST_CASE("registry audit: the AuditEvent shape", "[server][registry_audit]") {
    const auto ev = make_registry_audit_event("agent-1", rid(77), only_line(kOkLine), 1234567890);
    CHECK(ev.timestamp == 1234567890);
    CHECK(ev.principal == "agent:agent-1");
    CHECK(ev.principal_role == "agent");
    CHECK(ev.action == "registry.write");
    // The spelling of the dispatch and outbox rows this command_id joins to (command_routes.cpp,
    // dashboard_routes.cpp, command_outbox_delivery.cpp): the audit query matches it exactly.
    CHECK(ev.target_type == "command");
    CHECK(ev.target_id == rid(77));
    // The trusted token comes FIRST and the endpoint's line after it, so a reader that takes the
    // first `agent=` match (the role.elevation.granted convention) finds the server's.
    CHECK(ev.detail == "agent=agent-1 cut=0 " + std::string{kOkLine});
    CHECK(ev.result == "success");
    SECTION("an agent id with spaces or '=' cannot forge a detail token") {
        const auto e2 = make_registry_audit_event("a b=c", rid(1), only_line(kOkLine), 1);
        CHECK(e2.detail.starts_with("agent=a_b_c cut=0 audit|"));
    }
    SECTION("the id token is log_token's, which keeps the bytes log_id_token would replace") {
        REQUIRE(yuzu::log_token(kOddAgent) != yuzu::log_id_token(kOddAgent));
        const auto e5 = make_registry_audit_event(kOddAgent, rid(1), only_line(kOkLine), 1);
        CHECK(e5.detail.starts_with("agent=" + yuzu::log_token(kOddAgent) + " cut=0 audit|"));
    }
    SECTION("an agent= token inside the endpoint's own line is never the first one") {
        const auto e3 = make_registry_audit_event(
            "agent-1", rid(77),
            only_line("audit|op=set_value|result=ok|reason=x agent=evil|new=1"), 1);
        CHECK(e3.detail.starts_with("agent=agent-1 cut=0 audit|"));
        CHECK(e3.detail.find("agent=") == 0U);
        CHECK(e3.detail.find("agent=evil") == e3.detail.rfind("agent="));
        CHECK(e3.detail.find("agent=evil") > 0U);
    }
    SECTION("a cut= token inside the endpoint's own line is never the first one") {
        // Uncut: the server states cut=0, so the endpoint's ` cut=1` is not the first match.
        const auto uncut = make_registry_audit_event(
            "agent-1", rid(77), only_line("audit|op=set_value|result=ok|reason=x cut=1|new=1"), 1);
        CHECK(uncut.detail.starts_with("agent=agent-1 cut=0 audit|"));
        CHECK(uncut.detail.find("cut=") == std::string{"agent=agent-1 "}.size());
        CHECK(uncut.detail.find("cut=1") > uncut.detail.find("cut=0"));
        // Cut: the endpoint's ` cut=0` inside the kept prefix is not the first match either.
        const auto cut = make_registry_audit_event(
            "agent-1", rid(77),
            only_line("audit|op=x|reason=cut=0 " + std::string(5000, 'k')), 1);
        CHECK(cut.detail.starts_with("agent=agent-1 cut=1 audit|"));
        CHECK(cut.detail.find("cut=") == std::string{"agent=agent-1 "}.size());
    }
    SECTION("a cut line says so, right after the server's own token") {
        const auto e4 = make_registry_audit_event(
            "agent-1", rid(77), only_line("audit|op=x|key=" + std::string(5000, 'k')), 1);
        CHECK(e4.detail.starts_with("agent=agent-1 cut=1 audit|op=x|key=kkk"));
    }
}

// ── the binding ──────────────────────────────────────────────────────────

TEST_CASE("registry audit: only the three mutating actions of the registry plugin mint rows",
          "[server][registry_audit]") {
    const std::string output = "status|ok\n" + std::string{kOkLine} + "\n";
    const auto events = [&](std::string_view plugin, std::string_view action) {
        return registry_audit_events_for_frame("agent-1", rid(9), plugin, action, output, 5)
            .events;
    };
    for (const char* a : {"set_value", "delete_value", "delete_key"}) {
        INFO(a);
        CHECK(events("registry", a).size() == 1);
        CHECK(is_registry_mutating_action(a));
    }
    SECTION("read actions, an empty action (an old agent) and unknown actions mint nothing") {
        for (const char* a :
             {"get_value", "key_exists", "enumerate_keys", "enumerate_values", "get_user_value",
              "list_profiles", "", "Set_Value", "set_value ", "bogus"}) {
            INFO("[" << a << "]");
            CHECK(events("registry", a).empty());
            CHECK_FALSE(is_registry_mutating_action(a));
        }
    }
    SECTION("another plugin with a mutating-looking action mints nothing") {
        CHECK(events("filesystem", "set_value").empty());
        CHECK(events("", "set_value").empty());
        CHECK(events("registry2", "set_value").empty());
    }
    SECTION("each extracted line becomes its own row") {
        const std::string two = std::string{kOkLine} + "\n" + line_with_result("refused") + "\n";
        CHECK(registry_audit_events_for_frame("agent-1", rid(9), "registry", "delete_key", two, 5)
                  .events.size() == 2);
    }
    SECTION("the plugin compares ASCII-case-insensitively: a RAW `Registry` request still runs the "
            "write") {
        // command_routes.cpp mints the id from the spelling the operator typed; the agent runs the
        // catalogue's.
        for (const char* spelling : {"Registry", "REGISTRY", "rEgIsTrY"}) {
            const auto id = rid(9, spelling);
            INFO(id);
            CHECK(registry_audit_events_for_frame("agent-1", id, extract_plugin(id), "set_value",
                                                  output, 5)
                      .events.size() == 1);
        }
        CHECK(events("registr", "set_value").empty());
        CHECK(events("registry ", "set_value").empty());
    }
}

TEST_CASE("registry audit: only an id of the exact shape the server mints can mint rows",
          "[server][registry_audit]") {
    // The id becomes every row's target_id, so a shape the server never mints is not accepted: a
    // 3 MiB id times 300 lines was ~943 MB resident, and a target_id past ~2.7 KB is rejected by
    // idx_audit_target_ts. The shape is still only a shape: the rows are asserted by the agent.
    const std::string output = std::string{kOkLine} + "\n";
    const auto frame = [&](const std::string& id) {
        return registry_audit_events_for_frame("agent-1", id, "registry", "set_value", output, 5);
    };
    SECTION("both minted widths mint, and the row names the id as given") {
        CHECK(frame(rid(9)).events.size() == 1);
        CHECK(frame(rid32(9)).events.size() == 1);
        REQUIRE(frame(rid(9)).events.size() == 1);
        CHECK(frame(rid(9)).events[0].target_id == rid(9));
        CHECK(frame("registry-0123456789abcdef").events.size() == 1);
        CHECK(frame("registry-0123456789abcdef0123456789abcdef").events.size() == 1);
    }
    SECTION("the plugin name keeps the operator's spelling") {
        for (const char* spelling : {"Registry", "REGISTRY", "rEgIsTrY"})
            CHECK(frame(rid(9, spelling)).events.size() == 1);
    }
    SECTION("every other shape mints nothing and is reported") {
        std::vector<std::string> bad{
            "",
            "registry",
            "registry-",
            "registry-9",
            "registry-1700000000",
            "registry-0123456789abcde",                   // 15 hex
            "registry-0123456789abcdef0",                 // 17 hex
            "registry-0123456789abcdef0123456789abcde",   // 31 hex
            "registry-0123456789abcdef0123456789abcdef0", // 33 hex
            "registry-0123456789ABCDEF",                  // the server mints lowercase
            "registry-zzzzzzzzzzzzzzzz",                  // 16 characters, not hex
            "registry-0123456789abcdef ",                 // trailing space
            "registry-0123456789abcdef\n",
            "registry\r0123456789abcdef", // 0x0D | 0x20 == '-'
            "registry_0123456789abcdef",
            "registry-ext-0123456789abcdef",
            "registry-\x1b[2J0123456789a",
            "registry-\xC3\xA9"
            "0123456789abcdef",
            "registrz-0123456789abcdef", // one byte off the plugin name
        };
        // A bad character first, in the middle and last of both widths: the neighbours of the three
        // hex ranges, an upper-case digit and a space.
        for (const std::size_t width : {std::size_t{16}, std::size_t{32}})
            for (const char c : std::string_view{"/:@`gAF "})
                for (const std::size_t at : {std::size_t{0}, width / 2, width - 1}) {
                    std::string tail(width, '0');
                    tail[at] = c;
                    bad.push_back("registry-" + tail);
                }
        for (const auto& id : bad) {
            INFO("[" << id << "]");
            const auto f = frame(id);
            CHECK(f.events.empty());
            CHECK(f.unmintable_id);
        }
        const std::string huge(3U << 20, 'k');
        CHECK(frame(huge).events.empty());
    }
    SECTION("an id that does not name the registry plugin is not this binding's business") {
        CHECK(is_minted_registry_command_id(rid(1)));
        CHECK_FALSE(is_minted_registry_command_id(rid(1, "filesystem")));
        CHECK_FALSE(is_minted_registry_command_id(rid(1, "registryx")));
    }
}

TEST_CASE("registry audit: the frame verdict flags what was ignored or dropped",
          "[server][registry_audit]") {
    const std::string one = std::string{kOkLine} + "\n";
    std::string many;
    for (int i = 0; i < 301; ++i)
        many += one;
    const auto frame = [](std::string_view id, std::string_view plugin, std::string_view action,
                          const std::string& output) {
        return registry_audit_events_for_frame("agent-1", id, plugin, action, output, 5);
    };
    SECTION("a registry mutating frame whose id the server could not have minted is flagged") {
        const auto f = frame("registry-9 x", "registry", "set_value", one);
        CHECK(f.unmintable_id);
        CHECK(f.events.empty());
        CHECK_FALSE(f.truncated);
    }
    SECTION("a frame that is not registry-and-mutating is never flagged whatever its id") {
        CHECK_FALSE(frame("registry-9 x", "registry", "get_value", one).unmintable_id);
        CHECK_FALSE(frame("registry-9 x", "registry", "", one).unmintable_id);
        CHECK_FALSE(frame("filesystem-9 x", "filesystem", "set_value", one).unmintable_id);
    }
    SECTION("a minted id is not flagged and writes its row") {
        const auto f = frame(rid(9), "registry", "set_value", one);
        CHECK_FALSE(f.unmintable_id);
        CHECK_FALSE(f.truncated);
        CHECK(f.events.size() == 1);
    }
    SECTION("301 audit lines give 300 rows and the truncation flag") {
        const auto f = frame(rid(9), "registry", "delete_key", many);
        CHECK(f.events.size() == 300);
        CHECK(f.truncated);
        CHECK_FALSE(f.unmintable_id);
    }
    SECTION("a line over the byte bound is also a truncation, and its row says it was cut") {
        const auto f = frame(rid(9), "registry", "set_value",
                             "audit|op=x|key=" + std::string(5000, 'k') + "|result=ok\n");
        REQUIRE(f.events.size() == 1);
        CHECK(f.truncated);
        CHECK(f.events[0].detail.starts_with("agent=agent-1 cut=1 "));
        CHECK(f.events[0].result == "success");
    }
    SECTION("truncation is only reported for a frame that would have been audited") {
        CHECK_FALSE(frame(rid(9), "registry", "get_value", many).truncated);
        CHECK_FALSE(frame("registry-9 x", "registry", "set_value", many).truncated);
    }
}

TEST_CASE("registry audit: the mutating-action list matches the capability catalogue's "
          "non-ReadOnly registry rows in every fragment",
          "[server][registry_audit]") {
    // A mutating registry action added to the catalogue but not to kRegistryMutatingActions would
    // run unaudited; this ties the two lists together across ALL fragments, not just the one the
    // registry rows sit in today.
    std::size_t registry_rows = 0, mutating_rows = 0;
    for (const std::span<const CommandCapability> fragment : {YUZU_ALL_CAPABILITY_FRAGMENTS}) {
        for (const auto& r : fragment) {
            if (r.plugin != "registry")
                continue;
            ++registry_rows;
            const bool mutating = r.dispatch_class != DispatchClass::ReadOnly;
            if (mutating)
                ++mutating_rows;
            INFO("registry." << r.action);
            CHECK(is_registry_mutating_action(r.action) == mutating);
        }
    }
    CHECK(registry_rows == 9);
    CHECK(mutating_rows == kRegistryMutatingActions.size());
}

// ── the per-agent budget ─────────────────────────────────────────────────

TEST_CASE("registry audit budget: 600 rows per agent per window keyed on the whole agent id",
          "[server][registry_audit]") {
    std::int64_t now_ms = 5'000;
    const auto budget = make_registry_audit_budget([&now_ms] { return now_ms; });
    const auto admit = [&](const std::string& id) {
        return budget->try_admit(id, registry_audit_overflow_key(id)).admitted;
    };
    SECTION("the documented numbers: 600 rows, then refused, a window later again") {
        // The two table sizes the documents quote.
        CHECK(kRegistryAuditBudgetAgents == 262'144);
        CHECK(kRegistryAuditOverflowBuckets == 65'536);
        for (int i = 0; i < 600; ++i)
            REQUIRE(admit("agent-a"));
        CHECK_FALSE(admit("agent-a"));
        CHECK(admit("agent-b")); // another agent has its own allowance
        now_ms += 59'999;
        CHECK_FALSE(admit("agent-a"));
        now_ms += 1;
        CHECK(admit("agent-a"));
    }
    SECTION("ids that share their first 99 or 255 bytes are different agents") {
        // The shared primitive keys on 96 bytes by default; an agent id runs to 256.
        for (const std::size_t size : {std::size_t{100}, std::size_t{256}}) {
            const std::string a = std::string(size - 1, 'k') + 'a';
            const std::string b = std::string(size - 1, 'k') + 'b';
            for (int i = 0; i < 600; ++i)
                REQUIRE(admit(a));
            CHECK_FALSE(admit(a));
            CHECK(admit(b));
        }
    }
    SECTION("agents past the exact table are spread over many allowances, not pooled in one") {
        std::size_t refused = 0;
        for (std::size_t i = 0; i < kRegistryAuditBudgetAgents + 40'000; ++i)
            refused += admit("agent-" + std::to_string(i)) ? 0U : 1U;
        CHECK(refused == 0);
    }
}

// ── the live ingest (gateway ingress) ────────────────────────────────────

namespace {

yuzu::test::PgTestTemplate registry_audit_tpl{
    "agentaudit", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        AuditStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("agentaudit template: store failed to migrate");
    }};

// The shared "agentaudit" key is audit-only; the tracker's schema gets a template of its own.
yuzu::test::PgTestTemplate registry_audit_exec_tpl{
    "regauditexec", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        AuditStore audit{pool};
        ExecutionTracker tracker{pool};
        if (!audit.is_open() || !tracker.is_open())
            throw std::runtime_error("regauditexec template: a store failed to migrate");
    }};

/// MEMBER ORDER LOAD-BEARING (see GatewayResponseHarness in test_agent_service_impl.cpp): `svc`
/// holds `audit` weakly and locks it per frame, so `audit` and its pool are declared BEFORE it and
/// outlive it. Only the weak reference is wired: a hook that read the raw `audit_store_` instead
/// would find nothing and write no row, which every positive case here would notice.
struct IngestHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    yuzu::server::pg::PgPool pool;
    std::shared_ptr<AuditStore> audit;
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};

    explicit IngestHarness(const std::string& dsn) : pool({.conninfo = dsn, .size = 4}) {
        audit = std::make_shared<AuditStore>(pool);
        REQUIRE(audit->is_open());
        svc.set_registry_audit_store(audit);
    }
    static apb::CommandResponse frame(const std::string& command_id,
                                      apb::CommandResponse::Status status,
                                      const std::string& action, const std::string& output) {
        apb::CommandResponse r;
        r.set_command_id(command_id);
        r.set_status(status);
        r.set_action(action);
        r.set_output(output);
        return r;
    }
    std::vector<AuditEvent> rows() {
        AuditQuery q;
        q.action = "registry.write";
        q.limit = 1000;
        auto r = audit->query(q);
        REQUIRE(r.has_value());
        return *r;
    }
    /// yuzu_server_registry_audit_dropped_total{reason}
    double dropped(const char* reason) {
        return metrics.counter("yuzu_server_registry_audit_dropped_total", {{"reason", reason}})
            .value();
    }
};

} // namespace

TEST_CASE("registry audit live ingest: a RUNNING frame with output then the empty terminal gives "
          "ONE row",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());

    const std::string output =
        "audit|op=set_value|hive=HKLM|key=K|name=V|type=REG_DWORD|len=4|result=ok|reason=-|"
        "verify=ok|dry_run=-|counted_keys=-|counted_values=-|capped=-|sid=-|old_state=absent|"
        "old_type=-|old=-|new=01000000\nstatus|ok";
    const auto before = now_epoch_seconds();
    h.svc.process_gateway_response(
        "agent-1",
        IngestHarness::frame(rid(1), apb::CommandResponse::RUNNING, "set_value", output));
    // The agent's terminal frame carries NO output.
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(1), apb::CommandResponse::SUCCESS, "set_value", ""));
    const auto after = now_epoch_seconds();
    const auto rows = h.rows();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].action == "registry.write");
    CHECK(rows[0].principal == "agent:agent-1");
    CHECK(rows[0].principal_role == "agent");
    CHECK(rows[0].target_type == "command");
    CHECK(rows[0].target_id == rid(1));
    CHECK(rows[0].result == "success");
    CHECK(rows[0].timestamp >= before);
    CHECK(rows[0].timestamp <= after);
    CHECK(rows[0].detail.starts_with(
        "agent=agent-1 cut=0 audit|op=set_value|hive=HKLM|key=K|name=V|"));
    CHECK(rows[0].detail.find("status|ok") ==
          std::string::npos); // only the audit line, not the output
    CHECK(h.dropped("suppressed") == 0.0);
    CHECK(h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0})); // the hook left its gate
}

TEST_CASE("registry audit live ingest: a refused write is a failure row and read actions and old "
          "agents write none",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    const std::string refused = line_with_result("refused", "1") + "\nerror|key_has_subkeys";

    h.svc.process_gateway_response(
        "agent-1",
        IngestHarness::frame(rid(5), apb::CommandResponse::RUNNING, "delete_key", refused));
    CHECK(h.rows().size() == 1);
    CHECK(h.rows()[0].result == "failure");

    // The same bytes under a READ action, an empty action (an agent that stamps none) and another
    // plugin.
    h.svc.process_gateway_response(
        "agent-1",
        IngestHarness::frame(rid(6), apb::CommandResponse::RUNNING, "get_value", refused));
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(7), apb::CommandResponse::RUNNING, "", refused));
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(8, "filesystem"), apb::CommandResponse::RUNNING,
                                        "delete_key", refused));
    CHECK(h.rows().size() == 1);
}

TEST_CASE("registry audit live ingest: a terminal frame that does carry output still owes its rows",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    h.svc.process_gateway_response(
        "agent-2", IngestHarness::frame(rid(9), apb::CommandResponse::FAILURE, "delete_key",
                                        line_with_result("failed") + "\nerror|partial_failure"));
    const auto rows = h.rows();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].principal == "agent:agent-2");
    CHECK(rows[0].result == "failure");
}

TEST_CASE("registry audit live ingest: fan-out agents each get their own row for one command_id",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    for (const char* agent : {"agent-a", "agent-b", "agent-c"})
        h.svc.process_gateway_response(
            agent, IngestHarness::frame(rid32(4), apb::CommandResponse::RUNNING, "delete_value",
                                        std::string{kOkLine}));
    const auto rows = h.rows();
    CHECK(rows.size() == 3);
    std::vector<std::string> who;
    for (const auto& r : rows)
        who.push_back(r.principal);
    std::sort(who.begin(), who.end());
    CHECK(who == std::vector<std::string>{"agent:agent-a", "agent:agent-b", "agent:agent-c"});
}

TEST_CASE("registry audit live ingest: no audit store means no audit work and no log line",
          "[server][registry_audit]") {
    // server.cpp leaves the store unwired whenever audit is off, and the owner resets it at
    // shutdown: the registry hook holds it weakly and finds nothing to lock.
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};

    yuzu::test::LogCapture cap;
    svc.process_gateway_response("agent-1",
                                 IngestHarness::frame(rid(0xa1), apb::CommandResponse::RUNNING,
                                                      "set_value", std::string{kOkLine}));
    svc.process_gateway_response("agent-1",
                                 IngestHarness::frame(rid(0xa1), apb::CommandResponse::FAILURE,
                                                      "delete_key", std::string{kOkLine}));
    cap.stop();
    const std::string text = cap.text();
    // The capture is live (the terminal frame logs its completion at info), so the absence below
    // is a real absence and not a sink that saw nothing.
    CHECK(count_of(text, "[gateway] Command " + rid(0xa1) + " completed") == 1);
    CHECK(text.find("registry.write") == std::string::npos);
    // The hook entered its gate before it found no store, and left again.
    CHECK(svc.wait_registry_audit_idle(std::chrono::milliseconds{0}));
}

TEST_CASE("registry audit live ingest: a store its owner has reset is neither used nor required "
          "to be alive",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    // What ServerImpl::stop() does to the owner: drop the owning reference. The service keeps only
    // the weak reference, which now expires. (This shows an expired store is handled; that a hook
    // cannot outlive the object is structural: the weak member, locked per frame, which the lexical
    // gate pins.)
    h.audit.reset();
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(2), apb::CommandResponse::RUNNING, "set_value",
                                        std::string{kOkLine}));
    cap.stop();
    CHECK(cap.text().find("registry.write") == std::string::npos);
    // Nothing was written: a second, independent store over the same pool sees no row.
    AuditStore reader{h.pool};
    AuditQuery q;
    q.action = "registry.write";
    const auto rows = reader.query(q);
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
}

TEST_CASE("registry audit live ingest: a store that fails ends the frame at the first row",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    yuzu::test::SqlFault fault(h.pool,
                               "ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone",
                               "ALTER TABLE audit_store.audit_events_gone RENAME TO audit_events");
    fault.arm();
    const auto before = h.audit->emit_failed_count();
    const std::string one{kOkLine};
    const std::string three = one + "\n" + one + "\n" + one;
    const std::string& agent = kOddAgent;
    const std::string who = yuzu::log_id_token(agent);
    REQUIRE(who != yuzu::log_token(agent));
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        agent, IngestHarness::frame(rid(0xf1), apb::CommandResponse::RUNNING, "set_value", three));
    // The terminal gateway site runs the same hook.
    h.svc.process_gateway_response(
        agent, IngestHarness::frame(rid(0xf2), apb::CommandResponse::FAILURE, "set_value", three));
    cap.stop();
    CHECK(h.audit->emit_failed_count() - before ==
          2); // one INSERT per frame: the other rows were not attempted
    fault.repair();
    CHECK(h.rows().empty());
    CHECK(h.dropped("persist_failed") == 6.0); // all three rows of both frames

    const std::string text = cap.text();
    const auto count = [&](const std::string& needle) { return count_of(text, needle); };
    // The hook's failure line: once per frame, at error level, naming the agent, the command and
    // the two rows that were not attempted. (The store logs a diagnostic of its own for the failed
    // INSERT; that line is the store's, not the hook's.)
    for (const auto& id : {rid(0xf1), rid(0xf2)})
        CHECK(count("[error] [audit] registry.write row failed to persist (agent=" + who +
                    ", command=" + id + "); 2 further row(s) of this frame not attempted") == 1);
    // The gateway path has no trailer and the hook's line is its signal: the gateway sites add no
    // second line of their own.
    CHECK(count("[gateway] registry.write audit row failed to persist") == 0);
    // a failed write leaves its gate too
    CHECK(h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0}));
}

TEST_CASE("registry audit live ingest: a row that fails after earlier ones keeps the earlier ones",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    // Only the SECOND line carries the marker the constraint refuses.
    yuzu::test::SqlFault fault(
        h.pool,
        "ALTER TABLE audit_store.audit_events ADD CONSTRAINT registry_audit_boom CHECK (detail NOT "
        "LIKE '%boom%')",
        "ALTER TABLE audit_store.audit_events DROP CONSTRAINT registry_audit_boom");
    fault.arm();
    const auto before = h.audit->emit_failed_count();
    const std::string output = std::string{kOkLine} + "\naudit|op=set_value|key=boom|result=ok\n" +
                               std::string{kOkLine} + "\n";
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        "agent-1",
        IngestHarness::frame(rid(0xb1), apb::CommandResponse::RUNNING, "set_value", output));
    cap.stop();
    fault.repair();
    CHECK(h.rows().size() == 1); // the first row persisted, the failing second ended the frame
    CHECK(h.audit->emit_failed_count() - before == 1);
    CHECK(h.dropped("persist_failed") == 2.0); // the failed row and the one not attempted
    CHECK(count_of(cap.text(), "(agent=agent-1, command=" + rid(0xb1) +
                                   "); 1 further row(s) of this frame not attempted") == 1);
}

namespace {

/// Four rows from one agent; the budget admits ONE row per window and its clock raises on the THIRD
/// call. Row 0 is written, row 1 is refused, row 2 raises: rows 2 and 3 are owed and lost. `threw`
/// completes the error line the hook logs for what was raised.
void check_a_raising_hook(const std::string& dsn, const std::function<void()>& raise,
                          const std::string& threw) {
    int clock_calls = 0; // outlives the harness: the budget's clock reads it
    bool inside_seen = false;
    IngestHarness h(dsn);
    h.svc.set_registry_audit_budget(std::make_unique<DenialAuditBudget>(
        /*max_rows=*/1, /*window_ms=*/60'000,
        [&] {
            // The hook is inside its gate for the whole frame, so a 0 ms wait must fail here.
            if (clock_calls == 0)
                inside_seen = !h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0});
            if (++clock_calls == 3)
                raise();
            return std::int64_t{1'000};
        },
        /*max_keys=*/8));
    const std::string one{kOkLine};
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xa2), apb::CommandResponse::RUNNING, "set_value",
                                        one + "\n" + one + "\n" + one + "\n" + one));
    cap.stop();
    CHECK(h.rows().size() == 1);
    CHECK(h.dropped("suppressed") == 1.0);     // row 1
    CHECK(h.dropped("persist_failed") == 2.0); // rows 2 and 3
    const std::string text = cap.text();
    const std::string ids = " (agent=agent-1, command=" + rid(0xa2) + ")";
    CHECK(count_of(text, "[audit] registry.write hook threw" + threw + ids) == 1);
    // The hook's own line is the only report of the gap.
    CHECK(count_of(text, "[gateway] registry.write audit row failed to persist") == 0);
    // It was inside its gate while it raised, and a raise does not keep it there.
    CHECK(inside_seen);
    CHECK(h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0}));
}

} // namespace

TEST_CASE("registry audit live ingest: a std::exception inside the hook is a failed write with "
          "every row accounted for",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    check_a_raising_hook(db.dsn(), [] { throw std::runtime_error("clock failed"); },
                         ": clock failed");
}

TEST_CASE("registry audit live ingest: something that is not a std::exception inside the hook is "
          "the same",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    check_a_raising_hook(db.dsn(), [] { throw 42; }, "");
}

TEST_CASE("registry audit live ingest: a frame's rows are written or refused or lost and the three "
          "add up",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    std::int64_t now_ms = 1'000; // outlive the harness: the budget's clock reads them
    int clock_calls = 0;
    IngestHarness h(db.dsn());
    // One row per agent per window, and the window rolls over on the THIRD call: row 0 is written,
    // row 1 refused, row 2 admitted in the next window and then refused by the store (the SQL
    // constraint below), row 3 not attempted.
    h.svc.set_registry_audit_budget(std::make_unique<DenialAuditBudget>(
        /*max_rows=*/1, /*window_ms=*/60'000,
        [&] {
            if (++clock_calls == 3)
                now_ms += 60'000;
            return now_ms;
        },
        /*max_keys=*/8));
    yuzu::test::SqlFault fault(
        h.pool,
        "ALTER TABLE audit_store.audit_events ADD CONSTRAINT registry_audit_boom CHECK (detail NOT "
        "LIKE '%boom%')",
        "ALTER TABLE audit_store.audit_events DROP CONSTRAINT registry_audit_boom");
    fault.arm();
    const std::string one{kOkLine};
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        "agent-1",
        IngestHarness::frame(rid(0xb2), apb::CommandResponse::RUNNING, "set_value",
                             one + "\n" + one + "\naudit|op=set_value|key=boom|result=ok\n" + one));
    cap.stop();
    fault.repair();
    CHECK(h.rows().size() == 1);
    CHECK(h.dropped("suppressed") == 1.0);     // row 1
    CHECK(h.dropped("persist_failed") == 2.0); // row 2, which failed, and row 3, not attempted
    CHECK(count_of(cap.text(), "in the last window: 1") == 1);
    CHECK(count_of(cap.text(), "); 1 further row(s) of this frame not attempted") == 1);
}

// ── the shutdown rundown ──────────────────────────────────────────────────

namespace {

/// Four rows from one agent through a budget that never refuses, whose clock closes the hook (what
/// ServerImpl::stop() does) on its `close_at`-th call, on the hook's own thread. The clock runs
/// once per row, in the charge and before the check that precedes the write, so closing on call N
/// keeps rows 0..N-2 and loses N-1..3. It also asks, on the first call, whether the hook is inside
/// its gate.
void check_a_close_mid_frame(const std::string& dsn, int close_at, std::size_t kept) {
    int clock_calls = 0; // outlives the harness: the budget's clock reads it
    bool inside_seen = false;
    IngestHarness h(dsn);
    h.svc.set_registry_audit_budget(std::make_unique<DenialAuditBudget>(
        /*max_rows=*/100, /*window_ms=*/60'000,
        [&] {
            ++clock_calls;
            if (clock_calls == 1)
                inside_seen = !h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0});
            if (clock_calls == close_at)
                h.svc.close_registry_audit(); // never waits, so it cannot wait for itself
            return std::int64_t{1'000};
        },
        /*max_keys=*/8));
    constexpr std::size_t kRows = 4;
    std::string rows_text{kOkLine};
    for (std::size_t i = 1; i < kRows; ++i)
        rows_text += "\n" + std::string{kOkLine};
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xc3), apb::CommandResponse::RUNNING, "set_value",
                                        rows_text));
    cap.stop();
    const std::size_t lost = kRows - kept;
    CHECK(inside_seen);
    CHECK(h.rows().size() == kept);
    CHECK(h.dropped("persist_failed") == static_cast<double>(lost));
    CHECK(h.dropped("suppressed") == 0.0);
    const std::string text = cap.text();
    const std::string ids = " (agent=agent-1, command=" + rid(0xc3) + ")";
    CHECK(count_of(text, "[audit] registry.write frame cut short by shutdown" + ids + "; " +
                             std::to_string(lost) + " row(s) not recorded") == 1);
    // The hook's own line is the only report of the gap.
    CHECK(count_of(text, "[gateway] registry.write audit row failed to persist") == 0);
    CHECK(h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0})); // and the hook left
}

} // namespace

TEST_CASE("registry audit live ingest: shutdown closing the hook mid-frame keeps the rows written "
          "and counts the rest",
          "[pg][server][registry_audit][rundown]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    SECTION("closed during the third row's charge: two rows are kept") {
        check_a_close_mid_frame(db.dsn(), /*close_at=*/3, /*kept=*/2);
    }
    SECTION("closed during the first row's charge: none is written") {
        check_a_close_mid_frame(db.dsn(), /*close_at=*/1, /*kept=*/0);
    }
}

TEST_CASE("registry audit live ingest: a row the budget refuses stays suppressed when shutdown "
          "closes the hook",
          "[pg][server][registry_audit][rundown]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    int clock_calls = 0; // outlives the harness: the budget's clock reads it
    IngestHarness h(db.dsn());
    // One row per window: row 0 is written and rows 1-3 are refused. The clock closes the hook
    // during row 1's charge, so the close lands while every remaining row is already a budget
    // refusal. A refused row never reaches the pool, so the close changes nothing for it: it
    // stays `suppressed`, nothing is booked as lost to the shutdown, and the hook reports success.
    h.svc.set_registry_audit_budget(std::make_unique<DenialAuditBudget>(
        /*max_rows=*/1, /*window_ms=*/60'000,
        [&] {
            if (++clock_calls == 2)
                h.svc.close_registry_audit();
            return std::int64_t{1'000};
        },
        /*max_keys=*/8));
    const std::string one{kOkLine};
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xc4), apb::CommandResponse::RUNNING, "set_value",
                                        one + "\n" + one + "\n" + one + "\n" + one));
    cap.stop();
    CHECK(h.rows().size() == 1);
    CHECK(h.dropped("suppressed") == 3.0);
    CHECK(h.dropped("persist_failed") == 0.0);
    CHECK(count_of(cap.text(), "cut short by shutdown") == 0);
    CHECK(h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0}));
}

TEST_CASE("registry audit live ingest: rows refused before a shutdown close stay suppressed and the "
          "rows after it are counted lost",
          "[pg][server][registry_audit][rundown]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    int clock_calls = 0; // outlives the harness: the budget's clock reads it
    IngestHarness h(db.dsn());
    // One row per 1 s window. Row 0 is written (call 1), row 1 is refused (call 2), and the clock
    // closes the hook on call 3 while moving into a new window, so row 2 is admitted and then
    // finds the gate closed. The closed branch must book what it has not attempted (rows 2 and 3)
    // as lost to the shutdown and keep the earlier refusal as `suppressed`: the three counters
    // plus the written row add up to the four rows the frame owed.
    h.svc.set_registry_audit_budget(std::make_unique<DenialAuditBudget>(
        /*max_rows=*/1, /*window_ms=*/1'000,
        [&] {
            ++clock_calls;
            if (clock_calls == 3)
                h.svc.close_registry_audit();
            return clock_calls <= 2 ? std::int64_t{1'000} : std::int64_t{3'000};
        },
        /*max_keys=*/8));
    const std::string one{kOkLine};
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xc5), apb::CommandResponse::RUNNING, "set_value",
                                        one + "\n" + one + "\n" + one + "\n" + one));
    cap.stop();
    CHECK(h.rows().size() == 1);
    CHECK(h.dropped("suppressed") == 1.0);
    CHECK(h.dropped("persist_failed") == 2.0);
    CHECK(count_of(cap.text(), "; 2 row(s) not recorded") == 1);
    CHECK(h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0}));
}

TEST_CASE("registry audit live ingest: a frame after the shutdown close records and counts nothing",
          "[pg][server][registry_audit][rundown]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    h.svc.close_registry_audit();
    h.svc.close_registry_audit(); // idempotent
    std::string over_the_cap;
    for (int i = 0; i < 301; ++i)
        over_the_cap += std::string{kOkLine} + "\n";
    yuzu::test::LogCapture cap;
    // While the hook is open each of these writes a row or moves a counter: a minted id, an id the
    // server could not have minted (`unmintable_id`) and a frame past the line cap (`truncated`).
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xc1), apb::CommandResponse::RUNNING, "set_value",
                                        std::string{kOkLine}));
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame("registry-oops", apb::CommandResponse::RUNNING, "set_value",
                                        std::string{kOkLine}));
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xc2), apb::CommandResponse::RUNNING, "set_value",
                                        over_the_cap));
    // A terminal frame that owes rows too; it also proves the capture is live (it logs at info).
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xc1), apb::CommandResponse::FAILURE, "delete_key",
                                        std::string{kOkLine}));
    cap.stop();
    CHECK(count_of(cap.text(), "[gateway] Command " + rid(0xc1) + " completed") == 1);
    CHECK(cap.text().find("registry.write") == std::string::npos);
    CHECK(h.rows().empty());
    for (const char* reason : {"suppressed", "persist_failed", "unmintable_id", "truncated"})
        CHECK(h.dropped(reason) == 0.0);
    CHECK(h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0}));
}

TEST_CASE("registry audit live ingest: agents past the exact table are charged to their own "
          "allowances",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    std::int64_t now_ms = 1'000; // outlives the harness: the budget's clock reads it
    IngestHarness h(db.dsn());
    // Eight exact slots of three rows: the first eight agents have a slot, the next eight fall into
    // overflow allowances, which the hook names by agent. Charged without a name they would share
    // ONE allowance of three rows (11 rows written, not 16).
    h.svc.set_registry_audit_budget(std::make_unique<DenialAuditBudget>(
        /*max_rows=*/3, /*window_ms=*/60'000, [&now_ms] { return now_ms; }, /*max_keys=*/8,
        kRegistryAuditBudgetKeyBytes));
    for (unsigned i = 0; i < 16; ++i)
        h.svc.process_gateway_response(
            "agent-" + std::to_string(i),
            IngestHarness::frame(rid(0x60 + i), apb::CommandResponse::RUNNING, "set_value",
                                 std::string{kOkLine}));
    CHECK(h.rows().size() == 16);
    CHECK(h.dropped("suppressed") == 0.0);
}

TEST_CASE(
    "registry audit live ingest: an unmintable command_id warns once per frame and only when the "
    "frame was registry-and-mutating",
    "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    const std::string& agent = kOddAgent;
    REQUIRE(yuzu::log_id_token(agent) != yuzu::log_token(agent));
    const std::string ignored =
        "[audit] registry.write frame ignored: command_id is not a server-minted shape "
        "(agent=" +
        yuzu::log_id_token(agent) + ", ";
    const auto warns = [&](const std::string& command_id, const std::string& action) {
        yuzu::test::LogCapture cap;
        h.svc.process_gateway_response(agent, IngestHarness::frame(command_id,
                                                                   apb::CommandResponse::RUNNING,
                                                                   action, std::string{kOkLine}));
        cap.stop();
        const std::string text = cap.text();
        return std::pair{count_of(text, "registry.write frame ignored"), text};
    };

    const auto bad = warns("registry-9 x", "set_value"); // 12 bytes
    CHECK(bad.first == 1);
    CHECK(bad.second.find(ignored + "12 bytes)") != std::string::npos);
    CHECK(h.dropped("unmintable_id") == 1.0);
    // Anything but the exact minted shape is ignored, however plausible.
    CHECK(warns("registry-9", "set_value").first == 1);
    CHECK(h.dropped("unmintable_id") == 2.0);
    // A minted id is accepted (and writes its row), a non-registry plugin and a read action are
    // not this guard's business: none of the three warns.
    CHECK(warns(rid(10), "set_value").first == 0);
    CHECK(warns("filesystem-9 x", "delete_key").first == 0);
    CHECK(warns("registry-9 x", "get_value").first == 0);
    CHECK(h.rows().size() == 1);
    CHECK(h.dropped("unmintable_id") == 2.0);
}

TEST_CASE("registry audit live ingest: a frame past the line cap keeps 300 rows and warns once",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    const std::string& agent = kOddAgent;
    REQUIRE(yuzu::log_id_token(agent) != yuzu::log_token(agent));
    std::string many;
    for (int i = 0; i < 301; ++i)
        many += std::string{kOkLine} + "\n";
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        agent, IngestHarness::frame(rid(0xc1), apb::CommandResponse::RUNNING, "set_value", many));
    cap.stop();
    CHECK(h.rows().size() == 300);
    CHECK(h.dropped("truncated") == 1.0);
    CHECK(count_of(cap.text(),
                   "[audit] registry.write frame exceeded the audit bounds (more than 300 lines, or "
                   "a line over 4096 bytes); the excess was not recorded (agent=" +
                       yuzu::log_id_token(agent) + ", command=" + rid(0xc1) + ")") == 1);
}

TEST_CASE("registry audit live ingest: a line over the byte bound is cut visibly and keeps its "
          "result",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    const std::string line = "audit|op=set_value|key=" + std::string(5000, 'k') + "|result=ok";
    yuzu::test::LogCapture cap;
    h.svc.process_gateway_response(
        "agent-1",
        IngestHarness::frame(rid(0xc2), apb::CommandResponse::RUNNING, "set_value", line));
    cap.stop();
    const auto rows = h.rows();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].result == "success"); // read from the whole line, before the cut
    CHECK(rows[0].detail.starts_with("agent=agent-1 cut=1 audit|op=set_value|key=kkk"));
    CHECK(rows[0].detail.size() < line.size());
    CHECK(h.dropped("truncated") == 1.0);
    CHECK(count_of(cap.text(), "frame exceeded the audit bounds") == 1);
}

TEST_CASE("registry audit live ingest: a per-agent budget caps the rows an agent can write and "
          "counts the rest",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    std::int64_t now_ms = 1'000; // outlives the harness: the budget's clock reads it
    IngestHarness h(db.dsn());
    h.svc.set_registry_audit_budget(std::make_unique<DenialAuditBudget>(
        /*max_rows=*/3, /*window_ms=*/60'000, [&now_ms] { return now_ms; }, /*max_keys=*/8));
    const std::string two = std::string{kOkLine} + "\n" + std::string{kOkLine} + "\n";
    const auto send = [&](const char* agent, unsigned n) {
        h.svc.process_gateway_response(
            agent, IngestHarness::frame(rid(n), apb::CommandResponse::RUNNING, "set_value", two));
    };
    yuzu::test::LogCapture cap;
    send("agent-a", 1); // 2 rows: 2 of 3 spent
    send("agent-a", 2); // 1 row admitted, 1 refused
    send("agent-a", 3); // both refused
    send("agent-b", 4); // another agent has its own allowance
    CHECK(h.rows().size() == 3 + 2);
    CHECK(h.dropped("suppressed") == 3.0);
    // A refusal of rows is not a failure of the write: no failed-write count (and, below, no
    // error line).
    CHECK(h.dropped("persist_failed") == 0.0);

    // A window later the agent writes again, and the window that closed is reported once.
    now_ms += 60'000;
    send("agent-a", 5);
    cap.stop();
    CHECK(cap.text().find("failed to persist") == std::string::npos);
    CHECK(h.rows().size() == 3 + 2 + 2);
    CHECK(count_of(cap.text(), "[audit] registry.write rows refused by the per-agent budget in the "
                               "last window: 3") == 1);
}

TEST_CASE("registry audit live ingest: the row is written before the execution advances and a "
          "failed write does not stall it",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_exec_tpl);
    IngestHarness h(db.dsn());
    // Declared before the bus: the listener below captures them.
    int transitions = 0;
    std::optional<std::size_t> rows_at_first_transition;
    ExecutionEventBus exec_bus;
    yuzu::test::TrackerScope ts{h.svc, h.pool, &exec_bus};
    const auto id = ts.make_exec();
    h.svc.record_execution_id(rid(0xe1), id);

    // The tracker publishes `agent-transition` synchronously from inside the ingest, so the
    // listener sees exactly what a live operator watching the execution would.
    exec_bus.subscribe(id, [&](const ExecutionEvent& ev) {
        if (ev.event_type != "agent-transition" || transitions++ != 0)
            return;
        AuditQuery q;
        q.action = "registry.write";
        const auto r = h.audit->query(q);
        rows_at_first_transition = r ? r->size() : 0;
    });

    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xe1), apb::CommandResponse::RUNNING, "set_value",
                                        std::string{kOkLine}));
    REQUIRE(rows_at_first_transition.has_value());
    CHECK(*rows_at_first_transition == 1U);

    // A failing INSERT is reported (trailer / error line) but never strands the execution.
    yuzu::test::SqlFault fault(h.pool,
                               "ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone",
                               "ALTER TABLE audit_store.audit_events_gone RENAME TO audit_events");
    fault.arm();
    h.svc.process_gateway_response(
        "agent-1", IngestHarness::frame(rid(0xe1), apb::CommandResponse::SUCCESS, "set_value",
                                        std::string{kOkLine}));
    fault.repair();
    CHECK(transitions == 2);
}

// ── the direct Subscribe ingress (a live gRPC session) ───────────────────

namespace {

/// A live AgentServiceImpl over loopback with an AuthDB-backed enrolment, so an agent can Register
/// and Subscribe for real. `server` stops before `svc` is destroyed.
struct LiveHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::test::AuthDbPgShared auth_db;
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    yuzu::server::pg::PgPool pool;
    std::shared_ptr<AuditStore> audit;
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};
    std::unique_ptr<grpc::Server> server;
    int port = 0;
    std::unique_ptr<apb::AgentService::Stub> stub;

    /// `configure` runs on the service before the server starts, so nothing else can be reading
    /// what it sets (the budget's setter is for "before the service is shared").
    explicit LiveHarness(const std::string& dsn,
                         const std::function<void(AgentServiceImpl&)>& configure = {})
        : pool({.conninfo = dsn, .size = 4}) {
        auth_mgr.set_auth_db(auth_db.get());
        audit = std::make_shared<AuditStore>(pool);
        REQUIRE(audit->is_open());
        svc.set_registry_audit_store(audit);
        if (configure)
            configure(svc);
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&svc);
        server = builder.BuildAndStart();
        REQUIRE(server != nullptr);
        stub = apb::AgentService::NewStub(grpc::CreateChannel("127.0.0.1:" + std::to_string(port),
                                                              grpc::InsecureChannelCredentials()));
    }
    ~LiveHarness() {
        // A FINITE deadline, as test_ota_stalled_write.cpp does: a deadline-free Shutdown() waits for
        // in-flight handlers, so a regression that wedges a Subscribe would hang this suite to its
        // outer CI timeout instead of failing it.
        if (server)
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    }
};

/// Registers `agent_id` on `h`, streams `frames` over a real Subscribe, drains it and returns how
/// many `x-yuzu-audit-failed` entries the call ended with (the trailer, or several if it was added
/// once per failed frame).
std::size_t subscribe_with(LiveHarness& h, const std::string& agent_id,
                           const std::vector<apb::CommandResponse>& frames) {
    const auto deadline = [] {
        return std::chrono::system_clock::now() + std::chrono::seconds(20);
    };
    auto token = h.auth_mgr.create_enrollment_token("registry-audit", 0, std::chrono::hours(1),
                                                    "test-admin");
    REQUIRE(token.has_value());
    apb::RegisterRequest reg;
    reg.mutable_info()->set_agent_id(agent_id);
    reg.mutable_info()->set_hostname("host");
    reg.mutable_info()->mutable_platform()->set_os("windows");
    reg.mutable_info()->mutable_platform()->set_arch("x86_64");
    reg.set_enrollment_token(token->raw_token);
    apb::RegisterResponse reg_resp;
    grpc::ClientContext reg_ctx;
    reg_ctx.set_deadline(deadline());
    REQUIRE(h.stub->Register(&reg_ctx, reg, &reg_resp).ok());
    REQUIRE(reg_resp.accepted());

    grpc::ClientContext ctx;
    ctx.set_deadline(deadline());
    ctx.AddMetadata(std::string{AgentServiceImpl::kSessionMetadataKey}, reg_resp.session_id());
    auto stream = h.stub->Subscribe(&ctx);
    REQUIRE(stream != nullptr);
    for (const auto& f : frames)
        REQUIRE(stream->Write(f));
    REQUIRE(stream->WritesDone());
    apb::CommandRequest unused;
    while (stream->Read(&unused)) {}
    CHECK(stream->Finish().ok()); // the handler read every frame before it returned
    return ctx.GetServerTrailingMetadata().count(std::string{yuzu::server::kGrpcAuditFailedKey});
}

} // namespace

TEST_CASE(
    "registry audit live ingest: a real Subscribe session audits RUNNING output but not the empty "
    "terminal and only for mutating actions",
    "[pg][server][registry_audit][subscribe]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    LiveHarness h(db.dsn());
    const std::string refused = line_with_result("refused", "0");
    CHECK(subscribe_with(
              h, "agent-live",
              {IngestHarness::frame(rid(0xd1), apb::CommandResponse::RUNNING, "set_value",
                                    std::string{kOkLine} + "\nstatus|ok"),
               IngestHarness::frame(rid(0xd1), apb::CommandResponse::SUCCESS, "set_value", ""),
               IngestHarness::frame(rid(0xd2), apb::CommandResponse::RUNNING, "get_value", refused),
               IngestHarness::frame(rid(0xd3), apb::CommandResponse::RUNNING, "", refused),
               IngestHarness::frame(rid(0xd4), apb::CommandResponse::FAILURE, "delete_key",
                                    line_with_result("failed"))}) == 0U);

    AuditQuery q;
    q.action = "registry.write";
    auto rows = h.audit->query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);
    std::sort(rows->begin(), rows->end(),
              [](const auto& a, const auto& b) { return a.target_id < b.target_id; });
    CHECK((*rows)[0].target_id == rid(0xd1));
    CHECK((*rows)[0].principal == "agent:agent-live");
    CHECK((*rows)[0].result == "success");
    CHECK((*rows)[1].target_id == rid(0xd4));
    CHECK((*rows)[1].result == "failure");
}

TEST_CASE("registry audit live ingest: a dropped row sets the audit-failed trailer on the "
          "Subscribe call and only a frame that owed a row does",
          "[pg][server][registry_audit][subscribe]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    LiveHarness h(db.dsn());
    yuzu::test::SqlFault fault(h.pool,
                               "ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone",
                               "ALTER TABLE audit_store.audit_events_gone RENAME TO audit_events");
    fault.arm();
    // A READ action's output owes no row, so a store that is down is not touched and the trailer
    // stays absent ...
    CHECK(subscribe_with(h, "agent-r",
                         {IngestHarness::frame(rid(0xd5), apb::CommandResponse::RUNNING,
                                               "get_value", std::string{kOkLine})}) == 0U);
    // ... a mutating action's row cannot be written: the trailer tells the agent's peer the
    // evidence chain has a gap (the operator's signal is the counter and the log).
    CHECK(subscribe_with(h, "agent-w",
                         {IngestHarness::frame(rid(0xd6), apb::CommandResponse::RUNNING,
                                               "set_value", std::string{kOkLine})}) == 1U);
    // ... and the same holds for a TERMINAL frame.
    CHECK(subscribe_with(h, "agent-t",
                         {IngestHarness::frame(rid(0xd7), apb::CommandResponse::FAILURE,
                                               "delete_key", std::string{kOkLine})}) == 1U);
    fault.repair();
}

TEST_CASE("registry audit live ingest: the audit-failed trailer is added once per stream however "
          "many frames fail",
          "[pg][server][registry_audit][subscribe]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    LiveHarness h(db.dsn());
    yuzu::test::SqlFault fault(h.pool,
                               "ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone",
                               "ALTER TABLE audit_store.audit_events_gone RENAME TO audit_events");
    fault.arm();
    // AddTrailingMetadata appends to a multimap for the life of the call: five failed frames on one
    // stream must still end with ONE entry.
    std::vector<apb::CommandResponse> frames;
    for (unsigned n = 0; n < 4; ++n)
        frames.push_back(IngestHarness::frame(rid(0xd8 + n), apb::CommandResponse::RUNNING,
                                              "set_value", std::string{kOkLine}));
    frames.push_back(IngestHarness::frame(rid(0xdc), apb::CommandResponse::FAILURE, "delete_key",
                                          std::string{kOkLine}));
    CHECK(subscribe_with(h, "agent-many", frames) == 1U);
    fault.repair();
}

TEST_CASE("registry audit live ingest: a close mid-frame sets the audit-failed trailer and a frame "
          "after the close does not",
          "[pg][server][registry_audit][subscribe][rundown]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    int clock_calls = 0; // outlives the harness: the budget's clock reads it
    LiveHarness h(db.dsn(), [&](AgentServiceImpl& svc) {
        // Never refuses; the clock closes the hook (what ServerImpl::stop() does) on the second row
        // of the first frame, on the handler's own thread.
        svc.set_registry_audit_budget(std::make_unique<DenialAuditBudget>(
            /*max_rows=*/100, /*window_ms=*/60'000,
            [&clock_calls, &svc] {
                if (++clock_calls == 2)
                    svc.close_registry_audit();
                return std::int64_t{1'000};
            },
            /*max_keys=*/8));
    });
    const std::string one{kOkLine};
    // The frame is cut short: the first row is written, the other two are lost, and the Subscribe
    // call ends with the trailer, as it does for any row the store failed to write.
    CHECK(subscribe_with(h, "agent-c",
                         {IngestHarness::frame(rid(0xe2), apb::CommandResponse::RUNNING,
                                               "set_value", one + "\n" + one + "\n" + one)}) == 1U);
    CHECK(h.metrics
              .counter("yuzu_server_registry_audit_dropped_total", {{"reason", "persist_failed"}})
              .value() == 2.0);
    // A frame that arrives after the close is silent, like one after the store is released: no
    // row, no count, no trailer.
    CHECK(subscribe_with(h, "agent-after",
                         {IngestHarness::frame(rid(0xe3), apb::CommandResponse::RUNNING,
                                               "set_value", one)}) == 0U);
    AuditQuery q;
    q.action = "registry.write";
    const auto rows = h.audit->query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].target_id == rid(0xe2));
    CHECK(h.svc.wait_registry_audit_idle(std::chrono::milliseconds{0}));
}
