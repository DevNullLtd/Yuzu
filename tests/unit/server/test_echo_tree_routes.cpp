/// @file test_echo_tree_routes.cpp
/// Route-level authz / token / audit tests for the Echo process-tree viewer
/// (/fragments/echo/process-tree{,/run,/result,/detail}). Driven in-process through
/// TestRouteSink (no httplib acceptor, #438) with stub auth/perm/dispatch/responses/
/// audit fns. These pin exactly the paths the pure-engine tests cannot reach — the
/// ones carrying the PR #1551 review findings:
///   * /detail holds the Execute tier (a Read-but-no-Execute operator is denied),
///   * a reconstruction token is bound to its originating principal (no cross-session
///     replay) and to the device scope (no cross-scope replay),
///   * the cache token is CSPRNG and an entropy failure fails closed (no cache entry),
///   * preset/os are neutralized in the audit detail.

#include "authz_gates.hpp" // authz::FleetReadGate (#4027 fix round, CDX-P1-01/K4)
#include "authz_model.hpp"
#include "secure_random.hpp"
#include "echo_tree_routes.hpp"
#include "source_scan.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::test::source_scan::count_occurrences;

namespace {

DexAgentResponse resp(const std::string& agent_id, const std::string& output) {
    DexAgentResponse r;
    r.agent_id = agent_id;
    r.status = 1; // SUCCESS (terminal, carries output)
    r.output = output;
    return r;
}

// An empty $TCP_Hourly answer (schema and trailer only), what an agent sends for a quiet hour.
const char* kEmptyTcp =
    "__schema__|hour_ts|remote_addr|remote_port|proto|process_name|connect_count|disconnect_count|"
    "failed_count\n__total__|0\n";

// A canned $Process_Hourly body for hour 7200: systemd -> bash. node 0 is systemd, node 1
// bash. (parent_name and abnormal_exit_count are agent-folded; fixture-only until then.)
const char* kProcOut =
    "__schema__|hour_ts|name|parent_name|user|start_count|stop_count|abnormal_exit_count\n"
    "7200|systemd||root|1|0|0\n"
    "7200|bash|systemd|alice|3|3|1\n";
// Two hours: 7200 (systemd -> bash) is the newest, 3600 holds only cron.
const char* kProcTwoHours =
    "__schema__|hour_ts|name|parent_name|user|start_count|stop_count|abnormal_exit_count\n"
    "7200|systemd||root|1|0|0\n"
    "7200|bash|systemd|alice|3|3|1\n"
    "3600|cron||root|2|2|0\n";

// The three canned command ids the result route polls (must start with "echo-").
const std::string kProcCmd = "echo-p";
const std::string kTcpCmd = "echo-t";
const std::string kHoursCmd = "echo-h";
// Canned ids for the capture-sources frame's two dispatches (`echo status` and
// `echo compatibility`), which the route polls by the scmd/ccmd query params.
const std::string kDnsCmd = "echo-d";
const std::string kArpCmd = "echo-a";
const std::string kStatusCmd = "echo-s";
const std::string kCompatCmd = "echo-c";

// An EchoTreeRoutes registered over a TestRouteSink with toggleable stubs.
struct EchoHarness {
    yuzu::server::test::TestRouteSink sink;
    EchoTreeRoutes routes;

    std::string device = "dev-A";
    std::string session_user = "alice";
    bool allow_read = true;
    // #4027 fix round (CDX-P1-01/K4): the REST device-picker twins now gate on
    // fleet_read_fn_, not perm_fn_. Default mirrors `allow_read`'s admit/deny so
    // every existing test (driven off `allow_read`) needs no changes; set
    // `fleet_scope` to exercise the ADR-0017 admit-then-filter narrowing itself
    // (nullopt = unfiltered/TOP, matching a global grant or RBAC-off).
    std::optional<std::vector<std::string>> fleet_scope;
    bool allow_execute = true;
    int dispatch_sent = 1; // agents a dispatch reaches; 0 models an offline device
    // #4027: operator-scoped device list the /fragments/echo/... HTML frames
    // (still on devices_fn_/perm_fn_ this round) render.
    std::vector<DeviceRow> devices_list;
    // #4143 review fix: the UNFILTERED registry snapshot all_devices_fn_ now
    // supplies to the REST/MCP twins (production: registry_.to_json_obj(),
    // ALL agents regardless of membership) — gate.scope is the sole filter on
    // top. Defaults to devices_list so every pre-existing test (which never
    // needed to distinguish "unfiltered registry" from "the old flat
    // membership-only resolver's output") keeps working unchanged; a test
    // exercising the ADR-0017 ancestor-scope divergence itself sets this to a
    // strictly LARGER set than devices_list — see the regression test below.
    std::optional<std::vector<DeviceRow>> all_devices_list_override;
    std::string scope_device; // empty = unrestricted; else scoped Read denied elsewhere
    std::string os = "linux";
    std::string proc_output = kProcOut;
    // The window's hour list (the `SELECT DISTINCT hour_ts` answer) and an empty $TCP_Hourly
    // answer: a real agent always writes the schema line and the trailer.
    std::string hours_output = "__schema__|hour_ts\n7200\n3600\n__total__|2\n";
    std::string tcp_output = kEmptyTcp;
    std::string dns_output;    // canned $DNS_Hourly / $ARP_Hourly replies for the device-net poll
    std::string arp_output;
    std::vector<std::string> sql_log; // every echo.sql string a dispatch carried, in order
    // Capture-sources frame: canned `echo status` / `echo compatibility` replies.
    std::string status_output;
    std::string compat_output = "config|dummy|1";
    bool audit_ok = true;      // #1647: flip to drop the evidence row (audit_fn → false)
    bool audit_throws = false; // #1647: simulate a bad_alloc-class throw out of audit_fn
    bool service_scoped = false; // simulate a service-scoped API token session

    struct AuditRow {
        std::string action, result, target_id, detail;
    };
    std::vector<AuditRow> audit_log;
    DispatchCaller last_dispatch_caller; // #3133: observes what dispatch actually received
    std::unordered_map<std::string, std::string> last_dispatch_params; // what the last dispatch carried
    // Per command id, the exact frames the store answers (newest first, as the real store does):
    // a long answer is several frames. Overrides the one-frame replies below.
    std::unordered_map<std::string, std::vector<DexAgentResponse>> frames_override;

    EchoHarness() {
        auto auth = [this](const httplib::Request&,
                           httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            if (service_scoped)
                s.token_scope_service = "printers";
            return s;
        };
        auto perm = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                           const std::string&) {
            // #4027: mirror production require_permission's contract (sets the
            // response status on denial) — the `scoped` stub below already does
            // this; `perm` didn't need to until the REST twins added a route
            // whose ONLY gate (no scoped_perm_fn_ re-check) is this one.
            if (!allow_read)
                res.status = 403;
            return allow_read;
        };
        // #4027 fix round (CDX-P1-01/K4): fleet_read_fn_ stub — the REST twins'
        // sole gate. Mirrors `allow_read` for admit/deny by default (so tests
        // driven off `allow_read` need no changes) and additionally applies
        // `fleet_scope` as the gate's composed VisibleSet (nullopt/unset = TOP,
        // matching a global grant).
        auto fleet_read = [this](const httplib::Request&, httplib::Response& res,
                                 const std::string&,
                                 const std::string&) -> authz::FleetReadGate {
            if (!allow_read) {
                res.status = 403;
                return authz::FleetReadGate{false, authz::deny_all()};
            }
            if (fleet_scope) {
                return authz::FleetReadGate{
                    true, authz::VisibleSet(std::unordered_set<std::string>(
                              fleet_scope->begin(), fleet_scope->end()))};
            }
            return authz::FleetReadGate{true, std::nullopt}; // TOP — unfiltered
        };
        // Scoped gate: Execute toggled by allow_execute, Read by allow_read; a non-empty
        // scope_device denies any other device (mirrors a management-scope miss → 403).
        auto scoped = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string& op, const std::string& dev) {
            bool ok = (op == "Execute") ? allow_execute : allow_read;
            if (ok && !scope_device.empty() && dev != scope_device)
                ok = false;
            if (!ok)
                res.status = 403;
            return ok;
        };
        auto devices = [this](const std::string&) { return devices_list; };
        // #4143 review fix — all_devices_fn_ is now the REST twins'/MCP tools'
        // sole row source (gate.scope is the sole filter). Defaults to
        // devices_list (see the member's doc comment) so existing fixtures are
        // unaffected; override via all_devices_list_override to model the
        // unfiltered-registry-vs-flat-resolver divergence itself.
        auto all_devices = [this]() {
            return all_devices_list_override.value_or(devices_list);
        };
        auto lookup = [this](const std::string& id) -> std::optional<DeviceRow> {
            DeviceRow d;
            d.agent_id = id;
            d.os = os;
            return d;
        };
        // Dispatch returns a distinct echo- command id per query (process vs tcp),
        // keyed off the SQL the route built, so the responses stub can disambiguate.
        auto dispatch = [this](const std::string&, const std::string&, const std::vector<std::string>&,
                               const std::string&,
                               const std::unordered_map<std::string, std::string>& params,
                               const DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            last_dispatch_caller = caller;
            last_dispatch_params = params;
            const auto it = params.find("sql");
            const std::string sql = it != params.end() ? it->second : std::string{};
            sql_log.push_back(sql);
            const auto has = [&](const char* t) { return sql.find(t) != std::string::npos; };
            return {.sent = dispatch_sent,
                    .command_id = has("DISTINCT hour_ts") ? kHoursCmd
                                  : has("$Process_Hourly") ? kProcCmd
                                  : has("$DNS_Hourly")     ? kDnsCmd
                                  : has("$ARP_Hourly")     ? kArpCmd
                                                           : kTcpCmd};
        };
        // #3133 review fix: mirrors the production idiom (resolve the session,
        // derive a real caller) closely enough for this harness's simplified
        // auth — never a synthesized system caller. An unresolved session
        // (empty session_user) fails closed with an empty principal, same
        // contract every production CallerFn documents.
        auto caller_fn = [this](const httplib::Request&) -> DispatchCaller {
            if (session_user.empty())
                return DispatchCaller{.exec_visible = authz::deny_all()};
            return DispatchCaller{.principal = session_user, .system = false};
        };
        auto responses = [this](const std::string& cmd,
                                 const std::string& /*agent_id*/) -> std::vector<DexAgentResponse> {
            if (const auto f = frames_override.find(cmd); f != frames_override.end())
                return f->second;
            if (cmd == kProcCmd)
                return {resp(device, proc_output)};
            if (cmd == kTcpCmd)
                return {resp(device, tcp_output)};
            if (cmd == kHoursCmd)
                return {resp(device, hours_output)};
            if (cmd == kDnsCmd)
                return {resp(device, dns_output)};
            if (cmd == kArpCmd)
                return {resp(device, arp_output)};
            if (cmd == kStatusCmd)
                return {resp(device, status_output)};
            if (cmd == kCompatCmd)
                return {resp(device, compat_output)};
            return {};
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string&, const std::string& tid,
                            const std::string& d) -> bool {
            audit_log.push_back({a, r, tid, d});
            // #1647: the row is recorded before the throw so find_audit still proves the
            // site was reached; the throw then exercises the shared helper's catch-arm.
            if (audit_throws)
                throw std::runtime_error("audit DB write blew up");
            return audit_ok; // DexRoutes::AuditFn (aliased by EchoTreeRoutes) is bool-returning (#1549)
        };
        routes.register_routes(sink, auth, perm, scoped, devices, lookup, dispatch, responses, audit,
                               caller_fn);
        routes.set_fleet_read_fn(fleet_read); // #4027 fix round — REST twins' sole gate
        routes.set_all_devices_fn(all_devices); // #4143 review fix — REST twins' sole row source
    }

    // Drive /result directly (skips /run; the result route reads pcmd/tcmd/hcmd and the resolved
    // hour from the query, and we control the canned command ids). `hour` defaults to the hour
    // the canned process rows are for; "" sends none. Returns the response.
    std::unique_ptr<httplib::Response> run_result(const std::string& hour = "7200",
                                                  const std::string& extra = "") {
        return sink.Get("/fragments/echo/process-tree/result?device=" + device +
                        "&preset=24h&pcmd=" + kProcCmd + "&tcmd=" + kTcpCmd + "&hcmd=" + kHoursCmd +
                        "&n=1" + (hour.empty() ? "" : "&hour=" + hour) + extra);
    }

    // Drive the capture-sources frame past the pending poll, the same way
    // run_result() drives the tree: supply the canned command ids directly.
    std::unique_ptr<httplib::Response> run_capture_sources() {
        return sink.Get("/fragments/echo/capture-sources/load?device=" + device +
                        "&scmd=" + kStatusCmd + "&ccmd=" + kCompatCmd + "&n=1");
    }

    std::unique_ptr<httplib::Response> get_detail(const std::string& token, int node = 0) {
        return sink.Get("/fragments/echo/process-tree/detail?token=" + token +
                        "&node=" + std::to_string(node));
    }

    const AuditRow* find_audit(const std::string& action, const std::string& result) const {
        for (const auto& r : audit_log)
            if (r.action == action && r.result == result)
                return &r;
        return nullptr;
    }
};

// Pull the 32-hex reconstruction token out of a rendered tree fragment's detail URL.
std::string extract_token(const std::string& html) {
    const std::string needle = "detail?token=";
    auto p = html.find(needle);
    if (p == std::string::npos)
        return "";
    p += needle.size();
    auto end = html.find("&amp;", p);
    if (end == std::string::npos)
        end = html.size();
    return html.substr(p, end - p);
}

bool is_32_hex(const std::string& s) {
    if (s.size() != 32)
        return false;
    for (char c : s)
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            return false;
    return true;
}

} // namespace

TEST_CASE("echo routes: reconstruction mints a 32-hex CSPRNG token", "[echo][routes][token]") {
    EchoHarness h;
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->status == 200);
    const std::string token = extract_token(r->body);
    CHECK(is_32_hex(token));
    // The success audit fired with the data-class detail.
    REQUIRE(h.find_audit("echo.process_tree.read", "success") != nullptr);
}

TEST_CASE("echo routes: /detail renders for the owning operator + audits", "[echo][routes]") {
    EchoHarness h;
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->status == 200);
    CHECK(d->body.find("echo-detail") != std::string::npos);
    // Per-drilldown access audit fired with a neutralized os.
    const auto* row = h.find_audit("echo.process_tree.detail", "success");
    REQUIRE(row != nullptr);
    CHECK(row->target_id == "dev-A");
    CHECK(row->detail == "node=0 os=linux");
}

TEST_CASE("echo routes: /detail requires Execute (Read-only operator denied)",
          "[echo][routes][authz]") {
    EchoHarness h;
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    h.allow_execute = false; // operator keeps scoped Read but loses Execute
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->body.find("Execute") != std::string::npos);
    CHECK(d->body.find("echo-detail") == std::string::npos);
    CHECK(h.find_audit("echo.process_tree.detail", "success") == nullptr);
}

TEST_CASE("echo routes: /detail rejects a token replayed by a different principal",
          "[echo][routes][authz]") {
    EchoHarness h;
    const std::string token = extract_token(h.run_result()->body); // created by alice
    REQUIRE(is_32_hex(token));

    h.session_user = "mallory"; // same scope + Execute, but not the creator
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->body.find("different session") != std::string::npos);
    CHECK(d->body.find("echo-detail") == std::string::npos);
    CHECK(h.find_audit("echo.process_tree.detail", "success") == nullptr);
}

TEST_CASE("echo routes: /detail fails closed when the token's device leaves scope",
          "[echo][routes][authz]") {
    EchoHarness h;
    h.scope_device = "dev-A"; // build under a device the operator manages
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    h.scope_device = "dev-B"; // dev-A now outside the operator's management scope
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->status == 403);
    CHECK(d->body.find("echo-detail") == std::string::npos);
}

TEST_CASE("echo routes: CSPRNG failure fails closed (no cache, failure audit)",
          "[echo][routes][token]") {
    EchoHarness h;
    test_hooks::force_next_failure_for_this_thread();
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->status == 200); // htmx-swappable in-panel note, NOT a 503
    CHECK(r->body.find("secure token") != std::string::npos);
    CHECK(!test_hooks::is_failure_forced_for_this_thread()); // override consumed
    // A failure audit row exists and NO token/tree was cached.
    REQUIRE(h.find_audit("echo.process_tree.read", "failure") != nullptr);
    CHECK(h.find_audit("echo.process_tree.read", "failure")->detail == "csprng_unavailable");
    CHECK(extract_token(r->body).empty());
    // A fabricated 32-hex token resolves to nothing (the cache is empty).
    auto d = h.get_detail("0123456789abcdef0123456789abcdef", 0);
    REQUIRE(d);
    CHECK(d->body.find("expired") != std::string::npos);
    CHECK(d->body.find("echo-detail") == std::string::npos);
}

TEST_CASE("echo routes: an over-cap process payload is rejected (no cache)",
          "[echo][routes][token]") {
    EchoHarness h;
    h.proc_output = std::string(kMaxEchoProcOutputBytes + 1, 'x'); // > 16 MiB
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->body.find("unexpectedly large") != std::string::npos);
    CHECK(extract_token(r->body).empty());                          // nothing rendered/cached
    CHECK(h.find_audit("echo.process_tree.read", "success") == nullptr);
}

TEST_CASE("echo routes: /detail audit normalizes the agent-controlled os",
          "[echo][routes][audit]") {
    EchoHarness h;
    h.os = "win\ndows evil=1"; // CRLF + delimiter injection via device metadata
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    const auto* row = h.find_audit("echo.process_tree.detail", "success");
    REQUIRE(row != nullptr);
    CHECK(row->detail == "node=0 os=windows"); // normalized; no raw newline/'='
}

TEST_CASE("echo routes: /run audit neutralizes an injected preset", "[echo][routes][audit]") {
    EchoHarness h;
    // preset carries an audit-field-forgery attempt; canonicalization maps it to 24h.
    auto r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=x%20command_id%3Dforged");
    REQUIRE(r);
    const auto* row = h.find_audit("echo.process_tree.read", "dispatched");
    REQUIRE(row != nullptr);
    CHECK(row->detail.find("preset=24h") != std::string::npos);
    CHECK(row->detail.find("forged") == std::string::npos); // injection neutralized
}

TEST_CASE("echo routes: /result audit normalizes an agent-controlled os", "[echo][routes][audit]") {
    EchoHarness h;
    h.os = "win\ndows evil=1"; // CRLF + delimiter injection via device metadata
    h.run_result();
    const auto* row = h.find_audit("echo.process_tree.read", "success");
    REQUIRE(row != nullptr);
    CHECK(row->detail.find("os=windows") != std::string::npos);
    CHECK(row->detail.find("evil=1") == std::string::npos);
    CHECK(row->detail.find('\n') == std::string::npos); // no line splitting
}

TEST_CASE("echo routes: /run is denied for a Read-but-no-Execute operator",
          "[echo][routes][authz]") {
    EchoHarness h;
    h.allow_execute = false;
    auto r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=10m");
    REQUIRE(r);
    CHECK(r->body.find("Execute") != std::string::npos);
    // No dispatch audit when the Execute gate stops the reconstruction.
    CHECK(h.find_audit("echo.process_tree.read", "dispatched") == nullptr);
}

TEST_CASE("echo routes: /run refuses an unparseable custom window and dispatches nothing",
          "[echo][routes][parse]") {
    for (const char* query : {"&from=garbage&to=", "&from=&to=2026-13-01T00:00",
                              "&from=2026-06-18T12:00&to=2026-06-18T12:00:30xyz",
                              "&from=2026-02-31T00:00&to=2026-03-01T00:00"}) {
        EchoHarness h;
        auto r = h.sink.Get(std::string("/fragments/echo/process-tree/run?device=dev-A&preset=custom") +
                            query);
        REQUIRE(r);
        CHECK(r->body.find("not a valid time") != std::string::npos);
        CHECK(r->body.find("process-tree/result") == std::string::npos);
        CHECK(h.find_audit("echo.process_tree.read", "dispatched") == nullptr);
    }
    // A well-formed custom window still dispatches.
    EchoHarness h;
    auto r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=custom"
                        "&from=2026-06-18T12:00&to=2026-06-18T13:00");
    REQUIRE(r);
    CHECK(r->body.find("process-tree/result") != std::string::npos);
}

TEST_CASE("echo routes: /result refuses an invalid custom window and renders a valid one",
          "[echo][routes][parse]") {
    for (const char* window : {"&from=garbage&to=", "&from=2026-02-31T00:00&to=2026-03-01T00:00"}) {
        EchoHarness h;
        auto r = h.sink.Get("/fragments/echo/process-tree/result?device=" + h.device +
                            "&preset=custom&pcmd=" + kProcCmd + "&tcmd=" + kTcpCmd + "&hcmd=" + kHoursCmd +
                            "&n=1" + window);
        REQUIRE(r);
        CHECK(r->body.find("not a valid time") != std::string::npos);
        CHECK(h.find_audit("echo.process_tree.read", "success") == nullptr);
    }
    EchoHarness h;
    auto r = h.sink.Get("/fragments/echo/process-tree/result?device=" + h.device +
                        "&preset=custom&pcmd=" + kProcCmd + "&tcmd=" + kTcpCmd + "&hcmd=" + kHoursCmd +
                        "&n=1&from=2026-06-18T12:00&to=2026-06-18T13:00");
    REQUIRE(r);
    CHECK(r->body.find("not a valid time") == std::string::npos);
    CHECK(h.find_audit("echo.process_tree.read", "success") != nullptr);
}

// #1647 catch-arm parity: a THROWING audit_fn at every echo dispatch/read site must be
// caught by the shared rest_audit.hpp chokepoint — never escape the handler (which
// httplib would turn into a 500) — and must surface Sec-Audit-Failed while the route
// keeps its existing dispatch/render posture. Before #1647 these sites discarded the
// audit bool with no try/catch, so a bad_alloc-class throw escaped and a dropped row
// was invisible. One section per distinct call site.
TEST_CASE("echo routes: a throwing audit_fn is caught + flags Sec-Audit-Failed at every site",
          "[echo][routes][audit]") {
    SECTION("/run — echo.process_tree.read dispatched") {
        EchoHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=10m"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Posture preserved: the dispatch still rendered the polling fragment.
        CHECK(r->body.find("process-tree/result") != std::string::npos);
        CHECK(h.find_audit("echo.process_tree.read", "dispatched") != nullptr);
    }
    SECTION("/result success — echo.process_tree.read success (renders PII tree)") {
        EchoHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.run_result());
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Set-and-proceed: the tree still rendered (a detail token was minted).
        CHECK(is_32_hex(extract_token(r->body)));
    }
    SECTION("/result csprng failure — echo.process_tree.read failure") {
        EchoHarness h;
        h.audit_throws = true;
        test_hooks::force_next_failure_for_this_thread(); // forces the failure-audit branch
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.run_result());
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->body.find("secure token") != std::string::npos); // honest note still rendered
        CHECK(h.find_audit("echo.process_tree.read", "failure") != nullptr);
    }
    SECTION("/detail — echo.process_tree.detail") {
        EchoHarness h;
        const std::string token = extract_token(h.run_result()->body); // clean reconstruction
        REQUIRE(is_32_hex(token));
        h.audit_throws = true; // throw only on the detail open
        std::unique_ptr<httplib::Response> d;
        CHECK_NOTHROW(d = h.get_detail(token, 0));
        REQUIRE(d);
        CHECK(d->status == 200);
        CHECK(d->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(d->body.find("echo-detail") != std::string::npos); // detail still rendered
    }
    SECTION("/device-net — echo.dns.read + echo.arp.read") {
        EchoHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/echo/process-tree/device-net?device=dev-A"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Both verbs were reached before the throw was caught.
        CHECK(h.find_audit("echo.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("echo.arp.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/load — echo.sources.read") {
        EchoHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/echo/capture-sources/load?device=dev-A"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.find_audit("echo.sources.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/push — echo.sources.configure") {
        EchoHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        // changes=process=on (url-encoded '='); a known source toggled on.
        CHECK_NOTHROW(
            r = h.sink.Post("/fragments/echo/capture-sources/push?device=dev-A&changes=process%3Don",
                            ""));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.find_audit("echo.sources.configure", "dispatched") != nullptr);
    }
}

// #3133 external PR review finding: this route gated only Infrastructure:Read
// before dispatching the mutating, Infrastructure:Write-classified
// echo.configure action through a hardcoded system=true closure — bypassing
// the chokepoint's per-action authorization entirely regardless of the
// caller's actual grants. The fix threads the real, non-system caller
// through every dispatch in this class; this pins it at the exact route the
// review flagged, and the four others sharing the same dispatch_fn_ member.
TEST_CASE("echo routes: every dispatch carries the real caller, never a system one",
         "[echo][routes][security]") {
    EchoHarness h;
    h.session_user = "alice";

    SECTION("process-tree /run") {
        // /result only polls pre-canned command ids (run_result() skips /run
        // by design, per the harness's own doc comment) — /run is the
        // handler that actually calls dispatch_fn_.
        (void)h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=10m");
        CHECK_FALSE(h.last_dispatch_caller.system);
        CHECK(h.last_dispatch_caller.principal == "alice");
    }
    SECTION("capture-sources/push — echo.configure") {
        (void)h.sink.Post(
            "/fragments/echo/capture-sources/push?device=dev-A&changes=process%3Don", "");
        CHECK_FALSE(h.last_dispatch_caller.system);
        CHECK(h.last_dispatch_caller.principal == "alice");
    }
    SECTION("capture-sources/load — echo.status + echo.compatibility") {
        (void)h.sink.Get("/fragments/echo/capture-sources/load?device=dev-A");
        CHECK_FALSE(h.last_dispatch_caller.system);
        CHECK(h.last_dispatch_caller.principal == "alice");
    }
}

// PR11.8: the registry source joins the Push allowlist. The allowlist exists so an arbitrary
// token is never interpolated into the `<src>_enabled` configure key.
TEST_CASE("echo routes: capture-sources/push allows registry and still refuses unknown tokens",
          "[echo][routes][capture-sources]") {
    EchoHarness h;
    h.session_user = "alice";
    (void)h.sink.Post("/fragments/echo/capture-sources/push?device=dev-A&changes=registry%3Doff", "");
    REQUIRE(h.last_dispatch_params.contains("registry_enabled"));
    CHECK(h.last_dispatch_params.at("registry_enabled") == "false");

    h.last_dispatch_params.clear();
    (void)h.sink.Post("/fragments/echo/capture-sources/push?device=dev-A&changes=registryx%3Doff", "");
    CHECK(h.last_dispatch_params.empty()); // an unknown token never reaches dispatch
    (void)h.sink.Post("/fragments/echo/capture-sources/push?device=dev-A&changes=registry%3Dmaybe", "");
    CHECK(h.last_dispatch_params.empty()); // nor does a value other than on/off
}

// #1647: a DROPPED (returns-false) audit row is the realistic failure path (audit DB
// locked/full). Before this PR the echo sites discarded the bool and set NO header; now
// they surface Sec-Audit-Failed while still rendering (set-and-proceed). Also pins the
// idempotent-header guard: the two MULTI-CALL surfaces (dns+arp, the configure loop)
// must emit Sec-Audit-Failed AT MOST ONCE even when several audits in one request fail.
TEST_CASE("echo routes: dropped audit row flags Sec-Audit-Failed once; clean path sets none",
          "[echo][routes][audit]") {
    SECTION("/run dropped row — set-and-proceed (header + still dispatches)") {
        EchoHarness h;
        h.audit_ok = false;
        auto r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=10m");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->body.find("process-tree/result") != std::string::npos); // dispatch not blocked
    }
    SECTION("/device-net both dns+arp drop — header emitted exactly once (multimap guard)") {
        EchoHarness h;
        h.audit_ok = false;
        auto r = h.sink.Get("/fragments/echo/process-tree/device-net?device=dev-A");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1); // not two field-lines
        CHECK(h.find_audit("echo.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("echo.arp.read", "dispatched") != nullptr);
    }
    SECTION("/device-net both dns+arp throw — header still exactly once") {
        EchoHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/echo/process-tree/device-net?device=dev-A"));
        REQUIRE(r);
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1);
        // BOTH verbs must have fired (the first throw was caught, the second still ran)
        // — otherwise count==1 would prove single-emission, not de-duplication.
        CHECK(h.find_audit("echo.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("echo.arp.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/push two sources both drop — header exactly once over the loop") {
        EchoHarness h;
        h.audit_ok = false;
        // Two known sources toggled in one request; the per-source audit loop fails twice.
        auto r = h.sink.Post(
            "/fragments/echo/capture-sources/push?device=dev-A&changes=process%3Don,tcp%3Doff", "");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1);
        // BOTH loop iterations must have reached the audit chokepoint — otherwise
        // count==1 could mean the loop skipped the second source, not de-duplication.
        int cfg_rows = 0;
        for (const auto& row : h.audit_log)
            if (row.action == "echo.sources.configure")
                ++cfg_rows;
        CHECK(cfg_rows == 2);
    }
    SECTION("clean path sets NO Sec-Audit-Failed header") {
        EchoHarness h; // audit_ok=true, audit_throws=false
        auto r = h.run_result();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed").empty());
        CHECK(is_32_hex(extract_token(r->body))); // tree rendered normally
    }
}

TEST_CASE("Echo capture-sources: an offline device shows the agent's reason, not a blank grid",
          "[echo][tree][routes][capture-sources]") {
    // Governance Gate 3 (quality-engineer) BLOCKING: this branch had no test at
    // all, and it is the fix for the incident where a dead endpoint rendered
    // identically to a healthy one.
    //
    // `poll_command` treats any non-empty output as success, so the ONLY thing
    // separating "device is dead" from "device is fine" here is the
    // `starts_with("error|")` gate. If it misses, the frame falls through to the
    // capture-sources renderer, which parses only `config|` lines, and draws all
    // ten sources blank.
    EchoHarness h;
    // The REAL two-record reply, not just the error line. An earlier version of
    // this test supplied only the first line, so it could not see that the route
    // was truncating on a byte count and running past the newline into
    // `storage_state|offline` -- the operator saw a trailing `storage_stat`
    // (Sol adversarial review).
    h.status_output =
        "error|Echo storage is offline on this endpoint; the database was closed after a "
        "transaction could not be rolled back. Collection and retention are both stopped. The "
        "read-only query connection is unavailable too, so `echo sql` cannot read the historical "
        "data either. Restart the agent to recover.\nstorage_state|offline";

    auto res = h.run_capture_sources();
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);

    // The operator is told WHY, and which read path still works -- the agent
    // composes that sentence and it must survive the trip to the browser.
    CHECK(res->body.find("Echo storage is offline") != std::string::npos);
    CHECK(res->body.find("echo sql") != std::string::npos);
    // The recovery instruction is the last thing in the record and must survive.
    CHECK(res->body.find("Restart the agent to recover.") != std::string::npos);
    // ...and NOTHING from the following record leaks in as debris.
    CHECK(res->body.find("storage_state") == std::string::npos);
    CHECK(res->body.find("storage_stat") == std::string::npos);
    // The `error|` prefix itself is stripped, not echoed raw.
    CHECK(res->body.find("error|") == std::string::npos);
    // And it must NOT have rendered the sources grid for a dead store. Assert
    // the id the renderer actually emits (`capCards`, echo_process_tree.cpp)
    // -- an earlier version of this checked for "capture-source-row", a string
    // that exists nowhere in the codebase and so passed vacuously.
    CHECK(res->body.find("capCards") == std::string::npos);
}

TEST_CASE("Echo capture-sources: a healthy device still renders the sources grid",
          "[echo][tree][routes][capture-sources]") {
    // The other half, so the test above cannot pass by the route being broken
    // for everyone.
    EchoHarness h;
    // Needs a real `config|` line: the renderer builds the grid from those, so a
    // fixture without one cannot distinguish "rendered the grid" from "rendered
    // an empty body" and the absence-assertions below would pass vacuously.
    h.status_output = "storage_state|ok\nrecord_count|42\nconfig|process_enabled|true";

    auto res = h.run_capture_sources();
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);
    // Positively assert the grid: `capCards` is what the renderer emits.
    CHECK(res->body.find("capCards") != std::string::npos);
    CHECK(res->body.find("Echo storage is offline") == std::string::npos);
    CHECK(res->body.find("failed the status query") == std::string::npos);
}

// =============================================================================
// Roll-up only: the hourly SQL, whole-hour windows, the Hour selector, the cards
// =============================================================================

namespace {

// The number following `key` in `sql` (digits only), or -1.
std::int64_t number_after(const std::string& sql, const std::string& key) {
    const auto p = sql.find(key);
    if (p == std::string::npos)
        return -1;
    std::int64_t v = 0;
    std::size_t i = p + key.size();
    if (i >= sql.size() || !std::isdigit(static_cast<unsigned char>(sql[i])))
        return -1;
    for (; i < sql.size() && std::isdigit(static_cast<unsigned char>(sql[i])); ++i)
        v = v * 10 + (sql[i] - '0');
    return v;
}

} // namespace

TEST_CASE("echo routes: /run reads ONE hour of the process and tcp tables plus the window's hour list",
          "[echo][routes][sql]") {
    EchoHarness h;
    auto r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=24h");
    REQUIRE(r);
    REQUIRE(h.sql_log.size() == 3);
    const std::string& psql = h.sql_log[0];
    const std::string& tsql = h.sql_log[1];
    const std::string& hsql = h.sql_log[2];
    // No hour asked for: the window's last complete bucket, as a single int64 equality.
    const auto hour = number_after(hsql, "hour_ts <= ");
    REQUIRE(hour > 0);
    CHECK(hour % 3600 == 0);
    CHECK(psql == "SELECT hour_ts, name, parent_name, user, start_count, stop_count, "
                  "abnormal_exit_count FROM $Process_Hourly WHERE hour_ts = " +
                      std::to_string(hour) + " LIMIT 10000");
    CHECK(tsql == "SELECT hour_ts, remote_addr, remote_port, proto, process_name, connect_count, "
                  "disconnect_count, failed_count FROM $TCP_Hourly WHERE hour_ts = " +
                      std::to_string(hour) + " LIMIT 10000");
    // The hour list: the 24 whole buckets of the window, distinct, newest first, bounded.
    const auto from = number_after(hsql, "hour_ts >= ");
    REQUIRE(from > 0);
    CHECK(from % 3600 == 0);
    CHECK((hour - from) / 3600 == 23);
    CHECK(hsql == "SELECT DISTINCT hour_ts FROM $Process_Hourly WHERE hour_ts >= " +
                      std::to_string(from) + " AND hour_ts <= " + std::to_string(hour) +
                      " ORDER BY hour_ts DESC LIMIT 168");
    for (const auto& sql : h.sql_log)
        CHECK(sql.find("_Live") == std::string::npos); // no raw capture rows are read
    // The poll URL carries the window, the RESOLVED hour and all three command ids.
    CHECK(r->body.find("process-tree/result") != std::string::npos);
    CHECK(r->body.find("preset=24h") != std::string::npos);
    CHECK(r->body.find("hour=" + std::to_string(hour)) != std::string::npos);
    CHECK(r->body.find("pcmd=echo-p") != std::string::npos);
    CHECK(r->body.find("tcmd=echo-t") != std::string::npos);
    CHECK(r->body.find("hcmd=echo-h") != std::string::npos);

    SECTION("an asked-for hour is the one read; the hour list still covers the window") {
        EchoHarness one;
        auto res = one.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=24h&hour=3600");
        REQUIRE(res);
        REQUIRE(one.sql_log.size() == 3);
        CHECK(one.sql_log[0].find("FROM $Process_Hourly WHERE hour_ts = 3600 LIMIT 10000") !=
              std::string::npos);
        CHECK(one.sql_log[1].find("FROM $TCP_Hourly WHERE hour_ts = 3600 LIMIT 10000") !=
              std::string::npos);
        CHECK(number_after(one.sql_log[2], "hour_ts <= ") != 3600);
        CHECK(res->body.find("hour=3600") != std::string::npos);
    }
    SECTION("1h is one bucket; a reversed custom range collapses to one") {
        EchoHarness one;
        (void)one.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=1h");
        REQUIRE(one.sql_log.size() == 3);
        CHECK(number_after(one.sql_log[2], "hour_ts >= ") == number_after(one.sql_log[2], "hour_ts <= "));

        EchoHarness rev;
        (void)rev.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=custom"
                           "&from=2026-06-18T13:00&to=2026-06-18T12:00");
        REQUIRE(rev.sql_log.size() == 3);
        CHECK(number_after(rev.sql_log[2], "hour_ts >= ") == number_after(rev.sql_log[2], "hour_ts <= "));
    }
}

TEST_CASE("echo routes: the frame offers 1h / 24h / 7d / custom and no retired anchors",
          "[echo][routes][presets]") {
    EchoHarness h;
    auto r = h.sink.Get("/fragments/echo/process-tree");
    REQUIRE(r);
    for (const char* tok : {"preset=1h", "preset=24h", "preset=7d", "preset=custom"})
        CHECK(r->body.find(tok) != std::string::npos);
    for (const char* gone : {"on_boot", "on_install", "preset=1m", "preset=10m", "preset=1d",
                             "On boot", "On agent install", "data-statechip", "Running", "Exited"})
        CHECK(r->body.find(gone) == std::string::npos);
    // The device DNS / ARP placeholder is filled by the tree result, not by a host-change poll.
    CHECK(r->body.find("id=\"echo-devnet\"></div>") != std::string::npos);
}

TEST_CASE("echo routes: /result shows the resolved hour and an Hour selector for this device",
          "[echo][routes][hour]") {
    EchoHarness h;
    h.proc_output = kProcTwoHours; // the agent answers ONE hour; the extra rows are not trusted
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->status == 200);
    // Hour 7200 was asked for: systemd + bash, and cron (another hour's row) is not shown.
    CHECK(r->body.find("<span class=\"tt-name\">bash</span>") != std::string::npos);
    CHECK(r->body.find("<span class=\"tt-name\">cron</span>") == std::string::npos);
    // The selector lists the hours the device reported, the shown one selected. Its URL names
    // THIS device and carries no host-picker include, so a later hour change cannot ask another.
    CHECK(r->body.find("<option value=\"7200\" selected>") != std::string::npos);
    CHECK(r->body.find("<option value=\"3600\">") != std::string::npos);
    CHECK(r->body.find("id=\"echo-tree-hour\" name=\"hour\"") != std::string::npos);
    CHECK(r->body.find("process-tree/run?device=dev-A&amp;preset=24h") != std::string::npos);
    CHECK(r->body.find("hx-include") == std::string::npos);
    // Out-of-band: the device DNS / ARP panels follow the shown hour, for this device.
    CHECK(r->body.find("id=\"echo-devnet\" hx-swap-oob=\"true\"") != std::string::npos);
    CHECK(r->body.find("device-net?device=dev-A&amp;hour=7200") != std::string::npos);

    SECTION("an explicit hour picks that hour's tree") {
        h.proc_output = "__schema__|hour_ts|name|parent_name|user|start_count|stop_count|"
                        "abnormal_exit_count\n3600|cron||root|2|2|0\n__total__|1\n";
        auto older = h.run_result("3600");
        REQUIRE(older);
        CHECK(older->body.find("<span class=\"tt-name\">cron</span>") != std::string::npos);
        CHECK(older->body.find("<span class=\"tt-name\">bash</span>") == std::string::npos);
        CHECK(older->body.find("<option value=\"3600\" selected>") != std::string::npos);
        CHECK(older->body.find("device-net?device=dev-A&amp;hour=3600") != std::string::npos);
    }
    SECTION("an hour the device did not report is offered and selected, so the box and banner agree") {
        h.hours_output = "__schema__|hour_ts\n7200\n__total__|1\n";
        auto other = h.run_result("10800");
        REQUIRE(other);
        CHECK(other->body.find("<option value=\"10800\" selected>") != std::string::npos);
        CHECK(other->body.find("<option value=\"7200\">") != std::string::npos);
        CHECK(other->body.find("1970-01-01T03:00:00Z") != std::string::npos); // the banner's hour
        CHECK(other->body.find("No process activity recorded for this hour") != std::string::npos);
    }
    SECTION("no hour at all is the window's last complete bucket") {
        auto none = h.run_result("");
        REQUIRE(none);
        // Hour 7200's rows are not that bucket, so the tree is empty for it, and says so.
        CHECK(none->body.find("No process activity recorded for this hour") != std::string::npos);
        CHECK(none->body.find("<span class=\"tt-name\">bash</span>") == std::string::npos);
        CHECK(none->body.find(" selected>") != std::string::npos);
    }
    SECTION("an unparseable hour is refused") {
        EchoHarness bad;
        bad.proc_output = kProcTwoHours;
        auto res = bad.run_result("yesterday");
        REQUIRE(res);
        CHECK(res->body.find("not a valid time") != std::string::npos);
        CHECK(bad.find_audit("echo.process_tree.read", "success") == nullptr);
    }
    SECTION("a device that could not list the hours still shows the tree and says so") {
        h.hours_output = "error|no such column: hour_ts";
        auto res = h.run_result();
        REQUIRE(res);
        CHECK(res->body.find("<span class=\"tt-name\">bash</span>") != std::string::npos);
        CHECK(res->body.find("The list of other hours was unavailable") != std::string::npos);
        CHECK(res->body.find("<option value=\"7200\" selected>") != std::string::npos);
    }
}

TEST_CASE("echo routes: an agent without the roll-up store gets the upgrade note for the tree",
          "[echo][routes][skew]") {
    EchoHarness h;
    h.proc_output = "error|no such column: parent_name";
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->body.find("This device runs an agent without the roll-up store: upgrade the agent") !=
          std::string::npos);
    CHECK(r->body.find("parent_name") == std::string::npos); // the raw SQLite text is not the message
    CHECK(h.find_audit("echo.process_tree.read", "success") == nullptr);

    SECTION("any other agent error keeps its reason") {
        h.proc_output = "error|database is locked";
        auto other = h.run_result();
        REQUIRE(other);
        CHECK(other->body.find("The device reported an error: database is locked") != std::string::npos);
    }
    SECTION("a failed command reads the same way") {
        DexAgentResponse f;
        f.agent_id = "dev-A";
        f.status = 2;
        f.error_detail = "no such table: process_hourly";
        h.frames_override[kProcCmd] = {f};
        auto failed = h.run_result();
        REQUIRE(failed);
        CHECK(failed->body.find("upgrade the agent") != std::string::npos);
    }
    SECTION("an answer with no schema is unreadable and never an empty tree") {
        h.proc_output = "7200|bash|systemd|alice|3|3|1\n";
        auto bare = h.run_result();
        REQUIRE(bare);
        CHECK(bare->body.find("could not be read as process activity") != std::string::npos);
        CHECK(bare->body.find("No process activity recorded") == std::string::npos);
        CHECK(h.find_audit("echo.process_tree.read", "success") == nullptr);
    }
}

TEST_CASE("echo routes: the tree names why connections are missing", "[echo][routes][skew]") {
    EchoHarness h;
    SECTION("an old agent") {
        h.tcp_output = "error|no such column: failed_count";
        auto r = h.run_result();
        REQUIRE(r);
        CHECK(r->body.find("<span class=\"tt-name\">bash</span>") != std::string::npos); // tree kept
        CHECK(r->body.find("Connection data was unavailable for this host") != std::string::npos);
        CHECK(r->body.find("upgrade the agent") != std::string::npos);
    }
    SECTION("an answer with no schema") {
        h.tcp_output = "";
        auto r = h.run_result();
        REQUIRE(r);
        CHECK(r->body.find("its answer could not be read") != std::string::npos);
    }
    SECTION("a healthy empty answer says nothing is wrong") {
        auto r = h.run_result();
        REQUIRE(r);
        CHECK(r->body.find("Connection data was unavailable") == std::string::npos);
    }
}

// B1: the agent flushes a long answer as several frames and the store answers newest first.
// Reading only one frame showed a torn tree; every frame of the command is merged.
namespace {
DexAgentResponse frame(const std::string& body, int status = 1) {
    DexAgentResponse f;
    f.agent_id = "dev-A";
    f.status = status;
    f.output = body;
    return f;
}
const char* kProcSchema =
    "__schema__|hour_ts|name|parent_name|user|start_count|stop_count|abnormal_exit_count";
} // namespace

TEST_CASE("echo routes: a process answer in two frames reconstructs the whole tree",
          "[echo][routes][frames]") {
    EchoHarness h;
    // Newest first, as the store answers: the data-only frame ahead of the schema frame.
    h.frames_override[kProcCmd] = {frame("7200|bash|systemd|alice|3|3|1\n__total__|2"),
                                   frame(std::string(kProcSchema) + "\n7200|systemd||root|1|0|0")};
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->body.find("<span class=\"tt-name\">systemd</span>") != std::string::npos);
    CHECK(r->body.find("<span class=\"tt-name\">bash</span>") != std::string::npos);
    CHECK(r->body.find("2 process names") != std::string::npos);
    CHECK(r->body.find("unreadable") == std::string::npos);
    CHECK(h.find_audit("echo.process_tree.read", "success") != nullptr);

    SECTION("the same frames in the other order read the same") {
        h.frames_override[kProcCmd] = {frame(std::string(kProcSchema) + "\n7200|systemd||root|1|0|0"),
                                       frame("7200|bash|systemd|alice|3|3|1\n__total__|2")};
        auto swapped = h.run_result();
        REQUIRE(swapped);
        CHECK(swapped->body.find("2 process names") != std::string::npos);
    }
    SECTION("an answer that is still streaming is not rendered as the whole") {
        EchoHarness s;
        s.frames_override[kProcCmd] = {frame(std::string(kProcSchema) + "\n7200|systemd||root|1|0|0", 0)};
        auto streaming = s.run_result();
        REQUIRE(streaming);
        CHECK(streaming->body.find("process-tree/result") != std::string::npos); // keeps polling
        CHECK(streaming->body.find("tt-name") == std::string::npos);
        CHECK(s.find_audit("echo.process_tree.read", "success") == nullptr);
    }
}

TEST_CASE("echo routes: an answer at the agent's row cap is said to be cut", "[echo][routes][frames]") {
    const auto rows_for = [](std::size_t n) {
        std::string out = std::string(kProcSchema) + "\n";
        for (std::size_t i = 0; i < n; ++i)
            out += "7200|p" + std::to_string(i) + "||u|1|0|0\n";
        return out + "__total__|" + std::to_string(n);
    };
    EchoHarness h;
    h.proc_output = rows_for(kEchoAgentRowCap);
    auto cut = h.run_result();
    REQUIRE(cut);
    CHECK(cut->status == 200);
    CHECK(cut->body.find("Results were cut at 10,000 rows for this hour") != std::string::npos);
    CHECK(cut->body.find("echo-tree-banner") != std::string::npos); // the rows that came are shown
    // One row under the cap is complete: no note.
    EchoHarness under;
    under.proc_output = rows_for(kEchoAgentRowCap - 1);
    auto whole = under.run_result();
    REQUIRE(whole);
    CHECK(whole->body.find("were cut at") == std::string::npos);

    SECTION("the connection list is held to the same rule") {
        std::string tcp =
            "__schema__|hour_ts|remote_addr|remote_port|proto|process_name|connect_count|"
            "disconnect_count|failed_count\n";
        for (std::size_t i = 0; i < kEchoAgentRowCap; ++i)
            tcp += "7200|10.0.0.1|" + std::to_string(1 + i % 60000) + "|tcp|bash|1|1|0\n";
        EchoHarness c;
        c.tcp_output = tcp;
        auto r = c.run_result();
        REQUIRE(r);
        CHECK(r->body.find("Connection results were cut at 10,000 rows for this hour") != std::string::npos);
        CHECK(r->body.find(">Results were cut") == std::string::npos); // the process list was whole
    }
}

// B6: rows the parser cannot place are counted and shown, never silently absent.
TEST_CASE("echo routes: rows that could not be read are counted on the page", "[echo][routes][security]") {
    EchoHarness h;
    h.proc_output = std::string(kProcSchema) +
                    "\n7200|systemd||root|1|0|0\n"
                    "7200|x|winword.exe|SYSTEM|5|5|0|9|9\n" // a forged name carrying pipes
                    "7200|torn||u|1\n__total__|3";
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->body.find("2 rows unreadable") != std::string::npos);
    CHECK(r->body.find("1 process names") != std::string::npos);
    CHECK(r->body.find("tt-name\">x<") == std::string::npos); // the forged row is not in the tree
}

// B3: the DNS / ARP panels live outside the tree, so every answer that is not a finished tree
// for this device clears them. One host's tables must never sit under another host's view.
TEST_CASE("echo routes: every answer that is not a finished tree clears the DNS and ARP panels",
          "[echo][routes][devnet]") {
    const std::string reset = "<div id=\"echo-devnet\" hx-swap-oob=\"true\"></div>";
    SECTION("a blank host") {
        EchoHarness h;
        auto r = h.sink.Get("/fragments/echo/process-tree/run?device=&preset=24h");
        REQUIRE(r);
        CHECK(r->body.find("Select a host") != std::string::npos);
        CHECK(r->body.find(reset) != std::string::npos);
    }
    SECTION("the poll fragment /run answers while the tree is rebuilt") {
        EchoHarness h;
        auto r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=24h");
        REQUIRE(r);
        CHECK(r->body.find("process-tree/result") != std::string::npos);
        CHECK(r->body.find(reset) != std::string::npos);
    }
    SECTION("an offline device") {
        EchoHarness h;
        h.dispatch_sent = 0;
        auto r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=24h");
        REQUIRE(r);
        CHECK(r->body.find("Device offline") != std::string::npos);
        CHECK(r->body.find(reset) != std::string::npos);
    }
    SECTION("an operator without Execute") {
        EchoHarness h;
        h.allow_execute = false;
        auto run = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=24h");
        REQUIRE(run);
        CHECK(run->body.find(reset) != std::string::npos);
        auto result = h.run_result();
        REQUIRE(result);
        CHECK(result->body.find("Execute") != std::string::npos);
        CHECK(result->body.find(reset) != std::string::npos);
    }
    SECTION("an invalid window or hour") {
        EchoHarness h;
        auto r = h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=custom&from=garbage");
        REQUIRE(r);
        CHECK(r->body.find("not a valid time") != std::string::npos);
        CHECK(r->body.find(reset) != std::string::npos);
    }
    SECTION("a result still being collected, and one that timed out") {
        EchoHarness h;
        h.frames_override[kProcCmd] = {}; // nothing stored yet
        auto pending = h.run_result();
        REQUIRE(pending);
        CHECK(pending->body.find("hx-trigger=\"load delay:700ms\"") != std::string::npos);
        CHECK(pending->body.find(reset) != std::string::npos);
        auto late = h.sink.Get("/fragments/echo/process-tree/result?device=dev-A&preset=24h&hour=7200&pcmd=" +
                               kProcCmd + "&tcmd=" + kTcpCmd + "&hcmd=" + kHoursCmd + "&n=40");
        REQUIRE(late);
        CHECK(late->body.find("timed out") != std::string::npos);
        CHECK(late->body.find(reset) != std::string::npos);
    }
    SECTION("an agent error") {
        EchoHarness h;
        h.proc_output = "error|boom";
        auto r = h.run_result();
        REQUIRE(r);
        CHECK(r->body.find(reset) != std::string::npos);
    }
    SECTION("a finished tree replaces the panel once, for this device") {
        EchoHarness h;
        auto r = h.run_result();
        REQUIRE(r);
        CHECK(r->body.find(reset) == std::string::npos);
        CHECK(count_occurrences(r->body, "id=\"echo-devnet\"") == 1);
        CHECK(r->body.find("hx-get=\"/fragments/echo/process-tree/device-net?device=dev-A&amp;hour=7200\"") !=
              std::string::npos);
        CHECK(r->body.find("hx-include") == std::string::npos); // the picker's current value is not asked
    }
}

// B8: dispatch details name the window and the hour; the success detail names the hour.
TEST_CASE("echo routes: the tree audit rows name the window and the hour", "[echo][routes][audit]") {
    EchoHarness h;
    (void)h.sink.Get("/fragments/echo/process-tree/run?device=dev-A&preset=24h&hour=3600");
    const auto* run = h.find_audit("echo.process_tree.read", "dispatched");
    REQUIRE(run != nullptr);
    CHECK(run->detail.starts_with("dispatch preset=24h from="));
    CHECK(run->detail.find(" to=") != std::string::npos);
    CHECK(run->detail.find(" hour=3600 command_id=echo-p") != std::string::npos);

    EchoHarness r;
    (void)r.run_result();
    const auto* ok = r.find_audit("echo.process_tree.read", "success");
    REQUIRE(ok != nullptr);
    CHECK(ok->detail.find(" hour=7200 ") != std::string::npos);
    CHECK(ok->detail.find("from=") != std::string::npos);
    CHECK(ok->detail.find("to=") != std::string::npos);
}

TEST_CASE("echo routes: /detail joins connections by process name", "[echo][routes][detail]") {
    EchoHarness h;
    h.tcp_output =
        "__schema__|hour_ts|remote_addr|remote_port|proto|process_name|connect_count|"
        "disconnect_count|failed_count\n"
        "7200|1.2.3.4|443|tcp|bash|5|4|1\n"
        "3600|9.9.9.9|80|tcp|bash|1|1|0\n"; // another hour: not shown
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));
    auto bash = h.get_detail(token, 1);
    REQUIRE(bash);
    CHECK(bash->body.find("1.2.3.4:443") != std::string::npos);
    CHECK(bash->body.find("9.9.9.9") == std::string::npos);
    auto systemd = h.get_detail(token, 0);
    REQUIRE(systemd);
    CHECK(systemd->body.find("1.2.3.4") == std::string::npos);
    CHECK(systemd->body.find("No TCP connections recorded under this name") != std::string::npos);
}

TEST_CASE("echo routes: /device-net dispatches only the hourly tables for the chosen hour",
          "[echo][routes][sql]") {
    SECTION("with an hour: that single bucket, only the counts the agent measures") {
        EchoHarness h;
        auto r = h.sink.Get("/fragments/echo/process-tree/device-net?device=dev-A&hour=7200");
        REQUIRE(r);
        REQUIRE(h.sql_log.size() == 2);
        CHECK(h.sql_log[0] ==
              "SELECT hour_ts, name, record_type, data, appear_count, remove_count "
              "FROM $DNS_Hourly WHERE hour_ts >= 7200 AND hour_ts <= 7200 "
              "ORDER BY hour_ts DESC LIMIT 10000");
        CHECK(h.sql_log[1] ==
              "SELECT hour_ts, interface, ip_address, mac_address, appear_count, remove_count "
              "FROM $ARP_Hourly WHERE hour_ts >= 7200 AND hour_ts <= 7200 "
              "ORDER BY hour_ts DESC LIMIT 10000");
        for (const char* unmeasured : {"negative_count", "is_router", "rebind_count"})
            for (const auto& sql : h.sql_log)
                CHECK(sql.find(unmeasured) == std::string::npos);
        CHECK(r->body.find("hour=7200") != std::string::npos); // the poll keeps the hour
        // The dispatch audit names the hour it read.
        const auto* dns = h.find_audit("echo.dns.read", "dispatched");
        REQUIRE(dns != nullptr);
        CHECK(dns->detail == "hour=7200 command_id=echo-d");
        const auto* arp = h.find_audit("echo.arp.read", "dispatched");
        REQUIRE(arp != nullptr);
        CHECK(arp->detail == "hour=7200 command_id=echo-a");
    }
    SECTION("without one: the default 24-hour window") {
        EchoHarness h;
        (void)h.sink.Get("/fragments/echo/process-tree/device-net?device=dev-A");
        REQUIRE(h.sql_log.size() == 2);
        for (const auto& sql : h.sql_log) {
            CHECK(sql.find("_Live") == std::string::npos);
            CHECK((number_after(sql, "hour_ts <= ") - number_after(sql, "hour_ts >= ")) / 3600 == 23);
        }
    }
    SECTION("a bad hour is refused before any dispatch") {
        EchoHarness h;
        auto r = h.sink.Get("/fragments/echo/process-tree/device-net?device=dev-A&hour=soon");
        REQUIRE(r);
        CHECK(r->body.find("not a valid time") != std::string::npos);
        CHECK(h.sql_log.empty());
    }
}

namespace {
const char* kDnsSchema = "__schema__|hour_ts|name|record_type|data|appear_count|remove_count\n";
const char* kArpSchema =
    "__schema__|hour_ts|interface|ip_address|mac_address|appear_count|remove_count\n";
} // namespace

TEST_CASE("echo routes: /device-net renders the chosen hour's DNS and ARP activity",
          "[echo][routes][devnet]") {
    EchoHarness h;
    h.dns_output = std::string(kDnsSchema) +
                   "7200|new.test|A|1.1.1.1|4|3\n"
                   "3600|old.test|A|2.2.2.2|1|1\n__total__|2\n";
    h.arp_output = std::string(kArpSchema) + "7200|eth0|10.0.0.1|aa:bb:cc:dd:ee:ff|1|0\n__total__|1\n";
    const std::string poll = "/fragments/echo/process-tree/device-net?device=dev-A&dcmd=" + kDnsCmd +
                             "&acmd=" + kArpCmd + "&n=1";
    auto chosen = h.sink.Get(poll + "&hour=3600");
    REQUIRE(chosen);
    CHECK(chosen->body.find("old.test") != std::string::npos);
    CHECK(chosen->body.find("new.test") == std::string::npos);
    CHECK(chosen->body.find("No ARP activity recorded for this hour") != std::string::npos);
    // No hour given: the newest hour present in either answer.
    auto newest = h.sink.Get(poll);
    REQUIRE(newest);
    CHECK(newest->body.find("new.test") != std::string::npos);
    CHECK(newest->body.find("old.test") == std::string::npos);
    // Nothing the agent does not write is shown as a measure.
    for (const char* gone : {"No such name", "Rebinds", "<th>Role</th>"})
        CHECK(newest->body.find(gone) == std::string::npos);
}

// B8: the poll that renders the rows is the audited read, as on the device pages; the
// dispatch row alone recorded only a command id.
TEST_CASE("echo routes: /device-net audits the DNS and ARP rows it renders", "[echo][routes][audit]") {
    EchoHarness h;
    h.dns_output = std::string(kDnsSchema) +
                   "7200|a.test|A|1.1.1.1|1|0\n7200|b.test|A|1.1.1.2|1|0\n3600|old.test|A|2.2.2.2|1|1\n"
                   "__total__|3\n";
    h.arp_output = std::string(kArpSchema) + "7200|eth0|10.0.0.1|aa:bb:cc:dd:ee:ff|1|0\n__total__|1\n";
    const std::string poll = "/fragments/echo/process-tree/device-net?device=dev-A&dcmd=" + kDnsCmd +
                             "&acmd=" + kArpCmd + "&n=1&hour=7200";
    auto r = h.sink.Get(poll);
    REQUIRE(r);
    const auto* dns = h.find_audit("echo.dns.read", "success");
    REQUIRE(dns != nullptr);
    CHECK(dns->detail == "hour=7200 rows=2"); // the hour's rows only, as an int64 count
    CHECK(dns->target_id == "dev-A");
    const auto* arp = h.find_audit("echo.arp.read", "success");
    REQUIRE(arp != nullptr);
    CHECK(arp->detail == "hour=7200 rows=1");

    SECTION("a failed read is a failure row with no free text") {
        EchoHarness f;
        f.dns_output = "error|query failed: no such column: negative_count\nsecret detail";
        f.arp_output = std::string(kArpSchema) + "__total__|0\n";
        auto res = f.sink.Get(poll);
        REQUIRE(res);
        const auto* fail = f.find_audit("echo.dns.read", "failure");
        REQUIRE(fail != nullptr);
        CHECK(fail->detail == "hour=7200");
        CHECK(f.find_audit("echo.dns.read", "success") == nullptr);
        const auto* ok = f.find_audit("echo.arp.read", "success");
        REQUIRE(ok != nullptr);
        CHECK(ok->detail == "hour=7200 rows=0");
    }
    SECTION("a poll that is not ready yet audits nothing") {
        EchoHarness pending;
        DexAgentResponse running;
        running.agent_id = "dev-A";
        running.status = 0;
        running.output = std::string(kDnsSchema);
        pending.frames_override[kDnsCmd] = {running};
        auto res = pending.sink.Get(poll);
        REQUIRE(res);
        CHECK(res->body.find("device-net?device=dev-A") != std::string::npos); // keeps polling
        CHECK(pending.find_audit("echo.dns.read", "success") == nullptr);
        CHECK(pending.find_audit("echo.arp.read", "success") == nullptr);
    }
}

TEST_CASE("echo routes: a DNS or ARP failure is an error in the panel and never an empty note",
          "[echo][routes][skew]") {
    const std::string poll = "/fragments/echo/process-tree/device-net?device=dev-A&dcmd=" + kDnsCmd +
                             "&acmd=" + kArpCmd + "&n=1&hour=7200";
    const std::string upgrade = "This device runs an agent without the roll-up store: upgrade the agent";
    SECTION("an old agent, both panels") {
        EchoHarness h;
        h.dns_output = "error|query failed: no such column: negative_count";
        h.arp_output = "error|unknown table: $ARP_Hourly";
        auto r = h.sink.Get(poll);
        REQUIRE(r);
        CHECK(count_occurrences(r->body, upgrade) == 2);
        CHECK(r->body.find("recorded for this hour") == std::string::npos);
        CHECK(r->body.find("may be disabled") == std::string::npos);
    }
    SECTION("a failed command") {
        EchoHarness h;
        DexAgentResponse f;
        f.agent_id = "dev-A";
        f.status = 2;
        f.error_detail = "plugin crashed";
        h.frames_override[kDnsCmd] = {f};
        h.arp_output = std::string(kArpSchema) + "__total__|0\n";
        auto r = h.sink.Get(poll);
        REQUIRE(r);
        CHECK(r->body.find("The device reported an error: plugin crashed") != std::string::npos);
        CHECK(r->body.find("No ARP activity recorded for this hour") != std::string::npos); // ARP is fine and empty
    }
    SECTION("an answer with no schema and an oversize answer") {
        EchoHarness h;
        h.dns_output = "7200|a.test|A|1.1.1.1|1|0\n";
        h.arp_output = std::string(kMaxEchoDeviceNetOutputBytes + 1, 'x');
        auto r = h.sink.Get(poll);
        REQUIRE(r);
        CHECK(r->body.find("answer could not be read") != std::string::npos);
        CHECK(r->body.find("unexpectedly large") != std::string::npos);
        CHECK(r->body.find("a.test") == std::string::npos);
    }
    SECTION("a quiet host is still said to be quiet") {
        EchoHarness h;
        h.dns_output = std::string(kDnsSchema) + "__total__|0\n";
        h.arp_output = std::string(kArpSchema) + "__total__|0\n";
        auto r = h.sink.Get(poll);
        REQUIRE(r);
        CHECK(r->body.find("No DNS cache activity recorded for this hour") != std::string::npos);
        CHECK(r->body.find("upgrade the agent") == std::string::npos);
    }
    SECTION("cut and unreadable rows are flagged") {
        EchoHarness h;
        std::string dns = kDnsSchema;
        for (std::size_t i = 0; i < kEchoAgentRowCap; ++i)
            dns += "7200|n" + std::to_string(i) + ".test|A|1.1.1.1|1|0\n";
        h.dns_output = dns;
        h.arp_output = std::string(kArpSchema) + "7200|eth0|10.0.0.1|aa:bb|1|0|9|9\n__total__|1\n";
        auto r = h.sink.Get(poll);
        REQUIRE(r);
        CHECK(r->body.find("Results were cut at 10,000 rows for this hour") != std::string::npos);
        CHECK(r->body.find("1 row unreadable") != std::string::npos);
    }
}

TEST_CASE("echo routes: capture-source cards never relabel the old live count",
          "[echo][routes][capture-sources]") {
    SECTION("<src>_rows alone") {
        EchoHarness h;
        h.status_output = "config|process_enabled|true\nconfig|process_rows|1234\n";
        auto res = h.run_capture_sources();
        REQUIRE(res);
        CHECK(res->body.find(">1234<") != std::string::npos);
        CHECK(res->body.find("$Process_Hourly") != std::string::npos);
        CHECK(res->body.find("upgrade the agent") == std::string::npos);
    }
    SECTION("<src>_live_rows alone is a dash and one upgrade note") {
        EchoHarness h;
        h.status_output = "config|process_enabled|true\nconfig|process_live_rows|5678\n";
        auto res = h.run_capture_sources();
        REQUIRE(res);
        CHECK(res->body.find("5678") == std::string::npos);
        CHECK(res->body.find("This device runs an agent without the roll-up tables; upgrade the agent") !=
              std::string::npos);
        CHECK(res->body.find("&mdash;") != std::string::npos);
    }
    SECTION("neither key: a dash, not zero") {
        EchoHarness h;
        h.status_output = "config|process_enabled|true\n";
        auto res = h.run_capture_sources();
        REQUIRE(res);
        CHECK(res->body.find("&mdash;") != std::string::npos);
        CHECK(res->body.find("upgrade the agent") == std::string::npos);
    }
    SECTION("an oversize status reply is refused with a note") {
        EchoHarness h;
        h.status_output = "config|process_enabled|true\n" + std::string(kMaxEchoStatusOutputBytes, 'x');
        auto res = h.run_capture_sources();
        REQUIRE(res);
        CHECK(res->body.find("unexpectedly large status reply") != std::string::npos);
        CHECK(res->body.find("capCards") == std::string::npos);
    }
}

// SEC-2/SEC-3 confinement-gap class (found during a docs sweep): devices_fn_
// backing both Echo frame device pickers is username-keyed and does not
// confine a service-scoped API token whose principal resolves to an
// unscoped grant.
TEST_CASE("Echo device pickers: service-scoped token denied on both frames, "
          "denial audited",
          "[echo][tree][routes][security]") {
    EchoHarness h;
    h.service_scoped = true;

    auto tree = h.sink.Get("/fragments/echo/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 403);
    // #3167: no `.permission` (no grant admits a service-scoped caller here —
    // naming one is a false self-remediation claim), and header/body
    // correlation-id parity.
    auto tree_body = nlohmann::json::parse(tree->body, nullptr, false);
    REQUIRE_FALSE(tree_body.is_discarded());
    CHECK_FALSE(tree_body["error"].contains("permission"));
    CHECK_FALSE(tree_body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(tree->get_header_value("X-Correlation-Id") ==
         tree_body["error"]["correlation_id"].get<std::string>());

    auto cap = h.sink.Get("/fragments/echo/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 403);
    auto cap_body = nlohmann::json::parse(cap->body, nullptr, false);
    REQUIRE_FALSE(cap_body.is_discarded());
    CHECK_FALSE(cap_body["error"].contains("permission"));
    CHECK_FALSE(cap_body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(cap->get_header_value("X-Correlation-Id") ==
         cap_body["error"]["correlation_id"].get<std::string>());

    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[0].action == "echo.device_picker.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[1].action == "echo.device_picker.view");
    CHECK(h.audit_log[1].result == "denied");
}

// #4027 REST twins: GET /api/v1/echo/process-tree + /api/v1/echo/capture-sources
// share deny_fleet_wide_device_enumeration with their fragment siblings above —
// pin the SAME service-scoped-token 403 + audit on the new JSON routes too, so a
// future edit to the shared guard can't silently narrow to only the two original
// call sites.
TEST_CASE("Echo device picker REST twins: service-scoped token denied, audited",
          "[echo][tree][routes][security][rest]") {
    EchoHarness h;
    h.service_scoped = true;

    auto tree = h.sink.Get("/api/v1/echo/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 403);
    auto cap = h.sink.Get("/api/v1/echo/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 403);

    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[0].action == "echo.device_picker.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[1].action == "echo.device_picker.view");
    CHECK(h.audit_log[1].result == "denied");
}

TEST_CASE("Echo device picker REST twins: Infrastructure:Read denial -> 403, no data leak",
          "[echo][tree][routes][security][rest]") {
    EchoHarness h;
    h.allow_read = false;
    h.devices_list = {DeviceRow{.agent_id = "dev-A", .hostname = "host-a", .online = true}};

    auto tree = h.sink.Get("/api/v1/echo/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 403);
    CHECK(tree->body.find("dev-A") == std::string::npos);

    auto cap = h.sink.Get("/api/v1/echo/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 403);
    CHECK(cap->body.find("dev-A") == std::string::npos);
}

// #4143 review fix regression (BLOCKING, ADR-0017 INV-4/INV-7): an operator
// admitted via an ancestor management-group role — not a DIRECT member — must
// see the SAME rows gate.scope authorizes, not a subset silently narrowed by
// the old direct-membership-only resolver. Models the divergence the same way
// test_device_routes.cpp's "ancestor-authorized device" tests do: gate.scope
// (the ADR-0017-aware admit) includes "ancestor-child"; the flat resolver
// (devices_list, still wired to the un-migrated HTML fragment routes) does
// not. all_devices_fn_ (the REST twins' new row source) is the full registry —
// a strict superset of devices_list — so this only passes if gate.scope is
// genuinely the SOLE filter, not ANDed with the old resolver.
TEST_CASE("Echo device picker REST twins: ancestor-scoped (not direct-member) "
          "admit sees the gate-authorized row, not the flat resolver's subset",
          "[echo][tree][routes][security][rest][adr-0017]") {
    EchoHarness h;
    h.devices_list = {DeviceRow{.agent_id = "mine", .hostname = "mine-host", .online = true}};
    h.all_devices_list_override = std::vector<DeviceRow>{
        DeviceRow{.agent_id = "mine", .hostname = "mine-host", .online = true},
        DeviceRow{.agent_id = "ancestor-child", .hostname = "ancestor-host", .online = true},
    };
    // gate.scope admits BOTH — the ancestor-ward expansion a real
    // fleet_read_fn_/require_fleet_read performs in production.
    h.fleet_scope = std::vector<std::string>{"mine", "ancestor-child"};

    auto tree = h.sink.Get("/api/v1/echo/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 200);
    CHECK(tree->body.find("mine-host") != std::string::npos);
    CHECK(tree->body.find("ancestor-host") != std::string::npos); // was silently dropped pre-fix

    auto cap = h.sink.Get("/api/v1/echo/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 200);
    CHECK(cap->body.find("mine-host") != std::string::npos);
    CHECK(cap->body.find("ancestor-host") != std::string::npos); // was silently dropped pre-fix
}

// #4027 fix round (CDX-P1-02/K1): renamed from "...including offline devices" —
// that title claimed a production behavior this test does not exercise. This
// harness's `devices` stub returns whatever `devices_list` is set to directly,
// bypassing the real production provider entirely (`server.cpp`'s `devices_fn`,
// which sources exclusively from the live-session registry and stamps
// `online=true` unconditionally — every row is online in production today).
// What this test legitimately proves: the ROUTE/BUILDER passthrough does not
// discriminate against an `online=false` row if one is ever supplied — i.e. the
// route is READY for a future offline-inclusive provider, not that one is wired
// today. See echo_tree_routes.hpp's builder doc comment for the full correction.
TEST_CASE("Echo device picker REST twins: happy path returns the A4-enveloped "
          "device list; the route/builder does not discriminate against an "
          "online=false row if the provider ever supplies one",
          "[echo][tree][routes][rest]") {
    EchoHarness h;
    h.devices_list = {
        DeviceRow{.agent_id = "dev-A", .hostname = "host-a", .os = "linux",
                  .arch = "x86_64", .agent_version = "1.2.3", .online = true},
        DeviceRow{.agent_id = "dev-B", .hostname = "host-b", .os = "windows",
                  .arch = "arm64", .agent_version = "1.2.3", .online = false},
    };

    auto tree = h.sink.Get("/api/v1/echo/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 200);
    auto tree_json = nlohmann::json::parse(tree->body, nullptr, false);
    REQUIRE_FALSE(tree_json.is_discarded());
    CHECK(tree_json["meta"]["api_version"] == "v1");
    const auto& tree_devices = tree_json["data"]["devices"];
    REQUIRE(tree_devices.size() == 2);
    // Sorted by display name (hostname), ascending — host-a before host-b.
    CHECK(tree_devices[0]["agent_id"] == "dev-A");
    CHECK(tree_devices[0]["online"] == true);
    CHECK(tree_devices[1]["agent_id"] == "dev-B");
    CHECK(tree_devices[1]["online"] == false); // NOT hidden by the route/builder — see comment above

    // Same shared builder underlies the sibling endpoint — same shape, same data.
    auto cap = h.sink.Get("/api/v1/echo/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 200);
    auto cap_json = nlohmann::json::parse(cap->body, nullptr, false);
    REQUIRE_FALSE(cap_json.is_discarded());
    CHECK(cap_json["data"]["devices"].size() == 2);
}

// #4027 fix round (CDX-P1-01/K4 falsifier): a caller admitted with a SCOPED
// (non-TOP) VisibleSet — the shape a management-group-scoped-only RBAC grant
// produces via require_fleet_read/authorize_list_read — must be admitted
// (200, not the pre-fix 403) AND see only the agents in scope, never the
// unfiltered fleet. This is the concrete regression test for the finding: a
// bare perm_fn_/require_permission gate cannot produce this shape at all (it
// is binary admit-unfiltered-or-deny), so a test that never exercises a
// non-TOP gate can't tell the fixed gate from the old one.
TEST_CASE("Echo device picker REST twins: group-scoped grant is ADMITTED and "
          "filtered to exactly its VisibleSet, both surfaces",
          "[echo][tree][routes][rest][security]") {
    EchoHarness h;
    h.devices_list = {
        DeviceRow{.agent_id = "dev-A", .hostname = "host-a", .os = "linux",
                  .arch = "x86_64", .agent_version = "1.2.3", .online = true},
        DeviceRow{.agent_id = "dev-B", .hostname = "host-b", .os = "windows",
                  .arch = "arm64", .agent_version = "1.2.3", .online = true},
    };
    // A group-scoped-only grant: allow_read stays true (some grant admits),
    // but the composed VisibleSet is narrowed to dev-A only — exactly what
    // require_fleet_read would return for an operator whose Infrastructure:Read
    // exists only via a management-group role assignment covering dev-A.
    h.fleet_scope = std::vector<std::string>{"dev-A"};

    auto tree = h.sink.Get("/api/v1/echo/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 200); // NOT 403 — the pre-fix behavior for this exact grant shape
    auto tree_json = nlohmann::json::parse(tree->body, nullptr, false);
    REQUIRE_FALSE(tree_json.is_discarded());
    const auto& tree_devices = tree_json["data"]["devices"];
    REQUIRE(tree_devices.size() == 1);
    CHECK(tree_devices[0]["agent_id"] == "dev-A");

    auto cap = h.sink.Get("/api/v1/echo/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 200);
    auto cap_json = nlohmann::json::parse(cap->body, nullptr, false);
    REQUIRE_FALSE(cap_json.is_discarded());
    const auto& cap_devices = cap_json["data"]["devices"];
    REQUIRE(cap_devices.size() == 1);
    CHECK(cap_devices[0]["agent_id"] == "dev-A");
}

TEST_CASE("Echo device picker REST twins: fleet_read_fn_ unwired fails closed (503, "
          "not the pre-fix perm_fn_ path)",
          "[echo][tree][routes][rest][security]") {
    EchoHarness h;
    h.devices_list = {DeviceRow{.agent_id = "dev-A", .hostname = "host-a", .online = true}};
    h.routes.set_fleet_read_fn(nullptr); // simulate a misconfigured call site

    auto tree = h.sink.Get("/api/v1/echo/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 503);
    CHECK(tree->body.find("dev-A") == std::string::npos);

    auto cap = h.sink.Get("/api/v1/echo/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 503);
    CHECK(cap->body.find("dev-A") == std::string::npos);
}

// #4027 shared builders (api-twin-recipe.md Rule 1): pure, no route/store needed.
// echo_process_tree_frame_json and echo_capture_sources_devices_json are two named
// wrappers over one internal helper — pin that they stay byte-identical for the
// same input, which is the actual regression test for Rule 1 holding.
TEST_CASE("echo_process_tree_frame_json / echo_capture_sources_devices_json: "
          "identical shape, sorted by display name",
          "[echo][tree][model]") {
    const std::vector<DeviceRow> devices = {
        DeviceRow{.agent_id = "dev-Z", .hostname = "", .os = "linux", .online = true},
        DeviceRow{.agent_id = "dev-A", .hostname = "alpha", .os = "windows", .online = false},
    };
    const auto frame_json = echo_process_tree_frame_json(devices);
    const auto cap_json = echo_capture_sources_devices_json(devices);
    CHECK(frame_json == cap_json);

    auto parsed = nlohmann::json::parse(frame_json, nullptr, false);
    REQUIRE_FALSE(parsed.is_discarded());
    REQUIRE(parsed.size() == 2);
    // "alpha" (dev-A's hostname) sorts before "dev-Z" (dev-Z has no hostname, so
    // its agent_id is the sort key) — matches render_frame's own sort.
    CHECK(parsed[0]["agent_id"] == "dev-A");
    CHECK(parsed[1]["agent_id"] == "dev-Z");
}

TEST_CASE("echo_retention_paused_json: sorts value-error first, then oldest-paused-first",
          "[echo][tree][model]") {
    EchoRetentionPausedScan scan;
    scan.scan_id = "scan-1";
    scan.scan_count = 3;
    scan.agents_responded = 3;
    EchoPausedSourceRow older;
    older.agent_id = "dev-old";
    older.agent_display = "dev-old";
    older.source = "tcp";
    older.paused_at = 100;
    EchoPausedSourceRow newer;
    newer.agent_id = "dev-new";
    newer.agent_display = "dev-new";
    newer.source = "process";
    newer.paused_at = 200;
    EchoPausedSourceRow errored;
    errored.agent_id = "dev-err";
    errored.agent_display = "dev-err";
    errored.source = "service";
    errored.value_error = true;
    errored.enabled_raw = "garbage";
    scan.rows = {newer, older, errored}; // deliberately out of order

    const auto json_str = echo_retention_paused_json(scan);
    auto parsed = nlohmann::json::parse(json_str, nullptr, false);
    REQUIRE_FALSE(parsed.is_discarded());
    CHECK(parsed["scan_id"] == "scan-1");
    const auto& rows = parsed["rows"];
    REQUIRE(rows.size() == 3);
    CHECK(rows[0]["agent_id"] == "dev-err");  // value_error floats to the top
    CHECK(rows[0]["value_error"] == true);
    CHECK(rows[1]["agent_id"] == "dev-old"); // then oldest paused_at first
    CHECK(rows[2]["agent_id"] == "dev-new");
}

// #4644: `node` is ONE non-negative base-10 integer. `stoul` accepted "-1" (wrapping to
// SIZE_MAX) and "5x" (as 5), so a malformed node id silently selected a different process node.
TEST_CASE("process-tree detail: a malformed node id is a 400",
          "[echo][tree][numeric_params]") {
    EchoHarness h;
    const std::string token(32, 'a');
    for (const char* bad : {"-1", "5x", "0x10", "1e1", "", "99999999999999999999"}) {
        INFO("node=" << bad);
        auto res = h.sink.Get("/fragments/echo/process-tree/detail?token=" + token + "&node=" + bad);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
}
