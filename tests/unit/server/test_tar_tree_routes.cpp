/// @file test_tar_tree_routes.cpp
/// Route-level authz / token / audit tests for the TAR process-tree viewer
/// (/fragments/tar/process-tree{,/run,/result,/detail}). Driven in-process through
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
#include "tar_tree_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

DexAgentResponse resp(const std::string& agent_id, const std::string& output) {
    DexAgentResponse r;
    r.agent_id = agent_id;
    r.status = 1; // SUCCESS (terminal, carries output)
    r.output = output;
    return r;
}

// A canned $Process_Live body: systemd(1) -> bash(100). node 0 is systemd.
const char* kProcOut =
    "__schema__|ts|action|pid|ppid|name|cmdline|user\n"
    "100|started|1|0|systemd||root\n"
    "110|started|100|1|bash||alice\n";

// The two canned command ids the result route polls (must start with "tar-").
const std::string kProcCmd = "tar-p";
const std::string kTcpCmd = "tar-t";
// Canned ids for the capture-sources frame's two dispatches (`tar status` and
// `tar compatibility`), which the route polls by the scmd/ccmd query params.
const std::string kStatusCmd = "tar-s";
const std::string kCompatCmd = "tar-c";

// A TarTreeRoutes registered over a TestRouteSink with toggleable stubs.
struct TarHarness {
    yuzu::server::test::TestRouteSink sink;
    TarTreeRoutes routes;

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
    // #4027: operator-scoped device list the /fragments/tar/... HTML frames
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
    std::string tcp_output;    // empty → tree renders without conns (best-effort TCP)
    // Capture-sources frame: canned `tar status` / `tar compatibility` replies.
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

    TarHarness() {
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
        // Dispatch returns a distinct tar- command id per query (process vs tcp),
        // keyed off the SQL the route built, so the responses stub can disambiguate.
        auto dispatch = [this](const std::string&, const std::string&, const std::vector<std::string>&,
                               const std::string&,
                               const std::unordered_map<std::string, std::string>& params,
                               const DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            last_dispatch_caller = caller;
            const auto it = params.find("sql");
            const bool is_proc =
                it != params.end() && it->second.find("$Process_Live") != std::string::npos;
            return {.sent = 1, .command_id = is_proc ? kProcCmd : kTcpCmd};
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
            if (cmd == kProcCmd)
                return {resp(device, proc_output)};
            if (cmd == kTcpCmd)
                return {resp(device, tcp_output)};
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
            return audit_ok; // DexRoutes::AuditFn (aliased by TarTreeRoutes) is bool-returning (#1549)
        };
        routes.register_routes(sink, auth, perm, scoped, devices, lookup, dispatch, responses, audit,
                               caller_fn);
        routes.set_fleet_read_fn(fleet_read); // #4027 fix round — REST twins' sole gate
        routes.set_all_devices_fn(all_devices); // #4143 review fix — REST twins' sole row source
    }

    // Drive /result directly (skips /run; the result route reads pcmd/tcmd from the
    // query, and we control the canned command ids). Returns the response.
    std::unique_ptr<httplib::Response> run_result(const std::string& extra = "") {
        return sink.Get("/fragments/tar/process-tree/result?device=" + device +
                        "&preset=10m&pcmd=" + kProcCmd + "&tcmd=" + kTcpCmd + "&n=1" + extra);
    }

    // Drive the capture-sources frame past the pending poll, the same way
    // run_result() drives the tree: supply the canned command ids directly.
    std::unique_ptr<httplib::Response> run_capture_sources() {
        return sink.Get("/fragments/tar/capture-sources/load?device=" + device +
                        "&scmd=" + kStatusCmd + "&ccmd=" + kCompatCmd + "&n=1");
    }

    std::unique_ptr<httplib::Response> get_detail(const std::string& token, int node = 0) {
        return sink.Get("/fragments/tar/process-tree/detail?token=" + token +
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

TEST_CASE("tar routes: reconstruction mints a 32-hex CSPRNG token", "[tar][routes][token]") {
    TarHarness h;
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->status == 200);
    const std::string token = extract_token(r->body);
    CHECK(is_32_hex(token));
    // The success audit fired with the data-class detail.
    REQUIRE(h.find_audit("tar.process_tree.read", "success") != nullptr);
}

TEST_CASE("tar routes: /detail renders for the owning operator + audits", "[tar][routes]") {
    TarHarness h;
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->status == 200);
    CHECK(d->body.find("tar-detail") != std::string::npos);
    // Per-drilldown access audit fired with a neutralized os.
    const auto* row = h.find_audit("tar.process_tree.detail", "success");
    REQUIRE(row != nullptr);
    CHECK(row->target_id == "dev-A");
    CHECK(row->detail == "node=0 os=linux");
}

TEST_CASE("tar routes: /detail requires Execute (Read-only operator denied)",
          "[tar][routes][authz]") {
    TarHarness h;
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    h.allow_execute = false; // operator keeps scoped Read but loses Execute
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->body.find("Execute") != std::string::npos);
    CHECK(d->body.find("tar-detail") == std::string::npos);
    CHECK(h.find_audit("tar.process_tree.detail", "success") == nullptr);
}

TEST_CASE("tar routes: /detail rejects a token replayed by a different principal",
          "[tar][routes][authz]") {
    TarHarness h;
    const std::string token = extract_token(h.run_result()->body); // created by alice
    REQUIRE(is_32_hex(token));

    h.session_user = "mallory"; // same scope + Execute, but not the creator
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->body.find("different session") != std::string::npos);
    CHECK(d->body.find("tar-detail") == std::string::npos);
    CHECK(h.find_audit("tar.process_tree.detail", "success") == nullptr);
}

TEST_CASE("tar routes: /detail fails closed when the token's device leaves scope",
          "[tar][routes][authz]") {
    TarHarness h;
    h.scope_device = "dev-A"; // build under a device the operator manages
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));

    h.scope_device = "dev-B"; // dev-A now outside the operator's management scope
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    CHECK(d->status == 403);
    CHECK(d->body.find("tar-detail") == std::string::npos);
}

TEST_CASE("tar routes: CSPRNG failure fails closed (no cache, failure audit)",
          "[tar][routes][token]") {
    TarHarness h;
    test_hooks::force_next_failure_for_this_thread();
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->status == 200); // htmx-swappable in-panel note, NOT a 503
    CHECK(r->body.find("secure token") != std::string::npos);
    CHECK(!test_hooks::is_failure_forced_for_this_thread()); // override consumed
    // A failure audit row exists and NO token/tree was cached.
    REQUIRE(h.find_audit("tar.process_tree.read", "failure") != nullptr);
    CHECK(h.find_audit("tar.process_tree.read", "failure")->detail == "csprng_unavailable");
    CHECK(extract_token(r->body).empty());
    // A fabricated 32-hex token resolves to nothing (the cache is empty).
    auto d = h.get_detail("0123456789abcdef0123456789abcdef", 0);
    REQUIRE(d);
    CHECK(d->body.find("expired") != std::string::npos);
    CHECK(d->body.find("tar-detail") == std::string::npos);
}

TEST_CASE("tar routes: an over-cap process payload is rejected (no cache)",
          "[tar][routes][token]") {
    TarHarness h;
    h.proc_output = std::string(kMaxTarProcOutputBytes + 1, 'x'); // > 16 MiB
    auto r = h.run_result();
    REQUIRE(r);
    CHECK(r->body.find("unexpectedly large") != std::string::npos);
    CHECK(extract_token(r->body).empty());                          // nothing rendered/cached
    CHECK(h.find_audit("tar.process_tree.read", "success") == nullptr);
}

TEST_CASE("tar routes: /detail audit normalizes the agent-controlled os",
          "[tar][routes][audit]") {
    TarHarness h;
    h.os = "win\ndows evil=1"; // CRLF + delimiter injection via device metadata
    const std::string token = extract_token(h.run_result()->body);
    REQUIRE(is_32_hex(token));
    auto d = h.get_detail(token, 0);
    REQUIRE(d);
    const auto* row = h.find_audit("tar.process_tree.detail", "success");
    REQUIRE(row != nullptr);
    CHECK(row->detail == "node=0 os=windows"); // normalized; no raw newline/'='
}

TEST_CASE("tar routes: /run audit neutralizes an injected preset", "[tar][routes][audit]") {
    TarHarness h;
    // preset carries an audit-field-forgery attempt; canonicalization maps it to 10m.
    auto r = h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=x%20command_id%3Dforged");
    REQUIRE(r);
    const auto* row = h.find_audit("tar.process_tree.read", "dispatched");
    REQUIRE(row != nullptr);
    CHECK(row->detail.find("preset=10m") != std::string::npos);
    CHECK(row->detail.find("forged") == std::string::npos); // injection neutralized
}

TEST_CASE("tar routes: /result audit normalizes an agent-controlled os", "[tar][routes][audit]") {
    TarHarness h;
    h.os = "win\ndows evil=1"; // CRLF + delimiter injection via device metadata
    h.run_result();
    const auto* row = h.find_audit("tar.process_tree.read", "success");
    REQUIRE(row != nullptr);
    CHECK(row->detail.find("os=windows") != std::string::npos);
    CHECK(row->detail.find("evil=1") == std::string::npos);
    CHECK(row->detail.find('\n') == std::string::npos); // no line splitting
}

TEST_CASE("tar routes: /run is denied for a Read-but-no-Execute operator",
          "[tar][routes][authz]") {
    TarHarness h;
    h.allow_execute = false;
    auto r = h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=10m");
    REQUIRE(r);
    CHECK(r->body.find("Execute") != std::string::npos);
    // No dispatch audit when the Execute gate stops the reconstruction.
    CHECK(h.find_audit("tar.process_tree.read", "dispatched") == nullptr);
}

// #1647 catch-arm parity: a THROWING audit_fn at every tar dispatch/read site must be
// caught by the shared rest_audit.hpp chokepoint — never escape the handler (which
// httplib would turn into a 500) — and must surface Sec-Audit-Failed while the route
// keeps its existing dispatch/render posture. Before #1647 these sites discarded the
// audit bool with no try/catch, so a bad_alloc-class throw escaped and a dropped row
// was invisible. One section per distinct call site.
TEST_CASE("tar routes: a throwing audit_fn is caught + flags Sec-Audit-Failed at every site",
          "[tar][routes][audit]") {
    SECTION("/run — tar.process_tree.read dispatched") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=10m"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Posture preserved: the dispatch still rendered the polling fragment.
        CHECK(r->body.find("process-tree/result") != std::string::npos);
        CHECK(h.find_audit("tar.process_tree.read", "dispatched") != nullptr);
    }
    SECTION("/result success — tar.process_tree.read success (renders PII tree)") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.run_result());
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Set-and-proceed: the tree still rendered (a detail token was minted).
        CHECK(is_32_hex(extract_token(r->body)));
    }
    SECTION("/result csprng failure — tar.process_tree.read failure") {
        TarHarness h;
        h.audit_throws = true;
        test_hooks::force_next_failure_for_this_thread(); // forces the failure-audit branch
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.run_result());
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->body.find("secure token") != std::string::npos); // honest note still rendered
        CHECK(h.find_audit("tar.process_tree.read", "failure") != nullptr);
    }
    SECTION("/detail — tar.process_tree.detail") {
        TarHarness h;
        const std::string token = extract_token(h.run_result()->body); // clean reconstruction
        REQUIRE(is_32_hex(token));
        h.audit_throws = true; // throw only on the detail open
        std::unique_ptr<httplib::Response> d;
        CHECK_NOTHROW(d = h.get_detail(token, 0));
        REQUIRE(d);
        CHECK(d->status == 200);
        CHECK(d->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(d->body.find("tar-detail") != std::string::npos); // detail still rendered
    }
    SECTION("/device-net — tar.dns.read + tar.arp.read") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/tar/process-tree/device-net?device=dev-A"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        // Both verbs were reached before the throw was caught.
        CHECK(h.find_audit("tar.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("tar.arp.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/load — tar.sources.read") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/tar/capture-sources/load?device=dev-A"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.find_audit("tar.sources.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/push — tar.sources.configure") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        // changes=process=on (url-encoded '='); a known source toggled on.
        CHECK_NOTHROW(
            r = h.sink.Post("/fragments/tar/capture-sources/push?device=dev-A&changes=process%3Don",
                            ""));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.find_audit("tar.sources.configure", "dispatched") != nullptr);
    }
}

// #3133 external PR review finding: this route gated only Infrastructure:Read
// before dispatching the mutating, Infrastructure:Write-classified
// tar.configure action through a hardcoded system=true closure — bypassing
// the chokepoint's per-action authorization entirely regardless of the
// caller's actual grants. The fix threads the real, non-system caller
// through every dispatch in this class; this pins it at the exact route the
// review flagged, and the four others sharing the same dispatch_fn_ member.
TEST_CASE("tar routes: every dispatch carries the real caller, never a system one",
         "[tar][routes][security]") {
    TarHarness h;
    h.session_user = "alice";

    SECTION("process-tree /run") {
        // /result only polls pre-canned command ids (run_result() skips /run
        // by design, per the harness's own doc comment) — /run is the
        // handler that actually calls dispatch_fn_.
        (void)h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=10m");
        CHECK_FALSE(h.last_dispatch_caller.system);
        CHECK(h.last_dispatch_caller.principal == "alice");
    }
    SECTION("capture-sources/push — tar.configure") {
        (void)h.sink.Post(
            "/fragments/tar/capture-sources/push?device=dev-A&changes=process%3Don", "");
        CHECK_FALSE(h.last_dispatch_caller.system);
        CHECK(h.last_dispatch_caller.principal == "alice");
    }
    SECTION("capture-sources/load — tar.status + tar.compatibility") {
        (void)h.sink.Get("/fragments/tar/capture-sources/load?device=dev-A");
        CHECK_FALSE(h.last_dispatch_caller.system);
        CHECK(h.last_dispatch_caller.principal == "alice");
    }
}

// #1647: a DROPPED (returns-false) audit row is the realistic failure path (audit DB
// locked/full). Before this PR the tar sites discarded the bool and set NO header; now
// they surface Sec-Audit-Failed while still rendering (set-and-proceed). Also pins the
// idempotent-header guard: the two MULTI-CALL surfaces (dns+arp, the configure loop)
// must emit Sec-Audit-Failed AT MOST ONCE even when several audits in one request fail.
TEST_CASE("tar routes: dropped audit row flags Sec-Audit-Failed once; clean path sets none",
          "[tar][routes][audit]") {
    SECTION("/run dropped row — set-and-proceed (header + still dispatches)") {
        TarHarness h;
        h.audit_ok = false;
        auto r = h.sink.Get("/fragments/tar/process-tree/run?device=dev-A&preset=10m");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->body.find("process-tree/result") != std::string::npos); // dispatch not blocked
    }
    SECTION("/device-net both dns+arp drop — header emitted exactly once (multimap guard)") {
        TarHarness h;
        h.audit_ok = false;
        auto r = h.sink.Get("/fragments/tar/process-tree/device-net?device=dev-A");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1); // not two field-lines
        CHECK(h.find_audit("tar.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("tar.arp.read", "dispatched") != nullptr);
    }
    SECTION("/device-net both dns+arp throw — header still exactly once") {
        TarHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/tar/process-tree/device-net?device=dev-A"));
        REQUIRE(r);
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1);
        // BOTH verbs must have fired (the first throw was caught, the second still ran)
        // — otherwise count==1 would prove single-emission, not de-duplication.
        CHECK(h.find_audit("tar.dns.read", "dispatched") != nullptr);
        CHECK(h.find_audit("tar.arp.read", "dispatched") != nullptr);
    }
    SECTION("/capture-sources/push two sources both drop — header exactly once over the loop") {
        TarHarness h;
        h.audit_ok = false;
        // Two known sources toggled in one request; the per-source audit loop fails twice.
        auto r = h.sink.Post(
            "/fragments/tar/capture-sources/push?device=dev-A&changes=process%3Don,tcp%3Doff", "");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->get_header_value_count("Sec-Audit-Failed") == 1);
        // BOTH loop iterations must have reached the audit chokepoint — otherwise
        // count==1 could mean the loop skipped the second source, not de-duplication.
        int cfg_rows = 0;
        for (const auto& row : h.audit_log)
            if (row.action == "tar.sources.configure")
                ++cfg_rows;
        CHECK(cfg_rows == 2);
    }
    SECTION("clean path sets NO Sec-Audit-Failed header") {
        TarHarness h; // audit_ok=true, audit_throws=false
        auto r = h.run_result();
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed").empty());
        CHECK(is_32_hex(extract_token(r->body))); // tree rendered normally
    }
}

TEST_CASE("TAR capture-sources: an offline device shows the agent's reason, not a blank grid",
          "[tar][tree][routes][capture-sources]") {
    // Governance Gate 3 (quality-engineer) BLOCKING: this branch had no test at
    // all, and it is the fix for the incident where a dead endpoint rendered
    // identically to a healthy one.
    //
    // `poll_command` treats any non-empty output as success, so the ONLY thing
    // separating "device is dead" from "device is fine" here is the
    // `starts_with("error|")` gate. If it misses, the frame falls through to the
    // capture-sources renderer, which parses only `config|` lines, and draws all
    // ten sources blank.
    TarHarness h;
    // The REAL two-record reply, not just the error line. An earlier version of
    // this test supplied only the first line, so it could not see that the route
    // was truncating on a byte count and running past the newline into
    // `storage_state|offline` -- the operator saw a trailing `storage_stat`
    // (Sol adversarial review).
    h.status_output =
        "error|TAR storage is offline on this endpoint; the database was closed after a "
        "transaction could not be rolled back. Collection and retention are both stopped. The "
        "read-only query connection is unavailable too, so `tar sql` cannot read the historical "
        "data either. Restart the agent to recover.\nstorage_state|offline";

    auto res = h.run_capture_sources();
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);

    // The operator is told WHY, and which read path still works -- the agent
    // composes that sentence and it must survive the trip to the browser.
    CHECK(res->body.find("TAR storage is offline") != std::string::npos);
    CHECK(res->body.find("tar sql") != std::string::npos);
    // The recovery instruction is the last thing in the record and must survive.
    CHECK(res->body.find("Restart the agent to recover.") != std::string::npos);
    // ...and NOTHING from the following record leaks in as debris.
    CHECK(res->body.find("storage_state") == std::string::npos);
    CHECK(res->body.find("storage_stat") == std::string::npos);
    // The `error|` prefix itself is stripped, not echoed raw.
    CHECK(res->body.find("error|") == std::string::npos);
    // And it must NOT have rendered the sources grid for a dead store. Assert
    // the id the renderer actually emits (`capTable`, tar_process_tree.cpp:1235)
    // -- an earlier version of this checked for "capture-source-row", a string
    // that exists nowhere in the codebase and so passed vacuously.
    CHECK(res->body.find("capTable") == std::string::npos);
}

TEST_CASE("TAR capture-sources: a healthy device still renders the sources grid",
          "[tar][tree][routes][capture-sources]") {
    // The other half, so the test above cannot pass by the route being broken
    // for everyone.
    TarHarness h;
    // Needs a real `config|` line: the renderer builds the grid from those, so a
    // fixture without one cannot distinguish "rendered the grid" from "rendered
    // an empty body" and the absence-assertions below would pass vacuously.
    h.status_output = "storage_state|ok\nrecord_count|42\nconfig|process_enabled|true";

    auto res = h.run_capture_sources();
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);
    // Positively assert the grid: `capTable` is what the renderer emits.
    CHECK(res->body.find("capTable") != std::string::npos);
    CHECK(res->body.find("TAR storage is offline") == std::string::npos);
    CHECK(res->body.find("failed the status query") == std::string::npos);
}

// SEC-2/SEC-3 confinement-gap class (found during a docs sweep): devices_fn_
// backing both TAR frame device pickers is username-keyed and does not
// confine a service-scoped API token whose principal resolves to an
// unscoped grant.
TEST_CASE("TAR device pickers: service-scoped token denied on both frames, "
          "denial audited",
          "[tar][tree][routes][security]") {
    TarHarness h;
    h.service_scoped = true;

    auto tree = h.sink.Get("/fragments/tar/process-tree");
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

    auto cap = h.sink.Get("/fragments/tar/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 403);
    auto cap_body = nlohmann::json::parse(cap->body, nullptr, false);
    REQUIRE_FALSE(cap_body.is_discarded());
    CHECK_FALSE(cap_body["error"].contains("permission"));
    CHECK_FALSE(cap_body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(cap->get_header_value("X-Correlation-Id") ==
         cap_body["error"]["correlation_id"].get<std::string>());

    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[0].action == "tar.device_picker.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[1].action == "tar.device_picker.view");
    CHECK(h.audit_log[1].result == "denied");
}

// #4027 REST twins: GET /api/v1/tar/process-tree + /api/v1/tar/capture-sources
// share deny_fleet_wide_device_enumeration with their fragment siblings above —
// pin the SAME service-scoped-token 403 + audit on the new JSON routes too, so a
// future edit to the shared guard can't silently narrow to only the two original
// call sites.
TEST_CASE("TAR device picker REST twins: service-scoped token denied, audited",
          "[tar][tree][routes][security][rest]") {
    TarHarness h;
    h.service_scoped = true;

    auto tree = h.sink.Get("/api/v1/tar/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 403);
    auto cap = h.sink.Get("/api/v1/tar/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 403);

    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[0].action == "tar.device_picker.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[1].action == "tar.device_picker.view");
    CHECK(h.audit_log[1].result == "denied");
}

TEST_CASE("TAR device picker REST twins: Infrastructure:Read denial -> 403, no data leak",
          "[tar][tree][routes][security][rest]") {
    TarHarness h;
    h.allow_read = false;
    h.devices_list = {DeviceRow{.agent_id = "dev-A", .hostname = "host-a", .online = true}};

    auto tree = h.sink.Get("/api/v1/tar/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 403);
    CHECK(tree->body.find("dev-A") == std::string::npos);

    auto cap = h.sink.Get("/api/v1/tar/capture-sources");
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
TEST_CASE("TAR device picker REST twins: ancestor-scoped (not direct-member) "
          "admit sees the gate-authorized row, not the flat resolver's subset",
          "[tar][tree][routes][security][rest][adr-0017]") {
    TarHarness h;
    h.devices_list = {DeviceRow{.agent_id = "mine", .hostname = "mine-host", .online = true}};
    h.all_devices_list_override = std::vector<DeviceRow>{
        DeviceRow{.agent_id = "mine", .hostname = "mine-host", .online = true},
        DeviceRow{.agent_id = "ancestor-child", .hostname = "ancestor-host", .online = true},
    };
    // gate.scope admits BOTH — the ancestor-ward expansion a real
    // fleet_read_fn_/require_fleet_read performs in production.
    h.fleet_scope = std::vector<std::string>{"mine", "ancestor-child"};

    auto tree = h.sink.Get("/api/v1/tar/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 200);
    CHECK(tree->body.find("mine-host") != std::string::npos);
    CHECK(tree->body.find("ancestor-host") != std::string::npos); // was silently dropped pre-fix

    auto cap = h.sink.Get("/api/v1/tar/capture-sources");
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
// today. See tar_tree_routes.hpp's builder doc comment for the full correction.
TEST_CASE("TAR device picker REST twins: happy path returns the A4-enveloped "
          "device list; the route/builder does not discriminate against an "
          "online=false row if the provider ever supplies one",
          "[tar][tree][routes][rest]") {
    TarHarness h;
    h.devices_list = {
        DeviceRow{.agent_id = "dev-A", .hostname = "host-a", .os = "linux",
                  .arch = "x86_64", .agent_version = "1.2.3", .online = true},
        DeviceRow{.agent_id = "dev-B", .hostname = "host-b", .os = "windows",
                  .arch = "arm64", .agent_version = "1.2.3", .online = false},
    };

    auto tree = h.sink.Get("/api/v1/tar/process-tree");
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
    auto cap = h.sink.Get("/api/v1/tar/capture-sources");
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
TEST_CASE("TAR device picker REST twins: group-scoped grant is ADMITTED and "
          "filtered to exactly its VisibleSet, both surfaces",
          "[tar][tree][routes][rest][security]") {
    TarHarness h;
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

    auto tree = h.sink.Get("/api/v1/tar/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 200); // NOT 403 — the pre-fix behavior for this exact grant shape
    auto tree_json = nlohmann::json::parse(tree->body, nullptr, false);
    REQUIRE_FALSE(tree_json.is_discarded());
    const auto& tree_devices = tree_json["data"]["devices"];
    REQUIRE(tree_devices.size() == 1);
    CHECK(tree_devices[0]["agent_id"] == "dev-A");

    auto cap = h.sink.Get("/api/v1/tar/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 200);
    auto cap_json = nlohmann::json::parse(cap->body, nullptr, false);
    REQUIRE_FALSE(cap_json.is_discarded());
    const auto& cap_devices = cap_json["data"]["devices"];
    REQUIRE(cap_devices.size() == 1);
    CHECK(cap_devices[0]["agent_id"] == "dev-A");
}

TEST_CASE("TAR device picker REST twins: fleet_read_fn_ unwired fails closed (503, "
          "not the pre-fix perm_fn_ path)",
          "[tar][tree][routes][rest][security]") {
    TarHarness h;
    h.devices_list = {DeviceRow{.agent_id = "dev-A", .hostname = "host-a", .online = true}};
    h.routes.set_fleet_read_fn(nullptr); // simulate a misconfigured call site

    auto tree = h.sink.Get("/api/v1/tar/process-tree");
    REQUIRE(tree);
    CHECK(tree->status == 503);
    CHECK(tree->body.find("dev-A") == std::string::npos);

    auto cap = h.sink.Get("/api/v1/tar/capture-sources");
    REQUIRE(cap);
    CHECK(cap->status == 503);
    CHECK(cap->body.find("dev-A") == std::string::npos);
}

// #4027 shared builders (api-twin-recipe.md Rule 1): pure, no route/store needed.
// tar_process_tree_frame_json and tar_capture_sources_devices_json are two named
// wrappers over one internal helper — pin that they stay byte-identical for the
// same input, which is the actual regression test for Rule 1 holding.
TEST_CASE("tar_process_tree_frame_json / tar_capture_sources_devices_json: "
          "identical shape, sorted by display name",
          "[tar][tree][model]") {
    const std::vector<DeviceRow> devices = {
        DeviceRow{.agent_id = "dev-Z", .hostname = "", .os = "linux", .online = true},
        DeviceRow{.agent_id = "dev-A", .hostname = "alpha", .os = "windows", .online = false},
    };
    const auto frame_json = tar_process_tree_frame_json(devices);
    const auto cap_json = tar_capture_sources_devices_json(devices);
    CHECK(frame_json == cap_json);

    auto parsed = nlohmann::json::parse(frame_json, nullptr, false);
    REQUIRE_FALSE(parsed.is_discarded());
    REQUIRE(parsed.size() == 2);
    // "alpha" (dev-A's hostname) sorts before "dev-Z" (dev-Z has no hostname, so
    // its agent_id is the sort key) — matches render_frame's own sort.
    CHECK(parsed[0]["agent_id"] == "dev-A");
    CHECK(parsed[1]["agent_id"] == "dev-Z");
}

TEST_CASE("tar_retention_paused_json: sorts value-error first, then oldest-paused-first",
          "[tar][tree][model]") {
    TarRetentionPausedScan scan;
    scan.scan_id = "scan-1";
    scan.scan_count = 3;
    scan.agents_responded = 3;
    TarPausedSourceRow older;
    older.agent_id = "dev-old";
    older.agent_display = "dev-old";
    older.source = "tcp";
    older.paused_at = 100;
    TarPausedSourceRow newer;
    newer.agent_id = "dev-new";
    newer.agent_display = "dev-new";
    newer.source = "process";
    newer.paused_at = 200;
    TarPausedSourceRow errored;
    errored.agent_id = "dev-err";
    errored.agent_display = "dev-err";
    errored.source = "service";
    errored.value_error = true;
    errored.enabled_raw = "garbage";
    scan.rows = {newer, older, errored}; // deliberately out of order

    const auto json_str = tar_retention_paused_json(scan);
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
