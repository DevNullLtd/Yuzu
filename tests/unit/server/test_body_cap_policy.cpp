/**
 * test_body_cap_policy.cpp — coverage for the #2407 pre-auth body-cap policy
 * table (`body_cap_policy.hpp`'s `kBodyCapTable` / `resolve_body_cap`).
 *
 * This header is a PURE table + lookup — the enforcement chokepoint
 * (server.cpp's pre-routing handler, generalized from the existing #2437
 * `/mcp/` gate) is wired by a sibling change. This file locks the table
 * itself: every entry's cap, every entry's `requires_measurable` bit, the
 * segment-boundary matching rule that stops `/api/v1/bundlesevil` from
 * matching the `/api/v1/bundles` entry, method discrimination on a shared
 * prefix, longest-match precedence, and the catch-all default.
 *
 * Expected values below are an INDEPENDENT copy of the table, not derived
 * from it — mirroring `test_authz_topology_floor.cpp`'s `kExpectedFloorPairs`
 * pattern. A test that iterates `kBodyCapTable` to build its own
 * expectations would shrink in lockstep with an accidentally-shrunk or
 * silently-changed table and stop catching the very regression this file
 * exists to catch.
 */

#include "body_cap_policy.hpp"
#include "test_loopback_http.hpp"
#include "web_utils.hpp"

#include <httplib.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <format>
#include <set>
#include <string>
#include <string_view>
#include <thread>

#if defined(__has_feature)
#  if __has_feature(thread_sanitizer)
#    define YUZU_TSAN_BUILD 1
#  endif
#endif
#if defined(__SANITIZE_THREAD__)
#  define YUZU_TSAN_BUILD 1
#endif

#ifndef _WIN32
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
#endif

using yuzu::server::BodyCapDecision;
using yuzu::server::BodyCapMatch;
using yuzu::server::body_cap_prefix_matches;
using yuzu::server::content_length_for_body_cap;
using yuzu::server::evaluate_body_cap;
using yuzu::server::kBodyCapAnyMethod;
using yuzu::server::kBodyCapTable;
using yuzu::server::resolve_body_cap;

namespace {

/// One expected `(method, path)` -> `(cap, requires_measurable, class)`
/// resolution, hand-copied independently of `kBodyCapTable`.
struct ExpectedResolution {
    std::string_view method;
    std::string_view path;
    std::size_t max_body_bytes;
    bool requires_measurable;
    std::string_view path_class;
};

// clang-format off
constexpr ExpectedResolution kExpected[] = {
    // mcp_jsonrpc.hpp:63 kMcpMaxRequestBodyBytes. ANY method.
    {"GET",    "/mcp/v1/",                                4u * 1024 * 1024,   true,  "mcp"},
    {"POST",   "/mcp/v1/",                                4u * 1024 * 1024,   true,  "mcp"},
    {"DELETE", "/mcp/v1/",                                4u * 1024 * 1024,   true,  "mcp"},
    // bundle_service.hpp:24-33 / rest_api_v1.cpp:1417.
    {"POST",   "/api/v1/bundles",                         70u * 1024 * 1024,  false, "bundles"},
    // body_cap_policy.hpp upload_session row — the PR1.6a chunked-receive
    // surface. Cap = upload_grant::kDefaultChunkMaxBytes (bound by the
    // static_assert in file_retrieval_routes.cpp). requires_measurable=true:
    // the chunk route's session gate runs in the HANDLER, after httplib
    // buffers, so the pre-read bound is what stops an unauthenticated caller
    // buffering 100 MB. ANY method — sibling verbs (status GET, commit POST,
    // cancel DELETE, session-open POST on the bare prefix) share the class.
    {"PUT",    "/api/v1/uploads/abc123/chunk",            8u * 1024 * 1024,   true,  "upload_session"},
    {"POST",   "/api/v1/uploads",                          8u * 1024 * 1024,  true,  "upload_session"},
    {"POST",   "/api/v1/uploads/abc123/commit",            8u * 1024 * 1024,  true,  "upload_session"},
    // body_cap_policy.hpp plugin_config row — the PR1.5 config/secret/
    // kill-switch plane. 256 KiB = the 64 KiB secret-plaintext grammar cap
    // (plugin_config_parsers.hpp) plus JSON framing headroom.
    {"PUT",    "/api/v1/plugin-config/email/host",         256u * 1024,        false, "plugin_config"},
    {"PUT",    "/api/v1/plugin-config/email/key/secret",   256u * 1024,        false, "plugin_config"},
    {"DELETE", "/api/v1/plugin-config/email/host",         256u * 1024,        false, "plugin_config"},
    // settings_routes.cpp:5146,:5206 — keeps httplib's 100 MiB backstop.
    {"POST",   "/api/settings/updates/upload",            100u * 1024 * 1024, false, "ota_upload"},
    // server.cpp:10809 — unbounded by design, kept at httplib's backstop.
    {"POST",   "/api/export/json-to-csv",                 100u * 1024 * 1024, false, "json_to_csv_export"},
    // server.cpp:9258 — no aggregate contract, reasoned to realistic scale.
    {"POST",   "/api/nvd/match",                          8u * 1024 * 1024,   false, "nvd_match"},
    // ca_routes.cpp:24,:516.
    {"POST",   "/api/v1/ca/import-chain",                 256u * 1024,        false, "ca_import_chain"},
    // ca_routes.cpp:24 kMaxRevokeBody,:394.
    {"POST",   "/api/v1/ca/revoke",                       64u * 1024,         false, "ca_revoke"},
    // ca_routes.cpp kMaxIssueCodeSigningBody (gap-matrix #10).
    {"POST",   "/api/v1/ca/issue-code-signing",           64u * 1024,         false, "ca_issue_code_signing"},
    // kek_routes.cpp:46 kMaxKekBody,:54 validate_empty_body — shared by rotate+rewrap.
    {"POST",   "/api/v1/secrets/kek/rotate",               64u * 1024,        false, "kek_ops"},
    {"POST",   "/api/v1/secrets/kek/rewrap",               64u * 1024,        false, "kek_ops"},
    // ca_routes.cpp:727 dashboard twin, doubled for form-encoding overhead.
    {"POST",   "/api/settings/ca/import-chain",           512u * 1024,        false, "ca_import_chain_dashboard"},
    // settings_routes.cpp:3445,:3461, doubled for multipart framing overhead.
    {"POST",   "/api/settings/plugin-signing/upload",     512u * 1024,        false, "plugin_trust_bundle"},
    // scim_routes.cpp:65 kMaxBodyBytes. ANY method — see the method-independence
    // case below for why this is deliberately not scoped to the mutating verbs.
    {"POST",   "/scim/v2/Users",                          64u * 1024,         false, "scim"},
    {"PUT",    "/scim/v2/Users/deadbeef",                 64u * 1024,         false, "scim"},
    {"PATCH",  "/scim/v2/Users/deadbeef",                 64u * 1024,         false, "scim"},
    {"POST",   "/scim/v2/Groups",                         64u * 1024,         false, "scim"},
    {"PUT",    "/scim/v2/Groups/deadbeef",                64u * 1024,         false, "scim"},
    {"PATCH",  "/scim/v2/Groups/deadbeef",                64u * 1024,         false, "scim"},
    // auth_routes.cpp:2794-2798 kSamlMaxBodyBytes.
    {"POST",   "/saml/acs",                                1u * 1024 * 1024,  false, "saml_acs"},
    // rest_api_v1.cpp:4237 kRtMaxBodyBytes.
    {"POST",   "/api/v1/definitions/def-1/response-templates",             64u * 1024, false, "response_templates"},
    {"PUT",    "/api/v1/definitions/def-1/response-templates/tmpl-1",      64u * 1024, false, "response_templates"},
    // dashboard_routes.cpp:866 `sql.size() > 4096` on the DECODED field;
    // 16 KiB = 3x4096 worst-case percent-encoding + 4 KiB field/framing margin.
    {"POST",   "/api/dashboard/tar-execute",              16u * 1024,         false, "tar_dashboard_sql"},
    // rest_api_v1.cpp:6802 `sql.size() > 100000` on the JSON-parsed field;
    // 200 KiB = 2x100000 for JSON-escaping headroom plus the other JSON keys.
    {"POST",   "/api/v1/result-sets/from-tar-query",      200u * 1024,        false, "tar_result_set_sql"},
    // rest_api_v1.cpp:7759,:7842 — explicit generous, no contract yet.
    {"POST",   "/api/v1/guaranteed-state/rules",          16u * 1024 * 1024,  false, "guardian_rule_authoring"},
    // rest_api_v1.cpp:7904 regex PUT update — same class, same bound.
    {"PUT",    "/api/v1/guaranteed-state/rules/rule-1",   16u * 1024 * 1024,  false, "guardian_rule_authoring"},
    // workflow_routes.cpp:1023.
    {"POST",   "/api/workflows",                          16u * 1024 * 1024,  false, "workflow_yaml"},
    // workflow_routes.cpp:1746 / product_pack_store.cpp:122.
    {"POST",   "/api/product-packs",                      16u * 1024 * 1024,  false, "product_pack_yaml"},
    // server.cpp:11130 -> instruction_store.cpp:954,:434 — no aggregate
    // contract (yaml_source is capped but responseTemplates-as-array is not).
    {"POST",   "/api/instructions/import",                16u * 1024 * 1024,  false, "instruction_import"},
    // instruction_yaml.cpp:165 `yaml_source.size() > 1048576` on the
    // DECODED field; 3149824 = 3x1048576 worst-case percent-encoding +
    // 4 KiB field/framing margin. Three form-encoded routes, one check.
    {"POST",   "/api/instructions/yaml",                  3149824u,           false, "instruction_yaml"},
    {"POST",   "/api/instructions/validate-yaml",          3149824u,           false, "instruction_yaml"},
    {"POST",   "/fragments/instructions/yaml-preview",    3149824u,           false, "instruction_yaml"},
    // body_cap_policy.hpp hardware row — the Hardware CI list/record/sync REST
    // v1 twin (hardware_routes.cpp). Only POST .../sync carries a body (one
    // short "source" enum token); requires_measurable=true closes the same
    // pre-auth-buffering gap the upload_session row above does (governance
    // Gate 2). ANY method — the bodyless GET list/record routes on the same
    // prefix are unaffected but share the class rather than falling to the
    // (looser) catch-all.
    {"GET",    "/api/v1/hardware",                        4u * 1024,          true,  "hardware"},
    {"GET",    "/api/v1/hardware/agent-1",                4u * 1024,          true,  "hardware"},
    {"POST",   "/api/v1/hardware/agent-1/sync",           4u * 1024,          true,  "hardware"},
    // body_cap_policy.hpp rbac_role_assignment row — A2 global human role
    // assignment (rest_api_v1.cpp). POST body is {principal_type,
    // principal_id}; DELETE carries none. ANY method — the DELETE sibling
    // shares this literal prefix once past the role-name path segment.
    {"POST",   "/api/v1/rbac/roles/Operator/assignments",              4u * 1024, false, "rbac_role_assignment"},
    {"DELETE", "/api/v1/rbac/roles/Operator/assignments/alice",        4u * 1024, false, "rbac_role_assignment"},
    // Catch-all default — ordinary JSON/form traffic.
    {"POST",   "/api/v1/some-ordinary-mutation-route",    4u * 1024 * 1024,   false, "default"},
    {"GET",    "/api/v1/devices",                         4u * 1024 * 1024,   false, "default"},
};
// clang-format on

/// Independent list of every distinct metric label the table is expected to
/// emit — locks metric cardinality separately from the per-row cap values.
constexpr std::string_view kExpectedPathClasses[] = {
    "mcp",
    "bundles",
    "ota_upload",
    "json_to_csv_export",
    "nvd_match",
    "ca_import_chain",
    "ca_issue_code_signing",
    "ca_revoke",
    "kek_ops",
    "ca_import_chain_dashboard",
    "plugin_trust_bundle",
    "scim",
    "saml_acs",
    "response_templates",
    "tar_dashboard_sql",
    "upload_session",
    "plugin_config",
    "tar_result_set_sql",
    "guardian_rule_authoring",
    "workflow_yaml",
    "product_pack_yaml",
    "instruction_import",
    "instruction_yaml",
    "hardware",
    "rbac_role_assignment",
    "default",
};

} // namespace

// ── 1. Every table entry resolves to its own cap ─────────────────────────

TEST_CASE("resolve_body_cap: every documented route class resolves to its own measured cap",
          "[body_cap]") {
    for (const auto& exp : kExpected) {
        INFO("method=" << exp.method << " path=" << exp.path);
        const auto got = resolve_body_cap(exp.method, exp.path);
        CHECK(got.max_body_bytes == exp.max_body_bytes);
        CHECK(got.requires_measurable == exp.requires_measurable);
        CHECK(got.path_class == exp.path_class);
    }
}

// ── 2. Segment-boundary matching ──────────────────────────────────────────

TEST_CASE("resolve_body_cap: /api/v1/bundlesevil is NOT the bundles entry — segment boundary",
          "[body_cap]") {
    // The architect-named collision: a plain starts_with would let this
    // through onto the 70 MiB bundles cap instead of the 4 MiB default.
    const auto got = resolve_body_cap("POST", "/api/v1/bundlesevil");
    CHECK(got.path_class == "default");
    CHECK(got.max_body_bytes == 4u * 1024 * 1024);
}

TEST_CASE("body_cap_prefix_matches: exact length, boundary, and non-boundary cases",
          "[body_cap]") {
    CHECK(body_cap_prefix_matches("/api/v1/bundles", "/api/v1/bundles"));       // exact
    CHECK(body_cap_prefix_matches("/api/v1/bundles/abc", "/api/v1/bundles"));   // '/' boundary
    CHECK_FALSE(body_cap_prefix_matches("/api/v1/bundlesevil", "/api/v1/bundles")); // no boundary
    CHECK(body_cap_prefix_matches("/scim/v2/Users", "/scim/v2/"));              // prefix ends in '/'
    CHECK_FALSE(body_cap_prefix_matches("/api/v1", "/api/v1/bundles"));         // too short
}

// ── 3. Method discrimination ──────────────────────────────────────────────

TEST_CASE("resolve_body_cap: same prefix, different method -> different entry",
          "[body_cap]") {
    // The motivating real-world case (file header, and the intro to this
    // brief): rest_api_v1.cpp:7759 POST vs :7904 regex PUT on the SAME
    // guaranteed-state prefix. Only POST has an explicit entry in the
    // table; GET on the identical literal prefix must NOT inherit it.
    const auto post = resolve_body_cap("POST", "/api/v1/guaranteed-state/rules");
    CHECK(post.path_class == "guardian_rule_authoring");
    CHECK(post.max_body_bytes == 16u * 1024 * 1024);

    const auto get = resolve_body_cap("GET", "/api/v1/guaranteed-state/rules");
    CHECK(get.path_class == "default");
    CHECK(get.max_body_bytes == 4u * 1024 * 1024);

    // SCIM is the DELIBERATE COUNTER-EXAMPLE: its row is kBodyCapAnyMethod,
    // so every verb on the prefix resolves to the same 64 KiB class.
    //
    // This previously asserted the opposite — that DELETE "must fall through
    // rather than silently inherit", on the stated grounds that DELETE has no
    // route-registered body. Both halves were wrong. SCIM DELETE routes are
    // real (scim_routes.cpp:1577, :2316), and an adversarial review showed the
    // method-scoping let any verb switch drop the whole prefix to the 4 MiB
    // catch-all, 64x this class's bound, on a prefix that is session-auth-
    // exempt and buffered before the in-handler bearer check. The test had
    // frozen that as intent. Kept inverted as a regression guard: narrowing
    // the row back to the mutating verbs re-breaks here.
    for (const auto* method : {"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "GET"}) {
        const auto scim = resolve_body_cap(method, "/scim/v2/Users/deadbeef");
        INFO("method=" << method);
        CHECK(scim.path_class == "scim");
        CHECK(scim.max_body_bytes == 64u * 1024);
    }
}

// ── 4. Longest match wins ─────────────────────────────────────────────────

TEST_CASE("resolve_body_cap: longest matching prefix wins over the catch-all default",
          "[body_cap]") {
    // "/scim/v2/" (64 KiB, method-specific) and "" (the catch-all default,
    // ANY method, 4 MiB) BOTH match "/scim/v2/Users" for POST — the longer,
    // more specific entry must win.
    const auto got = resolve_body_cap("POST", "/scim/v2/Users");
    CHECK(got.path_class == "scim");
    CHECK(got.max_body_bytes == 64u * 1024);

    // Same principle for /mcp/ vs the default.
    const auto mcp = resolve_body_cap("PUT", "/mcp/v1/");
    CHECK(mcp.path_class == "mcp");
}

// ── 5. Unlisted path -> non-zero catch-all default ────────────────────────

TEST_CASE("resolve_body_cap: an unlisted path resolves to the non-zero catch-all default",
          "[body_cap]") {
    const auto got = resolve_body_cap("POST", "/api/v1/totally-unknown-route-xyz");
    CHECK(got.path_class == "default");
    CHECK(got.max_body_bytes > 0);
    CHECK(got.max_body_bytes == 4u * 1024 * 1024);
    CHECK_FALSE(got.requires_measurable);
}

// ── 6. Every cap is non-zero; the path_class label set is finite and locked ──

TEST_CASE("kBodyCapTable: every entry's cap is non-zero", "[body_cap]") {
    for (const auto& entry : kBodyCapTable) {
        INFO("path_class=" << entry.path_class);
        CHECK(entry.max_body_bytes > 0);
    }
}

TEST_CASE("kBodyCapTable: the path_class label set is exactly the documented, finite set",
          "[body_cap]") {
    std::set<std::string> got;
    for (const auto& entry : kBodyCapTable)
        got.insert(std::string(entry.path_class));

    std::set<std::string> expected;
    for (auto label : kExpectedPathClasses)
        expected.insert(std::string(label));

    CHECK(got == expected);
}

TEST_CASE("kBodyCapTable: the row count is locked", "[body_cap]") {
    // Independent of the label-set check above: a new row using an EXISTING
    // label (e.g. a second SCIM method already covered) would pass that
    // check while still silently growing the table. 28 = mcp(1) +
    // bundles(1) + ota_upload(1) + json_to_csv_export(1) + nvd_match(1) +
    // ca_import_chain(1) + ca_issue_code_signing(1: gap-matrix #10) +
    // ca_revoke(1) +
    // kek_ops(1: one prefix entry covers both rotate and rewrap) +
    // ca_import_chain_dashboard(1) + plugin_trust_bundle(1) + scim(3:
    // POST/PUT/PATCH) + saml_acs(1) + response_templates(2: POST/PUT) +
    // tar_dashboard_sql(1) + tar_result_set_sql(1) +
    // guardian_rule_authoring(2: POST create + PUT update) +
    // workflow_yaml(1) + product_pack_yaml(1) + instruction_import(1) +
    // instruction_yaml(3: save/validate/preview) + upload_session(1: the
    // PR1.6a chunked-receive surface) + plugin_config(1: the PR1.5 config/
    // secret plane) + hardware(1: the Hardware CI list/record/sync REST v1
    // twin, governance Gate 2) + rbac_role_assignment(1: A2 global human
    // role assignment, .claude/plans/rbac-industry-leading-DELIVERY-PLAN.md
    // §2) + default(1).
    CHECK(std::size(kBodyCapTable) == 30);
}

// ── 7. requires_measurable: ON for /mcp/ and upload_session, OFF elsewhere ──

// M2 (review finding): this case's own name claimed "ON only for /mcp/"
// while never asserting the OTHER measurable class at all — the doc's
// rest-api.md carried the identical stale claim (both fixed together). A
// regression on the upload_session opt-in would have shipped with this
// test green.
TEST_CASE("resolve_body_cap: requires_measurable is ON for /mcp/, upload_session, and "
         "hardware, OFF for every other named class",
         "[body_cap]") {
    CHECK(resolve_body_cap("POST", "/mcp/v1/").requires_measurable);
    CHECK(resolve_body_cap("GET", "/mcp/v1/").requires_measurable);
    CHECK(resolve_body_cap("PUT", "/api/v1/uploads/abc123/chunk").requires_measurable);
    CHECK(resolve_body_cap("POST", "/api/v1/uploads").requires_measurable);
    CHECK(resolve_body_cap("POST", "/api/v1/hardware/agent-1/sync").requires_measurable);
    CHECK(resolve_body_cap("GET", "/api/v1/hardware").requires_measurable);

    // Public REST (bundles), SCIM, certificate import (REST + dashboard),
    // product-pack/workflow authoring, OTA upload, and plugin-config all
    // default OFF — see the file header's rationale (chunked is legal HTTP;
    // no client population has been tested against a hard Content-Length
    // contract on these routes yet).
    CHECK_FALSE(resolve_body_cap("POST", "/api/v1/bundles").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/scim/v2/Users").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/v1/ca/import-chain").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/settings/ca/import-chain").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/workflows").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/product-packs").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/settings/updates/upload").requires_measurable);
    CHECK_FALSE(resolve_body_cap("PUT", "/api/v1/plugin-config/email/host").requires_measurable);
    CHECK_FALSE(resolve_body_cap("POST", "/api/v1/totally-unknown-route-xyz").requires_measurable);
}

// ── 8. On-the-wire coverage for the D1-D4 hardening of the pre-routing
//       chokepoint (server.cpp `set_pre_routing_handler`) ───────────────────
//
// SKIPPED UNDER ThreadSanitizer (#438), same reasoning as
// test_mcp_body_cap.cpp: this deliberately exercises httplib::Server's
// middleware wiring, which crashes the TSan build.
//
// This fixture drives the SAME UNIFIED pre-routing DECISION server.cpp's
// `enforce_pre_auth_body_cap` lambda makes (D1: one branch for every path,
// including /mcp/) by calling `evaluate_body_cap` (body_cap_policy.hpp)
// directly — not the server.cpp lambda itself (which has no seam for
// in-process testing; see test_mcp_body_cap.cpp's header comment for why
// that gap is accepted), and, since #2898, not a second hand-written
// combination of the underlying pure predicates either. Before #2898 this
// fixture called `resolve_body_cap` / `body_unmeasurable` /
// `has_non_identity_content_encoding` / `content_length_is_authoritative`
// itself and re-derived the branching around them — the individual
// predicates were shared with production, but the DECISION (branch order,
// precedence, which status each reason maps to) was written twice. That is
// exactly the gap a CHANGES_REQUESTED review on PR #2899 found (tracked as
// #2898): a mutation to production's combination had no test that could see
// it, because this fixture's own, separately-written combination still
// matched its own separately-written expectations. `evaluate_body_cap` is
// now that one combination, called from both places, so a mutation to it is
// a mutation to what BOTH `server.cpp` and this fixture observe — see the
// "Mutation test" note below the fixture for the empirical proof. This
// fixture deliberately does NOT reproduce the metric/log/A4-envelope/
// SCIM-envelope side effects — those are review-only at the call site, same
// convention as test_mcp_body_cap.cpp's own fixture — only the STATUS the
// decision reaches.
//
// D3 is additionally modelled by placing a probe-style early return (Get
// "/health" answers 200 unconditionally) AFTER this cap check, so a fixture
// bug that put the cap check back BELOW a probe exemption would show up as a
// false-negative here too. This models ONE of production's two call sites —
// `enforce_pre_auth_body_cap` is invoked inside server.cpp's probe branch
// (the shape mirrored here) and again after the on-behalf-of guard and rate
// limiter for every other route. The second call site is not modelled: those
// two guards are out of this fixture's scope.
#ifndef YUZU_TSAN_BUILD

namespace {

constexpr std::uint64_t kUnifiedTestCap = 4u * 1024 * 1024; // matches the real default cap

struct UnifiedBodyCapTestServer {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};
    std::atomic<int> handler_calls{0};
    // Rejection witness (#2757): incremented exactly where the pre-routing
    // handler below decides `decision.refuse`, so a Windows connection-reset
    // fallback (test_loopback_http.hpp) can prove the rejection actually
    // ran for a given request rather than accepting any lost response.
    // Distinct from post_read_rejections below, which counts a DIFFERENT
    // (later) stage.
    std::atomic<int> pre_routing_rejections{0};
    // body-cap-post-read-stage (#2898-aware): counts every invocation of the
    // fixture's `set_pre_request_handler` below, admitted or refused. Used
    // to prove ORDERING against the pre-routing stage — a request the
    // pre-routing handler already refused never reaches `dispatch_request`
    // at all (httplib's routing() returns as soon as pre-routing answers
    // Handled), so this stays 0 for a pre-routing rejection and >=1 for
    // anything that reaches the second stage.
    std::atomic<int> post_read_calls{0};
    // Mirrors server.cpp's ONE metrics-counter increment per post-read
    // rejection (this fixture has no real `metrics_` object to assert
    // against — see this file's header comment on what the fixture
    // deliberately does not reproduce). Used only to prove "increments once
    // per rejection, never twice for the one request" within the fixture's
    // own model, not as a stand-in for exercising the production Counter.
    std::atomic<int> post_read_rejections{0};

    void start() {
        auto ok_handler = [this](const httplib::Request&, httplib::Response& res) {
            handler_calls.fetch_add(1);
            res.set_content(R"({"ok":true})", "application/json");
        };
        svr.Get("/api/v1/devices", ok_handler);
        svr.Post("/api/v1/devices", ok_handler);
        svr.Get("/health", ok_handler);
        svr.Post("/health", ok_handler);
        svr.Post("/mcp/v1/", ok_handler);
        // A small-cap (256 KiB), requires_measurable=false class — used by
        // the post-read-stage tests below so a genuine chunked over-cap body
        // stays cheap to send in a test.
        svr.Post("/api/v1/ca/import-chain", ok_handler);

        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res)
                                        -> httplib::Server::HandlerResponse {
            // THE decision comes from `evaluate_body_cap`
            // (body_cap_policy.hpp) — the SAME callable server.cpp's
            // production `enforce_pre_auth_body_cap` lambda invokes, not a
            // second, independently-written combination of the same
            // predicates (#2898). Before this, the fixture combined
            // `resolve_body_cap` + `body_unmeasurable` +
            // `has_non_identity_content_encoding` +
            // `content_length_is_authoritative` A SECOND TIME by hand — the
            // individual pure functions were shared, but the DECISION (which
            // branch wins, in which order, mapped to which status) was not,
            // so a mutation to production's combination (an inverted
            // condition, a swapped 411/413, a dropped branch) had nothing
            // here that could see it. Routing through the one shared
            // function makes that divergence structurally impossible instead
            // of something to keep re-verifying by hand. `is_chunked` still
            // MUST come from httplib's own `is_chunked_transfer_encoding`
            // (unchanged from before this extraction — a prior version of
            // this fixture called `req.get_header_value_u64` directly for
            // Content-Length while production hand-rolled a
            // `std::from_chars` parse; the two disagreed on an all-digit
            // Content-Length above 2^64-1, and this fixture's assertions
            // passed green with that CRITICAL bypass live in the code it
            // claimed to replicate — `content_length_for_body_cap` closes
            // that specific gap, `evaluate_body_cap` closes the
            // decision-combination gap this same defect class lives in).
            const auto decision = evaluate_body_cap(
                req.method, req.path, req.has_header("Content-Length"),
                content_length_for_body_cap(req), req.get_header_value("Transfer-Encoding"),
                req.get_header_value("Content-Encoding"),
                httplib::detail::is_chunked_transfer_encoding(req.headers));
            if (decision.refuse) {
                res.status = decision.status;
                pre_routing_rejections.fetch_add(1);
                return httplib::Server::HandlerResponse::Handled;
            }
            // Everything below this point (onbehalf-of, rate limiting, the
            // real probe exemption in production) is out of scope for this
            // fixture — /health falls through to the SAME Unhandled as any
            // other admitted path. What matters is that it only gets here
            // AFTER the cap check above ran unconditionally (D3).
            return httplib::Server::HandlerResponse::Unhandled;
        });

        // body-cap-post-read-stage — GENUINELY WIRED into this fixture the
        // same way server.cpp wires it (issue #2898: earlier versions of
        // this fixture only reproduced the pre-routing decision with pure
        // functions, which meant a test against the fixture could never
        // observe a defect in server.cpp's real `set_pre_request_handler`).
        // Real httplib::Server here means `req.body` is genuinely populated
        // by httplib's own `read_content` before this fires — including for
        // a real chunked-Transfer-Encoding request the pre-routing handler
        // above admitted unmeasured, which is the whole point of this
        // stage.
        svr.set_pre_request_handler([this](const httplib::Request& req, httplib::Response& res)
                                        -> httplib::Server::HandlerResponse {
            post_read_calls.fetch_add(1);
            const auto cap_match = resolve_body_cap(req.method, req.path);
            if (req.body.size() <= cap_match.max_body_bytes) {
                return httplib::Server::HandlerResponse::Unhandled;
            }
            post_read_rejections.fetch_add(1);
            res.status = 413;
            return httplib::Server::HandlerResponse::Handled;
        });

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        svr.wait_until_ready();
        REQUIRE(svr.is_running());
    }

    ~UnifiedBodyCapTestServer() {
        // Ordering mirrors test_mcp_body_cap.cpp's BodyCapTestServer dtor —
        // see that file's comment for why the naive version deadlocks.
        if (server_thread.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            server_thread.join();
        }
    }
};

#ifndef _WIN32
/// Send a raw request declaring `Content-Length` without ever sending that
/// many body bytes, and return the first bytes of the response. Proves the
/// REJECTION happens before the (never-sent) body would be read — the same
/// technique test_mcp_body_cap.cpp uses, needed here because httplib::Client
/// has no `Get(path, body, ...)` overload to declare a body on a GET.
std::string raw_request_status_line(int port, const std::string& request_head) {
    struct Fd {
        int v;
        explicit Fd(int f) : v(f) {}
        ~Fd() {
            if (v >= 0)
                ::close(v);
        }
        Fd(const Fd&) = delete;
        Fd& operator=(const Fd&) = delete;
    } sock{::socket(AF_INET, SOCK_STREAM, 0)};
    REQUIRE(sock.v >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(sock.v, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    timeval tv{};
    tv.tv_sec = 10;
    REQUIRE(::setsockopt(sock.v, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);

    REQUIRE(::send(sock.v, request_head.data(), request_head.size(), 0) ==
            static_cast<ssize_t>(request_head.size()));

    char buf[256] = {};
    const ssize_t n = ::recv(sock.v, buf, sizeof(buf) - 1, 0);
    INFO("recv returned " << n << " bytes: " << std::string(buf, n > 0 ? n : 0));
    REQUIRE(n > 0);
    return std::string(buf, static_cast<size_t>(n));
}

/// Send a raw request and ACTUALLY WRITE the whole thing — unlike
/// `raw_request_status_line` above, which deliberately never sends the body
/// it declares. Needed for the post-read-stage tests: those need httplib to
/// genuinely finish `read_content` and populate `req.body` before this
/// stage's decision can be exercised at all, so the (chunked-framed) body
/// must actually be sent, not just declared. Loops on `::send` — a single
/// blocking call is not guaranteed to enqueue a several-hundred-KiB payload
/// in one syscall.
std::string raw_request_status_line_send_all(int port, const std::string& request) {
    struct Fd {
        int v;
        explicit Fd(int f) : v(f) {}
        ~Fd() {
            if (v >= 0)
                ::close(v);
        }
        Fd(const Fd&) = delete;
        Fd& operator=(const Fd&) = delete;
    } sock{::socket(AF_INET, SOCK_STREAM, 0)};
    REQUIRE(sock.v >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(sock.v, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    timeval tv{};
    tv.tv_sec = 10;
    REQUIRE(::setsockopt(sock.v, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);

    std::size_t sent = 0;
    while (sent < request.size()) {
        const ssize_t n = ::send(sock.v, request.data() + sent, request.size() - sent, 0);
        REQUIRE(n > 0);
        sent += static_cast<std::size_t>(n);
    }

    char buf[256] = {};
    const ssize_t n = ::recv(sock.v, buf, sizeof(buf) - 1, 0);
    INFO("recv returned " << n << " bytes: " << std::string(buf, n > 0 ? n : 0));
    REQUIRE(n > 0);
    return std::string(buf, static_cast<size_t>(n));
}

/// A genuine (real bytes, no Content-Length) chunked-encoded body of exactly
/// `total` bytes, as one HTTP chunk plus the terminating zero-length chunk.
std::string chunked_encode(std::size_t total) {
    const std::string data(total, 'x');
    return std::format("{:x}\r\n", total) + data + "\r\n0\r\n\r\n";
}
#endif // !_WIN32

} // namespace

#ifndef _WIN32
TEST_CASE("Pre-routing body cap: a GET with an oversized declared Content-Length is "
          "rejected (D2)",
          "[body_cap][mcp][bounds][integration]") {
    // The exclusion this pins the removal of was justified in-code by "GET
    // never carries a body" — false (web_utils.hpp already documented the
    // opposite; httplib's expect_content() is true for any method with
    // Content-Length > 0). A GET declaring an oversized Content-Length must
    // be rejected exactly like a POST, and — same load-bearing assumption as
    // the MCP raw-socket test — WITHOUT ever reading the (unsent) body.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string req = "GET /api/v1/devices HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Length: 104857600\r\n"
                            "\r\n"; // ...and then nothing.
    const auto resp = raw_request_status_line(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 413"));
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: POST /health with an oversized declared Content-Length "
          "is rejected (D3)",
          "[body_cap][mcp][bounds][integration]") {
    // /health is one of the four paths that ALSO skip the 401 gate — before
    // D3 moved the cap ahead of that exemption, this was the last
    // unauthenticated 100 MiB buffer on the server. The fixture's probe-style
    // Unhandled return for "/health" only fires below the cap check, so this
    // proves the ORDERING, not just that some cap exists somewhere.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string req = "POST /health HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Length: 104857600\r\n"
                            "\r\n";
    const auto resp = raw_request_status_line(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 413"));
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: a non-chunked Transfer-Encoding does NOT suppress the "
          "size check on a class that has not opted into requires_measurable",
          "[body_cap][mcp][bounds][integration]") {
    // REGRESSION GUARD for an unauthenticated bypass that survived three
    // governance rounds and an adversarial panel, and was found by the fifth
    // reviewer of this change.
    //
    // `body_unmeasurable` treats ANY non-empty Transfer-Encoding as
    // unmeasurable — the deliberately broad #2437 refuse rule. httplib only
    // treats a request as chunked when the value is EXACTLY `chunked`
    // (`is_chunked_transfer_encoding`, case-insensitive); for `identity`, `x`,
    // or even `identity, chunked` it falls through to the Content-Length
    // branch and reads that many bytes.
    //
    // So while the size check was gated on `!unmeasurable`, one header
    // suppressed the cap on all 24 classes that do not set
    // requires_measurable — including the rate-limit-exempt probe paths —
    // while httplib went on to read the declared body in full. Production now
    // gates the size check on `content_length_is_authoritative` instead, which
    // asks httplib rather than re-deciding the header.
    //
    // Why no test caught it: the suite's only Transfer-Encoding integration
    // case was on /mcp/, where requires_measurable=true makes the request
    // 411 either way. No non-mcp class was exercised with a TE header at all.
    UnifiedBodyCapTestServer ts;
    ts.start();

    // 8 MiB against ca_import_chain's 256 KiB cap. Every one of these values
    // is non-chunked to httplib, so the declared length is authoritative and
    // the cap must apply.
    for (const auto* te : {"identity", "x", "identity, chunked", "CHUNKED, identity"}) {
        const std::string req = std::string("POST /api/v1/ca/import-chain HTTP/1.1\r\n"
                                            "Host: 127.0.0.1\r\n"
                                            "Content-Length: 8388608\r\n"
                                            "Transfer-Encoding: ") +
                                te + "\r\n\r\n";
        const auto resp = raw_request_status_line(ts.port, req);
        INFO("Transfer-Encoding: " << te);
        CHECK(resp.starts_with("HTTP/1.1 413"));
    }
    CHECK(ts.handler_calls.load() == 0);

    // The genuine chunked case is UNCHANGED: no authoritative length, so the
    // documented requires_measurable=false trade still applies and the request
    // falls through to httplib's own backstop rather than being capped here.
    // Asserting this keeps the fix honest — it must not have quietly turned
    // into "refuse every Transfer-Encoding", which would break real clients.
    const std::string chunked = "POST /api/v1/ca/import-chain HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Transfer-Encoding: chunked\r\n\r\n"
                                "0\r\n\r\n";
    const auto resp = raw_request_status_line(ts.port, chunked);
    CHECK_FALSE(resp.starts_with("HTTP/1.1 413"));
}
#endif // !_WIN32

TEST_CASE("Pre-routing body cap: a non-identity Content-Encoding is refused regardless "
          "of class (D4)",
          "[body_cap][mcp][bounds][integration]") {
    UnifiedBodyCapTestServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    // A class with requires_measurable == false (the "default" catch-all,
    // matched by /api/v1/devices) — proves D4 does NOT gate on that bit.
    yuzu::test::expect_pre_routing_rejection(
        [&] {
            return cli.Post("/api/v1/devices", {{"Content-Encoding", "gzip"}}, "small body",
                            "application/json");
        },
        415, ts.pre_routing_rejections);
    CHECK(ts.handler_calls.load() == 0);

    // /mcp/ (requires_measurable == true) reaches the SAME refusal via the
    // SAME first check, not the class-specific unmeasurable path (411).
    yuzu::test::expect_pre_routing_rejection(
        [&] {
            return cli.Post("/mcp/v1/", {{"Content-Encoding", "br"}}, "small body",
                            "application/json");
        },
        415, ts.pre_routing_rejections);
    CHECK(ts.handler_calls.load() == 0);

    // A request with NO Content-Encoding header (ordinary traffic) is still
    // admitted (sanity: the check is encoding-VALUE aware, not "any
    // Content-Encoding header present"). Deliberately NOT tested by sending
    // an EXPLICIT `Content-Encoding: identity` end-to-end here: doing so
    // during development surfaced a SEPARATE, PRE-EXISTING httplib quirk,
    // unrelated to this change — `detail::create_decompressor` (httplib.h:
    // 6717) recognises only gzip/deflate/br/zstd and returns null for
    // anything else INCLUDING the literal string "identity", so httplib's
    // own content-reader 415s an explicit `identity` value for any ordinary
    // route's body read (`prepare_content_receiver`, httplib.h:6980-6986) —
    // completely independent of `has_non_identity_content_encoding`, which
    // correctly does NOT refuse it at THIS (pre-routing) chokepoint. That
    // downstream quirk is out of scope for #2407 and worth its own follow-up
    // (an explicit `identity` is a materially different declaration from
    // omitting the header, and RFC 7231 §3.1.2.1 lists it as valid), but
    // asserting past it here would make this test depend on unrelated
    // httplib internals rather than on the D4 decision under test.
    auto r3 = cli.Post("/api/v1/devices", "small body", "application/json");
    REQUIRE(r3);
    CHECK(r3->status == 200);
    CHECK(ts.handler_calls.load() == 1);
}

#ifndef _WIN32
TEST_CASE("Pre-routing body cap: /mcp/ still behaves as before through the unified path "
          "(rejections)",
          "[body_cap][mcp][bounds][integration]") {
    // Raw socket, not httplib::Client, for BOTH sub-cases below — declaring
    // a real 4 MiB+ Content-Length and then actually writing that many bytes
    // would block the client's write once the kernel socket buffers fill,
    // because (D5) a REJECTED request's body is never drained by the
    // server; the client can only finish writing once the server reads,
    // which for a 413/411 it never does. (Measured while writing this test:
    // that exact shape made an earlier version of this test time out.)
    // Declaring-without-sending sidesteps the deadlock and is the same
    // technique test_mcp_body_cap.cpp's own ordering test uses.
    UnifiedBodyCapTestServer ts;
    ts.start();

    {
        // Over the cap -> 413.
        const std::string req = "POST /mcp/v1/ HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: " +
                                std::to_string(kUnifiedTestCap + 1) + "\r\n\r\n";
        const auto resp = raw_request_status_line(ts.port, req);
        CHECK(resp.starts_with("HTTP/1.1 413"));
    }
    {
        // requires_measurable is still ON for /mcp/: chunked framing (no
        // Content-Length) is refused 411, not admitted up to the 100 MiB
        // backstop (the behaviour every OTHER class keeps, unchanged by D1).
        const std::string req = "POST /mcp/v1/ HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Transfer-Encoding: chunked\r\n\r\n";
        const auto resp = raw_request_status_line(ts.port, req);
        CHECK(resp.starts_with("HTTP/1.1 411"));
    }
    CHECK(ts.handler_calls.load() == 0);
}
#endif // !_WIN32

TEST_CASE("Pre-routing body cap: /mcp/ still behaves as before through the unified path "
          "(admits exactly at the cap)",
          "[body_cap][mcp][bounds][integration]") {
    UnifiedBodyCapTestServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    auto at_cap = cli.Post("/mcp/v1/", std::string(kUnifiedTestCap, 'x'), "application/json");
    REQUIRE(at_cap);
    CHECK(at_cap->status == 200);
    CHECK(ts.handler_calls.load() == 1);
}

#ifndef _WIN32
TEST_CASE("Pre-routing body cap: an all-digit Content-Length above 2^64-1 is refused as "
          "oversize, not silently admitted as absent (#2407 R2 — the CRITICAL bypass)",
          "[body_cap][bounds][integration]") {
    // The defect this pins: `std::from_chars` reports
    // `result_out_of_range` for these two values and the pre-#2407-R1 code
    // folded that to `content_length = 0` ("no header present, don't
    // cap") — while httplib's own `is_numeric()` + `strtoull()` parser
    // (httplib.h:2769-2789) accepts the same all-digit string and returns
    // `SIZE_MAX`, which is what it ALSO uses to decide what it buffers.
    // `content_length_for_body_cap` (web_utils.hpp) now delegates to that
    // same accessor, so both values must resolve to "oversize" (413), on
    // the plain catch-all class, not just /mcp/.
    UnifiedBodyCapTestServer ts;
    ts.start();

    for (const std::string& overflow_value :
         {std::string("99999999999999999999999"), std::string("18446744073709551616")}) {
        const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: " +
                                overflow_value + "\r\n\r\n";
        INFO("Content-Length: " << overflow_value);
        const auto resp = raw_request_status_line(ts.port, req);
        CHECK(resp.starts_with("HTTP/1.1 413"));
    }
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: a malformed (non-numeric) Content-Length is never "
          "silently admitted — refused end-to-end even where this gate alone reads it "
          "as absent (#2407 R2)",
          "[body_cap][bounds][integration]") {
    // `is_numeric()` (httplib.h:2769-2773) requires EVERY character to be
    // an ASCII digit, so each of these fails it and
    // `content_length_for_body_cap` reads them as 0 — matching httplib's
    // OWN accessor exactly (that is the point of #2407 R1/R2: one shared
    // function, not two that might disagree). A 0 reading is NOT oversize,
    // so THIS gate alone lets the request past as Unhandled. That is fine,
    // not a re-opened gap: httplib's own body reader
    // (`detail::read_content`, httplib.h:7057-7063) independently rejects
    // the SAME malformed header with its own `is_invalid_value` check and
    // answers 400 before any route handler runs — this test asserts THAT
    // end-to-end outcome, proving the request is refused somewhere in the
    // pipeline, never silently processed with an unbounded/unmeasured
    // body.
    UnifiedBodyCapTestServer ts;
    ts.start();

    for (const std::string& malformed_value :
         {std::string("-1"), std::string("+5"), std::string(" 12"), std::string("abc"),
          std::string("")}) {
        const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: " +
                                malformed_value + "\r\n\r\n";
        INFO("Content-Length: '" << malformed_value << "'");
        const auto resp = raw_request_status_line(ts.port, req);
        // httplib itself answers 400 for an invalid Content-Length value
        // it cannot parse (is_invalid_value branch) before any handler
        // runs — accept a 4xx broadly (never 200/2xx) so this stays
        // resilient to which layer of the pipeline answers, while still
        // failing if the request were ever admitted through to the
        // handler.
        CHECK(!resp.starts_with("HTTP/1.1 2"));
    }
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: duplicate Content-Length headers cannot desync the "
          "gate's decision from httplib's own body read (#2407 R2)",
          "[body_cap][bounds][integration]") {
    // httplib's `Headers` is `std::unordered_multimap<..., case_ignore::hash,
    // case_ignore::equal_to>` (httplib.h:778-780) — an UNORDERED container,
    // not the ordered `std::multimap` an RFC 7230 "first occurrence" framing
    // might suggest. WHICH of two duplicate `Content-Length` values
    // `get_header_value_u64("Content-Length", 0, /*id=*/0)` resolves to is
    // therefore UNSPECIFIED by the C++ standard (hash-bucket insertion
    // order, not header-line order). Measured empirically against this
    // vcpkg baseline while writing this test (a standalone reproduction
    // against a real httplib::Server): `id=0` resolved to the LAST header
    // LINE sent, not the first — the opposite of what an ordered container,
    // or an RFC-literal reading, would give. This test deliberately does
    // NOT assert on that specific measurement, because it is an
    // IMPLEMENTATION detail that could shift with a future vcpkg bump, not
    // a contract. What it asserts instead is the SAFETY property that holds
    // regardless of which duplicate value httplib's bucket order happens to
    // prefer: `content_length_for_body_cap` (this gate) and httplib's own
    // body reader (httplib.h:7057-7061) call the IDENTICAL accessor with
    // the IDENTICAL id against the SAME already-parsed `Headers` object,
    // for the SAME single request — so whichever value "wins" is the SAME
    // value at BOTH call sites, deterministically, every time. There is no
    // pair of duplicate values where this gate's admit/refuse decision and
    // httplib's actual buffering decision can disagree.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string small_body = "ok";
    const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: " +
                            std::to_string(small_body.size()) +
                            "\r\n"
                            "Content-Length: 99999999999999999999999\r\n\r\n" +
                            small_body;
    const auto resp = raw_request_status_line(ts.port, req);
    // Whichever duplicate value httplib's unordered_multimap resolves as
    // id=0: either it is the oversize one — refused here, 413, handler
    // never runs — or it is the small one — admitted, and httplib's ACTUAL
    // body read is then bounded to those `small_body.size()` bytes we
    // genuinely sent, so the handler runs normally, 200. Anything else
    // (a hang waiting on unsent bytes, a mid-read reset, a status neither
    // of these) would mean the gate and the real reader disagreed about
    // which duplicate to trust — the split-brain this test exists to rule
    // out.
    const bool refused = resp.starts_with("HTTP/1.1 413");
    const bool admitted = resp.starts_with("HTTP/1.1 200");
    INFO("response: " << resp);
    CHECK((refused || admitted));
    CHECK(ts.handler_calls.load() == (admitted ? 1 : 0));
}
#endif // !_WIN32

// ── 9. Post-read body cap, second stage (body-cap-post-read-stage) ────────
//
// GENUINELY WIRED into `UnifiedBodyCapTestServer` (see that fixture's
// `set_pre_request_handler` above) — issue #2898 is the reason this needed
// calling out explicitly: earlier body-cap fixtures in this file only
// reproduced production's DECISION with the same pure functions
// (`resolve_body_cap` etc.), never httplib's actual middleware wiring for
// this stage, so a test written only against a fixture like that could not
// have told a real server.cpp defect from a fixture defect. These cases
// exercise the real httplib `pre_request_handler_` call site end-to-end —
// same reasoning as section 8 above for the pre-routing stage.
#ifndef _WIN32
TEST_CASE("Post-read body cap: a genuine chunked body over a class's cap is rejected "
          "after being read, not admitted uncapped",
          "[body_cap][post_read][bounds][integration]") {
    // /api/v1/ca/import-chain: 256 KiB cap, requires_measurable=false — the
    // pre-routing stage admits ANY chunked body on this class unmeasured
    // (body_cap_policy.hpp's KNOWN LIMITATION paragraph). This sends a REAL
    // chunked body of 256 KiB + 1 byte — no Content-Length, so the
    // pre-routing gate cannot and does not reject it — and expects the
    // post-read stage to catch it once httplib has actually read it into
    // `req.body`.
    UnifiedBodyCapTestServer ts;
    ts.start();

    constexpr std::size_t kCap = 256u * 1024;
    const std::string req = "POST /api/v1/ca/import-chain HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Type: application/octet-stream\r\n"
                            "Transfer-Encoding: chunked\r\n\r\n" +
                            chunked_encode(kCap + 1);
    const auto resp = raw_request_status_line_send_all(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 413"));
    // The route handler never ran — the request was refused between read
    // and dispatch.
    CHECK(ts.handler_calls.load() == 0);
    // The post-read stage genuinely fired (not skipped/short-circuited) ...
    CHECK(ts.post_read_calls.load() == 1);
    // ... and its rejection-side effect (the counter-increment analogue)
    // fired EXACTLY once for this one request — not zero, not twice.
    CHECK(ts.post_read_rejections.load() == 1);
}

TEST_CASE("Post-read body cap: a genuine chunked body under a class's cap is still "
          "admitted",
          "[body_cap][post_read][bounds][integration]") {
    // Same class, same framing, comfortably under the 256 KiB cap — proves
    // this stage is a CAP, not a blanket refusal of every chunked body.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string req = "POST /api/v1/ca/import-chain HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Type: application/octet-stream\r\n"
                            "Transfer-Encoding: chunked\r\n\r\n" +
                            chunked_encode(1024);
    const auto resp = raw_request_status_line_send_all(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 200"));
    CHECK(ts.handler_calls.load() == 1);
    CHECK(ts.post_read_calls.load() == 1);
    CHECK(ts.post_read_rejections.load() == 0);
}

TEST_CASE("Post-read body cap: a MEASURABLE over-cap body is still caught by the "
          "earlier pre-routing stage, never reaching the post-read stage",
          "[body_cap][post_read][bounds][integration]") {
    // Same class (256 KiB cap) as the two cases above, but this time the
    // body is declared via Content-Length (never actually sent — the
    // pre-routing gate must refuse before any of it is read, same
    // declare-without-send technique as section 8's D2/D3 cases). Proves
    // the ORDERING claim from the brief: for a body the pre-routing stage
    // CAN size, it is the one that rejects — this second stage never even
    // runs (httplib's routing() returns as soon as pre-routing answers
    // Handled, without ever calling dispatch_request).
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string req = "POST /api/v1/ca/import-chain HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Length: 8388608\r\n\r\n"; // 8 MiB, never sent
    const auto resp = raw_request_status_line(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 413"));
    CHECK(ts.handler_calls.load() == 0);
    // The load-bearing assertion for this test: the post-read stage was
    // never even invoked for this request.
    CHECK(ts.post_read_calls.load() == 0);
    CHECK(ts.post_read_rejections.load() == 0);
}
#endif // !_WIN32

#endif // !YUZU_TSAN_BUILD
