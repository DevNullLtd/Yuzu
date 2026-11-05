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

#include "body_cap_httplib.hpp"
#include "body_cap_policy.hpp"
#include "post_read_stage_test_support.hpp"
#include "raw_close_probe.hpp"
#include "test_loopback_http.hpp"
#include "web_utils.hpp"

#include "../test_helpers.hpp"

#include <httplib.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

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
using yuzu::server::content_encoding_for_body_cap;
using yuzu::server::content_length_for_body_cap;
using yuzu::server::evaluate_body_cap;
using yuzu::server::kBodyCapAnyMethod;
using yuzu::server::kBodyCapTable;
using yuzu::server::resolve_body_cap;
using yuzu::server::transfer_encoding_for_body_cap;

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
    {"POST",   "/api/dashboard/echo-execute",              16u * 1024,         false, "echo_dashboard_sql"},
    // rest_api_v1.cpp:6802 `sql.size() > 100000` on the JSON-parsed field;
    // 200 KiB = 2x100000 for JSON-escaping headroom plus the other JSON keys.
    {"POST",   "/api/v1/result-sets/from-echo-query",      200u * 1024,        false, "echo_result_set_sql"},
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
    // v1 twin (hardware_routes.cpp). Only POST .../sync and the fleet fan-out
    // POST /api/v1/hardware/sync carry a body (a short "source" enum token, and
    // for the fan-out a scope token or a <=1024-character expression, which
    // inherits this row by segment-boundary prefix); requires_measurable=true closes the same
    // pre-auth-buffering gap the upload_session row above does (governance
    // Gate 2). ANY method — the bodyless GET list/record routes on the same
    // prefix are unaffected but share the class rather than falling to the
    // (looser) catch-all.
    {"GET",    "/api/v1/hardware",                        4u * 1024,          true,  "hardware"},
    {"GET",    "/api/v1/hardware/agent-1",                4u * 1024,          true,  "hardware"},
    {"POST",   "/api/v1/hardware/agent-1/sync",           4u * 1024,          true,  "hardware"},
    {"POST",   "/api/v1/hardware/sync",                   4u * 1024,          true,  "hardware"},
    // body_cap_policy.hpp rbac_role_assignment row — A2 global human role
    // assignment (rest_api_v1.cpp). POST body is {principal_type,
    // principal_id}; DELETE carries none. ANY method — the DELETE sibling
    // shares this literal prefix once past the role-name path segment.
    {"POST",   "/api/v1/rbac/roles/Operator/assignments",              4u * 1024, false, "rbac_role_assignment"},
    {"DELETE", "/api/v1/rbac/roles/Operator/assignments/alice",        4u * 1024, false, "rbac_role_assignment"},
    // body_cap_policy.hpp rbac_enforcement row — A1 enforcement toggle
    // (rest_api_v1.cpp). Body is {"enabled": true}. A segment-boundary
    // probe (not a literal prefix match) proves "enforcement-evil" does NOT
    // inherit this row and falls to the catch-all instead.
    {"PUT",    "/api/v1/rbac/enforcement",                             1u * 1024, false, "rbac_enforcement"},
    {"PUT",    "/api/v1/rbac/enforcement-evil",                        4u * 1024 * 1024, false, "default"},
    // body_cap_policy.hpp guardian_policy_generation row: the Guardian policy-generation
    // raise (rest_api_v1.cpp). ANY method. Body is {"target_generation": N,
    // "acknowledge_rule_set_replaced": true}. Segment-boundary probes prove neither a
    // lookalike sibling nor the guardian_rule_authoring prefix swallows it.
    {"POST",   "/api/v1/guaranteed-state/policy-generation/raise",     1u * 1024, false, "guardian_policy_generation"},
    {"POST",   "/api/v1/guaranteed-state/policy-generation-evil/raise", 4u * 1024 * 1024, false, "default"},
    // body_cap_policy.hpp users row — the /api/v1/users REST v1 subtree
    // (#5342 password routes + unlock + elevation-eligibility). ANY method;
    // a segment-boundary probe proves "/api/v1/usersevil" does NOT inherit it.
    {"POST",   "/api/v1/users/me/password",                            16u * 1024, false, "users"},
    {"POST",   "/api/v1/users/alice/password",                         16u * 1024, false, "users"},
    {"POST",   "/api/v1/users/alice/unlock",                           16u * 1024, false, "users"},
    {"POST",   "/api/v1/users/elevation-eligibility",                  16u * 1024, false, "users"},
    {"POST",   "/api/v1/usersevil",                                    4u * 1024 * 1024, false, "default"},
    // body_cap_policy.hpp dex_score_policy row: the DEX score policy document. ANY method,
    // measurable; a segment-boundary probe proves "/api/v1/dex/score-policyx" falls to default.
    {"PUT",    "/api/v1/dex/score-policy",                             320u * 1024, true,  "dex_score_policy"},
    {"DELETE", "/api/v1/dex/score-policy",                             320u * 1024, true,  "dex_score_policy"},
    {"PUT",    "/api/v1/dex/score-policyx",                            4u * 1024 * 1024, false, "default"},
    // body_cap_policy.hpp crypto row - the /crypto REST v1 subtree; PUT dashboard/layout is the
    // only body-bearing route (crypto_widget_catalogue.hpp kLayoutBodyMaxBytes). ANY method.
    {"PUT",    "/api/v1/crypto/dashboard/layout",                      16u * 1024, false, "crypto"},
    {"PUT",    "/api/v1/config/log_level",                             16u * 1024, false, "config"},
    {"GET",    "/api/v1/config",                                       16u * 1024, false, "config"},
    {"PUT",    "/api/v1/configevil/log_level",                         4u * 1024 * 1024, false, "default"},
    {"GET",    "/api/v1/crypto/ca/stats",                              16u * 1024, false, "crypto"},
    {"PUT",    "/api/v1/cryptoevil",                                   4u * 1024 * 1024, false, "default"},
    // body_cap_policy.hpp software_curation / software_alias_pack rows: the software-title
    // curation routes. ANY method; the pack row (1 MiB, mirrors kMaxPackBytes) is longer than
    // the 64 KiB subtree row and wins; segment-boundary probes prove lookalikes fall to default.
    {"POST",   "/api/v1/inventory/software/normalization/aliases",                64u * 1024, false, "software_curation"},
    {"POST",   "/api/v1/inventory/software/normalization/queue/abc/reject",       64u * 1024, false, "software_curation"},
    {"GET",    "/api/v1/inventory/software/normalization/status",                 64u * 1024, false, "software_curation"},
    {"POST",   "/api/v1/inventory/software/normalization/pack",                   1u * 1024 * 1024, false, "software_alias_pack"},
    {"PUT",    "/api/v1/inventory/software/normalization/pack",                   1u * 1024 * 1024, false, "software_alias_pack"},
    {"POST",   "/api/v1/inventory/software/normalization/packevil",               64u * 1024, false, "software_curation"},
    {"POST",   "/api/v1/inventory/software/normalizationevil/aliases",            4u * 1024 * 1024, false, "default"},
    // body_cap_policy.hpp commands row - POST /api/v1/commands (the REST v1 twin of MCP
    // execute_instruction). requires_measurable like the /mcp/ row; segment-boundary probe below.
    {"POST",   "/api/v1/commands",                                     4u * 1024 * 1024, true,  "commands"},
    {"POST",   "/api/v1/commandsevil",                                 4u * 1024 * 1024, false, "default"},
    // Catch-all default — ordinary JSON/form traffic.
    {"POST",   "/api/v1/some-ordinary-mutation-route",    4u * 1024 * 1024,   false, "default"},
    {"GET",    "/api/v1/devices",                         4u * 1024 * 1024,   false, "default"},
};
// clang-format on

/// Independent list of every distinct metric label the table is expected to
/// emit — locks metric cardinality separately from the per-row cap values.
constexpr std::string_view kExpectedPathClasses[] = {
    "mcp",
    "commands",
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
    "echo_dashboard_sql",
    "upload_session",
    "plugin_config",
    "echo_result_set_sql",
    "guardian_rule_authoring",
    "workflow_yaml",
    "product_pack_yaml",
    "instruction_import",
    "instruction_yaml",
    "hardware",
    "rbac_role_assignment",
    "rbac_enforcement",
    "guardian_policy_generation",
    "users",
    "dex_score_policy",
    "crypto",
    "config",
    "software_curation",
    "software_alias_pack",
    "default",
};

// Regression guard (#6367): `resolve_body_cap` must stay usable in a constant
// expression under -fsanitize=undefined. GCC 15 cannot constant-evaluate the
// UBSan pointer checks, so a `const BodyCapEntry*` best-match inside it breaks
// every UBSan leg that compiles `crypto_routes.cpp`'s `static_assert`. This
// TU is built in those legs too, so the guard also covers constexpr use
// outside `crypto_routes.cpp`.
static_assert(resolve_body_cap("PUT", "/api/v1/crypto/dashboard/layout").max_body_bytes > 0);
static_assert(resolve_body_cap("GET", "/no/such/route").path_class == std::string_view{"default"});

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
    // "/scim/v2/" (64 KiB, any method) and "" (the catch-all default,
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
    // check while still silently growing the table. 39 = mcp(1) +
    // commands(1: POST /api/v1/commands, the REST v1 twin of execute_instruction) +
    // bundles(1) + ota_upload(1) + json_to_csv_export(1) + nvd_match(1) +
    // ca_import_chain(1) + ca_issue_code_signing(1: gap-matrix #10) +
    // ca_revoke(1) +
    // kek_ops(1: one prefix entry covers both rotate and rewrap) +
    // ca_import_chain_dashboard(1) + plugin_trust_bundle(1) + scim(1:
    // one any-method row) + saml_acs(1) + response_templates(2: POST/PUT) +
    // echo_dashboard_sql(1) + echo_result_set_sql(1) +
    // guardian_rule_authoring(2: POST create + PUT update) +
    // workflow_yaml(1) + product_pack_yaml(1) + instruction_import(1) +
    // instruction_yaml(3: save/validate/preview) + upload_session(1: the
    // PR1.6a chunked-receive surface) + plugin_config(1: the PR1.5 config/
    // secret plane) + hardware(1: the Hardware CI list/record/sync REST v1
    // twin, governance Gate 2) + rbac_role_assignment(1: A2 global human
    // role assignment, .claude/plans/rbac-industry-leading-DELIVERY-PLAN.md
    // §2) + rbac_enforcement(1: A1 enforcement enable/disable toggle) +
    // guardian_policy_generation(1: the Guardian policy-generation raise) +
    // users(1: the /api/v1/users subtree, #5342 password routes) +
    // dex_score_policy(1: the DEX score policy document) +
    // crypto(1: the /api/v1/crypto subtree, the dashboard layout PUT) +
    // config(1: the /api/v1/config subtree, the runtime-config PUT) +
    // software_curation(1: the curation subtree) + software_alias_pack(1: the pack CSV) +
    // default(1).
    CHECK(std::size(kBodyCapTable) == 39);
}

// ── 7. requires_measurable: ON for /mcp/ and upload_session, OFF elsewhere ──

// M2 (review finding): this case's own name claimed "ON only for /mcp/"
// while never asserting the OTHER measurable class at all — the doc's
// rest-api.md carried the identical stale claim (both fixed together). A
// regression on the upload_session opt-in would have shipped with this
// test green.
TEST_CASE("resolve_body_cap: requires_measurable is ON for /mcp/ and upload_session and "
         "hardware and dex_score_policy and OFF for every other named class",
         "[body_cap]") {
    CHECK(resolve_body_cap("POST", "/mcp/v1/").requires_measurable);
    CHECK(resolve_body_cap("GET", "/mcp/v1/").requires_measurable);
    CHECK(resolve_body_cap("PUT", "/api/v1/uploads/abc123/chunk").requires_measurable);
    CHECK(resolve_body_cap("POST", "/api/v1/uploads").requires_measurable);
    CHECK(resolve_body_cap("POST", "/api/v1/hardware/agent-1/sync").requires_measurable);
    CHECK(resolve_body_cap("POST", "/api/v1/hardware/sync").requires_measurable);
    CHECK(resolve_body_cap("GET", "/api/v1/hardware").requires_measurable);
    CHECK(resolve_body_cap("PUT", "/api/v1/dex/score-policy").requires_measurable);
    CHECK(resolve_body_cap("GET", "/api/v1/dex/score-policy").requires_measurable);

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
// Compiled out under ThreadSanitizer (#438, the guard below), as in
// test_mcp_body_cap.cpp. The original reason was a crash of the TSan build in
// httplib's asynchronous name lookup; CI's TSan jobs now preload a synchronous
// getaddrinfo shim (scripts/ci/build-gai-sync-shim.sh, used by nightly.yml and
// sanitizer-tests.yml) that covers loopback servers, so the guard is a leftover
// until this section is re-enabled and run under TSan.
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
// two guards are out of this fixture's scope. The probe-branch call in server.cpp is
// pinned by the source-text wiring case in test_health_routes.cpp; the non-probe call
// site is pinned by neither file.
#ifndef YUZU_TSAN_BUILD

namespace {

constexpr std::uint64_t kUnifiedTestCap = 4u * 1024 * 1024; // matches the real default cap

struct UnifiedBodyCapTestServer {
    httplib::Server svr;
    // Declared right after `svr` so it is destroyed first; see post_read_stage_test_support.hpp.
    std::optional<yuzu::test::PostReadStageScope> stage_scope;
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
    // fixture's post-read stage below, admitted or refused. Used
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
        // body-cap-post-read-stage — GENUINELY WIRED into this fixture the
        // same way server.cpp wires it (issue #2898: earlier versions of
        // this fixture only reproduced the pre-routing decision with pure
        // functions, which meant a test against the fixture could never
        // observe a defect in server.cpp's real stage wiring): installed in
        // `PostReadStageRegistry` BEFORE any route, with the routes below
        // registered through an `HttplibRouteSink` that wraps each handler.
        // Real httplib::Server here means `req.body` is genuinely populated
        // by httplib's own `read_content` before this fires — including for
        // a real chunked-Transfer-Encoding request the pre-routing handler
        // admitted unmeasured, which is the whole point of this
        // stage.
        stage_scope.emplace(
            svr, [this](const httplib::Request& req,
                        httplib::Response& res) -> httplib::Server::HandlerResponse {
                post_read_calls.fetch_add(1);
                const auto cap_match = resolve_body_cap(req.method, req.path);
                if (req.body.size() <= cap_match.max_body_bytes) {
                    return httplib::Server::HandlerResponse::Unhandled;
                }
                post_read_rejections.fetch_add(1);
                res.status = 413;
                return httplib::Server::HandlerResponse::Handled;
            });
        yuzu::server::HttplibRouteSink sink{svr};

        sink.Get("/api/v1/devices", ok_handler);
        sink.Post("/api/v1/devices", ok_handler);
        sink.Get("/health", ok_handler);
        sink.Post("/health", ok_handler);
        sink.Post("/mcp/v1/", ok_handler);
        // Bodyless DELETE (MCP session teardown): a method other than POST/PUT/PATCH, so an
        // absent Content-Length is not itself "unmeasurable", which isolates the
        // Transfer-Encoding argument in the empty-first-line wire test below.
        sink.Delete("/mcp/v1/", ok_handler);
        // A small-cap (256 KiB), requires_measurable=false class — used by
        // the post-read-stage tests below so a genuine chunked over-cap body
        // stays cheap to send in a test.
        sink.Post("/api/v1/ca/import-chain", ok_handler);
        sink.Post("/api/v1/inventory/software/normalization/aliases", ok_handler);
        sink.Post("/api/v1/inventory/software/normalization/pack", ok_handler);

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
            // function shares the COMBINATION of predicates, so it need not be
            // re-verified by hand. The Content-Length, Transfer-Encoding and
            // Content-Encoding ARGUMENTS come from the same accessors
            // server.cpp uses (`content_length_for_body_cap`,
            // `transfer_encoding_for_body_cap`); a raw first-line
            // `get_header_value("Transfer-Encoding")` would miss an empty first
            // line followed by `chunked`. `is_chunked` still
            // MUST come from httplib's own chunked decision, `is_chunked_for_body_cap`
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
                req.method, req.path, yuzu::server::has_content_length_for_body_cap(req),
                content_length_for_body_cap(req), transfer_encoding_for_body_cap(req),
                content_encoding_for_body_cap(req),
                yuzu::server::is_chunked_for_body_cap(req));
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

TEST_CASE("Pre-routing body cap: the software curation routes refuse an oversized body "
          "pre-auth and admit an in-limit one",
          "[body_cap][bounds][integration]") {
    UnifiedBodyCapTestServer ts;
    ts.start();

    // Over-cap declared Content-Length (never sent): refused before any read.
    const auto over = [&](const char* path, std::size_t len) {
        return raw_request_status_line(
            ts.port, std::string("POST ") + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n" +
                         "Content-Length: " + std::to_string(len) + "\r\n\r\n");
    };
    CHECK(over("/api/v1/inventory/software/normalization/aliases", 64u * 1024 + 1)
              .starts_with("HTTP/1.1 413"));
    CHECK(over("/api/v1/inventory/software/normalization/pack", 1u * 1024 * 1024 + 1)
              .starts_with("HTTP/1.1 413"));
    CHECK(ts.handler_calls.load() == 0);

    // The pack route admits a body the alias class would refuse (the longer prefix wins).
    httplib::Client cli("127.0.0.1", ts.port);
    auto pack_big = cli.Post("/api/v1/inventory/software/normalization/pack",
                             std::string(64u * 1024 + 1, 'x'), "text/csv");
    REQUIRE(pack_big);
    CHECK(pack_big->status == 200);
    CHECK(ts.handler_calls.load() == 1);

    // In-limit bodies reach the handler on both routes.
    auto alias_ok = cli.Post("/api/v1/inventory/software/normalization/aliases",
                             std::string(64u * 1024, 'x'), "application/json");
    REQUIRE(alias_ok);
    CHECK(alias_ok->status == 200);
    CHECK(ts.handler_calls.load() == 2);
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
    // requires_measurable, including the probe paths,
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
        // httplib >= 0.43 rejects Content-Length > 0 together with ANY Transfer-Encoding with a 400
        // (RFC 9112 6.3) BEFORE the pre-routing gate runs, so the gate's own 413 is only reachable on
        // older httplib. Either way the request must be refused and the handler must never run; the
        // gate's authoritative-length logic is pinned directly by the pure tests above.
        CHECK((resp.starts_with("HTTP/1.1 413") || resp.starts_with("HTTP/1.1 400")));
    }
    CHECK(ts.handler_calls.load() == 0);

    // Content-Length: 0 with a non-chunked Transfer-Encoding: httplib 0.43 let it through to the gate
    // (the 400 applied to a non-zero length); httplib 0.59.0 answers 400 to ANY Transfer-Encoding
    // whose final coding is not chunked, whatever the Content-Length. Both are safe. The property
    // pinned here is that there is nothing to cap, so it is never answered 413, and that the
    // handler never runs for a request httplib considers mis-framed (asserted below for the 400).
    for (const auto* te : {"identity", "x"}) {
        const std::string req0 = std::string("POST /api/v1/ca/import-chain HTTP/1.1\r\n"
                                             "Host: 127.0.0.1\r\n"
                                             "Content-Length: 0\r\n"
                                             "Transfer-Encoding: ") +
                                 te + "\r\n\r\n";
        const auto resp0 = raw_request_status_line(ts.port, req0);
        INFO("Content-Length: 0 + Transfer-Encoding: " << te << " -> " << resp0);
        CHECK_FALSE(resp0.starts_with("HTTP/1.1 413"));
        CHECK(resp0.starts_with("HTTP/1.1 400"));
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
    // Content-Encoding header present"). An EXPLICIT `Content-Encoding: identity`
    // is asserted end-to-end in its own case further down, because the docs
    // promise it is admitted. Background: through 0.37.1 `detail::create_decompressor`
    // recognised only gzip/deflate/br/zstd and returned null for anything else
    // INCLUDING the literal string "identity", so httplib's own content-reader
    // 415'd an explicit `identity` value for any ordinary route's body read. From
    // 0.59.0 `prepare_content_receiver` leaves an unrecognised coding, "identity"
    // included, alone and passes the payload through (httplib.h v0.59.0:8489-8500).
    // `has_non_identity_content_encoding` never refused it at THIS (pre-routing)
    // chokepoint.
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

TEST_CASE("Pre-routing body cap: an empty first Transfer-Encoding line followed by chunked is "
          "refused 411 on a requires_measurable class",
          "[body_cap][mcp][bounds][integration]") {
    // `get_header_value("Transfer-Encoding")` reads the empty FIRST line, which reads as "no
    // Transfer-Encoding", while httplib reads the last line (chunked). DELETE is used because it
    // is a method (not POST/PUT/PATCH) whose absent Content-Length is not itself
    // unmeasurable, so the 411 can only come from the Transfer-Encoding argument
    // (`transfer_encoding_for_body_cap`) reaching `evaluate_body_cap`. The body is complete so a fixture that wrongly admits the request
    // answers promptly instead of waiting on the chunk reader.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string req = "DELETE /mcp/v1/ HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Transfer-Encoding:\r\n"
                            "Transfer-Encoding: chunked\r\n\r\n"
                            "0\r\n\r\n";
    const auto resp = raw_request_status_line(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 411"));
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: an empty first Content-Encoding line followed by an encoding is "
          "refused 415",
          "[body_cap][bounds][integration]") {
    // `get_header_value("Content-Encoding")` reads the empty FIRST line, which reads as "no
    // encoding", while httplib's body reader decodes against the combined value (`br`). The
    // gate must refuse on the value httplib acts on (`content_encoding_for_body_cap`), so a body
    // httplib would decode never reaches the reader or a handler.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string body = "garbage";
    const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Encoding:\r\n"
                            "Content-Encoding: br\r\n"
                            "Content-Length: " +
                            std::to_string(body.size()) + "\r\n\r\n" + body;
    const auto resp = raw_request_status_line(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 415"));
    // The gate answered (httplib without a brotli build would answer 415 itself).
    CHECK(ts.pre_routing_rejections.load() == 1);
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: an explicit Content-Encoding: identity is admitted",
          "[body_cap][bounds][integration]") {
    // The docs promise an explicit `identity` reaches the handler. It does so only while both
    // the gate (an exact, case-insensitive `identity`) and httplib's reader (an unrecognised
    // coding is passed through) agree, so a bump or a gate change that breaks either side fails
    // here instead of silently changing what clients may send.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string body = "small body";
    const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Encoding: identity\r\n"
                            "Content-Length: " +
                            std::to_string(body.size()) + "\r\n\r\n" + body;
    const auto resp = raw_request_status_line(ts.port, req);
    CHECK(resp.starts_with("HTTP/1.1 200"));
    CHECK(ts.pre_routing_rejections.load() == 0);
    CHECK(ts.handler_calls.load() == 1);
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
    // cap") — while httplib's own accessor returned `SIZE_MAX` for it (0.37.1:
    // `is_numeric()` + `strtoull()`), which is what it ALSO used to decide what it buffers. 0.59.0
    // flags the value invalid and answers 400 (`get_header_value_u64`, httplib.h v0.59.0:3480-3506).
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
        // httplib 0.59.0 treats an out-of-range Content-Length as invalid and answers 400 while
        // parsing the request head, before the pre-routing gate runs; older httplib saturates to
        // SIZE_MAX and the gate answers 413. Either refuses it before any body is read.
        CHECK((resp.starts_with("HTTP/1.1 413") || resp.starts_with("HTTP/1.1 400")));
    }
    CHECK(ts.handler_calls.load() == 0);
}

TEST_CASE("Pre-routing body cap: a malformed (non-numeric) Content-Length is never "
          "silently admitted — refused end-to-end even where this gate alone reads it "
          "as absent (#2407 R2)",
          "[body_cap][bounds][integration]") {
    // `is_numeric()` (httplib.h v0.59.0:3476-3478) requires EVERY character to be
    // an ASCII digit, so each of these fails it and
    // `content_length_for_body_cap` reads them as 0 — matching httplib's
    // OWN accessor exactly (that is the point of #2407 R1/R2: one shared
    // function, not two that might disagree). A 0 reading is NOT oversize,
    // so THIS gate alone lets the request past as Unhandled. That is fine,
    // not a re-opened gap: httplib's own body reader
    // (`detail::read_content`, httplib.h v0.59.0:8574-8579) independently rejects
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
    // Through 0.37.1 httplib's `Headers` was `std::unordered_multimap<...,
    // case_ignore::hash, case_ignore::equal_to>`, an UNORDERED container, so
    // WHICH of two duplicate `Content-Length` values
    // `get_header_value_u64("Content-Length", 0, /*id=*/0)` resolved to was
    // UNSPECIFIED by the C++ standard (measured then: the LAST header line
    // sent). From 0.59.0 `Headers` is an insertion-ordered multimap
    // (httplib.h v0.59.0:1084-1101, 1360-1362), so `id=0` is the FIRST line
    // sent. This test deliberately does NOT assert on which one wins, because
    // that is an implementation detail that could shift with a future vcpkg
    // bump, not a contract. What it asserts instead is the SAFETY property that
    // holds regardless of which duplicate value httplib prefers: `content_length_for_body_cap` (this gate) and httplib's own
    // body reader (httplib.h v0.59.0:8574-8576) call the IDENTICAL accessor with
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
    // Whichever duplicate value httplib's reader resolves as
    // id=0: either it is the oversize one — refused here, 413, handler
    // never runs — or it is the small one — admitted, and httplib's ACTUAL
    // body read is then bounded to those `small_body.size()` bytes we
    // genuinely sent, so the handler runs normally, 200. Anything else
    // (a hang waiting on unsent bytes, a mid-read reset, a status neither
    // of these) would mean the gate and the real reader disagreed about
    // which duplicate to trust — the split-brain this test exists to rule
    // out.
    // httplib >= 0.43 (RFC 9110 8.6) rejects DIFFERING duplicate Content-Length values with a 400
    // before the gate runs; older httplib resolves one of them and reaches the gate. Both are safe:
    // the property is that nothing is buffered past the cap and the handler never sees a body the
    // gate did not vet.
    const bool refused = resp.starts_with("HTTP/1.1 413") || resp.starts_with("HTTP/1.1 400");
    const bool admitted = resp.starts_with("HTTP/1.1 200");
    INFO("response: " << resp);
    CHECK((refused || admitted));
    CHECK(ts.handler_calls.load() == (admitted ? 1 : 0));

    // IDENTICAL duplicates are not rejected by httplib, so they still reach the gate and keep
    // exercising the original same-accessor property: the oversize value must be refused by the
    // gate (413), the small one admitted. The oversize value is deliberately a parseable u64:
    // httplib 0.59.0 answers 400 to an out-of-range one before the gate (pinned by the test above).
    {
        const std::string big = "POST /api/v1/devices HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: 99999999999\r\n"
                                "Content-Length: 99999999999\r\n\r\n";
        const auto rbig = raw_request_status_line(ts.port, big);
        INFO("identical oversize duplicates -> " << rbig);
        CHECK(rbig.starts_with("HTTP/1.1 413"));
    }
    {
        const std::string ok = "POST /api/v1/devices HTTP/1.1\r\n"
                               "Host: 127.0.0.1\r\n"
                               "Content-Type: application/json\r\n"
                               "Content-Length: 2\r\n"
                               "Content-Length: 2\r\n\r\nok";
        const auto rok = raw_request_status_line(ts.port, ok);
        INFO("identical small duplicates -> " << rok);
        CHECK(rok.starts_with("HTTP/1.1 200"));
    }
}
#endif // !_WIN32

// ── 9. Post-read body cap, second stage (body-cap-post-read-stage) ────────
//
// GENUINELY WIRED into `UnifiedBodyCapTestServer` (see that fixture's
// post-read stage above) — issue #2898 is the reason this needed
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

TEST_CASE("Pre-routing body cap: a pre-routing refusal closes the connection while the declared "
          "body is still unsent",
          "[body_cap][pre_routing][bounds][integration]") {
    // The real gate (`evaluate_body_cap`, through the fixture) refuses a declared 64 MiB body on
    // a route whose cap is 4 MiB. The probe sends the head and five body bytes and no more, with
    // no `Expect` header (an `httplib::Client` would send `Expect: 100-continue` for a body this
    // size and so never send it). A response head can therefore only arrive if the answer comes
    // before the body is read; the 413 must carry `Connection: close` and the socket must reach
    // EOF.
    UnifiedBodyCapTestServer ts;
    ts.start();

    const std::string req = "POST /api/v1/devices HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Content-Type: application/octet-stream\r\n"
                            "Content-Length: 67108864\r\n\r\nhello";
    const auto r = yuzu::test::probe_for_close(ts.port, req);
    INFO(r.head);
    CHECK(r.head.starts_with("HTTP/1.1 413"));
    CHECK(r.head.find("Connection: close") != std::string::npos);
    CHECK(r.closed);
    CHECK(ts.pre_routing_rejections.load() == 1);
    CHECK(ts.handler_calls.load() == 0);
}

namespace {

/// A server whose ONLY handler is a pre-routing one answering a fixed status, with the SAME
/// `close_if_unread_framed_body` helper server.cpp's post-routing handler calls on every response
/// (the wiring is pinned lexically in test_step_up_wiring.cpp; this fixture reproduces no rule of
/// its own).
struct PreRoutingAnswerServer {
    explicit PreRoutingAnswerServer(int status) {
        // 30 s read timeout, as production: a body that is still being read is then unambiguous
        // against the probe's wait (5 s by default).
        svr.set_read_timeout(30, 0);
        svr.set_pre_routing_handler(
            [status](const httplib::Request&, httplib::Response& res)
                -> httplib::Server::HandlerResponse {
                res.status = status;
                res.set_content("x", "text/plain");
                if (status >= 300 && status < 400)
                    res.set_header("Location", "/home");
                return httplib::Server::HandlerResponse::Handled;
            });
        svr.set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
            yuzu::server::close_if_unread_framed_body(req, res);
        });
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        th = std::thread([this] { svr.listen_after_bind(); });
        svr.wait_until_ready();
    }
    ~PreRoutingAnswerServer() {
        svr.stop();
        if (th.joinable())
            th.join();
    }
    PreRoutingAnswerServer(const PreRoutingAnswerServer&) = delete;
    PreRoutingAnswerServer& operator=(const PreRoutingAnswerServer&) = delete;

    httplib::Server svr;
    int port = 0;
    std::thread th;
};

} // namespace

TEST_CASE("Pre-routing answer: a response to a request with an unread framed body closes the "
          "connection",
          "[body_cap][pre_routing][bounds][integration]") {
    // From httplib 0.59 a response below 400 that leaves a declared request body unread must carry
    // `Connection: close`. The probe waits for EOF rather than reading the header alone: the header
    // is what we set, EOF is what the SERVER did with it. The 302 and 200 rows pin the close rule;
    // the 413 and 400 rows pin that a refusal is answered and closed too (httplib stamps close
    // itself for a status >= 400). The third framing is an empty Transfer-Encoding line followed by
    // `chunked`: `get_header_value` sees no Transfer-Encoding, httplib reads the body as chunked.
    for (const int status : {302, 200, 413, 400}) {
        for (const auto& [name, request] :
             {std::pair<const char*, std::string>{"chunked", yuzu::test::kChunkedPostRequest},
              std::pair<const char*, std::string>{"content-length 64 MiB declared",
                                                  yuzu::test::kLengthPostRequest},
              std::pair<const char*, std::string>{"empty then chunked Transfer-Encoding lines",
                                                  yuzu::test::kEmptyThenChunkedPostRequest}}) {
            DYNAMIC_SECTION("status " << status << ", " << name) {
                PreRoutingAnswerServer ts(status);
                const auto r = yuzu::test::probe_for_close(ts.port, request);
                INFO(r.head);
                CHECK(r.head.find("Connection: close") != std::string::npos);
                CHECK(r.closed);
            }
        }
    }
}

TEST_CASE("Pre-routing answer: a bodyless request keeps its keep-alive connection",
          "[body_cap][pre_routing][integration]") {
    // The close rule is for a declared, unread body only: an ordinary GET answered from the
    // pre-routing handler (the sign-in redirect of a bookmarked page) must not lose keep-alive.
    PreRoutingAnswerServer ts(302);
    const auto r = yuzu::test::probe_for_close(
        ts.port, "GET /home HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", std::chrono::seconds(2));
    INFO(r.head);
    CHECK(r.head.find("Connection: close") == std::string::npos);
    CHECK_FALSE(r.closed);
}

#endif // !_WIN32

#endif // !YUZU_TSAN_BUILD

TEST_CASE("close_if_unread_framed_body: decides on status and declared framing",
          "[body_cap][pre_routing]") {
    // Pure logic: no sockets, so it runs on every platform and under TSan.
    httplib::Request chunked;
    chunked.headers.emplace("Transfer-Encoding", "chunked");
    httplib::Request sized;
    sized.headers.emplace("Content-Length", "10");
    httplib::Request zero;
    zero.headers.emplace("Content-Length", "0");
    httplib::Request bare;
    httplib::Request overflow;
    overflow.headers.emplace("Content-Length", "99999999999999999999999");
    // First line empty, last line chunked: get_header_value reads the empty first line.
    httplib::Request empty_then_chunked;
    empty_then_chunked.headers.emplace("Transfer-Encoding", "");
    empty_then_chunked.headers.emplace("Transfer-Encoding", "chunked");

    const auto closes = [](const httplib::Request& req, int status) {
        httplib::Response res;
        res.status = status;
        yuzu::server::close_if_unread_framed_body(req, res);
        return res.get_header_value("Connection") == "close";
    };
    CHECK(closes(chunked, 302));
    CHECK(closes(sized, 200));
    CHECK(closes(overflow, 302)); // out-of-range reads as SIZE_MAX, which is a declared body
    CHECK(closes(empty_then_chunked, 302));
    CHECK_FALSE(closes(zero, 302));
    CHECK_FALSE(closes(bare, 302));
    // 400 and above: httplib closes itself, the helper adds nothing.
    CHECK_FALSE(closes(chunked, 413));
    CHECK_FALSE(closes(sized, 400));
    // A body a handler already read leaves nothing to drain: keep-alive is untouched.
    httplib::Request consumed = sized;
    consumed.body_consumed_ = true;
    CHECK_FALSE(closes(consumed, 200));
}

TEST_CASE("content_encoding_for_body_cap: reads the combined value httplib decodes against",
          "[body_cap]") {
    httplib::Request none;
    httplib::Request plain;
    plain.headers.emplace("Content-Encoding", "br");
    httplib::Request empty_then_br;
    empty_then_br.headers.emplace("Content-Encoding", "");
    empty_then_br.headers.emplace("Content-Encoding", "br");
    httplib::Request identity_then_br;
    identity_then_br.headers.emplace("Content-Encoding", "identity");
    identity_then_br.headers.emplace("Content-Encoding", "br");
    httplib::Request empty_only;
    empty_only.headers.emplace("Content-Encoding", "");
    CHECK(content_encoding_for_body_cap(none).empty());
    CHECK(content_encoding_for_body_cap(empty_only).empty());
    CHECK(content_encoding_for_body_cap(plain) == "br");
    // The raw first-line read this accessor replaces sees nothing here.
    CHECK(empty_then_br.get_header_value("Content-Encoding").empty());
    CHECK(content_encoding_for_body_cap(empty_then_br) == "br");
    CHECK(yuzu::server::has_non_identity_content_encoding(
        content_encoding_for_body_cap(empty_then_br)));
    // A list that is not exactly one coding is refused by the gate (httplib does not decode it).
    CHECK(content_encoding_for_body_cap(identity_then_br) == "identity, br");
    CHECK(yuzu::server::has_non_identity_content_encoding(
        content_encoding_for_body_cap(identity_then_br)));
}

TEST_CASE("transfer_encoding_for_body_cap: an empty first line still reads as present",
          "[body_cap]") {
    httplib::Request none;
    httplib::Request plain;
    plain.headers.emplace("Transfer-Encoding", "chunked");
    httplib::Request empty_then_chunked;
    empty_then_chunked.headers.emplace("Transfer-Encoding", "");
    empty_then_chunked.headers.emplace("Transfer-Encoding", "chunked");
    CHECK(yuzu::server::transfer_encoding_for_body_cap(none).empty());
    CHECK(yuzu::server::transfer_encoding_for_body_cap(plain) == "chunked");
    // body_unmeasurable refuses any non-empty value, so the marker must not be empty.
    CHECK_FALSE(yuzu::server::transfer_encoding_for_body_cap(empty_then_chunked).empty());
    CHECK(yuzu::server::body_unmeasurable(
        "POST", /*has_content_length=*/true,
        yuzu::server::transfer_encoding_for_body_cap(empty_then_chunked)));
}

// ── httplib's pre-request handler runs before the body is read (cpp-httplib >= 0.47) ─────────────
//
// The post-read body cap and the step-up check measure `req.body`, so they must run AFTER httplib
// has read it: they are installed through `PostReadStageRegistry` and the route sink, never as
// `set_pre_request_handler`. The cases in this section keep that true when the baseline moves or
// when the route-sink wrapper change is reverted on its own. The scan LOGIC below shares nothing
// with the wrapper change's own wiring tests, but this file as a whole needs that change
// (`post_read_stage_test_support.hpp`, `PostReadStageRegistry`), so it is the source scan that
// carries the pin, not the file's independence.

namespace {

/// `{major, minor}` of the httplib this build links, from `CPPHTTPLIB_VERSION` ("0.59.0").
/// A malformed string fails the test loudly instead of reading as an old version.
std::pair<int, int> httplib_major_minor() {
    const std::string_view v = CPPHTTPLIB_VERSION;
    const auto dot1 = v.find('.');
    REQUIRE(dot1 != std::string_view::npos);
    const auto dot2 = v.find('.', dot1 + 1);
    REQUIRE(dot2 != std::string_view::npos);
    int major = -1;
    int minor = -1;
    const auto r1 = std::from_chars(v.data(), v.data() + dot1, major);
    const auto r2 = std::from_chars(v.data() + dot1 + 1, v.data() + dot2, minor);
    INFO("CPPHTTPLIB_VERSION = " << v);
    REQUIRE(r1.ec == std::errc{});
    REQUIRE(r1.ptr == v.data() + dot1);
    REQUIRE(r2.ec == std::errc{});
    REQUIRE(r2.ptr == v.data() + dot2);
    REQUIRE(major >= 0);
    REQUIRE(minor >= 0);
    return {major, minor};
}

bool httplib_reads_body_after_pre_request_handler() {
    const auto [major, minor] = httplib_major_minor();
    return major > 0 || minor >= 47;
}

/// `in` with comments and string, raw-string and character literals blanked, so a mention in a
/// comment or a string cannot count as code. False in `clean` when a comment or literal is left
/// open. Minimal on purpose: it is enough for the identifier scan below.
struct CodeOnly {
    std::string text;
    bool clean = true;
};

CodeOnly code_only(const std::string& in) {
    CodeOnly r;
    const auto n = in.size();
    const auto is_ident = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_';
    };
    for (std::size_t i = 0; i < n;) {
        const char c = in[i];
        if (c == '/' && i + 1 < n && in[i + 1] == '/') {
            while (i < n && in[i] != '\n')
                ++i;
        } else if (c == '/' && i + 1 < n && in[i + 1] == '*') {
            const auto end = in.find("*/", i + 2);
            if (end == std::string::npos) {
                r.clean = false;
                break;
            }
            r.text += ' ';
            i = end + 2;
        } else if (c == '"' || c == '\'') {
            // A quote right after an identifier character that is not an encoding prefix is a
            // digit separator (120'000), not a literal.
            auto b = i;
            while (b > 0 && is_ident(in[b - 1]))
                --b;
            const auto id = in.substr(b, i - b);
            if (c == '\'' && !id.empty() && id != "L" && id != "u" && id != "U" && id != "u8") {
                r.text += c;
                ++i;
            } else if (c == '"' &&
                       (id == "R" || id == "u8R" || id == "uR" || id == "UR" || id == "LR")) {
                const auto open = in.find('(', i + 1);
                if (open == std::string::npos || open - (i + 1) > 16) {
                    r.clean = false;
                    break;
                }
                const std::string close = ")" + in.substr(i + 1, open - (i + 1)) + "\"";
                const auto end = in.find(close, open + 1);
                if (end == std::string::npos) {
                    r.clean = false;
                    break;
                }
                r.text += "\"\"";
                i = end + close.size();
            } else {
                ++i;
                while (i < n && in[i] != c) {
                    if (in[i] == '\\')
                        ++i;
                    ++i;
                }
                if (i >= n) {
                    r.clean = false;
                    break;
                }
                r.text += c;
                r.text += c;
                ++i;
            }
        } else {
            r.text += c;
            ++i;
        }
    }
    return r;
}

/// Occurrences of `name` as a whole identifier in the code-only text.
std::size_t count_identifier(const std::string& text, std::string_view name) {
    const auto is_ident = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_';
    };
    std::size_t n = 0;
    for (auto at = text.find(name); at != std::string::npos; at = text.find(name, at + 1)) {
        const bool left = at == 0 || !is_ident(text[at - 1]);
        const auto end = at + name.size();
        const bool right = end >= text.size() || !is_ident(text[end]);
        if (left && right)
            ++n;
    }
    return n;
}

/// How many times the bare token `set_pre_request_handler` appears as code in `text`: any use
/// (`->`, `.`, `::`, a member pointer, a call through an alias) counts, not only a call.
std::size_t pre_request_handler_uses(const std::string& text) {
    return count_identifier(text, "set_pre_request_handler");
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    INFO("reading " << path.string());
    REQUIRE(in.good());
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

struct SrcFile {
    std::string name; ///< path relative to the server source directory, '/' separated
    std::string text; ///< comment- and literal-stripped text
};

/// Every `.cpp`, `.hpp`, `.h`, `.inc` and `.ipp` file under the server source directory and the
/// public server header directory (`server/core/include/yuzu/server`, named with an `include/`
/// prefix), stripped of comments and literals, loaded once. A file whose comments or literals do
/// not balance fails the test loudly: it would otherwise hide code from every scan below. Test
/// sources are not under either directory, so the negative-control strings in tests are never
/// scanned.
const std::vector<SrcFile>& server_src_corpus() {
    static const std::vector<SrcFile> corpus = [] {
        std::vector<SrcFile> out;
        const std::filesystem::path src_root(YUZU_SERVER_SRC_DIR);
        const auto include_root = src_root / ".." / "include" / "yuzu" / "server";
        const std::pair<std::filesystem::path, std::string> roots[] = {{src_root, ""},
                                                                       {include_root, "include/"}};
        for (const auto& [root, prefix] : roots) {
            INFO("scanning " << root.string());
            REQUIRE(std::filesystem::is_directory(root));
            for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                if (!entry.is_regular_file())
                    continue;
                const auto ext = entry.path().extension().string();
                if (ext != ".cpp" && ext != ".hpp" && ext != ".h" && ext != ".inc" &&
                    ext != ".ipp")
                    continue;
                auto stripped = code_only(read_text_file(entry.path()));
                INFO("stripping " << entry.path().string());
                REQUIRE(stripped.clean);
                out.push_back(
                    {prefix + std::filesystem::relative(entry.path(), root).generic_string(),
                     std::move(stripped.text)});
            }
        }
        return out;
    }();
    return corpus;
}

const SrcFile& server_src_file(std::string_view name) {
    for (const auto& f : server_src_corpus())
        if (f.name == name)
            return f;
    FAIL("server source file not found in the corpus: " << name);
    std::abort();
}

/// Calls of `name` (an identifier followed by optional whitespace and `(`) in code-only text.
std::size_t count_calls(const std::string& text, std::string_view name) {
    std::size_t n = 0;
    for (auto at = text.find(name); at != std::string::npos; at = text.find(name, at + 1)) {
        const auto is_ident = [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   c == '_';
        };
        if (at > 0 && is_ident(text[at - 1]))
            continue;
        const auto next = text.find_first_not_of(" \t\r\n", at + name.size());
        if (next != std::string::npos && text[next] == '(')
            ++n;
    }
    return n;
}

std::string without_space(std::string s) {
    std::erase_if(s, [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; });
    return s;
}

} // namespace

TEST_CASE("httplib pre-request handler: it runs before the request body is read from 0.47 on",
          "[body_cap][httplib_version][integration]") {
    // A real socket and a POST that carries a body. On 0.47 and later the pre-request handler
    // sees an empty `req.body` (the body is read after it); on an earlier httplib it sees the
    // body. The route handler sees the body either way. If this case changes its answer on a
    // later httplib, the placement of the post-read stage must be re-examined.
    httplib::Server svr;
    std::atomic<std::size_t> pre_request_body_size{9999};
    std::atomic<std::size_t> handler_body_size{9999};
    svr.set_pre_request_handler(
        [&](const httplib::Request& req, httplib::Response&) -> httplib::Server::HandlerResponse {
            pre_request_body_size.store(req.body.size());
            return httplib::Server::HandlerResponse::Unhandled;
        });
    svr.Post("/probe", [&](const httplib::Request& req, httplib::Response& res) {
        handler_body_size.store(req.body.size());
        res.set_content("ok", "text/plain");
    });
    const int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&]() { svr.listen_after_bind(); });
    // Stops and joins on every exit, including a failed REQUIRE below: a joinable std::thread
    // destroyed during unwinding would terminate the whole test binary. The wait sits inside the
    // joinable() test because stop() is a no-op until the accept loop is running.
    yuzu::test::ScopeExit joiner{[&] {
        if (server_thread.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            server_thread.join();
        }
    }};
    svr.wait_until_ready();

    const std::string body(2048, 'x');
    httplib::Client cli("127.0.0.1", port);
    cli.set_read_timeout(10, 0);
    const auto r = cli.Post("/probe", body, "application/octet-stream");

    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(handler_body_size.load() == body.size());
    INFO("httplib " << CPPHTTPLIB_VERSION);
    if (httplib_reads_body_after_pre_request_handler())
        CHECK(pre_request_body_size.load() == 0);
    else
        CHECK(pre_request_body_size.load() == body.size());
}

TEST_CASE("no server source file uses httplib's pre-request handler on a baseline that reads "
          "the body after it",
          "[body_cap][httplib_version][lexical]") {
    // A source-text pin, over comment- and literal-stripped text of EVERY file under the server
    // source and public header directories, that does not depend on the route-sink wrapper
    // change's own tests: the bare token `set_pre_request_handler` must not appear as code
    // anywhere, in any form. If that wrapper change were reverted on its own on this baseline,
    // server.cpp would again install the stage that way, which runs before the body is read,
    // and the post-read body cap and the step-up check would see an empty body. (There is no
    // allowlist: the one deliberate use of the handler in this repository is in a test, outside
    // the scanned directories.)
    if (!httplib_reads_body_after_pre_request_handler()) {
        SUCCEED("this httplib reads the body before its pre-request handler");
        return;
    }
    const auto& corpus = server_src_corpus();
    REQUIRE(corpus.size() > 100);
    // Both directories are really in the corpus (a path that stopped resolving would shrink it).
    CHECK(std::any_of(corpus.begin(), corpus.end(),
                      [](const SrcFile& f) { return f.name.starts_with("include/"); }));
    std::string offenders;
    for (const auto& f : corpus)
        if (pre_request_handler_uses(f.text) != 0)
            offenders += f.name + " ";
    INFO("files using set_pre_request_handler: " << offenders);
    CHECK(offenders.empty());
    // The stage still goes in through the registry.
    CHECK(server_src_file("server.cpp").text.find("PostReadStageRegistry::instance().install(") !=
          std::string::npos);
}

TEST_CASE("the body-cap decision and the close rule have exactly one production caller each",
          "[body_cap][lexical]") {
    // Over the whole server source and public header directories: a second `evaluate_body_cap(`
    // call site (one that could read the headers raw) or a second `close_if_unread_framed_body(`
    // call site would be a second copy of a rule that has one home. The defining headers are
    // excluded by name.
    std::string eval_sites;
    std::string close_sites;
    std::size_t eval_calls = 0;
    std::size_t close_calls = 0;
    for (const auto& f : server_src_corpus()) {
        if (f.name != "body_cap_policy.hpp") {
            if (const auto n = count_calls(f.text, "evaluate_body_cap")) {
                eval_calls += n;
                eval_sites += f.name + " ";
            }
        }
        if (f.name != "body_cap_httplib.hpp") {
            if (const auto n = count_calls(f.text, "close_if_unread_framed_body")) {
                close_calls += n;
                close_sites += f.name + " ";
            }
        }
    }
    INFO("evaluate_body_cap call sites: " << eval_sites);
    INFO("close_if_unread_framed_body call sites: " << close_sites);
    CHECK(eval_calls == 1);
    CHECK(eval_sites == "server.cpp ");
    CHECK(close_calls == 1);
    CHECK(close_sites == "server.cpp ");
}

TEST_CASE("body_cap_httplib.hpp: the accessors stay thin wrappers over httplib's own rules",
          "[body_cap][lexical]") {
    // The accessors exist so the gate and httplib read the same bytes the same way. Pinned
    // whole, whitespace aside, over the stripped text: a body replaced by another predicate, or by
    // a constant, fails here.
    const auto flat = without_space(server_src_file("body_cap_httplib.hpp").text);
    CHECK(flat.find("inlineboolis_chunked_for_body_cap(consthttplib::Request&req){"
                    "returnhttplib::detail::is_chunked_transfer_encoding(req.headers);}") !=
          std::string::npos);
    CHECK(flat.find("inlineboolhas_content_length_for_body_cap(consthttplib::Request&req){"
                    "constautocl_range=req.headers.equal_range(\"\");"
                    "returncl_range.first!=cl_range.second;}") != std::string::npos);
    CHECK(flat.find("inlinestd::stringcontent_encoding_for_body_cap(consthttplib::Request&req){"
                    "returnhttplib::detail::get_combined_header_value(req.headers,\"\");}") !=
          std::string::npos);
    // Literals are blanked in the stripped text, so the header NAME is pinned on the raw file.
    const auto raw =
        read_text_file(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "body_cap_httplib.hpp");
    std::size_t names = 0;
    for (auto at = raw.find("req.headers.equal_range(\"Content-Length\")"); at != std::string::npos;
         at = raw.find("req.headers.equal_range(\"Content-Length\")", at + 1))
        ++names;
    CHECK(names == 1);
    CHECK(raw.find("get_combined_header_value(req.headers, \"Content-Encoding\")") !=
          std::string::npos);
}

TEST_CASE("pre-request handler scan: negative controls", "[body_cap][httplib_version][lexical]") {
    // The scan above must see every form of use, and must not see a mention.
    const auto uses = [](const std::string& src) {
        const auto s = code_only(src);
        REQUIRE(s.clean);
        return pre_request_handler_uses(s.text);
    };
    CHECK(uses("svr->set_pre_request_handler(f);") == 1);
    CHECK(uses("svr.set_pre_request_handler(f);") == 1);
    CHECK(uses("httplib::Server::set_pre_request_handler;") == 1);
    CHECK(uses("auto p = &httplib::Server::set_pre_request_handler;") == 1);
    CHECK(uses("x\n  ->\n  set_pre_request_handler\n  (f);") == 1);
    CHECK(uses("// svr->set_pre_request_handler(f);\n") == 0);
    CHECK(uses("/* set_pre_request_handler */ int a;") == 0);
    CHECK(uses("const char* s = \"set_pre_request_handler\";") == 0);
    CHECK(uses("auto s = R\"x(set_pre_request_handler)x\";") == 0);
    CHECK(uses("my_set_pre_request_handler(f); set_pre_request_handler_2(f);") == 0);
    CHECK_FALSE(code_only("int a; /* open").clean);
}
