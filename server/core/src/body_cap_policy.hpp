#pragma once

#include "web_utils.hpp" // body_unmeasurable / has_non_identity_content_encoding /
                          // content_length_is_authoritative — evaluate_body_cap composes
                          // these with resolve_body_cap below (#2898).

#include <cstddef>
#include <cstdint>
#include <string_view>

/// @file body_cap_policy.hpp
/// The ONE table deciding the pre-auth request-body byte cap per route class
/// (#2407).
///
/// THE DEFECT: an unauthenticated caller can make the server buffer up to
/// httplib's 100 MiB default (`CPPHTTPLIB_PAYLOAD_MAX_LENGTH`, httplib.h:130)
/// on every route except `/mcp/`, which `server.cpp`'s pre-routing handler
/// already caps at 4 MiB (#2437, `mcp_body_exceeds_cap`/`mcp_body_unmeasurable`
/// in `web_utils.hpp`). This header generalizes that per-path cap into one
/// table so every other route family gets a bound sized to what it actually
/// needs, instead of either httplib's 100 MiB backstop everywhere (too loose)
/// or one global 4 MiB cap (too tight — it would break the ~70 MiB live-query
/// bundle route outright).
///
/// THE RULE, stated once: the cap is enforced in `server.cpp`'s pre-routing
/// handler, the SAME chokepoint the existing `/mcp/` cap already runs from —
/// NEVER inside a route handler. httplib invokes the pre-routing handler
/// BEFORE it reads the request body (httplib.h: `routing()` calls the
/// pre-routing handler, then `read_content()`, in that order), so a rejection
/// returned from there costs a header parse and never buffers the oversized
/// payload. Enforcing the same bound inside a handler is too late — by the
/// time a handler runs, httplib has already buffered the body up to its own
/// 100 MiB backstop. This header is deliberately NOT a
/// `Server::set_payload_max_length` call: that knob is server-global and
/// would also squeeze the certificate-chain upload and content-distribution
/// staging on the same httplib instance — the issue text proposes it and it
/// is deliberately rejected here.
///
/// EXTEND this table, never fork it — a second cap list is exactly the kind
/// of drift `authz_topology_floor.hpp` and `dispatch_confined_arms.hpp` exist
/// to prevent for their own chokepoints.
///
/// MATCHING: the key is `{method, segment-boundary path prefix}`, NOT path
/// alone. Path-only matching is insufficient — the real route table carries
/// method-specific AND regex registrations on the very same literal prefix
/// (e.g. `rest_api_v1.cpp:7759`'s `POST /api/v1/guaranteed-state/rules` vs
/// `:7904`'s regex `PUT /api/v1/guaranteed-state/rules/{id}`), so a
/// path-only cap could not tell a bulk-create request from a single-rule
/// update even if they warranted different bounds. Matching is on SEGMENT
/// BOUNDARIES: `/api/v1/bundlesevil` must NOT match the `/api/v1/bundles`
/// entry (`body_cap_prefix_matches` requires the byte immediately after the
/// prefix to be `/`, or the prefix to already end in `/`, or an exact-length
/// match). Longest match wins, so a narrow, more specific entry (e.g.
/// `/scim/v2/`) always beats the always-matching catch-all default. There is
/// an explicit catch-all default entry (empty prefix, matches every method)
/// so `resolve_body_cap` never has "no answer" for an unlisted route.
///
/// `requires_measurable` decides whether a body this server cannot size in
/// advance — chunked `Transfer-Encoding`, or POST/PUT/PATCH with no
/// `Content-Length` — is REFUSED outright rather than admitted up to the
/// cap. Chunked request bodies are legal HTTP, and this repo does not
/// control every client that will ever talk to these routes, so the bit
/// DEFAULTS OFF and is opted into per class, not per table. It is ON only
/// for `/mcp/`: that surface's own protocol/client contract already requires
/// `Content-Length` on every framed body (see `web_utils.hpp:577`'s
/// `mcp_body_unmeasurable` rationale), so refusing an unmeasurable MCP body
/// costs a conforming client nothing. Every other class below — public REST
/// (bundles), SCIM, certificate import (REST + dashboard), the plugin trust
/// bundle, product-pack/workflow authoring, and the OTA upload — keeps it
/// OFF and falls back to httplib's 100 MiB backstop for a body it cannot
/// size, until a Content-Length contract is documented and a representative
/// client population is tested against it. That is a scoping decision for
/// THIS change, not a claim those routes are safe unmeasured forever.
///
/// KNOWN LIMITATION, recorded deliberately, not implied away: because of the
/// default above, a chunked or Content-Length-less body is NOT refused BEFORE
/// BEING READ on any class but `/mcp/` — this table's pre-routing chokepoint
/// admits it, up to httplib's own 100 MiB backstop, without checking this
/// table's cap at all. A comment or doc that says chunked bodies are
/// "refused" without naming `/mcp/` as the sole PRE-READ exception is wrong.
/// This is a recorded adjudication, not an oversight — see the paragraph
/// above for why — kept in sync with `docs/user-manual/rest-api.md` "Pre-Auth
/// Request Body Caps".
///
/// That gap is narrower than it once was: `server.cpp`'s `set_pre_request_
/// handler` (body-cap-post-read-stage) is a SECOND chokepoint, driven by the
/// SAME `resolve_body_cap` table, that runs after httplib has read the body
/// into `req.body` but before the route handler runs — so a chunked body
/// that turns out to be over this table's cap is still refused, just after
/// being buffered rather than before. It closes "reaches a handler
/// uncapped", not "gets buffered uncapped" — see that handler's own doc
/// comment for what it does and does not cover (notably: it cannot see a
/// multipart request's body at all, since httplib never copies multipart
/// content into `req.body`).
///
///
/// ROUTED-CONCERN ROW: `.claude/routed-concerns-access-control.md`, which
/// routes any change to this table or to `server.cpp`'s pre-routing cap
/// branch to `security-guardian` + `architect` + `cpp-safety`. That routing
/// is the row's ONLY job and nothing else performs it — this header, the
/// user docs and the tests all DESCRIBE the invariants, but none of them
/// puts a reviewer in front of a future change. Keep the row and this header
/// in step; if they ever disagree, the row governs, because it is what a
/// reviewer is actually handed.
///
/// (The row lives in the access-control file rather than the main table
/// because `.claude/routed-concerns.md` hit CLAUDE.md's 40k-character
/// ceiling and was split along that axis to make room — the same ceiling
/// that once split the table out of CLAUDE.md itself. This chokepoint sits
/// beside `authz_topology_floor` and `dispatch_target_shape` there, which is
/// where it belongs: same family, same failure mode.)
///
/// The numbers below are grounded in the cited call sites, not invented —
/// but "grounded" is not "measured byte-for-byte": two different kinds of
/// reasoning appear beside the exact matches, and BOTH are reasoned rather
/// than measured. (1) MEASURED-PLUS-MARGIN (`ca_import_chain_dashboard`,
/// `plugin_trust_bundle`, `tar_dashboard_sql`, `tar_result_set_sql`,
/// `instruction_yaml`): a real handler-level check exists and is cited, but
/// the pre-routing gate checks the RAW body while the handler checks a
/// DECODED/PARSED value (form-decoded, JSON-unescaped, or multipart-
/// extracted), so the cap adds an explicit margin over the handler's own
/// number instead of mirroring it — getting this wrong rejects legitimate
/// traffic, which is exactly what happened to the two TAR entries before
/// this fix (see their comments). (2) JUDGMENT CALL, NO CONTRACT
/// (`guardian_rule_authoring`, `workflow_yaml`, `product_pack_yaml`,
/// `instruction_import`, `nvd_match`): no aggregate size contract is defined
/// anywhere in the codebase for what these accept — arbitrary YAML/legacy
/// `yaml_source` bodies for the first three, an unbounded `responseTemplates`
/// array for `instruction_import`, an unbounded software-inventory array for
/// `nvd_match` — so each cap is an explicit, ADMITTEDLY-JUDGMENT-CALL bound
/// reasoned against that class's OWN realistic scale (not copy-pasted from a
/// sibling), rather than a squeeze. That is TEN of the table's entries
/// reasoned rather than exactly measured — do not tighten any of them
/// without a real contract to measure against, and do not read their
/// presence as license to guess a number for any OTHER class; every other
/// entry below mirrors a cited, decoded-equals-raw byte count exactly. A
/// THIRD, distinct category — `ota_upload` and `json_to_csv_export` — is
/// pinned at httplib's own 100 MiB backstop rather than squeezed OR given a
/// judgment-call MiB number: both carry content whose legitimate size is a
/// direct function of something this table cannot bound (an installer
/// binary's real size; an export's size following directly from the
/// operator's own prior query), so there is no smaller number to reason
/// toward — the entry's only job is making that an explicit, reviewed
/// decision instead of an accidental fallthrough to the catch-all.
namespace yuzu::server {

/// Sentinel method value meaning "matches every HTTP method". Used ONLY
/// where the cap genuinely does not depend on method — today that is
/// `/mcp/` (server.cpp's existing #2437 gate scopes it by path alone across
/// GET SSE, POST JSON-RPC, and DELETE session teardown) and the catch-all
/// default.
inline constexpr std::string_view kBodyCapAnyMethod = "*";

/// One `{method, path-prefix}` -> `{cap, requires_measurable, metric label}`
/// row.
struct BodyCapEntry {
    /// Exact HTTP method (e.g. "POST"), or `kBodyCapAnyMethod`.
    std::string_view method;
    /// Segment-boundary path prefix — see `body_cap_prefix_matches`.
    std::string_view path_prefix;
    /// The enforced cap, in bytes. Never zero (locked by test).
    std::size_t max_body_bytes;
    /// Refuse a chunked / Content-Length-less body for this class instead of
    /// admitting it up to the cap. Defaults OFF per-class; see file header.
    bool requires_measurable;
    /// Stable short label for a metric dimension. MUST be a fixed string
    /// literal from this table — NEVER derived from the raw, attacker-
    /// controlled request path (unbounded cardinality on a pre-auth metric
    /// is its own DoS surface).
    std::string_view path_class;
};

/// THE table. Longest matching `path_prefix` wins among entries whose
/// `method` also matches (exact, or `kBodyCapAnyMethod`). See the file
/// header for the enforcement chokepoint, the matching rule, and the
/// `requires_measurable` default.
inline constexpr BodyCapEntry kBodyCapTable[] = {
    // /mcp/ — unchanged from #2437. ANY method: is_mcp_path() (web_utils.hpp)
    // scopes this by path alone, and the pre-routing cap must cover every
    // method reaching that surface (GET SSE, POST JSON-RPC, DELETE session
    // teardown), not just POST. requires_measurable=true: MCP's own client
    // contract already requires Content-Length (web_utils.hpp:577).
    // Source: mcp_jsonrpc.hpp:63 (kMcpMaxRequestBodyBytes).
    {kBodyCapAnyMethod, "/mcp/", 4u * 1024 * 1024, true, "mcp"},

    // POST /api/v1/bundles — live-query bundle dispatch (rest_api_v1.cpp:1417).
    // bundle_service.hpp:24-33 admits up to kMaxBundleSteps(32) steps x
    // kMaxParamCountPerStep(32) params x kMaxParamValueLen(64 KiB) = 64 MiB
    // of raw param VALUE bytes alone; JSON structural overhead (keys,
    // quotes, braces, plugin/action strings) adds more on top. 70 MiB
    // leaves ~6 MiB of headroom above that computed 64 MiB floor. A 4 MiB
    // default (the catch-all below) would break this route outright — do
    // not "simplify" this entry away.
    {"POST", "/api/v1/bundles", 70u * 1024 * 1024, false, "bundles"},
    // /api/v1/uploads — the PR1.6a authenticated chunked-receive surface
    // (session open POST, chunk PUT, status GET, commit POST, cancel DELETE).
    // ANY method: only the chunk PUT carries a large body, but scoping to PUT
    // would silently drop every sibling verb on this prefix to the catch-all
    // (rule 4 in the routed-concern row — prefer any-method rows). Cap = the
    // protocol's own per-chunk maximum, `upload_grant::kDefaultChunkMaxBytes`
    // (upload_grant_parsers.hpp; bound by a static_assert in
    // file_retrieval_routes.cpp so the two cannot drift). requires_measurable
    // = true: the chunk route's session gate lives in the HANDLER, after
    // httplib buffers the body, so without a pre-read bound an
    // UNAUTHENTICATED caller could make the server buffer up to httplib's
    // 100 MB default per connection — and the agent uploader always sends an
    // identity-encoded body with a Content-Length (it needs one to build the
    // protocol's Content-Range header), so this refuses no conforming client.
    // Bodyless GET/DELETE on this prefix are unaffected: the measurability
    // rule fires only for POST/PUT/PATCH (web_utils.hpp body_unmeasurable).
    {kBodyCapAnyMethod, "/api/v1/uploads", 8u * 1024 * 1024, true, "upload_session"},
    // /api/v1/plugin-config — the PR1.5 config/secret/kill-switch plane. The
    // store's own grammar caps a config value at 8 KiB and a secret plaintext
    // at 64 KiB (plugin_config_parsers.hpp kMaxConfigValueBytes/
    // kMaxSecretValueBytes); 256 KiB covers the larger of the two plus JSON
    // framing/escaping headroom with room to spare, while keeping an
    // unauthenticated flood against this surface two orders of magnitude
    // under the 4 MiB catch-all. ANY method — PUT config/secret writes,
    // DELETE carries no body, GET/list are bodyless.
    {kBodyCapAnyMethod, "/api/v1/plugin-config", 256u * 1024, false, "plugin_config"},

    // POST /api/settings/updates/upload — OTA agent binary upload
    // (settings_routes.cpp:5146 handler start, :5206 the unbounded file
    // read). No route-local limit exists today; keep httplib's own 100 MiB
    // default (httplib.h:130, CPPHTTPLIB_PAYLOAD_MAX_LENGTH) as the outer
    // backstop rather than squeeze a legitimate multi-ten-MB installer
    // binary. This entry exists so the class is an explicit, reviewed
    // decision rather than an accidental fallthrough to the catch-all.
    {"POST", "/api/settings/updates/upload", 100u * 1024 * 1024, false, "ota_upload"},

    // POST /api/export/json-to-csv — generic JSON-array-to-CSV export
    // (server.cpp:10809; the entire raw body is handed to
    // `data_export::json_array_to_csv` verbatim). Unbounded BY DESIGN: this
    // converts a full exported dataset (responses, audit rows, inventory —
    // whatever REST query the caller ran) to CSV, and there is no natural
    // "this export is too big" line to draw; a large legitimate export is
    // the expected case, not an abuse case. Choice made here: an EXPLICIT
    // entry pinned at httplib's own 100 MiB backstop, mirroring the
    // ota_upload treatment immediately above — NOT squeezed to a judgment-
    // call MiB number, because unlike guardian_rule_authoring/workflow_yaml/
    // product_pack_yaml (arbitrary but SINGLE-DOCUMENT content, where a
    // generous MiB-scale cap is a defensible judgment call) an export's
    // size is a direct, unbounded function of how much data the operator's
    // own prior query returned — there is no analogous "one document" scale
    // to be generous relative to. This entry's only job is to make that a
    // reviewed decision instead of an accidental fallthrough to the 4 MiB
    // catch-all, which would break real exports outright.
    {"POST", "/api/export/json-to-csv", 100u * 1024 * 1024, false, "json_to_csv_export"},

    // POST /api/nvd/match — software-inventory vulnerability match
    // (server.cpp:9258; parses a JSON body's `inventory` array of
    // {name, version} pairs, no size check anywhere in the handler or
    // `NvdDatabase::match_inventory`). No aggregate contract exists, but
    // unlike json_to_csv_export above this content IS naturally bounded in
    // scale — one call carries one device's installed-software census.
    // Sized to that: even a maximal per-item JSON encoding (long name +
    // version strings, keys, braces, comma) is well under 200 bytes/item,
    // so 8 MiB admits roughly 40000+ inventory items — an order of
    // magnitude above any real single-device software census (a heavily
    // packaged Linux workstation or a Windows box with a large registry
    // Programs list runs to a few thousand entries at most). Reasoned to
    // this specific content's realistic scale, not borrowed from the
    // arbitrary-YAML judgment-call classes below; still two orders of
    // magnitude below httplib's 100 MiB backstop.
    {"POST", "/api/nvd/match", 8u * 1024 * 1024, false, "nvd_match"},

    // POST /api/v1/ca/import-chain — subordinate CA chain import, JSON body
    // (ca_routes.cpp:24 kMaxImportBody, enforced at :516). Mirrors the
    // handler's own 256 KiB bound exactly, so this pre-routing gate never
    // rejects anything the handler itself would still admit.
    {"POST", "/api/v1/ca/import-chain", 256u * 1024, false, "ca_import_chain"},

    // POST /api/v1/ca/issue-code-signing — code-signing leaf issuance via CSR
    // custody (gap-matrix #10; ca_routes.cpp kMaxIssueCodeSigningBody,
    // enforced before nlohmann::json::parse). Mirrors that bound exactly —
    // same two-authority-split precedent as ca_import_chain/ca_revoke below.
    {"POST", "/api/v1/ca/issue-code-signing", 64u * 1024, false, "ca_issue_code_signing"},

    // POST /api/v1/ca/revoke — serial-scoped cert revocation, JSON body
    // (ca_routes.cpp:24 kMaxRevokeBody, enforced at ca_routes.cpp:394 before
    // the body reaches nlohmann::json::parse). Mirrors that bound exactly —
    // same reasoning as the import-chain entry above. Without this entry the
    // route silently fell through to the 4 MiB catch-all, two authorities
    // (this table and the handler) disagreeing on the same route.
    {"POST", "/api/v1/ca/revoke", 64u * 1024, false, "ca_revoke"},

    // POST /api/v1/secrets/kek/rotate|rewrap — both take zero body fields
    // (kek_routes.cpp:46 kMaxKekBody, enforced at :54 in validate_empty_body,
    // shared by both handlers before either parses JSON). One entry covers
    // both routes: they share the literal prefix "/api/v1/secrets/kek/" and
    // the segment-boundary matcher treats a prefix already ending in '/' as
    // matching every child segment (see body_cap_prefix_matches). Mirrors
    // kMaxKekBody exactly — same two-authority-split fix as ca_revoke above.
    {"POST", "/api/v1/secrets/kek/", 64u * 1024, false, "kek_ops"},

    // POST /api/settings/ca/import-chain — the dashboard (HTMX,
    // application/x-www-form-urlencoded) twin of the above
    // (ca_routes.cpp:727). It has NO raw-body size check of its own, so
    // this pre-routing entry is its ONLY bound. Doubled versus the REST
    // JSON cap as conservative headroom for form percent-encoding overhead
    // (worst case 3x per byte on '+', '/', '=', and the line-wrap '\n's in
    // the base64 PEM text; real overhead is far smaller) plus the two form
    // field names/framing — still three orders of magnitude below
    // httplib's 100 MiB backstop.
    {"POST", "/api/settings/ca/import-chain", 512u * 1024, false,
     "ca_import_chain_dashboard"},

    // POST /api/settings/plugin-signing/upload — plugin code-signing trust
    // bundle (settings_routes.cpp:3445 upload handler, :3461 the 256 KiB
    // check). That check bounds the PARSED multipart file CONTENT, not the
    // raw request body (boundary markers, part headers, the filename
    // field). Doubled for that framing overhead, same reasoning as the CA
    // dashboard twin above.
    {"POST", "/api/settings/plugin-signing/upload", 512u * 1024, false,
     "plugin_trust_bundle"},

    // SCIM — scim_routes.cpp:65 kMaxBodyBytes, currently checked only AFTER
    // buffering (first call site :827). This moves the same bound BEFORE the
    // buffer. One path prefix covers both /Users and /Groups sub-resources
    // (scim_routes.cpp's route registrations all resolve under "/scim/v2/").
    //
    // ANY-METHOD, deliberately, and do NOT narrow this back to the three
    // mutating verbs. An adversarial review found that method-scoping let a
    // verb switch (DELETE, OPTIONS, or a GET carrying a body) drop the whole
    // prefix to the 4 MiB catch-all — 64x this class's bound. That is not a
    // widening in the capability sense, since the catch-all already offers
    // 4 MiB on every (method, path) by explicit reviewed decision, which is
    // why it was adjudicated MEDIUM rather than blocking. It is still wrong
    // here specifically: SCIM DELETE routes are real (scim_routes.cpp:1577,
    // :2316), every /scim/v2/* path is session-auth-exempt, and httplib
    // buffers before the in-handler require_bearer runs — so this prefix is
    // reachable pre-auth on more verbs than the three that mutate. A class
    // whose bound is justified by the shape of its payload should not depend
    // on the verb used to deliver it.
    {kBodyCapAnyMethod, "/scim/v2/", 64u * 1024, false, "scim"},

    // POST /saml/acs — SAML assertion consumer service
    // (auth_routes.cpp:2794-2798, kSamlMaxBodyBytes). A legitimate signed
    // SAMLResponse is well under 64 KiB; 1 MiB is generous headroom while
    // refusing a plaintext-amplification DoS via an oversized fake
    // SAMLResponse field.
    {"POST", "/saml/acs", 1u * 1024 * 1024, false, "saml_acs"},

    // POST/PUT /api/v1/definitions/{id}/response-templates[/{template_id}]
    // (rest_api_v1.cpp:4237 kRtMaxBodyBytes, checked at :4376 and :4461).
    // The id segments are regex-captured, so the widest LITERAL prefix this
    // table's segment-boundary matcher can key on is
    // "/api/v1/definitions/" — the whole subtree, not just the
    // response-templates sub-resource. That is safe today because those are
    // the ONLY two POST/PUT registrations under this prefix (verified
    // against rest_api_v1.cpp); a future mutation route added elsewhere
    // under /api/v1/definitions/ inherits this 64 KiB cap too unless it
    // gets its own, more specific entry ABOVE this one (longest match wins,
    // so a new entry naming its own longer literal prefix takes priority
    // automatically).
    {"POST", "/api/v1/definitions/", 64u * 1024, false, "response_templates"},
    {"PUT", "/api/v1/definitions/", 64u * 1024, false, "response_templates"},

    // POST /api/dashboard/tar-execute — TAR warehouse SQL query, HTMX form
    // fields `sql` + `scope` (dashboard_routes.cpp:866 `sql.size() > 4096`
    // check on the FORM-DECODED value). The #2407-as-shipped 4096-byte cap
    // capped the RAW body at the SAME number the handler checks against the
    // DECODED field — a unit mismatch, not a margin. The raw body is
    // `"sql=" + percent-encoded(sql) + "&scope=" + percent-encoded(scope)`,
    // so a 4093-4096 character query was unconditionally rejected before the
    // handler ever ran, and any query containing a `'`, `(`, `)`, `=`, `,`,
    // or a newline was rejected far earlier (percent-encoding is up to 3x
    // per character worst case). Measured case: a 4085-character realistic
    // query produced a 5078-byte raw body, 24% over the old 4096-byte cap —
    // legitimate traffic, rejected. Fix: 3 x 4096 (worst-case percent-
    // encoding of the full 4096-char decoded `sql` value the handler still
    // admits) + 4 KiB flat headroom for the "sql="/"&scope=" field-name
    // framing and the `scope` field's own percent-encoded value (which has
    // no size contract of its own — `scope` is normally an agent id or
    // "group:<name>", short, but nothing bounds it today) = 12288 + 4096 =
    // 16384 bytes exactly. Reasoned margin, not a byte-for-byte measurement
    // — same category as the CA/plugin-trust dashboard classes below.
    {"POST", "/api/dashboard/tar-execute", 16u * 1024, false, "tar_dashboard_sql"},

    // POST /api/v1/result-sets/from-tar-query — TAR result-set SQL, JSON
    // body (rest_api_v1.cpp:6802, `sql.size() > 100000` check on the JSON-
    // PARSED `sql` field). Same unit mismatch as tar_dashboard_sql above,
    // with almost no headroom to hide it: the old 102400-byte cap left only
    // 2400 bytes over the handler's 100000-character check to absorb JSON
    // string-escaping (quotes, backslashes, and control characters expand
    // under JSON escaping — a raw control byte with no named escape costs 6
    // bytes as `\u00XX`) plus the request's other keys (`include_empty`,
    // `parent_id`, object braces). The old comment claimed "this pre-routing
    // gate never rejects a body the handler would still admit" — false; a
    // legitimate 99000+-character query containing a modest amount of
    // escaping could exceed 102400 raw bytes and be rejected here while the
    // handler would have admitted it. Fix: double the handler's 100000-byte
    // check for escaping headroom (200000 bytes), which also covers the
    // other JSON keys — 200 KiB (204800 bytes) exactly. NOTE the asymmetry
    // this table cannot erase: the handler answers `400 RESULT_SET_BAD_
    // REQUEST` for an over-100000-character `sql` field; this pre-routing
    // gate answers `413` for an over-200-KiB raw body. They are not the same
    // check re-run twice — a raw body between 100000 and 204800 bytes whose
    // decoded `sql` value is still <=100000 characters passes here and is
    // then decided by the handler's own check, as intended; a raw body over
    // 204800 bytes never reaches the handler at all.
    {"POST", "/api/v1/result-sets/from-tar-query", 200u * 1024, false,
     "tar_result_set_sql"},

    // POST /api/v1/guaranteed-state/rules — Guardian rule authoring
    // (rest_api_v1.cpp:7759 handler start; :7842 the legacy path that
    // accepts an arbitrary supplied `yaml_source` verbatim). No aggregate
    // rule-size contract exists yet anywhere in the codebase, so this is a
    // deliberate, generous EXPLICIT entry rather than a squeeze — see the
    // file header. Do NOT tighten this without a real contract to measure
    // against.
    {"POST", "/api/v1/guaranteed-state/rules", 16u * 1024 * 1024, false,
     "guardian_rule_authoring"},

    // PUT /api/v1/guaranteed-state/rules/{id} — the sibling regex UPDATE
    // route (rest_api_v1.cpp:7904). #2407-as-shipped scoped the entry above
    // to POST only, so a PUT fell through to the 4 MiB catch-all default —
    // a rule created at up to 16 MiB (the entry above) could then never be
    // edited back through the same-sized route. Same class, same "no
    // contract yet" reasoning as the POST entry, so the same 16 MiB bound.
    // Path prefix ends in '/' so the segment-boundary matcher
    // (body_cap_prefix_matches) covers the regex-captured `{id}` suffix —
    // see the file header's MATCHING section for why path-only matching
    // could not otherwise tell this apart from the POST create route on the
    // identical literal prefix.
    {"PUT", "/api/v1/guaranteed-state/rules/", 16u * 1024 * 1024, false,
     "guardian_rule_authoring"},

    // POST /api/workflows — workflow authoring from a YAML bundle
    // (workflow_routes.cpp:1023). Same "no aggregate contract yet" shape as
    // guardian rule authoring above — deliberate, generous, explicit.
    {"POST", "/api/workflows", 16u * 1024 * 1024, false, "workflow_yaml"},

    // POST /api/product-packs — product-pack installation from a YAML
    // bundle (workflow_routes.cpp:1746). A pack holds MULTIPLE YAML
    // documents (product_pack_store.cpp:122's `split_yaml_documents`), so
    // this needs the same generous headroom as workflow authoring, not the
    // single-document default.
    {"POST", "/api/product-packs", 16u * 1024 * 1024, false, "product_pack_yaml"},

    // POST /api/instructions/import — JSON instruction-definition import,
    // whole raw body forwarded verbatim to `import_definition_json`
    // (instruction_routes.cpp -> instruction_store.cpp:954 -> create_definition_
    // impl:434, which DOES hard-reject an oversized `yaml_source` field at
    // 1048576 bytes via validate_definition_scope, instruction_store.cpp:
    // 411). That real check does NOT bound the whole request, though: an
    // imported definition also carries an optional `responseTemplates`
    // field, and when it is supplied as a native JSON array/object (not a
    // pre-serialized string) `normalise_templates_array` applies NO size
    // limit at all (the 256 KiB `kMaxImportTemplateStringBytes` guard,
    // instruction_store.cpp:904, only fires on the string-form branch) — so
    // a well-formed request with a huge templates array is not rejected by
    // anything downstream. No genuine aggregate contract, therefore: same
    // "no contract yet" judgment-call category as guardian_rule_authoring/
    // workflow_yaml/product_pack_yaml above, and the same peer bound.
    {"POST", "/api/instructions/import", 16u * 1024 * 1024, false, "instruction_import"},

    // POST /api/instructions/yaml (save), POST /api/instructions/validate-
    // yaml, POST /fragments/instructions/yaml-preview — three FORM-encoded
    // (application/x-www-form-urlencoded) twins of one shape: a single
    // `yaml_source` field (save also carries a small `id` field), all three
    // routed through the SAME check — instruction_store.cpp's
    // `validate_yaml_source` -> `instruction_yaml::validate_definition_yaml`, which hard-rejects
    // `yaml_source.size() > 1048576` at instruction_yaml.cpp:165 (the exact
    // 1 MiB decoded-value contract create/update also enforce). This is the
    // SAME raw-vs-decoded shape as tar_dashboard_sql (C1) — the pre-routing
    // gate sees the percent-encoded RAW body, the handler checks the
    // DECODED `yaml_source` value — so the cap must NOT mirror 1048576
    // directly (the #2407-as-shipped defect this table already paid for
    // once). Fix, same method as C1: 3x1048576 (worst-case percent-encoding
    // of the full 1 MiB decoded value the handler still admits) + 4 KiB
    // flat headroom for the "yaml_source="/"&id=" field-name framing (the
    // `id` field itself has no length contract anywhere in the codebase) =
    // 3145728 + 4096 = 3149824 bytes exactly. One shared cap+label across
    // all three routes — same size-defense reasoning, same check, distinct
    // literal paths (no common prefix to key one table entry on).
    {"POST", "/api/instructions/yaml", 3149824u, false, "instruction_yaml"},
    {"POST", "/api/instructions/validate-yaml", 3149824u, false, "instruction_yaml"},
    {"POST", "/fragments/instructions/yaml-preview", 3149824u, false, "instruction_yaml"},

    // /api/v1/hardware — the Hardware CI list/record/sync REST v1 twin
    // (hardware_routes.cpp). ANY method: GET /api/v1/hardware and
    // GET /api/v1/hardware/{id} are bodyless list/record reads; only
    // POST /api/v1/hardware/{id}/sync carries a body, and it is a single
    // JSON object with one short "source" token (one of 5 fixed literals,
    // e.g. "installed_software") — a few dozen bytes at most. 4 KiB leaves
    // generous headroom over that real shape while keeping this three orders
    // of magnitude under the 4 MiB catch-all (governance Gate 2: this route
    // had no reviewed entry, per the routed-concern row's requirement that
    // every new mutating route get one). requires_measurable = true: the
    // route's own `scoped_perm_fn` gate lives in the HANDLER, after httplib
    // buffers the body, so without a pre-read bound an unauthenticated
    // caller reaching this prefix with a chunked (no Content-Length) body
    // would be uncapped up to httplib's 100 MiB default — the same class the
    // /api/v1/uploads entry above closes.
    {kBodyCapAnyMethod, "/api/v1/hardware", 4u * 1024, true, "hardware"},

    // /api/v1/rbac/roles/{name}/assignments[/{principal_id}] — A2 global
    // human role assignment (rest_api_v1.cpp). POST's body is
    // {principal_type, principal_id}, two short strings well under a KiB;
    // DELETE carries no body. ANY method: the DELETE sibling shares this
    // literal prefix once past the role-name path segment the URL regex
    // captures — see the file header's MATCHING section for the same
    // reasoning applied to every other any-method entry with a same-prefix
    // sibling. 4 KiB leaves generous headroom over the real shape.
    {kBodyCapAnyMethod, "/api/v1/rbac/roles/", 4u * 1024, false, "rbac_role_assignment"},

    // The catch-all default. ANY method, empty prefix — always matches, and
    // always loses a longest-match comparison against every entry above.
    // Ordinary JSON/form traffic (most REST mutation routes) lands here.
    {kBodyCapAnyMethod, "", 4u * 1024 * 1024, false, "default"},
};

/// True when `path` matches `prefix` at a segment boundary: `path` starts
/// with `prefix`, and either the match consumes the whole path, `prefix`
/// itself already ends in `/`, or the next byte of `path` after the prefix
/// is `/`. This is what stops `/api/v1/bundlesevil` from matching the
/// `/api/v1/bundles` entry — a plain `starts_with` would let it through.
[[nodiscard]] constexpr bool body_cap_prefix_matches(std::string_view path,
                                                     std::string_view prefix) noexcept {
    if (!path.starts_with(prefix))
        return false;
    if (path.size() == prefix.size())
        return true;
    if (prefix.ends_with('/'))
        return true;
    return path[prefix.size()] == '/';
}

/// The resolved cap for one `(method, path)` pair — a copy of the matched
/// entry's non-key fields.
struct BodyCapMatch {
    std::size_t max_body_bytes;
    bool requires_measurable;
    std::string_view path_class;
};

/// Resolve the body-cap policy for one request. Longest matching
/// `path_prefix` wins among entries whose `method` also matches (exact
/// method, or `kBodyCapAnyMethod`); the catch-all default entry guarantees a
/// match always exists. `noexcept` — this is a pure table lookup called from
/// the pre-routing handler for every request server-wide, with no error path
/// to report through (mirrors `dispatch_confined_arms.hpp`'s style).
[[nodiscard]] constexpr BodyCapMatch resolve_body_cap(std::string_view method,
                                                      std::string_view path) noexcept {
    const BodyCapEntry* best = nullptr;
    for (const auto& entry : kBodyCapTable) {
        if (entry.method != kBodyCapAnyMethod && entry.method != method)
            continue;
        if (!body_cap_prefix_matches(path, entry.path_prefix))
            continue;
        if (best == nullptr || entry.path_prefix.size() > best->path_prefix.size())
            best = &entry;
    }
    // Unreachable in practice — the catch-all default (empty prefix,
    // kBodyCapAnyMethod) matches every (method, path), so `best` is always
    // set. Guarded rather than dereferenced blindly so a future edit that
    // accidentally removes or mis-scopes the default entry fails LOUD (a
    // zero-byte cap that rejects everything) instead of invoking UB.
    //
    // UNREACHABLE BY CONSTRUCTION, not merely by inspection: the
    // `static_assert` below this function proves `kBodyCapTable` contains an
    // any-method empty-prefix row, which `body_cap_prefix_matches` accepts
    // for every path, so `best` can never be null and this branch can never
    // execute. That is deliberate rather than pre-seeding the label: a
    // sentinel that CANNOT occur is stronger than one that is instrumented
    // when it does, and it removes the `yuzu_body_cap_rejected_total`
    // unannounced-series question entirely rather than answering it.
    //
    // Kept as a fail-CLOSED fallback anyway (cap 0, requires_measurable
    // true — reject everything) so that if a future edit defeats the assert
    // in a way the compiler cannot see, the failure mode is refusal, never
    // an uncapped admit. Historical note for anyone re-reading the metric
    // docs: this was previously an open gap where the label was emittable
    // but never pre-seeded (which `server.cpp`'s boot loop, iterating
    // `kBodyCapTable`, could not seed since it is not a row) — the series would
    // appear unannounced the first time this sentinel is ever reached.
    // `server.cpp` owns that seeding loop; this header only owns documenting
    // the gap so it is not silently assumed closed.
    if (best == nullptr)
        return {0, true, "unmatched"};
    return {best->max_body_bytes, best->requires_measurable, best->path_class};
}

/// True iff `kBodyCapTable` carries an any-method, empty-prefix catch-all row.
///
/// `body_cap_prefix_matches` accepts an empty prefix for every path, and
/// `kBodyCapAnyMethod` matches every verb, so such a row makes
/// `resolve_body_cap`'s null-`best` branch unreachable — the `unmatched`
/// sentinel becomes impossible rather than merely unlikely.
[[nodiscard]] constexpr bool body_cap_table_has_catch_all() noexcept {
    for (const auto& e : kBodyCapTable)
        if (e.method == kBodyCapAnyMethod && e.path_prefix.empty())
            return true;
    return false;
}

// Removing the catch-all row would make `path_class="unmatched"` emittable,
// and `server.cpp`'s boot-time pre-seed loop iterates kBodyCapTable, so that
// label could never be seeded — an unannounced Prometheus series that breaks
// the absent()-alert convention in docs/observability-conventions.md. This
// fails the BUILD instead, which is strictly stronger than instrumenting a
// series for a condition that should not exist.
static_assert(body_cap_table_has_catch_all(),
              "kBodyCapTable must keep its {kBodyCapAnyMethod, \"\"} catch-all row: without "
              "it resolve_body_cap can return path_class=\"unmatched\", which server.cpp's "
              "boot-time metric pre-seed loop cannot seed (it iterates the table), leaving an "
              "unannounced series. Re-add the catch-all rather than deleting this assert.");

/// The outcome of `evaluate_body_cap` for one request.
///
/// `status`/`reason` are only meaningful when `refuse` is true — a caller
/// must not write `status` to a response, or read `reason` as a metric
/// label, on the admit path (`status == 0`, `reason` empty there,
/// deliberately not a sentinel worth matching on: check `refuse` first).
///
/// `reason` is always one of three literals — `"unsupported_encoding"`,
/// `"unmeasurable"`, `"over_cap"` — the SAME strings `server.cpp` already
/// publishes as `yuzu_body_cap_rejected_total{reason=...}`, returned here
/// instead of re-spelled at the call site so the metric label and the
/// decision that produced it cannot drift apart.
struct BodyCapDecision {
    bool refuse;
    int status;
    std::string_view path_class;
    std::string_view reason;
};

/// THE pre-auth request-body-cap DECISION — the single callable both
/// `server.cpp`'s pre-routing handler and
/// `tests/unit/server/test_body_cap_policy.cpp`'s `UnifiedBodyCapTestServer`
/// fixture invoke (#2898). Before this existed, the fixture re-implemented
/// the same branching independently of `server.cpp`'s lambda — same pure
/// predicates, but combined a second time by hand — so a mutation to the
/// PRODUCTION combination (an inverted condition, a swapped status, a
/// dropped branch) had no test that could see it: the fixture's own,
/// separately-written combination still matched its own separately-written
/// expectations. Routing both call sites through this one function makes
/// that divergence structurally impossible instead of something to keep
/// re-verifying by hand — see `docs/postgres-store-playbook.md`-style
/// reasoning applied to a chokepoint rather than a store: EXTEND this
/// function, never fork it.
///
/// Composes `resolve_body_cap` (this header) with the framing/encoding
/// predicates in `web_utils.hpp` (`has_non_identity_content_encoding`,
/// `body_unmeasurable`, `content_length_is_authoritative`) in the EXACT
/// order and precedence `server.cpp`'s file-header comment documents as
/// D1-D5: Content-Encoding refused unconditionally FIRST (D4), then framing
/// unmeasurability gated per-class by `requires_measurable`, then the size
/// check gated on `content_length_is_authoritative` rather than
/// `!unmeasurable` (the #2407 R2 CRITICAL bypass this repo already paid for
/// once — see that predicate's own doc comment in `web_utils.hpp`).
///
/// DOES ONLY THE DECISION — no metric increment, no log line, no A4/SCIM
/// envelope, no write to an `httplib::Response`. Those are call-site-owned
/// WIRING (response shaping, envelope selection by `path_class`, metric
/// labels, log throttling) and stay in `server.cpp`; folding them in here
/// would pull `httplib::Response`, `spdlog`, and the metrics registry into
/// this pure header and make it untestable without booting a server, which
/// is the exact problem this function exists to avoid.
///
/// NO `httplib::Request` IN THE SIGNATURE, deliberately, even though every
/// production caller has one at hand: `is_chunked` MUST come from httplib's
/// own `httplib::detail::is_chunked_transfer_encoding(req.headers)` (see
/// `content_length_is_authoritative`'s doc comment for why re-deciding that
/// bit from the raw header text was a live bypass, twice). Accepting
/// `const httplib::Request&` here would tempt a future caller to re-derive
/// `is_chunked` (or `content_length`, or `has_content_length`) INSIDE this
/// function from the request instead of from the caller's own
/// `content_length_for_body_cap`/`is_chunked_transfer_encoding` calls — at
/// which point the production call site and the test fixture below are back
/// to two independent implementations of the same httplib quirk, which is
/// precisely the class of defect #2407 R2 was. Taking the already-extracted
/// facts instead keeps this header httplib-free (matching `is_mcp_path`'s
/// documented reason in `web_utils.hpp`) and keeps both callers reading the
/// SAME httplib accessors rather than two callers each trusting their own
/// reading of the same wire bytes.
///
/// `noexcept`, truthfully: every predicate this composes
/// (`resolve_body_cap`, `has_non_identity_content_encoding`,
/// `body_unmeasurable`, `content_length_is_authoritative`) is itself
/// `noexcept`, and this function allocates nothing and calls nothing else.
/// The header-comment requirement in `server.cpp` to "CONTAIN THE WHOLE
/// BLOCK" in a `try`/`catch(...)` still applies to the WIRING around this
/// call — extracting the request's `Content-Length`/`Transfer-Encoding`/
/// `Content-Encoding` header VALUES (`req.get_header_value*`) can throw, and
/// that extraction happens at the caller, before this function is invoked —
/// this function itself is not the boundary that containment protects, the
/// caller's header reads are.
[[nodiscard]] inline BodyCapDecision
evaluate_body_cap(std::string_view method, std::string_view path, bool has_content_length,
                   std::uint64_t content_length, std::string_view transfer_encoding,
                   std::string_view content_encoding, bool is_chunked) noexcept {
    const BodyCapMatch cap_match = resolve_body_cap(method, path);

    // D4: Content-Encoding is refused UNCONDITIONALLY, on every class,
    // checked FIRST and separately from the framing/size check below —
    // see server.cpp's file-header comment for why (httplib decompresses
    // before enforcing its own global limit, so Content-Length is not a
    // bound on a compressed body's expanded size).
    if (has_non_identity_content_encoding(content_encoding))
        return {true, 415, cap_match.path_class, "unsupported_encoding"};

    // 1. Do we REFUSE this framing outright? Deliberately broad (#2437):
    //    any non-empty Transfer-Encoding, on a class that opted into
    //    requires_measurable.
    const bool unmeasurable =
        body_unmeasurable(method, has_content_length, transfer_encoding);
    const bool refuse_unmeasurable = unmeasurable && cap_match.requires_measurable;

    // 2. May we CHECK the size? Only when httplib will actually read
    //    Content-Length bytes — asked of `is_chunked`, supplied by the
    //    caller from httplib's own predicate, never re-derived here. Two
    //    DIFFERENT questions; collapsing them back into one was a live
    //    unauthenticated bypass (#2407 R2) — see
    //    `content_length_is_authoritative`'s doc comment.
    const bool oversize =
        content_length_is_authoritative(has_content_length, is_chunked) &&
        content_length > cap_match.max_body_bytes;

    if (refuse_unmeasurable)
        return {true, 411, cap_match.path_class, "unmeasurable"};
    if (oversize)
        return {true, 413, cap_match.path_class, "over_cap"};

    return {false, 0, cap_match.path_class, ""};
}

} // namespace yuzu::server
