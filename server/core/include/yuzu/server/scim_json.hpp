#pragma once

/**
 * scim_json.hpp — JSON codec + discovery-doc layer for SCIM v2 provisioning
 * (slice 2 of 3).
 *
 * PURE functions only: serialize `ScimResource`/`ScimGroup` (server/core/
 * include/yuzu/server/scim_store.hpp) to/from SCIM JSON, build the SCIM
 * error/ListResponse envelopes, parse the `userName eq "..."` /
 * `displayName eq "..."` filters IdPs use for existence checks, and emit the
 * three static discovery documents (ServiceProviderConfig / ResourceTypes /
 * Schemas — both User and Group). No HTTP route, no database access — a
 * sibling junior (routes layer) wires these into routes that call
 * `ScimStore`.
 *
 * SCIM v2 Groups (#2021, slice 2): `group_to_json`/`parse_group`/
 * `parse_group_patch` mirror the User codec's strictness (non-string
 * displayName/externalId reject with 400). Group membership `members[].
 * value` is expected to be a SCIM User resource `scim_id` — this codec only
 * parses/serializes the raw string; resolving it against a live User
 * resource (and validate-and-skip on an unresolvable value) is the routes
 * layer's job.
 *
 * Spec reference: RFC 7643 (SCIM Core Schema) / RFC 7644 (SCIM Protocol).
 */

#include "yuzu/server/scim_store.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::scim {

// ── SCIM schema URNs ────────────────────────────────────────────────────────

inline constexpr std::string_view kSchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User";
inline constexpr std::string_view kSchemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group";
inline constexpr std::string_view kSchemaError =
    "urn:ietf:params:scim:api:messages:2.0:Error";
inline constexpr std::string_view kSchemaListResponse =
    "urn:ietf:params:scim:api:messages:2.0:ListResponse";
inline constexpr std::string_view kSchemaPatchOp =
    "urn:ietf:params:scim:api:messages:2.0:PatchOp";
inline constexpr std::string_view kSchemaServiceProviderConfig =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
inline constexpr std::string_view kSchemaResourceType =
    "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
inline constexpr std::string_view kSchemaSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/// Bound on `externalId` (S-EXTID, UP-13): IdP-supplied opaque identifiers
/// are typically GUIDs/short opaque strings; 256 bytes is generous headroom
/// while refusing an absurdly oversized value on a field Yuzu only stores
/// and echoes back, never interprets. Uniqueness enforcement on this field
/// is NOT implemented (out of scope for this slice).
inline constexpr std::size_t kMaxExternalIdLength = 256;

/// Bound on Group `displayName` (sec-L3/UP-9, governance hardening round):
/// mirrors kMaxExternalIdLength's rationale — IdP-supplied group names are
/// short human-readable strings; 256 bytes is generous headroom while
/// refusing an absurdly oversized value on a field stored and echoed back,
/// never interpreted (beyond the exact-byte --scim-admin-group comparison).
inline constexpr std::size_t kMaxDisplayNameLen = 256;

/// The `filter.maxResults` this server advertises in ServiceProviderConfig
/// (S-CLAMP-COUNT). `ScimRoutes`'s GET /Users list handler clamps a
/// caller-supplied `count` to this same constant so the advertised cap is
/// actually enforced, not just documented.
inline constexpr int kMaxScimListResults = 200;

/// A structured SCIM error: `status` is the HTTP status to send AND is
/// serialized as a JSON *string* per RFC 7644 §3.12; `scim_type` is the
/// optional detail enum (e.g. "invalidValue", "invalidPath", "invalidFilter")
/// — empty omits the field.
struct ScimError {
    int status{400};
    std::string scim_type;
    std::string detail;
};

/// Parsed body of a SCIM User POST/PUT. Unknown fields (name, emails, etc.,
/// which real IdPs send) are tolerated and ignored — only the fields Yuzu's
/// resource mapping cares about are extracted.
struct ScimUserInput {
    std::string user_name;
    std::string external_id;
    std::optional<bool> active;
};

/// Parsed, flattened result of a SCIM PatchOp body. Only `replace` (and
/// `add`, treated identically) on `active`/`userName`/`externalId` is
/// supported — see scim_json.cpp for the full op/path support matrix.
struct ScimPatch {
    std::optional<bool> active;
    std::optional<std::string> user_name;
    std::optional<std::string> external_id;
};

// ── User resource codec ─────────────────────────────────────────────────────

/// Serialize a stored `ScimResource` to a SCIM User JSON representation.
/// `location_base` is the collection URL (e.g. "https://host/scim/v2/Users")
/// — the per-resource `meta.location` is `"<location_base>/<scim_id>"`.
nlohmann::json user_to_json(const ScimResource& r, std::string_view location_base);

/// Parse a SCIM User create/replace body. Requires a non-empty `userName`.
std::expected<ScimUserInput, ScimError> parse_user(const nlohmann::json& body);

/// Parse a SCIM PatchOp body (`Operations` array). See scim_json.cpp for the
/// supported op/path combinations.
std::expected<ScimPatch, ScimError> parse_patch(const nlohmann::json& body);

// ── Group resource codec (#2021 slice 2) ────────────────────────────────────

/// Parsed body of a SCIM Group create/replace body. `member_values` holds
/// the raw `members[].value` strings (each expected to be a SCIM User
/// resource `scim_id`) — resolution against live User resources, and
/// validate-and-skip on an unresolvable value, happens in the routes layer,
/// never here.
struct ScimGroupInput {
    std::string display_name;
    std::string external_id;
    std::vector<std::string> member_values;
};

/// A single member-affecting `Operations` entry from a Group PatchOp body,
/// preserved in the body's own document order (RFC 7644 §3.5.2: PatchOps
/// are applied "in the order that they appear" — order-sensitive, since
/// `[{add:U},{remove:U}]` and `[{remove:U},{add:U}]` are different final
/// states). This replaces the old type-keyed-bucket design
/// (`members_to_add`/`members_to_remove` accumulators), which collapsed
/// every op into unordered sets and so could not express that distinction
/// (#2127 review HIGH). `values` holds the raw `members[].value` strings
/// for `Add`/`Remove`/`ReplaceAll` (resolution against live User resources
/// happens in the routes layer, never here); empty and ignored for
/// `RemoveAll`.
struct ScimGroupMemberOp {
    enum class Kind {
        Add,        ///< `add` on `members` (explicit path or pathless).
        Remove,     ///< `remove` on `members` with an explicit value/filter.
        RemoveAll,  ///< bare `remove` path `"members"`, no value/filter.
        ReplaceAll, ///< `replace` on `members` (explicit path or the
                    ///< pathless `{"members":[...]}` value-object form).
    };
    Kind kind;
    std::vector<std::string> values;
};

/// Parsed result of a SCIM Group PatchOp body (RFC 7644 §3.5.2).
/// `member_ops` holds every member-affecting `Operations` entry, IN THE
/// BODY'S ORDER — the routes layer folds them onto the current membership
/// set in that order to get the final result (never applies all removes
/// then all adds). `display_name`/`external_id` mirror the Users patch
/// shape (explicit path or pathless value-object) and are order-independent
/// against member ops (different targets) — only the LAST value for each
/// wins, same as before.
struct ScimGroupPatch {
    std::optional<std::string> display_name;
    std::optional<std::string> external_id;
    std::vector<ScimGroupMemberOp> member_ops;
};

/// Serialize a stored `ScimGroup` + its resolved member `scim_id`s to a SCIM
/// Group JSON representation. `group_location_base` is the Groups
/// collection URL (e.g. "https://host/scim/v2/Groups") for `meta.location`;
/// `users_location_base` is the Users collection URL (e.g.
/// "https://host/scim/v2/Users") each member's `$ref` is built against —
/// mirrors `user_to_json`'s `location_base` parameter, split in two because
/// a Group resource references both collections.
nlohmann::json group_to_json(const ScimGroup& g, const std::vector<std::string>& member_scim_ids,
                             std::string_view group_location_base,
                             std::string_view users_location_base);

/// Parse a SCIM Group create/replace body. Requires a non-empty
/// `displayName`; non-string `displayName`/`externalId`/member `value`
/// reject with 400 (mirrors `parse_user`'s strictness).
std::expected<ScimGroupInput, ScimError> parse_group(const nlohmann::json& body);

/// Parse a SCIM Group PatchOp body (`Operations` array) — see the
/// `ScimGroupPatch` doc comment for the supported op/path combinations.
std::expected<ScimGroupPatch, ScimError> parse_group_patch(const nlohmann::json& body);

// ── Envelopes ────────────────────────────────────────────────────────────────

/// Build the SCIM error envelope (RFC 7644 §3.12). `status` is emitted as a
/// JSON string. `scim_type` is omitted from the envelope when empty.
nlohmann::json error(int status, std::string_view detail, std::string_view scim_type = "");

/// Convenience overload building the envelope directly from a `ScimError`.
nlohmann::json error(const ScimError& e);

/// Build a SCIM `ListResponse` envelope wrapping already-serialized resource
/// JSON objects (see `user_to_json`).
nlohmann::json list_response(const std::vector<nlohmann::json>& resources, int total_results,
                             int start_index, int items_per_page);

// ── Filter parsing ───────────────────────────────────────────────────────────

/// Parse a SCIM filter expression, supporting exactly `userName eq "value"`
/// (attribute + operator case-insensitive; value double-quoted with `\"`/`\\`
/// escapes). Returns the unescaped value, or a `{400,"invalidFilter",...}`
/// error for any other attribute/operator/malformed input.
std::expected<std::string, ScimError> parse_username_filter(std::string_view filter);

/// Group-list counterpart of `parse_username_filter`, supporting exactly
/// `displayName eq "value"` (same case-insensitivity / quoting rules).
std::expected<std::string, ScimError> parse_displayname_filter(std::string_view filter);

// ── Discovery documents ──────────────────────────────────────────────────────

/// `GET /ServiceProviderConfig` — static capability document.
nlohmann::json service_provider_config();

/// `GET /ResourceTypes` — a ListResponse describing the User AND Group
/// resource types.
nlohmann::json resource_types();

/// `GET /Schemas` — a ListResponse describing the core User AND Group
/// schemas.
nlohmann::json schemas();

} // namespace yuzu::server::scim
