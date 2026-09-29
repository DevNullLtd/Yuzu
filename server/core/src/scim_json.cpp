#include "yuzu/server/scim_json.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>

namespace yuzu::server::scim {

namespace {

/// True if `s` contains an embedded NUL byte. PostgreSQL `text` columns
/// cannot round-trip one — `pg::exec_params` hands libpq a NUL-terminated
/// C string regardless of the caller's `std::string` length, so anything
/// after the first NUL is silently dropped on write, not stored. Rather
/// than let a value be silently truncated (which let a crafted
/// "Admins\0decoy" `displayName` collapse to the literal "Admins" and match
/// `--scim-admin-group`, spuriously promoting the submitting member — UP-3 /
/// #2018), every SCIM text field is rejected fail-closed at this parse
/// boundary the moment it contains one.
bool has_embedded_nul(std::string_view s) {
    return s.find('\0') != std::string_view::npos;
}

/// Case-insensitive ASCII compare — SCIM attribute names and op verbs are
/// case-insensitive per RFC 7644 §3.5.2.
bool ieq(std::string_view a, std::string_view b) {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) ==
                      std::tolower(static_cast<unsigned char>(y));
           });
}

/// Shared `<attr> eq "<value>"` filter parser backing both
/// `parse_username_filter` (attr "userName") and `parse_displayname_filter`
/// (attr "displayName") — same trim/split/unescape logic, parameterized on
/// the expected attribute name so neither public entry point's behavior
/// changes.
std::expected<std::string, ScimError> parse_eq_filter(std::string_view filter,
                                                      std::string_view attr_name) {
    auto fail = [] {
        return std::unexpected(ScimError{400, "invalidFilter", "unsupported filter"});
    };

    std::string_view s = filter;
    auto trim = [](std::string_view v) {
        size_t b = v.find_first_not_of(" \t");
        if (b == std::string_view::npos)
            return std::string_view{};
        size_t e = v.find_last_not_of(" \t");
        return v.substr(b, e - b + 1);
    };
    s = trim(s);

    size_t sp1 = s.find_first_of(" \t");
    if (sp1 == std::string_view::npos)
        return fail();
    std::string_view attr = s.substr(0, sp1);
    if (!ieq(attr, attr_name))
        return fail();

    s = trim(s.substr(sp1));

    size_t sp2 = s.find_first_of(" \t");
    if (sp2 == std::string_view::npos)
        return fail();
    std::string_view op = s.substr(0, sp2);
    if (!ieq(op, "eq"))
        return fail();

    s = trim(s.substr(sp2));

    if (s.size() < 2 || s.front() != '"' || s.back() != '"')
        return fail();
    std::string_view quoted = s.substr(1, s.size() - 2);

    std::string value;
    value.reserve(quoted.size());
    for (size_t i = 0; i < quoted.size(); ++i) {
        char c = quoted[i];
        if (c == '\\' && i + 1 < quoted.size() &&
            (quoted[i + 1] == '"' || quoted[i + 1] == '\\')) {
            value.push_back(quoted[i + 1]);
            ++i;
        } else if (c == '"' || c == '\\') {
            return fail();
        } else {
            value.push_back(c);
        }
    }

    // 2026-07-25 review (LOW): the helper's contract says "every SCIM text
    // field is rejected" on an embedded NUL, but filter values took this
    // return path without the check. Low impact — the surface is
    // authorized-reader-only and Postgres text columns reject the NUL on the
    // way in anyway, so the worst case was prefix-aliasing a lookup — but a
    // documented invariant with one unchecked exit is how the next reader
    // gets it wrong.
    if (has_embedded_nul(value))
        return fail();

    return value;
}

/// `members[value eq "<id>"]` valueFilter path parser (RFC 7644 §3.5.2) used
/// only by `parse_group_patch`'s `remove` handling — not exported. Returns
/// the unescaped member id, or `nullopt` for anything not matching this
/// exact shape (caller treats that as "unsupported path", a 400).
std::optional<std::string> parse_members_value_filter(std::string_view path) {
    constexpr std::string_view kPrefix = "members[";
    if (path.size() <= kPrefix.size() || path.back() != ']')
        return std::nullopt;
    if (!ieq(path.substr(0, kPrefix.size()), kPrefix))
        return std::nullopt;
    std::string_view inner = path.substr(kPrefix.size(), path.size() - kPrefix.size() - 1);
    auto result = parse_eq_filter(inner, "value");
    if (!result)
        return std::nullopt;
    return *result;
}

/// Extract member ids from a SCIM `members` value array — each entry is
/// expected to be `{"value": "<id>", ...}` (extra IdP-sent attributes like
/// `display`/`$ref`/`type` are ignored); a bare string entry is tolerated
/// too, since some connectors send `members` as a plain array of ids rather
/// than the full RFC shape. Any other entry shape is a 400.
std::expected<std::vector<std::string>, ScimError> extract_member_values(const nlohmann::json& arr) {
    if (!arr.is_array()) {
        return std::unexpected(ScimError{400, "invalidValue", "members value must be an array"});
    }
    std::vector<std::string> out;
    out.reserve(arr.size());
    for (const auto& item : arr) {
        std::string v;
        if (item.is_object() && item.contains("value") && item["value"].is_string()) {
            v = item["value"].get<std::string>();
        } else if (item.is_string()) {
            v = item.get<std::string>();
        } else {
            return std::unexpected(
                ScimError{400, "invalidValue", "each members entry requires a string 'value'"});
        }
        if (has_embedded_nul(v)) {
            return std::unexpected(
                ScimError{400, "invalidValue", "members value contains an invalid NUL byte"});
        }
        out.push_back(std::move(v));
    }
    return out;
}

} // namespace

// ── User resource codec ─────────────────────────────────────────────────────

nlohmann::json user_to_json(const ScimResource& r, std::string_view location_base) {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaUser});
    j["id"] = r.scim_id;
    j["userName"] = r.username;
    j["active"] = r.active;
    if (!r.external_id.empty())
        j["externalId"] = r.external_id;

    nlohmann::json meta;
    meta["resourceType"] = "User";
    meta["created"] = r.created_at;
    meta["lastModified"] = r.updated_at;
    meta["version"] = "W/\"" + std::to_string(r.etag_version) + "\"";
    meta["location"] = std::string(location_base) + "/" + r.scim_id;
    j["meta"] = std::move(meta);

    return j;
}

std::expected<ScimUserInput, ScimError> parse_user(const nlohmann::json& body) {
    if (!body.is_object()) {
        return std::unexpected(
            ScimError{400, "invalidValue", "request body must be a JSON object"});
    }

    ScimUserInput input;
    // FIX-3 (Hermes LOW): body.value<std::string>(...) throws
    // nlohmann::json::type_error when the key is present but holds a
    // non-string (e.g. {"userName":123}) — that escapes this function's
    // std::expected contract and surfaces as an unhandled 500 instead of a
    // clean SCIM 400. Guard the type before extracting.
    if (body.contains("userName") && !body["userName"].is_string()) {
        return std::unexpected(ScimError{400, "invalidValue", "userName must be a string"});
    }
    input.user_name = body.value("userName", std::string{});
    if (has_embedded_nul(input.user_name)) {
        return std::unexpected(
            ScimError{400, "invalidValue", "userName contains an invalid NUL byte"});
    }
    if (input.user_name.empty()) {
        return std::unexpected(ScimError{400, "invalidValue", "userName is required"});
    }

    if (body.contains("externalId") && !body["externalId"].is_string()) {
        return std::unexpected(ScimError{400, "invalidValue", "externalId must be a string"});
    }
    input.external_id = body.value("externalId", std::string{});
    if (has_embedded_nul(input.external_id)) {
        return std::unexpected(
            ScimError{400, "invalidValue", "externalId contains an invalid NUL byte"});
    }
    if (input.external_id.size() > kMaxExternalIdLength) {
        return std::unexpected(
            ScimError{400, "invalidValue",
                     "externalId exceeds the maximum length of " +
                         std::to_string(kMaxExternalIdLength) + " bytes"});
    }

    if (body.contains("active") && body["active"].is_boolean())
        input.active = body["active"].get<bool>();

    // Unknown fields (name, emails, phoneNumbers, groups, ...) are
    // intentionally ignored — real IdPs (Okta/Entra) send them, Yuzu's
    // resource mapping doesn't model them in this slice.
    return input;
}

std::expected<ScimPatch, ScimError> parse_patch(const nlohmann::json& body) {
    if (!body.is_object() || !body.contains("Operations") ||
        !body["Operations"].is_array() || body["Operations"].empty()) {
        return std::unexpected(
            ScimError{400, "invalidValue", "Operations array is required and must not be empty"});
    }

    ScimPatch patch;

    for (const auto& operation : body["Operations"]) {
        if (!operation.is_object() || !operation.contains("op") ||
            !operation["op"].is_string()) {
            return std::unexpected(
                ScimError{400, "invalidValue", "each operation requires a string 'op'"});
        }

        const std::string op = operation["op"].get<std::string>();
        const bool is_replace_like = ieq(op, "replace") || ieq(op, "add");

        if (ieq(op, "remove")) {
            // `remove` on `active` (or any of our attrs) has no well-defined
            // meaning for a boolean/required field — treat as a no-op rather
            // than erroring, since some IdPs send a bare `{"op":"remove",
            // "path":"active"}` defensively before a `replace`. Nothing to
            // apply, so just continue to the next operation.
            continue;
        }

        if (!is_replace_like) {
            return std::unexpected(
                ScimError{400, "invalidValue", "unsupported PatchOp op: " + op});
        }

        std::string path;
        if (operation.contains("path") && operation["path"].is_string())
            path = operation["path"].get<std::string>();

        if (!operation.contains("value")) {
            return std::unexpected(
                ScimError{400, "invalidValue", "operation requires a 'value'"});
        }
        const auto& value = operation["value"];

        if (!path.empty()) {
            // Explicit-path form: {"op":"replace","path":"active","value":false}
            if (ieq(path, "active")) {
                if (!value.is_boolean()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "active value must be boolean"});
                }
                patch.active = value.get<bool>();
            } else if (ieq(path, "userName")) {
                if (!value.is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "userName value must be a string"});
                }
                if (has_embedded_nul(value.get_ref<const std::string&>())) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "userName contains an invalid NUL byte"});
                }
                patch.user_name = value.get<std::string>();
            } else if (ieq(path, "externalId")) {
                if (!value.is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "externalId value must be a string"});
                }
                if (has_embedded_nul(value.get_ref<const std::string&>())) {
                    return std::unexpected(ScimError{
                        400, "invalidValue", "externalId contains an invalid NUL byte"});
                }
                if (value.get_ref<const std::string&>().size() > kMaxExternalIdLength) {
                    return std::unexpected(ScimError{
                        400, "invalidValue",
                        "externalId exceeds the maximum length of " +
                            std::to_string(kMaxExternalIdLength) + " bytes"});
                }
                patch.external_id = value.get<std::string>();
            } else {
                return std::unexpected(
                    ScimError{400, "invalidPath", "unsupported PatchOp path: " + path});
            }
        } else {
            // Pathless value-object form:
            // {"op":"replace","value":{"active":false}} — Okta/Entra's
            // deprovision shape.
            if (!value.is_object()) {
                return std::unexpected(ScimError{
                    400, "invalidValue",
                    "pathless PatchOp value must be an object of attribute:value pairs"});
            }
            if (value.contains("active")) {
                if (!value["active"].is_boolean()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "active value must be boolean"});
                }
                patch.active = value["active"].get<bool>();
            }
            if (value.contains("userName")) {
                if (!value["userName"].is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "userName value must be a string"});
                }
                if (has_embedded_nul(value["userName"].get_ref<const std::string&>())) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "userName contains an invalid NUL byte"});
                }
                patch.user_name = value["userName"].get<std::string>();
            }
            if (value.contains("externalId")) {
                if (!value["externalId"].is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "externalId value must be a string"});
                }
                if (has_embedded_nul(value["externalId"].get_ref<const std::string&>())) {
                    return std::unexpected(ScimError{
                        400, "invalidValue", "externalId contains an invalid NUL byte"});
                }
                if (value["externalId"].get_ref<const std::string&>().size() >
                    kMaxExternalIdLength) {
                    return std::unexpected(ScimError{
                        400, "invalidValue",
                        "externalId exceeds the maximum length of " +
                            std::to_string(kMaxExternalIdLength) + " bytes"});
                }
                patch.external_id = value["externalId"].get<std::string>();
            }
        }
    }

    return patch;
}

// ── Group resource codec (#2021 slice 2) ────────────────────────────────────

nlohmann::json group_to_json(const ScimGroup& g, const std::vector<std::string>& member_scim_ids,
                             std::string_view group_location_base,
                             std::string_view users_location_base) {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaGroup});
    j["id"] = g.scim_id;
    j["displayName"] = g.display_name;
    if (!g.external_id.empty())
        j["externalId"] = g.external_id;

    nlohmann::json members = nlohmann::json::array();
    for (const auto& uid : member_scim_ids) {
        nlohmann::json m;
        m["value"] = uid;
        m["$ref"] = std::string(users_location_base) + "/" + uid;
        m["type"] = "User";
        members.push_back(std::move(m));
    }
    j["members"] = std::move(members);

    nlohmann::json meta;
    meta["resourceType"] = "Group";
    meta["created"] = g.created_at;
    meta["lastModified"] = g.updated_at;
    meta["version"] = "W/\"" + std::to_string(g.etag_version) + "\"";
    meta["location"] = std::string(group_location_base) + "/" + g.scim_id;
    j["meta"] = std::move(meta);

    return j;
}

std::expected<ScimGroupInput, ScimError> parse_group(const nlohmann::json& body) {
    if (!body.is_object()) {
        return std::unexpected(
            ScimError{400, "invalidValue", "request body must be a JSON object"});
    }

    ScimGroupInput input;
    if (body.contains("displayName") && !body["displayName"].is_string()) {
        return std::unexpected(ScimError{400, "invalidValue", "displayName must be a string"});
    }
    input.display_name = body.value("displayName", std::string{});
    if (has_embedded_nul(input.display_name)) {
        return std::unexpected(
            ScimError{400, "invalidValue", "displayName contains an invalid NUL byte"});
    }
    if (input.display_name.empty()) {
        return std::unexpected(ScimError{400, "invalidValue", "displayName is required"});
    }
    if (input.display_name.size() > kMaxDisplayNameLen) {
        return std::unexpected(
            ScimError{400, "invalidValue",
                     "displayName exceeds the maximum length of " +
                         std::to_string(kMaxDisplayNameLen) + " bytes"});
    }

    if (body.contains("externalId") && !body["externalId"].is_string()) {
        return std::unexpected(ScimError{400, "invalidValue", "externalId must be a string"});
    }
    input.external_id = body.value("externalId", std::string{});
    if (has_embedded_nul(input.external_id)) {
        return std::unexpected(
            ScimError{400, "invalidValue", "externalId contains an invalid NUL byte"});
    }
    if (input.external_id.size() > kMaxExternalIdLength) {
        return std::unexpected(
            ScimError{400, "invalidValue",
                     "externalId exceeds the maximum length of " +
                         std::to_string(kMaxExternalIdLength) + " bytes"});
    }

    if (body.contains("members")) {
        auto members = extract_member_values(body["members"]);
        if (!members)
            return std::unexpected(members.error());
        input.member_values = std::move(*members);
    }

    return input;
}

std::expected<ScimGroupPatch, ScimError> parse_group_patch(const nlohmann::json& body) {
    if (!body.is_object() || !body.contains("Operations") ||
        !body["Operations"].is_array() || body["Operations"].empty()) {
        return std::unexpected(
            ScimError{400, "invalidValue", "Operations array is required and must not be empty"});
    }

    ScimGroupPatch patch;

    for (const auto& operation : body["Operations"]) {
        if (!operation.is_object() || !operation.contains("op") ||
            !operation["op"].is_string()) {
            return std::unexpected(
                ScimError{400, "invalidValue", "each operation requires a string 'op'"});
        }
        const std::string op = operation["op"].get<std::string>();

        std::string path;
        if (operation.contains("path") && operation["path"].is_string())
            path = operation["path"].get<std::string>();

        if (ieq(op, "add")) {
            if (!operation.contains("value")) {
                return std::unexpected(ScimError{400, "invalidValue", "'add' requires a 'value'"});
            }
            const auto& value = operation["value"];
            if (path.empty() || ieq(path, "members")) {
                auto members = extract_member_values(value);
                if (!members)
                    return std::unexpected(members.error());
                patch.member_ops.push_back(
                    ScimGroupMemberOp{ScimGroupMemberOp::Kind::Add, std::move(*members)});
            } else if (ieq(path, "displayName")) {
                if (!value.is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "displayName value must be a string"});
                }
                if (has_embedded_nul(value.get_ref<const std::string&>())) {
                    return std::unexpected(ScimError{
                        400, "invalidValue", "displayName contains an invalid NUL byte"});
                }
                patch.display_name = value.get<std::string>();
                if (patch.display_name->size() > kMaxDisplayNameLen) {
                    return std::unexpected(
                        ScimError{400, "invalidValue",
                                 "displayName exceeds the maximum length of " +
                                     std::to_string(kMaxDisplayNameLen) + " bytes"});
                }
            } else if (ieq(path, "externalId")) {
                if (!value.is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "externalId value must be a string"});
                }
                if (has_embedded_nul(value.get_ref<const std::string&>())) {
                    return std::unexpected(ScimError{
                        400, "invalidValue", "externalId contains an invalid NUL byte"});
                }
                patch.external_id = value.get<std::string>();
                if (patch.external_id->size() > kMaxExternalIdLength) {
                    return std::unexpected(
                        ScimError{400, "invalidValue",
                                 "externalId exceeds the maximum length of " +
                                     std::to_string(kMaxExternalIdLength) + " bytes"});
                }
            } else {
                return std::unexpected(
                    ScimError{400, "invalidPath", "unsupported PatchOp path: " + path});
            }
        } else if (ieq(op, "remove")) {
            // Unlike Users' `remove` (a documented tolerant no-op — see
            // parse_patch), Group `remove` on `members` is meaningful and
            // load-bearing (it demotes a group-elevated admin), so a
            // missing/unsupported path here is a 400, not a silent no-op.
            if (path.empty()) {
                return std::unexpected(
                    ScimError{400, "invalidPath", "'remove' requires a path"});
            }
            if (ieq(path, "members")) {
                if (operation.contains("value") && !operation["value"].is_null()) {
                    auto members = extract_member_values(operation["value"]);
                    if (!members)
                        return std::unexpected(members.error());
                    patch.member_ops.push_back(
                        ScimGroupMemberOp{ScimGroupMemberOp::Kind::Remove, std::move(*members)});
                } else {
                    // `remove` with no filter/value on the bare `members`
                    // path means "remove every member" (RFC 7644 §3.5.2.2).
                    patch.member_ops.push_back(
                        ScimGroupMemberOp{ScimGroupMemberOp::Kind::RemoveAll, {}});
                }
            } else if (auto id = parse_members_value_filter(path)) {
                patch.member_ops.push_back(
                    ScimGroupMemberOp{ScimGroupMemberOp::Kind::Remove, {*id}});
            } else {
                return std::unexpected(
                    ScimError{400, "invalidPath", "unsupported PatchOp path: " + path});
            }
        } else if (ieq(op, "replace")) {
            if (!operation.contains("value")) {
                return std::unexpected(
                    ScimError{400, "invalidValue", "'replace' requires a 'value'"});
            }
            const auto& value = operation["value"];
            if (path.empty()) {
                if (!value.is_object()) {
                    return std::unexpected(ScimError{
                        400, "invalidValue",
                        "pathless PatchOp value must be an object of attribute:value pairs"});
                }
                if (value.contains("displayName")) {
                    if (!value["displayName"].is_string()) {
                        return std::unexpected(
                            ScimError{400, "invalidValue", "displayName value must be a string"});
                    }
                    if (has_embedded_nul(value["displayName"].get_ref<const std::string&>())) {
                        return std::unexpected(ScimError{
                            400, "invalidValue", "displayName contains an invalid NUL byte"});
                    }
                    patch.display_name = value["displayName"].get<std::string>();
                    if (patch.display_name->size() > kMaxDisplayNameLen) {
                        return std::unexpected(
                            ScimError{400, "invalidValue",
                                     "displayName exceeds the maximum length of " +
                                         std::to_string(kMaxDisplayNameLen) + " bytes"});
                    }
                }
                if (value.contains("externalId")) {
                    if (!value["externalId"].is_string()) {
                        return std::unexpected(
                            ScimError{400, "invalidValue", "externalId value must be a string"});
                    }
                    if (has_embedded_nul(value["externalId"].get_ref<const std::string&>())) {
                        return std::unexpected(ScimError{
                            400, "invalidValue", "externalId contains an invalid NUL byte"});
                    }
                    patch.external_id = value["externalId"].get<std::string>();
                    if (patch.external_id->size() > kMaxExternalIdLength) {
                        return std::unexpected(
                            ScimError{400, "invalidValue",
                                     "externalId exceeds the maximum length of " +
                                         std::to_string(kMaxExternalIdLength) + " bytes"});
                    }
                }
                if (value.contains("members")) {
                    auto members = extract_member_values(value["members"]);
                    if (!members)
                        return std::unexpected(members.error());
                    patch.member_ops.push_back(ScimGroupMemberOp{
                        ScimGroupMemberOp::Kind::ReplaceAll, std::move(*members)});
                }
            } else if (ieq(path, "members")) {
                auto members = extract_member_values(value);
                if (!members)
                    return std::unexpected(members.error());
                patch.member_ops.push_back(
                    ScimGroupMemberOp{ScimGroupMemberOp::Kind::ReplaceAll, std::move(*members)});
            } else if (ieq(path, "displayName")) {
                if (!value.is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "displayName value must be a string"});
                }
                if (has_embedded_nul(value.get_ref<const std::string&>())) {
                    return std::unexpected(ScimError{
                        400, "invalidValue", "displayName contains an invalid NUL byte"});
                }
                patch.display_name = value.get<std::string>();
                if (patch.display_name->size() > kMaxDisplayNameLen) {
                    return std::unexpected(
                        ScimError{400, "invalidValue",
                                 "displayName exceeds the maximum length of " +
                                     std::to_string(kMaxDisplayNameLen) + " bytes"});
                }
            } else if (ieq(path, "externalId")) {
                if (!value.is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "externalId value must be a string"});
                }
                if (has_embedded_nul(value.get_ref<const std::string&>())) {
                    return std::unexpected(ScimError{
                        400, "invalidValue", "externalId contains an invalid NUL byte"});
                }
                patch.external_id = value.get<std::string>();
                if (patch.external_id->size() > kMaxExternalIdLength) {
                    return std::unexpected(
                        ScimError{400, "invalidValue",
                                 "externalId exceeds the maximum length of " +
                                     std::to_string(kMaxExternalIdLength) + " bytes"});
                }
            } else {
                return std::unexpected(
                    ScimError{400, "invalidPath", "unsupported PatchOp path: " + path});
            }
        } else {
            return std::unexpected(
                ScimError{400, "invalidValue", "unsupported PatchOp op: " + op});
        }
    }

    return patch;
}

// ── Envelopes ────────────────────────────────────────────────────────────────

nlohmann::json error(int status, std::string_view detail, std::string_view scim_type) {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaError});
    j["status"] = std::to_string(status); // SCIM `status` is a STRING.
    if (!scim_type.empty())
        j["scimType"] = std::string(scim_type);
    j["detail"] = std::string(detail);
    return j;
}

nlohmann::json error(const ScimError& e) {
    return error(e.status, e.detail, e.scim_type);
}

nlohmann::json list_response(const std::vector<nlohmann::json>& resources, int total_results,
                             int start_index, int items_per_page) {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaListResponse});
    j["totalResults"] = total_results;
    j["startIndex"] = start_index;
    j["itemsPerPage"] = items_per_page;
    j["Resources"] = resources;
    return j;
}

// ── Filter parsing ───────────────────────────────────────────────────────────

std::expected<std::string, ScimError> parse_username_filter(std::string_view filter) {
    // Expected shape: `userName eq "value"` — attribute + operator
    // case-insensitive, value double-quoted with \" and \\ escapes.
    return parse_eq_filter(filter, "userName");
}

std::expected<std::string, ScimError> parse_displayname_filter(std::string_view filter) {
    // Expected shape: `displayName eq "value"` — same rules as
    // `parse_username_filter`, different attribute.
    return parse_eq_filter(filter, "displayName");
}

// ── Discovery documents ──────────────────────────────────────────────────────

nlohmann::json service_provider_config() {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaServiceProviderConfig});
    j["patch"] = {{"supported", true}};
    j["bulk"] = {{"supported", false}, {"maxOperations", 0}, {"maxPayloadSize", 0}};
    j["filter"] = {{"supported", true}, {"maxResults", kMaxScimListResults}};
    j["changePassword"] = {{"supported", false}};
    j["sort"] = {{"supported", false}};
    // S-ETAG-FALSE: `meta.version`/`ETag` are emitted as informational
    // versioning only — there is no `If-Match` conditional-write enforcement
    // on PUT/PATCH in this slice, so advertising etag support would invite a
    // connector to rely on 412 semantics that never fire.
    j["etag"] = {{"supported", false}};
    j["authenticationSchemes"] = nlohmann::json::array(
        {{{"type", "oauthbearertoken"}, {"name", "OAuth Bearer Token"}, {"primary", true}}});
    j["meta"] = {{"resourceType", "ServiceProviderConfig"}};
    return j;
}

nlohmann::json resource_types() {
    nlohmann::json user_type;
    user_type["id"] = "User";
    user_type["name"] = "User";
    user_type["endpoint"] = "/Users";
    user_type["schema"] = kSchemaUser;
    user_type["meta"] = {{"resourceType", "ResourceType"}};

    nlohmann::json group_type;
    group_type["id"] = "Group";
    group_type["name"] = "Group";
    group_type["endpoint"] = "/Groups";
    group_type["schema"] = kSchemaGroup;
    group_type["meta"] = {{"resourceType", "ResourceType"}};

    return list_response({user_type, group_type}, 2, 1, 2);
}

nlohmann::json schemas() {
    nlohmann::json user_schema;
    user_schema["id"] = kSchemaUser;
    user_schema["name"] = "User";
    user_schema["description"] = "Yuzu SCIM User";
    user_schema["attributes"] = nlohmann::json::array(
        {{{"name", "userName"},
          {"type", "string"},
          {"required", true},
          {"uniqueness", "server"}},
         {{"name", "active"}, {"type", "boolean"}, {"required", false}},
         {{"name", "externalId"}, {"type", "string"}, {"required", false}}});
    user_schema["meta"] = {{"resourceType", "Schema"}};

    nlohmann::json group_schema;
    group_schema["id"] = kSchemaGroup;
    group_schema["name"] = "Group";
    group_schema["description"] = "Yuzu SCIM Group";
    group_schema["attributes"] = nlohmann::json::array(
        {{{"name", "displayName"},
          {"type", "string"},
          {"required", true},
          {"uniqueness", "none"}},
         {{"name", "externalId"}, {"type", "string"}, {"required", false}},
         {{"name", "members"},
          {"type", "complex"},
          {"multiValued", true},
          {"required", false}}});
    group_schema["meta"] = {{"resourceType", "Schema"}};

    return list_response({user_schema, group_schema}, 2, 1, 2);
}

} // namespace yuzu::server::scim
