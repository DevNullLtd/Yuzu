/// @file software_curation_api.cpp
/// See software_curation_api.hpp. The bodies moved here verbatim from
/// software_curation_routes.cpp; the REST routes keep the gate, the Content-Type check on the pack
/// route, the 201 and the envelope.

#include "software_curation_api.hpp"

#include "list_keyset.hpp"
#include "software_curation_routes.hpp" // curation_keys: the queue key and cursor codecs
#include "software_normalization_pack.hpp"
#include "web_utils.hpp" // audit_token

#include <spdlog/spdlog.h>

#include <algorithm>
#include <utility>

namespace yuzu::server::software_curation_api {

using json = nlohmann::json;
using Kind = Reply::Kind;

namespace {

Reply bad_request(std::string message) {
    return Reply{.kind = Kind::BadRequest, .message = std::move(message)};
}

Reply unavailable(std::string message) {
    return Reply{.kind = Kind::Unavailable,
                 .message = std::move(message),
                 .retry_after_ms = 5000,
                 .remediation = "retry the request"};
}

// A refusal of the caller's input: audited `denied` under `verb` (best effort, the refusal stands
// either way), no target.
Reply deny(const AuditSink& audit, const char* verb, const std::string& reason) {
    (void)audit(verb, "denied", "", reason, false);
    return bad_request(reason);
}

// Audit BEFORE the write; fail closed on a persist failure. An empty optional means the row is
// stored and the write may go on.
std::optional<Reply> audit_first(const AuditSink& audit, const char* verb,
                                 const std::string& target_id, const std::string& detail_text) {
    if (audit(verb, "requested", target_id, detail_text, true))
        return std::nullopt;
    return Reply{.kind = Kind::Unavailable,
                 .message = "audit subsystem unavailable - request not served",
                 .retry_after_ms = 5000};
}

} // namespace

Reply status(ProductRegistryStore* registry) {
    const auto st = registry->normalization_status();
    if (!st)
        return unavailable("normalisation status read degraded");
    return Reply{.kind = Kind::Ok,
                 .body = {{"pack_version", st->pack_version},
                          {"loaded_at", st->loaded_at},
                          {"loaded_by", st->loaded_by},
                          {"titles_normalized", st->titles_normalized},
                          {"titles_unnormalized", st->titles_unnormalized},
                          {"queue_open", st->queue_open},
                          {"queue_rejected", st->queue_rejected}}};
}

Reply queue(ProductRegistryStore* registry, const std::optional<std::string_view>& status_token,
            const std::optional<std::string_view>& limit_text, std::string_view cursor) {
    std::string filter = status_token ? std::string{*status_token} : std::string{"open"};
    if (filter != "open" && filter != "rejected" && filter != "all")
        return bad_request("status must be open, rejected or all");
    if (filter == "all")
        filter.clear();
    std::int64_t limit = kDefaultQueueLimit;
    if (limit_text) {
        const auto v = keyset::parse_int(*limit_text, 1, kCurationQueueMaxLimit);
        if (!v)
            return bad_request("limit must be an integer from 1 to " +
                               std::to_string(kCurationQueueMaxLimit));
        limit = *v;
    }
    CurationCursor after;
    if (!cursor.empty()) {
        auto c = curation_keys::decode_cursor(cursor);
        if (!c)
            return bad_request("invalid cursor");
        after = std::move(*c);
    }
    const auto page = registry->list_curation_queue(filter, static_cast<int>(limit), after);
    if (!page)
        return unavailable("curation queue read degraded");
    json items = json::array();
    for (const auto& r : page->rows) {
        const auto key = curation_keys::encode_key({r.raw_name, r.raw_publisher, r.ecosystem});
        items.push_back({{"key", key ? json(*key) : json(nullptr)},
                         {"raw_name", r.raw_name},
                         {"raw_publisher", r.raw_publisher},
                         {"ecosystem", r.ecosystem},
                         {"device_count", r.device_count},
                         {"status", r.status},
                         {"first_queued_at", r.first_queued_at},
                         {"last_seen_at", r.last_seen_at}});
    }
    json next = nullptr;
    if (page->has_more && !page->rows.empty()) {
        const auto& last = page->rows.back();
        if (const auto tok = curation_keys::encode_cursor(
                {true, last.device_count, last.raw_name, last.raw_publisher, last.ecosystem}))
            next = *tok;
    }
    return Reply{.kind = Kind::Ok,
                 .body = {{"items", std::move(items)},
                          {"count", page->rows.size()},
                          {"next_cursor", std::move(next)}}};
}

Reply curate_alias(ProductRegistryStore* registry, const json& body, const AuditSink& audit) {
    static constexpr const char* kVerb = kVerbAlias;
    if (body.is_discarded() || !body.is_object())
        return deny(audit, kVerb, "body must be a JSON object");
    // Every field is a string of at most kMaxFieldBytes with no NUL.
    const auto field = [&](const char* name, bool required,
                           std::string& out) -> std::optional<std::string> {
        const auto it = body.find(name);
        if (it == body.end() || it->is_null()) {
            if (required)
                return std::string{name} + " is required";
            return std::nullopt;
        }
        if (!it->is_string())
            return std::string{name} + " must be a string";
        out = it->get<std::string>();
        if (out.size() > kMaxFieldBytes)
            return std::string{name} + " exceeds " + std::to_string(kMaxFieldBytes) + " bytes";
        if (out.find('\0') != std::string::npos)
            return std::string{name} + " holds a NUL byte";
        if (required && out.empty())
            return std::string{name} + " is required";
        return std::nullopt;
    };
    std::string eco, raw_name, raw_pub, vendor, product, edition, category, cpe;
    for (const auto& err : {field("ecosystem", true, eco), field("raw_name", true, raw_name),
                            field("raw_publisher", false, raw_pub), field("vendor", true, vendor),
                            field("product", true, product), field("edition", false, edition),
                            field("category", false, category),
                            field("cpe_product", false, cpe)}) {
        if (err)
            return deny(audit, kVerb, *err);
    }
    if (!known_ecosystem(eco))
        return deny(audit, kVerb, "unknown ecosystem");
    // An omitted category is passed through empty: the store keeps an existing product's
    // category and gives a new product "other".
    if (!category.empty() &&
        std::find(kCategories.begin(), kCategories.end(), category) == kCategories.end())
        return deny(audit, kVerb, "unknown category");
    if (!valid_cpe_product(cpe) || reserved_cpe_product(cpe))
        return deny(audit, kVerb, "cpe_product has an invalid character or is a reserved value");
    const auto keys = derive_curated_alias(eco, raw_name, raw_pub, vendor, product, edition);
    if (!keys)
        return deny(audit, kVerb, keys.error());
    if (auto refused = audit_first(audit, kVerb, keys->norm_key,
                                   "ecosystem=" + audit_token(eco) +
                                       " alias=" + audit_token(keys->alias_key) +
                                       " publisher=" + audit_token(keys->alias_publisher)))
        return std::move(*refused);
    const auto pid = registry->curate_alias(eco, *keys, category, cpe);
    if (!pid) {
        spdlog::warn("software_curation_api: curate_alias failed: {}", pid.error());
        return unavailable("curation write failed");
    }
    return Reply{.kind = Kind::Created,
                 .body = {{"product_id", *pid},
                          {"norm_key", keys->norm_key},
                          {"alias_source", keys->source},
                          {"alias_key", keys->alias_key},
                          {"alias_publisher", keys->alias_publisher}}};
}

Reply reject(ProductRegistryStore* registry, std::string_view key, const AuditSink& audit) {
    static constexpr const char* kVerb = kVerbReject;
    const auto t = curation_keys::decode_key(key);
    if (!t)
        return deny(audit, kVerb, "invalid queue key");
    if (auto refused = audit_first(audit, kVerb, audit_token(t->ecosystem),
                                   "ecosystem=" + audit_token(t->ecosystem) +
                                       " raw_name=" + audit_token(t->raw_name) +
                                       " raw_publisher=" + audit_token(t->raw_publisher)))
        return std::move(*refused);
    const auto done = registry->reject_curation(t->raw_name, t->raw_publisher, t->ecosystem);
    if (!done)
        return unavailable("curation write failed");
    if (!*done)
        return Reply{.kind = Kind::NotFound, .message = "no open queue entry for that key"};
    return Reply{.kind = Kind::Ok, .body = {{"rejected", true}}};
}

Reply replace_pack(ProductRegistryStore* registry, std::string_view content,
                   const std::string& username, const AuditSink& audit) {
    static constexpr const char* kVerb = kVerbPack;
    // The parser is the trust boundary: its caps (bytes, rows, fields, NUL) apply here.
    auto pack = parse_normalization_pack(content);
    if (!pack)
        return deny(audit, kVerb, pack.error());
    if (auto refused = audit_first(audit, kVerb, audit_token(pack->pack_version),
                                   "pack_version=" + audit_token(pack->pack_version) +
                                       " sha256=" + audit_token(pack->sha256) +
                                       " rows=" + std::to_string(pack->rows.size())))
        return std::move(*refused);
    const auto out = registry->replace_pack(*pack, username);
    if (!out) {
        spdlog::warn("software_curation_api: replace_pack failed: {}", out.error());
        return unavailable("pack replace failed");
    }
    if (*out == PackReplaceOutcome::same_version)
        return Reply{.kind = Kind::Conflict,
                     .message = "the stored pack already has version " + pack->pack_version};
    return Reply{.kind = Kind::Ok,
                 .body = {{"pack_version", pack->pack_version},
                          {"sha256", pack->sha256},
                          {"rows", pack->rows.size()}}};
}

} // namespace yuzu::server::software_curation_api
