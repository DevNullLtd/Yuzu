/// @file software_curation_routes.cpp
/// See software_curation_routes.hpp.

#include "software_curation_routes.hpp"

#include "list_keyset.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error, a4_denial, ensure_correlation_id
#include "rest_audit.hpp"            // detail::emit_behavioral_audit, try_persist_audit
#include "software_normalization_pack.hpp"
#include "web_utils.hpp" // audit_token

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <limits>
#include <vector>

namespace yuzu::server {

namespace curation_keys {

namespace {
constexpr char kSep = '\x1F';

/// Split `s` on kSep into exactly `n` fields.
std::optional<std::vector<std::string>> split_exact(std::string_view s, std::size_t n) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const auto p = s.find(kSep, start);
        if (p == std::string_view::npos) {
            out.emplace_back(s.substr(start));
            break;
        }
        out.emplace_back(s.substr(start, p - start));
        start = p + 1;
    }
    if (out.size() != n)
        return std::nullopt;
    return out;
}

bool has_sep(std::string_view s) {
    return s.find(kSep) != std::string_view::npos;
}

// Bytes a decoded field must not carry: exec_params binds c_str() (a NUL truncates the value,
// so the key would act on a different row) and Postgres refuses invalid UTF-8 (22021).
bool bindable(std::string_view s) {
    return s.find('\0') == std::string_view::npos && valid_utf8(s);
}
} // namespace

std::optional<std::string> encode_key(const Triple& t) {
    if (has_sep(t.raw_name) || has_sep(t.raw_publisher) || has_sep(t.ecosystem))
        return std::nullopt;
    return keyset::b64url_encode(t.raw_name + kSep + t.raw_publisher + kSep + t.ecosystem);
}

std::optional<Triple> decode_key(std::string_view key) {
    auto raw = keyset::b64url_decode(key);
    if (!raw || raw->size() > kMaxKeyBytes || keyset::b64url_encode(*raw) != key ||
        !bindable(*raw))
        return std::nullopt;
    auto f = split_exact(*raw, 3);
    if (!f || (*f)[0].empty() || (*f)[2].empty())
        return std::nullopt;
    return Triple{std::move((*f)[0]), std::move((*f)[1]), std::move((*f)[2])};
}

std::optional<std::string> encode_cursor(const CurationCursor& c) {
    if (has_sep(c.raw_name) || has_sep(c.raw_publisher) || has_sep(c.ecosystem))
        return std::nullopt;
    return keyset::b64url_encode(std::to_string(c.device_count) + kSep + c.raw_name + kSep +
                                 c.raw_publisher + kSep + c.ecosystem);
}

std::optional<CurationCursor> decode_cursor(std::string_view token) {
    auto raw = keyset::b64url_decode(token);
    if (!raw || raw->size() > kMaxKeyBytes + 24 || keyset::b64url_encode(*raw) != token ||
        !bindable(*raw))
        return std::nullopt;
    const auto p = raw->find(kSep);
    if (p == std::string::npos)
        return std::nullopt;
    const auto count = keyset::parse_int(std::string_view{*raw}.substr(0, p), 0,
                                         std::numeric_limits<std::int64_t>::max());
    if (!count)
        return std::nullopt;
    auto f = split_exact(std::string_view{*raw}.substr(p + 1), 3);
    if (!f || (*f)[0].empty() || (*f)[2].empty())
        return std::nullopt;
    return CurationCursor{true, *count, std::move((*f)[0]), std::move((*f)[1]),
                          std::move((*f)[2])};
}

} // namespace curation_keys

namespace {

constexpr int kDefaultQueueLimit = 100;

// Audit verbs. The two read verbs appear only as a `denied` row (a service-scoped token's
// refusal); an admitted read is never audited.
constexpr const char* kVerbStatus = "inventory.software.curation.status";
constexpr const char* kVerbQueue = "inventory.software.curation.queue";
constexpr const char* kVerbAlias = "inventory.software.curation.alias";
constexpr const char* kVerbReject = "inventory.software.curation.reject";
constexpr const char* kVerbPack = "inventory.software.curation.pack";

std::string dump_safe(const nlohmann::json& j) {
    // Raw titles come from agents and may not be valid UTF-8: replace, never throw.
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::string ok_body(nlohmann::json data) {
    return dump_safe({{"data", std::move(data)}, {"meta", {{"api_version", "v1"}}}});
}

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

void unavailable(httplib::Response& res, std::string_view message) {
    fail(res, 503, message, {.retry_after_ms = 5000, .remediation = "retry the request"});
}

} // namespace

void SoftwareCurationRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    // The shared prologue: authenticated, not a service-scoped token (these are fleet-wide
    // operator surfaces; a service token has no Inventory grant to admit it), the GLOBAL
    // permission, then a wired store. false == the response is already written.
    auto admit = [deps](const httplib::Request& req, httplib::Response& res,
                        const char* operation, const char* verb) -> std::optional<auth::Session> {
        detail::ensure_correlation_id(res);
        if (!deps.auth_fn || !deps.perm_fn) {
            spdlog::error("SoftwareCurationRoutes: auth/permission gate unwired; failing closed");
            fail(res, 503, "service unavailable");
            return std::nullopt;
        }
        const auto session = deps.auth_fn(req, res);
        if (!session)
            return std::nullopt;
        if (!session->token_scope_service.empty()) {
            // No `.permission`: no grant would admit a service-scoped token here. Audited
            // `denied`, as the sibling software routes do (inventory_routes.cpp
            // deny_service_scoped). A permission refusal is audited by perm_fn itself.
            res.status = 403;
            res.set_content(detail::a4_denial(res, 403,
                                              "service-scoped tokens may not use the software "
                                              "curation queue"),
                            "application/json");
            (void)detail::try_persist_audit(deps.audit_fn, req, verb, "denied", "Inventory",
                                            "fleet",
                                            "service-scoped token denied on the software curation "
                                            "queue");
            return std::nullopt;
        }
        if (!deps.perm_fn(req, res, "Inventory", operation))
            return std::nullopt;
        if (!deps.registry) {
            fail(res, 503, "product registry not available");
            return std::nullopt;
        }
        return session;
    };
    // Audit BEFORE the write; fail closed on a persist failure.
    auto audit_first = [deps](const httplib::Request& req, httplib::Response& res,
                              const char* verb, const std::string& target_id,
                              const std::string& detail_text) -> bool {
        const auto cid = detail::ensure_correlation_id(res);
        if (detail::emit_behavioral_audit(deps.audit_fn, req, res, verb, "requested", "Inventory",
                                          target_id, detail_text + "; cid=" + cid))
            return true;
        fail(res, 503, "audit subsystem unavailable - request not served",
             {.retry_after_ms = 5000});
        return false;
    };
    auto deny_400 = [deps](const httplib::Request& req, httplib::Response& res, const char* verb,
                           const std::string& reason) {
        (void)detail::try_persist_audit(deps.audit_fn, req, verb, "denied", "Inventory", "", reason);
        fail(res, 400, reason);
    };

    // -- GET status -----------------------------------------------------------------------
    sink.Get("/api/v1/inventory/software/normalization/status",
             [deps, admit](const httplib::Request& req, httplib::Response& res) {
                 if (!admit(req, res, "Read", kVerbStatus))
                     return;
                 const auto st = deps.registry->normalization_status();
                 if (!st) {
                     unavailable(res, "normalisation status read degraded");
                     return;
                 }
                 res.set_content(
                     ok_body({{"pack_version", st->pack_version},
                              {"loaded_at", st->loaded_at},
                              {"loaded_by", st->loaded_by},
                              {"titles_normalized", st->titles_normalized},
                              {"titles_unnormalized", st->titles_unnormalized},
                              {"queue_open", st->queue_open},
                              {"queue_rejected", st->queue_rejected}}),
                     "application/json");
             });

    // -- GET queue ------------------------------------------------------------------------
    sink.Get("/api/v1/inventory/software/normalization/queue", [deps, admit](const httplib::Request& req,
                                                          httplib::Response& res) {
        if (!admit(req, res, "Read", kVerbQueue))
            return;
        for (const char* name : {"status", "limit", "cursor"}) {
            if (req.get_param_value_count(name) > 1) {
                fail(res, 400, std::string{"repeated query parameter: "} + name);
                return;
            }
        }
        std::string status = req.has_param("status") ? req.get_param_value("status") : "open";
        if (status != "open" && status != "rejected" && status != "all") {
            fail(res, 400, "status must be open, rejected or all");
            return;
        }
        if (status == "all")
            status.clear();
        std::int64_t limit = kDefaultQueueLimit;
        if (req.has_param("limit")) {
            const auto v = keyset::parse_int(req.get_param_value("limit"), 1, kCurationQueueMaxLimit);
            if (!v) {
                fail(res, 400, "limit must be an integer from 1 to " +
                                   std::to_string(kCurationQueueMaxLimit));
                return;
            }
            limit = *v;
        }
        CurationCursor after;
        if (req.has_param("cursor") && !req.get_param_value("cursor").empty()) {
            auto c = curation_keys::decode_cursor(req.get_param_value("cursor"));
            if (!c) {
                fail(res, 400, "invalid cursor");
                return;
            }
            after = std::move(*c);
        }
        const auto page = deps.registry->list_curation_queue(status, static_cast<int>(limit), after);
        if (!page) {
            unavailable(res, "curation queue read degraded");
            return;
        }
        nlohmann::json items = nlohmann::json::array();
        for (const auto& r : page->rows) {
            const auto key = curation_keys::encode_key({r.raw_name, r.raw_publisher, r.ecosystem});
            items.push_back({{"key", key ? nlohmann::json(*key) : nlohmann::json(nullptr)},
                             {"raw_name", r.raw_name},
                             {"raw_publisher", r.raw_publisher},
                             {"ecosystem", r.ecosystem},
                             {"device_count", r.device_count},
                             {"status", r.status},
                             {"first_queued_at", r.first_queued_at},
                             {"last_seen_at", r.last_seen_at}});
        }
        nlohmann::json next = nullptr;
        if (page->has_more && !page->rows.empty()) {
            const auto& last = page->rows.back();
            if (const auto tok = curation_keys::encode_cursor(
                    {true, last.device_count, last.raw_name, last.raw_publisher, last.ecosystem}))
                next = *tok;
        }
        res.set_content(ok_body({{"items", std::move(items)},
                                 {"count", page->rows.size()},
                                 {"next_cursor", std::move(next)}}),
                        "application/json");
    });

    // -- POST aliases (curate a title) ----------------------------------------------------
    sink.Post("/api/v1/inventory/software/normalization/aliases", [deps, admit, audit_first, deny_400](
                                                   const httplib::Request& req,
                                                   httplib::Response& res) {
        static constexpr const char* kVerb = kVerbAlias;
        if (!admit(req, res, "Write", kVerb))
            return;
        const auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) {
            deny_400(req, res, kVerb, "body must be a JSON object");
            return;
        }
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
            if (err) {
                deny_400(req, res, kVerb, *err);
                return;
            }
        }
        if (!known_ecosystem(eco)) {
            deny_400(req, res, kVerb, "unknown ecosystem");
            return;
        }
        // An omitted category is passed through empty: the store keeps an existing product's
        // category and gives a new product "other".
        if (!category.empty() &&
            std::find(kCategories.begin(), kCategories.end(), category) == kCategories.end()) {
            deny_400(req, res, kVerb, "unknown category");
            return;
        }
        if (!valid_cpe_product(cpe) || reserved_cpe_product(cpe)) {
            deny_400(req, res, kVerb, "cpe_product has an invalid character or is a reserved value");
            return;
        }
        const auto keys = derive_curated_alias(eco, raw_name, raw_pub, vendor, product, edition);
        if (!keys) {
            deny_400(req, res, kVerb, keys.error());
            return;
        }
        if (!audit_first(req, res, kVerb, keys->norm_key,
                         "ecosystem=" + audit_token(eco) + " alias=" + audit_token(keys->alias_key) +
                             " publisher=" + audit_token(keys->alias_publisher)))
            return;
        const auto pid = deps.registry->curate_alias(eco, *keys, category, cpe);
        if (!pid) {
            spdlog::warn("SoftwareCurationRoutes: curate_alias failed: {}", pid.error());
            unavailable(res, "curation write failed");
            return;
        }
        res.status = 201;
        res.set_content(ok_body({{"product_id", *pid},
                                 {"norm_key", keys->norm_key},
                                 {"alias_source", keys->source},
                                 {"alias_key", keys->alias_key},
                                 {"alias_publisher", keys->alias_publisher}}),
                        "application/json");
    });

    // -- POST queue/{key}/reject ----------------------------------------------------------
    sink.Post(R"(/api/v1/inventory/software/normalization/queue/([A-Za-z0-9_-]+)/reject)",
              [deps, admit, audit_first, deny_400](const httplib::Request& req,
                                                   httplib::Response& res) {
                  static constexpr const char* kVerb = kVerbReject;
                  if (!admit(req, res, "Write", kVerb))
                      return;
                  const auto t = curation_keys::decode_key(req.matches[1].str());
                  if (!t) {
                      deny_400(req, res, kVerb, "invalid queue key");
                      return;
                  }
                  if (!audit_first(req, res, kVerb, audit_token(t->ecosystem),
                                   "ecosystem=" + audit_token(t->ecosystem) +
                                       " raw_name=" + audit_token(t->raw_name) +
                                       " raw_publisher=" + audit_token(t->raw_publisher)))
                      return;
                  const auto done =
                      deps.registry->reject_curation(t->raw_name, t->raw_publisher, t->ecosystem);
                  if (!done) {
                      unavailable(res, "curation write failed");
                      return;
                  }
                  if (!*done) {
                      fail(res, 404, "no open queue entry for that key");
                      return;
                  }
                  res.set_content(ok_body({{"rejected", true}}), "application/json");
              });

    // -- POST pack ------------------------------------------------------------------------
    sink.Post("/api/v1/inventory/software/normalization/pack", [deps, admit, audit_first, deny_400](
                                                const httplib::Request& req,
                                                httplib::Response& res) {
        static constexpr const char* kVerb = kVerbPack;
        const auto session = admit(req, res, "Write", kVerb);
        if (!session)
            return;
        // The media type alone (RFC 9110 8.3.1): drop parameters, trim, compare
        // case-insensitively. `text/csvx` is not `text/csv`.
        auto ct = req.get_header_value("Content-Type");
        ct.resize(std::min(ct.find(';'), ct.size()));
        const auto first = ct.find_first_not_of(" \t");
        const auto last = ct.find_last_not_of(" \t");
        ct = first == std::string::npos ? std::string{} : ct.substr(first, last - first + 1);
        std::transform(ct.begin(), ct.end(), ct.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (ct != "text/csv" && ct != "text/plain") {
            (void)detail::try_persist_audit(deps.audit_fn, req, kVerb, "denied", "Inventory", "",
                                            "unsupported content type");
            fail(res, 415, "Content-Type must be text/csv or text/plain");
            return;
        }
        // The parser is the trust boundary: its caps (bytes, rows, fields, NUL) apply here.
        auto pack = parse_normalization_pack(req.body);
        if (!pack) {
            deny_400(req, res, kVerb, pack.error());
            return;
        }
        if (!audit_first(req, res, kVerb, audit_token(pack->pack_version),
                         "pack_version=" + audit_token(pack->pack_version) +
                             " sha256=" + audit_token(pack->sha256) +
                             " rows=" + std::to_string(pack->rows.size())))
            return;
        const auto out = deps.registry->replace_pack(*pack, session->username);
        if (!out) {
            spdlog::warn("SoftwareCurationRoutes: replace_pack failed: {}", out.error());
            unavailable(res, "pack replace failed");
            return;
        }
        if (*out == PackReplaceOutcome::same_version) {
            fail(res, 409, "the stored pack already has version " + pack->pack_version);
            return;
        }
        res.set_content(ok_body({{"pack_version", pack->pack_version},
                                 {"sha256", pack->sha256},
                                 {"rows", pack->rows.size()}}),
                        "application/json");
    });
}

} // namespace yuzu::server
