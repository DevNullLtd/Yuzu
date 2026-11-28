/// @file software_curation_routes.cpp
/// See software_curation_routes.hpp.

#include "software_curation_routes.hpp"

#include "list_keyset.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error, a4_denial, ensure_correlation_id
#include "rest_audit.hpp"            // detail::emit_behavioral_audit, try_persist_audit
#include "software_curation_api.hpp"
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

namespace api = software_curation_api;

namespace {

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

// Maps an API reply onto the response.
void respond(httplib::Response& res, const api::Reply& r) {
    using Kind = api::Reply::Kind;
    switch (r.kind) {
    case Kind::Ok:
        res.set_content(ok_body(r.body), "application/json");
        return;
    case Kind::Created:
        res.status = 201;
        res.set_content(ok_body(r.body), "application/json");
        return;
    case Kind::BadRequest:
        fail(res, 400, r.message);
        return;
    case Kind::NotFound:
        fail(res, 404, r.message);
        return;
    case Kind::Conflict:
        fail(res, 409, r.message);
        return;
    case Kind::Unavailable:
        fail(res, 503, r.message, {.retry_after_ms = r.retry_after_ms, .remediation = r.remediation});
        return;
    }
}

// A refusal row is plain; the `requested` row ahead of a write flags a lost row on the response
// (Sec-Audit-Failed) and carries the correlation id.
api::AuditSink audit_for(const SoftwareCurationRoutes::Deps& deps, const httplib::Request& req,
                         httplib::Response& res) {
    return [&deps, &req, &res](const char* verb, const char* result, const std::string& target,
                               const std::string& detail_text, bool signal_failure) {
        if (!signal_failure)
            return detail::try_persist_audit(deps.audit_fn, req, verb, result, api::kTargetType,
                                             target, detail_text);
        const auto cid = detail::ensure_correlation_id(res);
        return detail::emit_behavioral_audit(deps.audit_fn, req, res, verb, result, api::kTargetType,
                                             target, detail_text + "; cid=" + cid);
    };
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

    // -- GET status -----------------------------------------------------------------------
    sink.Get("/api/v1/inventory/software/normalization/status",
             [deps, admit](const httplib::Request& req, httplib::Response& res) {
                 if (!admit(req, res, "Read", api::kVerbStatus))
                     return;
                 respond(res, api::status(deps.registry));
             });

    // -- GET queue ------------------------------------------------------------------------
    sink.Get("/api/v1/inventory/software/normalization/queue", [deps, admit](const httplib::Request& req,
                                                          httplib::Response& res) {
        if (!admit(req, res, "Read", api::kVerbQueue))
            return;
        for (const char* name : {"status", "limit", "cursor"}) {
            if (req.get_param_value_count(name) > 1) {
                fail(res, 400, std::string{"repeated query parameter: "} + name);
                return;
            }
        }
        const std::string status_text = req.get_param_value("status");
        const std::string limit_text = req.get_param_value("limit");
        const std::string cursor_text = req.get_param_value("cursor");
        std::optional<std::string_view> status;
        if (req.has_param("status"))
            status = status_text;
        std::optional<std::string_view> limit;
        if (req.has_param("limit"))
            limit = limit_text;
        respond(res, api::queue(deps.registry, status, limit, cursor_text));
    });

    // -- POST aliases (curate a title) ----------------------------------------------------
    sink.Post("/api/v1/inventory/software/normalization/aliases",
              [deps, admit](const httplib::Request& req, httplib::Response& res) {
                  if (!admit(req, res, "Write", api::kVerbAlias))
                      return;
                  const auto body = nlohmann::json::parse(req.body, nullptr, false);
                  respond(res, api::curate_alias(deps.registry, body, audit_for(deps, req, res)));
              });

    // -- POST queue/{key}/reject ----------------------------------------------------------
    sink.Post(R"(/api/v1/inventory/software/normalization/queue/([A-Za-z0-9_-]+)/reject)",
              [deps, admit](const httplib::Request& req, httplib::Response& res) {
                  if (!admit(req, res, "Write", api::kVerbReject))
                      return;
                  respond(res, api::reject(deps.registry, req.matches[1].str(),
                                           audit_for(deps, req, res)));
              });

    // -- POST pack ------------------------------------------------------------------------
    sink.Post("/api/v1/inventory/software/normalization/pack", [deps, admit](
                                                const httplib::Request& req,
                                                httplib::Response& res) {
        static constexpr const char* kVerb = api::kVerbPack;
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
        respond(res, api::replace_pack(deps.registry, req.body, session->username,
                                       audit_for(deps, req, res)));
    });
}

} // namespace yuzu::server
