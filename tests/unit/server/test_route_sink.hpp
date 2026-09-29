#pragma once

// TestRouteSink — in-process implementation of HttpRouteSink for unit
// tests. Registered handlers are stored by (method, pattern); dispatch()
// matches an incoming (method, path) against every registration via
// std::regex (mirrors httplib::Server's routing semantics — patterns may
// be plain strings or raw-string regexes like R"(/api/v1/groups/([^/]+))").
//
// Why: tests that previously stood up an httplib::Server on a random port
// + std::thread acceptor crash under TSan with no TSan report (#438).
// This sink lets each route owner's `register_routes(HttpRouteSink&, ...)`
// overload be exercised in-process. Single-threaded, no sockets, nothing
// for TSan's interceptors to fight with.
//
// WHAT THIS SINK MODELS, AND WHAT IT DOES NOT (#1786).
// It reproduces httplib::Server's REQUEST PARSING for the handful of fields
// handlers actually read: the path, the query string, an
// `application/x-www-form-urlencoded` body (both into the same `req.params`
// multimap, query first so query values win — httplib's own precedence),
// headers, and the regex captures in `req.matches`. Anything else is NOT
// modelled, and a test must not be read as evidence about it:
//   - no percent-decoding of the path (httplib routes on
//     `decode_path_component`), so `%2E`-encoded paths behave differently;
//   - no multipart and no chunked transfer-encoding;
//   - `extra_headers` is a map, so DUPLICATE headers (the classic
//     `Origin:`-twice CSRF desync probe) cannot be synthesized at all, and
//     `Request::set_header` SILENTLY DROPS any value failing `is_field_value`
//     (e.g. one padded with whitespace, which httplib trims on the wire before
//     it ever reaches set_header) — so a header a test sets may simply not be
//     there;
//   - none of the request PIPELINE runs — no pre-routing chokepoint
//     (on-behalf-of rejection, quotas, rate limiting), no post-routing
//     handler (security headers). A gate that moves into pre-routing will
//     leave every sink test green while the route-level gate is gone.
// A fixture that needs any of the above needs a live socket, not this sink.
//
// TWO INVARIANTS FOR FIXTURES USING THIS SINK:
//  1. DECLARE THE SINK AFTER the route owner it registers. The sink stores
//     handlers capturing the owner's `this`; declaring it first means the
//     owner is destroyed while those handlers are still live. That is benign
//     only for as long as nothing dispatches during teardown — do not rely
//     on it. (27 of the 41 existing fixtures have the risky order; new ones
//     should not add to that.)
//  2. PASS THE CONTENT-TYPE EXPLICITLY when posting a form body. `Post(path,
//     body)` defaults to `application/json`, which does NOT populate
//     `req.params` — a handler reading `req.has_param(...)` would then be
//     tested through whatever fallback it has rather than the production
//     branch. That is exactly the false-green #1786 fixed; it is re-armable
//     by omitting the argument.
//
// `httplib::detail::` is an INTERNAL httplib API (pinned to 0.37.x here:
// `parse_query_text`, `extract_media_type`). That dependency predates this
// file's current form and is deliberate — no public equivalent exists, and
// the failure mode of an httplib bump is a loud compile error in a test-only
// header, never silent misbehaviour.

#include "http_route_sink.hpp"

#include <httplib.h>

#include <memory>
#include <regex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server::test {

class TestRouteSink : public yuzu::server::HttpRouteSink {
public:
    void Get(const std::string& p, Handler h) override { add("GET", p, std::move(h)); }
    void Post(const std::string& p, Handler h) override { add("POST", p, std::move(h)); }
    void Put(const std::string& p, Handler h) override { add("PUT", p, std::move(h)); }
    void Delete(const std::string& p, Handler h) override { add("DELETE", p, std::move(h)); }
    void Patch(const std::string& p, Handler h) override { add("PATCH", p, std::move(h)); }
    void Options(const std::string& p, Handler h) override { add("OPTIONS", p, std::move(h)); }

    /// Dispatch a synthesized request. Returns nullptr when no route matches
    /// (httplib would return 404 in that case; tests that need 404 semantics
    /// should assert nullptr or pre-set res->status = 404 before this call).
    ///
    /// Pre-sets res->status = 200 so handlers that don't touch status look
    /// the same as production (httplib::Server defaults completed handlers
    /// to 200). Handlers that explicitly set 401/204/403/etc. still win.
    ///
    /// `extra_headers` injects request headers (e.g. `Last-Event-ID`,
    /// `Authorization`) so tests can exercise header-driven code paths.
    /// W5.1 R2 governance fix — happy-path G1 caught that the prior
    /// signature accepted no headers map, so a test setting
    /// `Last-Event-ID` on a local Request and then calling dispatch
    /// silently dropped the header and the handler never saw it.
    std::unique_ptr<httplib::Response>
    dispatch(const std::string& method, const std::string& path, const std::string& body = {},
             const std::string& content_type = "application/json",
             const std::unordered_map<std::string, std::string>& extra_headers = {}) {
        // httplib::Server splits the request URI into path + query string
        // before routing, so handlers see `req.path` without the `?...` tail
        // and `req.params` populated from the query. Mirror that here so
        // handlers exercising `req.has_param("limit")` work identically.
        std::string match_path = path;
        std::string query_text;
        if (auto qpos = path.find('?'); qpos != std::string::npos) {
            match_path = path.substr(0, qpos);
            query_text = path.substr(qpos + 1);
        }

        for (auto& route : routes_) {
            if (route.method != method)
                continue;
            if (!std::regex_match(match_path, route.regex))
                continue;

            httplib::Request req;
            req.method = method;
            req.path = match_path;
            req.body = body;
            // Capture the regex groups by matching against `req.path` itself, so
            // `req.matches`' iterators alias the request's OWN string exactly as
            // httplib does (`std::regex_match(request.path, request.matches, ...)`).
            // Matching a dispatch()-local instead left `req.matches` pointing at a
            // string the request does not own — safe only while no handler outlives
            // the call, which is not a property worth depending on (#1786).
            std::regex_match(req.path, req.matches, route.regex);

            if (!query_text.empty())
                httplib::detail::parse_query_text(query_text, req.params);
            if (!content_type.empty())
                req.set_header("Content-Type", content_type);
            // Inject test-supplied headers. Done AFTER Content-Type so a
            // test that explicitly overrides Content-Type via the map
            // wins (rare, but a valid scenario).
            for (const auto& [name, value] : extra_headers) {
                req.set_header(name, value);
            }

            // httplib::Server parses an `application/x-www-form-urlencoded` body
            // into `req.params` — the same multimap as the query string, and after
            // it, so a query value wins over a body value of the same name. Without
            // this, a handler reading `req.has_param(...)` with an
            // `extract_form_value(req.body, ...)` fallback silently took the
            // FALLBACK branch under test while production took the params branch:
            // the tested path was not the shipped path (#1786).
            //
            // Read the EFFECTIVE header, not the `content_type` argument, since
            // `extra_headers` may have just overridden it — one source of truth.
            // Media type is compared httplib's way (`extract_media_type` trims and
            // drops `;`-parameters); `starts_with` would both accept
            // `...urlencoded-x` and reject a leading-space value.
            const std::string effective_ct = req.get_header_value("Content-Type");
            if (!body.empty() && httplib::detail::extract_media_type(effective_ct) ==
                                     "application/x-www-form-urlencoded") {
                // httplib rejects an oversized urlencoded body with 413 BEFORE the
                // handler runs, so the handler must not see it here either — a
                // fixture that skipped this would "prove" behaviour production
                // never reaches.
                if (body.size() > CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH) {
                    auto oversized = std::make_unique<httplib::Response>();
                    oversized->status = 413;
                    return oversized;
                }
                httplib::detail::parse_query_text(body, req.params);
            }

            auto res = std::make_unique<httplib::Response>();
            res->status = 200;
            route.handler(req, *res);
            return res;
        }
        return nullptr;
    }

    /// Convenience wrappers for common verbs.
    auto Get(const std::string& path) { return dispatch("GET", path); }
    auto Get(const std::string& path, const std::unordered_map<std::string, std::string>& headers) {
        return dispatch("GET", path, {}, "application/json", headers);
    }
    auto Post(const std::string& path, const std::string& body,
              const std::string& ct = "application/json") {
        return dispatch("POST", path, body, ct);
    }
    auto Put(const std::string& path, const std::string& body,
             const std::string& ct = "application/json") {
        return dispatch("PUT", path, body, ct);
    }
    auto Delete(const std::string& path) { return dispatch("DELETE", path); }

    /// Number of registered routes — handy for assertions in fixture setup.
    std::size_t route_count() const { return routes_.size(); }

    /// Every registered (method, pattern) pair, in registration order.
    /// Additive accessor for #3991's OpenAPI completeness contract test
    /// (test_openapi_spec_completeness.cpp), which needs to enumerate the
    /// full route table without dispatching each one individually. `pattern`
    /// is the raw string handed to Get/Post/etc — a plain path or an
    /// httplib-style regex (see `add()` below) — not percent-decoded or
    /// otherwise normalized.
    std::vector<std::pair<std::string, std::string>> registered_routes() const {
        std::vector<std::pair<std::string, std::string>> out;
        out.reserve(routes_.size());
        for (const auto& r : routes_)
            out.emplace_back(r.method, r.pattern);
        return out;
    }

private:
    struct Route {
        std::string method;
        std::string pattern;
        std::regex regex;
        Handler handler;
    };

    void add(const std::string& method, const std::string& pattern, Handler h) {
        // httplib treats the pattern as a regex if it contains regex
        // metacharacters; otherwise it's an exact path. We compile every
        // pattern as a regex — plain paths still match exactly because they
        // contain no metachars. Patterns the production code writes as raw
        // strings (R"(/api/v1/groups/([a-f0-9]+))") work as-is.
        routes_.push_back({method, pattern, std::regex(pattern), std::move(h)});
    }

    std::vector<Route> routes_;
};

} // namespace yuzu::server::test
