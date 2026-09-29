/// @file settings_model.cpp
/// Implementation of the pure Settings read-twin builders. See
/// settings_model.hpp for the shared-builder rationale (#4028).

#include "settings_model.hpp"

#include <cctype>

namespace yuzu::server::settings_model {

std::string sanitize_url_userinfo(std::string_view url) {
    if (url.empty())
        return std::string(url);

    // #4028 fix-round history (kept because the naive-looking design below
    // is the product of three iterations -- a future editor tempted to
    // reintroduce a host/authority-boundary heuristic should read this
    // first):
    //
    //   Round 1 tried to first locate the authority's end (the path-
    //   starting '/') and search for '@' only within that boundary, with a
    //   `looks_like_bare_host` heuristic to widen the search past an
    //   embedded, unescaped '/' in the password. Gate 8 re-review (three
    //   independent reviewers: cpp-safety, security-guardian, cpp-expert)
    //   found the boundary-first approach fundamentally unfixable: a
    //   password segment that happens to be digit-only before the '/'
    //   (e.g. "admin:1234/ss@host") is LEXICALLY IDENTICAL to a real
    //   "host:port" and the heuristic cannot tell them apart, no matter how
    //   it is patched -- two rounds of patching that same heuristic each
    //   shipped a new bypass or regression.
    //
    //   Round 2 deleted the heuristic entirely: `@` is never legal in a
    //   URL's host/port, so the LAST '@' anywhere at or after
    //   `authority_start` was always treated as ending userinfo, full stop
    //   -- deliberately over-stripping on ambiguity (see the "sweeps up a
    //   legitimate path '@'" test below, still accurate). An adversarial
    //   review round (Gate 8b) then found round 2 itself still leaked on
    //   two shapes, both closed here:
    //     (a) g8b-sanitizer-scheme-boundary: the scheme search
    //         (`url.find("://")`) matched the FIRST "://" ANYWHERE in the
    //         string, including one embedded in a later query value (e.g.
    //         "?ssl_ca=https://ca.example/root.pem"), pushing the computed
    //         authority boundary past the real userinfo and suppressing
    //         the strip entirely -- the credential leaked in full.
    //     (b) g8b-sanitizer-query-at-ordering: the userinfo strip and the
    //         query/fragment strip ran SEQUENTIALLY, the second against
    //         the first's already-mutated output. A query/fragment
    //         containing its own '@' (e.g.
    //         "?user=admin@corp.com&password=...") was picked up by the
    //         userinfo strip's unbounded "last '@'" search, discarding the
    //         real '?' delimiter before the query strip ever ran and
    //         leaving the trailing "password=..." intact.
    //
    //   Round 3 (this implementation) closes both:
    //     (a) is closed by bounding the scheme scan to a plain prefix scan
    //         from position 0 -- a URI scheme is
    //         `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` immediately
    //         followed by "://" (RFC 3986 §3.1). Validating that grammar
    //         from position 0 only means a "://" occurring past the first
    //         non-scheme character (e.g. the ':' in "user:pass@...", or
    //         any character at all in a schemeless credential) can never
    //         be mistaken for the real scheme delimiter, however far into
    //         the string it appears.
    //     (b) is closed by computing BOTH cut points -- the userinfo-
    //         ending '@' and the query/fragment start -- against the
    //         ORIGINAL `url`, never sequentially against a once-mutated
    //         result, then unioning the two removal ranges. When the
    //         query/fragment start is at or before the apparent userinfo-
    //         ending '@', the shape is inherently ambiguous: it means
    //         either a real, '?'-corrupted password whose true delimiter
    //         is that later '@' (see the "unescaped '?'" test below, whose
    //         expected output changed in this round), or no real userinfo
    //         at all, with the apparent "last '@'" actually living inside
    //         the query. Both readings produce an identical string shape,
    //         so -- consistent with round 2's own over-strip philosophy --
    //         the only string-safe resolution is to drop everything from
    //         the authority boundary to the end of the string.
    //
    //   Round 3's own scheme scan shipped one further defect (CDX-01, found
    //   by adversarial review of round 3 itself, /home/dgr/advrev-4028):
    //   it accepted a DIGIT (or '+'/'-'/'.') as the FIRST scheme byte,
    //   contrary to the RFC 3986 grammar it claimed to implement (scheme
    //   requires ALPHA first). A schemeless credential URL whose "username"
    //   happens to be scheme-shaped and digit-led -- e.g.
    //   "9name://pass@host:9000/db" -- was wrongly granted a scheme match,
    //   preserving "9name" verbatim in the output. Closed in the scan below
    //   by requiring the first byte be ALPHA before scanning the rest.
    std::size_t authority_start = 0;
    {
        // RFC 3986 §3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        // -- the FIRST byte must be a letter; only later bytes may also be a
        // digit or +/-/.. Adversarial-review finding CDX-01: an earlier
        // version of this scan accepted an alnum-led run (`std::isalnum` at
        // byte 0 too), so a digit-, '+'-, '-'-, or '.'-leading run
        // immediately followed by "://" was wrongly treated as a scheme --
        // e.g. "9name://pass@host:9000/db" (a schemeless credential URL
        // whose "username" happens to look scheme-shaped) had "9name"
        // preserved verbatim in the output instead of being swept up as
        // userinfo. Requiring ALPHA at byte 0 closes this: such input now
        // correctly finds no scheme, `authority_start` stays 0, and the
        // whole "9name" prefix is stripped along with the rest of the
        // userinfo.
        std::size_t i = 0;
        if (i < url.size() && std::isalpha(static_cast<unsigned char>(url[i]))) {
            ++i;
            while (i < url.size() && (std::isalnum(static_cast<unsigned char>(url[i])) ||
                                      url[i] == '+' || url[i] == '-' || url[i] == '.')) {
                ++i;
            }
            if (url.substr(i, 3) == "://")
                authority_start = i + 3;
        }
    }

    const auto at_pos = url.find_last_of('@');
    const bool has_userinfo = at_pos != std::string_view::npos && at_pos >= authority_start;

    // A query string or fragment can carry its OWN credential form this
    // function otherwise never models at all -- e.g. ClickHouse's HTTP
    // interface also accepts "?user=admin&password=..." with no '@'
    // anywhere in the URL (#4028 fix-round finding UP-2).
    const auto qf = url.find_first_of("?#", authority_start);
    const bool has_query = qf != std::string_view::npos;

    if (has_userinfo && has_query && qf <= at_pos) {
        // Overlapping/ambiguous ranges -- see (b) above. Over-strip: keep
        // only the scheme prefix, never a credential character.
        return std::string(url.substr(0, authority_start));
    }
    if (has_userinfo) {
        // Disjoint ranges (or no query at all): drop the userinfo, keep
        // whatever sits between it and the query start (or the rest of the
        // string when there is no query/fragment).
        const auto tail_len = has_query ? qf - (at_pos + 1) : std::string_view::npos;
        return std::string(url.substr(0, authority_start)) +
               std::string(url.substr(at_pos + 1, tail_len));
    }
    if (has_query) {
        // No userinfo; the query/fragment credential form is dropped
        // unconditionally rather than selectively redacted (selective
        // redaction would need to enumerate every driver's own
        // query-parameter convention and stays wrong for the next one).
        return std::string(url.substr(0, qf));
    }
    return std::string(url);
}

nlohmann::json build_tls_settings(const Config& cfg) {
    nlohmann::json j;
    j["enabled"] = cfg.tls_enabled;
    j["server_cert_path"] = cfg.tls_server_cert.string();
    j["server_key_path"] = cfg.tls_server_key.string();
    j["ca_cert_path"] = cfg.tls_ca_cert.string();
    j["insecure_skip_client_verify"] = cfg.insecure_skip_client_verify;
    j["mgmt_server_cert_path"] = cfg.mgmt_tls_server_cert.string();
    j["mgmt_server_key_path"] = cfg.mgmt_tls_server_key.string();
    j["mgmt_ca_cert_path"] = cfg.mgmt_tls_ca_cert.string();
    return j;
}

nlohmann::json build_https_settings(const Config& cfg) {
    nlohmann::json j;
    j["enabled"] = cfg.https_enabled;
    j["port"] = cfg.https_port;
    j["cert_path"] = cfg.https_cert_path.string();
    j["key_path"] = cfg.https_key_path.string();
    j["redirect"] = cfg.https_redirect;
    return j;
}

nlohmann::json build_gateway_settings(const Config& cfg, bool gateway_enabled,
                                      std::size_t active_sessions) {
    nlohmann::json j;
    j["enabled"] = gateway_enabled;
    j["listen_address"] = gateway_enabled ? cfg.gateway_upstream_address : std::string{};
    j["gateway_mode"] = gateway_enabled && cfg.gateway_mode;
    j["active_sessions"] =
        gateway_enabled ? static_cast<std::int64_t>(active_sessions) : std::int64_t{0};
    return j;
}

nlohmann::json build_server_config_settings(const Config& cfg) {
    nlohmann::json j;
    j["agent_grpc_address"] = cfg.listen_address;
    j["management_grpc_address"] = cfg.management_address;
    j["web_address"] = cfg.web_address;
    j["web_port"] = cfg.web_port;
    j["session_timeout_seconds"] = static_cast<std::int64_t>(cfg.session_timeout.count());
    j["max_agents"] = static_cast<std::int64_t>(cfg.max_agents);
    j["auth_config_path"] = cfg.auth_config_path.string();
    j["rate_limit_per_ip"] = cfg.rate_limit;
    j["login_rate_limit_per_ip"] = cfg.login_rate_limit;
    j["ota_max_concurrent_per_peer"] = cfg.ota_max_concurrent_per_peer;
    j["ota_rate_refill_per_min"] = cfg.ota_rate_refill_per_min;
    j["ota_rate_capacity"] = cfg.ota_rate_capacity;
    j["ota_max_concurrent_total"] = cfg.ota_max_concurrent_total;
    j["ota_max_peers_tracked"] = cfg.ota_max_peers_tracked;
    j["ota_transfer_deadline_secs"] = cfg.ota_transfer_deadline_secs;
    j["ota_chunk_write_deadline_secs"] = cfg.ota_chunk_write_deadline_secs;
    j["grpc_max_concurrent_streams"] = cfg.grpc_max_concurrent_streams;
    j["grpc_max_resource_memory_mb"] = cfg.grpc_max_resource_memory_mb;
    return j;
}

nlohmann::json build_mcp_settings(const Config& cfg) {
    nlohmann::json j;
    const bool mcp_enabled = !cfg.mcp_disable;
    j["enabled"] = mcp_enabled;
    j["read_only"] = cfg.mcp_read_only;
    // Mirrors render_mcp_fragment()'s own URL derivation exactly (settings_routes.cpp)
    // so the two surfaces can never disagree on the endpoint they advertise.
    const std::string proto = cfg.https_enabled ? "https" : "http";
    const std::string host = cfg.web_address == "0.0.0.0" ? "localhost" : cfg.web_address;
    const int port = cfg.https_enabled ? cfg.https_port : cfg.web_port;
    j["endpoint_url"] = proto + "://" + host + ":" + std::to_string(port) + "/mcp/v1/";
    return j;
}

nlohmann::json build_data_retention_settings(const Config& cfg) {
    nlohmann::json j;
    j["response_retention_days"] = cfg.response_retention_days;
    j["audit_retention_days"] = cfg.audit_retention_days;
    return j;
}

nlohmann::json build_analytics_settings(const Config& cfg) {
    nlohmann::json j;
    j["enabled"] = cfg.analytics_enabled;
    j["drain_interval_seconds"] = cfg.analytics_drain_interval_seconds;
    j["batch_size"] = cfg.analytics_batch_size;
    const bool ch_configured = !cfg.clickhouse_url.empty();
    j["clickhouse_configured"] = ch_configured;
    // #4028 Evidence: the URL, not just the discrete password field, can
    // carry embedded credentials (clickhouse://user:pass@host:port/db) —
    // always sanitize, never emit cfg.clickhouse_url raw.
    j["clickhouse_url"] = ch_configured ? sanitize_url_userinfo(cfg.clickhouse_url) : std::string{};
    j["clickhouse_database"] = cfg.clickhouse_database;
    j["clickhouse_table"] = cfg.clickhouse_table;
    j["clickhouse_username"] = cfg.clickhouse_username;
    // The raw password is intentionally never read into `j` — only whether
    // it is set. cfg.clickhouse_password itself is not referenced below.
    j["clickhouse_password_set"] = !cfg.clickhouse_password.empty();
    j["jsonl_export_path"] = cfg.analytics_jsonl_path.string();
    return j;
}

nlohmann::json build_plugin_signing_settings(
    bool required,
    const std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>>& bundle,
    std::string_view trust_bundle_pem) {
    nlohmann::json j;
    const bool enabled = bundle.has_value() && bundle->has_value();
    j["enabled"] = enabled;
    j["required"] = required;
    if (enabled) {
        const auto& stats = bundle->value();
        j["cert_count"] = stats.cert_count;
        j["sha256"] = stats.sha256_hex;
        j["subjects"] = stats.subjects;
    } else {
        j["cert_count"] = 0;
        j["sha256"] = "";
        j["subjects"] = nlohmann::json::array();
    }
    const bool unreadable = bundle.has_value() && !bundle->has_value();
    j["bundle_unreadable"] = unreadable;
    if (unreadable)
        j["bundle_error"] = bundle->error();
    if (!trust_bundle_pem.empty())
        j["trust_bundle_pem"] = trust_bundle_pem;
    return j;
}

} // namespace yuzu::server::settings_model
