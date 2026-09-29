/**
 * test_settings_model.cpp — pure unit tests for the shared Settings
 * read-twin builders (#4028, api-parity programme #2146,
 * docs/api-twin-recipe.md §1). These functions take only a `Config&` (plus
 * the handful of non-Config inputs a fragment needs) and return the JSON
 * "data" payload both `settings_routes.cpp`'s HTML fragment renderers and
 * its `GET /api/v1/settings/...` REST handlers consume — so testing them here
 * directly (no httplib, no TestRouteSink) covers the data-shape contract
 * both surfaces share.
 *
 * The ClickHouse URL userinfo-sanitization tests below are the regression
 * coverage for the security fix #4028's Evidence section flags: the
 * analytics builder must never let embedded URL credentials reach either
 * surface, only the discrete clickhouse_password_set bool.
 */

#include "settings_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/server/server.hpp>

using namespace yuzu::server;
namespace sm = yuzu::server::settings_model;

// ── sanitize_url_userinfo ────────────────────────────────────────────────

TEST_CASE("sanitize_url_userinfo strips user:pass@ from a scheme URL",
          "[settings][settings_model]") {
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin:s3cr3t@host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo strips a bare user@ with no password",
          "[settings][settings_model]") {
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin@host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo leaves a URL with no userinfo unchanged",
          "[settings][settings_model]") {
    CHECK(sm::sanitize_url_userinfo("clickhouse://host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo handles a schemeless authority",
          "[settings][settings_model]") {
    // No "://" at all — the whole prefix up to the first '/' is the
    // authority, so userinfo there must still be stripped.
    CHECK(sm::sanitize_url_userinfo("admin:s3cr3t@host:9000/yuzu") == "host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo sweeps up a legitimate path '@' along with it "
          "(deliberate over-strip, round 2)",
          "[settings][settings_model]") {
    // #4028 fix-round history: this test used to assert the path's '@' was
    // left untouched, distinguishing "no userinfo, path has an '@'" from a
    // real credential. That distinction turned out to be UNDECIDABLE from
    // the string alone -- "admin:1234/ss@host" (a real, '/'-corrupted
    // password) and "host:9000/db@table" (no userinfo at all) are
    // impossible to tell apart by any lexical heuristic (three independent
    // governance reviewers converged on this: cpp-safety, security-guardian,
    // cpp-expert, each finding a different input that broke a different
    // attempted heuristic). Since this is a display-only sanitizer with no
    // obligation to hand back a working URL, the design now deliberately
    // resolves the ambiguity by over-stripping: the LAST '@' anywhere in the
    // URL is always treated as ending userinfo, even when -- as here --
    // there was no userinfo and the '@' was harmless path content. This
    // trades path fidelity for a guarantee that no credential can ever
    // survive, regardless of shape.
    CHECK(sm::sanitize_url_userinfo("clickhouse://host:9000/db@table") == "clickhouse://table");
}

TEST_CASE("sanitize_url_userinfo handles an empty string", "[settings][settings_model]") {
    CHECK(sm::sanitize_url_userinfo("") == "");
}

// #4028 fix-round hardening (governance Gate 2-5/8: security-guardian,
// quality-engineer F1, unhappy-path UP-1/UP-2, chaos-injector CH-1) —
// adversarial regression coverage. History, since this function has been
// through two designs: round 1 tried to locate the authority boundary first
// and search for '@' within it (with a `looks_like_bare_host` heuristic to
// widen past an embedded '/'). Gate 8 re-review found that approach
// unfixable -- a digit-only password segment before the '/' is lexically
// identical to a real host:port, so no heuristic patch could close every
// shape. Round 2 (current) deletes the heuristic: the LAST '@' anywhere in
// the URL is always the delimiter, full stop -- see the sweeps-up-a-path-'@'
// test above for the accepted trade-off this makes.

TEST_CASE("sanitize_url_userinfo strips a password containing an unescaped '@'",
          "[settings][settings_model][security]") {
    // A naive FIRST-'@' scan stops mid-password here, leaking "ss@host..."
    // verbatim. The real delimiter is the LAST '@' in the URL.
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin:p@ss@host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo strips a password containing an unescaped '/'",
          "[settings][settings_model][security]") {
    // A naive FIRST-'/' authority boundary lands INSIDE the userinfo here
    // ("admin:pa" / "ss@host..."). Since round 2 never computes an authority
    // boundary before searching for '@', this shape was never a special
    // case to begin with.
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin:pa/ss@host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo strips a password containing an unescaped '/' even when "
          "the password's prefix is digit-only",
          "[settings][settings_model][security]") {
    // Round 1 regression (security-guardian + cpp-expert, Gate 8): a
    // password segment that happens to be all-digits before the embedded
    // '/' (here "1234") is lexically indistinguishable from a real
    // "host:port" to any last-colon-followed-by-digits heuristic, so round
    // 1's `looks_like_bare_host` widen check never fired and this shape
    // bypassed the sanitizer completely. Round 2 has no such heuristic.
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin:1234/ss@host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo over-strips when a '?' precedes the real userinfo '@' "
          "(round 3: ambiguous vs. a genuine query, deliberate over-strip)",
          "[settings][settings_model][security]") {
    // Round 1 regression (security-guardian, Gate 8): round 1 dropped the
    // query string/fragment from the RAW url before ever searching for
    // '@', so an unescaped '?' inside the password truncated the string
    // before the real delimiter was found, leaking the username and a
    // password prefix ("clickhouse://admin:p"). Round 2 fixed THIS shape
    // by running the query/fragment drop AFTER the '@'-based strip,
    // against the already-sanitized string -- but that sequential-mutation
    // design was itself the root cause of the g8b-sanitizer-query-at-
    // ordering bypass fixed in round 3 (see the two tests below). Round 3
    // computes both cut points against the ORIGINAL string and unions
    // them; when a '?'/'#' occurs AT OR BEFORE the last '@' (as it does
    // here -- the '?' sits inside what turns out to be the password), that
    // shape is LEXICALLY IDENTICAL to "no real userinfo, and the '?' is a
    // genuine query start whose own content happens to contain a later
    // '@'" (see g8b-sanitizer-query-at-ordering below) -- the two cannot be
    // told apart from the string alone. Consistent with round 2's own
    // over-strip philosophy, round 3 resolves the ambiguity by dropping
    // everything from the authority boundary onward rather than guessing:
    // this input now returns just the scheme, not "clickhouse://host:9000/yuzu".
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin:p?ss@host:9000/yuzu") == "clickhouse://");
}

// #4028 round 3 (adversarial-review hardening, /home/dgr/advrev-4028) --
// regression coverage for the two governance-ledger BLOCKING findings that
// round 2 shipped with (governance.d/4028-settings-read-twins.BAbeot.jsonl:
// g8b-sanitizer-scheme-boundary, g8b-sanitizer-query-at-ordering). Both were
// independently reproduced by two external adversarial reviewers (Kimi,
// Codex) against the compiled round-2 object before this fix landed.

TEST_CASE("sanitize_url_userinfo does not leak userinfo when a later query value embeds "
          "its own \"://\" (g8b-sanitizer-scheme-boundary)",
          "[settings][settings_model][security]") {
    // Round 2 regression: `url.find("://")` matched the FIRST "://"
    // anywhere in the string -- including one embedded in a later query
    // value -- pushing the computed authority boundary past the real
    // userinfo and suppressing the strip entirely. This schemeless input
    // (no real scheme at all) was returned COMPLETELY UNCHANGED by round 2,
    // leaking "myuser:mypassword" in full. Round 3 bounds the scheme scan
    // to a plain prefix walk from position 0, so the nested "https://"
    // deep in the query string can never be mistaken for the real scheme.
    CHECK(sm::sanitize_url_userinfo(
              "myuser:mypassword@10.0.0.5:9000/db?ssl_ca=https://ca.corp.example/root.pem") ==
          "10.0.0.5:9000/db");
}

TEST_CASE("sanitize_url_userinfo does not leak a query-embedded password when the query "
          "itself contains an '@' (g8b-sanitizer-query-at-ordering)",
          "[settings][settings_model][security]") {
    // Round 2 regression: the userinfo strip's unbounded "last '@'" search
    // picked up the '@' inside "admin@corp.com" (a query VALUE, not real
    // userinfo), discarding the real '?' delimiter along with it before
    // the query-strip step -- which ran second, against the already-
    // mutated string -- ever got a chance to find it. Round 2 returned
    // "clickhouse://corp.com&password=s3cr3t", leaking the password in
    // plaintext. Round 3 computes the query start against the ORIGINAL
    // string; since it falls before the apparent "last '@'", the two
    // removal ranges are unioned and the whole tail is dropped.
    CHECK(sm::sanitize_url_userinfo(
              "clickhouse://host:9000/yuzu?user=admin@corp.com&password=s3cr3t") ==
          "clickhouse://");
}

TEST_CASE("sanitize_url_userinfo strips real userinfo even when the path also contains an '@'",
          "[settings][settings_model][security]") {
    // Round 1 regression (cpp-safety, cpp-expert, compliance-officer, Gate
    // 8): round 1's `find_last_of('@')` was unbounded, so a URL combining
    // REAL credentials with a later path '@' (".../db@table") picked the
    // path's '@' instead of the credential's, failed the boundary check,
    // and fell through to `return base` -- the credential leaked in full.
    // Round 2's over-strip design (see the test above) sweeps up BOTH the
    // credential and the path '@' in the same pass -- lossier than round
    // 1's original intent, but the credential can never survive.
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin:s3cr3t@host:9000/db@table") ==
          "clickhouse://table");
}

TEST_CASE("sanitize_url_userinfo strips a query-string credential form entirely",
          "[settings][settings_model][security]") {
    // ClickHouse's HTTP interface also accepts credentials as query
    // parameters with no '@' anywhere in the URL — a shape the original
    // implementation never modeled at all. The query string (and any
    // fragment) is dropped unconditionally rather than selectively
    // redacted.
    CHECK(sm::sanitize_url_userinfo("http://host:8123/?user=admin&password=s3cr3t") ==
          "http://host:8123/");
}

// #4028 round-3 adversarial-review finding CDX-01 (/home/dgr/advrev-4028) —
// regression coverage for the digit-/symbol-leading pseudo-scheme bypass.
// RFC 3986 §3.1 requires a scheme to start with ALPHA; a scan that instead
// accepts DIGIT/'+'/'-'/'.' as the first byte wrongly treats a schemeless
// credential's scheme-shaped "username" as a real scheme, preserving it in
// the output instead of stripping it as userinfo.

TEST_CASE("sanitize_url_userinfo strips a digit-leading pseudo-scheme "
          "(CDX-01: ALPHA-first, not alnum-first)",
          "[settings][settings_model][security]") {
    // "9name" looks scheme-shaped (alnum run immediately followed by
    // "://") but cannot be a real RFC 3986 scheme -- schemes must start
    // with a letter. The round-3 fix that only checked "the first char is
    // alnum" wrongly preserved "9name://" as if it were a genuine scheme,
    // leaking the digit-led "username" in the output
    // ("9name://host:9000/db"). The correct reading has no scheme at all:
    // "9name" is part of the userinfo up to the real '@', and must be
    // stripped along with it.
    CHECK(sm::sanitize_url_userinfo("9name://pass@host:9000/db") == "host:9000/db");
}

TEST_CASE("sanitize_url_userinfo strips a hyphen-leading pseudo-scheme (CDX-01)",
          "[settings][settings_model][security]") {
    CHECK(sm::sanitize_url_userinfo("-bad://evil@host:1/db") == "host:1/db");
}

TEST_CASE("sanitize_url_userinfo strips a dot-leading pseudo-scheme (CDX-01)",
          "[settings][settings_model][security]") {
    CHECK(sm::sanitize_url_userinfo(".bad://evil@host:1/db") == "host:1/db");
}

TEST_CASE("sanitize_url_userinfo still recognizes an ordinary ALPHA-first scheme "
          "(CDX-01 regression guard)",
          "[settings][settings_model][security]") {
    // The ALPHA-first fix must not regress the ordinary case: a real
    // scheme name may still contain digits after its first letter.
    CHECK(sm::sanitize_url_userinfo("s3proxy2://admin:s3cr3t@host:9000/db") ==
          "s3proxy2://host:9000/db");
}

// ── build_analytics_settings — the security-fix regression coverage ─────

TEST_CASE("build_analytics_settings sanitizes the ClickHouse URL and never emits the raw password",
          "[settings][settings_model][security]") {
    Config cfg;
    cfg.analytics_enabled = true;
    cfg.analytics_drain_interval_seconds = 10;
    cfg.analytics_batch_size = 100;
    cfg.clickhouse_url = "clickhouse://admin:s3cr3t@host:9000/yuzu";
    cfg.clickhouse_database = "yuzu";
    cfg.clickhouse_table = "yuzu_events";
    cfg.clickhouse_username = "admin";
    cfg.clickhouse_password = "s3cr3t";

    auto j = sm::build_analytics_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("clickhouse_configured").get<bool>() == true);
    CHECK(j.at("clickhouse_url").get<std::string>() == "clickhouse://host:9000/yuzu");
    CHECK(j.at("clickhouse_password_set").get<bool>() == true);

    // The raw secret must not appear ANYWHERE in the serialized payload —
    // not just absent from a named field.
    auto dumped = j.dump();
    CHECK(dumped.find("s3cr3t") == std::string::npos);
    // The field itself must not exist at all (not even redacted-empty).
    CHECK(!j.contains("clickhouse_password"));
}

TEST_CASE("build_analytics_settings reports not-configured and password-unset when both are empty",
          "[settings][settings_model]") {
    Config cfg;
    cfg.clickhouse_url.clear();
    cfg.clickhouse_password.clear();

    auto j = sm::build_analytics_settings(cfg);

    CHECK(j.at("clickhouse_configured").get<bool>() == false);
    CHECK(j.at("clickhouse_url").get<std::string>().empty());
    CHECK(j.at("clickhouse_password_set").get<bool>() == false);
}

// ── build_tls_settings / build_https_settings ────────────────────────────

TEST_CASE("build_tls_settings reflects Config verbatim", "[settings][settings_model]") {
    Config cfg;
    cfg.tls_enabled = true;
    cfg.tls_server_cert = "/etc/yuzu/certs/server.pem";
    cfg.tls_server_key = "/etc/yuzu/certs/server.key";
    cfg.tls_ca_cert = "/etc/yuzu/certs/ca.pem";
    cfg.insecure_skip_client_verify = true;

    auto j = sm::build_tls_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("server_cert_path").get<std::string>() == "/etc/yuzu/certs/server.pem");
    CHECK(j.at("server_key_path").get<std::string>() == "/etc/yuzu/certs/server.key");
    CHECK(j.at("ca_cert_path").get<std::string>() == "/etc/yuzu/certs/ca.pem");
    CHECK(j.at("insecure_skip_client_verify").get<bool>() == true);
    // Unset management overrides serialize as empty strings, not omitted.
    CHECK(j.at("mgmt_server_cert_path").get<std::string>().empty());
}

TEST_CASE("build_https_settings reflects Config verbatim", "[settings][settings_model]") {
    Config cfg;
    cfg.https_enabled = true;
    cfg.https_port = 8443;
    cfg.https_redirect = false;

    auto j = sm::build_https_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("port").get<int>() == 8443);
    CHECK(j.at("redirect").get<bool>() == false);
}

// ── build_gateway_settings ────────────────────────────────────────────────

TEST_CASE("build_gateway_settings defaults every field when disabled",
          "[settings][settings_model]") {
    Config cfg;
    cfg.gateway_upstream_address = "0.0.0.0:50053";
    cfg.gateway_mode = true;

    auto j = sm::build_gateway_settings(cfg, /*gateway_enabled=*/false, /*active_sessions=*/5);

    CHECK(j.at("enabled").get<bool>() == false);
    CHECK(j.at("listen_address").get<std::string>().empty());
    CHECK(j.at("gateway_mode").get<bool>() == false);
    CHECK(j.at("active_sessions").get<std::int64_t>() == 0);
}

TEST_CASE("build_gateway_settings reports live state when enabled", "[settings][settings_model]") {
    Config cfg;
    cfg.gateway_upstream_address = "0.0.0.0:50053";
    cfg.gateway_mode = true;

    auto j = sm::build_gateway_settings(cfg, /*gateway_enabled=*/true, /*active_sessions=*/5);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("listen_address").get<std::string>() == "0.0.0.0:50053");
    CHECK(j.at("gateway_mode").get<bool>() == true);
    CHECK(j.at("active_sessions").get<std::int64_t>() == 5);
}

// ── build_mcp_settings ────────────────────────────────────────────────────

TEST_CASE("build_mcp_settings derives an https endpoint URL when HTTPS is enabled",
          "[settings][settings_model]") {
    Config cfg;
    cfg.mcp_disable = false;
    cfg.mcp_read_only = true;
    cfg.https_enabled = true;
    cfg.https_port = 8443;
    cfg.web_address = "0.0.0.0";
    cfg.web_port = 8080;

    auto j = sm::build_mcp_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("read_only").get<bool>() == true);
    CHECK(j.at("endpoint_url").get<std::string>() == "https://localhost:8443/mcp/v1/");
}

TEST_CASE("build_mcp_settings derives an http endpoint URL when HTTPS is disabled and enabled reflects mcp_disable",
          "[settings][settings_model]") {
    Config cfg;
    cfg.mcp_disable = true;
    cfg.https_enabled = false;
    cfg.web_address = "127.0.0.1";
    cfg.web_port = 8080;

    auto j = sm::build_mcp_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == false); // mcp_disable=true -> enabled=false
    CHECK(j.at("endpoint_url").get<std::string>() == "http://127.0.0.1:8080/mcp/v1/");
}

// ── build_data_retention_settings / build_server_config_settings ────────

TEST_CASE("build_data_retention_settings reflects Config verbatim", "[settings][settings_model]") {
    Config cfg;
    cfg.response_retention_days = 90;
    cfg.audit_retention_days = 365;

    auto j = sm::build_data_retention_settings(cfg);

    CHECK(j.at("response_retention_days").get<int>() == 90);
    CHECK(j.at("audit_retention_days").get<int>() == 365);
}

TEST_CASE("build_server_config_settings reflects Config verbatim", "[settings][settings_model]") {
    Config cfg;
    cfg.listen_address = "0.0.0.0:50051";
    cfg.management_address = "0.0.0.0:50052";
    cfg.web_address = "127.0.0.1";
    cfg.web_port = 8080;
    cfg.max_agents = 12345;
    cfg.rate_limit = 100;

    auto j = sm::build_server_config_settings(cfg);

    CHECK(j.at("agent_grpc_address").get<std::string>() == "0.0.0.0:50051");
    CHECK(j.at("management_grpc_address").get<std::string>() == "0.0.0.0:50052");
    CHECK(j.at("web_address").get<std::string>() == "127.0.0.1");
    CHECK(j.at("web_port").get<int>() == 8080);
    CHECK(j.at("max_agents").get<std::int64_t>() == 12345);
    CHECK(j.at("rate_limit_per_ip").get<int>() == 100);
}

// ── build_plugin_signing_settings ─────────────────────────────────────────

TEST_CASE("build_plugin_signing_settings reports disabled+empty when no bundle is on disk",
          "[settings][settings_model]") {
    auto j = sm::build_plugin_signing_settings(/*required=*/false, /*bundle=*/std::nullopt);

    CHECK(j.at("enabled").get<bool>() == false);
    CHECK(j.at("required").get<bool>() == false);
    CHECK(j.at("cert_count").get<int>() == 0);
    CHECK(j.at("sha256").get<std::string>().empty());
    CHECK(j.at("subjects").get<std::vector<std::string>>().empty());
    CHECK(j.at("bundle_unreadable").get<bool>() == false);
    CHECK(!j.contains("bundle_error"));
    // trust_bundle_pem defaults empty -> omitted (the fragment/settings-twin shape).
    CHECK(!j.contains("trust_bundle_pem"));
}

TEST_CASE("build_plugin_signing_settings reports the bundle stats when present",
          "[settings][settings_model]") {
    plugin_signing::TrustBundleStats stats;
    stats.cert_count = 2;
    stats.sha256_hex = "deadbeef";
    stats.subjects = {"CN=Yuzu Plugin Signer"};
    std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>> bundle = stats;

    auto j = sm::build_plugin_signing_settings(/*required=*/true, bundle);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("required").get<bool>() == true);
    CHECK(j.at("cert_count").get<int>() == 2);
    CHECK(j.at("sha256").get<std::string>() == "deadbeef");
    CHECK(j.at("subjects").get<std::vector<std::string>>() ==
          std::vector<std::string>{"CN=Yuzu Plugin Signer"});
    CHECK(j.at("bundle_unreadable").get<bool>() == false);
}

TEST_CASE("build_plugin_signing_settings reports bundle_unreadable and the error message",
          "[settings][settings_model]") {
    std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>> bundle =
        std::unexpected(std::string("missing PEM begin/end markers"));

    auto j = sm::build_plugin_signing_settings(/*required=*/false, bundle);

    CHECK(j.at("enabled").get<bool>() == false);
    CHECK(j.at("bundle_unreadable").get<bool>() == true);
    CHECK(j.at("bundle_error").get<std::string>() == "missing PEM begin/end markers");
}

TEST_CASE("build_plugin_signing_settings emits trust_bundle_pem only when explicitly passed",
          "[settings][settings_model]") {
    // The plugin-policy route (its ONLY caller with a non-empty pem — see
    // the builder's own doc comment) is the superset; the fragment/other
    // callers pass an empty string so the field is omitted for them.
    auto j_without = sm::build_plugin_signing_settings(false, std::nullopt);
    CHECK(!j_without.contains("trust_bundle_pem"));

    auto j_with = sm::build_plugin_signing_settings(false, std::nullopt, "-----BEGIN...-----");
    REQUIRE(j_with.contains("trust_bundle_pem"));
    CHECK(j_with.at("trust_bundle_pem").get<std::string>() == "-----BEGIN...-----");
}
