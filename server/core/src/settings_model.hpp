#pragma once

/// @file settings_model.hpp
///
/// Pure builder functions for the Settings read-twins (issue #4028, api-parity
/// programme #2146, docs/api-twin-recipe.md §1 "shared builder, projected
/// three ways"). Each `build_*_settings` function takes only the `Config`
/// (plus the handful of non-Config inputs a fragment needs, e.g. the
/// gateway's live session count) and returns the JSON "data" payload — the
/// SAME payload `settings_routes.cpp`'s `render_*_fragment()` HTML renderers
/// and its `GET /api/v1/settings/*` REST handlers both consume, so the two
/// surfaces cannot drift from each other by construction (recipe Rule 1).
///
/// No `httplib.h`, no MCP headers: these are pure data builders, not route
/// handlers. #4028's Context section (and this issue's #520 read: "MCP
/// tokens are for fleet management ... and must not be used to administer
/// the server itself (settings, users, TLS, OIDC)") is why this PR ships
/// these eight sub-areas REST-only — no MCP tool calls into this file. It is
/// kept transport-free anyway, on the same principle `discover_routes.hpp`
/// documents: if a future, separately-reviewed amendment to #520 ever adds
/// an MCP twin, it calls these same functions rather than re-deriving the
/// data.
///
/// Every function is pure (no I/O beyond reading the `Config&`/optional
/// bundle-stats value passed in) and side-effect-free.

#include "plugin_signing_helpers.hpp"

#include <yuzu/server/server.hpp> // Config

#include <nlohmann/json.hpp>

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::settings_model {

/// Strip embedded userinfo (`user:pass@` / `user@`) from a URL's authority,
/// and drop any query string or fragment outright, before the URL is ever
/// serialized or rendered. #4028 Evidence: `render_analytics_fragment`
/// masked the discrete `clickhouse_password` Config field but rendered
/// `clickhouse_url` verbatim — a URL of the form
/// `clickhouse://admin:s3cr3t@host:9000` leaks the credential regardless of
/// the separate field's own masking. `build_analytics_settings` below is the
/// only caller; exposed here so the sanitizer itself is unit-testable
/// without going through the full builder.
///
/// The userinfo delimiter is the LAST '@' anywhere at or after the
/// authority boundary, full stop — no "does this look like a host"
/// heuristic. That is a deliberate design choice, not an oversight: an
/// earlier version tried to first locate the authority's end (the
/// path-starting '/') and search for '@' only within it, with a heuristic
/// to widen past an unescaped '/' embedded in the password. Governance
/// review found that approach unfixable — a password segment that happens
/// to be digit-only before the '/' (e.g. "admin:1234/pass@host") is
/// lexically identical to a real "host:port", so no heuristic patch can
/// tell them apart, and two rounds of patching that heuristic each shipped
/// a new bypass. Since this is a display-only sanitizer with no obligation
/// to hand back a working URL, the unresolvable ambiguity between "a
/// corrupted password" and "legitimate path content containing '@'" (e.g.
/// `.../db@table`) is resolved by always preferring to OVER-strip: the
/// discarded prefix necessarily contains any real credential regardless of
/// its shape, at the cost of also discarding a later, harmless path '@'
/// when one happens to be present.
///
/// The authority boundary itself is a BOUNDED prefix scan from position 0
/// — a URI scheme is `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
/// immediately followed by "://" (RFC 3986 §3.1) — never an unbounded
/// search for "://" anywhere in the string (an earlier version used
/// `url.find("://")`, which a later adversarial-review round showed could
/// match a scheme-shaped substring embedded arbitrarily far into a query
/// value, e.g. `?ssl_ca=https://ca.example/root.pem`, pushing the computed
/// boundary past real userinfo and suppressing the strip entirely). The
/// ALPHA-first requirement is load-bearing, not decorative: a still-later
/// adversarial-review round (CDX-01) found an implementation that allowed
/// the scan to START on a digit (or `+`/`-`/`.`) preserved a schemeless
/// credential's digit-led "username" verbatim when it was immediately
/// followed by "://" — e.g. `9name://pass@host:9000/db` kept `9name` in
/// the output. The scan must reject any prefix that does not start with a
/// letter.
///
/// The query string and fragment are dropped unconditionally (rather than
/// selectively redacted — that would need to enumerate every driver's own
/// query-parameter convention and stays wrong for the next one). Both the
/// userinfo cut point and the query/fragment cut point are computed
/// against the ORIGINAL url, never sequentially against a once-mutated
/// result (an earlier version ran the query/fragment search against its
/// own already-stripped output, which broke when the query string itself
/// contained a later '@' — e.g. `?user=admin@corp.com&password=...` — the
/// userinfo strip's unbounded "last '@'" search swallowed the query's own
/// '?' before the query step ever ran, leaking the trailing password). When
/// the query/fragment start falls at or before the apparent userinfo-
/// ending '@', the two removal ranges overlap: that shape is inherently
/// ambiguous (it reads identically whether it's a real, '?'-corrupted
/// password whose true delimiter is the later '@', or no real userinfo at
/// all with the apparent "last '@'" actually living inside the query), so
/// consistent with the over-strip philosophy above, everything from the
/// authority boundary onward is dropped. A URL with no userinfo, query, or
/// fragment is returned unchanged.
[[nodiscard]] std::string sanitize_url_userinfo(std::string_view url);

/// `GET /fragments/settings/tls` + `GET /api/v1/settings/tls`. TlsConfig:Read.
/// {enabled, server_cert_path, server_key_path, ca_cert_path,
///  insecure_skip_client_verify, mgmt_server_cert_path, mgmt_server_key_path,
///  mgmt_ca_cert_path} — every `*_path` is `""` when unset (matches the
/// fragment's own "No file"/"Using agent TLS" placeholder logic, which is
/// applied by the fragment renderer, not this builder — this builder returns
/// raw config values only, never presentation text).
[[nodiscard]] nlohmann::json build_tls_settings(const Config& cfg);

/// `GET /fragments/settings/https` + `GET /api/v1/settings/https`. TlsConfig:Read.
/// {enabled, port, cert_path, key_path, redirect}.
[[nodiscard]] nlohmann::json build_https_settings(const Config& cfg);

/// `GET /fragments/settings/gateway` + `GET /api/v1/settings/gateway`. ServerConfig:Read.
/// {enabled, listen_address, gateway_mode, active_sessions}. The latter
/// three are zero-valued when `gateway_enabled` is false (matches the
/// fragment's own "upstream service not running" branch, which skips
/// rendering them entirely — the REST twin instead always emits a stable
/// shape with defaulted values).
[[nodiscard]] nlohmann::json build_gateway_settings(const Config& cfg, bool gateway_enabled,
                                                    std::size_t active_sessions);

/// `GET /fragments/settings/server-config` + `GET /api/v1/settings/server-config`.
/// ServerConfig:Read. Nothing secret (#4028 Evidence) — gRPC/web
/// addresses+ports, session timeout, max agents, rate limits, OTA/gRPC
/// tuning knobs.
[[nodiscard]] nlohmann::json build_server_config_settings(const Config& cfg);

/// `GET /fragments/settings/mcp` + `GET /api/v1/settings/mcp`. ServerConfig:Read.
/// {enabled, read_only, endpoint_url} — `endpoint_url` is computed the same
/// way `render_mcp_fragment` already did (proto from `https_enabled`, host
/// defaults `0.0.0.0` to `localhost` for a copy-pasteable value).
[[nodiscard]] nlohmann::json build_mcp_settings(const Config& cfg);

/// `GET /fragments/settings/data-retention` + `GET /api/v1/settings/data-retention`.
/// ServerConfig:Read. {response_retention_days, audit_retention_days} — two
/// integers, lowest sensitivity of the eight (#4028 Evidence).
[[nodiscard]] nlohmann::json build_data_retention_settings(const Config& cfg);

/// `GET /fragments/settings/analytics` + `GET /api/v1/settings/analytics`.
/// AnalyticsConfig:Read. {enabled, drain_interval_seconds, batch_size,
///  clickhouse_configured, clickhouse_url (sanitized, see
///  `sanitize_url_userinfo`), clickhouse_database, clickhouse_table,
///  clickhouse_username, clickhouse_password_set, jsonl_export_path}. The
/// raw `clickhouse_password` Config field is NEVER read into the returned
/// JSON — only whether it is set.
[[nodiscard]] nlohmann::json build_analytics_settings(const Config& cfg);

/// `GET /fragments/settings/plugin-signing` + the hardened
/// `GET /api/v2/agent/plugin-policy` (plugin-signing's ONLY REST twin —
/// #4028's acceptance criteria is explicit that this sub-area hardens the
/// existing route rather than adding a parallel `/api/v1/settings/*` one;
/// #4144 moved the hardened shape to `/v2/` — see that route's own comment
/// in settings_routes.cpp for why).
/// PluginSigning:Read. {enabled, required, cert_count, sha256, subjects[],
/// bundle_unreadable, bundle_error?} plus, only when the caller passes a
/// non-empty `trust_bundle_pem`, {trust_bundle_pem} — the superset field
/// only the agent-facing plugin-policy route emits (#4028 Evidence: that
/// route "serves a superset of this fragment's data, adds the full
/// trust_bundle_pem content"). The Settings fragment calls this with an
/// empty `trust_bundle_pem` so the field is omitted there.
///
/// `bundle` mirrors `read_on_disk_bundle()`'s own tri-state exactly so
/// callers can pass its return value straight through: `std::nullopt` = no
/// bundle on disk (not an error — a normal fresh-install state);
/// `std::unexpected` = a bundle file exists but failed to parse; otherwise
/// the parsed stats.
[[nodiscard]] nlohmann::json build_plugin_signing_settings(
    bool required,
    const std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>>& bundle,
    std::string_view trust_bundle_pem = {});

} // namespace yuzu::server::settings_model
