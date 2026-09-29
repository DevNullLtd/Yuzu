#pragma once

/// @file plugin_config_parsers.hpp
/// PURE parsing/validation for the plugin config/secret plane + kill switch
/// (PR1.5b). Zero includes of any store, httplib, or pg header — this file
/// depends on nothing but the standard library, so `plugin_config_store.cpp`
/// and `plugin_config_routes.cpp` share exactly ONE grammar/validation
/// definition instead of two drifting copies (the class of bug #1647 exists
/// to prevent for audit helpers; the same reasoning applies to key grammar).
///
/// Addressing scheme: every config/secret row is addressed as
/// `<plugin>.<key>` (plugin and key are validated + stored as separate
/// columns by the store; this header defines the shared identifier grammar
/// both halves obey). A kill switch is addressed as `<plugin>` (whole-plugin)
/// or `<plugin>.<action>` (one action) — `kill_switch_scope_key` produces the
/// SAME canonical text form the store persists as its `scope_key` column, so
/// the store and the REST layer can never derive two different scope keys
/// for the same (plugin, action) pair.
///
/// Secret redaction: `redact_secret_for_audit`/`redact_secret_for_log` take
/// ONLY the (plugin, key) coordinate — never a value parameter — so a secret
/// value structurally cannot reach an audit/log call through this header.

#include <array>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::plugin_config {

// ── Identifier grammar ──────────────────────────────────────────────────

/// Max bytes for one plugin/key/action identifier segment.
inline constexpr std::size_t kMaxIdentifierBytes = 64;

/// True iff `s` is a valid identifier segment: starts with a lowercase ASCII
/// letter, followed by lowercase ASCII letters/digits/underscore, 1..64
/// bytes. Deliberately ASCII-only and hyphen-free — this identifier is
/// stored as a plain TEXT column, embedded verbatim in URL path segments
/// (plugin_config_routes.cpp), and embedded verbatim in audit `target_id`
/// strings, so the grammar stays maximally boring on purpose.
[[nodiscard]] inline bool is_valid_identifier(std::string_view s) {
    if (s.empty() || s.size() > kMaxIdentifierBytes)
        return false;
    if (s[0] < 'a' || s[0] > 'z')
        return false;
    for (unsigned char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

/// A key segment may additionally contain internal dots (nested config
/// paths, e.g. plugin=`email`, key=`smtp.host`) — but never a leading,
/// trailing, or doubled dot, and each dot-separated piece must itself be a
/// valid identifier. Max 128 bytes total (longer than a bare identifier —
/// this is the full nested key, not one segment).
inline constexpr std::size_t kMaxKeyBytes = 128;

[[nodiscard]] inline bool is_valid_key(std::string_view s) {
    if (s.empty() || s.size() > kMaxKeyBytes)
        return false;
    std::size_t seg_start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '.') {
            if (!is_valid_identifier(s.substr(seg_start, i - seg_start)))
                return false;
            seg_start = i + 1;
        }
    }
    return true;
}

/// One validated (plugin, key) pair — the address of a config or secret row.
struct PluginKey {
    std::string plugin;
    std::string key;
};

/// Validates `plugin_raw` as an identifier and `key_raw` as a key (which may
/// itself contain dots). Returns nullopt on any grammar violation — the
/// caller (store or route) must treat that as InvalidInput, never guess a
/// sanitized form.
[[nodiscard]] inline std::optional<PluginKey> parse_plugin_key(std::string_view plugin_raw,
                                                                std::string_view key_raw) {
    if (!is_valid_identifier(plugin_raw) || !is_valid_key(key_raw))
        return std::nullopt;
    return PluginKey{std::string(plugin_raw), std::string(key_raw)};
}

/// The external, human-facing `<plugin>.<key>` form — used ONLY for display
/// (audit target_id, error messages), never as a storage key (the store
/// keeps plugin/key as separate columns).
[[nodiscard]] inline std::string canonical_plugin_key(const PluginKey& pk) {
    return pk.plugin + "." + pk.key;
}

// ── Value caps ───────────────────────────────────────────────────────────

/// Plain config value cap. Generous enough for a JSON blob or a small
/// certificate/script fragment; small enough that a single config row can
/// never become a multi-megabyte smuggling channel.
inline constexpr std::size_t kMaxConfigValueBytes = 8192;

/// Secret plaintext cap — deliberately mirrors
/// `pg::SecretCodec::kMaxPlaintextSize` (64 KiB). Kept as an independent
/// constant (not an include) because this header must stay pg/store-free;
/// if the codec's cap ever changes, `plugin_config_store.cpp`'s encrypt call
/// will surface the codec's own `crypto_failure` on an oversized value
/// regardless of what this constant says — this cap exists to reject an
/// oversized value BEFORE spending a lease/encrypt attempt on it, not to be
/// the sole enforcement point.
inline constexpr std::size_t kMaxSecretValueBytes = 64 * 1024;

/// True iff `s` contains a byte the underlying transport/storage cannot
/// round-trip. Postgres `TEXT` truncates at an embedded NUL (libpq hands
/// `PQexecParams` a NUL-terminated C string via `pg::exec_params`), so a
/// config value carrying one would silently store a truncated value —
/// reject it instead (mirrors `auth_db.cpp`'s `has_embedded_nul` rule).
[[nodiscard]] inline bool has_embedded_nul(std::string_view s) {
    return s.find('\0') != std::string_view::npos;
}

/// Config values are plain TEXT — size-capped and NUL-free.
[[nodiscard]] inline bool is_valid_config_value(std::string_view value) {
    return value.size() <= kMaxConfigValueBytes && !has_embedded_nul(value);
}

/// Secret plaintext is opaque bytes handed to `SecretCodec::encrypt` — no
/// NUL restriction (it is never stored as TEXT), just a non-empty size cap.
[[nodiscard]] inline bool is_valid_secret_value(std::string_view value) {
    return !value.empty() && value.size() <= kMaxSecretValueBytes;
}

// ── Kill-switch scope ────────────────────────────────────────────────────

/// A normalized kill-switch scope: `action` empty means the whole-plugin
/// switch; non-empty names one action under the plugin.
struct KillSwitchScope {
    std::string plugin;
    std::string action; ///< "" = whole-plugin
};

/// True iff `s` is a reserved-namespace plugin name of the form
/// `__<identifier>__` (e.g. `__guard__`, `__observation__`) — the
/// server-internal namespace convention used by `system_reserved` dispatch
/// capabilities (`capability_decls/core_dispatch_capabilities.hpp`). Unrelated
/// to the agent-side `yuzu::agent::is_reserved_plugin_name`
/// (`agents/core/include/yuzu/agent/plugin_loader.hpp`) despite the identical
/// name — that one is an exact-match check against a closed allowlist of
/// literal AGENT PLUGIN names a `.so`/`.dll` cannot register as; this one is a
/// shape-only grammar check for a SERVER dispatch-capability plugin name.
/// Different components, different closed sets, no shared code.
/// Deliberately narrower than "starts and ends with `_`": the inner span
/// must itself be a valid identifier, so `__`, `____`, `__GUARD__`, and
/// `_guard_` are all rejected. Config/secret addressing
/// (`is_valid_identifier`/`parse_plugin_key`) does NOT accept this form —
/// only the kill-switch scope grammar below does (#3265: a reserved-plugin
/// dispatch must be kill-switch-ADDRESSABLE, never kill-switch-UNREACHABLE).
[[nodiscard]] inline bool is_reserved_plugin_name(std::string_view s) {
    constexpr std::string_view kSentinel = "__";
    if (!s.starts_with(kSentinel) || !s.ends_with(kSentinel))
        return false;
    // starts_with(kSentinel) already guarantees pos<=size(); for s.size()<4 the
    // count below underflows, but substr clamps it to size()-pos, so this stays
    // in-bounds for every input.
    return is_valid_identifier(s.substr(kSentinel.size(), s.size() - kSentinel.size() * 2));
}

/// Validates `plugin_raw` as an identifier OR a reserved-namespace plugin
/// name (`__<identifier>__`, #3265), and, if `action_raw` is non-empty,
/// validates it as an identifier too (an action name is a single segment,
/// never a dotted key — it names one REST/MCP action, not a nested config
/// path). The reserved-namespace allowance is scoped to the kill-switch
/// grammar only: it lets a `system_reserved` dispatch capability such as
/// `__guard__.push_rules` be explicitly kill-switched (or left alone, which
/// must mean "not killed" — see `PluginConfigStore::action_allowed`'s
/// no-row default), and does NOT extend to `is_valid_identifier`/
/// `parse_plugin_key`, which continue to gate ordinary config/secret rows.
[[nodiscard]] inline std::optional<KillSwitchScope>
parse_kill_switch_scope(std::string_view plugin_raw, std::string_view action_raw) {
    if (!is_valid_identifier(plugin_raw) && !is_reserved_plugin_name(plugin_raw))
        return std::nullopt;
    if (!action_raw.empty() && !is_valid_identifier(action_raw))
        return std::nullopt;
    return KillSwitchScope{std::string(plugin_raw), std::string(action_raw)};
}

/// The canonical stored/looked-up form: `<plugin>` (whole-plugin) or
/// `<plugin>.<action>`. Store and route MUST call this — never hand-concat —
/// so a plugin-level and an action-level row can never collide or diverge.
[[nodiscard]] inline std::string kill_switch_scope_key(const KillSwitchScope& scope) {
    if (scope.action.empty())
        return scope.plugin;
    return scope.plugin + "." + scope.action;
}

/// Reason cap — an operator-entered free-text explanation for a kill-switch
/// flip. Capped so a pathological submission can't bloat the audit/kill-
/// switch row indefinitely; control characters rejected (it renders in an
/// operator UI and lands in an audit `detail` string verbatim).
inline constexpr std::size_t kMaxReasonBytes = 512;

[[nodiscard]] inline bool is_valid_reason(std::string_view reason) {
    if (reason.size() > kMaxReasonBytes)
        return false;
    for (unsigned char c : reason) {
        // Printable ASCII + common whitespace (space, tab); reject other
        // control bytes (CR/LF/NUL/etc.) outright rather than escaping them —
        // this field is stored verbatim and displayed verbatim.
        if (c < 0x20 && c != '\t')
            return false;
        if (c == 0x7F)
            return false;
    }
    return true;
}

/// "Who set it" actor name — mirrors the identifier grammar's leniency
/// somewhat but allows the characters an `auth::Session::username` can
/// legitimately carry (local usernames, `oidc:<iss>#<sub>`,
/// `engine:<slug>`), so this is deliberately looser than
/// `is_valid_identifier`: length-capped and control-character-free only.
inline constexpr std::size_t kMaxActorBytes = 255;

[[nodiscard]] inline bool is_valid_actor(std::string_view who) {
    if (who.empty() || who.size() > kMaxActorBytes)
        return false;
    for (unsigned char c : who) {
        if (c < 0x20 || c == 0x7F)
            return false;
    }
    return true;
}

// ── Secret redaction ─────────────────────────────────────────────────────

/// The one string ANY log line or audit detail may show for a secret's
/// value — never the value itself.
inline constexpr std::string_view kRedactedSecretPlaceholder = "[REDACTED]";

/// Builds a safe audit/log detail string for a secret mutation. Takes ONLY
/// the (plugin, key) coordinate — there is no parameter through which a
/// caller could pass the plaintext, so this function cannot leak it by
/// construction, unlike a redaction helper that takes-and-discards a value.
[[nodiscard]] inline std::string redact_secret_for_audit(const PluginKey& pk) {
    return "plugin=" + pk.plugin + " key=" + pk.key + " value=" + std::string(kRedactedSecretPlaceholder);
}

/// Same structural guarantee as `redact_secret_for_audit` (no value
/// parameter — cannot leak a plaintext by construction), for a `spdlog`
/// line rather than an audit detail string. Distinct entry point (rather
/// than reusing `redact_secret_for_audit` at every log call site) so a log
/// line's format can diverge from an audit detail's without either call
/// site having to remember which helper it borrowed.
[[nodiscard]] inline std::string redact_secret_for_log(const PluginKey& pk) {
    return "plugin=" + pk.plugin + " key=" + pk.key + " value=" + std::string(kRedactedSecretPlaceholder);
}

} // namespace yuzu::server::plugin_config
