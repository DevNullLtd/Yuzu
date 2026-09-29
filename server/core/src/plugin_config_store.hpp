#pragma once

/// @file plugin_config_store.hpp
/// Born-on-Postgres plugin configuration/secret plane + per-action kill
/// switch (PR1.5b). Schema `plugin_config_store` (ADR-0008 naming rule:
/// snake_case of the FULL class name including `Store`). Follows
/// `docs/postgres-store-playbook.md` §"Recipe — a new (greenfield) store"
/// exactly — `offline_endpoint_store.hpp`/`auth_db.cpp` are the two worked
/// references this store's shape is drawn from.
///
/// Posture: AUTHORITATIVE (ADR-0012 §1). This is config/secret/kill-switch
/// data — there is no in-memory layer that could stand in as "the real
/// answer" the way `OfflineEndpointStore`'s durability-on-top posture
/// assumes. Every read returns a typed `std::expected<T, Error>` (ADR-0036):
/// a genuine "no rows" is a value (possibly empty), a runtime DB failure is
/// `unexpected(Error::...)` — the two are never collapsed. The kill-switch
/// evaluation entrypoint (`action_allowed`) goes one step further and
/// collapses ITS OWN error case to `false` (disabled) internally, precisely
/// because that decision feeds a dispatch gate where a silently-empty/false
/// answer would be misread as "not killed" (see its doc comment).
///
/// Three row kinds, three tables, one schema:
///   - `configs`       — plain `<plugin>.<key>` -> value. Freely readable.
///   - `secrets`       — sealed `<plugin>.<key>` -> `SecretCodec` envelope.
///     WRITE-ONLY: no method on this store, anywhere, returns a secret's
///     plaintext — `set_secret`'s own return value is metadata
///     (`SecretMeta`, which structurally has no value field), never an echo
///     of what it just sealed.
///   - `kill_switches` — `<plugin>` or `<plugin>.<action>` -> enabled +
///     reason + who. Absence of a row means "enabled" (not killed) — a row
///     is written only once an operator has explicitly flipped the switch.
///
/// ADR-0010 secret handling — one `SecretCodec` instance per store (the
/// playbook's "Instance model", `AuthDB` is the worked precedent this
/// mirrors): the CALLER constructs the codec and this ctor registers this
/// store's own secret column (`plugin_config_store.secrets.sealed_value`,
/// pk `scope_key` — a deterministic `<plugin>.<key>` TEXT identity, not the
/// numeric `id`; see `set_secret`'s doc comment for why) immediately, so
/// `SecretCodec::init()` (which the caller runs right after this ctor
/// returns, per the playbook's register-before-init sequencing) validates
/// it.
///
/// KEK-rotation-surface enrolment (#2568/#2580) — NOT fully closed by this
/// package: registering the column makes it eligible for `rotate`/`rewrap`,
/// but the LIVE rotate/rewrap endpoints (`kek_routes.hpp`, `server.cpp`)
/// today invoke those operations on `auth_secret_codec_` specifically, not
/// on an arbitrary registered codec. `server.cpp` is out of this package's
/// owned files (boundary discipline), so actually wiring this store's own
/// codec instance into the live rotate/rewrap call path — so an operator's
/// `/rotate` or `/rewrap` request also re-wraps `secrets.sealed_value` — is
/// the constructing/wiring PR's job, exactly like the rest of this store's
/// server.cpp wiring. Recorded as an explicit open item in
/// `docs/adr/3005-plugin-config-store.md` rather than left implicit.
///
/// See `docs/adr/3005-plugin-config-store.md` for the full record: schema,
/// posture, secret handling, KEK enrolment, and the open agent-side secret-
/// delivery gap this package deliberately leaves unclosed.

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
class SecretCodec;
} // namespace yuzu::server::pg

namespace yuzu::server {

class PluginConfigStore {
public:
    enum class Error {
        Unavailable,       ///< store not open, or a bounded lease could not be acquired in time
        NotFound,          ///< no row for the given key (a genuine "not found", not a DB error)
        InvalidInput,      ///< a plugin/key/value/reason/actor failed plugin_config_parsers.hpp validation
        WriteFailed,       ///< a write statement failed or returned zero affected rows unexpectedly
        SecretUnavailable, ///< SecretCodec encrypt failure — the write was aborted, nothing persisted
    };
    [[nodiscard]] static std::string_view to_string(Error err);

    struct ConfigEntry {
        std::string plugin;
        std::string key;
        std::string value;
        std::int64_t updated_at_ms{0};
        std::string updated_by;
    };

    /// Secret METADATA only. Deliberately carries no value field — a
    /// secret's plaintext cannot be assigned into this struct even by
    /// accident, which is what makes the write-only contract structural
    /// rather than a discipline every call site must remember.
    struct SecretMeta {
        std::string plugin;
        std::string key;
        std::int64_t updated_at_ms{0};
        std::string updated_by;
    };

    struct KillSwitchEntry {
        std::string plugin;
        std::string action; ///< "" = whole-plugin switch
        bool enabled{true};
        std::string reason;
        std::string set_by;
        std::int64_t updated_at_ms{0};
    };

    /// Borrows the shared pool and the CALLER'S OWN `SecretCodec` instance
    /// (ADR-0010 per-store model). Runs the `plugin_config_store` schema
    /// migration on a pinned, unbounded, construction-only lease
    /// (ADR-0012 §2), then registers the `secrets.sealed_value` secret
    /// column. `is_open()` is false if the lease was empty, the migration
    /// failed, or column registration failed (should only happen if this
    /// ctor somehow ran twice against the same codec — a duplicate
    /// registration is refused by the codec).
    PluginConfigStore(pg::PgPool& pool, pg::SecretCodec& secret_codec);

    PluginConfigStore(const PluginConfigStore&) = delete;
    PluginConfigStore& operator=(const PluginConfigStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    // ── Config (plain, readable) ────────────────────────────────────────

    /// `plugin` empty lists every plugin's config; non-empty scopes to one
    /// plugin. Ordered (plugin, key). Empty vector is a genuine "no rows",
    /// distinct from `unexpected` (a read failure) — ADR-0036.
    ///
    /// Results are capped at `kListRowCap` rows (defensive — see
    /// plugin_config_store.cpp). `truncated`, if non-null, is set to true
    /// when more rows exist than were returned — a caller that ignores it
    /// gets the exact same rows as before this parameter existed, but a
    /// caller that reads it (the REST list route does) can surface the
    /// omission instead of silently presenting a partial list as complete.
    [[nodiscard]] std::expected<std::vector<ConfigEntry>, Error>
    list_config(std::string_view plugin, bool* truncated = nullptr) const;
    [[nodiscard]] std::expected<ConfigEntry, Error> get_config(std::string_view plugin,
                                                               std::string_view key) const;
    /// Upsert. Mutate-and-return via `RETURNING` (never `sqlite3_changes()`-
    /// style mutate-then-count, per the playbook's #1033-banning idiom).
    [[nodiscard]] std::expected<ConfigEntry, Error> set_config(std::string_view plugin,
                                                               std::string_view key,
                                                               std::string_view value,
                                                               std::string_view updated_by);
    /// `Error::NotFound` when no row matched (nothing to delete) — the
    /// caller (route layer) treats that as a 404, not a write failure.
    [[nodiscard]] std::expected<void, Error> delete_config(std::string_view plugin,
                                                            std::string_view key);

    // ── Secrets (sealed, write-only) ────────────────────────────────────

    /// Encrypts `plaintext_value` under a FRESH DEK (a DEK encrypts exactly
    /// one value exactly once — an update mints a new DEK, never reuse) and
    /// upserts the sealed blob. The AAD identity is the deterministic
    /// `scope_key` (`<plugin>.<key>`, from `canonical_plugin_key`) rather
    /// than a DB-assigned row id — this needs no "get-or-create the row
    /// first to learn its id" round trip before encrypting, so a brand-new
    /// secret is never briefly represented by a placeholder/empty
    /// `sealed_value` row, and an existing row's metadata is never touched
    /// until the encrypted blob it will carry is already in hand. Returns
    /// METADATA ONLY; see the `SecretMeta` doc comment — no method on this
    /// store ever returns a secret's plaintext.
    [[nodiscard]] std::expected<SecretMeta, Error> set_secret(std::string_view plugin,
                                                               std::string_view key,
                                                               std::string_view plaintext_value,
                                                               std::string_view updated_by);
    [[nodiscard]] std::expected<void, Error> delete_secret(std::string_view plugin,
                                                            std::string_view key);

    // ── Kill switch ──────────────────────────────────────────────────────

    /// Display/inspection accessor for the REST GET route. Resolves
    /// action-level first, falling back to the plugin-level row, falling
    /// back to the DEFAULT enabled state (`enabled=true`, empty
    /// reason/set_by) when neither row exists — absence of a row is a
    /// legitimate state, not a `NotFound` error. A genuine DB failure is
    /// `unexpected(Error::Unavailable)`.
    ///
    /// NOT the fail-closed gate — a caller making a go/no-go dispatch
    /// decision MUST use `action_allowed` below, never this accessor
    /// (an `unexpected` here must not be collapsed to "enabled" by a
    /// careless caller; `action_allowed` is what performs that collapse
    /// correctly, to `false`).
    [[nodiscard]] std::expected<KillSwitchEntry, Error>
    get_kill_switch(std::string_view plugin, std::string_view action) const;

    /// Flip the switch. Mutate-and-return via `RETURNING`.
    [[nodiscard]] std::expected<KillSwitchEntry, Error>
    set_kill_switch(std::string_view plugin, std::string_view action, bool enabled,
                    std::string_view reason, std::string_view set_by);

    /// THE fail-closed chokepoint every dispatch-gating caller must use.
    /// Action-level row wins over a plugin-level row; no row at all means
    /// "not killed" (returns true). ANY store error — closed store, lease
    /// timeout, query failure — returns `false`: degraded means disabled,
    /// never enabled (ADR-0036 authoritative-read rule; a silently
    /// empty/false-collapsed kill-switch read is exactly the fail-open shape
    /// that rule exists to forbid, so this function performs the collapse
    /// explicitly and in the ONE place every caller shares, rather than
    /// leaving each dispatch call site to remember it).
    [[nodiscard]] bool action_allowed(std::string_view plugin, std::string_view action) const;

    /// Wave 7: idempotent boot-time seed for a plugin that ships
    /// default-off (e.g. `execution_artifacts`, the forensics class). Writes
    /// a PLUGIN-LEVEL row (`action` = "") with `enabled=false`,
    /// `set_by="system"` — `ON CONFLICT (scope_key) DO NOTHING`, so this
    /// NEVER clobbers an operator's own `set_kill_switch` decision, on this
    /// call or a later restart. Returns `false` only on a genuine write
    /// failure (closed store, invalid plugin/reason, or the INSERT itself
    /// failing) — a conflict (row already exists, whichever value it holds)
    /// is success, not a distinct case the caller needs to branch on.
    [[nodiscard]] bool seed_kill_switch_default_off(std::string_view plugin,
                                                     std::string_view reason);

private:
    pg::PgPool& pool_;
    pg::SecretCodec& secret_codec_;
    bool open_{false};
};

} // namespace yuzu::server
