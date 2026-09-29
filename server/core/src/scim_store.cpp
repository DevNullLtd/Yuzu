#include "yuzu/server/scim_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "secure_random.hpp" // random_hex — CSPRNG-backed scim_id generation

#include <yuzu/server/auth.hpp> // AuthManager::sha256_hex — reuses the shared hashing helper

#include <openssl/crypto.h> // CRYPTO_memcmp — constant-time token compare

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "scim_store";

// Bounded acquires (ADR-0012 §2). SCIM is an admin/IdP-provisioning surface,
// not a gRPC hot path, but every acquire still stays bounded per the
// playbook — reads get a shorter budget than the transactional writes
// (group replace / delete cascades two statements).
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2500};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE scim_resources ("
         "  id            BIGSERIAL,"
         "  scim_id       TEXT PRIMARY KEY,"
         "  external_id   TEXT,"
         "  username      TEXT NOT NULL UNIQUE,"
         "  active        BOOLEAN NOT NULL DEFAULT TRUE,"
         "  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  etag_version  BIGINT NOT NULL DEFAULT 1);"
         "CREATE INDEX scim_resources_external_id_idx ON scim_resources (external_id);"
         "CREATE INDEX scim_resources_id_idx ON scim_resources (id);"

         "CREATE TABLE scim_tokens ("
         "  id            BIGSERIAL PRIMARY KEY,"
         "  token_hash    TEXT NOT NULL,"
         "  label         TEXT,"
         "  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  revoked_at    TIMESTAMPTZ);"
         "CREATE INDEX scim_tokens_active_idx ON scim_tokens (revoked_at) WHERE revoked_at IS NULL;"},
        // v2 (#2021, slice 2): SCIM Groups + membership join table.
        {2,
         "CREATE TABLE scim_groups ("
         "  id            BIGSERIAL,"
         "  scim_id       TEXT PRIMARY KEY,"
         "  external_id   TEXT,"
         "  display_name  TEXT NOT NULL,"
         "  active        BOOLEAN NOT NULL DEFAULT TRUE,"
         "  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  etag_version  BIGINT NOT NULL DEFAULT 1);"
         "CREATE INDEX scim_groups_id_idx ON scim_groups (id);"

         "CREATE TABLE scim_group_members ("
         "  group_scim_id TEXT NOT NULL,"
         "  user_scim_id  TEXT NOT NULL,"
         "  PRIMARY KEY (group_scim_id, user_scim_id));"
         "CREATE INDEX scim_group_members_user_idx ON scim_group_members (user_scim_id);"},
        // v3 (ADR-2001, Task 1 foundation): the identity-linkage tables +
        // the scim_resources.external_id ambiguity fix. All three DDL
        // changes below run as ONE migration transaction (the runner's
        // exec_ok wraps the whole multi-statement string), so the partial-
        // unique index failing rolls the two new tables back with it —
        // there is no "tables created but store still opens with an
        // unenforced uniqueness assumption" outcome.
        {3,
         // identity_links — durable (iss, sub) -> scim_id link recorded at
         // OIDC login (ADR-2001 §2). UNIQUE (iss, sub): one link per OIDC
         // identity. Secondary index on scim_id: deprovision looks up BY
         // scim_id, which the (iss,sub) key does not serve.
         "CREATE TABLE identity_links ("
         "  iss        TEXT NOT NULL,"
         "  sub        TEXT NOT NULL,"
         "  scim_id    TEXT NOT NULL,"
         "  linked_at  BIGINT NOT NULL,"
         "  UNIQUE (iss, sub));"
         "CREATE INDEX identity_links_scim_id_idx ON identity_links (scim_id);"

         // oidc_login_observations — every OIDC login's attempted
         // candidate claim value(s), regardless of match (ADR-2001 D2
         // detector). UNIQUE (iss, sub, claim_name): one observation PER
         // CANDIDATE CLAIM per identity, upserted on each login. Deliberately
         // NOT (iss, sub) alone (governance Gate 7 BLOCKING fix): the
         // headline D2 misconfiguration is an operator running with
         // `--oidc-scim-link-claim=sub` while the SCIM externalId is
         // actually the Entra `oid` — under a (iss, sub)-unique table only
         // the CONFIGURED claim's value survives the upsert, so
         // `observation_matches(external_id)` (keyed on the oid value) never
         // matches and D2 never fires for the exact misconfiguration it
         // exists to catch. Recording one row per candidate claim (sub AND
         // oid, when both are present) means the oid candidate is on record
         // even though link FORMATION never used it.
         "CREATE TABLE oidc_login_observations ("
         "  iss          TEXT NOT NULL,"
         "  sub          TEXT NOT NULL,"
         "  claim_name   TEXT NOT NULL,"
         "  claim_value  TEXT NOT NULL,"
         "  seen_at      BIGINT NOT NULL,"
         "  UNIQUE (iss, sub, claim_name));"

         // scim_resources.external_id ambiguity fix (codex-sol plan-review
         // BLOCK): external_id was indexed but never UNIQUE, so a
         // pre-existing duplicate could let link formation mis-link an
         // OIDC identity to the wrong SCIM user. A plain (non-CONCURRENT —
         // this runs inside the migration's transaction, and
         // CREATE INDEX CONCURRENTLY cannot run in one, see
         // pg_migration_runner.hpp) partial unique index means Postgres
         // itself detects any pre-existing duplicate non-empty external_id
         // and raises a unique_violation, which fails this whole migration
         // (and, per the comment above, the two new tables with it) —
         // construction then reports !is_open(), fail-closed, matching
         // this store's ADR-0012 posture. No separate detect-and-refuse
         // code path needed: the index creation IS the detector.
         "CREATE UNIQUE INDEX scim_resources_external_id_uniq ON scim_resources (external_id) "
         "WHERE external_id IS NOT NULL;"},
        // v4 (ADR-2001 PR4a): saml_identity_links — the SAML analogue of
        // v3's identity_links, durably recording the (entity_id, name_id)
        // SAML identity that a successful SAML login resolved to a SCIM
        // resource. Deliberately a SEPARATE table (never a generalization
        // of identity_links) — keeps this PR off PR3's scim_store schema
        // surface. UNIQUE (entity_id, name_id): one link per SAML identity.
        // Secondary index on scim_id: deprovision looks up BY scim_id,
        // which the (entity_id, name_id) key does not serve — same
        // rationale as identity_links_scim_id_idx above.
        {4,
         "CREATE TABLE saml_identity_links ("
         "  entity_id  TEXT NOT NULL,"
         "  name_id    TEXT NOT NULL,"
         "  scim_id    TEXT NOT NULL,"
         "  linked_at  BIGINT NOT NULL,"
         "  UNIQUE (entity_id, name_id));"
         "CREATE INDEX saml_identity_links_scim_id_idx ON saml_identity_links (scim_id);"},
        // v5 (ADR-2001 #3072, store layer): saml_login_observations — the
        // SAML analogue of v3's oidc_login_observations, recording every
        // SAML login's NameID observation regardless of whether it matched
        // a SCIM resource (the SAML D2-style detector). UNIQUE (entity_id,
        // name_id, name_id_format): name_id_format is DELIBERATELY part of
        // the uniqueness key, not folded into (entity_id, name_id) alone —
        // a later login presenting the same NameID value under a STABLE
        // format must not erase an earlier observation recorded under an
        // unstable one; each (entity_id, name_id, format) triple is its own
        // row. Secondary index on name_id: saml_observation_matches looks
        // up BY name_id alone, which the 3-column UNIQUE key does not serve.
        {5,
         "CREATE TABLE saml_login_observations ("
         "  entity_id      TEXT   NOT NULL,"
         "  name_id        TEXT   NOT NULL,"
         "  name_id_format TEXT   NOT NULL,"
         "  seen_at        BIGINT NOT NULL,"
         "  UNIQUE (entity_id, name_id, name_id_format));"
         "CREATE INDEX saml_login_observations_name_id_idx ON saml_login_observations (name_id);"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
}

// Null-safe column read.
std::string col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? std::string() : std::string(PQgetvalue(res, row, c));
}

// Column projection shared by every SELECT/RETURNING on scim_resources —
// keep in sync with `read_resource`'s column order. Timestamps are formatted
// to ISO-8601 UTC text at read time (RFC 7643 meta.created/lastModified are
// xsd:dateTime) rather than exposing the raw TIMESTAMPTZ wire format.
constexpr const char* kResourceCols =
    "scim_id, external_id, username, active, "
    "to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
    "to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
    "etag_version";

ScimResource read_resource(PGresult* res, int row) {
    ScimResource r;
    int c = 0;
    r.scim_id = col(res, row, c++);
    r.external_id = col(res, row, c++);
    r.username = col(res, row, c++);
    r.active = to_bool(PQgetisnull(res, row, c) ? nullptr : PQgetvalue(res, row, c));
    ++c;
    r.created_at = col(res, row, c++);
    r.updated_at = col(res, row, c++);
    r.etag_version = to_i64(PQgetisnull(res, row, c) ? nullptr : PQgetvalue(res, row, c));
    ++c;
    return r;
}

// Column projection shared by every SELECT/RETURNING on scim_groups — keep
// in sync with `read_group`'s column order.
constexpr const char* kGroupCols =
    "scim_id, external_id, display_name, active, "
    "to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
    "to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
    "etag_version";

ScimGroup read_group(PGresult* res, int row) {
    ScimGroup g;
    int c = 0;
    g.scim_id = col(res, row, c++);
    g.external_id = col(res, row, c++);
    g.display_name = col(res, row, c++);
    g.active = to_bool(PQgetisnull(res, row, c) ? nullptr : PQgetvalue(res, row, c));
    ++c;
    g.created_at = col(res, row, c++);
    g.updated_at = col(res, row, c++);
    g.etag_version = to_i64(PQgetisnull(res, row, c) ? nullptr : PQgetvalue(res, row, c));
    ++c;
    return g;
}

// Binds `external_id` as SQL NULL when empty (an empty externalId is "the
// IdP never sent one", not a meaningful stored value) — mirrors the
// create_resource/create_group SQLite-era NULL-bind.
std::optional<std::string> opt_ext(const std::string& external_id) {
    if (external_id.empty())
        return std::nullopt;
    return external_id;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────

ScimStore::ScimStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error(
            "ScimStore: no database connection at construction ({}) — SCIM store disabled",
            pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ScimStore: schema migration failed — SCIM store disabled");
        return;
    }
    open_ = true;
    spdlog::info("ScimStore: opened (schema {})", kStoreName);
}

bool ScimStore::is_open() const noexcept {
    return open_;
}

// ── Bearer token (SCIM credential) ──────────────────────────────────────

bool ScimStore::set_token(const std::string& raw, const std::string& label) {
    if (!open_ || raw.empty())
        return false;

    std::string hash = auth::AuthManager::sha256_hex(raw);

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    // Upsert-by-label: revoke any existing active token sharing this label
    // first, so re-running config with the same label rotates the token
    // instead of leaving the old one both active and orphaned. Best-effort
    // (result not checked) — matches the SQLite-era behavior; the INSERT
    // below is what this call's success/failure is judged on.
    pg::exec_params(lease.get(),
                    "UPDATE scim_store.scim_tokens SET revoked_at = now() "
                    "WHERE label = $1 AND revoked_at IS NULL",
                    std::vector<std::string>{label});

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO scim_store.scim_tokens (token_hash, label, created_at) "
        "VALUES ($1, $2, now()) RETURNING id",
        std::vector<std::string>{hash, label});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) == 1;
}

bool ScimStore::has_token() const {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return false;
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT 1 FROM scim_store.scim_tokens WHERE revoked_at IS NULL LIMIT 1",
        std::vector<std::string>{});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

bool ScimStore::validate_token(const std::string& raw) const {
    if (!open_ || raw.empty())
        return false;

    std::string hash = auth::AuthManager::sha256_hex(raw);

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return false;

    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT token_hash FROM scim_store.scim_tokens WHERE revoked_at IS NULL",
                        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return false;

    // Scan every active hash rather than short-circuiting on first match —
    // each individual comparison is constant-time via CRYPTO_memcmp, and not
    // early-returning keeps the total scan time independent of which row (if
    // any) matches.
    bool matched = false;
    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        if (PQgetisnull(res.get(), i, 0))
            continue;
        const char* candidate = PQgetvalue(res.get(), i, 0);
        const auto len = static_cast<std::size_t>(PQgetlength(res.get(), i, 0));
        if (len == hash.size() && CRYPTO_memcmp(candidate, hash.data(), hash.size()) == 0) {
            matched = true;
        }
    }
    return matched;
}

// ── SCIM resources ───────────────────────────────────────────────────────

std::optional<ScimResource> ScimStore::create_resource(const std::string& username,
                                                        const std::string& external_id) {
    if (!open_ || username.empty())
        return std::nullopt;

    auto id_result = random_hex(16); // 16 CSPRNG bytes -> 32 hex chars
    if (!id_result.has_value())
        return std::nullopt;
    std::string scim_id = *id_result;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::nullopt;

    std::string sql = std::string("INSERT INTO scim_store.scim_resources "
                                  "(scim_id, external_id, username, active, created_at, updated_at, "
                                  " etag_version) "
                                  "VALUES ($1, $2, $3, TRUE, now(), now(), 1) RETURNING ") +
                     kResourceCols;
    std::vector<std::optional<std::string>> params{scim_id, opt_ext(external_id), username};
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_resource(res.get(), 0);
}

std::optional<ScimResource> ScimStore::get_by_scim_id(const std::string& scim_id) const {
    if (!open_ || scim_id.empty())
        return std::nullopt;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    std::string sql =
        std::string("SELECT ") + kResourceCols + " FROM scim_store.scim_resources WHERE scim_id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{scim_id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_resource(res.get(), 0);
}

std::optional<bool> ScimStore::resource_exists(const std::string& scim_id) const {
    if (!open_)
        return std::nullopt; // store unusable — never "does not exist"
    if (scim_id.empty())
        return false; // nothing was asked for; a definitive negative

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT 1 FROM scim_store.scim_resources WHERE scim_id = $1",
                        std::vector<std::string>{scim_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;
    return PQntuples(res.get()) > 0;
}

std::optional<ScimResource> ScimStore::get_by_username(const std::string& username) const {
    if (!open_ || username.empty())
        return std::nullopt;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    std::string sql =
        std::string("SELECT ") + kResourceCols + " FROM scim_store.scim_resources WHERE username = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_resource(res.get(), 0);
}

std::optional<std::optional<ScimResource>>
ScimStore::get_by_username_checked(const std::string& username) const {
    if (!open_)
        return std::nullopt; // store unusable — never conflate with "not found"
    if (username.empty())
        return std::optional<ScimResource>{}; // nothing asked for — a definitive non-match

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt; // lease timeout — store error, not "not found"

    std::string sql =
        std::string("SELECT ") + kResourceCols + " FROM scim_store.scim_resources WHERE username = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt; // query failed — store error, not "not found"
    if (PQntuples(res.get()) == 0)
        return std::optional<ScimResource>{}; // store answered: genuinely no such row
    return std::optional<ScimResource>{read_resource(res.get(), 0)};
}

std::optional<ScimResource> ScimStore::find_by_external_id(const std::string& external_id) const {
    if (!open_ || external_id.empty())
        return std::nullopt;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    std::string sql = std::string("SELECT ") + kResourceCols +
                      " FROM scim_store.scim_resources WHERE external_id = $1 LIMIT 1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{external_id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_resource(res.get(), 0);
}

std::optional<ScimResource>
ScimStore::find_unique_active_by_external_id(const std::string& external_id) const {
    // Compatibility wrapper (ADR-2001 #3072): resource for `matched`,
    // nullopt for every other status — byte-unchanged behaviour for every
    // pre-existing caller.
    auto checked = find_unique_active_by_external_id_checked(external_id);
    if (checked.status == ActiveExternalIdLookupStatus::matched)
        return std::move(checked.resource);
    return std::nullopt;
}

ActiveExternalIdLookupResult
ScimStore::find_unique_active_by_external_id_checked(const std::string& external_id) const {
    if (!open_)
        return {.status = ActiveExternalIdLookupStatus::store_error, .resource = std::nullopt};
    if (external_id.empty())
        return {.status = ActiveExternalIdLookupStatus::no_match, .resource = std::nullopt};

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return {.status = ActiveExternalIdLookupStatus::store_error, .resource = std::nullopt};

    // Deliberately NO `LIMIT 1` — the exactly-one-match guarantee is the
    // point of this method (ADR-2001 §2 mis-link guard). Any number of
    // rows other than exactly 1 must fall through to `ambiguous`/`no_match`
    // below, including 2+: an ambiguous external_id is "no link", never an
    // arbitrary pick.
    std::string sql = std::string("SELECT ") + kResourceCols +
                      " FROM scim_store.scim_resources WHERE external_id = $1 AND active = TRUE";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{external_id});
    if (res.status() != PGRES_TUPLES_OK)
        return {.status = ActiveExternalIdLookupStatus::store_error, .resource = std::nullopt};

    const int rows = PQntuples(res.get());
    if (rows == 0)
        return {.status = ActiveExternalIdLookupStatus::no_match, .resource = std::nullopt};
    if (rows > 1)
        return {.status = ActiveExternalIdLookupStatus::ambiguous, .resource = std::nullopt};
    return {.status = ActiveExternalIdLookupStatus::matched, .resource = read_resource(res.get(), 0)};
}

std::vector<ScimResource> ScimStore::list(int start_index, int count, int& total_out) const {
    total_out = 0;
    std::vector<ScimResource> results;
    if (!open_)
        return results;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    {
        pg::PgResult cres = pg::exec_params(
            lease.get(), "SELECT COUNT(*) FROM scim_store.scim_resources", std::vector<std::string>{});
        if (cres.status() == PGRES_TUPLES_OK && PQntuples(cres.get()) == 1)
            total_out = static_cast<int>(to_i64(PQgetvalue(cres.get(), 0, 0)));
    }

    if (count <= 0)
        return results;
    // SCIM startIndex is 1-based (RFC 7644 §3.4.2); clamp anything below 1
    // (including 0/negative from a malformed caller) to the first page.
    int offset = start_index > 1 ? start_index - 1 : 0;

    // ORDER BY the hidden monotonic `id` (BIGSERIAL) — the Postgres
    // equivalent of SQLite's implicit `rowid` insertion order the original
    // store paginated by.
    std::string sql = std::string("SELECT ") + kResourceCols +
                      " FROM scim_store.scim_resources ORDER BY id ASC LIMIT $1::bigint OFFSET $2::bigint";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(count), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(read_resource(res.get(), i));
    return results;
}

bool ScimStore::set_active(const std::string& scim_id, bool active) {
    if (!open_ || scim_id.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE scim_store.scim_resources SET active = $1::boolean, etag_version = etag_version + 1, "
        "updated_at = now() WHERE scim_id = $2 RETURNING scim_id",
        std::vector<std::string>{active ? "true" : "false", scim_id});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) == 1;
}

bool ScimStore::update_resource(const std::string& scim_id, const std::string& username,
                                const std::string& external_id) {
    if (!open_ || scim_id.empty() || username.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    std::vector<std::optional<std::string>> params{username, opt_ext(external_id), scim_id};
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE scim_store.scim_resources SET username = $1, external_id = $2, "
        "etag_version = etag_version + 1, updated_at = now() WHERE scim_id = $3 RETURNING scim_id",
        params);
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) == 1;
}

std::optional<bool> ScimStore::delete_by_scim_id(const std::string& scim_id) {
    if (!open_ || scim_id.empty())
        return std::nullopt;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::nullopt;

    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM scim_store.scim_resources WHERE scim_id = $1 RETURNING scim_id",
        std::vector<std::string>{scim_id});
    // true = a row matched and was deleted; false = no row matched (already
    // gone) — a real, idempotent-success outcome, not an error; nullopt =
    // a genuine query-time error (lease timeout / backend error) — must NOT
    // be collapsed into "already gone", or the caller 204s a failed
    // teardown instead of 500ing it.
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ScimStore::delete_by_scim_id: query failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    return PQntuples(res.get()) > 0;
}

// ── SCIM groups ──────────────────────────────────────────────────────────

std::optional<ScimGroup> ScimStore::create_group(const std::string& display_name,
                                                 const std::string& external_id) {
    if (!open_ || display_name.empty())
        return std::nullopt;

    auto id_result = random_hex(16); // 16 CSPRNG bytes -> 32 hex chars
    if (!id_result.has_value())
        return std::nullopt;
    std::string scim_id = *id_result;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::nullopt;

    std::string sql = std::string("INSERT INTO scim_store.scim_groups "
                                  "(scim_id, external_id, display_name, active, created_at, "
                                  " updated_at, etag_version) "
                                  "VALUES ($1, $2, $3, TRUE, now(), now(), 1) RETURNING ") +
                     kGroupCols;
    std::vector<std::optional<std::string>> params{scim_id, opt_ext(external_id), display_name};
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_group(res.get(), 0);
}

std::optional<ScimGroup> ScimStore::get_group_by_id(const std::string& scim_id) const {
    if (!open_ || scim_id.empty())
        return std::nullopt;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    std::string sql =
        std::string("SELECT ") + kGroupCols + " FROM scim_store.scim_groups WHERE scim_id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{scim_id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_group(res.get(), 0);
}

std::optional<ScimGroup>
ScimStore::get_group_by_display_name(const std::string& display_name) const {
    if (!open_ || display_name.empty())
        return std::nullopt;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    std::string sql =
        std::string("SELECT ") + kGroupCols + " FROM scim_store.scim_groups WHERE display_name = $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{display_name});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_group(res.get(), 0);
}

std::vector<ScimGroup> ScimStore::list_groups(int start_index, int count, int& total_out) const {
    total_out = 0;
    std::vector<ScimGroup> results;
    if (!open_)
        return results;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    {
        pg::PgResult cres = pg::exec_params(
            lease.get(), "SELECT COUNT(*) FROM scim_store.scim_groups", std::vector<std::string>{});
        if (cres.status() == PGRES_TUPLES_OK && PQntuples(cres.get()) == 1)
            total_out = static_cast<int>(to_i64(PQgetvalue(cres.get(), 0, 0)));
    }

    if (count <= 0)
        return results;
    // SCIM startIndex is 1-based (RFC 7644 §3.4.2); clamp anything below 1
    // (including 0/negative from a malformed caller) to the first page.
    int offset = start_index > 1 ? start_index - 1 : 0;

    std::string sql = std::string("SELECT ") + kGroupCols +
                      " FROM scim_store.scim_groups ORDER BY id ASC LIMIT $1::bigint OFFSET $2::bigint";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(count), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(read_group(res.get(), i));
    return results;
}

int ScimStore::count_groups() const {
    if (!open_)
        return 0;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;

    pg::PgResult res = pg::exec_params(lease.get(), "SELECT COUNT(*) FROM scim_store.scim_groups",
                                       std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<int>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

bool ScimStore::update_group(const std::string& scim_id, const std::string& display_name,
                             const std::string& external_id) {
    if (!open_ || scim_id.empty() || display_name.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    std::vector<std::optional<std::string>> params{display_name, opt_ext(external_id), scim_id};
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE scim_store.scim_groups SET display_name = $1, external_id = $2, "
        "etag_version = etag_version + 1, updated_at = now() WHERE scim_id = $3 RETURNING scim_id",
        params);
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) == 1;
}

std::optional<bool> ScimStore::delete_group(const std::string& scim_id) {
    if (!open_ || scim_id.empty())
        return std::nullopt;

    bool matched = false;
    // Both the group row's delete AND its members' delete commit in ONE
    // transaction (or neither) — mirrors the SQLite-era BEGIN IMMEDIATE /
    // COMMIT pairing, so the reverse lookup (list_group_display_names_for_user)
    // never dangles on a mid-write failure.
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn, "DELETE FROM scim_store.scim_groups WHERE scim_id = $1 RETURNING scim_id",
            std::vector<std::string>{scim_id});
        if (res.status() != PGRES_TUPLES_OK)
            return false;
        matched = PQntuples(res.get()) > 0;

        pg::PgResult mres = pg::exec_params(
            conn, "DELETE FROM scim_store.scim_group_members WHERE group_scim_id = $1",
            std::vector<std::string>{scim_id});
        return mres.status() == PGRES_COMMAND_OK;
    });
    // !ok covers both "the transaction never committed" (genuine error,
    // rolled back — `matched` is not a committed fact) and "no connection
    // available in time" — either way nullopt, never collapsed into
    // "already gone" (mirrors delete_by_scim_id).
    if (!ok)
        return std::nullopt;
    return matched;
}

bool ScimStore::set_group_members(const std::string& group_scim_id,
                                  const std::vector<std::string>& user_scim_ids) {
    if (!open_ || group_scim_id.empty())
        return false;

    return pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult del = pg::exec_params(
            conn, "DELETE FROM scim_store.scim_group_members WHERE group_scim_id = $1",
            std::vector<std::string>{group_scim_id});
        if (del.status() != PGRES_COMMAND_OK)
            return false;

        for (const auto& user_scim_id : user_scim_ids) {
            pg::PgResult ins = pg::exec_params(
                conn,
                "INSERT INTO scim_store.scim_group_members (group_scim_id, user_scim_id) "
                "VALUES ($1, $2) ON CONFLICT (group_scim_id, user_scim_id) DO NOTHING",
                std::vector<std::string>{group_scim_id, user_scim_id});
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        return true;
    });
}

std::optional<bool> ScimStore::replace_group_and_members(
    const std::string& scim_id, const std::string& display_name,
    const std::string& external_id, const std::vector<std::string>& member_user_scim_ids) {
    if (!open_ || scim_id.empty() || display_name.empty())
        return std::nullopt;

    bool matched = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        std::vector<std::optional<std::string>> params{display_name, opt_ext(external_id), scim_id};
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE scim_store.scim_groups SET display_name = $1, external_id = $2, "
            "etag_version = etag_version + 1, updated_at = now() WHERE scim_id = $3 "
            "RETURNING scim_id",
            params);
        if (upd.status() != PGRES_TUPLES_OK)
            return false;

        // No row matched -> group doesn't exist. Not an error: commit the
        // (no-op) transaction and report "not found" via `matched=false`,
        // mirroring the SQLite-era guard's "the guard rolls back (nothing
        // was written anyway)" — nothing here writes either.
        if (PQntuples(upd.get()) == 0) {
            matched = false;
            return true;
        }
        matched = true;

        pg::PgResult del = pg::exec_params(
            conn, "DELETE FROM scim_store.scim_group_members WHERE group_scim_id = $1",
            std::vector<std::string>{scim_id});
        if (del.status() != PGRES_COMMAND_OK)
            return false;

        for (const auto& user_scim_id : member_user_scim_ids) {
            pg::PgResult ins = pg::exec_params(
                conn,
                "INSERT INTO scim_store.scim_group_members (group_scim_id, user_scim_id) "
                "VALUES ($1, $2) ON CONFLICT (group_scim_id, user_scim_id) DO NOTHING",
                std::vector<std::string>{scim_id, user_scim_id});
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        return true;
    });

    if (!ok)
        return std::nullopt;
    return matched;
}

bool ScimStore::add_group_member(const std::string& group_scim_id,
                                 const std::string& user_scim_id) {
    if (!open_ || group_scim_id.empty() || user_scim_id.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    // ON CONFLICT DO NOTHING reports PGRES_COMMAND_OK whether it inserted a
    // fresh row or silently ignored an existing one (idempotent add) — both
    // are success from the caller's point of view.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO scim_store.scim_group_members (group_scim_id, user_scim_id) VALUES ($1, $2) "
        "ON CONFLICT (group_scim_id, user_scim_id) DO NOTHING",
        std::vector<std::string>{group_scim_id, user_scim_id});
    return res.status() == PGRES_COMMAND_OK;
}

bool ScimStore::remove_group_member(const std::string& group_scim_id,
                                    const std::string& user_scim_id) {
    if (!open_ || group_scim_id.empty() || user_scim_id.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    // DELETE reports PGRES_COMMAND_OK whether or not a row matched
    // (idempotent remove) — both are success from the caller's point of
    // view.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM scim_store.scim_group_members WHERE group_scim_id = $1 AND user_scim_id = $2",
        std::vector<std::string>{group_scim_id, user_scim_id});
    return res.status() == PGRES_COMMAND_OK;
}

std::optional<std::vector<std::string>>
ScimStore::list_group_member_user_scim_ids(const std::string& group_scim_id) const {
    if (!open_)
        return std::nullopt; // store unusable — never "no members"
    if (group_scim_id.empty())
        return std::vector<std::string>{}; // no group asked for → genuinely nothing

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT user_scim_id FROM scim_store.scim_group_members WHERE group_scim_id = $1 "
        "ORDER BY user_scim_id ASC",
        std::vector<std::string>{group_scim_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;

    const int rows = PQntuples(res.get());
    std::vector<std::string> results;
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(col(res.get(), i, 0));
    return results;
}

std::optional<std::vector<std::string>>
ScimStore::list_group_display_names_for_user(const std::string& user_scim_id) const {
    if (!open_)
        return std::nullopt; // store unusable — never "member of no groups"
    if (user_scim_id.empty())
        return std::vector<std::string>{};

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    // Read the role-application task consumes; a display_name containing an
    // embedded NUL cannot be stored by Postgres text columns at all (the
    // write fails closed rather than silently truncating — UP-3 does not
    // apply the same way it did to SQLite).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT g.display_name FROM scim_store.scim_group_members m "
        "JOIN scim_store.scim_groups g ON g.scim_id = m.group_scim_id "
        "WHERE m.user_scim_id = $1 ORDER BY g.display_name ASC",
        std::vector<std::string>{user_scim_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;

    const int rows = PQntuples(res.get());
    std::vector<std::string> results;
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(col(res.get(), i, 0));
    return results;
}

// ── Identity linkage (ADR-2001) ─────────────────────────────────────────

bool ScimStore::upsert_link(const std::string& iss, const std::string& sub,
                            const std::string& scim_id) {
    if (!open_ || iss.empty() || sub.empty() || scim_id.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO scim_store.identity_links (iss, sub, scim_id, linked_at) "
        "VALUES ($1, $2, $3, extract(epoch FROM now())::bigint) "
        "ON CONFLICT (iss, sub) DO UPDATE "
        "SET scim_id = EXCLUDED.scim_id, linked_at = EXCLUDED.linked_at",
        std::vector<std::string>{iss, sub, scim_id});
    return res.status() == PGRES_COMMAND_OK;
}

std::optional<std::vector<LinkedIdentity>>
ScimStore::links_for_scim_id(const std::string& scim_id) const {
    if (!open_)
        return std::nullopt; // store unusable — never "no linked identities"
    if (scim_id.empty())
        return std::vector<LinkedIdentity>{}; // no scim_id asked for → genuinely nothing

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT iss, sub FROM scim_store.identity_links WHERE scim_id = $1 "
        "ORDER BY iss ASC, sub ASC",
        std::vector<std::string>{scim_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;

    const int rows = PQntuples(res.get());
    std::vector<LinkedIdentity> results;
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(LinkedIdentity{.iss = col(res.get(), i, 0), .sub = col(res.get(), i, 1)});
    return results;
}

// ── SAML identity linkage (ADR-2001 PR4a) ───────────────────────────────

bool ScimStore::upsert_saml_link(const std::string& entity_id, const std::string& name_id,
                                 const std::string& scim_id) {
    if (!open_ || entity_id.empty() || name_id.empty() || scim_id.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO scim_store.saml_identity_links (entity_id, name_id, scim_id, linked_at) "
        "VALUES ($1, $2, $3, extract(epoch FROM now())::bigint) "
        "ON CONFLICT (entity_id, name_id) DO UPDATE "
        "SET scim_id = EXCLUDED.scim_id, linked_at = EXCLUDED.linked_at",
        std::vector<std::string>{entity_id, name_id, scim_id});
    return res.status() == PGRES_COMMAND_OK;
}

std::optional<std::vector<SamlLinkedIdentity>>
ScimStore::saml_links_for_scim_id(const std::string& scim_id) const {
    if (!open_)
        return std::nullopt; // store unusable — never "no linked identities"
    if (scim_id.empty())
        return std::vector<SamlLinkedIdentity>{}; // no scim_id asked for → genuinely nothing

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT entity_id, name_id FROM scim_store.saml_identity_links WHERE scim_id = $1 "
        "ORDER BY entity_id ASC, name_id ASC",
        std::vector<std::string>{scim_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;

    const int rows = PQntuples(res.get());
    std::vector<SamlLinkedIdentity> results;
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        results.push_back(
            SamlLinkedIdentity{.entity_id = col(res.get(), i, 0), .name_id = col(res.get(), i, 1)});
    }
    return results;
}

std::optional<LinkedResourceState>
ScimStore::linked_resource_active(const std::string& iss, const std::string& sub) const {
    if (!open_)
        return std::nullopt; // store unusable — caller MUST fail closed
    if (iss.empty() || sub.empty())
        return LinkedResourceState{}; // nothing to look up — a definitive non-match, not a store error

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt; // lease timeout — store error, not "no link"

    // LEFT JOIN is load-bearing (see the .hpp doc comment): an INNER join
    // would collapse an orphaned link (scim_resources row hard-DELETEd,
    // identity_links not FK-cascaded) into "no rows", which reads as "no
    // link" and lets a fully-deprovisioned identity re-authenticate.
    // il.scim_id is carried alongside sr.active so a DENY can name which
    // resource drove it — a self-contained CC6.8 audit row, not just "denied".
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT il.scim_id, sr.active FROM scim_store.identity_links il "
        "LEFT JOIN scim_store.scim_resources sr ON sr.scim_id = il.scim_id "
        "WHERE il.iss = $1 AND il.sub = $2 LIMIT 1",
        std::vector<std::string>{iss, sub});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt; // query failed — store error, not "no link"

    if (PQntuples(res.get()) == 0)
        return LinkedResourceState{}; // no identity_links row — genuinely no link

    // Exactly one linked row. il.scim_id is NOT NULL (identity_links schema),
    // so this is always populated once a row matched. NULL sr.active means
    // the join found no matching scim_resources row (orphaned link) —
    // reported as an engaged scim_id with active left nullopt; the caller
    // treats that identically to an explicit active=false: deny.
    LinkedResourceState state;
    state.scim_id = col(res.get(), 0, 0);
    if (!PQgetisnull(res.get(), 0, 1))
        state.active = to_bool(PQgetvalue(res.get(), 0, 1));
    return state;
}

std::optional<LinkedResourceState>
ScimStore::saml_linked_resource_active(const std::string& entity_id,
                                       const std::string& name_id) const {
    if (!open_)
        return std::nullopt; // store unusable — caller MUST fail closed
    if (entity_id.empty() || name_id.empty())
        return LinkedResourceState{}; // nothing to look up — a definitive non-match, not a store error

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt; // lease timeout — store error, not "no link"

    // LEFT JOIN is load-bearing (see the .hpp doc comment): an INNER join
    // would collapse an orphaned link (scim_resources row hard-DELETEd,
    // saml_identity_links not FK-cascaded) into "no rows", which reads as
    // "no link" and lets a fully-deprovisioned identity re-authenticate.
    // sl.scim_id is carried alongside sr.active so a DENY can name which
    // resource drove it — a self-contained CC6.8 audit row, not just "denied".
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT sl.scim_id, sr.active FROM scim_store.saml_identity_links sl "
        "LEFT JOIN scim_store.scim_resources sr ON sr.scim_id = sl.scim_id "
        "WHERE sl.entity_id = $1 AND sl.name_id = $2 LIMIT 1",
        std::vector<std::string>{entity_id, name_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt; // query failed — store error, not "no link"

    if (PQntuples(res.get()) == 0)
        return LinkedResourceState{}; // no saml_identity_links row — genuinely no link

    // Exactly one linked row. sl.scim_id is NOT NULL (saml_identity_links
    // schema), so this is always populated once a row matched. NULL
    // sr.active means the join found no matching scim_resources row
    // (orphaned link) — reported as an engaged scim_id with active left
    // nullopt; the caller treats that identically to an explicit
    // active=false: deny.
    LinkedResourceState state;
    state.scim_id = col(res.get(), 0, 0);
    if (!PQgetisnull(res.get(), 0, 1))
        state.active = to_bool(PQgetvalue(res.get(), 0, 1));
    return state;
}

// ── OIDC login observations (ADR-2001 D2 detector) ──────────────────────

bool ScimStore::record_login_observation(const std::string& iss, const std::string& sub,
                                         const std::string& claim_name,
                                         const std::string& claim_value) {
    if (!open_ || iss.empty() || sub.empty() || claim_name.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO scim_store.oidc_login_observations "
        "(iss, sub, claim_name, claim_value, seen_at) "
        "VALUES ($1, $2, $3, $4, extract(epoch FROM now())::bigint) "
        "ON CONFLICT (iss, sub, claim_name) DO UPDATE "
        "SET claim_value = EXCLUDED.claim_value, "
        "    seen_at = EXCLUDED.seen_at",
        std::vector<std::string>{iss, sub, claim_name, claim_value});
    return res.status() == PGRES_COMMAND_OK;
}

bool ScimStore::observation_matches(const std::string& claim_value) const {
    if (!open_ || claim_value.empty())
        return false;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return false; // cannot tell — safe direction for a signal-only read

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT 1 FROM scim_store.oidc_login_observations WHERE claim_value = $1 LIMIT 1",
        std::vector<std::string>{claim_value});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

// ── SAML login observations (ADR-2001 #3072) ────────────────────────────

bool ScimStore::record_saml_login_observation(const std::string& entity_id,
                                              const std::string& name_id,
                                              const std::string& name_id_format) {
    if (!open_ || entity_id.empty() || name_id.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO scim_store.saml_login_observations "
        "(entity_id, name_id, name_id_format, seen_at) "
        "VALUES ($1, $2, $3, extract(epoch FROM now())::bigint) "
        "ON CONFLICT (entity_id, name_id, name_id_format) DO UPDATE "
        "SET seen_at = EXCLUDED.seen_at",
        std::vector<std::string>{entity_id, name_id, name_id_format});
    return res.status() == PGRES_COMMAND_OK;
}

std::optional<bool> ScimStore::saml_observation_matches(const std::string& name_id) const {
    if (!open_)
        return std::nullopt; // store unusable — caller MUST skip, not false-positive
    if (name_id.empty())
        return false; // nothing to look up — a definitive non-match, not a store error

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt; // lease timeout — store error, caller MUST skip

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT 1 FROM scim_store.saml_login_observations WHERE name_id = $1 LIMIT 1",
        std::vector<std::string>{name_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt; // query failed — store error, caller MUST skip
    return PQntuples(res.get()) > 0;
}

} // namespace yuzu::server
