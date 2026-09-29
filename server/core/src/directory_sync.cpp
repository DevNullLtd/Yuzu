#include "directory_sync.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <string_view>
#include <unordered_set>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
// clang-format on
#endif

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

constexpr const char* kStoreName = "directory_sync";

// Bounded acquires (ADR-0012 §2). Construction is the only unbounded one.
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

// Defends fetch_paginated against a runaway or malicious @odata.nextLink
// chain. 500 pages * $top=999 is ~500K objects per collection — far beyond
// any realistic tenant, so hitting this is itself evidence of a problem.
constexpr int kMaxGraphPages = 500;

// Defends sync_entra's whole-tenant EntraSyncData against unbounded memory
// growth (chaos-injector review, 2026-08-30): kMaxGraphPages bounds each
// individual fetch_paginated call, but the per-group membership loop makes
// ONE such call per group, and every group's members accumulate in the same
// in-memory snapshot before a single row is written (required by ADR-0012
// §2 — no lease held across the external Graph calls). A legitimately large
// tenant's group x membership graph is unbounded by kMaxGraphPages alone and
// could exhaust the whole server process's memory, not just this store's.
// 5M membership pairs is generous for any real enterprise tenant (a
// 500K-user tenant averaging 10 group memberships each is 5M) while still
// bounding peak memory to a recoverable, logged failure rather than an OS
// OOM-kill of the shared control-plane process.
constexpr size_t kMaxTotalMemberships = 5'000'000;

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Extracts "scheme://host" from an absolute URL, or nullopt if `url` has no
// "://" at all (not a well-formed absolute URL). Used to pin a
// response-supplied @odata.nextLink to the same host the request was made
// to -- explicit rejection on a malformed shape, never an unsigned-overflow
// fallthrough that would risk comparing the wrong substrings.
std::optional<std::string> scheme_host(const std::string& url) {
    auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos)
        return std::nullopt;
    auto host_end = url.find('/', scheme_end + 3);
    return url.substr(0, host_end); // host_end == npos -> substr runs to end
}

std::string url_encode(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() * 2);
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            escaped += c;
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned char>(c));
            escaped += buf;
        }
    }
    return escaped;
}

std::string base64_encode(const std::string& input) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    for (std::size_t i = 0; i < input.size(); i += 3) {
        uint32_t n = static_cast<uint8_t>(input[i]) << 16;
        if (i + 1 < input.size())
            n |= static_cast<uint8_t>(input[i + 1]) << 8;
        if (i + 2 < input.size())
            n |= static_cast<uint8_t>(input[i + 2]);
        out += kAlphabet[(n >> 18) & 0x3F];
        out += kAlphabet[(n >> 12) & 0x3F];
        out += (i + 1 < input.size()) ? kAlphabet[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < input.size()) ? kAlphabet[n & 0x3F] : '=';
    }
    return out;
}

// ── PG result helpers (file-local — mirrors offload_target_store.cpp /
//    auth_db.cpp's own file-local copies, no shared header across stores) ───

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1'); }

DirectoryUser row_to_user(PGresult* r, int i) {
    DirectoryUser u;
    u.id = col_str(r, i, 0);
    u.display_name = col_str(r, i, 1);
    u.email = col_str(r, i, 2);
    u.upn = col_str(r, i, 3);
    u.enabled = to_bool(col(r, i, 4));
    u.synced_at = to_i64(col(r, i, 5));
    return u;
}

DirectoryGroup row_to_group(PGresult* r, int i) {
    DirectoryGroup g;
    g.id = col_str(r, i, 0);
    g.display_name = col_str(r, i, 1);
    g.description = col_str(r, i, 2);
    g.mapped_role = col_str(r, i, 3);
    g.synced_at = to_i64(col(r, i, 4));
    return g;
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE directory_users ("
         "  id           TEXT    PRIMARY KEY,"
         "  display_name TEXT    NOT NULL DEFAULT '',"
         "  email        TEXT    NOT NULL DEFAULT '',"
         "  upn          TEXT    NOT NULL DEFAULT '',"
         "  enabled      BOOLEAN NOT NULL DEFAULT TRUE,"
         "  synced_at    BIGINT  NOT NULL DEFAULT 0"
         ");"
         // No mapped_role column here — it lives only in
         // directory_group_role_mappings, resolved via LEFT JOIN at read
         // time (adversarial review, 2026-08-28 — see store_group's comment
         // for why a denormalized copy raced concurrent mapping writes).
         "CREATE TABLE directory_groups ("
         "  id           TEXT    PRIMARY KEY,"
         "  display_name TEXT    NOT NULL DEFAULT '',"
         "  description  TEXT    NOT NULL DEFAULT '',"
         "  synced_at    BIGINT  NOT NULL DEFAULT 0"
         ");"
         // FK + cascade (new — the SQLite era had none): a membership row
         // for a user/group no longer present cannot linger.
         "CREATE TABLE directory_memberships ("
         "  user_id  TEXT NOT NULL REFERENCES directory_users(id) ON DELETE CASCADE,"
         "  group_id TEXT NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,"
         "  PRIMARY KEY (user_id, group_id)"
         ");"
         // role_name stays a soft reference into RbacStore — no cross-schema
         // FK (ADR-0012 §3 forbids cross-store SQL).
         "CREATE TABLE directory_group_role_mappings ("
         "  group_id  TEXT PRIMARY KEY,"
         "  role_name TEXT NOT NULL"
         ");"
         "CREATE TABLE directory_sync_status ("
         "  provider     TEXT    PRIMARY KEY,"
         "  status       TEXT    NOT NULL DEFAULT 'idle',"
         "  last_sync_at BIGINT  NOT NULL DEFAULT 0,"
         "  next_sync_at BIGINT  NOT NULL DEFAULT 0,"
         "  user_count   INTEGER NOT NULL DEFAULT 0,"
         "  group_count  INTEGER NOT NULL DEFAULT 0,"
         "  last_error   TEXT    NOT NULL DEFAULT ''"
         ");"
         "CREATE INDEX idx_dir_users_email ON directory_users(email);"
         "CREATE INDEX idx_dir_users_upn ON directory_users(upn);"
         "CREATE INDEX idx_dir_memberships_group ON directory_memberships(group_id);"},
    };
    return kMigrations;
}

// ── Connection-taking storage helpers ───────────────────────────────────────
// The caller (apply_entra_sync) already holds the transaction's connection;
// these never acquire a lease of their own (ADR-0012 §2 — never nest an
// acquire inside a held transaction).

bool store_user(PGconn* conn, const DirectoryUser& user) {
    pg::PgResult r = pg::exec_params(
        conn,
        "INSERT INTO directory_sync.directory_users "
        "(id, display_name, email, upn, enabled, synced_at) "
        "VALUES ($1, $2, $3, $4, $5, $6) "
        "ON CONFLICT (id) DO UPDATE SET "
        "display_name = EXCLUDED.display_name, email = EXCLUDED.email, "
        "upn = EXCLUDED.upn, enabled = EXCLUDED.enabled, synced_at = EXCLUDED.synced_at",
        std::vector<std::string>{user.id, user.display_name, user.email, user.upn,
                                 user.enabled ? "t" : "f", std::to_string(user.synced_at)});
    if (!r.ok()) {
        spdlog::error("DirectorySync: store_user failed for {}: {}", user.id,
                      PQresultErrorMessage(r.get()));
        return false;
    }
    return true;
}

// mapped_role is NOT a column here — it lives only in
// directory_group_role_mappings and is resolved via LEFT JOIN at read time
// (get_synced_groups). An earlier revision of this port denormalized it onto
// this table via a COALESCE subselect in this very statement's ON CONFLICT
// clause, reasoning that one statement execution has no read-then-write
// window; that reasoning was wrong (adversarial review, 2026-08-28,
// empirically reproduced with a two-connection libpq test): under READ
// COMMITTED, a concurrent configure_group_role_mapping that commits after
// this statement's snapshot but before it acquires the directory_groups row
// lock is invisible to the subselect even after Postgres's EvalPlanQual
// retry (EvalPlanQual re-checks the conflicting row, it does not re-snapshot
// unrelated tables the SET clause reads) — silently clobbering the
// concurrent write with a stale ''. Removing the column removes the race
// structurally rather than adding a lock to paper over it.
bool store_group(PGconn* conn, const DirectoryGroup& group) {
    pg::PgResult r = pg::exec_params(
        conn,
        "INSERT INTO directory_sync.directory_groups "
        "(id, display_name, description, synced_at) "
        "VALUES ($1, $2, $3, $4) "
        "ON CONFLICT (id) DO UPDATE SET "
        "display_name = EXCLUDED.display_name, description = EXCLUDED.description, "
        "synced_at = EXCLUDED.synced_at",
        std::vector<std::string>{group.id, group.display_name, group.description,
                                 std::to_string(group.synced_at)});
    if (!r.ok()) {
        spdlog::error("DirectorySync: store_group failed for {}: {}", group.id,
                      PQresultErrorMessage(r.get()));
        return false;
    }
    return true;
}

bool clear_memberships(PGconn* conn) {
    pg::PgResult r =
        pg::exec_params(conn, "DELETE FROM directory_sync.directory_memberships",
                        std::vector<std::string>{});
    if (!r.ok()) {
        spdlog::error("DirectorySync: clear_memberships failed: {}",
                      PQresultErrorMessage(r.get()));
        return false;
    }
    return true;
}

// Deletes every row in `table` (directory_users or directory_groups) whose
// `id` is NOT in `current_ids` — the SQLite era never did this (upsert-only,
// verified against the base commit), so a user/group Entra has since deleted
// stayed queryable forever (adversarial review, 2026-08-28). `current_ids`
// must be the COMPLETE current snapshot: an empty vector deletes every row
// in the table, which is correct ONLY when the caller has already confirmed
// the fetch was well-formed (see sync_entra's hard-error-on-malformed-
// response handling for both users and groups) — never call this with an
// empty vector that might mean "fetch failed", only "tenant genuinely has
// zero of this kind". ON DELETE CASCADE on directory_memberships handles
// the deleted rows' memberships.
bool delete_stale_rows(PGconn* conn, const char* table,
                       const std::vector<std::string>& current_ids) {
    std::vector<std::string_view> idv(current_ids.begin(), current_ids.end());
    const std::string id_arr = pg::to_text_array(idv);
    const std::string sql = std::string("DELETE FROM directory_sync.") + table +
                            " WHERE NOT (id = ANY($1::text[]))";
    pg::PgResult r = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{id_arr});
    if (!r.ok()) {
        spdlog::error("DirectorySync: delete_stale_rows({}) failed: {}", table,
                      PQresultErrorMessage(r.get()));
        return false;
    }
    return true;
}

// Single bulk insert via unnest() (pg_array.hpp's stated purpose,
// SoftwareInventoryStore precedent) — user_ids.size() can run to the
// thousands (users × their groups), and this store sits inside ONE pinned
// transaction (apply_entra_sync), so a per-row round trip here would be the
// N+1 the migration-programme plan calls out, just moved from a read to a
// write. `user_ids`/`group_ids` are parallel arrays (already filtered to
// known users by the caller).
bool store_memberships_bulk(PGconn* conn, const std::vector<std::string>& user_ids,
                            const std::vector<std::string>& group_ids) {
    if (user_ids.empty())
        return true;
    std::vector<std::string_view> uv(user_ids.begin(), user_ids.end());
    std::vector<std::string_view> gv(group_ids.begin(), group_ids.end());
    const std::string user_arr = pg::to_text_array(uv);
    const std::string group_arr = pg::to_text_array(gv);
    pg::PgResult r = pg::exec_params(
        conn,
        "INSERT INTO directory_sync.directory_memberships (user_id, group_id) "
        "SELECT * FROM unnest($1::text[], $2::text[]) ON CONFLICT DO NOTHING",
        std::vector<std::string>{user_arr, group_arr});
    if (!r.ok()) {
        spdlog::error("DirectorySync: store_memberships_bulk failed: {}",
                      PQresultErrorMessage(r.get()));
        return false;
    }
    return true;
}

} // namespace

// ── Construction / teardown ──────────────────────────────────────────────────

DirectorySync::DirectorySync(pg::PgPool& pool) : pool_(pool) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DirectorySync: no database connection at construction ({}) — "
                      "directory sync disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DirectorySync: schema migration failed — directory sync disabled");
        return;
    }
    lease.reset();

    open_ = true;
    // ADR-0009's 2026-08-25 fresh-start-by-default amendment: no
    // migrate_from_sqlite here, unconditionally, no flag — same posture as
    // ResponseStore/OffloadTargetStore. No production fleet has ever run a
    // pre-Postgres build of this store. `server.cpp` runs
    // legacy_sqlite_probe::warn_if_legacy_rows() once at boot to warn (never
    // fail) if the legacy directory-sync.db still holds rows.
    spdlog::info("DirectorySync initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

DirectorySync::~DirectorySync() = default;

bool DirectorySync::is_open() const {
    return open_;
}

// ── HTTP helpers (untouched — Microsoft Graph/WinHTTP client, not part of
//    this migration) ──────────────────────────────────────────────────────

#ifdef _WIN32

// WinHTTP GET with Bearer token — used on Windows where httplib's OpenSSL
// client may fail from handler threads.
std::expected<std::string, std::string>
DirectorySync::http_get(const std::string& url, const std::string& bearer_token) {
    std::wstring wurl(url.begin(), url.end());

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[4096] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 4096;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        return std::unexpected("WinHTTP: failed to parse URL: " + url);
    }

    HINTERNET session = WinHttpOpen(L"Yuzu-DirectorySync/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return std::unexpected("WinHTTP: WinHttpOpen failed");

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpConnect failed");
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"GET", path, nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpOpenRequest failed");
    }

    // Add Authorization header
    std::wstring auth_header = L"Authorization: Bearer ";
    auth_header.append(bearer_token.begin(), bearer_token.end());
    WinHttpAddRequestHeaders(request, auth_header.c_str(),
                             static_cast<DWORD>(auth_header.size()),
                             WINHTTP_ADDREQ_FLAG_ADD);

    BOOL ok = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpSendRequest failed");
    }

    ok = WinHttpReceiveResponse(request, nullptr);
    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpReceiveResponse failed");
    }

    // Check HTTP status
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size,
                        WINHTTP_NO_HEADER_INDEX);
    if (status_code != 200) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("Graph API returned HTTP " + std::to_string(status_code));
    }

    std::string response;
    DWORD bytes_available = 0;
    do {
        WinHttpQueryDataAvailable(request, &bytes_available);
        if (bytes_available > 0) {
            std::vector<char> buf(bytes_available);
            DWORD bytes_read = 0;
            WinHttpReadData(request, buf.data(), bytes_available, &bytes_read);
            response.append(buf.data(), bytes_read);
        }
    } while (bytes_available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return response;
}

#else

// httplib GET with Bearer token — used on Linux/macOS.
std::expected<std::string, std::string>
DirectorySync::http_get(const std::string& url, const std::string& bearer_token) {
    // Parse scheme://host/path
    std::string u = url;
    std::string scheme;
    if (u.starts_with("https://")) {
        scheme = "https://";
        u = u.substr(8);
    } else if (u.starts_with("http://")) {
        scheme = "http://";
        u = u.substr(7);
    } else {
        return std::unexpected("invalid URL scheme: " + url);
    }

    auto slash = u.find('/');
    auto host = (slash != std::string::npos) ? u.substr(0, slash) : u;
    auto path = (slash != std::string::npos) ? u.substr(slash) : "/";

    httplib::Client client(scheme + host);
    client.set_connection_timeout(15);
    client.set_read_timeout(30);
    client.set_write_timeout(30);

    httplib::Headers headers = {
        {"Authorization", "Bearer " + bearer_token},
        {"Accept", "application/json"}};

    auto result = client.Get(path, headers);
    if (!result) {
        return std::unexpected("HTTP GET failed: " + httplib::to_string(result.error()));
    }
    if (result->status != 200) {
        return std::unexpected("Graph API returned HTTP " +
                               std::to_string(result->status) + ": " +
                               result->body.substr(0, 500));
    }
    return result->body;
}

#endif

// ── OAuth2 client credentials flow ──────────────────────────────────────────
//
// Per RFC 6749 Section 2.3.1, confidential clients SHOULD authenticate via
// HTTP Basic (Authorization header) rather than sending client_secret in the
// POST body.  SECURITY: The token endpoint MUST be accessed over HTTPS.

std::expected<std::string, std::string>
DirectorySync::acquire_token(const EntraConfig& config) {
    auto token_url = "https://login.microsoftonline.com/" + config.tenant_id +
                     "/oauth2/v2.0/token";

    std::string form_body =
        "grant_type=client_credentials"
        "&scope=" + url_encode("https://graph.microsoft.com/.default");

    // RFC 6749 §2.3.1: use HTTP Basic auth for client credentials
    auto credentials = base64_encode(config.client_id + ":" + config.client_secret);
    std::string auth_value = "Basic " + credentials;

    spdlog::info("DirectorySync: acquiring token from {}", token_url);

#ifdef _WIN32
    // Reuse WinHTTP POST (same pattern as OIDC provider)
    std::wstring wurl(token_url.begin(), token_url.end());

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[2048] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        return std::unexpected("WinHTTP: failed to parse token URL");
    }

    HINTERNET session = WinHttpOpen(L"Yuzu-DirectorySync/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return std::unexpected("WinHTTP: WinHttpOpen failed");

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpConnect failed");
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpOpenRequest failed");
    }

    // Add HTTP Basic auth header
    std::string auth_hdr = "Authorization: " + auth_value;
    std::wstring wauth(auth_hdr.begin(), auth_hdr.end());
    WinHttpAddRequestHeaders(request, wauth.c_str(), static_cast<DWORD>(wauth.size()),
                             WINHTTP_ADDREQ_FLAG_ADD);

    const wchar_t* content_type = L"Content-Type: application/x-www-form-urlencoded";
    BOOL ok = WinHttpSendRequest(request, content_type, -1L,
                                 const_cast<char*>(form_body.data()),
                                 static_cast<DWORD>(form_body.size()),
                                 static_cast<DWORD>(form_body.size()), 0);
    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpSendRequest failed");
    }

    ok = WinHttpReceiveResponse(request, nullptr);
    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpReceiveResponse failed");
    }

    std::string response_body;
    DWORD bytes_available = 0;
    do {
        WinHttpQueryDataAvailable(request, &bytes_available);
        if (bytes_available > 0) {
            std::vector<char> buf(bytes_available);
            DWORD bytes_read = 0;
            WinHttpReadData(request, buf.data(), bytes_available, &bytes_read);
            response_body.append(buf.data(), bytes_read);
        }
    } while (bytes_available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

#else
    // httplib POST for Linux/macOS
    // SECURITY: Reject non-HTTPS URLs — client secret MUST NOT be sent over plaintext
    std::string u = token_url;
    if (!u.starts_with("https://")) {
        std::fill(form_body.begin(), form_body.end(), '\0');
        return std::unexpected("token endpoint must use HTTPS (client secret protection)");
    }
    u = u.substr(8); // strip "https://"

    auto slash = u.find('/');
    auto h = (slash != std::string::npos) ? u.substr(0, slash) : u;
    auto p = (slash != std::string::npos) ? u.substr(slash) : "/";

    httplib::Client client("https://" + h);
    client.set_connection_timeout(10);
    client.set_read_timeout(15);
    client.set_write_timeout(15);
    // Enable TLS peer verification (httplib verifies by default with OpenSSL,
    // but set explicitly for clarity)
    client.enable_server_certificate_verification(true);

    httplib::Headers headers{{"Authorization", auth_value}};
    auto result = client.Post(p, headers, form_body, "application/x-www-form-urlencoded");
    if (!result) {
        return std::unexpected("token request failed: " +
                               httplib::to_string(result.error()));
    }
    if (result->status != 200) {
        return std::unexpected("token endpoint returned " +
                               std::to_string(result->status) + ": " +
                               result->body.substr(0, 500));
    }
    std::string response_body = result->body;
#endif

    // Zero credentials (secret was in the auth header, not the body, but wipe defensively)
    std::fill(credentials.begin(), credentials.end(), '\0');

    // Parse token response
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(response_body);
    } catch (const nlohmann::json::parse_error& e) {
        return std::unexpected(std::string("token response parse error: ") + e.what());
    }

    if (j.contains("error")) {
        auto err = j["error"].get<std::string>();
        auto desc = j.value("error_description", "");
        return std::unexpected("token error: " + err + " - " + desc);
    }

    if (!j.contains("access_token") || !j["access_token"].is_string()) {
        return std::unexpected("no access_token in token response");
    }

    spdlog::info("DirectorySync: acquired access token (expires_in={})",
                 j.value("expires_in", 0));
    return j["access_token"].get<std::string>();
}

std::expected<void, std::string> DirectorySync::fetch_paginated(
    const std::string& initial_url, const std::string& bearer_token,
    const std::function<void(const nlohmann::json&)>& on_item) {
    std::string url = initial_url;
    for (int page = 0; page < kMaxGraphPages; ++page) {
        auto result = http_get(url, bearer_token);
        if (!result)
            return std::unexpected(result.error());

        nlohmann::json j;
        try {
            j = nlohmann::json::parse(*result);
        } catch (const nlohmann::json::parse_error& e) {
            return std::unexpected(std::string("response parse error: ") + e.what());
        }

        if (!j.contains("value") || !j["value"].is_array())
            return std::unexpected("unexpected Graph API response: no 'value' array");

        // on_item's field accessors (.value<T>(key, default)) throw
        // nlohmann::json::type_error on a PRESENT-but-null/wrong-typed field
        // (e.g. a guest/unlicensed Entra user's "mail": null) -- .value()
        // only substitutes the default when the key is ABSENT, not when it's
        // present-and-null. Left uncaught (unhappy-path review, 2026-08-30),
        // this escaped through sync_entra to the route handler, which caught
        // it as a bare HTTP 500 and skipped every update_status(..., "failed",
        // ...) call site -- leaving directory_sync_status permanently stuck
        // at "running" with no error ever recorded, identically on every
        // retry against the same tenant.
        for (const auto& item : j["value"]) {
            try {
                on_item(item);
            } catch (const nlohmann::json::exception& e) {
                return std::unexpected(std::string("malformed item in Graph response: ") +
                                       e.what());
            }
        }

        auto next = j.find("@odata.nextLink");
        if (next == j.end())
            return {}; // no more pages -- legitimate end of pagination
        if (!next->is_string())
            return std::unexpected("unexpected Graph API response: @odata.nextLink present but not a string");
        url = next->get<std::string>();

        // Pin nextLink to the initial request's own scheme+host (unhappy-path
        // review, 2026-08-30, MEDIUM defense-in-depth) -- Graph is TLS-verified
        // and the token transits on every request regardless, so a forged
        // nextLink needs the same channel control an attacker would already
        // need to forge the rest of the response; this is belt-and-braces
        // against that response-supplied URL ever leaving the expected host.
        auto initial_host = scheme_host(initial_url);
        auto next_host = scheme_host(url);
        if (!initial_host || !next_host || *initial_host != *next_host) {
            return std::unexpected("@odata.nextLink points off the expected host, refusing to follow");
        }
    }
    return std::unexpected("Graph API pagination exceeded " +
                           std::to_string(kMaxGraphPages) + " pages");
}

// ── Entra ID sync ────────────────────────────────────────────────────────────
//
// Fetches the complete remote snapshot first (no lease held across any of
// these external Graph calls), then applies it in one short transaction —
// see the file header's transaction-shape note (ADR-0012 §2: never hold a
// lease across external work).

std::expected<void, std::string> DirectorySync::sync_entra(const EntraConfig& config) {
    if (config.tenant_id.empty() || config.client_id.empty() || config.client_secret.empty()) {
        return std::unexpected("Entra config incomplete: tenant_id, client_id, and client_secret required");
    }

    // ADR-1007: re-entrancy guard, whole-operation scope. A concurrent
    // caller loses the CAS and is refused immediately — no queueing, no
    // blocking (see the header doc comment for the 409 mapping). RAII reset
    // covers every one of this function's several early-return exit paths.
    bool expected_free = false;
    if (!entra_sync_in_progress_.compare_exchange_strong(expected_free, true)) {
        return std::unexpected(std::string(kEntraSyncAlreadyInProgress));
    }
    // Reference, not pointer — matches nvd_sync.cpp's ActiveGuard, this
    // codebase's existing precedent for the identical reentrancy-guard
    // idiom (Gate 3 cpp-expert).
    struct Release {
        std::atomic<bool>& flag;
        ~Release() { flag.store(false); }
    } release_guard{entra_sync_in_progress_};
    if (test_hook_after_entra_guard_acquired_)
        test_hook_after_entra_guard_acquired_();

    update_status("entra", "running");
    spdlog::info("DirectorySync: starting Entra ID sync for tenant {}", config.tenant_id);

    // 1. Acquire access token via client credentials flow
    auto token_result = acquire_token(config);
    if (!token_result) {
        auto err = "token acquisition failed: " + token_result.error();
        update_status("entra", "failed", 0, 0, err);
        spdlog::error("DirectorySync: {}", err);
        return std::unexpected(err);
    }
    auto& access_token = *token_result;

    EntraSyncData data;

    // 2. Fetch users from Microsoft Graph. fetch_paginated follows
    // @odata.nextLink to exhaustion and hard-errors on any malformed page
    // (see its own doc comment) — a tenant with more than one page of users
    // must never be silently treated as "that's everyone".
    {
        std::string users_url = "https://graph.microsoft.com/v1.0/users"
                                "?$select=id,displayName,mail,userPrincipalName,accountEnabled"
                                "&$top=999";

        auto result = fetch_paginated(users_url, access_token, [&data](const nlohmann::json& u) {
            DirectoryUser du;
            du.id = u.value("id", "");
            du.display_name = u.value("displayName", "");
            du.email = u.value("mail", "");
            du.upn = u.value("userPrincipalName", "");
            du.enabled = u.value("accountEnabled", true);
            du.synced_at = now_epoch();

            if (!du.id.empty())
                data.users.push_back(std::move(du));
        });
        if (!result) {
            auto err = "fetching users failed: " + result.error();
            update_status("entra", "failed", 0, 0, err);
            spdlog::error("DirectorySync: {}", err);
            return std::unexpected(err);
        }
    }

    // 3. Fetch groups. fetch_paginated hard-errors on any malformed page
    // (adversarial review, 2026-08-28): the SQLite era silently treated a
    // malformed response as "zero groups" and simply upserted nothing,
    // harmless there since stale groups were never deleted anyway. Now that
    // apply_entra_sync deletes any group NOT in data.groups (see its own
    // comment), an empty data.groups from a transient/malformed/truncated
    // fetch would wipe every previously-synced group — so a genuinely empty
    // "value": [] array (the tenant really has zero groups) must stay
    // distinguishable from a malformed/missing "value" or an unfollowed
    // nextLink (a fetch problem this sync should abort on, leaving the store
    // untouched).
    {
        std::string groups_url = "https://graph.microsoft.com/v1.0/groups"
                                 "?$select=id,displayName,description"
                                 "&$top=999";

        auto result = fetch_paginated(groups_url, access_token, [&data](const nlohmann::json& g) {
            DirectoryGroup dg;
            dg.id = g.value("id", "");
            dg.display_name = g.value("displayName", "");
            dg.description = g.value("description", "");
            dg.synced_at = now_epoch();
            // mapped_role is never set here — it has no column on
            // directory_groups; see store_group's comment.

            if (!dg.id.empty())
                data.groups.push_back(std::move(dg));
        });
        if (!result) {
            auto err = "fetching groups failed: " + result.error();
            update_status("entra", "failed", static_cast<int>(data.users.size()), 0, err);
            spdlog::error("DirectorySync: {}", err);
            return std::unexpected(err);
        }
    }

    // 4. Fetch group memberships. One Graph call per group is an external
    // API shape (members are not addressable in bulk across groups), not a
    // store-side N+1 — the store-side N+1 this port fixes is in
    // get_synced_users's read path, below. A failed/malformed/truncated
    // fetch for ANY group hard-errors the whole sync (security review,
    // 2026-08-29) rather than silently leaving that group's membership
    // bucket empty — apply_entra_sync's clear-then-repopulate would
    // otherwise read an incomplete snapshot as "this group now has zero
    // members" and wipe its real memberships.
    size_t total_memberships = 0;
    for (const auto& g : data.groups) {
        std::string members_url = "https://graph.microsoft.com/v1.0/groups/" +
                                  g.id + "/members?$select=id&$top=999";

        auto& bucket = data.memberships[g.id];
        auto result = fetch_paginated(members_url, access_token,
                                      [&bucket](const nlohmann::json& m) {
            auto member_id = m.value("id", "");
            if (!member_id.empty())
                bucket.push_back(member_id);
        });
        if (!result) {
            auto err = "fetching members for group " + g.display_name +
                      " failed: " + result.error();
            update_status("entra", "failed", static_cast<int>(data.users.size()),
                          static_cast<int>(data.groups.size()), err);
            spdlog::error("DirectorySync: {}", err);
            return std::unexpected(err);
        }

        total_memberships += bucket.size();
        if (total_memberships > kMaxTotalMemberships) {
            auto err = "Entra tenant's total group memberships exceeded " +
                      std::to_string(kMaxTotalMemberships) +
                      " -- aborting to bound memory, store left untouched";
            update_status("entra", "failed", static_cast<int>(data.users.size()),
                          static_cast<int>(data.groups.size()), err);
            spdlog::error("DirectorySync: {}", err);
            return std::unexpected(err);
        }
    }

    // 5. Apply the complete snapshot in one short transaction.
    auto apply_result = apply_entra_sync(data);
    if (!apply_result) {
        auto err = "applying sync result failed: " + apply_result.error();
        update_status("entra", "failed", static_cast<int>(data.users.size()),
                      static_cast<int>(data.groups.size()), err);
        spdlog::error("DirectorySync: {}", err);
        return std::unexpected(err);
    }

    update_status("entra", "completed", static_cast<int>(data.users.size()),
                  static_cast<int>(data.groups.size()));
    spdlog::info("DirectorySync: Entra sync completed — {} users, {} groups",
                 data.users.size(), data.groups.size());
    return {};
}

std::expected<void, std::string> DirectorySync::apply_entra_sync(const EntraSyncData& data) {
    if (!open_)
        return std::unexpected("directory sync store not open");

    // Filter membership pairs to users present in THIS snapshot. Graph's
    // /groups/{id}/members can return non-user directoryObjects (devices,
    // service principals, nested groups); the SQLite era had no FK and
    // simply never surfaced those ids at read time (the JOIN with
    // directory_users filtered them out). The FK added by this port makes
    // that filtering happen HERE, at write time, instead — reproducing the
    // same observable behavior without risking a foreign-key violation
    // aborting the whole sync.
    std::unordered_set<std::string> known_user_ids;
    known_user_ids.reserve(data.users.size());
    std::vector<std::string> current_user_ids;
    current_user_ids.reserve(data.users.size());
    for (const auto& u : data.users) {
        known_user_ids.insert(u.id);
        current_user_ids.push_back(u.id);
    }

    std::vector<std::string> current_group_ids;
    current_group_ids.reserve(data.groups.size());
    for (const auto& g : data.groups)
        current_group_ids.push_back(g.id);

    std::vector<std::string> member_user_ids;
    std::vector<std::string> member_group_ids;
    for (const auto& [group_id, user_ids] : data.memberships) {
        for (const auto& uid : user_ids) {
            if (known_user_ids.contains(uid)) {
                member_user_ids.push_back(uid);
                member_group_ids.push_back(group_id);
            }
        }
    }

    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Remove any user/group no longer present in this snapshot — a
        // directory sync represents the COMPLETE current roster, not an
        // accumulating one (adversarial review, 2026-08-28: the SQLite era
        // never did this either, verified against the base commit, but the
        // gap is worth closing now — DirectorySync feeds the SOC 2
        // access-review email enrichment, where a deleted-from-Entra user
        // silently staying "synced" forever is a real correctness issue).
        // Safe to run unconditionally here because sync_entra hard-errors
        // (never reaches this transaction) on a malformed users OR groups
        // response — an empty current_user_ids/current_group_ids here means
        // the tenant genuinely has zero of that kind, not a fetch failure.
        // ON DELETE CASCADE removes the deleted rows' memberships.
        if (!delete_stale_rows(conn, "directory_users", current_user_ids))
            return false;
        if (!delete_stale_rows(conn, "directory_groups", current_group_ids))
            return false;
        for (const auto& u : data.users) {
            if (!store_user(conn, u))
                return false;
        }
        for (const auto& g : data.groups) {
            if (!store_group(conn, g))
                return false;
        }
        if (!clear_memberships(conn))
            return false;
        if (!store_memberships_bulk(conn, member_user_ids, member_group_ids))
            return false;
        return true;
    });
    if (!ok)
        return std::unexpected("transaction failed applying directory sync result");
    return {};
}

// ── LDAP sync (stub) ─────────────────────────────────────────────────────────

std::expected<void, std::string> DirectorySync::sync_ldap(const LdapConfig& /*config*/) {
    // LDAP support is planned but requires a dedicated LDAP library (e.g. ldap3,
    // OpenLDAP client) which is not currently in our vcpkg manifest. Entra ID
    // sync is available now and covers the majority of enterprise use cases.
    //
    // When LDAP support is added, this method will:
    // 1. Bind to the LDAP server (simple bind or SASL)
    // 2. Search for users under the configured base DN
    //    (objectClass=person, objectClass=user)
    // 3. Search for groups (objectClass=group, objectClass=groupOfNames)
    // 4. Resolve group memberships via member/memberOf attributes
    // 5. Store results in the same directory_sync schema as Entra sync

    spdlog::info("DirectorySync: LDAP sync not yet implemented — use Entra ID");
    return std::unexpected(
        "LDAP sync is planned but not yet implemented. "
        "Entra ID (Azure AD) sync is available now via POST /api/directory/sync "
        "with provider='entra'. To enable LDAP support, add an LDAP client "
        "library to vcpkg.json and implement the bind/search flow.");
}

// ── Query ────────────────────────────────────────────────────────────────────

std::vector<DirectoryUser> DirectorySync::get_synced_users(
    const std::string& group_filter) const {
    if (!open_)
        return {};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return {};
    PGconn* conn = lease.get();

    pg::PgResult res;
    if (group_filter.empty()) {
        res = pg::exec_params(conn,
                              "SELECT id, display_name, email, upn, enabled, synced_at "
                              "FROM directory_sync.directory_users ORDER BY display_name",
                              std::vector<std::string>{});
    } else {
        res = pg::exec_params(conn,
                              "SELECT u.id, u.display_name, u.email, u.upn, u.enabled, u.synced_at "
                              "FROM directory_sync.directory_users u "
                              "JOIN directory_sync.directory_memberships m ON m.user_id = u.id "
                              "WHERE m.group_id = $1 ORDER BY u.display_name",
                              std::vector<std::string>{group_filter});
    }
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("DirectorySync::get_synced_users: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return {};
    }

    const int rows = PQntuples(res.get());
    std::vector<DirectoryUser> result;
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(row_to_user(res.get(), i));
    if (result.empty())
        return result;

    // Bulk group-membership resolution — the SQLite era's per-user N+1
    // query (one JOIN per row here) fixed to one extra round trip regardless
    // of how many users matched (migration-programme plan requirement).
    std::vector<std::string_view> ids;
    ids.reserve(result.size());
    for (const auto& u : result)
        ids.emplace_back(u.id);
    const std::string id_arr = pg::to_text_array(ids);

    pg::PgResult mres = pg::exec_params(
        conn,
        "SELECT m.user_id, g.display_name FROM directory_sync.directory_memberships m "
        "JOIN directory_sync.directory_groups g ON g.id = m.group_id "
        "WHERE m.user_id = ANY($1::text[])",
        std::vector<std::string>{id_arr});
    if (mres.status() != PGRES_TUPLES_OK) {
        spdlog::error("DirectorySync::get_synced_users: membership query failed: {}",
                      PQresultErrorMessage(mres.get()));
        return result; // users still returned — group enrichment is best-effort
    }

    std::unordered_map<std::string, std::vector<std::string>> groups_by_user;
    const int mrows = PQntuples(mres.get());
    for (int i = 0; i < mrows; ++i)
        groups_by_user[col_str(mres.get(), i, 0)].push_back(col_str(mres.get(), i, 1));
    for (auto& u : result) {
        auto it = groups_by_user.find(u.id);
        if (it != groups_by_user.end())
            u.groups = std::move(it->second);
    }
    return result;
}

std::optional<DirectoryUser> DirectorySync::get_user(const std::string& id) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    PGconn* conn = lease.get();

    pg::PgResult res = pg::exec_params(conn,
                                       "SELECT id, display_name, email, upn, enabled, synced_at "
                                       "FROM directory_sync.directory_users WHERE id = $1",
                                       std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("DirectorySync::get_user: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt;

    DirectoryUser u = row_to_user(res.get(), 0);

    pg::PgResult gres = pg::exec_params(
        conn,
        "SELECT g.display_name FROM directory_sync.directory_memberships m "
        "JOIN directory_sync.directory_groups g ON g.id = m.group_id WHERE m.user_id = $1",
        std::vector<std::string>{id});
    if (gres.status() == PGRES_TUPLES_OK) {
        const int rows = PQntuples(gres.get());
        for (int i = 0; i < rows; ++i)
            u.groups.push_back(col_str(gres.get(), i, 0));
    }

    return u;
}

std::vector<DirectoryGroup> DirectorySync::get_synced_groups() const {
    if (!open_)
        return {};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return {};

    // mapped_role is resolved via LEFT JOIN, not a column on directory_groups
    // — see store_group's comment for why a denormalized copy raced
    // concurrent mapping writes (adversarial review, 2026-08-28).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT g.id, g.display_name, g.description, "
        "COALESCE(m.role_name, ''), g.synced_at "
        "FROM directory_sync.directory_groups g "
        "LEFT JOIN directory_sync.directory_group_role_mappings m ON m.group_id = g.id "
        "ORDER BY g.display_name",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("DirectorySync::get_synced_groups: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return {};
    }

    const int rows = PQntuples(res.get());
    std::vector<DirectoryGroup> result;
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(row_to_group(res.get(), i));
    return result;
}

SyncStatus DirectorySync::get_status() const {
    SyncStatus s;
    s.provider = "entra";
    s.status = "idle";
    if (!open_)
        return s;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return s;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT provider, status, last_sync_at, next_sync_at, user_count, group_count, last_error "
        "FROM directory_sync.directory_sync_status WHERE provider = 'entra'",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("DirectorySync::get_status: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return s;
    }
    if (PQntuples(res.get()) > 0) {
        s.provider = col_str(res.get(), 0, 0);
        s.status = col_str(res.get(), 0, 1);
        s.last_sync_at = to_i64(col(res.get(), 0, 2));
        s.next_sync_at = to_i64(col(res.get(), 0, 3));
        s.user_count = static_cast<int>(to_i64(col(res.get(), 0, 4)));
        s.group_count = static_cast<int>(to_i64(col(res.get(), 0, 5)));
        s.last_error = col_str(res.get(), 0, 6);
    }
    return s;
}

// ── Sync status (internal) ──────────────────────────────────────────────────

void DirectorySync::update_status(const std::string& provider, const std::string& status,
                                  int user_count, int group_count,
                                  const std::string& error) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("DirectorySync::update_status: could not acquire a connection");
        return;
    }

    pg::PgResult r = pg::exec_params(
        lease.get(),
        "INSERT INTO directory_sync.directory_sync_status "
        "(provider, status, last_sync_at, user_count, group_count, last_error) "
        "VALUES ($1, $2, $3, $4, $5, $6) "
        "ON CONFLICT (provider) DO UPDATE SET "
        "status = EXCLUDED.status, last_sync_at = EXCLUDED.last_sync_at, "
        "user_count = EXCLUDED.user_count, group_count = EXCLUDED.group_count, "
        "last_error = EXCLUDED.last_error",
        std::vector<std::string>{provider, status, std::to_string(now_epoch()),
                                 std::to_string(user_count), std::to_string(group_count), error});
    if (!r.ok()) {
        spdlog::error("DirectorySync::update_status: query failed: {}",
                      PQresultErrorMessage(r.get()));
    }
}

// ── Group-to-role mapping ────────────────────────────────────────────────────

void DirectorySync::configure_group_role_mapping(const std::string& group_id,
                                                  const std::string& role_name) {
    if (!open_)
        return;

    // Single-statement write — only directory_group_role_mappings, never
    // directory_groups (which has no mapped_role column; see store_group's
    // comment). A genuinely single-statement operation runs on a plain
    // acquire() under autocommit rather than with_txn_for (pg_pool.hpp's own
    // guidance — a transaction wrapper here would just double the round
    // trips for no atomicity benefit).
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("DirectorySync::configure_group_role_mapping: could not acquire a connection");
        return;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "INSERT INTO directory_sync.directory_group_role_mappings (group_id, role_name) "
        "VALUES ($1, $2) ON CONFLICT (group_id) DO UPDATE SET role_name = EXCLUDED.role_name",
        std::vector<std::string>{group_id, role_name});
    if (!r.ok()) {
        spdlog::error("DirectorySync::configure_group_role_mapping: mapping upsert failed: {}",
                      PQresultErrorMessage(r.get()));
        return;
    }
    spdlog::info("DirectorySync: mapped group {} -> role '{}'", group_id, role_name);
}

void DirectorySync::remove_group_role_mapping(const std::string& group_id) {
    if (!open_)
        return;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("DirectorySync::remove_group_role_mapping: could not acquire a connection");
        return;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(), "DELETE FROM directory_sync.directory_group_role_mappings WHERE group_id = $1",
        std::vector<std::string>{group_id});
    if (!r.ok()) {
        spdlog::error("DirectorySync::remove_group_role_mapping: mapping delete failed: {}",
                      PQresultErrorMessage(r.get()));
        return;
    }
    spdlog::info("DirectorySync: removed role mapping for group {}", group_id);
}

std::map<std::string, std::string> DirectorySync::get_group_role_mappings() const {
    if (!open_)
        return {};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return {};

    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT group_id, role_name FROM directory_sync.directory_group_role_mappings",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("DirectorySync::get_group_role_mappings: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return {};
    }

    std::map<std::string, std::string> result;
    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i)
        result[col_str(res.get(), i, 0)] = col_str(res.get(), i, 1);
    return result;
}

} // namespace yuzu::server
