#include "secret_codec.hpp"

#include "../aes_gcm.hpp"
#include "pg_migration_runner.hpp"
#include "pg_raii.hpp"

#include <openssl/rand.h>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <cstdlib>
#include <cstring>
#include <set>

namespace yuzu::server::pg {

namespace {

// Same first advisory-lock key as PgMigrationRunner (cluster-wide "yuzu"
// namespace); constant second key scoped to KEK bootstrap/rotation so two
// server processes first-booting against one database serialize here and the
// loser sees the winner's fingerprint row (the ADR-0010 §2 dual-server rule
// fails loudly instead of minting two independent v1 KEKs).
constexpr const char* kKekLockSql =
    "SELECT pg_advisory_xact_lock(2037545589, hashtext('secrets_kek'::text))";

constexpr std::string_view kKekIdPrefix = "secrets-kek-v";

std::string kek_key_id(std::uint32_t version) {
    return std::string{kKekIdPrefix} + std::to_string(version);
}

/// Strict u32 parse for values read back from the database. atoll would
/// silently return 0 on garbage and truncate >2^32 (cpp-B1).
std::optional<std::uint32_t> parse_u32(const char* text) {
    if (text == nullptr)
        return std::nullopt;
    std::string_view sv{text};
    std::uint32_t v = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), v);
    if (ec != std::errc{} || ptr != sv.data() + sv.size())
        return std::nullopt;
    return v;
}

bool exec_ok(PGconn* conn, const char* sql, std::string_view what) {
    PgResult res{PQexec(conn, sql)};
    if (!res.ok()) {
        spdlog::error("secret_codec: {} failed: {}", what, PQerrorMessage(conn));
        return false;
    }
    return true;
}

// ── #2530 A1: SQLSTATE classification, entirely internal to the codec ──────
// The raw SQLSTATE string never leaves this translation unit — only the
// LifecycleError::Kind discriminant crosses the codec boundary.
SecretCodec::LifecycleError::Kind classify_sqlstate(PGresult* res) {
    if (res == nullptr)
        return SecretCodec::LifecycleError::Kind::database;
    const char* sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);
    if (sqlstate != nullptr && std::strcmp(sqlstate, "57014") == 0)
        return SecretCodec::LifecycleError::Kind::query_canceled; // canceled OR
                                                                   // statement_timeout
    return SecretCodec::LifecycleError::Kind::database;
}

/// Build a LifecycleError from a failed query result: classifies via
/// SQLSTATE (query_canceled vs generic database) and carries the raw
/// PQerrorMessage text for server-side logging ONLY (LifecycleError doc).
SecretCodec::LifecycleError pg_lifecycle_error(PGresult* res, PGconn* conn,
                                               std::string_view what) {
    return SecretCodec::LifecycleError{classify_sqlstate(res),
                                       std::string{what} + ": " + PQerrorMessage(conn)};
}

SecretCodec::LifecycleError precondition_error(std::string msg) {
    return SecretCodec::LifecycleError{SecretCodec::LifecycleError::Kind::precondition,
                                       std::move(msg)};
}

SecretCodec::LifecycleError provider_error(std::string msg) {
    return SecretCodec::LifecycleError{SecretCodec::LifecycleError::Kind::provider,
                                       std::move(msg)};
}

void put_u32_be(std::uint8_t* out, std::uint32_t v) {
    out[0] = static_cast<std::uint8_t>(v >> 24);
    out[1] = static_cast<std::uint8_t>(v >> 16);
    out[2] = static_cast<std::uint8_t>(v >> 8);
    out[3] = static_cast<std::uint8_t>(v);
}

std::uint32_t get_u32_be(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

/// Canonical AAD field append: u32-BE length prefix, then the bytes
/// (ADR-0010 §1 "Canonical AAD serialization" — naive concatenation is
/// ambiguous, which is exactly the swap class AAD exists to defeat).
void append_field(std::vector<std::uint8_t>& aad, std::span<const std::uint8_t> field) {
    std::array<std::uint8_t, 4> len{};
    put_u32_be(len.data(), static_cast<std::uint32_t>(field.size()));
    aad.insert(aad.end(), len.begin(), len.end());
    aad.insert(aad.end(), field.begin(), field.end());
}

void append_field(std::vector<std::uint8_t>& aad, std::string_view field) {
    append_field(aad, std::span<const std::uint8_t>{
                          reinterpret_cast<const std::uint8_t*>(field.data()), field.size()});
}

/// Payload AAD: (ver, store, table, column, row_pk) — deliberately WITHOUT
/// kek_version, so re-wrap-only rotation never invalidates payload tags
/// (the #1333 HIGH-1 rotation-bricking bug class).
std::vector<std::uint8_t> payload_aad(const SecretCodec::SecretId& id) {
    std::vector<std::uint8_t> aad;
    aad.reserve(5 * 4 + 1 + id.store.size() + id.table.size() + id.column.size() +
                id.row_pk.size());
    const std::uint8_t ver = SecretCodec::kBlobVersion;
    append_field(aad, std::span<const std::uint8_t>{&ver, 1});
    append_field(aad, id.store);
    append_field(aad, id.table);
    append_field(aad, id.column);
    append_field(aad, id.row_pk);
    return aad;
}

/// Wrap AAD: the payload tuple PLUS kek_version — its 4 bytes byte-identical
/// to the blob's field, so a tampered blob kek_version fails the wrap tag.
std::vector<std::uint8_t> wrap_aad(const SecretCodec::SecretId& id, std::uint32_t kek_version) {
    std::vector<std::uint8_t> aad = payload_aad(id);
    std::array<std::uint8_t, 4> ver_be{};
    put_u32_be(ver_be.data(), kek_version);
    append_field(aad, std::span<const std::uint8_t>{ver_be});
    return aad;
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        s += kHex[b >> 4];
        s += kHex[b & 0xF];
    }
    return s;
}

std::optional<std::vector<std::uint8_t>> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0)
        return std::nullopt;
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

/// Parsed view over a v1 blob (borrows; caller keeps the bytes alive).
struct BlobView {
    std::uint32_t kek_version;
    WrappedDek wrapped;
    std::span<const std::uint8_t> data_nonce; // 12
    std::span<const std::uint8_t> data_tag;   // 16
    std::span<const std::uint8_t> ciphertext;
};

std::optional<BlobView> parse_blob(std::span<const std::uint8_t> blob) {
    // Reject below the fixed minimum BEFORE slicing (ADR §1).
    if (blob.size() < SecretCodec::kMinBlobSize)
        return std::nullopt;
    if (blob[0] != SecretCodec::kBlobVersion)
        return std::nullopt;
    BlobView v{};
    v.kek_version = get_u32_be(blob.data() + SecretCodec::kKekVersionOffset);
    std::memcpy(v.wrapped.nonce.data(), blob.data() + SecretCodec::kWrapNonceOffset, 12);
    std::memcpy(v.wrapped.wrapped.data(), blob.data() + SecretCodec::kWrappedDekOffset, 32);
    std::memcpy(v.wrapped.tag.data(), blob.data() + SecretCodec::kWrapTagOffset, 16);
    v.data_nonce = blob.subspan(SecretCodec::kDataNonceOffset, 12);
    v.data_tag = blob.subspan(SecretCodec::kDataTagOffset, 16);
    v.ciphertext = blob.subspan(SecretCodec::kCiphertextOffset);
    return v;
}

/// Quoted, dot-joined relation name from pre-validated identifiers.
std::string rel_name(const SecretCodec::SecretColumn& c) {
    return "\"" + c.store + "\".\"" + c.table + "\"";
}

/// kek_versions referenced by stored blobs (header scan) across all registered
/// columns but ABSENT from `known` (the kek_meta version set). Used at boot to
/// catch a deleted kek_meta registration before the codec silently mints a
/// fresh KEK and orphans those rows (S6; targeted availability attack).
///
/// A column whose table does not exist yet (SQLSTATE 42P01) is SKIPPED: at
/// substrate init a per-store table may not be migrated, and an absent table
/// holds no blobs. Any other SQL error → std::nullopt (caller maps to
/// db_error). Returns the sorted, de-duplicated orphan versions (empty = none).
std::optional<std::vector<std::uint32_t>>
scan_orphaned_versions(PGconn* conn, const std::vector<SecretCodec::SecretColumn>& columns,
                       const std::set<std::uint32_t>& known) {
    std::set<std::uint32_t> orphans;
    for (const auto& col : columns) {
        const std::string sql = "SELECT DISTINCT substring(\"" + col.column +
                                "\" from 2 for 4) FROM " + rel_name(col) + " WHERE \"" +
                                col.column + "\" IS NOT NULL";
        PgResult rows{PQexecParams(conn, sql.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 1)};
        if (rows.status() != PGRES_TUPLES_OK) {
            const char* sqlstate = PQresultErrorField(rows.get(), PG_DIAG_SQLSTATE);
            if (sqlstate != nullptr && std::strcmp(sqlstate, "42P01") == 0)
                continue; // undefined_table: not migrated yet, no blobs to orphan
            return std::nullopt;
        }
        const int n = PQntuples(rows.get());
        for (int i = 0; i < n; ++i) {
            if (PQgetlength(rows.get(), i, 0) != 4)
                continue; // shorter-than-header garbage; decrypt will report it
            const auto v =
                get_u32_be(reinterpret_cast<const std::uint8_t*>(PQgetvalue(rows.get(), i, 0)));
            if (!known.contains(v))
                orphans.insert(v);
        }
    }
    return std::vector<std::uint32_t>{orphans.begin(), orphans.end()};
}

} // namespace

std::string_view SecretCodec::to_string(FailureClass cls) {
    switch (cls) {
    case FailureClass::tag_mismatch:
        return "tag_mismatch";
    case FailureClass::kek_unresolvable:
        return "kek_unresolvable";
    case FailureClass::malformed_blob:
        return "malformed_blob";
    case FailureClass::crypto_failure:
        return "crypto_failure";
    }
    return "unknown";
}

std::string_view SecretCodec::to_string(InitError::Kind kind) {
    switch (kind) {
    case InitError::Kind::kek_unresolvable:
        return "kek_unresolvable";
    case InitError::Kind::kek_corrupt:
        return "kek_corrupt";
    case InitError::Kind::kek_orphaned:
        return "kek_orphaned";
    case InitError::Kind::unsupported_pk_type:
        return "unsupported_pk_type";
    case InitError::Kind::provider_failure:
        return "provider_failure";
    case InitError::Kind::db_error:
        return "db_error";
    }
    return "unknown";
}

std::string_view SecretCodec::to_external_error() {
    // One indistinguishable value for every decrypt failure — no caller can
    // tell decrypt-failure from not-found or tamper (S5; ADR-0010 §Decision 1).
    return "secret unavailable";
}

std::string SecretCodec::encode_bigint_pk(std::int64_t pk) {
    std::array<std::uint8_t, 8> be{};
    const auto u = static_cast<std::uint64_t>(pk);
    for (int i = 0; i < 8; ++i)
        be[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(u >> (56 - 8 * i));
    return {reinterpret_cast<const char*>(be.data()), be.size()};
}

SecretCodec::SecretCodec(KekProvider& provider) : provider_(provider) {}

void SecretCodec::set_audit_hook(AuditHook hook) {
    std::lock_guard lock{mu_};
    audit_hook_ = std::move(hook);
}

void SecretCodec::emit_audit(std::string_view verb, const std::string& detail_json) {
    AuditHook hook;
    {
        std::lock_guard lock{mu_};
        hook = audit_hook_;
    }
    if (!hook)
        return;
    try {
        hook(verb, detail_json);
    } catch (const std::exception& e) {
        // An audit-sink failure must never escape into a decrypt error path
        // or abort a rotation mid-flight (UP-5). Hooks must also not
        // re-enter the codec's lifecycle operations.
        spdlog::error("secret_codec: audit hook threw: {}", e.what());
    } catch (...) {
        spdlog::error("secret_codec: audit hook threw a non-exception");
    }
}

std::uint32_t SecretCodec::active_kek_version() const {
    std::lock_guard lock{mu_};
    return active_version_;
}

bool SecretCodec::register_secret_column(SecretColumn col) {
    const auto valid = PgMigrationRunner::valid_store_name;
    if (!valid(col.store) || !valid(col.table) || !valid(col.column) || !valid(col.pk_column)) {
        spdlog::error("secret_codec: rejected secret-column registration with invalid "
                      "identifier(s): {}.{}.{} pk={}",
                      col.store, col.table, col.column, col.pk_column);
        return false;
    }
    std::lock_guard lock{mu_};
    // #2530 A3: reject a duplicate (store, table, column) — a duplicate would
    // multiply the rewrap_all scan and distort the registered-column
    // trip-wire (test_secret_codec.cpp's production-wiring assertion).
    for (const auto& existing : columns_) {
        if (existing.store == col.store && existing.table == col.table &&
            existing.column == col.column) {
            spdlog::error("secret_codec: rejected duplicate secret-column registration: "
                          "{}.{}.{}",
                          col.store, col.table, col.column);
            return false;
        }
    }
    columns_.push_back(std::move(col));
    return true;
}

std::vector<SecretCodec::SecretColumn> SecretCodec::registered_columns() const {
    std::lock_guard lock{mu_};
    return columns_;
}

SecretCodec::Error SecretCodec::fail(const SecretId& id, FailureClass cls,
                                     std::uint32_t kek_version, std::string_view what) {
    {
        std::lock_guard lock{mu_};
        ++failure_counts_[{id.store, cls}];
    }
    // Identifiers only — the AAD tuple coordinates and version; never
    // ciphertext, plaintext, DEK, or key bytes (ADR-0010 §1).
    nlohmann::json detail{
        {"store", id.store},
        {"table", id.table},
        {"column", id.column},
        {"row_pk_hex",
         to_hex({reinterpret_cast<const std::uint8_t*>(id.row_pk.data()), id.row_pk.size()})},
        {"kek_version", kek_version},
        {"failure_class", to_string(cls)}};
    emit_audit("secret.decrypt_failure", detail.dump());
    // The failure class + detail go ONLY to the server-side log (operators
    // need them to triage). err.message stays GENERIC so a wiring PR that
    // forwards it to a client cannot leak a tamper/existence oracle (S5;
    // ADR-0010 §Decision 1).
    spdlog::error("secret_codec: decrypt failure [{}] {} ({}.{}.{} kek_v{})", to_string(cls), what,
                  id.store, id.table, id.column, kek_version);
    Error err;
    err.cls = cls;
    err.message = std::string{to_external_error()};
    return err;
}

SecretCodec::Error SecretCodec::fail_encrypt(const SecretId& id, FailureClass cls,
                                             std::string_view what) {
    spdlog::error("secret_codec: encrypt failed [{}] {} ({}.{}.{}) — caller must abort the "
                  "transaction",
                  to_string(cls), what, id.store, id.table, id.column);
    Error err;
    err.cls = cls;
    err.message = std::string{to_external_error()};
    return err;
}

std::expected<std::vector<std::uint8_t>, SecretCodec::Error>
SecretCodec::encrypt(const SecretId& id, std::span<const std::uint8_t> plaintext) {
    // Bound the allocation (S12): a buggy store passing an enormous span would
    // otherwise throw std::bad_alloc straight through this std::expected
    // contract. Every real secret column is far under kMaxPlaintextSize.
    if (plaintext.size() > kMaxPlaintextSize)
        return std::unexpected{
            fail_encrypt(id, FailureClass::crypto_failure, "plaintext exceeds maximum secret size")};

    std::uint32_t version = 0;
    std::string key_ref;
    {
        std::lock_guard lock{mu_};
        version = active_version_;
        if (auto it = key_refs_.find(version); it != key_refs_.end())
            key_ref = it->second;
    }
    if (version == 0 || key_ref.empty())
        return std::unexpected{fail_encrypt(id, FailureClass::kek_unresolvable,
                                            "no active KEK (init() not run or failed)")};

    // Fresh DEK + fresh data nonce per value per encryption (ADR §1).
    SecureBuffer dek{32};
    std::array<std::uint8_t, 12> data_nonce{};
    if (RAND_bytes(dek.data(), static_cast<int>(dek.size())) != 1 ||
        RAND_bytes(data_nonce.data(), static_cast<int>(data_nonce.size())) != 1)
        return std::unexpected{fail_encrypt(id, FailureClass::crypto_failure,
                                            "RAND_bytes failed minting DEK/nonce")};

    std::vector<std::uint8_t> blob(kCiphertextOffset + plaintext.size());
    blob[0] = kBlobVersion;
    put_u32_be(blob.data() + kKekVersionOffset, version);

    std::array<std::uint8_t, 16> data_tag{};
    const auto aad = payload_aad(id);
    const auto rc = detail::aes256gcm_encrypt(std::span<const std::uint8_t, 32>{dek.data(), 32},
                                              std::span<const std::uint8_t, 12>{data_nonce}, aad,
                                              plaintext, blob.data() + kCiphertextOffset,
                                              std::span<std::uint8_t, 16>{data_tag});
    if (rc != detail::GcmResult::ok)
        return std::unexpected{
            fail_encrypt(id, FailureClass::crypto_failure, "payload encrypt failed (EVP)")};

    const auto wrapped = provider_.wrap_dek(
        key_ref, std::span<const std::uint8_t, 32>{dek.data(), 32}, wrap_aad(id, version));
    if (!wrapped) {
        const FailureClass cls = wrapped.error() == KekError::unresolvable
                                     ? FailureClass::kek_unresolvable
                                     : FailureClass::crypto_failure;
        return std::unexpected{fail_encrypt(id, cls, "DEK wrap failed")};
    }

    std::memcpy(blob.data() + kWrapNonceOffset, wrapped->nonce.data(), 12);
    std::memcpy(blob.data() + kWrappedDekOffset, wrapped->wrapped.data(), 32);
    std::memcpy(blob.data() + kWrapTagOffset, wrapped->tag.data(), 16);
    std::memcpy(blob.data() + kDataNonceOffset, data_nonce.data(), 12);
    std::memcpy(blob.data() + kDataTagOffset, data_tag.data(), 16);
    return blob;
}

std::expected<SecureBuffer, SecretCodec::Error>
SecretCodec::decrypt(const SecretId& id, std::span<const std::uint8_t> blob) {
    const auto view = parse_blob(blob);
    if (!view)
        return std::unexpected{fail(id, FailureClass::malformed_blob, 0,
                                    "blob below minimum size or unknown version byte")};

    std::string key_ref;
    {
        std::lock_guard lock{mu_};
        if (auto it = key_refs_.find(view->kek_version); it != key_refs_.end())
            key_ref = it->second;
    }
    if (key_ref.empty())
        return std::unexpected{fail(id, FailureClass::kek_unresolvable, view->kek_version,
                                    "blob references unregistered/retired KEK version")};

    auto dek = provider_.unwrap_dek(key_ref, view->wrapped, wrap_aad(id, view->kek_version));
    if (!dek) {
        switch (dek.error()) {
        case KekError::tag_mismatch:
            return std::unexpected{fail(id, FailureClass::tag_mismatch, view->kek_version,
                                        "wrap-layer tag check failed (tampered blob field, "
                                        "swapped row/column, or wrong KEK)")};
        case KekError::unresolvable:
            return std::unexpected{
                fail(id, FailureClass::kek_unresolvable, view->kek_version, "KEK unresolvable")};
        case KekError::crypto_failure:
        default:
            return std::unexpected{
                fail(id, FailureClass::crypto_failure, view->kek_version, "DEK unwrap failed")};
        }
    }

    SecureBuffer plaintext{view->ciphertext.size()};
    const auto aad = payload_aad(id);
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 16> tag{};
    std::memcpy(nonce.data(), view->data_nonce.data(), nonce.size());
    std::memcpy(tag.data(), view->data_tag.data(), tag.size());
    const auto rc =
        detail::aes256gcm_decrypt(std::span<const std::uint8_t, 32>{dek->data(), 32},
                                  std::span<const std::uint8_t, 12>{nonce}, aad, view->ciphertext,
                                  std::span<const std::uint8_t, 16>{tag}, plaintext.data());
    if (rc == detail::GcmResult::auth_failed)
        return std::unexpected{fail(id, FailureClass::tag_mismatch, view->kek_version,
                                    "payload tag check failed (tampered ciphertext or "
                                    "swapped identity)")};
    if (rc != detail::GcmResult::ok)
        return std::unexpected{
            fail(id, FailureClass::crypto_failure, view->kek_version, "payload decrypt failed")};
    return plaintext;
}

std::expected<std::vector<std::uint8_t>, SecretCodec::Error>
SecretCodec::rewrap(const SecretId& id, std::span<const std::uint8_t> blob,
                    std::uint32_t to_version) {
    const auto view = parse_blob(blob);
    if (!view)
        return std::unexpected{fail(id, FailureClass::malformed_blob, 0,
                                    "blob below minimum size or unknown version byte")};
    if (view->kek_version == to_version)
        return std::vector<std::uint8_t>{blob.begin(), blob.end()};

    std::string from_ref;
    std::string to_ref;
    {
        std::lock_guard lock{mu_};
        if (auto it = key_refs_.find(view->kek_version); it != key_refs_.end())
            from_ref = it->second;
        if (auto it = key_refs_.find(to_version); it != key_refs_.end())
            to_ref = it->second;
    }
    if (from_ref.empty())
        return std::unexpected{fail(id, FailureClass::kek_unresolvable, view->kek_version,
                                    "source KEK version unresolvable")};
    if (to_ref.empty())
        return std::unexpected{fail(id, FailureClass::kek_unresolvable, to_version,
                                    "target KEK version unresolvable")};

    auto dek = provider_.unwrap_dek(from_ref, view->wrapped, wrap_aad(id, view->kek_version));
    if (!dek) {
        const FailureClass cls =
            dek.error() == KekError::tag_mismatch
                ? FailureClass::tag_mismatch
                : (dek.error() == KekError::unresolvable ? FailureClass::kek_unresolvable
                                                         : FailureClass::crypto_failure);
        return std::unexpected{fail(id, cls, view->kek_version, "DEK unwrap failed during rewrap")};
    }
    const auto rewrapped = provider_.wrap_dek(
        to_ref, std::span<const std::uint8_t, 32>{dek->data(), 32}, wrap_aad(id, to_version));
    if (!rewrapped)
        return std::unexpected{
            fail(id, FailureClass::crypto_failure, to_version, "DEK re-wrap failed")};

    // New header + wrap fields; payload section copied VERBATIM — rotation
    // must never touch data_nonce/data_tag/ciphertext (ADR §1/§3; the
    // fjarvis #1333 reproduction pins this).
    std::vector<std::uint8_t> out{blob.begin(), blob.end()};
    put_u32_be(out.data() + kKekVersionOffset, to_version);
    std::memcpy(out.data() + kWrapNonceOffset, rewrapped->nonce.data(), 12);
    std::memcpy(out.data() + kWrappedDekOffset, rewrapped->wrapped.data(), 32);
    std::memcpy(out.data() + kWrapTagOffset, rewrapped->tag.data(), 16);
    return out;
}

std::expected<void, SecretCodec::InitError> SecretCodec::init(PGconn* conn) {
    static const std::vector<PgMigration> kMigrations = {
        // kcv_alg: after a provider swap, versions minted by a
        // non-exportable provider derive their check value differently
        // (ADR-0010 §2) — the boot fingerprint check must know per-version
        // how to compare (arch-4).
        {1, "CREATE TABLE kek_meta ("
            "  kek_version BIGINT PRIMARY KEY,"
            "  kcv         BYTEA NOT NULL,"
            "  kcv_alg     TEXT NOT NULL DEFAULT 'sha256',"
            "  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  retired_at  TIMESTAMPTZ"
            ")"},
    };
    const auto db_err = [](std::string msg) {
        return std::unexpected{InitError{InitError::Kind::db_error, std::move(msg)}};
    };
    if (!PgMigrationRunner::run(conn, "secrets", kMigrations))
        return db_err("secrets schema migration failed");

    if (!exec_ok(conn, "BEGIN", "BEGIN (kek init)"))
        return db_err("kek init: BEGIN failed");
    PgTxn txn{conn};
    {
        PgResult lock{PQexec(conn, kKekLockSql)};
        if (lock.status() != PGRES_TUPLES_OK)
            return db_err(std::string{"kek init: advisory lock failed: "} + PQerrorMessage(conn));
    }

    PgResult rows{PQexec(conn, "SELECT kek_version, encode(kcv, 'hex'),"
                               "       (retired_at IS NOT NULL)::int, kcv_alg"
                               " FROM secrets.kek_meta ORDER BY kek_version")};
    if (rows.status() != PGRES_TUPLES_OK)
        return db_err(std::string{"kek init: kek_meta read failed: "} + PQerrorMessage(conn));

    std::map<std::uint32_t, std::string> refs;
    std::uint32_t max_live = 0;

    const int n = PQntuples(rows.get());

    // Snapshot the registered columns once for the boot-time scans below.
    std::vector<SecretColumn> reg_cols;
    {
        std::lock_guard lock{mu_};
        reg_cols = columns_;
    }

    // Known kek_meta version set (all rows, retired or not) for the orphan scan.
    std::set<std::uint32_t> known_versions;
    for (int i = 0; i < n; ++i) {
        const auto v = parse_u32(PQgetvalue(rows.get(), i, 0));
        if (!v)
            return db_err("kek init: unparseable kek_version in kek_meta");
        known_versions.insert(*v);
    }

    // S6: a stored blob referencing a kek_version ABSENT from kek_meta means a
    // registration row was deleted (operator error or a targeted SQL-write
    // availability attack). Treating that as first-boot and minting a fresh KEK
    // would permanently orphan every such blob. Fail closed with a distinct
    // token instead — runs for BOTH the n==0 and n>0 paths.
    {
        auto orphans = scan_orphaned_versions(conn, reg_cols, known_versions);
        if (!orphans)
            return db_err(std::string{"kek init: orphan-version scan failed: "} +
                          PQerrorMessage(conn));
        if (!orphans->empty()) {
            std::string vs;
            for (const auto v : *orphans)
                vs += (vs.empty() ? "v" : ", v") + std::to_string(v);
            return std::unexpected{InitError{
                InitError::Kind::kek_orphaned,
                "stored secret blobs reference KEK version(s) [" + vs +
                    "] absent from kek_meta — a deleted registration would be silently re-minted, "
                    "permanently orphaning those rows. Restore kek_meta AND the keys directory "
                    "from the paired backup; do NOT let the server generate a fresh KEK"}};
        }
    }

    // PK-type validation (the int4/SERIAL footgun): a registered pk_column
    // whose catalog type has no canonical AAD encoding would brick rotation
    // with a spurious tag_mismatch. Validate before any secret is written; a
    // not-yet-migrated table/column is skipped (re-checked at the next boot).
    for (const auto& col : reg_cols) {
        const char* params[] = {col.store.c_str(), col.table.c_str(), col.pk_column.c_str()};
        PgResult tr{PQexecParams(conn,
                                 "SELECT data_type FROM information_schema.columns"
                                 " WHERE table_schema = $1 AND table_name = $2"
                                 "   AND column_name = $3",
                                 3, nullptr, params, nullptr, nullptr, 0)};
        if (tr.status() != PGRES_TUPLES_OK)
            return db_err("kek init: pk-type lookup for " + col.store + "." + col.table + "." +
                          col.pk_column + " failed: " + PQerrorMessage(conn));
        if (PQntuples(tr.get()) == 0)
            continue; // column not migrated yet — re-checked at the next boot
        const std::string dt = PQgetvalue(tr.get(), 0, 0);
        const bool supported =
            dt == "bigint" || dt == "text" || dt == "character varying" || dt == "character";
        if (!supported)
            return std::unexpected{InitError{
                InitError::Kind::unsupported_pk_type,
                "secret column " + col.store + "." + col.table + "." + col.column +
                    " has pk_column '" + col.pk_column + "' of unsupported type '" + dt +
                    "' — only BIGINT and text types have a canonical AAD encoding (an "
                    "int4/SERIAL/uuid/numeric pk would brick rotation with a spurious "
                    "tag_mismatch)"}};
    }

    if (n == 0) {
        // First boot. Adopt-or-generate: a crash between KEK-file write and
        // the fingerprint INSERT leaves a valid fsynced key file with no
        // meta row — nothing can have been encrypted under it (encrypt
        // requires init() success), so adopting it is safe and refusing
        // would wedge boot forever.
        const std::string key_id = kek_key_id(1);
        std::optional<std::string> ref = provider_.resolve_kek(key_id);
        if (ref) {
            spdlog::warn("secret_codec: adopting existing un-registered KEK '{}' "
                         "(crashed first boot?)",
                         key_id);
        } else {
            ref = provider_.generate_kek(key_id);
            if (!ref)
                return std::unexpected{InitError{
                    InitError::Kind::provider_failure,
                    "kek init: KEK generation failed (CSPRNG or key storage) — refusing to "
                    "start without a secrets KEK"}};
        }
        const auto kcv = provider_.kek_check_value(*ref, "sha256");
        if (!kcv)
            return std::unexpected{InitError{
                InitError::Kind::provider_failure,
                "kek init: check-value computation failed for '" + key_id +
                    "'. If this install previously crashed during first boot, the key file may "
                    "be torn — nothing is encrypted under an unregistered KEK, so deleting that "
                    "file and restarting is safe"}};

        // Record the KCV algorithm explicitly (S2): a future non-exportable
        // provider derives KCVs differently, and boot verification dispatches
        // on this recorded value rather than assuming SHA-256.
        const std::string kcv_hex = to_hex(std::span<const std::uint8_t>{*kcv});
        const char* values[] = {kcv_hex.c_str()};
        PgResult ins{PQexecParams(conn,
                                  "INSERT INTO secrets.kek_meta (kek_version, kcv, kcv_alg)"
                                  " VALUES (1, decode($1, 'hex'), 'sha256')",
                                  1, nullptr, values, nullptr, nullptr, 0)};
        if (!ins.ok())
            return db_err(std::string{"kek init: fingerprint INSERT failed: "} +
                          PQerrorMessage(conn));
        if (!txn.commit())
            return db_err("kek init: COMMIT failed");

        {
            std::lock_guard lock{mu_};
            key_refs_ = {{1, *ref}};
            active_version_ = 1;
        }
        emit_audit("kek.generated", nlohmann::json{{"kek_version", 1}}.dump());
        spdlog::info("secret_codec: generated and registered secrets-kek-v1");
        return {};
    }

    // Boot verification (ADR §2): every registered, non-retired version must
    // resolve through the provider to material matching its fingerprint.
    for (int i = 0; i < n; ++i) {
        const auto version = parse_u32(PQgetvalue(rows.get(), i, 0));
        if (!version)
            return db_err("kek init: unparseable kek_version in kek_meta");
        const std::string kcv_hex = PQgetvalue(rows.get(), i, 1);
        const bool retired = std::strcmp(PQgetvalue(rows.get(), i, 2), "1") == 0;
        if (retired)
            continue;
        const std::string kcv_alg = PQgetvalue(rows.get(), i, 3);

        const std::string key_id = kek_key_id(*version);
        const auto ref = provider_.resolve_kek(key_id);
        if (!ref)
            return std::unexpected{InitError{
                InitError::Kind::kek_unresolvable,
                "registered KEK '" + key_id +
                    "' does not resolve through the KekProvider. Causes: keys directory older "
                    "than the database (backup skew — restore DB and keys dir as a PAIR), wrong "
                    "keys directory, or a second server instance sharing this database (one KEK "
                    "per database; see ADR-0010 §2)"}};

        // Verify against the algorithm the version was MINTED under (S2):
        // after a provider swap, SHA-256-derived and token-derived KCVs coexist
        // and must each be compared like-for-like. A provider that cannot
        // compute the recorded algorithm returns nullopt → a distinct,
        // actionable error rather than a silent mis-verification.
        const auto kcv = provider_.kek_check_value(*ref, kcv_alg);
        const auto expected = from_hex(kcv_hex);
        if (!kcv || !expected || expected->size() != kcv->size() ||
            !std::equal(kcv->begin(), kcv->end(), expected->begin()))
            return std::unexpected{InitError{
                InitError::Kind::kek_corrupt,
                "KEK '" + key_id + "' resolves but its check value (kcv_alg='" + kcv_alg +
                    "') does not match the registered fingerprint — a torn/corrupt key file, "
                    "foreign key material (NOT row tamper), or a version minted by a different "
                    "KeyProvider that this provider cannot verify. Restore the keys directory "
                    "from the backup paired with this database"}};

        refs.emplace(*version, *ref);
        max_live = std::max(max_live, *version);
    }

    if (max_live == 0)
        return db_err("kek init: kek_meta has rows but no live (non-retired) KEK version");

    if (!txn.commit())
        return db_err("kek init: COMMIT failed");

    {
        std::lock_guard lock{mu_};
        key_refs_ = std::move(refs);
        active_version_ = max_live;
    }
    spdlog::info("secret_codec: verified {} registered KEK version(s); active v{}",
                 key_refs_.size(), max_live);
    return {};
}

std::expected<std::uint32_t, SecretCodec::LifecycleError> SecretCodec::rotate_kek(PGconn* conn) {
    std::uint32_t cur = 0;
    {
        std::lock_guard lock{mu_};
        cur = active_version_;
    }
    if (cur == 0)
        return std::unexpected{precondition_error("rotate: init() has not run")};

    if (cur == std::numeric_limits<std::uint32_t>::max())
        return std::unexpected{precondition_error("rotate: kek_version space exhausted")}; // UP-7

    const std::uint32_t next = cur + 1;
    const std::string key_id = kek_key_id(next);

    // The ENTIRE mint+register sequence runs inside one transaction holding
    // the same advisory lock as init() (governance NEW-H1): without it, two
    // racing rotations could interleave so that the conflict-loser's
    // cleanup deleted the key file the winner had just registered —
    // permanent loss of every row rewrapped under it. Under the lock, a
    // second rotation cannot even observe the winner's key file until the
    // winner's fingerprint row is committed.
    if (!exec_ok(conn, "BEGIN", "BEGIN (rotate)"))
        return std::unexpected{pg_lifecycle_error(nullptr, conn, "rotate: BEGIN failed")};
    PgTxn txn{conn};
    {
        PgResult lock{PQexec(conn, kKekLockSql)};
        if (lock.status() != PGRES_TUPLES_OK)
            return std::unexpected{pg_lifecycle_error(lock.get(), conn,
                                                      "rotate: advisory lock failed")};
    }
    // Adopt-or-generate, mirroring first boot (sec-M3): a crash between a
    // prior rotation's generate_kek and its fingerprint INSERT leaves an
    // orphan key file, and generate_kek correctly refuses to overwrite it —
    // without adoption every subsequent rotation would wedge. Adoption is
    // safe by the same first-boot argument: nothing can be encrypted under
    // an unregistered version (encrypt only uses versions in key_refs_,
    // which only ever holds registered ones).
    bool adopted = false;
    std::optional<std::string> ref = provider_.resolve_kek(key_id);
    if (ref) {
        spdlog::warn("secret_codec: adopting existing un-registered KEK '{}' "
                     "(crashed prior rotation?)",
                     key_id);
        adopted = true;
    } else {
        ref = provider_.generate_kek(key_id);
        if (!ref)
            return std::unexpected{provider_error("rotate: KEK generation failed for " + key_id)};
    }
    const auto kcv = provider_.kek_check_value(*ref, "sha256");
    if (!kcv)
        return std::unexpected{provider_error(
            "rotate: check-value computation failed for " + key_id +
            (adopted ? " (adopted orphan may be torn — deleting it and re-running rotation is "
                       "safe: nothing is encrypted under an unregistered KEK)"
                     : ""))};

    const std::string kcv_hex = to_hex(std::span<const std::uint8_t>{*kcv});
    const std::string version_str = std::to_string(next);
    const char* values[] = {version_str.c_str(), kcv_hex.c_str()};
    PgResult ins{PQexecParams(conn,
                              "INSERT INTO secrets.kek_meta (kek_version, kcv, kcv_alg)"
                              " VALUES ($1::bigint, decode($2, 'hex'), 'sha256')"
                              " ON CONFLICT (kek_version) DO NOTHING",
                              2, nullptr, values, nullptr, nullptr, 0)};
    if (!ins.ok())
        return std::unexpected{
            pg_lifecycle_error(ins.get(), conn, "rotate: fingerprint INSERT failed")};
    if (std::strcmp(PQcmdTuples(ins.get()), "1") != 0) {
        // A row for this version already exists (a rotation on ANOTHER
        // server committed before we took the lock — the unsupported
        // dual-keys-dir topology, or a version minted while we were down).
        // If WE minted the key file just now it is OUR orphan with a
        // non-matching fingerprint — remove it or the next boot fails as
        // kek_corrupt. If we ADOPTED an existing file it may be the
        // legitimately registered one — never delete it; boot verification
        // arbitrates (NEW-H1: under the advisory lock a same-dir racer can
        // no longer reach this branch with our file registered).
        if (!adopted)
            (void)provider_.delete_kek(*ref);
        return std::unexpected{precondition_error("rotate: kek_version v" + std::to_string(next) +
                                                  " is already registered — re-run rotation")};
    }
    if (!txn.commit())
        return std::unexpected{pg_lifecycle_error(nullptr, conn, "rotate: COMMIT failed")};

    {
        std::lock_guard lock{mu_};
        key_refs_.emplace(next, *ref);
        active_version_ = next;
    }
    emit_audit("kek.rotated", nlohmann::json{{"kek_version", next}}.dump());
    spdlog::info("secret_codec: rotated to secrets-kek-v{}; re-wrapping stored DEKs", next);

    const auto rewrapped = rewrap_all(conn);
    if (!rewrapped)
        // Kind is PRESERVED from the rewrap_all() failure, never flattened
        // to `database` (#2530 A1) — a canceled/timed-out rewrap must still
        // classify as query_canceled to the caller.
        return std::unexpected{SecretCodec::LifecycleError{
            rewrapped.error().kind,
            "rotate: minted v" + std::to_string(next) + " but rewrap_all failed (" +
                rewrapped.error().internal_message +
                ") — resume with rewrap_all(); completion signal is "
                "oldest_kek_version_in_use()"}};
    return next;
}

std::expected<std::size_t, SecretCodec::LifecycleError> SecretCodec::rewrap_all(PGconn* conn) {
    std::uint32_t target = 0;
    std::vector<SecretColumn> columns;
    {
        std::lock_guard lock{mu_};
        target = active_version_;
        columns = columns_;
    }
    if (target == 0)
        return std::unexpected{precondition_error("rewrap_all: init() has not run")};

    std::size_t rewrapped_count = 0;
    std::size_t cas_skipped = 0;
    std::size_t malformed_skipped = 0;
    for (const auto& col : columns) {
        const std::string select = "SELECT \"" + col.pk_column + "\", \"" + col.column +
                                   "\" FROM " + rel_name(col) + " WHERE \"" + col.column +
                                   "\" IS NOT NULL";
        // Binary results: bytea arrives raw, BIGINT pks arrive as exactly
        // the canonical 8-byte-BE encoding the AAD uses.
        PgResult rows{PQexecParams(conn, select.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 1)};
        if (rows.status() != PGRES_TUPLES_OK)
            return std::unexpected{
                pg_lifecycle_error(rows.get(), conn, "rewrap_all: scan of " + rel_name(col) +
                                                         " failed")};

        const int n = PQntuples(rows.get());
        for (int i = 0; i < n; ++i) {
            const auto* pk_p = reinterpret_cast<const std::uint8_t*>(PQgetvalue(rows.get(), i, 0));
            const int pk_len = PQgetlength(rows.get(), i, 0);
            const auto* blob_p =
                reinterpret_cast<const std::uint8_t*>(PQgetvalue(rows.get(), i, 1));
            const int blob_len = PQgetlength(rows.get(), i, 1);
            const std::span<const std::uint8_t> blob{blob_p, static_cast<std::size_t>(blob_len)};

            if (blob.size() >= kMinBlobSize &&
                get_u32_be(blob.data() + kKekVersionOffset) == target)
                continue; // already on the active version (resume-safe)

            SecretId id{
                col.store, col.table, col.column,
                std::string{reinterpret_cast<const char*>(pk_p), static_cast<std::size_t>(pk_len)}};
            auto new_blob = rewrap(id, blob, target);
            if (!new_blob) {
                if (new_blob.error().cls == FailureClass::malformed_blob) {
                    // A garbage/pre-migration value is already undecryptable;
                    // hard-failing here would let one poisoned row wedge the
                    // whole rotation lifecycle forever (UP-3). Skip it — the
                    // rewrap() call has already audited and counted it, and
                    // retirement stays blocked only if the row's header bytes
                    // actually reference the old version.
                    ++malformed_skipped;
                    continue;
                }
                return std::unexpected{SecretCodec::LifecycleError{
                    SecretCodec::LifecycleError::Kind::crypto,
                    "rewrap_all: rewrap failed for a row of " + rel_name(col) + " [" +
                        std::string{to_string(new_blob.error().cls)} + "]"}};
            }

            // Compare-and-swap (ADR §3): a plain write would silently revert
            // a concurrent operator secret-update to the old value.
            const std::string update = "UPDATE " + rel_name(col) + " SET \"" + col.column +
                                       "\" = $1 WHERE \"" + col.pk_column + "\" = $2 AND \"" +
                                       col.column + "\" = $3";
            const char* values[] = {reinterpret_cast<const char*>(new_blob->data()),
                                    reinterpret_cast<const char*>(pk_p),
                                    reinterpret_cast<const char*>(blob_p)};
            const int lengths[] = {static_cast<int>(new_blob->size()), pk_len, blob_len};
            const int formats[] = {1, 1, 1};
            PgResult upd{
                PQexecParams(conn, update.c_str(), 3, nullptr, values, lengths, formats, 0)};
            if (!upd.ok())
                return std::unexpected{pg_lifecycle_error(
                    upd.get(), conn, "rewrap_all: CAS update on " + rel_name(col) + " failed")};
            if (std::strcmp(PQcmdTuples(upd.get()), "1") == 0)
                ++rewrapped_count;
            else
                ++cas_skipped; // concurrent writer re-encrypted under the active version
        }
    }
    if (cas_skipped > 0)
        spdlog::info("secret_codec: rewrap_all skipped {} row(s) updated concurrently",
                     cas_skipped);
    if (malformed_skipped > 0)
        spdlog::error("secret_codec: rewrap_all skipped {} MALFORMED row(s) — already "
                      "undecryptable; investigate via the secret.decrypt_failure audit trail",
                      malformed_skipped);
    spdlog::info("secret_codec: rewrap_all re-wrapped {} row(s) to v{}", rewrapped_count, target);
    return rewrapped_count;
}

std::expected<std::optional<std::uint32_t>, SecretCodec::LifecycleError>
SecretCodec::oldest_kek_version_in_use(PGconn* conn) {
    std::vector<SecretColumn> columns;
    {
        std::lock_guard lock{mu_};
        columns = columns_;
    }
    std::optional<std::uint32_t> oldest;
    for (const auto& col : columns) {
        // Header scan: kek_version sits at a fixed offset (bytes 2..5,
        // 1-based) so "find rows wrapped under v<N>" never reads payloads.
        const std::string sql = "SELECT substring(\"" + col.column + "\" from 2 for 4) FROM " +
                                rel_name(col) + " WHERE \"" + col.column + "\" IS NOT NULL";
        PgResult rows{PQexecParams(conn, sql.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 1)};
        if (rows.status() != PGRES_TUPLES_OK)
            return std::unexpected{pg_lifecycle_error(
                rows.get(), conn, "oldest_kek_version_in_use: scan of " + rel_name(col) +
                                       " failed")};
        const int n = PQntuples(rows.get());
        for (int i = 0; i < n; ++i) {
            if (PQgetlength(rows.get(), i, 0) != 4)
                continue; // shorter-than-header garbage; decrypt will report it
            const auto v =
                get_u32_be(reinterpret_cast<const std::uint8_t*>(PQgetvalue(rows.get(), i, 0)));
            if (!oldest || v < *oldest)
                oldest = v;
        }
    }
    return oldest;
}

std::expected<void, SecretCodec::LifecycleError> SecretCodec::retire_kek(PGconn* conn,
                                                                         std::uint32_t version) {
    {
        std::lock_guard lock{mu_};
        if (version == active_version_)
            return std::unexpected{precondition_error(
                "retire: refusing to retire the ACTIVE KEK version v" + std::to_string(version))};
        if (!key_refs_.contains(version))
            return std::unexpected{precondition_error(
                "retire: v" + std::to_string(version) + " is not a live registered KEK version")};
    }

    // Condition (a) (ADR §3): zero stored blobs may still reference it —
    // premature retirement is permanent, unrecoverable loss.
    std::vector<SecretColumn> columns;
    {
        std::lock_guard lock{mu_};
        columns = columns_;
    }
    std::array<std::uint8_t, 4> ver_be{};
    put_u32_be(ver_be.data(), version);
    for (const auto& col : columns) {
        const std::string sql = "SELECT count(*) FROM " + rel_name(col) + " WHERE \"" + col.column +
                                "\" IS NOT NULL AND substring(\"" + col.column +
                                "\" from 2 for 4) = $1";
        const char* values[] = {reinterpret_cast<const char*>(ver_be.data())};
        const int lengths[] = {4};
        const int formats[] = {1};
        PgResult res{PQexecParams(conn, sql.c_str(), 1, nullptr, values, lengths, formats, 0)};
        if (res.status() != PGRES_TUPLES_OK)
            return std::unexpected{pg_lifecycle_error(
                res.get(), conn, "retire: reference scan of " + rel_name(col) + " failed")};
        // Strict parse, refuse on garbage: this gate guards permanent key
        // destruction, so an unparseable count must fail CLOSED (CON-S3).
        const auto refs_count =
            PQntuples(res.get()) == 1 ? parse_u32(PQgetvalue(res.get(), 0, 0)) : std::nullopt;
        if (!refs_count)
            return std::unexpected{SecretCodec::LifecycleError{
                SecretCodec::LifecycleError::Kind::database,
                "retire: unparseable reference count from " + rel_name(col) + " — refusing"}};
        if (*refs_count > 0)
            return std::unexpected{precondition_error(
                "retire: refusing — " + rel_name(col) + " still holds blob(s) wrapped under v" +
                std::to_string(version) +
                "; run rewrap_all() and confirm with "
                "oldest_kek_version_in_use() first")};
    }

    const std::string version_str = std::to_string(version);
    const char* values[] = {version_str.c_str()};
    PgResult upd{PQexecParams(conn,
                              "UPDATE secrets.kek_meta SET retired_at = now()"
                              " WHERE kek_version = $1::bigint AND retired_at IS NULL"
                              " RETURNING kek_version",
                              1, nullptr, values, nullptr, nullptr, 0)};
    if (upd.status() != PGRES_TUPLES_OK || PQntuples(upd.get()) != 1)
        return std::unexpected{
            pg_lifecycle_error(upd.get(), conn, "retire: kek_meta update failed")};

    std::string ref;
    {
        std::lock_guard lock{mu_};
        if (auto it = key_refs_.find(version); it != key_refs_.end()) {
            ref = it->second;
            key_refs_.erase(it);
        }
    }

    // Destruction must be CONFIRMED before the audit event claims it (S3).
    // A failed delete_kek (HSM outage, permissions) is an ERROR, not a
    // warning: emitting `kek.retired` here would write false destruction
    // evidence and tell automation to stop retrying while usable key material
    // remains on disk. The retired_at UPDATE above is crash-safe — the version
    // is already excluded from boot verification — so the orphaned key file is
    // harmless until removed.
    if (ref.empty() || !provider_.delete_kek(ref)) {
        spdlog::error("secret_codec: v{} marked retired in kek_meta but provider key deletion "
                      "FAILED — key material for '{}' remains; remove it manually",
                      version, kek_key_id(version));
        return std::unexpected{provider_error(
            "retire: v" + std::to_string(version) +
            " marked retired but provider key deletion FAILED — key material "
            "for '" +
            kek_key_id(version) +
            "' still exists; remove it manually. The version is already "
            "excluded from boot verification (no kek.retired event was emitted "
            "— destruction is unconfirmed)")};
    }

    emit_audit("kek.retired", nlohmann::json{{"kek_version", version}}.dump());
    spdlog::info("secret_codec: retired secrets-kek-v{} (key destroyed; recorded in kek_meta)",
                 version);
    return {};
}

std::expected<std::size_t, SecretCodec::LifecycleError>
SecretCodec::live_kek_version_count(PGconn* conn) const {
    PgResult res{PQexec(conn, "SELECT COUNT(*) FROM secrets.kek_meta WHERE retired_at IS NULL")};
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected{
            pg_lifecycle_error(res.get(), conn, "live_kek_version_count: query failed")};
    if (PQntuples(res.get()) != 1)
        return std::unexpected{SecretCodec::LifecycleError{
            SecretCodec::LifecycleError::Kind::database,
            "live_kek_version_count: unexpected result shape (expected exactly one row)"}};
    // Strict parse + overflow guard (#2530 A4): the value lands in a
    // std::uint32_t status field downstream — parse_u32 both validates the
    // parse and range-checks into uint32, so a malformed/oversized COUNT(*)
    // never silently becomes 0.
    const auto count = parse_u32(PQgetvalue(res.get(), 0, 0));
    if (!count)
        return std::unexpected{SecretCodec::LifecycleError{
            SecretCodec::LifecycleError::Kind::database,
            "live_kek_version_count: unparseable or out-of-range COUNT(*) result"}};
    return static_cast<std::size_t>(*count);
}

std::expected<SecretCodec::RotateClock, SecretCodec::LifecycleError>
SecretCodec::rotate_clock(PGconn* conn) const {
    // Single statement, both timestamps from the SAME Postgres server clock
    // (#2530 A5) — this is what makes the anomaly check sound: we are never
    // comparing an app-host clock reading against the DB clock.
    PgResult res{PQexec(conn, "SELECT EXTRACT(EPOCH FROM (now() - created_at))::bigint,"
                              "       (created_at > now())"
                              "  FROM secrets.kek_meta"
                              " ORDER BY kek_version DESC"
                              " LIMIT 1")};
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected{pg_lifecycle_error(res.get(), conn, "rotate_clock: query failed")};

    RotateClock clock;
    const int n = PQntuples(res.get());
    if (n == 0)
        return clock; // any_rows stays false — no kek_meta rows yet
    if (n != 1)
        return std::unexpected{SecretCodec::LifecycleError{
            SecretCodec::LifecycleError::Kind::database,
            "rotate_clock: unexpected result shape (expected at most one row)"}};

    clock.any_rows = true;
    const char* age_text = PQgetvalue(res.get(), 0, 0);
    const bool age_is_null = PQgetisnull(res.get(), 0, 0) != 0;
    std::int64_t age_seconds = 0;
    if (age_is_null || age_text == nullptr) {
        return std::unexpected{SecretCodec::LifecycleError{
            SecretCodec::LifecycleError::Kind::database,
            "rotate_clock: NULL age from EXTRACT(EPOCH FROM (now() - created_at))"}};
    }
    {
        std::string_view sv{age_text};
        const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), age_seconds);
        if (ec != std::errc{} || ptr != sv.data() + sv.size())
            return std::unexpected{SecretCodec::LifecycleError{
                SecretCodec::LifecycleError::Kind::database,
                "rotate_clock: unparseable age value"}};
    }

    const char* future_text = PQgetvalue(res.get(), 0, 1);
    const bool future_is_null = PQgetisnull(res.get(), 0, 1) != 0;
    if (future_is_null || future_text == nullptr) {
        return std::unexpected{SecretCodec::LifecycleError{
            SecretCodec::LifecycleError::Kind::database,
            "rotate_clock: NULL future-dated flag from (created_at > now())"}};
    }
    // libpq text-format boolean is 't'/'f'. A negative age (age_seconds < 0)
    // is the same underlying condition and is treated as a second, defensive
    // confirmation — either signal alone is sufficient to flag the anomaly.
    const bool future_dated = (future_text[0] == 't') || (age_seconds < 0);
    clock.clock_anomaly = future_dated;
    clock.since_newest = std::chrono::seconds{age_seconds < 0 ? 0 : age_seconds};
    // #2530 G7-B6: capture the skew MAGNITUDE before it is discarded above.
    // `age_seconds` is `EXTRACT(EPOCH FROM (now() - created_at))`, so a
    // future-dated row makes it negative; its absolute value is exactly how
    // many seconds into the future the row is dated. The boolean-only
    // `future_text[0] == 't'` path (with a non-negative `age_seconds`,
    // possible only from clock jitter at the exact now()/created_at
    // boundary) has no usable magnitude — leave it at 0 rather than fabricate
    // one.
    // #2530 G8-S6: `-age_seconds` is signed-negation UB at INT64_MIN (no
    // representable positive counterpart). `0ULL - static_cast<uint64_t>(...)`
    // computes the same magnitude via well-defined unsigned wraparound instead.
    clock.future_skew_secs =
        (age_seconds < 0) ? (0ULL - static_cast<std::uint64_t>(age_seconds)) : 0;
    return clock;
}

std::vector<std::pair<std::pair<std::string, SecretCodec::FailureClass>, std::uint64_t>>
SecretCodec::decrypt_failure_counts() const {
    std::lock_guard lock{mu_};
    return {failure_counts_.begin(), failure_counts_.end()};
}

} // namespace yuzu::server::pg
