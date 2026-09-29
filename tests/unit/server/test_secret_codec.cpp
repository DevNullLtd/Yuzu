// SecretCodec tests (#1320 PR 4, ADR-0010): blob v1 format, canonical AAD
// anti-swap + boundary-shift, fail-closed boot verification
// (kek_unresolvable / kek_corrupt), fresh-DEK-per-encrypt, and the fjarvis
// #1333 rotation reproduction — encrypt → rotate (re-wrap only) → payload
// still decrypts; tampered blob kek_version → wrap tag fails.

#include <catch2/catch_test_macros.hpp>

#include "key_provider.hpp"
#include "pg/pg_raii.hpp"
#include "kek_op_lock.hpp"
#include "pg/secret_codec.hpp"

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

using yuzu::server::FileKeyProvider;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::SecretCodec;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()),
            reinterpret_cast<const std::uint8_t*>(s.data()) + s.size()};
}

SecretCodec::SecretId test_id(std::int64_t pk = 42) {
    return {"tstore", "things", "secret", SecretCodec::encode_bigint_pk(pk)};
}

/// The registered test table the rotation scan walks.
void create_test_table(PGconn* conn) {
    PgResult schema{PQexec(conn, "CREATE SCHEMA IF NOT EXISTS tstore")};
    REQUIRE(schema.ok());
    PgResult table{PQexec(conn, "CREATE TABLE IF NOT EXISTS tstore.things ("
                                "  id     BIGINT PRIMARY KEY,"
                                "  secret BYTEA"
                                ")")};
    REQUIRE(table.ok());
}

void upsert_secret(PGconn* conn, std::int64_t pk, std::span<const std::uint8_t> blob) {
    const std::string pk_str = std::to_string(pk);
    const char* values[] = {pk_str.c_str(), reinterpret_cast<const char*>(blob.data())};
    const int lengths[] = {0, static_cast<int>(blob.size())};
    const int formats[] = {0, 1};
    PgResult res{PQexecParams(conn,
                              "INSERT INTO tstore.things (id, secret)"
                              " VALUES ($1::bigint, $2)"
                              " ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret",
                              2, nullptr, values, lengths, formats, 0)};
    REQUIRE(res.ok());
}

std::vector<std::uint8_t> fetch_secret(PGconn* conn, std::int64_t pk) {
    const std::string pk_str = std::to_string(pk);
    const char* values[] = {pk_str.c_str()};
    PgResult res{PQexecParams(conn, "SELECT secret FROM tstore.things WHERE id = $1::bigint", 1,
                              nullptr, values, nullptr, nullptr, /*resultFormat=*/1)};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    const auto* p = reinterpret_cast<const std::uint8_t*>(PQgetvalue(res.get(), 0, 0));
    return {p, p + PQgetlength(res.get(), 0, 0)};
}

std::uint32_t blob_kek_version(std::span<const std::uint8_t> blob) {
    REQUIRE(blob.size() >= SecretCodec::kMinBlobSize);
    const auto* p = blob.data() + SecretCodec::kKekVersionOffset;
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void set_blob_kek_version(std::vector<std::uint8_t>& blob, std::uint32_t v) {
    blob[SecretCodec::kKekVersionOffset + 0] = static_cast<std::uint8_t>(v >> 24);
    blob[SecretCodec::kKekVersionOffset + 1] = static_cast<std::uint8_t>(v >> 16);
    blob[SecretCodec::kKekVersionOffset + 2] = static_cast<std::uint8_t>(v >> 8);
    blob[SecretCodec::kKekVersionOffset + 3] = static_cast<std::uint8_t>(v);
}

// Delegates every KEK op to an inner FileKeyProvider but forces delete_kek to
// fail — exercises the S3 "destruction unconfirmed" retire path (a real HSM
// outage / permissions failure).
class FailingDeleteProvider : public yuzu::server::KekProvider {
public:
    explicit FailingDeleteProvider(FileKeyProvider& inner) : inner_(inner) {}
    std::optional<std::string> generate_kek(std::string_view id) override {
        return inner_.generate_kek(id);
    }
    std::optional<std::string> resolve_kek(std::string_view id) override {
        return inner_.resolve_kek(id);
    }
    std::expected<yuzu::server::WrappedDek, yuzu::server::KekError>
    wrap_dek(std::string_view ref, std::span<const std::uint8_t, 32> dek,
             std::span<const std::uint8_t> aad) override {
        return inner_.wrap_dek(ref, dek, aad);
    }
    std::expected<yuzu::server::SecureBuffer, yuzu::server::KekError>
    unwrap_dek(std::string_view ref, const yuzu::server::WrappedDek& w,
               std::span<const std::uint8_t> aad) override {
        return inner_.unwrap_dek(ref, w, aad);
    }
    std::optional<std::array<std::uint8_t, 32>> kek_check_value(std::string_view ref,
                                                                std::string_view alg) override {
        return inner_.kek_check_value(ref, alg);
    }
    bool delete_kek(std::string_view) override { return false; } // forced failure
private:
    FileKeyProvider& inner_;
};

} // namespace

#ifdef YUZU_TEST_ENABLE_PG

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): pre-applies
// the `secrets` schema migration via a throwaway codec init, then resets
// kek_meta to the empty first-boot state — each test still mints its own KEK
// against a fresh keys dir, exactly as on a plain empty database.
// Security note (governance #2091 Gate 2/6 sign-off): no key material can
// reach the shared template — the throwaway KEK lives only in this lambda's
// TempDir (destroyed at scope exit), the DELETE empties kek_meta before the
// template is ever cloned, and template fingerprints are structure-only.
yuzu::test::PgTestTemplate secrets_tpl{"secrets", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("secrets template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("secrets template: init failed to migrate");
    PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("secrets template: kek_meta reset failed");
}};
} // namespace

TEST_CASE("SecretCodec: encode_bigint_pk is fixed 8-byte BE", "[secrets]") {
    const std::string be = SecretCodec::encode_bigint_pk(0x0102030405060708);
    REQUIRE(be.size() == 8);
    for (std::size_t i = 0; i < 8; ++i)
        REQUIRE(static_cast<std::uint8_t>(be[i]) == i + 1);
    // Negative pks stay canonical (two's complement BE), distinct from positive.
    REQUIRE(SecretCodec::encode_bigint_pk(-1) != SecretCodec::encode_bigint_pk(1));
}

TEST_CASE("SecretCodec: register_secret_column validates identifiers", "[secrets]") {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));
    REQUIRE_FALSE(codec.register_secret_column({"Bad-Schema", "things", "secret", "id"}));
    REQUIRE_FALSE(codec.register_secret_column({"tstore", "things; DROP TABLE x", "secret", "id"}));
    REQUIRE_FALSE(codec.register_secret_column({"public", "things", "secret", "id"}));
}

// #2530 A3: a duplicate (store, table, column) registration is rejected —
// duplicates would multiply the rewrap_all scan and distort the
// registered-column trip-wire.
TEST_CASE("SecretCodec: register_secret_column rejects a duplicate (store, table, column)",
          "[secrets]") {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));
    // Exact duplicate.
    REQUIRE_FALSE(codec.register_secret_column({"tstore", "things", "secret", "id"}));
    // Same (store, table, column) but a different pk_column is still a
    // duplicate registration of the same scan target — rejected too.
    REQUIRE_FALSE(codec.register_secret_column({"tstore", "things", "secret", "other_pk"}));
    // A genuinely different column registers fine.
    REQUIRE(codec.register_secret_column({"tstore", "things", "other_secret", "id"}));
    REQUIRE(codec.registered_columns().size() == 2);
}

// #2530 A2: registered_columns() is a snapshot in registration order.
TEST_CASE("SecretCodec: registered_columns() returns a snapshot in registration order",
          "[secrets]") {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    REQUIRE(codec.registered_columns().empty());

    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));
    REQUIRE(codec.register_secret_column({"tstore", "other", "secret", "id"}));
    REQUIRE(codec.register_secret_column({"tstore", "cfg", "secret", "key"}));

    const auto cols = codec.registered_columns();
    REQUIRE(cols.size() == 3);
    REQUIRE(cols[0].table == "things");
    REQUIRE(cols[1].table == "other");
    REQUIRE(cols[2].table == "cfg");
}

TEST_CASE("SecretCodec init: first boot generates v1; re-init verifies", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    PgConn conn = connect(db.dsn());

    std::vector<std::string> audit_verbs;
    SecretCodec codec(provider);
    codec.set_audit_hook(
        [&](std::string_view verb, const std::string&) { audit_verbs.emplace_back(verb); });

    REQUIRE(codec.active_kek_version() == 0);
    auto r = codec.init(conn.get());
    INFO((r ? std::string{} : r.error().message));
    REQUIRE(r.has_value());
    REQUIRE(codec.active_kek_version() == 1);
    REQUIRE(provider.resolve_kek("secrets-kek-v1"));
    REQUIRE(std::count(audit_verbs.begin(), audit_verbs.end(), "kek.generated") == 1);

    // One fingerprint row registered.
    PgResult res{PQexec(conn.get(), "SELECT count(*) FROM secrets.kek_meta")};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(std::string{PQgetvalue(res.get(), 0, 0)} == "1");

    // Second boot (fresh codec, same keys dir + db): verification passes,
    // no second generation.
    SecretCodec codec2(provider);
    auto r2 = codec2.init(conn.get());
    INFO((r2 ? std::string{} : r2.error().message));
    REQUIRE(r2.has_value());
    REQUIRE(codec2.active_kek_version() == 1);
}

TEST_CASE("SecretCodec init: fail-closed boot verification", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    PgConn conn = connect(db.dsn());
    {
        FileKeyProvider provider(keys.path);
        SecretCodec codec(provider);
        REQUIRE(codec.init(conn.get()).has_value());
    }

    SECTION("missing KEK file (backup skew / dual server) -> kek_unresolvable") {
        yuzu::test::TempDir other_keys{"yuzu_test_other_keys_"}; // empty keys dir, same database
        FileKeyProvider provider(other_keys.path);
        SecretCodec codec(provider);
        auto r = codec.init(conn.get());
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().kind == SecretCodec::InitError::Kind::kek_unresolvable);
    }
    SECTION("corrupt KEK file -> kek_corrupt") {
        // Overwrite the key file with different 32 bytes; fresh provider so
        // no resident cached copy masks the corruption.
        const auto key_path = keys.path / "secrets-kek-v1.key";
        {
            std::ofstream out(key_path, std::ios::binary | std::ios::trunc);
            const std::vector<std::uint8_t> junk(32, 0xAB);
            out.write(reinterpret_cast<const char*>(junk.data()),
                      static_cast<std::streamsize>(junk.size()));
        }
        FileKeyProvider provider(keys.path);
        SecretCodec codec(provider);
        auto r = codec.init(conn.get());
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().kind == SecretCodec::InitError::Kind::kek_corrupt);
    }
}

TEST_CASE("SecretCodec: round-trip, blob format, fresh DEK per encrypt", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    const auto plaintext = bytes_of("hunter2-totp-seed");
    const auto id = test_id();

    auto blob = codec.encrypt(id, plaintext);
    REQUIRE(blob.has_value());
    REQUIRE(blob->size() == SecretCodec::kMinBlobSize + plaintext.size());
    REQUIRE((*blob)[0] == SecretCodec::kBlobVersion);
    REQUIRE(blob_kek_version(*blob) == 1);

    auto back = codec.decrypt(id, *blob);
    REQUIRE(back.has_value());
    REQUIRE(back->size() == plaintext.size());
    REQUIRE(std::equal(plaintext.begin(), plaintext.end(), back->data()));

    // Fresh DEK + nonces per encryption: same value, different blob —
    // including the ciphertext (different DEK), not just the nonces.
    auto blob2 = codec.encrypt(id, plaintext);
    REQUIRE(blob2.has_value());
    REQUIRE(*blob != *blob2);
    REQUIRE_FALSE(std::equal(blob->begin() + SecretCodec::kCiphertextOffset, blob->end(),
                             blob2->begin() + SecretCodec::kCiphertextOffset));

    // Empty plaintext is a valid value (blob == fixed minimum).
    auto empty = codec.encrypt(id, {});
    REQUIRE(empty.has_value());
    REQUIRE(empty->size() == SecretCodec::kMinBlobSize);
    REQUIRE(codec.decrypt(id, *empty).has_value());

    // Oversized plaintext is rejected (S12) — never allowed to throw
    // std::bad_alloc through the std::expected error contract. The ceiling
    // itself is accepted.
    std::vector<std::uint8_t> over(SecretCodec::kMaxPlaintextSize + 1, 0x5A);
    auto over_r = codec.encrypt(id, over);
    REQUIRE_FALSE(over_r.has_value());
    REQUIRE(over_r.error().cls == SecretCodec::FailureClass::crypto_failure);
    std::vector<std::uint8_t> at_max(SecretCodec::kMaxPlaintextSize, 0x5A);
    REQUIRE(codec.encrypt(id, at_max).has_value());
}

TEST_CASE("SecretCodec: AAD anti-swap and boundary-shift", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    const auto plaintext = bytes_of("webhook-signing-secret");

    SECTION("any identity coordinate change fails the tag") {
        const auto id = test_id(42);
        auto blob = codec.encrypt(id, plaintext);
        REQUIRE(blob.has_value());

        auto wrong_pk = codec.decrypt(test_id(43), *blob);
        REQUIRE_FALSE(wrong_pk.has_value());
        REQUIRE(wrong_pk.error().cls == SecretCodec::FailureClass::tag_mismatch);

        SecretCodec::SecretId wrong_col = id;
        wrong_col.column = "other";
        auto r2 = codec.decrypt(wrong_col, *blob);
        REQUIRE_FALSE(r2.has_value());
        REQUIRE(r2.error().cls == SecretCodec::FailureClass::tag_mismatch);

        SecretCodec::SecretId wrong_table = id;
        wrong_table.table = "webhooks";
        REQUIRE_FALSE(codec.decrypt(wrong_table, *blob).has_value());

        SecretCodec::SecretId wrong_store = id;
        wrong_store.store = "offload";
        REQUIRE_FALSE(codec.decrypt(wrong_store, *blob).has_value());
    }

    SECTION("boundary shift: (a,bc) vs (ab,c) must not collide") {
        // Naive concatenation would serialize both identities to the same
        // AAD bytes; the u32-BE length prefixes must keep them distinct.
        SecretCodec::SecretId id1{"s", "a", "bc", "pk"};
        SecretCodec::SecretId id2{"s", "ab", "c", "pk"};
        auto blob = codec.encrypt(id1, plaintext);
        REQUIRE(blob.has_value());
        auto shifted = codec.decrypt(id2, *blob);
        REQUIRE_FALSE(shifted.has_value());
        REQUIRE(shifted.error().cls == SecretCodec::FailureClass::tag_mismatch);
        REQUIRE(codec.decrypt(id1, *blob).has_value());
    }
}

TEST_CASE("SecretCodec: malformed blobs and payload tamper", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    const auto id = test_id();
    auto blob = codec.encrypt(id, bytes_of("oidc-client-secret"));
    REQUIRE(blob.has_value());

    SECTION("below fixed minimum") {
        std::vector<std::uint8_t> shorted(blob->begin(),
                                          blob->begin() + SecretCodec::kMinBlobSize - 1);
        auto r = codec.decrypt(id, shorted);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::malformed_blob);
    }
    SECTION("unknown version byte") {
        auto t = *blob;
        t[0] = 0x7F;
        auto r = codec.decrypt(id, t);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::malformed_blob);
    }
    SECTION("flipped ciphertext byte") {
        auto t = *blob;
        t[SecretCodec::kCiphertextOffset] ^= 0x01;
        auto r = codec.decrypt(id, t);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::tag_mismatch);
    }
    SECTION("flipped data tag byte") {
        auto t = *blob;
        t[SecretCodec::kDataTagOffset] ^= 0x01;
        auto r = codec.decrypt(id, t);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::tag_mismatch);
    }
    SECTION("flipped wrap tag byte (S7 — wrap-layer tamper at the codec boundary)") {
        auto t = *blob;
        t[SecretCodec::kWrapTagOffset] ^= 0x01;
        auto r = codec.decrypt(id, t);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::tag_mismatch);
    }
    SECTION("flipped wrapped-DEK byte (S7 — wrap-layer tamper at the codec boundary)") {
        auto t = *blob;
        t[SecretCodec::kWrappedDekOffset] ^= 0x01;
        auto r = codec.decrypt(id, t);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::tag_mismatch);
    }
    SECTION("failure counters accumulate by store and class") {
        auto t = *blob;
        t[SecretCodec::kDataTagOffset] ^= 0x01;
        (void)codec.decrypt(id, t);
        const auto counts = codec.decrypt_failure_counts();
        bool found = false;
        for (const auto& [key, n] : counts)
            if (key.first == "tstore" && key.second == SecretCodec::FailureClass::tag_mismatch &&
                n >= 1)
                found = true;
        REQUIRE(found);
    }
}

TEST_CASE("SecretCodec: KEK rotation — the fjarvis #1333 reproduction", "[pg][secrets][pg-smoke]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    create_test_table(conn.get());
    REQUIRE(codec.register_secret_column(
        {"tstore", "things", "secret", "id"}));

    std::vector<std::string> audit_verbs;
    codec.set_audit_hook(
        [&](std::string_view verb, const std::string&) { audit_verbs.emplace_back(verb); });

    const auto plaintext = bytes_of("offload-credential");
    const auto id = test_id(42);
    auto v1_blob = codec.encrypt(id, plaintext);
    REQUIRE(v1_blob.has_value());
    REQUIRE(blob_kek_version(*v1_blob) == 1);
    upsert_secret(conn.get(), 42, *v1_blob);

    // Rotate: mint v2, re-wrap ONLY (payload untouched).
    auto rotated = codec.rotate_kek(conn.get());
    INFO((rotated ? std::string{} : rotated.error().internal_message));
    REQUIRE(rotated.has_value());
    REQUIRE(*rotated == 2);
    REQUIRE(codec.active_kek_version() == 2);
    REQUIRE(std::count(audit_verbs.begin(), audit_verbs.end(), "kek.rotated") == 1);

    const auto v2_blob = fetch_secret(conn.get(), 42);
    REQUIRE(blob_kek_version(v2_blob) == 2);
    // Payload section (data_nonce || data_tag || ciphertext) byte-identical:
    // rotation never touches it — including kek_version in the payload AAD
    // would have bricked this row (the #1333 HIGH-1 bug, reproduced live).
    REQUIRE(std::equal(v1_blob->begin() + SecretCodec::kDataNonceOffset, v1_blob->end(),
                       v2_blob.begin() + SecretCodec::kDataNonceOffset, v2_blob.end()));
    // Wrap section re-keyed.
    REQUIRE_FALSE(std::equal(v1_blob->begin() + SecretCodec::kWrapNonceOffset,
                             v1_blob->begin() + SecretCodec::kDataNonceOffset,
                             v2_blob.begin() + SecretCodec::kWrapNonceOffset));

    // The payload still decrypts after re-wrap-only rotation.
    auto back = codec.decrypt(id, v2_blob);
    INFO((back ? std::string{} : back.error().message));
    REQUIRE(back.has_value());
    REQUIRE(std::equal(plaintext.begin(), plaintext.end(), back->data()));

    // Completion signal: nothing references v1 anymore.
    auto oldest = codec.oldest_kek_version_in_use(conn.get());
    REQUIRE(oldest.has_value());
    REQUIRE(*oldest == 2);

    SECTION("tampered blob kek_version fails the wrap tag (version integrity)") {
        // Patch the v2 blob's version field back to 1 — v1 is still live, so
        // this resolves a KEK; the wrap AAD binds the field, so the wrap tag
        // must fail as tag_mismatch (NOT kek_unresolvable, NOT success).
        auto tampered = v2_blob;
        set_blob_kek_version(tampered, 1);
        auto r = codec.decrypt(id, tampered);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::tag_mismatch);
    }
    SECTION("unknown kek_version is unresolvable") {
        auto tampered = v2_blob;
        set_blob_kek_version(tampered, 99);
        auto r = codec.decrypt(id, tampered);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::kek_unresolvable);
    }
    SECTION("interrupted rotation resumes via rewrap_all (header-version detection)") {
        // Put the original v1 blob back (as if the CAS write never landed),
        // then resume: rewrap_all must rewrap exactly that one row.
        upsert_secret(conn.get(), 42, *v1_blob);
        auto resumed = codec.rewrap_all(conn.get());
        REQUIRE(resumed.has_value());
        REQUIRE(*resumed == 1);
        REQUIRE(blob_kek_version(fetch_secret(conn.get(), 42)) == 2);
        // Idempotent re-run: nothing left to do.
        auto again = codec.rewrap_all(conn.get());
        REQUIRE(again.has_value());
        REQUIRE(*again == 0);
    }
    SECTION("retirement lifecycle") {
        // Refuse while a blob still references v1.
        upsert_secret(conn.get(), 42, *v1_blob);
        REQUIRE_FALSE(codec.retire_kek(conn.get(), 1).has_value());
        // Refuse the active version outright.
        REQUIRE_FALSE(codec.retire_kek(conn.get(), 2).has_value());

        // After a full rewrap, v1 retires: meta row keeps destruction evidence,
        // the key file is gone, and a v1 blob now reads as unresolvable.
        REQUIRE(codec.rewrap_all(conn.get()).has_value());
        auto retired = codec.retire_kek(conn.get(), 1);
        INFO((retired ? std::string{} : retired.error().internal_message));
        REQUIRE(retired.has_value());
        REQUIRE(std::count(audit_verbs.begin(), audit_verbs.end(), "kek.retired") == 1);
        REQUIRE_FALSE(provider.resolve_kek("secrets-kek-v1"));

        PgResult meta{PQexec(conn.get(), "SELECT count(*) FROM secrets.kek_meta"
                                         " WHERE kek_version = 1 AND retired_at IS NOT NULL")};
        REQUIRE(meta.status() == PGRES_TUPLES_OK);
        REQUIRE(std::string{PQgetvalue(meta.get(), 0, 0)} == "1");

        auto r = codec.decrypt(id, *v1_blob);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().cls == SecretCodec::FailureClass::kek_unresolvable);

        // Boot verification skips retired versions: a fresh codec still
        // boots cleanly with the v1 key file destroyed.
        SecretCodec codec2(provider);
        auto r2 = codec2.init(conn.get());
        INFO((r2 ? std::string{} : r2.error().message));
        REQUIRE(r2.has_value());
        REQUIRE(codec2.active_kek_version() == 2);
    }
}


TEST_CASE("SecretCodec: TEXT primary keys rotate and decrypt (uniform binary-pk path)",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    PgResult schema{PQexec(conn.get(), "CREATE SCHEMA IF NOT EXISTS tstore")};
    REQUIRE(schema.ok());
    PgResult table{PQexec(conn.get(), "CREATE TABLE tstore.cfg ("
                                      "  key    TEXT PRIMARY KEY,"
                                      "  secret BYTEA"
                                      ")")};
    REQUIRE(table.ok());
    REQUIRE(codec.register_secret_column({"tstore", "cfg", "secret", "key"}));

    // Canonical pk encoding for TEXT is the raw bytes — identical to what
    // the binary-format rotation scan reads back.
    const SecretCodec::SecretId id{"tstore", "cfg", "secret", "oidc_client_secret"};
    const auto plaintext = bytes_of("s3cr3t-client-credential");
    auto blob = codec.encrypt(id, plaintext);
    REQUIRE(blob.has_value());
    {
        const char* values[] = {id.row_pk.c_str(), reinterpret_cast<const char*>(blob->data())};
        const int lengths[] = {static_cast<int>(id.row_pk.size()),
                               static_cast<int>(blob->size())};
        const int formats[] = {1, 1};
        PgResult ins{PQexecParams(conn.get(),
                                  "INSERT INTO tstore.cfg (key, secret) VALUES ($1, $2)", 2,
                                  nullptr, values, lengths, formats, 0)};
        REQUIRE(ins.ok());
    }

    auto rotated = codec.rotate_kek(conn.get());
    INFO((rotated ? std::string{} : rotated.error().internal_message));
    REQUIRE(rotated.has_value());

    const char* values[] = {id.row_pk.c_str()};
    const int lengths[] = {static_cast<int>(id.row_pk.size())};
    const int formats[] = {1};
    PgResult sel2{PQexecParams(conn.get(), "SELECT secret FROM tstore.cfg WHERE key = $1", 1,
                               nullptr, values, lengths, formats, 1)};
    REQUIRE(sel2.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(sel2.get()) == 1);
    const auto* bp = reinterpret_cast<const std::uint8_t*>(PQgetvalue(sel2.get(), 0, 0));
    const std::vector<std::uint8_t> v2_blob{bp, bp + PQgetlength(sel2.get(), 0, 0)};
    REQUIRE(blob_kek_version(v2_blob) == 2);

    auto back = codec.decrypt(id, v2_blob);
    INFO((back ? std::string{} : back.error().message));
    REQUIRE(back.has_value());
    REQUIRE(std::equal(plaintext.begin(), plaintext.end(), back->data()));

    auto oldest = codec.oldest_kek_version_in_use(conn.get());
    REQUIRE(oldest.has_value());
    REQUIRE(*oldest == 2);
}

TEST_CASE("SecretCodec: lifecycle edges — unknown retire, multi-column laggard, zero-row column",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    create_test_table(conn.get());
    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));

    SECTION("retire of a never-registered version is refused") {
        REQUIRE_FALSE(codec.retire_kek(conn.get(), 99).has_value());
        REQUIRE_FALSE(codec.retire_kek(conn.get(), 1).has_value()); // active
    }

    SECTION("zero-row registered column: oldest is nullopt, rewrap_all is a no-op") {
        auto oldest = codec.oldest_kek_version_in_use(conn.get());
        REQUIRE(oldest.has_value());
        REQUIRE_FALSE(oldest->has_value());
        auto rewrapped = codec.rewrap_all(conn.get());
        REQUIRE(rewrapped.has_value());
        REQUIRE(*rewrapped == 0);
    }

    SECTION("oldest_kek_version_in_use reflects the laggard across columns; "
            "late registration is honored") {
        PgResult table{PQexec(conn.get(), "CREATE TABLE tstore.other ("
                                          "  id     BIGINT PRIMARY KEY,"
                                          "  secret BYTEA"
                                          ")")};
        REQUIRE(table.ok());

        auto blob_a = codec.encrypt(test_id(1), bytes_of("alpha"));
        REQUIRE(blob_a.has_value());
        upsert_secret(conn.get(), 1, *blob_a);

        const SecretCodec::SecretId other_id{"tstore", "other", "secret",
                                             SecretCodec::encode_bigint_pk(7)};
        auto blob_b = codec.encrypt(other_id, bytes_of("beta"));
        REQUIRE(blob_b.has_value());
        {
            const char* values[] = {"7", reinterpret_cast<const char*>(blob_b->data())};
            const int lengths[] = {0, static_cast<int>(blob_b->size())};
            const int formats[] = {0, 1};
            PgResult ins{PQexecParams(conn.get(),
                                      "INSERT INTO tstore.other (id, secret)"
                                      " VALUES ($1::bigint, $2)",
                                      2, nullptr, values, lengths, formats, 0)};
            REQUIRE(ins.ok());
        }

        // Rotate with only the first column registered: tstore.other is a
        // laggard the codec cannot see yet.
        auto rotated = codec.rotate_kek(conn.get());
        REQUIRE(rotated.has_value());
        // Register late; the next scans must include it.
        REQUIRE(codec.register_secret_column({"tstore", "other", "secret", "id"}));

        auto oldest = codec.oldest_kek_version_in_use(conn.get());
        REQUIRE(oldest.has_value());
        REQUIRE(**oldest == 1); // the laggard pins the minimum

        REQUIRE_FALSE(codec.retire_kek(conn.get(), 1).has_value()); // still referenced

        auto rewrapped = codec.rewrap_all(conn.get());
        REQUIRE(rewrapped.has_value());
        REQUIRE(*rewrapped == 1); // exactly the laggard row

        oldest = codec.oldest_kek_version_in_use(conn.get());
        REQUIRE(oldest.has_value());
        REQUIRE(**oldest == 2);
        REQUIRE(codec.retire_kek(conn.get(), 1).has_value());
    }
}

TEST_CASE("SecretCodec: audit detail structure and failure-counter classes", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());

    std::vector<std::pair<std::string, std::string>> audit; // verb, detail_json
    codec.set_audit_hook([&](std::string_view verb, const std::string& detail) {
        audit.emplace_back(std::string{verb}, detail);
    });
    REQUIRE(codec.init(conn.get()).has_value());
    create_test_table(conn.get());
    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));

    // kek.generated carries the version (structured assert, not substring).
    REQUIRE(audit.size() == 1);
    REQUIRE(audit[0].first == "kek.generated");
    REQUIRE(nlohmann::json::parse(audit[0].second).at("kek_version").get<int>() == 1);

    const auto id = test_id();
    auto blob = codec.encrypt(id, bytes_of("x"));
    REQUIRE(blob.has_value());

    // Unknown kek_version: counted under kek_unresolvable, audited with the
    // identity tuple — and never the ciphertext.
    auto tampered = *blob;
    set_blob_kek_version(tampered, 99);
    REQUIRE_FALSE(codec.decrypt(id, tampered).has_value());

    REQUIRE(audit.size() == 2);
    REQUIRE(audit[1].first == "secret.decrypt_failure");
    const auto detail = nlohmann::json::parse(audit[1].second);
    REQUIRE(detail.at("store").get<std::string>() == "tstore");
    REQUIRE(detail.at("table").get<std::string>() == "things");
    REQUIRE(detail.at("column").get<std::string>() == "secret");
    REQUIRE(detail.at("kek_version").get<int>() == 99);
    REQUIRE(detail.at("failure_class").get<std::string>() == "kek_unresolvable");

    bool unresolvable_counted = false;
    for (const auto& [key, n] : codec.decrypt_failure_counts())
        if (key.first == "tstore" &&
            key.second == SecretCodec::FailureClass::kek_unresolvable && n == 1)
            unresolvable_counted = true;
    REQUIRE(unresolvable_counted);

    // Encrypt-side failures must NOT ride the decrypt-failure taxonomy: an
    // encrypt with no active KEK (fresh codec, init never run) errors but
    // emits no audit event and bumps no counter.
    SecretCodec uninitialized(provider);
    std::size_t hook_calls = 0;
    uninitialized.set_audit_hook(
        [&](std::string_view, const std::string&) { ++hook_calls; });
    REQUIRE_FALSE(uninitialized.encrypt(id, bytes_of("y")).has_value());
    REQUIRE(hook_calls == 0);
    REQUIRE(uninitialized.decrypt_failure_counts().empty());
}

// ── ADR-0010 §Decision 3 metric exposition ─────────────────────────────────
//
// server.cpp exports decrypt_failure_counts() at scrape time as
// `yuzu_server_secret_decrypt_failures_total{store,failure_class}`. That
// export carries a subtlety worth pinning: the value lives in the GAUGE
// family (it is a `set()` of a total the codec owns, not an increment), so
// without an explicit `describe(..., "counter")` the scrape would emit
// `# TYPE ... gauge` under a `_total` name — a silent violation of
// docs/observability-conventions.md that a reader of server.cpp cannot see.
// This asserts the exposition, so a future edit that drops the describe or
// switches families is caught here rather than in a Grafana query.
TEST_CASE("SecretCodec decrypt-failure counts export as a Prometheus counter", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    create_test_table(conn.get());
    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));

    const auto id = test_id();
    auto blob = codec.encrypt(id, bytes_of("x"));
    REQUIRE(blob.has_value());
    auto tampered = *blob;
    set_blob_kek_version(tampered, 99);
    REQUIRE_FALSE(codec.decrypt(id, tampered).has_value());

    // Mirror server.cpp's describe + scrape-time export exactly.
    yuzu::MetricsRegistry metrics;
    metrics.describe("yuzu_server_secret_decrypt_failures_total",
                     "Envelope-encrypted secret decrypt failures by store and failure class "
                     "(tamper, unresolvable KEK, malformed blob)",
                     "counter");
    for (const auto& [key, count] : codec.decrypt_failure_counts()) {
        const auto& [store, cls] = key;
        metrics
            .gauge("yuzu_server_secret_decrypt_failures_total",
                   {{"store", store}, {"failure_class", std::string(SecretCodec::to_string(cls))}})
            .set(static_cast<double>(count));
    }

    const std::string out = metrics.serialize();
    INFO(out);
    // Declared type wins over the gauge family's default.
    CHECK(out.find("# TYPE yuzu_server_secret_decrypt_failures_total counter") !=
          std::string::npos);
    CHECK(out.find("# TYPE yuzu_server_secret_decrypt_failures_total gauge") == std::string::npos);
    // The labelled sample the yuzu-secrets alert rules match on.
    CHECK(out.find(R"(store="tstore")") != std::string::npos);
    CHECK(out.find(R"(failure_class="kek_unresolvable")") != std::string::npos);
}

TEST_CASE("SecretCodec init: orphaned kek_version (deleted registration) fails closed",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    PgConn conn = connect(db.dsn());

    // Boot, register the column, encrypt + store a v1 blob.
    {
        SecretCodec codec(provider);
        REQUIRE(codec.init(conn.get()).has_value());
        create_test_table(conn.get());
        REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));
        auto blob = codec.encrypt(test_id(42), bytes_of("totp-seed"));
        REQUIRE(blob.has_value());
        upsert_secret(conn.get(), 42, *blob);
    }

    // Simulate a deleted registration (operator error or a targeted SQL-write
    // attack): wipe kek_meta. The stored blob still references v1. A fresh boot
    // must NOT treat this as first-boot and silently mint a new KEK (which
    // would permanently orphan the row) — it must fail closed (S6).
    REQUIRE(PgResult{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")}.ok());

    SecretCodec codec2(provider);
    REQUIRE(codec2.register_secret_column({"tstore", "things", "secret", "id"}));
    auto r = codec2.init(conn.get());
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error().kind == SecretCodec::InitError::Kind::kek_orphaned);
    REQUIRE(codec2.active_kek_version() == 0); // no fresh KEK was minted
}

TEST_CASE("SecretCodec init: unsupported pk_column type fails closed", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    PgConn conn = connect(db.dsn());

    PgResult schema{PQexec(conn.get(), "CREATE SCHEMA IF NOT EXISTS tstore")};
    REQUIRE(schema.ok());
    // INTEGER (int4) pk: its 4-byte binary width differs from the canonical
    // 8-byte-BE AAD encoding, so rotation would brick with a spurious
    // tag_mismatch. init() must reject it up front (the int4/SERIAL footgun).
    PgResult table{PQexec(conn.get(), "CREATE TABLE tstore.intpk ("
                                      "  id     INTEGER PRIMARY KEY,"
                                      "  secret BYTEA"
                                      ")")};
    REQUIRE(table.ok());

    SecretCodec codec(provider);
    REQUIRE(codec.register_secret_column({"tstore", "intpk", "secret", "id"}));
    auto r = codec.init(conn.get());
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error().kind == SecretCodec::InitError::Kind::unsupported_pk_type);
}

TEST_CASE("SecretCodec: retire with failed key deletion records no false destruction",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider file_provider(keys.path);
    FailingDeleteProvider provider(file_provider); // delete_kek always fails
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    create_test_table(conn.get());
    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));

    std::vector<std::string> audit_verbs;
    codec.set_audit_hook(
        [&](std::string_view verb, const std::string&) { audit_verbs.emplace_back(verb); });

    // Store a v1 blob, rotate to v2, rewrap it so v1 has zero references.
    auto blob = codec.encrypt(test_id(42), bytes_of("seed"));
    REQUIRE(blob.has_value());
    upsert_secret(conn.get(), 42, *blob);
    REQUIRE(codec.rotate_kek(conn.get()).has_value()); // rewraps the row to v2
    REQUIRE(codec.oldest_kek_version_in_use(conn.get()).value().value() == 2);

    // retire v1: the metadata UPDATE succeeds but delete_kek fails → retire
    // must return an error and NOT emit kek.retired (no false destruction
    // evidence — S3).
    auto r = codec.retire_kek(conn.get(), 1);
    REQUIRE_FALSE(r.has_value());
    REQUIRE(std::count(audit_verbs.begin(), audit_verbs.end(), "kek.retired") == 0);

    // retired_at IS recorded (crash-safe: the version is excluded from boot
    // verification, so the orphaned key file is harmless until removed).
    PgResult meta{PQexec(conn.get(), "SELECT count(*) FROM secrets.kek_meta"
                                     " WHERE kek_version = 1 AND retired_at IS NOT NULL")};
    REQUIRE(meta.status() == PGRES_TUPLES_OK);
    REQUIRE(std::string{PQgetvalue(meta.get(), 0, 0)} == "1");
}

// TODO(S10): a true concurrent-CAS race test — spawn a thread doing
// encrypt()+upsert against a row while rewrap_all() runs, asserting
// cas_skipped > 0 and the row ends on the concurrently-written value. Deferred:
// needs a deterministic interleave harness to avoid flakiness on the shared
// PG test instance. The idempotent-resume path is covered above.
// TODO(S11): exercise the GcmResult::error → FailureClass::crypto_failure
// decrypt path; needs an OpenSSL/EVP fault-injection seam (not yet available).

// #2395 track D: the KEK rotation REST/MCP seam's HalfCommitted detection
// (server.cpp kek_ops.rotate) compares active_kek_version() before vs. after
// one rotate_kek() call and classifies `after > before` as HalfCommitted vs.
// Internal. That heuristic is only trustworthy if a single successful
// rotate_kek() call ALWAYS advances the active version by exactly one — never
// zero (a caller could then misdiagnose a successful rotate as a failure) and
// never more than one (a caller could then miss an intermediate version and
// under-count how far rotation actually progressed). No existing case called
// rotate_kek() more than once in a row to pin this.
TEST_CASE("SecretCodec: active_kek_version() advances by exactly one per successful "
          "rotate_kek call (the REST/MCP seam's half-committed detection depends on this)",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    create_test_table(conn.get());
    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));

    upsert_secret(conn.get(), 42, *codec.encrypt(test_id(42), bytes_of("seed")));
    REQUIRE(codec.active_kek_version() == 1);

    for (std::uint32_t expected = 2; expected <= 4; ++expected) {
        const std::uint32_t before = codec.active_kek_version();
        auto rotated = codec.rotate_kek(conn.get());
        INFO((rotated ? std::string{} : rotated.error().internal_message));
        REQUIRE(rotated.has_value());
        const std::uint32_t after = codec.active_kek_version();
        REQUIRE(*rotated == expected);
        REQUIRE(after == expected);
        REQUIRE(after == before + 1); // exactly one, never zero, never more than one
    }

    // Every row landed on the final version — rotate_kek's internal
    // rewrap_all() left nothing on a superseded version after any of the
    // three rotations above.
    auto oldest = codec.oldest_kek_version_in_use(conn.get());
    REQUIRE(oldest.has_value());
    REQUIRE(*oldest == 4);
}

// #2530 A4: live_kek_version_count() counts only non-retired kek_meta rows.
TEST_CASE("SecretCodec: live_kek_version_count reflects retirement", "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    create_test_table(conn.get());
    REQUIRE(codec.register_secret_column({"tstore", "things", "secret", "id"}));

    auto count1 = codec.live_kek_version_count(conn.get());
    REQUIRE(count1.has_value());
    REQUIRE(*count1 == 1);

    REQUIRE(codec.rotate_kek(conn.get()).has_value()); // mints v2, both live
    auto count2 = codec.live_kek_version_count(conn.get());
    REQUIRE(count2.has_value());
    REQUIRE(*count2 == 2);

    REQUIRE(codec.retire_kek(conn.get(), 1).has_value()); // v1 now retired
    auto count3 = codec.live_kek_version_count(conn.get());
    REQUIRE(count3.has_value());
    REQUIRE(*count3 == 1);
}

// #2530 A5: rotate_clock() — no rows, then a fresh row, then a future-dated
// (clock-anomalous) row, each read via the single two-timestamp statement.
TEST_CASE("SecretCodec: rotate_clock reports any_rows=false against an empty kek_meta",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    // init() deliberately NOT run: the pre-migrated template's kek_meta is
    // empty (secrets_tpl resets it), so the `secrets` schema exists but no
    // row does — exactly the any_rows=false case.
    auto clock = codec.rotate_clock(conn.get());
    REQUIRE(clock.has_value());
    REQUIRE_FALSE(clock->any_rows);
    REQUIRE_FALSE(clock->clock_anomaly);
}

TEST_CASE("SecretCodec: rotate_clock reports a small age and no anomaly for a fresh row",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value()); // mints v1 with created_at = now()

    auto clock = codec.rotate_clock(conn.get());
    REQUIRE(clock.has_value());
    REQUIRE(clock->any_rows);
    REQUIRE_FALSE(clock->clock_anomaly);
    REQUIRE(clock->since_newest < std::chrono::minutes{1});
}

TEST_CASE("SecretCodec: rotate_clock flags a future-dated newest row as a clock anomaly",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    // Construct the anomaly directly: the newest kek_meta row is future-dated.
    PgResult upd{PQexec(conn.get(), "UPDATE secrets.kek_meta SET created_at = now() + "
                                    "interval '1 hour' WHERE kek_version = 1")};
    REQUIRE(upd.ok());

    auto clock = codec.rotate_clock(conn.get());
    REQUIRE(clock.has_value());
    REQUIRE(clock->any_rows);
    REQUIRE(clock->clock_anomaly);
    // #2530 G7-B6: the skew MAGNITUDE must be captured, not just the
    // boolean fact of the anomaly — this is what lets an operator tell "a
    // few seconds of jitter" from "dated a year out". Allow a few seconds
    // of slack for the time elapsed between the UPDATE above and this read.
    REQUIRE(clock->future_skew_secs > 3590);
    REQUIRE(clock->future_skew_secs <= 3600);
}

// #2530 A1: SQLSTATE 57014 (query canceled — including a genuine
// pg_cancel_backend, not just a statement_timeout) maps to
// LifecycleError::Kind::query_canceled, and the raw SQLSTATE never leaves
// the codec (only the Kind discriminant does). Constructed deterministically
// via a real PQcancel against a query that is genuinely blocked (an ACCESS
// EXCLUSIVE lock held by a second connection) rather than a
// statement_timeout race, which would be flaky on a fast local database.
TEST_CASE("SecretCodec: a canceled query maps to LifecycleError::Kind::query_canceled",
          "[pg][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());

    PgConn blocker = connect(db.dsn());
    REQUIRE(PgResult{PQexec(blocker.get(), "BEGIN")}.ok());
    REQUIRE(PgResult{PQexec(blocker.get(),
                            "LOCK TABLE secrets.kek_meta IN ACCESS EXCLUSIVE MODE")}
                .ok());

    // #2530 G8-S8: capture the backend pid BEFORE acquiring the PGcancel
    // handle, not after. With the pid REQUIRE between PQgetCancel and
    // PQfreeCancel, a failed REQUIRE here (pid <= 0) would throw and unwind
    // past the still-open `cancel` with no PQfreeCancel ever reached —
    // reordering means a failure here never opened a PGcancel to leak.
    const int conn_pid = PQbackendPID(conn.get());
    REQUIRE(conn_pid > 0);
    PGcancel* cancel = PQgetCancel(conn.get());
    REQUIRE(cancel != nullptr);

    // #2530 G8-F1: open the forced-termination fallback connection BEFORE
    // spawning the worker thread below, not inside the "still not done"
    // branch after it. NO REQUIRE/CHECK may run between the jthread's
    // construction and its join() while the worker can still be blocked
    // under `blocker`'s ACCESS EXCLUSIVE lock: this helper's connect()
    // (~L45) itself REQUIREs CONNECTION_OK, and a REQUIRE failing there
    // would throw and start unwinding while the worker is still blocked.
    // `~jthread` would then call `request_stop()` — a no-op, because the
    // worker lambda below takes no `stop_token` — and `join()` would
    // deadlock forever waiting on a worker that can never finish, because
    // `blocker`'s ROLLBACK further down is never reached either. Opening
    // `axe` here, before the worker exists, removes that REQUIRE from the
    // window entirely.
    PgConn axe = connect(db.dsn());

    std::expected<std::size_t, SecretCodec::LifecycleError> result;
    std::atomic<bool> done{false};
    // A plain std::thread plus an explicit join-guard, NOT std::jthread:
    // Apple Clang's libc++ does not provide std::jthread, so the jthread
    // form compiles on GCC/MSVC and breaks the macOS leg (caught by CI on
    // #2580 — local Linux success proves nothing about this). The guard
    // gives the same guarantee jthread was chosen for: ~thread on a still
    // joinable thread calls std::terminate, killing the whole shard with no
    // diagnostic, and the FAIL() below throws. Belt-and-braces alongside
    // keeping every REQUIRE/CHECK outside the construction-to-join window.
    std::thread worker([&] {
        result = codec.live_kek_version_count(conn.get());
        done.store(true, std::memory_order_release);
    });
    struct JoinGuard {
        std::thread& t;
        ~JoinGuard() {
            if (t.joinable())
                t.join();
        }
    } join_guard{worker};

    bool sent_cancel = false;
    for (int attempt = 0; attempt < 100 && !done.load(std::memory_order_acquire); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
        std::array<char, 256> errbuf{};
        if (PQcancel(cancel, errbuf.data(), static_cast<int>(errbuf.size())) == 1)
            sent_cancel = true;
    }
    PQfreeCancel(cancel);

    // #2530 G7-B5: bound the wait so a cancellation that never lands fails
    // this test fast with a clear message instead of hanging until the CI
    // job's outer timeout kills it with none. The loop above already gives
    // PQcancel ~2s of retries; if the worker still has not observed
    // completion, force it: sever `conn` from the pre-opened `axe`
    // connection (mirrors test_kek_op_lock_holder.cpp's severing idiom) so
    // the blocked query is guaranteed to error out one way or another. No
    // connect() call here — `axe` already exists (see above).
    if (!done.load(std::memory_order_acquire)) {
        const std::string kill =
            "SELECT pg_terminate_backend(" + std::to_string(conn_pid) + ")";
        (void)PgResult{PQexec(axe.get(), kill.c_str())};
        for (int i = 0; i < 100 && !done.load(std::memory_order_acquire); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }

    // Release the blocker's lock regardless of outcome — never leave a table
    // lock held past this test, even if the worker never landed.
    (void)PgResult{PQexec(blocker.get(), "ROLLBACK")};

    // #2530 G8-S9: gate on `done` BEFORE join(), not only after. join()
    // only returns once the worker has already stored `done=true` as its
    // last act, so a REQUIRE(done) placed after an unconditional join() is
    // vacuously true — it can never observe a cancellation/termination that
    // failed to land, because the test would already be hung at join()
    // instead of reaching that REQUIRE. FAIL loudly here instead, with the
    // pid so a real wedge is diagnosable, before letting the join-guard's
    // join() potentially block the rest of the shard.
    if (!done.load(std::memory_order_acquire)) {
        FAIL("worker did not observe cancellation or forced termination within "
             "the bound (backend pid " +
             std::to_string(conn_pid) + "); the connection is presumed wedged");
    }
    worker.join();

    REQUIRE(sent_cancel);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().kind == SecretCodec::LifecycleError::Kind::query_canceled);
}

#endif // YUZU_TEST_ENABLE_PG

// ── The KEK-operation advisory lock (#2395, gov cpp-safety BLOCKING) ────────
//
// This is the highest-consequence resource in the KEK surface and had ZERO
// coverage: the REST/MCP tests stub the seam entirely, so nothing ever took a
// real lease or ran the guard's destructor. A leaked session-scoped advisory
// lock wedges every future KEK operation cluster-wide, and because session
// locks are RE-ENTRANT per backend the wedge is asymmetric — the connection
// that leaked it keeps working while every other one 409s. These tests use two
// REAL connections so the mutual exclusion and the release are both observed.

TEST_CASE("KEK op lock: mutual exclusion across two connections, released by the guard",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    PgConn a = connect(db.dsn());
    PgConn b = connect(db.dsn());

    using yuzu::server::detail::KekOpLockAttempt;
    using yuzu::server::detail::KekOpLockGuard;
    using yuzu::server::detail::try_lock_kek_op;

    {
        REQUIRE(try_lock_kek_op(a.get()) == KekOpLockAttempt::kAcquired);
        KekOpLockGuard guard_a{a.get()};

        // A different SESSION must be excluded — this is the whole point of
        // using a session advisory lock rather than a per-process mutex.
        CHECK(try_lock_kek_op(b.get()) == KekOpLockAttempt::kConflict);
    } // guard_a releases here

    // Once released, the other connection can take it.
    REQUIRE(try_lock_kek_op(b.get()) == KekOpLockAttempt::kAcquired);
    KekOpLockGuard guard_b{b.get()};
    CHECK(try_lock_kek_op(a.get()) == KekOpLockAttempt::kConflict);
}

TEST_CASE("KEK op lock: the guard leaves nothing held on the connection it released",
          "[pg][secrets][kek]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    PgConn a = connect(db.dsn());
    PgConn observer = connect(db.dsn());

    using yuzu::server::detail::KekOpLockAttempt;
    using yuzu::server::detail::KekOpLockGuard;
    using yuzu::server::detail::try_lock_kek_op;

    {
        REQUIRE(try_lock_kek_op(a.get()) == KekOpLockAttempt::kAcquired);
        KekOpLockGuard guard{a.get()};
    }

    // Nothing left behind in pg_locks for this key. Checked from a THIRD
    // session so a re-entrant re-acquire on `a` cannot mask a leak — that
    // masking is exactly the UP-1 failure mode.
    //
    // #2530 H3 (Hermes round 2): `pg_locks` is CLUSTER-WIDE, and the 4 server
    // test shards share one Postgres container — an unfiltered count here
    // could observe a SIBLING SHARD's still-held `secrets_kek_op` lock in
    // its own (different) database and flake this assertion, or worse, mask
    // a real leak on THIS database behind a nonzero count that actually came
    // from elsewhere. `AND database = current_database()` scopes the read to
    // this test's own ephemeral database, matching kek_op_lock.hpp's
    // production query and test_kek_op_lock_holder.cpp's cross-check helper.
    PgResult held{PQexec(observer.get(),
                         "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                         "AND classid = 2037545589 AND database = (SELECT oid FROM "
                         "pg_database WHERE datname = current_database())")};
    REQUIRE(held.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(held.get(), 0, 0)) == "0");

    // And the lock is genuinely free for anyone.
    CHECK(try_lock_kek_op(observer.get()) == KekOpLockAttempt::kAcquired);
    KekOpLockGuard cleanup{observer.get()};
}

// ── Multi-codec rotation (PR1.5c/PR1.6c) ────────────────────────────────────
//
// The server now owns MORE THAN ONE SecretCodec: `auth_secret_codec_` (AuthDB's
// TOTP secrets) and `plugin_config_secret_codec_` (PluginConfigStore's sealed
// values), both enrolled in the live `kek_ops.{rotate,rewrap,status}` surface.
//
// The failure this pins is silent and expensive: `rotate_kek()` MINTS a new KEK
// version, so calling it once per codec would mint N versions and strand each
// codec on a different generation. The production loop therefore mints ONCE (on
// the primary) and brings every other codec onto that same version with
// `init()` (a non-minting resync) followed by `rewrap_all()`, all under a SINGLE
// `secrets_kek_op` lock hold. This test reproduces that sequence at the
// SecretCodec level and asserts the properties that make it correct.
TEST_CASE("SecretCodec: a second codec joins a rotation without minting a second KEK",
          "[pg][secrets][multicodec]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    PgConn conn = connect(db.dsn());
    create_test_table(conn.get());

    // A second store/table standing in for the second consumer.
    REQUIRE(PgResult{PQexec(conn.get(), "CREATE SCHEMA IF NOT EXISTS tstore2")}.ok());
    REQUIRE(PgResult{PQexec(conn.get(), "CREATE TABLE IF NOT EXISTS tstore2.things ("
                                        "  id     BIGINT PRIMARY KEY,"
                                        "  secret BYTEA)")}
                .ok());
    auto upsert2 = [&](std::int64_t pk, std::span<const std::uint8_t> blob) {
        const std::string pk_str = std::to_string(pk);
        const char* values[] = {pk_str.c_str(), reinterpret_cast<const char*>(blob.data())};
        const int lengths[] = {0, static_cast<int>(blob.size())};
        const int formats[] = {0, 1};
        REQUIRE(PgResult{PQexecParams(conn.get(),
                                      "INSERT INTO tstore2.things (id, secret)"
                                      " VALUES ($1::bigint, $2)"
                                      " ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret",
                                      2, nullptr, values, lengths, formats, 0)}
                    .ok());
    };
    auto fetch2 = [&](std::int64_t pk) {
        const std::string pk_str = std::to_string(pk);
        const char* values[] = {pk_str.c_str()};
        PgResult res{PQexecParams(conn.get(),
                                  "SELECT secret FROM tstore2.things WHERE id = $1::bigint", 1,
                                  nullptr, values, nullptr, nullptr, 1)};
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(res.get()) == 1);
        const auto* p = reinterpret_cast<const std::uint8_t*>(PQgetvalue(res.get(), 0, 0));
        return std::vector<std::uint8_t>{p, p + PQgetlength(res.get(), 0, 0)};
    };

    const SecretCodec::SecretId id_a = test_id(1);
    const SecretCodec::SecretId id_b{"tstore2", "things", "secret",
                                     SecretCodec::encode_bigint_pk(1)};

    // Both codecs boot against the same database and land on v1.
    SecretCodec codec_a(provider);
    REQUIRE(codec_a.register_secret_column({"tstore", "things", "secret", "id"}));
    REQUIRE(codec_a.init(conn.get()).has_value());

    SecretCodec codec_b(provider);
    REQUIRE(codec_b.register_secret_column({"tstore2", "things", "secret", "id"}));
    REQUIRE(codec_b.init(conn.get()).has_value());

    REQUIRE(codec_a.active_kek_version() == 1);
    REQUIRE(codec_b.active_kek_version() == 1);

    const auto plain_a = bytes_of("auth-totp-seed");
    const auto plain_b = bytes_of("plugin-config-sealed-value");
    auto blob_a = codec_a.encrypt(id_a, plain_a);
    auto blob_b = codec_b.encrypt(id_b, plain_b);
    REQUIRE(blob_a.has_value());
    REQUIRE(blob_b.has_value());
    upsert_secret(conn.get(), 1, *blob_a);
    upsert2(1, *blob_b);
    REQUIRE(blob_kek_version(*blob_a) == 1);
    REQUIRE(blob_kek_version(*blob_b) == 1);

    auto live_versions = [&] {
        PgResult res{PQexec(conn.get(), "SELECT count(*) FROM secrets.kek_meta"
                                        " WHERE retired_at IS NULL")};
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        return std::string{PQgetvalue(res.get(), 0, 0)};
    };
    REQUIRE(live_versions() == "1");

    // THE PRODUCTION SEQUENCE: mint once on A...
    auto rotated = codec_a.rotate_kek(conn.get());
    INFO((rotated ? std::string{} : rotated.error().internal_message));
    REQUIRE(rotated.has_value());
    REQUIRE(*rotated == 2);

    // ...then bring B onto that SAME version — init() resyncs without minting.
    REQUIRE(codec_b.init(conn.get()).has_value());
    REQUIRE(codec_b.active_kek_version() == 2);
    REQUIRE(codec_b.rewrap_all(conn.get()).has_value());

    // EXACTLY ONE new version exists. If the loop had called rotate_kek() per
    // codec this would be 3, and the two codecs would sit on 2 and 3.
    REQUIRE(live_versions() == "2");
    REQUIRE(codec_a.active_kek_version() == codec_b.active_kek_version());

    // Both codecs' stored rows moved onto v2, and both still decrypt.
    REQUIRE(blob_kek_version(fetch_secret(conn.get(), 1)) == 2);
    REQUIRE(blob_kek_version(fetch2(1)) == 2);

    auto back_a = codec_a.decrypt(id_a, fetch_secret(conn.get(), 1));
    REQUIRE(back_a.has_value());
    REQUIRE(back_a->size() == plain_a.size());
    REQUIRE(std::equal(plain_a.begin(), plain_a.end(), back_a->data()));

    auto back_b = codec_b.decrypt(id_b, fetch2(1));
    REQUIRE(back_b.has_value());
    REQUIRE(back_b->size() == plain_b.size());
    REQUIRE(std::equal(plain_b.begin(), plain_b.end(), back_b->data()));

    // A codec is NEVER responsible for a sibling's columns: A's rewrap scan
    // must not have touched tstore2, and vice versa. Proven by registration
    // being per-instance — a cross-registration would be a duplicate.
    REQUIRE(codec_a.registered_columns().size() == 1);
    REQUIRE(codec_b.registered_columns().size() == 1);
}

// #2395/M7 (Codex review): the other half of the story above — the window
// server.cpp's kek_ops.rotate route classifies HalfCommitted, BEFORE the
// secondary-codec loop's init()+rewrap_all() step has run for a given
// codec. codec_b's own registered rows must stay decryptable through
// codec_b right through that window: proof the two codecs are genuinely
// INDEPENDENT SecretCodec instances (one's rotate can leave a sibling
// stale, but never corrupt or block it), not accidentally-correct because
// nothing ever exercised the gap. Deliberately light — this pins the
// independence property, not a full HalfCommitted state machine (that
// belongs to server.cpp's kek_ops.rotate, out of scope here).
TEST_CASE("SecretCodec: a not-yet-resynced codec's rows stay decryptable through a "
          "sibling's mint-only rotate",
          "[pg][secrets][multicodec]") {
    YUZU_REQUIRE_PG_DB_TPL(db, secrets_tpl);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    PgConn conn = connect(db.dsn());
    create_test_table(conn.get());

    REQUIRE(PgResult{PQexec(conn.get(), "CREATE SCHEMA IF NOT EXISTS tstore2")}.ok());
    REQUIRE(PgResult{PQexec(conn.get(), "CREATE TABLE IF NOT EXISTS tstore2.things ("
                                        "  id     BIGINT PRIMARY KEY,"
                                        "  secret BYTEA)")}
                .ok());
    auto upsert2 = [&](std::int64_t pk, std::span<const std::uint8_t> blob) {
        const std::string pk_str = std::to_string(pk);
        const char* values[] = {pk_str.c_str(), reinterpret_cast<const char*>(blob.data())};
        const int lengths[] = {0, static_cast<int>(blob.size())};
        const int formats[] = {0, 1};
        REQUIRE(PgResult{PQexecParams(conn.get(),
                                      "INSERT INTO tstore2.things (id, secret)"
                                      " VALUES ($1::bigint, $2)"
                                      " ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret",
                                      2, nullptr, values, lengths, formats, 0)}
                    .ok());
    };
    auto fetch2 = [&](std::int64_t pk) {
        const std::string pk_str = std::to_string(pk);
        const char* values[] = {pk_str.c_str()};
        PgResult res{PQexecParams(conn.get(),
                                  "SELECT secret FROM tstore2.things WHERE id = $1::bigint", 1,
                                  nullptr, values, nullptr, nullptr, 1)};
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(res.get()) == 1);
        const auto* p = reinterpret_cast<const std::uint8_t*>(PQgetvalue(res.get(), 0, 0));
        return std::vector<std::uint8_t>{p, p + PQgetlength(res.get(), 0, 0)};
    };

    const SecretCodec::SecretId id_a = test_id(1);
    const SecretCodec::SecretId id_b{"tstore2", "things", "secret",
                                     SecretCodec::encode_bigint_pk(1)};

    // Both codecs boot against the same database and land on v1 — mirrors
    // the multi-codec test above.
    SecretCodec codec_a(provider);
    REQUIRE(codec_a.register_secret_column({"tstore", "things", "secret", "id"}));
    REQUIRE(codec_a.init(conn.get()).has_value());

    SecretCodec codec_b(provider);
    REQUIRE(codec_b.register_secret_column({"tstore2", "things", "secret", "id"}));
    REQUIRE(codec_b.init(conn.get()).has_value());

    const auto plain_b = bytes_of("plugin-config-sealed-value-still-v1");
    auto blob_b = codec_b.encrypt(id_b, plain_b);
    REQUIRE(blob_b.has_value());
    upsert2(1, *blob_b);
    REQUIRE(blob_kek_version(*blob_b) == 1);

    // codec_a rotates ALONE — the exact "mint on the primary" step
    // (server.cpp kek_ops.rotate) that runs BEFORE the secondary-codec
    // loop calls codec_b->init()/rewrap_all(). Stop right here, as if that
    // loop's step for codec_b had not run yet (or had failed) — the
    // HalfCommitted window.
    auto rotated = codec_a.rotate_kek(conn.get());
    REQUIRE(rotated.has_value());
    REQUIRE(*rotated == 2);
    REQUIRE(codec_a.active_kek_version() == 2);

    // codec_b's in-memory state is stale (nobody has told it about v2 yet)...
    REQUIRE(codec_b.active_kek_version() == 1);
    // ...but its own stored row is untouched — still v1, and still
    // decrypts cleanly through codec_b. codec_a's rotate neither corrupted
    // nor blocked it; the two codecs are genuinely independent, not merely
    // accidentally uninvolved with each other.
    const auto still_v1_blob = fetch2(1);
    REQUIRE(blob_kek_version(still_v1_blob) == 1);
    auto back_b = codec_b.decrypt(id_b, still_v1_blob);
    INFO((back_b ? std::string{} : back_b.error().message));
    REQUIRE(back_b.has_value());
    REQUIRE(back_b->size() == plain_b.size());
    REQUIRE(std::equal(plain_b.begin(), plain_b.end(), back_b->data()));

    // The production resume path (POST /secrets/kek/rewrap): catching up
    // now brings codec_b onto v2 and its row still decrypts afterward.
    REQUIRE(codec_b.init(conn.get()).has_value());
    REQUIRE(codec_b.active_kek_version() == 2);
    REQUIRE(codec_b.rewrap_all(conn.get()).has_value());
    const auto v2_blob = fetch2(1);
    REQUIRE(blob_kek_version(v2_blob) == 2);
    auto back_b2 = codec_b.decrypt(id_b, v2_blob);
    REQUIRE(back_b2.has_value());
    REQUIRE(std::equal(plain_b.begin(), plain_b.end(), back_b2->data()));
}
