/**
 * test_instruction_store_signing.cpp — #1073 / W7.4 sibling-gap closure.
 *
 * Migrated-to-Postgres store (ADR-0058, ADR-0012 §1 authoritative/fail-hard). PG-gated: skips
 * when YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Uses the pre-migrated PgTestTemplate variant (docs/postgres-store-playbook.md
 * step 7) — these tests only exercise the signature gate, not migration/construction itself.
 *
 * Covers the Ed25519 signature gate on `InstructionStore::import_definition_json` — unchanged in
 * intent and behaviour by the Postgres migration (the gate is pure/storage-independent,
 * `ProductPackStore::verify_signature`); only the store harness changed:
 *
 *   - Signed import with valid signature is ACCEPTED (positive crypto proof).
 *   - Signed import with TAMPERED yaml_source is REJECTED.
 *   - Signed import with WRONG public key is REJECTED.
 *   - Signed import without yaml_source is REJECTED (no signed content).
 *   - Incomplete signing metadata (signature without publicKey, or vice
 *     versa) is REJECTED.
 *   - Unsigned import is REJECTED when require_signed_definitions=true
 *     (the new default).
 *   - Unsigned import is ACCEPTED when require_signed_definitions=false
 *     (the operator opt-out path).
 *   - `import_definition_json_trusted` bypasses the gate (mirrors the
 *     boot-content seed path in server.cpp).
 *   - `set_require_signed_definitions` is idempotent and round-trips.
 *
 * Crypto pattern (Ed25519 keypair + sign-hex helper) is lifted from
 * test_product_pack_store.cpp so a regression that breaks
 * ProductPackStore::verify_signature for the InstructionDefinition wire
 * format is caught by both test suites.
 */

#include "instruction_store.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <memory>
#include <string>
#include <string_view>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate instruction_store_signing_tpl{
    "instrstoresign", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("instruction_store_signing template: store failed to "
                                     "migrate");
    }};

struct Ed25519Pair {
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> pkey{nullptr, &EVP_PKEY_free};
    std::string public_key_hex; // 64 hex chars
};

Ed25519Pair generate_ed25519() {
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> kctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), &EVP_PKEY_CTX_free);
    REQUIRE(kctx);
    REQUIRE(EVP_PKEY_keygen_init(kctx.get()) == 1);

    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(kctx.get(), &raw) == 1);
    Ed25519Pair p{std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)>(raw, &EVP_PKEY_free), {}};

    unsigned char pub[32];
    std::size_t pub_len = sizeof(pub);
    REQUIRE(EVP_PKEY_get_raw_public_key(p.pkey.get(), pub, &pub_len) == 1);
    REQUIRE(pub_len == 32);
    static constexpr char hex[] = "0123456789abcdef";
    p.public_key_hex.reserve(64);
    for (std::size_t i = 0; i < 32; ++i) {
        p.public_key_hex.push_back(hex[pub[i] >> 4]);
        p.public_key_hex.push_back(hex[pub[i] & 0x0F]);
    }
    return p;
}

std::string sign_hex(EVP_PKEY* pkey, std::string_view content) {
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    REQUIRE(ctx);
    REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey) == 1);
    std::size_t sig_len = 64;
    unsigned char sig[64];
    REQUIRE(EVP_DigestSign(ctx.get(), sig, &sig_len,
                           reinterpret_cast<const unsigned char*>(content.data()),
                           content.size()) == 1);
    REQUIRE(sig_len == 64);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(128);
    for (std::size_t i = 0; i < 64; ++i) {
        out.push_back(hex[sig[i] >> 4]);
        out.push_back(hex[sig[i] & 0x0F]);
    }
    return out;
}

/// Build the JSON envelope an operator would POST to /api/v1/instructions/import.
/// Caller provides yaml_source, signature, publicKey; non-signing fields use
/// sane defaults that pass the rest of the definition parser.
std::string build_envelope(const std::string& id, const std::string& yaml_source,
                           const std::string& signature_hex = "",
                           const std::string& public_key_hex = "") {
    nlohmann::json j;
    j["id"] = id;
    j["name"] = id;
    j["version"] = "1.0";
    j["type"] = "question";
    j["plugin"] = "system_info";
    j["action"] = "os_name";
    j["yaml_source"] = yaml_source;
    if (!signature_hex.empty())
        j["signature"] = signature_hex;
    if (!public_key_hex.empty())
        j["publicKey"] = public_key_hex;
    return j.dump();
}

constexpr const char* kSampleYaml = "---\n"
                                    "apiVersion: yuzu.io/v1alpha1\n"
                                    "kind: InstructionDefinition\n"
                                    "metadata:\n"
                                    "  id: signing.smoke.test\n"
                                    "  displayName: Signing Smoke Test\n";

} // namespace

// ── Positive crypto proof: valid signature is accepted ───────────────────────

TEST_CASE("InstructionStore: signed import with valid signature is accepted",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.require_signed_definitions()); // default

    auto kp = generate_ed25519();
    auto sig = sign_hex(kp.pkey.get(), kSampleYaml);

    auto env = build_envelope("def.signed.ok", kSampleYaml, sig, kp.public_key_hex);
    auto r = store.import_definition_json(env);
    REQUIRE(r.has_value());
    CHECK(!r->empty());

    // The definition is now persisted; yaml_source carried through.
    auto got = store.get_definition(*r);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->yaml_source == kSampleYaml);
}

// ── Negative crypto proofs ───────────────────────────────────────────────────

TEST_CASE("InstructionStore: signed import with tampered yaml_source is rejected",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    auto kp = generate_ed25519();
    // Sign the original yaml...
    auto sig = sign_hex(kp.pkey.get(), kSampleYaml);
    // ...but submit a TAMPERED yaml. Signature no longer matches content.
    std::string tampered_yaml = std::string(kSampleYaml) + "  injected: yes\n";
    auto env = build_envelope("def.tampered", tampered_yaml, sig, kp.public_key_hex);

    auto r = store.import_definition_json(env);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("signature verification failed") != std::string::npos);
}

TEST_CASE("InstructionStore: signed import with wrong public key is rejected",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    auto signer = generate_ed25519();
    auto attacker = generate_ed25519();

    auto sig = sign_hex(signer.pkey.get(), kSampleYaml);
    // Use the attacker's public key to verify the signer's signature — fails.
    auto env = build_envelope("def.wrongkey", kSampleYaml, sig, attacker.public_key_hex);

    auto r = store.import_definition_json(env);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("signature verification failed") != std::string::npos);
}

TEST_CASE("InstructionStore: signature without yaml_source is rejected",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    auto kp = generate_ed25519();
    auto sig = sign_hex(kp.pkey.get(), "");
    // Envelope with signature + publicKey but empty yaml_source — no signed
    // content carrier, so verification is meaningless. Reject explicitly.
    auto env = build_envelope("def.nosignedcontent", "", sig, kp.public_key_hex);

    auto r = store.import_definition_json(env);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("no yaml_source") != std::string::npos);
}

TEST_CASE("InstructionStore: incomplete signing metadata is rejected",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    auto kp = generate_ed25519();
    auto sig = sign_hex(kp.pkey.get(), kSampleYaml);

    SECTION("signature without publicKey") {
        auto env = build_envelope("def.sig.only", kSampleYaml, sig, "");
        auto r = store.import_definition_json(env);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("incomplete signing metadata") != std::string::npos);
    }
    SECTION("publicKey without signature") {
        auto env = build_envelope("def.pub.only", kSampleYaml, "", kp.public_key_hex);
        auto r = store.import_definition_json(env);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("incomplete signing metadata") != std::string::npos);
    }
}

// ── require_signed_definitions gate ─────────────────────────────────────────

TEST_CASE("InstructionStore: unsigned import rejected when signature enforcement is on",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.require_signed_definitions()); // secure default
    auto env = build_envelope("def.unsigned", kSampleYaml);
    auto r = store.import_definition_json(env);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("--allow-unsigned-definitions") != std::string::npos);
}

TEST_CASE("InstructionStore: unsigned import accepted when signature enforcement is off",
          "[instruction_store][1073]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_definitions(false);
    CHECK_FALSE(store.require_signed_definitions());

    auto env = build_envelope("def.unsigned.optout", kSampleYaml);
    auto r = store.import_definition_json(env);
    REQUIRE(r.has_value());
}

TEST_CASE("InstructionStore: opt-out does NOT bypass active-signature verification",
          "[instruction_store][1073][security]") {
    // Confirms `--allow-unsigned-definitions` only widens the unsigned-path
    // policy; a signed import with a BAD signature still fails. Mirrors
    // ProductPackStore's parallel guarantee from #802 governance.
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_definitions(false);

    auto kp = generate_ed25519();
    auto sig = sign_hex(kp.pkey.get(), kSampleYaml);
    std::string tampered = std::string(kSampleYaml) + "  tamper: true\n";
    auto env = build_envelope("def.optout.tampered", tampered, sig, kp.public_key_hex);

    auto r = store.import_definition_json(env);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("signature verification failed") != std::string::npos);
}

// ── Trusted variant (boot-content seed path) ────────────────────────────────

TEST_CASE("InstructionStore: import_definition_json_trusted bypasses signature gate",
          "[instruction_store][1073]") {
    // The bundled-content boot seed in server.cpp uses this variant — the
    // bytes are authenticated by build-time binary linkage, not runtime
    // signature, so the gate must not apply.
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.require_signed_definitions()); // gate is hot

    auto env = build_envelope("def.trusted.unsigned", kSampleYaml);
    auto r = store.import_definition_json_trusted(env);
    REQUIRE(r.has_value());
}

// ── Setter pin: idempotent + round-trip ─────────────────────────────────────

TEST_CASE("InstructionStore: set_require_signed_definitions is idempotent and round-trips",
          "[instruction_store][1073]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_definitions(true);
    CHECK(store.require_signed_definitions());

    store.set_require_signed_definitions(false);
    CHECK_FALSE(store.require_signed_definitions());

    store.set_require_signed_definitions(true);
    CHECK(store.require_signed_definitions());
}

// ── R1 governance R5: wrong-JSON-type fields ─────────────────────────────────

TEST_CASE("InstructionStore: signature field wrong JSON type rejected with typed error",
          "[instruction_store][1073][security]") {
    // {"signature": 42} previously silently fell into the "unsigned" branch
    // because extract_str returned empty for non-strings. Now distinguished
    // as its own error so attacker-corrupted payloads surface the actual
    // type bug instead of a misleading "unsigned" rejection.
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    nlohmann::json j;
    j["id"] = "def.badtype";
    j["name"] = "badtype";
    j["yaml_source"] = kSampleYaml;
    j["signature"] = 42;       // wrong type
    j["publicKey"] = "abcdef"; // any non-empty string
    auto r = store.import_definition_json(j.dump());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("wrong JSON type") != std::string::npos);
}

TEST_CASE("InstructionStore: publicKey field wrong JSON type rejected",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    nlohmann::json j;
    j["id"] = "def.badpub";
    j["name"] = "badpub";
    j["yaml_source"] = kSampleYaml;
    j["signature"] = std::string(128, 'a');            // valid length
    j["publicKey"] = nlohmann::json::array({1, 2, 3}); // wrong type
    auto r = store.import_definition_json(j.dump());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("wrong JSON type") != std::string::npos);
}

TEST_CASE("InstructionStore: null signing field treated as absent (matches existing semantics)",
          "[instruction_store][1073]") {
    // null is semantically "no value present" — distinct from a wrong-type
    // scalar. Falls into the absent branch, then into the unsigned-policy
    // path. Pin the contract so a json-lib bump can't silently flip it.
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_definitions(false);
    // Use the full envelope helper so create_definition's name/type/plugin
    // requirements are satisfied — the test is about NULL signing fields,
    // not about partial envelopes.
    auto env = build_envelope("def.null.sig", kSampleYaml);
    // Round-trip through nlohmann to add null fields without rebuilding.
    auto j = nlohmann::json::parse(env);
    j["signature"] = nullptr;
    j["publicKey"] = nullptr;
    auto r = store.import_definition_json(j.dump());
    REQUIRE(r.has_value()); // accepted as unsigned (enforcement off)
}

// ── R6 governance: hex length validation before allocation ───────────────────

TEST_CASE("InstructionStore: oversized signature_hex rejected before crypto verify",
          "[instruction_store][1073][security]") {
    // Without length-validation an attacker could post a 10 MB signature
    // field and trigger a hex_decode allocation peak inside
    // ProductPackStore::verify_signature. The early length check returns
    // a typed error AND short-circuits the allocation.
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    nlohmann::json j;
    j["id"] = "def.oversize.sig";
    j["name"] = "oversize-sig";
    j["yaml_source"] = kSampleYaml;
    j["signature"] = std::string(10 * 1024 * 1024, 'a'); // 10 MB
    j["publicKey"] = std::string(64, 'a');
    auto r = store.import_definition_json(j.dump());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("signature length invalid") != std::string::npos);
}

TEST_CASE("InstructionStore: oversized publicKey_hex rejected before crypto verify",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    nlohmann::json j;
    j["id"] = "def.oversize.pub";
    j["name"] = "oversize-pub";
    j["yaml_source"] = kSampleYaml;
    j["signature"] = std::string(128, 'a');
    j["publicKey"] = std::string(10 * 1024 * 1024, 'a'); // 10 MB
    auto r = store.import_definition_json(j.dump());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("publicKey length invalid") != std::string::npos);
}

TEST_CASE("InstructionStore: short signature_hex rejected (catches truncation bugs)",
          "[instruction_store][1073][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_signing_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    nlohmann::json j;
    j["id"] = "def.short.sig";
    j["name"] = "short-sig";
    j["yaml_source"] = kSampleYaml;
    j["signature"] = std::string(64, 'a'); // half-length
    j["publicKey"] = std::string(64, 'a');
    auto r = store.import_definition_json(j.dump());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("signature length invalid") != std::string::npos);
}
