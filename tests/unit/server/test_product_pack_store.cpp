/**
 * test_product_pack_store.cpp — `ProductPackStore` (operator-installed product packs,
 * ADR-0006/0009/0054).
 *
 * Migrated-to-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the two fail-closed construction cases use
 * YUZU_REQUIRE_PG_DB / no gate at all, per the plain-migration-test carve-out.
 *
 * Covers:
 *  - fail-closed construction: a live-but-unmigratable database, and an unreachable pool (every
 *    method fails closed with `kProductPackDbErrorPrefix`).
 *  - the pre-migration #802/W7.4 signed-pack coverage, unchanged in intent: default ctor
 *    requires signed packs; the escape hatch (`set_require_signed_packs(false)`) accepts
 *    unsigned packs; a present-but-invalid signature always rejects regardless of the flag; a
 *    signature with no publicKey rejects; the positive Ed25519 crypto path (a real signed pack
 *    installs, a one-byte-mutated signature rejects).
 *  - list/get/uninstall round-trip through the new `std::expected` reads (ADR-0036): `get`'s
 *    nullopt-inside-expected distinguishes "not found" from a genuine DB error; `uninstall`'s
 *    `"not_found: "` prefix.
 *
 * No legacy-SQLite backfill test coverage: the dedicated migrate_from_sqlite TEST_CASE suite
 * was removed as part of a fresh-start-by-default policy change (ADR-0009 amendment) -- no
 * production fleet has ever run a pre-Postgres build. ProductPackStore::migrate_from_sqlite()
 * itself was retired (chore/retire-migrate-from-sqlite-batch-b, #3623).
 */

#include "product_pack_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_route_sink.hpp"
#include "workflow_routes.hpp"

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <openssl/evp.h>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

using yuzu::server::InstallPartialResult;
using yuzu::server::InstructionStore;
using yuzu::server::ItemInstallFn;
using yuzu::server::ProductPack;
using yuzu::server::ProductPackQuery;
using yuzu::server::ProductPackStore;
using yuzu::server::WorkflowRoutes;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate product_pack_store_tpl{
    "productpackstore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        ProductPackStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("product_pack_store template: store failed to migrate");
    }};

/// Minimal valid YAML bundle with no signature — exercises the unsigned-pack branch.
constexpr const char* kUnsignedPackYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-unsigned
version: 1.0.0
description: Bundle without signature for #802 test
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction
)";

/// Three item documents — one intended to succeed, two intended to fail with DISTINCT reasons
/// (#3479). Paired with an install_fn keyed on `name` (see the test), not a fixed stub.
constexpr const char* kThreeItemPartialFailureYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-partial-failure
version: 1.0.0
description: One item succeeds, two fail with distinct reasons
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: item-ok
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: item-bad-a
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: item-bad-b
)";

/// Two InstructionDefinition documents — paired with make_accept_all_install_fn() (which
/// returns the same fixed id for every document), this bundle deterministically produces a
/// duplicate item_id.
constexpr const char* kUnsignedPackYamlDuplicateItems = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-duplicate-items
version: 1.0.0
description: Bundle with two documents assigned the same item id
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction-a
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction-b
)";

/// Two documents of DIFFERENT kind, both intended to resolve (via a test install_fn stub
/// returning a FIXED id regardless of kind) to the SAME item_id — the cross-kind analogue of
/// kUnsignedPackYamlDuplicateItems above (#3481, Gate 8 security-guardian finding: real sibling
/// stores like PolicyStore honor a caller-supplied `id:` field verbatim, so this is reachable
/// with a live PolicyFragment + Policy pair sharing an attacker-chosen id — this fixture proves
/// the mechanism generically with two stub kinds, same as the reverse-order test above does for
/// ordering).
constexpr const char* kUnsignedPackYamlCrossKindDuplicateId = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-cross-kind-duplicate-id
version: 1.0.0
description: Two different-kind documents sharing one item id
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction-cross
---
apiVersion: yuzu.io/v1alpha1
kind: Workflow
name: test-workflow-cross
)";

/// A second, content-distinct bundle — used only to prove idempotency-key reuse with a
/// DIFFERENT body is rejected (F033/#3481). Deliberately unrelated to kUnsignedPackYaml beyond
/// both being minimal valid unsigned bundles.
constexpr const char* kUnsignedPackYamlAlt = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-unsigned-alt
version: 1.0.0
description: A different bundle for the idempotency-key-reuse-with-different-body test
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction-alt
)";

/// install_fn stub — accepts every item, returns a synthetic id. We don't
/// care which items installed downstream because #802 is a pre-item-install
/// reject check; the install_fn here is just to satisfy the signature.
ItemInstallFn make_accept_all_install_fn() {
    return [](const std::string&, const std::string&) -> std::expected<std::string, std::string> {
        return std::string{"item-id"};
    };
}

ItemInstallFn make_counting_install_fn(int* counter) {
    return [counter](const std::string&,
                     const std::string&) -> std::expected<std::string, std::string> {
        ++*counter;
        return std::string{"item-id-"} + std::to_string(*counter);
    };
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("ProductPackStore reports !is_open on a migration failure", "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA product_pack_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE product_pack_store.product_packs (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ProductPackStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("ProductPackStore reports !is_open on an unreachable pool, and every method fails "
          "closed",
          "[product_pack_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    ProductPackStore store{pool};
    CHECK_FALSE(store.is_open());

    auto install_res = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    CHECK_FALSE(install_res.has_value());
    CHECK(install_res.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));

    auto list_res = store.list();
    CHECK_FALSE(list_res.has_value());
    CHECK(list_res.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));

    auto get_res = store.get("x");
    CHECK_FALSE(get_res.has_value());
    CHECK(get_res.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));

    auto uninstall_res = store.uninstall(
        "x", [](const std::string&, const std::string&) -> std::expected<void, std::string> { return {}; });
    CHECK_FALSE(uninstall_res.has_value());
    CHECK(uninstall_res.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
}

// ── #802 / W7.4 signature enforcement ───────────────────────────────────────

TEST_CASE("ProductPackStore: default ctor requires signed packs (#802)",
          "[product_pack_store][issue802][security][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    CHECK(store.require_signed_packs());

    auto result = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE_FALSE(result.has_value());
    // gov W7.4 R1 QE-S1: tighter than substring — pin the full operator-facing
    // suffix via `ends_with`. A regression that drops either piece (or
    // accidentally re-exposes the internal field name "require_signed_packs")
    // fails this test immediately.
    CHECK(result.error().ends_with(
        "is unsigned and signature enforcement is enabled "
        "(set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)"));
}

TEST_CASE("ProductPackStore: opt-out flag accepts unsigned packs (#802 escape hatch)",
          "[product_pack_store][issue802][security][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);
    CHECK_FALSE(store.require_signed_packs());

    auto result = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(result.has_value());
    CHECK_FALSE(result->empty());
}

TEST_CASE("ProductPackStore: set_require_signed_packs is idempotent and round-trips",
          "[product_pack_store][issue802][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.require_signed_packs()); // post-W7.4 default

    store.set_require_signed_packs(false);
    CHECK_FALSE(store.require_signed_packs());

    store.set_require_signed_packs(true);
    CHECK(store.require_signed_packs());

    store.set_require_signed_packs(true); // idempotent
    CHECK(store.require_signed_packs());
}

TEST_CASE("ProductPackStore: pack with malformed/zero public key + signature "
          "rejects regardless of require_signed_packs",
          "[product_pack_store][issue802][security][pg]") {
    constexpr const char* signed_pack_bad_sig = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-bad-sig
version: 1.0.0
description: Bundle with invalid signature
signature: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
publicKey: 0000000000000000000000000000000000000000000000000000000000000000
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: signed-test-instruction
)";

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    // Default (require_signed_packs == true) — rejects.
    auto result_default = store.install(signed_pack_bad_sig, make_accept_all_install_fn());
    REQUIRE_FALSE(result_default.has_value());
    CHECK(result_default.error().find("signature verification failed") != std::string::npos);

    // Even with the escape hatch on, a signature-present-but-invalid pack
    // still rejects — the flag is unsigned-only, not "skip all crypto".
    store.set_require_signed_packs(false);
    auto result_optout = store.install(signed_pack_bad_sig, make_accept_all_install_fn());
    REQUIRE_FALSE(result_optout.has_value());
    CHECK(result_optout.error().find("signature verification failed") != std::string::npos);
}

TEST_CASE("ProductPackStore: pack with signature but no publicKey rejects",
          "[product_pack_store][issue802][security][pg]") {
    constexpr const char* pack_sig_no_pubkey = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-orphan-sig
version: 1.0.0
description: Bundle with signature but missing publicKey
signature: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: orphan-sig-instruction
)";

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.install(pack_sig_no_pubkey, make_accept_all_install_fn());
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("has signature but no publicKey") != std::string::npos);
}

namespace {

/// Generate an Ed25519 keypair via OpenSSL EVP and return raw 32-byte
/// public key + private-key signer suitable for `EVP_DigestSign` over
/// arbitrary content.
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
    std::size_t sig_len = 64; // Ed25519 signature size
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

} // namespace

TEST_CASE("ProductPackStore: correctly signed pack installs (positive crypto path)",
          "[product_pack_store][issue802][security][pg]") {
    auto pair = generate_ed25519();

    // The content that gets signed is the non-ProductPack documents joined
    // with "\n---\n" (product_pack_store.cpp `install()`). Construct the
    // inner doc separately so we know its exact bytes.
    const std::string inner_doc = "apiVersion: yuzu.io/v1alpha1\n"
                                  "kind: InstructionDefinition\n"
                                  "name: signed-positive-test\n";
    const std::string signature_hex = sign_hex(pair.pkey.get(), inner_doc);

    const std::string bundle = "apiVersion: yuzu.io/v1alpha1\n"
                               "kind: ProductPack\n"
                               "name: test-signed-positive\n"
                               "version: 1.0.0\n"
                               "description: Bundle with valid signature\n"
                               "signature: " +
                               signature_hex +
                               "\n"
                               "publicKey: " +
                               pair.public_key_hex +
                               "\n"
                               "---\n" +
                               inner_doc;

    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.install(bundle, make_accept_all_install_fn());
    REQUIRE(result.has_value());
    CHECK_FALSE(result->empty());

    // The installed pack round-trips through get() with verified=true.
    auto got = store.get(*result);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->verified);
    CHECK((*got)->name == "test-signed-positive");

    // Mutate one byte of the signature (flip the last hex char). Verify
    // must now reject — proves the crypto path is real, not a stub.
    std::string mutated_sig = signature_hex;
    mutated_sig.back() = (mutated_sig.back() == '0' ? '1' : '0');
    const std::string mutated_bundle = "apiVersion: yuzu.io/v1alpha1\n"
                                       "kind: ProductPack\n"
                                       "name: test-signed-mutated\n"
                                       "version: 1.0.0\n"
                                       "description: Bundle with one-byte-mutated signature\n"
                                       "signature: " +
                                       mutated_sig +
                                       "\n"
                                       "publicKey: " +
                                       pair.public_key_hex +
                                       "\n"
                                       "---\n" +
                                       inner_doc;

    auto result_mut = store.install(mutated_bundle, make_accept_all_install_fn());
    REQUIRE_FALSE(result_mut.has_value());
    CHECK(result_mut.error().find("signature verification failed") != std::string::npos);
}

// ── list / get / uninstall round-trip ───────────────────────────────────────

TEST_CASE("ProductPackStore: list/get/uninstall round-trip", "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    int install_calls = 0;
    auto result = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls));
    REQUIRE(result.has_value());
    const std::string pack_id = *result;
    CHECK(install_calls == 1);

    SECTION("get finds the installed pack with its item") {
        auto got = store.get(pack_id);
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->id == pack_id);
        CHECK((*got)->name == "test-unsigned");
        CHECK_FALSE((*got)->verified);
        REQUIRE((*got)->items.size() == 1);
        CHECK((*got)->items[0].kind == "InstructionDefinition");
        CHECK((*got)->items[0].item_id == "item-id-1");
    }

    SECTION("get on an unknown id returns nullopt, not an error") {
        auto got = store.get("does-not-exist");
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
    }

    SECTION("list finds the installed pack") {
        auto listed = store.list();
        REQUIRE(listed.has_value());
        bool found = false;
        for (const auto& p : *listed)
            found = found || p.id == pack_id;
        CHECK(found);
    }

    SECTION("list name_filter narrows the result") {
        ProductPackQuery q;
        q.name_filter = "nonexistent-name-xyz";
        auto listed = store.list(q);
        REQUIRE(listed.has_value());
        CHECK(listed->empty());
    }

    SECTION("uninstall on an unknown id returns not_found") {
        auto r = store.uninstall("does-not-exist",
                                 [](const std::string&, const std::string&) -> std::expected<void, std::string> { return {}; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().starts_with("not_found:"));
    }

    SECTION("uninstall removes the pack and invokes uninstall_fn per item") {
        int uninstall_calls = 0;
        auto r = store.uninstall(pack_id, [&uninstall_calls](const std::string&,
                                                              const std::string&)
                                             -> std::expected<void, std::string> {
            ++uninstall_calls;
            return {};
        });
        REQUIRE(r.has_value());
        CHECK(uninstall_calls == 1);

        auto got = store.get(pack_id);
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
    }

    SECTION("uninstall aborts (never deletes the pack row) when an item's origin store reports "
            "a genuine DB error") {
        // Regression pin: an origin-store DB error used to be tolerated the same as a
        // not-found item (the callback collapsed to bool), so a pack could be reported
        // "uninstalled" while a contained item was actually never removed because its store
        // was down. A db_error-prefixed failure must abort the whole uninstall instead.
        auto r = store.uninstall(
            pack_id, [](const std::string&, const std::string&) -> std::expected<void, std::string> {
                return std::unexpected(std::string(yuzu::server::kProductPackDbErrorPrefix) +
                                       "simulated origin-store outage");
            });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));

        // The pack must still exist — uninstall() never reached the delete+tombstone txn.
        auto got = store.get(pack_id);
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->id == pack_id);
    }
}

// ── Per-document partial-failure detail (#3479) ──────────────────────────────

TEST_CASE("ProductPackStore::install: a partial success surfaces which documents failed and "
          "why, not just a bare pack id",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto install_fn =
        [](const std::string&,
           const std::string& yaml_source) -> std::expected<std::string, std::string> {
        auto name = ProductPackStore::extract_yaml_value(yaml_source, "name");
        if (name == "item-bad-a")
            return std::unexpected("reason A: bad configuration");
        if (name == "item-bad-b")
            return std::unexpected("reason B: unsupported field");
        return std::string{"item-id-ok"};
    };

    yuzu::server::InstallPartialResult partial;
    auto result = store.install(kThreeItemPartialFailureYaml, install_fn, {}, {}, &partial);
    // Overall outcome is still success — one item installed.
    REQUIRE(result.has_value());

    REQUIRE(partial.errors.size() == 2);
    CHECK(partial.installed_count == 1);
    CHECK(partial.total_items == 3);
    // Both distinct reasons are recoverable, not just the first.
    bool saw_a = false, saw_b = false;
    for (const auto& e : partial.errors) {
        if (e.find("reason A") != std::string::npos)
            saw_a = true;
        if (e.find("reason B") != std::string::npos)
            saw_b = true;
    }
    CHECK(saw_a);
    CHECK(saw_b);
}

TEST_CASE("ProductPackStore::install: a total failure surfaces EVERY document's reason, not "
          "just the first",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto install_fn =
        [](const std::string&,
           const std::string& yaml_source) -> std::expected<std::string, std::string> {
        auto name = ProductPackStore::extract_yaml_value(yaml_source, "name");
        return std::unexpected("rejected: " + name);
    };

    yuzu::server::InstallPartialResult partial;
    auto result = store.install(kThreeItemPartialFailureYaml, install_fn, {}, {}, &partial);
    REQUIRE_FALSE(result.has_value());
    // Pre-#3479 this only ever surfaced errors[0] here.
    CHECK(result.error().find("item-ok") != std::string::npos);
    CHECK(result.error().find("item-bad-a") != std::string::npos);
    CHECK(result.error().find("item-bad-b") != std::string::npos);

    REQUIRE(partial.errors.size() == 3);
    CHECK(partial.installed_count == 0);
    CHECK(partial.total_items == 3);
}

TEST_CASE("ProductPackStore::install: omitting partial_result preserves prior behavior exactly "
          "(no crash, no observable difference)",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto install_fn =
        [](const std::string&,
           const std::string& yaml_source) -> std::expected<std::string, std::string> {
        auto name = ProductPackStore::extract_yaml_value(yaml_source, "name");
        if (name == "item-bad-a" || name == "item-bad-b")
            return std::unexpected("rejected");
        return std::string{"item-id-ok"};
    };
    // No trailing partial_result argument — matches every pre-#3479 call site.
    auto result = store.install(kThreeItemPartialFailureYaml, install_fn);
    REQUIRE(result.has_value());
}

// Gate 8 review (Fable, external): a bundle whose documents assign the same item id twice
// must fail as a plain validation error (never kProductPackDbErrorPrefix) — retryable-503
// misclassification would turn a deterministic duplicate-id bundle into a repeated orphan
// generator against the sibling stores, since install_fn runs with no pool_ lease held and
// a client retry would re-invoke it on every attempt.
TEST_CASE("ProductPackStore::install: a duplicate item id in one bundle fails as a plain "
          "validation error, never a retryable db_error",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto result = store.install(kUnsignedPackYamlDuplicateItems, make_accept_all_install_fn());
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("duplicate item id") != std::string::npos);
    CHECK(result.error().find(yuzu::server::kProductPackDbErrorPrefix) == std::string::npos);

    // Nothing was persisted — the pack never reaches Postgres.
    auto listed = store.list();
    REQUIRE(listed.has_value());
    for (const auto& p : *listed)
        CHECK(p.name != "test-duplicate-items");
}

// Gov Gate 2 finding (security-guardian, this PR's own review): the duplicate-item-id check
// above returns BEFORE the persist transaction, but install_fn has ALREADY committed both
// documents into sibling stores by that point — the exact orphan shape F031 exists to close.
// The original fix only wired compensate_fn into the later with_txn_for failure path; this
// proves it now ALSO fires here.
//
// Gov Gate 6 finding (architect): both documents in this bundle share the SAME item_id (that
// IS the duplicate being detected), so items_to_store carries it twice — compensate_fn must be
// called for that id only ONCE, not twice; a second call against already-deleted content would
// either be a harmless no-op the sibling store can't distinguish from a real failure, or a
// false "partial" result/metric for content that was never actually left orphaned.
TEST_CASE("ProductPackStore::install: a duplicate item id also triggers compensation, exactly "
          "once per unique id (not just the final persist path)",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    std::vector<std::pair<std::string, std::string>> compensated;
    auto compensate_fn = [&compensated](const std::string& kind, const std::string& item_id)
        -> std::expected<void, std::string> {
        compensated.emplace_back(kind, item_id);
        return {};
    };

    auto result = store.install(kUnsignedPackYamlDuplicateItems, make_accept_all_install_fn(),
                                compensate_fn);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("duplicate item id") != std::string::npos);
    CHECK(result.error().find(yuzu::server::kProductPackDbErrorPrefix) == std::string::npos);
    REQUIRE(compensated.size() == 1);
    CHECK(compensated[0].first == "InstructionDefinition");
    CHECK(compensated[0].second == "item-id");
}

// Gate 8 finding (#3481, security-guardian, verified with a live PolicyStore repro): the
// item_id-only dedup above silently skips compensating a SECOND item that shares the same
// item_id but has a DIFFERENT kind — exactly the shape a caller-supplied `id:` YAML field on
// two different sibling-store documents produces. Proves the (kind, item_id) fix compensates
// BOTH, not just the first one seen.
TEST_CASE("ProductPackStore::install: a duplicate item id shared across TWO DIFFERENT kinds "
          "compensates both, not just one",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    std::vector<std::pair<std::string, std::string>> compensated;
    auto compensate_fn = [&compensated](const std::string& kind, const std::string& item_id)
        -> std::expected<void, std::string> {
        compensated.emplace_back(kind, item_id);
        return {};
    };

    auto result = store.install(kUnsignedPackYamlCrossKindDuplicateId,
                                make_accept_all_install_fn(), compensate_fn);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("duplicate item id") != std::string::npos);
    // Both items compensated — one per kind — even though they share the same item_id.
    REQUIRE(compensated.size() == 2);
    CHECK(compensated[0].second == "item-id");
    CHECK(compensated[1].second == "item-id");
    std::vector<std::string> kinds{compensated[0].first, compensated[1].first};
    CHECK(std::find(kinds.begin(), kinds.end(), "InstructionDefinition") != kinds.end());
    CHECK(std::find(kinds.begin(), kinds.end(), "Workflow") != kinds.end());
}

// ── Compensating cleanup (F031/#3481) ───────────────────────────────────────
//
// Pool-contention fault injection technique (proven precedent:
// test_api_token_store.cpp's "failed_pairs counts a POOL-CONTENTION ACQUIRE failure" test) — a
// size-1 pool, pinned by an unrelated held lease AFTER construction/migration has already
// released its own lease, leaves nothing for install()'s own with_txn_for to acquire. This is a
// REAL Postgres-level failure (a genuine bounded acquire timeout), not a mock.

TEST_CASE("ProductPackStore::install: a late persist failure (pool-contention) triggers "
          "best-effort compensation for every already-installed item",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    int install_calls = 0;
    std::vector<std::pair<std::string, std::string>> compensated;
    auto compensate_fn = [&compensated](const std::string& kind, const std::string& item_id)
        -> std::expected<void, std::string> {
        compensated.emplace_back(kind, item_id);
        return {};
    };

    auto result = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls),
                                compensate_fn);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    CHECK(install_calls == 1);
    REQUIRE(compensated.size() == 1);
    CHECK(compensated[0].first == "InstructionDefinition");
    CHECK(compensated[0].second == "item-id-1");

    unrelated_lease.reset();
    auto listed = store.list();
    REQUIRE(listed.has_value());
    for (const auto& p : *listed)
        CHECK(p.name != "test-unsigned");
}

TEST_CASE("ProductPackStore::install: compensation runs in reverse install order",
          "[product_pack_store][pg]") {
    // Reverse order matters when a bundle's documents have an install-order dependency — e.g. a
    // PolicyFragment installed before a Policy that references it (bundle order is dependency
    // order: PolicyStore::create_policy validates the fragment exists at creation time), and
    // PolicyStore::delete_fragment refuses while any Policy still references it. Compensating
    // forward would spuriously fail to clean up the fragment. This store's own unit tests don't
    // wire a live PolicyStore, so this proves the ordering mechanism generically with two stub
    // items, asserting compensation visits them in the reverse of install_fn's call order.
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    int install_calls = 0;
    std::vector<std::string> compensated_ids;
    auto compensate_fn = [&compensated_ids](const std::string&, const std::string& item_id)
        -> std::expected<void, std::string> {
        compensated_ids.push_back(item_id);
        return {};
    };

    auto result = store.install(kUnsignedPackYamlDuplicateItems,
                                make_counting_install_fn(&install_calls), compensate_fn);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(compensated_ids.size() == 2);
    CHECK(compensated_ids[0] == "item-id-2");
    CHECK(compensated_ids[1] == "item-id-1");
}

// Gov Gate 4 finding (#3481, unhappy-path, R2): compensate_fn is caller-supplied — same as
// uninstall_fn — and pre-PR every failure path below always reached workflow_routes.cpp's
// audit_fn uninterrupted. This proves a THROWING compensate_fn (as opposed to an ordinary
// `false` return, already covered above) does not unwind past install(): the throw is caught,
// logged as a failed compensation, and the reverse-order loop keeps going to the remaining
// item(s) rather than skipping them and the caller's own error handling / audit call.
TEST_CASE("ProductPackStore::install: a throwing compensate_fn is caught, logged as a failed "
          "compensation, and does not abort compensating the rest of the bundle",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    int install_calls = 0;
    std::vector<std::string> compensate_attempts;
    auto compensate_fn = [&compensate_attempts](const std::string&, const std::string& item_id)
        -> std::expected<void, std::string> {
        compensate_attempts.push_back(item_id);
        if (item_id == "item-id-2")
            throw std::runtime_error("simulated sibling-store delete failure");
        return {};
    };

    auto result = store.install(kUnsignedPackYamlDuplicateItems,
                                make_counting_install_fn(&install_calls), compensate_fn);
    REQUIRE_FALSE(result.has_value());
    // The throw must not propagate out of install() — the caller (workflow_routes.cpp) still
    // gets its normal std::unexpected (the late-persist failure, via pool contention below) and
    // runs its own error handling / audit call unimpeded.
    CHECK(result.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    // Both items attempted, in reverse order — the throw on the first (item-id-2) did not skip
    // the second (item-id-1).
    REQUIRE(compensate_attempts.size() == 2);
    CHECK(compensate_attempts[0] == "item-id-2");
    CHECK(compensate_attempts[1] == "item-id-1");
}

// Gate 8 finding (#3481, quality-engineer): no test in this file wires set_metrics before
// forcing a partial compensation, so the yuzu_server_product_pack_install_compensation_total
// emission — including this round's own `compensated == attempted` label-selection change
// (replacing `compensated == items_to_store.size()`, which the (kind, item_id) dedup fix just
// above made a real distinction rather than always-equal) — had zero coverage. This proves
// both label values a real partial-compensation run produces.
TEST_CASE("ProductPackStore::install: a partial compensation increments the compensation "
          "metric's partial series, a full one increments ok",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    {
        auto unrelated_lease = pool.acquire();
        REQUIRE(unrelated_lease);
        int install_calls = 0;
        // item-id-2 fails to compensate (ordinary `false`, not a throw — the metric must count
        // both failure shapes as "partial" identically); item-id-1 succeeds.
        auto compensate_fn = [](const std::string&,
                                const std::string& item_id) -> std::expected<void, std::string> {
            if (item_id != "item-id-2")
                return {};
            return std::unexpected("simulated compensation failure");
        };
        auto result = store.install(kUnsignedPackYamlDuplicateItems,
                                    make_counting_install_fn(&install_calls), compensate_fn);
        REQUIRE_FALSE(result.has_value());
    }
    CHECK(metrics.counter("yuzu_server_product_pack_install_compensation_total",
                          {{"result", "partial"}})
              .value() == 1);
    CHECK(metrics.counter("yuzu_server_product_pack_install_compensation_total",
                          {{"result", "ok"}})
              .value() == 0);

    {
        auto unrelated_lease = pool.acquire();
        REQUIRE(unrelated_lease);
        int install_calls = 0;
        auto compensate_fn = [](const std::string&,
                                const std::string&) -> std::expected<void, std::string> {
            return {};
        };
        auto result = store.install(kUnsignedPackYamlDuplicateItems,
                                    make_counting_install_fn(&install_calls), compensate_fn);
        REQUIRE_FALSE(result.has_value());
    }
    CHECK(metrics.counter("yuzu_server_product_pack_install_compensation_total",
                          {{"result", "ok"}})
              .value() == 1);
    // The prior partial event's series must not have been clobbered by this second install.
    CHECK(metrics.counter("yuzu_server_product_pack_install_compensation_total",
                          {{"result", "partial"}})
              .value() == 1);
}

// ── Ambiguous-commit-ack safety (Gate 5 CHAOS-1/CHAOS-1b, #3481) ─────────────
//
// A real network fault landing between Postgres processing COMMIT and the client reading
// PGRES_COMMAND_OK — or a middlebox/pooler severing the client's connection at a moment
// uncorrelated with the backend's own commit progress (CHAOS-1b) — is a genuine hazard that
// cannot be reproduced deterministically without a connection-level fault-injecting proxy this
// test suite doesn't have. What IS directly testable, and what these three cases prove instead:
// the check_transaction_outcome decision seam itself — the exact mechanism install()'s
// final-persist failure path now consults before deciding whether compensating is safe. Unlike
// the row-visibility check it replaced, all three of THIS mechanism's real outcomes (committed,
// aborted, still in progress) are directly, deterministically producible with two connections —
// no fault injection needed for the seam itself, only for the full ambiguous-commit integration
// (recorded as `likely`, not `verified`, in governance terms).

TEST_CASE("ProductPackStore::check_transaction_outcome: kUnknown while the transaction is still "
          "in progress (never guessed as kAborted)",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    auto held_lease = pool.acquire();
    REQUIRE(held_lease);
    REQUIRE(pg::exec_params(held_lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
           PGRES_COMMAND_OK);
    pg::PgResult xid_res = pg::exec_params(held_lease.get(), "SELECT pg_current_xact_id()::text",
                                           std::vector<std::string>{});
    REQUIRE(xid_res.status() == PGRES_TUPLES_OK);
    auto xact_id = std::string(PQgetvalue(xid_res.get(), 0, 0));

    // The transaction is still open on held_lease — queried from a SEPARATE connection while it
    // stays that way.
    CHECK(ProductPackStore::check_transaction_outcome(pool, xact_id) ==
         yuzu::server::TransactionOutcome::kUnknown);

    pg::exec_params(held_lease.get(), "ROLLBACK", std::vector<std::string>{});
}

TEST_CASE("ProductPackStore::check_transaction_outcome: kCommitted after a real COMMIT",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    auto lease = pool.acquire();
    REQUIRE(lease);
    REQUIRE(pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
           PGRES_COMMAND_OK);
    pg::PgResult xid_res = pg::exec_params(lease.get(), "SELECT pg_current_xact_id()::text",
                                           std::vector<std::string>{});
    REQUIRE(xid_res.status() == PGRES_TUPLES_OK);
    auto xact_id = std::string(PQgetvalue(xid_res.get(), 0, 0));
    REQUIRE(pg::exec_params(lease.get(), "COMMIT", std::vector<std::string>{}).status() ==
           PGRES_COMMAND_OK);
    lease.reset();

    CHECK(ProductPackStore::check_transaction_outcome(pool, xact_id) ==
         yuzu::server::TransactionOutcome::kCommitted);
}

TEST_CASE("ProductPackStore::check_transaction_outcome: kAborted after a real ROLLBACK",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    auto lease = pool.acquire();
    REQUIRE(lease);
    REQUIRE(pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
           PGRES_COMMAND_OK);
    pg::PgResult xid_res = pg::exec_params(lease.get(), "SELECT pg_current_xact_id()::text",
                                           std::vector<std::string>{});
    REQUIRE(xid_res.status() == PGRES_TUPLES_OK);
    auto xact_id = std::string(PQgetvalue(xid_res.get(), 0, 0));
    REQUIRE(pg::exec_params(lease.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
           PGRES_COMMAND_OK);
    lease.reset();

    CHECK(ProductPackStore::check_transaction_outcome(pool, xact_id) ==
         yuzu::server::TransactionOutcome::kAborted);
}

TEST_CASE("ProductPackStore::check_transaction_outcome: kUnknown when the pool can't be "
          "reached, never guessed as kAborted",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);
    CHECK(ProductPackStore::check_transaction_outcome(pool, "1") ==
         yuzu::server::TransactionOutcome::kUnknown);
}

// Gate 5 CHAOS-1b regression net: the install()-level integration, driven WITHOUT network fault
// injection by forcing a genuine, deterministic transaction failure while the write lease is
// held — a competing autocommit INSERT (on its OWN connection, simulating a concurrent racer)
// takes the SAME idempotency_key before this install's own persist INSERT runs, so the persist
// hits the partial unique index's violation with the lease still held. This exercises the REAL
// kAborted arm through install() end-to-end (not just the check_transaction_outcome seam above),
// and doubles as a live regression net for the CHAOS-3 race-loser scenario documented in
// product_pack_store.hpp (the loser gets a retryable db_error, not the differing-body 400).
TEST_CASE("ProductPackStore::install: a genuine persist failure (unique-violation, lease held) "
          "resolves kAborted via pg_xact_status and compensates through install() end to end",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    const std::string kRacingKey = "chaos-1b-racing-key";
    std::vector<std::pair<std::string, std::string>> compensated;
    auto compensate_fn = [&compensated](const std::string& kind, const std::string& item_id)
        -> std::expected<void, std::string> {
        compensated.emplace_back(kind, item_id);
        return {};
    };
    // install_fn plays the role of a concurrent racer: before this attempt's OWN persist INSERT
    // runs, a SEPARATE autocommit connection claims kRacingKey first — by the time this
    // attempt's persist transaction executes, the partial unique index already has a row for
    // that key, so the INSERT fails on a genuine, real constraint violation (not a fault).
    auto install_fn = [&pool, &kRacingKey](
                          const std::string&,
                          const std::string&) -> std::expected<std::string, std::string> {
        auto racer_lease = pool.acquire();
        if (!racer_lease)
            return std::unexpected("could not acquire racer lease");
        pg::PgResult ins = pg::exec_params(
            racer_lease.get(),
            "INSERT INTO product_pack_store.product_packs (id, name, yaml_source, "
            "idempotency_key) VALUES ('chaos-1b-racer-pack', 'racer', 'racer-yaml', $1)",
            std::vector<std::string>{kRacingKey});
        if (ins.status() != PGRES_COMMAND_OK)
            return std::unexpected("racer insert failed");
        return std::string{"item-id"};
    };

    auto result = store.install(kUnsignedPackYaml, install_fn, compensate_fn, kRacingKey);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    // The compensate_and_fail path ran (not the kUnknown-skip path) — proving
    // check_transaction_outcome resolved kAborted for this attempt's own (genuinely rolled
    // back) transaction, not the racer's (committed) one.
    REQUIRE(compensated.size() == 1);
    CHECK(compensated[0].first == "InstructionDefinition");
}

// Gate 5 CHAOS-1 regression net at the install() level: a write-lease ACQUIRE failure (the
// existing pool-starvation technique — pin the pool's only connection BEFORE calling install())
// must still compensate exactly as before, since the transaction never started and there is
// nothing ambiguous to verify. This is the same scenario the "late persist failure
// (pool-contention)" test above exercises; restated here explicitly as the CHAOS-1 regression
// guard so a future reader doesn't have to infer it from that test's unrelated name.
TEST_CASE("ProductPackStore::install: a write-lease ACQUIRE failure (not a txn failure) still "
          "compensates directly, no existence re-check needed",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    int install_calls = 0;
    std::vector<std::string> compensated_ids;
    auto compensate_fn = [&compensated_ids](const std::string&, const std::string& item_id)
        -> std::expected<void, std::string> {
        compensated_ids.push_back(item_id);
        return {};
    };
    auto result = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls),
                                compensate_fn);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    REQUIRE(compensated_ids.size() == 1);
}

// ── Idempotency (F033/#3481) ─────────────────────────────────────────────────

TEST_CASE("ProductPackStore::install: the idempotency pre-check fails closed under pool "
          "contention",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto unrelated_lease = pool.acquire();
    REQUIRE(unrelated_lease);

    int install_calls = 0;
    auto result = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls), {},
                                "some-key");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    CHECK(install_calls == 0); // install_fn never reached — the pre-check failed first
}

TEST_CASE("ProductPackStore::install: a repeated Idempotency-Key with an identical bundle "
          "returns the original pack id and does not re-invoke install_fn",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    int install_calls = 0;
    auto first = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls), {},
                               "replay-key-1");
    REQUIRE(first.has_value());
    CHECK(install_calls == 1);

    auto second = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls), {},
                                "replay-key-1");
    REQUIRE(second.has_value());
    CHECK(*second == *first);
    CHECK(install_calls == 1);

    auto listed = store.list();
    REQUIRE(listed.has_value());
    int matching = 0;
    for (const auto& p : *listed)
        if (p.name == "test-unsigned")
            ++matching;
    CHECK(matching == 1);
}

TEST_CASE("ProductPackStore::install: a repeated Idempotency-Key with a different bundle is "
          "rejected as a plain validation error",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    int install_calls = 0;
    auto first = store.install(kUnsignedPackYaml, make_counting_install_fn(&install_calls), {},
                               "reuse-key-1");
    REQUIRE(first.has_value());
    CHECK(install_calls == 1);

    auto second = store.install(kUnsignedPackYamlAlt, make_counting_install_fn(&install_calls),
                                {}, "reuse-key-1");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().find("idempotency key") != std::string::npos);
    CHECK(second.error().find(yuzu::server::kProductPackDbErrorPrefix) == std::string::npos);
    CHECK(install_calls == 1); // install_fn never invoked for the rejected second attempt
}

TEST_CASE("ProductPackStore::install: an empty idempotency_key preserves today's behavior (no "
          "dedup)",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto first = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(first.has_value());
    auto second = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(second.has_value());
    CHECK(*first != *second);
}

// ── Accepted-risk residual (F032/#3481) ──────────────────────────────────────

TEST_CASE("ProductPackStore::uninstall: a retried DELETE after a late metadata-delete failure "
          "eventually converges",
          "[product_pack_store][pg]") {
    // F032 is specifically the metadata-delete TRANSACTION failing AFTER uninstall_fn already
    // ran against sibling content — NOT get() failing before anything happens. A single pinned
    // connection (the technique used for F031 above) starves get() too, since uninstall() calls
    // get() first to fetch pack.items — that would prove the wrong thing. Instead, reuse the
    // erasure-coordination-lock test's technique below: hold kErasureCoordLockSql open on a
    // second connection from the SAME pool, and give the pool a short lock_timeout_ms so
    // uninstall()'s own attempt to take that lock (the first statement inside its with_txn_for,
    // AFTER uninstall_fn has already run) genuinely fails with a real Postgres lock-timeout
    // error — a deterministic, real failure at exactly the point F032 describes.
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 500}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    auto installed = store.install(kUnsignedPackYaml, make_accept_all_install_fn());
    REQUIRE(installed.has_value());
    const std::string pack_id = *installed;

    // Hold the SAME advisory lock uninstall() takes, uncommitted, on a separate connection —
    // must match kErasureCoordLockSql in product_pack_store.cpp exactly (private to that
    // translation unit, so hard-coded here, same as the erasure-coordination-lock test above).
    auto lease_a = pool.acquire();
    REQUIRE(lease_a);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "SELECT pg_advisory_xact_lock(2037545589, "
                            "hashtext('product_pack_store:erasure_coordination'))",
                            std::vector<std::string>{})
                .ok());

    int first_uninstall_calls = 0;
    auto first =
        store.uninstall(pack_id, [&first_uninstall_calls](const std::string&, const std::string&)
                                     -> std::expected<void, std::string> {
            ++first_uninstall_calls;
            return {};
        });
    REQUIRE_FALSE(first.has_value());
    CHECK(first.error().starts_with(yuzu::server::kProductPackDbErrorPrefix));
    CHECK(first_uninstall_calls == 1);

    // The pack must still be listed as installed — the metadata delete never committed, even
    // though uninstall_fn already ran against (fake) sibling content above.
    auto still_there = store.get(pack_id);
    REQUIRE(still_there.has_value());
    REQUIRE(still_there->has_value());

    // Releasing an open-transaction lease rolls it back defensively (PgPool contract), freeing
    // the advisory lock.
    lease_a.reset();

    int second_uninstall_calls = 0;
    auto second =
        store.uninstall(pack_id, [&second_uninstall_calls](const std::string&, const std::string&)
                                     -> std::expected<void, std::string> {
            ++second_uninstall_calls;
            return {};
        });
    REQUIRE(second.has_value());
    CHECK(second_uninstall_calls == 1);

    auto gone = store.get(pack_id);
    REQUIRE(gone.has_value());
    CHECK_FALSE(gone->has_value());
}

// ── REST-level regression net (Gate 8 round-2: quality-engineer + unhappy-path, twice-flagged)
// ──
//
// The store-level tests above prove the backend contract; nothing before this point drives an
// actual HTTP request through WorkflowRoutes' four product-pack handlers, so the genericization
// split (workflow_routes.cpp's product_pack_client_message — response body only, never the
// audit trail) and the DELETE-denied audit_fn addition (56fbd3580) were previously verified only
// by direct code reading. These two cases close that gap. No new test FILE — same
// [product_pack_store] tag family, inherits the existing shard placement, no meson.build change.

namespace {

/// Minimal WorkflowRoutes harness scoped to the product-pack routes only. Every other Deps
/// field stays default (nullptr/empty std::function) — safe, because auth_fn/scope_fn/
/// command_dispatch_fn/caller_fn are never invoked by the GET/POST/DELETE product-pack handlers
/// (only by this file's other registered routes, none of which this harness dispatches to).
struct ProductPackRestHarness {
    // Declaration order matters (gov Gate 8 round-3, cpp-safety): `sink` stores the
    // registered handlers, one of which captures `this` to append into `audit_rows` — so
    // `audit_rows` must outlive `sink` and therefore be declared BEFORE it (destroyed
    // after it, per reverse-declaration-order teardown). `metrics` is unreferenced by any
    // product-pack handler but is declared first regardless, matching
    // test_route_sink.hpp's own "declare the sink after the route owner" invariant.
    yuzu::MetricsRegistry metrics;
    std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string>>
        audit_rows; // (action, result, target_type, target_id, detail)
    yuzu::server::test::TestRouteSink sink;

    explicit ProductPackRestHarness(ProductPackStore* store,
                                    InstructionStore* instruction_store = nullptr) {
        WorkflowRoutes routes;
        WorkflowRoutes::Deps deps;
        deps.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        deps.audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) {
            audit_rows.emplace_back(action, result, target_type, target_id, detail);
        };
        deps.emit_fn = [](const std::string&, const httplib::Request&) {};
        deps.product_pack_store = store;
        deps.instruction_store = instruction_store;
        deps.metrics = &metrics;
        routes.register_routes(sink, std::move(deps));
    }
};

} // namespace

TEST_CASE("REST: a genuine DB error never reaches the response body or the audit trail as raw "
          "driver text",
          "[product_pack_store]") {
    // Unreachable pool (same fixture as the store-level "!is_open" test above) — every
    // ProductPackStore method deterministically returns a kProductPackDbErrorPrefix error, with
    // no live Postgres required. This is the classifier's PREFIX check, not its content, so it
    // exercises the same genericization path a real PQerrorMessage() leak would hit.
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    ProductPackStore store{pool};
    REQUIRE_FALSE(store.is_open());

    ProductPackRestHarness h{&store};

    // GET /api/product-packs has its OWN pre-existing `!is_open()` early guard (unrelated to
    // this fix round — it short-circuits before list() is ever called, so it never reaches
    // product_pack_client_message()'s genericization path at all) with its own hardcoded,
    // already-generic message. Different string than the genericizer's, same "no internals
    // leaked" property — assert that property, not byte-identical wording across routes.
    auto list_res = h.sink.dispatch("GET", "/api/product-packs");
    REQUIRE(list_res);
    CHECK(list_res->status == 503);
    CHECK(list_res->body.find("db_error") == std::string::npos);
    CHECK(list_res->body.find("not open") == std::string::npos);

    auto del_res = h.sink.dispatch("DELETE", "/api/product-packs/some-id");
    REQUIRE(del_res);
    CHECK(del_res->status == 503);
    CHECK(del_res->body.find("service unavailable") != std::string::npos);
    CHECK(del_res->body.find("db_error") == std::string::npos);
    CHECK(del_res->body.find("not open") == std::string::npos);

    // Regression net for 56fbd3580: the audit `detail` must be genericized identically to the
    // response body, not the raw "db_error: database not open" the store returned.
    REQUIRE(h.audit_rows.size() == 1);
    const auto& [action, result, target_type, target_id, detail] = h.audit_rows[0];
    CHECK(action == "product_pack.uninstall");
    CHECK(result == "denied");
    CHECK(target_type == "ProductPack");
    CHECK(target_id == "some-id");
    CHECK(detail == "service unavailable");
    CHECK(detail.find("db_error") == std::string::npos);
    CHECK(detail.find("not open") == std::string::npos);
}

TEST_CASE("REST: a not-found rejection is echoed verbatim in both the response and the audit "
          "trail",
          "[product_pack_store][pg]") {
    // Live store: not_found never carries kProductPackDbErrorPrefix, so it must pass through
    // product_pack_client_message() unchanged in both the response body and the audit detail —
    // the positive-path counterpart to the genericization test above.
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());

    ProductPackRestHarness h{&store};

    auto del_res = h.sink.dispatch("DELETE", "/api/product-packs/does-not-exist");
    REQUIRE(del_res);
    CHECK(del_res->status == 404);
    CHECK((del_res->body.find("not_found") != std::string::npos ||
          del_res->body.find("does-not-exist") != std::string::npos));

    REQUIRE(h.audit_rows.size() == 1);
    const auto& [action, result, target_type, target_id, detail] = h.audit_rows[0];
    CHECK(action == "product_pack.uninstall");
    CHECK(result == "denied");
    CHECK(target_type == "ProductPack");
    CHECK(target_id == "does-not-exist");
    CHECK(detail.starts_with("not_found:"));
    CHECK(detail.find("does-not-exist") != std::string::npos);
}

// Gov Gate 6 findings (quality-engineer + consistency-auditor, both independently, #3481): the
// store-level F033 tests above prove ProductPackStore::install()'s idempotency contract
// directly; nothing before this point drives a real HTTP POST through WorkflowRoutes' header
// parsing (length bound, missing-header default) or its threading of idempotency_key into
// install(). A metadata-only bundle (no item documents) avoids needing live
// InstructionStore/PolicyStore/WorkflowEngine — this harness leaves those null, same as the
// other REST-level tests above.
TEST_CASE("REST: POST /api/product-packs honors Idempotency-Key end to end (replay, conflict, "
          "and the length bound)",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    ProductPackRestHarness h{&store};

    constexpr const char* kMetaOnlyBundle = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-rest-idempotency
version: 1.0.0
description: Metadata-only bundle, no item documents
)";
    constexpr const char* kMetaOnlyBundleAlt = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-rest-idempotency-alt
version: 1.0.0
description: A different metadata-only bundle
)";

    auto first =
        h.sink.dispatch("POST", "/api/product-packs", kMetaOnlyBundle, "text/plain",
                        {{"Idempotency-Key", "rest-key-1"}});
    REQUIRE(first);
    REQUIRE(first->status == 201);
    auto first_id = nlohmann::json::parse(first->body).value("id", std::string{});
    REQUIRE_FALSE(first_id.empty());

    // Replay: same key, same body -> same id, no second row (still exactly one audit row for
    // the whole test so far — a replay must audit success, not silently skip it, per the
    // AskUserQuestion-confirmed "re-fire audit+emit on replay" decision).
    auto replay =
        h.sink.dispatch("POST", "/api/product-packs", kMetaOnlyBundle, "text/plain",
                        {{"Idempotency-Key", "rest-key-1"}});
    REQUIRE(replay);
    CHECK(replay->status == 201);
    CHECK(nlohmann::json::parse(replay->body).value("id", std::string{}) == first_id);

    // Same key, different body -> 400, not a retryable db_error.
    auto conflict =
        h.sink.dispatch("POST", "/api/product-packs", kMetaOnlyBundleAlt, "text/plain",
                        {{"Idempotency-Key", "rest-key-1"}});
    REQUIRE(conflict);
    CHECK(conflict->status == 400);
    CHECK(conflict->body.find("different") != std::string::npos);

    // Header too long -> 400, rejected before install() is ever called (not audited, per
    // rest-api.md/audit-log.md).
    auto too_long = h.sink.dispatch("POST", "/api/product-packs", kMetaOnlyBundle, "text/plain",
                                    {{"Idempotency-Key", std::string(201, 'k')}});
    REQUIRE(too_long);
    CHECK(too_long->status == 400);
    CHECK(too_long->body.find("too long") != std::string::npos);

    // Exactly two accepted installs (first + replay) audited as success/denied appropriately;
    // the too-long rejection above must NOT have added a third "denied" row.
    int install_audit_rows = 0;
    for (const auto& row : h.audit_rows)
        if (std::get<0>(row) == "product_pack.install")
            ++install_audit_rows;
    CHECK(install_audit_rows == 3); // first (success) + replay (success) + conflict (denied)
}

// #3479: end-to-end through the real POST handler — a live InstructionStore lets one document
// genuinely succeed alongside two that genuinely fail for two DIFFERENT real reasons (an
// invalid approval mode, checked inside workflow_routes.cpp's own install_fn; an unsupported
// kind, checked before any store is touched) without needing PolicyStore/WorkflowEngine at all.
TEST_CASE("REST: POST /api/product-packs reports which documents failed and why on a partial "
          "success, and the audit detail names the count",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    InstructionStore instruction_store{pool};
    REQUIRE(instruction_store.is_open());

    ProductPackRestHarness h{&store, &instruction_store};

    constexpr const char* kMixedBundle = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-rest-partial-failure
version: 1.0.0
description: One item succeeds, two fail for distinct real reasons
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: rest-item-ok
plugin: system
action: noop
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: rest-item-bad-mode
plugin: system
action: noop
mode: not-a-real-mode
---
apiVersion: yuzu.io/v1alpha1
kind: NotARealKind
name: rest-item-bad-kind
)";

    auto res = h.sink.dispatch("POST", "/api/product-packs", kMixedBundle, "text/plain");
    REQUIRE(res);
    CHECK(res->status == 201); // overall success — one item installed
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("errors"));
    REQUIRE(body["errors"].size() == 2);
    CHECK(body["installed_count"] == 1);
    CHECK(body["total_items"] == 3);

    bool saw_mode_error = false, saw_kind_error = false;
    for (const auto& e : body["errors"]) {
        auto s = e.get<std::string>();
        if (s.find("invalid approval mode") != std::string::npos)
            saw_mode_error = true;
        if (s.find("unsupported kind") != std::string::npos)
            saw_kind_error = true;
    }
    CHECK(saw_mode_error);
    CHECK(saw_kind_error);

    REQUIRE(h.audit_rows.size() == 1);
    const auto& [action, result, target_type, target_id, detail] = h.audit_rows[0];
    CHECK(action == "product_pack.install");
    CHECK(result == "success");
    CHECK(detail.find("2/3") != std::string::npos);
}

// Gate 8 finding (#3479/#3481, security-guardian): errors[] can reflect attacker-controlled
// YAML field values (e.g. an invalid `mode:` quoted verbatim into the error string) — unlike
// `id` (server-generated hex, always valid UTF-8). The default strict nlohmann::json dump()
// throws on invalid UTF-8, which would 500 AFTER the partial install (and its audit row)
// already committed. Proves the fix (error_handler_t::replace) instead of just asserting it.
TEST_CASE("REST: POST /api/product-packs survives invalid UTF-8 reflected into a per-item error "
          "string instead of 500ing after the partial install already committed",
          "[product_pack_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, product_pack_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);

    InstructionStore instruction_store{pool};
    REQUIRE(instruction_store.is_open());

    ProductPackRestHarness h{&store, &instruction_store};

    // The invalid byte sequence (\xFF\xFE, never valid UTF-8) is embedded directly in the
    // bundle text — this store's YAML extraction is a plain substring scan, not a UTF-8-aware
    // parser, so it passes the raw bytes through into `mode:`'s value verbatim, which
    // install_fn then quotes into its "invalid approval mode: <value>" error string.
    const std::string kBadUtf8Bundle =
        "apiVersion: yuzu.io/v1alpha1\n"
        "kind: ProductPack\n"
        "name: test-rest-bad-utf8\n"
        "version: 1.0.0\n"
        "description: One item succeeds, one fails with invalid UTF-8 in the reflected value\n"
        "---\n"
        "apiVersion: yuzu.io/v1alpha1\n"
        "kind: InstructionDefinition\n"
        "name: rest-item-ok\n"
        "plugin: system\n"
        "action: noop\n"
        "---\n"
        "apiVersion: yuzu.io/v1alpha1\n"
        "kind: InstructionDefinition\n"
        "name: rest-item-bad-utf8\n"
        "plugin: system\n"
        "action: noop\n"
        "mode: bad-\xFF\xFE-mode\n";

    auto res = h.sink.dispatch("POST", "/api/product-packs", kBadUtf8Bundle, "text/plain");
    REQUIRE(res);
    // Must NOT be a 500 (the pre-fix failure mode) — the partial install already committed by
    // the time the response is built, so the response itself must survive serializing it.
    CHECK(res->status == 201);
    // The body must be well-formed JSON (nlohmann::json::parse throws on malformed input,
    // failing this REQUIRE, if the response were ever empty/truncated by a mid-dump() throw).
    nlohmann::json body;
    REQUIRE_NOTHROW(body = nlohmann::json::parse(res->body));
    REQUIRE(body.contains("errors"));
    REQUIRE(body["errors"].size() == 1);
}
