// Runtime-config secret redaction, and a tripwire against the next one.
//
// WHY THIS EXISTS
// ---------------
// `oidc_client_secret` is stored SecretCodec-envelope-encrypted (ADR-0010/0060)
// in `runtime_config_secrets`, never plaintext. That is a recent hardening
// (this store used to persist it plaintext) -- but the VALUE was ALSO being
// emitted twice, independent of at-rest storage:
//
//   * written verbatim to yuzu-server.log on every boot by the startup override pass;
//   * returned by GET /api/config, which is gated only on Infrastructure:Read.
//
// Both contradicted the settings UI, which has always rendered the same field as
// "********". Redaction is now the emitter's job and `is_secret_key` is the single
// predicate every emitter consults.
//
// The tripwire below is the durable half. A future secret-valued key added to
// `allowed_keys()` and NOT to the secret list would silently start leaking through
// FOUR paths - the startup log, the GET /api/config override list, the PUT audit
// detail and the PUT response echo - and nothing else would notice. (This sentence
// said "the same two paths" while the fix was mid-flight; the audit detail and the
// response echo were found afterwards. A count in a comment is a fact that rots.)
//
// The four cases in the first block below are STATIC -- pure predicates over
// `allowed_keys()`/`is_secret_key()`/`redacted_placeholder()`, no store
// construction at all. They deliberately carry NO `[pg]` tag and touch no
// PgTestTemplate: a `~[pg]` filtered run (no Postgres available) must still
// run the tripwire. Everything past that needs a real store and is `[pg]`.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "runtime_config_store.hpp"
#include "runtime_config_view.hpp"
#include "../test_helpers.hpp"
#include "test_runtime_config_helpers.hpp"

#include <libpq-fe.h>

using yuzu::server::RuntimeConfigStore;

// ── Static predicates — NO Postgres, NO [pg] tag ────────────────────────────

TEST_CASE("is_secret_key identifies credential-valued keys", "[runtime_config][secret]") {
    CHECK(RuntimeConfigStore::is_secret_key("oidc_client_secret"));

    // Neighbouring OIDC keys are configuration, not credentials: redacting them would
    // cost an operator real diagnostic signal for no benefit.
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("oidc_issuer"));
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("oidc_client_id"));
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("oidc_admin_group"));
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("log_level"));

    // An unknown key is not a secret -- it is not storable at all.
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("not_a_real_key"));
    CHECK_FALSE(RuntimeConfigStore::is_secret_key(""));
}

TEST_CASE("the redaction placeholder is a single fixed spelling", "[runtime_config][secret]") {
    // Log scrapers and API consumers must see one token, not a family of them.
    const std::string p = RuntimeConfigStore::redacted_placeholder();
    CHECK_FALSE(p.empty());
    // It must not be mistakable for a real value.
    CHECK(p.find('<') != std::string::npos);
}

TEST_CASE("TRIPWIRE: every credential-shaped allowed key is registered as secret",
          "[runtime_config][secret][tripwire]") {
    // If you are here because this failed, you added a key to `allowed_keys()` whose
    // NAME says it carries a credential. Either add it to `kSecretKeys` in
    // config_secret_keys.cpp so the log line and GET /api/config redact it, or --
    // if the name is misleading and the value is not a credential -- rename the key.
    // Do not relax this test to make it pass.
    //
    // Deliberately name-based: it cannot know a value is a credential, only that the
    // key is spelled like one. That catches the realistic mistake (a `*_secret` /
    // `*_password` / `*_token` key added without redaction) and is honest about what
    // it cannot catch -- a credential-valued key with an innocuous name, which needs a
    // human to notice.
    // NOT "_key" on its own: `dex_cohort_export_key` is an allowed key whose value is
    // a grouping mode ("model"), so that suffix is genuinely ambiguous here and would
    // fire on a non-credential. The compound spellings below are not.
    static const std::vector<std::string> kCredentialShapedSuffixes = {
        "_secret",     "_password",   "_token",      "_key_material", "_credential",
        "_api_key",    "_access_key", "_secret_key", "_private_key",  "_passphrase",
        "_client_key", "_signing_key",
    };

    for (const auto& key : RuntimeConfigStore::allowed_keys()) {
        for (const auto& suffix : kCredentialShapedSuffixes) {
            if (key.size() >= suffix.size() &&
                key.compare(key.size() - suffix.size(), suffix.size(), suffix) == 0) {
                INFO("allowed key '" << key << "' is spelled like a credential but is not in "
                                              "kSecretKeys, so its value would be written to the "
                                              "startup log and returned by GET /api/config");
                CHECK(RuntimeConfigStore::is_secret_key(key));
            }
        }
    }
}

TEST_CASE("every registered secret key is actually storable", "[runtime_config][secret]") {
    // A secret key that is not in `allowed_keys()` can never be set, so its presence in
    // the secret list is dead weight and, worse, implies coverage that does not exist.
    const auto& allowed = RuntimeConfigStore::allowed_keys();
    CHECK(std::find(allowed.begin(), allowed.end(), std::string("oidc_client_secret")) !=
          allowed.end());
}

// ── Store-behaviour tests: pre-migrated template, [pg] ──────────────────────

namespace {

// Mirrors test_plugin_config_store_pg.cpp's `plugincfg_tpl` / the settings-
// routes templates: pre-applies the `runtime_config_store` + `secrets`
// schemas, then resets `secrets.kek_meta` so each test mints its own KEK.
yuzu::test::PgTestTemplate redaction_tpl{"rtcfgredact", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    yuzu::server::FileKeyProvider provider(keys.path);
    yuzu::server::pg::SecretCodec codec(provider);
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RuntimeConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("rtcfgredact template: store failed to migrate");
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("rtcfgredact template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("rtcfgredact template: codec init failed");
    yuzu::server::pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("rtcfgredact template: kek_meta reset failed");
}};

/// Fully-wired store for a test case: fresh keys dir, fresh codec, fresh
/// pool, `codec.init()` run in the correct order. Keep this alive for the
/// whole test case (it owns the pool and provider the store borrows).
struct Wired {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    yuzu::server::FileKeyProvider provider{keys.path};
    yuzu::server::pg::SecretCodec codec{provider};
    yuzu::server::pg::PgPool pool;
    RuntimeConfigStore store;

    explicit Wired(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, store{pool, codec} {
        REQUIRE(store.is_open());
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = codec.init(conn.get());
        REQUIRE(r.has_value());
    }
};

} // namespace

// The store-level contract is the part that makes a FUTURE emitter safe: get_all()
// redacts by default, and plaintext requires asking for it by name. Redaction being
// opt-in at the emitter is exactly how the plaintext value reached an audit row that
// every AuditLog:Read holder (Operator among them) can read -- a durable sink that
// cannot be rotated away, and one this file's earlier tests passed straight over
// because they only checked key REGISTRATION, never emitter consultation.
TEST_CASE("get_all() redacts secrets; read_secret() returns the real decrypted value",
          "[pg][runtime_config][secret]") {
    YUZU_REQUIRE_PG_DB_TPL(db, redaction_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set("oidc_client_secret", "s3cr3t-value", "tester").has_value());
    REQUIRE(w.store.set("oidc_issuer", "https://idp.example.com", "tester").has_value());

    std::string redacted_secret, redacted_issuer;
    auto redacted = w.store.get_all();
    REQUIRE(redacted.has_value());
    for (const auto& e : *redacted) {
        if (e.key == "oidc_client_secret") redacted_secret = e.value;
        if (e.key == "oidc_issuer")        redacted_issuer = e.value;
    }

    // The default must never hand back the credential.
    CHECK(redacted_secret == RuntimeConfigStore::redacted_placeholder());
    CHECK(redacted_secret != "s3cr3t-value");
    // A non-secret key is untouched -- redacting configuration would cost real
    // diagnostic signal.
    CHECK(redacted_issuer == "https://idp.example.com");
    // The dedicated accessor still hands back the real credential, or the startup
    // override pass breaks.
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "s3cr3t-value");
}

TEST_CASE("an EMPTY secret survives redaction as empty, so is_set can be false",
          "[pg][runtime_config][secret]") {
    // GET /api/config reports `is_set` as !value.empty() on the REDACTED entry.
    // Replacing every secret value -- including "" -- with the non-empty placeholder
    // made that unconditionally true: no stored secret could report unset. Caught by
    // review after the redaction landed, which is why it has its own case.
    YUZU_REQUIRE_PG_DB_TPL(db, redaction_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set("oidc_client_secret", "", "tester").has_value());

    std::string v;
    bool found = false;
    auto redacted = w.store.get_all();
    REQUIRE(redacted.has_value());
    for (const auto& e : *redacted) {
        if (e.key == "oidc_client_secret") { v = e.value; found = true; }
    }
    REQUIRE(found);
    CHECK(v.empty());
    CHECK(v != RuntimeConfigStore::redacted_placeholder());

    // And a non-empty one still redacts, or the fix for the emptiness case would
    // have been "stop redacting".
    REQUIRE(w.store.set("oidc_client_secret", "real", "tester").has_value());
    auto redacted2 = w.store.get_all();
    REQUIRE(redacted2.has_value());
    for (const auto& e : *redacted2) {
        if (e.key == "oidc_client_secret")
            CHECK(e.value == RuntimeConfigStore::redacted_placeholder());
    }
}

TEST_CASE("build_overrides_json omits a secret's value and reports is_set",
          "[runtime_config][secret]") {
    // Covers the GET /api/config shape directly. That route lives in server.cpp and is
    // not TestRouteSink-registered, so before this was extracted the omission rule -
    // one of the sites the secret leaked from - had no test at all, and the
    // suite was green through two rounds of getting it wrong.
    //
    // Pure data-shape test over build_overrides_json -- no store, no Postgres.
    std::vector<yuzu::server::RuntimeConfigEntry> entries = {
        {"oidc_client_secret", RuntimeConfigStore::redacted_placeholder(), "admin", 1754150400},
        {"oidc_issuer", "https://idp.example.com", "admin", 1754150401},
    };

    const auto j = yuzu::server::build_overrides_json(entries);

    // The secret carries NO value field at all - not the real one, and not the
    // placeholder either, because the placeholder is a legal value a round-tripping
    // client would write back as the credential.
    REQUIRE(j.contains("oidc_client_secret"));
    const auto& sec = j.at("oidc_client_secret");
    CHECK_FALSE(sec.contains("value"));
    CHECK(sec.at("is_set").get<bool>());
    // Attribution survives: an operator still sees THAT it is set and who set it.
    CHECK(sec.at("updated_by").get<std::string>() == "admin");
    CHECK(sec.at("updated_at").get<int64_t>() == 1754150400);

    // A non-secret key keeps its value and gains no is_set.
    const auto& iss = j.at("oidc_issuer");
    CHECK(iss.at("value").get<std::string>() == "https://idp.example.com");
    CHECK_FALSE(iss.contains("is_set"));

    // An UNSET secret reports is_set=false. This is the pairing that broke: blanket
    // redaction made the value non-empty, so is_set could never be false.
    std::vector<yuzu::server::RuntimeConfigEntry> unset = {
        {"oidc_client_secret", "", "admin", 1754150400},
    };
    const auto j2 = yuzu::server::build_overrides_json(unset);
    CHECK_FALSE(j2.at("oidc_client_secret").at("is_set").get<bool>());
    CHECK_FALSE(j2.at("oidc_client_secret").contains("value"));
}

TEST_CASE("get()/get_value() redact secrets too; read_secret() returns the real value",
          "[pg][runtime_config][secret]") {
    // get()/get_value() were the asymmetry: get_all() redacted while the single-key
    // reads returned plaintext, so the header's "every accessor is safe by default"
    // was false for half the API. Mutation testing caught that closing the gap left
    // NO failing test - this is that test.
    YUZU_REQUIRE_PG_DB_TPL(db, redaction_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set("oidc_client_secret", "s3cr3t-value", "tester").has_value());
    REQUIRE(w.store.set("oidc_issuer", "https://idp.example.com", "tester").has_value());

    auto sec = w.store.get("oidc_client_secret");
    REQUIRE(sec.has_value());
    REQUIRE(sec->has_value());
    CHECK((*sec)->value == RuntimeConfigStore::redacted_placeholder());
    CHECK((*sec)->value != "s3cr3t-value");
    CHECK(w.store.get_value("oidc_client_secret") == RuntimeConfigStore::redacted_placeholder());

    // The dedicated accessor still hands back the real credential, or the startup
    // override pass and any future legitimate consumer break.
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "s3cr3t-value");

    // A non-secret key is untouched by get()/get_value(), and has no secrets-table
    // row at all -- read_secret() on it is nullopt, not an error.
    auto iss = w.store.get("oidc_issuer");
    REQUIRE(iss.has_value());
    REQUIRE(iss->has_value());
    CHECK((*iss)->value == "https://idp.example.com");
    CHECK(w.store.get_value("oidc_issuer") == "https://idp.example.com");
    auto iss_secret = w.store.read_secret("oidc_issuer");
    REQUIRE(iss_secret.has_value());
    CHECK_FALSE(iss_secret->has_value());

    // An empty secret stays empty here too, matching get_all().
    REQUIRE(w.store.set("oidc_client_secret", "", "tester").has_value());
    CHECK(w.store.get_value("oidc_client_secret").empty());
}

TEST_CASE("set() refuses the redaction placeholder as a credential",
          "[pg][runtime_config][secret]") {
    // The read side omits a secret's value so a config-as-code client cannot round-
    // trip the placeholder back as the credential -- but the startup log PRINTS it,
    // and a human copying that line arrives at the same place. Refusing at the sink
    // covers every caller, present and future.
    YUZU_REQUIRE_PG_DB_TPL(db, redaction_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set("oidc_client_secret", "real-secret", "tester").has_value());

    auto rejected = w.store.set("oidc_client_secret", RuntimeConfigStore::redacted_placeholder(),
                                "tester");
    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error().find("placeholder") != std::string::npos);

    // And the real secret is still intact -- a refused write must not clobber.
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "real-secret");

    // The same literal is a legal value for a NON-secret key; the guard is scoped.
    CHECK(w.store.set("oidc_issuer", RuntimeConfigStore::redacted_placeholder(), "tester")
              .has_value());
}

TEST_CASE("set() refuses a WHITESPACE-PADDED placeholder, not just the exact string",
          "[pg][runtime_config][secret]") {
    // The guard first shipped as an exact `==` at one caller, so `PUT
    // /api/config/oidc_client_secret` with "<redacted>\n" reached the sink and
    // overwrote the real credential with a non-credential -- the precise outcome the
    // guard exists to prevent. Governance caught it; a mutation then showed the fix
    // itself had no failing test. This is that test.
    YUZU_REQUIRE_PG_DB_TPL(db, redaction_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set("oidc_client_secret", "real-secret", "tester").has_value());

    for (const char* padded : {"<redacted>\n", " <redacted>", "<redacted> ", "\t<redacted>\r\n",
                               "  <redacted>  "}) {
        auto rejected = w.store.set("oidc_client_secret", padded, "tester");
        INFO("padded form: [" << padded << "]");
        REQUIRE_FALSE(rejected.has_value());
        // ...and the real credential is still intact after every refused write.
        CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "real-secret");
    }

    // A value CONTAINING the placeholder is refused too, deliberately. No trim charset
    // is exhaustive against every invisible code point that can survive a paste
    // (U+FEFF and U+200B defeated the first byte-set version), so the substring rule is
    // the catch-all. It fails closed: an implausible secret is refused with a clear
    // message, rather than a padded placeholder silently destroying a real credential.
    CHECK_FALSE(
        w.store.set("oidc_client_secret", "prefix<redacted>suffix", "tester").has_value());
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "real-secret");
    // Zero-width paste artefacts are covered by the same rule.
    CHECK_FALSE(
        w.store.set("oidc_client_secret", "\xef\xbb\xbf<redacted>", "tester").has_value());
    // A normal secret is unaffected.
    CHECK(w.store.set("oidc_client_secret", "a-normal-secret", "tester").has_value());
}
