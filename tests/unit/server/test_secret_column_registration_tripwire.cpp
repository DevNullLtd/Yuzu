// #2530 registered-column trip-wire (contract item 4 / C3).
//
// WHY THIS TEST EXISTS: `pg::SecretCodec::rewrap_all` scans a registered
// secret column with a single UNBATCHED, client-side-materialized query — it
// currently reads the whole column into memory in one shot. That is a real
// scale risk that a single registrant (auth.users.mfa_totp_secret) has kept
// invisible so far. Registering a SECOND secret column would multiply that
// scan and can push a rewrap past `statement_timeout` on a large table — the
// batching work (#2530 UP-10/11/12) is deliberately DEFERRED, not done here.
// This test pins the registered set at exactly one column so that the moment
// someone adds a second `register_secret_column` call THAT REACHES THIS
// PRODUCTION `AuthDB` CONSTRUCTION PATH (server.cpp's FileKeyProvider ->
// SecretCodec -> AuthDB wiring), THIS test fails loudly and forces an
// explicit decision about the deferred batching work, rather than the
// second column silently inheriting whatever ceiling the first one was
// living under. #2530 G7-S4: this test observes exactly one construction
// site (AuthDB's), not "anywhere in the codebase" — a NEW secret-bearing
// store that registers its own column via its own constructor is invisible
// to this test unless it is added to the same production wiring this test
// constructs. Whoever adds a second secret-bearing store must add its OWN
// trip-wire test (or extend this one to also construct that store) — read
// this comment before updating the expected set below.
//
// Do NOT "fix" this by adding a runtime guard inside SecretCodec that refuses
// a second registration — SecretCodec is, by design, the registry for every
// secret-bearing store in the server, and a second legitimate store adding
// its own secret column is normal schema evolution. A runtime refusal would
// turn that into a boot outage. This test is the deliberate, reviewable
// speed bump instead (architect-ruled, #2530 contract §C3).
//
// PRODUCTION WIRING, NOT A HAND-BUILT CODEC: this test constructs its own
// `pg::SecretCodec` and hands it to a REAL `yuzu::server::AuthDB` by
// reference (AuthDB's constructor takes `pg::SecretCodec&`), then reads
// `registered_columns()` back off the codec it owns. That is exactly the
// production registration path in server.cpp (FileKeyProvider -> SecretCodec
// constructed-not-inited -> AuthDB, which registers `mfa_totp_secret` in its
// constructor at auth_db.cpp:431) with no new accessor added to AuthDB and no
// hand-rolled substitute registration. `SecretCodec::init()` is deliberately
// NOT called here — the trip-wire only cares about what got registered, not
// substrate-level KEK bootstrap.

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/secret_codec.hpp"

#include <yuzu/server/auth_db.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::server::AuthDB;
using yuzu::server::FileKeyProvider;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::SecretCodec;

TEST_CASE("SecretCodec registered-column trip-wire: production AuthDB registration is exactly "
          "{auth, users, mfa_totp_secret, id} (#2530)",
          "[pg][secret_codec][kek][tripwire]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    yuzu::test::TempDir keys{"yuzu_test_"};
    FileKeyProvider provider(keys.path);
    // Constructed only — never init()'d, matching the production order in
    // server.cpp (FileKeyProvider -> SecretCodec -> AuthDB -> init()). AuthDB
    // registers its column in its own constructor, before init() ever runs.
    SecretCodec codec(provider);

    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    AuthDB auth_db{pool, codec};
    REQUIRE(auth_db.is_open());

    const auto cols = codec.registered_columns();
    REQUIRE(cols.size() == 1);
    CHECK(cols[0].store == "auth");
    CHECK(cols[0].table == "users");
    CHECK(cols[0].column == "mfa_totp_secret");
    CHECK(cols[0].pk_column == "id");
}
