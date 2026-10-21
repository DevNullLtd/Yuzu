#pragma once

// test_auth_db_rbac_pg_template.hpp - the "authdbrbacwire" PgTestTemplate: the plain AuthDB
// template (test_auth_db_pg_helper.hpp) PLUS a migrated, default-seeded `rbac_store` schema.
//
// Why a SEPARATE template and not a change to "authdbwire": the plain template is cloned by ~160
// fixtures, several of which assert on RbacStore's own migration/seeding (or share state through
// AuthDbPgShared, whose TRUNCATE reset does not reach the rbac_store schema), so seeding
// `rbac_store` into it would change what those tests start from. This template is OPT-IN, for the
// #4966 fixtures that always construct an RbacStore on the AuthDbPg pool (the last-Administrator
// guard needs it). A clone's `RbacStore` constructor then finds every migration applied
// (`PgMigrationRunner` skips applied versions) and its seed statements are no-ops, which removes
// the four migrations from every fixture construction.
//
//   yuzu::test::AuthDbPg db{0, false, &yuzu::test::auth_db_rbac_pg_template};

#include "rbac_store.hpp"
#include "test_auth_db_pg_helper.hpp"

#include "pg/pg_pool.hpp"

#include <stdexcept>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_auth_db_rbac_pg_template(const std::string& dsn) {
    setup_auth_db_pg_template(dsn); // AuthDB first, exactly as the plain template builds it
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::RbacStore store{pool}; // migrates rbac_store and seeds its defaults
    if (!store.is_open())
        throw std::runtime_error("authdb+rbac template: RbacStore failed to open");
}
} // namespace detail

inline PgTestTemplate auth_db_rbac_pg_template{"authdbrbacwire",
                                               &detail::setup_auth_db_rbac_pg_template};

} // namespace yuzu::test
