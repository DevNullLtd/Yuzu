// Shared by test_engine_principal_lifecycle.cpp (REST) and test_mcp_server.cpp (MCP twin) so both
// surfaces of the engine-principal revoke are driven by ONE identity-revoke fault (#6716).
// Header-only and file-agnostic: the caller passes the pool of the database under test.
#pragma once

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <exception>
#include <string>
#include <vector>

namespace yuzu::server::test {

/// Puts a trigger on the real `engine_principals` table of the throwaway database the pool points
/// at to make the identity revoke misbehave after the credential revoke (a different table) has
/// succeeded:
///   Raise: the UPDATE errors, so `EnginePrincipalStore::revoke` returns an error.
///   Skip:  the UPDATE is skipped and the row stays active, so `revoke` reports "changed nothing".
///   Race:  a rival revoke "wins" first: the row is revoked by a nested UPDATE and the outer one is
///          skipped, so `revoke` reports "changed nothing" for an identity that is now revoked.
///          This is what a concurrent DELETE landing between the handler's read and its write
///          looks like. (A trigger on `api_tokens` cannot do this: it lives in another database.)
/// The database may be shared with other cases, so the trigger is dropped on scope exit. Nothing
/// here throws out of a destructor: cleanup failures are recorded as test failures
/// (non-throwing) so a case that failed to clean up is visible rather than silently poisoning the
/// next one.
class IdentityRevokeFault {
  public:
    enum class Mode { Raise, Skip, Race };

    explicit IdentityRevokeFault(yuzu::server::pg::PgPool& pool, Mode mode) : pool_(&pool) {
        std::string body;
        switch (mode) {
        case Mode::Raise:
            body = "IF NEW.lifecycle_state = 'revoked' THEN "
                   "RAISE EXCEPTION 'yuzu_test identity revoke fault'; END IF;";
            break;
        case Mode::Skip:
            body = "IF NEW.lifecycle_state = 'revoked' THEN RETURN NULL; END IF;";
            break;
        case Mode::Race:
            body = "IF NEW.lifecycle_state = 'revoked' AND OLD.lifecycle_state = 'active' AND "
                   "pg_trigger_depth() = 1 THEN "
                   "UPDATE engine_principal_store.engine_principals SET "
                   "lifecycle_state = 'revoked', revoked_at = NEW.revoked_at "
                   "WHERE principal_id = NEW.principal_id; RETURN NULL; END IF;";
            break;
        }
        // A leftover from an earlier failed run must not break this one.
        drop_all();
        std::string err;
        if (!try_run("CREATE OR REPLACE FUNCTION engine_principal_store.yuzu_test_revoke_fault() "
                     "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " +
                         body + " RETURN NEW; END $$",
                     err)) {
            drop_all();
            FAIL("IdentityRevokeFault: creating the trigger function failed: " << err);
        }
        if (!try_run("CREATE TRIGGER yuzu_test_revoke_fault BEFORE UPDATE ON "
                     "engine_principal_store.engine_principals FOR EACH ROW EXECUTE FUNCTION "
                     "engine_principal_store.yuzu_test_revoke_fault()",
                     err)) {
            // The function exists and the destructor will not run for a throwing constructor.
            drop_all();
            FAIL("IdentityRevokeFault: creating the trigger failed: " << err);
        }
        removed_ = false;
    }
    ~IdentityRevokeFault() noexcept { remove(); }
    IdentityRevokeFault(const IdentityRevokeFault&) = delete;
    IdentityRevokeFault& operator=(const IdentityRevokeFault&) = delete;

    /// Drops the trigger and function. Never throws; a failure is recorded as a test failure.
    void remove() noexcept {
        if (removed_)
            return;
        if (drop_all())
            removed_ = true;
    }

  private:
    /// Runs one statement on a pooled lease. Never throws.
    bool try_run(const std::string& sql, std::string& err) noexcept {
        try {
            auto lease = pool_->acquire();
            if (!lease) {
                err = "no pool lease";
                return false;
            }
            yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
            if (!r.ok()) {
                err = PQresultErrorMessage(r.get());
                return false;
            }
            return true;
        } catch (const std::exception& e) {
            err = e.what();
            return false;
        } catch (...) {
            err = "unknown exception";
            return false;
        }
    }

    /// Drops both objects (trigger first: the function depends on it). True when both are gone.
    bool drop_all() noexcept {
        std::string e1;
        std::string e2;
        const bool trig = try_run("DROP TRIGGER IF EXISTS yuzu_test_revoke_fault ON "
                                  "engine_principal_store.engine_principals",
                                  e1);
        const bool fn =
            try_run("DROP FUNCTION IF EXISTS engine_principal_store.yuzu_test_revoke_fault()", e2);
        if (!trig || !fn) {
            try {
                FAIL_CHECK("IdentityRevokeFault cleanup failed (the engine clone may "
                               "still carry the trigger): trigger: "
                               << e1 << " function: " << e2);
            } catch (...) {
            }
        }
        return trig && fn;
    }

    yuzu::server::pg::PgPool* pool_; // the pool of the database whose engine_principals is faulted
    bool removed_{true}; // nothing armed until the constructor has installed both objects
};

} // namespace yuzu::server::test
