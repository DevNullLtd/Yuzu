#include "pg_background_build.hpp"

#include "pg_exec.hpp"

#include <spdlog/spdlog.h>

#include <memory>
#include <optional>

namespace yuzu::server::pg {

namespace {
bool valid_ident(const std::string& s) {
    if (s.empty() || s.size() > 63)
        return false;
    for (const char c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    return true;
}
} // namespace

std::string IndexSpec::spec_text() const {
    return method + " (" + columns + ")" + (predicate.empty() ? std::string{} : " WHERE " + predicate);
}

std::string IndexSpec::sql() const {
    return "CREATE INDEX CONCURRENTLY IF NOT EXISTS \"" + name + "\" ON \"" + schema + "\".\"" + table +
           "\" USING " + method + " (" + columns + ")" +
           (predicate.empty() ? std::string{} : " WHERE " + predicate);
}

bool BuildCancel::arm(PGconn* conn) {
    std::lock_guard<std::mutex> lk(mu_);
    if (stop_.load(std::memory_order_acquire))
        return false; // a stop that landed before we were armed: refuse, the caller reports `stopped`
    cancel_.reset(PQgetCancel(conn));
    return true;
}

void BuildCancel::disarm() {
    std::lock_guard<std::mutex> lk(mu_);
    cancel_.reset();
}

void BuildCancel::cancel() {
    std::lock_guard<std::mutex> lk(mu_);
    stop_.store(true, std::memory_order_release);
    if (cancel_) {
        char errbuf[256] = {0};
        if (!PQcancel(cancel_.get(), errbuf, sizeof errbuf))
            spdlog::warn("pg_background_build: PQcancel failed: {}", errbuf);
    }
}

BuildResult result_from_failure(PGconn* conn, const PgResult& r) {
    BuildResult b;
    if (const char* st = r ? PQresultErrorField(r.get(), PG_DIAG_SQLSTATE) : nullptr)
        b.sqlstate = st;
    // The PRIMARY message only (SQLERRM-shaped): PQerrorMessage also carries DETAIL/HINT/CONTEXT, which
    // can quote data values; this text is logged and written to a table comment.
    const char* primary = r ? PQresultErrorField(r.get(), PG_DIAG_MESSAGE_PRIMARY) : nullptr;
    b.error = (b.sqlstate.empty() ? std::string() : b.sqlstate + " ") +
              (primary ? std::string(primary)
                       : (conn ? std::string(PQerrorMessage(conn)) : std::string("no connection")));
    while (!b.error.empty() && (b.error.back() == '\n' || b.error.back() == '\r'))
        b.error.pop_back();
    b.cancelled = b.sqlstate == "57014";
    return b;
}

UnboundedSession::UnboundedSession(PGconn* conn) noexcept : conn_(conn) {
    PgResult a{PQexec(conn_, "SET statement_timeout = 0")};
    PgResult b{PQexec(conn_, "SET lock_timeout = 0")};
    armed_ = a.status() == PGRES_COMMAND_OK && b.status() == PGRES_COMMAND_OK;
}

UnboundedSession::~UnboundedSession() {
    // RESET restores the pool's per-connection defaults (30 s / 10 s). If it cannot be CONFIRMED (a
    // cancel landed during it, the connection dropped) the connection must never go back to the pool
    // with timeouts of 0. Any doubt discards the session: PQreset opens a brand-new one from the
    // original connection parameters (the pool's defaults are connection options), and it is then
    // VERIFIED; if even that is in doubt the backend is terminated so the pool sees a BAD connection.
    const int forced = force_reset_failure_for_test.load(std::memory_order_acquire);
    PgResult a{forced ? PgResult{} : PgResult{PQexec(conn_, "RESET statement_timeout")}};
    PgResult b{forced ? PgResult{} : PgResult{PQexec(conn_, "RESET lock_timeout")}};
    if (!forced && a.status() == PGRES_COMMAND_OK && b.status() == PGRES_COMMAND_OK)
        return;
    spdlog::warn("pg_background_build: RESET of the session timeouts failed; discarding the session");
    PQreset(conn_);
    if (forced != 2 && PQstatus(conn_) == CONNECTION_OK) {
        PgResult v{PQexec(conn_, "SELECT current_setting('statement_timeout') <> '0' AND "
                                 "current_setting('lock_timeout') <> '0'")};
        if (v.status() == PGRES_TUPLES_OK && PQntuples(v.get()) == 1 &&
            std::string(PQgetvalue(v.get(), 0, 0)) == "t")
            return; // a fresh session with the pool's timeouts
    }
    // Still in doubt: terminate (retried; a further cancel can interrupt it) so the pool discards it.
    for (int i = 0; i < 3; ++i) {
        PgResult t{PQexec(conn_, "SELECT pg_terminate_backend(pg_backend_pid())")};
        if (PQstatus(conn_) != CONNECTION_OK)
            break;
    }
}

bool index_is_valid(PGconn* conn, const std::string& schema, const std::string& index_name) {
    PgResult r = exec_params(
        conn,
        "SELECT i.indisvalid AND i.indisready FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2",
        std::vector<std::string>{schema, index_name});
    return r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 &&
           std::string(PQgetvalue(r.get(), 0, 0)) == "t";
}

namespace {
// One statement on an armed connection: a stop requested before or during it yields `stopped`.
BuildResult run_cancellable(PGconn* conn, const std::string& sql, BuildCancel* cancel) {
    std::optional<BuildCancel::ScopedArm> arm;
    if (cancel) {
        arm.emplace(*cancel, conn);
        if (!arm->armed())
            return {false, true, "", "stopped", false};
    }
    PgResult r{PQexec(conn, sql.c_str())};
    arm.reset(); // disarm before touching the result
    if (r.status() == PGRES_COMMAND_OK)
        return {true, false, "", "", false};
    BuildResult b = result_from_failure(conn, r);
    b.stopped = b.cancelled && cancel && cancel->stop_requested();
    return b;
}
} // namespace

BuildResult ensure_index_concurrently(PGconn* conn, const IndexSpec& spec, BuildCancel* cancel) {
    if (!valid_ident(spec.schema) || !valid_ident(spec.name) || !valid_ident(spec.table))
        return {false, false, "", "invalid identifier", false};
    PgResult ex = exec_params(
        conn,
        "SELECT i.indisvalid AND i.indisready, coalesce(obj_description(c.oid, 'pg_class'), '') FROM "
        "pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = "
        "c.relnamespace WHERE n.nspname = $1 AND c.relname = $2",
        std::vector<std::string>{spec.schema, spec.name});
    if (ex.status() != PGRES_TUPLES_OK)
        return result_from_failure(conn, ex);
    if (PQntuples(ex.get()) == 1) {
        const bool valid = std::string(PQgetvalue(ex.get(), 0, 0)) == "t";
        const bool same = std::string(PQgetvalue(ex.get(), 0, 1)) == spec.spec_text();
        if (valid && same)
            return {true, false, "", "", false};
        spdlog::warn("pg_background_build: dropping {} index {}.{} before rebuilding",
                     valid ? "STALE (definition differs)" : "INVALID", spec.schema, spec.name);
        UnboundedSession lift{conn};
        auto d = run_cancellable(conn, "DROP INDEX CONCURRENTLY IF EXISTS \"" + spec.schema + "\".\"" +
                                           spec.name + "\"",
                                 cancel);
        if (!d.ok)
            return d;
    }
    {
        UnboundedSession lift{conn};
        if (!lift.armed())
            return {false, false, "", "could not lift the session timeouts for the index build", false};
        auto c = run_cancellable(conn, spec.sql(), cancel);
        if (!c.ok)
            return c;
    } // timeouts restored BEFORE the stamp: it must not wait unbounded and uncancellable
    // Stamp the spec so a later definition change is detected (COMMENT ON INDEX takes the index's
    // identifier, which is validated above; the text is escaped by libpq).
    std::unique_ptr<char, void (*)(void*)> lit{
        PQescapeLiteral(conn, spec.spec_text().c_str(), spec.spec_text().size()), [](void* p) { PQfreemem(p); }};
    if (!lit)
        return {false, false, "", "could not escape the index stamp", false};
    PgResult s{PQexec(conn, ("COMMENT ON INDEX \"" + spec.schema + "\".\"" + spec.name + "\" IS " + lit.get()).c_str())};
    if (s.status() != PGRES_COMMAND_OK)
        return result_from_failure(conn, s);
    return {true, false, "", "", false};
}

BuildResult run_batched_reconcile(const BatchedReconcile& step, const std::function<bool()>& should_stop,
                                  std::size_t* batches_run) {
    std::string cursor;
    std::size_t n = 0;
    for (;;) {
        if (should_stop && should_stop())
            return {false, true, "", "stopped", false};
        std::vector<std::string> batch;
        if (auto f = step.fetch(cursor, batch); !f.ok)
            return f;
        if (batch.empty())
            break;
        if (auto a = step.apply(batch); !a.ok)
            return a;
        ++n;
    }
    if (batches_run)
        *batches_run = n;
    return {true, false, "", "", false};
}

} // namespace yuzu::server::pg
