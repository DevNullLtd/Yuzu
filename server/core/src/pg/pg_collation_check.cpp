#include "pg_collation_check.hpp"

#include "../device_inventory_store.hpp" // kDeviceInventoryStoreSchema
#include "pg_exec.hpp"
#include "pg_pool.hpp"
#include "pg_raii.hpp"

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <exception>
#include <string>
#include <vector>

namespace yuzu::server::pg {

CollationVerdict decide_collation_verdict(const CollationFacts& facts) noexcept {
    if (!facts.column_exists)
        return CollationVerdict::NotApplicable;
    if (!facts.recorded)
        return CollationVerdict::NotApplicable;
    if (!facts.actual)
        return CollationVerdict::Unreadable;
    if (*facts.recorded != *facts.actual)
        return CollationVerdict::Mismatch;
    // Equal versions do not prove sound indexes while an invalid one exists (a failed REINDEX
    // CONCURRENTLY): hold, never conclude Ok. Reported as Unreadable so the gate is untouched.
    return facts.invalid_index ? CollationVerdict::Unreadable : CollationVerdict::Ok;
}

std::string invalid_index_failure_text() {
    return std::string("an invalid index exists in schema ") + kDeviceInventoryStoreSchema +
           ", typically a leftover of a failed REINDEX ... CONCURRENTLY; drop or rebuild it; the "
           "gate is held";
}

const char* to_string(CollationVerdict v) noexcept {
    for (const auto& entry : all_collation_verdicts())
        if (entry.verdict == v)
            return entry.name;
    return "unreadable";
}

const char* to_string(CollationGate g) noexcept {
    switch (g) {
    case CollationGate::Trusted:
        return "trusted";
    case CollationGate::Mismatch:
        return "mismatch";
    case CollationGate::Unproven:
        return "unproven";
    }
    return "unproven";
}

void seed_collation_metrics(yuzu::MetricsRegistry& metrics) {
    for (const auto& entry : all_collation_verdicts())
        (void)metrics.counter(kCollationCheckCounter, {{"result", entry.name}});
}

std::string quote_identifier(std::string_view name) {
    std::string out;
    out.reserve(name.size() + 2);
    out += '"';
    for (const char c : name) {
        if (c == '"')
            out += '"';
        out += c;
    }
    out += '"';
    return out;
}

std::string unreadable_failure_text(const std::string& failure, bool facts_read,
                                    const std::string& pool_error) {
    if (!failure.empty())
        return failure;
    if (facts_read)
        return "commit failed";
    if (!pool_error.empty())
        return "the pool's last error (may be from an earlier attempt): " + pool_error;
    return "could not run the collation version query";
}

namespace {

std::optional<std::string> nullable(PGresult* r, int row, int col) {
    if (PQgetisnull(r, row, col))
        return std::nullopt;
    return std::string(PQgetvalue(r, row, col));
}

} // namespace

CollationReport check_collation_version(PgPool& pool) noexcept {
    CollationReport out;
    try {
        CollationFacts facts;
        bool facts_read = false;
        std::string failure;
        const bool ok = pool.with_txn_for(kCollationCheckAcquireTimeout, [&](PGconn* c) -> bool {
            const std::string set_timeout = std::string("SET LOCAL statement_timeout = '") +
                                            kCollationCheckStatementTimeout + "'";
            PgResult t = exec_params(c, set_timeout.c_str(), std::vector<std::string>{});
            if (t.status() != PGRES_COMMAND_OK) {
                failure = PQerrorMessage(c);
                return false;
            }
            // pg_database.datcollversion exists from PostgreSQL 15. Naming a missing column is a
            // parse error, so look the column up first and only then select it.
            PgResult col = exec_params(c,
                                       "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute "
                                       "WHERE attrelid = 'pg_catalog.pg_database'::regclass "
                                       "AND attname = 'datcollversion' AND NOT attisdropped)",
                                       std::vector<std::string>{});
            if (col.status() != PGRES_TUPLES_OK || PQntuples(col.get()) != 1) {
                failure = PQerrorMessage(c);
                return false;
            }
            facts.column_exists = std::string(PQgetvalue(col.get(), 0, 0)) == "t";
            if (!facts.column_exists) {
                facts_read = true;
                return true;
            }
            PgResult row =
                exec_params(c,
                            "SELECT current_database(), d.datcollversion, "
                            "pg_catalog.pg_database_collation_actual_version(d.oid) "
                            "FROM pg_catalog.pg_database d WHERE d.datname = current_database()",
                            std::vector<std::string>{});
            if (row.status() != PGRES_TUPLES_OK || PQntuples(row.get()) != 1) {
                failure = row.status() != PGRES_TUPLES_OK
                              ? std::string(PQerrorMessage(c))
                              : std::string("no pg_database row for the current database");
                return false;
            }
            out.database = PQgetvalue(row.get(), 0, 0);
            facts.recorded = nullable(row.get(), 0, 1);
            facts.actual = nullable(row.get(), 0, 2);
            // The invalid-index fact matters only when the versions are equal (see
            // `decide_collation_verdict`), so it is read only then: every other verdict is
            // reached without this query, and cannot be made Unreadable by it.
            if (facts.recorded && facts.actual && *facts.recorded == *facts.actual) {
                PgResult inv = exec_params(
                    c,
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_index i "
                    "JOIN pg_catalog.pg_class c ON c.oid = i.indrelid "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE NOT i.indisvalid AND n.nspname = $1)",
                    std::vector<std::string>{kDeviceInventoryStoreSchema});
                if (inv.status() != PGRES_TUPLES_OK || PQntuples(inv.get()) != 1) {
                    failure = PQerrorMessage(c);
                    return false;
                }
                facts.invalid_index = std::string(PQgetvalue(inv.get(), 0, 0)) == "t";
            }
            facts_read = true;
            return true;
        });
        if (!ok || !facts_read) {
            out.verdict = CollationVerdict::Unreadable;
            // facts_read with ok false is a failed COMMIT, not a pool error.
            out.failure = unreadable_failure_text(failure, facts_read, pool.last_error());
            return out;
        }
        out.verdict = decide_collation_verdict(facts);
        out.recorded = facts.recorded.value_or("");
        out.actual = facts.actual.value_or("");
        if (out.verdict == CollationVerdict::Unreadable)
            out.failure = facts.invalid_index
                              ? invalid_index_failure_text()
                              : "the operating system reported no collation version for this "
                                "database";
    } catch (const std::exception& e) {
        out.verdict = CollationVerdict::Unreadable;
        // The text is best effort: assigning it can itself throw (out of memory), and this function
        // is noexcept, so the verdict above is the part that must survive.
        try {
            out.failure = e.what();
        } catch (...) {}
    } catch (...) {
        out.verdict = CollationVerdict::Unreadable;
        try {
            out.failure = "unknown exception";
        } catch (...) {}
    }
    return out;
}

CollationStep next_collation_state(const CollationState& prev, CollationVerdict verdict) noexcept {
    CollationStep step;
    switch (verdict) {
    case CollationVerdict::Ok:
        step.next = {CollationLast::Ok, false};
        step.gauge = GaugeAction::SetZero;
        if (prev.last == CollationLast::Mismatch)
            step.log = LogAction::InfoCleared;
        else if (prev.last != CollationLast::Ok)
            step.log = LogAction::InfoMatches;
        break;
    case CollationVerdict::Mismatch:
        step.next = {CollationLast::Mismatch, false};
        step.gauge = GaugeAction::SetOne;
        if (prev.last != CollationLast::Mismatch)
            step.log = LogAction::ErrorMismatch;
        break;
    case CollationVerdict::NotApplicable:
        step.next = {CollationLast::NotApplicable, false};
        step.gauge = GaugeAction::Remove;
        if (prev.last == CollationLast::Mismatch)
            step.log = LogAction::InfoMismatchNoLongerApplies;
        else if (prev.last != CollationLast::NotApplicable)
            step.log = LogAction::InfoNotApplicable;
        break;
    case CollationVerdict::Unreadable:
        step.next = {prev.last, true};
        step.gauge = GaugeAction::Leave;
        if (!prev.unreadable)
            step.log = LogAction::WarnUnreadable;
        break;
    }
    return step;
}

void report_collation_check(const CollationReport& report, yuzu::MetricsRegistry* metrics,
                            CollationState& state, std::atomic<CollationGate>* gate) noexcept {
    try {
        const CollationStep step = next_collation_state(state, report.verdict);
        // A CONCLUSIVE verdict publishes first, before the best-effort metric and log work below,
        // so a throw there cannot withhold it: the gate is safety state. An Unreadable report
        // publishes NOTHING. `step.next.last` for an Unreadable is the carried-over `state.last`,
        // and `state` lags the gate whenever the work below threw after a conclusive store (it
        // advances last), so recomputing from it could write a stale value over a newer one (a
        // standing Mismatch replaced by Trusted). The surviving gate value, or the boot value
        // Unproven, is the only correct answer to "the check could not run".
        if (gate && report.verdict != CollationVerdict::Unreadable)
            gate->store(gate_for(step.next.last), std::memory_order_release);
        // `state` advances LAST. The transition-only log lines (the mismatch ERROR, the unreadable
        // WARN, the clearing INFO) are decided by comparing a verdict with the previous state, so a
        // transient failure in the metric or log work below must leave the state behind: the next
        // report then repeats the transition (at-least-once) instead of losing its line for good.
        if (metrics) {
            metrics->counter(kCollationCheckCounter, {{"result", to_string(report.verdict)}})
                .increment();
            metrics->gauge(kCollationLastCompletedGauge)
                .set(static_cast<double>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count()));
        }
        if (metrics) {
            switch (step.gauge) {
            case GaugeAction::Leave:
                break;
            case GaugeAction::SetZero:
                metrics->gauge(kCollationMismatchGauge).set(0.0);
                break;
            case GaugeAction::SetOne:
                metrics->gauge(kCollationMismatchGauge).set(1.0);
                break;
            case GaugeAction::Remove:
                // Safe only because nothing holds a Gauge& to this family (every write above looks
                // it up by name); clearing the family invalidates such references.
                metrics->clear_gauge_family(kCollationMismatchGauge);
                break;
            }
        }
        const std::string db = ::yuzu::log_key_token(report.database);
        // The remedy is pasted into psql, so it may name the database only when the log token is
        // the real name byte for byte. A name the log token had to change (a control byte folded,
        // a long name shortened) would yield commands for a different database, so those cases
        // print a placeholder and say how to get the exact quoted name instead.
        const bool name_exact = db == report.database;
        const std::string quoted = name_exact ? quote_identifier(db) : std::string{"<name>"};
        const std::string name_note =
            name_exact
                ? std::string{}
                : std::string{" The database name above is not shown exactly (a control byte was "
                              "replaced or a long name shortened), so replace <name> with the "
                              "result of SELECT quote_ident(current_database()) run while "
                              "connected to that database; do not type the name from this line."};
        switch (step.log) {
        case LogAction::None:
            break;
        case LogAction::InfoMatches:
            spdlog::info("[PG] database '{}' collation version {} matches the operating system's",
                         db, ::yuzu::log_key_token(report.recorded));
            break;
        case LogAction::InfoCleared:
            spdlog::info("[PG] database '{}' collation version {} now matches the operating "
                         "system's again; the earlier mismatch is cleared (this compares "
                         "versions only; it does not show that the indexes were rebuilt)",
                         db, ::yuzu::log_key_token(report.recorded));
            break;
        case LogAction::ErrorMismatch:
            spdlog::error(
                "[PG] database '{}' records collation version {} but the operating "
                "system now reports {}. Indexes on text columns may be ordered under the old "
                "rules, and an ordered read of a text key (a keyset page walk) can skip or repeat "
                "rows. Remedy, in this order: connect to that database; reindex it (REINDEX "
                "DATABASE CONCURRENTLY {} on a server that is serving traffic, or REINDEX DATABASE "
                "{} with the Yuzu servers stopped); run ALTER DATABASE {} REFRESH COLLATION "
                "VERSION (only once the reindex has finished for every index). The server checks "
                "again every minute while this stands, so this clears "
                "without a restart.{} See docs/user-manual/server-admin.md, 'PostgreSQL collation "
                "version'. The server keeps running.",
                db, ::yuzu::log_key_token(report.recorded), ::yuzu::log_key_token(report.actual),
                quoted, quoted, quoted, name_note);
            break;
        case LogAction::WarnUnreadable:
            spdlog::warn(
                "[PG] could not check the database collation version (continuing; the "
                "check is repeated every minute until one concludes, and this is logged once "
                "per spell): {}",
                ::yuzu::log_key_token(report.failure));
            break;
        case LogAction::InfoMismatchNoLongerApplies:
            spdlog::info("[PG] database '{}': the earlier collation version mismatch no longer "
                         "applies; the database has no recorded collation version any more, so "
                         "there is nothing to compare",
                         db);
            break;
        case LogAction::InfoNotApplicable:
            spdlog::info(
                "[PG] database collation version check not applicable (no recorded version, or "
                "PostgreSQL before 15); the mismatch gauge has no series");
            break;
        }
        state = step.next;
    } catch (...) {
        // Logging and metrics are best effort; the check never affects the server. `state` was not
        // advanced if the work above failed, so the next report repeats the transition.
    }
}

} // namespace yuzu::server::pg
