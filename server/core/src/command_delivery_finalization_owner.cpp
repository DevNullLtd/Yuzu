#include "command_delivery_finalization_owner.hpp"

#include "command_outbox_store.hpp" // CommandOutboxStore::kWriteTimeout (#4982 round 6, Kimi K3)
#include "leader_elector.hpp" // LeaderElector::epoch_fence_sql — the embeddable epoch predicate
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <string>
#include <vector>

namespace yuzu::server {

// #4982 round 3 → round 5: byte-identical body to
// `CommandOutboxStore::mark_sent_with_target`'s pre-move implementation — see
// this file's header banner and `command_outbox_store.hpp`'s own doc comment
// on the public method for the full rationale (the race this closes, the
// rollback-on-either-failure contract). Only its location moved, per ADR-0012
// §3: `CommandOutboxStore` must stay a single-schema (`command_outbox_store`)
// owner, so the cross-schema write into `execution_tracker.executions` lives
// here instead.
CommandDeliveryFinalizationOwner::MarkSentWithTargetOutcome
CommandDeliveryFinalizationOwner::mark_sent_with_target(const std::string& occurrence_id,
                                                        const std::string& leader_lock_name,
                                                        std::int64_t leader_epoch,
                                                        const std::string& execution_id,
                                                        int agents_targeted) const {
    const std::string fence = LeaderElector::epoch_fence_sql(leader_lock_name, leader_epoch);
    const std::string sent_sql =
        "UPDATE command_outbox_store.outbox SET state='sent', updated_at=now() "
        "WHERE occurrence_id=$1 AND state='pending' AND " + fence + " RETURNING occurrence_id";

    bool matched = false;
    bool db_error = false;
    // The sent-transition and the target-count write commit in ONE
    // transaction — see the header doc comment for the race this closes.
    // Cross-schema, single pool/database — this owner's whole reason to
    // exist (ADR-0012 §3).
    const bool committed =
        pool_.with_txn_for(CommandOutboxStore::kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult sent_res =
            pg::exec_params(c, sent_sql.c_str(), std::vector<std::string>{occurrence_id});
        if (sent_res.status() != PGRES_TUPLES_OK) {
            spdlog::error("CommandDeliveryFinalizationOwner::mark_sent_with_target: "
                         "sent-transition failed for occurrence '{}': {}",
                         occurrence_id, PQresultErrorMessage(sent_res.get()));
            db_error = true;
            return false; // roll back
        }
        if (PQntuples(sent_res.get()) == 0)
            return true; // not ours (fenced out / already terminal) — commit the no-op

        matched = true;
        pg::PgResult tgt_res = pg::exec_params(
            c, "UPDATE execution_tracker.executions SET agents_targeted=$1 WHERE id=$2",
            std::vector<std::string>{std::to_string(agents_targeted), execution_id});
        if (tgt_res.status() != PGRES_COMMAND_OK) {
            spdlog::error(
                "CommandDeliveryFinalizationOwner::mark_sent_with_target: agents_targeted "
                "update failed for execution_id={} occurrence='{}': {} — rolling back the "
                "sent-transition too, so the occurrence stays 'pending' and is re-driven next "
                "tick (the wire send already happened; the agent's command_id dedup absorbs "
                "the harmless re-send)",
                execution_id, occurrence_id, PQresultErrorMessage(tgt_res.get()));
            db_error = true;
            matched = false;
            return false; // roll back BOTH writes
        }
        return true;
    });

    MarkSentWithTargetOutcome outcome;
    outcome.committed = committed;
    outcome.matched = matched;
    outcome.db_error = db_error;
    return outcome;
}

} // namespace yuzu::server
