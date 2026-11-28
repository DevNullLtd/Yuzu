#pragma once

/// @file workflow_claim_outcome.hpp
/// What a workflow run's claim transaction did, once its COMMIT was reported failed (#2146).
/// A lost COMMIT acknowledgement is indistinguishable, to the client, from a rollback: the
/// transaction may be committed (the run is bound and its row exists) while the call reports a
/// failure. Postgres is asked for the transaction's own fate (`pg_xact_status`), never inferred
/// from whether a row can be read, which is not ordered against the backend's commit progress
/// (pg_pool.hpp, CHAOS-1/CHAOS-1b; `ProductPackStore::check_transaction_outcome` is the same
/// question for the product-pack install).
///
/// Pure and header-only: the decision is a table the tests pin.

#include <optional>
#include <string_view>

namespace yuzu::server {

enum class ClaimTxnOutcome {
    kCommitted,  ///< Postgres confirms the transaction committed: the ack alone was lost.
    kRolledBack, ///< Postgres confirms it aborted: nothing was admitted.
    kUnknown,    ///< Not determinable (in progress, too old for the commit log, the check failed).
};

/// `pg_xact_status` answers 'committed', 'aborted', 'in progress', or NULL when the xid is too
/// old for the commit log. `nullopt` is NULL (and a check that could not run). Anything else,
/// including a value this code does not know, is `kUnknown`: the caller then fails the call as it
/// always did and never guesses that a run exists.
[[nodiscard]] inline ClaimTxnOutcome classify_xact_status(std::optional<std::string_view> status) {
    if (!status)
        return ClaimTxnOutcome::kUnknown;
    if (*status == "committed")
        return ClaimTxnOutcome::kCommitted;
    if (*status == "aborted")
        return ClaimTxnOutcome::kRolledBack;
    return ClaimTxnOutcome::kUnknown;
}

} // namespace yuzu::server
