#pragma once

#include <expected>
#include <utility>

#include "approval_manager.hpp" // StoreReadError

/// @file checked_pending_count.hpp
/// The throw-folding wrapper around `ApprovalManager::pending_count_for_checked` that the MCP
/// approval mint (mcp_server.cpp) uses for its per-submitter pending cap, extracted so the
/// exception arms are unit-testable without making a Postgres store throw.
///
/// An unreadable count must refuse (a store fault, retryable), never read as zero: a zero would
/// admit every principal exactly when the approval store is struggling. A count that THROWS (a
/// bad_alloc building its SQL, a driver fault) is the same unreadable count, folded into the
/// unexpected arm here so it cannot unwind the mint handler before the refusal row is written.
namespace yuzu::server {

/// Call `count()` (returning `std::expected<int, StoreReadError>`); an unexpected passes through
/// unchanged, and ANY exception becomes an unexpected with EMPTY message and sqlstate.
///
/// The error is built inside a handler for an exception that may itself have been `bad_alloc`,
/// so it must not allocate (empty strings stay within the small-string buffer). This function is
/// deliberately NOT `noexcept`: the catch-all above already absorbs everything the callable can
/// throw, and a `noexcept` here would turn any throw the handler itself did not expect into
/// `std::terminate` of the server.
template <class CountFn>
[[nodiscard]] std::expected<int, StoreReadError> checked_pending_count(CountFn&& count) {
    try {
        return std::forward<CountFn>(count)();
    } catch (...) {
        return std::unexpected(StoreReadError{{}, {}});
    }
}

} // namespace yuzu::server
