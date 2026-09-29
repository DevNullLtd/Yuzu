#pragma once

#include <utility>

namespace yuzu::server::detail {

// Bounded acquire-retry loop (issue #2396), factored out of `auth_db.cpp`'s
// `acquire_with_retry` so the retry *behaviour* is unit-testable without a live
// PostgreSQL pool — the "does a transient empty acquire actually ride out to a
// success within the same call" property that a saturated-pool test cannot pin
// deterministically (adv-review CDX-P1-02 / K7).
//
// `acquire(is_first)` returns a truthy-on-success, move-only value (an
// empty/false-y result means "the lease could not be acquired — retry"); the
// bool argument lets the caller use a longer budget on the first attempt and a
// short one on retries. `sleep()` runs the backoff between attempts. Returns
// the first successful value, or the last (empty) value once `retries` extra
// attempts are exhausted. `retries == 0` means a single un-retried acquire.
//
// Only the ACQUIRE is retried here; a caller that wants no retry passes
// retries == 0, and a caller must never route a query that ran and errored
// through this loop.
template <class Acquire, class Sleep>
[[nodiscard]] auto acquire_with_bounded_retry(int retries, Acquire&& acquire, Sleep&& sleep)
    -> decltype(acquire(true)) {
    auto value = acquire(true);
    for (int i = 0; i < retries && !value; ++i) {
        sleep();
        value = acquire(false);
    }
    return value;
}

} // namespace yuzu::server::detail
