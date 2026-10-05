#pragma once

/**
 * row_byte_budget.hpp -- one overflow-safe row/byte budget for the bounded-output
 * shapes (local_security_policy Tally, runtimes WalkBudget, privacy_permissions
 * macOS per-source bytes, Windows RetentionBudget, run OutputBudget).
 *
 * Plain arithmetic, deliberately NOT sticky:
 *   - An exact fill is admitted (rows + n_rows == max_rows, bytes + n_bytes ==
 *     max_bytes); the NEXT charge is refused.
 *   - `refused` is a RECORD that at least one charge() was refused. It does not
 *     gate later fits()/charge() calls. A consumer that must stop at the first
 *     refusal checks it (privacy_permissions RetentionBudget) or keeps its own
 *     flag (runtimes `exhausted`, local_security_policy `capped`); stopping is
 *     the consumer's policy.
 *   - full() is the loop-top "nothing more can fit" test.
 *   - add() is the unconditional, saturating reserve.
 */

#include <algorithm>
#include <cstddef>
#include <limits>

namespace yuzu::shared {

struct RowByteBudget {
    static constexpr std::size_t kUnbounded = std::numeric_limits<std::size_t>::max();

    std::size_t max_rows = kUnbounded;
    std::size_t max_bytes = kUnbounded;
    std::size_t rows = 0;
    std::size_t bytes = 0;
    bool refused = false;

    [[nodiscard]] bool fits(std::size_t n_bytes, std::size_t n_rows = 1) const noexcept {
        return n_rows <= max_rows - std::min(rows, max_rows) &&
               n_bytes <= max_bytes - std::min(bytes, max_bytes);
    }

    bool charge(std::size_t n_bytes, std::size_t n_rows = 1) noexcept {
        if (!fits(n_bytes, n_rows)) {
            refused = true;
            return false;
        }
        add(n_bytes, n_rows);
        return true;
    }

    void add(std::size_t n_bytes, std::size_t n_rows = 1) noexcept {
        rows = n_rows > kUnbounded - rows ? kUnbounded : rows + n_rows;
        bytes = n_bytes > kUnbounded - bytes ? kUnbounded : bytes + n_bytes;
    }

    [[nodiscard]] bool full() const noexcept { return rows >= max_rows || bytes >= max_bytes; }

    void reset() noexcept {
        rows = 0;
        bytes = 0;
        refused = false;
    }
};

} // namespace yuzu::shared
