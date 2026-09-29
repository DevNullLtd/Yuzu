#include "guardian_scope_guard.hpp"

#include <spdlog/spdlog.h>

#include <atomic>

namespace yuzu::agent {

namespace {
std::atomic<std::uint64_t> g_cleanup_failures{0};
}

std::uint64_t guardian_rollback_cleanup_failures() noexcept {
    return g_cleanup_failures.load(std::memory_order_relaxed);
}

GuardianRollback::~GuardianRollback() {
    if (committed || !fn)
        return;
    try {
        fn();
    } catch (...) {
        // Swallow: a throw out of this noexcept destructor would std::terminate the
        // agent, and a rollback almost always runs mid-unwind under bad_alloc. The
        // atomic increment is noexcept; the log is best-effort (it allocates), so it is
        // itself guarded.
        g_cleanup_failures.fetch_add(1, std::memory_order_relaxed);
        try {
            spdlog::error("Guardian: rollback cleanup threw during unwinding; state may leak");
        } catch (...) {
        }
    }
}

} // namespace yuzu::agent
