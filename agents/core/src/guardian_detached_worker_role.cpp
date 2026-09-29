#include "guardian_detached_worker_role.hpp"

namespace yuzu::agent {

namespace {
/// The one instance of the detached-worker flag (see the header for why it must not be
/// a header-inline thread_local).
thread_local bool tl_guardian_detached_worker = false;
} // namespace

YUZU_EXPORT void set_guardian_detached_worker_thread(bool on) noexcept {
    tl_guardian_detached_worker = on;
}
YUZU_EXPORT bool on_guardian_detached_worker_thread() noexcept {
    return tl_guardian_detached_worker;
}

} // namespace yuzu::agent
