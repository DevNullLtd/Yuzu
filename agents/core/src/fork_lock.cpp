#include <yuzu/agent/fork_lock.hpp>

namespace yuzu::agent {

std::mutex& global_fork_lock() {
    static std::mutex fork_lock;
    return fork_lock;
}

} // namespace yuzu::agent
