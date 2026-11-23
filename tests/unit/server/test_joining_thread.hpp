#pragma once
// A std::thread that joins in its destructor (std::jthread is not available in every libc++ the
// server tests build against). Move-only; `join()` is idempotent.

#include <thread>
#include <type_traits>
#include <utility>

namespace yuzu::test {

class JoiningThread {
public:
    JoiningThread() = default;
    template <class F, class = std::enable_if_t<!std::is_same_v<std::decay_t<F>, JoiningThread>>>
    explicit JoiningThread(F&& f) : t_(std::forward<F>(f)) {}
    JoiningThread(JoiningThread&&) noexcept = default;
    JoiningThread& operator=(JoiningThread&& o) noexcept {
        join();
        t_ = std::move(o.t_);
        return *this;
    }
    JoiningThread(const JoiningThread&) = delete;
    JoiningThread& operator=(const JoiningThread&) = delete;
    ~JoiningThread() { join(); }
    void join() {
        if (t_.joinable())
            t_.join();
    }

private:
    std::thread t_;
};

} // namespace yuzu::test
