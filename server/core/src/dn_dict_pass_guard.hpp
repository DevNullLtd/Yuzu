#pragma once
// RAII scope for ONE DN-dictionary maintenance pass (slice-2 PR 2a-2b). While alive, a watcher
// thread polls `is_leader` every 100 ms and, once leadership is lost, calls `cancel` about every
// 500 ms until the scope ends (a single cancel can be lost in the microseconds between a statement
// being armed and reaching the server). On EVERY exit - normal return or a throw out of the pass -
// the destructor stops and joins the watcher, then calls `done` (the caller clears the per-run
// stop there unless the process is shutting down). Joining a joinable std::thread is therefore
// never skipped, so an exception cannot reach std::terminate.
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <utility>

namespace yuzu::server {

class DnDictPassGuard {
public:
    DnDictPassGuard(std::function<bool()> is_leader, std::function<void()> cancel,
                    std::function<void()> done)
        : cancel_(std::move(cancel)), done_(std::move(done)),
          watcher_([this, lead = std::move(is_leader)] {
              using namespace std::chrono_literals;
              auto since_cancel = 500ms;
              while (!finished_.load(std::memory_order_acquire)) {
                  bool leading = true;
                  try {
                      leading = lead();
                  } catch (...) {
                      leading = false; // cannot tell: cancel, the safe side
                  }
                  if (!leading) {
                      if (since_cancel >= 500ms) {
                          try {
                              cancel_();
                          } catch (...) { // a throw here would terminate the process
                          }
                          since_cancel = 0ms;
                      }
                  }
                  std::this_thread::sleep_for(100ms);
                  since_cancel += 100ms;
              }
          }) {}
    ~DnDictPassGuard() {
        finished_.store(true, std::memory_order_release);
        if (watcher_.joinable())
            watcher_.join();
        if (done_) {
            try {
                done_();
            } catch (...) { // a destructor must not throw
            }
        }
    }
    DnDictPassGuard(const DnDictPassGuard&) = delete;
    DnDictPassGuard& operator=(const DnDictPassGuard&) = delete;

private:
    std::function<void()> cancel_;
    std::function<void()> done_;
    std::atomic<bool> finished_{false};
    std::thread watcher_; // declared LAST: starts after every member it reads is constructed
};

} // namespace yuzu::server
