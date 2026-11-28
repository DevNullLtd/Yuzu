#pragma once

// A loopback HTTP server whose handler holds every request until released, for tests that need
// a delivery worker to stay busy (a webhook or offload delivery pool backed up behind it).
//
// Teardown order is load-bearing, in two places. The destructor releases the held handlers FIRST,
// then stops the server, then joins its thread, so the join cannot hang on a blocked handler. And
// a test must declare the metrics registry, then the store it drives, BEFORE the sink: locals are destroyed in reverse order,
// so the sink then releases its held deliveries before the store's teardown waits to drain them
// (the other order makes a failing REQUIRE wait out each delivery's read timeout).

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

namespace yuzu::test {

class BlockingHttpSink {
public:
    BlockingHttpSink() {
        svr_.Post("/h", [this](const httplib::Request&, httplib::Response& res) {
            ++arrived_;
            while (!released_.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            res.status = 200;
            res.set_content("ok", "text/plain");
        });
        port_ = svr_.bind_to_any_port("127.0.0.1");
        if (port_ > 0) {
            thread_ = std::thread([this] { svr_.listen_after_bind(); });
            svr_.wait_until_ready();
        }
    }

    ~BlockingHttpSink() {
        released_.store(true);
        svr_.stop();
        if (thread_.joinable())
            thread_.join();
    }

    BlockingHttpSink(const BlockingHttpSink&) = delete;
    BlockingHttpSink& operator=(const BlockingHttpSink&) = delete;

    [[nodiscard]] bool ok() const noexcept { return port_ > 0; }
    [[nodiscard]] std::string url() const { return "http://127.0.0.1:" + std::to_string(port_) + "/h"; }
    /// Requests that have reached the handler (held or finished).
    [[nodiscard]] int arrived() const noexcept { return arrived_.load(); }
    void release() noexcept { released_.store(true); }

private:
    httplib::Server svr_;
    std::thread thread_;
    int port_{-1};
    std::atomic<bool> released_{false};
    std::atomic<int> arrived_{0};
};

} // namespace yuzu::test
