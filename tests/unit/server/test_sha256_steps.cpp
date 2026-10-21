// Tests for sha256_via_ops (server/core/src/sha256_steps.hpp): every stage that can fail
// must make the digest throw, never return a value, and leave no handle open.
#include "sha256_steps.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::oidc::detail::sha256_via_ops;

namespace {

enum class FailAt { None, Open, Create, Update, Finish };

// Counts handles that are open right now; a handle releases itself on destruction.
struct LiveHandles {
    int live = 0;
    int opened = 0;
};

class FakeHandle {
public:
    explicit FakeHandle(LiveHandles& c) : c_(&c) {
        ++c_->live;
        ++c_->opened;
    }
    FakeHandle(const FakeHandle&) = delete;
    FakeHandle& operator=(const FakeHandle&) = delete;
    FakeHandle(FakeHandle&& o) noexcept : c_(o.c_) { o.c_ = nullptr; }
    FakeHandle& operator=(FakeHandle&&) = delete;
    ~FakeHandle() {
        if (c_)
            --c_->live;
    }

private:
    LiveHandles* c_;
};

struct FakeOps {
    FakeOps(FailAt f, LiveHandles& h) : fail(f), handles(h) {}

    bool open() {
        calls.push_back("open");
        if (fail == FailAt::Open)
            return false;
        alg_.emplace_back(handles);
        return true;
    }
    bool create() {
        calls.push_back("create");
        if (fail == FailAt::Create)
            return false;
        hash_.emplace_back(handles);
        return true;
    }
    bool update(const std::string& input) {
        calls.push_back("update");
        seen_input = input;
        return fail != FailAt::Update;
    }
    bool finish(std::vector<uint8_t>& out) {
        calls.push_back("finish");
        if (fail == FailAt::Finish)
            return false;
        out.assign(out.size(), 0xAB);
        return true;
    }

    FailAt fail;
    LiveHandles& handles;
    std::vector<std::string> calls;
    std::string seen_input;

private:
    // Same ownership shape as the real providers: hash handle declared after the algorithm
    // handle, so it is released first.
    std::vector<FakeHandle> alg_;
    std::vector<FakeHandle> hash_;
};

} // namespace

TEST_CASE("sha256_via_ops: success runs all four stages in order and returns the 32 bytes written",
          "[oidc][sha256_steps]") {
    LiveHandles h;
    {
        FakeOps ops(FailAt::None, h);
        const auto out = sha256_via_ops(ops, "abc");
        CHECK(out == std::vector<uint8_t>(32, 0xAB));
        CHECK(ops.calls == std::vector<std::string>{"open", "create", "update", "finish"});
        CHECK(ops.seen_input == "abc");
        CHECK(h.live == 2);
    }
    CHECK(h.live == 0);
}

TEST_CASE("sha256_via_ops: a failing stage throws, stops the later stages and releases handles",
          "[oidc][sha256_steps]") {
    struct Case {
        FailAt at;
        const char* name;
        std::vector<std::string> expected_calls;
        int expected_opened;
    };
    const Case cases[] = {
        {FailAt::Open, "open", {"open"}, 0},
        {FailAt::Create, "create", {"open", "create"}, 1},
        {FailAt::Update, "update", {"open", "create", "update"}, 2},
        {FailAt::Finish, "finish", {"open", "create", "update", "finish"}, 2},
    };
    for (const auto& c : cases) {
        CAPTURE(c.name);
        LiveHandles h;
        {
            FakeOps ops(c.at, h);
            bool returned = false;
            std::vector<uint8_t> value;
            CHECK_THROWS_AS(
                [&] {
                    value = sha256_via_ops(ops, "abc");
                    returned = true;
                }(),
                std::runtime_error);
            CHECK_FALSE(returned);
            CHECK(value.empty());
            CHECK(ops.calls == c.expected_calls);
            CHECK(h.opened == c.expected_opened);
        }
        CHECK(h.live == 0);
    }
}

TEST_CASE("sha256_via_ops: the thrown error names the digest failure", "[oidc][sha256_steps]") {
    LiveHandles h;
    FakeOps ops(FailAt::Update, h);
    try {
        (void)sha256_via_ops(ops, "abc");
        FAIL("expected a throw");
    } catch (const std::runtime_error& e) {
        CHECK(std::string(e.what()) == "SHA-256 failed");
    }
}
