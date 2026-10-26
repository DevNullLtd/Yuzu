// test_leader_metrics.cpp -- HA WS-11 (#4014): the yuzu_server_leader_* metric
// family. No Postgres: `LeaderElector::Stats` is a plain value, so the seed and
// the scrape-time publisher are exercised with injected snapshots and an
// injected clock. The Postgres-backed behaviour that PRODUCES the Stats is in
// test_leader_elector.cpp; the /metrics wiring and the /readyz decision pin are
// in test_health_routes.cpp.

#include "leader_elector.hpp"
#include "leader_metrics.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;

namespace {

std::string scrape(yuzu::MetricsRegistry& m) {
    return m.serialize();
}

bool has_line(const std::string& body, const std::string& line) {
    // Whole-line match so "x 1" cannot be satisfied by "x 10".
    std::size_t pos = 0;
    while (pos < body.size()) {
        const auto nl = body.find('\n', pos);
        const auto end = nl == std::string::npos ? body.size() : nl;
        if (body.compare(pos, end - pos, line) == 0 && end - pos == line.size())
            return true;
        pos = end + 1;
    }
    return false;
}

constexpr std::int64_t kSec = 1'000'000'000;

// Every name the family exports, from the header's own constants.
std::vector<std::string> all_names() {
    return {kLeaderIsLeaderMetric,       kLeaderEpochMetric,       kLeaderAcquiredMetric,
            kLeaderAcquireFailuresMetric, kLeaderLostMetric,        kLeaderLastOkAgeMetric,
            kLeaderLoopErrorsMetric};
}

std::string read_src(const char* file) {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / file);
    REQUIRE(in.is_open());
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Crude line-comment stripper: enough for leader_elector.cpp, which holds no "//"
// inside a string literal. A needle that survives only in a comment must not
// satisfy a source pin.
std::string strip_line_comments(const std::string& src) {
    std::string out;
    std::size_t pos = 0;
    while (pos < src.size()) {
        auto nl = src.find('\n', pos);
        if (nl == std::string::npos)
            nl = src.size();
        std::string line = src.substr(pos, nl - pos);
        if (const auto c = line.find("//"); c != std::string::npos)
            line.erase(c);
        out += line;
        out += '\n';
        pos = nl + 1;
    }
    return out;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
        ++n;
    return n;
}

} // namespace

TEST_CASE("leader metrics: seed births every series at 0 and omits last_ok_age",
          "[leader-metrics][leader-elector]") {
    yuzu::MetricsRegistry m;
    seed_leader_metrics(m);
    const auto body = scrape(m);

    CHECK(has_line(body, "yuzu_server_leader_is_leader 0"));
    CHECK(has_line(body, "yuzu_server_leader_epoch 0"));
    CHECK(has_line(body, "yuzu_server_leader_acquired_total 0"));
    CHECK(has_line(body, "yuzu_server_leader_loop_errors_total 0"));
    // Every cause of both labelled counters, driven from the closed arrays.
    for (const char* c : kAcquireFailureLabels)
        CHECK(has_line(body, std::string("yuzu_server_leader_acquire_failures_total{cause=\"") +
                                 c + "\"} 0"));
    for (const char* c : kLeadershipLossLabels)
        CHECK(has_line(body, std::string("yuzu_server_leader_lost_total{cause=\"") + c + "\"} 0"));
    // ABSENT, not 0, until the connection first answers.
    CHECK(body.find("yuzu_server_leader_last_ok_age_seconds ") == std::string::npos);
}

TEST_CASE("leader metrics: the closed cause sets are exactly the documented labels",
          "[leader-metrics][leader-elector]") {
    // A rename or an added cause must be a deliberate change to the alert/doc
    // contract, not a silent one.
    CHECK(std::vector<std::string>(kAcquireFailureLabels.begin(), kAcquireFailureLabels.end()) ==
          std::vector<std::string>{"connect", "lock_query", "lock_guard", "epoch_record"});
    CHECK(std::vector<std::string>(kLeadershipLossLabels.begin(), kLeadershipLossLabels.end()) ==
          std::vector<std::string>{"liveness_failed", "resigned"});
    CHECK(kAcquireFailureCount == kAcquireFailureLabels.size());
    CHECK(kLeadershipLossCount == kLeadershipLossLabels.size());
    // The enum slots line up with the label slots they index.
    CHECK(static_cast<std::size_t>(AcquireFailure::EpochRecord) == kAcquireFailureCount - 1);
    CHECK(static_cast<std::size_t>(LeadershipLoss::Resigned) == kLeadershipLossCount - 1);
}

TEST_CASE("leader metrics: every exported name has an ASCII HELP and TYPE line",
          "[leader-metrics][leader-elector]") {
    yuzu::MetricsRegistry m;
    seed_leader_metrics(m);
    LeaderMetricsPublisher pub;
    // Publish a snapshot with last_ok set so last_ok_age exists too.
    LeaderElector::Stats s;
    s.last_ok_steady_ns = kSec;
    pub.publish(m, s, 0, 2 * kSec);
    const auto body = scrape(m);
    for (const auto& name : all_names()) {
        INFO(name);
        CHECK(body.find("# HELP " + name + " ") != std::string::npos);
        CHECK(body.find("# TYPE " + name + " ") != std::string::npos);
    }
    // 7-bit ASCII throughout the exposition text (scripts/ci/check-metrics-help-ascii.sh
    // guards the source; this guards the rendered output).
    CHECK(std::all_of(body.begin(), body.end(),
                      [](unsigned char c) { return c < 0x80; }));
}

TEST_CASE("leader metrics: publish sets the gauges from the snapshot",
          "[leader-metrics][leader-elector]") {
    yuzu::MetricsRegistry m;
    seed_leader_metrics(m);
    LeaderMetricsPublisher pub;

    LeaderElector::Stats s;
    s.leader = true;
    s.epoch = 7;
    pub.publish(m, s, 0, kSec);
    auto body = scrape(m);
    CHECK(has_line(body, "yuzu_server_leader_is_leader 1"));
    CHECK(has_line(body, "yuzu_server_leader_epoch 7"));

    // Leadership dropped: both return to 0 (epoch 0 means "not leading").
    s.leader = false;
    s.epoch = 0;
    pub.publish(m, s, 0, kSec);
    body = scrape(m);
    CHECK(has_line(body, "yuzu_server_leader_is_leader 0"));
    CHECK(has_line(body, "yuzu_server_leader_epoch 0"));

    // A stale epoch on a non-leader snapshot is never exported as an epoch.
    s.leader = false;
    s.epoch = 9;
    pub.publish(m, s, 0, kSec);
    CHECK(has_line(scrape(m), "yuzu_server_leader_epoch 0"));
}

TEST_CASE("leader metrics: counters sync by delta and are idempotent on an unchanged snapshot",
          "[leader-metrics][leader-elector]") {
    yuzu::MetricsRegistry m;
    seed_leader_metrics(m);
    LeaderMetricsPublisher pub;

    LeaderElector::Stats s;
    s.acquired = 3;
    s.acquire_failed[static_cast<std::size_t>(AcquireFailure::Connect)] = 2;
    s.acquire_failed[static_cast<std::size_t>(AcquireFailure::EpochRecord)] = 1;
    s.lost[static_cast<std::size_t>(LeadershipLoss::LivenessFailed)] = 4;
    s.lost[static_cast<std::size_t>(LeadershipLoss::Resigned)] = 1;

    // BINDING idempotence: re-publishing the SAME snapshot (what every later
    // scrape does) must not move a counter. A sync that incremented by the raw
    // value instead of the delta would double on the second call.
    for (int i = 0; i < 3; ++i)
        pub.publish(m, s, 5, kSec);
    auto body = scrape(m);
    CHECK(has_line(body, "yuzu_server_leader_acquired_total 3"));
    CHECK(has_line(body, "yuzu_server_leader_acquire_failures_total{cause=\"connect\"} 2"));
    CHECK(has_line(body, "yuzu_server_leader_acquire_failures_total{cause=\"epoch_record\"} 1"));
    CHECK(has_line(body, "yuzu_server_leader_acquire_failures_total{cause=\"lock_query\"} 0"));
    CHECK(has_line(body, "yuzu_server_leader_acquire_failures_total{cause=\"lock_guard\"} 0"));
    CHECK(has_line(body, "yuzu_server_leader_lost_total{cause=\"liveness_failed\"} 4"));
    CHECK(has_line(body, "yuzu_server_leader_lost_total{cause=\"resigned\"} 1"));
    CHECK(has_line(body, "yuzu_server_leader_loop_errors_total 5"));

    // Growth is applied once, by the difference.
    s.acquired = 4;
    pub.publish(m, s, 6, kSec);
    pub.publish(m, s, 6, kSec);
    body = scrape(m);
    CHECK(has_line(body, "yuzu_server_leader_acquired_total 4"));
    CHECK(has_line(body, "yuzu_server_leader_loop_errors_total 6"));

    // A counter never goes backwards (a Stats that read lower, e.g. a rebuilt
    // elector, must not make the exported counter decrease: a Prometheus counter
    // reset is the scraper's job, not ours).
    LeaderElector::Stats lower;
    lower.acquired = 1;
    pub.publish(m, lower, 0, kSec);
    CHECK(has_line(scrape(m), "yuzu_server_leader_acquired_total 4"));
}

TEST_CASE("leader metrics: last_ok_age is absent until a success and computed from the injected clock",
          "[leader-metrics][leader-elector]") {
    yuzu::MetricsRegistry m;
    seed_leader_metrics(m);
    LeaderMetricsPublisher pub;

    LeaderElector::Stats never; // last_ok_steady_ns == 0
    pub.publish(m, never, 0, 100 * kSec);
    CHECK(scrape(m).find("yuzu_server_leader_last_ok_age_seconds ") == std::string::npos);

    LeaderElector::Stats ok;
    ok.last_ok_steady_ns = 40 * kSec;
    pub.publish(m, ok, 0, 100 * kSec);
    CHECK(has_line(scrape(m), "yuzu_server_leader_last_ok_age_seconds 60"));

    // The age GROWS with the clock while the snapshot is frozen: this is the
    // property that makes the gauge expose a wedged election loop.
    pub.publish(m, ok, 0, 400 * kSec);
    CHECK(has_line(scrape(m), "yuzu_server_leader_last_ok_age_seconds 360"));

    // A reordered clock read never yields a negative age.
    pub.publish(m, ok, 0, 10 * kSec);
    CHECK(has_line(scrape(m), "yuzu_server_leader_last_ok_age_seconds 0"));
}

TEST_CASE("leader metrics: concurrent scrapes never double-count (TSan-oriented, non-binding)",
          "[leader-metrics][leader-elector]") {
    // The binding idempotence test is the sequential one above. This case is a
    // race exerciser for the nightly TSan leg: two scrape threads publish a
    // growing snapshot through ONE publisher; the final value must equal the
    // final snapshot. (Removing the publisher's mutex is caught by TSan, not here.)
    yuzu::MetricsRegistry m;
    seed_leader_metrics(m);
    LeaderMetricsPublisher pub;
    std::atomic<std::uint64_t> shared_acquired{0};

    auto scraper = [&] {
        for (int i = 0; i < 2000; ++i) {
            LeaderElector::Stats s;
            s.acquired = shared_acquired.load();
            pub.publish(m, s, 0, kSec);
        }
    };
    std::thread a(scraper), b(scraper);
    for (int i = 0; i < 2000; ++i)
        shared_acquired.fetch_add(1);
    a.join();
    b.join();

    LeaderElector::Stats last;
    last.acquired = shared_acquired.load();
    pub.publish(m, last, 0, kSec);
    CHECK(has_line(scrape(m), "yuzu_server_leader_acquired_total 2000"));
}

TEST_CASE("leader metrics: every cause enumerator has a count site in leader_elector.cpp",
          "[leader-metrics][leader-elector]") {
    // The lock_guard cause fires only on a bad_alloc inside a non-noexcept
    // constructor, which no test can inject; and every cause is a silent no-op if
    // its increment is deleted. So pin, mechanically, that each enumerator is
    // referenced in CODE (comments stripped) at least once.
    const auto code = strip_line_comments(read_src("leader_elector.cpp"));
    for (const char* e : {"AcquireFailure::Connect", "AcquireFailure::LockQuery",
                          "AcquireFailure::LockGuard", "AcquireFailure::EpochRecord",
                          "LeadershipLoss::LivenessFailed", "LeadershipLoss::Resigned"}) {
        INFO(e);
        CHECK(count_of(code, e) >= 1);
    }
    // The normal follower outcome (try-lock answered 'f') must never be counted:
    // no AcquireFailure increment may sit between the 'f' check and its return.
    const auto f_at = code.find("!= 't'");
    REQUIRE(f_at != std::string::npos);
    const auto ret_at = code.find("return false", f_at);
    REQUIRE(ret_at != std::string::npos);
    CHECK(code.substr(f_at, ret_at - f_at).find("acquire_failed_") == std::string::npos);
}

TEST_CASE("leader metrics: the election loop never calls the MetricsRegistry",
          "[leader-metrics][leader-elector]") {
    // Registry calls take a mutex and build a std::string key that can throw;
    // inside the loop's catch blocks that is a std::terminate defeating the loop's
    // own exception guard. The loop counts into a plain atomic instead.
    const auto code = strip_line_comments(read_src("server.cpp"));
    const auto begin = code.find("leader_thread_ = std::thread(");
    REQUIRE(begin != std::string::npos);
    const auto end = code.find("election loop stopped", begin);
    REQUIRE(end != std::string::npos);
    const auto loop = code.substr(begin, end - begin);
    CHECK(loop.find("metrics_") == std::string::npos);
    CHECK(loop.find(".counter(") == std::string::npos);
    CHECK(loop.find(".gauge(") == std::string::npos);
    CHECK(count_of(loop, "leader_loop_errors_.fetch_add(1, std::memory_order_relaxed);") == 2);
    // leader_metrics.hpp itself: the elector is never handed to the publisher.
    const auto hdr = strip_line_comments(read_src("leader_metrics.hpp"));
    CHECK(hdr.find("LeaderElector&") == std::string::npos);
    CHECK(hdr.find("LeaderElector*") == std::string::npos);
    CHECK(hdr.find("is_open") == std::string::npos);
}
