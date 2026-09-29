// test_guardian_spark_backend.cpp - GuardianSparkEngineBackend (ADR-0021 rung
// 7.3). Tests the adapter against a REAL SparkEngine (no fake mechanism
// needed - an Interval spark is timer-driven, serviced entirely by the wheel).

#include "guardian_spark_backend.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::agent;

namespace {
SparkSpec interval_spec(std::uint64_t interval_ms = 60'000) {
    return SparkSpec{SparkType::Interval, IntervalSparkParams{interval_ms}};
}
} // namespace

TEST_CASE("GuardianSparkEngineBackend: arm() before bind_consumer() is a typed error, "
          "not a raw SparkEngine rejection",
          "[spark][guardian][backend]") {
    SparkEngine engine;
    GuardianSparkEngineBackend backend(engine);

    const auto r = backend.arm(interval_spec());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("bind_consumer") != std::string::npos);
}

TEST_CASE("GuardianSparkEngineBackend: disarm() before bind_consumer() is a safe no-op",
          "[spark][guardian][backend]") {
    SparkEngine engine;
    GuardianSparkEngineBackend backend(engine);
    backend.disarm(12345); // must not crash or touch the engine
    SUCCEED("no-op disarm before bind did not crash");
}

TEST_CASE("GuardianSparkEngineBackend: after bind, arm()/disarm() forward to the bound consumer",
          "[spark][guardian][backend]") {
    SparkEngine engine;
    engine.start();
    GuardianSparkEngineBackend backend(engine);

    auto consumer_id = engine.register_consumer("guardian-spark-test", [](const SparkEvent&) {});
    REQUIRE(consumer_id.has_value());
    backend.bind_consumer(*consumer_id);

    auto sub = backend.arm(interval_spec());
    REQUIRE(sub.has_value());
    CHECK(engine.stats().armed_sparks == 1);

    backend.disarm(*sub);
    CHECK(engine.stats().armed_sparks == 0);

    engine.stop();
}

TEST_CASE("GuardianSparkEngineBackend: arm() through a stale ConsumerId (consumer unregistered) "
          "surfaces SparkEngine's own rejection",
          "[spark][guardian][backend]") {
    SparkEngine engine;
    engine.start();
    GuardianSparkEngineBackend backend(engine);

    auto consumer_id = engine.register_consumer("guardian-spark-test", [](const SparkEvent&) {});
    REQUIRE(consumer_id.has_value());
    backend.bind_consumer(*consumer_id);
    engine.unregister_consumer(*consumer_id);

    const auto r = backend.arm(interval_spec());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "unknown consumer id");

    engine.stop();
}
