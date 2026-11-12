#include <array>
#include <chrono>
#include <future>
#include <memory>

#include <catch2/catch_test_macros.hpp>
#include <grpc/event_engine/event_engine.h>
#include <openssl/rand.h>

TEST_CASE("the suite owns its default EventEngine until crypto workers drain", "[grpc][lifetime]") {
    using grpc_event_engine::experimental::EventEngine;
    using grpc_event_engine::experimental::GetDefaultEventEngine;

    std::weak_ptr<EventEngine> observed;
    {
        auto engine = GetDefaultEventEngine();
        observed = engine;
    }
    // With gRPC's ordinary weak default slot, releasing the last caller-owned
    // reference destroys the engine here. The shared runner must pin it.
    REQUIRE_FALSE(observed.expired());
    auto engine = observed.lock();
    REQUIRE(engine == GetDefaultEventEngine());

    // Initialize main-thread crypto state first, as the PostgreSQL suite sweep
    // does. Worker public/private DRBG state must then be released before the
    // process-wide OpenSSL exit handler; sanitizer checks cover that boundary.
    REQUIRE(RAND_status() == 1);
    auto completion = std::make_shared<std::promise<bool>>();
    auto result = completion->get_future();
    engine->Run([completion] {
        std::array<unsigned char, 32> bytes{};
        const bool ok = RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) == 1 &&
                        RAND_priv_bytes(bytes.data(), static_cast<int>(bytes.size())) == 1;
        completion->set_value(ok);
    });
    REQUIRE(result.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    REQUIRE(result.get());
    // No manual thread cleanup here: the real entry point and patched gRPC
    // dependency must make normal process exit safe after this scope returns.
}
