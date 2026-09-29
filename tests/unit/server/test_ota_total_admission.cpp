/**
 * test_ota_total_admission.cpp — the server-wide OTA gate's OCCUPANCY.
 *
 * WHY THIS FILE EXISTS. `test_ota_download_bound.cpp` proves the gate is wired
 * into the real handler over the real wire, but it can only reach it one call
 * at a time: `max_concurrent_total=0` refuses with the counter untouched
 * (`prev = 0 >= 0`), and a cap of 1 driven sequentially admits with the counter
 * untouched (`prev` is 0 on every call). A governance pass verified the
 * consequence — deleting the increment left the whole `[ota]` suite green.
 *
 * Holding a live `DownloadUpdate` mid-transfer would need a package on disk and
 * a peer that stalls, which is exactly what that file documents it cannot do.
 * So the counting is proven HERE instead, on the extracted gate: deterministic,
 * single-threaded, no timing.
 */

#include "ota_total_admission.hpp"

#include <catch2/catch_test_macros.hpp>

#include <utility>
#include <vector>

using yuzu::server::detail::OtaTotalAdmission;

TEST_CASE("OTA total gate: a held slot occupies the ceiling", "[ota][bound][total]") {
    OtaTotalAdmission gate;

    // THE CASE THE WIRE TESTS CANNOT REACH. Cap of one, and the first slot is
    // still held when the second call arrives. If the counter were never
    // incremented, `prev` would be 0 here too and this second call would be
    // admitted — which is precisely the mutation the live-wire suite could not
    // observe.
    auto first = gate.try_acquire(1, /*cert_reserve_pct=*/0, /*cert_keyed=*/false);
    REQUIRE(first.admitted);
    CHECK(first.slot.held());
    CHECK(gate.in_flight() == 1);

    auto second = gate.try_acquire(1, 0, false);
    CHECK_FALSE(second.admitted);
    CHECK_FALSE(second.slot.held());
    // The refused call must not leave its own increment behind, or the ceiling
    // erodes by one on every rejection until the server admits nothing.
    CHECK(gate.in_flight() == 1);
    CHECK(second.observed_in_flight == 1);
    CHECK(second.effective_cap == 1);

    // Release, and the capacity comes back.
    first.slot.reset();
    CHECK(gate.in_flight() == 0);
    auto third = gate.try_acquire(1, 0, false);
    CHECK(third.admitted);
}

TEST_CASE("OTA total gate: the slot releases exactly once", "[ota][bound][total]") {
    OtaTotalAdmission gate;
    {
        auto d = gate.try_acquire(4, 0, false);
        REQUIRE(d.admitted);
        CHECK(gate.in_flight() == 1);
        // A moved-from slot must not double-release: two decrements for one
        // acquire would drive the counter negative and silently uncap the gate.
        OtaTotalAdmission::Slot moved = std::move(d.slot);
        CHECK(moved.held());
        CHECK_FALSE(d.slot.held());
        CHECK(gate.in_flight() == 1);
    }
    CHECK(gate.in_flight() == 0);

    auto d = gate.try_acquire(4, 0, false);
    REQUIRE(d.admitted);
    d.slot.reset();
    d.slot.reset(); // idempotent
    CHECK(gate.in_flight() == 0);
}

TEST_CASE("OTA total gate: the ceiling holds across a full fill", "[ota][bound][total]") {
    OtaTotalAdmission gate;
    std::vector<OtaTotalAdmission::Slot> held;
    for (int i = 0; i < 3; ++i) {
        auto d = gate.try_acquire(3, 0, false);
        REQUIRE(d.admitted);
        held.push_back(std::move(d.slot));
    }
    CHECK(gate.in_flight() == 3);
    CHECK_FALSE(gate.try_acquire(3, 0, false).admitted);

    held.pop_back();
    CHECK(gate.in_flight() == 2);
    CHECK(gate.try_acquire(3, 0, false).admitted);
}

TEST_CASE("OTA total gate: the certificate reserve splits the ceiling", "[ota][bound][total]") {
    // An IP-keyed caller gets the unreserved share; a certificate-keyed one gets
    // the whole cap. This is what stops an unauthenticated flood — every peer of
    // which is IP-keyed where the identity gate is inert — from starving an
    // enrolled fleet out of the shared ceiling.
    CHECK(OtaTotalAdmission::effective_cap(10, 50, /*cert_keyed=*/false) == 5);
    CHECK(OtaTotalAdmission::effective_cap(10, 50, /*cert_keyed=*/true) == 10);
    CHECK(OtaTotalAdmission::effective_cap(10, 0, false) == 10);
    CHECK(OtaTotalAdmission::effective_cap(10, 100, false) == 1);  // floored, not zero
    CHECK(OtaTotalAdmission::effective_cap(10, 100, true) == 10);

    // The floor is on the ARITHMETIC, not on capacity: a cap of zero stays zero
    // for everyone. A reserve must never manufacture capacity nobody configured.
    CHECK(OtaTotalAdmission::effective_cap(0, 50, false) == 0);
    CHECK(OtaTotalAdmission::effective_cap(0, 50, true) == 0);

    // Rounding: 1 x 50% is 0 by integer division, and that would be a total OTA
    // outage on any deployment whose peers are all IP-keyed.
    CHECK(OtaTotalAdmission::effective_cap(1, 50, false) == 1);
    CHECK(OtaTotalAdmission::effective_cap(3, 99, false) == 1);

    // Out-of-range percentages are clamped rather than trusted — CLI11 validates
    // the flag, but a Config built in code does not go through it.
    CHECK(OtaTotalAdmission::effective_cap(10, -50, false) == 10);
    CHECK(OtaTotalAdmission::effective_cap(10, 500, false) == 1);
}

TEST_CASE("OTA total gate: an occupying IP-keyed caller cannot starve a certificate peer",
          "[ota][bound][total]") {
    // The reserve is only meaningful under OCCUPANCY: fill the unreserved share
    // and check an enrolled peer still gets in. A cap check alone would pass
    // even if the counter never moved.
    OtaTotalAdmission gate;
    std::vector<OtaTotalAdmission::Slot> flood;
    for (int i = 0; i < 5; ++i) {
        auto d = gate.try_acquire(10, /*cert_reserve_pct=*/50, /*cert_keyed=*/false);
        REQUIRE(d.admitted);
        flood.push_back(std::move(d.slot));
    }
    // The IP-keyed share is exhausted...
    CHECK_FALSE(gate.try_acquire(10, 50, false).admitted);
    // ...but the reserved half is still there for an enrolled agent.
    CHECK(gate.try_acquire(10, 50, /*cert_keyed=*/true).admitted);
}

TEST_CASE("OTA total gate: a very large ceiling does not overflow", "[ota][bound][total]") {
    // --ota-max-concurrent-total is only CLI::PositiveNumber-checked, so an
    // operator may legitimately configure a value whose product with the reserve
    // percentage exceeds int. Computed in int that multiply is undefined behaviour
    // — the UBSan nightly leg traps it — and in practice lands on a NEGATIVE
    // product, which then floors to 1: the operator asks for enormous capacity and
    // silently receives a single slot.
    CHECK(OtaTotalAdmission::effective_cap(1'000'000'000, 50, false) == 500'000'000);
    CHECK(OtaTotalAdmission::effective_cap(2'000'000'000, 50, false) == 1'000'000'000);
    CHECK(OtaTotalAdmission::effective_cap(2'147'483'647, 50, false) == 1'073'741'823);
    CHECK(OtaTotalAdmission::effective_cap(2'147'483'647, 0, false) == 2'147'483'647);
    // A certificate-keyed peer bypasses the arithmetic entirely, so it is exact.
    CHECK(OtaTotalAdmission::effective_cap(2'147'483'647, 50, true) == 2'147'483'647);
}
