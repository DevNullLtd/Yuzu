// Unit tests for claim_guardian_boot_epoch (UP-14): the hybrid max(persisted + 1, clock)
// boot epoch, its D1 recovery of an unusable stored value (including 2^62 - 1, whose
// successor would reach the ceiling), the 2^62 ceiling (checked on the persisted value
// BEFORE the + 1), the documented single-writer and same-second residuals, and the
// fail-to-zero rules (null store, read error, write failure, ceiling): a failed claim is 0
// and nothing is invented in memory or written. The UP-9 single-writer guard
// (GuardianInstanceLock) is covered at the end; the sole same-second equal-epoch residual
// that remains after it is pinned by the wiped-row test.

#include "guardian_boot_epoch.hpp"
#include "guardian_emit_seq.hpp"

#include <yuzu/agent/kv_store.hpp>

#include "fake_journal_store.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace yuzu::agent;
using Outcome = GuardianBootEpochClaim::Outcome;

namespace {

constexpr std::int64_t kNow = 1'790'000'000;
constexpr std::uint64_t kCeiling = std::uint64_t{1} << 62;

// Test-local fault injection over the shared FakeJournalStore. The faults live HERE, not on
// the shared fake, so no other suite can inherit a fault flag.
class FaultingStore final : public IJournalStore {
public:
    bool fail_get = false;
    bool fail_set = false;
    bool throw_get = false;
    bool throw_set = false;
    bool throw_sync = false;
    int sync_level = 2; // what pragma_synchronous() reports
    int set_calls = 0;
    int get_calls = 0;

    // Seed a raw value without counting it as a claim write.
    void seed(std::string_view value) {
        inner_.set(kGuardianBootEpochNamespace, kGuardianBootEpochKey, value);
    }
    [[nodiscard]] std::optional<std::string> stored() {
        auto r = inner_.get_entry(kGuardianBootEpochNamespace, kGuardianBootEpochKey);
        REQUIRE(r.has_value());
        return *r;
    }

    int pragma_synchronous() override {
        if (throw_sync)
            throw std::runtime_error("injected pragma_synchronous throw");
        return sync_level;
    }
    std::expected<KvNamespaceSize, KvStoreError> namespace_size(std::string_view p,
                                                                std::string_view x) override {
        return inner_.namespace_size(p, x);
    }
    std::expected<std::vector<KvKeySize>, KvStoreError>
    list_keys_sized(std::string_view p, std::string_view x) override {
        return inner_.list_keys_sized(p, x);
    }
    std::expected<std::optional<std::string>, KvStoreError> get_entry(std::string_view p,
                                                                      std::string_view k) override {
        ++get_calls;
        if (throw_get)
            throw std::runtime_error("injected get_entry throw");
        if (fail_get)
            return std::unexpected(KvStoreError{"injected get_entry failure"});
        return inner_.get_entry(p, k);
    }
    KvInsert insert_if_absent(std::string_view p, std::string_view k, std::string_view v) override {
        return inner_.insert_if_absent(p, k, v);
    }
    KvRename rename_key(std::string_view p, std::string_view a, std::string_view b) override {
        return inner_.rename_key(p, a, b);
    }
    int del_keys(std::string_view p, const std::vector<std::string>& keys) override {
        return inner_.del_keys(p, keys);
    }
    bool set(std::string_view p, std::string_view k, std::string_view v) override {
        ++set_calls;
        if (throw_set)
            throw std::runtime_error("injected set throw");
        if (fail_set)
            return false;
        return inner_.set(p, k, v);
    }

private:
    yuzu::test::FakeJournalStore inner_;
};

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

} // namespace

TEST_CASE("boot-epoch: absent row claims the clock and persists it", "[guardian][boot_epoch]") {
    FaultingStore s;
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::Claimed);
    CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow));
    CHECK(c.persisted == 0);
    CHECK(s.stored() == dec(kNow));
}

TEST_CASE("boot-epoch: the floor wins when persisted + 1 exceeds the clock",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed(dec(kNow + 100));
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::Claimed);
    CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow) + 101);
    CHECK(c.persisted == static_cast<std::uint64_t>(kNow) + 100);
    CHECK(s.stored() == dec(kNow + 101));
}

TEST_CASE("boot-epoch: the clock wins when it is ahead of persisted + 1",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed("5");
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::Claimed);
    CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow));
    CHECK(c.persisted == 5);
    CHECK(s.stored() == dec(kNow));
}

TEST_CASE("boot-epoch: a second claim in the same second is exactly one higher",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    const auto a = claim_guardian_boot_epoch(&s, kNow);
    const auto b = claim_guardian_boot_epoch(&s, kNow);
    REQUIRE(a.outcome == Outcome::Claimed);
    REQUIRE(b.outcome == Outcome::Claimed);
    CHECK(b.boot_epoch == a.boot_epoch + 1);
    CHECK(b.persisted == a.boot_epoch);
}

TEST_CASE("boot-epoch: a backward clock step between boots still increases the epoch",
          "[guardian][boot_epoch]") {
    // Crash after a durable claim: the next boot reads the persisted claim and adds one,
    // whatever the clock now says.
    FaultingStore s;
    const auto first = claim_guardian_boot_epoch(&s, kNow);
    const auto next = claim_guardian_boot_epoch(&s, kNow - 3600);
    CHECK(next.boot_epoch == first.boot_epoch + 1);
}

TEST_CASE("boot-epoch: a forward clock error is not undone by the corrected clock",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    const std::int64_t wrong = kNow + 10 * 86400; // clock ten days fast at boot 1
    const auto first = claim_guardian_boot_epoch(&s, wrong);
    const auto second = claim_guardian_boot_epoch(&s, kNow); // clock corrected at boot 2
    CHECK(first.boot_epoch == static_cast<std::uint64_t>(wrong));
    CHECK(second.boot_epoch == first.boot_epoch + 1); // stays ahead; never falls back to kNow
}

TEST_CASE("boot-epoch: a stale persisted value yields to the clock", "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed("1");
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::Claimed);
    CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow));
}

TEST_CASE("boot-epoch: a non-positive clock contributes zero, not a wrapped huge value",
          "[guardian][boot_epoch]") {
    SECTION("negative clock, persisted present -> persisted + 1") {
        FaultingStore s;
        s.seed("10");
        const auto c = claim_guardian_boot_epoch(&s, -5);
        CHECK(c.outcome == Outcome::Claimed);
        CHECK(c.boot_epoch == 11);
        CHECK(s.stored() == "11");
    }
    SECTION("zero clock, persisted present -> persisted + 1") {
        FaultingStore s;
        s.seed("10");
        const auto c = claim_guardian_boot_epoch(&s, 0);
        CHECK(c.boot_epoch == 11);
    }
    SECTION("negative clock, absent row -> 1 (never 0 on a successful claim)") {
        FaultingStore s;
        const auto c = claim_guardian_boot_epoch(&s, std::numeric_limits<std::int64_t>::min());
        CHECK(c.outcome == Outcome::Claimed);
        CHECK(c.boot_epoch == 1);
        CHECK(s.stored() == "1");
    }
}

TEST_CASE("boot-epoch: null store claims nothing", "[guardian][boot_epoch]") {
    const auto c = claim_guardian_boot_epoch(nullptr, kNow);
    CHECK(c.outcome == Outcome::NoStore);
    CHECK(c.boot_epoch == 0);
}

TEST_CASE("boot-epoch: a read error claims nothing and writes nothing", "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed("77");
    s.fail_get = true;
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::ReadFailed);
    CHECK(c.boot_epoch == 0);
    CHECK(s.set_calls == 0);
    s.fail_get = false;
    CHECK(s.stored() == "77"); // untouched
}

TEST_CASE("boot-epoch: a write failure claims nothing", "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed("77");
    s.fail_set = true;
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::WriteFailed);
    CHECK(c.boot_epoch == 0); // the candidate is NOT returned: it was not made durable
    CHECK(c.persisted == 77);
    CHECK(s.set_calls == 1);
    CHECK(s.stored() == "77");
}

TEST_CASE("boot-epoch: a throwing store is a failed claim, never an exception",
          "[guardian][boot_epoch]") {
    SECTION("get_entry throws") {
        FaultingStore s;
        s.throw_get = true;
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        CHECK(c.outcome == Outcome::ReadFailed);
        CHECK(c.boot_epoch == 0);
        CHECK(s.set_calls == 0);
    }
    SECTION("set throws") {
        FaultingStore s;
        s.throw_set = true;
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        CHECK(c.outcome == Outcome::WriteFailed);
        CHECK(c.boot_epoch == 0);
    }
}

TEST_CASE("boot-epoch: a store below FULL durability issues no epoch", "[guardian][boot_epoch]") {
    // UP-3: an epoch write that power loss can roll back could be re-issued by the next boot.
    for (const int level : {0, 1}) {
        DYNAMIC_SECTION("synchronous " << level) {
            FaultingStore s;
            s.seed("77");
            s.sync_level = level;
            const auto c = claim_guardian_boot_epoch(&s, kNow);
            CHECK(c.outcome == Outcome::DurabilityBelowFull);
            CHECK(c.boot_epoch == 0);
            CHECK(c.persisted == 77);
            CHECK(s.set_calls == 0);
            CHECK(s.stored() == "77"); // untouched
        }
    }
    SECTION("an absent row stays absent") {
        FaultingStore s;
        s.sync_level = 1;
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        CHECK(c.outcome == Outcome::DurabilityBelowFull);
        CHECK(c.boot_epoch == 0);
        CHECK(s.set_calls == 0);
        CHECK(!s.stored().has_value());
    }
    SECTION("an unusable row is not overwritten either") {
        FaultingStore s;
        s.seed("not-a-number");
        s.sync_level = 0;
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        CHECK(c.outcome == Outcome::DurabilityBelowFull);
        CHECK(c.boot_epoch == 0);
        CHECK(s.set_calls == 0);
        CHECK(s.stored() == "not-a-number");
    }
}

TEST_CASE("boot-epoch: an unreadable synchronous pragma is a failed read, nothing written",
          "[guardian][boot_epoch]") {
    // -1 is the store's "could not read the pragma" value, not a durability fact.
    FaultingStore s;
    s.seed("77");
    s.sync_level = -1;
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::ReadFailed);
    CHECK(c.boot_epoch == 0);
    CHECK(s.set_calls == 0);
    CHECK(s.stored() == "77"); // untouched
}

TEST_CASE("boot-epoch: FULL and EXTRA durability claim normally", "[guardian][boot_epoch]") {
    for (const int level : {2, 3}) {
        DYNAMIC_SECTION("synchronous " << level) {
            FaultingStore s;
            s.seed("77");
            s.sync_level = level;
            const auto c = claim_guardian_boot_epoch(&s, kNow);
            CHECK(c.outcome == Outcome::Claimed);
            CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow));
            CHECK(s.set_calls == 1);
            CHECK(s.stored() == dec(static_cast<std::uint64_t>(kNow)));
        }
    }
}

TEST_CASE("boot-epoch: a throwing pragma_synchronous is a failed read, nothing written",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed("77");
    s.throw_sync = true;
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::ReadFailed);
    CHECK(c.boot_epoch == 0);
    CHECK(s.set_calls == 0);
    CHECK(s.stored() == "77");
}

TEST_CASE("boot-epoch: a wiped row in the same second reuses the epoch (documented residual)",
          "[guardian][boot_epoch]") {
    // PINNED RESIDUAL (the UP-14 residual-acceptance ruling), not a goal: with the KV row wiped and
    // a restart inside the same wall-clock second, both boots resolve to that second, so the epochs
    // are EQUAL and the server cannot see a regression. Closing it needs a sub-second clock term,
    // which would change the epoch's definition. If this test starts failing, the residual changed:
    // update guardian_boot_epoch.hpp's DOCUMENTED RESIDUAL paragraph with it.
    FaultingStore before_wipe;
    const auto a = claim_guardian_boot_epoch(&before_wipe, kNow);
    FaultingStore after_wipe; // an empty store: the row is gone
    const auto b = claim_guardian_boot_epoch(&after_wipe, kNow);
    CHECK(a.boot_epoch == b.boot_epoch);

    // The consequence: equal epoch with a RESTARTED sequence. Each boot builds a fresh emit
    // source, so both start at emit_seq 1 and the pair (epoch, 1) is emitted twice; a server
    // comparing the pair cannot tell the two boots apart.
    GuardianEmitSeqSource first_boot(a.boot_epoch);
    GuardianEmitSeqSource second_boot(b.boot_epoch);
    CHECK(first_boot.boot_epoch == second_boot.boot_epoch);
    CHECK(first_boot.draw() == 1);
    CHECK(second_boot.draw() == 1);
}

TEST_CASE("boot-epoch: the ceiling is checked on the persisted value before the + 1",
          "[guardian][boot_epoch]") {
    SECTION("uint64 max is corrupt, not incremented: re-claim from the clock") {
        FaultingStore s;
        s.seed(dec(std::numeric_limits<std::uint64_t>::max()));
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        CHECK(c.outcome == Outcome::Recovered);
        CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow)); // a wrap would give 0 or 1
        CHECK(s.stored() == dec(kNow));
    }
    SECTION("exactly 2^62 is at the ceiling: corrupt") {
        FaultingStore s;
        s.seed(dec(kCeiling));
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        CHECK(c.outcome == Outcome::Recovered);
        CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow));
    }
    SECTION("2^62 - 1 is unusable: its successor would reach the ceiling, so it recovers") {
        FaultingStore s;
        s.seed(dec(kCeiling - 1));
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        // Not OutOfRange: that would leave the row in place and degrade EVERY later boot
        // to epoch 0 with nothing to correct it.
        CHECK(c.outcome == Outcome::Recovered);
        CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow));
        CHECK(c.persisted == 0); // an unusable value is not reported as a persisted one
        CHECK(s.set_calls == 1);
        CHECK(s.stored() == dec(kNow)); // overwritten with the re-claim
    }
    SECTION("2^62 - 2 -> 2^62 - 1 is the largest claimable epoch") {
        FaultingStore s;
        s.seed(dec(kCeiling - 2));
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        CHECK(c.outcome == Outcome::Claimed);
        CHECK(c.boot_epoch == kCeiling - 1);
        CHECK(s.stored() == dec(kCeiling - 1));
    }
    SECTION("a clock term at or above the ceiling is refused, nothing written") {
        FaultingStore s;
        const auto c = claim_guardian_boot_epoch(&s, static_cast<std::int64_t>(kCeiling)); // 2^62
        CHECK(c.outcome == Outcome::OutOfRange);
        CHECK(c.boot_epoch == 0);
        CHECK(s.set_calls == 0);
        CHECK_FALSE(s.stored().has_value());
    }
}

TEST_CASE("boot-epoch: a persisted 2^62 - 1 recovers once, then claims normally",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed(dec(kCeiling - 1));

    const auto boot1 = claim_guardian_boot_epoch(&s, kNow);
    REQUIRE(boot1.outcome == Outcome::Recovered);
    REQUIRE(boot1.boot_epoch == static_cast<std::uint64_t>(kNow));
    REQUIRE(s.stored() == dec(kNow));

    const auto boot2 = claim_guardian_boot_epoch(&s, kNow); // same second
    CHECK(boot2.outcome == Outcome::Claimed);
    CHECK(boot2.persisted == boot1.boot_epoch);
    CHECK(boot2.boot_epoch == boot1.boot_epoch + 1); // persisted + 1, not epoch 0
    CHECK(s.stored() == dec(boot2.boot_epoch));
}

TEST_CASE("boot-epoch: a persisted 2^62 - 2 claims the last usable epoch, then recovers",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed(dec(kCeiling - 2));

    const auto boot1 = claim_guardian_boot_epoch(&s, kNow);
    REQUIRE(boot1.outcome == Outcome::Claimed);
    REQUIRE(boot1.boot_epoch == kCeiling - 1);
    REQUIRE(s.stored() == dec(kCeiling - 1));

    // The next boot finds 2^62 - 1: unusable, so it re-claims from the clock rather than
    // sticking at 0.
    const auto boot2 = claim_guardian_boot_epoch(&s, kNow);
    CHECK(boot2.outcome == Outcome::Recovered);
    CHECK(boot2.boot_epoch == static_cast<std::uint64_t>(kNow));
    CHECK(s.stored() == dec(kNow));

    const auto boot3 = claim_guardian_boot_epoch(&s, kNow);
    CHECK(boot3.outcome == Outcome::Claimed);
    CHECK(boot3.boot_epoch == boot2.boot_epoch + 1);
}

TEST_CASE("boot-epoch: a stored value must parse in full, else it is recovered",
          "[guardian][boot_epoch]") {
    const auto expect_recovered = [](std::string_view raw) {
        FaultingStore s;
        s.seed(raw);
        const auto c = claim_guardian_boot_epoch(&s, kNow);
        CHECK(c.outcome == Outcome::Recovered);
        CHECK(c.boot_epoch == static_cast<std::uint64_t>(kNow));
        CHECK(c.persisted == 0);        // an unusable value is not reported as a persisted one
        CHECK(s.stored() == dec(kNow)); // overwritten with the re-claim
    };

    SECTION("embedded NUL") {
        expect_recovered(std::string("123\0"
                                     "456",
                                     7));
    }
    SECTION("trailing NUL") {
        expect_recovered(std::string("123\0", 4));
    }
    SECTION("trailing suffix") {
        expect_recovered("123abc");
    }
    SECTION("trailing space") {
        expect_recovered("123 ");
    }
    SECTION("trailing newline") {
        expect_recovered("123\n");
    }
    SECTION("leading space") {
        expect_recovered(" 123");
    }
    SECTION("leading plus") {
        expect_recovered("+123");
    }
    SECTION("negative") {
        expect_recovered("-5");
    }
    SECTION("empty") {
        expect_recovered("");
    }
    SECTION("not a number") {
        expect_recovered("garbage");
    }
    SECTION("overflows uint64") {
        expect_recovered("18446744073709551616");
    }
}

TEST_CASE("boot-epoch: recovering a corrupt row with a non-positive clock claims 1",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed("garbage");
    const auto c = claim_guardian_boot_epoch(&s, -1);
    CHECK(c.outcome == Outcome::Recovered);
    CHECK(c.boot_epoch == 1);
}

TEST_CASE("boot-epoch: a recovery that cannot be made durable is still 0",
          "[guardian][boot_epoch]") {
    FaultingStore s;
    s.seed("garbage");
    s.fail_set = true;
    const auto c = claim_guardian_boot_epoch(&s, kNow);
    CHECK(c.outcome == Outcome::WriteFailed);
    CHECK(c.boot_epoch == 0);
}

TEST_CASE("boot-epoch: round-trips through a real KvStore across a reopen",
          "[guardian][boot_epoch]") {
    yuzu::test::TempDbFile db{"yuzu_test_boot_epoch-"};

    std::uint64_t first = 0;
    {
        auto kv = KvStore::open(db.path);
        REQUIRE(kv.has_value());
        const auto c = claim_guardian_boot_epoch(&*kv, kNow);
        REQUIRE(c.outcome == Outcome::Claimed);
        first = c.boot_epoch;
        CHECK(first == static_cast<std::uint64_t>(kNow));
    } // closed: the claim must survive on disk, not in memory

    auto kv = KvStore::open(db.path);
    REQUIRE(kv.has_value());
    const auto stored = kv->get_entry(kGuardianBootEpochNamespace, kGuardianBootEpochKey);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == dec(first));

    const auto second = claim_guardian_boot_epoch(&*kv, kNow); // same second
    CHECK(second.outcome == Outcome::Claimed);
    CHECK(second.boot_epoch > first);
    CHECK(second.boot_epoch == first + 1);
}

namespace {

// Reads a stale snapshot of the epoch row, forwarding everything else to a real store. It
// stands in for a second process whose get_entry ran BEFORE the sibling's set(): the
// interleaving a plain read-then-set() claim does not exclude.
class StaleEpochReadStore final : public IJournalStore {
public:
    StaleEpochReadStore(IJournalStore& inner, std::string stale_row)
        : inner_(inner), stale_row_(std::move(stale_row)) {}

    int pragma_synchronous() override { return inner_.pragma_synchronous(); }
    std::expected<KvNamespaceSize, KvStoreError> namespace_size(std::string_view p,
                                                                std::string_view x) override {
        return inner_.namespace_size(p, x);
    }
    std::expected<std::vector<KvKeySize>, KvStoreError>
    list_keys_sized(std::string_view p, std::string_view x) override {
        return inner_.list_keys_sized(p, x);
    }
    std::expected<std::optional<std::string>, KvStoreError> get_entry(std::string_view p,
                                                                      std::string_view k) override {
        if (p == kGuardianBootEpochNamespace && k == kGuardianBootEpochKey)
            return std::optional<std::string>{stale_row_};
        return inner_.get_entry(p, k);
    }
    KvInsert insert_if_absent(std::string_view p, std::string_view k, std::string_view v) override {
        return inner_.insert_if_absent(p, k, v);
    }
    KvRename rename_key(std::string_view p, std::string_view a, std::string_view b) override {
        return inner_.rename_key(p, a, b);
    }
    int del_keys(std::string_view p, const std::vector<std::string>& keys) override {
        return inner_.del_keys(p, keys);
    }
    bool set(std::string_view p, std::string_view k, std::string_view v) override {
        return inner_.set(p, k, v);
    }

private:
    IJournalStore& inner_;
    std::string stale_row_;
};

} // namespace

TEST_CASE("boot-epoch: the claim ALONE lets two writers on one KV file take the SAME epoch",
          "[guardian][boot_epoch]") {
    // PINS THE ARITHMETIC OF THE UNGUARDED CLAIM, NOT DESIRED PRODUCTION BEHAVIOUR. The
    // two-argument claim is a plain read then a plain set(), and the KV file is in WAL mode,
    // which admits a second connection. If two writers both read N before either writes, both
    // claim N + 1 and draw emit_seq from 1. The production path closes this with the
    // per-data-directory GuardianInstanceLock (UP-9, tests below), which lives outside the
    // claim, so this test is expected to keep passing.
    //
    // The interleaving is SIMULATED: two real connections open one file (the WAL premise),
    // but the stale-read wrapper hands the second claim the row as it stood before the first
    // claim's write, so no real race runs. A compare-and-set INSIDE the claim goes through the
    // store interface and would be expected to make this test fail, which is the intended
    // signal to update the SINGLE-WRITER GUARD paragraph in guardian_boot_epoch.hpp and
    // design document section 7.1.
    yuzu::test::TempDbFile db{"yuzu_test_boot_epoch_two_proc-"};
    auto kv_a = KvStore::open(db.path);
    auto kv_b = KvStore::open(db.path);
    REQUIRE(kv_a.has_value());
    REQUIRE(kv_b.has_value()); // a second connection to the same file is not refused

    const auto seed = claim_guardian_boot_epoch(&*kv_a, kNow); // establishes the row N
    REQUIRE(seed.outcome == Outcome::Claimed);
    const std::string n = dec(seed.boot_epoch);

    // Process A claims N + 1 and writes it. Process B's read had already returned N.
    const auto a = claim_guardian_boot_epoch(&*kv_a, kNow);
    StaleEpochReadStore b_view(*kv_b, n);
    const auto b = claim_guardian_boot_epoch(&b_view, kNow);

    REQUIRE(a.outcome == Outcome::Claimed);
    REQUIRE(b.outcome == Outcome::Claimed);
    CHECK(a.boot_epoch == seed.boot_epoch + 1);
    CHECK(b.boot_epoch == a.boot_epoch); // the SAME epoch, from two writers

    GuardianEmitSeqSource proc_a(a.boot_epoch);
    GuardianEmitSeqSource proc_b(b.boot_epoch);
    CHECK(proc_a.draw() == proc_b.draw()); // overlapping sequences: both draw 1
}

TEST_CASE("boot-epoch: a second holder of the instance lock is refused while the first lives",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    auto first = GuardianInstanceLock::acquire(lock_path);
    REQUIRE(first.held());
    CHECK(first.state() == GuardianInstanceLock::State::Held);

    // A second acquire contends exactly like a second agent process would (flock is per open
    // file description; Windows share mode 0), including from this very process.
    auto second = GuardianInstanceLock::acquire(lock_path);
    CHECK_FALSE(second.held());
    CHECK(second.state() == GuardianInstanceLock::State::Contended);

    // A bounded wait on a lock that never frees still ends Contended.
    auto waited = GuardianInstanceLock::acquire(lock_path, std::chrono::milliseconds{150});
    CHECK(waited.state() == GuardianInstanceLock::State::Contended);
}

TEST_CASE("boot-epoch: releasing the instance lock lets the next process take it",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    {
        auto first = GuardianInstanceLock::acquire(lock_path);
        REQUIRE(first.held());
    } // destruction drops the lock, as process exit does after a crash
    auto next = GuardianInstanceLock::acquire(lock_path);
    CHECK(next.held());

    // A moved-from lock owns nothing; the moved-to one keeps the lock.
    GuardianInstanceLock moved = std::move(next);
    CHECK(moved.held());
    // NOLINTNEXTLINE(bugprone-use-after-move)
    CHECK(next.state() == GuardianInstanceLock::State::NotAcquired);
    CHECK(GuardianInstanceLock::acquire(lock_path).state() ==
          GuardianInstanceLock::State::Contended);
}

TEST_CASE("boot-epoch: a bounded wait takes the lock once the holder lets go",
          "[guardian][boot_epoch][instance_lock]") {
    // The service-restart case: the old process is still shutting down when the new one
    // starts, and the new one must still claim.
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    auto holder = std::make_unique<GuardianInstanceLock>(GuardianInstanceLock::acquire(lock_path));
    REQUIRE(holder->held());

    std::thread releaser([&holder] {
        std::this_thread::sleep_for(std::chrono::milliseconds{150});
        holder.reset();
    });
    auto waiter = GuardianInstanceLock::acquire(lock_path, std::chrono::seconds{5});
    releaser.join();
    CHECK(waiter.held());
}

TEST_CASE("boot-epoch: an unopenable lock path is Failed, not Held",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    // The parent directory does not exist.
    auto lock = GuardianInstanceLock::acquire(dir.path / "missing" / "guardian_boot_epoch.lock");
    CHECK_FALSE(lock.held());
    CHECK(lock.state() == GuardianInstanceLock::State::Failed);
}

TEST_CASE("boot-epoch: the guarded claim refuses without the lock and touches nothing",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    FaultingStore s;
    s.seed(dec(5));

    SECTION("not held: epoch 0, store untouched, row unchanged") {
        auto holder = GuardianInstanceLock::acquire(lock_path);
        REQUIRE(holder.held());
        auto loser = GuardianInstanceLock::acquire(lock_path);
        REQUIRE_FALSE(loser.held());

        const auto c = claim_guardian_boot_epoch(&s, kNow, loser);
        CHECK(c.boot_epoch == 0);
        CHECK(c.outcome == Outcome::InstanceLockNotHeld);
        CHECK(s.get_calls == 0);
        CHECK(s.set_calls == 0);
        CHECK(s.stored() == std::optional<std::string>{dec(5)});
    }
    SECTION("default-constructed (never acquired) is not held either") {
        GuardianInstanceLock none;
        const auto c = claim_guardian_boot_epoch(&s, kNow, none);
        CHECK(c.outcome == Outcome::InstanceLockNotHeld);
        CHECK(s.set_calls == 0);
    }
    SECTION("held: the claim proceeds exactly as the unguarded one") {
        auto lock = GuardianInstanceLock::acquire(lock_path);
        REQUIRE(lock.held());
        const auto c = claim_guardian_boot_epoch(&s, kNow, lock);
        CHECK(c.outcome == Outcome::Claimed);
        CHECK(c.boot_epoch == kNow); // max(5 + 1, clock)
        CHECK(s.set_calls == 1);
    }
    SECTION("a null store is NoStore whatever the lock says") {
        GuardianInstanceLock none;
        CHECK(claim_guardian_boot_epoch(nullptr, kNow, none).outcome == Outcome::NoStore);
    }
}

TEST_CASE("boot-epoch: two agents on one data directory cannot both claim an epoch",
          "[guardian][boot_epoch][instance_lock]") {
    // UP-9 end to end at the unit level: a real KvStore, two lock holders, two guarded claims.
    // The first claims N + 1; the second is refused and stays unordered (0/0), so the two can
    // no longer emit equal epochs with overlapping sequences.
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    auto kv = KvStore::open(dir.path / "kv_store.db");
    REQUIRE(kv.has_value());
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    auto lock_a = GuardianInstanceLock::acquire(lock_path);
    auto lock_b = GuardianInstanceLock::acquire(lock_path);
    const auto a = claim_guardian_boot_epoch(&*kv, kNow, lock_a);
    const auto b = claim_guardian_boot_epoch(&*kv, kNow, lock_b);

    CHECK(a.outcome == Outcome::Claimed);
    CHECK(a.boot_epoch != 0);
    CHECK(b.outcome == Outcome::InstanceLockNotHeld);
    CHECK(b.boot_epoch == 0);
}

TEST_CASE("boot-epoch: a directory or a missing parent is Failed and carries the OS error",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);

    // A directory in the lock file's place is never a lock.
    auto as_dir = GuardianInstanceLock::acquire(dir.path);
    CHECK(as_dir.state() == GuardianInstanceLock::State::Failed);
    CHECK(as_dir.native_error() != 0);

    auto missing = GuardianInstanceLock::acquire(dir.path / "missing" / "guardian_boot_epoch.lock");
    CHECK(missing.state() == GuardianInstanceLock::State::Failed);
    CHECK(missing.native_error() != 0);

    // A held lock reports no error, and a contended one reports the contention.
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";
    auto held = GuardianInstanceLock::acquire(lock_path);
    REQUIRE(held.held());
    CHECK(held.native_error() == 0);
    auto contended = GuardianInstanceLock::acquire(lock_path);
    CHECK(contended.state() == GuardianInstanceLock::State::Contended);
    CHECK(contended.native_error() != 0);
}

TEST_CASE("boot-epoch: move-assignment releases the lock it replaces",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto path_a = dir.path / "a.lock";
    const auto path_b = dir.path / "b.lock";

    auto target = GuardianInstanceLock::acquire(path_a);
    auto source = GuardianInstanceLock::acquire(path_b);
    REQUIRE(target.held());
    REQUIRE(source.held());

    target = std::move(source);
    CHECK(target.held());
    // NOLINTNEXTLINE(bugprone-use-after-move)
    CHECK(source.state() == GuardianInstanceLock::State::NotAcquired);
    // a.lock was released by the assignment; b.lock is still held, now by `target`.
    CHECK(GuardianInstanceLock::acquire(path_a).held());
    CHECK(GuardianInstanceLock::acquire(path_b).state() == GuardianInstanceLock::State::Contended);

    // Self-move-assignment keeps the lock.
    auto& alias = target;
    target = std::move(alias);
    CHECK(target.held());
}

TEST_CASE("boot-epoch: outcome names are the strings the operator documentation quotes",
          "[guardian][boot_epoch]") {
    CHECK(std::string_view{guardian_boot_epoch_outcome_name(Outcome::Claimed)} == "claimed");
    CHECK(std::string_view{guardian_boot_epoch_outcome_name(Outcome::Recovered)} == "recovered");
    CHECK(std::string_view{guardian_boot_epoch_outcome_name(Outcome::NoStore)} == "no_store");
    CHECK(std::string_view{guardian_boot_epoch_outcome_name(Outcome::ReadFailed)} == "read_failed");
    CHECK(std::string_view{guardian_boot_epoch_outcome_name(Outcome::WriteFailed)} ==
          "write_failed");
    CHECK(std::string_view{guardian_boot_epoch_outcome_name(Outcome::OutOfRange)} ==
          "out_of_range");
    CHECK(std::string_view{guardian_boot_epoch_outcome_name(Outcome::DurabilityBelowFull)} ==
          "durability_below_full");
    CHECK(std::string_view{guardian_boot_epoch_outcome_name(Outcome::InstanceLockNotHeld)} ==
          "instance_lock_not_held");
}

#ifndef _WIN32
TEST_CASE("boot-epoch: a symlink in the lock file's place is refused, not followed",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto target = dir.path / "elsewhere";
    {
        std::ofstream out{target};
        out << "x";
    }
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";
    std::filesystem::create_symlink(target, lock_path);

    auto lock = GuardianInstanceLock::acquire(lock_path);
    CHECK_FALSE(lock.held());
    CHECK(lock.state() == GuardianInstanceLock::State::Failed);
    CHECK(lock.native_error() == ELOOP);
}

TEST_CASE("boot-epoch: a lock file unlinked while held is re-created by the next acquire "
          "(documented residual: needs data-directory write access)",
          "[guardian][boot_epoch][instance_lock]") {
    // Pins the limit stated in guardian_boot_epoch.hpp: an unlink AFTER a successful claim is not
    // detected. The pre-lock window (unlinked or replaced between the open and the flock) is
    // closed by the device/inode comparison and is exercised through acquire_for_test below.
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    auto first = GuardianInstanceLock::acquire(lock_path);
    REQUIRE(first.held());
    std::filesystem::remove(lock_path);
    auto second = GuardianInstanceLock::acquire(lock_path);
    CHECK(second.held()); // a new file, a new inode: this is the residual, not a guarantee
}

namespace {
// Unlink the lock file and create a fresh one at the same path: what the post-flock re-check
// exists to notice.
void replace_file(const std::filesystem::path& p) {
    std::filesystem::remove(p);
    std::ofstream out{p};
}
} // namespace

TEST_CASE("boot-epoch: a lock file replaced between the open and the lock is re-locked",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    int calls = 0;
    auto lock = GuardianInstanceLock::acquire_for_test(
        lock_path, std::chrono::milliseconds{0}, [&] {
            if (++calls == 1)
                replace_file(lock_path); // only the first attempt loses its file
        });
    // The first attempt locked the unlinked inode, saw the path name another file, dropped it and
    // locked the new one: two attempts, and the lock is on the file that is now at the path.
    CHECK(calls == 2);
    REQUIRE(lock.held());
    CHECK(lock.native_error() == 0);
    CHECK(GuardianInstanceLock::acquire(lock_path).state() ==
          GuardianInstanceLock::State::Contended);
}

TEST_CASE("boot-epoch: a lock file replaced on every attempt ends Failed with ESTALE",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    int calls = 0;
    auto lock = GuardianInstanceLock::acquire_for_test(
        lock_path, std::chrono::seconds{5}, [&] {
            ++calls;
            replace_file(lock_path);
        });
    // The first attempt plus kMaxReplacedRetries (5) retries, then it gives up. The wait is not
    // consulted: replacement is not contention, so the loop never sleeps.
    CHECK(calls == 6);
    CHECK_FALSE(lock.held());
    CHECK(lock.state() == GuardianInstanceLock::State::Failed);
    CHECK(lock.native_error() == ESTALE);
}

TEST_CASE("boot-epoch: a path that cannot be re-resolved reports its own error, not ESTALE",
          "[guardian][boot_epoch][instance_lock]") {
    if (::geteuid() == 0)
        SKIP("root ignores directory permissions");
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto sub = dir.path / "sub";
    std::filesystem::create_directories(sub);
    const auto lock_path = sub / "guardian_boot_epoch.lock";

    auto lock = GuardianInstanceLock::acquire_for_test(
        lock_path, std::chrono::milliseconds{0}, [&] {
            // Search permission gone: stat(path) now fails with EACCES, which says nothing about
            // the file having been replaced.
            std::filesystem::permissions(sub, std::filesystem::perms::none);
        });
    std::filesystem::permissions(sub, std::filesystem::perms::owner_all); // let TempDir clean up
    CHECK_FALSE(lock.held());
    CHECK(lock.state() == GuardianInstanceLock::State::Failed);
    CHECK(lock.native_error() == EACCES);
}

TEST_CASE("boot-epoch: a parent that stops being a directory reports its own error, any user",
          "[guardian][boot_epoch][instance_lock]") {
    // Root-proof sibling of the EACCES case: no permission bits are involved, so it also runs
    // as root. The hook swaps the lock file's parent directory for a regular file, and the
    // re-resolve of "<parent>/guardian_boot_epoch.lock" then fails with ENOTDIR, which says
    // nothing about the file having been replaced and must not be relabelled ESTALE. (calls == 1
    // does not by itself prove "not retried": a retry would fail at open() with the same ENOTDIR
    // without running the hook again; the pinned facts are the error code and the single hook run.)
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto sub = dir.path / "sub";
    std::filesystem::create_directories(sub);
    const auto lock_path = sub / "guardian_boot_epoch.lock";

    int calls = 0;
    auto lock = GuardianInstanceLock::acquire_for_test(
        lock_path, std::chrono::milliseconds{0}, [&] {
            ++calls;
            std::filesystem::remove_all(sub);
            std::ofstream out{sub}; // "sub" is now a regular file
        });
    CHECK(calls == 1); // the hook ran once
    CHECK_FALSE(lock.held());
    CHECK(lock.state() == GuardianInstanceLock::State::Failed);
    CHECK(lock.native_error() == ENOTDIR);
}

TEST_CASE("boot-epoch: a non-regular file at the lock path is refused",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";
    REQUIRE(::mkfifo(lock_path.c_str(), 0600) == 0);

    // open(O_RDWR) on a FIFO succeeds without blocking; the regular-file check then refuses it.
    auto lock = GuardianInstanceLock::acquire(lock_path);
    CHECK_FALSE(lock.held());
    CHECK(lock.state() == GuardianInstanceLock::State::Failed);
    CHECK(lock.native_error() == EINVAL);
}

TEST_CASE("boot-epoch: a throwing test hook fails the attempt instead of escaping",
          "[guardian][boot_epoch][instance_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_boot_epoch_lock-"};
    std::filesystem::create_directories(dir.path);
    const auto lock_path = dir.path / "guardian_boot_epoch.lock";

    auto lock = GuardianInstanceLock::acquire_for_test(
        lock_path, std::chrono::milliseconds{0}, [] { throw std::runtime_error("hook"); });
    CHECK_FALSE(lock.held());
    CHECK(lock.state() == GuardianInstanceLock::State::Failed);
    // The attempt's descriptor was closed on the way out: the next acquire is not contended.
    CHECK(GuardianInstanceLock::acquire(lock_path).held());
}
#endif
