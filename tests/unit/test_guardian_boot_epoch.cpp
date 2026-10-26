// Unit tests for claim_guardian_boot_epoch (UP-14): the hybrid max(persisted + 1, clock)
// boot epoch, its D1 recovery of an unusable stored value (including 2^62 - 1, whose
// successor would reach the ceiling), the 2^62 ceiling (checked on the persisted value
// BEFORE the + 1), the documented single-writer and same-second residuals, and the
// fail-to-zero rules (null store, read error, write failure, ceiling): a failed claim is 0
// and nothing is invented in memory or written.

#include "guardian_boot_epoch.hpp"
#include "guardian_emit_seq.hpp"

#include <yuzu/agent/kv_store.hpp>

#include "fake_journal_store.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

TEST_CASE("boot-epoch: a wiped row in the same second reuses the epoch (documented residual)",
          "[guardian][boot_epoch]") {
    // PINNED RESIDUAL (D3), not a goal: with the KV row wiped and a restart inside the same
    // wall-clock second, both boots resolve to that second, so the epochs are EQUAL and the
    // server cannot see a regression. Closing it needs a sub-second clock term, which would
    // change the epoch's definition. If this test starts failing, the residual changed:
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

TEST_CASE("boot-epoch: two processes on one KV file can claim the SAME epoch (documented residual)",
          "[guardian][boot_epoch]") {
    // PINS A DOCUMENTED, ACCEPTED RESIDUAL (ruling D3), NOT DESIRED BEHAVIOUR. Nothing in the
    // agent enforces one process per data directory (see guardian_boot_epoch.hpp, SINGLE-WRITER
    // ASSUMPTION), and the KV file is in WAL mode, which admits a second connection. If two
    // processes both read N before either writes, both claim N + 1 and draw emit_seq from 1.
    // If this test starts failing, the residual changed: update that paragraph with it.
    //
    // Two REAL connections open one file (the WAL premise). The racing read is simulated by
    // handing the second claim the row as it stood before the first claim's write.
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
    CHECK(b.boot_epoch == a.boot_epoch); // the SAME epoch, from two live processes

    GuardianEmitSeqSource proc_a(a.boot_epoch);
    GuardianEmitSeqSource proc_b(b.boot_epoch);
    CHECK(proc_a.draw() == proc_b.draw()); // overlapping sequences: both draw 1
}
