/**
 * test_guardian_engine.cpp — Unit tests for GuardianEngine (Guardian PR 2).
 *
 * The engine accepts __guard__ commands (push_rules, get_status) over the
 * agent's CommandRequest dispatch path and persists rules into KvStore
 * under namespace "__guardian__". PR 2 has no real guard threads — these
 * tests verify the persistence + dispatch contract that PR 3 builds on.
 *
 * What is in scope:
 *   - apply_rules persists each rule under "rule:<id>" as binary-safe JSON
 *   - full_sync wipes the prior set; non-full_sync merges in
 *   - dispatch round-trips push_rules through proto SerializeAsString
 *   - dispatch returns a GuaranteedStateStatus on get_status
 *   - rule_count / policy_generation survive an in-process restart
 *     (re-construct GuardianEngine over the same KvStore)
 *   - kv-unavailable construction degrades gracefully without crashing
 *
 * What is out of scope (PR 3+):
 *   - Real guard threads, drift detection, remediation
 *   - sync_with_server doing anything beyond logging
 */

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>

#include "agent.grpc.pb.h"
#include "guaranteed_state.pb.h"
#include "guardian_arm_heartbeat.hpp" // GuardianArmStats complete type (rung 9c PR-3)
#include "guardian_legacy_sink_executor.hpp" // LegacySendOutcome (EventSink's return type, #4783)

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace gpb = ::yuzu::guardian::v1;
namespace apb = ::yuzu::agent::v1;
using yuzu::agent::GuardianEngine;
using yuzu::agent::KvStore;

namespace {

std::string uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME")) return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}

// Path uniqueness delegates to the shared salt + atomic counter helper in
// test_helpers.hpp — the pattern a90a21e introduced for this file is now the
// single source of truth for every test harness. See #482 for history.
fs::path unique_kv_path() {
    const auto dir = fs::temp_directory_path() / ("yuzu_test_guardian" + uid_suffix());
    return dir / (yuzu::test::unique_temp_path("guardian_").filename().string() + ".db");
}

struct GuardianFixture {
    // FIRST member — destructor fires even if downstream construction
    // throws, so a partial REQUIRE failure below does not leak the .db /
    // -wal / -shm trio. RAII cleanup means no manual fs::remove here.
    yuzu::test::TempDbFile db_{unique_kv_path()};
    std::unique_ptr<KvStore> kv;
    std::unique_ptr<GuardianEngine> engine;

    GuardianFixture() {
        auto opened = KvStore::open(db_.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));
        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-test");
        REQUIRE(engine->start_local().has_value());
    }

    // Default destructor: engine → kv → db_ destroy in reverse-declaration
    // order, so SQLite handles close before TempDbFile removes the files.

    static gpb::GuaranteedStateRule make_rule(const std::string& id, const std::string& name,
                                                bool enabled = true) {
        gpb::GuaranteedStateRule r;
        r.set_rule_id(id);
        r.set_name(name);
        r.set_yaml_source("name: " + name + "\n");
        r.set_version(1);
        r.set_enabled(enabled);
        r.set_enforcement_mode("enforce");
        return r;
    }

    // A rule that actually arms a RegistryGuard on Windows (registry-change spark
    // + registry-value-equals assertion). The key need not exist — post-C1 the
    // guard worker stays ALIVE on a nearest-ancestor watch (waiting for the key to
    // appear) instead of exiting; get_status is still fail-closed because there is
    // no self-test verdict yet, so the rule reports "errored" regardless.
    static gpb::GuaranteedStateRule make_registry_rule(const std::string& id,
                                                       const std::string& mode) {
        gpb::GuaranteedStateRule r = make_rule(id, id);
        r.set_enforcement_mode(mode);
        r.mutable_spark()->set_type("registry-change");
        auto* a = r.mutable_assertion();
        a->set_type("registry-value-equals");
        (*a->mutable_params())["hive"] = "HKCU";
        (*a->mutable_params())["key"] = "SOFTWARE\\YuzuTest\\GuardStatusTest";
        (*a->mutable_params())["value_name"] = "Flag";
        (*a->mutable_params())["value_type"] = "REG_DWORD";
        (*a->mutable_params())["expected"] = "1";
        return r;
    }

    // A rule that arms a service guard (service-status-change spark +
    // service-running assertion): ServiceGuard on Windows, SystemdServiceGuard on
    // Linux+systemd, no-op elsewhere. The service/unit need not exist — the guard
    // watches for it; get_status is fail-closed regardless (no self-test verdict yet).
    static gpb::GuaranteedStateRule make_service_rule(const std::string& id,
                                                      const std::string& mode) {
        gpb::GuaranteedStateRule r = make_rule(id, id);
        r.set_enforcement_mode(mode);
        r.mutable_spark()->set_type("service-status-change");
        auto* a = r.mutable_assertion();
        a->set_type("service-running");
        (*a->mutable_params())["service_name"] = "Spooler";
        return r;
    }

    // #4021: a file-change/file-hash-equals rule. FileGuard is Windows-only for
    // the MVP (start() no-ops elsewhere), so this never actually arms a running
    // guard off Windows — what IS testable everywhere is start_guard_for_rule_locked's
    // config-build step (path/expected_hash/baseline-seed), observed via
    // last_file_expected_hash_for_test(). `expected_hash` empty means author it
    // as baseline-on-arm (the case this issue is about).
    static gpb::GuaranteedStateRule make_file_hash_rule(const std::string& id,
                                                        const std::string& path,
                                                        const std::string& expected_hash = "") {
        gpb::GuaranteedStateRule r = make_rule(id, id);
        r.mutable_spark()->set_type("file-change");
        auto* a = r.mutable_assertion();
        a->set_type("file-hash-equals");
        (*a->mutable_params())["path"] = path;
        if (!expected_hash.empty())
            (*a->mutable_params())["expected_hash"] = expected_hash;
        return r;
    }

    static gpb::GuaranteedStatePush make_push(std::vector<gpb::GuaranteedStateRule> rules,
                                              bool full_sync) {
        gpb::GuaranteedStatePush push;
        push.set_full_sync(full_sync);
        for (auto& r : rules)
            *push.add_rules() = std::move(r);
        return push;
    }
};

} // namespace

// ── #4021: persisted baseline survives full_sync / seeds a re-arm ──────────
//
// full_sync (any unrelated fleet rule mutation, or an agent restart) used to tear
// down every guard and re-arm fresh, with no memory of a baseline a rule had
// already captured — a `file-hash-equals` rule authored with no `expected_hash`
// would silently re-capture "whatever's on disk right now" as its new baseline,
// laundering genuine drift into a false compliant with no remediation. These
// tests exercise the KV-persisted-baseline substrate + the seed-lookup that now
// runs at legacy arm time (start_guard_for_rule_locked) — the config-build step
// runs identically on every OS; only the running FileGuard itself is
// Windows-only, so last_file_expected_hash_for_test() is what's observable here.

TEST_CASE("a file-hash-equals rule with no persisted baseline arms with no seed",
          "[guardian][engine][baseline]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_file_hash_rule("r1", "/tmp/x");
    // Serialize-then-dispatch so the params Map is parsed INSIDE the agent DLL
    // (#501 cross-image hash-seed) - a direct apply_rules(p) call here builds
    // the rule's params Map in the TEST EXE, which a DLL-side .find() (in
    // spark_spec_from_rule/start_guard_for_rule_locked) can spuriously miss.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);
    CHECK(f.engine->last_file_expected_hash_for_test().empty()); // first-ever arm: nothing to seed
}

TEST_CASE("a persisted baseline matching this rule's fingerprint seeds the arm",
          "[guardian][engine][baseline]") {
    GuardianFixture f;
    const std::string hash(64, 'a');
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/x";
    j["hash"] = hash;
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_file_hash_rule("r1", "/tmp/x");
    // #501: serialize-then-dispatch, see the comment on the test above.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);
    CHECK(f.engine->last_file_expected_hash_for_test() == hash);
}

TEST_CASE("a persisted baseline for a DIFFERENT target does not seed (fingerprint mismatch)",
          "[guardian][engine][baseline]") {
    GuardianFixture f;
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/some-other-path";
    j["hash"] = std::string(64, 'b');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_file_hash_rule("r1", "/tmp/x");
    // #501: serialize-then-dispatch, see the comment on the first test above.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);
    CHECK(f.engine->last_file_expected_hash_for_test().empty()); // genuinely different target
}

TEST_CASE("an authored expected_hash always wins over any persisted baseline",
          "[guardian][engine][baseline]") {
    GuardianFixture f;
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/x";
    j["hash"] = std::string(64, 'c');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    const std::string authored(64, 'd');
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_file_hash_rule("r1", "/tmp/x", authored);
    // #501: serialize-then-dispatch, see the comment on the first test above.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);
    CHECK(f.engine->last_file_expected_hash_for_test() == authored);
}

TEST_CASE("full_sync clears the prior rule set but PRESERVES a persisted baseline",
          "[guardian][engine][baseline][full_sync]") {
    GuardianFixture f;
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/x";
    j["hash"] = std::string(64, 'e');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    // r1 must be a REAL pushed rule first (Gate 3 quality-engineer follow-up:
    // otherwise the closing CHECK_FALSE below is vacuously true regardless of
    // whether the scoped-delete fix works, since rule:r1 was never written in
    // the first place).
    //
    // Direct apply_rules() call is safe here (unlike the [baseline] tests
    // above/below, which route through guardian_dispatch_push_bytes_for_test
    // for #501) ONLY because make_rule() populates no assertion params() Map
    // at all - swap either make_rule() call in this test for
    // make_file_hash_rule() and it needs the same serialize-then-dispatch
    // migration, or the #501 cross-image hash-seed flake reopens.
    f.engine->apply_rules(
        GuardianFixture::make_push({GuardianFixture::make_rule("r1", "r1")}, /*full_sync=*/true));
    REQUIRE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r1"));

    // r1's baseline was captured BEFORE this push; the new full_sync push doesn't
    // even name r1 (an unrelated rule's fleet edit, mirroring #3990's amplifier) —
    // r1 is genuinely gone from this push, same as the server omitting a
    // disabled/out-of-scope rule (guardian_push_builder.cpp). The baseline record
    // must survive regardless: the agent cannot distinguish "r1 was deleted" from
    // "r1 is temporarily out of scope for this push", and sweeping on absence
    // would reintroduce this issue's exact laundering the next time r1 reappears.
    f.engine->apply_rules(
        GuardianFixture::make_push({GuardianFixture::make_rule("other", "other")}, /*full_sync=*/true));

    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "baseline:r1");
    REQUIRE(raw.has_value());
    auto parsed = nlohmann::json::parse(*raw);
    CHECK(parsed.value("hash", std::string{}) == std::string(64, 'e'));

    // The rule cache itself IS cleared by full_sync, unaffected by this change —
    // only baseline: keys are exempted from the sweep.
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r1"));
}

TEST_CASE("a full_sync that DOES re-arm the baselined rule seeds it from the persisted "
          "record, not from current disk content",
          "[guardian][engine][baseline][full_sync]") {
    GuardianFixture f;
    const std::string original_hash(64, 'f');
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/x";
    j["hash"] = original_hash;
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    // Simulates the exact bug scenario: r1 was baselined at `original_hash` some
    // time ago (possibly now genuinely drifted on disk — this test doesn't need a
    // real file since FileGuard doesn't run off Windows); an UNRELATED fleet edit
    // now triggers a full_sync that also re-includes r1 unchanged.
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_file_hash_rule("r1", "/tmp/x");
    // #501: serialize-then-dispatch - see the comment on the first [baseline]
    // test above for the full cross-image hash-seed rationale.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);
    CHECK(f.engine->last_file_expected_hash_for_test() == original_hash);

    // The persisted record itself is unchanged — this arm attempt (whether or not
    // a real guard ever runs to re-confirm it) did not silently recapture.
    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "baseline:r1");
    REQUIRE(raw.has_value());
    CHECK(nlohmann::json::parse(*raw).value("hash", std::string{}) == original_hash);
}

// ── guardian_persist_baseline's overwrite guard (adversarial-review K1/C2-1) ──
//
// A TRANSIENT seed-lookup failure (or, equivalently for this guard's purposes,
// any reason a capture fires despite a good record already being on file) must
// never let the resulting fresh capture overwrite that good record — on the
// happy path a matching well-formed record means guardian_seed_baseline would
// have seeded expected_hash and the capture branch would never fire at all, so
// reaching persist with a same-fingerprint record already present is only
// reachable via a failed seed lookup. Exercised directly via the
// `_for_test` forwarders since the real call site (FileGuard::Config::
// on_baseline) only fires from a Windows-only guard worker this platform's
// tests cannot run end-to-end.

TEST_CASE("persist refuses to overwrite an existing SAME-fingerprint baseline",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    const std::string good(64, 'a');
    const std::string drifted(64, 'b');
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = fp;
    j["hash"] = good;
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    // Simulates a fresh capture reaching persist despite a good record already
    // on file (the only reachable cause: the seed lookup that should have
    // prevented this capture in the first place failed transiently).
    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", fp, drifted);

    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "baseline:r1");
    REQUIRE(raw.has_value());
    CHECK(nlohmann::json::parse(*raw).value("hash", std::string{}) == good); // NOT overwritten
}

TEST_CASE("persist writes normally when no baseline exists yet",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    const std::string hash(64, 'c');

    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", fp, hash);

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", fp);
    REQUIRE(seeded.has_value());
    CHECK(*seeded == hash);
}

TEST_CASE("persist writes normally for a genuine retarget (different fingerprint)",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/old-path";
    j["hash"] = std::string(64, 'd');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    const std::string new_fp = "file-hash-equals|/tmp/new-path";
    const std::string new_hash(64, 'e');
    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", new_fp, new_hash);

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", new_fp);
    REQUIRE(seeded.has_value());
    CHECK(*seeded == new_hash); // the retarget's own capture DID write
}

TEST_CASE("persist writes normally over a malformed existing record (self-heals)",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", "not valid json"));

    const std::string hash(64, 'f');
    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", fp, hash);

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", fp);
    REQUIRE(seeded.has_value());
    CHECK(*seeded == hash);
}

// ── schema-version mismatch (Gate 3 quality-engineer follow-up) ────────────
//
// Pins the exact scenario the 7451b67df fingerprint/schema-version-separation
// fix was written for: a record from a future/incompatible schema must be
// treated as Malformed (recapture/rewrite, self-heals), never silently
// matched as-is or misread as "a different target" — deleting the schema
// check in read_baseline_record should flip both of these red.

TEST_CASE("seed does not match a record with a mismatched schema version",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    nlohmann::json j;
    j["schema"] = 2; // future/incompatible - kBaselineSchemaVersion is 1
    j["fingerprint"] = fp;
    j["hash"] = std::string(64, 'a');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", fp);
    CHECK_FALSE(seeded.has_value()); // Malformed, not a false match
}

TEST_CASE("persist overwrites a record with a mismatched schema version",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    nlohmann::json j;
    j["schema"] = 2;
    j["fingerprint"] = fp; // matching fingerprint - only the schema differs
    j["hash"] = std::string(64, 'a');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    // A schema mismatch must be read as Malformed, NOT as a same-fingerprint
    // match — otherwise the persist-side overwrite guard would (wrongly)
    // refuse this write, permanently wedging the record at the old schema.
    const std::string mismatch_hash(64, 'b');
    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", fp, mismatch_hash);

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", fp);
    REQUIRE(seeded.has_value());
    CHECK(*seeded == mismatch_hash); // the write landed, not refused
}

TEST_CASE("arming a file-hash-equals rule wires the on_baseline capture callback",
          "[guardian][engine][baseline]") {
    // Gate 3 quality-engineer follow-up: distinct from
    // last_file_expected_hash_for_test (which only proves the seed lookup
    // ran) - this proves the CAPTURE callback was actually attached, since a
    // seeded rule never re-enters the branch that would exercise it.
    GuardianFixture f;
    CHECK_FALSE(f.engine->last_file_on_baseline_wired_for_test()); // nothing armed yet
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_file_hash_rule("r1", "/tmp/x");
    // #501: serialize-then-dispatch - see the comment on the first [baseline]
    // test above for the full cross-image hash-seed rationale.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);
    CHECK(f.engine->last_file_on_baseline_wired_for_test());
}

TEST_CASE("GuardianEngine: start_local on fresh KV reports zero rules",
          "[guardian][engine][start]") {
    GuardianFixture f;
    CHECK(f.engine->rule_count() == 0);
    CHECK(f.engine->policy_generation() == 0);
}

TEST_CASE("GuardianEngine: apply_rules persists rules and bumps generation",
          "[guardian][engine][apply]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush push;
    push.set_full_sync(true);
    push.set_policy_generation(7);
    *push.add_rules() = GuardianFixture::make_rule("r-1", "rule-one");
    *push.add_rules() = GuardianFixture::make_rule("r-2", "rule-two");

    auto applied = f.engine->apply_rules(push);
    REQUIRE(applied.has_value());
    CHECK(*applied == 2);
    CHECK(f.engine->rule_count() == 2);
    CHECK(f.engine->policy_generation() == 7);

    // Each rule landed under "rule:<id>" in the reserved KV namespace.
    auto keys = f.kv->list(GuardianEngine::kv_namespace(), "rule:");
    REQUIRE(keys.size() == 2);
    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "rule:r-1");
    REQUIRE(raw.has_value());
    CHECK(raw->find("\"name\":\"rule-one\"") != std::string::npos);
}

TEST_CASE("GuardianEngine: full_sync replaces the prior rule set",
          "[guardian][engine][apply][full_sync]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "old-1");
        *p.add_rules() = GuardianFixture::make_rule("r-2", "old-2");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }
    REQUIRE(f.engine->rule_count() == 2);

    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(99);
        *p.add_rules() = GuardianFixture::make_rule("r-99", "new-rule");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }

    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->policy_generation() == 99);
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-1"));
    CHECK(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-99"));
}

TEST_CASE("GuardianEngine: delta merge keeps prior rules and updates overlap",
          "[guardian][engine][apply][delta]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "first");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(false);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "first-renamed");
        *p.add_rules() = GuardianFixture::make_rule("r-2", "second");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }
    CHECK(f.engine->rule_count() == 2);
    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "rule:r-1");
    REQUIRE(raw.has_value());
    CHECK(raw->find("\"name\":\"first-renamed\"") != std::string::npos);
}

// ── #4665: an invalid rule_id anywhere in a push rejects the WHOLE push ────
//
// Pre-#4665, a push containing one rule with an empty (or otherwise invalid)
// rule_id among otherwise-valid rules would skip just that one rule and
// still apply/arm the rest - and, on a full_sync push, still advance
// policy_generation_ to the pushed value even though the skipped rule's
// prior enforcement (torn down by full_sync's own teardown) was never
// re-armed. That silently drops a rule's enforcement while reporting the
// agent as caught-up on the generation. The fix pre-validates every rule_id
// BEFORE any teardown/mutation and rejects the whole push on the first
// invalid one - these tests assert no rule mutation and no generation
// advance happen on rejection, for both full_sync and incremental pushes.

TEST_CASE("GuardianEngine: a push with an empty rule_id is rejected whole, not skipped",
          "[guardian][engine][apply][validation]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(5);
    *p.add_rules() = GuardianFixture::make_rule("", "no-id");
    *p.add_rules() = GuardianFixture::make_rule("r-keep", "valid");
    auto applied = f.engine->apply_rules(p);
    CHECK_FALSE(applied.has_value());
    // Nothing was persisted - not even the otherwise-valid "r-keep" rule -
    // and the generation did not advance off its fresh-KV default of 0.
    CHECK(f.engine->rule_count() == 0);
    CHECK(f.engine->policy_generation() == 0);
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-keep"));
}

TEST_CASE("GuardianEngine: a push with a charset-violating rule_id is rejected whole",
          "[guardian][engine][apply][validation]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("bad id\nwith control bytes", "bad");
    *p.add_rules() = GuardianFixture::make_rule("r-keep", "valid");
    auto applied = f.engine->apply_rules(p);
    CHECK_FALSE(applied.has_value());
    CHECK(f.engine->rule_count() == 0);
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-keep"));
}

TEST_CASE("GuardianEngine: a push with an over-length rule_id is rejected whole",
          "[guardian][engine][apply][validation]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule(std::string(257, 'a'), "too-long");
    *p.add_rules() = GuardianFixture::make_rule("r-keep", "valid");
    auto applied = f.engine->apply_rules(p);
    CHECK_FALSE(applied.has_value());
    CHECK(f.engine->rule_count() == 0);
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-keep"));
}

TEST_CASE("GuardianEngine: a full_sync push with a mixed valid/invalid rule_id set "
          "does not tear down the prior rule set",
          "[guardian][engine][apply][validation][full_sync]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(1);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "first");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }
    REQUIRE(f.engine->rule_count() == 1);
    REQUIRE(f.engine->policy_generation() == 1);

    // A later full_sync push at a HIGHER generation, with a genuinely new
    // valid rule alongside one with a bad id - if this silently tore down
    // r-1 (full_sync's own teardown, ~line 1091 at the time this test was
    // written) before validating, r-1 would be gone even though the whole
    // push is rejected.
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(2);
        *p.add_rules() = GuardianFixture::make_rule("r-2", "second");
        *p.add_rules() = GuardianFixture::make_rule("", "bad");
        auto applied = f.engine->apply_rules(p);
        CHECK_FALSE(applied.has_value());
    }

    // r-1 survives, unarmed generation 2 rule never landed, generation held at 1.
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->policy_generation() == 1);
    CHECK(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-1"));
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-2"));
}

TEST_CASE("GuardianEngine: an incremental push with a mixed valid/invalid rule_id set "
          "leaves the prior rule set untouched",
          "[guardian][engine][apply][validation]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(1);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "first");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(false);
        p.set_policy_generation(2);
        *p.add_rules() = GuardianFixture::make_rule("r-2", "second");
        *p.add_rules() = GuardianFixture::make_rule("bad id", "bad");
        auto applied = f.engine->apply_rules(p);
        CHECK_FALSE(applied.has_value());
    }
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->policy_generation() == 1);
    CHECK(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-1"));
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-2"));
}

TEST_CASE("GuardianEngine: a push where every rule_id is valid is unaffected by the "
          "#4665 pre-validation pass",
          "[guardian][engine][apply][validation]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(3);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "first");
    *p.add_rules() = GuardianFixture::make_rule("r-2", "second");
    auto applied = f.engine->apply_rules(p);
    REQUIRE(applied.has_value());
    CHECK(*applied == 2);
    CHECK(f.engine->rule_count() == 2);
    CHECK(f.engine->policy_generation() == 3);
}

TEST_CASE("GuardianEngine: a full_sync push clears a pre-#4665 legacy rule's PERSISTED "
          "state when the server excludes it for a non-conforming rule_id (hard cutover, "
          "not preserved)",
          "[guardian][engine][apply][validation][full_sync]") {
    // Governance-external-review finding (fjarvis, PR #4979): apply_rules()'s own
    // pre-validation now rejects any push CONTAINING a non-conforming rule_id, and
    // guardian_push_builder.cpp's server-side filter (#4665) excludes such a row
    // from every push it builds -- so the only way this state exists in a real
    // fleet is a row that predates #4665 entirely, now silently ABSENT from every
    // push. Seeded directly into KV here (the only way to reach it, since
    // apply_rules() can no longer be used to create it) to prove the
    // full_sync/exclusion interaction actually clears its persisted state cleanly
    // -- Dave's explicit call: this is a hard cutover, not a migration, so
    // "cleanly cleared" is the CORRECT outcome to pin, not a bug to route around.
    //
    // What this pins vs. what it doesn't (Gate-8 re-verification finding, LOW,
    // 2026-09-25): it proves the KV row is genuinely deleted -- the crux of the
    // hard-cutover behaviour, and what apply_rules() itself controls. It does NOT
    // prove a previously-RUNNING legacy guard gets torn down, because this
    // codebase's own Windows-only-for-MVP legacy backends (make_registry_rule's
    // and make_file_hash_rule's own doc comments, above) mean armed_guard_count()
    // cannot observe a real arm on this test's Linux CI host regardless of what
    // this fix touches -- that teardown path (stop_all_guards_locked(), already
    // unconditional and unchanged by this fix) is proven separately by this
    // file's other full_sync TEST_CASEs, not re-proven here.
    GuardianFixture f;
    nlohmann::json legacy;
    legacy["rule_id"] = "bad id";
    legacy["name"] = "bad id";
    legacy["yaml_source"] = "name: bad id\n";
    legacy["version"] = 1;
    legacy["enabled"] = true;
    legacy["enforcement_mode"] = "enforce";
    legacy["spark"] = nlohmann::json::object();
    legacy["assertion"] = nlohmann::json::object();
    legacy["remediation"] = nlohmann::json::object();
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "rule:bad id", legacy.dump()));
    REQUIRE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:bad id"));

    // The push the agent actually receives in production: fully valid, simply
    // omitting the excluded legacy rule_id -- exactly what
    // guardian_push_builder.cpp's filter produces.
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(2);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "first");
    auto applied = f.engine->apply_rules(p);
    REQUIRE(applied.has_value());

    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:bad id"));
    CHECK(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-1"));
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->policy_generation() == 2);
}

TEST_CASE("GuardianEngine: a rejected push does not latch the ack ledger against a "
          "later valid push",
          "[guardian][engine][apply][validation]") {
    // The #4665 pre-validation pass deliberately does NOT call
    // ack_ledger_->latch_failure() on rejection (it runs before
    // begin_application(), so there is no current application to latch a
    // failure against). This proves that choice leaves nothing "stuck" -
    // a rejected push followed by a genuinely valid push at a higher
    // generation must apply and advance normally.
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(1);
        *p.add_rules() = GuardianFixture::make_rule("", "bad");
        CHECK_FALSE(f.engine->apply_rules(p).has_value());
    }
    CHECK(f.engine->policy_generation() == 0);
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(2);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "first");
        auto applied = f.engine->apply_rules(p);
        REQUIRE(applied.has_value());
        CHECK(*applied == 1);
    }
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->policy_generation() == 2);
}

TEST_CASE("GuardianEngine: dispatch routes push_rules through SerializeAsString",
          "[guardian][engine][dispatch][push]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(42);
    *p.add_rules() = GuardianFixture::make_rule("r-d", "dispatched");

    // Route through the DLL-side helper: building the CommandRequest and
    // populating its `parameters` map must happen inside yuzu_agent_core
    // so that the dispatch-time find() uses the same absl::HashOf seed as
    // the insert(). See guardian_engine.hpp and #501 for the full story.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(
        *f.engine, p.SerializeAsString());
    CHECK(dr.exit_code == 0);
    CHECK(dr.content_type == "text");
    // Space-anchor the numeric substrings: the raw output is
    // "applied=1 generation=42 total=1" and a bare `"applied=1"` search would
    // also match `"applied=10"` / `"applied=100"` if this test ever grows.
    CHECK(dr.output.find("applied=1 ") != std::string::npos);
    CHECK(dr.output.find(" generation=42 ") != std::string::npos);
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->policy_generation() == 42);
}

TEST_CASE("GuardianEngine: dispatch get_status returns serialised proto",
          "[guardian][engine][dispatch][status]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "a");
    *p.add_rules() = GuardianFixture::make_rule("r-2", "b");
    REQUIRE(f.engine->apply_rules(p).has_value());

    apb::CommandRequest cmd;
    cmd.set_command_id("cmd-status");
    cmd.set_plugin("__guard__");
    cmd.set_action("get_status");

    auto dr = f.engine->dispatch(cmd);
    REQUIRE(dr.exit_code == 0);
    CHECK(dr.content_type == "proto");

    gpb::GuaranteedStateStatus status;
    REQUIRE(status.ParseFromString(dr.output));
    CHECK(status.agent_id() == "agent-test");
    CHECK(status.total_rules() == 2);
    // Fail-closed: rules report errored, never compliant, without a real verdict.
    CHECK(status.errored_rules() == 2);
    CHECK(status.compliant_rules() == 0);
    CHECK(status.rules_size() == 2);
}

TEST_CASE("GuardianEngine: get_status is fail-closed — an armed guard is never healthy/compliant",
          "[guardian][engine][status][health]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    // audit (not enforce) so this status test never triggers C2's enforce-mode key
    // recreation as a side effect — it only needs an armed guard to assert
    // fail-closed status, which holds regardless of enforcement mode.
    *p.add_rules() = GuardianFixture::make_registry_rule("reg-1", "audit");
    // Serialize-then-dispatch so the params Map is parsed INSIDE the agent DLL
    // (the #501 cross-image hash-seed reason the helper exists). On Windows this
    // arms a real RegistryGuard (post-C1 its worker stays alive on a nearest-
    // ancestor watch while the key is absent); off-Windows no guard arms. Either
    // way the status MUST be fail-closed.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    auto status = f.engine->get_status();
    REQUIRE(status.rules_size() == 1);
    // The B1/UP-1/F4 false-green fix: armed (or dead-but-armed) does NOT prove
    // compliance or health. guard_healthy is a reserved field, default false.
    CHECK_FALSE(status.rules(0).guard_healthy());
    CHECK(status.rules(0).status() == "errored");
    CHECK(status.compliant_rules() == 0);
    CHECK(status.errored_rules() == 1);
}

TEST_CASE("GuardianEngine: a service-status-change rule dispatches and is fail-closed",
          "[guardian][engine][service][status]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    // audit mode: on Windows this arms a real ServiceGuard watching the SCM, on
    // Linux+systemd a SystemdServiceGuard watching the unit over sd-bus, no guard
    // off both. Either way the rule is persisted and status is fail-closed (no
    // self-test verdict yet → "errored", never healthy/compliant) — the same
    // B1/UP-1/F4 invariant as the registry case.
    *p.add_rules() = GuardianFixture::make_service_rule("svc-1", "audit");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    auto status = f.engine->get_status();
    REQUIRE(status.rules_size() == 1);
    CHECK_FALSE(status.rules(0).guard_healthy());
    CHECK(status.rules(0).status() == "errored");
    CHECK(status.compliant_rules() == 0);
    CHECK(status.errored_rules() == 1);
}

// ── rung 6: apply_rules must honor enabled() the same way start_local does ──
// Previously apply_rules called start_guard_for_rule_locked for EVERY pushed
// rule regardless of enabled() (unlike start_local, which already skipped
// disabled cached rules on restart), so a disabled rule still armed a guard,
// and pushing an already-armed rule as disabled never stopped it. These use
// make_service_rule because it is the one fixture that arms a REAL guard
// cross-platform (SystemdServiceGuard on Linux+systemd, ServiceGuard on
// Windows) without depending on the target unit/service existing (R5) - a
// SKIP mirrors the existing [statereader] "no reachable system bus" precedent
// for environments where arming genuinely cannot happen.
//
// Every push here goes through guardian_dispatch_push_bytes_for_test (byte-
// serialize then parse INSIDE the DLL) rather than calling apply_rules()
// directly on a proto built in the test EXE - the #501 rationale above
// (GuardianFixture::make_rule) applies to any rule carrying a params Map, and
// make_service_rule's assertion().params() is exactly that. Calling
// apply_rules() directly on such a rule hits the cross-image hash-seed split
// on Windows MSVC debug builds: the DLL-side find() can miss the EXE-side-
// inserted "service_name" entry, arming with an empty service name instead of
// "Spooler" (caught on DGRHP: [guardian][engine] Windows run, 2026-07-16).

TEST_CASE("GuardianEngine: apply_rules never arms a guard for a disabled rule",
          "[guardian][engine][enabled]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_service_rule("svc-disabled", "audit");
    p.mutable_rules(0)->set_enabled(false);
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(f.engine->rule_count() == 1);       // still persisted...
    CHECK(f.engine->armed_guard_count() == 0); // ...but never armed
}

TEST_CASE("GuardianEngine: full_sync does not arm a disabled rule alongside an enabled one",
          "[guardian][engine][enabled][full_sync]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_service_rule("svc-on", "audit");
    *p.add_rules() = GuardianFixture::make_service_rule("svc-off", "audit");
    p.mutable_rules(1)->set_enabled(false);
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    if (f.engine->armed_guard_count() == 0)
        SKIP("no reachable system bus in this environment");
    CHECK(f.engine->rule_count() == 2);
    CHECK(f.engine->armed_guard_count() == 1); // only svc-on
}

TEST_CASE("GuardianEngine: disabling a previously-armed rule stops it; re-enabling re-arms it",
          "[guardian][engine][enabled]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-toggle", "audit");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    if (f.engine->armed_guard_count() == 0)
        SKIP("no reachable system bus in this environment");
    CHECK(f.engine->armed_guard_count() == 1);

    {
        gpb::GuaranteedStatePush p; // delta push: same rule_id, now disabled
        p.set_full_sync(false);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-toggle", "audit");
        p.mutable_rules(0)->set_enabled(false);
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    CHECK(f.engine->rule_count() == 1);       // the rule is still tracked (disabled, not deleted)...
    CHECK(f.engine->armed_guard_count() == 0); // ...but its guard was stopped

    {
        gpb::GuaranteedStatePush p; // delta push: same rule_id, re-enabled
        p.set_full_sync(false);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-toggle", "audit");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    CHECK(f.engine->armed_guard_count() == 1); // re-armed
}

TEST_CASE("GuardianEngine: re-pushing an enabled rule with the same id replaces its guard, "
          "never double-arms",
          "[guardian][engine][enabled]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-replace", "audit");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    if (f.engine->armed_guard_count() == 0)
        SKIP("no reachable system bus in this environment");
    CHECK(f.engine->armed_guard_count() == 1);

    {
        gpb::GuaranteedStatePush p; // delta push: same id, changed content, still enabled
        p.set_full_sync(false);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-replace", "enforce");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->armed_guard_count() == 1); // swapped, not accumulated to 2
}

TEST_CASE("GuardianEngine: a same-id replacement with an invalid new assertion retires the prior "
          "guard instead of leaving it enforcing stale policy",
          "[guardian][engine][enabled]") {
    // Regression for a bug found reviewing the enabled()/replace contract:
    // start_guard_for_rule_locked's per-branch "stop the existing guard for this
    // rule_id" step ran only on the happy path, AFTER validating the new rule's
    // assertion type - so a same-id re-push whose new assertion failed validation
    // returned false early and left the PRIOR guard armed, silently enforcing a
    // stale definition even though apply_rules had already persisted (and reported
    // success for) the new one. The retire-existing-guard step is now hoisted to
    // the top of start_guard_for_rule_locked so every return path starts clean.
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-invalidate", "audit");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    if (f.engine->armed_guard_count() == 0)
        SKIP("no reachable system bus in this environment");
    CHECK(f.engine->armed_guard_count() == 1);

    {
        gpb::GuaranteedStatePush p; // delta push: same id, still enabled, INVALID assertion type
        p.set_full_sync(false);
        auto rule = GuardianFixture::make_service_rule("svc-invalidate", "audit");
        rule.mutable_assertion()->set_type("service-frobnicate"); // not a recognized assertion kind
        *p.add_rules() = rule;
        // persistence succeeds regardless of arm outcome
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    CHECK(f.engine->rule_count() == 1);       // still persisted (as the new, invalid definition)...
    CHECK(f.engine->armed_guard_count() == 0); // ...but the OLD guard was retired, not left running
}

TEST_CASE("GuardianEngine: dispatch unknown action fails with detail",
          "[guardian][engine][dispatch][error]") {
    GuardianFixture f;
    apb::CommandRequest cmd;
    cmd.set_plugin("__guard__");
    cmd.set_action("not_a_real_action");
    auto dr = f.engine->dispatch(cmd);
    CHECK(dr.exit_code != 0);
    CHECK(dr.output.find("not_a_real_action") != std::string::npos);
}

TEST_CASE("GuardianEngine: dispatch push_rules with missing payload → exit_code 1",
          "[guardian][engine][dispatch][error]") {
    GuardianFixture f;
    apb::CommandRequest cmd;
    cmd.set_plugin("__guard__");
    cmd.set_action("push_rules");
    auto dr = f.engine->dispatch(cmd);
    CHECK(dr.exit_code == 1);
    // The push rides in the `payload` bytes field (not a `parameters` entry)
    // since the payload-bytes migration; an empty payload reports accordingly.
    CHECK(dr.output.find("missing payload") != std::string::npos);
}

TEST_CASE("GuardianEngine: dispatch push_rules with garbage proto → exit_code 2",
          "[guardian][engine][dispatch][error]") {
    GuardianFixture f;
    // Same DLL-boundary reasoning as the success test above — see #501 and
    // guardian_engine.hpp for the absl hash seed cross-image mismatch.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(
        *f.engine, "not a valid proto byte sequence");
    CHECK(dr.exit_code == 2);
    CHECK(dr.output.find("failed to parse") != std::string::npos);
}

TEST_CASE("GuardianEngine: rule cache + policy_generation survive engine reconstruct",
          "[guardian][engine][persistence]") {
    yuzu::test::TempDbFile db{unique_kv_path()};
    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        auto kv = std::make_unique<KvStore>(std::move(*opened));
        GuardianEngine eng(kv.get(), "agent-test");
        REQUIRE(eng.start_local().has_value());

        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(13);
        *p.add_rules() = GuardianFixture::make_rule("r-x", "persisted");
        REQUIRE(eng.apply_rules(p).has_value());
    }
    // Re-open the same KV file under a fresh engine and verify recovery.
    {
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        auto kv = std::make_unique<KvStore>(std::move(*opened));
        GuardianEngine eng(kv.get(), "agent-test");
        REQUIRE(eng.start_local().has_value());
        CHECK(eng.rule_count() == 1);
        CHECK(eng.policy_generation() == 13);
    }
    // db destructor removes .db / -wal / -shm on scope exit.
}

TEST_CASE("GuardianEngine: construction with null KvStore degrades gracefully",
          "[guardian][engine][robustness]") {
    GuardianEngine eng(nullptr, "agent-test");
    REQUIRE(eng.start_local().has_value());  // soft success — warns and proceeds

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "no-kv");
    auto applied = eng.apply_rules(p);
    CHECK_FALSE(applied.has_value());
    CHECK(applied.error().find("kv store unavailable") != std::string::npos);
}

TEST_CASE("GuardianEngine: drift event_id embeds agent_id (#1307)",
          "[guardian][engine][event][event_id]") {
    GuardianFixture f;  // agent_id == "agent-test"

    // #4783: EventSink delivery is now asynchronous (a detached executor worker,
    // not the calling thread) — own the captured data via shared_ptr rather than
    // reference-capturing a local declared after the fixture, so destruction
    // order can never race the worker's own access to it.
    auto captured_id = std::make_shared<std::string>();
    f.engine->set_event_sink([captured_id](const gpb::GuaranteedStateEvent& ev) {
        *captured_id = ev.event_id();
        return yuzu::agent::LegacySendOutcome::Sent;
    });
    yuzu::test::ScopeExit retire(
        [&] { CHECK(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5})); });

    yuzu::agent::GuardDrift d;
    d.guard_type = "registry";
    d.rule_id = "rule-A";
    d.rule_name = "rule-A";
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, d);

    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE_FALSE(captured_id->empty());
    // Layout is "<rule_id>-<agent_id>-<ms>-<seq>"; assert agent_id is present and
    // sits immediately after the rule_id prefix (the slot the crash path uses).
    CHECK(captured_id->find("agent-test") != std::string::npos);
    CHECK(captured_id->rfind("rule-A-agent-test-", 0) == 0);
}

TEST_CASE("GuardianEngine: same rule + same seq on two agents → distinct event_ids (#1307)",
          "[guardian][engine][event][event_id]") {
    // The fleet-collision regression: per-agent event_seq_ both start at 0, so two
    // agents drifting on the SAME rule in the SAME millisecond previously minted an
    // identical "rule_id-ms-0" id and the server's global-PK events table dropped
    // all but one. Folding agent_id in must make the ids distinct regardless of
    // timing — so this test does NOT depend on the two emits landing in the same ms.
    // Declaration order pins the destruction contract (reverse order): eng_b,
    // eng_a destruct (stop(), no KV touch) before kv_b, kv_a close their SQLite
    // handles, before the TempDbFiles remove the .db/-wal/-shm trio — same engine
    // → kv → db ordering GuardianFixture documents at its top.
    yuzu::test::TempDbFile db_a{unique_kv_path()};
    yuzu::test::TempDbFile db_b{unique_kv_path()};
    auto open_a = KvStore::open(db_a.path);
    auto open_b = KvStore::open(db_b.path);
    REQUIRE(open_a.has_value());
    REQUIRE(open_b.has_value());
    KvStore kv_a{std::move(*open_a)};
    KvStore kv_b{std::move(*open_b)};
    GuardianEngine eng_a{&kv_a, "agent-alpha"};
    GuardianEngine eng_b{&kv_b, "agent-bravo"};
    REQUIRE(eng_a.start_local().has_value());
    REQUIRE(eng_b.start_local().has_value());

    // #4783: own the captures via shared_ptr — see the sibling event_id test's
    // comment above for why a reference capture of a local declared after the
    // engines is no longer safe now that delivery is asynchronous.
    auto id_a = std::make_shared<std::string>();
    auto id_b = std::make_shared<std::string>();
    eng_a.set_event_sink([id_a](const gpb::GuaranteedStateEvent& ev) {
        *id_a = ev.event_id();
        return yuzu::agent::LegacySendOutcome::Sent;
    });
    eng_b.set_event_sink([id_b](const gpb::GuaranteedStateEvent& ev) {
        *id_b = ev.event_id();
        return yuzu::agent::LegacySendOutcome::Sent;
    });
    yuzu::test::ScopeExit retire_a(
        [&] { CHECK(eng_a.retire_legacy_sink_workers_for_test(std::chrono::seconds{5})); });
    yuzu::test::ScopeExit retire_b(
        [&] { CHECK(eng_b.retire_legacy_sink_workers_for_test(std::chrono::seconds{5})); });

    yuzu::agent::GuardDrift d;
    d.guard_type = "registry";
    d.rule_id = "shared-rule";
    d.rule_name = "shared-rule";
    // Both engines emit their first event (seq 0) for the same rule_id.
    yuzu::agent::guardian_emit_drift_for_test(eng_a, d);
    yuzu::agent::guardian_emit_drift_for_test(eng_b, d);

    REQUIRE(eng_a.flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE(eng_b.flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE_FALSE(id_a->empty());
    REQUIRE_FALSE(id_b->empty());
    CHECK(*id_a != *id_b);  // no PK collision
    // Prefix-anchor each id independently (not just containment): this pins the
    // "{rule_id}-{agent_id}-..." layout so the test fails against the pre-fix
    // "{rule_id}-{ms}-{seq}" shape on its own, without depending on a timing
    // difference between the two emits or on the sibling test having run.
    CHECK(id_a->rfind("shared-rule-agent-alpha-", 0) == 0);
    CHECK(id_b->rfind("shared-rule-agent-bravo-", 0) == 0);
}

TEST_CASE("GuardianEngine: empty agent_id still yields a well-formed (if ambiguous) event_id",
          "[guardian][engine][event][event_id]") {
    // Edge bordering the #1307 invariant: agent_id is server-assigned at enrollment
    // so it is non-empty in production, but assert the degenerate empty case does not
    // crash and still produces the "{rule_id}-{agent_id}-{ms}-{seq}" skeleton with an
    // empty agent_id segment ("rule-Z--<ms>-<seq>"). Documents that an empty agent_id
    // re-opens the cross-agent collision for that (pathological) population — see the
    // UP-2 follow-up — rather than silently changing shape.
    yuzu::test::TempDbFile db{unique_kv_path()};
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    GuardianEngine eng{&kv, ""};
    REQUIRE(eng.start_local().has_value());

    auto captured_id = std::make_shared<std::string>();
    eng.set_event_sink([captured_id](const gpb::GuaranteedStateEvent& ev) {
        *captured_id = ev.event_id();
        return yuzu::agent::LegacySendOutcome::Sent;
    });
    yuzu::test::ScopeExit retire(
        [&] { CHECK(eng.retire_legacy_sink_workers_for_test(std::chrono::seconds{5})); });

    yuzu::agent::GuardDrift d;
    d.guard_type = "registry";
    d.rule_id = "rule-Z";
    d.rule_name = "rule-Z";
    yuzu::agent::guardian_emit_drift_for_test(eng, d);

    REQUIRE(eng.flush_legacy_sink_for_test(std::chrono::seconds{5}));
    REQUIRE_FALSE(captured_id->empty());
    CHECK(captured_id->rfind("rule-Z--", 0) == 0);  // empty agent_id segment, not a crash
}

TEST_CASE("GuardianEngine: stop() makes subsequent apply_rules fail",
          "[guardian][engine][lifecycle]") {
    GuardianFixture f;
    f.engine->stop();

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "after-stop");
    auto applied = f.engine->apply_rules(p);
    CHECK_FALSE(applied.has_value());
    CHECK(applied.error() == "guardian engine stopped");
}

TEST_CASE("GuardianEngine: stop() is sticky - a later start_local() does not resurrect the engine",
          "[guardian][engine][lifecycle]") {
    // rung 7.7a reordered start_local() to run AFTER SparkEngine start + wire_spark_engine.
    // If a stop() lands during boot (a SIGTERM / service-stop mid-startup), the later
    // start_local() must NOT bring the engine back to life - otherwise stop() was not
    // truthful (and at rung 7.7b, detection + buffered sends could resume post-stop).
    GuardianFixture f;
    f.engine->stop();
    // start_local() returns cleanly but is a no-op: it must not clear the stopped state.
    REQUIRE(f.engine->start_local().has_value());
    // Proof the engine stayed stopped: apply_rules still fails with "stopped". Without
    // the sticky guard, start_local() would have set stopped_=false and this would
    // succeed - i.e. the engine would have silently resurrected after stop() returned.
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "after-stop-then-startlocal");
    auto applied = f.engine->apply_rules(p);
    CHECK_FALSE(applied.has_value());
    CHECK(applied.error() == "guardian engine stopped");
}

// ---------------------------------------------------------------------------
// rung 9c PR-3, Check A (~/.claude/plans/spark-rung9c-pr3-telemetry-KICKOFF-v2.md):
// GuardianEngine::apply_rules() calls GuardianArmAckLedger::begin_application()
// UNCONDITIONALLY, regardless of prefer_spark_ - so a naive arm_stats() gated
// only on "is there a current application" would read every default
// (prefer_spark_=false) agent as a live, empty {pending:0, failed:0} snapshot,
// i.e. false-present-healthy on a fleet not running spark at all. This pins the
// fix: GuardianEngine::arm_stats() must gate on prefer_spark_ explicitly.
// ---------------------------------------------------------------------------
TEST_CASE("GuardianEngine::arm_stats(): default prefer_spark_=false stays "
          "ABSENT (nullopt) even after a real push opens an application",
          "[guardian][engine][arm_stats]") {
    GuardianFixture f; // GuardianFixture default-constructs prefer_spark_=false
    REQUIRE_FALSE(f.engine->prefer_spark());

    // BEFORE any push: no current application at all.
    CHECK_FALSE(f.engine->arm_stats().has_value());

    // A real push runs apply_rules(), which calls begin_application()
    // unconditionally - the exact trap Check A names. If arm_stats() were
    // gated on "current application exists" alone, this would now read
    // present {0, 0} instead of nullopt.
    REQUIRE(f.engine
                ->apply_rules(GuardianFixture::make_push(
                    {GuardianFixture::make_rule("r1", "r1")}, /*full_sync=*/true))
                .has_value());
    CHECK_FALSE(f.engine->arm_stats().has_value());

    // The io-ceiling counter is unaffected by this trap (see its own doc
    // comment for why) and reads a plain 0 either way.
    CHECK(f.engine->io_ceiling_rejections() == 0);
}

// ---------------------------------------------------------------------------
// guard.hpp's GuardDrift::Health / emit_guard_event's health arm (PR #4748 blocking fix):
// a health report must go out as "guard.unhealthy" via the health branch, never through
// apply_drift_to_event's default-arm 4-way event_type cascade, and every compliance field
// on the same report must be ignored outright — a health report never mints drift.detected
// or guard.compliant, even when the caller (a bug in some future producer) also sets them.
// ---------------------------------------------------------------------------

TEST_CASE("GuardianEngine: a health report emits guard.unhealthy with its detail, never "
          "through the drift/compliance cascade",
          "[guardian][engine][event][health]") {
    GuardianFixture f;

    // #4783: shared_ptr-owned capture — see the event_id test's comment near the
    // top of this file for why a reference to a local declared after the fixture
    // is no longer safe now that delivery is asynchronous.
    auto captured = std::make_shared<gpb::GuaranteedStateEvent>();
    f.engine->set_event_sink([captured](const gpb::GuaranteedStateEvent& ev) {
        *captured = ev;
        return yuzu::agent::LegacySendOutcome::Sent;
    });
    yuzu::test::ScopeExit retire(
        [&] { CHECK(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5})); });

    yuzu::agent::GuardDrift d;
    d.guard_type = "file";
    d.rule_id = "rule-health";
    d.rule_name = "rule-health-name";
    d.health = yuzu::agent::GuardDrift::Health::Unhealthy;
    d.health_detail = "parent-directory watch permanently disabled";
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, d);

    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    CHECK(captured->event_type() == "guard.unhealthy");
    CHECK(captured->guard_type() == "file");
    CHECK(captured->rule_name() == "rule-health-name");
    CHECK(captured->detail_json() == R"({"detail":"parent-directory watch permanently disabled"})");
    // event_id/rule_id/guard_category/timestamp/platform are stamped outside the
    // health/drift branch — unaffected by which arm ran.
    CHECK(captured->rule_id() == "rule-health");
    CHECK(captured->guard_category() == "event");
    CHECK_FALSE(captured->event_id().empty());
}

TEST_CASE("GuardianEngine: a health report with an empty detail omits detail_json",
          "[guardian][engine][event][health]") {
    GuardianFixture f;

    auto captured = std::make_shared<gpb::GuaranteedStateEvent>();
    f.engine->set_event_sink([captured](const gpb::GuaranteedStateEvent& ev) {
        *captured = ev;
        return yuzu::agent::LegacySendOutcome::Sent;
    });
    yuzu::test::ScopeExit retire(
        [&] { CHECK(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5})); });

    yuzu::agent::GuardDrift d;
    d.guard_type = "file";
    d.rule_id = "rule-health-empty";
    d.rule_name = "rule-health-empty";
    d.health = yuzu::agent::GuardDrift::Health::Unhealthy;
    // health_detail left empty.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, d);

    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    CHECK(captured->event_type() == "guard.unhealthy");
    CHECK(captured->detail_json().empty());
}

TEST_CASE("GuardianEngine: a health report with non-UTF-8 detail bytes still serializes "
          "(U+FFFD replacement, matches the spark health stream's convention)",
          "[guardian][engine][event][health]") {
    GuardianFixture f;

    auto captured = std::make_shared<gpb::GuaranteedStateEvent>();
    f.engine->set_event_sink([captured](const gpb::GuaranteedStateEvent& ev) {
        *captured = ev;
        return yuzu::agent::LegacySendOutcome::Sent;
    });
    yuzu::test::ScopeExit retire(
        [&] { CHECK(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5})); });

    yuzu::agent::GuardDrift d;
    d.guard_type = "file";
    d.rule_id = "rule-health-badutf8";
    d.rule_name = "rule-health-badutf8";
    d.health = yuzu::agent::GuardDrift::Health::Unhealthy;
    d.health_detail = "bad-byte-\xFF-here";
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, d);

    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    CHECK(captured->event_type() == "guard.unhealthy");
    CHECK_FALSE(captured->detail_json().empty()); // must serialize, never throw/drop the event
    CHECK(captured->detail_json().find("bad-byte-") != std::string::npos);
}

TEST_CASE("GuardianEngine: a health report with contradictory compliance fields set still "
          "emits guard.unhealthy and ignores every compliance field",
          "[guardian][engine][event][health]") {
    GuardianFixture f;

    auto captured = std::make_shared<gpb::GuaranteedStateEvent>();
    f.engine->set_event_sink([captured](const gpb::GuaranteedStateEvent& ev) {
        *captured = ev;
        return yuzu::agent::LegacySendOutcome::Sent;
    });
    yuzu::test::ScopeExit retire(
        [&] { CHECK(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5})); });

    yuzu::agent::GuardDrift d;
    d.guard_type = "file";
    d.rule_id = "rule-health-contradictory";
    d.rule_name = "rule-health-contradictory";
    d.health = yuzu::agent::GuardDrift::Health::Unhealthy;
    d.health_detail = "contradictory-fields-test";
    // Deliberately contradictory: a real producer never sets these alongside health, but
    // the health arm must ignore them unconditionally regardless of caller behavior.
    d.compliant = true;
    d.detected_value = "should-be-ignored";
    d.expected_value = "should-be-ignored";
    d.remediation_attempted = true;
    d.remediation_success = true;
    d.remediation_action = "should-be-ignored";
    d.collapsed_count = 3;
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, d);

    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    CHECK(captured->event_type() == "guard.unhealthy");
    CHECK(captured->remediation_action().empty());
    CHECK_FALSE(captured->remediation_success());
    CHECK(captured->detected_value().empty());
    CHECK(captured->expected_value().empty());
    CHECK(captured->drift_rate() == 0);
}

// ===========================================================================
// #5513 boot re-arm catch-up (LEGACY path: prefer_spark=false, no Spark wiring)
//
// A cached rule whose boot re-arm fails (a legacy guard's std::thread ctor
// throwing on thread-creation failure is the production-reachable case) used
// to leave the agent reporting its persisted, already-acknowledged generation, so
// the server's "agent behind current" reconcile never fired and the rule stayed
// unenforced until the next restart. start_local() now reports generation 0 while
// a boot re-arm is unresolved (boot_rearm_unresolved()), which makes the server
// re-push at the current generation; the first CLEAN application (every rule
// reconciled without failure) clears it. The INTERNAL generation
// (policy_generation_) and its persisted value are never touched: only the
// REPORTED value moves, so a second restart still reads the real generation from
// disk. Tests below drive the throw through set_rearm_fault_hook_for_test (armed
// BEFORE start_local(), fires with mtx_ held, so it throws or observes only).
//
// Rules: a registry-change rule is Inert on Linux/macOS (the legacy guard stub
// returns false), so a push of it applies and persists on every host with no
// platform dependency; the hook fires before reconcile_rule_locked, so the rule's
// arm outcome never matters to what the tests assert. Every registry rule here is
// "audit" mode, never "enforce": on Windows the seed phase really arms a
// RegistryGuard against the fixed, unsalted HKCU\SOFTWARE\YuzuTest\GuardStatusTest
// key, and enforce mode would create and write that key (a cross-job shared
// resource on the shared CI runners); audit mode only watches. The Spark-wired
// cases for this issue live in test_guardian_engine_spark_reconcile.cpp.
// ===========================================================================

namespace {

// One engine lifetime over a (possibly pre-existing) KV file. The hook, if any, is
// armed in start() strictly before start_local(), as the setter's contract requires.
// Declaration order matters: engine is destroyed before kv.
struct BootedEngine {
    std::unique_ptr<KvStore> kv;
    std::unique_ptr<GuardianEngine> engine;

    explicit BootedEngine(const fs::path& path) {
        auto opened = KvStore::open(path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));
        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-test");
    }

    void start(std::function<void(const std::string&)> hook = nullptr) {
        if (hook)
            engine->set_rearm_fault_hook_for_test(std::move(hook));
        REQUIRE(engine->start_local().has_value());
    }
};

// Models a legacy guard's thread ctor throwing on thread-creation failure, aimed at one rule.
std::function<void(const std::string&)> exhaust_on(std::string target) {
    return [target = std::move(target)](const std::string& rule_id) {
        if (rule_id == target)
            throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again),
                                    "injected thread exhaustion");
    };
}

gpb::GuaranteedStatePush push_at(std::uint64_t gen, std::vector<gpb::GuaranteedStateRule> rules,
                                 bool full_sync) {
    auto p = GuardianFixture::make_push(std::move(rules), full_sync);
    p.set_policy_generation(gen);
    return p;
}

// r1 + r2: registry rules, Inert on Linux/macOS (see the banner above). "audit" so a
// Windows run never creates the fixed shared HKCU test key (enforce mode would).
std::vector<gpb::GuaranteedStateRule> two_registry_rules() {
    return {GuardianFixture::make_registry_rule("r1", "audit"),
            GuardianFixture::make_registry_rule("r2", "audit")};
}

// Phase 1: a first engine on `path` applies a push at `gen` and goes away, leaving the
// rules and the generation persisted for a later engine to boot from.
void seed_persisted_generation(const fs::path& path, std::uint64_t gen,
                               std::vector<gpb::GuaranteedStateRule> rules, bool full_sync = true) {
    BootedEngine seed{path};
    seed.start();
    REQUIRE(seed.engine->apply_rules(push_at(gen, std::move(rules), full_sync)).has_value());
    REQUIRE(seed.engine->policy_generation() == gen);
}

} // namespace

TEST_CASE("GuardianEngine #5513: a re-arm that throws at boot reports generation 0 until a "
          "clean same-generation catch-up push",
          "[guardian][engine][boot_rearm]") {
    constexpr std::uint64_t kG = 5;
    yuzu::test::TempDbFile db{unique_kv_path()};
    seed_persisted_generation(db.path, kG, two_registry_rules());

    BootedEngine b{db.path};
    CHECK_FALSE(b.engine->boot_rearm_unresolved()); // nothing has booted yet
    const auto failures_before = b.engine->arm_failure_count();
    b.start(exhaust_on("r1"));

    // The persisted generation (kG) was loaded, yet the REPORTED value is 0: the
    // server sees an agent behind its current generation and re-pushes.
    CHECK(b.engine->policy_generation() == 0);
    CHECK(b.engine->boot_rearm_unresolved());
    CHECK(b.engine->arm_failure_count() == failures_before + 1);
    CHECK(b.engine->rule_count() == 2); // the cache is intact, including the failed rule
    // The heartbeat reads both values from ONE snapshot.
    const auto report = b.engine->generation_report();
    CHECK(report.reported == 0);
    CHECK(report.boot_rearm_unresolved);

    // The catch-up: the SAME generation, so the tail's `push > policy_generation_`
    // advance gate is false. The flag must clear on a clean application regardless of
    // that gate (it sits beside the gate, not inside it).
    REQUIRE(b.engine->apply_rules(push_at(kG, two_registry_rules(), /*full_sync=*/true))
                .has_value());
    CHECK_FALSE(b.engine->boot_rearm_unresolved());
    CHECK(b.engine->policy_generation() == kG);
    CHECK(b.engine->arm_failure_count() == failures_before + 1); // the clean push added none
    const auto cleared = b.engine->generation_report();
    CHECK(cleared.reported == kG);
    CHECK_FALSE(cleared.boot_rearm_unresolved);
}

TEST_CASE("GuardianEngine #5513: get_status keeps the internal persisted generation while the "
          "reported one reads 0",
          "[guardian][engine][boot_rearm]") {
    // get_status() is the census view and reads the INTERNAL generation (policy_generation_),
    // deliberately not policy_generation()'s reported value; only the heartbeat-facing accessors
    // move. Mutation: get_status() switched to the reported value reports 0 here.
    constexpr std::uint64_t kG = 8;
    yuzu::test::TempDbFile db{unique_kv_path()};
    seed_persisted_generation(db.path, kG, two_registry_rules());

    BootedEngine b{db.path};
    b.start(exhaust_on("r1"));
    REQUIRE(b.engine->boot_rearm_unresolved());
    CHECK(b.engine->policy_generation() == 0);
    CHECK(b.engine->get_status().policy_generation() == kG);

    REQUIRE(b.engine->apply_rules(push_at(kG, two_registry_rules(), /*full_sync=*/true))
                .has_value());
    CHECK_FALSE(b.engine->boot_rearm_unresolved());
    CHECK(b.engine->policy_generation() == kG);
    CHECK(b.engine->get_status().policy_generation() == kG);
}

TEST_CASE("GuardianEngine #5513: the push_rules reply text reports the persisted generation "
          "once the catch-up clears the flag",
          "[guardian][engine][boot_rearm][dispatch]") {
    // The reply is built from the REPORTED generation. A push that returns success is not
    // always a clean application: apply_rules counts a rule whose reconcile_rule_locked throws
    // into reconcile_failures, still returns success, leaves the flag set, and the reply can
    // then read generation=0 on the legacy path too. No deterministic legacy seam makes that
    // throw at apply time (the re-arm fault hook fires only in start_local()), so that case is
    // not pinned here; the Spark Accepted path is asserted in
    // test_guardian_engine_spark_reconcile.cpp. Here: the catch-up applies cleanly, so its
    // reply names kG, not 0. Space-anchored like the dispatch test above.
    constexpr std::uint64_t kG = 42;
    yuzu::test::TempDbFile db{unique_kv_path()};
    seed_persisted_generation(db.path, kG, two_registry_rules());

    BootedEngine b{db.path};
    b.start(exhaust_on("r1"));
    REQUIRE(b.engine->boot_rearm_unresolved());

    auto p = push_at(kG, two_registry_rules(), /*full_sync=*/true);
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*b.engine, p.SerializeAsString());
    CHECK(dr.exit_code == 0);
    CHECK(dr.output.find(" generation=42 ") != std::string::npos);
    CHECK(dr.output.find(" generation=0 ") == std::string::npos);
    CHECK_FALSE(b.engine->boot_rearm_unresolved());
}

TEST_CASE("GuardianEngine #5513: a second restart while unresolved re-derives the state from "
          "the walk, never from disk",
          "[guardian][engine][boot_rearm]") {
    // Nothing about the unresolved state is persisted: the disk keeps the real
    // generation throughout, so a restart WITHOUT the fault reports it at once, and a
    // restart WITH the fault reports 0 again.
    constexpr std::uint64_t kG = 9;
    yuzu::test::TempDbFile db{unique_kv_path()};
    seed_persisted_generation(db.path, kG, two_registry_rules());

    {
        BootedEngine failing{db.path};
        failing.start(exhaust_on("r1"));
        REQUIRE(failing.engine->boot_rearm_unresolved());
        CHECK(failing.engine->policy_generation() == 0);
        failing.engine->stop();
    }
    {
        BootedEngine healthy{db.path};
        healthy.start(); // no hook: the rule re-arms (or is Inert) without incident
        CHECK_FALSE(healthy.engine->boot_rearm_unresolved());
        CHECK(healthy.engine->policy_generation() == kG);
    }
    {
        BootedEngine failing_again{db.path};
        failing_again.start(exhaust_on("r1"));
        CHECK(failing_again.engine->boot_rearm_unresolved());
        CHECK(failing_again.engine->policy_generation() == 0);
    }
}

TEST_CASE("GuardianEngine #5513: generation 0 and a never-pushed boot never confuse the "
          "report",
          "[guardian][engine][boot_rearm]") {
    // A push at generation 0 with full_sync=false persists the rule but never writes
    // the generation key (the tail's `0 > 0` advance gate is false), so a later boot
    // loads 0 either way. This proves the CLEARING path at 0 (no `gen - 1` or
    // "reported != 0" arithmetic anywhere): it does NOT prove the server ever pushes
    // to an agent whose current generation is 0, which it does not.
    yuzu::test::TempDbFile db{unique_kv_path()};
    seed_persisted_generation(db.path, 0, two_registry_rules(), /*full_sync=*/false);

    SECTION("no fault: reports 0 and no flag") {
        BootedEngine b{db.path};
        b.start();
        CHECK(b.engine->policy_generation() == 0);
        CHECK_FALSE(b.engine->boot_rearm_unresolved());
    }
    SECTION("fault: flag set, a gen-0 push clears it, still reports 0") {
        BootedEngine b{db.path};
        b.start(exhaust_on("r1"));
        CHECK(b.engine->policy_generation() == 0);
        REQUIRE(b.engine->boot_rearm_unresolved());
        REQUIRE(b.engine->apply_rules(push_at(0, two_registry_rules(), /*full_sync=*/true))
                    .has_value());
        CHECK_FALSE(b.engine->boot_rearm_unresolved());
        CHECK(b.engine->policy_generation() == 0);
    }
}

TEST_CASE("GuardianEngine #5513: a catch-up that removes or disables the failed rule still "
          "clears the flag",
          "[guardian][engine][boot_rearm]") {
    // The flag clears on a clean APPLICATION, not on "the failed rule re-armed": a rule
    // the server no longer wants (removed, or authored disabled) is no longer an open
    // enforcement gap.
    constexpr std::uint64_t kG = 4;
    yuzu::test::TempDbFile db{unique_kv_path()};
    // "audit": see the banner above (no enforce-mode write to the fixed Windows test key).
    seed_persisted_generation(db.path, kG, {GuardianFixture::make_registry_rule("r1", "audit")});

    BootedEngine b{db.path};
    b.start(exhaust_on("r1"));
    REQUIRE(b.engine->boot_rearm_unresolved());
    REQUIRE(b.engine->policy_generation() == 0);

    SECTION("the full_sync push omits the rule") {
        // r9 carries no spark/assertion: it is validation-rejected and Inert on every OS,
        // so nothing is armed and the push is clean.
        REQUIRE(b.engine
                    ->apply_rules(push_at(kG, {GuardianFixture::make_rule("r9", "plain")},
                                          /*full_sync=*/true))
                    .has_value());
        CHECK(b.engine->rule_count() == 1);
        // Trivially true on every host: the boot hook threw before arming, so r1 was never
        // armed to begin with. What the section proves is the flag/generation pair below.
        CHECK(b.engine->armed_guard_count() == 0);
        CHECK_FALSE(b.engine->boot_rearm_unresolved());
        CHECK(b.engine->policy_generation() == kG);
    }
    SECTION("the full_sync push carries the rule disabled") {
        // A disabled r1 is withdrawn from both backends and never armed.
        REQUIRE(b.engine
                    ->apply_rules(push_at(
                        kG, {GuardianFixture::make_rule("r1", "r1", /*enabled=*/false)},
                        /*full_sync=*/true))
                    .has_value());
        CHECK(b.engine->rule_count() == 1);
        CHECK(b.engine->armed_guard_count() == 0); // trivially true, as in the section above
        CHECK_FALSE(b.engine->boot_rearm_unresolved());
        CHECK(b.engine->policy_generation() == kG);
    }
}

TEST_CASE("GuardianEngine #5513: stop() is sticky - a start_local() after stop() never walks, "
          "so never sets the flag",
          "[guardian][engine][boot_rearm][lifecycle]") {
    // CONTROL case: the sticky-stop invariant is untouched by the catch-up work. The hook
    // is armed (legal: start_local() has not run) yet must never fire.
    constexpr std::uint64_t kG = 3;
    yuzu::test::TempDbFile db{unique_kv_path()};
    seed_persisted_generation(db.path, kG, two_registry_rules());

    std::size_t hook_calls = 0; // declared before the engine that holds the hook
    BootedEngine b{db.path};
    b.engine->stop();
    b.engine->set_rearm_fault_hook_for_test([&hook_calls](const std::string&) { ++hook_calls; });
    REQUIRE(b.engine->start_local().has_value()); // returns cleanly, a no-op

    CHECK(hook_calls == 0);          // no walk
    CHECK(b.engine->rule_count() == 0); // the cache was never loaded
    CHECK(b.engine->arm_failure_count() == 0);
    CHECK_FALSE(b.engine->boot_rearm_unresolved());
    // 0 here is the construction default (start_local() returned before loading kKeyGen),
    // not an unresolved report: the flag above is the discriminator.
    CHECK(b.engine->policy_generation() == 0);
}

TEST_CASE("GuardianEngine #5513: a non-std::exception throw at boot is contained, counted and "
          "reported like any other re-arm failure",
          "[guardian][engine][boot_rearm]") {
    // start_local()'s caller does not catch, so a throw that is not a std::exception used
    // to escape run() and end the agent. A third-party or ABI-boundary type is the
    // realistic shape.
    constexpr std::uint64_t kG = 6;
    yuzu::test::TempDbFile db{unique_kv_path()};
    seed_persisted_generation(db.path, kG,
                              {GuardianFixture::make_service_rule("r1", "audit"),
                               GuardianFixture::make_service_rule("r2", "audit"),
                               GuardianFixture::make_service_rule("r3", "audit")});

    std::set<std::string> visited; // declared before the engine that holds the hook
    BootedEngine b{db.path};
    const auto failures_before = b.engine->arm_failure_count();
    b.engine->set_rearm_fault_hook_for_test([&visited](const std::string& rule_id) {
        visited.insert(rule_id);
        if (rule_id == "r2")
            throw 42; // NOT derived from std::exception
    });
    REQUIRE(b.engine->start_local().has_value()); // today: the throw escapes instead

    // The walk visits keys in sorted order, so r3 was reached AFTER the throw.
    const std::set<std::string> expected_visited{"r1", "r2", "r3"};
    CHECK(visited == expected_visited);
    CHECK(b.engine->boot_rearm_unresolved());
    CHECK(b.engine->policy_generation() == 0);
    CHECK(b.engine->arm_failure_count() == failures_before + 1);
    CHECK(b.engine->rule_count() == 3);
    // The degrade message names the throwing rule, like the std::exception arm's.
    const std::string degrade_msg = b.engine->last_rearm_degrade_message_for_test();
    CHECK(degrade_msg.find("r2") != std::string::npos);
    CHECK(degrade_msg.find("non-standard exception") != std::string::npos);
    // Legacy service guards arm only where a system bus is reachable (the existing
    // service-rule tests SKIP otherwise). Where they do, exactly the two rules whose
    // re-arm did not throw are armed and the poisoned one is not. On a host without a
    // system bus (macOS, a bus-less Linux container) `armed` is 0 and this check is
    // skipped; the continued walk is then carried by the `visited` set above (r3 was
    // reached after r2 threw), which holds on every host.
    if (const auto armed = b.engine->armed_guard_count(); armed != 0)
        CHECK(armed == 2);
}
