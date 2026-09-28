/**
 * guardian_engine.cpp — see guardian_engine.hpp.
 *
 * PR 2 scope: persistence + dispatch only. The engine speaks the wire
 * protocol from `__guard__` commands (push_rules, get_status), serialises
 * rule state into the agent's KvStore as JSON, and reports a pessimistic
 * "all rules compliant" status because no guards are running yet.
 *
 * Rule persistence layout (under KvStore namespace "__guardian__"):
 *   key="rule:<rule_id>"    — JSON blob of the rule (yaml_source + denorm fields)
 *   key="meta:policy_generation" — monotonically increasing uint64 (decimal text)
 *
 * The store is JSON, not SerializeAsString, because KvStore wraps the
 * value in sqlite3_bind_text + sqlite3_column_text — both APIs treat the
 * payload as a NUL-terminated C string and would truncate any embedded
 * null byte that proto wire-format readily produces. JSON is binary-safe
 * over those APIs and matches the storage style used by the rest of the
 * agent codebase.
 */

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/guard_file.hpp>
#include <yuzu/agent/guard_registry.hpp>
#include <yuzu/agent/guard_service.hpp>
#include <yuzu/agent/guard_systemd.hpp> // make_service_guard (platform factory)
#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp> // kReservedPluginNames - for the kKvNamespace pin

#include "agent.grpc.pb.h"
#include "guaranteed_state.pb.h"

// rung 7: the spark detection path GuardianEngine wires alongside legacy IGuard.
#include "guardian_arm_ack.hpp" // rung 9c PR-2 Unit 5/6: GuardianArmAckLedger, guardian_push_content_id
#include "guardian_arm_heartbeat.hpp" // GuardianArmStats (rung 9c PR-3)
#include "guardian_backend.hpp" // GuardianBackend, guardian_backend_from_state/label (F7)
#include "guardian_convergence_scheduler.hpp"
#include "guardian_drift_event.hpp" // apply_drift_to_event (shared with the spark path)
#include "guardian_detached_worker_role.hpp" // rung 9c R5.1: executor workers
#include "guardian_joined_thread_role.hpp"
#include "guardian_journal_heartbeat.hpp" // GuardianJournalStats (item 7 PR-Ag §8)
#include "guardian_legacy_sink_executor.hpp" // #4783: detached legacy-sink sender
#include "guardian_lifecycle_journal.hpp" // durable lifecycle journal (item 7 PR-Ag)
#include "guardian_outbox_drain_worker.hpp"
#include "guardian_rule_eval.hpp" // clamp_max_hash_bytes, kMaxFileHashBytes (#2233 item 6)
#include "guardian_scope_guard.hpp" // GuardianRollback (terminate-safe rollback)
#include "guardian_spark_backend.hpp"
#include "guardian_spark_bridge.hpp" // spark_spec_from_rule, rule_assertion_from_rule, classify
#include "guardian_spark_runtime.hpp"
#include "guardian_state_reader.hpp"
#include "spark_engine.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include <algorithm>
#include <cstdlib>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

namespace yuzu::agent {

namespace {

namespace gpb = ::yuzu::guardian::v1;
namespace apb = ::yuzu::agent::v1;

constexpr std::string_view kKvNamespace = "__guardian__";
constexpr std::string_view kRulePrefix  = "rule:";
constexpr std::string_view kKeyGen      = "meta:policy_generation";
// #4021: a captured file-hash-equals baseline, keyed by rule_id, NEVER swept by
// full_sync (only kRulePrefix keys are - see the full_sync teardown block) and
// never swept merely because a rule is absent from one push (the server omits
// disabled/out-of-scope rules from every push - guardian_push_builder.cpp - so
// absence is not deletion; a dormant baseline record for a rule that never comes
// back is an accepted, deliberate trade against silently laundering a genuinely
// still-drifted rule's compliance state - see guardian_seed_baseline's doc).
constexpr std::string_view kBaselinePrefix = "baseline:";

// #2303 sec-M. GuardianEngine persists rule state under kKvNamespace on the shared kv_store.db,
// keyed the same way plugin storage is (yuzu_ctx_storage_* by the plugin's own declared name).
// This namespace MUST be a reserved plugin name, or a native plugin could claim it and forge the
// policy rules the engine reloads as authoritative at boot. plugin_loader.hpp (include/) cannot
// include this src/ file, so the literal is duplicated in kReservedPluginNames and pinned here -
// the same bind-or-drift pattern as the journal's kJournalNamespace pin.
static_assert(is_reserved_plugin_name(kKvNamespace),
              "kKvNamespace must be a reserved plugin name (plugin_loader.hpp) - otherwise a "
              "native plugin can claim the GuardianEngine rule-state kv_store namespace");

constexpr std::string_view kActionPushRules = "push_rules";
constexpr std::string_view kActionGetStatus = "get_status";

// #4783 commit 4 (legacy_sink_kick()'s gap-repair loop): a small fixed cap on how
// many sticky integrity gaps get a repair report synthesized per heartbeat tick -
// bounds a single kick's work regardless of how many rules are gapped at once
// (a reconnect burst caps at this many repairs per tick; R6 in the delivery plan).
constexpr std::size_t kMaxGapRepairsPerKick = 32;

// The fixed, short health_detail carried by every synthesized gap-repair report
// (GuardDrift::health_detail -> detail_json {"detail": ...}). Deliberately a
// CONSTANT, never built from the gap's own lost-count/rule metadata, so the #4748
// health_detail length-cap concern never applies here (same argument that PR
// relied on - delivery plan D1b / #3 in this file's own header banner).
constexpr std::string_view kLegacySinkDeliveryGapDetail = "legacy-sink-delivery-gap";

// The rollback guard used by wire_spark_engine() (rollback runs on EVERY exit path,
// including a catch handler's own logging throwing - Sol rung-7.5 finding 2) is now
// the shared, terminate-safe GuardianRollback (guardian_scope_guard.hpp): its cleanup
// joins threads / resets shared_ptrs and could throw during unwinding, which a plain
// noexcept ~ScopeExit would turn into std::terminate (rung 7.7b PR-1 item 3 / Sol B3).

std::string hex_encode(const std::string& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        out += kHex[c >> 4];
        out += kHex[c & 0xF];
    }
    return out;
}

std::string hex_decode(std::string_view hex) {
    if (hex.size() % 2 != 0)
        return {};
    auto from_hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = from_hex(hex[i]);
        int lo = from_hex(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return {};
        out += static_cast<char>((hi << 4) | lo);
    }
    return out;
}

// #4021: baseline-on-arm persistence. A `file-hash-equals` rule authored with no
// `expected_hash` captures whatever the target contains at arm time as its "known
// good" state (guardian_rule_eval.cpp's own "baseline-on-arm" comment; the legacy
// FileGuard mirrors it independently in guard_file.cpp). Before this fix, that
// captured state lived ONLY in the running guard's own memory - a full_sync
// (any unrelated fleet rule mutation bumps the single global policy_generation,
// this file's full_sync teardown/rearm) or an agent restart (start_local()'s
// rearm loop) constructed a brand-new guard with no memory of the prior baseline,
// so the NEXT read re-captured "whatever's on disk right now" - silently
// reclassifying a rule that had been genuinely drifted for weeks as compliant,
// with no remediation and no visible action. This persists the FIRST captured
// baseline per rule_id in KvStore so every later arm re-seeds the SAME value
// instead of recapturing current content.
//
// Scope of this fix (deliberate, documented - see #4021 PR description): wired for
// the LEGACY FileGuard path only (start_guard_for_rule_locked below), the
// currently-shipped detection backend (prefer_spark_ defaults false - "legacy
// IGuard remains the sole live detection path"). The SEED lookup below also
// benefits a rule armed via Spark (reconcile_rule_locked mutates the shared
// RuleAssertion before the backend fork), so a baseline captured under legacy
// survives a later flip to Spark. Spark's OWN capture (guardian_rule_eval.cpp /
// guardian_spark_runtime.cpp) is NOT wired to this store - those files are
// Spark-workstream-in-flight elsewhere; under prefer_spark_=true a first-ever
// Spark-side capture is not yet persisted here, so the SAME full_sync-relaunder
// gap remains for a rule that has NEVER been armed via legacy. Tracked as
// #4045 rather than a bare prose follow-up (adversarial-review K4/C2-3).
constexpr int kBaselineSchemaVersion = 1;

std::string make_baseline_key(const std::string& rule_id) {
    return std::string(kBaselinePrefix) + rule_id;
}

/// Identifies WHAT is asserted, not how it's authored/watched elsewhere: changing
/// `settle_ms`/debounce/name/severity/enforcement_mode must NOT invalidate a
/// captured baseline (those don't change what "compliant" means); changing the
/// assertion TYPE or its TARGET must (a rule_id re-authored against a different
/// path is a genuinely different target, and its "first good read" baseline
/// captured under this fingerprint must never seed a mismatched one - a
/// fingerprint mismatch is simply treated as "no baseline yet", never a failure).
/// Only `file-hash-equals` baselines-on-arm today; a future baselining assertion
/// kind extends this, never guesses a shared shape with an unrelated one.
///
/// Gate 2 governance (security-guardian): deliberately does NOT fold
/// `kBaselineSchemaVersion` into this string (an earlier draft did, as a "v1|"
/// prefix). A future schema bump would then change the fingerprint of every
/// EXISTING record fleet-wide with no code change to the record's actual
/// content — read_baseline_record's fingerprint-mismatch branch would silently
/// treat every one of them as "a genuine retarget" and let the very next arm
/// recapture fresh, a mass, unlogged version of the exact relaunder #4021
/// exists to close. The schema version is carried ONLY in the stored record's
/// own `j["schema"]` field (see guardian_persist_baseline) and validated there
/// by read_baseline_record - version drift is a distinct failure (Malformed),
/// never conflated with "different target".
std::string guardian_baseline_fingerprint(std::string_view assertion_type,
                                          std::string_view target) {
    return std::string(assertion_type) + "|" + std::string(target);
}

bool is_valid_baseline_hash(const std::string& h) {
    if (h.size() != 64) // lowercase hex SHA-256, matching sha256_file's own output format
        return false;
    for (char c : h)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

/// How a persisted baseline record read went. `Ok` means the record parsed and its
/// hash is well-formed (the fingerprint may or may not match what the caller
/// wanted — that's for the caller to compare); every other value means "nothing
/// USABLE was read", collapsing "genuinely absent" and "read/parse/hash failure"
/// into one non-throwing shape both `guardian_seed_baseline` and
/// `guardian_persist_baseline` can switch on without duplicating the KV-read/JSON-
/// parse plumbing between them (adversarial-review K1/C2-1: the persist side needs
/// to distinguish "confirmed nothing there" from "read failed" too, not just the
/// seed side).
enum class BaselineReadOutcome { Ok, Absent, ReadError, Malformed };

struct BaselineRecord {
    std::string fingerprint;
    std::string hash;
};

/// Gate 2 governance (security-guardian): NOT `_locked` despite the name every
/// other `*_locked` helper in this file uses for "called under mtx_" - this one
/// touches only `KvStore` (its own internal mutex) and is called from a guard
/// worker thread that must NEVER take `GuardianEngine::mtx_` (guardian_persist_baseline's
/// call site). Named without the suffix so a future maintainer doesn't add
/// engine-state access here on the false assumption mtx_ is already held.
BaselineReadOutcome read_baseline_record(KvStore& kv, const std::string& rule_id,
                                         BaselineRecord& out) {
    auto raw = kv.get_entry(kKvNamespace, make_baseline_key(rule_id));
    if (!raw)
        return BaselineReadOutcome::ReadError;
    if (!raw->has_value())
        return BaselineReadOutcome::Absent;
    // Gate 3 governance (cpp-safety): the try below now covers EVERY
    // nlohmann::json call on this record, not just parse() - a well-formed
    // JSON document with a wrong-typed field (e.g. "schema" as a string, or a
    // top-level array, so .value<int>()/.value<string>() throws type_error)
    // must degrade to Malformed like every other corrupt-record case, never
    // escape as an uncaught exception. Before this fix such a record threw
    // out of read_baseline_record entirely: on the seed side that escaped
    // into apply_rules's push-application loop (degrading the WHOLE push,
    // not just this rule); on the persist side it escaped out of a guard
    // worker thread's on_baseline callback into FileGuard::run()'s own
    // top-level catch, permanently stopping that one guard until the next
    // full_sync/restart - both contradicting this function's own "never
    // propagated as an arm failure" contract.
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(**raw);
        // Schema-version drift is a DISTINCT failure from a fingerprint
        // mismatch (Gate 2 governance): a record from a future/incompatible
        // schema must never be silently treated as "a different target,
        // capture fresh" (which would recapture EVERY existing baseline
        // fleet-wide, unlogged, the moment kBaselineSchemaVersion is ever
        // bumped) - it needs its own migration path when one is written, not
        // a silent reinterpretation as a retarget.
        if (j.value("schema", -1) != kBaselineSchemaVersion)
            return BaselineReadOutcome::Malformed;
        out.fingerprint = j.value("fingerprint", std::string{});
        out.hash = j.value("hash", std::string{});
    } catch (const nlohmann::json::exception&) {
        return BaselineReadOutcome::Malformed;
    }
    if (!is_valid_baseline_hash(out.hash))
        return BaselineReadOutcome::Malformed;
    return BaselineReadOutcome::Ok;
}

/// Look up a persisted baseline for `rule_id`, returning it ONLY when the stored
/// fingerprint matches `fingerprint` (a mismatch is a genuinely different target,
/// not a failure - the caller captures fresh, same as a rule with no baseline at
/// all). A read failure or a malformed record is logged and treated as absent
/// (capture fresh) rather than propagated as an arm failure: the legacy FileGuard
/// has no "errored, don't arm" channel for this today (unlike Spark's Unhealthy
/// verdict), and a KvStore read failure here is the same failure mode every other
/// KV-backed read in this file already degrades-and-logs on (put_rule_locked's own
/// json_to_rule parse-failure sites), not a new weaker posture introduced for
/// baselines specifically.
std::optional<std::string> guardian_seed_baseline(KvStore& kv, const std::string& rule_id,
                                                   const std::string& fingerprint) {
    BaselineRecord rec;
    switch (read_baseline_record(kv, rule_id, rec)) {
    case BaselineReadOutcome::Absent:
        return std::nullopt; // genuinely no baseline yet - first-ever arm for this rule_id
    case BaselineReadOutcome::ReadError:
        spdlog::error("Guardian: baseline lookup for rule '{}' failed (KV read error) - "
                     "arming as if no baseline is on record",
                     log_id_token(rule_id));
        return std::nullopt;
    case BaselineReadOutcome::Malformed:
        spdlog::error("Guardian: baseline record for rule '{}' is malformed (bad JSON or hash) "
                     "- discarding and arming as if no baseline is on record",
                     log_id_token(rule_id));
        return std::nullopt;
    case BaselineReadOutcome::Ok:
        break;
    }
    if (rec.fingerprint != fingerprint)
        return std::nullopt; // different target under this rule_id - not a failure, fresh capture
    return rec.hash;
}

/// Persist a newly-captured baseline. Takes `KvStore*` by raw pointer (not
/// `GuardianEngine&`/`this`) so it is safe to call from a guard worker thread via a
/// callback: the worker must never reach back into GuardianEngine state or take
/// its lock (see emit_guard_event's own doc), and `kv_` outlives every guard
/// thread by construction (agent.cpp declares kv_store_ before guardian_, so it
/// destructs AFTER - and stop_all_guards_locked()/withdraw join every guard thread
/// before GuardianEngine itself is torn down).
///
/// adversarial-review K1/C2-1 (both Kimi and Codex, independently): a TRANSIENT
/// failure of guardian_seed_baseline's read (not absence — an actual KV read
/// error, or a momentarily-malformed record) makes the arm proceed as if there
/// were no baseline, so the guard captures WHATEVER the target currently holds —
/// which, if the target has genuinely drifted since the real baseline was
/// captured, is the drifted content. Persisting that unconditionally would
/// overwrite the still-good prior record with the drifted one, permanently
/// losing the only durable copy of the real baseline — reproducing this issue's
/// exact laundering through the read-failure path instead of the full_sync path
/// it was written to close. So this re-reads the CURRENT record first: if one
/// already exists, is well-formed, AND matches `fingerprint` (same target), this
/// write is refused — that combination is otherwise unreachable on the happy path
/// (a matching well-formed record means guardian_seed_baseline would have seeded
/// `expected_hash` and the guard's capture branch would never have fired at all),
/// so its only reachable cause is a failed seed lookup, and keeping the existing
/// record is always safer than trusting a capture that may be re-recording
/// drift. A genuinely ABSENT record, a malformed one (self-heals — it was
/// already unrecoverable), or one for a DIFFERENT fingerprint (a genuine
/// retarget) all still write normally. A read failure on THIS (persist-side) re-
/// read degrades to "write anyway" — the pre-existing, narrower posture — logged
/// distinctly, so a KV outage cannot indefinitely wedge a rule out of ever
/// getting a persisted baseline at all.
void guardian_persist_baseline(KvStore* kv, const std::string& rule_id,
                               const std::string& fingerprint, const std::string& hash) {
    if (!kv)
        return;
    BaselineRecord existing;
    switch (read_baseline_record(*kv, rule_id, existing)) {
    case BaselineReadOutcome::Ok:
        if (existing.fingerprint == fingerprint) {
            spdlog::warn("Guardian: refusing to overwrite rule '{}''s persisted baseline with a "
                        "fresh capture for the SAME target - a capture attempt only reaches "
                        "here for an already-baselined target via a failed seed lookup "
                        "(adversarial-review K1/C2-1); keeping the existing record",
                        log_id_token(rule_id));
            return;
        }
        break; // different fingerprint - a genuine retarget, write below
    case BaselineReadOutcome::Absent:
    case BaselineReadOutcome::Malformed:
        break; // nothing usable on record - safe to write
    case BaselineReadOutcome::ReadError:
        spdlog::warn("Guardian: could not re-check rule '{}''s persisted baseline before "
                    "writing (KV read error) - writing the fresh capture anyway rather than "
                    "risk wedging the rule out of ever getting a persisted baseline",
                    log_id_token(rule_id));
        break;
    }
    nlohmann::json j;
    j["schema"] = kBaselineSchemaVersion;
    j["fingerprint"] = fingerprint;
    j["hash"] = hash;
    if (!kv->set(kKvNamespace, make_baseline_key(rule_id), j.dump())) {
        spdlog::error("Guardian: failed to persist captured baseline for rule '{}' - a later "
                     "full_sync or restart will re-capture current content instead of this "
                     "one (#4021)",
                     log_id_token(rule_id));
    }
}

nlohmann::json block_to_json(const gpb::GuardianSpecBlock& b) {
    nlohmann::json j;
    j["type"] = b.type();
    nlohmann::json params = nlohmann::json::object();
    // Iterator form (not `auto& [k,v]`): MSVC C3493s on structured bindings used
    // inside a lambda/function template context.
    for (auto it = b.params().begin(); it != b.params().end(); ++it)
        params[it->first] = it->second;
    j["params"] = params;
    return j;
}

nlohmann::json rule_to_json(const gpb::GuaranteedStateRule& r) {
    nlohmann::json j;
    j["rule_id"]          = r.rule_id();
    j["name"]             = r.name();
    j["yaml_source"]      = r.yaml_source();
    j["version"]          = static_cast<std::uint64_t>(r.version());
    j["enabled"]          = r.enabled();
    j["enforcement_mode"] = r.enforcement_mode();
    j["spark"]            = block_to_json(r.spark());
    j["assertion"]        = block_to_json(r.assertion());
    j["remediation"]      = block_to_json(r.remediation());
    if (!r.signature().empty())
        j["signature_hex"] = hex_encode(r.signature());
    return j;
}

void json_to_block(const nlohmann::json& j, gpb::GuardianSpecBlock* b) {
    if (!j.is_object() || !b) return;
    b->set_type(j.value("type", std::string{}));
    if (j.contains("params") && j["params"].is_object()) {
        const auto& p = j["params"];
        for (auto it = p.begin(); it != p.end(); ++it)
            (*b->mutable_params())[it.key()] =
                it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
    }
}

bool json_to_rule(const nlohmann::json& j, gpb::GuaranteedStateRule& out) {
    if (!j.is_object()) return false;
    out.set_rule_id(j.value("rule_id", std::string{}));
    out.set_name(j.value("name", std::string{}));
    out.set_yaml_source(j.value("yaml_source", std::string{}));
    out.set_version(j.value("version", std::uint64_t{0}));
    out.set_enabled(j.value("enabled", false));
    out.set_enforcement_mode(j.value("enforcement_mode", std::string{}));
    if (j.contains("spark")) json_to_block(j["spark"], out.mutable_spark());
    if (j.contains("assertion")) json_to_block(j["assertion"], out.mutable_assertion());
    if (j.contains("remediation")) json_to_block(j["remediation"], out.mutable_remediation());
    if (j.contains("signature_hex"))
        out.set_signature(hex_decode(j["signature_hex"].get<std::string>()));
    return !out.rule_id().empty();
}

std::string make_rule_key(std::string_view rule_id) {
    std::string k(kRulePrefix);
    k.append(rule_id);
    return k;
}

// #4783 Gate 4 UP-3/UP-4: the legacy-sink loss ledger's persistence shape - a
// SINGLE fixed key (not per-rule, unlike kBaselinePrefix - the whole ledger is
// one small JSON blob), read at boot (start_local(), BEFORE the rule re-arm
// loop) and written from legacy_sink_kick() (gated on change_gen - see that
// method's own doc comment) and stop()'s unconditional final flush. Mirrors
// guardian_persist_baseline/read_baseline_record's shape (schema field, plain
// KvStore::set/get_entry, Ok/Absent/ReadError/Malformed collapsing) rather
// than inventing a new one - see this row's citation in the #4783 Gate 4
// completion report for exactly which lines this was copied from.
constexpr std::string_view kLegacySinkLossKey = "legacy_sink_loss_ledger";
constexpr int kLegacySinkLossSchemaVersion = 1;

nlohmann::json legacy_sink_snapshot_to_json(const GuardianLegacySinkExecutor::Snapshot& snap) {
    nlohmann::json j;
    j["schema"] = kLegacySinkLossSchemaVersion;
    auto& c = j["counters"];
    c["events_lost"] = snap.counters.events_lost;
    c["backpressure_drops"] = snap.counters.backpressure_drops;
    c["admission_failures"] = snap.counters.admission_failures;
    c["send_failures"] = snap.counters.send_failures;
    c["send_exceptions"] = snap.counters.send_exceptions;
    c["worker_faults"] = snap.counters.worker_faults;
    c["dropped_link_down"] = snap.counters.dropped_link_down;
    c["discarded_at_stop"] = snap.counters.discarded_at_stop;
    c["stalls"] = snap.counters.stalls;
    c["launch_failures"] = snap.counters.launch_failures;
    c["gap_ledger_faults"] = snap.counters.gap_ledger_faults;
    c["repairs_suppressed"] = snap.counters.repairs_suppressed;
    // gap_rules is a read-time denormalization (Stats::gap_rules, set by
    // GuardianLegacySinkExecutor::stats()/snapshot() from gaps.size()) -
    // deliberately NOT persisted; restore() recomputes it the same way once
    // the gaps array below is restored.
    auto& gaps = j["gaps"] = nlohmann::json::array();
    for (const auto& g : snap.gaps) {
        nlohmann::json ge;
        ge["rule_id"] = g.rule_id;
        ge["guard_type"] = g.guard_type;
        ge["rule_name"] = g.rule_name;
        ge["lost"] = g.lost;
        ge["first_lost_ms"] = g.first_lost_ms;
        ge["last_lost_ms"] = g.last_lost_ms;
        gaps.push_back(std::move(ge));
    }
    return j;
}

/// Same Ok/Absent/ReadError/Malformed collapsing as BaselineReadOutcome above -
/// see that enum's own doc comment for the rationale (both the boot-read caller
/// and any future re-check caller can switch on one shape without duplicating
/// the KV-read/JSON-parse plumbing).
enum class LegacySinkLossReadOutcome { Ok, Absent, ReadError, Malformed };

LegacySinkLossReadOutcome
read_legacy_sink_loss_record(KvStore& kv, GuardianLegacySinkExecutor::Stats& counters_out,
                             std::vector<GuardianLegacySinkExecutor::GapSnapshotEntry>& gaps_out) {
    auto raw = kv.get_entry(kKvNamespace, kLegacySinkLossKey);
    if (!raw)
        return LegacySinkLossReadOutcome::ReadError;
    if (!raw->has_value())
        return LegacySinkLossReadOutcome::Absent;
    try {
        auto j = nlohmann::json::parse(**raw);
        // Schema-version drift is a DISTINCT failure from "malformed" only in
        // spirit here (unlike the baseline record, this ledger has no
        // fingerprint-vs-retarget distinction to protect) - still gated
        // separately from the generic parse/shape checks below so a future
        // schema bump reads as an explicit, intentional case rather than
        // falling through whatever the shape checks happen to do with an
        // old-shaped record.
        if (j.value("schema", -1) != kLegacySinkLossSchemaVersion)
            return LegacySinkLossReadOutcome::Malformed;
        if (!j.contains("counters") || !j["counters"].is_object() || !j.contains("gaps") ||
            !j["gaps"].is_array())
            return LegacySinkLossReadOutcome::Malformed;
        const auto& c = j["counters"];
        GuardianLegacySinkExecutor::Stats counters{};
        counters.events_lost = c.value("events_lost", std::uint64_t{0});
        counters.backpressure_drops = c.value("backpressure_drops", std::uint64_t{0});
        counters.admission_failures = c.value("admission_failures", std::uint64_t{0});
        counters.send_failures = c.value("send_failures", std::uint64_t{0});
        counters.send_exceptions = c.value("send_exceptions", std::uint64_t{0});
        counters.worker_faults = c.value("worker_faults", std::uint64_t{0});
        counters.dropped_link_down = c.value("dropped_link_down", std::uint64_t{0});
        counters.discarded_at_stop = c.value("discarded_at_stop", std::uint64_t{0});
        counters.stalls = c.value("stalls", std::uint64_t{0});
        counters.launch_failures = c.value("launch_failures", std::uint64_t{0});
        counters.gap_ledger_faults = c.value("gap_ledger_faults", std::uint64_t{0});
        counters.repairs_suppressed = c.value("repairs_suppressed", std::uint64_t{0});
        std::vector<GuardianLegacySinkExecutor::GapSnapshotEntry> gaps;
        gaps.reserve(j["gaps"].size());
        std::size_t skipped_empty_rule_id = 0;
        for (const auto& ge : j["gaps"]) {
            if (!ge.is_object())
                return LegacySinkLossReadOutcome::Malformed;
            GuardianLegacySinkExecutor::GapSnapshotEntry g;
            g.rule_id = ge.value("rule_id", std::string{});
            g.guard_type = ge.value("guard_type", std::string{});
            g.rule_name = ge.value("rule_name", std::string{});
            g.lost = ge.value("lost", std::uint64_t{0});
            g.first_lost_ms = ge.value("first_lost_ms", std::int64_t{0});
            g.last_lost_ms = ge.value("last_lost_ms", std::int64_t{0});
            // #4783 Gate 4 unhappy-path finding, 2026-09-24 (defense in depth):
            // SKIP a single empty-rule_id entry rather than rejecting the WHOLE
            // record - every real entry always has one, but a rare "phantom"
            // gap (guardian_legacy_sink_executor.hpp's worker_loop/offer()
            // catch blocks both now refuse to create one in the first place,
            // see their own doc comments) is not the only conceivable source
            // of one, and this ledger is a best-effort loss-VISIBILITY marker,
            // never a durable-correctness store - discarding every OTHER
            // rule's legitimate open-gap state over ONE bad entry is a far
            // worse outcome than losing that one entry's own history. A
            // genuinely corrupt/hand-crafted record (bad JSON, wrong shape)
            // still fails Malformed via the type checks above/the outer
            // catch - this narrows ONLY the single-bad-entry case.
            if (g.rule_id.empty()) {
                ++skipped_empty_rule_id;
                // #4783 Gate 6 sre finding, 2026-09-24: fold into the SAME
                // durable counter record_gap_locked()'s own allocation-degrade
                // path already uses (see that field's doc comment, amended in
                // the same change) rather than leaving this a log-only,
                // easily-missed signal - a restart is exactly the moment an
                // operator is least likely to be watching logs for a one-line
                // warn that's also wrapped in its own try/catch below.
                ++counters.gap_ledger_faults;
                continue;
            }
            gaps.push_back(std::move(g));
        }
        if (skipped_empty_rule_id > 0) {
            try {
                spdlog::warn("Guardian: legacy-sink loss ledger record had {} entr{} with an "
                            "empty rule_id - skipped, the other {} entr{} restored normally",
                            skipped_empty_rule_id, skipped_empty_rule_id == 1 ? "y" : "ies",
                            gaps.size(), gaps.size() == 1 ? "y" : "ies");
            } catch (...) {
            }
        }
        counters_out = counters;
        gaps_out = std::move(gaps);
        return LegacySinkLossReadOutcome::Ok;
    } catch (const nlohmann::json::exception&) {
        return LegacySinkLossReadOutcome::Malformed;
    }
}

/// Persist `snap` to the fixed legacy-sink loss ledger key. Takes `KvStore*` by
/// raw pointer (not `GuardianEngine&`/`this`) for the SAME reason
/// guardian_persist_baseline does - safe to call from legacy_sink_kick(), which
/// deliberately runs off mtx_ (see that method's own doc comment), and `kv_`
/// outlives every caller by construction (agent.cpp declares kv_store_ before
/// guardian_). Returns kv_->set()'s own success bool (false if `kv` is null) -
/// every caller logs on false and does NOT advance its own "last persisted
/// generation" tracking, so a failed write is retried on the next opportunity
/// rather than silently believed to have happened.
bool persist_legacy_sink_loss_ledger(KvStore* kv, const GuardianLegacySinkExecutor::Snapshot& snap) {
    if (!kv)
        return false;
    return kv->set(kKvNamespace, kLegacySinkLossKey, legacy_sink_snapshot_to_json(snap).dump());
}

} // namespace

GuardianEngine::GuardianEngine(KvStore* kv, std::string agent_id, bool prefer_spark)
    : kv_{kv}, agent_id_{std::move(agent_id)},
      legacy_sink_executor_{std::make_unique<GuardianLegacySinkExecutor>()},
      prefer_spark_{prefer_spark}, ack_ledger_{std::make_unique<GuardianArmAckLedger>()} {}

GuardianEngine::~GuardianEngine() {
    // Explicit (not = default): join the guard worker threads here via stop().
    // Workers call emit_guard_event(), which reads THIS engine's own
    // event_sink_/sink_mtx_/event_seq_ — GuardianEngine members, so they outlive
    // this join regardless of declaration order.
    //
    // #4783 UPDATE: that join is now prompt — emit_guard_event() only enqueues onto
    // legacy_sink_executor_ (offer() never blocks on network I/O), so a guard's own
    // detection thread no longer parks inside a stalled Write() and stop_all_guards_
    // locked()'s join is no longer at the mercy of the network. What this join no
    // longer bounds is the AgentImpl-side sink state (stream_write_mu_ +
    // guardian_sink_stream_, H4 / #1209): the actual send now runs on
    // legacy_sink_executor_'s own DETACHED worker, which this stop() call does not
    // join and which can outlive both this engine and the AgentImpl instance that
    // owns those members. Safety for that no longer rests on thread-join ordering —
    // it rests on the orphan-exit contract instead: legacy_sink_executor_->
    // active_worker_count() is summed into active_io_workers() (below), and
    // main.cpp/service_win.cpp's hard_exit.hpp guard refuses normal C++ teardown of
    // AgentImpl while that count is nonzero, hard_exit()ing instead after a bounded
    // grace — exactly the same contract guardian_outbox_send_executor.hpp's Spark
    // send executor already relies on, not a join. stop() is idempotent.
    stop();
}

std::string_view GuardianEngine::kv_namespace() {
    return kKvNamespace;
}

std::string_view GuardianEngine::legacy_sink_loss_ledger_key_for_test() {
    return kLegacySinkLossKey;
}

std::expected<void, std::string> GuardianEngine::start_local() {
    std::lock_guard lock(mtx_);
    if (started_) return {};
    // stop() is STICKY: if it already ran (e.g. a SIGTERM / service-stop arrived
    // during boot, before the reordered start_local() at rung 7.7a), do NOT
    // resurrect. Without this, stop() -> start_local() would set started_=true and
    // re-arm cached guards AFTER stop() returned, so stop() would not be truthful
    // (and at rung 7.7b, detection + buffered sends could resume post-stop).
    if (stopped_) return {};
    started_ = true;

    if (!kv_) {
        spdlog::warn("Guardian: KV store unavailable — rule cache will be in-memory only "
                     "(survives only the current process lifetime)");
        return {};
    }

    refresh_count_locked();

    if (auto raw = kv_->get(kKvNamespace, kKeyGen); raw.has_value()) {
        std::uint64_t parsed = 0;
        const auto& s = *raw;
        [[maybe_unused]] auto [_, ec] = std::from_chars(s.data(), s.data() + s.size(), parsed);
        if (ec == std::errc{})
            policy_generation_ = parsed;
    }

    // rung 9c PR-2 Unit 6 (§R5.3's own boot note: "start_local() also receives
    // asynchronous reconciliation results - handle their eventual failures without
    // inventing a new server-generation acknowledgment"). Opens an application AT
    // the already-loaded policy_generation_ - not a new one - so the tick's own
    // `gen > policy_generation_` check can never advance anything from it; boot
    // re-arm's Accepted receipts are still drained and their failures still logged
    // (ack_ledger_'s drain, not reconcile_rule_locked's now-synchronous-only warn),
    // they just never move the generation. No content_id: nothing here is compared
    // against a later push (decide_retry() is apply_rules()-only), so the field is
    // unused for this application - left empty rather than computed for nothing.
    //
    // Defensive, not exercised by SparkReconcileFixture (test_guardian_engine_spark_
    // reconcile.cpp): that fixture calls start_local() BEFORE wire_spark_engine(), so
    // spark_availability_ is still Unwired here and reconcile_rule_locked's Arm branch
    // never reaches spark_runtime_->attach_rule() during ITS boot walk - nothing this
    // application could ever hold pending. Production wires first (agent.cpp calls
    // wire_spark_engine() before start_local()), so a real boot CAN re-arm via spark
    // here; this call exists for that ordering, not the test fixture's.
    // Governance finding UP-1 (Gate 4, folded): same unguarded-allocation class as
    // apply_rules()'s own begin_application() call, fixed alongside it. Non-fatal
    // here - a failure to open the boot bookkeeping application must not block
    // startup; the boot re-arm loop below re-arms every cached rule directly via
    // reconcile_rule_locked() regardless of whether this ledger call succeeded.
    try {
        ack_ledger_->begin_application(policy_generation_, "", /*full_sync=*/false,
                                       /*applied=*/0);
    } catch (const std::exception& e) {
        spdlog::warn("Guardian: failed to begin boot ack application: {}", e.what());
    } catch (...) {
        spdlog::warn("Guardian: failed to begin boot ack application: unknown exception");
    }

    // #4783 Gate 4 UP-3/UP-4: restore the legacy-sink loss ledger (counters +
    // open gaps) from a prior process, BEFORE the boot re-arm loop below -
    // reconcile_rule_locked() (called from that loop) can start a REAL guard
    // thread (e.g. a Windows FileGuard's watch thread) that reaches
    // emit_guard_event() -> legacy_sink_executor_->offer() asynchronously,
    // before this function returns. restore() itself is safe to call here
    // specifically because start_local() holds mtx_ for its entire body and
    // this call precedes every re-arm in that same locked call, so no
    // offer()/kick() against legacy_sink_executor_ can be in flight yet - see
    // GuardianLegacySinkExecutor::restore()'s own precondition doc comment.
    if (kv_) {
        GuardianLegacySinkExecutor::Stats seed_counters{};
        std::vector<GuardianLegacySinkExecutor::GapSnapshotEntry> seed_gaps;
        switch (read_legacy_sink_loss_record(*kv_, seed_counters, seed_gaps)) {
        case LegacySinkLossReadOutcome::Ok: {
            const std::size_t gap_count = seed_gaps.size(); // read BEFORE the move below
            legacy_sink_executor_->restore(seed_counters, std::move(seed_gaps));
            spdlog::info("Guardian: restored the legacy-sink loss ledger from a prior "
                        "process (events_lost={}, open gap_rules={})",
                        seed_counters.events_lost, gap_count);
            break;
        }
        case LegacySinkLossReadOutcome::Absent:
            break; // nothing persisted yet - fresh state, nothing to restore
        case LegacySinkLossReadOutcome::ReadError:
            spdlog::warn("Guardian: legacy-sink loss ledger lookup failed (KV read error) - "
                        "starting with an empty loss ledger");
            break;
        case LegacySinkLossReadOutcome::Malformed:
            spdlog::warn("Guardian: legacy-sink loss ledger record is malformed (bad JSON, "
                        "schema mismatch, or bad shape) - discarding and starting with an "
                        "empty loss ledger");
            break;
        }
    }

    // A2 (restart re-arm). A restarted agent must keep enforcing without waiting
    // for the next server push — re-arm a guard for every cached enabled rule
    // (design §4: enforce cached guards from KV pre-network). Enforcement
    // (write-back) needs no event sink, so it runs immediately; drift events
    // detected before set_event_sink() is wired are dropped (durable buffering
    // is A3). Guards re-armed by a later push replace these. Before this, a
    // restarted agent reported rules present while enforcing nothing.
    // Flush the boot re-arm's staged "armed" records to the durable journal on exit
    // (normal return or an un-firewalled throw). Same terminate-safe always-fire guard as
    // apply_rules; fires with mtx_ still held (declared after the lock).
    GuardianRollback journal_flush;
    // Firewall + COUNT a persist-during-unwind throw (review UP-6): GuardianRollback's dtor is
    // terminate-safe and swallows it, but a swallowed-yet-uncounted flush failure is an invisible
    // audit-durability gap. Match the B4a maintenance-tick posture: catch here and count it.
    journal_flush.fn = [this] {
        try {
            persist_lifecycle_journal_locked(kJournalPersistUnbounded,
                                             kJournalPersistUnbounded);
        } catch (...) {
            journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
        }
    };

    std::size_t rearmed = 0;
    for (const auto& key : kv_->list(kKvNamespace, kRulePrefix)) {
        auto raw = kv_->get(kKvNamespace, key);
        if (!raw)
            continue;
        gpb::GuaranteedStateRule rule;
        try {
            auto parsed = nlohmann::json::parse(*raw);
            if (!json_to_rule(parsed, rule))
                continue;
        } catch (const nlohmann::json::exception&) {
            continue;
        }
        if (!rule.enabled())
            continue;
        // Arming a legacy guard spawns a std::thread (guard_{file,registry,systemd}.cpp);
        // under thread-or-handle exhaustion that ctor throws std::system_error. This
        // loop runs OUTSIDE the json try above, and start_local()'s caller does not
        // catch, so an uncaught throw here escapes run() and terminates the agent. Since
        // rung 7.7a re-armed cached guards AFTER the SparkEngine's own boot threads, an
        // exhausted host could now hit this on the still-authoritative legacy backend.
        // Degrade per-rule (LOUD error, this rule does not enforce) so the agent survives
        // to arm the rest, rather than terminating the whole process.
        try {
            if (rearm_fault_hook_for_test_)
                rearm_fault_hook_for_test_(rule.rule_id());
            if (reconcile_rule_locked(rule) == ReconcileOutcome::Armed) // either backend
                ++rearmed;
        } catch (const std::exception& e) {
            // Build once, log, and record for last_rearm_degrade_message_for_test - a single
            // source of truth rather than a second copy of this text. spdlog::error("{}", msg),
            // a literal one-placeholder format string with msg as the substituted argument,
            // never reparses msg's own content as format syntax regardless of vendored spdlog
            // version/overload resolution - the version-proof safe idiom for logging arbitrary
            // (here, exception-supplied) text, not a workaround for a throw this specific
            // vendored version happens not to have.
            //
            // Nested try/catch (Gate 4 unhappy-path review, #2238): spdlog::error() firewalls
            // its OWN allocation internally (SPDLOG_TRY/SPDLOG_LOGGER_CATCH - never rethrows),
            // but the raw string concatenation building degrade_msg runs OUTSIDE that firewall,
            // in a catch block whose entire purpose is to survive exactly the resource-exhaustion
            // class (thread/handle exhaustion often correlates with memory pressure) that could
            // also make this concatenation throw bad_alloc. An uncaught throw here would escape
            // start_local() and terminate the agent - precisely the failure this outer catch
            // exists to prevent. Degrade further on a secondary failure rather than risk that.
            try {
                const std::string degrade_msg =
                    "Guardian: rule '" + log_id_token(rule.rule_id()) + "' failed to re-arm (" +
                    e.what() +
                    ") - NOT enforcing this rule; agent continues with the remaining rules";
                spdlog::error("{}", degrade_msg);
                last_rearm_degrade_message_for_test_ = degrade_msg;
            } catch (...) {
                spdlog::error("Guardian: a rule failed to re-arm and the degrade message itself "
                              "could not be built (secondary allocation failure) - NOT enforcing "
                              "this rule; agent continues with the remaining rules");
            }
        }
    }

    spdlog::info("Guardian engine started (cached_rules={}, re-armed={}, policy_generation={})",
                 rule_count_, rearmed, policy_generation_);
    if (rearmed > 0)
        spdlog::warn("Guardian: {} guard(s) re-armed pre-network — drift remediated before the "
                     "server connection is enforced but NOT reported until reconnect (durable "
                     "event buffering is A3)",
                     rearmed);
    return {};
}

void GuardianEngine::sync_with_server() {
    std::lock_guard lock(mtx_);
    if (!started_) {
        spdlog::warn("Guardian: sync_with_server called before start_local — ignoring");
        return;
    }
    spdlog::info("Guardian engine network-connected (policy_generation={}, rules={})",
                 policy_generation_, rule_count_);
}

void GuardianEngine::stop() {
    std::lock_guard lock(mtx_);
    // Spark teardown FIRST, in this order (rung 7): (1) runtime phase 1 - fast,
    // wakes any bounded reader waiter, makes a concurrent spark event a no-op;
    // (2) the convergence scheduler - joins its lane threads, CV-interruptible
    // so this is prompt, not a multi-minute wait; (3) the drain worker - joins
    // its thread. By the time all three return, spark_runtime_ is refusing new
    // commits, so the external spark_engine_->stop() (owned by agent.cpp,
    // called separately - GuardianEngine never owns spark_engine_ itself) can
    // safely tear down the consumer afterward without racing a live commit.
    // (4) legacy guards, unchanged.
    // Signal the durable-journal paging path to stop BEFORE joining the drain worker, so a
    // concurrent off-mtx_ page (tick / reconnect) bails between batches instead of mutating a
    // post-join window (rev-4.1 #7 stop-race gate).
    if (lifecycle_journal_)
        lifecycle_journal_->request_stop();
    // Persist BEFORE the joins, not only after (#2345 Gate 8 security + Gate 6 compliance).
    // stop() joins the drain worker below, and that join is a blocking wait on a send that may
    // be blackholed. If a supervisor's stop timeout or an operator kill lands in that window,
    // a persist placed only after the join never runs and the staged records are gone - real
    // destruction of an audit record, not the at-least-once redelivery this design otherwise
    // guarantees. Nothing about persisting orders on the join, so it costs only its own bounded
    // KvStore write to do it first. The post-join flush stays: it catches anything the worker
    // staged while it was winding down, and re-running is safe because persist() erases the
    // durably-written prefix, so a record is never written under two keys.
    try {
        persist_lifecycle_journal_locked(kJournalPersistUnbounded, kJournalPersistUnbounded);
    } catch (...) {
        journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
    }
    if (spark_runtime_)
        spark_runtime_->begin_stop();
    // rung 9c PR-2 Unit 6 (§R5.5): retire acknowledgment candidates and prevent
    // subsequent tick advancement - journal_maintenance_tick() itself already
    // no-ops after stopped_, so this is belt-and-suspenders against a tick that
    // raced this call and read stopped_ as still false, plus it stops watching
    // receipts whose claims begin_stop() just started tearing down.
    ack_ledger_->retire();
    if (spark_scheduler_)
        spark_scheduler_->stop();
    if (spark_drain_worker_)
        spark_drain_worker_->stop();
    stop_all_guards_locked();
    // #4783: stop legacy_sink_executor_ from admitting NEW sends only AFTER the
    // guards above have joined — by the time stop_all_guards_locked() returns, every
    // guard's own detection thread has already made its last emit_guard_event() call
    // (offer() never blocks, so nothing here is actually waiting ON a guard thread;
    // this is purely about ordering the two teardown steps). This does NOT flush the
    // backlog: any event still QUEUED (not yet in flight) at this point is DISCARDED
    // by the executor's own stop(), counted via its discarded_at_stop stat — only a
    // send already IN FLIGHT is left running, detached, covered by the orphan-exit
    // accounting active_io_workers() sums below. See
    // guardian_legacy_sink_executor.hpp's own stop() doc comment for the full
    // contract; never blocks.
    legacy_sink_executor_->stop();
    // #4783 Gate 4 UP-3/UP-4: one final, unconditional (not change_gen-gated,
    // unlike legacy_sink_kick()'s own persist) restart-durable write of the
    // loss ledger - same reasoning as the lifecycle-journal final flush right
    // below: a bounded, synchronous KV write that catches whatever changed
    // since the last successful kick()-driven persist, including a rule that
    // never got a single heartbeat before the agent shut down (an open gap
    // with zero prior kicks still needs to survive the restart it is about to
    // undergo). FIREWALLED for the same reason as the journal flush below -
    // stop() is reached from the (implicitly noexcept) ~GuardianEngine
    // destructor. kv_ read without mtx_ is safe - see legacy_sink_kick()'s own
    // comment on that; mtx_ IS held here (stop()'s whole body), but that does
    // not change kv_'s own never-reassigned-after-construction contract, and
    // it is NOT what protects the sequence below (mtx_ guards nothing legacy-
    // sink-related - see legacy_sink_persist_mu_'s own doc comment).
    //
    // #4783 Gate 8 re-review: snapshot + persist + record-gen run under
    // legacy_sink_persist_mu_ for their ENTIRE span, the same lock
    // legacy_sink_kick()'s own persist block takes for its entire span - this
    // is what stops a late in-flight heartbeat kick() (agent.cpp calls
    // stop() before joining the heartbeat thread - quiesce_run_workers())
    // from clobbering the fresher write below with a stale snapshot it took
    // before stop() ran; see legacy_sink_persist_mu_'s doc comment for the
    // exact race this closes. The lock_guard is taken INSIDE the try, not
    // outside it: std::mutex::lock() can throw std::system_error, and this
    // whole path is reached from the (implicitly noexcept) destructor, so an
    // escape here must be caught, not left to std::terminate.
    if (kv_) {
        try {
            std::lock_guard<std::mutex> persist_lk(legacy_sink_persist_mu_);
            const auto snap = legacy_sink_executor_->snapshot();
            if (persist_legacy_sink_loss_ledger(kv_, snap))
                legacy_sink_last_persisted_gen_ = snap.change_gen;
            else
                spdlog::warn("Guardian: failed to persist the legacy-sink loss ledger during "
                            "shutdown (change_gen={}) - a restart may see stale (though never "
                            "corrupt) loss/gap state",
                            snap.change_gen);
        } catch (...) {
        }
    }
    // F7: stop() is terminal - nothing reconciles again afterward, so there is no
    // re-log/false-transition risk (unlike apply_rules's full_sync, which must sweep
    // precisely instead). Blanket-clearing here just keeps a heartbeat composed
    // mid/post-shutdown from reporting stale unsupported counts.
    unsupported_rules_.clear();
    // Final flush: anything staged while the workers wound down, plus any records a prior
    // failed write left pending; there is no maintenance tick after stop(). Bounded +
    // circuit-broken (worst case one KvStore 5 s busy-timeout). FIREWALLED: stop() is reached
    // from the (implicitly noexcept) ~GuardianEngine destructor, so a throw here would
    // std::terminate (review B4a).
    try {
        persist_lifecycle_journal_locked(kJournalPersistUnbounded, kJournalPersistUnbounded);
    } catch (...) {
        journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
    }
    stopped_ = true;
    started_ = false;
}

void GuardianEngine::WorkerHostileMutex::abort_if_worker_thread() noexcept {
#ifdef YUZU_WORKER_MUTEX_GUARD
    // Enabled in debug AND in any sanitizer build, on every compiler we ship: GCC defines
    // __SANITIZE_THREAD__/__SANITIZE_ADDRESS__, Clang answers __has_feature. A release build
    // without sanitizers compiles this away entirely, so the production hot path pays
    // nothing for an invariant CI proves.
    const bool joined = on_guardian_joined_thread();
    const bool detached = on_guardian_detached_worker_thread();
    if (!joined && !detached)
        return;
    try {
        if (joined) {
            spdlog::critical("Guardian: a worker thread that stop() joins took GuardianEngine::"
                             "mtx_ - this deadlocks against stop(), which holds mtx_ while joining "
                             "it. Aborting rather than hanging. See "
                             "guardian_joined_thread_role.hpp (#2298).");
        } else {
            // rung 9c R5.1: the second role. A detached GuardianIoExecutor worker (run()
            // or submit() body, or its on_abandoned/on_complete callback) can never be
            // joined and may outlive stop() - blocking it here either stalls the F3
            // orphan grace into a hard_exit() or resumes it into a torn-down engine.
            spdlog::critical("Guardian: a detached GuardianIoExecutor worker (run()/submit() "
                             "body or its completion/abandon callback) took GuardianEngine::"
                             "mtx_ - such a worker may outlive the engine and can never be "
                             "joined: this either stalls the F3 orphan grace into a hard_exit "
                             "or resumes into a destroyed engine. Aborting rather than "
                             "wedging. See guardian_detached_worker_role.hpp (R5.1).");
        }
    } catch (...) {
    }
    // Deliberately std::abort, not assert: assert is a no-op under NDEBUG, which would have
    // meant a sanitizer-enabled release build logged this and then deadlocked anyway. A
    // crash with this message is strictly better than a fleet of hung agents.
    std::abort();
#endif
}

void GuardianEngine::persist_lifecycle_journal_locked(std::size_t max_batches,
                                                     std::size_t max_records) {
    // mtx_ held. Gated: no durable journal work unless spark is the ACTIVE backend and
    // the path is wired (rev-4.1 §7 inertness - at prefer_spark_=false a pre-populated
    // journal is neither written, pruned, nor paged. Precise exception (#2303 Sol): the
    // journal's CONSTRUCTOR still runs once regardless of prefer_spark_ - a read-only
    // PRAGMA synchronous check + a namespace_size() size probe to seed the gauges. Those
    // two boot-time reads are the only thing that touches the store while inert.
    if (!prefer_spark_ || !spark_runtime_ || !lifecycle_journal_)
        return;
    // The overflow-drop counter comes back FROM the snapshot, read under its lock: the erase
    // below has to identify the prefix it wrote, and a concurrent drop-oldest shifts positions
    // (#2345 Gate 8b).
    const auto snap = spark_runtime_->snapshot_pending();
    const auto& pending = snap.records;
    if (pending.empty())
        return;
    // snapshot released outbox_mu_; persist() does KV I/O holding NO runtime lock (so the
    // WRITE chain never nests outbox_mu_ under KvStore.mu_); erase re-takes outbox_mu_ for
    // ONLY the prefix persist() durably wrote (circuit-broken on the first failure - the
    // rest stay pending for the maintenance-tick retry, C3).
    std::vector<PersistedBatch> batches;
    const std::size_t written =
        lifecycle_journal_->persist(pending, &batches, max_batches, max_records);
    if (written > 0) {
        // Erase the durably-written staging prefix FIRST - it is the durability-completion step:
        // once a batch is committed it must NEVER be re-persisted under a fresh key. Provenance
        // back-fill (best-effort, allocates a set) runs AFTER, so a throw there loses only a
        // sent-label back-fill (a later false evicted_without_send_evidence, monitoring noise),
        // never leaves the records staged to re-persist as a DUPLICATE durable batch (review UP-6).
        spark_runtime_->erase_persisted_prefix(written, snap.drops_at_snapshot);
        for (const auto& b : batches)
            if (!b.event_ids.empty())
                spark_runtime_->backfill_batch_provenance(b.key, b.event_ids, b.event_ids.back());
    }
}

void GuardianEngine::journal_maintenance_tick() {
    // ONE phase since C0 (#2298 gate 1): retry any persist a prior write left pending, so a
    // failed write self-heals on the heartbeat with NO new push/reconnect (Sol BLOCKER-4).
    // Retention prune + replay paging - the two KvStore-bound full-journal passes that used to
    // run here off-mtx_ as phase 2 - now run on the drain worker, so a contended or oversized
    // journal can no longer stall the heartbeat into false staleness. A no-op after stop().
    //
    // No worker kick after a successful persist: paging is already MORE frequent than before
    // (the worker's 30 s page cadence, kicked immediately on reconnect, vs this 30 s tick), so a kick would add an mtx_ -> Signal.mu
    // lock edge on the heartbeat path for latency the page cadence already bounds.
    //
    // rung 9c PR-2 Unit 6: also THE ack-bookkeeping drain (§R5.3) - reused rather than a
    // second heartbeat call site, since both are "periodic maintenance under mtx_,
    // prefer_spark_-gated, firewalled" already. Runs AFTER the journal persist above (an
    // arbitrary but harmless ordering choice: neither reads the other's result) and BEFORE
    // agent.cpp reads policy_generation() for the heartbeat's own guardian_generation tag,
    // so an acknowledgment this tick produces is visible on the SAME heartbeat, not one late.
    std::lock_guard lock(mtx_);
    if (stopped_ || !prefer_spark_)
        return;
    // FIREWALLED: this runs on the BARE heartbeat thread (no top-level handler), so a
    // bad_alloc from the persist path must be swallowed + counted, never std::terminate
    // (review B4a).
    try {
        // BOUNDED (C0 flip-checklist item 11). This is the one caller that runs on the bare
        // heartbeat thread on a cadence, so it is the one that must not be able to sit under
        // mtx_ for an unbounded number of KvStore round trips when writes are merely SLOW
        // rather than failing. The remainder stays staged and the next tick continues it.
        // Boot, apply_rules and both shutdown flushes stay unbounded: each is a one-shot that
        // has to drain what it was given.
        persist_lifecycle_journal_locked(kJournalPersistMaxBatchesPerTick,
                                        kJournalPersistMaxRecordsPerTick);
    } catch (...) {
        journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
    }
    if (!spark_runtime_)
        return;
    // Own firewall (distinct counter): a throw here must not prevent the journal work
    // above (already done) from having happened, and must not escape onto the bare
    // heartbeat thread either.
    try {
        // UP-3 (Gate 4, folded): drain_locked()'s failed_out feeds the durable
        // fleet-visible arm_failures_ counter - an async-resolved arm failure used
        // to update only this ledger's own internal bookkeeping and a local log
        // line, never the counter a synchronous refusal already bumps.
        std::size_t ack_arm_failures_this_tick = 0;
        ack_ledger_->drain_locked(*spark_runtime_, kAckDrainMaxPerTick,
                                  &ack_arm_failures_this_tick);
        if (ack_arm_failures_this_tick > 0)
            arm_failures_.fetch_add(ack_arm_failures_this_tick, std::memory_order_relaxed);
        if (ack_ledger_->can_advance()) {
            const auto gen = ack_ledger_->pending_generation();
            // Persist BEFORE publishing, and check the result: a false return or a
            // throw (kv_->set() is not noexcept) must leave policy_generation_
            // unchanged, so this same `gen > policy_generation_` condition is still
            // true on the NEXT tick and retries the write with no separate retry
            // bookkeeping - publishing first and discarding the result (the old
            // shape) could strand policy_generation_ already advanced with nothing
            // durable behind it, silently and permanently halting the server's
            // re-push (coordinator finding, rung 9c PR-2 Unit 6 gate).
            if (gen > policy_generation_) {
                if (persist_generation_locked(gen))
                    policy_generation_ = gen;
                else
                    // Governance finding (Gate 6, sre + compliance-officer): this
                    // branch was previously silent on failure - no log, no counter -
                    // making a stuck generation undetectable from either the agent
                    // or the server side. Warn-once-per-tick is cheap and closes the
                    // detection gap; the actual retry is the `gen > policy_generation_`
                    // condition remaining true next tick.
                    spdlog::warn("Guardian: failed to persist policy_generation={} from "
                                 "the ack-drain tick (kv write returned false) - held at "
                                 "{}, retried next tick",
                                 gen, policy_generation_);
            }
        }
    } catch (...) {
        ack_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
    }
}

void GuardianEngine::page_journal() {
    // C0 (#2298 gate 1): a KICK, not a page. The reconnect hook runs on the run-loop thread;
    // paging there meant a full journal scan (up to a 5 s KvStore busy timeout per call) inline
    // on the path that has just re-established the stream. Now the drain worker runs the pass
    // and this only wakes it, so replay stays PROMPT (no waiting out the 5 s backstop) without
    // the reconnect thread ever touching the KvStore.
    //
    // Lock order mtx_ -> Signal.mu is safe and non-invertible: the worker thread NEVER takes
    // mtx_ (that is exactly why it is handed a pre-resolved journal pointer), so the
    // stop()-holds-mtx_-while-joining-the-worker shape cannot deadlock against this.
    // FIREWALLED (review B4a, restored after C0 dropped it): this runs on the BARE
    // run-loop thread with no top-level handler, and both the lock and notify()'s own
    // lock_guard can throw std::system_error. Losing a replay kick is a 30 s delay
    // (the page cadence still fires); letting it escape terminates the agent.
    try {
        std::lock_guard lock(mtx_);
        if (stopped_ || !prefer_spark_ || !spark_drain_worker_)
            return;
        spark_drain_worker_->notify();
    } catch (...) {
        journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
    }
}

GuardianJournalStats GuardianEngine::journal_stats() const {
    GuardianJournalStats s;
    std::lock_guard lock(mtx_);
    if (spark_runtime_) {
        s.stage_dropped = spark_runtime_->journal_stage_dropped();
        s.stage_failures = spark_runtime_->journal_stage_failures();
        s.field_rejected = spark_runtime_->journal_field_rejected();
        s.clock_rejected = spark_runtime_->journal_clock_rejected();
        s.pending_depth = spark_runtime_->pending_journal_depth();
        s.send_exceptions = spark_runtime_->send_exception_count();
        s.lifecycle_backpressure_drops = spark_runtime_->lifecycle_backpressure_drops();
    }
    if (lifecycle_journal_) {
        s.batches_written = lifecycle_journal_->batches_written();
        s.write_failures = lifecycle_journal_->write_failures();
        s.key_collisions = lifecycle_journal_->key_collisions();
        s.quarantined = lifecycle_journal_->quarantined();
        s.quarantine_failures = lifecycle_journal_->quarantine_failures();
        s.quarantine_capacity_evicted = lifecycle_journal_->quarantine_capacity_evicted();
        s.batches_pruned = lifecycle_journal_->batches_pruned();
        s.prune_failures = lifecycle_journal_->prune_failures();
        s.page_read_failures = lifecycle_journal_->page_read_failures();
        s.clock_jump_skips = lifecycle_journal_->clock_jump_skips();
        s.write_capacity_rejected = lifecycle_journal_->write_capacity_rejected();
        s.gauge_underflow = lifecycle_journal_->gauge_underflow();
        s.journal_bytes = lifecycle_journal_->journal_bytes();
        s.journal_batch_count = lifecycle_journal_->journal_batch_count();
        s.pages = lifecycle_journal_->pages();
        s.records_paged = lifecycle_journal_->records_paged();
        s.sent_labels_written = lifecycle_journal_->sent_labels_written();
        s.evicted_sent_unacked = lifecycle_journal_->evicted_sent_unacked();
        s.evicted_without_send_evidence = lifecycle_journal_->evicted_without_send_evidence();
        s.evicted_unclassified = lifecycle_journal_->evicted_unclassified();
    }
    // maint_exceptions keeps its NAME's meaning: journal work only - the heartbeat's
    // retry-persist plus the drain worker's prune/page, which is where prune/page throws were
    // counted before C0 moved them off the heartbeat. An operator watching this tag must not
    // see it go dead just because the work changed threads.
    //
    // Outbox-delivery and convergence-sweep firewalls get their OWN tags rather than being
    // folded in here (#2298 Gate 6 sre). Aggregating them looked like consolidation but
    // destroyed the distinction that matters on call: a journal failure means the audit trail
    // is at risk, a sweep failure means drift detection is degraded. Same number, opposite
    // responses. A counter nobody can read is not observability - but neither is one that
    // cannot be acted on.
    s.maint_exceptions =
        journal_maint_exceptions_.load(std::memory_order_relaxed) +
        (spark_drain_worker_ ? spark_drain_worker_->journal_maint_exception_count() : 0);
    s.drain_exceptions = spark_drain_worker_ ? spark_drain_worker_->drain_exception_count() : 0;
    s.sweep_exceptions = spark_scheduler_ ? spark_scheduler_->sweep_exception_count() : 0;
    // #3953 items 1+2: both GuardianOutboxSendExecutor lanes, summed.
    s.send_orphan_exceptions =
        spark_drain_worker_ ? spark_drain_worker_->send_orphan_exception_count() : 0;
    s.send_stalls = spark_drain_worker_ ? spark_drain_worker_->send_stall_count() : 0;
    return s;
}

std::optional<GuardianJournalAgeStats> GuardianEngine::journal_age_stats() const {
    std::lock_guard lock(mtx_);
    // Dormancy is an ABSENCE, not a zero (unlike every counter above, a zero age is a real
    // "fresh" reading). The worker is CONSTRUCTED even at prefer_spark_=false - only start()
    // is gated - so the flag check is load-bearing, not belt-and-braces; the stamp check
    // additionally covers the wired-but-not-yet-started window (stamps seed at start()).
    if (!prefer_spark_ || !spark_drain_worker_)
        return std::nullopt;
    const auto page_ms = spark_drain_worker_->last_page_success_steady_ms();
    const auto prune_ms = spark_drain_worker_->last_prune_success_steady_ms();
    if (page_ms == 0 || prune_ms == 0)
        return std::nullopt;
    // One `now` for every age, so the three readings are mutually consistent within a sample.
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
    const auto age_seconds = [now_ms](std::uint64_t since_ms) -> std::uint64_t {
        if (now_ms <= 0)
            return 0; // implausible steady reading: saturate rather than wrap
        const auto now_u = static_cast<std::uint64_t>(now_ms);
        return now_u > since_ms ? (now_u - since_ms) / 1000 : 0;
    };
    GuardianJournalAgeStats s;
    s.page_stale_seconds = age_seconds(page_ms);
    s.prune_stale_seconds = age_seconds(prune_ms);
    if (lifecycle_journal_)
        s.headroom_blocked_seconds = lifecycle_journal_->headroom_blocked_age_ms(now_ms) / 1000;
    return s;
}

std::size_t GuardianEngine::ack_pending_count_for_test() const {
    std::lock_guard lock(mtx_);
    return ack_ledger_->pending_count_for_test();
}

std::optional<GuardianArmStats> GuardianEngine::arm_stats() const {
    std::lock_guard lock(mtx_);
    // Check A (rung 9c PR-3 KICKOFF-v2, see this accessor's own doc comment in
    // guardian_engine.hpp): begin_application() runs unconditionally in
    // apply_rules() regardless of prefer_spark_, so ack_ledger_->arm_stats() alone
    // cannot distinguish "spark dormant" from "spark live, currently clean" - a
    // legacy agent has a live, empty Application on every push. Gate on all three
    // engine-level dormancy conditions explicitly (governance fix, adversarial
    // review CODEX-1/K1: `prefer_spark_` alone left `stopped_` and
    // `spark_availability_ != Available` - Unwired/SparkFailed/SparkDisabled -
    // emitting a false-present {0,0} pair), mirroring journal_age_stats()'s own
    // dormancy gate immediately above plus reconcile_rule_locked()'s own
    // try_spark condition for the availability check, or a reachable agent state
    // would read as "arming, healthy" while nothing is actually being observed.
    // The ledger's own arm_stats() supplies the fourth, orthogonal "no current
    // application yet" absence case.
    if (!prefer_spark_ || stopped_ || spark_availability_ != SparkAvailability::Available)
        return std::nullopt;
    return ack_ledger_->arm_stats();
}

std::uint64_t GuardianEngine::io_ceiling_rejections() const {
    std::lock_guard lock(mtx_);
    return spark_runtime_ ? spark_runtime_->io_ceiling_rejections() : 0;
}

std::uint64_t GuardianEngine::unhealthy_suppressed() const {
    std::lock_guard lock(mtx_);
    return spark_runtime_ ? spark_runtime_->unhealthy_suppressed() : 0;
}

std::uint64_t GuardianEngine::unhealthy_refreshed() const {
    std::lock_guard lock(mtx_);
    return spark_runtime_ ? spark_runtime_->unhealthy_refreshed() : 0;
}

std::uint64_t GuardianEngine::priority_demoted() const {
    std::lock_guard lock(mtx_);
    return spark_runtime_ ? spark_runtime_->priority_demoted() : 0;
}

std::uint64_t GuardianEngine::outbox_backpressure_drops() const { // #2993
    std::lock_guard lock(mtx_);
    return spark_runtime_ ? spark_runtime_->outbox_backpressure_drops() : 0;
}

std::map<SparkType, std::uint64_t> GuardianEngine::unsupported_counts_by_type() const {
    std::lock_guard lock(mtx_);
    std::map<SparkType, std::uint64_t> out;
    for (const auto& [rule_id, type] : unsupported_rules_)
        ++out[type];
    return out;
}

std::expected<std::size_t, std::string>
GuardianEngine::apply_rules(const gpb::GuaranteedStatePush& push) {
    std::lock_guard lock(mtx_);
    if (stopped_)
        return std::unexpected("guardian engine stopped");
    if (!kv_)
        return std::unexpected("kv store unavailable");

    // #4665: reject the WHOLE push on ANY invalid rule_id, before touching
    // anything else - including the full_sync teardown below AND
    // ack_ledger_->begin_application()'s own bookkeeping mutation further
    // down. A full_sync push that tore down every existing guard, then
    // skipped just the one rule with a bad id while arming the rest, would
    // still advance policy_generation_ to the pushed value - silently
    // dropping that rule's enforcement while reporting the agent as
    // caught-up on the generation. Pure read-only scan over push.rules() -
    // no reconcile_rule_locked call, no guard/spark state touched, and (by
    // running before begin_application()) no ack-ledger application exists
    // yet for this push to disturb, so a PRIOR push's still-pending
    // application is left completely untouched by this push's rejection.
    // Same rationale as the UP-1 comment on begin_application()'s own
    // allocation firewall below: nothing has been reconciled or staged yet
    // at this point, so returning std::unexpected here is a clean,
    // side-effect-free abort - ack_ledger_->latch_failure() is deliberately
    // NOT called (unlike put_rule_locked's failure path further down): it is
    // a no-op with no current application (its own doc comment), and there
    // is no current application until begin_application() runs, below this
    // check.
    for (const auto& rule : push.rules()) {
        if (!is_valid_rule_id(rule.rule_id())) {
            return std::unexpected(
                "rejecting push: rule '" + log_id_token(rule.rule_id()) + "' (name='" +
                log_key_token(rule.name()) + "') has an invalid or missing rule_id");
        }
    }

    // rung 9c PR-2 Unit 6 (§R5.3 duplicate-retry suppression): the server's 25s
    // full_sync heartbeat retry re-sends an identical push while episodes from the
    // PRIOR call are still genuinely pending - without this, every such retry would
    // re-run the full teardown+re-arm below, withdrawing and re-dispatching a claim
    // that was already correctly in flight (a spurious detach_all() per retry; an
    // arm slower than the retry interval would never converge). content_id is
    // computed BEFORE begin_application() below can supersede the application this
    // checks against. guardian_push_content_id() allocates on the unguarded dispatch
    // thread (#2037) - contained; on a throw, an empty id never matches a real one,
    // so this degrades to Reapply (always safe), never a wrongly-suppressed retry.
    // Counted via ack_maint_exceptions_, not arm_failures_ - hashing a push's content
    // is ack-bookkeeping housekeeping, not a rule arm failing (advisor review).
    std::string content_id;
    try {
        content_id = guardian_push_content_id(push);
    } catch (...) {
        content_id.clear();
        ack_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
    }
    if (spark_runtime_ &&
        ack_ledger_->decide_retry(push.policy_generation(), content_id, push.full_sync(),
                                  *spark_runtime_) == GuardianArmAckLedger::RetryDecision::Suppress)
        return ack_ledger_->applied_count();

    // Supersedes whatever the previous push's application still had pending (a stale
    // receipt from a superseded generation can never satisfy this one - see
    // GuardianArmAckLedger's own doc). `applied` is a placeholder here - the real
    // count is not known until the loop below finishes; set_applied() near the
    // bottom of this function corrects it before any later Suppress decision reads
    // applied_count().
    //
    // Governance finding UP-1 (Gate 4, unhappy-path, verified): this allocation
    // (std::make_unique<Application>() inside begin_application()) sat immediately
    // after the ONE call this preamble already firewalls (guardian_push_content_id(),
    // #2037) with no firewall of its own - a bad_alloc here would have escaped onto
    // the unfirewalled dispatch thread before GuardianRollback's own scope guard is
    // even declared below. Nothing has been reconciled or staged yet at this point,
    // so returning std::unexpected is a clean, side-effect-free abort of this push.
    try {
        ack_ledger_->begin_application(push.policy_generation(), content_id, push.full_sync(),
                                       /*applied=*/0);
    } catch (const std::exception& e) {
        ack_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
        return std::unexpected(std::string("failed to begin ack application: ") + e.what());
    } catch (...) {
        ack_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
        return std::unexpected("failed to begin ack application: unknown exception");
    }

    // Flush staged lifecycle records to the durable journal on EVERY exit - the normal
    // return, the put_rule early return below, and any un-firewalled throw. GuardianRollback
    // is the codebase's terminate-safe scope guard; left un-committed it becomes an
    // always-fire flush whose dtor swallows a persist-during-unwind throw (records stay
    // pending for the C3 maintenance-tick retry) rather than std::terminate. Declared after
    // the lock so it fires with mtx_ STILL held (reverse-order destruction).
    GuardianRollback journal_flush;
    // Firewall + COUNT a persist-during-unwind throw (review UP-6): GuardianRollback's dtor is
    // terminate-safe and swallows it, but a swallowed-yet-uncounted flush failure is an invisible
    // audit-durability gap. Match the B4a maintenance-tick posture: catch here and count it.
    journal_flush.fn = [this] {
        try {
            persist_lifecycle_journal_locked(kJournalPersistUnbounded,
                                             kJournalPersistUnbounded);
        } catch (...) {
            journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
        }
    };

    std::size_t applied = 0;
    std::size_t reconcile_failures = 0;
    // rung 9c PR-2 Unit 6 (R5.3): rules ACCEPTED this push whose arm has not yet
    // resolved - a diagnostic count only (the "pending" field in the log line
    // below); the actual generation-hold gate reads ack_ledger_->can_advance(),
    // never this counter (arm_failures_/reconcile_failures stay a genuine-failure
    // signal only, unaffected by Accepted).
    std::size_t pending_arms = 0;
    // F7: rule_ids seen in a full_sync push, for the unsupported_rules_ sweep below.
    // guards_/spark_runtime_ don't need this - they're unconditionally torn down and
    // rebuilt fresh by stop_all_guards_locked()/detach_all() + the loop below.
    // unsupported_rules_ is passive bookkeeping, not a live resource, so it is
    // deliberately NOT blanket-cleared the same way (see the comment further down) -
    // it needs this set instead.
    std::set<std::string> full_sync_ids;
    if (push.full_sync()) {
        // #4021: NEVER kv_->clear(kKvNamespace) here — a blanket clear would also
        // wipe every kBaselinePrefix baseline record, reintroducing exactly the
        // silent-relaunder bug this file's baseline persistence exists to close (a
        // rule's captured "known good" state must survive a full_sync). Scoped to
        // kRulePrefix keys only — the ONLY other keys ever written under this
        // namespace are kKeyGen (rewritten unconditionally just below regardless)
        // and kBaselinePrefix records (deliberately untouched by full_sync — see
        // guardian_seed_baseline's doc for why absence-from-a-push must not sweep
        // a baseline either).
        // Gate 4 governance BLOCKING-class finding (unhappy-path UP-1): `list()`'s
        // bare `while (step()==SQLITE_ROW)` loop cannot distinguish end-of-rows
        // from a mid-scan I/O error (kv_store.cpp's own comment on `list_entries`
        // names this exact gap) - the OLD full_sync teardown used a single atomic
        // `clear()` DELETE statement, which has no partial-failure mode at all, so
        // switching to list()+del_keys() for the #4021 baseline-preserving scoped
        // sweep introduced a genuinely NEW one: a mid-scan error would silently
        // return a TRUNCATED key list, and the (fully transactional) del_keys()
        // would then "successfully" delete only that truncated subset - some
        // rule: keys gone, others surviving, with the cleared-count log line
        // reporting it as an ordinary success. A surviving stale rule: key is
        // re-armed by start_local()'s restart re-arm loop even after the server
        // removed it from policy, silently re-enforcing on next restart - a
        // genuine compliance-evidence integrity gap for a product whose whole
        // point is Guaranteed State. Use the fallible list_entries() (which DOES
        // check the post-loop rc) instead, and on a genuine read failure, hold
        // the generation for retry and skip the sweep entirely THIS pass rather
        // than risk a partial delete - stale rule: keys lingering one extra cycle
        // is safe; a truncated delete masquerading as success is not.
        auto rule_key_rows = kv_->list_entries(kKvNamespace, kRulePrefix);
        if (!rule_key_rows) {
            ++reconcile_failures;
            arm_failures_.fetch_add(1, std::memory_order_relaxed);
            spdlog::error("Guardian: full_sync rule-key sweep failed ({}) - holding "
                         "policy_generation for retry rather than risk a partial delete",
                         rule_key_rows.error().message);
        } else {
            std::vector<std::string> rule_keys;
            rule_keys.reserve(rule_key_rows->size());
            // #4665 governance-external-review finding (fjarvis, PR #4979): a rule_id
            // that predates #4665's create-time charset/length enforcement can still
            // sit in KV, and guardian_push_builder.cpp's server-side filter now
            // excludes such a row from EVERY push it builds -- so it can never again
            // appear in push.rules() to be re-persisted below. This IS a hard cutover,
            // by deliberate operator decision (not a migration): the row is cleared
            // here like any other, and its guard is torn down two blocks below like
            // every other guard, with no attempt to preserve or re-arm it. Counted
            // and logged SEPARATELY, at WARN, specifically because it is real,
            // irreversible loss of a previously-enforcing control, not routine
            // teardown-and-rebuild noise -- docs/user-manual/upgrading.md's pre-upgrade
            // detection query exists precisely so an operator finds and fixes these
            // BEFORE hitting this line for real. See that doc for the operational
            // contract; do not reintroduce a "frozen"/preserved code path here.
            std::size_t non_conforming = 0;
            for (auto& row : *rule_key_rows) {
                const std::string_view key_view = row.key;
                const std::string_view rid = key_view.size() > kRulePrefix.size()
                                                  ? key_view.substr(kRulePrefix.size())
                                                  : std::string_view{};
                if (!is_valid_rule_id(rid))
                    ++non_conforming;
                rule_keys.push_back(std::move(row.key));
            }
            if (non_conforming > 0)
                spdlog::warn("Guardian: full_sync is disarming {} rule(s) with a rule_id "
                             "outside the [A-Za-z0-9._-]+/256-byte charset (#4665) -- "
                             "hard cutover, not preserved; see docs/user-manual/"
                             "upgrading.md for the pre-upgrade detection query",
                             non_conforming);
            if (!rule_keys.empty()) {
                const int cleared = kv_->del_keys(kKvNamespace, rule_keys);
                if (static_cast<std::size_t>(cleared) == rule_keys.size()) {
                    spdlog::info("Guardian: full_sync cleared {} prior rule(s)", cleared);
                } else {
                    // del_keys() is transactional (all-or-nothing) but returns 0 on
                    // EITHER a genuine BEGIN/step/COMMIT failure OR (defensively) a
                    // prepare failure - indistinguishable from here, and it does not
                    // throw. Gate 5 CH-1 (#4021 follow-up): treat any undercount as
                    // suspect and hold the generation for retry, mirroring the
                    // list_entries() failure branch immediately above - a stale
                    // rule: key lingering one extra cycle is safe, a failed delete
                    // silently reported as ordinary success is not.
                    ++reconcile_failures;
                    arm_failures_.fetch_add(1, std::memory_order_relaxed);
                    spdlog::error("Guardian: full_sync del_keys cleared {}/{} rule(s) - "
                                 "holding policy_generation for retry rather than trust a "
                                 "failed delete",
                                 cleared, rule_keys.size());
                }
            }
        }
        // Re-persist the policy generation marker (rewritten unconditionally here,
        // same as before this change — harmless whether or not the key survived).
        // Deliberately NOT given the publish-after-persist treatment the other two
        // call sites got (rung 9c PR-2 Unit 6 gate, coordinator finding): this site
        // does not GATE an advance decision - policy_generation_ is already whatever
        // it was, unchanged by this call either way - it only re-affirms the CURRENT
        // value defensively after a full_sync KV clear. A failed write here just
        // means the durable marker can lag the in-memory value for one more cycle,
        // never a wrong "caught up" signal to the server; out of scope for this fix.
        (void)persist_generation_locked(policy_generation_);
        // Full sync replaces the active set - tear down BOTH backends before
        // re-arming (rung 7: a spark-attached rule the new push omits must be
        // withdrawn too, not left dangling - Sol's rev-2 review). FIREWALLED like the
        // per-rule reconcile below: stop_all_guards_locked/detach_all allocate (lifecycle
        // enqueue, disarm, Key strings), and a bad_alloc here would otherwise escape
        // apply_rules onto the un-firewalled dispatch/run() thread and abort the whole
        // agent - the same #2037 class the per-rule firewall closes, on the full_sync
        // path (Gate 4 UP-1/UP-14). Count + hold the generation so the server retries,
        // then proceed to re-arm what we can.
        try {
            stop_all_guards_locked();
            if (spark_runtime_)
                spark_runtime_->detach_all();
            // F7: deliberately NOT unsupported_rules_.clear() here - that would make
            // every rule the loop below re-classifies Unsupported look "newly"
            // unsupported (the per-outcome erase/insert in reconcile_rule_locked can't
            // detect "already tracked" against an emptied map), spamming the
            // edge-triggered log on every full_sync. Swept precisely, after the loop,
            // against full_sync_ids instead.
        } catch (...) {
            ++reconcile_failures;
            arm_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::error("Guardian: full_sync teardown threw - partial teardown, "
                              "holding generation for retry");
            } catch (...) {
            }
        }
    }

    for (const auto& rule : push.rules()) {
        // #4665: an empty rule_id is one shape of an invalid rule_id, already
        // rejected for the WHOLE push by the pre-validation scan at the top of
        // this function (is_valid_rule_id() returns false on empty) - every
        // rule reaching this loop already has a non-empty, charset-valid id,
        // so the per-rule skip-and-continue this comment used to sit above is
        // unreachable and has been removed rather than kept as dead defensive
        // code.
        if (push.full_sync())
            full_sync_ids.insert(rule.rule_id()); // F7
        if (!put_rule_locked(rule)) {
            // This return skips the reconcile_failures > 0 latch below entirely -
            // latch explicitly, so a later heartbeat tick can never advance this
            // generation past a partially-applied push (§R5.3).
            ack_ledger_->latch_failure();
            return std::unexpected("failed to persist rule '" + rule.rule_id() + "'");
        }
        // Per-rule exception firewall: reconcile can throw (a spark attach OOM, a
        // backend arm that throws) and must NOT abort the whole push and escape to the
        // dispatch caller - an escaped exception on the unguarded ThreadPool task aborts
        // the whole agent (#2037). Degrade loud and continue - the posture start_local()
        // takes for a thread-exhaustion throw. catch(...) not just std::exception, and
        // the log is guarded (spdlog allocates and could itself throw under the bad_alloc
        // that triggered this). (rung 7.7b PR-1 item 3 / Sol B1 + Fable.)
        ReconcileOutcome outcome = ReconcileOutcome::Inert;
        try {
            outcome = reconcile_rule_locked(rule); // step 4: arm/withdraw (rung 7)
        } catch (...) {
            ++reconcile_failures;
            arm_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::error("Guardian: reconcile threw for rule '{}' - persisted but not armed",
                              log_id_token(rule.rule_id()));
            } catch (...) {
            }
            continue; // not counted as applied
        }
        // #2233 item 3: a genuine arm ATTEMPT that did not succeed (see
        // ReconcileOutcome's doc) must count the same as a throw here - both mean
        // this rule did not end up armed this push, and the policy_generation
        // hold-on-failure gate below must see it. Inert outcomes (disabled,
        // Unsupported, agent-wide SparkFailed/Unwired, ...) are NOT failures and
        // must not gate generation advancement - unchanged from before this fix.
        if (outcome == ReconcileOutcome::Failed) {
            ++reconcile_failures;
            arm_failures_.fetch_add(1, std::memory_order_relaxed);
            continue; // not counted as applied - reconcile_rule_locked already logged why
        }
        // rung 9c PR-2 Unit 6 (§R5.3): Accepted is not a failure - the rule was
        // eligible and its arm attempt was accepted (dispatched, queued behind an
        // in-flight/retained claim on the same key (R5.2), or - rung 9c PR-5c
        // (#4221 up-2) - re-observing an already-Wedged head via an identical
        // same-rule_id/same-spec retry, which constructs no new claim at all) - so
        // it is counted as applied exactly like Armed/Inert, never added to
        // reconcile_failures/arm_failures_. reconcile_rule_locked() already
        // registered the receipt with ack_ledger_ for THIS application (this
        // application was begun before this loop started) - including for a
        // re-observed retry, whose receipt is registered fresh by THIS call, not
        // inherited from whatever application the original attach ran under (see
        // the add_pending() call site's own doc comment below, ~:1940); the
        // generation-hold gate below now reads ack_ledger_->can_advance(), not this
        // counter - pending_arms is kept only for the diagnostic log line.
        if (outcome == ReconcileOutcome::Accepted)
            ++pending_arms;
        ++applied;
    }

    if (push.full_sync()) {
        // F7: a rule_id that was Unsupported before this full_sync but is absent from
        // the new push is no longer part of the active rule set at all (kv_ was
        // cleared above; only push.rules() gets re-persisted) - forget it, or it
        // reports a phantom count forever. Rule_ids retained in the new push were
        // already updated in place by the loop above (erase-if-not-Unsupported /
        // insert-if-Unsupported inside reconcile_rule_locked), so this only removes
        // what's genuinely gone. Deliberately unreached if the loop above returned
        // early via the put_rule_locked failure path above - the whole push is
        // mid-rebuild on that path (generation held, existing pre-F7 behavior), and
        // the next successful push's sweep heals it; not a new gap F7 introduces.
        for (auto it = unsupported_rules_.begin(); it != unsupported_rules_.end();) {
            if (!full_sync_ids.count(it->first))
                it = unsupported_rules_.erase(it);
            else
                ++it;
        }
    }

    // rung 9c PR-2 Unit 6: a reconcile_failures increment anywhere above (the full_sync
    // teardown block's own kv-sweep/del_keys/teardown-throw sites, or a per-rule
    // ReconcileOutcome::Failed/throw in the loop just above) must survive past THIS
    // function's own return, because it is a local variable that does not - a later
    // heartbeat tick only ever consults ack_ledger_->can_advance(), which would
    // otherwise see nothing latched and no resolved_failed once every accepted rule's
    // arm eventually commits, and wrongly advance a generation that had a genuine
    // failure this call.
    if (reconcile_failures > 0)
        ack_ledger_->latch_failure();
    ack_ledger_->set_applied(applied);

    // Do NOT advance the policy generation when any rule failed to arm. The server's
    // heartbeat reconcile fn re-pushes only while the agent reports a generation BEHIND
    // current (server.cpp), so advancing here would tell the server "caught up" and
    // strand the unarmed rule until restart - a silent enforcement hole on a
    // Guaranteed-State product. Holding the generation keeps the 25s heartbeat retry
    // live so a transient OOM/thread-exhaustion self-heals. (Sol B1 / Fable.) A later
    // successful push can still advance past a persistently-failing rule; arm_failures_
    // (surfaced via the heartbeat, item 9) is the durable fleet-visible signal for that.
    // rung 9c PR-2 Unit 6: ack_ledger_->can_advance() replaces the old pending_arms == 0
    // check - true for the ordinary case (nothing Accepted this push, matching today's
    // behavior exactly) and false whenever an accepted arm is still genuinely pending
    // OR has resolved to anything but Committed OR this call latched a failure above
    // (R5.3: "the policy generation advances ... only once every rule accepted under it
    // has ... armed ... never on acceptance alone"). If something IS still pending,
    // this call does not advance the generation at all - journal_maintenance_tick()'s
    // own drain does, once it resolves.
    // Persist BEFORE publishing (coordinator finding, rung 9c PR-2 Unit 6 gate - this
    // call site has the identical shape as journal_maintenance_tick()'s own, fixed
    // alongside it): a failed or throwing persist leaves policy_generation_ at its
    // prior value, so the same condition is still true on a repeat push, retrying
    // naturally - "naturally" depends on decide_retry() above never Suppressing a
    // repeat push while nothing is genuinely pending (governance finding
    // sec-1/arch-1, fixed in GuardianArmAckLedger::decide_retry() this same round:
    // an empty `pending` map used to reach a vacuous Suppress and this gate was
    // never reached again at all on a repeat push). NOTE the asymmetry with
    // journal_maintenance_tick()'s own retry (Gate 8, sre): that path is gated
    // `if (stopped_ || !prefer_spark_) return;` and therefore does NOT retry at
    // today's production default - a repeat PUSH is the only live recovery lane
    // at prefer_spark_=false, not a heartbeat tick. Do not conflate the two in a
    // future edit here or in the log line below.
    if (reconcile_failures == 0 && ack_ledger_->can_advance() &&
        push.policy_generation() > policy_generation_) {
        if (persist_generation_locked(push.policy_generation()))
            policy_generation_ = push.policy_generation();
        else
            // Governance finding (Gate 6, sre + compliance-officer): previously
            // silent on failure. See journal_maintenance_tick()'s identical warn
            // for the matching drain-triggered gate.
            spdlog::warn("Guardian: failed to persist policy_generation={} (kv write "
                         "returned false) - held at {}, retried on the server's next "
                         "identical repeat push",
                         push.policy_generation(), policy_generation_);
    }

    refresh_count_locked();
    spdlog::info(
        "Guardian: apply_rules ok (applied={}, failed={}, pending={}, full_sync={}, generation={}, "
        "total={})",
        applied, reconcile_failures, pending_arms, push.full_sync(), policy_generation_, rule_count_);
    return applied;
}

gpb::GuaranteedStateStatus GuardianEngine::get_status() const {
    std::lock_guard lock(mtx_);
    gpb::GuaranteedStateStatus status;
    status.set_agent_id(agent_id_);
    status.set_policy_generation(policy_generation_);
    status.set_total_rules(static_cast<std::uint32_t>(rule_count_));

    // Fail-closed status. An armed guard does NOT prove the watched value is
    // currently compliant, nor that the worker is healthy: the thread may have
    // exited after start() returned, an enforce write may be failing, or the
    // guard may have silently fallen back to read-only. `guard_healthy` is a
    // RESERVED wire field whose safe default is "unknown" (false). So until a
    // real self-test / last-remediation signal exists (deferred — see the richer
    // status-taxonomy follow-up), every rule is reported conservatively: not
    // compliant, not healthy. Under-reporting here is fail-closed; the prior
    // "armed ⇒ compliant/healthy" was the silently-deaf failure class.
    status.set_compliant_rules(0);
    status.set_drifted_rules(0);
    status.set_errored_rules(static_cast<std::uint32_t>(rule_count_));

#if defined(_WIN32)
    status.set_platform("windows");
#elif defined(__APPLE__)
    status.set_platform("macos");
#else
    status.set_platform("linux");
#endif

    if (kv_) {
        for (const auto& key : kv_->list(kKvNamespace, kRulePrefix)) {
            auto raw = kv_->get(kKvNamespace, key);
            if (!raw) continue;
            gpb::GuaranteedStateRule rule;
            try {
                auto parsed = nlohmann::json::parse(*raw);
                if (!json_to_rule(parsed, rule))
                    continue;
            } catch (const nlohmann::json::exception&) {
                continue;
            }
            auto* row = status.add_rules();
            row->set_rule_id(rule.rule_id());
            row->set_status("errored");
            row->set_guard_category("event");
            row->set_guard_healthy(false);
            row->set_notifications_total(0);
        }
    }
    return status;
}

GuardianDispatchResult GuardianEngine::dispatch(const apb::CommandRequest& cmd) {
    GuardianDispatchResult res;

    if (cmd.action() == kActionPushRules) {
        // The serialized GuaranteedStatePush rides in the `payload` bytes field, not
        // the `parameters` string map: proto3 string-map values must be valid UTF-8,
        // and raw proto bytes are not (the server's UTF-8 validator rejects the whole
        // CommandRequest before it reaches us). `bytes` is binary-safe across embedded
        // NUL bytes. The Erlang gateway preserves `payload` end-to-end: field 8 is
        // mirrored into its vendored agent.proto and it forwards the decoded request
        // straight through gpb (proven by yuzu_gw_guardian_wire_tests). Works in both
        // direct and gateway mode. See agent.proto CommandRequest.payload + G12.
        const std::string& push_bytes = cmd.payload();
        if (push_bytes.empty()) {
            res.exit_code = 1;
            res.content_type = "text";
            res.output = "missing payload (expected serialized GuaranteedStatePush)";
            return res;
        }
        gpb::GuaranteedStatePush push;
        if (!push.ParseFromString(push_bytes)) {
            res.exit_code = 2;
            res.content_type = "text";
            res.output = "failed to parse GuaranteedStatePush proto";
            return res;
        }
        auto applied = apply_rules(push);
        if (!applied) {
            res.exit_code = 3;
            res.content_type = "text";
            res.output = applied.error();
            return res;
        }
        res.exit_code = 0;
        res.content_type = "text";
        res.output = "applied=" + std::to_string(*applied) +
                     " generation=" + std::to_string(policy_generation()) +
                     " total=" + std::to_string(rule_count());
        return res;
    }

    if (cmd.action() == kActionGetStatus) {
        auto status = get_status();
        res.exit_code = 0;
        res.content_type = "proto";
        res.output = status.SerializeAsString();
        return res;
    }

    res.exit_code = 4;
    res.content_type = "text";
    res.output = "unknown __guard__ action: " + cmd.action();
    return res;
}

std::size_t GuardianEngine::rule_count() const {
    std::lock_guard lock(mtx_);
    return rule_count_;
}

std::size_t GuardianEngine::armed_guard_count() const {
    std::lock_guard lock(mtx_);
    return guards_.size();
}

std::size_t GuardianEngine::spark_armed_rule_count() const {
    std::lock_guard lock(mtx_);
    return spark_runtime_ ? spark_runtime_->rule_count() : 0;
}

std::string GuardianEngine::last_rearm_degrade_message_for_test() const {
    std::lock_guard lock(mtx_);
    return last_rearm_degrade_message_for_test_;
}

GuardianEngine::UnsupportedLogRecord GuardianEngine::last_unsupported_log_for_test() const {
    std::lock_guard lock(mtx_);
    return last_unsupported_log_for_test_;
}

std::string GuardianEngine::last_file_expected_hash_for_test() const {
    std::lock_guard lock(mtx_);
    return last_file_expected_hash_for_test_;
}

bool GuardianEngine::last_file_on_baseline_wired_for_test() const {
    std::lock_guard lock(mtx_);
    return last_file_on_baseline_wired_for_test_;
}

std::uint64_t GuardianEngine::policy_generation() const {
    std::lock_guard lock(mtx_);
    return policy_generation_;
}

bool GuardianEngine::put_rule_locked(const gpb::GuaranteedStateRule& rule) {
    if (!kv_) return false;
    auto j = rule_to_json(rule).dump();
    return kv_->set(kKvNamespace, make_rule_key(rule.rule_id()), j);
}

void GuardianEngine::refresh_count_locked() {
    if (!kv_) {
        rule_count_ = 0;
        return;
    }
    rule_count_ = kv_->list(kKvNamespace, kRulePrefix).size();
}

bool GuardianEngine::persist_generation_locked(std::uint64_t gen) {
    if (!kv_) return false;
    return kv_->set(kKvNamespace, kKeyGen, std::to_string(gen));
}

void GuardianEngine::set_event_sink(EventSink sink) {
    std::lock_guard lock(sink_mtx_);
    event_sink_ = std::move(sink);
}

void GuardianEngine::emit_guard_event(
    const GuardDrift& d, bool is_gap_repair,
    std::optional<std::chrono::system_clock::time_point> timestamp_override,
    std::optional<std::uint64_t> expected_gap_lost_seq) {
    // Snapshot the sink under sink_mtx_, then release BEFORE handing off to
    // legacy_sink_executor_ (#4783) — never hold the lock any longer than needed,
    // and never take mtx_ here (a guard worker can fire while apply_rules/stop hold
    // mtx_ and join this thread).
    EventSink sink;
    {
        std::lock_guard lock(sink_mtx_);
        sink = event_sink_;
    }
    if (!sink) {
        // sink not wired yet (pre-network arm) — drop; durable buffering is A3.
        // #4783: now COUNTED (previously a silent return) so "never wired" is
        // distinguishable from "wired and delivered/lost".
        ++legacy_sink_dropped_unwired_;
        return;
    }

    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    const auto seq = event_seq_.fetch_add(1, std::memory_order_relaxed);
    gpb::GuaranteedStateEvent ev;
    // event_id folds in agent_id_ because the server's events table keys on a
    // GLOBAL `event_id` PRIMARY KEY and drops on UNIQUE conflict (#1307). Without
    // agent_id, two agents drifting on the same rule in the same millisecond mint
    // an identical id (rule_id-{ms}-{seq}, seq being a per-agent counter that both
    // start at 0) → the server silently keeps one and loses the rest during a
    // fleet-wide drift wave. For any non-empty agent_id the agent_id segment
    // guarantees cross-agent distinctness regardless of clock skew; a degenerate
    // empty agent_id (pre-Register, before sync_with_server populates it) folds
    // in nothing and reverts to the old per-(rule,ms,seq) collision class — the
    // durable fix for that residual is the server-side composite key #1360. (The
    // crash/observation path landing with the DEX slice uses the same
    // {discriminator}-{agent_id}-{ms}-{seq} layout — keep them aligned.)
    ev.set_event_id(d.rule_id + "-" + agent_id_ + "-" + std::to_string(now_ms) + "-" +
                    std::to_string(seq));
    ev.set_rule_id(d.rule_id);
    ev.set_guard_category("event");
    if (d.health != GuardDrift::Health::None) {
        // Health arm: never through apply_drift_to_event — its default arm would mint
        // drift.detected from a report that carries no verdict, and every compliance
        // field on a health report is ignored outright (guard.hpp's doc comment).
        // Shape pinned byte-for-byte to guardian_spark_send.cpp's Health/!healthy case
        // (#2237) so the two wire producers cannot drift apart; extracting a shared
        // apply_health_to_event() helper is tracked as #4782, not done here, because
        // test_guardian_spark_send.cpp pins that serializer's exact literal output and
        // a shared-helper refactor was out of scope for this fix. No coupling test
        // exists between the two copies today (dormant risk while prefer_spark_
        // defaults false) — #4782 is exactly that gap.
        ev.set_guard_type(d.guard_type);
        ev.set_rule_name(d.rule_name);
        ev.set_event_type("guard.unhealthy");
        if (!d.health_detail.empty()) {
            nlohmann::json j;
            j["detail"] = d.health_detail;
            ev.set_detail_json(j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
        }
    } else {
        // rule_name / guard_type / detected_value / expected_value / detection_latency_us,
        // the 4-way event_type cascade (+ remediation fields) and drift_rate are shared
        // byte-for-byte with the spark consumer's Compliance branch — set them from the
        // single apply_drift_to_event source of truth so the two producers cannot drift
        // apart (#2237 item 1). event_id, rule_id, guard_category, timestamp and platform
        // stay stamped here (idempotency- and host-specific).
        apply_drift_to_event(d, ev);
    }
    // #4783 follow-up review, part (c): the wire `timestamp` field is stamped
    // from `timestamp_override` when the caller supplied one (ONLY
    // legacy_sink_kick(), with the gap's `last_lost` — see this function's own
    // doc comment in guardian_engine.hpp) rather than from `now_ms` above -
    // `event_id` keeps using `now_ms` regardless, so this touches ONLY the
    // event's timestamp, not its identity.
    const auto timestamp_secs = timestamp_override.has_value()
                                    ? std::chrono::duration_cast<std::chrono::seconds>(
                                          timestamp_override->time_since_epoch())
                                          .count()
                                    : now_ms / 1000;
    ev.mutable_timestamp()->set_seconds(timestamp_secs);
    // Stamp the agent's real platform (mirrors get_status) — not a hardcoded
    // "windows", which would mislabel every drift event once Linux/macOS guards land.
#if defined(_WIN32)
    ev.set_platform("windows");
#elif defined(__APPLE__)
    ev.set_platform("macos");
#else
    ev.set_platform("linux");
#endif
    // #4783: enqueue-only from here — offer() itself never blocks on network I/O and
    // never throws (an escaping exception from THIS specific call would end the
    // calling guard's detection loop permanently, see guard_file.cpp's outer catch);
    // everything ABOVE this line keeps whatever throw surface it already had.
    // Delivery, loss accounting and the sticky per-rule integrity gap are
    // legacy_sink_executor_'s job from here — see guardian_legacy_sink_executor.hpp.
    // `is_gap_repair` (#4783 commit 4) threads straight through: only
    // legacy_sink_kick() ever passes true, for a synthesized guard.unhealthy
    // report rebuilding an existing gap — see that method's own doc comment.
    // `expected_gap_lost_seq` (adversarial-review finding, 2026-09-24) also
    // threads straight through — see offer()'s own doc comment and the class
    // doc comment's ADMISSION-TIME EPISODE BINDING section.
    (void)legacy_sink_executor_->offer(std::move(ev), std::move(sink), is_gap_repair,
                                       expected_gap_lost_seq);
}

void GuardianEngine::legacy_sink_kick() noexcept {
    // #4783 commit 4: deliberately NOT gated on prefer_spark_ (unlike
    // journal_maintenance_tick() above, whose gate is specific to the spark-runtime
    // maintenance passes it drives) and deliberately NOT under mtx_ — see this
    // method's own doc comment in guardian_engine.hpp for the full rationale.
    // kick()/gapped_rules_needing_repair() take only the executor's own internal
    // lock; emit_guard_event() below takes only sink_mtx_ then that same executor
    // lock, exactly like a real guard's own emission path — never mtx_, so this
    // cannot contend with (or deadlock against) apply_rules()/stop().
    try {
        legacy_sink_executor_->kick();
        const auto gaps =
            legacy_sink_executor_->gapped_rules_needing_repair(kMaxGapRepairsPerKick);
        for (const auto& [rule_id, gap] : gaps) {
            if (gap.repair_seq != 0)
                continue;
            GuardDrift d;
            d.guard_type = gap.guard_type;
            d.rule_id = rule_id;
            d.rule_name = gap.rule_name;
            d.health = GuardDrift::Health::Unhealthy;
            d.health_detail = kLegacySinkDeliveryGapDetail;
            // #4783 follow-up review, part (c): stamp the repair with the gap's
            // OWN last_lost, not this kick's wall-clock now — see
            // emit_guard_event()'s doc comment in guardian_engine.hpp for why.
            // Adversarial-review finding, 2026-09-24: also pass the gap's OWN
            // lost_seq (captured in this SAME gapped_rules_needing_repair() call,
            // above) as expected_gap_lost_seq — see that doc comment and
            // guardian_legacy_sink_executor.hpp's ADMISSION-TIME EPISODE BINDING
            // section for why offer() must re-validate this repair still
            // describes the loss episode captured here, not whatever gap is live
            // by the time this call actually reaches offer().
            emit_guard_event(d, /*is_gap_repair=*/true, gap.last_lost, gap.lost_seq);
        }
    } catch (...) {
        // Firewalled: runs on the bare heartbeat thread (agent.cpp) - same posture
        // as journal_maintenance_tick()'s own try/catch (review B4a). A throw here
        // must never escalate to std::terminate.
    }

    // #4783 Gate 4 UP-3/UP-4: persist the loss ledger if it changed since the
    // last write - own try/catch, deliberately AFTER (and independent of) the
    // repair-dispatch loop above, so a KV write failure here can never prevent
    // (or be masked by) the gap-repair work. kv_ is a raw pointer set once at
    // construction and never reassigned (same rationale
    // guardian_persist_baseline's own doc comment gives for reading it off
    // mtx_ from a non-engine thread) - safe to read here without mtx_, which
    // this method deliberately never takes (see its own doc comment).
    //
    // #4783 Gate 8 re-review: snapshot + the change_gen decision + persist +
    // record-gen all run under legacy_sink_persist_mu_ for their ENTIRE span
    // (lock_guard taken INSIDE the try - std::mutex::lock() can throw, and
    // this whole method is noexcept), the same lock stop()'s own final
    // persist takes for its entire span - so the two call sites can never
    // interleave a stale snapshot from one against a fresher write from the
    // other. This lock is scoped ONLY to this orchestration, never anything
    // guard-thread-reachable, so it adds no new blocking dependency for a
    // guard thread's own reporting or an apply_rules reconcile - see
    // legacy_sink_persist_mu_'s own doc comment for the full race this closes
    // and why it is deliberately not mtx_.
    if (kv_) {
        try {
            std::lock_guard<std::mutex> persist_lk(legacy_sink_persist_mu_);
            const auto snap = legacy_sink_executor_->snapshot();
            if (snap.change_gen != legacy_sink_last_persisted_gen_) {
                // TEST-ONLY (#4783 Gate 8 re-review): fires here, with the lock
                // above already held, after the decision to write but before
                // the write itself - see legacy_sink_persist_race_hook_for_test_'s
                // own doc comment for the exact race this reproduces.
                if (legacy_sink_persist_race_hook_for_test_)
                    legacy_sink_persist_race_hook_for_test_();
                if (persist_legacy_sink_loss_ledger(kv_, snap)) {
                    legacy_sink_last_persisted_gen_ = snap.change_gen;
                } else {
                    spdlog::warn("Guardian: failed to persist the legacy-sink loss ledger "
                                "(change_gen={}) - will retry on the next heartbeat kick",
                                snap.change_gen);
                }
            }
        } catch (...) {
            // Same firewall posture as the repair-dispatch try/catch above.
        }
    }
}

std::uint64_t GuardianEngine::legacy_sink_events_lost() const {
    // No mtx_: legacy_sink_executor_ is set once at construction (never reset in
    // production - set_legacy_sink_max_events_for_test() is test-only and runs
    // strictly before start_local()) and guards this counter with its own internal
    // lock, same no-mtx_ rationale as legacy_sink_executor_for_test() above.
    return legacy_sink_executor_->stats().events_lost;
}

std::uint64_t GuardianEngine::legacy_sink_gap_rules() const {
    return static_cast<std::uint64_t>(legacy_sink_executor_->stats().gap_rules);
}

std::uint64_t GuardianEngine::legacy_sink_dropped_unwired() const {
    // No mtx_: legacy_sink_dropped_unwired_ is a plain atomic member, incremented
    // directly by emit_guard_event() with no lock - same no-mtx_ rationale as
    // legacy_sink_events_lost() above, one step simpler since there is no executor
    // indirection to cross here.
    return legacy_sink_dropped_unwired_.load();
}

void GuardianEngine::set_legacy_sink_max_events_for_test(std::size_t max_events) {
    assert(!started_ &&
           "set_legacy_sink_max_events_for_test: must be called before start_local()");
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = max_events;
    legacy_sink_executor_ = std::make_unique<GuardianLegacySinkExecutor>(cfg);
}

// #4783 TEST-ONLY seams (see guardian_engine.hpp's own doc comments). None of these
// take mtx_: legacy_sink_executor_ is set once at construction and never reset in
// production (set_legacy_sink_max_events_for_test() above is the one exception, and
// it is itself test-only, asserted to run before start_local()), and every method
// they delegate to is the executor's OWN thread-safe surface — no GuardianEngine-
// owned state is touched, so there is nothing here for mtx_ to guard.
GuardianLegacySinkExecutor& GuardianEngine::legacy_sink_executor_for_test() const {
    return *legacy_sink_executor_;
}

bool GuardianEngine::flush_legacy_sink_for_test(std::chrono::milliseconds timeout) const {
    return legacy_sink_executor_->wait_idle_for_test(timeout);
}

bool GuardianEngine::retire_legacy_sink_workers_for_test(std::chrono::milliseconds timeout) const {
    return legacy_sink_executor_->wait_workers_retired_for_test(timeout);
}

void GuardianEngine::stop_all_guards_locked() {
    for (auto& kv : guards_)
        if (kv.second) kv.second->stop();
    guards_.clear();
}

void GuardianEngine::withdraw_legacy_guard_locked(const std::string& rule_id) {
    if (auto it = guards_.find(rule_id); it != guards_.end()) {
        if (it->second)
            it->second->stop();
        guards_.erase(it);
    }
}

bool GuardianEngine::start_guard_for_rule_locked(const gpb::GuaranteedStateRule& rule) {
    // Spark dispatch. Each Spark type maps to a guard implementation, all no-op off
    // Windows for the MVP. Returns true iff a guard was actually armed (so callers
    // can count accurately).

    // Retire any guard already armed for this rule_id BEFORE validating/arming the
    // new definition below. Each branch used to do this find-stop-erase only on its
    // happy path, AFTER the type/assertion checks - so a same-id re-push whose new
    // assertion failed validation (an unsupported type, an unrecognized spark type)
    // returned false early and left the PRIOR guard running, silently enforcing a
    // stale definition the caller believes was replaced (apply_rules persists the
    // new rule to KV regardless of whether it arms). Hoisting this here means every
    // return path - early-invalid, late-failed-start, or success - starts from a
    // clean slate, so an unarmed/errored outcome is genuinely unarmed.
    withdraw_legacy_guard_locked(rule.rule_id());

    // ── file-change Spark (Change B) — realtime file watch via FileGuard ──────
    if (rule.spark().type() == "file-change") {
        const auto& fa = rule.assertion();
        const std::string atype = fa.type();
        if (atype != "file-exists" && atype != "file-hash-equals")
            return false; // unknown assertion stays unarmed (G11: errored upstream)
        auto aparam = [&fa](const char* k) -> std::string {
            auto it = fa.params().find(k);
            return it != fa.params().end() ? it->second : std::string{};
        };
        auto aparam_u64 = [&aparam](const char* k, std::uint64_t dflt) -> std::uint64_t {
            const std::string v = aparam(k);
            if (v.empty())
                return dflt;
            std::uint64_t out = dflt;
            auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), out);
            // Whole-string only: "123abc" → default, not 123 (M1 — symmetric with the
            // server validator and resilience_strategy::to_u64).
            return (ec == std::errc{} && p == v.data() + v.size()) ? out : dflt;
        };
        FileGuard::Config fcfg;
        fcfg.rule_id = rule.rule_id();
        fcfg.rule_name = rule.name();
        fcfg.path = aparam("path");
        if (atype == "file-hash-equals") {
            // Content-change detection: drift when size + SHA-256 differ from the
            // expected hash (empty → baseline captured on arm). max_bytes caps the
            // hashing-DoS; settle_ms coalesces mid-write notifications.
            fcfg.assertion = FileGuard::Assertion::HashEquals;
            fcfg.expected_hash = aparam("expected_hash");
            for (auto& c : fcfg.expected_hash) // normalise to the lowercase hex sha256_file emits
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c - 'A' + 'a');
            const std::uint64_t default_max_bytes = fcfg.max_hash_bytes;
            fcfg.max_hash_bytes = aparam_u64("max_bytes", default_max_bytes);
            // A 0 cap would report every covered file as <oversize> (never hashed,
            // perpetual false "compliant"/"drift") — treat 0 as unset and keep the
            // default cap. The server rejects max_bytes:"0" at authoring; this is the
            // agent-side backstop (M1).
            if (fcfg.max_hash_bytes == 0)
                fcfg.max_hash_bytes = default_max_bytes;
            // #2233 item 6: hard ceiling on an authored value, single-sourced with the
            // spark path's own clamp (guardian_spark_bridge.hpp) via
            // clamp_max_hash_bytes - see that function's doc for why and the exact bound.
            if (const auto clamped = clamp_max_hash_bytes(fcfg.max_hash_bytes);
                clamped != fcfg.max_hash_bytes) {
                spdlog::warn("Guardian: rule '{}' authored max_bytes={} exceeds the {}-byte "
                            "ceiling - clamped (#2233 item 6)",
                            log_id_token(fcfg.rule_id), fcfg.max_hash_bytes, kMaxFileHashBytes);
                fcfg.max_hash_bytes = clamped;
            }
            fcfg.settle_ms = aparam_u64("settle_ms", fcfg.settle_ms);

            // #4021: seed a previously-captured baseline before this guard ever gets
            // to baseline-on-arm itself, so a full_sync/restart re-arm of an
            // already-baselined rule re-asserts the SAME known-good state instead of
            // silently recapturing whatever the (possibly still-drifted) target
            // currently contains. A fingerprint mismatch (this rule_id's target
            // genuinely changed) is not seeded — that IS a fresh target, and a fresh
            // capture is correct for it. See guardian_baseline_fingerprint/
            // guardian_seed_baseline's doc for the full rationale and this fix's
            // documented scope.
            const auto baseline_fingerprint =
                guardian_baseline_fingerprint("file-hash-equals", fcfg.path);
            if (fcfg.expected_hash.empty()) {
                if (auto seeded = guardian_seed_baseline(*kv_, rule.rule_id(), baseline_fingerprint))
                    fcfg.expected_hash = *seeded;
            }
            last_file_expected_hash_for_test_ = fcfg.expected_hash; // test-only observability
            // Persist the FIRST-ever capture (fires at most once per FileGuard
            // lifetime — FileGuard's own `!baseline_set` guard ensures that; a
            // seeded rule never re-enters the capture branch at all, since
            // expected_hash is no longer empty from FileGuard's point of view).
            // Captures kv_ BY VALUE (a raw pointer, not `this`/GuardianEngine&) —
            // see guardian_persist_baseline's doc for why that's safe from a guard
            // worker thread.
            fcfg.on_baseline = [kv = kv_, rule_id = rule.rule_id(),
                               fp = baseline_fingerprint](const std::string& hash) {
                guardian_persist_baseline(kv, rule_id, fp, hash);
            };
            // Gate 3 quality-engineer follow-up, hardened per Gate 4 happy-path
            // (the two statements were independent — deleting the assignment
            // above while leaving this one untouched still left the flag true
            // and the regression test green, exactly the gap the flag exists to
            // catch). Derives the flag FROM the assignment's own observable
            // result instead of asserting it separately: last_file_expected_hash_
            // for_test_ only proves the SEED lookup ran, not that the capture
            // callback was actually attached — deleting the assignment above
            // now flips this false too, since `fcfg.on_baseline` would then be
            // empty.
            last_file_on_baseline_wired_for_test_ = static_cast<bool>(fcfg.on_baseline);
        } else {
            // file-exists: "absent" → drift when the file EXISTS; anything else
            // (default "present") → drift when the file is missing / has been deleted.
            fcfg.assertion = FileGuard::Assertion::Exists;
            fcfg.expect_present = (aparam("expected") != "absent");
        }
        // The event-debounce window shares remediation.params with the resilience
        // keys; a file guard is detection-only, so the resilience MODES do not apply
        // — only event_debounce_ms is read (single-sourced via parse_resilience_params,
        // the returned ResilienceConfig is intentionally discarded).
        const auto& frem = rule.remediation();
        auto fget = [&frem](std::string_view k) -> std::string {
            auto it = frem.params().find(std::string(k));
            return it != frem.params().end() ? it->second : std::string{};
        };
        parse_resilience_params(fget, fcfg.event_debounce_ms);
        const std::string log_path = fcfg.path;
        const std::string log_mode =
            atype == "file-hash-equals"
                ? std::string("hash-equals")
                : std::string(fcfg.expect_present ? "expect present" : "expect absent");

        auto file_sink = [this](const GuardDrift& d) { emit_guard_event(d); };
        // (prior guard for this rule_id already retired at function entry)
        auto fguard = std::make_unique<FileGuard>(std::move(fcfg), std::move(file_sink));
        if (fguard->start()) {
            guards_.emplace(rule.rule_id(), std::move(fguard));
            spdlog::info("Guardian: file guard armed for rule '{}' (path={}, {})",
                         log_id_token(rule.rule_id()), log_key_token(log_path), log_mode);
            return true;
        }
        spdlog::warn("Guardian: file guard for rule '{}' did not start (non-Windows or empty path)",
                     log_id_token(rule.rule_id()));
        return false;
    }

    // ── service-status-change Spark (PR5) — ServiceGuard ──────────────────────
    if (rule.spark().type() == "service-status-change") {
        const auto& sa = rule.assertion();
        const std::string atype = sa.type();
        ServiceGuard::Desired desired;
        if (atype == "service-running")
            desired = ServiceGuard::Desired::Running;
        else if (atype == "service-stopped")
            desired = ServiceGuard::Desired::Stopped;
        else
            return false; // unknown/unsupported assertion stays unarmed (G11: errored upstream)
        auto aparam = [&sa](const char* k) -> std::string {
            auto it = sa.params().find(k);
            return it != sa.params().end() ? it->second : std::string{};
        };
        const bool enforce = (rule.enforcement_mode() == "enforce");
        ServiceGuard::Config cfg;
        cfg.rule_id = rule.rule_id();
        cfg.rule_name = rule.name();
        cfg.service_name = aparam("service_name");
        cfg.desired = desired;
        // "enforce" → drive the service to its desired state on drift; any other mode
        // (audit / observe) only detects and reports.
        cfg.enforce = enforce;
        const auto& srem = rule.remediation();
        auto sget = [&srem](std::string_view k) -> std::string {
            auto it = srem.params().find(std::string(k));
            return it != srem.params().end() ? it->second : std::string{};
        };
        cfg.resilience = parse_resilience_params(sget, cfg.event_debounce_ms);
        const std::string log_service = cfg.service_name; // captured before the move below

        auto service_sink = [this](const GuardDrift& d) { emit_guard_event(d); };
        // (prior guard for this rule_id already retired at function entry)
        // Platform factory: Windows SCM ServiceGuard or Linux systemd
        // SystemdServiceGuard, both IGuard. Keeps this dispatch platform-clean.
        auto sguard = make_service_guard(std::move(cfg), std::move(service_sink));
        if (sguard->start()) {
            guards_.emplace(rule.rule_id(), std::move(sguard));
            // Honest mode label: the Linux systemd guard is observe-only in v1, so an
            // enforce-authored rule observes (it logs its own downgrade too) — don't
            // claim "enforce" on a platform that won't remediate (happy-path Q4).
            const char* mode = enforce ? "enforce" : "audit";
#if defined(__linux__)
            if (enforce)
                mode = "enforce (observe-only on Linux)";
#endif
            spdlog::info("Guardian: service guard armed for rule '{}' (service={}, expect={}, mode={})",
                         log_id_token(rule.rule_id()), log_key_token(log_service),
                         desired == ServiceGuard::Desired::Running ? "running" : "stopped", mode);
            return true;
        }
        spdlog::warn("Guardian: service guard for rule '{}' did not start "
                     "(unsupported platform / no service-control backend / invalid service name)",
                     log_id_token(rule.rule_id()));
        return false;
    }

    // ── registry-change Spark (C1/C2) — RegistryGuard ─────────────────────────
    if (rule.spark().type() != "registry-change")
        return false;
    const auto& a = rule.assertion();
    if (a.type() != "registry-value-equals")
        return false;
    auto param = [&a](const char* k) -> std::string {
        auto it = a.params().find(k);
        return it != a.params().end() ? it->second : std::string{};
    };
    const bool enforce = (rule.enforcement_mode() == "enforce");
    RegistryGuard::Config cfg;
    cfg.rule_id    = rule.rule_id();
    cfg.rule_name  = rule.name();
    cfg.hive       = param("hive");
    cfg.key        = param("key");
    cfg.value_name = param("value_name");
    cfg.value_type = param("value_type");
    cfg.expected   = param("expected");
    // "enforce" → the guard writes `expected` back on drift; any other mode
    // (audit / observe) only detects and reports.
    cfg.enforce    = enforce;

    // C3: per-rule resilience policy + debounce live in the remediation block's params
    // (design §8.5; canonical keys + parsing in resilience_strategy.hpp — the single
    // source of truth the C3b schema and C3c form must match). Absent → defaults
    // (Persist + 1s debounce), so existing rules keep their pre-C3 behaviour. The proto
    // Map .find runs INSIDE this DLL, so parse_resilience_params stays proto-free.
    const auto& rem = rule.remediation();
    auto get = [&rem](std::string_view k) -> std::string {
        auto it = rem.params().find(std::string(k));
        return it != rem.params().end() ? it->second : std::string{};
    };
    cfg.resilience = parse_resilience_params(get, cfg.event_debounce_ms);

    // Route drift through the engine rather than a captured sink copy, so a
    // guard armed before the sink is wired (A2 start_local pre-network) still
    // delivers once set_event_sink runs. emit_guard_event takes sink_mtx_ only.
    auto guard_sink = [this](const GuardDrift& d) { emit_guard_event(d); };

    // (prior guard for this rule_id already retired at function entry)
    auto guard = std::make_unique<RegistryGuard>(std::move(cfg), std::move(guard_sink));
    if (guard->start()) {
        guards_.emplace(rule.rule_id(), std::move(guard));
        spdlog::info("Guardian: registry guard armed for rule '{}' (mode={})",
                     log_id_token(rule.rule_id()), enforce ? "enforce" : "audit");
        return true;
    }
    spdlog::warn("Guardian: registry guard for rule '{}' did not start "
                 "(non-Windows or invalid hive)",
                 log_id_token(rule.rule_id()));
    return false;
}

GuardianEngine::ReconcileOutcome
GuardianEngine::reconcile_rule_locked(const gpb::GuaranteedStateRule& rule) {
    if (!rule.enabled()) {
        if (spark_runtime_)
            spark_runtime_->detach_rule(rule.rule_id());
        withdraw_legacy_guard_locked(rule.rule_id());
        unsupported_rules_.erase(rule.rule_id()); // F7: disabled, not Unsupported
        return ReconcileOutcome::Inert;
    }

    // VALIDATION FIRST, before any capability/preference question: an
    // authoring fault (an unrecognized spark type, a spark-type/assertion-
    // type mismatch, a missing required target param) must never be
    // mislabeled as a routine platform gap (Sol's rev-2 review flagged the
    // original ordering as backwards). A rule that fails validation is
    // withdrawn from both backends; get_status()'s existing universal
    // "errored" fail-closed behaviour already represents this correctly - no
    // separate error-reason tracking exists yet (deferred to a later rung
    // that wires status_for_rule() into a more granular get_status()).
    auto assertion = rule_assertion_from_rule(rule);
    auto spec = spark_spec_from_rule(rule);
    if (!assertion || !spec) {
        // A validation-rejected rule is withdrawn from BOTH backends with no
        // diagnostic at all otherwise - unlike every legacy arm-failure path,
        // which always spdlog::warns with the rule_id and a reason. Silent
        // withdrawal here means an operator sees a rule stop being enforced
        // (e.g. on the next restart re-arm pass) with nothing in the log to
        // explain why (sre Gate 6 finding, this PR).
        // #4665 governance-external-review finding (fjarvis, PR #4979): assertion.error()
        // and the spec-derivation fallback string below can BOTH embed operator-authored
        // free text raw (rule.spark().type() here; rule_assertion_from_rule's own
        // "unrecognized {spark,file,service,registry} {assertion} type: <atype>" error
        // strings in guardian_spark_bridge.hpp embed rule.spark().type()/the assertion's
        // own type() the same way) -- all four producer sites feed this ONE consumer, so
        // wrapping the WHOLE resulting message here, at the sink, covers every current AND
        // future producer in one place rather than chasing each one individually (exactly
        // the whack-a-mole this same function's rule_id handling already needed one prior
        // fix round for).
        spdlog::warn("Guardian: rule '{}' failed spark validation ({}) - withdrawing from "
                     "both detection paths",
                     log_id_token(rule.rule_id()),
                     log_key_token(!assertion ? assertion.error()
                                              : "spec derivation failed for spark type '" +
                                                    rule.spark().type() + "'"));
        if (spark_runtime_)
            spark_runtime_->detach_rule(rule.rule_id());
        withdraw_legacy_guard_locked(rule.rule_id());
        unsupported_rules_.erase(rule.rule_id()); // F7: an authoring fault, not Unsupported
        return ReconcileOutcome::Inert;
    }

    // #4021: seed a persisted baseline into the Spark-side assertion BEFORE the
    // backend fork below, so a rule that was previously armed (and baselined) via
    // legacy survives a later flip to Spark instead of Spark re-capturing current
    // content fresh. This does NOT cover Spark's OWN first-ever capture (see
    // guardian_seed_baseline's doc for the documented scope of this fix) — only
    // seeds a value that ALREADY exists in the durable store.
    if (assertion->kind == AssertionKind::FileHashEquals && assertion->expected_hash.empty()) {
        std::string path;
        if (auto it = rule.assertion().params().find("path"); it != rule.assertion().params().end())
            path = it->second;
        const auto fingerprint = guardian_baseline_fingerprint("file-hash-equals", path);
        if (auto seeded = guardian_seed_baseline(*kv_, rule.rule_id(), fingerprint))
            assertion->expected_hash = *seeded;
    }

    // spark_availability_ is set exactly once by wire_spark_engine() and never
    // changes afterward. prefer_spark_ is immutable for this object's
    // lifetime. SparkFailed and Unwired NEVER fall back to legacy - a failure
    // must be visible (errored), never silently absorbed (mutual exclusion).
    if (prefer_spark_ && (spark_availability_ == SparkAvailability::SparkFailed ||
                          spark_availability_ == SparkAvailability::Unwired)) {
        withdraw_legacy_guard_locked(rule.rule_id());
        unsupported_rules_.erase(rule.rule_id()); // F7: agent-wide errored/inert, not per-rule Unsupported
        return ReconcileOutcome::Inert;
    }

    const bool try_spark = prefer_spark_ && spark_availability_ == SparkAvailability::Available;
    if (try_spark) {
        // Capability set: registered AND ARMABLE (not boot-inert) mechanisms (#4685) -
        // NOT spark_heartbeat.hpp's own inert-filtering, which excludes the UNION of
        // boot-inert and runtime-degraded. A mechanism mid a TRANSIENT runtime-degraded
        // episode (Registry's sweeper / File's worker, three consecutive failed passes)
        // still accepts watch() and serves it once a pass next succeeds, so it must stay
        // armable here - filtering it out would strand every rule of that type
        // Unsupported for the whole episode with nothing to proactively re-reconcile on
        // recovery (the bug this fixes). Only a mechanism that could not bind its OS
        // facility at start() (every watch() refused) is excluded. `registered` tracks
        // every type this engine has ANY mechanism for, regardless of boot_inert - it
        // backs the Unsupported-branch log split below (never-registered vs
        // registered-but-boot-inert).
        std::set<SparkType> supported;
        std::set<SparkType> registered;
        if (spark_engine_)
            for (const auto& [type, ms] : spark_engine_->stats_by_type()) {
                registered.insert(type);
                if (!ms.boot_inert)
                    supported.insert(type);
            }
        const RulePlacement placement = classify(rule.spark().type(), supported);
        if (placement == RulePlacement::Arm) {
            withdraw_legacy_guard_locked(rule.rule_id());
            unsupported_rules_.erase(rule.rule_id()); // F7: about to arm (or fail arming) - not Unsupported either way
            // rung 9c PR-2 Unit 6: non-waiting entry point - attach_rule() no longer blocks
            // for its own claim's outcome. `res` resolves to Armed (already committed,
            // synchronously - an inline-type arm, or a same-key claim whose owner already
            // resolved by the time attach_core rechecked) or Accepted (dispatched, queued
            // behind an in-flight/retained claim - not yet resolved, or - rung 9c PR-5c
            // (#4221 up-2) - re-observing an already-Wedged head via an identical retry,
            // whose receipt is in that case already terminal) before ever throwing a
            // synchronous error.
            auto res = spark_runtime_->attach_rule(GuardianSparkRuntime::NonWaiting{},
                                                   rule.rule_id(), std::move(*spec),
                                                   std::move(*assertion),
                                                   /*emit_compliant_edge=*/true);
            if (!res) {
                // Synchronous refusal only - a genuine arm ATTEMPT that did not succeed
                // (admission rejection or a same-key busy rejection at attach_core's own
                // decision point). A rule that resolves ASYNCHRONOUSLY to a non-Committed
                // status is a DIFFERENT outcome (Accepted below); its own failure is logged
                // by ack_ledger_'s drain, not here.
                spdlog::warn("Guardian: spark arm failed for rule '{}': {}",
                             log_id_token(rule.rule_id()), res.error().message);
                // rung 9c PR-5c round 2 (#4221, UP-1 residual): the old comment here
                // read "defensive; attach_rule leaves nothing on failure" - true for
                // every OTHER Failed path, but FALSE for exactly the case UP-1's own
                // fix (round 1) introduced: a retarget refused onto a key wedged by a
                // DIFFERENT rule_id refuses BEFORE tearing down rule_id's own,
                // still-live arm on its previous key, specifically so that arm
                // survives. Calling detach_rule() unconditionally here would undo
                // that preservation one call later - detach_rule_locked() finds
                // rule_id's real, committed arm (untouched by attach_rule's own
                // refusal) and tears it down for real, reproducing UP-1's "zero live
                // arms, no recovery" defect one function call downstream of where
                // round 1 closed it. ArmError::prior_state_preserved is the signal
                // that distinguishes the two: only run this defensive cleanup when
                // attach_rule() itself did NOT already leave rule_id untouched.
                if (!res.error().prior_state_preserved)
                    spark_runtime_->detach_rule(rule.rule_id());
                return ReconcileOutcome::Failed;
            }
            if (res->kind == GuardianSparkRuntime::ArmOutcomeKind::Armed)
                return ReconcileOutcome::Armed; // attach_rule already enqueued its own "armed" audit entry
            // Accepted: register the receipt with whichever application is currently open
            // (apply_rules()'s per-push application, or none at boot - start_local()'s own
            // re-arm loop opens its own application before this ever runs, §R5.3's "handle
            // their eventual failures without inventing a new server-generation
            // acknowledgment"). A genuine arm ATTEMPT that did not (yet) succeed - the
            // caller's policy_generation hold-on-failure gate must not treat this push as
            // fully applied until it resolves. (Exception: a re-observed retry, rung 9c
            // PR-5c #4221 up-2, registers a receipt that is already terminal - the
            // Wedged head it observes - so ack_ledger_'s very next drain resolves it
            // immediately rather than waiting on anything new.)
            ack_ledger_->add_pending(rule.rule_id(), std::move(res->receipt));
            return ReconcileOutcome::Accepted;
        }
        if (placement == RulePlacement::Unrecognized) {
            // Structurally unreachable here: spec/assertion validation above
            // already rejected an unrecognized spark type before this point
            // is ever reached. Kept as an explicit branch (not folded into
            // the Unsupported branch below) so a future reordering of
            // the validation step cannot silently start treating an
            // authoring fault as a routine legacy fallback.
            if (spark_runtime_)
                spark_runtime_->detach_rule(rule.rule_id());
            withdraw_legacy_guard_locked(rule.rule_id());
            unsupported_rules_.erase(rule.rule_id()); // F7: an authoring fault, not Unsupported
            return ReconcileOutcome::Inert;
        }
        // placement == Unsupported (F7, #2298 rung 2 / design doc §R2 + §Platform-
        // rejection): a known spark type with NO mechanism registered on this host, OR
        // one that is registered but BOOT-INERT (#4685) - a TRANSIENT runtime-degraded
        // mechanism is EXCLUDED from this branch (it stays armable, see the capability
        // set above). A distinct terminal state now, not a legacy fallback - withdraw
        // from BOTH backends and record it. Enforcement is unchanged from before F7 for
        // the common off-Windows File/Registry case (legacy already no-ops there); what
        // changes is reporting. That is NOT a universal guarantee, though:
        // classify() keys off the REGISTERED-AND-ARMABLE capability set above, so a
        // registration failure or a registered-but-boot-inert mechanism can also land a
        // rule here on a platform where legacy might otherwise have worked. Fleet-loud
        // via mech_unsupported_total (rungs 2-3); per-rule REST/MCP surfacing is rung
        // 4 - get_status() is deliberately untouched here.
        withdraw_legacy_guard_locked(rule.rule_id()); // a rule_id legacy-armed by a
            // PRIOR push (a different type, or pre-dating this reconcile op) must not
            // keep silently enforcing in place of the terminal state.
        if (spark_runtime_)
            spark_runtime_->detach_rule(rule.rule_id()); // detach whatever was attached - a
                // no-op if this rule was never armed via spark, LOAD-BEARING (not merely
                // defensive) if it was: an Arm-to-Unsupported transition (a mechanism going
                // inert, or a rule's spark type edited) reaches this call still attached
                // (happy-path finding, F7/#2298 governance)
        if (const auto type = spark_type_from_token(rule.spark().type())) {
            // classify() only reaches Unsupported for a RECOGNIZED token, so this is
            // always Some - belt-and-braces, not a real gap.
            auto it = unsupported_rules_.find(rule.rule_id());
            const bool changed = (it == unsupported_rules_.end()) || (it->second != *type);
            unsupported_rules_[rule.rule_id()] = *type;
            if (changed) { // log only on a genuine edge (new, or a different type than before)
                ++last_unsupported_log_for_test_.edge_count;
                last_unsupported_log_for_test_.rule_id = rule.rule_id();
                last_unsupported_log_for_test_.type = *type;
                if (registered.contains(*type)) {
                    // Registered but boot-inert (#4685): start() could not bind this
                    // mechanism's OS facility, so every watch() is refused - a real host
                    // capability was expected and did not come up, distinct from "no
                    // mechanism on this host at all" below. Loud (warn), never emitted
                    // for a merely runtime-degraded episode (that mechanism stays in
                    // `supported` above and never reaches this branch at all).
                    last_unsupported_log_for_test_.level = UnsupportedLogLevel::Warn;
                    spdlog::warn("Guardian: rule '{}' classified unsupported ({} is "
                                 "registered but initialisation refused at start() "
                                 "(boot-inert)) - enforced by neither backend until the "
                                 "agent restarts",
                                 log_id_token(rule.rule_id()), rule.spark().type());
                } else {
                    last_unsupported_log_for_test_.level = UnsupportedLogLevel::Info;
                    spdlog::info("Guardian: rule '{}' classified unsupported ({} has no "
                                 "mechanism on this host) - enforced by neither backend, "
                                 "a routine cross-platform gap, not an error",
                                 log_id_token(rule.rule_id()), rule.spark().type());
                }
            }
        }
        return ReconcileOutcome::Inert; // pinned: "an all-unsupported push still advances
                                        // policy_generation" (test_guardian_engine_spark_reconcile.cpp)
    }

    if (spark_runtime_)
        spark_runtime_->detach_rule(rule.rule_id()); // harmless no-op if never attached
    unsupported_rules_.erase(rule.rule_id()); // F7: legacy-selected path, not Unsupported
    // existing legacy path, UNCHANGED - a legacy arm failure stays Inert here (status
    // quo before #2233 item 3; not this PR's concern to reclassify).
    return start_guard_for_rule_locked(rule) ? ReconcileOutcome::Armed : ReconcileOutcome::Inert;
}

void GuardianEngine::wire_spark_engine(SparkEngine* engine, bool spark_disabled_by_config,
                                       std::function<SendResult(const OutboxEntry&)> send) {
    std::lock_guard lock(mtx_);
    // stop() is STICKY (see start_local): if a stop already ran during boot, do NOT
    // start any spark machinery. Leaving spark_availability_ Unwired is correct - the
    // agent is shutting down and there is nothing to detect with.
    if (stopped_) {
        spdlog::info("Guardian: wire_spark_engine() after stop() - not wiring (shutdown in "
                     "progress); spark stays Unwired");
        return;
    }
    if (spark_availability_ != SparkAvailability::Unwired) {
        spdlog::warn("Guardian: wire_spark_engine() called more than once - ignoring (already {})",
                     spark_availability_ == SparkAvailability::Available ? "Available"
                     : spark_availability_ == SparkAvailability::SparkFailed ? "SparkFailed"
                                                                             : "SparkDisabled");
        return;
    }
    if (spark_disabled_by_config) {
        spark_availability_ = SparkAvailability::SparkDisabled;
        spdlog::info("Guardian: spark path disabled by --spark-disable - legacy IGuard is the "
                     "sole detection path");
        return;
    }
    if (!engine) {
        spark_availability_ = SparkAvailability::SparkFailed;
        // F7: legacy is the actual backend only when prefer_spark_ is false (today's
        // production default); under prefer_spark_=true, reconcile_rule_locked's own
        // SparkFailed guard withdraws legacy entirely, so nothing is enforced. Derived
        // from the same guardian_backend_from_state() the heartbeat tag and agent.cpp's
        // boot log use, so this can't drift from either of them again.
        spdlog::warn("Guardian: spark_engine_ failed to boot - spark path unavailable; "
                     "detection backend = {} (never silently substituted)",
                     guardian_backend_label(guardian_backend_from_state(
                         prefer_spark_, SparkAvailability::SparkFailed)));
        return;
    }

    // All-or-nothing wiring transaction. `registered` tracks whether
    // register_consumer() succeeded, so the guard below knows whether it must
    // unregister on a LATER step's failure (scheduler/drain-worker
    // construction, which can throw - both spawn threads).
    bool registered = false;
    SparkEngine::ConsumerId consumer_id = 0;
    // Runs rollback_spark_wiring_locked() on ANY exit from this point on -
    // an early return, an exception unwinding out of the try below, or a
    // catch handler's own spdlog::warn call itself throwing - unless
    // `committed` is set at the very end of the success path. Declaring this
    // OUTSIDE the try/catch, before either branch runs, is what guarantees
    // the destructor always fires (Sol rung-7.5 review finding 2: the prior
    // explicit rollback_spark_wiring_locked() call inside each catch block
    // could be skipped if the logging call ahead of it threw).
    GuardianRollback rollback;
    rollback.fn = [this, engine, &registered, &consumer_id] {
        rollback_spark_wiring_locked(engine, registered, consumer_id);
    };
    try {
        spark_reader_ = std::make_shared<GuardianStateReader>();
        spark_backend_ = std::make_shared<GuardianSparkEngineBackend>(*engine);
        // set_spark_backend_op_deadline_for_test: only the one Config field tests need
        // crosses the header's forward-declaration boundary (see that setter's doc).
        GuardianSparkRuntime::Config spark_runtime_cfg{};
        if (test_spark_backend_op_deadline_)
            spark_runtime_cfg.backend_op_deadline = *test_spark_backend_op_deadline_;
        spark_runtime_ = std::make_shared<GuardianSparkRuntime>(spark_reader_, spark_backend_,
                                                                spark_runtime_cfg);
        // Provider captures a COPY of agent_id_, never `this` (#2237): the runtime is the
        // object built to survive the agent via a detached SparkEngine handler, so a
        // provider that reached back into GuardianEngine would be the same class of
        // dormant UAF the journal's "own everything, borrow nothing" rule exists for.
        // agent_id_ is set once in the constructor and never reassigned, so a value
        // capture is exactly as current as the legacy path's own direct read of it
        // (guardian_engine.cpp's emit_guard_event) - same source, same lifetime, no new
        // dependency on Register completing first.
        spark_runtime_->set_agent_id_provider([id = agent_id_] { return id; });
        // The durable journal is engine-owned and borrows kv_ (may be null → it durably
        // writes nothing). Constructed whenever spark is wired; persist stays gated on
        // prefer_spark_ in persist_lifecycle_journal_locked, so it is inert at 7.7a.
        //
        // GUARDRAIL (#4153 round 4): the journal's constructor accepts any IJournalStore*
        // so tests can pass an in-memory FakeJournalStore - production must always pass a
        // real KvStore. That is enforced today by kv_'s own declared type (KvStore*, not
        // IJournalStore*), not by anything at this call site - so if a future refactor
        // ever widens kv_'s type, this assert fires as a compile error right here, forcing
        // that change to be a conscious, reviewed decision rather than a silent widening.
        // Scope, stated honestly: this only catches kv_'s TYPE being widened. It cannot
        // catch a future refactor that leaves kv_'s type alone but substitutes a
        // different pointer at the construction call site below.
        static_assert(std::is_same_v<decltype(kv_), KvStore*>,
                      "GuardianEngine::kv_ must stay KvStore*, not IJournalStore* - "
                      "production must never construct GuardianLifecycleJournal against "
                      "anything but a real KvStore (see kv_store.hpp's IJournalStore doc)");
        lifecycle_journal_ = std::make_shared<GuardianLifecycleJournal>(kv_);

        auto id = engine->register_consumer("guardian-spark",
                                            GuardianSparkRuntime::make_handler(spark_runtime_));
        if (!id) {
            spdlog::warn("Guardian: spark consumer registration failed ({}) - spark path "
                         "unavailable",
                         id.error());
            return; // rollback's destructor cleans up (registered is still false)
        }
        consumer_id = *id;
        registered = true;
        spark_backend_->bind_consumer(consumer_id);

        spark_scheduler_ = std::make_unique<ConvergenceScheduler>(*spark_runtime_);
        // Wrap the send so that after a PAGED batch's LAST entry is delivered, its best-effort
        // sent-label is written (item 7 PR-Ag). Live / compliance / health entries carry no
        // batch key → no-op.
        //
        // Captures the journal HANDLE, not `this` (C0 #2298): re-reading the lifecycle_journal_
        // member from wherever this wrap runs would be an unlocked read of engine state, and
        // taking mtx_ to read it safely risks a deadlock on any thread stop() joins while
        // holding mtx_. Resolved here, once, and held by shared_ptr so the wrap cannot outlive
        // what it points at. (#2233 item 4, revised: this wrap - the `send` passed to
        // GuardianOutboxDrainWorker - no longer necessarily runs ON the drain-worker thread at
        // all; drain_bounded() routes it through GuardianOutboxSendExecutor's detached worker,
        // guardian_outbox_send_executor.hpp. mark_batch_sent()'s kv_ write below is therefore a
        // THIRD caller into KvStore alongside persist()/prune()/page_into_window() - safe only
        // because KvStore serialises its single connection under its own mutex; see the CONCURRENCY
        // paragraph in guardian_lifecycle_journal.hpp, which names this caller explicitly.)
        auto journal = lifecycle_journal_; // shared: the wrap keeps it alive on its own
        auto journaled_send = [journal, send = std::move(send)](const OutboxEntry& e) -> SendResult {
            const SendResult r = send(e);
            if (r == SendResult::Sent && e.journal_last_in_batch && !e.journal_batch_key.empty() &&
                journal)
                journal->mark_batch_sent(e.journal_batch_key);
            return r;
        };
        // The same pointer also drives the worker's journal-maintenance pass (prune + page),
        // relocated off the heartbeat / reconnect threads by C0.
        GuardianMaintenanceConfig maint{.journal = journal};
        maint.jitter = maintenance_jitter_;
        if (test_page_interval_.count() > 0)
            maint.page_interval = test_page_interval_;
        if (test_prune_interval_.count() > 0)
            maint.prune_interval = test_prune_interval_;
        spark_drain_worker_ = std::make_unique<GuardianOutboxDrainWorker>(
            *spark_runtime_, std::move(journaled_send),
            test_periodic_bound_ms_ > 0 ? test_periodic_bound_ms_
                                        : GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
            maint);
        // Start the convergence + drain machinery ONLY when spark is the ACTIVE
        // detection backend (prefer_spark_). At prefer_spark_=false (rung 7.7a: spark
        // wired but legacy authoritative) no rule ever places on spark, so the outbox
        // never fills and the convergence lanes are empty - their 5 threads would be
        // pure overhead AND would claim thread budget ahead of the still-authoritative
        // legacy backend, whose re-arm (start_local) follows wiring at boot. rung 7.7b
        // (prefer_spark_=true) starts them here. stop() calls their stop()
        // unconditionally, a no-op on an unstarted scheduler/drain. (start() may throw:
        // it spawns threads - hence the ScopeExit rollback above.)
        if (prefer_spark_) {
            spark_scheduler_->start();
            spark_drain_worker_->start();
        }

        spark_engine_ = engine;
        spark_availability_ = SparkAvailability::Available;
        rollback.committed = true;
        spdlog::info("Guardian: spark path wired and available (consumer_id={})", consumer_id);
    } catch (const std::exception& e) {
        spdlog::warn("Guardian: spark wiring failed ({}) - rolling back, spark path unavailable",
                     e.what());
    } catch (...) {
        // Belt-and-braces: nothing may terminate the agent for this
        // best-effort subsystem, even a non-std throw.
        spdlog::warn("Guardian: spark wiring failed (unknown exception) - rolling back, spark "
                     "path unavailable");
    }
}

void GuardianEngine::rollback_spark_wiring_locked(SparkEngine* engine, bool registered,
                                                  std::uint64_t consumer_id) {
    // Unwind in the reverse order construction attempted them. Each step is
    // independently null-safe, so this is correct regardless of exactly how
    // far the wiring sequence got before it threw.
    //
    // Signal the journal FIRST, exactly as stop() does (#2298 governance cs-NICE): if
    // wiring failed after the worker started, it may be inside a full maintenance pass,
    // and without this the join below blocks BOOT for the length of that pass.
    if (lifecycle_journal_)
        lifecycle_journal_->request_stop();
    if (spark_drain_worker_)
        spark_drain_worker_->stop();
    spark_drain_worker_.reset();
    if (spark_scheduler_)
        spark_scheduler_->stop();
    spark_scheduler_.reset();
    if (spark_runtime_)
        spark_runtime_->begin_stop();
    spark_runtime_.reset();
    spark_backend_.reset();
    spark_reader_.reset();
    if (registered)
        engine->unregister_consumer(consumer_id);
    spark_engine_ = nullptr;
    spark_availability_ = SparkAvailability::SparkFailed;
}

GuardianEngine::SparkAvailability GuardianEngine::spark_availability() const {
    std::lock_guard lock(mtx_);
    return spark_availability_;
}

std::size_t GuardianEngine::active_io_workers() const {
    std::lock_guard lock(mtx_);
    // #2233 item 3: spark_runtime_'s own bounded arm/disarm executor is a SECOND
    // source of live backend I/O workers, distinct from spark_reader_'s state-read
    // executor (guardian_spark_runtime.hpp - dedicated instance, never shared).
    // #2233 item 4 adds a THIRD: spark_drain_worker_'s detached outbox-send executor
    // (guardian_outbox_send_executor.hpp) - its `send` callback captures AgentImpl
    // state directly and is safe ONLY because this sum is what keeps main.cpp /
    // service_win.cpp from tearing that state down while a send is still detached
    // and running (see guardian_outbox_drain_worker.hpp's class doc). #4783 adds a
    // FOURTH: legacy_sink_executor_'s own detached sender for the legacy IGuard
    // producers' events - always live (constructed unconditionally, not gated on
    // prefer_spark_), and its injected `send` callback reaches AgentImpl state the
    // exact same way (guardian_sink_stream_ + stream_write_mu_ via emit_guardian_
    // event()). All FOUR must be summed here: this is the orphan-exit contract's
    // sole source of truth (hard_exit.hpp / guardian_io_executor.hpp) -
    // main.cpp/service_win.cpp refuse normal C++ teardown while this is nonzero, and
    // a source left out of the sum would let a detached worker survive teardown
    // undetected. legacy_sink_executor_->active_worker_count() takes only its OWN
    // internal lock (never mtx_), so this stays mtx_ -> executor-mu, non-invertible.
    std::size_t n = spark_reader_ ? spark_reader_->active_io_workers() : 0;
    if (spark_runtime_)
        n += spark_runtime_->active_backend_op_workers();
    if (spark_drain_worker_)
        n += spark_drain_worker_->active_send_workers();
    n += legacy_sink_executor_->active_worker_count();
    return n;
}

// #501: Test-support helper — see guardian_engine.hpp for the full rationale.
// The CommandRequest construction happens INSIDE yuzu_agent_core.dll (where
// this TU compiles). The push payload now rides in the `payload` bytes field
// (a plain string field, not a Map), so the absl::HashOf-seed split that
// motivated this helper no longer applies to the payload itself — but the
// helper still usefully parses the GuaranteedStatePush (whose nested `params`
// Map IS hashed) inside the DLL during dispatch()→apply_rules(), so keep it.
GuardianDispatchResult
guardian_dispatch_push_bytes_for_test(GuardianEngine& engine,
                                      std::string_view push_param_bytes) {
    apb::CommandRequest cmd;
    cmd.set_command_id("test-dispatch");
    cmd.set_plugin("__guard__");
    cmd.set_action(std::string{kActionPushRules});
    cmd.set_payload(std::string{push_param_bytes});
    return engine.dispatch(cmd);
}

// Test-support helper — see guardian_engine.hpp. Friend of GuardianEngine so it
// can reach the private emit_guard_event(); production drift only ever enters
// that method from a guard worker's sink lambda (see start_guard_for_rule_locked).
void guardian_emit_drift_for_test(GuardianEngine& engine, const GuardDrift& drift) {
    engine.emit_guard_event(drift);
}

// Test-support helpers — see guardian_engine.hpp (#4021 adversarial-review
// K1/C2-1 regression net). Not friends: `guardian_persist_baseline`/
// `guardian_seed_baseline` are free functions in this file's anonymous
// namespace above (internal linkage), so these two thin, externally-linked
// forwarders are the only way a different translation unit reaches them —
// nothing else about them changes. Needed because the real call site
// (`FileGuard::Config::on_baseline`) fires only from a running Windows-only
// guard worker thread, which this platform's tests cannot exercise end-to-end.
void guardian_persist_baseline_for_test(KvStore& kv, const std::string& rule_id,
                                        const std::string& fingerprint,
                                        const std::string& hash) {
    guardian_persist_baseline(&kv, rule_id, fingerprint, hash);
}

std::optional<std::string> guardian_seed_baseline_for_test(KvStore& kv,
                                                           const std::string& rule_id,
                                                           const std::string& fingerprint) {
    return guardian_seed_baseline(kv, rule_id, fingerprint);
}

} // namespace yuzu::agent
