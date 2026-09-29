/**
 * test_guardian_ingest.cpp — the shared Guardian side-channel ingest chokepoint
 * (ingest_guardian_response, used by both the direct-agent and gateway paths).
 *
 * Pins the item-7 PR-Sv safety contract: the DEX blast-radius + alert observers fire
 * ONLY on a genuine first insert (`Inserted`) — never on an idempotent redelivery (the
 * durable agent lifecycle journal re-sends on every reconnect) and never on a
 * mismatched-payload collision. A regression that ran the observers on redelivery
 * would manufacture false fleet-wide blast-radius sightings and duplicate routed
 * alerts on every agent reconnect.
 */

#include "guardian_ingest.hpp"

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include "dex_alert_router.hpp"
#include "dex_blast_radius.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"
#include "guaranteed_state.pb.h"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <unordered_set>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
using yuzu::server::detail::guardian_event_store_buckets;
using yuzu::server::detail::ingest_guardian_response;
using yuzu::server::detail::kGuardianEventStoreDurationMetric;
using yuzu::server::detail::warm_create_guardian_event_store_metric;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own GuaranteedStateStore against a clone of this schema
// (ADR-0038 migration).
yuzu::test::PgTestTemplate guardian_pg_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};
namespace apb = ::yuzu::agent::v1;
namespace gpb = ::yuzu::guardian::v1;

// A ruleless DEX observation (rule_id == kObservationRuleId) — the only event class
// that feeds the blast-radius / alert observers.
apb::CommandResponse make_observation(const std::string& event_id, const std::string& process) {
    gpb::GuaranteedStateEvent ev;
    ev.set_event_id(event_id);
    ev.set_rule_id(kObservationRuleId);
    ev.set_event_type("process.crashed");
    ev.set_detail_json(std::string(R"({"process":")") + process + R"("})");
    ev.mutable_timestamp()->set_seconds(1718000000);

    apb::CommandResponse resp;
    resp.set_action("event");
    resp.set_payload(ev.SerializeAsString());
    return resp;
}

// An event that the store rejects with EventInsertOutcome::Error - an embedded NUL in a text
// field (the store never store-truncates one; recipe from test_guaranteed_state_store.cpp). Not
// a ruleless observation, so it never touches the DEX observers.
apb::CommandResponse make_error_event(const std::string& event_id) {
    gpb::GuaranteedStateEvent ev;
    ev.set_event_id(event_id);
    ev.set_rule_id("rule-err");
    ev.set_event_type("service.stopped");
    ev.set_detected_value(std::string("a\0b", 3)); // embedded NUL -> Error (round-trips via proto)
    ev.mutable_timestamp()->set_seconds(1718000000);

    apb::CommandResponse resp;
    resp.set_action("event");
    resp.set_payload(ev.SerializeAsString());
    return resp;
}

// An ordinary (non-observation) rule violation, with a caller-supplied wire
// timestamp — used to exercise the #4606 criterion-10 T_server diagnostic
// block, which is gated on rule_id != kObservationRuleId.
apb::CommandResponse make_rule_event(const std::string& event_id, const std::string& rule_id,
                                     std::int64_t ts_seconds = 1718000000,
                                     std::int32_t ts_nanos = 0, bool with_timestamp = true) {
    gpb::GuaranteedStateEvent ev;
    ev.set_event_id(event_id);
    ev.set_rule_id(rule_id);
    ev.set_event_type("service.stopped");
    ev.set_severity("high");
    ev.set_detected_value("stopped");
    ev.set_expected_value("running");
    if (with_timestamp) {
        ev.mutable_timestamp()->set_seconds(ts_seconds);
        ev.mutable_timestamp()->set_nanos(ts_nanos);
    }

    apb::CommandResponse resp;
    resp.set_action("event");
    resp.set_payload(ev.SerializeAsString());
    return resp;
}
} // namespace

TEST_CASE("guardian ingest: DEX observers fire once on insert, never on redelivery/collision",
          "[pg][guardian][ingest][redelivery]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    BlastRadiusConfig cfg;
    cfg.min_devices = 1; // fire on the first sighting so a single event is observable
    BlastRadiusDetector blast(cfg);
    int incidents = 0;
    blast.set_on_incident([&](const BlastRadiusIncident&) { ++incidents; });

    // BOTH observers are wired (the two are gated together; a null router would leave the
    // alert-router half of the gating unproven — qa-S1). The router fires per routed
    // sighting, so on_alert firing is itself the "observe() was called" probe.
    DexAlertRouter router;
    router.set_routes(std::unordered_set<std::string>{"process.crashed"});
    int alerts = 0;
    router.set_on_alert([&](const RoutedSignalAlert&) { ++alerts; });

    const auto resp = make_observation("__observation__-1", "svc.exe");

    // 1) First delivery -> Inserted -> BOTH observers fire exactly once.
    ingest_guardian_response(store, "agent-A", resp, &blast, &router);
    CHECK(store.event_count() == 1);
    CHECK(incidents == 1);
    CHECK(alerts == 1);

    // 2) Exact redelivery (same agent, same payload) -> Redelivered -> NEITHER observer
    //    fires again — no false fleet-wide sighting / duplicate routed alert on reconnect.
    ingest_guardian_response(store, "agent-A", resp, &blast, &router);
    CHECK(store.event_count() == 1);
    CHECK(store.events_redelivered_total() == 1);
    CHECK(incidents == 1);
    CHECK(alerts == 1);

    // 3) Same event_id from a DIFFERENT (connection-bound) agent -> mismatched-field
    //    Conflict -> not written, loud drop metric, and NEITHER observer fires.
    ingest_guardian_response(store, "agent-B", resp, &blast, &router);
    CHECK(store.event_count() == 1);
    CHECK(store.events_dropped_total() == 1);
    CHECK(incidents == 1);
    CHECK(alerts == 1);
}

TEST_CASE("guardian ingest: event-store histogram splits by outcome status, skips non-store paths",
          "[pg][guardian][ingest][metrics]") {
    // Pins yuzu_server_guardian_event_store_duration_seconds (A+): the timer wraps exactly the
    // insert_event_classified call and observes ONE sample per event under its outcome `status`
    // label. Only redelivered/conflict run the redelivery byte-compare, so the split is
    // load-bearing (a label-less aggregate would shift with the insert/redelivery mix). A frame
    // that never reaches the store (non-"event" action, unparseable payload) is NOT timed, and a
    // null registry is inert.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    yuzu::MetricsRegistry metrics;
    warm_create_guardian_event_store_metric(metrics); // pin the ladder + boot the series at 0
    const std::string kName = kGuardianEventStoreDurationMetric;
    auto count = [&](const char* status) {
        return metrics.histogram(kName, {{"status", status}}).snapshot().count;
    };

    // Warm-create seeds all four status series at 0, with the CUSTOM ladder (created-with-buckets,
    // not the default) so #2298's sub-ms resolution survives a first-observe-before-warm-create.
    CHECK(count("inserted") == 0);
    CHECK(count("redelivered") == 0);
    CHECK(count("conflict") == 0);
    CHECK(count("error") == 0);
    CHECK(metrics.histogram(kName, {{"status", "inserted"}}).snapshot().boundaries ==
          guardian_event_store_buckets());

    const auto resp = make_observation("__observation__-1", "svc.exe");
    ingest_guardian_response(store, "agent-A", resp, nullptr, nullptr, &metrics); // Inserted
    ingest_guardian_response(store, "agent-A", resp, nullptr, nullptr, &metrics); // Redelivered
    ingest_guardian_response(store, "agent-B", resp, nullptr, nullptr, &metrics); // Conflict
    ingest_guardian_response(store, "agent-C", make_error_event("evt-err"), nullptr, nullptr,
                             &metrics); // Error (embedded NUL)

    // Each store outcome timed exactly once, under its own status series.
    CHECK(count("inserted") == 1);
    CHECK(count("redelivered") == 1);
    CHECK(count("conflict") == 1);
    CHECK(count("error") == 1);
    // A real store op takes non-zero wall time (guards a zero-length/default-constructed span).
    CHECK(metrics.histogram(kName, {{"status", "inserted"}}).snapshot().sum > 0.0);

    // A non-"event" action, and a malformed "event" payload, both return before the store call
    // -> NO observation on any status series.
    apb::CommandResponse status_action;
    status_action.set_action("status");
    ingest_guardian_response(store, "agent-A", status_action, nullptr, nullptr, &metrics);
    apb::CommandResponse malformed;
    malformed.set_action("event");
    malformed.set_payload(std::string("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 11)); // bad varint
    ingest_guardian_response(store, "agent-A", malformed, nullptr, nullptr, &metrics);
    CHECK(count("inserted") == 1);
    CHECK(count("redelivered") == 1);
    CHECK(count("conflict") == 1);
    CHECK(count("error") == 1);

    // Null registry (the gateway path with no metrics wired) -> inert, no crash, still ingests.
    ingest_guardian_response(store, "agent-D", make_observation("__observation__-2", "svc.exe"),
                             nullptr, nullptr, nullptr);
    CHECK(store.event_count() == 2); // obs-1 (agent-A) + obs-2 (agent-D); conflict/error not stored
    CHECK(count("inserted") == 1);   // unchanged by the null-registry ingest
}

TEST_CASE("guardian ingest: #4606 criterion-10 T_server diagnostic block runs on a non-observation "
          "Inserted event without disrupting ingest, and is skipped for observations",
          "[pg][guardian][ingest][diagnostics]") {
    // guardian_ingest.cpp is compiled directly into the server test binary (not a separate
    // shared library), so LogCapture's cross-image caveat (test_log_capture.hpp's banner)
    // does not apply here — it reliably observes this file's spdlog calls.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);

    // Ordinary rule violation, well-formed wire timestamp: rule_id != kObservationRuleId,
    // so the T_server block's try-block actually runs on this Inserted outcome (computes
    // recv_ns/committed_ns/store_ms and a valid agent_ns from ev.timestamp()).
    yuzu::test::LogCapture cap1;
    ingest_guardian_response(store, "agent-A", make_rule_event("evt-r1", "rule-1"), nullptr, nullptr);
    cap1.stop();
    CHECK(store.event_count() == 1);
    CHECK(store.events_written_total() == 1);
    CHECK(cap1.text().find("Guardian T_server event_id=evt-r1 agent=agent-A rule=rule-1 ") !=
          std::string::npos);
    CHECK(cap1.text().find("agent_ns=1718000000000000000") != std::string::npos);
    // The two server instants must be real and ordered: a swapped or mis-wired recv/committed
    // pair would still print the prefix above. store_ms is only checked non-negative (a sub-ms
    // insert legitimately reads 0, so a stricter bound would flake).
    auto field = [](const std::string& text, const std::string& key) -> std::int64_t {
        const auto p = text.find(key);
        REQUIRE(p != std::string::npos);
        return std::stoll(text.substr(p + key.size()));
    };
    const std::int64_t recv_ns = field(cap1.text(), "recv_ns=");
    const std::int64_t committed_ns = field(cap1.text(), "committed_ns=");
    CHECK(recv_ns > 0);
    CHECK(committed_ns >= recv_ns); // COMMIT happens strictly after the receive stamp
    CHECK(field(cap1.text(), "store_ms=") >= 0);

    // Same, but with an out-of-range wire nanos field (untrusted agent input) — exercises
    // the bounds check that falls back to the agent_ns=-1 sentinel instead of computing a
    // value; must not crash/throw either.
    yuzu::test::LogCapture cap2;
    ingest_guardian_response(store, "agent-A", make_rule_event("evt-r2", "rule-1", 1718000000, -1),
                             nullptr, nullptr);
    cap2.stop();
    CHECK(store.event_count() == 2);
    CHECK(cap2.text().find("Guardian T_server event_id=evt-r2") != std::string::npos);
    CHECK(cap2.text().find("agent_ns=-1") != std::string::npos);

    // A ruleless observation takes the OTHER arm of the gate (rule_id == kObservationRuleId
    // -> block skipped entirely) — no T_server line at all, proving the gate actually
    // discriminates rather than always/never firing.
    yuzu::test::LogCapture cap3;
    ingest_guardian_response(store, "agent-A", make_observation("__observation__-t-server", "svc.exe"),
                             nullptr, nullptr);
    cap3.stop();
    CHECK(store.event_count() == 3);
    CHECK(cap3.text().find("Guardian T_server") == std::string::npos);

    // T_server is Inserted-only: an exact redelivery and a same-id/other-agent Conflict both reach
    // the store and neither may emit the line (a replay or a rejected event is not a fresh commit).
    yuzu::test::LogCapture cap4;
    ingest_guardian_response(store, "agent-A", make_rule_event("evt-r1", "rule-1"), nullptr, nullptr);
    ingest_guardian_response(store, "agent-B", make_rule_event("evt-r1", "rule-1"), nullptr, nullptr);
    cap4.stop();
    CHECK(store.event_count() == 3); // neither was stored
    // ...and each really reached its own store outcome (rather than both failing earlier).
    CHECK(store.events_redelivered_total() == 1);
    CHECK(store.events_dropped_total() == 1);
    CHECK(cap4.text().find("Guardian T_server") == std::string::npos);

    // An ABSENT wire timestamp reads as seconds()==0; it must report the -1 sentinel, not a
    // fabricated epoch-0 instant (agent_ns=0).
    yuzu::test::LogCapture cap5;
    ingest_guardian_response(store, "agent-A",
                             make_rule_event("evt-r5", "rule-1", 0, 0, /*with_timestamp=*/false),
                             nullptr, nullptr);
    cap5.stop();
    CHECK(store.event_count() == 4);
    CHECK(cap5.text().find("Guardian T_server event_id=evt-r5") != std::string::npos);
    CHECK(cap5.text().find("agent_ns=-1") != std::string::npos);
    CHECK(cap5.text().find("agent_ns=0") == std::string::npos);
}

TEST_CASE("guardian ingest: #4606 T_server neutralises agent- and operator-supplied ids so a hostile "
          "value cannot forge a token or a line",
          "[pg][guardian][ingest][diagnostics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto count = [](const std::string& hay, const std::string& needle) {
        std::size_t n = 0;
        for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
            ++n;
        return n;
    };

    // event_id, rule_id and agent_id are all free text on the wire (a rule id is operator-authored
    // and an event id embeds it): spaces and '=' would forge tokens, the newline would forge a
    // whole second line, and agent_id is only length-checked at registration.
    yuzu::test::LogCapture cap;
    ingest_guardian_response(
        store, "agent A=1",
        make_rule_event("evt x=1 agent=victim\nGuardian T_server event_id=z", "rule 2 recv_ns=9"),
        nullptr, nullptr);
    cap.stop();
    REQUIRE(store.event_count() == 1);

    const std::string text = cap.text();
    const auto at = text.find("Guardian T_server ");
    REQUIRE(at != std::string::npos);
    const auto eol = text.find('\n', at);
    const std::string line = text.substr(at, eol == std::string::npos ? std::string::npos : eol - at);
    CHECK(line.find("event_id=evt_x_1_agent_victim_Guardian_T_server_event_id_z agent=agent_A_1 "
                    "rule=rule_2_recv_ns_9 recv_ns=") != std::string::npos);
    // Exactly one of each key, and the record is one physical line (nothing followed the id).
    CHECK(count(line, "event_id=") == 1);
    CHECK(count(line, " agent=") == 1);
    CHECK(count(line, " rule=") == 1);
    CHECK(count(line, " recv_ns=") == 1);
    CHECK(count(text, "Guardian T_server ") == 1);

    // The Conflict warning is the line the alert text sends operators to for the event_id, so it
    // must read the SAME token (this event id again, from a different agent, is a mismatched
    // collision) and be just as un-forgeable.
    yuzu::test::LogCapture cap_conflict;
    ingest_guardian_response(
        store, "agent B=2",
        make_rule_event("evt x=1 agent=victim\nGuardian T_server event_id=z", "rule 2 recv_ns=9"),
        nullptr, nullptr);
    cap_conflict.stop();
    CHECK(store.event_count() == 1);
    const std::string ctext = cap_conflict.text();
    const auto cat = ctext.find("event_id collision with MISMATCHED fields");
    REQUIRE(cat != std::string::npos);
    const auto ceol = ctext.find('\n', cat);
    const std::string cline = ctext.substr(cat, ceol == std::string::npos ? std::string::npos : ceol - cat);
    CHECK(cline.find("event_id=evt_x_1_agent_victim_Guardian_T_server_event_id_z agent=agent_B_2 "
                     "rule=rule_2_recv_ns_9") != std::string::npos);
    CHECK(count(cline, " agent=") == 1);
    CHECK(count(ctext, "event_id collision") == 1);

    // An over-long id is shortened by the SAME function the agent's T_wire/T_detect lines use:
    // head, '~', and its LAST 24 bytes. The tail is the `<wall_ms>-<seq>` part, so two events of
    // one very long rule id stay distinct (a plain prefix cut would collapse them onto one token).
    constexpr std::size_t kHead = yuzu::kGuardianLogIdMaxBytes - yuzu::kGuardianLogIdTailBytes - 1;
    const std::string base(300, 'q');
    auto shortened_of = [&](const std::string& id) {
        return std::string(kHead, 'q') + "~" + id.substr(id.size() - yuzu::kGuardianLogIdTailBytes);
    };
    const std::string id1 = base + "-1789930557755-101";
    const std::string id2 = base + "-1789930557755-102";
    yuzu::test::LogCapture cap_long;
    ingest_guardian_response(store, "agent-A", make_rule_event(id1, "rule-1"), nullptr, nullptr);
    ingest_guardian_response(store, "agent-A", make_rule_event(id2, "rule-1"), nullptr, nullptr);
    cap_long.stop();
    CHECK(shortened_of(id1) != shortened_of(id2));
    CHECK(cap_long.text().find("Guardian T_server event_id=" + shortened_of(id1) + " agent=") !=
          std::string::npos);
    CHECK(cap_long.text().find("Guardian T_server event_id=" + shortened_of(id2) + " agent=") !=
          std::string::npos);
    CHECK(cap_long.text().find(std::string(yuzu::kGuardianLogIdMaxBytes + 1, 'q')) ==
          std::string::npos);

    // Non-ASCII bytes never reach the line (a cut could otherwise leave invalid UTF-8, and U+2028
    // could split the record for a Unicode-aware consumer): each of the five bytes becomes '_'.
    yuzu::test::LogCapture cap_na;
    ingest_guardian_response(store, "agent-A", make_rule_event("e\xC3\xA9\xE2\x80\xA8x", "rule-1"),
                             nullptr, nullptr);
    cap_na.stop();
    CHECK(cap_na.text().find("Guardian T_server event_id=e_____x agent=agent-A") != std::string::npos);
}

TEST_CASE("guardian ingest: #4606 the server's other id-printing log lines neutralise ids too",
          "[pg][guardian][ingest][diagnostics]") {
    // Every Guardian ingest line that prints an agent- or operator-supplied id goes through the
    // same neutraliser as T_server, so an id reads identically on every line an operator joins
    // across and none can forge a token. Each case uses a hostile agent id (a space, '=' and,
    // in one, a newline), which the registration gate only length-checks.
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);

    {   // parse failure: the agent id is printed before any event is known
        apb::CommandResponse malformed;
        malformed.set_action("event");
        malformed.set_payload(std::string("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 11));
        yuzu::test::LogCapture cap;
        ingest_guardian_response(store, "agent x=1\nfake", malformed, nullptr, nullptr);
        cap.stop();
        CHECK(cap.text().find("failed to parse GuaranteedStateEvent from agent agent_x_1_fake") !=
              std::string::npos);
        CHECK(cap.text().find("agent x=1") == std::string::npos);
    }
    {   // oversized detail_json: the agent id and the event id are printed
        gpb::GuaranteedStateEvent ev;
        ev.set_event_id("evt o=1");
        ev.set_rule_id("rule-1");
        ev.set_event_type("service.stopped");
        ev.set_severity("high");
        ev.set_detail_json(std::string(17 * 1024, 'x'));
        ev.mutable_timestamp()->set_seconds(1718000000);
        apb::CommandResponse resp;
        resp.set_action("event");
        resp.set_payload(ev.SerializeAsString());
        yuzu::test::LogCapture cap;
        ingest_guardian_response(store, "agent x=1", resp, nullptr, nullptr);
        cap.stop();
        CHECK(cap.text().find("from agent agent_x_1 event evt_o_1 (cap 16384)") != std::string::npos);
    }
    {   // store Error (an embedded NUL): the agent id and the rule id are printed
        yuzu::test::LogCapture cap;
        ingest_guardian_response(store, "agent x=1", make_error_event("evt e=1"), nullptr, nullptr);
        cap.stop();
        CHECK(cap.text().find("event ingest error (agent=agent_x_1, rule=rule-err)") !=
              std::string::npos);
    }
    {   // Redelivered (debug): event id, agent id and rule id are printed
        const auto resp = make_rule_event("evt r=1", "rule r=1");
        ingest_guardian_response(store, "agent x=1", resp, nullptr, nullptr);
        yuzu::test::LogCapture cap;
        ingest_guardian_response(store, "agent x=1", resp, nullptr, nullptr);
        cap.stop();
        CHECK(cap.text().find("idempotent event redelivery (no re-observe) event_id=evt_r_1 "
                              "agent=agent_x_1 rule=rule_r_1") != std::string::npos);
    }
}
