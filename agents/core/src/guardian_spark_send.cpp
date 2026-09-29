#include "guardian_spark_send.hpp"

#include "guardian_drift_event.hpp" // apply_drift_to_event (shared with the legacy path)

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace yuzu::agent {

namespace gpb = ::yuzu::guardian::v1;

namespace {

constexpr std::int64_t kNsPerSec = 1'000'000'000;

// Fields common to every domain. event_id and the timestamp come verbatim from the
// entry: event_id is the wire-idempotency key the runtime already made globally
// unique (agent_id + boot nonce folded in, #1307), and enqueued_ns is the wall-clock
// nanoseconds-since-epoch stamp fixed at enqueue (NOT a fresh now() at send time -
// the send may be a retry minutes later, and the observation time is when it was
// produced).
void set_common(gpb::GuaranteedStateEvent& ev, const OutboxEntry& e, std::string_view platform) {
    ev.set_event_id(e.event_id);
    ev.set_rule_id(e.rule_id);
    ev.set_guard_category("event");
    // The well-known Timestamp requires nanos in [0, 1e9): integer % is
    // sign-preserving in C++, so a negative enqueued_ns (a badly-skewed / pre-epoch
    // wall clock) would yield a negative nanos and a malformed Timestamp some consumers
    // reject. Normalize to a canonical (seconds, nanos>=0) pair via floored division.
    std::int64_t secs = e.enqueued_ns / kNsPerSec;
    std::int64_t nanos = e.enqueued_ns % kNsPerSec;
    if (nanos < 0) {
        nanos += kNsPerSec;
        --secs;
    }
    ev.mutable_timestamp()->set_seconds(secs);
    ev.mutable_timestamp()->set_nanos(static_cast<std::int32_t>(nanos));
    ev.set_platform(std::string(platform));
}

} // namespace

gpb::GuaranteedStateEvent guardian_outbox_entry_to_event(const OutboxEntry& e,
                                                         std::string_view platform) {
    gpb::GuaranteedStateEvent ev;
    set_common(ev, e, platform);

    switch (e.domain) {
    case OutboxDomain::Compliance:
        // The compliance-family drift fields are shared byte-for-byte with the legacy
        // GuardianEngine::emit_guard_event path via apply_drift_to_event (#2237 item 1).
        // event_id/timestamp differ by design - the outbox fixes them at enqueue, not
        // at send - and rule_id/guard_category/platform are already set by set_common.
        apply_drift_to_event(e.drift, ev);
        break;
    case OutboxDomain::Health:
        // Health/Lifecycle carry guard_type/rule_name on the entry (Compliance carries
        // them inside drift); set them so the wire event is fully identified (#2237).
        // This serialization (below) is duplicated byte-for-byte in guardian_engine.cpp's
        // emit_guard_event health arm (legacy FileGuard's own guard.unhealthy path,
        // PR #4748) with no coupling test between the two copies — tracked as #4782.
        ev.set_guard_type(e.guard_type);
        ev.set_rule_name(e.rule_name);
        // healthy = the watch recovered (Unknown -> Known); !healthy = a read error
        // left the guard unable to evaluate. Separate from compliance state. The
        // read-error text goes into detail_json as a STRUCTURED JSON object
        // {"detail": "..."} - the proto/server define detail_json as JSON, so a bare
        // string like "EACCES on hive" would be malformed. nlohmann handles escaping.
        ev.set_event_type(e.healthy ? "guard.healthy" : "guard.unhealthy");
        if (!e.healthy && !e.health_detail.empty()) {
            nlohmann::json j;
            j["detail"] = e.health_detail;
            // A read-error string can carry non-UTF-8 bytes (e.g. a Linux filesystem
            // path); nlohmann's default dump() THROWS type_error 316 on those. The
            // outbox drain firewalls the throw (catch-all + retain) but a permanently
            // un-dumpable entry then jams the outbox head every drain cycle. Emit
            // U+FFFD for invalid bytes instead so the entry always serializes.
            ev.set_detail_json(j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
        }
        break;
    case OutboxDomain::Lifecycle:
        ev.set_guard_type(e.guard_type);
        ev.set_rule_name(e.rule_name);
        // lifecycle_kind is one of "armed" | "disarmed" | "errored"; the wire token
        // is "guard." + kind. (Routed here only via GuardianLifecycleLog, whose drain
        // shares this send path - GuardianOutbox itself rejects Lifecycle entries.)
        ev.set_event_type("guard." + e.lifecycle_kind);
        break;
    }
    return ev;
}

} // namespace yuzu::agent
