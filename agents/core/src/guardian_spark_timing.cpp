#include "guardian_spark_timing.hpp"

#include <format>

#include <yuzu/log_token.hpp>

namespace yuzu::agent {

namespace {

/// An event id (which embeds the operator-authored rule id) or a bare rule id is neutralised and
/// shortened exactly as the server's T_server line does (yuzu/log_token.hpp, log_id_token): a
/// space, '=' or newline would otherwise forge tokens or whole lines, and a different rule on
/// either side breaks the join.
std::string id_token(const std::string& id) {
    return ::yuzu::log_id_token(id);
}

/// -1 sentinel for every trigger sub-field when a pass has no attributable Spark event
/// (Convergence reason). Kept as a single named constant so every sentinel write agrees.
constexpr std::int64_t kAbsentTriggerSentinel = -1;

const char* domain_name(OutboxDomain d) {
    switch (d) {
    case OutboxDomain::Compliance:
        return "compliance";
    case OutboxDomain::Health:
        return "health";
    case OutboxDomain::Lifecycle:
        return "lifecycle";
    }
    return "unknown"; // unreachable if the switch above is kept exhaustive
}

} // namespace

std::string format_eval_timing_line(const EvalTimingRecord& r) {
    std::string line = std::format(
        "Guardian T_detect event_id={} domain={} detect_wall_ns={} detect_mono_ns={} "
        "accepted={} fire_wall_ns={} fire_mono_ns={} trigger_present={}",
        id_token(r.event_id), domain_name(r.domain), r.detect_wall_ns, r.detect_mono_ns,
        r.accepted ? 1 : 0, r.fire_wall_ns, r.fire_mono_ns, r.trigger.has_value() ? 1 : 0);
    if (r.trigger) {
        line += std::format(
            " mechanism_wall_ns={} handler_wall_ns={} handler_mono_ns={} seq={}",
            r.trigger->mechanism_wall_ns, r.trigger->handler_wall_ns,
            r.trigger->handler_mono_ns, r.trigger->seq);
    } else {
        line += std::format(
            " mechanism_wall_ns={} handler_wall_ns={} handler_mono_ns={} seq={}",
            kAbsentTriggerSentinel, kAbsentTriggerSentinel, kAbsentTriggerSentinel,
            kAbsentTriggerSentinel);
    }
    return line;
}

SendTimingRecord make_outbox_send_timing(const OutboxEntry& e, bool sent,
                                         std::int64_t wire_wall_ns) {
    SendTimingRecord r;
    r.event_id = e.event_id;
    r.domain = e.domain;
    r.sent = sent;
    r.wire_wall_ns = wire_wall_ns;
    return r;
}

std::string format_send_timing_line(const SendTimingRecord& r) {
    return std::format("Guardian T_wire event_id={} domain={} sent={} wire_wall_ns={}",
                        id_token(r.event_id), r.domain ? domain_name(*r.domain) : "legacy",
                        r.sent ? 1 : 0, r.wire_wall_ns);
}

std::string format_arm_committed_line(const std::string& rule_id, std::uint64_t epoch,
                                      std::uint64_t incarnation, const char* type, const char* via,
                                      std::int64_t attach_to_commit_ms) {
    // std::format on a null const char* is undefined (the spdlog/fmt path this replaced rejected
    // it with a format_error that spdlog swallowed). "unknown" also keeps the token inside the
    // driver's T2_RE [\w-]+.
    return std::format("Guardian spark: arm committed for rule '{}' (epoch={}, incarnation={}, "
                       "type={}, via={}, attach_to_commit_ms={})",
                       id_token(rule_id), epoch, incarnation, type ? type : "unknown",
                       via ? via : "unknown", attach_to_commit_ms);
}

} // namespace yuzu::agent
