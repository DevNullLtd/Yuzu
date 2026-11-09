#pragma once

/// @file hardware_section_integrity.hpp
/// The side-effecting half of the hardware record section integrity check (#7159): the
/// `yuzu_hardware_section_integrity_total` counter and its sampled WARN. The verdicts themselves
/// (`served_section_verdict`, `verify_section_*`, `SectionFault`, the tokens) live in the pure
/// model, hardware_list_model.hpp; this file adds only the counting, so the model stays free of
/// metrics and logging. The header is metrics-free (forward declaration only).

#include "device_inventory_types.hpp" // DeviceCiSection
#include "digest_fn.hpp"              // DigestFn

#include <string_view>
#include <vector>

namespace yuzu {
class MetricsRegistry; // sdk/include/yuzu/metrics.hpp
}

namespace yuzu::server {

/// Describes `yuzu_hardware_section_integrity_total` and pre-seeds one series per non-None
/// `SectionFault` (the label values are `section_fault_label()`'s, so there is no second
/// hand-kept list) at 0, so a dashboard can tell "no fault" from "series absent". Called once at
/// server startup.
void register_section_integrity_metrics(yuzu::MetricsRegistry& metrics);

/// Counts the integrity faults of the sections of ONE composed read of a record, and logs the
/// first of an episode: `yuzu_hardware_section_integrity_total{reason}` once per faulted section
/// per COMPOSED read, plus a sampled WARN per reason naming the device id and the section kind,
/// never row contents.
///
/// What is counted: reads COMPOSED with a faulted section, not "served reads". The call is made
/// inside the one `hw_ci_detail_fn` closure, before the route's audit write, so a read whose body
/// is then withheld by an audit-write failure (503) is still counted. A polled device inflates
/// the counter; it is not a count of distinct defects. The WARN is SAMPLED per reason (the
/// leading edge of a 60 s episode, then every 100th occurrence), so it cannot list every
/// affected device.
///
/// The verdict comes from `served_section_verdict` - the same function and the same rows the
/// response body is built from - but it is a second CALL, so an intermittent digest-provider
/// failure between the two could make the counted label differ from the served token (accepted;
/// carrying a precomputed verdict would create a second serving path). Re-verifying costs two
/// SHA-256 passes over at most 96 KiB of section rows (the `device_ci_kinds.hpp` static_assert),
/// sub-millisecond against a Postgres round-trip. The provider is a PARAMETER (no process-global
/// state); nullptr means `sha256_hex`. `metrics` may be null (nothing counted, still logged).
/// Called for `CiRead::WithSections` only - so both transports are covered and the dashboard is
/// not.
void record_section_integrity(const std::vector<DeviceCiSection>& sections,
                              std::string_view agent_id, yuzu::MetricsRegistry* metrics,
                              DigestFn digest = nullptr);

/// TEST SEAM (#7159): forget the per-reason WARN sampling state, so a test can assert the
/// leading-edge WARN regardless of which tests ran before it in the same process.
void reset_section_integrity_log_state_for_test() noexcept;

} // namespace yuzu::server
