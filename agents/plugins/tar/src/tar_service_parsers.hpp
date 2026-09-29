#pragma once

/**
 * tar_service_parsers.hpp -- pure output parsers for the TAR service
 * collector's Linux (`systemctl list-units`) and macOS (`launchctl list`)
 * enumeration legs (runner-convergence PR, ADR-3002 rung 2 migration).
 *
 * Header-only, no I/O: tar_service_collector.cpp owns running
 * systemctl/launchctl through the bounded, shell-free runner
 * (yuzu::agent::run_bounded_subprocess) and hands this header the captured
 * SubprocessResult::lines, so every parser here is unit-testable directly
 * against fixture line arrays with no live systemctl/launchctl dependency
 * (see tests/unit/test_tar_service.cpp). Mirrors the
 * services_parsers.hpp / firewall_parsers.hpp / route_sysctl_arp.hpp split
 * already established elsewhere in this repo.
 *
 * This is a straight extraction of the two inline parsing loops the
 * collector used to run over the old pipe-read output -- column handling,
 * header skipping, and PID|LABEL|NAME semantics are unchanged, so collector
 * output for identical input text stays byte-identical to before the
 * runner migration.
 *
 * parse_launchctl_list() (A0, macOS Spark/Reflex/DEX programme) no longer
 * does its own tab-splitting: the raw `launchctl list` row decode is now the
 * shared agents/shared/launchctl_list.hpp (a second consumer, the macOS
 * Spark launchd service mechanism, needs the raw pid/status fields this file
 * used to discard). This is DELIBERATELY still named parse_launchctl_list in
 * THIS namespace (yuzu::tar) -- same name as yuzu::shared's raw parser, no
 * collision (different namespace, different signature) -- so every existing
 * caller and test in this file/tests/unit/test_tar_service.cpp is
 * byte-unchanged; only its body becomes a two-line compose of the shared
 * parser + launchctl_rows_to_services() below (the BR-service-001 malformed-
 * row policy, unchanged).
 */

#include "tar_collectors.hpp" // yuzu::tar::ServiceInfo

#include <launchctl_list.hpp> // yuzu::shared::{LaunchctlRow,parse_launchctl_list}

#include <cstddef>
#include <span>
#include <string>
#include <utility> // std::move
#include <vector>

namespace yuzu::tar {

/// Result of parsing a service-enumeration tool's output: the decoded rows
/// plus whether at least one row was malformed (dropped rather than
/// included as a garbage/empty-name entry). Mirrors tar_arp_parsers.hpp's
/// ProcNetArpParse{entries, malformed} shape (BR4-005) so the two
/// parser families stay consistent: a malformed row is a missing binding
/// relative to a genuinely complete table, and the CALLER
/// (enumerate_services(), tar_service_collector.cpp) is the one that turns
/// this flag into an IncompleteCaptureError throw, mirroring how ARP's
/// `malformed` is only acted on there too.
struct ServiceParseResult {
    std::vector<ServiceInfo> entries;
    bool malformed{false};
};

/// Parse the line-split stdout of `systemctl list-units --type=service
/// --all --plain --no-pager --no-legend` (SubprocessResult::lines -- blank
/// lines already dropped and a trailing '\r' already stripped by the
/// runner). `--plain` (BR-001) makes the invoked argv never emit a marker
/// column at all -- verified live (Docker jrei/systemd-ubuntu:22.04): a
/// `failed`/`not-found` unit's row starts directly at the UNIT field, no
/// leading glyph or space. Without `--plain`, systemctl marks such units
/// with a locale-dependent marker column -- ASCII `*` under a C locale, but
/// the UTF-8 glyph `●` (e2 97 8f) under a UTF-8 one, which this trim does
/// NOT recognise (a real, previously-latent defect this argv change makes
/// moot: see tar_service_collector.cpp's --plain comment). The
/// `find_first_not_of(" *")` trim below stays as defensive tolerance for
/// that ASCII form -- harmless on real `--plain` output (start is always 0,
/// nothing to trim) and correct if a future caller ever invokes this parser
/// against non-`--plain` C-locale output; `--no-legend` means there is no
/// header row to skip either way.
inline ServiceParseResult
parse_systemctl_list_units(const std::vector<std::string>& lines) {
    ServiceParseResult out;
    out.entries.reserve(lines.size());

    for (std::string line : lines) {
        // Trim leading whitespace and the bullet systemctl marks a failed
        // unit with.
        auto start = line.find_first_not_of(" *");
        if (start == std::string::npos)
            continue;
        line = line.substr(start);

        ServiceInfo si;
        std::size_t pos = 0;
        auto next_token = [&]() -> std::string {
            auto s = line.find_first_not_of(' ', pos);
            if (s == std::string::npos)
                return {};
            auto e = line.find(' ', s);
            if (e == std::string::npos)
                e = line.size();
            pos = e;
            return line.substr(s, e - s);
        };

        si.name = next_token();     // UNIT
        next_token();               // LOAD
        next_token();               // ACTIVE
        si.status = next_token();   // SUB
        // Remainder is description
        auto desc_start = line.find_first_not_of(' ', pos);
        if (desc_start != std::string::npos)
            si.display_name = line.substr(desc_start);

        // BR-service-001: a malformed/truncated row -- fewer than the 4
        // required columns (UNIT/LOAD/ACTIVE/SUB) on the line, so UNIT
        // and/or SUB come back "" once next_token() runs out of tokens --
        // must not be pushed as a ServiceInfo carrying an empty/garbage
        // name or status. A real systemctl row always carries a non-empty
        // SUB (dead/running/exited/failed/...), so an empty si.status is as
        // reliable a malformed signal as an empty si.name: checking name
        // alone would miss a row like "myservice.service loaded" that has a
        // real UNIT token but is missing ACTIVE/SUB, which previously
        // silently corrupted the diff the same way (a name-less row can
        // never match a previous snapshot's row, so it reads as a spurious
        // `appeared`, and the row it should have represented reads as a
        // spurious `removed` once a well-formed line replaces it). Same
        // policy as tar_arp_parsers.hpp's BR4-005: drop the row from
        // `entries` but set `malformed` so the CALLER (enumerate_services())
        // throws IncompleteCaptureError instead of diffing a subset as
        // complete.
        if (si.name.empty() || si.status.empty()) {
            out.malformed = true;
            continue;
        }

        si.startup_type = "unknown";
        out.entries.push_back(std::move(si));
    }

    return out;
}

/// Map decoded `launchctl list` rows (yuzu::shared::LaunchctlRow -- the raw
/// pid/status facts) onto this file's ServiceParseResult vocabulary: pid
/// present -> "running", absent -> "stopped" (macOS launchctl list provides
/// no startup type, so that field is always "unknown"). BR-service-001 (same
/// policy as parse_systemctl_list_units above, and tar_arp_parsers.hpp's
/// BR4-005): a row with an empty label (fewer than 3 tab-separated fields in
/// the original text -- see yuzu::shared::parse_launchctl_list) must not be
/// pushed as a name-less ServiceInfo. Drop it and flag `malformed` instead of
/// silently including or dropping it.
inline ServiceParseResult
launchctl_rows_to_services(std::span<const yuzu::shared::LaunchctlRow> rows) {
    ServiceParseResult out;
    out.entries.reserve(rows.size());

    for (const auto& row : rows) {
        if (row.label.empty()) {
            out.malformed = true;
            continue;
        }
        ServiceInfo si;
        si.name = row.label;
        si.status = row.pid.has_value() ? "running" : "stopped";
        si.startup_type = "unknown";
        out.entries.push_back(std::move(si));
    }

    return out;
}

/// Parse the line-split stdout of `launchctl list` (SubprocessResult::lines
/// -- blank lines already dropped and a trailing '\r' already stripped by
/// the runner) straight into this file's ServiceParseResult vocabulary.
/// Composes the shared raw row parser with launchctl_rows_to_services()
/// above; behaviourally identical to the pre-A0 inline body for a
/// well-formed capture (governance A0 fix round, cpp3-2: this is now FALSE
/// for a zero-line capture -- UP2-2 flipped that case's `malformed` from
/// false to true, a deliberate behaviour change from the pre-A0 body, not a
/// pure refactor). A structurally malformed header (UP-6 --
/// yuzu::shared::parse_launchctl_list's own `malformed`, e.g. a missing or
/// preamble-preceded header row, OR an empty capture, UP2-2) propagates
/// through as `malformed` here too, on top of the per-row BR-service-001
/// check.
inline ServiceParseResult parse_launchctl_list(const std::vector<std::string>& lines) {
    auto raw = yuzu::shared::parse_launchctl_list(lines);
    auto out = launchctl_rows_to_services(raw.rows);
    out.malformed = out.malformed || raw.malformed;
    return out;
}

} // namespace yuzu::tar
