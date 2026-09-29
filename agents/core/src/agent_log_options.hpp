#pragma once

/// @file agent_log_options.hpp
/// #4666 PR-2: pure translator from main.cpp's already-parsed CLI flags to
/// LogHandoff::Options (log_handoff.hpp). Split out as its own header so the
/// flag-routing decision -- which of --log-file/--service-mode/--data-dir wins,
/// and what happens to --log-max-size/--log-max-files along the way -- is
/// unit-testable without spinning up the whole agent; main.cpp stays a thin
/// caller of make_log_handoff_options(). No I/O, no logging, throws nothing
/// itself.

#include <cstddef>
#include <filesystem>
#include <string>

#include "log_handoff.hpp"

namespace yuzu::agent {

/// The subset of main.cpp's already-parsed CLI state this translator needs.
/// `service_mode` is caller-resolved (pass `_WIN32 && cli_service_mode`) --
/// this struct does not itself know about the Windows SCM.
struct AgentLogCli {
    std::string log_file;
    std::size_t log_max_size;
    int log_max_files;
    bool service_mode;
    std::filesystem::path data_dir;
};

/// Translates AgentLogCli into LogHandoff::Options, matching main.cpp's
/// existing (pre-#4666) flag-routing behaviour exactly:
///  - service_mode && log_file empty -> data_dir / "yuzu-agent.log" (main.cpp's
///    Windows-service default, main.cpp:645-649).
///  - otherwise: log_file non-empty -> that path; empty -> std::nullopt
///    (console-only -- see LogHandoff::Options::log_file's own doc comment).
///  - log_max_size / log_max_files pass straight through. This is a PIN, not
///    a fix: main.cpp's --log-max-files is parsed as `int` (main.cpp:324) and
///    forwarded, unmodified, to rotating_file_sink_mt's ctor, whose
///    `max_files` parameter is `std::size_t` -- so a negative value already
///    undergoes an int->std::size_t conversion at that call site today. The
///    assignment below performs the identical conversion. Per
///    [conv.integral], -1 becomes SIZE_MAX (value mod 2^64), not the
///    32-bit-wraparound value a reader might expect. SIZE_MAX exceeds
///    spdlog's rotating_file_sink::MaxFiles (200000), so the sink
///    constructor throws and LogHandoff::create() takes its documented
///    console-fallback path (used_log_file_fallback() becomes true) --
///    exactly like today's main.cpp try/catch at main.cpp:651-669. Rejecting
///    a negative --log-max-files earlier (e.g. at CLI11 parse time) is a
///    behaviour change, out of scope for this pure-translator slice.
[[nodiscard]] inline LogHandoff::Options make_log_handoff_options(const AgentLogCli& cli) {
    LogHandoff::Options opts;
    opts.service_mode = cli.service_mode;
    if (cli.service_mode && cli.log_file.empty())
        opts.log_file = cli.data_dir / "yuzu-agent.log";
    else if (!cli.log_file.empty())
        opts.log_file = cli.log_file;
    // else: leave opts.log_file at its default (std::nullopt) -- console-only.
    opts.log_max_size = cli.log_max_size;
    opts.log_max_files = cli.log_max_files; // pinned int->size_t conversion, see above
    return opts;
}

} // namespace yuzu::agent
