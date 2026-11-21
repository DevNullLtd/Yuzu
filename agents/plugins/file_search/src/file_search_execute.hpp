/**
 * file_search_execute.hpp -- the whole body of the plugin's execute() and its ONE try/catch, and the entry
 * points the POSIX shell (file_search_posix.cpp) exports to the plugin TU.
 *
 * It sits between the plugin TU (file_search_plugin.cpp: descriptors, init, shutdown, the heartbeat and log
 * hooks) and the pure driver (file_search_driver.hpp). The slice itself is injected (SliceFn), so a test
 * drives the whole execute path without a filesystem, and the allocation-failure case
 * (tests/unit/test_plugin_abi_oom_containment.cpp) compiles this header as the ABI seam under test.
 *
 * WHAT execute() DOES, in order. An unknown action writes one non-row line and returns 1. A request that
 * does not parse writes the `search|invalid|<token>` trailer alone, reports UNAVAILABLE and returns 1. Every
 * other answer is the slice's rows, written as the driver made them (the pool thread writes all rows), a
 * typed status and 0:
 *   ok      OK, and FULL when this slice ended the search with a complete verdict, else PARTIAL
 *   busy    UNAVAILABLE, provenance file_search:busy
 *   invalid UNAVAILABLE, provenance file_search:<reason>  (returns 1)
 *   failed  UNAVAILABLE, provenance file_search:<reason>
 * The status is a coarse summary for the host; the trailer and the coverage row are the answer.
 *
 * NO EXCEPTION CROSSES THE ABI. A throw anywhere in the body (parse, slice, row writes, the after hook)
 * becomes one `search|failed|internal_error` trailer and UNAVAILABLE; if even that cannot be built (the
 * allocator is failing) the call returns 1 rather than unwind through the SDK's extern "C" export.
 */
#pragma once

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>
#include <wire_utf8.hpp>

#include "file_search_driver.hpp"
#include "file_search_request.hpp"

#if !defined(_WIN32)
#include "component_legs.hpp" // ci::AroundLookup
#endif

#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::file_search {

inline constexpr std::string_view kSearchAction = "search";

/// The name rule of the OS the plugin runs on. A function, not a value: building it allocates, so it is
/// called inside the seam's try block.
using SemanticsFn = std::function<fsr::NameSemantics()>;

/// One slice of a parsed request. Production: run_posix_slice. A test injects its own.
using SliceFn = std::function<SliceResult(const Request&)>;

/// Called once with a finished slice's result, after its rows were written: the plugin TU's heartbeat and
/// log. Optional. It may throw; the seam below catches.
using AfterSliceFn = std::function<void(const SliceResult&)>;

namespace execute_detail {

[[nodiscard]] inline bool has_row(const std::vector<std::string>& rows, std::string_view prefix) {
    for (const auto& r : rows)
        if (r.starts_with(prefix))
            return true;
    return false;
}

inline void report_status(yuzu::CommandContext& ctx, const SliceResult& r) {
    if (r.status == Status::ok) {
        const bool complete = r.cursor.empty() && has_row(r.rows, "coverage|complete|");
        ctx.set_result_status(YUZU_RESULT_STATUS_OK,
                              complete ? YUZU_RESULT_COMPLETENESS_FULL : YUZU_RESULT_COMPLETENESS_PARTIAL);
        return;
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                          "file_search:" + r.reason);
}

} // namespace execute_detail

/// Dispatch, validation and the single ABI containment. `semantics` yields the name rule of this OS (the
/// pattern is compiled with it); `provenance_on_throw` is the typed status provenance when the body throws.
inline int execute_search(yuzu::CommandContext& ctx, std::string_view action, std::string_view root,
                          std::string_view pattern, std::string_view kinds, std::string_view cursor,
                          const SemanticsFn& semantics, const SliceFn& run, const AfterSliceFn& after,
                          std::string_view provenance_on_throw) {
    try {
        if (action != kSearchAction) {
            std::string a{action};
            yuzu::shared::scrub_wire_bytes(a);
            ctx.write_output("unknown action: " + yuzu::util::safe_output_field(a));
            return 1;
        }
        const auto req = parse_request(root, pattern, kinds, cursor, semantics());
        if (!req) {
            Trailer t;
            t.status = Status::invalid;
            t.reason = to_token(req.error());
            ctx.write_output(format_search_row(t));
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                                  "file_search:" + t.reason);
            return 1;
        }
        const SliceResult r = run(*req);
        for (const auto& row : r.rows)
            ctx.write_output(row);
        execute_detail::report_status(ctx, r);
        if (after)
            after(r);
        return r.status == Status::invalid ? 1 : 0;
    } catch (...) {
        try {
            Trailer t;
            t.status = Status::failed;
            t.reason = to_token(Fault::internal_error);
            ctx.write_output(format_search_row(t));
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                                  std::string{provenance_on_throw});
        } catch (...) {
            return 1;
        }
        return 0;
    }
}

#if !defined(_WIN32)

// ---- the POSIX shell (file_search_posix.cpp) ----

/// The name rule of this OS: byte-exact on Linux (`bytes`), Unicode NFC plus case folding on macOS
/// (`macos_nfc_casefold_v1`).
[[nodiscard]] fsr::NameSemantics posix_name_semantics();

/// One slice over the live filesystem: the mount table, a leg per unit, a worker thread per slice. Never
/// throws except for an allocation failure, which the execute seam contains.
[[nodiscard]] SliceResult run_posix_slice(const Request& req);

/// The hook the search leg wraps around every lookup that may need a capability. Linux: raises
/// CAP_DAC_READ_SEARCH on the calling thread for the lookup and drops it after; macOS: empty. Exported so
/// the shell test runs the hook the plugin runs.
[[nodiscard]] ci::AroundLookup around_lookup_hook();

/// Runs `work` on a fresh worker thread for at most `timeout`, inside the worker environment (Linux: the
/// capability dropped from the thread's effective set and the idle I/O class; macOS: dataless
/// materialisation off and the throttled disk class). The driver's BoundedRunner in production. Exported so
/// the shell test runs the environment the plugin runs.
[[nodiscard]] RunOutcome<WorkResult> run_on_worker(std::chrono::milliseconds timeout,
                                                   std::function<WorkResult()> work);

/// Asks a slice that is running to end at the next entry (the stop flag the worker polls). Idempotent.
void posix_request_stop() noexcept;

/// Clears the stop flag: a plugin that is initialised again after a shutdown (the module stays mapped, so
/// its statics outlive the unload) must not start cancelled.
void posix_clear_stop() noexcept;

#if defined(__APPLE__)
/// The canonical form macOS names are compared in: ASCII folded inline; any other well-formed UTF-8
/// normalised to NFC and case folded; invalid UTF-8 left as the bytes it is.
[[nodiscard]] std::string macos_canonical_name(std::string_view name);
#endif

#endif // !_WIN32

} // namespace yuzu::file_search
