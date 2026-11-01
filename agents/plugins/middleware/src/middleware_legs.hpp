/**
 * middleware_legs.hpp -- shared seam between the middleware plugin TU and its three per-OS leg TUs
 * (runtimes_legs.hpp shape).
 *
 * Holds (a) the per-OS entry-point declarations, (b) the two result-emission helpers every leg
 * calls, so no leg picks a status/completeness pairing by hand, and (c) the plugin's whole
 * execute() body, with the leg injected.
 *
 * A leg receives the PRODUCT (a row of the table in agents/shared/middleware_products.hpp), not an
 * action enum: adding a product is a table row, and no function here changes.
 *
 * Shipped legs: Linux. Windows and macOS are PLANNED placeholders that emit
 * `status|<action>|unsupported|<os>:planned` for every product.
 */
#pragma once

#include "middleware_parsers.hpp"

#include <middleware_products.hpp>

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::middleware {

// -- per-OS entry points (defined by the leg TUs) ---------------------------
//
// Each is a READ and returns 0 unconditionally: a degraded read is not a
// failed command; the degradation is reported through the status row and
// set_result_status. Declared unconditionally so every TU sees the same
// signature; only the DEFINITION is self-gated (each leg .cpp wraps its body
// in `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only
// the host leg under the same #if.

int run_windows(yuzu::CommandContext& ctx, const Product& p);
int run_linux(yuzu::CommandContext& ctx, const Product& p);
int run_macos(yuzu::CommandContext& ctx, const Product& p);

// -- result emission ---------------------------------------------------------

/// A completed read: writes the status row FIRST, then every data row, and
/// reports OK/FULL, or CONSTRAINED/PARTIAL (reason = the accumulated tokens)
/// when the accumulator recorded any failure. Zero rows + no failure means none
/// found at the places the leg looks (OK/FULL, status `supported`).
inline void emit_read(yuzu::CommandContext& ctx, const Product& p,
                      const std::vector<std::string>& data_rows,
                      const yuzu::shared::ConstraintAccumulator& acc) {
    for (const auto& row : compose_output(p.id, data_rows, acc))
        ctx.write_output(row);
    if (acc.any_failure()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              acc.reason());
    } else {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    }
}

/// A leg that does not read anything on this OS (planned / not yet wired):
/// writes `status|<action>|unsupported|<os_token>` and reports
/// UNAVAILABLE/PARTIAL. `os_token` is a string literal of the form
/// `<os>:<detail>` (e.g. "macos:planned").
inline void emit_planned(yuzu::CommandContext& ctx, const Product& p, std::string_view os_token) {
    ctx.write_output(yuzu::shared::format_status_row(
        p.id, yuzu::shared::StatusLevel::unsupported, os_token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          os_token);
}

// -- the plugin's whole execute() body ---------------------------------------

using LegFn = int (*)(yuzu::CommandContext&, const Product&);

/// execute() in full, with the leg injected so a test can drive the real containment with a
/// throwing leg. No exception may cross the plugin ABI on any leg: the unknown-action
/// diagnostic and the recovery itself run inside the guard. Leg failure tokens match
/// ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$; the catch-all's `internal_error` is the
/// one OS-neutral token. An unknown action writes ONE non-status line and returns 1 (no
/// status row); a throwing leg gets `status|<action>|constrained|internal_error` appended
/// (the LAST status row wins) and returns 1 -- a genuine internal failure is a failed command.
inline int execute_action(yuzu::CommandContext& ctx, std::string_view action, LegFn leg) {
    const Product* p = nullptr;
    try {
        p = find_product(action);
        if (p == nullptr) {
            // `action` is request-supplied and lands in a pipe-delimited stream, so it goes
            // through the shared escaper. Deliberately NOT a row.
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        }
        return leg(ctx, *p);
    } catch (...) {
        if (p == nullptr)
            return 1; // the refusal diagnostic itself failed; rc 1 still reports it
        try {
            ctx.write_output(yuzu::shared::format_status_row(
                p->id, yuzu::shared::StatusLevel::constrained, "internal_error"));
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, "internal_error");
        } catch (...) {
            // the recovery allocates too; rc 1 below still reports the failure
        }
        return 1;
    }
}

} // namespace yuzu::middleware
