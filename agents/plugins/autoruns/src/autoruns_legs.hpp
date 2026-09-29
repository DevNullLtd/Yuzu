/**
 * autoruns_legs.hpp — shared seam between the autoruns plugin TU and its
 * three per-OS leg TUs.
 *
 * `collect_windows` / `collect_linux` / `collect_macos` are the three entry
 * points `execute()`'s `list` action calls, unconditionally and always all
 * three -- exactly like `catalog` iterating every SourceDecl regardless of
 * build host, so a `list` capture always names every source in the catalog,
 * with a foreign-OS source honestly reporting `unsupported|foreign_os`
 * rather than being silently absent from the output.
 *
 * meson.build adds exactly ONE per-OS leg TU to this plugin's build, chosen
 * by `host_machine.system()` (autoruns_win.cpp / autoruns_linux.cpp /
 * autoruns_macos.cpp -- P12 / P13 / P14 respectively). That TU DEFINES the
 * matching `collect_*` function for real. The other two would otherwise be
 * declared-but-never-defined on this build and fail to link the moment
 * `execute()` calls them -- so THIS header supplies an inline foreign-OS stub
 * for whichever two are not the current build's own OS, keeping a single-OS
 * build always linkable without any per-OS TU ever writing a stub for a
 * platform it doesn't own.
 *
 * P11 (this file) never performs an OS read, never spawns anything: the
 * stub below does exactly one thing, walk the static kSourceCatalog and emit
 * the honest "not on this build" status line for every source that belongs
 * to the OS it stands in for.
 */
#pragma once

#include "autoruns_catalog.hpp"
#include "autoruns_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <cstddef>
#include <string_view>

namespace yuzu::autoruns {

namespace detail {

/// Emits `source|<id>|unsupported|0|foreign_os` for every SourceDecl whose
/// `os_field` is NOT YUZU_SUPPORT_UNSUPPORTED -- i.e. every source that
/// genuinely belongs to the OS this stub stands in for. A source foreign to
/// THAT OS too (os_field already UNSUPPORTED) is left to whichever stub DOES
/// own it, so no source is ever reported twice.
inline int emit_foreign_os(yuzu::CommandContext& ctx, YuzuSupportLevel SourceDecl::*os_field) {
    for (const auto& decl : kSourceCatalog) {
        if (decl.*os_field == YUZU_SUPPORT_UNSUPPORTED) continue;
        ctx.write_output(format_source_status(decl.id, YUZU_SUPPORT_UNSUPPORTED, std::size_t{0},
                                              "foreign_os"));
    }
    return 0;
}

} // namespace detail

#if defined(_WIN32)
/// Real definition: agents/plugins/autoruns/src/autoruns_win.cpp (P12).
int collect_windows(yuzu::CommandContext& ctx, std::string_view filter);
#else
inline int collect_windows(yuzu::CommandContext& ctx, std::string_view /*filter*/) {
    return detail::emit_foreign_os(ctx, &SourceDecl::windows);
}
#endif

#if defined(__linux__)
/// Real definition: agents/plugins/autoruns/src/autoruns_linux.cpp (P13).
int collect_linux(yuzu::CommandContext& ctx, std::string_view filter);
#else
inline int collect_linux(yuzu::CommandContext& ctx, std::string_view /*filter*/) {
    return detail::emit_foreign_os(ctx, &SourceDecl::linux);
}
#endif

#if defined(__APPLE__)
/// Real definition: agents/plugins/autoruns/src/autoruns_macos.cpp (P14).
int collect_macos(yuzu::CommandContext& ctx, std::string_view filter);
#else
inline int collect_macos(yuzu::CommandContext& ctx, std::string_view /*filter*/) {
    return detail::emit_foreign_os(ctx, &SourceDecl::macos);
}
#endif

} // namespace yuzu::autoruns
