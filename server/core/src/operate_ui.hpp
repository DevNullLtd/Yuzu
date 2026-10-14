#pragma once

/// @file operate_ui.hpp
/// Page-local CSS shared by the two Operate pages (Approvals, Executions).
///
/// Why not `yuzu.css`: these rules are page layout, not design primitives, and Phase 1's
/// convention is page-local CSS built from the design tokens; keeping `yuzu.css` untouched
/// also removes a shared-file conflict with the Access pages. Everything else the pages
/// use (`.panel .hd .pill .seg .kvl .tw .chip .btn .btns .page-header`) comes from
/// `yuzu.css`; this block only adds what that file lacks.
///
/// Rules of the block (pinned by test_operate_pages_ui.cpp):
///   * tokens only: no hex colour, no `box-shadow`, no literal `font-family`;
///   * one raw literal, comfortably under MSVC's 16,380-byte C2026 limit;
///   * the `ops-*` class family belongs to Operate: Access must not reuse it.
///
/// The text is the CONTENT of a `<style>` element; the page templates add the tags.

#include <string_view>

namespace yuzu::server {

inline constexpr std::string_view kOperateCss = R"CSS(
[hidden]{display:none!important}
.pg{padding:22px 28px 36px;display:flex;flex-direction:column;gap:20px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.empty-state{color:var(--mut);text-align:center;padding:32px 16px;font-size:13.5px}
.panel>.empty-state{background:none;border:0}
.hint{color:var(--mut);font-size:12.5px}
code{font-family:var(--mds-font-family-mono);font-size:12.5px}
.clip{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
.tag{display:inline-block;margin-left:6px;padding:0 6px;border-radius:3px;background:var(--surface2);border:1px solid var(--line2);color:var(--mut);font-size:11px;font-weight:600;vertical-align:1px}
.ops-grid{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:20px;align-items:start}
.ops-main,.ops-side{display:flex;flex-direction:column;gap:20px;min-width:0}
.ops-side{position:sticky;top:20px}
@media (max-width:1180px){
.ops-grid{display:flex;flex-direction:column;align-items:stretch;gap:20px}
.ops-main,.ops-side{display:contents}
.ops-grid .ops-listbox{order:1}
.ops-grid .ops-sel{order:2}
}
.panel .hd .chip{font-weight:400}
.ops-bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;padding:12px 16px;border-bottom:1px solid var(--line)}
.ops-list tr.row{cursor:pointer}
.ops-list tr.row:focus-visible{outline:2px solid var(--focus);outline-offset:-2px}
.ops-list table th,.ops-list table td{padding-left:12px;padding-right:12px}
.nm{display:block;max-width:196px;overflow:hidden;text-overflow:ellipsis;font-weight:600;color:var(--ink)}
.sub{display:block;max-width:196px;overflow:hidden;text-overflow:ellipsis;font-size:12px;color:var(--faint)}
.sub.mono{font-size:11.5px}
.tm{font-size:13px;color:var(--mut)}
td .scope{max-width:150px}
td .by{max-width:140px}
.ops-foot{padding:10px 16px;border-top:1px solid var(--line)}
.ops-sel [data-slot]>.hd{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:12px 16px;border-bottom:1px solid var(--line)}
.ops-sel [data-slot]>.hd h2{font-size:14px;font-weight:600}
.pv{display:block;max-width:132px;overflow:hidden;text-overflow:ellipsis;font-family:var(--mds-font-family-mono);font-size:12px;color:var(--bad)}
.empty-more{padding:0 16px 24px;text-align:center}
.prog{display:flex;flex-direction:column;gap:6px;padding:12px 16px 0}
.lnk{color:var(--primary);text-decoration:none}
.lnk:hover{color:var(--primary-h);text-decoration:underline}
.ops-sel [data-slot]>.btns{padding-top:16px}
.ops-sel .kvl small{display:block;font-size:11.5px;font-weight:400;color:var(--faint);text-align:right;overflow-wrap:anywhere}
.ops-sel .kvl b .clip{max-width:230px}
.ops-sel .kvl>div.stack{flex-direction:column;gap:6px}
.ops-sel .kvl code.blk,.ops-sel .kvl .cmt{display:block;padding:6px 8px;background:var(--bg);border:1px solid var(--line);border-radius:var(--rad-ctl);color:var(--ink2);white-space:pre-wrap;word-break:break-all;font-size:12.5px;text-align:left}
.ops-sel .kvl .cmt{font-family:var(--font);word-break:normal;overflow-wrap:anywhere}
.ops-sel .kvl .stack>.faint{font-size:13px}
.ops-sel>.btns{padding-top:16px}
.held{margin:0 16px 16px;padding:10px 12px;border:1px solid var(--line2);border-radius:var(--rad-panel);background:var(--surface2);color:var(--ink2);font-size:12.5px;display:flex;flex-direction:column;gap:4px}
.ops-sel>.btns+.held{margin-top:0}
.ops-sel>.kvl+.held{margin-top:16px}
.ops-dev [data-slot]>.hd{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:12px 16px;border-bottom:1px solid var(--line)}
.ops-dev .hd h2{font-size:14px;font-weight:600}
.ops-dev .hd .sub{display:inline;max-width:none}
.ops-dev .hd .end{margin-left:auto}
.readout.kpi{border-width:0 0 1px;border-radius:0}
.readout.kpi .ro{padding:12px 16px;flex-basis:110px}
.readout.kpi .v{font-size:22px}
.agrid-wrap{padding:14px 16px 4px}
.agent-grid{display:grid;grid-template-columns:repeat(auto-fill,12px);gap:2px;max-height:200px;overflow-y:auto}
.agent-cell{width:12px;height:12px;border-radius:2px;cursor:pointer}
.agent-cell--bucket{width:auto;height:18px;display:flex;align-items:center;justify-content:center;font-size:12px;color:var(--bg);padding:0 6px;border-radius:3px}
.agent-cell--succeeded{background:var(--ok)}
.agent-cell--failed{background:var(--bad)}
.agent-cell--running{background:var(--info)}
.agent-cell--pending{background:var(--mut);opacity:.4}
.ops-dev .tw{margin-top:10px}
table.pa th,table.pa td{padding:7px 12px;font-size:13px}
table.pa td.er{min-width:150px;max-width:240px;white-space:normal;overflow-wrap:anywhere;font-family:var(--mds-font-family-mono);font-size:12px;color:var(--bad)}
table.pa td code{font-size:12px;color:var(--ink2)}
table.pa td code.clip{max-width:262px}
.dbar{display:inline-block;height:6px;border-radius:2px;vertical-align:middle;min-width:3px}
.dbar--succeeded{background:var(--ok)}
.dbar--failed{background:var(--bad)}
.dbar--running{background:var(--info)}
.dbar--pending{background:var(--mut);opacity:.4}
.dtx{font-size:12px;color:var(--mut);margin-left:8px}
details.resp{border-top:1px solid var(--line);padding:10px 16px}
details.resp summary{cursor:pointer;font-size:13px;color:var(--mut)}
.resp-output pre{margin:6px 0;padding:8px;background:var(--bg);border:1px solid var(--line);border-radius:var(--rad-ctl);max-height:200px;overflow:auto;white-space:pre-wrap;font-family:var(--mds-font-family-mono);font-size:12.5px}
.ops-cap-note{padding:8px 16px}
@media (max-width:820px){
.pg{padding:16px}
.nm,.sub{max-width:200px}
}
)CSS";

// MSVC rejects a raw literal over 16,380 bytes (C2026); stay well under it. Executions adds
// its own rules to this block, so this fails the build before the page does.
static_assert(kOperateCss.size() < 15000, "kOperateCss outgrew the MSVC raw-literal bound");

} // namespace yuzu::server
