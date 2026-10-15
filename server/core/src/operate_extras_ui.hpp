#pragma once

/// @file operate_extras_ui.hpp
/// Page CSS shared by the Dashboard and Result sets extras (operate-extras
/// stream). Every selector is `ox-` prefixed so it cannot collide with
/// yuzu.css or a page's own inline rules, and every colour is a design token.
///
/// This is a macro, not a variable, on purpose: both page templates are one
/// chain of adjacent raw-string literals (split to stay under MSVC's C2026
/// 16,380-byte literal cap), and a macro expanding to a literal is the only
/// way to splice a shared chunk into that chain at compile time. Keep the
/// literal under 16,000 bytes (tools/rawcheck.py enforces it).
///
/// Used as:  "...<style>\n" YUZU_OX_CSS "</style>..."

/// The instruction-parameter keys whose typed values the extras script masks wherever it echoes
/// the command back (confirm dialog, history). Spliced into <body data-secret-params> so the
/// script keeps no list of its own; test_operate_extras_ui.cpp pins it equal to
/// kRedactedInstructionParamKeys (sensitive_instruction_params.hpp), the server's classification.
#define YUZU_OX_SECRET_PARAMS "grant_secret,grant_id,client_secret"

#define YUZU_OX_CSS                                                                              \
    R"OXC(.ox-panel{flex:none;max-height:46%;overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
.ox-panel>h2{font-size:14px;font-weight:600;padding:12px 16px;border-bottom:1px solid var(--line);color:var(--ink)}
.ox-pad{padding:10px 16px;display:flex;flex-direction:column;gap:8px}
.ox-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.ox-in{flex:1 1 140px;min-width:0;height:var(--ctl);padding:0 10px;background:var(--bg);color:var(--ink);border:1px solid var(--line2);border-radius:var(--rad-ctl);font-family:var(--mds-font-family-mono);font-size:12.5px}
.ox-btn{height:28px;padding:0 10px;font:inherit;font-size:13px;font-weight:500;cursor:pointer;color:var(--ink);background:var(--raise);border:1px solid var(--line2);border-radius:var(--rad-ctl)}
.ox-btn:hover{background:var(--surface2);border-color:var(--mut)}
.ox-btn:disabled{opacity:.4;cursor:not-allowed}
.ox-btn.pri{background:var(--primary);color:var(--on-primary);border-color:var(--primary);font-weight:600}
.ox-btn.bad{background:var(--bad);color:var(--on-primary);border-color:var(--bad);font-weight:600}
.ox-hint{color:var(--mut);font-size:12.5px}
.ox-note{padding:8px 10px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--surface2);color:var(--ink2);font-size:13px;overflow-wrap:anywhere}
.ox-note.ok{border-color:color-mix(in srgb,var(--ok) 50%,var(--line2));background:var(--mds-color-bg-success-tinted)}
.ox-note.bad{border-color:color-mix(in srgb,var(--bad) 50%,var(--line2));background:var(--mds-color-bg-error-tinted)}
.ox-note.warn{border-color:color-mix(in srgb,var(--warn) 50%,var(--line2))}
.ox-ids{margin:0;padding:0;list-style:none;display:grid;gap:2px;font-family:var(--mds-font-family-mono);font-size:12px;color:var(--ink2)}
.ox-facts{margin:0;border:1px solid var(--line);border-radius:var(--rad-panel);background:var(--surface)}
.ox-facts>div{display:flex;justify-content:space-between;gap:16px;padding:8px 12px;border-bottom:1px solid var(--line)}
.ox-facts>div:last-child{border-bottom:0}
.ox-facts dt{color:var(--mut)}
.ox-facts dd{margin:0;color:var(--ink);text-align:right;overflow-wrap:anywhere}
.ox-sql{margin:0;padding:8px 10px;background:var(--bg);border:1px solid var(--line);border-radius:var(--rad-ctl);color:var(--ink2);font-family:var(--mds-font-family-mono);font-size:12.5px;white-space:pre-wrap;overflow-wrap:anywhere}
)OXC"
