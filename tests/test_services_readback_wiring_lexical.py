#!/usr/bin/env python3
"""WP13 lexical pin: Linux `services.set_start_mode` verifies its work through the closed-set,
ran-to-completion readback and reports the state.

test_services_parsers.cpp tests start_mode_took_effect / start_mode_readback_matches in
isolation; nothing executes the Linux set_start_mode body (it needs a real systemd and a root
wrapper), so reverting the CALL SITE to the weak form would stay green. Pinned in
agents/plugins/services/src/services_plugin.cpp (comments, `#if 0` blocks and string-literal
contents removed first; tests/cpp_lex_helper.py):

  1. the readback verdict is `start_mode_readback_matches(mode, st)` (never the bare state test
     `start_mode_took_effect(`, which cannot see a readback that did not run);
  2. the `is-enabled` readback runs with stderr NOT merged (`run_command({..}, false)`): a SysV
     unit's "not a native service, redirecting" line is stderr and would otherwise be the first
     line of the state;
  3. the success path emits the `state|{}` line and consults `start_state_is_unchangeable`;
  4. INSIDE that unchangeable branch the plugin sets CONSTRAINED/PARTIAL with provenance
     `services:start_mode_unchangeable` (a prose `note|` alone is invisible to a machine reader
     that sees `status|ok`); the return code stays 0. This is checked STRUCTURALLY by
     u2_problems(): the `do_set_start_mode_linux` body is brace-matched; it must hold exactly one
     un-negated `if (start_state_is_unchangeable(state)) {` with no `&&`/`||`; the call must be the
     branch's only set_result_status, at depth 0, with no return/goto/throw/branching before it;
     and after the branch the function must close its block and `return 0;`. A plain regex pin was
     false-green for 11 mutations (call moved after the branch, in an else, under `if (false)`,
     `return 1;`, an early `return 0;`, under getenv, in an uncalled lambda, in `while (0)`...).

The self-test mutates each pin (revert, hide in a block comment / string / `#if 0`) and requires
a failure. Lexical only.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import cpp_lex_helper as lexh  # noqa: E402

SRC = ROOT / "agents" / "plugins" / "services" / "src" / "services_plugin.cpp"
CALL = "if (!yuzu::services::start_mode_readback_matches(mode, st)) {"
RUN = '''auto st = run_command({std::string{systemctl_path}, "is-enabled", "--", std::string(name)},
                              /*merge_stderr=*/false);'''


def _match_brace(t, open_idx):
    d = 0
    for k in range(open_idx, len(t)):
        if t[k] == "{":
            d += 1
        elif t[k] == "}":
            d -= 1
            if d == 0:
                return k
    return -1


_CALL = re.compile(r'set_result_status\(\s*YUZU_RESULT_STATUS_CONSTRAINED,\s*YUZU_RESULT_COMPLETENESS_PARTIAL,'
                   r'\s*""\s*\)\s*;')
_CTRL = re.compile(r'\b(return|goto|throw|if|else|for|while|switch|break|continue|do|try)\b')


def u2_problems(src):
    """Structural pin of the unchangeable-unit CONSTRAINED status (see the module docstring)."""
    t = lexh.code_only(src)  # comments, #if 0 and string contents gone; braces are structural
    live = lexh.live_text(src)
    out = []
    if live.count('"services:start_mode_unchangeable"') != 1:
        out.append("provenance token services:start_mode_unchangeable must appear exactly once in live code")
    m = re.search(r'\bint\s+do_set_start_mode_linux\s*\([^)]*\)\s*\{', t)
    if not m:
        return out + ["do_set_start_mode_linux not found"]
    fe = _match_brace(t, m.end() - 1)
    fb = t[m.end():fe]
    ifs = list(re.finditer(r'\bif\s*\(\s*yuzu::services::start_state_is_unchangeable\(\s*state\s*\)\s*\)\s*\{', fb))
    if len(ifs) != 1:
        return out + [f"expected exactly one un-negated `if (start_state_is_unchangeable(state)) {{` in the Linux "
                      f"body (no &&/||), found {len(ifs)}"]
    b = ifs[0]
    cb = _match_brace(fb, b.end() - 1)
    body = fb[b.end():cb]
    cm = _CALL.search(body)
    if not cm:
        out.append("the unchangeable branch lacks the CONSTRAINED/PARTIAL set_result_status call")
    else:
        pre = body[:cm.start()]
        if re.search(r'[{}]', pre) or _CTRL.search(pre):
            out.append("control flow or a nested block before the status call inside the unchangeable branch")
        if body.count("set_result_status") != 1:
            out.append("the unchangeable branch must contain exactly one set_result_status")
        if re.search(r'[{}]', body[cm.start():]):
            out.append("the status call is inside a nested block")
    if not re.match(r'\}\s*\}\s*return 0;\s*$', fb[cb:]):
        out.append("after the branch the function must close the block then `return 0;` and end (no else, no return 1)")
    j = fb.rfind("st_state = st.output;", 0, b.start())
    if j < 0:
        out.append("success-path anchor `st_state = st.output;` missing")
    elif re.search(r'\b(return|goto|throw)\b', fb[j:b.start()]):
        out.append("early exit between the readback and the unchangeable branch")
    return out


def problems(src):
    code = lexh.code_only(src)
    live = lexh.live_text(src)  # string contents kept
    out = []
    if not re.search(r"start_mode_readback_matches\( ?mode, ?st ?\)", code):
        out.append("set_start_mode no longer judges the readback with start_mode_readback_matches(mode, st)")
    if re.search(r"start_mode_took_effect\(", code):
        out.append("services_plugin.cpp calls the bare start_mode_took_effect( (cannot see a readback that did not run)")
    if not re.search(r'auto st = run_command\( ?\{ ?std::string\{ ?systemctl_path ?\}, "", "", std::string\( ?name ?\) ?\}, ?false ?\)', code):
        out.append("the is-enabled readback is not run with stderr unmerged: run_command({..}, false)")
    if '"state|{}"' not in live:
        out.append('the success path no longer emits the "state|{}" line')
    if not re.search(r"start_state_is_unchangeable\(", code):
        out.append("the success path no longer consults start_state_is_unchangeable")
    if not re.search(
            r"start_state_is_unchangeable\(state\)\)\s*\{[\s\S]{0,1200}?set_result_status\(\s*YUZU_RESULT_STATUS_CONSTRAINED,"
            r"\s*YUZU_RESULT_COMPLETENESS_PARTIAL,\s*\"services:start_mode_unchangeable\"\s*\)", live):
        out.append("the unchangeable branch no longer sets CONSTRAINED/PARTIAL services:start_mode_unchangeable")
    if not re.search(r"if \(yuzu::services::start_mode_needs_unmask\(mode\)\) \{", code):
        out.append("the unmask-first plan no longer comes from start_mode_needs_unmask(mode) (automatic must unmask)")
    if re.search(r'mode == "manual"\)\s*\{[^}]*unmask', code):
        out.append("unmask is gated on mode == manual only: mask -> automatic would fail")
    if len(re.findall(r"remask_after_failure\(\);", code)) != 2:
        out.append("both failure paths (change failed, readback mismatch) must call remask_after_failure()")
    if not re.search(r"start_mode_should_remask\( ?mode, was_masked,", code):
        out.append("remask_after_failure no longer consults start_mode_should_remask(mode, was_masked, ...)")
    return out + u2_problems(src)


def u2_mutations(src):
    """name -> mutated source; each must make problems() non-empty. Each replacement must change
    the text (a stale anchor fails loudly)."""
    call = re.search(r'ctx\.set_result_status\(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,\s*'
                     r'"services:start_mode_unchangeable"\);', src).group(0)
    tail = "        }\n    }\n    return 0;\n}\n\n#elif defined(__APPLE__)"
    br = "if (yuzu::services::start_state_is_unchangeable(state)) {"
    first = "        std::string state = st_state.substr(0, st_state.find('\\n'));"

    def rep(a, b, s_=src):
        assert a in s_, f"stale mutation anchor: {a[:50]!r}"
        return s_.replace(a, b, 1)

    no_call = rep(call, "")
    return {
        "call moved after the branch's closing brace": rep(tail, "        }\n    " + call + "\n    }\n    return 0;\n}\n\n#elif defined(__APPLE__)", no_call),
        "final return 0 -> return 1": rep("    }\n    return 0;\n}\n\n#elif defined(__APPLE__)", "    }\n    return 1;\n}\n\n#elif defined(__APPLE__)"),
        "early return 0 before the call": rep(call, "return 0;\n            " + call),
        "call in an else": rep(tail, "        } else {\n            " + call + "\n        }\n    }\n    return 0;\n}\n\n#elif defined(__APPLE__)", no_call),
        "under if (false)": rep(call, "if (false) { " + call + " }"),
        "branch condition inverted": rep(br, "if (!yuzu::services::start_state_is_unchangeable(state)) {"),
        "early return before the branch": rep(first, "        return 0;\n" + first),
        "under getenv": rep(call, 'if (std::getenv("X")) ' + call),
        "in an uncalled lambda": rep(call, "[&]{ " + call + " };"),
        "in while (0)": rep(call, "while (0) { " + call + " break; }"),
        "branch condition widened with &&": rep(br, "if (yuzu::services::start_state_is_unchangeable(state) && false) {"),
    }


def selftest(src):
    hide = {
        "block comment": lambda t: "/* " + t + " */",
        "string literal": lambda t: '"' + t.replace('"', "'") + '"',
        "#if 0": lambda t: "\n#if 0\n" + t + "\n#endif\n",
    }
    errs = []
    for tok in (CALL, RUN, '"state|{}"', "start_state_is_unchangeable("):
        if tok not in src:
            errs.append(f"selftest: pinned text not found (stale): {tok[:50]!r}")
            continue
        for name, fn in hide.items():
            if not problems(src.replace(tok, fn(tok), 1)):
                errs.append(f"selftest: hiding {tok[:40]!r} in a {name} was NOT detected")
    # revert to the weak verdict
    weak = src.replace(CALL, "if (!yuzu::services::start_mode_took_effect(mode, st.output)) {", 1)
    if weak == src or not problems(weak):
        errs.append("selftest: reverting to start_mode_took_effect(mode, st.output) was NOT detected")
    no_status = re.sub(r"ctx\.set_result_status\(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,\s*"
                       r"\"services:start_mode_unchangeable\"\);", "", src, count=1)
    if no_status == src or not problems(no_status):
        errs.append("selftest: deleting the unchangeable CONSTRAINED status was NOT detected")
    for hname, fn in hide.items():
        m = re.search(r"ctx\.set_result_status\(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,\s*"
                      r"\"services:start_mode_unchangeable\"\);", src)
        if m and not problems(src[:m.start()] + fn(m.group(0)) + src[m.end():]):
            errs.append(f"selftest: hiding the unchangeable status in a {hname} was NOT detected")
    m1 = src.replace("if (yuzu::services::start_mode_needs_unmask(mode)) {", 'if (mode == "manual") {', 1)
    if m1 == src or not problems(m1):
        errs.append("selftest: reverting the unmask plan to mode == manual was NOT detected")
    idx = src.rfind("remask_after_failure();")
    m2 = src[:idx] + src[idx + len("remask_after_failure();"):]
    if idx < 0 or not problems(m2):
        errs.append("selftest: dropping a remask_after_failure() call was NOT detected")
    for name, mutated in u2_mutations(src).items():
        if not problems(mutated):
            errs.append(f"selftest: U2 mutation '{name}' was NOT detected")
    k = src.index(RUN)
    merged = src[:k] + src[k:].replace("/*merge_stderr=*/false", "/*merge_stderr=*/true", 1)
    if merged == src or not problems(merged):
        errs.append("selftest: merging stderr into the readback was NOT detected")
    return errs


def main():
    src = SRC.read_text(encoding="utf-8")
    errs = problems(src) + selftest(src)
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
