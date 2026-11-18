#!/usr/bin/env python3
"""WP13 lexical pin: Linux `services.set_start_mode` verifies its work through the closed-set,
ran-to-completion readback and reports the state.

SECOND LAYER. The Linux set_start_mode body lives in agents/plugins/services/src/
services_set_start_mode.hpp behind a runner seam and is executed with a FAKE runner by the
`[setmode]` Catch2 cases in tests/unit/test_services_parsers.cpp (the primary, behavioural
tests; the 13 negations of the fixes that this gate once let through are RED there). This gate
pins the same body's shape in the header (comments, `#if 0` blocks and string-literal contents
removed first; tests/cpp_lex_helper.py) and that the plugin calls the body:

  1. the readback verdict is `start_mode_readback_matches(mode, st)` (never the bare state test
     `start_mode_took_effect(`, which cannot see a readback that did not run);
  2. the `is-enabled` readback runs with stderr NOT merged (`run_command({..}, false)`): a SysV
     unit's "not a native service, redirecting" line is stderr and would otherwise be the first
     line of the state;
  3. the success path emits the `state|{}` line and consults `start_state_is_unchangeable`;
  4. INSIDE that unchangeable branch the plugin sets CONSTRAINED/PARTIAL with provenance
     `services:start_mode_unchangeable` (a prose `note|` alone is invisible to a machine reader
     that sees `status|ok`); the return code stays 0. This is checked STRUCTURALLY by
     u2_problems(): the `set_start_mode_linux` body is brace-matched; it must hold exactly one
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

SRC = ROOT / "agents" / "plugins" / "services" / "src" / "services_set_start_mode.hpp"
PLUGIN = ROOT / "agents" / "plugins" / "services" / "src" / "services_plugin.cpp"
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
    m = re.search(r'\bint\s+set_start_mode_linux\s*\([^)]*\)\s*\{', t)
    if not m:
        return out + ["set_start_mode_linux not found"]
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
    out += body_pins(live)
    return out + u2_problems(src)


_BODY_PINS = {
    "was_masked comes from the prior read that ran (tool_ran, not timed out) and start_state_is_masked":
        r"was_masked\s*=\s*prior\.tool_ran\s*&&\s*!prior\.timed_out\s*&&\s*yuzu::services::start_state_is_masked\(\s*prior\.output\s*\)\s*;",
    "the prior is-enabled read is unmerged and uses `--`":
        r'const auto prior = run_command\(\{std::string\{systemctl_path\}, "is-enabled", "--",\s*std::string\(name\)\},\s*(?:/\*[^*]*\*/\s*)?false\)',
    "the re-mask runs the helper's mask verb":
        r'auto remask_after_failure = \[&\]\(\) \{[\s\S]{0,400}?const auto r = run_command\(build\("mask"\)\);',
    "note|remasked is written only when the re-mask ran, did not time out and exited 0":
        r'if \(r\.tool_ran && !r\.timed_out && r\.exit_code == 0\)\s*ctx\.write_output\(std::format\("note\|remasked:',
    "remask_after_failure asks for a re-mask of a FAILED change":
        r"start_mode_should_remask\(mode, was_masked,\s*(?:/\*[^*]*\*/\s*)?false\)",
    "the readback is is-enabled with `--`, unmerged":
        r'auto st = run_command\(\{std::string\{systemctl_path\}, "is-enabled", "--", std::string\(name\)\},\s*(?:/\*[^*]*\*/\s*)?false\)',
    "the readback-mismatch branch re-masks BEFORE its return":
        r"name, mode, st\.output\.substr\(0, st\.output\.find\([^)]*\)\)\)\);\s*remask_after_failure\(\);\s*return 1;\s*\}\s*st_state = st\.output;",
    "the failed-change branch re-masks BEFORE its return":
        r"ctx\.write_output\(outcome\.message\);\s*remask_after_failure\(\);\s*return 1;\s*\}",
    "the unmask call is the helper's unmask":
        r'run_command\(build\("unmask"\)\);',
    "masked-runtime is refused up front, before the unmask, with the typed CONSTRAINED token and rc 1":
        r'start_state_is_runtime_masked\(\s*prior\.output\s*\)\)\s*\{[\s\S]{0,300}?set_result_status\(YUZU_RESULT_STATUS_CONSTRAINED,'
        r'\s*YUZU_RESULT_COMPLETENESS_PARTIAL,\s*"services:start_mode_runtime_mask"\)[\s\S]{0,700}?return 1;\s*\}\s*run_command\(build\("unmask"\)\);',
}


def body_pins(live):
    """Body-level pins over live_text() (comments and #if 0 gone, strings kept): the prior read,
    the was_masked derivation, the re-mask verb and note, the readback verb, the unmask call and
    the masked-runtime refusal. Each regex matches the current source; u2_body_mutations() kills them."""
    return [f"body pin lost: {name}" for name, pat in _BODY_PINS.items() if not re.search(pat, live)]


def u2_mutations(src):
    """name -> mutated source; each must make problems() non-empty. Each replacement must change
    the text (a stale anchor fails loudly)."""
    call = re.search(r'ctx\.set_result_status\(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,\s*'
                     r'"services:start_mode_unchangeable"\);', src).group(0)
    tail = "        }\n    }\n    return 0;\n}\n\n} // namespace yuzu::services"
    br = "if (yuzu::services::start_state_is_unchangeable(state)) {"
    first = "        std::string state = st_state.substr(0, st_state.find('\\n'));"

    def rep(a, b, s_=src):
        assert a in s_, f"stale mutation anchor: {a[:50]!r}"
        return s_.replace(a, b, 1)

    no_call = rep(call, "")
    return {
        "call moved after the branch's closing brace": rep(tail, "        }\n    " + call + "\n    }\n    return 0;\n}\n\n} // namespace yuzu::services", no_call),
        "final return 0 -> return 1": rep("    }\n    return 0;\n}\n\n} // namespace yuzu::services", "    }\n    return 1;\n}\n\n} // namespace yuzu::services"),
        "early return 0 before the call": rep(call, "return 0;\n            " + call),
        "call in an else": rep(tail, "        } else {\n            " + call + "\n        }\n    }\n    return 0;\n}\n\n} // namespace yuzu::services", no_call),
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
    def rep(a_, b_):
        if a_ not in src:
            errs.append(f"selftest: body-mutation anchor not found (stale): {a_[:50]!r}")
            return None
        return src.replace(a_, b_, 1)
    body_muts = {
        "was_masked = true": rep("was_masked = prior.tool_ran && !prior.timed_out &&\n                     yuzu::services::start_state_is_masked(prior.output);", "was_masked = true;"),
        "prior tool_ran dropped": rep("prior.tool_ran && !prior.timed_out &&\n                     ", "!prior.timed_out &&\n                     "),
        "remask runs unmask": rep('const auto r = run_command(build("mask"));', 'const auto r = run_command(build("unmask"));'),
        "remask runs disable": rep('const auto r = run_command(build("mask"));', 'const auto r = run_command(build("disable"));'),
        "note remasked unconditional": rep("if (r.tool_ran && !r.timed_out && r.exit_code == 0)", "if (true)"),
        "exit_code check dropped": rep("r.tool_ran && !r.timed_out && r.exit_code == 0", "r.tool_ran"),
        "readback verb is-enabled -> status": rep('"is-enabled", "--", std::string(name)},\n                              /*merge_stderr=*/false);', '"status", "--", std::string(name)},\n                              /*merge_stderr=*/false);'),
        "mismatch branch: remask after its return": src.replace("            remask_after_failure();\n            return 1;\n        }\n        st_state","            return 1;\n            remask_after_failure();\n        }\n        st_state",1),
        "unmask removed": rep('run_command(build("unmask"));', ";"),
        "prior merges stderr": rep('std::string(name)},\n                                       /*merge_stderr=*/false);', 'std::string(name)},\n                                       /*merge_stderr=*/true);'),
        "change_succeeded true": rep("/*change_succeeded=*/false", "/*change_succeeded=*/true"),
        "readback loses `--`": rep('"is-enabled", "--", std::string(name)},\n                              /*merge_stderr=*/false);', '"is-enabled", std::string(name)},\n                              /*merge_stderr=*/false);'),
        "runtime-mask refusal removed": rep('services:start_mode_runtime_mask', 'services:other'),
        "runtime-mask refusal does not return": src.replace("                name, mode));\n            return 1;\n        }\n        run_command(build(\"unmask\"));", "                name, mode));\n        }\n        run_command(build(\"unmask\"));", 1),
        "unmask before the runtime-mask check": src.replace('        run_command(build("unmask"));\n    }', '    }', 1).replace("        if (prior.tool_ran && !prior.timed_out &&\n            yuzu::services::start_state_is_runtime_masked", '        run_command(build("unmask"));\n        if (prior.tool_ran && !prior.timed_out &&\n            yuzu::services::start_state_is_runtime_masked', 1),
    }
    for name, mutated in body_muts.items():
        if mutated is None:
            continue
        if mutated == src:
            errs.append(f"selftest: body mutation '{name}' did not change the source (stale)")
        elif not problems(mutated):
            errs.append(f"selftest: body mutation '{name}' was NOT detected")
    for name, mutated in u2_mutations(src).items():
        if not problems(mutated):
            errs.append(f"selftest: U2 mutation '{name}' was NOT detected")
    k = src.index(RUN)
    merged = src[:k] + src[k:].replace("/*merge_stderr=*/false", "/*merge_stderr=*/true", 1)
    if merged == src or not problems(merged):
        errs.append("selftest: merging stderr into the readback was NOT detected")
    return errs


def plugin_problems(plugin_src):
    code = lexh.code_only(plugin_src)
    out = []
    if not re.search(r"return yuzu::services::set_start_mode_linux\(", code):
        out.append("do_set_start_mode_linux no longer returns yuzu::services::set_start_mode_linux(...)")
    if re.search(r"start_mode_readback_matches|start_mode_took_effect", code):
        out.append("services_plugin.cpp carries its own readback logic again; it belongs in the seam header")
    return out


def main():
    src = SRC.read_text(encoding="utf-8")
    plug = PLUGIN.read_text(encoding="utf-8")
    errs = problems(src) + plugin_problems(plug) + selftest(src)
    hidden = plug.replace("return yuzu::services::set_start_mode_linux(", "return 0; // set_start_mode_linux(", 1)
    if hidden == plug or not plugin_problems(hidden):
        errs.append("selftest: the plugin no longer calling the seam body was NOT detected")
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
