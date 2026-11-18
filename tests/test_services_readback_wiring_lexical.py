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
  3. the success path emits the `state|{}` line and consults `start_state_is_unchangeable`.

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
RUN = '''auto st = run_command({systemctl_path, "is-enabled", "--", std::string(name)},
                              /*merge_stderr=*/false);'''


def problems(src):
    code = lexh.code_only(src)
    live = lexh.lex(lexh.drop_if0(src))  # string contents kept
    out = []
    if not re.search(r"start_mode_readback_matches\( ?mode, ?st ?\)", code):
        out.append("set_start_mode no longer judges the readback with start_mode_readback_matches(mode, st)")
    if re.search(r"start_mode_took_effect\(", code):
        out.append("services_plugin.cpp calls the bare start_mode_took_effect( (cannot see a readback that did not run)")
    if not re.search(r'run_command\( ?\{ ?systemctl_path, "", "", std::string\( ?name ?\) ?\}, ?false ?\)', code):
        out.append("the is-enabled readback is not run with stderr unmerged: run_command({..}, false)")
    if '"state|{}"' not in live:
        out.append('the success path no longer emits the "state|{}" line')
    if not re.search(r"start_state_is_unchangeable\(", code):
        out.append("the success path no longer consults start_state_is_unchangeable")
    return out


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
    merged = src.replace("/*merge_stderr=*/false", "/*merge_stderr=*/true", 1)
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
