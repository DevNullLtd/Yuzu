#!/usr/bin/env python3
"""Lexical tripwire: the process_introspect plugin must never request a task port.

A Mach task port is a write-capable handle on the target process. The macOS leg reads another
process through libproc only (one proc_pidinfo(PROC_PIDTBSDINFO) call) and the boot identity
through one sysctlbyname name. Nothing in the plugin may widen that without a new design note
(.claude/routed-concerns-software-estate.md, process_introspect row, clause 6).

Best-effort text pins over the plugin's C/C++ sources, read through cpp_lex_helper.lex (comments
removed, adjacent string literals joined): a name built at run time or reached by indirection is
not caught. Checks, over agents/plugins/process_introspect/src/*.cpp and *.hpp:
  1. no whole-word task or Mach VM call (task_for_pid and its variants, mach_vm_*, vm_read,
     task_threads, task_info, processor_set_tasks, ...);
  2. no #include <mach/...>, no dlsym or dlopen, no ptrace, no ReadProcessMemory, no subprocess
     runner, no string literal ending /mem;
  3. libproc allow-list: the only PROC_PID* tokens are PROC_PIDTBSDINFO and
     PROC_PIDTBSDINFO_SIZE, and no proc_pidpath, proc_name, proc_regionfilename, proc_pidfdinfo,
     proc_listpids or proc_pid_rusage;
  4. sysctl allow-list: the only sysctlbyname name is kern.bootsessionuuid, no MIB-form
     sysctl( call, no sysctlnametomib, no KERN_PROC* / KERN_ARGMAX token (the argv and
     environment read);
  5. non-vacuity: process_introspect_macos.cpp exists and contains proc_pidinfo and
     PROC_PIDTBSDINFO, so a rename cannot make the gate pass on nothing.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cpp_lex_helper as lexh  # noqa: E402

PLUGIN = ROOT / "agents/plugins/process_introspect/src"
MACOS_TU = "process_introspect_macos.cpp"

TASK_CALLS = re.compile(
    r"\b(task_for_pid|task_read_for_pid|task_inspect_for_pid|task_name_for_pid|processor_set_tasks|"
    r"mach_vm_\w+|vm_region_64|vm_region_recurse_64|vm_read|vm_read_overwrite|task_threads|"
    r"task_info)\b")
MACH_INCLUDE = re.compile(r"#\s*include\s*[<\"]mach/")
OTHER_BANS = re.compile(r"\b(dlsym|dlopen|ptrace|ReadProcessMemory|run_bounded_subprocess|"
                        r"subprocess_runner)\b")
MEM_LITERAL = re.compile(r'"[^"\n]*/mem"')
PROC_PID_TOKEN = re.compile(r"\bPROC_PID\w*")
PROC_PID_ALLOWED = {"PROC_PIDTBSDINFO", "PROC_PIDTBSDINFO_SIZE"}
LIBPROC_BANS = re.compile(r"\b(proc_pidpath|proc_name|proc_regionfilename|proc_pidfdinfo|"
                          r"proc_listpids|proc_pid_rusage)\b")
SYSCTLBYNAME = re.compile(r"\bsysctlbyname\s*\(\s*(\"[^\"\n]*\"|[^,)]*)")
SYSCTL_ALLOWED = '"kern.bootsessionuuid"'
SYSCTL_BANS = re.compile(r"\bsysctl\s*\(|\bsysctlnametomib\b|\bKERN_PROC\w*|\bKERN_ARGMAX\b")


def findings(name: str, src: str) -> list[str]:
    """One message per violation in one source file's text (comments removed)."""
    code = lexh.lex(src)
    ident = lexh.lex(src, keep_strings=False)
    out = []
    for m in TASK_CALLS.finditer(ident):
        out.append(f"{name}: names {m.group(0)} (no task port, no Mach VM read)")
    if MACH_INCLUDE.search(code):
        out.append(f"{name}: includes a <mach/...> header")
    for m in OTHER_BANS.finditer(ident):
        out.append(f"{name}: names {m.group(0)}")
    if MEM_LITERAL.search(code):
        out.append(f"{name}: has a string literal ending /mem")
    for m in PROC_PID_TOKEN.finditer(ident):
        if m.group(0) not in PROC_PID_ALLOWED:
            out.append(f"{name}: libproc flavour {m.group(0)} is not on the allow-list")
    for m in LIBPROC_BANS.finditer(ident):
        out.append(f"{name}: names {m.group(0)} (not on the libproc allow-list)")
    for m in SYSCTLBYNAME.finditer(code):
        if m.group(1).strip() != SYSCTL_ALLOWED:
            out.append(f"{name}: sysctlbyname({m.group(1).strip()}...) is not kern.bootsessionuuid")
    for m in SYSCTL_BANS.finditer(ident):
        out.append(f"{name}: uses {m.group(0).strip()} (only sysctlbyname of kern.bootsessionuuid)")
    return out


def self_check() -> list[str]:
    """The matcher must flag the bad shapes and pass the good ones, or the gate is a no-op."""
    errs = []
    bad_shapes = (
        'kern_return_t k = task_for_pid(mach_task_self(), pid, &t);',
        'mach_vm_region(t, &a, &s, 0, nullptr, nullptr, nullptr);',
        'vm_read_overwrite(t, a, s, b, &n);',
        'task_info(t, TASK_BASIC_INFO, nullptr, nullptr);',
        '#include <mach/mach.h>',
        'void* h = dlopen("x", 0);',
        'ptrace(PT_ATTACH, pid, 0, 0);',
        'auto p = "/proc/1/mem";',
        'proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, 0, &x, n);',
        'proc_pidpath(pid, buf, n);',
        'proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEINFO, &x, n);',
        'sysctlbyname("kern.procargs2", b, &n, nullptr, 0);',
        'sysctlbyname(name, b, &n, nullptr, 0);',
        'sysctl(mib, 4, b, &n, nullptr, 0);',
        'int m[2] = {CTL_KERN, KERN_PROC};',
        'int m = KERN_ARGMAX;',
        'auto r = run_bounded_subprocess(x);',
    )
    for bad in bad_shapes:
        if not findings("self", bad):
            errs.append(f"self-check: did not flag {bad!r}")
    good_shapes = (
        'proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pbi, PROC_PIDTBSDINFO_SIZE);',
        'struct proc_bsdinfo pbi;',
        'sysctlbyname("kern.bootsessionuuid", buf, &len, nullptr, 0);',
        '// task_for_pid is banned\nint x;',
        '/* mach_vm_region too */ int y;',
        'auto d = "libproc proc_pidinfo, no task port";',
        'auto t = "task_for_pid in a descriptor string";',
        '#include <libproc.h>\n#include <sys/sysctl.h>',
    )
    for good in good_shapes:
        got = findings("self", good)
        if got:
            errs.append(f"self-check: flagged {good!r}: {got}")
    return errs


def main() -> int:
    errs = self_check()
    if errs:
        for e in errs:
            print("FAIL:", e)
        return 1
    files = sorted(list(PLUGIN.glob("*.cpp")) + list(PLUGIN.glob("*.hpp")))
    if not files:
        print(f"FAIL: no sources under {PLUGIN}")
        return 1
    macos = next((f for f in files if f.name == MACOS_TU), None)
    if macos is None:
        print(f"FAIL: {MACOS_TU} not found: the gate would pass vacuously")
        return 1
    macos_code = lexh.lex(macos.read_text(encoding="utf-8"))
    for needed in ("proc_pidinfo", "PROC_PIDTBSDINFO"):
        if needed not in macos_code:
            errs.append(f"{MACOS_TU}: no longer contains {needed}: the gate would pass vacuously")
    for f in files:
        errs += findings(f.name, f.read_text(encoding="utf-8"))
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
