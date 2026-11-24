#!/usr/bin/env python3
"""Lexical tripwire: the process_introspect plugin must never request a task port.

A Mach task port is a write-capable handle on the target process. The macOS leg reads another
process through libproc only (one proc_pidinfo(PROC_PIDTBSDINFO) call, made in agent-core's bounded
snapshot unit, which this gate scans too) and the boot identity through one sysctlbyname name. Nothing in the plugin may widen that without a new design note
(.claude/routed-concerns-software-estate.md, process_introspect row, clause 6).

Best-effort text pins over the plugin's C/C++ sources and agent-core's proc_snapshot_read.cpp
(the libproc TU), read through cpp_lex_helper.lex (comments
removed, adjacent string literals joined): a name built at run time or reached by indirection is
not caught. Checks, over every regular file under agents/plugins/process_introspect/src (no
extension list: any list is a bypass list):
  1. no whole-word task or Mach VM call (task_for_pid and its variants, every (mach_)vm_*
     identifier, task_threads, task_info, processor_set_tasks*, ...);
  2. no #include <mach/...>, no dlsym or dlopen, no ptrace, no ReadProcessMemory, no subprocess
     runner, no kill, syscall or __proc_info, no pbi_comm or pbi_name (the process name in
     proc_bsdinfo is never stored), no string literal ending /mem. Raw spawns (popen, system,
     fork, exec*, posix_spawn) are gated over every plugin by
     scripts/ci/check-plugin-spawn-lexical.sh, not here;
  3. libproc allow-list: every proc_* identifier is one of proc_pidinfo, proc_bsdinfo, proc_info
     (the include path), proc_snapshot_read (the agent-core header) or proc_visibility (the
     Linux helper), and the only PROC_PID* tokens are PROC_PIDTBSDINFO and
     PROC_PIDTBSDINFO_SIZE; every proc_pidinfo is a call of the form
     proc_pidinfo(<pid>, PROC_PIDTBSDINFO, ...) (a numeric or variable flavour, or the bare name,
     fails; the pid argument holds no comma or parenthesis);
  4. sysctl allow-list: the only sysctlbyname name is kern.bootsessionuuid, no bare
     (uncalled) sysctlbyname, no MIB-form sysctl( call, no sysctlnametomib, no KERN_PROC* /
     KERN_ARGMAX token (the argv and environment read);
  5. non-vacuity: proc_snapshot_read.cpp exists and contains proc_pidinfo and PROC_PIDTBSDINFO,
     and process_introspect_macos.cpp exists and calls read_proc_snapshot_bounded, so a rename
     cannot make the gate pass on nothing;
  6. in the libproc TU (proc_snapshot_read.cpp) only: the include set stays within
     LIBPROC_INCLUDES and proc_pidinfo is called exactly once; in the plugin's macOS shell:
     no libproc call at all (it goes through agent-core) and its include set stays within
     MACOS_INCLUDES.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cpp_lex_helper as lexh  # noqa: E402

PLUGIN = ROOT / "agents/plugins/process_introspect/src"
MACOS_TU = "process_introspect_macos.cpp"
LIBPROC_TU_PATH = ROOT / "agents/core/src/proc_snapshot_read.cpp"
LIBPROC_TU = LIBPROC_TU_PATH.name

TASK_CALLS = re.compile(
    r"\b(task_for_pid|task_read_for_pid|task_inspect_for_pid|task_name_for_pid|"
    r"processor_set_tasks\w*|(?:mach_)?vm_\w+|task_threads|task_info)\b")
MACH_INCLUDE = re.compile(r"#\s*(?:include|import)\s*[<\"]mach/")
OTHER_BANS = re.compile(r"\b(dlsym|dlopen|ptrace|ReadProcessMemory|run_bounded_subprocess|"
                        r"subprocess_runner|kill|syscall|__proc_info|pbi_comm|pbi_name)\b")
MEM_LITERAL = re.compile(r'"[^"\n]*/mem"')
PROC_PID_TOKEN = re.compile(r"\bPROC_PID\w*")
PROC_PID_ALLOWED = {"PROC_PIDTBSDINFO", "PROC_PIDTBSDINFO_SIZE"}
PROC_PIDINFO = re.compile(r"\bproc_pidinfo\b")
PROC_PIDINFO_CALL = re.compile(r"proc_pidinfo\s*\(\s*[^,()]*,\s*PROC_PIDTBSDINFO\s*,")
PROC_IDENT = re.compile(r"\bproc_\w+")
# proc_snapshot_read is the agent-core header name in the include path.
PROC_ALLOWED = {"proc_pidinfo", "proc_bsdinfo", "proc_info", "proc_visibility",
                "proc_snapshot_read"}
SYSCTLBYNAME = re.compile(r"\bsysctlbyname\s*\(\s*(\"[^\"\n]*\"|[^,)]*)")
SYSCTLBYNAME_BARE = re.compile(r"\bsysctlbyname\b(?!\s*\()")
SYSCTL_ALLOWED = '"kern.bootsessionuuid"'
SYSCTL_BANS = re.compile(r"\bsysctl\s*\(|\bsysctlnametomib\b|\bKERN_PROC\w*|\bKERN_ARGMAX\b")
INCLUDE = re.compile(r"#\s*(?:include|import)\s*([<\"][^>\"\n]+[>\"])")
MACOS_INCLUDES = {'"process_introspect_legs.hpp"', "<sys/sysctl.h>",
                  "<yuzu/agent/proc_snapshot_read.hpp>", "<cerrno>", "<cstring>"}
LIBPROC_INCLUDES = {"<yuzu/agent/proc_snapshot_read.hpp>", "<cerrno>", "<libproc.h>",
                    "<sys/proc_info.h>", "<cstring>"}


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
    for m in PROC_PIDINFO.finditer(ident):
        if not PROC_PIDINFO_CALL.match(ident, m.start()):
            out.append(f"{name}: proc_pidinfo is not called as "
                       "proc_pidinfo(pid, PROC_PIDTBSDINFO, ...)")
    for m in PROC_IDENT.finditer(ident):
        if m.group(0) not in PROC_ALLOWED:
            out.append(f"{name}: names {m.group(0)} (not on the libproc allow-list)")
    for m in SYSCTLBYNAME.finditer(code):
        if m.group(1).strip() != SYSCTL_ALLOWED:
            out.append(f"{name}: sysctlbyname({m.group(1).strip()}...) is not kern.bootsessionuuid")
    for m in SYSCTLBYNAME_BARE.finditer(ident):
        out.append(f"{name}: sysctlbyname is named without being called")
    for m in SYSCTL_BANS.finditer(ident):
        out.append(f"{name}: uses {m.group(0).strip()} (only sysctlbyname of kern.bootsessionuuid)")
    if name in (MACOS_TU, LIBPROC_TU):
        allowed = MACOS_INCLUDES if name == MACOS_TU else LIBPROC_INCLUDES
        for m in INCLUDE.finditer(code):
            if m.group(1) not in allowed:
                out.append(f"{name}: includes {m.group(1)}, outside its include allow-list")
        want = 0 if name == MACOS_TU else 1
        if len(PROC_PIDINFO.findall(ident)) != want:
            out.append(f"{name}: proc_pidinfo must be called exactly {want} time(s)")
    return out


def self_check() -> list[str]:
    """The matcher must flag the bad shapes and pass the good ones, or the gate is a no-op."""
    errs = []
    bad_shapes = (
        '#include <mach/mach.h>',
        '#import <mach/mach.h>',
        'auto p = "/proc/1/mem";',
        'proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, 0, &x, n);',
        'proc_pidinfo(pid, 4, 0, &x, n);',
        'proc_pidinfo(pid, flavor, 0, &x, n);',
        'proc_pidinfo(pid, PROC_PIDTBSDINFO_SIZE, 0, &x, n);',
        'auto f = proc_pidinfo;',
        'proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEINFO, &x, n);',
        'sysctlbyname("kern.procargs2", b, &n, nullptr, 0);',
        'sysctlbyname(name, b, &n, nullptr, 0);',
        'sysctl(mib, 4, b, &n, nullptr, 0);',
        'int m[2] = {CTL_KERN, KERN_PROC};',
        'int m = KERN_ARGMAX;',
        'proc_terminate(pid, &rc, &sig);',
        'int n = proc_listallpids(buf, size);',
        'syscall(SYS_kill, pid, 9);',
        'kill(pid, SIGKILL);',
        '__proc_info(2, pid, 0, 0, buf, n);',
        'auto f = &sysctlbyname;',
        'auto n = pbi.pbi_comm;',
        'auto n = pbi.pbi_name;',
        'vm_write(task, a, d, n);',
        'vm_protect(task, a, n, 0, prot);',
    )
    for bad in bad_shapes:
        if not findings("self", bad):
            errs.append(f"self-check: did not flag {bad!r}")
    # Rules that apply to the libproc TU only: an extra include, and a second proc_pidinfo call.
    macos_call = "proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pbi, PROC_PIDTBSDINFO_SIZE);\n"
    for bad in ('#include <unistd.h>\n' + macos_call,
                '#include "macos_socket_walk.hpp"\n' + macos_call,
                macos_call + macos_call):
        if not findings(LIBPROC_TU, bad):
            errs.append(f"self-check: did not flag {bad!r} as the libproc TU")
    # The plugin's macOS shell makes no libproc call of its own, and keeps its include set.
    for bad in (macos_call, '#include <libproc.h>\n', '#include <unistd.h>\n'):
        if not findings(MACOS_TU, bad):
            errs.append(f"self-check: did not flag {bad!r} as the macOS shell")
    # Every banned name, spelled out here and not read back from the regexes above, so a typo in
    # any one regex alternative leaves its name unflagged and fails (a prefix such as mach_vm_
    # stands for its family).
    banned_names = (
        "task_for_pid", "task_read_for_pid", "task_inspect_for_pid", "task_name_for_pid",
        "processor_set_tasks", "processor_set_tasks_with_flavor", "mach_vm_region", "mach_vm_read",
        "vm_region", "vm_region_64", "vm_region_recurse", "vm_region_recurse_64", "vm_read",
        "vm_read_list", "vm_read_overwrite", "task_threads", "task_info",
        "vm_write", "vm_protect", "dlsym", "dlopen", "ptrace", "ReadProcessMemory",
        "run_bounded_subprocess", "subprocess_runner", "kill", "syscall", "__proc_info",
        "pbi_comm", "pbi_name", "proc_pidpath", "proc_name", "proc_regionfilename",
        "proc_pidfdinfo", "proc_listpids", "proc_listallpids", "proc_terminate", "proc_pid_rusage",
        "sysctlnametomib",
    )
    for name in banned_names:
        if not findings("self", f"{name}(x);"):
            errs.append(f"self-check: did not flag the banned name {name!r}")
    good_shapes = (
        'proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pbi, PROC_PIDTBSDINFO_SIZE);',
        'struct proc_bsdinfo pbi;',
        'sysctlbyname("kern.bootsessionuuid", buf, &len, nullptr, 0);',
        '// task_for_pid is banned\nint x;',
        '/* mach_vm_region too */ int y;',
        'auto d = "libproc proc_pidinfo, no task port";',
        'auto t = "task_for_pid in a descriptor string";',
        '#include <libproc.h>\n#include <sys/sysctl.h>',
        'auto m = "kill the process";\nint kill_switched = 1;',
        'bool v = proc_visibility(m) == ProcVisibility::visible;',
    )
    for good in good_shapes:
        got = findings("self", good)
        if got:
            errs.append(f"self-check: flagged {good!r}: {got}")
    libproc_good = ('#include <yuzu/agent/proc_snapshot_read.hpp>\n#include <cerrno>\n'
                    '#include <libproc.h>\n#include <sys/proc_info.h>\n#include <cstring>\n'
                    + macos_call)
    got = findings(LIBPROC_TU, libproc_good)
    if got:
        errs.append(f"self-check: flagged the libproc TU's own shape: {got}")
    macos_good = ('#include "process_introspect_legs.hpp"\n#include <sys/sysctl.h>\n'
                  '#include <yuzu/agent/proc_snapshot_read.hpp>\n#include <cerrno>\n'
                  '#include <cstring>\nread_proc_snapshot_bounded(pid, d);\n')
    got = findings(MACOS_TU, macos_good)
    if got:
        errs.append(f"self-check: flagged the macOS shell's own shape: {got}")
    return errs


def main() -> int:
    errs = self_check()
    if errs:
        for e in errs:
            print("FAIL:", e)
        return 1
    files = sorted(f for f in PLUGIN.rglob("*") if f.is_file())
    if not files:
        print(f"FAIL: no sources under {PLUGIN}")
        return 1
    macos = next((f for f in files if f.name == MACOS_TU), None)
    if macos is None or not LIBPROC_TU_PATH.is_file():
        print(f"FAIL: {MACOS_TU} or {LIBPROC_TU} not found: the gate would pass vacuously")
        return 1
    macos_code = lexh.lex(macos.read_text(encoding="utf-8", errors="replace"))
    if "read_proc_snapshot_bounded" not in macos_code:
        errs.append(f"{MACOS_TU}: no longer calls read_proc_snapshot_bounded: the gate would "
                    "pass vacuously")
    libproc_code = lexh.lex(LIBPROC_TU_PATH.read_text(encoding="utf-8", errors="replace"))
    for needed in ("proc_pidinfo", "PROC_PIDTBSDINFO"):
        if needed not in libproc_code:
            errs.append(f"{LIBPROC_TU}: no longer contains {needed}: the gate would pass vacuously")
    for f in [*files, LIBPROC_TU_PATH]:
        errs += findings(f.name, f.read_text(encoding="utf-8", errors="replace"))
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
