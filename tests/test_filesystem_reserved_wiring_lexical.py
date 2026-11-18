#!/usr/bin/env python3
"""Lexical pin: the filesystem plugin's reserved-path decision (path_is_reserved_unguarded) keeps
its NUL refusal, its POSIX /dev/fd refusal, its macOS /.vol/ refusal and its per-decision
re-resolution of the reserved set. These rules cannot be driven through the plugin seam on Linux
(a NUL is truncated before the plugin; /.vol and macOS /dev/fd do not exist here), so a deleted call
would leave every runtime test green. BEST-EFFORT tripwire: it reads the function body (comments
stripped) and checks the calls are present, in an order where the cheap refusals precede the
snapshot read."""
import pathlib
import re
import sys

SRC = pathlib.Path(__file__).resolve().parent.parent / "agents/plugins/filesystem/src/filesystem_plugin.cpp"


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def body(text: str, name: str) -> str:
    i = text.index(name)
    j = text.index("{", i)
    depth = 0
    for k in range(j, len(text)):
        depth += text[k] == "{"
        depth -= text[k] == "}"
        if depth == 0:
            return text[j : k + 1]
    raise SystemExit("unbalanced body")


def main() -> int:
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else SRC
    code = strip_comments(src.read_text())
    b = body(code, "bool path_is_reserved_unguarded(")
    problems = []

    def need(needle, why):
        if needle not in b:
            problems.append(f"missing {needle!r}: {why}")

    need("contains_nul(p.string())", "a NUL in the candidate path must refuse")
    need("contains_nul(cs)", "a NUL in the canonical path must refuse")
    need("is_dev_fd_path(cs)", "canonical /dev/fd spelling")
    need("is_dev_fd_path(path_bytes(p.lexically_normal()))", "literal /dev/fd spelling")
    need("#ifdef __APPLE__", "the /.vol/ refusal is macOS only")
    need("is_apple_vol_path(path_bytes(p.lexically_normal()))", "literal /.vol/")
    need("is_apple_vol_path(cs)", "canonical /.vol/")
    need("refresh(snapshot.files)", "per-decision re-resolution of reserved files")
    need("refresh(snapshot.dirs)", "per-decision re-resolution of reserved dirs")
    if "contains_nul(p.string())" in b and "g_reserved_mu" in b:
        if b.index("contains_nul(p.string())") > b.index("g_reserved_mu"):
            problems.append("the NUL refusal must precede the reserved-set snapshot")
    # Whole-statement pins: the call, its `return true`, and the exact argument spelling, so a
    # weakened condition (`&&` for `||`, a dropped argument, `if (false && ...)`) is caught too.
    flat = re.sub(r"\s+", " ", b)
    R = r"yuzu::filesystem::reserved::"
    pins = {
        "nul literal": r"^\{ if \(" + R + r"contains_nul\(p\.string\(\)\)\) return true;",
        "nul canonical": r"if \(" + R + r"contains_nul\(cs\)\) return true;",
        "dev_fd": r"if \(\s*" + R + r"is_dev_fd_path\(cs\) \|\| " + R
        + r"is_dev_fd_path\(path_bytes\(p\.lexically_normal\(\)\)\)\) return true;",
        "vol": r"#ifdef __APPLE__ if \(" + R + r"is_apple_vol_path\(path_bytes\(p\.lexically_normal\(\)\)\) \|\| "
        + R + r"is_apple_vol_path\(cs\)\) return true;",
        "refresh": r"if \(!refresh\(snapshot\.files\) \|\| !refresh\(snapshot\.dirs\)\) return true;",
        "eloop": r"too_many_symbolic_link_levels\) return false;",
        "unresolved": r"if \(ok && !resolved\) return false;",
    }
    for name, rx in pins.items():
        if not re.search(rx, flat):
            problems.append(f"whole-statement pin {name!r} not found (condition weakened or removed)")
    if re.search(r"if \(false|if \(0\b", flat):
        problems.append("a disabled branch (`if (false` / `if (0`) in the decision")
    if not re.search(r"constexpr int kMaxLinkHops = 40;", re.sub(r"\s+", " ", code)):
        problems.append("kMaxLinkHops is not the pinned 40")
    for p in problems:
        print("FAIL:", p)
    if problems:
        return 1
    print("filesystem reserved-path wiring lexical gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
