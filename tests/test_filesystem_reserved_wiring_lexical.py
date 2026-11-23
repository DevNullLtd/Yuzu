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

    need("contains_nul(path_bytes(p))", "a NUL in the candidate path must refuse (UTF-8 bytes, never p.string())")
    need("contains_nul(cs)", "a NUL in the canonical path must refuse")
    need("is_dev_fd_path(cs)", "canonical /dev/fd spelling")
    need("is_dev_fd_path(path_bytes(p.lexically_normal()))", "literal /dev/fd spelling")
    need("#ifdef __APPLE__", "the /.vol/ refusal is macOS only")
    need("is_apple_vol_path(path_bytes(p.lexically_normal()))", "literal /.vol/")
    need("is_apple_vol_path(cs)", "canonical /.vol/")
    need("refresh(snapshot.files)", "per-decision re-resolution of reserved files")
    need("refresh(snapshot.dirs)", "per-decision re-resolution of reserved dirs")
    if "contains_nul(path_bytes(p))" in b and "g_reserved_mu" in b:
        if b.index("contains_nul(path_bytes(p))") > b.index("g_reserved_mu"):
            problems.append("the NUL refusal must precede the reserved-set snapshot")
    # Whole-statement pins: the call, its `return true`, and the exact argument spelling, so a
    # weakened condition (`&&` for `||`, a dropped argument, `if (false && ...)`) is caught too.
    flat = re.sub(r"\s+", " ", b)
    R = r"yuzu::filesystem::reserved::"
    pins = {
        "nul literal": r"^\{ if \(" + R + r"contains_nul\(path_bytes\(p\)\)\) return true;",
        "nul canonical": r"if \(" + R + r"contains_nul\(cs\)\) return true;",
        "dev_fd": r"if \(\s*" + R + r"is_dev_fd_path\(cs\) \|\| " + R
        + r"is_dev_fd_path\(path_bytes\(p\.lexically_normal\(\)\)\)\) return true;",
        "vol": r"#ifdef __APPLE__ if \(" + R + r"is_apple_vol_path\(path_bytes\(p\.lexically_normal\(\)\)\) \|\| "
        + R + r"is_apple_vol_path\(cs\)\) return true;",
        "refresh": r"if \(!refresh\(snapshot\.files\) \|\| !refresh\(snapshot\.dirs\)\) return true;",
        # FAIL CLOSED on a link chain the system cannot resolve (MSVC ERROR_CANT_RESOLVE_FILENAME 1921 has no
        # errc mapping): only absent / unsearchable skips an entry, every other error refuses.
        "eloop": r"if \(rec\) \{ if \(absent_error\(rec\) \|\| rec == std::errc::permission_denied \|\| "
                 r"rec == std::errc::operation_not_permitted\) \{ ok = false; break; \} return false; \} "
                 r"const auto st = fs::symlink_status\(cur, rec\); if \(rec && !absent_error\(rec\)\) return false;",
        "winalias": r"#ifdef _WIN32 if \(yuzu::filesystem::reserved::is_windows_alias_spelling\("
                    r"path_bytes\(p\)\)\) return true; #endif",
        "unresolved": r"if \(ok && !resolved\) return false;",
    }
    for name, rx in pins.items():
        if not re.search(rx, flat):
            problems.append(f"whole-statement pin {name!r} not found (condition weakened or removed)")
    # path_bytes must be the NON-throwing shared converter (u8string() throws on MSVC for an unpaired
    # surrogate), and validate_path / validate_path_or_parent must turn any throw into a refusal.
    if "u8string()" in code[code.index("std::string path_bytes("):code.index("std::string path_bytes(") + 400]:
        problems.append("path_bytes calls u8string(): it throws on MSVC for an unpaired surrogate; use find_by_hash::path_utf8")
    for fn in ("validate_path", "validate_path_or_parent"):
        w = re.search(r"std::string " + fn + r"\(std::string_view raw_path, std::string_view base_dir\) \{\s*try \{\s*return " + fn + r"_impl\(raw_path, base_dir\);\s*\} catch \(\.\.\.\) \{\s*return \{\};", code)
        if not w:
            problems.append(f"{fn} is not a try/catch(...) wrapper returning an empty refusal over {fn}_impl")
    # path::string() throws on MSVC for a name the active code page cannot hold, and the guard turns a throw
    # into a REFUSAL: every non-ACP file name was refused as reserved. The decision converts through
    # path_bytes (UTF-8) only.
    if re.search(r"\.string\(\)", b):
        problems.append("the reserved decision calls .string(): use path_bytes() (MSVC throws for a non-ACP name)")
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
