---
name: warn-subprocess-text-no-encoding
enabled: true
event: file
action: warn
conditions:
  - field: file_path
    operator: regex_match
    pattern: \.py$
  - field: content
    operator: regex_match
    pattern: (?:subprocess\.[A-Za-z_]+|\bPopen|\bcheck_output|\brun|\b\w*kwargs\s*=\s*dict)\((?:(?!\bencoding\s*=)[\s\S]){0,800}?\b(?:text|universal_newlines)\s*=\s*True\b(?![\s\S]{0,200}?\bencoding\s*=)
---

**[WARN] `subprocess` with `text=True` and no `encoding=` decodes as cp1252 on Windows (#5925, #4839).**

With `text=True` (or `universal_newlines=True`) and no `encoding=`, Python decodes the
child's output with the locale code page. On Windows that is cp1252, in strict mode, and
Node / rebar3 / meson / git all write UTF-8. Any output byte cp1252 leaves unmapped
(0x81, 0x8D, 0x8F, 0x90, 0x9D) raises `UnicodeDecodeError` in subprocess's reader thread,
so the test errors on Windows while passing on Linux and macOS. It is how
`tests/test_compose_wizard.py` failed on Shulgi (#5925).

Pass the encoding explicitly (it covers `input=` too):

    subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

For output you only log or scan (a long-running build, a streamed reader), prefer
`encoding="utf-8", errors="replace"` so one stray byte cannot kill the reader (#4839).

(Harmless only when the child's output is guaranteed ASCII, such as a git SHA; add the
encoding anyway, it is one keyword. This rule fires on any OS because the code it guards
runs on the Windows CI leg.)
