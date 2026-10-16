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

**[WARN] `subprocess` with `text=True` and no `encoding=` decodes with the host's code page, not the child's (#5925, #4839).**

With `text=True` (or `universal_newlines=True`) and no `encoding=`, Python decodes the
child's output with the locale encoding. On Windows that is the ANSI code page (cp1252 on
Western locales), in strict mode, unless Python's UTF-8 mode is on (the default only from
Python 3.15). A child that writes UTF-8 then breaks on any byte cp1252 leaves unmapped
(0x81, 0x8D, 0x8F, 0x90, 0x9D). It does not fail loudly: `run()` / `communicate()` lose
the `UnicodeDecodeError` to the reader thread (a traceback on stderr) and return
`stdout=None` with the child's real exit code, so the caller errors only if it then uses
`stdout`. That is how `tests/test_compose_wizard.py` failed on Shulgi (#5925); a UTF-8
locale on Linux or macOS never shows it.

Pass the encoding the child actually writes:

    subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")  # Node, git

- A Python child (meson included) writes the locale code page on Windows, not UTF-8: add
  `PYTHONUTF8=1` to the env the call already passes (`{**base_env, "PYTHONUTF8": "1"}`,
  where `base_env` is `os.environ` only if the call passed no `env=`) and decode as
  `utf-8`; decoding with `errors="replace"` instead never raises but turns non-ASCII into
  U+FFFD.
- For output you only log or scan (a long build, a streamed reader), use
  `encoding="utf-8", errors="replace"` so one stray byte cannot kill the reader (#4839).
- `encoding=` also encodes `input=`.

Best-effort: this rule sees only the text being written (a Write's whole file, an Edit's
new text), so silence after an Edit does not mean the file is clean, and a call split
across an Edit boundary or hidden behind an alias, `functools.partial` or `**kwargs` is
missed. It fires on any OS because the code it guards runs on the Windows CI leg. It
matches `content`, not `new_text`, on purpose: `new_text` is empty for a Write.
