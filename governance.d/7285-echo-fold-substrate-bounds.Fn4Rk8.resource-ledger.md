# Resource Ledger — `7285-echo-fold-substrate-bounds.Fn4Rk8`

Every owning boundary the C++ in `b7a9905e6..4f4dd457e` (`fix/echo-fold-substrate-bounds`,
issue #7285) acquires. Required by the Gate 1 contract on any C++ diff.

The change edits SQL text (a saturating `CASE` for INTEGER sums), adds an arithmetic guard
before the replay-ring insert loop, and extends the schema probe to see views as well as
tables. The probe statement is held in the existing RAII `StmtPtr` and is finalised before
any `DROP`; the dropped name comes from `fold_view_names()`, never from input. No fd, HANDLE,
SOCKET, `FILE*`, new `sqlite3*`, OpenSSL/BCrypt object, thread, subprocess, mapped library or
temporary path is acquired, so owner, acquisition, release, transfer and failure-cleanup are
not applicable beyond the existing statement handle.

**Adjudications recorded:** none required — no manual (non-RAII) resource cleanup exists in
this diff.
