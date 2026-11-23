# Resource Ledger — `7173-echo-registry-live-etw-skip.Eq3Wn5`

Every owning boundary the C++ in `b7a9905e6..c3fc934a0` (`fix/echo-registry-live-etw-named-skip`,
issue #7173) acquires. Required by the Gate 1 contract on any C++ diff.

The change adds one `std::atomic<ULONG> last_start_rc` member to the Windows ETW wrapper, a
`std::function<unsigned long()> etw_start_error` callback on the registry reader that reads it,
and test-only helpers. It acquires no fd, HANDLE, SOCKET, `FILE*`, `sqlite3*`, prepared
statement, OpenSSL/BCrypt object, thread, subprocess, mapped library or temporary path. The
callback captures the existing `shared_ptr` that already owns the wrapper, so the wrapper's
lifetime is unchanged, and the stored value is a plain integer read after the synchronous
`start()` call returns. Owner, acquisition, release, transfer and failure-cleanup are therefore
not applicable.

**Adjudications recorded:** none required — no manual (non-RAII) resource cleanup exists in
this diff.
