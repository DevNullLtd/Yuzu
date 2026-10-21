# Resource Ledger — `5334-c4125-octal-escape-literals.Hq7Xv2`

Every owning boundary the C++ in `ca5ec2ea8..ca381d382` (`fix/5334-c4125-octal-escape-literals`,
issue #5334) acquires. Required by the Gate 1 contract on any C++ diff.

The range is test-only and string-literal-only: four string literals in
`tests/unit/test_inventory_sync.cpp` and `tests/unit/server/test_software_inventory_store.cpp`
are split into adjacent literals after a three-digit octal escape that is followed by a decimal
digit (MSVC C4125). Adjacent literals concatenate before the string is formed, so the resulting
bytes are identical; no production `agents/` or `server/` code changed.

The diff acquires no fd, HANDLE, SOCKET, `FILE*`, `sqlite3*`, prepared statement, OpenSSL/BCrypt
object, thread, subprocess, mapped library or temporary path. Owner, acquisition, release,
transfer and failure-cleanup are therefore not applicable. The only objects involved are the
`std::string` temporaries the edited expressions already built, which are RAII-managed.

**Adjudications recorded:** none required — no manual (non-RAII) resource cleanup exists in
this diff.
