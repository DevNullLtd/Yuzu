# Resource Ledger — `5328-published-ecosystem-vocabulary.Wz4Kd9`

Every owning boundary the C++ in `ca5ec2ea8..79a34abdd` (`fix/5328-published-ecosystem-vocabulary`,
issue #5328) acquires. Required by the Gate 1 contract on any C++ diff.

The C++ in this range is string-literal, comment and pure-predicate only: the description literals
in `server/core/src/mcp_server.cpp` and `server/core/src/rest_api_v1.cpp`, the boolean `is_os_native`
predicate in `server/core/src/cpe_normalize.hpp`, a comment in
`agents/plugins/installed_apps/src/installed_apps_inventory.hpp`, and rows in
`tests/unit/server/test_cpe_identity_resolver.cpp`. No new type, function with side effects, or
control flow with ownership was added.

The diff acquires no fd, HANDLE, SOCKET, `FILE*`, `sqlite3*`, prepared statement, OpenSSL/BCrypt
object, thread, subprocess, mapped library or temporary path. Owner, acquisition, release, transfer
and failure-cleanup are therefore not applicable. The only objects involved are RAII
`std::string` / `SoftwareEntry` temporaries and the `CpeIdentityResolver` locals in the test, which
are scope-managed.

**Adjudications recorded:** none required — no manual (non-RAII) resource cleanup exists in this
diff.
