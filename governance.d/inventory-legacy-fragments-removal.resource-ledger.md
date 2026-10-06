# Resource Ledger — `inventory-legacy-fragments-removal`

Every owning boundary the C++ in `f79ba8d13..HEAD` (`refactor/inventory-remove-legacy-fragments`)
acquires. Required by the Gate 1 contract on any C++ diff.

This diff is deletion-only on the production side: it removes the four dead
`/fragments/inventory/{devices,device,find,find/results}` handlers, their renderers and
helpers, four unused injected closures (`ScopedPermFn`/`AgentSoftwareFn`/`DevicesFn`/
`AgentCiFn` parameters and members), and the dead `visible` filter of server.cpp's
`build_hw_roster`. It adds two `TEST_CASE`s to `tests/unit/server/test_hardware_routes.cpp`
that run in-process through `TestRouteSink`. Nothing in it acquires a raw fd/HANDLE/SOCKET/
`FILE*`, an OpenSSL/BCrypt object, an allocated C string, a mapped library, a thread, a mutex,
or any heap-owning object beyond ordinary `std::string`/`std::vector` locals.

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| (none) | n/a | n/a | n/a | n/a | n/a |

**Adjudications recorded:** none required.

**Sanitizer coverage.** Not applicable — no ownership-bearing code is added.
