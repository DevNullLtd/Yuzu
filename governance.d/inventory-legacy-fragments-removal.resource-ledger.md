# Resource Ledger — `inventory-legacy-fragments-removal`

Every owning boundary the C++ in `f79ba8d13..HEAD` (`refactor/inventory-remove-legacy-fragments`)
acquires. Required by the Gate 1 contract on any C++ diff.

This diff is deletion-dominated on the production side: it removes the four dead
`/fragments/inventory/{devices,device,find,find/results}` handlers, their renderers and
helpers, four unused injected closures (`ScopedPermFn`/`AgentSoftwareFn`/`DevicesFn`/
`AgentCiFn` parameters and members), and the dead `visible` filter of server.cpp's
`build_hw_roster`. `build_hw_roster` is now a parameterless lambda passed by value as
`HardwareRoutes::Deps.roster_fn`, with the same `[this, inv_human_age]` capture as the
removed `hw_roster_fn` wrapper. Production additions are comments, one `#include`, the
`ScopedPermFn` alias re-declaration and one reworded caveat string. It adds nine
`TEST_CASE`s (five in test_hardware_routes.cpp, two in test_hardware_ui.cpp, two in
test_inventory_routes.cpp) that run in-process (`TestRouteSink` / pure renderers).
Nothing in it acquires a raw fd/HANDLE/SOCKET/`FILE*`, an OpenSSL/BCrypt object, an
allocated C string, a mapped library, a thread, a mutex, or any heap-owning object beyond
ordinary `std::string`/`std::vector` locals.

| Resource | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| (none) | n/a | n/a | n/a | n/a | n/a |

**Adjudications recorded:** none required.

**Sanitizer coverage.** Not applicable — no ownership-bearing code is added.
