# Resource Ledger: validator cache byte bound + hoist (#5562 item 1)

Covers `c8b77fd8b..HEAD` on `feat/5562-param-validator-cache-bound`.

No fd, HANDLE, SOCKET, `FILE*`, sqlite/libpq handle (production), OpenSSL object, BCrypt handle, allocated C string, mapped library, temp path, subprocess or thread is added. There is no `new`, `delete`, `malloc` or manual cleanup in the added C++.

| resource | owner | acquired | released | transfer / failure cleanup |
|---|---|---|---|---|
| `ParamValidatorCache` state: `std::mutex mu_`, `std::list<Entry> lru_`, `std::unordered_map<std::string, list::iterator> index_`, `total_bytes_` (plain `size_t` guarded by `mu_`) | the cache object | construction | destruction | every access under `std::lock_guard`; compile and SHA-256 run outside the lock; `total_bytes_` is changed only together with `lru_` under the lock; if `index_.emplace` throws the freshly pushed front entry is popped and the exception swallowed by `get()` (caching is an optimisation), leaving `total_bytes_` untouched because it is incremented after the emplace succeeds |
| the cache instance | `std::shared_ptr<instr::ParamValidatorCache>`: `ServerImpl::param_validator_cache_` (declared before `web_server_`, so destroyed after the HTTP server) plus a shared_ptr copy in `WorkflowRoutes::Deps::param_validators` captured by the execute-route lambda | `ServerImpl` construction | last shared_ptr drop | a null `Deps` value makes `register_routes` create a private cache (test harnesses); no raw pointer into any other ServerImpl member |
| prepared validators | `std::shared_ptr<const ParamValidator>` (cache entry plus each in-flight request) | `get` | last drop | an entry evicted, or never retained because it exceeds the budget or the per-entry cap, stays alive until the requesting call finishes; `estimated_retained_bytes()` is a read-only `size_t` computed once in `prepare_param_validator` |
| RE2 objects, `CompiledInputSchema` | unchanged from the merged validator (owned inside `ParamValidator::Impl`) | unchanged | unchanged | no change |
| test code | stack objects; the Deps-injection PG test uses the existing `ExecHarness` fixture with a trailing optional cache argument | per test | per test scope | no raw owning pointers; no threads added (the existing concurrency test is unchanged) |

Platform notes: no `#ifdef` added; `std::size_t` arithmetic only (a weight is the fixed 4096 + 1024 per property + 128 per enum member (at most 128 properties x 256 members, about 4 MiB) + the trimmed schema text length + `kPatternMaxMem` per compiled pattern (at most 128 x 512 KiB), far below 2^64; the `while` loop's subtraction cannot underflow because `total_bytes_` is the sum of resident weights). The outer `catch (...)` in `get()` swallows an allocation or lock failure, so a failed insert never makes the cache unusable.
