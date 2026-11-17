# Resource Ledger: bounded pack-uninstall referrer pre-check (#7921 item 1)

New or modified owned resources in `server/core/src/` (`instruction_referrers.{hpp,cpp}`,
`schedule_engine.{hpp,cpp}`, `workflow_engine.{hpp,cpp}`, `policy_store.{hpp,cpp}`,
`workflow_routes.cpp`) and `tests/unit/server/test_workflow_routes.cpp`. No file descriptor,
`FILE*`, socket, `HANDLE`, subprocess, mapped library, temp path, OpenSSL object, BCrypt handle, C
string, thread or callback-owned raw pointer is added. The owned things are short read-only pooled
leases, local value containers and one more type-erased callable inside an existing class. Context
for the surrounding sites: `2146-twin-batch-c-instructions-sets.md`.

## Resources

### Pooled leases of the four batched reads
- **Site:** `ScheduleEngine::schedules_referencing_definitions`,
  `WorkflowEngine::workflows_referencing_instructions`,
  `PolicyStore::fragments_referencing_instructions` and `PolicyStore::policies_using_fragments`.
  The one-id `WorkflowEngine::workflows_referencing_instruction` and
  `PolicyStore::fragments_referencing_instruction` now delegate to the batch methods.
- **Acquired by:** `pool_.try_acquire_for(...)`, once per call, after the empty-list early return
  (an empty id list takes no lease).
- **Owner type:** the pool's `Lease` RAII object, local to the method; the `PgResult` is the
  existing RAII result owner.
- **Release point:** scope exit of the method, on every return including a failed query. No lease is
  held across another read.
- **Transfer:** never moved or stored; the answer is copied into a returned `std::vector`.
- **Failure cleanup:** a missing lease or a failed query is an `unexpected` (fail closed, never an
  empty list). The number of leases a pre-check takes no longer grows with the pack: one for
  `policies_using_fragments`, at most three for `lookup_many` (one per source; a later source is
  not read once `limit` referrers are in hand). Pinned in `test_workflow_routes.cpp` at two
  levels: the store methods by the lease-count test (3 leases for `lookup_many` over 500 ids, 1 for
  `policies_using_fragments` over 60), and the route's use of them by two lease comparisons through
  the blocked-409 DELETE (a 5-definition against a 500-definition pack, and 5 against 60 own policy
  fragments cost the same number of leases).

### `DefinitionReferrersFn::batch_` and `lookup_many`
- **Site:** `instruction_referrers.hpp`; the batch lambda is built in
  `make_definition_referrers_fn` and attached with `DefinitionReferrersFn::with_batch`.
- **Owner type:** a second `std::function<Result(const std::vector<std::string>&, const
  Exclusions&, std::size_t)>` member (`batch_`) beside `fn_`. It captures by value the same three
  NON-OWNING raw pointers (`ScheduleEngine*`, `WorkflowEngine*`, `PolicyStore*`) and the same
  `std::shared_ptr<RefusalLogThrottle>` as the one-id closure, so the throttle's lifetime and the
  pointers' lifetime rules are unchanged (the closure is destroyed with its last copy; the stores
  outlive every request handler, `ServerImpl::stop()` joining `web_thread_` first).
- **Transfer:** copied with the class (the four consumers' copies keep `batch_`); a function rebuilt
  from a callable that wraps another loses it, which `has_batch()` reports.
- **Failure cleanup:** `lookup_many` copies the non-empty ids into a local vector, returns an
  `unexpected` on any source failure (it adds no `try`/`catch`; an allocation failure propagates to
  the route's caller like any other).

### Pack-uninstall handler locals (`workflow_routes.cpp`)
- **Site:** the `DELETE /api/product-packs/{id}` pre-check.
- **Owner type:** local value containers only: `own_fragment_ids` and `definition_ids`
  (`std::vector<std::string>`, copies of the pack's item ids), the `policy_held` map and the
  `blocking` list (at most `kMaxReferrersListed + 1` entries).
- **Release point:** scope exit; every refusal returns before `uninstall()` is reached.
- **Not covered / limitation:** there is no item cap, so the transient id copies and the array
  parameter grow linearly with the pack (bounded by the 16 MiB body cap); the number of leases does
  not.
