# Resource Ledger: sam33-rest-read-v3

Every owning boundary the C++ in `2c3d0ac14..HEAD` (feat/sam-33-rest-read-v3) acquires: the fleet snapshot and its holder, the rollup's refresh, the routes' borrowed pointers and the new store reads. No new fd, HANDLE, SOCKET, `FILE*`, OpenSSL object, allocated C string, temporary path or subprocess, and no new thread: the refresh runs on the existing rollup thread. The snapshot is per replica and never filtered for a caller. The new background-job row `software_catalog_rollup.refresh_fleet_snapshot` is `ReplicaSafe`.

| ID | Resource | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Fleet snapshot, `shared_ptr<const SoftwareFleetSnapshot>` | `SoftwareFleetSnapshotHolder`, a member of `ServerImpl` (`software_fleet_snapshot_`) | `make_shared` on the rollup thread | The last reader drops it; the holder dies with `ServerImpl`, after the rollup thread is joined | `publish()` swaps the pointer; a reader copies the `shared_ptr` under the lock | A failed refresh publishes nothing, so the last good snapshot stays |
| R2 | The one new mutex, `SoftwareFleetSnapshotHolder::mu_` | the holder | construction | holder destruction | none | Held only for a pointer copy or swap, never across a store read |
| R3 | `snapshot_`, a raw `SoftwareFleetSnapshotHolder*` in `SoftwareCatalogRollup` | borrowed | `set_snapshot_holder()` before `start()` | never | none | The holder is declared before the rollup, so it outlives it; `stop()` resets the rollup first |
| R4 | The refresh itself (`refresh_fleet_snapshot`) | the existing rollup `std::thread` | each tick, inside the tick's try/catch | tick end | none | A throw or a failed read is counted (`yuzu_software_fleet_snapshot_total{outcome}`) and keeps the last good snapshot |
| R5 | `SoftwareInventoryStore*` in `SoftwareReadRoutes::Deps` | borrowed from the `ServerImpl` `unique_ptr` | route registration | never | captured into the route handlers' shared `Ctx` | `stop()` joins the web server before it resets the store |
| R6 | Pool leases for the new store reads | `PgPool::Lease` (RAII) | one per read | scope exit | none | A failed lease or statement returns `std::nullopt`, which the route turns into a 503 |
| R7 | `roster_fn` and `snapshot_fn` lambdas in `server.cpp` | capture `this` | route registration | never | none | The web server is stopped before the stores they read are reset; an unwired or failed roster read is `std::nullopt` |
