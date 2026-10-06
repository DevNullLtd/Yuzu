# M.9 PR-3 (software page) Resource Ledger (governance Gate 1)

The production-code ledger for the rebuilt Software page. Files `server/core/src/inventory_routes.{hpp,cpp}`, `inventory_ui.cpp`, `server.cpp` (the `InventoryRoutes::Deps` wiring), `software_inventory_store.{hpp,cpp}` (`source_last_seen_bulk`).

## Resource Ledger (C++)
- `InventoryRoutes::Deps` closures (`std::function` members, moved into the route object's members by `register_routes`): owner = the `InventoryRoutes` instance; the `server.cpp` closures capture `this` (the server, which owns the store, the routes object and the web server, and destroys the web server first) and `device_api` by value (a `shared_ptr` copy); nothing is borrowed past the call that receives it. An unwired closure is a degrade or a 503, never a null call.
- Route handlers capture `this` of the `InventoryRoutes`; the object outlives the sink that holds them (tests declare `routes` before `sink`, #1786).
- `SoftwareInventoryStore::source_last_seen_bulk`: pooled lease via `pool_.try_acquire_for(kQueryAcquireTimeout)` (RAII, released at scope exit on every path, including the early degrade returns); one `pg::PgResult` (RAII, no `PQclear`); `PQgetvalue` pointers are copied into the returned `std::string` keys before the result dies; the `std::vector<std::string_view>` handed to `pg::to_text_array` views the caller's vector, which outlives the call; the bound on the id array is the caller's: the only production caller is the devices route, which passes the distinct agent_ids of one page (at most 100 rows, `kCatalogueDefaultLimit`), so the array parameter is at most 100 ids.
- Per-request locals (`SoftwarePageData`, `SoftwareDevicesTable`, the hostname map copy, id sets): plain value types owned by the handler frame; the hostname map is copied once per devices page and once per full page (`ponytail:` noted at the call sites).
- The page script is a `static` string literal returned by value; no handle, no thread, no timer.
- No new fd/HANDLE/SOCKET/FILE*/sqlite handle/OpenSSL object/mapped library/temp file/subprocess/shell string/`system`/`popen`/thread/lock, and no cast over a lifetime, in production code.
