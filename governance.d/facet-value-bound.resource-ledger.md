# Resource Ledger: facet value bound, deterministic facet cap, dropped-facets counter (#5623)

Covers `origin/dev..HEAD` on `fix/5623-facet-value-bound`.

No fd, HANDLE, SOCKET, `FILE*`, OpenSSL object, BCrypt handle, allocated C string, mapped library, temp path, subprocess or thread is added in production code. There is no `new`, `delete`, `malloc` or manual cleanup in the added C++. The libpq connection, `PgResult` objects and the SAVEPOINT are the existing ones in `ResponseStore::store`; no new libpq call site is added.

| resource | owner | acquired | released | transfer / failure cleanup |
|---|---|---|---|---|
| `flat` (`std::vector<std::tuple<int,std::string,int>>`) in `ResponseStore::store` | the `store` call frame | built from the per-response facet maps | end of the facet block | unchanged ownership; values longer than `kMaxFacetValueBytes` are skipped while building it (never copied), so its size is bounded by the same distinct-facet count as before; `std::partial_sort` runs in place only when `flat` exceeds the cap, O(n log cap) time and no allocation of its own |
| `yuzu_server_response_facets_dropped_total{reason}` counter series | `yuzu::MetricsRegistry` (owned by `ServerImpl`, pointer held by `ResponseStore` as before) | `seed_response_facet_metrics` at startup, and on first use per reason | registry destruction | the three reason labels are fixed constants (bounded cardinality); `note_facets_dropped` is a no-op when `metrics_` is null and when the count is zero; no label is built from response content |
| test code | stack objects and the existing PG fixtures (`YUZU_REQUIRE_PG_DB` family) | per test | per test scope | no raw owning pointers, no new thread-owning code, no temp paths or fixed ports |

Platform notes: no `#ifdef` added; the constant is a plain `std::size_t`; the comparator is a captureless lambda over `std::get`. The facet-drop paths run inside the existing fail-soft block, so a failure to count or to log cannot fail the response store. Behaviour that is intentionally unchanged: the 5000 facet cap value, the ingest byte cap, the schema and indexes.
