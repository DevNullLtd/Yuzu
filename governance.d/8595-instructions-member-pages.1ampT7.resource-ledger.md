# Packet 1.3 member-page resource ledger

| Resource | Ownership and lifetime | Failure and release |
| --- | --- | --- |
| PostgreSQL connection lease | The store acquires one timed pool lease and transfers it into the synchronous transaction. The collation reader and page helper borrow its connection only during the callback. | The pool rolls back a refused read and releases the lease after commit or rollback. |
| PostgreSQL results | Each catalog, isolation and page query owns its result via PgResult. Device IDs and cursors are copied before destruction. | Scoped result destructors free each result on success and error. A failed continuation discards the accumulated vector. |
| Candidate filter and page buffer | A single operation owns its candidate set, each page and the bounded accumulated matches. | No callback escapes the transaction. Stack unwinding destroys the containers. |
| Test database and instrumentation | Each PostgreSQL fixture owns its isolated database. A local connection installs the fault view. The marker is transaction-local. | RAII releases connections before the database is removed. Captured logging is detached before reading assertions. |

## PostgreSQL collation and the parent-page query

On 23 November 2026 Nathan approved (Instructions wiki D71) using PostgreSQL's existing maintenance rule for this producer. Rebuild affected indexes after a locale change before refreshing the database collation metadata. The comparison and ordering use the same database collation as the index. The check reads the catalog in the transaction that produces the members. An administrator's premature refresh, or changed sort rules with the same reported version, can leave undetected stale indexes. The runbook covers repair and verification of affected sets.

The comparison below used PostgreSQL 18.4 on Big Tam (x86-64, Debian, recorded collation version 2.36). One disposable temporary table contained one parent with a million device IDs. It had a primary key on the text pair (parent_id, device_id). After ANALYZE, each query supplied 5,000 distinct candidates (every 199th device). The first page requested 1,001 rows. The continuation also required device_id greater than device-00500000. The 30-second statement timeout never fired. These are single-process measurements on the synthetic table, including the heap visibility checks of a newly populated temporary table.

| Comparison and page | First execution | Repeat | Representative EXPLAIN ANALYZE |
| --- | ---: | ---: | --- |
| Database collation, first | 8.758 ms | 11.454 ms | Index Only Scan on the primary key, index conditions on parent_id and device_id = ANY. Returned 1,001 rows. |
| Database collation, continuation | 11.286 ms | 11.584 ms | Same plan, including device_id > cursor in the index condition. Returned 1,001 rows. |
| Explicit C collation, first | 60.955 ms | 74.316 ms | Sequential scan, 995,000 rows removed, 5,000 matches, top-N heapsort. |
| Explicit C collation, continuation | 53.479 ms | 55.259 ms | Sequential scan, 997,512 rows removed, 2,488 matches, top-N heapsort. |

Both plans used the same parent, candidate array and page limit. In the last two queries, the comparison, cursor and sort expressions explicitly collated the device ID with C. The indexed query retains the packet's existing keyset contract. These samples measure plan shape and cost for this distribution. They do not measure fleet latency.
