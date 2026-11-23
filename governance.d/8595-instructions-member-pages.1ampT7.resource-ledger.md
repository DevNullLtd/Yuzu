# Packet 1.3 member-page resource ledger

| Resource | Ownership and lifetime | Failure and release |
| --- | --- | --- |
| PostgreSQL connection lease | The store acquires one timed pool lease and transfers it into the synchronous transaction. The collation reader and page helper borrow its connection only during the callback. | The pool rolls back a refused read and releases the lease after commit or rollback. |
| PostgreSQL results | Each catalog, isolation and page query owns its result via PgResult. Device IDs and cursors are copied before destruction. | Scoped result destructors free each result on success and error. A failed continuation discards the accumulated vector. |
| Candidate filter and page buffer | A single operation owns its candidate set, each page and the bounded accumulated matches. | No callback escapes the transaction. Stack unwinding destroys the containers. |
| Test database and instrumentation | Each PostgreSQL fixture owns its isolated database. A local connection installs the fault view. The marker is transaction-local. | RAII releases connections before the database is removed. Captured logging is detached before reading assertions. |
