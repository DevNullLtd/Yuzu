# Resource Ledger — Find software panel on /software

Range: `2c3d0ac1489a57e1a4771ab9c0638687b7092271..HEAD` (branch `feat/sam-18-find-software-ui`)

Run: `governance.d/sam18-find-software-ui.Vm6NqR.jsonl`

## Summary

None new. This diff adds no fd, HANDLE, SOCKET, `FILE*`, `sqlite3*` or `sqlite3_stmt*`,
OpenSSL or BCrypt object, allocated C string, mapped library, temp path, subprocess, thread
or callback context. The new lambdas in the Find fragment handler are stack-scoped within the
request and run synchronously; the `store` pointer captured for the totals reads is a
non-owning borrow identical to the one `rest_api_v1.cpp` takes, and `web_server_->stop()`
precedes `software_inventory_store_.reset()`. The governance r1 fixes add two columns to the
existing `get_agent_software` SELECT (read through the same `PgResult` owned by RAII), a
`const char* const` verb literal in static storage, and a string tiebreak in a sort
comparator: no new owner.
