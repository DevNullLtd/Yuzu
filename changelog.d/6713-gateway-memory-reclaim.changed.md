- **The gateway gives memory back after its agent count drops.** After a reconnect
  storm or a drain, a new `yuzu_gw_mem_reclaim` process garbage-collects the
  gateway's large long-lived processes (connection supervisors, acceptors,
  registries) when the agent count has fallen by a quarter of its peak and by
  at least 1,000 agents, and again 30 s later. On a gateway built on glibc
  Linux (the chiselled image, the `.deb` and `.rpm`), each pass, plus a
  periodic one every 5 minutes, also calls `malloc_trim(0)` through a new
  one-function NIF. The default Alpine image, macOS and Windows have no NIF
  and collect only. On a 10,000-connection probe this cut the memory still
  held two minutes after every connection closed from 251-343 MiB to about
  150 MiB. Tunable under `{yuzu_gw, [{mem_reclaim, #{...}}]}` (see
  `docs/user-manual/gateway.md`, "Giving memory back after a drop"). Building
  the gateway on glibc Linux now needs a C compiler (`cc`, or `CC`).
