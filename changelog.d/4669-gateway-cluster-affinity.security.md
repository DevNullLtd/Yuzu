- **Multi-cluster gateway mode: agent<->cluster affinity closes the claim-then-answer
  hijack (#4669).** `ProxyRegister` re-registers any already-approved `agent_id` with
  no per-agent secret, and `register_fresh`'s newer-epoch-wins rule let whichever
  gateway claimed an agent most recently win the durable routing row — in
  multi-cluster mode (`--gateway-cluster-addr`, opt-in, no production deployments
  today) this meant a rogue/compromised gateway could claim an agent already live on
  a different cluster, then legitimately intercept its command payloads and forge its
  terminal results, despite each `--gateway-cluster-addr` entry conceptually modeling
  a separate trust zone. `GatewayRouteStore`'s `agent_routes` now carries a STICKY
  `home_cluster_id`, distinct from the ephemeral `cluster_id`/`gateway_node` that
  `register_fresh` resets on every fresh registration: `announce_connected` refuses,
  atomically, any session-matched claim whose `cluster_id` differs from an
  already-bound `home_cluster_id`, and `NotifyStreamStatus`'s CONNECTED handler adds a
  read-only pre-check that refuses the whole notification before publishing anything,
  for the common case; on a defensive-in-depth definitive write-time conflict (the
  pre-check missed it, e.g. under a transient store degradation) the already-published
  in-memory placement is reverted rather than left live. A first-ever connection still
  binds its cluster on trust (TOFU); re-homing to a genuinely different cluster
  requires either the prior cluster's lease having genuinely EXPIRED (the reaper's
  separate expired-lease sweep, unaffected by this fix) or an explicit operator
  `GatewayRouteStore::clear_cluster_affinity` action — and, since a pre-merge review
  found a single rogue registration (or even a legitimate agent's own ordinary
  disconnect) could otherwise manufacture the reaper's "tombstoned long enough"
  predicate on a row whose affinity was never actually stale, the reaper now never
  purges a row that still carries a bound home_cluster_id, full stop, regardless of
  whether a session is currently claiming it. Such a row is instead parked
  (soft-tombstoned if a claim was still outstanding; left untouched if it was already
  tombstoned) with the affinity preserved indefinitely, so neither an abandoned rogue
  claim nor an ordinary disconnect can be waited out to force a re-home — only a
  genuine lease expiry or an explicit operator action still clears it. Single-cluster
  deployments are unaffected (a stable `cluster_id` is presented on every reconnect).
  **Scope:** this closes the `GatewayRouteStore` half (mitigation 1) of the two named
  in the issue; per-cluster peer-identity binding at the gateway-upstream listener
  (mitigation 2) is not implemented, so `--gateway-cluster-addr` still does not
  provide full peer-authenticated trust-zone isolation between clusters — see
  `docs/adr/2002-high-availability-architecture.md` §7d's `#4669` update and
  `gateway_mgmt_stub_pool.hpp`'s TRUST BOUNDARY note.
