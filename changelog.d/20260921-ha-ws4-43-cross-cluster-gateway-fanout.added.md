- **The server can now dispatch commands to the correct gateway when agents are split across
  multiple independently-clustered gateways.** Deployments running more than one gateway cluster
  (for example, one per region) previously had every command forwarded to a single configured
  gateway address, regardless of which cluster the target agent was actually connected to — a
  command destined for an agent on a different cluster was silently misdirected. A new
  `--gateway-cluster-addr` option (repeatable, `cluster_id=host:port`) lets an operator configure a
  per-cluster gateway management address; the server now dials the cluster an agent's gateway
  actually announced, falling back to the existing single `--gateway-command-addr` for any
  deployment that doesn't configure per-cluster addresses (no change in behavior for existing
  single-cluster installs). A malformed or duplicate `--gateway-cluster-addr` entry fails startup
  with a clear error. **This is per-cluster routing only — it does not provide trust-zone isolation
  between clusters for a given agent's identity**, so do not rely on it to keep, e.g., a DMZ-zone
  gateway from being able to intercept an internal-zone agent's traffic; that guarantee is tracked
  separately and does not exist yet.
