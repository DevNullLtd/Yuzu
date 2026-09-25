- **A command forwarded to a gateway-connected agent now resolves to a terminal outcome instead
  of getting stuck forever, for every gateway-forwarding failure case (#4672).** The mgmt-plane
  peer pin rejecting this server's certificate; the gateway staying unreachable after retries; a
  target cluster with no configured management address; a response that could not be attributed
  to the intended agent — previously logged the failure and dropped the command silently: the
  executions drawer and any API caller polling that command's status saw it idle at RUNNING (or
  never resolve at all), with no terminal signal. Each of these cases now resolves the command to
  a terminal `FAILURE` with a specific reason code (`gateway_unauthenticated`,
  `gateway_unavailable`, `gateway_unknown_cluster`, `gateway_agent_mismatch`,
  `gateway_forward_failed`), applied through the same path a real gateway response already uses,
  at most once per command across every retry attempt — including a real RUNNING progress frame
  followed by an exhausted-retry failure, which a pre-merge review found the first cut of this fix
  still left stuck (fixed before merge). Durable automatic re-drive with backoff is deliberately
  NOT provided for this path yet — see `docs/adr/2002-high-availability-architecture.md` §7e for
  why, tracked in #4690 — so an operator who wants to retry after fixing the underlying cause (a
  cert/pin mismatch, a missing `--gateway-cluster-addr`) currently re-dispatches the command
  manually. One case remains open, tracked separately: a gateway response stream that closes
  cleanly with zero frames still does not resolve (#4691).
