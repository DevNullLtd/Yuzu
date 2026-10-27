# Shared NAT64 discovery cache and OIDC bounded resolver: security review record (2026-10-23)

Scope: `nat64_discovery.hpp`, `nat64_probe.hpp`, `resolver_errors.hpp`, `bounded_resolver.hpp` and
the OIDC egress path of `oidc_provider.cpp` (the `ipv4only.arpa` probe and the host-name check).
Routed row: `.claude/routed-concerns-security-posture.md`. This record covers the OIDC change
only; features that later read the same cache (a CRL source registry and fetcher) add their own
consumer section here when they land.

## What changed

- The OIDC client had a private cache of NAT64 prefixes learned from `ipv4only.arpa` (RFC 7050).
  The cache moved to `nat64_discovery.hpp` so every egress check shares ONE set: two caches
  disagree, and a prefix learned by one would be unknown to the other. OIDC is its only consumer
  today.
- Properties: never shrinks; bounded at 64 prefixes (an answer that would exceed it is never
  installed partially); positive TTL 10 min, negative 1 min.
- One outcome vocabulary (`Nat64LookupOutcome`): answered, answered-none, failed, inconclusive.
  NXDOMAIN/NODATA is an ANSWER (`resolver_errors.hpp`, POSIX `EAI_NONAME`/`EAI_NODATA`, Windows
  `WSAHOST_NOT_FOUND`/`WSANO_DATA`); everything else is a failure. The OIDC client previously
  counted NXDOMAIN as a failure. **This is an OIDC behaviour change** (named in the changelog
  fragment and `upgrading.md`): NXDOMAIN no longer logs the "lookup failed" warning, and the entry
  is cached for the negative TTL as "answered, none". It is needed so that any second consumer of
  the cache does not see the entry flipped to "failed" by ordinary OIDC traffic.
- A lookup that found the resolver pool busy (or, for a consumer with a clamped budget, timed out)
  is INCONCLUSIVE: failed for that call, recorded nowhere. OIDC never clamps its budget, so for
  OIDC this is the busy-pool and the waiter-without-an-answer case.
- **Log discipline (review point 3).** An inconclusive call sets `looked_up` but not
  `answered_now`; the OIDC caller used to warn on `looked_up && !answered_now`, which would have
  repeated "lookup failed" on every IPv6 vet while the single probe worker is stuck. `Nat64Discovery`
  now carries `inconclusive`, and OIDC warns only for a real failure, which is cached for the
  negative TTL and so logs at most once a minute. Pinned by a test.
- **Host check.** `resolve_host_addresses` (every OIDC host vet) no longer calls
  `httplib::detail::getaddrinfo_with_timeout` on Linux and macOS: it runs in the bounded resolver
  with its own cap-8 pool. Windows keeps its `GetAddrInfoExW` path and abandoned-request ledger
  unchanged (that path never had the glibc defect). httplib's wrapper hands glibc a request that
  lives on the caller's stack and, on timeout, returns without waiting for the resolver, which
  later writes into the dead frame (use-after-free); the bounded resolver's worker owns all it
  touches.
- Discovery FAILS OPEN for OIDC on purpose: when no lookup has ever answered, OIDC logs and
  proceeds (most networks have no DNS64). Overflow is the one state that refuses.

## Residuals (accepted, disclosed)

- **Hostile or lying resolver.** A resolver that answers NXDOMAIN or withholds the AAAA record
  suppresses discovery (the answer is believed). Mitigation: declare `--oidc-nat64-prefix` for any
  network whose prefix is known. One answer with more than 64 prefixes freezes the set in overflow
  (IPv6 refused) until a later answer fits or the server restarts; the metric
  `yuzu_server_nat64_discovery_overflowed` shows it. The set never shrinks, so a renumbered network
  needs a restart.
- **macOS and A-only answers.** Some resolvers (and the macOS system resolver in some modes)
  return only A records for `ipv4only.arpa`; that reads as "answered, none", so a DNS64 prefix is
  not learned there. Declare the prefix.
- **Classification is of the address as the server sees it.** It cannot know a translator that is
  neither declared nor discoverable (CLAT/464XLAT, VPNs, proxies).
- The resolver's detached worker threads are capped per pool (`bounded_resolver.hpp`): 1 for
  discovery, 8 for the OIDC host check. A worker stuck in a blocking resolver pins its slot until
  process exit; the in-flight gauges show it.
- **macOS and AI_ADDRCONFIG.** The system resolver on macOS (and glibc with `AI_ADDRCONFIG` set) can drop AAAA records on a host with no usable IPv6 route, which would read as "answered, none" for `ipv4only.arpa`. The bounded resolver does not set `AI_ADDRCONFIG`, but a host whose own resolver library filters AAAA the same way has the same residual: declare `--oidc-nat64-prefix` there.
- **Discovery is single-flight and has its own cap-1 pool.** The cache admits at most one lookup
  at a time; a caller that finds one running waits up to its own budget, then is inconclusive. The
  lookup runs in `nat64_probe_pool()` (capacity one), so even after its caller gave up, a hung
  resolver pins that one worker and nothing else: a burst of IPv6 sign-ins cannot fill the
  OIDC host check's pool. A late answer from an abandoned flight is discarded.
- The OIDC probe resolves through `bounded_resolver.hpp` (plain `getaddrinfo`, its own error
  classifier `resolver_errors.hpp`), not through OIDC's host resolver or httplib's wrapper: httplib
  returns `EAI_NODATA` for every CFHost error on macOS, which would read every failure as an
  answer. On Windows this moves the probe from `GetAddrInfoExW` to plain `getaddrinfo` on a worker
  thread; the Windows leg of the resolver is read-reviewed and simulated, so Windows CI is a merge
  condition.

## Tests

`test_bounded_resolver_nat64.cpp` (resolver cap and timeout, exact statuses, error-code classifier,
cache never-shrink, constants and the 64-prefix bound, inconclusive does not poison, single-flight,
waiters share the leader's answer, the flight is released on every exit, the status-to-outcome
mapping, retry hint equals the negative TTL). `test_oidc_egress.cpp` and `test_oidc_provider.cpp`
exercise the OIDC side: the probe's wiring through the real bounded resolver via
`set_nat64_probe_lookup_for_test` (NXDOMAIN answered and cached, failure cached, busy not
remembered), single-flight under concurrent refreshes, the host check through the bounded resolver,
and that an inconclusive probe does not warn.
