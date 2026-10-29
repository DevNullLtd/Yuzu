# Shared NAT64 discovery cache: security review record (2026-10-23)

Scope: ADR-0070 R1 slice 2b-1a (CRL source registration), `nat64_discovery.hpp`,
`resolver_errors.hpp`, `bounded_resolver.hpp`, the NAT64 path of `oidc_provider.cpp` and
`revocation_source_service.cpp`. Routed row: `.claude/routed-concerns-security-posture.md`.

## What changed

- The OIDC client had a private cache of NAT64 prefixes learned from `ipv4only.arpa` (RFC 7050).
  CRL source registration needs the same facts to classify an IPv6 address by the IPv4 address it
  embeds (so `Pref64 + 169.254.169.254` is metadata and `Pref64 + <server IPv4>` is the server).
  A second cache was rejected: two caches disagree, and a prefix learned by one would be unknown
  to the other. The cache moved to `nat64_discovery.hpp` and BOTH consumers use it.
- Properties: never shrinks; bounded at 64 prefixes (an answer that would exceed it is never
  installed partially); positive TTL 10 min, negative 1 min.
- One outcome vocabulary (`Nat64LookupOutcome`): answered, answered-none, failed, inconclusive.
  NXDOMAIN/NODATA is an ANSWER (`resolver_errors.hpp`, POSIX `EAI_NONAME`/`EAI_NODATA`, Windows
  `WSAHOST_NOT_FOUND`/`WSANO_DATA`); everything else is a failure. The OIDC client previously
  counted NXDOMAIN as a failure, which with steady OIDC traffic kept the shared entry "failed" and
  made IPv6 registrations 503 indefinitely and audit rows falsely say `nat64=stale`. **This is an
  OIDC behaviour change** (named in the changelog fragment): NXDOMAIN no longer logs the
  "lookup failed" warning, and the entry is cached for the negative TTL as "answered, none".
- A lookup whose budget was clamped below a full lookup and timed out, or that found the resolver
  pool busy, is INCONCLUSIVE: failed for that call, recorded nowhere.
- Registration classifies each IPv6 address with the declared prefixes and, separately, with the
  discovered ones; either view yielding a never-allowed class refuses it and every class either
  yields must be confirmed. A discovered ULA /96 therefore cannot turn unique-local into public.
- Registration FAILS CLOSED (retryable 503, `retry_after_ms` = the negative-cache remainder, 60 s
  for overflow) when no lookup has ever answered or the set overflowed. If a refresh fails after an
  earlier success, everything learned is applied and the audit row carries `nat64=stale`.

## Residuals (accepted, disclosed)

- **Hostile or lying resolver.** A resolver that answers NXDOMAIN or withholds the AAAA record
  suppresses discovery (the answer is believed). Mitigation: declare `--oidc-nat64-prefix` for any
  network whose prefix is known. One answer with more than 64 prefixes freezes the set in overflow
  (IPv6 refused, OIDC and CRL alike) until a later answer fits or the server restarts; the metric
  `yuzu_server_nat64_discovery_overflowed` shows it. The set never shrinks, so a renumbered network
  needs a restart.
- **macOS and A-only answers.** Some resolvers (and the macOS system resolver in some modes)
  return only A records for `ipv4only.arpa`; that reads as "answered, none", so a DNS64 prefix is
  not learned there. Declare the prefix.
- **Classification is of the address as the server sees it.** It cannot know a translator that is
  neither declared nor discoverable (CLAT/464XLAT, VPNs, proxies).
- **Registration-time only.** The registration check is a point-in-time judgement. **The CRL
  fetcher (2b-1b) must re-resolve and re-classify at fetch time** against the then-current cache;
  it must not trust the classes stored at registration for a name that may now resolve elsewhere.
- The resolver's detached worker threads are capped at 16 per pool (`bounded_resolver.hpp`).
- **macOS and AI_ADDRCONFIG.** The system resolver on macOS (and glibc with `AI_ADDRCONFIG` set) can drop AAAA records on a host with no usable IPv6 route, which would read as "answered, none" for `ipv4only.arpa`. The bounded resolver does not set `AI_ADDRCONFIG`, but a host whose own resolver library filters AAAA the same way has the same residual: declare `--oidc-nat64-prefix` there.
- **Discovery is single-flight and has its own cap-1 pool.** The cache admits at most one lookup
  at a time; a caller that finds one running waits up to its own budget, then is inconclusive. The
  lookup runs in `nat64_probe_pool()` (capacity one), so even after its caller gave up, a hung
  resolver pins that one worker and nothing else: a burst of IPv6 sign-ins can no longer fill the
  16-slot pool CRL registration resolves hosts in (previously ~half of registrations, IPv4 hosts
  included, answered `dns_busy`). A late answer from an abandoned flight is discarded.
- The OIDC probe now resolves through `bounded_resolver.hpp` (plain `getaddrinfo`, its own error
  classifier `resolver_errors.hpp`), not through OIDC's host resolver or httplib's wrapper: httplib
  returns `EAI_NODATA` for every CFHost error on macOS, which would read every failure as an
  answer. A busy pool or a clamped timeout is INCONCLUSIVE and is not remembered, so a busy
  resolver keeps IPv6 CRL registrations at 503 (`dns_busy`) until it recovers.

## Tests

`test_revocation_source_surface.cpp` (cache never-shrink, failure/overflow, inconclusive does not
poison, interleaving of two consumers through the cache API, retry hint equals negative TTL, ULA
probe, pinned bound and TTLs, the resolver-status to outcome mapping). `test_oidc_egress.cpp` and
`test_oidc_provider.cpp` exercise the OIDC side through its injected test resolver, which supplies
addresses only: the OIDC probe's real resolver mapping (NXDOMAIN, failure, busy) is pinned through
`nat64_outcome_from_resolve`, the ONE function both consumers call, not through an OIDC-level
failure injection.
