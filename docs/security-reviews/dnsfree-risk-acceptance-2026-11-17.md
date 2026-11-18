# Risk acceptance: DnsFree(DnsFreeFlat) on the DnsGetCacheDataTable list (WP12)

- Decider: Fraser Jarvis
- Accepted: 2026-11-17
- Expiry: 2027-02-17
- Tracking issue: #8148 (the expiry is tracked there; the owner re-verifies on a Windows build
  where `DnsGetCacheDataTable` returns TRUE before that date)

## Risk accepted

`agents/shared/win_dns_cache_table.hpp` (`DnsCacheTableOwner`) frees the list returned by the
undocumented dnsapi export `DnsGetCacheDataTable` with `DnsFree(p, DnsFreeFlat)` for every node and
every name buffer (used by `network_config.dns_cache` and `ioc.check` `domains` on Windows). That
this matches the allocator of the real table has NOT been verified against a real table: on the
only Windows host available (Windows 11 build 26200) the export returned FALSE with an empty list
on every call, so no real list was ever produced. If the assumption is wrong, the failure is heap
corruption or a crash in the agent the first time a non-empty table is freed. Before this change
the behaviour was a leak of the whole table on every call.

## Scope

This acceptance covers ONLY the possibility that `DnsFree(DnsFreeFlat)` is not the allocator that
produced the list. It does NOT cover list aliasing (a cycle, a shared node, a name that aliases a
node): that is handled in code and tested (including under AddressSanitizer), and a regression
there is a defect, not an accepted risk.

## Compensating controls

- The free logic is exercised with a process-heap stand-in list on Windows: 2000 lists of 200
  nodes freed with flat memory growth, 500 lists freed under a thrown exception with no growth,
  and a leak control that grows about 43 MB.
- `agents/plugins/echo/src/echo_dns_collector.cpp` already frees the same list with the same
  `DnsFree(..., DnsFreeFlat)` calls, so this adds no new assumption to the agent.
- The walk (`agents/shared/dns_cache_list.hpp`) is defensive against list aliasing: one visited set
  for nodes and names; it stops before reading a node already seen, stops if a name aliases any
  node, frees a buffer shared by healthy nodes once, has a node ceiling (65536), and never throws
  (it leaks the remainder instead).
- An unreadable cache (the API returning FALSE, as on build 26200) never reaches the free path and
  is reported to the operator as CONSTRAINED, not clean.
- Owner follow-up before expiry: run `ioc.check` and `network_config.dns_cache` repeatedly on a
  Windows build where `DnsGetCacheDataTable` returns TRUE with a non-empty list, and watch private
  bytes and for crashes.
