- **DEX performance Reporting card uses an OS-aware denominator** (#1845). The /dex
  Performance card, `GET /api/v1/dex/perf/fleet` and MCP `get_dex_perf_fleet` carry
  `perf_capable_online` (online devices whose OS has a perf collector) alongside the
  unchanged `windows_online`; the not-reporting wording is corrected.
