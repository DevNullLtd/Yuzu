- **TAR perf status tokens and per-source health** (#1846). New `counters_unavailable`
  collect token for a supported platform whose counter reads failed. `tar.status` gains
  `<source>_last_status`, `<source>_consecutive_failures` and `<source>_last_status_at`
  per source, plus `procperf_procs_seen` and `perf_capture_method`.
