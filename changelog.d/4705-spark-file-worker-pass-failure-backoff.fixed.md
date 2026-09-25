- **A persistently failing File Spark worker pass now backs off, is logged, and is reported
  `inert` (#4658).** The Windows agent's File Spark mechanism (Spark is the agent's event-driven change
  detection) retried a throwing worker pass with no delay, no counter and no log, so a persistent
  failure spun the worker and was invisible to the heartbeat. It now retries on a doubling backoff
  starting at the mechanism's sweep cadence (50 ms by default) and capped at 30 s, logs at
  consecutive failures 1, 2, 4, 8 and so on, and after three consecutive failed passes reports the
  mechanism `inert` (excluded from the `yuzu.spark_mechs` capability list) until a pass succeeds,
  matching the Registry mechanism's sweeper. The operator-visible signals are the
  `spark_file: worker pass failed (consecutive #N) - retrying in M ms`,
  `spark_file: worker failing persistently - file sparks reported inert until a pass succeeds` and
  `spark_file: worker pass recovered after N failure(s)` log lines and the `inert` exclusion; the
  count of failed passes is test-visible only. No watch is armed through Spark until Spark
  detection is turned on, which it is not in production agents; the fix is one of the
  preconditions for turning Spark detection on.
