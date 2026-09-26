- **Agent logging is now asynchronous, with a new self-exit code 5 (#4666).** The agent no longer
  writes log lines on the thread that produced them; a dedicated worker thread now drains a
  bounded, fixed-size queue instead, so a stalled log destination (a full disk, a stuck pipe under
  a container's log driver) can no longer stall the agent itself. Under sustained overload the
  queue drops the oldest still-queued lines rather than blocking or growing. Agent shutdown gains
  one more possible self-exit code, `5`, distinct from the existing `1`/`3`/`4`, if tearing down
  the logger does not complete within its own short internal deadline, or fails outright while
  doing so. Not a breaking change: same log format, same `--log-file`/rotation behaviour, no new
  flags — with one exception: the "Received signal, shutting down..." line printed on
  `SIGINT`/`SIGTERM`/Ctrl-C used to be a raw write straight to stderr and is now routed through the
  configured logger like everything else, so it now also lands in `--log-file` and picks up JSON
  formatting under `--log-format json` — and, being an ordinary `info`-level line now rather than
  an unconditional raw write, it is silently absent entirely at `--log-level warn` or above.
  Operators with a supervisor script or alert keyed to a fixed agent exit-code set should widen it
  to include `5`. See "Stopping a wedged agent" in `docs/user-manual/server-admin.md`.
