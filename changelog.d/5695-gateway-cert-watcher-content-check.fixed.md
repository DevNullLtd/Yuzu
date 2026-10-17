- **Gateway: a rotated certificate is picked up even when the new file has the same size and modification time (#5695).**
  The certificate watcher (management pins and the certificate expiry gauges) used
  a file's modification time and size to decide whether it had changed. A new
  certificate with a key of the same type is usually exactly the same size, and
  `cp -p`, `rsync -a` or `tar -p` keep the old modification time, so the gateway
  kept the old management pin (refusing the server's fan-out) and reported the file
  as healthy. It now reads each file on every check (`mgmt_pin_refresh_ms`, 5 s) and
  compares a SHA-256 of the contents; an unchanged file is still not parsed again
  or republished.
- **Gateway: a stream-status notice sent before the circuit breaker last recovered
  no longer counts against the recovered breaker (#5695).** Each notice worker
  carries the breaker generation it started in, as proxied calls already did; the
  notice itself is still retried or dropped exactly as before.
