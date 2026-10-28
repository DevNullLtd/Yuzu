- **Gateway: a rotated certificate is picked up even when the new file has the same size and modification time (#5695).**
  The certificate watcher (management pins and the certificate expiry gauges) used
  a file's modification time and size to decide whether it had changed. A new
  certificate with a key of the same type is usually exactly the same size, and
  `cp -p`, `rsync -a` or `tar -p` keep the old modification time, so the gateway
  kept the old management pin (refusing the server's fan-out) and reported the file
  as healthy. It now reads each file on every check (`mgmt_pin_refresh_ms`, 5 s) and
  compares a SHA-256 of the contents; an unchanged file is still not parsed again
  or republished.
- **Gateway: a certificate whose expiry date the gateway cannot parse still pins
  (#5695).** A management pin file whose certificate carried a `notAfter` in a time
  form the gateway does not read (anything but RFC 5280's) was treated as "not a
  certificate", so the previous key stayed pinned and the server's rotation to that
  certificate was refused. Its key now pins; only its expiry is unknown: the file
  reads `yuzu_gw_cert_file_readable` 1, the
  `yuzu_gw_cert_expiry_timestamp_seconds` series for it is removed and the gateway
  logs one warning. The same applies to listener and upstream certificate files. A
  block that does not decode as a certificate still pins nothing.
- **Gateway: a stream-status notice sent before the circuit breaker last recovered
  no longer counts against the recovered breaker (#5695).** Each notice worker
  carries the breaker generation it started in, as proxied calls already did; the
  notice itself is still retried or dropped exactly as before.
