- **Compose Wizard: Operator certs mode now starts, and keeps its KEK across recreates (#5420).**
  Operator mode bind-mounted the operator's PEM files read-only over `/etc/yuzu/certs`, the
  directory where the server writes its secrets KEK and internal CA. The server could not
  write the KEK, so a generated Operator-mode stack stopped at its first boot
  (`provider_failure: kek init`) before it registered a KEK or stored any data. Operator mode
  now mounts the PEM files read-only at a separate path, `./certs:/etc/yuzu/tls:ro`, and gives
  `/etc/yuzu/certs` the same writable volume as the other modes (the named `server-certs`
  volume when named volumes are on or Postgres is external). The `--cert`/`--key`/`--ca-cert`
  paths default to `/etc/yuzu/tls/...`, and the wizard refuses any of them outside
  `/etc/yuzu/tls/`. The server refuses a private key with any group or other permission bit set, so
  `server.key` must be owned by uid 999 with mode 0600; the generated header says how. **If
  you generated an Operator-mode compose before this fix:** change its `./certs` mount to
  `./certs:/etc/yuzu/tls:ro`, point the three paths at `/etc/yuzu/tls/`, and add
  `- server-certs:/etc/yuzu/certs` to the server's `volumes:` with `server-certs:` declared
  under the top-level `volumes:`. That stack never booted, so there is no KEK to carry over.
  If you instead applied the earlier workaround (you dropped `:ro` and made `./certs`
  writable), your KEK and CA are in `./certs`. Leave that stack as it is: switching it to the
  new layout without first copying those files into the new volume makes the server refuse
  to start (`kek_unresolvable`).
