- **Break-glass CLI prerequisites corrected, and two broken doc links fixed.**
  `server-admin.md` told operators that `--mfa-reset` requires `--config` + `--data-dir` and that
  `--break-glass-arm` requires `--data-dir`. Both are pre-ADR-0006 language: each actually requires
  the Postgres auth store (`--postgres-dsn` / `YUZU_POSTGRES_DSN`), and neither consults
  `--data-dir` at all — plus the same `--config` the service uses when it is not at the default
  `/etc/yuzu/yuzu-server.cfg`, since the container images run with
  `--config /var/lib/yuzu/yuzu-server.cfg` and without it the binary falls into interactive
  first-run setup and exits. Wrong prerequisites on a lockout-recovery path are costly precisely
  when they are read.
- **Removed a fabricated default-credentials table from the server-admin manual.** It claimed a
  `yuzu-server.cfg` ships with `admin`/`administrator` and `user`/`useroperator` so the server
  starts without interactive setup. No shipped artifact contains that pair: no image `COPY`s a
  config, the sole checked-in sample (`deploy/config/uat/`) holds one `admin` entry whose
  password is generated per-run by `scripts/start-viz-uat.sh`, and `useroperator` appears
  nowhere in the tree. Replaced with what is true, including that first-run setup prompts for
  two accounts rather than one. Also repointed `rest-api.md`'s Tag-source-precedence link (the guide is one
  directory up) and `upgrading.md`'s Server Administration link (the file is `server-admin.md`).
