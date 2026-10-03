- **The Windows server installer now keeps every server secret in a directory only Administrators and SYSTEM can open, and off the service's command line.** In every earlier version, `%ProgramData%\Yuzu Server` kept ProgramData's inherited permissions, so local users could read `yuzu-server.cfg` (the dashboard password hashes) and the TLS private keys in `certs\`, and could create files in its subfolders. The OIDC client secret was passed on the service's command line, which every local user can read, and the server's own CA key and key-encryption keys lived in `C:\ProgramData\Yuzu\certs`, a directory shared with the agent. The installer now:
  - locks `%ProgramData%\Yuzu Server` to exactly Administrators and SYSTEM, by SID so non-English Windows works, and verifies every entry before the install proceeds;
  - stores the PostgreSQL connection string (`postgres.dsn`) and the OIDC client secret (`oidc-client-secret`) there, passing only their paths to the server (`--postgres-dsn-file`, `--oidc-client-secret-file`);
  - points the server's CA, default certificates and key-encryption keys at `certs\` inside the locked directory (`--ca-dir`), copying existing ones from `C:\ProgramData\Yuzu\certs` on upgrade.

  An upgrade over an earlier, unsecured install builds a new locked directory, copies across only plain files owned by Administrators or SYSTEM, and renames the old directory to `Yuzu Server.insecure-<date>-<time>` rather than changing or deleting it. Delete that directory once the upgrade is confirmed. (#5196, #5210, #5272, #5273)

  **Behaviour changes for unattended installs:**
  - A fresh install now requires a connection string: `/POSTGRES_DSN_FILE=<file>`, which keeps the password out of the `/LOG=` file, or `/POSTGRES_DSN=`. Before, the registered service could never start, because no connection string was ever passed.
  - An upgrade without `/ADMIN_PASS` keeps the existing accounts.
  - Any input, directory, file or certificate that cannot be secured stops the install before anything is installed, with exit code **7** and the reason in the setup log on a `PrepareToInstall:` line.
  - An unsecured data directory that no Yuzu Server installation is registered for is refused.

  **The setup log (`/LOG=`) records the full command line**, including any password given on it. Prefer the `_FILE` parameters, and protect or delete the log. A Windows agent on the same machine no longer finds the server's CA automatically; give it `--ca-cert "C:\ProgramData\Yuzu Server\certs\default-ca.pem"`. Windows server remains unsupported (ADR-0035). Separately, it cannot yet run under the Service Control Manager at all (#5325).
