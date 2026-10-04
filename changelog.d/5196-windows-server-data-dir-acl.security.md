- **The Windows server installer now keeps the secrets it handles in a directory only Administrators and SYSTEM can open, and off the service's command line.** In every earlier version, `%ProgramData%\Yuzu Server` kept ProgramData's inherited permissions. Local users could read `yuzu-server.cfg` (the dashboard password hashes) and the TLS private keys in `certs\`, and could create files in its subfolders. The OIDC client secret was meant to be passed on the service's command line, which every local user can read. In practice an `sc.exe` quoting fault dropped every argument, so the service ran with none. The installer now:
  - locks that directory to exactly Administrators and SYSTEM, by SID so non-English Windows works;
  - verifies every entry it writes or resets before the install proceeds (the server's own subfolders in `data\` are not walked);
  - stores the PostgreSQL connection string (`postgres.dsn`) and the OIDC client secret (`oidc-client-secret`) there, passing only their paths to the server (`--postgres-dsn-file`, `--oidc-client-secret-file`);
  - writes the service's command line with its arguments and a quoted executable path, confirms it, and disables the service (exit code **10**) if it cannot.

  An upgrade over an earlier, unsecured install builds a new locked directory. It copies across only plain files that Administrators or SYSTEM own and no other account can change, from folders no other account can delete or rename in. It renames the old directory to `Yuzu Server.insecure-<date>-<time>` rather than changing or deleting it. After upgrading, rotate the passwords, TLS keys and OIDC secret it held. Move `data\agent-updates\` and `data\upload-blobs\` across if you ran the server, then delete the renamed directory. (#5196, #5210, #5272)

  **Behaviour changes for unattended installs:**
  - A connection string is now required on a fresh install and on an upgrade from any earlier version: `/POSTGRES_DSN_FILE=<file>`, which keeps the password out of logs, or `/POSTGRES_DSN=`. A `YUZU_POSTGRES_DSN` environment variable is honoured instead, with a warning. Before, the registered service could never start, because no connection string was ever passed.
  - An OIDC client secret is not carried from an earlier version; give it again. If one had been added to the service's command line by hand and OIDC is enabled on the upgrade, the upgrade refuses until it is.
  - An upgrade without `/ADMIN_PASS` keeps the existing accounts.
  - Upgrade in place rather than uninstalling first.
  - Any input, directory, file or certificate that cannot be secured stops the install before any file is installed, with exit code **7** and the reason in the setup log on a `PrepareToInstall:` line. A service already stopped by then stays stopped unless the abort came before the old directory was moved.
  - An unsecured data directory that no Yuzu Server installation is registered for is refused.

  **The setup log (`/LOG=`) and deployment tools record the full command line**, including any password given on it. Prefer the `_FILE` parameters. Windows server remains unsupported (ADR-0035). Separately, it cannot yet run under the Service Control Manager at all (#5325). The server's own CA and key-encryption keys stay in `C:\ProgramData\Yuzu\certs` for now (#5273).
