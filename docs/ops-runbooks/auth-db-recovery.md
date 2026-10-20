# Auth Store Recovery Runbook

Operator runbook for recovering a Yuzu server when authentication is broken or
an operator is locked out. Auth data lives in the server's **PostgreSQL
substrate, schema `auth`** (ADR-0006/0007) — there is no `auth.db` file, and
there is nothing to move aside.

**Read this first if you are mid-incident:** the two facts that change how you
recover, relative to the SQLite era, are

1. **The server fails closed without Postgres.** No SQLite fallback, no
   degraded mode. If Postgres is unreachable, `yuzu-server` refuses to start —
   so "auth is broken" is usually "Postgres is broken", and the fix is a
   Postgres fix, not a Yuzu fix.
2. **TOTP secrets are encrypted with a key that is NOT in the database.** A
   Postgres backup on its own cannot restore working MFA. See
   [Backup — the KEK pairing rule](#backup--the-kek-pairing-rule). This is the
   single most common way to turn a recoverable incident into an unrecoverable
   one.

This runbook assumes a single-node Yuzu deployment. For HA, coordinate with the
active leader; see `docs/architecture.md`.

> **Looking for the SQLite procedure?** It is gone, deliberately. Every
> file-based step (`sqlite3 .backup`, moving `auth.db`/`-wal`/`-shm` aside,
> `UPDATE`/`DELETE` against `auth.db`, the Windows Defender exclusion for those
> files) is inapplicable and will not work. Git history has it if you are
> recovering a pre-migration release.

## Detection signal

`yuzu-server` exits non-zero at startup. `journalctl -u yuzu-server` (Linux) or
the Windows event log shows one of these, and they mean different things:

| Log line | Meaning | Go to |
|---|---|---|
| `[PG] Refusing to start: no PostgreSQL DSN` | `--postgres-dsn` / `YUZU_POSTGRES_DSN` is unset | [Config](#no-dsn-configured) |
| `[PG] Refusing to start: cannot reach PostgreSQL substrate: …` | Postgres down, wrong DSN, network/auth failure | [Substrate down](#postgres-substrate-unreachable) |
| `[PG] Refusing to start: auth store (AuthDB) migration/open failed` | Database reachable, `auth` schema could not be created/opened | [Migration failure](#auth-schema-migration-failure) |
| `SecretCodec::init() failed for the auth store bootstrap — …` or `[PG] Refusing to start: SecretCodec::init() failed — …` | The secrets seam could not initialise — usually a missing or unreadable KEK | [KEK problems](#kek-missing-or-unreadable) |
| `SecretCodec::init() failed` … `kek_orphaned: stored secret blobs reference KEK version(s) […] absent from kek_meta` | A stored secret blob (for example one account's TOTP secret) names a key-encryption-key version that is not registered in `secrets.kek_meta` | [Stored secret names an unregistered KEK version](#stored-secret-names-an-unregistered-kek-version) |
| `[auth] Refusing to start: the 'engine:' namespace …` | An `engine:`-prefixed principal collides with the reserved namespace | `docs/ops-runbooks/engine-principal-store-recovery.md` |

If the shipped systemd unit is in use it retries `StartLimitBurst=3` times
within `StartLimitIntervalSec=60`, then enters `failed`:

```
$ systemctl status yuzu-server
● yuzu-server.service - Yuzu Endpoint Management Server
     Active: failed (Result: start-limit-hit) since ...
```

That `failed` state is deliberate — it stops a crash-loop from drowning the
journal. Clear it with `systemctl reset-failed yuzu-server` once fixed.

## Recovery procedures

### No DSN configured

The server has no auth store at all. Set the DSN and restart:

```bash
# Either the flag, in /etc/yuzu/yuzu-server.cfg …
--postgres-dsn postgresql://yuzu:...@db.internal:5432/yuzu
# … or the environment variable (preferred for secrets — keeps the password
# out of `ps` output and the config file).
sudo systemctl edit yuzu-server   # Environment=YUZU_POSTGRES_DSN=postgresql://…
sudo systemctl restart yuzu-server
```

### Postgres substrate unreachable

Yuzu is the symptom, not the cause. Confirm from the Yuzu host, as the service
account, using the same DSN the server uses:

```bash
sudo -u _yuzu psql "$YUZU_POSTGRES_DSN" -c 'SELECT 1'
```

Work the usual causes in order: Postgres service down; `pg_hba.conf` rejecting
the host/user; TLS requirement mismatch; network path (firewall, security
group, DNS); credential rotation that did not reach Yuzu; connection limit
exhausted (`FATAL: sorry, too many clients already`).

Yuzu restarts cleanly once Postgres is reachable — no Yuzu-side repair is
needed, and **no auth data is lost by the outage itself**. Sessions are
durable rows in Postgres (see [Sessions](#sessions-are-durable)), so an
operator whose session did not reach its absolute lifetime or idle timeout
during the outage does not need to sign in again after the restart.

### `auth` schema migration failure

The database is reachable but the `auth` schema could not be created or
opened. Usual causes, in likelihood order:

1. **Insufficient privilege.** The DSN's role needs `CREATE` on the database
   to run migrations. Verify:
   ```bash
   psql "$YUZU_POSTGRES_DSN" -c "\du"        # role attributes
   psql "$YUZU_POSTGRES_DSN" -c "SELECT has_database_privilege(current_user, current_database(), 'CREATE');"
   ```
2. **Schema drift** — a partially-created `auth` schema from an interrupted
   migration, or hand-made objects colliding with migration DDL. Inspect
   before touching anything:
   ```bash
   psql "$YUZU_POSTGRES_DSN" -c "\dt auth.*"
   psql "$YUZU_POSTGRES_DSN" -c "SELECT * FROM public.schema_meta WHERE store = 'auth';"
   ```
   The migration runner refuses to proceed on drift rather than guessing —
   that refusal is the fail-closed behaviour working, not a bug. Resolve by
   restoring from backup (preferred) or, on a deployment with no auth data
   worth keeping, dropping the schema so it rebuilds from the seed config:
   ```bash
   # DESTRUCTIVE — every local account, MFA enrolment and enrollment token in
   # this schema is discarded. Take a dump first even if you think it is empty.
   pg_dump "$YUZU_POSTGRES_DSN" --schema=auth > /var/backups/yuzu/auth-before-drop-$(date +%s).sql
   psql "$YUZU_POSTGRES_DSN" -c 'DROP SCHEMA auth CASCADE;'
   psql "$YUZU_POSTGRES_DSN" -c "DELETE FROM public.schema_meta WHERE store = 'auth';"
   sudo systemctl restart yuzu-server
   ```
   On restart the server re-seeds the admin account from `yuzu-server.cfg`.

### KEK missing or unreadable

`SecretCodec::init()` failed. The key-encryption key (KEK) that protects
envelope-encrypted columns lives on the **filesystem, not in Postgres**:

| | Path |
|---|---|
| Linux / macOS | `/etc/yuzu/certs/secrets-kek-v<N>.key` |
| Windows | `C:\ProgramData\Yuzu\certs\secrets-kek-v<N>.key` |

The directory is the one given by `--ca-dir`, falling back to the platform
default above. Files are `0600`, the directory `0700`, owned by the service
account (a restrictive DACL on Windows).

Check, as the service account:

```bash
sudo -u _yuzu ls -l /etc/yuzu/certs/secrets-kek-v*.key
```

- **Present but unreadable** → ownership/permissions drifted (a restore that
  did not preserve them, or a `chown -R` that overreached). Fix ownership to
  the service account; leave the modes at `0600`/`0700`.
- **Absent on a fresh install** → normal. The server generates
  `secrets-kek-v1` on first boot and logs
  `key_provider: generated KEK 'secrets-kek-v1' (0600, fsynced)`.
- **Absent on an existing install** → the KEK has been lost. Do **not** let the
  server generate a new one and consider it fixed: a new KEK cannot decrypt
  existing blobs. Go to [KEK permanently lost](#kek-permanently-lost).

**Docker Compose.** In the container the directory is `/etc/yuzu/certs` (the
images pass no `--ca-dir`), and it must sit on a named volume: `server-certs`
in the shipped composes from 0.14.1, `certs` in the two reference composes.
Check it with `docker compose exec server ls -l /etc/yuzu/certs`; while the
server is restart-looping, use
`docker compose run --rm --no-deps -T --user 0 --entrypoint ls server -ln /etc/yuzu/certs`
(as root, so a wrong owner shows as such instead of `Permission denied`).
In the affected 0.14.0 stacks there was no volume there, so recreating the
container (an image upgrade, `down` then `up`, `--force-recreate`) deleted the
key files, and `kek_unresolvable` follows on the next start (#5370).
Affected: a 0.14.0 Docker Compose stack whose server has no named volume on `/etc/yuzu/certs` while Postgres has one — `deploy/docker/docker-compose.yml` (the 0.14.0 README quickstart), `docker-compose.uat.yml`, `docker-compose.full-uat.yml`, `docker-compose.viz-uat.yml`, `docker-compose.demo.yml` used with `--keep`, any compose copied from them, and Compose Wizard output from before 0.14.1 in Plaintext mode, with 'Persist generated certs' unticked, or with named volumes off and an external Postgres. Not affected: `docker-compose.reference.yml` (which the README quickstart saves as `docker-compose.yml` since #5419) and `docker-compose.reference-gateway.yml` (their `certs` volume).
A `kek_unresolvable` there does not always mean the files are gone: a compose
that lost its volume line, files owned by the wrong uid, or keys left behind on
a dangling anonymous volume give the same error.
The diagnostic order, the copy-out procedure, and the options if the files are
already gone are in `docs/user-manual/upgrading.md`, "Docker Compose: copy
`/etc/yuzu/certs` out of the server container before you recreate it". Run the
diagnostics before anything destructive.

## Backup — the KEK pairing rule

**A Postgres dump alone is not a complete auth backup.** TOTP secrets in
`auth.users.mfa_totp_secret` are envelope-encrypted (ADR-0010); the wrapped
data key travels with the row, but the KEK that unwraps it is a file. Restore
the dump next to a *different* KEK and every MFA decrypt fails closed — users
are not silently downgraded to password-only, they are locked out of MFA with
`SecretUnavailable` errors and a `yuzu_server_secret_decrypt_failures_total{failure_class="kek_unresolvable"}`
counter climbing.

So: **capture the database dump and the keys directory as a pair, from the same
point in time, and restore them as a pair.**

Capture order: take the `pg_dump` first, then the keys directory; do not rotate the KEK between the two (key files only accumulate, so the archive stays a superset of what the dump references). Stopping the server for the pair guarantees it.

**Linux.** Both halves go to `/var/backups/yuzu`, which the block makes a root-owned `0700` directory, and both are written under `umask 077`, so the dump and the key archive are `0600` and owned by root. They stay root-owned: copy them off with `sudo`, keep them together, and encrypt the pair at rest. Use a directory that holds nothing else, since files already in it keep their own permissions. The block prints `OK:` only if both halves were written.

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 -o root -g root /var/backups/yuzu
( set -o pipefail
  sudo -u _yuzu pg_dump "$YUZU_POSTGRES_DSN" --format=custom \
    | sudo sh -c "umask 077; cat > /var/backups/yuzu/yuzu-$STAMP.dump" &&
  sudo sh -c "umask 077; tar -czf /var/backups/yuzu/yuzu-keys-$STAMP.tar.gz -C /etc/yuzu certs" ) &&
  echo "OK: pair written to /var/backups/yuzu"
```

**Docker Compose.** Run from the compose directory. The keys directory is the server container's `/etc/yuzu/certs` volume. Both halves go to an owner-only directory outside any git checkout, because the key archive holds the CA private key and the KEK. The server is stopped for the pair, and `docker cp` reads the volume from the stopped container, so this works on the chiselled image too. The last line starts the server again whether or not the backup succeeded.

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BK="$HOME/yuzu-keys-backup"; mkdir -p "$BK" && chmod 700 "$BK"
docker compose stop server
( umask 077; set -o pipefail
  docker compose exec -T postgres pg_dump -U yuzu --format=custom yuzu < /dev/null \
       > "$BK/yuzu-$STAMP.dump" &&
  docker cp "$(docker compose ps -aq server)":/etc/yuzu/certs - | gzip \
       > "$BK/yuzu-keys-$STAMP.tar.gz" ) && echo "pair written to $BK"
docker compose start server
```

**Windows** (elevated PowerShell). The Windows installer stores the connection string in a file only Administrators and SYSTEM can read; a hand-configured server may use the `YUZU_POSTGRES_DSN` environment variable instead. The block first locks the backup directory to Administrators and SYSTEM (owner Administrators, inheritance removed, full control for those two only), the same grant the installer gives its own directories, so both halves inherit it. Each run writes to a new, timestamped directory (files already in a directory keep any permissions set on them directly, so the block refuses to reuse one). `pg_dump --file` writes the dump itself, because in Windows PowerShell 5.1 (and PowerShell before 7.4) `>` re-encodes a native command's output as text, which corrupts a custom-format dump.

```powershell
& {
  $Stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $Bk = "C:\Backups\Yuzu-$Stamp"
  if (Test-Path -LiteralPath $Bk) { throw "$Bk already exists: use a new, empty folder" }
  New-Item -ItemType Directory -Path $Bk | Out-Null
  icacls $Bk /setowner '*S-1-5-32-544' /L /Q | Out-Null
  if ($LASTEXITCODE) { throw 'icacls failed: the backup folder is not locked down, stop here' }
  icacls $Bk /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /L /Q | Out-Null
  if ($LASTEXITCODE) { throw 'icacls failed: the backup folder is not locked down, stop here' }
  $DsnFile = "C:\ProgramData\Yuzu Server\postgres.dsn"
  $Dsn = if (Test-Path $DsnFile) { (Get-Content -LiteralPath $DsnFile -Raw).Trim() } else { $Env:YUZU_POSTGRES_DSN }
  pg_dump --format=custom --file "$Bk\yuzu-$Stamp.dump" $Dsn
  if ($LASTEXITCODE) { throw 'pg_dump failed: no pair was written, stop here' }
  Compress-Archive -Path C:\ProgramData\Yuzu\certs -DestinationPath "$Bk\yuzu-keys-$Stamp.zip" -ErrorAction Stop
  Write-Output "OK: pair written to $Bk"
}
```

The block is one `& { ... }` script block, so a failure stops everything after it however it is pasted. Go on only after `OK: pair written to ...`.

Rules that follow from the pairing:

- **Encrypt the key archive at rest**, separately from the dump if your threat
  model allows — an attacker with both has every stored secret.
- **Never restore a dump onto a host whose keys directory came from a
  different backup generation.** If you cannot prove they are paired, treat the
  MFA enrolments as lost and plan a re-enrolment.
- **Retain old KEK versions.** After a KEK rotation, older versions are still
  needed to read any backup taken before the rotation completed. Do not prune
  key files on a schedule that is shorter than your backup retention.
- **Drill it.** A restore you have never rehearsed is a hypothesis. Restore
  into a scratch database + scratch keys directory, start a throwaway server,
  and verify a real TOTP login succeeds.

Postgres backup mechanics (PITR/WAL archiving, base backups, retention) are
your Postgres platform's concern and out of scope here; what is in scope is
that the keys directory rides along with whatever you choose.

**A restore rolls credentials and sessions back to the dump.** Passwords live
only in the auth store (#5274), so restoring a dump puts every local account's
password back to what it was when the dump was taken — including a password
changed since because it was exposed — and brings back the session rows and
lockout state of that moment, so sessions revoked since the dump (a password
change, **Sign out everywhere**, an admin force-logout) become valid again
until they expire. After any restore of the auth schema:

1. Revoke every operator session (`DELETE /api/v1/sessions?username=<name>` per
   account, or the SQL in [Sessions are durable](#sessions-are-durable)).
2. Re-apply every password change or reset made since the dump — at minimum
   any made because a password was exposed — in the product.
3. Review the audit log for `user.password_change` / `user.password_reset`
   rows after the dump's timestamp to find them (the audit store is not
   rolled back unless you restored it from the same dump).

**Restoring onto an empty database instead re-seeds `yuzu-server.cfg`.** If the
`auth` schema is empty when the server starts (a recreated Postgres, a dump
that did not include it), the server provisions the first administrator from
the password hash in `yuzu-server.cfg` — usually the original first-boot
password, not the current one. Keep that file protected, and change the
administrator password in the product right after such a rebuild.

## Post-restore verification

After any restore, before declaring the incident closed:

```bash
# 1. The server started and is serving. (/health and /readyz are on the web
#    port — --web-port, default 8080; https:// if TLS is enabled.)
systemctl status yuzu-server
curl -fsS http://127.0.0.1:8080/health

# 2. The auth schema is at the expected migration version.
psql "$YUZU_POSTGRES_DSN" -c "SELECT store, version FROM public.schema_meta WHERE store IN ('auth','scim_store');"

# 3. The KEK resolved — this must be ZERO, or absent entirely. A non-zero
#    kek_unresolvable count is the signature of a dump restored against the
#    wrong keys directory. /metrics is on the same web port and is always
#    unauthenticated over loopback.
curl -fsS http://127.0.0.1:8080/metrics | grep secret_decrypt_failures_total

# 4. A real MFA login works end-to-end (not just "the page loads").
```

Step 3 is the one people skip. It is the only cheap check that distinguishes
"restored correctly" from "restored, and every MFA user will be locked out the
moment they try to log in".

## Sessions are durable

Operator sessions are rows in the Postgres `session_store.sessions` table
(`SessionStore`, HA WS-1/1a, ADR-2002 §4). `AuthManager`'s in-memory
`sessions_` map is only a per-replica validate cache in front of those rows:
on a cache miss the server re-reads the row and rebuilds the session from it.
So:

- **A server restart is NOT a revocation.** The restart empties the cache, and
  the next request rebuilds each session from its row. The same holds for a
  crash or a failover to another replica.
- A row is removed only by an explicit revoke (sign-out, or the REST calls
  below, which delete by token or by username) or by the reaper once the
  session passes its absolute lifetime (8 hours). An idle-timed-out session
  is refused on every replica, but its row stays until the reaper removes it.

To revoke sessions, use the REST surface:

```bash
# Revoke every session for one operator (admin).
curl -fsS -X DELETE "https://yuzu.internal/api/v1/sessions?username=alice" \
     -H "Authorization: Bearer $TOKEN"

# Revoke your own (self-service).
curl -fsS -X DELETE https://yuzu.internal/api/v1/sessions/me \
     -H "Authorization: Bearer $TOKEN"
```

**Check that the revoke persisted.** Both calls delete the durable rows first,
then clear this replica's cache. If the response body reports
`db_persisted: false` (the audit row shows `result=partial` with
`db_error=true`), only this replica's cache was cleared. The rows survive, and
any replica that misses its cache, including this one after a restart, will
rebuild those sessions from them. Retry the revoke once the database is
healthy.

API tokens are a separate credential class. The admin `?username=` call does
**not** revoke them, and neither does a restart. `/sessions/me` ("Sign out
everywhere") revokes the caller's API tokens as well as their sessions (check
`api_tokens_db_persisted` in its response). Otherwise revoke tokens explicitly
via the token endpoints.

**Emergency fleet-wide revocation.** There is no single admin route that
revokes every operator's sessions. The audited path is the admin
`?username=` call above, once per operator. If that is not practical, delete
the rows directly in Postgres. This is a direct database operation: it
bypasses the server, **writes no audit row** (record it manually), and signs
out every operator including you. Take a backup first (see
[Backup — the KEK pairing rule](#backup--the-kek-pairing-rule)).

```bash
psql -v ON_ERROR_STOP=1 "$YUZU_POSTGRES_DSN" <<'SQL'
BEGIN;
DELETE FROM session_store.sessions;
-- Bump the write-generation exactly as SessionStore does, so every
-- replica drops its cached sessions on its next generation poll (~1s).
INSERT INTO session_store.session_meta (key, value) VALUES ('write_generation', '1')
ON CONFLICT (key) DO UPDATE SET value = (session_store.session_meta.value::bigint + 1)::text;
COMMIT;
SQL
```

The generation bump is required. A running replica serves a cached session
without re-reading its row, and clears its cache only when it sees the
write-generation advance. A bare `DELETE` therefore leaves every cached
session valid on the replica that holds it, until some later session change
advances the generation, the session expires, or that replica restarts.

`ON_ERROR_STOP` makes `psql` exit non-zero if any statement fails, in which
case the whole transaction has rolled back and nothing changed. Afterwards,
confirm `SELECT count(*) FROM session_store.sessions;` returns 0 and that
`write_generation` in `session_store.session_meta` went up. This revokes
sessions only: API tokens stay valid and must be revoked through the token
endpoints.

## Account lockout recovery

An operator is locked out by failed-login lockout
(`--auth-lockout-threshold`, default 5 within `--auth-lockout-window-secs`,
default 900). The window auto-expires, so the first question is whether you
need to act at all — waiting it out is the zero-risk path.

**Preferred — admin API** (audited, no database access needed):

```bash
curl -fsS -X POST "https://yuzu.internal/api/v1/users/alice/unlock" \
     -H "Authorization: Bearer $TOKEN"
```

Requires `UserManagement:Write` (plus MFA step-up when the caller is enrolled).
Self-target is allowed.

**Fallback — direct SQL**, when every admin is locked out and no valid token
exists. This writes no audit row; record it in your change-management system:

```bash
# Inspect first.
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT username, failed_login_count, locked_until FROM auth.users WHERE username = 'alice';"

# Clear one account.
psql "$YUZU_POSTGRES_DSN" -c \
  "UPDATE auth.users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL WHERE username = 'alice';"
```

Mass-unlock is a threshold-misconfiguration remedy only (e.g. someone deployed
`--auth-lockout-threshold=1`). Fix the flag in the same maintenance window, or
you will be back:

```bash
psql "$YUZU_POSTGRES_DSN" -c \
  "UPDATE auth.users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL;"
```

**Bulk unlock after an auth-store blip.** Before #5342 a login whose account
row could not be read was answered as a wrong password and counted a lockout
strike, so a Postgres blip during busy sign-in traffic could lock many
legitimate accounts at once. A server on this release answers those logins
`503` with no strike, but a wave of `auth.lockout.applied` audit rows clustered
around a store outage can still happen (a server not yet upgraded, or
automation retrying a stale password through the outage). Unlock only the
accounts whose last failure falls inside the outage window, after confirming
from the audit log that the window is right:

```bash
# Inspect: accounts locked by a failure inside the window (UTC).
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT username, failed_login_count, last_failed_login_at, locked_until FROM auth.users
   WHERE locked_until > now()
     AND last_failed_login_at BETWEEN '2026-10-04 09:00:00+00' AND '2026-10-04 09:20:00+00';"

# Clear exactly those.
psql "$YUZU_POSTGRES_DSN" -c \
  "UPDATE auth.users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL
   WHERE locked_until > now()
     AND last_failed_login_at BETWEEN '2026-10-04 09:00:00+00' AND '2026-10-04 09:20:00+00';"
```

Like the single-account fallback, this writes no audit row; record it. The
locks expire on their own after `--auth-lockout-window-secs`, so waiting is
still the zero-risk choice.

## Password reset

A local account's password lives **only** in the PostgreSQL auth store
(`auth.users.password_hash`/`salt_hex`). `yuzu-server.cfg` seeds the first
administrator into an *empty* `auth` schema and is never consulted for an
account that already exists there (#5274) — so **editing or regenerating
`yuzu-server.cfg` no longer resets anyone's password**, and neither does
re-running an installer with a new admin password. (Before #5274 a cfg hash
silently shadowed the stored one on the replica that loaded it, which made a
cfg edit look like a reset; that path is gone.)

**Preferred — in the product** (audited, no database access):

- An administrator resets it: Settings → User Management → **Reset
  password**, or
  ```bash
  curl -fsS -X POST "https://yuzu.internal/api/v1/users/alice/password" \
       -H "Cookie: yuzu_session=$COOKIE" -H "Origin: https://yuzu.internal" \
       -H "Content-Type: application/json" \
       -d '{"new_password":"<12-1024 bytes>"}'
  ```
  This needs an interactive dashboard session of a **durable
  Administrator** — with RBAC off, an account whose own role is `admin`;
  with RBAC on, a user `Administrator` grant. A JIT elevation, an IdP-group
  admin role or a custom role holding `UserManagement:Write` is refused
  (`403 durable_admin_required`), as are API and MCP tokens; MFA step-up
  applies when the caller is enrolled. The configured break-glass account
  cannot be reset this way (`403 break_glass_target`). The new password, the
  sign-out of the user's sessions, the discarding of an unfinished MFA
  enrolment, the lockout clear and the audit row are one database
  transaction — all of it lands, or none of it. Their API tokens and any
  ENROLLED second factor are **not** touched (the response reports how many
  tokens remain active); for a compromised account also run
  `yuzu-server --mfa-reset <user>` and revoke the tokens.
- A user who still knows their password changes it themselves: Settings →
  User Management → **Change password**, or `POST /api/v1/users/me/password`.
  They are signed out everywhere and sign in again with the new password.

Audit: `user.password_reset` / `user.password_change`, written in the same
transaction as the change (an audit failure makes no change: `503`). A reset
also clears the account's lockout, recording `auth.lockout.cleared`
(`detail=password_reset`) only when there was a lockout to clear. There
is no MCP tool for either (#5357 tracks a temporary-password reset tool).

**Re-running the Windows server installer is not a reset.** On an upgrade it
refuses `/ADMIN_PASS=` (and the removed `/OPERATOR_PASS=`) with exit code 11
(the config file it would write only seeds an empty database).

**Fallback — direct SQL**, when no administrator can sign in at all (the only
admin forgot their password). This writes no audit row and revokes no
sessions; record it in your change-management system. Like the in-product
reset, it discards an unfinished (never-enrolled) TOTP enrolment so nobody can
complete it under the old password; an enrolled second factor is kept. Generate
the hash the way the server does (PBKDF2-HMAC-SHA256, 100 000 iterations, 32-byte key,
16-byte random salt, both hex-encoded):

```bash
read -rs NEWPW   # 12-1024 bytes; not echoed, not in shell history
# Passed via the environment, not argv (argv is visible to every local user in ps).
NEWPW="$NEWPW" python3 - <<'PY'
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', os.environ['NEWPW'].encode(), salt, 100000, dklen=32)
print(f"UPDATE auth.users SET password_hash = '{dk.hex()}', salt_hex = '{salt.hex()}', "
      "failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL, "
      "mfa_totp_secret = CASE WHEN mfa_enrolled_at IS NULL THEN NULL ELSE mfa_totp_secret END, "
      "mfa_last_counter = CASE WHEN mfa_enrolled_at IS NULL THEN 0 ELSE mfa_last_counter END, "
      "updated_at = now() WHERE username = 'admin' AND identity_source = 'local' "
      "AND provisioning_source = 'local' AND is_active;")
PY
# Review the printed statement, then run it:
psql "$YUZU_POSTGRES_DSN" -c "<the printed UPDATE>"
```

The same on Windows (elevated PowerShell; needs Python 3 and `psql` on
`PATH`). The connection string is read from the installer's locked file, as in
the backup example above:

```powershell
$Secure = Read-Host -AsSecureString 'New password (12-1024 bytes)'
$Env:NEWPW = [System.Net.NetworkCredential]::new('', $Secure).Password
@'
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', os.environ['NEWPW'].encode(), salt, 100000, dklen=32)
print(f"UPDATE auth.users SET password_hash = '{dk.hex()}', salt_hex = '{salt.hex()}', "
      "failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL, "
      "mfa_totp_secret = CASE WHEN mfa_enrolled_at IS NULL THEN NULL ELSE mfa_totp_secret END, "
      "mfa_last_counter = CASE WHEN mfa_enrolled_at IS NULL THEN 0 ELSE mfa_last_counter END, "
      "updated_at = now() WHERE username = 'admin' AND identity_source = 'local' "
      "AND provisioning_source = 'local' AND is_active;")
'@ | python -
Remove-Item Env:NEWPW
# Review the printed statement, then run it:
$DsnFile = "C:\ProgramData\Yuzu Server\postgres.dsn"
$Dsn = if (Test-Path $DsnFile) { (Get-Content -LiteralPath $DsnFile -Raw).Trim() } else { $Env:YUZU_POSTGRES_DSN }
psql $Dsn -c "<the printed UPDATE>"
```

With the Docker Compose reference stack, generate the statement on the host
as above (the server image has no Python), then run it inside the `postgres`
service, which needs no published port or password:

```bash
docker compose exec -T postgres psql -U postgres -d yuzu -c "<the printed UPDATE>"
```

Run it from the directory holding your compose file (or add `-f <file>`);
adjust `-d` if your server's DSN names a different database.

Expect `UPDATE 1`. No restart is needed: login reads the auth store directly.
Then sign in, revoke the account's old sessions
(`DELETE /api/v1/sessions?username=admin`, or **Sign out everywhere**), and
consider enrolling a second administrator so the in-product reset is
available next time.

## Emergency MFA disable (break-glass)

**When to use.** An operator has lost both their authenticator device *and*
every recovery code — or has been locked out by MFA enforcement (the IdP not
asserting `amr`, a sole admin who could not enroll). The Settings → MFA panel
is behind login, so the dashboard path is unreachable.

### The `--mfa-reset` CLI (audited)

`yuzu-server --mfa-reset <username>` clears the user's MFA enrolment and exits
**without starting the server**. It writes an audit row
(`mfa.reset.breakglass`, principal = the OS account that ran it).

**It needs the Postgres DSN and the keys directory.** This changed with the
Postgres migration and is the most common reason the command fails today:

```bash
sudo -u _yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --postgres-dsn "$YUZU_POSTGRES_DSN" \
  --ca-dir /etc/yuzu/certs \
  --mfa-reset alice
# {"status":"ok","user":"alice","action":"mfa.reset.breakglass"}
```

- `--postgres-dsn` is **required** — without it the one-shot exits non-zero
  with "requires the Postgres auth store". The mandatory audit row is written
  through the SAME `--postgres-dsn` (ADR-0040: audit is Postgres-backed,
  schema `audit_store`) — there is no `<data-dir>/audit.db` write path
  anymore. Point `--postgres-dsn` at the real production database or the row
  lands somewhere nobody is looking (SOC 2 CC6.6), same risk as before, wrong
  flag.
- `--data-dir` is not needed. There is no legacy `audit.db` backfill gate any
  more (retired by the ADR-0009 hard cutover, 2026-09-04), so the one-shot also
  works on a database that has never seen a server boot. If a data directory
  is set (`--data-dir` or `YUZU_DATA_DIR`), it is still created and checked
  writable, and a failure there aborts the command.
- `--ca-dir` is required whenever the KEK is not in the platform default
  location, because the command builds the full auth stack (pool → key
  provider → codec → AuthDB) exactly as the server does.
- No TLS/HTTPS flags are needed; the command never serves.

**Authorisation — read the threat model.** `--mfa-reset` strips a second factor
with **no MFA, admin-password, or token check of its own**. The only enforced
control is OS-level access: anyone who can run a `yuzu-server` binary with the
DSN and the keys directory can downgrade **any** account, including the sole
admin. It does not verify it is running as the service account — that is an
operational expectation, not a code-enforced gate. Treat *DSN + keys-directory
access* as equivalent to MFA-reset authority over every account:

- Run on the server host as the service account (`_yuzu` / `yuzu` /
  `NT SERVICE\YuzuAgent`; see `docs/agent-privilege-model.md`).
- Keep the keys directory `0700` and its contents `0600`, service-account
  owned. Keep the DSN out of world-readable config and out of `ps` (prefer
  `YUZU_POSTGRES_DSN` in a `0600` environment file).
- Gate the invocation behind a narrow `sudoers` entry — ideally a dedicated
  break-glass group with a separate approver. The audit principal is the real
  OS identity (`getpwuid`/`GetUserNameA`, **not** the forgeable `$USER`), so a
  tight sudoers entry gives trustworthy attribution.

**Audit is mandatory and fail-closed.** The CLI verifies the audit store is
writable *before* clearing any MFA, and refuses to proceed if it is not — the
whole point is to replace the unaudited SQL path. A `{"status":"ok",…}` line
with exit code 0 means an audit row persisted.

**Detective control.** Because the CLI exits without serving, it emits no
Prometheus metric — the audit row is the only signal. Alert on
`mfa.reset.breakglass` in `audit_events`; an unexpected one is an
authentication-downgrade event and should page on-call.

It is safe to run while the server is up: the one-shot opens its own pool and
does not talk to the running process.

### Fallback: direct SQL

Use it in two cases: no `yuzu-server` binary is available on the host, or
`--mfa-reset` fails with `kek_orphaned` because the stored secret's header names a
key version that is not registered and that header is corrupt (see
[Stored secret names an unregistered KEK version](#stored-secret-names-an-unregistered-kek-version),
where a restore of the paired backup comes first when the version once existed).
**Writes no audit row**, so record it manually.

```bash
psql "$YUZU_POSTGRES_DSN" <<'SQL'
BEGIN;
UPDATE auth.users
   SET mfa_totp_secret  = NULL,
       mfa_enrolled_at  = NULL,
       mfa_disabled_at  = now(),
       mfa_last_counter = 0
 WHERE username = 'alice';
DELETE FROM auth.mfa_recovery_codes WHERE username = 'alice';
COMMIT;
SQL
```

The two statements run in one transaction on purpose, as `--mfa-reset` does
(`AuthDB::mfa_disable`): an interruption between them must never leave the secret
cleared with the old recovery codes still valid.

Clearing the secret needs no KEK (you are writing NULL, not reading
ciphertext), so this works even when the KEK is unavailable.

### Stored secret names an unregistered KEK version

A stored secret blob carries its key-encryption-key (KEK) version in its header: a
one-byte format marker, then the version as a four-byte big-endian number. If that
version is not registered in the `secrets.kek_meta` table, the secret cannot be
read, and the usual recovery is closed:

- The step-up gated routes answer `503` for that account, as for any unreadable
  secret. While the secret stays unreadable the account's password sign-in also
  answers `503` (measured for a truncated blob; expected for any unreadable
  secret), so the user cannot sign in at all until it is recovered.
- `yuzu-server --mfa-reset <username>` fails with exit status 1 and
  `SecretCodec::init() failed for the auth store bootstrap` naming `kek_orphaned`,
  because the secrets seam refuses to initialise while any stored blob names an
  unregistered key version. It never gets as far as clearing the account.
- A server restart refuses to start for the same reason. A server that is already
  running keeps serving until it is restarted, so fix this before any restart.

**The boot check covers every secret column, not only TOTP.** It scans each
registered secret column for blob headers that name a version absent from
`kek_meta`: `auth.users.mfa_totp_secret`, `webhook_store.webhooks.secret`,
`plugin_config_store.secrets.sealed_value`,
`offload_target_store.offload_targets.auth_credential` and
`runtime_config_store.runtime_config_secrets.sealed_value`
(`scan_orphaned_versions` in `pg/secret_codec.cpp`, run for every registered
column). The refusal line names the version number or numbers (`v<N>`), not the
table or the account. Each store has its own codec and its own scan, and the
refusal line names the store (for example `webhook_store SecretCodec::init()
failed`; the auth store's own line carries no store name). The SQL in this
runbook clears MFA enrolment only: clearing an account's TOTP secret therefore
fixes an orphan only if that orphan lives in `auth.users`, and an orphan in any
other store is recovered by restoring the paired `kek_meta` and keys backup, not
by SQL here (the server otherwise keeps refusing with the same line).

**Identify the affected accounts first (read-only).** The query below reads the
same four header bytes the boot check reads and lists the accounts whose TOTP blob
names a version that is not in `kek_meta`. It changes nothing.

```sql
SELECT username, blob_kek_version
  FROM (SELECT username,
               ('x' || encode(substring(mfa_totp_secret from 2 for 4), 'hex'))
                 ::bit(32)::bigint AS blob_kek_version
          FROM auth.users
         WHERE mfa_totp_secret IS NOT NULL
           AND length(mfa_totp_secret) >= 5) AS blobs
 WHERE blob_kek_version NOT IN (SELECT kek_version FROM secrets.kek_meta)
 ORDER BY username;

-- For comparison: the registered versions (retired ones count as registered).
SELECT kek_version, created_at, retired_at FROM secrets.kek_meta ORDER BY kek_version;
```

The `length(...) >= 5` filter mirrors the boot check, which skips a blob too short to
have a four-byte version. A zero-row result for `auth.users` while the server still
refuses to start means the orphan is in one of the other columns. To check one,
repeat the first query with that table and column, for example
`webhook_store.webhooks` and `secret`.

**Choose the remedy by the version number the log names.** Versions are small
integers: the first is `1` and each KEK rotation adds one.

- **The version legitimately existed** (a small number that a real rotation could
  have produced, for example one missing from the middle of the `kek_meta` list or
  one above its highest entry): a registration row was deleted, or the database was restored against a
  mismatched `kek_meta`. This is the first-choice case, and the server's own
  message prescribes the fix: restore `kek_meta` **and** the keys directory from the
  paired backup (see [Backup, the KEK pairing rule](#backup--the-kek-pairing-rule)
  and [KEK permanently lost](#kek-permanently-lost)). It recovers every affected
  account and every other store at once without discarding enrolments, and it is the
  remedy for an orphan outside `auth.users`, where this runbook offers no clearing
  statement. Do not clear secrets that a correct restore would have kept.
- **The blob header is corrupt** (a version number that cannot be real, such as
  `2880154539`, which is what a damaged or garbage blob header decodes to): the
  secret is not recoverable by any backup of the keys. The
  [direct SQL fallback](#fallback-direct-sql) is the remedy, because writing NULL
  needs no key. Run it only for the accounts the identification query listed with
  such a version, not for accounts whose blob is intact. Keep the existing warnings:
  it writes no audit row, so record it by hand. The account can re-enrol afterwards.

If the identification query lists more than one account, or the missing version is
one in use by many blobs, the cause is probably a `kek_meta` and keys-directory pair
that no longer match, which points to the restore rather than to clearing accounts
one by one.

## Break-glass arm (IdP outage under `--auth-mode=sso-only`)

Under `--auth-mode=sso-only` only an SSO provider (OIDC or SAML) mints a session. If the IdP is down, the
`--break-glass-user` account is the way back in — but it is exempt **only while
armed**, and arming is an out-of-band host CLI operation so it works when the
IdP does not.

```bash
sudo -u _yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --postgres-dsn "$YUZU_POSTGRES_DSN" \
  --ca-dir /etc/yuzu/certs \
  --break-glass-user alice \
  --break-glass-arm
# → arms the named --break-glass-user for --break-glass-window-secs
#   (default 24h, auto-expiring), prints {"status":"ok",…,"armed_until":"…"}
#   and EXITS without serving.
```

`--break-glass-arm` **requires** `--break-glass-user` (or the
`YUZU_BREAK_GLASS_USER` env var) to name the account. It is a CLI/env option
only — it does not come from `yuzu-server.cfg`, so the one-shot must repeat
whatever the running service passes in its unit file. Omit it and the command
exits non-zero with `error: --break-glass-arm requires --break-glass-user`,
arming nothing.

Arming is fail-closed on audit: the audit store is checked reachable and
migrated *before* the mutate, and if the row fails to persist afterwards the
arm is rolled back (the account ends up NOT armed). If the rollback also fails,
the command exits non-zero and says so on stderr: the account may still be
armed, with no audit row. That makes the `--postgres-dsn` note above
load-bearing here too — point it at the real production database, or you
will arm the glass and record it somewhere nobody is looking.

Same flag requirements and the same threat model as `--mfa-reset` above. The
arm is audited at `kCritical` as `auth.breakglass.armed`, attributed to the OS
identity; the subsequent login is audited as `auth.breakglass.login` and
increments `yuzu_auth_break_glass_login_total`. The window auto-expires — you
do not need to disarm.

The break-glass account **must** have MFA enrolled: boot fails closed if it
does not, and an un-enrolled break-glass account is hard-denied at login
(enrolment is never offered on that path, since that would defeat the second
factor).

To enrol the break-glass account, restart the server with `--auth-mode=standard`
and sign in as that account. This re-enables local-password login for every local
account, so keep the window short: on bare metal consider `--web-address
127.0.0.1`; in a container, restrict the published port instead (the image binds
0.0.0.0). The break-glass lockout exemption does not apply in standard mode, so
failed password attempts can lock the account for `--auth-lockout-window-secs`.
Only with the listener restricted as above, consider `--auth-lockout-threshold=0`
for the window (it disables throttling for every local account); otherwise an SSO
admin, if the IdP is up, can clear a lock with `POST /api/v1/users/{name}/unlock`.
Under
`--mfa-enforcement=required` the sign-in itself enrols MFA; otherwise enrol at
Settings → Security and sign-in → Two-factor sign-in, which needs the admin role. For a
non-admin break-glass account, also pass `--mfa-enforcement=required` for that
restart, and note that it applies to every user for the window: un-enrolled local
users are enrolled at login, and SSO users whose IdP sends no `amr` cannot pass
step-up. Then restore `--auth-mode=sso-only` and your usual `--mfa-enforcement`.
If the arm has lapsed by then and you still need break-glass access (the IdP is
still down), re-run `--break-glass-arm`; do not re-arm for a planned rotation.
The mode switch itself writes no audit row, so record the window in a change
ticket; the evidence is the startup WARN that `--break-glass-user` is ignored under
standard mode, the missing sso-only boot banner, the
`auth.login` and `mfa.enroll.verified` rows inside the window, and the banner
returning on the final restart.

To rotate the break-glass TOTP, clear it first with `--mfa-reset <user>` (an
enrolled account gets a challenge at sign-in, not enrolment, and cannot re-enrol
from Settings), then follow the enrolment sequence above. Do not restart under
sso-only between the reset and the re-enrolment: boot refuses until the account
is enrolled again.

## Locked out by MFA enforcement misconfiguration

`--mfa-enforcement=required` (or `admin-only`) with no enrolled accounts locks
everyone out. Enforcement is read from configuration at startup, not from the
database, so the fix is a restart with the flag relaxed — no data surgery:

```bash
# 1. Relax enforcement and restart. The auth schema is untouched.
sudo systemctl edit yuzu-server     # --mfa-enforcement=optional
sudo systemctl restart yuzu-server

# 2. Log in with password alone, enroll via Settings → Security and
#    sign-in → Two-factor sign-in, and SAVE the recovery codes.

# 3. Restore enforcement and restart.
```

## Step-up returns 503 while the authentication store is unavailable

The 33 routes that need a fresh MFA step-up (token, session, engine-principal,
RBAC and Guardian writes, password reset and the others listed in the
[REST API reference](../user-manual/rest-api.md#step-up-envelope-on-high-risk-endpoints))
check the caller's MFA state before the route runs. Other mutating routes and all
MCP tools are not step-up gated in this release, so this incident does not close
them. A gated route answers **`503`** and does not run in three cases:

- the server has **no wired authentication store** (reason
  `auth_store_unwired`). This is a defensive state (a boot-wiring fault, or a
  build that wires no store), not a field condition you should see after a
  normal boot. It answers `503` for any caller that reaches the check, a token
  caller included, and even when the step-up window is disabled;
- the store is wired but **cannot be read, or an enrolled account's stored second
  factor cannot be decrypted** (reason `mfa_status_unavailable`). This answers
  `503` to **local (password) sessions only**, since those are the only sessions
  whose enrollment is read from the store. API-token and MCP-token callers pass
  before any store read, OIDC sessions are judged on the identity provider's
  assertion, SAML sessions get their `403`, and engine principals get `403`;
- the check itself **threw an unexpected exception** (reason
  `chokepoint_exception`), for any caller class. This is a fault in the server
  rather than in the store: the exception text is in the server log (sampled, one
  line in 100), and the window lever below is not a fix for it.

```json
{"error": {"code": 503, "message": "authentication store is temporarily unavailable", ...},
 "meta": {"api_version": "v1", "mfa_step_up_required": true}}
```

There is no `challenge_url`: this is a server-side outage, not a request to
re-prove, so entering a TOTP code cannot clear it. The envelope's `meta` still
carries `mfa_step_up_required: true`, so a client must treat a `503` as "retry
shortly" and prompt for a code only on a `401`. Each refusal writes an
`mfa.step_up.required` audit row, best effort (every refusal has `result=error`;
the `reason=` token in `detail` tells them apart: a missing store is
`reason=auth_store_unwired`, an unreadable enrollment
`reason=mfa_status_unavailable`, an unexpected failure inside the check itself
`reason=chokepoint_exception`; the `detail` also carries `cid=<id>`, equal to the
response's `X-Correlation-Id` header, and `stage=pre_authz`), and
`yuzu_auth_mfa_step_up_gate_total{outcome="unavailable"}` counts the 503s. If the
audit store is down too, the rows are lost and the counter is the only record. A
read failure the store does not classify as unavailable is answered `401` instead,
with the same `mfa_status_unavailable` reason and a remediation that says the
authentication store is unavailable; it is counted as `refused`, not
`unavailable`, so the alert below does not see it. A `503` is never a pass: the
gated route stays closed until the cause is fixed.

**The alert is slow by design.** `YuzuStepUpGateUnavailable` fires when the
`unavailable` outcome counts at least **3** refusals in a 10-minute window for one
instance and surface, held for 5 minutes. Expect it **no earlier than about 5
minutes after the third `503`**, plus scrape and evaluation delay, and it clears
up to 10 minutes after the last `503`. One or two stray `503`s never fire it, so a
quiet alert does not prove the check is healthy: on a low-traffic instance, read
the counter and the audit rows directly. The threshold is per (job, instance,
surface), so a few `503`s on each of many replicas (or spread across both
surfaces) may never reach 3 on any one series and not fire at all; during a
suspected outage, sum the counter across replicas yourself.

### When Postgres is stalled rather than down

A database that accepts connections but answers slowly or not at all (a frozen
host, a saturated disk, a paused container) behaves differently from one that
refuses connections. The measurements below come from one test rig: the database
container was paused for 30 seconds (the longer run is noted where it matters),
so the transport kept acknowledging packets while the database process answered
nothing. No gated request was admitted during any stall. Each figure below is
marked as measured or as derived from the code, because the two are not equally
firm.

- **Gated requests that already hold a database connection wait until the stall
  ends** (measured). The statement timeout does not cut them short, so they can
  stay open for the whole stall. That holds while the transport still
  acknowledges packets, as with a paused or hung database process. Over a dead
  network path the 10 second `tcp_user_timeout` on the pool's connections bounds
  the wait instead (`pg_pool.hpp`, derived from the code, not measured).
- **New requests fail with `503`** in about 1.6 to 10.3 seconds (measured over
  three runs: most failed within about 1.6 seconds, a second group took about 10.3
  seconds). The slower group is the requests that had to open a fresh connection
  and waited out the pool's 10 second connect timeout (`connect_timeout_s`,
  `pg_pool.hpp`).
- **After about 30 seconds of a long stall, cookie sessions begin to answer `401`
  `unauthorized` before the step-up check runs**, instead of `503`. The 30 second
  figure is derived from the code, not measured: the session validation cache is
  trusted for 30 seconds after the last successful refresh
  (`kSessionGenStaleServeBoundMs`, `auth.cpp`), after which a session has to be
  re-read from the database. It was seen only in a longer run (70 second stall),
  where the first `401` arrived after the first request had itself been held for
  60 seconds, so that run does not pin the onset. A `401` is still a refusal (the
  route does not run), but the status class changes from `503` to `401`. A client
  or monitor that reads every `401` as "re-authenticate" will misread the outage;
  check the database first.
- **Engine principals get `401` too** (measured). An engine token is resolved by
  the same pre-routing authentication as a session, so while the database cannot
  answer it is not resolved and the request is refused `401` `unauthorized`: no
  step-up envelope, no per-principal quota check and no step-up audit row. The
  `403` `engine_principal_denied` answer needs the credential to resolve first; the
  denial itself never reads the MFA store.
- **The server recovers without a restart** (one measurement: about 3 seconds
  after the database answered again, a gated request reached the step-up check
  and got its normal `401` challenge instead of `503`, and `/readyz` returned
  `200`). The wait is the pool's connect circuit breaker, whose
  window is capped at 5 seconds with jitter (`connect_backoff_cap`, `pg_pool.hpp`),
  so a slower recovery within that cap is expected.
- **The step-up refusal audit rows for requests during the stall are lost**
  (measured), as the audit store is the same database.

**What the counters record.** `yuzu_auth_mfa_step_up_gate_total` and
`yuzu_server_audit_emit_failed_total` count what happened, with two limits.
First, the gate counter records only refusals the step-up check itself decides.
A refusal decided before the gate is not counted there: the `401`
`unauthorized` that cookie sessions get once the session cache lapses, and an
engine credential that does not resolve during the outage, never reach the check.
Second, `yuzu_server_audit_emit_failed_total` is exposed with the type `counter`
(its `# TYPE` line comes from the metric's description, `server.cpp`), but the
server refreshes its value by a sweep every 15 seconds (the fleet health
recomputation thread in `server.cpp`), so it lags a burst by up to that long.
See the alert note above for the gate counter's own alert.

**An audit-only outage looks different.** If the audit store fails while the
authentication store is healthy, no step-up refusal is `unavailable`: the audit
write is best effort and never changes the refusal, so the refusals keep their
normal answer (for example a `401` challenge, counted `refused`) and `YuzuStepUpGateUnavailable` does not fire. The alert that
covers it is `YuzuAuditPersistFailures` (`docs/prometheus/yuzu-alerts.yml`), which
fires on `increase(yuzu_server_audit_emit_failed_total[5m]) > 0` held for 2
minutes, so allow for the 15 second refresh plus that hold. In that outage the
refusal rows are lost and the counters are the only record.

**Probes during a stall.** `/livez` and `/login` stay fast (milliseconds,
measured). `/readyz` does not flip at once. It answers from the latest result of
a background reachability probe, not from a live query: the probe runs every 2
seconds, each query has a 2 second deadline, and the replica reports not ready
after 2 consecutive failures (`pg_reachability_rules.hpp`), so it flips within
about 10 seconds. In the measurements `/readyz` kept answering `200` for the first
9 seconds of the stall and `503` after. If no probe succeeds for 15 seconds the
verdict reads stale, which is also not ready, whatever the failure count says.
`/health` can hang for up to about 10 seconds (measured, with unauthenticated
probes). The reason is in the code: `/health` resolves the caller's session
before it answers (`resolve_session_fn` in `health_routes.cpp`), and a session
lookup that the in-memory cache cannot answer is a database read, which during a
stall can wait for the pool's 10 second connect timeout. `/livez` does no session or
database work. Point **liveness** probes at `/livez` and **readiness**
probes at `/readyz`. A liveness probe pointed at `/health` can fail repeatedly
during a database stall (11 consecutive failures at 1 and 2 second probe timeouts
in the test) and restart a server that would have recovered by itself; the
restart then makes the incident longer.

### Precondition: Postgres must be reachable

Everything below assumes the server is running, which means it reached Postgres at
boot (the server refuses to start otherwise; see
[Postgres substrate unreachable](#postgres-substrate-unreachable)). If the server
is down, this section does not apply: use the boot procedures above.

### Work through the cause, not the route

1. Is Postgres reachable from the server now? See
   [Postgres substrate unreachable](#postgres-substrate-unreachable). Logins
   fail at the same time, so this is usually the same incident.
2. Did the KEK resolve? A non-zero `secret_decrypt_failures_total` for the
   `auth` store means enrolled accounts cannot be read; see
   [KEK missing or unreadable](#kek-missing-or-unreadable).
3. Check `yuzu_auth_secret_unavailable_total{route="mfa_stepup"}` against the
   other `route` values: if only `mfa_stepup` moves, look at the one account
   named in the audit rows' `detail`.

### Single account: prefer `--mfa-reset`

If one account's second factor is the problem (a corrupt or undecryptable
secret), reset that account with
[`yuzu-server --mfa-reset <username>`](#the---mfa-reset-cli-audited). It is
audited (`mfa.reset.breakglass`), needs the Postgres DSN and the keys directory,
and does not touch any other account or the rest of the fleet's step-up
protection. The account can re-enrol afterwards. Prefer it over the window
lever below. If `--mfa-reset` fails with `kek_orphaned`, the stored secret names
a key version that is not registered: see
[Stored secret names an unregistered KEK version](#stored-secret-names-an-unregistered-kek-version),
which makes restoring the paired `kek_meta` and keys backup the first choice and
keeps the [direct SQL fallback](#fallback-direct-sql) for a corrupt blob header.

### Last resort: disable the proof requirement fleet-wide

`--mfa-step-up-window-secs 0` (or less) makes the check pass without reading the
enrollment, so a gated route runs again for a local session. It is a deliberate
security reduction for **every** gated route and every account (see
[Locked out by MFA enforcement misconfiguration](#locked-out-by-mfa-enforcement-misconfiguration)
for the other recovery lever), so use it only when you cannot restore the
authentication store or reset the affected account. Know its limits:

- **It does not help the `auth_store_unwired` reason.** The null-store check
  runs before the window is consulted, so a server with no wired store answers
  `503` at any window value. That is a defensive state (a boot-wiring fault or
  a build that wires no store); restart the server with the store configured. The window lever only helps the
  `mfa_status_unavailable` case, and then only for the routes the check guards.
- **It is per process.** Set it on every replica that is failing, by restarting
  each with the flag; a replica you did not restart keeps refusing. The same holds
  for the revert: restore the window (default `300`) and restart **each** replica
  once the store is back. A replica left at `0` is a silent hole in step-up
  protection for as long as it runs.
- **The JIT-elevation routes ignore it.** They substitute a 300 s window, so
  elevation still asks for a fresh proof and still fails if the store cannot be
  read.
- **SAML sessions pass too.** The window check precedes the SAML denial, so while
  the window is `0` or less a SAML session reaches all 33 routes instead of
  getting its `403`.
- **Step-up evidence thins out.** While the window is `0` or less, no stale proof
  is refused, so none is recorded as a `mfa.step_up.required` row (passes never
  write one); the SAML refusal and the store read are skipped as well. Engine
  denials and unwired-store refusals still apply and are still recorded. Write the start and end times of the
  window into your incident record; the audit log cannot reconstruct them.
- **The reminder is slow too.** `YuzuStepUpWindowDisabled` fires after the gauge
  has read `0` or less for 10 minutes, so a short-lived window passes without an
  alert.

The server logs a startup `WARN` while the flag is in force. Restore the window and
restart once the store is back.

## What you cannot recover from

- **Lost `yuzu-server.cfg` and an empty `auth` schema.** The config is the seed
  for the admin account on first boot. If both are gone, start `yuzu-server`
  interactively on a terminal with no `yuzu-server.cfg` at the configured path
  (`--config`): it runs first-run setup, prompts for a new administrator and
  writes a fresh config. (There is no `--first-run-setup` flag; setup runs
  whenever the config file is absent and needs a TTY.)

- <a id="kek-permanently-lost"></a>**KEK permanently lost.** First, the server
  **will not start** on a database that still registers the lost version.
  Every boot verifies each registered KEK and stops with `kek_unresolvable`.
  The one-shot modes `--mfa-reset` and `--break-glass-arm` run after that check
  and fail the same way, and there is no supported way to deregister a KEK
  version. Without the key file, this database cannot be brought back by any
  supported means; it is usable again only with the key file restored from a
  backup. **Do not delete rows from `secrets.kek_meta` to force a start.** The
  server then mints a new key under the same version number, every secret
  sealed under the lost key (webhook secrets, plugin and runtime config
  secrets, offload credentials) becomes permanently undecryptable with no error
  at boot, and a key file you later find cannot be used (#5421). Take a
  `pg_dump` before you discard the database: it holds the audit log and
  configuration, but never restore it into a new install, because it registers
  the lost KEK. Otherwise you start over with a fresh database, and the CA in
  the same directory is usually gone too, which means a full agent
  re-enrolment. The Docker Compose case is worked through in
  `docs/user-manual/upgrading.md` (#5370). What the KEK does and does not
  protect:
  - **Not sealed under the KEK:** password hashes and MFA recovery codes are
    verify-only PBKDF2 hashes. They are lost only if you start over with a
    fresh database.
  - **Sealed, and unrecoverable without the key file:** TOTP secrets, so every
    enrolled user must re-enroll, and the other secret columns listed in
    `docs/user-manual/server-admin.md` "Key management (secrets KEK)", such as
    webhook signing secrets.
  - Any future envelope-encrypted column follows the same rule: re-enrollable
    or re-issuable by design, which is why ADR-0010 requires it.

  Do **not** delete the old key file until you are certain no backup you intend
  to honour still contains blobs wrapped under it.

- **Backups whose encryption key is lost.** Standard; nothing Yuzu-specific.

## Cross-references

- `docs/auth-architecture.md` — auth model, hardened mode, break-glass design
- `docs/user-manual/server-admin.md` — KEK lifecycle, rotation, secrets at rest
- `docs/adr/0006-server-postgresql-substrate.md` — fail-closed substrate
- `docs/adr/0010-secrets-at-rest-envelope-encryption.md` — envelope encryption
- `docs/postgres-store-playbook.md` — store authoring contract
- `docs/agent-privilege-model.md` — service accounts and sudoers
- `docs/ops-runbooks/engine-principal-store-recovery.md` — `engine:` namespace
