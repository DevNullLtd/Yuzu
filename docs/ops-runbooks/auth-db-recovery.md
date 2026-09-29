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
| `[PG] Refusing to start: SecretCodec::init() failed — …` | The secrets seam could not initialise — usually a missing or unreadable KEK | [KEK problems](#kek-missing-or-unreadable) |
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

```bash
# Linux — run both, keep them together, encrypt the pair at rest.
STAMP=$(date +%Y%m%dT%H%M%SZ)
sudo -u _yuzu pg_dump "$YUZU_POSTGRES_DSN" --format=custom \
     > /var/backups/yuzu/yuzu-$STAMP.dump
sudo tar -czf /var/backups/yuzu/yuzu-keys-$STAMP.tar.gz \
     -C /etc/yuzu certs
```

```powershell
# Windows
$Stamp = Get-Date -Format yyyyMMddTHHmmssZ
pg_dump $Env:YUZU_POSTGRES_DSN --format=custom > "C:\Backups\Yuzu\yuzu-$Stamp.dump"
Compress-Archive -Path C:\ProgramData\Yuzu\certs -DestinationPath "C:\Backups\Yuzu\yuzu-keys-$Stamp.zip"
```

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

Only when no `yuzu-server` binary is available on the host. **Writes no audit
row** — record it manually.

```bash
psql "$YUZU_POSTGRES_DSN" <<'SQL'
UPDATE auth.users
   SET mfa_totp_secret  = NULL,
       mfa_enrolled_at  = NULL,
       mfa_disabled_at  = now(),
       mfa_last_counter = 0
 WHERE username = 'alice';
DELETE FROM auth.mfa_recovery_codes WHERE username = 'alice';
SQL
```

Clearing the secret needs no KEK (you are writing NULL, not reading
ciphertext), so this works even when the KEK is unavailable.

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
Settings → Multi-Factor Authentication, which needs the admin role. For a
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

# 2. Log in with password alone, enroll via Settings → Multi-Factor
#    Authentication, and SAVE the recovery codes.

# 3. Restore enforcement and restart.
```

## What you cannot recover from

- **Lost `yuzu-server.cfg` and an empty `auth` schema.** The config is the seed
  for the admin account on first boot. If both are gone, run
  `yuzu-server --first-run-setup` to create a new admin interactively and write
  a fresh config.

- <a id="kek-permanently-lost"></a>**KEK permanently lost.** Painful, but not a
  total lockout — the blast radius is narrower than it first looks:
  - **Admin sign-in survives.** MFA recovery codes are verify-only PBKDF2
    hashes and need no KEK. Sign in with a recovery code, then re-enroll TOTP.
  - **Password login is unaffected** — password hashes are PBKDF2, not
    envelope-encrypted.
  - **TOTP secrets are unrecoverable.** Every enrolled user must re-enroll.
    Clear the dead ciphertext with the [fallback SQL](#fallback-direct-sql)
    above (writing NULL needs no key), then have users re-enroll.
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
