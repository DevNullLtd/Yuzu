# Auth Store Recovery Runbook

<!-- yuzu:anchor release=v0.13.0 -->

Operator runbook for recovering a Yuzu server when authentication is broken
or an operator is locked out.

**Read this first if you are mid-incident — this document describes
`v0.13.0`, the latest tagged release, unless a section is explicitly marked
"Not in v0.13.0" below:**

<!-- yuzu:claim id=auth-store-sqlite status=shipped evidence=server/core/src/auth_db.cpp#sqlite3_open_v2 -->
1. **Auth data lives in an on-disk SQLite file, `auth.db`** — there is no
   PostgreSQL involved in authentication at this release. (Yuzu's server
   substrate migration to PostgreSQL is underway and several *other* stores
   already require it — `--postgres-dsn`/`YUZU_POSTGRES_DSN` unset or
   unreachable still refuses to boot — but the `auth` schema specifically
   has **not** migrated yet at `v0.13.0`. See "Not in v0.13.0" below for
   what changes once it does.)
2. **TOTP (MFA) secrets are stored in plaintext in `auth.db`, protected only
   by the file's `0600` permission mode** — there is no encryption key to
   pair with a backup at this release. A `.backup`/copy of `auth.db` **is**
   a complete backup of everything auth-related, including MFA secrets. Do
   **not** assume you need a separate key file — you don't, yet. (This
   changes in a future release — see "Not in v0.13.0" below — which is a
   *security improvement* but also changes what "a complete backup" means;
   re-read this document after upgrading rather than assuming it still
   applies unchanged.)

This runbook assumes a single-node Yuzu deployment. For HA, see
"Not in v0.13.0" below — it is not shipped at this release.

## Detection signal

`yuzu-server` exits with a non-zero status at startup and `journalctl -u
yuzu-server` (Linux) or the server log file (Windows — the installer
configures `--log-file "<install dir>\logs\yuzu-server.log"`, default
install dir `C:\Program Files\Yuzu Server`; the server does not write to
the Windows event log) shows one of these
lines, each followed by `Failed to initialize auth DB: <error-code>`:

```
[error] Auth DB integrity check failed: <PRAGMA integrity_check result>
[error] Failed to open auth DB: <sqlite-error>
[error] Failed to create auth DB directory: <error>
[error] AuthDB: schema migration failed
```

If the shipped systemd unit is in use it retries `StartLimitBurst=3` times
within `StartLimitIntervalSec=60`, then enters `failed`:

```
$ systemctl status yuzu-server
● yuzu-server.service - Yuzu Endpoint Management Server
     Active: failed (Result: start-limit-hit) since ...
```

That `failed` state is deliberate — it stops a crash-loop from drowning the
journal. Clear it with `systemctl reset-failed yuzu-server` once fixed.

**If the server fails to start with a `[PG] Refusing to start: ...` line
instead of the lines above:** that is a *different* store failing (Yuzu
requires Postgres for its other stores even though auth itself doesn't use
it yet) — see "Not in v0.13.0" below for what that means, but the fix is a
Postgres fix (DSN, reachability, credentials), not an auth-recovery
procedure.

## Recovery procedure

The on-disk schema is rebuilt from the seed config (`yuzu-server.cfg`) on
fresh boot. Runtime state (active sessions, in-memory user list) does NOT
need to be preserved across this procedure — operators will need to
re-authenticate after recovery.

### Linux

```bash
# Stop the service so the file is closed.
sudo systemctl stop yuzu-server

# Archive the corrupt DB on-host. Do NOT delete it without a copy. The
# archive holds password hashes AND plaintext TOTP seeds, so it is created
# 0600 (umask inside the sudo'd shell, so it applies to sqlite3 itself) and
# never leaves this host — see "After the server is back online" step 4.
sudo sh -c 'set -eu; umask 077
  out=/var/lib/yuzu/auth.db.corrupt-$(date +%s)
  sqlite3 /var/lib/yuzu/auth.db ".backup $out"
  chmod 0600 "$out"; ls -l "$out"'

# Move the live file aside (NOT delete — keep one operator-recoverable
# copy in case the corruption was actually a permission/ownership issue
# that's reversible).
sudo mv /var/lib/yuzu/auth.db /var/lib/yuzu/auth.db.broken
sudo mv /var/lib/yuzu/auth.db-wal /var/lib/yuzu/auth.db-wal.broken 2>/dev/null || true
sudo mv /var/lib/yuzu/auth.db-shm /var/lib/yuzu/auth.db-shm.broken 2>/dev/null || true

# Reset the unit's restart counter so it can boot again.
sudo systemctl reset-failed yuzu-server

# Start it. The server re-seeds AuthDB from yuzu-server.cfg on first boot.
sudo systemctl start yuzu-server
sudo systemctl status yuzu-server
```

### Windows

Paths below are the installer defaults (`--data-dir "C:\ProgramData\Yuzu
Server\data"`, service name `YuzuServer`); adjust if you installed
differently.

```powershell
# Stop the service.
Stop-Service YuzuServer
$data = 'C:\ProgramData\Yuzu Server\data'

# Archive the corrupt DB on-host, then restrict it to SYSTEM + Administrators
# (it holds password hashes and plaintext TOTP seeds; never leaves this host).
$archive = "$data\auth.db.corrupt-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item "$data\auth.db" $archive
icacls $archive /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'

# Move the live file aside.
Move-Item "$data\auth.db"     "$data\auth.db.broken"
Move-Item "$data\auth.db-wal" "$data\auth.db-wal.broken" -ErrorAction SilentlyContinue
Move-Item "$data\auth.db-shm" "$data\auth.db-shm.broken" -ErrorAction SilentlyContinue

# Start the service.
Start-Service YuzuServer
Get-Service YuzuServer
```

After the server is back online:

1. Log in with the admin credentials from `yuzu-server.cfg`.
2. Re-create any user accounts that existed only in `auth.db` (i.e. created
   via Settings > Users after the seed config was first written). Accounts
   created via the seed config itself are restored automatically.
3. Enrollment tokens and the pending-agent queue do **not** need
   re-issuing: at this release they live in `enrollment-tokens.cfg` and
   `pending-agents.cfg` in the data directory, not in `auth.db` (the
   `enrollment_tokens` table in `auth.db` is never written). Leave those
   files where they are.
4. If you open a support ticket, **do NOT attach the archived
   `auth.db.corrupt-<timestamp>` file, the `.broken` files, or any copy of
   them** — they contain every password hash and every plaintext TOTP seed.
   Send sanitized diagnostics instead:
   - the server log excerpt around the failure (the detection lines above);
   - the output of `sqlite3 <archive> "PRAGMA integrity_check;"` (page/index
     structure only, no row contents);
   - the schema version, `sqlite3 <archive> "SELECT store, version FROM
     schema_meta;"`, if it runs;
   - file size and modification time (`ls -l` / `Get-Item`), filesystem
     type, and whether the host had a crash, disk-full, or AV event.

   If support determines the database itself is genuinely needed, that
   acquisition happens only through an approved, encrypted
   evidence-transfer procedure agreed with support in advance, with a
   recorded chain of custody and a confirmed deletion date — never as a
   ticket attachment, email, or chat upload. Until then the archive stays
   on this host, `0600` (Linux) / SYSTEM + Administrators only (Windows).

## Prevention — routine backup

`auth.db` should be backed up alongside the rest of `/var/lib/yuzu` (Linux)
or `C:\ProgramData\Yuzu Server\data` (Windows installer default) on the
operator's existing backup schedule. The backup procedure must NOT rely on
`cp` against the live file — SQLite's WAL means a naive `cp` can produce a
torn copy that fails integrity checks on restore. Use the built-in
`.backup` command, which is WAL-aware.

Every backup copy is as sensitive as the live file (see the encryption
requirement below), so the recipe creates it owner-only and verifies that.
The whole recipe runs inside one `sudo sh -c` so the `umask` applies to the
`sqlite3` process itself — a `umask` in your own shell is not reliably
carried across `sudo`:

```bash
sudo sh -c 'set -eu
  umask 077
  install -d -m 0700 -o root -g root /var/backups/yuzu   # creates or re-tightens
  out=/var/backups/yuzu/auth.db.$(date +%s)
  sqlite3 /var/lib/yuzu/auth.db ".backup $out"
  chmod 0600 "$out"
  test "$(stat -c %a /var/backups/yuzu)" = 700
  test "$(stat -c %a "$out")" = 600
  test "$(sqlite3 "$out" "PRAGMA integrity_check;")" = ok
  ls -l "$out"'
```

On Windows, write into a directory that only SYSTEM and Administrators can
read, and restrict the file itself too (run elevated):

```powershell
$dir = 'C:\backups\yuzu'
New-Item -ItemType Directory -Force $dir | Out-Null
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'
$out = "$dir\auth.db.$(Get-Date -Format yyyyMMdd-HHmmss)"
sqlite3 'C:\ProgramData\Yuzu Server\data\auth.db' ".backup '$out'"
icacls $out /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'
icacls $out    # verify: only NT AUTHORITY\SYSTEM and BUILTIN\Administrators
```

Run nightly on the same cadence as the rest of the data-directory backup.
The backup file is itself a valid SQLite database. **Restore procedure:**

1. Check the backup's integrity before touching anything live.
2. Stop the service.
3. Move the live `auth.db` **and any `auth.db-wal` / `auth.db-shm`** aside.
   A leftover WAL belongs to the old database; if it sits next to the
   restored file, SQLite can replay its frames into the restored file and
   corrupt it.
4. Copy the backup in, owner-only.
5. Check permissions and integrity again.
6. Start the service.

Linux (the service runs as `yuzu`, so the restored file must be
`0600 yuzu:yuzu`):

```bash
BACKUP=/var/backups/yuzu/auth.db.<timestamp>   # the backup to restore
sudo systemctl stop yuzu-server
sudo sh -c 'set -eu; umask 077
  b="$1"; d=/var/lib/yuzu; ts=$(date +%s)
  test "$(sqlite3 "$b" "PRAGMA integrity_check;")" = ok
  for f in auth.db auth.db-wal auth.db-shm; do
    if [ -e "$d/$f" ]; then mv "$d/$f" "$d/$f.pre-restore-$ts"; fi
  done
  install -m 0600 -o yuzu -g yuzu "$b" "$d/auth.db"
  test "$(stat -c "%a %U:%G" "$d/auth.db")" = "600 yuzu:yuzu"
  test "$(sudo -u yuzu sqlite3 "$d/auth.db" "PRAGMA integrity_check;")" = ok
  ls -l "$d"/auth.db*' sh "$BACKUP"
sudo systemctl start yuzu-server
```

Windows (run elevated; the `YuzuServer` service runs as LocalSystem):

```powershell
$backup = 'C:\backups\yuzu\auth.db.<timestamp>'   # the backup to restore
$data   = 'C:\ProgramData\Yuzu Server\data'
if ((sqlite3 $backup 'PRAGMA integrity_check;') -ne 'ok') { throw 'backup failed integrity_check' }
Stop-Service YuzuServer
$ts = Get-Date -Format yyyyMMdd-HHmmss
foreach ($f in 'auth.db', 'auth.db-wal', 'auth.db-shm') {
  if (Test-Path "$data\$f") { Move-Item "$data\$f" "$data\$f.pre-restore-$ts" }
}
Copy-Item $backup "$data\auth.db"
icacls "$data\auth.db" /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'
if ((sqlite3 "$data\auth.db" 'PRAGMA integrity_check;') -ne 'ok') { throw 'restored auth.db failed integrity_check' }
icacls "$data\auth.db"   # verify: only NT AUTHORITY\SYSTEM and BUILTIN\Administrators
Start-Service YuzuServer
```

The `*.pre-restore-<timestamp>` files are as sensitive as the live
database: they keep their `0600` mode (Linux) or data-directory ACL
(Windows). Delete them once the restored server is confirmed working. If
the restored backup predates an MFA schema migration, also run
"Post-restore migration check" below.

<!-- yuzu:claim id=mfa-secret-plaintext-at-rest status=shipped evidence=server/core/src/auth_db.cpp#mfa_totp_secret BLOB -->
**Backup encryption requirement.** `auth.db` contains the raw TOTP secret
bytes in plaintext — the `0600` file mode on the live host is the *only*
compensating control at this release (see "Not in v0.13.0" below for the
planned encryption-at-rest). Backups MUST be encrypted at rest if your
threat model includes exfiltration of the backup store — restic,
BorgBackup, or `gpg --symmetric` all satisfy this. A SOC 2 CC6.1 audit will
flag an unencrypted `auth.db` backup as a finding even though the live file
is `0600`.

## Windows: Defender exclusion

On Windows production deploys, Defender's real-time scan can hold the
`auth.db-wal` file open during bursts of `auth.db` writes (for example
failed-login lockout counters during a password spray, or bulk user/MFA
changes). Agent enrollment does not write `auth.db` at this release
(enrollment tokens live in `enrollment-tokens.cfg`). The symptom is
sporadic `SQLITE_BUSY` returns in `[warn]` lines that recover after a
retry. Adding the data directory to Defender's exclusion list eliminates
this entirely.

```powershell
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu Server\data\auth.db'
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu Server\data\auth.db-wal'
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu Server\data\auth.db-shm'
```

Or by glob if your policy syntax allows it: `Add-MpPreference
-ExclusionPath 'C:\ProgramData\Yuzu Server\data\auth.db*'`.

The exclusion is safe: `auth.db` is written only by `yuzu-server.exe`, the
file is not user-editable, and password hashes are PBKDF2-SHA256 (salted)
so a Defender bypass does not weaken credential storage.

## Filesystem permissions

`auth.db` is re-tightened to mode `0600` (owner read/write only) on every
open on Linux, and its directory to `0700`. On Windows the server applies
**no** ACL of its own (the permission call is a no-op there); the installer
grants Administrators + SYSTEM full control on `C:\ProgramData\Yuzu
Server\data`, but inherited `ProgramData` entries may still apply — check
with `icacls "C:\ProgramData\Yuzu Server\data\auth.db"` and remove any
entry other than SYSTEM and Administrators. If `ls -l` shows anything other
than `-rw-------` for `auth.db` on Linux, fix it before doing anything else
— a world-readable `auth.db` exposes password hashes AND plaintext MFA
secrets for offline attack:

```bash
sudo chmod 0600 /var/lib/yuzu/auth.db
sudo chown yuzu:yuzu /var/lib/yuzu/auth.db
```

## Emergency session revocation

<!-- yuzu:claim id=rest-session-revoke status=shipped evidence=server/core/src/rest_api_v1.cpp#/api/v1/sessions/me -->
**At this release, sessions are in-memory only — there is no PostgreSQL
durable-session store to worry about, and no build-discrimination step is
needed.** A server restart clears every session immediately, and is the
fastest fleet-wide revocation there is (no database access required).

**Preferred — REST API, audited, no restart needed** (targeted, one
operator at a time):

```bash
# Revoke every session for one operator (admin), needs UserManagement:Write.
curl -fsS -X DELETE "https://yuzu.internal/api/v1/sessions?username=alice" \
     -H "Authorization: Bearer $TOKEN"

# Revoke your own (self-service, "sign out everywhere").
curl -fsS -X DELETE https://yuzu.internal/api/v1/sessions/me \
     -H "Authorization: Bearer $TOKEN"
```

The in-memory wipe **is** the revocation: at this release every session
check reads only the server's in-memory session map. The handler also
issues a best-effort `DELETE` against the `sessions` table in `auth.db`,
but that table is a dead mirror — no production code path inserts session
rows into it or loads sessions from it at boot. So if the response body
reports `db_persisted: false` or the audit row shows `result=partial` with
`db_error=true`, the revocation still took effect and **a restart cannot
resurrect anything**; the partial flag only means the no-op mirror delete
failed, which is worth investigating as a sign of `auth.db` trouble
(locking, disk, permissions), not as a live session.

**Last resort — dashboard/API unreachable.** Restart the server. That
clears every operator session fleet-wide (not just the target user's) and
needs no database access. Editing the `sessions` table in `auth.db` does
nothing — sessions are not there. A restart produces no revocation audit
row, so file an incident note recording the action:

```bash
sudo systemctl restart yuzu-server
```

```powershell
Restart-Service YuzuServer
```

After the restart, verify the target user's previously-issued cookies
return 401 and that they can re-authenticate normally. File a manual
audit-log entry referencing the incident ticket so the unaudited DB-level
action is traceable in the SOC 2 evidence chain.

API tokens are a separate credential class. A restart does **not** revoke
them, and neither does the admin `DELETE /api/v1/sessions?username=` call
(cookie sessions only) — revoke a compromised user's tokens explicitly via
the token endpoints. The self-service `DELETE /api/v1/sessions/me` call is
the exception: it also revokes the caller's own API tokens (reported as
`api_tokens_revoked` in the response).

## Account lockout recovery

An operator is locked out by failed-login lockout
(`--auth-lockout-threshold`, default 5 within `--auth-lockout-window-secs`,
default 900). A locked account returns the same generic 401 as a bad
password. The window auto-expires, so the first question is whether you
need to act at all — waiting it out is the zero-risk path. A subsequent
*successful* login also clears the counter.

<!-- yuzu:claim id=account-lockout status=shipped evidence=server/core/src/main.cpp#--auth-lockout-threshold -->
<!-- yuzu:claim id=admin-unlock-endpoint status=shipped evidence=server/core/src/rest_api_v1.cpp#/users/{username}/unlock -->
**Preferred — admin API** (audited, no database access needed):

```bash
curl -fsS -X POST "https://yuzu.internal/api/v1/users/alice/unlock" \
     -H "Authorization: Bearer $TOKEN"
```

Requires `UserManagement:Write` (plus MFA step-up when the caller is
enrolled). Self-target is allowed. Produces the `auth.lockout.cleared` /
`admin_unlock` audit row.

**Fallback — direct SQL**, when every admin is locked out and no valid
token exists. This writes no audit row; record it in your
change-management system:

```bash
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username, failed_login_count, locked_until FROM users WHERE username = 'alice';"

sqlite3 /var/lib/yuzu/auth.db \
  "UPDATE users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL WHERE username = 'alice';"
```

A restart is **not** required — the lockout state is read from `auth.db` on
the next `POST /login`, so the clear takes effect immediately.

Mass-unlock is a threshold-misconfiguration remedy only (e.g. someone
deployed `--auth-lockout-threshold=1`). Fix the flag in the same
maintenance window, or you will be back:

```bash
sqlite3 /var/lib/yuzu/auth.db \
  "UPDATE users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL;"
```

There is no break-glass CLI for lockout (unlike `--mfa-reset` below); the
auto-expiry window is the standing safety net.

## Emergency MFA disable (break-glass)

**When to use.** An operator has lost both their authenticator device *and*
every recovery code — or has been locked out by MFA enforcement (the IdP
not asserting `amr`, a sole admin who could not enroll). The Settings → MFA
panel is behind login, so the dashboard path is unreachable.

<!-- yuzu:claim id=mfa-reset-cli status=shipped evidence=server/core/src/main.cpp#--mfa-reset -->
### The `--mfa-reset` CLI (audited)

`yuzu-server --mfa-reset <username>` clears the user's MFA enrolment and
exits **without starting the server**. It writes an audit row
(`mfa.reset.breakglass`, principal = the OS account that ran it) to
`auth.db`'s companion audit store.

```bash
sudo -u yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --data-dir /var/lib/yuzu \
  --mfa-reset alice
# {"status":"ok","user":"alice","action":"mfa.reset.breakglass"}
```

**Authorisation — read the threat model.** `--mfa-reset` strips a second
factor with **no MFA, admin-password, or token check of its own**. The only
enforced control is OS-level access: anyone who can run a `yuzu-server`
binary with read access to `data-dir/auth.db` can downgrade **any**
account, including the sole admin. It does not verify it is running as the
service account — that is an operational expectation, not a code-enforced
gate. Treat host access to `auth.db` as equivalent to MFA-reset authority
over every account:

- Run on the server host as the server's service account: `yuzu` on Linux
  (the shipped `yuzu-server.service` sets `User=yuzu`); on Windows the
  `YuzuServer` service runs as LocalSystem, so run it from an elevated
  prompt with `--config "C:\ProgramData\Yuzu Server\yuzu-server.cfg"
  --data-dir "C:\ProgramData\Yuzu Server\data"`. (The `_yuzu` /
  `NT SERVICE\YuzuAgent` accounts in `docs/agent-privilege-model.md` are
  the *agent daemon's*, not the server's.)
- Keep `data-dir` (and `auth.db`) `0700`/`0600`, service-account owned.
- Gate the invocation behind a narrow `sudoers` entry — ideally a dedicated
  break-glass group with a separate approver. The audit principal is the
  real OS identity (`getpwuid`/`GetUserNameA`, **not** the forgeable
  `$USER`), so a tight sudoers entry gives trustworthy attribution.

**Audit is mandatory and fail-closed.** The CLI verifies the audit store is
writable *before* clearing any MFA, and refuses to proceed if it is not.
Because the CLI exits without serving, it emits no Prometheus metric — the
audit row is the only signal. Alert on `mfa.reset.breakglass` in
`audit_events`; an unexpected one is an authentication-downgrade event and
should page on-call.

It is safe to run while the server is up: the one-shot opens its own
`auth.db` connection and does not talk to the running process; SQLite's WAL
+ FULLMUTEX serialise it against the server's concurrent reads/writes.

### Fallback: direct SQL

Only when no `yuzu-server` binary is available on the host. **Writes no
audit row** — record it manually.

```bash
sudo systemctl stop yuzu-server   # optional but safer — avoids contending SQLite

# Owner-only, WAL-safe snapshot first (same pattern as "Prevention — routine
# backup"); it holds every password hash and TOTP seed, so it stays 0600 on-host.
sudo sh -c 'set -eu; umask 077
  out=/var/lib/yuzu/auth.db.before-mfa-rescue.$(date +%s)
  sqlite3 /var/lib/yuzu/auth.db ".backup $out"
  chmod 0600 "$out"
  test "$(sqlite3 "$out" "PRAGMA integrity_check;")" = ok
  ls -l "$out"'

sudo -u yuzu sqlite3 /var/lib/yuzu/auth.db <<'SQL'
UPDATE users
   SET mfa_totp_secret  = NULL,
       mfa_enrolled_at  = NULL,
       mfa_disabled_at  = CURRENT_TIMESTAMP,
       mfa_last_counter = 0
 WHERE username = 'alice';
DELETE FROM mfa_recovery_codes WHERE username = 'alice';
SQL

sudo systemctl start yuzu-server
```

Clearing the secret needs no key (you are writing NULL, not reading
ciphertext) — this works regardless of the "Not in v0.13.0" encryption
status below. Record manually: operator name, target username, timestamp,
reason, and an approval reference (change ticket, on-call paging record) —
this is the SOC 2 CC6.6 break-glass evidence chain for this path.

<!-- yuzu:claim id=break-glass-arm status=shipped evidence=server/core/src/main.cpp#--break-glass-arm -->
## Break-glass arm (IdP outage under `--auth-mode=sso-only`)

Under `--auth-mode=sso-only` only an SSO provider (OIDC or SAML) mints a session. If the IdP is down, the
`--break-glass-user` account is the way back in — but it is exempt **only while
armed**, and arming is an out-of-band host CLI operation so it works when the
IdP does not.

```bash
sudo -u yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --data-dir /var/lib/yuzu \
  --break-glass-user alice \
  --break-glass-arm
# → arms `alice` for --break-glass-window-secs (default 24h, auto-expiring),
#   prints {"status":"ok",...,"armed_until":"..."} and EXITS (does not serve).
```

- **Prerequisite (enforced):** the break-glass account must exist and have
  **MFA enrolled** — the arm refuses otherwise.
- **Audited:** writes an `auth.breakglass.armed` audit row attributed to
  the real OS identity, checked writable *before* the arm mutates — if the
  audit store is unavailable, the arm refuses, so the exemption is never
  granted without a record.
- **Login still needs MFA** — arming does not skip the TOTP challenge.
- **Auto-expiry only** — no early-disarm command; restoring SSO is the way
  to reduce exposure before the window lapses.
- The break-glass account is **exempt from failed-login lockout** while
  `--auth-mode=sso-only` (so an attacker cannot lock the escape hatch by
  spraying wrong passwords during the very outage it exists for) — it
  still requires its second factor, and every attempt is audited
  (`auth.login_failed`) and per-IP rate-limited. Pick a non-guessable
  break-glass username regardless.

## Locked out by MFA enforcement misconfiguration

`--mfa-enforcement=required` (or `admin-only`) can lock operators out via
an IdP not asserting the expected `amr` claim, or a sole admin whose
login-time enrollment window expired before they scanned the QR code.
Enforcement is read from configuration at startup, not from the database,
so the fix is a restart with the flag relaxed — no data surgery:

```bash
# 1. Relax enforcement and restart. auth.db is untouched.
sudo systemctl edit yuzu-server     # --mfa-enforcement=optional
sudo systemctl restart yuzu-server

# 2. Log in with password alone, enroll via Settings → Multi-Factor
#    Authentication, and SAVE the recovery codes.

# 3. Restore enforcement and restart.
```

**Prevention.** Enroll the admin under `optional` *before* switching to
`required`, and validate your IdP's `amr` assertion before relying on
enforcement for SSO users.

## Post-restore migration check

If you restore `auth.db` from a backup taken before an MFA-related schema
migration, the binary will boot but the MFA columns from that migration
will be empty — the migration runner re-adds the columns on first open, but
any user who had MFA enrolled before the backup loses their TOTP
enrollment silently. After restoring an old backup:

```bash
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username FROM users WHERE mfa_enrolled_at IS NOT NULL;"
```

If the result is empty AND your pre-incident state had enrolled users,
notify them to re-enroll. Document the data-loss event in the change
record.

## What you cannot recover from

- **Lost `yuzu-server.cfg` and a lost/unreadable `auth.db`.** The config is
  the seed for the admin account on first boot. If both are gone, the
  original accounts are unrecoverable; create new ones with first-run
  setup. There is no flag for it — `yuzu-server` enters it automatically
  when the config file (`--config`, default `/etc/yuzu/yuzu-server.cfg` on
  Linux, `C:\ProgramData\Yuzu\yuzu-server.cfg` on Windows — the Windows
  installer passes `C:\ProgramData\Yuzu Server\yuzu-server.cfg`) is missing
  or contains no users. It prompts on the terminal for an admin account
  and password and a second, non-admin account and password (passwords at
  least 12 characters, entered twice), writes the config, and then
  **continues booting the server in the foreground**. It needs an
  interactive terminal: under systemd or the Windows service there is no
  stdin, setup fails (`First-run setup failed — exiting`), and the unit
  crash-loops into `start-limit-hit`. So stop the service, move any
  unreadable `auth.db` aside as in "Recovery procedure" above, run the
  binary by hand with the service's own arguments, then stop it and start
  the service (if the foreground run instead exits with `[PG] Refusing to
  start` because the unit's `/etc/yuzu/yuzu-server.env` DSN is not loaded
  in your shell, that is harmless — the config was already written):

  ```bash
  sudo systemctl stop yuzu-server
  sudo -u yuzu /usr/local/bin/yuzu-server --data-dir /var/lib/yuzu
  # answer the prompts; after "Configuration saved to ..." press Ctrl-C
  sudo systemctl reset-failed yuzu-server; sudo systemctl start yuzu-server
  ```

  On Linux/macOS the password prompts **echo what you type** at this
  release — clear the terminal scrollback afterwards and do not run it
  inside a recorded session. Change the second account's password or
  remove it after first login if you do not need it.
- **Encrypted backups whose key is also lost.** Standard; nothing
  Yuzu-specific — `auth.db` itself needs no key at this release (see
  above), but if *you* chose to encrypt the backup file and lost that
  key, the backup is not recoverable.

## Cross-references

- `docs/auth-architecture.md` — auth model, hardened mode, break-glass design
- `docs/user-manual/server-admin.md` — configuration files, upgrade notes
- `docs/adr/0006-server-postgresql-substrate.md` — the substrate migration
  program (see "Not in v0.13.0" below for what applies to `auth` today)
- `docs/adr/0010-secrets-at-rest-envelope-encryption.md` — planned MFA-secret
  encryption (see "Not in v0.13.0" below)
- `docs/agent-privilege-model.md` — service accounts and sudoers
- `docs/ops-runbooks/engine-principal-store-recovery.md` — `engine:` namespace
- `docs/operations/disaster-recovery.md` — the full backup/restore
  procedure. **This file's own copy is the pre-fix version** (reverted to
  `origin/dev` as part of a PO decision splitting DR-procedure fixes into
  separately-tracked work, **issue #4135**) — do not rely on it as the
  second half of a real recovery until that fix has landed in the
  procedure you run.
- Restore drill and the corrected DR procedure: tracked in **issue #4135**.
  Neither the drill transcripts nor the corrected scripts/doc are part of
  this branch's documentation set; no branch name is cited here on
  purpose — an unmerged branch reference goes stale the day it merges or
  is renamed, and the issue number is the durable pointer.

---

## Not in v0.13.0 — planned for a future release

**Everything below describes `dev`-HEAD (this checkout), not the
installed release most readers have.** If you are mid-incident on
`v0.13.0`, stop reading here — none of this applies to you; use the
sections above. Re-verify every claim below against your own commit
before relying on it (`git cat-file -e <your-tag>:<path>`) — this section
is not re-checked every time a new release cuts, and a claim that says
"not in v0.13.0" today may be wrong for whatever you are actually running.

### AuthDB migrates to PostgreSQL (ADR-0006/0007)

<!-- yuzu:claim id=auth-store-postgres status=planned evidence=server/core/src/auth_db.cpp#PgPool -->
At `dev`-HEAD, `auth` data lives in the server's **PostgreSQL substrate,
schema `auth`** — there is no `auth.db` file there, and there is nothing to
move aside. The detection table above does not apply; instead:

| Log line | Meaning |
|---|---|
| `[PG] Refusing to start: no PostgreSQL DSN` | `--postgres-dsn` / `YUZU_POSTGRES_DSN` is unset |
| `[PG] Refusing to start: cannot reach PostgreSQL substrate: …` | Postgres down, wrong DSN, network/auth failure |
| `[PG] Refusing to start: auth store (AuthDB) migration/open failed` | Database reachable, `auth` schema could not be created/opened |
| `[PG] Refusing to start: SecretCodec::init() failed — …` | The secrets seam could not initialise (see the KEK section below) |

**Postgres substrate unreachable.** Confirm from the Yuzu host, as the
service account, using the server's own DSN:
`sudo -u yuzu psql "$YUZU_POSTGRES_DSN" -c 'SELECT 1'`. Work the usual
causes: Postgres service down; `pg_hba.conf` rejecting the host/user; TLS
mismatch; network path; credential rotation; connection limit exhausted.
Yuzu restarts cleanly once Postgres is reachable — no auth data is lost by
the outage itself.

**`auth` schema migration failure.** Usual causes, in likelihood order:
insufficient privilege (verify with
`psql "$YUZU_POSTGRES_DSN" -c "SELECT has_database_privilege(current_user, current_database(), 'CREATE');"`),
or schema drift (a partially-created `auth` schema from an interrupted
migration). Inspect with
`psql "$YUZU_POSTGRES_DSN" -c "\dt auth.*"` and
`psql "$YUZU_POSTGRES_DSN" -c "SELECT * FROM public.schema_meta WHERE store = 'auth';"`
before touching anything — the migration runner refusing to proceed on
drift is the fail-closed behaviour working, not a bug.

If the schema truly must be rebuilt from the seed config (a deployment with
no auth data worth keeping), **every step below must succeed before the
next one runs — do not run these as independent, unchained lines.** A
`pg_dump` that fails silently (permission error, disk full, a missing
target directory) followed by an unconditional `DROP SCHEMA` is
irreversible destruction of every local account, MFA enrolment, and
enrollment token in the schema, with the backup the procedure itself
specified silently absent:

```bash
set -euo pipefail
# The dump holds every local account hash and MFA enrolment: create it
# owner-only, in an owner-only directory, exactly like the routine backup.
umask 077
sudo install -d -m 0700 -o "$(id -un)" /var/backups/yuzu
STAMP=$(date +%s)
DUMP="/var/backups/yuzu/auth-before-drop-$STAMP.dump"

# --format=custom (not plain SQL) so pg_restore --list can structurally
# validate the file before anything is dropped.
pg_dump "$YUZU_POSTGRES_DSN" --schema=auth --format=custom -f "$DUMP"
test -s "$DUMP"                              # non-empty, or stop here
test "$(stat -c %a "$DUMP")" = 600            # owner-only, or stop here
pg_restore --list "$DUMP" >/dev/null          # structurally valid, or stop here

# Only reached if every check above succeeded.
psql "$YUZU_POSTGRES_DSN" -c 'DROP SCHEMA auth CASCADE;'
psql "$YUZU_POSTGRES_DSN" -c "DELETE FROM public.schema_meta WHERE store = 'auth';"
sudo systemctl restart yuzu-server
```

`set -euo pipefail` at the top means any failing step aborts the whole
sequence before reaching the `DROP` — this is the fix for the version of
this procedure that used to present these as separate copy-pasteable
lines with no chaining, which let an operator's mid-incident copy-paste
run the `DROP` even after a failed dump. On restart the server re-seeds
the admin account from `yuzu-server.cfg`.

### Post-restore verification (Postgres substrate)

```bash
systemctl status yuzu-server
curl -fsS http://127.0.0.1:8080/health

psql "$YUZU_POSTGRES_DSN" -c "SELECT store, version FROM public.schema_meta WHERE store IN ('auth','scim_store');"

# The KEK-resolution check below needs `set -o pipefail` (or checking curl's
# exit status separately) — a bare `curl | grep` masks a curl failure as
# "grep found nothing", which this step's own pass condition ("must be
# ZERO, or absent entirely") cannot then distinguish from a genuine zero.
# It ALSO only works from the server's own loopback (127.0.0.1/::1 are the
# only addresses /metrics serves unauthenticated) — run it ON the server
# host, not from a container bridge or a remote jump box. A TLS-by-default
# deployment rejects a plain http:// probe, so use the HTTPS port; `-k` is
# acceptable here ONLY because the target is the server's own loopback and
# the request carries no credential.
set -o pipefail
curl -fsS http://127.0.0.1:8080/metrics | grep secret_decrypt_failures_total
# TLS-only deployment (plain HTTP disabled) — use this form instead:
#   curl -fsSk https://127.0.0.1:8443/metrics | grep secret_decrypt_failures_total
echo "curl+grep exit: $?"   # nonzero here means the CHECK ITSELF failed to
                             # run — re-run from the right host before
                             # trusting a "not found" result as "zero".

# A real MFA login works end-to-end (not just "the page loads").
```

The KEK check is the one people skip. It is the only cheap check that
distinguishes "restored correctly" from "restored, and every MFA user will
be locked out the moment they try to log in" — see the KEK section below.

### Secrets-at-rest envelope encryption for MFA (ADR-0010)

<!-- yuzu:claim id=mfa-secret-envelope-encryption status=planned evidence=server/core/src/auth_db.cpp#SecretCodec -->
At `dev`-HEAD, TOTP secrets in `auth.users.mfa_totp_secret` are
envelope-encrypted (ADR-0010) — a real change from the plaintext-at-rest
description above. The wrapped data key travels with the row in Postgres,
but the key-encryption key (KEK) that unwraps it is a **file, not in the
database**:

| | Path |
|---|---|
| Linux / macOS | `/etc/yuzu/certs/secrets-kek-v<N>.key` |
| Windows | `C:\ProgramData\Yuzu\certs\secrets-kek-v<N>.key` |

**A Postgres dump alone is no longer a complete backup once this ships for
you.** Restore the dump next to a *different* KEK and every MFA decrypt
fails closed — users are locked out of MFA with `SecretUnavailable` errors
and a `yuzu_server_secret_decrypt_failures_total{failure_class="kek_unresolvable"}`
counter climbing. Capture the database dump and the keys directory as a
pair, from the same point in time, and restore them as a pair:

The key archive contains the KEK **and the CA private key**, so it is at
least as sensitive as the dump. Create both owner-only, in an owner-only
directory, in one `sudo sh -c` so the `umask` applies to the processes that
write the files (the DSN is passed as an argument because `sudo` does not
carry your environment):

```bash
sudo sh -c 'set -eu
  umask 077
  install -d -m 0700 -o root -g root /var/backups/yuzu
  stamp=$(date +%Y%m%dT%H%M%SZ)
  pg_dump "$1" --format=custom -f /var/backups/yuzu/yuzu-$stamp.dump
  tar -czf /var/backups/yuzu/yuzu-keys-$stamp.tar.gz -C /etc/yuzu certs
  chmod 0600 /var/backups/yuzu/yuzu-$stamp.dump /var/backups/yuzu/yuzu-keys-$stamp.tar.gz
  test "$(stat -c %a /var/backups/yuzu)" = 700
  test "$(stat -c %a /var/backups/yuzu/yuzu-keys-$stamp.tar.gz)" = 600
  pg_restore --list /var/backups/yuzu/yuzu-$stamp.dump >/dev/null
  ls -l /var/backups/yuzu/yuzu-*$stamp*' sh "$YUZU_POSTGRES_DSN"
```

Rules that follow: encrypt the key archive at rest, separately from the
dump if your threat model allows; never restore a dump onto a host whose
keys directory came from a different backup generation (treat MFA
enrolments as lost and plan a re-enrolment if you cannot prove they are
paired); retain old KEK versions after a rotation (needed to read backups
taken before the rotation completed); drill it — restore into a scratch
database + scratch keys directory and verify a real TOTP login succeeds.

`SecretCodec::init()` failing at boot means the KEK is missing/unreadable
— check ownership/permissions (`sudo -u yuzu ls -l
/etc/yuzu/certs/secrets-kek-v*.key`); absent on a fresh install is normal
(the server generates one and logs it); absent on an existing install
means the KEK has been lost — do **not** let the server generate a new one
and consider it fixed, a new KEK cannot decrypt existing blobs. Admin
sign-in still survives a permanently-lost KEK (MFA recovery codes are
verify-only PBKDF2 hashes and need no KEK; password hashes are unaffected)
— every enrolled user's TOTP is unrecoverable and must re-enroll.

### Durable PostgreSQL-backed operator sessions (ADR-2002 §4, HA WS-1/1a, tracked #4283)

<!-- yuzu:claim id=session-store-durable-pg status=planned evidence=server/core/src/server.cpp#SessionStore -->
**No tagged release ships this today (verified 2026-09-11 via `git
cat-file -e <tag>:server/core/src/session_store.hpp`, which fails on every
release including `v0.13.0`).** At `dev`-HEAD, `SessionStore` is a
born-on-PG durable store wired into `AuthManager`, so sessions
write-through to PostgreSQL and **survive a restart, a crash, or a replica
failover.** This reverses the guidance in "Emergency session revocation"
above: **restarting a `dev`-HEAD server does NOT revoke a session** — the
durable row is untouched and the session is live again the moment the
server (or its replacement replica) comes back up.

**There is no reliable way to tell which build you are running from inside
this document, and this document should not pretend otherwise.** A
previous revision tried a log-line check and a Postgres-query check; both
were found, live, to give a confident WRONG answer rather than an honest
"can't tell" (a healthy durable boot logs nothing distinguishing it from
legacy; a Postgres query is unusable during the very outage this section
exists for). **If you must know for certain: ask whoever deployed the
build, or check the deployed commit** (`yuzu-server --version` prints the
git commit hash) **against your own build/release history** — do not trust
an in-band runtime check to tell you.

<!-- yuzu:claim id=version-flag-commit-hash status=shipped evidence=server/core/src/main.cpp#kGitCommitHash -->
**During an actual Postgres outage or `SessionStore` degrade, no
documented revocation path is complete, and a "success" you observe may
not be one:**

- **Restart revokes nothing durably.** The durable row survives; once
  Postgres recovers, it is exactly as valid as before the restart.
- **The REST revocation call can return 401/403 for a reason that has
  nothing to do with revocation succeeding or failing.** Both RBAC reads
  and the session-generation check serve from a bounded stale-serve cache
  during a brief outage (~5s for RBAC, ~30s for the session generation
  check) and then fail closed once that bound elapses — meaning the
  `DELETE /api/v1/sessions` handler is never even reached; the request
  itself is rejected. **A 401 returned from an endpoint you called to
  "sign out everywhere" is easy to misread as "it worked" — it did not.**
  No local wipe occurred, no durable delete occurred, and a compromised
  session already past that window is untouched.
- **If the call DOES reach the handler**, it still performs the
  process-local in-memory wipe unconditionally even if the durable delete
  fails (`db_persisted=false`, audited `result="partial"`, `db_error=true`
  — `docs/auth-architecture.md`'s "the local wipe still done so the
  operator's kill NOW intent is honored" language) — but that local wipe
  does not survive Postgres recovering with the row still undeleted: the
  next validation of that same bearer token re-reads the still-present row
  and the session is live again.
- **The only genuinely implementable containment options during the
  outage are network-layer, and only two are real:** block the specific
  source IP at a reverse proxy or firewall (a reverse proxy can see a
  connection's source IP; it cannot see a raw bearer token's hash, which
  lives in the unreachable Postgres instance — a token-hash-based deny
  rule is not something a proxy can execute), or take the whole listener
  offline. Neither is a substitute for the durable delete; both are
  better than believing an inaccessible 401 was a success.
- **Once Postgres has actually recovered**, issue the REST call and
  confirm the audit record reports `db_persisted=true` (not `"partial"`)
  before treating the session as revoked. If it still reports partial,
  retry rather than assume success from the HTTP status alone.

API tokens remain a separate credential class unaffected by any of the
above, on both builds.
