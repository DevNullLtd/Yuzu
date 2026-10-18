# Crypto — Cryptographic Library Inventory

The `/crypto` dashboard shows which cryptographic libraries are installed across the fleet and at
which versions. It answers questions such as "which devices still carry OpenSSL 1.1?" or "where
is GnuTLS installed?" from data Yuzu already collects: the daily-synced
[installed-software inventory](inventory.md) (ADR-0016). No new agent code runs and nothing new
is collected from endpoints.

Each installed package name is matched against a curated table of library families (OpenSSL,
GnuTLS, NSS, Mbed TLS and others, see [The library table](#the-library-table)). The page reports
two facts per family and nothing more: how many distinct devices carry it, and which versions
and package names were seen.

**What this is not.** It is package-level presence evidence. It does not decide whether a library
or a version is acceptable, and it carries no weak, vulnerable, post-quantum or outdated verdicts.
Interpreting a version is left to the reader (or to an agentic worker reading the same data):
Yuzu deliberately keeps the matching mechanical and deterministic, and leaves judgement out of
the product's core. A family that does not appear is not proof that the library is absent (see
[Coverage and limits](#coverage-and-limits)).

## Access

Crypto is an item in the **Posture** group of the sidebar (**Posture > Crypto**), or go to
`/crypto` directly. Permission required: **`Inventory:Read`**, the same permission that gates
the [`/software` and `/inventory` pages](inventory.md).

- **Management-group confinement applies.** A caller confined to management groups sees only
  the devices in their scope, and every figure on the page (family counts, the devices-reporting
  denominator, version buckets and the device drill) is computed over that scope, not filtered
  afterwards. Two operators can legitimately see different counts.
- **Service-scoped API tokens are confined** to the devices their service tag selects, by the
  same mechanism. This surface admits them (confined by the gate) where the `/software`
  catalogue refuses them, because the catalogue is an unfilterable rollup across the whole
  fleet while every figure here is computed over the caller's scope. While RBAC enforcement is
  off (the default), service-scoped tokens are refused with a 403 on these routes: the stricter
  default, not an error.
- A caller with no `Inventory:Read` grant gets a 403 on the REST routes, and the page shows a
  notice instead of data. The refusal is audited by the access gate (see [Audit](#audit)). When the authorization store
  itself cannot be read the page shows the same "unavailable" banner as an inventory outage, not
  a permission notice.

**Data classification.** The data is machine-scope and device-attributable: it names the devices
that carry a library, so it is treated as device inventory for works-council purposes (see
[enterprise readiness §3.5](../enterprise-readiness-soc2-first-customer.md)). It contains no user
content. Rows are erased with the device by the decommission cascade, like the rest of the
installed-software inventory.

## The page

### KPI strip

Three tiles across the top:

| Tile | Meaning |
|---|---|
| Devices reporting inventory | Devices in your visible scope that have an installed-software report. This is the denominator: a device that has never reported cannot be shown to carry or not carry a library. The denominator is floored at the numerator, so it is never smaller than the devices-with-a-library figure. |
| Devices with a crypto library | Distinct devices in scope with at least one package matching any family. A device carrying `libssl3` and `libgnutls30` counts once here. |
| Families matched | Number of curated families with at least one matching device, shown against the size of the table ("of 12 in the table"). |

### Families table

One row per family found, ordered by device count (highest first), then family id. Families with
no matching device are omitted.

| Column | Meaning |
|---|---|
| Family | The library family (for example OpenSSL). |
| Devices | Distinct devices carrying any package of the family. A device with both `libssl3` and `openssl` counts once. |
| Versions | Number of distinct (version, ecosystem) buckets. |
| Top versions | The four most-installed version buckets as chips; `+more` when there are others. |

The response is bounded, and every cut is flagged, never silent:

- The version list is capped at 50 buckets per family; when it is, the family is flagged
  `versions_truncated` in the API. The device count is unaffected by that cap.
- Each package name is cut to 256 bytes (on a character boundary, ending in `…`), and a bucket
  shows at most 8 package names.
- The whole summary has a byte budget of about 256 KiB, plus at most one first bucket per family
  (worst case about 300 KB). When one agent (or many) reports so many versions
  that the budget would be exceeded, further buckets of the most crowded families are dropped
  (every family keeps at least its most-installed bucket, which is why the budget can be exceeded
  by those twelve buckets), those families are flagged
  `versions_truncated` and the summary sets `result_truncated`. Buckets are kept most-installed
  first, so a flood of one-device versions cannot push the common versions out.
- If the store's row ceiling (2,000 version rows per read) is reached, the page says so and the
  API sets `result_truncated`; a family whose every version row was cut is flagged
  `versions_truncated` too.

In every case the family device counts and the coverage figures are still complete; only some
version rows are missing.

### Devices drill

Click a family row to load the devices carrying it, or click a version chip to narrow to that
exact (version, ecosystem) bucket. Each row is one matching package on one device:

| Column | Meaning |
|---|---|
| Device | Hostname (an em dash when the registry does not know the device) and the agent id. |
| Package | The package name as reported, for example `libssl3`. |
| Version, Release | As reported by the package manager; an em dash when the ecosystem does not store the field. |
| Ecosystem | `deb`, `rpm`, `apk`, `pacman`, `brew`, `windows` and so on. |
| Kind | The inventory row kind (for example `package`). |

A device with several matching packages appears once per package. Rows are ordered by agent id,
then package name, and loaded 100 at a time with a **Load more devices** button.

### The evidence caveat

Every state of the page, including the empty and the error states, carries this notice:

> Package-level evidence only, and coverage differs by operating system: Linux reports
> distribution packages, macOS reports Homebrew packages only, and Windows reports only
> installers registered with the OS (the registry). Statically linked, vendored and OS-bundled
> copies (for example LibreSSL on macOS, or DLLs shipped inside Windows applications) are not
> visible here. Certificates, SSH host keys and protocol settings are planned and not yet
> available.

## The library table

The mapping from package name to family is a single table in the server
(`server/core/src/crypto_library_model.cpp`). It is the only copy: the database query patterns
are generated from it, and the per-row results are re-checked against it. The current revision is
**`table_version` 2**, returned in every summary response. A client that stores results can use
it to tell which mapping produced them; the number is bumped on any edit to the table. A device-drill cursor is bound to it: a cursor
issued under another `table_version` is refused (the walk restarts without a cursor), so a walk
can never silently straddle two mappings. Version 2 narrowed the bare `libssl` and `libcrypto`
prefixes (which also matched unrelated packages such as `libcrypto++8` and `libssl-ocaml`) to
the real OpenSSL package names, so OpenSSL counts can differ from version 1.

**How a name is matched.** The package name is lowercased (ASCII) and compared with each rule
of the table. A rule is either *exact* (the whole name must equal the value) or *prefix* (the
name must start with the value). The first matching rule wins, and the table is built so that no
package name matches two families. Matching is on the package name only, never on the version,
publisher or file contents. A prefix rule also matches the related packages that share the
prefix (for example `libssl3t64` matches the `libssl3` rule), because the inventory records
package presence, not what is loaded in memory.

| Family id | Display name | Exact names | Prefixes |
|---|---|---|---|
| `openssl` | OpenSSL | `compat-openssl10`, `compat-openssl11`, `libopenssl1_1`, `libopenssl3`, `libssl-dev`, `libssl-doc`, `openssl`, `openssl-1.1`, `openssl-1_1`, `openssl-3`, `openssl-libs`, `openssl1.1`, `openssl3`, `openssl3-libs` | `libcrypto0`, `libcrypto1`, `libcrypto3`, `libcrypto4`, `libssl0`, `libssl1`, `libssl3`, `libssl4`, `openssl@` (Homebrew), `win32 openssl`, `win64 openssl` (Windows installers) |
| `libressl` | LibreSSL |  | `libressl` |
| `boringssl` | BoringSSL |  | `boringssl` |
| `gnutls` | GnuTLS | `gnutls` | `gnutls-`, `libgnutls` |
| `nss` | NSS | `libnss3`, `libnss3-tools`, `mozilla-nss`, `mozilla-nss-tools`, `nss`, `nss-softokn`, `nss-softokn-freebl`, `nss-sysinit`, `nss-tools`, `nss-util` |  |
| `mbedtls` | Mbed TLS | `mbedtls` | `libmbedcrypto`, `libmbedtls`, `libmbedx509` |
| `wolfssl` | wolfSSL | `wolfssl` | `libwolfssl` |
| `libgcrypt` | Libgcrypt |  | `libgcrypt` |
| `libsodium` | libsodium |  | `libsodium` |
| `nettle` | Nettle | `nettle` | `libhogweed`, `libnettle` |
| `botan` | Botan |  | `botan`, `libbotan` |
| `bouncycastle` | Bouncy Castle |  | `bcprov`, `bouncycastle`, `libbcpkix`, `libbcprov` |

**Deliberate exclusions.** The `nss` family is exact-names only. A `nss` prefix rule would also
match `nss-mdns` and `nss-pam-ldapd`, which are name-service switch plugins and not
cryptography, so they do not appear. Likewise `libssl` and `libcrypto` are not bare prefixes: only
the versioned names (`libssl3`, `libssl1.1`, `libcrypto3` and so on) and the exact development
names are matched, so `libcrypto++` (Crypto++), `libcryptominisat` and `libssl-ocaml` do not
count as OpenSSL. The same care is taken everywhere else: a rule is added only where the package
name reliably denotes the library. A cryptographic library that is packaged under a name the
table does not list is not reported.

On Windows, installers from the Shining Light OpenSSL distribution register display names such as
`Win64 OpenSSL v3.x`, which the `win64 openssl` and `win32 openssl` prefixes match. The prefix
`openssl ` alone is not used for Windows.

## Coverage and limits

The data comes from the installed-software daily sync, so what appears depends on what each
operating system's package source records:

| OS | What appears |
|---|---|
| Linux | Packages from `dpkg` (`deb`), `rpm`, `apk` and `pacman`; snaps and flatpaks (the table rarely matches these). |
| macOS | Homebrew formulae (`brew`, for example `openssl@3`) and applications and packages from `system_profiler`. |
| Windows | Applications registered in the `HKLM` and agent-account `HKCU` uninstall keys. |

What never appears:

- **Statically linked libraries.** A binary that embeds its own copy of a library has no package
  record for it.
- **Vendored or bundled copies**, including DLLs shipped inside Windows applications and
  libraries bundled with an application on any OS.
- **OS-shipped libraries that are not packages.** macOS ships LibreSSL and BoringSSL as part of
  the operating system; neither is a package, so neither is listed.
- Anything on a device that has not completed an inventory sync. Compare "Devices reporting
  inventory" with the size of your fleet before reading a count.

A "supported" inventory source that returns zero matching rows means "no matching package rows in
your visible inventory", not "the library is absent". The page, the API and the MCP tools all say
it that way. The inventory sync also keeps its last good state when a collection cycle fails, so
a figure can be up to one daily sync old.

## Agentic access

Both views are available to agentic workers with the same data and the same permission.

### REST

| Route | Purpose |
|---|---|
| `GET /api/v1/crypto/libraries` | Family summary: devices per family, version buckets, coverage. Optional `family`, `ecosystem`. |
| `GET /api/v1/crypto/libraries/devices` | One family's devices, paged. Required `family`; optional `version`, `ecosystem`, `cursor`, `limit` (1 to 1000, default 100). The response carries `table_version`. |

`version` and `ecosystem` are matched **exactly**, and a parameter that is present but empty is
the exact empty value (some rows genuinely carry no version or no ecosystem); an absent parameter
means any. Both accept up to 1,024 bytes, the same bound as the inventory ingest, so every bucket
the summary shows can be drilled. A repeated parameter with differing values is a `400`.

Full parameters, response shapes and error tables are in [rest-api.md](rest-api.md#crypto).

### MCP

| Tool | Mirrors | Notes |
|---|---|---|
| `get_crypto_libraries` | `GET /api/v1/crypto/libraries` | Args `family` (one of the twelve family ids) and `ecosystem` (at most 1,024 bytes; `""` selects rows with no ecosystem, omit for any), both optional. |
| `list_crypto_library_devices` | `GET /api/v1/crypto/libraries/devices` | Args `family` (required), `version` (at most 1,024 bytes), `ecosystem` (at most 1,024), `cursor` (at most 2048 bytes), `limit` (1 to 1000). |

Both tools are read-only. The intended chain is `get_crypto_libraries`, then
`list_crypto_library_devices` for the family or version bucket of interest. They take **strict
input**: an unknown family, a wrong JSON type, an over-long string or a `limit` outside 1 to 1000
is refused with an invalid-params error, where the REST routes clamp `limit` instead. Both return
the same JSON as the REST `data` object, so a result can be compared across surfaces. See
[mcp.md](mcp.md) for the tool table.

## Audit

Every read that serves data is written to the audit log (see [audit-log.md](audit-log.md)):

| Verb | Written when |
|---|---|
| `crypto.libraries.view` | The family summary is served (REST route and `/crypto` page). The MCP tool writes `mcp.get_crypto_libraries`. |
| `crypto.libraries.devices` | A page of one family's devices is served (REST route and the drill). The MCP tool writes `mcp.list_crypto_library_devices`. |

Every row, on every surface, carries one detail key set:
`cid=<correlation id> tv=<table_version> family=<family or all> rows=<n> src=<catalogue|live>`
(`src` is where the package names came from, see "How fresh the package names are"), plus
`page=continuation` on a page reached with a cursor, so a cursor walk cannot go unrecorded
(`rows` is the number of families for the summary and of package rows for the drill). The
filters are in the audit target. The MCP rows carry no `cid=` key (the MCP path mints no
correlation id) and put the filters in the detail as `target=...`. A failed read writes a
`failure` row with `cid=... tv=... store degraded` (the inventory read failed) or
`cid=... tv=... capacity in use` (the read was refused by the capacity bound).

Auditing is **set-and-proceed**: if the audit row cannot be written, the data is still served,
and the response says so. On REST the body carries `"audit_persisted": false` and the response has
the header `Sec-Audit-Failed: true`; the MCP tools set `audit_persisted: false` in their result.
On the `/crypto` page a lost audit row is invisible to the operator (an HTMX swap cannot carry
the header or the flag): the server still records the failure, and the REST and MCP surfaces are
where it is reported to the caller. A refusal at the access gate (no `Inventory:Read` grant,
authorization store unavailable) is written by the gate itself as `auth.fleet_read_required` and
is not duplicated here.

## Failure behavior

Reads are authoritative. When the inventory store cannot be read, the answer is an error and never
an empty list, because an empty list would read as "no library installed".

- **REST:** `503` with the A4 error envelope and `retry_after_ms: 5000`, in two distinct causes
  with their own message: `crypto library read degraded` (the inventory read failed or ran past
  its 5 s bound) and `crypto read capacity in use; retry` (the server's bound on concurrent
  `/crypto` reads is full, see "Capacity" below). Bad parameters (an
  unknown family, a parameter repeated with differing values, a `limit` that is not a plain
  decimal integer (including an out-of-range or signed form such as `+5`), a cursor issued for a
  different filter set, `table_version` or names source, over-long or non-UTF-8 values) are `400`.
- **MCP:** a retryable internal error carrying the store-fault retry hint, worded per cause as
  on REST; bad arguments are invalid-params.
- **Dashboard fragments** answer HTTP 200 so the page can show the problem in place, except a
  server misconfiguration (an unwired access gate), which is a `503`: an "unavailable" banner
  with a **Retry** button for a store failure or an unreadable authorization store, and a plain
  notice box for a refused permission or a bad parameter. On a **Load more** page the banner or
  notice is a single table row, so the list above it stays intact.

**Capacity.** Each server process lets at most two `/crypto` store reads run at once (summary and
drill share the bound; with several replicas the fleet-wide ceiling is two times the replica
count), because a summary read can hold a database connection for as long as the
statement timeout and the connection pool is shared with authorization, audit and ingest. A read
that arrives while both slots are in use is refused at once, without touching the database: REST
`503` with `retry_after_ms`, a retryable MCP error, and the "temporarily unavailable" banner or
row on the page. It is a shed, not a fault; retry after the hint. An agentic worker should
serialise its `list_crypto_library_devices` calls (one page at a time, following `next_cursor`)
rather than fan them out: parallel drills compete for the same two slots.

**Diagnosing a degrade.** A banner or `503` here has one of two causes, told apart by the
message, the audit row and the counter (the third row is how to tell a catalogue problem from the first):

| Cause | `503` message | Audit `failure` detail | Counter `yuzu_inventory_read_degrade_total{source="installed_software"}` |
|---|---|---|---|
| The inventory read failed or ran past its 5 s bound | `crypto library read degraded` | `store degraded` | `reason` is `store_not_open`, `pool_acquire_timeout` or `query_error` |
| The concurrent-read bound was full | `crypto read capacity in use; retry` | `capacity in use` | `reason="admission_full"` |
| The same `crypto library read degraded` while `YuzuInventoryCatalogRollupStale` or `YuzuInventoryCatalogRollupFailing` is firing | `crypto library read degraded` | `store degraded` | `reason="query_error"` (the 5 s statement timeout) |

The last row most likely means the live name scan exceeded its 5 s bound: there are too many
distinct package names for a live read, and retrying will not help (a Postgres overload also
yields `query_error`, so check the database load too). Above about 2.7 million installed-package
rows this is expected until the catalogue rollup is made incremental. Fix the catalogue refresh
(the alerts say how) or the flood of distinct names; `/crypto` recovers on its own once the
catalogue is fresh again. The two rollup alerts compare the catalogue stamp with the replica's
clock, so they can stay silent if the database clock stepped back by more than 5 minutes: compare
`names_as_of` with the database `now()` before trusting a silent alert.
On the dashboard page and its **Load more** row the capacity shed reads "Temporarily busy: two
reads are already running on this server; retry shortly" and a store fault reads "The inventory
store could not be read"; REST and MCP use the same `503` message per cause.

Every such response also writes a `failure` row for the `crypto.libraries.*` verb in the audit
log. A banner or `503` that comes
from the authorization store instead moves `yuzu_server_rbac_read_degrade_total`, not the
inventory counter, and writes no `crypto.libraries.*` failure row (the gate writes its own).

## Pilot expectations

Before showing this page to a stakeholder, check how many devices are reporting (the first KPI
tile) against the size of the fleet, and read the per-OS coverage caveat: Linux gives the most
complete package picture, macOS shows Homebrew packages only, and Windows shows only installers
registered in the registry. "One family found" therefore reads as "one family found in the
package evidence", not as "this is the only library in use". A statically linked or vendored
copy is the usual reason a known library does not appear. Component-level inventory that closes
that gap is planned (roadmap Issue 18.7, ADR-0028).

If an access-audit row cannot be written, the page still shows the data and the operator cannot
see that (REST and MCP report it in the response); watch `yuzu_server_audit_emit_failed_total` on
the server.

**How fresh the package names are.** The list of package NAMES that the table is matched against
has two sources, chosen on every read. While the hourly software-catalogue refresh is **fresh**
(it has run, and started at most two hours ago) the names come from it: `names_source` is
`catalogue` and `names_as_of` is the refresh time (epoch seconds in the API; "Package names as of
..." on the page). A package name first reported after that time appears after the next hourly
refresh. When the catalogue has never been built (a new server, or an upgrade), or is older than
two hours, the names are read **live** from the installed-software inventory instead:
`names_source` is `live`, `names_as_of` is `null` and the page says "Package names read live".
Either way counts and versions for the listed names are live: a device that reports an
already-listed name is counted at once. The two sources return the same answer for the same data;
only a name first reported since the last refresh differs. "Fresh" means the refresh **started** at
most two hours ago; a stamp more than five minutes in the future (a clock fault) counts as stale and
the names are read live. A drill cursor records the names source it was issued under. One change
between pages is refused: a walk that STARTED on live names and whose next page finds the shared
catalogue in use (it became fresh in between), because the catalogue may lack a name first reported
after its refresh, so rows of a name the walk has already listed could be skipped. That
continuation is a `400` that says to restart the walk without a cursor (a fragment shows the same
text as a note; MCP answers invalid-params). Every other change continues: a newer catalogue
refresh only adds names, and a switch from the catalogue to live names lists every name. A walk is
therefore refused at most once, because the restarted walk is on the catalogue. One residual: on a
continuing walk, a name that first appears in the new source and sorts before the cursor position
is not listed on that walk; restart to see it. A deny-all answer (an empty scope) reads nothing, so
it reports `names_source` `live` and `names_as_of` `null` (and its page still carries the
names-source note); a walk whose scope empties mid-walk continues and ends on an empty page. An old
catalogue is the signal to look at the rollup alerts `YuzuInventoryCatalogRollupStale` (a catalogue
was built, and its last success is more than two hours old) and `YuzuInventoryCatalogRollupFailing`
(the catalogue was never built, or the refresh keeps failing); both descriptions say `/crypto`
reads its package names live if the shared catalogue is also older than two hours (the alerts are
per replica; the catalogue is shared). There is no `503` for an unbuilt catalogue any more.

**Scale.** The two sources have different envelopes, measured on the reference host (about
+/-30 percent, host load 3 to 10). The catalogue path follows the number of DISTINCT package names
in the fleet, not the number of devices: from 30,000 to 1.03 million distinct names the summary
takes about 0.5 to 3.3 s and a family drill about 7 ms to 1.9 s. The live path does one index
probe per distinct name (about 28 to 36 microseconds each): at 15 million installed-package rows
with 30,000 distinct names the summary takes about 1.7 to 2.2 s and a family drill about 0.7 to
1.4 s (the skip-scan alone is 0.9 to 1.2 s), and the live path passes the 5 s statement bound at
about 140,000 to 250,000 distinct names, depending on host and load.

The catalogue refresh itself does not finish within its own 60 s statement cap at scale: 219 to
241 s is the UNCAPPED duration of the refresh's grouping statement (GROUPING SETS), measured at 3
million and at 15 million rows, and the 60 s cap is crossed at about 2.7 million rows (the
crossing is in `docs/user-manual/inventory.md`). On a fleet above about 2.7 million
installed-package rows the catalogue is therefore never built (or goes stale) until the rollup is
made incremental, and `/crypto` then reads its package names LIVE on every call. The worst case
is a stale or unbuilt catalogue on a fleet with more than about 140,000 to 250,000 distinct
package names: the read exceeds its 5 s bound and is a bounded `503` (`crypto library read
degraded`), never a hang and never an empty answer.

**Capacity note.** Each process allows two concurrent reads, so it cannot exhaust the connection
pool; at two concurrent live summaries the p50 is about 2.15 s and the p95 about 2.42 s with no
timeouts. The ceiling is per process: with about 8 replicas against one Postgres, 16 concurrent
live reads, about half time out, so size the replica count and the catalogue refresh together.

## Roadmap

The following are planned and not yet available. No dates are committed.

- A fleet certificate inventory with full X.509 fields (the endpoint `certificates` plugin
  already lists system store certificates per device; a fleet-wide view is planned).
- SSH key inventory (host keys and keys at rest) and SSH login evidence.
- Protocol and configuration settings (for example TLS and SSH daemon settings).
- A cryptographic bill of materials (CBOM) export.

These will be shown on this page alongside the library view, under the same permission and
audit model unless stated otherwise at release.

## Related documentation

- [Inventory](inventory.md): the installed-software data this page reads
- [REST API: Crypto](rest-api.md#crypto)
- [MCP tools](mcp.md)
- [Audit log](audit-log.md)
- [Device management](device-management.md)
