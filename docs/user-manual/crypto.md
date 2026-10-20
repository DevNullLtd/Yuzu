# Crypto — Cryptographic Library Inventory

The `/crypto` dashboard shows which cryptographic libraries are installed across the fleet and at
which versions, and counts the certificates issued by Yuzu's own internal CA (see
[The dashboard](#the-dashboard)). It answers questions such as "which devices still carry OpenSSL 1.1?" or "where
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
`/crypto` directly. Any signed-in operator can open the page and arrange their own dashboard;
each widget then needs its own permission:

- the **library widgets** need **`Inventory:Read`**, the same permission that gates the
  [`/software` and `/inventory` pages](inventory.md);
- the **Yuzu-issued certificate counts** also need **`Inventory:Read`**, but only an
  **unconfined** view of the fleet (ADR-0070 R2). They count Yuzu's whole internal CA and have no
  device dimension, so they cannot be narrowed to a scope. A caller whose view is confined (by
  management group or by a service-scoped token) gets the note "Yuzu-issued certificate figures
  are not available to this account: its view of the fleet is confined, and these are fleet-wide
  figures." in place of every count, never a smaller number. The counts disclose how many agents
  and gateways Yuzu has enrolled and how that changes over time; the ruling accepts that for
  unconfined `Inventory:Read` holders;
- the **certificates behind a Yuzu-issued count** (the drill) need **`Security:Read`**, the same
  permission as `GET /api/v1/ca/issued` ([PKI](server-admin.md)), and are withheld from a
  confined caller in the same way. A caller who can see a count but does not hold
  `Security:Read` sees the count, and a click shows "the certificate list needs Security:Read"
  in the drill panel. The withholding covers the drill and the **filtered** form of
  `GET /api/v1/ca/issued` / `list_issued_certs` only: the unfiltered `GET /api/v1/ca/issued`
  is unchanged and still returns every Yuzu-issued certificate to any `Security:Read` holder,
  a confined one included (owner decision; the same rows, without the dashboard's windows).

A widget whose permission you do not hold is drawn as a card that says "not available to this
account (`Inventory:Read` required)", not as an error.

The rest of this section applies to the **library widgets** only; the Yuzu-issued counts are
never confined, they are either shown whole or withheld.

- **Management-group confinement applies.** A caller confined to management groups sees only
  the devices in their scope, and every figure on the page (family counts, the devices-reporting
  denominator, version buckets and the device drill) is computed over that scope, not filtered
  afterwards. Two operators can legitimately see different counts.
- **Service-scoped API tokens.** While RBAC enforcement is off (the default), a service-scoped
  token is refused with a 403 on these routes: the stricter default, not an error. With RBAC
  enforcement on, the token is admitted within the `ITServiceOwner` ceiling and sees only the
  devices tagged with its IT service, by the same scope mechanism. This surface admits such a
  token where the `/software` catalogue refuses it, because the catalogue is an unfilterable
  rollup across the whole fleet while every figure here is computed over the caller's scope.
- A caller with no `Inventory:Read` grant gets a 403 on the REST routes, and the page shows a
  notice instead of data. The refusal is audited by the access gate (see [Audit](#audit)). When the authorization store
  itself cannot be read the page shows the same "unavailable" banner as an inventory outage, not
  a permission notice.

**Data classification.** The data is machine-scope and device-attributable: it names the devices
that carry a library, so it is treated as device inventory for works-council purposes (see
[enterprise readiness §3.5](../enterprise-readiness-soc2-first-customer.md)). It contains no user
content. Rows are erased with the device by the decommission cascade, like the rest of the
installed-software inventory.

## The dashboard

The page is a grid of widgets that each operator arranges for themselves. Every widget shows its
title, the **criterion** it counts in words (for example "Status active, notAfter from as_of
through as_of + 30 days (valid through notAfter, inclusive)"), and, for the certificate widgets,
a **Yuzu-issued certificates** label. Above the Yuzu-issued widgets, and in an empty dashboard,
the page states their scope: "Counts certificates Yuzu's own CA issued only (agent, server,
gateway, HTTPS and code-signing); certificates on your devices are not covered." Numbers are shown in the page's neutral text
colour: no widget grades a value with a colour, an icon or a risk order, and none uses words such
as "at risk" or "weak" (ADR-0070 D10, D13).

**Arranging it.** Use **Add widget** (the list groups the widgets not already on your grid under
"Crypto libraries" and "Yuzu-issued certificates"; a widget you cannot read is listed but
disabled), the **×** on a card to remove it, the **←** / **→** buttons to move it, and **Reset
to default** to go back to the default layout. Each change is saved at once, server-side, and
only for you: the layout is stored per operator (keyed by your user name) in Postgres
(ADR-0071), so it follows you to another browser and never changes anyone else's page. Saving
uses `PUT /api/v1/crypto/dashboard/layout`; if it fails the page shows "The layout was not saved:
..." above the grid and keeps the old layout. A layout holds at most 64 widgets.

- **Two tabs, one layout.** Every saved layout has a **version** that goes up by one on each
  save. The page sends the version it drew, and a save made after another tab or client saved
  first is refused rather than overwriting it: the page says "The layout changed in another tab —
  reloaded" and redraws the newer layout, so make your change again.
- **Widgets from another server version.** While replicas run different versions (a rolling
  upgrade or a rollback), a layout can hold widget ids this server does not know. They are kept,
  in their place after yours, on every save, and are not drawn; the toolbar says "N widgets from
  another server version kept but not shown." They reappear on a server that knows them.
- **Save outcome unknown.** If the database connection drops after a save was sent, the server
  cannot tell whether it was stored, and says "save outcome unknown — reload to check". Reload the
  page to see which layout was kept.
- **Reset to default** saves the default list. The toolbar then says "Showing the default layout."
  again, unless widgets from another server version are kept alongside it.

When you have never saved a layout you see the default, and the toolbar says "Showing the default
layout." The default is: Devices reporting inventory, Devices with a crypto library, Library
families found, Devices by library family, Crypto libraries, Yuzu-issued certificates: active,
expiring within 30 days, revoked in the last 30 days, and issued per week.

When the layout cannot be read the page shows a "Crypto dashboard unavailable" banner with
**Retry**, never the default in place of a saved layout. The banner names the cause: "Busy: too
many crypto reads are in progress on this server; retry shortly." or "Database degraded: your
saved widget layout could not be read". A stored layout the server cannot read at all (a damaged
row) is not retried: the page says "Your saved dashboard layout cannot be read" and offers
**Reset to default**, which replaces it.

If the layout store could not be opened when the server started (for example the database role
cannot create its schema), the server still starts and everything else works (ADR-0071). The page
then draws the default layout, read-only, under the notice "Saved layouts are unavailable on this
server": nobody's saved layout is shown or changed, and saves are refused until the server is
restarted with the store fixed. This is not retried automatically.

**Loading.** The dashboard draws every card at once from one read of the library summary and one
read of the Yuzu-issued counts, so all Yuzu-issued cards show the same `as_of`. A card that fails
shows its own "unavailable" banner with **Retry**, which reloads just that card; the rest of the
grid is unaffected.

**Drilling down.** Every widget is clickable, and the drill opens in the one panel below the grid:

- a library number opens the families table; a family row, a version chip or a bar of
  **Devices by library family** opens that family's (or bucket's) devices below the row, see
  [Devices drill](#devices-drill);
- a Yuzu-issued number opens the certificates it counts, and a point on a per-week chart opens
  the certificates issued (or revoked) that ISO week; a revoked count opens one reason bucket.
  The list shows serial, subject, purpose, issued, not after, status, revoked at and the
  recorded revocation reason, 100 at a time with **Load more certificates**, and names the
  criterion, the total and `as_of` above the table. The list is read at the card's `as_of`, and
  every **Load more** page keeps it, so the pages add up to the card's figure (see
  [Pinned `as_of`](#pinned-as_of-and-keyset-paging)). It needs `Security:Read`.

### Widgets

| Widget id | Title | Criterion (shown on the card) | Kind | Permission |
|---|---|---|---|---|
| `lib.devices_reporting` | Devices reporting inventory | Devices in your scope with an installed-software inventory report | number | `Inventory:Read` |
| `lib.devices_with_library` | Devices with a crypto library | Distinct devices with at least one package matching a library family in the curated table | number | `Inventory:Read` |
| `lib.families_matched` | Library families found | Library families with at least one matching device | number | `Inventory:Read` |
| `lib.families_table` | Crypto libraries | Each family's distinct device count and its version buckets | table | `Inventory:Read` |
| `lib.devices_by_family` | Devices by library family | Distinct devices carrying any package of each family | bar chart | `Inventory:Read` |
| `ca.active` | Yuzu-issued certificates: active | Status active, issued on or before as_of, notAfter on or after as_of (valid through notAfter, inclusive) | number | `Inventory:Read`, unconfined |
| `ca.expiring_3d`, `_7d`, `_14d`, `_21d`, `_30d`, `_60d` | Yuzu-issued: expiring within N days | Status active, notAfter from as_of through as_of + N days (valid through notAfter, inclusive) | number | `Inventory:Read`, unconfined |
| `ca.expired_7d`, `_30d`, `_60d`, `_90d` | Yuzu-issued: expired in the last N days | Status active, notAfter from as_of - N days up to, not including, as_of | number | `Inventory:Read`, unconfined |
| `ca.revoked_7d`, `_30d`, `_60d`, `_90d` | Yuzu-issued: revoked in the last N days | Revoked after as_of - N days and on or before as_of, counted separately by recorded reason: superseded, unpublished, other | number (three counts) | `Inventory:Read`, unconfined |
| `ca.issued_7d` | Yuzu-issued: issued in the last 7 days | Issued after as_of - 7 days and on or before as_of, excluding unpublished (recorded, never delivered) | number | `Inventory:Read`, unconfined |
| `ca.issued_per_week` | Yuzu-issued: issued per week | Issued in each of the last 52 ISO weeks (UTC, Monday start), excluding unpublished (recorded, never delivered); the current week is partial | line chart | `Inventory:Read`, unconfined |
| `ca.revoked_per_week` | Yuzu-issued: revoked per week | Revoked in each of the last 52 ISO weeks (UTC, Monday start), counted separately by recorded reason: superseded, unpublished, other; the current week is partial | line chart (three series) | `Inventory:Read`, unconfined |

"Unconfined" means the counts are withheld from a caller whose view is confined (see
[Access](#access)). The certificate list behind every Yuzu-issued widget needs `Security:Read`.

The library widgets read the same family summary as the rest of this page, over your visible
scope, and keep every notice described below (the evidence caveat, the truncation note, the
package-names-as-of note, the "not proof" wording when nothing matches).

### Yuzu-issued certificates

These widgets count the certificates **Yuzu's own internal CA** issued: agent, server, gateway,
HTTPS and code-signing certificates alike, with no filter by purpose (see [PKI](server-admin.md)). They are not the certificates found on your fleet's
devices: those are never read from Yuzu's CA store (ADR-0070 D6), and fleet certificate widgets
are not available yet. "Expiring within 30 days: 0" therefore says nothing about the
certificates on your devices.

Every count is computed when it is read, against `as_of`: the database clock (Postgres `now()`)
in whole seconds, read by the same SQL statement as every comparison it governs and returned by
it (ADR-0070 R4, R5). The card shows it ("as of 2026-10-19 08:00 UTC"). Nothing is stored as a
verdict, and nothing is cached: every call (the dashboard, REST and MCP alike) reads the CA table
at request time. Repeated reads are bounded by the per-process `/crypto` read admission bound
(a call over it is refused as busy, `503` with a retry hint), not by a cached count. The time a
certificate was
issued or revoked is recorded from the clock of the server that issued or revoked it, so a window
edge is accurate only to the servers' clock synchronisation (R4); every response says so.

The exact criteria, all times in epoch seconds. A certificate is valid through its `not_after`,
inclusive (RFC 5280). Windows are cumulative: a certificate expiring in 5 days is in the 7-day
window and every longer one.

| Kind | Counts a certificate when |
|---|---|
| active | status is `active`, `issued_at <= as_of` and `not_after >= as_of` (R10) |
| expiring within N days | it is active (above) and `not_after <= as_of + N days` (R14) |
| expired in the last N days | status is `active` and `as_of - N days <= not_after < as_of` (R11) |
| revoked in the last N days | `as_of - N days < revoked_at <= as_of`, counted in one of three buckets by its recorded reason |
| issued in the last 7 days | `as_of - 7 days < issued_at <= as_of`, and its reason is not `unpublished` |
| issued / revoked per week | `issued_at` (or `revoked_at`) is in that ISO week, `[Monday 00:00 UTC, next Monday)`, and no later than `as_of`; issued excludes `unpublished` |

- **Three revocation buckets** (D13). `superseded` (the certificate was replaced by a same-key
  successor) and `unpublished` (it was recorded but never delivered) are bookkeeping markers
  Yuzu writes itself, not compromise. Every other reason, including an operator-typed reason that
  collides with one of those words (stored as `operator-supplied: <text>`), is counted under
  `other`. The three are never added together or labelled.
- **Expired means it ran out while still active** (R11). A revoked certificate, of any reason,
  is counted only in the revoked windows, never as expired or expiring.
- **Unpublished certificates are not counted as issued**: they were never delivered. They are
  still counted when revoked, in the `unpublished` bucket.
- **The per-week series** covers 52 ISO 8601 weeks in UTC, oldest first, labelled by ISO year and
  week (`2026-W43`; the series crosses a year boundary, including a 53-week year, as the
  calendar does). The last week is the one containing `as_of`; it is partial, counts only up to
  `as_of`, and is marked "(partial)" on the chart and `partial: true` in the API. Weeks with none
  show 0.

The windows are a fixed, versioned set, **`crypto_widget_windows_v1`** (the `rule_set_version`
on every count): active; expiring 3, 7, 14, 21, 30 and 60 days; expired 7, 30, 60 and 90 days;
revoked 7, 30, 60 and 90 days in three reason buckets; issued 7 days; 52 weekly buckets with the
current, partial week included. It is the first released definition of the set. A different
window is not a setting: changing the set is a reviewed change to ADR-0070 D13 and bumps the
version.

**Recomputing a count.** Each count is defined over the rows `GET /api/v1/ca/issued` serves.
With `Security:Read`, list the rows behind a count with the same `kind`, `days`, `week` or
`bucket` and the count's `as_of` (`GET /api/v1/ca/issued?kind=...&as_of=...`, or the drill): its
`filter.total` equals the count. Without `Security:Read` you can see the counts but not
recompute them (R8).

### Pinned `as_of` and keyset paging

A drill or a paged certificate list carries the `as_of` of the card or first page that produced
it. Every further page is fetched with a **keyset cursor**: **Load more** in the drill, and
`next_cursor` passed back as `cursor` on REST (`GET /api/v1/ca/issued`) and MCP
(`list_issued_certs`). The cursor is opaque; it carries the position of the last certificate
served (its sort key and serial) and the walk's `as_of`, and it is bound to the list's `kind`,
`days`, `week` and `bucket`. The next page is the certificates strictly after that position, in
the list's order, at the same `as_of`. `next_cursor` is `null` on the last page. The filtered
list takes no `offset`: one is refused (`400` on REST, invalid-params on MCP) naming it, and so
is a cursor that is malformed, edited, or issued for a different filter ("start the list again
without a cursor").

A paged walk is therefore measured against one point in time, and no certificate is skipped or
listed twice because the selection changed between pages: a certificate revoked after page one
was served leaves the active list, but the next page still starts after the last certificate
page one showed (an offset would have shifted by one and skipped a row). While no certificate is
revoked during the walk, the drill total equals the card's count.

A pinned `as_of` (passed as `as_of`, or carried in a cursor) is accepted from 7 days before the
**database clock** up to 5 minutes after it, checked in the read's own transaction, never
against the serving replica's clock. An older one is refused naming `as_of`: start the list
again without it.

Pinning fixes the time, not the rows: the list reads each certificate's current status. A
certificate revoked after the pinned `as_of` drops out of the active, expiring and expired lists
(its status is no longer `active`) and is not in the revoked lists either (its revocation time is
after `as_of`), so the drill total can then be lower than the card. Reload the card for a fresh
`as_of`.

## Library widgets in detail

The library widgets of an operator who sees the whole fleet draw from one fleet-wide library
summary, which each server process reads at most once a minute and shares between callers (the
dashboard, `GET /api/v1/crypto/libraries` and MCP `get_crypto_libraries` alike). A count can
therefore be up to 60 seconds old. A filtered summary, or one for an operator whose view is
confined to some devices, is read for that request and never shared. The Yuzu-issued counts are
never shared either (see [Yuzu-issued certificates](#yuzu-issued-certificates)).

### KPI strip

The three library number widgets:

| Tile | Meaning |
|---|---|
| Devices reporting inventory | Devices in your visible scope that have an installed-software report. This is the denominator: a device that has never reported cannot be shown to carry or not carry a library. The denominator is floored at the numerator, so it is never smaller than the devices-with-a-library figure. |
| Devices with a crypto library | Distinct devices in scope with at least one package matching any family. A device carrying `libssl3` and `libgnutls30` counts once here. |
| Library families found | Number of curated families with at least one matching device, shown against the size of the table ("of 12 in the table"). |

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
  shows at most 8 package names. A bucket with more than 8 sets `package_names_truncated` in the
  API.
- The whole summary has a byte budget of about 256 KiB, plus at most one first bucket per family
  (worst case about 300 KB). When one agent (or many) reports so many versions
  that the budget would be exceeded, further buckets of the most crowded families are dropped
  (every family keeps at least its most-installed bucket, which is why the budget can be exceeded
  by those twelve buckets), those families are flagged
  `versions_truncated` and the summary sets `result_truncated`. Buckets are kept most-installed
  first, so a flood of one-device versions cannot push the common versions out.
- If the store's row ceiling (2,000 version rows per read) is reached, the page says so and the
  API sets `result_truncated` and flags **every** family `versions_truncated`, because the read
  cannot tell which families lost rows. Some of those families may in fact be complete.

In every case the family device counts and the coverage figures are still complete; only some
version rows are missing.

### Devices drill

Click a family row (or a bar of **Devices by library family**) to load the devices carrying it
into the drill panel, or click a version chip to narrow to that exact (version, ecosystem)
bucket. Each row is one matching package on one device:

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

The family summary carries this notice whenever it shows data, including when no family
matched. The "unavailable" banners and the permission and parameter notices do not repeat it:

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
**`table_version` 3**, returned in every summary and device-drill response. A client that stores
results can use it to tell which mapping produced them; the number is bumped on any edit to the
table. A device-drill cursor is bound to it: a cursor issued under another `table_version` is
refused (the walk restarts without a cursor), so a walk can never silently straddle two mappings.

**How a name is matched.** The package name is lowercased (ASCII) and compared with each rule
of the table. A rule is either *exact* (the whole name must equal the value) or *prefix* (the
name must start with the value). The first matching rule wins, and the table is built so that no
package name matches two families. Matching is on the package name only, never on the version,
publisher or file contents. A prefix rule also matches the related packages that share the
prefix (for example `libssl3t64` matches the `libssl3` rule), because the inventory records
package presence, not what is loaded in memory.

| Family id | Display name | Exact names | Prefixes |
|---|---|---|---|
| `openssl` | OpenSSL | `compat-openssl10`, `compat-openssl11`, `libopenssl1_1`, `libopenssl3`, `libssl-dev`, `libssl-doc`, `openssl`, `openssl-1.1`, `openssl-1_1`, `openssl-3`, `openssl-libs`, `openssl1.1`, `openssl3`, `openssl3-libs` | `libcrypto0`, `libcrypto1`, `libcrypto3`, `libcrypto4`, `libssl0`, `libssl1`, `libssl3`, `libssl4`, `openssl@` (Homebrew) |
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

**Windows installer builds of OpenSSL are not matched.** The table has no rule for the display
name a Windows OpenSSL installer registers in the Uninstall key, because no real `DisplayName`
capture has been recorded to base one on. Until one is, OpenSSL installed on Windows through such
an installer does not appear on this page.

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

Everything on the page is available to agentic workers with the same data and the same
permissions, through REST and MCP.

### REST

| Route | Purpose |
|---|---|
| `GET /api/v1/crypto/libraries` | Family summary: devices per family, version buckets, coverage. Optional `family`, `ecosystem`. |
| `GET /api/v1/crypto/libraries/devices` | One family's devices, paged. Required `family`; optional `version`, `ecosystem`, `cursor`, `limit` (1 to 1000, default 100). The response carries `table_version`. |
| `GET /api/v1/crypto/cbom` | The same summary as a CycloneDX 1.7 CBOM. Optional `family`, `ecosystem`. See "Exporting a CBOM". |
| `GET /api/v1/crypto/widgets` | The widget catalogue, the window set and, per widget, whether you can read it (`available`, `availability`) and, for Yuzu-issued widgets, whether you can open the certificate list (`drill_available`). Authentication only; not audited. |
| `GET /api/v1/crypto/dashboard/layout` | Your own layout (`widgets`, `is_default`, `version`, `preserved_unknown`). Authentication only; refused to service-scoped tokens. The dashboard page answers such a token, or an MCP token whose tier does not allow the read, with the default layout, read-only, and never reads or shows the minting operator's saved layout. |
| `PUT /api/v1/crypto/dashboard/layout` | Replace your own layout: body `{"widgets":[ids], "expected_version": n}`, at most 64 catalogue ids, no repeats; `expected_version` names the version you read (omit it only for a first save). A stale version, or none while a layout is stored, is `409`. Same-site browser writes only; audited `crypto.dashboard.layout.update`. |
| `GET /api/v1/crypto/ca/stats` | Every Yuzu-issued count against one `as_of`. `Inventory:Read`, withheld from a confined caller (`403`). |
| `GET /api/v1/ca/issued?kind=...` | The Yuzu-issued certificates behind one count: `kind` (required in this form), `days`, `week`, `bucket`, `as_of`, `limit` (1 to 500, default 100), `cursor` (the previous page's `next_cursor`; no `offset`). `Security:Read`, withheld from a confined caller. Without any of `kind`, `days`, `week`, `bucket`, `as_of` or `cursor` the route lists certificates exactly as before, `offset` paging included (see [PKI](server-admin.md)). That unfiltered list is unchanged by this feature and still returns every row to any `Security:Read` holder, a confined one included: only the filtered form is withheld from a confined caller. |

`version` and `ecosystem` are matched **exactly**, and a parameter that is present but empty is
the exact empty value (some rows genuinely carry no version or no ecosystem); an absent parameter
means any. Both accept up to 1,024 bytes, the same bound as the inventory ingest, so every bucket
the summary shows can be drilled. A repeated parameter with differing values is a `400`. On REST
`ecosystem` is free text: a value outside the published ecosystems (see MCP below) is not refused
and matches no rows.

The two library routes and the library fragments the page loads (and likewise the dashboard,
widget and Yuzu-issued certificate fragments) answer
`Cache-Control: no-store, private` and `Vary: Authorization, Cookie, X-Yuzu-Token`, because the answer depends on the caller's
scope and must not be served from a shared cache.

Full parameters, response shapes and error tables are in [rest-api.md](rest-api.md#crypto).

### MCP

| Tool | Mirrors | Notes |
|---|---|---|
| `get_crypto_libraries` | `GET /api/v1/crypto/libraries` | Args `family` (one of the twelve family ids) and `ecosystem` (one of the published ecosystems; `""` selects rows with no ecosystem, omit for any), both optional. |
| `list_crypto_library_devices` | `GET /api/v1/crypto/libraries/devices` | Args `family` (required), `version` (at most 1,024 bytes), `ecosystem` (one of the published ecosystems), `cursor` (at most 2048 bytes), `limit` (1 to 1000). |
| `export_crypto_cbom` | `GET /api/v1/crypto/cbom` | Args `family` and `ecosystem`, both optional, as for `get_crypto_libraries`. Returns the CycloneDX 1.7 BOM as a string in `bom`. See "Exporting a CBOM". |
| `list_crypto_widgets` | `GET /api/v1/crypto/widgets` | No args. |
| `get_crypto_dashboard_layout` / `set_crypto_dashboard_layout` | `GET` / `PUT /api/v1/crypto/dashboard/layout` | The calling principal's own layout; `set` takes `widgets` and optional `expected_version`. |
| `get_crypto_ca_stats` | `GET /api/v1/crypto/ca/stats` | No args. |
| `list_issued_certs` | `GET /api/v1/ca/issued` | With any of `kind`, `days`, `week`, `bucket`, `as_of` or `cursor` it lists the certificates behind one count, paged by `next_cursor`; without them it answers as before (`offset` paging). |

The published ecosystems are the closed list the software catalogue tools use: `""`, `rpm`,
`deb`, `apk`, `pacman`, `snap`, `flatpak`, `windows`, `macos`, `macos_pkgutil`, `brew`,
`optional_feature` and `msi`.

Every tool here is read-only except `set_crypto_dashboard_layout`, which replaces the caller's
own layout and is annotated destructive for that reason (it overwrites the previous layout; no
data, permission or other operator is touched).

- **Libraries.** The intended chain is `get_crypto_libraries`, then `list_crypto_library_devices`
  for the family or version bucket of interest. Both take **strict input**, refused with an
  invalid-params error: an `arguments` value that is not a JSON object ("arguments must be a JSON
  object"), an unknown family, an ecosystem outside the list above ("ecosystem is not one of the
  published ecosystems"), a wrong JSON type, an over-long string or a `limit` outside 1 to 1000.
  The REST routes clamp `limit` and accept any `ecosystem` instead. Both return the same JSON as
  the REST `data` object, so a result can be compared across surfaces. `export_crypto_cbom` is
  strict in the same way and also refuses any key other than `family` and `ecosystem`.
- **Yuzu-issued counts.** The chain is `get_crypto_ca_stats`, then, with `Security:Read`,
  `list_issued_certs` with a count's `kind`, `days` (or `week`), `bucket` and `as_of`, paging by
  passing `next_cursor` back as `cursor` (it carries the `as_of`; `null` on the last page). In
  this filtered form **both REST and MCP are strict**: an unknown kind or bucket, a `days` outside
  the kind's set, a `days`, `week` or `bucket` on a kind that does not take it, a `limit` outside
  1 to 500, any `offset`, a malformed, edited or other-filter `cursor`, or an `as_of` outside the
  accepted range (measured on the database clock) is refused (`400` on REST, invalid-params on
  MCP), with a message naming the parameter. The unfiltered form keeps its old behaviour: REST and MCP clamp `limit` to 1 to 1000.
- **Layouts.** `get_crypto_dashboard_layout` returns `version`; pass it as `expected_version` to
  `set_crypto_dashboard_layout` so a save is refused when the layout changed meanwhile (a
  non-retryable invalid-params error: read again, then save). `expected_version` `0` means "only
  if nothing is saved". Omit it only for a first save: without it the save succeeds only when
  nothing is stored, and over a stored layout it is the same non-retryable conflict naming the
  stored version.
- **`available` is for drawing only.** On REST and MCP alike, `available` and `drill_available`
  say whether the caller would be admitted now, so a client can decide what to draw. They grant
  nothing: every data read keeps its own gate.

See [mcp.md](mcp.md) for the tool table.

## Exporting a CBOM

This is a [CycloneDX](https://cyclonedx.org/) **1.7** bill of the cryptographic-library packages
Yuzu sees installed (library components). It does not yet describe algorithms, certificates, keys
or protocols (capability map 41.2 to 41.5).

`GET /api/v1/crypto/cbom` (MCP `export_crypto_cbom`) returns the same data as the family summary
as a CycloneDX 1.7 JSON bill of materials, so a CBOM or SBOM tool
can ingest it. It adds no collection: it re-shapes what the page already shows, behind the same
`Inventory:Read` gate, the same confinement (a confined caller exports only their visible
devices), the same read-capacity bound and the same `503 + retry_after_ms` on a degraded read.
The REST response is the BOM itself (not wrapped in a `data` object) with
`Content-Type: application/vnd.cyclonedx+json; version=1.7`, `Cache-Control: no-store, private`
and `Vary: Authorization, Cookie, X-Yuzu-Token`. The MCP tool returns the BOM as a string in its
`bom` field, with `components` (a count) and `result_truncated` beside it.

**Size.** A large fleet can produce a large document: roughly 1 MiB over REST and up to about
2.3 MiB inside the MCP result, in the worst case. Prefer the REST route for a full export; an
agentic worker that only needs a sample should pass `family` or `ecosystem`. The export shares the
two concurrent `/crypto` read slots with the dashboard (see "Capacity" below), so a burst of
exports can make the page answer "temporarily busy".

**What is in it.**

- One `component` per (family, version, ecosystem) bucket, always `"type": "library"` (an
  installed package matched by name), with the family name as `name`, the bucket's `version`
  (omitted when the bucket has none), and a stable `bom-ref` of the form
  `yuzu-crypto-lib/<family>/<version>/<ecosystem>` (percent-encoded).
- Yuzu's own facts in `properties` under the `yuzu:crypto:` namespace. Per component:
  `family_id`, `ecosystem`, `device_count`, `family_device_count`, `versions_truncated`, `package_names_truncated` (this bucket matches more package names than are listed) and one
  `package_name` per matching package. In `metadata`: `table_version`, `names_source`,
  `names_as_of` (absent when the names were read live), `result_truncated`,
  `truncated_families`, `devices_reporting`, `devices_with_crypto_library`, the filters applied,
  `scope` and `audit_persisted` (only when `false`). `names_as_of` is epoch seconds.
  `filter_family` is always present, and an empty value means no family filter;
  `filter_ecosystem` is present only when an ecosystem filter was applied (an absent property
  means no ecosystem filter, an empty value means rows that carry no ecosystem).
- `yuzu:crypto:scope` is `fleet` when the caller's visibility was unfiltered and `confined` when
  the caller is confined (a management group or a service-scoped token): a confined caller's BOM
  is marked `yuzu:crypto:scope` = `confined` and covers only the devices that caller can see, so
  it must not be read as the whole fleet.
- A top-level `compositions` entry with `aggregate` = `incomplete`, on every export: a package
  name match cannot see statically linked, vendored or OS-bundled copies, so the inventory is
  incomplete by nature, not only when truncated.
- A fresh random `serialNumber` (`urn:uuid:` version 4) and `timestamp` on every export, even
  when the content has not changed. `metadata.tools` names Yuzu and its version.

**What is deliberately not in it.** Components are never `cryptographic-asset`, and there are no
`cryptoProperties`, strength, quantum-security-level or good/bad fields: the export states which
libraries are installed at which versions and nothing about whether that is acceptable. That
interpretation belongs to the tool that consumes the BOM. There is no `purl` either, because the
inventory records a package name, version and ecosystem but not the distribution a correct purl
needs, and a wrong one is worse than none.

**Vulnerability scanners will not match these components.** With no `purl`, `cpe` or hash, a
scanner has nothing to look up, so an empty scan result means "not matchable", not "no known
vulnerabilities". Emitting a correct, distribution-aware `purl` is a known gap, tracked in
[crypto-asset-design.md](../crypto-asset-design.md).

**A cut is never silent.** Version lists are capped (50 buckets per family, a byte budget over
the whole answer, and the store's row cap). Every component of a family whose list was cut
carries `yuzu:crypto:versions_truncated` = `true` (when the store's row cap fires every family is flagged, since the model cannot tell which lost buckets), a bucket with more matching package names than are listed carries `yuzu:crypto:package_names_truncated` = `true`, and `yuzu:crypto:truncated_families` in the
metadata lists every such family, including one whose buckets were all dropped and which
therefore has no component at all. `yuzu:crypto:result_truncated` is `true` when the answer as a
whole was cut. A BOM with any of these set is incomplete, not wrong. As on the page, an empty
`components` array means "no matching package rows in the visible inventory", not "no library
is installed": statically linked, vendored and OS-bundled copies are invisible here.

The export is checked in CI against the official `bom-1.7.schema.json`.

## Audit

Every read that serves data is written to the audit log (see [audit-log.md](audit-log.md)):

| Verb | Written when |
|---|---|
| `crypto.libraries.view` | The family summary is served (REST route and `/crypto` page). The MCP tool writes `mcp.get_crypto_libraries`. |
| `crypto.libraries.devices` | A page of one family's devices is served (REST route and the drill). The MCP tool writes `mcp.list_crypto_library_devices`. |
| `crypto.cbom.export` | A CBOM is exported (REST route). The MCP tool writes `mcp.export_crypto_cbom`. Same detail key set as the summary (`rows` is the number of families), plus ` serial=<urn:uuid:...> [ecosystem=<filter>] components=<n>` (the `ecosystem` key only when that filter was given) on the success row, tying the audit row to the exact document handed out. |
| `crypto.ca.stats.view` | The Yuzu-issued counts are served (`GET /api/v1/crypto/ca/stats`, the dashboard, a single Yuzu-issued card, and the MCP tool `get_crypto_ca_stats` under the same verb). Target `Inventory` / `yuzu_ca`; detail `cid=.. ws=crypto_widget_windows_v1 as_of=<epoch>`, plus `widgets=<n>` on the dashboard row. A confined caller's refusal is a `denied` row with `withheld=confined`. |
| `crypto.ca.certificates.view` | A page of Yuzu-issued certificates behind one count is served: `GET /api/v1/ca/issued` **with filter parameters**, the drill with every Load more page, and `list_issued_certs` with filter arguments, under the same verb. Target `Security` / `kind=<k>[ days=<n>][ week=<YYYY-Www>][ bucket=<b>]`; detail adds `as_of` (with `pinned` when the caller supplied it or the page continues a cursor), `rows`, `page=first` or `page=continuation`, and `total`. A confined caller's refusal is a `denied` row with `withheld=confined`. The unfiltered `GET /api/v1/ca/issued` and `list_issued_certs` stay unaudited, as before. |
| `crypto.dashboard.layout.update` | You save a layout (`PUT /api/v1/crypto/dashboard/layout`, the dashboard buttons, or `set_crypto_dashboard_layout`). An `attempted` row is written first and the layout is not changed if it cannot be; then `success` (with the new `version=`) or `failure` (with `outcome=conflict`, `corrupt`, `degraded`, `unknown` or `invalid`). Target `CryptoDashboard` / your user name; detail `widgets=<n>`, plus `expected_version=<n>` when sent. A service-scoped token's attempt is a `denied` row. |
| `crypto.dashboard.layout.access_denied` | A service-scoped API token tried to read a layout (`GET /api/v1/crypto/dashboard/layout`); written as `denied`. |

**One row per dashboard draw.** Drawing the dashboard reads the library summary once and the
Yuzu-issued counts once for every card on it, and writes one `crypto.libraries.view` row (family
`all`) and one `crypto.ca.stats.view` row, each with `widgets=<n>` (how many cards that read
served), sharing one correlation id; a source with no card on the grid writes no row. Reloading
one card (**Retry**, or a card just added) writes one row for that card. REST and MCP calls write
one row per call. Reading your layout is not audited. The details below apply to the library verbs
(`crypto.cbom.export` included); the Yuzu-issued verbs are set-and-proceed in the same way.

Every row, on every surface, carries one detail key set:
`cid=<correlation id> tv=<table_version> family=<family or all> rows=<n> src=<catalogue|live> scope=<fleet|confined>`
(`src` is where the package names came from, see
[How fresh the package names are](#how-fresh-the-package-names-are)), plus `page=continuation` on
a page reached with a cursor, so a cursor walk cannot go unrecorded (`rows` is the number of
families for the summary and of package rows for the drill). `scope=fleet` means the caller read
unconfined; `scope=confined` means the read was limited to a visible device set, including an
empty one. The filters are in the audit target. The MCP rows carry no `cid=` key (the MCP path
mints no correlation id) and append the filters to the detail as `target=...`. A failed read
attempts a `failure` row with `cid=... tv=... scope=... store degraded` (the inventory read
failed) or `cid=... tv=... scope=... capacity in use` (the read was refused by the capacity
bound).

Auditing is **set-and-proceed**: if the audit row cannot be written, the response is still
served, and it says so. On REST the body carries `"audit_persisted": false` and the response has
the header `Sec-Audit-Failed: true`; the MCP tools set `audit_persisted: false` in their result.
A CBOM carries the same signal inside the document, as the metadata property
`yuzu:crypto:audit_persisted` = `false`: the BOM was served, but no audit row records the export
that produced it, so its `serialNumber` cannot be traced back to an export event. A BOM without
that property was recorded.
On the `/crypto` page the fragment response also carries `Sec-Audit-Failed: true`, and the
fragment shows a notice above the data (or above the "unavailable" banner, when the read failed):

> **Audit not recorded.** This view could not be recorded in the audit log. Audit store write
> failures are counted in yuzu_server_audit_emit_failed_total, which the shipped
> YuzuAuditPersistFailures alert watches.

On a **Load more** page the notice is a table row above the new rows. A refusal at the access
gate (no `Inventory:Read` grant, authorization store unavailable) is written by the gate itself as
`auth.fleet_read_required` and is not duplicated here.

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
  with a **Retry** button for a store failure or an incomplete access check, and a plain
  notice box for a refused permission or a bad parameter. The banner names what could not be
  read: "The inventory store could not be read" for a store failure, and "The access check could
  not be completed: one of its stores (permissions, management groups or tags) could not be read"
  when the access gate itself could not finish (the RBAC store is unavailable or its read failed,
  the management-group store is unavailable, or, for a service-scoped token, the tag store is
  unavailable or degraded). Neither is "no library installed", and the second is not a
  refusal. **Retry** re-requests what failed: the
  summary on the summary banner, the same drill on a failed first drill page, and the same page on
  a failed **Load more** page. On a **Load more** page the banner or notice is a single table row,
  so the list above it stays intact.
- **Dashboard cards and the Yuzu-issued drill** follow the same rules, always with HTTP 200: a
  card or drill whose read failed shows its own banner and **Retry** re-requests just that card
  (or that page). A Yuzu-issued banner names its cause: "Database degraded: Yuzu's certificate
  store could not be read" for a store fault, "Busy: too many crypto reads are in progress on this
  server; retry shortly" for a capacity shed, or "The access check could not be completed" when
  the permission check itself could not be made, and always says this is not a count of zero: a
  failed read is never drawn as 0. The REST twins answer `503` with `retry_after_ms: 5000` (message
  `Yuzu CA read degraded` or `crypto read capacity in use; retry`).
- **A wiring fault** (the server built without the `/crypto` seam: `503 service unavailable` on
  the `/api/v1/crypto/*` data routes, `503 filtered certificate list unavailable` on a filtered
  `GET /api/v1/ca/issued`) carries **no** `retry_after_ms`: it lasts until a restart with the
  wiring fixed, the same posture as layouts unavailable since server start (ADR-0071).
- **Layouts.** A layout read or save that fails answers `503` with `retry_after_ms` (`dashboard
  layout read degraded` / `dashboard layout save failed`), and `save outcome unknown — reload to
  check` when the connection dropped after a save was sent. A stale `expected_version`, or none
  while a layout is stored, is `409`
  and reading a damaged stored layout is `422` (a save naming its version replaces it), both carrying the stored version in the
  `X-Crypto-Layout-Version` header and neither retryable as sent. When the layout store did not
  open at server start, the server still starts and, until a restart with the store fixed: both
  layout routes answer `503` **without** `retry_after_ms` ("dashboard layouts unavailable: the
  layout store did not open at server start; ...") and the MCP layout tools a `kInternalError`
  with no retry hint (retrying cannot succeed before a restart); the dashboard draws the default
  layout, read-only, under the notice "Saved layouts are unavailable on this server." with no
  save controls; and `/readyz` stays `200` with `{"status":"ready","degraded":
  ["crypto_dashboard_layout_store"]}`, a notice that does not take the server out of rotation.
  Each refused layout request counts on
  `yuzu_inventory_read_degrade_total{source="crypto_layout",reason="store_not_open"}`. Layout reads and saves do not use the two-read bound below.

**Capacity.** Each server process lets at most two `/crypto` store reads run at once (the library
summary and drill and the Yuzu-issued counts and list share the bound; with several replicas the
fleet-wide ceiling is two times the replica count), because a summary read can hold a database
connection for as long as the statement timeout and the connection pool is shared with
authorization, audit and ingest. On a small connection pool the bound is a quarter of the pool,
at least one: one read at once on a pool of 4 to 7 connections. On a pool of 3 connections or
fewer (`--postgres-pool-size`) the Yuzu-issued reads are refused every time, leaving those few
connections to the rest of the server (the agent certificate revocation check among them), and
on a pool of a single connection the library reads, the device drill and the CBOM export
(`GET /api/v1/crypto/cbom`, MCP `export_crypto_cbom`) are refused too, so the revocation check
made when an agent connects always has that connection. That refusal is a configuration fault,
not a shed: it lasts until the server restarts with a larger `--postgres-pool-size`, so REST
answers `503` **without** `retry_after_ms` and MCP an error with no retry hint, both naming the
flag. The Yuzu-issued reads run under a 5 s statement bound. A read
that arrives while both slots are in use is refused at once, without touching the database: REST
`503` with `retry_after_ms`, a retryable MCP error, and the "temporarily unavailable" banner or
row on the page. It is a shed, not a fault; retry after the hint. An agentic worker should
serialise its `list_crypto_library_devices` calls (one page at a time, following `next_cursor`)
rather than fan them out: parallel drills compete for the same two slots.

**Diagnosing a degrade.** A banner or `503` here has one of a few causes, told apart by the
message, the audit row and the counter (the catalogue-rollup row is how to tell a catalogue
problem from a failed read; the access-gate row is the gate, not the inventory read).
The audit row is attempted, not guaranteed: when the cause is the database connection pool
(`pool_acquire_timeout`), the audit write needs the same pool and can be lost too, so rely on the
message and the counter, and check `yuzu_server_audit_emit_failed_total`:

| Cause | `503` message | Audit `failure` detail (when written) | Counter `yuzu_inventory_read_degrade_total{source="installed_software"}` |
|---|---|---|---|
| The inventory read failed or ran past its 5 s bound | `crypto library read degraded` | `store degraded` | `reason` is `store_not_open`, `pool_acquire_timeout` or `query_error` |
| The concurrent-read bound was full | `crypto read capacity in use; retry` | `capacity in use` | `reason="admission_full"` |
| The same `crypto library read degraded` while `YuzuInventoryCatalogRollupStale` or `YuzuInventoryCatalogRollupFailing` is firing | `crypto library read degraded` | `store degraded` | `reason="query_error"` (the 5 s statement timeout) |
| CBOM export only: the process could not mint the BOM serial number (CSPRNG failure) | `service unavailable` (REST, `retry_after_ms` 5000); a retryable internal error on MCP | none: this is checked before any inventory read, so no read slot is taken and nothing is audited; the server log carries `CSPRNG failure minting the BOM serial number` | not moved |
| The access gate could not complete its check (RBAC, management-group or tag store) | REST and MCP: the gate's own `503` A4 envelope (on MCP too, not a JSON-RPC error); on the page the banner "The access check could not be completed: one of its stores (permissions, management groups or tags) could not be read" | none here; the gate writes its own `auth.fleet_read_required` `denied` row, whose detail names the store that failed (for example `fleet read blocked: management-group store unavailable`) | not moved; `yuzu_server_rbac_read_degrade_total` moves only when an RBAC read itself fails, not for an unavailable RBAC store or a management-group or tag store failure |

The last row most likely means the live name scan exceeded its 5 s bound: there are too many
distinct package names for a live read, and retrying will not help (a Postgres overload also
yields `query_error`, so check the database load too). Above about 2.7 million installed-package
rows this is expected until the catalogue rollup is made incremental. Fix the catalogue refresh
(the alerts say how) or the flood of distinct names; `/crypto` recovers on its own once the
catalogue is fresh again. The two rollup alerts use each replica's own refresh-success time against the
Prometheus clock, while `/crypto` compares the shared catalogue stamp with the database clock, so a
database clock step back of more than five minutes, or forward far enough to push the stamp past
two hours, can send `/crypto` to live reads with neither alert firing; compare `names_as_of` with
the database `now()`.

The Yuzu-issued and layout reads count their degrades on the same counter under their own
`source`: `yuzu_inventory_read_degrade_total{source="ca_issued"}` for the counts and the
certificate list, and `{source="crypto_layout"}` for layouts, with `reason` `admission_full`
(the two-read bound was full; Yuzu-issued only), `store_not_open`, `pool_acquire_timeout` (no
database connection within the lease time) or `query_error` (a query error, including the 5 s
statement bound). `YuzuCryptoCaReadDegraded` fires when Yuzu-issued reads keep degrading for 15
minutes; its description says how to tell a shed (`admission_full`: look for a poll storm) from a
store fault (`query_error`: look at the database). The CA store and layout store degrade
warnings are sampled (the first of an episode, then every 100th) so a poll storm does not flood
the log; the counters count every one. The layout store logs a failed statement's SQLSTATE only,
never the libpq message (which can quote the username-keyed row). See
[metrics.md](metrics.md#crypto-dashboard-metrics).

### Deprovision erasure

A saved layout is keyed by the operator's username (personal data, ADR-0071). When an operator
is deprovisioned (SCIM `active:false`, SCIM `DELETE`, a SCIM create with `active:false`, or a
local user deleted from the dashboard), the server erases the layout row of the username and of
every linked `oidc:` / `saml:` identity, after the deprovision itself has committed. A SCIM
`DELETE` of an already-inactive user, and an `active:false` replay that finds the user already
inactive, run the same erasure again (it is idempotent), resolving the linked identities even
though the user is inactive; no credential is revoked again on that path. If those linked
identities cannot be read, that erasure removes the username's row alone and counts the case as
`link_read_failed` (below): a linked identity's row may remain, and the check below removes it.

The erasure is **best-effort**: it never changes the deprovision's answer. A failure is a `warn`
log line naming only the reason (never the username, a hash or a token) and an increment of
`yuzu_server_crypto_layout_erase_failures_total{reason}` (`store_not_open`,
`pool_acquire_timeout`, `outcome_unknown`, `query_error`, `link_read_failed`; pre-seeded at zero
at boot).
`YuzuCryptoLayoutEraseFailed` fires on any increase in the last hour. It runs synchronously
before the deprovision answers: on a saturated database each principal's erase can wait up to
2 s.

**Remedy, and a periodic check.** List the stored keys, compare them with your active operators
(local users from **Settings → Users**, SCIM users from your identity provider) and delete the
rows of principals who are no longer active. Product code never joins the layout table to the
user tables; you supply the list:

```sql
-- every stored layout key
SELECT username FROM crypto_dashboard_layout_store.layouts ORDER BY username;

-- replace the example keys with yours; run the SELECT above first and delete only keys
-- you have confirmed are no longer active
DELETE FROM crypto_dashboard_layout_store.layouts
 WHERE username = ANY (ARRAY['alice', 'oidc:https://idp.example.com/#sub-123']);
```

Two cases can leave a row behind even when nothing failed, and the same check removes them: a
layout **save already in flight** when the erasure ran can re-insert the row after it (the
operator's sessions are being revoked by the same deprovision, but that request may already be
past authentication), and **restoring a database backup** taken before the deprovision brings
erased rows back. Run the check after any restore.

On the dashboard page and its **Load more** row the capacity shed reads "Temporarily busy: two
reads are already running on this server; retry shortly" and a store fault reads "The inventory
store could not be read" (a degraded access gate reads "The access check could not be completed:
one of its stores (permissions, management groups or tags) could not be read" instead); REST uses
the same `503` message per cause and MCP the same message text in a retryable JSON-RPC error. An
access-gate failure is the exception: both REST and MCP carry the gate's own `503` A4 envelope,
not a JSON-RPC error.

Every such response also attempts a `failure` row for the `crypto.libraries.*` verb in the audit
log. Under connection-pool exhaustion that row can be lost; a failed audit store write increments
`yuzu_server_audit_emit_failed_total` (an audit sink that throws instead is caught and only logged,
not counted), and either way the page shows the "Audit not recorded" notice above the banner. A banner, `503` or MCP error
that comes from the access gate instead never moves the inventory counter and writes no
`crypto.libraries.*` failure row: the gate writes its own `auth.fleet_read_required` row, whose
detail names the store that failed, and `yuzu_server_rbac_read_degrade_total` moves only when the
failure was an RBAC read.

## Pilot expectations

Before showing this page to a stakeholder, check how many devices are reporting (the first KPI
tile) against the size of the fleet, and read the per-OS coverage caveat: Linux gives the most
complete package picture, macOS shows Homebrew packages only, and Windows shows only installers
registered in the registry. "One family found" therefore reads as "one family found in the
package evidence", not as "this is the only library in use". A statically linked or vendored
copy is the usual reason a known library does not appear. Component-level inventory that closes
that gap is planned (roadmap Issue 18.7, ADR-0028).

Fleets above about 2.7M installed-package rows (roughly 6,000 endpoints at about 450 packages
each, about 1,800 at 1,500): the hourly catalogue does not build, so
`/crypto` reads names live on every call (about 2 s per summary at 15M rows / 30,000 distinct
names) and, with many replicas on one database, can time out. See [Scale](#scale).

If an access-audit row cannot be written, the page still shows the data, with the "Audit not
recorded" notice above it (see [Audit](#audit)); REST and MCP report it in the response. Watch
`yuzu_server_audit_emit_failed_total` on the server.

### How fresh the package names are

The list of package NAMES that the table is matched against
has two sources, chosen on every read. While the hourly software-catalogue refresh is **fresh**
(it has run, and started at most two hours ago) the names come from it: `names_source` is
`catalogue` and `names_as_of` is the refresh time (epoch seconds in the API; "Package names as of
..." on the page). A package name first reported after that time appears after the next hourly
refresh. When the catalogue has never been built (a new server, or an upgrade), is older than
two hours, or its last refresh found zero titles, the names are read **live** from the installed-software inventory instead:
`names_source` is `live`, `names_as_of` is `null` and the page says "Package names read live".
Either way counts and versions for the listed names are live: a device that reports an
already-listed name is counted at once. The two sources return the same answer for the same data;
only a name first reported since the last refresh differs. "Fresh" means the refresh **started** at
most two hours ago; a stamp more than five minutes in the future (a clock fault) counts as stale and
the names are read live. A drill cursor records the names source it was issued under. One change between pages is
refused: a page whose cursor was issued on LIVE names, when the next page finds the shared catalogue
in use (it became fresh in between), because the catalogue may lack a name first reported after its
refresh, so rows of a name the walk has already listed could be skipped. That continuation is a
`400` that says to restart the walk without a cursor (a fragment shows the same text as a note; MCP
answers invalid-params). Every other change continues: a switch from the catalogue to live names
lists every name, and a newer catalogue lists every name that had rows at its refresh. The refusal
normally happens once, but it happens again each time the catalogue goes stale (the refresh failing
for more than two hours, or a database clock step) and then recovers during the same walk. A walk
is not a snapshot: rows are ordered agent first, and a row that appears during the walk, for any
name, on a device the walk has already passed (or earlier in order on the cursor's own device) is
not returned. Two further cases follow from the names source: a name with no rows anywhere at a
refresh that reappears before the next refresh is missed until a later refresh lists it again,
exactly as on a fresh walk on that catalogue (the catalogue lag above); and a name new in the newer
source IS listed for devices after the cursor, while its rows on devices already passed are missed.
Restart the walk to see them. A deny-all answer (an empty scope) reads nothing, so
it reports `names_source` `live` and `names_as_of` `null` (and its page still carries the
names-source note); a walk whose scope empties mid-walk continues and ends on an empty page. An old
catalogue is the signal to look at the rollup alerts `YuzuInventoryCatalogRollupStale` (a catalogue
was built, and its last success is more than two hours old) and `YuzuInventoryCatalogRollupFailing`
(the catalogue was never built, or the refresh keeps failing); both descriptions say `/crypto`
reads its package names live if the shared catalogue is also older than two hours (the alerts are
per replica; the catalogue is shared). There is no `503` for an unbuilt catalogue any more.

### Scale

The two sources have different envelopes, measured on the reference host (about
+/-30 percent, host load 3 to 10). The catalogue path follows the number of DISTINCT package names
in the fleet, not the number of devices: from 30,000 to 1.03 million distinct names the summary
takes about 0.5 to 3.3 s and a family drill about 7 ms to 1.9 s. The live path does one index
probe per distinct name (about 28 to 36 microseconds each): at 15 million installed-package rows
with 30,000 distinct names the summary takes about 1.7 to 2.2 s and a family drill about 0.7 to
1.4 s (the skip-scan alone is 0.9 to 1.2 s), and the live path passes the 5 s statement bound at
about 140,000 to 180,000 distinct names, depending on host and load.

The catalogue refresh itself does not finish within its own 60 s statement cap at scale: 219 to
241 s is the UNCAPPED duration of the refresh's grouping statement (GROUPING SETS), measured at 3
million and at 15 million rows, and the 60 s cap is crossed at about 2.7 million rows (the
crossing is in `docs/user-manual/inventory.md`). On a fleet above about 2.7 million
installed-package rows the catalogue is therefore never built (or goes stale) until the rollup is
made incremental, and `/crypto` then reads its package names LIVE on every call. The worst case
is a stale or unbuilt catalogue on a fleet with more than about 140,000 to 180,000 distinct
package names: the read exceeds its 5 s bound and is a bounded `503` (`crypto library read
degraded`), never a hang and never an empty answer.

**Capacity note.** On the live path only (catalogue stale or unbuilt): each process allows two
concurrent reads, so it cannot exhaust the connection pool; at two concurrent live summaries the p50
is about 2.15 s and the p95 about 2.42 s with no timeouts. The ceiling is per process: in a
worst-case test at 15M rows / 30k names, 16 simultaneous live reads on one database (about eight
replicas with both slots busy) timed out about half the time, so size the replica count and the
catalogue refresh together.

## Roadmap

The following are planned and not yet available. No dates are committed.

- A fleet certificate inventory with full X.509 fields. Certificate data is not available on
  this page until that slice ships (the endpoint `certificates` plugin already lists system store
  certificates per device).
- SSH key inventory (host keys and keys at rest). SSH login evidence is subject to a separate
  privacy decision before it is built.
- Protocol and configuration settings (for example TLS and SSH daemon settings).
- A fuller cryptographic bill of materials: the CBOM export already carries the installed
  libraries (see "Exporting a CBOM"); certificates, keys, protocols and algorithms will join it
  as they are collected, still carrying inventory facts only, with no security-level fields.

Yuzu does not label weak cryptography, expiry risk or post-quantum readiness, now or in these
planned views. It reports facts (libraries, versions and, later, certificates and keys); operators
can apply their own policy to those facts.

## Related documentation

- [Inventory](inventory.md): the installed-software data this page reads
- [REST API: Crypto](rest-api.md#crypto)
- [MCP tools](mcp.md)
- [Audit log](audit-log.md)
- [Device management](device-management.md)
