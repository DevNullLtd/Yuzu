# Slice 2: fleet certificate inventory and registered-CRL revocation

**Status:** design, not built. This is the slice-2 design that ADR-0070 (PR #6125) requires
before any slice-2 code is written ("Slice 2 is unblocked to design. Its design doc must cite this
ADR and satisfy D4, D5, D6, D7 and D12"). It is a design, not an ADR. The owner's decisions for
slice 2, and the points still open, are under [Decisions](#decisions). Where possible it states
outcomes and leaves mechanisms to the implementation PRs, which get their own governance.

It supersedes the "Slice 2: certificate inventory" section of `docs/crypto-asset-design.md` where
the two differ. One difference matters: that section proposes computing days-to-expiry on the
server. ADR-0070 rules that out as a field (D4, and D13 condition 3: "no stored
`days_remaining`"). This design has no `days_remaining` anywhere.

**How to read the labels.**
- **Decided (ADR-0070 Dn)** marks a rule ADR-0070 already makes. This doc restates it only so the
  design can be checked against it.
- **Proposed** marks this design's own choice. A reviewer can change it without touching the ADR.

**How to read the citations.**
- A bare `path:line` is a code fact, checked against `origin/dev` at `820afe501` on 2026-10-19.
- `0070:N` is a line in `docs/adr/0070-cryptographic-asset-inventory-placement.md` at commit
  **`430e67b7d`** of the `docs/adr-0070-crypto-asset-placement` branch (PR #6125, open, in review),
  which carries owner rulings R1–R14. Every `0070:N` citation in this doc is pinned to that commit
  and was re-checked by script against it. If #6125 changes before merge, the clause names govern,
  not the line numbers.
- `widgets:` marks work proposed in the unmerged, unpublished `feat/crypto-dashboard-widgets`
  branch. Its commits are not on `origin`, so this doc relies on nothing in it: where it is
  mentioned, it is "proposed in unmerged work", and every binding rule here comes from ADR-0070 or
  from `dev`.

## Contents

1. [What slice 2 delivers](#what-slice-2-delivers)
2. [Phasing and PR order](#phasing-and-pr-order)
3. [Collection on the agent](#collection-on-the-agent)
4. [The daily-sync source](#the-daily-sync-source)
5. [Server: store, ingest and lifecycle](#server-store-ingest-and-lifecycle)
6. [Read surface](#read-surface)
7. [R1: registered-CRL revocation (slice 2b)](#r1-registered-crl-revocation-slice-2b)
8. [Personal data](#personal-data)
9. [Dashboard widgets: the data they read](#dashboard-widgets-the-data-they-read)
10. [Tests and chaos](#tests-and-chaos)
11. [Decisions](#decisions)
12. [How this could ship wrong](#how-this-could-ship-wrong)
13. [ADR-0070 clause map](#adr-0070-clause-map)
14. [Capacity](#capacity)
15. [Still owed by every slice-2 PR](#still-owed-by-every-slice-2-pr)

## What slice 2 delivers

- **Slice 2a, the certificate inventory.** The agent enumerates the machine's certificate stores
  and trust-store files once a day. A new typed daily-sync source carries the raw X.509 facts to
  the server. The server stores them in a typed Postgres store and serves them over REST, MCP and
  the `/crypto` dashboard, behind a dedicated certificate securable. Slice 2a also ships D13's four
  weak-key rules and its expiry, expired and issued windows for fleet certificates, and adds the
  certificate half of the CBOM export.
- **Slice 2b, R1 revocation.** An administrator registers a CA certificate and its CRL URLs. A
  server-side fetcher retrieves exactly those URLs. The read surface then states revocation for
  fleet certificates under D5's revocation-statement rule. Slice 2b also adds D13's revoked windows
  and `crl_past_next_update`.

**Not in slice 2:**
- per-user certificate stores (decided by the owner, 2026-10-19; see [Decisions](#decisions));
- any live dispatch of the full-field collector. It runs only inside the daily sync (owner
  decision OD-1, [Decisions](#decisions)). Ad-hoc look-ups keep using today's `certificates.list`;
- the device-local chain-to-trust-store result. D5 makes it "optional, not committed" (`0070:498-501`),
  and this design does not build it;
- OCSP, and any fetch of a URL taken from a certificate (Decided, ADR-0070 D5, `0070:518`,
  `:565-568`);
- any certificate mutation, such as renewal, re-issue or deletion (Decided, ADR-0070 D6,
  `0070:607-620`);
- the Yuzu-CA issued and revoked widgets. They read `CaStore`, not fleet rows (R2), and the separate
  widgets work builds them.

## Phasing and PR order

**Proposed.** Each PR is reachable on merge: it changes behaviour an operator, an agent or a test
against the running server can observe. No PR ships half a feature that waits for a later one.

| # | PR | Contents | Why it is reachable on its own |
|---|---|---|---|
| 2a-1 | Typed-source hygiene | One exported constant array of typed source names in `typed_inventory_sources.hpp`, **already including the reserved name `certificate_inventory`**, used by the predicate (and so the gateway skip), a batched purge and a new read-time filter on the generic `InventoryStore` reads. No certificate code. Amends the app-usage read-surface routed-concern row in the same change. | It closes today's accepted stray-row window for `app_usage` and `device_ci` (see [Typed set](#typed-set-purge-and-read-filter)). D12 forbids that window for certificates, so it must exist, with the certificate source name reserved, before any agent sends the source. |
| 2a-2 | Certificate inventory, end to end | Agent action `certificates.list_inventory` and its parsers; daily-sync source `certificate_inventory`; `CertificateInventoryStore` and ingest seam; per-certificate read and raw-value summary, REST + MCP + `/crypto` fragment; the dedicated securable, its seeding and floor entry; decommission, `/readyz`, retention prune; the D10 lint and the schema lint. | The agent source cannot ship without the store (its rows would land nowhere, or in the generic store), and the store cannot ship without a read (it would be dormant). So this is one PR, reviewed commit by commit. |
| 2a-3 | D13 certificate counts | The counts read (REST + MCP), the D13 condition-1 lint entries and the recompute test; the data the certificate widgets read (their UI is proposed in unmerged work). | Operators see the counts on `/crypto` and through MCP. |
| 2a-4 | CBOM certificate half | Certificate, algorithm and public-key components in `GET /api/v1/crypto/cbom` and `export_crypto_cbom`, gated by the certificate securable. | Builds on the library-component CBOM (#6143, merged to `dev`). |
| 2b-1 | Revocation sources and fetcher | `RevocationSourceStore`; registration REST + MCP; the admin-only predicate and the floor-header amendment; the fetcher and its egress checks; CRL verification and acceptance; the leader-gated refresh job; `crl_past_next_update` on the source read; metrics and alerts. | An administrator registers a source and sees its fetch status, held CRL, `thisUpdate`, `nextUpdate`, entry count and `crl_past_next_update`; the alerts fire. |
| 2b-2 | Revocation statements | Read-time matching on the per-certificate read; the revoked windows in the counts read; the signature-verification job; the widgets' revoked data. | Certificates read "revoked on …", "on hold", "not listed on …" or "revocation not checked", with the cause. |
| 2b-3 | Delta CRLs (optional, last) | Delta CRL use together with its base. | Until it lands, a delta CRL is verified and recorded but never used, and the source shows `delta_not_supported`. Nothing earlier depends on it. |

**Order.** 2a-1 → 2a-2 → 2a-3. 2a-3 uses one shared set of D13 window constants and edge
predicates, written to ADR-0070's R5/R7/R10/R14. If the widgets work (proposed in unmerged work)
lands such a set first, 2a-3 imports it; otherwise 2a-3 lands it. 2a-4 can follow 2a-2 at any time
(the library-component CBOM, #6143, is merged). 2b-1 can
start once 2a-2 is merged, because it reads no fleet rows. 2b-2 needs 2a-2 and 2b-1. 2b-3 is
optional and comes last.

**Deploy order** is server before agents, as for blob v2 of `installed_software`
(`docs/adr/0016-agent-daily-sync-framework.md`, "Deploy order: server before agents"). Nothing
enforces that order, so the design does not rely on it:
- From 2a-1 on, `certificate_inventory` is in the typed set before any agent sends it. A server at
  2a-1 or later never stores the blob in the generic store on the gateway path, and its read filter
  hides any stray row.
- **The remaining window (disclosed):** a server older than 2a-1, including a server rolled back
  below it, that receives the blob from a 2a-2 agent through a gateway stores it in the generic
  store, readable under `Infrastructure:Read` / `Inventory:Read`. The rows become unreadable as soon as the server is
  at 2a-1 or later, and the purge removes them. `upgrading.md` states this and says to upgrade
  servers before agents and never roll a server back below 2a-1 while 2a-2 agents run.

**Owed documents, per PR** (beyond the obligations in
[Still owed by every slice-2 PR](#still-owed-by-every-slice-2-pr)):

| PR | Documents |
|---|---|
| 2a-1 | `upgrading.md`: the `app_usage`/`device_ci` behaviour change (stray generic rows stop being readable), the deploy order, and the downgrade note above. The app-usage read-surface routed-concern row: its accepted mixed-version window becomes closed. A changelog fragment. |
| 2a-2 | `crypto.md`, `rest-api.md`, `mcp.md`, `audit-log.md` (the new verbs, including `crypto.certificates.tombstones.view` and `crypto.certificates.tombstone_purge`), `rbac.md` and the SOC 2 access-control inventory (`CertificateInventory`), the generated plugin README, the OS capability matrix, and the DPIA screening record. The tombstone list and purge routes and their MCP tools. The A2/A1 RBAC-administration routed-concern row (`.claude/routed-concerns-access-control.md`), amended for the new `is_rbac_administrator()` call sites, as that row requires. |
| #6125 (owed request, not an edit) | Ask that D6's "never opens ... key blocks in PEM files" (`0070:630`) be worded as the exact property in [Linux link and file rules](#stores-read-per-os): key-block lines discarded unretained, never base64-decoded, buffer cleansed. Tracked until #6125 answers; this design does not edit the ADR. |
| 2a-3 | `crypto.md`, `rest-api.md`, `mcp.md` and `audit-log.md` for the snapshot export (`GET /api/v1/crypto/certificates/snapshot`, `export_crypto_certificate_snapshot`, verb `crypto.certificates.snapshot`), including that paged reads make no cross-page consistency promise. `crypto.md` (each count's rule, window and boundary), the D10 lint's allow-list entries. |
| 2a-4 | `crypto.md` and `rest-api.md`/`mcp.md` (the certificate half of the CBOM, its securable and its `halves_omitted` metadata). |
| 2b-1 | `server-admin.md` and `security-hardening.md`: CRL egress, the address rules, and firewall guidance for the server's outbound CRL fetches. `rbac.md`, `audit-log.md` and the SOC 2 inventory (`RevocationSource`). The fetcher's security review record. |
| 2b-2 | `crypto.md`: the revocation statements and their causes. |

## Collection on the agent

### The collector

**Decided (ADR-0070 D6, `0070:607-620`):** the sync source runs plugin actions in-process
through the agent's local dispatcher, so the server-side `ExecuteGate` never sees it. It must be a
dedicated read-only collector, or a fixed list of read-only actions, never `delete`. A
compile-time assertion or a test checks the list against the catalogue's `ReadOnly` /
`Mutability::None` rows.

**Proposed:**
- **A new action, `certificates.list_inventory`.** It is not a change to `list`, which is a stable
  contract with day-granular dates and SHA-1 identity (`certificates_x509.hpp:140-148`, `:187-197`).
  The precedent is `installed_apps.list_inventory`. It has a catalogue row
  (`capability_decls/plugin_action_catalogue_b.hpp:490-499`) but no instruction definition under
  `content/definitions/`, and the sync source calls it through `LocalDispatcher`
  (`agents/core/src/sync_source_installed_software.cpp:218`, `:473-491`).
- **Daily sync only (owner decision OD-1).** A live dispatch would put the full field set, UPN
  and e-mail SANs included, into the ResponseStore, readable under `Response:Read`: every user under
  RBAC off and the Viewer role under RBAC on. That is the breadth D12 forbids the synced copy to
  inherit (`0070:880-888`), and gating who may dispatch does not limit who may read the result. So
  every dispatch path refuses `list_inventory`.
  - **How every path refuses it.** `ExecuteGate` has no "never" value
    (`command_capability.hpp:76-81`). Instead, `certificates.list_inventory` gets **no**
    `CommandCapability` row. `classify_and_authorize_dispatch` then denies it as `Unclassified` on
    every server dispatch path, system callers included (`agent_registry.hpp:202-207`). REST, MCP,
    schedules, workflows and bundles all pass through that chokepoint. The agent's
    `LocalDispatcher` call inside the sync source does not.
  - **The test.** A capability-catalogue test asserts that no catalogue row names
    `certificates.list_inventory`, and that `classify("certificates", "list_inventory")` fails. A
    dispatch test sends it through the shared dispatch chokepoint as an operator and as a system
    caller, and asserts the `unclassified` denial both times.
  - **Not in the plugin's `actions()` list.** `tests/test_capability_catalogue_complete.py`
    (check 1, a "MISSING row") fails CI for any action a plugin lists in `actions()` without a
    catalogue row, so `list_inventory` must **not** appear in the plugin's `acts[]` array
    (`certificates_plugin.cpp:2316-2317`). The plugin still executes it when the sync source calls
    it by name. Consequences: the generated plugin README, the OS capability matrix and
    `enablement_units.hpp`'s `kUnitOs` never see it, so the README discloses it by hand, as a
    sync-only internal action.
  - **The server chokepoint is the only enforcement point.** The agent never checks a command's
    action against `actions()`; the list is only advertised at registration
    (`agents/core/src/agent.cpp:1828-1831`). A refusal therefore rests entirely on the missing
    catalogue row at `classify_and_authorize_dispatch`, which is why both tests above are
    required.
  - **Operators keep `certificates.list`** (`Security:Read`, unchanged) for ad-hoc look-ups.
- **The fixed-list check (D6).** `sync_source_certificate_inventory.cpp` names exactly one action,
  `list_inventory`. D6 asks for a check "against the catalogue's `ReadOnly` / `Mutability::None`
  rows". With no catalogue row, the check is instead: the sync source's action list is exactly
  `{"list_inventory"}` (a compile-time assertion), and a plugin test asserts that `list_inventory`
  reaches no write, delete or key-opening call. That is stricter than D6's wording (the action
  cannot be dispatched at all), and the 2a-2 PR records it as such.
- **One parser on every OS.** Every leg gets each certificate's DER and parses it with the plugin's
  libcrypto parser. `certificates_x509.hpp:325` already has `parse_der_cert`, which refuses a
  buffer it did not wholly consume. Today the Windows build does not link OpenSSL
  (`agents/plugins/certificates/meson.build:3-10`) and uses CryptoAPI's simple display name instead
  (`certificates_plugin.cpp:264-271`). Linking OpenSSL there is a build-graph change, owed to
  `build-ci` review against the Windows static-triplet rules in `CLAUDE.md`. The fallback, if that
  review refuses, is a CryptoAPI decode of the same fields with a cross-OS golden test.
- **Never a chain build, never a network call.** The collector parses certificates. It never calls
  an OS chain or trust-evaluation API, so D5's chain conditions do not arise in slice 2.
- **Run context.** The collector runs as the agent: LocalSystem on Windows today (#1442), root on
  macOS today (#1455), and the unprivileged `yuzu` account on Linux in production
  (`docs/agent-privilege-model.md`). On Linux a trust-store file the `yuzu` account cannot read is
  `unreadable`, never skipped.
- **Buffers.** A Linux trust-store file may hold a private-key block next to a certificate, so
  its bytes can enter the read buffer. The exact property is stated under the Linux link and file
  rules below. Every file buffer is cleansed (`OPENSSL_cleanse`) before release, and no file
  content is ever logged.

### Stores read, per OS

**Decided (ADR-0070 D12 "Identity", `0070:1017-1018`):** a fallback read never stands in for
LocalMachine, and a service account's own store is labelled as such, never as a person's.

**Proposed: machine scope only. Per-user stores are not read in slice 2.**

| OS | Read (the machine-scope allowlist) | Not read in slice 2, and disclosed by name |
|---|---|---|
| Windows | Every system store `CertEnumSystemStore` lists in three machine locations: `CERT_SYSTEM_STORE_LOCAL_MACHINE`, `..._LOCAL_MACHINE_GROUP_POLICY` and `..._LOCAL_MACHINE_ENTERPRISE`, opened with `CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG`, capped at 64 stores. `store_id` is `<location>\<name>`, for example `LocalMachine\Root` or `LocalMachineGroupPolicy\Trust`. This covers today's four (MY, ROOT, CA, Trust; `certificates_plugin.cpp:413`) and adds AuthRoot, Disallowed, TrustedPeople, TrustedPublisher and the other machine stores. | Every CurrentUser and per-user store. Per-service stores (`CERT_SYSTEM_STORE_SERVICES`). An unopenable LocalMachine store is `unreadable`. It is **never** answered from CurrentUser, unlike today's `list` (`certificates_plugin.cpp:340-361`). |
| Linux | PEM `CERTIFICATE` and `TRUSTED CERTIFICATE` blocks, **every block in a file**, plus single-certificate DER files, under fixed roots: `/etc/ssl/certs`, `/usr/share/ca-certificates`, `/usr/local/share/ca-certificates`, `/etc/pki/tls/certs`, `/etc/pki/ca-trust/source/anchors`, `/etc/pki/ca-trust/extracted/pem`, `/etc/pki/ca-trust/extracted/openssl` (RHEL's `/etc/pki/tls/certs/ca-bundle.trust.crt` links into it), `/usr/share/pki/ca-trust-source/anchors`, `/etc/ca-certificates/trust-source/anchors`, `/etc/ca-certificates/extracted` (Arch; `/etc/ssl/certs` links into it), `/etc/pki/trust/anchors`, `/usr/share/pki/trust/anchors`, `/var/lib/ca-certificates/pem`. Directories are walked to depth 2. | Java `cacerts` (JKS or PKCS#12 keystores), PKCS#12 files, `.p11-kit` files (Arch's default source bundle is one, so on Arch the read covers the extracted copies only), application and per-user stores, and NSS databases. `/etc/ssl/private` and every private-key directory are never opened (D6). |
| macOS | `System.keychain` and `SystemRootCertificates.keychain` only, read in-process through SecItem as the existing leg reads them (`certificates_plugin.cpp:1031`): one query per keychain, scoped to that keychain alone by `kSecMatchSearchList`, inside the bounded read slot, with authentication UI disallowed so no query can prompt. | The console user's login keychain, which today's `list` reads with `store=all` (README "Inputs"). Admin and user trust settings. Other keychains. |

**Windows notes.** How `CertEnumSystemStore` behaves across the three machine locations when run
as LocalSystem is unverified; the implementing PR measures it on the Windows test box and records
the store list it sees. Opening a store whose provider is registered by a third party loads that
provider's DLL into the agent process. The implementing PR lists the providers present and either
skips stores whose provider is not a built-in system provider (reason `third_party_provider`) or
records why loading them is acceptable.

The Linux root list is drawn from the Debian, RHEL, SUSE and Arch trust-store layouts as documented
by those distributions; none has been checked on a host yet, so 2a-2 verifies each layout (in
particular that no RHEL or Arch host reads `constrained` permanently from a link into an unlisted
directory) before merge. It is a
fixed list, not a crawl. A root that does not exist reads `absent` only after its parent directory
has been opened, so a parent that cannot be read is `unreadable`, not `absent`. This is the
`system_hardening` rule: `absent` only where the read surface is confirmed present.

**Linux link and file rules (Proposed):**
- Every entry is opened with `O_NOFOLLOW` from the root's held directory fd. The existing leg's
  `read_cert_entry` does **not** do this for a link: after the `O_NOFOLLOW` open fails it opens the
  link's target by path (`certificates_linux_store.hpp:203-216`). The new walk must not reuse
  `read_cert_entry` or any helper that opens a target by path.
- A root that is itself a symlink is not followed either. Today's leg refuses a symlinked
  `/etc/ssl/certs` outright (`certificates_linux_store.hpp:88-93`), and on RHEL-family systems that
  root is a link to `/etc/pki/tls/certs`. The new collector records such a root as an alias of its
  target when the target is another allowlisted root, which is read in its own right. Otherwise the
  root reads `unreadable`, reason `root_is_link`.
- A symlink entry is never opened. Its link text is read with `readlinkat` and resolved lexically
  against the link's own directory. A chain of links is resolved the same way, hop by hop, up to 8
  hops; a loop, a dangling hop or a ninth hop ends resolution. A directory component that is itself
  a link is not resolved, so a target reached only through one does not match.
- A link becomes a location of a certificate **only when the walk itself read a certificate at the
  resolved target path**, with its own `O_NOFOLLOW` open of a regular file inside an allowlisted
  root. Debian's hash links into `/usr/share/ca-certificates/` and Arch's links into
  `/etc/ca-certificates/extracted/` qualify, so they deduplicate.
- Any other link makes its store `constrained`: reason `link_outside_roots` when the resolved
  target is outside every root, `link_unresolved` for a loop, a dangling or over-long chain, or a
  target the walk did not read. The store never reads `ok` while a link it holds went unread.
- **Key blocks: discarded unretained, never decoded.** The collector frames each file line by line
  itself; it never hands a whole file to `PEM_read_bio_X509`, which would base64-decode a key
  block before discarding it. Lines inside a block whose armour label is not `CERTIFICATE` or
  `TRUSTED CERTIFICATE` (for example `PRIVATE KEY`, `RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`)
  are discarded as they are framed: never copied out of the read buffer, never base64-decoded,
  never parsed, never logged, and counted only as `non_certificate_block`. The read buffer that
  held them is cleansed before release. This is the exact property. D6's wording, "the collector
  never opens ... key blocks in PEM files" (`0070:630`), cannot hold literally for a mixed file,
  whose bytes are read as one file; so this design asks #6125 to word D6 as the property above (see
  the owed items under [Phasing and PR order](#phasing-and-pr-order)). The design does not edit
  the ADR.
- A root on, under or containing a network mount is not opened. This is the `runtimes` guard
  (`agents/shared/network_fstype.hpp`), with the same disclosed residuals.
- Slice 2 adds no delete. Any later certificate mutation inherits today's rule: a delete removes
  the directory entry, which for a symlinked bundle entry is the link, never its target
  (`certificates_linux_store.hpp:331-336`, `:431`).

### Fields collected

**Decided:** raw X.509 facts only (ADR-0070 placement table, `0070:253`). Validity is stored in
UTC to the second, unclamped, with RFC 5280's `99991231235959Z` sentinel kept (D4, `0070:410-413`).
For RSASSA-PSS the PSS hash parameter is recorded. For EC keys the named curve is recorded, so the
bit length of the curve's group order n is known (D12, `0070:915-922`). SHA-1 is display only
(D12, `0070:1004-1006`).

**Proposed field list.** Unknown is a distinct value from empty, everywhere (see
[blob contract](#blob-contract)).

| Field | Type | Notes |
|---|---|---|
| `sha256` | 64 hex | SHA-256 of the whole DER. The row identity (D12). |
| `sha1` | 40 hex | SHA-1 of the whole DER, display only. Equals today's `thumbprint`. |
| `tbs_sha256` | 64 hex | SHA-256 of the DER `tbsCertificate`, so the signature is excluded. This is the digest CycloneDX 1.7 `fingerprint` defines ("a cryptographic hash of the certificate excluding it's signature", `bom-1.7.schema.json` as vendored by #6143, now on `dev`). The whole-DER SHA-1 cannot fill that field, and schema validation would not notice if it did. |
| `version` | int | X.509 version. |
| `serial` | hex | Canonical: the unsigned big-endian magnitude, uppercase, no leading zero bytes. A negative (non-conforming) serial is flagged `serial_negative`. Equal canonical text means equal integers, which is how D5 compares serials. Today's Windows leg reverses bytes for display (`certificates_plugin.cpp:283-292`); the new field does not. |
| `subject_dn`, `issuer_dn` | UTF-8 text | The full DN in RFC 4514 order, from the DER on every OS. Today's Windows leg reads a simple display name (D6 gap). |
| `subject_name_sha256`, `issuer_name_sha256` | 64 hex | SHA-256 of the Name DER exactly as encoded. Equality of these is DER Name equality, which D5's matching rule needs (`0070:525`). |
| `not_before`, `not_after` | RFC 3339 UTC, seconds | `YYYY-MM-DDTHH:MM:SSZ`. UTCTime years are mapped per RFC 5280 (50–99 → 19xx). Pre-1970 and year-9999 values are kept. |
| `key_alg_oid` | OID | `subjectPublicKeyInfo` algorithm. |
| `rsa_modulus_bits` | int | RSA keys only. |
| `ec_curve_oid` | OID | Named-curve EC keys. |
| `ec_order_bits` | int | Bit length of the group order n, computed by the agent from the curve parameters. It is also recorded for explicit-parameter curves, which have no OID. |
| `sig_alg_oid` | OID | The certificate's `signatureAlgorithm`. |
| `pss_hash_oid`, `pss_mgf1_hash_oid` | OID | RSASSA-PSS only, from the algorithm parameters. |
| `spki_sha256` | 64 hex | Key identity. It stays stable only when a certificate is re-issued over the same key; key rotation changes it. It is never used as a certificate identity, a lifecycle join key or a "same certificate" rollup. |
| `ski`, `aki_key_id` | hex | Subject and authority key identifiers. `aki_key_id` comes from the AKI `keyIdentifier` only. |
| `is_ca`, `path_len` | bool / int | Basic constraints. |
| `key_usage` | bit names | As today. |
| `eku_oids` | OID list | Capped (below). |
| `sans` | list of (type, value) | Types `dns`, `ip`, `rfc822`, `uri`, `upn` (otherName `1.3.6.1.4.1.311.20.2.3`), `dirname`, `other` (OID only, no value). Capped (below). |
| `crl_dp_uris` | URI list | From the CRL distribution points extension. Collected only so the server can test a partitioned CRL's scope (D5 condition 2). **Never fetched** by anything (D5, `0070:579-582`). Capped. |
| `self_signed` | bool | Subject DER equals issuer DER **and** the signature verifies under the certificate's own key, computed by the agent (ADR-0070 field table, `0070:220`). |
| `der` | base64, optional | Shipped so the server can verify signatures itself (D5, `0070:545-546`). See the DER budget below. |
| key association | see next section | |
| `locations` | list | Each location is (`store_id`, `path` or empty). A path is a machine path such as `/etc/ssl/certs/ca-certificates.crt`. |

Today's plugin collects none of key algorithm, size, signature algorithm, SANs, EKU, basic
constraints or a SHA-256 fingerprint, and keeps dates as `YYYY-MM-DD`
(`certificates_x509.hpp:140-148`). That is the D6 field gap (`0070:668-669`).

**The DER budget (Proposed).** DER is shipped for a certificate that is not self-signed and whose
DER is at most 16 KiB, up to 1 MiB of DER per blob. A self-signed root is not shipped, because no
other CA's CRL can revoke it, and D5's statement does not apply to it. A certificate with no
shipped DER carries `der_omitted` = `self_signed`, `oversize` or `budget`. The server cannot verify
its signature, so its revocation statement uses the "matched by issuer and serial" basis
(`0070:539-546`). Where DER is present, the server re-parses it and uses the server-parsed facts. A
disagreement with the agent's claimed fields is counted
(`yuzu_server_cert_inventory_claim_mismatch_total`), and the server's values are stored.

### Private-key metadata

**Decided (ADR-0070 D6, `0070:622-630`; placement table, `0070:254`):** metadata only. Never read
key material. Never acquire or open a key to find these things out. On Windows, never call
`CryptAcquireCertificatePrivateKey` or open a key-storage-provider handle. On Linux, never open
private-key directories or PEM key blocks. Windows export policy is not collected unless the design
shows a way that opens no key.

**Proposed:**

| OS | `key_association` | `key_provider` | `key_exportable` |
|---|---|---|---|
| Windows | `present` when `CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID)` returns a value; otherwise `none`. | The provider name from that property, raw, for example `Microsoft Platform Crypto Provider` or `Microsoft Smart Card Key Storage Provider`. | Not collected: `unknown`. |
| macOS | `present` when a SecItem identity query on the System keychain matches the certificate, asking for attributes only (never `kSecReturnRef` on a key, never `kSecReturnData`); otherwise `none`. | `unknown` | `unknown` |
| Linux | `unknown`: there is no association to read without opening key files. | `unknown` | `unknown` |

- The provider name is reported raw, not mapped to "hardware-backed". A mapping table would be a
  Yuzu classification. Whether to add one is open decision 5 (see [Decisions](#decisions)).
- Every response says that an associated key "may since have been deleted" (placement table).
- The macOS identity query must be shown, in the implementing PR, to raise no keychain prompt and
  evaluate no key ACL when run as the agent daemon. If it cannot be shown, macOS reports `unknown`.

### Deadlines and caps

**Decided (ADR-0070 D12 "Untrusted input", `0070:969-975`):** the source inherits ADR-0016's ingest
caps and adds per-certificate bounds on SAN and EKU counts. Collection is deadline-bounded.

**Proposed:**

| Bound | Value | When hit |
|---|---|---|
| Whole action | 60 s, as `kCertActionBudget` (`certificates_plugin.cpp:1032`) | Every store not yet finished reads `constrained`, reason `deadline`. |
| macOS SecItem read, per keychain | 15 s, as `kSecItemReadDeadline` (`certificates_plugin.cpp:1031`) | That keychain reads `constrained`, reason `deadline`. |
| Certificates per store | 2,000, as `kMaxCertsPerKeychain` / `kMaxKeychainReadCerts` (`certificates_plugin.cpp:1033`, `agents/core/include/yuzu/agent/keychain_read.hpp:80`) | Store `constrained`, reason `row_cap`. |
| Stores per device | 64 | Device `constrained`, reason `store_cap`. |
| Certificates per blob | 10,000 distinct `sha256` | Device `constrained`, reason `row_cap`. |
| Blob bytes | 3 MiB, the largest existing ingest cap (`server/core/src/inventory_ingestion.cpp:35`), under the 4 MiB gRPC ceiling; `LocalDispatcher` capture cap 3.5 MiB, as `kInventoryCaptureCap` (`sync_source_installed_software.cpp:479`) | Deterministic cut (see [Blob contract](#blob-contract)): every store whose records do not fit reads `constrained`, reason `byte_cap`, and its server-side rows are kept. **Never** a silently cut blob. |
| DER per blob | 1 MiB; 16 KiB per certificate | `der_omitted=budget` or `oversize`. |
| SANs per certificate | 64 entries, 256 bytes each | Certificate `constrained`, `sans_truncated=true`. |
| EKUs per certificate | 32 | Certificate `constrained`, `ekus_truncated=true`. |
| CRL DP URIs per certificate | 8, 512 bytes each | Certificate `constrained`, `crl_dps_truncated=true`. |
| DN length | 1,024 bytes after RFC 4514 rendering, the field cap the existing ingest seams use (`inventory_ingestion.cpp:37`) | Certificate `constrained`, field marked truncated. |
| Linux file size | 4 MiB per file; 2,000 PEM blocks per file; 5,000 entries visited per root | Store `constrained`, reasons `file_cap`, `block_cap`, `entry_cap`. |

The server enforces the same caps at its ingest seam. As `app_usage_ingestion.cpp:35-36` notes, a
one-sided cap makes the agent send and the server drop in a tight loop.

### The D6 collection gaps, closed or disclosed

**Decided (ADR-0070 D6, `0070:663-682`):** the design covers the gaps the ADR found.

| Gap (ADR-0070 D6) | Slice 2 |
|---|---|
| No key algorithm, size, signature algorithm, SANs, EKU, basic constraints or SHA-256 fingerprint; SHA-1 only | **Closed** by the field list above. |
| Windows: subject and issuer are a simple display name | **Closed**: the full RFC 4514 DN from the DER. |
| Windows: only four LocalMachine stores | **Closed**: every enumerated store in three machine locations. |
| Windows: CurrentUser fallback when LocalMachine cannot be opened | **Closed**: no fallback. The store reads `unreadable`. |
| Linux: only `/etc/ssl/certs` | **Closed** for the listed distribution roots. **Disclosed**: Java `cacerts`, PKCS#12, `.p11-kit`, NSS and application stores are not read, and every read names them. |
| Linux: first certificate per file | **Closed**: every block (the current first-only behaviour is `certificates_linux_store.hpp:294-296`). |
| macOS: the login keychain through a subprocess in the console user's session | **Closed for the sync**: the machine allowlist excludes it. A per-user opt-in would revisit it; the owner has decided per-user stores are not in slice 2 (see [Decisions](#decisions)). |

## The daily-sync source

### Name and placement

**Proposed:** the source is `certificate_inventory`, a new `plugin_data` key with no proto change
(ADR-0016's sync-source pattern). It runs daily, with the framework's per-agent phase offset,
need_full jitter and weekly full floor (`docs/adr/0016-agent-daily-sync-framework.md` §3–§4).

### Blob contract

**Decided (ADR-0070 D12 "Honest capture", `0070:996-1001`):** a capped or timed-out capture is
`constrained` and never an empty success. An empty blob is never sent for a failed or constrained
capture. A field an older agent did not send reads as unknown, never as empty, and the blob is
versioned.

**Proposed.** The blob is pipe-delimited records, one per line, in a fixed order (below). The
server parses it with its own escape-aware splitter, following the pattern `sync_source_app_usage`
uses of a source-local splitter (`agents/core/src/sync_source_app_usage.cpp:34-72`), but **not**
its scanner: `find_unescaped_pipe` treats a pipe as escaped whenever the byte before it is `\`,
so it misparses `\\|` (an escaped backslash followed by a real delimiter). This source requires a
**stateful** scanner that walks left to right, consuming each `\` together with the byte after it,
so a delimiter is any `|` not consumed that way. The grammar, for this source only, is fully
reversible: `\\` is a literal
backslash, `\|` a literal pipe, `\n` and `\r` literal LF and CR. Every field is framed this way,
so store IDs such as `LocalMachine\Root`, RFC 4514 DNs with their own `\,` escapes, paths and SAN
values round-trip byte for byte. `yuzu::util::safe_output_field` is **not** used anywhere in this
blob: it is documented as intentionally lossy, folding a literal `\` to `/` and CR/LF to spaces
(`sdk/include/yuzu/string_utils.hpp:87-111`), so it would alter exactly the identity fields
(store IDs, DNs, paths, serials, SANs) that rows are keyed and matched on. A round-trip test pins
the grammar on both sides, including a value ending in `\` (encoded `\\` before the delimiter), a
value containing `\|`, and a value containing `\\|`; a trailing unpaired `\` at the end of a
record is a parse error, never silently kept.

**What ingest does with a parse error (Proposed).** A record-level parse error (a trailing unpaired
`\`, a wrong field count, a malformed field) refuses **only that record**. The store it belongs to
reads `constrained`, reason `parse_error`, and keeps its rows exactly as for any `constrained`
store (keep-unreported; counted in `from_kept_rows`), and its `status_at` advances. The rest of the
blob ingests and the blob is **acked**, so the agent neither resends it forever nor hides it: the
stored status stays `constrained`/`parse_error`, and every hash-skip replay of the same bytes keeps
it visibly `constrained` until the agent sends a blob that parses. A record that cannot be tied to
a store is refused and counted, and the whole report's stores read `constrained`/`parse_error`. An
unparseable header (the `ver|` line or a `store|` header record) still nacks the blob, as an
unknown major version does (see "Version" below).

```
ver|1
store|<store_id>|<scope>|<status>|<reason>|<cert_count>
cert|<sha256>|<sha1>|<tbs_sha256>|<version>|<serial>|<subject_dn>|<issuer_dn>|...
loc|<sha256>|<store_id>|<path>
san|<sha256>|<type>|<value>
eku|<sha256>|<oid>
cdp|<sha256>|<uri>
der|<sha256>|<base64>
```

- **Record order, and the byte cut.** Records are ordered by store, in a fixed order: stores sorted
  by `store_id` (bytewise), and within a store its `store|` record, then its certificate records
  sorted by `sha256`, each certificate's `loc|`, `san|`, `eku|`, `cdp|` and `der|` records
  immediately after its `cert|`. Every `store|` status record is written first, in a header section
  ahead of all certificate records, so it always fits. If the next store's whole record group would
  push the blob past the byte cap, that store **and every store after it** are not emitted beyond
  their header record, which reads `constrained`, reason `byte_cap`. A store is never cut part-way.
  The same inventory therefore always produces the same bytes (hash-skip holds), and a store past
  the cut keeps its server-side rows (ingest treats `constrained` as keep-unreported, see
  [Ingest](#ingest)) instead of ageing to `not_observed`.
- **Version.** `ver|1` is the first line. The server refuses an unknown major version with a nack,
  so the agent keeps its last good report and does not loop. It parses a newer minor version's extra
  fields as unknown.
- **Unknown versus empty.** A field an older agent's record does not have reads as NULL (unknown)
  on the server. A field the agent could not determine is sent as the literal `?` and also stored
  NULL. An empty field is a real empty value: for example, an empty SAN list is sent as no `san|`
  records together with `cert|...|sans=0`. A count of zero is an explicit 0; it never means "not
  collected".
- **Store status.** Every store the allowlist names gets exactly one `store|` record:

  | Status | Meaning | Reason tokens |
  |---|---|---|
  | `ok` | Read completely. | none |
  | `absent` | The store or root does not exist on this device, confirmed by a successful read of its parent. | none |
  | `unreadable` | Could not be read at all. | `open_failed:<errno or HRESULT>`, `permission_denied`, `network_mount`, `enum_failed`, `root_is_link` |
  | `constrained` | Partly read: a cap, a deadline, a partial enumeration or an unread link. | `deadline`, `row_cap`, `byte_cap`, `store_cap`, `file_cap`, `block_cap`, `entry_cap`, `enum_partial`, `parse_error` (server-side), `link_outside_roots`, `link_unresolved`, `third_party_provider` |
  | `not_observed` | Server-side only. The store was in an earlier report and is missing from this one. The agent never sends it. | `missing_from_report` |

  Reason tokens go through the shared `yuzu::shared::ConstraintAccumulator`
  (`agents/shared/constraint_accumulator.hpp`). The plugin's result status is `CONSTRAINED` if any
  store is `unreadable` or `constrained`.
- **Never empty; status-only when nothing could be read.** If every store is `unreadable`, the
  source sends a **status-only blob**: `ver|1` and one `store|` record per store, with no `cert|`
  records. That is not an empty blob, because it carries each failure and its reason, and ingest
  records every store as `unreadable` while keeping its rows. It meets ADR-0016's `app_usage`
  clause 4 ("never send an empty blob for a constrained capture") in substance. Skipping the cycle
  instead would leave the last `ok` status standing on the server. The source skips the cycle only
  when the action fails before it can name any store (for example, the plugin fails to load); the
  read then shows each store's `status_at` ageing. A device whose stores are all genuinely `absent`
  sends the `store|` records and no `cert|` records, and the read says "none found at the listed
  stores", never "no certificates".
- **No clock in the blob.** The blob carries no agent timestamp. Freshness is server receipt time
  (#1685), so agent clock skew cannot reach any stored time (CH-5).

### Hash-skip

**Proposed:** raw-byte hashing, the `app_usage` approach. The server recomputes SHA-256 over the
received blob bytes and stores that hash, never the agent's claim (ADR-0016 §4 "Hash trust").
Deterministic sorting makes the hash stable. Raw-byte hashing avoids canonical reconstruction's
"field set differs, so the hash never matches" loop (ADR-0016's "Known inherited property").

A hash-skip report means "byte-identical to the last full report", store records included. On a
skip, the server advances `observed_at` for every store whose stored status is `ok` or `absent`,
and leaves it alone for `unreadable` and `constrained` stores. For every store the last full report carried, a skip
also advances `store_state.status_at`, but advances `cert_location.last_seen` **only for the
locations that last full report carried**, never for locations kept from earlier reports in a
`constrained` store. The ingest records `agent_state.last_full_at` and marks each location with
the `last_full_at` of the report that carried it, so a skip refreshes exactly that set. Kept,
unreported locations therefore still age, and the location-grain prune can fire. A buggy agent that wrongly reports
"unchanged" is bounded by the weekly full floor, as ADR-0016 accepts.

### Per-user scope

**Decided (ADR-0070 D12 "Identity", `0070:1019-1036`):** per-user rows have their own replace scope,
keyed by device and a per-agent keyed pseudonym (`user_ref`, ADR-0024 D11,
`HMAC-SHA256(k_agent, profile)`), never a raw SID, uid or username. A per-user location is relative
to the profile. A user not read this run is `not_observed`, never an empty store.

**Proposed:** none of this is built in slice 2, because per-user stores are not read. The blob and
the store reserve it so a later opt-in is additive: `store|` carries `<scope>` = `machine`, and
the store's keys carry a `user_ref` column that is empty for machine rows. The per-agent key
already exists for `software_licensing` (`agents/core/src/sync_source_software_licensing.cpp:146-172`).
A test asserts that a slice-2 report never produces a row with a non-empty `user_ref`.

## Server: store, ingest and lifecycle

### Store and schema

**Decided:** a typed store, Postgres-born (ADR-0006), under the ADR-0012 author contract
(`docs/postgres-store-playbook.md`). Rows are keyed by (device, store/location/path, SHA-256), plus
the per-user identifier for per-user rows. Every count is of distinct (device, SHA-256). Every row
carries the server-receipt `last_seen`. Each store has its own `observed_at` (ADR-0070 D12,
`0070:977-1038`).

**Proposed:** `CertificateInventoryStore`, schema `cert_inventory`. All `*_at` and `*_seen`
columns are `TIMESTAMPTZ` set from `now()` in SQL. Certificate validity columns are `TIMESTAMPTZ`
from the certificate. Postgres covers 4713 BC to 294276 AD, so pre-1970 and year-9999 dates fit
unclamped.

| Table | Key | Columns (beyond the key) |
|---|---|---|
| `agent_state` | `agent_id` | `content_hash`, `blob_version`, `first_seen`, `last_seen` (receipt of any report, full or skip), `last_full_at` (receipt of the last full report) |
| `store_state` | (`agent_id`, `store_id`, `user_ref`) | `scope`, `status`, `reason`, `observed_at` (receipt of the last report in which the store read `ok` or `absent`), `status_at` (receipt of the last report that carried this store), `cert_count` |
| `cert_location` | (`agent_id`, `store_id`, `user_ref`, `path`, `sha256`) | `first_seen`, `last_seen`, `full_report_at` (the `last_full_at` of the full report that last carried it) |
| `decommission_tombstone` | `agent_id` | `decommissioned_at` |
| `cert_fact` | (`agent_id`, `sha256`) | every field in the field table, `der` (nullable), `server_parsed` (bool), `constrained_fields` |
| `cert_san` | (`agent_id`, `sha256`, `ord`) | `san_type`, `value` |
| `cert_eku` | (`agent_id`, `sha256`, `ord`) | `oid` |
| `cert_cdp` | (`agent_id`, `sha256`, `ord`) | `uri` |

**Indexes:** `cert_fact (not_after)`, `(not_before)`, `(issuer_name_sha256, serial)`,
`(sig_alg_oid, pss_hash_oid)`, `(key_alg_oid, rsa_modulus_bits)`, `(ec_order_bits)`, `(sha256)`,
`(spki_sha256)`, `(aki_key_id)` (see [Finding one CA's certificates](#finding-one-cas-certificates));
`store_state (status, observed_at)` for the prune; every table has `agent_id` leading its key, for
decommission and confinement.

A `cert_fact` row exists while at least one `cert_location` row references it. The ingest
transaction deletes orphaned facts. Engine-facing reads join `cert_fact` to its locations, so every
response presents one entry per (device, certificate), with its locations as a list, as D12
requires (`0070:1013-1016`).

**Schema lint (Decided, ADR-0070 D13 "Mechanical checks", `0070:1324-1325`):** no column is named
after a D13 rule id or window field, or `days_remaining`. 2a-2 adds the lint over every migration
in this store's migration array.

### Ingest

**Proposed:** one shared ingest seam, `certificate_inventory_ingestion.cpp`, for the direct
`ReportInventory` and gateway `ProxyInventory` paths (ADR-0016 §5). It runs in one transaction per
report, holding a per-agent row lock on `agent_state`, so concurrent replaces for one agent
serialise as the software store's do. Per store:

| Status in this report | What happens to that store's rows | `observed_at` |
|---|---|---|
| `ok` | Replaced: the store's locations become exactly those reported. | Set to `now()` |
| `absent` | All the store's locations removed. | Set to `now()` |
| `constrained` | Reported locations upserted. Unreported locations **kept**, since a partial read cannot prove a removal. | Unchanged |
| `unreadable` | Untouched. | Unchanged |
| missing from the report (stored, not reported) | Untouched; status becomes `not_observed` from this first omission (D12, `0070:989-991`). | Unchanged |

**No rows for a decommissioned agent (Proposed).** Ingest writes nothing for an agent that has
been decommissioned: the check runs inside the ingest transaction, against a decommission tombstone
that `delete_agent` writes in the same transaction as the erase (or an equivalent registry check;
the PR chooses). A report from such an agent is acknowledged, writes no row, and is counted
(`reason=decommissioned`).
- **No race.** Ingest and `delete_agent` both take the same per-agent lock first, for example
  `pg_advisory_xact_lock` on a hash of the agent id, so a decommission cannot commit between the
  ingest's tombstone read and its commit.
- **What decommission does today (verified).** The decommission cascade erases seven data stores
  and no auth store (`server.cpp:10019-10029`, `agent_decommission.hpp:117-125`); the only
  `pending_agents` delete is pending-only (`auth_db.cpp:2765`). So an approved agent's enrolment
  record survives decommission. If that agent is still running, it re-registers through the
  already-approved path (`agent_service_impl.cpp:206`), which writes nothing to the enrolment
  store, and **it stays tombstoned**.
- **Clearing the tombstone.** The tombstone is cleared inside any enrolment-store write that moves
  the agent to approved:
  - the token path, `AuthDB::consume_and_enroll` (`auth_db.cpp:2380`), from direct `Register`
    (`agent_service_impl.cpp:309`) and gateway `ProxyRegister` (`gateway_service_impl.cpp:783`);
  - auto-approve, `AuthDB::ensure_enrolled` (`auth_db.cpp:2570`), from `Register`
    (`agent_service_impl.cpp:492-530`, the call at `:510`) and `ProxyRegister`
    (`gateway_service_impl.cpp:959`);
  - admin approval, `AuthDB::approve_pending` (`auth_db.cpp:2698`), via
    `AuthManager::approve_pending_agent` (`auth.cpp:2750`) from `settings_routes.cpp:5462`;
  - bulk approval, `AuthDB::approve_all_pending` (`auth_db.cpp:2737`, the `UPDATE` at `:2721`), via
    `AuthManager::approve_all_pending_agents` (`auth.cpp:2762`) from `settings_routes.cpp:5382`;
  - the legacy enrolment import, `AuthDB::import_legacy_pending`
    (`enrollment_cfg_import.cpp:354`), for a row it imports as `approved`.

  Because an approved record survives decommission, none of these runs for an agent that was
  approved before it was decommissioned. **For such an agent the audited admin purge (below) is the
  only way back.** These writes are in the `auth` schema and the tombstone is in
  `cert_inventory`, so the clear is cross-schema SQL with its own named query owner (see
  [The store](#the-store)). Each site is checked by a test that approves a tombstoned agent through
  it and asserts the tombstone is gone.
- **A live agent decommissioned in error drops out silently.** Its reports are acknowledged and
  discarded, so it vanishes from every certificate read and count while it is still connected. The
  visible signal (Proposed): when the caller passes the administrator predicate, every certificate
  read and count response, REST, MCP and dashboard, carries
  `coverage.tombstoned_agents_registered`, the number of tombstoned agent ids that are currently
  registered and connected, and the dashboard shows it whenever it is above zero. **For any other
  caller the field is absent**, not zero: it is a fleet-wide figure, and serving it to a confined
  `CertificateInventory:Read` holder would disclose a count of agents outside its confinement
  (ADR-0070 D12). Absent means "not shown to you", never "none". An
  administrator lists them with `GET /api/v1/crypto/certificates/tombstones` (admin-only, audited
  `crypto.certificates.tombstones.view`, MCP `list_certificate_tombstones`), each with its
  `decommissioned_at` and whether it is connected, and purges one with the route below.
- **Retention:** a tombstone has no age-based prune, because a decommissioned agent that is still
  running would otherwise repopulate its rows once the tombstone aged out. It is one small row
  (`agent_id`, `decommissioned_at`) per decommissioned agent. It is removed by the audited,
  admin-only purge (`DELETE /api/v1/crypto/certificates/tombstones/{agent_id}` and MCP
  `purge_certificate_tombstone`, audit verb `crypto.certificates.tombstone_purge`, failing closed;
  its permission is `CertificateInventory:Write` behind the administrator predicate, OD-4), or by a fresh enrolment of a not-yet-approved agent id. See
  [Personal data](#personal-data).
- **Tests:** decommission an agent, replay its last full report on both the direct and gateway
  paths, and assert zero rows in every table; and the interleaving where `delete_agent` commits
  between an ingest's tombstone read and its commit, which must end with zero rows.

UTF-8 is validated at the seam. Invalid bytes are replaced, with `sanitize_utf8`
(`sdk/include/yuzu/string_utils.hpp:32`), and the field is marked. A record over a cap is refused,
never truncated silently. Refusals are counted on
`yuzu_server_cert_inventory_ingest_total{result,reason}`, with the reason label from a closed set that includes `parse_error`.

### Typed set, purge and read filter

**Decided (ADR-0070 D12 "Lifecycle", `0070:1043-1052`):** the source joins the typed set, with a
test. Stray rows in the generic store must never be readable, which needs both a read-time filter
that excludes typed sources and membership of the boot-time purge, tested against the typed set.
App-usage's accepted mixed-version window is not acceptable for this source.

What exists today:
- The typed set is a hand-written predicate (`typed_inventory_sources.hpp:23-36`).
- The gateway generic loop skips it (`gateway_service_impl.cpp:1803-1811`).
- The boot purge is a **second, hand-written list** (`server.cpp:7612-7621`). It calls
  `InventoryStore::delete_source` (`inventory_store.hpp:183-193`) for each name.
- The generic reads `list_tables`, `get` and `query` (`inventory_store.cpp:258`, `:304`, `:345`)
  have no typed-source filter. The routed concern for the app-usage read surface records that as an
  accepted gap.

**Proposed (PR 2a-1):**
- `typed_inventory_sources.hpp` exports `inline constexpr std::array kTypedInventorySources`. The
  predicate (and so the gateway skip), the purge and the read filter all iterate it, so there is
  one list.
- The array includes `certificate_inventory` from 2a-1, before the source or its store exists. Its
  only effects then are the gateway skip and the read filter, which is what closes the window for
  servers at 2a-1 or later (see [Phasing](#phasing-and-pr-order)). 2a-2 adds the seam behind it.
- `InventoryStore::get`, `query` and `list_tables` exclude every typed source in SQL
  (`plugin <> ALL($1)`).
- **The purge starts at boot but no longer blocks it.** The batched background pass (bounded rows
  per batch, classified in `background_jobs.hpp`) is started at every boot, so typed sources stay
  members of the boot-time purge ADR-0070 D12 requires (`0070:1049`). What changes is that the
  server does not wait for it to finish before serving, instead of one unbounded `delete_source`
  per name during boot (`server.cpp:7612-7621`). The read filter makes that deferral safe: a row
  the pass has not reached yet is already unreadable.
- Tests: the purge's list is the typed set; an inserted typed-source row is invisible to all three
  reads; the gateway skip drops a `certificate_inventory` blob on a 2a-1 server.

This also closes the window `app_usage` and `device_ci` accept today. That is a behaviour change for
those two sources (stray rows stop being readable under `Infrastructure:Read` / `Inventory:Read`).
2a-1 amends the app-usage read-surface routed-concern row in the same change (its accepted
mixed-version window becomes closed), and ships a changelog fragment and the `upgrading.md` note.

### Decommission and readiness

**Decided (ADR-0070 D12 "Lifecycle", `0070:1041-1042`, `:1053`):** the store joins
`AgentDecommissionStores` and its drift guard in the same change, and `/readyz` covers it.

**Proposed:**
- Add `CertificateInventoryStore* certificate_inventory` to `AgentDecommissionStores`
  (`agent_decommission.hpp:117-125`), following that header's standing rule (`:17-26`): register
  it in `agent_decommission.cpp`, bump `kCascadeStoreCount` in `test_agent_decommission.cpp`, and
  add it to the blast-radius lists in `sle_routes.hpp`/`.cpp`, the `rest_api_v1.cpp` delete block,
  ADR-0024 Decisions 9/11 and `rest-api.md`. `delete_agent` removes every table's rows for the
  agent in one transaction.
- Add `{"certificate_inventory_store", ...is_open()}` to the readiness list in `health_routes.cpp`
  (the `app_usage_store` row at `:729` is the template). In 2b-1, add `revocation_source_store`.
  Rationale, as for `app_usage_store` (`health_routes.cpp:722-728`): the store is constructed
  fail-closed at boot on the server's one PgPool, and a store that failed to open would make ingest
  acknowledge the blob with no rows and every certificate read answer 503. `/readyz` makes that
  boot state visible instead of leaving it to per-request 503s.

### Retention and the prune

**Decided (ADR-0070 D12 "Honest capture", `0070:986-995`):** kept rows are pruned only when both
hold: the store's latest report says `unreadable` or `not_observed`, and its `observed_at` is older
than a stated bound. Age alone never prunes. The prune follows the clock-guarded-retention routed
concern. The design states how a pruned store's rows are re-sent despite hash-skip.

**Proposed:**
- **Bound:** 30 days.
- **Predicate:** `status IN ('unreadable','not_observed') AND observed_at < now() - interval '30
  days'`.
- **A store that stays `constrained`.** Its reported locations refresh on every report; a location
  it stops reporting is kept, because a partial read cannot prove a removal. Without a rule those
  kept locations would grow for ever. Rule (Proposed): such a location is treated as not observed
  at location grain once it has been missing from every report the server received over 30 days,
  that is, when `store_state.status_at - cert_location.last_seen > 30 days`, and the same pass
  prunes it. Both times are server receipt times. An offline device sends no reports, so its
  `status_at` stops and nothing of its is pruned: age alone still never prunes. D12 states the
  prune condition at store grain, so this location-grain reading is listed under
  [Decisions](#decisions) (open decision 6) for confirmation.
- **Mechanics:** a single-writer pass under `pg_advisory_xact_lock`, capped per pass (500 stores).
  For each agent it prunes, it also takes the same per-agent lock that ingest and decommission take
  (see [Ingest](#ingest)) and rechecks the prune predicate under it, so a fresh ingest that
  refreshed the store between selection and delete is never undone. It follows the seven parts of
  `docs/clock-guarded-retention.md`, and the per-store adoption register records each part's
  decision. The cutoff reads Postgres `now()`, not the replica clock.
- **Re-send:** the same transaction that prunes a store clears `agent_state.content_hash` for that
  agent. The agent's next report then mismatches, the server answers `need_full`, and the agent
  resends the full blob. If the store has come back, its rows return on that report.
- **An offline device** sends no reports, so its stores keep their last status and are never
  pruned. Its rows stay until decommission, shown "last observed" at their `observed_at`. A
  fleet-wide outage behaves the same way.
- **Metrics:** `yuzu_server_cert_inventory_pruned_total{grain}` (`store`, `location`) and
  `yuzu_server_cert_inventory_prune_capped_total`, which counts passes that stopped at the per-pass
  cap.

### Background jobs

**Decided (ADR-0070 D12, `0070:945-946`, `:1054-1055`):** any new job is classified in
`background_jobs.hpp`, and the CRL refresh job is leader-gated.

**Proposed:**

| Pass | Class (`background_jobs.hpp:84-88`) | Why |
|---|---|---|
| `cert_inventory_store.run_retention_prune` | `ReplicaSafe` | Advisory-lock single-writer retention, the `execution_tracker.reap_command_execution_mappings` precedent (`background_jobs.hpp:118-119`). |
| `revocation_source.refresh` (2b-1) | `FencedLeaderOnly` | Network egress that would otherwise run once per replica. The dispatch site is wrapped in `leader_gate_permits` (`leader_gate.hpp`) and carries `YUZU_ASSERT_BACKGROUND_JOB`, as the header requires (`background_jobs.hpp:27-32`). `ca.publish_crl` is the nearest precedent (`:212`). |
| `revocation_source.verify_certificate_signatures` (2b-2) | `ReplicaSafe` | An idempotent upsert of a pure function of (certificate DER, registered key). It reads both schemas, so it runs through the named cross-schema query owner (see [The store](#the-store)). |
| `typed_inventory_purge` (2a-1) | `ReplicaSafe` | The batched purge of typed-source rows from the generic store: an idempotent bounded delete. |
| `cert_inventory.fleet_store_status` (2a-2) | `ReplicaSafe` | A read-only fleet gauge sweep, like the existing inventory-freshness gauge (`background_jobs.hpp:209`). |

A replica that loses leadership clears the gauges only the refresh job sets
(`yuzu_server_crl_scopes_past_next_update`, `yuzu_server_crl_url_last_success_age_seconds`), so a
demoted replica never keeps exporting a stale value beside the new leader's.

Correctness of the refresh does not rest on the leader gate. The store's anti-rollback
compare-and-set (below) makes a second fetcher harmless, so the gate only removes duplicate
egress. The test count tripwire in `test_background_jobs.cpp` is bumped by each PR that adds a pass.

## Read surface

### The securable

**Decided (ADR-0070 D12 "Read surface", `0070:875-900`):** a dedicated certificate securable that no
other surface uses. RBAC on: seeded only to Administrator plus any role the design names and
justifies, never granted through `Security:Read`, `Inventory:Read` or a seeded read-only role. RBAC
off: admin-only, by extending `authz_topology_floor.hpp`, never forking it. The entry fits that
header's class for preserving an existing admin-only posture.

**Proposed:**
- **Name:** `CertificateInventory` (decided by the owner, 2026-10-19).
- **Seeding:** add it to the securable-type array in `rbac_store.cpp` (`:567`, today 38 entries)
  and to `kRbacSecurables` in `mcp_server.cpp` (`:4749`). Administrator gets CRUD through the
  existing loop (`rbac_store.cpp:780-782`). No other role is seeded. `Read` gates every certificate read. `Write` gates the tombstone list and purge, behind the
  administrator predicate (OD-4).
- **Floor:** add `{"CertificateInventory", "Read"}` to `kTopologyFloor`
  (`authz_topology_floor.hpp:87-135`). **The entry fits none of the header's three inclusion
  classes** (`:54-63`), and the design does not pretend it does. It is not authorization topology
  or audit evidence. It is not an existing admin-only posture either: `CertificateInventory` is new
  data, and the output of today's `certificates.list` runs is readable now under `Response:Read`,
  by any signed-in user under RBAC off. So the same change **amends the header's inclusion test**
  with a fourth class, "a new fleet-wide copy of data that ADR-0070 D12 requires to be admin-only
  in both RBAC states", and says why. The `Forensics` entry (`:115-125`) is the nearest precedent:
  it too floors a new data class because its design requires admin-only reads, not because a
  previous gate was admin-only.
- **Service-scoped API tokens get 403 on both securables, in both RBAC states.** Under RBAC off,
  `require_fleet_read` refuses every service-scoped session (`authz_gates.cpp:220`). Under RBAC on,
  the ITServiceOwner authority ceiling refuses any pair that role does not hold
  (`authz_gates.cpp:233-236`), and neither securable is seeded to it. `RevocationSource` is also
  behind the administrator predicate, which a service token never satisfies. Why: a certificate
  inventory has no per-service slice to narrow to, and neither securable is in the seeded-empty
  `kServiceScopeGlobalSafe` (`service_scope_policy.hpp:38`); adding one would be a security
  decision.
- **Gate floors differ, so check each.** `require_fleet_read` applies the floor
  (`authz_gates.cpp:315`). `require_list_read` does **not**, and its own comment says a future
  floored securable routed through it "must re-apply the floor explicitly"
  (`auth_routes.hpp:407-413`). Every certificate read in this design is a per-device or
  device-filterable read, so it uses `require_fleet_read`. A later rollup that cannot be filtered,
  and so uses `require_list_read`, must re-apply the floor and carry a test proving it.

### Gates, confinement, denial text and errors

**Decided (ADR-0070 D12, `0070:901-905`):** the gate and the denial text take the securable as a
parameter. A denial names the permission actually required. On a page that shows both halves, a
denied certificate half says it was denied, never "no certificates".

**Proposed:**
- `CryptoRoutes` today calls `fleet_read_fn(req, res, "Inventory", "Read")` (`crypto_routes.cpp:165`)
  and hard-codes "Inventory:Read is required" (`:117-119`). 2a-2 makes both a per-surface parameter
  and passes `CertificateInventory` for every certificate surface. Slice 1's surfaces keep passing
  `Inventory`.
- Confinement is ADR-0017 admit-then-filter: the gate's visible-device set becomes a SQL
  `agent_id = ANY($n)` on every certificate query. Present-empty means deny-all, never "no filter"
  (the `dispatch_confined_arms` rule, `docs/authz-model.md`).
- Every REST error uses the A4 envelope, with `error.data` (`permission` on a 403, `retry_after_ms`
  on a retryable 503). Every MCP error path, including local ones (non-object arguments, an unwired
  gate, a parse error), returns an A4 `error.data`. This avoids the bare JSON-RPC errors the CBOM
  review found (cleanup stack Outstanding E).
- Per-caller responses carry `set_private_no_store` (`crypto_routes.cpp:74`).

### Audit and degrade

**Decided (ADR-0070 D12, `0070:906-907`):** each read is audited with its own verb, recording
fleet-wide or confined scope. A degraded read is a 503 with a retry hint, never an empty 200.

**Proposed audit verbs:**

| Verb | Surface | On audit-write failure |
|---|---|---|
| `crypto.certificates.view` | per-certificate read | REST: **fail closed**. Dashboard and MCP: set-and-proceed |
| `crypto.certificates.summary` | raw-value summary | as above |
| `crypto.certificates.counts` | D13 counts | as above |
| `crypto.cbom.export` | CBOM (extends #6143's verb, with a `halves=` detail) | as above, when the certificate half is included |
| `crypto.revocation_source.list` / `.view` | source list and detail | as above (Proposed) |
| `crypto.revocation_source.register` / `.update` / `.remove` / `.reset_high_water` | mutations | **fail closed** on every surface |
| `crypto.certificates.tombstone_purge` | decommission-tombstone purge | **fail closed** on every surface |
| `crypto.certificates.tombstones.view` | tombstone list (admin-only) | REST: fail closed. Dashboard and MCP: set-and-proceed |

- **REST certificate reads fail closed (owner decision OD-2).** They follow the behavioural-PII
  tier that `device_ci` uses, through `emit_behavioral_audit` in `server/core/src/rest_audit.hpp`
  (REST JSON fails closed, `:28-35`, `:188`): when the audit row cannot be written, the response is
  503 with `Sec-Audit-Failed` and a retry hint, and carries no data. Subjects and SANs can be
  personal data, which is why.
- **Dashboard fragments and MCP set-and-proceed**, as slice 1 does: the response carries the data
  and the lost row is visible, as the "Audit not recorded." notice in fragments
  (`crypto_ui.cpp:306`) and `audit_persisted: false` in the MCP envelope. This applies to failure
  rows too, closing #6122 item 1 for these surfaces. The revocation-source reads follow the same
  split (Proposed: they disclose internal hosts).
- **Mutations** fail closed: the platform posture is that mutations fail closed on audit failure
  (ADR-0033 D6, as restated in `docs/adr/0032-use-case-admission-protocol.md:892`). The route writes `result=requested` before the
  store mutation. If that write fails, it answers 503 with `Sec-Audit-Failed` and does not mutate.
  After the mutation it writes the outcome row (`success` or `failure`). If that second write
  fails, the header is set, and `audit-log.md` documents that a `requested` row with no outcome row
  means the outcome was not recorded, not that the change was not applied; the source's current
  state, from the list read, is then the record.
- Details record `scope=fleet|confined`, the **names and operators** of the filters applied (for
  example `issuer_dn=eq`, `not_after_before=lt`), never their values, the row count and the
  truncation flag. A filter value such as `issuer_dn` is free text that can carry personal data, so
  it never enters an audit row. Every other untrusted value that does goes through `log_token`
  (`common/include/yuzu/log_token.hpp:85`).
- The postures above need `docs/api-twin-recipe.md` §4 reconciled with `audit-log.md`
  (#6122 item 8). 2a-2 records this design's split there, so findings have one written basis, and
  adds every verb above to the `audit-log.md` catalogue.

### Admission

**Decided (ADR-0070 D12, `0070:909-910`):** reads, including read-time CRL matching, are admitted
through the existing `/crypto` read gate and degrade metric. Extend them; never fork them.

**Proposed:** every certificate store read leases from the one `CryptoReadGate` that
`LocalCryptoApi` owns (`crypto_read_gate.hpp:17`, `kMaxConcurrentCryptoReads = 2`). A shed calls
`note_read_shed()` as slice 1 does (`crypto_api.cpp:69-71`), so it counts on
`yuzu_inventory_read_degrade_total` and answers 503 with a retry hint. The bound stays 2. Libraries,
certificates, counts, the CBOM and the widgets then share two slots. 2a-3 measures shed rates under
the dashboard's polling, and any change to the bound is its own reviewed change.

### Truncation

**Decided (ADR-0070 D12, `0070:911-913`):** every capped read carries a named truncation flag. It
never looks complete, and never looks empty.

**Proposed, decided once for every certificate surface and the certificate CBOM.** This answers
FortitudeEtc's #6123 finding that `result_truncated` could be false on a truncated export:
- `result_truncated` is the OR of **every** cut in the response: page limit, row ceiling, byte
  budget, a per-entry list cap, and any `constrained` certificate or store in the result. It is
  never false while any cut happened.
- `truncated_parts` names each cut that happened: `page_limit`, `row_ceiling`, `byte_budget`,
  `locations_cap`, `sans_cap`, `constrained_store`, `constrained_certificate`.
- A response that is paged and complete across pages carries `next_cursor` and
  `result_truncated: false` on the last page. An engine-grain read either completes across pages or
  fails with a 503 (ADR-0070 D9, `0070:819-820`).

**Paged reads make no cross-page consistency promise (disclosed).** Each page of the
per-certificate read is its own statement. An ingest, prune or decommission that commits between
two pages can add, remove or change rows, so a caller paging the live read may see a certificate
twice, miss one, or count a different set than a counts response saw. Paged reads are for browsing
and drilling, not for recomputing a count exactly.

**The snapshot export carries D13 condition 2's recompute promise (senior ruling R-gen).** D13
condition 2 requires each fleet count to be recomputable from the raw per-certificate facts
(`0070:1288-1295`). That promise is scoped to one read:
- `GET /api/v1/crypto/certificates/snapshot`, MCP twin `export_crypto_certificate_snapshot`.
- It runs in **one** `REPEATABLE READ` transaction: it selects `date_trunc('second', now()) AS
  as_of`, the D13 counts and every raw row behind them (the per-certificate fields, with locations
  and each certificate's R1 revocation statement from 2b-2 on), all from that one transaction's
  snapshot. The counts it returns therefore recompute exactly from the rows it returns at the
  `as_of` it returns.
- It is bounded: at most 50,000 certificates and 32 MiB per response, filtered by the same
  confinement and the same filters as the per-certificate read (`agent_id`, `store`, `issuer_dn` and
  so on). Past the bound it stops at a whole certificate, sets `result_truncated: true` and
  `truncated_parts: ["row_ceiling"]` or `["byte_budget"]`, and returns the counts for the full set
  beside a `rows_returned` figure, so a truncated export is never read as complete. It is never a
  silent cut. A caller narrows the filters to get a complete export.
- It is gated and audited like the reads: `CertificateInventory:Read`, admin-floored while RBAC is
  off, confined by ADR-0017; its own audit verb `crypto.certificates.snapshot`, REST failing closed
  and MCP set-and-proceed (OD-2); admitted through the `/crypto` read gate, holding one slot for
  the whole transaction, under the counts statement timeout (see [Capacity](#capacity)).
- Its whole transaction is bounded, not only each statement. `statement_timeout` limits one
  statement, so a REPEATABLE READ snapshot spanning several statements could otherwise hold its
  slot and Postgres's `xmin` horizon (vacuum) for as long as it runs. The export therefore enforces
  a 30-second wall deadline from `BEGIN` in the route (and also sets `transaction_timeout` where
  the server's Postgres supports it), rolling back and answering 503 with a retry hint when it
  passes. Each principal may hold at most one snapshot at a time (a second concurrent request is a
  429 with `retry_after_ms`), so one caller cannot occupy both `CryptoReadGate` slots
  (`kMaxConcurrentCryptoReads = 2`, `crypto_read_gate.hpp:17`) and shed every other `/crypto`
  read. A chaos case runs two snapshots from one principal and one from another, and asserts the
  429, the deadline, and that a dashboard read still admits.
- The recompute unit test uses it, and so does any caller that wants to check a count.

### Routes and tools

**Proposed.** Each MCP tool has its own `if (tool_name == "...")` dispatch branch, as
`get_crypto_libraries` does (`mcp_server.cpp:9746`, `:9816`). The retry-hint gate
(`scripts/ci/check-mcp-retry-hints.py`) then sees each one; it misses tools that share a branch.
Each tool ships all five A5 annotations, a decision-grade description, a bounded input schema, a
typed output schema and per-error recovery metadata, with the values in
[MCP annotations and errors](#mcp-annotations-and-errors).

| REST | MCP | Securable | Slice |
|---|---|---|---|
| `GET /api/v1/crypto/certificates` | `list_crypto_certificates` | `CertificateInventory:Read` | 2a-2 |
| `GET /api/v1/crypto/certificates/summary` | `get_crypto_certificate_summary` | `CertificateInventory:Read` | 2a-2 |
| `GET /api/v1/crypto/certificates/snapshot` | `export_crypto_certificate_snapshot` | `CertificateInventory:Read` | 2a-3 |
| `GET /api/v1/crypto/certificates/counts` | `get_crypto_certificate_counts` | `CertificateInventory:Read` | 2a-3 (revoked windows 2b-2) |
| `GET /api/v1/crypto/cbom` (certificate half) | `export_crypto_cbom` | per half: `Inventory:Read` / `CertificateInventory:Read` | 2a-4 |
| `GET /api/v1/crypto/revocation-sources` (carries the `crl_past_next_update` count) | `list_revocation_sources` | `RevocationSource:Read` | 2b-1 |
| `GET /api/v1/crypto/revocation-sources/{id}` | `get_revocation_source` | `RevocationSource:Read` | 2b-1 |
| `POST /api/v1/crypto/revocation-sources` | `register_revocation_source` | `RevocationSource:Write` | 2b-1 |
| `PUT /api/v1/crypto/revocation-sources/{id}` | `update_revocation_source` | `RevocationSource:Write` | 2b-1 |
| `DELETE /api/v1/crypto/revocation-sources/{id}` | `remove_revocation_source` (`destructiveHint: true`) | `RevocationSource:Write` | 2b-1 |
| `POST /api/v1/crypto/revocation-sources/{id}/reset-high-water` | `reset_revocation_source_high_water` (`destructiveHint: true`) | `RevocationSource:Write` | 2b-1 |
| `GET /api/v1/crypto/certificates/tombstones` | `list_certificate_tombstones` | administrator predicate + `CertificateInventory:Write` (OD-4) | 2a-2 |
| `DELETE /api/v1/crypto/certificates/tombstones/{agent_id}` | `purge_certificate_tombstone` (`destructiveHint: true`) | administrator predicate + `CertificateInventory:Write` (OD-4) | 2a-2 |
| `/fragments/crypto/certificates`, `/fragments/crypto/certificates/devices` | — (dashboard, twin of the REST reads) | `CertificateInventory:Read` | 2a-2 |

Every certificate and revocation-source REST and MCP description carries D10's sentence: "facts
only; the only built-in checks are D13's named rules and windows, each shown with its criterion"
(`0070:831-832`).

#### MCP annotations and errors

**Proposed.** `openWorldHint` is `true` only where the tool itself reaches outside Yuzu's own
stores: register and update resolve the URL's host to show its address class. No tool fetches a
CRL; the refresh job does. These are the first tools with `openWorldHint: true`: the annotation
test on `dev` checks `open_world == false` for every tool ("Closed managed fleet: never
open-world", `tests/unit/server/test_mcp_server.cpp:2137-2138`). So 2b-1 amends that assertion to
allow exactly `register_revocation_source` and `update_revocation_source`, with the reason in a
comment: they resolve an administrator-registered host, the only outbound reach any tool has.

| MCP tool | `title` | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `openWorldHint` | Idempotency, stated |
|---|---|---|---|---|---|---|
| `list_crypto_certificates` | List fleet certificates | true | false | true | false | A read. |
| `get_crypto_certificate_summary` | Summarise fleet certificates by raw value | true | false | true | false | A read. |
| `get_crypto_certificate_counts` | Count certificates by D13 rule and window | true | false | true | false | A read; the result moves with `as_of`. |
| `export_crypto_certificate_snapshot` | Export a consistent certificate snapshot with its counts | true | false | true | false | A read; one transaction; the result moves with `as_of`. |
| `export_crypto_cbom` | Export the crypto CBOM | true | false | true | false | A read (existing tool; the certificate half is added). |
| `list_revocation_sources` | List registered CRL sources | true | false | true | false | A read. |
| `get_revocation_source` | Show one registered CRL source | true | false | true | false | A read. |
| `register_revocation_source` | Register a CA and its CRL URLs | false | false | false | true | Not idempotent: a second call for the same CA answers 409 `conflict` (one source per CA). |
| `update_revocation_source` | Replace a CRL source's keys and URLs | false | true | true | true | Idempotent: a full replace. A body equal to the current configuration changes nothing and does not bump `config_version`. Destructive because dropping a key or URL deletes its held CRLs. |
| `remove_revocation_source` | Remove a CRL source | false | true | true | false | Idempotent: a repeat has no further effect and answers 404 `not_found`. The high-water marks survive. |
| `reset_revocation_source_high_water` | Reset a CA's CRL anti-rollback marks | false | true | false | false | **Not** idempotent: each call sets a new `reset_at` and deletes the CA's held CRLs again, so a repeat after a CRL was accepted discards it. |
| `list_certificate_tombstones` | List decommission tombstones | true | false | true | false | A read (admin-only). |
| `purge_certificate_tombstone` | Purge one decommission tombstone | false | true | true | false | Idempotent: a repeat answers 404 `not_found`. |

**Error semantics, every tool** (A4 envelope on REST and in MCP `error.data`, including local
errors such as non-object arguments, an unwired gate or a parse error):

| Error | Retryable | Recovery metadata |
|---|---|---|
| 400 / `invalid_params` | no | names the parameter and the accepted shape |
| 403 / `forbidden` | no | names the permission actually required |
| 403 / `approval_required` (supervised MCP token on a mutation) | after approval | the approval ticket to recall |
| 404 / `not_found` | no | — |
| 409 / `conflict` (register of an already-registered CA) | no | the existing source id |
| 503 / store degraded, admission shed, or audit write failed | yes | `retry_after_ms` |

The `POST` and `PUT` bodies get an entry in `kBodyCapTable` (`body_cap_policy.hpp:179`), as the
pre-auth body-cap routed concern requires for a new mutating route. The proposed cap is 128 KiB.

### Parameters: strict or free text, the same on both twins

**Proposed:** the rule is set once, per parameter, and applies to REST and MCP alike. A closed enum
in OpenAPI beside "not refused" on the server is the #6122 item 2 defect.

| Parameter | Kind | REST and MCP behaviour |
|---|---|---|
| `store` (a `store_id`) | free text | Exact match; no enum in either schema. |
| `scope` | closed: `machine` | Unknown values refused, 400 / `kInvalidParams`; the enum is in both schemas. |
| `key_alg_oid`, `sig_alg_oid`, `ec_curve_oid` | dotted-decimal OID | Shape-checked (`^[0-2](\.[0-9]+){1,32}$`) and refused if malformed; any well-formed OID is accepted. |
| `not_after_before`, `not_after_after`, `not_before_after` | RFC 3339 UTC | Refused if malformed. These are D4's caller-supplied T. |
| `rsa_modulus_bits_lt`, `ec_order_bits_lt` | int 1..65536 | Caller-supplied thresholds (D4). Refused out of range. |
| `is_ca`, `self_signed` | bool | Refused if not a bool. |
| `agent_id` | free text | Exact; confined by the gate. |
| `issuer_dn` | free text | Exact match on the RFC 4514 string. |
| `issuer_dn_contains` | free text, 3..256 bytes | Case-insensitive substring of `issuer_dn` (ASCII case folding). The value is matched literally: `%`, `_` and `\` are escaped, never a pattern. Refused if shorter, longer or invalid UTF-8. |
| `subject_dn_contains` | free text, 3..256 bytes | The same match on `subject_dn`, accepted **only together with `is_ca=true`**. Without it, 400 / `kInvalidParams` naming `is_ca`. |
| `sha256` | 64 hex | Refused if malformed. |
| `spki_sha256` | 64 hex | Exact. Every certificate over one key. Refused if malformed. |
| `aki_key_id` | hex, 2..128 | Exact. Every certificate whose authority key identifier names one CA key. Refused if malformed. |
| `not_after_edges` (summary histogram) | list of RFC 3339, 1..32, ascending | The caller's bucket edges (ADR-0070's derived-field table, `0070:225`). Refused if unsorted or too many. |
| `cursor`, `limit` | opaque / int 1..500 (default 100) | REST and MCP both refuse a value out of range. |

#### Finding one CA's certificates

**Proposed.** An operator who learns that a CA is distrusted or compromised needs every device
holding that CA's own certificates, and every certificate it issued. The exact `issuer_dn` filter
alone cannot answer that: one CA issues under several names. The October 2026 eMudhra incident is
the reference case. Eight eMudhra intermediate CAs had P-384 private keys that were small integers
(4, 56, 115 and others), recoverable from the public certificates in under a second. Browsers
distrusted them, but a server, appliance or application with its own trust store does not follow a
browser update. eMudhra's names also vary: its CNs say `emSign` and its `O` says
`eMudhra Technologies Limited`.

The four filters added above answer it, each from fields the per-certificate read already
stores. Each query goes through the same gate, confinement, audit and pagination as any other
per-certificate read. The snapshot accepts them too, because it takes the same filters:

| Question | Query |
|---|---|
| Which devices hold one of this CA's own certificates, under any of its names? | `is_ca=true&subject_dn_contains=eMudhra`, then `subject_dn_contains=emSign` |
| Which certificates did any of its names issue? | `issuer_dn_contains=eMudhra`, then `issuer_dn_contains=emSign` |
| Where is one compromised key, including cross-signed and re-issued copies of its certificate? | `spki_sha256=<the key's hash>`; copies have their own `sha256` but share the key |
| What did one compromised CA key sign, whatever name the issuer used? | `aki_key_id=<that CA certificate's ski>` |

- **`subject_dn_contains` needs `is_ca=true`.** An end-entity subject can carry a person's name or
  e-mail address (see [Personal data](#personal-data)). A fleet-wide substring search over those
  would be a search for a person, which this design does not build. A CA's subject names the CA.
  `is_ca` is the certificate's own basic-constraints claim, so a non-CA certificate that falsely
  claims it is still a raw fact about that certificate, and the filter only narrows a read the
  caller is already admitted to.
- **`issuer_dn_contains` has no such condition.** An issuer DN names a CA. A self-signed end-entity
  certificate repeats its subject as its issuer, so this filter can still reach a person's name.
  It reaches nothing that the existing exact `issuer_dn` filter, or an unfiltered read, does not
  already return to the same caller. Filter values are audited (only counts and filters are), so a
  person's name typed into either filter lands in the audit details. The audit-log entry for the
  verb says so.
- **`spki_sha256` and `aki_key_id` are filters, not identity.** The rule that `spki_sha256` is never
  certificate identity or a join key (see [Fields collected](#fields-collected)) still holds:
  filtering by a key returns every certificate over it, and that is the point.
- **Indexes.** `cert_fact (spki_sha256)` and `(aki_key_id)` are added to the
  [store's index list](#store-and-schema). The two substring filters scan the caller's visible
  `cert_fact` rows under the read's statement timeout. That cost is unmeasured. 2a-2 measures it at
  the target scale and adds a `pg_trgm` index only if the measured p95 needs one.
- **Out of scope here.** Detecting a weak key from the key itself (a tiny EC private key, shared or
  close RSA primes) needs more than these filters. It is a separate proposal.

### Response shapes

**Per-certificate read** (`GET /api/v1/crypto/certificates`), one entry per (device, certificate):

```json
{
  "data": {
    "certificates": [{
      "agent_id": "...", "hostname": "...",
      "sha256": "...", "sha1": "...", "tbs_sha256": "...",
      "serial": "...", "subject_dn": "...", "issuer_dn": "...",
      "not_before": "2025-01-09T00:00:00Z", "not_after": "2026-01-09T23:59:59Z",
      "key_alg_oid": "1.2.840.113549.1.1.1", "rsa_modulus_bits": 2048,
      "ec_curve_oid": null, "ec_order_bits": null,
      "sig_alg_oid": "1.2.840.113549.1.1.11", "pss_hash_oid": null,
      "spki_sha256": "...", "ski": "...", "aki_key_id": "...",
      "is_ca": false, "path_len": null, "self_signed": false,
      "key_usage": ["digitalSignature"], "eku_oids": ["1.3.6.1.5.5.7.3.1"],
      "sans": [{"type": "dns", "value": "..."}],
      "key_association": "present", "key_provider": "...", "key_exportable": "unknown",
      "locations": [{"store_id": "LocalMachine\\My", "path": "", "store_status": "ok",
                     "observed_at": "...", "last_seen": "..."}],
      "last_seen": "...",
      "revocation": {"statement": "not_checked", "cause": "issuer_not_registered"},
      "constrained_fields": []
    }],
    "stores": [{"agent_id": "...", "store_id": "...", "status": "unreadable",
                "reason": "permission_denied", "observed_at": "...", "status_at": "..."}],
    "not_read": ["Java cacerts", "PKCS#12 files", "per-user stores", "..."],
    "coverage": {"devices_reporting": 0, "devices_included": 0, "confined": true},
    "result_truncated": false, "truncated_parts": [], "next_cursor": null,
    "blob_versions": [1]
  }
}
```

- `revocation` is present only from 2b-2. Before that, it is absent from the response, and the
  description says revocation is not checked by this version.
- `stores` lists the status of every store on every device in the page, so a kept row is never
  shown without the status that explains it.
- `not_read` is D10's honesty list (`0070:835-836`).
- `coverage.tombstoned_agents_registered` is added to `coverage` only for an administrator (see
  [Ingest](#ingest)); the example above is a confined caller's response, so it has none.

**Summary** (`/summary`): distinct-device and distinct-certificate counts grouped by raw value
(`key_alg_oid` + `rsa_modulus_bits` or `ec_order_bits`, `sig_alg_oid` + `pss_hash_oid`,
`ec_curve_oid`, `issuer_dn` top 50, `store_id`), plus a `not_after` histogram over the caller's
edges. These are raw-value rollups at a grain an engine can consume (ADR-0070 D9, `0070:821-823`).
No bucket edge is chosen by Yuzu. Subject DNs and SANs are never a grouping key (see
[Personal data](#personal-data)).

### D13 counts

**Decided (ADR-0070 D13 at `430e67b7d`, `0070:1079-1140`, `:1186-1270`, `:1283-1338`):** the four
rules, the windows and their edges (R5, R7, R10, R14), the `active` count, R13's partial-reasons
figure, conditions 1–5, the mechanical checks and the closed allow-list. This design adopts R5,
R7, R10, R12, R13 and R14 verbatim and does not restate them differently anywhere. `as_of` is
`date_trunc('second', now())` (R5, `0070:1188-1189`): R4's Postgres `now()` in whole seconds, read
in the same SQL statement as every comparison it governs, and returned exactly as compared (R4,
`0070:1176-1177`).

**Proposed rule definitions** (`rule_set_version: "crypto_weak_rules_v1"`). They are a closed OID
set, compiled in, and changed only by a reviewed code change (condition 4):

| `rule_id` | Matches | Criterion text |
|---|---|---|
| `sig_md5` | `sig_alg_oid` = `1.2.840.113549.1.1.4`, or RSASSA-PSS (`1.2.840.113549.1.1.10`) with `pss_hash_oid` = `1.2.840.113549.2.5` | "the signature algorithm uses MD5" |
| `sig_sha1` | `sig_alg_oid` in {`1.2.840.113549.1.1.5`, `1.3.14.3.2.29`, `1.2.840.10045.4.1`, `1.2.840.10040.4.3`}, or RSASSA-PSS with `pss_hash_oid` = `1.3.14.3.2.26` | "the signature algorithm uses SHA-1" |
| `rsa_lt_2048` | `key_alg_oid` in {`1.2.840.113549.1.1.1`, `1.2.840.113549.1.1.10`} and `rsa_modulus_bits` < 2048 | "RSA key under 2048 bits" |
| `ec_lt_224` | `key_alg_oid` = `1.2.840.10045.2.1` and `ec_order_bits` < 224. Ed25519 (`1.3.101.112`) and Ed448 (`1.3.101.113`) never match. | "EC key on a curve whose group order is under 224 bits" |

A certificate with an unknown field (NULL) does not match a rule. It is counted under
`not_evaluable`, so an older agent's rows never read as "no weak keys".

**The expiry boundary (owner decision OD-3, per RFC 5280; restated by R5).** OD-3 rules the
`not_after` boundary only: a certificate is valid through its `notAfter`, inclusive (R5,
`0070:1187`). So a certificate whose `not_after` equals `as_of` is still valid: it is active and
expiring, not expired. Because `as_of` is truncated to the second and certificate times are whole
seconds, that equality is exact. Every other edge below is R5's, R10's and R14's, not OD-3's.

**Window definitions (Decided, R5/R10/R14, `0070:1186-1202`, `:1237-1242`, `:1267-1270`).** Windows
are cumulative, not banded. Every bound is stated; none is implied:

| Window | Predicate (UTC, against `as_of`) | Values |
|---|---|---|
| `active` | `not_before <= as_of <= not_after` (R10) | — |
| `expiring_within_days` | active at `as_of` **and** `not_after <= as_of + N days` (R14); a not-yet-valid certificate is in neither this nor `active` | 3, 7, 14, 21, 30, 60 |
| `expired_within_days` | `as_of - N days <= not_after < as_of` (lower inclusive, upper exclusive) | 7, 30, 60, 90 |
| `issued_within_days` | `as_of - 7 days < not_before <= as_of` (lower **exclusive**; a future-dated `not_before` is not "issued") | 7 |
| `issued_per_iso_week` | `week_start <= not_before < week_start + 7 days`, and `not_before <= as_of`; ISO 8601 weeks in UTC starting Monday 00:00:00, labelled by ISO year and week | 52 weeks, the current, partial week included and flagged `partial` (R7) |
| `revoked_within_days` (2b-2) | `as_of - N days < revocation_date <= as_of` (lower **exclusive**), from statements under D5's rule only | 7, 30, 60, 90 |
| `revoked_per_iso_week` (2b-2) | `week_start <= revocation_date < week_start + 7 days`, and `revocation_date <= as_of` | 52 weeks, current week included and `partial` (R7) |
| `crl_past_next_update` (2b-1) | registered CRL scopes whose `next_update < as_of` (strictly before); a CRL with no `nextUpdate` is counted under `no_next_update`, never as past. Served on the `RevocationSource:Read` source list, not the certificate counts read (below). | — |

The window values, edges and 52-week span are ADR-0070's (`0070:1095-1134`, `:1212-1214`), and
`rule_set_version` `crypto_weak_rules_v1` names exactly the rules and windows as ADR-0070 states
them at `430e67b7d`. Retuning any rule, window, edge or the span bumps it, because condition 4
makes that a change to the rule set (`0070:1311-1314`). The constants are defined once, with one
shared predicate per edge, and every count surface (the certificate counts here and any Yuzu-CA
count) imports them rather than copying them.

**Coordination item (unmerged work).** A shared set of window constants and Yuzu-CA count
predicates is proposed in the unmerged `feat/crypto-dashboard-widgets` work. That work follows
ADR-0070's edges; this design moves to match it and the ADR, not the reverse. If the constants land
there first, slice 2 imports them; if slice 2 lands first, they land in 2a-3 and the widgets work
imports them. Either way there is one set and one version.

**`crl_past_next_update` is not a certificate count.** It is a count over registered CRL scopes, so
it is served on `GET /api/v1/crypto/revocation-sources` and `list_revocation_sources`, under
`RevocationSource:Read`, as a count object with the same four fields. A caller can recompute it from
that same response's per-scope `next_update` values and `as_of` (D13 condition 2). Serving it under
`CertificateInventory:Read` would disclose how many scopes are registered to a caller who cannot
see the source list, and could not be recomputed there.

**Count object.** Every count, in every list, is one object carrying the four fields condition 1's
lint requires (`rule_id`, `threshold` or criterion, `rule_set_version`, `as_of`):

```json
{"rule_id": "expiring_within_days", "threshold": 30,
 "criterion": "active at as_of and not_after within the next 30 days",
 "rule_set_version": "crypto_weak_rules_v1",
 "as_of": "2026-10-19T12:00:00Z",
 "certificates": 0, "devices": 0, "ca_certificates": 0, "end_entity_certificates": 0,
 "from_kept_rows": 0, "not_evaluable": 0}
```

The `active` count is the same object with `"rule_id": "active"`, no `threshold`, and the criterion
"valid at as_of (not_before <= as_of <= not_after)". `as_of` is always a whole second.

- `certificates` is distinct (device, `sha256`) and `devices` is distinct `agent_id`, over the
  caller's visible devices.
- `ca_certificates` / `end_entity_certificates` split on the raw `is_ca` field. A root store full
  of SHA-1-signed roots then reads as roots, without any label.
- `from_kept_rows` counts certificates whose only locations are in stores whose latest status is
  not `ok`. A count that rests on old observations says so.
- A revoked-window count adds `matched_by_issuer_and_serial`, `signature_verified`,
  `revocation_not_checked` with a per-cause breakdown, and beside it
  `checked_some_reasons_only`: how many certificates in scope were checked against a CRL covering
  only some reasons (R13, `0070:1105-1111`, `:1262-1266`).

The response's top-level keys are `weak_key_rules`, `active`, `expiring_within_days`,
`expired_within_days`, `issued_within_days`, `issued_per_iso_week` and, from 2b-2,
`revoked_within_days` and `revoked_per_iso_week`. Of these only `weak_key_rules`,
`expiring_within_days` and `expired_within_days` are verdict-shaped names under the D10 lint, and
they are exactly D13's closed allow-list (`0070:1332-1338`). 2a-3 adds three allow-list entries
keyed by (`/api/v1/crypto/certificates/counts`, field), the same three for
`get_crypto_certificate_counts`, and the same for the counts fragment, each citing D13.

**One SQL statement per count read.** The counts are computed in one statement that selects
`date_trunc('second', now()) AS as_of` and uses that value in every comparison. Nothing is stored
(condition 3). The statement runs under a statement timeout (see [Capacity](#capacity)); a
timeout is a 503 with a retry hint, never a partial count.

### CBOM certificate components

**Decided (ADR-0070 D7, `0070:684-713`):** facts only. Verdict fields stay empty or omitted. Each
half is gated by its own securable, and an omitted half never reads as "no certificates". Coverage,
confinement and truncation are carried.

**Proposed (2a-4, after #6143).** One CycloneDX 1.7 `cryptographic-asset` component per distinct
certificate (`sha256`), with `assetType: certificate`:
- `certificateProperties`: `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`,
  `serialNumber`, `certificateFormat: "X.509"`, and `fingerprint` = {`alg`: `SHA-256`, `content`:
  `tbs_sha256`};
- `relatedCryptographicAssets`: references to one `algorithm` component per distinct signature
  algorithm OID and one `related-crypto-material` public-key component per distinct `spki_sha256`
  (with its size), never the deprecated `signatureAlgorithmRef` / `subjectPublicKeyRef`;
- `yuzu:` properties: device count, store ids, `key_association`.

**Left empty:** `classicalSecurityLevel`, `nistQuantumSecurityLevel` and `certificateState`
(lifecycle state is derived against "now"). `revocationDate` is also left empty in 2a-4. Filling it
from an R1 statement is a fact, but it would need D5's basis wording, which the field cannot carry.
Whether to add it later is open decision 4 (see [Decisions](#decisions)). The exact field
list is checked against `bom-1.7.schema.json` when 2a-4 is built (D7, `0070:694-695`).

A caller holding `Inventory:Read` but not `CertificateInventory:Read` gets the library half, plus
`yuzu:crypto:halves_omitted: ["certificates"]` and the reason in the coverage metadata.

## R1: registered-CRL revocation (slice 2b)

**Decided (ADR-0070 D5 as amended by R1, `0070:507-570`; D12 "Registered-CRL revocation",
`0070:924-951`):** everything R1 requires is binding. This section designs it.

### Registration

**Decided:**
- Register, list and remove a CA certificate and its CRL URLs, with REST + MCP twins and its own
  audit verb.
- Admin-only in both RBAC states. `authz_topology_floor.hpp` is extended, never forked. The
  registered-URL list fits none of that header's three inclusion classes, so the same change amends
  the inclusion test and says why.
- The URL list is admin-only, because it reveals internal hosts.
- Registered URLs are logged through `log_token`.
- A registered CA certificate is supplied by an administrator, never imported from fleet rows, and
  never a trust anchor for any PKI decision path (D6, `0070:650-652`).

**Proposed:**
- **Securable:** `RevocationSource`, with two operations only: `Read` (the source list and detail)
  and `Write` (register, update and remove; removal is a `Write`, not a separate `Delete`). Both are
  seeded to Administrator only (owner decision, 2026-10-19).
- **Admin-only in both RBAC states means not grantable.** ADR-0070 R1 requires admin-only under RBAC
  on as well, so a custom role granted `RevocationSource:Write` must still be refused. Every
  `RevocationSource` route and tool therefore gates on an administrator predicate in the
  `is_rbac_administrator` style (`rbac_admin_predicate.hpp`), extended rather than forked, in
  addition to the securable. Under RBAC off, `Write` is already admin-only (`auth_routes.cpp:944`)
  and `Read` gets a floor entry under a fifth inclusion class added to the header's test (after
  the fourth that `CertificateInventory` adds)
  (`authz_topology_floor.hpp:54-63`): "the read discloses operator-registered egress targets, which
  map internal network topology". The reason the grant is refused: the fetch-status field
  (`last_failure_cause`) would otherwise make the fetcher a blind request-forgery and port-scan
  oracle for whoever holds the grant.
- **Registration body:** `name` (1..128 bytes, free text, escaped on render), `ca_certificates`
  (1..8 PEM certificates) and `crl_urls` (1..8). At most 64 sources may be registered, which also
  bounds every per-source and per-URL metric label.
- **Each CA certificate** must parse, be a CA (basic constraints `cA=TRUE`), and carry `cRLSign`
  if it has a key usage extension. All the certificates in one source must share one subject Name:
  a source is one CA, and its several keys let a CA renewal keep verifying (D5 condition 1). The
  store keeps each key's DER, the CA's subject Name DER hash, each key's SKI and its SPKI hash.
- **Each URL** must be `http` or `https`, with a host, and with no userinfo, no fragment and at
  most 2,048 bytes. The host must be ASCII (IDNs are given as punycode). `file:`, LDAP, UNC and
  everything else are refused (D12, `0070:940`). At registration the host is resolved and its
  address class shown to the administrator, who confirms it. Refused outright, at registration and
  on every fetch, with no override: the always-refused tier that `oidc_egress_policy.hpp:12-22`
  defines (unspecified, link-local, cloud metadata, multicast, reserved), **loopback**, and **every
  address the server itself is bound to or listening on**. A wildcard bind (`0.0.0.0` or `::`)
  expands to every address on every local interface. **Disclosed limit:** in an HA deployment the
  refusal covers only the fetching replica's own addresses, not the other replicas'; reaching
  another replica's listener needs a registered URL naming it, which only an administrator can
  register. That classifier is hoisted to a shared pure header rather than copied.
- **`PUT` replaces** the source's name, keys and URLs. This is how a renewed CA key is added. A
  `PUT` that drops a URL deletes that URL's `source_url` and `fetch_status` rows, and every held
  `crl` row fetched from it, in the same transaction. A `PUT` that drops a key deletes every held
  CRL that verified only under that key. The anti-rollback high-water mark is keyed by the CA, not
  the URL or key (below), so it is never lost this way.
- **`DELETE`** removes the source, its URLs, its held CRLs, its entries and its
  `cert_signature_check` rows. Certificates then read "issuer not registered". The high-water mark
  of each scope **survives** removal, so a remove and re-register cannot accept an older CRL.
- **Mutations fail closed on audit**, as in [Audit and degrade](#audit-and-degrade).
- **MCP approval: the real posture, and the fix.** On `origin/dev`, `mcp::requires_approval`
  (`server/core/src/mcp_policy.hpp:145`) asks a supervised-tier token for an approval ticket only
  for named pairs and any `Delete` (`:156`, `:158`, `:184`). Neither `RevocationSource:Write` nor
  `CertificateInventory:Write` is among them, and this design maps removal, reset and purge to
  `Write`, not `Delete`. Left as is, a supervised MCP token held by an administrator would
  register, update, remove, reset and purge with no ticket. So **2b-1 adds
  `RevocationSource:Write`, and 2a-2 adds `CertificateInventory:Write`, to `requires_approval`'s
  supervised list.** The REST mirror needs no second list: `AuthRoutes` already applies the same
  predicate to an MCP token on every non-MCP transport (`auth_routes.cpp:1017`, `:1156`), so the
  one edit covers both. Each PR adds a test that a supervised MCP token gets `approval_required`
  for every mutation on both transports. Both pairs are deliberate additions to that list, and the
  PR says so in its MCP-server routed-concern review.

### The fetcher

**Decided (ADR-0070 D5 and D12, `0070:511-518`, `:936-944`):** exactly the registered URLs;
redirects only to registered URLs; no credentials; bounded timeouts and sizes; `http`/`https` only;
the resolved address checked against the registered host on every fetch, so DNS rebinding cannot
redirect it; the revocation-statement rule applied before any entry is used. Internal addresses are
allowed only because an administrator registered that exact URL. The fetcher gets its own security
review, as a new egress surface.

**Proposed:**
- **Input is a source id, never a URL.** The fetcher's interface takes a registered `(source_id,
  url_id)`, and loads the URL from the store. No code path can hand it a URL string, so a URL from a
  certificate's AIA, CDP or OCSP field cannot reach it. `crl_dp_uris` lives in the certificate store
  and is only ever compared, never passed on.
- **Address check and pin on every fetch.** The fetcher resolves the host, classifies every
  address, and refuses if any address is in a refused class (above) or in a class the administrator
  did not confirm at registration. For example, a URL confirmed as public now resolving to an RFC
  1918 address is refused with cause `address_class_changed`. It then connects to the one address
  it checked, sending the registered host as `Host` and SNI, so no second lookup can land
  elsewhere. The OIDC client already pins this way with httplib's `set_hostname_addr_map`
  (`oidc_provider.cpp:1468`, `:2275`) and turns off redirect following (`:2296`); that
  resolve-classify-pin helper is hoisted to a shared place and reused, not copied.
- **Cleartext.** Plain `http` is allowed to any confirmed address class, unlike the OIDC policy's
  refusal of cleartext to a public address (`oidc_egress_policy.hpp:25-30`). A CRL's integrity comes
  from its signature, not the transport, and most CDPs are `http`. A tampered response fails
  verification, and the last good CRL is kept.
- **HTTPS** verifies the server certificate against the system trust store, with hostname checking,
  under the shared cipher policy (`common/include/yuzu/tls_policy.hpp`). The registered CA
  certificate is **never** a TLS trust anchor for this connection (D6).
- **Redirects:** followed by the fetcher itself, never by the client library, at most 3. Each target
  must equal a URL registered for the same source, and is re-checked and re-pinned as above.
  Anything else is refused with cause `redirect_unregistered`.
- **No credentials:** no `Authorization`, cookies, client certificate or proxy credentials, and no
  NTLM or Negotiate. Responses that ask for authentication fail with `auth_required`. No outbound
  proxy is used in 2b-1 (open decision 3).
- **Bounds:** connect 5 s, read 10 s, whole fetch 30 s. Response body at most 32 MiB, read with a
  counting limit; a larger body stops the read and records cause `over_size_bound`.
  `Content-Encoding` other than `identity` is refused. Conditional GET (`If-Modified-Since`,
  `ETag`) is used, and a 304 counts as success with the held CRL unchanged.
- **Cadence:** each URL is fetched when no CRL is held, and otherwise at most hourly. Once the held
  CRL's `nextUpdate` has passed, the fetcher retries with exponential backoff from 5 minutes up to
  6 hours, with jitter, **whether the fetch fails or the CA keeps serving the same stale CRL**, so a
  CA that has stopped publishing is not fetched on every leader tick. A newly registered source is
  picked up on the next leader tick (at most 1 minute). Until then it reads `no_crl_fetched`.

### Verifying and accepting a CRL

**Decided (ADR-0070 D5 "Revocation statements", `0070:520-530`):**
1. It verifies against a CA key registered for that CA.
2. It is in scope for the certificate: issuer by DER Name equality, AKI where present, serial as an
   integer; a partitioned CRL only within its distribution point and reasons; a delta CRL only with
   its base.
3. It is not older than the newest verified CRL already held for that scope, by CRL number (else
   `thisUpdate`). An older CRL is never stored over a newer one.

**Proposed:**
- **Parsing.** `d2i_X509_CRL` reads DER only. A body that starts with the `-----BEGIN X509 CRL-----`
  armour is decoded explicitly as PEM first (exactly one block); anything else is parsed as DER,
  with trailing bytes refused. Require a v2 CRL with `thisUpdate`. At most 2,000,000 entries; more
  is cause `over_size_bound`.
- **Verification.** Try **every** registered key of the source (the CA). A key whose SKI equals the
  CRL's AKI is tried first; the CRL's issuer Name DER must equal the CA's subject Name DER. The first
  key that verifies is recorded as `verified_key_sha256`, for display only. If none verifies, the
  cause is `verification_failed`.
- **Scope key** is (registered CA, IDP DER hash or "full", base or delta), where the registered CA
  is the source, identified by the CA's subject Name DER hash. It is **not** keyed by the signing
  key, so after a CA re-key a CRL signed by the new key supersedes one signed by the old key in the
  same scope, rather than living beside it as a second, staler answer. The IDP is read for
  `distributionPoint`, `onlySomeReasons`, `onlyContainsUserCerts` and `onlyContainsCACerts`. An
  indirect CRL (`indirectCRL`) or `onlyContainsAttributeCerts` is recorded and never used (cause
  `out_of_scope`).
- **Source configuration check.** Source ids are never reused (they come from a sequence that is
  never reset), and every `source` row carries a `config_version` taken from one global Postgres
  sequence (`revocation_source.config_seq`) in the same transaction as the register, `PUT`,
  `DELETE` or high-water reset that changes it. So a `DELETE` followed by a re-register can never
  reproduce an earlier (source id, `config_version`) pair. Before a fetch, the
  job snapshots the source's `config_version`, the URL and the key set. The acceptance transaction
  locks the `source` row (`FOR UPDATE`) and stores the CRL only if `config_version` is unchanged and
  the URL is still registered; otherwise it discards the CRL, records cause `config_changed`,
  counts it, and the next tick fetches against the new configuration. A fetch in flight across a
  `PUT` that dropped a URL or withdrew the key that verified it, or across a `DELETE` and
  re-register of the same CA, can therefore never commit a CRL.
- **Anti-rollback** is a compare-and-set in the store, on a high-water mark keyed by the same
  (CA subject Name DER hash, IDP, base or delta). Accept only if **all** hold:
  - `crl_number` is greater than the held one, or, with no CRL number, `this_update` is strictly
    later;
  - `this_update` is not earlier than the held mark's `this_update`: it never goes backwards within
    a scope, whatever the number says;
  - if the CA has ever been reset, `this_update >= reset_at - 5 minutes` (below).

  An equal number with identical bytes is a no-op. Anything else is rejected and counted, and the
  held CRL stays. The cause names the rule that refused it: `older_than_held` for a number not
  above the held one, `this_update_backwards` for a `this_update` earlier than the held one, and
  `before_reset_floor` for a `this_update` earlier than `reset_at - 5 minutes`. A CRL that breaks
  more than one rule reports the first in that order. The high-water mark outlives the source (see
  `DELETE` above).
- **High-water reset.** A CA rebuilt under the same DN restarts its CRL numbers, so every new CRL
  would read `older_than_held` for ever. An audited, admin-only reset
  (`POST /api/v1/crypto/revocation-sources/{id}/reset-high-water` and an MCP twin,
  `RevocationSource:Write` behind the administrator predicate, audit verb
  `crypto.revocation_source.reset_high_water`, failing closed) clears that CA's marks. Until an
  administrator resets it, the source fails safe: no newer CRL is accepted, and once the held one
  is gone or out of scope its certificates read "revocation not checked", never "not listed".
- **A reset cannot be replayed into.** Plain `http` is allowed, so after a reset an on-path
  attacker or a stale mirror could serve an older CRL that still verifies, possibly one from before
  the rebuild with a higher number. So:
  - the reset body lists the source's keys after the rebuild. Every key not listed is removed, and
    every held CRL of the CA is deleted, in the same transaction as the reset;
  - the reset clears each scope's number and `this_update` but writes `reset_at` (Postgres `now()`
    at the reset) on every high-water row of the CA, and on a CA-level row that scopes first seen
    later inherit. **`reset_at` is kept permanently**: every CRL accepted afterwards, not only the
    first, must have `this_update >= reset_at - 5 minutes`. A pre-rebuild CRL signed by a key the
    rebuilt CA reuses, with a higher number, is therefore refused at any time after the reset;
  - alternatively the administrator pins, in the reset body, the SHA-256 of the first CRL to
    accept; the permanent `reset_at` rule still applies to every later one;
  - until a qualifying CRL arrives, the CA's certificates read "revocation not checked"
    (`no_crl_fetched`).
  - **Residual (disclosed):** a pre-rebuild CRL whose `thisUpdate` falls within the 5 minutes
    before the reset, and that verifies under a reused key, can still be accepted. The window is
    the allowed CA clock skew; an administrator who rebuilds a CA under the same DN and key avoids
    it by pinning the first CRL's hash.
- **A CA clock that steps back wedges the source (disclosed).** The monotonic `this_update` rule
  refuses every CRL from a CA whose clock has moved backwards, and a reset alone does not recover it
  while the clock is still more than 5 minutes behind, because the permanent `reset_at` floor then
  refuses its CRLs too; a pinned hash admits one CRL only. The source fails safe (its certificates
  move to "revocation not checked" once the held CRL is out of scope, never "not listed"), but
  revocation checking for that CA has stopped. So:
  - a refusal for this reason carries its own cause, `this_update_backwards`, distinct from
    `older_than_held` on the number, and is counted on `yuzu_server_crl_fetch_total`
    (`result="rejected"`, `cause="this_update_backwards"`, a member of its closed cause set, as is
    `before_reset_floor`);
  - the shipped alert `YuzuCrlClockBackwards` fires (see [Metrics and alerts](#metrics-and-alerts));
  - the reset body accepts an optional administrator-supplied `reset_at` (no later than Postgres
    `now()`, audited in the reset's own audit row with the value supplied), so an administrator who
    has confirmed the CA's clock moved can set the floor below the CA's current `thisUpdate`. A
    supplied value widens the replay window to everything since it; the runbook says so, and the
    reset response echoes the window it opened.
- The **last good CRL** is kept on every failure. A failure, including `over_size_bound`, updates
  only the URL's fetch status. A certificate reads `over_size_bound` only when no verified CRL is
  held for its scope; otherwise it is judged on the held CRL, with that CRL's `nextUpdate` shown.
- **The cost of a replace.** A new CRL for a scope is written in one transaction that inserts the
  new entries before deleting the old, so a scope never reads with no entries. It runs only in the
  refresh job, off every request path, under its own statement timeout. An unchanged CRL (a 304, or
  the same number and bytes) writes nothing, so a large, stable CRL costs one conditional GET per
  cadence. A CA that reissues a 1M-entry CRL hourly costs a 1M-row insert and delete per hour; the
  [Capacity](#capacity) section bounds it.
- **Delta CRLs** are verified and recorded but not used until 2b-3, the last and optional PR. Until
  then the source shows `delta_not_supported`, and certificates are judged on the base alone. When
  2b-3 lands, a delta is used only with a held base whose CRL number is at least the delta's
  `BaseCRLNumber`. Entries are then base plus delta, minus the delta's `removeFromCRL`.
- **`ExpiredCertsOnCRL`** (`2.5.29.60`) is recorded with its date.
- **A fuzz target** covers the server-side parse of agent-shipped certificate DER and of fetched
  CRLs, beside the existing targets in `tests/fuzz/`.

### The store

**Decided (ADR-0070 D12, `0070:947-948`):** a Postgres store for registered CAs and CRL entries,
separate from `ca_store`, in the readiness conjunction.

**Proposed:** `RevocationSourceStore`, schema `revocation_source_store`. It never touches `ca_store`
(D6, `0070:632-639`).

| Table | Key | Columns |
|---|---|---|
| `source` | `id` | `name`, `ca_subject_name_sha256` (UNIQUE: one source per CA), `config_version`, `created_by`, `created_at`, `updated_at` |
| `source_ca_key` | (`source_id`, `cert_sha256`) | `cert_der`, `ski`, `spki_sha256` |
| `source_url` | `id` | `source_id`, `url`, `host`, `confirmed_address_classes` |
| `fetch_status` | `url_id` | `last_attempt_at`, `last_success_at`, `last_failure_cause`, `consecutive_failures`, `next_attempt_at`, `etag`, `last_modified` |
| `crl` | `id` | `source_id`, `scope_key`, `url_id`, `crl_number`, `this_update`, `next_update`, `is_delta`, `base_crl_number`, `idp_reasons`, `expired_certs_on_crl`, `verified_key_sha256`, `der_sha256`, `entry_count`, `fetched_at` |
| `crl_entry` | (`crl_id`, `serial`) | `revocation_date`, `reason`, `invalidity_date` |
| `rollback_high_water` | (`ca_subject_name_sha256`, `scope_key`; `scope_key = '*'` is the CA-level row) | `crl_number`, `this_update`, `reset_at` (permanent once set) |
| `cert_signature_check` (2b-2) | (`cert_sha256`, `ca_key_sha256`) | `source_id`, `verified` |

- `this_update`, `next_update` and `revocation_date` are the CA's own times, from the CRL.
- `fetched_at`, `last_*_at`, `created_at` and `updated_at` are Postgres `now()`.
- Only the newest accepted CRL per scope is kept.
- `cert_signature_check` is keyed by the server-recomputed whole-DER SHA-256, so it is a pure
  function of the bytes and the registered key. It is not a stored verdict under D13 condition 3:
  it reads no clock and applies no Yuzu threshold. Its rows are deleted with their source (above),
  and the retention pass deletes a row once no `cert_fact` row on any agent carries its
  `cert_sha256`.

**Cross-schema reads have one owner.** Read-time matching joins `cert_inventory` and
`revocation_source` in one statement, which R4's same-statement `as_of` needs for the revoked
windows. The signature-check job also reads `cert_fact.der` and writes `cert_signature_check`, and
its prune reads `cert_fact`. Under ADR-0012 §3, all of that cross-schema SQL lives in one named
query owner, as `RbacAdminAuthorityOwner` is for the RBAC/auth join (the access-control routed
concerns). Proposed: `CertificateRevocationReader`, depending on both stores sharing one PgPool, as
the RBAC precedent does (open decision 2).

The tombstone clear crosses the other way, from the `auth` schema's enrolment writes into
`cert_inventory`. Proposed: a second named owner, `CertificateEnrolmentTombstoneOwner`, holding the
clear statement each approval write calls inside its own transaction, and the tombstone list's
join against the agent registry. It carries the same one-PgPool assumption, which open decision 2
also covers.

### Matching and statements

**Decided, quoted verbatim from ADR-0070 D5 at `430e67b7d` (`0070:532-555`):**

> From such a CRL it states one of:
> - "revoked on <revocationDate> (reason <r>)". A `certificateHold` entry reads "on hold",
>   never "revoked";
> - "not listed on <CA>'s CRL of <thisUpdate>, next update <nextUpdate>", never "not revoked"
>   or "valid". From a CRL that covers only some reasons (`onlySomeReasons`), the statement
>   names the reasons it covers (R13).
>
> Every per-certificate statement carries the same matching basis as the counts. Unless the
> certificate's signature was verified against the registered CA key, "revoked" reads
> "matched by issuer and serial: revoked on …", and "not listed" reads "matched by issuer and
> serial: not listed on …". So a planted certificate that copies a registered issuer and a
> serial cannot read as plainly revoked, or as plainly not listed. A certificate with no
> AKI, whose signature was not verified, reads "revocation not checked" (issuer name alone
> does not bind it to the registered CA). Signature verification is done by the server
> against the DER the agent ships, not taken from the agent's own claim.
>
> In every other case it reads "revocation not checked", with the cause. The causes are:
> - issuer not registered;
> - no CRL fetched yet;
> - verification failed;
> - over the size bound;
> - out of scope;
> - the certificate was already past its `notAfter` at the CRL's `thisUpdate`, and the CRL
>   carries no `ExpiredCertsOnCRL` extension covering it (CAs drop expired entries).

**Proposed matching.** A fleet certificate is checked against a registered source when all of
these hold:
- `issuer_name_sha256` equals the source's `ca_subject_name_sha256`;
- `aki_key_id` is NULL or equals the SKI of one of the source's keys;
- a held CRL of that source covers the certificate's scope: an IDP `distributionPoint` must appear
  in the certificate's `crl_dp_uris`; `onlyContainsCACerts` and `onlyContainsUserCerts` are tested
  against `is_ca`.

Then `serial` equality against `crl_entry` decides "listed" or "not listed".

**Proposed response shape.** `revocation` on each certificate:

```json
{"statement": "not_listed", "basis": "matched_by_issuer_and_serial",
 "revocation_date": null, "reason": null,
 "source_name": "...", "crl_this_update": "...", "crl_next_update": "...",
 "crl_past_next_update": true, "crl_reasons_covered": null}
```

- `statement` is one of `revoked`, `on_hold`, `not_listed` or `not_checked`.
- `basis` is `signature_verified` or `matched_by_issuer_and_serial`, and it is present on
  `revoked`, `on_hold` **and** `not_listed`: "not listed" by issuer and serial alone is as weak as
  "revoked" by them.
- `crl_this_update` and `crl_next_update` are on every statement drawn from a CRL. When the held
  CRL is past its `nextUpdate` at `as_of`, `crl_past_next_update` is `true` and the fragment says
  so in the sentence: "not listed on <CA>'s CRL of thisUpdate <t>; that CRL's nextUpdate <n> has
  passed". It is the same criterion D13 counts, shown per certificate; it is never a "stale" label.
- `cause` (only with `not_checked`) is one of `issuer_not_registered`, `no_crl_fetched`,
  `verification_failed`, `over_size_bound`, `out_of_scope`, `expired_before_this_update` (past
  `notAfter` at the CRL's `thisUpdate`, with no covering `ExpiredCertsOnCRL`) and `unbound_issuer`
  (no AKI and no verified signature).
- The fragment renders the sentences D5 prescribes. It never renders "not revoked" or "valid".
- The source URL never appears on a certificate read: `CertificateInventory:Read` holders see the
  source name only.

### Metrics and alerts

**Decided (ADR-0070 D12, `0070:949-953`):** an alert on fetch failure and on `crl_past_next_update`,
following `docs/observability-conventions.md`. Each rule ships with a test proving it can fire.

**Proposed:** server metrics use the `yuzu_server_` prefix (`docs/observability-conventions.md:7-9`).
No metric has a URL, host or source-name label, since those reveal internal hosts and are unbounded.
Per-URL series use the opaque registered `url_id`, whose cardinality is bounded by the registration
caps (64 sources × 8 URLs). Closed label sets are pre-seeded to 0.

| Metric | Type | Labels | Exported by |
|---|---|---|---|
| `yuzu_server_crl_fetch_total` | counter | `url_id`, `result` (`ok`, `not_modified`, `failed`, `rejected`), `cause` (closed set) | the leader |
| `yuzu_server_crl_url_last_success_age_seconds` | gauge | `url_id` | the leader |
| `yuzu_server_crl_scopes_past_next_update` | gauge, set from Postgres `now()`; one unlabelled gauge (R12). One scope is one held CRL: the count is of held CRLs (one per (CA, IDP, base or delta) scope) whose `nextUpdate` is before `as_of` | none | the leader |
| `yuzu_server_crl_refresh_last_run_timestamp_seconds` | gauge, set at the end of every refresh tick | none | the leader |
| `yuzu_server_crl_sources` | gauge | none | every replica (a store count) |
| `yuzu_server_crl_refresh_leader` | gauge, 1 on the replica running the refresh, else 0 | none | every replica |
| `yuzu_server_cert_inventory_ingest_total` | counter | `result`, `reason` | every replica |
| `yuzu_server_cert_inventory_claim_mismatch_total` | counter | none | every replica |
| `yuzu_server_cert_inventory_pruned_total`, `..._prune_capped_total` | counter | `grain` | every replica |
| `yuzu_fleet_cert_store_status` | gauge, fleet rollup | `os`, `status` | every replica; absent-not-zero |

Leader-only gauges are cleared on demotion (see [Background jobs](#background-jobs)), so a
non-leader exports none of them.

Alerts in `docs/prometheus/yuzu-alerts.yml`, each with a `promtool` test that fires it:
- `YuzuCrlFetchFailing`: per `url_id`, failures increasing with no success for 6 hours;
- `YuzuCrlPastNextUpdate` (R12, `0070:1251-1260`) is **two rules with the same alert name**, so each
  has its own `for`:
  - *past next update*: `max(yuzu_server_crl_scopes_past_next_update) > 0`, `for: 1h`. It takes
    the `max` across replicas, so a former leader's stale value cannot hide a CRL past its
    `nextUpdate` (R12);
  - *gauge absent or stale*: `max(yuzu_server_crl_sources) > 0` **and** any of
    `absent(yuzu_server_crl_scopes_past_next_update)`,
    `absent(yuzu_server_crl_refresh_last_run_timestamp_seconds)`, or
    `time() - max(yuzu_server_crl_refresh_last_run_timestamp_seconds) > 1800`; `for: 15m`. Gated on
    registered sources, so a deployment with none never fires it. This is R12's "absent or stale
    gauge as not healthy" clause.

  Its `promtool` tests cover: the past-next-update case firing; the absent case and the stale case
  firing; and three negative cases that must not fire: zero registered sources (no gauge, no
  alert), a non-leader replica exporting no leader gauges while the leader exports healthy ones,
  and a demotion (the old leader clears its gauges, the new leader exports healthy ones within the
  window, and the alert clears).
- `YuzuCrlRefreshNoLeader`: `max(yuzu_server_crl_sources) > 0` and
  `max(yuzu_server_crl_refresh_leader) < 1` (or the latter absent) for 15 minutes, so a refresh
  job that runs nowhere is seen rather than silently freezing every CRL;
- `YuzuCrlClockBackwards`: per `url_id`, `yuzu_server_crl_fetch_total{cause="this_update_backwards"}`
  increasing with no `result="ok"` for 6 hours, so a CA whose clock stepped back is seen rather
  than leaving its source wedged on the held CRL.

## Personal data

**Decided (ADR-0070 D12 "Personal data", `0070:955-967`):** subjects and SANs can carry e-mail
addresses, UPNs and names. Per-user stores are per-user data, and including them is this design's
privacy decision. The design records the DPIA, works-council and retention position, the RBAC-off
posture, and the data-processor obligations an engine takes on.

**Proposed:**
- **Per-user stores are excluded from slice 2.** Machine stores can still hold personal data: a
  client or S/MIME certificate in `LocalMachine\My`, or a UPN SAN on a device certificate.
- **Where it can appear.** Subject DNs and SAN values (`rfc822`, `upn`, `dirname`) are stored and
  served on the per-certificate read and in the CBOM certificate half only. Both are behind
  `CertificateInventory:Read`, which is admin-only under RBAC off. They are never a summary or
  count grouping key, never a metric label, and never in audit details (only counts and filters are
  audited).
- **No redaction.** An e-mail SAN is the certificate's identity, so redacting it would falsify the
  fact. That differs from `browser_inventory`, where an e-mail is incidental. The narrow securable
  is the control instead.
- **Retention:** rows live while the device reports them, or until 30 days after a reporting
  device's store stops being read, when they are pruned. An offline device's rows are not pruned
  (see [Retention and the prune](#retention-and-the-prune)); decommission erases them.
- **DPIA (Proposed).** The owner and the compliance-officer own the screening. It is recorded in
  `docs/security-reviews/` (a dated screening record for machine-scope certificate data) before 2a-2
  merges, and the 2a-2 PR links it. Whether it needs a full DPIA and a works-council consultation is
  open decision 1. The data is not behavioural: it records what is installed, not what a person
  did.
- **Decommission tombstones.** A tombstone holds an `agent_id` and a time. An `agent_id` is a
  pseudonymous device identifier, and it is personal data, because the audit log links it to a
  hostname and so, often, to a person. It is kept only to stop a decommissioned agent repopulating
  its rows, carries nothing else, and is served only on the admin-only tombstone list. A device that
  was approved before decommission keeps its tombstone indefinitely, because nothing else removes
  it: erasure of the tombstone itself is the audited admin purge, which the DPIA screening names as
  the Art. 17 path for it.
- **Erasure of a departed person's certificate.** A person's certificate held in a machine store
  (for example an S/MIME certificate in `LocalMachine\My`) leaves the inventory when it is removed
  from the device, at the next successful read of that store, or when the device is decommissioned.
  Slice 2 builds no per-subject erasure route. A data-subject request is met by removing the
  certificate from the device; if the device is offline, its rows stay until it reports or is
  decommissioned. The DPIA screening records this, and whether a per-subject purge is needed.
- **Engines.** An engine that consumes subjects and SANs becomes a data processor with its own
  retention and deletion duties. ADR-1005 Decision 5's review applies to any bulk transfer of them
  (the ADR-0024 re-home note is the precedent). The engine-grain read carries `last_seen` and
  `observed_at`, so an engine can honour deletion by absence.

## Dashboard widgets: the data they read

This section defines only the data each widget reads. The widget UI, layout and catalogue are
proposed in unmerged work (`feat/crypto-dashboard-widgets`) and are not specified here. Every
certificate widget reads under `CertificateInventory:Read`, except the registered-CRL widget,
which reads under `RevocationSource:Read`. A caller without the permission sees "not available to
this account (<permission> is required)", never zeros (D12, `0070:901-905`).

| Widget (data, not UI) | Reads | Slice |
|---|---|---|
| Certificates per weak-key rule | counts `weak_key_rules[]` | 2a-3 |
| Active certificates | counts `active` | 2a-3 |
| Expiring within N days | counts `expiring_within_days[]` | 2a-3 |
| Expired within the last N days | counts `expired_within_days[]` | 2a-3 |
| Issued within 7 days; issued per ISO week | counts `issued_within_days`, `issued_per_iso_week` | 2a-3 |
| Key algorithm and size distribution | summary, grouped by raw value | 2a-2 |
| Store coverage (stores `unreadable` / `constrained` / `not_observed`) | per-certificate read `stores[]`, or a summary group by `status` | 2a-2 |
| Revoked within N days; revoked per ISO week | counts `revoked_within_days[]`, `revoked_per_iso_week` | 2b-2 |
| Registered CRLs past `nextUpdate` | the revocation-source list's `crl_past_next_update` (`RevocationSource:Read`) | 2b-1 |

Each widget drills into the per-certificate read with the matching filter, at the counts
response's `as_of`. A paged drill is not guaranteed to recompute the widget's number exactly (paged
reads make no cross-page promise); the snapshot export is the exact check, and the D13 recompute
test pins it. The Yuzu-CA widgets (R2) are not certificate widgets: ADR-0070
gates them on `Inventory:Read`, with the confined-caller note, and they are never joined to these.

## Tests and chaos

**Decided (ADR-0070 D12 "Chaos", `0070:1057-1067`):** the slice-2 PR runs CH-1..CH-6 before merge.
Each is defined by the property it must prove.

### Unit and integration tests (Proposed)

- **Agent** (`tests/unit/test_certificates_inventory_*.cpp`, suite `agent`):
  - parser goldens per OS: every field, including PSS parameters, explicit-curve order bits,
    Ed25519/Ed448, UTCTime/GeneralizedTime boundaries, a negative serial, `TRUSTED CERTIFICATE`
    blocks, and multi-block bundles;
  - a private-key block is skipped before base64 decode (an instrumented decoder is never called);
  - symlink alias versus `link_outside_roots`;
  - every cap and reason token;
  - a status-only blob when every store is unreadable, and no blob only when the action fails
    before naming a store;
  - chained, looping, dangling and outside-root links, each reading the right reason token;
  - file buffers cleansed (an instrumented allocator sees no key bytes after release);
  - blob determinism (two runs, identical bytes);
  - the sync-only assertions: no catalogue row names `certificates.list_inventory`, and a dispatch
    through the shared chokepoint is denied `unclassified` for an operator and a system caller.
- **Server store** (`tests/unit/server/test_cert_inventory_store.cpp`, `YUZU_REQUIRE_PG_DB`):
  - the per-store replace table above, row by row;
  - orphaned facts are deleted;
  - prune predicate truth table, including "age alone never prunes" and the cap per pass;
  - `content_hash` is cleared on prune;
  - decommission;
  - the schema lint.
- **Ingest:** direct/gateway parity; cap refusals on both sides; no rows written for a
  decommissioned agent on either path; a status-only blob marks every store `unreadable` and keeps
  its rows; unknown versus empty; version
  refusal; hash-skip advancing `observed_at` only for `ok` / `absent` stores; server re-parse
  overriding a mismatched claim.
- **Typed set (2a-1):** the array drives the predicate, the purge and the filter. A typed row is
  invisible to `get`, `query` and `list_tables`.
- **Routes:** the floor under RBAC off (an admin is admitted; a user is denied with the A4 body
  naming `CertificateInventory:Read`); RBAC on with and without the grant; confinement asserting the
  exact visible set; a service-scoped session; 503-never-empty on store degrade and on
  `CryptoReadGate` shed; a lost audit row on a REST read gives 503 with `Sec-Audit-Failed` and no
  data, and on MCP and the dashboard gives the data with the notice; the truncation OR rule;
  service-scoped tokens get 403 on both securables in both RBAC states;
  REST/MCP parameter parity (the same bad value is refused on both).
- **D13:** the condition-1 lint over OpenAPI, MCP schemas and fragments; the closed allow-list; a
  recompute test that takes one snapshot export and rebuilds every count it returns, `active` and
  `checked_some_reasons_only` included, from the rows it returns at the `as_of` it returns, with an
  independent predicate per R5/R10/R14 edge, failing on any difference (`0070:1326-1330`). Edge
  cases it pins: `not_after == as_of` (active and expiring, not expired); a not-yet-valid
  certificate (in neither `active` nor any expiring window); `not_before` exactly
  `as_of - 7 days` (not issued, lower bound exclusive) and one second later (issued); the same two
  for `revocation_date`; a week boundary at Monday 00:00:00 UTC; the 52nd week back.
- **Parse error:** a blob with one malformed record (a trailing unpaired `\`) among good ones is
  acked; that record's store reads `constrained`/`parse_error`, its stored rows are kept and its
  `status_at` advances; the other stores ingest normally; the next day's hash-skip of the same bytes
  still shows the store `constrained`/`parse_error`; and an unparseable `ver|` header is nacked.
- **Snapshot export:** an ingest committed while the export's transaction is open does not appear
  in it, and its counts still match its rows; an export past its bound sets `result_truncated` and
  `rows_returned` and never omits rows silently.
- **Blob:** the framing round-trips store IDs with backslashes, DNs with RFC 4514 escapes, pipes,
  CR and LF byte for byte; a byte cut is deterministic and every store after it reads
  `constrained`/`byte_cap` with its server rows kept.
- **Fetch:** a `PUT` that drops the fetching URL or the verifying key while a fetch is in flight
  ends with no CRL stored and cause `config_changed`; so does a `DELETE` followed by a re-register
  of the same CA (same URL) while a fetch is in flight.
- **MCP approval:** a supervised MCP token gets `approval_required` for every `RevocationSource`
  and `CertificateInventory` mutation, on MCP and on REST.
- **R1:** registration validation; loopback and the server's own bind addresses refused at
  registration and on fetch; audit fail-closed (an injected audit failure leaves no source behind);
  a custom role granted `RevocationSource:Write` under RBAC on is refused; floor on
  `RevocationSource:Read`; a `PUT` dropping a URL or key removes its rows; `log_token` on URLs in
  audit and logs; the fuzz target.
- **SOC 2:** the access-review export (`GET /api/v1/rbac/roles/assignments` and the access-review
  campaign) lists grants of both new securables.
- **Alerts:** a `promtool test rules` case for each new alert, including the no-leader rule.
- **Capacity:** the D13 counts statement on a seeded fleet-scale table (see [Capacity](#capacity))
  finishes inside its statement timeout, and a forced timeout answers 503.

### Chaos mapping

| ID | Concrete tests |
|---|---|
| CH-1 | Store-ingest test: a device with `LocalMachine\Root`, `LocalMachine\My` and `LocalMachine\CA` rows. The next report has `My` `unreadable` mid-replace. Assert that `Root` and `CA` are replaced, that `My` keeps its rows and its original `observed_at`, and that `My` reads `unreadable`. A fault-injected agent run with every store failing sends a status-only blob (`ver|1` and one `store|` record per store, every one `unreadable`, no `cert|` records), never no blob, and ingest keeps every store's rows and `observed_at`. **Per-user clause:** slice 2 reads no per-user store, so "the departed user's rows go only through the per-user scope" is proved negatively: a Windows run while a user logs off yields no row with a non-empty `user_ref`, and an unopenable LocalMachine store is never answered from CurrentUser. The positive per-user CH-1 runs with the per-user opt-in. |
| CH-2 | Generated hostile certificates (OpenSSL in the test): 10,000 SANs, a 64 KiB subject, control and script characters, invalid UTF-8 in a `UTF8String`, `rfc822` SANs. Assert the caps hit and the certificate reads `constrained`. A headless-browser test loads the certificate fragments with those rows and asserts zero CSP `pageerror` and no executed script (the `CLAUDE.md` CSP rule). Audit details are checked against `log_token` output. E-mail SANs appear only on the per-certificate read, never in summary groups or audit details. |
| CH-3 | Slice 2 builds no chain result, so no platform is in scope for the cached-CRL and cached-OCSP half. The planted-certificate half still runs on all three OSes: a certificate whose AIA, CDP and OCSP URLs point at a local listener is collected, synced and read, and the listener sees zero connections (agent and server). With an R1 source registered for a different URL, the listener still sees zero connections and only the registered URL is fetched. |
| CH-4 | An offline device: its rows expose `observed_at` and `last_seen`, and are not pruned. An engine-grain read paged across a store failure injected between pages answers 503, never a short 200. A read capped at `limit` sets `result_truncated` and `page_limit`. A CBOM export with the certificate half capped carries coverage and the flag. |
| CH-5 | The agent clock is skewed by ±10 years with no change in stored times, since the blob carries none. Certificates expiring at `23:59:59Z` and `00:00:00Z` on window edges; `as_of` is `date_trunc('second', now())`, so a statement run at 12:00:00.7 compares against 12:00:00; a certificate whose `not_after` equals `as_of` exactly (active and expiring, never expired, per OD-3/R5); a certificate whose `not_before` is after `as_of` (in neither `active` nor any expiring window, R14); `99991231235959Z`; a 1950 UTCTime; a 1965 GeneralizedTime. Assert storage to the second, unclamped. Assert that D4 filters change only with the caller's T, and D13 counts only with `as_of`: the test runs the count statement in transactions with different `now()` values. No agent-side policy over certificate facts ships in slice 2, so the agent-clock disclosure clause has nothing to test yet; it binds the first PR that adds one. |
| CH-6 | A local CRL server fixture, one test per case: never fetched (`no_crl_fetched`); bad signature (`verification_failed`, held CRL unchanged); an older replayed CRL (`older_than_held`, held CRL unchanged, also after remove and re-register); a delta without its base (unused, `delta_not_supported`); a CA re-key (two registered keys, a CRL signed by the new key verifies); a `certificateHold` entry ("on hold", not counted as revoked); a certificate past `notAfter` at `thisUpdate`, without and with a covering `ExpiredCertsOnCRL`; a held CRL past its `nextUpdate` while every refetch fails or returns the same CRL (statements still drawn from it, each carrying its `nextUpdate` and `crl_past_next_update: true`, the source counted in `crl_past_next_update`, and the fetch backing off). after a high-water reset, a replayed pre-reset CRL that verifies (lower and higher number) is refused unless its `thisUpdate` is at or after the reset (less the skew) or its hash was pinned, and the CA reads "revocation not checked" meanwhile; the same replay arriving **after** the first post-reset CRL was accepted, signed by a reused key with a higher number, is still refused (`older_than_held`); a CRL whose `thisUpdate` goes backwards within a scope is refused with cause `this_update_backwards`, and the alert fires once the refusal persists; a reset with an administrator-supplied `reset_at` earlier than the CA's current `thisUpdate` then admits it, and the audit row records the supplied value. Plus: a redirect to an unregistered URL refused; a confirmed-public host re-resolving to a private address refused; an oversize body refused (`over_size_bound`); request headers asserted free of `Authorization` and `Cookie`. No case may read "not listed" or "revoked" wrongly. |

## Decisions

Decided by the owner on 2026-10-19:

- **Per-user stores: not in slice 2.** Machine scope only (LocalMachine stores, the macOS System
  and SystemRoots keychains, Linux trust stores). Per-user stores are a later opt-in under D12's
  `user_ref` and privacy rules, with their own privacy review.
- **Securables: `CertificateInventory` and `RevocationSource`.** `CertificateInventory:Read` for
  fleet certificate reads (admin-floored while RBAC is off, seeded only to Administrator);
  `RevocationSource:Read`/`Write` for CRL registration and the URL list (admin-only in both RBAC
  states). `CertificateInventory:Write` is decided as OD-4 below.
- **R1 ships in slice 2, as 2b after 2a.** ADR-0070 D12's "Slice 2 builds R1" stands.
- **The Yuzu-CA counts follow R2: `Inventory:Read`, with the confined-caller note.** Any widget or
  route that gates them on `Security:Read` must change to match.
- **OD-1: daily sync only.** The full-field collector (`certificates.list_inventory`) runs only
  inside the agent's daily sync and is refused on every dispatch path: it has no catalogue row, so
  the dispatch chokepoint denies it as `Unclassified`, and a catalogue test and a dispatch test
  prove it ([The collector](#the-collector)). Operators keep today's `certificates.list` for ad-hoc
  look-ups.
- **OD-2: REST certificate reads fail closed on audit failure.** They follow the `device_ci`
  behavioural-PII precedent through `rest_audit.hpp`'s `emit_behavioral_audit`: 503 with
  `Sec-Audit-Failed` and no data. The dashboard and MCP set-and-proceed, with the "audit not
  recorded" notice, as slice 1 does ([Audit and degrade](#audit-and-degrade)).
- **OD-3: the `not_after` boundary follows RFC 5280.** A certificate is valid through `notAfter`,
  inclusive, so `not_after == as_of` is active, not expired. OD-3 rules that boundary only. Every
  other window edge (issued and revoked lower-exclusive, expiring within active, 52 ISO weeks,
  `as_of` truncated to the second) is ADR-0070's R5, R7, R10 and R14, which this design adopts
  verbatim ([D13 counts](#d13-counts)).
- **OD-4: the tombstone list and purge use `CertificateInventory:Write` behind the administrator
  predicate.** The same shape as `RevocationSource`: admin-only in both RBAC states, since with
  RBAC off the legacy rule admits only admins to a non-`Read` operation (`auth_routes.cpp:944`)
  and with RBAC on the `is_rbac_administrator` predicate refuses a custom-role grant. Seeding is
  unchanged (the Administrator loop grants every operation, `rbac_store.cpp:780-782`); no floor
  entry is needed, the floor covering `Read` only; the access-review export lists any custom grant.
  The purge mutates server-side tombstone rows only, never a device, so D6's read-only-by-
  construction rule for collection is unaffected. The new predicate call site means 2a-2 amends
  the A2/A1 access-control routed-concern row ([Ingest](#ingest)).

- **R-gen (senior review ruling, #6159 Gate 8): no dataset generation.** D13 condition 2's
  recompute promise is carried by the one-transaction snapshot export, not by generation-bound
  paging. Paged reads make no cross-page consistency promise and say so
  ([Truncation](#truncation)).

Decided by ADR-0070 R1 (recorded here so no section reads otherwise):

- **`RevocationSource` is admin-only in both RBAC states, so it is not grantable.** An
  administrator predicate in the `is_rbac_administrator` style backs the securable. The operations
  are `Read` and `Write` only; removal is a `Write`. The fetcher always refuses loopback and the
  server's own bind addresses ([Registration](#registration)).

Still open for the owner:

1. **DPIA and works-council position for machine-scope certificate data.** Proposed: a recorded
   DPIA screening, owned by the owner and the compliance-officer, with no works-council trigger
   because the data is not behavioural ([Personal data](#personal-data)).
2. **Cross-schema matching.** Proposed: two schemas with one named query owner on one PgPool. The
   alternative is the revocation tables in the `cert_inventory` schema ([The store](#the-store)).
3. **An outbound proxy for the CRL fetcher.** Proposed: none in 2b-1
   ([The fetcher](#the-fetcher)).
4. **CBOM `revocationDate`.** Proposed: left empty in 2a-4 and revisited after 2b-2
   ([CBOM certificate components](#cbom-certificate-components)).
5. **Mapping `key_provider` to "hardware-backed".** Proposed: no mapping. The raw provider name
   only ([Private-key metadata](#private-key-metadata)).
6. **Retention of locations in a store that stays `constrained`.** Proposed: a location missing
   from every report over 30 days of the store's own reports is treated as not observed at location
   grain and pruned. D12 states its prune condition at store grain, so the owner confirms this
   reading, or chooses to keep such rows under a per-store ceiling instead
   ([Retention and the prune](#retention-and-the-prune)).

## How this could ship wrong

1. **A failed or kept store reads as current.** Kept rows shown without their store status, or a
   hash-skip that advances `observed_at` for an `unreadable` store. Guard: `stores[]` on every read,
   the ingest table, CH-1 and CH-4.
2. **A typed source leaks through the generic store.** Shipping 2a-2 before 2a-1, or a second
   purge list drifting from the typed set. Guard: the PR order and the one array.
3. **The floor is missed on one gate.** A certificate rollup routed through `require_list_read`,
   which does not apply the floor (`auth_routes.hpp:407-413`), would be open to every signed-in
   user under RBAC off. Guard: `require_fleet_read` everywhere, and a floor test per route and tool.
4. **SPKI or SHA-1 used as identity.** A rollup or lifecycle join on `spki_sha256` would treat
   different certificates over one key as one certificate. A join on the SHA-1 thumbprint would
   reintroduce the collision-weak identity. Guard: `sha256` is the only key.
5. **The CBOM `fingerprint` filled with the wrong digest.** Whole-DER SHA-1 or SHA-256 passes
   schema validation but is not "excluding its signature". Guard: `tbs_sha256` only, with a golden
   test recomputing it from DER.
6. **"Revoked" from an agent claim.** A planted certificate that copies a registered issuer and a
   listed serial reads as plainly revoked if the basis wording is dropped, or if
   `cert_signature_check` is keyed on the agent's claimed hash rather than the server's own. Guard:
   key on the server-recomputed `sha256`, and the basis field on every statement and count.
7. **"Not listed" from a failed fetch.** A source whose fetch failed, or that has never fetched,
   matches no entry and so reads "not listed". Guard: `not_listed` requires a held, verified,
   in-scope CRL; everything else is `not_checked` with a cause; CH-6.
8. **The fetcher becomes an SSRF primitive.** A URL from a certificate's CDP reaches it, a redirect
   is followed off the registered set, or DNS rebinding moves a public URL to an internal address.
   Guard: the source-id-only interface, the address check and pin on every fetch, CH-3 and CH-6.
9. **Anti-rollback lost on re-registration.** Remove and re-register a source, then serve an older
   CRL. Guard: the high-water tombstone.
10. **SHA-1 roots inflate the weak-key counts.** `sig_sha1` counts every SHA-1-signed root in every
    trust store, and a reader takes it as an estate-wide incident. That is a true fact, shown with
    its criterion. Guard: the `ca_certificates` / `end_entity_certificates` split on each count, and
    the criterion text. Never a label.
11. **An older agent's NULL fields read as "no weak keys".** Guard: `not_evaluable` on every rule
    count, and `blob_versions` on the read.
12. **Truncation contradicts itself.** A top-level `result_truncated: false` beside a capped SAN
    list or a constrained store. Guard: the OR rule and its test.
13. **The window set is copied.** Slice 2 compiles its own window arrays beside another count
    surface's, and the two drift from each other or from ADR-0070. Guard: one shared set, written
    to R5/R7/R10/R14, and the per-source recompute tests.
14. **The admission gate is starved.** Certificates, counts, the CBOM and the widgets now share two
    slots. Dashboard polling sheds reads to 503 and an operator sees "temporarily unavailable" all
    the time. Guard: measure in 2a-3 before the widgets ship.
15. **The sync-only collector becomes dispatchable.** Someone adds a catalogue row for
    `certificates.list_inventory` "for consistency", and its full output lands in the ResponseStore
    under `Response:Read`. Guard: the catalogue test that no row names it, and the dispatch test.
16. **A decommissioned device comes back, or a live one vanishes.** A late or replayed report
    re-creates the rows decommission erased; or a live agent decommissioned in error drops out of
    every count with nothing to show it. Guard: the ingest decommission check and its test, and
    `coverage.tombstoned_agents_registered` with the admin tombstone list.
17. **An unread link reads as a complete store.** Guard: `link_outside_roots` and
    `link_unresolved` make the store `constrained`.
18. **The window edges drift between surfaces.** The certificate counts and any Yuzu-CA count
    use different edges or a different week span from ADR-0070's R5/R7/R10/R14. Guard: one shared
    set of constants and edge predicates, and the per-source recompute tests.
19. **A count is "recomputed" from paged reads.** A caller pages the live read, gets a different
    number from a counts response and reports a defect, or trusts a number it cannot reproduce.
    Guard: paged reads disclose that they make no cross-page promise, and the snapshot export,
    one transaction, is the only exact check.
20. **Personal data in a lower-privileged projection.** A SAN or subject used as a summary group, a
    metric label or an audit detail. Guard: the personal-data rules above and CH-2's checks.
21. **The subject substring search becomes a person search.** `subject_dn_contains` is admitted
    without `is_ca=true`, or the condition is checked on REST but not on MCP. Guard: one shared
    parameter validator for both twins. A test refuses the bare filter on each twin. Another test
    sends `is_ca=true` with an end-entity row in the store and asserts that row is not returned.
22. **A substring filter becomes a pattern.** An unescaped `%` or `_` in `issuer_dn_contains`
    matches far more than was typed, and the caller reads it as a match. Guard: the value is
    escaped before it reaches `ILIKE`. A test filters on a literal `%` and `_` and checks that only
    the literal rows return.

## ADR-0070 clause map

| ADR-0070 clause | Where this design meets it |
|---|---|
| D4: raw dates, caller thresholds, server clock | [Fields](#fields-collected) (UTC to the second, unclamped); [Parameters](#parameters-strict-or-free-text-the-same-on-both-twins) (caller T and thresholds); [D13 counts](#d13-counts) (`as_of`); no `days_remaining` anywhere |
| D5: device-local chain conditions | No chain result is built ([What slice 2 delivers](#what-slice-2-delivers)); CH-3 |
| D5: R1 revocation-statement rule | [R1](#r1-registered-crl-revocation-slice-2b), quoted under [Matching and statements](#matching-and-statements) |
| D6: read-only by construction | [The collector](#the-collector) (no catalogue row, so never dispatchable; a compile-time assertion that the sync source's action list is exactly `list_inventory`; a plugin test that it reaches no write, delete or key-opening call) |
| D6: no private keys | [Private-key metadata](#private-key-metadata); PEM key blocks skipped before decode |
| D6: separate from CaStore and trust anchors | [The store](#the-store) (own schemas); registered CA certificates never a TLS or PKI anchor ([The fetcher](#the-fetcher)) |
| D6: collection gaps | [The D6 collection gaps](#the-d6-collection-gaps-closed-or-disclosed) |
| D7: CBOM facts only | [CBOM certificate components](#cbom-certificate-components) |
| D10: no-verdict posture and lint | [D13 counts](#d13-counts) (closed allow-list entries); `not_read` list; no grading in widgets |
| D12: securable, floor | [The securable](#the-securable) |
| D12: gate and denial text | [Gates, confinement, denial text and errors](#gates-confinement-denial-text-and-errors) |
| D12: audit, degrade, admission | [Audit and degrade](#audit-and-degrade); [Admission](#admission) |
| D12: truncation flags | [Truncation](#truncation) |
| D12: raw fields for D13 | [Fields](#fields-collected) (`pss_hash_oid`, `ec_order_bits`) |
| D12: personal data | [Personal data](#personal-data) |
| D12: untrusted input | [Deadlines and caps](#deadlines-and-caps); [Ingest](#ingest); CH-2 |
| D12: honest capture, `observed_at`, retention | [Blob contract](#blob-contract); [Ingest](#ingest); [Retention](#retention-and-the-prune) |
| D12: identity, `user_ref`, distinct counts | [Fields](#fields-collected); [Store](#store-and-schema); [Per-user scope](#per-user-scope) |
| D12: lifecycle | [Typed set](#typed-set-purge-and-read-filter); [Decommission and readiness](#decommission-and-readiness); [Background jobs](#background-jobs) |
| D12: R1 registration, fetcher, job, store, alerts | [Registration](#registration); [The fetcher](#the-fetcher); [Background jobs](#background-jobs); [The store](#the-store); [Metrics and alerts](#metrics-and-alerts) |
| D12: chaos CH-1..CH-6 | [Chaos mapping](#chaos-mapping) |
| D13: four rules, windows, `crl_past_next_update` | [D13 counts](#d13-counts) |
| D13: conditions 1–5 and mechanical checks | [D13 counts](#d13-counts) (count object, one statement, lint); [Store](#store-and-schema) (schema lint); [Tests](#unit-and-integration-tests-proposed) (recompute test) |
| D13: R2 | Not slice 2's surface; [Dashboard widgets](#dashboard-widgets-the-data-they-read) keeps the Yuzu-CA widgets separate |
| D13: R3 | Slice 3; not touched |
| D13: R4 | [D13 counts](#d13-counts) (one statement, `as_of` returned) |
| D5/D12: R1 (registered-CRL revocation) | [R1](#r1-registered-crl-revocation-slice-2b): [Registration](#registration), [The fetcher](#the-fetcher), [Verifying and accepting a CRL](#verifying-and-accepting-a-crl), [The store](#the-store), [Matching and statements](#matching-and-statements), [Metrics and alerts](#metrics-and-alerts) |
| D13: R5 (window edges, `as_of` to the second) | [D13 counts](#d13-counts) (window table); [Tests](#unit-and-integration-tests-proposed) (edge cases); CH-5 |
| D13: R6 (Yuzu-CA active, expiring, expired) | Not slice 2's surface; the Yuzu-CA counts are separate ([Dashboard widgets](#dashboard-widgets-the-data-they-read)) |
| D13: R7 (52-week span) | [D13 counts](#d13-counts) (window table) |
| D13: R8 (recomputing the Yuzu-CA counts) | Not slice 2's surface |
| D13: R9 (`crl_past_next_update` audience) | [D13 counts](#d13-counts) (served on the `RevocationSource:Read` list) |
| D13: R10 (the active edge) | [D13 counts](#d13-counts) (`active` count) |
| D13: R11 (Yuzu-CA expiring and expired cover `active` only) | Not slice 2's surface |
| D13: R12 (the gauge and its alert) | [Metrics and alerts](#metrics-and-alerts) |
| D13: R13 (partial-reasons CRLs) | [Matching and statements](#matching-and-statements); [D13 counts](#d13-counts) (`checked_some_reasons_only`) |
| D13: R14 (expiring within active) | [D13 counts](#d13-counts) (window table) |
| D13 condition 2 under R-gen | [Truncation](#truncation) (snapshot export) |

## Capacity

**Proposed.** Estimates, to be replaced by measurements in 2a-2 and 2a-3.

- **Rows per device.** The committed samples show 81 rows on Windows, 162 on macOS and 152 on Linux
  from today's narrower read (`agents/plugins/certificates/README.md`, sample section). With every
  machine store and every bundle block, expect about 300–600 distinct certificates per device and,
  on Linux, two to four locations each. At 100,000 devices that is about 30–60 million `cert_fact`
  rows, up to about 150 million `cert_location` rows, and a similar number of SAN and EKU rows. The
  per-device caps bound the worst case at 10,000 certificates per device.
- **No de-duplication of identical DER across agents (decision, Proposed).** Most rows are the same
  public roots on every device, so a shared certificate-body table keyed by `sha256` would cut
  storage several-fold. Slice 2 does not do it: per-agent rows keep the per-store replace,
  decommission and confinement each a single-agent operation, and a shared body table would need
  reference counting on every replace and decommission. The cost is mitigated by not shipping DER
  for self-signed roots. 2a-2 measures table size on a seeded fleet; above an agreed size, a shared
  body table is its own reviewed change.
- **What a 5,000-certificate host reads.** A store over 2,000 certificates reads `constrained`
  (`row_cap`) on every report, a blob over 3 MiB reads `constrained` (`byte_cap`), and DER past
  1 MiB is omitted (`der_omitted=budget`). Such a host is permanently `constrained`, which every
  read discloses in `stores[]`, `from_kept_rows` and the coverage block. It is never presented as
  complete. Raising a cap is a change on both the agent and the server ingest seam together.
- **The D13 counts statement** runs under a statement timeout of 10 seconds (`SET LOCAL
  statement_timeout`), on the indexes in [Store and schema](#store-and-schema), and holds one
  `CryptoReadGate` slot. A timeout is a 503 with a retry hint. 2a-3 measures it at fleet scale and
  records the plan.
- **CRL entries.** At most 64 sources, 8 URLs each, and 2,000,000 entries per CRL bound the
  `crl_entry` table. A replace writes one CRL's entries in one transaction, in the refresh job only.

## Still owed by every slice-2 PR

The obligations `docs/crypto-asset-design.md` lists under "Every slice still owes": `/governance`
and `/test`, REST and MCP twins with audit, a compile-checked `ExecuteGate`, capability-catalogue
and OS-capability-matrix updates, the generated plugin README (except for `list_inventory`, which
deliberately has no catalogue row and so no `ExecuteGate`, no matrix entry and no generated README
row; its README text is written by hand, see [The collector](#the-collector)), privilege and spawn-sink manifests,
changelog fragments, SOC 2 evidence, and the user manual (`docs/user-manual/crypto.md`,
`rest-api.md`, `mcp.md`, `audit-log.md`, `rbac.md`). For SOC 2 specifically: both new securables
go in the access-control inventory, every new audit verb goes in the `audit-log.md` catalogue, and
the access-review export is tested to cover grants of both securables. The per-PR documents are
listed under [Phasing and PR order](#phasing-and-pr-order).
