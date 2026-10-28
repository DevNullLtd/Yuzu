# Cryptographic asset inventory: design and phasing

**Status:** design reference, mostly proposed. Only slice 1, the crypto-library view, is built:
PR #6056, merged to `dev` on 2026-10-18 (`be635620c`). A CycloneDX 1.7 CBOM export of that
slice-1 inventory (PR #6123) is also on `dev`, landed by #6143 on 2026-10-19. Everything from [Slice 2](#slice-2-certificate-inventory) on is a proposal that
each slice must confirm before it builds. Claims about existing code, slice 1 included, are
checked against `dev` at the date below; each cites the file it comes from. A claim marked
**Proposed** is a design intent that has not been built or tested.

Last checked against code: 2026-10-19.

## What this is for

Operators want one place to see the cryptography on their endpoints: which crypto libraries are
installed, which certificates exist and when they expire, which SSH host keys are in use, which
TLS and FIPS settings each machine enforces, and later which services actually negotiate what. The
long-term output is a cryptographic bill of materials (CBOM) in CycloneDX form.

The scope is deliberately narrower than "every cryptographic asset in the estate". The first phase
is an **endpoint crypto inventory** built from what the agent can read on the machine. Network
probing, file discovery and infrastructure connectors come later, opt-in, each behind its own
design decision.

This document records the phasing, the constraints every slice inherits, the decisions still open
and the ways this could ship wrong. The operator manual for what is built is
`docs/user-manual/crypto.md` (it landed with #6056).

## Principles every slice inherits

1. **Core collects facts; it does not grade them.** ADR-1005's boundary test
   (`docs/adr/1005-headless-platform-use-case-engines.md`) puts interpretation (labels such as weak,
   deprecated or quantum-safe) in a use-case engine, not the server. Slice 1 follows this: it never
   labels a library or version good, bad, current or out of date (`crypto_library_model.hpp`).
   Where classification lives for later slices is decided by ADR-0070
   (`docs/adr/0070-cryptographic-asset-inventory-placement.md`): facts in core, verdicts in an
   engine, except two maintainer exceptions it rules into core: the closed set of built-in
   weak-key rules and dashboard windows (D13), and revocation status read only from
   operator-registered CRLs (D5 as amended, R1).
2. **A failed or partial read never looks like a clean answer.** "Supported, zero rows" must not
   read as "none installed", and a collector that could not read a source reports that, never an
   empty success. This is the most likely way the feature misleads (see
   [How this could ship wrong](#how-this-could-ship-wrong)).
3. **Machine-scope first.** Per-user material (user SSH keys, tokens, browser stores) is deferred to
   Phase 3 and the Forensics tier. ADR-0016 says its "no PII" reasoning was built for
   `installed_software` and does not transfer to another source unchanged, so each new source needs
   its own classification.
4. **Every read is confined.** Fleet reads go through an ADR-0017 admit-then-filter gate:
   `require_fleet_read` for per-device reads, as slice 1 does, or `AuthRoutes::require_list_read`
   for rollups that cannot be filtered. They are not interchangeable: `require_list_read` refuses a
   service-scoped session outright (`auth_routes.cpp`, documented in `auth_routes.hpp`). Its
   subordinate primitive, `RbacStore::authorize_list_read`, takes no session and admits everything
   while RBAC is off, so a route never calls it directly. Every surface ships as REST and MCP twins
   with audit (ADR-1005, the agentic-first rules).

## Building blocks that already exist

All checked against `dev`:

- **`certificates` plugin.** It reads the system stores on all three OSes and emits
  `subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage`, the same 8 fields on
  every leg. Dates are day-granular and the thumbprint is SHA-1. It reports no key algorithm, key
  size or signature algorithm.
  - Linux reads only the first PEM block of each file, so `list` omits every later certificate in a
    bundle. Matching only the first block limits which thumbprints can trigger a delete of a bundle
    file, but a delete naming that first certificate still removes the directory entry: the whole
    regular file, or just the link for a symlinked bundle entry, never the link's target
    (`certificates_plugin.cpp`, the comment above `read_cert_entry`;
    `certificates_linux_store.hpp:331-336, 431`).
  - A Windows read may fall back from LocalMachine to CurrentUser when LocalMachine cannot be
    opened. That result is marked CONSTRAINED. Delete is LocalMachine-only and fails closed (#4377).
  - On macOS, the System keychains are read in-process through SecItem. The login keychain goes
    through `security find-certificate` and `/usr/bin/openssl x509`.
  - Its securable is `Security`. `list` and `details` are `Security:Read`; `delete` is
    `Destructive`, `Irreversible` and `AdminOrApproval`.
- **Network plugins.**
  - `netstat` lists sockets with state and PID. Process name and path come from its `attribution`
    action.
  - `netprobe` measures ICMP, TCP-connect and DNS timing.
  - Neither performs a TLS handshake. `http_client` fetches `https` URLs, but it blocks private
    ranges and reports nothing about the negotiated parameters, so TLS discovery would be new
    code.
- **Software and posture plugins:** `pkg_inventory`, `installed_apps`, `runtimes`,
  `platform_security`, `system_hardening` and `local_security_policy`.
- **ADR-0016 daily sync** (`docs/adr/0016-agent-daily-sync-framework.md`). The typed sources are
  `installed_software`, `app_perf`, `device_ci`, `software_licensing` and `app_usage`
  (`typed_inventory_sources.hpp`). The framework requires:
  - one shared ingest seam for the direct and gateway paths;
  - a server-side hash recomputed from the received rows;
  - a jittered `need_full`;
  - a weekly full refresh;
  - bounds on the untrusted input.

  On the `inventory_state` row, `first_seen` and `last_seen` are server receipt time (#1685).
  Per-row timestamps that are payload are not: `first_seen` and `last_seen` on `app_usage`'s
  `agent_last_used` rows are agent-observed (`app_usage_store.hpp:43-48`).
- **`ConstraintAccumulator`** (`agents/shared/constraint_accumulator.hpp`), the shared way plugins
  report partial reads.

## Slice 1: crypto libraries (built, #6056)

Slice 1 is the low-hanging fruit: a server-side view over data the fleet already reports.

- **What it does.** It joins the existing `installed_software` table against a curated rule table
  compiled into the server. There is no new agent code and no new store.
- **Families.** The rule table has 12: OpenSSL, LibreSSL, BoringSSL, GnuTLS, NSS, Mbed TLS,
  wolfSSL, Libgcrypt, libsodium, Nettle, Botan and Bouncy Castle. Every REST and MCP response,
  and the summary fragment, carries `table_version`; it is `3` today (`kCryptoTableVersion`,
  `crypto_library_model.hpp:38`). The device-drill fragment does not carry it.
- **Surfaces.**
  - The `/crypto` page and its two dashboard fragments.
  - `GET /api/v1/crypto/libraries` and `GET /api/v1/crypto/libraries/devices`.
  - The MCP tools `get_crypto_libraries` and `list_crypto_library_devices`.
- **Access.** Every data surface (both fragments, both REST routes, both MCP tools) is gated on
  `Inventory:Read` with confinement; the page shell needs only a session. While RBAC enforcement is
  off, a service-scoped token is refused: `403` on REST, a refusal notice in the fragments, and an
  error on MCP.
- **What it proves.** Package presence and version only. It does not show that a library is in use,
  and it cannot see statically linked or vendored copies.

Known follow-ups are #6044 to #6050, #6052 and #6109.

## Slice 2: certificate inventory

**Proposed.** #6056 has merged; slice 2 starts after the placement ADR (ADR-0070, #6051) is
accepted, and its design must satisfy that ADR's D4, D5, D6, D7 and D12.

The slice-2 design is `docs/crypto-slice2-certificate-design.md`; where it and this section
differ, it governs.

- **A new action, not a change to `list`.** `list` is a stable contract, and its Linux leg's
  first-PEM-only rule limits which requests can reach a bundle-file delete. A new read-only action can enumerate every
  certificate in a bundle without touching the delete path.
- **Fields.**
  - Emit OIDs rather than names: `key_alg_oid`, `key_bits_or_curve` and `sig_alg_oid`.
  - Also emit EKU, `is_ca`, `self_signed`, and absolute `not_before` and `not_after` timestamps.
- **`spki_sha256` as the cross-device key identity.** SPKI stays stable only when the
  certificate is re-issued over the same key; key rotation changes both. So SPKI identifies a key,
  never a certificate. Equal SPKI means shared public-key material. It does not mean the same file
  or the same service.
- **Store provenance on every row.** A CurrentUser certificate from the Windows fallback must never
  be reported as machine scope.
- **Platform APIs.**
  - Linux: libcrypto (`X509_get0_pubkey`, `EVP_PKEY_bits`, `X509_get_signature_nid`).
  - Windows: CryptoAPI (`CERT_INFO.SignatureAlgorithm`, `CertGetPublicKeyLength`).
  - macOS: a machine-store allowlist, `System.keychain` and `SystemRootCertificates.keychain`
    only, read in-process as the existing leg reads them. The machine-scope sync never reads the
    console user's login keychain, which the existing `list` reaches with `store=all`.
- **No stored or synced days-to-expiry.** The agent syncs full UTC validity timestamps
  (`not_before`, `not_after`) and nothing relative to "now": a relative value would change every
  day and defeat the daily sync's hash-skip. The server does not compute or serve a
  `days_remaining` field either (ADR-0070 D4 and its placement table). Expiry is read only
  through caller-supplied filters over the raw timestamps (D4) and D13's named, fixed read-time
  windows, each computed against Postgres `now()` and returned with its `as_of`.

## Slice 3: SSH host keys and usage

**Proposed.** It needs an ADR and privacy decisions first.

- **Public keys only.** Read only `ssh_host_*_key.pub` (`%ProgramData%\ssh` on Windows). Never open
  a private key file.
- **Fields.** Emit type, bits and SHA-256 fingerprint. Strip comments and certificate principals.
- **File times are not key age.** A private key file's mtime is reported as a file time.
- **Usage needs its own privacy review.** "Which device, when, who, how" is closer to behavioural
  data than to inventory, so it is decided separately.

## Later in Phase 1: crypto configuration

**Proposed:** a read-only `crypto_config` collector.

- **Rows.** `source|key|value|state`, where `state` is one of `value`, `absent`, `unreadable` or
  `unknown`. Partial reads are reported through `ConstraintAccumulator`, with one `try/catch` across
  the plugin ABI.
- **Windows.** SCHANNEL protocol and cipher settings, including `KeyExchangeAlgorithms`, plus the
  .NET `SchUseStrongCrypto` and `SystemDefaultTlsVersions` values (in both the 64-bit and
  `WOW6432Node` views), the cipher-suite-order policy and `FipsAlgorithmPolicy`.
- **Linux.** `/proc/sys/crypto/fips_enabled`, the crypto-policies `openssl.cnf` settings
  (`MinProtocol`, `CipherString`) and Java's `jdk.tls.disabledAlgorithms`.
- **Configured is not effective.** A registry value or config file is what is configured. The
  effective policy also depends on defaults, group policy and per-application settings.

## Storage, sync and surfaces for the new data

**Proposed.** These are the choices a typed source forces, recorded so a slice cannot skip them.

- **A typed daily-sync source** (working name `crypto_inventory`), carried as a new `plugin_data`
  key with no proto change.
  - It must be registered in `typed_inventory_sources.hpp` in the same change. Otherwise the
    gateway path also stores it in the generic store, which `Infrastructure:Read` can read. That is
    a lower bar than the source's own securable.
  - The generic read path has no typed-source filter, so a mixed-version deployment can leave a
    stray row readable until the next boot purge. `app_usage` and `device_ci` already accept this
    gap; a new source must accept it explicitly or close it.
- **Hashing.** Choose deliberately between server-side canonical reconstruction (the
  installed-software store's approach) and raw-byte hashing (`app_usage`'s). Rows are sorted
  deterministically before hashing, and only absolute timestamps are synced.
- **A failure contract**, which ADR-0016 does not supply:
  - schema-version compatibility and duplicate-identity rules;
  - "complete and empty" kept distinct from "failed" or "truncated";
  - a separate replacement boundary per collector, so one unreadable directory cannot erase another
    collector's facts. On failure, the previous facts are kept and marked stale;
  - serialised concurrent replaces for one agent, as the software store already does;
  - collection-disable semantics, byte and row budgets, purge, and per-source coverage reporting.
- **A store.** A new born-on-Postgres store would follow ADR-0006 and ADR-0007 (Postgres,
  fail-closed construction) and ADR-0012 (a declared runtime failure posture, bounded acquires, one
  lease per operation). It stamps freshness with server receipt time, as ADR-0016 requires (#1685).
- **Access and projection.**
  - Decide the securable (open decision 2). For certificates ADR-0070 D12 has decided it: a
    dedicated certificate securable, not `Inventory` or `Security`.
  - Decide, per action and per field, what each tier sees, including with RBAC off. Paths stay out
    of the daily blob and are served on demand, as ADR-0016 does for install locations. Whether an
    on-demand read needs a stricter tier is decided per field (open decision 3).
- **Surfaces.** REST list and summary, an MCP twin, and a CycloneDX export (see
  [CBOM export](#cbom-export-cyclonedx-17)).
- **Metrics.** Low-cardinality only, never one label per certificate. Each alert rule in
  `docs/prometheus/yuzu-alerts.yml` ships with a test proving it can fire.

## CBOM export (CycloneDX 1.7)

**Status:** built for library components only (#6123): `GET /api/v1/crypto/cbom` and the MCP tool
`export_crypto_cbom` emit one CycloneDX 1.7 `library` component per (family, version, ecosystem)
bucket of the Slice 1 summary (`server/core/src/crypto_cbom.*`), validated in CI against the
vendored `bom-1.7.schema.json`. Algorithms, certificates, keys and protocols are not exported yet;
they follow their own slices. Separately, release tooling generates SBOMs of Yuzu's release
artifacts and images with `anchore/sbom-action`, and `scripts/check-release-artifacts.sh` checks
that they exist.

**Background.** CycloneDX added cryptographic assets in 1.6 (2024-04-09). 1.7 keeps the same model and
extends it:

| Version | Released | Crypto support |
|---|---|---|
| 1.6 | 2024-04-09 (1.6.1: 2024-11-07, 1.6.2: 2026-06-02) | `component.type` `cryptographic-asset` and `cryptoProperties`. Asset types are `algorithm`, `certificate`, `protocol` and `related-crypto-material`. Certificates carry `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef` and `subjectPublicKeyRef`. Key material types include `private-key`, `public-key`, `secret-key` and `token`. Protocol types include `tls` and `ssh`. |
| 1.7 | 2025-10-21 (1.7.2: 2026-09-17) | Same four asset types. Certificates add `serialNumber`, `fingerprint`, `certificateState`, lifecycle dates and `relatedCryptographicAssets`, and deprecate `signatureAlgorithmRef` and `subjectPublicKeyRef` in favour of `relatedCryptographicAssets`. Protocol types add `dtls` and `quic`, among others. |

This was checked against the published JSON schemas `bom-1.6.schema.json` and
`bom-1.7.schema.json` in `CycloneDX/specification`.

**Decision: the export targets CycloneDX 1.7** (decided 2026-10-18). 1.7 adds `serialNumber`, which
the existing plugin already emits, and a `fingerprint` hash object; 1.6 would need custom
properties for both. The schema defines `fingerprint` as a hash of the certificate excluding its
signature. The plugin's SHA-1 thumbprint hashes the whole DER, signature included, so it cannot
fill that field, and schema validation would not catch the mismatch. `fingerprint` needs a new
digest that excludes the signature; slice 2 collects one
(`docs/crypto-slice2-certificate-design.md`), and until then the field stays empty. The export pins `bom-1.7.schema.json` and CI validates every export against
it. A consumer that reads only 1.6 is not a target. Supporting one would be a separate, explicit
change.

**Mapping notes:**

- Certificate dates map to `notValidBefore` and `notValidAfter`.
- Algorithms and keys are separate components that certificates reference through
  `relatedCryptographicAssets`, not the deprecated `signatureAlgorithmRef` and
  `subjectPublicKeyRef`.
- A library from Slice 1 is an ordinary `library` component, not a `cryptographic-asset`.
- The library components carry no `purl`, `cpe` or hash, so vulnerability scanners cannot match
  them (an empty scan result means "not matchable", not "no known vulnerabilities"). A correct
  `purl` needs the distribution or namespace, which the inventory does not record (it keeps a
  package name, version and ecosystem string such as `deb`); emitting a distribution-aware `purl`
  is a known gap that needs that field collected first.
- The export shows facts only. CycloneDX also has strength fields such as
  `nistQuantumSecurityLevel` and `classicalSecurityLevel`. Filling those in is interpretation, so
  they stay empty in core (ADR-0070 D7).

## Phase 2: opt-in active and file discovery

**Proposed.** Each part needs its own threat model and routed-concern row before it builds.

### TLS listener probing (`tls_listeners`)

- **Allowlisted targets only.** Each probe runs through an established TLS implementation in an
  isolated context, and never weakens the agent's own transport configuration.
- **It measures the probe's own view.** The result records the probe's capability set. Anything the
  probe could not test reads `untested`, never `unsupported`. Probing legacy protocols needs its own
  threat model.
- **Keyed by endpoint, not port.** Observations are keyed by address family, bind address, port,
  namespace and SNI, not by `(agent_id, port)`.
- **It records what was negotiated:** the key-exchange group and signature scheme. PQC readiness
  needs these.

### Crypto files (`crypto_files`)

- **Metadata first.** Search explicit machine-scope roots plus validated operator roots, with mount
  and ownership policy. Excluding `/home` alone misses relocated homes, `/root`, junctions and
  mounts.
- **It needs a new read-only walker.** `walk_dir_capped` (`posix_dir_walk.hpp`) has an entry cap
  only: no deadline and no confinement. `confined_fs` is built for deletion and leaves root
  authorisation to its caller. The new walker needs:
  - reparse-point, hard-link and mount policy;
  - regular-file checks;
  - global budgets;
  - incomplete-result reporting;
  - wiping of sensitive buffers.
- **Content sniffing is a separate, approved action.** It reads at most the armour `BEGIN` line
  (about 100 bytes); a 4 KB "header" read can contain an entire private key. Whether that is enough
  to classify OpenSSH-format keys is untested.
- **Key material is never parsed or decrypted,** and no default passwords are tried. Encryption
  status can be `unknown`. POSIX mode bits do not show effective access, because ACLs and mount
  options also apply.
- **Symlinks are refused,** which skips layouts built on links (Let's Encrypt `live/` is likely
  one). The skipped-link count is reported.

### Libraries beyond packages

- **Evidence layers, each with a `confidence` field:** ELF `DT_NEEDED`, PE imports, version
  resources, and JAR or Python dist-info.
- **Keep the claims distinct:** installed package, declared dependency, mapped library and actual
  cryptographic use are different statements.
- **Process-to-library mapping is on-demand only.** It is never in the daily blob, and it needs
  PID-reuse protection (PID plus start time) and a privacy review.
- **Privilege varies by platform.** The agent is designed to run unprivileged, but that is not yet
  true on Windows (it runs as LocalSystem, #1442) or macOS (it runs as root, #1455). On Linux the
  install script grants `cap_net_admin`, `cap_net_raw`, `cap_dac_read_search` and `cap_sys_ptrace`
  (`docs/agent-privilege-model.md`). A collector reports what it could read, never what it assumes
  it can.

## Phase 2B: analysis and enforcement

**Proposed.** Each part depends on Phase 2 data and on the decisions below.

- **Linkage.** Connect a listener to its owning executable, its leaf SPKI, the file path and its
  libraries, stored as timestamped edges because each input refreshes at a different rate.
- **PQC readiness.** This is use-case-engine territory, behind the ADR-0032 interlock (ADR-0070
  D9), and reports classes, not a score. Key exchange on live TLS listeners ranks highest,
  because traffic recorded today can be decrypted later; signatures rank lower, except
  long-lived roots.
- **Result sets.** No result-set producer reads a typed store: `from-inventory-query` reads the
  generic store with a 5,000-row limit and refuses a truncated result. So `from_result_set` cannot
  build on crypto data until an authorised typed producer exists (open decision 6).
- **Policy and Guardian.**
  - A check verdict must keep `unknown` distinct from compliant.
  - Guardian's `registry-change` spark with `registry-value-equals` is Windows-only, and in enforce
    mode it writes values back. A registry value is not effective TLS policy, and automatic
    enforcement risks outages, so the default is detect-only.
- **Remediation.** Preflight has exactly five fixed read-only checks (app, OS version, architecture,
  disk space, pending reboot). Deploy stages and runs installers through `content_dist`. Neither is
  a crypto-change workflow, so a risky change such as disabling TLS 1.0 needs its own staged,
  approved flow with a post-change check.

## Phase 3: deferred

- Per-user SSH keys and token or secret locations (Forensics tier).
- Passive TLS observation through the TAR capture path (opt-in).
- Active subnet scanning from agent vantage points.
- Cloud KMS, Vault and Kubernetes connectors, as ADR-1005 engines.
- CBOM and SBOM import.

## Decisions needed

| # | Decision | Tracking |
|---|---|---|
| 1 | Where classification lives: a use-case engine, or a minimal carve-out in core recorded in an ADR | decided: ADR-0070 (#6051); D13 and D5 as amended (R1) are its maintainer exceptions |
| 2 | The per-action, per-field projection matrix, including RBAC-off behaviour. For certificates the securable is decided: D12's dedicated certificate securable (ADR-0070), not `Inventory` or `Security` | not filed |
| 3 | Which fields and paths go in the daily sync, and which are on-demand at an operator tier | not filed |
| 4 | The `tls_listeners` allowlist model: static config, per-fleet policy, or supplied per run | not filed |
| 5 | Whether any private-key content sniffing is allowed at all, and under what approval | not filed |
| 6 | An authorised typed result-set producer, or bounded device-ID materialisation | not filed |
| 7 | Whether the agent's capability set is guaranteed by the installer or only observed | not filed |

## How this could ship wrong

The three most likely failures:

1. **Incomplete collection reads as clean or absent inventory.** The failure contract above exists
   to prevent this.
2. **Privileged collection leaks sensitive bytes or identities** through a lower-privileged
   projection: the generic store, a summary, an export, or a legacy route.
3. **Active probes or remediation cause outages,** or report compatibility evidence that misleads.

Medium risks:

- Equal SPKI taken to mean one file or one service.
- `(agent_id, port)` used as a listener key.
- A private key file's mtime taken as the key's age.

## Every slice still owes

Each slice carries the usual obligations:

- `/governance` and `/test`;
- REST and MCP twins with audit;
- a compile-checked `ExecuteGate` for each action;
- capability-catalogue and OS capability matrix updates;
- plugin READMEs;
- privilege and spawn-sink manifest updates;
- a changelog fragment;
- SOC 2 evidence;
- works-council and privacy review for anything near per-user data.
