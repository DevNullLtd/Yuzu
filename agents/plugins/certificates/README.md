# certificates

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Certificate inventory and management for system stores |
| **Version** | 1.0.0 |
| **Kind** | Action · mutating · gathered (security.certificates.list, security.certificates.details, security.certificates.delete) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `delete` (definition `security.certificates.delete`) · `details` (definition `security.certificates.details`) · `list` (definition `security.certificates.list`) |
| **Security** | `list`: securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `details`: securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `delete`: securable `Security` · operation Delete · risk High · dispatch Destructive · approval gate AdminOrApproval |
| **Roles** | execute: `list`: endpoint-admin, endpoint-operator, security-admin; `details`: endpoint-admin, endpoint-operator, security-admin; `delete`: endpoint-admin, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`list` and `details` enumerate certificates in the OS's own stores and emit the same eight-field row per certificate; `list` returns every match (filtered by `store` and `expiring_within_days`), `details` returns the one row whose thumbprint matches (case-insensitive) or a `status|not_found`. `delete` is destructive: it hex-validates the thumbprint, then removes the certificate from the named store. On macOS `delete` additionally pre-checks presence before ever running the destructive command (so deleting an absent cert reports `status|not_found` instead of a command failure) and re-enumerates the keychain afterward to prove the certificate is actually gone before reporting `status|deleted` — a zero exit code alone is not trusted.

Windows reads/writes CryptoAPI stores (MY, ROOT, CA, Trust) natively, in-process, no subprocess. `delete` opens the named store under the LocalMachine hive only and reports an error rather than falling back to CurrentUser; `list`/`details` do fall back to the CurrentUser hive when LocalMachine cannot be opened, and say so in the output and result status. Linux parses PEM files under `/etc/ssl/certs` via in-process libcrypto (`certificates_x509.hpp`) — the `openssl x509` subprocess this used to shell out to is gone. macOS is a genuine hybrid: System.keychain and SystemRootCertificates.keychain are read in-process via `SecItemCopyMatching`, bounded to 15 seconds per keychain through agent-core's `read_keychain_bounded` seam and abandoned (not cancelled) if `securityd` wedges past that bound, but the login keychain (the console user's own keychain, which the LaunchDaemon has none of itself) still reads through a `launchctl asuser`/`sudo -u`/`security find-certificate` subprocess hop — immediately preceded by an in-process re-check of `/dev/console`'s owner, so a fast-user-switch between console-user resolution and the spawn is refused rather than read against the wrong session — and `delete` always shells out to `/usr/bin/security delete-certificate`. Every macOS action runs under a shared 60-second wall-clock budget covering console-user resolution and every keychain read/parse it performs, so a wedged Directory Service or a pathological keychain degrades honestly (a `not_available|<reason>` row plus a `CONSTRAINED`/`PARTIAL` result status) instead of hanging or silently truncating.

This plugin deliberately does not validate a certificate's trust chain, check revocation (CRL/OCSP), import or renew certificates, or read anything beyond the fixed set of stores/keychains named above.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Security.Read / Security.Delete]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[certificates.execute]
  EX --> WIN[Windows leg<br/>CryptoAPI, in-process]
  EX --> MAC[macOS leg<br/>SecItem (System/root, in-process)<br/>+ security find-certificate/delete-certificate (login, subprocess)]
  EX --> LIN[Linux leg<br/>libcrypto PEM parse, in-process]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `delete` | ✅ supported · rung 1 · CryptoAPI (CertDeleteCertificateFromStore) | 🟡 constrained · rung 2 · security delete-certificate via subprocess runner | ✅ supported · rung 1 · libcrypto X509 match + held-dirfd openat/fstatat/unlinkat with pre-unlink identity recheck |
| `details` | ✅ supported · rung 1 · CryptoAPI (CertEnumCertificatesInStore) | ✅ supported · rung 2 · SecItem (System/root, in-process) + security find-certificate argv via subprocess runner (login) | ✅ supported · rung 1 · libcrypto X509 (in-process PEM parse) |
| `list` | ✅ supported · rung 1 · CryptoAPI (CertEnumCertificatesInStore) | ✅ supported · rung 2 · SecItem (System/root, in-process) + security find-certificate argv via subprocess runner (login) | ✅ supported · rung 1 · libcrypto X509 (in-process PEM parse) |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`delete` / macOS** — SystemRootCertificates.keychain is sealed under SIP and rejected outright; only System/MY store deletes are supported
- **`details` / macOS** — System.keychain and SystemRootCertificates.keychain are read natively via SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo session hop, run as a pre-split argv through the bounded subprocess runner
- **`list` / macOS** — System.keychain and SystemRootCertificates.keychain are read natively via SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo session hop, run as a pre-split argv through the bounded subprocess runner
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | `list`/`details`: none — `CertEnumCertificatesInStore` needs no elevation. `delete`: `SeBackupPrivilege` + `SeRestorePrivilege` to write the certificate store; already granted to the service account under LocalSystem today, no new grant. | 2026-09-07, bare-metal Windows 10.0.26200.0 x64, as SYSTEM | `enumerate_store()` returns a typed result that records whether the store actually opened under LocalMachine or fell back to CurrentUser, never a silent empty vector (`certificates_plugin.cpp:337-408`); `list` reports `not_available\|<store> store could not be opened` (provenance `cryptoapi:store-open`, `certificates_plugin.cpp:420-428`) or `not_available\|<store> store enumeration incomplete` when `CertEnumCertificatesInStore` ends abnormally part-way through a store (provenance `cryptoapi:store-enum`, `certificates_plugin.cpp:430-435`), then keeps scanning the remaining stores; when LocalMachine could not be opened but CurrentUser could, `list` emits a `not_available\|<store> store (LocalMachine) could not be opened; rows read from CurrentUser` row before that store's rows (provenance `cryptoapi:store-fallback`, `certificates_plugin.cpp:437-449`); `details` marks the result partial per store internally and, unlike `list`, does not emit a row for a plain open/enumeration failure at the point it happens — it keeps scanning, and only if a match is never found does it report one combined `not_available\|<store(s)> could not be opened/enumeration incomplete/read from CurrentUser; scan incomplete` row naming every affected store, instead of a false `status\|not_found`; a CurrentUser fallback, an unopened store, or an incompletely-enumerated store are the exceptions to "no row until the end" — `details_cert_win` discloses each such earlier store immediately alongside a later match, right before the matched certificate's own row, rather than waiting for the combined end-of-scan summary — see the Result-status table's `cryptoapi:store-fallback`/`cryptoapi:store-open`/`cryptoapi:store-enum` entries below for the exact shape (`details_cert_win`); `delete` opens the named store under LocalMachine only, with no CurrentUser retry (#4377) — a store that cannot be opened there reports `error\|<store> store could not be opened; nothing removed` (`certificates_plugin.cpp:615`), and a store whose enumeration ends abnormally reports `error\|<store> store enumeration ended abnormally; nothing removed` (`certificates_plugin.cpp:651`), both with a non-zero exit instead of `status\|not_found` |
| macOS | agent daemon; the shipped LaunchDaemon has no `UserName` key, so it runs as root — but this sample was captured unprivileged (see Measured) | System/root keychain reads: none (in-process `SecItemCopyMatching`, no subprocess). Login keychain read: root, via `launchctl asuser` + `sudo -u` — live today only because the daemon runs as root; needs a dormant sudoers grant once #1455 narrows the agent off root. `delete` (System/MY only): a sudoers grant for `/usr/bin/security delete-certificate -t /Library/Keychains/System.keychain *` under the future non-root account; moot today. | 2026-09-07, bare-metal macOS 26.6.2 arm64, euid 501 (jsmith) — unprivileged, captured via the test harness (`PluginHandle::load` + `LocalDispatcher::run`, no `init()`), not the production root LaunchDaemon | System/root keychain read failure emits `not_available\|<keychain> not readable (no read permission)`, `not_available\|<keychain> read timed out` (15 s per-keychain bound exceeded), `not_available\|<keychain> read refused (bounded-call ceiling)`, `not_available\|<keychain> read failed`, or `not_available\|<keychain> scan incomplete` (the read was capped before it finished) — each + `CONSTRAINED`/`PARTIAL` (`certificates_macos_parsers.hpp:516-538`); an in-process `/dev/console` owner recheck immediately before the login-keychain spawn emits `not_available\|console user changed` (`certificates_plugin.cpp:1636`) or `not_available\|console user recheck failed` (`certificates_plugin.cpp:1640`); a failed login-keychain spawn emits `not_available\|login keychain read failed (<detail>)` naming the termination reason, on both `list` (`certificates_plugin.cpp:1697`) and `details` (`certificates_plugin.cpp:1945`) — the macOS sample shows a login-keychain degradation (`macos.txt:164-165`) |
| Linux | dedicated unprivileged `yuzu` account in production; this sample was captured as euid 0 in a container, not representative of that account | `list`/`details`: none — native filesystem read + in-process libcrypto parse, no subprocess. `delete`: write access to `/etc/ssl/certs` to remove the matching file via `unlinkat` on the held `/etc/ssl/certs` dirfd (`certificates_linux_store.hpp:418`). | 2026-09-06, Debian GNU/Linux 13 (trixie) aarch64 container, euid 0 | An unreadable/unparseable PEM file reports `(unreadable)`/`(skipped)` and `CONSTRAINED`/`PARTIAL` rather than being silently dropped, provenance `libcrypto:unreadable-file` (`certificates_plugin.cpp:691-696`); `details` reports `not_available\|... scan incomplete` rather than a false `status\|not_found` when a candidate file couldn't be inspected (`certificates_plugin.cpp:805-811`); `/etc/ssl/certs` could not be opened (including a non-directory or symlink at that path) reports `not_available\|/etc/ssl/certs could not be opened` and CONSTRAINED/PARTIAL, provenance `posix:cert-dir` (`certificates_plugin.cpp:855-857`); a readdir(3)/fdopendir enumeration of `/etc/ssl/certs` that fails part-way through reports `not_available\|/etc/ssl/certs enumeration incomplete` (`list`) or folds into `delete`'s `error\|/etc/ssl/certs enumeration incomplete; nothing removed`, provenance `posix:cert-enum` (`certificates_plugin.cpp:727-729,894-897`); a `delete` whose target's identity (link inode, target text, and target inode) changed between match and unlink reports `error\|certificate file changed during delete; nothing removed`, provenance `posix:delete-recheck` (`certificates_linux_store.hpp:389-431`; `certificates_plugin.cpp:883,890`), instead of unlinking a different file than the one matched |

Binaries/subprocesses/network: Windows — none, in-process CryptoAPI/`crypt32` only. macOS — `/usr/bin/openssl` (per-block PEM parse, `certificates_plugin.cpp:1164-1167`), `/usr/bin/security` (`find-certificate` for the login keychain, built by `build_login_keychain_read_argv` in `agents/shared/macos_console_user.hpp`; `delete-certificate`, `certificates_plugin.cpp:2063-2066`), `/usr/bin/stat` (console-user resolution, `certificates_plugin.cpp:1292`) — all via the bounded subprocess runner, pre-split argv, no shell. Linux — none, in-process libcrypto only (`certificates_plugin.cpp:82-87`). No network access on any OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `security.certificates.delete` | `thumbprint` | string | yes | - | - | SHA-1 thumbprint (hex string, no colons) of the certificate to delete. Case-insensitive. |
| `security.certificates.delete` | `store` | string | no | MY | - | The certificate store to delete from. On Windows: MY, ROOT, CA, or Trust. Defaults to "MY". On macOS: "MY" (the default) or "System" deletes from /Library/Keychains/System.keychain, matching prior behaviour. "root" is REJECTED (non-zero exit, unsupported) -- SystemRootCertificates.keychain is sealed by System Integrity Protection on modern macOS and cannot actually be modified, so attempting it would report a change that never took effect. "login" and "all" are also not supported for delete and are rejected with an error rather than silently deleting from an unintended store, as is any other unrecognized value. Ignored on Linux. On Windows the named store is opened under the LocalMachine hive only; if it cannot be opened there the action reports error\|<store> store could not be opened; nothing removed (non-zero exit) and never falls back to the CurrentUser hive. |
| `security.certificates.details` | `thumbprint` | string | yes | - | - | SHA-1 thumbprint (hex string, no colons) of the certificate to retrieve. Case-insensitive. |
| `security.certificates.details` | `store` | string | no | all | - | On macOS, restrict the search to one store: "login" (the current console user's login keychain -- returns not_available\|no console session when nobody is logged in at the console, or not_available\|<reason> when the console user could not be determined; in the latter case the search result is PARTIAL and never a definitive status\|not_found, because the login keychain was not opened), "System" (/Library/Keychains/System.keychain), "root" (SystemRootCertificates.keychain), or "all" (System and root, plus login when a console user is present). Ignored on Windows and Linux, which always search every store. Defaults to "all". |
| `security.certificates.list` | `store` | string | no | all | - | Filter by store name. On Windows: MY, ROOT, CA, Trust, or "all" for all stores. On macOS: "login" (the current console user's login keychain -- returns not_available\|no console session when nobody is logged in at the console, or not_available\|<reason> when the console user could not be determined, e.g. the directory lookup timed out; the two are deliberately distinct, a degraded lookup is never reported as an empty console), "System" (/Library/Keychains/System.keychain), "root" (SystemRootCertificates.keychain), or "all" (System and root, plus login when a console user is present). Ignored on Linux, which always enumerates every available certificate. Defaults to "all". |
| `security.certificates.list` | `expiring_within_days` | int32 | no | 0 | minimum 0 | Only return certificates expiring within this many days. Set to 0 to return all certificates regardless of expiry. Useful for compliance audits of soon-to-expire certificates. |
<!-- END GENERATED -->

### Outputs

`list` and `details` write a header row followed by zero or more pipe-delimited certificate rows, or a `status|not_found` / `not_available|<reason>` line in place of a row when nothing matched or a store couldn't be read; on Windows, a `not_available|<store> store (LocalMachine) could not be opened; rows read from CurrentUser` line precedes that store's own rows rather than replacing them, disclosing the CurrentUser fallback. `delete` writes one line only: `status|<value>`, `error|<message>`, or (macOS only) `not_available|<reason>`. `(unknown)` is the honest per-field sentinel for a value that failed to parse — it never means zero or empty; `subject`/`issuer`/`serial`/`key_usage` are escaped so a hostile value can never inject an extra pipe-delimited column or newline-delimited row.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`security.certificates.delete` — `status`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `error\|thumbprint parameter required` | A successful macOS delete emits status\|deleted; a delete targeting a certificate already provably absent from the keychain emits status\|not_found (rc 0), matching the Windows/Linux contract for an absent cert. store=root is rejected with error\|MESSAGE (SystemRootCertificates.keychain is sealed by System Integrity Protection). Every other macOS rejection or failure -- an unsupported store, a failed delete command, or a post-delete verification that still finds the certificate or could not re-read the keychain -- also emits error\|MESSAGE. Windows and Linux emit status\|deleted, status\|delete_failed, or status\|not_found on a store that opened successfully; either OS instead emits error\|<store> store could not be opened; nothing removed if every open attempt for the target store fails. Values: status\|deleted, status\|not_found, status\|delete_failed (Windows/Linux only), error\|<message> (any OS: bad thumbprint, unsupported/rejected store, an unopenable Windows/Linux store, or a macOS delete that could not be verified), not_available\|<reason> (macOS only, pre-validation). |

**`security.certificates.details` — `subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `subject` | string | - | Windows, Linux, macOS | `CN=com.apple.systemdefault, O=System Identity` | The certificate's Subject distinguished name, rendered by the OS's own name printer (CryptoAPI simple display name on Windows, OpenSSL/libcrypto's default name rendering on Linux and macOS System/root reads, the `security find-certificate` subprocess's `subject=` line on the macOS login keychain). Values: free text (distinguished name). |
| `issuer` | string | - | Windows, Linux, macOS | `CN=com.apple.systemdefault, O=System Identity` | The certificate's Issuer distinguished name, rendered the same way as subject. Values: free text (distinguished name). |
| `thumbprint` | string | - | Windows, Linux, macOS | `0C24DA5DE02640D8924F5C7BCB7D5F734815228D` | SHA-1 fingerprint of the certificate's DER encoding, uppercase hex with no separators -- always equal to the request's `thumbprint` parameter (canonicalized to uppercase) on a matching row. Values: 40 uppercase hex characters. |
| `not_before` | string | - | Windows, Linux, macOS | `2026-07-18` | Validity-period start date, YYYY-MM-DD (no time-of-day). Values: date (YYYY-MM-DD), or "(unknown)" when the source date could not be parsed. |
| `not_after` | string | - | Windows, Linux, macOS | `2046-07-13` | Validity-period end date, YYYY-MM-DD. Values: date (YYYY-MM-DD), or "(unknown)" when the source date could not be parsed. |
| `serial` | string | - | Windows, Linux, macOS | `076C11D1` | Certificate serial number as hex text, via the OS's own serial renderer (Windows: little-endian byte reversal; Linux/macOS: `i2a_ASN1_INTEGER` or the openssl `-serial` line). Values: free text (hex). |
| `store` | string | - | Windows, Linux, macOS | `System.keychain` | Which store/keychain/directory the matching row was found in. Values: Windows: MY, ROOT, CA, Trust. macOS: System.keychain, SystemRootCertificates.keychain, login.keychain-db. Linux: the literal path "/etc/ssl/certs".. |
| `key_usage` | string | - | Windows, Linux, macOS | `Digital Signature, Key Encipherment, Data Encipherment` | Comma-separated X.509 Key Usage extension names, or "(none)" when the extension is absent, empty, or could not be read. Values: comma-separated usage names, or "(none)". |

**`security.certificates.list` — `subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `subject` | string | - | Windows, Linux, macOS | `Logitech Inc` | The certificate's Subject distinguished name, rendered by the OS's own name printer (CryptoAPI simple display name on Windows, OpenSSL/libcrypto's default name rendering on Linux and macOS System/root reads, the `security find-certificate` subprocess's `subject=` line on the macOS login keychain). Values: free text (distinguished name). |
| `issuer` | string | - | Windows, Linux, macOS | `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` | The certificate's Issuer distinguished name, rendered the same way as subject. Values: free text (distinguished name). |
| `thumbprint` | string | - | Windows, Linux, macOS | `FBD3B2C0991549EC5FB12FA1A994D2E0C32D8057` | SHA-1 fingerprint of the certificate's DER encoding, uppercase hex with no separators -- the identifier `details`/`delete` match against (the request parameter is case-insensitive, this column is always uppercase). "(unknown)" when the row's identity could not be established (a failed/timed-out per-block parse) and "(skipped)" for a Linux file that could not be read at all. Values: 40 uppercase hex characters, or "(unknown)"/"(skipped)". |
| `not_before` | string | - | Windows, Linux, macOS | `2025-01-09` | Validity-period start date, YYYY-MM-DD (no time-of-day). Values: date (YYYY-MM-DD), or "(unknown)" when the source date could not be parsed. |
| `not_after` | string | - | Windows, Linux, macOS | `2026-01-09` | Validity-period end date, YYYY-MM-DD. Also the field `expiring_within_days` filters on. Values: date (YYYY-MM-DD), or "(unknown)" when the source date could not be parsed. |
| `serial` | string | - | Windows, Linux, macOS | `09CFB6DE3AB5124757FFEFDF3759BBF2` | Certificate serial number as hex text, via the OS's own serial renderer (Windows: little-endian byte reversal; Linux/macOS: `i2a_ASN1_INTEGER` or the openssl `-serial` line). Values: free text (hex). |
| `store` | string | - | Windows, Linux, macOS | `ROOT` | Which store/keychain/directory the row was read from. Values: Windows: MY, ROOT, CA, Trust. macOS: System.keychain, SystemRootCertificates.keychain, login.keychain-db. Linux: the literal path "/etc/ssl/certs" for every row.. |
| `key_usage` | string | - | Windows, Linux, macOS | `Digital Signature` | Comma-separated X.509 Key Usage extension names, or "(none)" when the extension is absent, empty, or could not be read. Values: comma-separated usage names, or "(none)". |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `CONSTRAINED` | `PARTIAL` | `libcrypto:unreadable-file` | Linux: a PEM file under `/etc/ssl/certs` could not be read or parsed (`certificates_plugin.cpp:747,923`) |
| `CONSTRAINED` | `PARTIAL` | `cryptoapi:store-open` | Windows: a CryptoAPI store could not be opened for `list`/`details`/`delete` (`certificates_plugin.cpp:429,487,617`) |
| `CONSTRAINED` | `PARTIAL` | `cryptoapi:store-enum` | Windows: `CertEnumCertificatesInStore` ended abnormally part-way through a store for `list`/`details`/`delete` (`certificates_plugin.cpp:436,493,653`) |
| `CONSTRAINED` | `PARTIAL` | `cryptoapi:store-fallback` | Windows: the LocalMachine store could not be opened and `list`/`details` read the CurrentUser store instead; `list_certs_win` discloses it with a `not_available` row before that store's rows; `details_cert_win` discloses every such store the same way — either as its own row immediately before a match served from it, or, if an earlier fallback store didn't match, as a combined row emitted alongside whichever later store's match ends the scan — and folds every fallback store into the combined scan-incomplete verdict only when no store ever matches |
| `CONSTRAINED` | `PARTIAL` | `posix:cert-dir` | Linux: `/etc/ssl/certs` could not be opened (including a non-directory or symlink at that path) (`certificates_plugin.cpp:767,799,913`) |
| `CONSTRAINED` | `PARTIAL` | `posix:cert-enum` | Linux: a readdir(3)/fdopendir enumeration of `/etc/ssl/certs` failed part-way through (`certificates_plugin.cpp:729,794,896`) |
| `CONSTRAINED` | `PARTIAL` | `posix:delete-recheck` | Linux: `delete`'s pre-unlink identity recheck found the entry changed or could not be re-derived since the earlier match (`certificates_plugin.cpp:883,890`) |
| `CONSTRAINED` | `PARTIAL` | `login-keychain` | macOS: console-user resolution failed, the console user changed or its owner recheck failed immediately before the login-keychain spawn, or the login-keychain read/scan failed, degraded, or was capped (`certificates_plugin.cpp:1573,1636,1640,1697,1945`) |
| `CONSTRAINED` | `PARTIAL` | `secitem:System.keychain` | macOS: System.keychain was not readable (no read permission), timed out, was refused at the bounded-call ceiling, failed to open, or its scan was capped (`certificates_macos_parsers.hpp:516-538`) |
| `CONSTRAINED` | `PARTIAL` | `secitem:SystemRootCertificates.keychain` | macOS: SystemRootCertificates.keychain was not readable (no read permission), timed out, was refused at the bounded-call ceiling, failed to open, or its scan was capped (`certificates_macos_parsers.hpp:516-538`) |

A clean run on any OS — one that hits none of the degradations above — leaves the agent's default `UNDECLARED`/`UNKNOWN` status; the table rows above are the only places the plugin calls `set_result_status` — the sample captures show this (`windows.txt:84,89,93`; `linux.txt:155,160,164`; `macos.txt:170,174`).

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90-day default retention, `server/core/src/response_store.hpp:8,152`), queryable at `/api/responses/{id}` and aggregatable (`list` groups by `store`/`issuer` per its YAML `aggregation` block).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — no reference to the `certificates` plugin or its definition ids exists outside `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`.
- **Sensitivity.** `list`/`details` rows carry every certificate's `subject` and `issuer` — for code-signing certs (the Windows sample) this is effectively an installed-software-publisher inventory (e.g. `Logitech Inc`, `Microsoft Corporation`) by another route, and on macOS a successful login-keychain read can surface the signed-in user's own personal certificates; `thumbprint`/`serial` uniquely identify a specific certificate but not a device or person directly.
- **Siblings:** none in this plugin group; the `diagnostics.certificates` action (a different plugin, TLS cert/key diagnostics) is unrelated despite the similar name.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("security.certificates.list")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 12fa059e66fa

```
== action=list
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
Logitech Inc|DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1|FBD3B2C0991549EC5FB12FA1A994D2E0C32D8057|2025-01-09|2026-01-09|09CFB6DE3AB5124757FFEFDF3759BBF2|ROOT|Digital Signature
Microsoft Identity Verification Root Certificate Authority 2020|Microsoft Identity Verification Root Certificate Authority 2020|F40042E2E5F7E8EF8189FED15519AECE42C3BFA2|2020-04-16|2045-04-16|5498D2D1D45B1995481379C811C08799|ROOT|Digital Signature, Certificate Signing, CRL Signing
Logitech Inc|DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1|D8D11D216CC42B72EA838CAD51F4F4932A1940A0|2026-01-08|2027-01-13|0CADE25B085DD33813FD746151BF6B5E|ROOT|Digital Signature
Baltimore CyberTrust Root|Baltimore CyberTrust Root|D4DE20D05E66FC53FE1A50882C78DB2852CAE474|2000-05-12|2025-05-12|020000B9|ROOT|Certificate Signing, CRL Signing
AAA Certificate Services|AAA Certificate Services|D1EB23A46D17D68FD92564C2F1F1601764D8E349|2004-01-01|2028-12-31|01|ROOT|Certificate Signing, CRL Signing
Microsoft Root Certificate Authority|Microsoft Root Certificate Authority|CDD4EEAE6000AC7F40C3802C171E30148030C072|2001-05-09|2021-05-09|79AD16A14AA0A5AD4C7358F407132E65|ROOT|Digital Signature, Certificate Signing, CRL Signing, Non-Repudiation
Logitech Inc|DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1|C27999A8CEE208F833289CB1A129666E952C7EC2|2022-04-11|2025-04-10|08FABFA8F305A513536B9F231CD3249C|ROOT|Digital Signature
Thawte Timestamping CA|Thawte Timestamping CA|BE36A4562FB2EE05DBB3D32323ADF445084ED656|1997-01-01|2020-12-31|00|ROOT|(none)
Starfield Root Certificate Authority - G2|Starfield Root Certificate Authority - G2|B51C067CEE2B0C3DF855AB2D92F4FE39D4E70F0E|2009-09-01|2037-12-31|00|ROOT|Certificate Signing, CRL Signing
Microsoft Root Authority|Microsoft Root Authority|A43489159A520F0D93D032CCAF37E7FE20A8B419|1997-01-10|2020-12-31|00C1008B3C3C8811D13EF663ECDF40|ROOT|(none)
Symantec Enterprise Mobile Root for Microsoft|Symantec Enterprise Mobile Root for Microsoft|92B46C76E13054E104F230517E6E504D43AB10B5|2012-03-15|2032-03-14|0F6B552F9EBF907B0F6629A9BDF4D8CE|ROOT|Certificate Signing, CRL Signing
… 12 of 81 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=details thumbprint=FBD3B2C0991549EC5FB12FA1A994D2E0C32D8057
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
Logitech Inc|DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1|FBD3B2C0991549EC5FB12FA1A994D2E0C32D8057|2025-01-09|2026-01-09|09CFB6DE3AB5124757FFEFDF3759BBF2|ROOT|Digital Signature
[result_status] UNDECLARED / UNKNOWN

== action=delete
error|thumbprint parameter required
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 12fa059e66fa

```
== action=list
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
CN=com.apple.systemdefault, O=System Identity|CN=com.apple.systemdefault, O=System Identity|0C24DA5DE02640D8924F5C7BCB7D5F734815228D|2026-07-18|2046-07-13|076C11D1|System.keychain|Digital Signature, Key Encipherment, Data Encipherment
CN=com.apple.kerberos.kdc, O=System Identity|CN=com.apple.kerberos.kdc, O=System Identity|3CB6CE678431CB8DD8FDCF6601AA6A4F8CAD329A|2026-07-18|2046-07-13|38F8E0C5|System.keychain|Digital Signature, Key Encipherment
C=US, O=DigiCert, Inc., CN=DigiCert TLS ECC P384 Root G5|C=US, O=DigiCert, Inc., CN=DigiCert TLS ECC P384 Root G5|17F3DE5E9F0F19E98EF61F32266E20C407AE30EE|2021-01-15|2046-01-14|09E09365ACF7D9C8B93E1C0B042A2EF3|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=US, OU=www.xrampsecurity.com, O=XRamp Security Services Inc, CN=XRamp Global Certification Authority|C=US, OU=www.xrampsecurity.com, O=XRamp Security Services Inc, CN=XRamp Global Certification Authority|B80186D1EB9C86A54104CF3054F34C52B7E558C6|2004-11-01|2035-01-01|50946CEC18EAD59C4DD597EF758FA0AD|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=CH, O=WISeKey, OU=OISTE Foundation Endorsed, CN=OISTE WISeKey Global Root GB CA|C=CH, O=WISeKey, OU=OISTE Foundation Endorsed, CN=OISTE WISeKey Global Root GB CA|0FF9407618D3D76A4B98F0A8359E0CFD27ACCCED|2014-12-01|2039-12-01|76B1205274F0858746B3F8231AF6C2C0|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=US, O=Amazon, CN=Amazon Root CA 2|C=US, O=Amazon, CN=Amazon Root CA 2|5A8CEF45D7A69859767A8C8B4496B578CF474B1A|2015-05-26|2040-05-26|066C9FD29635869F0A0FE58678F85B26BB8A37|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=IT, L=Milan, O=Actalis S.p.A./03358520967, CN=Actalis Authentication Root CA|C=IT, L=Milan, O=Actalis S.p.A./03358520967, CN=Actalis Authentication Root CA|F373B387065A28848AF2F34ACE192BDDC78E9CAC|2011-09-22|2030-09-22|570A119742C4E3CC|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=Internet Security Research Group, CN=ISRG Root X1|C=US, O=Internet Security Research Group, CN=ISRG Root X1|CABD2A79A1076A31F21D253635CB039D4329A5E8|2015-06-04|2035-06-04|8210CFB0D240E3594463E0BB63828B00|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=Apple Inc., CN=Apple Platform Code Signing ECC Root CA - G1|C=US, O=Apple Inc., CN=Apple Platform Code Signing ECC Root CA - G1|E8DA8B1EFCFE2EB2FCEB9D41981E1869A71A9C13|2024-12-13|2049-12-08|521223A7BFF487D04BD387D29127D824|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES|CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES|93057A8815C64FCE882FFA9116522878BC536417|2011-05-05|2030-12-31|5EC3B7A6437FA4E0|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=Certainly, CN=Certainly Root R1|C=US, O=Certainly, CN=Certainly Root R1|A050EE0F2871F427B2126D6F509625BACC8642AF|2021-04-01|2046-04-01|8E0FF94B907168653354F4D44439B7E0|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
… 12 of 162 rows shown
[result_status] CONSTRAINED / PARTIAL / login-keychain

== action=details thumbprint=0C24DA5DE02640D8924F5C7BCB7D5F734815228D
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
CN=com.apple.systemdefault, O=System Identity|CN=com.apple.systemdefault, O=System Identity|0C24DA5DE02640D8924F5C7BCB7D5F734815228D|2026-07-18|2046-07-13|076C11D1|System.keychain|Digital Signature, Key Encipherment, Data Encipherment
[result_status] UNDECLARED / UNKNOWN

== action=delete
error|thumbprint parameter required
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 12fa059e66fa

```
== action=list
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
C=US, O=Google Trust Services LLC, CN=GTS Root R4|C=US, O=Google Trust Services LLC, CN=GTS Root R4|77D30367B5E00C15F60C3861DF7CE13B92464D47|2016-06-22|2036-06-22|0203E5C068EF631A9C72905052|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
C=ES, O=IZENPE S.A., CN=Izenpe.com|C=ES, O=IZENPE S.A., CN=Izenpe.com|2F783D255218A74A653971B52CA29C45156FE919|2007-12-13|2037-12-13|B0B75A16485FBFE1CBF58BD719E67D|/etc/ssl/certs|Certificate Sign, CRL Sign
C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 2 G3|C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 2 G3|093C61F38B8BDC7D55DF7538020500E125F5C836|2012-01-12|2042-01-12|445734245B81899B35F2CEB82B3B5BA726F07528|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, OU=emSign PKI, O=eMudhra Inc, CN=emSign Root CA - C1|C=US, OU=emSign PKI, O=eMudhra Inc, CN=emSign Root CA - C1|E72EF1DFFCB20928CF5DD4D56737B151CB864F01|2018-02-18|2043-02-18|AECF00BAC4CF32F843B2|/etc/ssl/certs|Certificate Sign, CRL Sign
C=DE, O=D-Trust GmbH, CN=D-TRUST BR Root CA 1 2020|C=DE, O=D-Trust GmbH, CN=D-TRUST BR Root CA 1 2020|1F5B98F0E3B5F7743CEDE6B0367D32CDF4094167|2020-02-11|2035-02-11|7CC98F2B84D7DFEA0FC9659AD34B4D96|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=The Go Daddy Group, Inc., OU=Go Daddy Class 2 Certification Authority|C=US, O=The Go Daddy Group, Inc., OU=Go Daddy Class 2 Certification Authority|2796BAE63F1801E277261BA0D77770028F20EEE4|2004-06-29|2034-06-29|00|/etc/ssl/certs|(none)
C=FR, O=Dhimyotis, CN=Certigna|C=FR, O=Dhimyotis, CN=Certigna|B12E13634586A46F1AB2606837582DC4ACFD9497|2007-06-29|2027-06-29|FEDCE3010FC948FF|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=Microsoft Corporation, CN=Microsoft ECC Root Certificate Authority 2017|C=US, O=Microsoft Corporation, CN=Microsoft ECC Root Certificate Authority 2017|999A64C37FF47D9FAB95F14769891460EEC4C3C5|2019-12-18|2042-07-18|66F23DAF87DE8BB14AEA0C573101C2EC|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia Global Root CA G3|C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia Global Root CA G3|63CFB6C1272B56E4888E1C239AB62E814724C3C7|2021-05-20|2046-05-19|64F60E6577616AAB3BB4EA8584BBB189B871930F|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=Amazon, CN=Amazon Root CA 2|C=US, O=Amazon, CN=Amazon Root CA 2|5A8CEF45D7A69859767A8C8B4496B578CF474B1A|2015-05-26|2040-05-26|066C9FD29635869F0A0FE58678F85B26BB8A37|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root R46|C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root R46|53A2B04BCA6BD645E6398A8EC40DD2BF77C3A290|2019-03-20|2046-03-20|11D2BBB9D723189E405F0A9D2DD0DF2567D1|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
… 12 of 152 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=details thumbprint=77D30367B5E00C15F60C3861DF7CE13B92464D47
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
C=US, O=Google Trust Services LLC, CN=GTS Root R4|C=US, O=Google Trust Services LLC, CN=GTS Root R4|77D30367B5E00C15F60C3861DF7CE13B92464D47|2016-06-22|2036-06-22|0203E5C068EF631A9C72905052|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
[result_status] UNDECLARED / UNKNOWN

== action=delete
error|thumbprint parameter required
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Windows store-open failures are no longer silent, `delete` on Windows never substitutes the CurrentUser store for an unopenable LocalMachine store (#4377), the Linux delete recheck still has a narrow residual window, and a macOS System/root keychain's empty answer is only trusted when the keychain is confirmed readable.** A CryptoAPI store that neither `CertOpenStore` attempt can open now reports `not_available|<store> store could not be opened` (`list`/`details`) or `error|<store> store could not be opened; nothing removed` with a non-zero exit (`delete`), and marks the result CONSTRAINED/PARTIAL via `cryptoapi:store-open` — the Windows leg does call `set_result_status` for this case (`certificates_plugin.cpp:422-430,487,613-619`); `delete` opens the named store under LocalMachine only and has no CurrentUser retry path at all (`certificates_plugin.cpp:602-611`), unlike `list`/`details`, which disclose a CurrentUser fallback rather than presenting it as a clean LocalMachine read. On Linux, the held-dirfd scan/delete core now lives in `certificates_linux_store.hpp`, with syscall-level tests in `tests/unit/test_certificates_linux_store.cpp` covering symlink retarget, inode swap, a failed recheck, and mid-enumeration failure; `delete` re-derives the matched entry's identity — its own device/inode and, for a symlink, the target's link text plus the target's device/inode — immediately before `unlinkat`, but POSIX has no unlink-by-fd, so a residual `fstatat`-then-`unlinkat` window remains (`certificates_linux_store.hpp:342-358,389-431`); because identity binds inode and target text/inode rather than content, an in-place rewrite of the SAME inode between match and unlink is not detected. A FIFO, device, socket or directory encountered during the scan is skipped silently via a nonblocking, post-open `S_ISREG` check rather than blocking the scan (`certificates_linux_store.hpp:232-252`), and deleting a symlinked entry always removes the link itself via `unlinkat`, never the file it points to. On macOS, a System/root keychain whose `SecItemCopyMatching` answer comes back empty is classified `zero certificates` only when the keychain's own read-permission status bit is set (`keychain_read.cpp:116`); otherwise it is reported as `not_available|<keychain> not readable (no read permission)` (`certificates_plugin.cpp:1586-1610`) and the result is CONSTRAINED/PARTIAL — an unreadable keychain is never a silent empty inventory (#2318).
2. **The login keychain read is a registered exception, not a rung-1 promotion.** System.keychain/SystemRootCertificates.keychain are read in-process via `SecItemCopyMatching`, bounded to 15 seconds per keychain via agent-core's `read_keychain_bounded` and abandoned (not cancelled) on timeout (`certificates_plugin.cpp:1031,1170-1185`); the login keychain stays on the `launchctl asuser` + `sudo -u` + `security find-certificate` subprocess (rung 2, #3406) because the LaunchDaemon has no login keychain of its own (`certificates_plugin.cpp:16-23`) — do not "fix" this to a direct API call. Immediately before that subprocess spawn the plugin re-reads `/dev/console`'s owner in-process and refuses to spawn on a mismatch, shrinking (not eliminating) the fast-user-switch race window from tens of seconds to microseconds (`certificates_plugin.cpp:1497-1533`).
3. **SystemRootCertificates.keychain delete is permanently rejected.** It is sealed under System Integrity Protection; `delete_cert_macos` rejects `store=root` outright before ever shelling out (`certificates_plugin.cpp:2089-2099`) — a hard OS limitation, not a bug to fix.
4. **A macOS delete self-verifies before reporting success.** `delete_cert_macos` re-enumerates the target keychain after `security delete-certificate` exits 0 and only reports `status|deleted` on a positively-proven absence; a keychain that can't be re-read or still shows the certificate reports `error|...`, never a false `status|deleted` (`certificates_plugin.cpp:2191-2229`).
5. **The macOS sample was captured unprivileged and shows the login-keychain leg degrading live, and test-only environment overrides exist on the macOS path that must never be set in production.** At euid 501 with no console session reachable via `launchctl asuser` without root, `list`'s login-keychain read failed and the result carries `CONSTRAINED`/`PARTIAL`/`login-keychain` (`macos.txt:164-165`) — expected under the capture harness, but it means this sample never exercises a successful login-keychain read. Separately, `YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE` / `YUZU_CERTIFICATES_ROOT_KEYCHAIN_PATH_OVERRIDE` (absolute paths; `agents/shared/macos_console_user.hpp`, `system_keychain_path`/`root_keychain_path`) redirect the System/root keychain reads of `list`/`details` to a fixture keychain — `delete` never consults them: `resolve_delete_keychain_path` returns the fixed literal paths regardless, so a destructive action can never be pointed at a substituted keychain. `YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE` replaces the `stat -f%Su /dev/console` console-user lookup with a fixed username (still validated and resolved through the bounded passwd lookup); `YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE` replaces the in-process `/dev/console` owner recheck's uid (an unparsable value is a failed recheck); `YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE` makes the login-keychain read report a failed read carrying that value instead of spawning `security`. They exist so `tests/unit/test_certificates_macos_actions.cpp` can drive the real plugin's SecItem-failure sentinels and the console-owner recheck end to end (#4374); each is read on every call, never cached, and is ignored when unset.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/certificates/src/certificates_linux_store.hpp` · `agents/plugins/certificates/src/certificates_macos_parsers.hpp` · `agents/plugins/certificates/src/certificates_plugin.cpp` · `agents/plugins/certificates/src/certificates_x509.hpp`
- Definitions: `content/definitions/certificates.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`
- Tests: `tests/unit/test_certificates_linux_store.cpp` · `tests/unit/test_certificates_macos.cpp` · `tests/unit/test_certificates_macos_actions.cpp` · `tests/unit/test_certificates_store_honesty.cpp` · `tests/unit/test_certificates_x509.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
