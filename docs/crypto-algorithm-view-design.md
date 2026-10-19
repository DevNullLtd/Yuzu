# Cryptographic algorithm view and the `crypto_config` collector

**Status:** design, not built. Nothing in this document exists in code. It designs two things:

- the **algorithm view**: one fleet-wide list of the cryptographic algorithms Yuzu has evidence of,
  computed at read time from the evidence sources Domain 41 collects;
- the **`crypto_config` collector**: the smallest collector that gives the view a second evidence
  source, the configured algorithm lists on each machine (capability 41.5).

It is a design, not an ADR. It sits beside `docs/crypto-asset-design.md` (the Domain 41 design and
phasing) and the slice-2 certificate design, PR #6159. A pointer from `crypto-asset-design.md` to
this file, and the other edits that file owes (see [Deferred edits](#deferred-edits-to-crypto-asset-designmd)),
are made once the two open PRs that edit it (#6125 and #6159) have merged.

It states outcomes. Mechanisms are left to the implementation PRs, each of which gets its own
governance.

**How to read the labels.**
- **Decided** marks a rule already made elsewhere: ADR-0070, the slice-2 design, an owner direction,
  or the architect's placement ruling of 2026-10-19, which the owner approved. Each Decided line
  names its source. This doc restates the rule so the design can be checked against it.
- **Proposed** marks this design's own choice. A reviewer can change it without touching any ADR.
  Decided and Proposed content are kept on separate lines.
- **Unverified** marks a platform fact taken from vendor documentation and not yet measured on a
  host. The implementing PR measures it before merge. Nothing on Windows has been measured yet.

**How to read the citations.**
- A bare `path:line` is a code fact, checked against `origin/dev` at `41a0678c4` on 2026-10-19 (after #6143, the library-component CBOM, merged).
- `0070:N` is a line in `docs/adr/0070-cryptographic-asset-inventory-placement.md` on the
  `docs/adr-0070-crypto-asset-placement` branch at `ad0482517` ("ADR-0070 (PR #6125)", under
  review, not on `dev`). If #6125 changes before merge, the clause names govern, not the numbers.
- `s2:N` is a line in `docs/crypto-slice2-certificate-design.md` on the
  `docs/crypto-slice2-certificate-design` branch at `5b53971af` (PR #6159, not on `dev`).
- **P1-P21** under [Placement](#placement) are the architect's placement ruling, restated in full.
  The ruling is not a repository document. Its restatement here is the citable form, approved by the
  owner, and a reviewer checks the design against P1-P21.

## Contents

1. [What it is for](#what-it-is-for)
2. [Placement](#placement)
3. [Row model](#row-model)
4. [The `crypto_config` collector](#the-crypto_config-collector)
5. [Read surface](#read-surface)
6. [Capacity](#capacity)
7. [Metrics and alerts](#metrics-and-alerts)
8. [CBOM algorithm components](#cbom-algorithm-components)
9. [D10 lint extension](#d10-lint-extension)
10. [Proposed ADR-0070 amendment](#proposed-adr-0070-amendment)
11. [Assurance impact](#assurance-impact)
12. [Phasing](#phasing)
13. [Coordination with the slice-2 design](#coordination-with-the-slice-2-design)
14. [Deferred edits to `crypto-asset-design.md`](#deferred-edits-to-crypto-asset-designmd)
15. [Tests and chaos](#tests-and-chaos)
16. [Open owner decisions](#open-owner-decisions)
17. [How this could ship wrong](#how-this-could-ship-wrong)

## What it is for

**Decided (owner direction, 2026-10-19):**
- **A separate algorithm list.** The view is its own surface, not a column on the certificate or
  library reads.
- **Evidence kinds are never merged.** A certificate's key algorithm and a configured cipher list
  are different statements. Each keeps its own counts, coverage and confinement.
- **No inference from installed libraries.** "OpenSSL 3 is installed, so these algorithms are
  available" is not evidence. Slice 1's library rows (`crypto_library_model.hpp:10-14`) never
  produce an algorithm row.
- **`crypto_config` is pulled forward** from "Later in Phase 1" (`docs/crypto-asset-design.md:143-156`)
  so that the view has more than one source.

**Two consumers.**
- **Post-quantum migration planning.** A planner needs the raw inventory first:
  - which public-key and signature algorithms are in use, at which parameter sets and on how many
    devices;
  - what each machine is configured to offer or refuse.

  That inventory is fact. Which of its rows is "quantum-vulnerable" is a judgement tied to a threat
  model and a standard.
- **CBOM algorithm components.** A CycloneDX 1.7 CBOM lists algorithms as `cryptographic-asset`
  components that certificates and protocols reference. The view is where those components come
  from, so the certificate summary, the CBOM and the view name an algorithm the same way.

**Facts only.**
- The view never says "quantum-vulnerable", "deprecated", "weak", "legacy", "recommended" or
  "approved".
- It never orders or colours rows by any of those labels.
- Those labels belong to a use-case engine (UCE), behind the ADR-0032 interlock (ADR-0070 D9,
  `0070:771-812`).
- D13's four weak-key rules (`0070:1048-1197`) are certificate counts on the slice-2 counts read.
  They are not attributes of the view's rows, and the view does not repeat them.

**What the view answers:** "Which algorithms, in which vocabulary and at which parameter set, does
Yuzu have evidence of, on how many devices, from which kind of evidence, and how complete is that
evidence?" Nothing more.

## Placement

**Decided (architect ruling, owner-approved, 2026-10-19).** Every clause binds this design. The
"Basis" column gives each clause's grounding in the repository.

| # | Clause | Basis |
|---|---|---|
| P1 | The view is **core**: pure aggregation of fleet-internal facts. | ADR-1005 Decision 2 (`docs/adr/1005-headless-platform-use-case-engines.md:47`); `0070:232-236` |
| P2 | The identifier name table is core **identity resolution**, the D2 class. Matching is **exact**, which is stricter than D2's prefix matching. | D2, `0070:289-345` |
| P3 | D2 condition 1 (identity only) is at risk. No `primitive`, security level, `bits_of_security` or CycloneDX `certificationLevel` field may enter the table. | D2 condition 1, `0070:313-316` |
| P4 | An unknown identifier still appears, with its raw value and a null name. It is never dropped. | the architect ruling; stated as part of the proposed condition-2 paragraph ([amendment](#proposed-adr-0070-amendment)) |
| P5 | Cipher-suite decomposition is core only within limits. TLS 1.3 suite names do not name the key exchange or the authentication, and filling them in from defaults is inference. The IANA "Recommended" column is a verdict and is never imported. | D2 condition 2, `0070:317-324` |
| P6 | ADR-0070 does not fully cover the view. D7 covers algorithm components, D10 covers field names, and the 41.5 row covers configured lists as facts. D2 condition 2 is written for libraries only, so it needs the [amendment](#proposed-adr-0070-amendment). | `0070:670-699`, `:814-835`, `:258`, `:846` |
| P7 | **No new securable for the view.** Each evidence kind is gated by its source's securable. Certificate rows gate on `CertificateInventory:Read` and its floor. | D12, `0070:874-875` |
| P8 | A caller holding only some kinds' permissions gets a partial result with disclosure (`kinds_omitted`, with a reason), not a refusal. | D7, `0070:689-691`; `halves_omitted`, `s2:1026-1027` |
| P9 | A row whose only evidence is an omitted kind is removed entirely. Showing zero counts would leak that the algorithm exists. | the architect ruling |
| P10 | Each kind is confined separately. There is **no cross-kind total**, because it would join differently confined sets. | the architect ruling |
| P11 | `strength`, `security_level` and `bits_of_security` are forbidden field names, and the D10 token list is extended (see [D10 lint extension](#d10-lint-extension)). The view is not a D13 count read, so the D13 allow-list does not apply. | `0070:195-206`, `:828-831`, `:1185-1191` |
| P12 | An algorithm is never a metric label. | `docs/observability-conventions.md:10` |
| P13 | No interlock applies while the view stays core and touches no engine-path marker. Cell (g) applies if anyone materialises the view across runs, so the view is computed at read time. | `0070:784`, `:793-794` |
| P14 | **Configured polarity.** Enabled, disabled, preference order and constraint are different things. A disabled algorithm **never** counts as present. | the architect ruling |
| P15 | No policy level or OS default is ever expanded into an algorithm list. | the architect ruling |
| P16 | **The parameter-set key** includes the RSA modulus size, the EC curve, and the PSS hash and MGF. Explicit curves have no OID. A missing size stays null and is never inferred. | the architect ruling |
| P17 | **No alias collapse.** `ssh-rsa` (a key type) is not `rsa-sha2-256` (a signature algorithm). OpenSSL, SCHANNEL and IANA names each match exactly within their own vocabulary. | the architect ruling |
| P18 | **One name table** (condition 4). The certificate summary, the CBOM and the view share it. The D13 OID sets never become table attributes. | D2 condition 4; `s2:921-926` |
| P19 | **Display names are not an enum.** Filters take raw identifiers, so a table change never breaks the contract. Ordering is by count or identifier only. | D10, `0070:819-820` |
| P20 | Every response carries: `as_of`; the identifier table's version, which is also in the cursor fingerprint; per-kind coverage; per-kind truncation. | D2 condition 2, `0070:323-324` |
| P21 | `observed` evidence waits for the TLS-probing threat model. | `docs/crypto-asset-design.md:242-252` |

## Row model

### Identifier vocabularies

**Proposed.** Every algorithm row is identified in exactly one **vocabulary**, and matched exactly
within it. Two identifiers from different vocabularies are two rows, even where a reader would call
them the same algorithm (P17).

Each vocabulary has its own **comparison rule**:
- The row key holds the identifier in the vocabulary's comparison form.
- The per-device drill keeps every `raw` spelling seen.
- A case rule marked Unverified is measured in the PR that first collects that vocabulary.

| `vocabulary` | Identifier form | Comparison rule | Example | Collected from |
|---|---|---|---|---|
| `oid` | dotted decimal, shape-checked as `s2:851` | byte-exact | `1.2.840.113549.1.1.11` | certificate `key_alg_oid`, `sig_alg_oid`, `ec_curve_oid`, `pss_hash_oid`, `pss_mgf1_hash_oid` (`s2:264-269`) |
| `iana_tls_cipher_suite` | two-byte codepoint, `0xHH,0xHH` | byte-exact | `0x13,0x02` | none yet (reserved for `observed`, P21) |
| `iana_tls_group` | decimal Supported Groups codepoint | numeric | `29` | none yet |
| `iana_tls_signature_scheme` | `0xHHHH` | numeric | `0x0804` | none yet |
| `ssh` | algorithm name | case-sensitive (SSH names are case-sensitive) | `rsa-sha2-256` | slice-3 host keys |
| `schannel` | the name Windows stores | ASCII case-insensitive. Registry key names are case-insensitive. Suite names in the policy list are Unverified. | `RC4 128/128`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384` | `crypto_config` Windows reads |
| `openssl` | a name OpenSSL's configuration accepts | as OpenSSL compares that directive's names (Unverified; case-sensitive until measured) | `TLS_AES_256_GCM_SHA384`, `X25519` | `crypto_config` `openssl.cnf` and crypto-policies reads |
| `jca` | a Java standard algorithm name | ASCII case-insensitive (JDK constraint matching is documented as case-insensitive; Unverified per property) | `RC4`, `MD5withRSA` | `crypto_config` `java.security` reads |

- **No cross-vocabulary link in v1.** These remain separate rows:
  - an OpenSSL TLS 1.3 suite name that matches the IANA Description byte for byte;
  - a SCHANNEL suite name that differs from the IANA one only by a curve suffix.

  A link would be Yuzu asserting equivalence. The SCHANNEL `_P384` suffix carries a curve
  restriction that the IANA suite does not.
- **The IANA codepoint vocabularies have no collected source.** They are defined now so that three
  things share one form:
  - the name table's IANA snapshot;
  - the CBOM `cipherSuites[].identifiers` field;
  - a future `observed` source.

  Whether a compiled IANA snapshot is identity data at all is [open decision 1](#open-owner-decisions).
- **Protocol versions are not algorithms.** `TLSv1`, `SSLv3`, `DTLSv1.0` and similar tokens never
  become view rows, from any source. A compiled, closed list of protocol-version tokens
  routes them to `setting` rows on the per-device config read ([Rows](#what-it-reads)).

### Role

**Proposed.** Every row carries `role`: where the identifier was found. The role is taken from the
source, never from the table.

| Kind | Roles |
|---|---|
| `certificate` | `public_key` (from `key_alg_oid`), `signature` (from `sig_alg_oid`) |
| `configured` | `cipher_suite`, `bulk_cipher`, `hash`, `key_exchange`, `group`, `signature_scheme`, `algorithm_constraint` |
| `ssh_host_key` | `host_key` (slice 3) |

`role` is part of the row key. Some OIDs name both a key algorithm and a signature algorithm:
RSASSA-PSS (`1.2.840.113549.1.1.10`) and Ed25519 (`1.3.101.112`) are both. Counting
"certificates with Ed25519 keys" together with "certificates signed with Ed25519" would conflate
two facts.

### Parameter-set key

**Decided (P16).**

**Proposed** field names, reusing slice 2's (`s2:264-269`):

| Role | Key fields | Notes |
|---|---|---|
| `public_key`, RSA | `rsa_modulus_bits` | Null when the agent could not determine it. Never inferred. |
| `public_key`, EC on a named curve | `ec_params` = `named`, `ec_curve_oid` | The curve OID is resolved by the same table. |
| `public_key`, EC with explicit parameters | `ec_params` = `explicit`, `ec_order_bits` | Explicit curves have no OID, so the order length is the only key. Needs coordination item C1. |
| `public_key`, EC whose parameters could not be read | `ec_params` = `unknown` | Never merged with either case above. |
| `signature`, RSASSA-PSS | `pss_hash_oid`, `pss_mgf1_hash_oid` | The PSS OID alone names no hash. |
| `signature`, other | none | The signer's key size is not in the certificate and is never guessed. |
| `configured` rows | none | A configured name is a name. Parameters it implies are not decomposed. |

Rules:
- Two rows that differ in any key field are two rows.
- A row with a null key field is its own row and is never merged into a sized one: "RSA, size
  unknown" is not "RSA 2048".
- In ordering and paging, a null key field sorts before any value.

### The name table

**Decided (P2-P4, P18).**

**Proposed:** one compiled-in table, `crypto_identifier_table`, kept beside
`crypto_library_model.hpp` and separate from the library-family table. The two tables answer
different questions, so this is not a second copy of one answer.

- **Entry:** (`vocabulary`, `identifier`) → `name`. For IANA cipher suites only, an entry also
  carries the registry Description and the literal `kx_auth_segment`
  ([decomposition](#cipher-suite-decomposition)). An entry carries nothing else: no `primitive`, no
  family, no security level, no "recommended", no certification and no colour (P3).
- **Names** are the defining specification's own name for the identifier:
  - for an OID, its ASN.1 value name (`sha256WithRSAEncryption`, `secp256r1`);
  - for an IANA codepoint, the registry's Description.

  A name is never taken from another vocabulary: OpenSSL's `prime256v1` is not the name of
  `1.2.840.10045.3.1.7`.
- **Unknown identifiers** appear with their raw identifier and `"name": null` (P4). There is no
  separate "known" flag. Null is the signal, and no field may suggest that an unknown identifier is
  suspect.
- **Version.** The table carries an integer, `kCryptoIdentifierTableVersion`, bumped by any change
  to an entry. It is serialised as **`identifier_table_version`** on every surface that uses the
  table: the view, the certificate surfaces that show names, and the CBOM
  (`yuzu:crypto:identifier_table_version`). It never appears as a bare `table_version`. That name
  already means slice 1's family table, on the library reads (`crypto_library_model.cpp:587`) and
  in the CBOM (`server/core/src/crypto_cbom.cpp:108`).
  - It is part of every view cursor fingerprint, as slice 1 binds its own table version into its
    drill cursor (`crypto_library_model.cpp:436-445`).
- **Scope of v1.** The OID entries needed for certificate key, signature, curve and hash OIDs.
  - The `schannel`, `openssl` and `jca` vocabularies get **no** names in v1. Their identifiers
    already are readable names, so the table would only copy them.
  - Their rows carry `"name": null` until an entry is added. That is honest, not a defect.
- **Not an enum.** No name appears in an OpenAPI or MCP `enum`. That differs from slice 1, whose
  family ids are in the contract (`0070:336-339`). Here a table edit changes only display text.
- **Never a verdict list.** The D13 OID sets (`s2:921-926`) live in the D13 rule code, never as a
  table column (P18).

### Cipher-suite decomposition

**Decided (P5).**

**Proposed.** Decomposition is limited to what each registry entry's own name states, decided entry
by entry when the table is written, never by parsing a name at run time:
- An IANA suite entry carries its registry Description.
- **`kx_auth_segment`**, the literal text between `TLS_` and `_WITH_`, is recorded only for an
  entry whose registered name has that TLS 1.0-1.2 form. Examples: `ECDHE_RSA`, `RSA`, `DHE_PSK`,
  `RSA_EXPORT`.
- The segment is **never split** into key exchange and authentication. `ECDH_ECDSA` names the CA's
  signature type, not the suite's authentication, and `RSA` alone states neither component. Bulk
  cipher and MAC are not split out either: `CCM` and `CCM_8` are modes, not MACs.
- These entries carry **no segment**:
  - TLS 1.3 suites, including the GOST suites whose names contain `_WITH_`;
  - the RFC 9150 integrity-only suites (`TLS_SHA256_SHA256`);
  - every entry whose name has no `_WITH_`.
- **SCSVs are excluded from decomposition.** `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` and
  `TLS_FALLBACK_SCSV` are signalling values, not suites. They carry their Description only.
- No "Recommended", "DTLS-OK" or other evaluative or administrative registry column is imported.
- `schannel` and `openssl` suite names are **not** decomposed in v1. Their naming conventions are not
  a registry.
- An OpenSSL `CipherString` is never decomposed (see [Polarity](#configured-polarity)).

### Evidence kinds

**Decided (owner direction; P7, P21):** these kinds, their sources, and the reserved status of
`observed`.

**Proposed:** the securable of the `configured` kind (open decision 3). **Undecided:** the
`ssh_host_key` securable (ADR-0070 D8).

| `evidence_kind` | Source | Status | Securable |
|---|---|---|---|
| `certificate` | slice 2a's `CertificateInventoryStore` `cert_fact` rows (`s2:461-485`) | after 2a-2 | `CertificateInventory:Read` (P7) |
| `ssh_host_key` | slice 3 host public keys | pending the slice-3 ADR (`0070:701-769`) | undecided (D8) |
| `configured` | `crypto_config` (this design) | after the collector ships | proposed `Security:Read` ([open decision 3](#open-owner-decisions)) |
| `observed` | none | **reserved**; needs the TLS-probing threat model | — |

- `observed` is a reserved name only. It is in no schema `enum` and no response until a source
  exists.
- **What each kind counts:**
  - **`certificate`** (from slice 2's count object, `s2:983-988`):
    - distinct (device, certificate `sha256`) and distinct devices;
    - the `ca_certificates` / `end_entity_certificates` split on raw `is_ca`;
    - `from_kept_rows`.
  - **`configured`:** distinct devices per source class and polarity.
  - **`ssh_host_key`:** set by the slice-3 ADR.

### Configured polarity

**Decided (P14, P15).**

**Proposed:** every `configured` row carries `polarity`, one of:

| `polarity` | What the configuration states | Example |
|---|---|---|
| `enabled` | the identifier is explicitly enabled | SCHANNEL `Ciphers\AES 128/128` `Enabled` = non-zero |
| `ordered` | the identifier is in a configured preference list, at `position` | the Group Policy cipher-suite order; OpenSSL `Ciphersuites` |
| `disabled` | the identifier is explicitly disabled | SCHANNEL `Ciphers\RC4 128/128` `Enabled` = 0 |
| `constraint` | the identifier, as a single bare token, is in a restriction list | `RC4` in Java `jdk.tls.disabledAlgorithms` |
| `deprioritised` | the identifier is listed in Java `jdk.tls.legacyAlgorithms` | `RC4_128` |

- Polarity is part of the configured evidence key. Counts of different polarities are never summed,
  and no response carries a total across them.
- **One polarity per key.** Within one source class, an identifier has exactly one polarity per key.
  A device carries two polarities for one identifier only through separate keys (for example two
  JVM homes, or two Java properties), and each is counted under its own polarity.
- **A `disabled`, `constraint` or `deprioritised` identifier is never "present".** It never adds to
  an `enabled` or `ordered` count. The dashboard lists `disabled` and `constraint` rows in a
  separate section, "Configured entries naming a restriction".
- **`deprioritised` is its own polarity.** It is not a restriction and is never counted as
  disabled. Its documented meaning, "negotiated only when no non-legacy choice remains", is
  Unverified. CC-1 measures the Java semantics on the JDKs it supports before shipping this
  polarity, and drops it to a raw `setting` if the measurement disagrees.
- **Java constraint expressions stay on the per-device config read.** An entry that is not a single
  bare algorithm token is a `setting` row on `/config`, with its raw text, and never a view row.
  Examples: `EC keySize < 224`, `SHA1 jdkCA & usage TLSServer`, `include jdk.disabled.namedCurves`.
  The row key never takes raw text. The expression is never parsed into a size rule.
- **Java's `jdk.disabled.namedCurves` is read as a property in its own right.** It is the property
  that `include jdk.disabled.namedCurves` names, inside another property's value: not a file. Its
  bare tokens are `constraint` rows (role `group`), attributed to that key, and the `include` entry
  that references it stays a raw `setting`. Reading it is reading the file's own text, not
  expanding a default.
- **An expression that is not a list becomes a setting, not rows.** These stay raw `setting` rows
  and are never split into algorithm rows:
  - an OpenSSL `CipherString`, such as `DEFAULT@SECLEVEL=2` or `HIGH:!aNULL:!MD5`;
  - an OpenSSL `Groups`, `Curves`, `SignatureAlgorithms` or `Ciphersuites` value that contains any
    keyword or operator: `DEFAULT`, a leading `-`, `?` or `*`, or `/`.

  Each such token's meaning is OpenSSL's own expansion, not a statement the configuration makes
  (P15).
- **Absent is not a polarity.** An unset key means a default applies, and Yuzu does not state what
  the default is (P15). An unset key produces either a `setting` row with state `absent`, or no row
  at all for an enumerated subkey that does not exist. It never produces an algorithm row. Its
  devices are counted as `defaults_apply_devices` ([coverage](#response-shape)).
- **A value of the wrong type is unknown.** For example, a SCHANNEL `Enabled` stored as `REG_SZ`
  produces a `setting` with state `unknown`, reason `wrong_type`, and no algorithm row. Polarity is
  never guessed from it.
- **An explicit setting that produced no row is not a default.** A device whose key was set but
  yielded no algorithm row is counted as `unparsed_setting_devices`, never as
  `defaults_apply_devices`. That covers:
  - a `wrong_type` value;
  - a value that hit its cap;
  - a raw or operator-bearing expression;
  - a key recorded `covered_by` another source.

### Row identity, in one line

A view row is (`vocabulary`, identifier in comparison form, `role`, parameter-set key). Its
`evidence` holds one block per admitted kind that has evidence for it. A `configured` block is split
by source class, then by polarity. No field sums across blocks, across source classes or across
polarities.

## The `crypto_config` collector

This section fixes what the view needs and the contract the collector must honour, and no more.
When the collector is built it may move to its own design doc, which would supersede this section.

**Decided (ADR-0070 41.5 row, `0070:258`):** "The configured list is a fact. 'Weak cipher enabled'
is a verdict."

**Decided (`docs/crypto-asset-design.md:155-156`):** configured is not effective. A registry value
or a config file is what is configured. The effective policy also depends on:
- defaults;
- group policy;
- per-application settings.

Every surface that shows a `configured` row says so.

### Shape

**Proposed.**
- **A new plugin, `crypto_config`, with one read-only action, `list`.**
  - Catalogue row: `DispatchClass::ReadOnly`, `Mutability::None`, `ExecuteGate::None`, and the
    securable from [open decision 3](#open-owner-decisions).
- **Live dispatch** is allowed only while the securable's read is no stricter than what the
  ResponseStore exposes, which is `Response:Read`.
  - **Under the recommended `Security:Read`:** a live `crypto_config.list` result lands in the
    ResponseStore. There it is readable under `Response:Read`, which is held more widely than
    `Security:Read` under RBAC on, and by every signed-in user under RBAC off.
    - Dispatching still needs `Security:Read` plus `Execution:Execute`.
    - Every posture plugin on `Security` accepts the same exposure. One example is
      `local_security_policy` (`server/core/src/capability_decls/plugin_action_catalogue_local_security_policy.hpp:35`).
  - **If the owner chooses a floored securable,** collection is **sync-only**. That action gets no
    catalogue row, so every dispatch path refuses it, as slice 2's OD-1 does (`s2:134-160`).
- **A daily-sync source, `crypto_config`,** calls `list` through `LocalDispatcher`, as the
  installed-software source does (`agents/core/src/sync_source_installed_software.cpp:501`, `:519`).
  It uses a new `plugin_data` key and needs no proto change (ADR-0016).
- **Never a write.**
  - No action sets a registry value, edits a file or runs a policy tool (`update-crypto-policies`,
    `Enable-TlsCipherSuite`).
  - A test asserts the plugin reaches no write call.
- **No subprocess.** Every source below is a registry value or a file. None needs `openssl`,
  `java`, `reg` or PowerShell.
- **OpenSSL's own configuration loaders are never called.**
  - The collector parses the file text itself. It never calls `NCONF_load`, `CONF_modules_load`,
    `OPENSSL_config` or `CONF_modules_load_file`, which would execute module initialisation and
    follow includes.
  - A `$ENV::name` or `$var` reference is never expanded. A value containing one is a raw
    `setting`.
- **Failure tokens** are collected by `ConstraintAccumulator` (`agents/shared/constraint_accumulator.hpp:43`).
- **The plugin ABI boundary.** The whole `execute()` body is one `try/catch(...)` across the plugin
  ABI, as `docs/crypto-asset-design.md:147-149` requires.
- **Kill switch.** This is an explicit decision, [open decision 5](#open-owner-decisions).
  - **Recommendation: default-on.** No `seed_kill_switch_default_off` entry, matching the read-only
    posture plugins on `ExecuteGate::None`.
  - The rows are machine configuration, not per-user data.
  - The server-side plugin-config kill switch still lets an operator turn the plugin off.

### What it reads

**Proposed. Every path, value name and value type below is Unverified until measured on a host.**

#### Parts, sources and rows

- **A source** is one class of configuration on one device (for example `schannel`), identified by
  `source_id`.
- **A part** is one file or one registry key that a source reads. It is identified by `part_id`:
  its machine path, or its key path under `HKLM`.
- **Replacement** is decided per part (see [Replace semantics](#source-status-and-replace-semantics)).
- The action emits four record types:

| Record | Fields |
|---|---|
| `source` | `source|<source_id>|<status>|<reason>` |
| `part` | `part|<source_id>|<part_id>|<status>|<reason>` |
| `setting` | `setting|<source_id>|<part_id>|<key>|<state>|<reason>|<value>` |
| `alg` | `alg|<source_id>|<part_id>|<key>|<vocabulary>|<identifier>|<role>|<polarity>|<position>|<raw>` |

- A **`setting`** is a configuration fact that is not an algorithm identifier. Examples: a
  protocol-version switch, a FIPS flag, a minimum key length, a policy name, a raw expression, an
  include directive, or a value of the wrong type.
  - Its `state` is one of `value`, `absent` (the parent was read and the value is not set),
    `unreadable`, or `unknown`.
  - `unknown` carries a reason: `wrong_type`, `value_cap`, `expression`, `env_reference`,
    `include_not_followed` or `covered_by:<source_id>`. (`no_system_configuration` is a source
    reason only, never a setting reason.)
- **A key** is one named setting inside a part: a registry value, an enumerated subkey such as
  `Ciphers\RC4 128/128`, or a property or directive such as `jdk.tls.disabledAlgorithms`. Every
  `setting` and `alg` record names its key. Replacement, freshness and the view's device sets are
  all computed at key grain.
- An **`alg`** row is one configured algorithm entry. Only `alg` rows feed the view.
- Protocol versions are `setting` rows. They are shown on the per-device config read, never in the
  view.

#### Per-OS sources

**Windows.** Registry views are selected with `KEY_WOW64_64KEY` and `KEY_WOW64_32KEY`, never by
writing a literal `WOW6432Node` path.

| Source (`source_id`) | Reads | Emits |
|---|---|---|
| `schannel` | Under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\`: `Protocols\<name>\{Client,Server}` (`Enabled`, `DisabledByDefault`), and by **subkey enumeration** (capped), `Ciphers\<name>`, `Hashes\<name>` and `KeyExchangeAlgorithms\<name>` (`Enabled`, plus `ClientMinKeyBitLength` / `ServerMinKeyBitLength` for key exchange). | Protocols as `setting`. Ciphers, hashes and key exchanges as `alg` (`schannel`, polarity from a `REG_DWORD` `Enabled`). Minimum lengths as `setting`. |
| `cng_ssl_order_policy` | The Group Policy key `HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`: `Functions` (a comma-separated `REG_SZ`) and `EccCurves` (`REG_MULTI_SZ`). | `alg` rows (`schannel`, `ordered`, with `position`), roles `cipher_suite` and `group`. |
| `dotnet` | `HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319` and `v2.0.50727`, in both registry views: `SchUseStrongCrypto`, `SystemDefaultTlsVersions`. | `setting` rows, one per view and version. |
| `winhttp` | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp` `DefaultSecureProtocols`, in both views. | `setting`. |
| `fips_lsa` | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy` `Enabled`. | `setting`. |
| `java_security` | — | `unsupported`, reason `jvm_discovery_unavailable`. The `runtimes` plugin's Windows `jvm` leg is planned, not built (`agents/plugins/runtimes/README.md:9`, `:36`). |

**Not read on Windows: the CNG local-configuration key** `HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002`.
- Its `Functions` and `EccCurves` values appear to hold the OS default lists (Unverified; the
  Windows test box was not reachable for review).
- Reading them as `configured` would show every untouched host's default list as configured, which
  breaks P15.
- The key is listed in `not_read` with that reason.
- **The distinguishing rule.** A key whose stock value cannot be told apart from an administrator's
  write, and that carries no provenance marker, is not read as configured. The Group Policy key
  passes: it does not exist until a policy writes it, so its presence is the provenance marker. The
  CNG local key fails: Windows populates it on a stock install (Unverified), and nothing in it says
  whether a person changed it.
- **Vendor defaults that are still read (disclosed).** Two Linux sources do report vendor-shipped
  content as configured files:
  - a stock `java.security` holds the JDK vendor's default restriction lists;
  - the crypto-policies back-end on a host left at `DEFAULT` holds the distribution's default
    lists.

  Both are read because they are files on the host that the runtime actually loads, and an
  administrator edits the same file. Neither carries a provenance marker either, so the view says
  "configured file as found", never "set by an administrator". `state/current` names the policy
  level the back-end was generated from (for example `DEFAULT`), and the `/config` read shows it next
  to the back-end's rows so a reader can see the lists come from a named level.
- **Implementation gate (CC-2):** measure the key on a clean host and on a host with an
  administrator-set order. Read it only if the measurement shows the two can be told apart. That
  would be a change to this design.

**Linux**

| Source (`source_id`) | Reads | Emits |
|---|---|---|
| `linux_fips` | `/proc/sys/crypto/fips_enabled`. | `setting` with `0` or `1`. When `/proc/sys` is confirmed to be procfs (statfs magic) and `crypto/` does not exist, the state is `absent` with reason `kernel_no_fips` (the kernel was built without `CONFIG_CRYPTO_FIPS`). An unreadable or non-procfs parent is `unreadable`. |
| `crypto_policies` | `/etc/crypto-policies/config` and `/etc/crypto-policies/state/current` (the policy name as written and as applied); `/etc/crypto-policies/back-ends/opensslcnf.config`. | The names as `setting`, never expanded. The back-end's directives as for `openssl_cnf`. |
| `crypto_policies_java` | `/etc/crypto-policies/back-ends/java.config`, the Java back-end that a JVM applies when its `java.security` sets `security.useSystemPropertiesFile=true`. | Its properties as for `java_security`. Whether a given JVM applies it is a `setting` on that JVM's part. |
| `openssl_cnf` | `/etc/ssl/openssl.cnf` and `/etc/pki/tls/openssl.cnf`: the system-default section that the file itself selects. | `MinProtocol`, `MaxProtocol` and `CipherString` as raw `setting`. `Ciphersuites`, `Groups` / `Curves` and `SignatureAlgorithms` as `alg` rows (`openssl`, `ordered`) only when every token is a plain name; otherwise one raw `setting`. |
| `java_security` | Per JVM home under the `runtimes` plugin's roots (`agents/plugins/runtimes/src/runtimes_linux_parsers.hpp:232`): `<home>/conf/security/java.security` (JDK 9+) and `<home>/jre/lib/security/java.security` (JDK 8). | The bare tokens of `jdk.tls.disabledAlgorithms`, `jdk.certpath.disabledAlgorithms`, `jdk.jar.disabledAlgorithms` and `jdk.disabled.namedCurves` as `alg` (`jca`, `constraint`). `jdk.tls.legacyAlgorithms` tokens as `alg` (`jca`, `deprioritised`). Expressions, protocol tokens and in-property `include` entries as raw `setting`. `security.overridePropertiesFile` and `security.useSystemPropertiesFile` as `setting`. |

**macOS**

| Source (`source_id`) | Reads | Emits |
|---|---|---|
| `java_security` | The same files under the fixed root `/Library/Java/JavaVirtualMachines/*/Contents/Home`. A JVM-home entry in that root that is itself a link resolving outside it (Homebrew installs its JDKs this way) is skipped at JVM-home grain and named in `not_read`, never followed. | As Linux. |
| `apple_tls` | — | `unsupported`, reason `no_system_configuration`. Apple platform TLS has no system-wide algorithm configuration file, App Transport Security is per application, and there is no FIPS switch. |

On macOS, `openssl_cnf` is **not read**. The system LibreSSL does not apply an `ssl_conf` section,
so the file can state no TLS algorithm configuration.

#### Link and include rules

- **The crypto-policies back-end is configuration, not expansion.** `update-crypto-policies` writes
  the expanded lists to disk, so reading that file reads what is configured. Yuzu never expands a
  policy name itself (`DEFAULT`, `LEGACY`, `FUTURE`, or a sub-policy such as `DEFAULT:NO-SHA1`)
  (P15).
- **Links are resolved lexically, inside allowlisted target roots.** The slice-2 rules apply
  (`s2:212-232`): never open a link, resolve it hop by hop, then open the target `O_NOFOLLOW` as a
  regular file. A part whose own file is a link that resolves elsewhere is `unreadable`, reason
  `link_outside_roots`: nothing of it was read. A JVM home that is such a link is skipped at
  JVM-home grain and named in `not_read` (`jvm_home_link_outside_roots`), not reported as a part.
  The allowlisted target roots are:
  - for the crypto-policies back-ends: `/usr/share/crypto-policies/`;
  - for distro JDKs, whose `java.security`, or whose whole `conf/` directory, is a link into `/etc`:
    `/etc/java-*/` (Debian, Ubuntu) and `/etc/java/` (Fedora, RHEL).

  Both target-root lists are Unverified, and CC-1 measures each supported distribution's layout
  before merge.
- **An include can be `covered_by` another source, under three conditions.** Two includes qualify:
  - the RHEL `openssl.cnf` `.include` of `/etc/crypto-policies/back-ends/opensslcnf.config`
    (reason `covered_by:crypto_policies`);
  - a `java.security` top-level `include` of `/etc/crypto-policies/back-ends/java.config`, if that is
    how a distribution wires in the Java back-end (reason `covered_by:crypto_policies_java`). Fedora
    and RHEL may use this instead of, or as well as, `security.useSystemPropertiesFile`; CC-1
    measures which mechanism each supported distribution uses.

  The include is recorded as a `setting` with state `unknown` and that reason, and does not make its
  part `constrained`, **only when all three hold**:
  1. the include target, after lexical normalisation, is exactly the covering source's file path;
  2. the include names a file, never a directory (a directory include is never covered);
  3. the covering source's part for that file is `ok` in the **same report**.

  Otherwise the include is treated as any other include, below. So `covered_by` can never hide a
  file that was not read in that report.
- **Any other include is recorded, never followed.** That covers any other OpenSSL `.include` and a
  top-level Java `include <file>` (JDK 23+). The include makes its part `constrained`, reason
  `include_not_followed`. The rest of the part is still read, and its keys still replace (see
  [Replace semantics](#source-status-and-replace-semantics)).
- **Machine-scope roots only (invariant).** Every root above is a fixed machine path. No root is
  under `/home`, `/Users`, `C:\Users` or a user profile. A test asserts the compiled root lists.
  Per-user JVMs (`~/Library/Java/JavaVirtualMachines`) and per-user Java deployment files are
  therefore never read.

#### Not read (named in every response's `not_read`)

The following are not read, and every response names them:
- `sshd_config` and the crypto-policies `opensshserver` back-end ([open decision 4](#open-owner-decisions));
- GnuTLS and NSS back-ends;
- per-application configuration (IIS bindings, nginx, Apache, Tomcat);
- Homebrew OpenSSL configuration;
- JDKs outside the fixed roots, and JVM homes inside a fixed root that are links resolving outside
  it (on macOS, Homebrew JDKs linked into `/Library/Java/JavaVirtualMachines`), each named by its
  link path;
- per-user JVMs;
- the CNG local-configuration key (above);
- Windows `BCryptEnumContextFunctions`, whose output may include defaults (Unverified);
- on macOS, `openssl.cnf`;
- Windows Java.

#### Containers

**Proposed (disclosure).** A containerised agent (`deploy/docker/Dockerfile.agent`) reads the
image's `/etc`, not the host's. Its `openssl_cnf`, `crypto_policies` and `java_security` rows
describe the container image. `/proc/sys/crypto/fips_enabled`, by contrast, is the host kernel's
value.
- The plugin README, the OS capability matrix and the `/config` description state this.
- When the agent detects that it is in a container, every response carries
  `container_image_config: true`. Detection is the implementing PR's choice.

#### Privilege

**Proposed claim, Unverified:**
- **Linux:** collection needs no elevation. The files above are world-readable on stock systems,
  and the agent runs as the unprivileged `yuzu` account (`docs/agent-privilege-model.md`).
- **Windows:** the keys are readable by LocalSystem, which the agent runs as today. The intended
  `NT SERVICE\YuzuAgent` virtual account is unmeasured; CC-2 measures it if the agent has moved to
  it by then.
- **macOS:** the files are readable by root.

**Network mounts on macOS (disclosed).** The network-mount guard's type list
(`agents/shared/network_fstype.hpp:13-26`) has no macOS-only type names such as `afpfs` or
`webdav`. A JVM home on such a mount is not recognised as a network mount, which is part of the
deadline residual below. CC-3 either extends the shared list or records the gap in the README.

CC-1 measures the Linux claim as the `yuzu` account. Any source that the account cannot read reports
`unreadable`, `permission_denied`, never `absent`. A `crypto_config` row in
`docs/agent-privilege-model.md` is owed with CC-1.

### Source status and replace semantics

**Proposed.** One closed status set, for sources and for parts. No other status value exists.

| Status | Sent by | Meaning | What ingest does to the part's rows | The part's `observed_at` |
|---|---|---|---|---|
| `ok` | agent | read completely | **replaced at part grain**: the part's rows become exactly the rows reported, so a key no longer present is removed | set to `now()` |
| `absent` | agent | the file or key does not exist, confirmed by a readable parent | **removed** | set to `now()` |
| `constrained` | agent | partly read: a cap, a deadline or an unfollowed include | **replaced at key grain**: each key reported in this blob, unless flagged `capped`, has its rows replaced by exactly the rows reported for it; a `capped` key **merges** (below); a key not reported is **kept**, and is counted in `from_kept_rows` | set to `now()` (the part was read) |
| `unreadable` | agent | nothing of it could be read, with a reason (`permission_denied`, `open_failed:<errno or HRESULT>`, `network_mount`, `link_outside_roots`) | **kept** | unchanged |
| `unsupported` | agent | the source cannot exist on this OS, or the leg is not built (`leg_not_built`, `no_system_configuration`, `jvm_discovery_unavailable`) | **removed**; the device is outside that source class's device set | unchanged |
| `not_observed` | server only | in an earlier report, missing from this one | **kept** | unchanged |

- **`status_at` advances on every report, for every part, whatever its status.** It is the server
  receipt time of the latest report that carried, or omitted, the part. The prune rule
  (`status_at - observed_at > 30 days`) depends on that: an `unreadable` or `not_observed` part
  ages only while its device keeps reporting.
- **A key cut by a cap is `capped`, and merges.** A key whose own content hit a cap (a `Ciphers`
  enumeration with more than 256 subkeys, or a list with more than 512 entries) is reported with
  the flag `capped` and its part is `constrained`. Its rows are **merged**, never replaced: reported
  rows are upserted, and rows stored beyond the cap are kept, because a cut read cannot prove a
  removal. For the view, such a key's devices count in `unparsed_setting_devices` for an identifier
  the reported rows do not name, never in `defaults_apply_devices`.
- **Freshness is kept at key grain.** Every stored key carries its own `observed_at`, set to `now()`
  whenever a report carries that key, and left unchanged when the key is kept. `from_kept_rows` and
  `oldest_observed_at` (see [Response shape](#response-shape)) are derived from these key times,
  never from the part's status alone. So a key re-read in a `constrained` part is fresh, and only
  the keys that were not re-read count as kept.
- **A key that is reported with no entries** (for example `Ciphersuites =` with an empty value) is
  reported as a `setting` with an empty value, so it replaces that key's earlier rows. A key that
  was not read at all is simply not reported.
- **The status-only blob never replaces anything.** In a status-only blob (nothing readable, or
  over the byte cap), every source and every part is sent as `unreadable` or `constrained`, never as
  `ok` or without a status, and it carries no keys. So ingest keeps every row. A status-only blob
  can never wipe a part.
- A source's status is the worst of its parts' statuses. A part's `part_id` is stable across
  reports, so replacement is exact.
- `setting` states (`value` / `absent` / `unreadable` / `unknown`) describe one value inside a part.
  They are not source statuses.
- The plugin's result status is `CONSTRAINED` when any source is `unreadable` or `constrained`.

### Rules the collector honours

| Rule | Proposed design |
|---|---|
| Configured is not effective | Every `configured` row and every surface description says "configured value as found; not the effective policy". |
| No expansion of policies or defaults | Policy names, `CipherString` expressions, operator-bearing lists, Java expressions, `include` references, `$ENV::` references and unset keys all stay raw. No table maps any of them to a list. |
| Honest absence | `absent` only where the parent is confirmed readable (the `system_hardening` rule): a missing value under an opened key, or a missing file in a listed directory. An unopenable key or directory is `unreadable`, never `absent`. |
| `unreadable` / `constrained` | Per part, with a reason token through `ConstraintAccumulator`. A refused read (`ERROR_ACCESS_DENIED`, `EACCES`, `EPERM`) reports `permission_denied`. |
| Read-only, link-safe | Files are opened `O_NOFOLLOW`, regular files only, and never on a network mount (`agents/shared/network_fstype.hpp:31`). Registry strings are read with `Reg*W` through `agents/shared/win_str.hpp`. A `REG_MULTI_SZ` is split with the existing record splitter (`agents/shared/user_profile_model.hpp:444`), never with `reg_sz_to_utf8`, which stops at the first NUL (`win_str.hpp:116-117`). |
| Agent caps | 1 MiB per file; 1,024 bytes per value, which is the server's field cap; 512 entries per list; 64 JVM homes; 256 subkeys or values per registry key; 4,000 records per blob; 2.5 MiB per blob, below the server's 3 MiB. A cap makes the part `constrained` (`file_cap`, `entry_cap`, `home_cap`, `value_count_cap`, `byte_cap`). A value over 1,024 bytes is sent as a `setting` with state `unknown`, reason `value_cap`, and no value. It is never cut. |
| Blob over its cap | If the blob would exceed 2.5 MiB, the agent sends a **status-only blob**: the `source` and `part` records only, with **every part** `constrained`, reason `byte_cap` (or `unreadable`, if it was unreadable anyway), and no keys. Ingest therefore keeps every row. It never sends a cut blob. |
| Server caps | The seam enforces the same caps. A record over a cap, which a conforming agent never sends, is dropped and counted, and its source is stored `constrained` with reason `server_cap`. It is **never** silently truncated. The generic inventory seam truncates fields silently (`server/core/src/inventory_ingestion.cpp:35-37`, `:67`, `:104-107`), so this source has its own seam and does not reuse that parser. |
| Deadline | 30 s for the action, checked cooperatively between reads. Unfinished sources read `constrained`, reason `deadline`. **Residual (disclosed):** a single blocking call (a registry read on a contended hive, a read on a stacked filesystem that the network-mount guard does not recognise) can overrun the deadline. No detached thread is used, so the action returns late rather than abandoning a call. |
| Untrusted bytes | Every value goes through `yuzu::util::safe_output_field` (`sdk/include/yuzu/string_utils.hpp:100`), and the server splits on unescaped pipes only: the `app_usage` byte-for-byte contract (`docs/adr/0016-agent-daily-sync-framework.md:534`). That function is **lossy**: a backslash becomes `/` and CR/LF become spaces (`string_utils.hpp:87-99`). So `raw` and `part_id` values are not byte-exact, and the README says so. Every surface HTML-escapes raw strings at render. |
| Paths in values | A path-valued field (`part_id`, `security.overridePropertiesFile`, an include target, any path inside a raw expression) has the segment after `/home/`, `/Users/` or `C:\Users\` replaced with `<redacted>` before it is sent. The match runs **before** `safe_output_field` folds backslashes, accepts either separator, and is case-insensitive, so `c:/users/`, `C:\USERS\` and `C:/Users/` are all caught. |

### Blob, hash-skip, store and lifecycle

**Proposed.** These follow slice 2's choices, adopted here by reference:
- **Blob contract.**
  - `ver|1` comes first, then one `source|` record per allowlisted source, followed by its `part|`,
    `setting|` and `alg|` records.
  - Records are sorted deterministically.
  - Unknown versus empty follows `s2:390-394`.
  - When nothing could be read, the agent sends a status-only blob, never an empty blob (ADR-0016's
    `app_usage` clause 4, `docs/adr/0016-agent-daily-sync-framework.md:544`).
  - The blob carries no agent timestamp.
- **Hash-skip.** Raw-byte hashing, the `app_usage` approach (`server/core/src/app_usage_ingestion.cpp:75-82`).
  The server stores its own SHA-256 of the received bytes, never the agent's claim
  (`docs/adr/0016-agent-daily-sync-framework.md:108-113`).
- **Typed store.** `CryptoConfigStore`, Postgres schema `crypto_config` (ADR-0006, ADR-0012).
  - Tables: `agent_state`, `source_state`, `part_state` (status, reason, `observed_at`,
    `status_at`), `key_state` (per key: `observed_at`), `setting_row` and `alg_row`.
  - Every `*_at` column is Postgres `now()`.
  - Ingest runs one transaction per report under a per-agent lock and applies
    [the replace table](#source-status-and-replace-semantics).
- **Acknowledgement.** Two outcomes, never confused:
  - **Transient failure nacks.** A report the store could not write (store down, lock timeout, or a
    degraded tombstone read) is never acknowledged as stored. The server answers `need_full` for
    the source and records no hash. The agent re-sends on ADR-0016's jittered schedule
    (`docs/adr/0016-agent-daily-sync-framework.md:101-103`), with its own back-off, so the nack
    cannot loop. An ack never pins an empty or stale state.
  - **Deterministic refusals are acknowledged.** A report refused for a reason that a re-send cannot
    change (an unknown major version, a parse failure, an agent that is decommissioned) is
    acknowledged, writes nothing, and is counted (`result=refused` or `decommissioned`), as slice 2
    does (`s2:506-510`). A nack there would only make the agent re-send the same bytes.
- **Decommission tombstone.** Ingest writes nothing for a decommissioned agent. It consults slice 2's
  decommission tombstone (`s2:506-561`) through its named owner, never a second tombstone table, so
  a decommissioned agent that keeps running cannot repopulate its rows. Three rules close the race
  (`s2:509-513`):
  - ingest takes **the same per-agent lock** as `delete_agent` before it reads the tombstone, and
    holds it until its transaction commits;
  - the decommission cascade commits the tombstone **before or with** the `crypto_config` erase,
    never after, so no ingest can observe "erased but not tombstoned";
  - a tombstone read that fails or degrades **nacks** the report (above), never treats the agent as
    live.

  If slice 2's tombstone design changes, this source follows it (coordination item C10).
- **Typed set.** `crypto_config` joins the typed-source array that slice 2's PR 2a-1 creates
  (`s2:584-600`), so the gateway skip, the read filter and the purge all cover it. Today's typed set
  is a hand-written predicate (`server/core/src/typed_inventory_sources.hpp:23-36`). The collector
  does not ship before 2a-1 (see [Phasing](#phasing)).
- **Lifecycle.**
  - The store joins `AgentDecommissionStores` (`server/core/src/agent_decommission.hpp:117`).
  - It joins `/readyz`; `server/core/src/health_routes.cpp:729` is the template.
  - Its prune is classified `ReplicaSafe` in `background_jobs.hpp`.

**Retention (the true rule).**
- Rows of a source that keeps reporting `ok`, `absent` or `constrained` live for as long as the
  device reports. That is the device's life, until decommission erases them.
- Rows of a part whose latest status is `unreadable` or `not_observed` are pruned when
  `status_at - observed_at > 30 days`: the part has been reported, unread or missing, across more
  than 30 days of the device's own reports. Both times are server receipt times. An offline device
  sends no reports, so its `status_at` stops and nothing of it is pruned: age alone never prunes.
  This is the same reading slice 2 uses for its location-grain rule (`s2:637-645`). Slice 2's
  store-grain predicate compares `observed_at` with `now()` (`s2:635-636`), which would prune an
  offline device; this design does not copy that form, and coordination item C12 asks #6159 to
  align. The prune follows `docs/clock-guarded-retention.md`.
- **A kept key in a part that stays `constrained`** is pruned by the same rule at key grain:
  `status_at - key observed_at > 30 days`. That is slice 2's location-grain rule, applied to keys,
  and it follows slice 2's open decision 6 outcome (`s2:1561-1565`).
- A prune clears the agent's `content_hash`, so the next report is a full one. That re-send is
  bounded twice:
  - ADR-0016 jitters the `need_full` re-send;
  - the prune is capped at 500 sources per pass.

  So a mass prune does not cause a synchronized fleet re-report.
- **Classification:** machine security-configuration data. It is not personal data, but it is
  security-sensitive, because it is a map of each host's configured attack surface.
- **Audit retention:** audit rows for the reads below follow the audit log's own retention
  (`docs/user-manual/audit-log.md`). This design adds no separate audit retention.

**Personal data.** None expected, given the machine-scope-roots invariant and the path redaction
above. Free-text values, such as a raw expression or a path in a property, are covered by that
redaction rule and by the invariant, which the tests check. Proposed position, pending the DPIA
screening that CC-1 links: no works-council trigger, because the data is not behavioural.

**Store capacity (estimate, to be measured in CC-1).**
- Size: about 50 `setting` rows and 50-300 `alg` rows per device, about 30 MB of rows at 100,000
  devices before indexes. The cap is 4,000 records per device.
- Indexes:
  - `alg_row (vocabulary, identifier, role, polarity, source_class, agent_id)`, for the view
    aggregate;
  - `alg_row (agent_id, source_id, part_id)` and `setting_row (agent_id, source_id, part_id)`, for
    replace, decommission and the drill;
  - `part_state (status, observed_at)` and `key_state (agent_id, observed_at)`, for the prune scan.
- The prune scan reads `part_state` and `key_state` by status and receipt times only.

### Securable

**Proposed, [open decision 3](#open-owner-decisions). Recommendation: `Security:Read`, with no floor
entry.** That means `Security:Read` gates:
- the per-device config read;
- the `configured` kind of the view;
- the plugin action's catalogue row.

**Reasons:**
- **Every posture plugin uses it.** `local_security_policy`, `system_hardening`, `platform_security`
  and the others gate on `Security` (`plugin_action_catalogue_local_security_policy.hpp:35`).
  Configured algorithm lists are posture data of the same kind.
- **It is narrower than `Inventory:Read` under RBAC on.** `Security:Read` is seeded only to:
  - Administrator, through the CRUD loop;
  - Viewer (`server/core/src/rbac_store.cpp:1013-1022`, `Security` at `:1015`).

  `Inventory:Read` is also held by PlatformEngineer (`:791-792`), Operator (`:827`) and
  ITServiceOwner (`:851-858`).
- **Service-scoped tokens are refused, in both RBAC states,** on the view and on `/config`. This
  does not cover results of a live `crypto_config.list` dispatch: those sit in the ResponseStore and
  stay readable under `Response:Read`, which ITServiceOwner holds (`rbac_store.cpp:851-858`). That is
  the same exposure the posture plugins have ([Shape](#shape)).
  - Under RBAC off, `require_fleet_read` refuses every service-scoped session
    (`server/core/src/authz_gates.cpp:220-231`).
  - Under RBAC on, `Security` is outside the ITServiceOwner authority ceiling (`rbac_store.cpp:851-858`
    does not list it), so the ceiling check refuses it (`authz_gates.cpp:253-282`).
  - The MCP tools carry the default `ServiceScopeClass`, which is `denied`.
- **Floor check.** `Security:Read` is not in `kTopologyFloor`
  (`server/core/src/authz_topology_floor.hpp:87-135`), and the header excludes it on purpose
  (`:30-34`). A configured-algorithm list fits none of the header's three inclusion classes
  (`:54-63`), so no floor entry is proposed.

**The risk the owner accepts under either option.** With RBAC off, the default, neither `Security:Read`
nor `Inventory:Read` is floored. So every signed-in user can read the fleet's configured-algorithm
posture map: which hosts enable RC4, which have FIPS off. That needs an explicit owner risk
acceptance and a risk-register entry. The only way to avoid it is a new floored securable (below).

**Alternatives:**
- **`Inventory:Read`.**
  - Under RBAC on, the posture map widens to PlatformEngineer, Operator and ITServiceOwner.
  - Service-scoped tokens behave differently. Under RBAC on, a token holding ITServiceOwner is
    **admitted and confined** to its service's devices if the MCP tools are classed `confined`, as
    the crypto library tools are (`server/core/src/mcp_server.cpp:4243-4245`). Under RBAC off, it
    is still refused (`authz_gates.cpp:220-231`).
  - The `configured` kind would then admit service tokens while the `certificate` kind refuses
    them, so the view's MCP tool would need a per-kind service-scope rule.
- **A new `CryptoConfig:Read`.** Worth it only if the owner wants the posture map admin-only.
  - It needs a floor entry and a new inclusion class in `authz_topology_floor.hpp`.
  - It needs seeding, `kRbacSecurables`, the SOC 2 access-control inventory and access-review export
    coverage.
  - It makes collection sync-only (see [Shape](#shape)).

## Read surface

### Routes and tools

**Proposed.**
- Each MCP tool has its own dispatch branch, so `scripts/ci/check-mcp-retry-hints.py` sees it.
- Each tool ships the A5 annotations (`docs/agentic-first-principle.md:92-128`): `title`,
  `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`, a
  bounded input schema and a typed output schema.
- Each tool is described in the MCP `initialize` instructions.
- Each tool's tier is `readonly`.
- Every description carries D10's sentence (`0070:817-818`), and "configured is not effective"
  wherever the `configured` kind can appear.

| REST | MCP | Gate | Audit verb | Ships in |
|---|---|---|---|---|
| `GET /api/v1/crypto/algorithms` | `get_crypto_algorithms` | per kind (below) | `crypto.algorithms.view` | AV-1 |
| `GET /api/v1/crypto/algorithms/devices` | `list_crypto_algorithm_devices` | the one requested kind | `crypto.algorithms.devices` | AV-1 |
| `GET /api/v1/crypto/identifiers` | `get_crypto_identifier_table` | `Infrastructure:Read` (no fleet data) | `crypto.identifiers.view` | AV-1 |
| `GET /api/v1/crypto/config` | `list_crypto_config` | the `crypto_config` securable, fleet-read confined | `crypto.config.view` | CC-1 |
| `/fragments/crypto/algorithms` | — (dashboard twin of the first row) | per kind | `crypto.algorithms.view` | AV-1 |

- **`/identifiers`** serves the name table itself, with `identifier_table_version`, so that an
  agentic caller can discover the vocabularies and resolve names without guessing (A2).
- **`/config`** is the per-device read of everything `crypto_config` collected. It returns:
  - every source and part, with status, reason, `observed_at` and `status_at`;
  - every `setting`, raw expressions included;
  - every `alg` row.

  It is paged, and it keeps the store from being dormant before AV-2. It has two modes:
  - **List mode** is confined to the caller's visible set through `require_fleet_read`.
  - **With an `agent_id`,** the answer for an agent outside the visible set is the same as for an
    agent id that does not exist.
- **MCP policy rows.**
  - Each tool's `kToolSecurityRows` entry names its securable.
  - In AV-1, `get_crypto_algorithms` and `list_crypto_algorithm_devices` serve one kind, so the row
    names `CertificateInventory:Read`.
  - From AV-2 the view tool spans securables. That PR extends the MCP policy table so a multi-kind
    tool's pre-handler check refuses no caller who holds any one kind's securable. Per-kind
    permission is enforced in the handler. Under the recommended securables, every kind refuses
    service tokens, so the tool's class stays `denied`.

### Parameters

**Proposed.** One rule per parameter, the same on both twins (the #6122 item 2 lesson, `s2:842-845`).

| Parameter | Kind | Behaviour |
|---|---|---|
| `kind` | repeatable, a closed set: the kinds this server serves | **Any value that is not a served kind, `observed` included, is refused with a 400 / `kInvalidParams`.** That is the only answer for an unknown or unserved kind. If absent, every served kind is used. In AV-1 the only served kind is `certificate`. |
| `vocabulary` | closed set | Unknown values refused. |
| `identifier` | raw identifier, repeatable up to 64 times, shape-checked per vocabulary (`oid` as at `s2:851`), compared by the vocabulary's rule | Exact match only. There is **no `name` filter** (P19). |
| `role` | closed set | Unknown values refused. |
| `rsa_modulus_bits`, `ec_order_bits` | integer 1..65536, or the literal `null` | Exact match on the key field. `ec_order_bits` matches only rows whose key holds it (`ec_params=explicit`). Named-curve rows are selected by `ec_curve_oid`. |
| `ec_params` | `named` / `explicit` / `unknown` | Exact match. |
| `ec_curve_oid`, `pss_hash_oid`, `pss_mgf1_hash_oid` | OID, or the literal `null` | Exact match. `null` selects rows where the field is null. |
| `polarity`, `source_class` | closed sets (configured kind only) | Unknown values refused. |
| `order_by` | `identifier` (the default); `certificate.devices`, `certificate.certificates`, or `configured.<source_class>.<polarity>.devices` | Nothing else is accepted (P19). **A count ordering whose kind is not in `kinds_included` is refused with a 400**, so ordering can never reveal an omitted kind. |
| `agent_id` | free text, exact | Confined by the gate. |
| `cursor`, `limit` | opaque; integer 1..500, default 100 | Out-of-range values refused on both twins. |

**Paging and ordering (Proposed):**
- **The cursor pages on the row key only.** Rows are the merge of the admitted kinds' grouped
  results on the full row key, in row-key order (null key fields first). A page is the next `limit`
  row keys after the cursor position. A row that a later ingest adds or removes behind the cursor is
  missed or not, but never repeated.
- **Count ordering is first-page only.** A request with a count `order_by` and a `cursor` is
  refused with a 400. A count-ordered response returns `next_cursor: null`. If more rows exist, it
  sets `result_truncated: true` with `truncated_parts` containing `order_by_first_page`. Counts
  change between reads, so keyset paging over them would skip or repeat rows silently. Ties on the
  count are broken by the row key, ascending, so the first page is deterministic.
- **The cursor fingerprint** binds:
  - `identifier_table_version`;
  - the full filter set;
  - the kind set;
  - the caller's admitted kind set, so a permission change mid-walk restarts the walk.

  A cursor from a different table version is refused with slice 1's wording ("cursor was issued for
  a different filter set or table version", `crypto_library_model.cpp:423-428`).
  - **Disclosed:** during a rolling HA upgrade that changes the table, replicas on different
    versions refuse each other's cursors. A walk then restarts once.

**The drill, `/algorithms/devices`:**
- It requires exactly one `kind` and a full row key, with each null key field given as the literal
  `null`. For the configured kind it also requires `source_class` and `polarity`.
- It returns one entry per device with that kind's per-device facts:
  - **`certificate`:** the device's certificate count for the row, with `from_kept_rows`;
  - **`configured`:** the source, part, key, polarity, position, `raw` spelling and the part's
    `observed_at`.

**Operator recipe (user manual, Proposed).** "Where is RSA and elliptic-curve public-key
cryptography?" is answered with:
- repeated `identifier` filters on the `oid` vocabulary;
- `role=public_key`.

The manual lists key-algorithm OIDs for that query, and says plainly that the list is **not
exhaustive**:
- RSA: `1.2.840.113549.1.1.1`, and RSASSA-PSS keys `1.2.840.113549.1.1.10`;
- elliptic-curve: `1.2.840.10045.2.1`;
- Edwards-curve: Ed25519 `1.3.101.112` and Ed448 `1.3.101.113` (the same OIDs slice 2 names,
  `s2:926`);
- others an operator may need: DSA `1.2.840.10040.4.1`, and X25519 / X448 `1.3.101.110` /
  `1.3.101.111`.

The list is documentation, not a table column, and the view does not say which of these is
"vulnerable".

### Per-kind gating

**Decided (P7-P10).**

**Proposed.** The gate is **tri-state** per kind: admit, deny or degraded.

1. The route resolves the requested kinds. For each, it calls the fleet-read gate with that kind's
   securable, in a **non-rendering** form that returns the decision without writing a response
   (coordination item C2). Today's gate renders its own 401/403/503 (`server/core/src/crypto_routes.cpp:292-294`).
2. **Degraded on any kind returns a whole-response 503**, in the A4 envelope with `retry_after_ms`.
   This covers a store-unavailable branch (`server/core/src/authz_gates.cpp:200-207`) and any read
   failure or timeout. A degraded kind is **never** listed in `kinds_omitted` and never shown as a
   denial. A degraded authorization read must never look like a permission decision, and an
   engine-grain consumer must get complete-or-fail (D9, `0070:805-806`).
   - **Residual (disclosed).** The gate turns a null or not-open management-group store into a 503,
     but a fault in the middle of `authorize_list_read`'s query comes back as `DenyAll` and is
     rendered as a 403 (`server/core/src/authz_gates.cpp:342-357`, `:369-376`). That is the
     deliberate weakening implementation plan §2c accepts for every `authorize_list_read` caller.
     Until it is fixed, such a fault shows as a denial on this route too: as a `kinds_omitted`
     entry with `permission_denied` from AV-2, or as a 403 in AV-1. Coordination item C11 asks the
     non-rendering gate (C2) to surface that in-query error as degraded, which would close it.
3. **An admitted kind** contributes its rows, confined by **its own** visible-device set. A
   present-empty set means deny-all, never "no filter".
4. **A denied kind** is listed in `kinds_omitted`. It carries `permission` only when that grant alone
   would admit the caller:
   - `{"kind": "certificate", "reason": "permission_denied", "permission": "CertificateInventory:Read"}`;
   - `{"kind": "certificate", "reason": "service_scope"}`, for a service-scoped session, which no
     grant admits;
   - `{"kind": "certificate", "reason": "admin_required"}`, for a non-admin under RBAC off on a
     floored kind, where only the admin role admits;
   - `{"kind": "certificate", "reason": "rbac_required"}`, for an engine principal while RBAC is
     off, which the gate denies whatever is granted (`server/core/src/authz_gates.cpp:150-159`);
   - `{"kind": "certificate", "reason": "mcp_tier"}`, for an MCP token whose tier does not allow
     the read (`authz_gates.cpp:170-178`), which a grant to the token's creator does not change.

   This follows the service-scope routed concern's clause 5: never name a permission that would not,
   by itself, admit the caller.
5. **A row whose only evidence is an omitted kind is not in the response** (P9). Rows are built from
   admitted kinds only, so this holds by construction, and a test proves it.
6. **If every requested kind is denied,** the response is a 403 in the A4 envelope. Its `error.data`
   lists each kind with its reason, and with a permission where step 4 allows one. No single
   top-level `permission` is set, because no one grant admits the whole request.

**Floors.** Every kind uses `require_fleet_read`, which applies the topology floor
(`server/core/src/authz_gates.cpp:315`). `require_list_read` does not apply it
(`server/core/src/auth_routes.hpp:407-413`), and is not used.

**AV-1 ships the single-kind gate only:**
- one kind (`certificate`) and one gate call, through C2's **non-rendering** form, so the route
  writes the 403 itself with step 4's reasons. Today's rendering gate names a permission even on
  the RBAC-off floor deny (`server/core/src/authz_gates.cpp:325-327`), which step 4 forbids; AV-1
  does not use it. C2 is built by whichever of 2a-2, 2a-4 or AV-1 merges first;
- 403 or 503 on deny or degrade;
- no `kinds_omitted` field.

AV-1's denial tests are scoped to that non-rendering form: they assert each step-4 reason, and that
no `permission` appears for `service_scope`, `admin_required`, `rbac_required` or `mcp_tier`.

The partial-admission branch, `kinds_omitted`, and the partial-permission and separate-confinement
tests all ship in AV-2, when a second kind exists. The field is additive, so nothing breaks.

### Response shape

**Proposed** (`GET /api/v1/crypto/algorithms`, AV-2 shape; the numbers are consistent with one
another):

```json
{
  "data": {
    "algorithms": [{
      "vocabulary": "oid", "identifier": "1.2.840.113549.1.1.1",
      "name": "rsaEncryption", "role": "public_key",
      "params": {"rsa_modulus_bits": 2048},
      "evidence": {
        "certificate": {"certificates": 812, "devices": 97,
                        "ca_certificates": 140, "end_entity_certificates": 672,
                        "from_kept_rows": 3}
      }
    }, {
      "vocabulary": "schannel", "identifier": "rc4 128/128", "name": null,
      "role": "bulk_cipher", "params": {},
      "evidence": {
        "configured": {"by_source_class": [{
          "source_class": "schannel",
          "devices_considered": 61,
          "devices_with_entry": 41,
          "disabled": {"devices": 41},
          "unparsed_setting_devices": 1,
          "defaults_apply_devices": 19,
          "from_kept_rows": 1,
          "oldest_observed_at": "2026-10-12T03:10:00Z"
        }]}
      }
    }],
    "kinds_included": ["certificate", "configured"],
    "kinds_omitted": [],
    "coverage": {
      "certificate": {
        "as_of": "2026-10-19T12:00:00Z",
        "devices_included": 120, "devices_reporting": 110,
        "oldest_observed_at": "2026-09-30T08:00:00Z", "from_kept_rows_devices": 4,
        "unattributed_certificates": {"public_key": 2, "signature": 0},
        "confined": true, "result_truncated": false, "truncated_parts": [],
        "not_read": ["per-user stores", "Java cacerts", "..."]
      },
      "configured": {
        "as_of": "2026-10-19T12:00:00Z",
        "devices_included": 120, "devices_reporting": 104,
        "statement": "configured values as found; not the effective policy",
        "container_image_config_devices": 0,
        "from_kept_rows_devices": 1,
        "oldest_observed_at": "2026-10-12T03:10:00Z",
        "sources": [{
          "source_class": "schannel",
          "devices_ok": 58, "devices_absent": 0, "devices_unreadable": 1,
          "devices_constrained": 2, "devices_no_source": 43, "devices_not_observed": 0,
          "oldest_observed_at": "2026-10-12T03:10:00Z"
        }],
        "confined": true, "result_truncated": false, "truncated_parts": [],
        "not_read": ["sshd_config", "CNG local-configuration key", "..."]
      }
    },
    "as_of": "2026-10-19T12:00:00Z",
    "identifier_table_version": 1,
    "result_truncated": false, "truncated_parts": [],
    "next_cursor": null
  }
}
```

**Definitions: one device set per kind and part.** Every count, denominator, `from_kept_rows` and
`oldest_observed_at` in a block derives from **one** device set, computed at key grain. Nothing in
a block counts a device outside its set.

- **Coverage, per kind.**
  - **`devices_included`:** devices in the caller's visible set for that kind.
  - **`devices_reporting`:** devices of `devices_included` with at least one stored report of that
    kind's source.
  - **Per source class** (configured kind), `devices_ok`, `devices_absent`, `devices_unreadable`,
    `devices_constrained`, `devices_no_source` (status `unsupported`) and `devices_not_observed`
    partition `devices_reporting`: each reporting device has exactly one status for each source
    class, so they sum to `devices_reporting`. In the example, 58 + 0 + 1 + 2 + 43 + 0 = 104.
- **The configured row's device set, D.** For a view row and a source class, D is the devices in
  the caller's visible set that have **stored state for the key that would carry the identifier**
  in that class, fresh or kept. Examples of that key: the SCHANNEL `Ciphers` enumeration for a
  bulk cipher; the `jdk.tls.disabledAlgorithms` property for a Java constraint. A device whose key
  was never read (its part only ever `unreadable`, its source `unsupported`, or no report at all) is
  outside D, and appears only in the per-source coverage above.
  - **`devices_considered`** = |D|.
  - D is partitioned. Each device is in exactly one of these, checked in this order:
    1. **`devices_with_entry`:** at least one stored `alg` row for this identifier, in any polarity;
    2. **`unparsed_setting_devices`:** no such row, but an explicit setting at that key produced
       none (a `wrong_type` or capped value for the identifier's own subkey, or an operator-bearing,
       raw or `covered_by` value for the whole key; see [Polarity](#configured-polarity));
    3. **`defaults_apply_devices`:** neither. An OS or library default applies, and Yuzu does not
       say what it is.

    So `devices_with_entry` + `unparsed_setting_devices` + `defaults_apply_devices` =
    `devices_considered`. In the example, 41 + 1 + 19 = 61.
  - **Polarity counts** (`enabled`, `ordered`, `disabled`, `constraint`, `deprioritised`) are each
    a subset of `devices_with_entry`. A device with entries of two polarities (for example two JVM
    homes) is in both, which is why polarities are never summed.
  - **`from_kept_rows`:** devices in D whose stored state for that key was not carried by their
    latest report (the key's `observed_at` is before the part's `status_at`, or the part's latest
    status is `unreadable` or `not_observed`).
  - **`oldest_observed_at`:** the oldest key `observed_at` over D.
  - In the example, the 61 devices are the 58 `ok`, the 2 `constrained` (both re-read the `Ciphers`
    key) and the 1 `unreadable` device whose earlier `Ciphers` state is kept. That device's kept
    rows say `disabled`, so it is one of the 41, and it is the 1 in `from_kept_rows`.
- **The certificate row's device set** is the devices in the visible set with a stored certificate
  row for the identifier and key. `certificates`, `devices`, the `is_ca` split and `from_kept_rows`
  (certificates whose only locations are in stores whose latest status is not `ok`, `s2:987-988`)
  all come from that set.
- **Kind-level `from_kept_rows_devices` and `oldest_observed_at`** in `coverage` are taken over the
  union of the kind's row sets on the page. They are a data-age signal, not a count to add to
  anything. Data from a reporting device is at most about a day old (the daily sync, with the weekly
  full floor). Kept rows can be up to the 30-day prune bound old, or older for an offline device.
  The dashboard shows both.
- **`unattributed_certificates`:** certificates in scope whose `key_alg_oid` or `sig_alg_oid` is
  null, for example from an older agent. They have no row, and are counted here so that they are
  never silently missing.

Each configured block's text says "devices with no explicit setting (default applies), and devices
whose setting could not be parsed, are not counted in any polarity".

**Rules.**
- **No cross-kind total** anywhere: no row-level `devices`, no `devices_total` and no union of
  device sets (P10). Configured counts are also never summed across source classes or polarities.
- **`as_of`.** Each kind's `as_of` is Postgres `now()` from that kind's statement. The top-level
  `as_of` is the earliest of them, so a reader never takes the response as newer than its oldest
  part.
- **Truncation.**
  - Each kind's `result_truncated` is slice 2's OR rule (`s2:800-809`): a page limit, a row ceiling,
    a byte budget, first-page-only count ordering, or any `constrained` store, part or certificate
    behind the counts (`constrained_store`, `constrained_source`, `constrained_certificate`).
  - The top-level `result_truncated` is the OR of all of them.
  - The top-level `truncated_parts` is the union of every kind's `truncated_parts`, plus
    `page_limit` when the page itself was cut.
- **Empty blocks are not emitted.** A configured `by_source_class` entry is left out when
  `devices_considered` is zero. A row with no non-empty admitted block is not
  emitted.
- **Dashboard wording.** A configured tile says "devices configured with …" and carries "configured
  value as found; not the effective policy" on the tile itself. Each source shows its
  `observed_at`.
- **Raw strings are HTML-escaped** at render.

### Audit, degrade, admission

**Proposed.**
- **Audit.** One row per read. It records:
  - `scope=fleet|confined` per kind;
  - the kinds included and omitted;
  - the filters, the row count and the truncation flag;
  - `itv=<identifier_table_version>`.

  Untrusted values go through `log_token`.
- **Audit-write failure.**
  - **REST fails closed:** 503, `Sec-Audit-Failed`, no data. This is slice 2's OD-2 for certificate
    reads (`s2:761-765`), so no certificate-derived read is weaker than the certificate read
    itself.
  - **MCP and the dashboard set-and-proceed**, with `audit_persisted: false` or the "Audit not
    recorded." notice, as slice 1 does.
  - `/config` follows the same split.
  - `/identifiers` is set-and-proceed everywhere, because it serves no fleet data.
- **503, never empty.** See [Per-kind gating](#per-kind-gating) step 2.
- **Admission.** One lease on the shared `CryptoReadGate` (`server/core/src/crypto_read_gate.hpp:17`,
  two slots) per request, held across the per-kind statements. A shed is a 503 with a retry hint,
  counted as slice 1 counts it. The hold time is bounded by the per-kind timeouts ([Capacity](#capacity)).

### Computed at read time

**Decided (P13).**

**Proposed:**
- Each kind is one SQL aggregate over that kind's typed store, grouped by the row key:
  - distinct devices;
  - for certificates, distinct (device, `sha256`).
- It runs under that kind's statement timeout, inside the store's own query owner.
- Names are joined in the server from the compiled table, after the SQL.
- Nothing is written: no materialised view, no cache table, no per-run rollup.
- No cross-schema SQL is needed, because kinds are never joined.

## Capacity

**Proposed.** These are estimates, replaced by measurements before AV-1 and AV-2 merge.

- **Certificate kind.** At 100,000 devices, slice 2 estimates 30-60 million `cert_fact` rows
  (`s2:1657-1662`). The view groups them twice:
  - `public_key` rows by (`key_alg_oid`, `rsa_modulus_bits`, `ec_params`, `ec_curve_oid`,
    `ec_order_bits`);
  - `signature` rows by (`sig_alg_oid`, `pss_hash_oid`, `pss_mgf1_hash_oid`).

  Slice 2's indexes (`s2:477-480`) do not cover these groupings, so AV-1 needs two covering
  indexes on `cert_fact`:
  - `(key_alg_oid, rsa_modulus_bits, ec_params, ec_curve_oid, ec_order_bits, agent_id, sha256)`;
  - `(sig_alg_oid, pss_hash_oid, pss_mgf1_hash_oid, agent_id, sha256)`.

  They belong to slice 2's store, so they are coordination item C9.
- **Configured kind.** 5-30 million `alg_row` rows, grouped on the first `alg_row` index
  ([Store capacity](#blob-hash-skip-store-and-lifecycle)).
- **Confinement is a join** against the caller's visible set as a relation (for a management group,
  its membership), never an `agent_id = ANY($array)` over tens of thousands of ids. The mechanism is
  the implementing PR's.
- **Statement timeouts:** 10 s for the certificate kind and 5 s for the configured kind, each by
  `SET LOCAL statement_timeout`. A timeout is a whole-response 503 ([Per-kind gating](#per-kind-gating)).
  Partial per-kind results on timeout were considered and rejected. A kind cut by time is not a
  defined subset, and it would turn a capacity fault into a changed answer.
- **Count ordering** is computed once, on the first page only, so no walk recomputes it per page.
- **Admission.** The worst-case slot hold is the sum of the timeouts, 15 s, on one of two shared
  slots. AV-2 measures shed rates under dashboard polling, together with slice 2's measurement
  (`s2:788-793`, C6).
- **AV-1 acceptance gate.** On a seeded fixture of 100,000 devices at slice 2's per-device estimate,
  run `EXPLAIN (ANALYZE, BUFFERS)` for:
  - a fleet-wide caller;
  - a caller confined to 50,000 devices.

  Each statement must finish inside its timeout, and the plans are recorded in the PR. AV-2 repeats
  the gate for the configured kind.
- **If the gate fails,** this design does not choose the fallback. A daily or cached rollup would
  materialise the view, which brings interlock cell (g) and P13 into play. The fallback becomes a new
  owner decision ([open decision 6](#open-owner-decisions)), decided with the measurements in hand.

## Metrics and alerts

**Proposed.** These follow `docs/observability-conventions.md`.
- Server metrics use `yuzu_server_`, and fleet rollups use `yuzu_fleet_`.
- Every label is a closed set. **Counters** are pre-seeded to zero for every label combination
  (`docs/observability-conventions.md:13`). The **fleet gauge** is the one exception: it is
  absent-not-zero, so a gauge with no data is absent rather than reporting a false zero.
- **No label is ever an algorithm, an identifier, a vocabulary or a cipher** (P12). A test over the
  metric registry asserts that no `yuzu_*crypto*` series has such a label.

| Metric | Type | Labels |
|---|---|---|
| `yuzu_server_crypto_config_ingest_total` | counter | `result` (`stored`, `skipped_unchanged`, `refused`, `store_failed`, `decommissioned`), `reason` (closed set: the caps, `version`, `parse`) |
| `yuzu_server_crypto_algorithm_read_seconds` | histogram, default buckets | `kind` (closed) |
| `yuzu_server_crypto_algorithm_read_timeouts_total` | counter | `kind` |
| `yuzu_inventory_read_degrade_total` | counter (existing; sheds counted as slice 1 counts them) | existing |
| `yuzu_fleet_crypto_config_source_status` | gauge, fleet rollup, absent-not-zero | `os`, `source_class` (closed), `status` (the closed status set) |

**Alerts**, in `docs/prometheus/yuzu-alerts.yml`. Each ships with a `promtool test rules` case that
fires it:
- **`YuzuCryptoConfigIngestFailing`:** the write-failure ratio,
  `increase(...{result="store_failed"}[1h]) / (increase(...{result="stored"}[1h]) + increase(...{result="store_failed"}[1h]))`,
  above a threshold (proposed 10 %) for 1 hour. Hash-skip reports (`skipped_unchanged`) write
  nothing, so they are left out of the denominator and cannot dilute the ratio. A ratio fires on a
  partial store failure too, which a "no successes at all" rule would miss. Its promtool tests cover
  a total failure, a partial failure, and the case where every write fails while hash-skip reports
  keep succeeding.
- **`YuzuCryptoAlgorithmReadTimeouts`:** the read-timeout rate above a threshold for 15 minutes.
  The threshold is set from AV-1's measurements.

The `sre` agent tunes both thresholds against fleet data, in the PR that ships them.

**Readiness.** `/readyz` includes `crypto_config_store` (`server/core/src/health_routes.cpp:729`
is the template).

## CBOM algorithm components

**Decided (D7, `0070:670-699`; the architect ruling):** facts only. `classicalSecurityLevel`,
`nistQuantumSecurityLevel` and `certificationLevel` stay empty.

**Proposed.** Checked against `bom-1.7.schema.json` as vendored with #6143
(`tests/fixtures/cyclonedx/bom-1.7.schema.json`).

- **Which rows become components.** A component is emitted only for a view row with:
  - certificate evidence, or
  - configured evidence of polarity `enabled` or `ordered`.

  A row whose only evidence is `disabled`, `constraint` or `deprioritised` is **not** a component. An
  asset in a CBOM reads as present, and P14 forbids that for an algorithm that is only refused.
- **One component per qualifying view row**, `assetType: algorithm`. Its `bom-ref` is derived from
  the full row key, so P-256 and P-384 keys, or PSS with SHA-256 and with SHA-384, are distinct
  components.
- **Filled fields:**
  - `name`: the table name, or the raw identifier when the name is null.
  - `cryptoProperties.oid`, for the `oid` vocabulary.
  - `algorithmProperties.parameterSetIdentifier`, defined for OID-keyed rows as:
    - the decimal `rsa_modulus_bits`, for an RSA `public_key` row;
    - the decimal `ec_order_bits`, for an `ec_params=explicit` row;
    - omitted otherwise. A named curve is identified by its OID property instead, and a signature
      by its PSS properties.
  - A parameter-key property for every non-null key field, in the form
    `yuzu:crypto:param:<field>`, for example `yuzu:crypto:param:pss_hash_oid`. The variants are
    told apart by properties, not by `bom-ref` alone.
  - `yuzu:crypto:vocabulary`, `yuzu:crypto:identifier` and `yuzu:crypto:role`.
  - One property per kind and count, in the form `yuzu:crypto:algorithm_evidence:<kind>:<count>`,
    for example `yuzu:crypto:algorithm_evidence:certificate:devices`. These counts are never summed
    across kinds. The name does not clash with #6143's document-level `yuzu:crypto:evidence`
    (`server/core/src/crypto_cbom.cpp:128`).
- **Left empty:**
  - `classicalSecurityLevel`, `nistQuantumSecurityLevel` and `certificationLevel` (P3);
  - `primitive` and `cryptoFunctions`: a classification the table does not carry;
  - `algorithmFamily` and `ellipticCurve`: both are enums of a second taxonomy in
    `cryptography-defs.schema.json`. Filling them would need a mapping into it, which is a second
    name table, against condition 4;
  - `curve`, which is deprecated;
  - `executionEnvironment`, `implementationPlatform`, `mode` and `padding`, which the evidence does
    not state.
- **`relatedCryptographicAssets`.**
  - Each certificate component references its `role: signature` row's component.
  - Each public-key component carries an `algorithm` entry pointing at its `role: public_key` row's
    component.
  - Configured components are referenced by no certificate. A protocol component that references
    them waits for `observed` evidence, because a configured list is not a negotiated protocol.
  - This requires 2a-4 to key its algorithm components by the view's row key (coordination item
    C8). Until AV-1b lands, 2a-4's components carry the raw identifier as `name` and no table
    name.
- **Omission and truncation shapes are aligned with slice 2.**
  - The CBOM keeps s2's `yuzu:crypto:halves_omitted` (`s2:1026-1027`), and adds the value
    `configured_algorithms` for an omitted configured kind. An omitted half's components are
    absent, never zero.
  - Truncation is reported as s2 reports it, with a top-level `truncated_parts`.
  - Scope is reported per half: `yuzu:crypto:scope:<half>`. #6143's single
    `yuzu:crypto:scope` (`server/core/src/crypto_cbom.cpp:126`) describes the library half only, and
    stays as it is.
  - The view's REST shape uses `kinds_omitted`, because the view is organised by evidence kind and
    the CBOM by half. The CBOM's `configured_algorithms` value is the one mapping between the two.
- **Versions.** The export carries `yuzu:crypto:identifier_table_version` beside #6143's existing
  `yuzu:crypto:table_version` (C4).

## D10 lint extension

**Decided (the architect ruling):** the D10 token list gains `strength`, `security_level`,
`bits_of_security`, `classical`, `quantum`, `deprecated`, `recommended` and `certification`.

**State of the lint.** No D10 lint exists yet, on `dev` or on any branch. ADR-0070 D10 requires one
(`0070:828-833`), and slice 2 plans it for 2a-2 (`s2:80`). This design specifies its matching rules
for 2a-2 (coordination item C5).

**Proposed matching:**
- **The base list** (`weak`, `strong`, `risk`, `score`, `expired`, `expiring`, `eol`, `supported`,
  `vulnerable`, `pqc`, `quantum_safe`, `approved`, `compliant`) keeps **case-insensitive substring
  matching** on property names. ADR-0070's "and similar" (`0070:831`) needs that breadth.
- **The new single tokens:** `strength`, `classical`, `quantum`, `deprecated`, `recommended` and
  `certification`.
  - These also use case-insensitive substring matching on property names.
  - The match catches glued forms such as `nistQuantumSecurityLevel`, `quantumVulnerable` and
    `certificationLevel`.
- **The new multi-token names:** `security_level` and `bits_of_security`.
  - These match a contiguous token sequence after splitting the property name on `_`, `-` and
    camelCase boundaries.
  - So `securityLevel`, `SecurityLevel` and `bits-of-security` all match.
- **Excluded:** the OpenAPI and JSON Schema keyword `deprecated` (a schema keyword, not a property
  name), and description text. D10's description sentence is checked separately.
- **No allow-list entries** for these tokens. D13's closed allow-list (`0070:1185-1191`) covers three
  D13 count fields, on D13 count reads only, and the view is not one (P11).
- **Where it lands.** AV-1 depends on 2a-2, so 2a-2's lint always exists first. 2a-2 builds it
  with the base list and, if it adopts C5, these rules; otherwise AV-1 adds these rules to it. The
  D13 allow-list entries are not part of either: they arrive with 2a-3, the PR that adds the D13
  count reads (`s2:81`, `:995-997`).

## Proposed ADR-0070 amendment

**Routing (Proposed; [open decision 2](#open-owner-decisions)):**
- **Not in #6125.** #6125 is under changes-requested review by another session.
- **Instead, an "Update" section** appended to ADR-0070 after #6125 merges.
- **Before slice 2's PR 2a-4,** because 2a-4 emits CBOM algorithm components (`s2:82`,
  `:1015-1017`) keyed by the identifiers the amendment admits. 2a-4 does not need the table itself:
  until AV-1b it emits raw identifiers with null names (see [Phasing](#phasing)).
- **Review:** it is reviewed as a placement change under ADR-1005 Decision 2.
- **Appendix row:** when ADR-1005's examples appendix exists, D11's D2 row (`0070:846`) carries the
  amended conditions.

**Proposed text, verbatim:**

> ### Update (YYYY-MM-DD): D2 admits a second curated identity table, matched on exact registry identifiers
>
> D2's class, "curated identity tables" (D11), was written for one table: crypto-library families
> matched on a component's declared name. The algorithm view
> (`docs/crypto-algorithm-view-design.md`) needs a second curated identity table, which names
> cryptographic algorithms by their registered identifiers. This update widens condition 2 to admit
> it, and states conditions 1, 3 and 4 for any curated identity table rather than for library
> families alone.
>
> Conditions 1, 3 and 4 read, for every curated identity table under D2:
>
> > 1. **Identity only.** A rule maps a declared identity or a registered identifier to a name or a
> >    family. The table carries no attribute that grades what it names: no strength, security
> >    level, security-bits estimate, primitive classification, certification status, support,
> >    end-of-life, CVE, post-quantum or preference field, and no colour or severity in any surface
> >    that renders it. Adding one moves that attribute, not the table, to the engine.
> > 3. **Inclusion is factual, not evaluative.** An entry is included because the identifier is a
> >    cryptographic library or a cryptographic algorithm or parameter, and excluded only on a
> >    factual ground. Nothing is included or omitted because it is considered good or bad.
> > 4. **No second copy.** Each question has one table, and a second, divergent list would turn the
> >    table into two answers to one question. For the library-family table, the SQL patterns are
> >    generated from the same table (`sql_patterns()`), and every store result is re-checked with
> >    `classify()` before it is shown. For the algorithm identifier table, every surface that names
> >    an identifier (the certificate summary, the CBOM export and the algorithm view) takes the name
> >    and the table's version from that one table, or shows the raw identifier with no name.
>
> Condition 2 ("Deterministic and inspectable") gains this paragraph:
>
> > Matching may also use a **registry identifier**, matched exactly within its own vocabulary and
> > never by prefix, alias or cross-vocabulary equivalence: a dotted OID, an IANA TLS codepoint (a
> > cipher suite, a supported group or a signature scheme), or an SSH algorithm name. The table
> > carries its version on every response and in every cursor fingerprint, as above. An identifier
> > the table does not hold is returned with its raw value and no name, never dropped. A
> > cipher-suite entry may record the registry Description and, where the registered name states
> > one, the literal key-exchange-and-authentication segment of that name, unsplit; it records
> > nothing the name does not state, so a TLS 1.3 suite records no key exchange or authentication.
> > No evaluative column of any registry (for example IANA's "Recommended") is imported.
>
> D11's D2 row ("curated identity tables") carries conditions 1 to 4 as amended here.

**Not part of the ADR text: a contingency for the decision record.** The architect's position is
that a compiled snapshot of an IANA registry is naming data, like the OID arc registry, not
"external domain data" (ADR-1005:47). The maintainer's review of the Update decides that
([open decision 1](#open-owner-decisions)). If the ruling goes the other way, the IANA codepoint
vocabularies are struck from the condition-2 paragraph before merge, and the dotted-OID and SSH-name
parts stand.

## Assurance impact

**Proposed.** This governs what customer-facing material may say: security questionnaire answers,
the SOC 2 narrative and any whitepaper. The AV-1 PR updates any such material that mentions Domain
41.

| Allowed claim | Not allowed |
|---|---|
| "Yuzu inventories the public-key and signature algorithms of collected certificates, as facts." | "Yuzu detects weak, deprecated or quantum-vulnerable cryptography." |
| "Yuzu reports configured algorithm lists from the named sources (SCHANNEL, Group Policy cipher order, crypto-policies, `openssl.cnf`, `java.security`)." | "Yuzu reports the effective TLS policy" or "what a host will negotiate". |
| "Yuzu reports the Linux `fips_enabled` flag and the Windows FIPS policy value as configured." | "Yuzu verifies FIPS compliance" or "FIPS 140 validation". |
| "Every read states its coverage, what it did not read, and how old its data is." | "A complete cryptographic inventory of the estate." |
| "A post-quantum migration planner can use the inventory as input." | "Yuzu assesses post-quantum readiness." |

The `not_read` lists of each kind are part of every claim. A claim made without them overstates
coverage. Containerised agents report their image's configuration, which any claim about containers
must say.

## Phasing

**Proposed.** Each PR is reachable on merge: an operator, an agent or a test against the running
server can observe what it adds. No PR ships a store without a read, or a read without data. Every
PR also owes the standard set: `/governance`, `/test`, a `changelog.d/` fragment, and SOC 2 evidence
for any new audit verb.

| # | PR | Contents | Depends on | Reachable because | Docs and evidence owed |
|---|---|---|---|---|---|
| AV-0 | ADR-0070 Update | The [amendment](#proposed-adr-0070-amendment). Docs only. | #6125 merged | It is the recorded placement the table rests on. | The ADR Update. The ADR-1005 appendix row, if that appendix exists. |
| AV-1 | Algorithm view, `certificate` kind | `crypto_identifier_table` (OID vocabulary). `/algorithms`, `/algorithms/devices` and `/identifiers`, with their MCP twins and the fragment. A single-kind gate. The D10 token rules, unless 2a-2 carried them. The two covering indexes (C9). The capacity gate. Metrics for reads. | AV-0; slice 2's 2a-2 | An operator with `CertificateInventory:Read` sees key and signature algorithm rows, with names. | `docs/user-manual/crypto.md` (the view, the recipe, the "not judged" statement, dashboard help); `rest-api.md`; `mcp.md`; `audit-log.md` (the three verbs); the SOC 2 audit-verb inventory; the assurance-material update; capability-map §41.6 (`docs/capability-map.md:1628`); roadmap Issue 18.8 (`docs/roadmap.md:1870`). |
| AV-1b | Shared names in the slice-2 surfaces | Slice 2's `/summary` (`s2:905-910`) and 2a-4's CBOM algorithm components, which until now carry raw identifiers with null names, take their names and `identifier_table_version` from the one table (C3, C8). | AV-1; lands with or after 2a-4 | The certificate summary and the CBOM show names identical to the view's. | `crypto.md` and `rest-api.md` (the new field). |
| CC-1 | `crypto_config`, Linux, end to end | The plugin and its `list` action. The Linux leg; Windows and macOS legs return `unsupported`, `leg_not_built`. The sync source, `CryptoConfigStore` and its ingest seam. The typed-set entry and the tombstone check. Decommission, `/readyz`, the prune. `/api/v1/crypto/config` and its MCP twin. The catalogue row. Ingest metrics and alerts. | slice 2's 2a-1 (the typed-source array) and its tombstone (2a-2); open decisions 3 and 5 | A Linux agent's configured lists and settings appear on the config read. | The generated plugin README, with the container, privilege and lossy-escape caveats. `docs/os-capability-matrix.md` and capability-map §41.5 (`docs/capability-map.md:1624`). The `docs/agent-privilege-model.md` row. `crypto.md`, `rest-api.md`, `mcp.md`, `audit-log.md` (`crypto.config.view`), and `rbac.md` if the securable changes. The SOC 2 inventory if a securable is added. The DPIA screening record linked from the PR. The YAML instruction definition under `content/definitions/` and its `docs/yaml-dsl-spec.md` §14.8 entry, if the action is dispatchable. The risk-register entry for the RBAC-off posture map. |
| CC-2 | `crypto_config`, Windows leg | SCHANNEL, the Group Policy order, .NET, WinHTTP and FIPS, measured on the Windows test box. The CNG local-key measurement gate. | CC-1 | Windows agents report. | README, capability matrix, `crypto.md`. |
| CC-3 | `crypto_config`, macOS leg | Java under `/Library/Java/JavaVirtualMachines`, and the `apple_tls` `unsupported` source. | CC-1 | macOS agents report, with their gaps named. | README, capability matrix, `crypto.md`. |
| AV-2 | `configured` kind in the view | The kind, `kinds_omitted` and the partial-admission branch. Polarity blocks and per-source coverage. The `schannel` / `openssl` / `jca` vocabularies, without names. The "Configured entries naming a restriction" dashboard section. The multi-kind MCP policy row. The capacity gate for this kind. | AV-1; CC-1 | The view shows configured rows beside certificate rows, never summed. | `crypto.md` (polarity, coverage, "not effective"), `rest-api.md`, `mcp.md`, `audit-log.md`. |
| AV-3 | CBOM: configured algorithm components and public-key links | The CBOM additions under [CBOM algorithm components](#cbom-algorithm-components) that 2a-4 does not already have. | AV-1b; AV-2; 2a-4 | The export lists configured `enabled` / `ordered` algorithms and links key components to algorithm rows. | `crypto.md`, `rest-api.md`, `mcp.md`. |
| AV-4 | `ssh_host_key` kind | The `ssh` vocabulary in the view. | the slice-3 ADR (D8) and slice-3 collection | Host key types appear as their own kind. | as the slice-3 ADR requires |
| — | `observed` kind | Not scheduled. | the TLS-probing threat model (P21) | — | — |

**Order and dependencies.**
- The view line runs AV-0 → AV-1 → AV-1b.
- **AV-0 merges before 2a-4** (the routing in open decision 2). 2a-4 does **not** depend on AV-1:
  the table ships in AV-1, and AV-1b lands with or after 2a-4. Until AV-1b, 2a-4 emits its
  algorithm components with the raw identifier and a null name. That keeps condition 4 intact: at
  no point does a second name list exist, because 2a-4 shows no names at all until it takes them
  from the one table.
- CC-1 can start once 2a-1 has merged, in parallel with AV-1.
- AV-2 needs both lines.
- CC-2 and CC-3 follow CC-1, in either order.
- The IANA codepoint vocabularies enter the table only after [open decision 1](#open-owner-decisions),
  and only with a collected source that uses them. None of AV-1 to AV-3 needs them.

## Coordination with the slice-2 design

These are things the view needs from #6159. Each is a request for that design or its PRs to settle.
Only C12 points at an inconsistency inside #6159 itself; none contradicts a decision it records.

| # | Item | Why |
|---|---|---|
| C1 | **Explicit-curve marker.** A null `ec_curve_oid` can mean "explicit parameters" or "unknown". Add a raw field `ec_params` (`named`, `explicit` or `unknown`) next to `ec_order_bits` (`s2:266-267`). | The parameter-set key must not merge explicit-curve keys with keys whose curve the agent could not read (P16). |
| C2 | **A non-rendering, tri-state gate.** The per-half CBOM gating (`s2:1026-1027`) and the view's per-kind gating both need the fleet-read gate to return admit, deny (with the reason and whether a grant would admit) or degraded, without writing a response. Store-unavailable (503) must stay distinct from deny. Build it once, in whichever of 2a-2, 2a-4 or AV-1 merges first, and the others reuse it. It also returns the step-4 reasons (`service_scope`, `admin_required`, `rbac_required`, `mcp_tier`) so no deny names a permission that would not admit. | Two partial-result surfaces, one gate seam. |
| C3 | **One name table.** If `/summary` or the 2a-4 CBOM shows any algorithm or curve name, the name comes from `crypto_identifier_table`, with `identifier_table_version` on the response and in any cursor (P18). Until AV-1b, both show raw identifiers with null names and no hand-written name list. | Condition 4: a second list is a second answer. |
| C4 | **Version field names.** The family table is `table_version` (library reads) and `yuzu:crypto:table_version` (`server/core/src/crypto_cbom.cpp:108`). The identifier table is `identifier_table_version` and `yuzu:crypto:identifier_table_version` on every surface. | Two tables, two names, no ambiguity in a response that carries both. |
| C5 | **The D10 lint.** No such lint exists yet. #6159 says 2a-2 adds it (`s2:80`) but does not state its matching rules. This design specifies them ([D10 lint extension](#d10-lint-extension)), and 2a-2 adopts them or records why not. | One lint, with stated rules. |
| C6 | **Admission budget.** The view adds a third consumer of the two `CryptoReadGate` slots. 2a-3's shed measurement (`s2:792-793`) includes the algorithm fragment's polling. | Slice 2 hazard 14 (`s2:1605-1607`). |
| C7 | **The typed-source array** (2a-1, `s2:584-600`) is the one place where `crypto_config` registers. | No second list. |
| C8 | **2a-4 keys algorithm components by the view's row key.** This amends `s2:1015-1016`'s "one `algorithm` component per distinct signature algorithm OID" to one per (`sig_alg_oid`, `pss_hash_oid`, `pss_mgf1_hash_oid`), with the parameter properties above. | PSS variants must not merge into one component, and the view and the CBOM must agree. |
| C9 | **Two covering indexes on `cert_fact`** ([Capacity](#capacity)), added to slice 2's store by AV-1 or by 2a-2. | The view's groupings are not served by `s2:477-480`. |
| C10 | **The decommission tombstone** (`s2:506-561`) is reusable by another typed source through its named owner, under the same per-agent lock as `delete_agent`, with the tombstone committed before or with every store's erase in the cascade (`s2:509-513`). | `crypto_config` ingest consults it rather than keeping a second tombstone table, and the race closes for both stores. |
| C11 | **The non-rendering gate (C2) surfaces an in-query `authorize_list_read` fault as degraded**, not `DenyAll`. Today such a fault renders as a 403 (`server/core/src/authz_gates.cpp:342-357`, the §2c weakening). | A per-kind partial result would otherwise show a store fault as a permission decision. Until then, it is a disclosed residual ([Per-kind gating](#per-kind-gating)). |
| C12 | **Slice 2's store-grain prune predicate** compares `observed_at` with `now()` (`s2:635-636`), so an offline device's unreadable store would be pruned on age alone, against D12's "age alone never prunes". This design uses `status_at - observed_at > 30 days`, the form slice 2 already uses for locations (`s2:641`). | One prune rule, consistent with D12, for both stores. |

## Deferred edits to `crypto-asset-design.md`

These edits are made once #6125 and #6159 have merged. Until then, this document governs wherever
the two differ.

- **Pointer.** Add a pointer to this file from "Later in Phase 1: crypto configuration"
  (`docs/crypto-asset-design.md:143-156`).
- **Placement.** That section's heading and its "Later in Phase 1" placement change, because
  `crypto_config` is pulled forward.
- **Row format.** Its row format, `source|key|value|state` with `state` in `value`, `absent`,
  `unreadable` or `unknown` (`:147`), is replaced by this design's records:
  - `source|`, `part|`, `setting|` and `alg|`;
  - the closed source-status set;
  - the `setting` states.
- **Securable.** Its open decision 2 (the securable, `:325`) is answered for `crypto_config` by this
  design's open decision 3.

## Tests and chaos

**Proposed.** Beyond the routine tests every PR owes:
- REST/MCP parity;
- A4 bodies;
- audit rows;
- the floor under RBAC off;
- confinement asserting the exact visible set.

| Case | Must prove |
|---|---|
| **Unknown identifiers** | A certificate with an unregistered key OID, and a configured SCHANNEL name not in any table, each appear as a row with the raw identifier and `name: null`. Neither is dropped. Neither sorts by a hidden rule. The CBOM component's `name` is the raw identifier. |
| **Alias non-collapse** | `ssh-rsa` and `rsa-sha2-256` are two rows (AV-4). OpenSSL `P-256`, SCHANNEL `NistP256` and OID `1.2.840.10045.3.1.7` are three rows. An OpenSSL TLS 1.3 suite name and the same text in another vocabulary are two rows. RSASSA-PSS as a key and as a signature are two rows, by `role`. |
| **Case rule** | SCHANNEL `RC4 128/128` and `rc4 128/128` on two devices form one row, and the drill shows both raw spellings. Two `ssh` names differing only in case form two rows. |
| **Parameter-set key** | RSA 2048 and RSA 3072 are two rows, and RSA of null size is a third. `ec_params` `named`, `explicit` and `unknown` are three rows. PSS with SHA-256 and with SHA-384 are two rows, and two CBOM components with distinct parameter properties. The `ec_order_bits` filter matches explicit-curve rows only. The drill addresses a null-size row with the literal `null`. |
| **Disabled is not present** | A device with `RC4 128/128` `Enabled = 0` adds 1 to `disabled` and 0 to `enabled`. A Java `RC4` constraint adds only to `constraint`, and a `legacyAlgorithms` entry only to `deprioritised`, which is never shown in the restriction section. No response field sums polarities or source classes. A device with no subkey for a cipher adds to `defaults_apply_devices` and to no polarity. A `REG_SZ` `Enabled` produces `unknown` / `wrong_type` and no row. The CBOM has no component for a disabled-only row. |
| **No expansion** | A host with crypto-policies `DEFAULT` and no readable back-end produces the policy-name `setting` and no algorithm rows. `CipherString = HIGH:!aNULL` produces one raw `setting`. `Groups = DEFAULT:-X25519` and `Groups = ?X25519MLKEM768:X25519` each produce one raw `setting` and no rows. `include jdk.disabled.namedCurves` stays a raw entry, while `jdk.disabled.namedCurves`' own tokens are `constraint` rows attributed to that key. `TLSv1` in `jdk.tls.disabledAlgorithms` produces a `setting`, never a view row. A Java `keySize < 2048` entry appears on `/config` only. |
| **Includes and replace** | A stock RHEL `openssl.cnf` with its back-end `.include` reads `ok`, and the include is `covered_by:crypto_policies`. An `openssl.cnf` with another `.include` reads `constrained`, and its directives from the read part still replace earlier rows: a suite removed from `Ciphersuites` disappears on the next report. A JDK 23 top-level `include <file>` is recorded and not followed. |
| **Partial permission** (AV-2) | A caller with `CertificateInventory:Read` only, asking for both kinds: `configured` is in `kinds_omitted` with `permission_denied` and its permission. A configured-only row is absent. A row with both kinds of evidence shows only the certificate block. Then the mirror case. Then neither: a 403 listing both. A fixture algorithm present only in configured data appears nowhere in the certificate-only response, its CBOM or its audit detail. |
| **Denial reasons** | A service-scoped session gets `service_scope` and no `permission`. A non-admin under RBAC off on the floored certificate kind gets `admin_required` and no `permission`. |
| **Ordering cannot reveal an omitted kind** | `order_by=certificate.devices` from a caller without the certificate kind returns a 400 on REST and MCP. A count `order_by` with a `cursor` returns a 400. A count-ordered response with more rows sets `order_by_first_page`. |
| **Unknown kind** | `kind=observed` and `kind=bogus` each return a 400. In AV-1, `kind=configured` returns a 400. |
| **Separate confinement** (AV-2) | A caller confined to group A for one securable and to group B for the other gets per-kind `devices_included` matching each group, and no union count. |
| **Degraded is not denied** | Scoped to the faults the gate can tell apart today: an RBAC store or management-group store that is null or not open, a store read failure in the kind's own query, and a statement timeout on one kind while the other is healthy. Each gives a whole-response 503 with `retry_after_ms`, never a 200 with that kind in `kinds_omitted`, and never a 403. A fault in the middle of `authorize_list_read`'s query is **out of scope** until C11 lands: it is the disclosed residual, and a separate test pins today's behaviour (a denial) so the C11 change flips it deliberately. |
| **TLS 1.3 nulls** | No IANA entry (once the snapshot exists) for a TLS 1.3 suite, a GOST TLS 1.3 suite, an RFC 9150 integrity-only suite or an SCSV has a `kx_auth_segment`. No entry has a key-exchange, authentication, bulk-cipher or MAC field, and none has a field named after "Recommended". |
| **Identifier table version against cursors** | Page 1 is read at version N. Page 2, sent to a server at N+1 with the old cursor, is refused with the restart message on REST and MCP. A raw-identifier filter returns the same rows at N and N+1; only names change. |
| **Coverage and the one device set** | A Windows device with SCHANNEL read and Java `unsupported` is in `schannel`'s `devices_considered` and outside `java_security`'s, and counts in `devices_no_source` there. For every configured block, `devices_with_entry` + `unparsed_setting_devices` + `defaults_apply_devices` = `devices_considered`, every polarity count is at most `devices_with_entry`, and `from_kept_rows` is at most `devices_considered`. Per source class, the six status counts sum to `devices_reporting`. A `wrong_type`, capped, raw or `covered_by` setting counts in `unparsed_setting_devices`, never in `defaults_apply_devices`. A device whose part turns `unreadable` stays in D with its kept state and moves into `from_kept_rows`. A key re-read in a `constrained` part is not counted as kept. `unattributed_certificates` counts certificates with a null key OID. |
| **Key-grain replace** | In a `constrained` part, a reported key's rows are replaced, so an entry removed from `jdk.tls.disabledAlgorithms` disappears, while an unreported key's rows stay and count as kept. An `ok` part removes a key that is no longer present. |
| **Capped key merges** | A `Ciphers` enumeration of 300 subkeys and a list of 600 entries are each reported `capped`. Rows stored earlier beyond the cap survive, and reported rows are upserted. An identifier the capped report does not name counts the device in `unparsed_setting_devices`, never `defaults_apply_devices`. |
| **One polarity per key** | Within one source class, no key ever yields two polarities for one identifier. A device with `RC4` restricted in one JVM home's `jdk.tls.disabledAlgorithms` and listed in another home's `jdk.tls.legacyAlgorithms` counts once under `constraint` and once under `deprioritised`, and once in `devices_with_entry`. |
| **`status_at` always advances** | Each report advances every part's `status_at`, including `unreadable` and `not_observed` parts. A part that stays unreadable across 31 days of reports is pruned; an offline device's part is not. |
| **Status-only blob never wipes** | A device with stored rows sends a status-only blob (over the byte cap, and once with every source unreadable). Every part arrives `constrained` or `unreadable`, and every stored row survives. |
| **`covered_by` cannot hide an unread file** | A RHEL `openssl.cnf` include of the back-end is `covered_by` only when the back-end part is `ok` in the same report. With the back-end unreadable, the include makes `openssl_cnf` `constrained`, `include_not_followed`. A directory include, and an include whose normalised path differs by one character, are never covered. |
| **Decommission race** | A report ingested concurrently with `delete_agent` either completes before the tombstone (and is then erased) or sees the tombstone and writes nothing. No interleaving leaves rows. A failed tombstone read nacks. |
| **Deterministic refusals** | An unknown major version and a decommissioned agent are acknowledged (`refused`, `decommissioned`), not answered `need_full`. |
| **Hostile config files** | Each input ends `constrained` or `unreadable` with its reason token: a 50 MiB `java.security`; a value with 100,000 entries; NUL bytes and invalid UTF-8; CRLF and backslash continuations, including one at end of file; a property key repeated 10,000 times; pipes and backslashes in values; an `openssl.cnf` whose `.include` names itself and `/etc/shadow`; `$ENV::HOME` in a directive; a `java.security` that is a FIFO or a directory; a distro-JDK link into `/etc/java-*` (accepted) and one into `/tmp` (`link_outside_roots`); a back-end link outside its target root; a `REG_MULTI_SZ` with no terminator, and one with 10,000 records; a registry string with an interior NUL; a key name with control characters; a value over 1,024 bytes (`value_cap`, never cut). For every input: the agent finishes within the deadline (or the residual is logged), no include is followed, no file outside the roots is opened (an instrumented open sees none), and the dashboard renders with no CSP `pageerror`. |
| **Caps on both sides** | A blob over 2.5 MiB becomes status-only, `byte_cap`. A record over a server cap is dropped, and its source is stored `constrained`, `server_cap`, never truncated. |
| **Store down at ingest** | The report is answered `need_full`, no hash is stored, and the next report succeeds. The alert's promtool case fires. |
| **Decommissioned agent** | A report from a tombstoned agent writes no `crypto_config` row on either ingest path. |
| **Machine-scope roots** | The compiled root lists contain no path under `/home`, `/Users`, `C:\Users` or a profile. Path-valued fields from a fixture containing `/home/<name>/` come out redacted. |
| **Configured is not effective** | Every `configured` block and every `/config` response carries the statement, and a test greps the OpenAPI and MCP descriptions for it. |
| **Computed at read** | A schema lint over the view's PRs finds no new table, materialised view or cache for algorithm rows. Two reads straddling an ingest return different counts. |
| **D10 lint** | A fixture schema fails with each of: `bits_of_security`, `bitsOfSecurity`, `securityLevel`, `quantumSafe`, `nistQuantumSecurityLevel`, `recommended`, `certificationLevel`. A schema whose only match is the keyword `deprecated: true` passes. The three D13 allow-list entries pass only on their D13 surfaces. |
| **Metric labels** | No `yuzu_*crypto*` series has a label named `algorithm`, `identifier`, `cipher` or `vocabulary`. |

**Chaos (Proposed), run before CC-1 and AV-2 merge:**

| ID | Scenario | Must prove |
|---|---|---|
| CC-CH-1 | On a Linux host, `/etc/crypto-policies` becomes unreadable to the agent account mid-run, and `openssl.cnf` is replaced between two reports. | `crypto_policies` reads `unreadable` and keeps its rows and `observed_at`. `openssl_cnf` is replaced. The blob is never empty. |
| CC-CH-2 | The agent is killed mid-read, on every leg. | No partial blob is sent. The next run's report is complete or `constrained`. |
| CC-CH-3 | A JVM home sits on an NFS mount whose server is down. | The home is skipped as a network mount, and the action finishes inside its deadline. |
| CC-CH-4 | The RBAC store becomes unavailable (null or not open) during a two-kind view read (AV-2). | A 503 with a retry hint. Never a partial 200, never a 403. A mid-query fault is the C11 residual and is not asserted here. |
| CC-CH-5 | The `crypto_config` store is down for one daily cycle across the fleet. | No source is pinned empty. Re-sends spread over the jittered window, and the ingest alert fires. |

## Open owner decisions

1. **Is a compiled IANA registry snapshot identity data?** Or is it "external domain data" under
   ADR-1005:47?
   - **Architect's recommendation: naming data**, like the OID arc registry. It names codepoints and
     grades nothing, once the Recommended column is excluded.
   - If the owner rules otherwise, the IANA codepoint vocabularies are dropped. Nothing scheduled in
     [Phasing](#phasing) changes.
2. **Routing of the D2 amendment.**
   - **Architect's recommendation:** an "Update" to ADR-0070 after #6125 merges and before 2a-4, not
     a change ridden on #6125.
3. **The `crypto_config` securable.**
   - **Recommendation: `Security:Read`, with no floor**, as argued under [Securable](#securable). It
     matches the posture plugins, and it refuses service tokens in both RBAC states on the view
     and `/config` (live-dispatch results stay readable under `Response:Read`). Live dispatch
     is allowed, and its ResponseStore exposure is accepted as the posture plugins accept it.
   - **The alternative: `Inventory:Read`.** It widens the posture map under RBAC on to
     PlatformEngineer, Operator and ITServiceOwner, and it admits confined service tokens.
   - **Under either,** the owner accepts that with RBAC off every signed-in user can read the
     posture map, and records that in the risk register.
   - **To make the map admin-only:** a new floored `CryptoConfig:Read`, with sync-only collection.
4. **Who collects `sshd_config` algorithm lists.**
   - **Recommendation:** leave this to the slice-3 ADR, so that SSH placement is decided once.
5. **The `crypto_config` kill-switch default.**
   - **Recommendation: default-on**, matching the read-only posture plugins on `ExecuteGate::None`.
   - The alternative is `seed_kill_switch_default_off`, the Forensics-class precedent.
6. **The capacity fallback, only if the AV-1 or AV-2 capacity gate fails.**
   - **No recommendation in advance.** A rollup or cache would materialise the view, which brings
     cell (g) into play (P13).
   - Deciding it needs the recorded plans.

## How this could ship wrong

1. **A verdict creeps into the table.** Someone adds `primitive`, a `quantum_safe` flag, a "legacy"
   marker or the IANA Recommended column "for convenience".
   - Guard: P3, the restated condition 1, the D10 tokens, and review as a placement finding (D10).
2. **Kinds are merged.** A row-level `devices` total, a union of device sets, or a CBOM component
   whose count adds certificate and configured evidence. That joins differently confined sets and
   leaks across securables.
   - Guard: P10, the per-kind blocks, the separate-confinement test.
3. **An omitted kind leaks.** It can leak through its rows (a configured-only row shown to a
   certificate-only caller with zero counts) or through ordering (`order_by` on that kind's
   counts).
   - Guard: P9 by construction, the 400 on an omitted-kind `order_by`, and the tests.
4. **A degraded read looks like a permission decision.** An RBAC-store outage turns into
   `kinds_omitted: permission_denied`, and an engine consumer takes the partial answer as complete.
   - Guard: the tri-state gate, the whole-response 503, and CC-CH-4.
5. **Disabled read as present.** A "devices with RC4" tile counts `disabled` rows. A consumer reads a
   constraint or `deprioritised` entry as enabled. A CBOM lists a refused algorithm as an asset.
   - Guard: polarity in the key, no cross-polarity sum, the separate dashboard section, no CBOM
     component for refused-only rows, and the tests.
6. **Defaults expanded.** A helper turns `DEFAULT`, `@SECLEVEL=2`, an operator-bearing `Groups` value,
   an unset SCHANNEL key or the CNG local defaults into a list "so the view is complete".
   - Guard: P15, the raw-setting rule, the CNG local-key exclusion, and the no-expansion test.
7. **Configured read as effective.** A reader takes "TLS 1.0 disabled in SCHANNEL" to mean "this host
   cannot speak TLS 1.0", or takes a container image's `/etc` as the host's.
   - Guard: the statement on every block, tile and description, the container flag, the
     [Assurance impact](#assurance-impact) table, and `observed` kept separate.
8. **A partly read source freezes stale rows.** An unfollowed include keeps a source `constrained`
   forever, and rows from its fully read part are never replaced.
   - Guard: per-part replacement, the covered-by rule for the RHEL include, the part-grain prune,
     and the includes test.
9. **Aliases collapsed, or case splits counts.** `ssh-rsa` is merged with `rsa-sha2-256`, or
   `prime256v1` with `secp256r1` and `NistP256`; or SCHANNEL names that differ only in case split
   one count in two.
   - Guard: P17, `role` in the key, the per-vocabulary comparison rule, and the alias and case tests.
10. **A failed collection reads as "nothing configured".** A Windows leg that cannot open `SCHANNEL`
    sends no rows, and the view shows no SCHANNEL evidence for that device, as if none were
    configured.
    - Guard: per-part status, the one device set with `devices_considered` and per-source coverage,
      the status-only blob,
      and `unreadable` never `absent`.
11. **A server cap truncates silently.** The seam reuses the generic parser and cuts a long value.
    - Guard: this source's own seam, equal caps on both sides, `server_cap`, and the test.
12. **Inference from libraries.** "OpenSSL 3 installed" turned into algorithm rows.
    - Guard: owner direction. Slice-1 data is never an evidence kind.
13. **Names become contract.** A client filters by display name, or a schema puts names in an
    `enum`, and a table fix breaks it.
    - Guard: P19, no `name` filter, no enum.
14. **A table edit silently changes a walk, or counts shift under a cursor.**
    - Guard: `identifier_table_version` in the cursor fingerprint, row-key paging, first-page-only
      count ordering, and the tests.
15. **The view is materialised to make it fast.** A cache table becomes cross-run derived state, and
    cell (g) applies (`0070:784`).
    - Guard: P13, the capacity gate deciding before AV-1, and open decision 6.
16. **An algorithm becomes a metric label.**
    - Guard: P12 and the label test.
17. **A decommissioned agent repopulates.**
    - Guard: the tombstone check at ingest (C10).
18. **A partial or fallback report wipes good rows.** A status-only blob is read as "every part
    empty", or an unreported key in a capped part is treated as removed.
    - Guard: a status-only blob carries only `constrained` or `unreadable` parts and no keys,
      key-grain replacement for `constrained` parts, and the tests.
19. **`covered_by` hides an unread file.** An include is marked covered while the covering file was
    not read in that report.
    - Guard: the three conditions on `covered_by`, and the test.
20. **A count exceeds its denominator.** Kept rows are counted in a polarity but left out of the
    denominator, or an unparsed setting is counted as a default.
    - Guard: the one device set per row and source class, and the sum test.

The three most likely:
- **10** (a failed read reads as clean), Domain 41's standing first risk
  (`docs/crypto-asset-design.md:336-337`);
- **5** (disabled read as present);
- **2** (kinds merged into one total that a planner treats as one number).
