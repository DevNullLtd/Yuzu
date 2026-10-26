# app_control

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Read-only WDAC and AppLocker application-control policy posture as configured (Windows-only) |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (windows.app_control.wdac_policy, windows.app_control.applocker_policy) |
| **Platforms** | Windows ✅ · macOS ⛔ unsupported · Linux ⛔ unsupported |
| **Actions** | `applocker_policy` (definition `windows.app_control.applocker_policy`) · `wdac_policy` (definition `windows.app_control.wdac_policy`) |
| **Security** | securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

The two actions report how Windows application control is *configured* on the device. Both are read-only; neither says what is blocked, nor whether a configured policy is being applied at this moment.

- `wdac_policy` enumerates every value under `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy` (bounded: 256 values, 4 KiB each) and gives one of them, `VerifiedAndReputablePolicyState`, a named state. It then lists the `*.cip` files in `%SystemRoot%\System32\CodeIntegrity\CiPolicies\Active` (file stem only, never contents, at most 64 files, more reports `row_cap`) and checks, by stat only, whether the legacy single-policy file `System32\CodeIntegrity\SiPolicy.p7b` exists.
- `applocker_policy` runs one bounded CIM query (15 second enumeration deadline) for `MSFT_ApplockerPolicy` in `root\StandardCimv2\Security\ApplicationControl`. When that gives no usable row, because the namespace or class is missing, the answer is empty, or the query fails, it walks `HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2` and reports one row per rule collection (`Appx`, `Dll`, `Exe`, `Msi`, `Script`) with its `EnforcementMode` and rule-subkey count.

The one naming trap is in the `state` column of `wdac_policy`. `VerifiedAndReputablePolicyState` is the **Smart App Control** setting, not the state of the listed `.cip` policies, and its values map as 0 `disabled`, 1 `enforced` (Smart App Control is on) and 2 `audit` (Smart App Control's evaluation mode, which observes without blocking; it is not WDAC audit mode). Only 0 was observed on hardware; 1 and 2 follow Microsoft's documentation and are untested. Any other value, and every other registry value under `CI\Policy`, reads `unmodelled`.

What it is not: no policy change of any kind, no PowerShell (`Get-AppLockerPolicy` is not used), no raw COM and no subprocess. It reports the state of an OS-native control and is not EDR-class telemetry.

### What you can decide with it

| Question | Where the answer is | What it does not tell you |
|---|---|---|
| Is Smart App Control off, evaluating or on? | `wdac_policy` row `wdac\|VerifiedAndReputablePolicyState\|<n>\|disabled`, `audit` or `enforced` | Anything about WDAC policies you or your organisation deployed |
| Does this device carry WDAC policy files? | `wdac_cip\|<stem>\|present` rows, or `wdac_cip\|none\|absent` | Whether a listed policy is enforced or audit-only, what it allows, or whether it is a Windows default or an organisation policy (the capture host listed eight GUID-named files, which the capture notes describe as Windows defaults) |
| Is AppLocker configured, and in what mode per collection? | `applocker_policy` rows: mode `audit` or `enforced` (SrpV2 registry only; `absent` for a collection that is not configured, `unmodelled` for any other value and for every row from the CIM class) and a rule count per collection | Whether the Application Identity service is running (rules apply only while it does), or a policy delivered another way such as MDM |
| Is WDAC enforcing on this device? | Not answerable | The plugin never reads the mode inside a policy file, so presence of a `.cip` file is the most it can say |

How to read the `wdac_policy` rows:

| Row | Meaning |
|---|---|
| `wdac\|VerifiedAndReputablePolicyState\|<n>\|<state>` | The Smart App Control state described above. |
| `wdac\|<name>\|<raw>\|unmodelled` | Any other value under `CI\Policy`, shown raw with no meaning assigned (the capture host had `EmodePolicyRequired`, `SkuPolicyRequired` and `SAC_PreviousState`). |
| `wdac\|policy_key\|-\|absent` | The `CI\Policy` key does not exist: nothing is configured there. |
| `wdac_cip\|<stem>\|present` | A `.cip` file exists in `CiPolicies\Active`. |
| `wdac_cip\|SiPolicy\|present` | The legacy single-format file exists. |
| `wdac_cip\|none\|absent` | Neither format is present under `System32`. A single-format policy held only on the EFI system partition is not visible, so this is not proof that no WDAC policy exists. |

A clean `OK` result means every read the plugin attempted was answered. It is the configured picture only. Linux and macOS agents return an `unsupported` row and exit code 1, so target Windows agents.

### Diagrams

`applocker_policy` is the plugin's one decision with real structure: which source is trusted, and when "nothing found" may be reported.

```mermaid
flowchart TD
  Q["CIM query: MSFT_ApplockerPolicy in the ApplicationControl namespace"] --> R{"Result"}
  R -- "at least one row maps" --> C["Rows from CIM, mode unmodelled; OK with provenance cim_msft_applockerpolicy, or CONSTRAINED if a row was unrecognised or the result hit the row cap (SrpV2 is not walked)"]
  R -- "namespace or class missing, no usable row, or a failure" --> S["Walk the SrpV2 registry key, one row per collection"]
  S --> T{"What did the walk and the CIM query record?"}
  T -- "rows, no failure" --> U["OK, provenance registry_srpv2"]
  T -- "no SrpV2 key, no failure anywhere" --> V["applocker none absent 0, OK"]
  T -- "any failure, including the CIM one" --> W["constrained row, status CONSTRAINED or PERMISSION_DENIED"]
```

Only two answers count as "the class is not there": `WBEM_E_INVALID_NAMESPACE` while connecting, and `WBEM_E_INVALID_CLASS` while querying or at the first row before any row came back. The same code at any other stage is a fault, and `WBEM_E_NOT_FOUND` is always a fault. A fault is recorded, the registry walk still runs, and the final status is non-OK, so a failed read can never produce the `none` row.

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `applocker_policy` | 🟡 constrained · rung 1 · wmi_bounded run_bounded_wmi_query root\\StandardCimv2\\Security\\ApplicationControl MSFT_ApplockerPolicy; registry walk of HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\<collection> when the class is absent, empty or failing | ⛔ unsupported | ⛔ unsupported |
| `wdac_policy` | ✅ supported · rung 1 · RegEnumValueW HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy + std::filesystem listing of %SystemRoot%\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip | ⛔ unsupported | ⛔ unsupported |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`applocker_policy` / Windows** — Rig-verified 2026-09-21 (Windows 11 Pro 10.0.26200, LocalSystem): the CIM namespace root\\StandardCimv2\\Security\\ApplicationControl does NOT exist on this host (WBEM_E_INVALID_NAMESPACE 0x8004100e), so the SrpV2 registry walk runs and, with no AppLocker policy configured, reports 'none'. The CIM property names (Collection/EnforcementMode/RuleCount) and the SrpV2 rule-collection layout are UNVERIFIED on a host with AppLocker configured, so CIM-sourced modes report unmodelled (the registry numbering is not assumed for them) and a policy delivered outside the SrpV2 key (for example by MDM) is not read. An enforced mode is the configured mode, not proof the rules apply (the Application Identity service is not read). The CIM namespace is caller-side allowlisted
- **`applocker_policy` / macOS** — Windows-only concept; macOS app-trust (Gatekeeper/SIP) is outside this plugin's scope
- **`applocker_policy` / Linux** — Windows-only concept; Linux fapolicyd is a separate, unimplemented leg of #282
- **`wdac_policy` / Windows** — Rig-verified 2026-09-21 (Windows 11 Pro 10.0.26200, LocalSystem): CI\\Policy holds EmodePolicyRequired, SkuPolicyRequired, VerifiedAndReputablePolicyState (0 reads 'disabled') and SAC_PreviousState (0xffffffff reads 'unmodelled'), and 8 default .cip policies are listed; only VerifiedAndReputablePolicyState=0 was observed, other values are mapped per documentation and unverified on hardware. An unmodelled value is reported 'unmodelled'; an unreadable key is constrained or permission_denied, never absent. The multiple-policy-format CiPolicies\\Active files and the legacy System32 SiPolicy.p7b are reported by presence only; a single-format policy held only on the EFI system partition is not visible
- **`wdac_policy` / macOS** — Windows-only concept; macOS app-trust (Gatekeeper/SIP) is outside this plugin's scope
- **`wdac_policy` / Linux** — Windows-only concept; Linux fapolicyd is a separate, unimplemented leg of #282
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None expected: registry reads (`KEY_READ`), a directory listing and a WMI SELECT; no privilege is enabled | Measured under LocalSystem on 2026-09-21 on a host with no AppLocker policy configured; least-privilege service-account behaviour is still unverified (see the source banner in `app_control_win.cpp`) | a `constrained\|<reason>` row plus result status `PERMISSION_DENIED` (registry `ERROR_ACCESS_DENIED`, CIM `WBEM_E_ACCESS_DENIED`) or `CONSTRAINED` (any other failure) |
| macOS | agent daemon (root LaunchDaemon today) | n/a — action returns the honest-unsupported sentinel unconditionally | not applicable (Windows-only concept) | n/a — no OS call is attempted |
| Linux | agent daemon, unprivileged | n/a — action returns the honest-unsupported sentinel unconditionally | not applicable (Windows-only concept) | n/a — no OS call is attempted |

No subprocesses and no network access. The CIM namespace is caller-side allowlisted to `root\StandardCimv2\Security\ApplicationControl` (`wmi_bounded.hpp` does no allowlisting of its own).

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
Neither action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows via `write_output()`, the first field naming the row kind (`row_kind`, the first declared column). `wdac_policy` writes `wdac|<name>|<raw>|<state>` per registry value and `wdac_cip|<policy_stem>|present` per active policy file (three fields: `state` stays empty); `applocker_policy` writes `applocker|<collection>|<mode>|<rules>` per rule collection. Placeholders: `wdac|policy_key|-|absent` (the CI\Policy key does not exist), `wdac_cip|none|absent` (no active `.cip` file and no `SiPolicy.p7b`), `applocker|none|absent|0` (neither the CIM class nor the SrpV2 key shows a policy; one delivered another way, such as MDM, is not read) — each a definitive absence reported by the OS for the source read; when the SrpV2 key exists every collection that reads cleanly gets a row, and one that is not configured reads `applocker|<collection>|absent|0`. Any failed step instead writes `constrained|<reason>` beside a non-OK result status (the reason lands in the second column); a failure is never rendered as an absent policy. Non-Windows legs write the single row `<action>|unsupported|windows_only_concept`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`windows.app_control.applocker_policy` — `row_kind|collection|mode|rules`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `applocker` `constrained` | Windows | `applocker` | Row family: `applocker` (one per rule collection, or the single `none` placeholder) or `constrained` (a failed step: the reason lands in `collection`, the rest are empty). |
| `collection` | string | `Appx` `Dll` `Exe` `Msi` `Script` `none` | Windows | `Exe` | AppLocker rule collection; `none` when neither the SrpV2 registry key nor the CIM class shows a policy (one delivered another way, for example by MDM, is not read); on a constrained row, the failure reason. |
| `mode` | string | `audit` `enforced` `unmodelled` `absent` | Windows | `enforced` | Enforcement mode of the collection; `absent` when the collection is not configured (no rule-collection subkey) or has no EnforcementMode value. Rows from the CIM class report `unmodelled`: the registry numbering is not assumed for that unverified class. |
| `rules` | int32 | - | Windows | `12` | Number of rules in the collection (rule subkeys under the SrpV2 walk); 0 when none is configured. |

**`windows.app_control.wdac_policy` — `row_kind|name|raw|state`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `wdac` `wdac_cip` `constrained` | Windows | `wdac` | Row family: `wdac` (a Control\CI\Policy value), `wdac_cip` (an active .cip policy file: the stem lands in `name`, `present` or `absent` in `raw`, and `state` is empty) or `constrained` (a failed step: the reason lands in `name`, the rest are empty). |
| `name` | string | - | Windows | `VerifiedAndReputablePolicyState` | Registry value name under Control\CI\Policy (or the policy file stem on a wdac_cip row, the failure reason on a constrained row). |
| `raw` | string | - | Windows | `1` | Raw value: a decimal for a DWORD, the text for a string value, opaque_<n>B for any other type; a dash on the key-absent row; `present` or `absent` on a wdac_cip row. |
| `state` | string | `disabled` `audit` `enforced` `unmodelled` `absent` | Windows | `enforced` | Named state of the value (`VerifiedAndReputablePolicyState` is the Smart App Control state, not the state of the listed `.cip` policies); empty on a wdac_cip or constrained row. |
<!-- END GENERATED -->

### Result status

`applocker_policy` walks the `SrpV2` registry key whenever no CIM row mapped (the class is absent, the result is empty, or the query failed or was refused); a CIM failure keeps the final status non-`OK`. Whether the CIM answer counts as `class_absent` is stage-aware: only `WBEM_E_INVALID_NAMESPACE` (`0x8004100e`) from `wmi_connect_failed_*`, or `WBEM_E_INVALID_CLASS` (`0x80041010`) from `wmi_query_failed_*` or from a `wmi_next_failed_*` that struck before any row was returned, is absence. The same HRESULT at any other stage (for example `wmi_next_failed_0x8004100e`, or `wmi_next_failed_0x80041010` after a row came back) is a fault and stays `CONSTRAINED`; `WBEM_E_NOT_FOUND` (`0x80041002`) is always a fault.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | FULL | `registry_ci_policy` | `wdac_policy`: every read succeeded |
| `OK` | FULL | `cim_msft_applockerpolicy`, `registry_srpv2` | `applocker_policy`: every read succeeded; the token names the source that produced the rows (the CIM class, or the `SrpV2` registry walk when the class was absent or empty) |
| `UNAVAILABLE` | PARTIAL | `windows_only_concept` | Linux/macOS: application control is a Windows-only concept here |
| `CONSTRAINED` | PARTIAL | `row_cap`, `value_too_large`, `cim_row_unrecognised`, `ci_policy_open_0x<hex>`, `ci_policy_enum_0x<hex>`, `srpv2_open_0x<hex>`, `srpv2_collection_open_0x<hex>`, `enforcement_mode_read_0x<hex>`, `srpv2_rule_count_0x<hex>`, `cip_stat_failed_<n>`, `cip_dir_failed_<n>`, `sipolicy_stat_failed_<n>`, `value_name_embedded_nul`, `system_directory_unresolved`, a `wmi_bounded` error token | a bounded read hit its cap, a value or CIM row could not be interpreted, or a registry / directory / CIM step failed with a non-access-denied error; the reasons are joined in one status string |
| `CONSTRAINED` | PARTIAL | `unhandled exception: <what>`, `unhandled exception of unknown type inside execute()` | an exception was caught inside `execute()`; the row written is `constrained\|internal_error` |
| `PERMISSION_DENIED` | PARTIAL | the comma-joined reason tokens, always including `permission_denied` | a registry, directory or CIM read was refused (`ERROR_ACCESS_DENIED` / `WBEM_E_ACCESS_DENIED`) |

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (`response_retention_days`, default 90 days), queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. Nothing here runs on a schedule.
- **Sensitivity.** Rows describe the device's application-control configuration (enforcement mode, rule counts, the file stem of each active policy). No username, hostname or rule content appears in any field; a `REG_SZ`/`REG_EXPAND_SZ` value under `CI\Policy` is reported verbatim (escaped, at most 4 KiB), so a string value could carry a path. The posture itself is security-relevant: it tells a reader which controls are not enforced.
- **Siblings:** `antivirus` (Defender and exclusion state, not application control), `windows_optional_features` (OS feature state), `registry` / `wmi` (general-purpose reads this plugin's narrow surface deliberately does not replace) — none join with this plugin's output.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("windows.app_control.wdac_policy")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-09-21 · LocalSystem (elevated) · leg-hash ea8979e16417

```
== action=wdac_policy
wdac|EmodePolicyRequired|0|unmodelled
wdac|SkuPolicyRequired|0|unmodelled
wdac|VerifiedAndReputablePolicyState|0|disabled
wdac|SAC_PreviousState|4294967295|unmodelled
wdac_cip|{0283AC0F-FFF1-49AE-ADA1-8A933130CAD6}|present
wdac_cip|{0939ED82-BFD5-4D32-B58E-D31D3C49715A}|present
wdac_cip|{1283AC0F-FFF1-49AE-ADA1-8A933130CAD6}|present
wdac_cip|{1678656C-05EF-481F-BC5B-EBD8C991502D}|present
wdac_cip|{1939ED82-BFD5-4D32-B58E-D31D3C49715A}|present
wdac_cip|{2678656C-05EF-481F-BC5B-EBD8C991502D}|present
wdac_cip|{60FD87F8-4593-44A0-91B0-2E0DA022F248}|present
wdac_cip|{784C4414-79F4-4C32-A6A5-F0FB42A51D0D}|present
[result_status] OK / FULL / registry_ci_policy

== action=applocker_policy
applocker|none|absent|0
[result_status] OK / FULL / registry_srpv2
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-21 · euid 501 · leg-hash ea8979e16417

```
== action=wdac_policy
wdac_policy|unsupported|windows_only_concept
[result_status] UNAVAILABLE / PARTIAL / windows_only_concept
[rc] 1

== action=applocker_policy
applocker_policy|unsupported|windows_only_concept
[result_status] UNAVAILABLE / PARTIAL / windows_only_concept
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-21 · euid 0 · leg-hash ea8979e16417

```
== action=wdac_policy
wdac_policy|unsupported|windows_only_concept
[result_status] UNAVAILABLE / PARTIAL / windows_only_concept
[rc] 1

== action=applocker_policy
applocker_policy|unsupported|windows_only_concept
[result_status] UNAVAILABLE / PARTIAL / windows_only_concept
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Read-only posture only; #282 stays open.** The plugin refs #282 and does not close it: the issue also asks for `add_rule`, `remove_rule` and `get_blocked_events` (`docs/enterprise-parity-plan.md` Phase 12.11) and a Linux fapolicyd leg, none of which exist. Rule changes would be Destructive-class actions in a separate change, and this plugin is not EDR-class telemetry (`docs/roadmap.md` Phase 18 excludes re-implementing EDR at the agent).
2. **Configuration is reported, not proof of enforcement.** An `enforced` AppLocker mode is what the policy is configured to do; the Application Identity service (AppIDSvc), which applies the rules, is not read, so a stopped or disabled service leaves rules unapplied under an `enforced` row. Only `VerifiedAndReputablePolicyState` (0 off, 1 on, 2 evaluation; only 0 was observed on hardware) and AppLocker `EnforcementMode` (0 audit, 1 enforce) are mapped; `.cip` files are listed by name only and their contents are never parsed.
3. **The CIM property names remain unverified on hardware.** The AppLocker provider namespace does not exist on the capture host (Windows 11 Pro 10.0.26200, no AppLocker policy configured), where the bounded WMI helper returned `wmi_connect_failed_0x8004100e`, so `applocker_policy` fell back to the `SrpV2` walk and read `applocker|none|absent|0` (`tests/unit/fixtures/wave8/app_control/windows/applocker_wmi_probe.txt`). `Collection`, `EnforcementMode` and `RuleCount` are assumed by `parse_cim_applocker_row` (a row lacking any of them is reported `cim_row_unrecognised`, never guessed), CIM-sourced rows report their mode `unmodelled`, and the `SrpV2` collection layout has never been read on an AppLocker-configured host. A policy delivered outside the `SrpV2` key, for example by MDM, is not read, so such a host also reads `applocker|none|absent|0`.
4. **Linux and macOS are placeholders by design.** The plugin loads everywhere, so an unscoped or mixed-fleet dispatch records exit code 1 (`UNAVAILABLE`) on a Linux or macOS agent; scope dispatches to Windows. Dispatching needs `Security:Read`, and the stored rows are read under `Response:Read` and the caller's group scope.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/app_control/src/app_control_legs.hpp` · `agents/plugins/app_control/src/app_control_parsers.hpp` · `agents/plugins/app_control/src/app_control_plugin.cpp` · `agents/plugins/app_control/src/app_control_win.cpp`
- Definitions: `content/definitions/app_control.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_app_control.hpp`
- Tests: `tests/unit/test_app_control_local_dispatcher.cpp` · `tests/unit/test_app_control_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
