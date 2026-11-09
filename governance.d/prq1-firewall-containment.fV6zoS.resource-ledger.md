# Resource Ledger — PRQ.1 firewall containment (agent side)

Run: `governance.d/prq1-firewall-containment.fV6zoS.jsonl`
Range: `origin/dev..HEAD` (branch `feat/firewall-quarantine`)

Rows are written at build time from the code; the `/governance` run that owns the findings
ledger above re-verifies each row at gate 3 and appends any finding it raises there.

## Summary

New C++ in `agents/plugins/firewall/`: a pure, OS-free core (`firewall_quarantine_parsers.hpp`:
value types, `std::function` seams, `std::shared_ptr` for a staged file's lifetime) and a shell
in `firewall_plugin.cpp` that acquires COM objects (Windows), a temporary file and subprocesses
(Linux), sockets (the verify probe) and plugin-KV entries. Every manual-lifetime resource below
has an RAII owner; the table lists it. No `new`/`delete`, no raw `malloc`, no detached thread.

## Table 1 — resources acquired by the shell (RAII owner named)

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| COM apartment | `ComInit` | `WinLeg::{preflight,apply,remove,read_status}` | function-local | One per entry point; `RPC_E_CHANGED_MODE` tolerated as in `win_com.hpp`. |
| `INetFwPolicy2`, `INetFwRules`, `INetFwRule`, `IEnumVARIANT`, `IUnknown` | `ComPtr<T>` | `WinLeg` entry points, `for_each_rule`, `add_rule` | function-local | `for_each_rule` holds one `INetFwRule` at a time and releases it before the next `Next()`. `VARIANT` from `IEnumVARIANT::Next` is `VariantClear`ed on every path. |
| `BSTR` out-params (`get_Name`, `get_Grouping`) | `OwnedBstr` (destructor `SysFreeString`) | `rule_name_of`, `rule_group_of` | function-local | The shared `BStr` only allocates, so a dedicated owner adopts the COM-returned BSTR. |
| `BSTR` in-params (rule name, group, ports, addresses) | `yuzu::shared::win::BStr` | `WinLeg::add_rule`, `remove_rules_by_name` | function-local | Allocation failure is checked (`E_OUTOFMEMORY`). |
| Winsock | `Wsa` guard (`WSAStartup`/`WSACleanup`) | `tcp_probe` (Windows) | function-local | Refcounted by Winsock; a failed startup reads as `timeout`, never as reachable. |
| Probe socket | `SocketGuard` (`icmp_probe.hpp`) | `tcp_sample` | function-local | Closed on every path including the connect timeout. |
| Staging directory | `<agent.data_dir>/firewall-staging` (POSIX) | `private_staging_dir()`, created and re-verified on every use | durable, empty between calls | `mkdir` 0700; trusted only when `lstat` shows a real directory owned by the agent with no group or other bits, else the apply is refused (`staging_unavailable`) and nothing is staged in the system temp directory. Shared by the nft and pf legs. |
| Ruleset file (nft ruleset text, pf anchor text) | `yuzu::TempFile` held by `std::shared_ptr<void>` in `StagedFile` | `temp_file_stage()` result, released after the privileged `nft -f` / `pfctl -f` returns | one apply call | Created by `yuzu_create_temp_file` (`mkstemps`: `O_CREAT|O_EXCL`, 0600) inside the staging directory; removed by the destructor even on exception. |
| Subprocesses | `run_bounded_subprocess` (argv, no shell, deadline per call) | `sudo_runner()` | per call | Sink IDs `firewall/do_quarantine_linux#1..#8` and `firewall/do_quarantine_macos#1..#10` in `docs/agent-spawn-sink-manifest.md`; the 60 s operation deadline bounds the sequence. |
| Mutation gate | `yuzu::quarantine::MutationGate::Guard` | `do_quarantine`, `do_release`, `do_quarantine_allow` | action body | FIFO ticket gate, 2 s budget; `quarantine_status` never takes it. Header reused from the retained plugin (`quarantine_serialization.hpp`). |
| Plugin-KV entries | `quarantine.state`, `win.prior_firewall_policy`, `win.disabled_rules` | `KvStateStore`, `WinLeg` | durable | `quarantine.state` is written (`applying`) before any mutation and deleted by a clean release or rollback; the two Windows images are write-once and deleted only after a clean release. The macOS enable token and boot time ride inside `quarantine.state` (`os.pf_token`, `os.boot_time`). |
| pf enable reference (`pfctl -E` token) | token string (digits only, 1-24) in `quarantine.state` | `PfLeg::apply` takes it and hands it to the driver's `persist` callback before `-f` or `-F states`; `PfLeg::remove` releases it (`-X`) | durable, until release or reboot | A failure before the anchor loads releases a reference taken in that call; a token that cannot be recorded is released at once; a dead token (pf disabled behind our back) is released best-effort before a fresh `-E`. **Residual:** a crash between `-E` and the record write leaks one reference until reboot, visible as `note\|pf_references=<n>` (tested). |
| pf anchor `com.apple/000.yuzu_quarantine` | kernel ruleset | `PfLeg::apply` (`-a -f`), `PfLeg::remove` (`-F rules`, `-F nat`) | until release | Emptied on every release and rollback; never `-F all` (global state); the main ruleset is never loaded. |
| Boot time (`kern.boottime`) | `struct timeval` on the stack, `sysctlbyname` | `kern_boot_time()` | function-local | Read in-process; no spawn, no fd. |
| Interval trigger | `register_trigger("firewall.quarantine.ttl")` | `settle_ttl`, `recover_containment_at_start` | until release | A failed registration keeps the quarantine and reports `ttl_trigger_unregistered` (PARTIAL); `release` unregisters it. |
| Netlink socket (status read) | `ScopedFd` | `open_nft_socket` (pre-existing) via `read_quarantine_table_netlink` | function-local | Fresh fd per dump; EPERM falls back to `sudo nft list table`. |

## Table 2 — value-type state (no manual lifetime management)

| Resource | Type | Owner | Notes |
|---|---|---|---|
| `AllowSet`, `QuarantineState`, `Outcome`, `FlatRule`, `WinRuleSpec`, `IptablesListing` | structs of `std::vector`/`std::string` | driver stack frames | Bounded: 64 exceptions, 8 resolvers, 32 control IPs, 20,000 disabled rule names, 256 KiB state record. |
| `Deadline` | clock + end time | driver stack frames | Injectable clock; cleanup and verification take a `fresh()` budget so a slow apply cannot starve the step that makes it safe. |

## Table 3 — threads and callbacks

No thread is created. `execute()` runs on the agent's pool; `init()` runs the boot-time recovery
synchronously (bounded by the 60 s deadline, never throws). The live test's watchdog thread is
joined in its destructor and exists only in the hidden real-host test.
