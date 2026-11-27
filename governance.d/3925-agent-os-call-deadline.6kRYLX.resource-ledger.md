# Resource Ledger: agent OS call deadline (#3925)

Range: `8404efecdc..45af69fb44` (branch `feat/agent-call-deadline`)

Recorded by: Doomgoose

## Resources
| Resource | Owner | Acquire | Release | Transfer / failure cleanup |
|---|---|---|---|---|
| 9 production SingleFlightSlot (g_wts, g_users, g_members, g_share, g_smb, g_join, g_registry, g_vss, g_adapter) + g_snapshot_slot | process; anonymous-namespace reference | `*new` at static init | never, by design (an abandoned worker may release late) | not transferred |
| detached worker thread per bounded call | yuzu::shared::bounded_call_ex (OutstandingCallGuard, ceiling 64/image) | std::thread().detach() in agent-core | thread return | lambda owns fn by move, shared_ptr<State>; setup failure -> Rejected and caller releases slot |
| slot admission | worker's Releaser RAII | try_acquire/acquire_until | Releaser dtor; caller on Rejected and zero-budget paths | generation guards stale mark_abandoned |
| NetAPI buffers (NetUserEnum, NetLocalGroupGetMembers, NetShareEnum, NetSessionEnum, NetGetJoinInformation) | unique_ptr<_, NetFree/NetApiFree> per call | API out-param | scope exit, NetApiBufferFree | data copied out; nothing crosses the thread |
| WTS buffers (session list, per-session query) | unique_ptr<_, WtsFree> | WTSEnumerateSessionsW / WTSQuerySessionInformationW | WTSFreeMemory at scope exit | copied out |
| COM apartment | ComInit on worker stack | VSS read_raw | scope exit, after every Release | worker-thread only |
| IVssBackupComponents, IVssEnumObject | ComPtr | CreateVssBackupComponents / Query | scope exit | none |
| VSS_SNAPSHOT_PROP strings | optional<ScopedSnapshotProp> | IVssEnumObject::Next | VssFreeSnapshotProperties per turn | non-snapshot union arm intentionally not freed (moved unchanged from the plugin) |
| HKEY base/child | yuzu::win::RegKey in HklmOps | RegOpenKeyExW | dtor | `current` is borrowed |
| adapter table buffer | std::vector | GetAdaptersAddresses | scope exit | flatten() copies; no pointer escapes |
| reader std::function (test seams) | copied into worker | call | worker end | by-value |
| subprocesses (users Linux/macOS) | existing run_bounded_subprocess | unchanged | unchanged | now under a shared 30 s budget |
| removed | plugin-side NetApiBuf (shares), NetApiBufGuard (echo), plugin WTS/Net frees (users, echo, device_identity), plugin VSS owners | | | |

NOTE: the earlier shares Resource Ledger (`docs/resource-ledgers/shares-windows-leg.md`, commit ae663d8696) is superseded in two lines by this change: the plugin-side NetApiBuf buffer now lives in agent-core (win_share_enum.cpp) and the "no deadline on NetShareEnum" statement no longer holds.

Casts: reinterpret_cast on LPBYTE* out-params, Net* buffers to typed arrays, GetAdaptersAddresses buffer to IP_ADAPTER_ADDRESSES*, sockaddr by family.
