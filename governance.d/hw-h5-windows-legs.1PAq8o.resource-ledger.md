# Resource Ledger: H.5 Windows legs of the hardware plugin (range d3f3d5686..HEAD)

Companion to the findings fragment of the same stem. Written at Gate 1 and updated for the fix commits.
Fix commits since Gate 1 added no owning resource: they added pure formatting/mapping functions, an
`execute()` try/catch (no resource), a `std::string*` error out-parameter on `wmi_query` (borrowed for the
call, written once), and `report_wmi_failure` (borrows `CommandContext&` for the call). No fd, HANDLE,
SOCKET, FILE*, sqlite3*, OpenSSL/BCrypt object, thread, callback context, subprocess or temp path was added.
The one `reinterpret_cast<LPBYTE>(wchar_t*)` (registry value buffer) is the standard Win32 byte-buffer
idiom: `wchar_t` is 2-aligned, byte-pointer access cannot violate aliasing, the buffer outlives the call.

## Resource Ledger (C++)
| resource | owner type | acquire | release | transfer | failure cleanup |
|---|---|---|---|---|---|
| HKEY (MachineGuid parent key) | yuzu::win::RegKey (agents/shared/win_reg_handle.hpp, move-only, closes in dtor) | RegOpenKeyExW into a local `HKEY raw` (hardware_estate_win.cpp read_machine_guid) then immediately `RegKey key{raw}` | RegKey dtor -> RegCloseKey | none (function-local) | open failure returns before wrap (raw==nullptr, nothing to close); no early return between open success and RegKey construction |
| registry value buffer | std::wstring | sized from the first RegQueryValueExW | RAII | none | error paths return before use |
| RSMB table buffer | std::vector<uint8_t> in win_rsmb.hpp RsmbRead (moved out on success) | GetSystemFirmwareTable fill | RAII | moved into caller's RsmbRead | oversize/size-race/call-failed return empty bytes + typed error |
| WMI enumeration (COM, IEnumWbemClassObject etc.) | wmi::run_bounded_wmi_query (agents/shared/wmi_bounded.hpp, UNCHANGED) returns a value-type result | inside the helper | inside the helper | none | helper-owned |
| SHA-256 / HMAC state | stack objects (Sha256), no heap | n/a | n/a | n/a | n/a |
| raw MachineGuid string | std::string inside MachineIdRead, function lifetime | read | dtor (NOT zeroised; low sensitivity, see machine_id_hash.hpp banner) | passed by const-ref to machine_id_report | n/a |
| threads, callbacks, subprocesses, temp paths, sqlite/OpenSSL/BCrypt objects, FILE*, fds, SOCKETs, mapped libs | NONE added | | | | |
| CommandContext& | borrowed for the call only (emit_report); never stored | | | | |
