# Resource Ledger: 7530-firewall-protective-set (range origin/dev..pm/7530)

Run: `governance.d/7530-firewall-protective-set.HSuLlL.jsonl`

The C++ in this range adds no owning boundary: `common/include/yuzu/protective_actions.hpp` adds a pure predicate over `std::string_view`; `agents/plugins/firewall/src/firewall_quarantine_parsers.hpp` adds `std::vector<std::string> dropping` to `IptablesListing` (a value type: owner is the struct, filled by `std::erase`/`emplace_back` over owned strings copied from the `-S` text, released with the struct) and a stricter boolean in `IptablesLeg::read_status`; the server and test changes are description strings, comments and Catch2 cases. No fd, HANDLE, socket, `FILE*`, sqlite or OpenSSL object, thread, callback context, subprocess, mapped library or temp path is added or changed in C++.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `IptablesListing::dropping` (`std::vector<std::string>`) | the `IptablesListing` value | `parse_iptables_listing` appends an owned copy of the chain name per terminal DROP line, after erasing any earlier claim for that chain | struct destructor | returned by value | none needed: no early-return cleanup, allocation failure unwinds the local |

Not C++ (recorded for completeness): `scripts/test/instructions_firewall_containment.py` runs `subprocess.run` with an argv list and a timeout (no shell), opens HTTP connections through `urllib` with an in-memory cookie jar, and installs SIGINT/SIGTERM/SIGHUP handlers inside a context manager that restores the previous handlers on every exit path; its tests patch time and the dispatch seam and open no socket or file.
