# Resource Ledger: 7710-ioc-hosts-exact-match (range b7a9905e6..fc4f05fb9 plus gate-fix round 1)

Run: `governance.d/7710-ioc-hosts-exact-match.9GpB4G.jsonl`

Every owning boundary the diff adds or changes in C++: `agents/plugins/ioc/src/ioc_plugin.cpp` (`check_domains`, POSIX leg) and the new pure header `agents/plugins/ioc/src/ioc_parsers.hpp`.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | read-only stream on `/etc/hosts` in `check_domains` (ioc_plugin.cpp, non-Windows leg) | `std::ifstream` local to a nested block (RAII) | once per `check_domains` call, before the domain loop | end of the nested block, before any match runs | none | a missing or unreadable file leaves the stream in a failed state, `std::getline` returns false at once, no lines are collected and every domain reports "Not found in /etc/hosts (DNS cache not available)" (unchanged from base); the destructor closes on every path |
| R2 | `std::vector<std::string> host_lines` in `check_domains` | value-owned local of the function | filled from R1, one element per line | end of `check_domains` | none; lent to `hosts_contains_domain` as `std::span<const std::string>` for the duration of each synchronous call | an allocation failure throws and unwinds the function; nothing else is held |
| R3 | `hosts_contains_domain` and `detail::strip_one_trailing_dot` (ioc_parsers.hpp) | none: pure functions over `std::string_view` / `std::span` views of caller-owned lines | n/a | n/a | none; no view is stored or returned | n/a (no allocation, no I/O) |

Notes:

- No new fd beyond R1, no handle, thread, subprocess, temp file or callback. No manual cleanup in the new C++.
- The Windows leg (`check_dns_cache`) is unchanged; R1 and R2 are compiled out there (`#ifndef _WIN32`).
