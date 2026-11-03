#pragma once

/**
 * process_enum.hpp -- Cross-platform process enumeration for Yuzu agent
 *
 * Returns a vector of ProcessInfo with PID, PPID, name, command line, and user
 * for every running process. Used by the Echo plugin for snapshot-based diff
 * detection and available to any other component that needs process data.
 *
 * Platform implementations:
 *   Windows — CreateToolhelp32Snapshot + OpenProcess/GetTokenInformation
 *   Linux   — /proc/[pid]/{status,cmdline} + getpwuid_r
 *   macOS   — sysctl(KERN_PROC_ALL) + proc_pidpath + getpwuid_r
 *
 * Thread-safe: no shared mutable state.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <istream>
#include <string>
#include <vector>

namespace yuzu::agent {

struct ProcessInfo {
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string cmdline;
    std::string user;
    // Canonical on-disk executable path (P-004, cursor-model seam
    // agents/plugins/echo/src/echo_cursor.hpp) -- used to correlate a running
    // process to an `exec_from_removable` event by checking whether this path
    // resolves under a removable volume's mount point. Empty when the path
    // could not be resolved (permission denied, process already exited,
    // platform API failure) -- NEVER guessed or derived from `cmdline` (argv[0]
    // is attacker/user controlled and frequently relative or a bare basename).
    // Linux: readlink("/proc/<pid>/exe") (empty on EACCES). Windows:
    // QueryFullProcessImageNameW via PROCESS_QUERY_LIMITED_INFORMATION. macOS:
    // the proc_pidpath result already fetched for `cmdline`.
    std::string exec_path;
};

/**
 * Enumerate all running processes on the current host.
 * Returns an empty vector on unsupported platforms or on failure.
 */
YUZU_EXPORT std::vector<ProcessInfo> enumerate_processes();

namespace detail {

/// Read every remaining byte of `in` (a /proc/<pid>/cmdline stream). Never throws: when the
/// process exits mid-read libstdc++'s filebuf::underflow throws, and an istreambuf_iterator
/// (unlike istream::read / operator<<) has no sentry to catch it, so the exception used to
/// unwind through the snapshot pump and terminate the agent. On a throw the bytes read before
/// it are returned. Exposed for the unit test.
YUZU_EXPORT std::string read_proc_bytes(std::istream& in) noexcept;

#if defined(__linux__) || defined(__APPLE__)
/// Parse a /proc/<pid>/status stream into `pi`: Name, PPid, and the real Uid resolved to a user
/// name. The whole stream is read (it is no longer cut after the three fields, so later fields
/// are reachable); the first occurrence of each field wins. Never throws: a malformed PPid or
/// Uid leaves that field at its default, and a stream that fails mid-read keeps what parsed.
/// Exposed for the unit test.
YUZU_EXPORT void parse_proc_status(std::istream& in, ProcessInfo& pi) noexcept;
#endif // __linux__ || __APPLE__

} // namespace detail

} // namespace yuzu::agent
