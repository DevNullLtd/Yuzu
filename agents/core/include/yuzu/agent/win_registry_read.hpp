#pragma once

/**
 * win_registry_read.hpp -- bounded, capped read of values under HKEY_LOCAL_MACHINE.
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * A registry call has no deadline and can stall behind a filter driver or a hung hive. Bounding
 * the wait needs a detached worker, whose code must not live in a plugin the agent can unload (see
 * bounded_single_flight.hpp). Plugins call the exported functions only.
 *
 * WHAT IT MAY BE ASKED
 * --------------------
 * This is a GENERIC read-only reader: the root is always HKEY_LOCAL_MACHINE and the access
 * KEY_READ. It takes any non-empty subkey and any value names and checks them against no list of
 * keys; it gives a plugin nothing the plugin cannot already do with the Reg*W calls. The policy is
 * therefore the CALLER's: the subkey and value names are compile-time constants in the calling
 * plugin, never operator input, parameter text or data read from the host. A consumer that needs a
 * host-derived path brings its own validation and review.
 *
 * Residual: children are enumerated by index, so a key that is changing during the read can have a
 * child skipped or repeated.
 *
 * One read is in flight process-wide. A second caller waits for a healthy read inside its own
 * deadline; after a deadline hit, callers are answered Abandoned until the blocked worker returns.
 * Every other field of the result is meaningful only when status == Completed.
 */

#include <yuzu/agent/bounded_status.hpp>
#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace yuzu::agent::win {

/// What to read. All text is UTF-8.
struct RegRequest {
    std::string hklm_subkey;              ///< non-empty, relative to HKEY_LOCAL_MACHINE
    std::vector<std::string> value_names; ///< at most kMaxRegValueNames; "" is the default value
    bool each_child = false; ///< read the names from each immediate child instead of the key
    bool wow64_32 = false;   ///< the 32-bit registry view; otherwise the 64-bit one
};

/// One requested value.
struct RegValue {
    std::string name;
    bool present = false; ///< the value exists
    /// 0 when the data below is the value. Not present: 2 (ERROR_FILE_NOT_FOUND) when absent,
    /// otherwise the error of the query. Present without data: 13 (ERROR_INVALID_DATA) for a
    /// REG_DWORD / REG_QWORD that is too short, 234 (ERROR_MORE_DATA) for a value over
    /// kMaxRegValueBytes or one that kept growing while it was read.
    std::uint32_t win_error = 0;
    std::uint32_t type = 0;          ///< the REG_* type
    std::string text;                ///< REG_SZ, REG_EXPAND_SZ (not expanded), REG_MULTI_SZ (\n)
    std::uint64_t number = 0;        ///< REG_DWORD, REG_QWORD
    std::vector<std::uint8_t> bytes; ///< any other type
};

struct RegKeyValues {
    std::string child;           ///< the child key name; empty when the key itself was read
    std::uint32_t win_error = 0; ///< why this child could not be opened; it then has no values
    std::vector<RegValue> values;
};

struct RegRead {
    BoundedStatus status = BoundedStatus::Rejected;
    std::uint32_t win_error = 0; ///< a refused request (87), or a failed open or enumeration
    /// Something asked for is missing or has no data: a cap was hit, a value kept growing, or the
    /// child enumeration failed.
    bool truncated = false;
    std::vector<RegKeyValues> keys;
};

inline constexpr std::chrono::milliseconds kRegistryReadDeadline{5000};
inline constexpr std::size_t kMaxRegValueNames = 64;
inline constexpr std::size_t kMaxRegChildren = 256;
inline constexpr std::size_t kMaxRegValueBytes = 64 * 1024;
inline constexpr std::size_t kMaxRegTotalBytes = 1024 * 1024; ///< value data of one request

/// The requested values, in ONE bounded call. An empty subkey or more than kMaxRegValueNames names
/// is answered with win_error = 87 (ERROR_INVALID_PARAMETER) and nothing is read. Non-Windows
/// builds answer Completed with win_error = 120 (ERROR_CALL_NOT_IMPLEMENTED). Out-of-line
/// (agent-core only).
YUZU_EXPORT RegRead read_hklm_values(const RegRequest& request, std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. The reader must own everything
/// it touches. No default arguments (see keychain_read.hpp).
YUZU_EXPORT RegRead read_hklm_values_for_test(std::chrono::milliseconds deadline,
                                              const std::function<RegRead()>& reader);

} // namespace yuzu::agent::win
