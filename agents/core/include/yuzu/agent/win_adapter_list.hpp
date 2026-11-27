#pragma once

/**
 * win_adapter_list.hpp -- bounded read of the Windows network adapter list.
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * GetAdaptersAddresses takes no deadline. Bounding the wait needs a detached worker, whose code
 * must not live in a plugin the agent can unload (see bounded_single_flight.hpp). Plugins call
 * the exported functions only.
 *
 * One read is in flight process-wide. A second caller waits for a healthy read inside its own
 * deadline; after a deadline hit, callers are answered Abandoned until the blocked worker returns.
 * Every other field of the result is meaningful only when status == Completed. The result owns all
 * of its data: nothing points into the OS buffer.
 */

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <yuzu/agent/bounded_status.hpp>
#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent::win {

/// One unicast or DNS server address.
struct AdapterAddr {
    std::string address; ///< inet_ntop text, no scope id; empty when it could not be rendered
    int family = 0;      ///< 4 or 6; 0 for any other family
    std::uint8_t prefix_len = 0; ///< unicast only (OnLinkPrefixLength)
};

/// One IP_ADAPTER_ADDRESSES record. Text is UTF-8; numbers are the API's own values.
struct Adapter {
    std::string adapter_name;
    std::string friendly_name;
    std::string description;
    std::string dns_suffix;
    std::uint32_t if_type = 0;
    std::uint32_t tunnel_type = 0;
    std::uint32_t oper_status = 0;
    std::uint32_t if_index = 0; ///< the IPv4 interface index
    std::uint32_t flags = 0;
    std::uint64_t transmit_link_speed = 0; ///< bits per second; all ones when unknown
    std::uint64_t receive_link_speed = 0;
    std::vector<std::uint8_t> physical_address;
    std::vector<AdapterAddr> unicast;
    std::vector<std::string> gateways; ///< list order; empty where it could not be rendered
    std::vector<AdapterAddr> dns_servers;
};

struct AdapterList {
    BoundedStatus status = BoundedStatus::Rejected;
    std::uint32_t win_error = 0; ///< Win32 error of a failed read
    bool empty_table = false;    ///< the sizing call asked for no bytes: no adapters
    std::vector<Adapter> adapters;
};

inline constexpr std::chrono::milliseconds kAdapterListDeadline{5000};

/// Every adapter (loopback and tunnels included), with prefixes and gateways, in ONE bounded call.
/// Non-Windows builds answer Completed with win_error = 120 (ERROR_CALL_NOT_IMPLEMENTED).
/// Out-of-line (agent-core only).
YUZU_EXPORT AdapterList read_adapters(std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. The reader must own everything
/// it touches. No default arguments (see keychain_read.hpp).
YUZU_EXPORT AdapterList read_adapters_for_test(std::chrono::milliseconds deadline,
                                               const std::function<AdapterList()>& reader);

} // namespace yuzu::agent::win
