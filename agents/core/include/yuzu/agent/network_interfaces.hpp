#pragma once

/**
 * network_interfaces.hpp -- Cross-platform local-IP enumeration for Yuzu agent
 *
 * Returns the set of IPv4 and IPv6 addresses bound to the host's non-loopback,
 * non-link-local network interfaces. Used by the Echo plugin's fleet_snapshot
 * action so the server can build a host -> agent_id map for cross-machine
 * connection resolution in the fleet-topology view.
 *
 * Filtering: loopback (127.0.0.0/8, ::1) and link-local (169.254.0.0/16,
 * fe80::/10) are excluded. They are not useful for fleet identification --
 * loopback is per-host, link-local can collide across hosts on the same link.
 *
 * Platform implementations:
 *   Linux/macOS -- getifaddrs(3)
 *   Windows     -- GetAdaptersAddresses (iphlpapi)
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <string>
#include <vector>

namespace yuzu::agent {

/**
 * Enumerate local IP addresses (IPv4 + IPv6) on the current host.
 * Loopback and link-local addresses are excluded. Returned strings are
 * deduplicated and in canonical form (IPv4 dotted-quad, IPv6 inet_ntop
 * output without scope id).
 *
 * Returns an empty vector on unsupported platforms or on failure.
 */
YUZU_EXPORT std::vector<std::string> enumerate_local_ips();

/**
 * Read the host's name (POSIX gethostname / Windows gethostname via winsock2).
 * Returns an empty string on failure.
 */
YUZU_EXPORT std::string get_hostname();

} // namespace yuzu::agent
