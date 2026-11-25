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

#include <optional>
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
 * Enumerate every IP address (IPv4 + IPv6) this host answers to, loopback and
 * link-local included (on Windows the software-loopback adapter too). On
 * Windows an adapter that is not up is skipped; the POSIX walk has no such
 * test. Addresses that are not on an interface (a cloud floating or elastic
 * IP, a port forward, a Linux `local` route) and other network namespaces are
 * not enumerable on any OS. Same canonical text form and deduplication as
 * enumerate_local_ips().
 *
 * Returns nullopt when the OS read fails or the platform is unsupported, so a
 * caller can tell "could not read" from "no addresses"; a decision that needs
 * the answer must fail closed on nullopt. On Windows the adapter read is tried
 * up to three times, so an adapter added mid-read does not read as a failure.
 * Every failure is logged at warn with the OS error (errno or the Windows
 * return code), so a permanent cause (for example AF_NETLINK denied to the
 * agent) can be told from a transient one.
 */
YUZU_EXPORT std::optional<std::vector<std::string>> enumerate_own_addresses();

/**
 * Read the host's name (POSIX gethostname / Windows gethostname via winsock2).
 * Returns an empty string on failure.
 */
YUZU_EXPORT std::string get_hostname();

} // namespace yuzu::agent
