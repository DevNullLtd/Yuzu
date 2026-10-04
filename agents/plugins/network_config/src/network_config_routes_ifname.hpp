/**
 * network_config_routes_ifname.hpp — ifindex -> interface name for the Linux and macOS
 * `routes` legs (the Windows leg resolves aliases through ConvertInterfaceLuidToAlias).
 *
 * INCLUDE ORDER: glibc's <net/if.h> must come before anything that pulls in <linux/if.h> —
 * network_config_parsers.hpp does, for IFF_UP — or the two redefine IFF_UP / IFF_BROADCAST /
 * struct ifreq (libc-compat.h makes the kernel header skip what glibc already declared, but
 * only in that order). Each leg TU therefore includes THIS header first; the rule lives here
 * and nowhere else.
 */
#pragma once

#if defined(__linux__) || defined(__APPLE__)

#include <net/if.h> // if_indextoname, IF_NAMESIZE

#include <string>

namespace yuzu::network_config {

/// The kernel's name for `ifindex` (the same table `ip` / `ifconfig` read), or empty when the
/// index is not positive or no longer resolves (the interface vanished between the dump and the
/// lookup) — rendered `-`, never guessed.
inline std::string interface_name_for_index(int ifindex) {
    if (ifindex <= 0)
        return {};
    char name[IF_NAMESIZE]{};
    return ::if_indextoname(static_cast<unsigned>(ifindex), name) == nullptr ? std::string{}
                                                                           : std::string{name};
}

} // namespace yuzu::network_config

#endif // __linux__ || __APPLE__
