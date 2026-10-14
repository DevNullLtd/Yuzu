#pragma once

/// @file cidr_match.hpp
/// CIDR containment for the #1128 NAT-aware per-session peer-IP binding.
///
/// `peer_ip.hpp` deliberately hand-rolls IP *validation* so it can stay
/// header-only and free of platform networking headers. CIDR *containment*
/// needs inet_pton-class parsing (IPv4 + IPv6, byte-array prefix masking), so it
/// lives in a .cpp that owns the `<ws2tcpip.h>` / `<arpa/inet.h>` includes —
/// keeping those out of the widely-included peer_ip.hpp.
///
/// Distinct from auth/auto_approve.cpp's IPv4-only `match_ip_subnet`: that one
/// is a private AutoApproveEngine method that treats a malformed prefix as a
/// non-match. These are free functions, IPv4+IPv6, and never throw — a future
/// consolidation could fold auto_approve onto these.

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::detail {

/// True iff bare-IP literal `ip` is inside `cidr` ("10.0.0.0/8",
/// "2001:db8::/32", or a bare address meaning an exact /32 or /128 match).
/// Families must match — an IPv4 `ip` against an IPv6 `cidr` (or vice-versa) is
/// false. Malformed `cidr` or `ip`, or an out-of-range prefix length, is false.
/// Never throws.
bool ip_in_cidr(std::string_view cidr, std::string_view ip);

/// True iff `cidr` is a well-formed CIDR (or bare address) this module can
/// match against — i.e. `ip_in_cidr` could ever return true for it. Used at
/// startup (gov UP-2/UP-9) to fail-loud on a mistyped `--trusted-nat-cidr`
/// entry instead of silently treating it as a range that matches nothing.
bool is_valid_cidr(std::string_view cidr);

/// True iff `a` and `b` BOTH fall inside at least one common CIDR in `cidrs`.
/// The #1128 binding tolerates a Register/Subscribe source-IP pair only when
/// both endpoints share an operator-declared multi-egress range — a mismatch
/// where only one side (or neither) is in range stays a hard reject. Empty `a`
/// or `b` is false (an empty extracted IP is a #826 mismatch, never a wildcard).
bool ips_share_trusted_cidr(const std::vector<std::string>& cidrs, std::string_view a,
                            std::string_view b);

} // namespace yuzu::server::detail
