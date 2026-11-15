#pragma once

/// @file approval_request_limits.hpp
/// The one size bound the approvals page renderer shares with the approval store, in a header with
/// no database dependency so `approvals_page_render.hpp` need not pull in `approval_manager.hpp`
/// (and with it `libpq-fe.h`).

#include <cstddef>

namespace yuzu::server {

/// Bound on a bound ticket's frozen request (#6062). `request_json` is returned by every
/// list/read of the table and rendered on the Approvals page, so it is capped; a request that does
/// not fit is refused at mint, never truncated (a truncated request is a different request than the
/// one that will be redeemed). The sibling bounds (depth, excluded roots) stay in
/// `approval_manager.hpp`, which includes this header.
inline constexpr std::size_t kMaxRequestJsonBytes = 16 * 1024;

} // namespace yuzu::server
