#pragma once

/// @file dispatch_position.hpp
/// #3678: one reading of the two dispatch counters the WS-3 command outbox measures its
/// redelivery horizon on. They are kept SEPARATE on purpose: they live on different scales, and
/// adding them into one number made a value stamped by one process meaningless to another.
///
///  * `shared`      -- `execution_tracker.dispatch_seq`, advanced inside the dispatch-record
///                     upsert. It lives in the database, so every replica sees the same number and
///                     it survives restarts (it can only go BACKWARD on a restore or a lost-WAL
///                     failover).
///  * `unrecorded`  -- this PROCESS's count of dispatches whose record was NOT written (failed,
///                     refused, latch-skipped). Each such command was still sent and may have taken
///                     an agent dedup-ring slot, but the shared sequence did not move. It starts at
///                     0 in every process, so it is only comparable with another reading taken by
///                     the SAME process, i.e. within one leadership term (the outbox stores the
///                     leader epoch beside the stamp to know which).
///
/// Pure value type, no behaviour: the comparison rule lives in
/// `CommandOutboxDelivery::deliver()` (rule R4).

#include <cstdint>

namespace yuzu::server {

struct DispatchPosition {
    std::int64_t shared{0};
    std::int64_t unrecorded{0};
};

} // namespace yuzu::server
