#pragma once

// sweep_audit_queue.hpp -- #2673: audit rows the response-deadline sweep has not yet written.
// Pure: the caller supplies the writer and the stop check. Single-threaded by contract (the
// server's maintenance thread owns the queue).
//
// A flush stops at the first failed write, so a degraded audit store holds the shared thread for
// one attempt and no longer; the rows stay queued, in order, for the next pass. The queue is
// bounded: past `cap` the OLDEST rows are dropped and handed to `dropped` so they can be logged.

#include <cstddef>
#include <deque>

namespace yuzu::server {

struct AuditFlush {
    std::size_t written{0};
    bool write_failed{false};
    std::size_t dropped{0};
};

template <class Event, class Write, class Stop, class Dropped>
AuditFlush flush_audit_queue(std::deque<Event>& queue, Write&& write, Stop&& stop,
                             std::size_t cap, Dropped&& dropped) {
    AuditFlush out;
    while (!queue.empty() && !stop()) {
        if (!write(queue.front())) {
            out.write_failed = true;
            break;
        }
        queue.pop_front();
        ++out.written;
    }
    while (queue.size() > cap) {
        dropped(queue.front());
        queue.pop_front();
        ++out.dropped;
    }
    return out;
}

} // namespace yuzu::server
