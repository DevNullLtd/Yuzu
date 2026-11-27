#pragma once

// sweep_audit_queue.hpp -- #2673: audit rows the response-deadline sweep has not yet written.
// Pure: the caller supplies the writer and the stop check. Single-threaded by contract (the
// server's maintenance thread owns the queue).
//
// A flush stops at the first failed write, so a degraded audit store holds the shared thread for
// one attempt and no longer; the rows stay queued, in order, for the next pass. After a failure
// every row still waiting is handed to `unwritten` ONCE, so the log holds it even if the process
// dies before the row is written. The queue is bounded: past `cap` the OLDEST rows are dropped
// and handed to `dropped`.

#include <cstddef>
#include <deque>

namespace yuzu::server {

struct AuditFlush {
    std::size_t written{0};
    bool write_failed{false};
    std::size_t dropped{0};
};

/// `announced` counts the rows at the front already handed to `unwritten`; the caller keeps it
/// beside the queue.
template <class Event, class Write, class Stop, class Unwritten, class Dropped>
AuditFlush flush_audit_queue(std::deque<Event>& queue, std::size_t& announced, Write&& write,
                             Stop&& stop, std::size_t cap, Unwritten&& unwritten,
                             Dropped&& dropped) {
    AuditFlush out;
    const auto pop = [&] {
        queue.pop_front();
        if (announced > 0)
            --announced;
    };
    while (!queue.empty() && !stop()) {
        if (!write(queue.front())) {
            out.write_failed = true;
            break;
        }
        pop();
        ++out.written;
    }
    if (out.write_failed) {
        for (; announced < queue.size(); ++announced)
            unwritten(queue[announced]);
    }
    while (queue.size() > cap) {
        dropped(queue.front());
        pop();
        ++out.dropped;
    }
    return out;
}

} // namespace yuzu::server
