/**
 * echo_proc_stream.cpp — explicit EventRing<ProcEvent> instantiation.
 *
 * EventRing<T> (the bounded push→pull backpressure bridge) is now a header-only
 * template in echo_proc_stream.hpp. This TU pins the ProcEvent instantiation — the
 * canonical process-stream ring shared by the ETW (Windows) and Endpoint Security
 * (macOS) collectors — so it is emitted here once in addition to the inline copies
 * at each use site. Platform-agnostic; no platform headers.
 */

#include "echo_proc_stream.hpp"

namespace yuzu::echo {

template class EventRing<ProcEvent>;

} // namespace yuzu::echo
