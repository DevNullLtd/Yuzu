/**
 * echo_module_stream.cpp — explicit EventRing<ModuleEvent> instantiation.
 *
 * The image-load peer of echo_proc_stream.cpp. EventRing<T> (the bounded push→pull
 * backpressure bridge) is a header-only template in echo_proc_stream.hpp; this TU
 * pins the ModuleEvent instantiation — the module/image-load ring the ETW
 * (Windows), Endpoint Security (macOS), and auditd (Linux) collectors share — so
 * it is emitted here once for build hygiene (and to keep the MSVC explicit-
 * instantiation behaviour identical to the ProcEvent ring) in addition to the
 * inline copies at each use site. Platform-agnostic; no platform headers.
 */

#include "echo_module_stream.hpp"

namespace yuzu::echo {

template class EventRing<ModuleEvent>;

} // namespace yuzu::echo
