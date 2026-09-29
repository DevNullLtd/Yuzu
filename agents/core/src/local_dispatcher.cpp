#include "local_dispatcher.hpp"

#include <yuzu/plugin.h>

// LocalDispatcher uses a dispatch shim defined in agent.cpp because the
// underlying CommandContextImpl carries gRPC-typed streaming fields that
// would force this TU to pull in grpcpp + agent.grpc.pb.h. The shim
// constructs an internal CommandContextImpl in capture mode, runs the
// descriptor's execute, and writes back into the buffer LocalDispatcher
// owns. The cap policy + truncation sentinel are owned here so future
// local-dispatch adopters (periodic Guardian eval, agent-side health
// probes) cannot accrete divergent caps.

namespace yuzu::agent {

// Defined in agent.cpp. Treats the supplied buffer as the capture target
// and bounds it at LocalDispatcher::kCaptureMaxBytes; on overflow it
// appends the truncation sentinel and sets *truncated = true. The three
// result_* out-params (BR-001) read back whatever the plugin reported via
// CommandContext::set_result_status() on the SAME CommandContextImpl this
// call constructs -- always non-null from this TU's one caller below.
int dispatch_with_capture(const YuzuPluginDescriptor* descriptor, const char* action,
                          const YuzuParam* params, std::size_t param_count,
                          std::string* capture_out, bool* truncated_out, std::size_t capture_cap,
                          YuzuResultStatus* result_status_out,
                          YuzuResultCompleteness* result_completeness_out,
                          std::string* result_provenance_out);

LocalDispatcher::Result LocalDispatcher::run(const YuzuPluginDescriptor* descriptor,
                                             std::string_view action,
                                             std::span<const YuzuParam> params,
                                             std::size_t capture_cap) {
    Result r;
    if (!descriptor || !descriptor->execute) {
        r.rc = -1;
        return r;
    }
    // action is std::string_view; the C ABI expects a null-terminated
    // C string. Materialise on the stack — actions are short symbols.
    std::string action_z(action);
    r.rc = dispatch_with_capture(descriptor, action_z.c_str(), params.data(), params.size(),
                                 &r.captured, &r.truncated, capture_cap, &r.result_status,
                                 &r.result_completeness, &r.result_provenance);
    return r;
}

} // namespace yuzu::agent
