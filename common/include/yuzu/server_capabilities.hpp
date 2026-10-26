#pragma once

/// @file server_capabilities.hpp
/// Capability tokens a server advertises in `RegisterResponse.server_capabilities` (field 9).
/// Pure constants, shared by the server (which advertises) and the agent (which gates a daily-sync
/// source on them): one literal, never retyped. A server lists a token ONLY while it can ingest that
/// source typed; an agent sends a capability-gated source only to a server that lists it.

namespace yuzu {

/// The `certificate_inventory` daily-sync source (ADR-0016 §5, ADR-0070 D12). Advertised only while
/// the server's CertificateInventoryStore is open: never advertise a source the server cannot ingest.
inline constexpr const char* kServerCapCertificateInventoryV1 = "certificate_inventory_v1";

} // namespace yuzu
