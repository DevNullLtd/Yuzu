#pragma once

/// @file discovered_devices_reader.hpp
/// Core-only adapter from `DiscoveryStore` to the `DiscoveredDevicesReadFn`
/// seam the discovered-devices twin (REST, MCP, fragment) reads through. Kept
/// out of `discovered_devices_model.hpp` so the presentation-side TUs never
/// reach a store header.

#include "discovered_devices_model.hpp"

namespace yuzu::server {

class DiscoveryStore;

/// Adapts a store to the read seam. A null or unopened store yields a function
/// that always errors, so callers never see "no rows" for "could not ask".
DiscoveredDevicesReadFn make_discovered_devices_reader(DiscoveryStore* store);

} // namespace yuzu::server
