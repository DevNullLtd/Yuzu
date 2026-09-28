- CI now anchors `docs/user-manual/rbac.md`'s system-role, securable-type,
  operation and authorization-topology-floor tables to their C++ seed arrays
  (`rbac_store.cpp`, `authz_topology_floor.hpp`), so a securable added without a
  doc row fails the build and names the securable (#480).
