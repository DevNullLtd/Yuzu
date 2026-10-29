- **The DEX Apps stability model can now answer for a platform scope (all, windows, macos,
  linux).** The population and every figure are computed over that scope's online devices,
  and an unknown scope is refused as degraded rather than defaulted to a platform. The
  Windows result, and the `GET /api/v1/dex/apps` and `list_dex_apps` outputs, are unchanged;
  exposing the scope on the API and MCP tool follows separately.
