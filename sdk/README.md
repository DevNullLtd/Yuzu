# Yuzu Plugin SDK

Public, ABI-stable C interface plus a thin C++23 wrapper for writing
plugins that load into the Yuzu agent at runtime.

## Contents

| File | Purpose |
|------|---------|
| `include/yuzu/plugin.h` | Stable C ABI — the only supported boundary for third-party plugin authors |
| `include/yuzu/plugin.hpp` | C++23 convenience wrapper (inline, header-only) |
| `include/yuzu/sdk_utilities.hpp` | Pipe-delimited-table ↔ JSON conversion helpers |
| `include/yuzu/json_log_formatter.hpp` | Structured JSON log formatting |
| `include/yuzu/metrics.hpp` | `MetricsRegistry` — counters, gauges, histograms |
| `include/yuzu/secure_zero.hpp` | Guaranteed-not-elided memory scrubbing |
| `include/yuzu/string_utils.hpp` | Common string helpers |
| `include/yuzu/version_string.hpp` | Application-version normalisation for DEX (name, version) identity (`yuzu::util`), shared by agent and server |
| `include/yuzu/version.hpp` | Build version constants (`kVersionString`, …), generated from `version.hpp.in` at configure time |

Only `plugin.h` is ABI-stable. `plugin.hpp` and every other header here are header-only C++
compiled into your plugin: they carry no ABI or API stability promise, are not covered by
`YUZU_PLUGIN_ABI_VERSION`, may change between releases, and none of their types may cross the
plugin boundary. `json_log_formatter.hpp` needs spdlog and `sdk_utilities.hpp` needs nlohmann_json;
`yuzu_sdk_dep` provides neither. (The licence exception in `LICENSE-SDK.md` still covers every
header under `sdk/include/`; this note is about stability, not licensing.)

## ABI compatibility

The C ABI advertises a version macro (`YUZU_PLUGIN_ABI_VERSION`). The
agent refuses to load a plugin whose declared `abi_version` falls
outside the closed range `[YUZU_PLUGIN_ABI_VERSION_MIN,
YUZU_PLUGIN_ABI_VERSION]` (checked in `plugin_loader.cpp` at load
time, immediately after `yuzu_plugin_descriptor()` returns and before
the rest of the descriptor is trusted). Breaking ABI
changes require bumping the major version and are reviewed by the
`architect` agent before landing. A version bump does **not** imply
"recompile everything" — `YuzuPluginDescriptor` only ever grows by
appending fields, so older plugins keep loading and keep working
until `YUZU_PLUGIN_ABI_VERSION_MIN` itself moves past them.

| ABI version | Added | Minimum supported (`YUZU_PLUGIN_ABI_VERSION_MIN`) | Rebuild required? |
|---|---|---|---|
| 1 | Initial stable C ABI (`YuzuPluginDescriptor` base fields through `execute`) | 1 | No — still loads today |
| 2 | KV-storage host API (persistent per-plugin SQLite) | 1 | No |
| 3 | `sdk_version` diagnostic descriptor field | 1 | No |
| 4 | Per-OS `YuzuActionDescriptor` capability-matrix fields (append-only; #2204) | 1 | No — a plugin built against ABI 1-3 still loads unchanged; only plugins that need the new fields must target ABI 4 |

`sdk/include/yuzu/plugin.h` is the source of truth for the current
`YUZU_PLUGIN_ABI_VERSION` / `YUZU_PLUGIN_ABI_VERSION_MIN` values — this
table records when each version was introduced and whether it retired
support for anything older. See `docs/Instruction-Engine.md` §14.3 for
the ABI evolution rules.

## License

The Yuzu agent and server are licensed under AGPL-3.0-or-later (see
top-level [`LICENSE`](../LICENSE)). The Plugin SDK carries an
**additional permission** — an AGPL linking exception — that allows
plugins to be distributed under any license (including proprietary
ones) provided they consume only the stable C ABI defined here and do
not statically link any Yuzu implementation code.

**Read the exception in full** before shipping a proprietary plugin:
[`LICENSE-SDK.md`](LICENSE-SDK.md).

## How to write a plugin

See the worked example under `agents/plugins/example/` and the author
guide in `docs/plugin-author-guide.md` (if present). In short:

1. Copy `agents/plugins/example/` as a starting point.
2. Implement your plugin class using the `YUZU_PLUGIN_EXPORT` macro
   from `plugin.hpp`.
3. Add a `meson.build` that produces a shared library.
4. Register the plugin directory with `subdir('agents/plugins/<name>')`
   in the root `meson.build` (or distribute your plugin independently and
   drop it into the agent's plugin directory at runtime).

The `plugin-developer` agent (`.claude/agents/plugin-developer.md`)
reviews any change that touches the SDK or adds a plugin.
