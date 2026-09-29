# tools/plugin-capture — README sample-output capture tool
# (docs/plugin-readme-standard.md rule 5).
#
# Host tool: loads one built plugin shared library through the agent's own
# PluginHandle::load, runs its init with a StandalonePluginContext (config
# only — no KV store, no trigger engine, no server), drives its actions
# through LocalDispatcher, then runs its shutdown, writing the stamped sample
# file tools/plugin-doc-gen splices into the plugin's README. Links
# libyuzu_agent_core (the dispatcher, loader and context live there) — never
# a stubbed yuzu_ctx_* host, so a row is what the agent host captures for a
# plugin that needs no store or server; a plugin that does fails closed here
# the same way it would under a host without them (see the tool's header).
#
# Guarded like capmatrix-gen: under cross-compilation the build machine cannot
# run a target-machine binary, so the tool is skipped rather than built as an
# artifact nothing on the host can execute.
if meson.can_run_host_binaries()
  plugin_capture_exe = executable(
    'plugin-capture',
    'plugin_capture.cpp',
    include_directories: [include_directories('../../agents/core/src')],
    dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep],
    install: false,
  )
endif
