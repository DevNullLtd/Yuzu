event_logs_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
event_logs_cpp_args = []

if host_machine.system() == 'windows'
  # Native wevtapi leg (EvtQuery/EvtRender, rung 1 -- users #3244 precedent).
  event_logs_deps += cxx.find_library('wevtapi')
elif host_machine.system() == 'linux'
  # Native sd_journal leg (rung 1). Reuses the SAME tri-state `systemd_guard`
  # feature the device_identity and firewall plugins consume -- never a
  # second build knob. libsystemd exports sd-journal alongside sd-bus, so the
  # one pkg-config module covers both. enabled (default): required; auto:
  # native leg if libsystemd is present, else the journalctl argv fallback;
  # disabled: always the fallback.
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    event_logs_deps += libsystemd_dep
    event_logs_cpp_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('EVENT_LOGS: libsystemd not found -- sd_journal native leg compiles out; '
            + 'errors/query fall back to the bounded journalctl argv invocation.')
  endif
endif

event_logs_plugin_lib = shared_library(
  'event_logs',
  files('src/event_logs_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'), # win_str.hpp (#1681)
  cpp_args: event_logs_cpp_args,
  dependencies: event_logs_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
