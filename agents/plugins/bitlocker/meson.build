bitlocker_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
bitlocker_sources = files('src/bitlocker_plugin.cpp')
bitlocker_include_dirs = []

if host_machine.system() == 'windows'
  # Win32_EncryptableVolume WMI query + a per-volume GetConversionStatus()
  # method call (root\CIMV2\Security\MicrosoftVolumeEncryption) replace the
  # raw `manage-bde -status` popen this plugin used to run. The bounded
  # helper is the header-only agents/shared/wmi_bounded.hpp (+ win_com.hpp):
  # this plugin compiles its own private inline copy, so there is no shared
  # .cpp to list (agents/shared/ is header-only leaves ONLY,
  # docs/cpp-conventions.md) -- only the COM/WMI link deps below.
  bitlocker_include_dirs += include_directories('../../shared')  # wmi_bounded.hpp, win_com.hpp, win_str.hpp
  bitlocker_deps += cxx.find_library('wbemuuid')
  bitlocker_deps += cxx.find_library('ole32')
  bitlocker_deps += cxx.find_library('oleaut32')
elif host_machine.system() == 'linux'
  # crypto_LUKS TYPE enumeration promoted from an `lsblk` shell-out to
  # genuine rung-1 in-process libblkid (util-linux) -- a system pkg-config
  # library, not vcpkg. Open/mapped state comes from a plain
  # /sys/class/block/dm-*/dm/uuid read (no library needed for that half).
  bitlocker_deps += dependency('blkid', required: true)
endif

shared_library(
  'bitlocker',
  bitlocker_sources,
  name_prefix: '',
  include_directories: bitlocker_include_dirs,
  dependencies: bitlocker_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
