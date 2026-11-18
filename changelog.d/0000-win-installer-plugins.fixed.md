- **The Windows agent installer now installs every plugin the build produces (#4867).**
  `YuzuAgentSetup-<version>.exe` left out six plugins that the release zip already
  carried: `browser_inventory`, `license_scan`, `netprobe`, `printing`,
  `privacy_permissions` and `rdp_control`, so a device installed from the installer
  answered "plugin not found" for them. They are now installed with the System
  (`browser_inventory`, `license_scan`, `printing`, `privacy_permissions`), Network
  (`netprobe`) and Windows (`rdp_control`) components. Nothing changes in what each
  plugin is allowed to do: `browser_inventory` and `privacy_permissions` stay off until
  an operator enables their server-side kill switch, and `browser_inventory`'s Windows
  leg still answers `windows:planned`. A new docs lint
  (`tests/test_agent_installer_plugin_coverage_lint.py`) fails when a plugin built by
  `meson.build` has no installer line and no recorded `; plugin-not-installed:` reason.
