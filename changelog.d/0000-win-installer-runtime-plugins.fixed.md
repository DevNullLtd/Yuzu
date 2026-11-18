- **The Windows agent archive and installer now carry the Visual C++ runtime.** Every
  Windows agent binary imports `vcruntime140.dll`, `vcruntime140_1.dll` and `msvcp140.dll`
  (`yuzu-agent.exe` also `msvcp140_atomic_wait.dll`), and up to 0.15.0 neither
  `yuzu-agent-windows-x64.zip` nor `YuzuAgentSetup-<version>.exe` shipped them, so the agent
  did not start on a machine without the Visual C++ 2015-2022 Redistributable (x64), 14.44 or
  later, installed (Windows reported a missing `VCRUNTIME140.dll` or `MSVCP140.dll`), or stopped
  with an access violation in `msvcp140.dll` where an older Redistributable was. The release
  now copies them, unmodified, from the build machine's Visual Studio redistributable directory
  into the agent's `bin` directory in both payloads (app-local deployment; see `NOTICE`, which both
  payloads now carry), builds with one pinned Visual C++ toolset (`msvc-toolset.pin`; the
  release fails on any other), and lists the staged DLLs and their file versions in the release
  job's step summary for that workflow run (the shipped version is the file version of the
  Microsoft-signed DLLs in the payload). A new release step reads the PE import table of every shipped `.exe` and
  `.dll` and fails the release when one imports a DLL its payload does not carry, treating the
  Visual C++ runtime as missing even though the build runner has it installed, which is how the
  gap went unnoticed. The agent uses its own copy of the runtime even where the
  Redistributable is installed, and Windows Update does not service it. Each release's
  installer and archive carry that release's runtime; agent self-update (OTA) replaces
  `yuzu-agent.exe` only and does not install or refresh the runtime (#8219). Reprovision a
  0.15.0 device from a 0.16.0 installer or archive. See "Windows agent: Visual C++ runtime" in
  `docs/user-manual/README.md`.
- **The Windows agent installer now installs five plugins it left out (#4867).**
  `YuzuAgentSetup-<version>.exe` left out six plugins that the release zip already carried, so
  a device installed from the installer answered "plugin not found" for them. Five are now
  installed: `browser_inventory`, `printing` and `privacy_permissions` with the System
  component, `netprobe` with Network and `rdp_control` with Windows. `browser_inventory` and
  `privacy_permissions` stay behind their server-side kill switch, which is off until an
  operator turns it on; where it is already on, a device installed with this installer answers
  them at once. `rdp_control`'s `set_state` can turn Remote Desktop on and open its firewall
  rule group (Mutating, Irreversible, admin or approval). The sixth, `license_scan`, is
  deliberately not installed: installing it starts the agent's daily software-licensing
  collection with no operator action, which ADR-3006 (decision D10) rules out until the
  fleet-level setting for additions exists (#8309); the release zip still carries it. Agent
  self-update (OTA) installs no plugin; each release's installer and archive carry its
  plugins. Uninstalling now also removes `plugins\license_scan.dll` (copied in from the zip,
  if it was) and the `bin\yuzu-agent.old.exe` and `bin\.yuzu-update-verified` files agent
  self-update leaves, for an agent installed with this installer (an earlier installer's
  uninstaller leaves them; delete them by hand). The installer also deletes those two
  self-update files before it copies its own, so the agent it installs is the one that starts
  (the agent switches back to `yuzu-agent.old.exe` when that file exists without the marker). Uninstall still keeps the data directory
  `%ProgramData%\Yuzu` apart from the enrollment token file. A new docs lint (`tests/test_agent_installer_plugin_coverage_lint.py`) fails
  when a plugin built by `meson.build` has no installer line and no recorded
  `; plugin-not-installed:` reason, or when an excluded plugin's DLL or those two files have
  no uninstall entry.
