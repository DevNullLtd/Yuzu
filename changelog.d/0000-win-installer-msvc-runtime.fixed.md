- **The Windows agent archive and installer now carry the Visual C++ runtime.** Every
  Windows agent binary imports `vcruntime140.dll`, `vcruntime140_1.dll` and `msvcp140.dll`
  (`yuzu-agent.exe` also `msvcp140_atomic_wait.dll`, Redistributable 14.28 or later), and up
  to 0.15.0 neither `yuzu-agent-windows-x64.zip` nor `YuzuAgentSetup-<version>.exe` shipped
  them, so the agent did not start on a machine without the Visual C++ Redistributable
  installed. The release now copies them, unmodified, from the build machine's Visual Studio
  redistributable directory into the agent's `bin` directory in both payloads (app-local
  deployment; see `NOTICE`), and a new release step reads the PE import table of every
  shipped `.exe` and `.dll` and fails the release when one imports a DLL its payload does not
  carry. The check treats the Visual C++ runtime as missing even though the build runner has
  it installed, which is how the gap went unnoticed. On 0.15.0 and earlier, install the
  Visual C++ 2015-2022 Redistributable (x64) or upgrade the agent.
