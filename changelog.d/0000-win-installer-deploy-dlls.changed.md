- **Windows builds now fail when a dependency or plugin DLL could not be copied into the
  build tree.** `scripts/deploy_build_dlls.py`, which the Windows Meson build runs at
  configure time and as the `deploy_dlls` target, used to ignore a copy refused with a
  permission error, so a build could finish with a DLL missing from `agents/core` or
  `plugins` (and from an installer built from that tree). Each copy now goes to a temporary
  name and is renamed onto the destination, so a copy that fails part-way never leaves a
  truncated DLL. A failed copy now fails the `deploy_dlls` target and names the DLL; at
  configure time it is a Meson warning, because the build-time target runs again. Only a DLL
  that could not be replaced because a running agent holds the older copy is still
  tolerated, now with a warning. A missing vcpkg DLL directory is reported instead of
  silently copying nothing. The set of DLLs copied is unchanged. A local
  `deploy/packaging/windows/build-installer.sh` run now also needs PowerShell 7 (`pwsh`) and
  a Visual Studio installation with its Visual C++ redistributable directory, from which it
  stages the runtime into the installer.
