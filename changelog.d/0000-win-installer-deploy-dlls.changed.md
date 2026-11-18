- **Windows builds now fail when a dependency or plugin DLL could not be copied into the
  build tree.** `scripts/deploy_build_dlls.py`, which the Windows Meson build runs at
  configure time and as the `deploy_dlls` target, used to ignore a copy refused with a
  permission error, so a build could finish with a DLL missing from `agents/core` or
  `plugins` (and from an installer built from that tree). A failed copy with no earlier copy
  in place now fails the `deploy_dlls` target and names the DLL; at configure time it is a
  Meson warning, because the build-time target runs again. A DLL that could not be replaced
  because a running agent holds the old copy is still tolerated, now with a warning. A
  missing vcpkg DLL directory is reported instead of silently copying nothing. The set of
  DLLs copied is unchanged.
