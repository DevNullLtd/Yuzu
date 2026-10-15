# Target libraries distributed in the macOS agent must remain runnable on the
# documented macOS 13.3 floor.  Keep this overlay intentionally identical to
# vcpkg's arm64-osx triplet apart from the deployment target. On an Apple
# silicon host the host triplet is also arm64-osx, so host tools are built with
# this floor too (harmless: they only run on the build machine). Linux/Windows
# triplets are unaffected.
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES arm64)
set(VCPKG_OSX_DEPLOYMENT_TARGET "13.3")
