- **The supported compiler floor is now exactly what CI builds and tests: GCC 15, Clang 21,
  MSVC 19.44 (Visual Studio 2022 17.14) and Apple Clang 21** (#5929). The previous floor
  (GCC 13, Clang 18, MSVC 19.38, Apple Clang 15) was wider than anything CI ran, and GCC 14
  was shown to miscompile code that is correct under GCC 15: it lacks P2718R0 (lifetime
  extension of temporaries in a range-for initializer), which left six use-after-free sites in
  the unit tests that only a below-floor build exposed (#5924). Packagers: on RHEL 9 use
  `gcc-toolset-15` instead of `gcc-toolset-14` (`scripts/setup-rhel9.sh` now installs it, and
  its `--check` fails a box still on 14). Ubuntu 24.04 and Debian 13 have no GCC 15 in their
  archives; build on Ubuntu 26.04, in an `ubuntu:26.04` container, or with `gcc-15` from the
  `ppa:ubuntu-toolchain-r/test` PPA on 24.04. See "Compiler floor" in `docs/build-guide.md`.
- **The `yuzu-server` and `yuzu-agent` images, and their chisel variants, are now built with
  GCC 15 on Ubuntu 26.04 instead of GCC 13 on Debian 13** (#5929). The non-chisel
  `Dockerfile.server` and `Dockerfile.agent` runtime stages also move from `debian:trixie-slim`
  to `ubuntu:26.04`, because a GCC 15 binary needs a newer libstdc++ than Debian 13 provides.
  The chisel images already ran on Ubuntu 26.04 and keep doing so. Anything that copies the
  agent out of the `Dockerfile.agent` image onto another base must provide Ubuntu 26.04's
  libstdc++ and glibc.
