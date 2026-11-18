#!/usr/bin/env python3
"""Deploy vcpkg dependency DLLs and plugin DLLs into build output directories.

Called by meson.build at configure time and as a custom_target at build time.

  --build-root     Path to the Meson build directory
  --vcpkg-bin      Explicit path to vcpkg DLL directory (preferred)
  --triplet        vcpkg triplet (default: x64-windows)
  --debug          Use debug DLL directory (fallback detection only)
"""

import argparse
import glob
import os
import shutil
import sys


# Copies that failed, filled in by copy_newer() and reported by main():
#   MISSING - the destination does not exist after the failed copy, so the
#             build tree lacks the DLL: main() exits 1 (the Meson custom_target
#             fails; the configure-time run reports a warning).
#   STALE   - the destination exists but could not be replaced, usually
#             because a running yuzu-agent has it loaded: main() warns on
#             stderr and carries on, as before, so a developer can rebuild
#             with the agent running. The old copy is still in the tree.
MISSING = []
STALE = []


def copy_newer(src, dst_dir):
    """Copy src into dst_dir if the destination is missing or older."""
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, os.path.basename(src))
    try:
        if not os.path.exists(dst) or os.path.getmtime(src) > os.path.getmtime(dst):
            shutil.copy2(src, dst)
    except OSError as e:
        # A DLL locked by a running process (PermissionError) used to be
        # swallowed here whether or not an older copy existed, so a copy that
        # never happened left the build tree without the DLL and nothing said
        # so. Record it instead; main() decides how loud to be.
        (STALE if os.path.isfile(dst) else MISSING).append((src, dst, e))


def find_vcpkg_dll_dir(explicit_bin, triplet, debug):
    """Return the vcpkg DLL directory, trying explicit path first."""
    if explicit_bin and os.path.isdir(explicit_bin):
        return explicit_bin

    # Fallback: derive from VCPKG_ROOT
    root = os.environ.get('VCPKG_ROOT', '')
    if not root or not os.path.isdir(root):
        for candidate in [
            os.path.expanduser('~/vcpkg'),
            'C:/vcpkg',
            'C:/src/vcpkg',
        ]:
            if os.path.isdir(candidate):
                root = candidate
                break
    if not root:
        return None

    if debug:
        return os.path.join(root, 'installed', triplet, 'debug', 'bin')
    return os.path.join(root, 'installed', triplet, 'bin')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build-root', required=True,
                   help='Meson build directory')
    p.add_argument('--vcpkg-bin', default='',
                   help='Explicit path to vcpkg DLL directory')
    p.add_argument('--triplet', default='x64-windows',
                   help='vcpkg triplet')
    p.add_argument('--debug', action='store_true',
                   help='Use debug DLLs')
    args = p.parse_args()

    build = args.build_root
    agent_dir  = os.path.join(build, 'agents', 'core')
    server_dir = os.path.join(build, 'server', 'core')
    plugin_dst = os.path.join(build, 'plugins')
    copied = 0

    # ── 1. Copy vcpkg dependency DLLs alongside executables ──────────────
    # Copy from both release and debug bin directories.  Some dependencies
    # (e.g. zlib) use different DLL names between configurations (zlib1.dll
    # vs zlibd1.dll) and the linker may pick either, so we need both.
    # The primary config directory is copied first; the secondary only fills
    # gaps (DLLs whose filename doesn't already exist) to avoid overwriting
    # a debug DLL with a same-named release DLL (or vice versa).
    dll_dir = find_vcpkg_dll_dir(args.vcpkg_bin, args.triplet, args.debug)
    if not dll_dir or not os.path.isdir(dll_dir):
        print(f"deploy_build_dlls: WARNING: no vcpkg DLL directory found "
              f"(--vcpkg-bin {args.vcpkg_bin or '(none)'}, VCPKG_ROOT fallback: {dll_dir or 'none'}); "
              f"no dependency DLLs were copied next to the executables", file=sys.stderr)
    if dll_dir and os.path.isdir(dll_dir):
        # Also locate the counterpart directory (release if debug, vice versa)
        parent = os.path.dirname(dll_dir)       # .../debug  or .../x64-windows
        grandparent = os.path.dirname(parent)   # .../x64-windows or .../installed
        # NOTE: only the debug branch resolves to the real counterpart
        # (<prefix>/bin). For a release build dll_dir is <prefix>/bin, so
        # grandparent is the directory ABOVE the prefix and other_dir names
        # a path that normally does not exist: release builds get no gap-fill.
        # That is left as is on purpose. Pointing it at <prefix>/debug/bin
        # would copy debug-only DLLs (zlibd1.dll and the like) into a release
        # agents/core, and yuzu-agent.iss installs agents\core\*.dll.
        if args.debug:
            other_dir = os.path.join(grandparent, 'bin')
        else:
            other_dir = os.path.join(grandparent, 'debug', 'bin')

        # Primary: copy all DLLs from the matching config
        deployed_names = set()
        for dll in glob.glob(os.path.join(dll_dir, '*.dll')):
            copy_newer(dll, agent_dir)
            copy_newer(dll, server_dir)
            deployed_names.add(os.path.basename(dll).lower())
            copied += 1

        # Secondary: fill in DLLs that only exist in the other config
        if os.path.isdir(other_dir):
            for dll in glob.glob(os.path.join(other_dir, '*.dll')):
                if os.path.basename(dll).lower() not in deployed_names:
                    copy_newer(dll, agent_dir)
                    copy_newer(dll, server_dir)
                    copied += 1

    # ── 2. Copy plugin DLLs into plugins/ directory ──────────────────────
    pattern = os.path.join(build, 'agents', 'plugins', '*', '*.dll')
    os.makedirs(plugin_dst, exist_ok=True)
    for dll in glob.glob(pattern):
        copy_newer(dll, plugin_dst)
        copied += 1

    for src, dst, e in STALE:
        print(f"deploy_build_dlls: WARNING: could not replace {dst} (is a yuzu-agent "
              f"running?); the build tree keeps an older copy than {src}: {e}", file=sys.stderr)
    if MISSING:
        for src, dst, e in MISSING:
            print(f"deploy_build_dlls: ERROR: could not copy {src} to {dst}: {e}", file=sys.stderr)
        print(f"deploy_build_dlls: {len(MISSING)} DLL(s) missing from the build tree; "
              f"the agent will not load without them", file=sys.stderr)
        return 1

    # Write stamp file so custom_target is satisfied
    stamp = os.path.join(build, '.dlls_deployed')
    with open(stamp, 'w') as f:
        f.write(f'copied {copied} items\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
