#!/usr/bin/env python3
"""Deploy vcpkg dependency DLLs and plugin DLLs into build output directories.

Called by meson.build at configure time and as a custom_target at build time.

  --build-root     Path to the Meson build directory
  --vcpkg-bin      Explicit path to vcpkg DLL directory (preferred)
  --triplet        vcpkg triplet (default: x64-windows)
  --debug          Use debug DLL directory (fallback detection only)
"""

import argparse
import contextlib
import glob
import os
import shutil
import sys
import tempfile


# Copies that failed, filled in by copy_newer() and reported by main():
#   MISSING - the build tree lacks the DLL or holds one that is not a good
#             copy: main() exits 1 (the Meson custom_target fails; the
#             configure-time run reports a warning). Every failure that is
#             not STALE is MISSING, whether or not an older copy remains.
#   STALE   - the copy was refused with PermissionError and an older
#             destination exists, usually because a running yuzu-agent has it
#             loaded: main() warns on stderr and carries on, as before, so a
#             developer can rebuild with the agent running. The destination
#             was not touched, so the older copy is still in the tree, whole.
MISSING = []
STALE = []

# Where a vcpkg checkout is looked for when neither --vcpkg-bin nor
# VCPKG_ROOT names one ("~" is expanded).
VCPKG_FALLBACK_ROOTS = ('~/vcpkg', 'C:/vcpkg', 'C:/src/vcpkg')


def copy_newer(src, dst_dir):
    """Copy src into dst_dir if the destination is missing or older.

    The copy is written under a temporary name in dst_dir and then renamed
    onto the destination (os.replace), so a copy that fails part-way (a full
    disk) leaves the destination as it was, never a truncated DLL with a newer
    mtime that no later run would replace. The temporary file is removed on
    any failure, including an exception that is not an OSError (an interrupt),
    which is then re-raised.
    """
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, os.path.basename(src))
    tmp = None
    try:
        if os.path.exists(dst) and os.path.getmtime(src) <= os.path.getmtime(dst):
            return
        fd, tmp = tempfile.mkstemp(dir=dst_dir, prefix='.deploy_', suffix='.tmp')
        os.close(fd)
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)
        tmp = None
    except OSError as e:
        # A DLL locked by a running process (PermissionError) used to be
        # swallowed here whether or not an older copy existed, so a copy that
        # never happened left the build tree without the DLL and nothing said
        # so. Record it instead; main() decides how loud to be.
        stale = isinstance(e, PermissionError) and os.path.isfile(dst)
        (STALE if stale else MISSING).append((src, dst, e))
    finally:
        if tmp is not None:
            with contextlib.suppress(OSError):
                os.remove(tmp)


def find_vcpkg_dll_dir(explicit_bin, triplet, debug):
    """Return the vcpkg DLL directory, trying explicit path first."""
    if explicit_bin and os.path.isdir(explicit_bin):
        return explicit_bin

    # Fallback: derive from VCPKG_ROOT
    root = os.environ.get('VCPKG_ROOT', '')
    if not root or not os.path.isdir(root):
        for candidate in (os.path.expanduser(c) for c in VCPKG_FALLBACK_ROOTS):
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
            kept = " (the older copy there is unchanged)" if os.path.isfile(dst) else ""
            print(f"deploy_build_dlls: ERROR: could not copy {src} to {dst}{kept}: {e}", file=sys.stderr)
        print(f"deploy_build_dlls: {len(MISSING)} DLL(s) missing from the build tree or not "
              f"brought up to date; the agent may not load or may load an older copy", file=sys.stderr)
        return 1

    # Write stamp file so custom_target is satisfied
    stamp = os.path.join(build, '.dlls_deployed')
    with open(stamp, 'w') as f:
        f.write(f'copied {copied} items\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
