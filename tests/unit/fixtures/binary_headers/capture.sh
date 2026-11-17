#!/bin/sh
# Rebuilds one family of binary-header fixtures from src/ and writes them next to this script.
# Usage: capture.sh macho | elf | pe     (run each on its own OS; see provenance.txt)
#   macho  needs cc (Xcode CLT) on macOS
#   elf    needs gcc on Linux
#   pe     needs cl, rc and link on PATH (an MSVC x64 environment) from a POSIX shell such as MSYS2
# Each output's first 4096 bytes are also copied into the matching fuzz corpus (the smoke test
# replays with -max_len=4096). Paths are relative to this directory; no debug info is emitted.
set -eu

here=$(dirname "$0")
cd "$here"
corpus_root=../../../fuzz/corpus

usage() {
    echo "usage: capture.sh macho|elf|pe" >&2
    exit 2
}

[ $# -eq 1 ] || usage
case "$1" in
macho | elf | pe) ;;
*) usage ;;
esac

work=$(mktemp -d ./scratch.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM

# seed <family> <output>... : copy the first 4096 bytes of each output into the family's corpus.
seed() {
    family=$1
    shift
    dir=$corpus_root/fuzz_binary_header_$family
    mkdir -p "$dir"
    for f in "$@"; do
        head -c 4096 "$f" >"$dir/$f"
    done
}

case "$1" in
macho)
    cc -dynamiclib -arch arm64 -install_name @rpath/libyuzu_fixture.1.dylib \
        -current_version 1.2.3 -compatibility_version 1.0.0 \
        -o macho_thin.bin src/yuzu_fixture.c
    cc -dynamiclib -arch arm64 -arch x86_64 -install_name @rpath/libyuzu_fixture.1.dylib \
        -current_version 1.2.3 -compatibility_version 1.0.0 \
        -o macho_fat.bin src/yuzu_fixture.c
    seed macho macho_thin.bin macho_fat.bin
    ;;
elf)
    gcc -shared -fPIC -nostdlib -Wl,-soname,libyuzu_fixture.so.1 -Wl,--build-id=sha1 \
        -Wl,-z,max-page-size=4096 -o elf_shared.bin src/yuzu_fixture.c
    seed elf elf_shared.bin
    ;;
pe)
    cl /nologo /c /GS- "/Fo$work/yuzu_fixture.obj" src/yuzu_fixture.c
    rc /nologo "/fo$work/yuzu_fixture.res" src/yuzu_fixture.rc
    link /nologo /dll /noentry /nodefaultlib /machine:x64 "/out:pe_version.bin" \
        "$work/yuzu_fixture.obj" "$work/yuzu_fixture.res"
    seed pe pe_version.bin
    ;;
esac
