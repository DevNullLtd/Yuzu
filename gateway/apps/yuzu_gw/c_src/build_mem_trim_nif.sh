#!/bin/sh
# Builds priv/yuzu_gw_mem_trim_nif.so. Run by the "-linux-gnu-" pre_hook in
# ../rebar.config, so only on a glibc Linux target; never by hand on musl,
# macOS or Windows. A script rather than an inline hook command because
# rebar3 runs only the first command of a hook string ("a && b" runs a).
#
# Fails (and so fails `rebar3 compile`) when no C compiler is found: every
# glibc build path has one, and shipping without the .so would go unnoticed.
# CC overrides the compiler. The output goes to a temporary name and is
# renamed, so parallel rebar3 runs (the Meson eunit shards) sharing this
# priv/ never load a half-written file.
set -eu
cd "$(dirname "$0")/.."
: "${ERLANG_ROOT_DIR:?set by rebar3 for hooks}"
: "${ERLANG_ERTS_VER:?set by rebar3 for hooks}"
mkdir -p priv
tmp="priv/yuzu_gw_mem_trim_nif.so.tmp.$$"
trap 'rm -f "$tmp"' EXIT
# shellcheck disable=SC2086 # CC may be several words ("ccache gcc")
${CC:-cc} -O2 -fPIC -shared -Wall -Wextra -Werror \
    -I"$ERLANG_ROOT_DIR/erts-$ERLANG_ERTS_VER/include" \
    -o "$tmp" c_src/yuzu_gw_mem_trim_nif.c
mv -f "$tmp" priv/yuzu_gw_mem_trim_nif.so
