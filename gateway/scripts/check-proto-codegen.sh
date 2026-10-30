#!/usr/bin/env bash
#
# check-proto-codegen.sh — F-3 (#1243): fail if the committed gateway protobuf
# modules (apps/yuzu_gw/src/*_pb.erl) have drifted from priv/proto.
#
# Why this exists: the gateway carries its OWN gpb-generated copies of the proto
# modules (separate from the server's protoc output). gpb modules are
# self-contained — if a field is added to a .proto but a module is not
# regenerated, the gateway silently stops carrying that field across transit
# (this is exactly the per-agent-enrollment CSR field-drop bug PR5 fixed). This
# guard converts that silent drift into a hard CI failure.
#
# How: regenerate every top-level proto with the EXACT gpb_opts read from
# rebar.config (via file:consult, so the guard cannot drift from the build's own
# options) into a temp dir, then byte-diff against the committed modules. gpb is
# version-pinned in rebar.config (4.21.7) + target_erlang_version is fixed, so
# the output is deterministic and reproducible across machines.
#
# It ALSO guards flat<->nested mirror drift: each .proto exists as a flat top-level
# copy (priv/proto/<x>.proto, the regen source for <x>_pb) AND a package-pathed
# copy (priv/proto/yuzu/<pkg>/v1/<x>.proto, the import target gpb resolves when
# another proto does `import "yuzu/<pkg>/v1/<x>.proto"`). gateway.proto and
# management.proto import the nested agent.proto, so gateway_pb/management_pb are
# generated from the nested copy while agent_pb comes from the flat copy — if the
# two copies' message defs diverge, agent_pb carries a field the gateway proxy
# drops. The top-level regen above cannot see this (it only reads the flat copy),
# so the nested loop below generates each nested copy and byte-diffs its module
# against the flat-generated one (gpb strips comments, so comment-only differences
# between the copies are ignored — only structure is compared).
#
# Prereq: `rebar3 compile` (or any rebar3 run that fetches deps) must have
# populated _build so gpb's ebin is available. CI runs this right after the
# gateway compile step.
#
# Usage: bash scripts/check-proto-codegen.sh   (from the gateway/ dir or anywhere)
set -euo pipefail

# Resolve to the gateway root regardless of CWD.
cd "$(dirname "$0")/.."

SRC="apps/yuzu_gw/src"
PROTO_DIR="priv/proto"
# Register the cleanup trap immediately after the FIRST mktemp so a failure of the
# second (under set -e) cannot leak the first dir; ${TMP_NESTED:-} tolerates the
# trap firing before the second assignment completes.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP" "${TMP_NESTED:-}"' EXIT
TMP_NESTED="$(mktemp -d)"

if [ ! -d "$PROTO_DIR" ]; then
    echo "ERROR: $PROTO_DIR not found — run from the gateway project root." >&2
    exit 2
fi

GPB_EBIN="$(find _build -path '*/gpb/ebin' -type d 2>/dev/null | head -1)"
if [ -z "$GPB_EBIN" ]; then
    echo "ERROR: gpb ebin not found under _build/. Run 'rebar3 compile' first." >&2
    exit 2
fi

# Regenerate every TOP-LEVEL proto (the package-pathed copies under
# priv/proto/yuzu/<pkg>/v1/ are import targets, not compiled directly HERE — they
# share basenames with the top-level files and would collide on module name. The
# nested loop below DOES compile them, one at a time into a separate temp dir,
# precisely to drift-check them against these flat-generated modules).
erl -noshell -pa "$GPB_EBIN" -eval "
    {ok, Terms} = file:consult(\"rebar.config\"),
    Grpc = proplists:get_value(grpc, Terms, []),
    GpbOpts = proplists:get_value(gpb_opts, Grpc, []),
    Opts = GpbOpts ++ [{i, \"$PROTO_DIR\"}, {o_erl, \"$TMP\"}, {o_hrl, \"$TMP\"}],
    Protos = filelib:wildcard(\"$PROTO_DIR/*.proto\"),
    case Protos of
        [] -> io:format(standard_error, \"::error::no top-level protos in $PROTO_DIR~n\", []), halt(3);
        _  -> ok
    end,
    lists:foreach(fun(P) ->
        Base = filename:basename(P),
        case gpb_compile:file(Base, Opts) of
            ok -> ok;
            Err ->
                io:format(standard_error, \"gpb_compile ~s failed: ~p~n\", [Base, Err]),
                halt(3)
        end
    end, Protos),
    halt(0).
" || { echo "ERROR: proto regeneration failed (see above)." >&2; exit 3; }

drift=0
for regen in "$TMP"/*_pb.erl; do
    [ -e "$regen" ] || continue
    name="$(basename "$regen")"
    committed="$SRC/$name"
    if [ ! -f "$committed" ]; then
        echo "::error::regenerated $name has no committed counterpart in $SRC" >&2
        drift=1
        continue
    fi
    if ! diff -u "$committed" "$regen"; then
        echo "::error::gateway proto codegen drift in $name" >&2
        drift=1
    fi
done

# Nested import-target consistency. Each proto exists as a flat top-level copy
# (priv/proto/<x>.proto, regenerated above into $TMP) AND a package-pathed mirror
# (priv/proto/yuzu/<pkg>/v1/<x>.proto), the import target gpb resolves for
# `import "yuzu/<pkg>/v1/<x>.proto"`. gateway.proto and management.proto import
# the NESTED agent.proto, so gateway_pb/management_pb are built from the nested
# agent copy while agent_pb is built from the flat copy — if the two agent copies'
# message defs diverge, agent_pb carries a field the gateway proxy drops (the
# csr_pem field-drop class; ADR-0016 added content_hashes/need_full to BOTH copies
# for exactly this reason). The flat regen above cannot see this divergence.
#
# Guard: generate each nested copy on its own and byte-diff its module against the
# flat-generated one. The load-bearing comparisons are the LEAF pairs (agent,
# common) — a divergence there is what skews agent_pb from the copy gateway_pb/
# management_pb embed. The gateway/management pairs are drift-invariant to the
# agent copy (both their flat and nested forms import the SAME nested agent.proto),
# so those pairs only catch drift between a wrapper proto's own two copies. gpb
# output is comment- and whitespace-free, so comment-only differences between the
# copies (which exist today) are ignored — only message/field structure compares.
nested_checked=0
while IFS= read -r nested; do
    [ -e "$nested" ] || continue
    flat="$PROTO_DIR/$(basename "$nested")"
    # nested proto with no flat mirror is compiled only via its import path; skip.
    [ -f "$flat" ] || continue
    rm -rf "$TMP_NESTED"
    mkdir -p "$TMP_NESTED"
    erl -noshell -pa "$GPB_EBIN" -eval "
        {ok, Terms} = file:consult(\"rebar.config\"),
        Grpc = proplists:get_value(grpc, Terms, []),
        GpbOpts = proplists:get_value(gpb_opts, Grpc, []),
        Opts = GpbOpts ++ [{i, \"$PROTO_DIR\"}, {o_erl, \"$TMP_NESTED\"}, {o_hrl, \"$TMP_NESTED\"}],
        case gpb_compile:file(\"$nested\", Opts) of
            ok -> halt(0);
            Err ->
                io:format(standard_error, \"gpb_compile ~s failed: ~p~n\", [\"$nested\", Err]),
                halt(3)
        end.
    " || { echo "ERROR: nested proto regeneration failed for $nested." >&2; exit 3; }
    for nested_gen in "$TMP_NESTED"/*_pb.erl; do
        [ -e "$nested_gen" ] || continue
        gen_name="$(basename "$nested_gen")"
        flat_gen="$TMP/$gen_name"
        if [ ! -f "$flat_gen" ]; then
            echo "::error::nested $nested generates $gen_name but no flat top-level proto produced it" >&2
            drift=1
            continue
        fi
        nested_checked=$((nested_checked + 1))
        if ! diff -u "$flat_gen" "$nested_gen"; then
            echo "::error::flat/nested proto drift: priv/proto/$(basename "$nested") vs $nested generate different $gen_name" >&2
            drift=1
        fi
    done
done < <(find "$PROTO_DIR/yuzu" -name '*.proto' 2>/dev/null | sort)

# Fail closed if the mirror set vanished (priv/proto/yuzu restructured/removed, or
# find returned nothing): a drift guard that silently no-ops is worse than none.
# Mirrors the flat loop's empty-set floor (the halt(3) on an empty wildcard above).
if [ "$nested_checked" -eq 0 ]; then
    echo "::error::no flat/nested proto mirror pairs were compared — priv/proto/yuzu/<pkg>/v1/ layout changed or find returned nothing. Refusing to pass: the mirror-drift guard would silently stop guarding." >&2
    exit 3
fi

if [ "$drift" -ne 0 ]; then
    echo "" >&2
    echo "Gateway proto codegen check failed. One or more of the following (see the" >&2
    echo "'::error::' lines above for the specific file):" >&2
    echo "  • 'gateway proto codegen drift in <x>_pb.erl' / 'regenerated <x>_pb.erl has" >&2
    echo "    no committed counterpart' — a committed module under apps/yuzu_gw/src is" >&2
    echo "    stale vs (or missing for) priv/proto. Regenerate + commit:" >&2
    echo "        cd gateway && escript regen_pb.escript" >&2
    echo "  • 'flat/nested proto drift: priv/proto/<x>.proto vs ...' — the flat copy" >&2
    echo "    and its package-pathed mirror under priv/proto/yuzu/<pkg>/v1/ disagree" >&2
    echo "    on message/field structure. Edit BOTH copies in lockstep so the field" >&2
    echo "    survives the gateway proxy re-encode, then regenerate the _pb modules." >&2
    echo "  • 'nested <x> generates <y> but no flat top-level proto produced it' — a" >&2
    echo "    nested mirror's basename has no matching flat proto (layout/rename" >&2
    echo "    mismatch); restore the flat counterpart or align the basenames." >&2
    echo "(gpb is version-pinned in rebar.config, so a matching toolchain reproduces these exactly.)" >&2
    exit 1
fi

echo "OK: all gateway _pb.erl match priv/proto, and flat/nested proto mirrors agree."
