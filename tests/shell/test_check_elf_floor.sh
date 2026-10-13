#!/usr/bin/env bash
# test_check_elf_floor.sh -- contract net for scripts/ci/check-elf-floor.sh
# (ADR-2003 slice S0), the Linux native-build floor gate.
#
# Builds tiny ELFs at test time with gcc. Symbol VERSIONS are synthesised, not
# inherited from the build host: a fake shared library carries a linker
# version script defining nodes such as GLIBC_2.38 / GLIBCXX_3.4.99 /
# LIBSYSTEMD_241 / OPENSSL_3.0.0, and fixture executables (-nostdlib, so no
# host-glibc tags leak in) import symbols from those nodes. Nothing is run.
#
# WHAT IT PINS
#   clean tree passes in both modes; numeric (not string) version comparison
#   violation reported; report-only exits 0, --enforce exits 1
#   exact-tag allow-list (LIBSYSTEMD_240 ok, _241 not)
#   forbidden symbol (EVP_sm4_*), imported versioned AND unversioned
#   absolute / relative / mixed RUNPATH and old-style RPATH; $ORIGIN ok
#   empty dir, text-only dir: warning in report-only, error in enforce
#   non-ELF files skipped; static and stripped ELFs; truncated ELF unreadable
#   a tag required from two libraries (libc + libm) is one tag
#   deterministic output (same stdout, same baseline bytes, path-independent)
#   --emit-baseline: content, merge of several sets, refusal to merge into junk
#   --include / --exclude
#   usage errors exit 2 in both modes (a broken call must not look clean)
#   GitHub annotations + job summary, and that a hostile file name cannot
#   inject a workflow command
#   the shipped floor files and the measured-baseline file parse and agree
#
# Run:  bash tests/shell/test_check_elf_floor.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/check-elf-floor.sh"
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 2; }

# Without a toolchain the fixtures cannot be built. Locally that is a skip;
# in CI it is a failure, because a skipped gate test reads as a green one.
for tool in gcc objdump readelf strip python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
      echo "FAIL: $tool is required to build the ELF fixtures" >&2; exit 1
    fi
    echo "SKIP: $tool not found; cannot build ELF fixtures" >&2; exit 0
  fi
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_elf_floor.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"
    [ -f "$TMP/out" ] && sed 's/^/         | /' "$TMP/out" | head -40; fail=$((fail+1)); fi
}
has() { grep -qF -- "$1" "${2:-$TMP/out}" && echo yes || echo no; }

# run <args...>: sets rc, writes stdout+stderr to $TMP/out. GITHUB_* scrubbed
# so a CI runner's own env cannot change what is asserted.
run() {
  rc=0
  env -u GITHUB_ACTIONS -u GITHUB_STEP_SUMMARY bash "$SCRIPT" "$@" > "$TMP/out" 2>&1 || rc=$?
}

# ---- fixtures ---------------------------------------------------------------
F="$TMP/fx"; mkdir -p "$F"
cat > "$F/lib.c" <<'EOF'
int sym_ok(void){return 1;}
int sym_old(void){return 2;}
int sym_new(void){return 3;}
int sym_cxx_new(void){return 4;}
int sym_sd_240(void){return 5;}
int sym_sd_241(void){return 6;}
int EVP_sm4_cbc(void){return 7;}
int plain_sym(void){return 8;}
EOF
cat > "$F/lib.map" <<'EOF'
GLIBC_2.9    { global: sym_old; };
GLIBC_2.28   { global: sym_ok; };
GLIBC_2.38   { global: sym_new; } GLIBC_2.28;
GLIBCXX_3.4.99 { global: sym_cxx_new; };
LIBSYSTEMD_240 { global: sym_sd_240; };
LIBSYSTEMD_241 { global: sym_sd_241; };
OPENSSL_3.0.0  { global: EVP_sm4_cbc; };
EOF
gcc -shared -fPIC -o "$F/libfake.so" "$F/lib.c" -Wl,--version-script="$F/lib.map" \
  -Wl,-soname,libfake.so || { echo "cannot build fake lib" >&2; exit 2; }

# shellcheck disable=SC2016  # the literal RUNPATH token, not a variable
ORIGIN='$ORIGIN'

# mkexe <out> <rpath-or-empty> <call>...   (-nostdlib: imports only the calls)
mkexe() {
  local out="$1" rp="$2"; shift 2
  local src="$F/src_$$_$RANDOM.c" body="" decl="" c
  for c in "$@"; do decl+="int $c(void); "; body+="$c(); "; done
  printf '%s\nvoid _start(void){ %s for(;;); }\n' "$decl" "$body" > "$src"
  local flags=(-nostdlib -o "$out" "$src" -L"$F" -lfake)
  case "$rp" in
    old:*) flags+=("-Wl,--disable-new-dtags" "-Wl,-rpath,${rp#old:}") ;;
    '')    ;;
    *)     flags+=("-Wl,--enable-new-dtags" "-Wl,-rpath,$rp") ;;
  esac
  gcc "${flags[@]}" || { echo "cannot build $out" >&2; exit 2; }
}

cat > "$TMP/floor.json" <<'EOF'
{
  "schema": 1, "name": "testfloor",
  "max": { "GLIBC": "2.28", "GLIBCXX": "3.4.25", "LIBSYSTEMD": "239" },
  "allow": [ "LIBSYSTEMD_240" ],
  "forbidden_symbols": [ "EVP_sm4_*" ],
  "unlisted_families": "report"
}
EOF
FLOOR="$TMP/floor.json"

# clean/: imports at/below the floor, the allowed LIBSYSTEMD_240, an
# unversioned symbol, and a $ORIGIN-anchored RUNPATH. GLIBC_2.9 < 2.28
# numerically but "2.9" > "2.28" as a string: pins the tuple comparison.
mkdir -p "$TMP/clean/bin" "$TMP/clean/plugins"
mkexe "$TMP/clean/bin/ok" "$ORIGIN/../lib" sym_ok sym_old sym_sd_240 plain_sym
cp "$TMP/clean/bin/ok" "$TMP/clean/plugins/also_ok.so"
printf '#!/bin/sh\necho hi\n' > "$TMP/clean/bin/script.sh"
printf 'not an elf, despite the name\n' > "$TMP/clean/plugins/fake.so"
: > "$TMP/clean/empty.file"

# bad/: one ELF per defect class
mkdir -p "$TMP/bad/bin"
mkexe "$TMP/bad/bin/glibc_new"  ''  sym_ok sym_new
mkexe "$TMP/bad/bin/cxx_new"    ''  sym_cxx_new
mkexe "$TMP/bad/bin/sd_241"     ''  sym_sd_241 sym_sd_240
mkexe "$TMP/bad/bin/sm4"        ''  EVP_sm4_cbc
mkexe "$TMP/bad/bin/abs_rpath"  '/opt/evil'       sym_ok
mkexe "$TMP/bad/bin/rel_rpath"  'lib'             sym_ok
mkexe "$TMP/bad/bin/mixed"      "/opt/x:$ORIGIN"  sym_ok
mkexe "$TMP/bad/bin/old_rpath"  'old:/opt/legacy' sym_ok

echo "check-elf-floor.sh:"

# ---- clean pass --------------------------------------------------------------
run --floor "$FLOOR" --dir "$TMP/clean"
check "clean tree, default mode: exit 0" 0 "$rc"
check "clean tree: reports 2 ELFs" yes "$(has 'ELF files scanned: 2 ')"
check "clean tree: non-ELF files skipped and counted (3)" yes "$(has 'non-ELF skipped: 3')"
check "clean tree: no violation lines" no "$(has 'above-floor')"
run --floor "$FLOOR" --dir "$TMP/clean" --enforce
check "clean tree, --enforce: exit 0" 0 "$rc"
check "clean tree, --enforce: RESULT: OK" yes "$(has 'RESULT: OK')"
check "numeric compare: GLIBC_2.9 is below 2.28" no "$(has 'GLIBC_2.9')"
check "allow-list: LIBSYSTEMD_240 not flagged" no "$(has 'LIBSYSTEMD_240 ')"

# ---- violations: report-only vs enforce -----------------------------------------
run --floor "$FLOOR" --dir "$TMP/bad"
check "violations, default mode: exit 0" 0 "$rc"
run --floor "$FLOOR" --dir "$TMP/bad" --report-only
check "violations, --report-only: exit 0" 0 "$rc"
check "report-only still prints the violation" yes "$(has 'bin/glibc_new: above-floor GLIBC_2.38 (floor GLIBC_2.28): sym_new')"
check "report-only labels itself" yes "$(has 'report-only, ')"
check "libstdc++ tag above floor reported" yes "$(has 'bin/cxx_new: above-floor GLIBCXX_3.4.99')"
check "LIBSYSTEMD_241 flagged (allow is by exact tag)" yes "$(has 'bin/sd_241: above-floor LIBSYSTEMD_241')"
check "LIBSYSTEMD_240 on the same ELF not flagged" no "$(has 'sd_241: above-floor LIBSYSTEMD_240')"
run --floor "$FLOOR" --dir "$TMP/bad" --enforce
check "violations, --enforce: exit 1" 1 "$rc"
check "--enforce: RESULT: FAIL" yes "$(has 'RESULT: FAIL')"

# ---- forbidden symbol ------------------------------------------------------------
check "forbidden symbol reported" yes "$(has 'bin/sm4: forbidden-symbol: EVP_sm4_cbc')"
mkdir -p "$TMP/sm4only"; cp "$TMP/bad/bin/sm4" "$TMP/sm4only/"
run --floor "$FLOOR" --dir "$TMP/sm4only" --enforce
check "forbidden symbol alone fails --enforce" 1 "$rc"
# the same name imported WITHOUT a version tag (blank column) is still caught
echo 'int EVP_sm4_ecb(void){return 1;}' > "$F/unvlib.c"
gcc -shared -fPIC -o "$F/libunv.so" "$F/unvlib.c" -Wl,-soname,libunv.so
echo 'int EVP_sm4_ecb(void); void _start(void){ EVP_sm4_ecb(); for(;;); }' > "$F/unv.c"
mkdir -p "$TMP/unversioned"
gcc -nostdlib -o "$TMP/unversioned/u" "$F/unv.c" -L"$F" -lunv
run --floor "$FLOOR" --dir "$TMP/unversioned" --enforce
check "unversioned forbidden import caught" 1 "$rc"
check "unversioned forbidden import named" yes "$(has 'EVP_sm4_ecb')"

# ---- RUNPATH / RPATH -------------------------------------------------------------
run --floor "$FLOOR" --dir "$TMP/bad" --enforce
check "absolute RUNPATH flagged" yes "$(has "bin/abs_rpath: runpath not \$ORIGIN-anchored: '/opt/evil'")"
check "bare relative RUNPATH flagged" yes "$(has "bin/rel_rpath: runpath not \$ORIGIN-anchored: 'lib'")"
check "mixed RUNPATH flags only the bad entry" yes "$(has "bin/mixed: runpath not \$ORIGIN-anchored: '/opt/x'")"
check "old-style RPATH flagged" yes "$(has "bin/old_rpath: runpath not \$ORIGIN-anchored: '/opt/legacy'")"
check "\$ORIGIN-relative RUNPATH not flagged" no "$(has 'bin/ok: runpath')"
mkdir -p "$TMP/rponly"; cp "$TMP/bad/bin/abs_rpath" "$TMP/rponly/"
run --floor "$FLOOR" --dir "$TMP/rponly" --enforce
check "absolute RUNPATH alone fails --enforce" 1 "$rc"

# ---- empty scans ----------------------------------------------------------------
mkdir -p "$TMP/empty"
run --floor "$FLOOR" --dir "$TMP/empty"
check "empty dir, report-only: exit 0" 0 "$rc"
check "empty dir, report-only: says so" yes "$(has 'PROBLEM: no ELF files found')"
run --floor "$FLOOR" --dir "$TMP/empty" --enforce
check "empty dir, --enforce: exit 1" 1 "$rc"
check "empty dir, --enforce: RESULT: FAIL, not OK" yes "$(has 'RESULT: FAIL')"
mkdir -p "$TMP/textonly"; echo hello > "$TMP/textonly/a.txt"
run --floor "$FLOOR" --dir "$TMP/textonly" --enforce
check "text-only dir, --enforce: exit 1" 1 "$rc"
run --floor "$FLOOR" --dir "$TMP/clean" --exclude '*' --enforce
check "--exclude removing every ELF is an empty scan: exit 1" 1 "$rc"

# ---- static, stripped, truncated -------------------------------------------------
mkdir -p "$TMP/odd"
echo 'void _start(void){for(;;);}' > "$F/st.c"
gcc -static -nostdlib -ffreestanding -o "$TMP/odd/static_exe" "$F/st.c"
strip -o "$TMP/odd/stripped" "$TMP/bad/bin/glibc_new"
run --floor "$FLOOR" --dir "$TMP/odd" --enforce
check "stripped ELF still gated (violation found)" yes "$(has 'stripped: above-floor GLIBC_2.38')"
check "static ELF scanned without error" yes "$(has 'static/no dynamic section: 1')"
check "static ELF has no violation of its own" no "$(has 'static_exe:')"
mkdir -p "$TMP/trunc"; head -c 100 "$TMP/clean/bin/ok" > "$TMP/trunc/cut"
run --floor "$FLOOR" --dir "$TMP/trunc" --enforce
check "truncated ELF, --enforce: exit 1" 1 "$rc"
check "truncated ELF is 'unreadable', not static" yes "$(has 'cut: unreadable')"
run --floor "$FLOOR" --dir "$TMP/trunc"
check "truncated ELF, report-only: exit 0" 0 "$rc"
mkdir -p "$TMP/linked"; ln -s "$TMP/bad/bin/glibc_new" "$TMP/linked/sym"
run --floor "$FLOOR" --dir "$TMP/linked" --enforce
check "symlinks are not followed (nothing scanned = empty scan)" 1 "$rc"
check "symlinks are not followed: no violation from the target" no "$(has 'above-floor')"

# ---- one tag from two libraries ---------------------------------------------------
cat > "$F/two.c" <<'EOF'
#include <math.h>
#include <stdio.h>
int main(int argc, char **argv) { volatile double x = argc; printf("%f", sin(x)); return 0; }
EOF
mkdir -p "$TMP/two"
gcc -o "$TMP/two/both" "$F/two.c" -lm
cat > "$TMP/floor_loose.json" <<'EOF'
{ "schema": 1, "name": "loose", "max": { "GLIBC": "99.0" } }
EOF
run --floor "$TMP/floor_loose.json" --dir "$TMP/two" --enforce --full-report "$TMP/two.full.json"
check "libc+libm binary under a loose floor: exit 0" 0 "$rc"
n="$(python3 -I - "$TMP/two.full.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
imp = d["artifacts"]["both"]["imports"]
# libm's `sin` and libc's `printf`-family both carry a GLIBC_2.x tag; the
# same tag name must appear exactly once as a key, with symbols merged.
tags = [t for t in imp if t.startswith("GLIBC_2.")]
print(len(tags) == len(set(tags)) and any("sin" in s for t in tags for s in imp[t]))
EOF
)"
check "shared version tag collapsed, libm symbol present" True "$n"

# ---- determinism --------------------------------------------------------------------
run --floor "$FLOOR" --dir "$TMP/bad"; cp "$TMP/out" "$TMP/out1"
run --floor "$FLOOR" --dir "$TMP/bad"
check "same input, same stdout" "$(cat "$TMP/out1")" "$(cat "$TMP/out")"
rm -rf "$TMP/bad_copy"; mkdir -p "$TMP/bad_copy"
# copy in reverse order to a different path: output must not depend on either
mkdir -p "$TMP/bad_copy/bin"
for f in "$TMP"/bad/bin/*; do echo "$f"; done | sort -r | while read -r f; do cp -p "$f" "$TMP/bad_copy/bin/"; done
rm -f "$TMP/b1.json" "$TMP/b2.json"
run --floor "$FLOOR" --dir "$TMP/bad" --emit-baseline "$TMP/b1.json" --source "fixture"
run --floor "$FLOOR" --dir "$TMP/bad_copy" --emit-baseline "$TMP/b2.json" --source "fixture"
check "baseline bytes independent of path and creation order" yes \
  "$(cmp -s "$TMP/b1.json" "$TMP/b2.json" && echo yes || echo no)"
check "baseline records no staging path" no "$(has "$TMP" "$TMP/b1.json")"

# ---- baseline emission / round-trip -------------------------------------------------
py() { python3 -I - "$@"; }
got="$(py "$TMP/b1.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["sets"]["testfloor"]
a = s["artifacts"]
print(d["schema"], s["floor"], s["source"], s["elf_count"], s["maxima"]["GLIBC"],
      s["maxima"]["GLIBCXX"], s["maxima"]["LIBSYSTEMD"],
      a["bin/glibc_new"]["offending"]["GLIBC_2.38"],
      a["bin/sm4"]["forbidden"], a["bin/abs_rpath"]["runpath"],
      "offending" in a["bin/abs_rpath"])
EOF
)"
check "baseline content: maxima, offending, forbidden, runpath" \
  "1 floor.json fixture 8 2.38 3.4.99 241 ['sym_new'] ['EVP_sm4_cbc'] ['/opt/evil'] False" "$got"
run --floor "$FLOOR" --dir "$TMP/clean" --set-name second --emit-baseline "$TMP/b1.json"
sets="$(py "$TMP/b1.json" <<'EOF'
import json, sys
print(sorted(json.load(open(sys.argv[1]))["sets"]))
EOF
)"
check "second set merged into the same file" "['second', 'testfloor']" "$sets"
cp "$TMP/b1.json" "$TMP/b1.before"
run --floor "$FLOOR" --dir "$TMP/bad" --emit-baseline "$TMP/b1.json" --source "fixture"
check "re-emitting an existing set is idempotent" yes "$(cmp -s "$TMP/b1.json" "$TMP/b1.before" && echo yes || echo no)"
echo '{"not":"a baseline"}' > "$TMP/junk.json"; cp "$TMP/junk.json" "$TMP/junk.before"
run --floor "$FLOOR" --dir "$TMP/clean" --emit-baseline "$TMP/junk.json"
check "refuses to merge into a non-baseline: exit 2" 2 "$rc"
check "refused merge leaves the file untouched" yes "$(cmp -s "$TMP/junk.json" "$TMP/junk.before" && echo yes || echo no)"

# ---- include / exclude --------------------------------------------------------------
run --floor "$FLOOR" --dir "$TMP/bad" --include 'bin/sm4' --enforce
check "--include narrows the scan to one ELF" yes "$(has 'ELF files scanned: 1 ')"
run --floor "$FLOOR" --dir "$TMP/bad" --exclude 'bin/*' --exclude 'x' --enforce
check "--exclude drops ELFs (here: all)" 1 "$rc"
run --floor "$FLOOR" --dir "$TMP/bad" --exclude 'bin/glibc_new' --exclude 'bin/cxx_new' --exclude 'bin/sd_241' --exclude 'bin/sm4' --exclude 'bin/abs_rpath' --exclude 'bin/rel_rpath' --exclude 'bin/mixed' --exclude 'bin/old_rpath'
check "--exclude applied (all excluded: empty-scan warning)" yes "$(has 'PROBLEM: no ELF')"

# ---- usage errors -------------------------------------------------------------------
run --dir "$TMP/clean"
check "missing --floor: exit 2" 2 "$rc"
run --floor "$FLOOR"
check "missing --dir: exit 2" 2 "$rc"
run --floor "$FLOOR" --dir "$TMP/nonexistent"
check "nonexistent --dir: exit 2 even in report-only" 2 "$rc"
run --floor "$TMP/nonexistent.json" --dir "$TMP/clean"
check "nonexistent floor file: exit 2" 2 "$rc"
echo '{ not json' > "$TMP/bad_floor.json"
run --floor "$TMP/bad_floor.json" --dir "$TMP/clean"
check "unparseable floor file: exit 2" 2 "$rc"
echo '{"schema":1,"name":"x","max":{"GLIBC":"two"}}' > "$TMP/bad_floor2.json"
run --floor "$TMP/bad_floor2.json" --dir "$TMP/clean"
check "non-numeric floor version: exit 2" 2 "$rc"
run --floor "$FLOOR" --dir "$TMP/clean" --enforce --report-only
check "--enforce with --report-only: exit 2" 2 "$rc"
rc=0; OBJDUMP=/nonexistent/objdump bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/clean" > "$TMP/out" 2>&1 || rc=$?
check "missing objdump: exit 2 even in report-only" 2 "$rc"

# ---- unlisted families ---------------------------------------------------------------
cat > "$TMP/floor_strict.json" <<'EOF'
{ "schema": 1, "name": "strict", "max": { "GLIBC": "2.28" }, "unlisted_families": "fail" }
EOF
run --floor "$TMP/floor_strict.json" --dir "$TMP/clean" --enforce
check "unlisted_families=fail: a family absent from max is a violation" 1 "$rc"
run --floor "$FLOOR" --dir "$TMP/bad" --enforce --emit-baseline "$TMP/unl.json"
check "unlisted_families=report: no unlisted-family violation" no "$(has 'unlisted-family')"
check "unlisted_families=report: the family is listed in the baseline" yes \
  "$(py "$TMP/unl.json" <<'EOF'
import json, sys
a = json.load(open(sys.argv[1]))["sets"]["testfloor"]["artifacts"]
print("yes" if a["bin/sm4"].get("unlisted", {}).get("OPENSSL_3.0.0") == ["EVP_sm4_cbc"] else "no")
EOF
)"

# ---- GitHub Actions output ------------------------------------------------------------
rc=0; env GITHUB_ACTIONS=true GITHUB_STEP_SUMMARY="$TMP/summary.md" \
  bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/bad" > "$TMP/out" 2>&1 || rc=$?
check "GitHub, report-only: exit 0" 0 "$rc"
check "GitHub, report-only: ::warning:: annotation" yes "$(has '::warning title=Linux ELF floor (testfloor)::bin/glibc_new: above-floor GLIBC_2.38')"
check "GitHub, report-only: no ::error::" no "$(has '::error')"
check "job summary has the family table" yes "$(has '| GLIBC | 2.28 | 2.38 |' "$TMP/summary.md")"
check "job summary says report-only" yes "$(has 'report-only' "$TMP/summary.md")"
rc=0; env GITHUB_ACTIONS=true bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/bad" --enforce > "$TMP/out" 2>&1 || rc=$?
check "GitHub, --enforce: ::error:: annotation, exit 1" "1 yes" "$rc $(has '::error title=')"
rc=0; env GITHUB_ACTIONS=true bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/empty" > "$TMP/out" 2>&1 || rc=$?
check "GitHub, empty scan in report-only: ::warning::, exit 0" "0 yes" "$rc $(has '::warning title=')"
run --floor "$FLOOR" --dir "$TMP/bad"
check "no annotations outside GitHub Actions" no "$(has '::warning')"
rc=0; env GITHUB_ACTIONS=true GITHUB_STEP_SUMMARY=/nonexistent/dir/summary.md \
  bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/bad" > "$TMP/out" 2>&1 || rc=$?
check "unwritable job summary never fails the run" 0 "$rc"

# a file name carrying a newline and a fake workflow command must not start a
# log line of its own, nor survive unescaped in an annotation
mkdir -p "$TMP/hostile"
evil=$'a%b\n::error::pwned'
cp "$TMP/bad/bin/glibc_new" "$TMP/hostile/$evil"
rc=0; env GITHUB_ACTIONS=true bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/hostile" > "$TMP/out" 2>&1 || rc=$?
check "hostile name: no log line starts with ::error::" no \
  "$(grep -q '^::error' "$TMP/out" && echo yes || echo no)"
check "hostile name: rendered escaped" yes "$(has 'a%25b\x0a::error::pwned')"

# ---- shipped floor + baseline files ------------------------------------------------
for fl in agent server; do
  run --floor "$ROOT/deploy/packaging/linux-floor-$fl.json" --dir "$TMP/clean" --enforce
  check "shipped linux-floor-$fl.json loads and the clean tree passes it" 0 "$rc"
done
BL="$ROOT/deploy/packaging/linux-floor-baseline.json"
if [ -f "$BL" ]; then
  got="$(py "$BL" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
ok = d["schema"] == 1 and set(d["sets"]) >= {"agent", "server"}
for name, s in d["sets"].items():
    ok = ok and s["elf_count"] == len(s["artifacts"]) and s["elf_count"] > 0
print("yes" if ok else "no")
EOF
)"
  check "committed baseline is schema 1 with agent+server sets, counts consistent" yes "$got"
else
  check "committed baseline exists" yes no
fi

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
