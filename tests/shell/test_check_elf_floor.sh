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

# The fixtures are Linux ELFs: elsewhere (macOS dev boxes) there is nothing to
# scan. Locally a skip; in CI a failure, like a missing toolchain.
if [ "$(uname -s)" != Linux ]; then
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "FAIL: the ELF floor tests need a Linux host (uname -s = $(uname -s))" >&2; exit 1
  fi
  echo "SKIP: not a Linux host ($(uname -s)); the ELF fixtures need GNU binutils/ELF" >&2; exit 0
fi

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
trap 'chmod -R u+rwx "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

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
int sym_cxx_old(void){return 9;}
int sym_cxx_100(void){return 10;}
int sym_priv(void){return 11;}
EOF
cat > "$F/lib.map" <<'EOF'
GLIBC_2.9    { global: sym_old; };
GLIBC_2.28   { global: sym_ok; };
GLIBC_2.38   { global: sym_new; } GLIBC_2.28;
GLIBCXX_3.4.99 { global: sym_cxx_new; };
LIBSYSTEMD_240 { global: sym_sd_240; };
LIBSYSTEMD_241 { global: sym_sd_241; };
OPENSSL_3.0.0  { global: EVP_sm4_cbc; };
GLIBCXX_3.4.9  { global: sym_cxx_old; };
GLIBCXX_3.4.100 { global: sym_cxx_100; };
GLIBC_PRIVATE  { global: sym_priv; };
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
mkexe "$TMP/clean/bin/ok" "$ORIGIN/../lib" sym_ok sym_old sym_sd_240 plain_sym sym_cxx_old
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


# ---- governance round 1 additions ---------------------------------------------------
# lines the runner would execute as workflow commands: after stripping leading
# whitespace they start with `::`. Only the script's own annotations may.
cmd_lines() { sed 's/^[[:space:]]*//' "$TMP/out" | grep '^::' | grep -vcE '^::(warning|error) title=Linux ELF floor' || true; }

# an `objdump` that prints a crafted import (tag from $STUB_TAG); readelf stays real
mkdir -p "$TMP/stub"
cat > "$TMP/stub/objdump" <<'EOF'
#!/bin/sh
printf '\nx:     file format elf64-x86-64\n\nDYNAMIC SYMBOL TABLE:\n'
printf '0000000000000000      DF *UND*\t0000000000000000 (%s) sym_x\n' "$STUB_TAG"
EOF
chmod +x "$TMP/stub/objdump"
cat > "$TMP/stub/hang_objdump" <<'EOF'
#!/bin/sh
exec sleep 60
EOF
chmod +x "$TMP/stub/hang_objdump"

# 1. workflow-command injection through a PRINTABLE file name (indented line form)
mkdir -p "$TMP/inject"; cp "$TMP/bad/bin/glibc_new" "$TMP/inject/::error::x.so"
rc=0; env GITHUB_ACTIONS=true bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/inject" > "$TMP/out" 2>&1 || rc=$?
check "file name '::error::x.so': no log line is a workflow command" 0 "$(cmd_lines)"
check "file name '::error::x.so': still reported, marked" yes "$(has '|   ::error::x.so: above-floor')"
run --floor "$FLOOR" --dir "$TMP/inject" --enforce
check "file name '::error::x.so' outside Actions: no '::' line either" 0 "$(sed 's/^[[:space:]]*//' "$TMP/out" | grep -c '^::' || true)"
# ... and through a version-family at column 0 (crafted objdump output)
mkdir -p "$TMP/injfam"; cp "$TMP/clean/bin/ok" "$TMP/injfam/ok"
rc=0; env STUB_TAG='::error::pwn_1.0' OBJDUMP="$TMP/stub/objdump" GITHUB_ACTIONS=true \
  GITHUB_STEP_SUMMARY="$TMP/summary2.md" bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/injfam" > "$TMP/out" 2>&1 || rc=$?
check "family '::error::pwn' at column 0: no log line is a workflow command" 0 "$(cmd_lines)"
check "family '::error::pwn' still listed, marked" yes "$(has '| ::error::pwn')"
mkdir -p "$TMP/mdinj"; cp "$TMP/bad/bin/glibc_new" "$TMP/mdinj/a|b\`c.so"
rc=0; env GITHUB_ACTIONS=true GITHUB_STEP_SUMMARY="$TMP/summary3.md" \
  bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/mdinj" > "$TMP/out" 2>&1 || rc=$?
check "markdown table cell: pipe escaped, backtick removed" yes "$(has "| \`a\\|b'c.so\` |" "$TMP/summary3.md")"

# 2. an unreadable DIRECTORY is a problem, not a silently smaller scan
if [ "$(id -u)" -ne 0 ]; then
  mkdir -p "$TMP/unrd/sub" "$TMP/unrd/ok"; cp "$TMP/clean/bin/ok" "$TMP/unrd/ok/"
  cp "$TMP/bad/bin/glibc_new" "$TMP/unrd/sub/"; chmod 000 "$TMP/unrd/sub"
  run --floor "$FLOOR" --dir "$TMP/unrd"
  check "unreadable directory, report-only: exit 0" 0 "$rc"
  check "unreadable directory is named as a PROBLEM" yes "$(has 'PROBLEM: directory sub cannot be read')"
  check "report-only on an unreadable directory says 1 problem, not clean" yes "$(has '1 problem(s)')"
  run --floor "$FLOOR" --dir "$TMP/unrd" --enforce
  check "unreadable directory, --enforce: exit 1" 1 "$rc"
  chmod 755 "$TMP/unrd/sub"
else
  echo "  [skip] unreadable-directory test (running as root: chmod 000 does not block root)"
fi

# 3. a FIFO in the tree is never opened (a blocking open would hang the scan)
mkdir -p "$TMP/fifo"; cp "$TMP/clean/bin/ok" "$TMP/fifo/ok"; mkfifo "$TMP/fifo/trap.so"
rc=0; timeout 30 env -u GITHUB_ACTIONS bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/fifo" --enforce > "$TMP/out" 2>&1 || rc=$?
check "FIFO in tree: no hang, exit 0, scanned the real ELF" "0 yes" "$rc $(has 'ELF files scanned: 1 ')"

# 4. a 4300+ digit version tag must not crash the run (int() digit-limit ValueError)
big="$(python3 -c 'print("9" * 5000)')"
mkdir -p "$TMP/bigtag"; cp "$TMP/clean/bin/ok" "$TMP/bigtag/ok"
rc=0; env STUB_TAG="GLIBC_$big" OBJDUMP="$TMP/stub/objdump" bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/bigtag" > "$TMP/out" 2>&1 || rc=$?
check "5000-digit tag, report-only: exit 0, no traceback" "0 no" "$rc $(has 'Traceback')"
rc=0; env STUB_TAG="GLIBC_$big" OBJDUMP="$TMP/stub/objdump" bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/bigtag" --enforce > "$TMP/out" 2>&1 || rc=$?
check "5000-digit tag, --enforce: no traceback (a verbatim unlisted tag)" no "$(has 'Traceback')"

# 5. a 7-byte ELF stub is not 'static', it is unreadable
mkdir -p "$TMP/stub7"; printf '\177ELF\002\001\001' > "$TMP/stub7/tiny"
run --floor "$FLOOR" --dir "$TMP/stub7" --enforce
check "7-byte ELF header stub, --enforce: exit 1" 1 "$rc"
check "7-byte ELF header stub is 'unreadable', not static" yes "$(has 'tiny: unreadable: error: ELF magic but only 7 byte(s)')"
run --floor "$FLOOR" --dir "$TMP/stub7"
check "7-byte ELF header stub, report-only: exit 0" 0 "$rc"

# 6. --dir=-w must be a directory, never an option to readelf/objdump
mkdir -p "$TMP/cwd/-w"; cp "$TMP/clean/bin/ok" "$TMP/cwd/-w/ok"
rc=0; (cd "$TMP/cwd" && env -u GITHUB_ACTIONS bash "$SCRIPT" --floor "$FLOOR" --dir=-w --enforce) > "$TMP/out" 2>&1 || rc=$?
check "--dir=-w: scanned as a directory, exit 0" "0 yes" "$rc $(has 'ELF files scanned: 1 ')"

# 7. RUNPATH grammar: only $ORIGIN-anchored entries pass
mkdir -p "$TMP/rp/bin"
mkexe "$TMP/rp/bin/brace"  "\${ORIGIN}/lib"       sym_ok
mkexe "$TMP/rp/bin/bare"   "$ORIGIN"              sym_ok
mkexe "$TMP/rp/bin/bracebare" "\${ORIGIN}"       sym_ok
mkexe "$TMP/rp/bin/evil"   "${ORIGIN}evil"        sym_ok
mkexe "$TMP/rp/bin/empty"  "$ORIGIN:"             sym_ok
mkexe "$TMP/rp/bin/second" "$ORIGIN:/opt/x"       sym_ok
run --floor "$FLOOR" --dir "$TMP/rp" --enforce
check "RUNPATH \${ORIGIN}/lib (brace form) accepted" no "$(has 'bin/brace:')"
check "RUNPATH bare \$ORIGIN accepted" no "$(has 'bin/bare:')"
check "RUNPATH bare \${ORIGIN} accepted" no "$(has 'bin/bracebare:')"
check "RUNPATH \$ORIGINevil rejected" yes "$(has "bin/evil: runpath not \$ORIGIN-anchored: '\$ORIGINevil'")"
check "RUNPATH empty entry (\$ORIGIN:) rejected" yes "$(has "bin/empty: runpath not \$ORIGIN-anchored: ''")"
check "RUNPATH bad entry in second position rejected" yes "$(has "bin/second: runpath not \$ORIGIN-anchored: '/opt/x'")"

# 8. version arithmetic and unlisted tags
mkdir -p "$TMP/ver/bin"; mkexe "$TMP/ver/bin/w100" '' sym_cxx_100
run --floor "$FLOOR" --dir "$TMP/ver" --enforce
check "GLIBCXX_3.4.100 > 3.4.25 (last component compared numerically)" yes "$(has 'bin/w100: above-floor GLIBCXX_3.4.100')"
run --floor "$FLOOR" --dir "$TMP/clean" --enforce
check "GLIBCXX_3.4.9 < 3.4.25 (not a string comparison)" 0 "$rc"
mkdir -p "$TMP/priv/bin"; mkexe "$TMP/priv/bin/p" '' sym_priv
run --floor "$FLOOR" --dir "$TMP/priv" --enforce --emit-baseline "$TMP/priv.json"
check "GLIBC_PRIVATE (no numeric suffix) under unlisted_families=report: exit 0" 0 "$rc"
check "GLIBC_PRIVATE recorded verbatim as unlisted in the baseline" yes \
  "$(py "$TMP/priv.json" <<'EOF'
import json, sys
a = json.load(open(sys.argv[1]))["sets"]["testfloor"]["artifacts"]["bin/p"]
print("yes" if a.get("unlisted") == {"GLIBC_PRIVATE": ["sym_priv"]} and a["maxima"] == {} else "no")
EOF
)"
cat > "$TMP/floor_strict2.json" <<'EOF'
{ "schema": 1, "name": "strict2", "max": { "GLIBC": "2.28" }, "unlisted_families": "fail" }
EOF
run --floor "$TMP/floor_strict2.json" --dir "$TMP/priv" --enforce
check "GLIBC_PRIVATE under unlisted_families=fail: exit 1" "1 yes" "$rc $(has 'unlisted-family GLIBC_PRIVATE')"

# 9. --include and --exclude together
run --floor "$FLOOR" --dir "$TMP/bad" --include 'bin/*' --exclude 'bin/sm4' --enforce
check "--include + --exclude: 8 ELFs minus the excluded one" yes "$(has 'ELF files scanned: 7 ')"
check "--include + --exclude: the excluded ELF is not reported" no "$(has 'bin/sm4')"

# 10. floor schema other than 1 is a configuration error
echo '{"schema":2,"name":"x","max":{"GLIBC":"2.28"}}' > "$TMP/floor_s2.json"
run --floor "$TMP/floor_s2.json" --dir "$TMP/clean"
check "floor schema 2: exit 2" 2 "$rc"
echo '{"schema":1,"name":"x","max":{"GLIBC":"2.28"},"unlisted_families":"maybe"}' > "$TMP/floor_u.json"
run --floor "$TMP/floor_u.json" --dir "$TMP/clean"
check "floor unlisted_families other than report/fail: exit 2" 2 "$rc"

# 11. time bound: ELFs not reached are reported, never silently dropped
rc=0; env YUZU_ELF_FLOOR_DEADLINE=0 bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/clean" > "$TMP/out" 2>&1 || rc=$?
check "deadline 0, report-only: exit 0" 0 "$rc"
check "deadline: each unreached ELF is named unreadable" yes "$(has 'bin/ok: unreadable: error: not scanned (aggregate deadline exceeded)')"
check "deadline: one PROBLEM line says how many" yes "$(has 'PROBLEM: aggregate deadline of 0s exceeded: 2 of 2 ELF(s) not scanned')"
rc=0; env YUZU_ELF_FLOOR_DEADLINE=0 bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/clean" --enforce > "$TMP/out" 2>&1 || rc=$?
check "deadline 0, --enforce: exit 1" 1 "$rc"
rc=0; env YUZU_ELF_FLOOR_DEADLINE=bogus bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/clean" > "$TMP/out" 2>&1 || rc=$?
check "bad YUZU_ELF_FLOOR_DEADLINE: exit 2" 2 "$rc"
start=$SECONDS; rc=0
env YUZU_ELF_FLOOR_DEADLINE=2 OBJDUMP="$TMP/stub/hang_objdump" timeout 40 bash "$SCRIPT" --floor "$FLOOR" --dir "$TMP/clean" --enforce > "$TMP/out" 2>&1 || rc=$?
check "hung objdump: bounded by the deadline (finished in < 20s), exit 1 under --enforce" "1 yes" "$rc $([ $((SECONDS - start)) -lt 20 ] && echo yes || echo no)"
check "hung objdump: reported as timed out" yes "$(has 'timed out')"

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
vt = lambda v: tuple(int(x) for x in v.split("."))
problems = []
if d.get("schema") != 1:
    problems.append("schema")
missing = {"agent", "server", "gateway"} - set(d["sets"])
if missing:
    problems.append("missing sets %s" % sorted(missing))
for name, s in d["sets"].items():
    arts = s["artifacts"]
    if not (s["elf_count"] == len(arts) > 0):
        problems.append("%s: elf_count" % name)
    # the set-level maxima must be the maxima of the per-artifact maxima
    want = {}
    for a in arts.values():
        for fam, v in a["maxima"].items():
            if fam not in want or vt(v) > vt(want[fam]):
                want[fam] = v
    if want != s["maxima"]:
        problems.append("%s: maxima %s != %s" % (name, s["maxima"], want))
print("yes" if not problems else "no: " + "; ".join(problems))
EOF
)"
  check "committed baseline: schema 1, agent+server+gateway sets, counts and maxima consistent" yes "$got"
else
  check "committed baseline exists" yes no
fi

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
