#!/usr/bin/env bash
# test_server_package_upgrade_warning.sh -- the yuzu-server package upgrade pre-flight.
#
# The shipped unit passes --gateway-upstream unconditionally, and the server now refuses to
# start on operator certificates without a gateway peer pin (docs/user-manual/upgrading.md,
# "Check before you upgrade the server"). The RPM %pre and the deb preinst therefore print an
# advisory warning on an upgrade when the host's own configuration would refuse. This test runs
# the REAL scriptlet text, extracted from deploy/packaging/debian/preinst and
# deploy/packaging/rpm/yuzu-server.spec, against synthetic /etc trees under a temp directory
# (the YUZU_PKG_ROOT prefix seam). It needs no built binary, no Postgres, no root and no rpm or
# dpkg tooling.
#
# Run:  bash tests/shell/test_server_package_upgrade_warning.sh
#
# Limits: the packages themselves are not built here, and rpm macro expansion is checked only by
# asserting the %pre text carries no percent sign. The warning is a heuristic over files; the
# decision rule in upgrading.md stays the authority.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREINST="$ROOT/deploy/packaging/debian/preinst"
SPEC="$ROOT/deploy/packaging/rpm/yuzu-server.spec"
POSTINST="$ROOT/deploy/packaging/debian/postinst"
BUILD_DEB="$ROOT/deploy/packaging/debian/build-deb.sh"
for f in "$PREINST" "$SPEC" "$POSTINST" "$BUILD_DEB"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 2; }
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_pkgwarn.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
ok()  { printf '  [pass] %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  [FAIL] %s\n' "$1"; fail=$((fail + 1)); }

# Shells to run every scenario under: whatever of sh, dash and bash exists (sh is dash on
# Debian and bash on RHEL, so both dialects get covered where available).
SHELLS=""
for s in sh dash bash; do
  command -v "$s" >/dev/null 2>&1 && SHELLS="$SHELLS $s"
done

# --- extract the real scriptlet text --------------------------------------------------------
# The shared block (between the BEGIN and END marker lines, inclusive).
extract_block() { sed -n '/^# BEGIN yuzu-gateway-peer-preflight/,/^# END yuzu-gateway-peer-preflight/p' "$1"; }
# The rpm %pre body up to and including the guard's closing "fi" (stops before useradd etc).
extract_rpm_pre() {
  awk '/^%pre$/ {f=1; next} f && /^# BEGIN yuzu-gateway-peer-preflight/ {g=1}
       g {print} g && /^fi$/ {exit}' "$SPEC"
}
# The deb preinst in full.
BLOCK_DEB="$TMP/block.deb.txt"; extract_block "$PREINST" > "$BLOCK_DEB"
BLOCK_RPM="$TMP/block.rpm.txt"; extract_block "$SPEC" > "$BLOCK_RPM"
extract_rpm_pre > "$TMP/rpm_pre.sh"

echo "== structure =="
if [ -s "$BLOCK_DEB" ] && [ -s "$BLOCK_RPM" ]; then ok "block found in both scriptlets"; else bad "block missing from preinst or spec"; fi
if cmp -s "$BLOCK_DEB" "$BLOCK_RPM"; then ok "deb and rpm blocks are byte-identical"; else bad "deb and rpm blocks have drifted apart"; fi
if grep -q '%' "$TMP/rpm_pre.sh"; then bad "rpm %pre text contains a percent sign (macro expansion hazard)"; else ok "rpm %pre text has no percent sign"; fi
if grep -q 'ypf_main' "$TMP/rpm_pre.sh" && grep -q '^if \[ "\$1" -ge 2 \]; then$' "$TMP/rpm_pre.sh"; then ok "rpm %pre calls the check only for \$1 -ge 2"; else bad "rpm %pre guard not found"; fi
if grep -q 'DEBIAN/preinst' "$BUILD_DEB"; then ok "build-deb.sh wires preinst"; else bad "build-deb.sh does not wire preinst"; fi
# The agent .deb must stay unaffected: preinst is copied exactly once (server section only), and
# the shared postinst did not grow any gateway logic.
if [ "$(grep -c 'cp "\$SCRIPT_DIR/preinst"' "$BUILD_DEB")" = 1 ]; then ok "preinst copied once (server .deb only)"; else bad "preinst copied a number of times other than once"; fi
if grep -qi 'gateway' "$POSTINST"; then bad "shared postinst mentions the gateway (it runs for the agent too)"; else ok "shared postinst untouched by the gateway check"; fi

# --- scenario harness ------------------------------------------------------------------------
# mkroot <name>: fresh synthetic root, prints its path.
mkroot() { local r="$TMP/root.$1"; rm -rf "$r"; mkdir -p "$r/etc/yuzu" "$r/etc/systemd/system/yuzu-server.service.d"; printf '%s' "$r"; }
# put <file> <content...>: write lines (printf %s\n per argument).
put() { local f="$1"; shift; printf '%s\n' "$@" > "$f"; }

# run_scriptlet <shell> <kind> <root>: runs the real text; stdout -> $TMP/out, stderr -> $TMP/err,
# sets RC. kind: block (the shared block + ypf_main) | preinst-upgrade | preinst-install |
# rpm-upgrade | rpm-install.
run_scriptlet() {
  local sh_="$1" kind="$2" root="$3"
  : > "$TMP/out"; : > "$TMP/err"
  case "$kind" in
    block)
      YUZU_PKG_ROOT="$root" "$sh_" -eu -c "$(cat "$BLOCK_DEB"; echo 'ypf_main')" > "$TMP/out" 2> "$TMP/err"; RC=$? ;;
    preinst-upgrade) YUZU_PKG_ROOT="$root" "$sh_" "$PREINST" upgrade 1.0.0 > "$TMP/out" 2> "$TMP/err"; RC=$? ;;
    preinst-install) YUZU_PKG_ROOT="$root" "$sh_" "$PREINST" install > "$TMP/out" 2> "$TMP/err"; RC=$? ;;
    preinst-abort)   YUZU_PKG_ROOT="$root" "$sh_" "$PREINST" abort-upgrade 1.0.0 > "$TMP/out" 2> "$TMP/err"; RC=$? ;;
    rpm-upgrade) YUZU_PKG_ROOT="$root" "$sh_" -e "$TMP/rpm_pre.sh" 2 > "$TMP/out" 2> "$TMP/err"; RC=$? ;;
    rpm-install) YUZU_PKG_ROOT="$root" "$sh_" -e "$TMP/rpm_pre.sh" 1 > "$TMP/out" 2> "$TMP/err"; RC=$? ;;
  esac
}

# expect_warn / expect_silent <desc> <root>: run under every shell; the block form also runs
# under `-eu` (rpm runs scriptlets with -e; the check must also be set -u clean).
expect_warn() {
  local desc="$1" root="$2" s
  for s in $SHELLS; do
    run_scriptlet "$s" block "$root"
    if [ "$RC" = 0 ] && [ ! -s "$TMP/out" ] && grep -q 'WARNING' "$TMP/err" \
       && grep -q 'YUZU_GATEWAY_PEER_PIN_FILE=<cert.pem>' "$TMP/err" \
       && grep -q 'YUZU_INSECURE_GATEWAY_PEER=1' "$TMP/err" \
       && grep -q 'remove --gateway-upstream' "$TMP/err" \
       && grep -q 'Check before you upgrade the server' "$TMP/err"; then
      ok "$desc [$s]"
    else
      bad "$desc [$s] (rc=$RC, stdout bytes=$(wc -c < "$TMP/out" | tr -d ' '), stderr: $(head -c 200 "$TMP/err" | tr '\n' ' '))"
    fi
  done
}
expect_silent() {
  local desc="$1" root="$2" s
  for s in $SHELLS; do
    run_scriptlet "$s" block "$root"
    if [ "$RC" = 0 ] && [ ! -s "$TMP/out" ] && [ ! -s "$TMP/err" ]; then
      ok "$desc [$s]"
    else
      bad "$desc [$s] (rc=$RC, stdout/stderr not empty: $(head -c 200 "$TMP/err" | tr '\n' ' '))"
    fi
  done
}

echo "== decision matrix (shared block) =="
r="$(mkroot own_nopin)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_POSTGRES_DSN=postgresql://x' 'YUZU_CERT=/etc/yuzu/server.pem' 'YUZU_KEY=/etc/yuzu/server.key' 'YUZU_CA_CERT=/etc/yuzu/ca.pem'
expect_warn "own certificate, no pin => warning" "$r"

r="$(mkroot own_cacert_only)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CA_CERT=/etc/yuzu/ca.pem'
expect_warn "CA certificate alone counts as an own certificate => warning" "$r"

r="$(mkroot own_pinfile)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem' 'YUZU_GATEWAY_PEER_PIN_FILE=/etc/yuzu/gw.pem'
expect_silent "own certificate + pin file => silent" "$r"

r="$(mkroot own_pins)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem' 'YUZU_GATEWAY_PEER_PINS=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
expect_silent "own certificate + pin list => silent" "$r"

r="$(mkroot own_ack)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem' 'YUZU_INSECURE_GATEWAY_PEER=1'
expect_silent "own certificate + acknowledgement => silent" "$r"

r="$(mkroot own_ack_false)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem' 'YUZU_INSECURE_GATEWAY_PEER=false'
expect_warn "acknowledgement set to false does not count => warning" "$r"

r="$(mkroot own_empty_pin)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem' 'YUZU_GATEWAY_PEER_PIN_FILE='
expect_warn "zero-length pin variable is unset => warning" "$r"

r="$(mkroot default_certs)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_POSTGRES_DSN=postgresql://x' 'YUZU_HTTPS_CERT=/etc/yuzu/web.pem' 'YUZU_HTTPS_KEY=/etc/yuzu/web.key'
expect_silent "default certificates (HTTPS cert variables only) => silent" "$r"

r="$(mkroot empty_cert_value)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=' 'YUZU_KEY='
expect_silent "zero-length certificate variables => silent" "$r"

r="$(mkroot commented)"
put "$r/etc/yuzu/yuzu-server.env" '# YUZU_CERT=/etc/yuzu/server.pem' '   # YUZU_KEY=/etc/yuzu/server.key'
put "$r/etc/systemd/system/yuzu-server.service.d/override.conf" '[Service]' '# Environment="YUZU_CERT=/etc/yuzu/server.pem"' '#ExecStart=/x --cert /a'
expect_silent "commented-out certificate lines (env and drop-in) are ignored => silent" "$r"

r="$(mkroot commented_pin)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem' '# YUZU_GATEWAY_PEER_PIN_FILE=/etc/yuzu/gw.pem'
expect_warn "a commented-out pin does not count => warning" "$r"

r="$(mkroot dropin_env)"
put "$r/etc/systemd/system/yuzu-server.service.d/certs.conf" '[Service]' 'Environment="YUZU_CERT=/etc/yuzu/server.pem"'
expect_warn "drop-in Environment=\"YUZU_CERT=..\" => warning" "$r"

r="$(mkroot dropin_env_unquoted)"
put "$r/etc/systemd/system/yuzu-server.service.d/certs.conf" '[Service]' 'Environment=YUZU_KEY=/etc/yuzu/server.key'
expect_warn "drop-in unquoted Environment=YUZU_KEY=.. => warning" "$r"

r="$(mkroot dropin_flag)"
put "$r/etc/systemd/system/yuzu-server.service.d/exec.conf" '[Service]' 'ExecStart=' 'ExecStart=/usr/local/bin/yuzu-server \' '    --gateway-upstream 0.0.0.0:50055 \' '    --cert /etc/yuzu/server.pem \' '    --key /etc/yuzu/server.key \' '    --data-dir /var/lib/yuzu'
expect_warn "drop-in ExecStart with --cert and --gateway-upstream => warning" "$r"

r="$(mkroot dropin_mgmt_flag)"
put "$r/etc/systemd/system/yuzu-server.service.d/exec.conf" '[Service]' 'ExecStart=' 'ExecStart=/usr/local/bin/yuzu-server --gateway-upstream 0.0.0.0:50055 --management-cert=/etc/yuzu/m.pem'
expect_warn "drop-in --management-cert=.. => warning" "$r"

r="$(mkroot dropin_cert_san)"
put "$r/etc/systemd/system/yuzu-server.service.d/exec.conf" '[Service]' 'ExecStart=' 'ExecStart=/usr/local/bin/yuzu-server --gateway-upstream 0.0.0.0:50055 --cert-san gw.example --cert-group yuzu'
expect_silent "--cert-san and --cert-group are not certificates => silent" "$r"

r="$(mkroot dropin_pin_flag)"
put "$r/etc/systemd/system/yuzu-server.service.d/exec.conf" '[Service]' 'ExecStart=' 'ExecStart=/usr/local/bin/yuzu-server --gateway-upstream 0.0.0.0:50055 --cert /a --key /b --gateway-peer-pin-file /etc/yuzu/gw.pem'
expect_silent "drop-in --gateway-peer-pin-file => silent" "$r"

r="$(mkroot dropin_ack_flag)"
put "$r/etc/systemd/system/yuzu-server.service.d/exec.conf" '[Service]' 'ExecStart=' 'ExecStart=/usr/local/bin/yuzu-server --gateway-upstream 0.0.0.0:50055 --cert /a --key /b --insecure-gateway-peer'
expect_silent "drop-in --insecure-gateway-peer => silent" "$r"

r="$(mkroot dropin_no_gateway)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem'
put "$r/etc/systemd/system/yuzu-server.service.d/exec.conf" '[Service]' 'ExecStart=' 'ExecStart=/usr/local/bin/yuzu-server --listen 0.0.0.0:50051 --data-dir /var/lib/yuzu'
expect_silent "own certificate but the operator dropped --gateway-upstream => silent" "$r"

r="$(mkroot dropin_no_gateway_env_upstream)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem' 'YUZU_GATEWAY_UPSTREAM=0.0.0.0:50055'
put "$r/etc/systemd/system/yuzu-server.service.d/exec.conf" '[Service]' 'ExecStart=' 'ExecStart=/usr/local/bin/yuzu-server --listen 0.0.0.0:50051'
expect_warn "no flag but YUZU_GATEWAY_UPSTREAM in the environment file => warning" "$r"

r="$(mkroot full_unit_override)"
put "$r/etc/systemd/system/yuzu-server.service" '[Service]' 'ExecStart=/usr/local/bin/yuzu-server --gateway-upstream 0.0.0.0:50055 --cert /a --key /b --ca-cert /c'
expect_warn "full unit copy in /etc/systemd/system => warning" "$r"

r="$(mkroot only_exec_reset)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem'
put "$r/etc/systemd/system/yuzu-server.service.d/reset.conf" '[Service]' 'ExecStart='
expect_warn "a bare ExecStart= reset is not a replacement command => warning (conservative)" "$r"

echo "== missing and unreadable inputs =="
r="$TMP/root.absent"; rm -rf "$r"; mkdir -p "$r"
expect_silent "no /etc tree at all => silent" "$r"

r="$(mkroot empty_files)"; : > "$r/etc/yuzu/yuzu-server.env"; : > "$r/etc/systemd/system/yuzu-server.service.d/empty.conf"
expect_silent "empty env file and empty drop-in => silent" "$r"

r="$(mkroot dir_not_file)"; mkdir -p "$r/etc/yuzu/yuzu-server.env" "$r/etc/systemd/system/yuzu-server.service.d/dir.conf"
expect_silent "a directory where a file is expected => silent" "$r"

r="$(mkroot unreadable)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem'
put "$r/etc/systemd/system/yuzu-server.service.d/certs.conf" 'Environment="YUZU_KEY=/b"'
chmod 000 "$r/etc/yuzu/yuzu-server.env" "$r/etc/systemd/system/yuzu-server.service.d/certs.conf"
if [ -r "$r/etc/yuzu/yuzu-server.env" ]; then
  echo "  [skip] unreadable files: running as a user that ignores file modes"
else
  expect_silent "unreadable env file and drop-in => silent, no error text" "$r"
fi
chmod 600 "$r/etc/yuzu/yuzu-server.env" "$r/etc/systemd/system/yuzu-server.service.d/certs.conf" 2>/dev/null

r="$(mkroot dangling)"
ln -s /nonexistent/target "$r/etc/yuzu/yuzu-server.env"
ln -s /dev/null "$r/etc/systemd/system/yuzu-server.service"
expect_silent "dangling symlink and a masked unit => silent" "$r"

echo "== real scriptlets: guards and exit status =="
r="$(mkroot guard)"
put "$r/etc/yuzu/yuzu-server.env" 'YUZU_CERT=/etc/yuzu/server.pem'
for s in $SHELLS; do
  run_scriptlet "$s" preinst-upgrade "$r"
  if [ "$RC" = 0 ] && [ ! -s "$TMP/out" ] && grep -q 'WARNING' "$TMP/err"; then ok "preinst upgrade warns, exit 0, stdout empty [$s]"; else bad "preinst upgrade [$s] rc=$RC"; fi
  run_scriptlet "$s" preinst-install "$r"
  if [ "$RC" = 0 ] && [ ! -s "$TMP/out" ] && [ ! -s "$TMP/err" ]; then ok "preinst fresh install is silent [$s]"; else bad "preinst install [$s] rc=$RC"; fi
  run_scriptlet "$s" preinst-abort "$r"
  if [ "$RC" = 0 ] && [ ! -s "$TMP/err" ]; then ok "preinst abort-upgrade is silent [$s]"; else bad "preinst abort-upgrade [$s] rc=$RC"; fi
  run_scriptlet "$s" rpm-upgrade "$r"
  if [ "$RC" = 0 ] && [ ! -s "$TMP/out" ] && grep -q 'WARNING' "$TMP/err"; then ok "rpm %pre dry run, upgrade (\$1=2) warns, exit 0 under sh -e [$s]"; else bad "rpm upgrade dry run [$s] rc=$RC"; fi
  run_scriptlet "$s" rpm-install "$r"
  if [ "$RC" = 0 ] && [ ! -s "$TMP/out" ] && [ ! -s "$TMP/err" ]; then ok "rpm %pre dry run, fresh install (\$1=1) is silent [$s]"; else bad "rpm install dry run [$s] rc=$RC"; fi
done

# A scriptlet must not change the exit status even when grep is unavailable on PATH.
mkdir -p "$TMP/emptybin"
for s in $SHELLS; do
  spath="$(command -v "$s")"
  YUZU_PKG_ROOT="$r" PATH="$TMP/emptybin" "$spath" "$PREINST" upgrade 1.0.0 > "$TMP/out" 2> /dev/null; rc=$?
  if [ "$rc" = 0 ]; then ok "preinst exits 0 even with no tools on PATH [$s]"; else bad "preinst exit $rc with empty PATH [$s]"; fi
done

echo
echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
