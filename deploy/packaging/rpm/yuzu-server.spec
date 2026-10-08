%{!?_sysusersdir:%global _sysusersdir /usr/lib/sysusers.d}
Name:           yuzu-server
Version:        0.1.0
Release:        1%{?dist}
Summary:        Yuzu endpoint management server
License:        AGPL-3.0-or-later
URL:            https://github.com/DevNullLtd/Yuzu

%description
Enterprise endpoint management platform — server component.
Provides the web dashboard, REST API, gRPC agent service,
instruction engine, policy engine, and all server-side stores.

%install
install -D -m 0755 %{_sourcedir}/yuzu-server %{buildroot}%{_bindir}/yuzu-server
install -D -m 0644 %{_sourcedir}/yuzu-server.service %{buildroot}%{_unitdir}/yuzu-server.service
install -D -m 0755 %{_sourcedir}/install-server-postgres.sh %{buildroot}%{_datadir}/yuzu/scripts/install-server-postgres.sh
install -d -m 0750 %{buildroot}/var/lib/yuzu
install -d -m 0750 %{buildroot}/var/log/yuzu
install -d -m 0750 %{buildroot}/etc/yuzu

# Service account as a sysusers.d entry (#5142). rpm >= 4.19 turns the
# yuzu-owned paths in %files into Requires: user(yuzu) and
# group(yuzu), and this file into the matching Provides, so the package
# satisfies its own requirement. %pre still creates the account.
install -d -m 0755 %{buildroot}%{_sysusersdir}
printf 'u yuzu - "Yuzu server" /var/lib/yuzu /sbin/nologin\n' > %{buildroot}%{_sysusersdir}/yuzu.conf

%pre
# Advisory upgrade pre-flight (warning only, never fails the scriptlet). It runs here so
# the text prints BEFORE the postun scriptlet restarts the service on upgrade. The same block lives in
# deploy/packaging/debian/preinst; keep the two identical.
# BEGIN yuzu-gateway-peer-preflight (this block is byte-identical in deploy/packaging/debian/preinst and deploy/packaging/rpm/yuzu-server.spec; tests/shell/test_server_package_upgrade_warning.sh fails if the copies drift)
# Advisory only: prints a warning on stderr and never changes the exit status or
# the service state. Reads only /etc/yuzu/yuzu-server.env and the operator
# overrides of the unit under /etc/systemd/system, ignoring comment lines.
# YUZU_PKG_ROOT is a test seam (a prefix for those paths), empty in production.
# Keep this block free of the percent sign: rpm expands macros inside scriptlets.
# The accepted shapes are pinned by docs/user-manual/upgrading.md ("Check before
# you upgrade the server", decision rule 3).
ypf_has() {
    ypf_re=$1
    shift
    for ypf_f in "$@"; do
        [ -f "$ypf_f" ] && [ -r "$ypf_f" ] || continue
        if grep -v '^[[:space:]]*#' "$ypf_f" 2>/dev/null | grep -E -q -- "$ypf_re" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}
ypf_main() {
    ypf_r="${YUZU_PKG_ROOT:-}"
    ypf_env="$ypf_r/etc/yuzu/yuzu-server.env"
    set -- "$ypf_r/etc/systemd/system/yuzu-server.service" "$ypf_r"/etc/systemd/system/yuzu-server.service.d/*.conf
    ypf_b="(^|[[:space:]=\"'])"
    ypf_gw=1
    if ypf_has '^[[:space:]]*ExecStart=[[:space:]]*[^[:space:]]' "$@"; then
        ypf_has '--gateway-upstream' "$@" || ypf_gw=0
    fi
    if ypf_has "${ypf_b}YUZU_GATEWAY_UPSTREAM=[\"']?[^[:space:]\"']" "$ypf_env" "$@"; then
        ypf_gw=1
    fi
    [ "$ypf_gw" = 1 ] || return 0
    ypf_has "${ypf_b}(YUZU_(CERT|KEY|CA_CERT)=[\"']?[^[:space:]\"']|--(management-)?(cert|key|ca-cert)([[:space:]=\"']|\$))" "$ypf_env" "$@" || return 0
    ypf_has "${ypf_b}(YUZU_GATEWAY_PEER_PIN(S|_FILE)?=[\"']?[^[:space:]\"']|--gateway-peer-pin)" "$ypf_env" "$@" && return 0
    ypf_has "${ypf_b}--insecure-gateway-peer" "$@" && return 0
    if ypf_has "${ypf_b}YUZU_INSECURE_GATEWAY_PEER=[\"']?[^[:space:]\"']" "$ypf_env" "$@"; then
        ypf_has "${ypf_b}YUZU_INSECURE_GATEWAY_PEER=[\"']?(0|false|no|off)([[:space:]\"']|\$)" "$ypf_env" "$@" || return 0
    fi
    cat >&2 <<'YUZU_PREFLIGHT_EOF'
yuzu-server: WARNING (advisory only, the upgrade continues): this host gives the
server its own certificates (YUZU_CERT, YUZU_KEY, YUZU_CA_CERT, or --cert, --key,
--ca-cert, --management-cert, --management-key, --management-ca-cert) with
--gateway-upstream, but sets no gateway peer pin and no acknowledgement. This
release refuses to start in that configuration. The RPM restarts the service on
upgrade, so it would fail at once; the deb does not restart it, so the failure
would appear at the next restart or reboot.
Fix it now, before the service restarts, with ONE of:
  - set YUZU_GATEWAY_PEER_PIN_FILE=<cert.pem> in /etc/yuzu/yuzu-server.env, where
    cert.pem is the gateway leaf certificate, kept under /etc/yuzu and readable
    by the yuzu user;
  - for a plaintext lab only, set YUZU_INSECURE_GATEWAY_PEER=1 in
    /etc/yuzu/yuzu-server.env (this disables gateway peer authorization);
  - if you run no gateway, remove --gateway-upstream: a package upgrade
    overwrites the unit file, so use a systemctl edit drop-in that first clears
    ExecStart= and then restates the command line without that flag.
This check reads only /etc/yuzu/yuzu-server.env and the unit overrides under
/etc/systemd/system, so it can miss a configuration supplied another way. The
authority is "Check before you upgrade the server" in the section "Breaking:
--gateway-upstream now refuses to start without gateway peer authorization" of
docs/user-manual/upgrading.md.
YUZU_PREFLIGHT_EOF
    return 0
}
# END yuzu-gateway-peer-preflight
if [ "$1" -ge 2 ]; then
    ypf_main || true
fi

getent group yuzu >/dev/null 2>&1 || groupadd -r yuzu
getent passwd yuzu >/dev/null 2>&1 || useradd -r -g yuzu -d /var/lib/yuzu -s /sbin/nologin yuzu

%post
%systemd_post yuzu-server.service
# Postgres provisioning (ADR-0006, #1320). NON-FATAL by design: the helper
# exits 0 with install hints when no local cluster is found, and any other
# failure must not break package install while the server still boots
# without Postgres (until the #1320 PR 3 fail-closed flip; re-evaluate then).
if [ -x %{_datadir}/yuzu/scripts/install-server-postgres.sh ]; then
    bash %{_datadir}/yuzu/scripts/install-server-postgres.sh || \
        echo "warn: Postgres provisioning incomplete — re-run %{_datadir}/yuzu/scripts/install-server-postgres.sh (see docs/user-manual/server-admin.md)" >&2
fi

%preun
%systemd_preun yuzu-server.service

%postun
%systemd_postun_with_restart yuzu-server.service

%files
%{_bindir}/yuzu-server
%{_unitdir}/yuzu-server.service
%attr(0755,root,root) %{_datadir}/yuzu/scripts/install-server-postgres.sh
%dir %attr(0750,yuzu,yuzu) /var/lib/yuzu
%dir %attr(0750,yuzu,yuzu) /var/log/yuzu
%dir %attr(0750,yuzu,yuzu) /etc/yuzu
%{_sysusersdir}/yuzu.conf
