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

%pre
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
