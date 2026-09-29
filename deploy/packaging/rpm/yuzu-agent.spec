Name:           yuzu-agent
Version:        0.1.0
Release:        1%{?dist}
Summary:        Yuzu endpoint management agent
License:        AGPL-3.0-or-later
URL:            https://github.com/DevNullLtd/Yuzu

%description
Enterprise endpoint management platform — agent component.
Runs on managed endpoints with plugin architecture for
system queries, actions, and compliance monitoring.

%install
install -D -m 0755 %{_sourcedir}/yuzu-agent %{buildroot}%{_bindir}/yuzu-agent
install -D -m 0644 %{_sourcedir}/yuzu-agent.service %{buildroot}%{_unitdir}/yuzu-agent.service
install -d -m 0755 %{buildroot}%{_libdir}/yuzu/plugins
install -d -m 0750 %{buildroot}/var/lib/yuzu-agent
# OTA update trust anchor (#416/#3807), at parity with debian/postinst. root-owned
# and 0755: on Linux the agent runs unprivileged, so it genuinely cannot rewrite
# the anchor that authorises its own updates. Empty by design -- the operator
# places the PEM bundle here; nothing is installed into it.
install -d -m 0755 %{buildroot}/etc/yuzu-agent
install -d -m 0755 %{buildroot}/etc/yuzu-agent/certs

# Agent core shared library (plugins link against it)
if ls %{_sourcedir}/libyuzu_agent_core.so* 1>/dev/null 2>&1; then
    install -m 0755 %{_sourcedir}/libyuzu_agent_core.so* %{buildroot}%{_libdir}/yuzu/
fi

# ldconfig configuration
install -D -m 0644 /dev/null %{buildroot}/etc/ld.so.conf.d/yuzu.conf
echo "%{_libdir}/yuzu" > %{buildroot}/etc/ld.so.conf.d/yuzu.conf

# Install plugins if present
if ls %{_sourcedir}/plugins/*.so 1>/dev/null 2>&1; then
    install -m 0755 %{_sourcedir}/plugins/*.so %{buildroot}%{_libdir}/yuzu/plugins/
fi

%pre
getent group yuzu-agent >/dev/null 2>&1 || groupadd -r yuzu-agent
getent passwd yuzu-agent >/dev/null 2>&1 || useradd -r -g yuzu-agent -d /var/lib/yuzu-agent -s /sbin/nologin yuzu-agent

%post
%systemd_post yuzu-agent.service
ldconfig

%preun
%systemd_preun yuzu-agent.service

%postun
%systemd_postun_with_restart yuzu-agent.service
ldconfig

%files
%{_bindir}/yuzu-agent
%{_unitdir}/yuzu-agent.service
%dir %{_libdir}/yuzu
%{_libdir}/yuzu/libyuzu_agent_core.so*
%dir %{_libdir}/yuzu/plugins
%{_libdir}/yuzu/plugins/*.so
/etc/ld.so.conf.d/yuzu.conf
%dir %attr(0750,yuzu-agent,yuzu-agent) /var/lib/yuzu-agent
%dir %attr(0755,root,root) /etc/yuzu-agent
%dir %attr(0755,root,root) /etc/yuzu-agent/certs
