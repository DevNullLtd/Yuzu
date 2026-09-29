// Pure-parser + selection/projection coverage for the Windows Security-
// channel (wevtapi) logon/logoff path (Wave-2 WP-A). The functions live in
// agents/plugins/users/src/users_win_events.hpp and are reachable at runtime
// (Windows only) from users_plugin.cpp's primary_user/session_history
// actions; this TU runs -- and is required to pass -- on every host,
// including macOS/Linux CI, since the header is Windows-headers-free and
// I/O-free by design.
//
// The two fixtures embedded below are lifted verbatim from
// ~/.claude/wave2-prestage/fixtures/windows/ (provenance repeated at each
// literal): captured 2026-08-14T21:10Z via SSH to the-rig (Windows host
// DESKTOP-04DNSIG), rc=0 both times, per that directory's manifest.txt.
#include "users_win_events.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <format>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::users_win;

namespace {

// Minimal single-<Event> XML fragment builder for the edge-case tests below
// (exclusion filters, absent/malformed fields) -- shaped like a real
// EvtRender(EvtRenderEventXml) document but trimmed to only the elements
// this parser reads, so each case stays readable. The field-by-field row
// assertions further down use the real prestage captures instead of this
// builder.
std::string make_event(std::string_view event_id, std::string_view system_time,
                       std::string_view target_user, std::string_view logon_type = "") {
    std::string out = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>";
    out += "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>";
    out += std::format("<EventID>{}</EventID>", event_id);
    if (!system_time.empty())
        out += std::format("<TimeCreated SystemTime='{}'/>", system_time);
    out += "</System><EventData>";
    out += "<Data Name='TargetUserSid'>S-1-5-21-0-0-0-1</Data>";
    out += std::format("<Data Name='TargetUserName'>{}</Data>", target_user);
    out += "<Data Name='TargetDomainName'>DOMAIN</Data>";
    if (!logon_type.empty())
        out += std::format("<Data Name='LogonType'>{}</Data>", logon_type);
    out += "</EventData></Event>";
    return out;
}

// captured 2026-08-14T21:10Z via SSH to the-rig (Windows, DESKTOP-04DNSIG),
// rc=0 -- ~/.claude/wave2-prestage/fixtures/windows/manifest.txt:
//   wevtutil qe Security /q:*[System[EventID=4624]] /c:5 /f:xml /rd:true
// (the real fixture file, fx_wevtutil_4624_xml.xml, holds 5 events: Alex
// (x4, LogonType=3) and sshd_3112 (x1, LogonType=5, a virtual sshd account)).
constexpr std::string_view kFixture4624Full =
    R"XML(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.4173297Z'/><EventRecordID>667844</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='7080'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d884d</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>sshd</Data><Data Name='AuthenticationPackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc28</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.3623572Z'/><EventRecordID>667839</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='21024'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d873e</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>sshd</Data><Data Name='AuthenticationPackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc28</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.2196124Z'/><EventRecordID>667834</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='21024'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-3112</Data><Data Name='TargetUserName'>sshd_3112</Data><Data Name='TargetDomainName'>VIRTUAL USERS</Data><Data Name='TargetLogonId'>0x41d8448</Data><Data Name='LogonType'>5</Data><Data Name='LogonProcessName'>Advapi  </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc28</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1842</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:48.2101789Z'/><EventRecordID>667828</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='7080'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d4769</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>sshd</Data><Data Name='AuthenticationPackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x56e0</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:48.0562166Z'/><EventRecordID>667823</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='21024'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d46d3</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>sshd</Data><Data Name='AuthenticationPackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x56e0</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event>)XML";

// captured 2026-08-14T21:10Z via SSH to the-rig (Windows, DESKTOP-04DNSIG),
// rc=0 -- ~/.claude/wave2-prestage/fixtures/windows/manifest.txt:
//   wevtutil qe Security /q:*[System[(EventID=4624 or EventID=4634)]] /c:8 /f:xml /rd:true
// (the real fixture file, fx_wevtutil_4624_4634_xml.xml -- 8 events, newest
// first: 4624,4634,4624,4624,4634,4634,4624,4634. Every 4634 in this capture
// carries exactly the five Target* Data items and NO IpAddress/WorkstationName
// element -- the pre-migration text parser's "Source Network Address" line
// never appeared for these events either.)
constexpr std::string_view kFixtureMixed =
    R"XML(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.4173297Z'/><EventRecordID>667844</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='7080'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d884d</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>sshd</Data><Data Name='AuthenticationPackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc28</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4634</EventID><Version>0</Version><Level>0</Level><Task>12545</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.3626600Z'/><EventRecordID>667841</EventRecordID><Correlation/><Execution ProcessID='1696' ThreadID='21024'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d873e</Data><Data Name='LogonType'>3</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.3623572Z'/><EventRecordID>667839</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='21024'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d873e</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>sshd</Data><Data Name='AuthenticationPackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc28</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.2196124Z'/><EventRecordID>667834</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='21024'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-3112</Data><Data Name='TargetUserName'>sshd_3112</Data><Data Name='TargetDomainName'>VIRTUAL USERS</Data><Data Name='TargetLogonId'>0x41d8448</Data><Data Name='LogonType'>5</Data><Data Name='LogonProcessName'>Advapi  </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc28</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1842</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4634</EventID><Version>0</Version><Level>0</Level><Task>12545</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.1761277Z'/><EventRecordID>667831</EventRecordID><Correlation/><Execution ProcessID='1696' ThreadID='7080'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='TargetUserSid'>S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-22240</Data><Data Name='TargetUserName'>sshd_22240</Data><Data Name='TargetDomainName'>VIRTUAL USERS</Data><Data Name='TargetLogonId'>0x41d43d3</Data><Data Name='LogonType'>5</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4634</EventID><Version>0</Version><Level>0</Level><Task>12545</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.1761272Z'/><EventRecordID>667830</EventRecordID><Correlation/><Execution ProcessID='1696' ThreadID='21024'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d4769</Data><Data Name='LogonType'>3</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:48.2101789Z'/><EventRecordID>667828</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='7080'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d4769</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>sshd</Data><Data Name='AuthenticationPackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x56e0</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4634</EventID><Version>0</Version><Level>0</Level><Task>12545</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:48.0565173Z'/><EventRecordID>667825</EventRecordID><Correlation/><Execution ProcessID='1696' ThreadID='21024'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d46d3</Data><Data Name='LogonType'>3</Data></EventData></Event>)XML";

} // namespace

// ---------------------------------------------------------------------------
// parse_logon_events
// ---------------------------------------------------------------------------

TEST_CASE("parse_logon_events: empty/non-XML input yields an empty vector, never throws",
          "[users][win_events]") {
    CHECK(parse_logon_events("").empty());
    CHECK(parse_logon_events("not xml at all").empty());
}

TEST_CASE("parse_logon_events: a block truncated mid-tag yields empty, never throws",
          "[users][win_events]") {
    // Opens <Event>, opens <System>, opens <EventID> -- and stops, exactly as
    // a short EvtRender buffer or a cut-short capture would.
    const std::string truncated =
        "<Event xmlns='...'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "<EventID>4624";
    std::vector<LogonEvent> events;
    CHECK_NOTHROW(events = parse_logon_events(truncated));
    CHECK(events.empty());
}

TEST_CASE("parse_logon_events: an attribute-bearing <EventID Qualifiers='...'> tag is parsed",
          "[users][win_events]") {
    // Some Windows event providers emit <EventID Qualifiers='...'>N</EventID>
    // rather than the bare <EventID>N</EventID> this plugin's own captured
    // fixtures happen to show -- the extractor must not silently drop the
    // event just because a real provider took the attribute-bearing shape.
    const std::string xml =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "<EventID Qualifiers='0'>4624</EventID><TimeCreated SystemTime='t'/></System>"
        "<EventData><Data Name='TargetUserSid'>S-1-5-21-0-0-0-1</Data>"
        "<Data Name='TargetUserName'>Alex</Data>"
        "<Data Name='LogonType'>3</Data></EventData></Event>";
    auto events = parse_logon_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == "4624");
    CHECK(events[0].target_user == "Alex");
}

TEST_CASE("parse_logon_events: a truncated SECOND event doesn't lose a complete first one",
          "[users][win_events]") {
    const std::string xml =
        make_event("4624", "2026-08-14T20:10:49Z", "Alex", "3") +
        "<Event xmlns='...'><System><EventID>4634"; // never closes
    std::vector<LogonEvent> events;
    CHECK_NOTHROW(events = parse_logon_events(xml));
    REQUIRE(events.size() == 1);
    CHECK(events[0].target_user == "Alex");
}

TEST_CASE("parse_logon_events: one real 4624 event round-trips every field",
          "[users][win_events]") {
    // The first <Event> of kFixture4624Full, isolated to its own literal so
    // this case exercises exactly one event.
    constexpr std::string_view kOne =
        R"XML(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-08-14T20:10:49.4173297Z'/><EventRecordID>667844</EventRecordID><Correlation ActivityID='{3c71acfb-2bdc-000e-85ad-713cdc2bdd01}'/><Execution ProcessID='1696' ThreadID='7080'/><Channel>Security</Channel><Computer>DESKTOP-04DNSIG</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DESKTOP-04DNSIG$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-571721511-16201247-3531262703-1001</Data><Data Name='TargetUserName'>Alex</Data><Data Name='TargetDomainName'>DESKTOP-04DNSIG</Data><Data Name='TargetLogonId'>0x41d884d</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>sshd</Data><Data Name='AuthenticationPackageName'>MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc28</Data><Data Name='ProcessName'>C:\Windows\System32\OpenSSH\sshd.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event>)XML";

    auto events = parse_logon_events(kOne);
    REQUIRE(events.size() == 1);
    const auto& ev = events[0];
    CHECK(ev.event_id == "4624");
    CHECK(ev.time_created == "2026-08-14T20:10:49.4173297Z");
    CHECK(ev.target_user == "Alex");
    CHECK(ev.target_domain == "DESKTOP-04DNSIG");
    CHECK(ev.logon_type_raw == "3");
    CHECK(ev.workstation == "-");
    CHECK(ev.ip_address == "-");
}

TEST_CASE("parse_logon_events: the mixed 4624/4634 fixture yields all 8 events in order",
          "[users][win_events]") {
    auto events = parse_logon_events(kFixtureMixed);
    REQUIRE(events.size() == 8);
    const std::array<std::string, 8> expected_ids = {"4624", "4634", "4624", "4624",
                                                      "4634", "4634", "4624", "4634"};
    for (size_t i = 0; i < expected_ids.size(); ++i)
        CHECK(events[i].event_id == expected_ids[i]);
}

TEST_CASE("parse_logon_events: a machine account ('$') is parsed, not dropped by the parser",
          "[users][win_events]") {
    // The exclusion filter lives in primary_user_from_events/
    // session_history_rows, not in the parser -- parse_logon_events reports
    // exactly what the XML says.
    auto events = parse_logon_events(make_event("4624", "t", "DESKTOP-04DNSIG$", "3"));
    REQUIRE(events.size() == 1);
    CHECK(events[0].target_user == "DESKTOP-04DNSIG$");
}

TEST_CASE("parse_logon_events: XML entity-escaped account text decodes to the real value",
          "[users][win_events]") {
    // EvtRender escapes '&' in element text as-rendered: a real account or
    // domain name containing '&' (e.g. an "R&D" AD domain) comes back over
    // the wire as "R&amp;D", not the literal string. Un-decoded, that literal
    // would be counted and reported under the wrong name.
    auto events = parse_logon_events(make_event("4624", "t", "R&amp;D User", "3"));
    REQUIRE(events.size() == 1);
    CHECK(events[0].target_user == "R&D User");
}

TEST_CASE("parse_logon_events: entity decoding covers all five predefined entities + numeric refs",
          "[users][win_events]") {
    auto events = parse_logon_events(
        make_event("4624", "t", "&lt;a&gt;&amp;&apos;b&apos;&quot;c&quot;&#65;&#x42;", "3"));
    REQUIRE(events.size() == 1);
    CHECK(events[0].target_user == "<a>&'b'\"c\"AB");
}

TEST_CASE("parse_logon_events: an unrecognised entity passes through unchanged",
          "[users][win_events]") {
    // Never silently drops text on a malformed/unrecognised entity -- degrade
    // to "still readable" rather than data loss.
    auto events = parse_logon_events(make_event("4624", "t", "weird&nbsp;name", "3"));
    REQUIRE(events.size() == 1);
    CHECK(events[0].target_user == "weird&nbsp;name");
}

TEST_CASE("parse_logon_events: entity decoding also applies to TargetDomainName",
          "[users][win_events]") {
    const std::string xml =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "<EventID>4624</EventID><TimeCreated SystemTime='t'/></System>"
        "<EventData><Data Name='TargetUserSid'>S-1-5-21-0-0-0-1</Data>"
        "<Data Name='TargetUserName'>Alex</Data>"
        "<Data Name='TargetDomainName'>R&amp;D</Data>"
        "<Data Name='LogonType'>3</Data></EventData></Event>";
    auto events = parse_logon_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].target_domain == "R&D");
}

TEST_CASE("primary_user_from_events / session_history_rows: entity-decoded text flows through "
          "both projections",
          "[users][win_events]") {
    auto events = parse_logon_events(make_event("4624", "2026-08-14T20:10:49.0000000Z",
                                                 "R&amp;D User", "3"));
    REQUIRE(events.size() == 1);

    auto [primary, count] = primary_user_from_events(events);
    CHECK(primary == "R&D User");
    CHECK(count == 1);

    auto rows = session_history_rows(events);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] ==
          "session_history|R&D User|logon|network|-|2026-08-14T20:10:49.0000000Z|4624");
}

// ---------------------------------------------------------------------------
// primary_user_from_events
// ---------------------------------------------------------------------------

TEST_CASE("primary_user_from_events: picks the max, excluding machine/'SYSTEM'/'-' accounts",
          "[users][win_events]") {
    // The real 5-event fixture: Alex x4 (LogonType=3), sshd_3112 x1
    // (LogonType=5) -- both are countable TargetUserName values (neither is
    // excluded), so Alex must win 4-to-1.
    auto events = parse_logon_events(kFixture4624Full);
    REQUIRE(events.size() == 5);
    auto [primary, count] = primary_user_from_events(events);
    CHECK(primary == "Alex");
    CHECK(count == 4);
}

TEST_CASE("primary_user_from_events: a machine account, SYSTEM, and '-' are all excluded",
          "[users][win_events]") {
    std::vector<LogonEvent> events = {
        {"4624", "t1", "DESKTOP-04DNSIG$", "", "3", "", ""},
        {"4624", "t2", "SYSTEM", "", "3", "", ""},
        {"4624", "t3", "-", "", "3", "", ""},
        {"4624", "t4", "Alex", "", "3", "", ""},
    };
    auto [primary, count] = primary_user_from_events(events);
    CHECK(primary == "Alex");
    CHECK(count == 1);
}

TEST_CASE("primary_user_from_events: a count TIE picks the lexicographically smallest name",
          "[users][win_events]") {
    // Bob and Alice both occur twice -- first-seen order (Bob first) must
    // NOT win; the ordered-map scan picks "Alice" (today's behaviour at the
    // pre-migration text parser's :930-936).
    std::vector<LogonEvent> events = {
        {"4624", "t1", "Bob", "", "3", "", ""},   {"4624", "t2", "Bob", "", "3", "", ""},
        {"4624", "t3", "Alice", "", "3", "", ""}, {"4624", "t4", "Alice", "", "3", "", ""},
    };
    auto [primary, count] = primary_user_from_events(events);
    CHECK(primary == "Alice");
    CHECK(count == 2);
}

TEST_CASE("primary_user_from_events: no countable events returns {\"\", 0}",
          "[users][win_events]") {
    std::vector<LogonEvent> events = {
        {"4624", "t1", "SYSTEM", "", "3", "", ""},
        {"4624", "t2", "-", "", "3", "", ""},
    };
    auto [primary, count] = primary_user_from_events(events);
    CHECK(primary.empty());
    CHECK(count == 0);

    auto [empty_primary, empty_count] = primary_user_from_events({});
    CHECK(empty_primary.empty());
    CHECK(empty_count == 0);
}

// ---------------------------------------------------------------------------
// session_history_rows
// ---------------------------------------------------------------------------

TEST_CASE("session_history_rows: full field-by-field assertion on one real 4624 event",
          "[users][win_events]") {
    auto events = parse_logon_events(kFixtureMixed);
    REQUIRE(events.size() == 8);
    REQUIRE(events[0].event_id == "4624");

    auto rows = session_history_rows(events);
    // event_type=logon (4624); logon_type=network (LogonType 3); source=- (
    // this capture's IpAddress Data element is the literal string "-", the
    // real-world "no client IP recorded" case for a local console/service
    // logon); time = the SystemTime attribute verbatim; event_id = 4624.
    CHECK(rows[0] ==
          "session_history|Alex|logon|network|-|2026-08-14T20:10:49.4173297Z|4624");
}

TEST_CASE("session_history_rows: a decoded pipe/CR/LF entity cannot corrupt row framing",
          "[users][win_events]") {
    // A TargetUserName/IpAddress containing an XML numeric entity for '|'
    // (&#124;), CR (&#13;), or LF (&#10;) decodes to that literal byte --
    // safe_output_field must fold it back to a harmless form so this row
    // still parses as exactly 7 pipe-delimited fields downstream.
    auto events =
        parse_logon_events(make_event("4624", "t", "Ev&#124;il&#13;&#10;User", "3"));
    REQUIRE(events.size() == 1);
    // Un-decoded/unescaped, this row would gain extra '|'-delimited fields
    // and an embedded newline that splits it into multiple lines.
    auto rows = session_history_rows(events);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].find('\n') == std::string::npos);
    CHECK(rows[0].find('\r') == std::string::npos);
    // The decoded '|' is present but backslash-escaped (safe_output_field's
    // contract, matching the shared server decoder's "\|" -> "|" unescape)
    // -- it must never appear as a bare, unescaped delimiter.
    CHECK(rows[0].find("\\|") != std::string::npos);
    // Splitting on UNESCAPED '|' only (the server decoder's own rule: a
    // literal '|' is preceded by '\\') must yield exactly 7 fields --
    // session_history|user|type|logon_type|source|time|event_id -- not more.
    int field_count = 1;
    for (std::size_t i = 0; i < rows[0].size(); ++i) {
        if (rows[0][i] == '|' && (i == 0 || rows[0][i - 1] != '\\'))
            ++field_count;
    }
    CHECK(field_count == 7);
}

TEST_CASE("session_history_rows: a malicious TimeCreated/EventID cannot corrupt row framing",
          "[users][win_events]") {
    // TimeCreated's SystemTime attribute is never entity-decoded (unlike
    // TargetUserName/EventID), so a raw '|'/CR/LF byte reaching it -- e.g.
    // from a malformed or replayed capture -- must still be safe_output_field
    // escaped, same as event_id (which IS entity-decoded via extract_tag_text
    // before this fix). Neither field was covered by the earlier pipe/CR/LF
    // regression test above, which only exercised TargetUserName.
    auto events = parse_logon_events(
        make_event("4624&#124;evil", "mal|icious\r\ntime", "Alex", "3"));
    REQUIRE(events.size() == 1);
    auto rows = session_history_rows(events);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].find('\n') == std::string::npos);
    CHECK(rows[0].find('\r') == std::string::npos);
    CHECK(rows[0].find("\\|") != std::string::npos);
    int field_count = 1;
    for (std::size_t i = 0; i < rows[0].size(); ++i) {
        if (rows[0][i] == '|' && (i == 0 || rows[0][i - 1] != '\\'))
            ++field_count;
    }
    CHECK(field_count == 7);
}

TEST_CASE("session_history_rows: full field-by-field assertion on one real 4634 event",
          "[users][win_events]") {
    auto events = parse_logon_events(kFixtureMixed);
    REQUIRE(events.size() == 8);
    REQUIRE(events[1].event_id == "4634");
    // Verified against the fixture: this 4634 event's <EventData> carries
    // only the five Target* items -- no IpAddress element at all.
    REQUIRE(events[1].ip_address.empty());

    auto rows = session_history_rows(events);
    // event_type=logoff (not 4624); logon_type=network (LogonType 3);
    // source=- (IpAddress absent -> the "-" sentinel, not empty); time =
    // the SystemTime attribute verbatim; event_id = 4634.
    CHECK(rows[1] ==
          "session_history|Alex|logoff|network|-|2026-08-14T20:10:49.3626600Z|4634");
}

TEST_CASE("session_history_rows: source is IpAddress, never WorkstationName",
          "[users][win_events]") {
    LogonEvent ev{"4624", "2026-08-14T00:00:00Z", "Alex", "DOMAIN",
                  "10",   "WORKSTATION-A",         "203.0.113.7"};
    auto rows = session_history_rows({ev});
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] ==
          "session_history|Alex|logon|remote_interactive|203.0.113.7|2026-08-14T00:00:00Z|4624");
}

TEST_CASE("session_history_rows: every documented LogonType maps to its name; an unmapped "
          "numeric value passes through verbatim",
          "[users][win_events]") {
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"2", "interactive"},        {"3", "network"},
        {"4", "batch"},              {"5", "service"},
        {"7", "unlock"},             {"8", "network_cleartext"},
        {"9", "new_credentials"},    {"10", "remote_interactive"},
        {"11", "cached_interactive"}, {"6", "6"}, // undocumented value -> verbatim
        {"99", "99"},
    };
    for (const auto& [raw, expected] : cases) {
        LogonEvent ev{"4624", "t", "Alex", "DOMAIN", raw, "", ""};
        auto rows = session_history_rows({ev});
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == std::format("session_history|Alex|logon|{}|-|t|4624", expected));
    }
}

TEST_CASE("session_history_rows: an ABSENT LogonType formats as the empty field, not '-'",
          "[users][win_events]") {
    LogonEvent ev{"4624", "t", "Alex", "DOMAIN", /*logon_type_raw=*/"", "", ""};
    auto rows = session_history_rows({ev});
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "session_history|Alex|logon||-|t|4624");
}

TEST_CASE("session_history_rows: an absent TimeCreated formats as '-'", "[users][win_events]") {
    LogonEvent ev{"4624", /*time_created=*/"", "Alex", "DOMAIN", "3", "", ""};
    auto rows = session_history_rows({ev});
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "session_history|Alex|logon|network|-|-|4624");
}

TEST_CASE("session_history_rows: event_type is logon only for 4624, logoff for everything else",
          "[users][win_events]") {
    LogonEvent logon{"4624", "t", "Alex", "DOMAIN", "3", "", ""};
    LogonEvent logoff{"4634", "t", "Alex", "DOMAIN", "3", "", ""};
    LogonEvent other{"4647", "t", "Alex", "DOMAIN", "3", "", ""}; // not 4624 -> logoff bucket
    CHECK(session_history_rows({logon})[0].find("|logon|") != std::string::npos);
    CHECK(session_history_rows({logoff})[0].find("|logoff|") != std::string::npos);
    CHECK(session_history_rows({other})[0].find("|logoff|") != std::string::npos);
}

TEST_CASE("session_history_rows: excludes machine/'SYSTEM'/'-' target users, in query order",
          "[users][win_events]") {
    std::vector<LogonEvent> events = {
        {"4624", "t1", "DESKTOP-04DNSIG$", "", "3", "", ""},
        {"4624", "t2", "SYSTEM", "", "3", "", ""},
        {"4624", "t3", "-", "", "3", "", ""},
        {"4624", "t4", "Alex", "", "3", "", ""},
        {"4634", "t5", "Alex", "", "3", "", ""},
    };
    auto rows = session_history_rows(events);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "session_history|Alex|logon|network|-|t4|4624");
    CHECK(rows[1] == "session_history|Alex|logoff|network|-|t5|4634");
}

TEST_CASE("session_history_rows: empty input yields an empty vector", "[users][win_events]") {
    CHECK(session_history_rows({}).empty());
}
