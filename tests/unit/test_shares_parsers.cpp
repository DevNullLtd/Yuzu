/**
 * test_shares_parsers.cpp -- pure tests for the shares plugin's exports(5) (Linux and BSD),
 * smb.conf and `sharing -l -f json` parsers and its row formatters. Portable, no I/O.
 *
 * Fixture provenance (labelled per case):
 *   REAL CAPTURE     -- `/usr/sbin/sharing -l -f json` on macOS 26.6.2 (2026-10-12), with the
 *                       record name and path anonymised ("Shared Folder", /Users/jsmith/Public);
 *                       and the stock /etc/exports (nfs-kernel-server 1:2.8.3-1) and
 *                       /etc/samba/smb.conf (samba-common 2:4.22.11+dfsg-0+deb13u1) from a
 *                       Debian GNU/Linux 13 (trixie) aarch64 container, 2026-10-12, verbatim except that
 *                       trailing whitespace is stripped (the parsers trim it; the repo lints it).
 *   RECONSTRUCTION   -- every other specimen (populated exports lines, Samba synonym / copy= /
 *                       registry / include / usershare cases, BSD exports lines), rebuilt from
 *                       exports(5), smb.conf(5) and the macOS `man exports` examples. None is
 *                       a capture.
 */
#include <catch2/catch_test_macros.hpp>

#include "shares_parsers.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::shares;

namespace {

yuzu::shared::RowByteBudget fresh_budget() {
    return yuzu::shared::RowByteBudget{kMaxShareRows, kMaxShareBytes};
}

ExportsParse lin(std::string_view text, std::size_t rows = kMaxShareRows) {
    auto b = yuzu::shared::RowByteBudget{rows, kMaxShareBytes};
    ExportsParse p;
    parse_exports(text, "exports", b, p);
    return p;
}

ExportsParse bsd(std::string_view text, std::size_t rows = kMaxShareRows) {
    auto b = yuzu::shared::RowByteBudget{rows, kMaxShareBytes};
    ExportsParse p;
    parse_bsd_exports(text, "exports", b, p);
    return p;
}

SmbConf smb(std::string_view text) {
    auto b = fresh_budget();
    return parse_smb_conf(text, b);
}

const Share& by_name(const SmbConf& c, std::string_view n) {
    const auto it = std::ranges::find_if(c.shares, [&](const Share& s) { return s.name == n; });
    REQUIRE(it != c.shares.end());
    return *it;
}

bool has_flag(const Share& s, std::string_view f) {
    return std::ranges::find(s.flags, f) != s.flags.end();
}

std::string flags_of(const Share& s) {
    std::string out;
    for (const auto& f : s.flags)
        out += (out.empty() ? "" : ",") + f;
    return out;
}

// REAL CAPTURE: /etc/exports as installed by nfs-kernel-server 1:2.8.3-1 (comments only),
// Debian GNU/Linux 13 (trixie) aarch64 container, 2026-10-12. Verbatim except stripped trailing
// whitespace (see banner).
constexpr const char* kStockExports = R"EXP(# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
)EXP";

// REAL CAPTURE: /etc/samba/smb.conf as installed by samba-common 2:4.22.11+dfsg-0+deb13u1,
// same container and date. Verbatim except stripped trailing whitespace (see
// banner).
constexpr const char* kStockSmb = R"SMB(#
# Sample configuration file for the Samba suite for Debian GNU/Linux.
#
#
# This is the main Samba configuration file. You should read the
# smb.conf(5) manual page in order to understand the options listed
# here. Samba has a huge number of configurable options most of which
# are not shown in this example
#
# Some options that are often worth tuning have been included as
# commented-out examples in this file.
#  - When such options are commented with ";", the proposed setting
#    differs from the default Samba behaviour
#  - When commented with "#", the proposed setting is the default
#    behaviour of Samba but the option is considered important
#    enough to be mentioned here
#
# NOTE: Whenever you modify this file you should run the command
# "testparm" to check that you have not made any basic syntactic
# errors.

#======================= Global Settings =======================

[global]

## Browsing/Identification ###

# Change this to the workgroup/NT-domain name your Samba server will part of
   workgroup = WORKGROUP

#### Networking ####

# The specific set of interfaces / networks to bind to
# This can be either the interface name or an IP address/netmask;
# interface names are normally preferred
;   interfaces = 127.0.0.0/8 eth0

# Only bind to the named interfaces and/or networks; you must use the
# 'interfaces' option above to use this.
# It is recommended that you enable this feature if your Samba machine is
# not protected by a firewall or is a firewall itself.  However, this
# option cannot handle dynamic or non-broadcast interfaces correctly.
;   bind interfaces only = yes



#### Debugging/Accounting ####

# This tells Samba to use a separate log file for each machine
# that connects
   log file = /var/log/samba/log.%m

# Cap the size of the individual log files (in KiB).
   max log size = 1000

# We want Samba to only log to /var/log/samba/log.{smbd,nmbd}.
# Append syslog@1 if you want important messages to be sent to syslog too.
   logging = file

# Do something sensible when Samba crashes: mail the admin a backtrace
   panic action = /usr/share/samba/panic-action %d


####### Authentication #######

# Server role. Defines in which mode Samba will operate. Possible
# values are "standalone server", "member server", "classic primary
# domain controller", "classic backup domain controller", "active
# directory domain controller".
#
# Most people will want "standalone server" or "member server".
# Running as "active directory domain controller" will require first
# running "samba-tool domain provision" to wipe databases and create a
# new domain.
   server role = standalone server

   obey pam restrictions = yes

# This boolean parameter controls whether Samba attempts to sync the Unix
# password with the SMB password when the encrypted SMB password in the
# passdb is changed.
   unix password sync = yes

# For Unix password sync to work on a Debian GNU/Linux system, the following
# parameters must be set (thanks to Ian Kahan <<kahan@informatik.tu-muenchen.de> for
# sending the correct chat script for the passwd program in Debian Sarge).
   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

# This boolean controls whether PAM will be used for password changes
# when requested by an SMB client instead of the program listed in
# 'passwd program'. The default is 'no'.
   pam password change = yes

# This option controls how unsuccessful authentication attempts are mapped
# to anonymous connections
   map to guest = bad user

########## Domains ###########

#
# The following settings only takes effect if 'server role = classic
# primary domain controller', 'server role = classic backup domain controller'
# or 'domain logons' is set
#

# It specifies the location of the user's
# profile directory from the client point of view) The following
# required a [profiles] share to be setup on the samba server (see
# below)
;   logon path = \\%N\profiles\%U
# Another common choice is storing the profile in the user's home directory
# (this is Samba's default)
#   logon path = \\%N\%U\profile

# The following setting only takes effect if 'domain logons' is set
# It specifies the location of a user's home directory (from the client
# point of view)
;   logon drive = H:
#   logon home = \\%N\%U

# The following setting only takes effect if 'domain logons' is set
# It specifies the script to run during logon. The script must be stored
# in the [netlogon] share
# NOTE: Must be store in 'DOS' file format convention
;   logon script = logon.cmd

# This allows Unix users to be created on the domain controller via the SAMR
# RPC pipe.  The example command creates a user account with a disabled Unix
# password; please adapt to your needs
; add user script = /usr/sbin/useradd --create-home %u

# This allows machine accounts to be created on the domain controller via the
# SAMR RPC pipe.
# The following assumes a "machines" group exists on the system
; add machine script  = /usr/sbin/useradd -g machines -c "%u machine account" -d /var/lib/samba -s /bin/false %u

# This allows Unix groups to be created on the domain controller via the SAMR
# RPC pipe.
; add group script = /usr/sbin/addgroup --force-badname %g

############ Misc ############

# Using the following line enables you to customise your configuration
# on a per machine basis. The %m gets replaced with the netbios name
# of the machine that is connecting
;   include = /home/samba/etc/smb.conf.%m

# Some defaults for winbind (make sure you're not using the ranges
# for something else.)
;   idmap config * :              backend = tdb
;   idmap config * :              range   = 3000-7999
;   idmap config YOURDOMAINHERE : backend = tdb
;   idmap config YOURDOMAINHERE : range   = 100000-999999
;   template shell = /bin/bash

# Setup usershare options to enable non-root users to share folders
# with the net usershare command.

# Maximum number of usershare. 0 means that usershare is disabled.
#   usershare max shares = 100

# Allow users who've been granted usershare privileges to create
# public shares, not just authenticated ones
   usershare allow guests = yes

#======================= Share Definitions =======================

[homes]
   comment = Home Directories
   browseable = no

# By default, the home directories are exported read-only. Change the
# next parameter to 'no' if you want to be able to write to them.
   read only = yes

# File creation mask is set to 0700 for security reasons. If you want to
# create files with group=rw permissions, set next parameter to 0775.
   create mask = 0700

# Directory creation mask is set to 0700 for security reasons. If you want to
# create dirs. with group=rw permissions, set next parameter to 0775.
   directory mask = 0700

# By default, \\server\username shares can be connected to by anyone
# with access to the samba server.
# The following parameter makes sure that only "username" can connect
# to \\server\username
# This might need tweaking when using external authentication schemes
   valid users = %S

# Un-comment the following and create the netlogon directory for Domain Logons
# (you need to configure Samba to act as a domain controller too.)
;[netlogon]
;   comment = Network Logon Service
;   path = /home/samba/netlogon
;   guest ok = yes
;   read only = yes

# Un-comment the following and create the profiles directory to store
# users profiles (see the "logon path" option above)
# (you need to configure Samba to act as a domain controller too.)
# The path below should be writable by all users so that their
# profile directory may be created the first time they log on
;[profiles]
;   comment = Users profiles
;   path = /home/samba/profiles
;   guest ok = no
;   browseable = no
;   create mask = 0600
;   directory mask = 0700

[printers]
   comment = All Printers
   browseable = no
   path = /var/tmp
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

# Windows clients look for this share name as a source of downloadable
# printer drivers
[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
# Uncomment to allow remote administration of Windows print drivers.
# You may need to replace 'lpadmin' with the name of the group your
# admin users are members of.
# Please note that you also need to set appropriate Unix permissions
# to the drivers directory for these users to have write rights in it
;   write list = root, @lpadmin

)SMB";

std::size_t unescaped_pipes(const std::string& s) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < s.size(); ++i)
        if (s[i] == '|' && (i == 0 || s[i - 1] != '\\'))
            ++n;
    return n;
}

} // namespace

// ---------------------------------------------------------------------------
// Linux exports(5)
// ---------------------------------------------------------------------------

TEST_CASE("shares exports: stock comments-only file yields zero shares", "[shares]") {
    const auto p = lin(kStockExports);
    CHECK(p.shares.empty());
    CHECK_FALSE(p.truncated);
}

TEST_CASE("shares exports: the stock example lines, uncommented", "[shares]") {
    const auto p = lin(
        "/srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)\n"
        "/srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)\n");
    REQUIRE(p.shares.size() == 2);
    CHECK(p.shares[0].path == "/srv/homes");
    CHECK(p.shares[0].name == "-");
    CHECK(p.shares[0].access == Access::mixed);
    CHECK(p.shares[0].anonymous == false);
    CHECK(flags_of(p.shares[0]) == "clients_2");
    CHECK(p.shares[1].access == Access::rw);
    CHECK(flags_of(p.shares[1]) == "clients_1");
}

TEST_CASE("shares exports: world export with no_root_squash", "[shares]") {
    const auto p = lin("/srv/pub *(rw,no_root_squash)\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].anonymous == true);
    CHECK(p.shares[0].access == Access::rw);
    CHECK(flags_of(p.shares[0]) == "no_root_squash,clients_1");
}

TEST_CASE("shares exports: `host (rw)` space footgun is a host plus a world spec", "[shares]") {
    const auto p = lin("/srv/x host (rw)\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].anonymous == true);
    CHECK(p.shares[0].access == Access::mixed); // host defaults to ro, the world spec is rw
    CHECK(flags_of(p.shares[0]) == "clients_2");
}

TEST_CASE("shares exports: a -opts token is a line default for later specs", "[shares]") {
    const auto p = lin("/srv/data -rw host1 host2(ro)\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].path == "/srv/data");
    CHECK(p.shares[0].access == Access::mixed);
    CHECK(flags_of(p.shares[0]) == "clients_2"); // the option token is not a client
    CHECK(p.shares[0].anonymous == false);
    const auto rw = lin("/srv/data -rw host1\n");
    REQUIRE(rw.shares.size() == 1);
    CHECK(rw.shares[0].access == Access::rw);
}

TEST_CASE("shares exports: octal escapes and sec= segments", "[shares]") {
    const auto p = lin("/srv/my\\040dir host\n"
                       "/srv/s1 host(sec=krb5p,rw,sec=sys,ro)\n"
                       "/srv/s2 host(sec=krb5p,rw,sec=sys,rw)\n"
                       "/srv/s3 host(rw,sec=sys)\n"
                       "/srv/s4 host(sec=krb5p,rw,sec=sys)\n"
                       "/srv/s5 host(ro,sec=sys,rw)\n");
    REQUIRE(p.shares.size() == 6);
    CHECK(p.shares[0].path == "/srv/my dir");
    CHECK(p.shares[1].access == Access::mixed);
    CHECK(p.shares[2].access == Access::rw);
    // nfsd: a sec= flavour inherits every option accumulated so far, not the line defaults.
    CHECK(p.shares[3].access == Access::rw);
    CHECK(p.shares[4].access == Access::rw);
    CHECK(p.shares[5].access == Access::rw);
}

TEST_CASE("shares exports: a line whose first token is not an absolute path is skipped",
          "[shares]") {
    const auto p = lin("-ro host(rw)\n/ok host\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].path == "/ok");
}

TEST_CASE("shares exports: quoted path, continuation, CRLF, no clients", "[shares]") {
    const auto p = lin("\"/srv/with space\" host(rw)\r\n"
                       "/srv/cont host1(rw) \\\r\n"
                       "   host2(ro)\r\n"
                       "/srv/noclients\r\n"
                       "# /srv/commented host\r\n");
    REQUIRE(p.shares.size() == 3);
    CHECK(p.shares[0].path == "/srv/with space");
    CHECK(p.shares[1].path == "/srv/cont");
    CHECK(flags_of(p.shares[1]) == "clients_2");
    CHECK(p.shares[1].access == Access::mixed);
    CHECK(p.shares[2].anonymous == true);
    CHECK(p.shares[2].access == Access::ro);
    CHECK(flags_of(p.shares[2]) == "clients_0");
}

TEST_CASE("shares exports: a comment ending in a backslash does not swallow the next entry",
          "[shares]") {
    const auto p = lin("# note \\\n/srv/real host(rw)\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].path == "/srv/real");
}

TEST_CASE("shares exports: the row budget stops the parser", "[shares]") {
    std::string text;
    for (int i = 0; i < 2000; ++i)
        text += "/s" + std::to_string(i) + " h(rw)\n";
    const auto p = lin(text, 512);
    CHECK(p.shares.size() == 512);
    CHECK(p.truncated);
}

TEST_CASE("shares exports: an oversized path is cut and flagged", "[shares]") {
    const auto p = lin("/" + std::string(10000, 'a') + " host\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].path.size() == kMaxFieldBytes);
    CHECK(p.field_oversized);
}

// ---------------------------------------------------------------------------
// BSD / macOS exports(5)
// ---------------------------------------------------------------------------

// RECONSTRUCTION: the EXAMPLES block of `man exports` on macOS 26.6.
constexpr const char* kManExports = R"(/usr /usr/local -maproot=0:10 friends
/usr -maproot=daemon grumpy.cis.uoguelph.ca 131.104.48.16
/usr -ro -mapall=nobody
/u -maproot=bin: -network 131.104.48 -mask 255.255.255.0
/u1 -alldirs -network 2001:DB8:: -mask ffff:ffff::
/u2 -maproot=root friends
/u2 -alldirs -network cis-net -mask cis-mask
/Users -alldirs -network 2.29.96.0 -mask 255.255.255.0
/Applications -ro -network 2.29.96.0 -mask 255.255.255.0
)";

TEST_CASE("shares bsd exports: the man page examples", "[shares]") {
    const auto p = bsd(kManExports);
    REQUIRE(p.shares.size() == 10); // /usr + /usr/local share one line
    CHECK(p.shares[0].path == "/usr");
    CHECK(p.shares[1].path == "/usr/local");
    CHECK(flags_of(p.shares[0]) == "clients_1");
    CHECK(p.shares[0].access == Access::rw);
    CHECK(p.shares[0].anonymous == false);
    CHECK(flags_of(p.shares[2]) == "clients_2"); // two hosts
    CHECK(p.shares[3].access == Access::ro);     // -ro, no host: the world
    CHECK(p.shares[3].anonymous == true);
    CHECK(flags_of(p.shares[3]) == "clients_0");
    CHECK(flags_of(p.shares[4]) == "clients_1"); // -network net -mask mask is one client
    CHECK(p.shares[4].path == "/u");
    CHECK(p.shares[7].path == "/u2");            // the -network/-mask values are not hosts
    CHECK(flags_of(p.shares[7]) == "clients_1");
    CHECK(p.shares[9].access == Access::ro);
    for (const auto& s : p.shares)
        CHECK(s.name == "-");
}

TEST_CASE("shares bsd exports: -o, -offline, =-form network, quoting, comments", "[shares]") {
    const auto p = bsd("# header\n"
                       "/a -o host\n"
                       "/b -offline -network=10.0.0.0 -mask=255.0.0.0\n"
                       "\"/Volumes/My Disk\" -ro friends\n"
                       "/c host1 \\\n"
                       "   host2 # trailing\n"
                       "-ro host\n");
    REQUIRE(p.shares.size() == 4);
    CHECK(p.shares[0].access == Access::ro);
    CHECK(has_flag(p.shares[1], "unavailable"));
    CHECK(flags_of(p.shares[1]) == "unavailable,clients_1");
    CHECK(p.shares[2].path == "/Volumes/My Disk");
    CHECK(flags_of(p.shares[3]) == "clients_2");
}

TEST_CASE("shares bsd exports: options after the client list are honoured", "[shares]") {
    const auto p = bsd("/x host -sec=krb5p -ro\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].path == "/x");
    CHECK(p.shares[0].access == Access::ro);
    CHECK(p.shares[0].anonymous == false);
    CHECK(flags_of(p.shares[0]) == "clients_1"); // the -sec= value is not a client
}

TEST_CASE("shares bsd exports: duplicate paths, no-path lines, NUL, invalid UTF-8", "[shares]") {
    const auto p = bsd("/dup hostA\n/dup hostB\n");
    CHECK(p.shares.size() == 2); // one row per line and path, never merged
    std::string text = "/bad";
    text += '\0';
    text += "\xC0\xAF host\n";
    const auto q = bsd(text);
    REQUIRE(q.shares.size() == 1);
    const std::string row = share_row(q.shares[0]);
    CHECK(row.find('\0') == std::string::npos);
    CHECK(yuzu::shared::count_invalid_wire_bytes(row) == 0);
    CHECK(row.find("/bad???") != std::string::npos);
}

TEST_CASE("shares bsd exports: over-long line and budget exhaustion", "[shares]") {
    const auto long_line = bsd("/" + std::string(10000, 'p') + " host\n");
    REQUIRE(long_line.shares.size() == 1);
    CHECK(long_line.field_oversized);
    std::string text;
    for (int i = 0; i < 1000; ++i)
        text += "/e" + std::to_string(i) + " -ro\n";
    const auto p = bsd(text, 100);
    CHECK(p.shares.size() == 100);
    CHECK(p.truncated);
}

// ---------------------------------------------------------------------------
// Samba smb.conf
// ---------------------------------------------------------------------------

TEST_CASE("shares smb.conf: Debian stock layout", "[shares]") {
    const auto c = smb(kStockSmb);
    REQUIRE(c.shares.size() == 3);
    CHECK(c.shares[0].name == "homes");
    const auto& homes = by_name(c, "homes");
    CHECK(flags_of(homes) == "hidden,special");
    CHECK(homes.path == "-");
    CHECK(homes.access == Access::ro);
    CHECK(homes.anonymous == false);
    const auto& printers = by_name(c, "printers");
    CHECK(flags_of(printers) == "hidden,special");
    CHECK(printers.path == "/var/tmp");
    const auto& drv = by_name(c, "print$");
    CHECK(drv.flags == std::vector<std::string>{"special"});
    CHECK(drv.path == "/var/lib/samba/printers");
    CHECK_FALSE(c.registry_backend);
    CHECK_FALSE(c.include_present); // the `;   include =` line is a comment
    CHECK_FALSE(c.usershares_configured);
    for (const auto& s : c.shares) {
        CHECK(s.proto == Proto::smb);
        CHECK(s.source == "smb_conf");
    }
}

TEST_CASE("shares smb.conf: [global] values are inherited and overridden", "[shares]") {
    const auto c = smb("[global]\nread only = no\nguest ok = yes\n"
                       "[a]\npath = /srv/a\n"
                       "[b]\npath = /srv/b\nread only = yes\nguest ok = no\n");
    CHECK(by_name(c, "a").access == Access::rw);
    CHECK(by_name(c, "a").anonymous == true);
    CHECK(by_name(c, "b").access == Access::ro);
    CHECK(by_name(c, "b").anonymous == false);
}

TEST_CASE("shares smb.conf: a share-local synonym beats a global read only; last wins",
          "[shares]") {
    const auto c = smb("[global]\nread only = yes\n"
                       "[a]\npath=/a\nwritable = yes\n"
                       "[b]\npath=/b\nread only = yes\nwritable = yes\n"
                       "[c]\npath=/c\nwritable = yes\nread only = yes\n");
    CHECK(by_name(c, "a").access == Access::rw);
    CHECK(by_name(c, "b").access == Access::rw);
    CHECK(by_name(c, "c").access == Access::ro);
}

TEST_CASE("shares smb.conf: case-variant section reopenings merge, last assignment wins",
          "[shares]") {
    const auto c = smb("[Global]\nguest ok = yes\n"
                       "[Docs]\npath=/old\n[docs]\npath=/middle\n[Docs]\npath=/new\n"
                       "[global]\nread only = no\n"
                       "[Copy]\ncopy = DOCS\n");
    CHECK(std::ranges::count_if(c.shares, [](const Share& s) { return s.name == "Docs"; }) == 1);
    CHECK(c.shares.size() == 2);
    CHECK(by_name(c, "Docs").path == "/new");
    CHECK(by_name(c, "Docs").access == Access::rw); // later [global] spelling honoured
    CHECK(by_name(c, "Docs").anonymous == true);
    CHECK(by_name(c, "Copy").path == "/new");
    CHECK_FALSE(c.copy_unresolved);
}

TEST_CASE("shares smb.conf: parameter synonyms and spelling normalise", "[shares]") {
    const auto c = smb("[a]\npath=/a\nwriteable = yes\n"
                       "[b]\npath=/b\nwrite ok = yes\n"
                       "[c]\ndirectory=/c\npublic = yes\nbrowsable = no\n"
                       "[d]\npath=/d\nreadonly=yes\n"
                       "[e]\npath=/e\nRead Only = No\n");
    CHECK(by_name(c, "a").access == Access::rw);
    CHECK(by_name(c, "b").access == Access::rw);
    CHECK(by_name(c, "c").path == "/c");
    CHECK(by_name(c, "c").anonymous == true);
    CHECK(has_flag(by_name(c, "c"), "hidden"));
    CHECK(by_name(c, "d").access == Access::ro);
    CHECK(by_name(c, "e").access == Access::rw);
}

TEST_CASE("shares smb.conf: copy chains, unresolved targets and cycles", "[shares]") {
    const auto c = smb("[base]\npath=/srv/base\nguest ok = yes\n"
                       "[a]\ncopy = base\npath = /srv/a\n"
                       "[b]\ncopy = a\n"
                       "[m]\ncopy = missing\npath=/srv/m\n");
    CHECK(by_name(c, "a").anonymous == true);
    CHECK(by_name(c, "a").path == "/srv/a"); // local key overrides the copy
    CHECK(by_name(c, "b").path == "/srv/a"); // chained through a
    CHECK(by_name(c, "b").anonymous == true);
    CHECK(c.copy_unresolved);
    CHECK(by_name(c, "m").path == "/srv/m"); // still emitted from its own keys
    const auto cyc = smb("[x]\ncopy = y\npath=/x\n[y]\ncopy = x\n");
    CHECK(cyc.copy_unresolved);
    CHECK(cyc.shares.size() == 2);
    const auto clean = smb("[x]\npath=/x\n");
    CHECK_FALSE(clean.copy_unresolved);
}

TEST_CASE("shares smb.conf: registry backend, include and usershares are detected", "[shares]") {
    CHECK(smb("[global]\nconfig backend = registry\n").registry_backend);
    CHECK(smb("[global]\nregistry shares = yes\n").registry_backend);
    CHECK_FALSE(smb("[global]\nregistry shares = no\n").registry_backend);
    CHECK(smb("[global]\ninclude = /etc/samba/shares.conf\n").include_present);
    CHECK(smb("[global]\nusershare max shares = 100\n").usershares_configured);
    CHECK_FALSE(smb("[global]\nusershare max shares = 0\n").usershares_configured);
    const auto p = smb("[global]\nusershare path = /var/lib/samba/us\n");
    CHECK(p.usershares_configured);
    CHECK(p.usershare_path == "/var/lib/samba/us");
}

TEST_CASE("shares smb.conf: continuation, macros kept verbatim, available = no", "[shares]") {
    const auto c = smb("[a]\npath = /srv/\\\n%U\navailable = no\n"
                       "[h]\r\npath = /home/%H\r\nread only = no\r\n");
    CHECK(by_name(c, "a").path == "/srv/%U");
    CHECK(has_flag(by_name(c, "a"), "unavailable"));
    CHECK(by_name(c, "h").path == "/home/%H");
    CHECK(by_name(c, "h").access == Access::rw);
}

TEST_CASE("shares smb.conf: a huge inherited value cannot be materialised per share", "[shares]") {
    // The F2 falsifier: a 100 KiB [global] path inherited by 10,000 sections. Allocation must
    // stop with the byte budget, not scale with the section count.
    std::string text = "[global]\npath = " + std::string(100 * 1024, 'p') + "\n";
    for (int i = 0; i < 10000; ++i)
        text += "[s" + std::to_string(i) + "]\n";
    auto b = fresh_budget();
    const auto c = parse_smb_conf(text, b);
    CHECK(c.truncated);
    CHECK(c.shares.size() <= 11);
    CHECK(b.bytes <= kMaxShareBytes);
    std::size_t held = 0;
    for (const auto& s : c.shares)
        held += s.path.size() + s.name.size();
    CHECK(held <= kMaxShareBytes);
    CHECK(c.field_oversized);
}

// ---------------------------------------------------------------------------
// macOS `sharing -l -f json`
// ---------------------------------------------------------------------------

// REAL CAPTURE 2026-10-12, macOS 26.6.2 (record name and path anonymised).
constexpr const char* kSharingJson = R"({
  "Shared Folder" : {
    "path" : "\/Users\/jsmith\/Public",
    "smb_guest_access" : 1,
    "smb_name" : "Shared Folder",
    "smb_read_only" : 0,
    "smb_sealed" : 0,
    "smb_shared" : 1
  }
})";

TEST_CASE("shares sharing json: real capture", "[shares]") {
    auto b = fresh_budget();
    const auto p = parse_sharing_json(kSharingJson, b);
    REQUIRE(p.recognised);
    REQUIRE(p.shares.size() == 1);
    const auto& s = p.shares[0];
    CHECK(s.proto == Proto::smb);
    CHECK(s.name == "Shared Folder");
    CHECK(s.path == "/Users/jsmith/Public");
    CHECK(s.access == Access::rw);
    CHECK(s.anonymous == true);
    CHECK(s.flags.empty());
    CHECK(s.source == "sharing");
    CHECK(share_row(s) == "share|smb|Shared Folder|/Users/jsmith/Public|rw|true|-|sharing");
}

TEST_CASE("shares sharing json: empty, unrecognised, flags, malformed records", "[shares]") {
    auto b = fresh_budget();
    CHECK(parse_sharing_json("{}", b).recognised);
    CHECK(parse_sharing_json("{}", b).shares.empty());
    const auto ws = parse_sharing_json("  \n ", b);
    CHECK(ws.recognised);
    CHECK(ws.shares.empty());
    CHECK_FALSE(parse_sharing_json("List of Share Points\n", b).recognised);
    CHECK_FALSE(parse_sharing_json("[1,2]", b).recognised);

    const auto f = parse_sharing_json(
        R"({"k":{"path":"/p","smb_shared":0,"smb_sealed":1,"smb_read_only":1}})", b);
    REQUIRE(f.shares.size() == 1);
    CHECK(f.shares[0].name == "k"); // missing smb_name falls back to the record key
    CHECK(f.shares[0].flags == std::vector<std::string>{"unavailable", "sealed"});
    CHECK(f.shares[0].access == Access::ro);
    CHECK_FALSE(f.shares[0].anonymous.has_value());

    const auto m1 = parse_sharing_json(R"({"x":{}})", b);
    CHECK(m1.malformed_records == 1);
    CHECK(m1.shares.empty());
    const auto m2 = parse_sharing_json(R"({"x":1})", b);
    CHECK(m2.malformed_records == 1);
    const auto mix = parse_sharing_json(R"({"bad":{"path":7},"good":{"path":"/g"}})", b);
    CHECK(mix.malformed_records == 1);
    REQUIRE(mix.shares.size() == 1);
    CHECK(mix.shares[0].name == "good");
}

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

TEST_CASE("shares formatters: field order, flag vocabulary, source rows", "[shares]") {
    Share s;
    s.proto = Proto::nfs;
    s.name = "-";
    s.path = "/srv/x";
    s.access = Access::mixed;
    s.anonymous = false;
    s.flags = {"no_root_squash", "clients_2"};
    s.source = "exports_d";
    CHECK(share_row(s) == "share|nfs|-|/srv/x|mixed|false|no_root_squash,clients_2|exports_d");
    Share bare;
    bare.proto = Proto::smb;
    bare.source = "sharing";
    CHECK(share_row(bare) == "share|smb|-|-|-|-|-|sharing");
    CHECK(source_row("exports", SourceState::absent) == "source|exports|absent|-");
    CHECK(source_row("smb_conf", SourceState::read, 3) == "source|smb_conf|read|3");
    CHECK(source_row("exports_d", SourceState::refused) == "source|exports_d|refused|-");
    CHECK(source_row("exports", SourceState::failed) == "source|exports|failed|-");
    CHECK(kMaxShareRows == 512);
    CHECK(is_exports_name("a.exports"));
    CHECK_FALSE(is_exports_name(".hidden.exports"));
    CHECK_FALSE(is_exports_name("a.conf"));
    CHECK_FALSE(is_exports_name(".exports"));
}

TEST_CASE("shares formatters: every bad byte becomes '?' and the field count holds", "[shares]") {
    Share s;
    s.proto = Proto::nfs;
    s.name = "-";
    s.access = Access::ro;
    s.anonymous = true;
    s.source = "exports";
    std::string path = "/p";
    path += "\xC0\xAF";     // overlong '/'
    path += "\xED\xA0\x80"; // UTF-16 surrogate
    path += "\xF4\x90\x80\x80"; // above U+10FFFF
    path += "\x80";         // stray continuation
    path += '|';
    path += '\\';
    path += '\0';
    path += "end";
    s.path = path;
    const std::string row = share_row(s);
    CHECK(unescaped_pipes(row) == 7); // 8 fields, none opened by the data
    CHECK(row.find('\0') == std::string::npos);
    CHECK(yuzu::shared::count_invalid_wire_bytes(row) == 0);
    // 2 + 3 + 4 + 1 bad bytes, then the escaped pipe, the folded backslash, NUL as '?'.
    CHECK(row.find("|/p??????????\\|/?end|") != std::string::npos);
}
