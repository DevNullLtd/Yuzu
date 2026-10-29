/**
 * test_shares_parsers.cpp -- pure tests for the shares plugin's exports(5) (Linux and BSD),
 * smb.conf and `sharing -l -f json` parsers and its row formatters. Portable, no I/O.
 *
 * Fixture provenance (labelled per case):
 *   REAL CAPTURE     -- the stock /etc/exports (nfs-kernel-server 1:2.8.3-1) and
 *                       /etc/samba/smb.conf (samba-common 2:4.22.11+dfsg-0+deb13u1) from a
 *                       Debian GNU/Linux 13 (trixie) aarch64 container, 2026-10-12, verbatim except that
 *                       trailing whitespace is stripped (the parsers trim it; the repo lints it).
 *   SEEDED INPUT     -- the three files the Linux sample was captured from (see
 *                       kSeeded*): written by the capture script into the same container,
 *                       2026-10-12, and kept here verbatim so the sample's rows are asserted.
 *   RECONSTRUCTION   -- every other specimen (populated exports lines, Samba synonym / copy= /
 *                       registry / include / usershare cases), rebuilt from exports(5) and
 *                       smb.conf(5). None is a capture. The BSD cases are the exports(5) man
 *                       page lines plus shapes read off Apple's mountd.c (get_export_entry,
 *                       nextfield, clean_pathname, do_opt, get_net) and the kernel's
 *                       nfsrv_hang_addrlist / nfsrv_export_lookup.
 *   REDACTED CAPTURE -- kSharingCapture: `sharing -l -f json` on macOS 26.6.2 arm64 (braga,
 *                       2026-10-29) with the account name and share name replaced (jsmith).
 *                       `No share point records.` is NOT a capture: it is the tool's string
 *                       table entry, never observed live.
 */
#include <catch2/catch_test_macros.hpp>

#include "shares_parsers.hpp"

#include <algorithm>
#include <array>
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

// SEEDED INPUT 2026-10-12 container -- produced docs/samples/linux.txt (verbatim from the
// capture script's heredocs).
constexpr const char* kSeededExports =
    "# /etc/exports: the access control list for filesystems which may be exported to NFS clients\n"
    "/srv/nfs/public    *(ro,sync,no_subtree_check)\n"
    "/srv/nfs/projects  192.168.10.0/24(rw,sync,no_root_squash) 10.0.0.5(ro)\n";
constexpr const char* kSeededExportsD = "/srv/nfs/archive   *(ro,all_squash)\n";
constexpr const char* kSeededSmb = R"SMB([global]
   workgroup = WORKGROUP
   server role = standalone server
   read only = yes
[public]
   path = /srv/samba/public
   guest ok = yes
[projects]
   path = /srv/samba/projects
   writable = yes
   browseable = no
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

TEST_CASE("shares exports: every world-equivalent client reads anonymous", "[shares]") {
    // One row per spelling; each is a client that admits everyone.
    for (const char* spec : {"*(rw)", "(rw)", "?*(rw)", "**(rw)", "0.0.0.0/0(rw)", "::/0(rw)", "0/0(rw)",
                             "0.0.0.0/0.0.0.0(rw)", "0:0:0:0:0:0:0:0/0(rw)",
                             // the mask decides, not the address (nfs-utils: ((a ^ b) & mask) == 0)
                             "10.1.2.3/0(rw)", "1.2.3.4/0.0.0.0(rw)", "::1/0(rw)", "0::/0(rw)",
                             "0:0:0::0/0(rw)", "1::/0(rw)"}) {
        const auto p = lin(std::string("/srv/w ") + spec + "\n");
        REQUIRE(p.shares.size() == 1);
        INFO(spec);
        CHECK(p.shares[0].anonymous == true);
        CHECK(flags_of(p.shares[0]) == "clients_1"); // still counted as one client
    }
    // Not the world: a real network, a single zero host, a partial wildcard, a netgroup.
    // Also not the world: zero-looking strings no resolver accepts as an address (RECONSTRUCTION
    // of the adversarial-review witnesses).
    for (const char* spec : {"10.0.0.0/8(rw)", "0.0.0.0(rw)", "0.0.0.0/8(rw)", "*.corp(rw)", "?x(rw)",
                             "@trusted(rw)", "gss/krb5i(rw)", "::::/0(rw)", "0.../0(rw)", ":/0(rw)",
                             "0.:/0(rw)", "0.0.0.0.0/0(rw)", "0::0::0/0(rw)", "0:0:0:0:0:0:0:0:0/0(rw)",
                             "0.0.0.0/..(rw)", "0.0.0.0/(rw)", "0:0:0:0:0:0:0/0(rw)", "0:0:0:0::0:0:0:0/0(rw)",
                             "00000::/0(rw)", "host/0(rw)", "1.2.3.4/0.0.0.1(rw)"}) {
        const auto p = lin(std::string("/srv/w ") + spec + "\n");
        REQUIRE(p.shares.size() == 1);
        INFO(spec);
        CHECK(p.shares[0].anonymous == false);
    }
}

TEST_CASE("shares exports: no_root_squash honours squash options as nfs-utils applies them in order",
          "[shares]") {
    const auto flags = [](const char* opts) {
        const auto p = lin(std::string("/srv/r host(") + opts + ")\n");
        REQUIRE(p.shares.size() == 1);
        return flags_of(p.shares[0]);
    };
    CHECK(flags("rw,no_root_squash") == "no_root_squash,clients_1");
    CHECK(flags("rw,root_squash") == "clients_1");
    CHECK(flags("no_root_squash,root_squash") == "clients_1");        // last wins
    CHECK(flags("no_root_squash,all_squash") == "clients_1");         // all_squash squashes root
    CHECK(flags("all_squash,no_all_squash,no_root_squash") == "no_root_squash,clients_1");
    CHECK(flags("all_squash") == "clients_1");
    // A line default is overridden by the spec's own option, in either direction.
    const auto d = lin("/srv/d -no_root_squash host(root_squash)\n");
    REQUIRE(d.shares.size() == 1);
    CHECK(flags_of(d.shares[0]) == "clients_1");
    const auto e = lin("/srv/e -no_root_squash host\n");
    REQUIRE(e.shares.size() == 1);
    CHECK(flags_of(e.shares[0]) == "no_root_squash,clients_1");
}

TEST_CASE("shares exports: only a double quote quotes and only octal escapes decode (xgettok)",
          "[shares]") {
    // RECONSTRUCTION from nfs-utils support/nfs/xio.c: `"` toggles quoting, `\NNN` is the only
    // escape, any other backslash is literal; exports(5) documents no single-quote form.
    CHECK(lin("'/srv/x' *(rw)\n").shares.empty());
    const auto p = lin("/srv/my\\040dir host\n/srv/a\\ b host\n\"/srv/q\\\"x\" host\n");
    REQUIRE(p.shares.size() == 3);
    CHECK(p.shares[0].path == "/srv/my dir");
    CHECK(p.shares[1].path == "/srv/a\\"); // `\ ` is no escape: the blank ends the token
    CHECK(p.shares[2].path == "/srv/q\\");  // `\"` closes the quote: the backslash stays literal
    // An octal escape that ends the line exactly (the `i + 3 < size` boundary).
    const auto e = lin("/srv/x\\040\n");
    REQUIRE(e.shares.size() == 1);
    CHECK(e.shares[0].path == "/srv/x ");
}

TEST_CASE("shares exports: an unterminated quote skips the line, never leaks clients into the path",
          "[shares]") {
    // nfsd's xgettok runs an open quote past the newline, so it never exports such a line.
    const auto p = lin("\"/srv/a 10.0.0.5(rw) 192.168.1.7(ro)\n/srv/ok host(ro)\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].path == "/srv/ok");
    // A later token left open skips the whole line too, not just that token.
    const auto q = lin("/srv/b host(rw) \"oops\n/srv/ok2 host\n");
    REQUIRE(q.shares.size() == 1);
    CHECK(q.shares[0].path == "/srv/ok2");
}

TEST_CASE("shares exports: a quoted non-absolute path is skipped like an unquoted one", "[shares]") {
    const auto p = lin("\"foo\" *(rw)\n\"/ok path\" host\n");
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].path == "/ok path");
}

TEST_CASE("shares exports: SEEDED INPUT reproduces the captured Linux sample rows", "[shares]") {
    auto b = fresh_budget();
    ExportsParse e;
    parse_exports(kSeededExports, "exports", b, e);
    ExportsParse d;
    parse_exports(kSeededExportsD, "exports_d", b, d);
    const auto c = smb(kSeededSmb);
    REQUIRE(e.shares.size() == 2);
    REQUIRE(d.shares.size() == 1);
    REQUIRE(c.shares.size() == 2);
    // docs/samples/linux.txt, byte for byte (the five `share` rows).
    CHECK(share_row(e.shares[0]) == "share|nfs|-|/srv/nfs/public|ro|true|clients_1|exports");
    CHECK(share_row(e.shares[1]) ==
          "share|nfs|-|/srv/nfs/projects|mixed|false|no_root_squash,clients_2|exports");
    CHECK(share_row(d.shares[0]) == "share|nfs|-|/srv/nfs/archive|ro|true|clients_1|exports_d");
    CHECK(share_row(c.shares[0]) == "share|smb|public|/srv/samba/public|ro|true|-|smb_conf");
    CHECK(share_row(c.shares[1]) == "share|smb|projects|/srv/samba/projects|rw|false|hidden|smb_conf");
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

TEST_CASE("shares smb.conf: a copy target Samba has not loaded at the directive is unresolved",
          "[shares]") {
    // RECONSTRUCTION: handle_copy resolves the target at parse time among already-loaded
    // services and snapshots it, so a forward reference or a later re-opening diverges from the
    // final merged file this parser reads. Flagged, never modelled; the share is still emitted.
    const auto fwd = smb("[x]\ncopy = base\n[base]\npath=/b\n");
    CHECK(fwd.copy_unresolved);
    CHECK(fwd.shares.size() == 2);

    const auto reopened = smb("[tpl]\npath=/early\n[x]\ncopy = tpl\n[tpl]\npath=/late\n");
    CHECK(reopened.copy_unresolved);
    CHECK(by_name(reopened, "x").path == "/late"); // still emitted from the merged view
    CHECK(by_name(reopened, "tpl").path == "/late");

    // All seven projected keys local: the lazy lookup never reaches `copy`, the eager pass does.
    const auto shadowed = smb("[x]\ncopy = missing\npath=/x\nread only = no\nwrite list = a\n"
                              "read list = b\nguest ok = no\nbrowseable = yes\navailable = yes\n");
    CHECK(shadowed.copy_unresolved);
    CHECK(by_name(shadowed, "x").path == "/x");

    // A target wholly before the copier and never re-opened after it stays resolved, through a
    // chain and through a case-variant spelling of the directive.
    CHECK_FALSE(smb("[tpl]\npath=/t\n[x]\ncopy = TPL\n[y]\ncopy = x\n").copy_unresolved);
    CHECK_FALSE(smb("[tpl]\npath=/t\n[tpl]\nguest ok = yes\n[x]\ncopy = tpl\n").copy_unresolved);
    CHECK(smb("[x]\ncopy = x\npath=/x\n").copy_unresolved);

    // Every copy line counts, not only the last: Samba refuses the file at the first bad one.
    CHECK(smb("[b]\n[a]\ncopy = C\ncopy = b\n").copy_unresolved);
    // `global` is no service to copy from, even with no [global] header after it.
    CHECK(smb("[a]\ncopy = global\n").copy_unresolved);
    // All seven keys local: only the eager pass can see the bad directive.
    const std::string local = "path=/a\nread only = no\nwrite list = x\nread list = y\n"
                              "guest ok = no\nbrowseable = yes\navailable = yes\n";
    CHECK(smb("[a]\ncopy = global\n" + local).copy_unresolved);
    CHECK(smb("[a]\ncopy = a\n" + local).copy_unresolved);
    // Keys after a malformed header are ignored, as parse_ini does, so its copy is not recorded.
    CHECK_FALSE(smb("[a]\npath=/a\n[broken\ncopy = nowhere\n").copy_unresolved);
}

TEST_CASE("shares smb.conf: the copy target length limit is 255 bytes exactly", "[shares]") {
    const std::string n255(255, 'x');
    const std::string n256(256, 'x');
    const auto ok = smb("[" + n255 + "]\nguest ok = yes\npath=/t\n[a]\ncopy = " + n255 + "\n");
    CHECK_FALSE(ok.copy_unresolved);
    CHECK(by_name(ok, "a").anonymous == true); // inherited through the 255-byte target
    // 256: both the eager pass and the lookup refuse it without lower-casing, so nothing inherits.
    const auto bad = smb("[" + n256 + "]\nguest ok = yes\npath=/t\n[a]\ncopy = " + n256 + "\n");
    CHECK(bad.copy_unresolved);
    CHECK(by_name(bad, "a").anonymous == false);
}

TEST_CASE("shares smb.conf: Samba's built-in read only = yes applies when nothing sets it",
          "[shares]") {
    const auto c = smb("[a]\npath=/a\n");
    CHECK(by_name(c, "a").access == Access::ro);
    const auto g = smb("[global]\nworkgroup = W\n[a]\npath=/a\n");
    CHECK(by_name(g, "a").access == Access::ro);
}

TEST_CASE("shares smb.conf: a read or write list only matters when it contradicts the default",
          "[shares]") {
    const auto c = smb("[ro_plain]\npath=/a\n"
                       "[ro_wl]\npath=/b\nwrite list = alice, @staff\n"
                       "[ro_rl]\npath=/c\nread list = bob\n"
                       "[rw_plain]\npath=/d\nread only = no\n"
                       "[rw_wl]\npath=/e\nread only = no\nwrite list = alice\n"
                       "[rw_rl]\npath=/f\nread only = no\nread list = bob\n"
                       "[ro_empty]\npath=/g\nwrite list =\n"
                       "[rw_empty]\npath=/h\nread only = no\nread list =\n");
    CHECK(by_name(c, "ro_plain").access == Access::ro);
    CHECK(by_name(c, "ro_wl").access == Access::mixed);   // ro, but alice can write
    CHECK(by_name(c, "ro_rl").access == Access::ro);      // a read list narrows nothing here
    CHECK(by_name(c, "rw_plain").access == Access::rw);
    CHECK(by_name(c, "rw_wl").access == Access::rw);      // a write list narrows nothing here
    CHECK(by_name(c, "rw_rl").access == Access::mixed);   // rw, but bob is read-only
    CHECK(by_name(c, "ro_empty").access == Access::ro);
    CHECK(by_name(c, "rw_empty").access == Access::rw);
    // Names are never emitted.
    for (const auto& s : c.shares)
        CHECK(share_row(s).find("alice") == std::string::npos);
}

TEST_CASE("shares smb.conf: a list is inherited through copy = and [global]", "[shares]") {
    const auto c = smb("[global]\nwrite list = root\n"
                       "[base]\npath=/srv/base\nread only = no\nread list = bob\n"
                       "[viacopy]\ncopy = base\n"
                       "[viaglobal]\npath=/srv/g\n"
                       "[override]\npath=/srv/o\nwrite list =\n");
    CHECK(by_name(c, "viacopy").access == Access::mixed);   // rw + inherited read list
    CHECK(by_name(c, "viaglobal").access == Access::mixed); // ro + inherited write list
    CHECK(by_name(c, "override").access == Access::ro);     // an empty local list clears it
}

TEST_CASE("shares smb.conf: lines before the first header are [global]", "[shares]") {
    const auto c = smb("guest ok = yes\nconfig backend = registry\nusershare max shares = 0\n"
                       "[a]\npath=/a\n");
    CHECK(by_name(c, "a").anonymous == true); // inherited from the headerless preamble
    CHECK(c.registry_backend);
    CHECK(c.usershares_off);
    CHECK_FALSE(c.usershares_configured);
    CHECK(smb("include = /etc/samba/x.conf\n").include_present);
    CHECK(smb("[global]\nconfig file = /etc/samba/%m.conf\n").include_present);
    CHECK_FALSE(smb("[a]\nconfig file = /x\n").include_present); // only [global] redirects
}

TEST_CASE("shares smb.conf: an empty section name is not a share", "[shares]") {
    CHECK(smb("[]\npath=/x\n[ ]\npath=/y\n").shares.empty());
    const auto c = smb("[]\npath=/x\n[a]\npath=/a\n");
    REQUIRE(c.shares.size() == 1);
    CHECK(c.shares[0].name == "a");
}

TEST_CASE("shares smb.conf: an over-long copy target is unresolved without a lookup", "[shares]") {
    const auto c = smb("[a]\npath=/a\ncopy = " + std::string(300, 'x') + "\n[b]\ncopy = a\n");
    CHECK(c.copy_unresolved);
    CHECK(by_name(c, "a").path == "/a");
    CHECK(by_name(c, "b").path == "/a");
}

TEST_CASE("shares smb.conf: a hostile section name still yields a well-formed row", "[shares]") {
    const auto c = smb("[a\xC0\xAF|b]\npath=/x\n");
    REQUIRE(c.shares.size() == 1);
    const std::string row = share_row(c.shares[0]);
    CHECK(unescaped_pipes(row) == 7); // 8 fields: the name's pipe is escaped
    CHECK(yuzu::shared::count_invalid_wire_bytes(row) == 0);
    CHECK(row.find('\0') == std::string::npos);
}

TEST_CASE("shares smb.conf: registry backend, include and usershares are detected", "[shares]") {
    CHECK(smb("[global]\nconfig backend = registry\n").registry_backend);
    CHECK(smb("[global]\nregistry shares = yes\n").registry_backend);
    CHECK_FALSE(smb("[global]\nregistry shares = no\n").registry_backend);
    CHECK(smb("[global]\ninclude = /etc/samba/shares.conf\n").include_present);
    CHECK(smb("[global]\nusershare max shares = 100\n").usershares_configured);
    CHECK_FALSE(smb("[global]\nusershare max shares = 100\n").usershares_off);
    const auto off = smb("[global]\nusershare max shares = 0\n");
    CHECK_FALSE(off.usershares_configured);
    CHECK(off.usershares_off); // an explicit disable
    CHECK(smb("[global]\nusershare max shares = 000\n").usershares_off);
    CHECK_FALSE(smb("[global]\nusershare max shares = many\n").usershares_off); // not a number
    CHECK_FALSE(smb("[a]\npath=/a\n").usershares_off); // unset is not off
    CHECK_FALSE(smb("[global]\nusershare max shares =\n").usershares_off); // empty is not zero
    const auto p = smb("[global]\nusershare path = /var/lib/samba/us\n");
    CHECK(p.usershares_configured);
    // An explicit all-zero max wins over a set path: usershares are definitively off.
    const auto both = smb("[global]\nusershare max shares = 0\nusershare path = /srv/us\n");
    CHECK(both.usershares_off);
    CHECK_FALSE(both.usershares_configured);
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
    bare.source = "smb_conf";
    CHECK(share_row(bare) == "share|smb|-|-|-|-|-|smb_conf");
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

// ---------------------------------------------------------------------------
// BSD / macOS exports(5): Apple's mountd grammar
// ---------------------------------------------------------------------------

namespace {

ExportsParse bsd(std::string_view text, std::size_t rows = kMaxShareRows) {
    auto b = yuzu::shared::RowByteBudget{rows, kMaxShareBytes};
    ExportsParse p;
    parse_bsd_exports(text, "exports", b, p);
    return p;
}

/// `path access anonymous flags` for one share, the facts the cases pin.
std::string sig(const Share& s) {
    std::string out = s.path + ' ' + std::string{access_token(s.access)} + ' ' +
                      (s.anonymous ? (*s.anonymous ? "anon" : "named") : "?") + ' ' + flags_of(s);
    return out;
}

std::vector<std::string> sigs(const ExportsParse& p) {
    std::vector<std::string> v;
    for (const auto& s : p.shares)
        v.push_back(sig(s));
    return v;
}

using Sigs = std::vector<std::string>;

} // namespace

TEST_CASE("shares bsd exports: the man page shapes", "[shares]") {
    CHECK(sigs(bsd("/usr /usr/local -maproot=0:10 friends")) ==
          Sigs{"/usr rw named no_root_squash,clients_1", "/usr/local rw named no_root_squash,clients_1"});
    CHECK(sigs(bsd("/usr -maproot=daemon grumpy.cis.uoguelph.ca 131.104.48.16")) ==
          Sigs{"/usr rw named clients_2"});
    CHECK(sigs(bsd("/usr -ro -mapall=nobody")) == Sigs{"/usr ro anon clients_0"});
    CHECK(sigs(bsd("/u -maproot=bin: -network 131.104.48 -mask 255.255.255.0")) ==
          Sigs{"/u rw named clients_1"});
    CHECK(sigs(bsd("/u1 -alldirs -network 2001:DB8:: -mask ffff:ffff::")) ==
          Sigs{"/u1 rw named clients_1"});
    CHECK(sigs(bsd("/u2 -maproot=root friends")) == Sigs{"/u2 rw named no_root_squash,clients_1"});
    CHECK(sigs(bsd("/u2 -alldirs -network cis-net -mask cis-mask")) == Sigs{"/u2 rw named clients_1"});
}

TEST_CASE("shares bsd exports: comma lists and next-field option values", "[shares]") {
    CHECK(sigs(bsd("/srv -ro,maproot=root")) == Sigs{"/srv ro anon no_root_squash,clients_0"});
    for (const char* line : {"/srv -maproot root", "/srv -mapall root", "/srv -r root", "/srv -root=0"})
        CHECK(sigs(bsd(line)) == Sigs{"/srv rw anon no_root_squash,clients_0"});
    CHECK(sigs(bsd("/srv -network 10.1.0.0 -mask 255.255.0.0")) == Sigs{"/srv rw named clients_1"});
    CHECK(sigs(bsd("/srv -n=10.1.0.0 -m=255.255.0.0")) == Sigs{"/srv rw named clients_1"});
    // `friends` is offered to the last item (alldirs) as a value but alldirs takes none, so it
    // stays a host.
    CHECK(sigs(bsd("/srv -ro,alldirs friends")) == Sigs{"/srv ro named clients_1"});
    for (const char* line : {"/srv -maproot=nobody", "/srv -mapall=nobody:group", "/srv -maproot=bin:",
                             "/srv -maproot nobody"})
        CHECK(sigs(bsd(line)) == Sigs{"/srv rw anon clients_0"});
    // An unrecognised name ends that option field only.
    CHECK(sigs(bsd("/srv -bogus,ro")) == Sigs{"/srv rw anon clients_0"});
    CHECK(sigs(bsd("/srv -bogus -ro")) == Sigs{"/srv ro anon clients_0"});
    // fspath takes no next-field value, so the path after it is a path after an option.
    CHECK(sigs(bsd("/srv -fspath /x")).empty());
    CHECK(sigs(bsd("/srv -fspath=/x")) == Sigs{"/srv rw anon clients_0"});
}

TEST_CASE("shares bsd exports: no_root_squash follows the last credential Apple resolves", "[shares]") {
    const auto root = [](const char* line) {
        return flags_of(bsd(line).shares.at(0)).find("no_root_squash") != std::string::npos;
    };
    // A digit- or '-'-led user is getpwuid(atoi(user)): every spelling atoi reads as 0 is root.
    for (const char* line :
         {"/srv -maproot=0", "/srv -maproot=00", "/srv -maproot=00000", "/srv -maproot=0x0",
          "/srv -maproot=0root", "/srv -maproot=-0", "/srv -maproot=-", "/srv -mapall=00:5",
          "/srv -r 0000", "/srv -root=root:1:2"})
        CHECK(root(line));
    for (const char* line : {"/srv -maproot=1", "/srv -maproot=01", "/srv -maproot=-2:-2", "/srv -maproot=10",
                             "/srv -maproot=roo", "/srv -maproot=Root", "/srv -maproot=daemon",
                             "/srv -maproot=1x0"})
        CHECK_FALSE(root(line));
    // atoi is (int)strtol: the low 32 bits survive (a wrap to 0 is root) and strtol saturates
    // beyond +-2^63, LONG_MAX to -1 (not root) and LONG_MIN to 0 (root).
    CHECK(root("/srv -maproot=4294967296"));
    CHECK_FALSE(root("/srv -maproot=4294967297"));
    CHECK(root("/srv -maproot=-4294967296"));
    CHECK_FALSE(root("/srv -maproot=9223372036854775807"));
    CHECK_FALSE(root("/srv -maproot=9223372036854775808"));
    CHECK_FALSE(root("/srv -maproot=99999999999999999999999"));
    CHECK(root("/srv -maproot=-9223372036854775808"));
    CHECK(root("/srv -maproot=-99999999999999999999999"));
    // parsecred resets the credential on every call: the last mapping wins, in both directions.
    CHECK_FALSE(root("/srv -maproot=0 -maproot=-2:-2"));
    CHECK_FALSE(root("/srv -maproot=root -r 5"));
    CHECK(root("/srv -maproot=-2:-2 -maproot=root"));
    CHECK(root("/srv -maproot=nobody -root=0"));
    CHECK_FALSE(root("/srv -maproot=0,r=daemon"));
}

TEST_CASE("shares bsd exports: entries are joined as get_export_entry joins them", "[shares]") {
    // A stripped backslash appends the next physical line with NO separator.
    CHECK(sigs(bsd("/a \\\n/b")) == Sigs{"/a/b rw anon clients_0"});
    CHECK(sigs(bsd("/a \\\n\t/b")) == Sigs{"/a rw anon clients_0", "/b rw anon clients_0"});
    CHECK(sigs(bsd("/a -ro \\\n friends")) == Sigs{"/a ro named clients_1"});
    // Trailing spaces and tabs are stripped.
    CHECK(sigs(bsd("/srv \t \n")) == Sigs{"/srv rw anon clients_0"});
    // A CR is NOT in get_export_entry's strip set (space, tab, newline, backslash): on a CRLF
    // file Apple keeps it in the last field, so the path is `/srv\r` (the wire folds it to a
    // space), a `-ro\r` option is unrecognised and the row stays rw, and a backslash before
    // the CR is no continuation.
    CHECK(sigs(bsd("/srv\r\n/b\r\n")) == Sigs{"/srv\r rw anon clients_0", "/b\r rw anon clients_0"});
    CHECK(share_row(bsd("/srv\r\n").shares.at(0)) == "share|nfs|-|/srv |rw|true|clients_0|exports");
    CHECK(sigs(bsd("/srv -ro\r\n")) == Sigs{"/srv rw anon clients_0"});
    CHECK(sigs(bsd("/a \\\r\n/b")) == Sigs{"/a rw named clients_1", "/b rw anon clients_0"});
    // A comment is an entry whose FIRST field starts with `#`; its backslash continues it.
    CHECK(sigs(bsd("# /srv\n/b")) == Sigs{"/b rw anon clients_0"});
    CHECK(sigs(bsd("#/srv\n  # /c\n")).empty());
    CHECK(sigs(bsd("# note \\\n/swallowed\n/b")) == Sigs{"/b rw anon clients_0"});
    // A `#` anywhere else is an ordinary field: here a host.
    CHECK(sigs(bsd("/srv #friends")) == Sigs{"/srv rw named clients_1"});
    // A continuation still open at end of file loses its entry (fgetln returns NULL).
    CHECK(sigs(bsd("/a\n/b \\")) == Sigs{"/a rw anon clients_0"});
    // Blank lines and a lone backslash are skipped.
    CHECK(sigs(bsd("\n\n  \n\\\n/a\n")) == Sigs{"/a rw anon clients_0"});
}

TEST_CASE("shares bsd exports: offline quoting escapes and trailing slashes", "[shares]") {
    CHECK(sigs(bsd("/srv -o")) == Sigs{"/srv ro anon clients_0"});
    CHECK(sigs(bsd("/srv -offline")) == Sigs{"/srv rw anon unavailable,clients_0"});
    CHECK(sigs(bsd("\"/my share\" -ro")) == Sigs{"/my share ro anon clients_0"});
    CHECK(sigs(bsd("'/a b'")) == Sigs{"/a b rw anon clients_0"});
    CHECK(sigs(bsd("/a\\ b friends")) == Sigs{"/a b rw named clients_1"});
    CHECK(sigs(bsd("\"/a\\\"b\"")) == Sigs{"/a\"b rw anon clients_0"});
    // An unterminated quote runs to end of line: one path, as Apple reads it.
    CHECK(sigs(bsd("\"/srv/x -ro\n/b")) == Sigs{"/srv/x -ro rw anon clients_0", "/b rw anon clients_0"});
    CHECK(sigs(bsd("/srv/\n///\n/")) == Sigs{"/srv rw anon clients_0", "/ rw anon clients_0",
                                             "/ rw anon clients_0"});
    // Options written after the host list are honoured.
    CHECK(sigs(bsd("/srv friends -ro")) == Sigs{"/srv ro named clients_1"});
}

TEST_CASE("shares bsd exports: one row per path and per line", "[shares]") {
    CHECK(sigs(bsd("/a /b /c -ro")) == Sigs{"/a ro anon clients_0", "/b ro anon clients_0",
                                             "/c ro anon clients_0"});
    CHECK(sigs(bsd("/a\n/a -ro")) == Sigs{"/a rw anon clients_0", "/a ro anon clients_0"});
    // The same path twice on ONE line is a duplicate directory Apple drops.
    CHECK(sigs(bsd("/a /a/ /b")) == Sigs{"/a rw anon clients_0", "/b rw anon clients_0"});
}

TEST_CASE("shares bsd exports: lines Apple rejects yield no row and no token", "[shares]") {
    for (const char* line :
         {"-ro /srv", "friends /srv", "friends", "-ro", "/a -ro /b", "/a friends /b",
          "/srv -network 10.0.0.0 -network 10.1.0.0", "/srv -mask 255.0.0.0 -mask 255.255.0.0",
          "/srv -network 10.0.0.0 friends", "/srv friends -network 10.0.0.0",
          "/srv -network 0.0.0.0/0", "/srv -network ::/0", "/srv -network=",
          "/srv -network 10.0.0.0 -mask ffff::", "/srv -network 2001:db8:: -mask 255.0.0.0",
          "/srv -mask ffff:: -network 10.0.0.0",
          // check_options: -mask needs a -network (hosts or not), and -maproot (-root, -r) and
          // -mapall are mutually exclusive in either order.
          "/srv -mask 255.255.255.0", "/srv -mask 255.0.0.0 friends", "/srv -m ffff::",
          "/srv -maproot=0 -mapall=-2:-2", "/srv -mapall=nobody -maproot=root",
          "/srv -root=0 -mapall=nobody", "/srv -mapall root -r root",
          // inet_pton refuses these dotted tails (short, out of range, too long, not last, no room).
          "/srv -network ::1.2.3", "/srv -network ::256.0.0.0", "/srv -network ::1.2.3.4.5",
          "/srv -network 1.2.3.4::", "/srv -network 1:2:3:4:5:6:7:1.2.3.4",
          // inet_network refuses a part over 0xff (0x0a000000, 0x100, 0400) and an 8 or 9 in octal.
          "/srv -network 0x0a000000", "/srv -network 0x100", "/srv -network 0400", "/srv -network 09",
          "/srv -network 0xg", "/srv -network 1.2.3.4.5",
          // a CR from a CRLF file ends an IPv4 value harmlessly but spoils an IPv6 one.
          "/srv -network 2001:db8::\r"}) {
        INFO(line);
        const auto p = bsd(line);
        CHECK(p.shares.empty());
        CHECK_FALSE(p.truncated);
        CHECK_FALSE(p.field_oversized);
    }
    // The line after a rejected one still parses.
    CHECK(sigs(bsd("/a -ro /b\n/c")) == Sigs{"/c rw anon clients_0"});
}

TEST_CASE("shares bsd exports: hostile bytes stay inside one escaped row", "[shares]") {
    const auto p = bsd(std::string("/p|\xff\xC0\xAF") + "q\\\\ friends\n/ok");
    REQUIRE(p.shares.size() == 2);
    const auto row = share_row(p.shares[0]);
    CHECK(unescaped_pipes(row) == 7);
    CHECK(yuzu::shared::count_invalid_wire_bytes(row) == 0);
    CHECK(share_row(p.shares[1]) == "share|nfs|-|/ok|rw|true|clients_0|exports");
}

TEST_CASE("shares bsd exports: world classification is Apple's", "[shares]") {
    const auto anon = [](const char* line) { return bsd(line).shares.at(0).anonymous.value(); };
    CHECK(anon("/srv"));
    // IPv6: an absent or all-zero mask is the world (the kernel's default radix entry).
    CHECK(anon("/srv -network ::"));
    CHECK(anon("/srv -network 2001:DB8::"));
    CHECK(anon("/srv -network 2001:DB8:: -mask ::"));
    CHECK(anon("/srv -network 2001:DB8:: -mask 0:0:0:0:0:0:0:0"));
    CHECK_FALSE(anon("/srv -network 2001:DB8:: -mask ffff:ffff::"));
    // IPv4: a zero or absent mask becomes the classful mask, never the world.
    CHECK_FALSE(anon("/srv -network 0.0.0.0"));
    CHECK_FALSE(anon("/srv -network 0.0.0.0 -mask 0.0.0.0"));
    CHECK_FALSE(anon("/srv -network 10.0.0.0 -mask 0.0.0.0"));
    CHECK_FALSE(anon("/srv -network 131.104.48 -mask 255.255.255.0"));
    CHECK_FALSE(anon("/srv -network cis-net"));
    CHECK_FALSE(anon("/srv friends"));
    // inet_pton's dotted-tail spellings decode like their hex twins: an all-zero mask is the
    // world however it is written, a v4-mapped network with a real mask is not.
    CHECK(anon("/srv -network 2001:db8:: -mask ::0.0.0.0"));
    CHECK(anon("/srv -network ::0.0.0.0"));
    CHECK(anon("/srv -network 2001:db8:: -mask 0:0:0:0:0:0:0.0.0.0"));
    CHECK_FALSE(anon("/srv -network ::ffff:10.0.0.0 -mask ::ffff:255.0.0.0"));
    CHECK_FALSE(anon("/srv -network 2001:db8:: -mask ::0.0.0.1"));
    CHECK(sigs(bsd("/srv -network ::ffff:10.0.0.0 -mask ::ffff:255.0.0.0")) ==
          Sigs{"/srv rw named clients_1"});
    // inet_network's hex and octal spellings are IPv4 networks: one client, never the world.
    CHECK(sigs(bsd("/srv -network 0x0a")) == Sigs{"/srv rw named clients_1"});
    CHECK(sigs(bsd("/srv -network 0X10.0x0.0.0 -mask 0xff.0.0.0")) == Sigs{"/srv rw named clients_1"});
    CHECK(sigs(bsd("/srv -network 010.0377 -mask 0")) == Sigs{"/srv rw named clients_1"});
    CHECK(sigs(bsd("/srv -network 4.XDe")) == Sigs{"/srv rw named clients_1"});
    CHECK(sigs(bsd("/srv -network 0x")) == Sigs{"/srv rw named clients_1"});
    // A trailing CR (a CRLF file) is whitespace to inet_network, so an IPv4 value still parses.
    CHECK(sigs(bsd("/srv -network 10.0.0.0\r\n")) == Sigs{"/srv rw named clients_1"});
    CHECK(sigs(bsd("/srv -network 10.0.0.0 -mask 255.0.0.0\r\n")) == Sigs{"/srv rw named clients_1"});
    CHECK(bsd("/srv -network 2001:DB8::").shares[0].flags.back() == "clients_1");
    CHECK(bsd("/srv").shares[0].flags.back() == "clients_0");
}

TEST_CASE("shares bsd exports: IPv6 literals decode the way inet_pton decodes them", "[shares]") {
    using Bytes = std::array<unsigned char, 16>;
    const auto dec = [](std::string_view s) { return detail::parse_v6(s); };
    CHECK(dec("::") == Bytes{});
    CHECK(dec("0:0:0:0:0:0:0:0") == Bytes{});
    CHECK(dec("::0.0.0.0") == Bytes{});
    CHECK(dec("1::") == Bytes{0, 1});
    CHECK(dec("::1") == Bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    CHECK(dec("2001:DB8::") == Bytes{0x20, 0x01, 0x0d, 0xb8});
    CHECK(dec("1:2:3:4:5:6:7::") == Bytes{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7});
    // A dotted-quad tail is the last 32 bits, with or without a `::`.
    CHECK(dec("::ffff:10.0.0.0") == Bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10});
    CHECK(dec("::1.2.3.4") == Bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4});
    CHECK(dec("1:2:3:4:5:6:1.2.3.4") == Bytes{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4});
    CHECK(dec("1::2.3.4.5") == Bytes{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 4, 5});
    // This libc (macOS 26.6.2) takes leading zeros in a group (the value must fit 16 bits) and
    // in an octet.
    CHECK(dec("00000::") == Bytes{});
    CHECK(dec("::0002AD") == Bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0xad});
    CHECK(dec("::01.2.3.4") == Bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4});
    CHECK(dec("::0.0.0.00") == Bytes{});
    for (const char* bad :
         {"", ":", ":1", "1:", ":::", "1:::2", "1::2::3", "12345::", "10000::", "g::", "1.2.3.4",
          "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "1:2:3:4:5:6::1.2.3.4", "::1.2.3",
          "::1.2.3.4.5", "::256.0.0.0", "::1.2.3.4:", "::1.2.3.4::", "::1.2.3.4 ", "::a.2.3.4", "::1..2.3",
          "::1.2.3.4/0", "ffff::/0", "1:2:3:4:5:6:7:1.2.3.4", "2001:db8::\r"})
        CHECK_FALSE(dec(bad).has_value());
}

TEST_CASE("shares bsd exports: a value-taking option with no value is ignored", "[shares]") {
    CHECK(sigs(bsd("/srv -network\n/b")) == Sigs{"/srv rw anon clients_0", "/b rw anon clients_0"});
    CHECK(sigs(bsd("/srv -network -ro")) == Sigs{"/srv ro anon clients_0"});
    CHECK(sigs(bsd("/srv -mask")) == Sigs{"/srv rw anon clients_0"});
}

TEST_CASE("shares bsd exports: the budget is charged before a Share is built", "[shares]") {
    const auto p = bsd("/a /b /c", 2);
    CHECK(p.shares.size() == 2);
    CHECK(p.truncated);
    // The cut stops the file, not just the line.
    CHECK(bsd("/a\n/b\n/c", 1).shares.size() == 1);
    const auto big = bsd("/" + std::string(5000, 'x'));
    REQUIRE(big.shares.size() == 1);
    CHECK(big.shares[0].path.size() == kMaxFieldBytes);
    CHECK(big.field_oversized);
}

// ---------------------------------------------------------------------------
// macOS `sharing -l -f json`
// ---------------------------------------------------------------------------

namespace {

// REDACTED CAPTURE: `/usr/sbin/sharing -l -f json`, macOS 26.6.2 arm64 (braga), 2026-10-29,
// verbatim except the account and share name (jsmith) and the shape's whitespace.
constexpr const char* kSharingCapture = R"JSON({
  "J Smith’s Public Folder" : {
    "path" : "\/Users\/jsmith\/Public",
    "smb_guest_access" : 1,
    "smb_name" : "J Smith’s Public Folder",
    "smb_read_only" : 0,
    "smb_sealed" : 0,
    "smb_shared" : 1
  }
}
)JSON";

SharingParse sharing(std::string_view text, std::size_t rows = kMaxShareRows) {
    auto b = yuzu::shared::RowByteBudget{rows, kMaxShareBytes};
    return parse_sharing_json(text, b);
}

} // namespace

TEST_CASE("shares sharing json: the redacted braga capture", "[shares]") {
    const auto p = sharing(kSharingCapture);
    CHECK(p.recognised);
    CHECK(p.malformed_records == 0);
    REQUIRE(p.shares.size() == 1);
    CHECK(share_row(p.shares[0]) == "share|smb|J Smith’s Public Folder|/Users/jsmith/Public|rw|true|-|sharing");
}

TEST_CASE("shares sharing json: flags name fallback and typing", "[shares]") {
    // smb_name absent: the record key names the share.
    auto p = sharing(R"({"Key":{"path":"/p"}})");
    REQUIRE(p.shares.size() == 1);
    CHECK(share_row(p.shares[0]) == "share|smb|Key|/p|-|-|-|sharing");
    // ro, guest off, sharing off, sealed.
    p = sharing(R"({"k":{"path":"/p","smb_read_only":1,"smb_guest_access":0,"smb_shared":0,"smb_sealed":1}})");
    REQUIRE(p.shares.size() == 1);
    CHECK(share_row(p.shares[0]) == "share|smb|k|/p|ro|false|unavailable,sealed|sharing");
    // String-typed flags are unknown: ignored.
    p = sharing(R"({"k":{"path":"/p","smb_read_only":"1","smb_guest_access":"1","smb_shared":"0","smb_sealed":"1"}})");
    REQUIRE(p.shares.size() == 1);
    CHECK(share_row(p.shares[0]) == "share|smb|k|/p|-|-|-|sharing");
}

TEST_CASE("shares sharing json: ACL permission and remark members are never read", "[shares]") {
    const auto plain = sharing(R"({"k":{"path":"/p","smb_name":"n","smb_guest_access":1}})");
    const auto extra = sharing(R"({"k":{"path":"/p","smb_name":"n","smb_guest_access":1,
        "acl":"ACLMARK","permissions":"PERMMARK","remark":"REMARKMARK","afp_shared":1}})");
    REQUIRE(plain.shares.size() == 1);
    REQUIRE(extra.shares.size() == 1);
    CHECK(extra.malformed_records == 0);
    const auto row = share_row(extra.shares[0]);
    CHECK(row == share_row(plain.shares[0]));
    for (const char* mark : {"ACLMARK", "PERMMARK", "REMARKMARK"})
        CHECK(row.find(mark) == std::string::npos);
}

TEST_CASE("shares sharing json: what is recognised and what is not", "[shares]") {
    for (const char* t : {"{}", "  {}\n", "No share point records.", "\n  No share point records.\n\n"}) {
        INFO(t);
        const auto p = sharing(t);
        CHECK(p.recognised);
        CHECK(p.shares.empty());
    }
    // Empty and whitespace-only output are NOT an empty success: no capture shows them.
    for (const char* t : {"", "  \n\t", "[]", "\"x\"", "{\"a\":", "No share point records. extra",
                          "garbage", "12"}) {
        INFO(t);
        CHECK_FALSE(sharing(t).recognised);
        CHECK(sharing(t).shares.empty());
    }
}

TEST_CASE("shares sharing json: a malformed member is counted and siblings are kept", "[shares]") {
    const auto p = sharing(R"({"a":1,"b":{"smb_name":"x"},"c":{"path":3},"d":{"path":"/ok"}})");
    CHECK(p.recognised);
    CHECK(p.malformed_records == 3);
    REQUIRE(p.shares.size() == 1);
    CHECK(p.shares[0].path == "/ok");
}

TEST_CASE("shares sharing json: a hostile name yields one well-formed row", "[shares]") {
    // pipe, newline, backslash and NUL (JSON escapes) in the name.
    const auto p = sharing(R"({"k":{"path":"/p","smb_name":"a|b\nc\\d\u0000e"}})");
    REQUIRE(p.shares.size() == 1);
    const auto row = share_row(p.shares[0]);
    CHECK(unescaped_pipes(row) == 7);
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find('\0') == std::string::npos);
    CHECK(yuzu::shared::count_invalid_wire_bytes(row) == 0);

    // Invalid UTF-8 never reaches a row: the JSON parser refuses the text, a named failure upstream.
    CHECK_FALSE(sharing(std::string(R"({"k":{"path":"/p","smb_name":"a)") + "\xff" + R"("}})").recognised);

    const auto big = sharing(R"({"k":{"path":"/p","smb_name":")" + std::string(5000, 'n') + R"("}})");
    REQUIRE(big.shares.size() == 1);
    CHECK(big.shares[0].name.size() == kMaxFieldBytes);
    CHECK(big.field_oversized);
}

TEST_CASE("shares sharing json: the budget is charged before a Share is built", "[shares]") {
    const auto p = sharing(R"({"a":{"path":"/1"},"b":{"path":"/2"},"c":{"path":"/3"}})", 2);
    CHECK(p.recognised);
    CHECK(p.shares.size() == 2);
    CHECK(p.truncated);
    CHECK(p.malformed_records == 0);
}
