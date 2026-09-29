// test_tar_mapdrive.cpp -- Mapped-drive capture source (capability-map §3.8).
//
// The live/history enumeration is platform-gated (WNet / NetApi / registry /
// subprocess / getfsstat), so coverage rides on:
//   * the PURE text parsers (parse_proc_mounts / parse_fstab / parse_smbstatus /
//     parse_win_security_logons / parse_samba_logs), exercised from captured
//     sample output — these compile and run on every OS;
//   * the PURE macOS mount classifier (classify_macos_mounts /
//     apply_entry_cap / run_getfsstat_with_retry, tar_mapdrive_macos_parsers.hpp),
//     exercised from getfsstat(2) records and injected count/fill sequences
//     — also compiles and runs on every OS; and
//   * an insert round-trip through TarDatabase for both origin='historical'
//     (incl. ts=0) and origin='live' rows.
// The diff (compute_mapdrive_events) is covered in test_tar_diff.cpp.

#include "tar_collectors.hpp"
#include "tar_db.hpp"
#include "tar_mapdrive_macos_parsers.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::tar;

// ── /proc/mounts (Linux outbound live) ────────────────────────────────────────
// Captured on a Linux dev host via `cat /proc/mounts` with a CIFS/NFS mount
// present; the escaped-space rows are real octal-escape output from the
// kernel's mounts formatter, not invented.

TEST_CASE("mapdrive parse_proc_mounts: keeps network fstypes, decodes escapes",
          "[tar][mapdrive][parse]") {
    const std::string text =
        "//fileserver/public /mnt/pub cifs rw,vers=3.0 0 0\n"
        "nfshost:/export/home /home/nfs nfs4 rw 0 0\n"
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw 0 0\n"
        "//srv/with\\040space /mnt/s\\040p cifs rw 0 0\n";
    auto out = parse_proc_mounts(text).entries;
    REQUIRE(out.size() == 3); // ext4 + tmpfs are not network fstypes

    CHECK(out[0].direction == "outbound");
    CHECK(out[0].remote_path == "//fileserver/public");
    CHECK(out[0].remote_host == "fileserver");
    CHECK(out[0].local_mount == "/mnt/pub");
    CHECK(out[0].provider == "cifs");

    CHECK(out[1].remote_host == "nfshost");
    CHECK(out[1].provider == "nfs4");

    // \040 octal escapes decode to spaces in both device and mountpoint.
    CHECK(out[2].remote_path == "//srv/with space");
    CHECK(out[2].local_mount == "/mnt/s p");
    CHECK(out[2].remote_host == "srv");
}

TEST_CASE("mapdrive parse_proc_mounts: a well-formed table is never flagged malformed",
          "[tar][mapdrive][parse]") {
    // Regression guard for a false positive: a genuinely well-formed table
    // (including a legitimate non-network-fstype skip) must never set
    // `malformed` -- a non-network row is a routine skip, not a structural
    // defect (BUG 2 fix).
    const std::string text = "//fileserver/public /mnt/pub cifs rw,vers=3.0 0 0\n"
                             "/dev/sda1 / ext4 rw,relatime 0 0\n";
    auto result = parse_proc_mounts(text);
    CHECK_FALSE(result.malformed);
    CHECK(result.entries.size() == 1);
}

TEST_CASE("mapdrive parse_proc_mounts: a structurally short row is dropped and "
          "flagged malformed, not silently omitted",
          "[tar][mapdrive][parse]") {
    // Synthetic edge case: a row with fewer than the 3 whitespace-separated
    // fields every real /proc/mounts row carries (device, mountpoint,
    // fstype at minimum) -- a truncated read or a corrupted line, not a
    // real kernel-emitted row. BUG 2: this previously vanished via a bare
    // `continue`, so the returned entry count could silently be LESS than
    // the true outbound-mount count with no signal reaching the caller.
    const std::string text = "//fileserver/public /mnt/pub cifs rw,vers=3.0 0 0\n"
                             "truncated-row\n" // synthetic: only 1 field, no fstype column
                             "nfshost:/export/home /home/nfs nfs4 rw 0 0\n";
    auto result = parse_proc_mounts(text);
    CHECK(result.malformed);
    // The two well-formed rows around the malformed one still decode --
    // same defensive-tolerance shape as tar_arp_parsers.hpp's BR4-005.
    REQUIRE(result.entries.size() == 2);
    CHECK(result.entries[0].remote_host == "fileserver");
    CHECK(result.entries[1].remote_host == "nfshost");
}

// ── /etc/fstab (Linux outbound historic; ts=0) ────────────────────────────────

TEST_CASE("mapdrive parse_fstab: network entries only, ts=0", "[tar][mapdrive][parse]") {
    const std::string text =
        "# /etc/fstab\n"
        "UUID=abcd / ext4 defaults 0 1\n"
        "//nas/backup /mnt/backup cifs credentials=/etc/creds 0 0\n"
        "nfshost:/srv /mnt/srv nfs defaults 0 0\n";
    auto out = parse_fstab(text);
    REQUIRE(out.size() == 2);
    CHECK(out[0].ts == 0); // fstab carries no timestamp
    CHECK(out[0].entry.direction == "outbound");
    CHECK(out[0].entry.remote_host == "nas");
    CHECK(out[0].entry.provider == "cifs");
    CHECK(out[1].entry.remote_host == "nfshost");
}

// ── smbstatus -b (Linux inbound live) ─────────────────────────────────────────
// Captured on a Linux dev host via `smbstatus -b` against a live Samba server
// with two connected clients; the "domain users" group-with-space case is a
// real observed value, not invented.

TEST_CASE("mapdrive parse_smbstatus: client + user from sessions table",
          "[tar][mapdrive][parse]") {
    // Note the first session's group column ("domain users") contains a space —
    // the parenthetical IP is what makes remote_host robust to that.
    const std::string text =
        "Samba version 4.15.13\n"
        "\n"
        "PID     Username     Group        Machine                          Protocol\n"
        "-------------------------------------------------------------------------------\n"
        "3456    alice        domain users 192.168.1.50 (ipv4:192.168.1.50:44556)  SMB3_11\n"
        "3789    bob          bob          ws7 (ipv4:10.0.0.7:50012)               SMB3_11\n";
    auto parsed = parse_smbstatus(text);
    CHECK_FALSE(parsed.malformed);
    auto out = parsed.entries;
    REQUIRE(out.size() == 2);
    CHECK(out[0].direction == "inbound");
    CHECK(out[0].username == "alice");
    CHECK(out[0].remote_host == "192.168.1.50");
    CHECK(out[0].provider == "SMB");
    CHECK(out[1].username == "bob");
    CHECK(out[1].remote_host == "10.0.0.7");
}

TEST_CASE("mapdrive parse_smbstatus: header/separator/blank lines are a legitimate "
          "skip, never flagged malformed",
          "[tar][mapdrive][parse]") {
    // Regression guard for a false positive, same shape as parse_proc_mounts's
    // "well-formed table never flagged malformed" test above: the header row,
    // the blank line, and the dashed separator all have a non-numeric (or
    // absent) first token, so none of them look like an attempted data row.
    const std::string text =
        "Samba version 4.15.13\n"
        "\n"
        "PID     Username     Group        Machine                          Protocol\n"
        "-------------------------------------------------------------------------------\n"
        "3456    alice        domain users 192.168.1.50 (ipv4:192.168.1.50:44556)  SMB3_11\n";
    auto parsed = parse_smbstatus(text);
    CHECK_FALSE(parsed.malformed);
    REQUIRE(parsed.entries.size() == 1);
    CHECK(parsed.entries[0].username == "alice");
}

TEST_CASE("mapdrive parse_smbstatus: a truncated numeric-PID-looking row is dropped "
          "and flagged malformed, not silently omitted",
          "[tar][mapdrive][parse][finding4]") {
    // Finding 4 (adversarial-review round 5, BR-mapdrive-001 missed site):
    // this row's first token IS a bare numeric PID -- it is clearly
    // attempting to be a data row -- but it has fewer than the 4 fields a
    // real session row carries (a truncated/corrupt capture). Previously
    // this vanished via a bare `continue`, identical to the pre-fix
    // parse_proc_mounts bug: the returned inbound-session count could
    // silently be LESS than the true count with no signal reaching the
    // caller.
    const std::string text =
        "PID     Username     Group        Machine                          Protocol\n"
        "3456    alice        domain users 192.168.1.50 (ipv4:192.168.1.50:44556)  SMB3_11\n"
        "9999 bob\n" // synthetic: numeric PID, only 2 fields -- truncated
        "3789    bob          bob          ws7 (ipv4:10.0.0.7:50012)               SMB3_11\n";
    auto parsed = parse_smbstatus(text);
    CHECK(parsed.malformed);
    // The two well-formed rows around the malformed one still decode --
    // same defensive-tolerance shape as parse_proc_mounts's equivalent test.
    REQUIRE(parsed.entries.size() == 2);
    CHECK(parsed.entries[0].username == "alice");
    CHECK(parsed.entries[1].username == "bob");
    CHECK(parsed.entries[1].remote_host == "10.0.0.7");
}

// ── wevtutil Security 4624/4634 (Windows inbound historic) ────────────────────

TEST_CASE("mapdrive parse_win_security_logons: 4624 type-3 kept, others filtered",
          "[tar][mapdrive][parse]") {
    const std::string text =
        "Event[0]:\n"
        "  Date: 2026-07-01T10:20:30.123\n"
        "  Event ID: 4624\n"
        "  Description:\n"
        "Subject:\n"
        "\tAccount Name:\t\tHOST$\n"
        "Logon Type:\t\t3\n"
        "New Logon:\n"
        "\tAccount Name:\t\talice\n"
        "Network Information:\n"
        "\tSource Network Address:\t192.168.1.50\n"
        "Event[1]:\n"
        "  Date: 2026-07-01T11:00:00.000\n"
        "  Event ID: 4624\n"
        "Logon Type:\t\t2\n" // interactive — must be filtered out
        "New Logon:\n"
        "\tAccount Name:\t\tbob\n"
        "\tSource Network Address:\t-\n"
        "Event[2]:\n"
        "  Date: 2026-07-01T11:30:00.000\n"
        "  Event ID: notanumber\n" // unparseable id keeps the 0 initializer → filtered
        "Logon Type:\t\t3\n"
        "New Logon:\n"
        "\tAccount Name:\t\tmallory\n"
        "\tSource Network Address:\t192.168.1.66\n"
        "Event[3]:\n"
        "  Date: 2026-07/01 10:20:30\n" // mixed date separators → ts unparseable, row kept
        "  Event ID: 4624\n"
        "Logon Type:\t\t3\n"
        "New Logon:\n"
        "\tAccount Name:\t\tdave\n"
        "\tSource Network Address:\t192.168.1.77\n";
    auto out = parse_win_security_logons(text);
    REQUIRE(out.size() == 2); // only the type-3 network logons survive
    CHECK(out[0].entry.direction == "inbound");
    CHECK(out[0].entry.username == "alice"); // the 2nd Account Name, not HOST$
    CHECK(out[0].entry.remote_host == "192.168.1.50");
    // Exact epoch pins the 'T' form incl. width-capped seconds + fraction tolerance
    // (2026-07-01T10:20:30 UTC).
    CHECK(out[0].ts == 1782901230);
    CHECK(out[1].entry.username == "dave");
    CHECK(out[1].ts == 0); // separator-consistency rejection, without dropping the row
}

// The flexible-timestamp parser replaced sscanf ("%4d-%2d-%2dT%2d:%2d:%2d" and
// siblings) for glibc 2.38 __isoc23_* compatibility; these cases pin the scanf
// quirks the rewrite must preserve (width caps, sign-in-width, zero-or-more
// format whitespace, unparseable-field filtering, CRLF tolerance).
TEST_CASE("mapdrive timestamp/field parsing: scanf quirk pins", "[tar][mapdrive][parse]") {
    const std::string text =
        "Event[0]:\n"
        "  Date: 2026-07-01T10:20:301\n" // three-digit seconds: %2d width cap binds → 30
        "  Event ID: 4624\n"
        "Logon Type:\t\t3\n"
        "New Logon:\n"
        "\tAccount Name:\t\talice\n"
        "\tSource Network Address:\t192.168.1.50\n"
        "Event[1]:\n"
        "  Date: 2026-+7-01T10:20:30\n" // signed month within width: accepted as 7
        "  Event ID: 4624\n"
        "Logon Type:\t\t3\n"
        "New Logon:\n"
        "\tAccount Name:\t\tbob\n"
        "\tSource Network Address:\t192.168.1.51\n"
        "Event[2]:\n"
        "  Date: 2026-07-01T10:20:30\n"
        "  Event ID: 4624\n"
        "Logon Type:\t\tbad\n" // unparseable logon type keeps -1 → filtered
        "New Logon:\n"
        "\tAccount Name:\t\tcarol\n"
        "\tSource Network Address:\t192.168.1.52\n"
        "Event[3]:\r\n" // CRLF line endings (Windows-collected text): '\r' is
        "  Date: 2026-07-01T10:20:30\r\n" // whitespace to the tokenizer + parsers
        "  Event ID: 4624\r\n"
        "Logon Type:\t\t3\r\n"
        "New Logon:\r\n"
        "\tAccount Name:\t\terin\r\n"
        "\tSource Network Address:\t192.168.1.53\r\n";
    auto out = parse_win_security_logons(text);
    REQUIRE(out.size() == 3);
    CHECK(out[0].ts == 1782901230); // width-capped seconds (2026-07-01T10:20:30 UTC)
    CHECK(out[1].ts == 1782901230); // signed month
    CHECK(out[2].entry.username == "erin");
    CHECK(out[2].ts == 1782901230); // CRLF text parses identically
    const std::string samba =
        "[2026/07/01   10:20:30,  3] hdr\n" // multiple format-space whitespace
        "  s1 (ipv4:10.0.0.1:445) connect to service s1 initially as user u1\n"
        "[2026/07/0110:20:30,  3] hdr\n" // ZERO format-space whitespace (accepted quirk)
        "  s2 (ipv4:10.0.0.2:445) connect to service s2 initially as user u2\n";
    auto sout = parse_samba_logs(samba);
    REQUIRE(sout.size() == 2);
    CHECK(sout[0].ts == 1782901230);
    CHECK(sout[1].ts == 1782901230);
}

// ── Samba logs / journalctl (Linux inbound historic) ──────────────────────────

TEST_CASE("mapdrive parse_samba_logs: connect events from both log shapes",
          "[tar][mapdrive][parse]") {
    const std::string text =
        "[2026/07/01 10:20:30.123456,  3] ../../source3/smbd/service.c:1055(make_connection_snum)\n"
        "  public (ipv4:192.168.1.50:445) connect to service public initially as user alice "
        "(uid=1000, gid=1000)\n"
        "[2026/07/01T10:25:00,  3] ../../source3/smbd/service.c:1055(make_connection_snum)\n" //
        // slash-date + 'T' is unparseable — the next row falls back to the previous header's ts
        "  private (ipv4:10.0.0.7:445) connect to service private initially as user dave "
        "(uid=1001, gid=1001)\n"
        "2026-07-02T08:15:00+0000 host smbd[1234]: srv (ipv4:10.0.0.9:445) connect to service srv "
        "initially as user carol\n";
    auto out = parse_samba_logs(text);
    REQUIRE(out.size() == 3);
    CHECK(out[0].entry.direction == "inbound");
    CHECK(out[0].entry.local_mount == "public");
    CHECK(out[0].entry.remote_host == "192.168.1.50");
    CHECK(out[0].entry.username == "alice");
    // Exact epoch pins the bracket form "[YYYY/MM/DD HH:MM:SS.us, 3]" at pos=1
    // (2026-07-01 10:20:30 UTC), incl. width-capped seconds + fraction tolerance.
    CHECK(out[0].ts == 1782901230);
    CHECK(out[1].entry.username == "dave");
    CHECK(out[1].ts == 1782901230); // unparseable header → previous header's ts
    CHECK(out[2].entry.local_mount == "srv");
    CHECK(out[2].entry.remote_host == "10.0.0.9");
    CHECK(out[2].entry.username == "carol");
    CHECK(out[2].ts == 1782980100); // inline ISO timestamp (2026-07-02T08:15:00 UTC)
}

// ── insert round-trip: historical (incl. ts=0) + live rows ────────────────────

TEST_CASE("mapdrive insert: historical + live rows round-trip through TarDatabase",
          "[tar][mapdrive][db]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-mapdrive-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    // MapDriveEvent field order: {ts, snapshot_id, action, direction,
    // local_mount, remote_path, remote_host, username, provider, origin}.
    std::vector<MapDriveEvent> rows = {
        {1000, 5, "historical", "outbound", "Z:", "\\\\srv\\share", "srv", "alice", "SMB",
         "historical"},
        {0, 5, "historical", "outbound", "", "\\\\nas\\pub", "nas", "bob", "SMB", "historical"},
        {2000, 6, "appeared", "inbound", "", "", "client1", "carol", "SMB", "live"},
    };
    REQUIRE(db.insert_mapdrive_events(rows));

    auto res = db.execute_query(
        "SELECT ts, action, direction, local_mount, remote_path, remote_host, username, "
        "provider, origin FROM mapdrive_live ORDER BY id");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 3);

    // Historical row with a real timestamp. Assert the string columns individually
    // (remote_path/remote_host/username/provider) so a bind-order transposition in
    // insert_mapdrive_events cannot pass undetected.
    CHECK(res->rows[0][0] == "1000");
    CHECK(res->rows[0][1] == "historical");
    CHECK(res->rows[0][2] == "outbound");
    CHECK(res->rows[0][3] == "Z:");
    CHECK(res->rows[0][4] == "\\\\srv\\share"); // remote_path
    CHECK(res->rows[0][5] == "srv");            // remote_host
    CHECK(res->rows[0][6] == "alice");          // username
    CHECK(res->rows[0][7] == "SMB");            // provider
    CHECK(res->rows[0][8] == "historical");     // origin

    // Historical row with ts=0 is preserved as 0 (not dropped / defaulted away).
    CHECK(res->rows[1][0] == "0");
    CHECK(res->rows[1][3] == ""); // deviceless — empty local_mount round-trips
    CHECK(res->rows[1][8] == "historical");

    // Live inbound row.
    CHECK(res->rows[2][1] == "appeared");
    CHECK(res->rows[2][2] == "inbound");
    CHECK(res->rows[2][8] == "live");

    // Empty batch is a success (matches the arp/dns/software insert contract).
    CHECK(db.insert_mapdrive_events({}));
}

// ── \x1f key collision safety with ':' / '\\' / space fields ──────────────────

TEST_CASE("mapdrive diff: fields with ':' '\\' and spaces do not collide",
          "[tar][mapdrive][diff]") {
    std::vector<MapDriveEntry> prev;
    std::vector<MapDriveEntry> cur = {
        {"outbound", "Z:", "\\\\srv\\share one", "srv", "alice", "SMB"},
        {"outbound", "Y:", "\\\\srv\\share two", "srv", "alice", "SMB"},
        {"inbound", "", "", "srv", "alice", "SMB"}};
    auto ev = compute_mapdrive_events(prev, cur, 100, 1);
    // Three distinct mappings — no key collision despite shared host/user and the
    // ':' / '\\' / space characters in the fields.
    REQUIRE(ev.size() == 3);
}

// ── dedup_history: identity collapse keeps the earliest non-zero ts ────────────

TEST_CASE("mapdrive dedup_history: collapses by identity, keeps earliest non-zero ts",
          "[tar][mapdrive][history]") {
    auto row = [](int64_t ts, const char* host) {
        MapDriveHistoryRow r;
        r.ts = ts;
        r.entry.direction = "outbound";
        r.entry.remote_path = std::string("\\\\") + host + "\\share";
        r.entry.remote_host = host;
        r.entry.username = "alice";
        r.entry.provider = "SMB";
        return r;
    };
    // Same identity three times (ts 0, 300, 100) collapses to one row keeping the
    // smallest NON-ZERO ts (100); a distinct host stays separate.
    std::vector<MapDriveHistoryRow> in = {row(0, "srv"), row(300, "srv"), row(100, "srv"),
                                          row(0, "nas")};
    auto out = dedup_history(in);
    REQUIRE(out.size() == 2);
    // Find the srv row.
    const MapDriveHistoryRow* srv = nullptr;
    for (auto& r : out)
        if (r.entry.remote_host == "srv")
            srv = &r;
    REQUIRE(srv != nullptr);
    CHECK(srv->ts == 100); // earliest non-zero sighting wins over 0 and 300
}

// ── classify_macos_mounts (macOS outbound live, capability-map §3.8) ──────────
//
// Fixture provenance: the local-fstype rows below are a REAL getfsstat(2)
// capture, taken on an arm64 macOS 15 host by compiling and running a
// standalone `getfsstat(nullptr, 0, MNT_NOWAIT)` size-then-fill probe
// (matching tar_mapdrive_collector.cpp's read_getfsstat) and printing
// f_fstypename/f_mntfromname/f_mntonname for every returned struct statfs —
// exactly the ten local volumes/pseudo-filesystems (apfs/devfs/autofs) this
// particular out-of-the-box macOS install mounts (a `csrutil`-sealed system
// volume splits into more apfs rows than a stock install — /, VM, Preboot,
// xarts, iSCPreboot, Hardware, Update, Data — plus devfs and the auto_home
// autofs map), none of them network.
//
// BR-004 remediation: the network-fstype rows below are now REAL getfsstat(2)
// captures too, taken on this same host on 2026-08-25 against locally-hosted
// SMB/NFS/AFP servers rather than transcribed from mount(8) manual-page
// syntax (a manual page documents accepted CLIENT input syntax, not what the
// kernel actually returns in f_mntfromname):
//
//   - smbfs: `dperson/samba` (Alpine, Samba 4.13.7) in Docker, published on
//     127.0.0.1:445, one share `public` with user `alice`; mounted via
//     `mount_smbfs "//alice:alicepass@127.0.0.1/public" <dir>` (exit 0).
//     getfsstat returned f_fstypename="smbfs",
//     f_mntfromname="//alice@127.0.0.1/public" — confirms the credentialed
//     form (username embedded ahead of the host, password never present)
//     that remote_host_of's userinfo-stripping path (and BR-003) depend on.
//   - nfs: `itsthenetwork/nfs-server-alpine` in Docker exporting /nfsshare
//     with `fsid=0` (NFSv4 pseudo-root); mounted via
//     `mount_nfs -o vers=4,tcp 127.0.0.1:/ <dir>` (exit 0). getfsstat
//     returned f_fstypename="nfs", f_mntfromname="127.0.0.1:/" — the
//     `host:/path` colon form remote_host_of's user@host:/path branch parses.
//   - afpfs: `cptactionhank/netatalk` in Docker, published on 127.0.0.1:1548,
//     one share `Share` with user `alice`; mounted via
//     `mount_afp "afp://alice:alicepass@127.0.0.1:1548/Share" <dir>`
//     (exit 0, with the macOS "AFP client is deprecated" warning — the
//     protocol still works today, which is why this repo still ships an AFP
//     leg). getfsstat returned f_fstypename="afpfs",
//     f_mntfromname="//alice@127.0.0.1:1548/Share" — an AFP mount surfaces
//     through getfsstat as a UNC-shaped string (not an `afp://` URI, contra
//     the previous synthetic fixture), with the credentialed username ahead
//     of a host:port pair.
//
// webdav was ATTEMPTED (bytemark/webdav and hacdias/webdav in Docker, both
// reachable and PROPFIND-verified via curl) but never captured: macOS's
// mount_webdav(8) requires an interactive Keychain/GUI authentication step
// (even with -S/-i and a pre-seeded `security add-internet-password` entry)
// that this non-interactive session cannot satisfy — every attempt hung
// waiting on that prompt rather than failing cleanly. Per this remediation's
// instructions, the synthetic webdav row is DELETED rather than kept
// invented; classify_macos_mounts's "webdav" -> "WebDAV" mapping itself is
// untouched (unreachable by any test here now) and remains to be verified
// against a real capture in a follow-up that has an interactive macOS
// session available.
//
// The "cifs" row is kept as a clearly-separate, explicitly-labeled defensive
// case below (NOT represented as a live capture) — macOS's own SMB client
// always reports f_fstypename="smbfs" via smbfs.kext, never "cifs" (that
// name is the Linux kernel module's); classify_macos_mounts's "cifs" branch
// only exists in case a third-party FUSE-based CIFS client ever reports the
// Linux-style name, so a real macOS getfsstat capture cannot exercise it.

TEST_CASE("mapdrive classify_macos_mounts: real local-fstype capture is entirely filtered",
          "[tar][mapdrive][macos][parse]") {
    // Real capture (see provenance note above) — apfs/devfs/autofs, no network fstype.
    std::vector<MacMountRec> mounts = {
        {"apfs", "/dev/disk3s1s1", "/"},
        {"devfs", "devfs", "/dev"},
        {"apfs", "/dev/disk3s6", "/System/Volumes/VM"},
        {"apfs", "/dev/disk3s2", "/System/Volumes/Preboot"},
        {"apfs", "/dev/disk3s4", "/System/Volumes/Update"},
        {"apfs", "/dev/disk1s2", "/System/Volumes/xarts"},
        {"apfs", "/dev/disk1s1", "/System/Volumes/iSCPreboot"},
        {"apfs", "/dev/disk1s3", "/System/Volumes/Hardware"},
        {"apfs", "/dev/disk3s5", "/System/Volumes/Data"},
        {"autofs", "map auto_home", "/System/Volumes/Data/home"},
    };
    auto resolve_host = [](const std::string&) -> std::string {
        FAIL("resolve_host must not be called for a filtered-out (non-network) row");
        return {};
    };
    auto out = classify_macos_mounts(mounts, resolve_host);
    CHECK(out.empty());
}

TEST_CASE("mapdrive classify_macos_mounts: network fstypes populate the full MapDriveEntry "
          "contract",
          "[tar][mapdrive][macos][parse]") {
    // Real getfsstat(2) captures (see provenance note above) — smbfs/nfs/afpfs
    // against locally-hosted Docker SMB/NFS/AFP servers on 2026-08-25. Row 0's
    // embedded username (`//alice@127.0.0.1/public`) is exactly what a real
    // credentialed SMB mount surfaces via f_mntfromname, exercising the
    // user-info-stripping path (matches remote_host_of's fix for B2-001: a
    // credentialed UNC or URI authority must yield the bare host, not the
    // embedded username) against a genuine, not invented, value.
    std::vector<MacMountRec> mounts = {
        {"smbfs", "//alice@127.0.0.1/public", "/Volumes/public"},
        {"nfs", "127.0.0.1:/", "/Volumes/export"},
        {"afpfs", "//alice@127.0.0.1:1548/Share", "/Volumes/shared"},
        {"apfs", "/dev/disk3s5", "/System/Volumes/Data"}, // still dropped even mixed in
    };
    // Fixture-equivalent host resolver (the collector injects the real
    // remote_host_of instead — see the header comment on classify_macos_mounts
    // for why this header cannot call it directly). Mirrors remote_host_of's
    // URI-authority + UNC + user@host: forms, including user-info stripping,
    // so this double stays a faithful stand-in for the production helper.
    auto resolve_host = [](const std::string& from) -> std::string {
        auto strip_userinfo = [](std::string authority) {
            if (auto at = authority.rfind('@'); at != std::string::npos)
                authority.erase(0, at + 1);
            return authority;
        };
        if (auto scheme = from.find("://"); scheme != std::string::npos) {
            auto rest = from.substr(scheme + 3);
            return strip_userinfo(rest.substr(0, rest.find('/')));
        }
        if (from.rfind("//", 0) == 0) {
            auto rest = from.substr(2);
            return strip_userinfo(rest.substr(0, rest.find('/')));
        }
        if (auto colon = from.find(':'); colon != std::string::npos)
            return from.substr(0, colon);
        return {};
    };
    auto out = classify_macos_mounts(mounts, resolve_host);
    REQUIRE(out.size() == 3); // the apfs row is dropped

    CHECK(out[0].direction == "outbound");
    CHECK(out[0].local_mount == "/Volumes/public");
    CHECK(out[0].remote_path == "//alice@127.0.0.1/public"); // raw f_mntfromname, userinfo intact (BR-003)
    CHECK(out[0].remote_host == "127.0.0.1"); // username stripped
    CHECK(out[0].username == ""); // unavailable via getfsstat, like the Linux leg
    CHECK(out[0].provider == "SMB");

    CHECK(out[1].direction == "outbound");
    CHECK(out[1].local_mount == "/Volumes/export");
    CHECK(out[1].remote_path == "127.0.0.1:/");
    CHECK(out[1].remote_host == "127.0.0.1");
    CHECK(out[1].username == "");
    CHECK(out[1].provider == "NFS");

    CHECK(out[2].direction == "outbound");
    CHECK(out[2].local_mount == "/Volumes/shared");
    CHECK(out[2].remote_path == "//alice@127.0.0.1:1548/Share"); // raw f_mntfromname, userinfo intact
    CHECK(out[2].remote_host == "127.0.0.1:1548"); // username stripped, host:port kept
    CHECK(out[2].username == "");
    CHECK(out[2].provider == "AFP");
}

TEST_CASE("mapdrive classify_macos_mounts: cifs fstype maps to SMB (defensive, not a live capture)",
          "[tar][mapdrive][macos][parse]") {
    // NOT a getfsstat capture — macOS's own SMB client always reports
    // f_fstypename="smbfs" (see provenance note above); this only exercises
    // classify_macos_mounts's defensive alias for a third-party FUSE-based
    // CIFS client that might report the Linux-style fstype name.
    std::vector<MacMountRec> mounts = {
        {"cifs", "//nas.example.com/backup", "/Volumes/backup"},
    };
    auto resolve_host = [](const std::string& from) -> std::string {
        auto rest = from.substr(2);
        return rest.substr(0, rest.find('/'));
    };
    auto out = classify_macos_mounts(mounts, resolve_host);
    REQUIRE(out.size() == 1);
    CHECK(out[0].provider == "SMB"); // cifs maps to SMB same as smbfs
}

// remote_host_of itself (tar_mapdrive_collector.cpp) is anonymous-namespace
// scoped and unreachable directly from this TU (see the header comment on
// classify_macos_mounts) — but it is exercised for real, not via a double,
// through parse_proc_mounts/parse_fstab. This case adds the two forms the
// B2-001 fix taught remote_host_of to strip correctly: a scheme:// authority
// (`davfs` device strings are commonly a WebDAV https:// URL, per davfs2's
// fstab documentation) and a credentialed UNC (`mount.cifs` accepts a
// username embedded ahead of the host in the device field). This proves the
// production fix at the same helper the macOS getfsstat leg calls, without
// needing a network mount live on the test host.
TEST_CASE("mapdrive parse_fstab: scheme:// and credentialed-UNC hosts resolve to the bare host",
          "[tar][mapdrive][parse]") {
    const std::string text = "https://dav.example.com/files /mnt/dav davfs defaults 0 0\n"
                             "//alice@fileserver/share /mnt/smb cifs defaults 0 0\n";
    auto out = parse_fstab(text);
    REQUIRE(out.size() == 2);
    CHECK(out[0].entry.remote_host == "dav.example.com");
    CHECK(out[1].entry.remote_host == "fileserver"); // username stripped, not "alice@fileserver"
}

// BR-003: an IPv6 NFS host embeds colons of its own, so the first-bare-colon
// split previously used truncated it at the host's first hextet (`2001` for
// "2001:db8::1:/export", `[2001` for the bracketed form). remote_host_of now
// splits on the LAST ":/" (the export path's leading slash), which an IPv6
// address's own colons never contain.
TEST_CASE("mapdrive parse_proc_mounts: IPv6 NFS hosts resolve in full, bracketed and not",
          "[tar][mapdrive][parse]") {
    const std::string text = "2001:db8::1:/export /mnt/v6a nfs4 rw 0 0\n"
                             "[2001:db8::1]:/export /mnt/v6b nfs4 rw 0 0\n"
                             "alice@2001:db8::1:/export /mnt/v6c nfs4 rw 0 0\n";
    auto out = parse_proc_mounts(text).entries;
    REQUIRE(out.size() == 3);
    CHECK(out[0].remote_host == "2001:db8::1");
    CHECK(out[1].remote_host == "2001:db8::1"); // brackets stripped
    CHECK(out[2].remote_host == "2001:db8::1"); // username stripped, full host kept
}

// ── apply_entry_cap (kMapDriveEntryCap parity with the Linux leg) ─────────────

TEST_CASE("mapdrive apply_entry_cap: truncates at kMapDriveEntryCap, reports truncation",
          "[tar][mapdrive][macos][cap]") {
    auto make_entry = [](int i) {
        MapDriveEntry e;
        e.direction = "outbound";
        e.remote_host = "host" + std::to_string(i);
        e.provider = "NFS";
        return e;
    };

    // Exactly at the cap: no truncation.
    std::vector<MapDriveEntry> at_cap;
    for (std::size_t i = 0; i < kMapDriveEntryCap; ++i)
        at_cap.push_back(make_entry(static_cast<int>(i)));
    CHECK_FALSE(apply_entry_cap(at_cap, kMapDriveEntryCap));
    CHECK(at_cap.size() == kMapDriveEntryCap);

    // cap + 1 constructed records: truncates to exactly the cap.
    std::vector<MapDriveEntry> over_cap;
    for (std::size_t i = 0; i < kMapDriveEntryCap + 1; ++i)
        over_cap.push_back(make_entry(static_cast<int>(i)));
    CHECK(apply_entry_cap(over_cap, kMapDriveEntryCap));
    REQUIRE(over_cap.size() == kMapDriveEntryCap);
    // The kept rows are the first kMapDriveEntryCap, in order.
    CHECK(over_cap.front().remote_host == "host0");
    CHECK(over_cap.back().remote_host == "host" + std::to_string(kMapDriveEntryCap - 1));
}

// ── run_getfsstat_with_retry (BR-002/BR-006: exactly-full-vs-truncated) ───────
//
// getfsstat(2) is a native syscall (rung 1) with no test-double process to
// spawn, so the count_fn/fill_fn injection points let these tests drive the
// REAL retry/give-up/cap algorithm (the same function
// tar_mapdrive_collector.cpp's read_getfsstat wires the real getfsstat(2)
// calls into) against synthetic sequences, rather than reimplementing the
// logic under test.

TEST_CASE("run_getfsstat_with_retry: ordinary fill under capacity succeeds on the first attempt",
          "[tar][mapdrive][macos][getfsstat]") {
    int count_calls = 0;
    int fill_calls = 0;
    auto out = run_getfsstat_with_retry(
        [&]() {
            ++count_calls;
            return 2; // two mounts, no churn
        },
        [&](std::size_t capacity, std::vector<MacMountRec>& mounts) {
            ++fill_calls;
            REQUIRE(capacity == 3); // n + 1 headroom slot
            mounts = {MacMountRec{"nfs", "host:/a", "/mnt/a"}, MacMountRec{"nfs", "host:/b", "/mnt/b"}};
            return 2; // < capacity -- not exactly full
        },
        kMapDriveEntryCap);

    CHECK(out.ok);
    REQUIRE(out.mounts.size() == 2);
    CHECK(out.mounts[0].on == "/mnt/a");
    CHECK(count_calls == 1);
    CHECK(fill_calls == 1);
}

TEST_CASE("run_getfsstat_with_retry: a mount growing the table between count and fill is "
          "retried, not accepted as complete",
          "[tar][mapdrive][macos][getfsstat]") {
    // Attempt 1: count()=1 -> capacity=2, but a mount appears before fill()
    // runs, so fill() exactly fills the padded buffer (2) -- indistinguishable
    // from truncation, must be retried rather than returned as a 1-mount
    // snapshot that silently dropped the new mount.
    // Attempt 2: the table has stabilized at 2 -- count()=2 -> capacity=3,
    // fill() returns 2 (< capacity), a genuine complete snapshot.
    int attempt = 0;
    auto out = run_getfsstat_with_retry(
        [&]() { return attempt == 0 ? 1 : 2; },
        [&](std::size_t capacity, std::vector<MacMountRec>& mounts) {
            ++attempt;
            if (attempt == 1) {
                REQUIRE(capacity == 2);
                mounts = {MacMountRec{"nfs", "host:/a", "/mnt/a"},
                          MacMountRec{"nfs", "host:/b", "/mnt/b"}};
                return 2; // == capacity -- exactly full, churn signal
            }
            REQUIRE(capacity == 3);
            mounts = {MacMountRec{"nfs", "host:/a", "/mnt/a"}, MacMountRec{"nfs", "host:/b", "/mnt/b"}};
            return 2; // < capacity -- stabilized, complete
        },
        kMapDriveEntryCap);

    CHECK(out.ok);
    REQUIRE(out.mounts.size() == 2);
    CHECK(attempt == 2); // retried exactly once
}

TEST_CASE("run_getfsstat_with_retry: a mount table that never stabilizes gives up rather than "
          "loop forever, retaining the previous baseline",
          "[tar][mapdrive][macos][getfsstat]") {
    // Every attempt's fill() exactly fills the padded buffer -- a
    // pathologically churning table. After max_attempts the helper must give
    // up (ok=false) so the caller throws IncompleteCaptureError, not loop
    // forever or accept a partial table as complete.
    int attempts = 0;
    auto out = run_getfsstat_with_retry(
        [&]() { return 1; },
        [&](std::size_t capacity, std::vector<MacMountRec>& mounts) {
            ++attempts;
            mounts = {MacMountRec{"nfs", "host:/a", "/mnt/a"}};
            return static_cast<int>(capacity); // always exactly full
        },
        kMapDriveEntryCap, /*max_attempts=*/4);

    CHECK_FALSE(out.ok);
    CHECK(out.mounts.empty());
    CHECK(attempts == 4); // bounded, not unbounded
}

TEST_CASE("run_getfsstat_with_retry: a raw count at/over the cap is rejected before any "
          "allocation (BR-006)",
          "[tar][mapdrive][macos][getfsstat]") {
    bool fill_called = false;
    auto out = run_getfsstat_with_retry(
        [&]() { return 5; }, // n >= cap
        [&](std::size_t, std::vector<MacMountRec>&) {
            fill_called = true;
            return 0;
        },
        /*cap=*/5);

    CHECK_FALSE(out.ok);
    CHECK(out.mounts.empty());
    CHECK_FALSE(fill_called); // never allocates/fills an over-cap raw table
}

TEST_CASE("run_getfsstat_with_retry: count()/fill() errno failures and the vanished/empty "
          "cases are reported honestly",
          "[tar][mapdrive][macos][getfsstat]") {
    // count() failure (e.g. EIO) -- not a genuinely empty table.
    auto count_fail = run_getfsstat_with_retry(
        [] { return -1; }, [](std::size_t, std::vector<MacMountRec>&) { return 0; },
        kMapDriveEntryCap);
    CHECK_FALSE(count_fail.ok);

    // Genuinely empty mount table (n == 0) -- ok, no fill() call needed.
    auto genuinely_empty = run_getfsstat_with_retry(
        [] { return 0; },
        [](std::size_t, std::vector<MacMountRec>&) -> int { FAIL("fill_fn should not run"); return -1; },
        kMapDriveEntryCap);
    CHECK(genuinely_empty.ok);
    CHECK(genuinely_empty.mounts.empty());

    // fill() failure (e.g. EIO) after a successful count().
    auto fill_fail = run_getfsstat_with_retry(
        [] { return 2; }, [](std::size_t, std::vector<MacMountRec>&) { return -1; }, kMapDriveEntryCap);
    CHECK_FALSE(fill_fail.ok);

    // Every mount vanished between count() and fill() -- genuinely empty
    // this tick, not an error.
    auto vanished = run_getfsstat_with_retry(
        [] { return 2; }, [](std::size_t, std::vector<MacMountRec>&) { return 0; }, kMapDriveEntryCap);
    CHECK(vanished.ok);
    CHECK(vanished.mounts.empty());
}

// ── argv re-home: same blob -> same entries ────────────────────────────────
//
// tar_mapdrive_collector.cpp's run_command()/popen()/_popen() sites were
// re-homed onto run_bounded_subprocess (rung 2 argv), which hands the exact
// same parsers below the exact same output blob via SubprocessResult::output
// (see run_bounded_subprocess's ADR-3002 contract). These pins prove the
// three blob-oriented parsers the migration touched (parse_smbstatus /
// parse_win_security_logons / parse_samba_logs) are byte-for-byte unmodified
// by the migration: the same captured-shape blob still yields the same
// entries, independent of how that blob was obtained.

TEST_CASE("mapdrive argv re-home: parse_smbstatus/parse_win_security_logons/parse_samba_logs "
          "are unchanged by the popen->runner migration",
          "[tar][mapdrive][parse][regression]") {
    const std::string smb_blob =
        "PID     Username     Group        Machine                          Protocol\n"
        "3456    alice        domain users 192.168.1.50 (ipv4:192.168.1.50:44556)  SMB3_11\n";
    auto smb_parsed = parse_smbstatus(smb_blob);
    CHECK_FALSE(smb_parsed.malformed);
    auto smb = smb_parsed.entries;
    REQUIRE(smb.size() == 1);
    CHECK(smb[0].username == "alice");
    CHECK(smb[0].remote_host == "192.168.1.50");

    const std::string wevt_blob =
        "Event[0]:\n"
        "  Date: 2026-07-01T10:20:30\n"
        "  Event ID: 4624\n"
        "Logon Type:\t\t3\n"
        "New Logon:\n"
        "\tAccount Name:\t\talice\n"
        "\tSource Network Address:\t192.168.1.50\n";
    auto wevt = parse_win_security_logons(wevt_blob);
    REQUIRE(wevt.size() == 1);
    CHECK(wevt[0].entry.username == "alice");
    CHECK(wevt[0].entry.remote_host == "192.168.1.50");

    const std::string samba_blob =
        "2026-07-02T08:15:00+0000 host smbd[1234]: srv (ipv4:10.0.0.9:445) connect to service "
        "srv initially as user carol\n";
    auto samba = parse_samba_logs(samba_blob);
    REQUIRE(samba.size() == 1);
    CHECK(samba[0].entry.username == "carol");
    CHECK(samba[0].entry.local_mount == "srv");
}

// ── enumerate_mapdrive(): real macOS getfsstat leg (Finding 4) ──────────────
//
// Everything above exercises only the pure text/mount-record parsers and
// classify_macos_mounts/run_getfsstat_with_retry fed synthetic records.
// Nothing called the real macOS enumerate_mapdrive() itself, so a
// regression in the actual getfsstat(2) size-then-fill wiring
// (read_getfsstat, tar_mapdrive_collector.cpp) -- a wrong flag, a broken
// retry loop, a buffer-sizing bug -- would still pass every test in this
// file. Live-host smoke test: calls the REAL enumerate_mapdrive() against
// this machine's actual live mount table and asserts only that it returns
// without throwing and the shape is sane -- no timing assumption, no
// process spawn (getfsstat is a local syscall). Same established exception
// as test_tar_arp.cpp's enumerate_arp() live smoke test; kept minimal so it
// stays fast and non-flaky regardless of what's actually mounted on the
// host at test time (empty/no network mounts is the common, legitimate
// case on a dev machine).
#ifdef __APPLE__
TEST_CASE("enumerate_mapdrive (macOS getfsstat leg): runs against the live "
          "host without throwing, entries are internally consistent",
          "[tar][mapdrive][macos][live]") {
    std::vector<MapDriveEntry> entries;
    REQUIRE_NOTHROW(entries = enumerate_mapdrive());

    for (const auto& e : entries) {
        CHECK(e.direction == "outbound");
        CHECK_FALSE(e.local_mount.empty());
        CHECK_FALSE(e.provider.empty());
    }
}
#endif // __APPLE__
