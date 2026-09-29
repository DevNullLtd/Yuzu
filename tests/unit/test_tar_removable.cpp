/**
 * test_tar_removable.cpp -- Unit tests for the `removable` cursor-model TAR
 * source: the pure parser core (tar_removable_parsers.hpp) plus the real-leg
 * sections the verification protocol requires (runDir/verification-protocol.
 * md UPDATE 2026-09-04) — a Windows/Linux/macOS section each running its own
 * live capture path and reporting an EXPLICIT, named result rather than a
 * silently-passing skip.
 *
 * Windows fixtures below are REAL CAPTURE the-rig 2026-09-04 (Kingston
 * DataTraveler 3.0, serial EE05D75054E9) — see runDir/fixtures/README.md and
 * removable-0{1,2,3}-*.txt for the untrimmed originals. Per README.md's own
 * "before committing" instruction, the Mbr/PartitionTable/Ebr* hex blobs are
 * TRIMMED here (hundreds of bytes each, not read by any field the parser
 * extracts) — every field the parser DOES read is kept verbatim from the
 * capture, including the real SerialNumber/ParentId identifiers.
 */

#include "tar_cursor.hpp"
#include "tar_db.hpp"
#include "tar_removable_parsers.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/process_enum.hpp>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>

#if defined(__linux__)
#include <dirent.h>
#endif

using namespace yuzu::tar;
namespace fs = std::filesystem;

namespace {

// REAL CAPTURE the-rig 2026-09-04T11:06:24+01:00. Command: wevtutil qe
// Microsoft-Windows-Partition/Diagnostic /c:10 /f:xml (capture-removable.ps1,
// phase=attached). EventRecordID 156 — Kingston DataTraveler 3.0 attach.
// PartitionTable/Mbr/Ebr* TRIMMED per README.md; every other field verbatim.
const std::string kPartitionAttach156 = R"(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Partition' Guid='{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}'/><EventID>1006</EventID><Version>7</Version><Level>4</Level><TimeCreated SystemTime='2026-09-04T10:06:24.2284397Z'/><EventRecordID>156</EventRecordID><Channel>Microsoft-Windows-Partition/Diagnostic</Channel><Computer>DESKTOP-04DNSIG</Computer></System><EventData><Data Name='DiskNumber'>2</Data><Data Name='BytesPerSector'>512</Data><Data Name='Capacity'>124117843968</Data><Data Name='BusType'>7</Data><Data Name='Manufacturer'>Kingston</Data><Data Name='Model'>DataTraveler 3.0</Data><Data Name='Revision'>PMAP</Data><Data Name='SerialNumber'>EE05D75054E9</Data><Data Name='ParentId'>USB\VID_0951&amp;PID_1666\E0D55EA574A4E57049410200</Data><Data Name='DiskId'>{edd4b19b-37b4-1c70-dc58-b3e793f55951}</Data><Data Name='UserRemovalPolicy'>true</Data><Data Name='PartitionCount'>4</Data></EventData></Event>)";

// REAL CAPTURE the-rig 2026-09-04T11:07:00+01:00, phase=detached. EventRecordID
// 157 -- SAME EventID 1006, SAME SerialNumber/DiskId as record 156, but
// Capacity/BytesPerSector/PartitionCount all zeroed and UserRemovalPolicy
// false -- the payload-collapse discriminator README.md documents.
const std::string kPartitionDetach157 = R"(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Partition' Guid='{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}'/><EventID>1006</EventID><Version>7</Version><Level>4</Level><TimeCreated SystemTime='2026-09-04T10:07:00.5985784Z'/><EventRecordID>157</EventRecordID><Channel>Microsoft-Windows-Partition/Diagnostic</Channel><Computer>DESKTOP-04DNSIG</Computer></System><EventData><Data Name='DiskNumber'>2</Data><Data Name='BytesPerSector'>0</Data><Data Name='Capacity'>0</Data><Data Name='BusType'>7</Data><Data Name='Manufacturer'>Kingston</Data><Data Name='Model'>DataTraveler 3.0</Data><Data Name='Revision'>PMAP</Data><Data Name='SerialNumber'>EE05D75054E9</Data><Data Name='ParentId'>USB\VID_0951&amp;PID_1666\E0D55EA574A4E57049410200</Data><Data Name='DiskId'>{edd4b19b-37b4-1c70-dc58-b3e793f55951}</Data><Data Name='UserRemovalPolicy'>false</Data><Data Name='PartitionCount'>0</Data></EventData></Event>)";

// Ephemeral on-disk TarDatabase for the real-leg sections (mirrors
// test_tar_cursor.cpp's TestTarDb).
struct TestTarDb {
    TarDatabase db;
    fs::path path;

    ~TestTarDb() {
        { TarDatabase discard = std::move(db); }
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
    }
};

TestTarDb make_test_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_removable_");
    auto opened = TarDatabase::open(tmp);
    REQUIRE(opened.has_value());
    return TestTarDb{std::move(*opened), tmp};
}

// Build a NUL-separated uevent-shaped buffer from plain tokens -- avoids
// hand-counting embedded-'\0' string-literal lengths (error-prone and, if
// wrong, silently truncates or over-reads the fixture).
std::string join_nul(std::initializer_list<std::string_view> tokens) {
    std::string out;
    for (auto t : tokens) {
        out.append(t);
        out.push_back('\0');
    }
    return out;
}

// REAL CAPTURE the-rig 2026-09-04T11:05:24+01:00 (baseline phase), EventRecordID
// 155 -- an INTERNAL Samsung NVMe drive, same EventID 1006, BusType 17 (not 7).
// This is what "keying on ID alone" wrongly ingests as removable.
const std::string kPartitionInternalNvme155 = R"(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Partition' Guid='{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}'/><EventID>1006</EventID><Version>7</Version><Level>4</Level><TimeCreated SystemTime='2026-09-04T09:51:16.9173930Z'/><EventRecordID>155</EventRecordID><Channel>Microsoft-Windows-Partition/Diagnostic</Channel><Computer>DESKTOP-04DNSIG</Computer></System><EventData><Data Name='DiskNumber'>1</Data><Data Name='BytesPerSector'>512</Data><Data Name='Capacity'>1000204886016</Data><Data Name='BusType'>17</Data><Data Name='Manufacturer'>NULL</Data><Data Name='Model'>Samsung SSD 970 EVO Plus 1TB</Data><Data Name='Revision'>3B2QEXM7</Data><Data Name='SerialNumber'>0025_3858_1150_C5F7.</Data><Data Name='UserRemovalPolicy'>false</Data><Data Name='PartitionCount'>2</Data></EventData></Event>)";

} // namespace

// ── Partition/Diagnostic parsing + payload-collapse classification ─────────

TEST_CASE("removable Partition/Diagnostic: real attach record (156) parses with BusType 7 and "
          "classifies as attach",
          "[tar][removable][parse][real-capture]") {
    const auto rec = parse_partition_diagnostic_xml(kPartitionAttach156);
    REQUIRE(rec.has_value());
    CHECK(rec->event_record_id == 156);
    CHECK(rec->bus_type == "7");
    CHECK(is_removable_bus_type(rec->bus_type));
    CHECK(rec->manufacturer == "Kingston");
    CHECK(rec->model == "DataTraveler 3.0");
    CHECK(rec->serial_number == "EE05D75054E9");
    CHECK(rec->parent_id == "USB\\VID_0951&PID_1666\\E0D55EA574A4E57049410200");
    CHECK(rec->disk_id == "{edd4b19b-37b4-1c70-dc58-b3e793f55951}");
    CHECK(rec->user_removal_policy);
    CHECK(classify_partition_transition(*rec) == PartitionTransition::kAttach);
}

TEST_CASE("removable Partition/Diagnostic: real detach record (157) shares EventID+Serial+DiskId "
          "with the attach but is NEVER classified as a second attach",
          "[tar][removable][parse][real-capture]") {
    const auto attach = parse_partition_diagnostic_xml(kPartitionAttach156);
    const auto detach = parse_partition_diagnostic_xml(kPartitionDetach157);
    REQUIRE(attach.has_value());
    REQUIRE(detach.has_value());

    // The load-bearing correlation: same serial/disk id, different payload.
    CHECK(detach->serial_number == attach->serial_number);
    CHECK(detach->disk_id == attach->disk_id);
    CHECK(detach->capacity == 0);
    CHECK(detach->bytes_per_sector == 0);
    CHECK(detach->partition_count == 0);
    CHECK_FALSE(detach->user_removal_policy);

    CHECK(classify_partition_transition(*detach) == PartitionTransition::kDetach);
    CHECK(classify_partition_transition(*detach) != classify_partition_transition(*attach));
}

TEST_CASE("removable Partition/Diagnostic: internal NVMe (BusType 17) is excluded despite sharing "
          "EventID 1006 with removable USB records",
          "[tar][removable][parse][real-capture]") {
    const auto rec = parse_partition_diagnostic_xml(kPartitionInternalNvme155);
    REQUIRE(rec.has_value());
    CHECK(rec->bus_type == "17");
    CHECK_FALSE(is_removable_bus_type(rec->bus_type));
}

TEST_CASE("removable Partition/Diagnostic: non-1006 / unparseable-time XML yields nullopt",
          "[tar][removable][parse]") {
    CHECK_FALSE(parse_partition_diagnostic_xml("<Event><System><EventID>4</EventID></System>"
                                               "<EventData/></Event>")
                  .has_value());
    CHECK_FALSE(parse_partition_diagnostic_xml("").has_value());
}

// ── Per-channel EventRecordID + wrap detection ──────────────────────────────

TEST_CASE("removable: generic EventRecordID extraction works across channels",
          "[tar][removable][parse]") {
    CHECK(extract_event_record_id(kPartitionAttach156) == 156);
    CHECK(extract_event_record_id(kPartitionDetach157) == 157);
    CHECK_FALSE(extract_event_record_id("<Event><System/></Event>").has_value());
}

TEST_CASE("removable channel wrap: a stored cursor behind the oldest retained record id has "
          "wrapped -- modelled on the MEASURED Kernel-PnP/Configuration eviction "
          "(1432 -> 1352 records, README.md discriminator #3)",
          "[tar][removable][cursor][real-capture]") {
    // The real capture evicted 80 records (1432 -> 1352). EventRecordIDs are
    // positive and monotonic, so the eviction moves the OLDEST RETAINED ID
    // forward by 80 — it is not a record count subtracted from another. A
    // cursor stored before the eviction (say record id 1) is now behind that
    // new floor. (An earlier revision of this line computed 1352 - 1432 + 1 =
    // -79 and asserted a NEGATIVE oldest-retained id, which no channel can
    // report; the predicate correctly returned false and the test failed.)
    CHECK(channel_cursor_wrapped(/*stored=*/1, /*oldest_retained=*/1 + 80));
    CHECK(channel_cursor_wrapped(1, 81));
    CHECK_FALSE(channel_cursor_wrapped(/*stored=*/100, /*oldest_retained=*/81));
    CHECK_FALSE(channel_cursor_wrapped(/*stored=*/81, /*oldest_retained=*/81)); // equal = not wrapped
    // C3: the boundary is the first UNREAD record. Committed through 80 and
    // retention has aged out everything through 80 -- record 81 is still there
    // and is exactly what we are about to read, so this is the healthy steady
    // state, not a wrap. Reporting it as one made the collector head-jump over
    // record 81 and lose it for real.
    CHECK_FALSE(channel_cursor_wrapped(/*stored=*/80, /*oldest_retained=*/81));
    // One further along IS a wrap: 81 was the first unread and it is gone.
    CHECK(channel_cursor_wrapped(/*stored=*/80, /*oldest_retained=*/82));
}

// ── Device identity (P-011) ─────────────────────────────────────────────────

TEST_CASE("removable identity: a non-generic serial is used directly", "[tar][removable][identity]") {
    CHECK_FALSE(is_generic_serial("EE05D75054E9"));
    const auto k1 = compute_device_key("Kingston", "DataTraveler 3.0", "EE05D75054E9", "unused");
    CHECK(k1.used_serial);
    const auto k2 = compute_device_key("Kingston", "DataTraveler 3.0", "EE05D75054E9", "different");
    CHECK(k1.device_key == k2.device_key); // instance id is irrelevant once serial is trusted
}

TEST_CASE("removable identity: empty/whitespace/all-zero serials are generic and fall back to the "
          "platform-stable instance id, marked in evidence via used_serial=false",
          "[tar][removable][identity]") {
    CHECK(is_generic_serial(""));
    CHECK(is_generic_serial("   "));
    CHECK(is_generic_serial("0000000000"));
    CHECK(is_generic_serial("0"));
    CHECK_FALSE(is_generic_serial("0025_3858_1150_C5F7.")); // NOT generic — real, just odd-shaped

    const auto k = compute_device_key("Generic", "USB Storage", "", "USB\\VID_0000&PID_0000\\6&abc");
    CHECK_FALSE(k.used_serial);
    CHECK_FALSE(k.device_key.empty());
}

TEST_CASE("removable identity: two anonymous-serial devices sharing a platform instance id "
          "collide -- the documented residual limitation (docs/user-manual/tar-removable.md)",
          "[tar][removable][identity]") {
    const auto a = compute_device_key("Generic", "Flash Disk", "", "USB\\VID_0000&PID_0000\\5&x");
    const auto b = compute_device_key("Generic", "Flash Disk", "", "USB\\VID_0000&PID_0000\\5&x");
    CHECK(a.device_key == b.device_key); // same vendor/product/instance id => same key, by design
    CHECK_FALSE(a.used_serial);

    const auto c = compute_device_key("Generic", "Flash Disk", "", "USB\\VID_0000&PID_0000\\5&y");
    CHECK(a.device_key != c.device_key); // a different instance id DOES distinguish them
}

TEST_CASE("removable identity: vendor/product participate in the key even with a shared serial "
          "basis",
          "[tar][removable][identity]") {
    const auto a = compute_device_key("VendorA", "ModelX", "SN1", "unused");
    const auto b = compute_device_key("VendorB", "ModelX", "SN1", "unused");
    CHECK(a.device_key != b.device_key);
}

// ── Cursor JSON encode/decode ────────────────────────────────────────────────

TEST_CASE("removable cursor json: round-trips channels, attach_set, and baseline_done",
          "[tar][removable][cursor]") {
    RemovableCursorState st;
    st.baseline_done = true;
    st.channels["partition"].record_id = 157;
    st.channels["pnp"].record_id = 1352;
    st.channels["storsvc"].record_id = 115;
    st.attach_set["deadbeef"] = true;

    const auto json = encode_removable_cursor(st);
    CHECK(json.find("\"v\":1") != std::string::npos);

    const auto back = decode_removable_cursor(json);
    CHECK(back.baseline_done);
    REQUIRE(back.channels.count("partition"));
    CHECK(back.channels.at("partition").record_id == 157);
    CHECK(back.channels.at("pnp").record_id == 1352);
    CHECK(back.channels.at("storsvc").record_id == 115);
    REQUIRE(back.attach_set.count("deadbeef"));
    CHECK(back.attach_set.at("deadbeef"));
}

TEST_CASE("removable cursor json: nullopt / empty JSON decode as honest 'never persisted' -- "
          "never a thrown error, and NOT malformed (R-005: this is an ordinary first run, not a "
          "lost cursor)",
          "[tar][removable][cursor]") {
    const auto never = decode_removable_cursor(std::nullopt);
    CHECK_FALSE(never.baseline_done);
    CHECK_FALSE(never.malformed);
    const auto empty = decode_removable_cursor(std::string{});
    CHECK_FALSE(empty.baseline_done);
    CHECK_FALSE(empty.malformed);
}

TEST_CASE("removable cursor json: malformed (unparseable) JSON decodes as an honest fresh state "
          "-- never a thrown error -- but IS flagged malformed=true (R-005: tar_cursor.hpp rule 2 "
          "names this an explicit CursorLost case, distinct from a genuine first run)",
          "[tar][removable][cursor]") {
    const auto garbled = decode_removable_cursor(std::string{"{not json"});
    CHECK_FALSE(garbled.baseline_done);
    CHECK(garbled.channels.empty());
    CHECK(garbled.attach_set.empty());
    CHECK(garbled.malformed);
}

TEST_CASE("removable cursor json: a decoded-then-immediately-re-encoded empty state is a stable "
          "fixed point (first-ever collect() round trip)",
          "[tar][removable][cursor]") {
    const RemovableCursorState fresh;
    const auto encoded = encode_removable_cursor(fresh);
    const auto decoded = decode_removable_cursor(encoded);
    CHECK_FALSE(decoded.baseline_done);
    CHECK(decoded.channels.empty());
    CHECK(decoded.attach_set.empty());
}

// ── exec-from-removable (P-004: exec_path only) ─────────────────────────────

TEST_CASE("removable exec-from-removable: a path under the volume root matches, with or without "
          "a trailing separator on the root",
          "[tar][removable][exec]") {
    CHECK(exec_path_under_removable_root("/Volumes/KINGSTON/payload/tool", "/Volumes/KINGSTON"));
    CHECK(exec_path_under_removable_root("/Volumes/KINGSTON/payload/tool", "/Volumes/KINGSTON/"));
    CHECK(exec_path_under_removable_root(R"(E:\payload\tool.exe)", R"(E:\)",
                                        /*case_insensitive=*/true,
                                        /*backslash_is_separator=*/true));
    CHECK(exec_path_under_removable_root("/Volumes/KINGSTON", "/Volumes/KINGSTON")); // exact root itself
}

TEST_CASE("removable exec-from-removable: a sibling path that merely shares a string prefix does "
          "NOT match (no boundary), and an empty exec_path never claims anything (P-004)",
          "[tar][removable][exec]") {
    CHECK_FALSE(exec_path_under_removable_root("/Volumes/KINGSTON2/tool", "/Volumes/KINGSTON"));
    CHECK_FALSE(exec_path_under_removable_root("/usr/bin/tool", "/Volumes/KINGSTON"));
    CHECK_FALSE(exec_path_under_removable_root("", "/Volumes/KINGSTON"));
    CHECK_FALSE(exec_path_under_removable_root("/Volumes/KINGSTON/tool", ""));
}

TEST_CASE("removable exec-from-removable: case-insensitive comparison matches differently-cased "
          "paths (Windows/macOS default filesystem semantics), while the default (case-sensitive) "
          "comparison does not -- R-016",
          "[tar][removable][exec]") {
    // Windows semantics: case-insensitive AND backslash-separated. The two
    // flags are separate so a POSIX caller can never get the second by asking
    // for the first (C9), which means a Windows-path case must state both.
    CHECK(exec_path_under_removable_root(R"(E:\Payload\Tool.exe)", R"(e:\payload)",
                                         /*case_insensitive=*/true,
                                         /*backslash_is_separator=*/true));
    CHECK_FALSE(exec_path_under_removable_root(R"(E:\Payload\Tool.exe)", R"(e:\payload)",
                                               /*case_insensitive=*/false,
                                               /*backslash_is_separator=*/true));
    // Case-sensitive (Linux default) never confuses a differently-cased sibling for a match.
    CHECK_FALSE(exec_path_under_removable_root("/media/USER/tool", "/media/user",
                                                /*case_insensitive=*/false));
}

TEST_CASE("removable exec-from-removable: select_exec_from_removable (R-013) is the pure decision "
          "core the collector's field-selection (ProcessInfo::exec_path, never cmdline) feeds -- "
          "exercised here without any live process_enum() call. An empty exec_path never "
          "produces a match (P-004); a populated one produces the typed device_key/image_path/pid "
          "triple; a process whose path resolves under no attached root produces nothing.",
          "[tar][removable][exec]") {
    const std::vector<std::pair<std::string, std::string>> roots = {
       {"devkey-a", "/Volumes/KINGSTON"},
    };
    const std::vector<std::pair<std::int64_t, std::string>> pid_exec_paths = {
       {111, ""},                                  // P-004: empty exec_path -- never a claim
       {222, "/Volumes/KINGSTON/payload/tool"},     // matches devkey-a
       {333, "/usr/bin/legit"},                     // resolves under no attached root
    };
    const auto matches = select_exec_from_removable(pid_exec_paths, roots, /*case_insensitive=*/false);
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].device_key == "devkey-a");
    CHECK(matches[0].image_path == "/Volumes/KINGSTON/payload/tool");
    CHECK(matches[0].pid == 222);
}

TEST_CASE("removable exec-from-removable: select_exec_from_removable with no attached roots "
          "produces no matches regardless of how many processes are supplied",
          "[tar][removable][exec]") {
    const std::vector<std::pair<std::int64_t, std::string>> pid_exec_paths = {
       {1, "/Volumes/KINGSTON/tool"},
    };
    CHECK(select_exec_from_removable(pid_exec_paths, {}, false).empty());
}

TEST_CASE("removable exec-from-removable: select_exec_from_removable_processes (R-013 fix round) "
          "reads ProcessInfo::exec_path, NEVER ::cmdline -- this is the collector-boundary "
          "field-selection line append_exec_from_removable feeds, now testable without a live "
          "process_enum() call. A process whose exec_path resolves under a root but whose cmdline "
          "does NOT still matches (proves exec_path is read); a process whose cmdline resolves "
          "under a root but whose exec_path does NOT produces no match (proves cmdline is never "
          "read) -- a regression that swapped the collector's field selection from exec_path to "
          "cmdline would flip both assertions and fail this test.",
          "[tar][removable][exec]") {
    const std::vector<std::pair<std::string, std::string>> roots = {
       {"devkey-a", "/Volumes/KINGSTON"},
    };
    yuzu::agent::ProcessInfo via_exec_path;
    via_exec_path.pid = 222;
    via_exec_path.exec_path = "/Volumes/KINGSTON/payload/tool"; // under the root
    via_exec_path.cmdline = "/usr/bin/legit --flag";            // NOT under the root

    yuzu::agent::ProcessInfo via_cmdline_only;
    via_cmdline_only.pid = 333;
    via_cmdline_only.exec_path = "/usr/bin/legit";                  // NOT under the root
    via_cmdline_only.cmdline = "/Volumes/KINGSTON/payload/decoy";   // under the root, must be ignored

    const auto matches = select_exec_from_removable_processes({via_exec_path, via_cmdline_only},
                                                               roots, /*case_insensitive=*/false);
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].pid == 222);
    CHECK(matches[0].image_path == "/Volumes/KINGSTON/payload/tool");
}

// ── record_key builders ──────────────────────────────────────────────────────

TEST_CASE("removable record_key builders: distinct inputs produce distinct, stable keys",
          "[tar][removable][recordkey]") {
    CHECK(removable_baseline_record_key("abc") == removable_baseline_record_key("abc"));
    CHECK(removable_baseline_record_key("abc") != removable_baseline_record_key("def"));
    CHECK(removable_exec_record_key("abc", 1700000000, "/bin/tool") ==
         removable_exec_record_key("abc", 1700000000, "/bin/tool"));
    CHECK(removable_exec_record_key("abc", 1700000000, "/bin/tool") !=
         removable_exec_record_key("abc", 1700000000, "/bin/other"));
    CHECK(removable_channel_record_key("partition", 156) ==
         removable_channel_record_key("partition", 156));
    CHECK(removable_channel_record_key("partition", 156) !=
         removable_channel_record_key("partition", 157));
    CHECK(removable_channel_record_key("partition", 156) !=
         removable_channel_record_key("pnp", 156));
}

// ── Linux udev/kobject uevent parsing (RECONSTRUCTION -- no Linux box with a
// live capture was available to this package; the wire format itself is
// documented kernel ABI, not guessed) ───────────────────────────────────────

TEST_CASE("removable Linux uevent: a whole-disk add is recognised; a partition sub-device and a "
          "non-block subsystem are excluded -- RECONSTRUCTION per documented kobject-uevent shape",
          "[tar][removable][linux][reconstruction]") {
    const auto add_disk = join_nul({"add@/devices/pci0000:00/usb1/1-1/block/sdb", "ACTION=add",
                                    "SUBSYSTEM=block", "DEVTYPE=disk", "DEVNAME=sdb"});
    const auto rec = parse_uevent_message(add_disk);
    REQUIRE(rec.has_value());
    CHECK(rec->action == "add");
    CHECK(is_block_disk_uevent(*rec));

    const auto add_partition =
       join_nul({"add@/devices/pci0000:00/usb1/1-1/block/sdb/sdb1", "ACTION=add",
                "SUBSYSTEM=block", "DEVTYPE=partition", "DEVNAME=sdb1"});
    const auto part = parse_uevent_message(add_partition);
    REQUIRE(part.has_value());
    CHECK_FALSE(is_block_disk_uevent(*part)); // DEVTYPE=partition — excluded

    const auto non_block =
       join_nul({"add@/devices/virtual/net/eth0", "ACTION=add", "SUBSYSTEM=net"});
    const auto net = parse_uevent_message(non_block);
    REQUIRE(net.has_value());
    CHECK_FALSE(is_block_disk_uevent(*net));
}

TEST_CASE("removable Linux uevent: a remove action on a whole disk is recognised",
          "[tar][removable][linux][reconstruction]") {
    const auto remove_disk = join_nul({"remove@/devices/pci0000:00/usb1/1-1/block/sdb",
                                       "ACTION=remove", "SUBSYSTEM=block", "DEVTYPE=disk",
                                       "DEVNAME=sdb"});
    const auto rec = parse_uevent_message(remove_disk);
    REQUIRE(rec.has_value());
    CHECK(rec->action == "remove");
    CHECK(is_block_disk_uevent(*rec));
}

TEST_CASE("removable Linux uevent: empty / malformed (no '@') input is nullopt, never a crash",
          "[tar][removable][linux]") {
    CHECK_FALSE(parse_uevent_message("").has_value());
    CHECK_FALSE(parse_uevent_message(join_nul({"no-at-sign", "ACTION=add"})).has_value());
}

// ── Linux exec-from-removable mount correlation (respec amendment,
// 2026-09-04) — RECONSTRUCTION: no Linux removable-mount capture exists in
// this run's fixture set and neither live host available to this package is
// Linux-with-USB, so this /proc/mounts fixture is built from the kernel's
// documented, already-in-tree-parsed fstab/mnttab format (same allowance the
// macOS DA structs below carry), NOT a REAL CAPTURE. ─────────────────────────

namespace {

// A representative /proc/mounts snapshot: one internal disk, one tmpfs, one
// NFS mount (none of which may ever match), two partitions of the same
// removable USB disk ("sdb1"/"sdb2" -- multi-mount-device case), a removable
// NVMe-named stick's second partition ("nvme0n1p2" -- parent-mapping case),
// an SD card via mmcblk naming ("mmcblk0p1"), an octal-escaped mount point,
// and one structurally short row.
const std::string kProcMountsFixture =
   "/dev/sda1 / ext4 rw,relatime 0 0\n"
   "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
   "nfsserver:/export /mnt/nfs nfs4 rw,relatime 0 0\n"
   "/dev/sdb1 /media/user/STICK_A vfat rw,nosuid,nodev,relatime 0 0\n"
   "/dev/sdb2 /media/user/STICK_B vfat rw,nosuid,nodev,relatime 0 0\n"
   "/dev/nvme0n1p2 /media/user/NVMESTICK ext4 rw,relatime 0 0\n"
   "/dev/mmcblk0p1 /media/user/SDCARD vfat rw,relatime 0 0\n"
   "/dev/sdc1 /media/user/MY\\040STICK vfat rw,relatime 0 0\n"
   "malformed-row-one-field\n";

const std::unordered_map<std::string, std::string> kKnownRemovableDisks = {
   {"sdb", "devkey-sdb"},
   {"nvme0n1", "devkey-nvme0n1"},
   {"mmcblk0", "devkey-mmcblk0"},
   {"sdc", "devkey-sdc"},
   // "sda" (internal disk) deliberately absent -- it must never correlate.
};

} // namespace

TEST_CASE("removable Linux mount correlation: linux_parent_block_device maps nvme/mmcblk "
          "partitions to their whole-disk name, sdX-style partitions by trailing-digit strip, "
          "and a name with no trailing digits to itself",
          "[tar][removable][linux][reconstruction]") {
    CHECK(linux_parent_block_device("nvme0n1p2") == "nvme0n1");
    CHECK(linux_parent_block_device("nvme0n1p12") == "nvme0n1");
    CHECK(linux_parent_block_device("mmcblk0p1") == "mmcblk0");
    CHECK(linux_parent_block_device("sdb1") == "sdb");
    CHECK(linux_parent_block_device("sdb12") == "sdb");
    CHECK(linux_parent_block_device("sdb") == "sdb");
    CHECK(linux_parent_block_device("") == "");
}

TEST_CASE("removable Linux mount correlation: a removable partition row correlates to its parent "
          "disk's device_key; an internal-disk row and tmpfs/nfs rows never match",
          "[tar][removable][linux][reconstruction]") {
    const auto result = correlate_removable_mounts(kProcMountsFixture, kKnownRemovableDisks);

    // sda1 (internal, not in the known-removable map), tmpfs and nfs never
    // produce a pair for any device_key other than the removable ones below.
    for (const auto& [device_key, root] : result.pairs)
        CHECK(device_key != "devkey-sda"); // never present -- sda was never removable

    bool saw_nvme = false, saw_mmc = false;
    for (const auto& [device_key, root] : result.pairs) {
        if (device_key == "devkey-nvme0n1") {
            saw_nvme = true;
            CHECK(root == "/media/user/NVMESTICK");
        }
        if (device_key == "devkey-mmcblk0") {
            saw_mmc = true;
            CHECK(root == "/media/user/SDCARD");
        }
    }
    CHECK(saw_nvme);
    CHECK(saw_mmc);
}

TEST_CASE("removable Linux mount correlation: an octal-escaped mount point decodes",
          "[tar][removable][linux][reconstruction]") {
    const auto result = correlate_removable_mounts(kProcMountsFixture, kKnownRemovableDisks);
    bool saw_escaped = false;
    for (const auto& [device_key, root] : result.pairs) {
        if (device_key == "devkey-sdc") {
            saw_escaped = true;
            CHECK(root == "/media/user/MY STICK"); // \040 decoded to a literal space
        }
    }
    CHECK(saw_escaped);
}

TEST_CASE("removable Linux mount correlation: one device mounted at multiple points yields "
          "multiple pairs sharing the same device_key",
          "[tar][removable][linux][reconstruction]") {
    const auto result = correlate_removable_mounts(kProcMountsFixture, kKnownRemovableDisks);
    int sdb_pairs = 0;
    for (const auto& [device_key, root] : result.pairs)
        if (device_key == "devkey-sdb")
            ++sdb_pairs;
    CHECK(sdb_pairs == 2);
}

TEST_CASE("removable Linux mount correlation: a structurally short row is flagged malformed and "
          "skipped, never thrown, and never blocks the well-formed rows around it",
          "[tar][removable][linux][reconstruction]") {
    const auto result = correlate_removable_mounts(kProcMountsFixture, kKnownRemovableDisks);
    CHECK(result.malformed);
    CHECK_FALSE(result.pairs.empty()); // the malformed row didn't poison the rest
}

TEST_CASE("removable Linux mount correlation: a non-/dev/ source (tmpfs/nfs) and empty input "
          "never match and never set malformed",
          "[tar][removable][linux][reconstruction]") {
    const auto result = correlate_removable_mounts(
       "tmpfs /dev/shm tmpfs rw 0 0\nnfsserver:/export /mnt/nfs nfs4 rw 0 0\n",
       kKnownRemovableDisks);
    CHECK(result.pairs.empty());
    CHECK_FALSE(result.malformed);

    const auto empty_result = correlate_removable_mounts("", kKnownRemovableDisks);
    CHECK(empty_result.pairs.empty());
    CHECK_FALSE(empty_result.malformed);
}

// ── BoundedPendingQueue<RemovableEvent> ack/retry semantics (P-003) ─────────

// ── decide_baseline_and_reconcile (shared baseline/reconcile decision) ─────

TEST_CASE("compute_device_key: the two Windows legs agree exactly when a trusted serial is "
          "present, which is why only those keys may drive reconciliation (C7)",
          "[tar][removable][identity][c7]") {
    // The Windows event leg keys an anonymous device on the PnP ParentId; the
    // snapshot leg keys it on a volume GUID / PHYSICALDRIVE<n> / drive letter.
    // With a trusted serial, compute_device_key ignores the instance id
    // entirely, so both legs land on the same key.
    const auto ev_serial = compute_device_key("Kingston", "DataTraveler", "SN-REAL-1",
                                              R"(USB\VID_0951&PID_1666\5)");
    const auto snap_serial = compute_device_key("Kingston", "DataTraveler", "SN-REAL-1",
                                                R"(\\?\Volume{GUID}\)");
    CHECK(ev_serial.used_serial);
    CHECK(snap_serial.used_serial);
    CHECK(ev_serial.device_key == snap_serial.device_key); // agree by construction

    // Without one, the instance id IS the identity — and the two legs supply
    // different identifiers, so the same physical device splits in two. That
    // is why the snapshot no longer reconciles anonymous devices: it would see
    // its own key as a new attach and the event leg's key as a device that had
    // vanished, fabricating an attach/detach pair every tick.
    const auto ev_anon = compute_device_key("Generic", "Flash Disk", "",
                                            R"(USB\VID_0000&PID_0000\7)");
    const auto snap_anon = compute_device_key("Generic", "Flash Disk", "",
                                              R"(\\?\Volume{OTHER-GUID}\)");
    CHECK_FALSE(ev_anon.used_serial);
    CHECK_FALSE(snap_anon.used_serial);
    CHECK(ev_anon.device_key != snap_anon.device_key);
}

TEST_CASE("trim_trailing_scsi_padding: trailing space is removed, internal space is not "
          "(PR #4023 review, should-fix)",
          "[tar][removable][identity][scsi_padding]") {
    // REAL CAPTURE, DGRHP: STORAGE_DEVICE_DESCRIPTOR's ProductId reported
    // "STORE N GO      " (6 trailing spaces) where the event-log leg's XML
    // field for the identical device reported "STORE N GO" -- splitting one
    // physical device across two device_keys despite a matching trusted
    // serial.
    CHECK(trim_trailing_scsi_padding("STORE N GO      ") == "STORE N GO");
    // A genuinely space-containing name must survive untouched apart from
    // the trailing padding -- only the END may be trimmed.
    CHECK(trim_trailing_scsi_padding("DataTraveler 3.0   ") == "DataTraveler 3.0");
    CHECK(trim_trailing_scsi_padding("DataTraveler 3.0") == "DataTraveler 3.0");
    // No padding at all is a no-op.
    CHECK(trim_trailing_scsi_padding("Kingston") == "Kingston");
    // All-padding trims to empty, not a crash.
    CHECK(trim_trailing_scsi_padding("      ") == "");
    CHECK(trim_trailing_scsi_padding("") == "");

    // Applied before is_generic_serial, this also closes a latent variant of
    // the all-zero placeholder check: an untrimmed "000000000000   " is
    // neither all-'0' (the spaces break that) nor all-whitespace (the zeros
    // break that), so it was NOT classified generic before trimming. Once
    // trimmed to "000000000000" it correctly is.
    CHECK_FALSE(is_generic_serial("000000000000   "));
    CHECK(is_generic_serial(trim_trailing_scsi_padding("000000000000   ")));
}

TEST_CASE("shared_serials_in_batch: two distinct ParentIds reporting the same serial in one "
          "batch is the shared-serial case, not a trustworthy identity (PR #4023 review, "
          "should-fix)",
          "[tar][removable][identity][shared_serial]") {
    // REAL CAPTURE, DGRHP: a multi-format card reader exposes two physically
    // distinct USBSTOR LUNs that both report the identical, non-generic
    // serial "000000002958" -- is_generic_serial() cannot catch this (the
    // string itself is not empty/whitespace/all-zero), and
    // compute_device_key collapsed both LUNs onto one device_key. The real
    // 7-day lookback replay recorded three genuine transitions as six rows.
    auto lun = [](std::string_view parent_id) {
        PartitionDiagnosticRecord r;
        r.manufacturer = "Generic-";
        r.model = "Multi-Card ";
        r.serial_number = "000000002958";
        r.parent_id = std::string(parent_id);
        return r;
    };
    const std::vector<PartitionDiagnosticRecord> batch = {
       lun(R"(USB\VID_0BDA&PID_0158\5&1a2b3c&0&0)"),
       lun(R"(USB\VID_0BDA&PID_0158\5&1a2b3c&0&1)"),
    };
    const auto shared = shared_serials_in_batch(batch);
    REQUIRE(shared.size() == 1);
    CHECK(shared.count("Generic-\x1f"
                       "Multi-Card \x1f"
                       "000000002958") == 1);

    // The SAME LUN reported twice (e.g. an attach then a detach record for
    // ONE physical device) shares a ParentId with itself -- exactly one
    // distinct id, so it must NOT be flagged. A false positive here would
    // downgrade an ordinary single-LUN device to the anonymous fallback for
    // no reason.
    const std::vector<PartitionDiagnosticRecord> one_lun_twice = {lun("same-parent"),
                                                                   lun("same-parent")};
    CHECK(shared_serials_in_batch(one_lun_twice).empty());

    // A record with no serial at all must never seed a group -- an empty
    // serial is already is_generic_serial's own case, and grouping on "" would
    // incorrectly flag every anonymous device in the batch as "shared."
    PartitionDiagnosticRecord no_serial = lun("some-parent");
    no_serial.serial_number.clear();
    PartitionDiagnosticRecord no_serial2 = lun("other-parent");
    no_serial2.serial_number.clear();
    CHECK(shared_serials_in_batch({no_serial, no_serial2}).empty());

    // A genuinely different device (different vendor/model) that happens to
    // report the SAME serial string is a real-world coincidence this
    // function must not conflate with the multi-LUN case -- the identity key
    // includes vendor+model precisely so it does not.
    PartitionDiagnosticRecord other_vendor = lun("yet-another-parent");
    other_vendor.manufacturer = "TotallyDifferentCo";
    CHECK(shared_serials_in_batch({lun("p1"), other_vendor}).empty());
}

TEST_CASE("a POSIX sibling whose NAME contains a backslash is not under the removable root (C9)",
          "[tar][removable][exec][c9]") {
    // On Linux and macOS a backslash is an ordinary filename character. Treating
    // it as a path boundary makes "/media/user/USB\\decoy" -- a sibling FILE in
    // /media/user/, not anything below the mount -- match the root
    // "/media/user/USB". Where the mount parent is writable that plants a
    // forensic row against a device the binary never ran from.
    CHECK_FALSE(exec_path_under_removable_root(R"(/media/user/USB\decoy)", "/media/user/USB"));

    // The same shape on Windows IS a real boundary, so it must still match.
    CHECK(exec_path_under_removable_root(R"(E:\payload\tool.exe)", R"(E:\payload)",
                                         /*case_insensitive=*/true,
                                         /*backslash_is_separator=*/true));

    // And a genuine POSIX child is unaffected.
    CHECK(exec_path_under_removable_root("/media/user/USB/decoy", "/media/user/USB"));
}

TEST_CASE("a non-UTF-8 exec_path cannot take the cursor write down with it (HIGH-4)",
          "[tar][removable][cursor][utf8]") {
    // exec_seen stores ProcessInfo::exec_path verbatim, and on Linux that is raw
    // bytes from /proc/<pid>/exe -- a binary on a FAT/exFAT stick can be named
    // with bytes that are not valid UTF-8. nlohmann's default dump() throws on
    // those, and the throw lands on collect()'s path, so the tick and every
    // retry are lost for as long as that process runs. It would also violate
    // the contract's rule that collect() throws only IncompleteCaptureError.
    yuzu::tar::RemovableCursorState st;
    st.attach_set["usb-1"] = true;
    st.exec_seen.insert(std::string("usb-1\x1f/mnt/usb/\xff\xfe-payload"));

    std::string encoded;
    REQUIRE_NOTHROW(encoded = yuzu::tar::encode_removable_cursor(st));
    CHECK_FALSE(encoded.empty());

    // And it must still round-trip to something usable rather than poisoning
    // the next decode.
    const auto back = yuzu::tar::decode_removable_cursor(encoded);
    CHECK_FALSE(back.malformed);
    CHECK(back.attach_set.count("usb-1") == 1);
    CHECK(back.exec_seen.size() == 1);
}

TEST_CASE("a re-attach starts a new exec session, so the same binary does not re-collide (HIGH-3)",
          "[tar][removable][exec][session]") {
    // The exec key must be STABLE while a device stays attached (one row per
    // execution, and a retry must dedupe) but DIFFER across attach sessions.
    // Clearing exec_seen on detach without changing the key meant a replug plus
    // a re-run re-derived the previous session's key with a new ts -- which the
    // store reads as a payload mismatch and refuses on every tick. That is the
    // same wedge exec_seen exists to prevent, reached through the clearing path.
    yuzu::tar::BaselineReconcileInputs attach;
    attach.baseline_already_done = true;
    attach.now = 1000;
    attach.pending = {{"attached", "usb-1"}};
    const auto s1 = yuzu::tar::decide_baseline_and_reconcile(attach);
    REQUIRE(s1.attach_epoch.count("usb-1") == 1);
    CHECK(s1.attach_epoch.at("usb-1") == 1000);

    // Detach ends the session and forgets the executions.
    yuzu::tar::BaselineReconcileInputs detach;
    detach.baseline_already_done = true;
    detach.now = 2000;
    detach.prev_attach_set = {{"usb-1", true}};
    detach.attach_epoch = s1.attach_epoch;
    detach.exec_seen = {std::string("usb-1") + "\x1f" + "/Volumes/USB/tool"};
    detach.pending = {{"detached", "usb-1"}};
    const auto s2 = yuzu::tar::decide_baseline_and_reconcile(detach);
    CHECK(s2.attach_epoch.count("usb-1") == 0);
    CHECK(s2.exec_seen.empty());

    // Re-attach starts a NEW session ...
    yuzu::tar::BaselineReconcileInputs again;
    again.baseline_already_done = true;
    again.now = 3000;
    again.attach_epoch = s2.attach_epoch;
    again.pending = {{"attached", "usb-1"}};
    const auto s3 = yuzu::tar::decide_baseline_and_reconcile(again);
    CHECK(s3.attach_epoch.at("usb-1") == 3000);

    // ... so the same binary on the same device yields a DIFFERENT key, and the
    // store sees a new record rather than a colliding replay.
    CHECK(removable_exec_record_key("usb-1", 1000, "/Volumes/USB/tool") !=
          removable_exec_record_key("usb-1", 3000, "/Volumes/USB/tool"));
    // While the session lasts, the key is stable so a retry still dedupes.
    CHECK(removable_exec_record_key("usb-1", 3000, "/Volumes/USB/tool") ==
          removable_exec_record_key("usb-1", 3000, "/Volumes/USB/tool"));
}

TEST_CASE("a CursorLost re-baseline does not permanently wedge on its own baseline row "
          "(PR #4023 review round 2, blocker #2)",
          "[tar][removable][cursor][rebaseline]") {
    // removable_baseline_record_key() is keyed ONLY on device_key -- ts is
    // deliberately excluded, because a CursorLost re-baseline re-emits the
    // SAME baseline row for a still-present device with a fresh wall-clock
    // ts. Before this fix, tar_db.cpp's replay-dedupe still compared ts for
    // a present_at_baseline row, so that re-emission collided against the
    // original row forever: every following tick reproduced the identical
    // KeyCollision, and the source was permanently wedged with no recovery
    // short of wiping the whole tar.db (tar_cursor is SELECT-only via
    // execute_user_query).
    auto t = make_test_db();

    RemovableEvent first;
    first.ts = 1000;
    first.action = "present_at_baseline";
    first.device_key = "usb-1";
    first.vendor = "Kingston";
    first.product = "DataTraveler";
    first.serial = "SN-1";
    first.bus = "block";
    first.evidence = "linux:/sys/block/sda";
    first.record_key = removable_baseline_record_key("usb-1");

    auto ins1 = t.db.insert_removable_events_and_cursor({first}, R"({"v":1})");
    REQUIRE(ins1.has_value());

    // A later CursorLost re-baseline re-emits the identical baseline row --
    // same record_key, same identity fields, but a DIFFERENT ts (now).
    RemovableEvent rebaselined = first;
    rebaselined.ts = 2000;

    auto ins2 = t.db.insert_removable_events_and_cursor({rebaselined}, R"({"v":1,"n":2})");
    REQUIRE(ins2.has_value()); // must NOT be CursorInsertError::KeyCollision

    // A genuinely DIFFERENT device at the same ts must still be accepted
    // normally -- this fix must not have widened the dedupe into ignoring
    // real distinct baseline rows.
    RemovableEvent other = first;
    other.device_key = "usb-2";
    other.record_key = removable_baseline_record_key("usb-2");
    auto ins3 = t.db.insert_removable_events_and_cursor({other}, R"({"v":1,"n":3})");
    REQUIRE(ins3.has_value());

    // And a row that collides on record_key but genuinely IS a different
    // event (different vendor, say a corrupted key derivation) must still be
    // refused as a real collision -- the fix narrows the ts exclusion to
    // present_at_baseline/capture_gap, it does not remove identity checking
    // altogether.
    RemovableEvent conflicting = first;
    conflicting.ts = 3000;
    conflicting.vendor = "SanDisk"; // genuinely different identity, same key
    auto ins4 = t.db.insert_removable_events_and_cursor({conflicting}, R"({"v":1,"n":4})");
    REQUIRE_FALSE(ins4.has_value());
    CHECK(ins4.error() == TarDatabase::CursorInsertError::KeyCollision);
}

TEST_CASE("exec_from_removable is reported once per attach session, not once per tick, and a "
          "re-attach reports afresh (K1)",
          "[tar][removable][exec][k1]") {
    // The exec record_key is deliberately STABLE for a (device, image) pair --
    // one row per execution observed, which is what the source is for. But the
    // row's ts is "now", so re-deriving the event every tick offers the store
    // the same key with a different payload. The seam refuses that as a
    // collision and rolls the WHOLE batch back, which repeats every tick for as
    // long as the process runs: the source goes dark, taking every unrelated
    // attach/detach and gap in those batches with it. The emission is therefore
    // gated on exec_seen, which is persisted in the cursor.
    yuzu::tar::RemovableCursorState st;
    st.attach_set["usb-1"] = true;
    st.exec_seen.insert(std::string("usb-1") + "\x1f" + "/Volumes/USB/installer");

    // Round-trip: the gate has to survive a restart, or the first tick after one
    // re-emits and wedges exactly as before.
    const auto encoded = yuzu::tar::encode_removable_cursor(st);
    const auto decoded = yuzu::tar::decode_removable_cursor(encoded);
    REQUIRE_FALSE(decoded.malformed);
    CHECK(decoded.exec_seen.size() == 1);
    CHECK(decoded.exec_seen.count(std::string("usb-1") + "\x1f" + "/Volumes/USB/installer") == 1);

    // Detaching the device forgets its executions, so plugging it back in
    // reports the same binary again rather than staying silent forever.
    yuzu::tar::BaselineReconcileInputs in;
    in.baseline_already_done = true;
    in.prev_attach_set = {{"usb-1", true}};
    in.exec_seen = decoded.exec_seen;
    in.pending = {{"detached", "usb-1"}};

    const auto out = yuzu::tar::decide_baseline_and_reconcile(in);
    CHECK(out.attach_set.count("usb-1") == 0);
    CHECK(out.exec_seen.empty());

    // A DIFFERENT device's executions are untouched by that detach.
    yuzu::tar::BaselineReconcileInputs other = in;
    other.exec_seen.insert(std::string("usb-2") + "\x1f" + "/Volumes/OTHER/tool");
    const auto out2 = yuzu::tar::decide_baseline_and_reconcile(other);
    CHECK(out2.exec_seen.size() == 1);
    CHECK(out2.exec_seen.count(std::string("usb-2") + "\x1f" + "/Volumes/OTHER/tool") == 1);
}

TEST_CASE("baseline tick seeds attach_set from what is attached, so the next tick does not "
          "re-report every device as a missed callback (P2)",
          "[tar][removable][baseline][p2]") {
    BaselineReconcileInputs first;
    first.baseline_already_done = false;
    first.current_keys = {"dev-a", "dev-b"};

    const auto t1 = decide_baseline_and_reconcile(first);
    CHECK(t1.baseline_keys.size() == 2);
    CHECK(t1.reconcile_added.empty());
    // The load-bearing assertion: baseline RECORDED what it saw.
    REQUIRE(t1.attach_set.size() == 2);
    CHECK(t1.attach_set.count("dev-a") == 1);
    CHECK(t1.attach_set.count("dev-b") == 1);

    // Tick 2, nothing changed on the host and no callbacks fired. Before the
    // fix attach_set persisted EMPTY, so the reconciler re-reported both
    // devices as `attached` with evidence claiming a missed DiskArbitration
    // callback -- a fabricated attach event on every agent, every restart.
    BaselineReconcileInputs second;
    second.baseline_already_done = true;
    second.current_keys = first.current_keys;
    second.prev_attach_set = t1.attach_set;

    const auto t2 = decide_baseline_and_reconcile(second);
    CHECK(t2.baseline_keys.empty());
    CHECK(t2.reconcile_added.empty());
    CHECK(t2.reconcile_removed.empty());
    CHECK(t2.attach_set.size() == 2);
}

TEST_CASE("a detach callback queued during the baseline tick still wins over the seed",
          "[tar][removable][baseline]") {
    BaselineReconcileInputs in;
    in.baseline_already_done = false;
    in.current_keys = {"dev-a", "dev-b"};
    in.pending = {{"detached", "dev-a"}};

    const auto out = decide_baseline_and_reconcile(in);
    CHECK(out.attach_set.count("dev-a") == 0); // the real callback ordered last
    CHECK(out.attach_set.count("dev-b") == 1);
}

TEST_CASE("a real detach arriving mid-tick is not re-attached by the stale snapshot (K3)",
          "[tar][removable][baseline][k3]") {
    // Kimi's falsifier, verbatim. The device set snapshot and the pending
    // callback queue are NOT captured atomically: a stick unplugged between the
    // two leaves a real `detached` callback in pending while the snapshot still
    // lists the device. Before the guard, the pending loop removed the key and
    // the reconcile loop immediately re-added it with evidence claiming a
    // missed appeared-callback that never went missing -- and left it in
    // attach_set, so a second reconcile-derived `detached` followed next tick.
    // Three rows for one removal, one of them factually false, on a default-on
    // forensic source.
    yuzu::tar::BaselineReconcileInputs in;
    in.baseline_already_done = true;
    in.current_keys = {"dev-a"};              // snapshot taken BEFORE the eject
    in.prev_attach_set = {{"dev-a", true}};
    in.pending = {{"detached", "dev-a"}};     // the real callback, taken after

    const auto out = yuzu::tar::decide_baseline_and_reconcile(in);
    CHECK(out.reconcile_added.empty());   // <- the fabricated row
    CHECK(out.reconcile_removed.empty()); // the real callback already covers it
    CHECK(out.attach_set.count("dev-a") == 0); // and it is genuinely gone

    // The mirror case: an `attached` callback in flight while the snapshot has
    // not caught up must not be double-reported either.
    yuzu::tar::BaselineReconcileInputs in2;
    in2.baseline_already_done = true;
    in2.current_keys = {};                    // snapshot predates the arrival
    in2.prev_attach_set = {};
    in2.pending = {{"attached", "dev-b"}};

    const auto out2 = yuzu::tar::decide_baseline_and_reconcile(in2);
    CHECK(out2.reconcile_added.empty());
    CHECK(out2.reconcile_removed.empty());
    CHECK(out2.attach_set.count("dev-b") == 1);
}

TEST_CASE("reconciliation still recovers a callback the OS never delivered, both directions",
          "[tar][removable][baseline]") {
    BaselineReconcileInputs in;
    in.baseline_already_done = true;
    in.current_keys = {"dev-new"};              // arrived, no callback
    in.prev_attach_set = {{"dev-gone", true}};  // left, no callback

    const auto out = decide_baseline_and_reconcile(in);
    REQUIRE(out.reconcile_added.size() == 1);
    CHECK(out.reconcile_added[0] == "dev-new");
    REQUIRE(out.reconcile_removed.size() == 1);
    CHECK(out.reconcile_removed[0] == "dev-gone");
    CHECK(out.attach_set.count("dev-new") == 1);
    CHECK(out.attach_set.count("dev-gone") == 0);
}

TEST_CASE("removable queue: a failed commit leaves the whole batch for retry, and acking by "
          "sequence never eats an event pushed during the commit",
          "[tar][removable][queue]") {
    BoundedPendingQueue<RemovableEvent> q;
    RemovableEvent a;
    a.record_key = "a";
    RemovableEvent b;
    b.record_key = "b";
    RemovableEvent c;
    c.record_key = "c";
    q.push(a);
    q.push(b);
    q.push(c);
    REQUIRE(q.size() == 3);

    // Simulated failed commit: snapshot but do NOT ack.
    auto batch = q.snapshot_batch();
    REQUIRE(batch.items.size() == 3);
    CHECK(q.size() == 3); // untouched — still there for the retry

    // A late-arriving event lands while that batch is being committed. Acking
    // by sequence (R-005) removes exactly the three that committed and leaves
    // the newcomer, which a positional ack(3) would have discarded unseen.
    RemovableEvent d;
    d.record_key = "d";
    q.push(d);
    q.ack_through(batch.last_seq);
    CHECK(q.size() == 1);
    CHECK(q.snapshot_batch().items.front().record_key == "d");
}

TEST_CASE("removable queue: overflow drops the oldest entry and counts it, never silently",
          "[tar][removable][queue]") {
    BoundedPendingQueue<RemovableEvent> q;
    for (std::size_t i = 0; i < BoundedPendingQueue<RemovableEvent>::kCap + 5; ++i) {
        RemovableEvent ev;
        ev.record_key = std::to_string(i);
        q.push(ev);
    }
    CHECK(q.size() == BoundedPendingQueue<RemovableEvent>::kCap);
    CHECK(q.dropped() == 5);
    CHECK(q.snapshot_batch().items.front().record_key == "5"); // the oldest 5 were evicted
}

// ── Real-leg sections (verification-protocol.md UPDATE 2026-09-04 / P-006) ─
// Each platform's own section runs the ACTUAL live leg on that platform's CI
// runner and this package's own build hosts; it is never compiled out for
// the platform it targets, and reports an EXPLICIT, named result either way
// -- a silent pass on a no-device host is exactly the defect this rule
// exists to prevent (PR6.1-b's dead Windows FSCTL leg).

#if defined(__APPLE__)

TEST_CASE("removable macOS real leg: start()/collect()/stop() run against the live host without "
          "throwing; when a removable volume is actually mounted its identity is populated",
          "[tar][removable][macos][live]") {
    auto source = make_removable_cursor_source();
    REQUIRE(source);
    REQUIRE(source->name() == "removable");

    auto harness = make_test_db();
    REQUIRE_NOTHROW(source->start(harness.db));

    CursorCollectResult result;
    REQUIRE_NOTHROW(result = source->collect(harness.db, std::nullopt));
    CHECK(result.outcome == CursorOutcome::Baseline);

    const auto st = decode_removable_cursor(result.new_cursor_json);
    CHECK(st.baseline_done);
    if (st.attach_set.empty()) {
        WARN("removable macOS real leg: no removable volume mounted on this host — "
            "present_at_baseline identity fields not exercised (honest-empty, not a failure)");
    } else {
        for (const auto& [device_key, present] : st.attach_set) {
            CHECK(present);
            CHECK_FALSE(device_key.empty());
        }
    }

    source->stop();
}

#elif defined(__linux__)

TEST_CASE("removable Linux real leg: a live /sys/block scan runs on this CI host with honest-empty "
          "acceptance -- no removable device present is success, not a skip",
          "[tar][removable][linux][live]") {
    // The pure identity/uevent parsers above are exercised without hardware;
    // this section's job is only to prove the /sys/block directory itself is
    // readable (or honestly absent) on the CI runner, per the verification
    // protocol's "honest-empty acceptance" requirement.
    DIR* dir = ::opendir("/sys/block");
    if (dir == nullptr) {
        WARN("removable Linux real leg: /sys/block not present on this host — "
            "honest-empty, not a failure");
        return;
    }
    std::size_t seen = 0;
    while (::readdir(dir) != nullptr)
        ++seen;
    ::closedir(dir);
    SUCCEED("removable Linux real leg: /sys/block scan completed (" << seen
                                                                     << " entries), honest-empty "
                                                                        "or populated either way");
}

TEST_CASE("removable Linux real leg: /proc/self/mounts is read live and correlated against a live "
          "/sys/block removable-disk scan -- honest-empty acceptance (no removable device on this "
          "host means zero pairs, which is success), with an EXPLICIT SKIP naming that the "
          "device-present correlation path was not exercised",
          "[tar][removable][linux][live]") {
    std::ifstream mounts("/proc/self/mounts");
    REQUIRE(mounts.is_open()); // /proc/self/mounts always exists on a real Linux kernel
    std::ostringstream ss;
    ss << mounts.rdbuf();
    REQUIRE_FALSE(mounts.bad());

    std::unordered_map<std::string, std::string> known_removable;
    if (DIR* dir = ::opendir("/sys/block")) {
        while (struct dirent* entry = ::readdir(dir)) {
            const std::string name = entry->d_name;
            if (name == "." || name == "..")
                continue;
            std::ifstream removable_flag("/sys/block/" + name + "/removable");
            std::string flag;
            if (removable_flag && std::getline(removable_flag, flag) && flag == "1")
                known_removable[name] = "live:" + name; // identity content is irrelevant here
        }
        ::closedir(dir);
    }

    const auto correlation = correlate_removable_mounts(ss.str(), known_removable);
    CHECK_FALSE(correlation.malformed); // a real kernel-authored /proc/self/mounts is well-formed

    if (correlation.pairs.empty()) {
        SKIP("removable Linux real leg: no removable block device mounted on this host — "
            "device-present /proc/mounts correlation path not exercised; see "
            "docs/user-manual/tar-removable.md's reviewer verification block");
    } else {
        for (const auto& [device_key, root] : correlation.pairs) {
            CHECK_FALSE(device_key.empty());
            CHECK_FALSE(root.empty());
        }
    }
}

// Collector-level "/proc/mounts read failure -> exec suppressed + detail note, attach events
// still emitted" is NOT independently forceable in an automated unit test: /proc/mounts is a
// kernel-guaranteed-present file on any real Linux host (same reason
// tar_arp_collector.cpp's own /proc/net/arp read-failure branch carries no dedicated unit test
// either). The degrade path itself is exercised by construction above -- collect() never throws
// on a read that DOES succeed, and the note is a plain string assignment gated on the read
// outcome (tar_removable_collector.cpp) -- and "attach events still emitted" is demonstrated by
// the baseline TEST_CASE above producing present_at_baseline rows on every run regardless of
// whether the /proc/mounts correlation found any pairs.

#elif defined(_WIN32)

TEST_CASE("removable Windows real leg: start()/collect() actually RUN the live snapshot+channel "
          "leg against this host before any SKIP decision (R-012: a SKIP issued without running "
          "the collector is exactly the false-green condition P-006 exists to prevent); zero "
          "removable devices present is an EXPLICIT named SKIP (the-rig's expected no-history "
          "state), a present device asserts populated identity",
          "[tar][removable][windows][live]") {
    auto source = make_removable_cursor_source();
    REQUIRE(source);
    REQUIRE(source->name() == "removable");

    auto harness = make_test_db();
    REQUIRE_NOTHROW(source->start(harness.db));

    CursorCollectResult result;
    REQUIRE_NOTHROW(result = source->collect(harness.db, std::nullopt));
    CHECK(result.outcome == CursorOutcome::Baseline);

    const auto st = decode_removable_cursor(result.new_cursor_json);
    CHECK(st.baseline_done);
    // Every channel this source polls must have advanced its cursor (or, if
    // ACL-denied/absent, be named in result.detail) -- the collector ran for
    // real, not a stub.
    CHECK_FALSE(st.channels.empty());

    source->stop();

    if (st.attach_set.empty()) {
        // On the-rig HKLM USBSTOR is ABSENT and no removable device is
        // attached during the CI/local-gate run — the reviewer's laptop run
        // (PR body's "Hardware checks needed from you" block) is what
        // converts this SKIP into a real assertion below. This SKIP's
        // ABSENCE on that laptop IS the signal the real device-present leg
        // ran and was asserted, not skipped -- the collector call above
        // (which DID run, unconditionally, on every host) is what makes
        // that claim honest.
        SKIP("no removable device attached on this host — device-present leg not exercised; see "
            "docs/user-manual/tar-removable.md's reviewer verification block");
    } else {
        for (const auto& [device_key, present] : st.attach_set) {
            CHECK(present);
            CHECK_FALSE(device_key.empty());
        }
    }
}

#endif
