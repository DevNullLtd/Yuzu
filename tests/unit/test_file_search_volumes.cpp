/**
 * test_file_search_volumes.cpp -- the volume plan, the fsv1 cursor and its transition rule of the
 * on-demand file search plugin (agents/plugins/file_search/src/file_search_volumes.hpp). Pure: a mount
 * table is parsed from text and planned; nothing opens a path.
 *
 * MUTATION NOTES (each case FAILS if the named production rule is removed):
 *  - order: sorting units any other way, or not putting the mount that contains the root first, fails the
 *    first case; the walk root of the containing unit being its mount point (not the root) fails the
 *    below-its-mount case.
 *  - prune sets: including an ancestor, omitting a nested mount, or a prefix test that is not on a
 *    component boundary (/home2 under /home) fails the nested and boundary cases.
 *  - refusals: a fstype reason mapped to the wrong token, or a refused type becoming a unit, fails the
 *    refusal table.
 *  - identity: comparing the label alone (btrfs subvolumes, a self-bind) makes a second unit a duplicate
 *    and fails those cases; comparing the root alone, or never deduplicating, fails the duplicate case;
 *    keeping the first twin instead of the one that contains the root fails the second duplicate case.
 *  - behind a network mount: a unit beneath a network mount becoming a unit, or a unit beneath a tmpfs
 *    becoming a refused row, fails the pair.
 *  - private /tmp: not recognising the service manager's per-service directory fails the private case.
 *  - macOS: reporting the data volume as a duplicate instead of firmlinks_only, or applying the rule to a
 *    root below "/", fails the macOS cases.
 *  - caps: dropping units without counting them, or leaving a dropped mount out of a prune set, fails the
 *    cap case.
 *  - hashes: the units hash covering a refused row, or the refused hash ignoring one, fails the hash case.
 *  - fsv1: accepting a non-canonical spelling (leading zero, sign, uppercase or short hash, an index of
 *    kMaxVolumes, a dot in the inner token) fails the refusal table; decoding without the query check
 *    fails the foreign-query refusal.
 *  - volume_advances: accepting a skipped index, a changed units hash, a backward sequence, a stale
 *    position or a changed generation on the move to the next unit fails the transition table; refusing a
 *    changed refused hash fails the accepting case.
 */
#include <catch2/catch_test_macros.hpp>

#include "file_search_volumes.hpp"

#include <file_search_cursor.hpp>
#include <network_fstype.hpp>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::file_search;
namespace fsr = yuzu::shared::file_search;

namespace {

/// A /proc/self/mountinfo table built a line at a time.
struct Mounts {
    std::string text;
    int id{1};
    Mounts& add(const std::string& mp, const std::string& fstype, const std::string& label = "8:1",
                const std::string& root = "/", const std::string& source = "/dev/x") {
        text += std::to_string(id++) + " 1 " + label + " " + root + " " + mp + " rw - " + fstype + " " + source + " rw\n";
        return *this;
    }
    [[nodiscard]] yuzu::shared::MountTable table() const { return yuzu::shared::mount_entries(text); }
};

std::vector<std::string> mount_points(const VolumePlan& p) {
    std::vector<std::string> v;
    for (const auto& u : p.units)
        v.push_back(u.mount_point);
    return v;
}

using Strs = std::vector<std::string>;

const Refused* refused_at(const VolumePlan& p, const std::string& mp) {
    for (const auto& r : p.refused)
        if (r.mount_point == mp)
            return &r;
    return nullptr;
}

fsr::Reason reason_at(const VolumePlan& p, const std::string& mp) {
    const Refused* r = refused_at(p, mp);
    REQUIRE(r != nullptr);
    return r->reason;
}

const Unit& unit_at(const VolumePlan& p, const std::string& mp) {
    for (const auto& u : p.units)
        if (u.mount_point == mp)
            return u;
    FAIL("no unit at " << mp);
    return p.units.front();
}

} // namespace

TEST_CASE("file_search volumes: allow-listed mounts become units in byte order, the mount containing the root first",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/home", "ext4", "8:2").add("/", "ext4", "8:1").add("/data", "xfs", "8:3");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    REQUIRE(p.valid);
    CHECK(mount_points(p) == Strs{"/", "/data", "/home"});
    CHECK(p.units[0].walk_root == "/");
    CHECK(p.units[1].walk_root == "/data"); // another unit is walked from its own mount point
    CHECK(p.refused.empty());
    CHECK(p.volumes_dropped == 0);
    CHECK(p.units_hash.size() == 16);

    // a root deep below a mount: the mount containing it is the only unit, whatever else is mounted
    Mounts n;
    n.add("/a", "ext4", "8:2").add("/", "ext4", "8:1").add("/b/c", "ext4", "8:3");
    const VolumePlan q = build_plan(n.table(), "/b/c/sub", Os::linux_os);
    CHECK(mount_points(q) == Strs{"/b/c"});
}

TEST_CASE("file_search volumes: a root below its mount point is one unit walked from the root, no ancestor pruned",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1").add("/home", "ext4", "8:2");
    const VolumePlan p = build_plan(m.table(), "/home/u", Os::linux_os);
    REQUIRE(p.valid);
    REQUIRE(p.units.size() == 1);
    CHECK(p.units[0].mount_point == "/home");
    CHECK(p.units[0].walk_root == "/home/u");
    CHECK(p.units[0].prune.empty()); // "/" and "/home" are ancestors: never in a prune set
    CHECK(p.refused.empty());        // an ancestor that is not the containing mount is not reported
}

TEST_CASE("file_search volumes: nested units are three units, each pruning only what is below it",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1").add("/home", "ext4", "8:2").add("/home/u/data", "ext4", "8:3");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    REQUIRE(p.units.size() == 3);
    CHECK(unit_at(p, "/").prune == Strs{"/home", "/home/u/data"});
    CHECK(unit_at(p, "/home").prune == Strs{"/home/u/data"});
    CHECK(unit_at(p, "/home/u/data").prune.empty());
}

TEST_CASE("file_search volumes: a prefix test is on a component boundary in the plan, the prune set and the join",
          "[file_search][file_search_volumes]") {
    CHECK(under("/home/x", "/home"));
    CHECK(under("/home", "/home"));
    CHECK_FALSE(under("/home2", "/home"));
    CHECK_FALSE(under("/home2/x", "/home"));
    CHECK(under("/anything", "/"));
    CHECK_FALSE(strictly_under("/home", "/home"));

    Mounts m;
    m.add("/", "ext4", "8:1").add("/home", "ext4", "8:2").add("/home2", "ext4", "8:3");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    REQUIRE(p.units.size() == 3);
    CHECK(unit_at(p, "/home").prune.empty()); // /home2 is not below /home
    CHECK(unit_at(p, "/").prune == Strs{"/home", "/home2"});
    const auto idx = [&](const std::string& mp) {
        for (std::size_t i = 0; i < p.units.size(); ++i)
            if (p.units[i].mount_point == mp)
                return i;
        return std::size_t{999};
    };
    CHECK(volume_for(p, "/home2/f") == idx("/home2"));
    CHECK(volume_for(p, "/home/f") == idx("/home"));  // personal-data-ok: synthetic test path
    CHECK(volume_for(p, "/homeX") == idx("/")); // a name that merely starts with a mount point
    CHECK(volume_for(p, "/home") == idx("/home"));

    // a root /home does not take /home2 into scope
    const VolumePlan q = build_plan(m.table(), "/home", Os::linux_os);
    CHECK(mount_points(q) == Strs{"/home"});
    CHECK(q.refused.empty());
}

TEST_CASE("file_search volumes: network, pseudo, overlay, tmpfs and vfat mounts are refused with the right reason",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1")
        .add("/mnt/nfs", "nfs4", "0:40", "/", "srv:/x")
        .add("/mnt/ssh", "fuse.sshfs", "0:41", "/", "u@h:/")
        .add("/proc", "proc", "0:5", "/", "proc")
        .add("/mnt/ov", "overlay", "0:6", "/", "overlay")
        .add("/mnt/tmp", "tmpfs", "0:7", "/", "tmpfs")
        .add("/mnt/usb", "vfat", "8:9", "/", "/dev/sdb1");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    CHECK(mount_points(p) == Strs{"/"});
    REQUIRE(p.refused.size() == 6);
    CHECK(reason_at(p, "/mnt/nfs") == fsr::Reason::network_mount);
    CHECK(reason_at(p, "/mnt/ssh") == fsr::Reason::network_mount);
    CHECK(reason_at(p, "/proc") == fsr::Reason::fstype_not_allowed);
    CHECK(reason_at(p, "/mnt/ov") == fsr::Reason::fstype_not_allowed);
    CHECK(reason_at(p, "/mnt/tmp") == fsr::Reason::fstype_not_allowed);
    CHECK(reason_at(p, "/mnt/usb") == fsr::Reason::fstype_not_allowed);
    CHECK(refused_at(p, "/mnt/usb")->fstype == "vfat");
    // every refused mount is still pruned from the unit that contains it
    CHECK(unit_at(p, "/").prune.size() == 6);
    // refused rows are in mount-point byte order
    CHECK(std::ranges::is_sorted(p.refused, {}, &Refused::mount_point));
}

TEST_CASE("file_search volumes: btrfs subvolume mounts share a label and are two units",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "btrfs", "0:30", "/@").add("/home", "btrfs", "0:30", "/@home");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    CHECK(mount_points(p) == Strs{"/", "/home"});
    CHECK(p.refused.empty()); // no duplicate_mount: the roots differ
}

TEST_CASE("file_search volumes: a self-bind is its own unit and sits in its parent's prune set",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1", "/").add("/srv/data", "ext4", "8:1", "/srv/data");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    CHECK(mount_points(p) == Strs{"/", "/srv/data"});
    CHECK(unit_at(p, "/").prune == Strs{"/srv/data"});
    CHECK(p.refused.empty());
}

TEST_CASE("file_search volumes: equal label and root at two mount points is one unit and one duplicate_mount",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1").add("/mnt/a", "ext4", "8:5").add("/mnt/b", "ext4", "8:5");
    const VolumePlan p = build_plan(m.table(), "/mnt", Os::linux_os);
    CHECK(mount_points(p) == Strs{"/", "/mnt/a"}); // the first of the twins by mount point stays
    CHECK(reason_at(p, "/mnt/b") == fsr::Reason::duplicate_mount);
    // the duplicate is still pruned: it is a mount, and reported once
    CHECK(unit_at(p, "/").prune == Strs{"/mnt/a", "/mnt/b"});

    // the mount containing the root is the one kept
    const VolumePlan q = build_plan(m.table(), "/mnt/b/x", Os::linux_os);
    CHECK(mount_points(q) == Strs{"/mnt/b"});
    CHECK(q.units[0].walk_root == "/mnt/b/x");
    CHECK(q.refused.empty()); // /mnt/a is not in scope of /mnt/b/x
    const VolumePlan r = build_plan(m.table(), "/mnt/b", Os::linux_os);
    CHECK(mount_points(r) == Strs{"/mnt/b"});
    const VolumePlan s = build_plan(m.table(), "/mnt", Os::linux_os);
    CHECK(s.refused.size() == 1);
}

TEST_CASE("file_search volumes: a disk beneath a network mount is behind it, one beneath a tmpfs is a unit",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1")
        .add("/mnt/nfs", "nfs4", "0:40", "/", "srv:/x")
        .add("/mnt/nfs/disk", "ext4", "8:2")
        .add("/mnt/t", "tmpfs", "0:7", "/", "tmpfs")
        .add("/mnt/t/disk", "ext4", "8:3");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    CHECK(mount_points(p) == Strs{"/", "/mnt/t/disk"});
    CHECK(reason_at(p, "/mnt/nfs") == fsr::Reason::network_mount);
    CHECK(reason_at(p, "/mnt/nfs/disk") == fsr::Reason::behind_network_mount);
    CHECK(reason_at(p, "/mnt/t") == fsr::Reason::fstype_not_allowed);
    // the tmpfs is an ancestor of the disk, never in the disk's prune set: the walk can cross it
    CHECK(unit_at(p, "/mnt/t/disk").prune.empty());
    CHECK(unit_at(p, "/").prune.size() == 4);

    // the root's own filesystem is behind a network mount
    Mounts n;
    n.add("/", "ext4", "8:1").add("/mnt/nfs", "nfs4", "0:40", "/", "srv:/x").add("/mnt/nfs/disk", "ext4", "8:2");
    const VolumePlan q = build_plan(n.table(), "/mnt/nfs/disk/x", Os::linux_os);
    CHECK(q.units.empty());
    CHECK(reason_at(q, "/mnt/nfs/disk") == fsr::Reason::behind_network_mount);
}

TEST_CASE("file_search volumes: a /tmp bind from a private namespace is refused as private_namespace",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1")
        .add("/tmp", "ext4", "8:1", "/tmp/systemd-private-abc-foo.service-xyz/tmp")
        .add("/var/tmp", "ext4", "8:1", "/var/tmp/systemd-private-abc-foo.service-xyz/tmp");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    CHECK(mount_points(p) == Strs{"/"});
    CHECK(reason_at(p, "/tmp") == fsr::Reason::private_namespace);
    CHECK(reason_at(p, "/var/tmp") == fsr::Reason::private_namespace);

    // an ordinary separate /tmp filesystem is a unit
    Mounts n;
    n.add("/", "ext4", "8:1").add("/tmp", "ext4", "8:4");
    CHECK(mount_points(build_plan(n.table(), "/", Os::linux_os)) == Strs{"/", "/tmp"});
}

TEST_CASE("file_search volumes: macOS prunes the data volume under '/' as firmlinks_only, a root below is one unit",
          "[file_search][file_search_volumes]") {
    // the data volume also reads as a twin of the system volume here, to prove firmlinks_only comes first
    Mounts m;
    m.add("/", "apfs", "1:1", "/", "/dev/disk3s1s1")
        .add("/System/Volumes/Data", "apfs", "1:1", "/", "/dev/disk3s5")
        .add("/dev", "devfs", "1:9", "/", "devfs");
    const VolumePlan p = build_plan(m.table(), "/", Os::macos);
    CHECK(mount_points(p) == Strs{"/"});
    CHECK(reason_at(p, "/System/Volumes/Data") == fsr::Reason::firmlinks_only);
    CHECK(reason_at(p, "/dev") == fsr::Reason::fstype_not_allowed);
    CHECK(unit_at(p, "/").prune == Strs{"/System/Volumes/Data", "/dev"});

    const VolumePlan home = build_plan(m.table(), "/Users/alex", Os::macos);
    CHECK(mount_points(home) == Strs{"/"});
    CHECK(home.units[0].walk_root == "/Users/alex");
    CHECK(home.refused.empty());

    // the data volume is searched from its own mount point when the root contains it
    const VolumePlan data = build_plan(m.table(), "/System/Volumes/Data/Users", Os::macos);
    CHECK(mount_points(data) == Strs{"/System/Volumes/Data"});
    CHECK(data.refused.empty());

    // Below "/" but not at "/": no firmlink reaches the data volume from such a root, so it is searched
    // from its own mount point like any other mount.
    Mounts real;
    real.add("/", "apfs", "1:1", "/", "/dev/disk3s1s1").add("/System/Volumes/Data", "apfs", "1:2", "/", "/dev/disk3s5");
    const VolumePlan sys = build_plan(real.table(), "/System", Os::macos);
    CHECK(mount_points(sys) == Strs{"/", "/System/Volumes/Data"});
    CHECK(sys.refused.empty());
    // and from "/" with a distinct label it is still firmlinks_only
    const VolumePlan whole = build_plan(real.table(), "/", Os::macos);
    CHECK(mount_points(whole) == Strs{"/"});
    CHECK(reason_at(whole, "/System/Volumes/Data") == fsr::Reason::firmlinks_only);
    // Linux has no such rule
    CHECK(mount_points(build_plan(real.table(), "/", Os::linux_os)) == Strs{"/", "/System/Volumes/Data"});
}

TEST_CASE("file_search volumes: no mount containing the root is not a plan", "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/home", "ext4", "8:2");
    const VolumePlan p = build_plan(m.table(), "/srv", Os::linux_os);
    CHECK_FALSE(p.valid);
    CHECK(p.units.empty());
    // entries with a relative or empty mount point are ignored
    Mounts n;
    n.add("relative", "ext4");
    CHECK_FALSE(build_plan(n.table(), "/", Os::linux_os).valid);
}

TEST_CASE("file_search volumes: past kMaxVolumes the rest are counted and still pruned",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1");
    for (int i = 0; i < 70; ++i)
        m.add("/m/" + std::string(i < 10 ? "0" : "") + std::to_string(i), "ext4", "9:" + std::to_string(i));
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    CHECK(p.units.size() == kMaxVolumes);
    CHECK(p.volumes_dropped == 1 + 70 - kMaxVolumes);
    CHECK(unit_at(p, "/").prune.size() == 70); // a dropped mount is never walked through its parent

    // units first, then refused rows: the refused rows that do not fit are counted
    Mounts n;
    n.add("/", "ext4", "8:1").add("/a", "ext4", "8:2").add("/b", "ext4", "8:3");
    for (int i = 0; i < 70; ++i)
        n.add("/t/" + std::string(i < 10 ? "0" : "") + std::to_string(i), "tmpfs", "0:" + std::to_string(100 + i), "/", "tmpfs");
    const VolumePlan q = build_plan(n.table(), "/", Os::linux_os);
    CHECK(q.units.size() == 3);
    CHECK(q.refused.size() == kMaxVolumes - 3);
    CHECK(q.volumes_dropped == 70 - (kMaxVolumes - 3));
    CHECK(unit_at(q, "/").prune.size() == 72);

    // a mount point too long to be a row is counted, never a row
    Mounts r;
    r.add("/", "ext4", "8:1").add("/" + std::string(kMaxVolumePathBytes, 'x'), "ext4", "8:2");
    const VolumePlan s = build_plan(r.table(), "/", Os::linux_os);
    CHECK(s.units.size() == 1);
    CHECK(s.volumes_dropped == 1);
}

TEST_CASE("file_search volumes: a long fstype is cut in its refused row", "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1").add("/x", std::string(500, 'f'), "8:2");
    const VolumePlan p = build_plan(m.table(), "/", Os::linux_os);
    REQUIRE(p.refused.size() == 1);
    CHECK(p.refused[0].fstype.size() == kMaxFstypeBytes);
}

TEST_CASE("file_search volumes: the units hash ignores refused rows and the refused hash follows them",
          "[file_search][file_search_volumes]") {
    Mounts m;
    m.add("/", "ext4", "8:1").add("/data", "ext4", "8:2");
    const VolumePlan base = build_plan(m.table(), "/", Os::linux_os);

    Mounts with_tmp = m;
    with_tmp.add("/mnt/t", "tmpfs", "0:7", "/", "tmpfs");
    const VolumePlan more = build_plan(with_tmp.table(), "/", Os::linux_os);
    CHECK(more.units_hash == base.units_hash);
    CHECK(more.refused_hash != base.refused_hash);

    Mounts other_reason = m;
    other_reason.add("/mnt/t", "nfs4", "0:7", "/", "srv:/x"); // same mount point, another reason
    CHECK(build_plan(other_reason.table(), "/", Os::linux_os).refused_hash != more.refused_hash);

    Mounts another_unit = m;
    another_unit.add("/more", "ext4", "8:9");
    const VolumePlan changed = build_plan(another_unit.table(), "/", Os::linux_os);
    CHECK(changed.units_hash != base.units_hash);
    CHECK(changed.refused_hash == base.refused_hash);

    // each field of a unit counts
    Mounts relabel;
    relabel.add("/", "ext4", "8:1").add("/data", "ext4", "8:3");
    CHECK(build_plan(relabel.table(), "/", Os::linux_os).units_hash != base.units_hash);
    Mounts reroot;
    reroot.add("/", "ext4", "8:1").add("/data", "ext4", "8:2", "/sub");
    CHECK(build_plan(reroot.table(), "/", Os::linux_os).units_hash != base.units_hash);
    Mounts refs;
    refs.add("/", "ext4", "8:1").add("/data", "xfs", "8:2");
    CHECK(build_plan(refs.table(), "/", Os::linux_os).units_hash != base.units_hash);

    // later entry for a mount point covers the earlier one
    Mounts over;
    over.add("/", "ext4", "8:1").add("/data", "tmpfs", "0:7", "/", "tmpfs").add("/data", "ext4", "8:2");
    CHECK(build_plan(over.table(), "/", Os::linux_os).units_hash == base.units_hash);
}

namespace {

fsr::QueryHash hash_of(std::uint8_t b) {
    fsr::QueryHash h{};
    h.fill(b);
    return h;
}

VolumeCursor cursor_at(std::size_t index, std::uint64_t sequence, std::uint32_t generation = 0,
                       std::uint32_t prior_gaps = 0, fsr::Position pos = {}, std::uint8_t q = 7) {
    VolumeCursor c;
    c.index = index;
    c.units_hash = "0123456789abcdef";
    c.refused_hash = "fedcba9876543210";
    c.inner.query_hash = hash_of(q);
    c.inner.sequence = sequence;
    c.inner.generation = generation;
    c.inner.prior_gaps = prior_gaps;
    c.inner.position = std::move(pos);
    return c;
}

fsr::Position pos_in(std::string dir, std::string after) {
    fsr::Position p;
    p.root_dev = 1;
    p.root_file_id = 2;
    p.dirs.push_back({std::move(dir), 3, 4});
    p.after = std::move(after);
    return p;
}

} // namespace

TEST_CASE("file_search volumes: the fsv1 cursor round-trips through its five fields",
          "[file_search][file_search_volumes]") {
    const VolumeCursor c = cursor_at(3, 12, 1, 4, pos_in("a", "b"));
    const std::string token = encode_volume_cursor(c);
    REQUIRE_FALSE(token.empty());
    CHECK(token.starts_with("fsv1.3.0123456789abcdef.fedcba9876543210.fs1:"));
    const auto back = decode_volume_cursor(token, hash_of(7));
    REQUIRE(back.has_value());
    CHECK(*back == c);
    CHECK(encode_volume_cursor(*back) == token);

    const auto fields = split_volume_cursor(token);
    REQUIRE(fields.has_value());
    CHECK(fields->index == 3);
    CHECK(fields->units_hash == "0123456789abcdef");
    CHECK(fields->inner.starts_with("fs1:"));

    // the first volume, the last volume
    for (const std::size_t i : {std::size_t{0}, kMaxVolumes - 1})
        CHECK(decode_volume_cursor(encode_volume_cursor(cursor_at(i, 1)), hash_of(7)).has_value());
}

TEST_CASE("file_search volumes: every non-canonical or forged spelling is refused before anything is called",
          "[file_search][file_search_volumes]") {
    const VolumeCursor c = cursor_at(3, 12);
    const std::string good = encode_volume_cursor(c);
    REQUIRE(decode_volume_cursor(good, hash_of(7)).has_value());
    const std::string inner = good.substr(good.find("fs1:"));
    const std::string uh = "0123456789abcdef";
    const std::string rh = "fedcba9876543210";

    const std::vector<std::string> bad = {
        "",
        "fsv1",
        "fsv2.3." + uh + "." + rh + "." + inner,           // another version
        "FSV1.3." + uh + "." + rh + "." + inner,
        "fsv1.03." + uh + "." + rh + "." + inner,          // leading zero
        "fsv1.+3." + uh + "." + rh + "." + inner,          // sign
        "fsv1.-3." + uh + "." + rh + "." + inner,
        "fsv1..." + uh + "." + rh + "." + inner,           // empty index
        "fsv1.64." + uh + "." + rh + "." + inner,          // an index of kMaxVolumes
        "fsv1.100." + uh + "." + rh + "." + inner,
        "fsv1.3.0123456789ABCDEF." + rh + "." + inner,     // uppercase hash
        "fsv1.3.0123456789abcde." + rh + "." + inner,      // short hash
        "fsv1.3." + uh + "0." + rh + "." + inner,          // long hash
        "fsv1.3." + uh + "." + rh + "x." + inner,
        "fsv1.3." + uh + "." + rh + "." + "xs1:" + inner.substr(4),
        "fsv1.3." + uh + "." + rh + "." + inner + ".",      // a sixth field
        "fsv1.3." + uh + "." + rh + "." + inner + ".x",
        "fsv1.3." + uh + "." + rh + "." + inner + "\n",
        "fsv1.3." + uh + "." + rh,                          // no inner token
        "fsv1.3." + uh + "." + rh + ".",
        "fsv1.3." + uh + "." + rh + ".fs1:",                // an inner token with no body
        " " + good,
        good + " ",
    };
    for (const auto& t : bad) {
        INFO(t);
        CHECK_FALSE(decode_volume_cursor(t, hash_of(7)).has_value());
    }
    // an inner token of another query, and a hostile one, never decode
    CHECK_FALSE(decode_volume_cursor(good, hash_of(8)).has_value());
    CHECK_FALSE(decode_volume_cursor(std::string(100000, 'f'), hash_of(7)).has_value());
    CHECK_FALSE(split_volume_cursor(std::string(100000, '.')).has_value());

    // a value the encoder cannot spell is no token
    VolumeCursor oversized = c;
    oversized.index = kMaxVolumes;
    CHECK(encode_volume_cursor(oversized).empty());
    VolumeCursor bad_hash = c;
    bad_hash.units_hash = "nothex";
    CHECK(encode_volume_cursor(bad_hash).empty());
    VolumeCursor bad_pos = c;
    bad_pos.inner.position.after = std::string(300, 'a'); // not a position fs1 can spell
    CHECK(encode_volume_cursor(bad_pos).empty());
}

TEST_CASE("file_search volumes: volume_advances accepts exactly the two transitions",
          "[file_search][file_search_volumes]") {
    const VolumeCursor prev = cursor_at(1, 5, 0, 2, pos_in("a", "b"));

    SECTION("a step of the same unit's walk") {
        CHECK(volume_advances(prev, cursor_at(1, 6, 0, 2, pos_in("a", "c"))));
        CHECK(volume_advances(prev, cursor_at(1, 6, 0, 3, pos_in("a", "c")))); // gaps found
        CHECK_FALSE(volume_advances(prev, cursor_at(1, 6, 0, 2, pos_in("a", "b")))); // no progress
        CHECK_FALSE(volume_advances(prev, cursor_at(1, 6, 0, 2, pos_in("a", "a")))); // backward
        CHECK_FALSE(volume_advances(prev, cursor_at(1, 5, 0, 2, pos_in("a", "c")))); // sequence repeated
        CHECK_FALSE(volume_advances(prev, cursor_at(1, 4, 0, 2, pos_in("a", "c")))); // sequence backward
        CHECK_FALSE(volume_advances(prev, cursor_at(1, 7, 0, 2, pos_in("a", "c")))); // sequence skipped
        // a restart (generation + 1) may go back, as the fs1 rule allows
        CHECK(volume_advances(prev, cursor_at(1, 6, 1, 2, pos_in("a", "a"))));
    }
    SECTION("the move to the next unit") {
        CHECK(volume_advances(prev, cursor_at(2, 6, 0, 2)));
        CHECK(volume_advances(prev, cursor_at(2, 6, 0, 9)));
        CHECK_FALSE(volume_advances(prev, cursor_at(3, 6, 0, 2)));                  // a skipped index
        CHECK_FALSE(volume_advances(prev, cursor_at(0, 6, 0, 2)));                  // backward
        CHECK_FALSE(volume_advances(prev, cursor_at(2, 5, 0, 2)));                  // sequence repeated
        CHECK_FALSE(volume_advances(prev, cursor_at(2, 4, 0, 2)));                  // sequence backward
        CHECK_FALSE(volume_advances(prev, cursor_at(2, 7, 0, 2)));                  // sequence skipped
        CHECK_FALSE(volume_advances(prev, cursor_at(2, 6, 0, 1)));                  // gaps forgotten
        CHECK_FALSE(volume_advances(prev, cursor_at(2, 6, 1, 2)));                  // generation moved
        CHECK_FALSE(volume_advances(prev, cursor_at(2, 6, 0, 2, pos_in("a", "b")))); // a stale position
        CHECK_FALSE(volume_advances(prev, cursor_at(2, 6, 0, 2, {}, 8)));           // another query
    }
    SECTION("a changed units hash ends it, a changed refused hash does not") {
        VolumeCursor next = cursor_at(1, 6, 0, 2, pos_in("a", "c"));
        next.units_hash = "ffffffffffffffff";
        CHECK_FALSE(volume_advances(prev, next));
        VolumeCursor move = cursor_at(2, 6, 0, 2);
        move.units_hash = "ffffffffffffffff";
        CHECK_FALSE(volume_advances(prev, move));

        VolumeCursor refused = cursor_at(1, 6, 0, 2, pos_in("a", "c"));
        refused.refused_hash = "ffffffffffffffff";
        CHECK(volume_advances(prev, refused));
        VolumeCursor refused_move = cursor_at(2, 6, 0, 2);
        refused_move.refused_hash = "ffffffffffffffff";
        CHECK(volume_advances(prev, refused_move));
    }
    SECTION("the sequence cannot wrap") {
        CHECK_FALSE(volume_advances(cursor_at(0, ~std::uint64_t{0}), cursor_at(1, 0)));
    }
}

TEST_CASE("file_search volumes: a walk's stop and a sticky health become the reason a row states",
          "[file_search][file_search_volumes]") {
    using yuzu::component_inventory::Stop;
    CHECK(reason_for(Stop::complete, fsr::Health::ok) == fsr::Reason::none);
    CHECK(reason_for(Stop::budget_entries, fsr::Health::ok) == fsr::Reason::budget_entries);
    CHECK(reason_for(Stop::budget_time, fsr::Health::ok) == fsr::Reason::budget_time);
    CHECK(reason_for(Stop::section_rows, fsr::Health::ok) == fsr::Reason::budget_rows);
    CHECK(reason_for(Stop::depth, fsr::Health::ok) == fsr::Reason::unsupported);
    // health wins over the stop
    CHECK(reason_for(Stop::budget_time, fsr::Health::stalled) == fsr::Reason::stalled);
    CHECK(reason_for(Stop::section_rows, fsr::Health::unstable) == fsr::Reason::unstable);
}
