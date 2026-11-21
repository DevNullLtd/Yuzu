/**
 * file_search_volumes.hpp -- the volume plan of one search, the fsv1 cursor that carries a search across
 * volumes and the mapping from a walk's stop to the reason a row states. Pure: it reads a mount table the
 * caller already parsed, never the filesystem.
 *
 * A search walks ONE ROOT but may cross many mounts. The plan decides, from the mount table alone, which
 * mounts are searched (UNITS), which are not and why (REFUSED rows), and which mount points each unit's
 * walk must never enter (its PRUNE set). One slice searches one unit.
 *
 * PATH TESTS. Every path test here is on a component boundary (under()): /home2 is not under /home.
 *
 * WHAT THE PLAN READS. The mounts at or under the root, plus the mounts that contain the root; a later
 * entry for a mount point covers an earlier one (the plan does that itself, so it never depends on the
 * reader). The mount that contains the root is the longest of the latter.
 * Without one the table does not describe the root and the plan is not valid.
 *
 * IDENTITY. A mount is its device label ("major:minor") and its root field. Two in-scope mounts with
 * EQUAL identity are one subtree mounted twice: one stays (the mount containing the root if it is one of
 * them, else the first by mount-point bytes) and the other is not_searched/duplicate_mount. Mounts that
 * share a label but differ in root are separate units (btrfs subvolume mounts, a ReadWritePaths
 * self-bind, a directory bind), each walked from its own mount point. Containment is deliberately NOT
 * used: a walk cannot cross a btrfs subvolume boundary (other_device in component_walk.hpp), so a mount
 * contained in another is not reachable through it.
 *
 * WHICH MOUNTS ARE SEARCHED. The allow-list (is_searchable_local_fstype). Every other in-scope mount is a
 * refused row with its own reason, decided in this order: network type -> network_mount; a /tmp or
 * /var/tmp bind from a private namespace -> private_namespace; not on the allow-list ->
 * fstype_not_allowed; macOS data volume under a root of "/" -> firmlinks_only (the system volume reaches
 * it through its firmlinks; walking its mount point too would find everything twice); beneath a network
 * mount -> behind_network_mount (reaching it would open a directory on that mount); equal identity to a
 * kept mount -> duplicate_mount. A mount that is only an ANCESTOR of a unit and is of another refused type
 * (tmpfs, overlay) never blocks it: it is crossed by one no-follow open per hop and never listed.
 *
 * PRUNING. A unit's prune set is every in-scope mount point strictly BELOW its walk root, refused and
 * dropped mounts included, never an ancestor. The walk never lists them and reports nothing for them: the
 * plan's rows are the one record of a pruned mount, a nested unit by its own volume row and a refused
 * mount by its own refused row (not_searched, or partial for firmlinks_only). So a mount point's own
 * directory name is not a match candidate.
 *
 * CAPS. At most kMaxVolumes volumes are planned, units first and then refused rows; the rest are counted
 * in volumes_dropped and make the verdict partial. A mount point longer than kMaxVolumePathBytes cannot
 * be a row and is counted the same way. Prune sets are computed before the cap.
 *
 * THE FSV1 CURSOR wraps the unchanged fs1 cursor:  fsv1.<volume index>.<units hash>.<refused hash>.<fs1>
 * The units hash covers the walk units only (mount point, label, root, fstype, in order); the refused hash
 * covers the refused rows (mount point, reason). A changed units hash ends the search. A changed refused
 * hash does not: refused mounts come and go (overlays, snaps, automounts) and are only re-reported.
 * Decoding is strict: every accepted token re-encodes to itself.
 */
#pragma once

#include <file_search_coverage.hpp>
#include <file_search_cursor.hpp>
#include <file_search_governor.hpp>
#include <network_fstype.hpp>
#include <sha256.hpp>

#include "file_search_rows.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// The breadth-first walk's Stop vocabulary: the one stop the reason mapping below reads.
#include "component_walk.hpp"

namespace yuzu::file_search {

// ---- path tests ----

/// Strictly below: under() (file_search_rows.hpp) and not equal.
[[nodiscard]] inline bool strictly_under(std::string_view path, std::string_view prefix) noexcept {
    return path != prefix && under(path, prefix);
}

// ---- the plan ----

/// One mount the search walks, from its own mount point (or, for the mount that contains the root, from
/// the root).
struct Unit {
    std::string mount_point;
    std::string fstype;
    std::string label;      // "major:minor"
    std::string root_field; // the mount's root inside its filesystem
    std::string walk_root;
    std::vector<std::string> prune; // mount points strictly below walk_root, in byte order

    /// The key an abandoned worker is recorded under and a cursor's hash covers.
    [[nodiscard]] std::string key() const {
        return mount_point + '\x1f' + label + '\x1f' + root_field + '\x1f' + fstype;
    }
};

struct Refused {
    std::string mount_point;
    std::string fstype; // cut at kMaxFstypeBytes
    fsr::Reason reason{fsr::Reason::fstype_not_allowed};
};

struct VolumePlan {
    bool valid{false}; // false: no mount in the table contains the root
    std::vector<Unit> units;
    std::vector<Refused> refused;
    std::size_t volumes_dropped{0};
    std::string units_hash;   // 16 lowercase hex digits
    std::string refused_hash; // 16 lowercase hex digits
};

namespace detail {

[[nodiscard]] inline std::string label_of(const yuzu::shared::MountEntry& e) {
    return std::to_string(e.dev_major) + ":" + std::to_string(e.dev_minor);
}

/// A /tmp or /var/tmp mount that a service manager bound in from a private per-service directory.
[[nodiscard]] inline bool is_private_tmp_bind(const yuzu::shared::MountEntry& e) {
    if (e.mount_point != "/tmp" && e.mount_point != "/var/tmp")
        return false;
    return e.root.starts_with("/tmp/systemd-private-") || e.root.starts_with("/var/tmp/systemd-private-");
}

inline constexpr const char* kMacosDataVolume = "/System/Volumes/Data";

[[nodiscard]] inline std::string hash16(std::string_view domain, const std::vector<std::string>& parts) {
    std::string buf(domain);
    for (const auto& p : parts) {
        const auto n = static_cast<std::uint32_t>(p.size());
        for (int i = 0; i < 4; ++i)
            buf.push_back(static_cast<char>((n >> (8 * i)) & 0xFFu));
        buf += p;
    }
    return yuzu::shared::sha256_hex(buf).substr(0, 16);
}

} // namespace detail

/// Covers the units only: mount point, label, root field and fstype of each, in order. Nothing about a
/// refused mount changes it.
[[nodiscard]] inline std::string units_hash(const std::vector<Unit>& units) {
    std::vector<std::string> parts;
    for (const auto& u : units)
        for (const auto* f : {&u.mount_point, &u.label, &u.root_field, &u.fstype})
            parts.push_back(*f);
    return detail::hash16("yuzu.file_search.units.v1", parts);
}

/// Covers the refused rows: mount point and reason of each, in order.
[[nodiscard]] inline std::string refused_hash(const std::vector<Refused>& refused) {
    std::vector<std::string> parts;
    for (const auto& r : refused) {
        parts.push_back(r.mount_point);
        parts.emplace_back(fsr::to_token(r.reason));
    }
    return detail::hash16("yuzu.file_search.refused.v1", parts);
}

/// Plans the search of `root` over `table`. `root` is absolute and normalised (request parser).
[[nodiscard]] inline VolumePlan build_plan(const yuzu::shared::MountTable& table, const std::string& root, Os os) {
    using yuzu::shared::MountEntry;
    VolumePlan plan;

    // In scope: at or under the root, or containing it. One entry per mount point, the last one wins.
    std::map<std::string, const MountEntry*> by_point; // byte order
    for (const auto& e : table.entries) {
        if (e.mount_point.empty() || e.mount_point.front() != '/' || e.mount_point.find('\0') != std::string::npos)
            continue;
        if (under(e.mount_point, root) || under(root, e.mount_point))
            by_point[e.mount_point] = &e;
    }

    const MountEntry* containing = nullptr;
    for (const auto& point : by_point)
        if (under(root, point.first) &&
            (containing == nullptr || point.first.size() > containing->mount_point.size()))
            containing = point.second;
    if (containing == nullptr)
        return plan; // the table does not describe the root
    plan.valid = true;

    const auto behind_network = [&](const MountEntry& m) {
        for (const auto& point : by_point)
            if (strictly_under(m.mount_point, point.first) && yuzu::shared::is_network_mount_fstype(point.second->fstype))
                return true;
        return false;
    };

    std::vector<const MountEntry*> candidates; // searchable so far
    std::vector<Refused> refused;
    for (const auto& point : by_point) {
        const std::string& mp = point.first;
        const MountEntry* e = point.second;
        const bool is_containing = e == containing;
        if (!under(mp, root) && !is_containing)
            continue; // an ancestor of the root that does not contain it: never searched, never reported
        if (mp.size() > kMaxVolumePathBytes) {
            ++plan.volumes_dropped;
            continue;
        }
        const auto refuse = [&refused, &mp, e](fsr::Reason why) {
            refused.push_back({mp, e->fstype.substr(0, kMaxFstypeBytes), why});
        };
        if (yuzu::shared::is_network_mount_fstype(e->fstype))
            refuse(fsr::Reason::network_mount);
        else if (detail::is_private_tmp_bind(*e))
            refuse(fsr::Reason::private_namespace);
        else if (!yuzu::shared::is_searchable_local_fstype(e->fstype))
            refuse(fsr::Reason::fstype_not_allowed);
        else if (os == Os::macos && root == "/" && mp == detail::kMacosDataVolume)
            refuse(fsr::Reason::firmlinks_only);
        else if (behind_network(*e))
            refuse(fsr::Reason::behind_network_mount);
        else
            candidates.push_back(e);
    }

    // Equal identity is one subtree mounted twice: keep the mount containing the root, else the first.
    std::vector<const MountEntry*> kept;
    std::unordered_map<std::string, const MountEntry*> by_identity;
    for (const auto* e : candidates) { // byte order of the mount point
        const std::string id = detail::label_of(*e) + '\x1f' + e->root;
        const auto [it, inserted] = by_identity.try_emplace(id, e);
        if (!inserted && e == containing)
            it->second = e; // the containing mount wins over an earlier twin
    }
    for (const auto* e : candidates) {
        const std::string id = detail::label_of(*e) + '\x1f' + e->root;
        if (by_identity.at(id) == e)
            kept.push_back(e);
        else
            refused.push_back({e->mount_point, e->fstype.substr(0, kMaxFstypeBytes), fsr::Reason::duplicate_mount});
    }

    // The mount containing the root first, walked from the root; the others by mount point.
    std::ranges::stable_sort(kept, [&](const MountEntry* a, const MountEntry* b) {
        if ((a == containing) != (b == containing))
            return a == containing;
        return a->mount_point < b->mount_point;
    });
    for (const auto* e : kept) {
        Unit u;
        u.mount_point = e->mount_point;
        u.fstype = e->fstype;
        u.label = detail::label_of(*e);
        u.root_field = e->root;
        u.walk_root = e == containing ? root : e->mount_point;
        for (const auto& point : by_point)
            if (strictly_under(point.first, u.walk_root))
                u.prune.push_back(point.first);
        plan.units.push_back(std::move(u));
    }
    std::ranges::sort(refused, {}, &Refused::mount_point);

    // The cap: units first, then refused rows; whatever does not fit is counted.
    if (plan.units.size() > kMaxVolumes) {
        plan.volumes_dropped += plan.units.size() - kMaxVolumes + refused.size();
        plan.units.resize(kMaxVolumes);
        refused.clear();
    } else if (plan.units.size() + refused.size() > kMaxVolumes) {
        const std::size_t room = kMaxVolumes - plan.units.size();
        plan.volumes_dropped += refused.size() - room;
        refused.resize(room);
    }
    plan.refused = std::move(refused);
    plan.units_hash = units_hash(plan.units);
    plan.refused_hash = refused_hash(plan.refused);
    return plan;
}

/// The unit a path belongs to: the one with the longest mount point on a component boundary above it.
[[nodiscard]] inline std::optional<std::size_t> volume_for(const VolumePlan& plan, std::string_view path) {
    std::optional<std::size_t> best;
    for (std::size_t i = 0; i < plan.units.size(); ++i)
        if (under(path, plan.units[i].mount_point) &&
            (!best || plan.units[i].mount_point.size() > plan.units[*best].mount_point.size()))
            best = i;
    return best;
}

// ---- the fsv1 cursor ----

struct VolumeCursor {
    std::size_t index{0}; // the unit being searched
    std::string units_hash;
    std::string refused_hash;
    fsr::Cursor inner; // the fs1 cursor of that unit's walk
    bool operator==(const VolumeCursor&) const = default;
};

inline constexpr std::string_view kVolumeCursorPrefix = "fsv1";

namespace detail {

[[nodiscard]] inline bool is_hash16(std::string_view s) noexcept {
    return s.size() == 16 && std::ranges::all_of(s, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

} // namespace detail

/// Empty when the inner cursor has no spelling (an invalid position) or a field is not canonical.
[[nodiscard]] inline std::string encode_volume_cursor(const VolumeCursor& c) {
    if (c.index >= kMaxVolumes || !detail::is_hash16(c.units_hash) || !detail::is_hash16(c.refused_hash))
        return {};
    const std::string inner = fsr::encode_cursor(c.inner);
    if (inner.empty())
        return {};
    return std::string(kVolumeCursorPrefix) + "." + std::to_string(c.index) + "." + c.units_hash + "." +
           c.refused_hash + "." + inner;
}

/// The five fields of a token, strictly: nullopt for any other spelling. The inner token is returned as
/// text; it is decoded by fsr::decode_cursor.
struct VolumeTokenFields {
    std::size_t index{0};
    std::string units_hash;
    std::string refused_hash;
    std::string inner;
};

[[nodiscard]] inline std::optional<VolumeTokenFields> split_volume_cursor(std::string_view token) {
    if (token.size() > fsr::kMaxCursorTokenBytes + 128)
        return std::nullopt;
    std::string_view rest = token;
    std::string_view f[4];
    for (auto& field : f) {
        const auto dot = rest.find('.');
        if (dot == std::string_view::npos)
            return std::nullopt;
        field = rest.substr(0, dot);
        rest = rest.substr(dot + 1);
    }
    if (f[0] != kVolumeCursorPrefix)
        return std::nullopt;
    // the volume index: canonical decimal, below kMaxVolumes
    if (f[1].empty() || f[1].size() > 2 || (f[1].size() > 1 && f[1][0] == '0') ||
        !std::ranges::all_of(f[1], [](char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    const std::size_t index = static_cast<std::size_t>(std::stoul(std::string(f[1])));
    if (index >= kMaxVolumes || !detail::is_hash16(f[2]) || !detail::is_hash16(f[3]))
        return std::nullopt;
    if (!rest.starts_with(fsr::kCursorPrefix) || rest.find('.') != std::string_view::npos)
        return std::nullopt;
    return VolumeTokenFields{index, std::string(f[2]), std::string(f[3]), std::string(rest)};
}

/// Decodes a token for the query whose hash is `expected`. Nothing is opened. Every accepted token
/// re-encodes to itself.
[[nodiscard]] inline std::optional<VolumeCursor> decode_volume_cursor(std::string_view token,
                                                                      const fsr::QueryHash& expected) {
    const auto fields = split_volume_cursor(token);
    if (!fields)
        return std::nullopt;
    auto inner = fsr::decode_cursor(fields->inner, expected);
    if (!inner)
        return std::nullopt;
    VolumeCursor c{fields->index, fields->units_hash, fields->refused_hash, std::move(*inner)};
    if (encode_volume_cursor(c) != token)
        return std::nullopt;
    return c;
}

/// True for exactly two transitions, both with the same units hash: a step of the unit's own walk (the
/// fs1 rule, fsr::strictly_advances) or the move to the next unit (index + 1, a fresh position, sequence
/// + 1, the same generation and query, prior_gaps not smaller). A changed refused hash is not a change:
/// refused mounts are only re-reported.
[[nodiscard]] inline bool volume_advances(const VolumeCursor& prev, const VolumeCursor& next) noexcept {
    if (prev.units_hash != next.units_hash)
        return false;
    if (next.index == prev.index)
        return fsr::strictly_advances(prev.inner, next.inner);
    if (next.index != prev.index + 1)
        return false;
    return prev.inner.query_hash == next.inner.query_hash &&
           prev.inner.sequence != (std::numeric_limits<std::uint64_t>::max)() &&
           next.inner.sequence == prev.inner.sequence + 1 && next.inner.generation == prev.inner.generation &&
           next.inner.prior_gaps >= prev.inner.prior_gaps && next.inner.position == fsr::Position{};
}

// ---- stop and health to the reason a row states ----

/// The coverage reason of a slice that did not finish its unit: a sticky unhealthy state wins, else the
/// walk's own stop. The ordered walk only ever stops on a budget; any other stop reads `unsupported`.
[[nodiscard]] inline fsr::Reason reason_for(yuzu::component_inventory::Stop stop, fsr::Health health) noexcept {
    using yuzu::component_inventory::Stop;
    if (health == fsr::Health::stalled)
        return fsr::Reason::stalled;
    if (health == fsr::Health::unstable)
        return fsr::Reason::unstable;
    switch (stop) {
    case Stop::complete:
        return fsr::Reason::none;
    case Stop::budget_entries:
        return fsr::Reason::budget_entries;
    case Stop::budget_time:
        return fsr::Reason::budget_time;
    case Stop::section_rows:
        return fsr::Reason::budget_rows;
    default:
        return fsr::Reason::unsupported;
    }
}

} // namespace yuzu::file_search
