// file_search_position.hpp -- the ONE walk-position type of the on-demand file search.
//
// A Position names where a depth-first directory walk stands: the directories entered below the
// root (root first, each with the identity seen when it was listed, 0 = unknown) and the last
// completed entry of the innermost directory. The resume cursor (file_search_cursor.hpp) carries
// it over the wire and the ordered walker includes this same header; there is no second
// position or frame type anywhere.
//
// Names here are only ever COMPARED with the entries of a real directory listing. They are never
// joined into a path that is opened, so nothing in this header takes or produces a filesystem
// path.
//
// GapCause is the one vocabulary for a place the walk could not search, shared by the ordered
// walker (OrderedGap) and the coverage envelope; there is no second gap enum.
//
// Platform-agnostic pure C++, no OS call, no I/O: the zero-dependency leaf-helper convention of
// this directory (docs/cpp-conventions.md).
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::shared::file_search {

// The longest directory-entry name a Position can hold (the POSIX NAME_MAX). A longer name that a
// filesystem allows (255 UTF-16 units can be 765 UTF-8 bytes on HFS-family and Windows volumes) is
// never placed in a Position: the walker reports it as a `name_too_long` gap instead.
inline constexpr std::size_t kMaxNameBytes = 255;
inline constexpr std::size_t kMaxPositionDepth = 64;

enum class GapCause {
    depth,
    dir_unreadable,
    dir_truncated,
    other_device,
    network_mount,
    memory_cap,
    permission_denied,
    dataless,
    private_namespace,
    name_too_long // an entry whose name cannot be held in a Position (too long, or a slash or NUL): not searched
};

[[nodiscard]] constexpr const char* to_token(GapCause c) noexcept {
    switch (c) {
    case GapCause::depth:
        return "depth";
    case GapCause::dir_unreadable:
        return "dir_unreadable";
    case GapCause::dir_truncated:
        return "dir_truncated";
    case GapCause::other_device:
        return "other_device";
    case GapCause::network_mount:
        return "network_mount";
    case GapCause::memory_cap:
        return "memory_cap";
    case GapCause::permission_denied:
        return "permission_denied";
    case GapCause::dataless:
        return "dataless";
    case GapCause::private_namespace:
        return "private_namespace";
    case GapCause::name_too_long:
        return "name_too_long";
    }
    return "unknown";
}

/// One directory entered below the root: its name and the (dev, file id) seen when it was listed.
struct Frame {
    std::string name;
    std::uint64_t dev{0};
    std::uint64_t file_id{0};
    bool operator==(const Frame&) const = default;
};

/// `dirs` are the directories entered below the root (root first). `after` is the last completed
/// entry name in the innermost directory (empty = start of that directory).
struct Position {
    std::uint64_t root_dev{0};
    std::uint64_t root_file_id{0};
    std::vector<Frame> dirs;
    std::string after;
    bool operator==(const Position&) const = default;
};

/// THE identity rule of a Position, for its root and for every Frame: a half (device or file id) that
/// is 0 is unknown. The ordered walker and the cursor validator both use these two functions; there is
/// no other identity comparison.
/// known(): what a recorded half becomes after a later reading (an unknown half takes the reading).
[[nodiscard]] constexpr std::uint64_t known(std::uint64_t now, std::uint64_t recorded) noexcept {
    return now != 0 ? now : recorded;
}
/// True when a half the EARLIER identity knows is not the same in the LATER one: another value, or
/// back to unknown. Unknown-to-known is refinement, never a change.
[[nodiscard]] constexpr bool identity_changed(std::uint64_t dev, std::uint64_t id, std::uint64_t later_dev,
                                              std::uint64_t later_id) noexcept {
    return (dev != 0 && dev != later_dev) || (id != 0 && id != later_id);
}

/// One directory-entry name: 1..255 bytes, no NUL, no '/', not "." or "..".
[[nodiscard]] inline bool valid_component(std::string_view s) noexcept {
    if (s.empty() || s.size() > kMaxNameBytes || s == "." || s == "..")
        return false;
    for (const char c : s)
        if (c == '\0' || c == '/')
            return false;
    return true;
}

/// Depth at most kMaxPositionDepth, every dir name a valid component, `after` empty or valid.
[[nodiscard]] inline bool valid_position(const Position& p) noexcept {
    if (p.dirs.size() > kMaxPositionDepth)
        return false;
    for (const auto& f : p.dirs)
        if (!valid_component(f.name))
            return false;
    return p.after.empty() || valid_component(p.after);
}

namespace detail {

[[nodiscard]] inline std::strong_ordering bytes_order(std::string_view a, std::string_view b) noexcept {
    const int c = a.compare(b); // char_traits<char>: unsigned byte order, shorter prefix first
    return c < 0 ? std::strong_ordering::less
                 : (c > 0 ? std::strong_ordering::greater : std::strong_ordering::equal);
}

} // namespace detail

/// Depth-first walk order by NAMES only (identities are ignored), compared level by level. Two
/// dirs at a level compare by name bytes. Where one side has a dir D at the level at which the
/// other has its `after` A, the side inside D is EARLIER when D <= A (A, and so D, is already
/// completed) and LATER when D > A. Two `after` values compare by bytes, empty smallest.
[[nodiscard]] inline std::strong_ordering walk_order(const Position& a, const Position& b) noexcept {
    const std::size_t common = a.dirs.size() < b.dirs.size() ? a.dirs.size() : b.dirs.size();
    for (std::size_t i = 0; i < common; ++i)
        if (const auto c = detail::bytes_order(a.dirs[i].name, b.dirs[i].name); c != 0)
            return c;
    if (a.dirs.size() == b.dirs.size())
        return detail::bytes_order(a.after, b.after);
    if (a.dirs.size() > common) // a is inside dirs[common]; b stands at `after` on that level
        return detail::bytes_order(a.dirs[common].name, b.after) <= 0 ? std::strong_ordering::less
                                                                      : std::strong_ordering::greater;
    return detail::bytes_order(b.dirs[common].name, a.after) <= 0 ? std::strong_ordering::greater
                                                                  : std::strong_ordering::less;
}

} // namespace yuzu::shared::file_search
