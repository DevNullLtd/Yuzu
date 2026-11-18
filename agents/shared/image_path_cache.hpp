// image_path_cache.hpp -- the per-action "already hashed" lookup that runs BEFORE the helper budget.
//
// A process listing hashes many processes that share one image. The content cache
// (image_hash_cache.hpp) is keyed by the OPENED image and so can only be consulted after an open on
// a helper; once the per-action cap of stuck helpers trips, every later row would read
// `hash_unavailable:skipped` even when its image was already hashed earlier in the same action.
// `ImagePathCache` answers those rows from an IDENTITY key taken from procfs alone, never from the
// image or its filesystem: the mount namespace link plus the (device, inode) of the executable's
// mapping in /proc/<pid>/maps. It is deliberately NOT keyed on path text: a replaced binary reads
// "<path> (deleted)" with the marker stripped for display, so the old and the new image share one
// path text and a path-keyed hit would hand the old image's hash to the new one. A running
// executable cannot be written in place (ETXTBSY), so a (dev, inode) held by a live process names
// fixed content. Residual: if the first process exits mid-action and its inode number is reused by a
// different file at the same path, the reused identity matches; one action only, and only a hash that
// completed is stored. Pure; one action only.
#pragma once

#include "helper_budget.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::shared {

class ImagePathCache {
public:
    /// The identity of the executable mapping in a /proc/<pid>/maps text: `<dev>:<inode>` of the first
    /// mapping whose pathname (less a trailing " (deleted)") equals `exe_path` and whose inode is not
    /// 0; empty when none is found or the text is off-shape. Reads no file.
    [[nodiscard]] static std::string maps_identity(std::string_view maps, std::string_view exe_path) {
        constexpr std::string_view kDeleted = " (deleted)";
        while (!maps.empty()) {
            const auto nl = maps.find('\n');
            std::string_view line = maps.substr(0, nl);
            maps = nl == std::string_view::npos ? std::string_view{} : maps.substr(nl + 1);
            // "addr perms offset dev inode      pathname"
            std::string_view f[5];
            std::string_view rest = line;
            bool ok = true;
            for (auto& fld : f) {
                while (!rest.empty() && rest.front() == ' ')
                    rest.remove_prefix(1);
                const auto sp = rest.find(' ');
                if (rest.empty()) { ok = false; break; }
                fld = rest.substr(0, sp);
                rest = sp == std::string_view::npos ? std::string_view{} : rest.substr(sp);
            }
            if (!ok)
                continue;
            while (!rest.empty() && rest.front() == ' ')
                rest.remove_prefix(1);
            if (rest.size() >= kDeleted.size() && rest.substr(rest.size() - kDeleted.size()) == kDeleted)
                rest.remove_suffix(kDeleted.size());
            if (f[4] == "0" || rest != exe_path)
                continue;
            std::string id{f[3]};
            id.push_back(':');
            id.append(f[4]);
            return id;
        }
        return {};
    }
    /// The cache key: mount namespace plus the maps identity. Empty (no caching) when either is missing.
    [[nodiscard]] static std::string make_key(std::string_view mount_ns, std::string_view identity) {
        if (mount_ns.empty() || identity.empty())
            return {};
        std::string k{mount_ns};
        k.push_back('\n');
        k.append(identity);
        return k;
    }
    [[nodiscard]] const std::string* find(const std::string& key) const {
        if (key.empty())
            return nullptr;
        const auto it = map_.find(key);
        return it == map_.end() ? nullptr : &it->second;
    }
    void put(const std::string& key, const std::string& hash) {
        if (!key.empty() && is_real_hash(hash))
            map_.emplace(key, hash);
    }
    /// A completed hash: not empty and not a `hash_unavailable:<cause>` marker.
    [[nodiscard]] static bool is_real_hash(std::string_view h) {
        return !h.empty() && h.rfind(kHashUnavailablePrefix, 0) != 0;
    }

private:
    std::unordered_map<std::string, std::string> map_;
};

/// One row's hash. The cache is consulted BEFORE the helper gate: a row whose image was already
/// hashed in this action answers from the cache even when no helper may be started. Otherwise a row
/// that may not start a helper reads the `skipped` marker, and one that may runs `compute()`.
template <typename Compute>
[[nodiscard]] std::string hash_row_cached(ImagePathCache& cache, const std::string& key, bool may_start,
                                          Compute&& compute) {
    if (const auto* hit = cache.find(key))
        return *hit;
    if (!may_start)
        return std::string{kHashUnavailableSkipped};
    std::string h = std::forward<Compute>(compute)();
    cache.put(key, h);
    return h;
}

} // namespace yuzu::shared
