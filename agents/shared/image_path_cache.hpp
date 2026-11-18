// image_path_cache.hpp -- the per-action "already hashed" lookup that runs BEFORE the helper budget.
//
// A process listing hashes many processes that share one image. The identity cache
// (image_hash_cache.hpp) is keyed by the OPENED image and so can only be consulted after an open on
// a helper; once the per-action cap of stuck helpers trips, every later row would read
// `hash_unavailable:skipped` even when its image was already hashed earlier in the same action.
// `ImagePathCache` answers those rows from a key of (mount namespace, image path text), taken from
// procfs without touching the image, and only for a hash that really completed. The namespace is part
// of the key so two containers' `/usr/bin/python` never share an answer. One action only; pure.
#pragma once

#include "helper_budget.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::shared {

class ImagePathCache {
public:
    [[nodiscard]] static std::string make_key(std::string_view mount_ns, std::string_view path) {
        if (mount_ns.empty() || path.empty())
            return {};
        std::string k{mount_ns};
        k.push_back('\n');
        k.append(path);
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
