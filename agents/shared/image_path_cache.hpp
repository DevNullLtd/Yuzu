// image_path_cache.hpp -- the per-action "already hashed" answer for rows that may not start a helper.
//
// A process listing hashes many processes that share one image. The content cache
// (image_hash_cache.hpp) is keyed by the OPENED image and so can only be consulted after an open on
// a helper; once the per-action cap of stuck helpers trips, every later row would read
// `hash_unavailable:skipped` even when its image was already hashed earlier in the same action.
// `ImagePathCache` answers THOSE rows (and only those: a row that may start a helper always hashes for
// real) from an identity key taken from procfs alone, never from the image or its filesystem: the
// mount namespace link plus the (device, inode) shared by every mapping of the executable in the
// COMPLETE /proc/<pid>/maps. It is not keyed on path text (a replaced binary reads "<path> (deleted)"
// and the marker is stripped for display, so old and new image share one path text); the deleted
// state must match the exe link's; two mappings with that path text but different inodes make the
// identity unknown (no caching); an incomplete maps read is unknown. A running executable cannot be
// written in place (ETXTBSY), so a (dev, inode) held by a live process names fixed content.
// RESIDUALS (stated, not closed): the inode is read from the process's own mappings, which the
// process can shape (it can unmap its executable and map another file at the same path text), and
// only stat() of /proc/<pid>/exe is authoritative but that can block on a hung mount, which is what
// the helper cap exists to avoid; so a hostile process can borrow another image's hash in the
// capped regime, where the alternative is an unknown. An inode number reused after the first process
// exits mid-action matches too. One action only; only a completed hash is stored. Pure.
#pragma once

#include "helper_budget.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::shared {

class ImagePathCache {
public:
    /// The identity of the executable in a COMPLETE /proc/<pid>/maps text: `<dev>:<inode>` shared by EVERY
    /// mapping whose pathname equals `exe_path` and whose " (deleted)" state equals `exe_deleted` (the
    /// readlink text of /proc/<pid>/exe says which). Empty (no caching) when no such mapping exists, when
    /// two such mappings disagree on device or inode (a second file mapped at the same path text, or a
    /// replacement mapped beside a deleted executable, must never be picked by address order), or when
    /// the text is off-shape. Reads no file. The caller must pass the WHOLE text: a prefix is not
    /// parsed (see `image_identity_of`).
    [[nodiscard]] static std::string maps_identity(std::string_view maps, std::string_view exe_path,
                                                   bool exe_deleted) {
        constexpr std::string_view kDeleted = " (deleted)";
        std::string found;
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
                if (rest.empty()) { ok = false; break; }
                const auto sp = rest.find(' ');
                fld = rest.substr(0, sp);
                rest = sp == std::string_view::npos ? std::string_view{} : rest.substr(sp);
            }
            if (!ok)
                continue;
            while (!rest.empty() && rest.front() == ' ')
                rest.remove_prefix(1);
            bool deleted = false;
            if (rest.size() >= kDeleted.size() && rest.substr(rest.size() - kDeleted.size()) == kDeleted) {
                rest.remove_suffix(kDeleted.size());
                deleted = true;
            }
            if (f[4] == "0" || rest != exe_path || deleted != exe_deleted)
                continue;
            std::string id{f[3]};
            id.push_back(':');
            id.append(f[4]);
            if (found.empty())
                found = std::move(id);
            else if (found != id)
                return {}; // two different files carry the executable's path text: ambiguous
        }
        return found;
    }
    /// Reads a source to EOF in chunks: `read(buf, len)` returns bytes read, 0 at EOF, negative on error.
    /// Returns nullopt on an error, when `expired()` is true before a read, or when more than `cap`
    /// bytes arrive: an INCOMPLETE text is never returned, because parsing a prefix of
    /// /proc/<pid>/maps could miss the executable's mapping or find a different one with the same path.
    template <typename ReadFn, typename ExpiredFn>
    [[nodiscard]] static std::optional<std::string> read_complete(ReadFn&& read, std::size_t cap,
                                                                  ExpiredFn&& expired) {
        std::string out;
        char buf[16384];
        for (;;) {
            if (expired())
                return std::nullopt;
            const auto n = read(buf, sizeof(buf));
            if (n < 0)
                return std::nullopt;
            if (n == 0)
                return out;
            out.append(buf, static_cast<std::size_t>(n));
            if (out.size() > cap)
                return std::nullopt;
        }
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

/// What a row's `compute()` returns: the hash (or marker) and whether it may be remembered. A hash
/// is `cacheable` only when its caller verified that the identity key matches the image that was
/// really opened and hashed (so a process that shapes its own maps cannot plant an entry).
struct RowHash {
    std::string hash;
    bool cacheable{false};
};

/// One row's hash. A row that MAY start a helper always hashes for real (the content cache keyed on
/// the opened image is authoritative) and a completed, `cacheable` hash is remembered under `key`. A
/// row that may NOT start a helper (the per-action cap or the action budget is reached) answers from
/// the cache when this action already hashed that identity, else reads the `skipped` marker. The key
/// comes from /proc/<pid>/maps, which the process itself can shape, so it is never trusted while a
/// real hash is possible.
template <typename Compute>
[[nodiscard]] std::string hash_row_cached(ImagePathCache& cache, const std::string& key, bool may_start,
                                          Compute&& compute) {
    if (!may_start) {
        if (const auto* hit = cache.find(key))
            return *hit;
        return std::string{kHashUnavailableSkipped};
    }
    RowHash r = std::forward<Compute>(compute)();
    if (r.cacheable)
        cache.put(key, r.hash);
    return std::move(r.hash);
}

} // namespace yuzu::shared
