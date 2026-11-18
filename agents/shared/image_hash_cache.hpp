// image_hash_cache.hpp -- a hash cache keyed on the IDENTITY of the opened image, never on path text.
//
// A process image is named by `readlink(/proc/<pid>/exe)` (or proc_pidpath): text a process can alias
// (a binary replaced after the first hash, a "(deleted)" path, a bind-mounted or namespace-different
// path with the same spelling, two pids with identical text and different images). Keying a cache on
// that text hands a later process the FIRST process's hash. The key here is taken from the fstat of
// the descriptor that was actually opened and is then hashed: device, inode, size and modification
// time in nanoseconds, so a file rewritten in place (same inode) is a different key too. The lookup
// therefore happens AFTER the open (cheap) and BEFORE the read (the expensive part).
#pragma once

#ifndef _WIN32

#include <sys/stat.h>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace yuzu::shared {

[[nodiscard]] inline std::string image_identity_key(const struct stat& st) {
#if defined(__APPLE__)
    const auto mtime_ns = static_cast<long long>(st.st_mtimespec.tv_sec) * 1000000000LL + st.st_mtimespec.tv_nsec;
#else
    const auto mtime_ns = static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
#endif
    return std::to_string(static_cast<unsigned long long>(st.st_dev)) + ":" +
           std::to_string(static_cast<unsigned long long>(st.st_ino)) + ":" +
           std::to_string(static_cast<long long>(st.st_size)) + ":" + std::to_string(mtime_ns);
}

/// Thread-safe (the hash runs on a bounded helper thread) and bounded (cleared when it reaches
/// `kMaxEntries`, so a host with thousands of distinct images cannot grow it without limit).
class ImageHashCache {
public:
    [[nodiscard]] std::optional<std::string> get(const std::string& key) const {
        std::lock_guard lock(mu_);
        const auto it = map_.find(key);
        return it == map_.end() ? std::nullopt : std::optional<std::string>(it->second);
    }
    void put(const std::string& key, const std::string& hash) {
        std::lock_guard lock(mu_);
        if (map_.size() >= kMaxEntries)
            map_.clear();
        map_[key] = hash;
    }

private:
    static constexpr std::size_t kMaxEntries = 8192;
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::string> map_;
};

} // namespace yuzu::shared

#endif // !_WIN32
