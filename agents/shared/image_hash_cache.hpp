// image_hash_cache.hpp -- a hash cache keyed on the IDENTITY of the opened image, never on path text.
//
// A process image is named by `readlink(/proc/<pid>/exe)` (or proc_pidpath): text a process can alias
// (a binary replaced after the first hash, a "(deleted)" path, a bind-mounted or namespace-different
// path with the same spelling, two pids with identical text and different images). Keying a cache on
// that text hands a later process the FIRST process's hash. The key here is taken from the fstat of
// the descriptor that was actually opened and is then hashed: device, inode, size and modification
// time and CHANGE time in nanoseconds. mtime and size are forgeable by the file's owner (a replaced
// binary padded to its old size, with utimensat() restoring the old mtime); ctime is not: only the
// kernel sets it, on every write, chmod, link and utimensat. The lookup happens AFTER the open
// (cheap) and BEFORE the read (the expensive part). Lifetime: a cache is created per ACTION and
// dropped with it (never a process-wide static), so an image replaced between two dispatches is
// always re-hashed and the key's residual (a same-nanosecond ctime) cannot outlive one action.
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
    // The seconds and nanoseconds fields are written separately: `sec * 1e9 + nsec` overflows a signed
    // 64-bit value for a far-future timestamp (undefined behaviour), and a wrapped value could make two
    // different timestamps collide.
#if defined(__APPLE__)
    const auto m_sec = static_cast<long long>(st.st_mtimespec.tv_sec);
    const auto m_nsec = static_cast<long long>(st.st_mtimespec.tv_nsec);
    const auto c_sec = static_cast<long long>(st.st_ctimespec.tv_sec);
    const auto c_nsec = static_cast<long long>(st.st_ctimespec.tv_nsec);
#else
    const auto m_sec = static_cast<long long>(st.st_mtim.tv_sec);
    const auto m_nsec = static_cast<long long>(st.st_mtim.tv_nsec);
    const auto c_sec = static_cast<long long>(st.st_ctim.tv_sec);
    const auto c_nsec = static_cast<long long>(st.st_ctim.tv_nsec);
#endif
    return std::to_string(static_cast<unsigned long long>(st.st_dev)) + ":" +
           std::to_string(static_cast<unsigned long long>(st.st_ino)) + ":" +
           std::to_string(static_cast<long long>(st.st_size)) + ":" + std::to_string(m_sec) + "." +
           std::to_string(m_nsec) + ":" + std::to_string(c_sec) + "." + std::to_string(c_nsec);
}

/// Thread-safe (the hash runs on a bounded helper thread) and bounded (cleared when it reaches
/// `kMaxEntries`, so a host with thousands of distinct images cannot grow it without limit). Own one
/// per action (see the banner); never a static.
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
