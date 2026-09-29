#pragma once

// Handle/fd-scoped SHA-256 hashing (W2.2 / #807).
//
// `sha256_file` (plugin_loader.hpp) opens the path FRESHLY, which is the bug
// behind #807: between the hash and a later open of the same path an attacker
// who can write to the directory can swap the file content. These helpers hash
// from an ALREADY-OPEN fd/HANDLE, so a caller that has pinned the inode once
// (O_NOFOLLOW on POSIX, FILE_SHARE_READ + FILE_FLAG_OPEN_REPARSE_POINT on
// Windows) hashes exactly the bytes it pinned. macOS keeps a documented
// narrower race. The caller OWNS the fd/HANDLE lifetime; these functions seek
// to BEGIN and read, and never close it.
//
// Bounded by `max_bytes`: content that exceeds the cap (a growing / hostile
// file) is REFUSED (empty return) rather than hashed unbounded - the same
// bounded-read guard `sha256_file` carries, so the primitive is safe on the
// untrusted watched files the Guardian state reader hashes. (The refusal is
// checked per 64 KiB block, so up to one block may be read past the cap before
// it trips; the operation is byte-bounded, not literally "at most max_bytes".)
// Plugin-loader callers pass the default (SIZE_MAX), keeping their behaviour
// byte-identical.
//
// Returns lowercase hex SHA-256, or an empty string on any error (bad handle,
// seek/read failure, over-cap, crypto failure). errno / GetLastError is preserved
// across the spdlog::error line so callers retain the OS reason.
//
// Moved from plugin_loader.cpp's anonymous namespace (#807) so the Guardian spark
// state reader (guardian_state_reader.cpp) reuses the single hardened primitive
// instead of duplicating a security-sensitive hash loop; the only change from the
// original bodies is the `max_bytes` bounded-read cap (defaulted off).

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstddef> // std::size_t
#include <cstdint> // SIZE_MAX
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace yuzu::agent {

#ifdef _WIN32
/// Hash up to `max_bytes` of an open, readable file HANDLE (seeks to BEGIN
/// first); returns empty if the content exceeds the cap. The caller retains
/// ownership of the HANDLE.
[[nodiscard]] YUZU_EXPORT std::string sha256_from_handle(HANDLE h, std::size_t max_bytes = SIZE_MAX);
#else
/// Hash up to `max_bytes` of an open, readable file descriptor (seeks to BEGIN
/// first); returns empty if the content exceeds the cap. The caller retains
/// ownership of the fd.
[[nodiscard]] YUZU_EXPORT std::string sha256_from_fd(int fd, std::size_t max_bytes = SIZE_MAX);
#endif

} // namespace yuzu::agent
