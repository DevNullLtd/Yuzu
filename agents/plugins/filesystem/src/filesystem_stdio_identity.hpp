#pragma once

/// @file filesystem_stdio_identity.hpp
/// POSIX only. The agent's own stdout and stderr can be a regular file: launchd's StandardErrorPath
/// (macOS) and systemd's StandardOutput=file: send the process's log lines to a file the log-file
/// rule does not name (`yuzu-agent.stderr.log`). A caller must not read those bytes through the
/// filesystem plugin either, so a candidate that is the SAME FILE (st_dev and st_ino) as an open
/// regular-file descriptor 1 or 2 is refused as the agent's own log.

#ifndef _WIN32

#include <sys/stat.h>

#include <filesystem>

namespace yuzu::filesystem::reserved {

/// True when `path` names the same file as the open descriptor `fd`, and `fd` is a regular file.
/// Any failure to stat either answers false (the other reserved legs still apply).
[[nodiscard]] inline bool is_same_file_as_open_fd(const std::filesystem::path& path, int fd) {
    struct stat fst{};
    if (::fstat(fd, &fst) != 0 || !S_ISREG(fst.st_mode))
        return false;
    struct stat pst{};
    if (::stat(path.c_str(), &pst) != 0)
        return false;
    return pst.st_dev == fst.st_dev && pst.st_ino == fst.st_ino;
}

/// True for the agent's own stdout or stderr when either is a regular file.
[[nodiscard]] inline bool is_agent_stdio_file(const std::filesystem::path& path) {
    return is_same_file_as_open_fd(path, 1) || is_same_file_as_open_fd(path, 2);
}

} // namespace yuzu::filesystem::reserved

#endif
