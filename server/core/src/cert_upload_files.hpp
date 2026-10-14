#pragma once

/// Disk writes behind the Settings cert-upload / cert-paste routes.
///
/// The TLS server PRIVATE KEY goes through FileKeyProvider (one custody
/// primitive for every private key file the server writes: exclusive-create
/// 0600 temp -> fsync -> rename; owner-only DACL on Windows), so it is never
/// visible at a looser mode, not even for the instant between create and a
/// later chmod. The certificate and CA bundle are public and keep a plain
/// write.

#include "key_provider.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#ifndef _WIN32
#include <cerrno>
#include <sys/stat.h>
#endif

namespace yuzu::server::cert_upload {

/// Create `dir` (and missing parents). On POSIX the leaf is created with mkdir(2) mode 0700,
/// so it is never visible at a wider mode; parents keep the default mode. An existing
/// directory is left as the operator/installer set it. On Windows this is create_directories
/// (the key FILE carries its own owner-only DACL from creation).
inline void create_cert_dir(const std::filesystem::path& dir, std::error_code& ec) {
#ifndef _WIN32
    ec.clear();
    std::error_code probe_ec; // a missing path is the expected case, not an error
    if (std::filesystem::is_directory(dir, probe_ec))
        return;
    if (dir.has_parent_path()) {
        std::filesystem::create_directories(dir.parent_path(), ec);
        if (ec)
            return;
    }
    if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST)
        ec = std::error_code(errno, std::generic_category());
#else
    std::filesystem::create_directories(dir, ec);
#endif
}

/// Write `content` as `<dir>/<name>`. `is_key` selects the private-key path.
[[nodiscard]] inline bool write_cert_file(const std::filesystem::path& dir, const std::string& name,
                                          bool is_key, const std::string& content) {
    if (is_key)
        return FileKeyProvider{dir}.store_named_file(name, content);
    std::ofstream f(dir / name, std::ios::binary | std::ios::trunc);
    if (!f.is_open())
        return false;
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    f.flush();
    return f.good(); // a short write / disk-full must not read as a successful upload
}

} // namespace yuzu::server::cert_upload
