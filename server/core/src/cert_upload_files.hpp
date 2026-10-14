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

#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

namespace yuzu::server::cert_upload {

/// create_directories, plus 0700 when THIS call created the leaf directory
/// (POSIX). An existing directory is left as the operator/installer set it.
inline void create_cert_dir(const std::filesystem::path& dir, std::error_code& ec) {
    const bool created = std::filesystem::create_directories(dir, ec);
#ifndef _WIN32
    if (!ec && created) {
        std::error_code perm_ec;
        std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace, perm_ec);
        if (perm_ec)
            spdlog::warn("cert upload: could not set 0700 on {}: {}", dir.string(),
                         perm_ec.message());
    }
#else
    (void)created;
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
    return true;
}

} // namespace yuzu::server::cert_upload
