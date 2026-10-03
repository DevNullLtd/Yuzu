#pragma once

// Read a secret (a Postgres connection string, an OIDC client secret) from a
// file named on the command line, instead of taking the secret itself on the
// command line (#5272).
//
// Why a file: a service's command line is readable by any local user. On
// Windows the YuzuServer service's ImagePath (its binary path) and its registry
// Environment value are both readable by local users, so a password passed as
// --postgres-dsn or --oidc-client-secret is disclosed to everyone on the host.
// The installer instead writes the secret into the locked data directory and
// passes only the file's path. The same flag serves the Docker/Kubernetes
// secret-file convention on Linux (/run/secrets/...).
//
// The file's own permissions are NOT checked: a Docker secret is mounted 0444,
// and refusing that would break the standard path. Protecting the file is the
// job of the directory it lives in (on Windows, the installer's locked data
// directory, verified at install time).
//
// Error messages name the file and the problem, never the contents.

#include <cstddef>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Larger than any real connection string or client secret; a bigger file is
/// almost certainly the wrong path, and is refused rather than read.
inline constexpr std::size_t kMaxSecretFileBytes = 64 * 1024;

/// The secret in `path`: the whole file, minus a leading UTF-8 byte-order mark
/// and trailing whitespace (so a file written by an editor, PowerShell or
/// `echo` with its final newline is accepted). Interior content is kept
/// byte-for-byte. Fails on an unreadable, oversized or (after trimming) empty
/// file. `flag` names the option in the error, e.g. "--postgres-dsn-file".
[[nodiscard]] inline std::expected<std::string, std::string>
read_secret_file(const std::filesystem::path& path, std::string_view flag) {
    const std::string where = std::string(flag) + " '" + path.string() + "'";

    std::error_code ec;
    const auto status = std::filesystem::status(path, ec);
    if (ec || !std::filesystem::exists(status))
        return std::unexpected(where + ": the file does not exist or cannot be accessed");
    if (!std::filesystem::is_regular_file(status))
        return std::unexpected(where + ": not a regular file");
    const auto size = std::filesystem::file_size(path, ec);
    if (ec)
        return std::unexpected(where + ": its size could not be read");
    if (size > kMaxSecretFileBytes)
        return std::unexpected(where + ": larger than " + std::to_string(kMaxSecretFileBytes) +
                               " bytes, so it is not a secret file");

    std::ifstream in(path, std::ios::binary);
    if (!in)
        return std::unexpected(where + ": could not be opened for reading");
    std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    if (in.bad())
        return std::unexpected(where + ": could not be read");
    // Re-check after reading: the file may have grown since file_size().
    if (text.size() > kMaxSecretFileBytes)
        return std::unexpected(where + ": larger than " + std::to_string(kMaxSecretFileBytes) +
                               " bytes, so it is not a secret file");

    constexpr std::string_view kBom = "\xEF\xBB\xBF";
    if (text.starts_with(kBom))
        text.erase(0, kBom.size());
    const auto end = text.find_last_not_of(" \t\r\n");
    text.erase(end == std::string::npos ? 0 : end + 1);
    if (text.empty())
        return std::unexpected(where + ": the file is empty");
    return text;
}

} // namespace yuzu::server
