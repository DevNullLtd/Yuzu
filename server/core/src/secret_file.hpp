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
    // Read at most one byte past the cap: the path may have been swapped for
    // something unbounded (a FIFO, a device) since the checks above.
    std::string text(kMaxSecretFileBytes + 1, '\0');
    in.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (in.bad())
        return std::unexpected(where + ": could not be read");
    text.resize(static_cast<std::size_t>(in.gcount()));
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

/// One --x-file / --x pair: when `file` is given, read it into `target`.
/// Refuses (returns the reason) when `target` already holds a value -- from
/// the direct option or its environment variable -- so a secret is never
/// silently taken from two places. Returns "" on success or when `file` is
/// empty. `file_flag` and `direct` name the options in the message.
[[nodiscard]] inline std::string resolve_secret_file_option(const std::string& file,
                                                            std::string& target,
                                                            std::string_view file_flag,
                                                            std::string_view direct) {
    if (file.empty())
        return {};
    if (!target.empty())
        return std::string(file_flag) + " cannot be combined with " + std::string(direct) +
               " (set on the command line or in the environment); use one of them";
    auto secret = read_secret_file(file, file_flag);
    if (!secret)
        return secret.error();
    target = std::move(*secret);
    return {};
}

} // namespace yuzu::server
