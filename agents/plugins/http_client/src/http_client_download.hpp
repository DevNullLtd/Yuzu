// http_client_download.hpp -- the pure half of http_client.download: when is a fetched body a COMPLETE,
// acceptable download, and what happens to the destination. No sockets and no httplib, so the unit
// suite drives every branch on every host (a download over loopback is refused by the SSRF guard, so
// the real action cannot be exercised against a local server).
//
// Contract (the plugin README states the same):
//   * nothing touches the destination until the body is judged complete and, when expected_hash is
//     given, verified; a failed, non-2xx, over-cap, truncated or unverified transfer writes NOTHING
//     and leaves an existing destination exactly as it was;
//   * COMPLETE means: an expected_hash verifies it, or the response declared its length
//     (Content-Length, or chunked framing that httplib verifies) and the body matches; a body with
//     neither is refused, because a close-delimited body cut short is indistinguishable from a
//     finished one;
//   * the replacement is one atomic rename (atomic_file_write.hpp). It replaces a symlink or a
//     hard-linked destination with a new regular file instead of writing through it.
#pragma once

#include <atomic_file_write.hpp>
#include <sha256.hpp>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace yuzu::http_client {

struct DownloadObservation {
    bool https_unsupported{false}; ///< https URL on a build without OpenSSL
    bool out_of_memory{false};     ///< the body buffer could not be allocated
    bool size_exceeded{false};     ///< over the cap (declared or counted)
    int rejected_status{0};        ///< non-2xx status the response handler aborted on (0 = none)
    bool transport_ok{false};      ///< httplib returned a result
    int final_status{0};           ///< the result's status (only when transport_ok)
    bool has_length{false};        ///< a parseable Content-Length was declared
    bool chunked{false};           ///< chunked transfer coding (httplib verifies the framing)
    std::uint64_t declared_length{0};
    std::uint64_t body_size{0};
    bool hash_will_verify{false};  ///< an expected_hash was supplied
};

/// Empty when the observation is a complete, acceptable body; otherwise the operator-facing reason.
[[nodiscard]] inline std::string download_failure(const DownloadObservation& o) {
    if (o.https_unsupported)
        return "HTTPS not supported (OpenSSL not available)";
    if (o.out_of_memory)
        return "download aborted: out of memory";
    if (o.size_exceeded)
        return "download aborted: exceeded maximum size limit (100 MB)";
    if (o.rejected_status != 0)
        return "download failed: HTTP " + std::to_string(o.rejected_status);
    if (!o.transport_ok)
        return "download failed: HTTP connection error";
    if (o.final_status < 200 || o.final_status >= 300)
        return "download failed: HTTP " + std::to_string(o.final_status);
    if (o.has_length && o.body_size != o.declared_length)
        return "download incomplete: body shorter than Content-Length";
    if (!o.has_length && !o.chunked && !o.hash_will_verify)
        return "download not verifiable: the response has no Content-Length and no expected_hash "
               "was given, so a truncated body cannot be told from a complete one";
    return {};
}

enum class FinalizeStatus : std::uint8_t { ok, hash_mismatch, write_failed };

struct FinalizeResult {
    FinalizeStatus status{FinalizeStatus::write_failed};
    std::string hash;    ///< lowercase hex SHA-256 of the body
    std::string message; ///< write failure text
};

/// Hash `body`, compare with `expected_hash` (case-insensitive hex; empty = no pin) and, only if it
/// matches, atomically replace `dest` (0666 under the umask, carrying an existing file's rwx bits).
[[nodiscard]] inline FinalizeResult finalize_download(std::string_view body,
                                                      std::string_view expected_hash,
                                                      const std::filesystem::path& dest) {
    FinalizeResult r;
    yuzu::shared::Sha256 hasher;
    hasher.update(body.data(), body.size());
    r.hash = hasher.hex_digest();

    std::string expected{expected_hash};
    for (auto& c : expected)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    if (!expected.empty() && r.hash != expected) {
        r.status = FinalizeStatus::hash_mismatch;
        return r;
    }
    const auto written = yuzu::shared::write_file_atomic(dest, body, {.owner_only_mode = false});
    if (!written) {
        r.status = FinalizeStatus::write_failed;
        r.message = written.error().message;
        return r;
    }
    r.status = FinalizeStatus::ok;
    return r;
}

} // namespace yuzu::http_client
