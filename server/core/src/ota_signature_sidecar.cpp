#include "ota_signature_sidecar.hpp"

#include <fstream>
#include <iterator>
#include <system_error>
#include <string_view>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace yuzu::server {

std::filesystem::path signature_sidecar_path(const std::filesystem::path& binary) {
    auto p = binary;
    p += ".sig";
    return p;
}

SidecarOutcome read_signature_sidecar(const std::filesystem::path& sidecar, std::string& out) {
    out.clear();

    std::error_code exists_ec;
    const bool present = std::filesystem::exists(sidecar, exists_ec);
    if (exists_ec) {
        // A FAILED existence check is not an absence. EACCES or EIO on the parent
        // directory would otherwise read as "unsigned" silently, and under
        // --update-require-signature the fleet then refuses the package with no
        // server-side cause to point at.
        return SidecarOutcome::kUnreadable;
    }
    if (!present)
        return SidecarOutcome::kAbsent;

    // A SEPARATE error_code from the exists() call above: reusing one meant a
    // FAILED file_size left the cap branch unentered and fell through to an
    // unbounded read — the exact case the cap exists for.
    std::error_code size_ec;
    const auto size = std::filesystem::file_size(sidecar, size_ec);
    if (size_ec || size > kMaxSignatureBytes)
        return SidecarOutcome::kOverCap;

    std::ifstream in(sidecar, std::ios::binary);
    if (!in)
        return SidecarOutcome::kUnreadable;

    out.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (out.empty()) {
        // A zero-byte sidecar is NOT a signature. Served as-is it would put an
        // empty string on the wire, which the agent reads as ABSENT — so in
        // permissive mode it applies the binary UNVERIFIED while the operator's
        // Signed column, reading only existence, says "signed". Refuse it here so
        // both surfaces agree and the operator gets a log line.
        out.clear();
        return SidecarOutcome::kUnreadable;
    }
    return SidecarOutcome::kServed;
}

namespace {

/// Owns a raw descriptor for the duration of a scope.
///
/// There is exactly one acquire/release pair below with no branch between them
/// today, so this is not fixing a live leak — it is making the next edit safe.
/// An error-detail branch added between the open and the close is the ordinary
/// way this function grows, and it would leak silently.
class ScopedFd {
public:
    explicit ScopedFd(int fd) noexcept : fd_(fd) {}
    ~ScopedFd() {
        if (fd_ >= 0) {
#ifdef _WIN32
            ::_close(fd_);
#else
            ::close(fd_);
#endif
        }
    }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

private:
    int fd_;
};

/// Flush a file or directory all the way to stable storage.
///
/// `std::ofstream` has no portable fsync, and these artifacts are a security
/// control: a file that is "written" but not durable is indistinguishable from
/// one that was never written, and the package then serves as unsigned.
[[nodiscard]] bool fsync_path(const std::filesystem::path& p, bool is_directory) {
#ifdef _WIN32
    // Windows has no directory-handle flush through the CRT, and NTFS commits
    // directory metadata with the file, so the directory case is a no-op here
    // rather than a silent failure.
    if (is_directory)
        return true;
    // _O_WRONLY, NOT _O_RDONLY. `_commit` is FlushFileBuffers, which is documented
    // to require GENERIC_WRITE; a read-only handle fails with ERROR_ACCESS_DENIED.
    // Since a failed fsync fails the whole upload, getting this wrong made every
    // signed upload on a Windows-hosted server return 500 while unsigned uploads
    // kept working — the shape of breakage a smoke test walks straight past.
    // No _O_TRUNC: the file is already written and closed, we only need a handle.
    const ScopedFd fd(::_wopen(p.c_str(), _O_WRONLY | _O_BINARY));
    if (!fd.valid())
        return false;
    return ::_commit(fd.get()) == 0;
#else
    // O_RDONLY is sufficient for fsync on both files and directories, and is the
    // only mode a directory can be opened in — so POSIX needs no branch on the
    // kind, and the parameter exists purely for the Windows arm above.
    (void)is_directory;
    const ScopedFd fd(::open(p.c_str(), O_RDONLY));
    if (!fd.valid())
        return false;
    return ::fsync(fd.get()) == 0;
#endif
}


/// Remove the staging file only.
///
/// DELIBERATELY NOT the surviving predecessor. Enumerating the windows shows why:
/// old-binary + new-signature fails closed; new-binary + old-signature fails
/// closed; new-binary + NO signature is the one unsafe state, because a permissive
/// agent applies it UNVERIFIED. So destroying a signature must be an operator's
/// explicit choice to upload unsigned — never a failure recovery.
///
/// The concrete case: on Windows a concurrent CheckForUpdate holds the sidecar
/// open without FILE_SHARE_DELETE, so the rename fails with a sharing violation.
/// Removing the predecessor there would silently strip a VALID signature during
/// an ordinary re-upload, and permissive agents would then apply the new binary
/// unverified. Leaving it makes them refuse instead, which is the safe direction,
/// and the caller reports the failure so the operator knows to retry.
void discard_staging(const std::filesystem::path& tmp) {
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
}

} // namespace

SidecarOutcome signature_sidecar_outcome(const std::filesystem::path& sidecar) {
    // Deliberately delegates rather than duplicating the ladder: two copies of
    // "is this servable" is exactly how the column and the server came to
    // disagree in the first place. The discarded buffer is the price of one
    // decision site, and it is paid only on the settings fragment.
    std::string ignored;
    return read_signature_sidecar(sidecar, ignored);
}

bool fsync_file(const std::filesystem::path& path) {
    return fsync_path(path, /*is_directory=*/false);
}

bool signature_sidecar_covers_binary(const std::filesystem::path& binary,
                                     const std::filesystem::path& sidecar) {
    std::error_code sig_ec;
    const auto sig_time = std::filesystem::last_write_time(sidecar, sig_ec);
    if (sig_ec)
        return true; // no sidecar, or unreadable: not evidence of a mismatch

    std::error_code bin_ec;
    const auto bin_time = std::filesystem::last_write_time(binary, bin_ec);
    if (bin_ec)
        return true;

    return !(sig_time > bin_time);
}

bool looks_like_pem_cms(const std::string& signature_pem) {
    // Accept both armour spellings OpenSSL emits for a detached CMS signature:
    // `CMS` from `openssl cms -sign`, `PKCS7` from the older `smime`/`pkcs7`
    // tooling. Both are what `CMS_verify` consumes, so refusing either at upload
    // would reject signatures the agent would have accepted.
    static constexpr std::string_view kHeaders[] = {"-----BEGIN CMS-----",
                                                    "-----BEGIN PKCS7-----"};
    for (const auto header : kHeaders) {
        const auto begin = signature_pem.find(header);
        if (begin == std::string::npos)
            continue;
        // The matching footer must follow the header, so a file carrying only an
        // armour line, or a truncated upload, is still rejected.
        std::string footer("-----END ");
        footer.append(header.substr(std::string_view("-----BEGIN ").size()));
        return signature_pem.find(footer, begin + header.size()) != std::string::npos;
    }
    return false;
}

bool replace_signature_sidecar(const std::filesystem::path& sidecar,
                               const std::string& signature_pem) {
    if (signature_pem.empty()) {
        // Genuinely unsigned now: remove any predecessor. This is the case that
        // must never be skipped — see the header.
        //
        // REPORT A REAL REMOVAL FAILURE. Swallowing the error_code made this
        // return true unconditionally, so the caller's own failure branch was
        // dead code and a sidecar that could not be deleted — the Windows
        // sharing-violation case `discard_staging` cites — answered 200 while
        // every anchored agent refused the package. `remove` returning false with
        // no error means the file was already absent, which IS success here.
        std::error_code stale_ec;
        std::filesystem::remove(sidecar, stale_ec);
        return !stale_ec;
    }

    // REPLACE VIA RENAME, not remove-then-write. CheckForUpdate reads this path
    // concurrently, so a remove followed by a write publishes a window in which
    // the package is served UNSIGNED — brief, but an agent that polls inside it
    // is refused under --update-require-signature, and the operator sees a
    // spurious refusal with no cause to point at.
    //
    // ON POSIX the rename is atomic, so a reader sees either the old signature
    // or the new one and never neither. ON WINDOWS IT IS NOT: the STL's
    // replacement is documented as non-atomic for concurrent readers
    // (microsoft/STL#5501), which can transiently surface ERROR_FILE_NOT_FOUND.
    // `agent_service_impl` treats an absent sidecar as "no signature", so on a
    // Windows-hosted server a concurrent re-upload can still expose a narrow
    // unsigned window to an agent polling inside it — enforced-mode agents get a
    // spurious refusal, permissive-mode agents apply on the hash alone. Narrower
    // than remove-then-write, but not zero; closing it needs a publication
    // primitive with a proven cross-platform reader-visibility guarantee, which
    // this is not. Do not restate the POSIX guarantee as if it were universal.
    auto tmp = sidecar;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            discard_staging(tmp);
            return false;
        }
        out.write(signature_pem.data(), static_cast<std::streamsize>(signature_pem.size()));

        // CLOSE EXPLICITLY AND RE-TEST. Testing the stream before it is destroyed
        // checks only what reached the filebuf: anything still buffered is flushed
        // by ~ofstream, whose failure NOBODY can read. On a full disk that returned
        // success while renaming a ZERO-LENGTH file over a valid signature —
        // reproduced on a full ramdisk, and the exact "one unsafe state" the header
        // argues is unreachable by failure, since the package is then served
        // unsigned and permissive agents apply the new binary UNVERIFIED.
        out.close();
        if (!out) {
            discard_staging(tmp);
            return false;
        }
    }

    // Durability before publication. The rename is atomic with respect to a
    // concurrent READER, which is what the comment above is about, but atomic is
    // not durable: without this a crash shortly after an apparently-successful
    // upload can expose the renamed name pointing at unflushed (zero-length)
    // data — the same end state as the short write above, reached with no disk
    // pressure at all. Both the file and the DIRECTORY entry need syncing; a
    // failure here is a failure of the upload, not a warning.
    if (!fsync_path(tmp, /*is_directory=*/false)) {
        discard_staging(tmp);
        return false;
    }

    std::error_code ren_ec;
    std::filesystem::rename(tmp, sidecar, ren_ec);
    if (ren_ec) {
        discard_staging(tmp);
        return false;
    }

    // Sync the directory so the RENAME itself survives a crash. Deliberately not
    // fatal: at this point the sidecar is already in place and readable, so a
    // failure to sync the directory entry is strictly weaker than the states
    // above — reporting failure here would send the operator to recover a
    // package that is actually correct.
    (void)fsync_path(sidecar.parent_path(), /*is_directory=*/true);
    return true;
}

PackageDeleteAudit describe_package_delete(const PackageDeleteOutcome& outcome) {
    if (!outcome.matched) {
        // `denied` with the reason in `detail`, not a bespoke `not_found` result:
        // audit-log.md's probe-detection recipe tells operators to filter on
        // `result == "denied"`, so a fourth token would be invisible to exactly
        // the rule this row exists to feed.
        return {"denied", "not_found"};
    }

    const bool binary_failed = !outcome.binary_error.empty();
    const bool signature_failed = !outcome.signature_error.empty();
    if (binary_failed || signature_failed) {
        std::string detail = "registry row removed";
        if (binary_failed) {
            detail += "; binary delete failed: " + outcome.binary_error;
        }
        if (signature_failed) {
            detail += "; signature sidecar delete failed: " + outcome.signature_error;
        }
        return {"partial", detail};
    }

    // Distinguish "deleted it" from "it was not there": a package whose binary had
    // already been removed out of band is a different fact from one this call
    // deleted, and collapsing them hides the out-of-band removal.
    std::string detail = outcome.binary_removed ? "binary removed" : "binary already absent";
    detail += outcome.signature_removed ? ", signature sidecar removed"
                                        : ", signature sidecar already absent";
    return {"success", detail};
}

} // namespace yuzu::server
