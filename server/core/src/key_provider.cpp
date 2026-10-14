#include "key_provider.hpp"

#include "aes_gcm.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <spdlog/spdlog.h>

#include <cstddef>
#include <fstream>
#include <random>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace yuzu::server {

namespace fs = std::filesystem;

namespace {

// A private key PEM is never legitimately large; cap it to bound a hostile or
// buggy caller (disk / memory DoS).
constexpr std::size_t kMaxKeyPemSize = 1024 * 1024;

// Set owner-only (0600) permissions on a file.
void set_owner_only_file(const fs::path& p) {
    std::error_code ec;
    fs::permissions(p, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace,
                    ec);
    if (ec)
        spdlog::warn("key_provider: could not set 0600 on {}: {}", p.string(), ec.message());
#ifdef _WIN32
        // POSIX mode bits are advisory on Windows. The real custody control is
        // the explicit, PROTECTED owner-only DACL applied in write_file_atomic
        // (WinOwnerOnlyDacl) to both the key directory and the key file — that
        // is what excludes `Users`/`Everyone` (ADR-0010 §Decision 2). This
        // fs::permissions call is left as a harmless best-effort no-op.
#endif
}

// Collision-avoidance suffix for the temp file. NOT a security boundary —
// O_EXCL on create is what defeats a planted-path attack. Drawn straight from
// random_device (rather than a single-seeded mt19937_64) for better per-call
// entropy.
std::string random_suffix() {
    std::random_device rd;
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (int i = 0; i < 4; ++i) {
        uint32_t v = rd();
        for (int j = 0; j < 8; ++j) {
            s += kHex[v & 0xF];
            v >>= 4;
        }
    }
    return s;
}

// Read exactly `n` bytes from `p` straight into `dst`, bypassing any
// std::ifstream/filebuf heap buffer that would retain an unzeroized transient
// copy of the key material (S4; ADR-0010 §Decision 2 — "the zeroization rule
// covers every KEK representation"). The write path already uses raw FDs for
// the same reason; the KEK read path now matches. Returns true iff exactly `n`
// bytes were read (a short or over-long file fails).
[[nodiscard]] bool read_exact(const fs::path& p, std::uint8_t* dst, std::size_t n) {
#ifndef _WIN32
    const int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    std::size_t off = 0;
    bool ok = true;
    while (off < n) {
        const ssize_t r = ::read(fd, dst + off, n - off);
        if (r < 0 && errno == EINTR)
            continue; // benign signal interruption — retry
        if (r <= 0) { // error or premature EOF
            ok = false;
            break;
        }
        off += static_cast<std::size_t>(r);
    }
    (void)::close(fd);
    return ok && off == n;
#else
    const HANDLE h = ::CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    std::size_t off = 0;
    bool ok = true;
    while (off < n) {
        DWORD got = 0;
        const DWORD want =
            (n - off) > 0x0FFFFFFF ? 0x0FFFFFFF : static_cast<DWORD>(n - off);
        if (!::ReadFile(h, dst + off, want, &got, nullptr)) {
            ok = false;
            break;
        }
        if (got == 0) { // premature EOF
            ok = false;
            break;
        }
        off += got;
    }
    (void)::CloseHandle(h);
    return ok && off == n;
#endif
}

#ifdef _WIN32
// Owner-only, PROTECTED DACL for the secrets KEK + CA key files and their
// directory (S1; ADR-0010 §Decision 2 — on Windows the equivalent of POSIX
// 0600/0700 is "a restrictive DACL granting only the service account").
//
// The bug this fixes: CreateFileW with a null lpSecurityAttributes lets the
// new key file INHERIT the parent directory's ambient ACL — on a default
// install `Users`/`Everyone` may have read access to the 32-byte KEK. The fix
// is an explicit DACL granting FILE_ALL_ACCESS to the running account (the
// service account), SYSTEM, and the local Administrators group, and nothing to
// Users/Everyone, marked SE_DACL_PROTECTED so broader inheritable parent ACEs
// are NOT merged. Callers FAIL CLOSED when ok() is false — never silently fall
// back to ambient ACLs.
class WinOwnerOnlyDacl {
public:
    WinOwnerOnlyDacl() { build(); }
    ~WinOwnerOnlyDacl() {
        if (acl_ != nullptr)
            ::LocalFree(acl_);
        if (admins_ != nullptr)
            ::FreeSid(admins_);
        if (system_ != nullptr)
            ::FreeSid(system_);
        // The user SID lives inside token_user_buf_ — no separate free.
    }
    WinOwnerOnlyDacl(const WinOwnerOnlyDacl&) = delete;
    WinOwnerOnlyDacl& operator=(const WinOwnerOnlyDacl&) = delete;

    [[nodiscard]] bool ok() const { return ok_; }

    // SECURITY_ATTRIBUTES for CreateFileW: the explicit, protected DACL gives
    // the new file an owner-only ACL from creation (no inheritance window).
    [[nodiscard]] SECURITY_ATTRIBUTES* sa() { return ok_ ? &sa_ : nullptr; }

    // Apply the protected DACL to an existing path (directory or file).
    [[nodiscard]] bool apply_to(const std::wstring& path) {
        if (!ok_)
            return false;
        std::wstring mutable_path = path; // SetNamedSecurityInfoW takes a mutable LPWSTR
        const DWORD rc = ::SetNamedSecurityInfoW(
            mutable_path.data(), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl_,
            nullptr);
        return rc == ERROR_SUCCESS;
    }

private:
    void build() {
        HANDLE token = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
            return;
        DWORD len = 0;
        ::GetTokenInformation(token, TokenUser, nullptr, 0, &len); // size probe
        if (len == 0) {
            ::CloseHandle(token);
            return;
        }
        token_user_buf_.resize(len);
        if (!::GetTokenInformation(token, TokenUser, token_user_buf_.data(), len, &len)) {
            ::CloseHandle(token);
            return;
        }
        ::CloseHandle(token);
        PSID user_sid = reinterpret_cast<TOKEN_USER*>(token_user_buf_.data())->User.Sid;

        SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        if (!::AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0,
                                        &system_))
            return;
        if (!::AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins_))
            return;

        EXPLICIT_ACCESS_W ea[3] = {};
        const auto grant = [](EXPLICIT_ACCESS_W& e, PSID sid) {
            e.grfAccessPermissions = FILE_ALL_ACCESS;
            e.grfAccessMode = SET_ACCESS;
            e.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            e.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            e.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            e.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid);
        };
        grant(ea[0], user_sid);
        grant(ea[1], system_);
        grant(ea[2], admins_);
        if (::SetEntriesInAclW(3, ea, nullptr, &acl_) != ERROR_SUCCESS) {
            acl_ = nullptr;
            return;
        }

        if (!::InitializeSecurityDescriptor(&sd_, SECURITY_DESCRIPTOR_REVISION))
            return;
        if (!::SetSecurityDescriptorDacl(&sd_, TRUE, acl_, FALSE))
            return;
        // PROTECTED: a new file created with this SD does NOT merge broader
        // inheritable ACEs from the parent — the actual inheritance-gap fix.
        if (!::SetSecurityDescriptorControl(&sd_, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
            return;
        sa_.nLength = sizeof(sa_);
        sa_.bInheritHandle = FALSE;
        sa_.lpSecurityDescriptor = &sd_;
        ok_ = true;
    }

    std::vector<std::uint8_t> token_user_buf_;
    PSID system_ = nullptr;
    PSID admins_ = nullptr;
    PACL acl_ = nullptr;
    SECURITY_DESCRIPTOR sd_ = {};
    SECURITY_ATTRIBUTES sa_ = {};
    bool ok_ = false;
};
#endif // _WIN32

} // namespace

FileKeyProvider::FileKeyProvider(fs::path base_dir) : base_dir_(std::move(base_dir)) {}

bool FileKeyProvider::is_safe_key_id(std::string_view key_id) {
    if (key_id.empty() || key_id.size() > 128)
        return false;
    if (key_id == "." || key_id == "..")
        return false;
    for (char c : key_id) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

bool FileKeyProvider::within_base(const fs::path& p) const {
    std::error_code ec;
    const fs::path base = fs::weakly_canonical(base_dir_, ec);
    if (ec)
        return false;
    const fs::path cand = fs::weakly_canonical(p, ec);
    if (ec)
        return false;
    // cand must start with base.
    auto bi = base.begin();
    auto ci = cand.begin();
    for (; bi != base.end(); ++bi, ++ci) {
        if (ci == cand.end() || *ci != *bi)
            return false;
    }
    return true;
}

fs::path FileKeyProvider::path_for(std::string_view key_id) const {
    return base_dir_ / (std::string(key_id) + ".key");
}

std::optional<std::string> FileKeyProvider::store_key(std::string_view key_id,
                                                      std::string_view pem) {
    if (!is_safe_key_id(key_id)) {
        spdlog::error("key_provider: rejected unsafe key_id '{}'", std::string(key_id));
        return std::nullopt;
    }
    if (pem.empty()) {
        spdlog::error("key_provider: refusing to store empty key '{}'", std::string(key_id));
        return std::nullopt;
    }
    if (pem.size() > kMaxKeyPemSize) {
        spdlog::error("key_provider: refusing oversized key '{}' ({} bytes)", std::string(key_id),
                      pem.size());
        return std::nullopt;
    }

    const fs::path dest = path_for(key_id);
    if (!write_file_atomic(key_id, dest,
                           {reinterpret_cast<const std::uint8_t*>(pem.data()), pem.size()}))
        return std::nullopt;

    spdlog::info("key_provider: stored key '{}' (0600)", std::string(key_id));
    return dest.string();
}

bool FileKeyProvider::store_named_file(std::string_view file_name, std::string_view bytes) {
    if (!is_safe_key_id(file_name)) {
        spdlog::error("key_provider: rejected unsafe file name '{}'", std::string(file_name));
        return false;
    }
    if (bytes.empty() || bytes.size() > kMaxKeyPemSize) {
        spdlog::error("key_provider: refusing empty/oversized file '{}' ({} bytes)",
                      std::string(file_name), bytes.size());
        return false;
    }
#ifdef _WIN32
    // Windows has no --cert-group sharing, and this directory already carries
    // the owner-only DACL from the CA/KEK custody that writes into it at boot,
    // so applying it again is the existing posture, not a new narrowing.
    constexpr bool kTightenExistingDir = true;
#else
    // A pre-existing directory may be deliberately 0750 + group (--cert-group).
    constexpr bool kTightenExistingDir = false;
#endif
    return write_file_atomic(file_name, base_dir_ / std::string(file_name),
                             {reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()},
                             kTightenExistingDir);
}

bool FileKeyProvider::write_file_atomic(std::string_view key_id, const fs::path& dest,
                                        std::span<const std::uint8_t> bytes,
                                        bool tighten_existing_dir) {
    std::error_code ec;
    const bool dir_created = fs::create_directories(base_dir_, ec);
    if (ec) {
        spdlog::error("key_provider: cannot create {}: {}", base_dir_.string(), ec.message());
        return false;
    }
    // Owner-only directory so the brief pre-chmod window on the temp file is not
    // exposed to other local users.
    if (tighten_existing_dir || dir_created) {
        fs::permissions(base_dir_, fs::perms::owner_all, fs::perm_options::replace, ec);
        if (ec)
            spdlog::warn("key_provider: could not set 0700 on {}: {}", base_dir_.string(),
                         ec.message()); // UP-13: files are 0600, so exposure is listing-only
    }

#ifdef _WIN32
    // POSIX mode bits are advisory on Windows; the real owner-only control is
    // an explicit PROTECTED DACL on the directory + key file (S1; ADR-0010
    // §Decision 2). Build it once, apply to the directory now (so the temp
    // file does not inherit an ambient parent ACL even before its own DACL is
    // set), and FAIL CLOSED if it cannot be built/applied — never write key
    // material under an inherited ACL.
    WinOwnerOnlyDacl dacl;
    if (!dacl.ok()) {
        spdlog::error("key_provider: could not build owner-only DACL — refusing to write key "
                      "file (ADR-0010 §Decision 2 Windows key custody)");
        return false;
    }
    if (!dacl.apply_to(base_dir_.wstring())) {
        spdlog::error("key_provider: could not apply owner-only DACL to {} (err {}) — refusing",
                      base_dir_.string(), ::GetLastError());
        return false;
    }
#endif

    const fs::path tmp = base_dir_ / (std::string(key_id) + ".key.tmp." + random_suffix());

#ifndef _WIN32
    {
        // Manual fd close is deliberate here (documented RAII exception): the
        // checked close return feeds the durability verdict — a guard that
        // closes on unwind would swallow it — and there is no throwing
        // operation between open and close.
        //
        // Create the temp file mode 0600 from the outset — no umask window where
        // the private key is group/other-readable. O_EXCL refuses to reuse an
        // attacker-planted path.
        const int fd = ::open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) {
            spdlog::error("key_provider: open temp {} failed: {}", tmp.string(),
                          std::strerror(errno));
            return false;
        }
        const std::uint8_t* p = bytes.data();
        std::size_t remaining = bytes.size();
        bool ok = true;
        while (remaining > 0) {
            const ssize_t n = ::write(fd, p, remaining);
            if (n < 0 && errno == EINTR)
                continue; // benign signal interruption — retry the write
            if (n <= 0) {
                ok = false;
                break;
            }
            p += n;
            remaining -= static_cast<std::size_t>(n);
        }
        // fsync before rename (ADR-0010 §2 "Atomic write"): power loss after
        // the rename must never reveal a torn file that "resolves" but fails
        // every decrypt as pseudo-tamper. On Darwin fsync only reaches the
        // drive cache; F_FULLFSYNC is the durable form (fall back where the
        // volume rejects it).
#ifdef __APPLE__
        if (ok && ::fcntl(fd, F_FULLFSYNC) != 0 && ::fsync(fd) != 0)
            ok = false;
#else
        if (ok && ::fsync(fd) != 0)
            ok = false;
#endif
        if (::close(fd) != 0)
            ok = false;
        if (!ok) {
            spdlog::error("key_provider: write failed for {}", tmp.string());
            fs::remove(tmp, ec);
            return false;
        }
    }
#else
    {
        // CREATE_NEW = the O_EXCL analogue; FlushFileBuffers = the fsync
        // analogue. Wide-char API: fs::path is wchar_t on Windows and
        // path::string() converts through the ANSI code page (garbles
        // non-ASCII base dirs); path::c_str() is already wchar_t*. The
        // explicit owner-only PROTECTED DACL (dacl.sa()) gives the new file an
        // owner-only ACL from creation — no inheritance window where
        // `Users`/`Everyone` could read the key (S1; ADR-0010 §Decision 2).
        // Manual CloseHandle is the same documented RAII exception as the
        // POSIX branch (checked close feeds the durability verdict).
        const HANDLE h = ::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, dacl.sa(), CREATE_NEW,
                                       FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            spdlog::error("key_provider: cannot open temp {} (err {})", tmp.string(),
                          ::GetLastError());
            return false;
        }
        const std::uint8_t* p = bytes.data();
        std::size_t remaining = bytes.size();
        bool ok = true;
        while (remaining > 0) {
            DWORD written = 0;
            const DWORD chunk = remaining > 0x0FFFFFFF ? 0x0FFFFFFF : static_cast<DWORD>(remaining);
            if (!::WriteFile(h, p, chunk, &written, nullptr) || written == 0) {
                ok = false;
                break;
            }
            p += written;
            remaining -= written;
        }
        if (ok && !::FlushFileBuffers(h))
            ok = false;
        if (!::CloseHandle(h))
            ok = false;
        if (!ok) {
            spdlog::error("key_provider: write failed for {}", tmp.string());
            fs::remove(tmp, ec);
            return false;
        }
    }
#endif
    set_owner_only_file(tmp); // POSIX: re-assert 0600; Windows: no-op (DACL set at creation)

    fs::rename(tmp, dest, ec); // same-directory rename is atomic on POSIX + Windows
    if (ec) {
        spdlog::error("key_provider: rename {} -> {} failed: {}", tmp.string(), dest.string(),
                      ec.message());
        fs::remove(tmp, ec);
        return false;
    }
    set_owner_only_file(dest); // re-assert in case rename reset perms
#ifdef _WIN32
    // The temp file already carried the owner-only DACL through the rename;
    // re-assert on the final path as belt-and-braces (warn, not fail — the
    // material is already written with the correct ACL).
    if (!dacl.apply_to(dest.wstring()))
        spdlog::warn("key_provider: could not re-apply owner-only DACL to {} after rename (err {})",
                     dest.string(), ::GetLastError());
#endif

#ifndef _WIN32
    // Make the RENAME durable, not just the file contents (governance
    // sec-M2): without a directory fsync, power loss after the caller
    // records the key's fingerprint can lose the dirent entirely —
    // kek_unresolvable at next boot. Windows has no std-expressible
    // equivalent (it would need MoveFileEx(MOVEFILE_WRITE_THROUGH), which
    // std::filesystem::rename cannot request); FlushFileBuffers above plus
    // NTFS metadata journaling is the available posture there.
    {
        // Failure here propagates (governance LOW-1): the rename has already
        // happened, so the caller treats this as a failed store — for
        // generate_kek that means no fingerprint is registered, and the next
        // boot safely ADOPTS the on-disk file instead of orphaning it.
        bool dir_synced = false;
        const int dfd = ::open(base_dir_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) {
#ifdef __APPLE__
            dir_synced = ::fcntl(dfd, F_FULLFSYNC) == 0 || ::fsync(dfd) == 0;
#else
            dir_synced = ::fsync(dfd) == 0;
#endif
            (void)::close(dfd);
        }
        if (!dir_synced) {
            spdlog::error("key_provider: could not fsync {} after rename: {}", base_dir_.string(),
                          std::strerror(errno));
            return false;
        }
    }
#endif
    return true;
}

std::optional<std::string> FileKeyProvider::load_key(std::string_view key_ref) {
    const fs::path p{key_ref};
    if (!within_base(p)) {
        spdlog::error("key_provider: refusing to load key_ref outside base: {}",
                      std::string(key_ref));
        return std::nullopt;
    }
    std::error_code sz_ec;
    const auto sz = fs::file_size(p, sz_ec);
    if (!sz_ec && sz > kMaxKeyPemSize) {
        spdlog::error("key_provider: key file {} too large ({} bytes)", p.string(), sz);
        return std::nullopt;
    }
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        spdlog::error("key_provider: cannot open key {}", p.string());
        return std::nullopt;
    }
    std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (pem.empty()) {
        spdlog::error("key_provider: empty key file {}", p.string());
        return std::nullopt;
    }
    return pem;
}

bool FileKeyProvider::has_key(std::string_view key_ref) {
    const fs::path p{key_ref};
    if (!within_base(p))
        return false;
    std::error_code ec;
    return fs::exists(p, ec) && !ec;
}

bool FileKeyProvider::delete_key(std::string_view key_ref) {
    // Hold kek_mutex_ across BOTH the file removal and the cache eviction:
    // evicting first (or unlocked) lets a concurrent wrap_dek cache-miss
    // re-read the still-present file and resurrect a retired KEK in memory
    // (governance safety-S1; ADR-0010 §3 retirement). The lock also covers
    // plain CA-PEM deletes — harmless, they share no cache entries.
    std::lock_guard lock{kek_mutex_};
    const fs::path p{key_ref};
    if (!within_base(p)) {
        spdlog::error("key_provider: refusing to delete key_ref outside base: {}",
                      std::string(key_ref));
        return false;
    }
    std::error_code rm_ec;
    fs::remove(p, rm_ec);
    std::error_code ex_ec;
    if (rm_ec && fs::exists(p, ex_ec)) {
        spdlog::error("key_provider: delete {} failed: {}", p.string(), rm_ec.message());
        return false;
    }
    if (fs::exists(p, ex_ec))
        return false;
    if (auto it = kek_cache_.find(key_ref); it != kek_cache_.end())
        kek_cache_.erase(it); // SecureBuffer dtor cleanses
    return true;
}

bool FileKeyProvider::delete_kek(std::string_view key_ref) {
    // Same storage and the same eviction-after-remove discipline.
    return delete_key(key_ref);
}

// ── KEK wrap/unwrap seam (ADR-0010 §2) ───────────────────────────────────────

namespace {
constexpr std::size_t kKekSize = 32; // AES-256 KEK, raw bytes on disk
} // namespace

std::optional<std::string> FileKeyProvider::generate_kek(std::string_view key_id) {
    if (!is_safe_key_id(key_id)) {
        spdlog::error("key_provider: rejected unsafe kek key_id '{}'", std::string(key_id));
        return std::nullopt;
    }
    const fs::path dest = path_for(key_id);
    std::error_code ec;
    if (fs::exists(dest, ec)) {
        // Overwriting an existing KEK would orphan every blob wrapped under
        // it — a generation race or id-reuse bug must fail loudly, never
        // silently re-mint.
        spdlog::error("key_provider: refusing to overwrite existing KEK '{}'", std::string(key_id));
        return std::nullopt;
    }

    SecureBuffer kek{kKekSize};
    if (RAND_bytes(kek.data(), static_cast<int>(kek.size())) != 1) {
        // CSPRNG failure at generation is the startup_failed() class —
        // never fall back to a weaker source.
        spdlog::error("key_provider: RAND_bytes failed generating KEK '{}'", std::string(key_id));
        return std::nullopt;
    }
    if (!write_file_atomic(key_id, dest, kek.span()))
        return std::nullopt;

    std::string ref = dest.string();
    {
        std::lock_guard lock{kek_mutex_};
        kek_cache_.insert_or_assign(ref, std::move(kek));
    }
    spdlog::info("key_provider: generated KEK '{}' (0600, fsynced)", std::string(key_id));
    return ref;
}

std::optional<std::string> FileKeyProvider::resolve_kek(std::string_view key_id) {
    if (!is_safe_key_id(key_id))
        return std::nullopt;
    const fs::path p = path_for(key_id);
    std::error_code ec;
    if (!fs::exists(p, ec) || ec)
        return std::nullopt;
    return p.string();
}

const SecureBuffer* FileKeyProvider::kek_for_locked(std::string_view key_ref) {
    if (auto it = kek_cache_.find(key_ref); it != kek_cache_.end())
        return &it->second;

    const fs::path p{key_ref};
    if (!within_base(p)) {
        spdlog::error("key_provider: refusing KEK ref outside base: {}", std::string(key_ref));
        return nullptr;
    }
    std::error_code ec;
    const auto sz = fs::file_size(p, ec);
    if (ec || sz != kKekSize) {
        // Wrong size = torn/corrupt/absent. Unresolvable here; the
        // fingerprint check in SecretCodec::init() distinguishes
        // kek_corrupt from kek_unresolvable for the operator.
        spdlog::error("key_provider: KEK {} unreadable or not {} bytes", p.string(), kKekSize);
        return nullptr;
    }
    SecureBuffer kek{kKekSize};
    if (!read_exact(p, kek.data(), kKekSize)) {
        spdlog::error("key_provider: cannot read KEK {}", p.string());
        return nullptr;
    }
    auto [it, inserted] = kek_cache_.insert_or_assign(std::string(key_ref), std::move(kek));
    return &it->second;
}

std::expected<WrappedDek, KekError>
FileKeyProvider::wrap_dek(std::string_view key_ref, std::span<const std::uint8_t, 32> dek,
                          std::span<const std::uint8_t> wrap_aad) {
    std::lock_guard lock{kek_mutex_};
    const SecureBuffer* kek = kek_for_locked(key_ref);
    if (kek == nullptr)
        return std::unexpected{KekError::unresolvable};

    WrappedDek out;
    if (RAND_bytes(out.nonce.data(), static_cast<int>(out.nonce.size())) != 1) {
        spdlog::error("key_provider: RAND_bytes failed minting wrap nonce");
        return std::unexpected{KekError::crypto_failure};
    }
    const auto rc =
        detail::aes256gcm_encrypt(std::span<const std::uint8_t, 32>{kek->data(), 32},
                                  std::span<const std::uint8_t, 12>{out.nonce}, wrap_aad, dek,
                                  out.wrapped.data(), std::span<std::uint8_t, 16>{out.tag});
    if (rc != detail::GcmResult::ok) {
        spdlog::error("key_provider: DEK wrap failed (EVP)");
        return std::unexpected{KekError::crypto_failure};
    }
    return out;
}

std::expected<SecureBuffer, KekError>
FileKeyProvider::unwrap_dek(std::string_view key_ref, const WrappedDek& wrapped,
                            std::span<const std::uint8_t> wrap_aad) {
    std::lock_guard lock{kek_mutex_};
    const SecureBuffer* kek = kek_for_locked(key_ref);
    if (kek == nullptr)
        return std::unexpected{KekError::unresolvable};

    SecureBuffer dek{kKekSize};
    const auto rc =
        detail::aes256gcm_decrypt(std::span<const std::uint8_t, 32>{kek->data(), 32},
                                  std::span<const std::uint8_t, 12>{wrapped.nonce}, wrap_aad,
                                  std::span<const std::uint8_t>{wrapped.wrapped},
                                  std::span<const std::uint8_t, 16>{wrapped.tag}, dek.data());
    switch (rc) {
    case detail::GcmResult::ok:
        return dek;
    case detail::GcmResult::auth_failed:
        // No spdlog here: the caller (SecretCodec) owns the audit event and
        // counter for tag failures — double-logging would let a systemic
        // class bury a genuine single-row tamper.
        return std::unexpected{KekError::tag_mismatch};
    case detail::GcmResult::error:
    default:
        spdlog::error("key_provider: DEK unwrap failed (EVP)");
        return std::unexpected{KekError::crypto_failure};
    }
}

std::optional<std::array<std::uint8_t, 32>>
FileKeyProvider::kek_check_value(std::string_view key_ref, std::string_view kcv_alg) {
    if (kcv_alg != "sha256") {
        // FileKeyProvider derives KCVs as SHA-256 of the raw key material. A
        // version minted under a different algorithm (e.g. a token-derived KCV
        // after a FileKeyProvider → HSM/KMS swap) cannot be reproduced here —
        // return nullopt so boot raises a distinct, actionable error instead
        // of mis-flagging valid material as corrupt (S2; ADR-0010 Amendment 4).
        spdlog::error("key_provider: unsupported kcv_alg '{}' for FileKeyProvider (expected "
                      "'sha256')",
                      std::string(kcv_alg));
        return std::nullopt;
    }
    std::lock_guard lock{kek_mutex_};
    const SecureBuffer* kek = kek_for_locked(key_ref);
    if (kek == nullptr)
        return std::nullopt;
    // SHA-256 of the key material (ADR-0010 §2): safe for a full-entropy
    // 256-bit key — no dictionary angle. KCVs are non-secret.
    std::array<std::uint8_t, 32> kcv{};
    unsigned int md_len = 0;
    if (EVP_Digest(kek->data(), kek->size(), kcv.data(), &md_len, EVP_sha256(), nullptr) != 1 ||
        md_len != kcv.size()) {
        spdlog::error("key_provider: EVP_Digest failed computing KCV");
        return std::nullopt;
    }
    return kcv;
}

} // namespace yuzu::server
