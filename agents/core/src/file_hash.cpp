#include <yuzu/agent/file_hash.hpp>

#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <bcrypt.h>
#include <vector>
#pragma comment(lib, "bcrypt.lib")
#else
#include <cerrno>
#include <cstring>

#include <unistd.h>

#include <openssl/evp.h>
#endif

// These two functions are moved from plugin_loader.cpp's anonymous namespace
// (the #807 / W2.2 hardening): the SINGLE hardened fd/HANDLE-scoped hash
// primitive, now shared between the plugin loader and the Guardian spark state
// reader. The ONLY change from that history is the `max_bytes` bounded-read
// guard (the same one `sha256_file` carries) so untrusted, growing watched
// files cannot drive an unbounded read; plugin-loader callers pass the default
// (SIZE_MAX) and keep byte-identical behaviour.

namespace yuzu::agent {

#ifdef _WIN32
namespace {
// RAII owners for the BCrypt alg/hash handles so a bad_alloc from a vector
// allocation or from spdlog's own formatting (both of which can throw between
// a successful BCrypt* call and its paired manual close) cannot leak the
// handle - closed unconditionally on every return path, not just the ones
// that remembered to call BCryptDestroyHash/BCryptCloseAlgorithmProvider.
struct BCryptAlgGuard {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~BCryptAlgGuard() {
        if (h)
            BCryptCloseAlgorithmProvider(h, 0);
    }
    BCryptAlgGuard(const BCryptAlgGuard&) = delete;
    BCryptAlgGuard& operator=(const BCryptAlgGuard&) = delete;
    BCryptAlgGuard() = default;
};
struct BCryptHashGuard {
    BCRYPT_HASH_HANDLE h = nullptr;
    ~BCryptHashGuard() {
        if (h)
            BCryptDestroyHash(h);
    }
    BCryptHashGuard(const BCryptHashGuard&) = delete;
    BCryptHashGuard& operator=(const BCryptHashGuard&) = delete;
    BCryptHashGuard() = default;
};
} // namespace

std::string sha256_from_handle(HANDLE h, std::size_t max_bytes) {
    if (h == INVALID_HANDLE_VALUE)
        return {};
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(h, zero, nullptr, FILE_BEGIN)) {
        spdlog::error("sha256_from_handle: SetFilePointerEx failed: {}", GetLastError());
        return {};
    }
    BCryptAlgGuard alg_guard;
    NTSTATUS status =
        BCryptOpenAlgorithmProvider(&alg_guard.h, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::error("sha256_from_handle: BCryptOpenAlgorithmProvider failed: 0x{:08x}",
                      static_cast<unsigned>(status));
        return {};
    }

    DWORD obj_size = 0, data_len = 0;
    status = BCryptGetProperty(alg_guard.h, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&obj_size), sizeof(DWORD), &data_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::error("sha256_from_handle: BCryptGetProperty failed: 0x{:08x}",
                      static_cast<unsigned>(status));
        return {};
    }
    std::vector<unsigned char> hash_obj(obj_size);
    BCryptHashGuard hash_guard;
    status = BCryptCreateHash(alg_guard.h, &hash_guard.h, hash_obj.data(),
                              static_cast<ULONG>(hash_obj.size()), nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::error("sha256_from_handle: BCryptCreateHash failed: 0x{:08x}",
                      static_cast<unsigned>(status));
        return {};
    }

    constexpr DWORD kBufSize = 64 * 1024;
    std::vector<unsigned char> buf(kBufSize);
    std::uintmax_t hashed_total = 0; // bounded-read guard against max_bytes
    for (;;) {
        DWORD bytes_read = 0;
        if (!ReadFile(h, buf.data(), kBufSize, &bytes_read, nullptr)) {
            spdlog::error("sha256_from_handle: ReadFile failed: {}", GetLastError());
            return {};
        }
        if (bytes_read == 0)
            break;
        hashed_total += static_cast<std::uintmax_t>(bytes_read);
        if (hashed_total > max_bytes) // exceeds the read cap - refuse (oversize)
            return {};
        status = BCryptHashData(hash_guard.h, buf.data(), bytes_read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            spdlog::error("sha256_from_handle: BCryptHashData failed: 0x{:08x}",
                          static_cast<unsigned>(status));
            return {};
        }
    }

    unsigned char digest[32]{};
    status = BCryptFinishHash(hash_guard.h, digest, sizeof(digest), 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::error("sha256_from_handle: BCryptFinishHash failed: 0x{:08x}",
                      static_cast<unsigned>(status));
        return {};
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (unsigned char b : digest) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0F]);
    }
    return hex;
}
#else
namespace {
// RAII owner for EVP_MD_CTX so a bad_alloc from spdlog's own formatting (which
// can throw between a successful EVP_MD_CTX_new/Init and its paired manual
// free, e.g. the read-failure log below) cannot leak the context - mirrors
// the BCryptAlgGuard/BCryptHashGuard treatment on the Windows side.
struct EvpMdCtxGuard {
    EVP_MD_CTX* ctx = nullptr;
    ~EvpMdCtxGuard() {
        if (ctx)
            EVP_MD_CTX_free(ctx);
    }
    EvpMdCtxGuard(const EvpMdCtxGuard&) = delete;
    EvpMdCtxGuard& operator=(const EvpMdCtxGuard&) = delete;
    EvpMdCtxGuard() = default;
};
} // namespace

std::string sha256_from_fd(int fd, std::size_t max_bytes) {
    if (fd < 0)
        return {};
    if (::lseek(fd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        spdlog::error("sha256_from_fd: lseek failed: {}", std::strerror(errno));
        return {};
    }
    EvpMdCtxGuard ctx_guard;
    ctx_guard.ctx = EVP_MD_CTX_new();
    if (!ctx_guard.ctx) {
        spdlog::error("sha256_from_fd: EVP_MD_CTX_new failed");
        return {};
    }
    if (EVP_DigestInit_ex(ctx_guard.ctx, EVP_sha256(), nullptr) != 1) {
        spdlog::error("sha256_from_fd: EVP_DigestInit_ex failed");
        return {};
    }
    constexpr size_t kBufSize = 64 * 1024;
    char buf[kBufSize];
    std::uintmax_t hashed_total = 0; // bounded-read guard against max_bytes
    for (;;) {
        ssize_t n = ::read(fd, buf, kBufSize);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            spdlog::error("sha256_from_fd: read failed: {}", std::strerror(errno));
            return {};
        }
        if (n == 0)
            break;
        hashed_total += static_cast<std::uintmax_t>(n);
        if (hashed_total > max_bytes) // exceeds the read cap - refuse (oversize)
            return {};
        if (EVP_DigestUpdate(ctx_guard.ctx, buf, static_cast<size_t>(n)) != 1) {
            spdlog::error("sha256_from_fd: EVP_DigestUpdate failed");
            return {};
        }
    }
    unsigned char digest[32]{};
    unsigned int out_len = 0;
    bool ok = EVP_DigestFinal_ex(ctx_guard.ctx, digest, &out_len) == 1 && out_len == 32;
    if (!ok) {
        spdlog::error("sha256_from_fd: EVP_DigestFinal_ex failed");
        return {};
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (unsigned char b : digest) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0F]);
    }
    return hex;
}
#endif // _WIN32

} // namespace yuzu::agent
