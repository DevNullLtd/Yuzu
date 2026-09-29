#include <yuzu/agent/plugin_loader.hpp>

#include <yuzu/agent/detached_signature.hpp>

#include <yuzu/agent/file_hash.hpp> // sha256_from_fd / sha256_from_handle (#807, extracted)

#include <spdlog/spdlog.h>

#include <cerrno>
#include <cstdint> // std::uintmax_t (sha256_file bounded-read counter, used before the #ifdef)
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#define YUZU_DLOPEN(p) LoadLibraryW((p).wstring().c_str())
#define YUZU_DLSYM(h, s) GetProcAddress(static_cast<HMODULE>(h), s)
#define YUZU_DLCLOSE(h) FreeLibrary(static_cast<HMODULE>(h))
#define YUZU_SO_EXT ".dll"
#else
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#define YUZU_DLOPEN(p) dlopen((p).c_str(), RTLD_LAZY | RTLD_LOCAL)
#define YUZU_DLSYM(h, s) dlsym(h, s)
#define YUZU_DLCLOSE(h) dlclose(h)
#ifdef __APPLE__
#define YUZU_SO_EXT ".dylib"
#else
#define YUZU_SO_EXT ".so"
#endif
#endif

// pem.h must come before cms.h so the PEM_*_CMS macros are declared
// (cms.h gates them on OPENSSL_PEM_H).
#include <openssl/evp.h>
#include <openssl/x509_vfy.h>

namespace yuzu::agent {

// ── SHA-256 file hashing ─────────────────────────────────────────────────────

std::string sha256_file(const std::filesystem::path& path, std::size_t max_bytes) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        spdlog::error("sha256_file: cannot open {}", path.string());
        return {};
    }

    constexpr size_t kBufSize = 64 * 1024;
    char buf[kBufSize];
    constexpr size_t kDigestLen = 32;
    unsigned char digest[kDigestLen]{};
    std::uintmax_t hashed_total = 0; // bounded-read guard against max_bytes

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return {};

    DWORD obj_size = 0, data_len = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_size), sizeof(DWORD),
                      &data_len, 0);
    std::vector<unsigned char> hash_obj(obj_size);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, hash_obj.data(),
                                         static_cast<ULONG>(hash_obj.size()), nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    while (f.read(buf, kBufSize) || f.gcount() > 0) {
        hashed_total += static_cast<std::uintmax_t>(f.gcount());
        if (hashed_total > max_bytes) { // exceeds the read cap — refuse (oversize)
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        if (!BCRYPT_SUCCESS(BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf),
                                           static_cast<ULONG>(f.gcount()), 0))) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        if (f.eof())
            break;
    }

    bool ok = BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, kDigestLen, 0));
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok)
        return {};
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (ctx)
            EVP_MD_CTX_free(ctx);
        return {};
    }

    while (f.read(buf, kBufSize) || f.gcount() > 0) {
        hashed_total += static_cast<std::uintmax_t>(f.gcount());
        if (hashed_total > max_bytes) { // exceeds the read cap — refuse (oversize)
            EVP_MD_CTX_free(ctx);
            return {};
        }
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount()));
        if (f.eof())
            break;
    }

    unsigned int out_len = 0;
    bool ok = EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 && out_len == kDigestLen;
    EVP_MD_CTX_free(ctx);
    if (!ok)
        return {};
#endif

    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(kDigestLen * 2);
    for (size_t i = 0; i < kDigestLen; ++i) {
        hex.push_back(kHex[digest[i] >> 4]);
        hex.push_back(kHex[digest[i] & 0x0F]);
    }
    return hex;
}

// ── Plugin code-signing verification ─────────────────────────────────────────
//
// Wire format:
//   * Signature file lives at `<plugin-path>.sig` (e.g. chargen.so.sig).
//   * Content is a PEM-armoured CMS detached signature, exactly what
//     `openssl cms -sign -binary -nodetach=false -outform PEM` produces.
//   * Trust anchor is a PEM file with one or more X.509 root/intermediate
//     certificates the operator chooses to trust. The bundle is
//     deployment-format-agnostic — it can hold a public CA root, an
//     internal-CA root, or (when shipped) the Yuzu self-managed CA root.
//
// What the verifier checks: CMS_verify with X509_V_FLAG inherits from the
// store. The store is built fresh per scan() call from the trust bundle.
// CMS_verify validates the embedded signing cert chain, the signature over
// the plugin file bytes, and basic cert validity (notBefore/notAfter,
// signature alg sanity). It does *not* fetch CRLs by default — CRL/OCSP
// integration is a future enhancement (issue follow-up).
//
// What the verifier does *not* claim: it does not bind the signature to
// the plugin filename. That binding is provided by the existing allowlist
// (which maps filename → expected SHA-256 of file content). When both
// allowlist and signature are enforced, an attacker cannot cross-replay
// signatures because: stolen-sig-on-different-file → CMS_verify fails
// (digest mismatch); stolen-sig-on-renamed-original → allowlist filename
// mismatch.

std::optional<std::string> verify_plugin_signature(const std::filesystem::path& plugin_path,
                                                   const std::filesystem::path& trust_bundle_path) {
    auto sig_path = plugin_path;
    sig_path += ".sig";

    std::error_code ec;
    if (!std::filesystem::exists(sig_path, ec)) {
        return std::string{kSignatureMissingReason};
    }

    // Read the detached signature into memory and hand it to the shared
    // verifier. The verifier takes a buffer rather than a path because the OTA
    // update path (#416/#3807) receives its signature over the wire; the CMS
    // policy, the codeSigning-EKU purpose and the flag ban all live there now,
    // so the two callers cannot drift apart.
    // BOUNDED. The lift replaced a streaming BIO_new_file with a whole-file read,
    // which dropped the implicit bound the stream gave us: a plugin directory is
    // root-owned, but a .sig symlinked at /dev/zero would otherwise be read until
    // memory ran out. A detached CMS signature is a few KB; the server side caps
    // the equivalent OTA sidecar at the same order.
    std::error_code sig_sz_ec;
    const auto sig_size = std::filesystem::file_size(sig_path, sig_sz_ec);
    if (sig_sz_ec || sig_size > kMaxSignatureBytes) {
        return std::string{kSignatureInvalidReason} + ": signature file unusable or too large";
    }
    std::ifstream sig_in(sig_path, std::ios::binary);
    if (!sig_in) {
        return std::string{kSignatureInvalidReason} + ": cannot open signature file";
    }
    const std::string sig_pem((std::istreambuf_iterator<char>(sig_in)),
                              std::istreambuf_iterator<char>());

    auto err = verify_detached_cms(plugin_path, sig_pem, trust_bundle_path);
    if (!err)
        return std::nullopt; // verified

    const std::string_view prefix = err->kind == CmsFailure::kUntrusted
                                        ? kSignatureUntrustedReason
                                        : kSignatureInvalidReason;
    return std::string{prefix} + ": " + err->detail;
}

std::unordered_map<std::string, std::string>
load_plugin_allowlist(const std::filesystem::path& allowlist_path) {
    std::unordered_map<std::string, std::string> result;
    if (allowlist_path.empty() || !std::filesystem::exists(allowlist_path))
        return result;

    std::ifstream f(allowlist_path);
    if (!f) {
        spdlog::error("Cannot open plugin allowlist: {}", allowlist_path.string());
        return result;
    }

    std::string line;
    int lineno = 0;
    while (std::getline(f, line)) {
        ++lineno;
        if (line.empty() || line[0] == '#')
            continue;
        // Format: "hash  filename" or "hash filename" (sha256sum compatible)
        std::istringstream iss(line);
        std::string hash, filename;
        if (!(iss >> hash >> filename)) {
            spdlog::warn("Allowlist line {} malformed, skipping: {}", lineno, line);
            continue;
        }
        // Normalize hash to lowercase
        for (auto& c : hash)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        // Strip path prefix if present — match on filename only
        auto fname = std::filesystem::path(filename).filename().string();
        result[fname] = hash;
        spdlog::debug("Allowlist entry: {} -> {}", fname, hash);
    }

    spdlog::info("Loaded {} plugin allowlist entries from {}", result.size(),
                 allowlist_path.string());
    return result;
}

// ── PluginHandle ──────────────────────────────────────────────────────────────

// #2204 / plugin B2 — single source of truth for the ABI-gate on
// action_descriptor_count: action_descriptors/action_descriptor_count exist
// ONLY at ABI v4+ (sdk/include/yuzu/plugin.h). An ABI<4 plugin's actual
// in-memory descriptor (tests/fixtures/abi3/plugin_abi3.h is the frozen,
// real-world proof) ends at sdk_version — reading action_descriptor_count
// off it is not merely wrong data, it is a read past the end of the real
// allocation. Kept as the one place that computes this value (PluginHandle::
// load()'s diagnostic log line below calls it) so nothing can silently read
// the raw field instead. No public header — tests/unit/
// test_capability_descriptor.cpp forward-declares it directly, the same
// convention agents/core/src/agent.cpp uses for
// derive_effective_result_status()/dispatch_with_capture().
YUZU_EXPORT std::size_t gated_action_descriptor_count(const YuzuPluginDescriptor* desc) {
    return (desc->abi_version >= 4) ? desc->action_descriptor_count : 0;
}

PluginHandle::PluginHandle(PluginHandle&& o) noexcept
    : handle_{o.handle_}, descriptor_{o.descriptor_}, path_{std::move(o.path_)} {
    o.handle_ = nullptr;
    o.descriptor_ = nullptr;
}

PluginHandle& PluginHandle::operator=(PluginHandle&& o) noexcept {
    if (this != &o) {
        if (handle_)
            YUZU_DLCLOSE(handle_);
        handle_ = o.handle_;
        descriptor_ = o.descriptor_;
        path_ = std::move(o.path_);
        o.handle_ = nullptr;
        o.descriptor_ = nullptr;
    }
    return *this;
}

PluginHandle::~PluginHandle() {
    if (handle_) {
        spdlog::debug("Unloading plugin: {}", path_);
        YUZU_DLCLOSE(handle_);
    }
}

std::expected<PluginHandle, LoadError> PluginHandle::load(const std::filesystem::path& so_path) {
    spdlog::debug("Loading plugin: {}", so_path.string());

    void* handle = YUZU_DLOPEN(so_path);
    if (!handle) {
#ifdef _WIN32
        auto err = GetLastError();
        return std::unexpected(
            LoadError{so_path.string(), "LoadLibrary failed with error " + std::to_string(err)});
#else
        return std::unexpected(LoadError{so_path.string(), dlerror()});
#endif
    }

    auto* sym =
        reinterpret_cast<yuzu_plugin_descriptor_fn>(YUZU_DLSYM(handle, "yuzu_plugin_descriptor"));
    if (!sym) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(
            LoadError{so_path.string(), "missing export 'yuzu_plugin_descriptor'"});
    }

    const YuzuPluginDescriptor* desc = sym();
    if (!desc) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(
            LoadError{so_path.string(), "yuzu_plugin_descriptor() returned null"});
    }

    if (desc->abi_version < YUZU_PLUGIN_ABI_VERSION_MIN ||
        desc->abi_version > YUZU_PLUGIN_ABI_VERSION) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(LoadError{
            so_path.string(), "ABI version mismatch: plugin=" + std::to_string(desc->abi_version) +
                                  " host_range=[" + std::to_string(YUZU_PLUGIN_ABI_VERSION_MIN) +
                                  "," + std::to_string(YUZU_PLUGIN_ABI_VERSION) + "]"});
    }

    // ABI v3+ includes sdk_version for diagnostics
    const char* sdk_ver =
        (desc->abi_version >= 3 && desc->sdk_version) ? desc->sdk_version : "unknown";
    // ABI v4+ includes per-action capability declarations (#2204); ABI<4
    // plugins (or an ABI4 plugin that simply never populated the array)
    // report 0 here, which the capability-matrix generator reads as
    // "undeclared" for every action rather than an error.
    const std::size_t action_descriptor_count = gated_action_descriptor_count(desc);
    spdlog::info("Loaded plugin '{}' v{} (ABI={}, SDK={}, capability declarations={})", desc->name,
                 desc->version, desc->abi_version, sdk_ver, action_descriptor_count);

    PluginHandle ph;
    ph.handle_ = handle;
    ph.descriptor_ = desc;
    ph.path_ = so_path.string();
    return ph;
}

// ── PluginLoader ──────────────────────────────────────────────────────────────

PluginLoader::ScanResult
PluginLoader::scan(const std::filesystem::path& plugin_dir,
                   const std::unordered_map<std::string, std::string>& allowlist,
                   const PluginSigningPolicy& signing) {
    ScanResult result;

    if (!std::filesystem::is_directory(plugin_dir)) {
        spdlog::warn("Plugin directory does not exist: {}", plugin_dir.string());
        return result;
    }

    // W2.2 / #807 follow-up — glibc dlopen path cache.
    //
    // The /proc/self/fd/N path that the Linux branch passes to dlopen is
    // CACHED by glibc keyed on the path string. If we close the fd at
    // end-of-iteration and the next iteration's open() recycles the
    // number (almost always true — fd allocation is lowest-available),
    // every subsequent dlopen of /proc/self/fd/<reused-number> returns
    // the FIRST plugin's cached handle. Symptom: every plugin's
    // descriptor reports the name of the FIRST plugin loaded.
    //
    // Fix: stash each per-plugin fd into a vector with scope of the
    // whole scan(), so fd numbers don't recycle across iterations and
    // each /proc/self/fd/N stays unique while glibc resolves the path.
    // Closed automatically at the end of scan() via vector destruction;
    // the dlopen()-mapped .so stays loaded independently.
    std::vector<int> linux_fd_keepalive; // POSIX-only; empty on macOS, no fd flow there

    const bool enforce_allowlist = !allowlist.empty();
    const bool enforce_signing = signing.enabled();
    if (enforce_allowlist) {
        spdlog::info("Plugin allowlist enforcement active ({} entries)", allowlist.size());
    }
    if (enforce_signing) {
        spdlog::info("Plugin code-signing enforcement active (trust bundle '{}', require={})",
                     signing.trust_bundle_path.string(), signing.require_signature);
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(plugin_dir)) {
        if (!entry.is_regular_file())
            continue;
        if (entry.path().extension() != YUZU_SO_EXT)
            continue;

            // W2.2 / #807: pin the inode by opening ONCE.
            //
            // POSIX: open with O_NOFOLLOW + O_CLOEXEC. The previous flow
            //   sha256_file(path) → is_symlink(path) → dlopen(path)
            // did three independent path resolutions, each racy against a writer
            // in the plugin directory. We now hash via the held fd, and on Linux
            // load via `/proc/self/fd/N` so dlopen sees the same inode the hash
            // covered. On macOS there is no /proc/self/fd → dlopen bridge, so we
            // close the fd and fall back to a path-based dlopen; the race window
            // narrows (no separate symlink stat) but is not fully eliminated.
            // Documented residual on darwin.
            //
            // Windows (cross-platform-debt closure): CreateFileW with
            // FILE_SHARE_READ only (no SHARE_WRITE, no SHARE_DELETE) — while we
            // hold the handle nothing can write to, delete, or rename our file,
            // so the directory entry at this path cannot be re-pointed at a
            // different inode. LoadLibraryW(path) therefore loads the same inode
            // we hashed. FILE_FLAG_OPEN_REPARSE_POINT opens reparse points raw
            // (matching POSIX O_NOFOLLOW) so we can refuse symlinks/junctions
            // via the reparse-point attribute check.
#ifdef _WIN32
        struct ScopedHandle {
            HANDLE h = INVALID_HANDLE_VALUE;
            ScopedHandle() = default;
            ~ScopedHandle() {
                if (h != INVALID_HANDLE_VALUE)
                    CloseHandle(h);
            }
            ScopedHandle(const ScopedHandle&) = delete;
            ScopedHandle& operator=(const ScopedHandle&) = delete;
            ScopedHandle(ScopedHandle&&) = delete;
            ScopedHandle& operator=(ScopedHandle&&) = delete;
        } guard;
        guard.h = CreateFileW(entry.path().wstring().c_str(), GENERIC_READ,
                              FILE_SHARE_READ, // path-swap blocked while held
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT, // don't follow symlinks
                              nullptr);
        if (guard.h == INVALID_HANDLE_VALUE) {
            auto err = GetLastError();
            spdlog::error("Plugin {} CreateFileW failed: {}", entry.path().string(), err);
            result.errors.push_back(LoadError{
                entry.path().string(), "CreateFileW failed with error " + std::to_string(err)});
            continue;
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(guard.h, &info)) {
            auto err = GetLastError();
            spdlog::error("Plugin {} GetFileInformationByHandle failed: {}", entry.path().string(),
                          err);
            result.errors.push_back(
                LoadError{entry.path().string(),
                          "GetFileInformationByHandle failed with error " + std::to_string(err)});
            continue;
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            spdlog::warn("Plugin {} is a reparse point (symlink/junction) — skipping",
                         entry.path().string());
            result.errors.push_back(
                LoadError{entry.path().string(), "symlinks not allowed in plugin directory"});
            continue;
        }
#else
        struct ScopedFd {
            int fd = -1;
            ~ScopedFd() {
                if (fd >= 0)
                    ::close(fd);
            }
        } guard;
        guard.fd = ::open(entry.path().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (guard.fd < 0) {
            if (errno == ELOOP) {
                spdlog::warn("Plugin {} is a symlink — skipping", entry.path().string());
                result.errors.push_back(
                    LoadError{entry.path().string(), "symlinks not allowed in plugin directory"});
            } else {
                spdlog::error("Plugin {} open failed: {}", entry.path().string(),
                              std::strerror(errno));
                result.errors.push_back(LoadError{
                    entry.path().string(), std::string{"open failed: "} + std::strerror(errno)});
            }
            continue;
        }
#endif

        // Allowlist verification: hash the file BEFORE dlopen (on POSIX,
        // hash from the fd we already hold, so the swap-after-hash TOCTOU
        // is closed).
        if (enforce_allowlist) {
            auto fname = entry.path().filename().string();
            auto it = allowlist.find(fname);
            if (it == allowlist.end()) {
                spdlog::warn("Plugin {} not in allowlist — skipping", fname);
                result.errors.push_back(
                    LoadError{entry.path().string(), "not in plugin allowlist"});
                continue;
            }

#ifdef _WIN32
            auto actual_hash = sha256_from_handle(guard.h);
#else
            auto actual_hash = sha256_from_fd(guard.fd);
#endif
            if (actual_hash.empty()) {
                result.errors.push_back(
                    LoadError{entry.path().string(), "failed to compute SHA-256 hash"});
                continue;
            }

            if (actual_hash != it->second) {
                spdlog::error("Plugin {} hash mismatch: expected={}, actual={}", fname, it->second,
                              actual_hash);
                result.errors.push_back(LoadError{entry.path().string(),
                                                  "SHA-256 hash mismatch (expected " + it->second +
                                                      ", got " + actual_hash + ")"});
                continue;
            }
            spdlog::debug("Plugin {} hash verified: {}", fname, actual_hash);
        }

        // Code-signing verification — runs after allowlist (cheap-fail-first)
        // and before dlopen so a malformed/sig-bad library is never mapped.
        // Two-mode contract:
        //   * require_signature=true  → no sig OR bad sig = reject
        //   * require_signature=false → no sig is allowed (transitional);
        //     a sig file present must still verify or the plugin is
        //     rejected (defence against attacker-supplied malicious .sig).
        //
        // Note: signature verification re-reads the plugin file from path
        // (CMS_verify wants a BIO). A swap between the held-fd hash and
        // this verify would cause CMS_verify to fail (digest mismatch over
        // tampered content), so the race window here is self-protecting
        // via the cryptographic check.
        if (enforce_signing) {
            auto sig_path = entry.path();
            sig_path += ".sig";
            const bool sig_present = std::filesystem::exists(sig_path);
            if (!sig_present && !signing.require_signature) {
                spdlog::debug("Plugin {} has no signature (require=false), allowing",
                              entry.path().filename().string());
            } else {
                auto err = verify_plugin_signature(entry.path(), signing.trust_bundle_path);
                if (err) {
                    spdlog::error("Plugin {} signature rejected: {}", entry.path().string(), *err);
                    result.errors.push_back(LoadError{entry.path().string(), std::move(*err)});
                    continue;
                }
                spdlog::info("Plugin {} signature verified", entry.path().filename().string());
            }
        }

#ifdef _WIN32
        // Symlinks were refused at handle-open time via FILE_FLAG_OPEN_REPARSE_POINT
        // + FILE_ATTRIBUTE_REPARSE_POINT check — no separate is_symlink stat
        // needed (and using one would re-introduce a path resolution race).
        // LoadLibraryW(path) is safe here even though it is path-based: the
        // FILE_SHARE_READ-only handle we still hold in `guard` prevents any
        // other party from writing to, deleting, or renaming our file, so the
        // directory entry at this path cannot be re-pointed at a different
        // inode while LoadLibrary resolves it.
        auto loaded = PluginHandle::load(entry.path());
#elif defined(__linux__)
        // Linux: load via /proc/self/fd/N — the kernel resolves this to the
        // open file description we hold, so the same inode the hash covered
        // is the one dlopen maps. Full TOCTOU close.
        //
        // After dlopen, transfer fd ownership to the scan-scoped keepalive
        // vector so the fd number does NOT recycle into the next iteration
        // (see the keepalive declaration above for the glibc-path-cache
        // rationale). guard.fd is set to -1 to disarm the per-iteration
        // ScopedFd destructor.
        std::filesystem::path fd_path{"/proc/self/fd/"};
        fd_path += std::to_string(guard.fd);
        auto loaded = PluginHandle::load(fd_path);
        linux_fd_keepalive.push_back(guard.fd);
        guard.fd = -1;
#else
        // macOS: no /proc/self/fd. Fall back to path-based dlopen. The
        // residual race window is from the moment of the held-fd hash
        // through dlopen's internal open. The fd holds the original inode
        // open, so a writer who replaces the path entry can rotate the
        // inode but cannot remove ours from disk while we hold it — that
        // narrows but does not eliminate the race. Tracked as follow-up
        // for a Darwin-specific fix (likely via private dyld API).
        auto loaded = PluginHandle::load(entry.path());
#endif
        if (loaded) {
            // The descriptor name is plugin-self-declared and crosses the C ABI
            // as a bare `const char*`. Validate it before constructing a
            // std::string_view from it — the string_view(const char*) ctor calls
            // strlen, which is UB on a null pointer that a malformed C plugin
            // could set — and before any reserved-name / dispatch comparison, so
            // a crafted name cannot diverge between this security check and a
            // downstream C-string consumer of descriptor->name (#822).
            const char* raw_name = loaded->descriptor()->name;
            if (raw_name == nullptr || !is_valid_plugin_name(raw_name)) {
                // Do NOT echo raw_name: it may carry NUL/control/newline bytes
                // that would forge log lines or corrupt the error channel. The
                // on-disk entry path is operator-controlled and safe to log.
                spdlog::error("Plugin {} declares an invalid name — rejecting (a "
                              "plugin name must be a non-empty [A-Za-z0-9_] "
                              "identifier of at most {} bytes)",
                              entry.path().string(), kMaxPluginNameLen);
                result.errors.push_back(
                    LoadError{entry.path().string(), std::string{kInvalidNameReason}});
                continue;
            }
            const std::string_view plugin_name{raw_name};
            if (is_reserved_plugin_name(plugin_name)) {
                // #453: prevent a compromised plugin author from shadowing
                // the Guardian (__guard__) or other reserved dispatch names.
                // The handle destructs here and dlcloses the library.
                spdlog::error("Plugin {} declares reserved name '{}' — rejecting to protect "
                              "internal dispatch",
                              entry.path().string(), plugin_name);
                result.errors.push_back(
                    LoadError{entry.path().string(), std::string{kReservedNameReason} + ": '" +
                                                         std::string{plugin_name} + "'"});
                continue;
            }
            // Log with the on-disk entry path, not loaded->path(): on Linux
            // the latter is `/proc/self/fd/N` (our race-free dlopen handle)
            // which is useless in operator logs.
            spdlog::info("Loaded plugin: {} v{} from {}", loaded->descriptor()->name,
                         loaded->descriptor()->version, entry.path().string());
            result.loaded.push_back(std::move(*loaded));
        } else {
            spdlog::error("Failed to load plugin {}: {}", entry.path().string(),
                          loaded.error().reason);
            // Rewrite the error path to the on-disk entry path so the
            // operator-visible error string isn't `/proc/self/fd/N`.
            loaded.error().path = entry.path().string();
            result.errors.push_back(std::move(loaded.error()));
        }
    }

#ifdef __linux__
    // Plugins are all dlopen'd and the dynamic linker has its own
    // mapping for each .so — safe to release the keepalive fds now.
    // The path-cache collision risk is gone the moment we move past
    // the scan loop, since no further dlopen of /proc/self/fd/N will
    // be issued.
    for (int fd : linux_fd_keepalive) {
        if (fd >= 0)
            ::close(fd);
    }
#endif

    return result;
}

} // namespace yuzu::agent
