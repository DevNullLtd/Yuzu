/**
 * temp_file.cpp — Cross-platform secure temporary file/directory creation
 *
 * POSIX:   mkstemps() for files (mode 0600), mkdtemp() for dirs (mode 0700).
 * Windows: CreateFile/CreateDirectory with owner-only DACL + crypto-random names.
 */

#include <yuzu/plugin.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#include <sddl.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

#ifdef _WIN32

// Generate 16 crypto-random bytes and format as 32-char hex string.
static bool generate_random_hex(char* out, size_t hex_len) {
    if (hex_len < 32)
        return false;
    UCHAR bytes[16];
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return false;
    }
    for (int i = 0; i < 16; ++i) {
        std::snprintf(out + i * 2, 3, "%02x", bytes[i]);
    }
    return true;
}

// Create an owner-only SECURITY_ATTRIBUTES. Caller must LocalFree sd.
static bool make_owner_only_sa(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& sd) {
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sd = nullptr;
    // D:P(A;;GA;;;OW) = Protected DACL, allow Generic All to Owner only
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)", SDDL_REVISION_1,
                                                              &sd, nullptr)) {
        return false;
    }
    sa.lpSecurityDescriptor = sd;
    return true;
}

// Get the temp directory as a wide string.
static bool get_temp_dir_w(const char* directory, wchar_t* out, DWORD out_size) {
    if (directory && directory[0]) {
        return MultiByteToWideChar(CP_UTF8, 0, directory, -1, out, out_size) != 0;
    }
    return GetTempPathW(out_size, out) != 0;
}

// Build "dir\prefixHEXsuffix" wide-string path, return UTF-8 length.
static std::wstring build_temp_path_w(const wchar_t* dir, const char* prefix, const char* hex,
                                      const char* suffix) {
    std::wstring result(dir);
    if (!result.empty() && result.back() != L'\\' && result.back() != L'/') {
        result += L'\\';
    }
    // Append prefix + hex + suffix (all ASCII, safe to widen char-by-char)
    for (const char* p = prefix; *p; ++p)
        result += static_cast<wchar_t>(*p);
    for (const char* p = hex; *p; ++p)
        result += static_cast<wchar_t>(*p);
    if (suffix) {
        for (const char* p = suffix; *p; ++p)
            result += static_cast<wchar_t>(*p);
    }
    return result;
}

// NOT migrated to the shared agents/shared/win_str.hpp (#1681): that helper
// allocates and returns a std::string, whereas this writes UTF-8 directly into a
// caller-provided fixed buffer (out/out_size) and returns a status code — a
// different contract (same for get_temp_dir_w above, which fills a caller
// wchar_t*). Keeping the local convert avoids an extra allocation + copy on the
// temp-path path; it is a thin WideCharToMultiByte wrapper, not a re-derived helper.
static int wide_to_utf8(const wchar_t* wide, char* out, size_t out_size) {
    int written = WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, static_cast<int>(out_size),
                                      nullptr, nullptr);
    return (written > 0) ? 0 : -1;
}

#endif // _WIN32

extern "C" {

YUZU_EXPORT int yuzu_create_temp_file(const char* prefix, const char* suffix, const char* directory,
                                      char* path_out, size_t path_out_size) {
    if (!path_out || path_out_size == 0) {
#ifdef _WIN32
        // This guard runs before the platform split below, so it isn't
        // covered by any of that code's own SetLastError() calls -- without
        // this, a caller relying on the "always meaningful on failure"
        // contract documented in sdk/include/yuzu/plugin.h would read
        // whatever stale, unrelated code happened to be left over.
        SetLastError(ERROR_INVALID_PARAMETER);
#endif
        return -1;
    }

    const char* pfx = (prefix && prefix[0]) ? prefix : "yuzu-";
    const char* sfx = (suffix && suffix[0]) ? suffix : ".tmp";

#ifdef _WIN32
    wchar_t temp_dir_w[MAX_PATH];
    if (!get_temp_dir_w(directory, temp_dir_w, MAX_PATH))
        return -1; // MultiByteToWideChar/GetTempPathW already set a meaningful last-error

    char hex[33]{};
    if (!generate_random_hex(hex, sizeof(hex))) {
        // BCryptGenRandom returns an NTSTATUS, not a Win32 error — it never calls
        // SetLastError, so a caller checking GetLastError() right after this
        // function returns would otherwise see whatever unrelated code happened
        // to be left over from an earlier, unrelated Win32 call on this thread.
        SetLastError(ERROR_GEN_FAILURE);
        return -1;
    }

    auto full_path = build_temp_path_w(temp_dir_w, pfx, hex, sfx);
    if (full_path.size() >= MAX_PATH) {
        // A pure C++ string-length check — no Win32 call happened, so
        // GetLastError() would otherwise be equally stale.
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return -1;
    }

    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!make_owner_only_sa(sa, sd)) {
        // Fail closed rather than fall through to CreateFileW with a null
        // lpSecurityDescriptor (the token's default, potentially-inheriting
        // DACL instead of the intended owner-only one) -- mirrors
        // updater.cpp's identical ConvertStringSecurityDescriptorTo
        // SecurityDescriptorW call, which has always failed closed here.
        // GetLastError() already carries the real failure from inside
        // make_owner_only_sa's own Win32 call.
        return -1;
    }

    HANDLE hFile = CreateFileW(full_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                               0, // no sharing
                               &sa,
                               CREATE_NEW, // fail if exists — prevents TOCTOU race
                               FILE_ATTRIBUTE_TEMPORARY, nullptr);
    // Capture CreateFileW's real failure code BEFORE LocalFree runs -- it is
    // unconditional (success or failure) and, like every other cleanup call
    // in this file, is not documented by MSDN as leaving GetLastError()
    // untouched.
    const DWORD create_file_err = GetLastError();

    if (sd)
        LocalFree(sd);

    if (hFile == INVALID_HANDLE_VALUE) {
        SetLastError(create_file_err);
        return -1;
    }

    CloseHandle(hFile);

    if (wide_to_utf8(full_path.c_str(), path_out, path_out_size) != 0) {
        // Capture wide_to_utf8's real failure code BEFORE DeleteFileW can
        // overwrite it — a successful cleanup call is not guaranteed to leave
        // GetLastError() untouched (some Win32 APIs reset it to ERROR_SUCCESS
        // on success, some don't; MSDN does not document this as reliable).
        const DWORD saved_err = GetLastError();
        DeleteFileW(full_path.c_str());
        SetLastError(saved_err);
        return -1;
    }
    return 0;

#else
    std::string temp_dir;
    if (directory && directory[0]) {
        temp_dir = directory;
    } else {
        std::error_code ec;
        temp_dir = fs::temp_directory_path(ec).string();
        if (ec)
            return -1;
    }

    // mkstemps template: dir/prefixXXXXXXsuffix
    auto sfx_len = static_cast<int>(std::strlen(sfx));
    std::string tmpl = temp_dir + "/" + pfx + "XXXXXX" + sfx;

    int fd = mkstemps(tmpl.data(), sfx_len);
    if (fd < 0)
        return -1;
    close(fd);

    if (tmpl.size() + 1 > path_out_size) {
        unlink(tmpl.c_str());
        return -1;
    }
    std::memcpy(path_out, tmpl.c_str(), tmpl.size() + 1);
    return 0;
#endif
}

YUZU_EXPORT int yuzu_create_temp_dir(const char* prefix, const char* directory, char* path_out,
                                     size_t path_out_size) {
    if (!path_out || path_out_size == 0) {
#ifdef _WIN32
        // See the identical guard/comment in yuzu_create_temp_file above.
        SetLastError(ERROR_INVALID_PARAMETER);
#endif
        return -1;
    }

    const char* pfx = (prefix && prefix[0]) ? prefix : "yuzu-";

#ifdef _WIN32
    wchar_t temp_dir_w[MAX_PATH];
    if (!get_temp_dir_w(directory, temp_dir_w, MAX_PATH))
        return -1; // MultiByteToWideChar/GetTempPathW already set a meaningful last-error

    char hex[33]{};
    if (!generate_random_hex(hex, sizeof(hex))) {
        // See yuzu_create_temp_file's identical comment above: BCryptGenRandom
        // never calls SetLastError, so GetLastError() would otherwise be stale.
        SetLastError(ERROR_GEN_FAILURE);
        return -1;
    }

    auto full_path = build_temp_path_w(temp_dir_w, pfx, hex, nullptr);
    if (full_path.size() >= MAX_PATH) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return -1;
    }

    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!make_owner_only_sa(sa, sd)) {
        // See the identical fail-closed reasoning at the CreateFileW call
        // site in yuzu_create_temp_file above.
        return -1;
    }

    BOOL ok = CreateDirectoryW(full_path.c_str(), &sa);
    // Capture before LocalFree -- see the identical reasoning at the
    // CreateFileW call site in yuzu_create_temp_file above.
    const DWORD create_dir_err = GetLastError();
    if (sd)
        LocalFree(sd);
    if (!ok) {
        SetLastError(create_dir_err);
        return -1;
    }

    if (wide_to_utf8(full_path.c_str(), path_out, path_out_size) != 0) {
        // Capture wide_to_utf8's real failure code before RemoveDirectoryW's
        // (possibly successful) call can overwrite it -- see the identical
        // reasoning in yuzu_create_temp_file above.
        const DWORD saved_err = GetLastError();
        RemoveDirectoryW(full_path.c_str());
        SetLastError(saved_err);
        return -1;
    }
    return 0;

#else
    std::string temp_dir;
    if (directory && directory[0]) {
        temp_dir = directory;
    } else {
        std::error_code ec;
        temp_dir = fs::temp_directory_path(ec).string();
        if (ec)
            return -1;
    }

    std::string tmpl = temp_dir + "/" + pfx + "XXXXXX";

    if (mkdtemp(tmpl.data()) == nullptr)
        return -1;

    if (tmpl.size() + 1 > path_out_size) {
        rmdir(tmpl.c_str());
        return -1;
    }
    std::memcpy(path_out, tmpl.c_str(), tmpl.size() + 1);
    return 0;
#endif
}

} // extern "C"
