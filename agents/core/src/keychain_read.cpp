// keychain_read.cpp -- bounded, raw SecItem keychain read (#3246, #2318a).
// See keychain_read.hpp for why this lives in agent-core rather than in the
// plugin that consumes it (detached-thread lifetime vs plugin dlclose()).

#include <yuzu/agent/keychain_read.hpp>

#include <bounded_wait.hpp> // yuzu::shared::bounded_call_ex (agents/shared)

#include <spdlog/spdlog.h>

#include <cstddef>

#if defined(__APPLE__) && defined(YUZU_HAVE_SECURITY_FRAMEWORK)
#include <Security/Security.h> // SecKeychainOpen/SecItemCopyMatching

#include <yuzu/agent/scoped_cfref.hpp>
#endif

namespace yuzu::agent {

#if defined(__APPLE__) && defined(YUZU_HAVE_SECURITY_FRAMEWORK)

static_assert(kKeychainReadPermBit == kSecReadPermStatus);

/**
 * test_keychain_read.cpp's injected-read seam cannot exercise this function
 * directly (it needs a real keychain), so the mechanism's equivalence to the
 * `security find-certificate -a -p` subprocess it replaces was established
 * empirically instead, and the check is REPRODUCIBLE rather than anecdotal:
 * enumerate each keychain through this query and compare the resulting
 * uppercase SHA-1 thumbprint SET to the set obtained by piping
 * `security find-certificate -a -p <keychain>` through
 * `openssl x509 -noout -fingerprint -sha1` per PEM block. Measured
 * 2026-08-17 on macOS 26.5.2 arm64 (certificates_plugin.cpp:783-789, prior to
 * the move): System.keychain 3/3 and SystemRootCertificates.keychain 158/158
 * thumbprints, both sets IDENTICAL. Re-run that comparison, not a re-read of
 * this comment, when changing the query below.
 *
 * SecKeychainOpen/SecItemCopyMatching are synchronous CoreFoundation/Security
 * calls with no deadline or cancellation primitive of their own; the timeout
 * is enforced by detail::bounded_keychain_call (keychain_read.hpp) waiting on
 * a detached thread, never by this function itself.
 *
 * Every CoreFoundation object here is ScopedCFRef-owned (scoped_cfref.hpp) --
 * that header's reset()/same-identity contract governs everything below.
 * Every value handed to a ScopedCFRef below is a fresh Create/Copy-rule +1
 * reference; `CFArrayGetValueAtIndex` results are borrowed (Get-rule)
 * references owned by the array and are never ScopedCFRef-wrapped
 * themselves, only passed to SecCertificateCopyData (which DOES return an
 * owned +1 CFDataRef, and IS wrapped).
 *
 * SecKeychainOpen is deprecated (macOS 10.10+) but remains the API this
 * seam is built against and is fully functional on every supported host;
 * the pragma below silences just that one, already-triaged warning.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
KeychainReadResult secitem_keychain_read(const std::string& keychain_path) {
    KeychainReadResult out;
    out.status = KeychainReadStatus::OpenFailed;

    SecKeychainRef raw_keychain = nullptr;
    OSStatus open_status = SecKeychainOpen(keychain_path.c_str(), &raw_keychain);
    if (open_status != errSecSuccess || !raw_keychain) {
        out.detail = "SecKeychainOpen failed (" + std::to_string(open_status) + ")";
        return out;
    }
    ScopedCFRef<SecKeychainRef> keychain(raw_keychain);

    // SecKeychainOpen DOES NOT VALIDATE THE PATH -- it returns errSecSuccess
    // and a live SecKeychainRef for a path that does not exist, and for a
    // file that is not a keychain at all. SecItemCopyMatching over such a
    // reference then returns errSecItemNotFound, which is indistinguishable
    // from a genuinely empty keychain -- so without this check a missing,
    // deleted or corrupt System.keychain would be reported as "read fine,
    // zero certificates" rather than as a read failure, silently dropping
    // the entire trust store from a certificate inventory.
    //
    // SecKeychainGetStatus is the cheap discriminator (measured on macOS
    // 26.5.2, arm64): errSecSuccess for a real keychain,
    // errSecNoSuchKeychain (-25294) for a non-existent path,
    // errSecInvalidKeychain (-25295) for an existing non-keychain file.
    SecKeychainStatus keychain_status = 0;
    OSStatus status_rc = SecKeychainGetStatus(keychain.get(), &keychain_status);
    if (status_rc != errSecSuccess) {
        out.detail = "SecKeychainGetStatus failed (" + std::to_string(status_rc) + ")";
        return out;
    }
    bool readable = keychain_status_readable(static_cast<std::uint32_t>(keychain_status));

    const void* keychain_values[] = {keychain.get()};
    ScopedCFRef<CFArrayRef> search_list(
        CFArrayCreate(nullptr, keychain_values, 1, &kCFTypeArrayCallBacks));
    if (!search_list) {
        out.detail = "CFArrayCreate failed";
        return out;
    }

    ScopedCFRef<CFMutableDictionaryRef> query(CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    if (!query) {
        out.detail = "CFDictionaryCreateMutable failed";
        return out;
    }
    CFDictionarySetValue(query.get(), kSecClass, kSecClassCertificate);
    CFDictionarySetValue(query.get(), kSecMatchSearchList, search_list.get());
    CFDictionarySetValue(query.get(), kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query.get(), kSecReturnRef, kCFBooleanTrue);

    CFTypeRef raw_result = nullptr;
    OSStatus status = SecItemCopyMatching(query.get(), &raw_result);
    if (status == errSecItemNotFound) {
        // #2318a: an empty query is ambiguous on its own -- the keychain's
        // own readable-permission bit is what disambiguates a genuinely
        // empty, readable keychain from one this process cannot read.
        out.status = classify_empty_query(readable);
        return out;
    }
    if (status != errSecSuccess || !raw_result) {
        out.detail = "SecItemCopyMatching failed (" + std::to_string(status) + ")";
        return out;
    }
    ScopedCFRef<CFTypeRef> result(raw_result);

    // kSecMatchLimitAll documents a CFArrayRef result; defensively also
    // accept a bare (non-array) single-item result, in case a future SDK's
    // behaviour for a one-item match ever differs from what this header was
    // verified against.
    std::vector<CFTypeRef> items;
    if (CFGetTypeID(result.get()) == CFArrayGetTypeID()) {
        auto array = static_cast<CFArrayRef>(const_cast<void*>(result.get()));
        CFIndex count = CFArrayGetCount(array);
        for (CFIndex i = 0; i < count; ++i)
            items.push_back(CFArrayGetValueAtIndex(array, i));
    } else {
        items.push_back(result.get());
    }

    std::size_t converted = 0;
    std::size_t attempted = 0;
    for (CFTypeRef item : items) {
        if (attempted >= kMaxKeychainReadCerts)
            break;
        ++attempted;
        auto cert_ref = static_cast<SecCertificateRef>(const_cast<void*>(item));
        ScopedCFRef<CFDataRef> der(SecCertificateCopyData(cert_ref));
        if (!der)
            continue; // conversion failure -- result is no longer exhaustive
        const auto* bytes = CFDataGetBytePtr(der.get());
        auto len = CFDataGetLength(der.get());
        if (!bytes || len <= 0)
            continue;
        out.certs_der.emplace_back(bytes, bytes + static_cast<std::size_t>(len));
        ++converted;
    }
    out.status = fold_read_cap(items.size(), converted, kMaxKeychainReadCerts);
    return out;
}
#pragma clang diagnostic pop

// SecKeychainGetStatus bits measured on macOS 26.6.2 (arm64), unprivileged
// user session (not root -- production runs as the root LaunchDaemon, but
// SecKeychainGetStatus reads the keychain's own ACL/lock state, not the
// caller's identity, so the bits are session-relative rather than
// privilege-relative and this measurement is representative):
//   System.keychain              -> rc=0  bits=0x2 (readable=yes writable=no)
//   SystemRootCertificates.keychain -> rc=0 bits=0x2 (readable=yes writable=no)
//   login.keychain-db (own)      -> rc=0  bits=0x7 (readable=yes writable=yes)
//   fresh empty keychain, unlocked (`security create-keychain`) -> rc=0 bits=0x7
//   fresh empty keychain, LOCKED                                -> rc=0 bits=0x2
//     (readable bit STAYS SET while locked -- kSecReadPermStatus tracks the
//     keychain's ACL, not its current unlock state)
//   a copy of System.keychain, chmod 000 -> SecKeychainOpen still succeeds
//     (it does not validate the path, see above), but SecKeychainGetStatus
//     itself FAILS: rc=-61, bits=0x0 -- this is the OpenFailed branch, not
//     the readable-bit fold; a file-permission failure and a locked-but-
//     accessible keychain are distinguishable failure MODES, not points on
//     the same bit.
//
// The #2318a question this exists to answer -- "can a LOCKED keychain be
// misread as a genuinely EMPTY one" -- was tested directly through
// read_keychain_bounded (not just the raw bits) against a real locked
// keychain: a freshly-created, then-locked, EMPTY keychain reads back
// {Completed, certs=0} (correctly empty), and the SAME keychain populated
// with one self-signed certificate BEFORE locking reads back
// {Completed, certs=1} even while locked. Both results are correct, and for
// the same underlying reason: SecItemCopyMatching(kSecClassCertificate, ...)
// does not require the keychain to be unlocked, because a certificate is
// public, non-secret material (unlike a generic/internet password or a
// private key, which DO require an unlock) -- so lock state genuinely
// cannot hide a certificate from this specific query shape. The original
// #2318 "locked keychain read as absent" defect lived in a different code
// path (the `security find-certificate` CLI wrapper around the login
// keychain, since retired by #3406's argv-ization plus this seam's own
// console-owner recheck, B3) and does not reproduce here, empirically, on
// the class of item this seam reads.

#else // !(defined(__APPLE__) && defined(YUZU_HAVE_SECURITY_FRAMEWORK))

KeychainReadResult secitem_keychain_read(const std::string&) {
    // No Security framework on this build. The only consumer is macOS-only;
    // this exists so the TU compiles in the shared agent-core build.
    KeychainReadResult out;
    out.status = KeychainReadStatus::OpenFailed;
    out.detail = "Security framework unavailable in this build";
    return out;
}

#endif

// The shared status-mapping logic is detail::bounded_keychain_call
// (keychain_read.hpp, header-only). Both callers below instantiate it with a
// TU-local lambda, so every byte the detached thread runs -- the lambda, its
// invoker, its destructor -- is still agent-core text; only the lambdas are
// TU-local, the template itself is instantiated here.

KeychainReadResult read_keychain_bounded(const std::string& keychain_path,
                                         std::chrono::milliseconds timeout) {
    // No std::function anywhere on this path: the callable is a lambda whose
    // closure type is defined HERE, so its invoker/destructor are emitted
    // here too. See the header's note on why a default argument on the
    // _for_test overload would be unsafe.
    return detail::bounded_keychain_call(timeout, [keychain_path]() -> KeychainReadResult {
        return secitem_keychain_read(keychain_path);
    });
}

KeychainReadResult read_keychain_bounded_for_test(const std::string& keychain_path,
                                                   std::chrono::milliseconds timeout,
                                                   const KeychainReadFn& read) {
    // Test-only overload. The injected std::function is COPIED into a lambda
    // defined in this TU; a test's own target type is instantiated in the
    // test binary, which is never dlclose()'d, so this path carries no
    // unload risk.
    return detail::bounded_keychain_call(timeout, [read, keychain_path]() -> KeychainReadResult {
        return read(keychain_path);
    });
}

} // namespace yuzu::agent
