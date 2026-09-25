#pragma once

// installed_apps_macos_enrich.hpp -- #2273 macOS `list_inventory` enrichment (and, since
// ADR-0028's binding condition, the `list` action's bundle_id via bundle_id_for):
// per-app bundle identifier + signer + integrity, read NATIVELY (CFBundle +
// Security.framework's SecStaticCode API), never a subprocess. Modeled on
// certificates_plugin.cpp's read_keychain_secitem() for the
// Security/CoreFoundation linkage + ScopedCFRef discipline (the ESTABLISHED
// pattern for real CF/Security API calls in this tree); filesystem_macos_sig.hpp
// supplied the honest-status vocabulary this mirrors (valid/unsigned/unknown --
// no fabricated verdict), though that header classifies an already-captured
// `codesign` CLI result rather than calling Security.framework directly.
//
// SCOPE OF THE VERDICT -- read before trusting `signature_status`.
// This calls SecCodeCopySigningInformation only. It deliberately does NOT call
// SecStaticCodeCheckValidity (a deep, disk-reading verify). So what this
// reports is the PRESENCE of signing metadata, NOT its validity:
//   - an ad-hoc or self-signed bundle reads "signed";
//   - a bundle whose signature has been BROKEN reads "signed" too. Measured
//     during adversarial review: a copy of Calculator.app with
//     Contents/_CodeSignature deleted, and separately one with bytes appended
//     to its Mach-O, both still report an identifier and 3 certificates
//     (SecStaticCodeCheckValidity returns -67023 for them), so this reports
//     "signed" AND hands back the original vendor's leaf CN as `publisher`.
//     Treat `publisher` here as UNVERIFIED attribution, never as proof of
//     origin.
// This is the same guarantee rpm's signature_status already carries in
// installed_apps_inventory.hpp -- "a signature is recorded", read from stored
// metadata, never a live cryptographic verification -- which is why the two
// share one binary vocabulary. It is NOT a Gatekeeper or notarization verdict
// and must not be presented as tamper detection.
//
// Deep verification was left OUT rather than ruled out. The measured cost is
// not prohibitive (SecStaticCodeCheckValidity: Calculator 4 ms, Signal 31 ms,
// Safari 70 ms, Docker 1304 ms; ~30 s across the 316 apps on the review host,
// on a DAILY collector), so the original "far too slow" rationale does not
// survive measurement. Adopting it would change signature_status from a
// presence flag into a validity verdict -- a contract change for the server
// and every consumer, and a third state for "signed but invalid". That is an
// open decision for the repo owner, recorded here and in the gate report,
// deliberately not taken unilaterally in this PR.
//
// ADR-0028 binding condition (list-only): bundle_id_for() below feeds the
// `list` action's trailing bundle_id column. That is an operator-facing column
// only; the ADR-0016 InvRecord is untouched (see the next paragraph).
//
// ADR-0016 CRITICAL: the blob-v2 12-field row (installed_apps_inventory.hpp)
// is hashed byte-identically on agent and server. This header hands its
// caller a bundle id, publisher, and a binary signed/unsigned verdict; the
// caller (installed_apps_plugin.cpp::get_inventory_macos) fills ONLY the
// pre-existing, currently-honest-empty `publisher`/`signature_status` fields
// with it. `bundle_id` has no existing home in the frozen 12-field row and is
// deliberately NOT persisted there -- see the call site's comment and this
// PR's report for the open question this leaves for a future field (a v3
// contract bump, not a repurposed Linux-only field).

#if defined(__APPLE__)

#include <string>

#include <yuzu/agent/scoped_cfref.hpp>

#ifdef YUZU_HAVE_SECURITY_FRAMEWORK
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace yuzu::installed_apps::macos_enrich {

struct EnrichResult {
    std::string bundle_id;       // CFBundleGetIdentifier -- e.g. "com.apple.Keynote"
    std::string publisher;       // the leaf signing cert's Common Name
    std::string signature_status; // "signed" | "unsigned" | "" (unknown/no
                                  // Security framework at build time -- honest-
                                  // empty, matching installed_apps_inventory.hpp's
                                  // "fields an ecosystem does not store are EMPTY,
                                  // never synthesised" contract)
};

#ifdef YUZU_HAVE_SECURITY_FRAMEWORK

namespace detail {

inline std::string cfstring_to_utf8(CFStringRef s) {
    if (!s)
        return {};
    // CFStringGetCStringPtr is a fast-path that may return null even for a
    // valid string (no guaranteed backing UTF-8 buffer); CFStringGetCString
    // always works and is what's used here, matching read_keychain_secitem's
    // sibling code in certificates_plugin.cpp for CF string extraction.
    const CFIndex len = CFStringGetLength(s);
    if (len <= 0)
        return {};
    const CFIndex raw_max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    // Documented to return kCFNotFound (-1) if the conversion size cannot be
    // computed; +1 would then make a 0-sized buffer and CFStringGetCString
    // would be handed a zero capacity.
    if (raw_max <= 0)
        return {};
    const CFIndex max_bytes = raw_max + 1;
    std::string out(static_cast<std::size_t>(max_bytes), '\0');
    if (!CFStringGetCString(s, out.data(), max_bytes, kCFStringEncodingUTF8))
        return {};
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
}

// CFBundleIdentifier of the bundle at `url` (borrowed: the caller keeps the CFURL),
// or "" when it is not a readable bundle or carries no identifier. The ONE
// bundle-id read in this plugin: bundle_id_for() (the `list` action's bundle_id
// column) builds a URL from a path and calls it; enrich_app() passes the CFURL it
// already built for SecStaticCode, so each app costs one CFURL, not two.
inline std::string bundle_id_for_url(CFURLRef url) {
    auto* raw_bundle = CFBundleCreate(nullptr, url);
    if (!raw_bundle)
        return {};
    yuzu::agent::ScopedCFRef<CFBundleRef> bundle(raw_bundle);
    // CFBundleGetIdentifier returns a BORROWED (Get-rule) reference owned
    // by the bundle -- never itself ScopedCFRef-wrapped, matching
    // certificates_plugin.cpp's own borrowed-vs-owned discipline.
    return cfstring_to_utf8(CFBundleGetIdentifier(bundle.get()));
}

} // namespace detail

// Bundle identifier (CFBundleIdentifier) for the app at `app_path` (an absolute
// .app path), or "" when the path is not a readable bundle or carries no
// identifier. The `list` action's bundle_id column calls this; the read itself is
// detail::bundle_id_for_url, shared with enrich_app(). No SecStaticCode --
// CFBundle only, so it is cheap enough for the interactive `list` path.
inline std::string bundle_id_for(const std::string& app_path) {
    yuzu::agent::ScopedCFRef<CFURLRef> url(CFURLCreateFromFileSystemRepresentation(
        // reinterpret_cast char* -> const UInt8*: byte-type aliasing is the
        // explicit exemption to the strict-aliasing rule, and `app_path` is a
        // caller-owned lvalue that outlives this call, so the buffer stays
        // valid for the whole of CFURLCreateFromFileSystemRepresentation.
        nullptr, reinterpret_cast<const UInt8*>(app_path.c_str()),
        static_cast<CFIndex>(app_path.size()), /*isDirectory=*/true));
    if (!url)
        return {};
    return detail::bundle_id_for_url(url.get());
}

// Enrich one app bundle at `app_path` (an absolute .app path, taken from a
// system_profiler "Location:" line -- see installed_apps_parsers.hpp).
// Every CoreFoundation object here is ScopedCFRef-owned (scoped_cfref.hpp) --
// read that header's reset()/same-identity contract before touching this
// function, exactly as certificates_plugin.cpp's own header comment directs.
inline EnrichResult enrich_app(const std::string& app_path) {
    EnrichResult out;

    yuzu::agent::ScopedCFRef<CFURLRef> url(CFURLCreateFromFileSystemRepresentation(
        // reinterpret_cast char* -> const UInt8*: byte-type aliasing is the
        // explicit exemption to the strict-aliasing rule, and `app_path` is a
        // caller-owned lvalue that outlives this call, so the buffer stays
        // valid for the whole of CFURLCreateFromFileSystemRepresentation.
        nullptr, reinterpret_cast<const UInt8*>(app_path.c_str()),
        static_cast<CFIndex>(app_path.size()), /*isDirectory=*/true));
    if (!url)
        return out;

    // -- bundle identifier via CFBundle (shared read, see detail::bundle_id_for_url) --
    out.bundle_id = detail::bundle_id_for_url(url.get());

    // -- signer + integrity via SecStaticCode --
    // ADOPT FIRST, TEST SECOND. Testing the status before adopting leaves a
    // return statement between the +1 and its owner: if the API ever returns a
    // non-success OSStatus while still having written the out-param, that
    // reference is dropped on the floor -- and this runs across every bundle on
    // the host, daily. ScopedCFRef adopts nullptr safely, so ordering the
    // adoption first is a strict widening of the guard, never a narrowing.
    SecStaticCodeRef raw_code = nullptr;
    const OSStatus create_status =
        SecStaticCodeCreateWithPath(url.get(), kSecCSDefaultFlags, &raw_code);
    yuzu::agent::ScopedCFRef<SecStaticCodeRef> code(raw_code);
    if (create_status != errSecSuccess || !code)
        return out;

    // SecCodeCopySigningInformation's declared parameter type (SecCode.h) is
    // SecStaticCodeRef -- it takes the static code object directly, no cast
    // to SecCodeRef needed or correct here.
    // Adopt first, test second -- same reasoning as the block above.
    CFDictionaryRef raw_info = nullptr;
    const OSStatus info_status =
        SecCodeCopySigningInformation(code.get(), kSecCSSigningInformation, &raw_info);
    yuzu::agent::ScopedCFRef<CFDictionaryRef> info(raw_info);
    if (info_status != errSecSuccess || !info) {
        // errSecCSUnsigned is a POSITIVE "definitely has no signature at all"
        // -- report it honestly rather than folding it into the unknown
        // default. Any other failure (a locked/unreadable bundle, a Security
        // framework internal error, ...) stays honest-empty: this is NOT a
        // deep-verify call, so a non-errSecCSUnsigned failure here proves
        // nothing about whether the code object is actually signed.
        out.signature_status = (info_status == errSecCSUnsigned) ? "unsigned" : "";
        return out;
    }

    // CALL SUCCESS IS NOT A SIGNATURE. Measured on macOS 26 (2026-08-24):
    // SecStaticCodeCreateWithPath AND SecCodeCopySigningInformation BOTH
    // return errSecSuccess for a bundle `codesign -dv` calls "code object is
    // not signed at all" -- the dictionary simply comes back without signing
    // keys, and errSecCSUnsigned is never surfaced on this path. Reporting
    // "signed" on call success therefore labelled EVERY enriched app signed,
    // including genuinely unsigned ones -- a false positive on a
    // security-posture field (installed_apps_inventory.hpp's own wording).
    //
    // kSecCodeInfoIdentifier presence is the discriminator, verified against
    // three ground-truth cases on this host:
    //   unsigned  -> identifier ABSENT,  0 certs  => "unsigned"
    //   ad-hoc    -> identifier PRESENT, 0 certs  => "signed" (no publisher)
    //   Apple     -> identifier PRESENT, 3 certs  => "signed" + leaf CN
    // This is a PRESENCE test, not a validity test -- a bundle whose signature
    // has been broken still has an identifier and still reads "signed". See
    // this header's top comment for the measured cases and why deep
    // verification is an open decision rather than an oversight.
    const bool has_identifier =
        CFDictionaryGetValue(info.get(), kSecCodeInfoIdentifier) != nullptr;
    out.signature_status = has_identifier ? "signed" : "unsigned";
    if (!has_identifier)
        return out; // unsigned code has no leaf cert to read a publisher from

    if (auto* certs = static_cast<CFArrayRef>(
            CFDictionaryGetValue(info.get(), kSecCodeInfoCertificates));
        certs && CFArrayGetCount(certs) > 0) {
        // Array element is a BORROWED (Get-rule) reference owned by `certs`,
        // which is itself borrowed from `info` -- so the leaf stays valid for
        // as long as `info` does, which is this whole scope.
        // const_cast: CFArrayGetValueAtIndex is typed `const void*` purely
        // because CF has no const-qualified object model; the underlying
        // SecCertificateRef is a genuinely non-const CF object, and
        // SecCertificateCopyCommonName takes it by non-const ref. Nothing here
        // writes through the pointer, so this removes a const the API added,
        // never one the object actually had.
        auto leaf = static_cast<SecCertificateRef>(
            const_cast<void*>(CFArrayGetValueAtIndex(certs, 0)));
        CFStringRef raw_name = nullptr;
        if (SecCertificateCopyCommonName(leaf, &raw_name) == errSecSuccess && raw_name) {
            yuzu::agent::ScopedCFRef<CFStringRef> common_name(raw_name);
            out.publisher = detail::cfstring_to_utf8(common_name.get());
        }
    }
    return out;
}

#else // !YUZU_HAVE_SECURITY_FRAMEWORK

// A box missing the Security framework at build time compiles an honest
// no-op -- every field stays empty, matching certificates/meson.build's own
// `required: false` fallback contract.
inline EnrichResult enrich_app(const std::string& /*app_path*/) { return EnrichResult{}; }
inline std::string bundle_id_for(const std::string& /*app_path*/) { return {}; }

#endif // YUZU_HAVE_SECURITY_FRAMEWORK

} // namespace yuzu::installed_apps::macos_enrich

#endif // __APPLE__
