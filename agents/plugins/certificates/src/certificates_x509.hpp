#pragma once

// certificates_x509.hpp -- pure, in-process X.509 certificate parsing via
// libcrypto (OpenSSL). No filesystem access, no subprocess execution: every
// function here operates only on already-in-memory PEM/DER bytes handed in
// by the caller. certificates_plugin.cpp owns all the I/O (the Linux PEM
// file read, the macOS SecItem DER fetch) and hands this header the raw
// bytes; that split is what makes this header directly unit-testable
// (tests/unit/test_certificates_x509.cpp) without a filesystem or a
// keychain.
//
// This replaces the `openssl x509 ...` subprocess call on Linux and backs
// the macOS SecItem DER decode path (certificates_plugin.cpp's list/details
// for System.keychain and SystemRootCertificates.keychain -- see the plugin
// file's own comments). It deliberately does NOT touch the macOS
// login-keychain path, which stays on its existing `security
// find-certificate` + certificates_macos_parsers.hpp combined-output parse
// (a rung-2 pre-split argv through the bounded subprocess runner since
// #3406 -- no shell; registered as Decision-1 sinks
// `certificates/list_certs_macos#1` / `certificates/details_cert_macos#1` in
// docs/agent-spawn-sink-manifest.md).
//
// Every field-extraction recipe below is EMPIRICALLY PINNED against the
// verified host OpenSSL 3.6.2 at /opt/homebrew/opt/openssl@3/bin/openssl
// (the system /usr/bin/openssl on this host is LibreSSL 3.3.6 and was NOT
// used to derive any of these strings) -- tests/unit/test_certificates_x509.cpp
// records, for every vector, the exact generating command and the exact
// `openssl x509 -noout -subject -issuer -serial -fingerprint -sha1 -ext
// keyUsage` output each recipe is asserted against. Do not substitute a
// plausible-looking alternative API (e.g. XN_FLAG_ONELINE for the name
// printer, or ASN1_INTEGER_to_BN+BN_bn2hex for the serial) without
// re-verifying parity -- see the doc comment on each extractor below for
// exactly what was ruled out and why.
//
// Every OpenSSL object below is RAII-owned (BioPtr/X509Ptr, unique_ptr with
// a custom deleter) -- no manual _free() call on any path, success or
// error. Garbage/truncated input is handled by treating a failed
// PEM_read_bio_X509/d2i_X509 call as "no more certificates here", never a
// thrown exception.

// Include order per docs/cpp-conventions.md: STL -> third-party -> project.
#include <climits>
#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace yuzu::certificates_x509 {

/// One certificate's worth of operator-visible fields, in the exact shape
/// certificates_plugin.cpp's CertRecord expects to adopt them into. Every
/// field defaults to this header's own honest sentinel ("(unknown)"/
/// "(none)") so a caller that only partially fills a CertFields (it
/// shouldn't -- extract_all() below always sets every field) still gets a
/// defined value rather than an empty string.
struct CertFields {
    std::string subject = "(unknown)";
    std::string issuer = "(unknown)";
    std::string not_before = "(unknown)";
    std::string not_after = "(unknown)";
    std::string serial = "(unknown)";
    std::string thumbprint = "(unknown)";
    std::string key_usage = "(none)";
};

namespace detail {

struct BioDeleter {
    void operator()(BIO* b) const noexcept {
        if (b)
            BIO_free(b);
    }
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

struct X509Deleter {
    void operator()(X509* x) const noexcept {
        if (x)
            X509_free(x);
    }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

/// Left-trim ASCII spaces/tabs and drop a trailing '\r' -- mirrors
/// certificates_macos_parsers.hpp's strip_leading_blank plus the extra
/// carriage-return strip a BIO_new(BIO_s_mem()) line may carry.
inline std::string trim_line(std::string s) {
    std::size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
        ++i;
    s.erase(0, i);
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

/// subject/issuer: X509_NAME_print_ex with XN_FLAG_SEP_CPLUS_SPC |
/// ASN1_STRFLGS_UTF8_CONVERT -- get_nameopt()'s exact flag combination, i.e.
/// the `openssl x509 -noout -subject` CLI's OWN default rendering. Verified
/// (test_certificates_x509.cpp) to print `C=GB, O=Yuzu, Inc., CN=t+e` for a
/// subject that XN_FLAG_ONELINE would print as
/// `C = GB, O = "Yuzu, Inc.", CN = "t+e"` and XN_FLAG_RFC2253 would print
/// (reversed AND escaped) as `CN=t\+e,O=Yuzu\, Inc.,C=GB` -- neither of
/// those, nor X509_NAME_oneline, is an acceptable substitute: this is an
/// operator-visible output contract, not a free choice of "a" name
/// renderer. The trailing strip below is defensive (this rendering has no
/// leading space in practice, unlike the old `subject=<space>...` subprocess
/// line it replaces) -- kept for parity with that old code's own strip.
inline std::string extract_name(const X509_NAME* name) {
    if (!name)
        return "(unknown)";
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio)
        return "(unknown)";
    if (X509_NAME_print_ex(bio.get(), name, 0,
                            XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_UTF8_CONVERT) < 0)
        return "(unknown)";
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || !data)
        return "(unknown)";
    std::string s(data, static_cast<std::size_t>(len));
    while (!s.empty() && s.front() == ' ')
        s.erase(s.begin());
    return s;
}

/// not_before/not_after: ASN1_TIME_to_tm then a plain YYYY-MM-DD format --
/// the in-process equivalent of the old code's `-dateopt iso_8601` substr(10)
/// result. tm_year is years-since-1900 and tm_mon is 0-based per <ctime>
/// convention; both are corrected here. The old code's OTHER fallback (a raw
/// `notBefore=<RFC-822-ish date>` string) only fired when a SECOND openssl
/// subprocess call failed -- there is no in-process analogue to "the second
/// of two calls disagreeing", so any ASN1_TIME_to_tm failure here goes
/// straight to "(unknown)" rather than trying to reproduce that fallback.
inline std::string extract_date(const ASN1_TIME* t) {
    if (!t)
        return "(unknown)";
    struct tm tm_val {};
    if (ASN1_TIME_to_tm(t, &tm_val) != 1)
        return "(unknown)";
    return std::format("{:04d}-{:02d}-{:02d}", tm_val.tm_year + 1900, tm_val.tm_mon + 1,
                        tm_val.tm_mday);
}

/// serial: i2a_ASN1_INTEGER, NOT ASN1_INTEGER_to_BN + BN_bn2hex. Both render
/// identically for every serial that survives d2i (OpenSSL's ASN1 INTEGER
/// decoder strips the DER sign-disambiguation leading 0x00 byte on decode,
/// so a "padded" positive serial's in-memory ASN1_INTEGER never actually
/// retains that byte either way -- verified empirically against this header's
/// own decode path, not assumed) EXCEPT for the serial value zero: i2a
/// prints the single content byte 0x00 as the byte-pair "00", while
/// ASN1_INTEGER_to_BN's BIGNUM normalizes a zero magnitude to nothing and
/// BN_bn2hex prints just "0" -- a real, empirically-confirmed divergence
/// (see test_certificates_x509.cpp's serial-zero vector) between the two
/// APIs that i2a_ASN1_INTEGER's byte-pair rendering avoids. i2a also handles
/// a negative serial's sign (a literal '-' prefix) the same way BN_bn2hex
/// would -- prints unchanged for that case -- so the only vector that
/// actually needs to pin i2a over BN is the zero-value one.
inline std::string extract_serial(const ASN1_INTEGER* serial) {
    if (!serial)
        return "(unknown)";
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio)
        return "(unknown)";
    if (i2a_ASN1_INTEGER(bio.get(), serial) < 0)
        return "(unknown)";
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || !data)
        return "(unknown)";
    return std::string(data, static_cast<std::size_t>(len));
}

/// thumbprint: X509_digest(x, EVP_sha1(), ...) rendered as uppercase hex with
/// no separators -- parity with the old colon-stripped
/// `-fingerprint -sha1` subprocess output. EVP recipe precedent:
/// agents/plugins/procfetch/src/procfetch_plugin.cpp:79-115 (there via
/// EVP_MD_CTX for a whole-file digest; here X509_digest is the one-call
/// libcrypto convenience wrapper for hashing a certificate's own DER
/// encoding, so no separate EVP_MD_CTX/BIO plumbing is needed).
inline std::string extract_thumbprint(X509* x) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (X509_digest(x, EVP_sha1(), md, &len) != 1)
        return "(unknown)";
    std::string hex;
    hex.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i)
        hex += std::format("{:02X}", md[i]);
    return hex;
}

/// key_usage: X509_get_ext_by_NID(x, NID_key_usage, -1) locates the
/// extension (absent -> "(none)"; verified: `openssl x509 -ext keyUsage`
/// writes "No extensions in certificate" to STDERR, which the old
/// `2>/dev/null` subprocess call discarded, leaving an empty captured
/// stdout and hence the old code's "(none)" branch). When present,
/// X509V3_EXT_print(bio, ext, 0, 0) is the SAME routine the CLI's `-ext`/
/// `-text` extension printers call, so no hand-written bit-name table can
/// drift from it. Verified (test_certificates_x509.cpp) that
/// X509V3_EXT_print's own output is JUST the value line(s) -- no
/// "X509v3 Key Usage:"/"critical" header, that header is added by a
/// different, higher-level caller the CLI uses (X509V3_extensions_print),
/// which this header deliberately does not call. The old code's line
/// selection (split into lines, left-trim each, skip any line containing
/// "X509v3" or "critical", take the LAST remaining non-empty line) is
/// applied VERBATIM anyway: it is a no-op filter on output that never
/// contains those substrings, so it stays correct if a future OpenSSL
/// version's X509V3_EXT_print ever changes to include its own header again.
inline std::string extract_key_usage(X509* x) {
    int idx = X509_get_ext_by_NID(x, NID_key_usage, -1);
    if (idx < 0)
        return "(none)";
    X509_EXTENSION* ext = X509_get_ext(x, idx);
    if (!ext)
        return "(none)";
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio)
        return "(none)";
    if (X509V3_EXT_print(bio.get(), ext, 0, 0) <= 0)
        return "(none)";
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || !data)
        return "(none)";
    std::string text(data, static_cast<std::size_t>(len));

    std::istringstream iss(text);
    std::string raw_line;
    std::string last_line;
    while (std::getline(iss, raw_line)) {
        auto line = trim_line(std::move(raw_line));
        if (!line.empty() && line.find("X509v3") == std::string::npos &&
            line.find("critical") == std::string::npos) {
            last_line = line;
        }
    }
    return last_line.empty() ? "(none)" : last_line;
}

/// Extract every field for one already-parsed X509*. Always sets every
/// CertFields member (never leaves a partial/default-constructed field for
/// a certificate that parsed successfully as an X509 object) -- an
/// individual field's own extractor falls back to "(unknown)"/"(none)" only
/// for a failure WITHIN that field's own extraction, never for the whole
/// certificate.
inline CertFields extract_all(X509* x) {
    CertFields f;
    f.subject = extract_name(X509_get_subject_name(x));
    f.issuer = extract_name(X509_get_issuer_name(x));
    f.not_before = extract_date(X509_get0_notBefore(x));
    f.not_after = extract_date(X509_get0_notAfter(x));
    f.serial = extract_serial(X509_get_serialNumber(x));
    f.thumbprint = extract_thumbprint(x);
    f.key_usage = extract_key_usage(x);
    return f;
}

} // namespace detail

/// Parse EVERY certificate in `pem`, in file order, via BIO_new_mem_buf
/// (a read-only view over the caller's own bytes -- no copy, no filesystem)
/// feeding a PEM_read_bio_X509 loop that keeps reading until a call fails
/// (end of valid PEM blocks reached, or the remaining bytes aren't a valid
/// PEM certificate at all). Garbage input, a truncated PEM block, or an
/// empty string all yield an empty vector -- PEM_read_bio_X509 failing on
/// its FIRST call ends the loop before anything is pushed -- never a thrown
/// exception. Whether a caller must restrict itself to only the first
/// returned certificate (cardinality parity with the replaced
/// `openssl x509 -in <file>`, which reads only the first PEM block in a
/// file) is the CALLER's decision, not this function's -- see
/// certificates_plugin.cpp's first_cert_of_file() helper.
inline std::vector<CertFields> parse_pem_certs(std::string_view pem) {
    std::vector<CertFields> out;
    if (pem.empty() || pem.size() > static_cast<std::size_t>(INT_MAX))
        return out;
    detail::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio)
        return out;
    for (;;) {
        detail::X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (!cert) {
            ERR_clear_error(); // expected EOF/no-start-line failure
            break;
        }
        out.push_back(detail::extract_all(cert.get()));
    }
    return out;
}

/// Parse EXACTLY ONE DER-encoded certificate (the macOS SecItem path: each
/// SecCertificateCopyData result is one certificate's raw DER, never a PEM
/// stream) via d2i_X509. std::nullopt for empty input, a decode failure, or
/// anything that isn't a valid single DER certificate -- never a thrown
/// exception.
///
/// "Exactly one" is ENFORCED, not merely documented. d2i_X509 decodes the
/// FIRST DER object it finds and advances `p` past just that object; it does
/// not care what follows. Discarding that cursor (as this function first did)
/// meant a buffer holding a valid certificate followed by arbitrary trailing
/// bytes -- or two concatenated certificates -- was accepted, and the caller
/// silently got only the first one while believing the whole buffer had been
/// validated. That contradicted this function's own "a valid single DER
/// certificate" contract, so the cursor is now checked against the end of the
/// span and any unconsumed tail is a rejection.
///
/// This cannot change the behaviour of the production caller: SecItem hands
/// over exactly one certificate's DER per SecCertificateCopyData result, so
/// the cursor always lands precisely on the end. It closes the contract for
/// every FUTURE caller, where a framed or concatenated buffer is the
/// realistic input.
inline std::optional<CertFields> parse_der_cert(std::span<const unsigned char> der) {
    if (der.empty() || der.size() > static_cast<std::size_t>(LONG_MAX))
        return std::nullopt;
    const unsigned char* p = der.data();
    detail::X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    if (!cert) {
        ERR_clear_error();
        return std::nullopt;
    }
    if (p != der.data() + der.size()) {
        // A valid certificate, but not the WHOLE input -- reject rather than
        // silently authenticate a prefix of a buffer the caller handed over
        // as one certificate. No OpenSSL error was queued (the decode itself
        // succeeded), so there is nothing to ERR_clear_error() here.
        return std::nullopt;
    }
    return detail::extract_all(cert.get());
}

} // namespace yuzu::certificates_x509
