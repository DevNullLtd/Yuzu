/**
 * licensing_x509.hpp — pure, in-process PEM → certificate expiry (`notAfter`)
 * for the license_scan Linux entitlement_certs surface (SAM.10).
 *
 * Replaces the two `openssl x509 -noout -enddate` subprocess runs per
 * certificate with libcrypto called in this process (rung 1): PEM bytes in,
 * the `expires_at` wire strings out. No filesystem, no subprocess — the caller
 * (licensing_linux.cpp) owns the bounded file read and hands over bytes, which
 * is what makes this directly unit-testable (tests/unit/test_licensing_x509.cpp).
 *
 * Plugin-local on purpose: it mirrors the RAII owners and the
 * ASN1_TIME_to_tm recipe of agents/plugins/certificates/src/certificates_x509.hpp
 * (BioPtr/X509Ptr, extract_date) rather than including across plugins, and
 * reuses this plugin's own epoch_from_civil / expiry_wire_from_epoch so the
 * wire value is byte-identical to the previous openssl-CLI path (UTC-midnight
 * epoch seconds, decimal string).
 *
 * Failure semantics (the entitlement surface is authoritative — a certificate
 * that cannot be read must never vanish silently):
 *   - the ONLY clean end of input is PEM_R_NO_START_LINE from PEM_read_bio_X509
 *     (no further CERTIFICATE block). Any other PEM/ASN.1 error — a truncated
 *     block, bad base64, a block that does not decode as a certificate — is
 *     `parse_failure`, with every certificate parsed before it kept;
 *   - a file with no certificate at all (empty, garbage, key-only) is
 *     `parse_failure`;
 *   - a certificate whose notAfter cannot be converted, or is before the Unix
 *     epoch, is `parse_failure` for that certificate and contributes no row;
 *   - more than `max_certs` certificates sets `cert_cap_hit` (certificates
 *     left unexamined) and stops.
 * Non-certificate PEM blocks (the ENTITLEMENT DATA / RSA SIGNATURE blocks Red
 * Hat appends to entitlement certificates) are skipped by PEM_read_bio_X509's
 * own name matching, not treated as errors.
 *
 * Pinned against OpenSSL 3.x (vectors in the test record the generating
 * command). The OpenSSL error queue is per-thread; this function clears it on
 * entry and on every exit it leaves an error behind, so a stale entry from
 * other libcrypto use on the same thread cannot be mistaken for a clean EOF.
 */

#ifndef YUZU_LICENSE_SCAN_LICENSING_X509_HPP
#define YUZU_LICENSE_SCAN_LICENSING_X509_HPP

#include "licensing_parsers.hpp"

#include <climits>
#include <cstddef>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace yuzu::license_scan {

struct PemNotAfter {
    std::vector<std::string> expires_wire; ///< one UTC-midnight epoch string per parsed cert, file order
    bool parse_failure = false;            ///< something in the input could not be parsed as a certificate
    bool cert_cap_hit = false;             ///< more than max_certs certificates were present
};

namespace x509_detail {

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

/// notAfter → expires_at wire string; "" when the time cannot be converted or
/// is not after the Unix epoch.
[[nodiscard]] inline std::string not_after_wire(const X509* cert) {
    const ASN1_TIME* t = X509_get0_notAfter(cert);
    if (!t)
        return {};
    struct tm tm_val {};
    if (ASN1_TIME_to_tm(t, &tm_val) != 1)
        return {};
    // tm_year is years since 1900, tm_mon is 0-based (<ctime> convention).
    return expiry_wire_from_epoch(epoch_from_civil(
        static_cast<long long>(tm_val.tm_year) + 1900, static_cast<unsigned>(tm_val.tm_mon + 1),
        static_cast<unsigned>(tm_val.tm_mday)));
}

/// True when the most recent queued error is "no PEM start line" — the one
/// clean end-of-input signal PEM_read_bio_X509 gives.
[[nodiscard]] inline bool last_error_is_clean_eof() noexcept {
    const unsigned long e = ERR_peek_last_error();
    return e != 0 && ERR_GET_LIB(e) == ERR_LIB_PEM && ERR_GET_REASON(e) == PEM_R_NO_START_LINE;
}

} // namespace x509_detail

/// Every certificate's notAfter in `pem`, in file order, up to `max_certs`.
/// Never throws and never touches the filesystem or a subprocess.
[[nodiscard]] inline PemNotAfter parse_pem_not_after(std::string_view pem, std::size_t max_certs) {
    PemNotAfter out;
    if (pem.empty() || pem.size() > static_cast<std::size_t>(INT_MAX)) {
        out.parse_failure = true;
        return out;
    }
    ERR_clear_error();
    x509_detail::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) {
        ERR_clear_error();
        out.parse_failure = true;
        return out;
    }

    std::size_t read_ok = 0; // certificates decoded, whether or not notAfter converted
    for (;;) {
        x509_detail::X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (!cert) {
            if (!x509_detail::last_error_is_clean_eof())
                out.parse_failure = true;
            break;
        }
        if (read_ok == max_certs) {
            out.cert_cap_hit = true; // a (max_certs+1)-th certificate exists
            break;
        }
        ++read_ok;
        std::string wire = x509_detail::not_after_wire(cert.get());
        if (wire.empty())
            out.parse_failure = true;
        else
            out.expires_wire.push_back(std::move(wire));
    }
    ERR_clear_error();
    if (read_ok == 0 && !out.cert_cap_hit)
        out.parse_failure = true; // nothing decodable: never an empty success
    return out;
}

} // namespace yuzu::license_scan

#endif // YUZU_LICENSE_SCAN_LICENSING_X509_HPP
