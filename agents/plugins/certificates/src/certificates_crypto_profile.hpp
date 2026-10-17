#pragma once

// certificates_crypto_profile.hpp -- the cryptographic profile of one
// certificate (public-key algorithm, key size, signature algorithm), named
// from the algorithm OBJECT IDENTIFIERs alone.
//
// Pure by design: no OpenSSL, no CryptoAPI, no I/O. Each OS leg extracts the
// dotted OIDs (and, for RSA/DSA, the library's own key length) with its own
// API -- certificates_x509.hpp via libcrypto on Linux and macOS,
// certificates_plugin.cpp's get_crypto_profile() via CryptoAPI on Windows --
// and hands them to describe() below. Naming happens here, ONCE, so the same
// certificate reports the same three values on every OS. That cross-OS
// agreement is the whole reason this header exists: CryptoAPI's own display
// names ("sha256RSA") and OpenSSL's ("sha256WithRSAEncryption") differ, and an
// operator filtering a mixed fleet for weak crypto needs one vocabulary.
//
// The vocabulary is the standard ASN.1 identifier names (RFC 3279, 4055,
// 5758, 8410; NIST CSOR for SHA-3, ML-DSA and ML-KEM). Every OID/name pair in
// the tables below was checked against python-cryptography 50.0.1's
// SignatureAlgorithmOID / PublicKeyAlgorithmOID / _OID_TO_CURVE constants
// (tests/unit/test_certificates_crypto_profile.cpp records the check).
//
// An OID this header does not name is reported as its dotted form, never as
// "(unknown)": a dotted OID is still a correct, searchable answer (an
// operator can look it up, and a later table entry upgrades it to a name
// without any consumer seeing a different kind of value). "(unknown)" is
// reserved for "the certificate did not yield this field at all".

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::certificates_crypto {

/// The three operator-visible crypto-profile fields of a certificate row.
/// Defaults are the honest "could not be established" sentinel, matching
/// certificates_x509::CertFields' own "(unknown)".
struct CryptoProfile {
    std::string key_algorithm = "(unknown)";
    std::string key_bits = "(unknown)";
    std::string signature_algorithm = "(unknown)";
};

/// key_bits for an algorithm whose strength is fixed by the parameter set
/// key_algorithm already names (Ed25519, X448, ML-DSA-65, ...). Reporting a
/// number there would invent one: libcrypto says 253 for Ed25519, CryptoAPI
/// has no answer at all, and the RFCs speak of 256- and 456-bit keys.
inline constexpr std::string_view kImpliedBits = "(implied)";

/// Longest dotted OID accepted from a caller. Real algorithm and curve OIDs
/// are under 32 characters; the cap exists so a hostile certificate cannot
/// push an arbitrarily long string into a row.
inline constexpr std::size_t kMaxDottedOidLength = 64;

/// True when `oid` is a well-formed dotted OID: at least two arcs, digits and
/// single dots only, no leading/trailing dot, at most kMaxDottedOidLength
/// characters. Anything else (empty, a name, embedded '|' or CR/LF) is not
/// trusted as an OID and is treated as absent by describe().
inline bool is_dotted_oid(std::string_view oid) {
    if (oid.empty() || oid.size() > kMaxDottedOidLength)
        return false;
    bool prev_dot = true; // rejects a leading dot
    int dots = 0;
    for (char c : oid) {
        if (c == '.') {
            if (prev_dot)
                return false;
            prev_dot = true;
            ++dots;
        } else if (c >= '0' && c <= '9') {
            prev_dot = false;
        } else {
            return false;
        }
    }
    return !prev_dot && dots >= 1;
}

/// Decode a complete DER-encoded OBJECT IDENTIFIER (tag 0x06, definite length,
/// content) into dotted form. Used by the Windows leg on the EC public key's
/// AlgorithmIdentifier parameters, which CryptoAPI hands back as raw DER.
/// std::nullopt for anything that is not exactly one well-formed OID filling
/// the whole buffer: wrong tag, a length that disagrees with the buffer,
/// empty content, a non-minimal (0x80-led) arc, an arc that would overflow 64
/// bits, a final byte with its continuation bit set, or a result longer than
/// kMaxDottedOidLength.
inline std::optional<std::string> der_oid_to_dotted(std::span<const unsigned char> der) {
    if (der.size() < 3 || der[0] != 0x06)
        return std::nullopt;
    std::size_t len = 0;
    std::size_t pos = 2;
    if (der[1] < 0x80) {
        len = der[1];
    } else if (der[1] == 0x81 && der[2] >= 0x80) {
        // One long-form length byte; DER requires the short form below 128.
        len = der[2];
        pos = 3;
    } else {
        return std::nullopt;
    }
    if (len == 0 || pos + len != der.size())
        return std::nullopt;

    std::string out;
    std::uint64_t arc = 0;
    bool first = true;
    bool arc_started = false;
    for (std::size_t i = pos; i < der.size(); ++i) {
        const unsigned char b = der[i];
        if (!arc_started && b == 0x80)
            return std::nullopt; // non-minimal encoding
        if (arc > (UINT64_MAX >> 7))
            return std::nullopt; // would overflow
        arc = (arc << 7) | (b & 0x7Fu);
        arc_started = true;
        if (b & 0x80u)
            continue;
        if (first) {
            // X.690 8.19.4: the first subidentifier packs the first two arcs.
            const std::uint64_t top = arc < 40 ? 0 : (arc < 80 ? 1 : 2);
            out += std::to_string(top);
            out += '.';
            out += std::to_string(arc - top * 40);
            first = false;
        } else {
            out += '.';
            out += std::to_string(arc);
        }
        arc = 0;
        arc_started = false;
        if (out.size() > kMaxDottedOidLength)
            return std::nullopt;
    }
    if (arc_started)
        return std::nullopt; // last byte had its continuation bit set
    return out;
}

namespace detail {

struct OidName {
    std::string_view oid;
    std::string_view name;
};

struct CurveInfo {
    std::string_view oid;
    std::string_view name;
    std::string_view bits;
};

inline constexpr std::string_view kOidRsa = "1.2.840.113549.1.1.1";
inline constexpr std::string_view kOidRsaPss = "1.2.840.113549.1.1.10";
inline constexpr std::string_view kOidDsa = "1.2.840.10040.4.1";
inline constexpr std::string_view kOidEc = "1.2.840.10045.2.1";

/// Public-key algorithms whose key length is fixed by the named parameter set
/// (key_bits reports kImpliedBits). RSA, RSASSA-PSS, DSA and EC are handled
/// explicitly in describe() because their length varies per key.
inline constexpr std::array<OidName, 10> kFixedSizeKeyAlgorithms{{
    {"1.3.101.110", "X25519"},
    {"1.3.101.111", "X448"},
    {"1.3.101.112", "Ed25519"},
    {"1.3.101.113", "Ed448"},
    {"2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
    {"2.16.840.1.101.3.4.3.18", "ML-DSA-65"},
    {"2.16.840.1.101.3.4.3.19", "ML-DSA-87"},
    {"2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
    {"2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
    {"2.16.840.1.101.3.4.4.3", "ML-KEM-1024"},
}};

/// Named elliptic curves (the EC public key's namedCurve parameter).
inline constexpr std::array<CurveInfo, 9> kCurves{{
    {"1.2.840.10045.3.1.1", "P-192", "192"},
    {"1.3.132.0.33", "P-224", "224"},
    {"1.2.840.10045.3.1.7", "P-256", "256"},
    {"1.3.132.0.34", "P-384", "384"},
    {"1.3.132.0.35", "P-521", "521"},
    {"1.3.132.0.10", "secp256k1", "256"},
    {"1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1", "256"},
    {"1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1", "384"},
    {"1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1", "512"},
}};

/// Certificate signature algorithms.
inline constexpr std::array<OidName, 30> kSignatureAlgorithms{{
    {"1.2.840.113549.1.1.2", "md2WithRSAEncryption"},
    {"1.2.840.113549.1.1.4", "md5WithRSAEncryption"},
    {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
    {"1.3.14.3.2.29", "sha1WithRSASignature"},
    {"1.2.840.113549.1.1.14", "sha224WithRSAEncryption"},
    {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
    {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
    {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
    {"1.2.840.113549.1.1.10", "RSASSA-PSS"},
    {"2.16.840.1.101.3.4.3.13", "rsa-with-SHA3-224"},
    {"2.16.840.1.101.3.4.3.14", "rsa-with-SHA3-256"},
    {"2.16.840.1.101.3.4.3.15", "rsa-with-SHA3-384"},
    {"2.16.840.1.101.3.4.3.16", "rsa-with-SHA3-512"},
    {"1.2.840.10045.4.1", "ecdsa-with-SHA1"},
    {"1.2.840.10045.4.3.1", "ecdsa-with-SHA224"},
    {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
    {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
    {"1.2.840.10045.4.3.4", "ecdsa-with-SHA512"},
    {"2.16.840.1.101.3.4.3.9", "ecdsa-with-SHA3-224"},
    {"2.16.840.1.101.3.4.3.10", "ecdsa-with-SHA3-256"},
    {"2.16.840.1.101.3.4.3.11", "ecdsa-with-SHA3-384"},
    {"2.16.840.1.101.3.4.3.12", "ecdsa-with-SHA3-512"},
    {"1.2.840.10040.4.3", "dsa-with-SHA1"},
    {"2.16.840.1.101.3.4.3.1", "dsa-with-SHA224"},
    {"2.16.840.1.101.3.4.3.2", "dsa-with-SHA256"},
    {"1.3.101.112", "Ed25519"},
    {"1.3.101.113", "Ed448"},
    {"2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
    {"2.16.840.1.101.3.4.3.18", "ML-DSA-65"},
    {"2.16.840.1.101.3.4.3.19", "ML-DSA-87"},
}};

template <std::size_t N>
std::optional<std::string_view> lookup(const std::array<OidName, N>& table,
                                       std::string_view oid) {
    for (const auto& e : table)
        if (e.oid == oid)
            return e.name;
    return std::nullopt;
}

inline const CurveInfo* lookup_curve(std::string_view oid) {
    for (const auto& c : kCurves)
        if (c.oid == oid)
            return &c;
    return nullptr;
}

inline std::string lookup_signature(std::string_view oid) {
    if (auto name = lookup(kSignatureAlgorithms, oid))
        return std::string(*name);
    return std::string(oid);
}

} // namespace detail

/// Name a certificate's crypto profile from what its OS leg extracted:
///   key_oid       the SubjectPublicKeyInfo algorithm OID (dotted)
///   curve_oid     the EC namedCurve OID (dotted); empty when the key is not
///                 EC, or its parameters are not a named curve
///   library_bits  the OS library's own key length in bits (libcrypto
///                 EVP_PKEY_get_bits / CryptoAPI CertGetPublicKeyLength), or
///                 0 when the library could not decode the key. Consulted
///                 ONLY for RSA, RSASSA-PSS and DSA, whose length is a
///                 property of the individual key; every other key's length
///                 comes from this header's tables, so it cannot disagree
///                 between OSes.
///   sig_oid       the certificate signature algorithm OID (dotted)
/// Any OID argument that fails is_dotted_oid() is treated as absent.
inline CryptoProfile describe(std::string_view key_oid, std::string_view curve_oid,
                              int library_bits, std::string_view sig_oid) {
    CryptoProfile p;
    const std::string library_bits_text =
        library_bits > 0 ? std::to_string(library_bits) : std::string("(unknown)");

    if (is_dotted_oid(key_oid)) {
        if (key_oid == detail::kOidRsa) {
            p.key_algorithm = "RSA";
            p.key_bits = library_bits_text;
        } else if (key_oid == detail::kOidRsaPss) {
            p.key_algorithm = "RSASSA-PSS";
            p.key_bits = library_bits_text;
        } else if (key_oid == detail::kOidDsa) {
            p.key_algorithm = "DSA";
            p.key_bits = library_bits_text;
        } else if (key_oid == detail::kOidEc) {
            // No named curve (explicit parameters, or parameters the leg
            // could not read) leaves the curve -- and so the size -- unknown.
            if (!is_dotted_oid(curve_oid)) {
                p.key_algorithm = "EC";
            } else if (const auto* curve = detail::lookup_curve(curve_oid)) {
                p.key_algorithm = std::string("EC ") + std::string(curve->name);
                p.key_bits = std::string(curve->bits);
            } else {
                p.key_algorithm = std::string("EC ") + std::string(curve_oid);
            }
        } else if (auto name = detail::lookup(detail::kFixedSizeKeyAlgorithms, key_oid)) {
            p.key_algorithm = std::string(*name);
            p.key_bits = std::string(kImpliedBits);
        } else {
            p.key_algorithm = std::string(key_oid);
        }
    }

    if (is_dotted_oid(sig_oid))
        p.signature_algorithm = detail::lookup_signature(sig_oid);

    return p;
}

} // namespace yuzu::certificates_crypto
