#include <yuzu/agent/cert_store.hpp>

#include <spdlog/spdlog.h>

#include <string>
#include <vector>

#ifdef _WIN32
// clang-format off
#include <winsock2.h>  // must precede windows.h
#include <windows.h>
// clang-format on
#include <ncrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

namespace yuzu::agent {

namespace {

// Convert a hex-encoded thumbprint string to raw bytes.
// Accepts "AB12CD..." or "AB:12:CD:..." (with or without colons/spaces).
std::vector<unsigned char> parse_thumbprint(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(20); // SHA-1 = 20 bytes
    for (size_t i = 0; i < hex.size();) {
        char c = hex[i];
        if (c == ':' || c == ' ') {
            ++i;
            continue;
        }
        if (i + 1 >= hex.size())
            break;
        auto hi = hex[i], lo = hex[i + 1];
        auto nibble = [](char ch) -> unsigned char {
            if (ch >= '0' && ch <= '9')
                return static_cast<unsigned char>(ch - '0');
            if (ch >= 'a' && ch <= 'f')
                return static_cast<unsigned char>(ch - 'a' + 10);
            if (ch >= 'A' && ch <= 'F')
                return static_cast<unsigned char>(ch - 'A' + 10);
            return 0;
        };
        bytes.push_back(static_cast<unsigned char>((nibble(hi) << 4) | nibble(lo)));
        i += 2;
    }
    return bytes;
}

// PEM-encode a DER blob with the given label (e.g. "CERTIFICATE", "RSA PRIVATE KEY").
std::string pem_encode(const std::string& label, const unsigned char* data, size_t len) {
    // Base64 encode
    DWORD b64_len = 0;
    CryptBinaryToStringA(data, static_cast<DWORD>(len), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         nullptr, &b64_len);
    std::string b64(b64_len, '\0');
    CryptBinaryToStringA(data, static_cast<DWORD>(len), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         b64.data(), &b64_len);
    b64.resize(b64_len);

    // Wrap at 64 characters per line
    std::string pem = "-----BEGIN " + label + "-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) {
        pem += b64.substr(i, 64) + "\n";
    }
    pem += "-----END " + label + "-----\n";
    return pem;
}

} // anonymous namespace

CertStoreResult read_cert_from_store(const std::string& store_name, const std::string& subject,
                                     const std::string& thumbprint) {
    CertStoreResult result;

    // Open the Local Machine certificate store
    auto store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                               CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
                               store_name.c_str());

    if (!store) {
        // Fall back to Current User store
        store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                              CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                              store_name.c_str());
    }

    if (!store) {
        result.error = "Failed to open certificate store '" + store_name + "' (error " +
                       std::to_string(GetLastError()) + ")";
        return result;
    }

    PCCERT_CONTEXT cert_ctx = nullptr;

    if (!thumbprint.empty()) {
        // Search by SHA-1 thumbprint
        auto hash_bytes = parse_thumbprint(thumbprint);
        CRYPT_HASH_BLOB hash_blob;
        hash_blob.cbData = static_cast<DWORD>(hash_bytes.size());
        hash_blob.pbData = hash_bytes.data();

        cert_ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                              CERT_FIND_HASH, &hash_blob, nullptr);

        if (!cert_ctx) {
            result.error = "No certificate found with thumbprint '" + thumbprint + "'";
            CertCloseStore(store, 0);
            return result;
        }
        spdlog::info("Found certificate by thumbprint: {}", thumbprint);

    } else if (!subject.empty()) {
        // Search by subject CN substring
        cert_ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                              CERT_FIND_SUBJECT_STR_A, subject.c_str(), nullptr);

        if (!cert_ctx) {
            result.error = "No certificate found with subject matching '" + subject + "'";
            CertCloseStore(store, 0);
            return result;
        }

        // Log the matched subject for diagnostics
        char subject_name[256] = {};
        CertGetNameStringA(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject_name,
                           sizeof(subject_name));
        spdlog::info("Found certificate by subject: {}", subject_name);

    } else {
        result.error = "Either --cert-subject or --cert-thumbprint is required with --cert-store";
        CertCloseStore(store, 0);
        return result;
    }

    // ── Extract the certificate chain as PEM ─────────────────────────────────

    // Build the certificate chain to include intermediate CAs
    CERT_CHAIN_PARA chain_para = {};
    chain_para.cbSize = sizeof(chain_para);
    PCCERT_CHAIN_CONTEXT chain_ctx = nullptr;

    BOOL chain_ok = CertGetCertificateChain(nullptr, // default chain engine
                                            cert_ctx,
                                            nullptr, // current time
                                            store,   // additional store to search
                                            &chain_para,
                                            0,       // flags
                                            nullptr, // reserved
                                            &chain_ctx);

    std::string cert_pem;
    if (chain_ok && chain_ctx && chain_ctx->cChain > 0) {
        // Walk the first simple chain — leaf first, then intermediates
        auto* simple_chain = chain_ctx->rgpChain[0];
        for (DWORD i = 0; i < simple_chain->cElement; ++i) {
            auto* elem = simple_chain->rgpElement[i]->pCertContext;
            cert_pem += pem_encode("CERTIFICATE", elem->pbCertEncoded, elem->cbCertEncoded);
        }
    } else {
        // Fall back to just the leaf certificate
        cert_pem = pem_encode("CERTIFICATE", cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded);
    }

    if (chain_ctx)
        CertFreeCertificateChain(chain_ctx);

    result.pem_cert_chain = std::move(cert_pem);

    // ── Extract the private key ──────────────────────────────────────────────

    DWORD key_spec = 0;
    BOOL caller_free = FALSE;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key_handle = 0;

    BOOL key_ok = CryptAcquireCertificatePrivateKey(
        cert_ctx, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, nullptr,
        &key_handle, &key_spec, &caller_free);

    if (!key_ok || key_handle == 0) {
        // Try legacy CSP path
        key_ok = CryptAcquireCertificatePrivateKey(cert_ctx, CRYPT_ACQUIRE_SILENT_FLAG, nullptr,
                                                   &key_handle, &key_spec, &caller_free);
    }

    if (!key_ok || key_handle == 0) {
        result.error = "Certificate found but private key is not accessible "
                       "(error " +
                       std::to_string(GetLastError()) +
                       "). "
                       "Ensure the key is marked as exportable and the agent runs "
                       "with sufficient privileges (Local System or admin).";
        CertFreeCertificateContext(cert_ctx);
        CertCloseStore(store, 0);
        return result;
    }

    // Export the private key via NCrypt (CNG) or legacy CAPI
    if (key_spec == CERT_NCRYPT_KEY_SPEC) {
        // CNG key — export as PKCS#8 blob, then PEM-encode
        DWORD blob_len = 0;
        SECURITY_STATUS ss =
            NCryptExportKey(key_handle, 0,
                            BCRYPT_RSAFULLPRIVATE_BLOB, // or NCRYPT_PKCS8_PRIVATE_KEY_BLOB
                            nullptr, nullptr, 0, &blob_len, 0);

        // Try PKCS#8 first (more portable)
        ss = NCryptExportKey(key_handle, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, nullptr, 0,
                             &blob_len, 0);

        if (ss == ERROR_SUCCESS && blob_len > 0) {
            std::vector<unsigned char> blob(blob_len);
            ss = NCryptExportKey(key_handle, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, blob.data(),
                                 blob_len, &blob_len, 0);

            if (ss == ERROR_SUCCESS) {
                result.pem_private_key = pem_encode("PRIVATE KEY", blob.data(), blob_len);
            } else {
                result.error = "NCryptExportKey (PKCS8) failed: " + std::to_string(ss) +
                               ". The private key may not be marked as exportable.";
            }
            // Zero private key material from intermediate buffer
            SecureZeroMemory(blob.data(), blob.size());
        } else {
            result.error = "NCryptExportKey failed: " + std::to_string(ss) +
                           ". The private key may not be marked as exportable.";
        }

        if (caller_free)
            NCryptFreeObject(key_handle);
    } else {
        // Legacy CAPI key — export as PRIVATEKEYBLOB, convert to PKCS#8
        HCRYPTKEY hkey = 0;
        if (CryptGetUserKey(key_handle, key_spec, &hkey)) {
            DWORD blob_len = 0;
            CryptExportKey(hkey, 0, PRIVATEKEYBLOB, 0, nullptr, &blob_len);

            if (blob_len > 0) {
                std::vector<unsigned char> blob(blob_len);
                if (CryptExportKey(hkey, 0, PRIVATEKEYBLOB, 0, blob.data(), &blob_len)) {
                    // Convert CAPI PRIVATEKEYBLOB to PKCS#8 DER
                    DWORD der_len = 0;
                    if (CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                            PKCS_RSA_PRIVATE_KEY, blob.data(), 0, nullptr, nullptr,
                                            &der_len) &&
                        der_len > 0) {
                        std::vector<unsigned char> der(der_len);
                        if (CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                PKCS_RSA_PRIVATE_KEY, blob.data(), 0, nullptr,
                                                der.data(), &der_len)) {
                            result.pem_private_key =
                                pem_encode("RSA PRIVATE KEY", der.data(), der_len);
                        }
                    }

                    if (result.pem_private_key.empty()) {
                        // Fall back: encode the raw CAPI blob as RSA PRIVATE KEY
                        // (may not be standard PEM, but gRPC can sometimes handle it)
                        result.error = "Failed to convert CAPI private key to PEM format.";
                    }
                } else {
                    result.error = "CryptExportKey failed. The key may not be exportable.";
                }
                // Zero private key material from intermediate buffer
                SecureZeroMemory(blob.data(), blob.size());
            }
            CryptDestroyKey(hkey);
        } else {
            result.error = "CryptGetUserKey failed (error " + std::to_string(GetLastError()) + ")";
        }

        if (caller_free)
            CryptReleaseContext(key_handle, 0);
    }

    // Cleanup
    CertFreeCertificateContext(cert_ctx);
    CertCloseStore(store, 0);

    return result;
}

} // namespace yuzu::agent

#elif defined(__APPLE__) // macOS — keychain identity is intentionally unsupported

namespace yuzu::agent {

// The macOS agent runs as a root LaunchDaemon (docs/agent-privilege-model.md)
// with no attached user login session, and therefore no user login keychain
// to read an operator-provisioned identity from. A prior revision of this
// file implemented --cert-store on macOS via SecItemCopyMatching /
// SecItemExport against the CURRENT USER's login keychain, resolved through
// SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, ...) — which is
// backwards for this deployment: under launchd's root-daemon context that
// call resolves root's own (nonexistent) login keychain, not an operator's,
// so the lookup could only ever fail closed at startup. It also wiped
// exported key material by writing through CFDataGetBytePtr's read-only
// pointer via const_cast, which is undefined behavior on an immutable
// CFDataRef and could crash while loading mTLS credentials.
//
// Both problems trace back to the same root cause — treating the daemon as
// if it had a user session — so the fix is to stop pretending: the agent's
// own startup identity must not depend on a login session a root daemon
// never has. Report this path as honestly unsupported and point the
// operator at the identity sources that DO work headless: --client-cert /
// --client-key PEM files, or cert_auto_discovery (cert_discovery.cpp).
CertStoreResult read_cert_from_store(const std::string& /*store_name*/,
                                     const std::string& /*subject*/,
                                     const std::string& /*thumbprint*/) {
    return CertStoreResult{
        .error = "OS certificate store (keychain) identity is not supported on the macOS "
                 "agent — it runs as a root LaunchDaemon with no user login keychain; use "
                 "--client-cert/--client-key PEM files instead."};
}

} // namespace yuzu::agent

#else // Linux (and any other non-Windows, non-Apple target) — PEM files only

namespace yuzu::agent {

CertStoreResult read_cert_from_store(const std::string& /*store_name*/,
                                     const std::string& /*subject*/,
                                     const std::string& /*thumbprint*/) {
    return CertStoreResult{.error =
                               "OS certificate store integration is only available on Windows. "
                               "Use --client-cert and --client-key with PEM files instead."};
}

} // namespace yuzu::agent

#endif // _WIN32 / __APPLE__
