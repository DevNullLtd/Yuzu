/**
 * certificates_plugin.cpp — Certificate inventory plugin for Yuzu
 *
 * Enumerates and manages certificates in system stores.
 *
 * Actions:
 *   "list"    — List certificates in system stores (pipe-delimited).
 *   "details" — Get details for a specific certificate by thumbprint.
 *   "delete"  — Delete a certificate by thumbprint from a given store.
 *
 * Output is pipe-delimited via write_output().
 *
 * Platform implementations:
 *   Windows — CryptoAPI (CertOpenStore, CertEnumCertificatesInStore, etc.)
 *   Linux   — PEM files in /etc/ssl/certs/ parsed in-process via libcrypto
 *             (certificates_x509.hpp) -- no subprocess.
 *   macOS   — System.keychain / SystemRootCertificates.keychain read via a
 *             bounded, in-process SecItem query in agent-core
 *             (yuzu/agent/keychain_read.hpp; certificates_x509.hpp's DER
 *             parse backs the result); the login keychain still reads
 *             via a `security find-certificate` subprocess routed through
 *             the per-user launchd/Aqua session, as a pre-split argv
 *             through the bounded runner (rung 2, #3406 -- see
 *             build_login_keychain_read_argv()).
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (BR-07)

#include "certificates_macos_parsers.hpp" // pure parse/validate/classify/verdict helpers (shared with the unit test)

#include <spdlog/spdlog.h> // degraded-subprocess WARN (SRE S1 observability)

#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <format>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#else
#include <filesystem>
#include <fstream>
#endif

#ifdef __APPLE__
// geteuid() -- privilege detection for the store-read sudo hop (mirrors
// quarantine_plugin.cpp's sudo_prefix()). macos_console_user.hpp declares
// `namespace yuzu::macos`, and subprocess_runner.hpp declares
// `namespace yuzu::agent` -- ALL THREE headers below MUST be included
// here, at global scope, before the anonymous namespace below opens:
// including them inside `namespace { ... }` would nest `yuzu::macos`/
// `yuzu::agent` under `(anonymous namespace)::yuzu`, shadowing the global
// `::yuzu` namespace (from <yuzu/plugin.hpp> above) for every unqualified
// `yuzu::` lookup in this file -- e.g. `yuzu::TempFile` below would then
// fail to resolve, since the nested `(anonymous namespace)::yuzu` has no
// TempFile member.
#include <sys/stat.h>
#include <unistd.h>
#include <yuzu/agent/keychain_read.hpp>     // yuzu::agent::read_keychain_bounded -- agent-core bounded SecItem seam (#3246, #2318a)
#include <yuzu/agent/passwd_lookup.hpp>    // bounded passwd resolution -- replaces the shell's `~username` expansion (#3406)
#include <macos_console_user.hpp>          // shared console-user + store/keychain mapping (#2277)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (BR-03)
#endif

// NOTE: the Linux leg deliberately includes NO subprocess header. WP-B removed
// the `openssl x509` shell-out that used to need one, so the Linux
// list/details/delete paths below spawn nothing at all -- the previous
// `#ifdef __linux__ #include <yuzu/agent/subprocess_runner.hpp>` block is gone
// with the mechanism it served. Every remaining spawn site in this file is
// inside the __APPLE__ region.

#ifdef __linux__
// certificates_linux_store.hpp declares `namespace yuzu::certificates_linux`
// and pulls in confined_fs.hpp (`namespace yuzu::agent::confined_fs`) and
// scoped_fd.hpp (`namespace yuzu::agent`) itself -- included here, at global
// scope, before the anonymous namespace below opens, for the exact reason
// the __APPLE__ block above this one documents in full: including it inside
// `namespace { ... }` would nest `yuzu::agent`/`yuzu::certificates_linux`
// under `(anonymous namespace)::yuzu`, shadowing the global `::yuzu`
// namespace (from <yuzu/plugin.hpp> above) for every unqualified `yuzu::`
// lookup in this file, and would give `capture_identity`'s call sites below
// a declaration in a different, TU-local namespace than the one agent-core
// actually exports the symbol from (confirmed via a real compile: GCC 13
// and Clang both reject or mis-resolve the resulting ambiguous/orphaned
// `yuzu::agent::confined_fs::capture_identity` reference).
#include "certificates_linux_store.hpp"
using namespace yuzu::certificates_linux;
#endif

#if defined(__linux__) || defined(__APPLE__)
// yuzu::certificates_x509 -- in-process libcrypto PEM/DER parsing (WP-B).
// Backs the Linux PEM-file read entirely and the macOS System.keychain/
// SystemRootCertificates.keychain SecItem read's DER decode; the macOS
// login-keychain path stays on the PEM-block parse in
// certificates_macos_parsers.hpp / parse_pem_block_macos below, untouched.
#include "certificates_x509.hpp"
#endif

// The pure parse/validate/classify/verdict helpers this file shares with
// tests/unit/test_certificates_macos.cpp live in yuzu::certificates_macos
// (certificates_macos_parsers.hpp). Pulled into scope here -- including for
// the CertificatesPlugin::execute() methods further down, which are outside
// the anonymous namespace below -- so the many call sites read exactly as they
// did when these functions were file-local, with no per-call qualification.
using namespace yuzu::certificates_macos;

namespace {

// ── Input validation ────────────────────────────────────────────────────────
// is_valid_thumbprint / expires_within_days moved to certificates_macos_parsers.hpp.
//
// is_safe_path() (a shell-metacharacter allowlist guarding the filename this
// file used to interpolate into an `openssl x509 -in "<path>"` command
// line) and run_command() (the popen-or-bounded-subprocess wrapper that ran
// that command) are DELETED as of WP-B: certificates_x509.hpp's in-process
// libcrypto parse and native std::ifstream file I/O (see
// read_linux_cert_record() below) never build a shell command line from a
// filesystem path, so there is nothing left for either to guard.

// ── Certificate record ───────────────────────────────────────────────────────

struct CertRecord {
    std::string subject;
    std::string issuer;
    std::string thumbprint;
    std::string not_before;
    std::string not_after;
    std::string serial;
    std::string store;
    std::string key_usage;

    std::string to_row() const {
        // subject/issuer/serial/key_usage come from parsed certificate data
        // (subject/issuer are attacker-influenced DN text on any store
        // that can hold a self-signed or otherwise untrusted leaf cert;
        // serial/key_usage are wrapped too for defense-in-depth even
        // though they are openssl-derived hex/enum text) -- escaped via
        // safe_output_field so a hostile '|' or embedded CR/LF can never
        // inject an extra column or row into this pipe-delimited output
        // (BR-07). thumbprint/not_before/not_after/store are excluded:
        // thumbprint is hex-validated (is_valid_thumbprint) or one of this
        // file's own literal sentinels ("(unknown)"/"(skipped)" -- both
        // parenthesised ASCII, no '|' or CR/LF), the dates are produced
        // entirely by this
        // file's own date formatting, and store is always one of this
        // plugin's own fixed literal labels -- none of the four can carry
        // attacker-controlled bytes.
        return std::format("{}|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(subject),
                           yuzu::util::safe_output_field(issuer), thumbprint, not_before,
                           not_after, yuzu::util::safe_output_field(serial), store,
                           yuzu::util::safe_output_field(key_usage));
    }
};

/// Report a partial certificate read through the ABI4 typed result seam
/// (`yuzu_ctx_set_result_status`, sdk/include/yuzu/plugin.hpp) in addition to
/// the operator-visible `not_available|<reason>` row the caller writes.
///
/// The sentinel row alone is only OPERATOR-visible: a consumer reading the
/// command's RESULT METADATA rather than scraping rows would otherwise see an
/// inventory that is missing a whole keychain (or a whole certificate file)
/// presented with the default UNDECLARED status, from which the agent derives
/// a coarse success. Every degraded read here is therefore CONSTRAINED +
/// PARTIAL, with `provenance` naming the half that failed so the two halves
/// of a hybrid macOS read stay distinguishable ("login-keychain" is the
/// spec-named value for the login-keychain subprocess half).
///
/// Idempotent by construction: the seam records the last call for the
/// currently-executing command, and every call here reports the same
/// CONSTRAINED/PARTIAL pair, so a read that degrades in two places reports
/// degraded once with the last-named provenance rather than escalating.
///
/// Also logs at WARN: the ABI4 seam alone is invisible to log/alert-based
/// monitoring (governance Gate 6 sre finding) -- the sibling subprocess
/// degradation sites in this file (run_bounded_checked/parse_pem_block_macos)
/// already spdlog::warn on their own failures, and the SecItem/libcrypto
/// in-process read paths this PR added had no equivalent, silently invisible
/// to anything watching the agent log rather than result-status metadata.
/// `reason` is the operator-facing detail, when there is one distinct from the
/// provenance tag. The tag alone is not diagnosable: every console-user
/// degradation shares the `login-keychain` provenance, so a timed-out directory
/// lookup, an unresolvable account and a failed `stat` all logged the SAME
/// line. That is the one case where the agent log has to distinguish them --
/// the result row reaches the operator, but an on-call engineer reading only
/// the log needs to know a wedged Directory Service is the cause.
///
/// Defined outside every platform guard: the Windows CryptoAPI store-open
/// path (enumerate_store) needs it too, so it can no longer live only under
/// `#if defined(__linux__) || defined(__APPLE__)`.
void mark_result_partial(yuzu::CommandContext& ctx, std::string_view provenance,
                         std::string_view reason = {}) {
    if (reason.empty())
        spdlog::warn("certificates: degraded read ({})", provenance);
    else
        spdlog::warn("certificates: degraded read ({}): {}", provenance, reason);
    ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          provenance);
}

#if defined(__linux__) || defined(__APPLE__)
// Adopt a certificates_x509::CertFields (the pure libcrypto parse result)
// into this file's own CertRecord shape, setting `store` from the caller --
// certificates_x509.hpp never knows which keychain/directory a certificate
// came from, only the plugin's platform-specific read sites do. Shared by
// the Linux PEM-file path (read_linux_cert_record) and the macOS SecItem
// System/root path (list/details_cert_macos) so both adopt CertFields into
// CertRecord identically.
CertRecord to_cert_record(const yuzu::certificates_x509::CertFields& fields, std::string store) {
    CertRecord rec;
    rec.store = std::move(store);
    rec.subject = fields.subject;
    rec.issuer = fields.issuer;
    rec.not_before = fields.not_before;
    rec.not_after = fields.not_after;
    rec.serial = fields.serial;
    rec.thumbprint = fields.thumbprint;
    rec.key_usage = fields.key_usage;
    return rec;
}
#endif

// ── Expiry filtering helper ──────────────────────────────────────────────────
// expires_within_days moved to certificates_macos_parsers.hpp (shared with the
// unit test and used by the Windows/Linux paths below too).

// ── Windows implementation ───────────────────────────────────────────────────

#ifdef _WIN32

std::string filetime_to_string(const FILETIME& ft) {
    SYSTEMTIME st{};
    FileTimeToSystemTime(&ft, &st);
    return std::format("{:04d}-{:02d}-{:02d}", st.wYear, st.wMonth, st.wDay);
}

std::string bytes_to_hex(const BYTE* data, DWORD len) {
    std::string hex;
    hex.reserve(len * 2);
    for (DWORD i = 0; i < len; ++i) {
        hex += std::format("{:02X}", data[i]);
    }
    return hex;
}

std::string get_cert_name(PCCERT_CONTEXT cert, DWORD type) {
    char buf[512]{};
    DWORD len =
        CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, type, nullptr, buf, sizeof(buf));
    if (len <= 1)
        return "(unknown)";
    return std::string(buf);
}

std::string get_cert_thumbprint(PCCERT_CONTEXT cert) {
    BYTE hash[20]{};
    DWORD hash_len = sizeof(hash);
    if (CryptHashCertificate(0, CALG_SHA1, 0, cert->pbCertEncoded, cert->cbCertEncoded, hash,
                             &hash_len)) {
        return bytes_to_hex(hash, hash_len);
    }
    return "(unknown)";
}

std::string get_cert_serial(PCCERT_CONTEXT cert) {
    const auto& sn = cert->pCertInfo->SerialNumber;
    // Serial number is stored in little-endian order in Windows
    std::string serial;
    serial.reserve(sn.cbData * 2);
    for (DWORD i = sn.cbData; i > 0; --i) {
        serial += std::format("{:02X}", sn.pbData[i - 1]);
    }
    return serial;
}

std::string get_key_usage(PCCERT_CONTEXT cert) {
    BYTE usage_bits[2]{};
    DWORD usage_size = sizeof(usage_bits);
    if (!CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert->pCertInfo,
                                 usage_bits, usage_size)) {
        return "(none)";
    }

    std::vector<std::string> usages;
    if (usage_bits[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE)
        usages.emplace_back("Digital Signature");
    if (usage_bits[0] & CERT_KEY_ENCIPHERMENT_KEY_USAGE)
        usages.emplace_back("Key Encipherment");
    if (usage_bits[0] & CERT_DATA_ENCIPHERMENT_KEY_USAGE)
        usages.emplace_back("Data Encipherment");
    if (usage_bits[0] & CERT_KEY_AGREEMENT_KEY_USAGE)
        usages.emplace_back("Key Agreement");
    if (usage_bits[0] & CERT_KEY_CERT_SIGN_KEY_USAGE)
        usages.emplace_back("Certificate Signing");
    if (usage_bits[0] & CERT_CRL_SIGN_KEY_USAGE)
        usages.emplace_back("CRL Signing");
    if (usage_bits[0] & CERT_NON_REPUDIATION_KEY_USAGE)
        usages.emplace_back("Non-Repudiation");

    if (usages.empty())
        return "(none)";

    std::string result;
    for (size_t i = 0; i < usages.size(); ++i) {
        if (i > 0)
            result += ", ";
        result += usages[i];
    }
    return result;
}

enum class StoreLocation { kLocalMachine, kCurrentUser };
enum class StoreReadFailure { kNone, kOpen, kEnumeration };

struct StoreEnumeration {
    StoreReadFailure failure = StoreReadFailure::kNone;
    StoreLocation location = StoreLocation::kLocalMachine;
    std::vector<CertRecord> records;
};

StoreEnumeration enumerate_store(const char* store_name) {
    StoreEnumeration result;

    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                      CERT_SYSTEM_STORE_LOCAL_MACHINE |
                                          CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                                      store_name);

    if (!hStore &&
        yuzu::certificates_macos::win_store_fallback_allowed(
            yuzu::certificates_macos::WinStoreAction::kRead)) {
        // Disclosed fallback (#4377): a READ may consult CurrentUser when
        // LocalMachine could not be opened -- callers are told which
        // location actually served the data via `result.location`, and mark
        // the result CONSTRAINED/PARTIAL with cryptoapi:store-fallback
        // provenance rather than silently presenting CurrentUser rows as if
        // they came from LocalMachine.
        hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                               CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
                                   CERT_STORE_READONLY_FLAG,
                               store_name);
        if (hStore)
            result.location = StoreLocation::kCurrentUser;
    }
    if (!hStore) {
        // Both opens failed (or fallback is not allowed for this action) --
        // an honest typed failure, never a silent empty vector
        // indistinguishable from "store opened, found nothing"
        // (consistency-auditor Gate-4 BLOCKING finding, same shape as the
        // macOS/Linux honesty fixes elsewhere in this file).
        spdlog::warn("certificates: CryptoAPI store '{}' could not be opened (GetLastError={})",
                    store_name, GetLastError());
        result.failure = StoreReadFailure::kOpen;
        return result;
    }

    PCCERT_CONTEXT cert = nullptr;
    while ((cert = CertEnumCertificatesInStore(hStore, cert)) != nullptr) {
        CertRecord rec;
        rec.subject = get_cert_name(cert, 0);
        rec.issuer = get_cert_name(cert, CERT_NAME_ISSUER_FLAG);
        rec.thumbprint = get_cert_thumbprint(cert);
        rec.not_before = filetime_to_string(cert->pCertInfo->NotBefore);
        rec.not_after = filetime_to_string(cert->pCertInfo->NotAfter);
        rec.serial = get_cert_serial(cert);
        rec.store = store_name;
        rec.key_usage = get_key_usage(cert);
        result.records.push_back(std::move(rec));
    }
    // CertEnumCertificatesInStore returns NULL both at genuine end-of-store
    // (CRYPT_E_NOT_FOUND, per Microsoft Learn) and on a real mid-enumeration
    // error -- treating every NULL as "fully scanned" would let a transient
    // CryptoAPI failure look like a clean, complete, possibly-empty result
    // (adversarial-review CDX-003). Fold anything else into a typed
    // kEnumeration failure, discarding the partial records the same way the
    // open-failure path above never invents any: this function's callers
    // already treat a non-kNone failure as "cannot trust this store's
    // results, mark PARTIAL, never report a definitive not_found".
    DWORD enum_err = GetLastError();
    if (enum_err != CRYPT_E_NOT_FOUND) {
        spdlog::warn("certificates: CryptoAPI enumeration of store '{}' ended abnormally "
                    "(GetLastError={}), scan incomplete",
                    store_name, enum_err);
        CertCloseStore(hStore, 0);
        result.failure = StoreReadFailure::kEnumeration;
        result.records.clear();
        return result;
    }

    CertCloseStore(hStore, 0);
    return result;
}

void list_certs_win(yuzu::CommandContext& ctx, std::string_view store_filter, int expiring_days) {
    static const char* kStores[] = {"MY", "ROOT", "CA", "Trust"};

    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    for (const auto* store_name : kStores) {
        if (store_filter != "all" && store_filter != store_name)
            continue;

        auto enumeration = enumerate_store(store_name);
        if (enumeration.failure == StoreReadFailure::kOpen) {
            // Every open attempt for this store failed -- say so
            // (operator-visible row + ABI4 typed status) and keep scanning
            // the remaining stores rather than silently reporting them as
            // empty (consistency-auditor Gate-4 BLOCKING finding).
            auto reason = std::format("not_available|{} store could not be opened", store_name);
            ctx.write_output(reason);
            mark_result_partial(ctx, "cryptoapi:store-open", reason);
            continue;
        }
        if (enumeration.failure == StoreReadFailure::kEnumeration) {
            auto reason =
                std::format("not_available|{} store enumeration incomplete", store_name);
            ctx.write_output(reason);
            mark_result_partial(ctx, "cryptoapi:store-enum", reason);
            continue;
        }
        if (enumeration.location == StoreLocation::kCurrentUser) {
            // Disclosed fallback (#4377): rows below actually came from
            // CurrentUser, not the LocalMachine hive this store name
            // normally means -- say so before the rows themselves, and mark
            // the result CONSTRAINED/PARTIAL rather than presenting them as
            // an ordinary LocalMachine read.
            auto reason = std::format(
                "not_available|{} store (LocalMachine) could not be opened; rows read from "
                "CurrentUser",
                store_name);
            ctx.write_output(reason);
            mark_result_partial(ctx, "cryptoapi:store-fallback", reason);
        }
        for (const auto& rec : enumeration.records) {
            if (expires_within_days(rec.not_after, expiring_days)) {
                ctx.write_output(rec.to_row());
            }
        }
    }
}

void details_cert_win(yuzu::CommandContext& ctx, std::string_view thumbprint) {
    static const char* kStores[] = {"MY", "ROOT", "CA", "Trust"};

    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    auto needle = canonical_thumbprint(thumbprint);
    // Tracks whether every selected store was actually opened AND fully
    // enumerated AND (if fallback-served) that fallback was disclosed. Any
    // one of those failing leaves this loop free to keep scanning the rest,
    // but the eventual "not found" verdict must not be reported as
    // definitive if any store was skipped, incompletely scanned, or served
    // from a hive its name doesn't normally mean -- mirrors
    // details_cert_linux's scan_complete flag.
    bool scan_complete = true;
    std::string unopened;
    std::string incomplete;
    std::string fallback;
    auto append_store = [](std::string& list, const char* store_name) {
        if (!list.empty())
            list += ", ";
        list += store_name;
    };
    for (const auto* store_name : kStores) {
        auto enumeration = enumerate_store(store_name);
        if (enumeration.failure == StoreReadFailure::kOpen) {
            scan_complete = false;
            append_store(unopened, store_name);
            mark_result_partial(ctx, "cryptoapi:store-open");
            continue;
        }
        if (enumeration.failure == StoreReadFailure::kEnumeration) {
            scan_complete = false;
            append_store(incomplete, store_name);
            mark_result_partial(ctx, "cryptoapi:store-enum");
            continue;
        }
        // Snapshot every per-store degradation accumulated from EARLIER
        // iterations, before this store's own (possible) append below -- if
        // a match turns up in this store, any name in here never got its
        // row-level disclosure because the loop moved on without a return
        // (the "scan incomplete" summary below is skipped entirely on an
        // early match-and-return, silently dropping it; CDX-P1-001 fixed
        // this for the fallback case only -- governance Gate 2 found the
        // identical gap for unopened/incomplete and it's fixed here too).
        std::string prior_unopened = unopened;
        std::string prior_incomplete = incomplete;
        std::string prior_fallback = fallback;
        bool is_fallback = enumeration.location == StoreLocation::kCurrentUser;
        if (is_fallback) {
            append_store(fallback, store_name);
            mark_result_partial(ctx, "cryptoapi:store-fallback");
        }
        for (const auto& rec : enumeration.records) {
            if (rec.thumbprint == needle) {
                if (!prior_unopened.empty()) {
                    ctx.write_output(
                        std::format("not_available|{} store(s) could not be opened",
                                    prior_unopened));
                }
                if (!prior_incomplete.empty()) {
                    ctx.write_output(
                        std::format("not_available|{} store(s) enumeration incomplete",
                                    prior_incomplete));
                }
                if (!prior_fallback.empty()) {
                    // An earlier store in this scan fell back to CurrentUser
                    // and didn't match -- its own row-level disclosure was
                    // never written because the loop moved on without a
                    // return. Disclose it now, alongside (not instead of)
                    // the current store's own disclosure below, or the scan
                    // silently omits a fallback #4377 requires surfaced.
                    ctx.write_output(std::format(
                        "not_available|{} store(s) (LocalMachine) could not be opened; rows read "
                        "from CurrentUser",
                        prior_fallback));
                }
                if (is_fallback) {
                    // Disclosed fallback (#4377), same wording and ordering
                    // as list_certs_win's matching branch: the row about to
                    // be written came from CurrentUser, not the LocalMachine
                    // hive this store name normally means -- say so
                    // immediately before it. README.md and this issue's own
                    // changelog fragment promise this row for both list and
                    // details; returning the match without it (as this
                    // branch previously did) left a caller with no
                    // output-level signal, only the
                    // CONSTRAINED/PARTIAL/cryptoapi:store-fallback status
                    // metadata. Scoped to the matched store only -- the
                    // no-match path below already has its own combined
                    // "N store(s) read from CurrentUser" summary line, and
                    // duplicating a per-store row there would be redundant.
                    ctx.write_output(std::format(
                        "not_available|{} store (LocalMachine) could not be opened; rows read "
                        "from CurrentUser",
                        store_name));
                }
                ctx.write_output(rec.to_row());
                return;
            }
        }
    }
    if (scan_complete && fallback.empty()) {
        ctx.write_output("status|not_found");
    } else {
        // At least one store was unopened, incompletely enumerated, or
        // fallback-served, so "not found" was never established -- mirrors
        // details_cert_linux's "scan incomplete" convention.
        std::vector<std::string> parts;
        if (!unopened.empty())
            parts.push_back(std::format("{} store(s) could not be opened", unopened));
        if (!incomplete.empty())
            parts.push_back(std::format("{} store(s) enumeration incomplete", incomplete));
        if (!fallback.empty())
            parts.push_back(std::format(
                "{} store(s) read from CurrentUser (LocalMachine could not be opened)",
                fallback));
        std::string joined;
        for (std::size_t i = 0; i < parts.size(); ++i) {
            if (i > 0)
                joined += "; ";
            joined += parts[i];
        }
        ctx.write_output(std::format("not_available|{}; scan incomplete", joined));
    }
}

bool delete_cert_win(yuzu::CommandContext& ctx, std::string_view thumbprint,
                     std::string_view store_name) {
    // store_name is caller-supplied free text (execute() passes
    // params.get("store", "MY") straight through, unvalidated) -- escape it
    // (K-7/BR-07) so a hostile value containing '|' or embedded CR/LF can
    // never inject an extra pipe-delimited column or newline-delimited row
    // into this output, same rule the cert-derived fields already follow in
    // CertRecord::to_row().
    auto safe_store = yuzu::util::safe_output_field(store_name);

    // CERT_STORE_OPEN_EXISTING_FLAG: without it, opening the store silently
    // CREATES a missing store and this function then reports the
    // certificate "not_found" in a store that was never actually opened --
    // an unopenable store must be reported honestly, not masked as a
    // definitive negative (consistency-auditor Gate-4 BLOCKING finding).
    //
    // LOCAL_MACHINE only, no CURRENT_USER retry: unlike the read path
    // (enumerate_store), a destructive delete must never target a store the
    // caller did not name (#4377). If the caller-named store can't be
    // opened under LocalMachine, this fails closed and reports the failure
    // rather than silently falling back to a different hive and deleting
    // from a store the caller never asked about.
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG,
        std::string{store_name}.c_str());

    if (!hStore) {
        auto reason =
            std::format("error|{} store could not be opened; nothing removed", safe_store);
        ctx.write_output(reason);
        mark_result_partial(ctx, "cryptoapi:store-open", reason);
        return false;
    }

    auto needle = canonical_thumbprint(thumbprint);
    PCCERT_CONTEXT cert = nullptr;
    bool found = false;
    bool ok = true;
    while ((cert = CertEnumCertificatesInStore(hStore, cert)) != nullptr) {
        auto fp = get_cert_thumbprint(cert);
        if (fp == needle) {
            // Duplicate the context because CertDeleteCertificateFromStore
            // frees the context and invalidates the enumeration
            PCCERT_CONTEXT dup = CertDuplicateCertificateContext(cert);
            if (CertDeleteCertificateFromStore(dup)) {
                ctx.write_output("status|deleted");
            } else {
                ctx.write_output("status|delete_failed");
                ok = false;
            }
            found = true;
            break;
        }
    }

    if (!found) {
        // CertEnumCertificatesInStore returns NULL both at genuine
        // end-of-store (CRYPT_E_NOT_FOUND) and on a real mid-enumeration
        // error (adversarial-review CDX-003, same fix as enumerate_store
        // above) -- a "not found" verdict on a destructive delete must not
        // be reported unless the scan genuinely completed.
        DWORD enum_err = GetLastError();
        if (enum_err != CRYPT_E_NOT_FOUND) {
            auto reason = std::format(
                "error|{} store enumeration ended abnormally; nothing removed", safe_store);
            ctx.write_output(reason);
            mark_result_partial(ctx, "cryptoapi:store-enum", reason);
            CertCloseStore(hStore, 0);
            return false;
        }
        // A definitive negative: the store opened and was fully scanned,
        // so "not found" is a successful idempotent no-op, matching
        // delete_cert_macos's pre-delete presence check.
        ctx.write_output("status|not_found");
    }

    CertCloseStore(hStore, 0);
    return ok;
}

#endif // _WIN32

// ── Linux implementation ─────────────────────────────────────────────────────

#ifdef __linux__

// Every Linux-only include this file needs (dirent.h/fcntl.h/sys/stat.h/
// unistd.h/climits, confined_fs.hpp, scoped_fd.hpp) is at global scope
// above, before the anonymous namespace opens -- see the comment there for
// why confined_fs.hpp/scoped_fd.hpp specifically cannot live inside it.

// parity: `openssl x509 -in <file>` -- the subprocess call this file used to
// shell out to for every field, replaced below by
// yuzu::certificates_x509::parse_pem_certs -- reads ONLY the first PEM block
// in a file. parse_pem_certs can return every certificate a multi-cert
// bundle contains, so BOTH callers that need "the certificate this file
// represents" (read_linux_cert_record below and delete_cert_linux further
// down) go through this ONE helper (read_cert_entry) and consume only
// certs.front() -- never anything past index 0. Widening either caller to
// consider a 2nd-or-later certificate would make MANY MORE thumbprints
// match a bundle file, and since `delete` removes the whole ENTRY
// (`::unlinkat`, the only mechanism available for a PEM-directory store),
// every extra match is another way to reach a bulk trust-anchor removal.
// Note carefully what this guard does and does NOT buy: matching only
// certs.front() is a strict REDUCTION in the number of requests that can
// trigger a bundle-wide delete, and it is byte-parity with the replaced
// subprocess -- but it does not make the delete granular. A request naming
// a bundle's FIRST certificate still removes the entire bundle, exactly as
// the pre-migration code did. That pre-existing coarseness is out of WP-B's
// scope (a granular delete means rewriting the file, a different and
// mutating design); do not read this comment as a claim that bundle files
// are safe from bulk removal.

// CertDir/open_cert_dir/ScopedDir/for_each_cert_entry/CertEntryRead/
// read_cert_entry/StoreSyscalls/DeleteScan/delete_matching_cert now live in
// certificates_linux_store.hpp (yuzu::certificates_linux), pulled into scope
// above via `using namespace yuzu::certificates_linux;` -- moved there so
// tests/unit/test_certificates_linux_store.cpp can drive a real delete
// against a TempDir on macOS and Linux alike.

CertRecord read_linux_cert_record(yuzu::CommandContext& ctx, int dirfd, const std::string& name,
                                  const std::string& store_name) {
    auto read = read_cert_entry(dirfd, name);
    if (read.state == CertEntryOpen::kVanished) {
        // Entry vanished mid-scan, or turned out not to be a regular file/
        // target -- callers skip this record silently, exactly like a
        // concurrently-removed file.
        CertRecord rec;
        rec.thumbprint = "(vanished)";
        return rec;
    }
    if (read.state == CertEntryOpen::kUnreadable || !read.cert) {
        // The deleted is_safe_path() rejected a path containing shell
        // metacharacters before this file ever shelled out to
        // `openssl x509 -in <path>` -- native openat/read I/O never
        // interpolates the name into a shell command, so that specific risk
        // is gone, and with it the only condition "(unsafe path)" ever
        // described. What reaches this branch now is a DIFFERENT condition:
        // an entry this code genuinely cannot turn into a certificate record
        // (permission denied, empty, garbage, or a truncated PEM block).
        // Reporting that as "(unsafe path)" would name a cause that cannot
        // occur, so the sentinel says what actually happened.
        //
        // This is a deliberate, narrow divergence from the pre-migration
        // output, and NOT the one the deleted code's own comment claimed:
        // pre-migration an unreadable/unparseable file did NOT take the
        // unsafe-path branch at all -- every `openssl x509` call simply
        // failed, leaving subject/issuer/thumbprint at "(unknown)" and
        // key_usage at "(none)". So "(unsafe path)" was never this case's
        // output either way; "(unreadable)" is strictly more honest than
        // both the old "(unknown)" (which is also what a per-field parse
        // failure on a VALID certificate produces, and so cannot be
        // distinguished from it) and "(unsafe path)".
        //
        // The row is still emitted, not dropped: expires_within_days()
        // returns true for a not_after shorter than 10 characters, so this
        // record survives the expiry filter in list_certs_linux and the
        // unreadable file stays operator-visible. mark_result_partial makes
        // it machine-visible too -- an inventory missing a certificate file
        // is a partial inventory, not a clean one.
        mark_result_partial(ctx, "libcrypto:unreadable-file");
        CertRecord rec;
        rec.store = store_name;
        rec.subject = "(unreadable)";
        rec.thumbprint = "(skipped)";
        return rec;
    }
    return to_cert_record(*read.cert, store_name);
}

void list_certs_linux(yuzu::CommandContext& ctx, std::string_view /*store_filter*/,
                      int expiring_days) {
    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    auto dir = open_cert_dir(kDefaultCertDir);
    if (dir.state == CertDirOpen::kAbsent) {
        return;
    }
    if (dir.state == CertDirOpen::kUnreadable) {
        ctx.write_output("not_available|/etc/ssl/certs could not be opened");
        mark_result_partial(ctx, "posix:cert-dir", std::strerror(dir.err));
        return;
    }

    int enum_err = 0;
    bool dir_complete = for_each_cert_entry(
        dir.fd.get(),
        [&](const std::string& name) {
            auto rec = read_linux_cert_record(ctx, dir.fd.get(), name, "/etc/ssl/certs");
            if (rec.thumbprint == "(vanished)")
                return;
            if (expires_within_days(rec.not_after, expiring_days)) {
                ctx.write_output(rec.to_row());
            }
        },
        &enum_err);
    if (!dir_complete) {
        ctx.write_output("not_available|/etc/ssl/certs enumeration incomplete");
        mark_result_partial(ctx, "posix:cert-enum", std::strerror(enum_err));
    }
}

void details_cert_linux(yuzu::CommandContext& ctx, std::string_view thumbprint) {
    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    auto dir = open_cert_dir(kDefaultCertDir);
    if (dir.state == CertDirOpen::kAbsent) {
        ctx.write_output("status|not_found");
        return;
    }
    if (dir.state == CertDirOpen::kUnreadable) {
        ctx.write_output("not_available|/etc/ssl/certs could not be opened");
        mark_result_partial(ctx, "posix:cert-dir", std::strerror(dir.err));
        return;
    }

    // Case-insensitive per content/definitions/certificates.yaml -- see
    // canonical_thumbprint's own comment (consistency-auditor Gate-4 finding:
    // this compared as-is, unlike the macOS path fixed for the same gap
    // earlier in this same PR).
    auto needle = canonical_thumbprint(thumbprint);
    bool found = false;
    // Tracks whether every candidate ENTRY was actually readable -- distinct
    // from `dir_complete` below (which tracks whether the readdir(3) scan
    // itself ran to completion). A file read_linux_cert_record couldn't
    // parse reports its own degradation via mark_result_partial (the ABI4
    // result-status channel) but still leaves this loop free to keep
    // scanning -- so without this flag, an unreadable entry that happened to
    // be the real target would fall all the way through to
    // "status|not_found" below, an incomplete scan silently presenting as a
    // definitive negative (consistency-auditor Gate-4 BLOCKING finding).
    bool scan_complete = true;
    int enum_err = 0;
    bool dir_complete = for_each_cert_entry(
        dir.fd.get(),
        [&](const std::string& name) {
            if (found)
                return;
            auto rec = read_linux_cert_record(ctx, dir.fd.get(), name, "/etc/ssl/certs");
            if (rec.thumbprint == "(vanished)")
                return;
            if (rec.thumbprint == "(skipped)") {
                scan_complete = false;
                return;
            }
            if (canonical_thumbprint(rec.thumbprint) == needle) {
                ctx.write_output(rec.to_row());
                found = true;
            }
        },
        &enum_err);
    // A match already fully answers the query: whatever happened to the
    // readdir(3) scan on entries past the match (including a mid-scan
    // failure, dir_complete=false) cannot retroactively make this result
    // wrong, so the row already written above stands unconditionally. But
    // an incomplete scan is still worth surfacing -- the caller asked about
    // ONE thumbprint and got a real answer, yet other entries in the store
    // went unexamined, so mark the result PARTIAL without touching the row
    // already written (reviewer A3-02: silently dropping this would make a
    // real enumeration failure invisible whenever it happened to fall after
    // the match).
    if (found) {
        if (!dir_complete)
            mark_result_partial(ctx, "posix:cert-enum", std::strerror(enum_err));
        return;
    }
    if (!dir_complete) {
        // Mirrors the directory-open failure row: an errno-bearing readdir
        // failure mid-scan is exactly as inconclusive as never having opened
        // the directory at all.
        ctx.write_output("not_available|/etc/ssl/certs enumeration incomplete");
        mark_result_partial(ctx, "posix:cert-enum", std::strerror(enum_err));
        return;
    }
    if (scan_complete) {
        ctx.write_output("status|not_found");
    } else {
        // Mirrors details_cert_macos's "not_available|<store> scan
        // incomplete" convention for the identical situation: a definitive
        // negative was never established, so this must not say "not_found".
        ctx.write_output("not_available|/etc/ssl/certs scan incomplete");
    }
}

/// Deletes the certificate matching `thumbprint` from /etc/ssl/certs. Returns
/// true iff the request reached a definitive outcome (deleted, or a proven
/// not_found); false on every failure path, so execute() can map "nothing
/// was removed" to a non-zero rc.
///
/// A symlinked entry: the LINK is removed (untrusted), never the target --
/// unlinkat(dirfd, name, 0) always acts on the entry's own name, and this
/// code never opens or resolves the target for anything other than parsing.
/// The identity that must match binds the link's own inode, the target
/// TEXT, and the target's resolved INODE (capture_identity of the parse fd),
/// so a link retargeted to a different path, or rename-over-replaced at the
/// SAME path text, is refused by classify_delete_recheck (kChanged). An
/// in-place rewrite of the same target inode (open+truncate+write, no
/// rename) is NOT detectable this way -- the decision is identity-bound, not
/// content-bound, and that is a deliberate, documented limit, not a gap.
///
/// The residual fstatat-then-unlinkat window (POSIX has no unlink-by-fd) is
/// narrowed to the identity-verified microseconds between the two calls, but
/// not closed. confined_fs_posix.cpp:348-366 documents a STRONGER mitigation
/// for its own (different) delete-with-byte-cap problem -- capture-then-
/// measure: renameat the entry to an unpredictable name, then measure and
/// unlink THAT name -- and that comment is explicit that even THAT only
/// narrows the window further, it does not close it either. This function
/// deliberately does NOT adopt that rename step: /etc/ssl/certs is the
/// host's live trust store, and renaming an entry there before unlinking it
/// has its own hazards a staging/quarantine directory doesn't -- a renamed
/// entry keeping its .pem/.crt suffix would still be trusted under the new
/// name, one without the suffix would be silently untrusted before this
/// function ever verifies it, a crash between rename and unlink would leave
/// renamed residue sitting in a security-relevant directory, and a rename-
/// back on a failed recheck is itself just as racy as the original problem.
/// fstatat-then-unlinkat with full identity verification is the WEAKER but
/// side-effect-free sequence, and is chosen here for exactly that reason.
bool delete_cert_linux(yuzu::CommandContext& ctx, std::string_view thumbprint,
                       std::string_view /*store*/) {
    auto dir = open_cert_dir(kDefaultCertDir);
    if (dir.state == CertDirOpen::kAbsent) {
        ctx.write_output("status|not_found");
        return true;
    }
    if (dir.state == CertDirOpen::kUnreadable) {
        ctx.write_output("error|/etc/ssl/certs could not be opened; nothing removed");
        mark_result_partial(ctx, "posix:cert-dir", std::strerror(dir.err));
        return false;
    }

    auto scan = delete_matching_cert(dir.fd.get(), canonical_thumbprint(thumbprint));
    if (scan.unreadable_entries > 0) {
        // Same degraded-read signal read_linux_cert_record gives list/
        // details -- an unreadable entry here means this scan cannot prove
        // the target is absent/complete (consistency-auditor Gate-4
        // BLOCKING finding).
        mark_result_partial(ctx, "libcrypto:unreadable-file");
    }

    bool ok = true;
    switch (scan.kind) {
    case DeleteScanKind::kDeleted:
        ctx.write_output("status|deleted");
        break;
    case DeleteScanKind::kUnlinkFailed:
        spdlog::warn("certificates: unlinkat('{}') failed (errno={}): {}", scan.entry,
                    scan.unlink_err, std::strerror(scan.unlink_err));
        ctx.write_output("status|delete_failed");
        ok = false;
        break;
    case DeleteScanKind::kChanged:
        ctx.write_output("error|certificate file changed during delete; nothing removed");
        mark_result_partial(ctx, "posix:delete-recheck",
                            "identity at unlink time differs from identity at match time");
        ok = false;
        break;
    case DeleteScanKind::kUnverifiable:
        ctx.write_output(
            "error|certificate file could not be re-verified before delete; nothing removed");
        mark_result_partial(ctx, "posix:delete-recheck",
                            "identity could not be re-derived immediately before unlink");
        ok = false;
        break;
    case DeleteScanKind::kEnumerationFailed:
        ctx.write_output("error|/etc/ssl/certs enumeration incomplete; nothing removed");
        mark_result_partial(ctx, "posix:cert-enum", std::strerror(scan.enum_err));
        return false;
    case DeleteScanKind::kUnreadableEntries:
        ctx.write_output(
            "error|unreadable file(s) in /etc/ssl/certs prevented a complete scan; "
            "cannot confirm the certificate is absent");
        return false;
    case DeleteScanKind::kNotFound:
        ctx.write_output("status|not_found");
        return true;
    }

    // A match already decided the row/rc above -- a readdir failure on
    // entries scanned AFTER that match cannot undo a mutation (or a
    // definitive non-mutation) that already happened, so this is surfaced
    // as PARTIAL rather than reversing `ok` (reviewer A3-02: this must be a
    // real signal, not a reason to reverse the rc).
    if (scan.enumeration_failed)
        mark_result_partial(ctx, "posix:cert-enum", std::strerror(scan.enum_err));
    return ok;
}

#endif // __linux__

// ── macOS implementation ─────────────────────────────────────────────────────

#ifdef __APPLE__

/**
 * Parse individual PEM certificates from the output of
 * `security find-certificate -a -p <keychain>`.
 * Returns the PEM blocks as separate strings.
 */
std::vector<std::string> split_pem_blocks(const std::string& pem_stream) {
    std::vector<std::string> blocks;
    const std::string begin_marker = "-----BEGIN CERTIFICATE-----";
    const std::string end_marker = "-----END CERTIFICATE-----";

    size_t pos = 0;
    while (pos < pem_stream.size()) {
        auto start = pem_stream.find(begin_marker, pos);
        if (start == std::string::npos)
            break;
        auto end = pem_stream.find(end_marker, start);
        if (end == std::string::npos)
            break;
        end += end_marker.size();
        blocks.push_back(pem_stream.substr(start, end - start));
        pos = end;
    }
    return blocks;
}

// ── Bounded-execution bounds (BR-03) ────────────────────────────────────────
//
// Mirrors installed_apps_plugin.cpp's kEnrichmentBudget/kMaxEnrichedApps
// pattern: a per-call deadline alone does not bound a WHOLE action against
// a pathological keychain with many thousands of entries, so every
// action-level entry point (list/details/the delete verify step) also
// computes a wall-clock budget shared across everything IT does, and caps
// how many certificates it will parse out of any single keychain.
constexpr std::chrono::milliseconds kCertParseDeadline{5000};     // one openssl parse of one PEM block (local temp file -- no network)
// The console user's passwd lookup. Deliberately its OWN constant rather than
// borrowing kCertParseDeadline: that one is documented "no network", whereas
// this budget covers a Directory Services round trip that on a domain-joined
// Mac may leave the host entirely (#3406). Same 5s value today, but the two
// are tuned against different failure modes and must move independently -- a
// WAN-latent AD lookup is the case that would justify raising THIS one.
constexpr std::chrono::milliseconds kPasswdLookupDeadline{5000};
constexpr std::chrono::milliseconds kKeychainReadDeadline{15000}; // one `security find-certificate` keychain read (incl. the login-keychain launchctl/sudo hop)
// One bounded, in-process SecItem keychain read of System.keychain or
// SystemRootCertificates.keychain (agents/core/include/yuzu/agent/
// keychain_read.hpp's read_keychain_bounded). Its own constant rather than
// reusing kKeychainReadDeadline: that one bounds a CHILD PROCESS the runner
// can SIGKILL at the deadline, whereas this bounds a detached in-process
// thread against a wedged securityd that can only be ABANDONED, never
// killed -- a wall-clock-equal but mechanically different bound, and the
// two must be able to move independently. Costs a process-global
// bounded_call slot (see keychain_read.hpp's own comment on the ceiling).
constexpr std::chrono::milliseconds kSecItemReadDeadline{15000};
constexpr std::chrono::seconds kCertActionBudget{60};             // whole list/details/delete-verify action, across every keychain it reads
constexpr std::size_t kMaxCertsPerKeychain = 2000;                // per-keychain parsed-certificate cap

/**
 * Run `argv` through the bounded subprocess runner and reduce it to the
 * {output, ok, exit_code} shape the macOS cert-reading call sites below
 * were already written against (pre-#2273 they called a popen-backed
 * run_command_checked() with this exact shape) -- so replacing the
 * transport only touches the two lines that build the call, never the
 * surrounding read/verify logic. `ok` requires a CLEAN, COMPLETE capture:
 * the process actually ran, was not killed at its deadline, was not cut
 * off by the runner's internal capture cap, and exited 0 -- the same bar
 * the old ferror()-based `capture_complete` check enforced, now expressed
 * via SubprocessResult's own timed_out/output_truncated fields (BR-03's
 * "honest sentinel on truncation/timeout").
 */
struct CheckedCommandResult {
    std::string output;
    bool ok = false;
    // Populated whenever the child was spawned, independent of `ok` --
    // delete_cert_macos() reads this directly (not `ok`) to decide whether
    // its post-delete re-enumeration is warranted; see its own comment.
    // -1 when the child could not be spawned or did not exit normally
    // (signaled, killed at the deadline/cancel).
    int exit_code = -1;
    // Human-readable reason the capture was not usable (is_usable_capture's
    // negative case, via capture_failure_detail) -- empty iff `ok`. Lets a
    // caller fold the runner's own diagnosis into its `not_available|<...>`
    // row instead of a bare "read failed" that drops the "why".
    std::string failure_detail;
};

/// TerminationReason -> the stable text name capture_failure_detail and the
/// WARN log line below key on (subprocess_runner.hpp:61-72). A plain switch
/// rather than reusing any enum-to-string elsewhere in the tree, since this
/// name set (exited/signaled/deadline/cancelled/line_limit/spawn_error) is
/// TerminationReason's own and nothing else's.
const char* termination_reason_name(yuzu::agent::TerminationReason reason) {
    switch (reason) {
    case yuzu::agent::TerminationReason::exited:
        return "exited";
    case yuzu::agent::TerminationReason::signaled:
        return "signaled";
    case yuzu::agent::TerminationReason::deadline:
        return "deadline";
    case yuzu::agent::TerminationReason::cancelled:
        return "cancelled";
    case yuzu::agent::TerminationReason::line_limit:
        return "line_limit";
    case yuzu::agent::TerminationReason::spawn_error:
        return "spawn_error";
    }
    return "unknown"; // unreachable -- exhaustive switch above
}

CheckedCommandResult run_bounded_checked(const std::vector<std::string>& argv,
                                         const yuzu::agent::SubprocessOptions& opts,
                                         std::string_view operation) {
    auto result = yuzu::agent::run_bounded_subprocess(argv, opts);
    CheckedCommandResult out;
    out.output = std::move(result.output);
    if (result.tool_ran)
        out.exit_code = result.exit_code;
    out.ok = is_usable_capture(result.tool_ran, result.timed_out, result.output_truncated,
                               result.exit_code);
    // SRE S1 observability: ANY non-ok result -- a deadline kill, capture-cap
    // truncation, a nonzero exit, a spawn failure, ... -- still produces an
    // honest sentinel row + rc downstream, but that is only visible by
    // parsing the emitted output. Surface it, matching
    // event_logs_plugin.cpp's `log show` WARN pattern; termination_reason
    // (ADR-3002) is what lets an on-call engineer reading only the log tell
    // "killed at deadline" (escalate) from "spawn error" (never retry) from
    // a plain nonzero exit.
    if (!out.ok) {
        const char* name = termination_reason_name(result.termination_reason);
        out.failure_detail = capture_failure_detail(
            result.tool_ran, result.timed_out, result.output_truncated, result.exit_code, name);
        spdlog::warn("certificates: {} failed: {} (termination_reason={}, exit_code={})",
                     operation, out.failure_detail, name, result.exit_code);
    }
    return out;
}

// Test-only fault-injection seam (#4374): lets a test prove a login-keychain
// read spawn site was REACHED or SUPPRESSED without spawning anything and
// without reading the host's real login keychain. Read per call (never
// cached) so one test process can point successive dispatches at different
// fixtures. When YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE is set
// and non-empty, returns a failed CheckedCommandResult carrying the env
// value (truncated to 200 bytes) as failure_detail; otherwise nullopt, and
// the caller spawns exactly as today.
std::optional<CheckedCommandResult> injected_login_keychain_read_failure() {
    const char* override_detail =
        std::getenv("YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE");
    if (override_detail == nullptr || override_detail[0] == '\0')
        return std::nullopt;
    CheckedCommandResult injected;
    injected.ok = false;
    injected.failure_detail = std::string(override_detail).substr(0, 200);
    return injected;
}

// ── System/root keychain read: bounded SecItem via agent-core (#3246, #2318a) ──
//
// System.keychain and SystemRootCertificates.keychain ONLY -- the login
// keychain stays on the `security find-certificate` subprocess path via
// build_login_keychain_read_argv() below (rung-2 pre-split argv since
// #3406, registered as sink `certificates/list_certs_macos#1` +
// `certificates/details_cert_macos#1` in docs/agent-spawn-sink-manifest.md).
// The actual bounded SecItem query and its bounded-call wrapping live in
// agent-core (yuzu::agent::read_keychain_bounded,
// agents/core/include/yuzu/agent/keychain_read.hpp), not here: bounding a
// synchronous Security-framework call against a wedged securityd needs
// bounded_call's detached-thread-plus-abandon pattern, and a plugin
// .dylib/.so can be dlclose()'d while that detached thread is still
// executing inside it -- see that header's own comment for the full
// argument, which mirrors passwd_lookup.hpp's identical constraint.

struct SecItemKeychainResult {
    std::vector<yuzu::certificates_x509::CertFields> certs;
    yuzu::agent::KeychainReadStatus status = yuzu::agent::KeychainReadStatus::OpenFailed;
};

static_assert(kMaxCertsPerKeychain == yuzu::agent::kMaxKeychainReadCerts);

/**
 * Adapt agent-core's bounded raw-DER read into this file's own CertFields
 * shape (to_cert_record/expires_within_days downstream expect
 * certificates_x509::CertFields, not raw DER bytes). `budget` is the
 * caller's clamp_to_action_budget(action_deadline, kSecItemReadDeadline)
 * result -- this function never computes its own deadline.
 *
 * A DER blob Security.framework accepted but libcrypto's parse_der_cert
 * rejects downgrades an otherwise-Completed read to Truncated: the read
 * itself finished, but the result is no longer exhaustive (mirrors the
 * per-item conversion-failure fold the previous in-plugin implementation
 * performed at this same seam).
 */
SecItemKeychainResult read_keychain_secitem(const std::string& keychain_path,
                                            std::chrono::milliseconds budget) {
    auto raw = yuzu::agent::read_keychain_bounded(keychain_path, budget);
    SecItemKeychainResult out;
    out.status = raw.status;
    for (const auto& der : raw.certs_der) {
        auto parsed = yuzu::certificates_x509::parse_der_cert(
            std::span<const unsigned char>(der.data(), der.size()));
        if (parsed) {
            out.certs.push_back(std::move(*parsed));
        } else if (out.status == yuzu::agent::KeychainReadStatus::Completed) {
            out.status = yuzu::agent::KeychainReadStatus::Truncated;
        }
    }
    return out;
}

// clamp_to_action_budget, parse_openssl_native_date and strip_leading_blank
// moved to certificates_macos_parsers.hpp (shared with the unit test).

// `deadline` is the CALLER's already-clamped budget for this one openssl
// call (see clamp_to_action_budget) -- never the raw kCertParseDeadline
// constant directly, so a whole-action budget nearing exhaustion (BR-03/
// FP-CERTS-03) is honoured even for a single PEM block's parse.
CertRecord parse_pem_block_macos(const std::string& pem_block, const std::string& store_name,
                                 std::chrono::milliseconds deadline) {
    CertRecord rec;
    rec.store = store_name;
    rec.subject = "(unknown)";
    rec.issuer = "(unknown)";
    rec.not_before = "(unknown)";
    rec.not_after = "(unknown)";
    rec.serial = "(unknown)";
    rec.thumbprint = "(unknown)";
    rec.key_usage = "(none)";

    // Write PEM to a temp file to avoid shell injection via echo (PEM
    // content from the keychain could contain single quotes that break an
    // echo '...' pattern). yuzu::TempFile (mkstemps/O_EXCL, mode 0600) gives
    // each call its own unique, exclusively-created path -- a fixed shared
    // name would collide when two calls run concurrently.
    auto tmp_file_result = yuzu::TempFile::create("yuzu-cert-", ".pem");
    if (!tmp_file_result) {
        rec.subject = "(temp file error)";
        return rec;
    }
    auto tmp_file = std::move(*tmp_file_result);
    {
        std::ofstream tmp(tmp_file.path(), std::ios::trunc);
        if (!tmp) {
            rec.subject = "(temp file error)";
            return rec;
        }
        tmp << pem_block;
    }

    // ONE bounded subprocess call for every field (was up to 7 separate
    // popen-based calls). LibreSSL happily accepts multiple print options on a
    // single invocation and emits them in the EXACT order given, so
    // -subject/-issuer/-startdate/-enddate/-serial/-fingerprint each
    // contribute one fixed-position, never-indented "label=value" line,
    // followed by the full -text dump (used only for Key Usage below --
    // -text replaces the removed `-ext keyUsage`, which LibreSSL also
    // rejects). Absolute path, matching the /usr/bin/security convention
    // used by every other privileged subprocess call in this file (PATH is
    // not trusted for a process that can run as root).
    // sink: certificates/parse_pem_block_macos#1 — rung-2 runner argv (LibreSSL
    // rejects -ext keyUsage, so this login-keychain block parse stays on the CLI),
    // see manifest
    auto result = yuzu::agent::run_bounded_subprocess(
        {"/usr/bin/openssl", "x509", "-noout", "-in", tmp_file.path(), "-subject", "-issuer",
         "-startdate", "-enddate", "-serial", "-fingerprint", "-sha1", "-text"},
        yuzu::agent::SubprocessOptions{.deadline = deadline});

    // SRE S1 observability: this is the one certificate-reading call site that
    // goes through run_bounded_subprocess directly (not run_bounded_checked),
    // so surface a degraded openssl parse here too, matching that wrapper's WARN.
    if (result.timed_out || result.output_truncated) {
        spdlog::warn("certificates: openssl x509 parse {} (timed_out={}, output_truncated={})",
                     result.timed_out ? "timed out" : "output truncated", result.timed_out,
                     result.output_truncated);
    }

    // A killed or capture-capped run's output is only a PARTIAL prefix of
    // the real dump -- it may have captured subject/issuer but been cut
    // off before serial/fingerprint/Key Usage, which would silently shift
    // every subsequent positional field read below onto the wrong line.
    // Treated as wholly unusable rather than parsed piecemeal, the same
    // discipline filesystem_plugin.cpp applies to a timed-out codesign run
    // (PLAN-02: never report a partial capture as if it were a complete,
    // trustworthy read) -- BR-03's "honest sentinel on truncation/timeout".
    // A nonzero exit is rejected too (fix-round finding FP-CERTS-05): a
    // fully-captured, non-timed-out run can still have failed partway
    // through -- e.g. openssl prints a plausible preamble then exits
    // nonzero -- so trusting the captured text without checking the exit
    // status would risk misreporting a failure as valid certificate data.
    if (!is_usable_capture(result.tool_ran, result.timed_out, result.output_truncated,
                           result.exit_code))
        return rec;

    // Positional field parsing lives in the shared, unit-tested
    // parse_openssl_combined_output (certificates_macos_parsers.hpp); rec keeps
    // the store this keychain read set and adopts the parsed identity fields.
    auto parsed = parse_openssl_combined_output(result.output);
    rec.subject = std::move(parsed.subject);
    rec.issuer = std::move(parsed.issuer);
    rec.not_before = std::move(parsed.not_before);
    rec.not_after = std::move(parsed.not_after);
    rec.serial = std::move(parsed.serial);
    rec.thumbprint = std::move(parsed.thumbprint);
    rec.key_usage = std::move(parsed.key_usage);

    return rec;
}

// Whether THIS process (the agent daemon) is already root. Mirrors
// quarantine_plugin.cpp's sudo_prefix(): the shipped macOS LaunchDaemon has
// no `UserName` key today, so it runs as root (docs/agent-privilege-model.md's
// TL;DR) and `launchctl asuser` -- which itself requires root privileges,
// per `man launchctl` -- already succeeds with no escalation. The target
// least-privilege `_yuzu` account (future hardening, #1455) is NOT root, so
// build_login_keychain_read_argv() uses this to decide whether it needs
// to add its own outer `sudo -n` hop first. Cached: EUID can't change during
// the agent's lifetime.
bool caller_is_root() {
    static const bool is_root = (geteuid() == 0);
    return is_root;
}

/// One passwd record, reduced to the two fields this plugin needs.
/// `home_dir` is EMPTY when the record's pw_dir is not a usable absolute
/// path -- see ConsoleUser::home_dir for what that means to the caller.
struct PasswdEntry {
    std::string uid;      // pw_uid, decimal-formatted
    std::string home_dir; // pw_dir, "" if it failed is_valid_home_dir
};

/**
 * Resolve the current console (GUI) user via subprocess. SystemConfiguration
 * IS linkable from this LaunchDaemon (see agents/shared/macos_console_user.hpp's
 * SCDynamicStoreCopyConsoleUser, already used by the users plugin) -- this
 * shells out to `stat` by deliberate choice, not because the framework is
 * unavailable: `stat -f%Su /dev/console` reports the console DEVICE owner,
 * while SCDynamicStoreCopyConsoleUser reports the Aqua SESSION owner, and the
 * two diverge under fast user switching / screen sharing -- WHICH user's login
 * keychain this plugin reads is an operator-visible behavioural contract that
 * a rung-1 promotion would need to verify separately (tracked in #2380). See
 * docs/agent-spawn-sink-manifest.md's `resolve_console_user#1` row. Returns
 * std::nullopt when there is no interactive console session (login window /
 * headless -- stat reports the "root" sentinel, see
 * yuzu::macos::is_no_console_user) OR when the resolved username/uid fails
 * the shared allowlist/numeric validation: an unsafe value is never
 * interpolated into a command, so it is treated exactly like "no console
 * user" rather than risking a later step trusting it.
 *
 * `action_deadline` is the CALLER's whole-action budget (BR-03/
 * FP-CERTS-03): this is the FIRST subprocess work any action performs, so
 * both the `stat` spawn and the bounded passwd lookup below clamp to it via
 * clamp_to_action_budget rather than the raw kCertParseDeadline constant, and
 * bail out to std::nullopt (same as "no console session") if the budget is
 * already exhausted before either can even be attempted.
 */
/// Why console-user resolution produced no user. The distinction is
/// load-bearing and was added by an adversarial/governance finding: collapsing
/// "nobody is logged in" together with "the lookup degraded" made a wedged
/// Directory Service read as an EMPTY CONSOLE, which silently dropped the
/// login-keychain leg -- `list` then presented a truncated inventory as
/// complete and `details` answered a confident `status|not_found` for a
/// certificate that was simply never looked for. Same defect class, and the
/// same fix shape, as the Gate-6 SRE finding recorded at
/// discovery_plugin.cpp:346-353 (a degraded reverse-DNS lookup that looked
/// identical to a host with no PTR record).
enum class ConsoleUserOutcome {
    kResolved,  ///< a console user was identified and validated
    kNoSession, ///< definitively nobody at the console (login window / headless)
    kDegraded,  ///< the question could not be answered -- NEVER report as "no session"
};

struct ConsoleUserResolution {
    ConsoleUserOutcome outcome = ConsoleUserOutcome::kNoSession;
    std::optional<yuzu::macos::ConsoleUser> user;
    /// Operator-facing reason, set iff kDegraded. A literal, so string_view-safe.
    std::string_view degrade_reason;
};

ConsoleUserResolution resolve_console_user(
        std::chrono::steady_clock::time_point action_deadline) {
    ConsoleUserResolution out;
    auto stat_deadline = clamp_to_action_budget(action_deadline, kCertParseDeadline);
    if (stat_deadline <= std::chrono::milliseconds::zero()) {
        out.outcome = ConsoleUserOutcome::kDegraded;
        out.degrade_reason = "console-user lookup skipped: action deadline exceeded";
        return out;
    }
    std::string username;
    // Test-only seam (#4374): a substitute for the `stat` spawn's OUTPUT
    // only, never a bypass of the validation below -- read per call (never
    // cached), so a single test process can point successive dispatches at
    // different fixtures.
    if (const char* override_user = std::getenv("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE");
        override_user != nullptr && override_user[0] != '\0') {
        username = override_user;
    } else {
        // sink: certificates/resolve_console_user#1 — rung-2 runner argv;
        // SystemConfiguration IS linkable here, deliberately not used (device-
        // vs session-owner semantics), see manifest
        auto stat_result = run_bounded_checked({"/usr/bin/stat", "-f%Su", "/dev/console"},
                                               yuzu::agent::SubprocessOptions{
                                                   .deadline = stat_deadline},
                                               "console-user stat /dev/console");
        if (!stat_result.ok) {
            // The `stat` spawn itself failed/timed out -- we do not KNOW whether
            // anyone is at the console, so we must not answer as though we do.
            out.outcome = ConsoleUserOutcome::kDegraded;
            out.degrade_reason = "console-user lookup failed (stat /dev/console)";
            return out;
        }
        username = yuzu::macos::parse_console_user_output(stat_result.output);
    }
    if (yuzu::macos::is_no_console_user(username)) {
        out.outcome = ConsoleUserOutcome::kNoSession; // a real, definite answer
        return out;
    }
    if (!yuzu::macos::is_valid_username(username)) {
        // A console owner exists but its name failed the allowlist. Refusing to
        // use it is correct; calling that "no session" is not.
        out.outcome = ConsoleUserOutcome::kDegraded;
        out.degrade_reason = "console user name failed validation";
        return out;
    }

    // The uid and the home directory both come from ONE passwd read (#3406).
    // This replaced a second `/usr/bin/id -u <username>` subprocess that asked
    // the same database for the same uid: once the login-keychain leg needed
    // pw_dir from here anyway, that spawn was pure redundancy, so it is gone
    // and sink `certificates/resolve_console_user#2` is retired.
    //
    // It STILL clamps to the action budget. Losing the subprocess lost the
    // runner's SIGKILL-at-deadline, so the bound has to be re-imposed on the
    // lookup itself -- `getpwnam_r` can block on a wedged Directory Services
    // with no timeout of its own (adversarial-review finding, #3406). Without
    // this clamp a single directory-joined host with a sick DS could pin a
    // plugin-host worker per request and starve unrelated commands.
    auto pw_budget = clamp_to_action_budget(action_deadline, kPasswdLookupDeadline);
    if (pw_budget <= std::chrono::milliseconds::zero()) {
        out.outcome = ConsoleUserOutcome::kDegraded;
        out.degrade_reason = "passwd lookup skipped: action deadline exceeded";
        return out;
    }
    // Each status is reported as itself. kNotFound is the ONLY one that is a
    // definite negative, and even it is not "no console session" -- somebody is
    // at the console, their account just did not resolve.
    auto pw_res = yuzu::agent::resolve_passwd_bounded(username, pw_budget);
    switch (pw_res.status) {
    case yuzu::agent::PasswdLookupStatus::kTimeout:
        out.outcome = ConsoleUserOutcome::kDegraded;
        out.degrade_reason = "console user's directory lookup timed out";
        return out;
    case yuzu::agent::PasswdLookupStatus::kError:
        out.outcome = ConsoleUserOutcome::kDegraded;
        out.degrade_reason = "console user's directory lookup failed";
        return out;
    case yuzu::agent::PasswdLookupStatus::kNotFound:
        out.outcome = ConsoleUserOutcome::kDegraded;
        out.degrade_reason = "console user has no passwd record";
        return out;
    case yuzu::agent::PasswdLookupStatus::kOk:
        break;
    }
    PasswdEntry pw_entry;
    pw_entry.uid = std::move(pw_res.record.uid);
    if (yuzu::macos::is_valid_home_dir(pw_res.record.home_dir))
        pw_entry.home_dir = std::move(pw_res.record.home_dir);
    auto* pw = &pw_entry;
    // Defensive: pw_uid is an integral uid_t, so a decimal format of it is
    // digits by construction and this can't fail -- kept because every value
    // this plugin carries into an argv passes its shared guard first, and a
    // future change to how uid is sourced must not silently skip it.
    if (!yuzu::macos::is_valid_uid(pw->uid)) {
        out.outcome = ConsoleUserOutcome::kDegraded;
        out.degrade_reason = "console user's uid failed validation";
        return out;
    }

    out.outcome = ConsoleUserOutcome::kResolved;
    out.user = yuzu::macos::ConsoleUser{std::move(username), std::move(pw->uid),
                                        std::move(pw->home_dir)};
    return out;
}

// canonical_thumbprint() lives in certificates_macos_parsers.hpp (resolved
// unqualified via `using namespace yuzu::certificates_macos;` above)
// -- details_cert_linux/delete_cert_linux need the identical fold.

// BlockIdentityOutcome / classify_block_identity moved to
// certificates_macos_parsers.hpp (shared with the unit test).

/**
 * Enumerate one keychain's PEM blocks and emit rows for it, filtered by
 * expiry. `action_deadline` is the CALLER's whole-action budget (shared
 * across every keychain that single list_certs_macos() call reads);
 * kMaxCertsPerKeychain additionally caps how many blocks THIS keychain
 * alone contributes, so one pathological keychain can't spend the entire
 * action budget by itself. Once either bound is spent, remaining blocks in
 * this keychain are simply not parsed/emitted -- never a fabricated row --
 * and this returns false so the caller can emit an honest "scan
 * incomplete" sentinel instead of silently presenting a truncated keychain
 * as a complete result (fix-round finding FP-CERTS-02). Returns true only
 * when every block in `pem` was scanned within budget.
 */
bool emit_keychain_rows_macos(yuzu::CommandContext& ctx, const std::string& pem,
                              const std::string& store_label, int expiring_days,
                              std::chrono::steady_clock::time_point action_deadline) {
    std::size_t parsed = 0;
    for (const auto& block : split_pem_blocks(pem)) {
        auto parse_deadline = clamp_to_action_budget(action_deadline, kCertParseDeadline);
        if (parsed >= kMaxCertsPerKeychain || parse_deadline <= std::chrono::milliseconds::zero())
            return false;
        ++parsed;
        auto rec = parse_pem_block_macos(block, store_label, parse_deadline);
        if (expires_within_days(rec.not_after, expiring_days)) {
            ctx.write_output(rec.to_row());
        }
    }
    return true;
}

// #2318b: re-confirm the console session owner immediately before a
// login-keychain spawn -- resolve_console_user() above ran a Directory
// Services lookup that can itself take seconds; this in-process
// ::stat("/dev/console") needs none, so the window between "who is logged
// in" and "whose keychain are we about to read" -- a fast-user-switch could
// change it in between -- shrinks from tens of seconds to microseconds. Not
// eliminated: see classify_console_owner_recheck's own comment. No new spawn
// is added by this check, so it adds no sink-manifest row. The single
// ::stat("/dev/console") site for both list_certs_macos and
// details_cert_macos.
struct ConsoleOwnerSnapshot {
    bool ok = false;
    unsigned long long uid = 0;
};

ConsoleOwnerSnapshot snapshot_console_owner() {
    // Test-only seam (#4374), read per call (never cached): a substitute for
    // the ::stat() OUTPUT only. The whole value must be digits and fully
    // consumed by std::from_chars -- any parse failure yields ok=false, the
    // same "unknown" answer a failed ::stat produces.
    if (const char* override_uid =
            std::getenv("YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE");
        override_uid != nullptr && override_uid[0] != '\0') {
        ConsoleOwnerSnapshot out;
        std::string_view value(override_uid);
        auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), out.uid);
        out.ok = (ec == std::errc{} && ptr == value.data() + value.size());
        if (!out.ok)
            out.uid = 0;
        return out;
    }
    struct stat console_st {};
    ConsoleOwnerSnapshot out;
    out.ok = ::stat("/dev/console", &console_st) == 0;
    out.uid = static_cast<unsigned long long>(console_st.st_uid);
    return out;
}

void list_certs_macos(yuzu::CommandContext& ctx, std::string_view store_filter,
                      int expiring_days) {
    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    // Whole-action budget across EVERYTHING this call does, including
    // console-user resolution (BR-03, mirrors installed_apps_plugin.cpp's
    // kEnrichmentBudget) -- started here, before the first subprocess this
    // action may run, so the 60s bound covers the call's entire wall-clock
    // cost rather than just the per-certificate parsing loops (fix-round
    // finding FP-CERTS-03: previously this was created only AFTER
    // console-user resolution, and every keychain-level `security` read
    // still received its own full, unclamped kKeychainReadDeadline
    // regardless of how much budget was already spent -- letting one call
    // run to roughly 100s in the worst case). See emit_keychain_rows_macos's
    // own comment for how the per-keychain cap and this budget interact.
    const auto action_deadline = std::chrono::steady_clock::now() + kCertActionBudget;

    auto cu = resolve_console_user(action_deadline);
    auto& console_user = cu.user;
    auto plan = yuzu::macos::resolve_store_plan(store_filter, console_user.has_value());

    if (cu.outcome == ConsoleUserOutcome::kDegraded) {
        // We could not determine the console user, so the login keychain was
        // NEVER LOOKED AT. Say so, on every store filter that would have
        // included it. Without this the default/`all` path emits no sentinel
        // at all (resolve_store_plan only sets sentinel_required for an
        // explicit store=login) and the caller receives a login-less
        // certificate list presented as complete.
        // Same question as details_cert_macos asks, via the same keyword table:
        // would this store filter have read the login keychain at all?
        if (yuzu::macos::resolve_store_plan(store_filter, /*has_console_user=*/true).want_login) {
            ctx.write_output(std::format("not_available|{}", cu.degrade_reason));
            mark_result_partial(ctx, "login-keychain", cu.degrade_reason);
        }
    } else if (plan.sentinel_required) {
        // store=login was explicitly requested and there is DEFINITELY no
        // console session to read it from -- never a silent empty (the header
        // row above with zero rows following would read as "ran fine, no
        // certs") and never a fabricated result.
        ctx.write_output("not_available|no console session");
        mark_result_partial(ctx, "login-keychain");
        return;
    }

    // System.keychain / SystemRootCertificates.keychain: bounded SecItem read
    // via read_keychain_secitem (agent-core seam, #3246/#2318a) -- budget is
    // whatever remains of the whole-action budget, clamped to
    // kSecItemReadDeadline, exactly like the subprocess reads below. A
    // checked failure emits an honest sentinel row instead of silently
    // contributing zero rows, same discipline PLAN-12 established for the
    // subprocess path SecItem itself replaced.
    auto emit_secitem_keychain = [&](std::string_view label, const std::string& path) {
        auto budget = clamp_to_action_budget(action_deadline, kSecItemReadDeadline);
        if (budget <= std::chrono::milliseconds::zero()) {
            ctx.write_output(std::format("not_available|{} action deadline exceeded", label));
            mark_result_partial(ctx, secitem_provenance(label));
            return;
        }
        auto r = read_keychain_secitem(path, budget);
        if (r.status == yuzu::agent::KeychainReadStatus::Completed ||
            r.status == yuzu::agent::KeychainReadStatus::Truncated) {
            for (const auto& cert : r.certs) {
                auto rec = to_cert_record(cert, std::string(label));
                if (expires_within_days(rec.not_after, expiring_days)) {
                    ctx.write_output(rec.to_row());
                }
            }
        }
        if (r.status == yuzu::agent::KeychainReadStatus::TimedOut) {
            spdlog::warn("certificates: {} secitem read timed out", label);
        }
        if (auto reason = secitem_failure_reason(r.status, label)) {
            ctx.write_output(std::format("not_available|{}", *reason));
            mark_result_partial(ctx, secitem_provenance(label), *reason);
        }
    };

    if (plan.want_system) {
        emit_secitem_keychain("System.keychain", yuzu::macos::system_keychain_path());
    }

    if (plan.want_root) {
        emit_secitem_keychain("SystemRootCertificates.keychain", yuzu::macos::root_keychain_path());
    }

    if (plan.want_login) {
        // console_user is guaranteed engaged here: resolve_store_plan only
        // sets want_login when has_console_user was true.
        // Two DISTINCT failures, reported distinctly. An empty home_dir means
        // the console user resolved but their passwd record carried no usable
        // absolute pw_dir -- the realistic failure, and the one an operator can
        // actually act on. An empty argv after a good home_dir would mean
        // build_login_keychain_read_argv()'s own re-validation rejected a
        // uid/username resolve_console_user() had already validated: defensive
        // only, and a genuinely different (internal) fault. Reporting both as
        // "command construction failed" told the operator the wrong thing.
        // #2318b: re-confirm the console session owner -- see
        // snapshot_console_owner's own comment for the full rationale.
        auto owner = snapshot_console_owner();
        switch (classify_console_owner_recheck(owner.ok, owner.uid, console_user->uid)) {
        case ConsoleOwnerRecheck::kChanged:
            ctx.write_output("not_available|console user changed");
            mark_result_partial(ctx, "login-keychain", "console user changed");
            break;
        case ConsoleOwnerRecheck::kUnknown:
            ctx.write_output("not_available|console user recheck failed");
            mark_result_partial(ctx, "login-keychain", "console user recheck failed");
            break;
        case ConsoleOwnerRecheck::kUnchanged: {
            spdlog::info("certificates: login keychain read for console user {} (uid {})",
                        console_user->username, console_user->uid);
            auto argv = console_user->home_dir.empty()
                            ? std::vector<std::string>{}
                            : yuzu::macos::build_login_keychain_read_argv(
                                  console_user->uid, console_user->username,
                                  console_user->home_dir, caller_is_root());
            if (console_user->home_dir.empty()) {
                ctx.write_output(
                    "not_available|login keychain home directory unresolved for console user");
                mark_result_partial(ctx, "login-keychain");
            } else if (argv.empty()) {
                ctx.write_output("not_available|login keychain command construction failed");
                mark_result_partial(ctx, "login-keychain");
            } else {
                auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
                if (read_deadline <= std::chrono::milliseconds::zero()) {
                    ctx.write_output("not_available|login keychain action deadline exceeded");
                    mark_result_partial(ctx, "login-keychain");
                } else {
                    // Pre-split argv through the bounded runner -- no shell
                    // (#3406, rung 2). The former "/bin/sh -c" hop existed for
                    // exactly two shell features, both now provided without
                    // one: `~username` tilde expansion (resolve_passwd_entry's
                    // bounded passwd lookup above -- the same lookup the shell
                    // performed) and a `2>/dev/null` redirect (the runner's
                    // merge_stderr=false default already discards child
                    // stderr). The launchctl/sudo/security session hop itself
                    // never needed a shell -- it execs fine as plain argv.
                    // sink: certificates/list_certs_macos#1 — rung-2 runner argv (launchctl asuser + sudo -u session hop), see manifest
                    auto injected = injected_login_keychain_read_failure();
                    auto login_result = injected ? std::move(*injected)
                                                  : run_bounded_checked(
                                                        argv,
                                                        yuzu::agent::SubprocessOptions{
                                                            .deadline = read_deadline},
                                                        "login keychain read");
                    if (login_result.ok) {
                        if (!emit_keychain_rows_macos(ctx, login_result.output, "login.keychain-db",
                                                      expiring_days, action_deadline)) {
                            ctx.write_output("not_available|login keychain scan incomplete");
                            mark_result_partial(ctx, "login-keychain");
                        }
                    } else {
                        // A missing sudoers grant, a launchctl/sudo failure, or an
                        // inaccessible keychain path all land here. Report it
                        // honestly instead of emitting zero rows, which would be
                        // indistinguishable from "this keychain is genuinely
                        // empty". Names the termination reason (post
                        // code-review CXR-03: this used to drop
                        // login_result.failure_detail entirely, unlike
                        // details_cert_macos's equivalent branch, contrary to
                        // what the #2318 changelog fragment already claimed).
                        ctx.write_output(std::format("not_available|login keychain read failed ({})",
                                                     login_result.failure_detail));
                        mark_result_partial(ctx, "login-keychain", login_result.failure_detail);
                    }
                }
            }
            break;
        }
        }
    }
}

void details_cert_macos(yuzu::CommandContext& ctx, std::string_view thumbprint,
                        std::string_view store_filter) {
    ctx.write_output("subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");

    // Whole-action budget across EVERYTHING this call does, including
    // console-user resolution -- see list_certs_macos's matching comment
    // (BR-03/fix-round finding FP-CERTS-03).
    const auto action_deadline = std::chrono::steady_clock::now() + kCertActionBudget;

    auto cu = resolve_console_user(action_deadline);
    auto& console_user = cu.user;
    auto plan = yuzu::macos::resolve_store_plan(store_filter, console_user.has_value());

    if (cu.outcome == ConsoleUserOutcome::kNoSession && plan.sentinel_required) {
        ctx.write_output("not_available|no console session");
        mark_result_partial(ctx, "login-keychain");
        return;
    }
    // Would this request have read the login keychain AT ALL, had the console
    // user resolved? Ask resolve_store_plan with has_console_user=true rather
    // than comparing store keywords here: it owns the keyword table, so a
    // future store name stays correctly classified instead of silently falling
    // into the wrong branch.
    const bool login_selected =
        yuzu::macos::resolve_store_plan(store_filter, /*has_console_user=*/true).want_login;
    // A DEGRADED resolution must not reach the `status|not_found` fall-through
    // at the end of this function: that would report a completed, negative
    // search over a keychain this call never opened. Seeding read_failed here
    // is what makes the existing not_available/partial branch fire instead.
    // (See that branch's own comment -- this is exactly the case it warns of.)
    // Gated on login_selected: a `store=System` request never selected the
    // login keychain, so a degraded console-user lookup is irrelevant to it and
    // must not attach a login-keychain sentinel to its result.
    const bool console_user_degraded =
        (cu.outcome == ConsoleUserOutcome::kDegraded) && login_selected;

    // Canonicalized once so the loop below is a plain `==` against
    // parse_pem_block_macos's always-uppercase output -- the thumbprint
    // parameter is documented case-insensitive (certificates.yaml) but was
    // previously compared as-is, so a lowercase caller-supplied thumbprint
    // silently never matched (CERT-READ-01).
    auto needle = canonical_thumbprint(thumbprint);

    // Tri-state per-keychain scan outcome (fix-round finding FP-CERTS-02):
    // a search that hits the cap/deadline before reaching a conclusive
    // answer, or that encounters a block classify_block_identity can't
    // establish the identity of (a failed/timed-out per-cert openssl
    // parse leaves the honest "(unknown)" sentinel, never a fabricated
    // thumbprint), can never positively prove the needle is ABSENT from
    // that keychain -- both must report kIncomplete, never silently fold
    // into a clean kNotFound that ultimately surfaces as the definitive
    // "status|not_found" below.
    enum class ScanOutcome { kFound, kNotFound, kIncomplete };

    auto check = [&](const std::string& pem, const std::string& store) -> ScanOutcome {
        std::size_t parsed = 0;
        for (const auto& block : split_pem_blocks(pem)) {
            auto parse_deadline = clamp_to_action_budget(action_deadline, kCertParseDeadline);
            if (parsed >= kMaxCertsPerKeychain ||
                parse_deadline <= std::chrono::milliseconds::zero())
                return ScanOutcome::kIncomplete;
            ++parsed;
            auto rec = parse_pem_block_macos(block, store, parse_deadline);
            switch (classify_block_identity(rec.thumbprint, needle)) {
            case BlockIdentityOutcome::kMatch:
                ctx.write_output(rec.to_row());
                return ScanOutcome::kFound;
            case BlockIdentityOutcome::kInconclusive:
                return ScanOutcome::kIncomplete;
            case BlockIdentityOutcome::kNoMatch:
                break;
            }
        }
        return ScanOutcome::kNotFound;
    };

    // Same tri-state scan, but over a SecItem-derived CertFields vector
    // (System/root, WP-B rung-1) instead of raw PEM blocks -- reuses the
    // SAME classify_block_identity decision `check` above uses, so the two
    // scans can never drift on what counts as a match/no-match/inconclusive
    // identity. `result.status != Completed` (Truncated: kMaxCertsPerKeychain
    // capped the read, or a DER blob failed to parse; anything worse never
    // reaches here -- see scan_secitem_store) folds into kIncomplete exactly
    // like `check`'s own cap/deadline check does.
    auto check_secitem = [&](const SecItemKeychainResult& result,
                             const std::string& store) -> ScanOutcome {
        for (const auto& cert : result.certs) {
            switch (classify_block_identity(cert.thumbprint, needle)) {
            case BlockIdentityOutcome::kMatch:
                ctx.write_output(to_cert_record(cert, store).to_row());
                return ScanOutcome::kFound;
            case BlockIdentityOutcome::kInconclusive:
                return ScanOutcome::kIncomplete;
            case BlockIdentityOutcome::kNoMatch:
                break;
            }
        }
        return result.status == yuzu::agent::KeychainReadStatus::Completed
                   ? ScanOutcome::kNotFound
                   : ScanOutcome::kIncomplete;
    };

    // A checked read failure, an exhausted action budget, or an incomplete
    // scan on a selected store all mean the search below is incomplete for
    // that store -- remembered (first failure wins) so the final result
    // can honestly report "not_available" instead of a false "not_found"
    // if no match turns up. A match found in a store that DID read/scan
    // successfully is still reported normally, even if an earlier store
    // had already failed.
    bool read_failed = console_user_degraded;
    // std::string rather than std::string_view (fix-round shape, B3): unlike
    // the previous file-local literals, System/root failure text is now
    // COMPUTED by secitem_failure_reason and would dangle as a view into a
    // temporary.
    std::string failure_reason =
        console_user_degraded ? std::string(cu.degrade_reason) : std::string{};
    // Which half of the hybrid read failed, for the ABI4 result seam below --
    // set together with failure_reason at every site (first failure wins), so
    // the machine-visible provenance can never name a different keychain from
    // the operator-visible reason.
    std::string failure_provenance = console_user_degraded ? "login-keychain" : std::string{};

    // System.keychain / SystemRootCertificates.keychain: bounded SecItem read
    // (agent-core seam, #3246/#2318a) -- same budget discipline and failure
    // vocabulary as list_certs_macos's emit_secitem_keychain.
    auto scan_secitem_store = [&](std::string_view label, const std::string& path) {
        auto budget = clamp_to_action_budget(action_deadline, kSecItemReadDeadline);
        if (budget <= std::chrono::milliseconds::zero()) {
            if (!read_failed) {
                read_failed = true;
                failure_reason = std::format("{} action deadline exceeded", label);
                failure_provenance = secitem_provenance(label);
            }
            return false; // not found -- caller should not return early
        }
        auto result = read_keychain_secitem(path, budget);
        const bool ok = result.status == yuzu::agent::KeychainReadStatus::Completed ||
                        result.status == yuzu::agent::KeychainReadStatus::Truncated;
        if (!ok) {
            if (!read_failed) {
                read_failed = true;
                failure_reason = *secitem_failure_reason(result.status, label);
                failure_provenance = secitem_provenance(label);
            }
            return false;
        }
        switch (check_secitem(result, std::string(label))) {
        case ScanOutcome::kFound:
            return true;
        case ScanOutcome::kIncomplete:
            if (!read_failed) {
                read_failed = true;
                auto reason = secitem_failure_reason(result.status, label);
                failure_reason = reason ? *reason : std::format("{} scan incomplete", label);
                failure_provenance = secitem_provenance(label);
            }
            return false;
        case ScanOutcome::kNotFound:
            return false;
        }
        return false; // unreachable -- exhaustive switch above
    };

    if (plan.want_system) {
        if (scan_secitem_store("System.keychain", yuzu::macos::system_keychain_path()))
            return;
    }

    if (plan.want_root) {
        if (scan_secitem_store("SystemRootCertificates.keychain", yuzu::macos::root_keychain_path()))
            return;
    }

    if (plan.want_login) {
        // #2318b: re-confirm the console session owner -- see
        // snapshot_console_owner's own comment for the full rationale.
        auto owner = snapshot_console_owner();
        switch (classify_console_owner_recheck(owner.ok, owner.uid, console_user->uid)) {
        case ConsoleOwnerRecheck::kChanged:
            if (!read_failed) {
                read_failed = true;
                failure_reason = "console user changed";
                failure_provenance = "login-keychain";
            }
            break;
        case ConsoleOwnerRecheck::kUnknown:
            if (!read_failed) {
                read_failed = true;
                failure_reason = "console user recheck failed";
                failure_provenance = "login-keychain";
            }
            break;
        case ConsoleOwnerRecheck::kUnchanged: {
            spdlog::info("certificates: login keychain read for console user {} (uid {})",
                        console_user->username, console_user->uid);
            // See list_certs_macos's matching comment: home-resolution failure
            // and a defensive argv-construction failure are distinct faults
            // and are reported as such.
            auto argv = console_user->home_dir.empty()
                            ? std::vector<std::string>{}
                            : yuzu::macos::build_login_keychain_read_argv(
                                  console_user->uid, console_user->username,
                                  console_user->home_dir, caller_is_root());
            if (argv.empty()) {
                if (!read_failed) {
                    read_failed = true;
                    failure_reason =
                        console_user->home_dir.empty()
                            ? "login keychain home directory unresolved for console user"
                            : "login keychain command construction failed";
                    failure_provenance = "login-keychain";
                }
            } else {
                auto read_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
                if (read_deadline <= std::chrono::milliseconds::zero()) {
                    if (!read_failed) {
                        read_failed = true;
                        failure_reason = "login keychain action deadline exceeded";
                        failure_provenance = "login-keychain";
                    }
                } else {
                    // See list_certs_macos's matching comment: pre-split argv
                    // through the bounded runner, no shell (#3406, rung 2) --
                    // tilde expansion is replaced by
                    // resolve_passwd_entry's bounded passwd lookup above.
                    // sink: certificates/details_cert_macos#1 — rung-2 runner argv (launchctl asuser + sudo -u session hop), see manifest
                    auto injected = injected_login_keychain_read_failure();
                    auto login_result = injected ? std::move(*injected)
                                                  : run_bounded_checked(
                                                        argv,
                                                        yuzu::agent::SubprocessOptions{
                                                            .deadline = read_deadline},
                                                        "login keychain read");
                    if (!login_result.ok) {
                        if (!read_failed) {
                            read_failed = true;
                            failure_reason = std::format("login keychain read failed ({})",
                                                        login_result.failure_detail);
                            failure_provenance = "login-keychain";
                        }
                    } else {
                        switch (check(login_result.output, "login.keychain-db")) {
                        case ScanOutcome::kFound:
                            return;
                        case ScanOutcome::kIncomplete:
                            if (!read_failed) {
                                read_failed = true;
                                failure_reason = "login keychain scan incomplete";
                                failure_provenance = "login-keychain";
                            }
                            break;
                        case ScanOutcome::kNotFound:
                            break;
                        }
                    }
                }
            }
            break;
        }
        }
    }

    if (read_failed) {
        // Don't fall through to "status|not_found" below -- that would
        // claim a completed, negative search when a selected keychain was
        // never actually readable OR its scan never reached a conclusive
        // answer (missing sudoers grant, launchctl/sudo failure, an
        // inaccessible keychain path, the cap/deadline hit mid-scan, an
        // unparseable block, ...). See list_certs_macos's matching comment.
        ctx.write_output(std::format("not_available|{}", failure_reason));
        mark_result_partial(ctx, failure_provenance, failure_reason);
        return;
    }

    ctx.write_output("status|not_found");
}

/**
 * Re-enumerate `keychain_path` and report whether `canonical_needle` (an
 * already-uppercased thumbprint -- see canonical_thumbprint) is present.
 * Used by delete_cert_macos() to VERIFY a delete actually took effect
 * rather than trusting a zero exit status alone -- `security
 * delete-certificate` can exit 0 without the item actually being gone
 * (ACL/SIP quirks, an unexpected keychain state), and reporting "deleted"
 * in that case would be exactly the false-success this package exists to
 * prevent. Returns std::nullopt when the keychain itself could not be read
 * (locked, missing, permission denied, a read failure, ...) --
 * delete_cert_macos() treats that as the unreadable-keychain verdict,
 * never "absent": a verification read that could not run proves nothing
 * about the outcome.
 *
 * MECHANISM (post code-review F1, #2318a): this used to shell out to
 * `/usr/bin/security find-certificate -a -p <keychain_path>` and trust a
 * zero exit status plus empty stdout as proof the keychain is genuinely
 * empty. That is exactly the #2318a UP-4 defect the issue named this
 * function by, and it is NOT hypothetical: empirically verified on real
 * macOS 26.6.2 (`security find-certificate -a -p` against a chmod-000,
 * genuinely permission-denied copy of a populated System.keychain) --
 * `security` exits 0 with EMPTY stdout and no diagnostic, indistinguishable
 * from a truly empty keychain. (A merely LOCKED-but-otherwise-readable
 * keychain does NOT trigger this: certificates are non-secret keychain
 * items and both `security` and `SecItemCopyMatching` correctly enumerate
 * them regardless of lock state -- also empirically verified. The
 * reproducible failure mode is a file-permission/ACL denial, not a lock.)
 * delete_cert_macos() only ever resolves `keychain_path` to System.keychain
 * (see resolve_delete_keychain_path -- "root" is rejected earlier as
 * SIP-sealed, "login" is rejected outright, nothing else is recognized), so
 * this now reuses the SAME bounded, in-process SecItem seam
 * (read_keychain_secitem / agents/core/include/yuzu/agent/keychain_read.hpp,
 * #3246) that list_certs_macos/details_cert_macos already use for
 * System.keychain -- eliminating the second, honesty-blind reading
 * mechanism entirely rather than teaching it a new special case.
 * KeychainReadStatus::NotReadable/OpenFailed/TimedOut/Rejected all map to
 * std::nullopt (never "absent"); only Completed with no match, or Truncated
 * with no match found before truncation, is a real "not present" answer --
 * and Truncated can only narrow future certainty, never manufacture it, so
 * it takes the same nullopt-if-inconclusive path as the old scan-incomplete
 * case did.
 *
 * `action_deadline` is the CALLER's whole-action budget (fix-round finding
 * FP-CERTS-R3: this used to start its own fresh kCertActionBudget window
 * regardless of how much of delete_cert_macos()'s own budget the preceding
 * `security delete-certificate` call had already spent, letting the pair
 * run to roughly 75s worst case). The keychain read below clamps to this
 * same shared deadline via clamp_to_action_budget, same as
 * list/details_cert_macos. If the budget is already exhausted before the
 * read can even be attempted, this returns std::nullopt without issuing a
 * doomed call -- classify_delete_verdict already treats std::nullopt as
 * kVerifyUnreadable (an honest "action deadline exceeded" outcome), never
 * kDeleted.
 */
// Deliberately does not call secitem_failure_reason/mark_result_partial the
// way list_certs_macos/details_cert_macos do on a non-Completed read: this
// helper's std::nullopt already reaches delete_cert_macos's own
// classify_delete_verdict, which turns it into a hard `error|...` result and
// a non-zero rc -- a stronger signal than CONSTRAINED/PARTIAL, and the one a
// destructive action's caller actually needs. Naming the specific
// KeychainReadStatus in that error text (rather than a generic "could not be
// re-read to verify") would be a nice-to-have, not a correctness gap.
std::optional<bool> keychain_contains_thumbprint(
    const std::string& keychain_path, const std::string& canonical_needle,
    std::chrono::steady_clock::time_point action_deadline) {
    auto read_deadline = clamp_to_action_budget(action_deadline, kSecItemReadDeadline);
    if (read_deadline <= std::chrono::milliseconds::zero()) {
        return std::nullopt;
    }
    auto result = read_keychain_secitem(keychain_path, read_deadline);
    bool matched = false;
    for (const auto& cert : result.certs) {
        if (cert.thumbprint == canonical_needle) {
            matched = true;
            break;
        }
    }
    return fold_secitem_presence(result.status, matched);
}

// is_provably_absent_macos moved to certificates_macos_parsers.hpp (shared
// with the unit test).

bool delete_cert_macos(yuzu::CommandContext& ctx, std::string_view thumbprint,
                       std::string_view store) {
    // Validate thumbprint is hex-only to prevent command injection.
    if (!is_valid_thumbprint(thumbprint)) {
        ctx.write_output("error|invalid thumbprint format (expected 40 hex characters)");
        return false;
    }

    // SystemRootCertificates.keychain is SEALED on modern (SIP-protected)
    // macOS -- /System/Library/Keychains/... sits under the sealed system
    // volume and cannot be modified by `security delete-certificate` (or
    // anything else short of disabling SIP). Advertising deletion from it
    // as achievable would report a root-trust change that can never
    // actually take effect: reject outright, before ever shelling out, with
    // the same fail-closed posture as the unsupported-store branch below --
    // never silently redirect to a writable keychain either. This check
    // MUST come before resolve_delete_keychain_path(): that resolver maps
    // "root" to a real path (it is a legitimate read target for list/
    // details), so the delete-specific sealed-root rejection has to happen
    // here, not there.
    if (store == "root") {
        // error| prefix for convention consistency (SHOULD-3): every other
        // delete rejection in this function emits `error|<msg>`, so the
        // sealed-root case does too rather than a bespoke
        // `certificates|unsupported|` grammar a downstream consumer would have
        // to special-case.
        ctx.write_output(
            "error|SystemRootCertificates.keychain is sealed on this macOS "
            "version (System Integrity Protection) and cannot be modified");
        return false;
    }

    // Delete acts on exactly one keychain; store otherwise preserves
    // today's unconditional System.keychain target for the unset/"MY"
    // default and "System" (see yuzu::macos::resolve_delete_keychain_path).
    // store=login is deliberately NOT supported for delete here -- unlike
    // list/details it would need the same asuser/sudo dance (and its own
    // honest-sentinel handling) for a destructive action that has no test
    // coverage in this change; left for a follow-up if a real need shows
    // up. "login", "all", and any other unrecognized value (root is
    // already handled above) are REJECTED rather than silently redirected
    // to System.keychain -- a destructive action must never target a
    // keychain the caller didn't ask for.
    auto target = yuzu::macos::resolve_delete_keychain_path(store);
    if (!target) {
        // store is caller-supplied free text (the cross-platform dispatcher
        // passes the raw `store` param straight through) -- safe_output_field
        // it (K-7) so a hostile value containing '|' or embedded CR/LF can
        // never inject an extra column/row into this pipe/newline-delimited
        // output, same as CertRecord::to_row() above.
        ctx.write_output(std::format("error|store '{}' is not supported for delete",
                                     yuzu::util::safe_output_field(store)));
        return false;
    }

    auto needle = canonical_thumbprint(thumbprint);

    // Whole-action budget (BR-03) covering the pre-delete presence check
    // (K-4, below), the delete command, AND its post-delete verify read,
    // same pattern as list/details_cert_macos (fix-round finding
    // FP-CERTS-R3: before this, the verify read computed its own fresh
    // kCertActionBudget window independent of what the delete call above it
    // had already spent, letting the pair run to roughly 75s worst case).
    // Every subprocess this action runs clamps to it via
    // clamp_to_action_budget rather than receiving its own full, unclamped
    // deadline.
    const auto action_deadline = std::chrono::steady_clock::now() + kCertActionBudget;

    // K-4: prove the thumbprint is present (or absent) BEFORE ever running
    // the destructive delete. Without this, deleting an ABSENT thumbprint
    // hits `security delete-certificate`'s own exit-1 "not found" path,
    // which the code below reports as a generic kCommandFailed
    // `error|delete failed ...` -- inconsistent with Windows/Linux (and
    // this macOS action's own pre-change behaviour), which report
    // `status|not_found` rc 0 for an absent cert. Idempotent "ensure-absent"
    // remediation depends on that contract. Reuses the SAME
    // keychain_contains_thumbprint helper the post-delete verify below
    // already trusts, clamped to the same action_deadline budget, so this
    // pre-check can never itself blow the whole-action budget unaccounted
    // for. See is_provably_absent_macos for why only a definitive `false`
    // (never std::nullopt) takes the not_found branch.
    auto pre_delete_presence = keychain_contains_thumbprint(*target, needle, action_deadline);
    if (is_provably_absent_macos(pre_delete_presence)) {
        ctx.write_output("status|not_found");
        return true;
    }

    auto delete_deadline = clamp_to_action_budget(action_deadline, kKeychainReadDeadline);
    if (delete_deadline <= std::chrono::milliseconds::zero()) {
        // Defensive only -- action_deadline is set immediately above, so a
        // freshly-clamped kKeychainReadDeadline cannot itself be zero. Kept
        // for parity with clamp_to_action_budget's other call sites, which
        // must all treat zero as "do not even attempt this subprocess"
        // (see its own comment).
        ctx.write_output("error|action deadline exceeded before delete could run");
        return false;
    }

    // Inspect the ACTUAL exit status of `security delete-certificate`
    // rather than grepping its combined stdout+stderr for words like
    // "error": text-only classification would report "deleted" for any
    // output that doesn't happen to contain those words, including
    // genuine operational failures (permission denied, a locked keychain,
    // ...). merge_stderr=true (was the shell string's `2>&1`) so a failure
    // diagnostic -- `security` writes those to stderr -- is captured into
    // `.output` for the error message below.
    // sink: certificates/delete_cert_macos#1 — rung-2 runner argv, MUTATING,
    // hex-validated thumbprint + fixed literal keychain path, see manifest
    auto delete_result = run_bounded_checked(
        {"/usr/bin/security", "delete-certificate", "-Z", needle, *target},
        yuzu::agent::SubprocessOptions{.deadline = delete_deadline, .merge_stderr = true},
        "delete-certificate");

    // Only re-enumerate to verify when the delete command itself exited 0
    // -- a nonzero/abnormal exit is already a terminal failure, and
    // re-checking presence after a command that didn't run to completion
    // would tell us nothing its own exit status didn't already tell us.
    // Checked via exit_code rather than .ok deliberately: .ok also
    // requires a fully-captured, non-timed-out, non-capped read of THIS
    // command's own diagnostic text (see run_bounded_checked), which is
    // irrelevant here -- only whether `security delete-certificate` itself
    // exited cleanly decides whether a re-enumeration is warranted.
    std::optional<bool> still_present;
    if (delete_result.exit_code == 0) {
        // keychain_contains_thumbprint clamps to the SAME action_deadline
        // (see its own comment) -- if the delete call above consumed most
        // of the budget, the verify read either gets whatever remains or,
        // if nothing remains, an honest std::nullopt (never a doomed call).
        // classify_delete_verdict below maps that to kVerifyUnreadable,
        // never kDeleted.
        still_present = keychain_contains_thumbprint(*target, needle, action_deadline);
    }

    switch (yuzu::macos::classify_delete_verdict(delete_result.exit_code, still_present)) {
    case yuzu::macos::DeleteVerdict::kCommandFailed:
        // delete_result.output is `security`'s captured stderr (merge_stderr
        // = true above) -- raw, attacker-influenceable diagnostic text that
        // typically ends with its own trailing newline and can span multiple
        // lines. safe_output_field it (K-7) so it can never inject an extra
        // pipe-delimited column or newline-delimited row into this output,
        // same as the store field above and CertRecord::to_row().
        ctx.write_output(std::format("error|delete failed (exit {}): {}", delete_result.exit_code,
                                     yuzu::util::safe_output_field(delete_result.output)));
        return false;
    case yuzu::macos::DeleteVerdict::kVerifyUnreadable:
        // rc==0 alone is never sufficient: the keychain could not be
        // re-read to confirm the certificate is actually gone, so this is
        // reported as an unverified failure, NEVER as "deleted" -- an
        // unreadable keychain must not be treated as "absent".
        ctx.write_output(
            "error|delete reported success but the keychain could not be re-read to verify");
        return false;
    case yuzu::macos::DeleteVerdict::kStillPresent:
        ctx.write_output(
            "error|delete reported success but certificate is still present in the keychain");
        return false;
    case yuzu::macos::DeleteVerdict::kDeleted:
        ctx.write_output("status|deleted");
        return true;
    }
    return false; // unreachable -- silences -Wreturn-type
}

#endif // __APPLE__

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Windows enumerates/deletes via CryptoAPI natively (rung 1). Linux (WP-B)
// enumerates PEM files from /etc/ssl/certs via native filesystem I/O and
// parses every field (subject/issuer/dates/serial/thumbprint/key usage)
// in-process via libcrypto (certificates_x509.hpp) — no subprocess of any
// kind, rung 1 for list/details/delete alike; the openssl-subprocess
// mechanism this replaced, and the /bin/sh -c governed-shell rung it used
// to run under, are gone. macOS list/details are a genuine HYBRID: reading
// System.keychain/SystemRootCertificates.keychain promotes to rung 1
// (SecItemCopyMatching, a direct Security-framework API call — no
// subprocess at all), but the SAME call also still reads the login
// keychain by default via the launchctl/sudo session hop — since #3406 a
// PRE-SPLIT argv through the bounded runner (rung 2; the former
// "/bin/sh -c" wrapping, whose only shell dependency was `~user` tilde
// expansion, is gone — see build_login_keychain_read_argv()) — so
// list/details declare rung 2 overall, the rung reflecting the DEEPEST
// interpreter either call path intentionally invokes, not the shallowest
// (no interpreter remains on any path here). macOS delete (System/MY only,
// login unsupported — see below) is unchanged: a direct
// `/usr/bin/security delete-certificate` argv call through the bounded
// subprocess runner, rung 2, and also rejects SystemRootCertificates.keychain
// outright (sealed under System Integrity Protection) — a genuine, permanent
// capability limitation, not merely an error path.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "libcrypto X509 (in-process PEM parse)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "SecItem (System/root, in-process) + security find-certificate "
                                    "argv via subprocess runner (login)",
         "System.keychain and SystemRootCertificates.keychain are read natively via "
         "SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo "
         "session hop, run as a pre-split argv through the bounded subprocess runner"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "CryptoAPI (CertEnumCertificatesInStore)",
                              nullptr},
    },
    {
        /* .action      = */ "details",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "libcrypto X509 (in-process PEM parse)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "SecItem (System/root, in-process) + security find-certificate "
                                    "argv via subprocess runner (login)",
         "System.keychain and SystemRootCertificates.keychain are read natively via "
         "SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo "
         "session hop, run as a pre-split argv through the bounded subprocess runner"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "CryptoAPI (CertEnumCertificatesInStore)",
                              nullptr},
    },
    {
        /* .action      = */ "delete",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "libcrypto X509 match + held-dirfd openat/fstatat/unlinkat with pre-unlink identity "
         "recheck",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "security delete-certificate via subprocess runner",
         "SystemRootCertificates.keychain is sealed under SIP and rejected outright; only "
         "System/MY store deletes are supported"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "CryptoAPI (CertDeleteCertificateFromStore)",
                              nullptr},
    },
};

} // namespace

// ── Plugin class ─────────────────────────────────────────────────────────────

class CertificatesPlugin final : public yuzu::Plugin {
public:
    static constexpr const char* kName = "certificates";
    static constexpr const char* kVersion = "1.0.0";

    std::string_view name() const noexcept override { return kName; }
    std::string_view version() const noexcept override { return kVersion; }
    std::string_view description() const noexcept override {
        return "Certificate inventory and management for system stores";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "details", "delete", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {

        if (action == "list") {
            auto store = params.get("store", "all");
            auto days_str = params.get("expiring_within_days", "0");
            int expiring_days = 0;
            if (!days_str.empty()) {
                expiring_days = std::atoi(std::string{days_str}.c_str());
            }

#ifdef _WIN32
            list_certs_win(ctx, store, expiring_days);
#elif defined(__linux__)
            list_certs_linux(ctx, store, expiring_days);
#elif defined(__APPLE__)
            list_certs_macos(ctx, store, expiring_days);
#endif
            return 0;
        }

        if (action == "details") {
            auto thumbprint = params.get("thumbprint");
            if (thumbprint.empty()) {
                ctx.write_output("error|thumbprint parameter required");
                return 1;
            }
            if (!is_valid_thumbprint(thumbprint)) {
                ctx.write_output("error|invalid thumbprint format (expected 40 hex characters)");
                return 1;
            }

#ifdef _WIN32
            details_cert_win(ctx, thumbprint);
#elif defined(__linux__)
            details_cert_linux(ctx, thumbprint);
#elif defined(__APPLE__)
            // store defaults to "all" here (unset -> legacy unfiltered
            // behaviour, extended to include the login keychain when a
            // console user is available) -- Windows/Linux details_cert_*
            // don't take a store filter, so the param is only read on this
            // branch to avoid an unused-variable warning on those platforms.
            details_cert_macos(ctx, thumbprint, params.get("store", "all"));
#endif
            return 0;
        }

        if (action == "delete") {
            auto thumbprint = params.get("thumbprint");
            auto store = params.get("store", "MY");
            if (thumbprint.empty()) {
                ctx.write_output("error|thumbprint parameter required");
                return 1;
            }
            if (!is_valid_thumbprint(thumbprint)) {
                ctx.write_output("error|invalid thumbprint format (expected 40 hex characters)");
                return 1;
            }

#ifdef _WIN32
            // delete_cert_win() returns false only when nothing was
            // actually removed (the store couldn't be opened, or the
            // delete call itself failed) -- propagate that as a non-zero rc
            // so orchestration can't mistake "nothing was deleted" for a
            // successful no-op, same rc/typed-status coherence as macOS.
            if (!delete_cert_win(ctx, thumbprint, store))
                return 1;
#elif defined(__linux__)
            // delete_cert_linux() returns false only when nothing was
            // actually removed (the store couldn't be opened, an
            // incomplete scan couldn't prove absence, or the pre-unlink
            // identity recheck refused the delete) -- propagate that as a
            // non-zero rc so orchestration can't mistake "nothing was
            // deleted" for a successful no-op, same rc/typed-status
            // coherence as Windows/macOS.
            if (!delete_cert_linux(ctx, thumbprint, store))
                return 1;
#elif defined(__APPLE__)
            // delete_cert_macos() returns false only for a request REJECTED
            // outright (sealed root / unsupported store) or a delete that
            // was never verified as actually taking effect -- propagate
            // that as a non-zero rc so orchestration can't mistake "nothing
            // was deleted" for a successful no-op.
            if (!delete_cert_macos(ctx, thumbprint, store))
                return 1;
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(CertificatesPlugin)
