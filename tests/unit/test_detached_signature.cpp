/**
 * test_detached_signature.cpp — the shared detached-CMS verifier (#416/#3807).
 *
 * This is the primitive both the plugin loader and the OTA updater rely on to
 * answer "is this binary the one my operator authorised". The plugin side has
 * its own end-to-end tests; these cover the verifier itself, and in particular
 * the fd-based form the updater needs, which has no plugin-side coverage at all.
 */

#include <yuzu/agent/detached_signature.hpp>

#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <string>

#include "cms_test_fixtures.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

using yuzu::agent::CmsFailure;
using yuzu::agent::verify_detached_cms;
using yuzu::agent::verify_detached_cms_fd;
using namespace yuzu::test::cms;

namespace {

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

} // namespace

TEST_CASE("detached CMS: a valid signature verifies", "[signature][cms]") {
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);
    CHECK_FALSE(verify_detached_cms(f.artifact_file, sig, f.trust_bundle).has_value());
}

TEST_CASE("detached CMS: a tampered artifact is rejected as invalid", "[signature][cms]") {
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);
    {
        // Flip content AFTER signing. The digest no longer covers these bytes,
        // so this must fail on the CONTENT check, not the chain check.
        std::ofstream out(f.artifact_file, std::ios::binary | std::ios::app);
        out << "tampered";
    }
    auto err = verify_detached_cms(f.artifact_file, sig, f.trust_bundle);
    REQUIRE(err.has_value());
    CHECK(err->kind == CmsFailure::kInvalid);
}

TEST_CASE("detached CMS: a signature from a foreign CA is rejected as untrusted",
          "[signature][cms]") {
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);
    // Same artifact, same signature, a trust bundle holding a DIFFERENT CA.
    auto err = verify_detached_cms(f.artifact_file, sig, f.other_trust_bundle);
    REQUIRE(err.has_value());
    CHECK(err->kind == CmsFailure::kUntrusted);
}

TEST_CASE("detached CMS: a leaf without codeSigning EKU is rejected even under the trusted CA",
          "[signature][cms]") {
    // The case X509_PURPOSE_CODE_SIGN exists for. Scope note, measured: DELETING
    // that line entirely still fails this case, because CMS_verify falls back to
    // OpenSSL's own smime_sign purpose, which also rejects a serverAuth leaf.
    // What this case actually discriminates is the purpose being WEAKENED (e.g.
    // to X509_PURPOSE_ANY), which is the realistic regression. Internal PKIs commonly
    // issue mTLS and S/MIME certs from the same root an operator would put in
    // this bundle. Without X509_PURPOSE_CODE_SIGN, trusting that root for
    // signing would silently make every cert it ever issued a signing authority.
    auto f = build_signing_fixtures();

    auto ca_key = generate_ec_key();
    auto ca_cert = mint_cert(ca_key.get(), ca_key.get(), nullptr, "Yuzu Test CA 2", true);
    auto leaf_key = generate_ec_key();
    auto leaf_cert = mint_cert_eku(leaf_key.get(), ca_key.get(), ca_cert.get(),
                                   "Server Auth Leaf", "serverAuth");

    const auto bundle = f.dir / "eku-bundle.pem";
    write_pem_cert(bundle, ca_cert.get());
    const auto sig_path = f.dir / "eku.sig";
    write_cms_signature(sig_path, f.artifact_file, leaf_cert.get(), leaf_key.get());

    auto err = verify_detached_cms(f.artifact_file, read_file(sig_path), bundle);
    REQUIRE(err.has_value());
    CHECK(err->kind == CmsFailure::kUntrusted);
}

TEST_CASE("detached CMS: malformed and empty signatures are rejected", "[signature][cms]") {
    auto f = build_signing_fixtures();
    auto bad = verify_detached_cms(f.artifact_file, "-----BEGIN CMS-----\nnope\n-----END CMS-----\n",
                                   f.trust_bundle);
    REQUIRE(bad.has_value());
    CHECK(bad->kind == CmsFailure::kInvalid);

    auto empty = verify_detached_cms(f.artifact_file, "", f.trust_bundle);
    REQUIRE(empty.has_value());
    CHECK(empty->kind == CmsFailure::kInvalid);
}

TEST_CASE("detached CMS: an unreadable trust bundle fails CLOSED", "[signature][cms]") {
    // A bundle we cannot read proves nothing. The one outcome that must never
    // happen is treating "cannot check" as "checked out fine".
    //
    // #5249: it fails closed with its OWN kind, not kUntrusted. Lumping the two
    // together made the rc1-rc5 Windows installer ACL bug (#5196) read as an
    // untrusted signer in both the log and the refusal counter.
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);
    const auto missing = f.dir / "does-not-exist.pem";
    auto err = verify_detached_cms(f.artifact_file, sig, missing);
    REQUIRE(err.has_value());
    CHECK(err->kind == CmsFailure::kBundleUnreadable);
    CHECK(err->kind != CmsFailure::kUntrusted);
    // The detail names the bundle and says what is wrong with it.
    CHECK(err->detail.find(missing.string()) != std::string::npos);
    CHECK(err->detail.find("not found") != std::string::npos);
}

TEST_CASE("detached CMS: a bundle that is not PEM is bundle_unreadable, not untrusted",
          "[signature][cms]") {
    // An existing, readable file holding no certificate is the other half of
    // "cannot load the anchor" — a truncated copy, or the wrong file entirely.
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);

    const auto garbage = f.dir / "garbage-bundle.pem";
    std::ofstream(garbage, std::ios::binary) << "this is not a certificate\n";
    auto err = verify_detached_cms(f.artifact_file, sig, garbage);
    REQUIRE(err.has_value());
    CHECK(err->kind == CmsFailure::kBundleUnreadable);

    const auto empty = f.dir / "empty-bundle.pem";
    std::ofstream(empty, std::ios::binary).flush();
    auto err2 = verify_detached_cms(f.artifact_file, sig, empty);
    REQUIRE(err2.has_value());
    CHECK(err2->kind == CmsFailure::kBundleUnreadable);
}

TEST_CASE("detached CMS: a genuinely untrusted signer is still kUntrusted, not bundle_unreadable",
          "[signature][cms]") {
    // The other direction of the #5249 split: a READABLE bundle holding the
    // wrong CA must keep reporting a chain failure.
    auto f = build_signing_fixtures();
    auto err = verify_detached_cms(f.artifact_file, read_file(f.sig_file), f.other_trust_bundle);
    REQUIRE(err.has_value());
    CHECK(err->kind == CmsFailure::kUntrusted);
}

TEST_CASE("probe_trust_bundle: agrees with the verifier's own load", "[signature][cms]") {
    // The startup warning (#5249) uses this. It must go through the verifier's
    // loader, so a bundle it calls loadable is one the verifier gets past.
    auto f = build_signing_fixtures();
    CHECK_FALSE(yuzu::agent::probe_trust_bundle(f.trust_bundle).has_value());
    CHECK_FALSE(yuzu::agent::probe_trust_bundle(f.other_trust_bundle).has_value());

    const auto missing = f.dir / "nope.pem";
    auto problem = yuzu::agent::probe_trust_bundle(missing);
    REQUIRE(problem.has_value());
    CHECK(problem->find(missing.string()) != std::string::npos);
    CHECK(problem->find("not found") != std::string::npos);

    const auto garbage = f.dir / "garbage.pem";
    std::ofstream(garbage, std::ios::binary) << "junk";
    CHECK(yuzu::agent::probe_trust_bundle(garbage).has_value());

    // A directory is not a bundle file.
    auto dir_problem = yuzu::agent::probe_trust_bundle(f.dir);
    REQUIRE(dir_problem.has_value());
    CHECK(dir_problem->find("not a regular file") != std::string::npos);
}

TEST_CASE("signature_refusal_reason: every kind maps into the shared reason list",
          "[signature][cms]") {
    // The heartbeat sums over kSignatureRefusalReasons; a kind whose label is
    // not in that list would be counted by neither the tag nor the fleet gauge.
    using yuzu::agent::kSignatureRefusalReasons;
    using yuzu::agent::signature_refusal_reason;
    const auto in_list = [](std::string_view r) {
        for (const auto known : kSignatureRefusalReasons)
            if (known == r)
                return true;
        return false;
    };
    CHECK(signature_refusal_reason(CmsFailure::kInvalid) == "invalid");
    CHECK(signature_refusal_reason(CmsFailure::kUntrusted) == "untrusted");
    CHECK(signature_refusal_reason(CmsFailure::kBundleUnreadable) == "bundle_unreadable");
    for (const auto kind :
         {CmsFailure::kInvalid, CmsFailure::kUntrusted, CmsFailure::kBundleUnreadable})
        CHECK(in_list(signature_refusal_reason(kind)));
    CHECK(in_list("missing")); // the updater's no-signature reason, not a CmsFailure
}

#ifndef _WIN32

TEST_CASE("detached CMS (fd): verifies from an open descriptor", "[signature][cms][fd]") {
    // The form the updater uses. It matters that this works on a descriptor the
    // caller already read to EOF while hashing.
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);

    const int fd = ::open(f.artifact_file.c_str(), O_RDONLY);
    REQUIRE(fd >= 0);
    ::lseek(fd, 0, SEEK_END); // as the updater leaves it after hashing

    CHECK_FALSE(verify_detached_cms_fd(fd, sig, f.trust_bundle).has_value());
    ::close(fd);
}

TEST_CASE("detached CMS (fd): the caller's file offset is restored", "[signature][cms][fd]") {
    // The verifier borrows someone else's descriptor. Silently rewinding it
    // would be a trap for the next reader of that fd.
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);

    const int fd = ::open(f.artifact_file.c_str(), O_RDONLY);
    REQUIRE(fd >= 0);
    const off_t before = ::lseek(fd, 7, SEEK_SET);
    REQUIRE(before == 7);

    CHECK_FALSE(verify_detached_cms_fd(fd, sig, f.trust_bundle).has_value());
    CHECK(::lseek(fd, 0, SEEK_CUR) == 7);
    ::close(fd);
}

TEST_CASE("detached CMS (fd): a tampered artifact is rejected through the fd form too",
          "[signature][cms][fd]") {
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);
    {
        std::ofstream out(f.artifact_file, std::ios::binary | std::ios::app);
        out << "tampered";
    }
    const int fd = ::open(f.artifact_file.c_str(), O_RDONLY);
    REQUIRE(fd >= 0);
    auto err = verify_detached_cms_fd(fd, sig, f.trust_bundle);
    ::close(fd);
    REQUIRE(err.has_value());
    CHECK(err->kind == CmsFailure::kInvalid);
}

TEST_CASE("detached CMS (fd): a descriptor without read access fails CLOSED",
          "[signature][cms][fd]") {
    // THE CASE THAT HID A REAL BUG. Every other fd test here opens O_RDONLY — a
    // readable descriptor the production path did not actually supply. The
    // Windows updater staged its download GENERIC_WRITE|DELETE with no share
    // access, so the handle the verifier read through had no read rights and
    // every signed update was refused on that platform, invisibly to this suite.
    //
    // The behaviour is correct — unreadable content must never verify — so what
    // this pins is the fail-closed direction, and it stands as the reason the
    // updater's file handle must carry read access.
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);

    const int fd = ::open(f.artifact_file.c_str(), O_WRONLY);
    REQUIRE(fd >= 0);
    auto err = verify_detached_cms_fd(fd, sig, f.trust_bundle);
    ::close(fd);
    REQUIRE(err.has_value()); // never "verified"
}

TEST_CASE("detached CMS (fd): a bad descriptor is rejected, not dereferenced",
          "[signature][cms][fd]") {
    auto f = build_signing_fixtures();
    const auto sig = read_file(f.sig_file);
    auto err = verify_detached_cms_fd(-1, sig, f.trust_bundle);
    REQUIRE(err.has_value());
    CHECK(err->kind == CmsFailure::kInvalid);
}

#endif // !_WIN32
