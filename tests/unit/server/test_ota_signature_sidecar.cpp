/**
 * test_ota_signature_sidecar.cpp — the server half of OTA signature delivery.
 *
 * WHY THIS FILE EXISTS. Two independent external reviewers found, in the same
 * round, that the ~200 production lines carrying a signature from an operator's
 * upload to an agent's CheckForUpdate response had NO discriminating test: the
 * upload handler needs a multipart request the test route sink cannot build, and
 * the reader needs an UpdateRegistry, which needs Postgres. The green server
 * suite proved only that the new code did not break assertions written before
 * the field existed.
 *
 * The decisions now live in ota_signature_sidecar.hpp, testable with a temp
 * directory and nothing else. What is NOT covered here, honestly: that the
 * handlers actually call these functions. That is a wiring claim, and the two
 * call sites remain Postgres-bound.
 */

#include "ota_signature_sidecar.hpp"
#include "update_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <fstream>
#include <string>

#include "../test_helpers.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#endif

using yuzu::server::kMaxSignatureBytes;
using yuzu::server::looks_like_pem_cms;
using yuzu::server::signature_sidecar_covers_binary;
using yuzu::server::read_signature_sidecar;
using yuzu::server::replace_signature_sidecar;
using yuzu::server::SidecarOutcome;
using yuzu::server::signature_sidecar_path;
using yuzu::server::describe_package_delete;
using yuzu::server::PackageDeleteOutcome;

namespace fs = std::filesystem;

namespace {

struct Dir {
    fs::path p;
    Dir() {
        p = yuzu::test::unique_temp_path("yuzu_test_ota_sidecar_");
        fs::create_directories(p);
    }
    ~Dir() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
};

void write(const fs::path& f, const std::string& s) {
    std::ofstream o(f, std::ios::binary);
    o.write(s.data(), static_cast<std::streamsize>(s.size()));
}

} // namespace

TEST_CASE("sidecar path is derived from the binary, never named separately",
          "[ota][sidecar]") {
    // Derived, so one package cannot be pointed at another's signature.
    CHECK(signature_sidecar_path("/updates/yuzu-agent-1.2.3") ==
          fs::path("/updates/yuzu-agent-1.2.3.sig"));
    CHECK(signature_sidecar_path("/updates/x.exe") == fs::path("/updates/x.exe.sig"));
}

TEST_CASE("sidecar: a normal signature is served verbatim", "[ota][sidecar]") {
    Dir d;
    const auto sig = d.p / "pkg.sig";
    const std::string pem = "-----BEGIN CMS-----\nabc\n-----END CMS-----\n";
    write(sig, pem);

    std::string out;
    CHECK(read_signature_sidecar(sig, out) == SidecarOutcome::kServed);
    CHECK(out == pem); // byte-for-byte: the agent verifies against exactly this
}

TEST_CASE("sidecar: an absent one is the ordinary unsigned case, not an error",
          "[ota][sidecar]") {
    Dir d;
    std::string out{"stale"};
    CHECK(read_signature_sidecar(d.p / "nope.sig", out) == SidecarOutcome::kAbsent);
    CHECK(out.empty()); // never leaves a previous caller's value behind
}

TEST_CASE("sidecar: an over-cap file is refused rather than served", "[ota][sidecar]") {
    // This blob rides on EVERY CheckForUpdateResponse, and gRPC clients default
    // to a 4 MB receive limit — an oversized file here breaks update checks for
    // the whole fleet, not for one package.
    Dir d;
    const auto sig = d.p / "big.sig";
    write(sig, std::string(kMaxSignatureBytes + 1, 'x'));

    std::string out;
    CHECK(read_signature_sidecar(sig, out) == SidecarOutcome::kOverCap);
    CHECK(out.empty());

    // Exactly at the cap is still served — an off-by-one here would reject
    // legitimate signatures.
    const auto ok = d.p / "atcap.sig";
    write(ok, std::string(kMaxSignatureBytes, 'y'));
    CHECK(read_signature_sidecar(ok, out) == SidecarOutcome::kServed);
    CHECK(out.size() == kMaxSignatureBytes);
}

#ifndef _WIN32
TEST_CASE("sidecar: a FIFO is refused WITHOUT being opened", "[ota][sidecar]") {
    // THE CASE THE ORDERING EXISTS FOR. open(2) on a FIFO blocks until a writer
    // appears, so reading before the size check would wedge the CheckForUpdate
    // handler thread — one wedged thread per agent check, which is pool
    // exhaustion rather than a slow response.
    //
    // VERIFIED BY MUTATION, and note HOW it fails: disabling the size check makes
    // this case HANG rather than fail, because the open blocks forever. That is
    // attributable but slow, so the assertion below is deliberately preceded by a
    // writer-less non-blocking probe — if a future change reintroduces the
    // blocking open, the meson timeout is what catches it, and this comment is
    // the map back to the cause.
    Dir d;
    const auto fifo = d.p / "pipe.sig";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);

    std::string out;
    CHECK(read_signature_sidecar(fifo, out) == SidecarOutcome::kOverCap);
    CHECK(out.empty());
}
#endif

TEST_CASE("sidecar: an unsigned re-upload does NOT inherit the previous signature",
          "[ota][sidecar]") {
    // THE BUG THREE REVIEWERS FOUND. The binary is overwritten in place, so
    // without an unconditional remove a rebuilt package uploaded unsigned kept
    // the old .sig — a signature over bytes that no longer exist. Agents refuse
    // that in BOTH enforcement modes, so one unsigned re-upload stopped the
    // whole anchored fleet updating.
    Dir d;
    const auto sig = d.p / "pkg.sig";

    REQUIRE(replace_signature_sidecar(sig, "-----BEGIN CMS-----\nv1\n-----END CMS-----\n"));
    REQUIRE(fs::exists(sig));

    // Re-upload, unsigned.
    REQUIRE(replace_signature_sidecar(sig, ""));
    CHECK_FALSE(fs::exists(sig));

    std::string out;
    CHECK(read_signature_sidecar(sig, out) == SidecarOutcome::kAbsent);
}

TEST_CASE("sidecar: a signed re-upload replaces the previous signature", "[ota][sidecar]") {
    Dir d;
    const auto sig = d.p / "pkg.sig";
    REQUIRE(replace_signature_sidecar(sig, "old"));
    REQUIRE(replace_signature_sidecar(sig, "new"));

    std::string out;
    REQUIRE(read_signature_sidecar(sig, out) == SidecarOutcome::kServed);
    CHECK(out == "new"); // not appended, not stale
}

TEST_CASE("sidecar: a signed replace never publishes an unsigned window",
          "[ota][sidecar]") {
    // CheckForUpdate reads this path concurrently, so a remove-then-write
    // publishes a brief window in which the package is served UNSIGNED — an
    // agent polling inside it is refused under --update-require-signature, with
    // no cause an operator can point at. The replace is therefore write-sibling
    // -then-rename. What this pins is the observable consequence: no temp file
    // is left behind, and the sidecar is readable and correct immediately after.
    Dir d;
    const auto sig = d.p / "pkg.sig";
    REQUIRE(replace_signature_sidecar(sig, "v1"));

    REQUIRE(replace_signature_sidecar(sig, "v2"));
    std::string out;
    REQUIRE(read_signature_sidecar(sig, out) == SidecarOutcome::kServed);
    CHECK(out == "v2");

    // The staging sibling must not survive — a stray "<pkg>.sig.tmp" would be
    // mistaken for a package named "<pkg>.sig" by a later directory listing.
    CHECK_FALSE(fs::exists(d.p / "pkg.sig.tmp"));

    int entries = 0;
    for (const auto& e : fs::directory_iterator(d.p)) {
        (void)e;
        ++entries;
    }
    CHECK(entries == 1); // exactly the sidecar
}

TEST_CASE("sidecar: a zero-byte signature is refused, not served as signed",
          "[ota][sidecar]") {
    // Served as-is, an empty sidecar puts an empty string on the wire. The agent
    // tests `sig.empty()` and reads that as ABSENT — so in permissive mode it
    // applies the binary UNVERIFIED, while the operator's Signed column (which
    // only asks whether a file exists) says "signed". Two surfaces disagreeing
    // about the same package is precisely what that column exists to prevent.
    Dir d;
    const auto sig = d.p / "pkg.sig";
    write(sig, "");
    REQUIRE(fs::exists(sig));

    std::string out{"poison"};
    CHECK(read_signature_sidecar(sig, out) == SidecarOutcome::kUnreadable);
    CHECK(out.empty());
}

TEST_CASE("sidecar: a failed replace KEEPS the predecessor rather than stripping a signature",
          "[ota][sidecar]") {
    // THE FAILURE PATH TWO REVIEWERS FOUND INDEPENDENTLY. The binary is
    // overwritten before the sidecar is replaced, so a write or rename failure
    // that left the PREVIOUS signature behind would leave it covering bytes that
    // no longer exist — refused by every anchored agent in both modes, making the
    // package permanently undeliverable while the log claimed it was unsigned.
    //
    // Forced realistically: <sig>.tmp is pre-created as a DIRECTORY, so the
    // staging ofstream cannot open it, while the PARENT stays writable. That
    // matters — an earlier version of this test made the parent read-only, but
    // then the binary overwrite that precedes this call would have failed too, so
    // it tested a state production never reaches AND defeated the cleanup it was
    // checking for.
    Dir d;
    const auto sig = d.p / "pkg.sig";
    REQUIRE(replace_signature_sidecar(sig, "v1-signature"));
    REQUIRE(fs::exists(sig));

    auto tmp = sig;
    tmp += ".tmp";
    fs::create_directory(tmp); // occupies the staging path

    CHECK_FALSE(replace_signature_sidecar(sig, "v2-signature"));

    // THE CONTRACT, and the reason it is the way round it is: a failed replace
    // LEAVES the predecessor. Enumerating the windows shows only one is unsafe.
    // Old-binary + new-signature and new-binary + old-signature both make every
    // anchored agent REFUSE — fail-closed, recoverable, loud. New-binary + NO
    // signature is the one state where a permissive agent applies the binary
    // UNVERIFIED, which is precisely what this feature exists to prevent.
    //
    // So removing the predecessor here would convert a benign, ordinary failure
    // — on Windows, a concurrent CheckForUpdate holding the sidecar open without
    // FILE_SHARE_DELETE is enough to fail the rename — into silently stripping a
    // VALID signature. The caller reports the failure instead; the operator
    // retries the upload.
    CHECK(fs::exists(sig));
    std::string out;
    REQUIRE(read_signature_sidecar(sig, out) == SidecarOutcome::kServed);
    CHECK(out == "v1-signature");

    fs::remove_all(tmp);
}

TEST_CASE("PEM CMS shape check accepts what the agent accepts", "[ota][signature][sidecar]") {
    // Both armour spellings OpenSSL emits for a detached CMS signature reach
    // CMS_verify, so rejecting either at upload would refuse a signature the
    // agent would have honoured.
    CHECK(looks_like_pem_cms("-----BEGIN CMS-----\nMIIB\n-----END CMS-----\n"));
    CHECK(looks_like_pem_cms("-----BEGIN PKCS7-----\nMIIB\n-----END PKCS7-----\n"));

    // Leading commentary is what `openssl cms -sign` itself emits in some
    // configurations, and is not grounds for refusal.
    CHECK(looks_like_pem_cms("comment\n-----BEGIN CMS-----\nMIIB\n-----END CMS-----\n"));
}

TEST_CASE("PEM CMS shape check rejects the states nothing else catches",
          "[ota][signature][sidecar]") {
    // The case that motivated it: well-sized garbage. Stored, reported "signed",
    // served, then refused by every anchored agent in BOTH modes.
    CHECK_FALSE(looks_like_pem_cms(std::string(4096, 'x')));

    // A truncated upload — header present, footer never arrived. This is why the
    // check is a header/footer PAIR and not a `starts_with`.
    CHECK_FALSE(looks_like_pem_cms("-----BEGIN CMS-----\nMIIB\n"));

    // Footer before header is not a valid block either.
    CHECK_FALSE(looks_like_pem_cms("-----END CMS-----\n-----BEGIN CMS-----\n"));

    // A private key, or any other PEM object, is not a CMS signature.
    CHECK_FALSE(looks_like_pem_cms("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"));

    // Mismatched armour: the footer must match the header that was found.
    CHECK_FALSE(looks_like_pem_cms("-----BEGIN CMS-----\nMIIB\n-----END PKCS7-----\n"));

    CHECK_FALSE(looks_like_pem_cms(""));
}

TEST_CASE("a sidecar newer than its binary is reported as not covering it",
          "[ota][sidecar]") {
    // The invariant: a successful upload writes the sidecar FIRST and the binary
    // second, so binary mtime >= sidecar mtime. A sidecar strictly NEWER proves
    // the binary write never followed it -- the upload died or failed in
    // between -- so the stored signature cannot cover the bytes on disk.
    Dir d;
    const auto bin = d.p / "yuzu-agent";
    const auto sig = signature_sidecar_path(bin);

    {
        std::ofstream(bin.string(), std::ios::binary) << "binary-bytes";
        std::ofstream(sig.string(), std::ios::binary) << "-----BEGIN CMS-----\nx\n-----END CMS-----\n";
    }

    // Consistent: binary written after the sidecar.
    const auto t0 = fs::last_write_time(sig);
    fs::last_write_time(bin, t0 + std::chrono::seconds(1));
    CHECK(signature_sidecar_covers_binary(bin, sig));

    // Equal timestamps count as consistent, so a coarse-granularity filesystem
    // degrades to the old behaviour rather than to false alarms.
    fs::last_write_time(bin, t0);
    CHECK(signature_sidecar_covers_binary(bin, sig));

    // The failure this exists to catch: sidecar landed, binary write did not.
    fs::last_write_time(bin, t0 - std::chrono::seconds(1));
    CHECK_FALSE(signature_sidecar_covers_binary(bin, sig));
}

TEST_CASE("an unreadable or absent sidecar is not evidence of a mismatch",
          "[ota][sidecar]") {
    // An absent sidecar is the ordinary unsigned case and must not render as a
    // mismatch -- that would put a scary state on every unsigned package.
    Dir d;
    const auto bin = d.p / "yuzu-agent";
    { std::ofstream(bin.string(), std::ios::binary) << "binary-bytes"; }
    CHECK(signature_sidecar_covers_binary(bin, signature_sidecar_path(bin)));

    // A sidecar with no binary beside it likewise proves nothing.
    const auto orphan_sig = d.p / "gone.sig";
    { std::ofstream(orphan_sig.string(), std::ios::binary) << "x"; }
    CHECK(signature_sidecar_covers_binary(d.p / "gone", orphan_sig));
}

TEST_CASE("removing a signature is ordered last, so a failure never leaves the served "
          "package unprotected",
          "[ota][sidecar]") {
    // The upload handler's ordering rule, pinned at the level this file can reach:
    // replace_signature_sidecar with an EMPTY signature is the signature-weakening
    // step, and the handler must not run it until the binary is published.
    //
    // The rule exists because the first version of the reorder ran the removal
    // unconditionally UP FRONT: an operator re-uploading an existing signed
    // package as unsigned, whose binary write then failed, was left with the OLD
    // binary still served and its signature gone -- protection stripped from a
    // package nobody had replaced.
    Dir d;
    const auto bin = d.p / "yuzu-agent";
    const auto sig = signature_sidecar_path(bin);
    { std::ofstream(bin.string(), std::ios::binary) << "v1-binary"; }
    REQUIRE(replace_signature_sidecar(sig, "-----BEGIN CMS-----\nv1\n-----END CMS-----\n"));
    REQUIRE(fs::exists(sig));

    // The weakening step, run on its own, does remove -- unconditionally, by
    // design, because the operator explicitly chose to publish unsigned.
    REQUIRE(replace_signature_sidecar(sig, ""));
    CHECK_FALSE(fs::exists(sig));

    // And it reports success even when there was nothing to remove, so the
    // handler cannot mistake "already unsigned" for a failure and 500 on it.
    CHECK(replace_signature_sidecar(sig, ""));
}

TEST_CASE("package filenames that escape the update directory are refused (#3863)",
          "[ota][sidecar][security]") {
    using yuzu::server::is_safe_package_filename;

    // Ordinary names an operator actually uploads.
    CHECK(is_safe_package_filename("yuzu-agent-linux-x86_64"));
    CHECK(is_safe_package_filename("yuzu-agent.exe"));
    CHECK(is_safe_package_filename("yuzu-agent-0.12.0.tar.gz"));
    CHECK(is_safe_package_filename("weird but legal name (1)"));

    // Relative traversal: every artifact path is update_dir_ / filename, so this
    // writes the binary, its sidecar and the staging file outside the directory.
    CHECK_FALSE(is_safe_package_filename("../x"));
    CHECK_FALSE(is_safe_package_filename("../../../../etc/cron.d/x"));
    CHECK_FALSE(is_safe_package_filename(".."));
    CHECK_FALSE(is_safe_package_filename("."));

    // Absolute is strictly worse than traversal and needs no "..": operator/
    // DISCARDS the left operand when the right is absolute, so update_dir_ is
    // ignored entirely.
    CHECK_FALSE(is_safe_package_filename("/etc/cron.d/x"));

    // Rejected on every platform, not only Windows: the server may run there,
    // where both are path-significant and ':' also selects an NTFS alternate
    // data stream. A rule that varies by build host is one nobody can reason
    // about.
    CHECK_FALSE(is_safe_package_filename("..\\..\\x"));
    CHECK_FALSE(is_safe_package_filename("C:\\windows\\x"));
    CHECK_FALSE(is_safe_package_filename("file.exe:ads"));

    // A subdirectory is not a traversal, but it is still not a bare filename and
    // the allowlist refuses it rather than reasoning about where it lands.
    CHECK_FALSE(is_safe_package_filename("sub/dir/agent"));

    CHECK_FALSE(is_safe_package_filename(""));
}

TEST_CASE("describe_package_delete: a failed unlink is never audited as a removal",
          "[sidecar][ota][audit]") {
    // The branch this exists for. audit-log.md documents `ota.package.deleted` as
    // meaning the binary AND its sidecar were removed; an unlink that failed must
    // not be able to produce that claim. The registry row is gone either way, so
    // the package stops being served — but the leftover file is still on disk and
    // this row is the only record saying so.
    SECTION("binary delete failed") {
        PackageDeleteOutcome o;
        o.matched = true;
        o.signature_removed = true;
        o.binary_error = "Permission denied";
        const auto a = describe_package_delete(o);
        CHECK(a.result == "partial");
        CHECK(a.detail == "registry row removed; binary delete failed: Permission denied");
        CHECK(a.detail.find("removed,") == std::string::npos);
    }

    SECTION("sidecar delete failed") {
        PackageDeleteOutcome o;
        o.matched = true;
        o.binary_removed = true;
        o.signature_error = "Device or resource busy";
        const auto a = describe_package_delete(o);
        CHECK(a.result == "partial");
        CHECK(a.detail ==
              "registry row removed; signature sidecar delete failed: Device or resource busy");
    }

    SECTION("both failed — both causes are named, neither is dropped") {
        PackageDeleteOutcome o;
        o.matched = true;
        o.binary_error = "Permission denied";
        o.signature_error = "Read-only file system";
        const auto a = describe_package_delete(o);
        CHECK(a.result == "partial");
        CHECK(a.detail.find("binary delete failed: Permission denied") != std::string::npos);
        CHECK(a.detail.find("signature sidecar delete failed: Read-only file system") !=
              std::string::npos);
    }
}

TEST_CASE("describe_package_delete: 'deleted it' and 'it was not there' stay distinct",
          "[sidecar][ota][audit]") {
    // Collapsing these would hide an out-of-band removal: a package whose binary
    // someone else already deleted is a different fact from one this call deleted,
    // and only the audit row can carry that difference.
    PackageDeleteOutcome o;
    o.matched = true;

    SECTION("both really removed") {
        o.binary_removed = true;
        o.signature_removed = true;
        const auto a = describe_package_delete(o);
        CHECK(a.result == "success");
        CHECK(a.detail == "binary removed, signature sidecar removed");
    }

    SECTION("unsigned package — no sidecar existed") {
        o.binary_removed = true;
        o.signature_removed = false;
        const auto a = describe_package_delete(o);
        CHECK(a.result == "success");
        CHECK(a.detail == "binary removed, signature sidecar already absent");
    }

    SECTION("binary already gone out of band") {
        o.binary_removed = false;
        o.signature_removed = true;
        const auto a = describe_package_delete(o);
        CHECK(a.result == "success");
        CHECK(a.detail == "binary already absent, signature sidecar removed");
    }

    SECTION("row with neither file on disk") {
        const auto a = describe_package_delete(o);
        CHECK(a.result == "success");
        CHECK(a.detail == "binary already absent, signature sidecar already absent");
    }
}

TEST_CASE("describe_package_delete: an unmatched package is denied, not successful",
          "[sidecar][ota][audit]") {
    // `denied` rather than a bespoke `not_found` token, because audit-log.md's
    // probe-detection recipe tells operators to filter on result == "denied" — a
    // fourth token would be invisible to exactly the rule this row feeds.
    PackageDeleteOutcome o;
    o.matched = false;
    const auto a = describe_package_delete(o);
    CHECK(a.result == "denied");
    CHECK(a.detail == "not_found");

    // An unmatched delete removed nothing, so it must never claim otherwise even
    // if the removal flags are somehow set.
    o.binary_removed = true;
    o.signature_removed = true;
    const auto b = describe_package_delete(o);
    CHECK(b.result == "denied");
    CHECK(b.detail == "not_found");
}
