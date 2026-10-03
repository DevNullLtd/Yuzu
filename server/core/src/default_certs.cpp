#include "default_certs.hpp"

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_session_advisory_lock.hpp"
#include "x509_ca.hpp"

#include <yuzu/secure_zero.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <random>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <cerrno>
#include <cstring> // strerror
#include <grp.h>   // getgrnam (--cert-group resolution)
#include <unistd.h> // gethostname, chown
#endif

namespace yuzu::server {

namespace fs = std::filesystem;

namespace {

// Apply the cross-container cert-sharing perms (PKI #1289). Default (empty group)
// keeps the tight single-host posture: dir 0700, keys 0600. When `cert_group` is
// set (a name or numeric gid that the server, gateway, AND agent users all belong
// to), the shared cert volume is opened up *just enough* for sibling containers:
//   - cert dir → 0750 + group=cert_group   (so a different-uid container can
//     TRAVERSE in; the server makes it 0700 by default, which blocks that)
//   - default-gateway.key → 0640 + group=cert_group  (the ONE shared private key:
//     the gateway runs as a different uid and must read its own leaf key)
// The CA cert + leaf certs are public (0644); the server/HTTPS private keys stay
// 0600 owner-only — never group-shared.
void apply_cert_group_share(const fs::path& dir, const DefaultCertSet& out,
                            const std::string& cert_group) {
    std::error_code ec;
    if (cert_group.empty()) {
        fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec); // 0700
        // True idempotency: if a prior boot ran with --cert-group, the gateway key
        // may still carry 0640. Re-tighten it to 0600 so dropping --cert-group fully
        // reverts the posture (the 0700 dir already blocks traversal, but be explicit).
        if (fs::exists(out.gateway_key))
            fs::permissions(out.gateway_key, fs::perms::owner_read | fs::perms::owner_write,
                            fs::perm_options::replace, ec); // 0600
        return;
    }
#ifndef _WIN32
    gid_t gid = static_cast<gid_t>(-1);
    char* end = nullptr;
    const long n = std::strtol(cert_group.c_str(), &end, 10);
    if (end && *end == '\0' && n >= 0) {
        gid = static_cast<gid_t>(n);
    } else if (const struct group* gr = ::getgrnam(cert_group.c_str())) {
        gid = gr->gr_gid;
    }
    if (gid == static_cast<gid_t>(-1)) {
        spdlog::warn("default_certs: --cert-group '{}' does not resolve to a group — leaving "
                     "tight 0700/0600 perms (a gateway/agent in another container will NOT be "
                     "able to read the shared certs)", cert_group);
        fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
        return;
    }
    // Chgrp BEFORE widening: never expose the dir to a group we have not
    // confirmed ownership of. On chgrp failure the dir stays 0700.
    if (::chown(dir.c_str(), static_cast<uid_t>(-1), gid) == 0) {
        fs::permissions(dir, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec,
                        fs::perm_options::replace, ec); // 0750
    } else {
        spdlog::warn("default_certs: chgrp '{}' on {} failed: {} — leaving 0700 (the server user "
                     "must be a member of that group to share it)", cert_group, dir.string(),
                     std::strerror(errno));
        fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec); // 0700
        return; // do not group-share the gateway key either if the dir chgrp failed
    }
    if (fs::exists(out.gateway_key)) {
        if (::chown(out.gateway_key.c_str(), static_cast<uid_t>(-1), gid) == 0)
            fs::permissions(out.gateway_key,
                            fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read,
                            fs::perm_options::replace, ec); // 0640
        else
            spdlog::warn("default_certs: chgrp on gateway key failed: {}", std::strerror(errno));
    }
    spdlog::info("default_certs: cert dir + gateway key shared with group '{}' (gid {}) for "
                 "multi-container TLS", cert_group, static_cast<unsigned long>(gid));
#else
    (void)out;
    spdlog::warn("default_certs: --cert-group is POSIX-only; ignored on Windows (use ACLs / a "
                 "shared service account). Leaving owner-only perms.");
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
#endif
}

constexpr int kMarkerVersion = 1;

int64_t to_epoch(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}
std::chrono::system_clock::time_point from_epoch(int64_t s) {
    return std::chrono::system_clock::time_point{std::chrono::seconds{s}};
}

std::string read_text_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in)
        return {};
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string rand_suffix() {
    std::random_device rd;
    static const char* kHex = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 4; ++i) {
        uint32_t v = rd();
        for (int j = 0; j < 8; ++j) {
            s += kHex[v & 0xF];
            v >>= 4;
        }
    }
    return s;
}

// Atomic write of a PUBLIC file (certs, marker) — stage to a sibling temp then
// rename. The artifact is set to a DETERMINISTIC 0644 (world-readable), NOT the
// umask default: the CA cert + leaf certs are public trust material (the CA cert
// is also served at GET /api/v1/ca/root), and under the secure-by-default
// multi-container deploy a different-uid agent/gateway container must be able to
// read the shared default-ca.pem. A strict server umask (e.g. 0077) would
// otherwise leave it 0600 and break CA auto-discovery even with --cert-group
// sharing the dir. The 0700/0750 dir still gates who can traverse to it, so 0644
// on the file never widens access beyond what the dir already allows. Private
// keys never come through here — they go through FileKeyProvider (0600).
bool write_public_file(const fs::path& dest, const std::string& contents) {
    std::error_code ec;
    const fs::path tmp = dest.parent_path() / (dest.filename().string() + ".tmp." + rand_suffix());
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            spdlog::error("default_certs: cannot open temp {}", tmp.string());
            return false;
        }
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        out.flush();
        if (!out) {
            spdlog::error("default_certs: write failed for {}", tmp.string());
            out.close();
            fs::remove(tmp, ec);
            return false;
        }
    }
    // Set perms on the temp BEFORE the rename so the destination is never briefly
    // visible at the umask default (and so the public bit is atomic with publish).
    fs::permissions(tmp,
                    fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                        fs::perms::others_read,
                    fs::perm_options::replace, ec); // 0644
    if (ec)
        spdlog::warn("default_certs: chmod 0644 on {} failed: {}", tmp.string(), ec.message());
    fs::rename(tmp, dest, ec);
    if (ec) {
        spdlog::error("default_certs: rename {} -> {} failed: {}", tmp.string(), dest.string(),
                      ec.message());
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool file_present(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p, ec) && !ec && fs::file_size(p, ec) > 0 && !ec;
}

// One server-side leaf to generate.
struct LeafSpec {
    const char* key_id;    // FileKeyProvider id -> <dir>/<key_id>.key
    const char* cert_file; // <dir>/<cert_file>
    const char* purpose;   // ca_store purpose + subject text
    pki::LeafUsage usage;
};

std::string join_san(const pki::SubjectAltNames& san) {
    std::string s;
    auto add = [&](const char* pfx, const std::vector<std::string>& v) {
        for (const auto& e : v) {
            if (!s.empty())
                s += ',';
            s += pfx;
            s += e;
        }
    };
    add("DNS:", san.dns);
    add("IP:", san.ips);
    add("URI:", san.uris);
    return s;
}

void fill_paths(const fs::path& dir, DefaultCertSet& out) {
    out.ca_cert = dir / "default-ca.pem";
    out.https_cert = dir / "default-https.pem";
    out.https_key = dir / "default-https.key";
    out.server_cert = dir / "default-server.pem";
    out.server_key = dir / "default-server.key";
    out.gateway_cert = dir / "default-gateway.pem";
    out.gateway_key = dir / "default-gateway.key";
}

bool all_files_present(const DefaultCertSet& s) {
    return file_present(s.ca_cert) && file_present(s.https_cert) && file_present(s.https_key) &&
           file_present(s.server_cert) && file_present(s.server_key) &&
           file_present(s.gateway_cert) && file_present(s.gateway_key);
}

// RAII: wipe key material on scope exit, INCLUDING exception unwind. ~std::string
// does not zero freed memory, so a throw mid-generation would otherwise leave the
// CA / leaf private key recoverable in freed heap.
struct KeyZeroGuard {
    std::string& s;
    explicit KeyZeroGuard(std::string& str) : s(str) {}
    ~KeyZeroGuard() { yuzu::secure_zero(s); }
    KeyZeroGuard(const KeyZeroGuard&) = delete;
    KeyZeroGuard& operator=(const KeyZeroGuard&) = delete;
};

// case-insensitive ASCII prefix test (no locale, no <cctype> surprises).
bool ci_prefix(std::string_view s, std::string_view pfx) {
    if (s.size() < pfx.size())
        return false;
    for (std::size_t i = 0; i < pfx.size(); ++i) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
        if (c != pfx[i])
            return false;
    }
    return true;
}

std::string_view trim_ws(std::string_view s) {
    auto ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && ws(s.front()))
        s.remove_prefix(1);
    while (!s.empty() && ws(s.back()))
        s.remove_suffix(1);
    return s;
}

bool has_control_char(std::string_view s) {
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f)
            return true;
    return false;
}

// Bounds on operator --cert-san input so a malformed/huge value (CLI or the
// YUZU_CERT_SAN env, which a deployment may template from a less-trusted source)
// cannot hang or balloon boot, and so each DNS name stays within RFC 1035 limits.
constexpr std::size_t kMaxExtraSans = 64;     // total accepted extra names
constexpr std::size_t kMaxRawEntryLen = 1024; // per raw --cert-san entry
constexpr std::size_t kMaxDnsNameLen = 253;   // RFC 1035 total
constexpr std::size_t kMaxDnsLabelLen = 63;   // RFC 1035 label

// Validate a dNSName SAN: non-empty, <=253 bytes, every dot-separated label
// non-empty and <=63 bytes, no leading/trailing dot, and a host-name charset
// (letters/digits/hyphen/underscore, plus '*' for a wildcard). The charset keeps
// genuine config mistakes (path-like '/', zone-id '%', whitespace, ':') out of
// the certificate rather than baking a never-matching SAN; IDNs are punycode
// (xn--…) so they remain ASCII-LDH. Wildcards are warned on by the caller.
bool valid_dns_name(std::string_view s) {
    if (s.empty() || s.size() > kMaxDnsNameLen)
        return false;
    std::size_t label = 0;
    for (char c : s) {
        if (c == '.') {
            if (label == 0)
                return false; // empty label (leading dot or "a..b")
            label = 0;
            continue;
        }
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '*';
        if (!ok)
            return false;
        if (++label > kMaxDnsLabelLen)
            return false;
    }
    return label != 0; // reject a trailing dot
}

// Parse operator --cert-san values into a validated, de-duplicated SAN set.
// Each raw entry may be comma-separated; each piece is "dns:<name>", "ip:<addr>",
// or a bare value classified IP-vs-DNS by pki::is_valid_ip_literal — the EXACT
// parser issue_leaf uses, so a value accepted here can never hard-fail cert
// generation (a typo'd IP is dropped, not boot-fatal). Invalid / over-bound /
// control-char / non-IP-"ip:" pieces are dropped with a warning; the total is
// capped. Returns only the extras (the base SAN set is merged separately).
pki::SubjectAltNames parse_extra_sans(const std::vector<std::string>& extra) {
    pki::SubjectAltNames out;
    std::size_t total = 0;
    auto push_unique = [](std::vector<std::string>& v, std::string val) -> bool {
        if (val.empty() || std::find(v.begin(), v.end(), val) != v.end())
            return false;
        v.push_back(std::move(val));
        return true;
    };
    auto add_dns = [&](std::string_view name) {
        std::string n(name);
        if (!valid_dns_name(n)) {
            spdlog::warn("default_certs: ignoring --cert-san DNS '{}' (empty/over-length/malformed)",
                         n);
            return;
        }
        if (n.find('*') != std::string::npos) {
            // #1271 UP-10/11: REJECT wildcards in default-cert SANs (was warn-only).
            // The install CA is distributed to every agent as a trust anchor, so a
            // wildcard leaf has real blast radius — a single stolen default-leaf key
            // would validate for an entire `*.<domain>`. An operator who genuinely
            // needs a wildcard must bring their own cert (`--https-cert` etc.).
            spdlog::warn("default_certs: REJECTING --cert-san DNS '{}' — wildcard SANs are not "
                         "allowed in fleet-trusted default certs; supply your own cert for a "
                         "wildcard",
                         n);
            return;
        }
        if (push_unique(out.dns, std::move(n)))
            ++total;
    };
    auto add_ip = [&](std::string_view addr) {
        std::string a(addr);
        if (!pki::is_valid_ip_literal(a)) {
            spdlog::warn("default_certs: ignoring --cert-san IP '{}' (not a valid IP literal)", a);
            return;
        }
        if (push_unique(out.ips, std::move(a)))
            ++total;
    };
    auto classify = [&](std::string_view piece) {
        piece = trim_ws(piece);
        if (piece.empty())
            return;
        if (has_control_char(piece)) {
            spdlog::warn("default_certs: ignoring --cert-san entry containing control characters");
            return;
        }
        if (ci_prefix(piece, "dns:")) {
            const std::string_view v = trim_ws(piece.substr(4));
            if (pki::is_valid_ip_literal(std::string(v)))
                spdlog::warn("default_certs: --cert-san 'dns:{}' is an IP literal — keeping it as a "
                             "DNS-type SAN as written; use 'ip:' for an iPAddress SAN",
                             std::string(v));
            add_dns(v);
        } else if (ci_prefix(piece, "ip:")) {
            add_ip(trim_ws(piece.substr(3)));
        } else if (pki::is_valid_ip_literal(std::string(piece))) {
            add_ip(piece);
        } else {
            add_dns(piece);
        }
    };
    // #1271 UP-9: the kMaxExtraSans cap counts only ACCEPTED names, so a flood of
    // INVALID entries (each warns + validates without ever incrementing `total`)
    // could CPU/log-flood at boot. Bound the total PIECES parsed (raw entries ×
    // comma-split) independently — generous headroom above kMaxExtraSans, then a
    // hard stop. Never boot-fatal (matches the drop-with-warning posture).
    constexpr std::size_t kMaxSanPieces = 512;
    std::size_t pieces_seen = 0;
    for (const auto& raw : extra) {
        if (total >= kMaxExtraSans) {
            spdlog::warn("default_certs: --cert-san capped at {} extra names — ignoring the rest",
                         kMaxExtraSans);
            break;
        }
        if (raw.size() > kMaxRawEntryLen) {
            spdlog::warn("default_certs: ignoring oversize --cert-san entry ({} bytes)", raw.size());
            continue;
        }
        std::string_view rv{raw};
        std::size_t start = 0;
        for (;;) {
            if (++pieces_seen > kMaxSanPieces) {
                spdlog::warn("default_certs: --cert-san piece limit ({}) reached — ignoring the "
                             "rest (invalid-entry flood guard)",
                             kMaxSanPieces);
                return out;
            }
            const std::size_t comma = rv.find(',', start);
            classify(rv.substr(
                start, comma == std::string_view::npos ? std::string_view::npos : comma - start));
            if (comma == std::string_view::npos || total >= kMaxExtraSans)
                break;
            start = comma + 1;
        }
    }
    return out;
}

// Merge validated extras into the base SAN set, de-duping against it.
void merge_sans(pki::SubjectAltNames& base, const pki::SubjectAltNames& extra) {
    for (const auto& d : extra.dns)
        if (std::find(base.dns.begin(), base.dns.end(), d) == base.dns.end())
            base.dns.push_back(d);
    for (const auto& i : extra.ips)
        if (std::find(base.ips.begin(), base.ips.end(), i) == base.ips.end())
            base.ips.push_back(i);
}

// Best-effort operator-footgun guard for the idempotent fast path: if --cert-san
// asks for names the EXISTING cert set does not carry, warn. Changing --cert-san
// deliberately does NOT auto-rotate (that would mint a new CA and break every
// enrolled agent's trust) — the operator must clear the dir to apply. DNS + IPv4
// only; IPv6 is skipped because the parsed-back form is uncompressed
// (e.g. "0:0:0:0:0:0:0:1"), so a literal compare would false-positive.
void warn_on_san_drift(const fs::path& representative_leaf,
                       const std::vector<std::string>& extra_sans) {
    const pki::SubjectAltNames want = parse_extra_sans(extra_sans);
    if (want.dns.empty() && want.ips.empty())
        return;
    const auto cert = pki::parse_certificate(read_text_file(representative_leaf));
    if (!cert)
        return;
    auto missing = [](const std::vector<std::string>& w, const std::vector<std::string>& have,
                      bool skip_ipv6) {
        std::vector<std::string> m;
        for (const auto& e : w) {
            if (skip_ipv6 && e.find(':') != std::string::npos)
                continue;
            if (std::find(have.begin(), have.end(), e) == have.end())
                m.push_back(e);
        }
        return m;
    };
    std::vector<std::string> miss = missing(want.dns, cert->san.dns, false);
    const std::vector<std::string> miss_ip = missing(want.ips, cert->san.ips, true);
    miss.insert(miss.end(), miss_ip.begin(), miss_ip.end());
    if (miss.empty())
        return;
    std::string joined;
    for (const auto& m : miss) {
        if (!joined.empty())
            joined += ", ";
        joined += m;
    }
    spdlog::warn("default_certs: --cert-san requests [{}] not present in the existing default certs "
                 "(they predate these SANs). Clear the cert directory to regenerate with them.",
                 joined);
}

// Forward-declared: defined further down alongside the rest of the bootstrap
// advisory-lock machinery it belongs with; referenced here first.
[[nodiscard]] bool lock_connection_alive(PGconn* conn);

// Shared tail for ensure_default_certs: purge stale default-cert inventory, mint
// the 3 default leaves under an ALREADY-ESTABLISHED root, and write the
// completion marker LAST (its presence is the "set is complete" signal). Two
// callers reach here, both having already proven exclusive ownership of
// `ca_cert_pem`/`ca_key_pem` before calling: (1) the normal first-boot path,
// having just won try_insert_root(); (2) the UP-2 same-instance resume path
// (Gate 4 unhappy-path, 2026-08-21), having proven via a local key-file match
// that THIS instance minted the root ca_store already holds. The purge below is
// safe in both cases for the same reason: whoever calls this function is the
// confirmed sole legitimate writer for "system:default-certs" going forward.
// `lock_conn`: the SAME connection holding the bootstrap advisory lock (null
// when there is no lock to verify — the no-ca_store local-only fallback).
// Re-checked with a real round-trip immediately before the marker write —
// see lock_connection_alive()'s doc comment for why (chaos-injector C5-1,
// Gate 5, 2026-08-21): a dead lock-holding connection releases the session
// lock silently, and nothing else on this path would ever notice.
[[nodiscard]] bool complete_default_cert_set(const fs::path& dir, const std::string& hostname,
                                             const std::vector<std::string>& extra_sans,
                                             const std::string& cert_group, CaStore* ca_store,
                                             FileKeyProvider& kp, const std::string& ca_cert_pem,
                                             const std::string& ca_key_pem, const std::string& ca_fp,
                                             const std::string& ca_key_id, const pki::CertDetails& ca_info,
                                             const fs::path& marker, DefaultCertSet& out,
                                             PGconn* lock_conn = nullptr) {
    if (ca_store) {
        // Best-effort / non-fatal: a failed purge leaves stale rows, not a
        // security or correctness defect (#1238 should-fix: don't silently
        // ignore the rc).
        if (!ca_store->delete_issued_by("system:default-certs"))
            spdlog::warn("default_certs: failed to purge prior default-cert inventory rows "
                         "(stale rows may remain) — continuing");
    }

    // Leaves are sized to the CA's exact notAfter so they never outlive the
    // issuer (the x509_ca leaf-<=-CA invariant would otherwise reject them).
    // #1302: backdate notBefore by the clock-skew allowance — mirrors the CA root
    // and the per-agent client leaf (sign_agent_csr, PR3 H-2). Without this, an
    // agent whose clock lags the server at first connect sees these freshly-minted
    // server leaves as not-yet-valid and rejects the TLS handshake, and the retry
    // paths don't recover a "valid cert, skewed clock" until the skew elapses.
    const pki::Validity leaf_validity{
        std::chrono::system_clock::now() - pki::kClockSkewBackdate, ca_info.not_after};

    pki::SubjectAltNames san;
    san.dns = {"localhost"};
    san.ips = {"127.0.0.1", "::1"};
    // An IP-literal hostname must go in the iPAddress SAN, not dNSName. The
    // detected hostname is gated through the SAME validation as operator extras
    // (a container gethostname() can return non-hostname bytes) — if it is
    // neither a valid IP nor a valid DNS name it is omitted with a warning rather
    // than baking a malformed SAN; localhost/loopback still cover local access.
    if (pki::is_valid_ip_literal(hostname))
        san.ips.push_back(hostname);
    else if (valid_dns_name(hostname))
        san.dns.push_back(hostname);
    else if (!hostname.empty())
        spdlog::warn("default_certs: host name '{}' is not a valid DNS name — omitting from the "
                     "default-cert SAN (use --cert-san to add a reachable name)",
                     hostname);
    // Operator --cert-san extend the SAME set on every default leaf. This mirrors
    // the base set above — localhost/loopback/hostname is itself identical across
    // all three leaves — so an extra grants nothing a stolen leaf key couldn't
    // already do (impersonation needs the 0600 key = host compromise; all three
    // are co-located, same-operator, same-CA server infra). Per-leaf scoping is a
    // possible future refinement, not a day-one need.
    merge_sans(san, parse_extra_sans(extra_sans));

    const std::array<LeafSpec, 3> leaves = {{
        {"default-https", "default-https.pem", "https", pki::LeafUsage{.server_auth = true}},
        // The server is a server to agents/gateway AND a client when it forwards
        // commands to the gateway's mgmt plane over mutual TLS (#1314), so its leaf
        // needs clientAuth too — otherwise a strict verifier rejects it as a client
        // cert and the mTLS command-forwarding dial fails.
        {"default-server", "default-server.pem", "server",
         pki::LeafUsage{.server_auth = true, .client_auth = true}},
        // The gateway is a server to agents AND a client to the server upstream.
        {"default-gateway", "default-gateway.pem", "gateway",
         pki::LeafUsage{.server_auth = true, .client_auth = true}},
    }};

    bool ok = write_public_file(out.ca_cert, ca_cert_pem);

    for (const auto& spec : leaves) {
        if (!ok)
            break;
        pki::LeafParams lp;
        lp.subject = {std::string("Yuzu Default ") + spec.purpose, "Yuzu"};
        lp.san = san;
        lp.validity = leaf_validity;
        lp.usage = spec.usage;
        auto kc = pki::issue_leaf(ca_cert_pem, ca_key_pem, pki::KeyAlgo::EcP256, lp);
        if (!kc) {
            ok = false;
            break;
        }
        KeyZeroGuard leaf_zero{kc->private_key_pem}; // exception-safe wipe
        ok = write_public_file(dir / spec.cert_file, kc->cert_pem);
        if (ok && !kp.store_key(spec.key_id, kc->private_key_pem)) {
            ok = false;
        }

        if (ok && ca_store) {
            IssuedCertRecord rec;
            rec.serial_hex = kc->serial_hex;
            rec.subject = lp.subject.common_name;
            rec.san = join_san(san);
            rec.purpose = spec.purpose;
            rec.not_after = to_epoch(ca_info.not_after);
            rec.cert_pem = kc->cert_pem;
            rec.issued_by = "system:default-certs";
            rec.issuer_fingerprint = ca_fp;
            rec.issuer_key_id = ca_key_id;
            if (auto rec_result = ca_store->record_issued(rec); !rec_result) {
                spdlog::error("default_certs: failed to record issued '{}' in ca_store — aborting "
                              "(the inventory must be consistent for revocation / rotation): {}",
                              spec.purpose, rec_result.error());
                ok = false;
            }
        }
    }

    if (!ok) {
        spdlog::error("default_certs: generation failed; leaving no marker (will retry next boot)");
        return false;
    }

    // Fencing check (chaos-injector C5-1, Gate 5, 2026-08-21): every write
    // above is done, but if THIS lock-holding connection died partway through
    // (pg_terminate_backend, an idle-session reap, a network blackhole to
    // just this socket) Postgres already released the session advisory lock
    // — silently, with no error from any of the calls above, since they each
    // draw their OWN fresh per-call lease from the pool rather than reusing
    // this connection. A sibling racer could already be mid-flight on its own
    // concurrent attempt right now. Refuse to write the marker (the "this set
    // is trustworthy" signal) if we can no longer prove we still hold the
    // lock — the next boot (or the sibling that's likely already running)
    // retries cleanly; writing the marker here would falsely vouch for a
    // possibly-torn result.
    if (lock_conn && !lock_connection_alive(lock_conn)) {
        spdlog::error("default_certs: lock-holding connection died mid-critical-section — this "
                      "attempt's result cannot be trusted, leaving no marker (will retry next "
                      "boot)");
        return false;
    }

    // Marker LAST — its presence is the "set is complete" signal.
    nlohmann::json j;
    j["version"] = kMarkerVersion;
    j["generated_at"] = to_epoch(std::chrono::system_clock::now());
    j["ca_fingerprint"] = ca_fp;
    j["expires_at"] = to_epoch(ca_info.not_after);
    j["hostname"] = hostname;
    if (!write_public_file(marker, j.dump(2))) {
        spdlog::error("default_certs: failed to write marker");
        return false;
    }

    out.ca_fingerprint_sha256 = ca_fp;
    out.ca_expires_at = ca_info.not_after;
    out.freshly_generated = true;
    // Now that the full set (incl. default-gateway.key) exists, apply the
    // cross-container sharing perms (no-op tight perms when --cert-group is unset).
    apply_cert_group_share(dir, out, cert_group);
    spdlog::warn("default_certs: generated default cert set — CA {} expires {}",
                 out.ca_fingerprint_sha256, to_epoch(ca_info.not_after));
    return true;
}

// The idempotent fast path, extracted so it can ALSO be used as the bootstrap
// lock's re-validation check (UP-2 Gate 8 fix, 2026-08-21): a caller that just
// won the lock must re-check whether a concurrent sibling already finished
// this exact work while it waited, rather than unconditionally purging and
// re-minting over a sibling's just-completed, now-live set. Returns true
// (and populates `out`) iff a complete, currently-valid set already exists on
// disk; false means the caller should proceed to generate.
[[nodiscard]] bool try_use_existing_complete_set(const fs::path& dir, const fs::path& marker,
                                                 const std::string& hostname,
                                                 const std::vector<std::string>& extra_sans,
                                                 const std::string& cert_group, DefaultCertSet& out) {
    if (!(file_present(marker) && all_files_present(out)))
        return false;
    const std::string marker_text = read_text_file(marker);
    try {
        const auto j = nlohmann::json::parse(marker_text);
        if (j.value("version", 0) != kMarkerVersion)
            return false;
        const std::string expected_fp = j.value("ca_fingerprint", "");
        const std::string ca_pem = read_text_file(out.ca_cert);
        auto fp = pki::fingerprint_sha256(ca_pem);
        if (!fp || *fp != expected_fp || expected_fp.empty()) {
            spdlog::warn("default_certs: marker/CA fingerprint mismatch — regenerating");
            return false;
        }
        // Beyond file-exists+size: confirm every leaf still chains to this CA
        // (catches a corrupt/substituted leaf) AND that the CA is CURRENTLY
        // valid. The validity check self-heals a set minted under a skewed
        // clock — e.g. clock ahead at first boot yields a not-yet-valid CA;
        // once the clock is corrected the next boot regenerates rather than
        // serving an unusable (or expired) cert.
        const bool leaves_ok = pki::verify_chain(read_text_file(out.https_cert), ca_pem) &&
                               pki::verify_chain(read_text_file(out.server_cert), ca_pem) &&
                               pki::verify_chain(read_text_file(out.gateway_cert), ca_pem);
        // Chain-verify alone does NOT catch a cert paired with the WRONG key
        // for its own purpose — a corrupted-pairing class the chain check is
        // blind to (chaos-injector C5-1, Gate 5, 2026-08-21): if the bootstrap
        // advisory lock's holding connection ever died mid-critical-section
        // (mitigated, not made impossible, by the fencing check in
        // complete_default_cert_set()) a sibling racer could interleave
        // writes and leave one purpose's cert from one racer paired with its
        // key from the other — both individually valid, chaining fine, but
        // mismatched. This is the ONLY thing standing between that corruption
        // and it validating as intact forever, so it must self-heal on the
        // very next boot rather than depend solely on prevention.
        // Deliberately non-const (cpp-safety, Gate 8, 2026-08-21): a `const auto`
        // here is a genuinely const-qualified automatic object, so wiping it via
        // a `const_cast`-obtained reference in KeyZeroGuard would be UB under
        // [dcl.type.cv]/4 — writing through a non-const reference to an object
        // that is actually const, not the "const ref to a non-const object" case
        // that would be fine. Matches this file's own established idiom
        // (`KeyZeroGuard leaf_zero{kc->private_key_pem}` above, `ca_zero`
        // elsewhere) — neither casts.
        auto https_key = read_text_file(out.https_key);
        auto server_key = read_text_file(out.server_key);
        auto gateway_key = read_text_file(out.gateway_key);
        KeyZeroGuard https_key_zero{https_key};
        KeyZeroGuard server_key_zero{server_key};
        KeyZeroGuard gateway_key_zero{gateway_key};
        const bool keys_paired =
            pki::cert_matches_key(read_text_file(out.https_cert), https_key) &&
            pki::cert_matches_key(read_text_file(out.server_cert), server_key) &&
            pki::cert_matches_key(read_text_file(out.gateway_cert), gateway_key);
        auto ca_info = pki::parse_certificate(ca_pem);
        const auto now = std::chrono::system_clock::now();
        const bool ca_valid_now =
            ca_info && ca_info->not_before <= now && now < ca_info->not_after;
        if (!leaves_ok || !keys_paired || !ca_valid_now) {
            spdlog::warn("default_certs: existing default certs unusable ({}) — regenerating",
                         !leaves_ok  ? "a leaf no longer chains to the CA"
                         : !keys_paired ? "a leaf cert/key pair no longer matches"
                                        : "CA not currently valid (clock skew?)");
            return false;
        }
        out.ca_fingerprint_sha256 = *fp;
        out.ca_expires_at = from_epoch(j.value("expires_at", int64_t{0}));
        out.freshly_generated = false;
        spdlog::info("default_certs: existing default cert set is intact (CA {}, dir {})",
                     out.ca_fingerprint_sha256, dir.string());
        // Tell the operator if --cert-san now asks for names the existing
        // certs don't carry (we never auto-rotate).
        warn_on_san_drift(out.gateway_cert, extra_sans);
        // Re-assert the cert-sharing perms on the existing set so a restart
        // (or a --cert-group added after first boot) is consistent — idempotent.
        apply_cert_group_share(dir, out, cert_group);
        return true;
    } catch (const std::exception& e) {
        spdlog::warn("default_certs: marker parse failed ({}) — regenerating", e.what());
        return false;
    }
}

// UP-2 Gate 8 fix (2026-08-21, security-guardian + unhappy-path): both
// complete_default_cert_set() callers — the normal winning-the-root-race path
// AND the B-2 self-heal resume path below — must run under mutual exclusion.
// The self-heal ownership proof (local key resolves + cryptographically pairs
// with the stored root) proves this instance MINTED the root, but is a static
// predicate every process sharing the same cert directory satisfies
// IDENTICALLY — it is not a claim/CAS, so it cannot by itself prevent two
// instances (e.g. two HA replicas restarting against one shared volume, or a
// self-heal resumer racing the ORIGINAL instance which was merely slow, not
// actually dead) from both reaching complete_default_cert_set() concurrently
// and corrupting the on-disk set (mismatched cert/key pairs from
// unsynchronized per-file renames; a purge deleting a sibling's
// just-recorded rows). The normal winning path is already serialized by
// try_insert_root()'s Postgres CAS — a losing fresh-CA attempt never reaches
// complete_default_cert_set() at all — but is wrapped in the SAME lock here
// too, both for the 3-instance interleaving above and so there is exactly one
// mutual-exclusion mechanism to reason about, not two.
//
// Mirrors kek_op_lock.hpp's non-blocking try-lock + confirmed-acquired guard
// pattern (the ONE reusable session-advisory-lock idiom in this codebase,
// PgSessionAdvisoryLockGuard) rather than hand-rolling a new one — but RETRIES
// (bounded) instead of KEK's immediate-Conflict-report, since this is a
// one-shot boot-time operation where briefly waiting for a sibling to finish
// is preferable to failing the boot outright.
//
// cpp-safety NOTE (Gate 8, 2026-08-21): complete_default_cert_set_locked()
// holds its own pool::Lease for the ENTIRE critical section, while
// complete_default_cert_set() (called from inside it) makes its OWN nested
// try_acquire_for calls via CaStore's per-call leasing on the SAME pool
// (delete_issued_by + up to 3x record_issued). A single racing instance needs
// 2 simultaneous connections (its own outer lease + one nested call at a
// time); an N-way race needs N outer leases (one per racer, held idle by
// every non-lock-holder while it retries) + 1 more for whichever racer
// currently holds the lock and is doing nested work. --postgres-pool-size
// must stay comfortably above the realistic number of instances that could
// share one --ca-dir + ca_store concurrently (2-3 for ordinary HA topologies
// → pool size >= 4-5 with margin) — the default (16) is nowhere near this
// floor. At --postgres-pool-size=1 specifically this is NOT merely "self-
// contends under a race": the outer lease permanently holds the pool's only
// connection, so EVERY nested call must time out — a deterministic failure
// on every boot that needs default-cert generation, with zero racers
// required (unhappy-path, Gate 8 narrow re-verify, 2026-08-21). It fails
// CLOSED and LOUDLY either way (a nested acquire timeout surfaces as a normal
// record_issued failure → "Refusing to start"; a delete_issued_by failure is
// only logged — the purge is best-effort), never a
// hang or silent corruption — so this is a documented constraint, not a
// defect requiring a code fix.
constexpr std::chrono::milliseconds kBootstrapLockAcquireTimeout{5000};
constexpr std::chrono::milliseconds kBootstrapLockRetryInterval{100};

// UP-3 (consistency-auditor, Gate 4, 2026-08-21; built on operator request in a
// later round): a losing HA replica used to discard its own material and
// return false unconditionally, needing a full process restart to pick up
// the winner's certs from the shared cert directory. Poll for the winner's
// complete set to land instead, bounded so a genuinely stuck/absent winner
// still falls back to today's refuse-and-restart behaviour rather than
// hanging boot indefinitely. The window is sized around
// kBootstrapLockAcquireTimeout (the winner's own lock-acquire budget) plus
// slack for actual cert generation + the 3 record_issued round-trips — NOT a
// tight bound, since a boot that's going to succeed anyway losing a few extra
// seconds to self-heal is a better trade than an avoidable restart.
constexpr std::chrono::milliseconds kLoserSelfHealPollWindow{15000};
constexpr std::chrono::milliseconds kLoserSelfHealPollInterval{250};

const pg::PgAdvisoryLockKey& default_certs_bootstrap_lock_key() {
    static const pg::PgAdvisoryLockKey key =
        pg::PgAdvisoryLockKey::single("hashtextextended('yuzu:default_certs_bootstrap', 0)");
    return key;
}

enum class BootstrapLockAttempt { kAcquired, kConflict, kError };

[[nodiscard]] BootstrapLockAttempt try_lock_default_certs_bootstrap(PGconn* conn) {
    const std::string sql = default_certs_bootstrap_lock_key().try_lock_sql();
    pg::PgResult res{PQexec(conn, sql.c_str())};
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("default_certs: bootstrap advisory-lock attempt failed: {}",
                      PQerrorMessage(conn));
        return BootstrapLockAttempt::kError;
    }
    // Guard the row read by construction, not by assumption (mirrors
    // try_lock_kek_op's own defensive shape) — PQgetvalue returns nullptr
    // out-of-range, so a future SQL edit would otherwise null-deref here.
    if (PQntuples(res.get()) != 1 || PQgetisnull(res.get(), 0, 0)) {
        spdlog::error("default_certs: bootstrap advisory-lock attempt returned an unexpected "
                      "result shape");
        return BootstrapLockAttempt::kError;
    }
    return (PQgetvalue(res.get(), 0, 0)[0] == 't') ? BootstrapLockAttempt::kAcquired
                                                    : BootstrapLockAttempt::kConflict;
}

// Fencing-token gap (chaos-injector, Gate 5, 2026-08-21): holding the
// bootstrap advisory lock is only as good as the SESSION it's held on still
// being alive. Postgres releases a session advisory lock the moment that
// session ends — if THIS connection dies mid-critical-section
// (pg_terminate_backend, an idle_session_timeout, a network blackhole to
// just this one socket) while the rest of the process keeps running on its
// other, healthy per-call leases, nothing before this point would notice: a
// sibling racer's retry loop acquires the now-free lock and starts its own
// purge-and-regenerate concurrently with THIS attempt's still-in-flight
// writes — reopening the exact corruption Finding A's lock exists to
// prevent, via a broader trigger than "two processes racing at boot." A real
// round-trip, not PQstatus alone (stale until the next I/O) and not
// re-issuing pg_try_advisory_lock (re-entrant on the same connection — would
// falsely reconfirm exclusivity while silently incrementing the hold count,
// never proving liveness).
[[nodiscard]] bool lock_connection_alive(PGconn* conn) {
    if (!conn || PQstatus(conn) != CONNECTION_OK)
        return false;
    pg::PgResult res{PQexec(conn, "SELECT 1")};
    return res.status() == PGRES_TUPLES_OK;
}

class DefaultCertsBootstrapLockGuard {
public:
    // Construct only after a `kAcquired` result — mirrors KekOpLockGuard.
    // Declare AFTER the pool `Lease` in the same scope so it destructs
    // (releases) BEFORE the lease returns the connection to the pool: a
    // session advisory lock outlives the statement, so releasing it here is
    // the only way to unlock at all.
    //
    // Deliberately NOT `noexcept` — same reason as KekOpLockGuard's identical
    // constructor (`kek_op_lock.hpp`): `inner_`'s mem-initializer heap-allocates
    // a fresh unlock-SQL string, so this can throw `bad_alloc`. Cpp-safety
    // review (Gate 8, 2026-08-21) confirmed the resulting window — the lock is
    // genuinely held at the DB before this constructor finishes, so a throw
    // here leaks the session lock until the pooled connection is eventually
    // discarded — already exists identically in the shipped `KekOpLockGuard`;
    // this is a faithful mirror of that accepted precedent, not a new gap. If
    // this is ever hardened, harden both consumers together.
    explicit DefaultCertsBootstrapLockGuard(PGconn* conn)
        : inner_(conn, default_certs_bootstrap_lock_key(), "default_certs bootstrap") {}
    DefaultCertsBootstrapLockGuard(const DefaultCertsBootstrapLockGuard&) = delete;
    DefaultCertsBootstrapLockGuard& operator=(const DefaultCertsBootstrapLockGuard&) = delete;
    DefaultCertsBootstrapLockGuard(DefaultCertsBootstrapLockGuard&&) = delete;
    DefaultCertsBootstrapLockGuard& operator=(DefaultCertsBootstrapLockGuard&&) = delete;

private:
    pg::PgSessionAdvisoryLockGuard inner_;
};

// Acquire the bootstrap lock (bounded retry on Conflict), re-validate inside
// it (a sibling may have JUST finished), and only then purge + regenerate.
// `pool` is the SAME pg::PgPool `ca_store` borrows (CaStore::pool()) — a
// SEPARATE lease from ca_store's own per-call leasing, held for exactly the
// duration of the critical section, matching KekOpLockGuard's precedent.
[[nodiscard]] bool complete_default_cert_set_locked(pg::PgPool& pool, const fs::path& dir,
                                                    const fs::path& marker,
                                                    const std::string& hostname,
                                                    const std::vector<std::string>& extra_sans,
                                                    const std::string& cert_group, CaStore* ca_store,
                                                    FileKeyProvider& kp, const std::string& ca_cert_pem,
                                                    const std::string& ca_key_pem, const std::string& ca_fp,
                                                    const std::string& ca_key_id, const pki::CertDetails& ca_info,
                                                    DefaultCertSet& out) {
    auto lease = pool.try_acquire_for(kBootstrapLockAcquireTimeout);
    if (!lease) {
        spdlog::error("default_certs: could not acquire a database connection to take the "
                      "bootstrap advisory lock — aborting this attempt (will retry next boot)");
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + kBootstrapLockAcquireTimeout;
    BootstrapLockAttempt attempt;
    for (;;) {
        attempt = try_lock_default_certs_bootstrap(lease.get());
        if (attempt != BootstrapLockAttempt::kConflict)
            break;
        if (std::chrono::steady_clock::now() >= deadline)
            break;
        std::this_thread::sleep_for(kBootstrapLockRetryInterval);
    }
    if (attempt == BootstrapLockAttempt::kError) {
        spdlog::error("default_certs: bootstrap advisory-lock attempt failed — aborting this "
                      "attempt (will retry next boot)");
        return false;
    }
    if (attempt == BootstrapLockAttempt::kConflict) {
        spdlog::error("default_certs: another instance is completing default-cert bootstrap "
                      "concurrently and did not finish within {}ms — aborting this attempt "
                      "(will retry next boot)",
                      static_cast<long long>(kBootstrapLockAcquireTimeout.count()));
        return false;
    }
    DefaultCertsBootstrapLockGuard guard{lease.get()};
    // Re-validate INSIDE the lock: a sibling may have completed this exact
    // work while we waited for the lock (or before we even asked). Without
    // this, an instance that legitimately lost a close race would still
    // unconditionally purge + re-mint over its sibling's just-completed,
    // now-live set.
    if (try_use_existing_complete_set(dir, marker, hostname, extra_sans, cert_group, out)) {
        spdlog::info("default_certs: a concurrent instance already completed the default-cert "
                     "set while this one waited for the bootstrap lock — using it, not "
                     "re-minting");
        return true;
    }
    return complete_default_cert_set(dir, hostname, extra_sans, cert_group, ca_store, kp,
                                     ca_cert_pem, ca_key_pem, ca_fp, ca_key_id, ca_info, marker,
                                     out, lease.get());
}

} // namespace

std::string detect_hostname() {
#ifdef _WIN32
    if (const char* c = std::getenv("COMPUTERNAME"); c && c[0])
        return std::string(c);
    return "localhost";
#else
    char buf[256] = {};
    if (::gethostname(buf, sizeof(buf) - 1) == 0 && buf[0])
        return std::string(buf);
    return "localhost";
#endif
}

bool ensure_default_certs(const fs::path& dir, const std::string& hostname, CaStore* ca_store,
                          DefaultCertSet& out, const std::vector<std::string>& extra_sans,
                          const std::string& cert_group) {
    fill_paths(dir, out);
    const fs::path marker = dir / "default-marker.json";

    // ── Idempotent fast path ──────────────────────────────────────────────────
    if (try_use_existing_complete_set(dir, marker, hostname, extra_sans, cert_group, out))
        return true;

    // ── B-2 (#1238): never silently re-root a populated CA ─────────────────────
    // We only reach here because the fast path found the on-disk default certs
    // missing / corrupt / mismatched. If ca_store STILL remembers a CA root,
    // generating a fresh one would set_root-REPLACE it and purge the issued
    // inventory — orphaning every agent already enrolled under the old root (their
    // leaves now chain to a dead CA). That is the dangerous quadrant the
    // corrupt-only self-heal above does NOT cover: a wiped cert dir against a
    // still-populated ca_store, or a botched restore. Refuse with an actionable
    // message; the operator restores the certs from backup (matching the ca_store
    // root) or performs a deliberate clean re-root (docs/pki-architecture.md
    // "Operator runbook" — clears ca_store.ca_root/ca_issued/ca_crl_versions
    // directly, ca.db has no bearing on this since ADR-0053). We refuse on ANY
    // existing root (not only a fingerprint mismatch): the regen path always mints
    // a brand-new CA, so proceeding would re-root regardless.
    if (ca_store && ca_store->is_open()) {
        // ADR-0036/ADR-0053: get_root() directly, NOT has_root() — this is the ONE call site
        // where a degraded read must NOT collapse to "no root". A DB blip misread as "no root"
        // here would let a fresh CA generation proceed and silently re-root a fleet that already
        // has one (the exact danger this guard exists to prevent).
        auto root_or_err = ca_store->get_root();
        if (!root_or_err) {
            spdlog::error("default_certs: cannot determine whether ca_store already holds a CA "
                          "root ({}) — refusing to regenerate. A fresh CA would re-root the fleet "
                          "if one already exists and this read simply failed to see it; resolve "
                          "the database error and retry.",
                          root_or_err.error());
            return false;
        }
        if (root_or_err->has_value()) {
            const auto& root = **root_or_err;

            // UP-2 self-heal (Gate 4 unhappy-path, 2026-08-21): reaches here any
            // time the on-disk leaf set is unusable (missing, corrupt, no
            // longer chains, or the CA isn't currently valid — see
            // try_use_existing_complete_set() above) while ca_store already
            // holds a root. This is NOT scoped to a first-boot crash window —
            // enterprise-readiness (Gate 6, 2026-08-21) correctly named it
            // broader: an ESTABLISHED, long-running install that later loses a
            // leaf file (a bad partial restore, a lost volume file) hits this
            // exact branch too. Before refusing outright, check whether THIS
            // instance is provably the one that minted the root: for
            // FileKeyProvider, key_ref IS the local file path (never shared
            // state — see the "Store the CA private key LOCALLY" comment
            // below), so if a key still resolves at that exact path AND its
            // private half cryptographically pairs with the stored root cert,
            // this instance has DIRECTORY ACCESS to the material that minted
            // the root — a wiped persistent volume or a botched restore leaves
            // no local key, or a mismatched one, and falls through to the
            // refusal unchanged. Resume completing the SAME root (re-mints the
            // server's own https/server/gateway leaves under it) rather than a
            // heavyweight clean re-root — safe regardless of WHEN in the
            // install's life this fires, because it never touches the root
            // itself or any agent-issued leaf.
            //
            // CORRECTED (Gate 8, 2026-08-21): this is directory access, NOT
            // instance identity — every process sharing this exact cert
            // directory passes the check identically, which is exactly why
            // complete_default_cert_set_locked() below serializes entry with a
            // Postgres advisory lock rather than treating this check alone as
            // sufficient mutual exclusion (unhappy-path Finding A named this
            // comment's original "no other instance could be the true owner"
            // phrasing specifically — that claim was false for a
            // shared-cert-volume topology). Multi-replica HA over one shared
            // ca_store is NOT an officially supported deployment shape (see
            // this ADR's Decision section) — the lock exists because the code
            // must stay safe if an operator does it anyway, and because a
            // self-heal resumer can race the ORIGINAL instance on a SINGLE
            // host too (merely slow, not actually dead), which needs no HA
            // topology at all (enterprise-readiness, Gate 6, 2026-08-21 —
            // corrected from an earlier round's "describes as supported"
            // overclaim, which contradicted this same ADR's own Decision
            // section).
            FileKeyProvider self_heal_kp(dir);
            if (self_heal_kp.has_key(root.key_ref)) {
                auto key_pem = self_heal_kp.load_key(root.key_ref);
                if (key_pem) {
                    // Wrap the guard immediately on acquisition, matching every
                    // other key-load in this file (ca_zero, leaf_zero) — Gate 8
                    // security-guardian NICE (2026-08-21): constructing it only
                    // after cert_matches_key succeeded left the present-but-WRONG
                    // key case (a stale/mistaken local key from a botched
                    // restore — real, not hypothetical) unwiped in freed heap.
                    KeyZeroGuard heal_zero{*key_pem};
                    if (pki::cert_matches_key(root.cert_pem, *key_pem)) {
                        auto ca_info = pki::parse_certificate(root.cert_pem);
                        if (!ca_info) {
                            spdlog::error(
                                "default_certs: self-heal aborted — the ca_store root cert this "
                                "instance owns the key for does not parse; falling back to the "
                                "manual-recovery refusal below");
                        } else {
                            spdlog::warn(
                                "default_certs: re-minting the default leaf set under the SAME "
                                "root (fingerprint {}) — the local CA key file still matches "
                                "ca_store's stored root (directory access, arbitrated under the "
                                "bootstrap lock, not a standalone ownership proof); the on-disk "
                                "set was missing/corrupt (a first-boot crash before completing, "
                                "or later damage to an established install — e.g. a lost leaf "
                                "file).",
                                root.fingerprint_sha256);
                            const std::string ca_key_id =
                                pki::issuer_key_id(root.cert_pem).value_or(std::string{});
                            // Gate 8 BLOCKING fix (security-guardian + unhappy-path,
                            // 2026-08-21): the ownership proof above is a static
                            // predicate every process sharing this cert directory
                            // satisfies identically — it does NOT by itself prevent
                            // two such instances (e.g. two HA replicas restarting
                            // against one shared volume) from both reaching here
                            // concurrently. Route through the bootstrap advisory
                            // lock, not complete_default_cert_set() directly.
                            return complete_default_cert_set_locked(
                                ca_store->pool(), dir, marker, hostname, extra_sans, cert_group,
                                ca_store, self_heal_kp, root.cert_pem, *key_pem,
                                root.fingerprint_sha256, ca_key_id, *ca_info, out);
                        }
                    }
                }
            }

            const std::string on_disk =
                file_present(out.ca_cert)
                    ? ("on-disk CA " +
                       pki::fingerprint_sha256(read_text_file(out.ca_cert)).value_or(std::string{"unreadable"}))
                    : std::string{"no on-disk CA cert"};
            spdlog::error(
                "default_certs: ca_store already holds a CA root ({}) but the on-disk default "
                "certs in {} are missing/corrupt ({}). Refusing to regenerate — a fresh CA "
                "would re-root the fleet and orphan every enrolled agent. Restore "
                "default-*.{{pem,key}} from backup (matching the ca_store root), or perform a "
                "deliberate clean re-root per docs/pki-architecture.md \"Operator runbook\".",
                root.fingerprint_sha256, dir.string(), on_disk);
            return false;
        }
    }

    // ── (Re)generate the whole set ────────────────────────────────────────────
    spdlog::warn("default_certs: generating a fresh per-install CA + default leaves in {}",
                 dir.string());

    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        spdlog::error("default_certs: cannot create {}: {}", dir.string(), ec.message());
        return false;
    }
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec); // 0700
    if (ec)
        spdlog::error("default_certs: could not set 0700 on {}: {} (keys stay 0600 regardless)",
                      dir.string(), ec.message());

    auto ca_key_pem = pki::generate_private_key(pki::KeyAlgo::EcP384);
    if (!ca_key_pem)
        return false;
    KeyZeroGuard ca_zero{*ca_key_pem}; // exception-safe wipe of the CA key

    pki::CaParams ca_params;
    ca_params.subject = {"Yuzu Install CA (" + hostname + ")", "Yuzu"};
    ca_params.validity = pki::validity_years_from_now(10);
    ca_params.path_len = 0;
    auto ca_cert_pem = pki::self_sign_ca(*ca_key_pem, ca_params);
    if (!ca_cert_pem)
        return false;

    auto ca_info = pki::parse_certificate(*ca_cert_pem);
    auto ca_fp = pki::fingerprint_sha256(*ca_cert_pem);
    if (!ca_info || !ca_fp)
        return false;
    // #1296: STABLE key-based CA identity stamped on every issued row so an
    // "issued by this CA" query survives a subordinate re-key. Best-effort: a
    // derivation miss leaves the field blank (the row stays serial-addressable).
    const std::string ca_key_id = pki::issuer_key_id(*ca_cert_pem).value_or(std::string{});

    FileKeyProvider kp(dir);
    // UP-3 (built on operator request, 2026-08-21): the CA private key is NOT
    // written to disk here, before the cross-replica root race resolves — only
    // its intended path is computed (path_for() is pure, no I/O). Multiple
    // simultaneous candidates in a shared-cert-dir topology (the only place
    // this race is reachable at all) would otherwise ALL speculatively write
    // to the SAME well-known "default-ca" path, and whichever write lands
    // LAST wins the file regardless of which candidate actually wins
    // try_insert_root's CAS below — silently detaching the established root
    // from its own real private key, permanently defeating every future
    // self-heal attempt for that root (found empirically: a 6-way race on one
    // shared TempDir hit this ~20% of the time before this fix). The actual
    // key write is deferred to AFTER this candidate is confirmed the sole
    // winner (below), by which point no other candidate can still be racing
    // for the same "default-ca" name.
    const std::string ca_key_ref = kp.path_for("default-ca").string();

    if (ca_store) {
        CaRoot root;
        root.cert_pem = *ca_cert_pem;
        root.key_ref = ca_key_ref;
        root.algo = "EcP384";
        root.not_before = to_epoch(ca_info->not_before);
        root.not_after = to_epoch(ca_info->not_after);
        root.fingerprint_sha256 = *ca_fp;
        root.mode = CaMode::Builtin;
        // ADR-0053 "Root-singleton first-boot race": try_insert_root(), NOT set_root() — a
        // shared Postgres substrate makes it possible for two instances to independently
        // generate root material and race to establish it (impossible under per-instance
        // SQLite, where this call used to be an unconditional INSERT OR REPLACE). ON CONFLICT
        // DO NOTHING means at most one caller's row is ever inserted; every caller reads back
        // whichever root is now canonical.
        //
        // RESOLVED HERE, BEFORE any leaf generation, disk writes, inventory purge, or
        // record_issued() call below (architect review, 2026-08-21 — moved from AFTER leaf
        // generation, where it originally sat). The prior ordering let two racing instances
        // BOTH pass this function's earlier B-2 empty-root check, then both proceed to purge
        // ("system:default-certs" is a shared, unscoped WHERE clause) and record their own
        // three leaf rows concurrently — the SECOND instance's purge could delete the FIRST
        // instance's already-committed, now-live leaf rows regardless of which one went on to
        // win the root race below, permanently orphaning the winner's certs from ca_store
        // (unrevocable, absent from any future CRL). Resolving the race FIRST means only the
        // confirmed winner ever reaches the purge/leaf/record_issued code past this point — a
        // losing instance returns immediately, having touched no shared ca_store state at all.
        auto established = ca_store->try_insert_root(root);
        if (!established) {
            spdlog::error("default_certs: failed to record CA root in ca_store — aborting: {}",
                          established.error());
            return false; // before the marker — next boot regenerates
        }
        if (established->fingerprint_sha256 != *ca_fp) {
            // Lost the race — another instance already established a DIFFERENT root. This
            // instance's freshly-generated key material is unusable (nobody else holds its
            // private key): never write it, or proceed as though it were authoritative, rather
            // than silently operating under, or clobbering, a root nobody else recognises.
            // Nothing shared has been touched — no leaf was generated, no ca_issued row was
            // written or purged.
            //
            // UP-3 self-heal (consistency-auditor, Gate 4; built on operator request): if
            // instances share one --ca-dir volume (the only topology where losing this race is
            // even possible), the winner is writing its OWN complete set to that SAME directory
            // concurrently. Poll for it rather than failing this boot outright —
            // try_use_existing_complete_set() only succeeds once the winner's marker (written
            // LAST, after every cert/key file) is present AND every file individually
            // chain-verifies and cert/key-pairs, so a partial/in-flight write is never adopted.
            // This instance holds no claim on the shared resource (it already lost), so no lock
            // is needed here — purely a passive reader.
            spdlog::warn(
                "default_certs: lost the first-boot CA-root race — ca_store already holds a "
                "DIFFERENT root (fingerprint {}) established by another instance. This "
                "instance's freshly generated CA (fingerprint {}) is discarded. Polling the "
                "shared cert directory ({}) for up to {}s for the winner to finish writing its "
                "own complete set before falling back to refusing boot.",
                established->fingerprint_sha256, *ca_fp, dir.string(),
                std::chrono::duration_cast<std::chrono::seconds>(kLoserSelfHealPollWindow).count());
            const auto deadline = std::chrono::steady_clock::now() + kLoserSelfHealPollWindow;
            do {
                std::this_thread::sleep_for(kLoserSelfHealPollInterval);
                if (try_use_existing_complete_set(dir, marker, hostname, extra_sans, cert_group,
                                                  out)) {
                    // cpp-safety (Gate 8 domain re-review, 2026-08-21): don't assume the set this
                    // just validated is necessarily THE root we lost the race to — cross-check
                    // explicitly rather than relying on an unstated invariant, since this adoption
                    // decision (and the log line below) both depend on it.
                    if (out.ca_fingerprint_sha256 != established->fingerprint_sha256) {
                        spdlog::warn(
                            "default_certs: a complete cert set appeared on {} but its CA "
                            "fingerprint ({}) does not match the root this instance lost the "
                            "race to ({}) — not adopting; continuing to poll.",
                            dir.string(), out.ca_fingerprint_sha256, established->fingerprint_sha256);
                        continue;
                    }
                    spdlog::warn(
                        "default_certs: self-healed onto the winning root (fingerprint {}) from "
                        "disk without a restart.",
                        established->fingerprint_sha256);
                    return true;
                }
            } while (std::chrono::steady_clock::now() < deadline);
            spdlog::error(
                "default_certs: lost the first-boot CA-root race and the winner's complete cert "
                "set never appeared on {} within {}s. This instance's freshly generated CA "
                "(fingerprint {}) remains discarded. If instances are meant to share one cert "
                "volume, restart this instance once the winner has finished; otherwise "
                "investigate why two instances raced first-boot generation concurrently.",
                dir.string(),
                std::chrono::duration_cast<std::chrono::seconds>(kLoserSelfHealPollWindow).count(),
                *ca_fp);
            // cpp-safety (closure re-verify of d54311fce, 2026-08-21): a fingerprint
            // mismatch above can leave `out` populated with a validated-but-wrong-root
            // set (try_use_existing_complete_set() writes it before this function gets
            // a chance to reject it) that then survives to this false return if the
            // poll window subsequently times out. Reset so `out` is never left holding
            // material for a root this instance did NOT adopt.
            out = DefaultCertSet{};
            return false;
        }
        // Won (or ca_store's root is uncontested single-instance) — the root race
        // above already confirmed this instance is the sole legitimate writer for
        // "system:default-certs" going forward; a losing instance never reaches
        // this line. complete_default_cert_set() does the purge + leaf generation
        // + marker write (shared with the UP-2 same-instance resume path above).
        //
        // UP-3: NOW safe to actually persist the CA key to the "default-ca" path
        // computed above — no other candidate can still be racing for this exact
        // name once try_insert_root's CAS has resolved in this candidate's
        // favor. Residual (rare, already-covered by the existing manual-recovery
        // runbook): if this specific write fails — a disk fault landing in the
        // narrow window between winning the CAS and persisting the key — ca_store
        // already holds this root with no local key resolving anywhere; the next
        // boot hits the ordinary "on-disk certs missing/corrupt, no local key
        // matches" refusal further up this function, the same recovery path any
        // other cause of local key loss already documents (restore from backup,
        // or a deliberate clean re-root).
        if (!kp.store_key("default-ca", *ca_key_pem)) {
            spdlog::error(
                "default_certs: won the first-boot CA-root race (fingerprint {}) but failed to "
                "persist the CA key locally at {} — ca_store now holds this root with no "
                "resolvable local key. Restore default-ca.key from backup, or perform a "
                "deliberate clean re-root per docs/pki-architecture.md \"Operator runbook\".",
                *ca_fp, ca_key_ref);
            return false;
        }
        // Still routed through the SAME bootstrap advisory lock as the self-heal
        // path (Gate 8 fix, 2026-08-21): this instance winning try_insert_root's
        // CAS only proves no OTHER instance is establishing a NEW root right
        // now — it says nothing about a self-heal resumer on another process
        // that believes (wrongly, if this instance is merely slow rather than
        // dead) it owns the SAME already-established root concurrently.
        return complete_default_cert_set_locked(ca_store->pool(), dir, marker, hostname,
                                                extra_sans, cert_group, ca_store, kp, *ca_cert_pem,
                                                *ca_key_pem, *ca_fp, ca_key_id, *ca_info, out);
    }

    // No ca_store (local-only / no-PG mode): no shared substrate means no
    // cross-instance race to defer the key write past — persist it directly.
    if (!kp.store_key("default-ca", *ca_key_pem)) {
        spdlog::error("default_certs: generation failed; leaving no marker (will retry next boot)");
        return false;
    }
    return complete_default_cert_set(dir, hostname, extra_sans, cert_group, ca_store, kp,
                                     *ca_cert_pem, *ca_key_pem, *ca_fp, ca_key_id, *ca_info,
                                     marker, out);
}

} // namespace yuzu::server
