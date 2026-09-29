#include "saml_provider.hpp"

#include <spdlog/spdlog.h>

#include <yuzu/secure_zero.hpp> // sanctioned std::string zeroizer — used on BOTH platform branches

// ──────────────────────────────────────────────────────────────────────────────
// Windows: compile stubs only — SAML is unsupported on Windows (N4).
// Never return success-without-verify; is_enabled() returns false so callers
// can gate on it and skip the SAML flow entirely.
// ──────────────────────────────────────────────────────────────────────────────
#if defined(_WIN32)

namespace yuzu::server::saml {

SamlProvider::SamlProvider(SamlConfig config) : config_(std::move(config)) {
    // Wipe any transit SP signing PEM even on the (never-constructed-in-prod)
    // Windows path, so a future Windows-port test that hands one in cannot leave
    // raw key bytes in the config_ member. (Hermes pass-2 LOW; wipe-on-all-paths)
    yuzu::secure_zero(config_.sp_signing_key_pem);
    spdlog::info("SamlProvider: SAML is not supported on Windows — provider disabled");
}

SamlProvider::~SamlProvider() = default;

bool SamlProvider::is_enabled() const {
    return false; // N4: always false on Windows
}

SamlProvider::AuthnRequestResult
SamlProvider::build_authn_request(const std::string& /*relay_state*/) {
    return {}; // url="" and cookie_secret="" — callers check url.empty()
}

bool SamlProvider::signing_configured_but_broken() const {
    return false; // N4: SP signing key is never parsed on Windows
}

const std::string& SamlProvider::signing_init_error() const {
    return signing_init_error_; // always empty on Windows
}

std::expected<SamlAssertion, std::string>
SamlProvider::validate_response(const std::string& /*saml_response_b64*/,
                                const std::string& /*cookie_secret*/) {
    // N4: must never silently succeed without verification
    return std::unexpected("SAML is not supported on this platform");
}

void SamlProvider::cleanup_expired_states() {}
void SamlProvider::cleanup_expired_states_locked() {}

} // namespace yuzu::server::saml

#else // !_WIN32 ───────────────────────────────────────────────────────────────

// Non-Windows: full xmlsec1 + libxml2 + zlib implementation.
// All platform-specific #include blocks are inside this guard (N4).

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace {

// ── SAML namespace constants ─────────────────────────────────────────────────

constexpr const char* kSamlAssertionNs  = "urn:oasis:names:tc:SAML:2.0:assertion";
constexpr const char* kSamlProtocolNs   = "urn:oasis:names:tc:SAML:2.0:protocol";
constexpr const char* kSamlSuccessCode  = "urn:oasis:names:tc:SAML:2.0:status:Success";
constexpr const char* kSamlBearerConf   = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
constexpr const char* kXmlDSigNs        = "http://www.w3.org/2000/09/xmldsig#";

/// Allow ±5 minutes clock skew for condition timestamp checks.
constexpr int64_t kClockSkewSeconds = 300;

// ── xmlsec1 global init (call_once) ──────────────────────────────────────────

// xmlSecInit / xmlSecOpenSSLInit are NOT thread-safe when called concurrently.
// Use std::call_once so the initialisation runs exactly once per process
// before any SamlProvider method is invoked on a request thread.
// Shutdown is intentionally omitted — xmlsec is long-lived for the process
// lifetime; resources are reclaimed at exit.

static std::once_flag g_xmlsec_init_flag;
static bool g_xmlsec_init_ok{false};

static void do_xmlsec_init() {
    xmlInitParser();

    if (xmlSecInit() < 0) {
        spdlog::error("SamlProvider: xmlSecInit failed");
        return;
    }
    if (xmlSecOpenSSLAppInit(nullptr) < 0) {
        spdlog::error("SamlProvider: xmlSecOpenSSLAppInit failed");
        return;
    }
    if (xmlSecOpenSSLInit() < 0) {
        spdlog::error("SamlProvider: xmlSecOpenSSLInit failed");
        return;
    }
    g_xmlsec_init_ok = true;
    spdlog::debug("SamlProvider: xmlsec1 initialized");
}

/// Call before any xmlsec operation. Throws on first-time failure.
static void ensure_xmlsec_initialized() {
    std::call_once(g_xmlsec_init_flag, do_xmlsec_init);
    if (!g_xmlsec_init_ok) {
        throw std::runtime_error("xmlsec1 initialization failed");
    }
}

// ── Standard base64 codec (not URL-safe) ────────────────────────────────────
// SAML POST binding uses standard base64 (+/= padding); HTTP-Redirect uses
// the same encoding before URL-encoding. Not base64url.

static std::string b64_encode(const unsigned char* data, std::size_t len) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        auto n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out += kAlphabet[(n >> 18) & 0x3F];
        out += kAlphabet[(n >> 12) & 0x3F];
        out += (i + 1 < len) ? kAlphabet[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? kAlphabet[n & 0x3F] : '=';
    }
    return out;
}

static std::string b64_decode(const std::string& input) {
    // clang-format off
    static constexpr unsigned char kT[256] = {
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64, // 0-15
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64, // 16-31
        64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63, // 32-47 (+/)
        52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64, // 48-63 (0-9)
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 64-79 (A-O)
        15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64, // 80-95 (P-Z)
        64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // 96-111 (a-o)
        41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64, // 112-127 (p-z)
        // 128-255: all 64 (invalid)
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,
    };
    // clang-format on
    std::string out;
    out.reserve(input.size() * 3 / 4);
    unsigned int val = 0;
    int bits = -8;
    for (unsigned char c : input) {
        if (kT[c] == 64) continue;
        val = (val << 6) | kT[c];
        bits += 6;
        if (bits >= 0) {
            out += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

// ── URL encoding ─────────────────────────────────────────────────────────────

static std::string url_encode(const std::string& value) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            oss << static_cast<char>(c);
        } else {
            oss << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
    }
    return oss.str();
}

// ── Random request ID ─────────────────────────────────────────────────────────

/// Returns "_" + 40 hex chars (160-bit random ID). Prefix '_' ensures a valid
/// XML ID (must start with letter or underscore per the XML ID production rule).
static std::string generate_request_id() {
    uint8_t buf[20];
    if (RAND_bytes(buf, static_cast<int>(sizeof(buf))) != 1) {
        throw std::runtime_error("RAND_bytes failed generating SAML request ID");
    }
    std::string id = "_";
    id.reserve(41);
    for (auto b : buf) {
        char hex[3];
        std::snprintf(hex, sizeof(hex), "%02x", b);
        id.append(hex, 2);
    }
    return id;
}

// ── SHA-256 helper (binding cookie hash) ─────────────────────────────────────

/// Returns the hex-encoded SHA-256 digest of the given input (UTF-8 bytes).
/// Throws on OpenSSL failure (should not happen with a correctly built OpenSSL).
static std::string sha256_hex(const std::string& input) {
    unsigned char digest[32] = {};
    unsigned int  len        = 32;
    EVP_MD_CTX*   ctx        = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA-256 digest failed (EVP)");
    }
    EVP_MD_CTX_free(ctx);
    std::string hex;
    hex.reserve(64);
    for (unsigned int i = 0; i < 32; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", digest[i]);
        hex.append(buf, 2);
    }
    return hex;
}

// ── RSA PKCS#1 v1.5 + SHA-256 signing (HTTP-Redirect binding AuthnRequest) ────

/// Returns the raw signature bytes over `octets`, or an empty vector on any
/// OpenSSL failure. Uses EXPLICIT RSA_PKCS1_PADDING — EVP_DigestSignInit with
/// EVP_sha256() alone does not itself pin the padding scheme, so the padding
/// is set on the derived EVP_PKEY_CTX before signing.
static std::vector<unsigned char> rsa_sha256_sign(EVP_PKEY* key, std::string_view octets) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    struct CtxGuard { EVP_MD_CTX* c; ~CtxGuard() { EVP_MD_CTX_free(c); } } guard{ctx};

    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), nullptr, key) != 1 || !pctx) {
        return {};
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
        return {};
    }
    if (EVP_DigestSignUpdate(ctx, octets.data(), octets.size()) != 1) {
        return {};
    }
    std::size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) != 1 || sig_len == 0) {
        return {};
    }
    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSignFinal(ctx, sig.data(), &sig_len) != 1) {
        return {};
    }
    sig.resize(sig_len);
    return sig;
}

/// Constant-time comparison of two SHA-256 hex strings. Length is compared
/// first (not secret — both operands are always fixed-length 64-char hex
/// digests in this file's callers), then OpenSSL's CRYPTO_memcmp compares
/// the equal-length byte ranges without early-exit-on-mismatch, so branch
/// timing does not leak how many leading bytes matched.
static bool constant_time_hex_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true; // both empty — nothing to compare
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

/// Generate a 256-bit (32-byte) CSPRNG secret encoded as 64 lowercase hex chars.
/// This is the raw value placed in the __Host-yuzu_saml_bind cookie; the server
/// stores SHA-256 of this value so the cookie itself is never retained server-side.
static std::string generate_cookie_secret() {
    uint8_t buf[32] = {};
    if (RAND_bytes(buf, static_cast<int>(sizeof(buf))) != 1) {
        throw std::runtime_error("RAND_bytes failed generating SAML binding secret");
    }
    std::string hex;
    hex.reserve(64);
    for (auto b : buf) {
        char h[3];
        std::snprintf(h, sizeof(h), "%02x", b);
        hex.append(h, 2);
    }
    return hex;
}

// ── ISO 8601 datetime parsing (UTC only) ──────────────────────────────────────

/// Parse "YYYY-MM-DDTHH:MM:SS[.frac]Z" → Unix epoch seconds.
/// Returns -1 on parse failure. Only Z (UTC) is accepted — no offset support.
static int64_t parse_iso8601(const char* s) {
    if (!s || !*s) return -1;
    struct tm tm = {};
    const char* p = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
    if (!p) return -1;
    if (*p == '.') { // skip optional fractional seconds
        while (*++p && (std::isdigit(static_cast<unsigned char>(*p)))) {}
    }
    if (*p != 'Z') return -1; // require UTC
    return static_cast<int64_t>(timegm(&tm));
}

// ── ISO 8601 IssueInstant formatter ──────────────────────────────────────────

static std::string format_issue_instant() {
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm utc = {};
    gmtime_r(&t, &utc);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buf;
}

// ── Raw-DEFLATE compress (HTTP-Redirect binding) ──────────────────────────────

static std::string deflate_raw(const std::string& input) {
    // windowBits = -15 → raw DEFLATE (no zlib header or gzip wrapper)
    z_stream zs{};
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("deflateInit2 failed");
    }
    zs.next_in  = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    zs.avail_in = static_cast<uInt>(input.size());
    std::string out(deflateBound(&zs, static_cast<uLong>(input.size())), '\0');
    zs.next_out  = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(out.size());
    int ret = deflate(&zs, Z_FINISH);
    deflateEnd(&zs);
    if (ret != Z_STREAM_END) throw std::runtime_error("deflate failed");
    out.resize(zs.total_out);
    return out;
}

// ── XML tree helpers ──────────────────────────────────────────────────────────

/// Find the first direct-child element with the given local name and namespace URI.
static xmlNodePtr find_child_ns(xmlNodePtr parent, const char* local, const char* ns) {
    for (xmlNodePtr n = xmlFirstElementChild(parent); n; n = xmlNextElementSibling(n)) {
        if (n->type == XML_ELEMENT_NODE &&
            n->name && xmlStrEqual(n->name, BAD_CAST local) &&
            n->ns   && n->ns->href && xmlStrEqual(n->ns->href, BAD_CAST ns)) {
            return n;
        }
    }
    return nullptr;
}

/// Get attribute value from a node (caller must NOT xmlFree the returned string).
static std::string get_attr(xmlNodePtr node, const char* attr) {
    xmlChar* v = xmlGetProp(node, BAD_CAST attr);
    if (!v) return {};
    std::string s(reinterpret_cast<const char*>(v));
    xmlFree(v);
    return s;
}

/// Get the text content of a node, whitespace-trimmed.
static std::string get_text(xmlNodePtr node) {
    xmlChar* c = xmlNodeGetContent(node);
    if (!c) return {};
    std::string s(reinterpret_cast<const char*>(c));
    xmlFree(c);
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

/// Extract group identifier values from the verified assertion's
/// <AttributeStatement>/<Attribute Name="group_attribute">/<AttributeValue>
/// text content.
///
/// SECURITY (N2 parity): reads ONLY from `assertion` — the SAME XSW-verified
/// node that name_id is read from in validate_response — never a second
/// XPath/search over the whole document. Callers MUST pass the single
/// verified assertion node, never `root` or any other document-wide handle.
///
/// SAML core permits more than one <AttributeStatement> and more than one
/// <Attribute> with the same Name; this walks all of them but ignores any
/// <Attribute> whose Name does not exactly equal `group_attribute`.
///
/// DoS guard: stops once kMaxGroupValues values have been collected, so an
/// attacker-signed or IdP-misconfigured assertion cannot force unbounded
/// allocation (the overall response is also already size- and depth-capped
/// upstream in validate_response).
///
/// @param cap_truncated  #1828.3 out-param — set true iff at least one more
///     non-empty group value existed past the kMax cap (detection is bounded
///     to exactly one extra element scanned per matching Attribute; never an
///     unbounded walk). nullptr is accepted for callers that don't care.
static std::vector<std::string> extract_group_values(xmlNodePtr assertion,
                                                       const std::string& group_attribute,
                                                       bool* cap_truncated = nullptr) {
    std::vector<std::string> groups;
    if (cap_truncated) *cap_truncated = false;
    if (group_attribute.empty()) return groups;

    constexpr std::size_t kMax = yuzu::server::saml::kMaxGroupValues;

    for (xmlNodePtr stmt = xmlFirstElementChild(assertion); stmt && groups.size() < kMax;
         stmt = xmlNextElementSibling(stmt)) {
        if (stmt->type != XML_ELEMENT_NODE || !stmt->name ||
            !xmlStrEqual(stmt->name, BAD_CAST "AttributeStatement") || !stmt->ns ||
            !stmt->ns->href || !xmlStrEqual(stmt->ns->href, BAD_CAST kSamlAssertionNs)) {
            continue;
        }
        for (xmlNodePtr attr = xmlFirstElementChild(stmt); attr && groups.size() < kMax;
             attr = xmlNextElementSibling(attr)) {
            if (attr->type != XML_ELEMENT_NODE || !attr->name ||
                !xmlStrEqual(attr->name, BAD_CAST "Attribute") || !attr->ns || !attr->ns->href ||
                !xmlStrEqual(attr->ns->href, BAD_CAST kSamlAssertionNs)) {
                continue;
            }
            if (get_attr(attr, "Name") != group_attribute) continue;
            // Deliberately NOT bounded by `groups.size() < kMax` here (unlike
            // the stmt/attr loops above) — once the cap is reached this loop
            // still needs to look at the NEXT value to tell "exactly kMax
            // values, no more" apart from "more values were dropped". The
            // scan still terminates in O(1) extra work: the first non-empty
            // value seen once the cap is already full sets cap_truncated and
            // breaks immediately, so at most one AttributeValue past the cap
            // is ever inspected.
            for (xmlNodePtr val = xmlFirstElementChild(attr); val;
                 val = xmlNextElementSibling(val)) {
                if (val->type != XML_ELEMENT_NODE || !val->name ||
                    !xmlStrEqual(val->name, BAD_CAST "AttributeValue") || !val->ns ||
                    !val->ns->href || !xmlStrEqual(val->ns->href, BAD_CAST kSamlAssertionNs)) {
                    continue;
                }
                // UP-8: skip empty/whitespace-only values — they can never
                // match a non-empty admin_group and would otherwise waste a
                // slot against the kMax DoS cap.
                std::string text = get_text(val);
                if (text.empty()) continue;
                if (groups.size() < kMax) {
                    groups.push_back(std::move(text));
                    continue;
                }
                if (cap_truncated) *cap_truncated = true;
                break;
            }
        }
    }
    return groups;
}

/// Max stored length of an IdP-attested display/email attribute value, and a
/// sanitiser applied at the parse boundary. These values are semi-trusted (a
/// compromised IdP, or an Entra/AD tenant where `displayName` is user-settable,
/// controls them) and flow to the operational log (spdlog), the dashboard, and
/// `/whoami`. An internal newline would let a value forge a second log record
/// (Gate 4 UP-1/2), and an unbounded value would be retained in the session and
/// logged in full (UP-3). So strip C0 controls (incl. `\n`/`\r`/`\t`) and DEL,
/// then clamp — WITHOUT splitting a UTF-8 multibyte sequence (a split byte would
/// be invalid UTF-8 and could break JSON serialisation of `/whoami`). Sanitise
/// ONCE here so every downstream sink is safe. Group values need no such
/// treatment: `extract_group_values` matches them by exact equality and only
/// ever counts them — they are never displayed or logged verbatim.
constexpr std::size_t kMaxAttributeValueLen = 256;

static std::string sanitize_attribute_value(std::string s) {
    std::erase_if(s, [](unsigned char c) { return c < 0x20 || c == 0x7F; });
    if (s.size() > kMaxAttributeValueLen) {
        std::size_t cut = kMaxAttributeValueLen;
        // Back up over UTF-8 continuation bytes (0b10xxxxxx) so the clamp lands
        // on a codepoint boundary, never mid-sequence.
        while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
        s.resize(cut);
    }
    return s;
}

/// Extract the FIRST non-empty `<AttributeValue>` text of the verified
/// assertion's `<AttributeStatement>/<Attribute Name="attr_name">`.
///
/// SECURITY (N2 parity): reads ONLY from `assertion` — the SAME XSW-verified
/// node `name_id` and the groups are read from — never a second XPath/search
/// over the document. Callers MUST pass the single verified assertion node,
/// never `root`. It reuses `extract_group_values`'s exact three-level,
/// namespace-checked descent so a new attribute cannot drift off the verified
/// subtree. Returns "" when `attr_name` is empty (feature off), the attribute
/// is absent, or it carries no non-empty value. Bounded by construction: it
/// stops at the first match, so there is no DoS-cap concern (a single scalar,
/// not an unbounded multi-value list like groups).
static std::string extract_first_attribute_value(xmlNodePtr assertion,
                                                  const std::string& attr_name) {
    if (attr_name.empty()) return {};

    for (xmlNodePtr stmt = xmlFirstElementChild(assertion); stmt;
         stmt = xmlNextElementSibling(stmt)) {
        if (stmt->type != XML_ELEMENT_NODE || !stmt->name ||
            !xmlStrEqual(stmt->name, BAD_CAST "AttributeStatement") || !stmt->ns ||
            !stmt->ns->href || !xmlStrEqual(stmt->ns->href, BAD_CAST kSamlAssertionNs)) {
            continue;
        }
        for (xmlNodePtr attr = xmlFirstElementChild(stmt); attr;
             attr = xmlNextElementSibling(attr)) {
            if (attr->type != XML_ELEMENT_NODE || !attr->name ||
                !xmlStrEqual(attr->name, BAD_CAST "Attribute") || !attr->ns || !attr->ns->href ||
                !xmlStrEqual(attr->ns->href, BAD_CAST kSamlAssertionNs)) {
                continue;
            }
            if (get_attr(attr, "Name") != attr_name) continue;
            for (xmlNodePtr val = xmlFirstElementChild(attr); val;
                 val = xmlNextElementSibling(val)) {
                if (val->type != XML_ELEMENT_NODE || !val->name ||
                    !xmlStrEqual(val->name, BAD_CAST "AttributeValue") || !val->ns ||
                    !val->ns->href || !xmlStrEqual(val->ns->href, BAD_CAST kSamlAssertionNs)) {
                    continue;
                }
                // Sanitise at the parse boundary (control chars stripped,
                // length clamped) so a newline can't forge a log record and a
                // huge value can't be retained/logged (Gate 4 UP-1/2/3). A
                // value that is empty AFTER sanitising (e.g. all control chars)
                // is skipped, exactly like an empty raw value.
                std::string text = sanitize_attribute_value(get_text(val));
                if (!text.empty()) return text; // first non-empty (sanitised) value wins
            }
        }
    }
    return {};
}

/// Maximum element-nesting depth we will traverse in the XSW walks. libxml2
/// already caps parse depth (XML_PARSE_HUGE is off → default 256), but we bound
/// our own recursion explicitly so these walks are provably stack-safe
/// regardless of future parser-flag changes, and a pathologically deep document
/// is rejected (fail-closed) rather than partially scanned. Legitimate SAML
/// responses nest well under 20 levels.
constexpr int kMaxXmlDepth = 100;

/// Collect ALL saml:Assertion elements at any depth below root into out.
/// Searching all depths catches wrapped/injected assertions for XSW detection.
/// Returns false if the document nests deeper than kMaxXmlDepth — the caller
/// MUST reject, because a truncated collection could undercount wrapped
/// assertions and weaken the exactly-one-Assertion XSW check.
static bool collect_assertions(xmlNodePtr node, std::vector<xmlNodePtr>& out,
                               int depth = 0) {
    if (depth > kMaxXmlDepth) return false;
    for (xmlNodePtr n = xmlFirstElementChild(node); n; n = xmlNextElementSibling(n)) {
        if (n->type == XML_ELEMENT_NODE &&
            n->name && xmlStrEqual(n->name, BAD_CAST "Assertion") &&
            n->ns   && n->ns->href &&
            xmlStrEqual(n->ns->href, BAD_CAST kSamlAssertionNs)) {
            out.push_back(n);
        }
        if (!collect_assertions(n, out, depth + 1)) return false; // recurse regardless
    }
    return true;
}

/// H-E: scan the subtree rooted at `node` (inclusive) for any element OTHER
/// than `exclude` that carries an "ID" or "xml:id" attribute whose value
/// equals `target_id`.  Returns true if such a decoy element is found.
///
/// Motivation: a crafted response may contain a non-Assertion element (e.g.
/// `<samlp:Extension ID="<assertionID>">`) whose attribute value matches the
/// signed Assertion's ID.  Even if the xmlsec Reference resolves correctly
/// (because we registered the Assertion's ID first), the presence of a second
/// node sharing that ID is a strong indicator of a XSW document and must be
/// rejected.
static bool has_duplicate_id(xmlNodePtr node, xmlNodePtr exclude,
                              const xmlChar* target_id, int depth = 0) {
    if (!node || !target_id) return false;
    if (depth > kMaxXmlDepth) return true;  // fail closed: too deep to scan → treat as suspicious
    if (node->type == XML_ELEMENT_NODE && node != exclude) {
        // Check "ID" attribute (plain, no namespace — standard SAML)
        xmlChar* id_val = xmlGetProp(node, BAD_CAST "ID");
        if (id_val) {
            const bool match = xmlStrEqual(id_val, target_id);
            xmlFree(id_val);
            if (match) return true;
        }
        // Check "xml:id" (explicit XML namespace per XML-Core spec)
        static constexpr const char* kXmlNs = "http://www.w3.org/XML/1998/namespace";
        xmlChar* xml_id = xmlGetNsProp(node, BAD_CAST "id", BAD_CAST kXmlNs);
        if (xml_id) {
            const bool match = xmlStrEqual(xml_id, target_id);
            xmlFree(xml_id);
            if (match) return true;
        }
    }
    for (xmlNodePtr c = xmlFirstElementChild(node); c; c = xmlNextElementSibling(c)) {
        if (has_duplicate_id(c, exclude, target_id, depth + 1)) return true;
    }
    return false;
}

} // anonymous namespace

// ── SamlProvider ─────────────────────────────────────────────────────────────

namespace yuzu::server::saml {

SamlProvider::SamlProvider(SamlConfig config) : config_(std::move(config)) {
    // Wipe + clear the transit PEM on EVERY ctor exit path — declared FIRST so it
    // also covers the !config_.enabled early-return and the xmlsec-init failure
    // path below (both skip the parse block) — so raw private-key bytes never
    // linger in the by-value config_ member. (security-guardian LOW / cpp-safety INFO)
    struct PemCleanser {
        std::string& pem;
        ~PemCleanser() { yuzu::secure_zero(pem); } // wipes + clears; no-op when empty
    } pem_cleanser{config_.sp_signing_key_pem};

    if (!config_.enabled) return;
    try {
        ensure_xmlsec_initialized();
        spdlog::info("SamlProvider: initialized (idp_entity_id={})", config_.idp_entity_id);
    } catch (const std::exception& e) {
        spdlog::error("SamlProvider: initialization failed: {} — disabling", e.what());
        config_.enabled = false;
    }

    // Parse the SP AuthnRequest signing key (if configured) exactly once, at
    // construction — never per-request. Configured-but-broken (malformed PEM,
    // or a non-RSA key) sets signing_init_failed_ rather than falling back to
    // unsigned; server.cpp checks signing_configured_but_broken() and disables
    // SAML loudly rather than shipping a silent unsigned fallback.
    if (config_.enabled && !config_.sp_signing_key_pem.empty()) {
        struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } };
        // static_cast<int> is safe only because server.cpp caps the key-file
        // read at kSamlCertMaxBytes (64 KiB) before populating this field, so
        // the size never approaches INT_MAX. (cpp-expert N1)
        BioGuard bio{BIO_new_mem_buf(config_.sp_signing_key_pem.data(),
                                     static_cast<int>(config_.sp_signing_key_pem.size()))};
        // Explicit no-op password callback (returns a zero-length password): a
        // passphrase-protected key then fails deterministically here instead of
        // falling back to OpenSSL's default callback, which prompts on /dev/tty
        // — hanging an interactive boot, misleading a headless one. (UP-1)
        auto no_password = [](char*, int, int, void*) -> int { return 0; };
        EVP_PKEY* raw_key = bio.b ? PEM_read_bio_PrivateKey(bio.b, nullptr, no_password, nullptr)
                                  : nullptr;
        if (!raw_key) {
            // Clear the thread-local OpenSSL error queue so our own parse failure
            // does not leak into unrelated later diagnostics. (Hermes pass-2 LOW)
            ERR_clear_error();
            signing_init_failed_ = true;
            signing_init_error_  = "SAML SP signing key: failed to parse PEM private key "
                                   "(an encrypted/passphrase-protected key is not supported; "
                                   "provide an unencrypted RSA private key)";
            spdlog::error("SamlProvider: {}", signing_init_error_);
        } else {
            std::shared_ptr<EVP_PKEY> parsed(raw_key, EVP_PKEY_free);
            const int base_id = EVP_PKEY_base_id(parsed.get());
            const int bits    = EVP_PKEY_bits(parsed.get());
            if (base_id != EVP_PKEY_RSA) {
                // Reject EC and RSA-PSS (base id EVP_PKEY_RSA_PSS) and anything
                // else — only plain RSA (PKCS#1 v1.5) is supported. `parsed`
                // destructs here (EVP_PKEY_free) — the rejected key is never retained.
                signing_init_failed_ = true;
                signing_init_error_  = "SAML SP signing key must be an RSA key";
                spdlog::error("SamlProvider: {} (EVP_PKEY base id={})", signing_init_error_,
                              base_id);
            } else if (bits < 2048 || bits > 16384) {
                // Floor: a sub-2048-bit RSA key is factorable, letting an attacker
                // forge AuthnRequests and defeat the SP->IdP signing binding.
                // Ceiling: an absurdly large key makes each per-request signature
                // pathologically slow — an amplification vector on the
                // unauthenticated /auth/saml/start. (Hermes HIGH + partial UP-3)
                signing_init_failed_ = true;
                signing_init_error_  = "SAML SP signing key size out of range "
                                       "(RSA modulus must be 2048-16384 bits)";
                spdlog::error("SamlProvider: {} ({} bits)", signing_init_error_, bits);
            } else {
                sp_signing_key_ = std::move(parsed);
                spdlog::info("SamlProvider: SP AuthnRequest signing enabled (RSA-{} key configured)",
                             bits);
            }
        }

        // The transit PEM is wiped + cleared by pem_cleanser on ctor exit
        // (declared above) on every path — never logged, never retained past
        // parse (config_ is a by-value member; the owned EVP_PKEY stays live).
    }
}

SamlProvider::~SamlProvider() = default;

bool SamlProvider::signing_configured_but_broken() const {
    return signing_init_failed_;
}

const std::string& SamlProvider::signing_init_error() const {
    return signing_init_error_;
}

bool SamlProvider::is_enabled() const {
    // H-F: Require all config fields that the flow and the Issuer/Audience/
    // Recipient checks depend on.  A provider constructed with an empty
    // entity-ID (e.g. in tests or via a partial config) must not be considered
    // enabled; that would allow the Issuer/Audience comparisons to succeed
    // against an empty string and weaken the validation.
    return config_.enabled &&
           !config_.idp_cert_pem.empty() &&
           !config_.idp_entity_id.empty() &&
           !config_.sp_entity_id.empty() &&
           !config_.sp_acs_url.empty() &&
           !config_.idp_sso_url.empty();
}

// ── build_authn_request ───────────────────────────────────────────────────────

SamlProvider::AuthnRequestResult
SamlProvider::build_authn_request(const std::string& relay_state) {
    if (!is_enabled()) return {};

    const auto request_id    = generate_request_id();
    const auto issue_instant = format_issue_instant();

    // Generate the per-request browser-binding secret.
    // We store the SHA-256 hash (not the raw secret) so a database/memory read
    // does not expose the value that would let an attacker forge the cookie.
    const auto cookie_secret = generate_cookie_secret();
    const auto binding_hash  = sha256_hex(cookie_secret);

    // Store the request ID so InResponseTo can be validated in validate_response.
    {
        std::lock_guard lock(mu_);
        cleanup_expired_states_locked();
        if (pending_requests_.size() >= kMaxPendingRequests) {
            // Evict the earliest-expiring entry under pressure.
            auto oldest = pending_requests_.begin();
            for (auto it = oldest; it != pending_requests_.end(); ++it) {
                if (it->second.expiry < oldest->second.expiry) oldest = it;
            }
            pending_requests_.erase(oldest);
        }
        pending_requests_[request_id] = {std::chrono::steady_clock::now() + kRequestTtl,
                                         binding_hash};
    }

    // AuthnRequest XML. Signed on the wire via the detached HTTP-Redirect
    // binding query-string signature below when an SP signing key is
    // configured (sp_signing_key_); otherwise unsigned (backward-compatible).
    // clang-format off
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<samlp:AuthnRequest"
          " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
          " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
          " ID=\""                           + request_id    + "\""
          " Version=\"2.0\""
          " IssueInstant=\""                 + issue_instant + "\""
          " Destination=\""                  + config_.idp_sso_url + "\""
          " AssertionConsumerServiceURL=\""  + config_.sp_acs_url  + "\">"
          "<saml:Issuer>"                    + config_.sp_entity_id + "</saml:Issuer>"
        "</samlp:AuthnRequest>";
    // clang-format on

    // HTTP-Redirect binding: raw-DEFLATE → standard base64 → URL-encode
    const auto compressed = deflate_raw(xml);
    const auto b64 = b64_encode(
        reinterpret_cast<const unsigned char*>(compressed.data()),
        compressed.size());
    const auto enc_req = url_encode(b64);

    std::string url;
    if (sp_signing_key_) {
        // HTTP-Redirect binding signing (SAML 2.0 core §3.4.4.1): the
        // signature is computed over the ALREADY percent-encoded,
        // '&'-joined query parameters in exactly this order —
        // SAMLRequest, RelayState (omitted entirely when empty, never
        // "RelayState="), SigAlg — with no leading '?' and no Signature
        // param. The signed bytes and the sent bytes must be byte-identical,
        // so `base` becomes the URL's query string verbatim.
        std::string base = "SAMLRequest=" + enc_req;
        if (!relay_state.empty()) base += "&RelayState=" + url_encode(relay_state);
        base += "&SigAlg=" + url_encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

        const auto sig = rsa_sha256_sign(sp_signing_key_.get(), base);
        if (sig.empty()) {
            // Per-request signing failure: never emit an unsigned redirect
            // when signing is configured — fail this request instead.
            spdlog::error("SamlProvider: AuthnRequest signing failed (id={})", request_id);
            return {};
        }
        const auto sig_b64 = b64_encode(sig.data(), sig.size());
        url = config_.idp_sso_url + "?" + base + "&Signature=" + url_encode(sig_b64);
    } else {
        url = config_.idp_sso_url + "?SAMLRequest=" + enc_req;
        if (!relay_state.empty()) url += "&RelayState=" + url_encode(relay_state);
    }

    spdlog::debug("SamlProvider: AuthnRequest id={} signed={}", request_id,
                  sp_signing_key_ != nullptr);
    return {std::move(url), cookie_secret};
}

// ── validate_response ─────────────────────────────────────────────────────────

std::expected<SamlAssertion, std::string>
SamlProvider::validate_response(const std::string& saml_response_b64,
                                const std::string& cookie_secret) {
    if (!is_enabled()) return std::unexpected("SAML provider is not enabled");

    // ── 1. Decode base64 ─────────────────────────────────────────────────────
    const std::string xml_bytes = b64_decode(saml_response_b64);
    if (xml_bytes.empty()) return std::unexpected("base64 decode produced empty result");

    // ── 1.5. Size guard — defence-in-depth against oversized documents ────────
    // The ACS route already rejects POST bodies > 1 MiB; this second check
    // protects any other caller path and prevents the static_cast<int>() below
    // from narrowing a > INT_MAX size (which would be UB or wrap negative).
    if (xml_bytes.size() > 1048576 ||
        xml_bytes.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::unexpected("SAML response XML exceeds maximum allowed size (1 MiB)");
    }

    // ── 2. Parse XML — no external entities, no network access ───────────────
    // XML_PARSE_NONET prevents external-entity network fetches (XXE).
    // XML_PARSE_NOENT is intentionally absent — we don't expand entities.
    xmlDocPtr doc = xmlReadMemory(
        xml_bytes.data(), static_cast<int>(xml_bytes.size()),
        "saml_response.xml", nullptr,
        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) return std::unexpected("failed to parse SAML response XML");

    struct DocGuard { xmlDocPtr d; ~DocGuard() { if (d) xmlFreeDoc(d); } } dg{doc};

    // ── 2.5. Reject DOCTYPE/DTD declarations ─────────────────────────────────
    // Explicit rejection is cheaper to reason about than relying on NOENT-off
    // semantics. No well-formed SAML response carries a DTD; presence indicates
    // a crafted document (XXE attempt, entity injection, or fuzzer probe).
    if (doc->intSubset || doc->extSubset) {
        return std::unexpected("SAML response contains a DOCTYPE/DTD declaration — rejected");
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) return std::unexpected("SAML response has no root element");

    // ── 3. Verify root is samlp:Response ─────────────────────────────────────
    if (!xmlStrEqual(root->name, BAD_CAST "Response") ||
        !root->ns || !xmlStrEqual(root->ns->href, BAD_CAST kSamlProtocolNs)) {
        return std::unexpected("root element is not samlp:Response");
    }

    // ── 4. Extract samlp:Status — a DEFERRED, advisory-only gate ─────────────
    // samlp:Status/StatusCode live on the samlp:Response wrapper, which is
    // NOT signature-covered: only the nested <saml:Assertion> is enveloped
    // by the ds:Signature verified below (steps 8-11). An attacker able to
    // tamper with the wire (or a malicious intermediary) can therefore
    // rewrite or strip this element at will WITHOUT invalidating the
    // assertion's signature. Because of that:
    //   - No trusted identity data is ever read from Status — every claim
    //     this function returns comes from the signed assertion.
    //   - Rejecting on a bad/missing Status is deferred until AFTER the
    //     InResponseTo single-use token (step 13) has been consumed from the
    //     verified assertion, so an attacker cannot flip an otherwise-valid
    //     response's Status to leave InResponseTo un-consumed (and thus
    //     replayable later by resubmitting the untampered original).
    //   - The real security gate for this response is the signed assertion;
    //     Status is advisory. See the deferred check at step 13.5.
    std::string status_reject_reason;
    {
        const xmlNodePtr status_node = find_child_ns(root, "Status", kSamlProtocolNs);
        if (!status_node) {
            status_reject_reason = "missing samlp:Status";
        } else {
            const xmlNodePtr status_code = find_child_ns(status_node, "StatusCode", kSamlProtocolNs);
            if (!status_code) {
                status_reject_reason = "missing samlp:StatusCode";
            } else {
                const auto status_value = get_attr(status_code, "Value");
                if (status_value != kSamlSuccessCode) {
                    status_reject_reason = "SAML status is not Success: " + status_value;
                }
            }
        }
    }

    // ── 5. Collect ALL Assertions at any depth — must be exactly 1 ───────────
    // Searching recursively catches XSW variants that nest a signed assertion
    // inside a forged outer assertion. Requiring exactly one element eliminates
    // the entire XSW attack class that relies on multiple assertions.
    std::vector<xmlNodePtr> assertions;
    if (!collect_assertions(root, assertions)) {
        return std::unexpected("SAML response XML nests too deep — rejected");
    }

    if (assertions.empty()) return std::unexpected("no saml:Assertion found in response");
    if (assertions.size() > 1) {
        return std::unexpected(
            "XSW rejected: response contains " + std::to_string(assertions.size()) +
            " Assertion elements (exactly 1 required)");
    }
    xmlNodePtr assertion = assertions[0];

    // ── 6. Get the Assertion's ID attribute ──────────────────────────────────
    const auto assertion_id = get_attr(assertion, "ID");
    if (assertion_id.empty()) return std::unexpected("Assertion has no ID attribute");

    // ── 7. Register the Assertion's ID so xmlsec can resolve the Reference URI.
    // SAML documents do not carry a DTD, so the "ID" attribute is not
    // automatically recognised as an XML ID type. xmlAddID registers it
    // explicitly, making URI="#<id>" fragment references resolvable by xmlsec.
    //
    // H-E: Check the xmlAddID return value.  xmlAddID returns nullptr when the
    // requested id value is ALREADY in the document's ID table — meaning another
    // element was registered with the same ID before our call.  If that happened,
    // the Reference URI would resolve to that other element, not our Assertion:
    // classic XSW via duplicate XML-ID injection.  Reject immediately.
    {
        xmlAttrPtr id_attr = xmlHasProp(assertion, BAD_CAST "ID");
        if (id_attr) {
            xmlIDPtr registered = xmlAddID(nullptr, doc, BAD_CAST assertion_id.c_str(), id_attr);
            if (!registered) {
                return std::unexpected(
                    "XSW rejected: Assertion ID '" + assertion_id +
                    "' is already registered in the document (duplicate XML-ID)");
            }
        }
    }

    // ── 8. Find the <ds:Signature> inside the Assertion (enveloped) ──────────
    xmlNodePtr sig_node = nullptr;
    for (xmlNodePtr n = xmlFirstElementChild(assertion); n; n = xmlNextElementSibling(n)) {
        if (n->type == XML_ELEMENT_NODE &&
            n->name && xmlStrEqual(n->name, BAD_CAST "Signature") &&
            n->ns   && n->ns->href && xmlStrEqual(n->ns->href, BAD_CAST kXmlDSigNs)) {
            sig_node = n;
            break;
        }
    }
    if (!sig_node) return std::unexpected("no ds:Signature found in Assertion");

    // ── 9. Load the PINNED IdP cert as the signing key (N1) ──────────────────
    // Setting dsig_ctx->signKey DIRECTLY before calling xmlSecDSigCtxVerify
    // bypasses all KeyInfo-based key discovery: xmlsec checks signKey first
    // and skips KeyInfo processing entirely if it is already set. This means
    // ANY keys embedded in the document's <ds:KeyInfo> are never consulted,
    // eliminating the key-substitution attack class.
    xmlSecKeyPtr sign_key = xmlSecOpenSSLAppKeyLoadMemory(
        reinterpret_cast<const xmlSecByte*>(config_.idp_cert_pem.data()),
        static_cast<xmlSecSize>(config_.idp_cert_pem.size()),
        xmlSecKeyDataFormatCertPem,
        nullptr, nullptr, nullptr);
    if (!sign_key) return std::unexpected("failed to load pinned IdP certificate");

    // ── 10. Create DSig context, set the pinned key, verify ──────────────────
    // nullptr keys manager → key MUST come from signKey (enforced by N1 above).
    xmlSecDSigCtxPtr dsig_ctx = xmlSecDSigCtxCreate(nullptr);
    if (!dsig_ctx) {
        xmlSecKeyDestroy(sign_key);
        return std::unexpected("xmlSecDSigCtxCreate failed");
    }

    struct DsigGuard {
        xmlSecDSigCtxPtr c;
        ~DsigGuard() { if (c) xmlSecDSigCtxDestroy(c); }
    } dg2{dsig_ctx};

    // Transfer key ownership to dsig_ctx (dsig_ctx frees it on destroy).
    dsig_ctx->signKey = sign_key;

    // Restrict allowed Reference URIs to same-document fragment references (#ID).
    // This rejects detached signatures (empty URI "") and external-URI references.
    dsig_ctx->enabledReferenceUris = xmlSecTransformUriTypeSameDocument;

    // ── 10.5. Algorithm allowlist — reject signature/digest downgrade ────────
    // N1 (signKey pinning above) controls WHICH key signs; it does NOT restrict
    // WHICH algorithm is used to sign. Without an explicit allowlist, xmlsec1's
    // defaults accept legacy SHA-1 digests and RSA-SHA1/HMAC/DSA signatures, so
    // an attacker who can get the pinned IdP key to (re-)sign — or who can find
    // any SHA-1 collision/weakness — could forge or otherwise downgrade a
    // signature that this verifier would still accept. Constrain to modern,
    // strong algorithms only, at every layer xmlsec consults:
    //
    //  - SignedInfo-level (C14N method + SignatureMethod): gated via
    //    dsigCtx->transformCtx.enabledTransforms, populated by
    //    xmlSecDSigCtxEnableSignatureTransform(). Empty list == allow-all, so
    //    this call MUST run before xmlSecDSigCtxVerify.
    //  - Per-Reference (enveloped-signature transform, any Reference-level
    //    C14N transform, and DigestMethod): gated via
    //    dsigCtx->enabledReferenceTransforms, populated by
    //    xmlSecDSigCtxEnableReferenceTransform(). Copied into each Reference's
    //    own transform context at verify time.
    //  - KeyInfo key data: gated via keyInfoReadCtx.enabledKeyData. N1 already
    //    bypasses <ds:KeyInfo> entirely (signKey is set directly), so this is
    //    defence-in-depth only, in case that bypass is ever weakened.
    //
    // RSA-SHA1, plain SHA1, MD5, HMAC-*, and DSA-* are deliberately excluded.
    {
        // Mandatory floor. Transform ids are GetKlass() results that resolve to
        // NULL when the algorithm is not compiled into this xmlsec/OpenSSL build.
        // We skip a NULL optional id below (a build without ECDSA simply does not
        // allow ECDSA) — but an EMPTY enabled-transform list means allow-all in
        // xmlsec, so we fail closed if the always-required floor (RSA-SHA256 +
        // SHA-256 digest + ExclC14N) is itself absent, guaranteeing the list can
        // never degenerate to allow-all.
        if (xmlSecTransformExclC14NId == nullptr ||
            xmlSecOpenSSLTransformRsaSha256Id == nullptr ||
            xmlSecOpenSSLTransformSha256Id == nullptr) {
            return std::unexpected(
                "xmlsec build lacks a required transform (ExclC14N / RSA-SHA256 / SHA-256)");
        }

        const xmlSecTransformId kAllowedSignatureTransforms[] = {
            // Canonicalization methods (SignedInfo-level).
            xmlSecTransformInclC14NId,
            xmlSecTransformInclC14NWithCommentsId,
            xmlSecTransformExclC14NId,
            xmlSecTransformExclC14NWithCommentsId,
            // Signature methods — RSA and ECDSA, SHA-256 and stronger only.
            xmlSecOpenSSLTransformRsaSha256Id,
            xmlSecOpenSSLTransformRsaSha384Id,
            xmlSecOpenSSLTransformRsaSha512Id,
            xmlSecOpenSSLTransformEcdsaSha256Id,
            xmlSecOpenSSLTransformEcdsaSha384Id,
            xmlSecOpenSSLTransformEcdsaSha512Id,
        };
        for (xmlSecTransformId id : kAllowedSignatureTransforms) {
            if (id == nullptr) continue;  // algorithm not built into this xmlsec — not allowed
            if (xmlSecDSigCtxEnableSignatureTransform(dsig_ctx, id) < 0) {
                return std::unexpected("failed to configure signature algorithm allowlist");
            }
        }

        const xmlSecTransformId kAllowedReferenceTransforms[] = {
            // Enveloped-signature transform (standard for enveloped ds:Signature).
            xmlSecTransformEnvelopedId,
            // Canonicalization methods, in case a Reference also specifies C14N.
            xmlSecTransformInclC14NId,
            xmlSecTransformInclC14NWithCommentsId,
            xmlSecTransformExclC14NId,
            xmlSecTransformExclC14NWithCommentsId,
            // Digest methods — SHA-256 and stronger only.
            xmlSecOpenSSLTransformSha256Id,
            xmlSecOpenSSLTransformSha384Id,
            xmlSecOpenSSLTransformSha512Id,
        };
        for (xmlSecTransformId id : kAllowedReferenceTransforms) {
            if (id == nullptr) continue;  // algorithm not built into this xmlsec — not allowed
            if (xmlSecDSigCtxEnableReferenceTransform(dsig_ctx, id) < 0) {
                return std::unexpected("failed to configure digest algorithm allowlist");
            }
        }

        // Defence-in-depth: restrict KeyInfo key data to RSA/EC (no HMAC/DSA),
        // even though N1's signKey bypass above means KeyInfo is never consulted.
        // xmlSecKeyDataId is `const struct _xmlSecKeyDataKlass*`; xmlSecPtrListAdd
        // takes a non-const xmlSecPtr (void*), hence the const_cast.
        if (xmlSecPtrListAdd(&dsig_ctx->keyInfoReadCtx.enabledKeyData,
                              const_cast<void*>(static_cast<const void*>(xmlSecOpenSSLKeyDataRsaId))) < 0 ||
            xmlSecPtrListAdd(&dsig_ctx->keyInfoReadCtx.enabledKeyData,
                              const_cast<void*>(static_cast<const void*>(xmlSecOpenSSLKeyDataEcId))) < 0) {
            return std::unexpected("failed to configure key-data allowlist");
        }
    }

    if (xmlSecDSigCtxVerify(dsig_ctx, sig_node) < 0) {
        return std::unexpected("xmlSecDSigCtxVerify returned internal error");
    }
    if (dsig_ctx->status != xmlSecDSigStatusSucceeded) {
        return std::unexpected("SAML signature verification failed");
    }

    // ── 11. XSW binding — Reference URI must resolve to THIS assertion (N2) ──
    //
    // After xmlsec confirms the cryptographic signature is valid, we bind
    // the verified reference to the specific assertion node we will read from.
    // An attacker who:
    //   (a) inserts a second assertion → caught by the exactly-1 check above
    //   (b) has the valid signature reference a DIFFERENT element → caught here
    //
    // We also require exactly one <Reference> in the SignedInfo — enveloping
    // signatures (data inside <Object>) or multi-reference attacks are rejected.
    {
        const auto ref_count =
            static_cast<std::size_t>(xmlSecPtrListGetSize(&dsig_ctx->signedInfoReferences));
        if (ref_count != 1) {
            return std::unexpected(
                "XSW rejected: expected exactly 1 signed reference, got " +
                std::to_string(ref_count));
        }

        xmlSecDSigReferenceCtxPtr ref_ctx = static_cast<xmlSecDSigReferenceCtxPtr>(
            xmlSecPtrListGetItem(&dsig_ctx->signedInfoReferences, 0));
        if (!ref_ctx || ref_ctx->status != xmlSecDSigStatusSucceeded) {
            return std::unexpected("XSW rejected: signed reference did not verify");
        }

        // Reference URI must be a same-document fragment "#<id>"
        if (!ref_ctx->uri || ref_ctx->uri[0] != '#') {
            return std::unexpected(
                "XSW rejected: Reference URI is not a same-document fragment (#ID)");
        }

        // Strip '#' and compare to the single Assertion's ID.
        // Because we've already required exactly 1 Assertion, a match here proves
        // the signature covers exactly the assertion we are about to read from.
        const std::string ref_id(reinterpret_cast<const char*>(ref_ctx->uri + 1));
        if (ref_id != assertion_id) {
            return std::unexpected(
                "XSW rejected: Reference URI '" + ref_id +
                "' does not match Assertion ID '" + assertion_id + "'");
        }

        // H-E: Duplicate-ID scan — node-identity binding.
        // The xmlAddID check above (step 7) catches the case where the ID was
        // already pre-registered (ID table collision).  This scan is a second,
        // independent layer: it searches the parsed document for any OTHER element
        // (not the Assertion itself) that ALSO carries `assertion_id` as an "ID"
        // or "xml:id" attribute value.  Such a decoy node (e.g.
        // <samlp:Extension xml:id="<assertionID>">) could confuse a verifier that
        // resolves signed references by attribute-value search rather than the
        // registered ID table — we must reject before any such ambiguity can exist.
        if (has_duplicate_id(root, assertion,
                             BAD_CAST assertion_id.c_str())) {
            return std::unexpected(
                "XSW rejected: another element in the document shares "
                "the Assertion ID '" + assertion_id + "' (duplicate-ID injection)");
        }
    }

    spdlog::debug("SamlProvider: signature verified (assertion_id={})", assertion_id);

    // ── 11.5. Validate Assertion-level <saml:Issuer> ─────────────────────────
    // Read the Issuer from the VERIFIED assertion node.  The SAML 2.0 WebSSO
    // profile §4.1.4 requires the assertion issuer to equal the IdP entity ID
    // the SP was configured to trust.  An absent or mismatched Issuer indicates
    // a forged or misdirected assertion.
    {
        const xmlNodePtr issuer_node = find_child_ns(assertion, "Issuer", kSamlAssertionNs);
        if (!issuer_node) {
            return std::unexpected("Assertion is missing required <saml:Issuer> element");
        }
        const auto issuer_value = get_text(issuer_node);
        if (issuer_value != config_.idp_entity_id) {
            return std::unexpected(
                "Assertion Issuer mismatch: got '" + issuer_value +
                "', expected '" + config_.idp_entity_id + "'");
        }
    }

    // ── 12. Validate Conditions ───────────────────────────────────────────────
    // All reads below are from 'assertion' — the single verified node (N2).
    const auto now_epoch = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    // <Conditions> is MANDATORY per the SAML 2.0 WebSSO profile §4.1.4.
    const xmlNodePtr conditions = find_child_ns(assertion, "Conditions", kSamlAssertionNs);
    if (!conditions) {
        return std::unexpected("Assertion is missing required <saml:Conditions> element");
    }
    {
        const auto nb_str = get_attr(conditions, "NotBefore");
        if (!nb_str.empty()) {
            const int64_t nb = parse_iso8601(nb_str.c_str());
            if (nb < 0) return std::unexpected("invalid Conditions NotBefore: " + nb_str);
            if (now_epoch < nb - kClockSkewSeconds) {
                return std::unexpected("assertion not yet valid (NotBefore)");
            }
        }

        // NotOnOrAfter is MANDATORY per the SAML 2.0 WebSSO profile §4.1.4.2
        // (parity with SubjectConfirmationData which is already enforced below).
        // An absent NotOnOrAfter lets an assertion replay indefinitely.
        const auto nooa_str = get_attr(conditions, "NotOnOrAfter");
        if (nooa_str.empty()) {
            return std::unexpected(
                "Conditions is missing required NotOnOrAfter attribute");
        }
        {
            const int64_t nooa = parse_iso8601(nooa_str.c_str());
            if (nooa < 0) return std::unexpected("invalid Conditions NotOnOrAfter: " + nooa_str);
            if (now_epoch >= nooa + kClockSkewSeconds) {
                return std::unexpected("assertion has expired (Conditions NotOnOrAfter)");
            }
        }

        // <AudienceRestriction> is MANDATORY — at least one <Audience> must match
        // sp_entity_id. An absent AudienceRestriction means the assertion may have
        // been issued for a different SP (audience confusion attack).
        const xmlNodePtr aud_restr =
            find_child_ns(conditions, "AudienceRestriction", kSamlAssertionNs);
        if (!aud_restr) {
            return std::unexpected(
                "Assertion is missing required <saml:AudienceRestriction> element");
        }
        bool audience_ok = false;
        for (xmlNodePtr n = xmlFirstElementChild(aud_restr); n;
             n = xmlNextElementSibling(n)) {
            if (n->type == XML_ELEMENT_NODE &&
                n->name && xmlStrEqual(n->name, BAD_CAST "Audience") &&
                n->ns   && n->ns->href &&
                xmlStrEqual(n->ns->href, BAD_CAST kSamlAssertionNs)) {
                if (get_text(n) == config_.sp_entity_id) {
                    audience_ok = true;
                    break;
                }
            }
        }
        if (!audience_ok) {
            return std::unexpected(
                "AudienceRestriction does not contain our SP entity ID: " +
                config_.sp_entity_id);
        }
    }

    // Subject / SubjectConfirmation / SubjectConfirmationData
    // All three are MANDATORY per the SAML 2.0 WebSSO profile §4.1.4.2.
    // <SubjectConfirmationData> must carry both Recipient and NotOnOrAfter;
    // absence of either means the assertion cannot be bound to this SP request.
    const xmlNodePtr subject =
        find_child_ns(assertion, "Subject", kSamlAssertionNs);
    if (!subject) {
        return std::unexpected("Assertion is missing required <saml:Subject> element");
    }
    const xmlNodePtr subj_conf =
        find_child_ns(subject, "SubjectConfirmation", kSamlAssertionNs);
    if (!subj_conf) {
        return std::unexpected(
            "Assertion is missing required <saml:SubjectConfirmation> element");
    }
    const auto method = get_attr(subj_conf, "Method");
    if (method != kSamlBearerConf) {
        return std::unexpected("unsupported SubjectConfirmation Method: " + method);
    }
    const xmlNodePtr scd =
        find_child_ns(subj_conf, "SubjectConfirmationData", kSamlAssertionNs);
    if (!scd) {
        return std::unexpected(
            "Assertion is missing required bearer <saml:SubjectConfirmationData> element");
    }

    // Recipient is now mandatory (WebSSO profile §4.1.4.2 — MUST be present).
    const auto recipient = get_attr(scd, "Recipient");
    if (recipient.empty()) {
        return std::unexpected(
            "SubjectConfirmationData is missing required Recipient attribute");
    }
    if (recipient != config_.sp_acs_url) {
        return std::unexpected(
            "SubjectConfirmationData Recipient mismatch: got '" +
            recipient + "', expected '" + config_.sp_acs_url + "'");
    }

    // NotOnOrAfter is now mandatory (WebSSO profile §4.1.4.2 — MUST be present).
    const auto scd_nooa_str = get_attr(scd, "NotOnOrAfter");
    if (scd_nooa_str.empty()) {
        return std::unexpected(
            "SubjectConfirmationData is missing required NotOnOrAfter attribute");
    }
    {
        const int64_t scd_nooa = parse_iso8601(scd_nooa_str.c_str());
        if (scd_nooa < 0) {
            return std::unexpected("invalid SubjectConfirmationData NotOnOrAfter");
        }
        if (now_epoch >= scd_nooa + kClockSkewSeconds) {
            return std::unexpected("SubjectConfirmationData has expired");
        }
    }

    const std::string in_response_to = get_attr(scd, "InResponseTo");

    // ── 13. InResponseTo — solicited-only, replay-protected, browser-bound ───
    // Require InResponseTo to be present and match an AuthnRequest we issued.
    // Absent InResponseTo = unsolicited response = rejected.
    // Repeated InResponseTo = replay = rejected (pending_requests_ is single-use).
    //
    // Browser-binding: the ACS route extracts the __Host-yuzu_saml_bind cookie
    // and passes its value here as cookie_secret.  We verify that SHA-256 of
    // that secret matches the binding_hash stored when the AuthnRequest was
    // issued.  This binds the SAML round-trip to the browser that initiated
    // login — a forced-login CSRF (attacker CSRF-POSTs a valid assertion into
    // a victim's browser) fails because the victim's browser has no cookie.
    // All four checks (entry existence, hash match, TTL, consume) are atomic
    // under mu_ to prevent a TOCTOU race on concurrent ACS posts.
    if (in_response_to.empty()) {
        return std::unexpected(
            "missing InResponseTo: unsolicited responses are not accepted");
    }
    {
        std::lock_guard lock(mu_);
        auto it = pending_requests_.find(in_response_to);
        if (it == pending_requests_.end()) {
            return std::unexpected(
                "unsolicited or replayed response: InResponseTo=" + in_response_to);
        }
        // Browser-binding check: SHA-256(cookie_secret) must match stored binding_hash.
        // An empty cookie_secret cannot match any real binding_hash (which is
        // SHA-256 of a 32-byte random secret and thus a non-trivial hex string).
        const auto provided_hash = sha256_hex(cookie_secret);
        if (!constant_time_hex_equal(provided_hash, it->second.binding_hash)) {
            // Consume the entry to prevent an attacker from probing with
            // different cookie values (forced-login becomes a single-shot attempt).
            pending_requests_.erase(it);
            return std::unexpected(
                "browser-binding check failed: binding cookie mismatch "
                "(InResponseTo=" + in_response_to + ")");
        }
        if (std::chrono::steady_clock::now() > it->second.expiry) {
            pending_requests_.erase(it);
            return std::unexpected(
                "AuthnRequest has expired: InResponseTo=" + in_response_to);
        }
        pending_requests_.erase(it); // Consume — prevents replay
    }

    // ── 13.5. Enforce the deferred Status check (see step 4) ─────────────────
    // InResponseTo has now been consumed from the verified, signed assertion,
    // so replay protection holds regardless of what the unsigned Status
    // wrapper said. Only now do we act on Status.
    if (!status_reject_reason.empty()) {
        return std::unexpected(status_reject_reason);
    }

    // ── 14. Extract NameID (all reads from the verified 'assertion' node) ─────
    // subject is guaranteed non-null at this point (mandatory check above).
    std::string name_id;
    std::string name_id_format; // ADR-2001 PR4a — see SamlAssertion::name_id_format
    {
        const xmlNodePtr name_id_node =
            find_child_ns(subject, "NameID", kSamlAssertionNs);
        if (name_id_node) {
            name_id = get_text(name_id_node);
            name_id_format = get_attr(name_id_node, "Format");
        }
    }
    if (name_id.empty()) {
        return std::unexpected("no NameID found in verified assertion");
    }

    // ── 15. Extract group attribute values (all reads from the verified
    // 'assertion' node — see extract_group_values' N2 parity comment). Empty
    // config_.group_attribute (the default) yields an empty groups vector,
    // preserving the thin slice's behaviour exactly.
    bool group_cap_truncated = false;
    std::vector<std::string> groups =
        extract_group_values(assertion, config_.group_attribute, &group_cap_truncated);

    // Session-enrichment attributes (display name, email) — read from the SAME
    // verified 'assertion' node (N2 parity). Empty config (default) yields
    // empty strings, preserving the raw-NameID display fallback. These NEVER
    // feed identity/authz/SCIM-linkage — only Session::display_name rendering.
    std::string display_name = extract_first_attribute_value(assertion, config_.name_attribute);
    std::string email        = extract_first_attribute_value(assertion, config_.email_attribute);

    spdlog::info("SamlProvider: assertion accepted (name_id={}, groups={}, has_display={}, "
                 "has_email={})",
                 name_id, groups.size(), !display_name.empty(), !email.empty());
    return SamlAssertion{std::move(name_id),   std::move(name_id_format), std::move(groups),
                         group_cap_truncated,  std::move(display_name),   std::move(email)};
}

// ── cleanup ───────────────────────────────────────────────────────────────────

void SamlProvider::cleanup_expired_states() {
    std::lock_guard lock(mu_);
    cleanup_expired_states_locked();
}

void SamlProvider::cleanup_expired_states_locked() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = pending_requests_.begin(); it != pending_requests_.end();) {
        if (now > it->second.expiry)
            it = pending_requests_.erase(it);
        else
            ++it;
    }
}

} // namespace yuzu::server::saml

#endif // !_WIN32
