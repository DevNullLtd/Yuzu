#pragma once

// remote_access_audit_keys_parsers.hpp -- pure parsers and row formatters for the
// authorized_keys half of the remote_access_audit plugin: which public keys let someone log
// in to an account. Header-only and portable; no file I/O, no subprocess, no OS header.
//
//   parse_authorized_keys      one authorized_keys file -> `key|...` rows plus the
//                              malformed/oversized line counts
//   parse_key_options          the options prefix, by sshd's rules (auth-options.c)
//   decode_key_blob            the COMPLETE bounded decode of one key or certificate blob
//                              (sshkey.c), returning the PLAIN public blob to fingerprint
//   fingerprint_sha256         `SHA256:` + unpadded base64 of the plain blob, byte-identical
//                              to `ssh-keygen -lf` (a certificate fingerprints the key it
//                              carries)
//   expand_authorized_keys_file  one AuthorizedKeysFile token -> which file to open
//
// FINGERPRINTS AND OPTION NAMES ONLY. A key comment, an option VALUE (command=, from=,
// principals=, environment=, ...) and a key-file path are NEVER emitted: the comment is
// skipped, option values are dequoted only to find where they end, and the only option
// output is the lowercased NAME from a closed set plus has_command/has_from/has_principals.
//
// The row is a SYNTACTIC inventory of what sshd's parser would accept. Option VALUES are not
// validated (expiry-time, environment, tunnel, permitopen/permitlisten), and an ECDSA point is
// checked for its length and 0x04 prefix, not for lying on the curve. A line sshd would reject
// for such a value is therefore counted as a key here (README caveat).
//
// Every parser charges the caller's yuzu::shared::RowByteBudget BEFORE materialising a row
// and stops at the first refusal, so allocation is bounded by the budget plus the input.

#include "remote_access_audit_config_parsers.hpp"

#include <base64.hpp>
#include <sha256.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::remote_access_audit {

/// sshd's authorized_keys reader has no line cap (getline); this one does, and counts the
/// lines it did not parse.
inline constexpr std::size_t kMaxKeyLine = 16 * 1024;

// ---------------------------------------------------------------------------
// Key blob decoding (sshkey.c sshkey_from_blob_internal)
// ---------------------------------------------------------------------------

enum class Family { ed25519, ed25519_sk, ecdsa, ecdsa_sk, rsa };

struct TypeInfo {
    Family family = Family::ed25519;
    bool cert = false;
    int curve_bits = 0; ///< ecdsa / ecdsa_sk
};

/// The 20 `.name` strings of OpenSSH's keyimpls (ssh-dss and ssh-xmss are not among them).
inline std::optional<TypeInfo> type_info(std::string_view name) {
    struct Entry {
        std::string_view name;
        TypeInfo info;
    };
    static constexpr Entry kTable[] = {
        {"ssh-ed25519", {Family::ed25519, false, 0}},
        {"ssh-ed25519-cert-v01@openssh.com", {Family::ed25519, true, 0}},
        {"sk-ssh-ed25519@openssh.com", {Family::ed25519_sk, false, 0}},
        {"sk-ssh-ed25519-cert-v01@openssh.com", {Family::ed25519_sk, true, 0}},
        {"ecdsa-sha2-nistp256", {Family::ecdsa, false, 256}},
        {"ecdsa-sha2-nistp384", {Family::ecdsa, false, 384}},
        {"ecdsa-sha2-nistp521", {Family::ecdsa, false, 521}},
        {"ecdsa-sha2-nistp256-cert-v01@openssh.com", {Family::ecdsa, true, 256}},
        {"ecdsa-sha2-nistp384-cert-v01@openssh.com", {Family::ecdsa, true, 384}},
        {"ecdsa-sha2-nistp521-cert-v01@openssh.com", {Family::ecdsa, true, 521}},
        {"sk-ecdsa-sha2-nistp256@openssh.com", {Family::ecdsa_sk, false, 256}},
        {"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", {Family::ecdsa_sk, true, 256}},
        {"webauthn-sk-ecdsa-sha2-nistp256@openssh.com", {Family::ecdsa_sk, false, 256}},
        {"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", {Family::ecdsa_sk, true, 256}},
        {"ssh-rsa", {Family::rsa, false, 0}},
        {"ssh-rsa-cert-v01@openssh.com", {Family::rsa, true, 0}},
        {"rsa-sha2-256", {Family::rsa, false, 0}},
        {"rsa-sha2-512", {Family::rsa, false, 0}},
        {"rsa-sha2-256-cert-v01@openssh.com", {Family::rsa, true, 0}},
        {"rsa-sha2-512-cert-v01@openssh.com", {Family::rsa, true, 0}},
    };
    for (const auto& e : kTable) {
        if (e.name == name)
            return e.info;
    }
    return std::nullopt;
}

/// The name `to_blob(force_plain)` writes for a family (rsa-sha2-* and webauthn blobs are
/// serialised under their base names).
inline std::string plain_type_name(const TypeInfo& t) {
    switch (t.family) {
    case Family::ed25519:
        return "ssh-ed25519";
    case Family::ed25519_sk:
        return "sk-ssh-ed25519@openssh.com";
    case Family::ecdsa:
        return "ecdsa-sha2-nistp" + std::to_string(t.curve_bits);
    case Family::ecdsa_sk:
        return "sk-ecdsa-sha2-nistp256@openssh.com";
    case Family::rsa:
        return "ssh-rsa";
    }
    return {};
}

namespace detail {

/// Bounds-checked big-endian reader over one blob. Every length is checked against what is
/// left BEFORE it is used.
struct Reader {
    std::string_view d;
    std::size_t pos = 0;

    [[nodiscard]] std::size_t left() const { return d.size() - pos; }

    std::optional<std::uint32_t> u32() {
        if (left() < 4)
            return std::nullopt;
        const auto* p = reinterpret_cast<const unsigned char*>(d.data() + pos);
        pos += 4;
        return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
               (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
    }

    std::optional<std::uint64_t> u64() {
        const auto hi = u32();
        const auto lo = u32();
        if (!hi || !lo)
            return std::nullopt;
        return (static_cast<std::uint64_t>(*hi) << 32) | *lo;
    }

    std::optional<std::string_view> str() {
        const auto n = u32();
        if (!n || *n > left())
            return std::nullopt;
        const auto out = d.substr(pos, *n);
        pos += *n;
        return out;
    }

    /// sshbuf_get_cstring: a string with no embedded NUL.
    std::optional<std::string_view> cstr() {
        const auto s = str();
        if (!s || s->find('\0') != std::string_view::npos)
            return std::nullopt;
        return s;
    }
};

inline void put_string(std::string& out, std::string_view s) {
    const auto n = static_cast<std::uint32_t>(s.size());
    out += static_cast<char>((n >> 24) & 0xFF);
    out += static_cast<char>((n >> 16) & 0xFF);
    out += static_cast<char>((n >> 8) & 0xFF);
    out += static_cast<char>(n & 0xFF);
    out.append(s);
}

/// sshbuf_get_bignum2 + BN serialisation: the value bytes with leading zeros trimmed (a
/// non-minimal encoding is ACCEPTED, as OpenSSH accepts it), `nullopt` for a negative value
/// (high bit set) or one over 16384 bits.
inline std::optional<std::string_view> read_bignum(Reader& r) {
    const auto s = r.str();
    if (!s)
        return std::nullopt;
    if (!s->empty() && (static_cast<unsigned char>((*s)[0]) & 0x80) != 0)
        return std::nullopt;
    constexpr std::size_t kMaxBignum = 16384 / 8;
    if (s->size() > kMaxBignum + 1 || (s->size() == kMaxBignum + 1 && (*s)[0] != '\0'))
        return std::nullopt;
    auto v = *s;
    while (!v.empty() && v.front() == '\0')
        v.remove_prefix(1);
    return v;
}

/// The mpint wire form of a trimmed magnitude (0x00 prepended when the high bit is set).
inline void put_mpint(std::string& out, std::string_view magnitude) {
    if (!magnitude.empty() && (static_cast<unsigned char>(magnitude[0]) & 0x80) != 0) {
        std::string padded(1, '\0');
        padded.append(magnitude);
        put_string(out, padded);
    } else {
        put_string(out, magnitude);
    }
}

inline std::size_t bit_length(std::string_view magnitude) {
    if (magnitude.empty())
        return 0;
    return (magnitude.size() - 1) * 8 +
           static_cast<std::size_t>(std::bit_width(static_cast<unsigned char>(magnitude[0])));
}

} // namespace detail

struct KeyFacts {
    TypeInfo info; ///< info.family is the decoded family
    std::size_t bits = 0;
    std::string plain_blob; ///< string(plain type) + public fields, certificate framing removed
};

namespace detail {

/// cert_parse (sshkey.c:1854): every certificate field is read and bounds-checked and then
/// DISCARDED; none is retained. Returns false for any structural defect.
inline bool skip_certificate_body(Reader& r);

inline std::optional<KeyFacts> decode_blob(std::string_view blob, bool allow_cert) {
    Reader r{blob};
    const auto name = r.str();
    if (!name)
        return std::nullopt;
    const auto ti = type_info(*name);
    if (!ti || (ti->cert && !allow_cert))
        return std::nullopt;
    if (ti->cert && !r.str()) // the nonce
        return std::nullopt;

    KeyFacts out;
    out.info = *ti;
    out.info.cert = false;
    std::string fields;
    switch (ti->family) {
    case Family::ed25519:
    case Family::ed25519_sk: {
        const auto pk = r.str();
        if (!pk || pk->size() != 32) // ssh-ed25519.c:110
            return std::nullopt;
        put_string(fields, *pk);
        out.bits = 256;
        if (ti->family == Family::ed25519_sk) {
            const auto app = r.cstr();
            if (!app)
                return std::nullopt;
            put_string(fields, *app);
        }
        break;
    }
    case Family::ecdsa:
    case Family::ecdsa_sk: {
        const auto curve = r.cstr();
        if (!curve || *curve != "nistp" + std::to_string(ti->curve_bits))
            return std::nullopt;
        const auto point = r.str();
        const std::size_t want = 1 + 2 * static_cast<std::size_t>((ti->curve_bits + 7) / 8);
        if (!point || point->size() != want || (*point)[0] != '\x04')
            return std::nullopt;
        put_string(fields, *curve);
        put_string(fields, *point);
        out.bits = static_cast<std::size_t>(ti->curve_bits);
        if (ti->family == Family::ecdsa_sk) {
            const auto app = r.cstr();
            if (!app)
                return std::nullopt;
            put_string(fields, *app);
        }
        break;
    }
    case Family::rsa: {
        const auto e = read_bignum(r);
        const auto n = read_bignum(r);
        if (!e || !n)
            return std::nullopt;
        out.bits = bit_length(*n);
        if (out.bits < 1024) // SSH_RSA_MINIMUM_MODULUS_SIZE
            return std::nullopt;
        put_mpint(fields, *e);
        put_mpint(fields, *n);
        break;
    }
    }
    if (ti->cert) {
        if (!skip_certificate_body(r))
            return std::nullopt;
    }
    if (r.left() != 0) // sshkey.c:2063 -- trailing bytes
        return std::nullopt;

    put_string(out.plain_blob, plain_type_name(out.info));
    out.plain_blob += fields;
    out.info.cert = ti->cert;
    return out;
}

inline bool skip_certificate_body(Reader& r) {
    constexpr std::uint32_t kMaxPrincipals = 256; // SSHKEY_CERT_MAX_PRINCIPALS
    if (!r.u64())                                // serial
        return false;
    const auto type = r.u32();
    if (!type || (*type != 1 && *type != 2)) // SSH2_CERT_TYPE_USER / HOST
        return false;
    if (!r.cstr())                // key_id
        return false;
    const auto principals = r.str();
    if (!principals)
        return false;
    {
        Reader p{*principals};
        std::uint32_t n = 0;
        while (p.left() != 0) {
            if (++n > kMaxPrincipals || !p.cstr())
                return false;
        }
    }
    if (!r.u64() || !r.u64()) // valid_after, valid_before
        return false;
    for (int i = 0; i < 2; ++i) { // critical options, extensions: (name, data) string pairs
        const auto sect = r.str();
        if (!sect)
            return false;
        Reader s{*sect};
        while (s.left() != 0) {
            if (!s.str() || !s.str())
                return false;
        }
    }
    if (!r.str()) // reserved
        return false;
    const auto ca = r.str();
    if (!ca || !decode_blob(*ca, /*allow_cert=*/false))
        return false;
    const auto sig = r.str();
    if (!sig)
        return false;
    Reader sr{*sig};
    return sr.str().has_value(); // sshkey_get_sigtype: the signature leads with its type string
}

} // namespace detail

/// Decodes `blob` completely (every field of the key and, for a certificate, of the
/// certificate), nullopt on any defect. The result's plain_blob is what `ssh-keygen -l`
/// fingerprints: the public key alone, certificate nonce and fields excluded.
inline std::optional<KeyFacts> decode_key_blob(std::string_view blob) {
    return detail::decode_blob(blob, /*allow_cert=*/true);
}

[[nodiscard]] inline std::string fingerprint_sha256(std::string_view plain_blob) {
    yuzu::shared::Sha256 h;
    h.update(plain_blob.data(), plain_blob.size());
    const auto raw = h.raw_digest();
    return "SHA256:" + yuzu::shared::base64_encode(
                           std::string_view{reinterpret_cast<const char*>(raw.data()), raw.size()}, false);
}

// ---------------------------------------------------------------------------
// authorized_keys options (authfile.c sshkey_advance_past_options, auth-options.c)
// ---------------------------------------------------------------------------

/// authfile.c sshkey_advance_past_options: moves `i` past the options (to the first unquoted
/// space/tab or the end). `\"` inside quotes is skipped as a pair. false == unterminated quote.
inline bool advance_past_options(std::string_view s, std::size_t& i) {
    bool quoted = false;
    for (; i < s.size() && (quoted || (s[i] != ' ' && s[i] != '\t')); ++i) {
        if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == '"')
            ++i;
        else if (s[i] == '"')
            quoted = !quoted;
    }
    return !(i >= s.size() && quoted);
}

struct KeyOptions {
    std::vector<std::string> names; ///< lowercased, first-seen order, from the closed set
    bool cert_authority = false;
    bool has_command = false;
    bool has_from = false;
    bool has_principals = false;
};

namespace detail {

inline bool starts_with_ci(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() &&
           std::ranges::equal(s.substr(0, prefix.size()), prefix, [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
           });
}

/// misc.c opt_dequote: `s[at]` must be '"'; only `\"` is an escape; the value runs to the
/// closing quote. false == missing start or end quote. `at` ends after the closing quote.
inline bool skip_dequoted(std::string_view s, std::size_t& at) {
    if (at >= s.size() || s[at] != '"')
        return false;
    ++at;
    while (at < s.size() && s[at] != '"') {
        if (s[at] == '\\' && at + 1 < s.size() && s[at + 1] == '"')
            ++at;
        ++at;
    }
    if (at >= s.size())
        return false;
    ++at;
    return true;
}

/// The grammar of a key-type name this table does not know: 1..64 bytes of [A-Za-z0-9._@+-]
/// (every OpenSSH name fits: `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`). The type token is
/// the one subject-authored token that reaches a key row verbatim, so it can never carry the
/// quote, `=`, `/`, space or free text of an option clause.
inline bool is_key_type_name(std::string_view t) {
    if (t.empty() || t.size() > 64)
        return false;
    return std::ranges::all_of(t, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
               c == '_' || c == '@' || c == '+' || c == '-';
    });
}

} // namespace detail

/// auth-options.c sshauthopt_parse, syntactically. nullopt == sshd would reject the line:
/// an unknown option name, a trailing comma, a value without its quotes, or a SECOND
/// command/principals/from clause (auth-options.c:364-390).
inline std::optional<KeyOptions> parse_key_options(std::string_view s) {
    static constexpr std::array<std::string_view, 7> kNegatable = {
        "port-forwarding", "agent-forwarding", "x11-forwarding", "touch-required",
        "verify-required", "pty",              "user-rc"};
    static constexpr std::array<std::string_view, 8> kValued = {
        "command", "principals", "from", "expiry-time", "environment", "permitopen",
        "permitlisten", "tunnel"};

    KeyOptions out;
    const auto note = [&](std::string name) {
        if (std::ranges::find(out.names, name) == out.names.end())
            out.names.push_back(std::move(name));
    };
    std::size_t i = 0;
    while (i < s.size() && s[i] != ' ' && s[i] != '\t') {
        const auto rest = s.substr(i);
        bool matched = false;
        if (detail::starts_with_ci(rest, "restrict")) {
            note("restrict");
            i += 8;
            matched = true;
        } else if (detail::starts_with_ci(rest, "cert-authority")) {
            note("cert-authority");
            out.cert_authority = true;
            i += 14;
            matched = true;
        }
        for (const auto f : kNegatable) {
            if (matched)
                break;
            std::size_t at = 0;
            bool negate = false;
            if (detail::starts_with_ci(rest, "no-")) {
                at = 3;
                negate = true;
            }
            if (detail::starts_with_ci(rest.substr(at), f)) {
                note((negate ? "no-" : "") + std::string(f));
                i += at + f.size();
                matched = true;
            }
        }
        for (const auto v : kValued) {
            if (matched)
                break;
            if (detail::starts_with_ci(rest, v) && rest.size() > v.size() && rest[v.size()] == '=') {
                std::size_t at = i + v.size() + 1;
                if (!detail::skip_dequoted(s, at))
                    return std::nullopt;
                bool* once = v == "command" ? &out.has_command
                             : v == "from"  ? &out.has_from
                             : v == "principals" ? &out.has_principals
                                                 : nullptr;
                if (once != nullptr) {
                    if (*once)
                        return std::nullopt; // "multiple ... clauses"
                    *once = true;
                }
                note(std::string(v));
                i = at;
                matched = true;
            }
        }
        // Skip the comma and move to the next option, or end the options.
        if (i >= s.size() || s[i] == ' ' || s[i] == '\t')
            break;
        if (s[i] != ',')
            return std::nullopt; // an unknown option, or garbage after a known one
        ++i;
        if (i >= s.size())
            return std::nullopt; // trailing comma: "unexpected end-of-options"
    }
    return out;
}

// ---------------------------------------------------------------------------
// authorized_keys lines
// ---------------------------------------------------------------------------

/// What reading one key off the front of `s[at..]` found. Mirrors sshkey_read: the type
/// token runs to space/tab, the blob token to the next space/tab, and the decoded blob must
/// be the same KEY TYPE as the token (rsa-sha2-256 and ssh-rsa are one type; an ECDSA token
/// must name the blob's curve). A type this table does not know is accepted only as 1..64 bytes
/// of [A-Za-z0-9._@+-] (detail::is_key_type_name), so the token is never an option clause.
struct ReadKey {
    KeyFacts facts;
    std::string type_token; ///< as written; a known name, or an unknown type (see unknown)
    bool unknown = false;   ///< not in the known-name set: fingerprinted over the raw blob
    std::size_t end = 0;    ///< index just past the blob token
};

inline std::optional<ReadKey> try_read_key(std::string_view s, std::size_t at) {
    const auto tend = s.find_first_of(" \t", at);
    if (tend == std::string_view::npos)
        return std::nullopt;
    const auto type_token = s.substr(at, tend - at);
    std::size_t b = tend;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t'))
        ++b;
    if (b >= s.size())
        return std::nullopt;
    const auto bend = std::min(s.find_first_of(" \t", b), s.size());
    // b64_pton skips isspace() anywhere, so a trailing CR of a CRLF file does not matter.
    std::string token;
    for (const char c : s.substr(b, bend - b)) {
        if (c != '\r' && c != '\v' && c != '\f')
            token += c;
    }
    const auto blob = yuzu::shared::base64_decode(token);
    if (!blob)
        return std::nullopt;

    ReadKey out;
    out.type_token = std::string(type_token);
    out.end = bend;
    if (const auto ti = type_info(type_token)) {
        auto facts = decode_key_blob(*blob);
        if (!facts)
            return std::nullopt;
        const bool same = facts->info.family == ti->family && facts->info.cert == ti->cert &&
                          (ti->family != Family::ecdsa || facts->info.curve_bits == ti->curve_bits);
        if (!same)
            return std::nullopt;
        out.facts = std::move(*facts);
        return out;
    }
    // A type this table does not know (ssh-dss, a newer algorithm): inventoried when the
    // blob leads with that same name, fingerprinted over the raw blob (which is what
    // ssh-keygen does for a plain key). A certificate of an unknown type cannot be unwrapped.
    // The name must also fit detail::is_key_type_name (1..64 bytes of [A-Za-z0-9._@+-]): the
    // token is written to the key row verbatim, so an option clause such as `command="..."`
    // that a crafted blob repeats is refused here and left to the option parser.
    detail::Reader r{*blob};
    const auto lead = r.str();
    if (!lead || *lead != type_token || !detail::is_key_type_name(type_token) ||
        type_token.find("-cert-v01@openssh.com") != std::string_view::npos)
        return std::nullopt;
    out.unknown = true;
    out.facts.plain_blob = *blob;
    return out;
}

struct KeysParse {
    std::vector<std::string> rows;
    std::size_t keys = 0;
    std::size_t malformed = 0;
    std::size_t oversized = 0;
    bool truncated = false;       ///< the row budget refused a row
    bool unknown_type = false;    ///< a key of an unknown type was emitted
    bool field_oversized = false;
    bool nul_truncated = false;   ///< a line held a NUL byte and was read only up to it, as sshd reads it
};

[[nodiscard]] inline std::string key_row(std::string_view account, std::string_view kind,
                                         std::string_view type, std::string_view fingerprint,
                                         std::string_view bits, std::string_view flags,
                                         std::string_view options, bool& oversized) {
    return pipe_row("key", {account, kind, type, fingerprint, bits, flags, options}, oversized);
}

[[nodiscard]] inline std::string file_row(std::string_view account, std::string_view kind, SourceState state,
                                          std::optional<std::size_t> keys,
                                          std::optional<std::size_t> malformed,
                                          std::optional<std::size_t> oversized, bool& field_oversized) {
    const auto num = [](std::optional<std::size_t> n) { return n ? std::to_string(*n) : std::string{"-"}; };
    return pipe_row("file", {account, kind, state_token(state), num(keys), num(malformed), num(oversized)},
                    field_oversized);
}

/// Parses one authorized_keys file's text into `out.rows` (one `key|...` row per accepted
/// line, in file order, duplicates kept). Blank and `#` lines are ignored and uncounted. A
/// line over kMaxKeyLine is counted oversized and not parsed; a line sshd would not accept is
/// counted malformed and not emitted. Formats each row, charges its wire size plus overhead
/// and retains it only when admitted; stops at the first refusal (`out.truncated`). A line is
/// cut at its first NUL byte before it is parsed (`out.nul_truncated`): sshd reads each line
/// with getline() and treats it as a C string, so a key before the NUL is a key it trusts and
/// the file is still accepted.
inline void parse_authorized_keys(std::string_view text, std::string_view account, std::string_view kind,
                                  yuzu::shared::RowByteBudget& budget, KeysParse& out) {
    std::size_t at = 0;
    while (at < text.size()) {
        const auto nl = text.find('\n', at);
        std::string_view line = nl == std::string_view::npos ? text.substr(at) : text.substr(at, nl - at);
        at = nl == std::string_view::npos ? text.size() : nl + 1;
        if (const auto nul = line.find('\0'); nul != std::string_view::npos) {
            line = line.substr(0, nul);
            out.nul_truncated = true;
        }

        std::size_t pos = 0;
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
            ++pos;
        if (pos >= line.size() || line[pos] == '#')
            continue;
        if (line.size() > kMaxKeyLine) {
            ++out.oversized;
            continue;
        }

        std::optional<ReadKey> key = try_read_key(line, pos);
        KeyOptions opts;
        if (!key) {
            const std::size_t start = pos;
            if (!advance_past_options(line, pos)) {
                ++out.malformed;
                continue;
            }
            const auto parsed = parse_key_options(line.substr(start, pos - start));
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
                ++pos;
            key = try_read_key(line, pos);
            if (!key || !parsed) {
                ++out.malformed;
                continue;
            }
            opts = *parsed;
        }

        std::string options_field;
        for (const auto& n : opts.names) {
            if (!options_field.empty())
                options_field += ',';
            options_field += n;
        }
        std::string flags;
        const auto flag = [&](bool on, std::string_view name) {
            if (!on)
                return;
            if (!flags.empty())
                flags += ',';
            flags += name;
        };
        flag(opts.cert_authority, "cert_authority");
        flag(key->facts.info.cert, "certificate");
        flag(opts.has_command, "has_command");
        flag(opts.has_from, "has_from");
        flag(opts.has_principals, "has_principals");
        flag(key->unknown, "unknown_type");

        // Charge the row as it goes on the wire (escaped and cut), never an estimate of its
        // parts: a pipe in the account doubles on the wire. A refusal stops the whole parse
        // and leaves every counter and flag as the last admitted row left it.
        bool row_oversized = false;
        std::string row = key_row(account, kind, key->type_token, fingerprint_sha256(key->facts.plain_blob),
                                  key->unknown ? std::string{} : std::to_string(key->facts.bits), flags,
                                  options_field, row_oversized);
        if (!budget.charge(row.size() + kRowOverhead)) {
            out.truncated = true;
            return;
        }
        out.field_oversized = out.field_oversized || row_oversized;
        if (key->unknown)
            out.unknown_type = true;
        out.rows.push_back(std::move(row));
        ++out.keys;
    }
}

// ---------------------------------------------------------------------------
// AuthorizedKeysFile resolution
// ---------------------------------------------------------------------------

/// Which file one AuthorizedKeysFile token names, resolved against one account's home.
struct KeyFileSpec {
    enum class Where { home_relative, absolute };
    Where where = Where::home_relative;
    std::vector<std::string> components; ///< home_relative: single path components under the home
    std::string path;                    ///< absolute: the whole path
    std::string kind;                    ///< authorized_keys | authorized_keys2 | custom
};

/// Expands `%%` and `%h` ONLY. `%u`, `%U` and every other `%X`, a trailing `%`, and a `~`
/// form need the account's login name or uid, which a home found by directory walk does not
/// authoritatively have: they are unsupported (nullopt), never guessed. A `..` component is
/// unsupported too. A relative result is joined under the home, as sshd does; an absolute
/// result is first normalised lexically (empty and `.` components and a trailing `/` dropped;
/// an absolute path with no component left is unsupported), then, when inside the home,
/// reduced to home-relative components so it is read through the home's directory descriptor.
/// An absolute result outside the home is stored in that normalised form, the one spelling the
/// network-mount prefix compare and the open both use.
inline std::optional<KeyFileSpec> expand_authorized_keys_file(std::string_view entry, std::string_view home) {
    KeyFileSpec out;
    out.kind = entry == ".ssh/authorized_keys" ? "authorized_keys"
               : entry == ".ssh/authorized_keys2" ? "authorized_keys2"
                                                   : "custom";
    if (entry.empty() || entry[0] == '~' || entry.find('\0') != std::string_view::npos)
        return std::nullopt;
    std::string path;
    for (std::size_t i = 0; i < entry.size(); ++i) {
        if (entry[i] != '%') {
            path += entry[i];
            continue;
        }
        if (i + 1 >= entry.size())
            return std::nullopt;
        const char c = entry[++i];
        if (c == '%')
            path += '%';
        else if (c == 'h')
            path += home;
        else
            return std::nullopt;
    }
    // The components of `p` with empty and `.` parts dropped; nullopt on `..`.
    const auto split = [](std::string_view p) -> std::optional<std::vector<std::string>> {
        std::vector<std::string> parts;
        std::size_t i = 0;
        while (i <= p.size()) {
            const auto slash = p.find('/', i);
            const auto part = p.substr(i, slash == std::string_view::npos ? std::string_view::npos : slash - i);
            if (part == "..")
                return std::nullopt;
            if (!part.empty() && part != ".")
                parts.emplace_back(part);
            if (slash == std::string_view::npos)
                break;
            i = slash + 1;
        }
        return parts;
    };
    auto parts = split(path);
    if (!parts)
        return std::nullopt;
    if (!path.empty() && path[0] == '/') {
        if (parts->empty())
            return std::nullopt;
        // Lexically normalised BEFORE classification (never realpath: it would touch a dead
        // mount), so the home-prefix test, the network-mount prefix compare and the open all see
        // the one spelling: `//`, `/./` and a trailing `/` cannot slip past a byte compare.
        std::string norm;
        for (const auto& c : *parts) {
            norm += '/';
            norm += c;
        }
        const std::string prefix = std::string(home) + "/";
        if (home.empty() || norm.compare(0, prefix.size(), prefix) != 0) {
            out.where = KeyFileSpec::Where::absolute;
            out.path = std::move(norm);
            return out;
        }
        // norm was rebuilt from an already-validated split, so this re-split cannot fail.
        parts = split(std::string_view{norm}.substr(prefix.size()));
    }
    if (parts->empty())
        return std::nullopt;
    out.components = std::move(*parts);
    return out;
}

} // namespace yuzu::remote_access_audit
