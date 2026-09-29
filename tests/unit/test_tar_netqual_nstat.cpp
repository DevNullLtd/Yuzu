// Tests for tar_netqual_nstat — the pure (guard-free, no Apple headers) decode
// and mapping functions the macOS NstatClient (roadmap 2.2) is built from.
// The live kctl client (PF_SYSTEM/SYSPROTO_CONTROL socket, reader/query
// threads, #if defined(__APPLE__)) needs a live kernel and is not exercised
// here; what IS unit-testable everywhere is every decode/mapping free
// function in tar_netqual_nstat.hpp, by hand-building raw wire-format byte
// buffers matching the transcribed nstat_raw structs and feeding them to the
// decoders — see the header's "Pure/testable boundary" doc comment.

#include "tar_netqual_nstat.hpp"
#include "tar_netqual.hpp" // TcpQualitySample, remote_bucket

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace yuzu::tar;
using namespace yuzu::tar::nstat_raw;

namespace {

template <typename T>
std::vector<std::byte> to_bytes(const T& v) {
    std::vector<std::byte> out(sizeof(T));
    std::memcpy(out.data(), &v, sizeof(T));
    return out;
}

std::vector<std::byte> concat(std::vector<std::byte> a, const std::vector<std::byte>& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

/// Darwin sockaddr_in layout within the 28-byte sockaddr union: sa_family at
/// byte[1], port big-endian at bytes[2:4], address at bytes[4:8] — mirrors
/// nstat_decode_sockaddr() in the .cpp (never a system sockaddr type).
SockaddrBlob make_v4(std::array<std::uint8_t, 4> addr, std::uint16_t port) {
    SockaddrBlob b{};
    b.bytes[0] = 16;
    b.bytes[1] = kNstatAfInet;
    b.bytes[2] = static_cast<std::uint8_t>(port >> 8);
    b.bytes[3] = static_cast<std::uint8_t>(port & 0xFF);
    for (int i = 0; i < 4; ++i)
        b.bytes[4 + i] = addr[i];
    return b;
}

/// Darwin sockaddr_in6 layout: sa_family at byte[1], port at bytes[2:4],
/// address at bytes[8:24].
SockaddrBlob make_v6(std::array<std::uint8_t, 16> addr, std::uint16_t port) {
    SockaddrBlob b{};
    b.bytes[0] = 28;
    b.bytes[1] = kNstatAfInet6;
    b.bytes[2] = static_cast<std::uint8_t>(port >> 8);
    b.bytes[3] = static_cast<std::uint8_t>(port & 0xFF);
    for (int i = 0; i < 16; ++i)
        b.bytes[8 + i] = addr[i];
    return b;
}

/// Builds a 16-byte v6 address from 8 16-bit groups — far less error-prone
/// than hand-counting zero bytes for each test address.
std::array<std::uint8_t, 16> v6_from_groups(std::array<std::uint16_t, 8> g) {
    std::array<std::uint8_t, 16> out{};
    for (int i = 0; i < 8; ++i) {
        out[2 * i] = static_cast<std::uint8_t>(g[i] >> 8);
        out[2 * i + 1] = static_cast<std::uint8_t>(g[i] & 0xFF);
    }
    return out;
}

void set_cstr(char* dst, std::size_t cap, const char* s) {
    std::size_t n = std::strlen(s);
    if (n > cap)
        n = cap;
    std::memcpy(dst, s, n);
}

/// Writes `value` little-endian at absolute byte `offset` in `buf`, growing it
/// if needed. Used by the "golden byte" tests below to lay a message out at the
/// literal XNU offsets — decoding those proves WIRE compatibility, independent
/// of our own struct definitions (which the fixture-based tests reuse).
template <typename T>
void put_le(std::vector<std::byte>& buf, std::size_t offset, T value) {
    if (buf.size() < offset + sizeof(T))
        buf.resize(offset + sizeof(T));
    for (std::size_t i = 0; i < sizeof(T); ++i)
        buf[offset + i] = static_cast<std::byte>((value >> (8 * i)) & 0xFF);
}

/// Builds a full SRC_DESC datagram (fixed header + TCP descriptor) with a
/// correct declared length by default; `length_override` lets a test inject
/// a mismatched length to exercise the layout self-check.
std::vector<std::byte> build_src_desc_msg(std::uint64_t srcref, std::uint64_t provider,
                                          const TcpDescriptor& desc,
                                          std::uint16_t length_override = 0) {
    MsgSrcDescHeader head{};
    head.hdr.type = kNstatMsgSrcDesc;
    head.hdr.length = length_override != 0
                          ? length_override
                          : static_cast<std::uint16_t>(sizeof(MsgSrcDescHeader) +
                                                       sizeof(TcpDescriptor));
    head.srcref = srcref;
    head.provider = provider;
    return concat(to_bytes(head), to_bytes(desc));
}

} // namespace

// ── Header decode ───────────────────────────────────────────────────────────

TEST_CASE("nstat_decode_header decodes a valid header", "[tar][netqual][nstat]") {
    NstatMsgHdr hdr{};
    hdr.context = 0xdeadbeef;
    hdr.type = kNstatMsgSrcAdded;
    hdr.length = 32;
    hdr.flags = 7;

    auto decoded = nstat_decode_header(to_bytes(hdr));
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->context == 0xdeadbeef);
    REQUIRE(decoded->type == kNstatMsgSrcAdded);
    REQUIRE(decoded->length == 32);
    REQUIRE(decoded->flags == 7);
}

TEST_CASE("nstat_decode_header rejects a too-short buffer", "[tar][netqual][nstat]") {
    std::vector<std::byte> short_buf(sizeof(NstatMsgHdr) - 1);
    REQUIRE_FALSE(nstat_decode_header(short_buf).has_value());
    std::vector<std::byte> empty_buf;
    REQUIRE_FALSE(nstat_decode_header(empty_buf).has_value());
}

// ── Datagram framing (multi-message recv, XNU accumulation) ──────────────────

TEST_CASE("nstat_frame_messages splits concatenated SRC_ADDED + SRC_COUNTS in one buffer",
          "[tar][netqual][nstat]") {
    // XNU's accumulator batches records back-to-back into one datagram, so a
    // single recv() can carry several messages; the reader must dispatch every
    // one. This is the regression guard for the "decode only the first, drop
    // the rest" bug — the failure mode hits hardest during the ADD_ALL_SRCS
    // burst, exactly the feature's primary use case.
    MsgSrcAdded added{};
    added.hdr.type = kNstatMsgSrcAdded;
    added.hdr.length = sizeof(MsgSrcAdded);
    added.provider = kNstatProviderTcp;
    added.srcref = 0x1111;

    MsgSrcCounts counts{};
    counts.hdr.type = kNstatMsgSrcCounts;
    counts.hdr.length = sizeof(MsgSrcCounts);
    counts.srcref = 0x2222;

    auto buf = concat(to_bytes(added), to_bytes(counts));
    auto msgs = nstat_frame_messages(buf);

    REQUIRE(msgs.size() == 2);
    // Each subspan is exactly its declared length and decodes independently.
    REQUIRE(msgs[0].size() == sizeof(MsgSrcAdded));
    REQUIRE(msgs[1].size() == sizeof(MsgSrcCounts));
    auto d0 = nstat_decode_src_added(msgs[0]);
    REQUIRE(d0.has_value());
    REQUIRE(d0->srcref == 0x1111);
    auto d1 = nstat_decode_src_counts(msgs[1]);
    REQUIRE(d1.has_value());
    REQUIRE(d1->srcref == 0x2222);
}

TEST_CASE("nstat_frame_messages frames a burst of three SRC_ADDED records",
          "[tar][netqual][nstat]") {
    std::vector<std::byte> buf;
    for (std::uint64_t ref : {0xA1u, 0xB2u, 0xC3u}) {
        MsgSrcAdded m{};
        m.hdr.type = kNstatMsgSrcAdded;
        m.hdr.length = sizeof(MsgSrcAdded);
        m.provider = kNstatProviderTcp;
        m.srcref = ref;
        buf = concat(buf, to_bytes(m));
    }
    auto msgs = nstat_frame_messages(buf);
    REQUIRE(msgs.size() == 3);
    REQUIRE(nstat_decode_src_added(msgs[0])->srcref == 0xA1u);
    REQUIRE(nstat_decode_src_added(msgs[2])->srcref == 0xC3u);
}

TEST_CASE("nstat_frame_messages yields the single message unchanged",
          "[tar][netqual][nstat]") {
    MsgSrcAdded m{};
    m.hdr.type = kNstatMsgSrcAdded;
    m.hdr.length = sizeof(MsgSrcAdded);
    auto msgs = nstat_frame_messages(to_bytes(m));
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].size() == sizeof(MsgSrcAdded));
}

TEST_CASE("nstat_frame_messages keeps complete frames and stops at a truncated trailer",
          "[tar][netqual][nstat]") {
    // A complete SRC_ADDED followed by a header that declares a length the
    // buffer can't satisfy: the good frame is returned, the partial one dropped
    // rather than read past the buffer.
    MsgSrcAdded good{};
    good.hdr.type = kNstatMsgSrcAdded;
    good.hdr.length = sizeof(MsgSrcAdded);
    good.srcref = 0x55;

    NstatMsgHdr partial{};
    partial.type = kNstatMsgSrcCounts;
    partial.length = sizeof(MsgSrcCounts); // declares 144B but only 16B follow

    auto buf = concat(to_bytes(good), to_bytes(partial));
    auto msgs = nstat_frame_messages(buf);
    REQUIRE(msgs.size() == 1);
    REQUIRE(nstat_decode_src_added(msgs[0])->srcref == 0x55);
}

TEST_CASE("nstat_frame_messages stops on a zero declared length rather than spinning",
          "[tar][netqual][nstat]") {
    // A header claiming length 0 must not advance the offset by zero forever.
    NstatMsgHdr zero{};
    zero.type = kNstatMsgSrcAdded;
    zero.length = 0;
    auto msgs = nstat_frame_messages(to_bytes(zero));
    REQUIRE(msgs.empty());
}

TEST_CASE("nstat_frame_messages returns nothing for a buffer shorter than a header",
          "[tar][netqual][nstat]") {
    std::vector<std::byte> tiny(sizeof(NstatMsgHdr) - 1);
    REQUIRE(nstat_frame_messages(tiny).empty());
    REQUIRE(nstat_frame_messages({}).empty());
}

// ── nstat_subscription_rejected — the ERROR-reply demote latch ─────────────

TEST_CASE("nstat_subscription_rejected demotes only once BOTH subscriptions are rejected",
          "[tar][netqual][nstat]") {
    bool tcp = false, tcp_kernel = false;

    SECTION("an unrelated context latches nothing") {
        REQUIRE_FALSE(nstat_subscription_rejected(0, tcp, tcp_kernel));
        REQUIRE_FALSE(nstat_subscription_rejected(0xdeadbeef, tcp, tcp_kernel));
        REQUIRE_FALSE(tcp);
        REQUIRE_FALSE(tcp_kernel);
    }

    SECTION("one rejected subscription is informational, not a demote") {
        REQUIRE_FALSE(nstat_subscription_rejected(kNstatCtxSubscribeTcp, tcp, tcp_kernel));
        REQUIRE(tcp);
        REQUIRE_FALSE(tcp_kernel);
        // A repeat of the same rejection still doesn't demote.
        REQUIRE_FALSE(nstat_subscription_rejected(kNstatCtxSubscribeTcp, tcp, tcp_kernel));
    }

    SECTION("both rejected demotes, in either order") {
        REQUIRE_FALSE(nstat_subscription_rejected(kNstatCtxSubscribeTcpKernel, tcp, tcp_kernel));
        REQUIRE(nstat_subscription_rejected(kNstatCtxSubscribeTcp, tcp, tcp_kernel));
    }

    SECTION("an unrelated context between the two rejections does not reset the latches") {
        REQUIRE_FALSE(nstat_subscription_rejected(kNstatCtxSubscribeTcp, tcp, tcp_kernel));
        REQUIRE_FALSE(nstat_subscription_rejected(7, tcp, tcp_kernel));
        REQUIRE(nstat_subscription_rejected(kNstatCtxSubscribeTcpKernel, tcp, tcp_kernel));
    }
}

// ── nstat_length_matches_expected — the layout-mismatch guard ──────────────

TEST_CASE("nstat_length_matches_expected accepts exact fixed-size lengths",
          "[tar][netqual][nstat]") {
    REQUIRE(nstat_length_matches_expected(kNstatMsgSrcAdded, sizeof(MsgSrcAdded)));
    REQUIRE(nstat_length_matches_expected(kNstatMsgSrcRemoved, sizeof(MsgSrcRemoved)));
    REQUIRE(nstat_length_matches_expected(kNstatMsgSrcCounts, sizeof(MsgSrcCounts)));
}

TEST_CASE("nstat_length_matches_expected rejects a mismatched fixed-size length — "
          "the transcription-disagrees-with-kernel guard",
          "[tar][netqual][nstat]") {
    // A mismatched length means OUR transcribed struct disagrees with THIS
    // kernel's wire layout; the caller must fail closed rather than decode
    // (and potentially emit) a plausible-but-wrong value.
    REQUIRE_FALSE(nstat_length_matches_expected(kNstatMsgSrcAdded, sizeof(MsgSrcAdded) - 1));
    REQUIRE_FALSE(nstat_length_matches_expected(kNstatMsgSrcAdded, sizeof(MsgSrcAdded) + 1));
    REQUIRE_FALSE(nstat_length_matches_expected(kNstatMsgSrcRemoved, sizeof(MsgSrcRemoved) - 4));
    REQUIRE_FALSE(nstat_length_matches_expected(kNstatMsgSrcCounts, sizeof(MsgSrcCounts) - 8));
}

TEST_CASE("nstat_length_matches_expected treats SRC_DESC as a variable-length floor",
          "[tar][netqual][nstat]") {
    const auto floor = sizeof(MsgSrcDescHeader) + sizeof(TcpDescriptor);
    REQUIRE(nstat_length_matches_expected(kNstatMsgSrcDesc, static_cast<std::uint16_t>(floor)));
    REQUIRE(
        nstat_length_matches_expected(kNstatMsgSrcDesc, static_cast<std::uint16_t>(floor + 16)));
    REQUIRE_FALSE(
        nstat_length_matches_expected(kNstatMsgSrcDesc, static_cast<std::uint16_t>(floor - 1)));
}

TEST_CASE("nstat_length_matches_expected passes through an unvalidated message type",
          "[tar][netqual][nstat]") {
    REQUIRE(nstat_length_matches_expected(kNstatMsgError, 0));
    REQUIRE(nstat_length_matches_expected(999999, 12345));
}

// ── SRC_ADDED / SRC_REMOVED decode ──────────────────────────────────────────

TEST_CASE("nstat_decode_src_added extracts provider and srcref", "[tar][netqual][nstat]") {
    MsgSrcAdded msg{};
    msg.hdr.type = kNstatMsgSrcAdded;
    msg.hdr.length = sizeof(MsgSrcAdded);
    msg.provider = kNstatProviderTcp;
    msg.srcref = 0x1122334455667788ULL;

    auto decoded = nstat_decode_src_added(to_bytes(msg));
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->provider == kNstatProviderTcp);
    REQUIRE(decoded->srcref == 0x1122334455667788ULL);
}

TEST_CASE("nstat_decode_src_added rejects a too-short buffer", "[tar][netqual][nstat]") {
    MsgSrcAdded msg{};
    msg.hdr.type = kNstatMsgSrcAdded;
    msg.hdr.length = sizeof(MsgSrcAdded);
    msg.provider = kNstatProviderTcp;
    msg.srcref = 42;
    auto full = to_bytes(msg);
    // Header parses (>=16 bytes) and its declared length still checks out,
    // but the actual buffer is short of the full fixed-size struct.
    std::vector<std::byte> truncated(full.begin(), full.begin() + 20);
    REQUIRE_FALSE(nstat_decode_src_added(truncated).has_value());
}

TEST_CASE("nstat_decode_src_added rejects a length-mismatched message",
          "[tar][netqual][nstat]") {
    MsgSrcAdded msg{};
    msg.hdr.type = kNstatMsgSrcAdded;
    msg.hdr.length = sizeof(MsgSrcAdded) - 1; // declared length disagrees with our struct
    msg.provider = kNstatProviderTcp;
    msg.srcref = 42;
    REQUIRE_FALSE(nstat_decode_src_added(to_bytes(msg)).has_value());
}

TEST_CASE("nstat_decode_src_added rejects the wrong message type", "[tar][netqual][nstat]") {
    MsgSrcAdded msg{};
    msg.hdr.type = kNstatMsgSrcRemoved; // wrong type in the header
    msg.hdr.length = sizeof(MsgSrcAdded);
    REQUIRE_FALSE(nstat_decode_src_added(to_bytes(msg)).has_value());
}

TEST_CASE("nstat_decode_src_removed extracts srcref", "[tar][netqual][nstat]") {
    MsgSrcRemoved msg{};
    msg.hdr.type = kNstatMsgSrcRemoved;
    msg.hdr.length = sizeof(MsgSrcRemoved);
    msg.srcref = 0xaabbccdd;

    auto decoded = nstat_decode_src_removed(to_bytes(msg));
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->srcref == 0xaabbccdd);
}

TEST_CASE("nstat_decode_src_removed rejects a too-short buffer", "[tar][netqual][nstat]") {
    MsgSrcRemoved msg{};
    msg.hdr.type = kNstatMsgSrcRemoved;
    msg.hdr.length = sizeof(MsgSrcRemoved);
    msg.srcref = 42;
    auto full = to_bytes(msg);
    // Exactly the 16-byte common header, no srcref payload.
    std::vector<std::byte> truncated(full.begin(), full.begin() + 16);
    REQUIRE_FALSE(nstat_decode_src_removed(truncated).has_value());
}

// ── TCP descriptor decode ───────────────────────────────────────────────────

TEST_CASE("nstat_decode_tcp_src_desc decodes an IPv4 flow", "[tar][netqual][nstat]") {
    TcpDescriptor desc{};
    desc.local = make_v4({127, 0, 0, 1}, 8443);
    desc.remote = make_v4({93, 184, 216, 34}, 443);
    desc.pid = 4321;
    set_cstr(desc.pname, sizeof(desc.pname), "testproc");

    auto raw = build_src_desc_msg(0x99, kNstatProviderTcp, desc);
    auto decoded = nstat_decode_tcp_src_desc(raw);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->srcref == 0x99);
    REQUIRE(decoded->proto == "tcp");
    REQUIRE(decoded->local_addr == "127.0.0.1");
    REQUIRE(decoded->local_port == 8443);
    REQUIRE(decoded->remote_addr == "93.184.216.34");
    REQUIRE(decoded->remote_port == 443);
    REQUIRE(decoded->pid == 4321);
    REQUIRE(decoded->process_name == "testproc");
}

TEST_CASE("nstat_decode_tcp_src_desc decodes the pname process identity",
          "[tar][netqual][nstat]") {
    // The macOS 13.3 tcp descriptor carries only pname (no epname/uid).
    TcpDescriptor desc{};
    desc.local = make_v4({10, 0, 0, 5}, 1);
    desc.remote = make_v4({10, 0, 0, 6}, 2);
    set_cstr(desc.pname, sizeof(desc.pname), "onlypname");

    auto decoded = nstat_decode_tcp_src_desc(build_src_desc_msg(1, kNstatProviderTcp, desc));
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->process_name == "onlypname");
}

TEST_CASE("nstat_decode_tcp_src_desc decodes IPv6 in RFC5952 canonical form and buckets it "
          "correctly",
          "[tar][netqual][nstat]") {
    // ::1 — loopback, maximal compression.
    {
        TcpDescriptor desc{};
        auto loopback = v6_from_groups({0, 0, 0, 0, 0, 0, 0, 1});
        desc.local = make_v6(loopback, 1);
        desc.remote = make_v6(loopback, 2);
        auto decoded = nstat_decode_tcp_src_desc(build_src_desc_msg(1, kNstatProviderTcp, desc));
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->proto == "tcp6");
        REQUIRE(decoded->local_addr == "::1");
        REQUIRE(decoded->remote_addr == "::1");
        REQUIRE(remote_bucket(decoded->remote_addr) == "loopback");
    }
    // fe80::1 — link-local.
    {
        TcpDescriptor desc{};
        auto link_local = v6_from_groups({0xfe80, 0, 0, 0, 0, 0, 0, 1});
        desc.local = make_v6(link_local, 1);
        desc.remote = make_v6(link_local, 2);
        auto decoded = nstat_decode_tcp_src_desc(build_src_desc_msg(2, kNstatProviderTcp, desc));
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->remote_addr == "fe80::1");
        REQUIRE(remote_bucket(decoded->remote_addr) == "private");
    }
    // 2001:db8::1 — global/public, with an interior zero-run compressed.
    {
        TcpDescriptor desc{};
        auto global = v6_from_groups({0x2001, 0x0db8, 0, 0, 0, 0, 0, 1});
        desc.local = make_v6(global, 1);
        desc.remote = make_v6(global, 2);
        auto decoded = nstat_decode_tcp_src_desc(build_src_desc_msg(3, kNstatProviderTcp, desc));
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->remote_addr == "2001:db8::1");
        REQUIRE(remote_bucket(decoded->remote_addr) == "public");
    }
    // ::ffff:192.168.1.1 — IPv4-mapped, classified by the embedded v4
    // (private) so an internal dual-stack peer isn't mislabelled "public".
    {
        TcpDescriptor desc{};
        auto mapped = v6_from_groups({0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101});
        desc.local = make_v6(mapped, 1);
        desc.remote = make_v6(mapped, 2);
        auto decoded = nstat_decode_tcp_src_desc(build_src_desc_msg(4, kNstatProviderTcp, desc));
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->remote_addr == "::ffff:192.168.1.1");
        REQUIRE(remote_bucket(decoded->remote_addr) == "private");
    }
}

TEST_CASE("nstat_decode_tcp_src_desc rejects a too-short buffer", "[tar][netqual][nstat]") {
    MsgSrcDescHeader head{};
    head.hdr.type = kNstatMsgSrcDesc;
    head.hdr.length =
        static_cast<std::uint16_t>(sizeof(MsgSrcDescHeader) + sizeof(TcpDescriptor));
    head.srcref = 1;
    head.provider = kNstatProviderTcp;
    auto full = to_bytes(head);
    // Header decodes (type matches) but the buffer is short of even the
    // fixed MsgSrcDescHeader, let alone the TCP descriptor that follows it.
    std::vector<std::byte> truncated(full.begin(), full.begin() + 20);
    REQUIRE_FALSE(nstat_decode_tcp_src_desc(truncated).has_value());
}

TEST_CASE("nstat_decode_tcp_src_desc rejects a non-TCP provider", "[tar][netqual][nstat]") {
    TcpDescriptor desc{};
    desc.local = make_v4({127, 0, 0, 1}, 1);
    desc.remote = make_v4({127, 0, 0, 1}, 2);
    auto raw = build_src_desc_msg(1, /*provider=*/999, desc);
    REQUIRE_FALSE(nstat_decode_tcp_src_desc(raw).has_value());
}

TEST_CASE("nstat_decode_tcp_src_desc rejects a self-check length mismatch",
          "[tar][netqual][nstat]") {
    TcpDescriptor desc{};
    desc.local = make_v4({127, 0, 0, 1}, 1);
    desc.remote = make_v4({127, 0, 0, 1}, 2);
    // Declared length shorter than header+descriptor — our transcription
    // would disagree with this kernel's wire layout; must fail closed rather
    // than decode a truncated/misaligned descriptor.
    auto raw = build_src_desc_msg(1, kNstatProviderTcp, desc,
                                  static_cast<std::uint16_t>(sizeof(MsgSrcDescHeader) + 10));
    REQUIRE_FALSE(nstat_decode_tcp_src_desc(raw).has_value());
}

// ── Counts decode + apply ───────────────────────────────────────────────────

TEST_CASE("nstat_decode_src_counts extracts the counters netqual needs",
          "[tar][netqual][nstat]") {
    MsgSrcCounts msg{};
    msg.hdr.type = kNstatMsgSrcCounts;
    msg.hdr.length = sizeof(MsgSrcCounts);
    msg.srcref = 7;
    msg.counts.txpackets = 1000;
    msg.counts.txretransmit = 12;
    msg.counts.avg_rtt = 25000; // microseconds
    msg.counts.var_rtt = 500;

    auto decoded = nstat_decode_src_counts(to_bytes(msg));
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->srcref == 7);
    REQUIRE(decoded->txpackets == 1000);
    REQUIRE(decoded->txretransmit == 12);
    REQUIRE(decoded->avg_rtt == 25000);
    REQUIRE(decoded->var_rtt == 500);
}

TEST_CASE("nstat_decode_src_counts rejects a too-short buffer", "[tar][netqual][nstat]") {
    MsgSrcCounts msg{};
    msg.hdr.type = kNstatMsgSrcCounts;
    msg.hdr.length = sizeof(MsgSrcCounts);
    msg.srcref = 1;
    auto full = to_bytes(msg);
    // Header + srcref only, no counts payload.
    std::vector<std::byte> truncated(full.begin(), full.begin() + 30);
    REQUIRE_FALSE(nstat_decode_src_counts(truncated).has_value());
}

TEST_CASE("nstat_apply_counts updates FlowState's cumulative counters",
          "[tar][netqual][nstat]") {
    FlowState flow;
    DecodedCounts c;
    c.srcref = 1;
    c.txpackets = 200;
    c.txretransmit = 3;
    c.avg_rtt = 15000;
    c.var_rtt = 250;

    REQUIRE_FALSE(flow.has_counts);
    nstat_apply_counts(flow, c);
    REQUIRE(flow.has_counts);
    REQUIRE(flow.rtt_us == 15000);
    REQUIRE(flow.rtt_var_us == 250);
    REQUIRE(flow.txpackets_cum == 200);
    REQUIRE(flow.txretransmit_cum == 3);
    // apply_counts never touches the delta baseline itself — only
    // nstat_advance_snapshot_baseline() does (doc comment on both functions).
    REQUIRE(flow.txretransmit_prev_snapshot == 0);
}

// ── Golden wire-layout bytes (XNU absolute offsets) ─────────────────────────
// These build message buffers at the LITERAL byte offsets XNU's
// bsd/net/ntstat.h produces (revision 9 / macOS 13.3) — NOT via our own
// nstat_raw structs. They fail if a decoder reads a field from the wrong
// offset even when our struct definition happens to agree with itself, which
// is the exact false-confidence gap a struct-derived fixture cannot catch.

TEST_CASE("golden: SRC_ADDED reads srcref@16 and provider@24 (field order + width)",
          "[tar][netqual][nstat]") {
    std::vector<std::byte> buf(sizeof(MsgSrcAdded), std::byte{0});
    put_le<std::uint32_t>(buf, 8, kNstatMsgSrcAdded);            // hdr.type @8
    put_le<std::uint16_t>(buf, 12, sizeof(MsgSrcAdded));          // hdr.length @12
    put_le<std::uint64_t>(buf, 16, 0xCAFEF00DDEADBEEFULL);        // srcref @16 (u64)
    put_le<std::uint32_t>(buf, 24, kNstatProviderTcp);            // provider @24 (u32)

    auto decoded = nstat_decode_src_added(buf);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->srcref == 0xCAFEF00DDEADBEEFULL);
    REQUIRE(decoded->provider == kNstatProviderTcp);
}

TEST_CASE("golden: SRC_COUNTS reads the u32 counters after all ten u64 counters",
          "[tar][netqual][nstat]") {
    // counts starts at 32; txpackets is counts+16=48; the u32 block begins at
    // counts+80=112, so txretransmit=counts+88=120, avg_rtt=counts+104=136,
    // var_rtt=counts+108=140. A struct that interleaved u32s earlier (the
    // pre-remediation bug) would read these from ~counts+32 and get garbage.
    std::vector<std::byte> buf(sizeof(MsgSrcCounts), std::byte{0});
    put_le<std::uint32_t>(buf, 8, kNstatMsgSrcCounts);
    put_le<std::uint16_t>(buf, 12, sizeof(MsgSrcCounts));
    put_le<std::uint64_t>(buf, 16, 77);   // srcref @16
    put_le<std::uint64_t>(buf, 48, 1000); // counts.txpackets @48
    put_le<std::uint32_t>(buf, 120, 12);  // counts.txretransmit @120
    put_le<std::uint32_t>(buf, 136, 25000); // counts.avg_rtt @136
    put_le<std::uint32_t>(buf, 140, 500);   // counts.var_rtt @140

    auto decoded = nstat_decode_src_counts(buf);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->srcref == 77);
    REQUIRE(decoded->txpackets == 1000);
    REQUIRE(decoded->txretransmit == 12);
    REQUIRE(decoded->avg_rtt == 25000);
    REQUIRE(decoded->var_rtt == 500);
}

TEST_CASE("golden: SRC_DESC reads pid@156, local@164, pname@236 (post-13.3-prefix)",
          "[tar][netqual][nstat]") {
    // header is 40 bytes; descriptor starts at 40. Within the descriptor:
    // pid=+116=156, local(sockaddr union)=+124=164, pname=+196=236.
    const std::size_t total = sizeof(MsgSrcDescHeader) + sizeof(TcpDescriptor); // 376
    std::vector<std::byte> buf(total, std::byte{0});
    put_le<std::uint32_t>(buf, 8, kNstatMsgSrcDesc);       // hdr.type @8
    put_le<std::uint16_t>(buf, 12, static_cast<std::uint16_t>(total)); // hdr.length @12
    put_le<std::uint64_t>(buf, 16, 0xABCD);                // srcref @16
    put_le<std::uint32_t>(buf, 32, kNstatProviderTcp);     // provider @32
    put_le<std::uint32_t>(buf, 156, 4321);                 // descriptor.pid @156
    // descriptor.local sockaddr_in @164: sa_len@164, family@165, port@166..167,
    // addr@168..171.
    buf[164] = std::byte{16};
    buf[165] = std::byte{kNstatAfInet};
    buf[166] = std::byte{static_cast<std::uint8_t>(8443 >> 8)};
    buf[167] = std::byte{static_cast<std::uint8_t>(8443 & 0xFF)};
    buf[168] = std::byte{127};
    buf[171] = std::byte{1};
    // descriptor.remote sockaddr_in @192.
    buf[192] = std::byte{16};
    buf[193] = std::byte{kNstatAfInet};
    buf[194] = std::byte{static_cast<std::uint8_t>(443 >> 8)};
    buf[195] = std::byte{static_cast<std::uint8_t>(443 & 0xFF)};
    buf[196 + 0] = std::byte{93}; // remote addr starts at 192+4=196
    buf[196 + 1] = std::byte{184};
    buf[196 + 2] = std::byte{216};
    buf[196 + 3] = std::byte{34};
    // descriptor.pname @236.
    const char* pname = "goldenproc";
    for (std::size_t i = 0; pname[i]; ++i)
        buf[236 + i] = static_cast<std::byte>(pname[i]);

    auto decoded = nstat_decode_tcp_src_desc(buf);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->srcref == 0xABCD);
    REQUIRE(decoded->pid == 4321);
    REQUIRE(decoded->local_addr == "127.0.0.1");
    REQUIRE(decoded->local_port == 8443);
    REQUIRE(decoded->remote_addr == "93.184.216.34");
    REQUIRE(decoded->remote_port == 443);
    REQUIRE(decoded->process_name == "goldenproc");
}

// ── Quality-sample mapping — SIGNAL DISCIPLINE invariants ──────────────────

TEST_CASE("nstat_build_quality_sample copies rtt_us as an IDENTITY, not scaled",
          "[tar][netqual][nstat]") {
    FlowState flow;
    flow.proto = "tcp";
    flow.remote_addr = "1.2.3.4";
    DecodedCounts c;
    c.avg_rtt = 42; // already microseconds per the nstat wire format
    c.var_rtt = 7;
    nstat_apply_counts(flow, c);

    TcpQualitySample s = nstat_build_quality_sample(flow);
    REQUIRE(s.rtt_us == 42); // NOT *1000 — unlike the Windows ESTATS path (ms -> us)
    REQUIRE(s.rtt_var_us == 7);
}

TEST_CASE("nstat_build_quality_sample's lost is a per-tick delta, not the raw cumulative",
          "[tar][netqual][nstat]") {
    FlowState flow;
    flow.proto = "tcp";
    flow.remote_addr = "1.2.3.4";

    // First snapshot: 5 cumulative retransmits, no prior baseline (0) ->
    // delta == 5.
    DecodedCounts c1;
    c1.txretransmit = 5;
    c1.txpackets = 100;
    nstat_apply_counts(flow, c1);
    TcpQualitySample s1 = nstat_build_quality_sample(flow);
    REQUIRE(s1.lost == 5);       // per-tick delta
    REQUIRE(s1.retrans == 5);    // cumulative context
    REQUIRE(s1.segs_out == 100); // cumulative context
    REQUIRE(s1.ca_state == 3);   // retransmit activity this tick -> Recovery
    nstat_advance_snapshot_baseline(flow);

    // Second snapshot: cumulative unchanged since the baseline moved -> a
    // tick with no NEW retransmits must yield lost == 0.
    DecodedCounts c2;
    c2.txretransmit = 5;
    c2.txpackets = 140;
    nstat_apply_counts(flow, c2);
    TcpQualitySample s2 = nstat_build_quality_sample(flow);
    REQUIRE(s2.lost == 0);
    REQUIRE(s2.retrans == 5);    // cumulative, unchanged
    REQUIRE(s2.segs_out == 140); // cumulative context still tracks
    REQUIRE(s2.ca_state == 0);   // no retransmit activity this tick -> Open
    nstat_advance_snapshot_baseline(flow);

    // Third snapshot: 3 new retransmits since the second baseline.
    DecodedCounts c3;
    c3.txretransmit = 8;
    c3.txpackets = 150;
    nstat_apply_counts(flow, c3);
    TcpQualitySample s3 = nstat_build_quality_sample(flow);
    REQUIRE(s3.lost == 3);
    REQUIRE(s3.retrans == 8); // cumulative — never the delta
}

TEST_CASE("nstat_build_quality_sample clamps a decreasing counter (wrap/reset) to lost==0",
          "[tar][netqual][nstat]") {
    FlowState flow;
    flow.proto = "tcp";
    flow.remote_addr = "1.2.3.4";
    flow.txretransmit_cum = 8;
    flow.txretransmit_prev_snapshot = 8; // baseline from a previous tick

    // The counter went backwards (provider reset/wrap). nq_delta_clamped
    // must treat a negative delta as "unknown this tick", never emit a
    // negative or (via unsigned wraparound) huge bogus value.
    DecodedCounts c;
    c.txretransmit = 2;
    c.txpackets = 10;
    nstat_apply_counts(flow, c);

    TcpQualitySample s = nstat_build_quality_sample(flow);
    REQUIRE(s.lost == 0);
    REQUIRE(s.ca_state == 0);
}

// ── Snapshot baseline advance ───────────────────────────────────────────────

TEST_CASE("nstat_advance_snapshot_baseline moves the delta baseline to the current cumulative",
          "[tar][netqual][nstat]") {
    FlowState flow;
    flow.proto = "tcp";
    flow.txretransmit_cum = 17;
    flow.txretransmit_prev_snapshot = 0;

    nstat_advance_snapshot_baseline(flow);
    REQUIRE(flow.txretransmit_prev_snapshot == 17);

    // A subsequent tick with no new movement now reports lost == 0, measured
    // from the NEW baseline, not the original 0.
    TcpQualitySample s = nstat_build_quality_sample(flow);
    REQUIRE(s.lost == 0);
}

// ── Open/close event build ──────────────────────────────────────────────────

TEST_CASE("nstat_build_open_event carries the flow identity from the descriptor",
          "[tar][netqual][nstat]") {
    DecodedTcpDesc desc;
    desc.srcref = 55;
    desc.proto = "tcp";
    desc.local_addr = "10.0.0.1";
    desc.local_port = 4000;
    desc.remote_addr = "10.0.0.2";
    desc.remote_port = 443;
    desc.pid = 999;
    desc.process_name = "safari";

    NstatFlowEvent ev = nstat_build_open_event(1'700'000'000, desc);
    REQUIRE(ev.ts_unix == 1'700'000'000);
    REQUIRE(ev.is_open);
    REQUIRE(ev.proto == "tcp");
    REQUIRE(ev.local_addr == "10.0.0.1");
    REQUIRE(ev.local_port == 4000);
    REQUIRE(ev.remote_addr == "10.0.0.2");
    REQUIRE(ev.remote_port == 443);
    REQUIRE(ev.pid == 999);
    REQUIRE(ev.process_name == "safari");
}

TEST_CASE("nstat_build_close_event carries the last-known flow state", "[tar][netqual][nstat]") {
    FlowState flow;
    flow.proto = "tcp6";
    flow.local_addr = "::1";
    flow.local_port = 5000;
    flow.remote_addr = "2001:db8::1";
    flow.remote_port = 80;
    flow.pid = 321;
    flow.process_name = "curl";
    flow.has_desc = true;

    NstatFlowEvent ev = nstat_build_close_event(1'700'000'500, flow);
    REQUIRE(ev.ts_unix == 1'700'000'500);
    REQUIRE_FALSE(ev.is_open);
    REQUIRE(ev.proto == "tcp6");
    REQUIRE(ev.local_addr == "::1");
    REQUIRE(ev.local_port == 5000);
    REQUIRE(ev.remote_addr == "2001:db8::1");
    REQUIRE(ev.remote_port == 80);
    REQUIRE(ev.pid == 321);
    REQUIRE(ev.process_name == "curl");
}

// ── Stall detection ──────────────────────────────────────────────────────────

TEST_CASE("nstat_stream_is_stalled measures idle from the later of last-event/start",
          "[tar][netqual][nstat]") {
    const std::int64_t threshold = 3600;
    const std::int64_t start = 1'700'000'000;

    // Fresh start, no event yet (last_event_ts == 0): idle measured from start.
    REQUIRE_FALSE(nstat_stream_is_stalled(0, start, start + 100, threshold));  // quiet but young
    REQUIRE(nstat_stream_is_stalled(0, start, start + 3601, threshold));      // silent past threshold

    // Once events have arrived, idle is measured from the LAST event, not start.
    const std::int64_t last = start + 10'000;
    REQUIRE_FALSE(nstat_stream_is_stalled(last, start, last + 60, threshold)); // recent event
    REQUIRE(nstat_stream_is_stalled(last, start, last + 3601, threshold));     // silent since last

    // Neither set (clock never initialised) -> never stalls (no spurious fallback).
    REQUIRE_FALSE(nstat_stream_is_stalled(0, 0, 9'999, threshold));
    // Backward clock step (now < since) -> negative delta -> not stalled (benign).
    REQUIRE_FALSE(nstat_stream_is_stalled(last, start, last - 500, threshold));
}
