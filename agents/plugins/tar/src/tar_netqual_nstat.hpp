#pragma once

/**
 * tar_netqual_nstat.hpp — macOS `NstatClient`: ONE kernel-control (kctl) client
 * over `com.apple.network.statistics` feeding BOTH the netqual per-connection
 * quality snapshot AND the tcp lifecycle (open/close) event stream.
 *
 * Roadmap 2.1 (spike memo `~/.claude/plans/nstat-spike-2.1-memo.md`) found that
 * nstat's message set contains exactly the two shapes 2.2 needs from one source
 * table: SRC_ADDED/SRC_REMOVED are the lifecycle events; SRC_DESC/SRC_COUNTS
 * carry the per-flow tcp_connection_info-shaped payload that becomes a
 * TcpQualitySample. This header is that client — see memo §1/§2/§4 for the
 * design this mirrors.
 *
 * Mechanism (memo §1): nstat is the kernel's network-statistics kernel control,
 * reached via a `PF_SYSTEM`/`SYSPROTO_CONTROL` socket — the same kctl transport
 * `utun` and friends use. No framework link, no entitlement (unlike Endpoint
 * Security / #239): `dependency('appleframeworks', ...)` is NOT needed here,
 * only libSystem headers (`<sys/kern_control.h>`, `<sys/sys_domain.h>`,
 * `<sys/ioctl.h>`).
 *
 * Shape (memo §4.1): follows the `ProcStreamCollector` contract
 * (start/stop/running/drain/dropped/kernel_dropped/stalled/method_name) but is
 * NOT a `ProcStreamCollector` subclass — the drained event type is a tcp 4-tuple
 * open/close (`NstatFlowEvent`), not a `ProcEvent`, so the base interface (fixed
 * to `std::vector<ProcEvent>`) doesn't fit. This is the documented streaming-
 * source exception in `docs/tar-implementer.md` §8.1 — the same reason
 * `ImageStreamCollector` is a sibling interface, not a subclass: the contract,
 * not the base class, is the invariant. `EventRing<T>` is generic, so the
 * lifecycle ring is `EventRing<NstatFlowEvent>` — the SAME backpressure idiom,
 * reused, not forked. `snapshot_quality()` is the one extra verb the streaming
 * contract has no room for: a live-table read (no drain) that answers the
 * netqual leg. Both legs read the SAME internal `srcref -> FlowState` table fed
 * by the nstat message stream — "two views over one source table" (memo §2).
 *
 * Wire layout risk (memo §6, HIGHEST): `nstat_msg_*` / `nstat_tcp_descriptor` /
 * `nstat_counts` are declared in XNU's open-source `bsd/net/ntstat.h`, so this
 * is a transcription, not a guess — but the interface is PRIVATE and
 * UNVERSIONED; Apple has changed field order/size across releases with no ABI
 * promise. The structs below are transcribed from the `bsd/net/ntstat.h`
 * generation shipped with the macOS 13.x (Ventura) XNU releases, matching this
 * project's `-mmacosx-version-min=13.3` deployment floor
 * (`meson/native/macos-appleclang.ini`). They have NOT been validated against
 * real hardware (spike constraint: CLT-only box, no live client). Every decode
 * function below therefore gates on `nstat_length_matches_expected()` before
 * trusting the bytes — a declared-length mismatch means OUR transcription
 * disagrees with THIS kernel's wire layout, and the caller fails the message
 * (or, for the two simplest fixed-size types, the whole client) to an inert
 * state rather than ever emit a plausible-but-wrong rtt/loss number. See
 * `NstatClient::layout_mismatch()`.
 *
 * Pure/testable boundary: every struct in `nstat_raw` and every decode/mapping
 * free function below is plain data + arithmetic — no `<sys/kern_control.h>`,
 * no socket syscalls, no Apple headers of any kind. They compile and are
 * callable on any host (Linux CLT box included), which is how wave 2's unit
 * tests exercise the decode/mapping logic without a live client or root. Only
 * `NstatClient`'s socket/thread implementation (tar_netqual_nstat.cpp, guarded
 * `#if defined(__APPLE__)`) needs Apple headers.
 */

#include "tar_netqual.hpp"     // TcpQualitySample
#include "tar_proc_stream.hpp" // EventRing<T>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace yuzu::tar {

// ── Transcribed nstat wire structs (memo §1/§6) ────────────────────────────
//
// Plain fixed-width-int PODs, natural alignment (no #pragma pack — matches how
// the kernel struct itself is declared; static_asserts below pin the sizes AND
// the offsets we depend on so a future edit that reorders a field or
// introduces padding is caught at compile time). Deliberately independent of
// any system <sys/socket.h> `sockaddr` type: the wire bytes are always
// Darwin's layout regardless of the host this decoder runs on (a portable unit
// test on Linux must decode the SAME bytes a macOS kernel produced), so
// addresses are read by hand from the 28-byte sockaddr union (`SockaddrBlob`)
// at the known Darwin `sockaddr_in`/`sockaddr_in6` offsets — see
// nstat_decode_sockaddr() in the .cpp.
namespace nstat_raw {

// Every struct and every static_assert below is transcribed field-for-field
// from XNU `bsd/net/ntstat.h` (__NSTAT_REVISION__ 9, Ventura tag
// xnu-8792.41.9 — the macOS 13.3 deployment floor). The `offsetof`/`sizeof`
// asserts are the compile-time cross-check the review asked for: because that
// header is XNU-private (absent from the macOS SDK) it cannot be #included
// here, so instead every offset we actually read is pinned to the value the
// real layout produces. A future edit that reorders a field, changes a width,
// or introduces padding fails the build rather than silently misdecoding a
// kernel datagram. The natural-alignment layout (no #pragma pack) mirrors how
// the kernel declares these structs; the kernel's explicit
// `__attribute__((aligned(8)))` on post-header fields is a no-op here because
// each is already at an 8-aligned offset.

struct NstatMsgHdr {
    std::uint64_t context{0};
    std::uint32_t type{0};
    std::uint16_t length{0};
    std::uint16_t flags{0};
};
static_assert(sizeof(NstatMsgHdr) == 16);
static_assert(offsetof(NstatMsgHdr, context) == 0);
static_assert(offsetof(NstatMsgHdr, type) == 8);
static_assert(offsetof(NstatMsgHdr, length) == 12);
static_assert(offsetof(NstatMsgHdr, flags) == 14);

/// Raw sockaddr storage — exactly the size of Darwin's
/// `union { sockaddr_in; sockaddr_in6; }` (28 bytes: sockaddr_in6 is the
/// larger arm). Never interpreted via a system sockaddr type; the wire bytes
/// are always Darwin's layout regardless of the host running this decoder, so
/// addresses are read by hand at the known Darwin offsets — see
/// nstat_decode_sockaddr(). The 28-byte size is load-bearing: it sets the
/// offset of every TcpDescriptor field after `local`/`remote`.
struct alignas(4) SockaddrBlob {
    std::uint8_t bytes[28]{};
};
static_assert(sizeof(SockaddrBlob) == 28);

/// nstat_msg_add_all_srcs — the ADD_ALL_SRCS subscription request. All five
/// fields after the header are REQUIRED; a truncated request is rejected by
/// the kernel. `filter`/`events`/`target_pid`/`target_uuid` are left zero
/// (subscribe to every source for the provider, no event push — we poll via
/// QUERY_SRC); `provider` selects the source class.
struct MsgAddAllSrcs {
    NstatMsgHdr hdr;
    std::uint64_t filter{0};
    std::uint64_t events{0};
    std::uint32_t provider{0};
    std::int32_t target_pid{0};
    std::uint8_t target_uuid[16]{};
};
static_assert(sizeof(MsgAddAllSrcs) == 56);
static_assert(offsetof(MsgAddAllSrcs, provider) == 32);
static_assert(offsetof(MsgAddAllSrcs, target_pid) == 36);
static_assert(offsetof(MsgAddAllSrcs, target_uuid) == 40);

struct MsgGetSrcDesc {
    NstatMsgHdr hdr;
    std::uint64_t srcref{0};
};
static_assert(sizeof(MsgGetSrcDesc) == 24);
static_assert(offsetof(MsgGetSrcDesc, srcref) == 16);

struct MsgQuerySrc {
    NstatMsgHdr hdr;
    std::uint64_t srcref{0};
};
static_assert(sizeof(MsgQuerySrc) == 24);
static_assert(offsetof(MsgQuerySrc, srcref) == 16);

/// nstat_msg_src_added. Field ORDER and WIDTH matter: `srcref` (u64) precedes
/// `provider` (u32) + 4 reserved bytes — the reverse of a naive
/// {provider, srcref} transcription, which would misread both.
struct MsgSrcAdded {
    NstatMsgHdr hdr;
    std::uint64_t srcref{0};
    std::uint32_t provider{0};
    std::uint8_t reserved[4]{};
};
static_assert(sizeof(MsgSrcAdded) == 32);
static_assert(offsetof(MsgSrcAdded, srcref) == 16);
static_assert(offsetof(MsgSrcAdded, provider) == 24);

struct MsgSrcRemoved {
    NstatMsgHdr hdr;
    std::uint64_t srcref{0};
};
static_assert(sizeof(MsgSrcRemoved) == 24);
static_assert(offsetof(MsgSrcRemoved, srcref) == 16);

/// Fixed header of a SRC_DESC message (nstat_msg_src_description_header); the
/// provider-specific descriptor (TcpDescriptor for the TCP providers) follows
/// immediately in the datagram. `event_flags` sits between `srcref` and
/// `provider` — omitting it (as the pre-remediation layout did) shifts
/// `provider` and every following byte.
struct MsgSrcDescHeader {
    NstatMsgHdr hdr;
    std::uint64_t srcref{0};
    std::uint64_t event_flags{0};
    std::uint32_t provider{0};
    std::uint8_t reserved[4]{};
};
static_assert(sizeof(MsgSrcDescHeader) == 40);
static_assert(offsetof(MsgSrcDescHeader, srcref) == 16);
static_assert(offsetof(MsgSrcDescHeader, provider) == 32);

/// nstat_tcp_descriptor (TCP-provider SRC_DESC payload) at the macOS 13.3
/// layout. `local`/`remote` are the sockaddr union (28 bytes each), NOT
/// 128-byte blobs, and they sit AFTER the counter/pid block, not before it.
/// `pname` is a NUL-padded C string (not necessarily NUL-terminated at 64).
/// There is no `epname` and no `uid` at this OS floor (both were added in
/// later releases, after every field we read); the runtime length floor-check
/// tolerates the larger later-OS descriptor because those additions are all
/// past `pname` — see nstat_length_matches_expected().
struct TcpDescriptor {
    std::uint64_t upid{0};
    std::uint64_t eupid{0};
    std::uint64_t start_timestamp{0};
    std::uint64_t timestamp{0};
    std::uint64_t rx_transfer_size{0};
    std::uint64_t tx_transfer_size{0};
    std::uint64_t activity_start{0};   // activity_bitmap_t.start
    std::uint64_t activity_bitmap[2]{}; // activity_bitmap_t.bitmap (128-bit)
    std::uint32_t ifindex{0};
    std::uint32_t state{0};
    std::uint32_t sndbufsize{0};
    std::uint32_t sndbufused{0};
    std::uint32_t rcvbufsize{0};
    std::uint32_t rcvbufused{0};
    std::uint32_t txunacked{0};
    std::uint32_t txwindow{0};
    std::uint32_t txcwindow{0};
    std::uint32_t traffic_class{0};
    std::uint32_t traffic_mgt_flags{0};
    std::uint32_t pid{0};
    std::uint32_t epid{0};
    SockaddrBlob local;
    SockaddrBlob remote;
    char cc_algo[16]{};
    char pname[64]{};
    std::uint8_t uuid[16]{};
    std::uint8_t euuid[16]{};
    std::uint8_t vuuid[16]{};
    std::uint8_t fuuid[16]{};
    std::uint32_t conn_status{0}; // tcp_conn_status union (4 bytes on our arches)
    std::uint32_t ifnet_properties{0};
    std::uint8_t fallback_mode{0};
    std::uint8_t reserved[3]{};
};
static_assert(sizeof(TcpDescriptor) == 336);
static_assert(offsetof(TcpDescriptor, pid) == 116);
static_assert(offsetof(TcpDescriptor, epid) == 120);
static_assert(offsetof(TcpDescriptor, local) == 124);
static_assert(offsetof(TcpDescriptor, remote) == 152);
static_assert(offsetof(TcpDescriptor, pname) == 196);

/// nstat_counts, embedded in a SRC_COUNTS message. All ten u64 counters come
/// FIRST (base rx/tx, then cell/wifi/wired rx/tx), then the eight u32 counters
/// — the pre-remediation layout interleaved them, which read every field past
/// the first 32 bytes from the wrong offset while still summing to 112.
struct Counts {
    std::uint64_t rxpackets{0};
    std::uint64_t rxbytes{0};
    std::uint64_t txpackets{0};
    std::uint64_t txbytes{0};
    std::uint64_t cell_rxbytes{0};
    std::uint64_t cell_txbytes{0};
    std::uint64_t wifi_rxbytes{0};
    std::uint64_t wifi_txbytes{0};
    std::uint64_t wired_rxbytes{0};
    std::uint64_t wired_txbytes{0};
    std::uint32_t rxduplicatebytes{0};
    std::uint32_t rxoutoforderbytes{0};
    std::uint32_t txretransmit{0};
    std::uint32_t connectattempts{0};
    std::uint32_t connectsuccesses{0};
    std::uint32_t min_rtt{0};
    std::uint32_t avg_rtt{0};
    std::uint32_t var_rtt{0};
};
static_assert(sizeof(Counts) == 112);
static_assert(offsetof(Counts, txpackets) == 16);
static_assert(offsetof(Counts, txretransmit) == 88);
static_assert(offsetof(Counts, avg_rtt) == 104);
static_assert(offsetof(Counts, var_rtt) == 108);

/// nstat_msg_src_counts — like the SRC_DESC header, `event_flags` sits between
/// `srcref` and the embedded counts.
struct MsgSrcCounts {
    NstatMsgHdr hdr;
    std::uint64_t srcref{0};
    std::uint64_t event_flags{0};
    Counts counts;
};
static_assert(sizeof(MsgSrcCounts) == 144);
static_assert(offsetof(MsgSrcCounts, srcref) == 16);
static_assert(offsetof(MsgSrcCounts, counts) == 32);

} // namespace nstat_raw

// ── Message type / provider constants ──────────────────────────────────────
// Values are the literal `enum` members of XNU `bsd/net/ntstat.h`
// (__NSTAT_REVISION__ 9, Ventura tag xnu-8792.41.9): request codes live in the
// 100x band, async response/notify codes in the 1000x band, and the two
// control replies (SUCCESS/ERROR) are 0/1 — NOT a sequential-from-2 scheme.
inline constexpr std::uint32_t kNstatMsgError = 1;         // NSTAT_MSG_TYPE_ERROR
inline constexpr std::uint32_t kNstatMsgAddAllSrcs = 1002; // NSTAT_MSG_TYPE_ADD_ALL_SRCS

// Request contexts for the two ADD_ALL_SRCS subscriptions (echoed back in the
// kernel's SUCCESS/ERROR control reply `hdr.context`). Non-zero and distinct so
// an NSTAT_MSG_TYPE_ERROR can be attributed to the specific subscription it
// rejects — a rejected subscription must demote the client promptly (poll
// fallback), not hide behind the 1-hour idle-stall threshold.
inline constexpr std::uint64_t kNstatCtxSubscribeTcp = 0xA1;
inline constexpr std::uint64_t kNstatCtxSubscribeTcpKernel = 0xA2;

/// Pure decision for the NSTAT_MSG_TYPE_ERROR handler: latch a rejection for
/// whichever subscription the control reply's `context` names (an unrelated
/// context latches nothing), and return true only once BOTH subscriptions have
/// been rejected — the point at which the client can never receive a flow and
/// must demote to the poll fallback immediately.
inline bool nstat_subscription_rejected(std::uint64_t context, bool& tcp_rejected,
                                        bool& tcp_kernel_rejected) noexcept {
    if (context == kNstatCtxSubscribeTcp)
        tcp_rejected = true;
    else if (context == kNstatCtxSubscribeTcpKernel)
        tcp_kernel_rejected = true;
    return tcp_rejected && tcp_kernel_rejected;
}
inline constexpr std::uint32_t kNstatMsgQuerySrc = 1004;   // NSTAT_MSG_TYPE_QUERY_SRC
inline constexpr std::uint32_t kNstatMsgGetSrcDesc = 1005; // NSTAT_MSG_TYPE_GET_SRC_DESC
inline constexpr std::uint32_t kNstatMsgSrcAdded = 10001;  // NSTAT_MSG_TYPE_SRC_ADDED
inline constexpr std::uint32_t kNstatMsgSrcRemoved = 10002; // NSTAT_MSG_TYPE_SRC_REMOVED
inline constexpr std::uint32_t kNstatMsgSrcDesc = 10003;   // NSTAT_MSG_TYPE_SRC_DESC
inline constexpr std::uint32_t kNstatMsgSrcCounts = 10004; // NSTAT_MSG_TYPE_SRC_COUNTS

/// TCP_KERNEL (legacy) and TCP (modern alias, aka TCP_USERLAND) provider ids.
/// start() subscribes to BOTH (memo §1: "NSTAT_PROVIDER_TCP / ..._TCP_KERNEL")
/// since which one a given kernel expects is itself part of the layout risk;
/// subscribing to an id a kernel doesn't recognize is harmless (it simply
/// yields no sources for that id).
inline constexpr std::uint32_t kNstatProviderTcpKernel = 2; // NSTAT_PROVIDER_TCP_KERNEL
inline constexpr std::uint32_t kNstatProviderTcp = 3;       // NSTAT_PROVIDER_TCP_USERLAND

/// Darwin AF_INET / AF_INET6 values as they appear in the wire `sockaddr`
/// family byte — Darwin's AF_INET6 (30) differs from Linux's (10), and the
/// bytes decoded here always come from a Darwin kernel regardless of which
/// host runs the decoder, so these are NOT the host's own <sys/socket.h>
/// constants (deliberately not included).
inline constexpr std::uint8_t kNstatAfInet = 2;
inline constexpr std::uint8_t kNstatAfInet6 = 30;

// ── Pure decode: raw datagram bytes -> our structs ──────────────────────────

struct DecodedMsgHeader {
    std::uint64_t context{0};
    std::uint32_t type{0};
    std::uint16_t length{0};
    std::uint16_t flags{0};
};

/// PURE. Reads the 16-byte nstat_msg_hdr common to every message. nullopt if
/// `raw` is shorter than the header.
std::optional<DecodedMsgHeader> nstat_decode_header(std::span<const std::byte> raw) noexcept;

/// PURE. Splits one received datagram into its constituent message subspans.
/// A single kctl SOCK_DGRAM recv() can carry SEVERAL nstat messages: XNU's
/// nstat_accumulate_msg()/nstat_flush_accumulated_msgs() batch records
/// back-to-back into one mbuf (no inter-message padding), so a burst of
/// SRC_ADDED during the ADD_ALL_SRCS bulk subscribe, or a SRC_DESC followed
/// immediately by SRC_COUNTS, arrives concatenated. Each subspan spans exactly
/// one message, sized by that message's declared `nstat_msg_hdr.length`.
/// Framing stops (returning what was framed so far) at the first frame whose
/// declared length can't hold the common header or would overrun the buffer —
/// a truncated trailing frame the kernel should never emit for SOCK_DGRAM.
std::vector<std::span<const std::byte>>
nstat_frame_messages(std::span<const std::byte> buf);

/// PURE. The runtime offset/size self-check (memo §6 risk 1): true when a
/// decoded `nstat_msg_hdr.length` matches what OUR transcribed struct expects
/// for `type`. Fixed-size types (SrcAdded/SrcRemoved/SrcCounts) require an
/// EXACT match; SrcDesc is variable (header + provider-specific descriptor) so
/// it requires `length` to be at least the TCP descriptor's total size — the
/// decode functions additionally bounds-check the actual buffer, so a `true`
/// return here is necessary but not sufficient for a given call to succeed.
/// Any `false` here means OUR transcription disagrees with THIS kernel's wire
/// layout for this message type: the caller must never decode further and
/// must fail toward the inert state (see NstatClient::layout_mismatch()).
bool nstat_length_matches_expected(std::uint32_t type, std::uint16_t length) noexcept;

struct DecodedSrcAdded {
    std::uint64_t provider{0};
    std::uint64_t srcref{0};
};
/// PURE. Decodes a SRC_ADDED message. nullopt on a too-short buffer or a
/// length/self-check mismatch (nstat_length_matches_expected).
std::optional<DecodedSrcAdded> nstat_decode_src_added(std::span<const std::byte> raw) noexcept;

struct DecodedSrcRemoved {
    std::uint64_t srcref{0};
};
/// PURE. Decodes a SRC_REMOVED message.
std::optional<DecodedSrcRemoved> nstat_decode_src_removed(std::span<const std::byte> raw) noexcept;

/// One decoded TCP flow identity (SRC_DESC payload, TCP provider only).
struct DecodedTcpDesc {
    std::uint64_t srcref{0};
    std::string proto;        ///< "tcp" | "tcp6" (from the sockaddr family)
    std::string local_addr;   ///< numeric, canonical (IPv6 RFC5952-compressed)
    int local_port{0};
    std::string remote_addr;  ///< raw — bucketed downstream by remote_bucket(), never persisted as-is
    int remote_port{0};
    std::uint32_t pid{0};
    std::string process_name; ///< pname; "" if empty (the macOS 13.3 tcp descriptor has no epname/uid)
};
/// PURE. Decodes a SRC_DESC message whose embedded provider is
/// kNstatProviderTcp/kNstatProviderTcpKernel into a DecodedTcpDesc. Returns
/// nullopt for: a too-short buffer, a non-TCP provider (defensive — the
/// client only subscribes TCP providers, but a stray message must not be
/// mis-decoded as one), or a self-check length mismatch.
/// NOT noexcept: builds std::string fields (address formatting, process name),
/// which can allocate — unlike the fixed-size-only decoders above.
std::optional<DecodedTcpDesc> nstat_decode_tcp_src_desc(std::span<const std::byte> raw);

/// One decoded flow's counters (SRC_COUNTS payload).
struct DecodedCounts {
    std::uint64_t srcref{0};
    std::uint64_t txpackets{0};    ///< cumulative — proxy for segs_out
    std::uint32_t txretransmit{0}; ///< cumulative retransmits — NEVER feed raw into TcpQualitySample.lost (memo §6.3)
    std::uint32_t avg_rtt{0};      ///< believed MICROSECONDS already (memo §6.2) — TODO(hardware-verify)
    std::uint32_t var_rtt{0};      ///< same units as avg_rtt
};
/// PURE. Decodes a SRC_COUNTS message.
std::optional<DecodedCounts> nstat_decode_src_counts(std::span<const std::byte> raw) noexcept;

// ── Flow table + lifecycle event (memo §2/§4.1) ─────────────────────────────

/// One tcp open/close event decoded from the nstat stream — the lifecycle
/// leg's analogue of ProcEvent. A dedicated type (not ProcEvent) because a tcp
/// flow needs the 4-tuple ProcEvent has no fields for; EventRing<T> is generic
/// so EventRing<NstatFlowEvent> reuses the exact same backpressure idiom.
struct NstatFlowEvent {
    std::int64_t ts_unix{0};
    bool is_open{true}; ///< true = SRC_ADDED+first SRC_DESC ("open"); false = SRC_REMOVED ("close")
    std::string proto;  ///< "tcp" | "tcp6"
    std::string local_addr;
    int local_port{0};
    std::string remote_addr; ///< raw — same privacy posture as TcpQualitySample::remote_addr
    int remote_port{0};
    std::uint32_t pid{0};
    std::string process_name;
};

/// The lifecycle-event ring — EventRing<T> reused verbatim (tar_proc_stream.hpp),
/// not forked, per the ProcStreamCollector precedent.
using NstatFlowEventRing = EventRing<NstatFlowEvent>;

/// One live flow's accumulated state, keyed by nstat_src_ref_t in the client's
/// internal table. Fed by SRC_ADDED (creates the entry) / SRC_DESC (identity)
/// / SRC_COUNTS (quality) / SRC_REMOVED (erases the entry) — the ADDED -> DESC
/// -> COUNTS -> REMOVED state machine from memo §2. Also the input to the pure
/// mapping functions below, so it is a plain header-visible struct (no Apple
/// headers) even though only the guarded NstatClient ever owns a live table of
/// these.
struct FlowState {
    std::string proto;
    std::string local_addr;
    int local_port{0};
    std::string remote_addr;
    int remote_port{0};
    std::uint32_t pid{0};
    std::string process_name;
    bool has_desc{false};   ///< a SRC_DESC has been applied — identity fields valid
    bool has_counts{false}; ///< a SRC_COUNTS has been applied at least once — quality fields valid
    std::int64_t rtt_us{0};
    std::int64_t rtt_var_us{0};
    std::uint64_t txpackets_cum{0};    ///< latest known cumulative tx packets (segs_out proxy)
    std::uint64_t txretransmit_cum{0}; ///< latest known cumulative retransmits
    /// The txretransmit_cum value as of the PREVIOUS snapshot_quality() tick —
    /// the previous-counters snapshot memo §6.3 calls for, so `lost` can be a
    /// per-tick DELTA (nq_delta_clamped, tar_netqual.hpp:216) instead of the
    /// cumulative counter nstat actually exposes. 0 (== "no prior snapshot")
    /// on the flow's first tick, which the delta clamp already treats safely.
    std::uint64_t txretransmit_prev_snapshot{0};
    /// Monotonic seconds (nstat_mono_seconds) of the last message that touched
    /// this flow (ADDED/DESC/COUNTS). The flow reaper (UP-2) evicts entries not
    /// updated within kNstatFlowStaleSeconds — a live flow is refreshed by the
    /// 2s QUERY_SRC/SRC_COUNTS cycle; a flow whose SRC_REMOVED was lost stops
    /// updating and is reaped, so a dropped removal can never leak forever.
    std::int64_t last_update_mono{0};
};

// ── Pure mapping: decoded messages -> FlowState mutations ──────────────────

/// PURE. Applies a decoded SRC_DESC to `flow` (identity fields + has_desc).
void nstat_apply_tcp_desc(FlowState& flow, const DecodedTcpDesc& desc);

/// PURE. Applies a decoded SRC_COUNTS to `flow` (quality fields + has_counts).
/// Does NOT touch txretransmit_prev_snapshot — only
/// nstat_advance_snapshot_baseline() (called once per snapshot_quality() tick,
/// not once per SRC_COUNTS message, which can arrive more often) moves that.
void nstat_apply_counts(FlowState& flow, const DecodedCounts& counts) noexcept;

// ── Pure mapping: FlowState -> the two consumer-facing shapes ──────────────

/// PURE. Builds the lifecycle "open" event from a flow's first SRC_DESC.
NstatFlowEvent nstat_build_open_event(std::int64_t ts_unix, const DecodedTcpDesc& desc);

/// PURE. Builds the lifecycle "close" event from the last known state of a
/// flow that has just received SRC_REMOVED. `last_known` must have
/// has_desc == true (callers skip emitting a close event for a flow that was
/// removed before its identity was ever resolved — there is nothing
/// meaningful to report).
NstatFlowEvent nstat_build_close_event(std::int64_t ts_unix, const FlowState& last_known);

/// PURE. Derives one TcpQualitySample from a live flow. `lost` is
/// nq_delta_clamped(txretransmit_cum, txretransmit_prev_snapshot) — the
/// per-tick delta, never the raw cumulative (memo §6.3, SIGNAL DISCIPLINE,
/// tar_netqual.hpp:19-33). `retrans`/`segs_out` stay cumulative context.
/// `rtt_us`/`rtt_var_us` are an IDENTITY copy of the decoded counters
/// (TODO(hardware-verify): confirm nstat rtt is microseconds on real
/// hardware, memo §6.2 — unlike Windows ESTATS, which is milliseconds and
/// needs *1000, tar_netqual.hpp:258). `ca_state` is a minimal two-state
/// synthesis (0=Open, 3=Recovery on any retransmit delta this tick) — nstat's
/// transcribed Counts has no timeout/dup-ack/ECN counters to support the
/// finer-grained nq_win_ca_state-style mapping Windows uses; TODO(hardware-verify)
/// widen the transcription if XNU exposes them and align the two mappings.
/// Caller (NstatClient::snapshot_quality) must have already checked
/// has_desc && has_counts.
TcpQualitySample nstat_build_quality_sample(const FlowState& flow);

/// PURE. Advances `flow`'s per-tick delta baseline
/// (txretransmit_prev_snapshot = txretransmit_cum). Call exactly once per
/// flow per snapshot_quality() tick, AFTER nstat_build_quality_sample() — kept
/// as a separate step (not fused into the builder) so tests can inspect the
/// computed delta before the baseline moves.
void nstat_advance_snapshot_baseline(FlowState& flow) noexcept;

// ── Stall detection (memo §4.2 — mirrors the ES stalled() contract) ────────

/// PURE. True when a stream that is nominally alive should be presumed dead:
/// it has delivered nothing for longer than `threshold_seconds`. Same shape
/// as yuzu/agent/es_client.hpp's es_stream_is_stalled (kept as its own named
/// function, not a cross-collector call, since the two streams' health
/// semantics are conceptually independent even though the arithmetic is
/// identical).
bool nstat_stream_is_stalled(std::int64_t last_event_ts, std::int64_t started_ts, std::int64_t now,
                             std::int64_t threshold_seconds) noexcept;

// ── The live client ──────────────────────────────────────────────────────

/// Owns the ONE kctl socket to com.apple.network.statistics, a background
/// reader thread (decode + route only — memo §4.2), a lightweight query
/// thread (periodic NSTAT_MSG_TYPE_QUERY_SRC refresh per known flow, so
/// counts stay current without a second socket/subscription), and the
/// internal srcref -> FlowState table both consumer legs read.
///
/// Single-owner, non-copyable, non-movable (owns a live socket + two
/// threads) — the ProcEsCollector precedent. NOT an EsClientBroker: nstat has
/// exactly one consumer surface (this plugin, feeding two of its own legs),
/// so there is no cross-ABI sharing to broker (memo §4.3).
///
/// Off-macOS every method is a no-op / returns empty; start() returns false.
class NstatClient {
public:
    /// `ring_capacity` bounds buffered-but-undrained lifecycle events.
    explicit NstatClient(std::size_t ring_capacity = 20000);
    ~NstatClient();

    NstatClient(const NstatClient&) = delete;
    NstatClient& operator=(const NstatClient&) = delete;
    NstatClient(NstatClient&&) = delete;
    NstatClient& operator=(NstatClient&&) = delete;

    /// Opens the kctl socket, subscribes both TCP provider ids, and starts
    /// the reader + query threads. Returns false off-macOS, if already
    /// running, or on any socket/ioctl/connect failure — callers fall back to
    /// the existing sysctl poll cleanly (memo §2: the poll is NOT deleted).
    bool start();

    /// Stops the threads (closing the socket first to unblock the reader's
    /// blocking recv) and joins them. Safe if not started.
    void stop();

    /// False once started() has self-detected it is no longer functioning —
    /// either stop() was called, the socket died, or a layout mismatch forced
    /// the fail-to-inert path (layout_mismatch()). Unlike a stream with no
    /// way to detect its own death (Endpoint Security), the nstat reader
    /// thread's exit IS the detection, so this flips immediately rather than
    /// only after an idle timeout. Reads a client-owned atomic ONLY — never
    /// dereferences impl_ — so it is always safe to call concurrently with
    /// stop() (HIGH-1 fix); the reader thread clears it (via a borrowed
    /// pointer, same idiom as kernel_dropped_/last_event_ts_/layout_mismatch_
    /// below) the instant it exits for any reason, and stop() also clears it
    /// explicitly before impl_.reset().
    bool running() const noexcept;

    /// Moves buffered lifecycle (open/close) events out for the batched
    /// tar.db write. Drains the client-owned ring REGARDLESS of running(), so
    /// the plugin's death/stall-transition drain can still recover events the
    /// reader buffered just before a fatal exit (R2-1/HIGH-5). Empty off-macOS
    /// or when no events are buffered.
    std::vector<NstatFlowEvent> drain();

    /// Lifecycle events dropped due to ring overflow since construction.
    std::uint64_t dropped() const noexcept;

    /// Desync signal (memo §4.2): a SRC_DESC/SRC_COUNTS referencing an
    /// unknown srcref, or (TODO(hardware-verify): unconfirmed on real
    /// hardware, memo §6 risk 6) an ENOBUFS on recv. 0 off-macOS / before
    /// start. Persists across a stop()->restart, like ProcEsCollector's.
    std::uint64_t kernel_dropped() const noexcept;

    /// True when the stream is nominally running() but has gone quiet past
    /// the idle-fallback threshold — mirrors the ES stalled() contract
    /// (tar_proc_stream.hpp:173). Always false off-macOS / before start.
    bool stalled() const noexcept;

    /// Flows evicted by the UP-2 bound since construction: reaped as stale (a
    /// lost SRC_REMOVED) or dropped at the hard cap. Non-zero here is the
    /// observable signal of a leaking/oversized kernel-flow table. 0 off-macOS.
    std::uint64_t flow_reaped() const noexcept;

    /// Current live flow-table cardinality (Impl::flows.size()), mirrored to a
    /// client-owned atomic so a status read never dereferences impl_ or takes
    /// flows_mu. 0 off-macOS / not running.
    std::int64_t flow_table_size() const noexcept;

    /// True when the runtime layout self-check (nstat_length_matches_expected)
    /// forced the client to an inert state — a fixed-size message's declared
    /// length disagreed with our transcribed struct. Reset at the start of
    /// each start() (a fresh attempt gets a fresh chance) but persists for the
    /// remainder of the session it tripped in, during which running() is
    /// false and method_name() reports "none". Always false off-macOS.
    bool layout_mismatch() const noexcept;

    /// True when this session is seeing SYSTEM-WIDE flows rather than only
    /// this process's own (memo §3: unprivileged access is scoped to
    /// own-process flows; system-wide needs root). Proxied by the effective
    /// uid at start() — the agent's production LaunchDaemon runs as root, so
    /// this is expected true there and honestly false in an unprivileged dev
    /// run. Always false when not running() / off-macOS — callers must NEVER
    /// treat a non-system-wide session as complete capture.
    bool system_wide() const noexcept;

    /// "nstat" while running() and not layout_mismatch(); "none" otherwise
    /// (not started, stopped, or self-failed to the inert state). Deliberately
    /// does NOT fold system_wide() in here — a constrained (own-process-only)
    /// capture is still real capture via the nstat mechanism, just not
    /// complete; callers report completeness via system_wide() separately so
    /// "nstat but constrained" is never conflated with "none" (memo §3: no
    /// silent partial capture, but constrained-and-honest is not "none"
    /// either).
    const char* method_name() const noexcept;

    /// The netqual leg (memo §4.1, §2): reads the live flow table — NO drain,
    /// repeatable, always reflects the current tick's state — and maps every
    /// live TCP flow with both an identity (SRC_DESC) and at least one
    /// counters snapshot (SRC_COUNTS) to a TcpQualitySample. Empty when not
    /// running() / off-macOS. Advances each included flow's per-tick delta
    /// baseline as a side effect (nstat_advance_snapshot_baseline) — calling
    /// this twice in immediate succession will report `lost` as 0 the second
    /// time, by design (there is no new cumulative-counter movement to diff
    /// against yet).
    ///
    /// HIGH-1 fix: takes client_mu_ for its entire body (the running_ check
    /// AND the impl_ read), so a concurrent stop() can never free impl_ while
    /// this is reading it — see client_mu_'s doc comment for the ordering
    /// argument.
    std::vector<TcpQualitySample> snapshot_quality() const;

private:
    struct Impl; ///< kctl socket + reader/query threads + flow table; defined only in the .cpp
    std::unique_ptr<Impl> impl_;
    NstatFlowEventRing ring_;

    // Cross-thread stream-health state, kept on the CLIENT (which outlives
    // impl_) rather than on Impl — mirrors ProcEsCollector's rationale
    // verbatim: kernel_dropped()/stalled() must be safely readable by a
    // status-command thread without racing a concurrent stop()/impl_.reset().
    // [[maybe_unused]]: the no-op (non-Apple) build never touches these.
    [[maybe_unused]] std::atomic<std::uint64_t> kernel_dropped_{0};
    [[maybe_unused]] std::atomic<std::int64_t> last_event_ts_{0};
    [[maybe_unused]] std::atomic<std::int64_t> started_ts_{0};
    [[maybe_unused]] std::atomic<bool> layout_mismatch_{false};
    [[maybe_unused]] std::atomic<bool> system_wide_{false};
    // UP-2: flow-table bound observability — same borrowed-atomic idiom so a
    // status read never touches impl_/flows_mu.
    [[maybe_unused]] std::atomic<std::uint64_t> flow_reaped_{0};
    [[maybe_unused]] std::atomic<std::int64_t> flow_table_size_{0};

    // HIGH-1 fix: collector-owned running flag. Set true at the END of a
    // successful start() (after impl_ is published) and false at the START
    // of stop() (before impl_.reset()); the reader thread ALSO clears it
    // (through a borrowed pointer, same idiom as kernel_dropped/last_event_ts
    // /layout_mismatch above) the instant its own loop exits for any reason,
    // preserving the immediate self-detection the old impl_->thread_alive
    // check gave -- just relocated so running() never dereferences impl_.
    [[maybe_unused]] std::atomic<bool> running_{false};

    // HIGH-1 fix: the innermost lock. Guards the impl_-touching bodies of
    // snapshot_quality()/drain() and is taken by stop() before impl_.reset(),
    // so a concurrent reader and a concurrent teardown are mutually
    // exclusive -- impl_ can never be freed while snapshot_quality()/drain()
    // is reading it. Lock order: the plugin's collect_mu_ may already be
    // held by whatever calls into drain()/snapshot_quality()/stop() (all
    // three are called under collect_mu_ today), but client_mu_ itself never
    // calls back out to the plugin nor takes any other lock while held --
    // so there is no cycle. mutable: snapshot_quality() is const.
    mutable std::mutex client_mu_;
};

} // namespace yuzu::tar
