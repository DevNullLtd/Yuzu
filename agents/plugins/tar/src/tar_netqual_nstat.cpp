/**
 * tar_netqual_nstat.cpp — NstatClient (see tar_netqual_nstat.hpp).
 *
 * Layout: pure decode/mapping functions first (compile + unit-test on every
 * platform, no Apple headers), then the live socket/thread client guarded
 * `#if defined(__APPLE__)`, then the off-macOS no-op path.
 */

#include "tar_netqual_nstat.hpp"

#include "tar_netqual.hpp" // nq_delta_clamped

#include <cstring>
#include <format>

namespace yuzu::tar {

// ── Pure decode (cross-platform, unit-tested everywhere) ──────────────────

std::optional<DecodedMsgHeader> nstat_decode_header(std::span<const std::byte> raw) noexcept {
    if (raw.size() < sizeof(nstat_raw::NstatMsgHdr))
        return std::nullopt;
    nstat_raw::NstatMsgHdr hdr{};
    std::memcpy(&hdr, raw.data(), sizeof(hdr));
    return DecodedMsgHeader{hdr.context, hdr.type, hdr.length, hdr.flags};
}

std::vector<std::span<const std::byte>>
nstat_frame_messages(std::span<const std::byte> buf) {
    std::vector<std::span<const std::byte>> msgs;
    std::size_t off = 0;
    while (off + sizeof(nstat_raw::NstatMsgHdr) <= buf.size()) {
        const std::span<const std::byte> rest = buf.subspan(off);
        auto hdr = nstat_decode_header(rest);
        if (!hdr)
            break; // guarded by the while condition; defensive
        const std::size_t msg_len = hdr->length;
        // A declared length that can't hold even the common header, or that
        // overruns this datagram (a truncated trailing frame the kernel should
        // never emit for SOCK_DGRAM), means we can no longer frame safely —
        // stop rather than spin on a zero-length message or read past the end.
        if (msg_len < sizeof(nstat_raw::NstatMsgHdr) || off + msg_len > buf.size())
            break;
        msgs.push_back(rest.subspan(0, msg_len));
        off += msg_len;
    }
    return msgs;
}

bool nstat_length_matches_expected(std::uint32_t type, std::uint16_t length) noexcept {
    switch (type) {
    case kNstatMsgSrcAdded:
        return length == sizeof(nstat_raw::MsgSrcAdded);
    case kNstatMsgSrcRemoved:
        return length == sizeof(nstat_raw::MsgSrcRemoved);
    case kNstatMsgSrcCounts:
        return length == sizeof(nstat_raw::MsgSrcCounts);
    case kNstatMsgSrcDesc:
        // Variable-length: header + provider-specific descriptor. A FLOOR
        // check (>=), not an exact one, is deliberate and forward-compatible:
        // Apple grew nstat_tcp_descriptor after macOS 13.3 (adding fields past
        // `pname`, e.g. persona_id/uid), so a newer kernel sends a LARGER
        // descriptor. Every field we decode lives in the stable 13.3 prefix
        // (srcref/pid/local/remote/pname), so a longer descriptor still decodes
        // correctly; requiring an exact size would fail-closed on every macOS
        // release newer than the floor. The decoders additionally bounds-check
        // the actual buffer, so a `true` here is necessary, not sufficient.
        return length >= sizeof(nstat_raw::MsgSrcDescHeader) + sizeof(nstat_raw::TcpDescriptor);
    default:
        return true; // a type we don't validate has nothing of ours to check
    }
}

std::optional<DecodedSrcAdded> nstat_decode_src_added(std::span<const std::byte> raw) noexcept {
    auto hdr = nstat_decode_header(raw);
    if (!hdr || hdr->type != kNstatMsgSrcAdded)
        return std::nullopt;
    if (!nstat_length_matches_expected(hdr->type, hdr->length))
        return std::nullopt;
    if (raw.size() < sizeof(nstat_raw::MsgSrcAdded))
        return std::nullopt;
    nstat_raw::MsgSrcAdded msg{};
    std::memcpy(&msg, raw.data(), sizeof(msg));
    return DecodedSrcAdded{msg.provider, msg.srcref};
}

std::optional<DecodedSrcRemoved> nstat_decode_src_removed(std::span<const std::byte> raw) noexcept {
    auto hdr = nstat_decode_header(raw);
    if (!hdr || hdr->type != kNstatMsgSrcRemoved)
        return std::nullopt;
    if (!nstat_length_matches_expected(hdr->type, hdr->length))
        return std::nullopt;
    if (raw.size() < sizeof(nstat_raw::MsgSrcRemoved))
        return std::nullopt;
    nstat_raw::MsgSrcRemoved msg{};
    std::memcpy(&msg, raw.data(), sizeof(msg));
    return DecodedSrcRemoved{msg.srcref};
}

namespace {

/// Darwin sockaddr_in / sockaddr_in6 field offsets within the raw 28-byte
/// sockaddr union (sa_len[1] sa_family[1] port[2] ...) — NOT read via a system
/// sockaddr type; see the header comment on nstat_raw::SockaddrBlob.
std::string format_ipv4(const std::uint8_t* b) {
    return std::format("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
}

/// RFC5952 canonical (compressed, lowercase) IPv6 text form. Canonical form
/// is LOAD-BEARING here, not cosmetic: tar_netqual.hpp's remote_bucket()
/// pattern-matches on the compressed form ("::1", "fe8"/"fe9"/"fea"/"feb",
/// "fc"/"fd", "::ffff:") — an uncompressed decode would silently misclassify
/// loopback/link-local/unique-local/v4-mapped remotes into "public".
std::string format_ipv6_canonical(const std::uint8_t* b) {
    bool v4_mapped = true;
    for (int i = 0; i < 10 && v4_mapped; ++i)
        if (b[i] != 0)
            v4_mapped = false;
    if (v4_mapped && b[10] == 0xff && b[11] == 0xff)
        return std::format("::ffff:{}.{}.{}.{}", b[12], b[13], b[14], b[15]);

    std::uint16_t groups[8];
    for (int i = 0; i < 8; ++i)
        groups[i] = static_cast<std::uint16_t>((b[2 * i] << 8) | b[2 * i + 1]);

    // Longest run of >=2 consecutive zero groups gets compressed to "::".
    int best_start = -1, best_len = 0, i = 0;
    while (i < 8) {
        if (groups[i] == 0) {
            int j = i;
            while (j < 8 && groups[j] == 0)
                ++j;
            if (j - i > best_len) {
                best_len = j - i;
                best_start = i;
            }
            i = j;
        } else {
            ++i;
        }
    }

    std::string out;
    if (best_len >= 2) {
        for (i = 0; i < best_start; ++i) {
            out += std::format("{:x}", groups[i]);
            if (i < best_start - 1)
                out += ":";
        }
        out += "::";
        for (i = best_start + best_len; i < 8; ++i) {
            out += std::format("{:x}", groups[i]);
            if (i < 7)
                out += ":";
        }
    } else {
        for (i = 0; i < 8; ++i) {
            out += std::format("{:x}", groups[i]);
            if (i < 7)
                out += ":";
        }
    }
    return out;
}

struct DecodedAddr {
    std::string proto_suffix; // "" for v4, "6" for v6 — appended to "tcp"
    std::string addr;
    int port{0};
};

std::optional<DecodedAddr> nstat_decode_sockaddr(const nstat_raw::SockaddrBlob& blob) {
    const std::uint8_t family = blob.bytes[1];
    const int port = (static_cast<int>(blob.bytes[2]) << 8) | static_cast<int>(blob.bytes[3]);
    if (family == kNstatAfInet)
        return DecodedAddr{"", format_ipv4(&blob.bytes[4]), port};
    if (family == kNstatAfInet6)
        return DecodedAddr{"6", format_ipv6_canonical(&blob.bytes[8]), port};
    return std::nullopt; // not v4/v6 (e.g. an all-zero/unset blob) — not decodable
}

/// Fixed-size NUL-padded field -> std::string, stopping at the first NUL
/// (matches the ES collector's es_str / path_basename convention for
/// kernel-sourced fixed buffers that may not be fully NUL-terminated).
std::string cstr_from_fixed(const char* buf, std::size_t cap) {
    std::size_t n = 0;
    while (n < cap && buf[n] != '\0')
        ++n;
    return std::string(buf, n);
}

} // namespace

std::optional<DecodedTcpDesc> nstat_decode_tcp_src_desc(std::span<const std::byte> raw) {
    auto hdr = nstat_decode_header(raw);
    if (!hdr || hdr->type != kNstatMsgSrcDesc)
        return std::nullopt;
    if (raw.size() < sizeof(nstat_raw::MsgSrcDescHeader))
        return std::nullopt;

    nstat_raw::MsgSrcDescHeader head{};
    std::memcpy(&head, raw.data(), sizeof(head));
    // Defensive, not a layout concern: the client only subscribes TCP
    // providers, but a stray non-TCP descriptor must never be mis-decoded as
    // one rather than simply ignored.
    if (head.provider != kNstatProviderTcp && head.provider != kNstatProviderTcpKernel)
        return std::nullopt;

    if (!nstat_length_matches_expected(hdr->type, hdr->length))
        return std::nullopt;
    if (raw.size() < sizeof(nstat_raw::MsgSrcDescHeader) + sizeof(nstat_raw::TcpDescriptor))
        return std::nullopt;

    nstat_raw::TcpDescriptor desc{};
    std::memcpy(&desc, raw.data() + sizeof(nstat_raw::MsgSrcDescHeader), sizeof(desc));

    auto local = nstat_decode_sockaddr(desc.local);
    auto remote = nstat_decode_sockaddr(desc.remote);
    if (!local || !remote)
        return std::nullopt;

    DecodedTcpDesc out;
    out.srcref = head.srcref;
    out.proto = "tcp" + local->proto_suffix;
    out.local_addr = local->addr;
    out.local_port = local->port;
    out.remote_addr = remote->addr;
    out.remote_port = remote->port;
    out.pid = desc.pid;
    // The macOS 13.3 tcp descriptor carries only `pname` (the reporting
    // process); there is no effective-process name field at this OS floor, so
    // this is the single available process identity.
    out.process_name = cstr_from_fixed(desc.pname, sizeof(desc.pname));
    return out;
}

std::optional<DecodedCounts> nstat_decode_src_counts(std::span<const std::byte> raw) noexcept {
    auto hdr = nstat_decode_header(raw);
    if (!hdr || hdr->type != kNstatMsgSrcCounts)
        return std::nullopt;
    if (!nstat_length_matches_expected(hdr->type, hdr->length))
        return std::nullopt;
    if (raw.size() < sizeof(nstat_raw::MsgSrcCounts))
        return std::nullopt;
    nstat_raw::MsgSrcCounts msg{};
    std::memcpy(&msg, raw.data(), sizeof(msg));
    DecodedCounts out;
    out.srcref = msg.srcref;
    out.txpackets = msg.counts.txpackets;
    out.txretransmit = msg.counts.txretransmit;
    out.avg_rtt = msg.counts.avg_rtt;
    out.var_rtt = msg.counts.var_rtt;
    return out;
}

// ── Pure mapping (cross-platform, unit-tested everywhere) ─────────────────

void nstat_apply_tcp_desc(FlowState& flow, const DecodedTcpDesc& desc) {
    flow.proto = desc.proto;
    flow.local_addr = desc.local_addr;
    flow.local_port = desc.local_port;
    flow.remote_addr = desc.remote_addr;
    flow.remote_port = desc.remote_port;
    flow.pid = desc.pid;
    flow.process_name = desc.process_name;
    flow.has_desc = true;
}

void nstat_apply_counts(FlowState& flow, const DecodedCounts& counts) noexcept {
    // avg_rtt/var_rtt copied as-is — believed microseconds already, see the
    // TODO(hardware-verify) on TcpQualitySample::rtt_us in the header.
    flow.rtt_us = static_cast<std::int64_t>(counts.avg_rtt);
    flow.rtt_var_us = static_cast<std::int64_t>(counts.var_rtt);
    flow.txpackets_cum = counts.txpackets;
    flow.txretransmit_cum = counts.txretransmit;
    flow.has_counts = true;
}

NstatFlowEvent nstat_build_open_event(std::int64_t ts_unix, const DecodedTcpDesc& desc) {
    NstatFlowEvent ev;
    ev.ts_unix = ts_unix;
    ev.is_open = true;
    ev.proto = desc.proto;
    ev.local_addr = desc.local_addr;
    ev.local_port = desc.local_port;
    ev.remote_addr = desc.remote_addr;
    ev.remote_port = desc.remote_port;
    ev.pid = desc.pid;
    ev.process_name = desc.process_name;
    return ev;
}

NstatFlowEvent nstat_build_close_event(std::int64_t ts_unix, const FlowState& last_known) {
    NstatFlowEvent ev;
    ev.ts_unix = ts_unix;
    ev.is_open = false;
    ev.proto = last_known.proto;
    ev.local_addr = last_known.local_addr;
    ev.local_port = last_known.local_port;
    ev.remote_addr = last_known.remote_addr;
    ev.remote_port = last_known.remote_port;
    ev.pid = last_known.pid;
    ev.process_name = last_known.process_name;
    return ev;
}

TcpQualitySample nstat_build_quality_sample(const FlowState& flow) {
    TcpQualitySample s;
    s.proto = flow.proto;
    s.remote_addr = flow.remote_addr; // raw — bucketed downstream, never persisted as-is
    s.process_name = flow.process_name;
    s.rtt_us = flow.rtt_us;
    s.rtt_var_us = flow.rtt_var_us;
    // `lost` MUST be the per-tick delta, never the raw cumulative — memo §6.3 /
    // tar_netqual.hpp SIGNAL DISCIPLINE. Reuses the exact clamp Windows ESTATS
    // uses for the same reason (32/64-bit counter reset -> negative delta ==
    // "unknown this tick", never a real value).
    s.lost = nq_delta_clamped(static_cast<std::int64_t>(flow.txretransmit_cum),
                              static_cast<std::int64_t>(flow.txretransmit_prev_snapshot));
    s.retrans = static_cast<std::int64_t>(flow.txretransmit_cum); // cumulative — context only
    s.segs_out = static_cast<std::int64_t>(flow.txpackets_cum);   // cumulative — context only
    // Minimal two-state synthesis — see the header doc on this function for
    // why nstat's transcribed Counts can't support nq_win_ca_state's finer
    // Loss/Recovery/CWR/Disorder distinctions.
    s.ca_state = s.lost > 0 ? 3 : 0;
    return s;
}

void nstat_advance_snapshot_baseline(FlowState& flow) noexcept {
    flow.txretransmit_prev_snapshot = flow.txretransmit_cum;
}

bool nstat_stream_is_stalled(std::int64_t last_event_ts, std::int64_t started_ts, std::int64_t now,
                             std::int64_t threshold_seconds) noexcept {
    const std::int64_t since = (last_event_ts != 0) ? last_event_ts : started_ts;
    if (since <= 0)
        return false; // never started / clock uninitialised — don't fall back blindly
    return (now - since) > threshold_seconds;
}

} // namespace yuzu::tar

// The live kctl client compiles only on macOS. Off-macOS every NstatClient
// method is a no-op / returns empty and start() returns false so the caller
// falls back to the existing sysctl-based poll (enumerate_connections /
// collect_tcp_quality's Linux/Windows/other-macOS-fallback paths) cleanly.
// Unlike tar_proc_es.cpp's Endpoint Security guard (a lib+header pair
// needing its own build-time find_library()/has_header() probe -- see
// docs/darwin-compat.md's EndpointSecurity row), nstat needs NO detection
// macro at all: it is a plain kctl socket over libSystem
// (<sys/kern_control.h> etc.), always available on any macOS SDK — full
// Xcode or Command Line Tools alike.
#if defined(__APPLE__)

#include <spdlog/spdlog.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring> // std::strerror
#include <ctime>
#include <map>
#include <mutex>
#include <string.h> // strlcpy — a BSD extension, global-namespace-only, not in <cstring>/std::
#include <thread>
#include <vector>

namespace yuzu::tar {

namespace {

// Minimal single-owner fd holder for the kctl socket during start(): the fd
// has exactly one owner at all times (docs/cpp-conventions.md), so it lives in
// this guard from socket() until it is released into the Impl. Without it, a
// throw between connect() and `impl->fd = fd` (e.g. bad_alloc in make_unique)
// would leak the connected socket for the process lifetime. Same idiom as
// UniqueFd in subprocess_runner.cpp, kept local to avoid a cross-module dep.
class ScopedFd {
public:
    explicit ScopedFd(int fd) noexcept : fd_(fd) {}
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    ~ScopedFd() {
        if (fd_ >= 0)
            ::close(fd_);
    }
    int get() const noexcept { return fd_; }
    int release() noexcept {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

private:
    int fd_{-1};
};

// No liveness heartbeat exists for nstat (unlike an explicit "session ended"
// callback), so — mirroring the ES idle-fallback rationale — size this well
// beyond any plausible quiet period on a host with live TCP flows. Only
// consulted while running() is otherwise true (the reader thread hasn't
// itself detected its own death yet).
constexpr std::int64_t kNstatIdleFallbackSeconds = 3600;

// How often the query thread re-requests counts for every known flow
// (NSTAT_MSG_TYPE_QUERY_SRC per srcref — see the header doc on why this
// avoids depending on an uncertain-to-exist QUERY_ALL_SRCS message type).
constexpr auto kNstatQueryInterval = std::chrono::seconds(2);

// recv() buffer: comfortably larger than the largest message we decode
// (sizeof(MsgSrcDescHeader) + sizeof(TcpDescriptor) == 376 bytes at the 13.3
// floor; a later-OS descriptor is larger but still far under this).
constexpr std::size_t kNstatRecvBufSize = 8192;

// UP-2 flow-table bound. The kernel table is normally self-limiting (SRC_REMOVED
// erases a closed flow), but a LOST removal (ENOBUFS/kernel drop during a storm)
// would leak an entry forever. Two mechanisms keep it bounded: (a) a TTL reaper —
// query_loop re-queries every live flow every 2s, so a genuinely-open flow's
// last_update_mono stays fresh while a flow whose removal was lost stops getting
// SRC_COUNTS and goes stale; anything not updated within kNstatFlowStaleSeconds is
// reaped. (b) a hard-cap backstop for a burst faster than the reaper.
// UP-3: the reaper is a BACKSTOP for a lost SRC_REMOVED, not the primary close
// path — a flow closing sends SRC_REMOVED (which emits the CLOSED event and
// erases the entry directly). We only reach the reaper for a flow whose
// SRC_REMOVED we never saw. Keying eviction on counter-staleness assumes the 2s
// QUERY_SRC round-trip refreshes last_update_mono for a still-open flow (the
// SRC_COUNTS handler refreshes on ANY counts reply, changed or not); if the
// kernel silently omits COUNTS for a zero-delta idle flow — TODO(hardware-verify)
// — a live keep-alive could otherwise be reaped and its later CLOSED event lost.
// A wide window (150 query cycles) makes that false-eviction vanishingly likely
// while the 50k hard cap + the at-cap reap still bound the table.
constexpr std::int64_t kNstatFlowStaleSeconds = 300; // backstop for a lost SRC_REMOVED (UP-3)
constexpr std::size_t kNstatMaxFlows = 50000;       // backstop cap; drops+counts beyond it
// UP-2: consecutive fixed-size decode failures required before latching the
// permanent layout-mismatch demotion. A genuine transcription mismatch fails
// every message of that type so it reaches this in a burst; a single garbled
// datagram never does.
constexpr int kNstatMaxDecodeFailStreak = 3;

// Monotonic seconds for liveness/staleness comparisons (stall detection, the flow
// reaper) — never wall-clock time(), so an NTP/DST step cannot make a "seconds
// since" go negative and mis-decide a stall or a reap (UP-6). Event ts_unix that
// gets PERSISTED stays wall-clock (a real timestamp), separate from this.
inline std::int64_t nstat_mono_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

} // namespace

struct NstatClient::Impl {
    int fd{-1};
    NstatFlowEventRing* ring{nullptr};

    // Borrowed (non-owning) pointers to the CLIENT's stream-health atomics —
    // same ProcEsCollector rationale: kernel_dropped()/stalled() must stay
    // readable by a status-command thread without racing a concurrent
    // stop()/impl_.reset(), and the counters should persist across a
    // stop()->restart.
    std::atomic<std::uint64_t>* kernel_dropped{nullptr};
    std::atomic<std::int64_t>* last_event_ts{nullptr};
    std::atomic<bool>* layout_mismatch{nullptr};
    // HIGH-1 fix: borrowed (non-owning) pointer to the CLIENT's running_
    // atomic — same rationale as the three pointers above. The reader thread
    // clears *running the instant its own loop exits, for whatever reason
    // (stop() shut the socket down, a fatal recv error, or a layout-mismatch
    // self-heal); NstatClient::running() reads running_ directly and never
    // dereferences impl_, so this preserves the immediate self-detection the
    // old impl_->thread_alive check gave without the use-after-free race.
    std::atomic<bool>* running{nullptr};
    // UP-2: borrowed counters for the flow-table bound (same idiom as above).
    std::atomic<std::uint64_t>* flow_reaped{nullptr};
    std::atomic<std::int64_t>* flow_table_size{nullptr};

    std::thread reader_thread;
    std::thread query_thread;
    std::atomic<bool> stop_requested{false};

    // Per-subscription rejection latches (reader thread only — no atomics
    // needed). Subscribing both TCP provider ids is deliberately redundant
    // ("harmless if one is invalid for this kernel"), so a single rejection is
    // informational; BOTH rejected means the client can never receive a flow
    // and must demote to the poll now, not after the 1-hour idle stall.
    bool sub_tcp_rejected{false};
    bool sub_tcp_kernel_rejected{false};

    // UP-2: consecutive fixed-size decode failures, tracked PER MESSAGE TYPE
    // (reader thread only). A real layout mismatch fails every message of that
    // type, so its streak trips the threshold; a one-off garbled datagram resets
    // on the next good decode of the SAME type. Per-type (not one shared
    // counter) so a partial-ABI mismatch that fails only SRC_DESC still latches
    // even while healthy SRC_COUNTS keep arriving (Gate-7 review) — a good
    // SRC_COUNTS must not paper over a descriptor that never decodes.
    int decode_fail_streak_desc{0};
    int decode_fail_streak_counts{0};

    std::mutex query_cv_mu;
    std::condition_variable query_cv;

    mutable std::mutex flows_mu;
    std::map<std::uint64_t, FlowState> flows; // srcref -> FlowState, guarded by flows_mu

    Impl(NstatFlowEventRing* r, std::atomic<std::uint64_t>* kd, std::atomic<std::int64_t>* let,
         std::atomic<bool>* lm, std::atomic<bool>* rn, std::atomic<std::uint64_t>* fr,
         std::atomic<std::int64_t>* fts)
        : ring(r), kernel_dropped(kd), last_event_ts(let), layout_mismatch(lm), running(rn),
          flow_reaped(fr), flow_table_size(fts) {}

    // UP-2 reaper. Caller MUST hold flows_mu. Evicts flows not updated within
    // kNstatFlowStaleSeconds (a lost SRC_REMOVED stops refreshing them) and
    // republishes the live size. Returns the number reaped.
    std::size_t reap_stale_flows_locked(std::int64_t mono_now) {
        std::size_t reaped = 0;
        for (auto it = flows.begin(); it != flows.end();) {
            if (mono_now - it->second.last_update_mono > kNstatFlowStaleSeconds) {
                it = flows.erase(it);
                ++reaped;
            } else {
                ++it;
            }
        }
        if (reaped)
            flow_reaped->fetch_add(reaped, std::memory_order_relaxed);
        flow_table_size->store(static_cast<std::int64_t>(flows.size()), std::memory_order_relaxed);
        return reaped;
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    // Structural teardown (HIGH-2 fix): signal both threads, shutdown() the
    // socket to unblock the reader's blocking recv (memo §4.2 contract), wake
    // the query thread's condvar wait, JOIN both threads, and ONLY THEN close
    // the fd. Closing before the joins let a thread still holding the plain
    // `fd` int race a fd-number reuse by an unrelated open() elsewhere in the
    // process — a query/reader thread could then send()/recv() on a socket
    // that is no longer ours. shutdown() alone is sufficient to unblock recv;
    // the fd number itself must stay allocated (open) until neither thread
    // can touch it again, i.e. until both joins have returned.
    ~Impl() {
        stop_requested.store(true, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lk(query_cv_mu);
        }
        query_cv.notify_all();
        if (fd >= 0) {
            ::shutdown(fd, SHUT_RDWR);
        }
        if (query_thread.joinable())
            query_thread.join();
        if (reader_thread.joinable())
            reader_thread.join();
        // Only now, with both threads fully exited, is it safe to close the
        // fd and let the number be reused.
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }

    void send_msg(const void* data, std::size_t len) {
        if (fd < 0)
            return;
        const ssize_t n = ::send(fd, data, len, 0);
        if (n < 0)
            spdlog::debug("TAR: nstat send failed: {}", std::strerror(errno));
    }

    // Reader thread: DECODE + ROUTE ONLY (memo §4.2) — parse one message,
    // update the flow map under flows_mu, push at most one lifecycle event to
    // the ring. No persistence, no DNS, no rule eval here; that all happens
    // at drain()/snapshot_quality() time on the plugin tick thread.
    void handle_message(std::span<const std::byte> raw) {
        auto hdr = nstat_decode_header(raw);
        if (!hdr)
            return; // too short to even have a header — drop silently, not fatal

        const std::int64_t wall_now = static_cast<std::int64_t>(::time(nullptr)); // persisted event ts
        const std::int64_t mono = nstat_mono_seconds(); // liveness/reaper timestamps (UP-6)

        switch (hdr->type) {
        case kNstatMsgSrcAdded: {
            auto added = nstat_decode_src_added(raw);
            if (!added) {
                // This is our simplest fixed-size message type; a decode
                // failure here means our transcribed layout itself is wrong
                // for this kernel, not a one-off garbled datagram. Fail to
                // the inert state (memo §6 risk 1) rather than keep guessing.
                spdlog::warn("TAR: nstat SRC_ADDED decode mismatch — "
                            "transcribed layout disagrees with this kernel; "
                            "disabling the nstat client");
                layout_mismatch->store(true, std::memory_order_relaxed);
                stop_requested.store(true, std::memory_order_relaxed);
                return;
            }
            // UP-7: only track TCP-provider sources. We subscribe only TCP
            // providers, but a non-TCP source arriving (provider-id ambiguity)
            // would create a permanent has_desc=false orphan we never query a
            // DESC for — a concrete leak into the flow table. Drop it.
            if (added->provider != kNstatProviderTcp &&
                added->provider != kNstatProviderTcpKernel)
                return;
            bool tracked = false;
            {
                std::lock_guard<std::mutex> lk(flows_mu);
                const bool known = flows.find(added->srcref) != flows.end();
                if (!known && flows.size() >= kNstatMaxFlows) {
                    // UP-2 backstop: at the hard cap, reap stale entries first;
                    // if that frees nothing, drop this new flow (bounded +
                    // counted) rather than grow the table without bound.
                    reap_stale_flows_locked(mono);
                }
                if (known || flows.size() < kNstatMaxFlows) {
                    flows[added->srcref].last_update_mono = mono;
                    tracked = true;
                } else {
                    flow_reaped->fetch_add(1, std::memory_order_relaxed);
                }
                flow_table_size->store(static_cast<std::int64_t>(flows.size()),
                                       std::memory_order_relaxed);
            }
            if (tracked) {
                nstat_raw::MsgGetSrcDesc req{};
                req.hdr.type = kNstatMsgGetSrcDesc;
                req.hdr.length = static_cast<std::uint16_t>(sizeof(req));
                req.srcref = added->srcref;
                send_msg(&req, sizeof(req));
            }
            last_event_ts->store(mono, std::memory_order_relaxed);
            return;
        }
        case kNstatMsgSrcRemoved: {
            auto removed = nstat_decode_src_removed(raw);
            if (!removed) {
                spdlog::warn("TAR: nstat SRC_REMOVED decode mismatch — "
                            "transcribed layout disagrees with this kernel; "
                            "disabling the nstat client");
                layout_mismatch->store(true, std::memory_order_relaxed);
                stop_requested.store(true, std::memory_order_relaxed);
                return;
            }
            std::optional<FlowState> erased;
            {
                std::lock_guard<std::mutex> lk(flows_mu);
                auto it = flows.find(removed->srcref);
                if (it == flows.end()) {
                    // A removal for a source we never saw ADDED for — desync.
                    kernel_dropped->fetch_add(1, std::memory_order_relaxed);
                } else {
                    erased = it->second;
                    flows.erase(it);
                    flow_table_size->store(static_cast<std::int64_t>(flows.size()),
                                           std::memory_order_relaxed);
                }
            }
            if (erased && erased->has_desc) {
                // Only a flow whose identity we actually resolved is worth a
                // close row; one that never got a SRC_DESC has nothing
                // meaningful to report (memo §2 ADDED->DESC->COUNTS->REMOVED).
                ring->push(nstat_build_close_event(wall_now, *erased));
            }
            last_event_ts->store(mono, std::memory_order_relaxed);
            return;
        }
        case kNstatMsgSrcDesc: {
            auto desc = nstat_decode_tcp_src_desc(raw);
            if (!desc) {
                // Could be a non-TCP provider's descriptor (harmless — we
                // only asked for TCP, but be defensive) OR a genuine layout
                // mismatch. We cannot tell the two apart from the return
                // value alone without re-parsing the header ourselves; the
                // provider check inside nstat_decode_tcp_src_desc already
                // filters non-TCP away before the layout check runs, so a
                // header that IS type SRC_DESC and STILL fails to decode has
                // exhausted the benign explanations.
                // Already inside `case kNstatMsgSrcDesc`, so the type is fixed;
                // a length self-check failure is the only way to get here after
                // the provider filter, and it means our transcription disagrees
                // with this kernel's descriptor size — fail to the inert state.
                if (!nstat_length_matches_expected(hdr->type, hdr->length)) {
                    // UP-2: latch permanent only after a run of SRC_DESC
                    // failures. A real TcpDescriptor-layout mismatch fails every
                    // SRC_DESC, so its own streak trips fast; a lone garbled
                    // datagram resets on the next good SRC_DESC. Per-type, so
                    // healthy SRC_COUNTS can't paper over a descriptor that
                    // never decodes (Gate-7 review).
                    if (++decode_fail_streak_desc >= kNstatMaxDecodeFailStreak) {
                        spdlog::warn("TAR: nstat SRC_DESC decode mismatch x{} — transcribed "
                                     "TcpDescriptor disagrees with this kernel; disabling the "
                                     "nstat client",
                                     decode_fail_streak_desc);
                        layout_mismatch->store(true, std::memory_order_relaxed);
                        stop_requested.store(true, std::memory_order_relaxed);
                    } else {
                        spdlog::debug("TAR: nstat SRC_DESC decode mismatch ({}/{}) — tolerating as a "
                                      "possible one-off garbled datagram",
                                      decode_fail_streak_desc, kNstatMaxDecodeFailStreak);
                    }
                }
                return;
            }
            decode_fail_streak_desc = 0; // a good SRC_DESC clears its own run
            bool first_desc = false;
            {
                std::lock_guard<std::mutex> lk(flows_mu);
                // A DESC can race a missed ADDED, so this path also upserts —
                // which means it must honour the same kNstatMaxFlows hard cap
                // the ADDED path does (UP-2), or a burst of DESCs for unknown
                // srcrefs could grow the table past the cap between reaps. Reap
                // stale entries at the cap; if that frees nothing, drop this
                // orphan (bounded + counted) rather than insert unconditionally.
                auto it = flows.find(desc->srcref);
                if (it == flows.end() && flows.size() >= kNstatMaxFlows)
                    reap_stale_flows_locked(mono);
                it = flows.find(desc->srcref);
                if (it == flows.end() && flows.size() >= kNstatMaxFlows) {
                    flow_reaped->fetch_add(1, std::memory_order_relaxed);
                } else {
                    FlowState& flow = flows[desc->srcref];
                    first_desc = !flow.has_desc;
                    nstat_apply_tcp_desc(flow, *desc);
                    flow.last_update_mono = mono;
                }
                flow_table_size->store(static_cast<std::int64_t>(flows.size()),
                                       std::memory_order_relaxed);
            }
            if (first_desc)
                ring->push(nstat_build_open_event(wall_now, *desc));
            last_event_ts->store(mono, std::memory_order_relaxed);
            return;
        }
        case kNstatMsgSrcCounts: {
            auto counts = nstat_decode_src_counts(raw);
            if (!counts) {
                if (!nstat_length_matches_expected(hdr->type, hdr->length)) {
                    // UP-2: same consecutive-failure gate as the SRC_DESC path,
                    // on its own SRC_COUNTS streak.
                    if (++decode_fail_streak_counts >= kNstatMaxDecodeFailStreak) {
                        spdlog::warn("TAR: nstat SRC_COUNTS decode mismatch x{} — transcribed "
                                     "Counts disagrees with this kernel; disabling the nstat client",
                                     decode_fail_streak_counts);
                        layout_mismatch->store(true, std::memory_order_relaxed);
                        stop_requested.store(true, std::memory_order_relaxed);
                    } else {
                        spdlog::debug("TAR: nstat SRC_COUNTS decode mismatch ({}/{}) — tolerating as "
                                      "a possible one-off garbled datagram",
                                      decode_fail_streak_counts, kNstatMaxDecodeFailStreak);
                    }
                }
                return;
            }
            decode_fail_streak_counts = 0; // a good SRC_COUNTS clears its own run
            {
                std::lock_guard<std::mutex> lk(flows_mu);
                auto it = flows.find(counts->srcref);
                if (it == flows.end()) {
                    kernel_dropped->fetch_add(1, std::memory_order_relaxed); // desync
                } else {
                    nstat_apply_counts(it->second, *counts);
                    it->second.last_update_mono = mono; // refresh liveness (UP-2 reaper)
                }
            }
            last_event_ts->store(mono, std::memory_order_relaxed);
            return;
        }
        case kNstatMsgError:
            // A control ERROR echoing one of our subscription contexts means
            // that ADD_ALL_SRCS was REJECTED. One provider id being invalid on
            // a given kernel is expected (the dual subscription is deliberately
            // redundant); both rejected means no SRC_* message will ever
            // arrive — demote to the poll fallback immediately rather than
            // letting the dead client hide behind the idle-stall threshold.
            if (nstat_subscription_rejected(hdr->context, sub_tcp_rejected,
                                            sub_tcp_kernel_rejected)) {
                spdlog::warn("TAR: nstat kernel rejected both ADD_ALL_SRCS "
                             "subscriptions; disabling the nstat client "
                             "(poll fallback takes over)");
                stop_requested.store(true, std::memory_order_relaxed);
                return;
            }
            spdlog::debug("TAR: nstat kernel returned NSTAT_MSG_TYPE_ERROR (context={})",
                          hdr->context);
            return;
        default:
            return; // an unhandled/future message type — not our concern
        }
    }

    void reader_loop() {
        std::vector<std::byte> buf(kNstatRecvBufSize);
        for (;;) {
            const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
            if (n <= 0) {
                if (n < 0 && errno == ENOBUFS) {
                    // TODO(hardware-verify, memo §6 risk 6 / UP-4): unconfirmed
                    // whether a kctl SOCK_DGRAM recv actually surfaces ENOBUFS on
                    // kernel-side overrun rather than silently dropping —
                    // validate against a real connection storm. Until then the
                    // overrun IS observable: each ENOBUFS bumps kernel_dropped,
                    // which surfaces in the plugin status keys, so a sustained
                    // rate is at least visible to an operator (a demote-to-poll
                    // or resubscribe heuristic on that rate is the follow-up if
                    // the storm test shows silent loss).
                    kernel_dropped->fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                // 0 = orderly close (our own stop()); other errno = fatal. Latch
                // stop_requested on the fatal path so the sibling query thread
                // stops re-issuing QUERY_SRC on the now-dead socket (every other
                // self-death path sets this; a bare break left the query loop
                // waking forever until plugin shutdown).
                if (n < 0)
                    stop_requested.store(true, std::memory_order_relaxed);
                break;
            }
            if (stop_requested.load(std::memory_order_relaxed))
                break;
            // A single recv() can carry MULTIPLE concatenated messages: XNU
            // batches records back-to-back into one datagram (nstat_frame_messages
            // documents the kernel path). Dispatch EVERY framed sub-message —
            // decoding only the first and discarding the rest silently violates
            // the fail-closed contract (docs/darwin-compat.md) exactly during
            // the feature's primary use case (the ADD_ALL_SRCS burst), without
            // ever tripping a self-check.
            for (std::span<const std::byte> msg :
                 nstat_frame_messages(std::span<const std::byte>(
                     buf.data(), static_cast<std::size_t>(n)))) {
                try {
                    handle_message(msg);
                } catch (...) {
                    // A decode/mapping exception (e.g. bad_alloc under memory
                    // pressure) must cost one message, never the reader thread.
                }
                if (stop_requested.load(std::memory_order_relaxed))
                    break; // handle_message may have set this on a layout mismatch
            }
            if (stop_requested.load(std::memory_order_relaxed))
                break; // handle_message may have set this on a layout mismatch
        }
        // HIGH-1 fix: self-detected death, written through the borrowed
        // pointer to the CLIENT's running_ atomic (never touches impl_ from
        // the client side to observe this). Release so that a layout_mismatch_
        // set by handle_message() before the break is visible to any thread
        // that acquires running_ and observes false (R2-4).
        running->store(false, std::memory_order_release);
    }

    void query_loop() {
        std::unique_lock<std::mutex> lk(query_cv_mu);
        while (!stop_requested.load(std::memory_order_relaxed)) {
            query_cv.wait_for(lk, kNstatQueryInterval);
            if (stop_requested.load(std::memory_order_relaxed))
                break;
            std::vector<std::uint64_t> srcrefs;
            {
                std::lock_guard<std::mutex> flk(flows_mu);
                // UP-2: reap flows the kernel stopped reporting (a lost
                // SRC_REMOVED) before re-querying, so the table can't leak and
                // the O(n) query volume stays bounded to genuinely-live flows.
                reap_stale_flows_locked(nstat_mono_seconds());
                srcrefs.reserve(flows.size());
                for (const auto& entry : flows)
                    srcrefs.push_back(entry.first);
            }
            lk.unlock();
            for (std::uint64_t srcref : srcrefs) {
                if (stop_requested.load(std::memory_order_relaxed))
                    break;
                nstat_raw::MsgQuerySrc q{};
                q.hdr.type = kNstatMsgQuerySrc;
                q.hdr.length = static_cast<std::uint16_t>(sizeof(q));
                q.srcref = srcref;
                send_msg(&q, sizeof(q));
            }
            lk.lock();
        }
    }
};

NstatClient::NstatClient(std::size_t ring_capacity) : ring_(ring_capacity) {}

NstatClient::~NstatClient() { stop(); }

bool NstatClient::start() {
    if (impl_)
        return false; // already running

    // Stall/liveness timestamps are MONOTONIC (UP-6): an NTP/DST step must not
    // corrupt "seconds since" and mis-decide a stall. Seed last_event to now so
    // a just-started client isn't instantly considered stalled.
    const std::int64_t mono0 = nstat_mono_seconds();
    started_ts_.store(mono0, std::memory_order_relaxed);
    last_event_ts_.store(mono0, std::memory_order_relaxed);
    layout_mismatch_.store(false, std::memory_order_relaxed); // a fresh start gets a fresh chance
    flow_table_size_.store(0, std::memory_order_relaxed);     // fresh impl_ starts with an empty table

    // Own the fd in a ScopedFd from creation: every early return below closes
    // it automatically, and it stays owned across the throwing make_unique<Impl>
    // until released into impl->fd (K-14 — no leak on a bad_alloc there).
    ScopedFd sock(::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL));
    if (sock.get() < 0) {
        spdlog::warn("TAR: nstat socket() failed: {} — falling back to the poll",
                     std::strerror(errno));
        return false;
    }

    // FD_CLOEXEC so a bounded-runner child (or any exec elsewhere in the agent)
    // does not inherit this long-lived kctl socket (K-10/CDX-09) — mirrors the
    // runner's own pipe-fd discipline. Not atomic with socket() on Darwin (no
    // SOCK_CLOEXEC for PF_SYSTEM), so set it immediately and FAIL CLOSED to the
    // poll if it cannot be set rather than leak the descriptor across execs.
    if (::fcntl(sock.get(), F_SETFD, FD_CLOEXEC) < 0) {
        spdlog::warn("TAR: nstat fcntl(FD_CLOEXEC) failed: {} — falling back to the poll",
                     std::strerror(errno));
        return false;
    }

    struct ctl_info ci {};
    ::strlcpy(ci.ctl_name, "com.apple.network.statistics", sizeof(ci.ctl_name));
    if (::ioctl(sock.get(), CTLIOCGINFO, &ci) < 0) {
        spdlog::warn("TAR: nstat CTLIOCGINFO failed: {} — falling back to the poll",
                     std::strerror(errno));
        return false;
    }

    struct sockaddr_ctl sc {};
    sc.sc_len = static_cast<unsigned char>(sizeof(sc));
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = ci.ctl_id;
    sc.sc_unit = 0;
    if (::connect(sock.get(), reinterpret_cast<struct sockaddr*>(&sc), sizeof(sc)) < 0) {
        spdlog::warn("TAR: nstat connect() failed: {} — falling back to the poll",
                     std::strerror(errno));
        return false;
    }

    // Privilege honesty (memo §3): proxied by effective uid at start(), since
    // there is no direct "did the kernel actually scope me to my own flows"
    // signal available. The agent's production LaunchDaemon runs as root, so
    // this is expected true there; an unprivileged dev run honestly reports
    // false rather than silently claiming complete capture.
    system_wide_.store(::geteuid() == 0, std::memory_order_relaxed);

    auto impl = std::make_unique<Impl>(&ring_, &kernel_dropped_, &last_event_ts_, &layout_mismatch_,
                                       &running_, &flow_reaped_, &flow_table_size_);
    impl->fd = sock.release(); // ownership transfers to Impl (~Impl closes it)
    Impl* raw = impl.get();
    impl_ = std::move(impl);

    // R2-4 fix: publish running_ = true BEFORE launching the reader thread.
    // The reader self-detects fatal death by storing running_ = false at the
    // end of reader_loop(); std::thread construction synchronizes-with the new
    // thread, so a reader that dies immediately stores false strictly AFTER
    // this store — start() can no longer clobber a dead reader's false with a
    // stale true (the previous order launched the reader first, then set true,
    // which could overwrite an instant death and advertise a dead client as
    // primary). impl_ is already assigned, so any observer of running_ == true
    // sees a valid impl_; and no external caller can reach running_ during
    // start() — the client is registered (netqual_nstat_register_client) only
    // after start() returns.
    running_.store(true, std::memory_order_release);

    // C2 fix: std::thread construction can throw under resource exhaustion.
    // Roll back to the inert state (running_ = false, impl_ reset — ~Impl joins
    // any thread that WAS created and closes the fd) so the client is never
    // advertised live with missing workers; the caller falls back to the poll.
    try {
        raw->reader_thread = std::thread([raw] { raw->reader_loop(); });
        raw->query_thread = std::thread([raw] { raw->query_loop(); });
    } catch (const std::system_error& e) {
        running_.store(false, std::memory_order_release);
        impl_.reset();
        spdlog::warn("TAR: nstat client thread launch failed ({}); falling back to poll",
                     e.what());
        return false;
    }

    // Subscribe both known TCP provider ids — harmless if one is invalid for
    // this kernel; the flow table is keyed purely by srcref, not by which
    // provider id "won", so nothing downstream depends on this succeeding for
    // both. The zero-init leaves filter/events/target_pid/target_uuid all 0:
    // subscribe to every source of the provider (root scopes it system-wide),
    // no async event push — counts come from the QUERY_SRC poll loop.
    nstat_raw::MsgAddAllSrcs add_tcp{};
    add_tcp.hdr.type = kNstatMsgAddAllSrcs;
    add_tcp.hdr.length = static_cast<std::uint16_t>(sizeof(add_tcp));
    add_tcp.hdr.context = kNstatCtxSubscribeTcp; // attribute a control reply to this subscription
    add_tcp.provider = kNstatProviderTcp;
    raw->send_msg(&add_tcp, sizeof(add_tcp));

    nstat_raw::MsgAddAllSrcs add_tcp_kernel{};
    add_tcp_kernel.hdr.type = kNstatMsgAddAllSrcs;
    add_tcp_kernel.hdr.length = static_cast<std::uint16_t>(sizeof(add_tcp_kernel));
    add_tcp_kernel.hdr.context = kNstatCtxSubscribeTcpKernel;
    add_tcp_kernel.provider = kNstatProviderTcpKernel;
    raw->send_msg(&add_tcp_kernel, sizeof(add_tcp_kernel));
    spdlog::info("TAR: nstat client active (provider=tcp, system_wide={})",
                 system_wide_.load(std::memory_order_relaxed));
    return true;
}

void NstatClient::stop() {
    // HIGH-1 fix: clear running_ BEFORE taking client_mu_/resetting impl_, so
    // a snapshot_quality()/drain() call that has not yet acquired client_mu_
    // (or acquires it after this stop()) observes running_ == false and never
    // touches impl_ at all. A call that already holds client_mu_ (acquired
    // client_mu_ before this stop() did) is still safely reading impl_ right
    // now — the lock below blocks this stop() until that call releases it,
    // so impl_ is never freed mid-read.
    running_.store(false, std::memory_order_release);
    std::lock_guard<std::mutex> lk(client_mu_);
    // ~Impl shuts down the socket (unblocking the reader's recv), wakes the
    // query thread, joins both, and only then closes the fd (HIGH-2); flows_mu
    // /ring_ outlive impl_, so teardown is use-after-free-safe by construction
    // — same structural argument as ProcEsCollector::stop().
    impl_.reset();
}

bool NstatClient::running() const noexcept {
    // HIGH-1 fix: reads a client-owned atomic only — no impl_ dereference —
    // so this is always safe to call regardless of a concurrent stop().
    // Acquire pairs with the reader's release store on death (R2-4).
    return running_.load(std::memory_order_acquire);
}

std::vector<NstatFlowEvent> NstatClient::drain() {
    // R2-1/HIGH-5 fix: drain the ring REGARDLESS of running_. The whole point
    // of the plugin's death/stall-transition drain is to recover events that
    // were buffered just before the reader died — gating on running_ discarded
    // exactly those (running_ is already false by then). ring_ is a client
    // member (it outlives impl_), so this is safe; client_mu_ is still held to
    // serialize with stop() resetting impl_ (uniform with snapshot_quality()).
    std::lock_guard<std::mutex> lk(client_mu_);
    return ring_.drain();
}

std::uint64_t NstatClient::dropped() const noexcept { return ring_.dropped(); }

std::uint64_t NstatClient::kernel_dropped() const noexcept {
    return kernel_dropped_.load(std::memory_order_relaxed);
}

std::uint64_t NstatClient::flow_reaped() const noexcept {
    return flow_reaped_.load(std::memory_order_relaxed);
}

std::int64_t NstatClient::flow_table_size() const noexcept {
    return flow_table_size_.load(std::memory_order_relaxed);
}

bool NstatClient::stalled() const noexcept {
    if (!running())
        return false;
    // MONOTONIC now, matching the monotonic last_event_ts_/started_ts_ stores
    // (UP-6) — a wall-clock backward step can no longer make this negative and
    // falsely report not-stalled (which would suppress the poll fallback).
    const std::int64_t now = nstat_mono_seconds();
    return nstat_stream_is_stalled(last_event_ts_.load(std::memory_order_relaxed),
                                   started_ts_.load(std::memory_order_relaxed), now,
                                   kNstatIdleFallbackSeconds);
}

bool NstatClient::layout_mismatch() const noexcept {
    return layout_mismatch_.load(std::memory_order_relaxed);
}

bool NstatClient::system_wide() const noexcept {
    return running() && system_wide_.load(std::memory_order_relaxed);
}

const char* NstatClient::method_name() const noexcept {
    return (running() && !layout_mismatch()) ? "nstat" : "none";
}

std::vector<TcpQualitySample> NstatClient::snapshot_quality() const {
    // HIGH-1 fix: client_mu_ held for the ENTIRE body — the running_ check
    // AND every impl_ access below — so a concurrent stop() cannot free
    // impl_ while this function is reading it. See client_mu_'s doc comment
    // (tar_netqual_nstat.hpp) for the ordering argument.
    std::lock_guard<std::mutex> lk(client_mu_);
    // Acquire (not relaxed): start() publishes impl_ then stores running_=true
    // with release, so an acquire load here orders the impl_ read below after
    // that publish. The class advertises concurrent-call safety, so don't rely
    // only on client_mu_ to provide the ordering.
    if (!running_.load(std::memory_order_acquire))
        return {};
    std::vector<TcpQualitySample> out;
    std::lock_guard<std::mutex> flk(impl_->flows_mu);
    out.reserve(impl_->flows.size());
    for (auto& entry : impl_->flows) {
        FlowState& flow = entry.second;
        if (!flow.has_desc || !flow.has_counts)
            continue; // incomplete flow — no full picture yet, skip this tick
        out.push_back(nstat_build_quality_sample(flow));
        nstat_advance_snapshot_baseline(flow);
    }
    return out;
}

} // namespace yuzu::tar

#else // not macOS — every method is a no-op, start() returns false

namespace yuzu::tar {

struct NstatClient::Impl {};

NstatClient::NstatClient(std::size_t ring_capacity) : ring_(ring_capacity) {}
NstatClient::~NstatClient() = default;

bool NstatClient::start() { return false; }
void NstatClient::stop() {}
bool NstatClient::running() const noexcept { return false; }
std::vector<NstatFlowEvent> NstatClient::drain() { return {}; }
std::uint64_t NstatClient::dropped() const noexcept { return ring_.dropped(); }
std::uint64_t NstatClient::kernel_dropped() const noexcept { return 0; }
std::uint64_t NstatClient::flow_reaped() const noexcept { return 0; }
std::int64_t NstatClient::flow_table_size() const noexcept { return 0; }
bool NstatClient::stalled() const noexcept { return false; }
bool NstatClient::layout_mismatch() const noexcept { return false; }
bool NstatClient::system_wide() const noexcept { return false; }
const char* NstatClient::method_name() const noexcept { return "none"; }
std::vector<TcpQualitySample> NstatClient::snapshot_quality() const { return {}; }

} // namespace yuzu::tar

#endif // __APPLE__
