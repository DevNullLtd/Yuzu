/**
 * virtualization_linux.cpp -- Linux leg: virtualization facts from CPUID, DMI, sysfs and procfs.
 *
 * Only the POSIX boundary lives here: bounded reads and access(2) fill a LinuxReads, and
 * linux_facts (virtualization_parsers.hpp) turns them into Facts, tokens included. Every decision
 * (the vendor tables, the root-partition gate, the precedence, bare_metal vs unknown, the
 * container verdict) is in that header too. Reads go through posix_secure_read (bounded, regular
 * files only, no deadline of its own: a hung procfs/sysfs read pins the calling pool worker like
 * every posix_secure_read consumer, #4875); ENOENT is "absent" and any other failure is an
 * unreadable source (a host-decision one blocks bare_metal, a container one only constrains the
 * status). Leaf::follow is the LEAF POLICY's root-only case: every path read is in a
 * kernel-served or root-owned tree (/sys, /proc, /run/systemd, /etc) that no unprivileged user
 * can write, so a leaf link there is not attacker-controlled. The container check reads the
 * AGENT's own /proc/self/cgroup, not PID 1's, which answers a different question when the PID
 * namespace is shared, plus the type systemd records in /run/systemd/container (how a system
 * container is told from a host).
 */
#include "virtualization_legs.hpp"

#if defined(__linux__)

#include <network_fstype.hpp>
#include <posix_secure_read.hpp>
#include <yuzu/agent/scoped_fd.hpp>

#include <httplib.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace yuzu::virtualization {

namespace {

constexpr size_t kSmallCap = 4096;
constexpr size_t kCgroupCap = 64 * 1024;

CpuidFacts read_cpuid() {
#if defined(__x86_64__) || defined(__i386__)
    if (__get_cpuid_max(0, nullptr) >= 1) {
        return cpuid_facts([](std::uint32_t leaf) {
            unsigned a = 0, b = 0, c = 0, d = 0;
            __cpuid_count(leaf, 0, a, b, c, d);
            return CpuidRegs{a, b, c, d};
        });
    }
#endif
    return CpuidFacts{}; // available = false
}

/// One bounded read mapped to the ok / absent / unreadable trichotomy; the cause segment is
/// all linux_facts needs to build the token. posix_secure_read's types stop here.
FieldRead read_source(const char* path, size_t cap) {
    FieldRead r;
    const auto fr = yuzu::shared::read_file(path, cap, yuzu::shared::Leaf::follow);
    if (fr.ok()) {
        r.state = ReadState::ok;
        r.value = fr.data;
        return r;
    }
    switch (fr.error) {
    case yuzu::shared::ReadError::not_regular:
        r.cause = "not_regular";
        break;
    case yuzu::shared::ReadError::oversized:
        r.cause = "oversized";
        break;
    default:
        if (fr.err == ENOENT)
            return r; // absent
        r.cause = errno_token(fr.err);
        break;
    }
    r.state = ReadState::unreadable;
    return r;
}

/// access(2) as an errno: 0 present, ENOENT absent, anything else a failed probe.
int probe(const char* path) { return ::access(path, F_OK) == 0 ? 0 : errno; }

// ---------------------------------------------------------------------------------------------
// runtime_posture shell: the POSIX and httplib boundaries over runtime_posture_linux. Every
// decision (what to refuse, what to ask, what to emit) is in virtualization_runtime_parsers.hpp
// and virtualization_legs.hpp. The one thing mapped here is httplib's own error enum, which the pure
// header cannot see; the single timing decision in that mapping is runtime::classify_read_error.
// ---------------------------------------------------------------------------------------------

runtime::StatResult to_stat_result(const struct stat& st) {
    runtime::StatResult r;
    r.mode = st.st_mode;
    r.uid = st.st_uid;
    r.gid = st.st_gid;
    r.dev = static_cast<std::uint64_t>(st.st_dev);
    r.ino = static_cast<std::uint64_t>(st.st_ino);
    return r;
}

runtime::StatResult stat_path(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) {
        runtime::StatResult r;
        r.err = errno;
        return r;
    }
    return to_stat_result(st);
}

/// Opens the endpoint O_PATH|O_NOFOLLOW so a link at the leaf is returned as a link (and refused by
/// the caller's fstat check) rather than followed. `handle` is held by the caller for the whole run:
/// the transport connects through it, so the object that was checked is the object connected to.
runtime::StatResult open_endpoint_checked(yuzu::agent::ScopedFd& handle, const std::string& path) {
    const int fd = ::open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
    runtime::StatResult r;
    if (fd < 0) {
        r.err = errno;
        return r;
    }
    handle.reset(fd);
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        r.err = errno;
        return r;
    }
    return to_stat_result(st);
}

runtime::Outcome outcome_for_errno(int e) {
    switch (e) {
    case EACCES:
    case EPERM:
        return runtime::Outcome::eacces;
    case ENOENT:
    case ENXIO:
        return runtime::Outcome::enoent;
    default:
        return runtime::Outcome::other;
    }
}

/// Carries the absolute deadline of one request, independent of socket readiness. httplib's total
/// timeout (`set_max_timeout`) is only consulted when it next has to WAIT for data and, once the
/// budget is spent, clamps to a zero-time poll that still reads whatever is ready: a peer that is
/// always readable (an endless stream of `100 Continue` lines, which the client skips without bound
/// or a clock check) is never made to wait, so it can hold the request, and the agent worker, for as
/// long as it keeps writing. This thread shuts the in-flight socket down at the budget. `stop()` is
/// the client's one cross-thread-safe call (it only shuts the socket down while a request is in
/// flight), it is re-issued every 100 ms because a call that lands before the request has marked its
/// socket in flight does nothing, and it returns the request's reads as end of stream. The thread
/// is owned here and joined in the destructor on every exit path. Declare an instance AFTER the
/// client so it is joined before the client is destroyed. A failure to start the thread propagates
/// to the one ABI catch like any other.
class DeadlineWatchdog {
public:
    DeadlineWatchdog(httplib::Client& cli, std::chrono::milliseconds budget)
        : thread_([this, &cli, budget] { run(cli, budget); }) {}
    DeadlineWatchdog(const DeadlineWatchdog&) = delete;
    DeadlineWatchdog& operator=(const DeadlineWatchdog&) = delete;
    ~DeadlineWatchdog() {
        {
            std::lock_guard<std::mutex> lk(m_);
            done_ = true;
        }
        cv_.notify_one();
        thread_.join();
    }

private:
    void run(httplib::Client& cli, std::chrono::milliseconds budget) {
        std::unique_lock<std::mutex> lk(m_);
        if (cv_.wait_for(lk, budget, [this] { return done_; }))
            return; // the request ended inside its budget
        while (!done_) {
            lk.unlock();
            cli.stop();
            lk.lock();
            cv_.wait_for(lk, std::chrono::milliseconds{100}, [this] { return done_; });
        }
    }

    std::mutex m_;
    std::condition_variable cv_;
    bool done_ = false;
    std::thread thread_; // last: starts only once the members above exist
};

/// One GET over the unix socket at `connect_path`. Transport pins (design note section 5): the total
/// timeout is the remaining action budget and is never zero (the caller stops below 1 ms), connect
/// min(2 s, budget), read min(5 s, budget), no redirects, no decompression, Connection: close. The
/// budget is ABSOLUTE: DeadlineWatchdog shuts the socket at it, and whatever the request reported,
/// one that returns at or past the budget is a `timeout` (runtime::budget_outcome), never `ok`. The
/// 1 MiB body cap is enforced twice, both naming the cause: a declared Content-Length over it is
/// refused before the body is read, and the receiver stops reading at it for a chunked or unframed
/// reply. httplib's own payload cap sits one read buffer above the receiver's, as a backstop that
/// cannot fire first (its check precedes the receiver and would read as a plain read error). Bodies
/// and error text are never logged.
runtime::TransportResult one_request(const std::string& connect_path, const runtime::Request& req,
                                     std::chrono::milliseconds budget) {
    using namespace std::chrono;
    const auto connect_to = std::min(milliseconds{2000}, budget);
    const auto read_to = std::min(milliseconds{5000}, budget);

    httplib::Client cli(connect_path);
    cli.set_address_family(AF_UNIX); // before the first request (printing_plugin.cpp precedent)
    cli.set_connection_timeout(connect_to);
    cli.set_read_timeout(read_to);
    cli.set_write_timeout(read_to);
    cli.set_max_timeout(budget); // the per-request TOTAL bound; 0 would mean unbounded
    cli.set_keep_alive(false);
    cli.set_follow_location(false);
    cli.set_decompress(false);
    cli.set_payload_max_length(runtime::kMaxBodyBytes + CPPHTTPLIB_RECV_BUFSIZ);

    runtime::TransportResult out;
    bool oversized = false;
    const httplib::Headers headers{{"Connection", "close"}};
    const httplib::ResponseHandler on_headers = [&](const httplib::Response& r) {
        if (r.get_header_value_u64("Content-Length") > runtime::kMaxBodyBytes) {
            oversized = true;
            return false;
        }
        return true;
    };
    const httplib::ContentReceiver on_body = [&](const char* data, size_t n) {
        if (out.body.size() + n > runtime::kMaxBodyBytes) {
            oversized = true;
            return false;
        }
        out.body.append(data, n);
        return true;
    };
    const auto started = steady_clock::now(); // before the watchdog's own timer starts
    DeadlineWatchdog watchdog(cli, budget);   // after `cli`: joined first on every exit path
    errno = 0;
    auto res = cli.Get(req.path(), headers, on_headers, on_body);
    const int saved_errno = errno;
    if (oversized) {
        out.outcome = runtime::Outcome::oversized;
        out.body.clear();
    } else if (res) {
        out.outcome = runtime::Outcome::ok;
        out.http_status = res->status;
    } else {
        out.body.clear();
        switch (res.error()) {
        case httplib::Error::Connection:
            out.outcome = outcome_for_errno(saved_errno);
            break;
        case httplib::Error::ConnectionTimeout:
        case httplib::Error::Timeout:
            out.outcome = runtime::Outcome::timeout;
            break;
        case httplib::Error::Read:
        case httplib::Error::ConnectionClosed:
            out.outcome = runtime::classify_read_error(
                duration_cast<milliseconds>(steady_clock::now() - started), read_to);
            break;
        default:
            out.outcome = runtime::Outcome::not_http;
            break;
        }
    }
    out.outcome = runtime::budget_outcome(
        out.outcome, duration_cast<milliseconds>(steady_clock::now() - started), budget);
    return out;
}

/// Reads /proc/self/mountinfo once per dispatch for the network-mount guard on the data roots.
void read_mounts(runtime::RuntimeFs& fs) {
    const auto fr = yuzu::shared::read_file("/proc/self/mountinfo", 1024 * 1024,
                                            yuzu::shared::Leaf::follow);
    if (!fr.ok()) {
        fs.mountinfo_unreadable = true;
        return;
    }
    fs.network_mounts = yuzu::shared::network_mount_points(fr.data);
}


} // namespace

int run_linux(yuzu::CommandContext& ctx) {
    CpuidFacts cpuid = read_cpuid();
    LinuxReads r;
    r.sys_vendor = read_source("/sys/class/dmi/id/sys_vendor", kSmallCap);
    r.product_name = read_source("/sys/class/dmi/id/product_name", kSmallCap);
    r.hypervisor_type = read_source("/sys/hypervisor/type", kSmallCap);
    r.systemd_container = read_source("/run/systemd/container", kSmallCap);
    r.cgroup = read_source("/proc/self/cgroup", kCgroupCap);
    r.dockerenv_errno = probe("/.dockerenv");
    r.containerenv_errno = probe("/run/.containerenv");

    report_host(ctx, decide(linux_facts(std::move(cpuid), r)));
    return 0;
}

int run_linux_runtime_posture(yuzu::CommandContext& ctx) {
    report(ctx, "runtime_posture",
           runtime::single_flight(runtime::runtime_posture_flight(), [] {
               yuzu::agent::ScopedFd handle; // the checked endpoint descriptor, held for the whole run
               runtime::RuntimeFs fs;
               fs.stat = stat_path;
               fs.read = [](const std::string& path, size_t cap) {
                   return read_source(path.c_str(), cap);
               };
               fs.open_endpoint = [&handle](const std::string& path) {
                   return open_endpoint_checked(handle, path);
               };
               read_mounts(fs);
               fs.egid = ::getegid();
               fs.groups.push_back(fs.egid);
               if (const int n = ::getgroups(0, nullptr); n > 0) {
                   std::vector<gid_t> g(static_cast<size_t>(n));
                   const int got = ::getgroups(n, g.data());
                   for (int i = 0; i < got; ++i)
                       fs.groups.push_back(static_cast<std::uint32_t>(g[static_cast<size_t>(i)]));
               }

               // Every request connects through the descriptor that was checked, so the object
               // that passed the checks is the object connected to. There is no retry by path: if
               // /proc/self/fd cannot be resolved the request reads `unreachable`, and design note
               // section 9 item 6 decides what happens then.
               const runtime::Transport transport = [&handle](const runtime::Request& req,
                                                              std::chrono::milliseconds budget) {
                   return one_request("/proc/self/fd/" + std::to_string(handle.get()), req,
                                      budget);
               };
               const runtime::Clock clock = [] { return std::chrono::steady_clock::now(); };
               return runtime::runtime_posture_linux(fs, transport, clock,
                                                     container_runtime_endpoint());
           }));
    return 0;
}

int run_linux_wsl(yuzu::CommandContext& ctx) {
    report_unavailable(ctx, "wsl", "linux:virtualization:wsl:unsupported");
    return 0;
}

} // namespace yuzu::virtualization

#endif // defined(__linux__)
