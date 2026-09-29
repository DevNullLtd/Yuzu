/**
 * test_dex_linux_journal.cpp — pure journald classification (dex_linux_journal).
 *
 * The sibling of test_dex_linux_proc / test_dex_macos: parsing a `journalctl -o
 * json` line into a SignalObservation is pure text handling, so it runs on EVERY
 * host against captured fixtures. The journalctl shell-out + cursor checkpoint
 * (dex_linux_collector) are exercised on a real Linux box via the live pipeline,
 * not here.
 */

#include "dex_linux_journal.hpp"

#include "dex_event.hpp" // signal_detail_json — prove no path / memory-figure PII reaches the wire payload

#include "test_helpers.hpp" // yuzu::test::unique_temp_path — portable temp file

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace yuzu::agent::lnx;

namespace {
// A real temp file seeded with `content` and rewound for reading — the portable
// stand-in for the journalctl popen() stream, so the pipe-read + drain
// orchestration runs on EVERY platform without journalctl. std::tmpfile() is NOT
// portable here: on MSVC it opens at the C:\ drive root and fails without write
// access there, and these [journal] cases also run on the Windows CI leg. RAII —
// the backing file is closed + removed on destruction.
class TempPipe {
public:
    explicit TempPipe(std::string_view content)
        : path_(yuzu::test::unique_temp_path("dex-journal-pipe-")) {
        // "x" = C11 exclusive create: fails if path_ already exists, closing the
        // symlink-preplant/TOCTOU window a plain "w" leaves open on a
        // shared-identity CI box (CodeQL cpp/world-writable-file-creation #5084).
        f_ = std::fopen(path_.string().c_str(), "w+bx");
        if (f_ && !content.empty()) {
            std::fwrite(content.data(), 1, content.size(), f_);
            std::rewind(f_);
        }
    }
    ~TempPipe() {
        if (f_)
            std::fclose(f_);
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    TempPipe(const TempPipe&) = delete;
    TempPipe& operator=(const TempPipe&) = delete;
    std::FILE* get() const { return f_; }

private:
    std::filesystem::path path_;
    std::FILE* f_ = nullptr;
};
} // namespace

TEST_CASE("journal: coredump → process.crashed", "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=1;b=cd","MESSAGE_ID":"fc2e22bc6ee647b6b90729ab34a250b1",)"
        R"("COREDUMP_COMM":"nginx","COREDUMP_SIGNAL":"11","COREDUMP_EXE":"/usr/sbin/nginx"})";
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "s=ab;i=1;b=cd");
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "process.crashed");
    CHECK(jl.obs->subject == "nginx");
    CHECK(jl.obs->reason == "SIGSEGV");
    CHECK(jl.obs->kind == "signal");
    CHECK(jl.obs->platform.empty()); // collector stamps platform, not the parser
}

TEST_CASE("journal: coredump without a comm is dropped (no EXE path shipped)",
          "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=2;b=cd","MESSAGE_ID":"fc2e22bc6ee647b6b90729ab34a250b1",)"
        R"("COREDUMP_EXE":"/opt/app/secret-path"})";
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "s=ab;i=2;b=cd"); // cursor still advances
    CHECK_FALSE(jl.obs.has_value());
}

TEST_CASE("journal: unit failed → service.crashed", "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=3;b=cd","MESSAGE_ID":"be02cf6855d2428ba40df7e9d022f03d",)"
        R"("UNIT":"postgresql.service","UNIT_RESULT":"exit-code"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "service.crashed");
    CHECK(jl.obs->subject == "postgresql.service");
    CHECK(jl.obs->reason == "exit-code");
    CHECK(jl.obs->kind == "unit");
}

TEST_CASE("journal: unit failed without UNIT_RESULT still emits (empty reason)",
          "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"x","MESSAGE_ID":"be02cf6855d2428ba40df7e9d022f03d","UNIT":"sshd.service"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "service.crashed");
    CHECK(jl.obs->subject == "sshd.service");
    CHECK(jl.obs->reason.empty());
}

TEST_CASE("journal: 'Failed with result' (the real failure message) → service.crashed",
          "[guardian][dex][linux][journal]") {
    // The MESSAGE_ID a simple service failure actually logs (confirmed against a live
    // specimen) — distinct from SD_MESSAGE_UNIT_FAILED, carries UNIT + UNIT_RESULT.
    const std::string line =
        R"({"__CURSOR":"s=ab;i=9;b=cd","MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c",)"
        R"("UNIT":"yuzu-smoke.service","UNIT_RESULT":"exit-code"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "service.crashed");
    CHECK(jl.obs->subject == "yuzu-smoke.service");
    CHECK(jl.obs->reason == "exit-code");
}

TEST_CASE("journal: watchdog timeout → service.hung (routed by UNIT_RESULT, same entry)",
          "[guardian][dex][linux][journal]") {
    // LIVE-CAPTURED: a WatchdogSec timeout logs the SAME d9b373ed entry as a crash but
    // with UNIT_RESULT="watchdog" — the service stopped responding, so it routes to
    // service.hung, not service.crashed. One entry, no double-emit.
    const std::string line =
        R"({"__CURSOR":"x","MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c",)"
        R"("UNIT":"yz-wd.service","UNIT_RESULT":"watchdog"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "service.hung");
    CHECK(jl.obs->subject == "yz-wd.service");
    CHECK(jl.obs->reason == "watchdog");
    CHECK(jl.obs->kind == "hang");
}

TEST_CASE("journal: chronyd 'no selectable sources' → os.time_unsynced (gated on trusted _COMM)",
          "[guardian][dex][linux][journal]") {
    // LIVE-CAPTURED chrony format. Gated on `_COMM` (journald-trusted) — NOT
    // SYSLOG_IDENTIFIER (forgeable). Custom raw-string delimiter R"j(...)j": the message
    // contains ")" which would otherwise close a plain R"(...)" early.
    const std::string line =
        R"j({"__CURSOR":"x","_COMM":"chronyd","_TRANSPORT":"stdout","MESSAGE":"Can't synchronise: no selectable sources (5 unreachable sources)"})j";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "os.time_unsynced");
    CHECK(jl.obs->subject == "clock");
}

TEST_CASE("journal: privacy — os.time_unsynced ships a fixed sentence, never the raw chrony line",
          "[guardian][dex][linux][journal][privacy]") {
    // The raw chrony MESSAGE can carry NTP source IPs and other detail; only the fixed
    // subject "clock" + sentence may leave the device. Prove signal_detail_json (the wire
    // payload) is free of any message content even when an IP is embedded in the marker.
    const std::string line =
        R"j({"__CURSOR":"x","_COMM":"chronyd","MESSAGE":"System clock wrong by 1.5 seconds (source 203.0.113.7)"})j";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "os.time_unsynced");
    const std::string detail = signal_detail_json(*jl.obs);
    for (const std::string_view leak : {"203.0.113.7", "1.5 seconds", "source", "wrong by"}) {
        CHECK(jl.obs->subject.find(leak) == std::string_view::npos);
        CHECK(jl.obs->sentence.find(leak) == std::string_view::npos);
        CHECK(detail.find(leak) == std::string_view::npos);
    }
}

TEST_CASE("journal: a forged SYSLOG_IDENTIFIER=chronyd does NOT fire os.time_unsynced",
          "[guardian][dex][linux][journal]") {
    // An unprivileged process can set SYSLOG_IDENTIFIER freely (`logger -t chronyd …`),
    // but not the trusted _COMM. A forged line with the right MESSAGE but no _COMM=chronyd
    // must produce no observation (integrity — Gate-4 UP-3).
    const std::string line =
        R"j({"__CURSOR":"x","SYSLOG_IDENTIFIER":"chronyd","_COMM":"logger","MESSAGE":"Can't synchronise: no selectable sources"})j";
    const JournalLine jl = parse_journal_line(line);
    CHECK_FALSE(jl.obs.has_value());
}

TEST_CASE("journal: chronyd source online/offline flap is NOT a sync loss",
          "[guardian][dex][linux][journal]") {
    // The frequent, noisy chrony lines (which carry source IPs) must produce NO
    // observation — the cursor still advances past them.
    const std::string line =
        R"({"__CURSOR":"adv","_COMM":"chronyd","MESSAGE":"Source 185.125.190.121 offline"})";
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "adv");
    CHECK_FALSE(jl.obs.has_value());
}

TEST_CASE("journal: kernel OOM-kill → memory.exhausted", "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=4;b=cd","_TRANSPORT":"kernel",)"
        R"("MESSAGE":"Out of memory: Killed process 4321 (mysqld) total-vm:9000000kB"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "memory.exhausted");
    CHECK(jl.obs->subject == "mysqld");
    CHECK(jl.obs->reason == "oom-kill");
}

TEST_CASE("journal: cgroup-v2 OOM-kill → memory.exhausted (the modern systemd common case)",
          "[guardian][dex][linux][journal]") {
    // LIVE-CAPTURED on a cgroup-v2 host: a memory-limited service that OOMs logs THIS
    // form, not the system-wide "Out of memory:" — the leading "Out " is lower-cased
    // mid-sentence. On modern systemd every service is in a cgroup, so this is the
    // common case; the earlier capital-"Out" marker missed it entirely.
    const std::string line =
        R"({"__CURSOR":"s=ab;i=4b;b=cd","_TRANSPORT":"kernel",)"
        R"("MESSAGE":"Memory cgroup out of memory: Killed process 1802705 (python3) total-vm:161112kB, anon-rss:130680kB"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "memory.exhausted");
    CHECK(jl.obs->subject == "python3"); // the comm, never the memory figures / cgroup path
    CHECK(jl.obs->reason == "oom-kill");
}

TEST_CASE("journal: OOM victim comm containing ')' is taken whole (rfind, not find)",
          "[guardian][dex][linux][journal]") {
    // A process comm can itself contain ')'. The kernel wraps the WHOLE comm in one
    // "(…)" — so a comm "ba)sh" renders as "(ba)sh)". The closer is the LAST ')' in the
    // line (the stats tail has none), so rfind takes the full comm; find('(') + find(')')
    // would truncate it to "ba".
    const std::string line =
        R"({"__CURSOR":"s=ab;i=4c;b=cd","_TRANSPORT":"kernel",)"
        R"("MESSAGE":"Out of memory: Killed process 777 (ba)sh) total-vm:512kB, anon-rss:64kB"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "memory.exhausted");
    CHECK(jl.obs->subject == "ba)sh"); // whole comm, not "ba"
    CHECK(jl.obs->reason == "oom-kill");
}

TEST_CASE("journal: non-OOM kernel line is dropped but advances the cursor",
          "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=5;b=cd","_TRANSPORT":"kernel","MESSAGE":"usb 1-1: new device"})";
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "s=ab;i=5;b=cd");
    CHECK_FALSE(jl.obs.has_value());
}

TEST_CASE("journal: unrelated MESSAGE_ID is dropped (cursor kept)",
          "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=6;b=cd","MESSAGE_ID":"7d4958e842da4a758f6c1cdc7b36dcc5",)"
        R"("UNIT":"cron.service"})"; // unit STARTED, not failed
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "s=ab;i=6;b=cd");
    CHECK_FALSE(jl.obs.has_value());
}

TEST_CASE("journal: malformed JSON yields no cursor, no obs (never throws)",
          "[guardian][dex][linux][journal]") {
    CHECK_FALSE(parse_journal_line("not json at all").obs.has_value());
    CHECK(parse_journal_line("not json at all").cursor.empty());
    CHECK_FALSE(parse_journal_line("").obs.has_value());
    // a JSON array (not an object) is also rejected
    CHECK_FALSE(parse_journal_line("[1,2,3]").obs.has_value());
    // a well-formed object whose __CURSOR is a NON-string (array) yields no cursor —
    // jstr() takes a field only when it is a plain string, so structured / binary
    // journal values are never shipped.
    CHECK(parse_journal_line(R"({"__CURSOR":["a"],"MESSAGE_ID":"x"})").cursor.empty());
}

TEST_CASE("crash_signal_name maps the core-generating signals",
          "[guardian][dex][linux][journal]") {
    CHECK(crash_signal_name(11) == "SIGSEGV");
    CHECK(crash_signal_name(6) == "SIGABRT");
    CHECK(crash_signal_name(7) == "SIGBUS");
    CHECK(crash_signal_name(8) == "SIGFPE");
    CHECK(crash_signal_name(99) == "signal 99"); // unmapped → numeric fallback
}

TEST_CASE("journal: coredump without COREDUMP_SIGNAL emits with an empty reason",
          "[guardian][dex][linux][journal]") {
    // A coredump entry that carries no COREDUMP_SIGNAL is still a crash — emit it with
    // an empty reason and a sentence that omits the "(signal …)" suffix.
    const std::string line =
        R"({"__CURSOR":"s=ab;i=10;b=cd","MESSAGE_ID":"fc2e22bc6ee647b6b90729ab34a250b1",)"
        R"("COREDUMP_COMM":"worker"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "process.crashed");
    CHECK(jl.obs->subject == "worker");
    CHECK(jl.obs->reason.empty());
    CHECK(jl.obs->sentence == "worker crashed"); // no signal suffix
}

TEST_CASE("journal: privacy — coredump ships the comm only, never the COREDUMP_EXE path",
          "[guardian][dex][linux][journal][privacy]") {
    // A real coredump entry carries COREDUMP_EXE — a full binary path that can embed a
    // user / tenant / project directory. Only the comm may leave the device; the path
    // must not appear in ANY emitted surface (subject, sentence, or detail_json wire
    // payload). This is the [dex][privacy] pin the macOS / storage collectors carry.
    const std::string line =
        R"({"__CURSOR":"s=ab;i=11;b=cd","MESSAGE_ID":"fc2e22bc6ee647b6b90729ab34a250b1",)"
        R"("COREDUMP_COMM":"acmeapp","COREDUMP_SIGNAL":"6",)"
        R"("COREDUMP_EXE":"/home/alice/acme-secret/acmeapp"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->subject == "acmeapp"); // the comm, never the path
    const std::string detail = signal_detail_json(*jl.obs);
    for (const std::string_view leak : {"alice", "acme-secret", "/home", "secret"}) {
        CHECK(jl.obs->subject.find(leak) == std::string_view::npos);
        CHECK(jl.obs->sentence.find(leak) == std::string_view::npos);
        CHECK(detail.find(leak) == std::string_view::npos);
    }
}

TEST_CASE("journal: privacy — OOM ships the victim comm only, never the kernel memory figures",
          "[guardian][dex][linux][journal][privacy]") {
    // The kernel OOM line carries total-vm / anon-rss / file-rss figures; only the
    // parenthesized victim comm may leave the device — never the memory numbers, the
    // cgroup path, or the rest of the raw kernel message. Pinned for BOTH the
    // system-wide and the (live-captured) cgroup-v2 message forms.
    const auto no_leak = [](const char* message, const char* comm) {
        const std::string line = std::string(R"({"__CURSOR":"x","_TRANSPORT":"kernel","MESSAGE":")") +
                                 message + R"("})";
        const JournalLine jl = parse_journal_line(line);
        REQUIRE(jl.obs.has_value());
        CHECK(jl.obs->subject == comm);
        const std::string detail = signal_detail_json(*jl.obs);
        for (const std::string_view leak :
             {"total-vm", "anon-rss", "file-rss", "9000000", "8000000", "161112", "Memory cgroup"}) {
            CHECK(jl.obs->subject.find(leak) == std::string_view::npos);
            CHECK(jl.obs->sentence.find(leak) == std::string_view::npos);
            CHECK(detail.find(leak) == std::string_view::npos);
        }
    };
    no_leak("Out of memory: Killed process 4321 (mysqld) total-vm:9000000kB, anon-rss:8000000kB, file-rss:0kB",
            "mysqld");
    no_leak("Memory cgroup out of memory: Killed process 1802705 (python3) total-vm:161112kB, anon-rss:8000000kB",
            "python3");
}

// ── pipe orchestration (extracted from the collector; tmpfile-driven, off-Linux) ──

TEST_CASE("read_pipe_line: strips the trailing newline and a preceding CR",
          "[guardian][dex][linux][journal][pipe]") {
    TempPipe tp{"alpha\r\nbeta\ngamma"};
    REQUIRE(tp.get());
    std::string line;
    REQUIRE(read_pipe_line(tp.get(), line));
    CHECK(line == "alpha"); // \r\n both stripped
    REQUIRE(read_pipe_line(tp.get(), line));
    CHECK(line == "beta");
    REQUIRE(read_pipe_line(tp.get(), line)); // final line, no trailing newline
    CHECK(line == "gamma");
    CHECK_FALSE(read_pipe_line(tp.get(), line)); // clean EOF
}

TEST_CASE("read_pipe_line: accumulates a line longer than the fgets buffer",
          "[guardian][dex][linux][journal][pipe]") {
    const std::string big(40000, 'x'); // > the 16 KiB internal buffer → multiple fgets chunks
    TempPipe tp{big + "\n"};
    REQUIRE(tp.get());
    std::string line;
    REQUIRE(read_pipe_line(tp.get(), line));
    CHECK(line == big);
    CHECK_FALSE(read_pipe_line(tp.get(), line));
}

TEST_CASE("read_pipe_line: an empty stream returns false and clears out",
          "[guardian][dex][linux][journal][pipe]") {
    TempPipe tp{""};
    REQUIRE(tp.get());
    std::string line = "stale";
    CHECK_FALSE(read_pipe_line(tp.get(), line));
    CHECK(line.empty()); // cleared even on the false path
}

TEST_CASE("build_journald_after_cursor_query: well-formed cursor → bounded, filtered query",
          "[guardian][dex][linux][journal][query]") {
    const auto cmd = build_journald_after_cursor_query("s=ab;i=1;b=cd");
    REQUIRE(cmd.has_value());
    CHECK(cmd->find("timeout ") != std::string::npos);                       // wedge-bounded
    CHECK(cmd->find("--after-cursor='s=ab;i=1;b=cd'") != std::string::npos); // cursor only in the quoted slot
    CHECK(cmd->find(std::string(kMsgIdCoredump)) != std::string::npos);
    CHECK(cmd->find(std::string(kMsgIdUnitFailed)) != std::string::npos);
    CHECK(cmd->find(std::string(kMsgIdUnitResult)) != std::string::npos);
    CHECK(cmd->find("_TRANSPORT=kernel") != std::string::npos);
    CHECK(cmd->find("_COMM=chronyd") != std::string::npos); // os.time_unsynced source (trusted field)
}

TEST_CASE("build_journald_after_cursor_query: a cursor with a single quote → nullopt (injection guard)",
          "[guardian][dex][linux][journal][query]") {
    // A real __CURSOR never contains a single quote; one that does could break out of
    // the single-quoted shell slot, so the builder refuses and signals re-baseline.
    CHECK_FALSE(build_journald_after_cursor_query("s=ab';rm -rf /;'").has_value());
    CHECK_FALSE(build_journald_after_cursor_query("'").has_value());
}

TEST_CASE("journald_baseline_query: tails one entry, wedge-bounded",
          "[guardian][dex][linux][journal][query]") {
    const std::string q = journald_baseline_query();
    CHECK(q.find("timeout ") != std::string::npos);
    CHECK(q.find("-n 1") != std::string::npos);
    CHECK(q.find("-o json") != std::string::npos);
}

TEST_CASE("drain_journal_pipe: classifies a stream and advances the cursor to the last entry",
          "[guardian][dex][linux][journal][drain]") {
    // coredump (→ obs), a non-OOM kernel line (no obs, advances cursor), unit failure
    // (→ obs). drain returns the 2 observations; the cursor advances to the newest.
    const std::string stream =
        R"({"__CURSOR":"c1","MESSAGE_ID":"fc2e22bc6ee647b6b90729ab34a250b1","COREDUMP_COMM":"nginx","COREDUMP_SIGNAL":"11"})"
        "\n"
        R"({"__CURSOR":"c2","_TRANSPORT":"kernel","MESSAGE":"usb 1-1: new device"})"
        "\n"
        R"({"__CURSOR":"c3","MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c","UNIT":"db.service","UNIT_RESULT":"exit-code"})"
        "\n";
    TempPipe tp{stream};
    REQUIRE(tp.get());
    std::string cursor = "c0";
    const auto obs = drain_journal_pipe(tp.get(), cursor);
    REQUIRE(obs.size() == 2);
    CHECK(obs[0].obs_type == "process.crashed");
    CHECK(obs[0].subject == "nginx");
    CHECK(obs[1].obs_type == "service.crashed");
    CHECK(obs[1].subject == "db.service");
    CHECK(cursor == "c3"); // advanced past the non-obs kernel line to the newest entry
}

TEST_CASE("drain_journal_pipe: an empty pipe yields no obs and leaves the cursor untouched",
          "[guardian][dex][linux][journal][drain]") {
    TempPipe tp{""};
    REQUIRE(tp.get());
    std::string cursor = "keep-me";
    const auto obs = drain_journal_pipe(tp.get(), cursor);
    CHECK(obs.empty());
    CHECK(cursor == "keep-me");
}

TEST_CASE("drain_journal_pipe: a malformed tail line does not advance the cursor",
          "[guardian][dex][linux][journal][drain]") {
    // The good line advances the cursor; the malformed tail has no __CURSOR, so the
    // cursor stops at the last good entry and that window is re-read next poll.
    const std::string stream =
        R"({"__CURSOR":"good","MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c","UNIT":"x.service","UNIT_RESULT":"exit-code"})"
        "\n"
        "this is not json\n";
    TempPipe tp{stream};
    REQUIRE(tp.get());
    std::string cursor = "start";
    const auto obs = drain_journal_pipe(tp.get(), cursor);
    REQUIRE(obs.size() == 1);
    CHECK(cursor == "good"); // not advanced past by the malformed line
}

TEST_CASE("JournalDebounce: collapses within the window, re-emits after it",
          "[guardian][dex][linux][journal][debounce]") {
    JournalDebounce d{300};
    CHECK(d.should_emit("service.crashed", "db.service", 1000));       // first → emit
    CHECK_FALSE(d.should_emit("service.crashed", "db.service", 1100)); // +100s, within → collapse
    CHECK_FALSE(d.should_emit("service.crashed", "db.service", 1299)); // still within
    CHECK(d.should_emit("service.crashed", "db.service", 1300));       // window elapsed → emit
    // a different (type, subject) is independent
    CHECK(d.should_emit("process.crashed", "db.service", 1100));
    CHECK(d.should_emit("service.crashed", "web.service", 1100));
}

TEST_CASE("JournalDebounce: evict_stale drops entries past the window, keeps fresh ones",
          "[guardian][dex][linux][journal][debounce]") {
    JournalDebounce d{300};
    d.should_emit("service.crashed", "old.service", 1000);
    d.should_emit("service.crashed", "new.service", 1250);
    CHECK(d.size() == 2);
    d.evict_stale(1300); // old: 1300-1000=300 >= window → evicted; new: 50 < window → kept
    CHECK(d.size() == 1);
    // the evicted key no longer suppresses — a fresh emit at the same time succeeds
    CHECK(d.should_emit("service.crashed", "old.service", 1300));
    CHECK(d.size() == 2);
}
