/**
 * printing_plugin.cpp — printer/job inventory plus one narrowly-scoped
 * `clear_queue` mutation (Destructive/Irreversible — cancelling a job has no
 * compensating Yuzu dispatch; see plugin_action_catalogue_printing.hpp).
 *
 * Actions:
 *   "printers"    — one row per printer: name, state (idle/processing/
 *                    stopped/unknown), state reasons, is_default, make and
 *                    model, uri, queued job count.
 *   "jobs"        — one row per queued job, optionally filtered to one
 *                    `printer`: printer, job id, owner, document (the job's
 *                    name/title — see printing_parsers.hpp's file banner for
 *                    the retention posture), status, submitted_at (ISO-8601
 *                    UTC), size in bytes.
 *   "clear_queue" — cancels EXACTLY ONE job (`printer` + `job_id`, both
 *                   required) via SetJobW(JOB_CONTROL_CANCEL) on Windows or
 *                   an IPP Cancel-Job over the CUPS Unix domain socket on
 *                   macOS/Linux. This file contains NO whole-queue-clearing
 *                   code path of any kind: no repeated per-job cancel loop,
 *                   no every-job control code, no "act on every job"
 *                   selector on the Cancel-Job request — one Cancel-Job call,
 *                   one job id, every time. On macOS/Linux the named printer
 *                   is BOUND to the job first: cupsd's Cancel-Job looks a job
 *                   up by id alone and ignores the printer, so a Get-Jobs of
 *                   that printer's not-completed jobs must list the id on
 *                   that printer before the Cancel-Job is sent
 *                   (run_clear_queue in printing_parsers.hpp). Windows binds
 *                   it in the spooler.
 *
 * No libcups, no vcpkg cups entry (verified absent from vcpkg.json) — the
 * IPP codec (printing_ipp.hpp) is a from-scratch minimal RFC 8010 encoder/
 * decoder built for this plugin alone. No OpenSSL — the CUPS Unix domain
 * socket carries no TLS. This is deliberately NOT http_client_plugin.cpp's
 * SSRF-guarded HTTP client: only `httplib_dep` is used directly, against a
 * fixed local socket path or `localhost:631`, never an operator-supplied
 * URL.
 *
 * AUTHORIZATION (macOS) — measured vs. unmeasured, stated explicitly so
 * neither gets overstated:
 *   - MEASURED: /etc/cups/cupsd.conf:88-90 `<Limit Cancel-Job
 *     CUPS-Authenticate-Job> Require user @OWNER
 *     @AUTHKEY(system.print.operator) @admin @lpadmin`, no `@SYSTEM`.
 *     cupsd consults the Unix-domain-socket peer's credentials ONLY when
 *     the request carries header `Authorization: PeerCred <username>` —
 *     hence `clear_queue` sends BOTH
 *     `requesting-user-name=<getpwuid(geteuid())->pw_name>` in the IPP
 *     request body AND that same header, over the Unix socket ONLY. No
 *     socket -> refused, `<os>:cups:socket_unavailable`, never a TCP
 *     fallback for this action (TCP `localhost:631` is used for READ
 *     actions only, and only when no socket is found).
 *   - MEASURED: cupsd accepts the header and returns a normal IPP response
 *     with it present — real capture
 *     tests/unit/fixtures/wave9/printing/macos/
 *     real_cancel_job_not_found_peercred.ipp is byte-identical to its
 *     without-header sibling real_cancel_job_not_found.ipp, proving the
 *     header does not disturb request framing or the IPP response.
 *   - EXPLICITLY UNMEASURED: whether the header changes the authorisation
 *     *outcome* for a job the daemon identity does not own. Both real
 *     captures above target a job id that does not exist, so both
 *     short-circuit at not-found (0x0406) before cupsd's Cancel-Job policy
 *     is ever evaluated — this open question is closed only by a
 *     privileged `capture.sh --phase-b` run (an owner-mismatch cancel
 *     against a real job) or by I93-7's Debian/Ubuntu cupsd container
 *     capture. No sentence here may resolve it in either direction until
 *     one of those exists. No identity-mismatch control is possible on a
 *     stock macOS host at all — every local account is a print operator
 *     via `_lpoperator`'s nested groups — so even Phase B cannot supply
 *     the identity-refusal half of that control; only the Linux container
 *     can.
 *
 * Windows: EnumPrintersW/EnumJobsW/OpenPrinterW/GetJobW/SetJobW
 * (winspool.h). `kReadDesiredAccess`/`kCancelDesiredAccess` below are
 * RECONCILED against P93-2's the-rig measurement (both admin and SYSTEM,
 * against `Microsoft Print to PDF`) — see
 * tests/unit/fixtures/wave9/printing/windows/setjob_cancel.txt.provenance.txt.
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

#include "printing_ipp.hpp"
#include "printing_parsers.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <winspool.h>
#pragma comment(lib, "winspool.lib")

#include "win_str.hpp" // yuzu::win::from_wide/to_wide — ../../shared include dir
#include "bounded_wait.hpp" // yuzu::shared::bounded_call — ../../shared include dir
#else
#include <httplib.h>

#include <cstdio>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

using namespace yuzu::printing;

std::atomic<uint32_t> g_request_id{1};

uint32_t next_request_id() {
    return g_request_id.fetch_add(1, std::memory_order_relaxed);
}

#ifdef _WIN32

// Used to open the handle for every read (EnumJobsW/GetJobW). Confirmed by
// P93-2's the-rig measurement (admin and SYSTEM, both cancel paths below).
constexpr DWORD kReadDesiredAccess = PRINTER_ACCESS_USE;

// Round-3 review Should-fix: failure tokens for the Windows leg, mirroring
// the POSIX leg's <os>:<source>:<detail> taxonomy (kTokConnectFailed et al.
// below in the #else block) -- the Windows leg previously never called
// set_result_status() at all, so every failure silently read as an empty-
// but-fine queue instead of a distinguishable CONSTRAINED/PARTIAL result.
constexpr std::string_view kTokEnumPrintersFailed = "windows:winspool:enum_printers_failed";
constexpr std::string_view kTokJobEnumFailed = "windows:winspool:enum_jobs_failed";
// Round-4 review minor: a denied/failed OpenPrinterW is a different failure
// point than EnumJobsW itself failing -- folding both under the enum token
// mislabels the actual failing call for triage. do_jobs uses it when every
// per-printer job-read problem in one dispatch was an open failure, never an
// enum one (see do_jobs's token-selection comment); do_clear_queue uses it
// for an open failure that is neither not-found nor access-denied.
constexpr std::string_view kTokOpenPrinterFailed = "windows:winspool:open_printer_failed";

// Round-3 review Should-fix: EnumPrintersW/EnumJobsW are plain synchronous
// calls with no cancellation of their own. PRINTER_ENUM_CONNECTIONS
// specifically requests enumeration of network-connected printer mappings,
// which Windows documents as able to block for an extended period against
// an unreachable print server -- bounding the WAIT (yuzu::shared::
// bounded_call, agents/shared/bounded_wait.hpp) keeps a stuck spooler from
// pinning this plugin's dispatch thread indefinitely. This is an
// availability bound only, not the dism_bounded_call.hpp plugin-unload UAF
// class -- neither enum function holds an OS handle across the timeout
// boundary that a caller would need to synchronize against on abandonment.
constexpr std::chrono::milliseconds kSpoolerCallTimeout{5000};

// Round-4 review blocker (fjarvis + Codex, cross-examined): bounded_call is a
// header-only template, so instantiating it here compiles the ENTIRE
// detached-thread body -- spawn, condvar logic, enum_printers_raw_impl()
// itself -- into printing.dll. plugin.hpp:245's shutdown() contract says a
// background thread that may still be running past the bounded wait's
// timeout "must never touch this plugin's own code or statics after that
// point (dlclose/FreeLibrary can unmap them while it runs)". This plugin's
// original shutdown() was a bare no-op, so 100% of a timed-out call's
// residual work could run into an unmapped DSO -- a MODULE-lifetime hazard,
// distinct from the OS-handle-lifetime one kMaxJobsPerPrinter's own comment
// discusses below (that one is about enum_jobs_raw's live HANDLE; this one
// is about the .dll's own code/statics).
//
// power_health_plugin.cpp establishes the fix for exactly this primitive:
// g_outstanding_calls/OutstandingGuard/bounded_call_tracked() below are
// copied from there verbatim in shape (see that file's own comment on why
// the guard decrements on the CALLING thread only, never from inside
// bounded_call()'s detached thread) -- shutdown() pairs with it via the same
// bounded 2x-timeout quiesce.
std::atomic<int> g_outstanding_calls{0};

class OutstandingGuard {
public:
    OutstandingGuard() noexcept { ++g_outstanding_calls; }
    ~OutstandingGuard() noexcept { --g_outstanding_calls; }
    OutstandingGuard(const OutstandingGuard&) = delete;
    OutstandingGuard& operator=(const OutstandingGuard&) = delete;
};

template <typename Fn>
auto bounded_call_tracked(Fn fn) -> std::optional<std::invoke_result_t<Fn>> {
    OutstandingGuard guard;
    return yuzu::shared::bounded_call(kSpoolerCallTimeout, std::move(fn));
}

// SetJobW(JOB_CONTROL_CANCEL) through a PRINTER_ACCESS_USE-only handle
// cancelled a real job on `Microsoft Print to PDF` under BOTH
// BUILTIN\Administrators and NT AUTHORITY\SYSTEM (GetLastError()==0) -- see
// tests/unit/fixtures/wave9/printing/windows/setjob_cancel.txt.provenance.txt.
// Both measured tokens are already elevated, so the outcome for a
// least-privileged identity cancelling ANY job (its own or another user's)
// was NOT measured (docs/agent-privilege-model.md); nor is it measured
// whether job access is judged against the caller's token or the handle's
// access mask. "USE is enough" must not be read as "no administer right is
// ever needed". Kept narrower than
// PRINTER_ALL_ACCESS/JOB_ACCESS_ADMINISTER on purpose: clear_queue cancels
// exactly one job id and needs no broader grant than that.
constexpr DWORD kCancelDesiredAccess = PRINTER_ACCESS_USE;

// Move-only RAII owner for an HPRINTER (PH-015-style ownership rule, same
// shape as power_health's DirHandle / the repo's other Scoped* wrappers):
// takes ownership only once OpenPrinterW has actually succeeded, and
// ClosePrinter()s exactly once on every exit path.
class PrinterHandle {
public:
    PrinterHandle() = default;
    explicit PrinterHandle(HANDLE h) noexcept : h_{h} {}
    ~PrinterHandle() {
        if (h_ != nullptr)
            ClosePrinter(h_);
    }
    PrinterHandle(const PrinterHandle&) = delete;
    PrinterHandle& operator=(const PrinterHandle&) = delete;
    PrinterHandle(PrinterHandle&& other) noexcept : h_{other.h_} { other.h_ = nullptr; }
    PrinterHandle& operator=(PrinterHandle&& other) noexcept {
        if (this != &other) {
            if (h_ != nullptr)
                ClosePrinter(h_);
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept { return h_ != nullptr; }

private:
    HANDLE h_ = nullptr;
};

// `last_error`, when non-null, receives GetLastError() read immediately after
// a failed OpenPrinterW -- before anything else can overwrite it -- so a
// caller can tell access-denied from a nonexistent printer. It is a plain
// caller-stack pointer written synchronously: do NOT run this under
// bounded_call_tracked (an abandoned worker would write into a dead frame).
// A TRUE return with a null handle is not known to occur; if it did, the
// code read here would be stale and meaningless.
[[nodiscard]] std::optional<PrinterHandle> open_printer(const std::wstring& name, DWORD access,
                                                         DWORD* last_error = nullptr) {
    PRINTER_DEFAULTSW defaults{};
    defaults.DesiredAccess = access;
    HANDLE raw = nullptr;
    if (!OpenPrinterW(const_cast<LPWSTR>(name.c_str()), &raw, &defaults) || raw == nullptr) {
        if (last_error != nullptr)
            *last_error = GetLastError();
        return std::nullopt;
    }
    return PrinterHandle{raw};
}

// PRINTER_INFO_2W/JOB_INFO_2W are fixed-size structs whose string members
// (pPrinterName, pDriverName, pUserName, pDocument, ...) are pointers INTO
// the flat marshaled buffer EnumPrintersW/EnumJobsW filled — copying the
// struct by value does not copy what it points to. Bundling the backing
// buffer alongside the parsed structs (moved, so the heap block's address
// is unchanged) keeps every one of those pointers valid for as long as the
// caller holds this result; returning the structs alone left every pointer
// dangling into a buffer freed at function return (heap-use-after-free on
// every field read by do_printers/do_jobs — fixed here, the-rig build).
// Round-3 review Should-fix: `ok` distinguishes "the call genuinely found
// zero items" (ok=true, items empty) from "the win32 call itself failed"
// (ok=false) -- an empty PrinterEnumRaw{} used to mean both, which is
// exactly the false-empty failure mode the POSIX leg's transport/decode/
// status checks were built to avoid. `last_error` is GetLastError() from
// whichever call failed, folded into the CONSTRAINED status detail string.
struct PrinterEnumRaw {
    std::vector<PRINTER_INFO_2W> items;
    std::vector<std::byte> backing;
    bool ok = false;
    DWORD last_error = 0;
};

struct JobEnumRaw {
    std::vector<JOB_INFO_2W> items;
    std::vector<std::byte> backing;
    bool ok = false;
    DWORD last_error = 0;
};

// EnumPrintersW's standard two-call pattern: size, allocate, fill. A first
// call that SUCCEEDS with needed==0 means genuinely zero printers (ok=true,
// empty); a first call that FAILS with needed==0 is a real error, never
// silently treated as "no printers" (contrast the pre-fix version, which
// returned an indistinguishable empty result either way).
[[nodiscard]] PrinterEnumRaw enum_printers_raw_impl() {
    PrinterEnumRaw result;
    DWORD needed = 0, returned = 0;
    if (EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, nullptr, 2, nullptr, 0,
                       &needed, &returned)) {
        result.ok = true; // zero-size success: genuinely no printers
        return result;
    }
    if (needed == 0) {
        result.last_error = GetLastError();
        return result;
    }
    std::vector<std::byte> buf(needed);
    if (!EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, nullptr, 2,
                        reinterpret_cast<LPBYTE>(buf.data()), needed, &needed, &returned)) {
        result.last_error = GetLastError();
        return result;
    }
    std::vector<PRINTER_INFO_2W> out;
    out.reserve(returned);
    auto* items = reinterpret_cast<PRINTER_INFO_2W*>(buf.data());
    for (DWORD i = 0; i < returned; ++i)
        out.push_back(items[i]);
    result.items = std::move(out);
    result.backing = std::move(buf);
    result.ok = true;
    return result;
}

// Bounds the WAIT on enum_printers_raw_impl() -- PRINTER_ENUM_CONNECTIONS
// can block against an unreachable network print server (see
// kSpoolerCallTimeout's own comment above). A timeout or ceiling-rejection
// both fold into the same not-ok, no-GetLastError() outcome as a genuine
// win32 failure -- the caller's CONSTRAINED path doesn't need to
// distinguish them, and PrinterEnumRaw's default-constructed ok=false
// already means exactly that.
[[nodiscard]] PrinterEnumRaw enum_printers_raw() {
    auto result = bounded_call_tracked(enum_printers_raw_impl);
    return result ? std::move(*result) : PrinterEnumRaw{};
}

[[nodiscard]] std::wstring default_printer_name_raw() {
    DWORD size = 0;
    GetDefaultPrinterW(nullptr, &size);
    if (size == 0)
        return {};
    std::vector<wchar_t> buf(size, L'\0');
    if (!GetDefaultPrinterW(buf.data(), &size))
        return {};
    return std::wstring(buf.data());
}

// Round-3 review Should-fix: caps the row count EnumJobsW is asked to
// return, matching the POSIX leg's own bounded design intent (no leg had an
// explicit cap before this). Deliberately NOT wrapped in bounded_call()
// like enum_printers_raw() above -- unlike that function, this one is
// handed a live HANDLE the CALLER owns and closes immediately on return
// (PrinterHandle's destructor, do_jobs's per-printer loop); bounded_call()
// abandoning a timed-out call would race that close against the still-
// running detached thread's use of the same handle (bounded_wait.hpp's own
// documented caller contract: "closing the handle races a live call").
// Retrofitting that safely needs the caller to defer ClosePrinter() past
// any possible in-flight detached use, which is a larger structural change
// than this non-blocking finding calls for -- the row cap alone bounds the
// call's OWN cost without touching handle lifetime.
constexpr DWORD kMaxJobsPerPrinter = 5000;

// EnumJobsW's standard two-call pattern over an already-open printer handle.
[[nodiscard]] JobEnumRaw enum_jobs_raw(HANDLE h) {
    JobEnumRaw result;
    DWORD needed = 0, returned = 0;
    if (EnumJobsW(h, 0, kMaxJobsPerPrinter, 2, nullptr, 0, &needed, &returned)) {
        result.ok = true; // zero-size success: genuinely no queued jobs
        return result;
    }
    if (needed == 0) {
        result.last_error = GetLastError();
        return result;
    }
    std::vector<std::byte> buf(needed);
    if (!EnumJobsW(h, 0, kMaxJobsPerPrinter, 2, reinterpret_cast<LPBYTE>(buf.data()), needed,
                    &needed, &returned)) {
        result.last_error = GetLastError();
        return result;
    }
    std::vector<JOB_INFO_2W> out;
    out.reserve(returned);
    auto* items = reinterpret_cast<JOB_INFO_2W*>(buf.data());
    for (DWORD i = 0; i < returned; ++i)
        out.push_back(items[i]);
    result.items = std::move(out);
    result.backing = std::move(buf);
    result.ok = true;
    return result;
}

// JOB_INFO_2W's `Submitted` is the spooler's local wall-clock time at
// submission (matches the "Submitted" column the Windows print-queue UI
// shows), not UTC — converted here before formatting so `submitted_at`
// keeps the same ISO-8601 UTC contract as the IPP leg's `time-at-creation`.
// A zeroed or unconvertible SYSTEMTIME (job info with no submission stamp)
// falls back to "-", same as the IPP leg's absent-attribute case.
[[nodiscard]] std::string iso8601_utc_from_local_systemtime(const SYSTEMTIME& local) {
    if (local.wYear == 0)
        return "-";
    SYSTEMTIME utc{};
    if (!TzSpecificLocalTimeToSystemTime(nullptr, &local, &utc))
        return "-";
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", utc.wYear, utc.wMonth, utc.wDay,
                        utc.wHour, utc.wMinute, utc.wSecond);
}

[[nodiscard]] JobRow job_row_from_info(std::string_view printer_name, const JOB_INFO_2W& j) {
    JobRow row;
    row.printer = std::string(printer_name);
    row.job_id = static_cast<int64_t>(j.JobId);
    row.owner = j.pUserName != nullptr ? yuzu::win::from_wide(j.pUserName) : "-";
    row.document = j.pDocument != nullptr ? yuzu::win::from_wide(j.pDocument) : "-";
    row.status = job_status_from_winspool(j.Status);
    row.submitted_at = iso8601_utc_from_local_systemtime(j.Submitted);
    // JOB_INFO_2W::Size is a DWORD -- always non-negative, so there is no
    // winspool "unknown size" sentinel to detect here (unlike the IPP leg's
    // absent job-k-octets attribute, which does have one). `j.Size >= 0` was
    // a tautology (MinGW -Wsign-conversion et al.: "comparison of unsigned
    // expression in '>= 0' is always true"), so the -1 fallback was dead
    // code -- report the byte count verbatim.
    row.size_bytes = static_cast<int64_t>(j.Size);
    return row;
}

// Round-4 review minor: last_error==0 on a !ok result means the bounded wait
// itself gave up (timeout or ceiling-rejection, see enum_printers_raw's own
// comment) -- EnumPrintersW was never actually reached, so it never called
// SetLastError at all. Reporting that bare as "GetLastError=0" reads like
// "the call succeeded with no error", the opposite of what happened.
[[nodiscard]] std::string format_printer_enum_failure(DWORD last_error) {
    if (last_error == 0)
        return "EnumPrintersW bounded call timed out or was rejected (never reached the win32 "
               "call)";
    return std::format("EnumPrintersW failed, GetLastError={}", last_error);
}

int do_printers(yuzu::CommandContext& ctx) {
    const auto raw = enum_printers_raw();
    if (!raw.ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               format_printer_enum_failure(raw.last_error));
        ctx.write_output(std::format("printer|unavailable|{}", kTokEnumPrintersFailed));
        return 0;
    }
    const std::wstring default_name = default_printer_name_raw();

    if (raw.items.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        ctx.write_output("printer|none");
        return 0;
    }

    for (const auto& pi : raw.items) {
        PrinterRow row;
        row.name = pi.pPrinterName != nullptr ? yuzu::win::from_wide(pi.pPrinterName) : "-";
        row.state = printer_state_from_winspool(pi.Status, pi.cJobs);
        row.state_reasons = "-"; // winspool has no state-reasons vocabulary
        row.is_default = !default_name.empty() && pi.pPrinterName != nullptr &&
                          default_name == pi.pPrinterName;
        row.make_model = pi.pDriverName != nullptr ? yuzu::win::from_wide(pi.pDriverName) : "-";
        row.uri = pi.pPortName != nullptr ? yuzu::win::from_wide(pi.pPortName) : "-";
        row.queued_jobs = static_cast<int64_t>(pi.cJobs);
        ctx.write_output(format_printer_row(row));
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    return 0;
}

int do_jobs(yuzu::CommandContext& ctx, const yuzu::Params& params) {
    const std::string filter_printer{params.get("printer")};
    const auto raw_printers = enum_printers_raw();
    if (!raw_printers.ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               format_printer_enum_failure(raw_printers.last_error));
        ctx.write_output(std::format("job|unavailable|{}", kTokEnumPrintersFailed));
        return 0;
    }

    bool any = false;
    // Round-3 review Should-fix: tracks whether ANY per-printer job read
    // failed (open_printer denied, or enum_jobs_raw() itself failing) so the
    // action's overall result_status can surface CONSTRAINED/PARTIAL rather
    // than reporting a subset of printers' queues as though it were the
    // complete picture. A single printer's own queue being unreadable stays
    // a per-printer skip, not a whole-action failure (existing design), but
    // it is no longer a SILENT one.
    //
    // Round-4 review: split into two signals so the aggregate token names
    // the actual failing call (minor) and so a TRUNCATED-but-successful read
    // is treated the same as an outright failed one (should-fix) --
    // `enum_incomplete` covers both: enum_jobs_raw() itself failing, and
    // enum_jobs_raw() succeeding but returning fewer rows than the printer's
    // own queue depth (`pi.cJobs`, sampled by the same enum_printers_raw()
    // call moments earlier) says exist. EnumJobsW's NoJobs parameter
    // (kMaxJobsPerPrinter) is a requested MAXIMUM, not a completeness proof
    // -- a queue past that cap returns exactly the cap's worth of rows,
    // which the old code reported as OK/FULL, contradicting this plugin's
    // own "never present a partial read as complete" design.
    bool any_open_failed = false;
    bool any_enum_incomplete = false;
    for (const auto& pi : raw_printers.items) {
        const std::string name = pi.pPrinterName != nullptr ? yuzu::win::from_wide(pi.pPrinterName) : "";
        if (!filter_printer.empty() && name != filter_printer)
            continue;

        auto handle = open_printer(pi.pPrinterName != nullptr ? pi.pPrinterName : L"", kReadDesiredAccess);
        if (!handle) {
            any_open_failed = true;
            continue; // this printer's jobs are simply unavailable; not a whole-action failure
        }
        const auto jobs = enum_jobs_raw(handle->get());
        if (!jobs.ok) {
            any_enum_incomplete = true;
            continue;
        }
        if (jobs.items.size() < pi.cJobs)
            any_enum_incomplete = true; // truncated at kMaxJobsPerPrinter; not the full queue
        for (const auto& j : jobs.items) {
            any = true;
            ctx.write_output(format_job_row(job_row_from_info(name, j)));
        }
    }

    // enum_incomplete outranks open_failed when both occurred in one
    // dispatch: a truncated/failed enumeration is the more actionable signal
    // (it means real job data was dropped), while an open failure alone
    // means that printer contributed nothing either way.
    const bool any_job_read_failed = any_open_failed || any_enum_incomplete;
    const std::string_view failure_token =
        any_enum_incomplete ? kTokJobEnumFailed : kTokOpenPrinterFailed;

    if (!any) {
        if (any_job_read_failed) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "one or more printers' job queues could not be read");
            ctx.write_output(std::format("job|unavailable|{}", failure_token));
        } else {
            ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
            ctx.write_output("job|none");
        }
        return 0;
    }
    if (any_job_read_failed) {
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "one or more printers' job queues could not be read; partial results only");
    } else {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    }
    return 0;
}

// Round-3/4 review bounded enum_printers_raw() (a network-reachable-server
// hang risk, PRINTER_ENUM_CONNECTIONS) but deliberately left enum_jobs_raw()
// unbounded -- see that function's own comment: it is handed a live HANDLE
// the CALLER owns and closes on return, and bounded_call()'s own documented
// contract (bounded_wait.hpp) says a caller holding an OS handle across a
// timeout "races a live call and it has to be leaked". open_printer/GetJobW/
// SetJobW below are in exactly that same shape -- all three run against
// `handle`, which PrinterHandle's destructor closes the moment this function
// returns -- so they follow enum_jobs_raw's precedent and stay unbounded on
// purpose, not by oversight. Wrapping them in bounded_call_tracked() would
// reintroduce the exact handle-close race that precedent exists to avoid.
int do_clear_queue(yuzu::CommandContext& ctx, const yuzu::Params& params) {
    const std::string printer{params.get("printer")};
    const std::string job_id_str{params.get("job_id")};

    if (printer.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "missing required param 'printer'");
        ctx.write_output(format_clear_queue_row("", 0, "error", "missing_printer"));
        return 1;
    }
    const auto job_id = parse_job_id(job_id_str);
    if (!job_id) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "invalid or missing 'job_id'");
        ctx.write_output(format_clear_queue_row(printer_name_is_valid_windows(printer) ? printer : "-", 0, "error",
                                                 "invalid_job_id"));
        return 1;
    }
    // OpenPrinterW gives `,` special meaning (address syntaxes such as `,XcvPort ...`,
    // `Printer, Job N`, `,LocalPrintServer`) and a Windows printer name cannot contain
    // one, so such a name is never a real printer: refuse it, do not open it. (On real
    // Windows, with this agent's PRINTER_ACCESS_USE, only `,XcvMonitor Local Port` was
    // recognised, with error 5; this is hardening, not a closed hole.)
    if (!printer_name_is_valid_windows(printer)) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "invalid printer name");
        ctx.write_output(format_clear_queue_row("-", *job_id, "error", "invalid_printer"));
        return 1;
    }

    const std::wstring wprinter = yuzu::win::to_wide(printer);

    DWORD open_error = 0;
    auto handle = open_printer(wprinter, kCancelDesiredAccess, &open_error);
    if (!handle) {
        const OpenPrinterFailure failure = classify_open_printer_error(static_cast<uint32_t>(open_error));
        if (failure == OpenPrinterFailure::refused) {
            ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_FULL,
                                   "OpenPrinterW: access denied");
            ctx.write_output(
                format_clear_queue_row(printer, *job_id, "refused", "windows:winspool:access_denied"));
            return 1;
        }
        if (failure == OpenPrinterFailure::not_found) {
            // 1801 is definitive for a plain local name, but OpenPrinterW returns
            // the SAME 1801 for a UNC name whose server is unreachable (observed
            // on real Windows). A name with a path separator or colon may name a
            // remote server (UNC, URL forms), so it cannot claim the printer is
            // gone: report it, but PARTIAL.
            const bool plain = printer_name_is_plain_local(printer);
            ctx.set_result_status(
                YUZU_RESULT_STATUS_UNAVAILABLE,
                plain ? YUZU_RESULT_COMPLETENESS_FULL : YUZU_RESULT_COMPLETENESS_PARTIAL,
                plain ? "OpenPrinterW: printer not found"
                      : "OpenPrinterW: printer not found (name may be remote; the server may be unreachable)");
            ctx.write_output(
                format_clear_queue_row(printer, *job_id, "not_found", "windows:winspool:printer_not_found"));
            return 1;
        }
        // Every other failure (spooler stopped, RPC unavailable, ...): always
        // reported, so a future OpenPrinterFailure enumerator cannot fall out
        // of a switch silently on MSVC (where -Wswitch is not enabled).
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               std::format("OpenPrinterW failed (Win32 error {})", open_error));
        ctx.write_output(format_clear_queue_row(printer, *job_id, "error", kTokOpenPrinterFailed));
        return 1;
    }

    // GetJobW confirms the job exists before attempting SetJobW.
    DWORD needed = 0;
    GetJobW(handle->get(), static_cast<DWORD>(*job_id), 1, nullptr, 0, &needed);
    if (GetLastError() == ERROR_INVALID_PARAMETER) {
        // PARTIAL, not FULL: 87 for a nonexistent job was measured only under
        // elevated identities, and what GetJobW returns for an EXISTING job the
        // caller may not read is unmeasured -- a FULL not_found could hide a
        // denial. Upgrade only once a non-elevated identity has been measured.
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "GetJobW: job not found");
        ctx.write_output(format_clear_queue_row(printer, *job_id, "not_found", "windows:winspool:job_not_found"));
        return 1;
    }

    // Microsoft documents JOB_CONTROL_CANCEL as "do not use" in favour of
    // JOB_CONTROL_DELETE; cancel was nonetheless measured working on real
    // hardware (setjob_cancel.txt.provenance.txt), which is what this leg is
    // reconciled against.
    if (!SetJobW(handle->get(), static_cast<DWORD>(*job_id), 0, nullptr, JOB_CONTROL_CANCEL)) {
        const DWORD set_error = GetLastError();
        if (set_error == ERROR_ACCESS_DENIED) {
            ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_FULL,
                                   "SetJobW: access denied");
            ctx.write_output(
                format_clear_queue_row(printer, *job_id, "refused", "windows:winspool:access_denied"));
            return 1;
        }
        if (set_error == ERROR_INVALID_PARAMETER) {
            // The job finished between the GetJobW check above and this call
            // (SetJobW returned 87 for a nonexistent JobId when measured on
            // real hardware, under elevated identities only).
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "SetJobW: job not found");
            ctx.write_output(
                format_clear_queue_row(printer, *job_id, "not_found", "windows:winspool:job_not_found"));
            return 1;
        }
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               std::format("SetJobW failed (Win32 error {})", set_error));
        ctx.write_output(format_clear_queue_row(printer, *job_id, "error", "windows:winspool:set_job_failed"));
        return 1;
    }

    // Best-effort readback — does not change the outcome; SetJobW already
    // reported success. A readback failure here would not un-succeed the
    // cancellation, so it is not consulted for the status/exit code.
    DWORD readback_needed = 0;
    GetJobW(handle->get(), static_cast<DWORD>(*job_id), 1, nullptr, 0, &readback_needed);

    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    ctx.write_output(format_clear_queue_row(printer, *job_id, "canceled", "-"));
    return 0;
}

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "printers",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib)",
         "localhost:631 fallback for reads when no socket is found"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib)",
         "localhost:631 fallback for reads when no socket is found"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool EnumPrintersW level 2", nullptr},
    },
    {
        /* .action      = */ "jobs",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket",
         "localhost:631 fallback for reads when no socket is found"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket",
         "localhost:631 fallback for reads when no socket is found"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool EnumJobsW level 2", nullptr},
    },
    {
        /* .action      = */ "clear_queue",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "IPP Cancel-Job on one job id over the CUPS Unix socket with Authorization: PeerCred",
         "measured in a Debian/Ubuntu cupsd container: container root/@SYSTEM (SystemGroup root "
         "lpadmin) cancelling another user's job succeeds (status 0x0000, I93-7) — but the "
         "production Linux agent runs unprivileged (docs/agent-privilege-model.md), never root "
         "or @SYSTEM, so an ordinary non-owning cancel is correctly refused (403) before "
         "Cancel-Job is ever reached; reliable only for a job the agent's own identity owns"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "IPP Cancel-Job on one job id over the CUPS Unix socket with Authorization: PeerCred",
         "PROVISIONAL — cupsd.conf Cancel-Job policy requires @OWNER/"
         "@AUTHKEY(system.print.operator)/@admin/@lpadmin (no @SYSTEM); header accepted by "
         "cupsd, authorisation outcome for a non-owned job UNMEASURED"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool SetJobW JOB_CONTROL_CANCEL on one job id",
         "cancel measured only under Administrators and SYSTEM (SYSTEM is today's agent identity, #1442); "
         "a least-privileged identity cancelling any job (its own or another user's) is unmeasured, and "
         "that a PRINTER_ACCESS_USE handle suffices for it is an extrapolation - see "
         "docs/agent-privilege-model.md"},
    },
};

#else // POSIX (macOS + Linux) — one leg for both, per this plugin's failure-token split below

// ── failure tokens — <os>:<source>:<detail> string literals ────────────────
// The POSIX leg below is ONE #else block shared by macOS and Linux, so the
// concrete token text is split by #if defined(__APPLE__) here — both literal
// sets are present in this file's text, and the leg picks the right one at
// compile time (never a runtime string substitution).
#if defined(__APPLE__)
constexpr std::string_view kTokSocketUnavailable = "macos:cups:socket_unavailable";
constexpr std::string_view kTokConnectFailed = "macos:cups:connect_failed";
constexpr std::string_view kTokDecodeFailed = "macos:cups:decode_failed";
constexpr std::string_view kTokAccessDenied = "macos:cups:access_denied";
constexpr std::string_view kTokNotFound = "macos:cups:not_found";
constexpr std::string_view kTokUnexpectedStatus = "macos:cups:unexpected_status";
constexpr std::string_view kTokNoIdentity = "macos:cups:no_identity";
#else
constexpr std::string_view kTokSocketUnavailable = "linux:cups:socket_unavailable";
constexpr std::string_view kTokConnectFailed = "linux:cups:connect_failed";
constexpr std::string_view kTokDecodeFailed = "linux:cups:decode_failed";
constexpr std::string_view kTokAccessDenied = "linux:cups:access_denied";
constexpr std::string_view kTokNotFound = "linux:cups:not_found";
constexpr std::string_view kTokUnexpectedStatus = "linux:cups:unexpected_status";
constexpr std::string_view kTokNoIdentity = "linux:cups:no_identity";
#endif

constexpr int kConnectTimeoutSec = 2;
constexpr int kReadTimeoutSec = 5;

// First existing candidate is the CUPS Unix domain socket this plugin talks
// to; `/private/var/run/cupsd` is the measured path on this Mac.
[[nodiscard]] std::optional<std::string> find_cups_socket() {
    static constexpr const char* kCandidates[] = {
        "/private/var/run/cupsd",
        "/var/run/cupsd",
        "/run/cups/cups.sock",
        "/var/run/cups/cups.sock",
    };
    for (const char* path : kCandidates) {
        struct stat st{};
        if (::stat(path, &st) == 0 && S_ISSOCK(st.st_mode))
            return std::string(path);
    }
    return std::nullopt;
}

[[nodiscard]] std::string current_username() {
    // getpwuid(geteuid()) — the real effective-user CUPS's peer-credential
    // check reads off the Unix socket; not getlogin(), which reads the
    // controlling terminal's login name and can disagree with euid.
    if (struct passwd* pw = getpwuid(geteuid()); pw != nullptr && pw->pw_name != nullptr)
        return std::string(pw->pw_name);
    return std::string();
}

// Issues one IPP POST over the CUPS Unix socket (set_address_family(AF_UNIX)
// BEFORE the first Post — httplib 0.37.1 only emits `Host: localhost` once
// address_family_ == AF_UNIX, and cupsd 400s a path-shaped Host otherwise).
[[nodiscard]] IppResult post_ipp_unix(const std::string& socket_path, const std::string& body,
                                       const httplib::Headers& extra_headers) {
    httplib::Client cli(socket_path);
    cli.set_address_family(AF_UNIX);
    cli.set_connection_timeout(kConnectTimeoutSec, 0);
    cli.set_read_timeout(kReadTimeoutSec, 0);

    IppResult result;
    auto res = cli.Post("/", extra_headers, body, "application/ipp");
    if (!res)
        return result;
    result.transport_ok = true;
    result.http_status = res->status;
    if (res->status == 200) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(res->body.data());
        result.message = ipp::decode(std::span<const uint8_t>(bytes, res->body.size()));
    }
    return result;
}

[[nodiscard]] IppResult post_ipp_tcp_localhost(const std::string& body) {
    httplib::Client cli("localhost", 631);
    cli.set_connection_timeout(kConnectTimeoutSec, 0);
    cli.set_read_timeout(kReadTimeoutSec, 0);

    IppResult result;
    auto res = cli.Post("/", httplib::Headers{}, body, "application/ipp");
    if (!res)
        return result;
    result.transport_ok = true;
    result.http_status = res->status;
    if (res->status == 200) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(res->body.data());
        result.message = ipp::decode(std::span<const uint8_t>(bytes, res->body.size()));
    }
    return result;
}

// Shared by "printers" and "jobs": a READ-only IPP round trip, preferring
// the Unix socket and falling back to TCP localhost:631 when no socket is
// found (reads only — clear_queue never falls back to TCP, see its own
// comment).
[[nodiscard]] IppResult do_read_ipp(const std::string& body) {
    if (const auto socket_path = find_cups_socket())
        return post_ipp_unix(*socket_path, body, httplib::Headers{});
    return post_ipp_tcp_localhost(body);
}

int do_printers(yuzu::CommandContext& ctx) {
    const auto req = ipp::encode_request(ipp::kCupsGetPrinters, next_request_id(), {});
    const auto result = do_read_ipp(req);

    if (!result.transport_ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "CUPS-Get-Printers: transport failed");
        ctx.write_output(std::format("printer|unavailable|{}", kTokConnectFailed));
        return 0;
    }
    if (!result.message) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "CUPS-Get-Printers: response did not decode");
        ctx.write_output(std::format("printer|unavailable|{}", kTokDecodeFailed));
        return 0;
    }
    // 0x0406 (client-error-not-found) is CUPS's own vendor convention for
    // CUPS-Get-Printers with zero configured destinations -- REAL CAPTURE
    // confirmed (real_cups_get_printers_empty.ipp: status-message "No
    // destinations added."). This request never names a specific printer,
    // so 0x0406 here can only mean "none exist", never "the one you asked
    // about is missing" (contrast Get-Jobs, where the same code names a
    // bad printer-uri and is a genuine failure) -- fall through to the
    // ordinary empty-rows path rather than reporting CONSTRAINED.
    if (result.message->op_or_status > 0x00FF && result.message->op_or_status != 0x0406) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               std::format("CUPS-Get-Printers: unexpected status 0x{:04x}",
                                           result.message->op_or_status));
        ctx.write_output(std::format("printer|unavailable|{}", kTokUnexpectedStatus));
        return 0;
    }

    // Best-effort default-printer resolution — a failure here just means no
    // row gets is_default=1, never a whole-action failure.
    std::string default_name;
    {
        const auto default_req = ipp::encode_request(ipp::kCupsGetDefault, next_request_id(), {});
        if (const auto default_result = do_read_ipp(default_req);
            default_result.transport_ok && default_result.message) {
            for (const auto& [tag, attrs] : default_result.message->groups) {
                if (tag != ipp::kTagPrinterAttributes)
                    continue;
                for (const auto& a : attrs) {
                    if (a.name == "printer-name" && !a.values.empty()) {
                        default_name = a.values.front();
                    }
                }
            }
        }
    }

    const auto rows = printers_from_ipp(*result.message, default_name);
    if (rows.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        ctx.write_output("printer|none");
        return 0;
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    for (const auto& row : rows)
        ctx.write_output(format_printer_row(row));
    return 0;
}

int do_jobs(yuzu::CommandContext& ctx, const yuzu::Params& params) {
    const std::string printer{params.get("printer")};

    std::vector<ipp::OperationAttr> attrs;
    // Server-root URI ("ipp://localhost/") is CUPS's own idiom for "every
    // printer" here -- verified against a real cupsd: the seemingly-obvious
    // "ipp://localhost/jobs/" is NOT recognised and is refused outright with
    // client-error-not-found ("The printer or class does not exist"), which
    // the status check below now catches instead of silently reporting an
    // empty queue.
    const std::string uri = printer.empty() ? std::string("ipp://localhost/") : printer_uri_for(printer);
    attrs.push_back({ipp::kTagUri, "printer-uri", uri, {}});
    attrs.push_back({ipp::kTagKeyword, "which-jobs", "not-completed", {}});
    // Get-Jobs' server-chosen default attribute set is minimal (verified
    // against a real cupsd: just job-id/job-uri) -- every field jobs_from_ipp
    // reads must be requested explicitly or it silently comes back absent.
    attrs.push_back({ipp::kTagKeyword,
                      "requested-attributes",
                      "job-id",
                      {"job-printer-uri", "job-originating-user-name", "job-name", "job-state",
                       "job-k-octets", "date-time-at-creation"}});

    const auto req = ipp::encode_request(ipp::kGetJobs, next_request_id(), attrs);
    if (req.empty()) { // the encoder refused an over-long attribute: never sent
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "Get-Jobs: printer name too long");
        ctx.write_output("job|unavailable|invalid_printer");
        return 0;
    }
    const auto result = do_read_ipp(req);

    if (!result.transport_ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "Get-Jobs: transport failed");
        ctx.write_output(std::format("job|unavailable|{}", kTokConnectFailed));
        return 0;
    }
    if (!result.message) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "Get-Jobs: response did not decode");
        ctx.write_output(std::format("job|unavailable|{}", kTokDecodeFailed));
        return 0;
    }
    // RFC 8010 successful-* is 0x0000-0x00FF -- a status outside that range
    // (e.g. client-error-not-found) must never be read as "zero job rows".
    if (result.message->op_or_status > 0x00FF) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               std::format("Get-Jobs: unexpected status 0x{:04x}", result.message->op_or_status));
        ctx.write_output(std::format("job|unavailable|{}", kTokUnexpectedStatus));
        return 0;
    }

    const auto rows = jobs_from_ipp(*result.message);
    if (rows.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        ctx.write_output("job|none");
        return 0;
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    for (const auto& row : rows)
        ctx.write_output(format_job_row(row));
    return 0;
}

int do_clear_queue(yuzu::CommandContext& ctx, const yuzu::Params& params) {
    const std::string printer{params.get("printer")};
    const std::string job_id_str{params.get("job_id")};

    if (printer.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "missing required param 'printer'");
        ctx.write_output(format_clear_queue_row("", 0, "error", "missing_printer"));
        return 1;
    }
    const auto job_id = parse_job_id(job_id_str);
    if (!job_id) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "invalid or missing 'job_id'");
        ctx.write_output(format_clear_queue_row(printer_echo_posix(printer), 0, "error", "invalid_job_id"));
        return 1;
    }

    // No socket -> refused, never a TCP fallback for this mutating action: a
    // deliberate policy refusal (the agent will not cancel over TCP), even though
    // the same token also covers cupsd simply not running. `no_identity` below is
    // an `error` instead, because a failed local lookup is not a policy decision.
    const auto socket_path = find_cups_socket();
    if (!socket_path) {
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_FULL,
                               "no CUPS Unix socket found; refusing to cancel over TCP");
        ctx.write_output(format_clear_queue_row(printer_echo_posix(printer), *job_id, "refused", kTokSocketUnavailable));
        return 1;
    }

    // No resolvable effective-user identity -> do not send. Sending an empty
    // requesting-user-name and a malformed `Authorization: PeerCred ` header
    // would make cupsd's answer about a request we never meant to send. This is
    // a local precondition failure, NOT an authorization decision (cupsd was
    // never asked), so it reports `error`, not `refused`: a transient NSS
    // failure must not read as a final denial.
    const std::string user = current_username();
    if (user.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "no resolvable effective-user identity; not sending the cancel");
        ctx.write_output(format_clear_queue_row(printer_echo_posix(printer), *job_id, "error", kTokNoIdentity));
        return 1;
    }

    httplib::Headers headers;
    headers.emplace("Authorization", "PeerCred " + user);

    // The whole cancel ladder is the pure run_clear_queue() (printing_parsers.hpp):
    // it binds the job to the named printer with a Get-Jobs BEFORE sending
    // Cancel-Job, because cupsd's Cancel-Job looks a job up by id alone and
    // ignores the printer (observed on a real cupsd: a nonexistent printer name
    // plus a valid job id cancelled the job and reported `canceled`). Windows
    // needs no such step: the spooler itself binds a job to its printer. This
    // shell only owns the transport and the per-OS tokens.
    const ClearQueueTokens tokens{.connect_failed = kTokConnectFailed,
                                  .decode_failed = kTokDecodeFailed,
                                  .access_denied = kTokAccessDenied,
                                  .not_found = kTokNotFound,
                                  .unexpected_status = kTokUnexpectedStatus};
    const ClearQueueDisposition d = run_clear_queue(
        printer, *job_id, user, tokens, [&](uint16_t op, const std::vector<ipp::OperationAttr>& attrs) {
            const std::string body = ipp::encode_request(op, next_request_id(), attrs);
            if (body.empty()) // an over-long attribute was refused by the encoder; never sent
                return IppResult{};
            return post_ipp_unix(*socket_path, body, headers);
        });
    ctx.set_result_status(d.status == ClearQueueStatus::ok
                              ? YUZU_RESULT_STATUS_OK
                              : (d.status == ClearQueueStatus::permission_denied ? YUZU_RESULT_STATUS_PERMISSION_DENIED
                                                                                  : YUZU_RESULT_STATUS_UNAVAILABLE),
                          d.full ? YUZU_RESULT_COMPLETENESS_FULL : YUZU_RESULT_COMPLETENESS_PARTIAL, d.detail);
    ctx.write_output(d.row);
    return d.rc;
}

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "printers",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib)",
         "localhost:631 fallback for reads when no socket is found"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib)",
         "localhost:631 fallback for reads when no socket is found"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool EnumPrintersW level 2", nullptr},
    },
    {
        /* .action      = */ "jobs",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket",
         "localhost:631 fallback for reads when no socket is found"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket",
         "localhost:631 fallback for reads when no socket is found"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool EnumJobsW level 2", nullptr},
    },
    {
        /* .action      = */ "clear_queue",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "IPP Cancel-Job on one job id over the CUPS Unix socket with Authorization: PeerCred",
         "measured in a Debian/Ubuntu cupsd container: container root/@SYSTEM (SystemGroup root "
         "lpadmin) cancelling another user's job succeeds (status 0x0000, I93-7) — but the "
         "production Linux agent runs unprivileged (docs/agent-privilege-model.md), never root "
         "or @SYSTEM, so an ordinary non-owning cancel is correctly refused (403) before "
         "Cancel-Job is ever reached; reliable only for a job the agent's own identity owns"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "IPP Cancel-Job on one job id over the CUPS Unix socket with Authorization: PeerCred",
         "PROVISIONAL — cupsd.conf Cancel-Job policy requires @OWNER/"
         "@AUTHKEY(system.print.operator)/@admin/@lpadmin (no @SYSTEM); header accepted by "
         "cupsd, authorisation outcome for a non-owned job UNMEASURED"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool SetJobW JOB_CONTROL_CANCEL on one job id",
         "cancel measured only under Administrators and SYSTEM (SYSTEM is today's agent identity, #1442); "
         "a least-privileged identity cancelling any job (its own or another user's) is unmeasured, and "
         "that a PRINTER_ACCESS_USE handle suffices for it is an extrapolation - see "
         "docs/agent-privilege-model.md"},
    },
};

#endif // _WIN32

} // namespace

class PrintingPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "printing"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Printer/job inventory plus a single narrowly-scoped clear_queue cancellation";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"printers", "jobs", "clear_queue", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

#ifdef _WIN32
    // Round-4 review blocker: short BOUNDED quiesce (plugin.hpp:245),
    // mirroring power_health_plugin.cpp's shutdown() shape exactly -- wait up
    // to 2x kSpoolerCallTimeout for g_outstanding_calls to drain (every
    // individual bounded_call_tracked() wait resolves, one way or another,
    // within kSpoolerCallTimeout by construction, so 2x always covers the
    // last in-flight one with margin), then log any residue and return.
    // Never an unbounded join.
    //
    // What this does NOT close -- and cannot, without a cancellable winspool
    // API, which doesn't exist -- is bounded_call()'s own pre-existing
    // residual: a call that has already timed out may still be physically
    // running enum_printers_raw_impl() on bounded_call()'s own detached
    // thread past this function's return. That is bounded_wait.hpp's own
    // governance-accepted hazard, identical in kind to every other plugin
    // using this primitive (discovery_plugin.cpp, power_health_plugin.cpp);
    // this quiesce narrows the window, it doesn't eliminate it.
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
        const auto deadline = std::chrono::steady_clock::now() + 2 * kSpoolerCallTimeout;
        while (g_outstanding_calls.load(std::memory_order_relaxed) > 0 &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (const int residue = g_outstanding_calls.load(std::memory_order_relaxed); residue > 0) {
            std::fprintf(stderr,
                          "printing: shutdown quiesce timed out with %d bounded call(s) still "
                          "outstanding\n",
                          residue);
        }
    }
#else
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}
#endif

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "printers")
            return do_printers(ctx);
        if (action == "jobs")
            return do_jobs(ctx, params);
        if (action == "clear_queue")
            return do_clear_queue(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(PrintingPlugin)
