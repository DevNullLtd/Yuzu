/**
 * firmware_posture_linux.cpp -- Linux leg: sysfs DMI + fwupd over sd-bus.
 *
 * Two sources, both rung 1 (in-process, no spawn, no dmidecode/fwupdmgr):
 *
 *   dmi     the four /sys/class/dmi/id/{bios_vendor,bios_version,bios_date,
 *           bios_release} files, each read once through a ScopedFd with a
 *           4 KiB bound. The raw text goes to parse_dmi_sysfs (pure, in
 *           firmware_posture_parsers.hpp); this file decides nothing about
 *           what the strings mean.
 *   fwupd   org.freedesktop.fwupd on the SYSTEM bus: GetDevices, then
 *           GetUpgrades per updatable device (update-pending signal). Compiled
 *           only under YUZU_HAVE_LIBSYSTEMD; without it the branch is
 *           unreachable and the sysfs rows still emit (meson: -Dsystemd_guard
 *           auto|disabled -- the default `enabled` fails configure by design).
 *
 * Failure vs absence (run-context CONTRACT DECISION): a DEFINITIVE not-there
 * (dmi file ENOENT, fwupd's ServiceUnknown/NameHasNoOwner reply) adds NO
 * failure token. Everything else (EACCES, EIO, ENOTDIR, a system bus that
 * cannot be opened, oversized, signature mismatch, budget exhausted,
 * unexpected D-Bus error) is recorded through FirmwareReport::fail /
 * note_failure as a `<source>:<cause>` token; a refused read (EACCES/EPERM,
 * AccessDenied) also sets the denial flag. Every classification
 * (classify_errno, classify_fwupd_error), the failed-read outcome-to-row/token
 * mappings (apply_fwupd_failure, apply_upgrades_failure, record_dmi_read_error)
 * and every row mapping (parse_dmi_sysfs/dmi_rows, fwupd_device_rows) are pure
 * functions in the parsers header; this TU performs the calls, formats errno
 * names, builds a FirmwareReport and hands it to finish_report -- the one
 * writer of rows and result status. (Recorded inline here: `dmi:<file>:oversized`,
 * `dmi:bios_release`, `fwupd:budget`, `fwupd:not_built` and the `fwupd:shape` of a
 * mismatched reply; `fwupd:row_cap` and the per-device `fwupd:shape` come from the
 * pure fwupd_device_rows.)
 *
 * A build without libsystemd (-Dsystemd_guard=auto|disabled) is a
 * reduced-coverage BUILD, not an OS statement: it reports update_pending
 * `unreadable` with the token `fwupd:not_built`, never `unavailable` (the
 * plugin cannot know whether fwupd is installed).
 *
 * ── fwupd D-Bus type-signature table ─────────────────────────────────────
 * Every sd_bus read below cites its row. Rows 1-3 were confirmed against a
 * LIVE daemon (fwupd 1.9.28 on fedora:40, see the fixtures'
 * .provenance.txt): `busctl introspect` shows GetDevices/GetUpgrades, and
 * the fixture is the real reply.
 *
 *  # | Call               | Interface              | Member      | Wire shape
 * ---|--------------------|------------------------|-------------|-------------------------------------------
 *  1 | method             | org.freedesktop.fwupd  | GetDevices  | () -> 'aa{sv}' (array of devices, each a{sv})
 *  2 | dict values (in v) | (row 1 payload)        | DeviceId    | 'v' wrapping 's'
 *    |                    |                        | Name        | 'v' wrapping 's'
 *    |                    |                        | Version     | 'v' wrapping 's' (ABSENT on some devices,
 *    |                    |                        |             |  e.g. the emulated CPU in the fixture)
 *    |                    |                        | Flags       | 'v' wrapping 't' (uint64 bitmask)
 *    |                    |                        | (others)    | Guid 'as', Created 't', VersionFormat 'u', ...
 *    |                    |                        |             |  -- stepped over with sd_bus_message_skip
 *  3 | method             | org.freedesktop.fwupd  | GetUpgrades | ('s' DeviceId) -> 'aa{sv}'; an error named
 *    |                    |                        |             |  ...fwupd.NothingToDo means "no upgrade"
 *    |                    |                        |             |  (classify_fwupd_error -> no_devices); any
 *    |                    |                        |             |  other error is a failure token
 *
 * In sd-bus a dict entry is container type 'e' (SD_BUS_TYPE_DICT_ENTRY),
 * contents "sv"; the array of them is entered as 'a' with contents "{sv}".
 * A shape mismatch (sd_bus_message_enter_container / read / skip failing, a
 * known key carrying the wrong variant type, or a reply signature other than
 * 'aa{sv}') yields the constrained token `fwupd:shape` -- never a partial,
 * silently-shortened device list.
 *
 * ── Probe record (run-context: symbol + service-identity in the banner) ──
 * Linux fwupd probe: REAL, in a container (root, euid 0) -- fwupd 1.9.28
 * answers GetDevices and, for a device it cannot update, GetUpgrades ->
 * org.freedesktop.fwupd.NothingToDo "Device is not updatable"; an unknown id
 * -> org.freedesktop.fwupd.NotFound; no fwupd on a running bus ->
 * org.freedesktop.DBus.Error.ServiceUnknown; no bus at all -> sd_bus_open_system
 * fails ENOENT (reported as a failed read, not as fwupd being absent). NOT
 * probed on real hardware or as the agent's service user (no such host in
 * this run): an unprivileged caller's polkit outcome is unmeasured, which is
 * exactly why AccessDenied is treated as a refusal (denied).
 */
#include "firmware_posture_legs.hpp"

#if defined(__linux__)

#include "firmware_posture_parsers.hpp"

#include <yuzu/agent/scoped_fd.hpp>

#if defined(YUZU_HAVE_LIBSYSTEMD)
#include <systemd/sd-bus.h>
#endif

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// classify_errno (parsers header) spells EPERM/ENOENT/EACCES as the bare integers 1/2/13 so the
// pure layer needs no OS header, and lets ENOTDIR (20) deliberately fall through to `failed`; pin
// all four to this platform's real values, as the Windows leg does for its constants.
static_assert(EPERM == 1 && ENOENT == 2 && EACCES == 13 && ENOTDIR == 20,
              "classify_errno's integer literals (EPERM 1, ENOENT 2, EACCES 13) must match this "
              "platform's errno values, and ENOTDIR (20) must stay a non-absent fall-through");

namespace yuzu::firmware_posture {

namespace {

// ── shared helpers ───────────────────────────────────────────────────────

/// Stable lowercase token for the errnos a sysfs/sd-bus read realistically
/// returns; anything else is `errno_<n>`. Formatting only -- what the errno
/// MEANS (absent/denied/failed) is classify_errno's job.
std::string errno_token(int e) {
    switch (e) {
    case EACCES: return "eacces";
    case EPERM: return "eperm";
    case EIO: return "eio";
    case ENOENT: return "enoent";
    case ENOTDIR: return "enotdir";
    case EISDIR: return "eisdir";
    case ENODEV: return "enodev";
    case ETIMEDOUT: return "etimedout";
    case ECONNREFUSED: return "econnrefused";
    default: return "errno_" + std::to_string(e);
    }
}

// ── dmi (sysfs) ──────────────────────────────────────────────────────────

constexpr std::size_t kDmiMaxBytes = 4096; // SMBIOS strings are far smaller; bound the read

// Same order as the descriptor/README lists them; the KEY is the file name,
// which is what parse_dmi_sysfs expects.
constexpr const char* kDmiFiles[] = {"bios_vendor", "bios_version", "bios_date", "bios_release"};

struct DmiRead {
    enum class State { ok, oversized, error } state = State::error;
    int err = 0;
    std::string data;
};

DmiRead read_dmi_file(const std::string& path) {
    DmiRead r;
    yuzu::agent::ScopedFd fd{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
    if (!fd) {
        r.err = errno;
        return r;
    }
    char buf[kDmiMaxBytes + 1];
    std::size_t total = 0;
    while (total < sizeof(buf)) {
        const ssize_t n = ::read(fd.get(), buf + total, sizeof(buf) - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            r.err = errno;
            return r;
        }
        if (n == 0)
            break;
        total += static_cast<std::size_t>(n);
    }
    if (total > kDmiMaxBytes) {
        r.state = DmiRead::State::oversized;
        return r;
    }
    r.data.assign(buf, total);
    // sysfs terminates the value with one newline: framing, not content.
    if (!r.data.empty() && r.data.back() == '\n')
        r.data.pop_back();
    r.state = DmiRead::State::ok;
    return r;
}

void collect_dmi(FirmwareReport& report) {
    std::map<std::string, std::string> files;
    std::vector<std::string> unreadable_keys;
    for (const char* name : kDmiFiles) {
        const DmiRead r = read_dmi_file(std::string{"/sys/class/dmi/id/"} + name);
        switch (r.state) {
        case DmiRead::State::ok:
            files.emplace(name, r.data);
            break;
        case DmiRead::State::oversized:
            // Unreadable, not absent: the field row must say so next to the token.
            unreadable_keys.emplace_back(name);
            report.note_failure(std::string{"dmi:"} + name + ":oversized");
            break;
        case DmiRead::State::error: {
            // ENOENT (no DMI on this platform, or no bios_release on this
            // board) is a definitive absence: not in the map, no token. ENOTDIR
            // is a malformed path, so it falls through to a failure token.
            record_dmi_read_error(report, unreadable_keys, name, classify_errno(r.err),
                                  errno_token(r.err));
            break;
        }
        }
    }
    const DmiInfo d = parse_dmi_sysfs(files, unreadable_keys);
    report.add_all(dmi_rows(d));
    if (d.release_malformed)
        report.note_failure("dmi:bios_release");
}

// ── fwupd (sd-bus) ───────────────────────────────────────────────────────

#if defined(YUZU_HAVE_LIBSYSTEMD)

// RAII guards, hand-rolled per file (same shape as firewall_plugin.cpp's
// BusGuard/SdBusErrorGuard/SdBusMessageGuard; no shared sd-bus header exists).
struct BusGuard {
    sd_bus* bus = nullptr;
    ~BusGuard() {
        if (bus)
            sd_bus_flush_close_unref(bus);
    }
    BusGuard() = default;
    BusGuard(const BusGuard&) = delete;
    BusGuard& operator=(const BusGuard&) = delete;
};
struct SdBusErrorGuard {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    ~SdBusErrorGuard() { sd_bus_error_free(&err); }
    SdBusErrorGuard() = default;
    SdBusErrorGuard(const SdBusErrorGuard&) = delete;
    SdBusErrorGuard& operator=(const SdBusErrorGuard&) = delete;
};
struct SdBusMessageGuard {
    sd_bus_message* m = nullptr;
    ~SdBusMessageGuard() {
        if (m)
            sd_bus_message_unref(m);
    }
    SdBusMessageGuard() = default;
    SdBusMessageGuard(const SdBusMessageGuard&) = delete;
    SdBusMessageGuard& operator=(const SdBusMessageGuard&) = delete;
};

// Total budget for the whole fwupd read, re-armed with the remainder before
// each call (same shape as firewall_plugin.cpp / guardian_state_reader.cpp),
// so a wedged fwupd cannot hold the leg for an unbounded multiple of the
// per-method timeout.
constexpr std::uint64_t kSdBusTotalBudgetUs = 5'000'000; // 5s

constexpr const char* kFwupdDest = "org.freedesktop.fwupd";
constexpr const char* kFwupdPath = "/";
constexpr const char* kFwupdIface = "org.freedesktop.fwupd";

struct FwupdBudget {
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    std::uint64_t remaining_us() const {
        const auto elapsed = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start)
                .count());
        return elapsed >= kSdBusTotalBudgetUs ? 0 : kSdBusTotalBudgetUs - elapsed;
    }
};

/// The D-Bus error name carried by `err`, or empty.
std::string_view dbus_error_name(const sd_bus_error& err) {
    return err.name ? std::string_view{err.name} : std::string_view{};
}

/// A failed sd_bus_open_system / GetDevices: classify through the pure
/// classifier, then map through apply_fwupd_failure (the pure half). Returns
/// true when the caller continues to the row mapper (NothingToDo: a reachable
/// daemon with an empty device list); false when the outcome was final (row
/// and/or token already recorded).
bool handle_fwupd_failure(FirmwareReport& report, std::string_view dbus_name, int neg_rc,
                          std::string_view what) {
    const int e = neg_rc < 0 ? -neg_rc : EIO;
    return apply_fwupd_failure(report, classify_fwupd_error(dbus_name, e), what, errno_token(e));
}

/// Reads a device array (reply signature 'aa{sv}', table rows 1-2) into
/// string maps. Returns false on ANY shape mismatch; the caller then emits
/// `fwupd:shape` and discards `devices` entirely. At most kMaxFwupdDevices+1
/// maps are kept: the extra one lets fwupd_device_rows detect the cap and emit
/// `fwupd:row_cap` itself; the rest of the reply is still walked so a shape
/// error past the cap is not missed.
bool read_device_array(sd_bus_message* m, std::vector<FwupdDevice>& devices) {
    // Row 1: the reply body must be exactly one 'aa{sv}'.
    const char* sig = sd_bus_message_get_signature(m, 1);
    if (!sig || std::strcmp(sig, "aa{sv}") != 0)
        return false;
    // Row 1: outer array of a{sv}.
    if (sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "a{sv}") < 0)
        return false;
    int r = 0;
    // Row 1: one a{sv} per device; enter returns 0 at end of the outer array.
    while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}")) > 0) {
        FwupdDevice dev;
        // Row 2: each dict entry is 'e' with contents "sv".
        int e = 0;
        while ((e = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
            const char* key = nullptr;
            if (sd_bus_message_read(m, "s", &key) < 0 || !key)
                return false;
            char type = 0;
            const char* contents = nullptr;
            if (sd_bus_message_peek_type(m, &type, &contents) <= 0 || type != SD_BUS_TYPE_VARIANT ||
                !contents)
                return false;
            if (sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, contents) < 0)
                return false;
            const std::string_view k{key};
            const std::string_view c{contents};
            if (k == "DeviceId" || k == "Name" || k == "Version") {
                // Row 2: 'v' wrapping 's'.
                const char* s = nullptr;
                if (c != "s" || sd_bus_message_read(m, "s", &s) < 0)
                    return false;
                if (s)
                    dev.emplace(std::string{k}, std::string{s});
            } else if (k == "Flags") {
                // Row 2: 'v' wrapping 't'.
                std::uint64_t flags = 0;
                if (c != "t" || sd_bus_message_read(m, "t", &flags) < 0)
                    return false;
                dev.emplace("Flags", std::to_string(flags));
            } else if (sd_bus_message_skip(m, contents) < 0) {
                // Row 2 (others): step over the payload by its own signature.
                return false;
            }
            if (sd_bus_message_exit_container(m) < 0) // variant
                return false;
            if (sd_bus_message_exit_container(m) < 0) // dict entry
                return false;
        }
        if (e < 0)
            return false;
        if (sd_bus_message_exit_container(m) < 0) // this device's a{sv}
            return false;
        if (devices.size() <= kMaxFwupdDevices)
            devices.push_back(std::move(dev));
    }
    if (r < 0)
        return false;
    return sd_bus_message_exit_container(m) >= 0; // outer array
}

/// Table row 3: GetUpgrades(s) for one updatable device -> 'aa{sv}'. Sets
/// dev["HasUpgrades"] to "true"/"false" on a definite answer; on any failure
/// it stays UNSET (the mapper reads that as `unknown`) and a token is noted.
void query_upgrades(sd_bus* bus, FwupdBudget& budget, FirmwareReport& report, FwupdDevice& dev,
                    const std::string& device_id) {
    const std::uint64_t left = budget.remaining_us();
    if (left == 0) {
        report.note_failure("fwupd:budget");
        return;
    }
    sd_bus_set_method_call_timeout(bus, left);

    SdBusErrorGuard uerr;
    SdBusMessageGuard ureply;
    // Table row 3.
    const int rc = sd_bus_call_method(bus, kFwupdDest, kFwupdPath, kFwupdIface, "GetUpgrades",
                                      &uerr.err, &ureply.m, "s", device_id.c_str());
    if (rc < 0) {
        // NothingToDo (no upgrade offered) -> HasUpgrades=false; anything else records a token.
        if (apply_upgrades_failure(report, classify_fwupd_error(dbus_error_name(uerr.err), -rc),
                                   errno_token(-rc)))
            dev["HasUpgrades"] = "false";
        return;
    }
    // Table row 3: reply body is exactly one 'aa{sv}'.
    const char* sig = sd_bus_message_get_signature(ureply.m, 1);
    if (!sig || std::strcmp(sig, "aa{sv}") != 0 ||
        sd_bus_message_enter_container(ureply.m, SD_BUS_TYPE_ARRAY, "a{sv}") < 0) {
        report.note_failure("fwupd:shape");
        return;
    }
    // Table row 3: >=1 element <=> entering an a{sv} returns > 0 (0 == empty array).
    const int has = sd_bus_message_enter_container(ureply.m, SD_BUS_TYPE_ARRAY, "{sv}");
    if (has < 0) {
        report.note_failure("fwupd:shape");
        return;
    }
    dev["HasUpgrades"] = has > 0 ? "true" : "false";
}

void collect_fwupd(FirmwareReport& report) {
    BusGuard bus;
    const int open_rc = sd_bus_open_system(&bus.bus);
    if (open_rc < 0 || !bus.bus) {
        // An unopenable bus proves this process cannot reach it, not that
        // fwupd is absent: a failed read (bus_open:<errno>), or a refusal
        // (bus_open:permission_denied) for EACCES/EPERM, never unavailable. An
        // empty D-Bus name = the failure is an errno.
        handle_fwupd_failure(report, {}, open_rc, "bus_open");
        return;
    }

    FwupdBudget budget;
    sd_bus_set_method_call_timeout(bus.bus, budget.remaining_us());

    // Table row 1: GetDevices() -> aa{sv}.
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    const int rc = sd_bus_call_method(bus.bus, kFwupdDest, kFwupdPath, kFwupdIface, "GetDevices",
                                      &err.err, &reply.m, "");
    std::vector<FwupdDevice> devices;
    if (rc < 0) {
        // NothingToDo falls through with an empty list (the mapper then emits
        // update_pending=no); every other outcome is final.
        if (!handle_fwupd_failure(report, dbus_error_name(err.err), rc, "get_devices"))
            return;
    } else if (!read_device_array(reply.m, devices)) {
        report.fail("update_pending", kSrcFwupd, "fwupd:shape");
        return; // never a partial device list
    }

    // Table row 3 per UPDATABLE device; the presence of >=1 upgrade is the
    // update-pending signal the mapper reads from "HasUpgrades". Devices past
    // the cap get no rows, so they are not queried either.
    const std::size_t queried = std::min(devices.size(), kMaxFwupdDevices);
    for (std::size_t i = 0; i < queried; ++i) {
        FwupdDevice& dev = devices[i];
        const auto id = dev.find("DeviceId");
        const auto fl = dev.find("Flags");
        if (id == dev.end() || fl == dev.end())
            continue; // the mapper reports fwupd:shape for these
        std::uint64_t flags = 0;
        const auto& fs = fl->second; // decimal text we wrote from a 't' in read_device_array
        if (std::from_chars(fs.data(), fs.data() + fs.size(), flags).ec != std::errc{})
            continue; // non-numeric: the mapper reports fwupd:shape
        if ((flags & kFwupdUpdatable) == 0)
            continue;
        query_upgrades(bus.bus, budget, report, dev, id->second);
    }

    FwupdRows fr = fwupd_device_rows(devices);
    report.add_all(std::move(fr.rows));
    for (const auto& token : fr.failures)
        report.note_failure(token);
}

#else // !YUZU_HAVE_LIBSYSTEMD

// Built with -Dsystemd_guard=auto|disabled and no libsystemd: the fwupd
// branch is permanently unreachable. That is a reduced-coverage BUILD, not
// an OS statement (the plugin cannot know whether fwupd is installed), so it
// is an `unreadable` row plus a token -- never `unavailable`.
void collect_fwupd(FirmwareReport& report) {
    report.fail("update_pending", kSrcFwupd, "fwupd:not_built");
}

#endif // YUZU_HAVE_LIBSYSTEMD

} // namespace

int collect_firmware_linux(yuzu::CommandContext& ctx) {
    FirmwareReport report;
    collect_dmi(report);
    collect_fwupd(report);
    return finish_report(ctx, report);
}

} // namespace yuzu::firmware_posture

#endif // __linux__
