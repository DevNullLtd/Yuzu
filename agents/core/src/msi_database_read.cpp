// msi_database_read.cpp -- bounded, read-only Property-table read of one cached Windows
// Installer package for the msi_packages plugin (SAM-46). See
// yuzu/agent/msi_database_read.hpp for why this lives in agent-core (detached-worker
// lifetime vs plugin FreeLibrary), the handle rule and the single-flight contract.

#include <yuzu/agent/msi_database_read.hpp>

#include <bounded_wait.hpp> // yuzu::shared::bounded_call_ex (agents/shared)

#include <expected>
#include <utility>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <msi.h>
#include <msiquery.h>

#include <vector>

#include "win_str.hpp" // yuzu::win::to_wide / from_wide (agents/shared)

#endif

namespace yuzu::agent::msi {

namespace {

/// The process-wide slot. Agent-core resident (never unloaded), so a worker that outlives
/// the plugin can still release it safely.
SingleFlightSlot g_slot;

/// Releases the slot on the WORKER thread, as the last thing the worker does (it is the
/// first local constructed, so it is destroyed after every handle guard below).
struct SlotRelease {
    SingleFlightSlot& slot;
    ~SlotRelease() { slot.release(); }
};

#ifdef _WIN32

// RAII owner of one MSIHANDLE, closed on the worker's own thread.
class MsiHandle {
public:
    MsiHandle() = default;
    MsiHandle(const MsiHandle&) = delete;
    MsiHandle& operator=(const MsiHandle&) = delete;
    ~MsiHandle() {
        if (h_ != 0)
            ::MsiCloseHandle(h_);
    }
    [[nodiscard]] MSIHANDLE get() const noexcept { return h_; }
    [[nodiscard]] MSIHANDLE* put() noexcept { return &h_; }

private:
    MSIHANDLE h_ = 0;
};

// Reads string field `field` of `rec`. The failing code on error (ERROR_MORE_DATA when the
// value is longer than kMaxPropertyChars).
std::expected<std::wstring, UINT> read_field(MSIHANDLE rec, unsigned field) {
    std::wstring buf(kMaxPropertyChars + 1, L'\0');
    DWORD cch = static_cast<DWORD>(buf.size());
    const UINT rc = ::MsiRecordGetStringW(rec, field, buf.data(), &cch);
    if (rc != ERROR_SUCCESS)
        return std::unexpected(rc);
    return std::wstring(buf.c_str()); // cut at the first NUL, as the registry readers do
}

// Only the five Property rows the plugin reads; every other row is skipped by name.
std::string* slot_for(PropertyTable& t, const std::wstring& name) {
    if (name == L"ProductCode")
        return &t.product_code;
    if (name == L"UpgradeCode")
        return &t.upgrade_code;
    if (name == L"ProductVersion")
        return &t.product_version;
    if (name == L"Manufacturer")
        return &t.manufacturer;
    if (name == L"ProductName")
        return &t.product_name;
    return nullptr;
}

Outcome read_worker(const std::string& path_utf8) {
    Outcome out;
    try {
        const std::wstring wpath = yuzu::win::to_wide(path_utf8);
        if (wpath.empty()) {
            out.kind = Outcome::Kind::OpenFailed;
            out.rc = ERROR_INVALID_PARAMETER;
            return out;
        }
        // Read-only open: the persist mode is MSIDBOPEN_READONLY, the null pointer (the SDK
        // macro is spelled with LPCTSTR, which does not convert to LPCWSTR in a build without
        // UNICODE, so the null is written out). Nothing below writes, executes or re-sequences.
        MsiHandle db;
        UINT rc = ::MsiOpenDatabaseW(wpath.c_str(), static_cast<LPCWSTR>(nullptr), db.put());
        if (rc != ERROR_SUCCESS) {
            out.kind = Outcome::Kind::OpenFailed;
            out.rc = rc;
            return out;
        }
        MsiHandle view;
        rc = ::MsiDatabaseOpenViewW(db.get(), L"SELECT `Property`, `Value` FROM `Property`",
                                    view.put());
        if (rc == ERROR_SUCCESS)
            rc = ::MsiViewExecute(view.get(), 0);
        if (rc != ERROR_SUCCESS) {
            out.kind = Outcome::Kind::ViewFailed;
            out.rc = rc;
            return out;
        }
        std::size_t rows = 0;
        for (;; ++rows) {
            MsiHandle rec;
            rc = ::MsiViewFetch(view.get(), rec.put());
            if (rc == ERROR_NO_MORE_ITEMS)
                break;
            if (rc != ERROR_SUCCESS || rows >= kMaxPropertyRows) {
                out.kind = Outcome::Kind::ReadFailed;
                out.rc = rc != ERROR_SUCCESS ? rc : ERROR_MORE_DATA;
                return out;
            }
            const auto name = read_field(rec.get(), 1);
            if (!name) {
                if (name.error() == ERROR_MORE_DATA)
                    continue; // a name this long is none of the five wanted ones
                out.kind = Outcome::Kind::ReadFailed;
                out.rc = name.error();
                return out;
            }
            std::string* dest = slot_for(out.props, *name);
            if (dest == nullptr)
                continue;
            const auto value = read_field(rec.get(), 2);
            if (!value) {
                out.kind = Outcome::Kind::ReadFailed;
                out.rc = value.error(); // ERROR_MORE_DATA: a wanted value over the character cap
                return out;
            }
            *dest = yuzu::win::from_wide(value->c_str());
        }
        out.kind = Outcome::Kind::Ok;
        return out;
    } catch (...) {
        Outcome ex;
        ex.kind = Outcome::Kind::Exception;
        return ex;
    }
}

#else // !_WIN32

// No Windows Installer off Windows; the slot protocol around this still runs so the
// Busy/Rejected behaviour is the same on every OS.
Outcome read_worker(const std::string&) {
    Outcome out;
    out.kind = Outcome::Kind::ApiUnavailable;
    return out;
}

#endif

} // namespace

ReadResult read_property_table(SingleFlightSlot& slot, const std::string& path_utf8,
                               std::chrono::milliseconds deadline) {
    return read_property_table(slot, path_utf8, deadline, &read_worker);
}

ReadResult read_property_table(SingleFlightSlot& slot, const std::string& path_utf8,
                               std::chrono::milliseconds deadline, ReadFn reader) {
    ReadResult result;
    // The worker closure (it copies the path, which can throw) is built BEFORE the slot is
    // taken, so a throw here cannot leave the slot held with no worker to release it.
    auto worker = [&slot, reader, path = path_utf8]() {
        SlotRelease release{slot}; // constructed first, destroyed last, on the worker
        return reader(path);
    };
    // Taken on the DISPATCHING thread, before any thread exists: a held slot is Busy and
    // starts nothing.
    if (!slot.try_acquire()) {
        result.status = ReadStatus::Busy;
        return result;
    }
    const auto started = std::chrono::steady_clock::now();
    auto bounded = yuzu::shared::bounded_call_ex(deadline, std::move(worker));
    result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    switch (bounded.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        result.status = ReadStatus::Completed;
        result.outcome = std::move(*bounded.value);
        break;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        // The worker still owns the slot and releases it when it returns.
        result.status = ReadStatus::TimedOut;
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        // fn never ran: no worker owns the slot, so this is the one caller-side release.
        slot.release();
        result.status = ReadStatus::Rejected;
        break;
    }
    return result;
}

ReadResult read_property_table(const std::string& path_utf8, std::chrono::milliseconds deadline) {
    return read_property_table(g_slot, path_utf8, deadline);
}

bool read_in_flight() noexcept { return g_slot.in_flight(); }

} // namespace yuzu::agent::msi
