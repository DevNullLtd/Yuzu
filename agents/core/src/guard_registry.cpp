/**
 * guard_registry.cpp — see guard_registry.hpp.
 *
 * Windows: a single watch thread holds a FIXED two-event + stop wait set and runs
 * reconcile() on every wakeup. reconcile() re-resolves state from scratch — open
 * the watched key if it exists, else open the nearest existing ancestor and watch
 * it for (re)creation — arming each RegNotifyChangeKeyValue subscription BEFORE it
 * reads, so no change is missed in the check->arm gap. This makes the guard
 * *resilient* (design §8.5 / §24): it survives deletion of the watched key — and of
 * its whole ancestor chain — and keeps detecting until stop(); it never exits on a
 * recoverable error. The value-drift fast path touches only the target handle, so
 * detection stays sub-millisecond.
 *
 * In enforce mode a deleted key is RECREATED (RegCreateKeyExW creates the whole
 * missing chain) and its value rewritten (C2); audit mode only reports the absence.
 * No self-elevation — an HKLM create denied under a non-privileged account fails
 * honestly as remediation.failed (SYSTEM is the deployment service-account concern,
 * docs/agent-privilege-model.md).
 *
 * Deliberately proto-free: this keeps windows.h and protobuf out of the same
 * translation unit (windows.h's ERROR / min / max macros vs protobuf headers).
 * On non-Windows the class is a no-op (start() returns false) so the engine and
 * tests build everywhere; real enforcement is Windows-only for the MVP.
 *
 * KNOWN RESIDUAL: unlike FileGuard (guard_file.cpp), this guard has no watch on the
 * target key's own PARENT — RegNotifyChangeKeyValue is armed on the target/ancestor
 * handle itself, which (by the same class of gap FileGuard's parent-watch exists to
 * close) reports the handle's own subkeys/values changing, not the key itself being
 * renamed/moved by its parent. A rename of the watched key is not detected until an
 * unrelated wake re-resolves it. Not yet fixed here; tracked alongside this branch's
 * disclosure decision for FileGuard's own fix.
 */

#include <yuzu/agent/guard_registry.hpp>

#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include <chrono>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// Self-sufficient link (#1287): this TU calls advapi32 directly (RegOpenKeyExW,
// RegNotifyChangeKeyValue, RegQueryValueExW, RegSetValueExW). Don't rely on a
// sibling TU's pragma to carry advapi32 across the whole yuzu_agent_core link line.
#pragma comment(lib, "advapi32.lib")

#include "guard_win_handle.hpp"
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)

#include <algorithm>
#include <charconv>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::agent {
namespace {

// Event/sink debounce (H3 / #1209): rapid drifts within Config::event_debounce_ms of
// the last EMITTED event are collapsed into a count carried on the next emission.
// Bounds the SINK only; the enforce remediation is gated separately by the per-rule
// resilience strategy (C3, design §8.5).

// Fallback re-arm cadence used ONLY when no watch (target or ancestor) could be armed
// — a rare RegNotifyChangeKeyValue failure on a freshly-opened handle. Without it the
// INFINITE wait would block forever, silently breaking live-until-disabled. The
// healthy absent state never uses this — it stays fully event-driven (no poll).
constexpr std::uint64_t kArmFailRetryMs = 30000;

// The hive tokens here are the canonical agent-supported set, declared once as
// registry_support::kHives (guard_registry.hpp) and cross-checked against the
// published /schemas enum by a server unit test (H2). Add a hive here AND there,
// or neither — never publish one the agent can't map.
HKEY parse_hive(const std::string& hive) {
    if (hive == "HKLM") return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU") return HKEY_CURRENT_USER;
    if (hive == "HKCR") return HKEY_CLASSES_ROOT;
    if (hive == "HKU") return HKEY_USERS;
    return nullptr;
}

// to_wide / from_wide now delegate to the shared agents/shared/win_str.hpp
// helpers (#1681). The removed local copies were behaviour-equivalent here:
//   - to_wide popped the trailing NUL the -1 convert appends, which is exactly
//     yuzu::win::to_wide's size-based (NUL-excluded) result;
//   - from_wide is only ever reached from read_value() AFTER it strips trailing
//     NUL(s) on REG_SZ/EXPAND_SZ (see below), so yuzu::win::from_wide's
//     trailing-NUL pop is a no-op on the wlen passed here.
using yuzu::win::from_wide;
using yuzu::win::to_wide;

// REG_NOTIFY_CHANGE_LAST_SET catches value writes; _NAME catches add/delete of the
// value itself. Subtree is FALSE — we watch this key's values only.
constexpr DWORD kNotifyFilter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET;

// Read the watched value and string-encode it per the G4 convention (DWORD/QWORD =
// decimal, SZ/EXPAND_SZ = literal). Returns "<absent>" when the value is missing,
// "<unsupported-type>" for types this MVP slice doesn't decode (forces a drift
// rather than a silent false-match).
std::string read_value(HKEY key, const std::string& value_name) {
    std::wstring wname = to_wide(value_name);
    const wchar_t* name = value_name.empty() ? nullptr : wname.c_str();
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
        return "<absent>";
    std::vector<BYTE> buf(size ? size : 1);
    if (RegQueryValueExW(key, name, nullptr, &type, buf.data(), &size) != ERROR_SUCCESS)
        return "<absent>";
    switch (type) {
    case REG_DWORD: {
        DWORD v = 0;
        if (size >= sizeof(DWORD)) std::memcpy(&v, buf.data(), sizeof(DWORD));
        return std::to_string(v);
    }
    case REG_QWORD: {
        unsigned long long v = 0;
        if (size >= sizeof(v)) std::memcpy(&v, buf.data(), sizeof(v));
        return std::to_string(v);
    }
    case REG_SZ:
    case REG_EXPAND_SZ: {
        int wlen = static_cast<int>(size / sizeof(wchar_t));
        const auto* wp = reinterpret_cast<const wchar_t*>(buf.data());
        while (wlen > 0 && wp[wlen - 1] == L'\0') --wlen; // strip trailing NUL(s)
        return from_wide(wp, wlen);
    }
    default:
        return "<unsupported-type>";
    }
}

// Re-encode `expected` per value_type and write it to value_name — the inverse
// of read_value(). Used only in enforce mode. Returns true on a successful
// RegSetValueExW. The write is bounded to the rule's `expected`: a fixed-value
// restore, never an arbitrary-write-of-arbitrary-data primitive — value name,
// type, and content all come from the server-authored rule, not from any
// runtime/endpoint input. NOTE on trust: the rule's `signature` is NOT yet
// verified by the agent (deferred — contract G3), so the integrity gate on
// "what gets written where" is Push RBAC + mTLS on the control-plane link, not
// rule signing. Unsupported types are refused rather than written as garbage.
// `key` may be null (target absent) — write_value returns false so the caller
// reports remediation.failed rather than dereferencing a dead handle.
bool write_value(HKEY key, const std::string& value_name, const std::string& value_type,
                 const std::string& expected) {
    if (!key)
        return false;
    std::wstring wname = to_wide(value_name);
    const wchar_t* name = value_name.empty() ? nullptr : wname.c_str();
    if (value_type == "REG_DWORD") {
        DWORD v = 0;
        auto [ptr, ec] = std::from_chars(expected.data(), expected.data() + expected.size(), v);
        if (ec != std::errc{}) return false;
        return RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v),
                              sizeof(v)) == ERROR_SUCCESS;
    }
    if (value_type == "REG_QWORD") {
        unsigned long long v = 0;
        auto [ptr, ec] = std::from_chars(expected.data(), expected.data() + expected.size(), v);
        if (ec != std::errc{}) return false;
        return RegSetValueExW(key, name, 0, REG_QWORD, reinterpret_cast<const BYTE*>(&v),
                              sizeof(v)) == ERROR_SUCCESS;
    }
    if (value_type == "REG_SZ" || value_type == "REG_EXPAND_SZ") {
        std::wstring w = to_wide(expected);
        const DWORD bytes = static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t)); // include NUL
        const DWORD t = (value_type == "REG_EXPAND_SZ") ? REG_EXPAND_SZ : REG_SZ;
        return RegSetValueExW(key, name, 0, t, reinterpret_cast<const BYTE*>(w.c_str()), bytes) ==
               ERROR_SUCCESS;
    }
    return false; // unsupported type — refuse rather than write garbage
}

// RAII owner for an HKEY obtained from RegOpenKeyExW. Closes on reset/destruction.
// Only ever holds opened handles (never a predefined hive-root constant) — the
// resolver below always goes through RegOpenKeyExW, even for the hive root (via a
// null subkey) — so RegCloseKey is always the correct teardown. Leak/double-close
// proof for the repeated open/close churn of the reconcile loop (Gate-3 ownership).
class RegKeyHandle {
public:
    RegKeyHandle() = default;
    ~RegKeyHandle() { reset(); }
    RegKeyHandle(const RegKeyHandle&) = delete;
    RegKeyHandle& operator=(const RegKeyHandle&) = delete;
    void reset(HKEY h = nullptr) {
        if (h_ && h_ != h) RegCloseKey(h_);
        h_ = h;
    }
    HKEY get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    HKEY h_ = nullptr;
};

// "SOFTWARE\\YuzuTest\\Sub" -> "SOFTWARE\\YuzuTest"; a top-level subkey -> "" (the
// hive root). Used to walk upward toward the nearest existing ancestor.
std::string parent_path(const std::string& key) {
    auto pos = key.find_last_of('\\');
    return pos == std::string::npos ? std::string{} : key.substr(0, pos);
}

// Open the deepest EXISTING ancestor of `key` (its parent, else grandparent, ...,
// else the hive root, which is always openable) with KEY_NOTIFY. A NAME notify on
// this handle fires when the missing descendant is (re)created — even when the
// whole chain is created atomically by one RegCreateKeyExW or a .reg import — which
// is why reconcile() re-resolves from scratch rather than descending one level at a
// time. Returns the opened handle in `out` and the path that opened in `opened`.
bool open_nearest_ancestor(HKEY root, const std::string& key, RegKeyHandle& out,
                           std::string& opened) {
    std::string p = parent_path(key);
    for (;;) {
        std::wstring wp = to_wide(p);
        HKEY h = nullptr;
        LONG rc = RegOpenKeyExW(root, p.empty() ? nullptr : wp.c_str(), 0, KEY_NOTIFY, &h);
        if (rc == ERROR_SUCCESS) {
            out.reset(h);
            opened = p;
            return true;
        }
        if (p.empty()) { // even the hive root failed — should not happen
            out.reset();
            return false;
        }
        p = parent_path(p);
    }
}

} // namespace

RegistryGuard::RegistryGuard(Config cfg, Sink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

RegistryGuard::~RegistryGuard() { stop(); }

bool RegistryGuard::start() {
    if (!parse_hive(cfg_.hive)) {
        spdlog::warn("Guardian RegistryGuard[{}]: invalid hive '{}'", log_id_token(cfg_.rule_id),
                     log_key_token(cfg_.hive));
        return false;
    }
    HANDLE evt = CreateEventW(nullptr, /*manualReset=*/FALSE, /*initial=*/FALSE, nullptr);
    if (!evt) return false;
    stop_event_ = evt;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
    return true;
}

void RegistryGuard::stop() {
    if (thread_.joinable()) {
        stop_.store(true, std::memory_order_release);
        if (stop_event_) SetEvent(static_cast<HANDLE>(stop_event_));
        thread_.join();
    }
    if (stop_event_) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }
}

void RegistryGuard::run() try {
    HKEY root = parse_hive(cfg_.hive); // validated in start()

    // FIXED wait set: two lifetime auto-reset events + the stop event. We arm/disarm
    // the RegNotify *subscriptions*, never resize or reindex the wait (avoids the
    // classic "read the wrong handle" bug). `target_event` carries value drift +
    // deletion of the watched key (sub-ms fast path); `ancestor_event` carries
    // (re)creation seen at the nearest existing ancestor while the key is absent.
    // RAII owners — released on every exit incl. an exception unwind (the sink does a
    // network write and can throw); the manual-close version leaked + std::terminate'd.
    detail::EventHandle target_event(CreateEventW(nullptr, /*manualReset=*/FALSE, /*initial=*/FALSE, nullptr));
    detail::EventHandle ancestor_event(CreateEventW(nullptr, /*manualReset=*/FALSE, /*initial=*/FALSE, nullptr));
    if (!target_event || !ancestor_event) {
        spdlog::error("Guardian RegistryGuard[{}]: event creation failed",
                      log_id_token(cfg_.rule_id));
        return; // RAII closes whichever event was created
    }

    RegKeyHandle target;       // owned; valid iff the watched key currently exists
    RegKeyHandle ancestor;     // owned; nearest existing ancestor watched for (re)creation
    std::string ancestor_path; // path that the ancestor handle opened (logging/transitions)

    // Sink-debounce state (H3 / #1209). Only this run() thread touches these.
    std::optional<std::chrono::steady_clock::time_point> last_emit;
    std::uint64_t suppressed = 0;
    bool ro_fallback_warned = false; // UP-2 read-only fallback warned once

    // Compliance-edge state (Slice B). nullopt until the first reconcile, then tracks
    // the last-reported compliant/drifted state so a guard.compliant event fires ONCE
    // on the compliant↔drift edge — steady compliant state stays silent (NFR). Only
    // this run() thread touches it.
    std::optional<bool> last_compliant;

    // C3: per-rule retry policy. Consulted ONLY in enforce mode and ONLY to gate the
    // remediation write/create — detection + event emission happen regardless, so a
    // backed-off / given-up guard still reports drift. `next_wake_ms` carries a
    // strategy-scheduled self-wake (Backoff retry / Bounded resume cooldown) to the
    // wait loop; reset at the top of each reconcile().
    ResilienceStrategy strategy{cfg_.resilience};
    std::optional<std::uint64_t> next_wake_ms;
    auto now_ms = [] {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
    };

    // C2: recreate the watched key when it is absent (enforce only). RegCreateKeyExW
    // creates EVERY missing key in the path in one call (the atomic whole-chain
    // create C1's reconcile()-from-scratch is built to tolerate). Opens with the
    // access the watch + write-back need. Failure (e.g. KEY_CREATE_SUB_KEY denied on
    // an HKLM key under a non-privileged account) returns false — reported as
    // remediation.failed; NO self-elevation.
    auto create_target = [&]() -> bool {
        std::wstring wkey = to_wide(cfg_.key);
        HKEY h = nullptr;
        LONG rc = RegCreateKeyExW(root, wkey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                                  KEY_NOTIFY | KEY_READ | KEY_SET_VALUE, nullptr, &h, nullptr);
        if (rc != ERROR_SUCCESS) return false;
        target.reset(h);
        return true;
    };

    auto emit = [&](const std::string& detected, std::uint64_t latency_us) {
        if (detected == cfg_.expected) {
            // Compliant. Emit guard.compliant ONCE on the edge into compliant (incl.
            // the first reconcile, last_compliant == nullopt); steady compliant is
            // silent. Bypasses the drift-debounce collapse below — a compliant edge is
            // the end of a drift, not another drift to fold.
            if (last_compliant != true) {
                last_compliant = true;
                RegistryDrift c;
                c.rule_id = cfg_.rule_id;
                c.rule_name = cfg_.rule_name;
                c.detected_value = cfg_.expected;
                c.expected_value = cfg_.expected;
                c.detection_latency_us = latency_us;
                c.compliant = true;
                if (sink_) sink_(c);
            }
            return;
        }
        last_compliant = false; // drifted (reported below, possibly collapsed)
        RegistryDrift d;
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = detected;
        d.expected_value = cfg_.expected;
        d.detection_latency_us = latency_us;
        // Enforce mode: write `expected` back through the live target handle before
        // reporting (so the self-write's notify re-reads expected==expected and emit
        // short-circuits — no remediation loop). When the key is ABSENT (target null)
        // write_value() returns false → reported as remediation.failed. C1 does NOT
        // (re)create the key — that is C2.
        if (cfg_.enforce) {
            // C3: the resilience strategy decides whether to fix THIS drift and when
            // to wake next. It gates only the write/create — we always build + emit
            // the event below, so a backed-off / given-up guard still alerts.
            const ResilienceDecision dec = strategy.decide(now_ms());
            next_wake_ms = dec.next_wake_ms;
            if (dec.remediate) {
                d.remediation_attempted = true;
                const auto r0 = std::chrono::steady_clock::now();
                bool ok;
                if (!target) {
                    // C2: the key itself is gone — recreate it (whole chain) THEN write
                    // the value. write_value uses the freshly-opened handle create_target
                    // stores in `target`. If create is denied, ok stays false below.
                    d.remediation_action = "registry-create";
                    ok = create_target() &&
                         write_value(target.get(), cfg_.value_name, cfg_.value_type, cfg_.expected);
                } else {
                    d.remediation_action = "registry-write";
                    ok = write_value(target.get(), cfg_.value_name, cfg_.value_type, cfg_.expected);
                }
                d.remediation_latency_us = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - r0)
                        .count());
                d.remediation_success = ok;
                if (ok)
                    spdlog::info("Guardian RegistryGuard[{}]: {} {}\\{} [{}] {} -> {} ({}us)",
                                 log_id_token(cfg_.rule_id), d.remediation_action,
                                 log_key_token(cfg_.hive), log_key_token(cfg_.key),
                                 log_key_token(cfg_.value_name), log_key_token(detected),
                                 log_key_token(cfg_.expected), d.remediation_latency_us);
                else
                    spdlog::warn("Guardian RegistryGuard[{}]: enforce {} FAILED for {}\\{} [{}] "
                                 "(detected={}, type={}{})",
                                 log_id_token(cfg_.rule_id), d.remediation_action,
                                 log_key_token(cfg_.hive), log_key_token(cfg_.key),
                                 log_key_token(cfg_.value_name), log_key_token(detected),
                                 log_key_token(cfg_.value_type), target.get() ? "" : ", key absent");
            } else {
                // Backoff window or Bounded give-up: drift detected + reported (this
                // event is the alert) but the fix is withheld this cycle.
                spdlog::info("Guardian RegistryGuard[{}]: drift {}\\{} [{}] detected={} -- "
                             "{}, not remediating",
                             log_id_token(cfg_.rule_id), log_key_token(cfg_.hive),
                             log_key_token(cfg_.key), log_key_token(cfg_.value_name),
                             log_key_token(detected), dec.gave_up ? "given up (alert)" : "backing off");
            }
        }
        // A successful write-back restored `expected`: the self-write's notify will
        // re-reconcile and read compliant. drift.remediated already carries that
        // "now compliant" meaning, so pre-set the edge to avoid a redundant
        // guard.compliant chasing every remediation (Slice B).
        if (d.remediation_attempted && d.remediation_success)
            last_compliant = true;

        // Collapse-with-count debounce: emit the first drift immediately, fold
        // subsequent drifts within the window into `suppressed`, attach that count
        // to the next post-window emission. Bounds the SINK only.
        const auto now = std::chrono::steady_clock::now();
        if (last_emit && (now - *last_emit) < std::chrono::milliseconds(cfg_.event_debounce_ms)) {
            ++suppressed;
            return;
        }
        d.collapsed_count = suppressed;
        suppressed = 0;
        last_emit = now;
        if (sink_) sink_(d);
    };

    // Open the watched key with the right access. Enforce adds KEY_SET_VALUE with a
    // UP-2 read-only fallback when write access is denied (e.g. an HKLM key under a
    // non-privileged account) — we still detect drift and report failed write-backs
    // rather than disarming. Re-opened fresh on every reconcile (cheap; ~µs) so the
    // handle is never stale.
    auto open_target = [&]() -> bool {
        std::wstring wkey = to_wide(cfg_.key);
        const REGSAM read_access = KEY_NOTIFY | KEY_READ;
        HKEY h = nullptr;
        LONG rc = RegOpenKeyExW(root, wkey.c_str(), 0,
                                cfg_.enforce ? (read_access | KEY_SET_VALUE) : read_access, &h);
        if (rc != ERROR_SUCCESS && cfg_.enforce) {
            if (!ro_fallback_warned) {
                spdlog::warn("Guardian RegistryGuard[{}]: write-access open of {}\\{} failed "
                             "(rc={}) — read-only watch; enforcement will report failures",
                             log_id_token(cfg_.rule_id), log_key_token(cfg_.hive),
                             log_key_token(cfg_.key), rc);
                ro_fallback_warned = true;
            }
            rc = RegOpenKeyExW(root, wkey.c_str(), 0, read_access, &h);
        }
        if (rc == ERROR_SUCCESS) {
            target.reset(h);
            return true;
        }
        target.reset();
        return false;
    };

    // (Re)resolve the nearest existing ancestor from scratch and arm its NAME watch
    // on `ancestor_event`. Armed whenever the target is absent so a (re)creation
    // re-fires — robust to atomic whole-chain creation.
    auto arm_ancestor = [&]() -> bool {
        return open_nearest_ancestor(root, cfg_.key, ancestor, ancestor_path) &&
               RegNotifyChangeKeyValue(ancestor.get(), FALSE, REG_NOTIFY_CHANGE_NAME,
                                       ancestor_event.get(),
                                       /*async=*/TRUE) == ERROR_SUCCESS;
    };

    // Single source of truth. Re-resolve from scratch; ARM each subscription BEFORE
    // it reads/checks (edge-triggered: a change during the read re-fires the armed
    // event), then emit. Carries no incremental per-level state.
    auto reconcile = [&]() {
        next_wake_ms.reset(); // fresh evaluation; emit() re-sets it iff the strategy schedules a wake
        // Fast path: the watched key exists → arm value/deletion notify, then read.
        if (open_target()) {
            if (RegNotifyChangeKeyValue(target.get(), FALSE, kNotifyFilter, target_event.get(),
                                        /*async=*/TRUE) == ERROR_SUCCESS) {
                const auto t0 = std::chrono::steady_clock::now();
                std::string detected = read_value(target.get(), cfg_.value_name);
                const auto latency = std::chrono::duration_cast<std::chrono::microseconds>(
                                         std::chrono::steady_clock::now() - t0)
                                         .count();
                emit(detected, static_cast<std::uint64_t>(latency));
                return;
            }
            target.reset(); // key vanished between open and arm → handle as absent
        }
        // Absent: arm the ancestor (re)creation watch BEFORE re-checking existence,
        // so an atomic whole-chain recreate during this window re-fires ancestor_event.
        const bool ancestor_armed = arm_ancestor();
        if (open_target()) {
            if (RegNotifyChangeKeyValue(target.get(), FALSE, kNotifyFilter, target_event.get(),
                                        /*async=*/TRUE) == ERROR_SUCCESS) {
                emit(read_value(target.get(), cfg_.value_name), 0);
                return;
            }
            target.reset();
        }
        // Genuinely absent. In enforce mode emit() recreates the key (whole chain) +
        // writes the value (C2); in audit it just reports the absence. If emit
        // restored the key, arm the value/deletion watch on it immediately.
        emit("<absent>", 0);
        if (target) {
            RegNotifyChangeKeyValue(target.get(), FALSE, kNotifyFilter, target_event.get(),
                                    /*async=*/TRUE);
        } else if (!ancestor_armed && !next_wake_ms) {
            // Neither a target nor an ancestor watch could be armed (rare notify
            // failure) and the strategy scheduled no wake — schedule a bounded
            // degraded re-arm so the guard self-heals instead of blocking forever.
            spdlog::warn("Guardian RegistryGuard[{}]: could not arm any watch for {}\\{} — "
                         "degraded re-arm retry in {}ms",
                         log_id_token(cfg_.rule_id), log_key_token(cfg_.hive),
                         log_key_token(cfg_.key), kArmFailRetryMs);
            next_wake_ms = kArmFailRetryMs;
        }
    };

    spdlog::info("Guardian RegistryGuard[{}]: watching {}\\{} [{}] (expect {}={}) [resilient]",
                 log_id_token(cfg_.rule_id), log_key_token(cfg_.hive), log_key_token(cfg_.key),
                 log_key_token(cfg_.value_type), log_key_token(cfg_.value_name),
                 log_key_token(cfg_.expected));

    reconcile(); // initial compare + initial arm

    HANDLE handles[3] = {target_event.get(), ancestor_event.get(),
                         static_cast<HANDLE>(stop_event_)};
    while (!stop_.load(std::memory_order_acquire)) {
        // INFINITE unless the strategy scheduled a self-wake (Backoff retry / Bounded
        // resume) — keeps Persist / audit / idle fully quiescent (no busy-wake).
        const DWORD timeout =
            next_wake_ms ? static_cast<DWORD>(std::min<std::uint64_t>(*next_wake_ms, 0xFFFFFFFEull))
                         : INFINITE;
        DWORD r = WaitForMultipleObjects(3, handles, FALSE, timeout);
        if (r == WAIT_OBJECT_0 + 2) break; // stop event signaled
        // Target drift/deletion, ancestor (re)creation, OR a scheduled-retry timeout
        // all re-run reconcile(). WAIT_TIMEOUT must NOT break — that would silently end
        // the guard the instant a Backoff/Bounded delay expired (live-until-disabled).
        if (r == WAIT_OBJECT_0 || r == WAIT_OBJECT_0 + 1 || r == WAIT_TIMEOUT)
            reconcile();
        else
            break; // WAIT_FAILED / WAIT_ABANDONED — unrecoverable
    }

    // RAII: target_event / ancestor_event (and RegKeyHandle target / ancestor) close
    // on scope exit, including an exception unwind.
} catch (const std::exception& e) {
    spdlog::error("Guardian RegistryGuard[{}]: watch thread exception: {} — watch stopping",
                  log_id_token(cfg_.rule_id), e.what());
} catch (...) {
    spdlog::error("Guardian RegistryGuard[{}]: watch thread unknown exception — watch stopping",
                  log_id_token(cfg_.rule_id));
}

} // namespace yuzu::agent

#else // ── Non-Windows: no-op (no registry) ───────────────────────────────────

namespace yuzu::agent {

RegistryGuard::RegistryGuard(Config cfg, Sink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}
RegistryGuard::~RegistryGuard() {}
bool RegistryGuard::start() { return false; }
void RegistryGuard::stop() {}
void RegistryGuard::run() {}

} // namespace yuzu::agent

#endif
