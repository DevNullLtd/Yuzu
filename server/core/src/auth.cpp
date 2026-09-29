#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/metrics.hpp>

#include "oidc_principal.hpp" // oidc_principal_id — ADR-2001 §5 single principal-string builder
#include "saml_principal.hpp" // saml_principal_id — ADR-2001 PR4a single principal-string builder
#include "session_store.hpp"  // HA WS-1/1a — durable operator sessions (ADR-2002 §4)

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
// clang-format off
#include <windows.h>  // must precede bcrypt.h (provides NTSTATUS)
#include <bcrypt.h>
// clang-format on
#pragma comment(lib, "bcrypt.lib")
#include <shlobj.h>
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h> // umask()
#include <unistd.h>   // geteuid()
#endif

namespace yuzu::server::auth {

namespace {
// Interval-gated poll of the durable session write-generation (~1s
// cross-replica staleness bound, ADR-2002 §4). Matches the memory note's
// approved bound; sessions number in the tens so a global generation whose
// bump clears the whole cache is cheap.
constexpr std::int64_t kSessionGenRefreshMs = 1000;

// Bounded stale-serve window (the rbac_store pattern the ADR names, ADR-2002 §4).
// The validate-cache is trusted only within this window of the last SUCCESSFUL
// generation refresh; once a refresh outage exceeds it, a cache hit is no longer
// trusted (validate falls through to the authoritative store, failing closed to
// 401 while the store stays degraded) — so a revoked/demoted/elevated session
// cannot ride a stale cache up to its 8h absolute expiry during a PG brownout.
constexpr std::int64_t kSessionGenStaleServeBoundMs = 30'000; // 30s

// Defense-in-depth authored-width ceiling on a durable session's base lifetime
// (adversarial-review K1 / unhappy-path UP-12), mirroring is_elevated's
// kMaxElevationWindow. The authored lifetime is a fixed 8h (kSessionDuration) at
// every mint site; this bound is generous (7d) so every legitimate session passes
// while a corrupted far-future expires_at is REJECTED in derive_session_deadlines.
// Per the clock-guarded-retention rule's "per-store bound must exceed the store's
// own max legitimate horizon": 7d >> 8h. Not copied from another store's constant.
constexpr std::int64_t kMaxSessionLifetimeMs = 7LL * 24 * 3600 * 1000;

std::int64_t steady_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::int64_t wall_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::chrono::system_clock::time_point tp_from_ms(std::int64_t ms) {
    return std::chrono::system_clock::time_point{std::chrono::milliseconds{ms}};
}

std::int64_t ms_from_tp(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}
} // namespace

// ── Platform crypto ─────────────────────────────────────────────────────────

std::vector<uint8_t> AuthManager::random_bytes(std::size_t n) {
    std::vector<uint8_t> buf(n);
#ifdef _WIN32
    auto status = BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(n),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
#endif
    return buf;
}

std::string AuthManager::bytes_to_hex(const std::vector<uint8_t>& v) {
    std::string out;
    out.reserve(v.size() * 2);
    for (auto b : v) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        out.append(buf, 2);
    }
    return out;
}

std::vector<uint8_t> AuthManager::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
        out.push_back(byte);
    }
    return out;
}

std::string AuthManager::pbkdf2_sha256(const std::string& password,
                                       const std::vector<uint8_t>& salt, int iterations) {
    constexpr int kKeyLen = 32; // SHA-256 output
    std::vector<uint8_t> derived(kKeyLen);

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                              BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    }

    status =
        BCryptDeriveKeyPBKDF2(hAlg, reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
                              static_cast<ULONG>(password.size()), const_cast<PUCHAR>(salt.data()),
                              static_cast<ULONG>(salt.size()), static_cast<ULONGLONG>(iterations),
                              derived.data(), static_cast<ULONG>(derived.size()), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptDeriveKeyPBKDF2 failed");
    }
#else
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()), salt.data(),
                           static_cast<int>(salt.size()), iterations, EVP_sha256(), kKeyLen,
                           derived.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }
#endif

    return bytes_to_hex(derived);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

std::string role_to_string(Role r) {
    return r == Role::admin ? "admin" : "user";
}

Role string_to_role(const std::string& s) {
    return s == "admin" ? Role::admin : Role::user;
}

std::filesystem::path default_config_path() {
#ifdef _WIN32
    return R"(C:\ProgramData\Yuzu\yuzu-server.cfg)";
#elif defined(__APPLE__)
    // Use per-user Application Support when not running as root. Gated on
    // euid (not just __APPLE__) for the same reason as default_cert_dir()
    // below: macOS sudo preserves $HOME by default, so an unqualified $HOME
    // fallback would send "sudo yuzu-server" to the invoking user's home
    // instead of the shared system config path.
    if (::geteuid() == 0)
        return "/etc/yuzu/yuzu-server.cfg";
    if (const char* home = std::getenv("HOME")) {
        return std::filesystem::path(home) / "Library/Application Support/Yuzu/yuzu-server.cfg";
    }
    return "/Library/Application Support/Yuzu/yuzu-server.cfg";
#else
    return "/etc/yuzu/yuzu-server.cfg";
#endif
}

std::filesystem::path default_cert_dir() {
#ifdef _WIN32
    return R"(C:\ProgramData\Yuzu\certs)";
#elif defined(__APPLE__)
    // Root keeps the shared /etc/yuzu/certs convention (matches Linux, matches
    // every doc/runbook/script that names it, and matches a packaged/privileged
    // install). A non-root run falls back to per-user Application Support, same
    // as default_config_path() above: /etc/yuzu is root-owned, so a native
    // macOS server run as a dev (start-UAT.sh, no --ca-dir) previously refused
    // to generate default-ca.pem / the secrets KEK with EACCES. Gating on euid
    // (not just __APPLE__) matters because macOS sudo preserves $HOME by
    // default (no -H) — an unqualified $HOME fallback would make "sudo
    // yuzu-server" write CA/KEK key material into the invoking user's home
    // instead of /etc/yuzu/certs.
    if (::geteuid() == 0)
        return "/etc/yuzu/certs";
    if (const char* home = std::getenv("HOME")) {
        return std::filesystem::path(home) / "Library/Application Support/Yuzu/certs";
    }
    return "/Library/Application Support/Yuzu/certs";
#else
    return "/etc/yuzu/certs";
#endif
}

std::string AuthManager::generate_session_token() {
    return bytes_to_hex(random_bytes(32));
}

bool AuthManager::constant_time_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size())
        return false;
    volatile unsigned char result = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return result == 0;
}

// ── Config I/O ──────────────────────────────────────────────────────────────

bool AuthManager::load_config(const std::filesystem::path& cfg_path) {
    cfg_path_ = cfg_path;

    std::ifstream f(cfg_path);
    if (!f.is_open())
        return false;

    bool has_users = false;
    {
        std::unique_lock lock(mu_);
        users_.clear();

        std::string line;
        while (std::getline(f, line)) {
            // Trim
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (line.empty())
                continue;
            // Parse version header (e.g. "# Version: 1")
            if (line.starts_with("# Version: ")) {
                try {
                    int ver = std::stoi(line.substr(11));
                    if (ver != 1) {
                        spdlog::error("Unsupported config file version {} in {}", ver,
                                      cfg_path.string());
                        return false;
                    }
                } catch (const std::exception& e) {
                    spdlog::error("Malformed version line in {}: {}", cfg_path.string(), e.what());
                    return false;
                }
                continue;
            }
            if (line[0] == '#')
                continue;

            // Format: username:role:salt_hex:hash_hex
            std::istringstream ss(line);
            std::string username, role_str, salt_hex, hash_hex;
            if (!std::getline(ss, username, ':'))
                continue;
            if (!std::getline(ss, role_str, ':'))
                continue;
            if (!std::getline(ss, salt_hex, ':'))
                continue;
            if (!std::getline(ss, hash_hex, ':'))
                continue;

            UserEntry entry;
            entry.username = username;
            entry.role = string_to_role(role_str);
            entry.salt_hex = salt_hex;
            entry.hash_hex = hash_hex;
            users_[username] = std::move(entry);
        }

        has_users = !users_.empty();
        spdlog::info("Loaded {} user(s) from {}", users_.size(), cfg_path.string());
    }

    // Load enrollment tokens and pending agents (each acquires mu_ internally)
    load_tokens();
    load_pending();

    return has_users;
}

bool AuthManager::save_config() const {
    if (auth_db_) {
        // AuthDB handles persistence — no config file write needed
        return true;
    }

    std::shared_lock lock(mu_);

    auto parent = cfg_path_.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            spdlog::error("Cannot create config directory {}: {}", parent.string(), ec.message());
            return false;
        }
    }

#ifndef _WIN32
    // Set restrictive umask so the file is created with 0600 from the start,
    // closing the TOCTOU window where it could be world-readable.
    mode_t old_mask = umask(0077);
#endif
    std::ofstream f(cfg_path_, std::ios::trunc);
#ifndef _WIN32
    umask(old_mask);
#endif
    if (!f.is_open()) {
        spdlog::error("Cannot write config file {}", cfg_path_.string());
        return false;
    }

    f << "# Yuzu Server Configuration\n";
    f << "# Version: 1\n";
    f << "# Format: username:role:salt:hash\n";
    f << "# DO NOT EDIT — managed by yuzu-server\n\n";

    for (const auto& [name, entry] : users_) {
        f << entry.username << ':' << role_to_string(entry.role) << ':' << entry.salt_hex << ':'
          << entry.hash_hex << '\n';
    }
    f.close();

#ifndef _WIN32
    // Belt-and-suspenders: ensure 0600 even if the file pre-existed with looser perms.
    std::error_code perm_ec;
    std::filesystem::permissions(
        cfg_path_, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, perm_ec);
    if (perm_ec) {
        spdlog::warn("Failed to set permissions on {}: {}", cfg_path_.string(), perm_ec.message());
    }
#endif

    spdlog::info("Saved {} user(s) to {}", users_.size(), cfg_path_.string());
    return true;
}

// ── First-run setup ─────────────────────────────────────────────────────────

static std::string prompt(const std::string& msg, const std::string& default_val = {}) {
    if (default_val.empty()) {
        std::cout << msg << ": ";
    } else {
        std::cout << msg << " [" << default_val << "]: ";
    }
    std::cout.flush();

    std::string input;
    std::getline(std::cin, input);
    // Trim
    while (!input.empty() && (input.back() == '\r' || input.back() == '\n'))
        input.pop_back();

    if (input.empty() && !default_val.empty())
        return default_val;
    return input;
}

static std::string prompt_password(const std::string& msg) {
    std::cout << msg << ": ";
    std::cout.flush();

    // Disable echo
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
#else
    // POSIX: use termios to disable echo
    struct termios_guard {
        // Simple approach: just read without echo toggle for now.
        // Full implementation would use tcgetattr/tcsetattr.
    };
#endif

    std::string pw;
    std::getline(std::cin, pw);
    while (!pw.empty() && (pw.back() == '\r' || pw.back() == '\n'))
        pw.pop_back();

    std::cout << '\n';

#ifdef _WIN32
    SetConsoleMode(hStdin, mode);
#endif

    return pw;
}

bool AuthManager::first_run_setup(const std::filesystem::path& cfg_path) {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════╗\n";
    std::cout << "║       Yuzu Server — First Run Setup      ║\n";
    std::cout << "╠══════════════════════════════════════════╣\n";
    std::cout << "║  No configuration file found.            ║\n";
    std::cout << "║  Let's create your initial accounts.     ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n\n";

    // Admin account
    auto admin_name = prompt("Admin account name", "admin");
    if (admin_name.empty()) {
        std::cerr << "Account name cannot be empty.\n";
        return false;
    }
    auto admin_pw = prompt_password("Admin password");
    if (admin_pw.size() < 12) {
        std::cerr << "Password must be at least 12 characters.\n";
        return false;
    }
    auto admin_pw2 = prompt_password("Confirm admin password");
    if (admin_pw != admin_pw2) {
        std::cerr << "Passwords do not match.\n";
        return false;
    }

    std::cout << '\n';

    // User account
    auto user_name = prompt("User account name", "user");
    if (user_name.empty()) {
        std::cerr << "Account name cannot be empty.\n";
        return false;
    }
    if (user_name == admin_name) {
        std::cerr << "User account must differ from admin account.\n";
        return false;
    }
    auto user_pw = prompt_password("User password");
    if (user_pw.size() < 12) {
        std::cerr << "Password must be at least 12 characters.\n";
        return false;
    }
    auto user_pw2 = prompt_password("Confirm user password");
    if (user_pw != user_pw2) {
        std::cerr << "Passwords do not match.\n";
        return false;
    }

    // Build and save config
    AuthManager mgr;
    mgr.cfg_path_ = cfg_path;
    mgr.upsert_user(admin_name, admin_pw, Role::admin);
    mgr.upsert_user(user_name, user_pw, Role::user);

    if (!mgr.save_config()) {
        std::cerr << "Failed to write config to " << cfg_path.string() << '\n';
        return false;
    }

    std::cout << "\nConfiguration saved to " << cfg_path.string() << '\n';
    std::cout << "You can now restart the server.\n\n";
    return true;
}

// ── Durable session store integration (HA WS-1/1a, ADR-2002 §4) ───────────────

std::string AuthManager::hash_token(const std::string& raw_token) {
    return sha256_hex(raw_token);
}

void AuthManager::note_session_store_degrade(const char* op) const {
    if (metrics_)
        metrics_->counter("yuzu_auth_session_store_degrade_total", {{"op", op}}).increment();
}

bool AuthManager::is_session_store_ok() const noexcept {
    return session_store_ == nullptr || session_store_->is_open();
}

bool AuthManager::derive_session_deadlines(Session& s, std::int64_t created_ms,
                                           std::int64_t expires_ms, std::int64_t last_activity_ms,
                                           std::int64_t mfa_verified_ms,
                                           std::int64_t elevated_until_ms,
                                           std::int64_t elevation_issued_ms, std::int64_t now_ms) {
    using namespace std::chrono;
    // Authored ABSOLUTE wall instants — display/audit and the suspend backstop
    // (is_elevated / validate consult these with a generous slack). A stored 0
    // (no proof / not elevated) maps to the epoch sentinel.
    s.expires_at = tp_from_ms(expires_ms);
    s.mfa_verified_at = tp_from_ms(mfa_verified_ms);
    s.elevated_until = tp_from_ms(elevated_until_ms);
    s.elevation_issued_at = tp_from_ms(elevation_issued_ms);
    s.last_activity_at = tp_from_ms(last_activity_ms);
    s.last_activity_persisted_at = s.last_activity_at;

    // Fail-closed sentinels FIRST, so an early return below leaves EVERY steady
    // field in the defined {} state — even when re-deriving a LIVE cached session
    // (mark_mfa / elevate re-derive `it->second` in place), where a partially-set
    // false path would otherwise leave a stale steady_elevated_until/mfa live
    // (adversarial-review K2). A false return means "do not honor / do not cache".
    s.steady_expires = {};
    s.steady_elevated_until = {};
    s.steady_last_activity = {};
    s.steady_mfa_verified = {};
    s.steady_last_persisted = {};

    const auto steady = steady_clock::now();
    // Base-lifetime authored-width ceiling (adversarial-review K1 / unhappy-path
    // UP-12, mirroring the elevation §4(b) width REJECT below): a corrupted
    // far-future `expires_at` — the same partial-row-corruption class §4(b)
    // defends `elevated_until` against, and which the wall backstop cannot catch
    // because it is anchored to that same corrupted instant — is REJECTED, not
    // honored for its claimed width. kMaxSessionLifetime is generous vs the fixed
    // 8h authored default (kSessionDuration), so every legitimate session passes.
    if (expires_ms - created_ms > kMaxSessionLifetimeMs)
        return false;
    // Base lifetime. Clamp `now_ms` up to created_at so a backward DB step (now
    // below creation) cannot inflate the remaining past the authored lifetime
    // (H2); a signed remaining <= 0 means already expired at populate — fail
    // closed (H4). The caller must not cache/honor a false return.
    // (std::max) parenthesised to dodge the <windows.h> `max` function-like macro
    // (same MSVC defense as the `min` sites below; GCC/Clang unaffected).
    const std::int64_t rem_session = expires_ms - (std::max)(now_ms, created_ms);
    if (rem_session <= 0)
        return false;
    s.steady_expires = steady + milliseconds(rem_session);

    // Idle slide anchor: age since last activity in the DB domain, clamped >= 0.
    // A future-dated last_activity (a backward DB step below the last
    // GREATEST-clamped touch) clamps idle_age to 0 (treated active-now) — the
    // deliberate availability-preserving choice (K3): idle is defense-in-depth
    // UNDER the absolute expiry, which steady_expires + the ceiling above bound.
    const std::int64_t idle_age = std::max<std::int64_t>(0, now_ms - last_activity_ms);
    s.steady_last_activity = steady - milliseconds(idle_age);
    // The durable-touch throttle starts from how stale the durable row already is
    // (same age), so the first post-populate touch persists iff the row is older
    // than the persist granularity. Steady-domain — never wall (CDX-P1-001).
    s.steady_last_persisted = s.steady_last_activity;

    // Elevation. {} (not elevated) unless ALL hold:
    //   - a grant is set and is not future-issued (now < issued = a backward step
    //     below the grant instant → treat as not elevated, fail closed);
    //   - the AUTHORED width `elevated_until - elevation_issued` is within the hard
    //     kMaxElevationWindow ceiling — a wider window (a forward-corrupted
    //     elevated_until, or an epoch-anchored enormous one) is REJECTED outright,
    //     the ADR §4(b) defense-in-depth bound (NOT clamped — a corrupted grant
    //     confers zero admin, not a capped 24h);
    //   - the remaining, computed against `max(now, issued)`, is positive — the H2
    //     clamp: a backward `now_ms` (below issued) cannot inflate the LIVED window
    //     past its authored width, because remaining is bounded by the width.
    s.steady_elevated_until = {};
    if (elevated_until_ms != 0 && now_ms >= elevation_issued_ms) {
        const std::int64_t kMaxElevMs = duration_cast<milliseconds>(kMaxElevationWindow).count();
        const std::int64_t width = elevated_until_ms - elevation_issued_ms;
        if (width > 0 && width <= kMaxElevMs) {
            const std::int64_t rem_elev =
                elevated_until_ms - (std::max)(now_ms, elevation_issued_ms); // (std::max): MSVC macro
            if (rem_elev > 0)
                s.steady_elevated_until = steady + milliseconds(rem_elev);
        }
    }

    // MFA proof. {} unless a proof exists and is not future-dated (a proof stamped
    // after `now_ms` is a backward step → treated as absent, matching the legacy
    // guard). mfa_step_up ages against this steady anchor.
    s.steady_mfa_verified = {};
    if (mfa_verified_ms != 0 && mfa_verified_ms <= now_ms)
        s.steady_mfa_verified = steady - milliseconds(now_ms - mfa_verified_ms);
    return true;
}

Session AuthManager::session_from_row(const yuzu::server::SessionRow& row, std::int64_t db_now_ms) {
    Session s;
    s.username = row.username;
    s.display_name = row.display_name;
    s.role = string_to_role(row.role);
    s.auth_source = row.auth_source;
    s.oidc_sub = row.oidc_sub;
    s.token_scope_service = row.token_scope_service;
    s.mcp_tier = row.mcp_tier;
    s.principal_kind = row.principal_kind.empty() ? "human" : row.principal_kind;
    // Adjudicate against the DB clock at read time and derive the local monotonic
    // deadlines. A false return (already expired at db_now) leaves the steady
    // sentinels {}; callers check that where it matters (validate rejects).
    (void)derive_session_deadlines(s, row.created_at_ms, row.expires_at_ms, row.last_activity_ms,
                                   row.mfa_verified_ms, row.elevated_until_ms,
                                   row.elevation_issued_ms, db_now_ms);
    return s;
}

bool AuthManager::wipe_user_sessions_durable(const std::string& username) {
    if (!session_store_)
        return true; // legacy in-memory path — nothing durable to fail
    if (auto r = session_store_->invalidate_user(username); !r) {
        spdlog::error("durable session wipe for user '{}' failed ({}) — role change NOT honored, "
                      "retry (invalidate_user is idempotent)",
                      username, r.error().message);
        note_session_store_degrade("invalidate_user"); // parity with the other degrade sites
        return false; // fail closed — caller must not report success (authdb-BLOCKING)
    }
    return true;
}

bool AuthManager::persist_new_session(const std::string& raw_token,
                                      const yuzu::server::SessionWriteParams& params) {
    // The cached Session's non-time fields come straight from params; its
    // adjudication deadlines are derived from the AUTHORED times (DB clock for a
    // durable store; this host's wall clock for the legacy path) so the cache
    // matches the durable row exactly.
    Session s;
    s.username = params.username;
    s.display_name = params.display_name;
    s.role = string_to_role(params.role);
    s.auth_source = params.auth_source;
    s.oidc_sub = params.oidc_sub;
    s.token_scope_service = params.token_scope_service;
    s.mcp_tier = params.mcp_tier;
    s.principal_kind = params.principal_kind.empty() ? "human" : params.principal_kind;

    std::string key = raw_token;
    if (session_store_) {
        auto p = params;
        p.token_hash = hash_token(raw_token);
        key = p.token_hash;
        auto r = session_store_->create(p);
        if (!r) {
            spdlog::error("AuthManager: durable session create failed for '{}': {}", s.username,
                          r.error().message);
            note_session_store_degrade("create");
            return false; // fail closed — login not honored (ADR-0007)
        }
        const auto& a = *r;
        derive_session_deadlines(s, a.created_at_ms, a.expires_at_ms, a.last_activity_ms,
                                 a.mfa_verified_ms, a.elevated_until_ms, a.elevation_issued_ms,
                                 a.db_now_ms);
    } else {
        // Legacy no-store path: this host's wall clock IS the authority.
        const std::int64_t now_ms = wall_now_ms();
        const std::int64_t mfa_ms = params.mfa_verified_now ? now_ms : params.mfa_verified_ms_abs;
        derive_session_deadlines(s, now_ms, now_ms + params.session_lifetime_ms, now_ms, mfa_ms,
                                 /*elevated_until*/ 0, /*elevation_issued*/ 0, now_ms);
    }
    std::unique_lock lock(mu_);
    sessions_[key] = s;
    return true;
}

void AuthManager::maybe_refresh_session_generation() const {
    if (!session_store_)
        return;
    bool do_refresh = false;
    {
        std::lock_guard<std::mutex> g(session_gen_mtx_);
        const std::int64_t now = steady_now_ms();
        // Single-flight: claim the refresh slot by advancing the gate BEFORE the
        // read (like RbacStore) so concurrent validators don't all poll PG.
        if (!session_gen_valid_ ||
            now - last_session_gen_refresh_ms_ >= kSessionGenRefreshMs) {
            last_session_gen_refresh_ms_ = now;
            do_refresh = true;
        }
    }
    if (!do_refresh)
        return;
    auto gen = session_store_->read_generation();
    if (!gen) {
        // Refresh failed (DB blip): keep serving the existing cache unchanged —
        // every cached session is still bounded by its absolute expires_at. Never
        // clear on failure (that would log out every locally-cached operator).
        spdlog::debug("AuthManager: durable session generation refresh failed: {}",
                      gen.error().message);
        note_session_store_degrade("generation_refresh");
        return;
    }
    bool advanced = false;
    {
        std::lock_guard<std::mutex> g(session_gen_mtx_);
        last_successful_session_gen_refresh_ms_ = steady_now_ms(); // bounded stale-serve anchor
        if (!session_gen_valid_ || *gen > cached_session_gen_) {
            cached_session_gen_ = *gen;
            session_gen_valid_ = true;
            advanced = true;
        }
    }
    if (advanced) {
        // A mutation landed (possibly on another replica) — drop the whole cache
        // so the next lookup re-reads authoritative state. Cleared under mu_,
        // which is never held together with session_gen_mtx_.
        std::unique_lock lock(mu_);
        sessions_.clear();
    }
}

bool AuthManager::session_generation_view_stale() const {
    if (!session_store_)
        return false; // legacy in-memory: no cross-replica coherence to bound
    std::lock_guard<std::mutex> g(session_gen_mtx_);
    if (!session_gen_valid_)
        return true; // never confirmed a generation → don't trust the cache
    return (steady_now_ms() - last_successful_session_gen_refresh_ms_) >
           kSessionGenStaleServeBoundMs;
}

// ── Authentication ──────────────────────────────────────────────────────────

std::expected<UserEntry, AuthManager::UserLookupMiss>
AuthManager::find_user_or_hydrate(const std::string& username) {
    {
        std::shared_lock lock(mu_);
        auto it = users_.find(username);
        if (it != users_.end())
            return it->second;
    }
    if (!auth_db_)
        return std::unexpected(UserLookupMiss::NotFound); // cfg-file mode: the map IS the truth

    // Cold cache (#4020): the row may exist in AuthDB even though this process
    // never cached it. Read it OUTSIDE mu_ (durable PG I/O, same lock ordering as
    // the other AuthDB-first paths). get_user filters is_active, so a
    // soft-deleted account stays a miss here.
    auto db_user = auth_db_->get_user(username);
    if (!db_user) {
        // Gate 2/4 re-review follow-up (security-guardian + authdb, converged
        // independently): InvalidUsername (get_user()'s own input-validation
        // rejection, #2755e3871) is NOT a store-health signal - it's a
        // rejected-shape input, the same class as a plain miss from the
        // caller's point of view. Routing it through the DbError branch below
        // would log a real attack attempt as a false "AuthDB lookup failed",
        // masking a genuine outage during exactly that attack.
        if (db_user.error() == yuzu::server::AuthDBError::UserNotFound ||
            db_user.error() == yuzu::server::AuthDBError::InvalidUsername)
            return std::unexpected(UserLookupMiss::NotFound);
        spdlog::error("AuthManager: AuthDB lookup for '{}' failed on a cold cache - failing "
                      "closed (no credential check)",
                      username);
        return std::unexpected(UserLookupMiss::DbError);
    }

    // Gate 5 CH-1 re-review follow-up: stamp BEFORE the possible emplace, not
    // after - try_emplace no-ops if a concurrent write already installed an
    // entry, and this call must never touch that entry's version once it
    // exists (see the no-op comment below).
    db_user->role_version = next_role_version_();
    std::unique_lock lock(mu_);
    // try_emplace, never insert_or_assign: an upsert_user (new password) or
    // reactivate_user that landed while the read above was in flight has already
    // installed a NEWER entry than the row we hold; clobbering it would make the
    // new password fail until the next restart. Whatever is cached now wins.
    auto [it, inserted] = users_.try_emplace(username, std::move(*db_user));
    (void)inserted;
    return it->second;
}

std::optional<Role>
AuthManager::recheck_role_after_credential_check(const std::string& username, Role pre_check_role,
                                                  [[maybe_unused]] std::uint64_t pre_check_version,
                                                  std::string_view context) {
    if (!auth_db_)
        return pre_check_role; // cfg-file mode: users_ IS the truth, nothing to re-check
    // TEST-ONLY seam (see set_role_recheck_race_hook_for_test's doc): fires
    // before this call's own row-locked read starts - a no-op (nullptr) in
    // production. Row-locking (below) means a hook that synchronously calls
    // update_role() here would self-deadlock (this thread would hold the row
    // lock later while its own hook blocks on it) - test seams that need a
    // GENUINE race drive the writer from a separate thread instead; see
    // set_role_recheck_race_hook_for_test's doc for the current contract.
    if (role_recheck_race_hook_for_test_)
        role_recheck_race_hook_for_test_();
    // #4107: row-locked re-check, closes the same-process divergence residual
    // by construction (serializes against any concurrent update_role()/
    // reactivate_user()) rather than detecting it after the fact via a
    // version counter - see recheck_role_locked's header doc for the full
    // mechanism. `pre_check_version` is now unused THROUGHOUT this function
    // (fjarvis Gate 8 catch: an earlier version of this comment wrongly
    // claimed the cfg-file-mode branch above used it - it doesn't, that
    // branch only reads `pre_check_role`). Kept in the signature only to
    // avoid touching both call sites in this same round - cleanup tracked
    // as a follow-up.
    std::optional<Role> result;
    auto outcome = auth_db_->recheck_role_locked(username, [&](Role db_role) {
        // Invoked while AuthDB holds this row's lock - see the header doc.
        // Lock ORDERING invariant (cpp-expert Gate 8 catch): this is the
        // first place in this file mu_ is acquired from INSIDE an open
        // AuthDB transaction. Safe only because every AuthDB write this file
        // makes (update_role/reactivate_user/remove_user) completes its own
        // DB call BEFORE ever touching mu_ (the file-wide "never hold mu_
        // across a DB call" discipline, stated where each of those calls
        // takes mu_) - so no code path can be holding mu_ while ALSO
        // attempting to open a transaction that needs this same row lock,
        // which would deadlock against this one. A future change that holds
        // mu_ and then calls an AuthDB write method would break this.
        //
        // TEST-ONLY seam (see set_role_recheck_inside_lock_hook_for_test's
        // doc): a no-op (nullptr) in production.
        if (role_recheck_inside_lock_hook_for_test_)
            role_recheck_inside_lock_hook_for_test_();
        std::unique_lock lock(mu_);
        auto it = users_.find(username);
        if (it != users_.end()) {
            it->second.role = db_role;
            it->second.role_version = next_role_version_();
        }
        // else: the entry vanished from the cache mid-recheck. Provably
        // unreachable today (cpp-expert Gate 8 verified this by tracing):
        // the only eraser of a specific username is remove_user(), whose own
        // DB write takes this SAME row lock, so its cache-erase (which runs
        // strictly after its own DB commit) cannot land before a callback
        // that already observed the row as active. Not a silent bypass if
        // this invariant is ever broken by a future change - `result` still
        // gets set to the DB-confirmed role either way, which is the
        // conservative choice (the row lock already proved the account is
        // active; a merely-absent cache entry is this process's own
        // bookkeeping lagging, not a signal to deny).
        result = db_role;
    });
    if (!outcome) {
        // #4020 Gate 3 quality-engineer follow-up: only a genuine UserNotFound
        // (soft-deleted/removed) means the cache is actually stale - evicting on
        // ANY failure (a transient QueryFailed/StoreBusy from pool contention)
        // would erase a perfectly valid, freshly-verified entry over a
        // momentary DB hiccup on an otherwise-successful credential check,
        // forcing a needless re-hydrate on this user's very next request. Fail
        // closed for THIS call either way (a DB outage must not silently fall
        // back to trusting a role we can no longer confirm), but only evict when
        // we've actually confirmed removal (External adversarial review,
        // fjarvis, C1: mirrors the reasoning that made this the right call for
        // a concurrent remove_user() specifically).
        if (yuzu::server::AuthDBError::UserNotFound == outcome.error()) {
            spdlog::warn("{}: user '{}' not active in AuthDB", context, username);
            std::unique_lock lock(mu_);
            users_.erase(username);
        } else {
            spdlog::error("{}: AuthDB re-check for '{}' failed (store error, not a removal) - "
                         "failing closed without touching the cache",
                         context, username);
        }
        return std::nullopt;
    }
    return result;
}

bool AuthManager::post_mint_role_recheck(const std::string& username, Role minted_role,
                                         std::string_view context) {
    // #4107 check-then-mint gap (external adversarial review, fjarvis, PR
    // #4076): recheck_role_after_credential_check's row-locked read closes
    // the SAME-process/cross-replica divergence race for the read itself,
    // but a demotion committing strictly AFTER that read and before this
    // session's mint completes still lands a session stamped with the
    // pre-demote role - and that demote's own sweep (update_role's
    // std::erase_if) already ran before this session existed, so it can't
    // catch it either.
    //
    // Closed here via the SAME pattern this codebase already uses for the
    // structurally identical OIDC/SAML deprovision-race (docs/
    // auth-architecture.md, "post-mint re-check"): mint normally, then
    // immediately re-verify against the authority and revoke-and-deny if it
    // diverged, rather than serializing the mint inside the row lock.
    // Serializing was considered and explicitly rejected for that race
    // class - it would require holding AuthDB's row lock across a
    // SessionStore call, violating this codebase's "never hold one store's
    // pool lease while calling another" discipline (docs/
    // auth-architecture.md §3) - SessionStore's shared write-generation row
    // is exactly the kind of cross-store lock that could deadlock against
    // AuthDB's row lock under the wrong interleaving.
    //
    // Ordering proof (why this closes the race rather than merely
    // narrowing it, for the SAME-PROCESS case): a racing update_role()
    // commits its AuthDB UPDATE BEFORE taking mu_ to sweep sessions_ (see
    // update_role's own body). persist_new_session's mint-write and
    // update_role's sweep both take mu_, so one strictly happens-before
    // the other. If the mint happens-before the sweep, the sweep (running
    // after) finds and erases this just-minted session - self-healed. If
    // the sweep happens-before the mint, the sweep's own UPDATE already
    // committed before the sweep ran, which is before the mint, which is
    // before this call - so this call's fresh AuthDB read is guaranteed to
    // observe it. Cross-replica: this needs no mu_ analogue at all (authdb
    // Gate 8 correction to an earlier draft of this comment, which wrongly
    // reached for one) - mu_ is per-process and has no cross-replica
    // meaning. The actual argument is simpler and stronger: this call's
    // own SELECT (get_user(), a bare autocommit read, no held transaction)
    // runs strictly AFTER persist_new_session returns, and ordinary READ
    // COMMITTED visibility on a single-primary Postgres instance guarantees
    // it observes any commit that landed before it, regardless of which
    // connection or replica issued either statement - no replica-local
    // state or clock needs to agree with any other's. This reasoning
    // assumes single-primary Postgres; it would need re-deriving under
    // read-replica routing, the same caveat ADR-2001's own analogous
    // cross-replica guarantee (docs/adr/2001-scim-oidc-identity-linkage.md,
    // "Known residuals") flags for its own case.
    //
    // Residual this does NOT close (same one ADR-2001/OIDC's own post-mint
    // recheck discloses for its structurally identical race): a demote
    // landing strictly between this call's own read and the response/
    // Set-Cookie actually reaching the client is not observable to this
    // function at all - closing that would mean holding this transaction
    // open all the way to the HTTP response, which is a different, larger
    // change than a role recheck.
    //
    // wipe_user_sessions_durable/invalidate_user_sessions delete the
    // durable row directly rather than working off a stale local list,
    // which is what makes the revoke-on-divergence half of this function
    // (not just the read half above) cross-replica-correct too.
    //
    // Returns true (nothing to do) in cfg-file mode - `users_` IS the
    // truth there, nothing to diverge from.
    if (!auth_db_)
        return true;
    auto post = auth_db_->get_user(username);
    if (!post) {
        const bool removed = yuzu::server::AuthDBError::UserNotFound == post.error();
        spdlog::warn("{}: post-mint re-check for '{}' {} - revoking the session just minted",
                    context, username, removed ? "found the account no longer active"
                                                : "hit a store error (failing closed)");
        auto revoke = invalidate_user_sessions(username);
        if (metrics_) {
            metrics_->counter("yuzu_auth_role_recheck_post_mint_denied_total").increment();
        }
        (void)revoke; // best-effort revoke; the mint is already denied to the caller either way
        return false;
    }
    if (post->role != minted_role) {
        spdlog::warn("{}: post-mint re-check for '{}' found the role changed {} -> {} during "
                    "the mint (concurrent role-change race) - revoking the session just minted",
                    context, username, role_to_string(minted_role), role_to_string(post->role));
        auto revoke = invalidate_user_sessions(username);
        if (metrics_) {
            metrics_->counter("yuzu_auth_role_recheck_post_mint_denied_total").increment();
        }
        (void)revoke;
        return false;
    }
    return true;
}

std::optional<std::string> AuthManager::authenticate(const std::string& username,
                                                     const std::string& password) {
    // Time the PBKDF2 verify path. Histogram is observed even on failure
    // (unknown user / bad password) because the dominant cost on a busy
    // server is the iteration loop itself, and a regression there hits
    // both branches equally. Buckets default to ms-scale; PBKDF2 at
    // 100k iterations runs ~50-150 ms on commodity hardware.
    const auto t_start = std::chrono::steady_clock::now();

    // Cache-or-AuthDB lookup (#4020); a COPY, so PBKDF2 below runs off mu_.
    auto entry = find_user_or_hydrate(username);
    if (!entry) {
        if (entry.error() == UserLookupMiss::DbError)
            return std::nullopt; // AuthDB unreachable: fail closed, already logged, not a
                                 // bad-username signal (no unknown_user histogram sample)
        spdlog::warn("Auth failed: unknown user '{}'", username);
        if (metrics_) {
            const auto elapsed =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
            metrics_
                ->histogram("yuzu_auth_login_duration_seconds",
                            {{"method", "password"}, {"result", "unknown_user"}})
                .observe(elapsed);
        }
        return std::nullopt;
    }

    auto salt = hex_to_bytes(entry->salt_hex);
    auto hash = pbkdf2_sha256(password, salt, kPbkdf2Iterations);

    if (!constant_time_compare(hash, entry->hash_hex)) {
        spdlog::warn("Auth failed: bad password for '{}'", username);
        if (metrics_) {
            const auto elapsed =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
            metrics_
                ->histogram("yuzu_auth_login_duration_seconds",
                            {{"method", "password"}, {"result", "bad_password"}})
                .observe(elapsed);
        }
        return std::nullopt;
    }

    // Re-verify against AuthDB: catches a soft-deleted/removed user AND makes
    // this the authoritative role for the session about to be minted (#4020 +
    // Gate 2/3 governance follow-ups — see recheck_role_after_credential_check's
    // doc for the full rationale, including the row-lock serialization #4107
    // added to close the same-process divergence race).
    auto current_role = recheck_role_after_credential_check(username, entry->role,
                                                             entry->role_version, "Auth failed");
    if (!current_role)
        return std::nullopt;
    entry->role = *current_role;

    auto token = generate_session_token();
    yuzu::server::SessionWriteParams params;
    params.username = username;
    params.display_name = username; // local auth: username IS the human label
    params.role = role_to_string(entry->role);
    params.auth_source = "local";
    params.session_lifetime_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(kSessionDuration).count();
    // password login carries no MFA proof yet — a step-up stamps it later.
    // TEST-ONLY seam (see set_post_mint_race_hook_for_test's doc): fires
    // here, squarely inside the #4107 check-then-mint window - the row lock
    // has already released (recheck above returned) but the session has not
    // yet been minted. A no-op (nullptr) in production.
    if (post_mint_race_hook_for_test_)
        post_mint_race_hook_for_test_();
    // mu_ is not held here: persist_new_session does durable PG I/O and
    // re-takes mu_ to cache (non-recursive) — never hold mu_ across it.
    if (!persist_new_session(token, params))
        return std::nullopt; // durable-write failure → login not honored (ADR-0007)
    // #4107 check-then-mint gap: see post_mint_role_recheck's own doc.
    if (!post_mint_role_recheck(username, entry->role, "Auth failed"))
        return std::nullopt;

    spdlog::info("User '{}' authenticated (role={})", username, params.role);
    if (metrics_) {
        const auto elapsed =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
        metrics_
            ->histogram("yuzu_auth_login_duration_seconds",
                        {{"method", "password"}, {"result", "success"}})
            .observe(elapsed);
    }
    return token;
}

std::optional<Role> AuthManager::verify_password(const std::string& username,
                                                 const std::string& password) {
    // Mirrors authenticate() up to the credential check but stops short of
    // session creation. Histogram labels match authenticate() so dashboards
    // continue to roll up "password verify" cost across both call sites.
    const auto t_start = std::chrono::steady_clock::now();
    auto entry = find_user_or_hydrate(username); // cache-or-AuthDB (#4020), a COPY
    if (!entry) {
        if (entry.error() == UserLookupMiss::DbError)
            return std::nullopt; // fail closed; logged by the helper, not an unknown_user sample
        spdlog::warn("verify_password failed: unknown user '{}'", username);
        if (metrics_) {
            const auto elapsed =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
            metrics_
                ->histogram("yuzu_auth_login_duration_seconds",
                            {{"method", "password"}, {"result", "unknown_user"}})
                .observe(elapsed);
        }
        return std::nullopt;
    }
    auto salt = hex_to_bytes(entry->salt_hex);
    auto hash = pbkdf2_sha256(password, salt, kPbkdf2Iterations);
    if (!constant_time_compare(hash, entry->hash_hex)) {
        spdlog::warn("verify_password failed: bad password for '{}'", username);
        if (metrics_) {
            const auto elapsed =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
            metrics_
                ->histogram("yuzu_auth_login_duration_seconds",
                            {{"method", "password"}, {"result", "bad_password"}})
                .observe(elapsed);
        }
        return std::nullopt;
    }
    // Re-verify against AuthDB: catches a soft-deleted/removed user AND makes
    // this the authoritative role for the caller (same rationale as
    // authenticate() — see recheck_role_after_credential_check's doc).
    auto current_role = recheck_role_after_credential_check(
        username, entry->role, entry->role_version, "verify_password failed");
    if (!current_role)
        return std::nullopt;
    auto role = *current_role;
    if (metrics_) {
        const auto elapsed =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
        metrics_
            ->histogram("yuzu_auth_login_duration_seconds",
                        {{"method", "password"}, {"result", "success"}})
            .observe(elapsed);
    }
    return role;
}

std::string AuthManager::create_local_session(const std::string& username, Role role,
                                              bool mfa_verified) {
    auto token = generate_session_token();
    yuzu::server::SessionWriteParams params;
    params.username = username;
    params.display_name = username; // local auth: username IS the human label
    params.role = role_to_string(role);
    params.auth_source = "local";
    params.session_lifetime_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(kSessionDuration).count();
    params.mfa_verified_now = mfa_verified; // local step-up → stamp now() in the store
    if (!persist_new_session(token, params)) {
        // Durable-write failure (store configured but unreachable) → no session.
        // An empty token degrades to "not authenticated" at the caller's cookie
        // set / next validate (fail-safe), never a false success (ADR-0007).
        spdlog::error("create_local_session: durable persist failed for '{}'", username);
        return {};
    }
    // #4107 check-then-mint gap: see post_mint_role_recheck's own doc. This
    // function's `role` parameter can be arbitrarily stale by the time this
    // point is reached (its callers include /login/mfa's TOTP/recovery-code
    // verify, which reads a role from an earlier verify_password() call
    // across an entire TOTP-verification round trip, NOT /login/mfa/stepup -
    // that route re-proves MFA on an existing session and never calls this
    // function) - the fresh re-read here closes the gap
    // regardless of how wide that earlier window was. Same empty-token
    // fail-safe contract as the durable-write-failure branch above: no
    // session, degrades to "not authenticated" at the caller's cookie set.
    if (!post_mint_role_recheck(username, role, "create_local_session"))
        return {};
    // Stamp last_login_at on every successful login, not just the
    // MFA-verified TOTP path. The MFA-verified TOTP path already does
    // this as part of its counter UPDATE so calling here is harmless
    // duplicated work for that branch; for the no-MFA, recovery-code,
    // and OIDC paths it is the only place the column gets written.
    // Best-effort — touch_last_login is fail-silent (Gate 4
    // happy-path B1).
    if (auth_db_) {
        auth_db_->touch_last_login(username);
    }
    spdlog::info("Local session created for '{}' (mfa_verified={})", username, mfa_verified);
    return token;
}

bool AuthManager::mark_session_mfa_verified(const std::string& token) {
    if (token.size() > auth::kMaxSessionTokenLength)
        return false;
    if (session_store_) {
        const std::string key = hash_token(token);
        // Durable write FIRST (bumps the generation → every replica's cache drops
        // the stale copy on its next refresh); the store authors mfa_verified =
        // now() and RETURNs every time field, so the cache re-derives exactly.
        auto r = session_store_->mark_mfa(key);
        if (!r) {
            spdlog::error("mark_session_mfa_verified: durable write failed ({})",
                          r.error().message);
            note_session_store_degrade("mark_mfa");
            return false;
        }
        if (!r->has_value())
            return false; // no such durable session
        const auto& a = r->value();
        std::unique_lock lock(mu_);
        if (auto it = sessions_.find(key); it != sessions_.end())
            derive_session_deadlines(it->second, a.created_at_ms, a.expires_at_ms,
                                     a.last_activity_ms, a.mfa_verified_ms, a.elevated_until_ms,
                                     a.elevation_issued_ms, a.db_now_ms);
        return true;
    }
    std::unique_lock lock(mu_);
    auto it = sessions_.find(token);
    if (it == sessions_.end())
        return false;
    it->second.mfa_verified_at = std::chrono::system_clock::now();
    it->second.steady_mfa_verified = std::chrono::steady_clock::now();
    return true;
}

std::optional<std::chrono::system_clock::time_point>
AuthManager::elevate_session(const std::string& token, std::chrono::seconds duration) {
    if (token.size() > auth::kMaxSessionTokenLength)
        return std::nullopt;
    if (session_store_) {
        const std::string key = hash_token(token);
        // The store authors the grant in the DB clock domain and does the
        // "never past absolute expiry" clamp (LEAST) + dead-window guard in SQL,
        // atomically against the row's own expiry — no read-then-clamp TOCTOU
        // here (design-review S4). nullopt ⇒ absent OR the grant would already be
        // expired; either way the route maps it to 401 (fail-closed for a
        // privileged op). A degraded write ⇒ nullopt too.
        const std::int64_t dur_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        auto r = session_store_->set_elevation(key, dur_ms);
        if (!r) {
            spdlog::error("elevate_session: durable set_elevation failed ({})", r.error().message);
            note_session_store_degrade("elevate");
            return std::nullopt;
        }
        if (!r->has_value())
            return std::nullopt;
        const auto& a = r->value();
        // Re-derive the cached session (best-effort — it may live only on another
        // replica, which picks up the grant on its next generation refresh).
        std::unique_lock lock(mu_);
        if (auto it = sessions_.find(key); it != sessions_.end())
            derive_session_deadlines(it->second, a.created_at_ms, a.expires_at_ms,
                                     a.last_activity_ms, a.mfa_verified_ms, a.elevated_until_ms,
                                     a.elevation_issued_ms, a.db_now_ms);
        return tp_from_ms(a.elevated_until_ms);
    }
    std::unique_lock lock(mu_);
    auto it = sessions_.find(token);
    if (it == sessions_.end())
        return std::nullopt;
    // Clamp to the session's own absolute lifetime — an elevation can never
    // outlive the cookie session that carries it (follow-up B, security review
    // 2026-06-30). (std::min) parenthesised to dodge the <windows.h> `min`
    // function-like macro on MSVC (see the note at validate_session below).
    const auto now = std::chrono::system_clock::now();
    const auto until = (std::min)(now + duration, it->second.expires_at);
    // Dead-window guard (governance hardening round, UP-1/UP-4): a session
    // that crosses its own absolute expires_at between validate_session and
    // this call clamps to `until <= now` — a window already in the past. Do
    // NOT mutate the session or report success for that: no granted audit, no
    // "200 ok" that misleads a scripted caller into believing it holds admin,
    // and no later spurious `role.elevation.expired` for a window that never
    // conferred privilege. The caller (POST /api/v1/elevate) already treats
    // nullopt as "session vanished between validate and elevate" → 401, which
    // is the correct outcome here too.
    if (until <= now)
        return std::nullopt;
    it->second.elevated_until = until;
    // Stamp the max-delta anchor together with elevated_until (auth.hpp
    // is_elevated ceiling, ADR-2002 §4): the granted window `until - now` is
    // already ≤ the caller-clamped duration, so it passes kMaxElevationWindow;
    // the anchor lets that ceiling re-check the invariant on every read.
    it->second.elevation_issued_at = now;
    // The steady deadline is what is_elevated adjudicates against (auth.hpp);
    // set it from the same window (legacy no-store path — this host's clock is
    // the authority, so steady_now + the granted duration).
    it->second.steady_elevated_until =
        std::chrono::steady_clock::now() +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(until - now);
    return until;
}

std::expected<bool, std::string> AuthManager::revoke_elevation(const std::string& token) {
    if (token.size() > auth::kMaxSessionTokenLength)
        return false;
    if (session_store_) {
        const std::string key = hash_token(token);
        // Determine "was elevated" from authoritative state (cache-first), then
        // clear durably. was_elevated distinguishes a real step-down from a
        // no-op for the route's audit.
        std::optional<Session> s;
        {
            std::shared_lock lock(mu_);
            if (auto it = sessions_.find(key); it != sessions_.end())
                s = it->second;
        }
        if (!s) {
            auto found = session_store_->find(key);
            if (!found) {
                // Degraded authoritative read — cannot tell if an elevation is
                // live. Fail closed: do NOT report a successful no-op over a
                // possibly-live durable elevation (adversarial C2).
                note_session_store_degrade("validate");
                return std::unexpected(std::string("session lookup degraded: ") +
                                       found.error().message);
            }
            if (!found->has_value())
                return false; // definitively no such session → genuine no-op
            s = session_from_row(found->value().row, found->value().db_now_ms);
        }
        const bool was_elevated = is_elevated(*s);
        auto r = session_store_->clear_elevation(key);
        if (!r) {
            spdlog::error("revoke_elevation: durable clear failed ({})", r.error().message);
            note_session_store_degrade("invalidate_user");
            // The durable elevation is STILL LIVE — surface the failure so the
            // route fails closed instead of auditing a false revocation.
            return std::unexpected(std::string("durable clear failed: ") + r.error().message);
        }
        std::unique_lock lock(mu_);
        if (auto it = sessions_.find(key); it != sessions_.end()) {
            it->second.elevated_until = {};
            it->second.elevation_issued_at = {};
            it->second.steady_elevated_until = {}; // the field is_elevated reads
        }
        return was_elevated;
    }
    std::unique_lock lock(mu_);
    auto it = sessions_.find(token);
    if (it == sessions_.end())
        return false;
    const bool was_elevated = is_elevated(it->second);
    it->second.elevated_until = {};        // clear → effective role reverts to base
    it->second.elevation_issued_at = {};   // clear the anchor together (auth.hpp)
    it->second.steady_elevated_until = {}; // the field is_elevated reads
    return was_elevated;
}

std::optional<std::string> AuthManager::reap_expired_elevation(const std::string& token) {
    if (token.size() > auth::kMaxSessionTokenLength)
        return std::nullopt;

    if (session_store_) {
        const std::string key = hash_token(token);
        // Cache-cheap: this runs on EVERY authenticated request via
        // resolve_session, AFTER validate_session has populated the cache, so the
        // shared-lock-first / exclusive-recheck dance (below) applies verbatim.
        {
            std::shared_lock lock(mu_);
            auto it = sessions_.find(key);
            if (it == sessions_.end() ||
                it->second.elevated_until.time_since_epoch().count() == 0 ||
                is_elevated(it->second))
                return std::nullopt;
        }
        std::string username;
        {
            std::unique_lock lock(mu_);
            auto it = sessions_.find(key);
            if (it == sessions_.end() ||
                it->second.elevated_until.time_since_epoch().count() == 0 ||
                is_elevated(it->second))
                return std::nullopt; // TOCTOU recheck (single-replica exactly-once)
            username = it->second.username;
            it->second.elevated_until = {};
            it->second.elevation_issued_at = {};
            it->second.steady_elevated_until = {};
        }
        // Mirror the clear durably (bumps the generation → other replicas drop
        // the stale elevation on refresh). Cross-replica exactly-once is NOT
        // guaranteed for this passive-expiry audit — a rare duplicate
        // `role.elevation.expired` is acceptable (effectively-once, ADR-2002);
        // single-replica stays exact via the recheck above. Best-effort: the
        // cache is already cleared so this replica won't re-emit.
        if (auto r = session_store_->clear_elevation(key); !r)
            spdlog::debug("reap_expired_elevation: durable clear failed ({})", r.error().message);
        return username;
    }

    // Shared-lock-first (governance UP-1): this runs on EVERY authenticated
    // cookie request via AuthRoutes::resolve_session, so it must match
    // validate_session's discipline of staying on the shared lock in the
    // overwhelmingly common case (no lapsed elevation to reap) — an
    // unconditional exclusive lock here would reintroduce the full
    // serialisation of dashboard auth on `mu_` that validate_session's
    // need_write dance was built to avoid.
    {
        std::shared_lock lock(mu_);
        auto it = sessions_.find(token);
        if (it == sessions_.end())
            return std::nullopt;
        // Sentinel (epoch) means "never elevated" OR "already reaped/revoked"
        // — nothing to report. Still-live means nothing to report yet either.
        if (it->second.elevated_until.time_since_epoch().count() == 0 ||
            is_elevated(it->second))
            return std::nullopt;
    }

    // A lapsed, non-sentinel elevation was observed — escalate to the
    // exclusive lock to clear it. Re-find and re-check under the new lock
    // (TOCTOU): another thread may have reaped, manually revoked
    // (revoke_elevation / revoke_user_elevations), or invalidated the session
    // entirely between the two locks. The exactly-once / no-double-emit
    // guarantee is preserved by this re-check, not by the shared-lock probe.
    std::unique_lock lock(mu_);
    auto it = sessions_.find(token);
    if (it == sessions_.end())
        return std::nullopt;
    if (it->second.elevated_until.time_since_epoch().count() != 0 && !is_elevated(it->second)) {
        it->second.elevated_until = {};
        it->second.elevation_issued_at = {}; // clear the anchor together (auth.hpp)
        it->second.steady_elevated_until = {};
        return it->second.username;
    }
    return std::nullopt;
}

void AuthManager::expire_session_for_test(const std::string& token, std::chrono::seconds offset) {
    // CACHE-ONLY (both current callers use the legacy no-store AuthManager). Push
    // back BOTH the absolute wall instant (the suspend-backstop / display value)
    // and the steady deadline that validate/is_elevated actually adjudicate
    // against (ADR-2002 §4). A store-backed durable-expiry scenario is exercised
    // by the real reap tests instead, not by re-authoring here (create() authors
    // from now() and cannot stamp an absolute past-expiry).
    const std::string key = session_store_ ? hash_token(token) : token;
    std::unique_lock lock(mu_);
    auto it = sessions_.find(key);
    if (it == sessions_.end())
        return;
    it->second.expires_at -= offset;
    it->second.steady_expires -=
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(offset);
}

void AuthManager::set_role_recheck_race_hook_for_test(std::function<void()> hook) {
    role_recheck_race_hook_for_test_ = std::move(hook);
}

void AuthManager::set_role_recheck_inside_lock_hook_for_test(std::function<void()> hook) {
    role_recheck_inside_lock_hook_for_test_ = std::move(hook);
}

void AuthManager::set_post_mint_race_hook_for_test(std::function<void()> hook) {
    post_mint_race_hook_for_test_ = std::move(hook);
}

std::optional<Role> AuthManager::cached_role_for_test(const std::string& username) const {
    std::shared_lock lock(mu_);
    auto it = users_.find(username);
    if (it == users_.end())
        return std::nullopt;
    return it->second.role;
}

std::optional<std::uint64_t>
AuthManager::cached_role_version_for_test(const std::string& username) const {
    std::shared_lock lock(mu_);
    auto it = users_.find(username);
    if (it == users_.end())
        return std::nullopt;
    return it->second.role_version;
}

std::uint64_t AuthManager::next_role_version_() {
    return role_version_epoch_.fetch_add(1, std::memory_order_relaxed);
}

std::expected<int, std::string> AuthManager::revoke_user_elevations(const std::string& username) {
    if (session_store_) {
        // Durable clear FIRST (bumps the generation → every replica drops the
        // stale elevations on refresh); the store's count is authoritative
        // (sessions may live only on other replicas). Then clear local cache.
        auto r = session_store_->clear_user_elevations(username);
        if (!r) {
            spdlog::error("revoke_user_elevations: durable clear failed ({})", r.error().message);
            note_session_store_degrade("invalidate_user");
            // Elevations may still be live durably — surface so the caller fails
            // closed rather than reporting a successful "0 cleared" (C2).
            return std::unexpected(std::string("durable clear failed: ") + r.error().message);
        }
        std::unique_lock lock(mu_);
        for (auto& [key, s] : sessions_) {
            if (s.username == username) {
                s.elevated_until = {};
                s.elevation_issued_at = {};
                s.steady_elevated_until = {}; // the field is_elevated reads
            }
        }
        return *r;
    }
    std::unique_lock lock(mu_);
    int cleared = 0;
    for (auto& [token, s] : sessions_) {
        if (s.username == username && is_elevated(s)) {
            s.elevated_until = {};
            s.elevation_issued_at = {};    // clear the anchor together (auth.hpp)
            s.steady_elevated_until = {}; // the field is_elevated reads
            ++cleared;
        }
    }
    return cleared;
}

std::optional<Session> AuthManager::validate_session(const std::string& token) const {
    // Reject overly-long tokens early to prevent DoS via map key exhaustion (#630).
    // This check intentionally fires BEFORE the mutex acquire below — rejecting
    // obviously invalid tokens without contention reduces lock contention under
    // token-spray attacks.
    if (token.size() > auth::kMaxSessionTokenLength)
        return std::nullopt;

    const bool idle_enabled = session_inactivity_ > std::chrono::seconds(0);

    // HA WS-1/1a: durable sessions take the store-backed path (cache + Postgres).
    // A store-less deployment (config-file-only, most unit tests) keeps the
    // legacy in-memory body below, byte-for-byte.
    if (session_store_)
        return validate_session_durable(token, idle_enabled);

    std::shared_lock lock(mu_);

    auto it = sessions_.find(token);
    if (it == sessions_.end())
        return std::nullopt;

    auto now = std::chrono::system_clock::now();
    if (now > it->second.expires_at) // absolute lifetime — always enforced
        return std::nullopt;

    // Idle (inactivity) timeout (SOC 2 CC6.3): a sliding window UNDER the
    // absolute expiry. Decided here, BEFORE the touch below, so an active
    // session is kept alive while one idle past the window is rejected.
    const bool idle_expired =
        idle_enabled && (now - it->second.last_activity_at > session_inactivity_);

    // Throttle the in-memory touch (governance UP-1/UP-2). Sliding the window
    // needs the exclusive lock, so touching on EVERY request would serialise all
    // dashboard auth on `mu_` once the feature is on. Instead we slide it at most
    // once per `touch_granularity`, so a burst of requests for an active session
    // stays on the shared lock. The granularity is a quarter of the idle window
    // capped at 30s, so `last_activity_at` never lags real activity by more than
    // that — far inside any minutes-scale window — and an active session can
    // therefore never be wrongly evicted (it is always re-touched well before the
    // window elapses; idle-out fires within [window - granularity, window] of the
    // last request). Sub-4s windows floor the granularity at 0 → touch every
    // request (test/degenerate windows; correctness preserved, no throttle gain).
    // (std::min) is parenthesised to dodge the `min` function-like macro that
    // <windows.h> leaks on MSVC (without it: C2589 "illegal token '(' on right
    // side of '::'"). Portable; a no-op elsewhere.
    const auto touch_granularity =
        idle_enabled ? (std::min)(session_inactivity_ / 4, std::chrono::seconds(30))
                     : std::chrono::seconds(0);
    const bool need_touch = idle_enabled && !idle_expired &&
                            (now - it->second.last_activity_at >= touch_granularity);

    // Copy the session BEFORE any lock manipulation to avoid a dangling
    // iterator after the erase/reap below.
    auto session_copy = it->second;

    // Take the exclusive lock ONLY when something must change: evict an idle
    // session, slide the (throttled) activity window, or run the large-map
    // opportunistic reap. The common cases — idle disabled, or an active session
    // already touched within the granularity — stay on the shared lock with no
    // serialisation (UP-1) and no O(N) sweep (UP-2).
    const bool need_write = idle_expired || need_touch || sessions_.size() > 100;
    if (need_write) {
        lock.unlock();
        std::unique_lock wlock(mu_);
        auto wnow = std::chrono::system_clock::now();

        // Opportunistic reap (G2-SEC-A1-004), extended to drop idle sessions
        // when the feature is on. Runs on the large map (pre-existing cadence)
        // and, when idle is enabled, whenever we already hold the lock to
        // touch/evict — so idle sessions stay bounded without a per-request
        // O(N) sweep.
        if (sessions_.size() > 100 || (idle_enabled && (need_touch || idle_expired))) {
            std::erase_if(sessions_, [&](const auto& p) {
                if (wnow > p.second.expires_at)
                    return true;
                return idle_enabled && (wnow - p.second.last_activity_at > session_inactivity_);
            });
        }

        if (idle_expired) {
            // The reap above already removed THIS session if it is still idle
            // under the write lock (the predicate re-reads last_activity with a
            // fresh `wnow`, so a concurrent boundary refresh keeps it alive).
            // Either way this request, which observed it idle, is rejected —
            // fails safe (a spurious 401 → the browser re-authenticates).
            return std::nullopt;
        }

        if (need_touch) {
            // Slide the window forward. Throttle the durable AuthDB mirror to at
            // most one write per kActivityPersistGranularity so the touch is not
            // a per-request SQL write.
            if (auto wit = sessions_.find(token); wit != sessions_.end()) {
                wit->second.last_activity_at = wnow;
                session_copy.last_activity_at = wnow;
                if (auth_db_ && wnow - wit->second.last_activity_persisted_at >=
                                    kActivityPersistGranularity) {
                    wit->second.last_activity_persisted_at = wnow;
                    session_copy.last_activity_persisted_at = wnow;
                }
            } else {
                // Raced an evict/invalidate between the two locks → reject.
                return std::nullopt;
            }
        }
        wlock.unlock();
    }

    return session_copy;
}

std::optional<Session> AuthManager::validate_session_durable(const std::string& token,
                                                             bool idle_enabled) const {
    // Refresh cross-replica cache coherence BEFORE consulting the cache: a
    // create/invalidate/elevate/mfa mutation on any replica advances the durable
    // generation, which clears this replica's now-stale cache.
    maybe_refresh_session_generation();

    const std::string key = hash_token(token);

    // 1. Cache-first (shared lock) — but ONLY when the generation view is fresh
    // enough to trust. Past the stale-serve bound (a sustained refresh outage),
    // a cache hit is discarded so we go authoritative below (rbac_store pattern,
    // blocker #2): this bounds how long a revoked/demoted/elevated session can
    // ride a stale cache during a PG brownout to ~kSessionGenStaleServeBoundMs
    // rather than its 8h absolute expiry.
    std::optional<Session> session_copy;
    if (!session_generation_view_stale()) {
        std::shared_lock lock(mu_);
        if (auto it = sessions_.find(key); it != sessions_.end())
            session_copy = it->second;
    }

    // 2. Cache miss (or a distrusted stale cache) → authoritative store lookup.
    bool from_store = false;
    if (!session_copy) {
        auto found = session_store_->find(key);
        if (!found) {
            // Authoritative read degraded. Never silently grant, and there is
            // nothing cached to stale-serve for a token this replica has not
            // seen — fail the request (401 → client re-auths). A session minted
            // on THIS replica is in the cache and never reaches here on a blip.
            spdlog::warn("validate_session: durable session lookup degraded ({})",
                         found.error().message);
            note_session_store_degrade("validate");
            return std::nullopt;
        }
        if (!found->has_value())
            return std::nullopt; // definitively absent
        // Adjudicate against the DB clock at read time (db_now) — session_from_row
        // derives the local monotonic deadlines from it, so a backward-skewed
        // replica cannot accept an expired session on a cache miss (design-review
        // B1). An already-expired-at-db_now row derives a {} steady_expires,
        // rejected by step 3.
        session_copy = session_from_row(found->value().row, found->value().db_now_ms);
        from_store = true;
    }

    // Adjudication uses the LOCAL MONOTONIC deadlines derived at populate (immune
    // to local wall skew/steps), with the generous wall ceiling as the suspend
    // backstop (steady_clock pauses across host suspend; ADR-2002 §4 / H5).
    const auto steady_now = std::chrono::steady_clock::now();
    const auto wall_now = std::chrono::system_clock::now();
    const auto expired_now = [&](const Session& sc) {
        // A {} steady_expires (expired at populate, or underived) reads as expired.
        return steady_now >= sc.steady_expires ||
               wall_now > sc.expires_at + kWallSanitySkew;
    };

    // 3. Absolute lifetime — always enforced.
    if (expired_now(*session_copy)) {
        if (!from_store) { // drop a stale cache entry
            std::unique_lock wlock(mu_);
            sessions_.erase(key);
        }
        return std::nullopt;
    }

    // 4. Idle (inactivity) timeout: a sliding window under the absolute expiry,
    // aged on the monotonic idle anchor.
    bool idle_expired =
        idle_enabled && (steady_now - session_copy->steady_last_activity > session_inactivity_);
    if (idle_expired && !from_store) {
        // A cache-hit idle anchor can lag a touch that landed on another replica
        // (touch does NOT bump the generation, so the cache is not cleared for
        // it). Re-check the authoritative row before evicting, so an
        // active-elsewhere session is not falsely idled out. On a degraded
        // re-check keep the cache-derived verdict (fail-safe: a spurious 401 →
        // re-auth, never a false keep-alive).
        if (auto found = session_store_->find(key); found && found->has_value()) {
            session_copy = session_from_row(found->value().row, found->value().db_now_ms);
            from_store = true;
            if (expired_now(*session_copy))
                return std::nullopt;
            idle_expired =
                idle_enabled &&
                (std::chrono::steady_clock::now() - session_copy->steady_last_activity >
                 session_inactivity_);
        }
    }
    if (idle_expired) {
        // Evict from the local cache only — the durable row is left for the
        // absolute-expiry reaper; every replica independently derives idle
        // expiry from last_activity. Fails safe.
        std::unique_lock wlock(mu_);
        sessions_.erase(key);
        return std::nullopt;
    }

    // 5. Slide the activity window (throttled), mirror it durably, and (re)cache.
    const auto touch_granularity =
        idle_enabled ? (std::min)(session_inactivity_ / 4, std::chrono::seconds(30))
                     : std::chrono::seconds(0);
    const bool need_touch =
        idle_enabled && (steady_now - session_copy->steady_last_activity >= touch_granularity);
    if (need_touch) {
        session_copy->steady_last_activity = steady_now; // activity is now (monotonic)
        session_copy->last_activity_at = wall_now;       // keep the wall value in sync
        // Durable mirror, throttled to kActivityPersistGranularity. touch_activity
        // deliberately does NOT bump the generation, so it never invalidates any
        // replica's cache — the whole point of a sliding update being cheap. It
        // stamps now() in the store (the DB clock). The throttle rides the LOCAL
        // MONOTONIC clock (steady_last_persisted), NOT wall vs a DB-authored
        // timestamp: that cross-domain comparison let host skew suppress every
        // touch, idling out an actively-used session on another replica / after
        // failover (adversarial-review CDX-P1-001) — the exact cross-host-skew
        // contract WS-1/1a exists to close. Clamp the interval strictly below the
        // idle window (half it) so the durable row is never staler than the window
        // a cache-cold replica ages it against (C5/K10).
        const auto durable_persist_gran =
            idle_enabled ? (std::min)(kActivityPersistGranularity, session_inactivity_ / 2)
                         : kActivityPersistGranularity;
        if (steady_now - session_copy->steady_last_persisted >= durable_persist_gran) {
            session_copy->steady_last_persisted = steady_now;
            session_copy->last_activity_persisted_at = wall_now; // display only
            if (auto r = session_store_->touch_activity(key); !r) {
                spdlog::debug("validate_session: durable touch_activity failed ({})",
                              r.error().message);
                note_session_store_degrade("touch");
            }
        }
    }
    {
        std::unique_lock wlock(mu_);
        sessions_[key] = *session_copy;
    }
    return session_copy;
}

bool AuthManager::invalidate_session(const std::string& token) {
    const std::string key = session_store_ ? hash_token(token) : token;
    bool db_persisted = true;
    if (session_store_) {
        // Durable delete FIRST (bumps the generation so every replica drops its
        // cached copy on the next refresh), then the local cache erase for
        // immediacy. On a store error the local cache is still erased (the
        // operator's "sign out NOW" intent is honored on THIS replica), but
        // db_persisted=false is returned so the caller does NOT report a clean
        // logout: the durable row survives, and validate_session_durable
        // rehydrates a valid Session from it on a cache miss (another replica,
        // or a copied cookie) — the exact fail-open (adversarial-round blocker
        // #3) this return closes. reap_expired only deletes by absolute expiry,
        // so an un-deleted row is NOT swept early.
        if (auto r = session_store_->invalidate(key); !r) {
            spdlog::error("invalidate_session: durable delete failed ({})", r.error().message);
            note_session_store_degrade("invalidate");
            db_persisted = false;
        }
    }
    std::unique_lock lock(mu_);
    sessions_.erase(key);
    return db_persisted;
}

AuthManager::RevokeResult
AuthManager::invalidate_user_sessions(const std::string& username) {
    // Lock-ordering: AuthDB call OUTSIDE mu_, then take mu_ for the
    // in-memory erase. Same pattern as remove_user and update_role.
    //
    // Failure tolerance INTENTIONALLY DIFFERS from remove_user/update_role.
    // Those abort on DB write failure because removing a user is a
    // strictly-ordered durability operation: if the DB doesn't accept
    // the change, the in-memory cache must not diverge or the server's
    // first restart silently resurrects the deleted user. Revocation is
    // different — the operator's mental model is "kill this session NOW",
    // and the in-memory wipe IS the operationally-critical step (the
    // active cookie validating against `sessions_` stops working
    // immediately). We therefore wipe in-memory even on DB failure but
    // surface `db_persisted=false` so the caller can audit the partial
    // outcome and the operator knows to retry or restart.
    if (session_store_) {
        // Durable delete FIRST (bumps the generation → every replica drops the
        // cached copies on its next refresh). On success the store's count is
        // the fleet-wide total killed; on failure fall back to this replica's
        // local-erase count so the number is never falsely 0 while db_persisted
        // truthfully reports the partial outcome (Gate 6 COMPL-H1 / authdb-H1 /
        // UP-3). The local cache is wiped either way — the "kill NOW" intent is
        // honored on this replica even on a store error.
        bool db_persisted = true;
        std::size_t count = 0;
        if (auto r = session_store_->invalidate_user(username)) {
            count = static_cast<std::size_t>(*r);
        } else {
            db_persisted = false;
            spdlog::error("invalidate_user_sessions: durable delete failed ({})",
                          r.error().message);
            note_session_store_degrade("invalidate_user"); // parity with wipe/other sites
        }
        std::unique_lock lock(mu_);
        const auto before = sessions_.size();
        std::erase_if(sessions_,
                      [&](const auto& pair) { return pair.second.username == username; });
        if (!db_persisted)
            count = before - sessions_.size();
        return RevokeResult{count, db_persisted};
    }

    bool db_persisted = true;
    std::unique_lock lock(mu_);
    const auto before = sessions_.size();
    std::erase_if(sessions_, [&](const auto& pair) {
        return pair.second.username == username;
    });
    return RevokeResult{before - sessions_.size(), db_persisted};
}

// ── User management ─────────────────────────────────────────────────────────

bool AuthManager::has_users() const {
    std::shared_lock lock(mu_);
    return !users_.empty();
}

bool AuthManager::is_auth_db_ok() const noexcept {
    // Legacy config-file-only deployments leave auth_db_ as nullptr.
    // That is not a /readyz failure — the readyz check should report ok
    // unless the operator opted into AuthDB and the DB is unhealthy.
    if (!auth_db_) {
        return true;
    }
    return auth_db_->is_ready();
}

std::vector<UserEntry> AuthManager::list_users() const {
    if (auth_db_) {
        auto result = auth_db_->list_users();
        if (result) {
            return *result;
        }
        // Fall through to in-memory on error
        spdlog::warn("AuthDB list_users failed, falling back to in-memory");
    }

    std::shared_lock lock(mu_);
    std::vector<UserEntry> out;
    out.reserve(users_.size());
    for (const auto& [_, e] : users_) {
        out.push_back(e);
    }
    return out;
}

bool AuthManager::upsert_user(const std::string& username, const std::string& password, Role role) {
    if (password.size() < 12)
        return false; // minimum password length (G2-SEC-A1-003)
    auto salt = random_bytes(16);
    auto salt_hex = bytes_to_hex(salt);
    auto hash = pbkdf2_sha256(password, salt, kPbkdf2Iterations);

    if (auth_db_) {
        // Use AuthDB for persistence
        auto result = auth_db_->upsert_user(username, hash, salt_hex, role);
        if (!result) {
            spdlog::error("AuthDB upsert_user failed for '{}'", username);
            return false;
        }
    }

    std::unique_lock lock(mu_);
    // Check if role is changing for an existing user
    auto it = users_.find(username);
    bool role_changed = it != users_.end() && it->second.role != role;

    UserEntry entry;
    entry.username = username;
    entry.role = role;
    entry.salt_hex = salt_hex;
    entry.hash_hex = hash;
    // Gate 5 CH-1 re-review follow-up: a process-wide stamp, not a carried-
    // forward per-username counter - see UserEntry::role_version's doc for why
    // a per-username scheme (this call's first shape) still let the wholesale
    // entry-replace below reopen the ABA hole through remove_user()+
    // reactivate_user()/a cold re-hydrate, which reset the OLD counter to 0.
    entry.role_version = next_role_version_();
    users_[username] = std::move(entry);

    if (role_changed) {
        // Invalidate sessions so the user picks up the new role on next login
        // Prevents stale session role from granting old privileges (G4-CON-AUTH-001)
        std::erase_if(sessions_,
                      [&](const auto& pair) { return pair.second.username == username; });
    }
    lock.unlock(); // release before durable I/O and save_config (both take their own locks)

    // Mirror the wipe durably so the stale-role session cannot survive on another
    // replica or across a restart (no-op without a session store). Fail closed on
    // a durable-wipe error — the local cache erase above is only eviction in store
    // mode, so a failed durable delete would leave the old-role session live.
    //
    // RETRY-SAFETY CAVEAT (security-guardian Gate 8, LOW/latent): unlike
    // update_role/remove_user — which re-attempt the wipe unconditionally on a
    // retry — this path recomputes `role_changed` against the NOW-mutated in-memory
    // role, so a retry after a wipe failure sees role_changed=false and skips the
    // wipe. That is safe today ONLY because no production path demotes via
    // upsert_user (dashboard create 409s on a dup username; role edits route
    // through update_role; SCIM upserts at a fixed Role::user). A future
    // demote-via-upsert MUST recompute role_changed against the durable/DB row (or
    // wipe unconditionally) before relying on retry to converge.
    if (role_changed && !wipe_user_sessions_durable(username))
        return false;

    // Only save config file if NOT using DB (backwards compat)
    if (!auth_db_)
        save_config();

    return true;
}

bool AuthManager::remove_user(const std::string& username) {
    if (auth_db_) {
        auto result = auth_db_->remove_user(username);
        if (!result) {
            spdlog::error("AuthDB remove_user failed for '{}'", username);
            return false;
        }

        // In-memory cache/session cleanup is a best-effort side effect only —
        // it must NOT gate the return value. On a cold-booted server users_
        // may never have been warmed for this username even though the DB row
        // existed and was just soft-deleted; returning the cache-erase result
        // in that case falsely reports failure (SCIM deprovision fail-closed
        // 500 loop on restart). The DB write is authoritative.
        std::unique_lock lock(mu_);
        users_.erase(username);
        // Invalidate all active sessions belonging to this user
        // to prevent deleted users from retaining access (CHAOS-T1-001)
        std::erase_if(sessions_,
                      [&](const auto& pair) { return pair.second.username == username; });
        lock.unlock();
        // Fail closed on a durable-wipe error (see wipe_user_sessions_durable):
        // a removed user's sessions must not survive because the durable delete
        // was lost — the operator retries (invalidate_user is idempotent).
        if (!wipe_user_sessions_durable(username))
            return false;

        return *result;
    }

    std::unique_lock lock(mu_);
    auto erased = users_.erase(username) > 0;
    if (erased) {
        // Invalidate all active sessions belonging to this user
        // to prevent deleted users from retaining access (CHAOS-T1-001)
        std::erase_if(sessions_,
                      [&](const auto& pair) { return pair.second.username == username; });
    }

    lock.unlock();
    if (erased && !wipe_user_sessions_durable(username)) // no-op (true) w/o store
        return false;
    save_config();

    return erased;
}

bool AuthManager::reactivate_user(const std::string& username) {
    // No AuthDB, no soft-delete to reverse — config-file-only deployments
    // never set is_active=0 in the first place (remove_user() there just
    // erases the in-memory/config entry outright).
    if (!auth_db_) {
        spdlog::error("AuthManager::reactivate_user: no AuthDB configured for '{}'", username);
        return false;
    }

    // DB write FIRST, outside mu_ — mirrors remove_user/update_role's lock
    // ordering: the durable row is authoritative, the in-memory map is a
    // read-optimization layered on top, never the other way around.
    auto result = auth_db_->reactivate_user(username);
    if (!result) {
        spdlog::error("AuthDB reactivate_user failed for '{}'", username);
        return false;
    }

    // remove_user() erased this username from users_; re-read the REAL row
    // (role/credential-hash/identity_source) from AuthDB rather than
    // synthesizing a stale entry, so get_user_role/list_users reflect the
    // reactivated account immediately rather than only after a fresh login.
    auto entry = auth_db_->get_user(username);
    if (!entry) {
        spdlog::error("AuthManager::reactivate_user: AuthDB reactivated '{}' but the row could "
                      "not be re-read afterward",
                      username);
        return false;
    }

    // Gate 5 CH-1 re-review follow-up (cpp-safety + cpp-expert, converged
    // independently): AuthDB::get_user() has no knowledge of role_version, so
    // `*entry` defaults it to 0 - a wholesale entry-replace exactly like
    // upsert_user()'s, and needs the same process-wide stamp for the same
    // reason: every writer pairs `.role`/`.role_version` together (an
    // invariant #4107's row-locking rewrite still relies on for cache
    // write-ordering, even though nothing compares this value for
    // correctness anymore - see UserEntry::role_version's doc).
    entry->role_version = next_role_version_();

    std::unique_lock lock(mu_);
    users_[username] = *entry;
    return true;
}

std::optional<Role> AuthManager::get_user_role(const std::string& username) const {
    // Gate 3 governance BLOCKING finding (cpp-safety), fix shape confirmed via
    // Sol/codex opine: this was a pure `users_` cache read with NO AuthDB
    // fallback at all - completely independent of authenticate()/
    // verify_password(), which #4020's other fixes never reach from here.
    // `auth_routes.cpp`'s legacy API-token session synthesis calls this
    // EVERY request (`synth.role = get_user_role(principal_id).value_or(user)`)
    // - its own adjacent (pre-existing, not written by this change) comment
    // already asserts the intent ("queries the current role on every call, so
    // a creator who's been demoted... will produce a user-role session"),
    // which the cache-only implementation never actually delivered. A
    // DEMOTED user's still-valid token (tokens are NOT revoked on a role
    // change, by design - the documented contract is "inherits the creator's
    // CURRENT role", not "frozen at mint time") kept resolving to their
    // pre-demotion role indefinitely on any manager whose cache was ever
    // warmed for that username.
    //
    // (Removal is a narrower residual: production's actual user-deletion
    // paths - the dashboard DELETE and SCIM deprovision, both via
    // deprovision_revoke.hpp/ADR-2001 - already revoke a removed principal's
    // API tokens credentials-FIRST, before AuthManager::remove_user() is ever
    // called, so a removed user's token already fails validation before
    // reaching this method in production. This fix does not depend on that
    // and also covers removal for any future/direct caller of remove_user()
    // that bypasses the orchestrator.)
    //
    // Fix: when AuthDB is configured, this is now ALWAYS authoritative - no
    // cache read, no cache fallback on a miss or a store error (falling back
    // to `users_` on a DB error would silently reopen the exact stale-
    // privilege gap this exists to close, the one time it matters most:
    // while the store degrades). `users_`/`mu_` need no change - a `const`
    // method may freely call through the already-non-const-pointee `AuthDB*`.
    // Config-file mode (no `auth_db_`) is unchanged: the cache IS the truth
    // there, exactly as before.
    //
    // Cost (deliberately accepted for this P0, not silently overlooked): an
    // unconditional PG round-trip on every legacy-API-token-authenticated
    // request - this repo's session/token validation paths use generation-
    // gated or TTL caches specifically to avoid this class of cost, and this
    // method does not. A per-entry TTL was considered and rejected here: it
    // would convert a correctness BLOCKING closure into an explicitly-
    // accepted stale-privilege window, and adds refresh/single-flight/outage
    // semantics not worth inventing under this fix's time budget. If
    // profiling later shows this cost matters, the durable answer is a
    // generation-gated cache modeled on SessionStore/RbacStore (~1s
    // propagation, single-flight refresh, mutation-time generation bump) -
    // not a bare TTL.
    if (auth_db_) {
        auto db_user = auth_db_->get_user(username);
        if (!db_user) {
            // Gate 3 re-review follow-up (cpp-expert + authdb, converged): log
            // a genuine store error distinctly from a plain not-found, so a PG
            // outage that silently floors every legacy-token session to
            // Role::user (auth_routes.cpp's `.value_or(Role::user)`) leaves an
            // operational trail instead of zero diagnostic signal - mirrors
            // find_user_or_hydrate's own UserNotFound-vs-DbError split in this
            // same file.
            // Gate 2/4 re-review follow-up (security-guardian + authdb,
            // converged): InvalidUsername (get_user()'s own input-validation
            // rejection, #2755e3871) is a rejected-shape input, not a store
            // health signal - bucket it with UserNotFound so a real attack
            // attempt is never logged as a false store-error, masking a
            // genuine outage during exactly that attack.
            if (db_user.error() != yuzu::server::AuthDBError::UserNotFound &&
                db_user.error() != yuzu::server::AuthDBError::InvalidUsername) {
                spdlog::error("get_user_role: AuthDB lookup for '{}' failed (store error, not "
                             "a genuine miss) - returning nullopt",
                             username);
                // Gate 5 chaos-injector CH-3/UP-6 follow-up: a log line alone is
                // invisible exactly while the store is already stressed (the
                // scenario that matters). This is the ONLY caller-visible signal
                // that auth_routes.cpp's `.value_or(Role::user)` is about to
                // floor a legacy-token-authenticated request's role down - narrows
                // the observability gap; the honest fix (this call returning
                // std::expected so callers can distinguish "not found" from
                // "store degraded" and respond accordingly, e.g. 503 instead of a
                // silent floor) touches 6 call sites and is a follow-up, not this
                // metric.
                if (metrics_)
                    metrics_->counter("yuzu_auth_get_user_role_store_error_total").increment();
            }
            return std::nullopt;
        }
        return db_user->role;
    }
    std::shared_lock lock(mu_);
    auto it = users_.find(username);
    if (it == users_.end())
        return std::nullopt;
    return it->second.role;
}

bool AuthManager::update_role(const std::string& username, Role new_role) {
    if (auth_db_) {
        auto result = auth_db_->update_role(username, new_role);
        if (!result) {
            spdlog::error("AuthDB update_role failed for '{}'", username);
            return false;
        }

        // In-memory cache/session cleanup is a best-effort side effect only —
        // it must NOT gate the return value. On a cold-booted server users_
        // may never have been warmed for this username even though the DB row
        // existed and was just updated; returning the cache-lookup result in
        // that case falsely reports failure (e.g. an unaudited SCIM role
        // recompute after restart). The DB write is authoritative — same
        // pattern as remove_user.
        std::unique_lock lock(mu_);
        auto it = users_.find(username);
        if (it != users_.end()) {
            it->second.role = new_role;
            it->second.role_version = next_role_version_(); // keeps .role/.role_version paired - see UserEntry::role_version's doc
        }

        // Invalidate sessions so the user picks up the new role on next login
        // Prevents stale session role from granting old privileges
        std::erase_if(sessions_,
                      [&](const auto& pair) { return pair.second.username == username; });
        lock.unlock();
        // Fail closed on a durable-wipe error — a demoted user's higher-role
        // session must not survive a lost durable delete (see the helper).
        if (!wipe_user_sessions_durable(username))
            return false;

        return true;
    }

    std::unique_lock lock(mu_);
    auto it = users_.find(username);
    if (it == users_.end()) {
        return false;
    }
    it->second.role = new_role;
    it->second.role_version = next_role_version_(); // keeps .role/.role_version paired, same as the AuthDB-backed branch above

    // Invalidate sessions so the user picks up the new role on next login
    // Prevents stale session role from granting old privileges
    std::erase_if(sessions_, [&](const auto& pair) { return pair.second.username == username; });

    lock.unlock();
    if (!wipe_user_sessions_durable(username)) // no-op (true) w/o store
        return false;
    save_config();

    return true;
}

// ── Shared group→role resolution ────────────────────────────────────────────

Role resolve_role_from_groups(const std::vector<std::string>& groups,
                              const std::string& admin_group) {
    // Determine role: admin if the caller's IdP-attested groups contain the
    // configured admin group. Security (C3 fix, later mirrored for SAML):
    // admin role ONLY through explicit group membership. Do NOT match on
    // email/display_name/NameID — these are attacker-controlled values that
    // ride in the same claims/assertion.
    Role role = Role::user;
    if (!admin_group.empty()) {
        for (const auto& gid : groups) {
            if (gid == admin_group) {
                role = Role::admin;
                break;
            }
        }
    }
    return role;
}

// ── OIDC session creation ───────────────────────────────────────────────────

std::string AuthManager::create_oidc_session(const std::string& display_name,
                                             const std::string& email, const std::string& oidc_sub,
                                             const std::string& iss,
                                             const std::vector<std::string>& groups,
                                             const std::string& admin_group_id,
                                             std::chrono::system_clock::time_point mfa_verified_at) {
    Role role = resolve_role_from_groups(groups, admin_group_id);

    // #1837 — the STABLE authorization principal is `iss` + `sub`, never a
    // display name. `sub` is only guaranteed unique per-issuer (RFC 7519),
    // and a display name is a mutable, IdP-editable label two users can
    // share — keying on it let two same-named users collide onto one
    // principal, which #1832's RBAC reconcile then makes destructive
    // (one user's login can delete the other's group memberships).
    // ADR-2001 §5 — built through the single shared helper (never hand-built
    // here) so a future deprovision-time resolver reconstructing this same
    // string cannot silently drift from the mint site.
    const std::string stable_username = yuzu::server::oidc::oidc_principal_id(iss, oidc_sub);
    const std::string resolved_display = display_name.empty() ? email : display_name;

    auto token = generate_session_token();
    yuzu::server::SessionWriteParams params;
    params.username = stable_username;
    params.display_name = resolved_display;
    params.role = role_to_string(role);
    params.auth_source = "oidc";
    params.oidc_sub = oidc_sub;
    params.session_lifetime_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(kSessionDuration).count();
    // The MFA proof is the IdP's asserted instant (an absolute, not a local
    // authoring) — pass it through; the epoch sentinel maps to 0 (no proof).
    params.mfa_verified_ms_abs = ms_from_tp(mfa_verified_at);
    if (!persist_new_session(token, params)) {
        spdlog::error("create_oidc_session: durable persist failed for '{}'", stable_username);
        return {}; // fail-safe empty token (ADR-0007)
    }

    spdlog::info("OIDC session created for '{}' (display={}, email={}, sub={}, role={})",
                 stable_username, resolved_display, email, oidc_sub, role_to_string(role));
    return token;
}

// #1852 — see the header doc for the fail-soft / lock-ordering contract.
void AuthManager::provision_sso_identity(const std::string& principal, const std::string& iss,
                                         const std::string& sub,
                                         const std::string& display_name) {
    if (!auth_db_) {
        // Legacy config-file-only deployment — no durable store to
        // provision into. Not an error: elevation is unreachable for this
        // deployment mode regardless (POST /api/v1/elevate 503s without
        // auth_db_ptr()).
        return;
    }
    auto result = auth_db_->upsert_sso_identity(principal, iss, sub, display_name, "oidc");
    if (!result) {
        spdlog::warn("provision_sso_identity failed for '{}': error={} (login proceeds; this "
                     "principal cannot elevate until a future login provisions it)",
                     principal, static_cast<int>(result.error()));
        return;
    }
    // governance round (sec-LOW/UP-5) — observable IdP-provisioning volume.
    // Every successful login re-runs this upsert (it is also the re-login
    // refresh path, not just first-provision), so a sustained spike is a
    // signal worth alerting on: either a legitimate onboarding wave or an
    // IdP-side provisioning flood/credential-stuffing sweep against the SSO
    // login path.
    if (metrics_) {
        metrics_->counter("yuzu_auth_sso_provision_total", {{"source", "oidc"}}).increment();
    }
}

// ── SAML session creation ───────────────────────────────────────────────────

std::string AuthManager::create_saml_session(const std::string& name_id,
                                             const std::string& entity_id,
                                             const std::vector<std::string>& groups,
                                             const std::string& admin_group,
                                             const std::string& saml_display_name,
                                             const std::string& saml_email) {
    // NB (HA WS-1/1a rebase): no top-level `mu_` lock here — the write-through
    // goes through persist_new_session(), which takes `mu_` internally; a
    // top-level lock would deadlock it. The SAML display-name/email params are
    // dev's #3698 attribute-parsing feature, merged with this store integration.
    // ADR-2001 PR4a — the STABLE authorization principal is
    // `saml_principal_id(entity_id, name_id)`, mirroring #1837's OIDC split
    // exactly (`oidc_principal_id(iss, sub)`): a NameID is only guaranteed
    // unique per-IdP, so a bare NameID is unsafe as the durable RBAC/session
    // key (SAML doesn't sync to rbac_store yet, so the display-name-
    // collision risk #1837 closes for OIDC is still dormant here — see
    // docs/auth-architecture.md "Stable principal vs. display name" — but
    // the cross-IdP NameID-reuse risk this closes is live from PR4a
    // onward). `username` becomes the stable principal; `display_name`
    // stays the raw NameID (human-readable rendering only). Built through
    // the single shared builder (saml_principal.hpp) — never hand-built
    // here — so a future deprovision-time resolver reconstructing this same
    // string cannot silently drift from this mint site
    // (deprovision_revoke.cpp).
    Role role = resolve_role_from_groups(groups, admin_group);

    const std::string stable_username = yuzu::server::saml::saml_principal_id(entity_id, name_id);

    // Display-name derivation mirrors OIDC's `create_oidc_session` exactly:
    // prefer the parsed name attribute, else the parsed email, else the raw
    // NameID (the pre-attributes behaviour, so a SAML deployment that never
    // configures --saml-name-attribute/--saml-email-attribute renders exactly
    // as before). `display_name` is UI/audit-detail only, NEVER authz
    // (auth.hpp Session contract), and `saml_email` — like OIDC — is used only
    // as a display fallback + logged, never stored as a durable session field.
    const std::string resolved_display =
        !saml_display_name.empty() ? saml_display_name
                                   : (!saml_email.empty() ? saml_email : name_id);

    auto token = generate_session_token();
    yuzu::server::SessionWriteParams params;
    params.username = stable_username;
    params.display_name = resolved_display;
    params.role = role_to_string(role);
    params.auth_source = "saml";
    params.session_lifetime_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(kSessionDuration).count();
    if (!persist_new_session(token, params)) {
        spdlog::error("create_saml_session: durable persist failed for '{}'", stable_username);
        return {}; // fail-safe empty token (ADR-0007)
    }

    spdlog::info("SAML session created for '{}' (display={}, email={}, role={})", stable_username,
                 resolved_display, saml_email, role_to_string(role));
    return token;
}

// ── Enrollment tokens (Tier 2) ──────────────────────────────────────────────

std::string AuthManager::sha256_hex(const std::string& input) {
    // Reuse PBKDF2 with 1 iteration and empty salt for a simple SHA-256 hash.
    // This is fine for token hashing (tokens are already high-entropy).
    constexpr int kKeyLen = 32;
    std::vector<uint8_t> derived(kKeyLen);

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed for SHA-256");
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptCreateHash failed");
    }

    status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                            static_cast<ULONG>(input.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptHashData failed");
    }

    status = BCryptFinishHash(hHash, derived.data(), static_cast<ULONG>(derived.size()), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptFinishHash failed");
    }
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, derived.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP SHA-256 digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif

    return bytes_to_hex(derived);
}

std::string AuthManager::create_enrollment_token(const std::string& label, int max_uses,
                                                 std::chrono::seconds ttl) {
    // Generate a high-entropy raw token
    auto raw_bytes = random_bytes(32);
    auto raw_token = bytes_to_hex(raw_bytes);

    // Hash it for storage (we never store the raw token)
    auto hash = sha256_hex(raw_token);

    // Token ID = first 8 hex chars of the hash (for display/admin reference)
    auto token_id = hash.substr(0, 8);

    auto now = std::chrono::system_clock::now();

    EnrollmentToken et;
    et.token_id = token_id;
    et.token_hash = hash;
    et.label = label;
    et.max_uses = max_uses;
    et.use_count = 0;
    et.created_at = now;
    et.expires_at = (ttl.count() == 0) ? (std::chrono::system_clock::time_point::max)() : now + ttl;
    et.revoked = false;

    {
        std::unique_lock lock(mu_);
        enrollment_tokens_[token_id] = std::move(et);
    }

    save_tokens();

    spdlog::info("Enrollment token created: id={}, label='{}', max_uses={}, ttl={}s", token_id,
                 label, max_uses, ttl.count());
    return raw_token;
}

std::vector<std::string>
AuthManager::create_enrollment_tokens_batch(const std::string& label_prefix, int count,
                                            int max_uses_each, std::chrono::seconds ttl) {
    std::vector<std::string> tokens;
    tokens.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
        auto label = label_prefix.empty() ? std::format("batch-{}", i + 1)
                                          : std::format("{}-{}", label_prefix, i + 1);
        tokens.push_back(create_enrollment_token(label, max_uses_each, ttl));
    }
    spdlog::info("Batch created {} enrollment tokens (prefix='{}')", count, label_prefix);
    return tokens;
}

bool AuthManager::validate_enrollment_token(const std::string& raw_token) {
    // W1.4 R2 / UP-H2: read-only observability check. The W1.4 PR1 pass
    // of this wrapper silently delegated to consume_enrollment_token,
    // which burned a use on every call — a semantic break with the
    // function name and the doc comment ("validate, not consume"). A
    // caller checking "is this token still usable?" would unintentionally
    // exhaust a max_uses=1 token. The behaviour was acceptable in PR1
    // because the only callers were tests asserting the exhaustion
    // behaviour, but a future caller would not know to expect the
    // mutation. Restored to true read-only.
    //
    // Length-bound applied here as well (defence-in-depth) so a caller
    // of validate can't bypass the consume-path length check.
    if (raw_token.empty() || raw_token.size() > kMaxEnrollmentTokenLength) {
        return false;
    }
    auto hash = sha256_hex(raw_token);
    auto now = std::chrono::system_clock::now();
    std::shared_lock lock(mu_);
    for (const auto& [_, et] : enrollment_tokens_) {
        if (!constant_time_compare(et.token_hash, hash))
            continue;
        if (et.revoked)
            return false;
        if (now > et.expires_at)
            return false;
        if (et.max_uses > 0 && et.use_count >= et.max_uses)
            return false;
        return true;
    }
    return false;
}

std::expected<EnrollmentClaim, EnrollmentTokenError>
AuthManager::consume_enrollment_token(std::string_view raw_token,
                                      std::string_view consuming_agent_id) {
    // W1.1 UP-H2: length-bound at the API entry. The same kMaxEnrollment
    // TokenLength constant guards the handlers (where it converts to a 400/
    // gRPC INVALID_ARGUMENT) AND this consume function (defence-in-depth,
    // so an in-process caller can't bypass the handler check and force the
    // store to SHA-256 a 1 MiB blob). Empty token is also rejected here —
    // the handler should never call us with an empty token, but it makes
    // the consume contract self-describing.
    if (raw_token.empty() || raw_token.size() > kMaxEnrollmentTokenLength) {
        return std::unexpected(EnrollmentTokenError::invalid_input);
    }

    auto hash = sha256_hex(std::string{raw_token});
    auto now = std::chrono::system_clock::now();

    EnrollmentClaim claim;
    bool consumed = false;

    {
        // The atomic-claim critical section. Everything from validity check
        // through ++use_count and last_consumed_by_agent_id write happens
        // under one unique_lock so no second consumer can interleave between
        // "this token is valid" and "this token's use_count is now N+1".
        // Loosening this lock is the bug #827 closes; do not split into a
        // shared_lock for the SELECT + unique_lock for the UPDATE without
        // re-reading the issue's race scenario.
        std::unique_lock lock(mu_);

        for (auto& [id, et] : enrollment_tokens_) {
            if (!constant_time_compare(et.token_hash, hash))
                continue;

            if (et.revoked) {
                spdlog::warn("Enrollment token {} is revoked", id);
                return std::unexpected(EnrollmentTokenError::revoked);
            }
            if (now > et.expires_at) {
                spdlog::warn("Enrollment token {} has expired", id);
                return std::unexpected(EnrollmentTokenError::expired);
            }
            if (et.max_uses > 0 && et.use_count >= et.max_uses) {
                // The race-lost case is structurally indistinguishable from a
                // "stale exhausted" case at this point — both look like
                // use_count >= max_uses. The handler discriminates via the
                // `last_consumed_by_agent_id` value (already set by the prior
                // winner) and emits an audit row naming the winner so the
                // operator can see the contention. We just classify as
                // already_consumed and let the handler do the attribution.
                spdlog::warn("Enrollment token {} exhausted ({}/{}) — race lost or stale", id,
                             et.use_count, et.max_uses);
                return std::unexpected(EnrollmentTokenError::already_consumed);
            }

            // The atomic claim. ++use_count and the agent_id stamp happen
            // before we drop the lock. The use_count value we return to the
            // caller is the POST-increment value, so a successful single-use
            // consume returns use_count_after == 1.
            ++et.use_count;
            if (!consuming_agent_id.empty()) {
                et.last_consumed_by_agent_id.assign(consuming_agent_id.data(),
                                                    consuming_agent_id.size());
            }

            claim.token_id = id;
            claim.max_uses = et.max_uses;
            claim.use_count_after = et.use_count;
            claim.single_use = (et.max_uses == 1);
            consumed = true;

            spdlog::info("Enrollment token {} consumed by '{}' ({}/{})", id,
                         consuming_agent_id.empty() ? std::string_view{"<unknown>"}
                                                    : consuming_agent_id,
                         et.use_count, et.max_uses == 0 ? -1 : et.max_uses);
            break;
        }
    }

    if (!consumed) {
        spdlog::warn("Enrollment token not found (hash prefix={})", hash.substr(0, 8));
        return std::unexpected(EnrollmentTokenError::not_found);
    }

    // W1.4 R2 / UP-C1: persist immediately after the in-memory claim.
    // The PR1 implementation left persistence to whatever next mutation
    // (revoke, create, manager destruction) happened to call save_tokens(),
    // which left a crash-replay window: a server SIGKILL between the
    // in-memory ++use_count and any disk write meant the next boot's
    // load_tokens() read use_count=0 and the consumed token would
    // re-enroll. Now save_tokens() lands before we return, closing the
    // window to "crash inside save_tokens() itself" (atomic file write
    // via ofstream::trunc + close, so the on-disk file is either the
    // pre-consume or post-consume snapshot, never a torn intermediate).
    //
    // Lock-release first because save_tokens() acquires shared_lock(mu_)
    // itself — holding unique_lock across the call would deadlock. Once
    // the in-memory claim has landed, releasing the unique_lock is safe:
    // parallel consumers see exhausted, parallel saves serialise via
    // their own shared_lock so the on-disk snapshot only ever advances.
    //
    // Failure handling: do NOT roll back the in-memory consume on save
    // failure. The agent will be told their token is consumed (success
    // response in flight) and rolling back would create a different
    // bug (token reuse under disk-failure injection). Log loudly so SRE
    // sees it; the prior best-effort behaviour for non-consume paths
    // (revoke, create) is preserved by the existing save_tokens callers.
    //
    // Note on AuthDB: AuthManager has an `auth_db_` member, but
    // create_enrollment_token never inserts into the AuthDB enrollment
    // _tokens table — that table is dead. Wiring AuthDB as the source
    // of truth would require reconciling the AuthDB schema (single-use
    // only) against the in-memory schema (max_uses, label, revoked)
    // and porting create_enrollment_token. Out of scope for R2; the
    // in-memory + file-snapshot path is the production-correct one.
    if (!save_tokens()) {
        spdlog::error("Enrollment token {} consume succeeded in-memory but save_tokens "
                      "failed — on a crash before the next save, the consumed state will "
                      "be lost and the token may replay",
                      claim.token_id);
    }
    return claim;
}

std::string AuthManager::last_consumer_for_token_hash(std::string_view token_hash) const {
    std::shared_lock lock(mu_);
    for (const auto& [_, et] : enrollment_tokens_) {
        if (constant_time_compare(et.token_hash, std::string{token_hash})) {
            return et.last_consumed_by_agent_id;
        }
    }
    return {};
}

std::vector<EnrollmentToken> AuthManager::list_enrollment_tokens() const {
    std::shared_lock lock(mu_);
    std::vector<EnrollmentToken> out;
    out.reserve(enrollment_tokens_.size());
    for (const auto& [_, et] : enrollment_tokens_) {
        out.push_back(et);
    }
    return out;
}

bool AuthManager::revoke_enrollment_token(const std::string& token_id) {
    {
        std::unique_lock lock(mu_);
        auto it = enrollment_tokens_.find(token_id);
        if (it == enrollment_tokens_.end())
            return false;
        it->second.revoked = true;
    }
    save_tokens();
    spdlog::info("Enrollment token {} revoked", token_id);
    return true;
}

// ── Enrollment token persistence ────────────────────────────────────────────

bool AuthManager::save_tokens() const {
    auto path = state_dir() / "enrollment-tokens.cfg";

    std::shared_lock lock(mu_);

#ifndef _WIN32
    mode_t old_mask = umask(0077);
#endif
    std::ofstream f(path, std::ios::trunc);
#ifndef _WIN32
    umask(old_mask);
#endif
    if (!f.is_open()) {
        spdlog::error("Cannot write enrollment tokens to {}", path.string());
        return false;
    }

    f << "# Yuzu Enrollment Tokens\n";
    f << "# Version: 1\n";
    f << "# Format: "
         "token_id:token_hash:label:max_uses:use_count:created_epoch:expires_epoch:revoked\n\n";

    for (const auto& [id, et] : enrollment_tokens_) {
        auto created_epoch =
            std::chrono::duration_cast<std::chrono::seconds>(et.created_at.time_since_epoch())
                .count();
        auto expires_epoch =
            (et.expires_at == (std::chrono::system_clock::time_point::max)())
                ? int64_t{0}
                : std::chrono::duration_cast<std::chrono::seconds>(et.expires_at.time_since_epoch())
                      .count();

        f << et.token_id << ':' << et.token_hash << ':' << et.label << ':' << et.max_uses << ':'
          << et.use_count << ':' << created_epoch << ':' << expires_epoch << ':'
          << (et.revoked ? '1' : '0') << '\n';
    }
    f.close();

#ifndef _WIN32
    // Restrict token file to owner-only (0600) — contains token hashes.
    std::error_code perm_ec;
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, perm_ec);
    if (perm_ec) {
        spdlog::warn("Failed to set permissions on {}: {}", path.string(), perm_ec.message());
    }
#endif

    return true;
}

bool AuthManager::load_tokens() {
    auto path = state_dir() / "enrollment-tokens.cfg";

    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::unique_lock lock(mu_);
    enrollment_tokens_.clear();

    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;
        if (line.starts_with("# Version: ")) {
            try {
                int ver = std::stoi(line.substr(11));
                if (ver != 1) {
                    spdlog::error("Unsupported enrollment-tokens.cfg version {}", ver);
                    return false;
                }
            } catch (const std::exception& e) {
                spdlog::error("Malformed version line in enrollment-tokens.cfg: {}", e.what());
                return false;
            }
            continue;
        }
        if (line[0] == '#')
            continue;

        std::istringstream ss(line);
        std::string token_id, token_hash, label, max_uses_s, use_count_s, created_s, expires_s,
            revoked_s;

        if (!std::getline(ss, token_id, ':'))
            continue;
        if (!std::getline(ss, token_hash, ':'))
            continue;
        if (!std::getline(ss, label, ':'))
            continue;
        if (!std::getline(ss, max_uses_s, ':'))
            continue;
        if (!std::getline(ss, use_count_s, ':'))
            continue;
        if (!std::getline(ss, created_s, ':'))
            continue;
        if (!std::getline(ss, expires_s, ':'))
            continue;
        if (!std::getline(ss, revoked_s, ':'))
            continue;

        EnrollmentToken et;
        et.token_id = token_id;
        et.token_hash = token_hash;
        et.label = label;
        et.max_uses = std::stoi(max_uses_s);
        et.use_count = std::stoi(use_count_s);
        et.created_at =
            std::chrono::system_clock::time_point(std::chrono::seconds(std::stoll(created_s)));
        et.expires_at = (expires_s == "0") ? (std::chrono::system_clock::time_point::max)()
                                           : std::chrono::system_clock::time_point(
                                                 std::chrono::seconds(std::stoll(expires_s)));
        et.revoked = (revoked_s == "1");

        enrollment_tokens_[token_id] = std::move(et);
    }

    spdlog::info("Loaded {} enrollment token(s)", enrollment_tokens_.size());
    return true;
}

// ── Pending agents (Tier 1) ─────────────────────────────────────────────────

std::string pending_status_to_string(PendingStatus s) {
    switch (s) {
    case PendingStatus::pending:
        return "pending";
    case PendingStatus::approved:
        return "approved";
    case PendingStatus::denied:
        return "denied";
    }
    return "unknown";
}

void AuthManager::add_pending_agent(const std::string& agent_id, const std::string& hostname,
                                    const std::string& os, const std::string& arch,
                                    const std::string& agent_version) {
    {
        std::unique_lock lock(mu_);
        // Don't overwrite if already exists
        if (pending_agents_.contains(agent_id))
            return;

        PendingAgent pa;
        pa.agent_id = agent_id;
        pa.hostname = hostname;
        pa.os = os;
        pa.arch = arch;
        pa.agent_version = agent_version;
        pa.requested_at = std::chrono::system_clock::now();
        pa.status = PendingStatus::pending;
        pending_agents_[agent_id] = std::move(pa);
    }
    save_pending();
    spdlog::info("Agent {} added to pending approval queue", agent_id);
}

std::optional<PendingStatus> AuthManager::get_pending_status(const std::string& agent_id) const {
    std::shared_lock lock(mu_);
    auto it = pending_agents_.find(agent_id);
    if (it == pending_agents_.end())
        return std::nullopt;
    return it->second.status;
}

std::vector<PendingAgent> AuthManager::list_pending_agents() const {
    std::shared_lock lock(mu_);
    std::vector<PendingAgent> out;
    out.reserve(pending_agents_.size());
    for (const auto& [_, pa] : pending_agents_) {
        out.push_back(pa);
    }
    return out;
}

bool AuthManager::approve_pending_agent(const std::string& agent_id) {
    {
        std::unique_lock lock(mu_);
        auto it = pending_agents_.find(agent_id);
        if (it == pending_agents_.end())
            return false;
        it->second.status = PendingStatus::approved;
    }
    save_pending();
    spdlog::info("Agent {} approved for enrollment", agent_id);
    return true;
}

bool AuthManager::deny_pending_agent(const std::string& agent_id) {
    {
        std::unique_lock lock(mu_);
        auto it = pending_agents_.find(agent_id);
        if (it == pending_agents_.end())
            return false;
        it->second.status = PendingStatus::denied;
    }
    save_pending();
    spdlog::info("Agent {} denied enrollment", agent_id);
    return true;
}

bool AuthManager::ensure_enrolled(const std::string& agent_id, const std::string& hostname,
                                  const std::string& os, const std::string& arch,
                                  const std::string& agent_version) {
    {
        std::unique_lock lock(mu_);
        auto it = pending_agents_.find(agent_id);
        if (it != pending_agents_.end()) {
            // Never override an explicit admin denial — tokens don't outrank admins
            if (it->second.status == PendingStatus::denied) {
                spdlog::warn("ensure_enrolled: agent {} is admin-denied, refusing to override",
                             agent_id);
                return false;
            }
            it->second.status = PendingStatus::approved;
        } else {
            PendingAgent pa;
            pa.agent_id = agent_id;
            pa.hostname = hostname;
            pa.os = os;
            pa.arch = arch;
            pa.agent_version = agent_version;
            pa.requested_at = std::chrono::system_clock::now();
            pa.status = PendingStatus::approved;
            pending_agents_[agent_id] = std::move(pa);
        }
    }
    save_pending();
    return true;
}

bool AuthManager::remove_pending_agent(const std::string& agent_id) {
    {
        std::unique_lock lock(mu_);
        if (pending_agents_.erase(agent_id) == 0)
            return false;
    }
    save_pending();
    return true;
}

// ── Pending agent persistence ───────────────────────────────────────────────

bool AuthManager::save_pending() const {
    auto path = state_dir() / "pending-agents.cfg";

    std::shared_lock lock(mu_);

#ifndef _WIN32
    mode_t old_mask = umask(0077);
#endif
    std::ofstream f(path, std::ios::trunc);
#ifndef _WIN32
    umask(old_mask);
#endif
    if (!f.is_open()) {
        spdlog::error("Cannot write pending agents to {}", path.string());
        return false;
    }

    f << "# Yuzu Pending Agents\n";
    f << "# Version: 1\n";
    f << "# Format: agent_id:hostname:os:arch:version:requested_epoch:status\n\n";

    for (const auto& [id, pa] : pending_agents_) {
        auto epoch =
            std::chrono::duration_cast<std::chrono::seconds>(pa.requested_at.time_since_epoch())
                .count();

        f << pa.agent_id << ':' << pa.hostname << ':' << pa.os << ':' << pa.arch << ':'
          << pa.agent_version << ':' << epoch << ':' << pending_status_to_string(pa.status) << '\n';
    }
    f.close();

#ifndef _WIN32
    // Restrict pending-agents file to owner-only (0600).
    std::error_code perm_ec;
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, perm_ec);
    if (perm_ec) {
        spdlog::warn("Failed to set permissions on {}: {}", path.string(), perm_ec.message());
    }
#endif

    return true;
}

bool AuthManager::load_pending() {
    auto path = state_dir() / "pending-agents.cfg";

    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::unique_lock lock(mu_);
    pending_agents_.clear();

    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;
        if (line.starts_with("# Version: ")) {
            try {
                int ver = std::stoi(line.substr(11));
                if (ver != 1) {
                    spdlog::error("Unsupported pending-agents.cfg version {}", ver);
                    return false;
                }
            } catch (const std::exception& e) {
                spdlog::error("Malformed version line in pending-agents.cfg: {}", e.what());
                return false;
            }
            continue;
        }
        if (line[0] == '#')
            continue;

        std::istringstream ss(line);
        std::string agent_id, hostname, os, arch, version, epoch_s, status_s;

        if (!std::getline(ss, agent_id, ':'))
            continue;
        if (!std::getline(ss, hostname, ':'))
            continue;
        if (!std::getline(ss, os, ':'))
            continue;
        if (!std::getline(ss, arch, ':'))
            continue;
        if (!std::getline(ss, version, ':'))
            continue;
        if (!std::getline(ss, epoch_s, ':'))
            continue;
        if (!std::getline(ss, status_s, ':'))
            continue;

        PendingAgent pa;
        pa.agent_id = agent_id;
        pa.hostname = hostname;
        pa.os = os;
        pa.arch = arch;
        pa.agent_version = version;
        pa.requested_at =
            std::chrono::system_clock::time_point(std::chrono::seconds(std::stoll(epoch_s)));

        if (status_s == "approved")
            pa.status = PendingStatus::approved;
        else if (status_s == "denied")
            pa.status = PendingStatus::denied;
        else
            pa.status = PendingStatus::pending;

        pending_agents_[agent_id] = std::move(pa);
    }

    spdlog::info("Loaded {} pending agent(s)", pending_agents_.size());
    return true;
}

} // namespace yuzu::server::auth
