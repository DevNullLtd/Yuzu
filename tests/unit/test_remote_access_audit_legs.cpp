/**
 * test_remote_access_audit_legs.cpp -- the OS-free decision logic, `list_posix`, over an
 * injected PosixFs: status rules, Include order and caps, AuthorizedKeysFile resolution
 * (including an inaccessible home beside a readable absolute entry), the network-mount guard,
 * the service arms, and the dispatch-wide row / attempt budgets. Portable, no disk, no
 * process, no clock.
 *
 * REAL CAPTURE: kAliceKey/kAliceFp from ssh-keygen OpenSSH_10.0p2 Debian 13; systemctl/launchctl
 * strings are labelled per case. CONSTRUCTED: everything else.
 */
#include <catch2/catch_test_macros.hpp>

#include "remote_access_audit_legs.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

using namespace yuzu::remote_access_audit;

namespace {

constexpr const char* kAliceKey =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEfwkBaM2u8m02IuUZ4wuvCPggDaq5R5MqdQWA82+WdV alice@laptop\n";
constexpr const char* kAliceFp = "SHA256:BPH4QduMtDlX59CWZCda5Zf0U0jseMmFVimvek7EMhA";

FileReadLike ok(std::string text) { return FileReadLike{std::move(text), ReadErr::none, 0}; }
FileReadLike err(int e) { return FileReadLike{{}, ReadErr::io, e}; }

yuzu::agent::SubprocessResult ran(std::string out, int code = 0) {
    yuzu::agent::SubprocessResult r;
    r.tool_ran = true;
    r.exit_code = code;
    r.termination_reason = yuzu::agent::TerminationReason::exited;
    r.output = std::move(out);
    return r;
}
yuzu::agent::SubprocessResult died(yuzu::agent::TerminationReason why) {
    yuzu::agent::SubprocessResult r;
    r.termination_reason = why;
    return r;
}

/// A scriptable PosixFs. Every call that touches a path is recorded in `touched`.
struct Fake {
    std::string os = "linux";
    bool launchd = false;
    std::map<std::string, FileReadLike> config_files; // by absolute path
    std::map<std::string, std::vector<std::string>> listings; // "dir|leaf" -> names (in the dir)
    bool listing_too_many = false;
    std::map<std::string, FileReadLike> dir_files; // "dir/name" -> contents (include entries)
    std::vector<HomeEntry> homes;
    int homes_err = 0;
    bool homes_too_many = false;
    std::vector<std::string> roots{"/home", "/root"};
    std::map<std::string, int> open_err;                 // by home path
    std::map<std::string, FileReadLike> key_files;        // home path + "/" + components joined
    std::map<std::string, FileReadLike> abs_files;
    std::optional<std::vector<std::string>> prefixes{std::vector<std::string>{}};
    std::function<yuzu::agent::SubprocessResult(const std::vector<std::string>&)> runner;
    std::function<bool(const HomeEntry&)> account_probe; // set => PosixFs::is_account_home
    std::function<std::string(const std::string&)> resolve; // set => PosixFs::resolve_root (a readlink hop)

    mutable std::vector<std::string> touched;
    mutable std::string current_dir;
    mutable std::string current_home;
    mutable int open_home_calls = 0;
    mutable int key_reads = 0;
    mutable int probe_calls = 0;
    mutable int mount_calls = 0;           // network_mount_prefixes acquisitions
    mutable std::size_t touched_at_mount = 0; // path touches when the table was last asked for
    mutable std::vector<std::string> resolved; // roots resolve_root was asked about (readlink only; not in `touched`)
    mutable std::vector<bool> merge_flags;     // SubprocessOptions::merge_stderr of every fs.run call

    PosixFs build() const {
        PosixFs fs;
        fs.os = os;
        fs.launchd = launchd;
        fs.config_path = "/etc/ssh/sshd_config";
        fs.home_roots = roots;
        fs.read_config = [this](const std::string& p) {
            touched.push_back(p);
            const auto it = config_files.find(p);
            return it == config_files.end() ? err(ENOENT) : it->second;
        };
        fs.list_include_dir = [this](const std::string& dir, const std::string& leaf, std::vector<std::string>& names,
                                     bool& too_many) {
            touched.push_back(dir);
            current_dir = dir;
            const auto it = listings.find(dir + "|" + leaf);
            if (it != listings.end())
                names = it->second;
            too_many = listing_too_many;
            return 0;
        };
        fs.read_include_at = [this](const std::string& name) {
            touched.push_back(current_dir + "/" + name);
            const auto it = dir_files.find(current_dir + "/" + name);
            return it == dir_files.end() ? err(ENOENT) : it->second;
        };
        fs.run = [this](const std::vector<std::string>& args, const yuzu::agent::SubprocessOptions& o) {
            merge_flags.push_back(o.merge_stderr);
            return runner ? runner(args) : died(yuzu::agent::TerminationReason::spawn_error);
        };
        fs.network_mount_prefixes = [this]() {
            ++mount_calls;
            touched_at_mount = touched.size();
            return prefixes;
        };
        fs.list_homes = [this](const std::vector<std::string>& r, std::vector<HomeEntry>& out, bool& too_many) {
            for (const auto& x : r)
                touched.push_back(x);
            out = homes;
            too_many = homes_too_many;
            return homes_err;
        };
        if (resolve) {
            fs.resolve_root = [this](const std::string& root) {
                resolved.push_back(root);
                return resolve(root);
            };
        }
        if (account_probe) {
            fs.is_account_home = [this](const HomeEntry& h) {
                ++probe_calls;
                touched.push_back(h.path);
                return account_probe(h);
            };
        }
        fs.open_home = [this](const HomeEntry& h) {
            ++open_home_calls;
            touched.push_back(h.path);
            current_home = h.path;
            const auto it = open_err.find(h.path);
            return it == open_err.end() ? 0 : it->second;
        };
        fs.read_key_file = [this](const std::vector<std::string>& comps) {
            ++key_reads;
            std::string p = current_home;
            for (const auto& c : comps)
                p += "/" + c;
            touched.push_back(p);
            const auto it = key_files.find(p);
            return it == key_files.end() ? err(ENOENT) : it->second;
        };
        fs.read_key_file_abs = [this](const std::string& p) {
            ++key_reads;
            touched.push_back(p);
            const auto it = abs_files.find(p);
            return it == abs_files.end() ? err(ENOENT) : it->second;
        };
        return fs;
    }

    bool touched_under(std::string_view prefix) const {
        return std::ranges::any_of(touched, [&](const std::string& t) { return t.rfind(prefix, 0) == 0; });
    }
    /// The one run-start mount snapshot: acquired exactly once, before any path was touched.
    bool mount_snapshot_first() const {
        return mount_calls == 1 && touched_at_mount == 0 && !touched.empty();
    }
};

/// Every unit answers `enabled` (a REAL CAPTURE string) unless overridden.
Fake healthy() {
    Fake f;
    f.config_files["/etc/ssh/sshd_config"] = ok("PermitRootLogin no\n");
    f.runner = [](const std::vector<std::string>&) { return ran("enabled\n"); };
    return f;
}

/// A macOS host: launchd service state, /Users home root, `com.openssh.sshd` not overridden.
Fake healthy_macos() {
    auto f = healthy();
    f.os = "macos";
    f.launchd = true;
    f.roots = {"/Users"};
    f.runner = [](const std::vector<std::string>&) { return ran("disabled services = {\n}\n"); };
    return f;
}

std::vector<std::string> kind_rows(const Listing& l, std::string_view kind) {
    std::vector<std::string> out;
    for (const auto& r : l.rows) {
        if (r.rfind(std::string(kind) + "|", 0) == 0)
            out.push_back(r);
    }
    return out;
}

/// Whole-token match on the comma-joined reason: a substring match once let `keys:oversized`
/// pass on `keys:oversized_line`.
bool has_token(const Listing& l, std::string_view t) {
    return (',' + l.reason + ',').find(',' + std::string(t) + ',') != std::string::npos;
}

/// True when `needle` appears in ANY row or in the reason (the status row is composed from it).
bool leaks(const Listing& l, std::string_view needle) {
    return l.reason.find(needle) != std::string::npos ||
           std::ranges::any_of(l.rows, [&](const std::string& r) { return r.find(needle) != std::string::npos; });
}

std::string row_with(const std::vector<std::string>& rows, std::string_view prefix) {
    const auto it =
        std::ranges::find_if(rows, [&](const std::string& r) { return r.rfind(prefix, 0) == 0; });
    return it == rows.end() ? std::string{} : *it;
}

HomeEntry home(std::string name) { return HomeEntry{name, "/home/" + name}; }

} // namespace

TEST_CASE("remote_access_audit legs: a clean read is supported, with every fixed row present",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.homes = {home("alice"), home("bob")};
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    f.key_files["/home/bob/.ssh/authorized_keys"] = ok("");
    const auto l = list_posix(f.build());
    CHECK(l.status == StatusState::supported);
    REQUIRE(l.rows.size() >= 3 + 14 + 4);
    CHECK(l.rows[0] == "source|sshd_config|read|1");
    CHECK(l.rows[1] == "source|homes|read|2|-");
    CHECK(l.rows[2] == "source|service|read|4");
    CHECK(kind_rows(l, "config").size() == 14);
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|no|sshd_config");
    CHECK(kind_rows(l, "service").size() == 4);
    CHECK(row_with(l.rows, "service|ssh.socket|") == "service|ssh.socket|enabled|systemctl_is_enabled");
    // MUTATION: dropping the 4th literal leaves a socket-activated Fedora host reading as SSH off
    CHECK(row_with(l.rows, "service|sshd.socket|") ==
          "service|sshd.socket|enabled|systemctl_is_enabled");
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|read|1|0|0");
    CHECK(row_with(l.rows, "file|bob|authorized_keys|") == "file|bob|authorized_keys|read|0|0|0");
    CHECK(row_with(l.rows, "file|alice|authorized_keys2|") == "file|alice|authorized_keys2|absent|-|-|-");
    CHECK(row_with(l.rows, "key|alice|") ==
          std::string("key|alice|authorized_keys|ssh-ed25519|") + kAliceFp + "|256|-|-");
}

TEST_CASE("remote_access_audit legs: Include is followed in directive order, sorted, with first-wins",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.config_files["/etc/ssh/sshd_config"] =
        ok("Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\n");
    f.listings["/etc/ssh/sshd_config.d|*.conf"] = {"10-a.conf", "20-b.conf"};
    f.dir_files["/etc/ssh/sshd_config.d/10-a.conf"] = ok("PermitRootLogin no\n");
    f.dir_files["/etc/ssh/sshd_config.d/20-b.conf"] = ok("PermitRootLogin yes\nPasswordAuthentication no\n");
    auto l = list_posix(f.build());
    // the include precedes the parent's PermitRootLogin, so the first include wins
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|no|include:10-a.conf");
    CHECK(row_with(l.rows, "config|passwordauthentication|") == "config|passwordauthentication|no|include:20-b.conf");
    CHECK(l.rows[0] == "source|sshd_config|read|3");

    // the same Include AFTER the parent's assignment: the parent wins
    f.config_files["/etc/ssh/sshd_config"] = ok("PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n");
    l = list_posix(f.build());
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|yes|sshd_config");
    CHECK(l.status == StatusState::supported);
}

TEST_CASE("remote_access_audit legs: Include caps, unreadable includes and Match are tokens, not silence",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    // depth: sshd_config -> i1 -> i2 -> i3 -> i4 is four levels (allowed); i4's Include of i5 is too deep
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /i1\n");
    for (int i = 1; i <= 5; ++i)
        f.config_files["/i" + std::to_string(i)] = ok("Include /i" + std::to_string(i + 1) + "\n");
    auto l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:include:depth_cap"));
    CHECK(f.touched_under("/i4"));
    CHECK_FALSE(f.touched_under("/i5")); // never read past the cap

    // too many matches in a listing
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/d/*\n");
    f.listings["/etc/ssh/d|*"] = {"a"};
    f.listing_too_many = true;
    f.dir_files["/etc/ssh/d/a"] = ok("");
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:include:too_many"));

    // an unreadable include
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/x.conf\n");
    f.config_files["/etc/ssh/x.conf"] = err(EIO);
    l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:include:eio"));

    // an unsupported pattern, and an Include inside a Match block is not followed or read
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] =
        ok("Include ~/x.conf\nMatch User bob\nInclude /etc/ssh/m.conf\nPermitRootLogin yes\n");
    f.config_files["/etc/ssh/m.conf"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:include:pattern_unsupported"));
    CHECK(has_token(l, "linux:remote_access_audit:include:in_match"));
    CHECK_FALSE(f.touched_under("/etc/ssh/m.conf"));
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|-|-");
    CHECK(row_with(l.rows, "config|match_blocks|") == "config|match_blocks|1|-");

    // the file cap is dispatch-wide: 33 single includes read at most 32 files in all
    f = healthy();
    std::string inc;
    for (int i = 0; i < 40; ++i) {
        inc += "Include /inc" + std::to_string(i) + "\n";
        f.config_files["/inc" + std::to_string(i)] = ok("");
    }
    f.config_files["/etc/ssh/sshd_config"] = ok(inc);
    l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:include:too_many"));
    CHECK(l.rows[0] == "source|sshd_config|read|32");
}

TEST_CASE("remote_access_audit legs: sshd_config absent, refused and invalid",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.config_files.clear();
    auto l = list_posix(f.build());
    CHECK(l.rows[0] == "source|sshd_config|absent|-");
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|-|-");
    CHECK(l.status == StatusState::supported); // absent is a state, not a failure

    // refused with nothing else readable -> permission_denied
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = err(EACCES);
    f.homes_err = ENOENT;
    f.runner = nullptr; // spawn_error
    l = list_posix(f.build());
    CHECK(l.rows[0] == "source|sshd_config|refused|-");
    CHECK(l.status == StatusState::permission_denied);
    CHECK(has_token(l, "linux:remote_access_audit:sshd_config:permission_denied"));

    // a symlinked, oversized or NUL-bearing config is a failure with its own token
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = FileReadLike{{}, ReadErr::symlink_refused, 0};
    l = list_posix(f.build());
    CHECK(l.rows[0] == "source|sshd_config|failed|-");
    CHECK(has_token(l, "linux:remote_access_audit:sshd_config:symlink_refused"));
    f.config_files["/etc/ssh/sshd_config"] = ok(std::string("Port 22\0", 8));
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:sshd_config:invalid_bytes"));
    f.config_files["/etc/ssh/sshd_config"] = ok("PermitRootLogin \"yes\n");
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:sshd_config:invalid_quotes"));
}

TEST_CASE("remote_access_audit legs: every home refused is constrained, never empty",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.homes = {home("alice"), home("bob")};
    f.open_err["/home/alice"] = EACCES;
    f.open_err["/home/bob"] = EACCES;
    const auto l = list_posix(f.build());
    CHECK(l.status == StatusState::constrained); // the config and the service were read
    CHECK(std::ranges::count(l.reason, ',') == 0);
    CHECK(has_token(l, "linux:remote_access_audit:homes:permission_denied"));
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|refused|-|-|-");
    CHECK(row_with(l.rows, "file|bob|authorized_keys|") == "file|bob|authorized_keys|refused|-|-|-");
    CHECK(kind_rows(l, "key").empty());
}

TEST_CASE("remote_access_audit legs: an inaccessible home does not hide a readable absolute entry",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile /srv/keys/shared %h/.ssh/authorized_keys\n");
    f.homes = {home("alice")};
    f.open_err["/home/alice"] = EACCES;
    f.abs_files["/srv/keys/shared"] = ok(kAliceKey);
    auto l = list_posix(f.build());
    CHECK(row_with(l.rows, "file|alice|custom|") == "file|alice|custom|read|1|0|0");
    CHECK(kind_rows(l, "file").size() == 2); // both entries are "custom": one read, one refused
    CHECK(kind_rows(l, "file")[1] == "file|alice|custom|refused|-|-|-");
    REQUIRE(row_with(l.rows, "key|alice|") != "");
    CHECK(has_token(l, "linux:remote_access_audit:homes:permission_denied"));
    // the ABSOLUTE path of the config entry is never emitted anywhere: not a row, not the status reason
    CHECK_FALSE(leaks(l, "/srv/keys"));
    CHECK(row_with(l.rows, "config|authorizedkeysfile|") == "config|authorizedkeysfile|custom:2|sshd_config");

    // every entry absolute: the home is never opened at all
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile /srv/keys/one /srv/keys/two\n");
    f.homes = {home("alice"), home("bob")};
    f.abs_files["/srv/keys/one"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(f.open_home_calls == 0);
    CHECK(kind_rows(l, "key").size() == 2); // the same absolute file, once per account
    CHECK(l.status == StatusState::supported);
}

TEST_CASE("remote_access_audit legs: a non-account home is skipped by the eligibility probe, an unopenable account is refused",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.homes = {home("alice"), home("remote"), home("shared"), home("locked")};
    f.prefixes = std::vector<std::string>{"/home/remote"};  // personal-data-ok: synthetic fixture account
    f.account_probe = [](const HomeEntry& h) { return h.name != "shared"; }; // shared: positively not an account
    f.open_err["/home/locked"] = EACCES;                                      // an account the agent cannot open personal-data-ok: synthetic fixture account
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    const auto l = list_posix(f.build());
    CHECK(f.mount_snapshot_first());

    // shared: probed once and nothing else (no open, no read), no file rows, not counted as an account
    CHECK(std::ranges::count(f.touched, "/home/shared") == 1);
    CHECK_FALSE(f.touched_under("/home/shared/"));
    CHECK(row_with(l.rows, "file|shared|") == "");
    CHECK(l.rows[1] == "source|homes|read|3|1"); // alice, remote, locked; shared refused by the probe

    // a network-mounted home is never probed (the probe would stat it), opened or read
    CHECK(f.probe_calls == 3); // alice, shared, locked
    CHECK_FALSE(f.touched_under("/home/remote"));  // personal-data-ok: synthetic fixture account
    CHECK(row_with(l.rows, "file|remote|authorized_keys|") == "file|remote|authorized_keys|failed|-|-|-");
    CHECK(has_token(l, "linux:remote_access_audit:keys:network_mount_skipped"));

    // an eligible account the agent cannot open is a refused row plus a token, never a silent drop
    CHECK(row_with(l.rows, "file|locked|authorized_keys|") == "file|locked|authorized_keys|refused|-|-|-");
    CHECK(has_token(l, "linux:remote_access_audit:homes:permission_denied"));
    CHECK(row_with(l.rows, "key|alice|") != "");

    // a non-account is skipped before the %u-style token check too: it adds no token of its own
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile /srv/%u/keys\n");
    f.homes = {home("shared")};
    f.account_probe = [](const HomeEntry&) { return false; };
    const auto none = list_posix(f.build());
    CHECK_FALSE(has_token(none, "linux:remote_access_audit:keys:path_token_unsupported"));
    CHECK(none.rows[1] == "source|homes|read|0|1");
    CHECK(none.status == StatusState::supported);
}

TEST_CASE("remote_access_audit legs: a NUL in a key file cuts only its own line and the file is still read",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.homes = {home("alice")};
    std::string text = kAliceKey;               // "<key> alice@laptop\n"
    text.insert(text.size() - 1, 1, '\0');      // ... alice@laptop<NUL>\n
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(text);
    const auto l = list_posix(f.build());
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|read|1|0|0"); // read, not failed
    CHECK(row_with(l.rows, "key|alice|") ==
          std::string("key|alice|authorized_keys|ssh-ed25519|") + kAliceFp + "|256|-|-");
    CHECK(has_token(l, "linux:remote_access_audit:keys:invalid_bytes"));
    // sshd_config keeps the whole-file rule (a NUL there is not per-line): pinned above in the config test
}

TEST_CASE("remote_access_audit legs: AuthorizedKeysFile none, unsupported tokens and Match scope",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile none\n");
    f.homes = {home("alice")};
    auto l = list_posix(f.build());
    CHECK(kind_rows(l, "file").empty());
    CHECK(f.open_home_calls == 0);
    CHECK(l.status == StatusState::supported);

    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile /srv/%u/keys .ssh/authorized_keys\n");
    f.homes = {home("alice")};
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:keys:path_token_unsupported"));
    CHECK(kind_rows(l, "file").size() == 1); // the %u entry has no file row, the other is read

    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("Match User x\nAuthorizedKeysFile /elsewhere\n");
    f.homes = {home("alice")};
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:keys:match_scoped_authorizedkeysfile"));
    CHECK(row_with(l.rows, "key|alice|") != ""); // the global (default) entries are still used
}

TEST_CASE("remote_access_audit legs: a network mount is never touched", "[remote_access_audit][legs]") {
    auto f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile .ssh/authorized_keys /mnt/nfs/keys\n");
    f.homes = {home("alice"), home("remote")};
    f.prefixes = std::vector<std::string>{"/home/remote", "/mnt/nfs"};  // personal-data-ok: synthetic fixture account
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    auto l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:keys:network_mount_skipped"));
    CHECK(row_with(l.rows, "file|remote|authorized_keys|") == "file|remote|authorized_keys|failed|-|-|-");
    CHECK_FALSE(f.touched_under("/home/remote"));  // personal-data-ok: synthetic fixture account
    CHECK_FALSE(f.touched_under("/mnt/nfs")); // an absolute entry under a prefix is skipped too
    CHECK_FALSE(leaks(l, "/mnt/nfs"));        // the mount point is never named on the wire
    CHECK_FALSE(leaks(l, "/home/remote"));  // personal-data-ok: synthetic fixture account
    CHECK(row_with(l.rows, "key|alice|") != "");

    // a home root on a network mount is not listed
    f = healthy();
    f.prefixes = std::vector<std::string>{"/home"};
    f.homes = {home("alice")};
    l = list_posix(f.build());
    CHECK_FALSE(f.touched_under("/home"));
    CHECK(has_token(l, "linux:remote_access_audit:keys:network_mount_skipped"));

    // a home root that is itself a link into a network mount is skipped on its RESOLVED path:
    // the alias passes the prefix check, the readlink hop reveals the target, and nothing under
    // either path is listed, opened or read
    f = healthy();
    f.roots = {"/home"};
    f.resolve = [](const std::string& r) { return r == "/home" ? std::string{"/net/home"} : r; };
    f.prefixes = std::vector<std::string>{"/net"};
    f.homes = {HomeEntry{"alice", "/net/home/alice"}};
    f.key_files["/net/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    l = list_posix(f.build());
    // the config half asks about its own path first, then the keys half about the home root
    CHECK(f.resolved == std::vector<std::string>{"/etc/ssh/sshd_config", "/home"});
    CHECK(has_token(l, "linux:remote_access_audit:keys:network_mount_skipped"));
    CHECK(row_with(l.rows, "key|alice|").empty());
    CHECK_FALSE(f.touched_under("/home"));
    CHECK_FALSE(f.touched_under("/net"));

    // a link whose target is local is listed at the TARGET path, mount-checked and then read
    f = healthy();
    f.roots = {"/home"};
    f.resolve = [](const std::string& r) { return r == "/home" ? std::string{"/var/home"} : r; };
    f.prefixes = std::vector<std::string>{"/net"};
    f.homes = {HomeEntry{"alice", "/var/home/alice"}};
    f.key_files["/var/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(l.status == StatusState::supported);
    CHECK(row_with(l.rows, "key|alice|") != "");
    CHECK(f.touched_under("/var/home"));

    // an unreadable mount table is a token and the walk proceeds
    f = healthy();
    f.prefixes = std::nullopt;
    f.homes = {home("alice")};
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(f.mount_snapshot_first()); // an unreadable table is still ONE acquisition, taken first
    CHECK(has_token(l, "linux:remote_access_audit:keys:mounts_unreadable"));
    CHECK(row_with(l.rows, "key|alice|") != "");
}

TEST_CASE("remote_access_audit legs: the config half honours the same run-start mount snapshot",
          "[remote_access_audit][legs]") {
    const auto touched_mentions = [](const Fake& x, std::string_view needle) {
        return std::ranges::any_of(x.touched, [&](const std::string& t) { return t.find(needle) != std::string::npos; });
    };

    // the sshd_config path itself is under a mount: never read, a failed source, the rows say `-`
    auto f = healthy();
    f.prefixes = std::vector<std::string>{"/etc/ssh"};
    f.config_files["/etc/ssh/sshd_config"] = ok("PermitRootLogin yes\n");
    auto l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "sshd_config"));
    CHECK(l.rows[0] == "source|sshd_config|failed|-");
    CHECK(has_token(l, "linux:remote_access_audit:sshd_config:network_mount_skipped"));
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|-|-");

    // a direct Include under a mount: never read; the parent's own directives still are
    f = healthy();
    f.prefixes = std::vector<std::string>{"/network"};
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /network/ssh.conf\nPermitRootLogin no\n");
    f.config_files["/network/ssh.conf"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "network"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(l.rows[0] == "source|sshd_config|read|1"); // the parent was read, the include was not
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|no|sshd_config");

    // the same path spelled with `..`, `.` and `//` is judged on its lexical form
    for (const char* spelling : {"/etc/ssh/../../network/ssh.conf", "//network//./ssh.conf"}) {
        f.config_files["/etc/ssh/sshd_config"] = ok(std::string("Include ") + spelling + "\n");
        l = list_posix(f.build());
        CHECK_FALSE(touched_mentions(f, "network"));
        CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    }

    // a glob Include whose DIRECTORY is under a mount: never listed, nothing in it read
    f = healthy();
    f.prefixes = std::vector<std::string>{"/network"};
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /network/conf.d/*.conf\n");
    f.listings["/network/conf.d|*.conf"] = {"a.conf"};
    f.dir_files["/network/conf.d/a.conf"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "network"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|-|-");

    // an Include DIRECTORY already under a mount is never lstat'ed (the resolver would traverse the
    // mount), glob and single arm alike; the resolver is identity so only the gate keeps it silent.
    // MUTATION: lstat_dir = c.fs.resolve_root != nullptr resolves the directory and goes red.
    for (const char* inc : {"Include /mnt/shares/*.conf\n", "Include /mnt/shares/x.conf\n"}) {
        INFO(inc);
        f = healthy();
        f.prefixes = std::vector<std::string>{"/mnt/shares"};
        f.resolve = [](const std::string& p) { return p; };
        f.config_files["/etc/ssh/sshd_config"] = ok(inc);
        f.listings["/mnt/shares|*.conf"] = {"x.conf"};
        f.dir_files["/mnt/shares/x.conf"] = ok("PermitRootLogin yes\n");
        l = list_posix(f.build());
        CHECK(std::ranges::count(f.resolved, "/mnt/shares") == 0);
        CHECK(std::ranges::count(f.resolved, "/mnt/shares/x.conf") == 0);
        CHECK_FALSE(touched_mentions(f, "mnt"));
        CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    }

    // a glob Include in a LOCAL directory, one listed entry (a per-file bind mount) under a mount:
    // that entry is judged by its name and never opened; the token is raised
    f = healthy();
    f.prefixes = std::vector<std::string>{"/etc/ssh/sshd_config.d/mounted.conf"};
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/sshd_config.d/*.conf\n");
    f.listings["/etc/ssh/sshd_config.d|*.conf"] = {"mounted.conf"};
    f.dir_files["/etc/ssh/sshd_config.d/mounted.conf"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "mounted.conf"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(l.rows[0] == "source|sshd_config|read|1");
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|-|-");

    // the Include DIRECTORY is a link (one readlink hop) over a per-file mount: the entry is judged
    // under BOTH spellings, so the mounted one is never opened and its sibling still is.
    // MUTATION: dropping the resolved-spelling comparison opens share1.conf.
    f = healthy();
    f.prefixes = std::vector<std::string>{"/mnt/shares/share1.conf"};
    f.resolve = [](const std::string& p) {
        return p == "/etc/ssh/conf.d" ? std::string{"/mnt/shares"} : p;
    };
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/conf.d/*.conf\n");
    f.listings["/etc/ssh/conf.d|*.conf"] = {"share1.conf", "ok.conf"};
    f.dir_files["/etc/ssh/conf.d/share1.conf"] = ok("PermitRootLogin yes\n");
    f.dir_files["/etc/ssh/conf.d/ok.conf"] = ok("PasswordAuthentication no\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "share1"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|-|-");
    CHECK(row_with(l.rows, "config|passwordauthentication|") ==
          "config|passwordauthentication|no|include:ok.conf");

    // a dot-spelled Include directory and a mounted entry that sorts BEFORE its sibling.
    // MUTATION: dropping BOTH lexical_normal(spec.dir) and the configured-spelling join
    // normalisation opens m.conf (each alone is killed by the `..`-spelled glob and the
    // `Include /*.conf` cases below); `continue` -> `break` drops z.conf.
    f = healthy();
    f.prefixes = std::vector<std::string>{"/etc/ssh/conf.d/m.conf"};
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/./conf.d/*.conf\n");
    f.listings["/etc/ssh/./conf.d|*.conf"] = {"m.conf", "z.conf"};
    f.dir_files["/etc/ssh/./conf.d/m.conf"] = ok("PermitRootLogin yes\n");
    f.dir_files["/etc/ssh/./conf.d/z.conf"] = ok("PasswordAuthentication no\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "m.conf"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(row_with(l.rows, "config|passwordauthentication|") ==
          "config|passwordauthentication|no|include:z.conf");

    // the Include DIRECTORY is a link to "/": the joined resolved spelling would be "//m.conf",
    // which a byte compare never matches against the prefix "/m.conf". Two mounted entries and one
    // local sibling: neither mounted entry is opened, the skipped entries are not counted as
    // read, and the sibling still parses.
    // MUTATION: dropping lexical_normal from the resolved spelling opens m.conf;
    // `++c.files_read` in the skip branch makes the source row say read|4.
    f = healthy();
    f.prefixes = std::vector<std::string>{"/m.conf", "/n.conf"};
    f.resolve = [](const std::string& p) { return p == "/etc/ssh/conf.d" ? std::string{"/"} : p; };
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/conf.d/*.conf\n");
    f.listings["/etc/ssh/conf.d|*.conf"] = {"m.conf", "n.conf", "z.conf"};
    f.dir_files["/etc/ssh/conf.d/m.conf"] = ok("PermitRootLogin yes\n");
    f.dir_files["/etc/ssh/conf.d/n.conf"] = ok("PermitRootLogin yes\n");
    f.dir_files["/etc/ssh/conf.d/z.conf"] = ok("PasswordAuthentication no\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "m.conf"));
    CHECK_FALSE(touched_mentions(f, "n.conf"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(l.rows[0] == "source|sshd_config|read|2");
    CHECK(row_with(l.rows, "config|passwordauthentication|") ==
          "config|passwordauthentication|no|include:z.conf");

    // a glob Include whose DIRECTORY is a link to a whole-directory mount: the directory compare on
    // the resolved spelling fires, nothing is listed. The resolver answers `//mnt/shares`, so the
    // helper's normalisation is what lets the byte compare see it.
    // MUTATION: under_prefix(dir_resolved) -> dir_norm lists the directory; dropping lexical_normal
    // from one_hop misses the `//` spelling.
    f = healthy();
    f.prefixes = std::vector<std::string>{"/mnt/shares"};
    f.resolve = [](const std::string& p) {
        return p == "/etc/ssh/conf.d" ? std::string{"//mnt/shares"} : p;
    };
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/conf.d/*.conf\n");
    f.listings["/etc/ssh/conf.d|*.conf"] = {"a.conf"};
    f.dir_files["/etc/ssh/conf.d/a.conf"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "conf.d"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));

    // a glob Include whose DIRECTORY is spelled with `..` or `//` and `.`: judged on the lexical
    // form, so the directory is neither lstat'ed nor listed.
    // MUTATION: dir_norm = spec.dir lstat's the raw spelling and lists the mount.
    for (const char* spelling : {"/etc/ssh/../../network/conf.d/*.conf", "//network//./conf.d/*.conf"}) {
        INFO(spelling);
        f = healthy();
        f.prefixes = std::vector<std::string>{"/network"};
        f.resolve = [](const std::string& p) { return p; };
        f.config_files["/etc/ssh/sshd_config"] = ok(std::string("Include ") + spelling + "\n");
        l = list_posix(f.build());
        CHECK(std::ranges::none_of(f.resolved, [](const std::string& r) { return r.find("network") != std::string::npos; }));
        CHECK_FALSE(touched_mentions(f, "network"));
        CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    }

    // a glob Include in "/" with a mounted entry that sorts BEFORE its sibling: the configured
    // join would be "//m.conf" without normalisation.
    // MUTATION: dropping the configured-spelling lexical_normal in entry_on_network opens m.conf.
    f = healthy();
    f.prefixes = std::vector<std::string>{"/m.conf"};
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /*.conf\n");
    f.listings["/|*.conf"] = {"m.conf", "z.conf"};
    f.dir_files["//m.conf"] = ok("PermitRootLogin yes\n");
    f.dir_files["//z.conf"] = ok("PasswordAuthentication no\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "m.conf"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(row_with(l.rows, "config|passwordauthentication|") ==
          "config|passwordauthentication|no|include:z.conf");

    // a single-file Include under a LINK parent over a per-file mount: the file is judged by name
    // under the parent's one-hop target BEFORE it is itself lstat'ed (that lstat would traverse the
    // link and reach a dead mount), so the file is never opened and its path is never asked of
    // resolve_root.
    // MUTATION: dropping the parent-spelling compare opens root.conf.
    f = healthy();
    f.prefixes = std::vector<std::string>{"/mnt/shares/root.conf"};
    f.resolve = [](const std::string& p) {
        return p == "/etc/ssh/conf.d" ? std::string{"/mnt/shares"} : p;
    };
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/conf.d/root.conf\n");
    f.config_files["/etc/ssh/conf.d/root.conf"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "root.conf"));
    CHECK(std::ranges::count(f.resolved, "/etc/ssh/conf.d/root.conf") == 0);
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(l.rows[0] == "source|sshd_config|read|1");
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|-|-");

    // the config path is itself a link whose single readlink hop lands under a mount
    f = healthy();
    f.prefixes = std::vector<std::string>{"/net"};
    f.resolve = [](const std::string& p) {
        return p == "/etc/ssh/sshd_config" ? std::string{"/net/ssh/sshd_config"} : p;
    };
    f.config_files["/etc/ssh/sshd_config"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    CHECK(std::ranges::count(f.resolved, "/etc/ssh/sshd_config") == 1);
    CHECK_FALSE(touched_mentions(f, "sshd_config"));
    CHECK(has_token(l, "linux:remote_access_audit:sshd_config:network_mount_skipped"));
    CHECK(l.rows[0] == "source|sshd_config|failed|-");

    // an Include file that is a link into a mount (relative argument: SSHDIR-prefixed) is skipped likewise
    f = healthy();
    f.prefixes = std::vector<std::string>{"/net"};
    f.resolve = [](const std::string& p) { return p == "/etc/ssh/extra.conf" ? std::string{"/net/extra.conf"} : p; };
    f.config_files["/etc/ssh/sshd_config"] = ok("Include extra.conf\n");
    f.config_files["/etc/ssh/extra.conf"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    CHECK_FALSE(touched_mentions(f, "extra.conf"));
    CHECK(has_token(l, "linux:remote_access_audit:include:network_mount_skipped"));
    CHECK(l.rows[0] == "source|sshd_config|read|1");

    // segment boundary: /networking is not under the /network mount and is read
    f = healthy();
    f.prefixes = std::vector<std::string>{"/network"};
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /networking/x.conf\n");
    f.config_files["/networking/x.conf"] = ok("PermitRootLogin no\n");
    l = list_posix(f.build());
    CHECK(touched_mentions(f, "/networking/x.conf"));
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|no|include:x.conf");
    CHECK(l.status == StatusState::supported);

    // an unreadable mount table is ONE token, and the config half reads unguarded
    f = healthy();
    f.prefixes = std::nullopt;
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /network/ssh.conf\n");
    f.config_files["/network/ssh.conf"] = ok("PermitRootLogin yes\n");
    l = list_posix(f.build());
    const std::string unreadable = "linux:remote_access_audit:keys:mounts_unreadable";
    CHECK(touched_mentions(f, "/network/ssh.conf"));
    CHECK(row_with(l.rows, "config|permitrootlogin|") == "config|permitrootlogin|yes|include:ssh.conf");
    CHECK(l.reason.find(unreadable) != std::string::npos);
    CHECK(l.reason.find(unreadable) == l.reason.rfind(unreadable));
}

TEST_CASE("remote_access_audit legs: add_data_volume_aliases adds the other spelling of every mount prefix",
          "[remote_access_audit][legs]") {
    std::vector<std::string> p{"/System/Volumes/Data/Users/alice", "/Users/bob", "/"};
    add_data_volume_aliases(p);
    CHECK(p == std::vector<std::string>{"/System/Volumes/Data/Users/alice", "/Users/bob", "/", "/Users/alice",
                                        "/System/Volumes/Data/Users/bob"});

    // the Data volume's own root, a relative or empty entry and an empty table add nothing
    std::vector<std::string> none{"/System/Volumes/Data", "relative/path", ""};
    add_data_volume_aliases(none);
    CHECK(none.size() == 3);

    // a sibling directory that merely shares the name prefix is aliased as an ordinary path
    std::vector<std::string> sibling{"/System/Volumes/DataX/y"};
    add_data_volume_aliases(sibling);
    REQUIRE(sibling.size() == 2);
    CHECK(sibling[1] == "/System/Volumes/Data/System/Volumes/DataX/y");
}

TEST_CASE("remote_access_audit legs: a mount recorded under the macOS Data volume covers the firmlinked spelling",
          "[remote_access_audit][legs]") {
    // The fake hands list_posix the table as the kernel lists it (RAW): the macOS alias expansion
    // is list_posix's own step, so deleting it from the production path turns this test red.
    // The mount is named /System/Volumes/Data/Users/alice, the home is walked as /Users/alice. personal-data-ok: synthetic fixture account
    auto f = healthy_macos();
    f.prefixes = std::vector<std::string>{"/System/Volumes/Data/Users/alice"};
    f.homes = {HomeEntry{"alice", "/Users/alice"}, HomeEntry{"bob", "/Users/bob"}};
    f.account_probe = [](const HomeEntry&) { return true; };
    f.key_files["/Users/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    f.key_files["/Users/bob/.ssh/authorized_keys"] = ok(kAliceKey);
    auto l = list_posix(f.build());
    CHECK(f.mount_snapshot_first());
    CHECK(f.probe_calls == 1);                     // bob only: alice is never asked about
    CHECK(f.open_home_calls == 1);                 // bob only
    CHECK_FALSE(f.touched_under("/Users/alice"));  // not probed, opened or read
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|failed|-|-|-");
    CHECK(has_token(l, "macos:remote_access_audit:keys:network_mount_skipped"));
    CHECK(row_with(l.rows, "key|bob|") != "");     // the local home is still audited

    // negative control: the same RAW table on the Linux leg (no alias expansion) lets the home open
    f = healthy();
    f.roots = {"/Users"};
    f.prefixes = std::vector<std::string>{"/System/Volumes/Data/Users/alice"};
    f.homes = {HomeEntry{"alice", "/Users/alice"}};
    f.key_files["/Users/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(f.open_home_calls == 1);
    CHECK_FALSE(has_token(l, "linux:remote_access_audit:keys:network_mount_skipped"));

    // the other direction: a mount recorded as /Users/alice covers an absolute AuthorizedKeysFile
    // entry spelled through the Data volume, and the entry's reader is never called
    f = healthy_macos();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile /System/Volumes/Data/Users/alice/.ssh/k\n");
    f.prefixes = std::vector<std::string>{"/Users/alice"};
    f.homes = {HomeEntry{"bob", "/Users/bob"}};
    f.abs_files["/System/Volumes/Data/Users/alice/.ssh/k"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(f.key_reads == 0);
    CHECK_FALSE(f.touched_under("/System/Volumes/Data/Users/alice"));
    CHECK(row_with(l.rows, "file|bob|custom|") == "file|bob|custom|failed|-|-|-");
    CHECK(has_token(l, "macos:remote_access_audit:keys:network_mount_skipped"));
    CHECK(row_with(l.rows, "key|bob|").empty());

    // ... and a configured Include through the Data volume is covered the same way
    f = healthy_macos();
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /System/Volumes/Data/net/ssh.conf\n");
    f.config_files["/System/Volumes/Data/net/ssh.conf"] = ok("PermitRootLogin yes\n");
    f.prefixes = std::vector<std::string>{"/net"};
    l = list_posix(f.build());
    CHECK_FALSE(f.touched_under("/System/Volumes/Data/net"));
    CHECK(has_token(l, "macos:remote_access_audit:include:network_mount_skipped"));
}

TEST_CASE("remote_access_audit legs: service state arms", "[remote_access_audit][legs]") {
    auto f = healthy();
    f.runner = nullptr; // spawn_error: systemctl is not installed
    auto l = list_posix(f.build());
    CHECK(l.rows[2] == "source|service|failed|-");
    CHECK(kind_rows(l, "service").empty()); // never a `disabled` row
    CHECK(has_token(l, "linux:remote_access_audit:service:systemctl_unavailable"));

    f = healthy();
    f.runner = [](const std::vector<std::string>& args) {
        REQUIRE(args.size() == 2);
        REQUIRE(args[0] == "is-enabled");
        // REAL CAPTURE: rc and stdout as systemctl printed them
        if (args[1] == "ssh.service")
            return ran("not-found\n", 4);
        if (args[1] == "sshd.service")
            return ran("disabled\n", 1); // disabled exits 1: not a failure
        return ran("static\n", 0);
    };
    l = list_posix(f.build());
    CHECK(l.status == StatusState::supported);
    CHECK(row_with(l.rows, "service|ssh.service|") == "service|ssh.service|not-found|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|sshd.service|") == "service|sshd.service|disabled|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|ssh.socket|") == "service|ssh.socket|static|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|sshd.socket|") ==
          "service|sshd.socket|static|systemctl_is_enabled");

    f = healthy();
    f.runner = [](const std::vector<std::string>&) { return died(yuzu::agent::TerminationReason::deadline); };
    l = list_posix(f.build());
    CHECK(has_token(l, "subprocess_runner:deadline"));
    CHECK(row_with(l.rows, "service|ssh.service|") == "service|ssh.service|unknown|systemctl_is_enabled");
    CHECK(l.rows[2] == "source|service|failed|-");

    // MIXED: one unit answers, the others fail. A failed unit query makes the source `failed`
    // (clause 5); the unit that answered keeps its row, the failed ones say `unknown`, none `disabled`.
    f = healthy();
    f.runner = [](const std::vector<std::string>& args) {
        if (args[1] == "ssh.service")
            return ran("enabled\n", 0);
        return died(yuzu::agent::TerminationReason::deadline);
    };
    l = list_posix(f.build());
    CHECK(l.rows[2] == "source|service|failed|-");
    CHECK(row_with(l.rows, "service|ssh.service|") == "service|ssh.service|enabled|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|sshd.service|") == "service|sshd.service|unknown|systemctl_is_enabled");
    CHECK(has_token(l, "subprocess_runner:deadline"));
    CHECK(l.status == StatusState::constrained);
    // the same when the failing unit printed something unrecognised rather than timing out
    f.runner = [](const std::vector<std::string>& args) {
        return args[1] == "ssh.service" ? ran("enabled\n", 0) : ran("flibbertigibbet\n");
    };
    l = list_posix(f.build());
    CHECK(l.rows[2] == "source|service|failed|-");
    CHECK(has_token(l, "linux:remote_access_audit:service:unrecognised_output"));

    f = healthy();
    f.runner = [](const std::vector<std::string>&) {
        auto r = ran("enabled\n");
        r.output_truncated = true;
        return r;
    };
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:service:output_truncated"));

    f = healthy();
    f.runner = [](const std::vector<std::string>&) { return ran(""); };
    l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:service:no_output"));
    CHECK(row_with(l.rows, "service|ssh.service|") == "service|ssh.service|unknown|systemctl_is_enabled");
    f.runner = [](const std::vector<std::string>&) { return ran("flibbertigibbet\n"); };
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:service:unrecognised_output"));
}

TEST_CASE("remote_access_audit legs: macOS launchctl arm", "[remote_access_audit][legs]") {
    auto f = healthy_macos();
    f.runner = [](const std::vector<std::string>& args) {
        REQUIRE(args == std::vector<std::string>{"print-disabled", "system"});
        return ran("disabled services = {\n\t\"com.apple.ftpd\" => disabled\n\t\"com.openssh.sshd\" => enabled\n}\n");
    };
    auto l = list_posix(f.build());
    CHECK(l.status == StatusState::supported);
    CHECK(l.rows[2] == "source|service|read|1");
    CHECK(row_with(l.rows, "service|") == "service|com.openssh.sshd|enabled|launchctl_print_disabled");

    // no entry for the label is `unknown`, never `disabled`
    f.runner = [](const std::vector<std::string>&) { return ran("disabled services = {\n}\n"); };
    l = list_posix(f.build());
    CHECK(row_with(l.rows, "service|") == "service|com.openssh.sshd|unknown|launchctl_print_disabled");
    CHECK(l.status == StatusState::supported);

    f.runner = [](const std::vector<std::string>&) { return ran("usage: launchctl\n"); };
    CHECK(has_token(list_posix(f.build()), "macos:remote_access_audit:service:unrecognised_output"));
    f.runner = [](const std::vector<std::string>&) { return ran("", 64); };
    CHECK(has_token(list_posix(f.build()), "macos:remote_access_audit:service:exit_nonzero"));
    f.runner = nullptr;
    l = list_posix(f.build());
    CHECK(kind_rows(l, "service").empty());
    CHECK(has_token(l, "macos:remote_access_audit:service:launchctl_unavailable"));
}

TEST_CASE("remote_access_audit legs: malformed lines and unknown key types make the listing constrained",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.homes = {home("alice")};
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(std::string(kAliceKey) + "this is not a key\n");
    auto l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:keys:malformed"));
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|read|1|1|0");
    CHECK(l.status == StatusState::constrained);

    // A key of a type the plugin does not know is refused, counted malformed, never reported as
    // a key (its blob cannot be decoded completely); the listing says why with its own token.
    // CONSTRUCTED: an ssh-dss line whose blob leads with its own name.
    f = healthy();
    f.homes = {home("alice")};
    f.key_files["/home/alice/.ssh/authorized_keys"] =
        ok(std::string(kAliceKey) + "ssh-dss AAAAB3NzaC1kc3MAAAABAwAAAAEFAAAAAQcAAAABCw== c\n");
    l = list_posix(f.build());
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|read|1|1|0");
    CHECK(kind_rows(l, "key").size() == 1); // only the real key
    CHECK(has_token(l, "linux:remote_access_audit:keys:unknown_key_type"));
    CHECK(has_token(l, "linux:remote_access_audit:keys:malformed"));
    CHECK(l.status == StatusState::constrained);
    // plain garbage is malformed WITHOUT the unknown-type token
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(std::string(kAliceKey) + "this is not a key\n");
    CHECK_FALSE(has_token(list_posix(f.build()), "linux:remote_access_audit:keys:unknown_key_type"));
}

TEST_CASE("remote_access_audit legs: a partial homes listing still audits the homes it listed",
          "[remote_access_audit][legs]") {
    // One root listed, another refused: the homes source keeps its refused state and token, and
    // the listed home is still audited (its file and key rows), so evidence is not lost.
    auto f = healthy();
    f.homes = {home("alice")};
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    f.homes_err = EACCES;
    const auto l = list_posix(f.build());
    CHECK(l.rows[1] == "source|homes|refused|-|-");
    CHECK(has_token(l, "linux:remote_access_audit:homes:permission_denied"));
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|read|1|0|0");
    CHECK(kind_rows(l, "key").size() == 1);
    CHECK(l.status == StatusState::constrained);
}

TEST_CASE("remote_access_audit legs: partial sources decide the aggregate status",
          "[remote_access_audit][legs]") {
    // permission_denied means a refusal and NO source read. MUTATION: counting a mixed service
    // result (one unit answered, another failed) as a read source turns case A into constrained.
    auto f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = err(EACCES); // refused
    f.homes_err = ENOENT;                                  // no home root: absent
    f.runner = [](const std::vector<std::string>& args) {
        if (args[1] == "ssh.service")
            return ran("enabled\n", 0);
        return died(yuzu::agent::TerminationReason::deadline);
    };
    auto l = list_posix(f.build());
    CHECK(l.rows[2] == "source|service|failed|-");
    CHECK(has_token(l, "linux:remote_access_audit:sshd_config:permission_denied"));
    CHECK(l.status == StatusState::permission_denied);

    // Case B: nothing else was read, but a partial home listing recovered a readable key file.
    // That is partial evidence, so the aggregate is constrained, not permission_denied.
    // MUTATION: not counting a partial listing as a read source turns this into permission_denied.
    f = healthy();
    f.config_files.erase("/etc/ssh/sshd_config"); // absent
    f.runner = nullptr;                             // systemctl unavailable: the service source fails
    f.homes = {home("alice")};
    f.homes_err = EACCES;
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(l.rows[1] == "source|homes|refused|-|-");
    CHECK(kind_rows(l, "key").size() == 1);
    CHECK(has_token(l, "linux:remote_access_audit:homes:permission_denied"));
    CHECK(l.status == StatusState::constrained);
}

TEST_CASE("remote_access_audit legs: file read failures are states with their own tokens",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.homes = {home("alice")};
    f.key_files["/home/alice/.ssh/authorized_keys"] = FileReadLike{{}, ReadErr::symlink_refused, 0};
    f.key_files["/home/alice/.ssh/authorized_keys2"] = FileReadLike{{}, ReadErr::oversized, 0};
    auto l = list_posix(f.build());
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|failed|-|-|-");
    CHECK(row_with(l.rows, "file|alice|authorized_keys2|") == "file|alice|authorized_keys2|failed|-|-|-");
    CHECK(has_token(l, "linux:remote_access_audit:keys:symlink_refused"));
    CHECK(has_token(l, "linux:remote_access_audit:keys:oversized"));
    CHECK_FALSE(has_token(l, "linux:remote_access_audit:keys:oversized_line")); // a different token; a whole-file cap
    f.key_files["/home/alice/.ssh/authorized_keys"] = err(ENOTDIR);
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:keys:enotdir"));
    f.key_files["/home/alice/.ssh/authorized_keys"] = err(EACCES);
    l = list_posix(f.build());
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|refused|-|-|-");
    CHECK(has_token(l, "linux:remote_access_audit:keys:permission_denied"));
}

TEST_CASE("remote_access_audit legs: homes listing failures, the cap and a vanished home",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.homes_err = EACCES;
    auto l = list_posix(f.build());
    CHECK(l.rows[1] == "source|homes|refused|-|-");
    CHECK(has_token(l, "linux:remote_access_audit:homes:permission_denied"));
    CHECK(l.status == StatusState::constrained);

    f = healthy();
    f.homes_err = ENOENT;
    l = list_posix(f.build());
    CHECK(l.rows[1] == "source|homes|absent|-|-");
    CHECK(l.status == StatusState::supported);

    f = healthy();
    f.homes = {home("alice")};
    f.homes_too_many = true;
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:homes:too_many"));

    // a home that vanished between the listing and the open is skipped silently
    f = healthy();
    f.homes = {home("alice"), home("ghost")};
    f.open_err["/home/ghost"] = ENOENT;  // personal-data-ok: synthetic fixture account
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    l = list_posix(f.build());
    CHECK(l.status == StatusState::supported);
    CHECK(row_with(l.rows, "file|ghost|").empty());
}

TEST_CASE("remote_access_audit legs: the row budget is dispatch-wide and the fixed rows always fit",
          "[remote_access_audit][legs]") {
    // 400 accounts x 5 entries = 2000 file rows plus the fixed rows: over the 2048-row cap.
    auto f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile a b c d e\n");
    for (int i = 0; i < 450; ++i) {
        f.homes.push_back(home("u" + std::to_string(i)));
        f.open_err["/home/u" + std::to_string(i)] = ENOTDIR; // failed rows cost no read attempt
    }
    auto l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:keys:row_cap"));
    CHECK(l.rows.size() <= kMaxRows);
    CHECK(kind_rows(l, "source").size() == 3);
    CHECK(kind_rows(l, "config").size() == 14);
    CHECK(kind_rows(l, "service").size() == 4);

    // the byte budget binds first for long account names (4 KiB each, cut on the wire)
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile a b\n");
    for (int i = 0; i < 300; ++i) {
        f.homes.push_back(HomeEntry{std::string(5000, 'a' + (i % 26)) + std::to_string(i), "/home/h" + std::to_string(i)});  // personal-data-ok: synthetic fixture account
        f.open_err["/home/h" + std::to_string(i)] = ENOTDIR;  // personal-data-ok: synthetic fixture account
    }
    l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:keys:row_cap"));
    CHECK(has_token(l, "linux:remote_access_audit:keys:field_oversized"));
    CHECK(l.rows.size() < 600);

    // the byte budget counts the ESCAPED account: a 255-byte pipe basename is 510 bytes on the wire in
    // every key row, and 1900 valid key lines would otherwise be charged for half of it (1,143,023
    // bytes admitted against 1 MiB with no token)
    f = healthy();
    f.homes = {HomeEntry{std::string(255, '|'), "/home/pipes"}};  // personal-data-ok: synthetic fixture account
    std::string many_keys;
    for (int i = 0; i < 1900; ++i)
        many_keys += kAliceKey;
    f.key_files["/home/pipes/.ssh/authorized_keys"] = ok(many_keys);  // personal-data-ok: synthetic fixture account
    l = list_posix(f.build());
    std::size_t wire_bytes = 0;
    for (const auto& r : l.rows)
        wire_bytes += r.size();
    CHECK(has_token(l, "linux:remote_access_audit:keys:row_cap"));
    CHECK(wire_bytes <= kMaxBytes); // every emitted row, status/source/config/service/file/key alike
    CHECK(kind_rows(l, "key").size() < 1900);
    CHECK(kind_rows(l, "source").size() == 3);

    // the file-read attempt cap: 300 accounts x 5 entries would be 1500 reads; 1024 are made
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("AuthorizedKeysFile a b c d e\n");
    for (int i = 0; i < 300; ++i)
        f.homes.push_back(home("u" + std::to_string(i)));
    l = list_posix(f.build());
    CHECK(f.key_reads == static_cast<int>(kMaxKeyFileAttempts));
    CHECK(has_token(l, "linux:remote_access_audit:keys:file_cap"));
}

// MUTATION: reading stdout only (merge_stderr false, or the stderr branch dropped) turns every unit a
// Debian/Ubuntu/RHEL host does not have into `no_output`, so a packaged host is permanently CONSTRAINED.
TEST_CASE("remote_access_audit legs: a unit systemd 249/252 reports on stderr is not-found, not a failure",
          "[remote_access_audit][legs]") {
    // REAL CAPTURE (debian:12 systemd 252.39, ubuntu:22.04 systemd 249.11), openssh-server NOT installed:
    // stdout empty, exit 1, this one line on stderr -- merged into the captured output by the runner.
    auto f = healthy();
    f.runner = [](const std::vector<std::string>& args) {
        REQUIRE(args.size() == 2);
        return ran("Failed to get unit file state for " + args[1] + ": No such file or directory\n", 1);
    };
    auto l = list_posix(f.build());
    CHECK(l.status == StatusState::supported);
    CHECK(l.reason.empty());
    CHECK(l.rows[2] == "source|service|read|4");
    CHECK(row_with(l.rows, "service|ssh.service|") == "service|ssh.service|not-found|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|sshd.service|") == "service|sshd.service|not-found|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|ssh.socket|") == "service|ssh.socket|not-found|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|sshd.socket|") ==
          "service|sshd.socket|not-found|systemctl_is_enabled");
    // the runner is asked for stderr: without it the line above is never seen
    REQUIRE(f.merge_flags.size() == 4);
    CHECK(std::ranges::all_of(f.merge_flags, [](bool m) { return m; }));

    // REAL CAPTURE (same containers) AFTER `apt-get install openssh-server`: ssh.service enabled (exit 0),
    // sshd.service an alias (0), ssh.socket disabled (exit 1). Not a failure, whatever the exit code.
    f = healthy();
    f.runner = [](const std::vector<std::string>& args) {
        if (args[1] == "ssh.service")
            return ran("enabled\n", 0);
        if (args[1] == "sshd.service")
            return ran("alias\n", 0);
        return ran("disabled\n", 1);
    };
    l = list_posix(f.build());
    CHECK(l.status == StatusState::supported);
    CHECK(row_with(l.rows, "service|ssh.service|") == "service|ssh.service|enabled|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|sshd.service|") == "service|sshd.service|alias|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|ssh.socket|") == "service|ssh.socket|disabled|systemctl_is_enabled");
    CHECK(row_with(l.rows, "service|sshd.socket|") ==
          "service|sshd.socket|disabled|systemctl_is_enabled");

    // narrow: another stderr line that merely contains the words, or the right line on exit 0, is still a failure
    f = healthy();
    f.runner = [](const std::vector<std::string>&) { return ran("Failed to connect to bus: No such file or directory\n", 1); };
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:service:unrecognised_output"));
    f.runner = [](const std::vector<std::string>& args) {
        return ran("Failed to get unit file state for " + args[1] + ": No such file or directory\n", 0);
    };
    CHECK(has_token(list_posix(f.build()), "linux:remote_access_audit:service:unrecognised_output"));

    // launchctl stays stdout-only (its diagnostics are not the answer)
    f = healthy_macos();
    list_posix(f.build());
    REQUIRE(f.merge_flags.size() == 1);
    CHECK_FALSE(f.merge_flags[0]);
}

// MUTATION: dropping the OTHER_CREDENTIAL flag from audit_config (or the keyword from the closed set)
// leaves a CA-trust / command-keys host reading `supported` with zero key rows -- asserted on the WIRE
// (status + token + the paired reason), not on a parser flag.
TEST_CASE("remote_access_audit legs: a credential source the plugin does not read is never a clean supported",
          "[remote_access_audit][legs]") {
    const std::string tok = "linux:remote_access_audit:sshd_config:other_credential_sources";
    for (const char* line :
         {"TrustedUserCAKeys /etc/ssh/zq-ca-9731.pub", "AuthorizedKeysCommand /usr/local/bin/zq-keys-9731 %u",
          "AuthorizedPrincipalsFile /etc/ssh/zq-principals-9731/%u", "AuthorizedPrincipalsCommand /usr/bin/zq-9731",
          "HostbasedAuthentication yes", "AuthenticationMethods publickey,keyboard-interactive"}) {
        INFO(line);
        auto f = healthy();
        f.config_files["/etc/ssh/sshd_config"] = ok(std::string("PermitRootLogin no\n") + line + "\n");
        f.homes = {home("alice")};
        f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
        const auto l = list_posix(f.build());
        CHECK(l.status == StatusState::constrained);
        CHECK(has_token(l, tok));
        CHECK(row_with(l.rows, "key|alice|") != ""); // the keys it does read are still reported
        CHECK_FALSE(leaks(l, "zq-")); // presence only: no value and no path reaches any row or the reason
    }
    // the same token through an Include, and on macOS under its own prefix
    auto f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("Include /etc/ssh/ca.conf\n");
    f.config_files["/etc/ssh/ca.conf"] = ok("TrustedUserCAKeys /etc/ssh/ca.pub\n");
    CHECK(has_token(list_posix(f.build()), tok));
    f.os = "macos";
    f.launchd = true;
    f.runner = [](const std::vector<std::string>&) { return ran("disabled services = {\n}\n"); };
    CHECK(has_token(list_posix(f.build()), "macos:remote_access_audit:sshd_config:other_credential_sources"));

    // controls: the disabling values, a Match-scoped directive and an unread config raise nothing
    for (const char* text : {"AuthorizedKeysCommand none\nHostbasedAuthentication no\n"
                             "AuthenticationMethods any\nTrustedUserCAKeys none\n"
                             "AuthorizedPrincipalsFile none\nAuthorizedPrincipalsCommand none\n",
                             "Match User bob\n  TrustedUserCAKeys /etc/ssh/ca.pub\n"}) {
        f = healthy();
        f.config_files["/etc/ssh/sshd_config"] = ok(text);
        const auto l = list_posix(f.build());
        CHECK(l.status == StatusState::supported);
    }
    f = healthy();
    f.config_files.clear(); // sshd_config absent: nothing was read, so nothing is claimed
    CHECK_FALSE(has_token(list_posix(f.build()), tok));
}

// MUTATION: dropping `gssapiauthentication` from kScalarKeys leaves a global
// `GSSAPIAuthentication yes` with no row and no token. It is a login METHOD like password auth:
// reported as written, supported, no token.
TEST_CASE("remote_access_audit legs: GSSAPIAuthentication is reported as written, not flagged",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.config_files["/etc/ssh/sshd_config"] = ok("GSSAPIAuthentication yes\n");
    const auto l = list_posix(f.build());
    CHECK(l.status == StatusState::supported);
    CHECK(l.reason.empty());
    CHECK(row_with(l.rows, "config|gssapiauthentication|") ==
          "config|gssapiauthentication|yes|sshd_config");

    // first wins in directive order and carries its Include origin: a Match-scoped `yes` in the
    // first Include is not global, the second Include's `no` is the first global value, and the
    // main file's later `yes` loses.
    // MUTATIONS: last-wins reports yes|sshd_config; applying a Match-scoped value reports
    // yes|include:h.conf.
    f = healthy();
    f.config_files["/etc/ssh/sshd_config"] =
        ok("Include /etc/ssh/h.conf\nInclude /etc/ssh/g.conf\nGSSAPIAuthentication yes\n");
    f.config_files["/etc/ssh/h.conf"] = ok("Match User bob\n  GSSAPIAuthentication yes\n");
    f.config_files["/etc/ssh/g.conf"] = ok("GSSAPIAuthentication no\n");
    const auto first_wins = list_posix(f.build());
    CHECK(first_wins.status == StatusState::supported);
    CHECK(first_wins.reason.empty());
    CHECK(row_with(first_wins.rows, "config|gssapiauthentication|") ==
          "config|gssapiauthentication|no|include:g.conf");
}

// MUTATION: matching a closed-set keyword by prefix (`starts_with` in place of the exact lookup in
// parse_sshd_config) turns every look-alike below that extends a closed-set keyword into a false
// `other_credential_sources`; each carries a non-inert value, so only the keyword match can keep it
// quiet. HostbasedAcceptedAlgorithms is a real keyword that diverges from hostbasedauthentication,
// so it stays quiet under the mutation and is kept as the real-name case; the look-alike that
// extends it is HostbasedAuthenticationX. AuthorizedKeysCommandUser and
// AuthorizedPrincipalsCommandUser are real sshd keywords; the rest are CONSTRUCTED look-alikes.
TEST_CASE("remote_access_audit legs: a keyword that resembles a credential keyword raises nothing",
          "[remote_access_audit][legs]") {
    const std::string tok = "linux:remote_access_audit:sshd_config:other_credential_sources";
    for (const char* line :
         {"TrustedUserCAKeysFile /etc/ssh/zq-ca-9731.pub", "AuthorizedKeysCommandUser zq-9731",
          "AuthorizedPrincipalsFileX /etc/ssh/zq-principals-9731",
          "AuthorizedPrincipalsCommandUser zq-9731", "AuthenticationMethodsExtra publickey",
          "HostbasedAcceptedAlgorithms ssh-ed25519", "HostbasedAuthenticationX yes"}) {
        INFO(line);
        auto f = healthy();
        f.config_files["/etc/ssh/sshd_config"] =
            ok(std::string("PermitRootLogin no\n") + line + "\n");
        f.homes = {home("alice")};
        f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
        const auto l = list_posix(f.build());
        CHECK(l.status == StatusState::supported);
        CHECK_FALSE(has_token(l, tok));
        CHECK(l.reason.find("other_credential_sources") == std::string::npos);
        CHECK(row_with(l.rows, "key|alice|") != "");
    }
}

// MUTATION: removing the skipped-home count (or the probe wiring) puts `-`/0 on the wire for a Mac whose
// hidden uid<500 account holds a key, so the exclusion is invisible to the caller.
TEST_CASE("remote_access_audit legs: the homes row counts the entries the eligibility probe refused",
          "[remote_access_audit][legs]") {
    // Shared (uid 0) and a hidden service account (uid 400) are positively not accounts; alice is
    auto f = healthy_macos();
    f.homes = {HomeEntry{"Shared", "/Users/Shared"}, HomeEntry{"_hidden", "/Users/_hidden"}, HomeEntry{"alice", "/Users/alice"}};  // personal-data-ok: synthetic fixture account
    f.account_probe = [](const HomeEntry& h) { return h.name == "alice"; };
    f.key_files["/Users/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    f.key_files["/Users/_hidden/.ssh/authorized_keys"] = ok(kAliceKey); // never read: not an account personal-data-ok: synthetic fixture account
    auto l = list_posix(f.build());
    CHECK(l.rows[1] == "source|homes|read|1|2");
    CHECK(row_with(l.rows, "file|_hidden|").empty());
    CHECK_FALSE(f.touched_under("/Users/_hidden/"));  // personal-data-ok: synthetic fixture account
    CHECK(kind_rows(l, "key").size() == 1);

    // every home an account: the count is a real 0, not `-`
    f = healthy_macos();
    f.homes = {HomeEntry{"alice", "/Users/alice"}};
    f.account_probe = [](const HomeEntry&) { return true; };
    CHECK(list_posix(f.build()).rows[1] == "source|homes|read|1|0");

    // a network-mounted home is not probed, so it is neither counted as skipped nor as refused-by-probe
    f = healthy_macos();
    f.homes = {HomeEntry{"nfsuser", "/Users/nfsuser"}, HomeEntry{"Shared", "/Users/Shared"}};  // personal-data-ok: synthetic fixture account
    f.prefixes = std::vector<std::string>{"/Users/nfsuser"};  // personal-data-ok: synthetic fixture account
    f.account_probe = [](const HomeEntry&) { return false; };
    l = list_posix(f.build());
    CHECK(l.rows[1] == "source|homes|read|1|1");

    // roots that were never listed carry `-` for both counts
    f = healthy_macos();
    f.homes_err = EACCES;
    f.account_probe = [](const HomeEntry&) { return true; };
    CHECK(list_posix(f.build()).rows[1] == "source|homes|refused|-|-");
    f = healthy_macos();
    f.homes_err = ENOENT;
    f.account_probe = [](const HomeEntry&) { return true; };
    CHECK(list_posix(f.build()).rows[1] == "source|homes|absent|-|-");
}

// MUTATION: counting only the directives that read a file lets a config of many non-matching globs
// re-list a 4096-entry directory once per line, pinning a shared command worker.
TEST_CASE("remote_access_audit legs: every Include directive counts against the cap, read or not",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    std::string cfg;
    for (int i = 0; i < 200; ++i)
        cfg += "Include /etc/ssh/d/*.nomatch\n"; // lists the directory, matches nothing, reads nothing
    f.config_files["/etc/ssh/sshd_config"] = ok(cfg);
    f.listings["/etc/ssh/d|*.nomatch"] = {};
    const auto l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:include:too_many"));
    CHECK(std::ranges::count(f.touched, "/etc/ssh/d") == static_cast<long>(kMaxIncludeFiles)); // listed 32 times, not 200
    CHECK(l.rows[0] == "source|sshd_config|read|1"); // nothing beyond the main file was read

    // under the cap nothing is reported: exactly kMaxIncludeFiles directives are fine
    f = healthy();
    cfg.clear();
    for (std::size_t i = 0; i < kMaxIncludeFiles; ++i)
        cfg += "Include /etc/ssh/d/*.nomatch\n";
    f.config_files["/etc/ssh/sshd_config"] = ok(cfg);
    f.listings["/etc/ssh/d|*.nomatch"] = {};
    const auto ok_l = list_posix(f.build());
    CHECK(ok_l.status == StatusState::supported);
}

// The cap counts ARGUMENTS (one IncludeDirective per pattern), not `Include` lines: one line with
// 32 patterns is at the cap and one with 33 is over it, in the same single directive.
TEST_CASE("remote_access_audit legs: one Include line counts every pattern against the cap",
          "[remote_access_audit][legs]") {
    const auto one_line = [](std::size_t patterns) {
        auto f = healthy();
        std::string cfg = "Include";
        for (std::size_t i = 0; i < patterns; ++i)
            cfg += " /etc/ssh/d/*.nomatch";
        f.config_files["/etc/ssh/sshd_config"] = ok(cfg + "\n");
        f.listings["/etc/ssh/d|*.nomatch"] = {};
        return std::pair{list_posix(f.build()), std::ranges::count(f.touched, "/etc/ssh/d")};
    };
    const auto [at_cap, at_cap_lists] = one_line(kMaxIncludeFiles);
    CHECK(at_cap_lists == static_cast<long>(kMaxIncludeFiles));
    CHECK(at_cap.status == StatusState::supported);

    const auto [over_cap, over_cap_lists] = one_line(kMaxIncludeFiles + 1);
    CHECK(has_token(over_cap, "linux:remote_access_audit:include:too_many"));
    CHECK(over_cap_lists == static_cast<long>(kMaxIncludeFiles)); // the 33rd is never listed
}

TEST_CASE("remote_access_audit legs: AuthorizedKeysFile tokens beyond the cap are dropped with a token",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    std::string cfg = "AuthorizedKeysFile";
    for (std::size_t i = 0; i < kMaxAuthorizedKeysFileTokens + 40; ++i)
        cfg += " k" + std::to_string(i);
    f.config_files["/etc/ssh/sshd_config"] = ok(cfg + "\n");
    f.homes = {home("alice")};
    const auto l = list_posix(f.build());
    CHECK(has_token(l, "linux:remote_access_audit:keys:path_token_cap"));
    CHECK(f.key_reads == static_cast<int>(kMaxAuthorizedKeysFileTokens)); // one read per kept token, none for the 40 dropped
    CHECK(row_with(l.rows, "config|authorizedkeysfile|") ==
          "config|authorizedkeysfile|custom:" + std::to_string(kMaxAuthorizedKeysFileTokens + 40) + "|sshd_config");
}

// MUTATION: charging the file row AFTER the parse (the old order) drops the file row and every key row
// already admitted when one subject-authored file saturates the dispatch budget (2,100 lines -> zero rows).
TEST_CASE("remote_access_audit legs: a file that saturates the row budget keeps its first keys and its file row",
          "[remote_access_audit][legs]") {
    const std::size_t fixed = kSourceRows + 14 + 4; // source + config + service rows
    for (const std::size_t n : {std::size_t{1900}, std::size_t{2020}, std::size_t{2100}}) {
        INFO("lines in alice's file: " << n);
        auto f = healthy();
        f.homes = {home("alice"), home("bob")};
        std::string many;
        for (std::size_t i = 0; i < n; ++i)
            many += kAliceKey;
        f.key_files["/home/alice/.ssh/authorized_keys"] = ok(many);
        f.key_files["/home/bob/.ssh/authorized_keys"] = ok(kAliceKey);
        const auto l = list_posix(f.build());
        CHECK(l.rows.size() <= kMaxRows);
        const auto keys = kind_rows(l, "key").size();
        // alice's file row is charged first (one row), then her key rows, then the rows that follow
        const std::size_t room = kMaxRows - fixed - 1;
        if (n <= room - 3) { // her keys, her authorized_keys2 row, bob's three rows all fit
            CHECK(keys == n + 1);
            CHECK(row_with(l.rows, "file|alice|authorized_keys|") ==
                  "file|alice|authorized_keys|read|" + std::to_string(n) + "|0|0");
            CHECK(l.status == StatusState::supported);
        } else { // saturated: first N kept, the file row says how many, the cap is a token, nothing is dropped whole
            CHECK(keys == room);
            CHECK(row_with(l.rows, "file|alice|authorized_keys|") ==
                  "file|alice|authorized_keys|read|" + std::to_string(room) + "|0|0");
            CHECK(has_token(l, "linux:remote_access_audit:keys:row_cap"));
        }
    }
}

// MUTATION: removing the nested-mount guard on the key path turns this red (governance r1).
TEST_CASE("remote_access_audit legs: a key path under a nested mount is never read, though its home is local",
          "[remote_access_audit][legs]") {
    auto f = healthy();
    f.homes = {home("alice")};
    f.prefixes = std::vector<std::string>{"/home/alice/.ssh"}; // .ssh is an NFS mount inside a local home
    f.key_files["/home/alice/.ssh/authorized_keys"] = ok(kAliceKey);
    f.key_files["/home/alice/.ssh/authorized_keys2"] = ok(kAliceKey);
    const auto l = list_posix(f.build());
    CHECK(f.open_home_calls == 1); // the home itself is local and is opened
    CHECK(f.key_reads == 0);       // neither key path is read
    CHECK_FALSE(f.touched_under("/home/alice/.ssh"));
    CHECK(row_with(l.rows, "file|alice|authorized_keys|") == "file|alice|authorized_keys|failed|-|-|-");
    CHECK(row_with(l.rows, "file|alice|authorized_keys2|") == "file|alice|authorized_keys2|failed|-|-|-");
    CHECK(has_token(l, "linux:remote_access_audit:keys:network_mount_skipped"));
    CHECK(kind_rows(l, "key").empty());
    CHECK_FALSE(leaks(l, "/home/alice/.ssh"));
    CHECK(l.status == StatusState::constrained);
}

TEST_CASE("remote_access_audit legs: the documented limits are pinned", "[remote_access_audit][legs]") {
    static_assert(kMaxRows == 2048);
    static_assert(kMaxBytes == 1024 * 1024);
    static_assert(kMaxFieldBytes == 4096);
    static_assert(kMaxKeyLine == 16 * 1024);
    static_assert(kMaxIncludeDepth == 4);
    static_assert(kMaxIncludeFiles == 32);
    static_assert(kMaxAuthorizedKeysFileTokens == 100);
    static_assert(kMaxHomes == 512);
    static_assert(kMaxKeyFileAttempts == 1024);
    static_assert(kKeyFileCap == 1024 * 1024);
    static_assert(kConfigFileCap == 256 * 1024);
    static_assert(kMaxDirEntries == 4096);
    SUCCEED();
}
