#include <yuzu/server/auto_approve.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#ifdef _WIN32
// clang-format off
#include <winsock2.h>  // must precede windows.h (which ws2tcpip.h pulls in)
#include <ws2tcpip.h>
// clang-format on
#else
#include <arpa/inet.h>
#endif

namespace yuzu::server::auth {

namespace {

std::string rule_type_to_string(AutoApproveRuleType t) {
    switch (t) {
    case AutoApproveRuleType::trusted_ca:
        return "trusted_ca";
    case AutoApproveRuleType::hostname_glob:
        return "hostname_glob";
    case AutoApproveRuleType::ip_subnet:
        return "ip_subnet";
    case AutoApproveRuleType::cloud_provider:
        return "cloud_provider";
    }
    return "unknown";
}

// Prefix length 0-32 from 1-2 ASCII digits; nullopt otherwise (no stoi, never throws).
std::optional<int> parse_prefix_len(std::string_view s) {
    if (s.empty() || s.size() > 2)
        return std::nullopt;
    int n = 0;
    for (char c : s) {
        if (c < '0' || c > '9')
            return std::nullopt;
        n = n * 10 + (c - '0');
    }
    if (n > 32)
        return std::nullopt;
    return n;
}

bool has_delimiter_or_control(std::string_view s) {
    return std::any_of(s.begin(), s.end(), [](unsigned char c) {
        return c == ':' || c < 0x20 || c == 0x7f;
    });
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // anonymous namespace

std::optional<AutoApproveRuleType> parse_auto_approve_rule_type(std::string_view s) {
    if (s == "trusted_ca")
        return AutoApproveRuleType::trusted_ca;
    if (s == "hostname_glob")
        return AutoApproveRuleType::hostname_glob;
    if (s == "ip_subnet")
        return AutoApproveRuleType::ip_subnet;
    if (s == "cloud_provider")
        return AutoApproveRuleType::cloud_provider;
    return std::nullopt;
}

std::string validate_auto_approve_rule(AutoApproveRuleType type, std::string_view value,
                                       std::string_view label) {
    if (value.empty())
        return "value is required";
    if (value.size() > kMaxRuleValueLen)
        return "value is too long";
    if (label.size() > kMaxRuleLabelLen)
        return "label is too long";
    if (has_delimiter_or_control(value))
        return "value must not contain ':' or control characters";
    if (has_delimiter_or_control(label))
        return "label must not contain ':' or control characters";
    if (type == AutoApproveRuleType::trusted_ca) {
        const bool hex64 = value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
                               return std::isxdigit(c) != 0;
                           });
        if (!hex64)
            return "trusted_ca value must be a 64-character hex SHA-256 fingerprint";
    } else if (type == AutoApproveRuleType::hostname_glob) {
        if (value.find_first_not_of('*') == std::string_view::npos)
            return "hostname_glob must not match every host";
    } else if (type == AutoApproveRuleType::ip_subnet) {
        const auto slash = value.find('/');
        const std::string net(value.substr(0, slash));
        struct in_addr a{};
        if (inet_pton(AF_INET, net.c_str(), &a) != 1)
            return "ip_subnet value must be an IPv4 address or CIDR";
        if (slash != std::string_view::npos) {
            const auto prefix = parse_prefix_len(value.substr(slash + 1));
            if (!prefix)
                return "ip_subnet prefix must be 0-32";
            if (*prefix == 0)
                return "ip_subnet must not match every address";
        }
    }
    return {};
}

// ── Persistence ──────────────────────────────────────────────────────────────

bool AutoApproveEngine::load(const std::filesystem::path& path) {
    config_path_ = path;

    std::ifstream f(path);
    if (!f.is_open())
        return false;

    // Parse into temporaries: the live policy is replaced only by a file that is entirely
    // well-formed. A torn or hand-edited line must never silently widen admission (a bad
    // `mode:` reading as `any`, or an unknown-type line vanishing from an `all` conjunction).
    std::vector<AutoApproveRule> parsed;
    bool require_all = false;
    bool malformed = false;

    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') // a hand-edited CRLF file
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;

        // mode:any or mode:all - exactly, nothing else
        if (line.starts_with("mode:")) {
            const auto m = std::string_view(line).substr(5);
            if (m == "any" || m == "all") {
                require_all = (m == "all");
            } else {
                malformed = true;
            }
            continue;
        }

        // type:value:label:enabled
        std::istringstream ss(line);
        std::string type_s, value, label, enabled_s;
        std::getline(ss, type_s, ':');
        const bool has_value = static_cast<bool>(std::getline(ss, value, ':'));
        std::getline(ss, label, ':');
        std::getline(ss, enabled_s, ':');

        // An unknown type is never defaulted to another (broader) type.
        const auto parsed_type = parse_auto_approve_rule_type(type_s);
        if (!parsed_type || !has_value) {
            malformed = true;
            continue;
        }
        AutoApproveRule rule;
        rule.type = *parsed_type;
        rule.value = value;
        rule.label = label;
        rule.enabled = enabled_s.empty() || enabled_s == "1";
        parsed.push_back(std::move(rule));
    }
    f.close();

    std::lock_guard lock(mu_);
    if (malformed) {
        // Zero rules in mode `any`: evaluate() matches nothing, so agents wait for a human.
        // Keep the original bytes - a later save would otherwise overwrite them.
        rules_.clear();
        require_all_ = false;
        std::error_code ec;
        std::filesystem::rename(path, path.string() + ".rejected", ec);
        spdlog::error("Auto-approve policy {} has a malformed line; no auto-approve rules are "
                      "active. The file was {} - re-create the rules in Settings.",
                      path.string(),
                      ec ? "left in place (rename to .rejected failed: " + ec.message() + ")"
                         : "kept as " + path.string() + ".rejected");
        return true;
    }
    rules_ = std::move(parsed);
    require_all_ = require_all;
    spdlog::info("Loaded {} auto-approve rules from {}", rules_.size(), path.string());
    return true;
}

bool AutoApproveEngine::save() const {
    std::lock_guard lock(mu_);
    return write_locked(rules_, require_all_);
}

// Must be called with mu_ held.
bool AutoApproveEngine::write_locked(const std::vector<AutoApproveRule>& rules,
                                     bool require_all) const {
    if (config_path_.empty())
        return true;

    // Temp file + rename: a crash or a full disk mid-write must never leave a torn live
    // file (a truncated `mode:` or glob line would load as a different, wider policy).
    const auto tmp = std::filesystem::path(config_path_.string() + ".tmp");
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f.is_open()) {
            spdlog::error("Failed to save auto-approve config to {}", tmp.string());
            return false;
        }
        f << "# Yuzu Auto-Approve Policies\n";
        f << "# Format: type:value:label:enabled\n";
        f << "mode:" << (require_all ? "all" : "any") << "\n";
        for (const auto& rule : rules) {
            f << rule_type_to_string(rule.type) << ":" << rule.value << ":" << rule.label << ":"
              << (rule.enabled ? "1" : "0") << "\n";
        }
        f.flush();
        if (!f.good()) {
            spdlog::error("Failed to write auto-approve config to {}", tmp.string());
            f.close();
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            return false;
        }
    }
    std::error_code ec;
    std::filesystem::rename(tmp, config_path_, ec);
    if (ec) {
        spdlog::error("Failed to replace auto-approve config {}: {}", config_path_.string(),
                      ec.message());
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}

// ── Evaluation ───────────────────────────────────────────────────────────────

std::string AutoApproveEngine::evaluate(const ApprovalContext& ctx) const {
    std::lock_guard lock(mu_);

    if (rules_.empty())
        return {};

    if (require_all_) {
        // All enabled rules must match
        for (const auto& rule : rules_) {
            if (!rule.enabled)
                continue;
            if (!match_rule(rule, ctx))
                return {};
        }
        // All matched — return first rule's label as reference
        for (const auto& rule : rules_) {
            if (rule.enabled)
                return rule.label.empty() ? "(all rules)" : rule.label;
        }
        return {};
    }

    // Any mode — first match wins
    for (const auto& rule : rules_) {
        if (!rule.enabled)
            continue;
        if (match_rule(rule, ctx)) {
            return rule.label.empty() ? rule_type_to_string(rule.type) + ":" + rule.value
                                      : rule.label;
        }
    }
    return {};
}

bool AutoApproveEngine::match_rule(const AutoApproveRule& rule, const ApprovalContext& ctx) const {
    switch (rule.type) {
    case AutoApproveRuleType::trusted_ca:
        return !ctx.ca_fingerprint_sha256.empty() &&
               to_lower(ctx.ca_fingerprint_sha256) == to_lower(rule.value);

    case AutoApproveRuleType::hostname_glob:
        return match_hostname_glob(rule.value, ctx.hostname);

    case AutoApproveRuleType::ip_subnet:
        return match_ip_subnet(rule.value, ctx.peer_ip);

    case AutoApproveRuleType::cloud_provider:
        return !ctx.attestation_provider.empty() &&
               to_lower(ctx.attestation_provider) == to_lower(rule.value);
    }
    return false;
}

// ── Glob matching ────────────────────────────────────────────────────────────

bool AutoApproveEngine::match_hostname_glob(const std::string& pattern,
                                            const std::string& hostname) const {
    auto p = to_lower(pattern);
    auto h = to_lower(hostname);

    // Simple glob: * matches any sequence of characters
    size_t pi = 0, hi = 0;
    size_t star_p = std::string::npos, star_h = 0;

    while (hi < h.size()) {
        if (pi < p.size() && (p[pi] == h[hi] || p[pi] == '?')) {
            ++pi;
            ++hi;
        } else if (pi < p.size() && p[pi] == '*') {
            star_p = pi++;
            star_h = hi;
        } else if (star_p != std::string::npos) {
            pi = star_p + 1;
            hi = ++star_h;
        } else {
            return false;
        }
    }

    while (pi < p.size() && p[pi] == '*')
        ++pi;
    return pi == p.size();
}

// ── CIDR subnet matching ─────────────────────────────────────────────────────

bool AutoApproveEngine::match_ip_subnet(const std::string& cidr, const std::string& ip) const {
    // Parse CIDR: "10.0.0.0/8"
    auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        // Exact IP match
        return ip == cidr;
    }

    auto net_str = cidr.substr(0, slash);
    // Fail closed: a malformed/out-of-range prefix never matches and never throws
    // (this runs under mu_ on the Register path).
    const auto parsed_prefix = parse_prefix_len(std::string_view(cidr).substr(slash + 1));
    if (!parsed_prefix)
        return false;
    const int prefix_len = *parsed_prefix;

    // Parse both IPs as IPv4
    struct in_addr net_addr{}, ip_addr{};
    if (inet_pton(AF_INET, net_str.c_str(), &net_addr) != 1)
        return false;
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1)
        return false;

    // Apply prefix mask
    uint32_t net = ntohl(net_addr.s_addr);
    uint32_t addr = ntohl(ip_addr.s_addr);
    uint32_t mask = prefix_len == 0 ? 0 : (~uint32_t{0}) << (32 - prefix_len);

    return (net & mask) == (addr & mask);
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

bool AutoApproveEngine::add_rule(const AutoApproveRule& rule) {
    std::lock_guard lock(mu_);
    auto next = rules_;
    next.push_back(rule);
    if (!write_locked(next, require_all_))
        return false;
    rules_ = std::move(next);
    return true;
}

RuleEdit AutoApproveEngine::remove_rule(size_t index) {
    std::lock_guard lock(mu_);
    if (index >= rules_.size())
        return {RuleEdit::Status::not_found, {}};
    auto next = rules_;
    next.erase(next.begin() + static_cast<std::ptrdiff_t>(index));
    if (!write_locked(next, require_all_))
        return {RuleEdit::Status::persist_failed, rules_[index]};
    RuleEdit edit{RuleEdit::Status::ok, rules_[index]};
    rules_ = std::move(next);
    return edit;
}

RuleEdit AutoApproveEngine::toggle_rule(size_t index) {
    std::lock_guard lock(mu_);
    if (index >= rules_.size())
        return {RuleEdit::Status::not_found, {}};
    auto next = rules_;
    next[index].enabled = !next[index].enabled;
    if (!write_locked(next, require_all_))
        return {RuleEdit::Status::persist_failed, rules_[index]};
    rules_ = std::move(next);
    return {RuleEdit::Status::ok, rules_[index]};
}

std::vector<AutoApproveRule> AutoApproveEngine::list_rules() const {
    std::lock_guard lock(mu_);
    return rules_;
}

bool AutoApproveEngine::require_all() const {
    std::lock_guard lock(mu_);
    return require_all_;
}

bool AutoApproveEngine::set_require_all(bool val) {
    std::lock_guard lock(mu_);
    if (!write_locked(rules_, val))
        return false;
    require_all_ = val;
    return true;
}

} // namespace yuzu::server::auth
