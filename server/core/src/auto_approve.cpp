#include <yuzu/server/auto_approve.hpp>

#include "query_int_parse.hpp" // parse_query_int (#4644)

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
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

// The prefix length of an `a.b.c.d/N` rule: ONE base-10 integer in 0..32 whose first character is a
// digit. `from_chars` accepts a leading '-', so `/-0` parsed as 0 and became a match-all /0;
// '+', whitespace and any trailing text are rejected by the full-consumption parse itself.
// Shared by the admission check and the matcher so the two cannot disagree.
std::optional<int> parse_prefix_len(std::string_view text) {
    if (text.empty() || text.front() < '0' || text.front() > '9')
        return std::nullopt;
    const auto v = parse_query_int<int>(text);
    if (!v || *v < 0 || *v > 32)
        return std::nullopt;
    return v;
}

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

AutoApproveRuleType string_to_rule_type(const std::string& s) {
    if (s == "trusted_ca")
        return AutoApproveRuleType::trusted_ca;
    if (s == "hostname_glob")
        return AutoApproveRuleType::hostname_glob;
    if (s == "ip_subnet")
        return AutoApproveRuleType::ip_subnet;
    if (s == "cloud_provider")
        return AutoApproveRuleType::cloud_provider;
    return AutoApproveRuleType::hostname_glob; // safe default
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // anonymous namespace

// ── Persistence ──────────────────────────────────────────────────────────────

bool AutoApproveEngine::load(const std::filesystem::path& path) {
    config_path_ = path;

    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::lock_guard lock(mu_);
    rules_.clear();
    require_all_ = false;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#')
            continue;

        // mode:any or mode:all
        if (line.starts_with("mode:")) {
            require_all_ = (line.substr(5) == "all");
            continue;
        }

        // type:value:label:enabled
        std::istringstream ss(line);
        std::string type_s, value, label, enabled_s;
        if (!std::getline(ss, type_s, ':'))
            continue;
        if (!std::getline(ss, value, ':'))
            continue;
        std::getline(ss, label, ':');
        std::getline(ss, enabled_s, ':');

        AutoApproveRule rule;
        rule.type = string_to_rule_type(type_s);
        rule.value = value;
        rule.label = label;
        rule.enabled = enabled_s.empty() || enabled_s == "1";
        if (rule.type == AutoApproveRuleType::ip_subnet && !is_valid_ip_subnet_value(rule.value))
            spdlog::warn("Auto-approve rule {} in {} is not a valid ip_subnet value and will "
                         "never match",
                         rules_.size(), path.string());
        rules_.push_back(std::move(rule));
    }

    spdlog::info("Loaded {} auto-approve rules from {}", rules_.size(), path.string());
    return true;
}

void AutoApproveEngine::save() const {
    std::lock_guard lock(mu_);
    save_locked();
}

// Must be called with mu_ held.
void AutoApproveEngine::save_locked() const {
    if (config_path_.empty())
        return;

    std::ofstream f(config_path_, std::ios::trunc);
    if (!f.is_open()) {
        spdlog::error("Failed to save auto-approve config to {}", config_path_.string());
        return;
    }

    f << "# Yuzu Auto-Approve Policies\n";
    f << "# Format: type:value:label:enabled\n";
    f << "mode:" << (require_all_ ? "all" : "any") << "\n";

    for (const auto& rule : rules_) {
        f << rule_type_to_string(rule.type) << ":" << rule.value << ":" << rule.label << ":"
          << (rule.enabled ? "1" : "0") << "\n";
    }
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

bool AutoApproveEngine::is_valid_ip_subnet_value(const std::string& value) {
    if (!is_valid_rule_text(value))
        return false; // inet_pton would read only up to an embedded NUL
    const auto slash = value.find('/');
    const auto net_str = value.substr(0, slash);
    struct in_addr net_addr{};
    if (inet_pton(AF_INET, net_str.c_str(), &net_addr) != 1)
        return false;
    if (slash == std::string::npos)
        return true;
    return parse_prefix_len(std::string_view(value).substr(slash + 1)).has_value();
}

bool AutoApproveEngine::match_ip_subnet(const std::string& cidr, const std::string& ip) const {
    // Parse CIDR: "10.0.0.0/8"
    // A blank rule value must never match (an empty peer IP would otherwise equal it).
    if (cidr.empty())
        return false;
    auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        // Exact IP match
        return ip == cidr;
    }

    auto net_str = cidr.substr(0, slash);
    // Strict prefix (#4644): `std::stoi` threw out of Register/ProxyRegister on a malformed
    // prefix, read `1e3` as /1, and a prefix above 32 made the mask shift undefined. A malformed
    // rule never matches, so it never auto-approves (fail closed; in `all` mode it blocks).
    const auto prefix = parse_prefix_len(std::string_view(cidr).substr(slash + 1));
    if (!prefix)
        return false;
    const int prefix_len = *prefix;

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

bool AutoApproveEngine::is_valid_rule_text(std::string_view text) {
    return std::none_of(text.begin(), text.end(), [](char c) {
        return c == ':' || static_cast<unsigned char>(c) < 0x20;
    });
}

bool AutoApproveEngine::add_rule(const AutoApproveRule& rule) {
    if (!is_valid_rule_text(rule.value) || !is_valid_rule_text(rule.label)) {
        spdlog::warn("Refused an auto-approve rule whose value or label contains ':' or a "
                     "control character");
        return false;
    }
    std::lock_guard lock(mu_);
    rules_.push_back(rule);
    save_locked();
    return true;
}

std::optional<AutoApproveRule> AutoApproveEngine::remove_rule(size_t index) {
    std::lock_guard lock(mu_);
    if (index >= rules_.size())
        return std::nullopt;
    auto removed = rules_[index];
    rules_.erase(rules_.begin() + static_cast<std::ptrdiff_t>(index));
    save_locked();
    return removed;
}

std::optional<AutoApproveRule> AutoApproveEngine::toggle_enabled(size_t index) {
    std::lock_guard lock(mu_);
    if (index >= rules_.size())
        return std::nullopt;
    rules_[index].enabled = !rules_[index].enabled;
    save_locked();
    return rules_[index];
}

void AutoApproveEngine::set_enabled(size_t index, bool enabled) {
    std::lock_guard lock(mu_);
    if (index < rules_.size()) {
        rules_[index].enabled = enabled;
        save_locked();
    }
}

std::vector<AutoApproveRule> AutoApproveEngine::list_rules() const {
    std::lock_guard lock(mu_);
    return rules_;
}

bool AutoApproveEngine::require_all() const {
    std::lock_guard lock(mu_);
    return require_all_;
}

void AutoApproveEngine::set_require_all(bool val) {
    std::lock_guard lock(mu_);
    require_all_ = val;
}

} // namespace yuzu::server::auth
