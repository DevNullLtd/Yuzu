#pragma once

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::auth {

/// Types of auto-approve rules that bypass the pending queue.
enum class AutoApproveRuleType {
    trusted_ca,     // Match by CA certificate SHA-256 fingerprint
    hostname_glob,  // Wildcard match on agent hostname
    ip_subnet,      // CIDR match on agent peer IP
    cloud_provider, // Match by attestation_provider field
};

/// A single auto-approve rule.
struct AutoApproveRule {
    AutoApproveRuleType type;
    std::string value; // e.g. "ab12cd..." / "*.prod.example.com" / "10.0.0.0/8" / "aws"
    std::string label; // Admin-friendly description
    bool enabled{true};
};

/// Context passed to the engine for evaluation. Populated from the Register RPC.
struct ApprovalContext {
    std::string hostname;              // From AgentInfo
    std::string peer_ip;               // From grpc::ServerContext::peer()
    std::string ca_fingerprint_sha256; // SHA-256 of issuer CA cert (from peer TLS)
    std::string attestation_provider;  // From RegisterRequest
};

/// Engine that evaluates auto-approve rules against agent registration context.
class AutoApproveEngine {
public:
    /// Load policy from a config file. Returns false if file doesn't exist (not an error).
    bool load(const std::filesystem::path& path);

    /// Save current policy to disk.
    void save() const;

    /// Evaluate the policy against a registration context.
    /// Returns the label of the matching rule, or empty string if no match.
    std::string evaluate(const ApprovalContext& ctx) const;

    /// True iff `value` is an `ip_subnet` rule value this engine can ever match: a bare IPv4
    /// literal or `a.b.c.d/N` with N one base-10 integer in 0..32 that starts with a digit (so no
    /// leading '-', which would read `/-0` as a match-all /0, no '+', no whitespace). IPv4 only on purpose: the rule
    /// file is `type:value:label:enabled` and splits on ':', so an IPv6 value could not survive a
    /// restart. The admin route refuses anything else (#4644); the matcher treats it as no match.
    [[nodiscard]] static bool is_valid_ip_subnet_value(const std::string& value);

    /// True iff `text` can be a rule value or label without changing meaning on a reload: the
    /// rules file is `type:value:label:enabled`, one rule per line, so a ':' or any control
    /// character (NUL, CR, LF, ...) would split into a different rule or flip a field. The ONE
    /// check for the admin route, `add_rule` and `is_valid_ip_subnet_value`; applies to every rule
    /// type, to the value AND the label.
    [[nodiscard]] static bool is_valid_rule_text(std::string_view text);

    /// CRUD for rules
    /// Returns false, storing nothing, when the value or the label fails is_valid_rule_text.
    bool add_rule(const AutoApproveRule& rule);
    /// Returns the rule that was removed, or nullopt for an out-of-range index. The removal and
    /// the returned copy happen under one lock, so an audit row built from it names exactly the
    /// rule that was deleted.
    std::optional<AutoApproveRule> remove_rule(size_t index);
    void set_enabled(size_t index, bool enabled);
    /// Flip a rule's enabled flag. Returns the rule as it is AFTER the flip, or nullopt for an
    /// out-of-range index; the read, the flip and the returned copy are one critical section.
    std::optional<AutoApproveRule> toggle_enabled(size_t index);

    /// Get all rules (for admin UI).
    std::vector<AutoApproveRule> list_rules() const;

    /// Mode: false = any rule match approves, true = all rules must match.
    /// Out-of-line (auto_approve.cpp), both locking `mu_` — the sole
    /// exception to that discipline used to be these two inline bare
    /// accesses, racing the (also unlocked) production POST
    /// /api/settings/auto-approve/mode writer against #4031's REST v1
    /// GET /api/v1/enrollment/auto-approve-rules reader, a genuine C++ data
    /// race (unlocked write + unlocked read, no happens-before) on a field
    /// every OTHER touch point (load/save_locked/evaluate) already reads
    /// under `mu_`. Same bug class as the `oidc_mu_` race #4031 fixed
    /// earlier in the same diff (967276a61) — this is its sibling instance.
    bool require_all() const;
    void set_require_all(bool val);

private:
    bool match_rule(const AutoApproveRule& rule, const ApprovalContext& ctx) const;
    bool match_hostname_glob(const std::string& pattern, const std::string& hostname) const;
    bool match_ip_subnet(const std::string& cidr, const std::string& ip) const;
    void save_locked() const; // must be called with mu_ held

    mutable std::mutex mu_;
    std::vector<AutoApproveRule> rules_;
    bool require_all_{false};
    std::filesystem::path config_path_;
};

} // namespace yuzu::server::auth
