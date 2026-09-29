#pragma once

#include <filesystem>
#include <mutex>
#include <string>
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

    /// CRUD for rules
    void add_rule(const AutoApproveRule& rule);
    void remove_rule(size_t index);
    void set_enabled(size_t index, bool enabled);

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
