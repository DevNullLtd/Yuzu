#pragma once

#include <cstddef>
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

/// Parse a persisted/submitted rule type name. nullopt for anything unknown --
/// callers must reject, never default to a (broader) type.
std::optional<AutoApproveRuleType> parse_auto_approve_rule_type(std::string_view s);

/// The machine name of a rule type (`hostname_glob`, ...): what the policy file stores and
/// `parse_auto_approve_rule_type` accepts. Not the wording the dashboard shows.
std::string rule_type_to_string(AutoApproveRuleType t);

/// Upper bounds on a persisted rule's text: a hostname is at most 253 characters, and a
/// label is an admin note. Without them a near-4 MiB value would be stored and then
/// copied and matched under the engine mutex on every Register.
inline constexpr std::size_t kMaxRuleValueLen = 253;
inline constexpr std::size_t kMaxRuleLabelLen = 128;

/// Validate a rule before it is persisted. Returns an empty string when acceptable,
/// otherwise a short reason. Rejects ':' / CR / LF / control characters in value and
/// label (the store is a colon/newline-delimited file), an empty value, a value or
/// label over kMaxRuleValueLen / kMaxRuleLabelLen, a malformed ip_subnet (IPv4 literal,
/// optional /0-32), a trusted_ca that is not 64 hex, and the two match-everything
/// forms (a hostname glob of only '*' and an ip_subnet of /0), which in the default
/// `any` mode would admit every registering machine.
std::string validate_auto_approve_rule(AutoApproveRuleType type, std::string_view value,
                                       std::string_view label);

/// Context passed to the engine for evaluation. Populated from the Register RPC.
struct ApprovalContext {
    std::string hostname;              // From AgentInfo
    std::string peer_ip;               // From grpc::ServerContext::peer()
    std::string ca_fingerprint_sha256; // SHA-256 of issuer CA cert (from peer TLS)
    std::string attestation_provider;  // From RegisterRequest
};

/// What a caller saw at an index. The dashboard addresses a rule by list position, which shifts
/// under a concurrent edit, so a view may state the rule it meant. Every field that is set must
/// match the rule now at that index, checked under the engine lock; unset fields are not
/// checked (a caller that states nothing keeps the by-index behaviour).
struct RuleExpectation {
    std::optional<AutoApproveRuleType> type;
    std::optional<std::string> value;
    std::optional<bool> enabled;
};

/// Outcome of a mutation that targets one rule by index.
struct RuleEdit {
    /// `mismatch`: a rule exists at the index but is not the one the caller expected; nothing
    /// changed.
    enum class Status { ok, not_found, persist_failed, mismatch };
    Status status{Status::not_found};
    AutoApproveRule rule; ///< the rule acted on (removed / toggled) - read under the same lock
};

/// Engine that evaluates auto-approve rules against agent registration context.
class AutoApproveEngine {
public:
    /// Load policy from a config file. Returns false if file doesn't exist (not an error).
    /// Fail closed: a file with ANY malformed line (an unknown rule type, a short line,
    /// a `mode:` other than exactly `any` / `all`) activates ZERO rules in mode `any`
    /// (evaluate() then matches nothing, so every agent waits for manual approval) and
    /// the original file is renamed to `<path>.rejected` so the next save cannot destroy it.
    bool load(const std::filesystem::path& path);

    /// Save current policy to disk (temp file + rename). False if the write failed.
    bool save() const;

    /// Evaluate the policy against a registration context.
    /// Returns the label of the matching rule, or empty string if no match.
    std::string evaluate(const ApprovalContext& ctx) const;

    /// CRUD for rules. Every mutation is commit-or-nothing: the new policy is written to
    /// disk first and only a successful write changes the in-memory policy, so a failed
    /// persist leaves memory and file as they were.
    bool add_rule(const AutoApproveRule& rule);
    RuleEdit remove_rule(size_t index, const RuleExpectation& expect = {});
    /// Flips `enabled`; `rule` is the post-toggle state.
    RuleEdit toggle_rule(size_t index, const RuleExpectation& expect = {});

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
    bool set_require_all(bool val); ///< persists; false (and unchanged) if the write failed

private:
    bool match_rule(const AutoApproveRule& rule, const ApprovalContext& ctx) const;
    bool match_hostname_glob(const std::string& pattern, const std::string& hostname) const;
    bool match_ip_subnet(const std::string& cidr, const std::string& ip) const;
    /// Write `rules`/`require_all` to config_path_ via a temp file + rename. True when
    /// persisted (or when there is no config path - an in-memory engine). mu_ held.
    bool write_locked(const std::vector<AutoApproveRule>& rules, bool require_all) const;

    mutable std::mutex mu_;
    std::vector<AutoApproveRule> rules_;
    bool require_all_{false};
    std::filesystem::path config_path_;
};

} // namespace yuzu::server::auth
