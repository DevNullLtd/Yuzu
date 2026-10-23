#pragma once

/**
 * @file dex_score_policy_writer.hpp
 * The one write path for the customer DEX score policy: validate, persist, audit, refresh.
 * apply_dex_score_policy() sits behind PUT and DELETE /api/v1/dex/score-policy and is the
 * entry the Settings panel reuses, so the two surfaces cannot drift.
 *
 * Header-only and store-free: it includes no store, httplib or clock type. Every boundary is
 * an injected closure (the observed store read, the store compare-and-set / -remove, the audit
 * hook) and the provider that serialises writers and installs the policy on this instance.
 * The caller resolves authentication, authorisation and the same-site gate first; this
 * function owns everything after.
 *
 * Order of work (each refusal leaves exactly one `denied` row, except where noted):
 *   1. If-Match: required (428), one strong validator: "default" (nothing stored) or the
 *      16-digit lower-hex revision GET returned (400 otherwise).
 *   2. dry_run (PUT only): "true" or "false". DELETE refuses the parameter outright.
 *   3. PUT body: size cap, depth guard, then the reader's own validation
 *      (dex_score_policy_validate_text), so a document accepted here is a document served.
 *   4. The OBSERVED store text is read; an unreadable store is a 503 with no row. The
 *      If-Match must equal the observed revision (409 otherwise).
 *   5. dry_run: one `validate` row, then the would-be document. Nothing is stored.
 *   6. An `attempted` row is written BEFORE the store is touched; a row the audit store
 *      refuses is a 503 (REST JSON fails closed on audit, rest_audit.hpp).
 *   7. provider->write(): commit-then-install under the provider's writer lock; the commit
 *      is the store compare-and-set / -remove against the exact observed text.
 *
 * Outcome of the store write. A store error returned after the statement was sent (a
 * connection lost after the commit) leaves the outcome UNKNOWN, as does an exception that
 * escapes write() after the commit (the provider's install runs outside its commit guard).
 * Both are resolved by re-reading the store: when the intended state is observed the write
 * answers 200 with a success row recording outcome "observed_after_store_error" (the desired
 * state is in force; it does not prove THIS request's commit made it so). Anything else is a
 * 503 OutcomeUnknown whose row and message carry the revision now stored, or say the re-read
 * failed. That answer never asserts the policy was left as it was: another replica may have
 * overwritten a commit this request did make.
 *
 * Failure of the later audit rows (success, failure, no_change) never changes the answer: the
 * store state they describe already exists, and the handler's Sec-Audit-Failed header carries
 * the signal.
 *
 * Audit row size. The whole canonical document (up to ~97 KB) rides only on the rows that
 * record a proposal or an applied change: `attempted`, `success` and `validate`. Every other
 * row (denied, failure, no_change) carries `document_bytes`, the size of the canonical text,
 * instead, so a refused or failed request cannot multiply the document in the audit store.
 */

#include "dex_score_policy_json.hpp"
#include "dex_score_policy_provider.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: the shared #2437 guard
#include "store_errors.hpp" // kDbErrorPrefix: how the store marks a failure of its own

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

/// Audit verbs of the score policy writer (target_type RuntimeConfig, target_id
/// kDexScorePolicyKey).
inline constexpr std::string_view kDexScorePolicyUpdateVerb = "dex.score_policy.update";
inline constexpr std::string_view kDexScorePolicyResetVerb = "dex.score_policy.reset";
inline constexpr std::string_view kDexScorePolicyValidateVerb = "dex.score_policy.validate";

/// retry_after_ms for a writer-busy or store-unavailable answer (the store's lease wait).
inline constexpr std::int64_t kDexScorePolicyRetryMs = 2000;
/// The 503 message for an unreadable or unwired store: spelled once, for apply and the handlers.
inline constexpr std::string_view kDexScorePolicyStoreUnavailableMessage =
    "runtime config store unavailable";
/// retry_after_ms when the audit store refused a row (the other REST audit fail-closed 503s).
inline constexpr std::int64_t kDexScorePolicyAuditRetryMs = 5000;
/// Longest If-Match value considered at all; a revision is at most 18 bytes quoted.
inline constexpr std::size_t kDexScorePolicyIfMatchMaxBytes = 64;

/// Parse an If-Match header value into the revision it names: "default" or 16 lower-hex
/// digits, optionally inside ONE pair of double quotes. Refuses `*`, a weak validator (W/),
/// a list, an empty value and anything else; every message starts with "If-Match" and none
/// echoes the value.
[[nodiscard]] inline std::expected<std::string, std::string> parse_if_match(std::string_view raw) {
    const auto b = raw.find_first_not_of(" \t");
    if (b == std::string_view::npos)
        return std::unexpected(std::string("If-Match must not be empty"));
    auto s = raw.substr(b, raw.find_last_not_of(" \t") - b + 1);
    if (s.size() > kDexScorePolicyIfMatchMaxBytes)
        return std::unexpected(std::string("If-Match is longer than ") +
                               std::to_string(kDexScorePolicyIfMatchMaxBytes) + " bytes");
    if (s == "*")
        return std::unexpected(std::string("If-Match: * is not supported; send the revision GET "
                                           "returned"));
    if (s.starts_with("W/"))
        return std::unexpected(std::string("If-Match: a weak validator is not supported; send the "
                                           "revision GET returned"));
    if (s.find(',') != std::string_view::npos)
        return std::unexpected(std::string("If-Match: send exactly one revision"));
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        s = s.substr(1, s.size() - 2);
    const bool hex16 =
        s.size() == 16 && s.find_first_not_of("0123456789abcdef") == std::string_view::npos;
    if (s != kDexScorePolicyDefaultRevision && !hex16)
        return std::unexpected(std::string("If-Match: expected \"default\" or a 16-digit "
                                           "lower-case hex revision"));
    return std::string(s);
}

/// Parse the raw `dry_run` query value: absent is false, "true" and "false" are accepted,
/// anything else (including the empty string) is refused with a message starting "dry_run".
[[nodiscard]] inline std::expected<bool, std::string>
parse_dry_run(const std::optional<std::string>& raw) {
    if (!raw)
        return false;
    if (*raw == "true")
        return true;
    if (*raw == "false")
        return false;
    return std::unexpected(std::string("dry_run must be true or false"));
}

struct DexScorePolicyWriteRequest {
    enum class Op { Put, Reset };
    Op op{Op::Put};
    /// The RAW `dry_run` query value (nullopt = the parameter is absent). Parsed here, not by
    /// the handler, so a refusal and its denied row live in one place.
    std::optional<std::string> dry_run;
    /// The raw If-Match header value (nullopt = the header is absent).
    std::optional<std::string> if_match;
    std::string body;  ///< PUT: the policy document
    std::string actor; ///< stored as updated_by
};

/// Store compare-and-set. `expected` is the observed text exactly (nullopt only when no row
/// exists); true = written, false = stale.
using DexScorePolicyCasFn = std::function<std::expected<bool, std::string>(
    const std::optional<std::string>& expected, const std::string& canonical,
    const std::string& actor)>;
/// Store compare-and-remove against the exact observed text.
using DexScorePolicyCarFn = std::function<std::expected<bool, std::string>(const std::string&)>;

struct DexScorePolicyWriteDeps {
    /// The OBSERVED store text (nullopt = no row, error = unreadable).
    DexScorePolicyProvider::ReadFn read_stored;
    DexScorePolicyCasFn compare_and_set;
    DexScorePolicyCarFn compare_and_remove;
    /// Serialises writers and installs the policy on this instance. The caller's Deps outlives
    /// the call.
    std::shared_ptr<DexScorePolicyProvider> provider;
    /// Audit hook: true = the row persisted (or audit is off). Empty = audit off.
    std::function<bool(std::string_view verb, std::string_view result,
                       const std::string& detail_json)>
        audit;
};

enum class DexScorePolicyWriteStatus {
    Ok,
    IfMatchMissing,
    IfMatchMalformed,
    Stale,
    Invalid,
    WriterBusy,
    StoreUnavailable,
    OutcomeUnknown,
    AuditUnavailable,
};

[[nodiscard]] constexpr int dex_score_policy_http_status(DexScorePolicyWriteStatus s) noexcept {
    switch (s) {
    case DexScorePolicyWriteStatus::Ok:
        return 200;
    case DexScorePolicyWriteStatus::IfMatchMissing:
        return 428;
    case DexScorePolicyWriteStatus::IfMatchMalformed:
    case DexScorePolicyWriteStatus::Invalid:
        return 400;
    case DexScorePolicyWriteStatus::Stale:
        return 409;
    case DexScorePolicyWriteStatus::WriterBusy:
    case DexScorePolicyWriteStatus::StoreUnavailable:
    case DexScorePolicyWriteStatus::OutcomeUnknown:
    case DexScorePolicyWriteStatus::AuditUnavailable:
        return 503;
    }
    return 500;
}

struct DexScorePolicyWriteResult {
    DexScorePolicyWriteStatus status{DexScorePolicyWriteStatus::StoreUnavailable};
    std::string message;     ///< empty on Ok
    std::string remediation; ///< a recovery hint, or empty
    std::optional<std::int64_t> retry_after_ms;
    /// Ok: the policy now in force (a dry run: the policy that WOULD be).
    DexPolicyInForce in_force;
    /// The revision the store held when the write was checked ("default" when none).
    std::string previous_revision;
    bool dry_run{false};
};

/// {document, revision, source, fault?} of a policy in force: the data shape of GET and the
/// base of every 200 write answer. `document` is the stored shape (version, tiers.edges,
/// tiers.names, weights, overrides), never the Apps projection.
[[nodiscard]] inline nlohmann::json dex_score_policy_in_force_json(const DexPolicyInForce& p) {
    nlohmann::json j{{"document", dex_score_policy_to_json(p.policy)},
                     {"revision", p.revision},
                     {"source", p.source}};
    if (!p.fault.empty())
        j["fault"] = p.fault;
    return j;
}

namespace dex_score_policy_writer_detail {

/// An untrusted value on its way into an audit row: control bytes, space, `=` and `,` folded
/// (CWE-117) and the length capped. May cut a multi-byte character; the row is dumped with
/// error_handler_t::replace.
[[nodiscard]] inline std::string cap_token(std::string_view s) {
    std::string t = ::yuzu::log_token(s);
    constexpr std::size_t kMax = 128;
    if (t.size() > kMax)
        t.resize(kMax);
    return t;
}

/// The detail object of every audit row on this surface.
struct AuditDetail {
    nlohmann::json if_match = nullptr;
    nlohmann::json prior_revision = nullptr;
    nlohmann::json revision = nullptr;
    nlohmann::json document = nullptr;
    nlohmann::json document_bytes = nullptr; ///< size of the canonical text, when there is one
    nlohmann::json dry_run = nullptr;
    std::string reason;
    std::string field;
    std::string outcome;
    std::string observed_revision;
    std::string reread_error;

    /// `with_document`: the whole canonical document (attempted, success, validate rows);
    /// otherwise only its byte count (denied, failure, no_change rows).
    [[nodiscard]] std::string dump(bool with_document) const {
        nlohmann::json j = nlohmann::json::object();
        j["if_match"] = if_match;
        j["prior_revision"] = prior_revision;
        j["revision"] = revision;
        if (with_document)
            j["document"] = document;
        else
            j["document_bytes"] = document_bytes;
        if (!dry_run.is_null())
            j["dry_run"] = dry_run;
        auto put = [&j](const char* key, const std::string& value) {
            if (!value.empty())
                j[key] = value;
        };
        put("reason", reason);
        put("field", field);
        put("outcome", outcome);
        put("observed_revision", observed_revision);
        put("reread_error", reread_error);
        return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    }
};

/// A store failure (the store's own prefix, or a commit that threw) leaves the outcome
/// unknown; anything else is the store refusing the caller's input.
[[nodiscard]] inline bool is_store_failure(std::string_view detail) noexcept {
    return detail.starts_with(kDbErrorPrefix) || detail.starts_with("commit threw");
}

} // namespace dex_score_policy_writer_detail

/// Validate, persist, audit and refresh the score policy. See the file banner.
[[nodiscard]] inline DexScorePolicyWriteResult
apply_dex_score_policy(const DexScorePolicyWriteRequest& rq, const DexScorePolicyWriteDeps& d) {
    using namespace dex_score_policy_writer_detail;
    using Status = DexScorePolicyWriteStatus;
    using Result = DexScorePolicyWriteResult;

    Result out;
    const bool put = rq.op == DexScorePolicyWriteRequest::Op::Put;
    const std::string_view verb = put ? kDexScorePolicyUpdateVerb : kDexScorePolicyResetVerb;

    auto emit = [&](std::string_view v, std::string_view result, const AuditDetail& det) -> bool {
        if (!d.audit)
            return true; // audit-off deployment: not a persist failure
        try {
            // The proposal and the applied change carry the document; the rest its size.
            return d.audit(v, result, det.dump(result == "attempted" || result == "success"));
        } catch (...) {
            return false;
        }
    };
    auto refuse = [&](Status st, std::string msg, std::string_view reason, AuditDetail det,
                      std::string field = {}, std::string remediation = {}) -> Result {
        det.reason = std::string(reason);
        det.field = std::move(field);
        (void)emit(verb, "denied", det); // the refusal does not depend on this row
        out.status = st;
        out.message = std::move(msg);
        out.remediation = std::move(remediation);
        return out;
    };
    using Rd = std::expected<std::optional<std::string>, std::string>;
    // The injected reader is untrusted: an exception from it is an unreadable store.
    auto safe_read = [&]() -> Rd {
        try {
            return d.read_stored();
        } catch (const std::exception& e) {
            return std::unexpected(std::string("read threw: ") + e.what());
        } catch (...) {
            return std::unexpected(std::string("read threw"));
        }
    };
    auto audit_unavailable = [&]() -> Result {
        out.status = Status::AuditUnavailable;
        out.message = "audit subsystem unavailable; refusing to change the score policy without "
                      "durable evidence";
        out.remediation = "retry the request";
        out.retry_after_ms = kDexScorePolicyAuditRetryMs;
        return out;
    };
    auto store_unavailable = [&]() -> Result {
        out.status = Status::StoreUnavailable;
        out.message = std::string(kDexScorePolicyStoreUnavailableMessage);
        out.remediation = "retry shortly";
        out.retry_after_ms = kDexScorePolicyRetryMs;
        return out;
    };
    const std::string kGetHint = "GET /api/v1/dex/score-policy and send the revision it returns";

    if (!d.provider || !d.read_stored)
        return store_unavailable();

    AuditDetail base;

    // 1. If-Match.
    if (!rq.if_match)
        return refuse(Status::IfMatchMissing,
                      "If-Match header required: send the policy's current revision (\"default\" "
                      "when none has been written)",
                      "if_match_missing", base, {}, kGetHint);
    auto im = parse_if_match(*rq.if_match);
    if (!im) {
        base.if_match = cap_token(*rq.if_match);
        return refuse(Status::IfMatchMalformed, std::move(im.error()), "if_match_malformed", base,
                      {}, kGetHint);
    }
    base.if_match = *im;

    // 2. dry_run.
    bool dry = false;
    if (!put) {
        if (rq.dry_run) {
            base.dry_run = cap_token(*rq.dry_run);
            return refuse(Status::Invalid, "DELETE does not support dry_run",
                          "dry_run_unsupported", base, "dry_run");
        }
    } else {
        const auto dr = parse_dry_run(rq.dry_run);
        if (!dr) {
            base.dry_run = cap_token(*rq.dry_run);
            return refuse(Status::Invalid, dr.error(), "dry_run_invalid", base, "dry_run");
        }
        dry = *dr;
    }

    // 3. PUT body: the reader's own validation.
    std::string canonical;
    if (put) {
        if (rq.body.size() <= kDexScorePolicyMaxBytes &&
            mcp::json_exceeds_depth(rq.body, mcp::kMcpMaxJsonDepth))
            return refuse(Status::Invalid, "request body nests too deeply", "invalid", base,
                          "document");
        const auto v = dex_score_policy_validate_text(rq.body);
        if (!v) {
            std::string fix(dex_score_policy_projection_remediation(v.error().field));
            if (fix.empty() && v.error().field == "version")
                fix = "this server reads version " + std::to_string(kDexScorePolicyVersion) +
                      " documents; leave the stored document alone (a newer server reads it) or "
                      "send a version " +
                      std::to_string(kDexScorePolicyVersion) + " document";
            return refuse(Status::Invalid, v.error().message, "invalid", base, v.error().field,
                          std::move(fix));
        }
        canonical = dex_score_policy_canonical(*v);
        base.revision = dex_score_policy_revision(canonical);
        base.document = dex_score_policy_to_json(*v);
        base.document_bytes = canonical.size();
    } else {
        base.revision = std::string(kDexScorePolicyDefaultRevision);
    }

    // 4. The observed store text, and the precondition against it.
    auto rd = safe_read();
    if (!rd) {
        spdlog::warn("DEX score policy write: store read failed: {}",
                     ::yuzu::log_key_token(rd.error()));
        return store_unavailable();
    }
    const std::optional<std::string> stored = std::move(*rd);
    const std::string observed = dex_score_policy_revision(stored.value_or(""));
    base.prior_revision = observed;
    out.previous_revision = observed;
    if (*im != observed)
        return refuse(Status::Stale,
                      "the stored policy's revision is " + observed +
                          ", which is not the If-Match revision",
                      "stale", base, {}, kGetHint + " (and review the current policy first)");

    // 5. Dry run: validated, current, nothing stored.
    if (put && dry) {
        base.dry_run = true;
        if (!emit(kDexScorePolicyValidateVerb, "success", base))
            return audit_unavailable();
        out.status = Status::Ok;
        out.dry_run = true;
        out.in_force = dex_policy_in_force_from_stored(canonical);
        return out;
    }

    // DELETE of a policy that was never written: audited, nothing to do.
    if (!put && !stored) {
        if (!emit(verb, "attempted", base))
            return audit_unavailable();
        (void)emit(verb, "no_change", base);
        out.status = Status::Ok;
        out.in_force = dex_policy_in_force_from_stored(std::nullopt);
        return out;
    }

    // 6. Audit first.
    if (!emit(verb, "attempted", base))
        return audit_unavailable();

    // 7. Commit then install, under the provider's writer lock.
    const std::optional<std::string> text = put ? std::optional<std::string>(canonical)
                                                : std::nullopt;
    const DexScorePolicyProvider::CommitFn commit = [&]() -> std::expected<bool, std::string> {
        return put ? d.compare_and_set(stored, canonical, rq.actor)
                   : d.compare_and_remove(*stored);
    };
    std::optional<std::expected<DexPolicyInForce, DexPolicyWriteFailure>> w;
    std::string ambiguous; // non-empty: the commit's outcome is unknown, for this reason
    try {
        w = d.provider->write(text, commit);
    } catch (const std::exception& e) {
        // write() catches a throwing commit itself, so an exception that reaches here is a
        // parse before the lock or the install AFTER the commit: the store may hold the text.
        ambiguous = std::string("write threw: ") + e.what();
    } catch (...) {
        ambiguous = "write threw";
    }

    if (w && *w) {
        out.status = Status::Ok;
        out.in_force = std::move(**w);
        base.revision = out.in_force.revision;
        (void)emit(verb, "success", base);
        return out;
    }
    if (w) {
        const DexPolicyWriteFailure& f = (*w).error();
        switch (f.kind) {
        case DexPolicyWriteError::WriterBusy:
            base.reason = "writer_busy";
            (void)emit(verb, "failure", base);
            out.status = Status::WriterBusy;
            out.message = "another score policy write is still running";
            out.remediation = "retry after the suggested delay";
            out.retry_after_ms = kDexScorePolicyRetryMs;
            return out;
        case DexPolicyWriteError::Stale:
            base.reason = "stale";
            (void)emit(verb, "failure", base);
            out.status = Status::Stale;
            out.message = "the stored policy changed while this write was being made";
            out.remediation = kGetHint;
            return out;
        case DexPolicyWriteError::CommitFailed:
            if (is_store_failure(f.detail)) {
                ambiguous = f.detail;
                break;
            }
            base.reason = "commit_refused";
            (void)emit(verb, "failure", base);
            out.status = Status::Invalid;
            out.message = f.detail;
            return out;
        }
    }

    // Ambiguous outcome: re-read the store to learn what is there now.
    const auto re = safe_read();
    out.status = Status::OutcomeUnknown;
    out.retry_after_ms = kDexScorePolicyRetryMs;
    out.remediation = "GET /api/v1/dex/score-policy and compare its revision: the If-Match you sent "
                      "means the write did not apply, any other means review the policy before "
                      "changing it again";
    if (re) {
        const bool intended = put ? (re->has_value() && **re == canonical) : !re->has_value();
        if (intended) {
            base.reason = cap_token(ambiguous);
            base.outcome = "observed_after_store_error";
            base.revision = dex_score_policy_revision(re->value_or(""));
            (void)emit(verb, "success", base);
            out = Result{};
            out.status = Status::Ok;
            out.in_force = dex_policy_in_force_from_stored(*re);
            out.previous_revision = observed;
            return out;
        }
        base.observed_revision = dex_score_policy_revision(re->value_or(""));
        out.message = "the write's outcome is unknown; the stored policy's revision is now " +
                      base.observed_revision;
    } else {
        base.reread_error = cap_token(re.error());
        out.message = "the write's outcome is unknown; the stored policy could not be re-read";
    }
    spdlog::warn("DEX score policy write: outcome unknown ({}): {}",
                 ::yuzu::log_key_token(ambiguous), out.message);
    base.reason = "outcome_unknown";
    (void)emit(verb, "failure", base);
    return out;
}

} // namespace yuzu::server
