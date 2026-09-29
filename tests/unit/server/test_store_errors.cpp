// test_store_errors.cpp — Unit tests for the kConflictPrefix shared
// contract (#396, #399, #402; governance Gate 3 arch-B1).
//
// The store↔route layer uses a magic-string prefix to signal duplicate
// conflicts. A typo in either layer would silently degrade 409 → 400 with
// no test failure. Centralizing the constant + helpers in store_errors.hpp
// makes a typo a compile error; testing the helpers themselves locks in
// the contract semantics so a refactor of one helper can't drift the
// invariant.

#include "store_errors.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

TEST_CASE("kConflictPrefix is the canonical 'conflict:' string", "[store_errors]") {
    // Wire-contract assertion. If anyone ever shortens this to 'conf:' or
    // capitalizes it, the route handlers and this test all fail together
    // — exactly the failure mode the centralization is designed to enforce.
    CHECK(std::string(kConflictPrefix) == "conflict:");
}

TEST_CASE("is_conflict_error matches only the canonical prefix",
          "[store_errors]") {
    CHECK(is_conflict_error("conflict: anything"));
    CHECK(is_conflict_error("conflict:nospace"));
    CHECK(is_conflict_error("conflict:"));

    // Negative cases — the route layer must default to 400 for these.
    CHECK_FALSE(is_conflict_error(""));
    CHECK_FALSE(is_conflict_error("Conflict: capitalized"));
    CHECK_FALSE(is_conflict_error(" conflict: leading space"));
    CHECK_FALSE(is_conflict_error("not a conflict"));
    CHECK_FALSE(is_conflict_error("internal: prepare failed"));
    CHECK_FALSE(is_conflict_error("insert failed: UNIQUE constraint"));
}

TEST_CASE("strip_conflict_prefix returns the operator-facing message",
          "[store_errors]") {
    // Canonical form: "conflict: <message>" → "<message>".
    CHECK(strip_conflict_prefix("conflict: instruction definition 'foo' already exists") ==
          "instruction definition 'foo' already exists");
    CHECK(strip_conflict_prefix("conflict: policy fragment named 'bar' already exists") ==
          "policy fragment named 'bar' already exists");

    // Multiple spaces after the prefix collapse — defensive against future
    // contributors writing "conflict:  foo" by accident.
    CHECK(strip_conflict_prefix("conflict:   spaced") == "spaced");

    // No-space form is also stripped (helper does not require the space).
    CHECK(strip_conflict_prefix("conflict:nospace") == "nospace");

    // Non-conflict messages are returned unchanged.
    CHECK(strip_conflict_prefix("internal: prepare failed") == "internal: prepare failed");
    CHECK(strip_conflict_prefix("") == "");
    CHECK(strip_conflict_prefix("insert failed") == "insert failed");
}

// iter-L1: lock in boundary behavior on degenerate inputs flagged by Gate 7
// re-review (sec-LOW1 deferred — verify these don't crash or underflow).
TEST_CASE("strip_conflict_prefix handles boundary inputs without underflow",
          "[store_errors][boundary]") {
    // Bare prefix with no body — must return an empty view, not underflow
    // when the rest is empty after the leading-space loop.
    CHECK(strip_conflict_prefix("conflict:") == "");
    CHECK(strip_conflict_prefix("conflict: ") == "");
    CHECK(strip_conflict_prefix("conflict:    ") == "");

    // Embedded NUL after the prefix — string_view preserves the NUL; the
    // helper must still strip the prefix correctly. Audit/log layers may
    // truncate at NUL but that's their concern, not the helper's.
    std::string nul_after_prefix("conflict:\0bar", 13);
    auto stripped = strip_conflict_prefix(nul_after_prefix);
    CHECK(stripped.size() == 4);  // "\0bar" is 4 bytes
    CHECK(stripped[0] == '\0');
    CHECK(stripped[1] == 'b');

    // is_conflict_error matches the prefix even if the body contains NULs.
    CHECK(is_conflict_error(nul_after_prefix));
}

// #753: kind_mismatch_error()/kind_missing_error() unify the kind-validation
// wording across PolicyStore, WorkflowEngine and ProductPackStore. These
// pin the exact byte output so a refactor of either helper can't silently
// drift what operators see.
TEST_CASE("kind_mismatch_error produces the exact two-argument message",
          "[store_errors]") {
    CHECK(kind_mismatch_error("Workflow", "Policy") ==
          "kind must be 'Workflow', got 'Policy'. yaml_source must be a "
          "complete YAML document including 'apiVersion: yuzu.io/v1alpha1' "
          "and 'kind: Workflow'.");
}

TEST_CASE("kind_missing_error produces the exact message", "[store_errors]") {
    CHECK(kind_missing_error() ==
          "kind is required. yaml_source must be a complete YAML document "
          "including 'apiVersion: yuzu.io/v1alpha1' and a 'kind:' field.");
}

TEST_CASE("kind_mismatch_error wording agrees across stores modulo the "
          "substituted kind",
          "[store_errors]") {
    // Cross-store wording agreement asserted mechanically: swap the
    // expected kind for the substring that would differ, and the three
    // results must then be byte-identical.
    auto fragment_msg = kind_mismatch_error("PolicyFragment", "X");
    auto policy_msg = kind_mismatch_error("Policy", "X");
    auto workflow_msg = kind_mismatch_error("Workflow", "X");

    auto normalize = [](std::string s, std::string_view kind) {
        std::string placeholder = "<KIND>";
        std::string::size_type pos = 0;
        while ((pos = s.find(kind, pos)) != std::string::npos) {
            s.replace(pos, kind.size(), placeholder);
            pos += placeholder.size();
        }
        return s;
    };

    auto fragment_norm = normalize(fragment_msg, "PolicyFragment");
    auto policy_norm = normalize(policy_msg, "Policy");
    auto workflow_norm = normalize(workflow_msg, "Workflow");

    CHECK(fragment_norm == policy_norm);
    CHECK(policy_norm == workflow_norm);

    // Sanity: the un-normalized messages actually differ (otherwise the
    // check above would be vacuous).
    CHECK(fragment_msg != policy_msg);
    CHECK(policy_msg != workflow_msg);
}

// Governance Gate 2/3/4/6 (SEC-1/ARCH-1/Finding-B/CO-1, InstructionStore PG migration):
// three independent call sites let a kDbErrorPrefix error reach a client response or a
// persisted audit row verbatim before genericize_db_error()/is_generic_db_error() existed —
// each had re-derived its own ad hoc prefix check. These tests lock in the shared contract
// so a future call site can trust the helper instead of re-deriving a fourth check, the same
// way the kConflictPrefix tests above protect create_definition's 409 path.

TEST_CASE("kDbErrorPrefix is the canonical 'db_error: ' string", "[store_errors]") {
    CHECK(std::string(kDbErrorPrefix) == "db_error: ");
}

TEST_CASE("is_generic_db_error matches only the canonical prefix", "[store_errors]") {
    CHECK(is_generic_db_error("db_error: connection refused"));
    CHECK(is_generic_db_error("db_error: "));

    CHECK_FALSE(is_generic_db_error(""));
    CHECK_FALSE(is_generic_db_error("db_error:no space, wrong form"));
    CHECK_FALSE(is_generic_db_error("Db_Error: capitalized"));
    CHECK_FALSE(is_generic_db_error("conflict: instruction set 'x' already exists"));
    CHECK_FALSE(is_generic_db_error("not_found: no such instruction"));
}

TEST_CASE("genericize_db_error hides driver text and passes everything else through",
          "[store_errors]") {
    // The exact defect this closes: a raw PQerrorMessage() fragment — connection detail,
    // occasionally host:port — must never reach the caller verbatim.
    CHECK(genericize_db_error("test-op", "db_error: connection to server at "
                                         "\"10.0.4.7\", port 5432 failed") ==
          "service unavailable");
    CHECK(genericize_db_error("test-op", "db_error: ") == "service unavailable");

    // not_found/conflict/validation text is operator-facing feedback, not database
    // internals — must pass through unchanged (this is what create_set's 409 fix and
    // dispatch_fn's "unknown instruction" message both rely on).
    CHECK(genericize_db_error("test-op", "conflict: instruction set 'x' already exists") ==
          "conflict: instruction set 'x' already exists");
    CHECK(genericize_db_error("test-op", "unknown instruction: foo") ==
          "unknown instruction: foo");
    CHECK(genericize_db_error("test-op", "") == "");
}
