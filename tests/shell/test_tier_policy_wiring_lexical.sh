#!/usr/bin/env bash
# test_tier_policy_wiring_lexical.sh -- #5047 static lexical gate over
# server/core/src/server.cpp's two TierPolicyFn wiring sites.
#
# AuthRoutes::gateless_tier_policy_fn() (auth_routes.hpp) is the SOLE
# production factory for a gate-less-route TierPolicyFn -- both server.cpp
# sites' own comments say so explicitly: "never re-inline this as a local
# lambda; a second copy is exactly how the original clause-5 violation this
# belt exists to prevent could recur unreviewed at a 9th call site."
#
# The unit test in test_auth_routes.cpp ("gateless_tier_policy_fn -- the
# REAL production TierPolicyFn...") drives the factory directly and proves
# its OUTPUT is correct, but it cannot observe whether server.cpp actually
# calls the factory -- a reverted call site (back to a hand-rolled lambda
# naming .permission, reopening the clause-5 gap) or a new undocumented
# third call site would pass every existing test. This gate closes that:
#
#   1. `result_set::Deps`'s designated-init field (the dashboard-fragment
#      wiring, /fragments/result-sets/*) reads
#      `.tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),` --
#      exactly once.
#   2. `rest_api_v1_->register_routes(...)`'s final positional argument
#      (the REST /api/v1/result-sets JSON wiring) is
#      `auth_routes_->gateless_tier_policy_fn());` -- exactly once.
#   3. The literal substring `auth_routes_->gateless_tier_policy_fn()`
#      appears in server.cpp EXACTLY TWICE, total -- catches both a
#      reversion at either known site (count drops below 2) and a new,
#      undocumented third call site (count rises above 2).
#
# Static/text-only, no build required -- a lexical gate, not a semantic one
# (mirrors test_log_handoff_wiring_lexical.sh's own framing): it cannot see
# a relocation that keeps the same tokens but changes the surrounding
# control flow -- that stays a review-enforced concern.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
SERVER_CPP="$ROOT/server/core/src/server.cpp"

if [ ! -f "$SERVER_CPP" ]; then
  echo "::error::test_tier_policy_wiring_lexical: $SERVER_CPP not found" >&2
  exit 1
fi

fail=0

total_count="$(grep -c 'auth_routes_->gateless_tier_policy_fn()' "$SERVER_CPP" || true)"
designated_count="$(grep -c '\.tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),' "$SERVER_CPP" || true)"
positional_count="$(grep -c '^[[:space:]]*auth_routes_->gateless_tier_policy_fn());$' "$SERVER_CPP" || true)"

if [ "$designated_count" -ne 1 ]; then
  echo "::error::test_tier_policy_wiring_lexical: expected exactly 1 designated-init site ('.tier_policy_fn = auth_routes_->gateless_tier_policy_fn(),' -- the dashboard-fragment result_set::Deps wiring), found $designated_count. A reversion to a hand-rolled lambda here reopens the #5047 clause-5 gap on /fragments/result-sets/*." >&2
  fail=1
fi

if [ "$positional_count" -ne 1 ]; then
  echo "::error::test_tier_policy_wiring_lexical: expected exactly 1 positional-arg site ('auth_routes_->gateless_tier_policy_fn());' -- the REST rest_api_v1_->register_routes(...) wiring), found $positional_count. A reversion to a hand-rolled lambda here reopens the #5047 clause-5 gap on /api/v1/result-sets." >&2
  fail=1
fi

if [ "$total_count" -ne 2 ]; then
  echo "::error::test_tier_policy_wiring_lexical: expected the literal 'auth_routes_->gateless_tier_policy_fn()' to appear EXACTLY TWICE in server.cpp (the two known call sites), found $total_count. A count above 2 means an undocumented new call site was added outside this gate's knowledge -- extend this script in the same change, per gateless_tier_policy_fn()'s own doc comment (auth_routes.hpp: 'both server.cpp wiring sites call this SAME function')." >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "test_tier_policy_wiring_lexical: OK -- both server.cpp TierPolicyFn wiring sites call AuthRoutes::gateless_tier_policy_fn() (designated-init site: 1, positional-arg site: 1, total literal occurrences: $total_count)"
