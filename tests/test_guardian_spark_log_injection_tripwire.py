#!/usr/bin/env python3
"""#4665 tripwire: no NEW spdlog:: call prints a rule-id/Spark-key-shaped value unwrapped.

#4665 closed CWE-117 log-injection on operator-authored Guardian `rule_id` /
Spark `key` (and the path/hive/service/unit-name values a Spark mechanism embeds
in a log line): every raw print site across the agent's guard_*/spark_*/
guardian_* sources and the server's guardian_push_builder.cpp/
guaranteed_state_store.cpp now goes through yuzu::log_id_token / yuzu::
log_key_token (common/include/yuzu/log_token.hpp). This test is the regression
net: it fails the moment a NEW spdlog:: call in the Guardian/Spark subsystem
prints one of these fields unwrapped.

WHY POSITION-AWARE, NOT "does log_id_token/log_key_token appear ANYWHERE in the
statement". A whole-statement substring check passes a multi-argument call
where only ONE of several sensitive arguments is wrapped -- e.g.
`spdlog::warn("rule '{}' key '{}'", log_id_token(rule_id), key)` would pass
with `key` still raw. This is not hypothetical: it is the exact shape fixed at
guardian_spark_runtime.cpp's "key '{}' still has {} queued claim(s) ... for
rule '{}'" site during this sweep (one placeholder wrapped, the other not, in
the SAME statement). So this scanner:
  1. parses each spdlog::LEVEL(...) call's format-string literal (concatenating
     adjacent string-literal tokens, which several real call sites split across
     physical lines) and its argument list separately;
  2. finds every `{}`-shaped placeholder in the literal, in left-to-right
     (= positional) order;
  3. matches SENSITIVE_PATTERNS against the literal's TEXT -- a pattern match's
     character span marks every placeholder whose span overlaps it as sensitive;
  4. maps placeholder i (0-indexed) to argument i (0-indexed) -- the ordinary
     spdlog/fmt convention for bare `{}` placeholders (verified: no call site in
     the scanned tree uses an indexed `{0}` or spec'd `{:...}` placeholder that
     would break this mapping -- grep `spdlog::.*\\{[0-9]` / `\\{:` came back
     empty across the scanned file set at the time this test was written; a
     FUTURE indexed placeholder would silently defeat the positional mapping,
     a documented limitation, not something this scanner detects);
  5. for each sensitive placeholder, requires ITS OWN argument's text (not the
     whole statement) to contain a call to a recognised wrapper or safe
     formatter (WRAP_CALLS / SAFE_FORMATTER_CALLS below) -- substring-within-
     the-argument-slot, which is what correctly flags the two-placeholder gap
     above (only one slot's text contains the call) while still passing a
     wrapped value hidden inside a ternary, e.g.
     `detail.empty() ? "no reason given" : log_key_token(detail)`
     (guardian_spark_runtime.cpp's "subscription {} lost" site) -- the call
     appears somewhere WITHIN that specific argument's own text, not merely
     somewhere in the statement.

FILE SCOPE -- three roots, filtered to the Guardian/Spark basename glob, NOT a
bare three-root scan. "rule" and "key" are common English words: an early,
literal three-root sweep for a bare `key '{}'` pattern hit key_provider.cpp
(KMS key ids), runtime_config_store.cpp (encrypted-blob keys),
custom_properties_store.cpp (schema keys), trigger_engine.cpp (a registry-
trigger key, a DIFFERENT feature from Guardian), server.cpp (a SAML
signing-key path) and grpc_on_behalf_interceptor.hpp (an on-behalf-of metadata
key) -- none are #4665's domain, and none would be caught by a human reviewer
reading a `git grep key` dump without also reading each site. Restricting the
walk to FILE_BASENAME_RE (guardian_*/guard_*/spark_*/guaranteed_state*, the
same basename family the routed-concern rows in .claude/routed-concerns.md use
as the Guardian/Spark trigger surface) removes that false-positive class
without weakening precision inside the subsystem: every literal-substring
pattern below was verified, by a fresh `git grep` sweep of the FILTERED file
set at authoring time, to match ONLY genuine rule-id/Spark-key print sites
(each match's file:line was read and classified by hand) plus, in exactly one
case, a documented false positive that a SECOND condition (a message-prefix
requirement, not a per-file exclusion) resolves -- see the "key '{}'" entry in
SENSITIVE_PATTERNS below.

KNOWN, ACCEPTED, PERMANENT LIMITATION (do not try to close, matching this
repo's convention of stating a check's limits plainly -- see
test_no_connless_pq_escape.py's own header): a format string of bare `"{}"`
with no surrounding sensitive-pattern text is NEVER flagged, because this
scanner decides sensitivity from the LITERAL's text, and a bare `"{}"` carries
none. guardian_engine.cpp's `start_local()` builds `degrade_msg` (a
std::string) by concatenating `"Guardian: rule '" + log_id_token(rule.rule_id())
+ "' failed to re-arm (" + ...` THREE LINES ABOVE its print site
(`spdlog::error("{}", degrade_msg)`) -- the rule_id is correctly wrapped at
the point of concatenation, but this scanner cannot see that: it has no
data-flow analysis, only literal-text pattern matching on the format string
actually passed to spdlog. This is a real, permanent limitation of the lexical
approach (tracing local-variable construction is out of scope), not a scanner
bug -- see _selfcheck()'s degrade_msg-shaped case, which asserts the scanner
does NOT flag it and documents why that is expected.

SECOND KNOWN LIMITATION (Phase-3 governance quality-engineer finding,
2026-09-25, empirically confirmed and left open rather than closed here):
`parse_call()` requires the statement's first token after `(` to be a `"`
string literal, so `spdlog::warn(fmt::format("Guardian: rule '{}' failed",
rule_id));` -- a raw, wholly unwrapped rule_id, zero token wrapping anywhere
in the statement -- makes `parse_call` return `None` and the whole statement
is silently skipped. No current call site in this tree uses this idiom
(verified by grep at authoring time), but `fmt::format`-wrapped-then-passed
spdlog calls are a standard idiom industry-wide, so this is a real gap in
the scanner's coverage claim above, not a hypothetical one. Extending
`parse_call` to descend into a sole `fmt::format(...)`/`fmt::vformat(...)`
wrapping call is tracked as a follow-up rather than fixed in this same
governance pass (Test 1/2 in Gate 7: no live instance exists today, so this
is scanner-hardening against a future regression class, not a fix for a
current forgery sink).

SAFE FORMATTERS. A call site that passes a raw-looking argument to a function
in SAFE_FORMATTER_CALLS below -- not to spdlog:: directly -- is not flagged;
the wrap happens INSIDE the formatter:
  - format_arm_committed_line() (agents/core/src/guardian_spark_timing.cpp) --
    wraps its rule_id parameter via log_id_token before building the returned
    string (confirmed by reading the implementation). Its one real call site
    (guardian_spark_runtime.cpp) passes the result through
    `spdlog::info("{}", format_arm_committed_line(rule_id, ...))` -- a bare
    `"{}"` literal, so it is not even reached by the sensitivity check (see the
    known-limitation paragraph above); the exemption is still real and
    exercised by _selfcheck() against a synthetic literal that WOULD otherwise
    be flagged, so a future direct call shaped like
    `spdlog::info("... for rule '{}'", format_arm_committed_line(rule_id, ...))`
    stays correctly unflagged too.
  - log_safe() (server/core/src/web_utils.hpp) is DELIBERATELY NOT in
    SAFE_FORMATTER_CALLS, and this is a correction, not the original design: an
    earlier revision of this file allowlisted it as an "adequate CWE-117
    mitigation" for guardian_routes.cpp's rate-limited "platform support-matrix
    stale" k=v-shaped log line (#4665 governance-external-review finding,
    fjarvis, PR #4979). That reasoning was WRONG -- log_safe() folds only
    control bytes (0x00-0x1F, 0x7F), not space/'='/',', so on a `k=v k=v` line
    a crafted value could still forge an ADJACENT field (e.g. a rule_id like
    "x result=success"), the exact same-line CWE-117 threat this whole sweep
    exists to close, just missed because log_safe's own call sites were
    blanket-exempted rather than checked for line shape. That call site now
    uses audit_token (web_utils.hpp, forwards to yuzu::log_token, folds
    space/'='/',' too) instead. log_safe() remains a real, still-used helper
    OUTSIDE this file family (instruction_routes.cpp, approval_routes.cpp) for
    genuinely non-k=v-shaped single-value lines, where control-byte folding
    alone is sufficient -- this scanner has no opinion on those, since its
    scan scope never reaches them. A FUTURE log_safe(...) call appearing
    inside a file this scanner DOES cover is deliberately left unexempted, so
    it gets flagged and a reviewer has to consciously verify the line shape
    rather than inherit a blanket pass.

SECOND, SEPARATE CHECK (#5513): claimed agent ids in seven named files outside the
Guardian/Spark basename family -- server/core/src/agent_service_impl.cpp,
gateway_service_impl.cpp, agent_registry.cpp, custom_properties_store.cpp,
custom_properties_routes.cpp, tag_store.cpp and config_routes.cpp (AGENT_ID_FILES). It flags a spdlog:: argument that is a request-derived agent id
(`info.agent_id()`, `request->agent_id()`, `req->agent_id()`, a local alias bound from
one of those in the same function, or the bare `agent_id` in the custom-properties
files and tag_store.cpp, where the bare caller-supplied tag `key` is also matched; the bare `key`
and `validation_regex` in custom_properties_store.cpp and the bare path parameter `key` in
config_routes.cpp are matched the same way) and is
not wholly a log_id_token / log_key_token / audit_token /
onbehalf::sanitize_for_log call or the local `safe_agent_id`. It is LEXICAL: it reads
argument text, not data flow, so an id reaching the log through a variable it cannot
trace to a request accessor, or a new spelling, is not seen. The exact scope and limits
are in the block comment above find_agent_id_violations_in_text(). FILE_BASENAME_RE and
the pattern check above are unchanged and do not apply to these seven files.
In agent_registry.cpp only the claimed ids from `info.agent_id()` (and the local
`safe_agent_id` built from it) are in scope; the many other spdlog calls in that file print
ids taken from the session table and are deliberately not matched.
A fourth, narrower rule (REGISTRY_FREE_TEXT_FILES, agent_registry.cpp only) requires an
spdlog:: argument that is an agent-supplied hostname (`info.hostname()` or a local alias bound
from it) or the `.error()` of a `revoke_by_device(` or `register_agent(` result (a store error
string that can quote the device id) to be wholly one wrap call. The `register_agent(` half
also runs on agent_service_impl.cpp and gateway_service_impl.cpp (REGISTRY_FREE_TEXT_FILES).
A fifth, narrower rule (COMMAND_TEXT_FILES, agent_service_impl.cpp, gateway_service_impl.cpp and
agent_registry.cpp)
requires every spdlog:: argument that is `.command_id()` or `.plugin()` on a message receiver
(these are free-form bytes on a CommandResponse frame the agent sends), `.gateway_node()` on a
message receiver or a `.cluster_id()` accessor or the bare local `cluster_id` (gateway-asserted
provenance fields on the stream-status and heartbeat notifications) to be wholly one
log_id_token / log_key_token / audit_token / sanitize_for_log call. It also matches the
member form `.gateway_node` (no parentheses, a session-table read) in agent_registry.cpp. It
reads argument text only: a value copied into a local under another name first is not seen;
request-metadata session ids printed before their lookup, `sync.error()`-style fixed-text
errors and member-form session reads other than `.gateway_node` are not tracked (lexical limit).
A sixth guard (UNSCANNED_LOGGING_FILES, the second check's files except config_routes.cpp, which
reads the default logger's level without logging through it, plus server/core/src/pg/pg_pool.cpp)
fails on any
logging FORM the scanner does not parse: an `SPDLOG_TRACE|DEBUG|INFO|WARN|ERROR|CRITICAL(`
macro, `spdlog::log(` or `default_logger`. The rules above only understand `spdlog::<level>(`
and `<logger>-><level>(` calls, so a different form would otherwise escape them silently;
this makes it fail loudly instead. A new file added to the second check is covered by
extending that tuple, not by this note.
A third, narrower rule (PQ_ERROR_FILES) requires every spdlog:: argument that contains a
PQerrorMessage( or PQresultErrorMessage( call in custom_properties_store.cpp, tag_store.cpp and
pg/pg_pool.cpp to be wrapped (libpq error text can quote the claimed agent id). It matches the
call name only: a value copied into a local first is not seen, which is why pg_pool.cpp's
connect-failure line (it prints a local `err` copied from PQerrorMessage) is wrapped by hand but
not covered here. The same rule keyed on a store `.error()` argument covers config_routes.cpp
(STORE_ERROR_FILES).

A seventh, narrower rule (PKI_SIGNER_FILES, server/core/src/server.cpp only) covers the PKI signer
legs of the Register / ProxyRegister path: an spdlog:: statement whose format literal starts with
"PKI:" must wrap a bare `agent_id` argument and any `.what()` argument. It is not the broad
bare-name rule and does not apply to the rest of server.cpp.

WHAT THE SECOND CHECK DELIBERATELY DOES NOT COVER (session-resolved ids). Log lines that print an
agent id read back from the session table or the enrollment store print it as stored: the
Heartbeat / BatchHeartbeat and ReportInventory / ProxyInventory ingest paths and the shared
ingestion modules they call, the Subscribe stream open and close lines, and the registry's removal
and sweep lines (in agent_registry.cpp only claimed ids from `info.agent_id()` are matched).
AuthDB's agent-id check (`agent_id_ok`, auth_db.cpp) has already refused control bytes and ',' for
such an id, so it cannot add a physical log line, but an id enrolled before the new-id charset gate
(`auth::is_valid_new_agent_id`) may still contain a space, '=' or a non-ASCII byte, and so can add
same-line key=value tokens. The `ex.what()` of the ingest catch-alls on those paths is likewise
printed as-is. This is a stated limit of the check, not a claim that those lines are neutralised.

Wired into tests/meson.build (suite 'docs') and .github/workflows/docs-lint.yml,
same precedent shape as test_no_connless_pq_escape.py and
test_split_interlock_tripwire.py. Zero third-party dependencies (stdlib only).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()

SEARCH_ROOTS = ["agents/core/src", "server/core/src", "common/include"]

# Guardian/Spark subsystem basenames -- see the module docstring's FILE SCOPE
# paragraph for why this is not a bare three-root scan.
FILE_BASENAME_RE = re.compile(r"^(guardian_|guard_|spark_|guaranteed_state)[A-Za-z0-9_]*\.(cpp|hpp)$")

# #4666 PR-4: also matches a call THROUGH a bound `spdlog::logger` handle
# (`logger->info(...)`), not only the free-function `spdlog::info(...)` form --
# server/core/src/guardian_ingest.cpp's T_server line resolves its logger
# through a seam (`t_server_logger_snapshot()`) and calls `->info(...)` on the
# result, which the free-function-only pattern silently missed (a false green:
# the scan just finds zero statements in the file, not a scan failure). `\w+->`
# covers a PLAIN IDENTIFIER holding a logger handle (any name, not anchored to
# `logger` specifically), so a FUTURE bound-logger call anywhere in this file
# family is covered the same way without its own scanner change -- this is a
# regression net, not just a fix for the one site found here. It does NOT
# match a chained call, e.g. `get_logger()->info(...)` (the `)` immediately
# before `->` is not a `\w` character) -- a real gap if that idiom appears in
# this file family later, not claimed closed here.
# Verified harmless against this file family's existing content: no non-
# logging `<ident>->info|warn|error|...(` call shape exists in it today (the
# nearest look-alike, `r->error()` in guardian_spark_runtime.cpp, is a bare
# no-argument call whose first token after `(` is not a string literal, so
# parse_call() already returns None for it, the same graceful skip every
# non-spdlog statement this scanner cannot analyse gets -- see parse_call()'s
# own docstring).
SPDLOG_CALL_RE = re.compile(r"\b(?:spdlog::|\w+->)(?:trace|debug|info|warn|error|critical)\s*\(")

# Recognised wrappers that fully neutralise a rule-id/Spark-key-shaped argument.
# Checked as a substring WITHIN the specific argument's own text slot -- see the
# module docstring's WHY POSITION-AWARE paragraph. audit_token (web_utils.hpp)
# forwards to yuzu::log_token verbatim -- the same control-byte/DEL/space/'='/
# ',' fold log_id_token itself builds on -- so it closes the same-line k=v
# field-forgery threat just as completely for a server-side log line
# (guardian_routes.cpp's platform-matrix-stale site, #4665
# governance-external-review fix, fjarvis PR #4979). log_id_token additionally
# ASCII-folds and length-truncates on top of that same core, for a different
# concern (non-ASCII confusables / unbounded identifier length) this
# particular site doesn't need.
WRAP_CALLS = (
    "log_id_token(",
    "log_key_token(",
    "audit_token(",
)

# Named list of "known safe formatter" functions -- see the module docstring's
# SAFE FORMATTERS paragraph. Extend this list deliberately, not by accretion:
# a new entry needs the same "read the implementation, confirm it wraps before
# returning" justification this one got. log_safe() is deliberately NOT here
# (see the docstring's log_safe paragraph) -- it folds only control bytes, not
# space/'='/',', so it is not a safe substitute for a k=v-shaped log line, and
# blanket-exempting it once already hid a real forgery gap (#4665
# governance-external-review, fjarvis, PR #4979).
SAFE_FORMATTER_CALLS = (
    "format_arm_committed_line(",
)

ALL_SAFE_CALLS = WRAP_CALLS + SAFE_FORMATTER_CALLS

PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")


class Pattern:
    """A sensitive-field literal pattern. `text` is matched as a literal
    substring (case-sensitive) against the concatenated format-string
    literal; every `{}` placeholder whose span overlaps a match is marked
    sensitive. `requires_prefix`, if set, additionally requires the WHOLE
    literal to start with that substring (used to scope a pattern to one
    call-site family, e.g. RegistryGuard-only). `excludes_suffix`, if set,
    skips a match whose span is IMMEDIATELY followed by that substring --
    infrastructure kept for a future scoping need; no current pattern uses
    it (the one prior use, on the RegistryGuard bracket pattern, was removed
    when the field it carved out for -- value_type -- was itself found to
    need wrapping, see that pattern's own comment)."""

    __slots__ = ("name", "text", "requires_prefix", "excludes_suffix")

    def __init__(
        self,
        name: str,
        text: str,
        requires_prefix: str | None = None,
        excludes_suffix: str | None = None,
    ) -> None:
        self.name = name
        self.text = text
        self.requires_prefix = requires_prefix
        self.excludes_suffix = excludes_suffix


# Derived from a fresh sweep of this branch's own #4665 commits (git log
# 2ef5b8d3c..d081b0c75) plus a fresh git grep of the filtered file set at
# authoring time -- see the module docstring. Each entry's rationale/evidence:
SENSITIVE_PATTERNS = [
    # The `XxxGuard[{}]:` rule_id-bracket line prefix shared by FileGuard/
    # RegistryGuard/ServiceGuard/SystemdServiceGuard (guard_file.cpp,
    # guard_registry.cpp, guard_service.cpp, guard_systemd.cpp) -- the FIRST
    # placeholder on every one of those lines is cfg_.rule_id.
    Pattern("Guard[{}]", "Guard[{}]"),
    # Quoted rule_id: `rule '{}'` (and `for rule '{}'`, which contains this as
    # a substring) -- guardian_engine.cpp, guardian_arm_ack.cpp,
    # guardian_spark_bridge.hpp, guardian_spark_runtime.cpp.
    Pattern("rule '{}'", "rule '{}'"),
    # Unquoted key=value rule_id forms -- guaranteed_state_store.cpp
    # (`rule_id={}`), guardian_ingest.cpp/guardian_routes.cpp (`rule={}`).
    Pattern("rule_id={}", "rule_id={}"),
    Pattern("rule={}", "rule={}"),
    # guardian_push_builder.cpp's two-placeholder id+name form: "Guardian
    # push: rule {} ('{}') ...". Deliberately spans BOTH placeholders in one
    # pattern (the id at bare `{}`, the name inside the quotes) -- covers the
    # mutation shape where only one of the two got wrapped.
    Pattern("rule {} ('{}')", "rule {} ('{}')"),
    # Spark key, quoted: `key '{}'`. Conditioned on the literal STARTING WITH
    # "Guardian spark:" -- a fresh sweep of the filtered file set found this
    # exact phrase in exactly two places: guardian_spark_runtime.cpp (9 sites,
    # all genuine Spark-key prints, all under this prefix) and
    # guardian_lifecycle_journal.cpp's "Guardian journal: batch key '{}' is in
    # the PRE-TIMESTAMP format" (a FALSE POSITIVE on the English word "key":
    # that key is `journal_batch_key(ts_ms, boot_nonce, seq)` --
    # "lc:<ts13>:<nonce>:<seq12>" -- entirely agent-minted from a timestamp, a
    # random boot nonce and a counter, with NO operator-controlled substring,
    # so it carries no injection risk and is not #4665's domain). The prefix
    # condition is evidence-derived (every genuine site really does start with
    # "Guardian spark:"), not a one-off exclusion for that one file: a NEW
    # non-spark guardian_* file's unrelated "... key '{}' ..." line still
    # correctly does not match, without needing its own carve-out.
    Pattern("key '{}'", "key '{}'", requires_prefix="Guardian spark:"),
    # SparkEngine mechanism-layer key prints, all quoted -- spark_engine.cpp.
    Pattern("armed '{}'", "armed '{}'"),
    Pattern("disarmed '{}'", "disarmed '{}'"),
    Pattern("spark '{}'", "spark '{}'"),
    Pattern("watch '{}'", "watch '{}'"),
    Pattern("unwatch('{}')", "unwatch('{}')"),
    # "for '{}'" -- spark_file.cpp/spark_registry.cpp's "probe for '{}'",
    # "establishment report for '{}'", "drain worker for '{}'", "synthetic
    # fire for '{}'", "emit for '{}'"; guard_service.cpp/guard_systemd.cpp's
    # "FAILED for '{}'"/"failed for '{}'"/"match arm failed for '{}'"; and
    # spark_service.cpp's "ActiveState read transient error for '{}'"/"match
    # arm failed for '{}'" (the Linux systemd Spark MECHANISM's own unit-name
    # prints -- see this test's own docstring-adjacent RISKS note in the
    # senior handoff for the two sites this pattern is expected to catch as
    # genuine, currently-unwrapped findings).
    Pattern("for '{}'", "for '{}'"),
    Pattern("establishing '{}'", "establishing '{}'"),
    # systemd unit name, quoted -- guard_systemd.cpp, spark_service.cpp.
    Pattern("LoadUnit '{}'", "LoadUnit '{}'"),
    Pattern("unit '{}'", "unit '{}'"),
    # Registry hive/value-name, quoted -- guard_registry.cpp.
    Pattern("hive '{}'", "hive '{}'"),
    # Service name, quoted -- guard_service.cpp. "service name '{}'" (the
    # invalid-name refusal) and "service '{}'" (the armed/watching lines) are
    # genuinely distinct substrings (the word "name" sits between "service"
    # and the quote in the first), so both are listed rather than one
    # subsuming the other.
    Pattern("service name '{}'", "service name '{}'"),
    Pattern("service '{}'", "service '{}'"),
    # guard_registry.cpp's "{}\\{} [{}]" hive\key[value_name] triple, split
    # into two overlapping patterns so each of the three placeholders is
    # covered: the first spans hive+key (the "{}\\{}" shared by every
    # hive/key print, including the ones with no value_name in the message),
    # the second spans key+value_name (present only where value_name is also
    # printed) -- both patterns' hits on the shared "key" placeholder are
    # redundant-but-harmless, not a bug.
    Pattern("hive\\key (registry)", "{}\\\\{}"),
    # guard_registry.cpp's ONE "watching {}\\{} [{}] (expect {}={})" summary
    # line uses this exact bracket position for value_TYPE, not value_name
    # -- verified by reading its argument list (rule_id, hive, key,
    # value_type, value_name, expected) against its placeholder order
    # (rule_id, hive, key, [bracket], "expect X=", "=Y"). Previously excluded
    # via excludes_suffix=" (expect " on the theory that value_type was a
    # closed-set/compile-time-literal string safe to leave raw -- the #4665
    # Phase-3 governance security-guardian review (2026-09-25) traced it
    # empirically to `param("value_type")`, fully attacker-authored free text
    # on the agent side, validated only indirectly by the SERVER's
    # `derive_rule_spec`/`validate_assertion_params` before a structured rule
    # is ever pushed -- NOT a compile-time enum. `value_type` is now wrapped
    # at both its call sites (guard_registry.cpp:403,525) and the exclusion
    # is removed so this pattern checks that bracket like every other one.
    Pattern("key[value_name] (registry)", "\\\\{} [{}]"),
    # guard_registry.cpp's "(detected={}, type={}{})" enforce-FAILED line's
    # OWN value_type placeholder -- scoped to RegistryGuard statements only
    # (guardian_spark_timing.cpp's unrelated "type={}" placeholder in its
    # frozen #4606 arm-committed evidence line is a closed-set Spark
    # mechanism-type enum, not operator input, and must NOT be flagged).
    Pattern("type={}", "type={}", requires_prefix="Guardian RegistryGuard["),
    # Guardian event_id, both call conventions seen in the tree --
    # guaranteed_state_store.cpp/guardian_ingest.cpp use "event_id={}";
    # guardian_outbox_send_executor.hpp uses "event_id {}" (a space, not '=').
    # log_token.hpp's own header names a Guardian event id as a log_id_token
    # case by definition ("a Guardian event id ends in `<wall_ms>-<seq>`"),
    # and make_event_id() (guardian_spark_runtime.cpp) concatenates
    # `agent_id + "-" + boot_nonce_ + "-" + rule_id + ...` -- rule_id is
    # charset-valid past apply_rules()'s #4665 pre-validation, but agent_id's
    # own neutralisation was NOT covered by this sweep's own event_id wrap,
    # so the composed event_id is not provably safe to print raw on that
    # basis alone. (3784a6f21's commit message deferred agent_id itself to
    # "#489's scope" -- re-checked at Phase-3 governance and found NOT to
    # hold: #489 is a REST audit `detail`/`target_id` sanitizer-promotion
    # sweep in rest_api_v1.cpp, and neither names agent_id nor this file's
    # spdlog:: sites. agent_id is now wrapped at its 3 real raw sites below.)
    Pattern("event_id={}", "event_id={}"),
    Pattern("event_id {}", "event_id {}"),
    # Guardian agent_id -- client-supplied at Register (length- and NUL-checked,
    # agent_service_impl.cpp), charset-unrestricted, so the same CWE-117
    # forgery threat model as rule_id/event_id applies. guaranteed_state_store
    # .cpp's upsert_rule_status and both insert_event_classified/insert_events
    # observation-projection-failure logs print it unquoted as "agent_id={}"
    # alongside an already-wrapped rule_id/event_id on the SAME line -- found
    # by Phase-3 governance cpp-safety review (2026-09-25) as a sibling-field
    # miss the original #4665 sweep left open under a miscited #489 deferral.
    Pattern("agent_id={}", "agent_id={}"),
    # The same agent_id printed under the other spellings the Guardian sources use:
    # "agent {}" (guardian_ingest.cpp's "ignoring __guard__ action '{}' from agent {}"),
    # "agent={}" (the T_server line), the quoted and colon forms ("agent '{}'", "agent: {}"),
    # and the "agent_id" key spelled with a colon, a quote or a space. Register checks the
    # id's length and NUL bytes at the door; control bytes and ',' are rejected later, in the
    # enrollment store (AuthDB agent_id_ok), so an id is logged before that rejection unless it
    # is wrapped (CWE-117 log-injection model as above). These spellings cover the shapes seen
    # so far; the scanner is lexical, so a new spelling needs a new pattern.
    Pattern("agent {}", "agent {}"),
    Pattern("agent={}", "agent={}"),
    Pattern("agent '{}'", "agent '{}'"),
    Pattern("agent: {}", "agent: {}"),
    Pattern("agent_id: {}", "agent_id: {}"),
    Pattern("agent_id '{}'", "agent_id '{}'"),
    Pattern("agent_id {}", "agent_id {}"),
    Pattern("agent ({})", "agent ({})"),
    # Unquoted key=value path/service forms in the "guard armed" summary lines
    # -- guardian_engine.cpp.
    Pattern("path={}", "path={}"),
    Pattern("service={}", "service={}"),
    # guardian_engine.cpp's "failed spark validation (...)" reconcile_rule_locked
    # diagnostic -- the parenthetical carries assertion.error(), whose content can
    # originate from FOUR different producer sites (rule.spark().type() here;
    # guardian_spark_bridge.hpp's "unrecognized {spark,file,service,registry}
    # {assertion} type: <value>" error strings), all operator-authored free text
    # with no charset validation before this point. #4665 governance-external-review
    # finding (fjarvis, PR #4979) -- found because the second placeholder's literal
    # text ("failed spark validation (") matched no existing pattern, so it carried
    # no sensitivity signal at all, not because a wrap was present and wrong.
    Pattern("failed spark validation (", "failed spark validation ("),
    # guard_registry.cpp's registry assertion VALUES -- operator-authored
    # `cfg_.expected` (a REG_SZ/REG_EXPAND_SZ value has no charset/format
    # constraint anywhere on its ingest path -- verified against
    # guardian_rule_spec.cpp's registry-assertion validator, which checks
    # only hive/key/value_type) and endpoint-read `detected`. #4665's
    # Phase-2 adversarial review (CDX-01/K5) found and reproduced these as a
    # real, previously-unwrapped physical-line forgery sink -- the same
    # driver-evidence threat model as every other pattern in this list, just
    # against an assertion datum rather than an identifier. Two shapes:
    # Scoped to RegistryGuard lines specifically: guard_service.cpp and
    # guard_systemd.cpp ALSO have "detected={}" text (their own drift/FAILED
    # lines), but their `detected_value` is a closed-set enum-to-string
    # mapping (service_state_token()/systemd_state_token(), a handful of
    # fixed literals -- verified by reading both), not operator-controlled
    # free text, so those are correctly NOT sensitive and must not be
    # flagged. Only RegistryGuard's `detected` (a raw REG_SZ/REG_EXPAND_SZ
    # read-back) is free text.
    Pattern("detected={}", "detected={}", requires_prefix="Guardian RegistryGuard["),
    # The "watching ... (expect {}={}) [resilient]" summary line's OWN
    # value_name+expected pair -- deliberately spans both placeholders in
    # one pattern (matching this file's own established style for
    # guardian_push_builder.cpp's "rule {} ('{}')" two-placeholder form),
    # so a future mutation wrapping only one of the two is still caught.
    Pattern("(expect {}={})", "(expect {}={})"),
    # The remediation-outcome ("armed[...] -> detected -> expected (Nus)")
    # success line has NO distinguishing key=value text around its bare
    # `detected`/`expected` placeholders -- anchor on the literal suffix
    # immediately after the value_name bracket instead (verified unique to
    # this one call site: guard_service.cpp's near-identical remediation
    # line uses `'{}' {} -> {}`, a single-quote before the arrow, not
    # `] {} -> {}`, so this text does not collide with it). Deliberately
    # stops right after the SECOND placeholder's closing brace -- extending
    # it to include the trailing " ({}us)" text would also span the
    # NEXT placeholder (d.remediation_latency_us, a plain integer, not
    # sensitive), wrongly demanding it be wrapped too.
    Pattern("] {} -> {}", "] {} -> {}"),
]


# ---------------------------------------------------------------------------
# Statement / literal / argument parsing. Pure lexical (no libclang / no AST):
# balanced-paren statement extraction and top-level comma splitting, both
# string/char-literal aware so a `(`, `)`, or `,` inside a quoted argument
# never mis-counts. Adjacent string-literal tokens (a format string split
# across physical lines, several real sites in this sweep do this) are
# concatenated the same way the C++ compiler would.
# ---------------------------------------------------------------------------


def _skip_ws_and_comments(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        if s[i].isspace():
            i += 1
        elif s.startswith("//", i):
            j = s.find("\n", i)
            i = n if j == -1 else j + 1
        elif s.startswith("/*", i):
            j = s.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            break
    return i


def _skip_string_literal(s: str, i: int) -> int:
    """s[i] == '"'. Return the index just past the closing quote."""
    n = len(s)
    i += 1
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == '"':
            return i + 1
        i += 1
    return n  # unterminated -- caller treats as "consumed the rest"


def _skip_char_literal(s: str, i: int) -> int:
    n = len(s)
    i += 1
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "'":
            return i + 1
        i += 1
    return n


def find_spdlog_statements(text: str) -> list[str]:
    """Return the full `spdlog::LEVEL(...)` statement text (including the
    call and its balanced closing paren) for every call in `text`."""
    return [stmt for _, stmt in find_spdlog_statements_with_pos(text)]


def find_spdlog_statements_with_pos(text: str) -> list[tuple[int, str]]:
    """As find_spdlog_statements, but each statement comes with its start
    offset in `text` (the agent-id check needs to look at the code before it)."""
    out: list[tuple[int, str]] = []
    for m in SPDLOG_CALL_RE.finditer(text):
        start = m.start()
        i = m.end()  # just past the opening '('
        depth = 1
        n = len(text)
        while i < n and depth > 0:
            c = text[i]
            if c == '"':
                i = _skip_string_literal(text, i)
                continue
            if c == "'":
                i = _skip_char_literal(text, i)
                continue
            if text.startswith("//", i):
                j = text.find("\n", i)
                i = n if j == -1 else j + 1
                continue
            if text.startswith("/*", i):
                j = text.find("*/", i + 2)
                i = n if j == -1 else j + 2
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            i += 1
        out.append((start, text[start:i]))
    return out


def parse_call(stmt: str) -> tuple[str, str] | None:
    """Given a full `spdlog::LEVEL(...)` statement, return
    (concatenated_format_literal, argument_list_text) or None if the first
    argument is not a string literal (nothing this scanner can analyse --
    a documented limitation, not an error)."""
    open_paren = stmt.index("(")
    i = _skip_ws_and_comments(stmt, open_paren + 1)
    if i >= len(stmt) or stmt[i] != '"':
        return None
    parts: list[str] = []
    while i < len(stmt) and stmt[i] == '"':
        end = _skip_string_literal(stmt, i)
        parts.append(stmt[i + 1 : end - 1])
        i = _skip_ws_and_comments(stmt, end)
    literal = "".join(parts)
    # i now points just past the format string's last literal token. The
    # statement's outer closing ')' is the LAST char (find_spdlog_statements
    # always ends a statement on its balancing close-paren). Explicit raise,
    # not assert: python3 -O strips asserts, and a violation here would mean
    # find_spdlog_statements' own invariant broke silently.
    if not stmt.endswith(")"):
        raise ValueError(f"internal invariant violated: statement does not end with ')': {stmt!r}")
    tail = stmt[i : len(stmt) - 1]
    tail_stripped = tail.lstrip()
    if tail_stripped.startswith(","):
        args_text = tail_stripped[1:]
    else:
        args_text = ""  # no arguments after the format string
    return literal, args_text


def split_top_level_args(args_text: str) -> list[str]:
    """Split on commas at paren/bracket/quote depth 0."""
    args: list[str] = []
    depth = 0
    cur_start = 0
    i = 0
    n = len(args_text)
    while i < n:
        c = args_text[i]
        if c == '"':
            i = _skip_string_literal(args_text, i)
            continue
        if c == "'":
            i = _skip_char_literal(args_text, i)
            continue
        if args_text.startswith("//", i):
            j = args_text.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if args_text.startswith("/*", i):
            j = args_text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            args.append(args_text[cur_start:i])
            cur_start = i + 1
        i += 1
    tail = args_text[cur_start:].strip()
    if tail:
        args.append(args_text[cur_start:])
    elif args:
        pass  # trailing comma with nothing after it -- ignore
    return [a for a in args if a.strip()]


def find_placeholders(literal: str) -> list[tuple[int, int]]:
    """Placeholder spans in left-to-right (positional) order. Assumes bare
    `{}` / unindexed-spec placeholders only -- see the module docstring's
    point 4 for why this was verified against the scanned tree, and its
    limitation if that ever changes."""
    return [m.span() for m in PLACEHOLDER_RE.finditer(literal)]


def sensitive_placeholder_indices(literal: str) -> dict[int, list[str]]:
    """Map placeholder index -> list of matching Pattern names."""
    placeholders = find_placeholders(literal)
    hits: dict[int, list[str]] = {}
    for pat in SENSITIVE_PATTERNS:
        if pat.requires_prefix is not None and not literal.startswith(pat.requires_prefix):
            continue
        start = 0
        while True:
            idx = literal.find(pat.text, start)
            if idx == -1:
                break
            end = idx + len(pat.text)
            if pat.excludes_suffix is not None and literal[end : end + len(pat.excludes_suffix)] == pat.excludes_suffix:
                start = idx + 1
                continue
            for pi, (ps, pe) in enumerate(placeholders):
                if ps < end and pe > idx:
                    hits.setdefault(pi, []).append(pat.name)
            start = idx + 1
    return hits


_SAFE_CALL_NAME_RE = re.compile(
    r"^(?:::)?(?:[A-Za-z_][A-Za-z0-9_]*::)*("
    + "|".join(re.escape(c.rstrip("(")) for c in ALL_SAFE_CALLS)
    + r")\("
)


def _is_whole_call_wrapped(text: str, name_re: "re.Pattern[str]" = _SAFE_CALL_NAME_RE) -> bool:
    """True iff `text`, taken as a WHOLE expression (not a substring match
    anywhere within it), is a single call to one of ALL_SAFE_CALLS --
    optionally namespace-qualified, e.g. `::yuzu::log_key_token(w.spark_key)`
    -- whose parens balance exactly at the end of `text`. `log_id_token(a)`
    passes; `raw + log_key_token(x)` and `log_id_token(a) + b` do NOT,
    because the call is not the whole expression, only a substring of it --
    this is the distinction #4665's Phase-2 adversarial review (CDX-03/K6)
    found the old substring-any check couldn't make."""
    text = text.strip()
    m = name_re.match(text)
    if m is None:
        return False
    i = m.end()  # just past the opening '(' the regex matched.
    depth = 1
    n = len(text)
    while i < n and depth > 0:
        c = text[i]
        if c == '"':
            i = _skip_string_literal(text, i)
            continue
        if c == "'":
            i = _skip_char_literal(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    return depth == 0 and i == n


_STD_STRING_CTOR_RE = re.compile(r"^std::string\s*[({]\s*")


def _is_fixed_string_literal(text: str) -> bool:
    """True iff `text` is nothing but a (optionally parenthesised, optionally
    `std::string{...}`/`std::string("...")`-constructed) double-quoted
    string literal -- a fixed, non-identifier, non-value-carrying expression.
    This is the ONE other shape a ternary branch may legitimately take
    without being wrapped: guardian_spark_runtime.cpp has real examples of
    both the bare form (`detail.empty() ? "no reason given" :
    log_key_token(detail)`) and the std::string-constructed form
    (`rule_id ? log_id_token(*rule_id) : std::string{"<all>"}`) -- neither
    branch carries operator-authored content, so neither needs a wrap; the
    OTHER (non-literal) branch of each ternary still must be wrapped."""
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    m = _STD_STRING_CTOR_RE.match(text)
    if m is not None and text.endswith((")", "}")):
        text = text[m.end() : -1].strip()
    return len(text) >= 2 and text[0] == '"' and _skip_string_literal(text, 0) == len(text)


def _split_top_level_ternary(text: str) -> tuple[str, str] | None:
    """If `text` is a `cond ? true_branch : false_branch` expression with the
    '?' and its matching ':' both at paren/quote depth 0, return
    (true_branch, false_branch), whitespace-trimmed. Otherwise None. Only the
    FIRST top-level '?'/':' pair is located; a nested ternary inside either
    branch is handled by the recursive safety check in argument_is_wrapped,
    not by this splitter finding it."""
    depth = 0
    q_idx = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i = _skip_string_literal(text, i)
            continue
        if c == "'":
            i = _skip_char_literal(text, i)
            continue
        if text.startswith("::", i):
            # The C++ scope-resolution operator, not a ternary colon -- a
            # single ':' inside it (e.g. the first one in `::yuzu::...`)
            # would otherwise be mistaken for the ternary's own ':' the
            # moment it appears after the '?', silently mis-splitting every
            # namespace-qualified true-branch call (::yuzu::log_id_token(...)
            # is exactly this shape and is real production code).
            i += 2
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "?" and depth == 0 and q_idx is None:
            q_idx = i
        elif c == ":" and depth == 0 and q_idx is not None:
            return text[q_idx + 1 : i].strip(), text[i + 1 :].strip()
        i += 1
    return None


def _branch_is_safe(text: str) -> bool:
    """A ternary branch is safe if it is itself wholly wrapped, a fixed
    string literal, or (recursively) a nested ternary whose own two branches
    are each safe by this same rule."""
    if _is_whole_call_wrapped(text) or _is_fixed_string_literal(text):
        return True
    nested = _split_top_level_ternary(text)
    if nested is not None:
        return _branch_is_safe(nested[0]) and _branch_is_safe(nested[1])
    return False


def argument_is_wrapped(arg_text: str) -> bool:
    """An argument bound to a sensitive placeholder is safe only if its
    ENTIRE value-producing expression is wrapped -- not merely if a wrap
    call's text appears SOMEWHERE within it. The prior "any(call in
    arg_text ...)" substring-any check silently passed both
    `cond ? raw_id : log_id_token(raw_id)` and `raw_key + log_key_token(x)`,
    since each contains a safe-call substring without every value-producing
    path actually being safe -- confirmed exploitable by #4665's Phase-2
    adversarial review (CDX-03/K6) via exactly those two constructions.
    Two shapes are accepted: the whole expression is a single balanced call
    to a safe helper, or the whole expression is a top-level ternary whose
    EACH branch is independently safe (wrapped, a fixed string literal, or a
    nested ternary of the same shape). Anything else -- concatenation, a
    bare raw identifier/member-access, a ternary with a raw non-literal
    branch -- is UNSAFE."""
    text = arg_text.strip()
    if _is_whole_call_wrapped(text):
        return True
    ternary = _split_top_level_ternary(text)
    if ternary is not None:
        true_branch, false_branch = ternary
        return _branch_is_safe(true_branch) and _branch_is_safe(false_branch)
    return False


def find_violations_in_text(text: str) -> list[tuple[int, str, list[str]]]:
    """Return (1-based line number, matched pattern names joined, statement
    snippet) for every unwrapped sensitive placeholder found in `text`."""
    violations: list[tuple[int, str, list[str]]] = []
    for stmt in find_spdlog_statements(text):
        parsed = parse_call(stmt)
        if parsed is None:
            continue
        literal, args_text = parsed
        sensitive = sensitive_placeholder_indices(literal)
        if not sensitive:
            continue
        args = split_top_level_args(args_text)
        for pi, pattern_names in sensitive.items():
            if pi >= len(args):
                # Fewer arguments than placeholders -- malformed call the
                # compiler would itself reject; nothing to check.
                continue
            if not argument_is_wrapped(args[pi]):
                line_no = text.count("\n", 0, text.index(stmt)) + 1
                violations.append((line_no, ", ".join(sorted(set(pattern_names))), stmt))
    return violations


# ---------------------------------------------------------------------------
# Second check: raw CLAIMED AGENT ID in a log call (register path, OTA path,
# custom-properties). Separate from the rule-id/Spark-key check above: that one
# is pattern-driven and confined to the Guardian/Spark basename family, which
# does not include the files below.
#
# LEXICAL, and narrow on purpose. It reuses the statement/argument helpers
# above (no new lexer) and looks at each spdlog call's arguments, not at the
# format string. It flags an argument that is, or contains, an agent id taken
# straight from a request, unless the argument is wholly one of the wrap calls
# (log_id_token / log_key_token / audit_token), onbehalf::sanitize_for_log, or the
# local `safe_agent_id` that Register / ProxyRegister build once. What counts as
# "an agent id taken straight from a request":
#   - a member-accessor spelling, `info.agent_id()`, `request->agent_id()`,
#     `req->agent_id()` (any receiver), except when it is immediately sized or
#     emptiness-tested (`.size()`, `.empty()`, `.length()`), which prints no
#     characters of the id;
#   - a local alias bound from such an accessor earlier in the SAME function, e.g.
#     `const auto& agent_id = request->agent_id();` (the function boundary is the
#     last line that starts with `}` in column 0 before the call);
#   - in the custom-properties files, the bare name `agent_id`, which there is
#     always a request-derived parameter or route capture.
# `safe_agent_id` is trusted only because its DEFINITION is checked too. What is checked, exactly:
# every declaration or init of a local NAMED `safe_agent_id` must have a right-hand side that is
# wholly one `log_id_token(...)` call, and a file that logs `safe_agent_id` without any such
# definition is flagged (use-without-definition, per file). Weakening that one definition, or
# deleting it while a use remains, goes red. It is NOT a proof about the name: renaming the
# local, passing it in as a parameter, or building it with `+=` after a safe init evades the
# definition check, and a definition in one function does not vouch for a use in another
# function of the same file.
# agent_registry.cpp is scanned by this check too, but only claimed ids from
# `info.agent_id()` and `safe_agent_id` are in scope there; its other spdlog calls print
# ids from the session table, which look like bare names with no accessor alias and are
# deliberately not matched. Hostnames and the revoke error text in that file are covered
# by the separate free-text rule (REGISTRY_FREE_TEXT_FILES) below.
# Not covered, by design: a bare id that reaches the log through a variable the
# check cannot trace to a request accessor (for example an id read back from a
# session table), any other claimed field, and any new spelling nobody
# has added here. An accessor passed as a sub-expression of a larger call (for
# example `fmt::format("{}", request->agent_id())`) IS flagged, conservatively,
# unless the whole argument is a wrap call. Known lexical limits: alias forms such
# as `string_view x = ...` and `auto&& x = ...`, brace-init aliases and a later
# plain assignment to an alias are not tracked; the `safe_agent_id` evasions listed above
# (rename, parameter, `+=`) are not seen; `SPDLOG_*` macros, `spdlog::log(level, ...)` calls,
# calls through `spdlog::default_logger()->` and logging through a helper lambda or wrapper
# function are not scanned, because the statement finder only recognises
# `spdlog::LEVEL(` and `<name>->LEVEL(`. It is a regression net for the
# sites fixed under #5513, not proof that no claimed id is ever logged raw.
# ---------------------------------------------------------------------------

AGENT_ID_FILES: dict[str, tuple[str, ...]] = {
    # path -> bare names that are ALWAYS a request-derived agent id in that file
    "server/core/src/agent_service_impl.cpp": (),
    "server/core/src/gateway_service_impl.cpp": (),
    # Only claimed ids from `info.agent_id()` / `safe_agent_id` are matched; the file's other
    # spdlog calls print ids from the session table, which the check cannot trace and ignores.
    "server/core/src/agent_registry.cpp": (),
    # `key` is the schema/property key and `validation_regex` the admin-defined pattern: the
    # invalid-regex warning prints both. Neither name is used as a local in any other log argument.
    "server/core/src/custom_properties_store.cpp": ("agent_id", "key", "validation_regex"),
    # `key` is the caller-supplied tag key (get_values_for_key prints it); the file has no
    # other local of that name in a log argument.
    "server/core/src/tag_store.cpp": ("agent_id", "key"),
    "server/core/src/custom_properties_routes.cpp": ("agent_id",),
    # `key` is the URL path parameter of PUT /api/config/{key}. The store `.error()` text this
    # file also logs is covered by STORE_ERROR_FILES below, not by this entry.
    "server/core/src/config_routes.cpp": ("key",),
}

# Any receiver, including a chained one such as `request->info().agent_id()`: the match starts at
# the member access itself, not at a word character before it.
_RAW_AGENT_ID_ACCESSOR_RE = re.compile(
    r"(?:\.|->)\s*agent_id\(\)(?!\s*\.\s*(?:size|empty|length)\s*\()"
)
_AGENT_ID_ALIAS_DECL_RE = re.compile(
    r"\b(?:const\s+)?(?:auto|std::string)\s*&?\s*(\w+)\s*=\s*[^;=]*?(?:\.|->)\s*agent_id\(\)\s*;"
)
_SANITIZE_CALL_NAME_RE = re.compile(r"^(?:::)?(?:[A-Za-z_][A-Za-z0-9_]*::)*sanitize_for_log\(")


_LOG_ID_TOKEN_CALL_NAME_RE = re.compile(r"^(?:::)?(?:[A-Za-z_][A-Za-z0-9_]*::)*log_id_token\(")
_SAFE_AGENT_ID_DEF_RE = re.compile(r"\bsafe_agent_id\s*(=(?!=)|[({])")
_SAFE_AGENT_ID_USE_RE = re.compile(r"(?<![\w.>:])safe_agent_id\b(?!\s*[=({])")


def _safe_agent_id_definitions(text: str) -> list[tuple[int, str, bool]]:
    """Every declaration / init of `safe_agent_id` in `text` as (1-based line,
    statement snippet, rhs_is_whole_log_id_token_call). Lines in a `//` comment
    before the match are skipped. The right-hand side runs to the top-level `;`
    (for `=`) or to the balancing close of the `(` / `{` initialiser."""
    out: list[tuple[int, str, bool]] = []
    for m in _SAFE_AGENT_ID_DEF_RE.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        if "//" in text[line_start : m.start()]:
            continue
        opener = m.group(1)
        i = m.end() if opener == "=" else m.end() - 1
        rhs_start = i if opener == "=" else i + 1
        depth = 0 if opener == "=" else 1
        n = len(text)
        while i < n:
            c = text[i]
            if c == '"':
                i = _skip_string_literal(text, i)
                continue
            if c == "'":
                i = _skip_char_literal(text, i)
                continue
            if c in "({[":
                depth += 1
            elif c in ")}]":
                depth -= 1
                if depth == 0 and opener != "=":
                    break
            elif c == ";" and depth == 0 and opener == "=":
                break
            i += 1
        rhs = text[rhs_start:i]
        line_no = text.count("\n", 0, m.start()) + 1
        snippet = " ".join(text[m.start() : min(i + 1, n)].split())
        out.append((line_no, snippet, _is_whole_call_wrapped(rhs, _LOG_ID_TOKEN_CALL_NAME_RE)))
    return out


def _agent_id_arg_is_safe(arg: str) -> bool:
    text = arg.strip()
    return (
        text == "safe_agent_id"
        or argument_is_wrapped(text)
        or _is_whole_call_wrapped(text, _SANITIZE_CALL_NAME_RE)
    )


def find_agent_id_violations_in_text(
    text: str, always_bare: tuple[str, ...] = ()
) -> list[tuple[int, str]]:
    """Return (1-based line number, statement) for every spdlog call in `text`
    with an unwrapped request-derived agent-id argument (see the block comment
    above for exactly what that means)."""
    out: list[tuple[int, str]] = []
    defs = _safe_agent_id_definitions(text)
    for line_no, snippet, wrapped in defs:
        if not wrapped:
            out.append((line_no, snippet))
    for pos, stmt in find_spdlog_statements_with_pos(text):
        parsed = parse_call(stmt)
        if parsed is None:
            continue
        _, args_text = parsed
        if not defs and any(
            _SAFE_AGENT_ID_USE_RE.search(a) for a in split_top_level_args(args_text)
        ):
            out.append((text.count("\n", 0, pos) + 1, stmt))
            continue
        fn_start = text.rfind("\n}", 0, pos)
        scope = text[fn_start + 1 if fn_start != -1 else 0 : pos]
        bare = set(always_bare) | {m.group(1) for m in _AGENT_ID_ALIAS_DECL_RE.finditer(scope)}
        for arg in split_top_level_args(args_text):
            raw = _RAW_AGENT_ID_ACCESSOR_RE.search(arg) is not None or any(
                re.search(r"(?<![\w.>:])" + re.escape(name) + r"\b(?!\s*\()", arg) for name in bare
            )
            if raw and not _agent_id_arg_is_safe(arg):
                out.append((text.count("\n", 0, pos) + 1, stmt))
                break
    return out


# Third, narrower rule: libpq error text (`PQerrorMessage`) can quote the statement
# parameters, i.e. the claimed agent id, so in the custom-properties store every spdlog
# argument that contains a `PQerrorMessage(` call must be wholly one wrap call. Lexical,
# like the check above; it covers only this one file.
PQ_ERROR_FILES: tuple[str, ...] = (
    "server/core/src/custom_properties_store.cpp",
    "server/core/src/tag_store.cpp",
    # The pool's BEGIN-failure and connect-failure lines (the connect line prints a local copied
    # from PQerrorMessage, which the name-only match does not see; it is wrapped by hand).
    "server/core/src/pg/pg_pool.cpp",
)

# Same rule, different marker: in config_routes.cpp the store's `.error()` text (which on the
# database-failure path carries a kRuntimeConfigDbErrorPrefix plus libpq text) must be wrapped
# wherever it is an spdlog argument.
STORE_ERROR_FILES: tuple[str, ...] = ("server/core/src/config_routes.cpp",)


# Name-only: the rule matches the call NAME inside the argument text. A value copied into a
# local first (`const char* e = PQerrorMessage(c); spdlog::warn("{}", e)`) is not caught.
def find_pq_error_violations_in_text(
    text: str, markers: tuple[str, ...] = ("PQerrorMessage(", "PQresultErrorMessage(")
) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for pos, stmt in find_spdlog_statements_with_pos(text):
        parsed = parse_call(stmt)
        if parsed is None:
            continue
        for arg in split_top_level_args(parsed[1]):
            if any(m in arg for m in markers) and not argument_is_wrapped(arg):
                out.append((text.count("\n", 0, pos) + 1, stmt))
                break
    return out


# Fourth, narrower rule: agent-supplied free text and store error text in the register path.
# In agent_registry.cpp an spdlog argument that is
#   - `info.hostname()` (any receiver) or a local alias bound from such an accessor earlier in
#     the SAME function (`const auto& host = info.hostname();`), or
#   - `X.error()` where `X` is a local bound earlier in the same function from a
#     `revoke_by_device(` or `register_agent(` call (a store error string that can quote the
#     claimed device id; the latter can carry raw libpq text)
# must be wholly one wrap call (log_key_token / log_id_token / audit_token). Lexical, like the
# checks above: a hostname reaching the log through a variable it cannot trace to the accessor,
# another store call's error, and `session->hostname` (a member, not an accessor call) are not
# seen. The function boundary is the last `\n}` before the call, as for the agent-id check.
REGISTRY_FREE_TEXT_FILES: tuple[str, ...] = (
    "server/core/src/agent_registry.cpp",
    "server/core/src/agent_service_impl.cpp",
    "server/core/src/gateway_service_impl.cpp",
)

_RAW_HOSTNAME_ACCESSOR_RE = re.compile(
    r"\b\w+(?:\.|->)hostname\(\)(?!\s*\.\s*(?:size|empty|length)\s*\()"
)
_HOSTNAME_ALIAS_DECL_RE = re.compile(
    r"\b(?:const\s+)?(?:auto|std::string)\s*&?\s*(\w+)\s*=\s*\w+(?:\.|->)hostname\(\)\s*;"
)
_REVOKE_RESULT_DECL_RE = re.compile(
    r"\b(?:const\s+)?auto\s*&?\s*(\w+)\s*=\s*[\w.>:-]*(?:revoke_by_device|register_agent)\s*\("
)


def find_registry_free_text_violations_in_text(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for pos, stmt in find_spdlog_statements_with_pos(text):
        parsed = parse_call(stmt)
        if parsed is None:
            continue
        fn_start = text.rfind("\n}", 0, pos)
        scope = text[fn_start + 1 if fn_start != -1 else 0 : pos]
        host_names = {m.group(1) for m in _HOSTNAME_ALIAS_DECL_RE.finditer(scope)}
        revoke_names = {m.group(1) for m in _REVOKE_RESULT_DECL_RE.finditer(scope)}
        for arg in split_top_level_args(parsed[1]):
            raw = (
                _RAW_HOSTNAME_ACCESSOR_RE.search(arg) is not None
                or any(re.search(r"(?<![\w.>:])" + re.escape(n) + r"\b(?!\s*\()", arg) for n in host_names)
                or any(re.search(r"(?<![\w.>:])" + re.escape(n) + r"\.error\(\)", arg) for n in revoke_names)
            )
            if raw and not argument_is_wrapped(arg):
                out.append((text.count("\n", 0, pos) + 1, stmt))
                break
    return out


# Fifth, narrower rule: `.command_id()` / `.plugin()` on a message receiver are free-form bytes
# on a CommandResponse frame the agent sends, and `.gateway_node()` / `.cluster_id()` / the local
# `cluster_id` are gateway-asserted provenance strings on the stream-status and heartbeat
# notifications. In the two files below every spdlog argument that contains one (not merely
# sized or emptiness-tested) must be wholly one wrap call. Lexical: a value copied into a local
# under another name first, a longer receiver chain through a call result other than a plain
# accessor, and helper lambdas are not seen; the logging forms the scanner does not parse at all
# are refused outright by the UNSCANNED_LOGGING_FILES guard below.
COMMAND_TEXT_FILES: tuple[str, ...] = (
    "server/core/src/agent_service_impl.cpp",
    "server/core/src/gateway_service_impl.cpp",
    "server/core/src/agent_registry.cpp",
)

_RAW_COMMAND_TEXT_ACCESSOR_RE = re.compile(
    r"(?:\.|->)\s*(?:command_id|plugin|gateway_node|cluster_id)\(\)"
    r"(?!\s*\.\s*(?:size|empty|length)\s*\()"
)
# The member form `.gateway_node` / `->gateway_node` (no parentheses): the session table keeps the
# gateway's CONNECTED-notification node name unclamped in `AgentSession::gateway_node`, and
# agent_registry.cpp prints it from the session. Not a call, so the accessor pattern above does
# not see it; a `.gateway_node.empty()` / `.size()` / `.length()` test is not a print.
_RAW_GATEWAY_NODE_MEMBER_RE = re.compile(
    r"(?:\.|->)\s*gateway_node\b(?!\s*\()(?!\s*\.\s*(?:size|empty|length)\s*\()"
)
# The bare local `cluster_id` (gateway_service_impl.cpp binds `std::string cluster_id =
# request->cluster_id();` and clamps it); not a member access, not a call.
_RAW_BARE_CLUSTER_ID_RE = re.compile(r"(?<![\w.>:])cluster_id\b(?!\s*[(.])")


def find_command_text_violations_in_text(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for pos, stmt in find_spdlog_statements_with_pos(text):
        parsed = parse_call(stmt)
        if parsed is None:
            continue
        for arg in split_top_level_args(parsed[1]):
            raw = (
                _RAW_COMMAND_TEXT_ACCESSOR_RE.search(arg) is not None
                or _RAW_GATEWAY_NODE_MEMBER_RE.search(arg) is not None
                or _RAW_BARE_CLUSTER_ID_RE.search(arg) is not None
            )
            if raw and not (
                argument_is_wrapped(arg) or _is_whole_call_wrapped(arg, _SANITIZE_CALL_NAME_RE)
            ):
                out.append((text.count("\n", 0, pos) + 1, stmt))
                break
    return out


# Seventh, narrower rule: the PKI signer legs in server.cpp. The Register / ProxyRegister signer
# (the `cert_signer` lambda and `sign_agent_csr`) prints the claimed `agent_id` and, on a throw,
# `e.what()`. In server.cpp, an spdlog statement whose format literal starts with "PKI:" must not
# print a bare `agent_id` or an `e.what()` argument: each must be wholly one wrap call. This is
# deliberately NOT the broad bare-name rule of AGENT_ID_FILES (server.cpp is a very large file in
# which `agent_id` is a common name outside the PKI lines). Lexical: it reads the literal's prefix
# and the argument text, so a PKI line whose literal does not start with "PKI:", or an id copied
# into another local first, is not seen.
PKI_SIGNER_FILES: tuple[str, ...] = ("server/core/src/server.cpp",)

_PKI_BARE_AGENT_ID_RE = re.compile(r"(?<![\w.>:])agent_id\b(?!\s*[(.])")
_PKI_WHAT_RE = re.compile(r"\.what\(\)")


def find_pki_signer_violations_in_text(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for pos, stmt in find_spdlog_statements_with_pos(text):
        parsed = parse_call(stmt)
        if parsed is None or not parsed[0].lstrip().startswith("PKI:"):
            continue
        for arg in split_top_level_args(parsed[1]):
            raw = _PKI_BARE_AGENT_ID_RE.search(arg) is not None or _PKI_WHAT_RE.search(arg) is not None
            if raw and not argument_is_wrapped(arg):
                out.append((text.count("\n", 0, pos) + 1, stmt))
                break
    return out


# Sixth guard: logging forms the scanner above does not parse. find_spdlog_statements only
# understands `spdlog::<level>(` and `<logger>-><level>(`; any other form in the files of
# the second check would print its arguments unexamined. They are absent today, so the guard
# fails on any occurrence (a mention in a comment too: reword it) rather than trying to scan them.
# config_routes.cpp is the one AGENT_ID_FILES member left out: it reads the default logger's LEVEL
# (`spdlog::default_logger()->level()`, line 38) to report the effective log level and never logs
# through it, so the guard would fail on a non-logging use. Its spdlog:: calls are all the
# `spdlog::<level>(` form the other rules parse.
UNSCANNED_LOGGING_FILES: tuple[str, ...] = tuple(
    f for f in AGENT_ID_FILES if f != "server/core/src/config_routes.cpp"
) + ("server/core/src/pg/pg_pool.cpp",)

_UNSCANNED_LOGGING_FORM_RE = re.compile(
    r"\bSPDLOG_(?:TRACE|DEBUG|INFO|WARN|ERROR|CRITICAL)\s*\("
    r"|\bspdlog\s*::\s*log\s*\("
    r"|\bdefault_logger\b"
)


def find_unscanned_logging_forms_in_text(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for m in _UNSCANNED_LOGGING_FORM_RE.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line = text[line_start : line_end if line_end != -1 else len(text)]
        out.append((text.count("\n", 0, m.start()) + 1, " ".join(line.split())))
    return out


# ---------------------------------------------------------------------------
# _selfcheck()
# ---------------------------------------------------------------------------


def _selfcheck() -> None:
    def flagged(src: str) -> bool:
        return len(find_violations_in_text(src)) > 0

    # 1. Must-match: a raw sensitive argument, unwrapped, in each pattern shape.
    must_match = [
        'spdlog::warn("Guardian FileGuard[{}]: no watch armed for {}", cfg_.rule_id, cfg_.path);',
        'spdlog::error("Guardian: reconcile threw for rule \'{}\'", rule.rule_id());',
        'spdlog::warn("GuaranteedStateStore: status upsert failed for rule_id={}: {}", rule_id, e);',
        'spdlog::warn("Guardian: event ingest error (rule={}): {}", rule_id, e);',
        'spdlog::warn("Guardian push: rule {} (\'{}\') requests enforce", row.rule_id, row.name);',
        'spdlog::error("Guardian spark: key \'{}\' still has queued claims", key);',
        'spdlog::info("SparkEngine: armed \'{}\'", key);',
        'spdlog::info("SparkEngine: disarmed \'{}\' (last subscription gone)", key);',
        'spdlog::warn("SparkEngine: consumer \'{}\' handler threw on spark \'{}\'", name, key);',
        'spdlog::warn("SparkEngine: watch \'{}\' FAULTED", key);',
        'spdlog::error("SparkEngine: defensive unwatch(\'{}\') after a failed watch()", key);',
        'spdlog::warn("spark_file: probe for \'{}\' failed", w.dir);',
        'spdlog::warn("spark_registry: establishing \'{}\' failed", w.spark_key);',
        'spdlog::warn("Guardian SystemdServiceGuard[{}]: LoadUnit \'{}\' transient error", cfg_.rule_id, unit);',
        'spdlog::warn("Guardian RegistryGuard[{}]: invalid hive \'{}\'", cfg_.rule_id, cfg_.hive);',
        'spdlog::warn("Guardian ServiceGuard[{}]: invalid service name \'{}\'", cfg_.rule_id, cfg_.service_name);',
        'spdlog::info("Guardian ServiceGuard[{}]: watching service \'{}\'", cfg_.rule_id, cfg_.service_name);',
        'spdlog::info("Guardian RegistryGuard[{}]: {} {}\\\\{} [{}]", cfg_.rule_id, action, cfg_.hive, cfg_.key, cfg_.value_name);',
        'spdlog::warn("Guardian outbox send stalled (event_id {})", event_id);',
        'spdlog::info("Guardian: file guard armed for rule \'{}\' (path={})", log_id_token(rule.rule_id()), log_path);',
        'spdlog::info("Guardian: service guard armed for rule \'{}\' (service={})", log_id_token(rule.rule_id()), log_service);',
        # #4666 PR-4: a call through a BOUND logger handle, not the free
        # function -- guardian_ingest.cpp's T_server line shape (real code is
        # correctly wrapped; this is the synthetic UNWRAPPED negative-control
        # version, proving the widened SPDLOG_CALL_RE actually opens this
        # statement rather than silently skipping it as before).
        'logger->info("Guardian T_server event_id={} agent={} rule={}", event_id, agent_id, rule_id);',
        # #5513: raw agent_id shapes.
        'spdlog::info("Guardian: peer agent {} seen", agent_id);',
        'spdlog::debug("Guardian: ignoring __guard__ action \'{}\' from agent {} (only \'event\' ingested in A1)", ::yuzu::log_key_token(resp.action()), agent_id);',
        'spdlog::info("Guardian peer agent={} seen", agent_id);',
        'spdlog::warn("Guardian: dropped a frame from agent \'{}\'", agent_id);',
        'spdlog::warn("Guardian: frame rejected, agent: {}", agent_id);',
        'spdlog::warn("Guardian: bad frame, agent_id: {}", agent_id);',
        'spdlog::warn("Guardian: bad frame, agent_id \'{}\'", agent_id);',
        'spdlog::warn("Guardian: bad frame from agent_id {}", agent_id);',
        'spdlog::warn("Guardian: bad frame from agent ({})", agent_id);',
    ]
    for src in must_match:
        if not flagged(src):
            raise SystemExit(f"selfcheck: expected a violation, found none:\n  {src!r}")

    # 2. Must-not-match: the same shapes, correctly wrapped.
    must_not = [
        'spdlog::warn("Guardian FileGuard[{}]: no watch armed for {}", log_id_token(cfg_.rule_id), log_key_token(cfg_.path));',
        'spdlog::error("Guardian: reconcile threw for rule \'{}\'", log_id_token(rule.rule_id()));',
        'spdlog::warn("GuaranteedStateStore: status upsert failed for rule_id={}: {}", log_id_token(rule_id), e);',
        'spdlog::warn("Guardian: event ingest error (rule={}): {}", log_id_token(rule_id), e);',
        'spdlog::warn("Guardian push: rule {} (\'{}\') requests enforce", log_id_token(row.rule_id), log_key_token(row.name));',
        'spdlog::error("Guardian spark: key \'{}\' still has queued claims", ::yuzu::log_key_token(key));',
        'spdlog::info("SparkEngine: armed \'{}\'", ::yuzu::log_key_token(key));',
        'spdlog::info("SparkEngine: disarmed \'{}\' (last subscription gone)", ::yuzu::log_key_token(key));',
        'spdlog::warn("SparkEngine: consumer \'{}\' handler threw on spark \'{}\'", consumer->name, ::yuzu::log_key_token(key));',
        'spdlog::warn("SparkEngine: watch \'{}\' FAULTED", ::yuzu::log_key_token(key));',
        'spdlog::error("SparkEngine: defensive unwatch(\'{}\') after a failed watch()", ::yuzu::log_key_token(key));',
        'spdlog::warn("spark_file: probe for \'{}\' failed", ::yuzu::log_key_token(fs::path(w.dir).string()));',
        'spdlog::warn("spark_registry: establishing \'{}\' failed", ::yuzu::log_key_token(w.spark_key));',
        'spdlog::warn("Guardian SystemdServiceGuard[{}]: LoadUnit \'{}\' transient error", log_id_token(cfg_.rule_id), log_key_token(unit));',
        'spdlog::warn("Guardian RegistryGuard[{}]: invalid hive \'{}\'", log_id_token(cfg_.rule_id), log_key_token(cfg_.hive));',
        'spdlog::info("Guardian RegistryGuard[{}]: {} {}\\\\{} [{}]", log_id_token(cfg_.rule_id), action, log_key_token(cfg_.hive), log_key_token(cfg_.key), log_key_token(cfg_.value_name));',
        'spdlog::warn("Guardian outbox send stalled (event_id {})", log_id_token(event_id));',
        # a ternary hiding the wrap call inside its own argument slot --
        # guardian_spark_runtime.cpp's real "subscription {} lost" shape.
        'spdlog::warn("Guardian spark: key \'{}\' subscription {} lost ({})", ::yuzu::log_key_token(key), subscription_id, detail.empty() ? "no reason given" : ::yuzu::log_key_token(detail));',
        # the REAL guardian_spark_runtime.cpp:1730 shape: a std::string{...}-
        # constructed fixed literal as the ternary's un-wrapped branch, not a
        # bare quoted string -- must be recognised as safe too.
        'spdlog::critical("Guardian spark #4508: a wedge candidate survived a withdrawal of rule \'{}\' - the sweep was skipped or reordered", rule_id ? ::yuzu::log_id_token(*rule_id) : std::string{"<all>"});',
        # the REAL guard_registry.cpp:523-525 shape: hive, key, value_type,
        # value_name AND expected are now ALL wrapped -- value_type's bracket
        # was the one site the #4665 Phase-3 governance run's security-guardian
        # pass found still raw (the "closed-set string" theory it was excluded
        # under was wrong; see the pattern's own comment).
        'spdlog::info("Guardian RegistryGuard[{}]: watching {}\\\\{} [{}] (expect {}={}) [resilient]", log_id_token(cfg_.rule_id), log_key_token(cfg_.hive), log_key_token(cfg_.key), log_key_token(cfg_.value_type), log_key_token(cfg_.value_name), log_key_token(cfg_.expected));',
        # the REAL guard_registry.cpp:392/399/407 success/failure shapes,
        # fully fixed: detected AND expected both wrapped.
        'spdlog::info("Guardian RegistryGuard[{}]: {} {}\\\\{} [{}] {} -> {} ({}us)", log_id_token(cfg_.rule_id), d.remediation_action, log_key_token(cfg_.hive), log_key_token(cfg_.key), log_key_token(cfg_.value_name), log_key_token(detected), log_key_token(cfg_.expected), d.remediation_latency_us);',
        # value_type now wrapped too (was the raw sibling this fixture existed
        # to document before the #4665 Phase-3 fix).
        'spdlog::warn("Guardian RegistryGuard[{}]: enforce {} FAILED for {}\\\\{} [{}] (detected={}, type={}{})", log_id_token(cfg_.rule_id), d.remediation_action, log_key_token(cfg_.hive), log_key_token(cfg_.key), log_key_token(cfg_.value_name), log_key_token(detected), log_key_token(cfg_.value_type), target.get() ? "" : ", key absent");',
        # #4666 PR-4: the REAL guardian_ingest.cpp T_server shape (bound
        # logger handle, all three ids wrapped) -- correctly unflagged.
        'logger->info("Guardian T_server event_id={} agent={} rule={} recv_ns={} committed_ns={} agent_ns={} store_ms={}", log_id_token(ev_row.event_id), log_id_token(agent_id), log_id_token(ev_row.rule_id), recv_wall_ns, res.committed_wall_ns, agent_ns, store_ms);',
        # #5513: agent_id shapes, wrapped.
        'spdlog::info("Guardian: peer agent {} seen", ::yuzu::log_id_token(agent_id));',
        'spdlog::debug("Guardian: ignoring __guard__ action \'{}\' from agent {} (only \'event\' ingested in A1)", ::yuzu::log_id_token(resp.action()), ::yuzu::log_id_token(agent_id));',
        'spdlog::warn("Guardian: dropped a frame from agent \'{}\'", ::yuzu::log_id_token(agent_id));',
        'spdlog::warn("Guardian: frame rejected, agent: {}", ::yuzu::log_id_token(agent_id));',
        'spdlog::warn("Guardian: bad frame, agent_id: {}", ::yuzu::log_id_token(agent_id));',
        'spdlog::warn("Guardian: bad frame, agent_id \'{}\'", ::yuzu::log_id_token(agent_id));',
        'spdlog::warn("Guardian: bad frame from agent_id {}", ::yuzu::log_id_token(agent_id));',
        'spdlog::warn("Guardian: bad frame from agent ({})", ::yuzu::log_id_token(agent_id));',
    ]
    for src in must_not:
        if flagged(src):
            raise SystemExit(f"selfcheck: expected no violation, found one:\n  {src!r}")

    # 3. Mutation-style cases: two sensitive placeholders, wrap only ONE --
    # must still be flagged (the naive-design gap this scanner exists to
    # catch, guardian_spark_runtime.cpp:2798's real shape).
    mutations = [
        # rule_id wrapped, key raw.
        'spdlog::error("Guardian spark: key \'{}\' still has {} queued claim(s) after the sweep for rule \'{}\'", key, n, ::yuzu::log_id_token(rule_id));',
        # key wrapped, rule_id raw.
        'spdlog::error("Guardian spark: key \'{}\' still has {} queued claim(s) after the sweep for rule \'{}\'", ::yuzu::log_key_token(key), n, rule_id);',
        # guardian_push_builder.cpp's two-slot form: id wrapped, name raw.
        'spdlog::warn("Guardian push: rule {} (\'{}\') requests enforce on {}", log_id_token(row.rule_id), row.name, why);',
        # ... and the reverse.
        'spdlog::warn("Guardian push: rule {} (\'{}\') requests enforce on {}", row.rule_id, log_key_token(row.name), why);',
        # guard_registry.cpp's 392-style shape (value_name genuinely in the
        # bracket, no "(expect " suffix -- the excludes_suffix condition must
        # NOT blind this pattern to a real regression here): hive/key wrapped,
        # value_name/detected/expected all left raw -- the #4665 Phase-2
        # adversarial-review (CDX-01/K5) shape, now flagged on THREE
        # independent grounds (value_name, detected, expected).
        'spdlog::info("Guardian RegistryGuard[{}]: {} {}\\\\{} [{}] {} -> {} ({}us)", log_id_token(cfg_.rule_id), d.remediation_action, log_key_token(cfg_.hive), log_key_token(cfg_.key), cfg_.value_name, detected, cfg_.expected, d.remediation_latency_us);',
        # the same shape with value_name/hive/key correctly wrapped but
        # detected/expected left raw -- isolates the NEW patterns from the
        # pre-existing value_name one (must still be flagged on their own).
        'spdlog::info("Guardian RegistryGuard[{}]: {} {}\\\\{} [{}] {} -> {} ({}us)", log_id_token(cfg_.rule_id), d.remediation_action, log_key_token(cfg_.hive), log_key_token(cfg_.key), log_key_token(cfg_.value_name), detected, cfg_.expected, d.remediation_latency_us);',
        # the "(expect {}={})" line with only `expected` left raw (value_type
        # and value_name both wrapped) -- must still be flagged; the pattern
        # spans both placeholders precisely so this single-slot mutation
        # isn't missed.
        'spdlog::info("Guardian RegistryGuard[{}]: watching {}\\\\{} [{}] (expect {}={}) [resilient]", log_id_token(cfg_.rule_id), log_key_token(cfg_.hive), log_key_token(cfg_.key), log_key_token(cfg_.value_type), log_key_token(cfg_.value_name), cfg_.expected);',
        # intra-argument mutations (CDX-03/K6): a wrap call's TEXT appears
        # somewhere in the argument slot, but the argument as a WHOLE is not
        # wrapped -- the exact two constructions the adversarial review used
        # to prove the old substring-any check was too permissive. Each case
        # below is otherwise-clean (its only sensitive placeholder is the
        # mutated one) so the flag is driven purely by the intra-argument
        # weakness, not a separate already-known-raw argument.
        'spdlog::error("Guardian: reconcile threw for rule \'{}\' - persisted but not armed", enabled ? rule.rule_id() : log_id_token(rule.rule_id()));',
        'spdlog::warn("Guardian outbox send stalled (event_id {})", raw_prefix + log_id_token(event_id));',
    ]
    for src in mutations:
        if not flagged(src):
            raise SystemExit(f"selfcheck: expected mutation-style violation, found none:\n  {src!r}")
    # And BOTH wrapped must pass.
    both_wrapped = [
        'spdlog::error("Guardian spark: key \'{}\' still has {} queued claim(s) after the sweep for rule \'{}\'", ::yuzu::log_key_token(key), n, ::yuzu::log_id_token(rule_id));',
        'spdlog::warn("Guardian push: rule {} (\'{}\') requests enforce on {}", log_id_token(row.rule_id), log_key_token(row.name), why);',
    ]
    for src in both_wrapped:
        if flagged(src):
            raise SystemExit(f"selfcheck: expected no violation once both slots are wrapped:\n  {src!r}")

    # 4. Reworded-literal cases -- prove pattern matching isn't over-fit to one
    # exact phrase (spark_registry.cpp/spark_file.cpp use several distinct
    # phrasings of the same "for '{}'" shape).
    reworded = [
        'spdlog::warn("spark_file: establishing \'{}\' failed ({}, err={}) - watch is deaf", w.dir, reason, err);',
        'spdlog::warn("spark_registry: probe for \'{}\' failed at {} (err={})", w.spark_key, stage, err);',
        'spdlog::warn("spark_registry: drain worker for \'{}\' {} ({} backlogged)", w->spark_key, why, n);',
    ]
    for src in reworded:
        if not flagged(src):
            raise SystemExit(f"selfcheck: expected reworded-literal violation, found none:\n  {src!r}")

    # 5. Multi-line call case -- format string AND arguments split across
    # physical lines (mirrors real sites in guard_file.cpp/guard_registry.cpp).
    multiline_bad = (
        'spdlog::warn(\n'
        '    "Guardian FileGuard[{}]: parent-directory watch for {} "\n'
        '    "not armed (event creation failed)",\n'
        '    cfg_.rule_id, cfg_.path);\n'
    )
    if not flagged(multiline_bad):
        raise SystemExit("selfcheck: expected multi-line violation, found none")
    multiline_ok = (
        'spdlog::warn(\n'
        '    "Guardian FileGuard[{}]: parent-directory watch for {} "\n'
        '    "not armed (event creation failed)",\n'
        '    log_id_token(cfg_.rule_id), log_key_token(cfg_.path));\n'
    )
    if flagged(multiline_ok):
        raise SystemExit("selfcheck: expected no violation on wrapped multi-line call")

    # 6. format_arm_committed_line(...) call site -- must be exempted, not
    # flagged, at BOTH the real shape (bare "{}", never reaches the
    # sensitivity check at all) and a synthetic shape where the OUTER
    # placeholder's literal text IS sensitive (proves the exemption itself,
    # not just the accident of a bare "{}").
    real_shape = 'spdlog::info("{}", format_arm_committed_line(rule_id, detach_epoch_, gen, guard_type, via, ms));'
    if flagged(real_shape):
        raise SystemExit("selfcheck: real format_arm_committed_line call site was flagged")
    synthetic_shape = (
        'spdlog::info("Guardian spark: arm committed for rule \'{}\'", '
        'format_arm_committed_line(rule_id, epoch, incarnation, type, via, ms));'
    )
    if flagged(synthetic_shape):
        raise SystemExit("selfcheck: format_arm_committed_line exemption did not hold under a sensitive literal")
    # log_safe(...) is NO LONGER exempt (#4665 governance-external-review
    # correction, fjarvis PR #4979) -- this k=v-shaped line, log_safe-wrapped,
    # must be FLAGGED, proving the scanner would now catch a regression back
    # to the weaker helper on a line shape it can't safely cover.
    log_safe_shape = (
        'spdlog::info("guardian: platform support-matrix stale — agent={} rule={} spark_type={}", '
        'log_safe(std::string(agent_id)), log_safe(std::string(rule_id)), log_safe(std::string(spark_type)));'
    )
    if not flagged(log_safe_shape):
        raise SystemExit("selfcheck: expected log_safe on a k=v line to be flagged, found none")
    # The REAL current shape at that call site uses audit_token instead -- must
    # stay unflagged.
    audit_token_shape = (
        'spdlog::info("guardian: platform support-matrix stale — agent={} rule={} spark_type={}", '
        'audit_token(agent_id), audit_token(rule_id), audit_token(spark_type));'
    )
    if flagged(audit_token_shape):
        raise SystemExit("selfcheck: audit_token exemption did not hold")

    # 7. The KNOWN, ACCEPTED GAP: a bare "{}" printing a local variable built
    # from a wrapped concatenation three lines above (guardian_engine.cpp's
    # degrade_msg). Must NOT be flagged -- this is a documented limitation of
    # literal-text matching, not something this scanner can or should catch
    # (would require tracing local-variable data flow). See the module
    # docstring's KNOWN, ACCEPTED, PERMANENT LIMITATION paragraph.
    degrade_msg_shape = (
        'const std::string degrade_msg = "Guardian: rule \'" + log_id_token(rule.rule_id()) + '
        '"\' failed to re-arm (" + e.what() + ") - NOT enforcing this rule";\n'
        'spdlog::error("{}", degrade_msg);'
    )
    if flagged(degrade_msg_shape):
        raise SystemExit(
            "selfcheck: the documented degrade_msg limitation regressed -- a bare '{}' literal "
            "should never be flagged regardless of what local variable it prints"
        )

    # 8. The claimed-agent-id check (find_agent_id_violations_in_text).
    def aflagged(src: str, always: tuple[str, ...] = ()) -> bool:
        return len(find_agent_id_violations_in_text(src, always)) > 0

    agent_must_match = [
        ('spdlog::info("peer {} seen", info.agent_id());', ()),
        ('spdlog::warn("update check: agent {} v{}", request->agent_id(), v);', ()),
        ('spdlog::info("sent {} bytes to {}", n, req->agent_id());', ()),
        # A chained receiver (a call result before the member access) is "any receiver" too.
        ('spdlog::info("peer {}", request->info().agent_id());', ()),
        ('spdlog::info("peer {}", msg.header().agent_id());', ()),
        (
            "void F() {\n  const auto& aid = request->info().agent_id();\n"
            '  spdlog::info("peer {}", aid);\n}\n',
            (),
        ),
        ('spdlog::info("peer {} and {}", log_id_token(a), info.agent_id());', ()),
        ('spdlog::info("peer {}", "id=" + info.agent_id());', ()),
        # The trusted local must be DEFINED as a whole log_id_token call: an unwrapped
        # definition, a partial wrap, a brace/paren init and a use with no definition
        # in the file all go red.
        (
            "void F() {\n  const std::string safe_agent_id = info.agent_id();\n"
            '  spdlog::info("peer {}", safe_agent_id);\n}\n',
            (),
        ),
        (
            "void F() {\n  const std::string safe_agent_id = ::yuzu::log_id_token(a) + info.agent_id();\n"
            '  spdlog::info("peer {}", safe_agent_id);\n}\n',
            (),
        ),
        (
            "void F() {\n  const std::string safe_agent_id{info.agent_id()};\n"
            '  spdlog::info("peer {}", safe_agent_id);\n}\n',
            (),
        ),
        ('void F() {\n  spdlog::info("peer {}", safe_agent_id);\n}\n', ()),
        ('spdlog::info("peer {}", log_id_token(a) + info.agent_id());', ()),
        ('spdlog::warn("delete failed for agent={}", agent_id);', ("agent_id",)),
        # The caller-supplied tag key: a bare `key` is raw in a file that lists it.
        ('spdlog::warn("values_for_key(\'{}\') failed", key);', ("agent_id", "key")),
        (
            "void F() {\n  const auto& agent_id = request->agent_id();\n"
            '  spdlog::info("peer {}", agent_id);\n}\n',
            (),
        ),
        (
            "void F() {\n  std::string aid = info.agent_id();\n"
            '  spdlog::info("peer {}", aid);\n}\n',
            (),
        ),
    ]
    for src, always in agent_must_match:
        if not aflagged(src, always):
            raise SystemExit(f"selfcheck: expected a claimed-agent-id violation, found none: {src!r}")
    agent_must_not = [
        ('spdlog::info("peer {} seen", ::yuzu::log_id_token(info.agent_id()));', ()),
        ('spdlog::info("peer {} seen", audit_token(request->agent_id()));', ()),
        ('spdlog::warn("x {}", onbehalf::sanitize_for_log(req->agent_id(), 64));', ()),
        (
            "void F() {\n  const std::string safe_agent_id = ::yuzu::log_id_token(info.agent_id());\n"
            '  spdlog::info("peer {}", safe_agent_id);\n}\n',
            (),
        ),
        ('spdlog::warn("length {} (max {})", info.agent_id().size(), kMax);', ()),
        ('spdlog::warn("empty? {}", request->agent_id().empty());', ()),
        ('spdlog::warn("len {}", request->info().agent_id().size());', ()),
        ('spdlog::info("peer {}", ::yuzu::log_id_token(request->info().agent_id()));', ()),
        ('spdlog::warn("delete failed for agent={}", ::yuzu::log_id_token(agent_id));', ("agent_id",)),
        ('spdlog::warn("tag sync failed ({})", err);', ("agent_id",)),
        ('spdlog::warn("values_for_key(\'{}\') failed", ::yuzu::log_key_token(key));', ("agent_id", "key")),
        # `key` is only a bare name in a file that lists it; a method call named key() is not it.
        ('spdlog::warn("failed", row.key());', ("agent_id", "key")),
        # A bare name with no accessor alias in scope is not request-derived as far as this
        # check can tell (session-table ids look like this).
        ('void F() {\n  std::string agent_id;\n  spdlog::info("hb {}", agent_id);\n}\n', ()),
        # An alias bound in an EARLIER function must not leak into the next one.
        (
            "void F() {\n  const auto& agent_id = request->agent_id();\n}\n"
            'void G() {\n  std::string agent_id;\n  spdlog::info("hb {}", agent_id);\n}\n',
            (),
        ),
        # A wrapped alias is fine.
        (
            "void F() {\n  const auto& agent_id = request->agent_id();\n"
            '  spdlog::info("peer {}", ::yuzu::log_id_token(agent_id));\n}\n',
            (),
        ),
        ('spdlog::info("n {}", n);', ()),
    ]
    for src, always in agent_must_not:
        if aflagged(src, always):
            raise SystemExit(f"selfcheck: unexpected claimed-agent-id violation: {src!r}")

    # 9. The libpq-error rule (find_pq_error_violations_in_text).
    pq_must_match = 'spdlog::warn("query failed: {}", PQerrorMessage(lease.get()));'
    if not find_pq_error_violations_in_text(pq_must_match):
        raise SystemExit(f"selfcheck: expected a PQerrorMessage violation: {pq_must_match!r}")
    pq_must_not = (
        'spdlog::warn("query failed: {}", ::yuzu::log_key_token(PQerrorMessage(lease.get())));'
    )
    if find_pq_error_violations_in_text(pq_must_not):
        raise SystemExit(f"selfcheck: unexpected PQerrorMessage violation: {pq_must_not!r}")
    pq_res_must_match = 'spdlog::warn("query failed: {}", PQresultErrorMessage(res.get()));'
    if not find_pq_error_violations_in_text(pq_res_must_match):
        raise SystemExit(f"selfcheck: expected a PQresultErrorMessage violation: {pq_res_must_match!r}")
    pq_res_must_not = (
        'spdlog::warn("query failed: {}", ::yuzu::log_key_token(PQresultErrorMessage(res.get())));'
    )
    if find_pq_error_violations_in_text(pq_res_must_not):
        raise SystemExit(f"selfcheck: unexpected PQresultErrorMessage violation: {pq_res_must_not!r}")

    # 9b. The same rule keyed on a store `.error()` (config_routes.cpp).
    store_must_match = 'spdlog::error("write failed: {}", result.error());'
    if not find_pq_error_violations_in_text(store_must_match, (".error()",)):
        raise SystemExit(f"selfcheck: expected a store .error() violation: {store_must_match!r}")
    store_must_not = 'spdlog::error("write failed: {}", ::yuzu::log_key_token(result.error()));'
    if find_pq_error_violations_in_text(store_must_not, (".error()",)):
        raise SystemExit(f"selfcheck: unexpected store .error() violation: {store_must_not!r}")
    path_key_must_match = 'spdlog::error("PUT /api/config/{}: failed", key);'
    if not find_agent_id_violations_in_text(path_key_must_match, ("key",)):
        raise SystemExit(f"selfcheck: expected a raw path-key violation: {path_key_must_match!r}")
    regex_must_match = 'spdlog::warn("invalid regex \'{}\': {}", ::yuzu::log_key_token(key), validation_regex);'
    if not find_agent_id_violations_in_text(regex_must_match, ("key", "validation_regex")):
        raise SystemExit(f"selfcheck: expected a raw validation_regex violation: {regex_must_match!r}")

    # 10. The register-path free-text rule (find_registry_free_text_violations_in_text).
    free_must_match = [
        'spdlog::info("Agent registered: hostname=\'{}\'", info.hostname());',
        'spdlog::info("Agent registered: hostname=\'{}\'", req->hostname());',
        "void F() {\n  const auto& host = info.hostname();\n"
        '  spdlog::info("registered \'{}\'", host);\n}\n',
        "void F() {\n  auto revoked = store->revoke_by_device(info.agent_id());\n"
        '  spdlog::error("revoke failed for \'{}\': {}", safe_agent_id, revoked.error());\n}\n',
        "void F() {\n  auto revoked = store->revoke_by_device(info.agent_id());\n"
        '  spdlog::error("revoke failed: {}", "x" + revoked.error());\n}\n',
        "void F() {\n  if (auto reg_result = registry_.register_agent(info); !reg_result) {\n"
        '    spdlog::error("failed for \'{}\': {}", safe_agent_id, reg_result.error());\n  }\n}\n',
        "void F() {\n  auto reg_result = registry_.register_agent(info);\n"
        '  spdlog::error("failed for \'{}\': {}", safe_agent_id, reg_result.error());\n}\n',
    ]
    for src in free_must_match:
        if not find_registry_free_text_violations_in_text(src):
            raise SystemExit(f"selfcheck: expected a register-path free-text violation: {src!r}")
    free_must_not = [
        'spdlog::info("Agent registered: hostname=\'{}\'", ::yuzu::log_key_token(info.hostname()));',
        'spdlog::info("host empty? {}", info.hostname().empty());',
        "void F() {\n  const auto& host = info.hostname();\n"
        '  spdlog::info("registered \'{}\'", ::yuzu::log_key_token(host));\n}\n',
        "void F() {\n  auto revoked = store->revoke_by_device(info.agent_id());\n"
        '  spdlog::error("revoke failed for \'{}\': {}", safe_agent_id,'
        " ::yuzu::log_key_token(revoked.error()));\n}\n",
        # An alias bound in an EARLIER function must not leak into the next one, and an
        # unrelated result's error() is not this rule's business.
        "void F() {\n  auto revoked = store->revoke_by_device(a);\n}\n"
        'void G() {\n  auto revoked = other();\n  spdlog::error("x {}", revoked.error());\n}\n',
        'spdlog::info("tags {}", session->hostname);',
        "void F() {\n  auto reg_result = registry_.register_agent(info);\n"
        '  spdlog::error("failed for \'{}\': {}", safe_agent_id,'
        " ::yuzu::log_key_token(reg_result.error()));\n}\n",
    ]
    for src in free_must_not:
        if find_registry_free_text_violations_in_text(src):
            raise SystemExit(f"selfcheck: unexpected register-path free-text violation: {src!r}")

    # 11. The command-id / plugin free-text rule (find_command_text_violations_in_text).
    cmd_must_match = [
        'spdlog::info("Command {} completed: status={}", resp.command_id(), st);',
        'spdlog::info("[gateway] Command {} completed: status={}", resp.command_id(), st);',
        'spdlog::warn("not guardian (plugin=\'{}\', command_id=\'{}\')", '
        "resp.plugin(), resp.command_id());",
        'spdlog::warn("x {}", request->response().command_id());',
        'spdlog::warn("x {}", "id=" + resp.command_id());',
        'spdlog::warn("x {}", ::yuzu::log_id_token(a) + resp.plugin());',
        'spdlog::info("node \'{}\'", request->gateway_node());',
        'spdlog::debug("node \'{}\'", req.gateway_node());',
        'spdlog::warn("cluster \'{}\'", cluster_id);',
        'spdlog::warn("cluster \'{}\'", request->cluster_id());',
        'spdlog::warn("x {} {}", ::yuzu::log_id_token(agent_id), "c=" + cluster_id);',
        'spdlog::warn("node \'{}\'", session.gateway_node);',
        'spdlog::warn("node \'{}\'", sess->gateway_node);',
        'spdlog::warn("x {} \'{}\'", agent_id, session.gateway_node, cap);',
    ]
    for src in cmd_must_match:
        if not find_command_text_violations_in_text(src):
            raise SystemExit(f"selfcheck: expected a command-id/plugin violation: {src!r}")
    cmd_must_not = [
        'spdlog::info("Command {} completed", ::yuzu::log_id_token(resp.command_id()));',
        'spdlog::warn("x {}", ::yuzu::log_key_token(resp.plugin()));',
        'spdlog::warn("x {}", audit_token(resp.command_id()));',
        'spdlog::warn("x {}", onbehalf::sanitize_for_log(resp.command_id(), 64));',
        'spdlog::warn("empty? {}", resp.command_id().empty());',
        'spdlog::warn("len {}", resp.command_id().size());',
        'spdlog::info("n {}", n);',
        'spdlog::info("node \'{}\'", onbehalf::sanitize_for_log(request->gateway_node(), 64));',
        'spdlog::warn("cluster \'{}\'", onbehalf::sanitize_for_log(cluster_id, 64));',
        'spdlog::warn("cluster \'{}\'", ::yuzu::log_key_token(request->cluster_id()));',
        'spdlog::warn("cluster {}", unmapped_cluster_id);',
        'spdlog::warn("n {}", request->cluster_id().size());',
        'spdlog::warn("cap {}", kMaxClusterIdLen);',
        'spdlog::warn("node \'{}\'", onbehalf::sanitize_for_log(session.gateway_node, 64));',
        'spdlog::warn("n {}", session.gateway_node.size());',
        'spdlog::warn("e {}", session.gateway_node.empty());',
        'spdlog::warn("x {}", session.gateway_nodes);',
    ]
    for src in cmd_must_not:
        if find_command_text_violations_in_text(src):
            raise SystemExit(f"selfcheck: unexpected command-id/plugin violation: {src!r}")

    # 12. The unscanned-logging-forms guard (find_unscanned_logging_forms_in_text).
    form_must_match = [
        'SPDLOG_INFO("x {}", agent_id);',
        '  SPDLOG_CRITICAL ("x");',
        'spdlog::log(spdlog::level::warn, "x {}", id);',
        'spdlog::log (lvl, "x");',
        'auto lg = spdlog::default_logger();',
        'default_logger()->warn("x {}", id);',
    ]
    for src in form_must_match:
        if not find_unscanned_logging_forms_in_text(src):
            raise SystemExit(f"selfcheck: expected an unscanned-logging-form hit: {src!r}")
    form_must_not = [
        'spdlog::warn("x {}", id);',
        'logger->info("x {}", id);',
        'spdlog::set_level(spdlog::level::info);',
        'const auto catalog = spdlog_log_path;',
        'MY_SPDLOG_INFO_MARK();',
    ]
    for src in form_must_not:
        if find_unscanned_logging_forms_in_text(src):
            raise SystemExit(f"selfcheck: unexpected unscanned-logging-form hit: {src!r}")

    # 13. The PKI signer rule (find_pki_signer_violations_in_text).
    pki_must_match = [
        'spdlog::warn("PKI: sign_csr failed for agent {}", agent_id);',
        'spdlog::warn("PKI: throttling agent CSR for {} (one issuance per {}s)", agent_id, 30);',
        'spdlog::error("PKI: agent CSR signing threw ({}) for {} - non-fatal", e.what(),'
        " ::yuzu::log_id_token(agent_id));",
        'spdlog::error("PKI: agent CSR signing threw ({}) for {}", ::yuzu::log_key_token(e.what()),'
        " agent_id);",
        'spdlog::warn("PKI: x {}", "a=" + agent_id);',
        'spdlog::warn("PKI: x {}", ::yuzu::log_id_token(a) + agent_id);',
    ]
    for src in pki_must_match:
        if not find_pki_signer_violations_in_text(src):
            raise SystemExit(f"selfcheck: expected a PKI signer violation: {src!r}")
    pki_must_not = [
        'spdlog::warn("PKI: sign_csr failed for agent {}", ::yuzu::log_id_token(agent_id));',
        'spdlog::error("PKI: x ({}) for {}", ::yuzu::log_key_token(e.what()),'
        " ::yuzu::log_id_token(agent_id));",
        'spdlog::warn("PKI: n {}", agent_id.size());',
        'spdlog::warn("PKI: x {}", rev.agent_id);',
        'spdlog::warn("PKI: x {}", my_agent_id);',
        'spdlog::warn("PKI: initial CRL publish failed: {}", err);',
        # Not a PKI line: the broad bare-name rule is deliberately not applied to server.cpp.
        'spdlog::warn("Agent {} did a thing", agent_id);',
    ]
    for src in pki_must_not:
        if find_pki_signer_violations_in_text(src):
            raise SystemExit(f"selfcheck: unexpected PKI signer violation: {src!r}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _scanned_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "--", *SEARCH_ROOTS],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    files = []
    for rel in out.splitlines():
        p = REPO_ROOT / rel
        if p == SELF or not p.is_file():
            continue
        if FILE_BASENAME_RE.match(p.name):
            files.append(p)
    return files


def main() -> int:
    _selfcheck()
    hits: list[str] = []
    for path in _scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(REPO_ROOT)
        for line_no, pattern_names, stmt in find_violations_in_text(text):
            snippet = " ".join(stmt.split())[:160]
            hits.append(f"{rel}:{line_no}: [{pattern_names}] {snippet}")
    agent_hits: list[str] = []
    for rel, always_bare in AGENT_ID_FILES.items():
        path = REPO_ROOT / rel
        if not path.is_file():
            # A rename would otherwise silently shrink this check to nothing.
            agent_hits.append(f"{rel}: file listed in AGENT_ID_FILES does not exist")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, stmt in find_agent_id_violations_in_text(text, always_bare):
            snippet = " ".join(stmt.split())[:160]
            agent_hits.append(f"{rel}:{line_no}: {snippet}")
    for rel in PQ_ERROR_FILES:
        path = REPO_ROOT / rel
        if not path.is_file():
            agent_hits.append(f"{rel}: file listed in PQ_ERROR_FILES does not exist")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, stmt in find_pq_error_violations_in_text(text):
            snippet = " ".join(stmt.split())[:160]
            agent_hits.append(f"{rel}:{line_no}: {snippet}")
    for rel in STORE_ERROR_FILES:
        path = REPO_ROOT / rel
        if not path.is_file():
            agent_hits.append(f"{rel}: file listed in STORE_ERROR_FILES does not exist")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, stmt in find_pq_error_violations_in_text(text, (".error()",)):
            snippet = " ".join(stmt.split())[:160]
            agent_hits.append(f"{rel}:{line_no}: {snippet}")
    for rel in REGISTRY_FREE_TEXT_FILES:
        path = REPO_ROOT / rel
        if not path.is_file():
            agent_hits.append(f"{rel}: file listed in REGISTRY_FREE_TEXT_FILES does not exist")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, stmt in find_registry_free_text_violations_in_text(text):
            snippet = " ".join(stmt.split())[:160]
            agent_hits.append(f"{rel}:{line_no}: {snippet}")
    for rel in COMMAND_TEXT_FILES:
        path = REPO_ROOT / rel
        if not path.is_file():
            agent_hits.append(f"{rel}: file listed in COMMAND_TEXT_FILES does not exist")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, stmt in find_command_text_violations_in_text(text):
            snippet = " ".join(stmt.split())[:160]
            agent_hits.append(f"{rel}:{line_no}: {snippet}")
    for rel in PKI_SIGNER_FILES:
        path = REPO_ROOT / rel
        if not path.is_file():
            agent_hits.append(f"{rel}: file listed in PKI_SIGNER_FILES does not exist")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, stmt in find_pki_signer_violations_in_text(text):
            snippet = " ".join(stmt.split())[:160]
            agent_hits.append(f"{rel}:{line_no}: {snippet}")
    for rel in UNSCANNED_LOGGING_FILES:
        path = REPO_ROOT / rel
        if not path.is_file():
            agent_hits.append(f"{rel}: file listed in UNSCANNED_LOGGING_FILES does not exist")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in find_unscanned_logging_forms_in_text(text):
            agent_hits.append(
                f"{rel}:{line_no}: logging form the scanner does not parse "
                f"(use spdlog::<level>(...)): {line[:160]}"
            )
    rc = 0
    if hits:
        print(
            "FAIL: unwrapped rule-id/Spark-key-shaped spdlog:: argument(s) found (#4665 "
            "CWE-117 log-injection tripwire). Wrap with yuzu::log_id_token / "
            "yuzu::log_key_token (common/include/yuzu/log_token.hpp):"
        )
        print("\n".join(hits))
        rc = 1
    if agent_hits:
        print(
            "FAIL: spdlog:: call prints a request-derived agent id, agent-supplied hostname or "
            "command id / plugin name, or raw store/libpq error text unwrapped (#5513 CWE-117 log-injection tripwire). Wrap with ::yuzu::log_id_token(...) "
            "/ ::yuzu::log_key_token(...) "
            "(common/include/yuzu/log_token.hpp):"
        )
        print("\n".join(agent_hits))
        rc = 1
    if rc == 0:
        print("OK: no unwrapped rule-id/Spark-key-shaped or claimed-agent-id spdlog:: arguments found")
    return rc


if __name__ == "__main__":
    sys.exit(main())
