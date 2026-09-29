#!/usr/bin/env bash
# detect-code-change.sh — fail-closed changed-path classifier for ci.yml.
#
# Prints exactly "true" or "false" to stdout; diagnostics go to stderr.
#
# Interfaces:
#
#   detect-code-change.sh [--class code] [TOTAL] < changed-paths
#
#     The existing docs-only gate (issue #1978). Reads one path per line from
#     stdin. TOTAL is GitHub's authoritative pull_request.changed_files count.
#
#   detect-code-change.sh --class ci-infrastructure --git-diff BASE [HEAD]
#
#     The workflow canary gate. Establishes the diff itself, then reports true
#     iff it includes .github/workflows/, .github/actions/, or scripts/ci/.
#     A diff error reports true: an uncertain change set must run the canary.
#
# The default class remains `code` for backward compatibility.
#
# For the default `code` class, the optional positional TOTAL is GitHub's
# authoritative pull_request.changed_files count. It guards the "List pull
# requests files" REST endpoint's 3000-file cap: if the piped list is shorter
# than this count the list was truncated, and we FAIL CLOSED to "true" (build)
# rather than trust a partial view that might hide a code file past the cap.
#
# The docs-only ignore set mirrors the ci.yml `push:` trigger's `paths`
# allow-list (an ALLOW-list with `!`-negations, not `paths-ignore` — BR-010;
# the pull_request trigger carries no path filter at all, #1978), with
# GitHub's root-anchored filter semantics — a bare `*.md`,
# `LICENSE`, or `.gitignore` pattern matches ONLY the repository root, never a
# nested path:
#   - docs/**                        (any depth under docs/), EXCEPT
#     docs/os-capability-matrix.md — carved OUT of docs/** (#2204 PR1.1): it
#     carries a machine-generated block, so a hand-edit there must still run
#     the build/gate matrix. Kept in lockstep with the ci.yml `push:`
#     trigger's `paths` allow-list re-include entry.
#   - root-level *.md                (README.md, but NOT sdk/README.md)
#   - LICENSE, .gitignore            (root only)
#   - .github/runner-inventory.json
#   - .github/workflows/runner-inventory-sentinel.yml
# Anything else -> code_changed=true. Fail-closed throughout: any uncertainty
# (empty list, truncated list) builds rather than silently skipping the matrix.
#
# KEEP IN SYNC: this ignore set must match the `push:` trigger's `paths`
# allow-list negations in .github/workflows/ci.yml — editing one without the
# other diverges PR-time and post-merge build behaviour.
#
# Run tests:  bash tests/shell/test_detect_code_change.sh
set -euo pipefail

path_class="code"
expected_total=""

usage() {
  cat >&2 <<'EOF'
usage:
  detect-code-change.sh [--class code] [TOTAL] < changed-paths
  detect-code-change.sh --class ci-infrastructure --git-diff BASE [HEAD]
  detect-code-change.sh --class ci-infrastructure --git-diff-merge-base BASE HEAD
EOF
  exit 2
}

if [[ "${1:-}" == "--class" ]]; then
  (( $# >= 2 )) || usage
  path_class="$2"
  shift 2
fi

emit() { printf '%s\n' "$1"; exit 0; }

files=()
diff_established=false
case "$path_class" in
  code)
    (( $# <= 1 )) || usage
    expected_total="${1:-}"
    mapfile -t files || true
    ;;
  ci-infrastructure)
    # Two diff modes, deliberately distinct spellings rather than one flag with
    # a switch, so the caller's choice is visible at the call site and testable.
    #
    #   --git-diff             two-dot `A B`. Correct for a PUSH, where the
    #                          question is "what did this push move" and BASE is
    #                          `github.event.before`.
    #   --git-diff-merge-base  three-dot. Correct for a PULL REQUEST, where BASE
    #                          is a live branch tip that may have advanced past
    #                          the fork point; two-dot there reports the base
    #                          branch's own commits as if the PR contained them.
    #
    # CRITICAL for callers: pass the PR **head** as HEAD, never the checked-out
    # `refs/pull/N/merge` commit. `base.sha` is always an ancestor of that merge
    # commit, so `merge-base(base.sha, merge_commit) == base.sha` and three-dot
    # silently collapses back to two-dot — a byte-identical no-op that leaves
    # this whole mode inert while every test still passes.
    case "${1:-}" in
      --git-diff)            diff_mode=two-dot ;;
      --git-diff-merge-base) diff_mode=merge-base ;;
      *)                     usage ;;
    esac
    (( $# >= 2 && $# <= 3 )) || usage
    # merge-base mode must be given an explicit HEAD. Falling through to the
    # `${3:-HEAD}` default below would hand it the checked-out ref, which for a
    # PR is the merge commit — the very object the comment above forbids.
    # `${3:-HEAD}` below substitutes on EMPTY as well as unset, so an explicitly
    # empty head would pass an arity check and silently become HEAD — the merge
    # commit, i.e. the no-op this mode exists to prevent. Reject both.
    if [[ "$diff_mode" == "merge-base" ]] && { (( $# != 3 )) || [[ -z "$3" ]]; }; then usage; fi
    diff_base="$2"
    diff_head="${3-HEAD}"
    diff_range_args=()
    [[ "$diff_mode" == "merge-base" ]] && diff_range_args+=(--merge-base)
    # Keep diff acquisition inside this module. In particular, do not pipe
    # `git diff` into a matcher: without explicit pipefail handling, git's
    # error becomes the matcher's ordinary "no paths matched" result (the old
    # canary false-green). Disable external diff drivers so repo/user config
    # cannot replace this evidence source.
    # Disable rename folding too. A rename out of an owned path must expose
    # both its source and destination; the default rename display can report
    # only the non-CI destination and incorrectly classify the change as safe.
    # git exits non-zero — into the same fail-closed branch as any other diff
    # failure — when there is NO merge base (unrelated histories) and also when
    # there are SEVERAL (criss-cross history). Two-dot has neither case.
    if ! diff_output=$(git --no-pager -c core.quotePath=false diff \
          --no-ext-diff --no-renames --name-only \
          "${diff_range_args[@]}" "$diff_base" "$diff_head" --); then
      echo "detect-code-change: unable to establish git diff ($diff_mode) '$diff_base'..'$diff_head' -> matched (fail-closed)" >&2
      emit true
    fi
    diff_established=true
    if [[ -n "$diff_output" ]]; then
      mapfile -t files <<< "$diff_output"
    fi
    ;;
  *)
    echo "detect-code-change: unknown path class '$path_class'" >&2
    usage
    ;;
esac

count=${#files[@]}

# An empty stdin is missing evidence. An empty, successfully established git
# diff is a proven no-change result and is handled by the selected class below.
if (( count == 0 )); then
  if [[ "$diff_established" != true ]]; then
    echo "detect-code-change: empty file list -> matched (fail-closed)" >&2
    emit true
  fi
  emit false
fi

# Fail-closed: the files API is capped at 3000 entries. If the caller passed
# the authoritative changed-file count and it does not match what we received,
# the list is truncated (or otherwise inconsistent) and a code file may sit
# beyond the cap — build rather than trust the partial list.
if [[ -n "$expected_total" ]]; then
  if [[ ! "$expected_total" =~ ^[0-9]+$ ]]; then
    echo "detect-code-change: invalid authoritative total '$expected_total' -> matched (fail-closed)" >&2
    emit true
  fi
  if (( count != expected_total )); then
    echo "detect-code-change: received $count of $expected_total files (truncated/mismatch) -> matched (fail-closed)" >&2
    emit true
  fi
fi

for f in "${files[@]}"; do
  [[ -z "$f" ]] && continue
  # Git C-quotes paths containing control characters. A line-oriented parser
  # cannot prove their original prefix, so select the expensive path rather
  # than treating the quoted representation as a non-match.
  if [[ "$diff_established" == true && "$f" == \"* ]]; then
    echo "detect-code-change: quoted git path cannot be classified -> matched (fail-closed)" >&2
    emit true
  fi
  if [[ "$path_class" == "ci-infrastructure" ]]; then
    case "$f" in
      .github/workflows/*|.github/actions/*|scripts/ci/*)
        echo "detect-code-change: CI infrastructure path matched: $f" >&2
        emit true
        ;;
    esac
  else
    case "$f" in
      docs/os-capability-matrix.md)
        # Carved out of the docs-only ignore set (#2204 PR1.1): this file
        # carries a machine-generated block (tools/capmatrix-gen +
        # scripts/ci/check-capability-matrix.sh) that only stays honest if a
        # hand-edit here still runs the full build/gate matrix — a docs-only
        # PR that quietly edited the generated block would otherwise skip
        # the drift gate entirely. Matched IN LOCKSTEP with the ci.yml
        # `push:` trigger's `paths` allow-list re-include — edit both or neither.
        echo "detect-code-change: docs/os-capability-matrix.md carved out of docs-only -> building: $f" >&2
        emit true
        ;;
      docs/*) ;;                                        # docs/** (any depth)
      LICENSE|.gitignore) ;;                             # root-only exact match
      .github/runner-inventory.json) ;;
      .github/workflows/runner-inventory-sentinel.yml) ;;
      *.md)
        # GitHub's `*.md` filter is root-only; a nested .md is NOT ignored.
        if [[ "$f" == */* ]]; then
          echo "detect-code-change: nested markdown is code-side per the paths allow-list -> building: $f" >&2
          emit true
        fi
        ;;
      *)
        echo "detect-code-change: non-docs path -> building: $f" >&2
        emit true
        ;;
    esac
  fi
done

emit false
