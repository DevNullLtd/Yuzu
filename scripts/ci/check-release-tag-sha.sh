#!/usr/bin/env bash
# Refuse to publish from a run whose tag no longer points at its commit (#5282,
# SEC-F2). Two runs for one tag at different commits (a re-tag while a run is
# in flight; a moved tag whose push webhook never fired) both pass release-guard
# because no release exists yet; whichever pushes LAST would own :X.Y.Z while
# the other's release job signs SHA256SUMS for different images. Every image
# push and the release creation call this immediately before acting, so a run
# whose tag has moved away from its commit refuses at its next publishing step.
# It does NOT detect a tag moved away and back again (A->B->A) while two runs
# are in flight: cancel in-flight release runs for a tag before re-tagging it
# (release skill, Recovery; digest check before signing: #5478).
# Fail-closed: any error reading the tag refuses.
# Shell contract: tests/shell/test_release_tag_sha.sh.
set -uo pipefail
tag="${GITHUB_REF_NAME:?}"; want="${GITHUB_SHA:?}"
# No credential: the repository is public, and a token passed to git via -c
# would sit in git's argv (visible to other processes on a self-hosted runner),
# unmasked. If the repository ever goes private, read the ref with
# `gh api repos/$GITHUB_REPOSITORY/git/ref/tags/$tag` instead (#5282, SEC-G8-1).
# Bounded: a hung connection must not hold a runner slot (G8-CHAOS-1).
export GIT_TERMINAL_PROMPT=0   # never wait for a credential prompt
if ! refs="$(timeout 60 git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")"; then
  echo "::error::Could not read refs/tags/$tag from origin; refusing to publish (fail-closed, #5282)."
  exit 1
fi
plain="$(awk -v r="refs/tags/$tag" '$2==r{print $1}' <<<"$refs")"
peeled="$(awk -v r="refs/tags/$tag^{}" '$2==r{print $1}' <<<"$refs")"
if [[ -z "$plain" ]]; then
  echo "::error::Tag $tag no longer exists on origin; refusing to publish (#5282)."
  exit 1
fi
current="${peeled:-$plain}"
if [[ "$current" != "$want" && "$plain" != "$want" ]]; then
  echo "::error::Tag $tag now points at $current, not this run's $want: the tag moved after this run started, so the newer run owns :$tag. Refusing to publish (#5282)."
  exit 1
fi
echo "Tag $tag still points at $want; publishing may proceed."
