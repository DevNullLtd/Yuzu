#!/usr/bin/env bash
# Refuse to publish from a run whose tag no longer points at its commit (#5282,
# SEC-F2). Two runs for one tag at different commits (a re-tag while a run is
# in flight; a moved tag whose push webhook never fired) both pass release-guard
# because no release exists yet; whichever pushes LAST would own :X.Y.Z while
# the other's release job signs SHA256SUMS for different images. Every image
# push and the release creation call this immediately before acting, so only
# the run whose commit the tag names right now may publish.
# Fail-closed: any error reading the tag refuses.
# Shell contract: tests/shell/test_release_tag_sha.sh.
set -uo pipefail
tag="${GITHUB_REF_NAME:?}"; want="${GITHUB_SHA:?}"
auth=()
if [[ -n "${GH_TOKEN:-}" ]]; then
  # Same mechanism actions/checkout uses; keeps this working if the repo goes private.
  auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w0)")
fi
if ! refs="$(git "${auth[@]}" ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")"; then
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
