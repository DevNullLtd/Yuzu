#!/usr/bin/env bash
# release-degraded.sh DIR: say, from the published attempt's own grype report,
# whether any image of a release was scanned DEGRADED (it passed under a grype
# provider waiver: docs/ci-architecture.md "A grype DB provider is stale").
#
# It changes no verdict. `gate: pass` still opens the publish journal and
# still passes check-release-artifacts.sh; this only makes the DEGRADED
# marking appear where a release is assembled and checked, so the release
# notes' statement no longer depends on a person remembering it.
#
# For every image that has a publish journal or a grype report in DIR, the
# published attempt is the one `image-publish.sh published` names (the highest
# whose journal ends `publish: tagged`; a refused attempt's report is not read),
# and its grype-<image>.attempt-<N>.gate.txt is read.
#
# Fail-safe: anything that stops the answer being known (no published attempt,
# an unreadable or missing report, a report with no `provider waiver:` line at
# all) is reported as "could not be determined", never as "not degraded".
#
# Output: nothing when every image positively reads "provider waiver: none
# used"; otherwise a Markdown section for the release notes.
# Exit: 0 nothing to report, 10 a degraded or undetermined image is reported.
set -u

DIR="${1:-}"
[ -n "$DIR" ] && [ -d "$DIR" ] || { echo "usage: release-degraded.sh DIR" >&2; exit 2; }
PUBLISH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/image-publish.sh"

declare -A images=()
shopt -s nullglob
for f in "$DIR"/publish-*.attempt-*.txt "$DIR"/grype-*.attempt-*.gate.txt; do
    b="${f##*/}"
    if [[ "$b" =~ ^publish-([a-z0-9][a-z0-9._-]*)\.attempt-[1-9][0-9]{0,3}\.txt$ ]]; then
        images[${BASH_REMATCH[1]}]=1
    elif [[ "$b" =~ ^grype-([a-z0-9][a-z0-9._-]*)\.attempt-[1-9][0-9]{0,3}\.gate\.txt$ ]]; then
        images[${BASH_REMATCH[1]}]=1
    fi
done
shopt -u nullglob

# Only printable ASCII from a report reaches the notes.
clean() { LC_ALL=C tr -cd '[:print:]\n'; }

degraded=() unknown=()
for img in $(printf '%s\n' "${!images[@]}" | sort); do
    out="" rc=0 n=""
    out="$(bash "$PUBLISH" published "$DIR" "$img" 2>/dev/null)" || rc=$?
    n="$(sed -n 's/^published=//p' <<<"$out")"
    if [ "$rc" -ne 0 ] || [[ ! "$n" =~ ^[1-9][0-9]{0,3}$ ]]; then
        unknown+=("$img: no published attempt could be named")
        continue
    fi
    f="$DIR/grype-$img.attempt-$n.gate.txt"
    if [ ! -s "$f" ] || ! content="$(cat "$f" 2>/dev/null)"; then
        unknown+=("$img: grype-$img.attempt-$n.gate.txt is missing, empty or unreadable")
        continue
    fi
    if grep -q '^DEGRADED:' <<<"$content"; then
        degraded+=("$img (attempt $n)")
        while IFS= read -r l; do degraded+=("  $l"); done < <(grep -e '^provider waiver:' -e '^DEGRADED:' <<<"$content" | clean)
    elif ! grep -q '^provider waiver: none used$' <<<"$content"; then
        unknown+=("$img: grype-$img.attempt-$n.gate.txt records neither a degraded pass nor \`provider waiver: none used\`")
    fi
done

# No image at all is not "none degraded": the reports are missing.
[ "${#images[@]}" -gt 0 ] || unknown+=("no image gate report or publish journal was found in $DIR")
[ "${#degraded[@]}" -gt 0 ] || [ "${#unknown[@]}" -gt 0 ] || exit 0

echo "## Image scan: DEGRADED"
echo
if [ "${#degraded[@]}" -gt 0 ]; then
    echo "The image(s) below passed the grype vulnerability gate under a reviewed provider waiver: grype matched a provider's packages against advisories older than 72 hours, so a fix published upstream since then may be missing from the verdict. Each line is from the published attempt's own grype \`.gate.txt\` (provider, capture age, waiver expiry, \`approval_ref\`); see [\`docs/user-manual/release-verification.md\`](docs/user-manual/release-verification.md) \"A degraded pass\"."
    echo
    printf '    %s\n' "${degraded[@]}"
    echo
fi
if [ "${#unknown[@]}" -gt 0 ]; then
    echo "Whether the following image(s) were scanned degraded could not be determined from their reports; treat them as degraded until verified:"
    echo
    printf '    %s\n' "${unknown[@]}"
    echo
fi
exit 10
