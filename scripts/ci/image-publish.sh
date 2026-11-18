#!/usr/bin/env bash
# The publish journal: the write-ahead record of how far one run attempt got in
# publishing one image (WP15/S9). This script is the ONLY writer of the journal
# and the only reader its consumers use.
#
# Why. A release tag (`:X.Y.Z`, `:X.Y`, `:latest`) is public the moment it
# moves. So the tag moves LAST, after the pushed digest is verified to be the
# scanned image and is signed and attested, and every step that touches the
# registry is announced in the journal BEFORE it runs. Whatever stops the job
# (a failure, a cancel, a timeout), the journal's last line claims at least
# what the registry holds, never less.
#
# The file: <DIR>/publish-<NAME>.attempt-<N>.txt, beside the gate's reports
# (<scanner>-<NAME>.attempt-<N>.*), uploaded with them. One line per completed
# transition, appended, never rewritten; the LAST line is the state. The only
# legal contents are a prefix of exactly this sequence, one digest throughout:
#
#   publish: none                                     the gate passed; nothing pushed
#   publish: push-started <candidate>                 written BEFORE the push
#   publish: verified <repo>@<digest>                 the pushed digest has the scanned layers
#   publish: signed-attested <repo>@<digest>          SBOM, provenance and signature made by digest,
#                                                     and the signature verifies
#   publish: tagging <repo>:<tag>[,...] <digest>      written BEFORE the first tag moves
#   publish: tagged <repo>:<tag>[,...] <digest>       every tag resolves to the digest
#
# <candidate> is <repo> (a buildx push by digest: no tag at all) or
# <repo>:candidate-<run id>-<N> (the agent bundle's `docker push`). <repo>'s
# last path component is <NAME>. No file at all means nothing was pushed by that
# attempt: the gate refused the image, or the job stopped before the journal was
# opened. A failure or a cancel simply stops the journal: there is no failure
# label and no trap. A `tagging` journal means some of the tags may name the
# digest and some may not (moving several tags is not atomic).
#
# Usage:
#   image-publish.sh open            DIR NAME N
#       Starts the journal (`publish: none`). Refused unless every
#       <scanner>-<NAME>.attempt-<N>.gate.txt in DIR (Trivy's is required)
#       records exactly `gate: pass`, or when the journal already exists.
#   image-publish.sh push-started    DIR NAME N CANDIDATE
#       Records the intent to push CANDIDATE. Run it immediately BEFORE the push.
#       Refused unless the state is `none` and the gate reports still pass.
#   image-publish.sh verified        DIR NAME N REPO@DIGEST LAYERS
#       Runs `image-identity.sh verify-pushed REPO@DIGEST LAYERS` (and, for a
#       tagged candidate, checks the candidate tag names DIGEST), then records it.
#   image-publish.sh signed-attested DIR NAME N REPO@DIGEST
#       Runs `cosign verify` on REPO@DIGEST against this workflow's identity
#       (GITHUB_SERVER_URL/GITHUB_WORKFLOW_REF, issuer GitHub Actions), then
#       records it. Run it after the SBOM, attestation and signing steps.
#   image-publish.sh tag             DIR NAME N REPO@DIGEST REPO:TAG...
#       Records `tagging`, points every tag at REPO@DIGEST with
#       `docker buildx imagetools create --prefer-index=false` (a carbon copy:
#       the tag names the same manifest digest), checks every tag resolves to
#       DIGEST, then records `tagged`. Any failure leaves the journal at
#       `tagging`.
#   image-publish.sh state           DIR NAME N
#       Prints state=, candidate=, repo=, digest=, tags= for one attempt's
#       journal (state=absent when there is none). Exit 1 when the journal is
#       not a legal prefix.
#   image-publish.sh published       DIR NAME
#       Reads every attempt in DIR (journals and gate reports) and prints
#       published=<N>|none, digest=, tags=, plus one `attempt <N>: <state>` line
#       per attempt on stderr. The published image is the HIGHEST attempt whose
#       journal ends `tagged`. Exit 1 when any journal is not a legal prefix, or
#       an attempt has a journal but its gate reports do not all record
#       `gate: pass`; exit 3 when the journals are legal but an attempt ABOVE
#       the published one ends `tagging` (some tag may name its digest, so no
#       attempt can be called the published image).
#
# A step summary is not a consumer: job outputs carry no publish state.
# Contract and the residuals (a SIGKILL before the upload, a re-run moving the
# tag to a new digest, non-atomic multi-tag moves, leftover candidate digests):
# docs/ci-architecture.md "Release image vulnerability gate", "The publish
# journal". Tests: tests/test_image_publish.py.
#
# Exit status: 0 ok; 1 refused, failed check, or illegal journal; 2 usage;
# 3 (`published` only) a higher attempt stopped while tagging.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISSUER="https://token.actions.githubusercontent.com"
LABELS=(none push-started verified signed-attested tagging tagged)

err() {
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error::$*"; else echo "ERROR: $*" >&2; fi
}
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2; exit 2; }

RE_NAME='^[a-z0-9][a-z0-9._-]*$'
RE_ATTEMPT='^[1-9][0-9]{0,3}$'
RE_REPO='^[a-z0-9][a-z0-9.-]*(:[0-9]{1,5})?(/[a-z0-9][a-z0-9._-]*)+$'
RE_DIGEST='^sha256:[0-9a-f]{64}$'
RE_TAG='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'

journal_of() { printf '%s/publish-%s.attempt-%s.txt' "$1" "$2" "$3"; }

# repo_ok REPO NAME: a registry repository whose last component is NAME.
repo_ok() { [[ "$1" =~ $RE_REPO ]] && [ "${1##*/}" = "$2" ]; }

# tags_ok LIST REPO: LIST is <REPO>:<tag>[,<REPO>:<tag>...], no duplicates, no
# candidate tag. Sets TAGS_ARR.
tags_ok() {
    local list="$1" repo="$2" t tag
    declare -A seen=()
    TAGS_ARR=()
    [ -n "$list" ] || return 1
    IFS=, read -r -a TAGS_ARR <<<"$list"
    [ "${#TAGS_ARR[@]}" -gt 0 ] || return 1
    # A trailing comma leaves an empty last field that `read -a` drops.
    [ "${list: -1}" != "," ] || return 1
    for t in "${TAGS_ARR[@]}"; do
        [ "${t%:*}" = "$repo" ] || return 1
        tag="${t##*:}"
        [ "$t" = "$repo:$tag" ] || return 1
        [[ "$tag" =~ $RE_TAG ]] || return 1
        case "$tag" in candidate-*) return 1 ;; esac
        [ -z "${seen[$tag]:-}" ] || return 1
        seen[$tag]=1
    done
}

# parse FILE NAME N: reads one journal. Sets J_STATE (absent, or the last
# label), J_CAND, J_REPO, J_DIGEST, J_TAGS. Returns 1, with J_WHY, when the file
# is not a legal prefix of the sequence.
parse() {
    local f="$1" name="$2" n="$3" i line want rest cand repo ref
    J_STATE="absent"; J_CAND=""; J_REPO=""; J_DIGEST=""; J_TAGS=""; J_WHY=""
    if [ ! -e "$f" ] && [ ! -L "$f" ]; then return 0; fi
    if [ -L "$f" ] || [ ! -f "$f" ]; then J_WHY="not a regular file"; return 1; fi
    if [ ! -s "$f" ]; then J_WHY="empty"; return 1; fi
    if [ "$(tail -c 1 "$f" | od -An -tx1 | tr -d ' \n')" != "0a" ]; then
        J_WHY="the last line is not complete"; return 1
    fi
    local -a lines=()
    mapfile -t lines <"$f"
    if [ "${#lines[@]}" -gt "${#LABELS[@]}" ]; then J_WHY="more lines than the sequence has"; return 1; fi
    for i in "${!lines[@]}"; do
        line="${lines[$i]}"
        want="${LABELS[$i]}"
        if [ "$want" = none ]; then
            [ "$line" = "publish: none" ] || { J_WHY="line 1 is not 'publish: none'"; return 1; }
            J_STATE=none; continue
        fi
        case "$line" in
            "publish: $want "*) rest="${line#"publish: $want "}" ;;
            *) J_WHY="line $((i + 1)) is not 'publish: $want ...' (labels must come in order)"; return 1 ;;
        esac
        case "$want" in
            push-started)
                cand="$rest"
                repo="${cand%%:candidate-*}"
                if [ "$repo" != "$cand" ]; then
                    [[ "${cand#"$repo:"}" =~ ^candidate-[0-9]{1,20}-${n}$ ]] \
                        || { J_WHY="bad candidate tag in '$cand' (must be candidate-<run id>-$n)"; return 1; }
                fi
                repo_ok "$repo" "$name" || { J_WHY="candidate '$cand' is not a repository named $name"; return 1; }
                J_CAND="$cand"; J_REPO="$repo" ;;
            verified)
                ref="$rest"
                if ! { [ "${ref%@*}" = "$J_REPO" ] && [[ "${ref#*@}" =~ $RE_DIGEST ]] && [ "$ref" = "$J_REPO@${ref#*@}" ]; }; then
                    J_WHY="verified '$ref' is not $J_REPO@sha256:<digest>"; return 1
                fi
                J_DIGEST="${ref#*@}" ;;
            signed-attested)
                [ "$rest" = "$J_REPO@$J_DIGEST" ] \
                    || { J_WHY="signed-attested '$rest' is not the verified $J_REPO@$J_DIGEST"; return 1; } ;;
            tagging)
                if ! { [ "${rest##* }" = "$J_DIGEST" ] && [ "${rest% *}" != "$rest" ]; }; then
                    J_WHY="tagging does not name the verified digest $J_DIGEST"; return 1
                fi
                tags_ok "${rest% *}" "$J_REPO" \
                    || { J_WHY="tagging names a bad tag list '${rest% *}'"; return 1; }
                J_TAGS="${rest% *}" ;;
            tagged)
                [ "$rest" = "$J_TAGS $J_DIGEST" ] \
                    || { J_WHY="tagged '$rest' is not the tagging line's '$J_TAGS $J_DIGEST'"; return 1; } ;;
        esac
        J_STATE="$want"
    done
}

# load DIR NAME N: parse, or fail the command naming the file.
load() {
    local f
    f="$(journal_of "$1" "$2" "$3")"
    parse "$f" "$2" "$3" || { err "${f##*/} is not a legal publish journal: $J_WHY"; exit 1; }
}

# gates_pass DIR NAME N: every <scanner>-NAME.attempt-N.gate.txt records
# exactly `gate: pass` (one gate line, that one), and Trivy's exists.
# Sets GATE_WHY when not.
gates_pass() {
    local dir="$1" name="$2" n="$3" f base scanner have_trivy=0
    local -a files=() gl=()
    GATE_WHY=""
    shopt -s nullglob
    files=("$dir"/*-"$name".attempt-"$n".gate.txt)
    shopt -u nullglob
    for f in "${files[@]}"; do
        base="${f##*/}"
        scanner="${base%-"$name".attempt-"$n".gate.txt}"
        [[ "$scanner" =~ ^[a-z0-9]+$ ]] || continue   # another image's report (x-NAME)
        [ "$scanner" != trivy ] || have_trivy=1
        mapfile -t gl < <(grep -E '(^|[[:space:]])gate:' "$f" || true)
        if [ "${#gl[@]}" -ne 1 ] || [ "${gl[0]}" != "gate: pass" ]; then
            GATE_WHY="$base does not record exactly 'gate: pass'"; return 1
        fi
    done
    [ "$have_trivy" = 1 ] || { GATE_WHY="no trivy-$name.attempt-$n.gate.txt"; return 1; }
}

# append DIR NAME N LINE: one write of one complete line.
append() {
    printf 'publish: %s\n' "$4" >>"$(journal_of "$1" "$2" "$3")"
}

# split_ref REF: REPO@DIGEST into REF_REPO, REF_DIGEST.
split_ref() {
    REF_REPO="${1%@*}"; REF_DIGEST="${1#*@}"
    [ "$1" = "$REF_REPO@$REF_DIGEST" ] && [[ "$REF_DIGEST" =~ $RE_DIGEST ]]
}

resolve_digest() {
    docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}'
}

cmd="${1:-}"
[ -n "$cmd" ] || usage
shift
case "$cmd" in
    open|push-started|verified|signed-attested|tag|state)
        [ "$#" -ge 3 ] || usage
        DIR="$1"; NAME="$2"; N="$3"; shift 3
        [[ "$NAME" =~ $RE_NAME ]] || { err "bad image name '$NAME'"; exit 2; }
        [[ "$N" =~ $RE_ATTEMPT ]] || { err "bad run attempt '$N'"; exit 2; }
        JOURNAL="$(journal_of "$DIR" "$NAME" "$N")"
        ;;
    published)
        [ "$#" -eq 2 ] || usage
        DIR="$1"; NAME="$2"
        [[ "$NAME" =~ $RE_NAME ]] || { err "bad image name '$NAME'"; exit 2; }
        ;;
    *) usage ;;
esac

case "$cmd" in
    open)
        [ "$#" -eq 0 ] || usage
        [ -d "$DIR" ] || { err "$DIR does not exist (the gate writes its reports there)"; exit 1; }
        if [ -e "$JOURNAL" ] || [ -L "$JOURNAL" ]; then
            err "${JOURNAL##*/} already exists; a journal is opened once per attempt"; exit 1
        fi
        gates_pass "$DIR" "$NAME" "$N" || { err "not opening the publish journal: $GATE_WHY"; exit 1; }
        append "$DIR" "$NAME" "$N" "none"
        echo "publish: none ($NAME, attempt $N; the gate passed)"
        ;;
    push-started)
        [ "$#" -eq 1 ] || usage
        cand="$1"
        load "$DIR" "$NAME" "$N"
        [ "$J_STATE" = none ] || { err "push-started needs state none, the journal is at $J_STATE"; exit 1; }
        gates_pass "$DIR" "$NAME" "$N" || { err "not pushing: $GATE_WHY"; exit 1; }
        repo="${cand%%:candidate-*}"
        if [ "$repo" != "$cand" ]; then
            [[ "${cand#"$repo:"}" =~ ^candidate-[0-9]{1,20}-${N}$ ]] \
                || { err "candidate tag must be candidate-<run id>-$N: '$cand'"; exit 1; }
        fi
        repo_ok "$repo" "$NAME" || { err "candidate '$cand' is not a repository named $NAME"; exit 1; }
        append "$DIR" "$NAME" "$N" "push-started $cand"
        echo "publish: push-started $cand"
        ;;
    verified)
        [ "$#" -eq 2 ] || usage
        ref="$1"; layers="$2"
        load "$DIR" "$NAME" "$N"
        [ "$J_STATE" = push-started ] || { err "verified needs state push-started, the journal is at $J_STATE"; exit 1; }
        split_ref "$ref" || { err "verified needs REPO@sha256:<digest>, got '$ref'"; exit 1; }
        [ "$REF_REPO" = "$J_REPO" ] || { err "$ref is not in the candidate's repository $J_REPO"; exit 1; }
        if [ "$J_CAND" != "$J_REPO" ]; then
            got="$(resolve_digest "$J_CAND")" || { err "could not resolve $J_CAND"; exit 1; }
            [ "$got" = "$REF_DIGEST" ] || { err "$J_CAND names $got, not $REF_DIGEST"; exit 1; }
        fi
        "$HERE/image-identity.sh" verify-pushed "$ref" "$layers"
        append "$DIR" "$NAME" "$N" "verified $ref"
        echo "publish: verified $ref"
        ;;
    signed-attested)
        [ "$#" -eq 1 ] || usage
        ref="$1"
        load "$DIR" "$NAME" "$N"
        [ "$J_STATE" = verified ] || { err "signed-attested needs state verified, the journal is at $J_STATE"; exit 1; }
        [ "$ref" = "$J_REPO@$J_DIGEST" ] || { err "$ref is not the verified $J_REPO@$J_DIGEST"; exit 1; }
        if [ -z "${GITHUB_SERVER_URL:-}" ] || [ -z "${GITHUB_WORKFLOW_REF:-}" ]; then
            err "GITHUB_SERVER_URL and GITHUB_WORKFLOW_REF name the signing identity; not set"; exit 1
        fi
        identity="$GITHUB_SERVER_URL/$GITHUB_WORKFLOW_REF"
        cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" "$ref" >/dev/null \
            || { err "$ref has no signature from $identity that verifies"; exit 1; }
        append "$DIR" "$NAME" "$N" "signed-attested $ref"
        echo "publish: signed-attested $ref (signature verified for $identity)"
        ;;
    tag)
        [ "$#" -ge 2 ] || usage
        ref="$1"; shift
        load "$DIR" "$NAME" "$N"
        [ "$J_STATE" = signed-attested ] || { err "tag needs state signed-attested, the journal is at $J_STATE"; exit 1; }
        [ "$ref" = "$J_REPO@$J_DIGEST" ] || { err "$ref is not the signed $J_REPO@$J_DIGEST"; exit 1; }
        list="$(IFS=,; printf '%s' "$*")"
        tags_ok "$list" "$J_REPO" \
            || { err "tags must be distinct $J_REPO:<tag> references, not a candidate tag: '$*'"; exit 1; }
        append "$DIR" "$NAME" "$N" "tagging $list $J_DIGEST"
        echo "publish: tagging $list $J_DIGEST"
        for t in "${TAGS_ARR[@]}"; do
            docker buildx imagetools create --prefer-index=false -t "$t" "$ref" \
                || { err "could not point $t at $ref; the journal stays at tagging"; exit 1; }
        done
        for t in "${TAGS_ARR[@]}"; do
            got="$(resolve_digest "$t")" || { err "could not resolve $t; the journal stays at tagging"; exit 1; }
            [ "$got" = "$J_DIGEST" ] || { err "$t names $got, not $J_DIGEST; the journal stays at tagging"; exit 1; }
        done
        append "$DIR" "$NAME" "$N" "tagged $list $J_DIGEST"
        echo "publish: tagged $list $J_DIGEST"
        ;;
    state)
        [ "$#" -eq 0 ] || usage
        load "$DIR" "$NAME" "$N"
        echo "state=$J_STATE"
        echo "candidate=$J_CAND"
        echo "repo=$J_REPO"
        echo "digest=$J_DIGEST"
        echo "tags=$J_TAGS"
        ;;
    published)
        declare -A seen=()
        shopt -s nullglob
        for f in "$DIR"/publish-"$NAME".attempt-*.txt "$DIR"/*-"$NAME".attempt-*.gate.txt; do
            base="${f##*/}"
            if [[ "$base" =~ ^publish-${NAME//./\\.}\.attempt-([1-9][0-9]{0,3})\.txt$ ]] \
                || [[ "$base" =~ ^[a-z0-9]+-${NAME//./\\.}\.attempt-([1-9][0-9]{0,3})\.gate\.txt$ ]]; then
                seen[${BASH_REMATCH[1]}]=1
            fi
        done
        shopt -u nullglob
        best=""; best_digest=""; best_tags=""; bad=0
        declare -A st=()
        for n in $(printf '%s\n' "${!seen[@]}" | sort -n); do
            f="$(journal_of "$DIR" "$NAME" "$n")"
            if ! parse "$f" "$NAME" "$n"; then
                err "${f##*/} is not a legal publish journal: $J_WHY"; bad=1; continue
            fi
            st[$n]="$J_STATE"
            if [ "$J_STATE" != absent ] && ! gates_pass "$DIR" "$NAME" "$n"; then
                err "attempt $n of $NAME has a publish journal but its gate did not pass: $GATE_WHY"; bad=1; continue
            fi
            echo "attempt $n: ${J_STATE}${J_DIGEST:+ $J_DIGEST}" >&2
            if [ "$J_STATE" = tagged ]; then best="$n"; best_digest="$J_DIGEST"; best_tags="$J_TAGS"; fi
        done
        [ "$bad" = 0 ] || exit 1
        echo "published=${best:-none}"
        echo "digest=$best_digest"
        echo "tags=$best_tags"
        for n in "${!st[@]}"; do
            if [ "${st[$n]}" = tagging ] && { [ -z "$best" ] || [ "$n" -gt "$best" ]; }; then
                err "attempt $n of $NAME stopped while moving its tags (journal ends 'tagging'), above the published attempt ${best:-(none)}: a tag may name either digest. Re-run the job so a new attempt completes tagging"
                exit 3
            fi
        done
        ;;
esac
