# #7529 governance evidence companion — live proof, chaos closure, ledger disclosures

Companion to `governance.d/7529-bundle-verify-signature.gYfD7P.jsonl` (same stem, committed in the same commit).
Run id: `7529-bundle-verify-signature.gYfD7P`. Branch `ci/7529-bundle-verify-signature`.
Reviewed heads: `27c6609d5d` (Gates 1-6), `3dfbb5fcd8` (Gate 8 round 1), `90bf1da6b0` (Gate 8 round 2), `7f82c2522d` (Gate 8 round 3), `685cbc7211` (Gate 8 round 4), `39fdc69d99` (Gate 8 round 5); merge-base `e269e5154f`.
Date: 2026-11-12 (all times UTC). Who ran what is named per section.

**Limits, stated first.** Everything below was produced by the authoring session (the senior) or by governance agents and the
workflow-orchestrator that the authoring session spawned. None of it is independent of the change's author. It is a
transcript, not a re-runnable artefact: a third party verifies it only by repeating the commands, which need network access
to GitHub, GHCR and the Sigstore public-good instance (TUF, Rekor). Release assets can be edited after the fact; the
SHA256SUMS hashes in section 9 pin what was verified.

**Redaction.** No token, OIDC material or credential appears here. Local paths are replaced by `<scratch>` (a per-session
scratch directory) and `<wt>` (the worktree). Output lines are abbreviated with `…` where a line was long; no line was altered otherwise.

## 1. cosign binaries

| version | source | sha256 of binary | matched line in that release's checksums file |
|---|---|---|---|
| v3.1.3 (GitCommit 11926fa5bbbbde47e88fc006b625a17769b743b2) | local install (`~/.local/bin/cosign`); checked against https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt | `4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71` | line 11: `4629c757…7f71  cosign-linux-amd64` (checksums file sha256 `aec2a6f6…fadfa63`) |
| v3.0.5 (GitCommit 479147a4df05f31be48aeb2b3a9d32dfc35ba877) | https://github.com/sigstore/cosign/releases/download/v3.0.5/cosign-linux-amd64 | `db15cc99e6e4837daabab023742aaddc3841ce57f193d11b7c3e06c8003642b2` | `db15cc99…642b2  cosign-linux-amd64` (release checksums file, sha256 `812ec724…daf616`) |
| v2.6.2 (GitCommit 3ade80c5f77cefc904f8c994e88618e5892e8f1c) | https://github.com/sigstore/cosign/releases/download/v2.6.2/cosign-linux-amd64 | `d437b8f0d30f5dec169337607fcfa0238de1348503e175f1bb5b94330b1ee409` | `d437b8f0…ee409  cosign-linux-amd64` (release checksums file, sha256 `63a725c2…cd6d20`) |

## 2. Manifest signature, exact published command, DIRECT exit codes (workflow-orchestrator, Gate 8 round 3)

Command form (exactly as `docs/user-manual/release-verification.md` and the script publish it):

```
cosign verify-blob --bundle <BUNDLE> \
  --certificate-identity "https://github.com/<SIGNER>/.github/workflows/release.yml@refs/tags/<TAG>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

`rc` is cosign's own exit status, taken as `$?` directly after the command in a subshell that ran nothing after it; no pipe.
The loop that produced this table (orchestrator's statement of the method; the log it wrote is hashed in section 9):

```
( cd <scratch>/dl/<release> && "$COSIGN" verify-blob --bundle <BUNDLE> --certificate-identity "…" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS >/dev/null 2>cos.err ); rc=$?
```

| cosign | release files | bundle | identity (signer @ tag) | rc | expected | cosign's last line |
|---|---|---|---|---|---|---|
| 3.1.3 / 3.0.5 / 2.6.2 | v0.7.1-rc1 | SHA256SUMS.bundle (legacy) | Tr3kkR/Yuzu @ v0.7.1-rc1 | 0 / 0 / 0 | 0 | Verified OK |
| 3.1.3 / 3.0.5 / 2.6.2 | v0.11.0 | SHA256SUMS.sigstore | Tr3kkR/Yuzu @ v0.11.0 | 0 / 0 / 0 | 0 | Verified OK |
| 3.1.3 / 3.0.5 / 2.6.2 | v0.13.0 | SHA256SUMS.sigstore | Tr3kkR/Yuzu @ v0.13.0 | 0 / 0 / 0 | 0 | Verified OK |
| 3.1.3 / 3.0.5 / 2.6.2 | v0.15.0 | SHA256SUMS.sigstore | DevNullLtd/Yuzu @ v0.15.0 | 0 / 0 / 0 | 0 | Verified OK |
| 3.1.3 / 3.0.5 / 2.6.2 | v0.15.0 | SHA256SUMS.sigstore | Tr3kkR/Yuzu @ v0.15.0 (wrong signer) | 1 / 1 / 1 | 1 | failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value "https://github.com… |
| 3.1.3 / 3.0.5 / 2.6.2 | v0.14.0-rc2 | SHA256SUMS.sigstore | DevNullLtd/Yuzu @ v0.15.0 (tag replay) | 1 / 1 / 1 | 1 | same SAN-mismatch error |

Correction carried from round 1: the senior's first proof log (`proof.log`, 50a01435b6) printed `rc=0` on the tag-replay line.
That was a logging artefact (`${PIPESTATUS[0]}` read after a subshell pipe). Re-run with a direct exit code: rc=1, as above.

Consequence recorded in the change: the documented minimum is "cosign v2.6.2 or later" (commit 90bf1da6b0), not v3.x.

## 3. Bundle format (XP8-3)

v0.15.0 `SHA256SUMS.sigstore` (`jq` extract):
`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","tlog":[{"logIndex":"3597770460","integratedTime":"1793378734","kind":{"kind":"hashedrekord","version":"0.0.1"}}],"tsa_count":1}`.
The senior's 50a01435b6 run recorded the same shape for v0.13.0 (mediaType v0.3, tlogEntries=1, rfc3161 timestamps=1).
cosign v2.6.2 reads this v0.3 bundle (rows above).

## 4. The script end to end (senior, at 50a01435b6, cosign v3.1.3)

`bash scripts/build-agent-bundle.sh --verify-only --version X` (stops before any build):
- positives: 0.13.0 (Tr3kkR/Yuzu) rc=0; 0.14.0-rc2 (DevNullLtd/Yuzu) rc=0; 0.15.0 (DevNullLtd/Yuzu) rc=0. Each printed "signature verified", then "All 7 artifacts match their own SHA256SUMS line".
- negatives: 0.15.0 `--signer-repo Tr3kkR/Yuzu` rc=1 (cosign SAN mismatch shown, never "hash MISMATCH"); 0.13.0 `--signer-repo DevNullLtd/Yuzu` rc=1 (same); 0.10.0 rc=1 "no SHA256SUMS.sigstore … refusing"; 0.7.1-rc1 rc=1 with the legacy `.bundle` message and the inline exact tag-bound command (that command verifies: section 2, row 1).
- leftovers: all of the script's temporary directories removed; no `deploy/docker/.agent-bundle-build*` left in the worktree.

Round-2 happy-path run at 90bf1da6b0: `--version 0.15.0 --verify-only` rc=0.

## 5. The bundle image, verified by digest (SEC9-1 closure, round 3)

Senior, at 7f82c2522d, cosign v3.1.3; re-run independently of the senior by the round-3 security-guardian agent:
```
docker buildx imagetools inspect ghcr.io/devnullltd/yuzu-agent-bundle-chisel:0.15.0 --format '{{.Manifest.Digest}}'
  -> sha256:2b05ed3d1217ebbf7cca50ea878bc29b1d1e874d3b41b4e4781414bd6532598e   (a single docker v2 manifest, not an index)
cosign verify ghcr.io/devnullltd/yuzu-agent-bundle-chisel@sha256:2b05ed3d… \
  --certificate-identity https://github.com/DevNullLtd/Yuzu/.github/workflows/release.yml@refs/tags/v0.15.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com            -> rc=0; signed payload's
  critical.image.docker-manifest-digest = sha256:2b05ed3d… (equal to the digest verified)
same digest, identity …@refs/tags/v0.14.1                                           -> rc=1 (SAN mismatch)
empty DIGEST (ghcr.io/devnullltd/yuzu-agent-bundle-chisel@)                         -> rc=1 "could not parse reference"
```
Earlier tag-form image checks (senior, 50a01435b6): `yuzu-agent-bundle-chisel:0.15.0` and `yuzu-server:0.15.0` with the
DevNullLtd identity rc=0; `yuzu-server:0.13.0` with the Tr3kkR identity rc=0. `yuzu-agent-bundle-chisel:0.13.0` does not
exist in GHCR (MANIFEST_UNKNOWN), so the bundle image form is proven for the DevNullLtd era only. `gh attestation verify` by
digest was not run (the local gh 2.46 has no `attestation` subcommand).

## 6. C8-2: installer selection by requested version

`gh release download v0.13.0-rc6 --repo DevNullLtd/Yuzu -p SHA256SUMS -O - | grep -c rc4` -> `4` (re-run in round 3; grep rc=0).
The SIGNED v0.13.0-rc6 manifest lists the rc4 agent/server .deb/.rpm, so before the fix a verify-success build could bundle
rc4 installers. `select_installer` harness (consistency-auditor, round 2, exact HEAD lines under `set -euo pipefail`, empty
files named as the real assets): the rc6 asset set picks `yuzu-agent_0.13.0.rc6_amd64.deb` and the `.rc6` rpm, rc=0; adding a
second spelling `yuzu-agent_0.13.0-rc6_amd64.deb` gives "ambiguous: 2 .deb installer assets …", rc=1; removing the rc6 .deb gives
"no .deb installer asset for 0.13.0-rc6 … (expected one of: …; downloaded: yuzu-agent_0.13.0.rc4_amd64.deb)", rc=1. Real asset
names of 13 releases v0.11.0-rc1..v0.15.0 each select exactly the requested version's four installers.

## 7. Chaos closure

At 50a01435b6 (+3dfbb5fcd8 for the timeout), scratch `git init` copy, stub gh/docker, real cosign v3.1.3, fresh HOME per case:
- CH-4: real v0.15.0 sums+sigstore verify. `HTTPS_PROXY=127.0.0.1:9` -> "cosign verify-blob FAILED … getting trusted root from TUF … connection refused" plus the transient wait-and-re-run line, rc=1, no build, no `--signer-repo` advice. Truncated `.sigstore` -> "unexpected end of JSON input", rc=1. Sums edited, real signature -> "cosign verify-blob FAILED … invalid signature" (not MISMATCH). Tampered tarball, valid signature -> "hash MISMATCH against its own SHA256SUMS line". `--signer-repo Tr3kkR/Yuzu` on 0.15.0 -> "[!!] … differs from the era table's DevNullLtd/Yuzu", then SAN mismatch, rc=1.
- CH-2 / CH-3: a staging tree is stable while another run executes; concurrent 0.15.0 and 0.14.0 builds use distinct staging dirs, both exit 0, each cleans only its own.
- CH-7: the docs test under 8 CPU spinners pinned to one core took 150 s (38 s unstarved), above the 120 s meson timeout, so it was raised to 300 s in 3dfbb5fcd8.
- Not run: faketime (absent), nftables (needs root).
Round 2 (chaos-injector at 90bf1da6b0): R17 (stale or expired TUF cache while online) REFUTED, because cosign self-heals. SEC9-1 VERIFIED (a tag verify never reads the local image: rc=0 with no docker binary and a dead DOCKER_HOST), closed in round 3 (section 5). ARCH9-1 VERIFIED: `check-release-artifacts.sh` passes `yuzu-agent-0.15.0-1.el9.x86_64.rpm`, but the script dies "no .rpm installer asset". Not folded here; filed with the owner's approval as #7595 (deferred-to-issue #7595, covering ARCH9-1 and REL9-3). CH9-1: an unwritable `~/.sigstore` gives `tuf_tmp: permission denied`; `TUF_ROOT=<writable>` passes.

## 8. SEC-3: published release pages carrying the wildcard command (owner-accepted residual)

Exactly 18 of the 22 published release pages print `cosign verify-blob … --certificate-identity-regexp '.*'` (re-read by the
round-3 security-guardian agent on 2026-11-12):
v0.7.0-rc1, v0.7.1-rc1, v0.11.0-rc1, v0.11.0-rc2, v0.11.0, v0.12.0-rc0, v0.12.0, v0.13.0-rc6, v0.13.0, v0.14.0-rc2, v0.14.0-rc3,
v0.14.0-rc4, v0.14.0-rc5, v0.14.0-rc6, v0.14.0-rc7, v0.14.0, v0.14.1, v0.15.0. The other four (v0.8.0-rc0, v0.8.1-rc0, v0.9.0,
v0.10.0) carry no cosign command. That wildcard accepts a certificate from any GitHub Actions workflow in any repository.
Decision (repository owner, directly, 2026-11-12, relayed by the senior): no published page is edited; the acceptance covers all
18. In-repo mitigation: the changelog fragment and the warning at the top of `docs/user-manual/release-verification.md`, both
naming the 18 pages; future release notes use the exact identity (`release.yml`). Caveat: a release tagged from `main` before
this change reaches `main` would be a 19th page outside this acceptance.

## 9. Source material and hashes

Derived from these scratch files (sha256):
- `companion-rerun.log` (workflow-orchestrator, round 3: sections 2, 3, 6 and the hashes below): `f96430e9ea632883724759fdb647db239f2c1427ddbed71feafb8aaf09fe127a`
- `proof.log` (senior, 50a01435b6): `4283608848af2b0e8716f1cb3d5b0a2647847ffbb92a8a5c1600a63a29fc1103`
- `live-proof-50a01435b6.md`: `89e704d9840a9d23c5f0c845b134f4e385182e7ae7a890fa0c36de3fa24ffc39`
- `live-proof-cosign-versions.md`: `64b6ad47fdb76757b88b904b262d8152993e31f1948cd0b0401a733b93980c56`
- `chaos-closure-50a01435b6.md`: `390a4a91fd7e8d48891081dcf0a8733d157b2f86d89a2c40b6adbe0f111ae815`
Downloaded release files verified (sha256):
- v0.7.1-rc1 SHA256SUMS `eb211a59…109`, SHA256SUMS.bundle `e79be5e6…046045`
- v0.11.0 SHA256SUMS `91e9e885…c3fc7d`, SHA256SUMS.sigstore (and its byte-identical `.bundle` twin) `c9e7d8c4…cd5759`
- v0.13.0 SHA256SUMS `7bfe30e2…f3e19`, .sigstore `31a5359c…058b4`
- v0.14.0-rc2 SHA256SUMS `d2f48bc7…c57c03`, .sigstore `42e97b10…d40e`
- v0.15.0 SHA256SUMS `5bb54576…bc8520`, .sigstore `ad7580d5…1232d`
The scratch files are not committed. These hashes let a reader confirm a re-download is the same material.

## 10. Ledger `recorded_at` disclosure (COMP9-1, and the same issue in round 2)

The governance rows were drafted in session scratch space and written with synthetic sub-second or one-second offsets. The
original per-row write instants were not recorded. What the stamps are:
- Rows 1-67 (round-1 first-raise): `10:39:13.000Z + k×10 ms`, anchored to the generator's input mtime (10:39:13.833).
- Row 68 (SEC-6 correction): `10:58:00.000Z`, before the 10:58:02 backup that first contains it.
- Rows 69-172 (Gate 8 round 1): `11:50:35.000Z + k×100 ms` (last 11:50:45.300), within the window between the rows file (11:50:35.006) and the fragment (11:50:46.139).
- Rows 173-275 (Gate 8 round 2, pass_ordinal 3): `13:19:01Z + k s`, ending at 13:20:43Z. The fragment file holding them was last modified at 13:19:01.686. So rows 174-275 carry stamps up to about 102 s LATER than the write that contains them: they were written together at 13:19:01, and their order within that block is file order.
- Gate 8 round 3 rows (pass_ordinal 4) carry one real instant per block, taken immediately before the append; no finding_id has two rows in that block.
- Gate 8 round 4 rows (pass_ordinal 5) carry one real instant (`2026-11-12T16:05:53.266Z`), taken immediately before the append; no finding_id has two rows in that block.
- Gate 8 round 5 rows (pass_ordinal 6) carry one real instant (`2026-11-12T16:24:57.459Z`), taken immediately before the append; no finding_id has two rows in that block.
- The COMP8-1, COMP9-3, COMP10-1, COMP10-2, COMP10-3, COMP11-1 and COMP11-2 `fixed` rows (pass_ordinal 0, "outside the run's rounds") are appended LAST, at commit time, by the author, with the real wall clock at the append, after this companion is in place. They cite this file's sha256 and size, so this file must not change after they are written.
The commit time is the corroborating witness: every stamp precedes the commit that carries the fragment. Within any block, no
finding_id has two rows, so the reconstruction cannot reorder one finding's history.

## 11. Gate 8 round 4 addendum (workflow-orchestrator, reviewed `7f82c2522d..685cbc7211`)

**What round 4 changed** (one commit, six files): the release-skill Phase 4 block (both `.claude` and `.codex` copies,
byte-identical in the changed hunks) now downloads `yuzu-linux-x64.tar.gz`, checks it with `sha256sum -c --ignore-missing`
plus a required `yuzu-linux-x64.tar.gz: OK` line, and stops on a failed `gh attestation verify`. The partner flow (the generated
README and `docs/agent-bundle.md`) resets `VERIFIED=`, sets it only after a successful `cosign verify` by digest, and refuses every
step-3 pull/run/create through `${VERIFIED:?step 2 did not verify - stop}`. `release-verification.md` now says the old pages print
`cosign verify-blob`. The test pins the verify slice's identity and issuer and adds four mutants.

**The round-4 implementer's evidence** (scratch `<scratch>/r4/`), and what the reviewers re-ran:
- Phase 4 against v0.15.0, real cosign v3.1.3: good release rc 0; archive byte-flipped rc 1 "missing or does not match";
  `.sigstore` swapped rc 1 "did not verify". release-deploy and build-ci re-ran copies with REAL cosign and reproduced all three;
  architect re-ran a copy with stub gh and stub cosign on a fixture (one live `cosign verify-blob` of the good release) and got the
  same pass/fail split. The `SHA256SUMS` contents list the archive as exactly `yuzu-linux-x64.tar.gz` (no `./`, no `*`, no subdirectory)
  for the eight releases whose file was read: v0.11.0-rc1, v0.11.0, v0.12.0-rc0, v0.12.0, v0.13.0, v0.14.0, v0.14.1, v0.15.0
  (consistency-auditor, release-deploy); the other releases with a `.sigstore` were checked by asset name only.
- The local `gh` is 2.46, so the attestation branch was skipped with a WARN in every live run. The gh >= 2.50 branch was exercised
  only with a stub (build-ci, unhappy-path, chaos-injector). Not run with a real gh >= 2.50 anywhere in this review.
- README block pasted whole with a failing cosign stub: no pull/run/create; empty DIGEST: refused; real cosign by digest
  (`ghcr.io/devnullltd/yuzu-agent-bundle-chisel@sha256:2b05ed3d…598e`, the v0.15.0 identity): step 3 reached, docker stubbed.
  chaos-injector re-ran its round-3 paste-whole scenario at `685cbc7211` with REAL cosign failing for genuine reasons (a wrong
  tag-bound identity; a foreign digest) and a log-only docker stub: 0 pull/run/create/cp/rm in all 36 failure cells (bash, dash,
  busybox sh, zsh; interactive and script); every positive control ran all five. No docker pull/run/create was executed by any reviewer.

**Outcome.** Closed: REL10-1, ARCH9-3, SEC10-2, QE10-1, CA10-3, DOC10-2. Partial (stay open): UP10-3 (no decision for gh < 2.50),
SEC10-1 (the macOS gating-sentence mutant survives). New, caused by round 4: SEC11-1 (HIGH, BLOCKING: with an unwritable stale
`sha256-check.out` holding the archive's OK line, an absent archive, another `SHA256SUMS`-listed file present in the directory and
gh < 2.50, the block ends rc 0 with nothing verified, reproduced in the skill's documented executors), ARCH11-1 (MEDIUM, translated `OK` fails a good release), and LOW/INFO SEC11-2, SEC11-3, XP11-1, BCI11-2, REL11-1, HP11-1,
UP11-1, QE11-1, DOC11-1. SEC10-3 part (a) (the warning's range reads as all 22 pages) was not folded and stays open. The residual
rows from earlier rounds are linked to #7575, #7576, #7579, #239 and #7595 or deferred to the newly filed #7614, #7615 and #7616.

**Process deviations.** One release-deploy run downloaded the 57 MB v0.15.0 archive once (gh fetches the missing files even when
it refuses an existing one), against the brief's no-large-downloads limit; no other reviewer reported downloading it (not otherwise verifiable). During the round, two
untracked `gateway/*.coverdata` files appeared in the worktree from a process outside this review; no reviewer created or removed them.

## 12. Gate 8 round 5 addendum: the freeze (workflow-orchestrator, reviewed `685cbc7211..39fdc69d99`)

**Why a freeze.** Rounds 2-4 each hardened the release skill's hand-run Phase 4 verify block, which is outside #7529's accepted scope
(the agent-bundle script's verification), and each round's hardening produced the next round's findings: UP9-1, then REL10-1, UP10-1
and UP10-3, then SEC11-1 (HIGH), ARCH11-1, BCI11-2, REL11-1, HP11-1 and UP11-1.

**The ruling.** A non-author adjudicator (enterprise-architect, 2026-11-12; Gate 7 separation, Test 2 scope change) ruled as follows,
recorded at `<scratch>/gov-7529/gate7-adjudication-r5.md` (sha256 `446da2144e9f…`):
- The block, in both copies, goes back to its round-1 (`50a01435b6`) state: origin/dev's block plus only the `SIGNER_REPO`
  assignment (its comment on its own line above it, DOC9-3) and the two exact `--certificate-identity` lines.
- The "Tighten the identity regex" paragraph stays deleted (UP8-3).
- SEC11-1 is withdrawn because the construct it describes was removed.
- The design content moves to the new issue #7630. The behaviours the revert brings back (UP9-1, C8-6, ARCH9-3 and UP10-3) are
  origin/dev's, are recorded as pre-existing, and are deferred to #7630. C8-6 was closed in round 2 and is reopened by the freeze.
- The round-4 partner-flow and test residuals (SEC11-2, SEC11-3, XP11-1, QE11-1 and DOC11-1) are linked to #7614
  (comment `https://github.com/DevNullLtd/Yuzu/issues/7614#issuecomment-6829256595`).
- Both issue numbers were supplied by the senior and checked read-only by the orchestrator with `gh issue view` and `gh api`. #7630
  is open, labelled bug, P2, security, governance-deferred and needs-triage, and its body names all 11 ids. The #7614 comment names
  all 5 linked ids.

**The revert, as a diff against origin/dev.** It is identical in both copies, and the Phase 4 section is byte-identical across
them (sha256 `d8783dfb8bc2…`). Against round 1, the only differences are the DOC9-3 comment move and the deleted paragraph.

```diff
-# cosign: verify the keyless signature on SHA256SUMS + both images
+# cosign: verify the keyless signature on SHA256SUMS + both images, with the EXACT
+# tag-bound identity (never a wildcard). Signer = the repo that ran release.yml.
+# Tr3kkR/Yuzu only for releases <= 0.13.x
+SIGNER_REPO=DevNullLtd/Yuzu
 if command -v cosign >/dev/null 2>&1; then
   cosign verify-blob \
     --bundle SHA256SUMS.sigstore \
-    --certificate-identity-regexp '.*' \
+    --certificate-identity "https://github.com/$SIGNER_REPO/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
 …
     cosign verify \
-      --certificate-identity-regexp '.*' \
+      --certificate-identity "https://github.com/$SIGNER_REPO/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
 …
-**Tighten the identity regex for an auditor-grade check** (optional but recommended …) …
```

The same commit also adds two test assertions for the macOS gating sentence (SEC10-1). It also changes the warning and the changelog
fragment to read "18 of the 22" pages, with the other 4 carrying no cosign command (SEC10-3 part (a)).

**Who re-reviewed it, and what they ran.** Five reviewers: docs-writer, security-guardian, release-deploy, quality-engineer and
consistency-auditor. The worktree's `git status` was clean before and after the round.
- **The two mandatory assertions.** Four reviewers (docs-writer, security-guardian, release-deploy, consistency-auditor) found both
  assertions PASS, independently of each other:
  - `git grep -n certificate-identity-regexp -- .claude/skills .codex/skills` gives exactly one hit per copy, at :245. That hit is the
    failure-table sentence "Never widen the check to a `--certificate-identity-regexp`"; neither hit is inside Phase 4.
  - The block's diff against origin/dev is the one shown above.
- **The removed constructs.** security-guardian and release-deploy grepped both copies for every round 2-4 construct and found none.
  consistency-auditor grepped the whole tree for prose describing that hardening and also found none.
- **Live runs.** All used real cosign v3.1.3 and downloaded `SHA256SUMS*` only; no archive, no installer, and no docker
  pull/run/create.
  - release-deploy ran the HEAD block and origin/dev's block against v0.15.0. Both ended rc 0, line for line the same: the bare
    `sha256sum -c` reported "34 listed files could not be read", verify-blob printed "Verified OK", both image verifies passed, and
    attestation was skipped by the gh 2.46 WARN.
  - Negative controls by release-deploy and security-guardian all ended rc 1: the Tr3kkR signer on v0.15.0, the v0.14.1 tag replayed
    against v0.15.0, and the wrong signer on the image.
  - The era comment checked out: v0.13.0 and v0.11.0-rc1 verify only as Tr3kkR/Yuzu, and v0.14.0-rc2 only as DevNullLtd/Yuzu.
- **The 18-of-22 wording.** Three reviewers (security-guardian, release-deploy, consistency-auditor) re-read all 22 release pages.
  18 carry `--certificate-identity-regexp '.*'` inside `cosign verify-blob`. The other 4 (v0.8.0-rc0, v0.8.1-rc0, v0.9.0, v0.10.0)
  carry no cosign command.
- **SEC10-1.** security-guardian and quality-engineer each built the mutant that cuts the gating sentence to "Clear quarantine", on
  scratch copies. Each found it is killed at test :681, while the same mutant passes the round-4 test file.
- **The tests.** `tests/test_build_agent_bundle_verify.py` ran 41 OK and `tests/test_release_agent_only.py` ran 2 OK, with no skips,
  in four reviewers' runs.
- **Not exercised.** The gh >= 2.50 attestation branch: local gh is 2.46. Its text is identical to origin/dev's.

**Outcome.** Round 5 caused no new findings. Closed or fixed:
- by the revert: SEC11-1, ARCH11-1, BCI11-2, REL11-1, HP11-1, UP11-1, UP10-1 and REL10-1;
- re-verified: ARCH-1 and UP8-3;
- fixed in this commit: DOC9-3, SEC10-1, and SEC10-3 part (a). SEC10-3's remaining part (c) stays linked to #239.

Still open:
- SEC-3 is held open and BLOCKING under the owner waiver.
- The COMP rows (COMP8-1, COMP9-3, COMP10-1..3 and COMP11-1..2) are written at commit time.

**Process notes.**
- quality-engineer and docs-writer returned their reports without writing the report file. The orchestrator transcribed both,
  marked as transcriptions.
- The reviewers recorded these for filing, none caused by round 5:
  - No test pins the release skills' exact identity, so an ARCH-1 regression would pass every test.
  - The "# Preflight: require cosign + gh 2.50+" comment contradicts the WARN-only preflight; this is origin/dev text, in the C8-6
    family.
  - A NICE wording polish at `release-verification.md:13-18`.
