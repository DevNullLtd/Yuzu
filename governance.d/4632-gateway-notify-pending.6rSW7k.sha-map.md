# Commit SHA map for the #4632 PR-1a history rewrite

Companion to `governance.d/4632-gateway-notify-pending.6rSW7k.jsonl` (same stem). Written with the ledger closure; recorded 2026-10-12.

## Why this exists

The commit history was rewritten before the first push to correct commit message and record wording. Git gives a rewritten commit and every commit above it a new SHA, so ledger rows raised before the rewrite, and the SHAs in the evidence record `docs/security-reviews/gateway-notify-pending-store-2026-10-05.md`, cite the OLD SHAs. This table resolves each of them: it maps the earlier SHAs cited by older ledger rows to the current ones. The pre-rewrite objects are not reachable from the pull request, so for a reviewer this table is the only resolution. Structured ledger fields, authors, dates and trailers are unchanged.

## What was checked

- Range: `54dd63c8a93060acf6783163cb343cb23095e40b..d0be68da4f527327a311d0cd480f7c1f2d121d85`, 118 commits (one of them the merge of `origin/dev`, preserved as a merge).
- 79 of the 118 commits have a new SHA; 39 are unchanged (the commits below the first reworded body).
- Tree equality: for every one of the 118 pairs the old and the new commit have the IDENTICAL tree (`git rev-parse OLD^{tree}` equals `git rev-parse NEW^{tree}`, checked for all pairs on 2026-10-12). The final tree `29806cde400559a378d7c6c6a3af05e858e0a904` equals the tree of the pre-rewrite head, so no file content changed; only commit messages and the SHAs that follow from them.
- Authors, dates and the `Co-Authored-By` trailers are unchanged.

## The seven reworded commit bodies

| old | new | subject |
|---|---|---|
| `2c947a4d8` | `cbe1b0a3e` | test(gateway): red test for a local encode exception feeding the breaker |
| `309a3dbda` | `a9f0efcab` | fix(gateway): a local encode exception never feeds the circuit breaker (#4632) |
| `30b9987be` | `ecbbbf5b3` | test(gateway): red test for a server-rejected agent id counted as an upstream failure |
| `a352a7e39` | `edf9203bc` | fix(gateway): bound the agent id at the edge and treat caller-fault statuses as answers (#4632) |
| `b24e17146` | `aacdd9d71` | fix(gateway): rate-limit the warnings a rejected registration can trigger (#4632) |
| `8074ace8f` | `fc4c53d34` | test(prometheus): YuzuGatewayUpstreamEncodeErrors needs 10 increases in 10m (red) (#4632) |
| `6f66c0f11` | `2ca28bc2e` | fix(alerts): YuzuGatewayUpstreamEncodeErrors fires at 10 increases in 10m (#4632) |

Every commit above the first of these (`2c947a4d8`, now `cbe1b0a3e`) also has a new SHA, because a SHA covers its parent.

## Other SHAs that rows and the evidence record cite

- `d2fe78f16` (the pre-rebase adversarial-review head) and `98c715d74` (the pre-rebase rig head) are on a local ref only. Their post-rebase counterparts are `50461a9cf` and `e22b48444` (matched by subject, and each pair also has an identical `git patch-id --stable`: `5a579504...` for `d2fe78f16` and `50461a9cf`, `a173c1dc...` for `98c715d74` and `e22b48444`, checked 2026-10-12). Both counterparts are unchanged by the rewrite.
- `f79ba8d13` is the old merge base (before the merge of `origin/dev`); the current merge base is `54dd63c8a93060acf6783163cb343cb23095e40b`. Ledger rows raised before the merge carry the range `f79ba8d13..dafc4821b`; `dafc4821b` is now `3bca31d7e`.
- `492b40aaa` (the rig control build, an `origin/dev` commit) is outside the range and unaffected.
- The `Tested SHAs` ranges of the evidence record: `b38549ca7..93295f030` is unchanged (both ends); `93295f030..38071062c` is now `93295f030..b52dea46a`; `1bcfc15a2..bc7a3bdac` is now `a90f0c54a..db8fa9888`.

## Full table, oldest first

Status `same` means the SHA did not change.

| old | new | status | subject |
|---|---|---|---|
| `336ee6b4b` | `336ee6b4b` | same | test(gateway): red tests for yuzu_gw_notify_queue |
| `c1bf8160e` | `c1bf8160e` | same | feat(gateway): add yuzu_gw_notify_queue |
| `5731ac034` | `5731ac034` | same | test(gateway): red telemetry wiring for notify_queue gauges |
| `7ee9aadf1` | `7ee9aadf1` | same | feat(gateway): notify pending and in-flight gauges |
| `e40cec9f4` | `e40cec9f4` | same | test(gateway): red wiring tests for the pending store |
| `52be21098` | `52be21098` | same | fix(gateway): hold stream-status notifications instead of dropping them (#4632) |
| `52ec803af` | `52ec803af` | same | test(gateway): red replay-fairness test |
| `3e9a43c31` | `3e9a43c31` | same | fix(gateway): reserve one notify slot while a replay is active |
| `292c824ad` | `292c824ad` | same | test(gateway): red probe tests |
| `ba57187d6` | `ba57187d6` | same | feat(gateway): a held notification probes a half-open breaker |
| `13b25e98d` | `13b25e98d` | same | docs(gateway): pending notifications, gauges, runbook (#4632) |
| `9416e2660` | `9416e2660` | same | docs(changelog): #4632 gateway notify pending fragment |
| `e22b48444` | `e22b48444` | same | docs(gateway): correct the replay pre-check comment, a held reannounce is no longer dropped |
| `d71cec801` | `d71cec801` | same | docs(gateway): fill in the #4632 rig measurements |
| `b8800362f` | `b8800362f` | same | docs(gateway): record the failing-probe and old-build contrast measurements (#4632) |
| `6bdc57f89` | `6bdc57f89` | same | docs(gateway): correct the run count in the #4632 probe evidence |
| `4bb5464a6` | `4bb5464a6` | same | docs(gateway): record the backoff cap, RPC-error, killed-probe and collision measurements (#4632) |
| `50461a9cf` | `50461a9cf` | same | docs(gateway): record the TLS measurements for the pending notification store (#4632) |
| `4030c0a21` | `4030c0a21` | same | docs(gateway): correct three comments that contradicted the notify probe code (#4632) |
| `a6fe8e307` | `a6fe8e307` | same | test(gateway): red test for the closed notify_dropped reason set |
| `2fe5b52a0` | `2fe5b52a0` | same | fix(gateway): fold out-of-set notify_dropped reasons into a pre-seeded unknown series (#4632) |
| `d23cc32cd` | `d23cc32cd` | same | docs(gateway): notify_dropped closed label set now includes unknown (#4632) |
| `b38549ca7` | `b38549ca7` | same | docs(gateway): record the CSR, TLS-proof and management-load measurements (#4632) |
| `31b4a8f00` | `31b4a8f00` | same | test(gateway): red test for a poison head peer_addr (#4632) |
| `4f6fdb2b7` | `4f6fdb2b7` | same | fix(gateway): sanitise and cap the peer_addr of stream-status notifications (#4632) |
| `c97d0fcb8` | `c97d0fcb8` | same | test(gateway): cover a probe result arriving while the breaker is open (#4632) |
| `23aeafaf7` | `23aeafaf7` | same | test(gateway): tighten the replay reserve, label-set and queue diagnostics (#4632) |
| `65b6c6af9` | `65b6c6af9` | same | fix(gateway): redact the notify cast and log a killed probe worker (#4632) |
| `9e6b99afd` | `9e6b99afd` | same | docs(gateway): correct comments about the probe, the cap and the pseudo-seeds (#4632) |
| `b7d7e8e02` | `b7d7e8e02` | same | test(gateway): use a documentation hostname in the peer_addr table (#4632) |
| `d9919852b` | `d9919852b` | same | docs(gateway): runbook rows for a repeating probe failure and held notifications (#4632) |
| `c3c8d639c` | `c3c8d639c` | same | docs(gateway): correct the cold-start, burst-peak, TLS and drip wording (#4632) |
| `c80aaa75a` | `c80aaa75a` | same | docs(server-admin): say at_capacity is a loss at admission (#4632) |
| `911c37462` | `911c37462` | same | docs(changelog): tighten the #4632 fragment (open breaker, memory only, peer address) |
| `8c59d7d22` | `8c59d7d22` | same | docs(upgrading): add the gateway upgrade note for held stream-status notifications (#4632) |
| `711854302` | `711854302` | same | docs(adr-2002): dated update for held stream-status notifications (#4632) |
| `c91ee1491` | `c91ee1491` | same | docs(security-reviews): evidence record for the held stream-status notification store (#4632) |
| `553ba05f9` | `553ba05f9` | same | docs(gateway): mirror the final notify metric HELP wording in the manual (#4632) |
| `93295f030` | `93295f030` | same | docs(observability): mirror the final notify metric HELP wording (#4632) |
| `2c947a4d8` | `cbe1b0a3e` | new | test(gateway): red test for a local encode exception feeding the breaker |
| `309a3dbda` | `a9f0efcab` | new | fix(gateway): a local encode exception never feeds the circuit breaker (#4632) |
| `27f91c720` | `9e9f97517` | new | test(gateway): red test for a non-UTF-8 cluster_id |
| `9e239f72e` | `a8b000776` | new | fix(gateway): convert cluster_id with the unicode conversion and refuse an unrepresentable value (#4632) |
| `733bf6854` | `ccad9711f` | new | fix(gateway): copy the sanitised peer address out of the header block (#4632) |
| `7387664ac` | `89cfa219c` | new | fix(gateway): log text from agents through log_text and warn when the edge replaces a peer address (#4632) |
| `5a4720ead` | `8285b1d6c` | new | fix(gateway): validate circuit_breaker_reset_timeout_ms (#4632) |
| `856609051` | `b834cfdeb` | new | test(gateway): close the Gate 8 test gaps (#4632) |
| `272de1ba9` | `2042674ce` | new | test(gateway): the application refuses to start with an unrepresentable cluster_id (#4632) |
| `524201ea6` | `2f8d199d0` | new | test(gateway): a replayed registration that cannot be encoded leaves the breaker alone (#4632) |
| `ff82c35ee` | `2556e5fd9` | new | test(gateway): make the cluster_id start test independent of the node's cookie (#4632) |
| `38071062c` | `b52dea46a` | new | docs(gateway): plain dashes in the breaker timeout config comment (#4632) |
| `cd2c2c593` | `15fb85b83` | new | docs(gateway): name the killed-probe WARN in the runbook (#4632) |
| `5e228fe6f` | `2a9a06719` | new | docs(gateway): describe the redacted notify cast and status report (#4632) |
| `80fadf2be` | `7f3ecf7e8` | new | docs(gateway): state the upstream-port identity and TLS 1.3 limits plainly (#4632) |
| `db89c9a6a` | `91266e18c` | new | docs(gateway): describe the peer address sanitiser and the 5 s worker timeout (#4632) |
| `745833c0e` | `8703ba771` | new | docs(security-reviews): record the Gate 8 findings, ledger glob and rig build base (#4632) |
| `3d6171a74` | `63f83c393` | new | docs(gateway): a local encode exception never feeds the breaker (#4632) |
| `4d1d02f98` | `7761eadbb` | new | docs(gateway): breaker reset timeout range and cluster_id conversion (#4632) |
| `e2a00b9c2` | `773d6d058` | new | docs(upgrading): add the #4632 tunables and behaviour changes to the gateway note |
| `e7b9192ad` | `c60df5165` | new | docs(changelog): cap note and a security fragment for the encode-exception fix (#4632) |
| `ab54f5be8` | `cc1f64cfd` | new | docs(security-reviews): mutation checks, round 2 results and updated residuals for #4632 |
| `1bcfc15a2` | `a90f0c54a` | new | docs(adr-2002): note that the local encode exception no longer blocks the queue (#4632) |
| `30b9987be` | `ecbbbf5b3` | new | test(gateway): red test for a server-rejected agent id counted as an upstream failure |
| `a352a7e39` | `edf9203bc` | new | fix(gateway): bound the agent id at the edge and treat caller-fault statuses as answers (#4632) |
| `b795d78a4` | `c176c983e` | new | test(gateway): red tests for cluster_id from the environment under both native encodings |
| `2f78eb73d` | `1ec6a30cc` | new | fix(gateway): interpret the cluster_id environment text in the native encoding (#4632) |
| `b24e17146` | `aacdd9d71` | new | fix(gateway): rate-limit the warnings a rejected registration can trigger (#4632) |
| `7185a5dbf` | `97387ae81` | new | feat(gateway): count local encode exceptions under their own rpc_errors code (#4632) |
| `afffa6b43` | `f0fb2018f` | new | fix(gateway): apply log_text to the remaining agent-controlled log text (#4632) |
| `452302012` | `b1682b885` | new | fix(gateway): validate the breaker thresholds and keep the reset timeouts consistent (#4632) |
| `5f4ef66f3` | `ae7b4a008` | new | test(gateway): close the remaining Gate 8 test gaps (#4632) |
| `bc7a3bdac` | `db8fa9888` | new | test(gateway): keep the cluster_id test comments ASCII (#4632) |
| `432f8d61e` | `4cc05890e` | new | docs(gateway): scope the eviction wording to the half open probe and fix runbook and Known limits truth items (#4632) |
| `9e65b323c` | `c74c25c2e` | new | docs(gateway): say plainly that the sanitised peer address is not sent in the registration request (#4632) |
| `3ffb25c3d` | `6839fe4b8` | new | docs(changelog): lead the security fragment with the control and soften the trigger detail (#4632) |
| `fe8b08897` | `5459c9a6e` | new | docs(upgrading): lead the #4632 gateway upgrade with the boot refusal and list behaviour changes as bullets |
| `a750161e1` | `f435e76ac` | new | docs(security-reviews): record the round-2 re-review findings, ranges and mutants for #4632 |
| `2e3fc6c53` | `287315d95` | new | docs(adr-2002): dated note for the agent id bound and the caller-fault status classification (#4632) |
| `7fe75c929` | `08332c97b` | new | docs(gateway): agent id edge bound, request-fault statuses, encode label, rate-limited warnings and breaker validation (#4632) |
| `d7586b4b4` | `4011ed08d` | new | docs(gateway): cluster_id locale and per-source rules, refusal runbook rows, upgrade note and fragment (#4632) |
| `4717a6907` | `b6c43fed9` | new | docs(security-reviews): record fix round 3 results, mutants, residuals and follow-ups for #4632 |
| `0aae07381` | `a79752a63` | new | test(gateway): round 4 red tests for edge refusal counter, pre-seeded error codes, clamp wording (#4632) |
| `6ea1f31cc` | `e2c96cc7e` | new | fix(gateway): count edge-refused Registers, pre-seed local error codes, alert on encode errors (#4632) |
| `311d96f02` | `1c669c182` | new | docs(gateway): correct the neutral-status header, the reset-range test comment and the cluster_id binary note (#4632) |
| `8e5ccea0c` | `c2e9bf4d1` | new | style(tests): plain ASCII in the new promtool case comments (#4632) |
| `772d5a048` | `ed60201f9` | new | docs(gateway): round 4 wording, alert and counter documentation, supervisor behaviour (#4632) |
| `b9b6bed82` | `16f8924b1` | new | docs(security-reviews): round 4 corrections to the #4632 evidence record |
| `8074ace8f` | `fc4c53d34` | new | test(prometheus): YuzuGatewayUpstreamEncodeErrors needs 10 increases in 10m (red) (#4632) |
| `6f66c0f11` | `2ca28bc2e` | new | fix(alerts): YuzuGatewayUpstreamEncodeErrors fires at 10 increases in 10m (#4632) |
| `eade956a4` | `72de40f48` | new | docs(gateway): reword the 4 MiB bound and heartbeat encode comments (#4632) |
| `e2a269050` | `5019a3d54` | new | test(gateway): pin log_text at the remaining yuzu_gw_upstream log sites (#4632) |
| `bc75af667` | `01fc49f03` | new | test(gateway): an out-of-range circuit breaker cap is never reported as the operator's (#4632) |
| `1857e06bf` | `967080fc7` | new | test(gateway): the server drift check fails when the server tree is there but unreadable (#4632) |
| `5d0a52ee0` | `48da637b3` | new | docs(gateway): the register bound test header states the replay FAILED_PRECONDITION exception (#4632) |
| `0b77fd0f5` | `b2710b159` | new | docs(alerts): the encode alert threshold is about ten, increase() extrapolates (#4632) |
| `e4362e1c3` | `a3951e37a` | new | test(gateway): wait for the registry to drop the replay test agent before teardown ends (#4632) |
| `15de7788d` | `3a1005eb9` | new | docs(gateway): round 5 corrections for the encode alert threshold, breaker feeding and pre-seeding (#4632) |
| `52a46e24f` | `43ae778c8` | new | docs(gateway): the encode alert threshold is about ten, increase() is extrapolated (#4632) |
| `d07cc79c9` | `55620acf6` | new | test(gateway): reword the oversize-request comment to the can-still-arrive form (#4632) |
| `fc7f4c9e3` | `aae7f96ed` | new | docs(gateway): say about ten for the encode alert threshold everywhere (#4632) |
| `cd4b97a0b` | `85490b8e1` | new | docs(alerts): state the encode alert's sensitivity and scrape-interval caveat (#4632) |
| `dafc4821b` | `3bca31d7e` | new | test(gateway): bound the drift-check throwaway walk at its own root so a TMPDIR inside a checkout cannot escape (#4632) |
| `002b7e806` | `080f0e944` | new | test(gateway): trim notify queue examples to the randomized model plus seven spec examples (#4632) |
| `d0c6bdb45` | `973dddfa7` | new | test(gateway): drop redundant notify_pending tests with a covering test (#4632) |
| `fd2f67e38` | `ad49f687f` | new | test(gateway): share the logger capture and upstream fixture helpers (#4632) |
| `acff4e1b5` | `cf234600d` | new | test(gateway): shorten the narrative headers of the log-text, cluster_id and alert tests (#4632) |
| `3614f8517` | `9fdaf1b1a` | new | test(gateway): fold duplicated cases in the telemetry, peer_addr, register_bound and related tests (#4632) |
| `d28935c66` | `dc0063b23` | new | test(gateway): remove two timing dependencies from the register_bound and heartbeat_binding tests (#4632) |
| `5d9b58e28` | `1e6bde168` | new | Merge origin/dev into fix/4632-pr1a |
| `4e4e7b54f` | `143ef8d3f` | new | docs(gateway): reword the #4632 rollback sentence so the restart-advice lint does not read it as unconditional advice |
| `17f5f7ac0` | `cfd26efef` | new | fix(gateway): a newer notification for the half-open probe's own key replaces it at the cap instead of being dropped (#4632) |
| `547fce8d3` | `f47b6d65f` | new | test(gateway): restore four pins dropped by the test trims and close the log capture helper gap (#4632) |
| `8b34b1417` | `4e8baef91` | new | docs(gateway): correct comment wording for the probe key, test headers and the queue mutant claim (#4632) |
| `33b501821` | `fed9f9d4a` | new | test(prometheus): restore the exp_samples line the dev merge dropped from the TLS handshake case (#4632) |
| `1cc45915c` | `2a3a6de5c` | new | docs(gateway): align the runbook, probe key, memory, rollback and matrix text with the shipped behaviour (#4632) |
| `4f4de43dd` | `bcec6d40a` | new | docs(gateway): describe the pre-fix breaker weakness at class level in every public artifact (#4632) |
| `922f93612` | `48b7ed8da` | new | test(gateway): pin the ESC byte too in the Register peer-address warning line test (#4632) |
| `1a8028190` | `d0be68da4` | new | docs(gateway): class-level wording for the pre-fix weakness and the Gate 8 round 8 truth fixes (#4632) |

## Full SHAs of the 79 changed commits

Format: `old new`, 40 hex digits each.

```
2c947a4d84195704211e8579abdb02d2a162a632 cbe1b0a3e964771ee7e81fa3992048b52c64948f
309a3dbda554e9cb27c9df3c89b702e37c5f1f79 a9f0efcabd8e374f49c538fb616e5af6e69806b9
27f91c720a49f4ef151582eb15429a6359256505 9e9f97517cf197a55c6c7c7c30877b7da6b2b341
9e239f72e98faea5c645f2f6e79939b9bbb68c31 a8b000776869b53441fc1774505cf6dd0f10ff55
733bf6854b885c1d75c22ea758ed662743ea49ac ccad9711fe49b14ad964b732a9ab51009514a2ad
7387664ac0adc9bcdaba1e69786a9b77c70659b6 89cfa219cc1f55fc7dc607cd5855aee1d3e2bb9c
5a4720ead58b3f46839fa6900f6965ae3f6d7b61 8285b1d6c19d4ff7a5db417a3ec02b99fa4ca7e1
856609051177c0cc7b78d12bbc6f0bab94df2418 b834cfdebf1f77cfd8e3666292a4999b6affbc15
272de1ba97faf6f8d1ac5e8e42c6e79c833038f2 2042674ceeb510e031857d99d058d89ccfb58a79
524201ea62908de65d275145395fe61618867dc9 2f8d199d08ba52a4b8a2747a4703b8aa43bcf33a
ff82c35ee01d0971217edcdeadbf67c6dfdb8089 2556e5fd9a02ab50abc1a3cecddd2245205c161c
38071062cc169b94918bddb0258cc0f26b565220 b52dea46aa05181bea04ab886b381d7760ec4c2c
cd2c2c593c8946306d87e692fac0413ce317089d 15fb85b83692f797b18cbd5f16e13dd6ae7ee0a9
5e228fe6fb2c8d3d9d6279f81541b0325e0d91e2 2a9a067191de4b995a45974aaef8ea85780dd38e
80fadf2bea0b112ebe125e9efb3064ff47aeabbe 7f3ecf7e878c458d4f3797af9d75f8253c2bbb73
db89c9a6ad4b17f693ed8cc0392c3d95bc362436 91266e18c5730d6d50c5192f2e2992425986a706
745833c0e1fbb93fd917002194b2c69f364bfc1d 8703ba771a4537a40df6203ffc9caef48150c63e
3d6171a746b46fc3888b6903979f99e5e8c57592 63f83c3931f3783251938ef96f1e83420ee5c54d
4d1d02f9804d41b8c7e950a5486beea8ff43f723 7761eadbb0e2696a7316d9ffcd289824c6b66927
e2a00b9c20138fafaef55b64eea23567a5489f86 773d6d058b7591d24e1dbe0be92f9dea585a29b0
e7b9192ad66d95eeb85774146a9aa9f98caed17b c60df5165436de56b2e41563fe02708c6d0aca2d
ab54f5be8bda62949c58edeb93fe4df1e847a616 cc1f64cfd9ab250e0f4d056309e85ac59c2e0e92
1bcfc15a206e2c6a58a9f71d89705cb2390466a6 a90f0c54a731dc4e6317b7270d7c36c9f31c4366
30b9987bed2bfc79c2b3f20d2c9579c6d93dc0df ecbbbf5b39d6a95ad5d23ad3c339f5ebbb9bbff7
a352a7e39d0ec89f0965dfc3f31d0600969f8ff9 edf9203bc3461028076ca6f578a8835e6872bf20
b795d78a49ff5d7f19371ff3e7569d537951cd0d c176c983e246f09f07e632be8c9580634e7c81dd
2f78eb73d69f48e3acb62ed68077267d64e2a255 1ec6a30cc520e5e46701ff1e674645a817103898
b24e171465916635946a6dd9c3f0a647b79a7cf9 aacdd9d715e056f4060f50e6272bac270dfca2c4
7185a5dbf4d3bb33883ae4c992528b443fcd88c5 97387ae81830dd5e77b40c6ef6756ba1e51e09d1
afffa6b43af6130abead121dba3ba4f447736a05 f0fb2018f625771a7d10bc4397b781ee09149c71
452302012762f3a036b15933b6ac78b3e788e715 b1682b885e76d95eb872b057e05a191d8f19fe0a
5f4ef66f3e5e4c069c00ebd46d8747e408fe8cf7 ae7b4a008e64e4dbe5fa1c0ed75794cac26fc7cf
bc7a3bdac4e2eade5e6d78e8e4e39481eb17aa35 db8fa9888e97d4aa6d7a135de2a30058c0bf2292
432f8d61e19191c772dea91da3d6e0ec7a0dd1a8 4cc05890e0a8dbffb0d59feb58ccf30b5fe4f75d
9e65b323c204b7112f7d989f46fdb30e73b4f71e c74c25c2edbfa621e531c4a23aa0a8fbe9aaad61
3ffb25c3d26505671cacbf94a26dcd541471f3b2 6839fe4b88a46a9fed86bff39f3f19428c6d9bfe
fe8b0889774f882bff29a5421ca7aefafbdf1537 5459c9a6e5e97dd9accbfbe83bc55775859aad30
a750161e1129e737fa7ba9330b954996ee43c5ab f435e76aca9fcfe6679ca7ef2835a08655e36152
2e3fc6c53a4b5a7376165e9a4677d1e6e88742d7 287315d95344a592e8d8a03c5d6720129531d972
7fe75c929ca19710b13fed2f1805547cfa4425fa 08332c97b24edbf0a0bbea634325e3573b412bbe
d7586b4b42892ebf5a1540f76c7d6d48f63fe254 4011ed08d132139a557a311939876e3154c33266
4717a6907477d292b564dd3260f739658a315b89 b6c43fed995357851f202c4e261339cd6faa9684
0aae073816ee8167af612237217c01644e287946 a79752a635eb01c9c231639eaecb1335e7e81266
6ea1f31cccf1eadd8f3deb52bb759081f89f3736 e2c96cc7ee23685a954addad51dfb309837e4ae5
311d96f02d033350f59c4ea766c5f4253548e3e7 1c669c182258d651d60cc76ce3b20ff57a545c40
8e5ccea0c600cb577be7d9d02f747b0ebce7beb1 c2e9bf4d1dfce8cadb9280602ce51a9c585fdd09
772d5a048c6cabc242d0ad5f3d52ea7e3f42574b ed60201f92b8ea31faaef3fe31d17fb9eeddafbd
b9b6bed82ee0bdcf0ea0b3dc34fd739f9b1eef8b 16f8924b16e1ab061dc805f9431125bb43d7d4e6
8074ace8fa6c0666a73caa46ae64c5ba3214380b fc4c53d341b7601d31d39fa87a3d758ec78ae2c8
6f66c0f118ec3c8882b4579ebeaa20259c30f45e 2ca28bc2e72c61b128212201882f4159a7e7dfe2
eade956a4034cc8c5f6728b3c87794d5303b1885 72de40f48e6ecfcb3762d51fbef48e4ed222e021
e2a2690507802972999dd733346e4f887127d0f4 5019a3d545a9aa0a1d1cddfa442d9527cae86bef
bc75af6670856ace9d171348d3d31f59f5cd4565 01fc49f0377790d033b20aabe35a7187ce033e41
1857e06bfc4235468d1b33f26dae7ea29c386766 967080fc7528f5bd8f156a997c01bdada125277e
5d0a52ee00456b001db1830ae17cf3af8161b2a1 48da637b334b544a894521e46772786ca21b7a99
0b77fd0f57f961e888a1dcdb441139ff9c192dd9 b2710b1594e5db6a94036d54948138ec226b3424
e4362e1c38eaa36819c4b930af580295b4922dce a3951e37acd0fff28ac45c4721ec66fbf134d4c1
15de7788d3356838a0ed1af976b5e6b2b9506299 3a1005eb9da4cab02597e6189f699a93d5f4febd
52a46e24f966aff2ec67cd731ef77d9fa2c7ccb4 43ae778c8ffdac675dae0917f54a2e7fe9c4c869
d07cc79c9a2bb3151444d3518f8fff2c2c038647 55620acf6e419a9824746c121bd1f26e231bab5a
fc7f4c9e3fc3a05c79b28f417e19bb84a329ab16 aae7f96ed33e4493fa4ffeba534a75389e5eca82
cd4b97a0b9d855194fc2c90ab8e0203c189742c8 85490b8e1483cb88b1b1c307049e2fd94abb6d56
dafc4821bef645722bc196eac56fa584f1a03fd3 3bca31d7e34ba197665b208ce9998bd20a0d4b4f
002b7e80618d85b35dfbed7a149f515419eae3f2 080f0e94438a9dd89484c2d8eb337de77c5e7085
d0c6bdb4522009d3eb0c6db660a5deabd4a189c8 973dddfa7b9ad097cd93ddf08c667e74b9af33e0
fd2f67e38c3e6de2784b784d2325fbea600cc4c6 ad49f687fcccd81aea3891a7ea764f24d66717e1
acff4e1b548bb8e0ab717d0135a90be0b3c82380 cf234600d448b3c6d7c22dfe85c1e33ffe3f658b
3614f8517a764b63c2ec36bf1940dc04b4bf1961 9fdaf1b1a55fc822d70769e3d2b84639ac1170ca
d28935c662758c2d3b4687892f71a6cbc498f6a4 dc0063b23a8350b619ef5709e6eaa18b800ea67e
5d9b58e284125d7d1af117d18ff9a86b11946734 1e6bde1681111949e12850e85113856c1bd2cba0
4e4e7b54f32aeb42d896dc42746b9c9550381d59 143ef8d3f639f038e7c38a6d244020cf82367273
17f5f7ac0c28fffa0bd525f8494bac2a64babd0f cfd26efef1997ef5999a9993f91c038600553b2f
547fce8d3cb996ce041bffc7d2ffba1bf67822e0 f47b6d65f3e204388fd920dccf7b006e975405c1
8b34b141767454e7214297c69201eeae437849c1 4e8baef91584aa446d4f52553aa8feb9b5e4e38e
33b501821ae7d9a2a68b46113d4db0a186e4094a fed9f9d4a07dd95e0e4381928deaf0d4546a1c22
1cc45915c770af6df10b6d4ed1aca52bab5c7945 2a3a6de5c082f7d670def1249296c4bc6122341e
4f4de43ddc3b95a70825de9a063a80a6270201ff bcec6d40a05670d7256f9651b9731a2cdb379f35
922f936124d5152cd5550400fae1f5174d1d95be 48b7ed8da174d753a4a29f22e628818aeafb928c
1a8028190473ed9a5b3b9a8f178202d47e1a55a5 d0be68da4f527327a311d0cd480f7c1f2d121d85
```

Commits after `d0be68da4f527327a311d0cd480f7c1f2d121d85` were rewritten as well; the SHAs that the ledger and the evidence record cite for them are the current ones, and no map is kept for their earlier SHAs, which are cited nowhere. Structured ledger fields, authors, dates and trailers are unchanged.
