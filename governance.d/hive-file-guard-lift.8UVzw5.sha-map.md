# hive-file-guard-lift.8UVzw5 -- commit SHA map (replay onto a newer dev head)

The run ledgers `hive-file-guard-lift.qBtoDe.jsonl` (first run) and `hive-file-guard-lift.8UVzw5.jsonl`
(second run) cite the gated commits by the SHAs they had before the branch was raised: in `commit_range`,
`reviewed_at_sha` and free text. On 2026-10-21, before the branch was raised, the 16 commits were replayed
one by one with `git cherry-pick` onto the then-current `dev` (8f88367a3); they had been built on `dev` 34db683fa. No merge, no squash, no amend: each replayed commit keeps its author, date and
message, and the originals were not rewritten.

Each replayed commit carries the SAME patch as its original: `git range-diff 34db683fa..<original tip>
8f88367a3..<replayed tip>` pairs all 16 as identical, and the patch id in column 3 is the same for both
commits. The ledger rows are left as written (append-only); read every original SHA in them through this
table. Verify a row with `git show <replayed SHA> | git patch-id --stable`.

| Original SHA | Replayed SHA | Patch id (identical for both) | Subject |
|---|---|---|---|
| `dbb6c1298ceb43de281e705661239e9844dabd5d` | `f38a4460a1bcbf1f1baa6d47be74235af1d5c0cf` | `97e2770f5549c94d376254e80d1ce6d9c11a7a2f` | refactor(privacy_permissions): lift the offline-hive file guard into agents/shared so the registry plugin can reuse it |
| `9979c51071597ff60a0ec03ded3a68c2b4ff8c65` | `6006fe999cf947c607da11cf29dbae3e199f2ed3` | `2e6d9cac08baa22e23270c29d4a9bd48ca662136` | gate-fix: hive-file guard lift (comment trims and the Loaded-by entries naming the shared guard files), carried from e330f2592 and 3d4f0e738 |
| `db593bbfb49ab3b64f7586e11d12871a51095643` | `776648ce94eeb713ff72e0113f08598b9c7cf74d` | `36748778465586d14c3e7854616531350baa6f13` | docs(win_hive_file_guard): name only the current consumer in the header |
| `1451c10baa9645940b767d930ba7c4fcbf66cdd5` | `8cd30a674acf780de91557c9ddc8556f4c2c8eae` | `e0b0c376d8bb9c7dd24ad248acdeec3b2b0d1966` | gate-fix: code-review r1 (wrap the lines the lift left over 100 columns, drop four includes privacy_permissions_win.cpp no longer uses) |
| `2ee8520216ea48077a6db1242da4e4a6ca07671f` | `576f367b9f30558148f5d85104fa33b187efc585` | `2af3582e06ef9d600b6d75cbf0cd72ebbf4ec7f5` | gate-fix: governance r1 (guard usage contract sentence, UniqueHandle sentinel doc, probe header names the handle-less sources, test header wrap) |
| `dc7a748bef7c1d0be9415960d736f08fb632485b` | `730c6a7f9951d2730359aa72e92396ae951a0f31` | `da794207b8ac0df25606e96625b298a7cec41258` | gate-fix: governance run on the final head (banner wording, wrapped comments, README measured note) |
| `938e20c0c4600ce4a2e00d08ed2549010fa2d2d9` | `e875bcd41f96908b50bf15b1b510ec059d3388cb` | `7b89dc9bf49185841fdb5d4bf413b74c34545dcb` | governance: run ledger and resource ledger for the hive-file guard lift |
| `3fa7fd7bc8eb9b0218e295b00417abd49f915893` | `febae79c9925542a039c22d50f53a5ad5c04ba3b` | `2327864750286a9406156b09b35f063f2c482a24` | governance: point the duplicated-routed-rows finding at the PR that removes the duplicates |
| `bbbc757c47011d1bb1570c064821afaa14d7a0cd` | `e409d1785e045e93eea0f352ef649a7df68b3024` | `81deca938a30a1efda21cc689d94870dc5b72807` | gate-fix: ponytail r2 (the test-only probe aliases leave the production translation unit) |
| `a47bcea8ac2f6918f70757d08f1247b84d2d60f7` | `67847f12936c7550f3a0c89e3ef14aeb11476048` | `a512226fd0310b970087761db488bb0d3eba1a5c` | gate-fix: code-review r2 (the deadline test counts the drive query; depth and size limits pinned by value; one shared name respelled) |
| `d2d2dba27c8b3a54abef366c41ac7bdf3ec1ed7d` | `ea2ac38f3a263a13316ff4357a47288ed06510f4` | `8b4e98c3f49a08a5bc979b6971acbda42a425cf8` | gate-fix: adversarial-review r2 (the fake probe records every question and its paths; one test pins a stock hive's exact sequence) |
| `079b7faa6347b966bc0341d05e11ed4d259f795d` | `1744dfb9b964c55123fa64c89d424f7a0d416953` | `6530a6393a8be62d83c5cfec08cd8c3401ccdb8f` | gate-fix: governance r2 (guard seams pinned by tests, verdict hooks [[nodiscard]], the namespace directive moves into the tests, header comments corrected) |
| `f289c1b9427460c47da5ae319d84226ac19a9255` | `e1b226f21224cfb081babddcb92c8638fdd18998` | `5ae8fe485e7d2312f90bd325df33ab3451b2f9e7` | gate-fix: governance r2 (one more malformed path shape) |
| `ea254770f6726492b013d0ee7ae9c8b928899082` | `cb491cfe166bf9eabaf0704c2206acef408e3432` | `4e93ee00056180cb8b51ee8fa0da905377f8c55d` | gate-fix: governance r2 re-review (more guard seams pinned, a refusal with a failed unload reported, comments made exact) |
| `8d253f4bc5344e4b90b1bbff849ec2fa28b16777` | `3bb083a7b5a3547d659e18ae58dba363403ca36b` | `436bf700ca36a31ef5a6d649c0eb7b567e8dfb22` | docs(privacy_permissions): the Windows Measured cell names the native run it rests on; hive_stat_failed and the shared headers described |
| `40e1f7c1dfa2e45a59a934088b3f24952b1598cc` | `2a6ae2b8463c0bc0d9b344c756327e8a85fb6077` | `32376b9854a2a6c05eb16d9979a2700babe63d55` | governance: second run ledger and resource ledger for the hive-file guard lift |
