# crypto-library-dashboard.8IQ4Df — commit SHA map (authorship rewrite)

The run ledger `crypto-library-dashboard.8IQ4Df.jsonl` cites the branch commits by their
ORIGINAL SHAs in `commit_range`, `reviewed_at_sha` and free text. Those commits were authored under a
local-only address no GitHub account owns, so the CLA check on
PR #6056 could not match a signer. On 2026-10-18, with the operator's explicit approval, the 11
branch commits were re-authored (author and committer only) as
`liamsomerville <8363579+liamsomerville@users.noreply.github.com>` with `git filter-branch
--env-filter` over `origin/dev..HEAD`, and force-pushed with lease.

Nothing else changed: each rewritten commit has the SAME tree as the original (column 3), and
the merge commit keeps the same `origin/dev` parent. The ledger rows are left as written
(append-only); read every original SHA in them through this table. Verify a row with
`git rev-parse <new>^{tree}`.

| Original SHA | Rewritten SHA | Tree (identical for both) |
|---|---|---|
| `c29ed8091f5292db8686cea75829394ee13d8639` | `8b53bdf428369e4af49984be89d720b0717998d8` | `fc6348ece249731492b602785c2779f59aee95d9` |
| `b012b0521f90437954e7c5394c75c740e9590318` | `4c94a99964ea43f4b0d0f96d3b139558b6d0ecc6` | `f49089082dd1366f4cfde03444bd96fb7c16c1fa` |
| `f0ae9987a5606deb76bd7b4901cf933f5e12276b` | `0e4907c463afd26a0856cbd9cb135c4bd12ed96c` | `8f63c31fc47ed574d0583a377ecc466b14c236fa` |
| `54fc956fa968ad2e09a1b020363000ef3b541d8a` | `1698b2ad74b282a72d85aefcec33ad60c71c6cfa` | `5d7801c3621bd54f1b4fae1bfe46533f7d133d73` |
| `ad1aeecb22fb7cf4993b1cc9cc1770aa2abc9a9e` | `162144b1ff9f5434ea89f1eeb98cf58684e613f1` | `441e797c2f2e20f429e36bd8690be77d7ac7f471` |
| `10b1f54bd7c62e0c87c5750b61e528cf9e4bf619` | `0e670a0c42548de10b93615aa9baca71fd3fe1c2` | `4c1830da509522111bd950f5ae191cd40387aa24` |
| `131204feed349916ecb43f56e6689662d97b7f6f` | `c0f0a317ebd7be8879f7f175c7f6f8746528727b` | `2814b02163d91b4868b799da275fd9d221f71df2` |
| `06850d6cf5e6bd54cd33bd014e727609d4bfed76` | `d8fece8831a560be5e5489b2312f81c9250828fd` | `67ef492f99328bc7bf57b5c7f9e7791d423ee296` |
| `24b9c22fc2ddc532298d4b3ec00e016267bf6b91` | `445b00c2f7afe9fcea2d5a24c561823a2dfc1355` | `3d7fefa24127612ed68cfc4dfb68167f24ba5f1f` |
| `7a4e8018718aadba6809c9cbf6ae7dd30373a3ee` | `159e4c9f34689ffb853a9cb361ba1910b7004e8c` | `e14b0f07f4460f00405ac0df76c9c0fad10fb038` |
| `27b035259a86117e41ec620e8ea1fba75d49486e` | `a809fb49a209ba9fddbaa261062fdc2a29deb50f` | `252c13bdc3dc3599a8acd9a79f10ddaef48d2ffe` |
