# Resource Ledger — 48 h CRL validity (#6016 PR 4d)

Range: `dd36f791a..HEAD` (branch `feat/6016-crl-cadence-48h`)

## Summary

This diff introduces **no fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` / OpenSSL object / BCrypt
handle / allocated C string / mapped library / temp path / subprocess / thread / callback
context**. The C++ change is two `inline constexpr std::chrono::hours` constants, one
`static_assert`, and replacing two existing literals (`std::chrono::hours(24 * 7)` and `24 * 3600`)
with those constants. The `server.cpp` hunk is comment-only.

## Table 1 — new owned state

None. The constants are namespace-scope `constexpr` values with no storage that needs release.

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| CA key (`ScopedKeyZero`) in `CrlPublisher::publish` | `publish()` frame | Untouched; only the `Validity` end point passed to `pki::build_crl` changes. |
| `build` lambda capturing `root` / `ca_key` by reference | `publish()` frame | Untouched; used only inside the synchronous `CaStore::publish_next_crl` call. |
| `CaStore::publish_next_crl` table lock (`SHARE ROW EXCLUSIVE`) | PG transaction | Untouched; the call rate rises from about once per six days to about once a day on a quiet fleet. |

## Tests

The new and changed test code adds only locals: a `CrlPublisher` returned by value from the
`publisher_at` lambda (guaranteed elision, `now_fn` captures a `time_point` by value; `store`,
`metrics` and `kp` outlive every publisher), an `epoch_to_tp` captureless lambda, and a
`decide_with` lambda used only inside the test case. Each case clones its own database from the
`crl_publisher_tpl` template, so there is no shared hardcoded name between concurrent runners.
