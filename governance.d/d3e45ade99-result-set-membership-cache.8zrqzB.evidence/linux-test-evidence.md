# Linux validation of the result-set cache

On 2026-11-21, Big Tam built Meson's normal GCC 15 Linux server test executable and exercised the checked-in Catch2 cases with PostgreSQL enabled. No alternate test executable or linker recipe was used.

| Source revision | Tests passed | Assertions | Exit |
|---|---:|---:|---:|
| a20119b06c | 87 | 2071 | 0 |
| 9e98085a7e | 93 | 2312 | 0 |

The exact 9e98085a7e Git archive was synchronized into the existing isolated Meson build's source tree by file checksum. The four-file Catch filter covered migration, store, scope preview, and scope authorization. The test output reported all cases passed and the run-end listener dropped its PostgreSQL template. The parallel-reader scenario ran in the GCC 15 debug configuration. This was not a TSan run.

Working directory on Big Tam: /tmp/yuzu-cache12-DAMgkrmZ/src. The commands for each row were:

```sh
ninja -C build-linux -j8 tests/yuzu_server_tests
./build-linux/tests/yuzu_server_tests --filenames-as-tags '[#test_result_set_store],[#test_scope_walking_authz],[#test_rest_scope_v1_routes],[#test_echo_rename_migration_pg]' --reporter compact
```

YUZU_TEST_POSTGRES_DSN pointed to Big Tam's disposable PostgreSQL test instance. The 9e98085a7e logs are in /tmp/yuzu-cache12-DAMgkrmZ/final-9e98085a7e-build.log and final-9e98085a7e-tests.log. Later revisions need their own evidence.

## d3e45ade99 final-head verification

After the host reboot, a fresh untampered git archive for d3e45ade99 was configured under /tmp/yuzu-cache12-d3e45ade99/src with GCC 15, the existing vcpkg x64-linux triplet and Meson 1.12.1. All 1,132 build steps succeeded for the standard server target. PostgreSQL 18.4 was enabled.

The four-file focused command above exited 42: 96 of 97 passed, 2,570 of 2,571 assertions passed. An isolated repeat of `*cascading many member rows*` exited 42 (12 of 13 assertions passed). The bulk fixture seed at test_result_set_store.cpp:1194 invokes exec_sql after database limits are set to 64 kB. That setup call reports `temporary file size exceeds "temp_file_limit" (64kB)` before the sweep. Both invocations reported that the run-end listener dropped their PostgreSQL template. The full Meson server suite was separately launched with the CI file_copy clone strategy.

Full server suite at d3e45ade99 completed with 24 OK, 2 failures, 5 skips (31 Meson entries). PG shard I repeated the same 64 kB fixture seed failure. The second failure and five skips traced to this build shell's PATH: the partition self-test could not spawn the Meson CLI, and five UI checks skipped when Node was unavailable. With Meson 1.12.1 and the installed Node 24 on PATH, the partition self-test and all five UI entries passed individually. Thus 30 of 31 entries passed when the required executables were supplied. The full run's canonical log is build-linux/meson-logs/gov-server-d3e45ade99.txt and the two environment-only replays are gov-partition-replay.txt and gov-node-replay.txt in that directory.

## 1f0c89b02e corrected fixture verification

On 2026-11-22 the only source diff from d3e45ade99, tests/unit/server/test_result_set_store.cpp, was synchronized from the committed Git archive. Standard GCC 15 Linux target rebuilt successfully. All 97 cases passed, 2,583 assertions, with PostgreSQL 18.4 enabled and the normal listener dropping the template. The corrected test proved the actual sweep connection had both limits set to 64 kB while handling the seeded cascade. Meson suite server started in the same environment with the Meson CLI and Node 24 on PATH and the CI file_copy database clone strategy.

All 31 registered Meson server suite entries passed at 1f0c89b02e, zero failed and zero skipped (exit 0). This includes all 14 PostgreSQL shards, all 4 non-PG shards, pg smoke, shard partition invariant, UI behaviors, healthcheck CLI and server-check cases. Source checkout and logs are under /tmp/yuzu-cache12-d3e45ade99 on Big Tam. Suite log: src/build-linux/meson-logs/gov-server-1f0c89b02e.txt. Focused regression: 1f0c89b02e-focused.log.

## 47dd31527d final documentation and source comment verification

The only production diff since 1f0c89b02e was a comment in result_set_store.cpp. Its four changed files were synced from the committed Git archive, the ordinary Meson target rebuilt, and all 97 focused PostgreSQL cases passed again (2,583 assertions, exit 0). The run-end listener reported dropping its template. Full server suite launched again at this content.

Final full Linux Meson server suite passed all 31 entries, zero failures and zero suite-entry skips, exit 0. The full log is `/tmp/yuzu-cache12-d3e45ade99/src/build-linux/meson-logs/gov-server-47dd31527d.txt` on Big Tam. The branch head `cf497f7691` differs from the tested revision only in the two governance ledger files.

## Clock-skew regression

The three source files supplied after the source-ready signal were rebuilt on Big Tam using the normal Meson `yuzu_server_tests` target. PostgreSQL 18.4 was enabled with file-copy clone isolation. `[clock_skew]` passed 40 assertions in one test, and Catch2's file tag `[#test_result_set_store]` passed all 58 cases and 1,497 assertions. Both exited 0. The logs are `clock-build.log`, `clock-focused.log`, and `clock-store.log` in `/tmp/yuzu-cache12-d3e45ade99` on Big Tam.
