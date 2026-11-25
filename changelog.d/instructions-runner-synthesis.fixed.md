- The `/test` Instructions gate sends parameter values the plugins accept: `echo.query` and
  `echo.export` get epoch-second `from`/`to`, and `filesystem.list_dir`/`read` get the seeded
  directory and text file. Rows that cannot succeed honestly are skipped with a recorded reason,
  never passed: `agent.http_client.get`/`head` (the plugin SSRF-blocks every offline target),
  `echo.configure` (any synthesised value would overwrite each reached agent's Echo byte budget),
  and `network_actions.ping`/`flush_dns` only when `YUZU_INSTRUCTIONS_SKIP_PRIVILEGED=1` is set by a
  rig that lacks sudo or raw sockets. Verdict grading is unchanged.
