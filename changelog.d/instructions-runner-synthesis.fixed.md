- The `/test` Instructions gate sends parameter values the plugins accept: `echo.query` and
  `echo.export` get epoch-second `from`/`to`, `echo.configure` gets the documented default
  `db_budget_bytes`, and `filesystem.list_dir`/`read` get the seeded directory and text file. The
  two `http_client` read rows are skipped with a recorded reason (the plugin SSRF-blocks every
  offline target), and `network_actions.ping`/`flush_dns` skip with a reason only when
  `YUZU_INSTRUCTIONS_SKIP_PRIVILEGED=1` is set by an isolated rig. Verdict grading is unchanged.
