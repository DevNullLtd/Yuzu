- **CI: the Windows and macOS legs build and test the agent only (ADR-0035 ladder step 1).**
  `ci.yml`'s Windows and macOS legs and `codeql.yml`'s Windows row now configure with
  `-Dbuild_server=false`, so no server code is built or tested off Linux in those workflows;
  the server, its Postgres `[pg]` suites and the libpq link-provenance canary run on the Linux legs
  only. The Windows leg drops its `Ensure Postgres`, `pg_mode` resolution, pg-shard and pg-smoke
  steps and builds into new `build-windows-agent-{debug,release}`
  directories; the first run on each Wee Tam runner, and any run of a branch not yet rebased onto
  this change, builds cold (ccache-warm). The dispatch-only `instructions-windows-validate.yml`
  server smoke rig is removed. `release.yml` still builds the Windows and macOS server until ladder
  step 2, the vcpkg install still includes the server ports until step 3, and Wee Tam's Postgres
  services stay provisioned (and health-checked) until step 4.
