# macOS development foundation

Start here before implementing macOS Spark mechanisms or their Guardian, DEX and
Reflex consumers. This is an **opt-in development lane**, not a notarized release
or a claim of feature parity. It keeps SIP enabled, uses a signed immutable agent
app with external plugins, and disables executable-replacement OTA.

## Build and package from a checkout

1. Use an SDK that ships the Endpoint Security header and library stub (both the
   Command Line Tools and full Xcode SDKs do). Configure must not print
   "EndpointSecurity library or header not found"; otherwise TAR deliberately
   compiles the polling fallback.
2. Follow [the build guide](build-guide.md) for Meson, the C++23 toolchain and
   vcpkg prerequisites. Use the pinned manifest and repository `arm64-osx` triplet.
   In a fresh checkout, rebuild target dependencies without binary-cache restores:

   ```sh
   "$VCPKG_ROOT/vcpkg" install --triplet arm64-osx --x-manifest-root=. --binarysource=clear
   ./scripts/setup.sh --tests --native-file meson/native/macos-appleclang.ini
   meson compile -C build-macos
   meson test -C build-macos --suite agent --suite tar --print-errorlogs
   ```

   `--binarysource=clear` disables binary caches; it does not force replacement of
   an already-populated installed prefix. Do not reuse dependencies built with a
   newer deployment target. The development bundle requires every emitted Mach-O
   to declare 13.3, preserving the project's C++23 library requirements. This is
   a build floor, not evidence of execution on the oldest supported OS. Intel and
   older-OS runtime qualification remain separate; this lane was exercised arm64.
3. Obtain an explicit App ID with the Endpoint Security grant, a matching macOS
   development profile containing this Mac, and its signing identity **with the
   private key** in Keychain. `zsh scripts/macos-device-registration.zsh` prints
   the local registration name and Provisioning UDID. Keep that output private;
   never substitute Hardware UUID. No private key, certificate bundle, provisioning
   profile, cookie jar or enrollment credential belongs in git.
4. Stage and package using [the packaging README](../deploy/packaging/macos/README.md).
   It is the authoritative command reference, including final-byte CMS sidecars.
   Hash the resulting package and record source commit, toolchain, architecture,
   deployment target and executable/profile hashes in private evidence. A signed
   development app inside an unsigned `.pkg` is not a signed/notarized installer.

Do not develop by editing files inside the installed sealed app. Rebuild, restage,
sign and deliberately install a new package. Network Extension targets and their
profiles are a later independently reviewed component, not supplied by the ES grant.

## Use an existing authorized Mac safely

This can be a developer's actual Mac; it need not be disposable. Installation,
service interruption, permission changes, downgrade and uninstall still require
explicit operator authorization. Back up the existing plist and record the package
and preserved data locations first. Use the package transaction documented above;
do not replace it with a privileged script that edits signed code or wipes identity.

The installed app lives at `/Library/Application Support/YuzuAgent/YuzuAgent.app`;
the root service is `system/com.yuzu.agent`. Data lives separately at
`/Library/Application Support/Yuzu`. Full Disk Access (FDA) is a separate macOS
privacy permission: grant it deliberately through System Settings when needed.
Never disable SIP or edit TCC databases to make a test pass.

Follow [UAT environment guidance](uat-environment.md) to choose one stack and its
ports. **Do not rerun `start-UAT.sh` to inspect a retained rig:** startup may wipe
its state. Use server/gateway builds from compatible source revisions. Registration
alone does not prove command delivery: a stale gateway missing
`command_dispatch_tag_v1` can accept enrollment but have targeted dispatch refused.
Rebuild the gateway; never bypass that protocol guard.

Keep TLS verification separate from development plumbing. Plaintext is only for an
explicitly authorized local lab with loopback-published ports; never expose agent
or management listeners to a LAN or Internet. A successful HTTP smoke check does
not establish TLS/mTLS on the agent-to-gateway or gateway-to-server connection.

## Repeatable installed-agent smoke check

Use the installed daemon's ID, not a different user-mode development agent's ID.
Verify it from the installed daemon's startup log and server inventory. Supply an
existing authorized operator cookie jar as a private regular file (0600). The tool
does not log in, mint enrollment tokens, reset accounts or broaden permissions.
Administrative read access may be required for the installed plist; review the
script before running it with `sudo`.

```sh
sudo python3 scripts/macos-foundation-check.py \
  --server https://localhost:8080 \
  --cookie-file /absolute/private/operator.cookies \
  --agent-id INSTALLED_AGENT_ID
```

For an already authorized plaintext local rig, use `http://localhost:8080` and
explicitly add `--allow-local-plaintext`. There is no certificate-verification bypass.
The operator chooses the installed target: the tool is not an identity attestation
service and does not infer a target from an aggregate fleet health metric.

The check leaves the service running and its configuration untouched. It verifies:

- Root launchd PID points to the installed executable and remains stable.
- App and external plugin signatures pass; executable, profile and plugin hashes
  remain unchanged, with no executable-adjacent OTA markers.
- Explicit single-target `os_info.os_name`, `tar.status` and `tar.sql` commands
  return terminal SUCCESS; failures, wrong-target replies and timeouts fail closed.
- TAR reports `endpoint_security`, process capture enabled, and unchanged drop
  counters. A private native `/usr/bin/true` copy generates a unique EXEC/EXIT pair
  retrieved through normal command dispatch, not by reading the TAR database.
- Repeated targeted commands succeed during the observation window (default 120
  seconds). This tests responsiveness, **not** a per-agent heartbeat metric.

Only safe summaries/hashes are printed. The unique marker is removed on exit;
normal command/audit records and captured marker events remain subject to Yuzu's
retention. Keep evidence private under `.agent-runs/`, excluded from git **and**
Docker contexts. Python parser/mock regressions run on every host via Meson's
`agent` suite; the live smoke is opt-in and never invoked automatically by CI.

If marker rows are initially absent, allow TAR's configured drain interval (normally
60 seconds). A new SQL command is a fresh snapshot; repeatedly polling the same
receipt cannot discover later rows. If launchd bootstrap returns 5 after bootout,
first check whether the previous PID is still exiting and inspect retained logs;
do not repeatedly unload/reinstall or discard recovery state. No harness cleanup
should stop a successfully retained service.

## Where implementation begins

| Surface | Starting point and boundary |
|---|---|
| Spark | `agents/core/include/yuzu/agent/spark.hpp`, `agents/core/src/spark_engine.*`, `spark_mechanism.hpp`. The File/Registry/Service factories currently provide no Darwin mechanism; portable timer types are distinct. Add real supported mechanisms, never stubs that imply capture. |
| Guardian | `guardian_engine.cpp`, `guardian_spark_runtime.*`, `guardian_state_reader.*`. Preserve the single reconciliation chokepoint and §24 invariants; this PR does not flip production `prefer_spark`. |
| DEX | `dex_macos_collector.cpp`, `dex_macos_signals.*`, `dex_macos_oslog.*`, `dex_macos_iokit.*` already implement Mac collection. Extend/converge these, not a second competing collector stack. |
| Reflex | [ADR-0021](adr/0021-spark-reflex-architecture.md) defines the future consumer. Existing TriggerEngine is not a shipped Reflex implementation. A root daemon cannot substitute for an interactive-session consent helper. |
| Endpoint Security | `agents/plugins/tar/src/tar_proc_es.cpp` currently feeds TAR, **not Spark**. Its NOTIFY EXEC/EXIT stream proves observation, not synchronous AUTH prevention. |

Read ADR-0021, [the Spark consumer design](spark-stage2-guardian-consumer-design.md),
[the delta registry](spark-legacy-delta-registry.md), and
[Guardian's invariants](yuzu-guardian-design-v1.1.md#24-standing-guardian-invariants-governance-reference)
before a consumer change. Update the relevant capability registries with each real
platform-support change. Keep unsupported and permission-denied outcomes honest.

## Acceptance boundaries

Before relying on a **new artifact**, rerun its packaging/signature checks and the
installed smoke after an authorized install. A previous package's live result is
not evidence for freshly rebased source. Keep restart/reconnect, upgrade/downgrade,
failure recovery and uninstall as explicit lifecycle tests; the smoke deliberately
does not interrupt a workstation to exercise them. Release additionally needs
distribution signing/notarization, secure transport validation, older-OS execution,
the remaining platform regressions and independent review. Do not mark those gates
passed because the local development smoke succeeds.
