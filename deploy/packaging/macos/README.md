# macOS agent packages

For the complete developer workflow and opt-in live smoke check, see
[macOS development foundation](../../../docs/macos-development-foundation.md).

The default package remains the loose-binary lane:

```sh
bash deploy/packaging/macos/build-pkg.sh --bin-dir build-macos --version <version> --output dist
```

The opt-in development lane stages a signed, immutable `YuzuAgent.app` and keeps
plugins external at `/usr/local/lib/yuzu/plugins`:

```sh
python3 deploy/packaging/macos/build-app.py \
  --bin-dir build-macos --version <version> --bundle-id <registered-app-id> \
  --profile <original.provisionprofile> --sign-identity <SHA-1-identity> \
  --output-dir <empty-task-directory> \
  --final-plugin-sig-dir <final-sidecars-dir> --plugin-trust-bundle <build-trust.pem> \
  --runtime-plugin-trust-bundle <installed-trust-bundle-path>
bash deploy/packaging/macos/build-pkg.sh --bundle-dir <empty-task-directory> \
  --version <version> --output dist --plugin-trust-bundle <build-trust.pem>
```

Omit the three sidecar options and the package trust-bundle option only when no
plugin has a CMS sidecar. For sidecars, the package command uses the same
build-time trust bundle as `build-app.py` to verify the final copied bytes.

The helper requires `security cms` to decode the original profile, a current
explicit macOS App ID, ES Boolean entitlement, matching developer certificate,
and this Mac's **Provisioning UDID**. Apple silicon registration uses
`system_profiler SPHardwareDataType`'s `Provisioning UDID`; never substitute
`IOPlatformUUID`. Run `scripts/macos-device-registration.zsh` to obtain it.

Build this lane with `meson/native/macos-appleclang.ini`. Before configuring or
rebuilding, rebuild the **target** dependencies with the repository's
`arm64-osx` triplet and bypass all binary caches so pre-13.3-incompatible
archives cannot be reused:

```sh
vcpkg install --triplet arm64-osx --x-manifest-root=. --binarysource=clear
```

The repository-local triplet is found automatically by vcpkg. It sets
`VCPKG_OSX_DEPLOYMENT_TARGET=13.3` only for target dependencies; it does not
change host tools or Linux/Windows triplets. The helper inspects every staged
Mach-O `LC_BUILD_VERSION` and refuses anything other than the project's macOS
13.3 deployment target; `Info.plist` and installer metadata cannot make a
newer binary compatible.

The agent, core library, copied framework closure, and every external plugin
must have the same complete Mach-O architecture slice set; the helper rejects a
mixed closure. The required process collector is the exact output `tar.dylib`,
not a similarly named plugin.

The bundle LaunchDaemon runs as root, retains external plugins, and always passes
`--no-auto-update`. The sealed app is in the package-owned, root-owned
`/Library/Application Support/YuzuAgent/YuzuAgent.app`; data stays in
`/Library/Application Support/Yuzu` and is never ownership-reset or removed by
this lane. Logs, configuration, and trust anchors also remain outside the sealed
app, with existing configuration and certificate-directory ownership and modes
preserved.
When upgrading an earlier development build that placed `YuzuAgent.app` below
the data directory, the installer snapshots that package-owned child for
recovery and removes it only after the new daemon is healthy; it never changes
the containing data directory's ownership, mode, or unrelated contents. A
legacy child is removed only if its exact application identifier, team,
developer-signing authority, embedded-profile SHA-256, and strict code-signature
verification all match the development bundle. Any other legacy child is retained
under the root-owned recovery directory for operator inspection, and the service
is deliberately left stopped rather than bootstrapping code from the mutable data
directory. This migration is narrowly limited to the original profile hash,
expected Yuzu team, signed application identifier, and signer; a renewed or
otherwise different profile is intentionally retained.
Package transitions preserve them and retain package-owned code/configuration for
recovery. The package first writes its code and LaunchDaemon plist to package-owned
incoming paths. To prevent Installer from relocating an upgradeable `.app` before
the transaction, the sealed bundle arrives as a private archive of `Contents`;
postinstall extracts it only inside the trusted incoming root, rejects symlinks,
strictly verifies the reconstructed app, then promotes it and removes the
recovery snapshot only after launchd reports `running` with a PID for three
consecutive observations (up to six seconds). Interrupted-promotion recovery has
the same sustained check; a failure restores the previous state and retains the
recovery journal. A payload failure before postinstall therefore leaves the active
installation in place. Development app signing does not installer-sign or notarize
the `.pkg`.

Do not install the root LaunchDaemon, grant Full Disk Access, or test live
Endpoint Security without explicit test-rig authorization. A valid signature, a
running process, or polling fallback does not prove live ES: `tar.status` must
report `process_capture_method|endpoint_security`, followed by a unique observed
exec and exit with checked drop counters. The active SDK must ship the Endpoint
Security header and library stub; both the Command Line Tools and full Xcode
SDKs do. CMS sidecars must cover final
Apple-signed plugin bytes; stale sidecars are rejected. When input plugins carry
sidecars, provide `--final-plugin-sig-dir`, `--plugin-trust-bundle` and
`--runtime-plugin-trust-bundle`. The helper invokes Yuzu's shared CMS verifier on
the final plugin bytes and the generated LaunchDaemon enforces that runtime trust
bundle with `--plugin-require-signature`. During an upgrade, existing server/TLS
arguments and supported `YUZU_*` environment settings are retained. A generated
sidecar policy deliberately replaces existing plugin-signing arguments and
environment settings; bundle-owned paths and `--no-auto-update` are forced.
If the bundle contains CMS sidecars, pass the same build-time
`--plugin-trust-bundle` to `build-pkg.sh`: packaging reruns the shared verifier
over the bytes it is about to copy, so a stale or final-byte-modified sidecar
cannot produce a package.

### Bootstrap final-byte CMS signing (two stages)

For a new build whose inputs do not already carry CMS sidecars, first run
`build-app.py` normally to publish the Apple-signed app and relocated plugins.
Keep this staging directory private and do not install/package it yet. Sign every
**output** `plugins/*.dylib` with the existing
[Plugin Code Signing workflow](../../../docs/user-manual/agent-plugins.md#plugin-code-signing).
The signer leaf must have the code-signing EKU and chain to the build trust bundle;
private keys remain operator-managed, outside this repository. For example:

```sh
MAC_BUNDLE=/private/tmp/yuzu-signed-stage
for plugin in "$MAC_BUNDLE"/plugins/*.dylib; do
    openssl cms -sign -binary -signer /private/path/signer.pem \
      -inkey /private/path/signer.key -certfile /private/path/signer_chain.pem \
      -in "$plugin" -outform PEM -out "$plugin.sig" || exit 1
done
```

Create `plugins/plugin-signing-policy.json` in that same staging directory:

```json
{"runtime_plugin_trust_bundle":"/etc/yuzu-agent/certs/plugin-trust.pem"}
```

Provision the public trust bundle at that absolute runtime path through the
normal operator-managed configuration; the package does not install trust anchors.
Now run `build-pkg.sh --bundle-dir "$MAC_BUNDLE" --version <version> --output <dist>
--plugin-trust-bundle <build-trust.pem>` (on one command line). Packaging verifies
every final sidecar with the staged agent's shared CMS verifier and embeds the
require-signature policy in the LaunchDaemon. Missing/mixed/stale signatures fail.
Do **not** rerun `build-app.py`, re-sign, or edit plugin bytes after CMS signing.
`--final-plugin-sig-dir` is an import path for already-known final-byte sidecars,
not the bootstrap procedure. Never delete existing enforced input sidecars to
bypass policy; use a fresh build for the two-stage workflow.

## Authorized test-rig lifecycle

Do not run these commands on a development workstation without explicit
authorization for the target rig. They install and start the root LaunchDaemon.
For an explicitly authorized Mac (including a developer workstation), record the
package hash and preserve the existing service configuration first, then perform a
non-interactive install with:

```sh
sudo /usr/sbin/installer -pkg YuzuAgent-<version>-macos-<arch>.pkg -target /
```

The same command performs loose-to-bundle, bundle-to-bundle, and bundle-to-loose
transitions. It stages the new payload under incoming names while the old daemon
continues to run, validates the bundle, then stops and replaces the selected lane.
The postinstall script restores the saved plist and package-owned files if that
promotion or its sustained launchd health observation fails. It leaves data, logs,
configuration, certificates, and third-party plugins alone. The recovery snapshot records a
durable `prepared` or `promoting` phase; a later package invocation discards an
unused prepared snapshot or restores an interrupted promotion before taking a
new snapshot. The root-owned recovery state rejects symlinked,
group/world-writable, or out-of-root pointers rather than using them.

Older loose packages did not ship `package-files.list`. Their first upgrade
derives that manifest only from the system Installer receipt for `com.yuzu.agent`
and snapshots it with the old plugin bytes. Missing receipts do not authorize
overwriting same-named plugins: an unrecognized collision stops before unloading
the running service. The plugin directory must be root-owned, non-symlinked, and
not group/world writable. A missing data working directory is created; an existing
one keeps its owner, mode, and contents.

For an authorized silent uninstall, run:

```sh
sudo /usr/local/lib/yuzu/uninstall.sh
```

It removes only Yuzu's manifest-listed plugin files and both package-owned code
lanes; it retains operational data, logs, configuration, trust anchors, and
third-party plugins. If the legacy app in the data root is unrecognized, the
script moves it to a root-only `/var/db/yuzu-agent/uninstall-legacy.*` recovery
directory, exits nonzero, and leaves the package-owned code lanes and plist in
place. Inspect that retained app and deliberately retry or remediate the
installation; the daemon remains unloaded until a later successful package
transition, so do not restart it before that inspection. Do not delete the
recovery directory to force an uninstall. If
an installation reports an error, retain
`/var/db/yuzu-agent/install-recovery.*` and the Installer log for diagnosis;
do not delete them before comparing the restored plist and package manifest.
