# macOS agent packages

For the complete developer workflow and opt-in live smoke check, see
[macOS development foundation](../../../docs/macos-development-foundation.md).

The default package remains the loose-binary lane:

```sh
bash deploy/packaging/macos/build-pkg.sh --bin-dir build-macos --version <version> --output dist
```

Both lanes run root code from below `/usr/local`, a tree the package shares
with other tools and never re-owns: plugins from `/usr/local/lib/yuzu`, and in
the loose lane the daemon itself from `/usr/local/bin`. Installation therefore
requires each existing directory of `/usr/local`, `/usr/local/lib` and
`/usr/local/lib/yuzu` (plus `/usr/local/bin` for the loose lane) to be
root-owned and not group- or world-writable. These checks run in `preinstall`,
before Installer writes or removes anything, so a refusal leaves the existing
installation exactly as it was. Hosts this can stop:

- Macs whose Homebrew lives in `/usr/local`: its installer gives the admin user
  ownership of `/usr/local/bin` and `/usr/local/lib`. That is the default on
  Intel Macs, and also on Apple silicon Macs that run an Intel (Rosetta)
  Homebrew or were migrated from an Intel Mac. A native Apple silicon Homebrew
  lives in `/opt/homebrew` and is not affected.
- Hosts where an MDM or provisioning script loosened `/usr/local` modes.

Making the directories root-owned does not undo what another account already
wrote into them. The installer also refuses when any `yuzu-agent*`,
`libyuzu_agent_core*`, `.yuzu-*` or `.libyuzu_agent_core*` entry in
`/usr/local/bin`, or anything at any depth below `/usr/local/lib/yuzu/plugins`
(the agent loads plugins recursively), is a symlink, is not root-owned, is
group- or world-writable, or has an access control list (`ls -le`) that lets
anyone modify it. The `/usr/local` directories are checked for such ACLs too.
It lists each one, even when it also refused a
directory. Inspect them, remove anything you did not install as root, then
retry. Do not `chown -R` these paths: that makes another account's files look
root-installed. Package promotion removes the updater's `yuzu-agent.old`
rollback file and its marker, because they belong to the code being replaced.
In the loose lane, the delivered binary and core library are promoted only if
their SHA-256 matches what the package recorded. The plist-merge helper runs
from the package's own Scripts directory, never from `/usr/local`.

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
this lane. Because it is the root daemon's data and working directory, an existing one
must be owned by root or by the `_yuzu` service account that
`scripts/install-agent-user.sh` provisions, and must not be group- or
world-writable; otherwise installation stops before anything is staged, and the
directory is left exactly as it was. It holds the agent's identity and
enrolment, so never delete it to get past this check; remove the write bit or
restore its owner instead. `/Library/Logs/Yuzu` follows the same rule, since the
same script gives it to `_yuzu`. Configuration, certificate and plugin
directories must be root-owned and not group- or world-writable; these are all
checked in `preinstall`, before the payload. Logs,
configuration, and trust anchors remain outside the sealed app, with existing
ownership and modes preserved.
When upgrading an earlier development build that placed `YuzuAgent.app` below
the data directory, the installer leaves that child in place until the new
daemon is in place, then moves it into the recovery snapshot and deletes or
quarantines it there; it never changes
the containing data directory's ownership, mode, or unrelated contents. A
legacy child is removed only if its exact application identifier, team,
developer-signing authority, embedded-profile SHA-256, and strict code-signature
verification all match the development bundle. Any other legacy child is never
run, restored, or deleted: it is moved to a root-only quarantine,
`/var/db/yuzu-agent/quarantine/legacy-YuzuAgent.*/`, outside both the data
directory and the recovery state, and reported. An install whose new daemon is
already healthy is kept; recovery never starts a service whose program lives in
the data directory, and it never blocks a later install. This migration is
narrowly limited to the original profile hash, expected Yuzu team, signed
application identifier, and signer; a renewed or otherwise different profile is
intentionally quarantined.

These values are pinned in `postinstall` and `uninstall.sh` as
`LEGACY_TEAM_ID`, `LEGACY_APP_ID`, `LEGACY_SIGNING_AUTHORITY`, and
`LEGACY_PROFILE_SHA256`, and identify one developer's pre-package development
build only. They grant nothing to any other signer: retirement requires all of
them to match. Remove the legacy migration (and these pins) once no managed Mac
still has a `YuzuAgent.app` under the data directory; never extend them to a new
identity.
Package transitions preserve them and retain package-owned code/configuration for
recovery. The package first writes its code and LaunchDaemon plist to package-owned
incoming paths. To prevent Installer from relocating an upgradeable `.app` before
the transaction, the sealed bundle arrives as a private archive of `Contents`;
postinstall extracts it only inside the trusted incoming root, rejects symlinks,
strictly verifies the reconstructed app, and merges the existing service
settings into the new definition, all before anything active is stopped. A
failure there leaves the running agent untouched. When upgrading a package from
before this installer, which wrote straight to the live paths, Installer may
remove files the old package's receipt listed before `postinstall` runs. A
refusal at that point puts back every live file missing since the snapshot, and
never overwrites one.

Whether the new agent is started depends on what it replaces:

- **A running agent.** The installer waits (up to 30 seconds) for it to exit,
  then starts the new one, which must report `running` with a PID for three
  consecutive observations (up to six seconds), or the previous package state is
  restored and restarted. If an administrator had disabled it while it ran, the
  override is put back for the next boot. If its definition could not be read,
  so its settings were lost, the new agent is installed but not started, and the
  Installer log (`/var/log/install.log`) says so.
- **A service an administrator disabled** (`launchctl disable`) and not
  running. It is installed and left stopped.
- **Nothing running, but a server trust anchor is configured** (`--ca-cert`,
  `--tls-system-roots`, `--no-tls`, the matching `YUZU_*` variable, or
  `/etc/yuzu/certs/default-ca.pem`). It is started and its state is reported, with
  no rollback, since nothing running was replaced.
- **Nothing configured** (a first install of the stock package). It is installed
  but not started, because the agent refuses to run without a trust anchor. The
  Installer log (`/var/log/install.log`) says how to configure and start it. The definition is in
  `/Library/LaunchDaemons`, so after a reboot launchd starts it and it exits
  and retries every 10 seconds until configured, as earlier packages did.
  Disable the service if it should stay off until then.

"Running" means the same process for two seconds, so an agent that launchd
keeps restarting does not count, and its upgrade is not health-gated.

Recovery restarts a restored agent only if it was running when the snapshot was
taken. A restored definition that recovery does not start (because the agent
was not running before, its code directory is untrusted, it cannot be read, or
it points into the data directory) is still in `/Library/LaunchDaemons`, so
launchd starts it at the next boot, exactly as before the install. Disable it
(`launchctl disable system/com.yuzu.agent`) if it must stay stopped. A restored agent that does not stay running is reported, and recovery
still completes, so the next install is never blocked by it. A payload failure
before postinstall leaves the active installation in place. Development app
signing does not installer-sign or notarize the `.pkg`.

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
bundle with `--plugin-require-signature`. During an upgrade, existing arguments
other than the package-owned paths are retained. Every existing `YUZU_*`
environment variable is retained (OTA signing, inventory and licence-scan
opt-outs included), as are the standard proxy variables. Exceptions: the
generated definition's own keys, `YUZU_PLUGIN_DIR` and `YUZU_DATA_DIR`. Any
other variable is dropped, and each drop is named in the Installer log. A
generated sidecar policy deliberately replaces existing plugin-signing
arguments and environment settings; bundle-owned paths and `--no-auto-update`
are forced. If the existing definition cannot be parsed, the package default is
installed with a warning, and earlier settings must be re-applied. If the
existing definition requires plugin signatures and this package ships an
unsigned plugin (every release `.pkg` does), the install stops before anything
is changed: remove `--plugin-require-signature` first, or install a signed
package.
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
continues to run, validates it, then stops and replaces the selected lane.
The postinstall script restores the saved plist and package-owned files if
promotion or the health observation of a previously running agent fails. It
leaves data, logs, configuration, certificates, and third-party plugins alone.
The recovery snapshot records a durable `prepared` or `promoting` phase. A later
package run restores an interrupted promotion, or discards an unused prepared
snapshot after first putting back any live file it holds that is missing (an
install interrupted after Installer removed an older package's files), before
taking a new snapshot. A recovery pointer that is unusable
(dangling after an interrupted cleanup, empty after a torn write, or a symlink)
is reported and dropped, and a phase that cannot be read is treated as an
interrupted promotion, so no recovery state can block later installs. Installs
and `uninstall.sh` take one lock (`/var/db/.yuzu-agent-transition.lock`, readable
only by root, so no other account can hold it), so an
uninstall waits while either install script is running. Installer lays down the
payload between the two scripts without the lock; an uninstall in that gap
removes the incoming files, and the install's `postinstall` then refuses.

Older loose packages did not ship `package-files.list`. Their first upgrade
derives that manifest only from the system Installer receipt for `com.yuzu.agent`
and snapshots it with the old plugin bytes. Missing receipts do not authorize
overwriting same-named plugins: an unrecognized collision stops before unloading
the running service. Current packages also record each plugin's SHA-256 in
`package-files.sha256`: a listed plugin whose bytes no longer match is not treated
as package-owned (a collision with it stops the upgrade) and is never re-owned by
the installer. Removal follows the same rule: a listed plugin whose bytes were
changed by an operator is kept, with a warning. Packages from before the hash
sidecar existed remove listed plugins by name. The plugin directory must be
root-owned, non-symlinked, and not group/world writable. A missing data working
directory is created; an existing one keeps its owner, mode, and contents.

The first line of `package-files.list` names the package version that wrote it.
A package without a manifest (any release from before this one), installed over
a newer one, leaves that manifest behind. The next install sees that its version
differs from the Installer receipt. It then re-derives ownership: the receipt's
plugins, plus each listed plugin whose bytes still match its recorded hash. So
rolling back a fleet and forward again does not refuse every later upgrade.

For an authorized silent uninstall, run:

```sh
sudo /usr/local/lib/yuzu/uninstall.sh
```

It removes Yuzu's manifest-listed plugin files (except ones an operator
changed), both package-owned code lanes, the updater's rollback file and the
service definition, `/Library/LaunchDaemons/com.yuzu.agent.plist`. It retains
operational data, logs, `/etc/yuzu-agent`, trust anchors, and third-party
plugins. The server address and any other setting kept only in the service
definition is removed with it: keep a copy if you will reinstall, or pre-stage
it as in "Deploying with MDM". It first discards any interrupted-install recovery state, so a later
install can never restore the agent it removed. An unrecognized legacy app in
the data root is quarantined, as the installer does, and the uninstall
continues. `/var/db/yuzu-agent` is removed unless its `quarantine/` directory
holds something; then it is kept, and the script names it.

To decommission a Mac completely, run `uninstall.sh`, then remove
`/Library/Application Support/Yuzu` (the agent's identity, enrolment and local
databases), `/Library/Logs/Yuzu` and `/etc/yuzu-agent`, and remove or revoke the
device on the Yuzu server so its certificate is no longer trusted.

If an installation reports an error, keep the Installer log
(`/var/log/install.log`) for diagnosis. macOS rotates that log by size, so it
is not an evidence store: forward it (or the installer's lines from it) to your
log collection if you need refusals, quarantines and recoveries as audit
evidence. Treat anything in `/var/db/yuzu-agent/quarantine/` as untrusted code:
hand it to your security team before deleting it. The installer has already restored the
previous state. You do not need to clear `/var/db/yuzu-agent` by hand, because
the next package run repairs or discards whatever it finds there.

## Deploying with MDM

The package needs no interaction. The target needs the directory state described
above: a root-owned, non-writable `/usr/local` chain, and data and log
directories owned by root or `_yuzu`. To have the agent start on its first
install, make its configuration available before the package runs:

1. Deploy the server's CA certificate, for example
   `/etc/yuzu-agent/certs/server-ca.pem` (root-owned, mode 644).
2. Deploy `/Library/LaunchDaemons/com.yuzu.agent.plist` (root:wheel, 644). Its
   `ProgramArguments` carries the server and trust settings, and its
   `EnvironmentVariables` carries any `YUZU_*` settings, for example
   `YUZU_UPDATE_TRUST_BUNDLE` or `YUZU_AGENT_INVENTORY_DISABLE`. Do not load it.
3. Install the package, for example as an MDM package payload or with
   `installer -pkg … -target /`.

The installer treats that plist as the existing definition. It keeps your
arguments and `YUZU_*` variables, adds its own fixed paths, and starts the agent
because a trust anchor is configured. A minimal plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.yuzu.agent</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/yuzu-agent</string>
    <string>--server</string><string>yuzu.example.com:50051</string>
    <string>--ca-cert</string><string>/etc/yuzu-agent/certs/server-ca.pem</string>
    <string>--enrollment-token</string><string>REPLACE-ME</string>
  </array>
</dict></plist>
```

A LaunchDaemon plist is readable by every local account, so use a single-use,
short-lived enrollment token there. It is only needed until the agent has
enrolled.

After the agent has enrolled, the token is no longer needed: remove it so it
does not stay readable and carried forward by upgrades
(`sudo /usr/libexec/PlistBuddy -c 'Delete :ProgramArguments:N'` for its two
entries, or `Delete :EnvironmentVariables:YUZU_ENROLLMENT_TOKEN`), then
`sudo launchctl kickstart -k system/com.yuzu.agent`.

The service definition is the only place the package reads settings from. It
does not read configuration profiles, so an MDM's custom-settings payload has
no effect; deliver the plist as a file instead.

Other points for an MDM rollout:

- **Signature.** Release packages are product-signed and notarized only when
  the release pipeline has the macOS signing and notarization credentials.
  Check a package with `pkgutil --check-signature` before uploading it to an
  MDM that requires signed packages. Development packages are never signed.
- **Privacy permissions.** Plugins that read data macOS protects with
  Transparency, Consent and Control (for example the privacy-permissions
  inventory) need Full Disk Access for the agent. Grant it with a PPPC profile
  naming `/usr/local/bin/yuzu-agent` (release package) or the app bundle's
  identifier (development lane); without it those reads report constrained
  results rather than failing.
- **Success is not "running".** An install that is refused fails, but an
  unconfigured first install succeeds with the agent not started. Check the
  outcome with `sudo launchctl print system/com.yuzu.agent` (or your MDM's
  script runner) rather than the install status alone.
- **Rollback.** Installing a package from before this installer replaces the
  service definition with its own default, so re-apply the settings afterwards.

Without step 2, the package installs the agent but does not start it. A later
script can add the settings to the installed plist and run
`launchctl bootstrap system /Library/LaunchDaemons/com.yuzu.agent.plist`. To keep
an installed agent stopped across upgrades, disable it
(`launchctl disable system/com.yuzu.agent`); upgrades then leave it stopped.
