# Plugin process isolation (sandboxing plugins from the agent)

Yuzu does not isolate agent plugins from the agent daemon that loads them, and does not plan to. Plugins are native shared libraries (`.so` / `.dll` / `.dylib`) loaded into the agent's own process through the stable C ABI (`sdk/include/yuzu/plugin.h`). A plugin therefore holds the agent's full authority: its memory (including the mTLS private key and the live gRPC stream), its OS account, and its capabilities.

There is no in-code defence against a malicious or compromised plugin stealing the agent's identity, and none is wanted. The control is **admission, not containment**: every plugin is assessed and code-signed before it ships, and an unsigned plugin must not run.

## Why this is out of scope

Isolating plugins from the agent would need a process boundary. In-process mechanisms cannot provide it, because a plugin shares the agent's address space:

- **seccomp-bpf** and **Landlock** restrict a *whole process*. Applied to the agent, the policy has to admit the union of every plugin's needs (`script_exec` runs arbitrary scripts, `software_actions` installs packages, `filesystem` reads anywhere), so it cannot separate one plugin from the agent. That process-wide hardening is still worth having against *external* exploitation, and is tracked separately (#422). It is not plugin isolation.
- **Real isolation** means a privileged broker beside unprivileged per-plugin workers, with IPC between them. `docs/agent-privilege-model.md` already weighs and defers this ("privileged broker beside an unprivileged worker"). It would double the operational surface (two processes, two metrics sets, an IPC contract), give up the in-process dispatch that `docs/architecture.md` ("Why in-process plugins?") chose deliberately, and need a separate native sandbox per OS: seccomp/Landlock on Linux, AppContainer or job objects on Windows, and sandbox profiles on macOS.

Plugins are vendor-shipped or operator-assessed code, not untrusted third-party extensions. For that trust model, cryptographic admission gives the needed guarantee at a fraction of the cost:

```
agent boot → PluginLoader::scan()
  allowlist hash check (--plugin-allowlist)
  → CMS detached signature verified against the trust bundle (--plugin-trust-bundle)
  → unsigned or bad signature ⇒ rejected, never dlopen'd (--plugin-require-signature)
```

Making that signature gate mandatory by default is tracked in #4915. A plugin that is not signed must not load.

## What would reopen this

Reconsider only if the trust model changes, for example if Yuzu starts accepting unassessed third-party or customer-authored native plugins. Customer-authored *scripts* are a different path, the signed-script ADR stub (#2329), and do not reopen this.

## Prior requests

- #115: "Add plugin sandboxing or document trust model"
