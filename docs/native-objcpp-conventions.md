# Native Objective-C++ conventions (macOS)

macOS-only frameworks (CoreWLAN, IOKit, CoreFoundation, ...) sometimes have no
usable pure-C++/C API — the only supported entry point is Objective-C. This
document is the convention set for a Yuzu plugin that needs one, and the
reusable meson wiring behind it. The worked example is the `wifi` plugin
(`agents/plugins/wifi/`), the first Objective-C++ (`.mm`) translation unit in
the tree (`wifi_corewlan.mm`, `docs/darwin-compat.md` → "CoreWLAN +
Objective-C++").

## When does a plugin need Objective-C++, not plain C++?

Only when the framework's supported entry point is an Objective-C class with
no C shim — CoreWLAN's `CWInterface`/`CWWiFiClient` is the model case. Prefer
a plain-C/CoreFoundation API when one exists (most Apple frameworks —
`IOKit`, `Security`, `SystemConfiguration` — expose one); reach for `.mm` only
when the framework itself forces it. A `.mm` file compiles both Objective-C
and C++ in the one translation unit, so it can still call straight into the
rest of the plugin's C++ (`agents/core`, the SDK, `<yuzu/plugin.h>`)
unchanged — the boundary is file-scoped, not a separate ABI.

## ARC — when it applies, and what it does not cover

Every `.mm` file in this project is compiled `-fobjc-arc` (Automatic
Reference Counting) — there is no manual-retain-count variant. Concretely:

- **Objective-C objects** (anything typed as an `NSObject`-derived pointer —
  `NSString*`, `CWInterface*`, a block's captured Objective-C variables) are
  ARC-managed: no `retain`/`release`/`autorelease` calls, ever; a `strong` /
  `weak` local behaves like a smart pointer and the compiler inserts the
  retain/release traffic for you.
- **CoreFoundation objects** (`CFStringRef`, `CFArrayRef`, `SCDynamicStoreRef`,
  ...) are a **different, non-ARC world** — ARC's `-fobjc-arc` flag governs
  Objective-C object pointers only. A CF object obtained from a `Create`/`Copy`
  function still needs an explicit, exactly-once release, and that is what
  `ScopedCFRef<T>` (`agents/core/include/yuzu/agent/scoped_cfref.hpp`) is for
  — an RAII wrapper around `CFRelease`, so a `.mm` (or plain `.cpp`) TU that
  mixes CF calls with ARC-managed Objective-C objects gets exception-safe
  cleanup on **both** halves without hand-rolled `CFRelease` calls scattered
  through the function. `CFBridgingRelease`/`CFBridgingRetain` are the
  toll-free-bridging idiom where a single object genuinely needs to cross
  from the CF world into ARC's (or back) — reach for them only at that exact
  boundary, not as a routine substitute for `ScopedCFRef`.
- **IOKit objects released via `IOObjectRelease`** — iterators, services, and
  registry entries returned by `io_object_t`-typed accessors
  (`IOServiceGetMatchingService`, `IOIteratorNext`,
  `IORegistryEntryGetChildEntry`, ...) — use `ScopedIOObject`
  (`agents/core/include/yuzu/agent/scoped_ioobject.hpp`). **Do not** use it
  for an `io_connect_t` returned by `IOServiceOpen`: despite the typedef
  relationship, `IOServiceClose` performs the actual kernel-side connection
  close before releasing, so a bare `IOObjectRelease` on a connection leaves
  the user client instantiated in the kernel. A connection needs its own
  owner with `IOServiceClose` as the deleter.
- **Blocks** that capture Objective-C objects are themselves ARC-managed
  (the compiler treats a `^{ ... }` literal like an Objective-C object for
  retain/release purposes); a block that outlives the scope it was created in
  (queued for later dispatch, stored in an ivar) should be copied to the heap
  as usual (ARC does this automatically when a block is assigned to a
  strong-qualified variable — ARC's stack-to-heap block promotion means an
  explicit `Block_copy`/`[block copy]` is rarely needed, unlike pre-ARC code).

## Visibility

Every objcpp target passes `-fvisibility=hidden`, matching the project-wide
C++ default (`-fvisibility=hidden` in the top-level `add_project_arguments`)
— an Objective-C++ TU does not inherit that project-level flag automatically
(objcpp is a distinct Meson language from cpp; see below), so it is re-passed
explicitly. Nothing in a `.mm` plugin TU should be exported beyond the
plugin's `plugin.h` ABI entry points, exactly as for a `.cpp` one.

## The C++23 flag: `-std=c++23` vs `-std=c++2b`

Apple Clang 15 (the Command Line Tools SDK floor this project targets,
`-mmacosx-version-min=13.3`) rejects the canonical `-std=c++23` spelling for
Objective-C++ and requires the pre-standardization alias `-std=c++2b`; newer
Apple Clang accepts `-std=c++23` directly. **Probe, never hardcode**: ask the
`objcpp` compiler object (`meson.get_compiler('objcpp').has_argument(...)`)
which spelling it accepts and pick that one, so a build on an older toolchain
does not fail with an "unknown argument" configure error while a build on a
newer one is not stuck on the deprecated alias forever. See also
`docs/ci-cpp23-troubleshooting.md` for the parallel plain-C++ pitfalls this
project has already hit across compilers.

## The meson wiring: a reusable per-target template

Objective-C++ is a **separate Meson language from `cpp`** — the top-level
`project()` declares `cpp` only, and a `.mm` TU's compile flags (`-std=`,
`-fvisibility`, `-fobjc-arc`) are *not* inherited from the project-level C++
`add_project_arguments`; each objcpp target must set them via its own
`objcpp_args:` kwarg on `shared_library()`/`executable()`.

Meson has no user-defined functions, so "reusable template" means: the parts
of this wiring that are identical for *every* Objective-C++ plugin are
declared **once**, at the top-level `meson.build`'s existing Darwin-frameworks
site (next to `corefoundation_dep`, ~line 348) —

- `add_languages('objcpp', native: false, required: true)` — a process-global
  language registration; doing it once here means a second `.mm`-consuming
  plugin never needs to repeat (or worry about ordering) its own call.
- `apple_objcpp_args` — the probed C++23 flag plus `-fvisibility=hidden` and
  `-fobjc-arc`, computed once.

— and only the genuinely target-specific parts stay in the plugin's own
`meson.build`: its `.mm` source list and its own
`dependency('appleframeworks', modules: [...])` call (the module list is
target-specific by definition, so this part is not further factored). A new
Objective-C++ plugin's darwin branch is then just:

```meson
elif host_machine.system() == 'darwin'
  foo_sources += files('src/foo_thing.mm')
  foo_deps    += dependency('appleframeworks', modules: ['Whatever'],
                            include_type: 'system')
  foo_objcpp_args += apple_objcpp_args
endif
```

`agents/plugins/wifi/meson.build` is the worked example — it consumes the
template exactly this way for `CoreWLAN`/`Foundation`.

### `required: true` on the per-target `appleframeworks` dependency

Whether a plugin's own `dependency('appleframeworks', modules: [...])` call
should be `required: true` or `required: false` is a **per-framework**
decision, not part of the shared template:

- `required: true` — the framework ships in the base macOS SDK / Command
  Line Tools (CoreWLAN, Foundation, IOKit, CoreFoundation, Security,
  SystemConfiguration, ...). A configure-time failure to find one is a real
  toolchain problem, never a "missing optional Xcode" case — see
  `docs/darwin-compat.md`'s CoreWLAN row.
- `required: false` — the framework genuinely may be absent on a given SDK/
  build environment. Guard the capability behind a `-DYUZU_HAVE_...` define
  and a runtime/no-op fallback path. **`EndpointSecurity` is NOT a real
  example of this case** — despite a long-standing myth in this codebase, it
  is not an `.framework` bundle at all (it ships as
  `usr/lib/libEndpointSecurity.tbd` + `usr/include/EndpointSecurity/`, present
  in BOTH the Command Line Tools and full Xcode SDKs), so probing it via
  `dependency('appleframeworks', modules: ['EndpointSecurity'])` — as the
  top-level `meson.build`'s shared ES probe currently does (TAR's own
  `meson.build` only consumes the shared result, it does not probe itself)
  — is a probe DEFECT, not a legitimate optional-framework pattern: see
  `docs/darwin-compat.md`'s EndpointSecurity row and the
  `feat/macos-spark-a0.5-es-probe` fix slice for the corrected
  `cxx.find_library()`/`cxx.has_header()` form.

## Coverage

There is no dedicated CI job for `.mm` compilation — Objective-C++ code rides
the existing macOS `meson compile` leg in `ci.yml` (the same job that already
builds every other Darwin-conditional target); a `.mm` file that fails to
compile fails that job exactly as a `.cpp` file would. No workflow change is
needed (or made) to get this coverage.
