project(
  'yuzu',
  'cpp',
  # Convention: plain X.Y.Z here, always — on dev this is the NEXT release's
  # base version. No -dev/-rcN suffix (operator ruling 2026-07-13): a suffix
  # once generated `int kVersionPatch = 1-dev;` and red-lined the whole C++
  # matrix (fca69e34). The suffix-tolerant split below (search
  # PROJECT_VERSION_PATCH) stays as defense-in-depth, not as licence.
  version: '0.13.1',
  license: 'AGPL-3.0-or-later',
  meson_version: '>=1.3.0',
  default_options: [
    # cpp_std is set per-compiler below: '/std:c++latest' for MSVC (meson's
    # cpp_std validation list has no 'vc++23' / 'c++23' entry for MSVC since
    # toolset 14.40 / meson 1.9), '-std=c++23' for GCC 13+ / Clang 18+ /
    # Apple Clang 15+. Setting cpp_std here makes `meson setup` fail on
    # Windows MSVC before per-compiler add_project_arguments runs.
    'warning_level=3',
    'werror=false',
    'default_library=shared',
    'b_pie=true',
  ],
)

# ── Compiler / host info ──────────────────────────────────────────────────────
cxx = meson.get_compiler('cpp')
host_os  = host_machine.system()   # 'linux', 'windows', 'darwin'
host_cpu = host_machine.cpu_family() # 'x86_64', 'aarch64', ...
if cxx.get_id() == 'msvc'
  add_project_arguments(
    '/std:c++latest',           # meson's cpp_std has no MSVC c++23 option
    '/wd4251', '/wd4127', '/wd4275',
    '/permissive-', '/Zc:__cplusplus', '/utf-8',
    language: 'cpp',
  )
else
  add_project_arguments(
    '-std=c++23',
    '-Wno-unused-parameter',
    '-fvisibility=hidden',
    '-fstack-protector-strong',
    language: 'cpp',
  )
  # FORTIFY_SOURCE requires optimisation; only enable for release builds.
  # Undef first to avoid -Wmacro-redefined on distros that set it in system headers.
  if get_option('buildtype') != 'debug'
    add_project_arguments('-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=2', language: 'cpp')
  endif
  # Full RELRO + immediate binding — makes GOT/PLT read-only after load.
  # Only ELF platforms; Apple's ld64 does not support -z flags.
  if host_os != 'darwin'
    add_project_link_arguments('-Wl,-z,relro,-z,now', language: 'cpp')
  endif
  if cxx.get_id() == 'clang'
    add_project_arguments('-Wno-gnu-zero-variadic-macro-arguments', language: 'cpp')
  endif
endif

# ── Build number from git ────────────────────────────────────────────────────
git = find_program('git', required: false)
if git.found()
  git_count = run_command(git, 'rev-list', '--count', 'HEAD', check: false)
  yuzu_build_number = git_count.returncode() == 0 ? git_count.stdout().strip() : '0'
  git_hash = run_command(git, 'rev-parse', '--short', 'HEAD', check: false)
  yuzu_git_commit_hash = git_hash.returncode() == 0 ? git_hash.stdout().strip() : 'unknown'
else
  yuzu_build_number = '0'
  yuzu_git_commit_hash = 'unknown'
endif

version_conf = configuration_data()
# The three numeric components feed `int` fields in version.hpp
# (`int kVersionMajor/Minor/Patch = @...@;`), so each MUST be a plain integer.
# A pre-release version (e.g. a stray 0.13.1-dev — the convention is plain
# X.Y.Z, see the version: line above) carries its suffix on the patch element,
# which would emit `int kVersionPatch = 1-dev;` —
# invalid C++ ("use of undeclared identifier 'dev'") that red-lines the whole
# build matrix. Strip the pre-release suffix off the patch, then validate every
# component with `.to_int()`: that turns any malformed version (typo, SemVer
# `+build` metadata, non-numeric) into a loud single `meson setup` failure
# instead of an opaque compile break across every CI leg. PROJECT_VERSION (below)
# keeps the full string for the string-typed fields (kVersionString/kFullVersionString).
version_conf.set('PROJECT_VERSION_MAJOR', meson.project_version().split('.')[0].to_int())
version_conf.set('PROJECT_VERSION_MINOR', meson.project_version().split('.')[1].to_int())
version_conf.set('PROJECT_VERSION_PATCH', meson.project_version().split('.')[2].split('-')[0].to_int())
version_conf.set('YUZU_BUILD_NUMBER', yuzu_build_number)
version_conf.set('YUZU_GIT_COMMIT_HASH', yuzu_git_commit_hash)
version_conf.set('PROJECT_VERSION', meson.project_version())

# ── Git-derived version tag ──────────────────────────────────────────────────
# Produces a header that is rebuilt whenever HEAD changes, so the version
# string always reflects the current commit (e.g. v0.5.0-42-gabcdef).
vcs_tag(
  input:   'sdk/include/yuzu/git_version.hpp.in',
  output:  'git_version.hpp',
  command: git.found() ? [git, 'describe', '--tags', '--always', '--dirty'] : ['echo', 'v' + meson.project_version()],
  fallback: 'v' + meson.project_version(),
)

# ── Feature summary ───────────────────────────────────────────────────────────
build_agent    = get_option('build_agent')
build_server   = get_option('build_server')
build_examples = get_option('build_examples')
build_tests    = get_option('build_tests')

# ── Dependencies ──────────────────────────────────────────────────────────────
# All third-party includes are marked `include_type: 'system'` so the compiler
# treats them as `-isystem` paths and suppresses their warnings. This is
# load-bearing for build log readability — without it the gRPC / abseil /
# protobuf deprecation warnings drown out our own code warnings and force a
# grep-for-error filter workflow. Our own code remains under `warning_level=3`.
if host_os == 'windows'
  # ──────────────────────────────────────────────────────────────────────
  # #375 option D: bypass meson's cmake dep for protobuf/grpc on Windows.
  # ──────────────────────────────────────────────────────────────────────
  # Meson's cmake dependency translator reads IMPORTED_LOCATION_RELEASE
  # from vcpkg's imported targets regardless of --buildtype=debug, so a
  # debug build with `dependency('protobuf', method: 'cmake', ...)` would
  # link release-CRT static libs into /MDd debug user code and trip
  # dozens of LNK2038 RuntimeLibrary mismatches. Dropping the triplet's
  # static-linkage override doesn't help either — vcpkg's grpc port
  # forces static regardless, and grpc.lib's embedded abseil template
  # symbols collide with abseil_dll.lib exports on release builds,
  # producing LNK2005 duplicate symbol errors. The only configuration
  # that threads both needles is static linkage in triplets/x64-windows.cmake
  # + this explicit find_library() wiring with build-type-conditional
  # search dirs. Keep BOTH halves in sync; neither can be simplified
  # alone. Full diagnosis:
  #   .claude/agents/build-ci.md "Windows MSVC static-link history and #375"
  # Strategic escape (P1): #376 "Migrate transport off gRPC to QUIC".

  _cxx = meson.get_compiler('cpp')
  _vcpkg_root_win = meson.project_source_root() / 'vcpkg_installed' / 'x64-windows'
  # include_directories() rejects absolute paths inside the source tree,
  # so the include dir has to be a relative-to-source-root string.
  # Headers are the same across debug and release variants, so this
  # points at the shared include/ regardless of buildtype.
  #
  # Two forms exist on purpose:
  #   * _vcpkg_include_win_rel — string path, used in run_command() / find_program()
  #     contexts that take a string (none today, but kept stable for diagnostics).
  #   * _vcpkg_inc_win         — IncludeDirs object captured once at the project
  #     root, safe to reuse across subdirs.
  #
  # include_directories() resolves a relative string path against the CURRENT
  # meson.build's source directory. Calling include_directories('vcpkg_installed/...')
  # from tests/meson.build would look for tests/vcpkg_installed/... and fail.
  # Capturing the IncludeDirs object here once anchors it to the project root;
  # subdirs can then reuse the same object via the project-global variable.
  _vcpkg_include_win_rel = 'vcpkg_installed/x64-windows/include'
  _vcpkg_inc_win = include_directories(_vcpkg_include_win_rel, is_system: true)
  if get_option('buildtype') == 'debug'
    _vcpkg_lib_win = _vcpkg_root_win / 'debug' / 'lib'
    _pbd = 'd'   # vcpkg convention: libprotobufd.lib / libprotobuf-lited.lib / libprotocd.lib / libupbd.lib
  else
    _vcpkg_lib_win = _vcpkg_root_win / 'lib'
    _pbd = ''
  endif

  # Enumerate absl_*.lib at configure time via python glob. The transitive
  # absl dep closure of protobuf+grpc is ~40 libs and shifts between
  # abseil versions; hand-listing would be a maintenance burden. Enumerating
  # here means a vcpkg abseil bump doesn't need a parallel meson.build edit.
  _py = find_program('python3')
  _absl_enum = run_command(
    _py, '-c',
    'import glob, os, sys\n' +
    'for p in sorted(glob.glob(os.path.join(sys.argv[1], "absl_*.lib"))):\n' +
    '    print(os.path.splitext(os.path.basename(p))[0])\n',
    _vcpkg_lib_win,
    check: true,
  )
  _absl_names = _absl_enum.stdout().strip().split('\n')
  if _absl_names.length() == 0 or (_absl_names.length() == 1 and _absl_names[0] == '')
    error('#375 option D: no absl_*.lib files found in @0@ — vcpkg install may be incomplete'.format(_vcpkg_lib_win))
  endif
  message('#375 option D: enumerated @0@ abseil libs from @1@'.format(_absl_names.length(), _vcpkg_lib_win))
  _absl_deps = []
  foreach _absl_name : _absl_names
    _absl_deps += _cxx.find_library(_absl_name, dirs: [_vcpkg_lib_win], required: true)
  endforeach

  # Protobuf core + transitive utf8_range.
  _libprotobuf      = _cxx.find_library('libprotobuf'      + _pbd, dirs: [_vcpkg_lib_win], required: true)
  _libprotobuf_lite = _cxx.find_library('libprotobuf-lite' + _pbd, dirs: [_vcpkg_lib_win], required: true)
  _libprotoc        = _cxx.find_library('libprotoc'        + _pbd, dirs: [_vcpkg_lib_win], required: true)
  _libupb           = _cxx.find_library('libupb'           + _pbd, dirs: [_vcpkg_lib_win], required: true)
  _libutf8_range    = _cxx.find_library('utf8_range',              dirs: [_vcpkg_lib_win], required: true)
  _libutf8_validity = _cxx.find_library('utf8_validity',           dirs: [_vcpkg_lib_win], required: true)

  # gRPC core + C++ API + transitive re2 / c-ares / address_sorting.
  _libgrpc             = _cxx.find_library('grpc',             dirs: [_vcpkg_lib_win], required: true)
  _libgrpcpp           = _cxx.find_library('grpc++',           dirs: [_vcpkg_lib_win], required: true)
  _libgpr              = _cxx.find_library('gpr',              dirs: [_vcpkg_lib_win], required: true)
  _libaddress_sorting  = _cxx.find_library('address_sorting',  dirs: [_vcpkg_lib_win], required: true)
  _libre2              = _cxx.find_library('re2',              dirs: [_vcpkg_lib_win], required: true)
  _libcares            = _cxx.find_library('cares',            dirs: [_vcpkg_lib_win], required: true)

  # OpenSSL — grpc.lib has unresolved references to BIO_*, EVP_*, PEM_*,
  # X509_*, OPENSSL_sk_* that only libssl + libcrypto can satisfy. vcpkg's
  # grpc port compiles its TLS / JWT / SPIFFE / PEM code paths against
  # OpenSSL headers regardless of any triplet or manifest hint that it
  # "should" use schannel — the schannel path was never wired up in the
  # upstream grpc port. See CLAUDE.md `## vcpkg` section and .claude/agents/
  # build-ci.md "Windows MSVC static-link history and #375" for history.
  _libssl    = _cxx.find_library('libssl',    dirs: [_vcpkg_lib_win], required: true)
  _libcrypto = _cxx.find_library('libcrypto', dirs: [_vcpkg_lib_win], required: true)

  # CLI11 — same build-type-conditional reasoning as protobuf/grpc above.
  # Meson's cmake dep would pick `lib/CLI11.lib` (release) for both debug
  # and release consumers, producing LNK2038 mismatches between debug
  # user code (/MDd, _ITERATOR_DEBUG_LEVEL=2) and release CLI11.lib's
  # Precompile.cpp.obj (/MD, =0). Hand-wire to the buildtype-specific
  # _vcpkg_lib_win directory so debug picks debug/lib/CLI11.lib.
  # CLI11's vcpkg port keeps the same name in both lib/ and debug/lib/
  # (no `d` suffix), so no _pbd handling needed here.
  _libcli11 = _cxx.find_library('CLI11', dirs: [_vcpkg_lib_win], required: true)

  # zlib — grpc.lib(message_compress.cc.obj) has unresolved references to
  # __imp_deflate / __imp_inflate / __imp_deflateInit2_ / __imp_inflateInit2_
  # etc. gRPC's message compression code path uses zlib for gzip-compressed
  # messages, and the `__imp_` prefix tells us zlib is built as a DLL
  # (vcpkg default) so we're linking zlib's import lib. Failure mode seen:
  # LNK2019 "unresolved external symbol __imp_deflate referenced in function
  # zlib_compress" from the option D first canary on commit 713ae8c.
  #
  # Naming quirk: vcpkg's zlib port uses the `d` suffix for debug variants
  # (lib/zlib.lib + debug/lib/zlibd.lib) — same convention as protobuf's
  # libprotobufd.lib. libcrypto/libssl above do NOT use the d suffix
  # (same name in both variant dirs). Check `debug/lib/` layout via the
  # inspect-vcpkg.sh diagnostic if a new transitive lib surfaces and you
  # aren't sure which convention it follows.
  _libzlib = _cxx.find_library('zlib' + _pbd, dirs: [_vcpkg_lib_win], required: true)

  # Construct the meson dep objects yuzu's build graph consumes. These
  # REPLACE the `dependency('protobuf', method: 'cmake')` / `dependency('gRPC',
  # method: 'cmake')` calls that Linux/macOS use — those paths are
  # unreachable on Windows.
  protobuf_dep = declare_dependency(
    include_directories: _vcpkg_inc_win,
    dependencies: [
      _libprotobuf, _libprotobuf_lite, _libprotoc, _libupb,
      _libutf8_range, _libutf8_validity,
    ] + _absl_deps,
  )
  grpcpp_dep = declare_dependency(
    include_directories: _vcpkg_inc_win,
    dependencies: [
      _libgrpcpp, _libgrpc, _libgpr, _libaddress_sorting,
      _libre2, _libcares,
      _libssl, _libcrypto,
      _libzlib,
      # grpc transitively uses protobuf and upb; include them so consumers
      # that only pull in grpcpp_dep still see protobuf's symbols.
      _libprotobuf, _libprotobuf_lite, _libupb, _libutf8_range, _libutf8_validity,
    ] + _absl_deps,
  )
  cli11_dep = declare_dependency(
    include_directories: _vcpkg_inc_win,
    dependencies: [_libcli11],
  )
else
  # Linux/macOS: meson's cmake dep method works correctly because gcc/clang
  # don't have MSVC's runtime-library variant ABI — debug user code can
  # safely link against release-built .a static libs, and the cmake dep
  # translator's IMPORTED_LOCATION_RELEASE bias is harmless.
  grpcpp_dep = dependency('gRPC', method: 'cmake', modules: ['gRPC::grpc++'],
    required: false, include_type: 'system')
  if not grpcpp_dep.found()
    grpcpp_dep = dependency('grpc++', method: 'pkg-config', required: true,
      include_type: 'system')
  endif
  protobuf_dep = dependency('protobuf', method: 'cmake', modules: ['protobuf::libprotobuf'],
    required: false, include_type: 'system')
  if not protobuf_dep.found()
    protobuf_dep = dependency('protobuf', method: 'pkg-config', required: true,
      include_type: 'system')
  endif
  cli11_dep = dependency('CLI11', method: 'cmake', modules: ['CLI11::CLI11'],
    required: true, include_type: 'system')
endif
add_project_arguments('-DSPDLOG_COMPILED_LIB', language: 'cpp')
spdlog_dep      = dependency('spdlog',        required: true, include_type: 'system')
nlohmann_dep    = dependency('nlohmann_json', required: true, include_type: 'system')
httplib_dep     = dependency('httplib', required: false, include_type: 'system')
if not httplib_dep.found()
  httplib_dep   = dependency('cpp-httplib', required: true, include_type: 'system')
endif
sqlite3_dep     = dependency('SQLite3', method: 'cmake', modules: ['SQLite::SQLite3'],
  required: true, include_type: 'system')

# libxml2 — real XML parsing for the autoruns plugin's Task Scheduler XML
# (agents/plugins/autoruns) and its portable test TU (both include
# autoruns_parsers.hpp, which parses via libxml2 unconditionally on every
# platform, not just Windows), AND for server/core's Windows-deferred SAML
# feature (server/core/meson.build reuses this SAME declaration rather than
# re-declaring it — do not add a second libxml2_dep anywhere; one global
# declaration, reused by every consumer). Declared here at root scope,
# UNCONDITIONALLY (no host_machine.system() guard) because autoruns needs it
# on every platform including Windows, even though SAML's own consumption of
# it is Windows-deferred — that gate says nothing about whether libxml2
# itself links on Windows. It does: libxml2 is not in
# triplets/x64-windows.cmake's static-linkage override list (scoped to
# abseil/grpc/protobuf/upb/re2/c-ares/utf8-range only, the #375 landmine), so
# it resolves as an ordinary dynamic DLL + import lib on Windows, same shape
# as sqlite3/libpq/openssl above.
libxml2_dep = dependency('LibXml2', method: 'cmake', modules: ['LibXml2::LibXml2'],
  required: false, include_type: 'system')
if not libxml2_dep.found()
  libxml2_dep = dependency('libxml-2.0', required: true, include_type: 'system')
endif

# libpq — Postgres client library for the server storage substrate (ADR-0006/
# ADR-0008). Server-only: the agent stays SQLite (ADR-0006), so agent-only
# (-Dbuild_server=false) and cross builds must not require libpq at configure.
#
# Linkage per platform: static .a on Linux/macOS (vcpkg static triplets);
# **dynamic DLL on Windows** — triplets/x64-windows.cmake's base linkage is
# dynamic and its static override is scoped to the grpc stack only, so vcpkg
# produces libpq.dll + import lib, same as sqlite3/openssl. The release zip's
# vcpkg-DLL sweep (release.yml `Get-ChildItem $vcpkgBin *.dll`) bundles it.
# Static libpq (unix) needs the companion libpgcommon/libpgport archives
# (scram/auth helpers) that neither cmake's FindPostgreSQL nor any imported
# target carries — only libpq.pc's Libs.private lists them, and pkg-config
# isn't wired to the vcpkg prefix in this build. So: resolve libpq via cmake
# (unix) or hand-wired find_library (windows, same reasoning as the #375
# protobuf/grpc block above), then add pgcommon/pgport explicitly. Pure-C
# libpq carries no MSVC detect_mismatch records, so the buildtype-conditional
# _vcpkg_lib_win selection is load-bearing — a wrong-CRT pick links silently
# rather than failing with LNK2038. Baseline-bump watch: a vcpkg libpq port
# moving to PostgreSQL 17/18's meson build may rename or drop the
# pgcommon/pgport archives — revisit this block on any baseline change.
if not build_server
  libpq_dep = disabler()
elif host_os == 'windows'
  _libpq_libs = []
  foreach _pq_name : ['libpq', 'libpgcommon', 'libpgport']
    _libpq_libs += _cxx.find_library(_pq_name, dirs: [_vcpkg_lib_win], required: true)
  endforeach
  # With dynamic libpq (the current triplet posture) the DLL self-contains
  # these; they are listed so a future flip of libpq to the static override
  # (SSPI auth paths + socket layer + OpenSSL) links without edits here.
  # Harmless overlinking today. libssl/libcrypto reused from the grpc block.
  foreach _pq_sys : ['ws2_32', 'secur32', 'advapi32', 'shell32', 'crypt32']
    _libpq_libs += _cxx.find_library(_pq_sys, required: true)
  endforeach
  libpq_dep = declare_dependency(
    include_directories: _vcpkg_inc_win,
    dependencies: _libpq_libs + [_libssl, _libcrypto],
  )
else
  libpq_dep = dependency('PostgreSQL', method: 'cmake', modules: ['PostgreSQL::PostgreSQL'],
    required: true, include_type: 'system')
  _pq_prefixes = get_option('cmake_prefix_path')
  _pq_extras = []
  foreach _pq_name : ['pgcommon', 'pgport']
    _pq_extras += cxx.find_library(_pq_name,
      dirs: _pq_prefixes.length() > 0 ? [_pq_prefixes[0] / 'lib'] : [],
      required: true)
  endforeach
  # vcpkg's libpq is built with the openssl feature, so libpq.a's TLS layer
  # (fe-secure-openssl.o) needs libssl/libcrypto at final link.
  _pq_openssl = dependency('openssl', required: true, include_type: 'system')
  libpq_dep = declare_dependency(dependencies: [libpq_dep] + _pq_extras + [_pq_openssl])
endif

# macOS frameworks needed by gRPC, abseil, and cpp-httplib
if host_os == 'darwin'
  corefoundation_dep = dependency('appleframeworks', modules: ['CoreFoundation', 'Security', 'CFNetwork'])
  grpcpp_dep  = declare_dependency(dependencies: [grpcpp_dep, corefoundation_dep])
  httplib_dep = declare_dependency(dependencies: [httplib_dep, corefoundation_dep])

  # ── Endpoint Security (shared probe, A0) ────────────────────────────────────
  # CORRECTION (A0 governance fix round): EndpointSecurity is NOT an
  # `.framework` bundle -- it ships as `usr/lib/libEndpointSecurity.tbd` +
  # `usr/include/EndpointSecurity/` in BOTH the Command Line Tools SDK and the
  # full Xcode SDK. The `dependency('appleframeworks', modules:
  # ['EndpointSecurity'])` probe below therefore NEVER succeeds on any SDK --
  # it always falls to the `else` branch below, so the real ES client never
  # compiles today. The correct probe (`cxx.find_library('EndpointSecurity')`
  # + `cxx.has_header('EndpointSecurity/EndpointSecurity.h')`) is a separate,
  # deliberately isolated behaviour change -- see the follow-up slice
  # (feat/macos-spark-a0.5-es-probe) rather than this comment-only fix. This
  # is the SINGLE probe site for every ES consumer in the tree: TAR's process
  # stream (tar_proc_es.cpp) and agent-core's pure ES helpers (es_client.hpp)
  # both consume endpoint_security_dep/_deps/_args instead of probing
  # independently (a shared full ES client lands in a later slice). Found:
  # real ES client compiles (-DYUZU_HAVE_ENDPOINT_SECURITY -fblocks; -fblocks
  # because the ES client passes an Objective-C block literal to
  # es_new_client, which Apple Clang does not enable by default for a .cpp
  # TU) and libbsm links (audit_token_to_pid / audit_token_to_ruid). Absent:
  # every consumer's #if-guarded no-op path is used instead -- see
  # docs/darwin-compat.md's EndpointSecurity pitfalls-table row.
  endpoint_security_dep = dependency('appleframeworks', modules: ['EndpointSecurity'],
                                     required: false, include_type: 'system')
  endpoint_security_deps = []
  endpoint_security_args = []
  if endpoint_security_dep.found()
    endpoint_security_deps += endpoint_security_dep
    endpoint_security_deps += cxx.find_library('bsm')
    endpoint_security_args += ['-DYUZU_HAVE_ENDPOINT_SECURITY', '-fblocks']
  else
    # rd-1 (governance A0 round-4, MEDIUM): this branch fires on EVERY host,
    # SDK present or not -- see the accurate CORRECTION comment 8 lines above
    # (the appleframeworks probe can never find EndpointSecurity, because it
    # is not a `.framework` bundle). The previous wording here ("EndpointSecurity
    # SDK not found") claimed the opposite and could resurrect the exact
    # "needs full Xcode SDK" myth this A0 slice exists to correct.
    message('EndpointSecurity probe cannot succeed on this SDK shape (appleframeworks '
          + 'has no EndpointSecurity.framework to find -- see the CORRECTION comment '
          + 'above; the SDK itself may well have the lib+header pair) -- ES-dependent '
          + 'code compiles as a no-op on this host.')
  endif

  # ── Reusable per-target Apple frameworks + Objective-C++/ARC template ──────
  # Meson has no user-defined functions, so "template" here means: the parts
  # of the wifi plugin's pioneering objcpp/ARC pattern (agents/plugins/wifi/
  # meson.build, the first .mm TU in the tree) that are IDENTICAL for every
  # future Objective-C++ plugin are hoisted here, ONCE, next to the framework
  # dependency this project already centralises; only the parts that
  # genuinely vary per target (which frameworks, which .mm sources) stay in
  # the plugin's own meson.build. A plugin consumes the template as:
  #
  #   if host_machine.system() == 'darwin'
  #     foo_sources += files('src/foo_thing.mm')
  #     foo_deps    += dependency('appleframeworks', modules: ['Whatever'],
  #                               include_type: 'system')
  #     foo_objcpp_args += apple_objcpp_args
  #   endif
  #
  # (the per-target `dependency('appleframeworks', modules: [...])` call itself
  # is NOT further factored — each target's module list is genuinely target-
  # specific, and Meson has no dict-kwarg-splat to fold it into one call; see
  # docs/native-objcpp-conventions.md for the "when is required:true correct"
  # rule that call must follow.)
  #
  # add_languages('objcpp') is a process-global registration — calling it once
  # here, rather than once per plugin, means a SECOND .mm-consuming plugin
  # after wifi needs no add_languages call of its own at all (harmless but
  # redundant if repeated). `native: false` matches wifi's original call
  # (host-side compiler; irrelevant to cross-compilation, which this project
  # does not do for macOS). `required: true` is deliberate, not a leftover:
  # every macOS host this project targets ships a working Objective-C++
  # front-end in the same Clang that already builds the C++ half, so a
  # failure here is a real toolchain problem, not a missing-optional-
  # framework case (that distinction belongs to the PER-FRAMEWORK
  # `dependency('appleframeworks', ...)` call in each target, not here).
  add_languages('objcpp', native: false, required: true)

  # objcpp is a separate Meson language from cpp, so this project's
  # `-std=c++23`/`-fvisibility=hidden` (set above for cpp only) do not reach a
  # .mm TU; every objcpp target must re-pass them via its own `objcpp_args:`.
  # Probe for the C++23 spelling rather than hardcoding it: Apple Clang 15
  # rejects raw `-std=c++23` and needs `-std=c++2b` (docs/ci-cpp23-
  # troubleshooting.md); newer Apple Clang accepts the canonical spelling, so
  # prefer it when available instead of pinning the older alias forever.
  # `-fobjc-arc` is included unconditionally: every objcpp TU in this project
  # keeps Objective-C object lifetimes ARC-managed (see
  # docs/native-objcpp-conventions.md) — there is no manual-retain-count
  # variant to opt out into.
  # xplat-A5: the native file's `cpp_args = ['-mmacosx-version-min=13.3']`
  # (meson/native/macos-appleclang.ini) is a cpp-language setting and never
  # reaches an objcpp TU (objcpp is its own Meson language, per the comment
  # above) — without repeating it here every .mm target silently compiles
  # against the build host's SDK default deployment target instead of the
  # project's pinned 13.3 floor. Keep this literal in sync with the native
  # file's cpp_args/cpp_link_args value.
  _apple_objcpp = meson.get_compiler('objcpp')
  _apple_objcpp_std = _apple_objcpp.has_argument('-std=c++23') ? '-std=c++23' : '-std=c++2b'
  apple_objcpp_args = [
    _apple_objcpp_std, '-fvisibility=hidden', '-fobjc-arc',
    '-mmacosx-version-min=13.3',
  ]
endif

# ── Proto codegen ─────────────────────────────────────────────────────────────
subdir('proto')

# ── SDK ───────────────────────────────────────────────────────────────────────
subdir('sdk')

# ── Agent ─────────────────────────────────────────────────────────────────────
if build_agent
  subdir('agents/core')
  # build_examples gates ONLY the four genuinely decorative demo plugins
  # below -- every other plugin is a real, shipped capability (several are
  # unconditional link_depends of tests/meson.build's yuzu_agent_tests
  # target) and must build regardless of this flag (#4262). Verified via
  # a grep sweep of every subdir name against the rest of the tree before
  # narrowing this list -- `netstat` (a real `attribution` action + a
  # dedicated real-plugin-by-path test) and `status` (a
  # dashboard-consumed key-value plugin) were the two closest calls and
  # are real, shipped plugins, not demos.
  if build_examples
    subdir('agents/plugins/example')
    subdir('agents/plugins/chargen')
    subdir('agents/plugins/procfetch')
    subdir('agents/plugins/netprobe')
  endif
  subdir('agents/plugins/netstat')
  subdir('agents/plugins/status')
  subdir('agents/plugins/device_identity')
  subdir('agents/plugins/os_info')
  subdir('agents/plugins/hardware')
  subdir('agents/plugins/users')
  subdir('agents/plugins/installed_apps')
  subdir('agents/plugins/msi_packages')
  subdir('agents/plugins/network_config')
  subdir('agents/plugins/diagnostics')
  subdir('agents/plugins/agent_actions')
  subdir('agents/plugins/processes')
  subdir('agents/plugins/services')
  subdir('agents/plugins/filesystem')
  subdir('agents/plugins/filesystem_posture')
  subdir('agents/plugins/windows_updates')
  subdir('agents/plugins/disk_actions')
  subdir('agents/plugins/disk_space')
  subdir('agents/plugins/event_logs')
  subdir('agents/plugins/sccm')
  subdir('agents/plugins/script_exec')
  subdir('agents/plugins/software_actions')
  subdir('agents/plugins/network_diag')
  subdir('agents/plugins/network_actions')
  subdir('agents/plugins/firewall')
  subdir('agents/plugins/antivirus')
  subdir('agents/plugins/bitlocker')
  subdir('agents/plugins/vuln_scan')
  subdir('agents/plugins/tags')
  subdir('agents/plugins/asset_tags')
  subdir('agents/plugins/quarantine')
  subdir('agents/plugins/certificates')
  subdir('agents/plugins/ioc')
  subdir('agents/plugins/storage')
  subdir('agents/plugins/interaction')
  subdir('agents/plugins/agent_logging')
  subdir('agents/plugins/http_client')
  subdir('agents/plugins/content_dist')
  subdir('agents/plugins/registry')
  subdir('agents/plugins/rdp_control')
  subdir('agents/plugins/wmi')
  subdir('agents/plugins/tar')
  subdir('agents/plugins/wifi')
  subdir('agents/plugins/wol')
  subdir('agents/plugins/discovery')
  subdir('agents/plugins/license_scan')
  subdir('agents/plugins/power_health')
  subdir('agents/plugins/autoruns')  # Wave 7 PR7.1
  subdir('agents/plugins/windows_optional_features')  # Wave 9 PR9.2b
  subdir('agents/plugins/peripherals')  # Wave 9 PR9.1a
  subdir('agents/plugins/app_usage')  # Wave 7b PR7b.3
  subdir('agents/plugins/execution_artifacts')  # Wave 7b PR7b.1
  subdir('agents/plugins/app_control')  # Wave 8 PR8.6
  subdir('agents/plugins/firmware_posture')  # Wave 8 PR8.4
  subdir('agents/plugins/platform_security')  # Wave 8 PR8.1-a1
  subdir('agents/plugins/system_hardening')  # Wave 8 PR8.1-b
  subdir('agents/plugins/printing')  # Wave 9 PR9.1b
  subdir('agents/plugins/runtimes')  # Wave 10 PR10.1-b
  subdir('agents/plugins/browser_inventory')  # Wave 10 P2a
  subdir('agents/plugins/pkg_inventory')  # Wave 10 PR10.1-c
endif

# ── Server ────────────────────────────────────────────────────────────────────
if build_server
  subdir('server/core')
endif

# ── Enterprise (commercial license; see enterprise/LICENSE-ENTERPRISE.md) ────
# This subtree is NOT covered by the AGPL license that governs the rest of
# the repository. It only builds when explicitly enabled via
# -Denable_enterprise=true, and doing so requires a commercial license.
if get_option('enable_enterprise')
  message('Building WITH enterprise modules — commercial license required (see enterprise/LICENSE-ENTERPRISE.md).')
  subdir('enterprise')
endif

# ── Tests ─────────────────────────────────────────────────────────────────────
if build_tests
  subdir('tests')
endif

# ── Fuzzers (libFuzzer harnesses; clang-only, see tests/fuzz/meson.build) ────
if get_option('build_fuzzers')
  subdir('tests/fuzz')
endif

# ── Capability-matrix generator (PR1.1 / #2204; IT-2) ────────────────────────
# Placed AFTER the build_fuzzers endif — OUTSIDE that conditional (PLAN-04: an
# insert right after subdir('tests/fuzz') would bury it inside the fuzzer gate
# and normal CI would never build it). Guarded on build_agent alone (the tool
# dlopens the built plugin shared objects to read their ABI4 descriptors) —
# every real plugin now builds unconditionally under build_agent regardless
# of build_examples (#4262), so there is always something for the generator
# to inspect; the former build_examples half of this guard predated that fix
# and no longer applies.
if build_agent
  subdir('tools/capmatrix-gen')
  # plugin-capture (docs/plugin-readme-standard.md rule 5): same guard, same
  # reason — it exists to run the built plugins.
  subdir('tools/plugin-capture')
endif

# docs-regen: rewrite every plugin README fence, the user-manual plugin index,
# the site nav fragment and the content/plugin-docs manifests from the
# committed sources (docs/plugin-readme-standard.md rule 9). Pure Python over
# the checked-in tree — no build products are read, so it is a run_target
# rather than a custom_target and never enters the default build graph.
run_target('docs-regen',
  command: [
    find_program('python3', 'python'),
    files('tools/plugin-doc-gen/plugin_doc_gen.py'),
    '--all', '--repo-root', meson.project_source_root(),
  ],
)

# ── Erlang Gateway (optional — requires rebar3 + Erlang/OTP) ─────────────
_rebar3 = find_program('rebar3', required: false)
if _rebar3.found()
  _gw_src = meson.project_source_root() / 'gateway'
  _gw_build_script = meson.project_source_root() / 'scripts' / 'build_gateway.py'
  # rebar3 must run from inside the gateway/ directory.
  # We use a Python wrapper instead of 'cmd /c cd ... && rebar3 compile'
  # because Ninja quotes compound commands as a single argument, which
  # breaks cmd.exe on Windows.
  custom_target('gateway',
    command: [find_program('python3'), _gw_build_script, _gw_src],
    output: '.gateway_built',
    build_always_stale: true,
    build_by_default: true,
    # console: stream rebar3 output live instead of letting Ninja buffer the
    # edge until completion — so a hung gateway build is visible in real time
    # (it previously showed nothing until the 120-min job timeout). Pairs with
    # the bounded timeout in build_gateway.py.
    console: true,
  )
  # ── Gateway tests (EUnit + Common Test) ──────────────────────────────
  _gw_test_script = meson.project_source_root() / 'scripts' / 'test_gateway.py'
  _python3 = find_program('python3')
  # The test script prepends OTP 28 / rebar3 paths to PATH internally,
  # handling the case where Meson inherits a system PATH with OTP 25.
  #
  # Each suite gets its own REBAR_BASE_DIR so the eunit and ct tests
  # never share `_build/test/lib/<dep>/` on disk. Meson schedules
  # tests in parallel by default, and two rebar3 processes writing
  # to the same ebin tree racing each other's `.bea#`→`.beam` rename
  # fired consistently on Windows MSVC as
  #     "failed to rename proper_orddict.bea# to proper_orddict.beam:
  #      no such file or directory"
  # (in `proper`, because parallel compile workers in both processes
  # both wrote temp files and one renamed before the other read).
  # Linux/macOS tolerated the race through atomic POSIX rename; the
  # isolation fix applies unconditionally so the race can't come
  # back if Linux kernel semantics ever change. `test_gateway.py`
  # honors REBAR_BASE_DIR when computing the ebin wipe path.
  # Timeout 600s — upper-bound safety net for the nightly Coverage and
  # sanitizer jobs on slower cloud runners (scw-eager-lumiere) where
  # parallel meson test execution can starve the eunit job of CPU.
  # Healthy runs finish in ~30-90s on a fast runner and are unaffected
  # by the upper bound. The previous 120s landed at exactly 120.03s on
  # nightly Coverage and killed the suite by SIGTERM; gateway eunit is
  # only reached during nightly anyway, so a generous bound is free.
  test('gateway eunit',
    _python3,
    args: [_gw_test_script, _gw_src, 'eunit'],
    suite: 'gateway',
    timeout: 600,
    env: {'REBAR_BASE_DIR': _gw_src / '_build_eunit'},
  )
  test('gateway ct',
    _python3,
    args: [_gw_test_script, _gw_src, 'ct'],
    suite: 'gateway',
    timeout: 300,
    env: {'REBAR_BASE_DIR': _gw_src / '_build_ct'},
  )
  message('Erlang gateway: enabled (rebar3 found)')
else
  message('Erlang gateway: skipped (rebar3 not found)')
endif

# ── Deploy DLLs (Windows) ────────────────────────────────────────────────
# Copies vcpkg dependency DLLs alongside executables and gathers plugin
# DLLs into builddir/plugins/ so the agent can find them at runtime.
if host_machine.system() == 'windows'
  _python3 = find_program('python3')
  _deploy_script = meson.project_source_root() / 'scripts' / 'deploy_build_dlls.py'
  _build_root = meson.project_build_root()

  # Derive the vcpkg DLL directory from cmake_prefix_path so we don't
  # depend on VCPKG_ROOT being set in every environment (e.g. CLion).
  _vcpkg_bin = ''
  _cmake_prefixes = get_option('cmake_prefix_path')
  foreach _prefix : _cmake_prefixes
    if _vcpkg_bin == ''
      if get_option('buildtype') == 'debug' or get_option('buildtype') == 'debugoptimized'
        _vcpkg_bin = _prefix / 'debug' / 'bin'
      else
        _vcpkg_bin = _prefix / 'bin'
      endif
    endif
  endforeach

  _deploy_args = ['--build-root', _build_root, '--triplet', 'x64-windows']
  if _vcpkg_bin != ''
    _deploy_args += ['--vcpkg-bin', _vcpkg_bin]
  endif
  if get_option('buildtype') == 'debug' or get_option('buildtype') == 'debugoptimized'
    _deploy_args += ['--debug']
  endif

  # Run at configure time so a fresh setup has all DLLs immediately
  run_command(_python3, _deploy_script, _deploy_args, check: false)

  # Run at build time so rebuilt plugins are always copied to plugins/
  custom_target('deploy_dlls',
    command: [_python3, _deploy_script] + _deploy_args,
    output: '.dlls_deployed',
    build_always_stale: true,
    build_by_default: true,
  )
endif

# ── Summary ───────────────────────────────────────────────────────────────────
summary({
  'Agent':      build_agent,
  'Server':     build_server,
  'Examples':   build_examples,
  'Tests':      build_tests,
  'Enterprise': get_option('enable_enterprise'),
}, section: 'Components')

summary({
  'OS':  host_os,
  'CPU': host_cpu,
}, section: 'Platform')
