# Locate protoc and grpc_cpp_plugin.  When PATH doesn't include the vcpkg
# tools directories (e.g. CLion builds), fall back to the vcpkg install tree
# using cmake_prefix_path (set automatically by vcpkg toolchain integration).
_protoc_extra_dirs = []
_grpc_extra_dirs   = []
_cmake_prefixes = get_option('cmake_prefix_path')
foreach _prefix : _cmake_prefixes
  _protoc_extra_dirs += _prefix / 'tools' / 'protobuf'
  _grpc_extra_dirs   += _prefix / 'tools' / 'grpc'
endforeach

protoc = find_program('protoc',
  dirs: _protoc_extra_dirs,
  required: true,
)

# Log protoc version for build reproducibility
_protoc_ver = run_command(protoc, '--version', check: false)
if _protoc_ver.returncode() == 0
  message('protoc version: ' + _protoc_ver.stdout().strip())
endif

grpc_cpp_plugin = find_program('grpc_cpp_plugin',
  dirs: _grpc_extra_dirs,
  required: true,
)

proto_root = meson.current_source_dir()

gen = custom_target(
    'all_proto_gen',
    input: [
        proto_root / 'yuzu/common/v1/common.proto',
        proto_root / 'yuzu/agent/v1/agent.proto',
        proto_root / 'yuzu/guardian/v1/guaranteed_state.proto',
        proto_root / 'yuzu/server/v1/management.proto',
        proto_root / 'yuzu/gateway/v1/gateway.proto',
        proto_root / 'yuzu/reflex/v1/reflex.proto',
    ],
    output: [
        'common.pb.cc', 'common.pb.h', 'common.grpc.pb.cc', 'common.grpc.pb.h',
        'agent.pb.cc',  'agent.pb.h',  'agent.grpc.pb.cc',  'agent.grpc.pb.h',
        'guaranteed_state.pb.cc', 'guaranteed_state.pb.h',
        'guaranteed_state.grpc.pb.cc', 'guaranteed_state.grpc.pb.h',
        'management.pb.cc', 'management.pb.h', 'management.grpc.pb.cc', 'management.grpc.pb.h',
        'gateway.pb.cc', 'gateway.pb.h', 'gateway.grpc.pb.cc', 'gateway.grpc.pb.h',
        'reflex.pb.cc', 'reflex.pb.h', 'reflex.grpc.pb.cc', 'reflex.grpc.pb.h',
    ],
    command: [
        find_program('python3', 'python'),
        files('gen_proto.py'),
        '@OUTDIR@',
        protoc.full_path(),
        grpc_cpp_plugin.full_path(),
        proto_root,
        proto_root / 'yuzu/common/v1/common.proto',
        proto_root / 'yuzu/agent/v1/agent.proto',
        proto_root / 'yuzu/guardian/v1/guaranteed_state.proto',
        proto_root / 'yuzu/server/v1/management.proto',
        proto_root / 'yuzu/gateway/v1/gateway.proto',
        proto_root / 'yuzu/reflex/v1/reflex.proto',
    ],
)

# Twelve source files (even indices) and twelve headers (odd indices), in
# input order: common, agent, guaranteed_state, management, gateway, reflex
# — each with .pb + .grpc.pb pairs.
gen_srcs = [gen[0],  gen[2],  gen[4],  gen[6],  gen[8],  gen[10],
            gen[12], gen[14], gen[16], gen[18], gen[20], gen[22]]
gen_hdrs = [gen[1],  gen[3],  gen[5],  gen[7],  gen[9],  gen[11],
            gen[13], gen[15], gen[17], gen[19], gen[21], gen[23]]

# Override the project-wide -fvisibility=hidden so that proto symbols baked
# into a consumer shared_library (libyuzu_agent_core.so /
# libyuzu_server_core.so) end up in the .so's dynamic symbol table. Without
# this, downstream test binaries that need proto symbols are forced to
# relink yuzu_proto.a directly, which puts a second copy of every .pb.o's
# static descriptor-registration into the process and trips protobuf's
# "File already exists in database" CHECK at startup under ASan (#572).
# Per-target cpp_args wins because project arguments are emitted first; the
# meson `gnu_symbol_visibility` kwarg is emitted before project args and
# loses the last-flag-wins fight against `add_project_arguments`. MSVC has
# no default-hidden behaviour, so the override is GCC/Clang only.
_proto_visibility_args = cxx.get_id() == 'msvc' ? [] : ['-fvisibility=default']

yuzu_proto_lib = static_library(
    'yuzu_proto',
    gen_srcs,
    cpp_args: (cxx.get_id() == 'msvc'
      ? ['/wd4100','/wd4267','/wd4244','/wd4458','/wd4018','/wd4996']
      : ['-Wno-unused-parameter', '-Wno-array-bounds']) + _proto_visibility_args,
    include_directories: include_directories('.'),
    dependencies: [grpcpp_dep, protobuf_dep],
)

yuzu_proto_dep = declare_dependency(
    link_with: yuzu_proto_lib,
    sources: gen_hdrs,
    include_directories: include_directories('.'),
    dependencies: [grpcpp_dep, protobuf_dep],
)

# Header-only sibling of yuzu_proto_dep — same include path + generated-
# header ordering, but no link_with. Use this for any target that already
# pulls the proto symbols in transitively via a shared_library (#572).
yuzu_proto_headers_dep = declare_dependency(
    sources: gen_hdrs,
    include_directories: include_directories('.'),
    dependencies: [grpcpp_dep, protobuf_dep],
)