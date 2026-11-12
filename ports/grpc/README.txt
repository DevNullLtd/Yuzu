Yuzu gRPC overlay

Upstream port: microsoft/vcpkg ports/grpc at baseline
9eec002df1cd109f8f104cd966a763daf9751489 (gRPC1.81.1, port revision0).
Local revision1 adds only 00017-openssl-worker-cleanup.patch to that recipe.

Why: detached EventEngine workers decrement the quiescence count before their
OS thread-local destructors run. A process may consequently begin OpenSSL global
cleanup while worker DRBG cleanup is still accessing the default library context.
The secure grpc target now calls OPENSSL_thread_stop after draining its worker
callbacks, before deleting ThreadState and publishing worker retirement.
The compile definition is PRIVATE to grpc, not grpc_unsecure or standalone
EventEngine targets. BoringSSL/LibreSSL builds retain their own behavior.

Application obligation: stop and join caller-owned crypto threads and own/drain
the default EventEngine before process exit. This patch is not a general thread
join, does not cover custom engines, and does not authorize using OpenSSL after
global cleanup. The Yuzu server test runner supplies its suite's engine owner;
agent fixtures retain scoped ownership to preserve their pre-fork quiescence.

When changing the vcpkg baseline, refresh this full upstream port directory,
reapply/review the local patch, and rebuild the sanitizer dependencies. Overlay
ports override registry resolution: a baseline bump alone does not upgrade this
copy. Preserve the upstream archive hash and existing patches. Remove this
overlay once an upstream release supplies an equivalent lifetime guarantee.
