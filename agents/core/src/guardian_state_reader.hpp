#pragma once

// GuardianStateReader - the production IStateReader for the Guardian spark
// runtime (rung 5). Resolves live endpoint state for the three event-driven
// guard types the runtime re-reads on every initial / event / convergence pass
// (an event is a hint; the verdict always comes from a live re-read):
//   * file     - handle-scoped, #807-safe (file_hash.hpp); cross-platform.
//   * registry - RegOpenKeyExW + RegQueryValueExW, G4-encoded; Windows only
//                (Unknown on other platforms, where a registry rule cannot arm).
//   * service  - sd_bus ActiveState (Linux) / SCM QueryServiceStatusEx (Windows);
//                a truly absent unit/service folds to Stopped (R5); other
//                platforms report Unknown.
//
// THREAD-SAFE VIA THE EXECUTOR: each read body is a self-contained free function
// that resolves from its own params/plan using only locals plus OS handles it
// opens and closes within the call. The convergence lanes and the consumer
// handler may call the reader concurrently for different keys; the shared
// GuardianIoExecutor member is the only mutable state and is internally
// synchronised.
//
// BOUNDED / CANCELLABLE (F3): every read runs on a detached worker via the
// GuardianIoExecutor with a per-class deadline (file-hash ~15s, file-metadata-only
// / registry / service 5s), single-flighted per canonical spark_key and
// bulkheaded per type. A read that exceeds its deadline (a network/FUSE mount
// stall, a wedged SCM, a hung sd-bus broker) degrades to Unknown instead of
// hanging a lane join or the consumer detach; the wedged worker is decoupled, not
// force-cancelled (a D-state syscall cannot be cancelled or joined). request_stop()
// (from begin_stop(), including ~GuardianSparkRuntime) wakes any waiter and rejects
// new reads. The reader never fabricates an absent/stopped from a failure - it
// degrades to Unknown.
//
// ORPHAN-EXIT OBLIGATION: a decoupled worker may still be running a kernel/library
// call after the reader is destroyed. active_io_workers() surfaces the executor's
// live worker count (total + per class); the process MUST NOT perform normal C++
// static/DSO teardown while it is > 0 (a detached worker in libc/OpenSSL/sd-bus
// through teardown is UB). The enforcement (main taking _exit after a bounded
// grace) is a tracked rung-7 / separate-PR dependency; see guardian_io_executor.hpp.
//
// Unknown vs Known is the load-bearing distinction: a DEFINITIVE negative (file
// ENOENT, registry key/value not found, systemd NoSuchUnit, SCM
// ERROR_SERVICE_DOES_NOT_EXIST) is a KNOWN snapshot (absent / stopped) that the
// evaluator turns into a real verdict; a TRANSIENT fault (EMFILE, ACCESS_DENIED,
// a bus transport blip, a mid-transition *_PENDING / activating state, or a bounded
// I/O failure from the executor) is UNKNOWN, so the evaluator leaves the compliance
// verdict untouched and raises guard.unhealthy instead of a false drift.

#include <yuzu/plugin.h> // YUZU_EXPORT

#include "guardian_io_executor.hpp"   // GuardianIoExecutor + IoClass
#include "guardian_spark_runtime.hpp" // IStateReader + seam types (plan/snapshot/params)

#include <cstddef>

namespace yuzu::agent {

class YUZU_EXPORT GuardianStateReader : public IStateReader {
public:
    ReadResult<FileSnapshot> read_file(const FileSparkParams& p, const FileReadPlan& plan) override;
    RegistryRead read_registry(const RegistrySparkParams& p, const RegistryReadPlan& plan) override;
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams& p) override;
    // executor_.stop() is not itself noexcept (it takes a mutex, and
    // std::mutex::lock() is permitted to throw std::system_error), so this must
    // contain any exception itself rather than merely avoid causing one - an
    // escape here would std::terminate the agent (this runs from begin_stop(),
    // including ~GuardianSparkRuntime()). The critical section is bounded and
    // I/O-free (see the stop() contract note), so in practice this never throws.
    void request_stop() noexcept override {
        try {
            executor_.stop();
        } catch (...) {
        }
    }

    /// Live bounded-I/O worker count (orphan-exit obligation, see the header note).
    [[nodiscard]] std::size_t active_io_workers() const { return executor_.active_worker_count(); }
    [[nodiscard]] std::size_t active_io_workers(IoClass c) const {
        return executor_.active_worker_count(c);
    }

private:
    GuardianIoExecutor executor_;
};

} // namespace yuzu::agent
