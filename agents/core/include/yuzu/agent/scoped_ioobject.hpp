#pragma once

/**
 * scoped_ioobject.hpp -- move-only RAII owner for an IOKit `io_object_t`.
 *
 * Every IOKit lookup/iterator call (`IOServiceGetMatchingService`,
 * `IOIteratorNext`, `IORegistryEntryGetChildEntry`, ...) hands back an
 * `io_object_t` -- a Mach port name -- that the caller must balance with
 * exactly one `IOObjectRelease`, mirroring CoreFoundation's Create/Copy Rule
 * one level down the stack (IOKit is itself built on CF). `ScopedIOObject`
 * adopts that reference and releases it on destruction, move-out, or an
 * explicit reset() -- no double-release, no leaked Mach port past an early
 * return or a thrown exception. Apple-only (guarded `#if defined(__APPLE__)`
 * -- IOKit exists nowhere else.
 *
 * Not a template like `ScopedCFRef<T>`: every IOKit accessor this wrapper is
 * meant for already returns the single `io_object_t` type (iterators,
 * services, and registry entries), so one concrete wrapper covers every
 * such caller.
 *
 * NOT for an `io_connect_t` returned by `IOServiceOpen`: although
 * `io_connect_t` is a typedef of `io_object_t`, Apple's `IOServiceClose`
 * does more than release the underlying Mach port -- it first makes the
 * `io_service_close` call that actually closes the user-client connection
 * in the kernel, then releases. Calling `IOObjectRelease` on a connection
 * skips that close step, leaving the user client instantiated in the
 * kernel even though the local reference is gone. A connection needs a
 * distinct owner with `IOServiceClose` as its deleter, not this wrapper.
 *
 * On reset()'s same-identity behaviour: this type's contract mirrors
 * ScopedCFRef's and is the OPPOSITE of ScopedFd's (scoped_fd.hpp) -- see
 * reset() below, and scoped_fd.hpp's own doc comment for the full three-way
 * cross-reference (ScopedFd / ScopedCFRef & this type / subprocess_runner.cpp's
 * file-local UniqueFd).
 */

#if defined(__APPLE__)

#include <IOKit/IOKitLib.h>

#include <utility> // std::exchange

namespace yuzu::agent {

/// Owns exactly one IOKit `io_object_t` reference; releases it via
/// `IOObjectRelease` on destruction, move, or reset().
class ScopedIOObject {
public:
    ScopedIOObject() noexcept = default;

    /// Adopts `obj` -- the caller must already own the reference (the
    /// result of an IOKit lookup/iterator call), not a borrowed one.
    explicit ScopedIOObject(io_object_t obj) noexcept : obj_(obj) {}

    ScopedIOObject(const ScopedIOObject&) = delete;
    ScopedIOObject& operator=(const ScopedIOObject&) = delete;

    ScopedIOObject(ScopedIOObject&& other) noexcept : obj_(other.release()) {}
    ScopedIOObject& operator=(ScopedIOObject&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    ~ScopedIOObject() { reset(); }

    /// The raw io_object_t, or IO_OBJECT_NULL if this instance owns nothing.
    /// Ownership is retained -- do not IOObjectRelease the result.
    [[nodiscard]] io_object_t get() const noexcept { return obj_; }

    [[nodiscard]] bool valid() const noexcept { return obj_ != IO_OBJECT_NULL; }
    explicit operator bool() const noexcept { return valid(); }

    /// Give up ownership without releasing; the caller now owns the
    /// reference and is responsible for its eventual IOObjectRelease.
    [[nodiscard]] io_object_t release() noexcept {
        return std::exchange(obj_, IO_OBJECT_NULL);
    }

    /// Release the currently-owned object (if any) and adopt `obj` instead
    /// (default IO_OBJECT_NULL: own nothing).
    void reset(io_object_t obj = IO_OBJECT_NULL) noexcept {
        // `obj` is a +1 OWNED reference — the caller transfers ownership. It is
        // consumed even when it shares identity with the current obj_, because a
        // same-identity +1 is a DISTINCT retain obligation: an earlier self-reset
        // guard that returned early on `obj == obj_` (BR-008) LEAKED that +1
        // (CDX-004, the IOObjectRetain twin of the reproduced CFRetain leak). A
        // bare `reset(get())` is caller misuse — `get()` is a BORROWED reference,
        // not a +1 — and is a precondition violation, not silently absorbed.
        if (obj_ != IO_OBJECT_NULL)
            IOObjectRelease(obj_);
        obj_ = obj;
    }

private:
    io_object_t obj_ = IO_OBJECT_NULL;
};

} // namespace yuzu::agent

#endif // __APPLE__
