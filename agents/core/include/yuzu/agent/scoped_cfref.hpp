#pragma once

/**
 * scoped_cfref.hpp -- move-only RAII owner for a CoreFoundation object.
 *
 * CoreFoundation's Create/Copy Rule hands the caller a +1 owning reference
 * from any `Create`/`Copy` function (CFStringCreate*, SCDynamicStoreCopy*,
 * CFArrayCreate*, ...) that the caller must balance with exactly one
 * `CFRelease`. `ScopedCFRef<T>` adopts that reference and calls `CFRelease`
 * on destruction, move-out, or an explicit reset() -- no double-release, no
 * leak past an early return or a thrown exception. Apple-only (guarded
 * `#if defined(__APPLE__)`): CoreFoundation.h exists nowhere else.
 *
 * Templated on the specific CF pointer typedef (`CFStringRef`,
 * `CFDictionaryRef`, ...) rather than the erased `CFTypeRef`, so a caller's
 * variable keeps its real static type (`ScopedCFRef<CFStringRef>::get()`
 * returns `CFStringRef`, no cast needed at the call site) while still
 * releasing through the common `CFRelease(CFTypeRef)` -- every CF pointer
 * type converts implicitly to `CFTypeRef` for that one call.
 *
 * Deliberately does NOT call CFRetain anywhere: this wraps an ALREADY-OWNED
 * (+1) reference, matching the Create/Copy Rule the CF APIs this is meant
 * for (nstat/SCNetwork/CoreWLAN-adjacent CF calls) always hand back. A
 * "borrow + retain" wrapper for the Get Rule (non-owned references from a
 * `CFArrayGetValueAtIndex`-style getter) is a different contract and is not
 * this type -- adding one is out of scope here (genuinely-absent primitive,
 * not a redesign of CF ownership handling).
 *
 * On reset()'s same-identity behaviour: this type's contract is the OPPOSITE
 * of ScopedFd's (scoped_fd.hpp) -- see reset() below, and that header's own
 * doc comment for the full three-way cross-reference (ScopedFd / this type &
 * ScopedIOObject / subprocess_runner.cpp's file-local UniqueFd).
 */

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>

#include <utility> // std::exchange

namespace yuzu::agent {

/// Owns exactly one +1 CoreFoundation reference of type `T` (a CF pointer
/// typedef, e.g. `CFStringRef`); releases it on destruction, move, or reset().
template <typename T>
class ScopedCFRef {
public:
    ScopedCFRef() noexcept = default;

    /// Adopts `ref` -- the caller must already own a +1 reference (the
    /// result of a Create/Copy call), never a borrowed (Get Rule) one.
    explicit ScopedCFRef(T ref) noexcept : ref_(ref) {}

    ScopedCFRef(const ScopedCFRef&) = delete;
    ScopedCFRef& operator=(const ScopedCFRef&) = delete;

    ScopedCFRef(ScopedCFRef&& other) noexcept : ref_(other.release()) {}
    ScopedCFRef& operator=(ScopedCFRef&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    ~ScopedCFRef() { reset(); }

    /// The raw reference, or nullptr if this instance owns nothing.
    /// Ownership is retained -- do not CFRelease the result.
    [[nodiscard]] T get() const noexcept { return ref_; }

    [[nodiscard]] bool valid() const noexcept { return ref_ != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    /// Give up ownership without releasing; the caller now owns the +1
    /// reference and is responsible for its eventual CFRelease.
    [[nodiscard]] T release() noexcept { return std::exchange(ref_, nullptr); }

    /// Release the currently-owned reference (if any) and adopt `ref`
    /// instead (default nullptr: own nothing). `ref`, like the constructor
    /// argument, must already be a +1 owning reference.
    void reset(T ref = nullptr) noexcept {
        // `ref` is a +1 OWNED reference — the caller transfers ownership. It is
        // consumed even when it shares object identity with the current ref_,
        // because a same-identity +1 is a DISTINCT retain obligation: an earlier
        // self-reset guard that returned early on `ref == ref_` (BR-008) LEAKED
        // that +1 (CDX-004, reproduced — `CFRetain(obj); reset(obj)` left the
        // retain count at 2, not 1). A bare `reset(get())` is caller misuse —
        // `get()` is a BORROWED reference, not a +1 — and is a precondition
        // violation, not something this method silently absorbs.
        if (ref_ != nullptr)
            CFRelease(ref_);
        ref_ = ref;
    }

private:
    T ref_ = nullptr;
};

} // namespace yuzu::agent

#endif // __APPLE__
