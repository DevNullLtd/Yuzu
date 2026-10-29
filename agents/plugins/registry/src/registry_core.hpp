#pragma once

/**
 * registry_core.hpp -- the registry plugin's write logic over an INJECTED registry (OS-free: unit-tested
 * on every host against an in-memory fake; the Win32 binding is registry_win.cpp's Win32Registry).
 *
 * MUTATION TARGETING (the check-to-use closure): every mutation runs on a CHECKED HANDLE and nothing
 * re-resolves a path by name; keys are deleted by handle (NtDeleteKey), never RegDeleteKeyW(parent, name).
 * Every operation captures the previous value first and reads back on the same handle after mutating.
 * Mechanism and residuals: README "How it works"; the invariants: routed-concerns-security-posture.md, registry
 * row. open_checked obtains the handle one of two ways:
 *
 *  - the WALK (the reference, and the only path that produces a verdict token or creates a key): the path
 *    component by component, each opened from the previous HANDLE with REG_OPTION_OPEN_LINK and probed for
 *    `SymbolicLinkValue` (a hit refuses `key_is_link`). The probes alone leave a window: a link is made in two
 *    steps (the key, then its `SymbolicLinkValue`), so one completed after its probe is followed by the next
 *    relative open, and a component renamed away leaves the handle bound to the object at its new name. The
 *    walk therefore ends on the fast open's own test: the canonical name of the leaf handle has to equal the
 *    canonical name of the FIRST component's handle (read right after that open, before its probe, and itself
 *    required to end in the requested first component) plus the remaining requested components, ASCII
 *    case-insensitively, else `key_is_link`; a name that cannot be read refuses with its win32 token. One
 *    derivation serves every hive, HKCU and HKCR included. A create is relative to a handle the kernel parses
 *    again, so it can land beneath a link completed meanwhile. The keys a creating walk made stay owned by the
 *    returned Opened (the leaf included) until commit(), which the verified write calls once it is over; its
 *    destructor is the rollback. So a walk that does not hand its leaf over (the name test refuses, or a later
 *    create fails or finds its key already there) and an exception anywhere from the first create to the end of the
 *    verified write both try to delete (best effort) every key the walk created, by its own handle, leaf first, after the value the
 *    write set (when it had landed). A key that still holds a value or a subkey the walk did not put there is
 *    kept, and `created` reports every key that could not be deleted. A key a create merely opened is closed,
 *    never deleted.
 *  - the FAST open (open_fast; HKLM and HKU only): ONE open_path of the whole path with REG_OPTION_OPEN_LINK,
 *    then final_name -- the kernel's canonical name of the object the handle is bound to -- is compared
 *    with `<root kernel name>\<requested path>` (ASCII case-insensitively, every other byte exactly) and the
 *    leaf is probed. ACCEPT needs all three; any other outcome closes the handle and falls back to the walk.
 *
 * SOUNDNESS RULE (the fast open is one-way: it may only ACCEPT): fast ACCEPT => the handle is bound to the
 * object whose kernel name is the requested canonical path, and no real link (a key the kernel resolves as a
 * link) was traversed. Why: the kernel follows an intermediate link to its target, so the object it opens is
 * named by the TARGET path; a link object has no children, so the link's own path is never an ancestor of
 * the object it redirects to, and that object's canonical name cannot equal the requested name. The handle is
 * bound to the object, so a later swap of a path component cannot redirect the mutation. This implies the
 * walk's ACCEPT of the same object EXCEPT for two ancestor-only divergences, where the walk is the stricter
 * of the two (in both the write still lands on the real requested key, as 1.0.0's single RegOpenKeyExW did):
 *  (i)  an ancestor the caller may traverse but not read: the walk reports access_denied, the fast open
 *       accepts;
 *  (ii) an ordinary non-link ancestor carrying a decoy VALUE named SymbolicLinkValue: probe_link reports
 *       key_is_link on any successful query whatever the value's type, so the walk refuses, the fast open
 *       accepts.
 * A decoy on the LEAF of a set_value or delete_value is refused on both paths (the same probe); a delete_key
 * leaf is opened as a possible link (leaf_may_be_link) and is not probed on either path. A non-ASCII case variant, a failed or
 * overflowing final_name and a failed root_name all fall back to the walk (which refuses the non-ASCII variant,
 * its own name tests using the same ASCII-only fold). No handle outlives one command.
 *
 * The walk's ACCEPT carries the same kind of guarantee (see its bullet): the leaf handle's kernel name is the
 * first component's name plus the remaining requested components, so a link completed after its probe, or a
 * component moved by a rename, refuses `key_is_link` instead of landing the write on the object it now reaches.
 * A same-path substitution (a plain key recreated at the requested name) is not a redirect and stays out of scope.
 *
 * RECURSIVE delete_key (count_tree, delete_subtree): RegDeleteTreeW is never called (it follows a link found inside
 * the tree). The vet walk opens every child from its parent's HANDLE with REG_OPTION_OPEN_LINK and probes it for a
 * link (a hit refuses key_is_link); it is a SIZE BOUND (kMaxTreeNodes keys and values, kMaxTreeDepth levels) and a link
 * sweep, NOT a membership list. The delete walk re-opens and re-probes every child it finds AT DELETE TIME and removes
 * it post-order by its own handle, so a key added after the vet is deleted and counted like any other (it sits under the
 * key the operator named), a link added after the vet is refused key_is_link, and a tree that outgrew the bound stops
 * concurrent_change; the counts it reports are what it REMOVED.
 *
 * `apply` (run_apply) opens each DISTINCT key of a plan once on a checked handle and reuses it for the later value
 * items on that key; one verdict function (refusal_reason) is taken over the same facts in a dry run and a real run, and
 * a real run mutates only after it. Each item's rows (audit line, item row, undo rows) are written as the item
 * concludes, before the next item opens anything. The undo manifest is bounded by ONE budget (CaptureBudget).
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "registry_parsers.hpp"
#include "registry_plan.hpp"

namespace yuzu {
class CommandContext;
class Params;
} // namespace yuzu

namespace yuzu::registry {

/// The Windows shell's entry point (registry_win.cpp); registry_plugin.cpp dispatches into it.
int execute_windows(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params);

using Handle = std::uintptr_t;

// Registry access rights, mirrored (registry_win.cpp static_asserts each against the SDK).
inline constexpr std::uint32_t kKeyQueryValue = 0x0001;
inline constexpr std::uint32_t kKeySetValue = 0x0002;
inline constexpr std::uint32_t kKeyCreateSubKey = 0x0004;
inline constexpr std::uint32_t kKeyEnumerateSubKeys = 0x0008;
inline constexpr std::uint32_t kAccessDelete = 0x00010000;

struct QueryResult {
    std::uint32_t type = 0;
    std::size_t size = 0;             ///< the value's full size in bytes
    std::vector<std::uint8_t> bytes;  ///< its first min(size, cap) bytes; empty when size > the reader's own bound
};

/// The Win32 value read over an injected `raw(type*, data*, size*) -> long` that mirrors RegQueryValueExW
/// (`data == nullptr` asks for the size only, whatever `*size` holds). Fills `out` like
/// RegistryWriter::query_value: the full size, and the first min(size, cap) bytes (none when `cap` is
/// 0 or the value is larger than `max_read`). A read that needs bytes (`cap` > 0) makes ONE data call into a
/// small stack buffer first: a value that fits (the common case) costs one call; a bigger one answers
/// ERROR_MORE_DATA with its size and is read into a buffer of that size. The size-only question (`cap` 0, or a
/// value past `max_read`) is the null-data call. EVERY data call gets non-null storage of at least one byte: a
/// null lpData would turn a value that grew 0 -> N between calls into a size answer over an empty buffer
/// (win_profiles.hpp, #2771 P2-N5). A value that keeps growing is retried three times, then answered
/// kErrorMoreData; a count the buffer cannot hold never forms a copy range.
template <class Raw>
[[nodiscard]] long query_value_bounded(std::size_t cap, Raw&& raw, QueryResult& out,
                                       std::size_t max_read = kMaxWriteBytes) {
    std::uint32_t type = 0;
    std::uint32_t size = 0;
    if (cap != 0) {
        std::uint8_t first[256];
        std::uint32_t got = sizeof first;
        const long rc = raw(&type, first, &got);
        if (rc == kErrorSuccess && got <= sizeof first) {
            out.type = type;
            out.size = got;
            out.bytes.assign(first, first + (got <= max_read ? std::min<std::size_t>(got, cap) : 0));
            return kErrorSuccess;
        }
        if (rc != kErrorSuccess && rc != kErrorMoreData) return rc;
        size = got; // larger than the first buffer: the size the call reported
    }
    if (size == 0 || size > max_read) // size unknown, or the answer is size-only: ask for it (it also yields the type)
        if (const long rc = raw(&type, nullptr, &size); rc != kErrorSuccess) return rc;
    out.type = type;
    out.size = size;
    out.bytes.clear();
    if (cap == 0 || size > max_read) return kErrorSuccess; // the caller sees the size and no bytes
    std::vector<std::uint8_t> buf(size > 0 ? size : 1);
    for (int attempt = 0; attempt < 3; ++attempt) {
        std::uint32_t got = static_cast<std::uint32_t>(buf.size());
        const long rc = raw(&type, buf.data(), &got);
        if (rc != kErrorSuccess && rc != kErrorMoreData) return rc;
        // The value grew between the two reads, or SUCCESS reported a count the buffer cannot hold (never form the
        // copy range from it): one arm, so both honour the ceiling.
        if (rc == kErrorMoreData || got > buf.size()) {
            if (got > max_read) {
                out.type = type;
                out.size = got;
                return kErrorSuccess;
            }
            buf.resize(got);
            continue;
        }
        out.type = type;
        out.size = got;
        out.bytes.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(got, cap)));
        return kErrorSuccess;
    }
    return kErrorMoreData; // kept growing: win32:234
}

/// The registry as the write logic sees it. Raw `long` Win32 codes and out-parameters by design (an
/// exception to cpp-conventions' std::expected rule): each method mirrors one Win32 call so the
/// shell is a thin binding and the fake can inject any return code per call. The same exception, for
/// the same reason, covers the two free functions that sit directly on one raw call: query_value_bounded
/// (above; it drives the RegQueryValueExW-shaped `raw` callable and fills the seam's QueryResult) and the
/// shell's query_key_name (registry_win.cpp; one NtQueryKey call). Everything built on the seam returns by
/// value, with one exception: `write_value_on` takes a `bool* landed` output parameter, because the fact that
/// the value landed must be published before the read-back can throw so that Opened's destructor can roll the
/// value back; it is consumed immediately and never retained. Names are UTF-8.
struct RegistryWriter {
    RegistryWriter() = default;
    RegistryWriter(const RegistryWriter&) = delete;
    RegistryWriter& operator=(const RegistryWriter&) = delete;
    virtual ~RegistryWriter() = default;

    /// Opens `name` under `parent` with REG_OPTION_OPEN_LINK. `out` is set only on success.
    virtual long open_sub(Handle parent, std::string_view name, std::uint32_t access, Handle& out) = 0;
    /// RegOpenKeyExW(root, key_path, REG_OPTION_OPEN_LINK, access): the kernel resolves the WHOLE path in this
    /// one call. It follows a link met before the leaf and opens a link AT the leaf as the link object. The
    /// call checks nothing; open_fast does. `out` is set only on success.
    virtual long open_path(Handle root, std::string_view key_path, std::uint32_t access, Handle& out) = 0;
    /// NtQueryKey(KeyNameInformation): the canonical kernel name of the object `key` is bound to (UTF-8,
    /// e.g. `\REGISTRY\MACHINE\SOFTWARE\Acme`). Any failure, a name that does not fit included, is non-zero.
    /// Exact: a name that does not round-trip UTF-16 to UTF-8 (a NUL, a lone surrogate) is a failure.
    virtual long final_name(Handle key, std::string& out) = 0;
    /// The kernel name of the predefined root `root`, cached by the shell. Only HKLM and HKU have one: HKCU
    /// resolves per calling user and HKCR is a merged view, so for them (and on any failure) it is non-zero.
    virtual long root_name(Handle root, std::string& out) = 0;
    /// RegCreateKeyExW with REG_OPTION_OPEN_LINK; `created_new` is false for REG_OPENED_EXISTING_KEY.
    /// `out` and `created_new` are set only on success.
    virtual long create_sub(Handle parent, std::string_view name, std::uint32_t access, Handle& out,
                            bool& created_new) = 0;
    /// noexcept: Owned and the rollback close handles from destructors.
    virtual void close(Handle key) noexcept = 0;
    /// `cap` = 0 asks for the size only.
    virtual long query_value(Handle key, std::string_view name, std::size_t cap, QueryResult& out) = 0;
    virtual long set_value(Handle key, std::string_view name, std::uint32_t type,
                           std::span<const std::uint8_t> data) = 0;
    virtual long delete_value(Handle key, std::string_view name) = 0;
    /// kErrorNoMoreItems ends the enumeration. The name is converted from UTF-16 lossily (a lone surrogate becomes
    /// U+FFFD, win_str.hpp), which is fine for display. `require_exact` (the callers that act on the name: the delete
    /// vet that captures each value by it, and the recursive delete's walks that open each child by it): a raw name
    /// that is not well-formed UTF-16 (kernel_name_well_formed) answers kErrorInvalidData instead, because its lossy
    /// form names a DIFFERENT value or key (or none).
    virtual long enum_value(Handle key, std::uint32_t index, std::string& name, bool require_exact = false) = 0;
    virtual long enum_subkey(Handle key, std::uint32_t index, std::string& name, bool require_exact = false) = 0;
    /// NtDeleteKey(key): marks the key for deletion by handle. There is NO tree delete here: RegDeleteTreeW
    /// follows a registry link found inside the tree (measured 2026-10-19). noexcept: the rollback calls it from a
    /// destructor.
    virtual long delete_key_by_handle(Handle key) noexcept = 0;
    /// RegFlushKey(key): writes the key's hive to disk. The per-user write arm calls it on an offline-mounted hive
    /// before the unload, because RegUnLoadKeyW does not itself modify the file.
    virtual long flush_key(Handle key) = 0;
};

/// Closes a non-predefined handle on scope exit (a predefined root is never wrapped).
class Owned {
public:
    explicit Owned(RegistryWriter& r, Handle h = 0) noexcept : r_(&r), h_(h) {}
    ~Owned() { reset(); }
    Owned(const Owned&) = delete;
    Owned& operator=(const Owned&) = delete;
    Owned(Owned&& o) noexcept : r_(o.r_), h_(std::exchange(o.h_, Handle{0})) {}
    Owned& operator=(Owned&& o) noexcept {
        if (this != &o) {
            reset();
            r_ = o.r_;
            h_ = std::exchange(o.h_, Handle{0});
        }
        return *this;
    }
    void reset(Handle h = 0) noexcept {
        if (h_ != 0 && h_ != h) r_->close(h_);
        h_ = h;
    }
    [[nodiscard]] Handle get() const noexcept { return h_; }

private:
    RegistryWriter* r_;
    Handle h_;
};

// ── checked open ─────────────────────────────────────────────────────────

/// "" when `h` is a plain key; key_is_link when it carries `SymbolicLinkValue`; access_denied /
/// win32:<n> when the probe itself failed (a key that cannot be probed is not treated as plain).
[[nodiscard]] inline std::string probe_link(RegistryWriter& reg, Handle h) {
    QueryResult q;
    const long rc = reg.query_value(h, "SymbolicLinkValue", 0, q);
    if (rc == kErrorSuccess) return std::string{kTokKeyIsLink};
    if (rc == kErrorFileNotFound) return {};
    return rc_token(rc, Missing::value);
}

/// What open_checked returns, and the owner of everything a creating walk made. `made` holds the keys create_sub
/// reported new, leaf last, open and still undeleted until commit(): the destructor is the rollback (rollback()
/// below), so an exception between the first create and the end of the verified write cannot strand a key. The
/// caller commits once the verified write is over, whatever it concluded; a walk that makes nothing owns nothing.
struct Opened {
    explicit Opened(RegistryWriter& r) : reg(&r), leaf(r) {}
    Opened(Opened&&) noexcept = default; // move-construct only; the moved-from `made` is empty, so its destructor has nothing to roll back
    ~Opened() { rollback(); }

    RegistryWriter* reg;
    Owned leaf;            ///< the checked handle when the leaf already existed (or the fast open took it); empty when the walk made it
    unsigned created = 0;  ///< keys THIS call created and left behind: every key made, less each one rollback() deleted
    unsigned missing = 0;  ///< components that did not exist when the walk reached them
    std::string error;     ///< "" or a token
    bool fast = false;     ///< the handle came from open_fast
    std::vector<Owned> made;          ///< the keys this walk created, leaf last
    std::string_view value_name;      ///< the value a creating write sets on the leaf (the caller's view, which outlives this)
    bool value_landed = false;        ///< set_value returned success for `value_name`: rollback() removes it first

    /// The checked handle every mutation runs on.
    [[nodiscard]] Handle handle() const noexcept { return made.empty() ? leaf.get() : made.back().get(); }

    /// The verified write is over: the keys it made stay (reported in `created`). The leaf stays OPEN as `leaf`, so a
    /// caller that holds the Opened (apply, which reuses one handle per key) keeps working on it; the intermediate
    /// handles close. The destructor closes the leaf, so no handle outlives the Opened.
    void commit() noexcept {
        if (!made.empty()) leaf = std::move(made.back());
        made.clear();
        value_landed = false;
    }

    /// Deletes what this walk made, by its own handles, leaf first: first the value the write set (when it
    /// landed; best effort), then each key that holds no value (enum_value finds none, so a key that now holds
    /// another party's value, or one the enumeration cannot rule out, is kept) and has no subkey (NtDeleteKey
    /// refuses a key with subkeys). `created` is left as the number of keys still present. A deleted key's handle
    /// is closed before its parent is deleted in turn. Never throws (it runs from the destructor of a frame that
    /// is already unwinding); a seam call that throws leaves its key in place, counted. Idempotent.
    void rollback() noexcept {
        if (made.empty()) return;
        if (value_landed) {
            try {
                (void)reg->delete_value(made.back().get(), value_name);
            } catch (...) {
            }
            value_landed = false;
        }
        for (auto it = made.rbegin(); it != made.rend(); ++it) {
            if (it->get() == 0) continue;
            try {
                std::string name;
                if (reg->enum_value(it->get(), 0, name) != kErrorNoMoreItems) continue;
                if (reg->delete_key_by_handle(it->get()) == kErrorSuccess) {
                    it->reset();
                    --created;
                }
            } catch (...) {
            }
        }
        made.clear();
    }
};

/// Equal byte for byte except that A-Z fold to a-z: a strict subset of the kernel's case folding, so it never
/// equates two names the kernel keeps distinct. A name that differs only in non-ASCII case compares unequal:
/// the fast open declines and the walk's own name test (leaf_name_check) refuses it.
[[nodiscard]] inline bool names_equal_ascii_ci(std::string_view a, std::string_view b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(),
                      [](char x, char y) { return detail::lower_ascii(x) == detail::lower_ascii(y); });
}

/// The fast open (see the file banner). ACCEPT => `fast` is set and `leaf` is the checked handle; every
/// other outcome (undecided, never a verdict) leaves `fast` false with no handle open, `error` empty, and the
/// caller walks. `leaf_may_be_link` (delete_key) skips the leaf probe: the handle opened with OPEN_LINK IS the
/// link object, and its canonical name still has to equal the requested path.
[[nodiscard]] inline Opened open_fast(RegistryWriter& reg, Handle root, std::string_view key_path,
                                      std::uint32_t leaf_access, bool leaf_may_be_link) {
    Opened out{reg};
    // An empty component (a leading, trailing or doubled backslash): the walk reports invalid_key_path.
    if (key_path.empty() || key_path.front() == '\\' || key_path.back() == '\\' ||
        key_path.find("\\\\") != std::string_view::npos)
        return out;
    std::string expected;
    if (reg.root_name(root, expected) != kErrorSuccess || expected.empty()) return out;
    Handle h = 0;
    if (reg.open_path(root, key_path, leaf_access | kKeyQueryValue, h) != kErrorSuccess) return out;
    Owned leaf{reg, h}; // closes on every return below that does not hand it over
    std::string actual;
    if (reg.final_name(h, actual) != kErrorSuccess) return out;
    expected += '\\';
    expected += key_path;
    if (!names_equal_ascii_ci(expected, actual)) return out;
    if (!leaf_may_be_link && !probe_link(reg, h).empty()) return out;
    out.leaf = std::move(leaf);
    out.fast = true;
    return out;
}

/// The walk's last test (see the file banner): "" when the canonical name of the leaf handle equals `first_name`
/// (the canonical name of the first component's handle) plus the remaining requested components, ASCII
/// case-insensitively; key_is_link when it does not (a link resolved mid-walk, or a component moved); win32:<n> /
/// access_denied when the leaf's name cannot be read (a handle that cannot be identified is never accepted).
[[nodiscard]] inline std::string leaf_name_check(RegistryWriter& reg, Handle leaf, std::string_view first_name,
                                                 const std::vector<std::string_view>& parts) {
    std::string actual;
    if (const long rc = reg.final_name(leaf, actual); rc != kErrorSuccess) return rc_token(rc, Missing::key);
    std::string expected{first_name};
    for (std::size_t i = 1; i < parts.size(); ++i) {
        expected += '\\';
        expected += parts[i];
    }
    return names_equal_ascii_ci(expected, actual) ? std::string{} : std::string{kTokKeyIsLink};
}

/// See the file banner. `leaf_access` always gains KEY_QUERY_VALUE (the link probe needs it).
/// `leaf_may_be_link` (delete_key only): the handle opened with REG_OPTION_OPEN_LINK IS the link object,
/// so NtDeleteKey on it removes the link, never its target. A creating op refuses a component missing
/// directly under the hive root as root_level_create (README). `fast_eligible` (HKLM and HKU, decided by the
/// shell) tries open_fast first; a missing key, a refusal and every doubt fall through to the walk below. A
/// creating walk returns the keys it made inside the Opened (see there): the caller commits them.
///
/// `probe_create` (apply's dry run, with create=false): where a real run would create a missing component, answer the
/// question "could it?" without creating anything. At the first missing component the walk re-opens the DEEPEST EXISTING
/// key with KEY_CREATE_SUB_KEY (RegOpenKeyExW(h, L"") is an access-checked new handle to the same key): a denial is
/// `access_denied`, exactly what the real run's create would answer; success closes the probe and the walk answers
/// key_not_found with `missing` set. A first component missing under the hive root is `root_level_create` in both
/// modes. LIMIT (documented, not closable here): the probe proves create access on the EXISTING parent only. The ACL a
/// key that does not exist yet would INHERIT is first seen by the real run, which can therefore still answer failed
/// (the keys it made are rolled back by handle, `created` reports what stayed) where the dry run said would_apply.
[[nodiscard]] inline Opened open_checked(RegistryWriter& reg, Handle root, std::string_view key_path,
                                         std::uint32_t leaf_access, bool create,
                                         bool leaf_may_be_link = false, bool fast_eligible = false,
                                         bool probe_create = false) {
    if (fast_eligible)
        if (auto fast = open_fast(reg, root, key_path, leaf_access, leaf_may_be_link); fast.fast) return fast;
    Opened out{reg};
    const auto parts = split_key(key_path);
    for (const auto p : parts)
        if (p.empty()) {
            out.error = std::string{kTokInvalidKeyPath};
            return out;
        }
    leaf_access |= kKeyQueryValue;
    const std::uint32_t inter_access = kKeyQueryValue | (create ? kKeyCreateSubKey : 0);
    Owned cur{reg};
    Handle parent = root;
    std::string first_name; // the canonical name of the first component's handle, read right after its open
    // Every exit that follows a create but does not hand the leaf over rolls back what this call created (a create
    // made through a parent that had become a link lands beneath the link's target before any name can be read);
    // `created` is then what could not be deleted. An exception does the same through ~Opened. Only a key
    // create_sub reported as new is in out.made: one it merely opened is somebody else's and is closed, never deleted.
    // Hands the leaf over only when its kernel name is the requested path (leaf_name_check); otherwise it rolls back.
    const auto hand_over = [&]() -> Opened {
        const Handle leaf = out.made.empty() ? cur.get() : out.made.back().get(); // the key the walk made last, else the last it opened
        if (auto why = leaf_name_check(reg, leaf, first_name, parts); !why.empty()) {
            out.error = std::move(why);
            out.rollback();
        } else if (out.made.empty()) {
            out.leaf = std::move(cur);
        }
        return std::move(out);
    };
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const bool last = i + 1 == parts.size();
        Handle next = 0;
        long rc = reg.open_sub(parent, parts[i], last ? leaf_access : inter_access, next);
        if (rc == kErrorAccessDenied && !last && create)
            rc = reg.open_sub(parent, parts[i], kKeyQueryValue, next);
        if (rc == kErrorFileNotFound || rc == kErrorPathNotFound) {
            out.missing = static_cast<unsigned>(parts.size() - i);
            if (i == 0 && (create || probe_create)) { // a component missing directly under the hive root is never created
                out.error = std::string{kTokRootLevelCreate};
                return out;
            }
            if (!create) {
                if (probe_create) { // i > 0: `parent` is the deepest existing key, still open
                    Handle probe = 0;
                    if (const long prc = reg.open_sub(parent, "", kKeyCreateSubKey, probe); prc != kErrorSuccess) {
                        out.error = rc_token(prc, Missing::key);
                        return out;
                    }
                    const Owned closes{reg, probe}; // the probe created nothing; it only asked
                }
                out.error = std::string{kTokKeyNotFound};
                return out;
            }
            // push_back cannot throw once the storage is reserved, so a key create_sub reported new is always in out.made.
            out.made.reserve(parts.size() - i); // (no test can fail this: the fake has no allocation seam)
            for (std::size_t j = i; j < parts.size(); ++j) {
                const bool last_j = j + 1 == parts.size();
                Handle made = 0;
                bool created_new = false;
                // kAccessDelete: a walk that stops deletes what it made through this very handle.
                const std::uint32_t create_access =
                    (last_j ? leaf_access : (kKeyQueryValue | kKeyCreateSubKey)) | kAccessDelete;
                const long crc = reg.create_sub(parent, parts[j], create_access, made, created_new);
                if (crc != kErrorSuccess) {
                    out.error = rc_token(crc, Missing::key);
                    out.rollback();
                    return out;
                }
                Owned made_owner{reg, made}; // closes on the early return below: opened-existing is never deleted
                if (!created_new) { // the walk saw it absent a moment ago
                    out.error = std::string{kTokConcurrentChange};
                    out.rollback();
                    return out;
                }
                out.made.push_back(std::move(made_owner));
                ++out.created;
                parent = out.made.back().get(); // the checked parent in `cur` stays open until the walk ends
            }
            return hand_over();
        }
        if (rc != kErrorSuccess) {
            out.error = rc_token(rc, Missing::key);
            return out;
        }
        Owned opened{reg, next};
        if (i == 0) { // before the probe: no later swap can move what this names
            if (const long nrc = reg.final_name(next, first_name); nrc != kErrorSuccess) {
                out.error = rc_token(nrc, Missing::key);
                return out;
            }
            // The component the handle is bound to must still be named as requested: a rename between the open
            // and this read would otherwise anchor the whole walk at the renamed object.
            const auto sep = first_name.rfind('\\');
            if (!names_equal_ascii_ci(std::string_view{first_name}.substr(sep + 1), parts[0])) {
                out.error = std::string{kTokKeyIsLink};
                return out;
            }
        }
        if (!(last && leaf_may_be_link)) {
            if (auto link = probe_link(reg, next); !link.empty()) {
                out.error = std::move(link);
                return out;
            }
        }
        cur = std::move(opened); // closes the previous parent
        parent = cur.get();
    }
    return hand_over();
}

// ── previous-value capture ───────────────────────────────────────────────

[[nodiscard]] inline OldValue capture_old(RegistryWriter& reg, Handle key, std::string_view name) {
    OldValue v;
    QueryResult q;
    const long rc = reg.query_value(key, name, kCaptureValueCap, q);
    if (rc == kErrorSuccess) {
        v.state = OldState::present;
        v.type = q.type;
        v.total = q.size;
        v.bytes = std::move(q.bytes);
    } else if (rc != kErrorFileNotFound) {
        v.state = OldState::unreadable;
        v.error = rc_token(rc, Missing::value);
    }
    return v;
}

// ── single-action outcome ────────────────────────────────────────────────

struct WriteOutcome {
    /// ok | refused (nothing was mutated, or every key the walk created was removed again) |
    /// failed (a mutation was attempted)
    std::string result = "refused";
    std::string reason; ///< "" or a token
    std::string verify; ///< ok | mismatch | ""
    /// Keys created and still present: on ok the keys the write made; after a walk that stopped,
    /// only those it could not delete again.
    unsigned created = 0;
    OldValue old;
    bool has_old = false;
    bool mutated = false;
    std::uint64_t counted_keys = 0;
    std::uint64_t counted_values = 0;
    bool capped = false;
    bool dry_run = false; ///< delete_key: the request asked to count and delete nothing
    [[nodiscard]] bool ok() const noexcept { return result == "ok"; }

    /// Records a failure: `attempted` false = refused (nothing was mutated), true = failed (a mutation ran).
    void fail(std::string why, bool attempted) {
        result = attempted ? "failed" : "refused";
        reason = std::move(why);
    }

    /// Stamps the read-back verdict of a mutation that was applied: ok, or a verify_mismatch failure.
    void confirm(bool verified) {
        if (verified) {
            verify = "ok";
            result = "ok";
            return;
        }
        verify = "mismatch";
        fail(std::string{kTokVerifyMismatch}, true);
    }
};

/// Writes `bytes` to `name` on the checked handle `h`, reads it back and compares (type + bytes). `landed`, when
/// given, is set the moment set_value succeeds, so a caller whose frame unwinds during the read-back still knows the
/// value is there.
[[nodiscard]] inline WriteOutcome write_value_on(RegistryWriter& reg, Handle h, std::string_view name,
                                                 std::uint32_t type, std::span<const std::uint8_t> bytes,
                                                 bool* landed = nullptr) {
    WriteOutcome o;
    if (const long rc = reg.set_value(h, name, type, bytes); rc != kErrorSuccess) {
        o.fail(rc_token(rc, Missing::value), true);
        return o;
    }
    if (landed != nullptr) *landed = true;
    o.mutated = true;
    QueryResult q;
    const long qrc = reg.query_value(h, name, kMaxWriteBytes, q);
    o.confirm(qrc == kErrorSuccess && q.type == type && q.size == bytes.size() &&
              std::equal(q.bytes.begin(), q.bytes.end(), bytes.begin(), bytes.end()));
    return o;
}

/// Deletes `name` on the checked handle `h` and confirms it is gone.
[[nodiscard]] inline WriteOutcome delete_value_on(RegistryWriter& reg, Handle h, std::string_view name) {
    WriteOutcome o;
    if (const long rc = reg.delete_value(h, name); rc != kErrorSuccess) {
        o.fail(rc_token(rc, Missing::value), true);
        return o;
    }
    o.mutated = true;
    QueryResult q;
    o.confirm(reg.query_value(h, name, 0, q) == kErrorFileNotFound);
    return o;
}

/// `flush` (the per-user write arm, on an offline-mounted hive): RegFlushKey on the written key's handle, so the change
/// reaches the hive FILE before RegUnLoadKeyW, whose documentation says unloading does not itself modify the file. A
/// flush failure fails the write (`flush_failed:<rc token>`, a mutation was attempted): durability is unknown. Only
/// called after a verified write, never after a refusal. False when it failed.
inline bool flush_on(RegistryWriter& reg, Handle h, WriteOutcome& o) {
    const long rc = reg.flush_key(h);
    if (rc != kErrorSuccess) o.fail("flush_failed:" + rc_token(rc, Missing::key), true);
    return rc == kErrorSuccess;
}

[[nodiscard]] inline WriteOutcome set_value_verified(RegistryWriter& reg, Handle root, std::string_view key,
                                                     std::string_view name, std::uint32_t type,
                                                     std::span<const std::uint8_t> bytes,
                                                     bool fast_eligible = false, bool flush = false) {
    auto op = open_checked(reg, root, key, kKeySetValue | kKeyQueryValue, /*create=*/true,
                           /*leaf_may_be_link=*/false, fast_eligible);
    if (!op.error.empty()) {
        WriteOutcome o;
        o.created = op.created;
        o.fail(op.error, op.created > 0);
        return o;
    }
    op.value_name = name; // a creating write that unwinds first removes this value again (Opened::rollback)
    OldValue old = capture_old(reg, op.handle(), name);
    WriteOutcome o = write_value_on(reg, op.handle(), name, type, bytes, &op.value_landed);
    // A write whose flush failed is NOT committed: the destructor-path rollback removes the value and the keys this
    // call made (best effort), so a creating write that cannot be made durable does not leave its keys behind. Any
    // other outcome is over, whatever it concluded: the keys it made stay and are reported.
    if (flush && o.ok() && !flush_on(reg, op.handle(), o))
        op.rollback();
    else
        op.commit();
    o.created = op.created;
    o.old = std::move(old);
    o.has_old = true;
    return o;
}

[[nodiscard]] inline WriteOutcome delete_value_verified(RegistryWriter& reg, Handle root, std::string_view key,
                                                        std::string_view name, bool fast_eligible = false,
                                                        bool flush = false) {
    auto op = open_checked(reg, root, key, kKeySetValue | kKeyQueryValue, /*create=*/false,
                           /*leaf_may_be_link=*/false, fast_eligible);
    if (!op.error.empty()) {
        WriteOutcome o;
        o.fail(op.error, false);
        return o;
    }
    OldValue old = capture_old(reg, op.handle(), name);
    WriteOutcome o;
    if (old.state == OldState::absent)
        o.fail(std::string{kTokValueNotFound}, false);
    else
        o = delete_value_on(reg, op.handle(), name);
    if (flush && o.ok()) (void)flush_on(reg, op.handle(), o);
    o.old = std::move(old);
    o.has_old = true;
    return o;
}

// ── delete_key ───────────────────────────────────────────────────────────

struct TreeCount {
    std::uint64_t keys = 0, values = 0, nodes = 0;
    bool capped = false;
    bool attempted = false; ///< the delete walk only: an NtDeleteKey was issued (so a stop is `failed`, not `refused`)
    std::string error;
};

/// The token of a failed exact enumeration (`require_exact`): a raw name that is not well-formed UTF-16 is
/// unrepresentable_name (nothing can address it by a UTF-8 name), every other code as rc_token spells it.
[[nodiscard]] inline std::string exact_enum_token(long rc, Missing what) {
    return rc == kErrorInvalidData ? std::string{kTokUnrepresentableName} : rc_token(rc, what);
}

/// Adds the values of the key `h` to `c`: nodes are keys + values, and the caller has already counted the key itself, so
/// the cap is kMaxTreeNodes nodes in all. kMaxTreeNodes bounds the enumeration at 10,000 iterations even when the value
/// set grows between calls. Past the bound `capped` is set and `values` is a lower bound.
inline void count_values_into(RegistryWriter& reg, Handle h, TreeCount& c) {
    std::string name;
    for (std::uint32_t i = 0;; ++i) {
        const long rc = reg.enum_value(h, i, name);
        if (rc == kErrorNoMoreItems) return;
        if (rc != kErrorSuccess) {
            c.error = rc_token(rc, Missing::value);
            return;
        }
        if (c.nodes >= kMaxTreeNodes) {
            c.capped = true;
            return;
        }
        ++c.values;
        ++c.nodes;
    }
}

/// Counts the values of the leaf `h`: the key itself is node 1 (so the cap is the key plus up to kMaxTreeNodes - 1
/// values). A leaf delete proceeds past the cap, because NtDeleteKey of a leaf removes its values whatever their number.
[[nodiscard]] inline TreeCount count_values(RegistryWriter& reg, Handle h) {
    TreeCount c;
    c.keys = 1;
    c.nodes = 1;
    count_values_into(reg, h, c);
    return c;
}

/// The mask both the vet (count_tree) and the delete walk (delete_subtree) open every child with: they must match, so a
/// child whose ACL denies the delete is refused by the vet before anything is removed.
inline constexpr std::uint32_t kDeleteWalkAccess = kAccessDelete | kKeyQueryValue | kKeyEnumerateSubKeys;

/// The VET of a recursive delete: counts `h` and everything beneath it, depth first. Every child is opened from its
/// parent's handle with REG_OPTION_OPEN_LINK and probed for a link; a link inside the tree fails the walk closed
/// (key_is_link), because nothing may be deleted through a redirect; a child whose raw name is not well-formed UTF-16
/// fails it unrepresentable_name (its lossy name would open a sibling). It is a SIZE BOUND and a LINK SWEEP, not a
/// membership list (README "delete_key"): kMaxTreeNodes and kMaxTreeDepth cap it, `capped` is then set and the counts
/// are a lower bound, and delete_key_tree refuses a REAL recursive delete of a tree it could not finish
/// (tree_too_large) so that no unvetted tail is ever deleted. The real delete is delete_subtree, which re-checks every
/// key. One Owned per level is held (at most kMaxTreeDepth + 1 handles).
inline void count_tree(RegistryWriter& reg, Handle h, TreeCount& c, unsigned depth = 0) {
    if (depth > kMaxTreeDepth || c.nodes >= kMaxTreeNodes) {
        c.capped = true;
        return;
    }
    ++c.keys;
    ++c.nodes;
    count_values_into(reg, h, c);
    if (c.capped || !c.error.empty()) return;
    std::string name;
    for (std::uint32_t i = 0;; ++i) {
        // Exact: a child is opened BY this name, and a lossy one would open a sibling (or nothing) instead.
        const long rc = reg.enum_subkey(h, i, name, /*require_exact=*/true);
        if (rc == kErrorNoMoreItems) return;
        if (rc != kErrorSuccess) {
            c.error = exact_enum_token(rc, Missing::key);
            return;
        }
        Handle child = 0;
        // The delete walk's own mask, so a child whose ACL denies the delete refuses here, before anything is deleted,
        // instead of stopping the real delete part-way.
        if (const long orc = reg.open_sub(h, name, kDeleteWalkAccess, child);
            orc != kErrorSuccess) {
            c.error = rc_token(orc, Missing::key);
            return;
        }
        const Owned guard{reg, child};
        if (auto link = probe_link(reg, child); !link.empty()) {
            c.error = std::move(link);
            return;
        }
        count_tree(reg, child, c, depth + 1);
        if (c.capped || !c.error.empty()) return;
    }
}

/// The delete of a recursive delete_key: removes the tree under `h` post-order and then `h` itself, every removal an
/// NtDeleteKey on the key's OWN handle. Each child found AT DELETE TIME is opened with REG_OPTION_OPEN_LINK and probed
/// again (count_tree ran earlier, and a link planted since is the link object itself: it STOPS the walk with key_is_link
/// and is never entered or followed), so a key added after the vet is deleted and counted like any other. A tree that
/// outgrew the bound (nodes or levels) stops concurrent_change. `d` holds what this walk REMOVED, so a stop reports
/// the partial truth. ponytail: the per-child kernel-name check is not repeated here (one NtQueryKey per child on the
/// delete path); a half-made link is still only ever deleted as its own object, by its own handle.
inline void delete_subtree(RegistryWriter& reg, Handle h, TreeCount& d, unsigned depth = 0) {
    if (depth > kMaxTreeDepth || d.nodes >= kMaxTreeNodes) {
        d.error = std::string{kTokConcurrentChange};
        return;
    }
    std::string name;
    for (;;) {
        const long rc = reg.enum_subkey(h, 0, name, /*require_exact=*/true); // a removed child no longer enumerates
        if (rc == kErrorNoMoreItems) break;
        if (rc != kErrorSuccess) {
            d.error = exact_enum_token(rc, Missing::key);
            return;
        }
        Handle child = 0;
        if (const long orc = reg.open_sub(h, name, kDeleteWalkAccess, child);
            orc != kErrorSuccess) {
            d.error = rc_token(orc, Missing::key);
            return;
        }
        const Owned guard{reg, child};
        if (auto link = probe_link(reg, child); !link.empty()) {
            d.error = std::move(link);
            return;
        }
        delete_subtree(reg, child, d, depth + 1);
        if (!d.error.empty()) return;
    }
    // This key and its values join the walk's running total before the delete takes them, so a value added to any
    // key since the vet (an ancestor included) cannot carry the delete past kMaxTreeNodes nodes in all.
    if (d.nodes >= kMaxTreeNodes) {
        d.error = std::string{kTokConcurrentChange};
        return;
    }
    TreeCount own;
    own.nodes = d.nodes + 1;
    count_values_into(reg, h, own);
    if (!own.error.empty() || own.capped) {
        d.error = own.error.empty() ? std::string{kTokConcurrentChange} : own.error;
        return;
    }
    d.attempted = true;
    if (const long rc = reg.delete_key_by_handle(h); rc != kErrorSuccess) {
        d.error = rc_token(rc, Missing::key);
        return;
    }
    ++d.keys;
    d.values += own.values;
    d.nodes = own.nodes;
}

/// Deletes the key on the checked handle `h`: with `recursive`, everything beneath it first (delete_subtree, which also
/// removes `h`), else NtDeleteKey(h). Verified by the deleted handle reporting ERROR_KEY_DELETED. A recursive run's
/// counts are what the walk REMOVED (a stop reports the partial total); a non-recursive run leaves them 0 (the caller
/// has the vet's).
[[nodiscard]] inline WriteOutcome delete_key_on(RegistryWriter& reg, Handle h, bool recursive = false) {
    WriteOutcome o;
    if (recursive) {
        TreeCount d;
        delete_subtree(reg, h, d);
        o.counted_keys = d.keys;
        o.counted_values = d.values;
        o.mutated = d.keys > 0;
        if (!d.error.empty()) {
            o.fail(d.error, d.attempted);
            return o;
        }
    } else {
        if (const long rc = reg.delete_key_by_handle(h); rc != kErrorSuccess) {
            o.fail(rc_token(rc, Missing::key), true);
            return o;
        }
        o.mutated = true;
    }
    QueryResult q;
    o.confirm(reg.query_value(h, "", 0, q) == kErrorKeyDeleted);
    return o;
}

/// delete_key. Non-recursive (the default): a key with subkeys is refused `key_has_subkeys` and nothing is deleted; a
/// leaf's counts are what the enumeration saw before the delete (a lower bound when `capped`); a link leaf is opened as
/// the link object, so the delete removes the link and never its target. `recursive`: the vet (count_tree) first, then
/// delete_subtree. `dry_run`: the vet only -- result ok, the vet's counts, nothing deleted. Counts: a dry run, a
/// refusal and a non-recursive delete report the vet's count (a lower bound when capped; a refusal reports what was
/// counted before it); a REAL recursive delete reports what its walk REMOVED -- exact when ok, the partial total when
/// it stopped -- which can exceed a dry run's snapshot. A REAL recursive delete whose vet was capped is refused
/// tree_too_large with nothing deleted. (The recursion flags follow `fast_eligible` so every earlier caller's
/// positional arguments keep their meaning.)
[[nodiscard]] inline WriteOutcome delete_key_tree(RegistryWriter& reg, Handle root, std::string_view key,
                                                  bool fast_eligible = false, bool recursive = false,
                                                  bool dry_run = false) {
    auto op = open_checked(reg, root, key, kAccessDelete | kKeyEnumerateSubKeys | kKeyQueryValue,
                           /*create=*/false, /*leaf_may_be_link=*/true, fast_eligible);
    if (!op.error.empty()) {
        WriteOutcome o;
        o.dry_run = dry_run;
        o.fail(op.error, false);
        return o;
    }
    const Handle h = op.handle();
    TreeCount c;
    if (recursive) {
        count_tree(reg, h, c);
    } else {
        std::string first;
        const long rc = reg.enum_subkey(h, 0, first);
        if (rc == kErrorSuccess)
            c.error = std::string{kTokKeyHasSubkeys};
        else if (rc != kErrorNoMoreItems)
            c.error = rc_token(rc, Missing::key);
        else
            c = count_values(reg, h);
    }
    WriteOutcome o;
    const bool too_large = recursive && c.capped && !dry_run;
    if (!c.error.empty())
        o.fail(c.error, false);
    else if (too_large)
        o.fail(std::string{kTokTreeTooLarge}, false);
    else if (dry_run)
        o.result = "ok";
    else
        o = delete_key_on(reg, h, recursive);
    o.dry_run = dry_run;
    if (!(recursive && !dry_run && c.error.empty() && !too_large)) { // else: the walk's removed counts stand
        o.counted_keys = c.keys;
        o.counted_values = c.values;
        o.capped = c.capped;
    }
    return o;
}

// ── audit + output ───────────────────────────────────────────────────────

struct ActionOutput {
    std::vector<std::string> lines;
    int rc = 0;
};

/// Writes an action's lines one at a time (`Ctx` is yuzu::CommandContext; a template so the pure unit suites can drive
/// it with a recording fake). Once the real `audit|` line of the current unit is out, a sink failure on a later line of
/// that unit must not reach `report_exception`'s fixed failed audit line: the server would mint a success row and then a
/// failure row for the same mutation. So that failure answers only `error|exception` (best effort) and put() answers
/// false: the caller stops (apply mutates nothing more). A failure before the unit's audit line has gone out propagates,
/// and the seam's catch leaves its fixed line.
///
/// A single action is one unit. `apply` is one per ITEM (the server mints one row per `audit|` line, so an apply
/// command's rows may be ok and failed alike): put_audit() opens the item's unit, so a failure writing item N's audit
/// line -- after item N mutated, with item N-1's line already out -- reaches the seam instead of being swallowed with
/// no row at all for the mutation.
template <class Ctx>
struct LineSink {
    Ctx& ctx;
    bool audit_written = false;

    /// The audit line of a new unit: nothing of THIS unit is out yet, so its failure propagates.
    [[nodiscard]] bool put_audit(const std::string& line) {
        audit_written = false;
        return put(line);
    }

    [[nodiscard]] bool put(const std::string& line) {
        try {
            ctx.write_output(line);
        } catch (...) {
            if (!audit_written) throw;
            try {
                ctx.write_output("error|exception");
            } catch (...) {
            }
            return false;
        }
        audit_written = audit_written || line.starts_with("audit|");
        return true;
    }
};

/// Copies a captured previous value onto an audit record (state always, type and bytes when present).
inline void fill_old(AuditRecord& au, const OldValue& old) {
    au.old_state = std::string{old_state_name(old.state)};
    au.has_old = old.state == OldState::present;
    if (au.has_old) {
        au.old_type = std::string{yuzu::profiles::reg_type_name(old.type)};
        au.old_bytes = old.bytes;
        au.old_total = old.total;
    }
}

/// The wire output of one single mutating action: the audit line, then `status|ok` (and, for
/// delete_key, the four appended count rows) or `error|<token>` with rc 1. `base` arrives pre-filled
/// with op, hive, key, name, type, len and the new bytes (`sid` stays unset: it renders `-`); the outcome fields
/// are set here.
[[nodiscard]] inline ActionOutput render_single_action(AuditRecord base, const WriteOutcome& o,
                                                       bool is_delete_key) {
    base.result = o.result;
    base.reason = o.reason;
    base.verify = o.verify;
    base.created = static_cast<long long>(o.created);
    if (o.has_old) fill_old(base, o.old);
    if (is_delete_key) {
        base.dry_run = o.dry_run ? 1 : 0;
        base.counted_keys = static_cast<long long>(o.counted_keys);
        base.counted_values = static_cast<long long>(o.counted_values);
        base.capped = o.capped ? 1 : 0;
    }
    ActionOutput out;
    out.lines.reserve(is_delete_key ? 6 : 2);
    out.lines.push_back(render_audit_line(base));
    if (!o.ok()) {
        out.lines.push_back("error|" + o.reason);
        out.rc = 1;
        return out;
    }
    out.lines.push_back("status|ok");
    if (is_delete_key) {
        out.lines.push_back("counted_keys|" + std::to_string(o.counted_keys));
        out.lines.push_back("counted_values|" + std::to_string(o.counted_values));
        out.lines.push_back(std::string{"dry_run|"} + (o.dry_run ? "1" : "0"));
        out.lines.push_back(std::string{"capped|"} + (o.capped ? "1" : "0"));
    }
    return out;
}

// ── per-user write output ────────────────────────────────────────────────

/// What with_user_hive and the post-unload probe reported (registry_win.cpp fills it).
struct HiveFacts {
    yuzu::profiles::HiveAccessStatus status = yuzu::profiles::HiveAccessStatus::ok;
    bool unload_failed = false;
    std::string mount_name;
    std::string refusal;      ///< the OfflineHiveFileCheck token when status == file_refused
    std::string race_warning; ///< classify_offline_write_race's token ("" = none)
};

/// The wire output of set_user_value / delete_user_value, in emission order: the hive-access lines (the unload warning
/// first, then the terminal hive error, which names the file-guard refusal token when there is one: unload_failed can be
/// true even on mount_failed), the offline-write race warning, then the audit line and `status|ok` / `error|<token>`. A
/// hive that was not reached or was refused means nothing was written: the audit result is `refused` with the hive reason
/// (hive_not_found, privilege_missing, hive_mount_failed, or the guard's own token). A verified, flushed write whose mount
/// then failed to unload stays result=ok (the write is durable) with reason=hive_unload_failed in the audit trail. rc is
/// 1 unless the write is ok. `au` arrives pre-filled like render_single_action's `base`; the sid is set here.
[[nodiscard]] inline ActionOutput render_user_write(AuditRecord au, WriteOutcome wo, const HiveFacts& hf,
                                                    std::string_view sid) {
    using yuzu::profiles::HiveAccessStatus;
    ActionOutput out;
    out.lines = yuzu::profiles::render_hive_access_lines(hf.status, hf.unload_failed, hf.mount_name, sid, hf.refusal);
    if (!hf.race_warning.empty()) out.lines.push_back("warning|" + hf.race_warning);
    if (hf.status != HiveAccessStatus::ok) {
        wo = WriteOutcome{};
        // The audit reason and the closing `error|<token>` share the write tokens' space (key_not_found,
        // value_not_found, access_denied ...), so a hive outcome carries a hive_ prefix here: the bare not_found /
        // mount_failed / file_refused that yuzu::profiles::hive_access_token spells for the autoruns and tar rows would
        // read as a key or value fact. The hive-access lines above are the shared sentences, unchanged.
        switch (hf.status) {
        case HiveAccessStatus::not_found: wo.reason = "hive_not_found"; break;
        case HiveAccessStatus::privilege_missing: wo.reason = "privilege_missing"; break;
        case HiveAccessStatus::mount_failed: wo.reason = "hive_mount_failed"; break;
        case HiveAccessStatus::file_refused: wo.reason = hf.refusal.empty() ? "hive_file_refused" : hf.refusal; break;
        case HiveAccessStatus::ok: break;
        }
    } else if (wo.ok() && hf.unload_failed) {
        wo.reason = "hive_unload_failed";
    }
    au.sid = std::string{sid};
    auto single = render_single_action(std::move(au), wo, false);
    out.rc = single.rc;
    for (auto& line : single.lines) out.lines.push_back(std::move(line));
    return out;
}

// ── apply ────────────────────────────────────────────────────────────────

/// A value of a key an item deletes, retained for the undo manifest (a row's worth, charged to the CaptureBudget).
struct NamedValue {
    std::string name;
    OldValue v;
};

/// Everything the verdict function sees about one item, captured on the item's own checked handle (the same facts in a
/// dry run and a real run).
struct ItemFacts {
    std::string open_error;   ///< open_checked's token other than a plain missing key
    bool key_exists = true;
    OldValue old;             ///< value ops: the previous value (full, up to kCaptureValueCap)
    bool has_subkeys = false; ///< delete_key
    std::string leaf_error;   ///< delete_key: enumerating or vetting the leaf's values answered a refusal token
    bool leaf_capped = false; ///< delete_key: the leaf holds more values than count_values' bound
    std::uint64_t leaf_value_count = 0;
    std::vector<NamedValue> leaf_values; ///< delete_key: the values retained for the undo manifest, budget permitting
};

/// THE verdict function: "" = the item proceeds, else the refusal token. A dry run and a real run call it with the same
/// facts, so their verdicts are identical (the parser's dependent_items refusal guarantees no earlier item changes what a
/// later one captures, apart from creating a key, which run_apply's dry run simulates). It reads no mode.
[[nodiscard]] inline std::string refusal_reason(const PlanItem& item, const ItemFacts& f) {
    if (!item.invalid.empty()) return item.invalid;
    if (!f.open_error.empty()) return f.open_error;
    switch (item.op) {
    case PlanOp::set_value:
        if (f.old.state == OldState::unreadable) return f.old.error;
        if (!restorable(f.old)) return std::string{kTokUnsupportedOldType};
        return {};
    case PlanOp::delete_value:
        if (!f.key_exists) return std::string{kTokKeyNotFound};
        if (f.old.state == OldState::absent) return std::string{kTokValueNotFound};
        if (f.old.state == OldState::unreadable) return f.old.error;
        if (!restorable(f.old)) return std::string{kTokUnsupportedOldType};
        return {};
    case PlanOp::create_key: return {};
    case PlanOp::delete_key:
        if (!f.key_exists) return std::string{kTokKeyNotFound};
        if (f.has_subkeys) return std::string{kTokKeyHasSubkeys};
        if (!f.leaf_error.empty()) return f.leaf_error;
        if (f.leaf_capped) return std::string{kTokTreeTooLarge};
        return {};
    case PlanOp::count_: return std::string{kTokInvalidData}; // unreachable: parse_plan never yields it
    }
    return {};
}

/// The ONE budget of everything a plan retains for its undo manifest: every retained row is charged its name bytes, its
/// data bytes and kUndoRowOverhead BEFORE anything is kept or rendered, against kCaptureTotalCap. A row that does not fit
/// is not retained and the manifest is flagged incomplete (`undo_complete=0` in the summary, visible in the dry run, which
/// charges identically); so is a value cut at kCaptureValueCap. Hex doubles what is retained, which keeps the whole reply
/// under the dispatcher's 2 MiB output cap (agents/core/src/local_dispatcher.hpp):
///   - retained rows: <= 512 KiB charged => <= ~1 MiB of rendered hex, names and row text;
///   - <= 256 audit lines, each < 2 KiB (render_audit_line): <= 512 KiB;
///   - <= 256 item rows whose key and name come from the <= 64 KiB plan: ~110 KiB; one summary row.
/// A deleted key's values are STREAMED (vet_leaf_values) and only the ones that fit are retained.
struct CaptureBudget {
    std::size_t remaining = kCaptureTotalCap;
    bool incomplete = false;

    /// Charges one row; false = it does not fit (nothing may be kept) and the manifest is incomplete.
    [[nodiscard]] bool charge(std::size_t name_bytes, std::size_t data_bytes) noexcept {
        const std::size_t cost = name_bytes + data_bytes + kUndoRowOverhead;
        if (cost > remaining) {
            incomplete = true;
            return false;
        }
        remaining -= cost;
        return true;
    }
};

/// The previous value of a value op as the item row keeps it: charged to the budget, and its bytes dropped (metadata and
/// `~total` stay) when the row does not fit. A value cut at kCaptureValueCap flags the manifest incomplete.
[[nodiscard]] inline OldValue budgeted_old(CaptureBudget& budget, std::string_view name, const OldValue& old) {
    OldValue kept = old;
    if (old.state != OldState::present) return kept;
    if (old.bytes.size() < old.total) budget.incomplete = true;
    if (!budget.charge(name.size(), old.bytes.size())) kept.bytes.clear();
    return kept;
}

/// A name this plugin can write back AND the manifest can spell exactly: set_value's own check plus `representable`.
[[nodiscard]] inline bool name_restorable(std::string_view name) {
    return validate_value_name(name).empty() && representable(name);
}

/// What an enumerated value failed with: a name that is not restorable, a value the enumeration listed but a query cannot
/// find (removed under us: the exact enumeration means the name itself round-trips), an unreadable value or a type this
/// plugin cannot write.
[[nodiscard]] inline std::string leaf_value_defect(std::string_view name, const OldValue& v) {
    if (!name_restorable(name)) return std::string{kTokUnrepresentableName};
    if (v.state == OldState::absent) return std::string{kTokConcurrentChange}; // never "nothing to restore"
    if (v.state == OldState::unreadable) return v.error;
    if (!restorable(v)) return std::string{kTokUnsupportedOldType};
    return {};
}

struct LeafVet {
    std::string error;      ///< the first defect of any value ("" = every value can be restored)
    bool capped = false;    ///< more values than count_values' bound: nothing is deleted (tree_too_large)
    std::uint64_t values = 0;
    std::vector<NamedValue> kept; ///< the values `budget` retained, in enumeration order
};

/// Streams EVERY value of the leaf `h` (enum_value + one capture each) up to count_values' bound and answers the first
/// defect it meets, so the refuse-before-delete promise covers every value, not only the ones the budget can keep. The
/// same pass retains the values `budget` keeps (a value cut at kCaptureValueCap keeps its first part; the first row that
/// does not fit ends the retention and flags the manifest incomplete). The caller passes a trial copy of its budget and
/// adopts it only when the vet is clean, so a refused item charges nothing and retains nothing. The enumeration is
/// EXACT: a raw name that is not well-formed UTF-16 is unrepresentable_name, because its lossy UTF-8 form (U+FFFD for a
/// lone surrogate) would capture a different value, or the same one twice, under a manifest that looks complete.
[[nodiscard]] inline LeafVet vet_leaf_values(RegistryWriter& reg, Handle h, CaptureBudget& budget) {
    LeafVet vet;
    bool retaining = true;
    std::string name;
    for (std::uint32_t i = 0;; ++i) {
        const long rc = reg.enum_value(h, i, name, /*require_exact=*/true);
        if (rc == kErrorNoMoreItems) return vet;
        if (rc != kErrorSuccess) {
            vet.error = exact_enum_token(rc, Missing::value);
            return vet;
        }
        if (static_cast<std::size_t>(i) + 1 >= kMaxTreeNodes) { // the key is node 1: count_values' bound
            vet.capped = true;
            return vet;
        }
        OldValue v = capture_old(reg, h, name);
        if (auto defect = leaf_value_defect(name, v); !defect.empty()) {
            vet.error = std::move(defect);
            return vet;
        }
        ++vet.values;
        if (!retaining) continue;
        if (v.bytes.size() < v.total) budget.incomplete = true;
        if (budget.charge(name.size(), v.bytes.size()))
            vet.kept.push_back(NamedValue{name, std::move(v)});
        else
            retaining = false;
    }
}

struct ApplyOptions {
    bool dry_run = true;
    bool continue_on_error = false;
};

/// Runs a parsed plan against the machine hive `hklm` in one pass, writing its rows to `ctx` (yuzu::CommandContext; a
/// template so the pure unit suites can drive it with a recording fake). Per item: the key is opened ONCE per distinct
/// (ASCII-case-folded) key on a checked handle and reused by the later items on that key (one checked
/// open per key, not per item); a FAILED open is a fact for that item only and is never cached, so the next item on the
/// key opens again with its own flags (delete_value on a missing key refused, a later set_value on it still creates it).
/// The open uses the mutation's own access mask in BOTH modes, so a dry run sees the same denials; a dry run's create
/// check is open_checked's `probe_create`. The facts are captured, ONE verdict (refusal_reason) is taken, and only a real
/// run then mutates and verifies. NOT transactional: continue_on_error=false stops at the first refused or failed item (the
/// rest are `skipped`); the answer is 1 whenever any item was refused or failed. Rows, undo coverage per op and the
/// bounds: README "apply".
///
/// STREAMED: each item's rows go out AS THE ITEM CONCLUDES, before the next item opens anything: its audit line, then its
/// item row, then (a delete_key that mutated) its undo rows; the summary row comes last. So a later exception inside the
/// plugin, or a failed output channel, cannot take back the rows already written. NOT durable against agent death: the
/// agent buffers them and sends at command end or each 64 KiB (agent.cpp kOutputFlushThreshold; the ABI has no flush),
/// so an agent that dies mid-plan loses whatever it had not sent (all of it for a plan under 64 KiB of output). A
/// sink failure follows LineSink's rule and STOPS the plan: nothing after that item is opened or mutated, and the answer
/// is 1. The handles are closed when this returns (the map dies with it).
template <class Ctx>
[[nodiscard]] int run_apply(Ctx& ctx, RegistryWriter& reg, Handle hklm, const std::vector<PlanItem>& items,
                            ApplyOptions opt, bool fast_eligible = false) {
    LineSink<Ctx> sink{ctx};
    int rc = 0;
    ApplySummary sum;
    sum.total = items.size();
    sum.dry_run = opt.dry_run;
    CaptureBudget budget;
    std::map<std::string, Opened> by_key; // folded key -> its checked handle; SUCCESSFUL opens only
    std::set<std::string> sim_created;    // dry run only: folded keys an earlier would-be item creates
    bool stopped = false;

    for (std::size_t idx = 0; idx < items.size(); ++idx) {
        const PlanItem& item = items[idx];
        ItemRow row;
        row.index = idx;
        row.op = std::string{plan_op_name(item.op)};
        row.hive = item.hive;
        row.key = item.key;
        row.name = item.name;
        if (stopped) {
            row.verdict = "skipped";
            ++sum.skipped;
            if (!sink.put(render_item_row(row))) return 1;
            continue;
        }

        const bool value_op = !detail::is_key_op(item.op);
        const bool creating_op = item.op == PlanOp::set_value || item.op == PlanOp::create_key;
        AuditRecord au;
        au.op = "apply." + row.op;
        au.hive = item.hive;
        au.key = item.key;
        au.name = item.name;
        au.dry_run = opt.dry_run ? 1 : 0;
        if (item.op == PlanOp::set_value) {
            au.type_name = item.type_name;
            au.len = static_cast<long long>(item.bytes.size());
            au.new_bytes = item.bytes;
            au.new_total = item.bytes.size();
            au.has_new = true;
            row.new_len = au.len;
        }

        ItemFacts facts;
        Opened* handle = nullptr; // this item's checked handle, owned by by_key
        unsigned open_created = 0, open_missing = 0;
        std::string fold;
        if (item.invalid.empty()) {
            fold = detail::fold_ascii(item.key);
            auto it = by_key.find(fold);
            if (it == by_key.end()) {
                std::uint32_t mask = kKeyQueryValue;
                if (value_op) mask |= kKeySetValue;
                if (item.op == PlanOp::delete_key) mask |= kAccessDelete | kKeyEnumerateSubKeys;
                // A link leaf is refused (key_is_link) for delete_key and create_key too: apply promises an undo
                // and its vocabulary has no op that recreates a link.
                Opened op = open_checked(reg, hklm, item.key, mask, /*create=*/!opt.dry_run && creating_op,
                                         /*leaf_may_be_link=*/false, fast_eligible,
                                         /*probe_create=*/opt.dry_run && creating_op);
                open_created = op.created;
                open_missing = op.missing;
                if (op.error.empty())
                    it = by_key.emplace(fold, std::move(op)).first;
                else if (op.error == kTokKeyNotFound && (opt.dry_run || !creating_op))
                    facts.key_exists = false; // a missing key is a fact, not an open failure
                else // a real creating open that answers "not found" lost a race with a delete
                    facts.open_error = op.error == kTokKeyNotFound ? std::string{kTokConcurrentChange} : op.error;
            }
            if (it != by_key.end()) handle = &it->second;
            if (handle != nullptr) {
                const Handle h = handle->handle();
                if (value_op) {
                    facts.old = capture_old(reg, h, item.name);
                } else if (item.op == PlanOp::delete_key) {
                    std::string first;
                    const long src = reg.enum_subkey(h, 0, first);
                    facts.has_subkeys = src == kErrorSuccess;
                    if (src != kErrorSuccess && src != kErrorNoMoreItems) facts.leaf_error = rc_token(src, Missing::key);
                    if (!facts.has_subkeys && facts.leaf_error.empty()) {
                        CaptureBudget trial = budget;
                        LeafVet vet = vet_leaf_values(reg, h, trial);
                        facts.leaf_error = std::move(vet.error);
                        facts.leaf_capped = vet.capped;
                        facts.leaf_value_count = vet.values;
                        if (facts.leaf_error.empty() && !vet.capped) {
                            budget = trial;
                            facts.leaf_values = std::move(vet.kept);
                        }
                    }
                }
            }
            if (opt.dry_run && !facts.key_exists) {
                // A dry run creates nothing, so the key an earlier would-be item creates is still missing here: predict
                // `created` through the folded prefixes those items would make, and let a delete_value see such a key.
                if (creating_op) {
                    const auto parts = split_key(item.key);
                    std::string prefix;
                    unsigned would = 0;
                    for (std::size_t i = 0; i < parts.size(); ++i) {
                        prefix += (i != 0 ? "\\" : "") + detail::fold_ascii(parts[i]);
                        if (i + open_missing >= parts.size() && sim_created.insert(prefix).second) ++would;
                    }
                    open_created = would;
                } else if (sim_created.contains(fold)) {
                    facts.key_exists = true; // the real run would find it (with no values in it)
                }
            }
            row.created = static_cast<long long>(open_created);
            au.created = row.created;
        }
        std::string reason = refusal_reason(item, facts);
        // Unreachable by construction (a real run's creating open either yields a handle or an open_error, and the other
        // ops refuse a missing key); it keeps a null handle from ever being dereferenced below.
        if (reason.empty() && !opt.dry_run && handle == nullptr) reason = std::string{kTokConcurrentChange};

        // The previous value and the delete_key counts are facts only when they were read (a handle was captured on, or
        // the key is known missing): an item refused BEFORE that (invalid, or its open failed) shows `-`, never
        // `old_state=absent`, which the undo table reads as "delete it". The dry run reads the same facts as the real run.
        // A new pre-capture refusal added to refusal_reason must also clear facts_read.
        const bool facts_read = item.invalid.empty() && facts.open_error.empty();
        if (value_op && facts_read) {
            row.value_op = true;
            if (reason.empty()) {
                row.old = budgeted_old(budget, item.name, facts.old);
            } else {
                // A refused item changes nothing, so its previous value is not undo evidence: it must not spend the
                // shared budget (which would flag a later item's manifest incomplete) nor flag it itself. Its bytes are
                // not retained on the row either (state, type and ~total stay), which keeps the reply bound.
                row.old = facts.old;
                row.old.bytes.clear();
            }
            fill_old(au, facts.old); // the audit line keeps its own bounded evidence (256 raw bytes)
        }
        if (item.op == PlanOp::delete_key && facts_read) {
            au.counted_keys = facts.key_exists ? 1 : 0;
            // The values were counted only when the vet ran to its end or its bound: a key with subkeys, or a leaf whose
            // enumeration or vet refused, keeps `-` (not read), never a partial or zero count.
            if (!facts.has_subkeys && facts.leaf_error.empty()) {
                au.counted_values = static_cast<long long>(facts.leaf_value_count);
                au.capped = facts.leaf_capped ? 1 : 0;
            }
        }

        std::string verdict;
        bool undo = false; // a real delete_key that took its values: its undo rows follow its item row
        if (!reason.empty()) {
            // A real creating item whose open made keys and that is then refused: roll them back NOW, by their own
            // handles, so `created` is what stayed when the row goes out and nothing the item made outlives it; the
            // entry is erased, so a later item on the key opens afresh.
            if (!opt.dry_run && handle != nullptr && !handle->made.empty()) {
                handle->rollback();
                open_created = handle->created;
                row.created = au.created = static_cast<long long>(open_created);
                by_key.erase(fold);
                handle = nullptr;
            }
            // open_checked created some components, then failed (it rolled back what it could: `created` is what stayed).
            const bool partial = !opt.dry_run && open_created > 0;
            // created < missing: a PREFIX of the missing tail exists, so `created=<n>` (the undo reads it as the n
            // trailing components) cannot name what to remove -- flag the manifest. All created and then refused is exact.
            if (partial && open_created < open_missing) budget.incomplete = true;
            verdict = partial ? "failed" : "refused";
            row.reason = reason;
            au.result = verdict;
            au.reason = reason;
            ++(partial ? sum.failed : sum.refused);
        } else if (opt.dry_run) {
            verdict = "would_apply";
            au.result = "ok";
            ++sum.applied;
        } else {
            const Handle h = handle->handle();
            WriteOutcome wo;
            switch (item.op) {
            case PlanOp::set_value:
                handle->value_name = item.name; // a creating write that unwinds first removes this value again
                wo = write_value_on(reg, h, item.name, item.type, item.bytes, &handle->value_landed);
                break;
            case PlanOp::delete_value: wo = delete_value_on(reg, h, item.name); break;
            // No read-back (verify stays `-`): the handle open_checked returned is the evidence the key exists -- an
            // existing key it opened and link-probed, or one it created whose REG_CREATED_NEW_KEY disposition it
            // checked -- and a re-query would prove only that it is open.
            case PlanOp::create_key: wo.result = "ok"; break;
            case PlanOp::delete_key: wo = delete_key_on(reg, h, false); break;
            case PlanOp::count_: break; // unreachable: parse_plan never yields it
            }
            if (creating_op) handle->commit(); // the item is over, whatever it concluded: the keys it made stay
            row.verify = wo.verify;
            au.verify = wo.verify;
            // `mutated`, not `ok`: a delete whose verify then mismatched still took the values with it.
            undo = item.op == PlanOp::delete_key && wo.mutated;
            if (wo.ok()) {
                verdict = "applied";
                au.result = "ok";
                ++sum.applied;
            } else {
                verdict = "failed";
                row.reason = wo.reason;
                au.result = "failed";
                au.reason = wo.reason;
                ++sum.failed;
            }
        }
        row.verdict = verdict;
        // The audit line first: it is the evidence a later sink failure must not lose. put_audit opens this item's unit,
        // so if THIS line cannot be written the failure reaches the seam's fixed row (item N may already have mutated).
        if (!sink.put_audit(render_audit_line(au)) || !sink.put(render_item_row(row))) return 1;
        if (undo)
            for (const auto& nv : facts.leaf_values)
                if (!sink.put(render_undo_row(idx, nv.name, nv.v))) return 1;
        if (verdict == "refused" || verdict == "failed") {
            rc = 1;
            if (!opt.continue_on_error) stopped = true;
        }
    }

    sum.undo_complete = !budget.incomplete;
    if (!sink.put(render_summary_row(sum))) return 1;
    if (rc != 0 && !sink.put("error|partial_failure")) return 1;
    return rc;
}

/// Writes a single action's rendered lines through LineSink (its failure rule applies).
template <class Ctx>
int emit_lines(Ctx& ctx, const ActionOutput& out) {
    LineSink<Ctx> sink{ctx};
    for (const auto& line : out.lines)
        if (!sink.put(line)) return 1;
    return out.rc;
}

/// The catch at the plugin ABI seam, both OS legs (`Ctx` is yuzu::CommandContext; a template so the pure unit
/// suites can drive it with a recording fake): a mutating action leaves its fixed `exception` audit line first, so
/// the server still mints a failed `registry.write` row, then every action answers `error|exception`. Each write is
/// best effort and separate: an allocation failure on one cannot suppress the other, and nothing escapes.
template <class Ctx>
void report_exception(Ctx& ctx, std::string_view action) noexcept {
    try {
        if (const auto row = exception_audit_line(action); !row.empty()) ctx.write_output(row);
    } catch (...) {
    }
    try {
        ctx.write_output("error|exception");
    } catch (...) {
    }
}

} // namespace yuzu::registry
