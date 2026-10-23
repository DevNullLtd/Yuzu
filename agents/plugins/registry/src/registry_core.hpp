#pragma once

/**
 * registry_core.hpp -- the registry plugin's write logic over an INJECTED registry (OS-free: unit-tested
 * on every host against an in-memory fake; the Win32 binding is registry_win.cpp's Win32Registry).
 *
 * MUTATION TARGETING (the check-to-use closure): every mutation runs on a CHECKED HANDLE and nothing
 * re-resolves a path by name; keys are deleted by handle (NtDeleteKey), never RegDeleteKeyW(parent, name).
 * Every operation captures the previous value first and reads back on the same handle after mutating.
 * README "How it works"; routed-concerns-security-posture.md, registry row. open_checked obtains the handle
 * one of two ways:
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
 *    again, so it can land beneath a link completed meanwhile; a walk that does not hand its leaf over (the name
 *    test refuses, or a later create fails or finds its key already there) deletes every key it created, by its
 *    own handle, leaf first, and `created` reports any that could not be. A key a create merely opened is
 *    closed, never deleted.
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
 * A decoy on the LEAF is refused on both paths (the same probe). A non-ASCII case variant, a failed or
 * overflowing final_name and a failed root_name all fall back to the walk (which refuses the non-ASCII variant,
 * its own name tests using the same ASCII-only fold). No handle outlives one command.
 *
 * The walk's ACCEPT carries the same kind of guarantee (see its bullet): the leaf handle's kernel name is the
 * first component's name plus the remaining requested components, so a link completed after its probe, or a
 * component moved by a rename, refuses `key_is_link` instead of landing the write on the object it now reaches.
 * A same-path substitution (a plain key recreated at the requested name) is not a redirect and stays out of scope.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "registry_parsers.hpp"

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
/// value. Names are UTF-8.
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
    virtual long final_name(Handle key, std::string& out) = 0;
    /// The kernel name of the predefined root `root`, cached by the shell. Only HKLM and HKU have one: HKCU
    /// resolves per calling user and HKCR is a merged view, so for them (and on any failure) it is non-zero.
    virtual long root_name(Handle root, std::string& out) = 0;
    /// RegCreateKeyExW with REG_OPTION_OPEN_LINK; `created_new` is false for REG_OPENED_EXISTING_KEY.
    /// `out` and `created_new` are set only on success.
    virtual long create_sub(Handle parent, std::string_view name, std::uint32_t access, Handle& out,
                            bool& created_new) = 0;
    virtual void close(Handle key) = 0;
    /// `cap` = 0 asks for the size only.
    virtual long query_value(Handle key, std::string_view name, std::size_t cap, QueryResult& out) = 0;
    virtual long set_value(Handle key, std::string_view name, std::uint32_t type,
                           std::span<const std::uint8_t> data) = 0;
    virtual long delete_value(Handle key, std::string_view name) = 0;
    /// kErrorNoMoreItems ends the enumeration.
    virtual long enum_value(Handle key, std::uint32_t index, std::string& name) = 0;
    virtual long enum_subkey(Handle key, std::uint32_t index, std::string& name) = 0;
    /// NtDeleteKey(key): marks the key for deletion by handle. There is NO tree delete here: RegDeleteTreeW
    /// follows a registry link found inside the tree (kingsley probe K1).
    virtual long delete_key_by_handle(Handle key) = 0;
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

struct Opened {
    explicit Opened(RegistryWriter& r) : leaf(r) {}
    Owned leaf;
    unsigned created = 0;  ///< keys THIS call created and left behind (a walk that stops deletes them: the residual)
    unsigned missing = 0;  ///< components that did not exist when the walk reached them
    std::string error;     ///< "" or a token
    bool fast = false;     ///< the handle came from open_fast
};

/// Equal byte for byte except that A-Z fold to a-z: a strict subset of the kernel's case folding, so it never
/// equates two names the kernel keeps distinct. A name that differs only in non-ASCII case compares unequal:
/// the fast open declines and the walk's own name test (leaf_name_check) refuses it.
[[nodiscard]] inline bool names_equal_ascii_ci(std::string_view a, std::string_view b) {
    const auto fold = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c; };
    return std::equal(a.begin(), a.end(), b.begin(), b.end(), [&](char x, char y) { return fold(x) == fold(y); });
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
/// shell) tries open_fast first; a missing key, a refusal and every doubt fall through to the walk below.
[[nodiscard]] inline Opened open_checked(RegistryWriter& reg, Handle root, std::string_view key_path,
                                         std::uint32_t leaf_access, bool create,
                                         bool leaf_may_be_link = false, bool fast_eligible = false) {
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
    std::vector<Owned> made_keys; // keys create_sub reported new, leaf last; held open so a walk that stops can delete them
    Handle parent = root;
    std::string first_name; // the canonical name of the first component's handle, read right after its open
    // Every exit that follows a create but does not hand the leaf over deletes what this call created, by its own
    // handles, leaf first (a create made through a parent that had become a link lands beneath the link's target
    // before any name can be read); `created` is then what could not be deleted. Only a key create_sub reported
    // as new is in made_keys: one it merely opened is somebody else's and is closed, never deleted.
    const auto roll_back = [&] {
        for (auto it = made_keys.rbegin(); it != made_keys.rend(); ++it)
            if (reg.delete_key_by_handle(it->get()) == kErrorSuccess) {
                it->reset(); // a deleted key's handle is closed before its parent is deleted in turn
                --out.created;
            }
    };
    // Hands the leaf over only when its kernel name is the requested path (leaf_name_check); otherwise it rolls back.
    const auto hand_over = [&]() -> Opened {
        Owned& leaf = made_keys.empty() ? cur : made_keys.back();
        if (auto why = leaf_name_check(reg, leaf.get(), first_name, parts); !why.empty()) {
            out.error = std::move(why);
            roll_back();
        } else {
            out.leaf = std::move(leaf);
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
            if (i == 0 && create) { // a component missing directly under the hive root is never created
                out.error = std::string{kTokRootLevelCreate};
                return out;
            }
            if (!create) {
                out.error = std::string{kTokKeyNotFound};
                return out;
            }
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
                    roll_back();
                    return out;
                }
                Owned made_owner{reg, made}; // closes on the early return below: opened-existing is never deleted
                if (!created_new) { // the walk saw it absent a moment ago
                    out.error = std::string{kTokConcurrentChange};
                    roll_back();
                    return out;
                }
                made_keys.push_back(std::move(made_owner));
                ++out.created;
                parent = made_keys.back().get(); // the checked parent in `cur` stays open until the walk ends
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
    std::string result = "refused"; ///< ok | refused (nothing mutated) | failed (a mutation was attempted)
    std::string reason;             ///< "" or a token
    std::string verify;             ///< ok | mismatch | ""
    unsigned created = 0;           ///< keys this operation created and left behind (0 = nothing stranded)
    OldValue old;
    bool has_old = false;
    bool mutated = false;
    std::uint64_t counted_keys = 0;
    std::uint64_t counted_values = 0;
    bool capped = false;
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

/// Writes `bytes` to `name` on the checked handle `h`, reads it back and compares (type + bytes).
[[nodiscard]] inline WriteOutcome write_value_on(RegistryWriter& reg, Handle h, std::string_view name,
                                                 std::uint32_t type, std::span<const std::uint8_t> bytes) {
    WriteOutcome o;
    if (const long rc = reg.set_value(h, name, type, bytes); rc != kErrorSuccess) {
        o.fail(rc_token(rc, Missing::value), true);
        return o;
    }
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

[[nodiscard]] inline WriteOutcome set_value_verified(RegistryWriter& reg, Handle root, std::string_view key,
                                                     std::string_view name, std::uint32_t type,
                                                     std::span<const std::uint8_t> bytes,
                                                     bool fast_eligible = false) {
    auto op = open_checked(reg, root, key, kKeySetValue | kKeyQueryValue, /*create=*/true,
                           /*leaf_may_be_link=*/false, fast_eligible);
    if (!op.error.empty()) {
        WriteOutcome o;
        o.created = op.created;
        o.fail(op.error, op.created > 0);
        return o;
    }
    OldValue old = capture_old(reg, op.leaf.get(), name);
    WriteOutcome o = write_value_on(reg, op.leaf.get(), name, type, bytes);
    o.created = op.created;
    o.old = std::move(old);
    o.has_old = true;
    return o;
}

[[nodiscard]] inline WriteOutcome delete_value_verified(RegistryWriter& reg, Handle root, std::string_view key,
                                                        std::string_view name, bool fast_eligible = false) {
    auto op = open_checked(reg, root, key, kKeySetValue | kKeyQueryValue, /*create=*/false,
                           /*leaf_may_be_link=*/false, fast_eligible);
    if (!op.error.empty()) {
        WriteOutcome o;
        o.fail(op.error, false);
        return o;
    }
    OldValue old = capture_old(reg, op.leaf.get(), name);
    WriteOutcome o;
    if (old.state == OldState::absent)
        o.fail(std::string{kTokValueNotFound}, false);
    else
        o = delete_value_on(reg, op.leaf.get(), name);
    o.old = std::move(old);
    o.has_old = true;
    return o;
}

// ── delete_key ───────────────────────────────────────────────────────────

struct TreeCount {
    std::uint64_t keys = 0, values = 0, nodes = 0;
    bool capped = false;
    std::string error;
};

/// Counts the values of the leaf `h`: nodes are keys + values, and the key itself is node 1 (so the cap is
/// the key plus up to kMaxTreeNodes - 1 values). kMaxTreeNodes bounds the enumeration at 10,000 iterations even
/// when the value set grows between calls. Past the bound `capped` is set and `values` is a lower bound; the
/// delete still proceeds, because NtDeleteKey of a leaf removes its values.
[[nodiscard]] inline TreeCount count_values(RegistryWriter& reg, Handle h) {
    TreeCount c;
    c.keys = 1;
    c.nodes = 1;
    std::string name;
    for (std::uint32_t i = 0;; ++i) {
        const long rc = reg.enum_value(h, i, name);
        if (rc == kErrorNoMoreItems) return c;
        if (rc != kErrorSuccess) {
            c.error = rc_token(rc, Missing::value);
            return c;
        }
        if (c.nodes >= kMaxTreeNodes) {
            c.capped = true;
            return c;
        }
        ++c.values;
        ++c.nodes;
    }
}

/// Deletes the key on the checked handle `h` with NtDeleteKey(h), verified by the deleted handle reporting
/// ERROR_KEY_DELETED.
[[nodiscard]] inline WriteOutcome delete_key_on(RegistryWriter& reg, Handle h) {
    WriteOutcome o;
    if (const long rc = reg.delete_key_by_handle(h); rc != kErrorSuccess) {
        o.fail(rc_token(rc, Missing::key), true);
        return o;
    }
    o.mutated = true;
    QueryResult q;
    o.confirm(reg.query_value(h, "", 0, q) == kErrorKeyDeleted);
    return o;
}

/// Non-recursive delete_key: a key with subkeys is refused `key_has_subkeys` and nothing is deleted. A leaf's
/// counts are what the enumeration saw before the delete (a lower bound when `capped`); a link leaf is
/// opened as the link object, so the delete removes the link and never its target.
[[nodiscard]] inline WriteOutcome delete_key_tree(RegistryWriter& reg, Handle root, std::string_view key,
                                                  bool fast_eligible = false) {
    auto op = open_checked(reg, root, key,
                           kAccessDelete | kKeyEnumerateSubKeys | kKeyQueryValue | kKeySetValue,
                           /*create=*/false, /*leaf_may_be_link=*/true, fast_eligible);
    if (!op.error.empty()) {
        WriteOutcome o;
        o.fail(op.error, false);
        return o;
    }
    const Handle h = op.leaf.get();
    TreeCount c;
    std::string first;
    const long rc = reg.enum_subkey(h, 0, first);
    if (rc == kErrorSuccess)
        c.error = std::string{kTokKeyHasSubkeys};
    else if (rc != kErrorNoMoreItems)
        c.error = rc_token(rc, Missing::key);
    else
        c = count_values(reg, h);
    WriteOutcome o;
    if (c.error.empty())
        o = delete_key_on(reg, h);
    else
        o.fail(c.error, false);
    o.counted_keys = c.keys;
    o.counted_values = c.values;
    o.capped = c.capped;
    return o;
}

// ── audit + output ───────────────────────────────────────────────────────

struct ActionOutput {
    std::vector<std::string> lines;
    int rc = 0;
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
/// with op, hive, key, name, type, len, sid and the new bytes; the outcome fields are set here.
[[nodiscard]] inline ActionOutput render_single_action(AuditRecord base, const WriteOutcome& o,
                                                       bool is_delete_key) {
    base.result = o.result;
    base.reason = o.reason;
    base.verify = o.verify;
    base.created = static_cast<long long>(o.created);
    if (o.has_old) fill_old(base, o.old);
    if (is_delete_key) {
        base.dry_run = 0;
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
        out.lines.push_back("dry_run|0");
        out.lines.push_back(std::string{"capped|"} + (o.capped ? "1" : "0"));
    }
    return out;
}

} // namespace yuzu::registry
