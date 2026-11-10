#pragma once

/// @file installed_software_v3.hpp
/// The pure writer for the `installed_software` blob contract v3 (ADR-0016 Updates 2026-11-04
/// and 2026-11-09): sectioned, one section per source (a plugin action), rows plus a row-hash
/// delta when the source is FULL, status only when it is degraded. No plugin, no KV, no clock and
/// no I/O, so the whole writer is unit-tested against the server's golden vectors
/// (tests/unit/server/test_software_inventory_store.cpp) without a build of the collector.
///
/// The server parser is server/core/src/inventory_blob_v3.hpp and its hash recipes are
/// SoftwareInventoryStore::{canonical_section_hash, v3_report_hash, component_row_hash,
/// canonical_component_section_hash}. This file mirrors them byte for byte. A one-sided change
/// breaks hash agreement permanently (a delta is refused `mismatch` and the facet is resent in
/// full on every cycle), so the caps below are comment-coordinated with that header.
///
/// ONE preparation step: every field of every record passes through clamp_field
/// (sync_canonical.hpp: scrub to UTF-8, clamp to 1,024 bytes on a codepoint boundary, then strip
/// 0x1F, 0x1E and NUL). The server only ever sees the bytes sent, so stripping a separator and
/// replacing it agree on the hash equally; what must not happen is a raw separator or NUL
/// reaching the wire (the first re-frames the record, the second refuses the section).

#include "sync_source_installed_software.hpp" // SwEntry

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// Wire caps. MUST equal server/core/src/inventory_blob_v3.hpp (kV3Max*). A section the agent
/// sends over a cap is refused whole, so the writer plans to them.
inline constexpr std::size_t kV3MaxBlobBytes = 3u * 1024 * 1024;
inline constexpr std::size_t kV3MaxSections = 32;
inline constexpr std::size_t kV3MaxRows = 20000;        ///< `+` rows per call
inline constexpr std::size_t kV3MaxDeletions = 20000;   ///< `-` records per call
inline constexpr std::size_t kV3MaxComponents = 20000;  ///< `comp` records per call
inline constexpr std::size_t kV3MaxFieldLen = 1024;
inline constexpr std::string_view kV3Header = "\037v3\036";

/// Bytes reserved per status-only section when a row-bearing section is sized against the blob
/// cap. A status-only `S` record carries no base and no expect, so at worst it is 1 + 1 + 64
/// (facet) + 1 + 13 (status) + 1 + 64 (token) + 1 + 19 + 1 + 19 (the two numerics) + 3 separators
/// and the terminator, well inside this.
inline constexpr std::size_t kV3StatusRecordReserve = 256;
/// The most one row-bearing section may occupy and still ship alone: the blob cap, less the
/// header and a status record for every section the blob may carry. A facet whose FULL form
/// exceeds it is `oversize` (status-only) and is never deferred: waiting cannot make it fit.
inline constexpr std::size_t kV3SectionByteBudget =
    kV3MaxBlobBytes - kV3Header.size() - kV3MaxSections * kV3StatusRecordReserve;

/// Section status; the wire spelling is v3_status_name.
enum class V3Status { full, delta, constrained, timeout, oversize, not_collected, disabled };

[[nodiscard]] constexpr std::string_view v3_status_name(V3Status s) noexcept {
    switch (s) {
    case V3Status::full:
        return "full";
    case V3Status::delta:
        return "delta";
    case V3Status::constrained:
        return "constrained";
    case V3Status::timeout:
        return "timeout";
    case V3Status::oversize:
        return "oversize";
    case V3Status::not_collected:
        return "not_collected";
    case V3Status::disabled:
        return "disabled";
    }
    return "not_collected";
}

/// Only full and delta sections carry records.
[[nodiscard]] constexpr bool v3_status_carries_rows(V3Status s) noexcept {
    return s == V3Status::full || s == V3Status::delta;
}

// ── Field rules ──────────────────────────────────────────────────────────────────────────

/// The canonical epoch spelling: rpm prints "(none)" for an unset epoch and some hosts print an
/// explicit "0"; both mean no epoch, so both are written empty and one package reads the same
/// from one collection to the next (a flipping spelling would be a remove and an install on the
/// server's ledger).
[[nodiscard]] YUZU_EXPORT std::string canonical_epoch(std::string_view epoch);
/// The canonical release spelling: "(none)" (rpm's unset marker) is empty. A release of "0" is
/// a real release and is kept.
[[nodiscard]] YUZU_EXPORT std::string canonical_release(std::string_view release);

/// The install_location the writer sends for a raw collector value, or empty. Slot 13 is an
/// ALLOWLIST (ADR-0016 section 8: machine-scope data only; the server stores it as sent and
/// keeps a copy in the change ledger for 400 days): the value is canonicalised first (quotes
/// and padding trimmed, the Win32 `\\?\` and `\\.\` prefixes dropped, separator runs collapsed,
/// `.` and `..` resolved, trailing dots and spaces stripped per Windows segment, the macOS
/// `/System/Volumes/Data` firmlink folded) and KEPT, in one spelling with the segments' own
/// case (`C:\Program Files\X`, `/Applications/X.app`), only when it sits under a root of `kMachineRoots` in
/// installed_software_v3.cpp: Windows `Program Files`, `Program Files (x86)`, `ProgramData`
/// and `Windows` under any drive letter; macOS `/Applications`, `/Library`,
/// `/System/Applications`, `/Developer`; `/opt` and `/usr`; Linux `/snap`, `/var/lib/flatpak`,
/// `/nix`, `/app`. Everything else is blanked: a home under any root (`C:\Users`, `/home`,
/// `E:\Profiles\alice`, `/Volumes/<label>/Users`), a UNC path (a home share cannot be told
/// from an application share), a drive-relative path, an unexpanded `%ProgramFiles%`, an NT
/// object name (`\??\`, `Volume{...}`, `GLOBALROOT`), an 8.3 name, a `..` that escapes the
/// root, anything with a control byte (DEL included). Fails closed: an unrecognised shape is
/// blank. The row's name, version, publisher and hash are reported whatever this returns. The
/// result is a fixed point (`machine_install_location(x) == machine_install_location(
/// machine_install_location(x))`): a stored form normalised again is the same bytes.
[[nodiscard]] YUZU_EXPORT std::string machine_install_location(std::string_view raw);

/// The stored form of one row, exactly what the server holds after its own field step: every
/// field through clamp_field, the canonical epoch and release, and install_location through
/// machine_install_location. A fixed point: `v3_normal_form(v3_normal_form(x)) == v3_normal_form(x)`
/// over every field (tests/unit/test_installed_software_v3.cpp pins it over the privacy corpus).
/// Every hash below is taken over this form.
[[nodiscard]] YUZU_EXPORT SwEntry v3_normal_form(const SwEntry& e);

/// Normal form of every row, nameless rows dropped (the server drops them too), then sorted and
/// de-duplicated in the server's comparator order (name .. distro_version, install_location,
/// package_id, source; byte-wise). Order- and duplicate-independent input in, one canonical
/// vector out.
[[nodiscard]] YUZU_EXPORT std::vector<SwEntry> v3_normalise_rows(std::vector<SwEntry> rows);

// ── Records and hashes (installed software) ──────────────────────────────────────────────

/// One row in the section-hash form: ALL 16 wire slots (slot 14, the reserved uninstall_string,
/// empty; no conditional tail), 0x1F-joined and 0x1E-terminated. The wire `+` record is "+" US
/// then this.
[[nodiscard]] YUZU_EXPORT std::string v3_record(const SwEntry& e);
/// SHA-256 hex of v3_record(e): the server's `instance_key`, the value a `-` record names.
[[nodiscard]] YUZU_EXPORT std::string v3_row_hash(const SwEntry& e);
/// SHA-256 hex over the sorted, de-duplicated records of a section: the server's
/// canonical_section_hash. The empty set hashes the empty string.
[[nodiscard]] YUZU_EXPORT std::string v3_section_hash(std::vector<SwEntry> rows);
/// "v3:" + SHA-256 hex over `facet 0x1F section_hash 0x1E`, byte-order sorted by facet: the
/// server's v3_report_hash, over the facets the agent HOLDS (full or delta acked, not since
/// reported status-only).
[[nodiscard]] YUZU_EXPORT std::string
v3_report_hash(std::vector<std::pair<std::string, std::string>> held);

// ── Components (the `component_inventory` facet) ─────────────────────────────────────────
// No plugin produces component rows yet (the evidence collector is a later change); the
// records and hashes are pinned to the server recipe now so that change cannot drift.
// component_normal_form clamps `path` and `anchor_app` but applies NO machine-root allowlist to
// them (ADR-0016 holds the component writer to the slot-13 precondition: the server stores both
// as sent). The producer (SAM-40) must canonicalise each row ONCE, apply the allowlist there,
// and pin planner-vs-wire equality for component sections the way the installed-software tests
// below do; nothing reaches the wire until it exists.

struct SwComponent {
    std::string kind;
    std::string name;
    std::string version;
    std::string version_source; ///< filename|pom|manifest|metadata|package_json|pe|elf|macho|unreadable
    std::string path;
    std::int64_t size{0};
    std::int64_t mtime{0};
    std::string anchor_app;
};

/// `kind US name US version US version_source US path US size US mtime US anchor_app RS`, text
/// fields through clamp_field, size and mtime decimal (a negative reads as 0), a version_source
/// outside the server's closed set written `unreadable`.
[[nodiscard]] YUZU_EXPORT std::string v3_component_record(const SwComponent& c);
[[nodiscard]] YUZU_EXPORT std::string v3_component_row_hash(const SwComponent& c);
/// Sorted (size and mtime numerically), de-duplicated by whole record, SHA-256 hex over the
/// concatenated records. A component whose kind or name is empty after clamping is dropped (the
/// server refuses the section that carries one).
[[nodiscard]] YUZU_EXPORT std::string v3_component_section_hash(std::vector<SwComponent> rows);

// ── Planning a section ───────────────────────────────────────────────────────────────────

/// What the server holds for a facet as far as the agent knows: the section hash it last
/// acknowledged and the sorted row hashes (SHA-256 hex) of that set.
struct AckedSet {
    std::string section_hash;
    std::vector<std::string> row_hashes; ///< sorted ascending, unique
};

/// One facet's section for one call.
struct SectionPlan {
    std::string facet;
    V3Status status{V3Status::not_collected};
    std::string token;  ///< bounded reason (sanitised by the writer); empty for full/delta
    std::string base;   ///< delta: the acked section hash the delta applies on
    std::string expect; ///< delta: the section hash after the delta; empty otherwise
    std::vector<SwEntry> adds;          ///< full: every row; delta: the `+` rows
    std::vector<std::string> deletes;   ///< delta: row hashes of the `-` records
    std::vector<SwComponent> components; ///< full component_inventory only
    std::int64_t duration_ms{0};
    std::int64_t bytes_read{0};
    // Planner facts, not on the wire.
    bool unchanged{false};          ///< acked set equals the current set: no section at all
    std::string section_hash;       ///< hash of the CURRENT set (the hash held after this section)
    std::vector<std::string> row_hashes; ///< sorted row hashes of the CURRENT set
    std::size_t full_bytes{0};      ///< serialised size of the FULL form of the section
};

/// Plan one facet's section from its current rows.
///  - more than kV3MaxRows rows, or a FULL form over kV3SectionByteBudget -> `oversize` with
///    token `rows=<n>` / `bytes=<n>`. Intrinsically unshippable: never deferred, never split.
///  - no acked set, or `need_full` -> `full`.
///  - an acked set equal to the current one -> `unchanged`.
///  - otherwise a `delta`: `+` for current rows whose hash is not acked, `-` for acked hashes no
///    longer current, `base` the acked hash, `expect` the hash of the current set. A delta that
///    would exceed kV3MaxRows adds, kV3MaxDeletions deletions, or kV3SectionByteBudget bytes falls
///    back to `full`.
/// `rows` need not be normalised.
[[nodiscard]] YUZU_EXPORT SectionPlan plan_section(std::string facet, std::vector<SwEntry> rows,
                                                   const std::optional<AckedSet>& acked,
                                                   bool need_full);

/// A status-only section (constrained, timeout, oversize, not_collected, disabled).
[[nodiscard]] YUZU_EXPORT SectionPlan status_section(std::string facet, V3Status status,
                                                     std::string token);

struct V3Blob {
    std::string blob;
    std::vector<std::string> sent;     ///< facets written, in wire order (status-only first)
    std::vector<std::string> deferred; ///< row-bearing facets left out because a call cap was reached
};

/// Serialise a call: the header, then every status-only section, then the row-bearing sections
/// in `plans` order while the running `+` count stays within kV3MaxRows, `-` within
/// kV3MaxDeletions, `comp` within kV3MaxComponents, the blob within kV3MaxBlobBytes and the
/// section count within kV3MaxSections. A row-bearing section that would cross a cap (it fits
/// alone, the planner guarantees it) is deferred: not written and not claimed held, so the
/// next collection sends it. An `unchanged` plan is skipped (it is in neither list).
/// `adds` are written byte for byte as planned: plan_section is the ONE normalisation point, so
/// the record the section hash and row hashes were taken over is the record on the wire.
[[nodiscard]] YUZU_EXPORT V3Blob write_v3_blob(const std::vector<SectionPlan>& plans);

// ── The persisted acked set ──────────────────────────────────────────────────────────────

/// `<section_hash> '\n' <concatenated sorted 64-hex row hashes>`: one value, so one KV write
/// (one SQLite statement) commits the hash and the set together.
[[nodiscard]] YUZU_EXPORT std::string acked_encode(const AckedSet& a);
/// The inverse. Anything that is not exactly that shape (a 64-lowercase-hex head, '\n', a body
/// whose length is a multiple of 64 made of lowercase hex, at most kV3MaxRows hashes) reads as
/// no acked set, so a torn or hand-edited value costs one full section and nothing else.
[[nodiscard]] YUZU_EXPORT std::optional<AckedSet> acked_decode(std::string_view value);

} // namespace yuzu::agent
