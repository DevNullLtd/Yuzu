/**
 * middleware_runner.hpp -- the GENERIC runner of the middleware plugin: one product leg of the table
 * (agents/shared/middleware_products.hpp) turned into data rows and status tokens.
 *
 * Pure orchestration. No OS header, no filesystem library, no logging, no thread: every OS touch goes
 * through the `Fs` the caller passes, every per-item shortfall through the `Log` callable, so the
 * runner is unit-tested end to end over an in-memory fake (tests/unit/test_middleware_parsers.cpp)
 * and the same body serves every OS and every product.
 *
 * THE Fs CONCEPT (MiddlewareFs, checked by a requires clause on run_leg). The Fs owns path safety
 * (absolute-path validation, no followed symlink, network-mount skip) and the entries-visited budget;
 * it answers with an Outcome, never an exception:
 *
 *   Read    read_abs(std::string_view abs_path, std::size_t cap)
 *               the file's text, or why not. A file larger than `cap` is Outcome::oversized.
 *   Listing list_under(std::string_view base_abs_path, std::string_view subdir)
 *               the file NAMES of `<base>/<subdir>`: `error` = the listing is unreliable, `truncated`
 *               = it was cut at the Fs's own per-directory cap or by its entries budget; `out`
 *               carries a refusal.
 *   bool    exhausted() const        the Fs's entries-visited budget ran dry
 *   std::string_view os() const      "linux" | "windows" | "macos", the first token field
 *
 * THE Log CALLABLE. `log(product_id, probe_id, ItemReason, item)` -- one call per per-item shortfall;
 * `item` is the installation's name, or `stanza <n>` (1-based) for a dropped stanza, which may have
 * no name. It never reaches the status row.
 *
 * WHAT CONSTRAINS THE ANSWER, token by token. Only an ACCESS or WALK fault constrains (a status
 * token, `constrained`, and the collector then withholds the source); a DATA-SHAPE fault in one
 * stanza beside valid ones is logged and the valid siblings are kept. Failure never reads as
 * absent: nothing below turns an unreadable read into an empty `supported`.
 *
 *   enumerator file absent                              supported, zero rows (none found)
 *   denied / oversized / symlink / network / refused /
 *     failed read of the enumerator file                CONSTRAINED  <probe>:permission_denied |
 *                                                       oversized | symlink_refused |
 *                                                       network_fs_skipped | unreadable
 *   stanzas cut at kMaxRows (report.truncated)          CONSTRAINED  <probe>:row_cap; first
 *                                                       kMaxRows kept
 *   entries / row / byte budget out (walk or Fs)        CONSTRAINED  walk:row_cap
 *   mount table unreadable (the caller adds it)         CONSTRAINED  mountinfo:unreadable
 *   content but no stanza line (report.malformed)       CONSTRAINED  <probe>:malformed; zero
 *                                                       candidates by construction
 *   some stanzas dropped (no Name or no FilePath), at
 *     least one valid                                   supported; one log line per dropped stanza
 *                                                       (ItemReason::malformed), siblings kept
 *   every stanza dropped (non-empty file, zero valid)   CONSTRAINED  <probe>:malformed; an
 *                                                       incomplete answer, never an empty supported
 *   one candidate's listing missing / refused /
 *     unreadable / no product tag                       supported; logged; that row's version is "-"
 *
 * ONE BUDGET. `budget` is THE row/byte budget of the leg: the caller builds it (make_row_budget
 * clamps every injected limit to the production ceilings) and nothing in the runner or the Fs
 * constructs a second one. A row the budget refuses, or a listing that leaves the Fs budget
 * exhausted, ends the walk with `<os>:middleware:walk:row_cap`; the candidate being resolved when
 * the Fs budget ran dry gets no row, because its version is no longer trustworthy.
 *
 * ORDER OF THE VERSION PROBES (a per-item decision, fixed): for a candidate, every dir_name probe in
 * table order; a listing is judged ONCE per distinct sub-directory and in this order --
 *   1. out is refused / network / symlink      -> ItemReason::path_refused
 *   2. out is absent                           -> ItemReason::missing
 *   3. out is not ok, or error, or truncated   -> ItemReason::unreadable; the names are DISCARDED
 *      unexamined: a partial listing is never matched, even when a valid product name is in it
 *   4. a complete, clean listing               -> sorted and scanned; the first name the probe's
 *      grammar accepts wins
 * A clean listing that names no product under any probe logs ItemReason::missing (once, against the
 * last probe tried) unless a listing already logged a reason for this candidate. The version then
 * stays empty and the row is still emitted: one installation's unknown version degrades its row, it
 * does not constrain the host.
 */
#pragma once

#include "middleware_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <middleware_products.hpp>
#include <row_byte_budget.hpp>

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::middleware {

/// The production default of the most file names one swidtag-style listing may return before it is
/// `truncated` (the Fs enforces it; a leg's WalkLimits can lower it).
inline constexpr std::size_t kMaxDirEntries = 1024;

struct Candidate {
    std::string name, install_path, version;
};

struct Read {
    enum class Outcome { ok, absent, refused, network, symlink, denied, oversized, failed };
    Outcome out = Outcome::failed; ///< a default-built Read is a failure, never an empty success
    std::string text;
};

struct Listing {
    std::vector<std::string> names;
    bool truncated = false;
    bool error = false;
    Read::Outcome out = Read::Outcome::ok;
};

template <class F>
concept MiddlewareFs = requires(F& fs, const F& cfs) {
    { fs.read_abs(std::string_view{}, std::size_t{}) } -> std::same_as<Read>;
    { fs.list_under(std::string_view{}, std::string_view{}) } -> std::same_as<Listing>;
    { cfs.exhausted() } -> std::convertible_to<bool>;
    { cfs.os() } -> std::convertible_to<std::string_view>;
};

/// A leg's row budget with both limits clamped to the production ceilings.
[[nodiscard]] inline yuzu::shared::RowByteBudget
make_row_budget(std::size_t max_rows = kMaxRows, std::size_t max_bytes = kMaxRowBytes) noexcept {
    yuzu::shared::RowByteBudget b;
    b.max_rows = (std::min)(max_rows, kMaxRows);
    b.max_bytes = (std::min)(max_bytes, kMaxRowBytes);
    return b;
}

namespace detail {

/// The token cause of a failed enumerator read. Not for ok / absent (the caller handles those).
[[nodiscard]] constexpr Cause cause_of(Read::Outcome o) noexcept {
    switch (o) {
    case Read::Outcome::denied:    return Cause::permission_denied;
    case Read::Outcome::oversized: return Cause::oversized;
    case Read::Outcome::symlink:   return Cause::symlink_refused;
    case Read::Outcome::network:   return Cause::network_fs_skipped;
    case Read::Outcome::ok:
    case Read::Outcome::absent:
    case Read::Outcome::refused:
    case Read::Outcome::failed:    break;
    }
    return Cause::unreadable;
}

[[nodiscard]] constexpr bool path_refused(Read::Outcome o) noexcept {
    return o == Read::Outcome::refused || o == Read::Outcome::network ||
           o == Read::Outcome::symlink;
}

/// One distinct sub-directory of one candidate: judged once, scanned by every probe that names it.
struct DirMemo {
    std::string subdir;
    std::vector<std::string> names; ///< sorted; empty and `usable` false unless the listing was clean
    bool usable = false;
};

} // namespace detail

/// Runs one leg of `p` over `fs` and returns its DATA rows (the caller wraps them with
/// compose_output). Enumeration failures are `<os>:middleware:<probe id>:<cause>` tokens in `acc`;
/// per-item shortfalls go to `log` only. A PLANNED leg (no probes) yields nothing.
template <MiddlewareFs Fs, class Log>
[[nodiscard]] std::vector<std::string> run_leg(const Product& p, const OsLeg& leg, Fs& fs,
                                               yuzu::shared::ConstraintAccumulator& acc,
                                               yuzu::shared::RowByteBudget& budget, Log&& log)
    requires std::invocable<Log&, std::string_view, std::string_view, ItemReason, std::string_view>
{
    std::vector<std::string> rows;
    if (leg.probes.empty())
        return rows;
    const std::string_view os = fs.os();
    const auto fail = [&](std::string_view source, Cause c) {
        acc.add_failure(make_token(os, source, c));
    };

    // 1. the enumerator: every stanza of probes[0] is a candidate.
    const Probe& enumerator = leg.probes[0]; // products_well_formed() guarantees a kv_file
    Read file = fs.read_abs(enumerator.path, kMaxKvFileBytes);
    if (file.out == Read::Outcome::absent)
        return rows; // no such file: none found, and not a failure
    if (file.out != Read::Outcome::ok) {
        fail(enumerator.id, detail::cause_of(file.out));
        return rows;
    }
    ParseReport report;
    const std::vector<KvStanza> stanzas = parse_kv_stanzas(file.text, enumerator.stanza, report);
    if (report.malformed)
        fail(enumerator.id, Cause::malformed);
    if (report.truncated)
        fail(enumerator.id, Cause::row_cap);
    std::vector<Candidate> candidates;
    std::size_t ordinal = 0;
    for (const KvStanza& s : stanzas) {
        ++ordinal;
        const std::string* name = s.get(enumerator.name_key);
        const std::string* path = s.get(enumerator.path_key);
        if (name == nullptr || path == nullptr || name->empty() || path->empty()) {
            // A data-shape fault of ONE stanza: logged against its 1-based position (it may have
            // no name to give), its siblings are kept. The table above says when this is a token.
            ++report.dropped;
            const std::string where = "stanza " + std::to_string(ordinal);
            log(std::string_view{p.id}, std::string_view{enumerator.id}, ItemReason::malformed,
                std::string_view{where});
            continue;
        }
        candidates.push_back({*name, *path, std::string{}});
    }
    if (!stanzas.empty() && report.dropped == stanzas.size())
        fail(enumerator.id, Cause::malformed); // every stanza dropped: incomplete, not "none found"

    // 2. per candidate: the version from the first dir_name probe that names one.
    for (Candidate& c : candidates) {
        std::vector<detail::DirMemo> memo; // one entry per distinct sub-directory, per candidate
        bool logged = false;
        const auto note = [&](const Probe& pr, ItemReason r) {
            logged = true;
            log(std::string_view{p.id}, std::string_view{pr.id}, r, std::string_view{c.name});
        };
        const Probe* last = nullptr;
        for (std::size_t i = 1; i < leg.probes.size() && c.version.empty(); ++i) {
            const Probe& pr = leg.probes[i];
            last = &pr;
            auto it = std::find_if(memo.begin(), memo.end(), [&](const detail::DirMemo& m) {
                return m.subdir == pr.path;
            });
            if (it == memo.end()) {
                Listing l = fs.list_under(c.install_path, pr.path);
                memo.push_back({pr.path, {}, false});
                it = std::prev(memo.end());
                if (detail::path_refused(l.out))
                    note(pr, ItemReason::path_refused);
                else if (l.out == Read::Outcome::absent)
                    note(pr, ItemReason::missing);
                else if (l.out != Read::Outcome::ok || l.error || l.truncated)
                    note(pr, ItemReason::unreadable);
                else {
                    std::sort(l.names.begin(), l.names.end());
                    it->names = std::move(l.names);
                    it->usable = true;
                }
                if (fs.exhausted()) { // the listing ran the entries budget dry: no row past it
                    fail("walk", Cause::row_cap);
                    return rows;
                }
            }
            if (!it->usable)
                continue;
            for (const std::string& n : it->names) {
                if (auto v = version_from_file_name(n, pr.name_prefix, pr.name_suffix, pr.name_form)) {
                    c.version = std::move(*v);
                    break;
                }
            }
        }
        if (c.version.empty() && !logged && last != nullptr)
            note(*last, ItemReason::missing);

        // 3. the row.
        std::string row = format_row(p.id, p.title, c.name, c.version, c.install_path, "");
        if (!budget.charge(row.size())) {
            fail("walk", Cause::row_cap);
            return rows;
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

} // namespace yuzu::middleware
