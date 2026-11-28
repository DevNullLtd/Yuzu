/**
 * file_search_os.hpp -- the bindings each OS shell defines exactly once per build, and the neutral shell
 * (file_search_shell.cpp) stands on. file_search_posix.cpp defines them on Linux and macOS and
 * file_search_win.cpp on Windows; every TU of the plugin compiles on every OS and each of those two is
 * self-gated, so exactly one definition of each name exists in a build (the read_file_extents precedent,
 * file_search_legs.hpp). The slot, the stop flag, the search state, the cursor-key holder and the worker
 * runner are NOT here: they live once, in the neutral shell.
 *
 *   kOs                    the platform tag: the name rule, user-directory rule and mount rules of a plan.
 *   kExceptionProvenance   the typed status provenance when the execute body throws: a literal per OS, so
 *                          the catch-all answers without allocating outside its own guarded calls.
 *   os_read_mounts         the mount table at or under a root and the mounts that contain it.
 *   os_make_leg            one filesystem leg for a unit. Called on the slice's worker.
 *   os_draw_cursor_key     fills the 32-byte cursor key from the system's random source; false if it cannot.
 *   os_in_worker_environment  runs `body` inside the worker thread's environment (priority class, error mode,
 *                          dataless, cloud-files view or capability scope); the environment lasts exactly as
 *                          long as `body`.
 *   os_name_semantics      the OS's name rule.
 *   os_normalise_root      the OS's root normaliser (the request parser's RootNormaliser).
 *   os_user_roots          profile directories of the unit's volume that the built-in `/home`-style rule does
 *                          not reach, as labels in the unit's own namespace. Called on the slice's worker; a
 *                          failure returns none.
 */
#pragma once

#include "file_search_legs.hpp"
#include "file_search_request.hpp"
#include "file_search_rows.hpp"
#include "file_search_volumes.hpp"

#include <file_search_query.hpp>
#include <network_fstype.hpp>

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::file_search {

extern const Os kOs;
extern const std::string_view kExceptionProvenance;

[[nodiscard]] std::optional<yuzu::shared::MountTable> os_read_mounts(const std::string& root);
[[nodiscard]] UnitLeg os_make_leg(const Unit& unit);
[[nodiscard]] bool os_draw_cursor_key(CursorKey& key) noexcept;
void os_in_worker_environment(const std::function<void()>& body);
[[nodiscard]] fsr::NameSemantics os_name_semantics();
[[nodiscard]] std::expected<std::string, RequestError> os_normalise_root(std::string_view raw);
[[nodiscard]] std::vector<std::string> os_user_roots(const Unit& unit);

} // namespace yuzu::file_search
