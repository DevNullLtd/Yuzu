#pragma once

/// @file result_set_extras_render.hpp
/// Pure renderers for the Result sets extras (operate-extras slice 5): the
/// member list fragment (B-5) and the producer picker fragment (B-6). No I/O:
/// the route fetches rows and hands them in. Every user string goes through
/// html_escape.
///
/// State vocabulary (SPEC 5.3), carried as data attributes so a test and the
/// page controller can tell the states apart without parsing prose:
///   data-denied="true"    permission-free sentence, HTTP 200 (htmx drops 4xx bodies)
///   data-degraded="1"     store read failed; the text ends "This is not an empty ..."
///   data-truncated="1"    the list is cut at the route's bound

#include <string>
#include <vector>

namespace yuzu::server {

/// One producer the picker may offer: an enabled, ReadOnly, auto-approval definition.
struct ResultSetProducer {
    std::string id;
    std::string name;
    std::string plugin;
    std::string action;
};

/// One page of a set's member device ids, with a "Show more" control when a
/// cursor remains. `degraded` = the read failed (never rendered as empty).
std::string render_result_set_members(const std::string& set_id,
                                      const std::vector<std::string>& device_ids,
                                      const std::string& next_cursor, bool degraded);

/// The producer picker for From instruction: `<option>` rows the controller
/// reads, plus the approval-rules note. `truncated` = the definition read hit
/// its limit and the list is partial.
std::string render_result_set_producers(const std::vector<ResultSetProducer>& producers,
                                        bool truncated);
std::string render_result_set_producers_denied();
std::string render_result_set_producers_degraded();

} // namespace yuzu::server
