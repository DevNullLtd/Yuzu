#pragma once

/// @file groups_ui.hpp
/// The Groups and enrolment page. `kGroupsTemplate` is the page before the shell is baked in
/// (exposed so tests can inspect the literal); `kGroupsHtml` is what `GET /groups` serves.
/// The panels fill themselves by htmx from the existing enrolment fragments.

extern const char* const kGroupsTemplate;
extern const char* const kGroupsHtml;
