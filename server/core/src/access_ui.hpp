#pragma once

/// @file access_ui.hpp
/// The Access pages' HTML. `kAccessUsersTemplate` is the page before the shell is baked in
/// (exposed so tests can inspect the literal); `kAccessUsersHtml` is what `GET /access/users`
/// serves. The two panels fill themselves by htmx (`/fragments/access/users/*`).

extern const char* const kAccessUsersTemplate;
extern const char* const kAccessUsersHtml;
