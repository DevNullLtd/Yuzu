#pragma once

/// @file home_ui.hpp
/// The Home page (`GET /home`). `kHomeHtml` is the baked page (shell included, no
/// nav item active: Home is reached from the Yuzu logo, not a nav entry). The
/// CSS and the body template are exposed so the page pins can size-check each
/// literal against the MSVC string-literal cap without parsing the baked page.

/// Scoped `home-` rules for what yuzu.css does not carry (grid, donut, stacked bar,
/// attention rows). Colours are tokens only, never hex literals.
extern const char* const kHomeCss;
/// Page body template (shell marker pair still unbaked).
extern const char* const kHomeTemplate;
/// Baked page served at `/home`.
extern const char* const kHomeHtml;
