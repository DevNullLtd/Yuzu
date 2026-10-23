// TAR timeline page shell (docs/tar-dashboard.md section 5.8). The page carries no CSS of its
// own (the .tl- rules live in yuzu.css) and no inline script: the htmx load pulls the run
// fragment, static/yuzu-tar-timeline.js does the rest.

#include "tar_timeline_page_ui.hpp"

#include "app_shell.hpp"
#include "web_utils.hpp"

#include <array>

namespace yuzu::server {

namespace {

// Two literals, each far under the MSVC C2026 16380-character cap; kept apart so the cap is a
// per-piece pin in the tests.
constexpr std::string_view kHead = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuzu — TAR timeline</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <meta name="htmx-config" content='{"allowEval":false,"historyEnabled":false}'>
  <script src="/static/htmx.js"></script>
  <script src="/static/yuzu-tar-timeline.js" defer></script>
</head>
<body>
<!--yuzu:shell--><!--/yuzu:shell-->
)HTM";

constexpr std::string_view kBody = R"HTM(<main class="page">
  <header class="page-header">
    <div>
      <h1>Timeline</h1>
      <p class="subtitle">Drag back in time to see what this device was doing, and what its record can still say as it ages.</p>
    </div>
    <div class="header-actions">
      <button class="btn" id="tl-copy" type="button">Copy link to this moment</button>
      <a class="btn" href="/hardware/ci?id={{ID}}">Open device</a>
    </div>
  </header>
  <p class="hint"><a href="/tar">Back to TAR</a> &middot; <a href="/tar#frame-process-tree">Choose another device</a></p>
  <section class="panel">
    <div class="tl-ctl">
      <div class="tl-clk"><b id="tl-clock">—</b><span>UTC</span></div>
      <div class="cg">
        <button class="btn play" id="tl-play" type="button" aria-pressed="false" disabled>Play</button>
        <button class="btn" id="tl-speed" type="button" aria-label="Playback speed" disabled>Speed 1x</button>
      </div>
      <span class="lbl">Drag the yellow line, click the timeline, or use the arrow, Home, End and Page keys. Times are UTC. Play moves the yellow line through the record already loaded; it does not show live data.</span>
      <span class="lbl" id="tl-play-note" role="status"></span>
    </div>
    <div id="tl-run" data-moment-url="/fragments/tar/timeline/moment?id={{ID}}" data-selected-url="/fragments/tar/timeline/selected?id={{ID}}" hx-get="/fragments/tar/timeline/run?id={{ID}}{{AT}}" hx-trigger="load" hx-swap="innerHTML">
      <p class="tl-empty">Reading this device's record…</p>
    </div>
  </section>
  <div class="split">
    <div class="grow">
      <section class="panel">
        <div class="hd"><h2>At this moment</h2></div>
        <div class="tl-det" id="tl-moment"></div>
      </section>
    </div>
    <div class="side2">
      <section class="panel">
        <div class="hd"><h2>Selected</h2></div>
        <div class="tl-det" id="tl-selected"><p class="tl-empty">Click a process, a count or a marker to see what its record keeps.</p></div>
      </section>
    </div>
  </div>
</main>
</body>
</html>
)HTM";

constexpr std::array<std::string_view, 2> kParts{kHead, kBody};

// The shell is rendered into the template once, on first use.
const std::string& baked_page() {
    static const std::string page = [] {
        std::string tmpl;
        for (const auto p : kParts)
            tmpl += p;
        return std::string{shell::bake(tmpl.c_str(), {.active_key = "tar", .title = "Timeline"})};
    }();
    return page;
}

void replace_all(std::string& s, std::string_view token, const std::string& with) {
    for (auto pos = s.find(token); pos != std::string::npos; pos = s.find(token, pos + with.size()))
        s.replace(pos, token.size(), with);
}

bool is_epoch_digits(std::string_view at) {
    if (at.empty() || at.size() > 19)
        return false;
    for (const char c : at)
        if (c < '0' || c > '9')
            return false;
    return true;
}

} // namespace

std::string render_tar_timeline_page(std::string_view agent_id, std::string_view at) {
    std::string html = baked_page();
    replace_all(html, "{{AT}}", is_epoch_digits(at) ? "&at=" + std::string{at} : std::string{});
    replace_all(html, "{{ID}}", html_escape(url_query_value(agent_id)));
    return html;
}

std::span<const std::string_view> tar_timeline_page_parts() { return kParts; }

} // namespace yuzu::server
