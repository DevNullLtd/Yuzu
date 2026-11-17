- **`NOTICE` now lists every shipped third-party component.** Brotli, zlib, c-ares, RE2,
  utf8_range, {fmt}, libxml2, xmlsec and the vendored Cytoscape.js 3.33.3 were linked or
  served but missing from the attribution list, and jsoncpp and libuuid (linked only into the
  Drogon build canary, like the Drogon and trantor entries already there) are now recorded too.
  Each licence was taken from the vcpkg port's `copyright` file. xmlsec is recorded as X11
  (MIT with a no-advertising clause): the port declares MPL-1.1 AND X11 because upstream's
  xmlsec-nss backend contains MPL-1.1-derived code, and vcpkg builds only the core and
  OpenSSL libraries. Cytoscape.js gains `server/core/static/cytoscape-NOTICE.txt` (licence,
  source, SHA-256), as ECharts and three.js have, and a byte-count pin in the static bundle
  tests. The stray `SPDX-License-Identifier: Apache-2.0` line in
  `server/core/src/oidc_writer_gate.hpp`, which contradicted the AGPL-3.0-or-later licence,
  is removed.
