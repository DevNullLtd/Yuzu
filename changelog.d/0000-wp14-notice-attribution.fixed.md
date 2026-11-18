- **The repository `NOTICE` attributes more of the third-party code Yuzu ships.** Brotli, zlib,
  c-ares, RE2, utf8_range, {fmt}, libxml2, xmlsec, the vendored Cytoscape.js 3.33.3, and the
  zrender and tslib code bundled inside ECharts were linked or served but missing from the
  attribution list. jsoncpp and libuuid are recorded too: they are linked only into the Drogon
  build canary, like the Drogon and trantor entries already there. Each licence was taken from the
  vcpkg port's `copyright` file. xmlsec is recorded as X11 (MIT with a no-advertising clause). The
  port declares MPL-1.1 AND X11 because upstream's xmlsec-nss backend contains MPL-1.1-derived
  code, and vcpkg builds only the core and OpenSSL libraries. Cytoscape.js gains
  `server/core/static/cytoscape-NOTICE.txt` (licence, source, SHA-256), as ECharts and three.js
  have, and a byte-count pin in the static bundle tests. These attributions live in the source
  repository: `NOTICE` and the `*-NOTICE.txt` files are not yet packaged with release archives,
  packages or images. The stray `SPDX-License-Identifier: Apache-2.0` line in
  `server/core/src/oidc_writer_gate.hpp`, which contradicted the AGPL-3.0-or-later licence, is
  removed.
