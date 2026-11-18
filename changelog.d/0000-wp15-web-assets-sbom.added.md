- **Server SBOMs list the third-party files compiled into `yuzu-server`.** Every
  release file holding the server (the Linux archive, the server `.deb` and `.rpm`)
  now lists, in its CycloneDX and SPDX SBOM, the web assets the dashboard serves and
  the QR-code library behind MFA enrolment: htmx 2.0.4 and its SSE extension, Apache
  ECharts 5.6.0 with the ZRender 5.6.1 and tslib code bundled in it, three.js r168
  (with OrbitControls), Cytoscape.js 3.33.3, IBM Plex Sans 1.1.0 and Mono 2.5.0, and
  Nayuki's QR Code generator 1.8.0, each with its licence, upstream, `pkg:npm` (or
  `pkg:github`) purl and the SHA-256 of the vendored file. A scanner cannot find them
  inside the binary, so they come from a new manifest,
  `server/core/vendored-components.json`; the release fails if it does not match the
  files it built from, and a CI check fails a change that adds or alters a vendored
  file without updating it. Two versions the vendored files do not state are left
  blank rather than guessed: the htmx SSE extension (byte-identical to both 2.2.2 and
  2.2.3) and tslib. With these listed, a server file's SBOM is not marked incomplete
  for them.
