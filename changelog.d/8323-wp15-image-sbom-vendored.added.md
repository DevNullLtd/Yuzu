- **The `yuzu-server` and `yuzu-server-chisel` image SBOMs list the third-party files
  compiled into the server.** The CycloneDX and SPDX SBOMs of the two images that
  hold `yuzu-server` carry the same web-asset and QR-code-library entries as the
  server's release-file SBOMs (htmx and its SSE extension, Apache ECharts with ZRender
  and tslib, three.js, Cytoscape.js, IBM Plex, Nayuki's QR Code generator), so a
  scanner reading an image SBOM sees them too. They come from
  `server/core/vendored-components.json`, checked against the source the image was
  built from, and are added to syft's scan of the pushed image with a
  `yuzu:sbom:vendored` note in both formats; every entry syft wrote is kept as it
  was. They are not a reason for the incomplete marker: the two server images are
  marked `image-static-cpp` only, for the C++ libraries linked statically into
  `yuzu-server` (its file SBOMs list those). The release fails instead of publishing a
  server image SBOM without exactly these entries, or another image's SBOM with them. The
  gateway, postgres and agent image SBOMs do not get them.
