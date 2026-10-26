- **Closed 2 open npm advisories across two lockfiles.** Bumped `sharp` to
  0.35.5 in `site/package-lock.json`, resolving a `librsvg` dependency
  vulnerability (CVE-2026-96889); bumped `express` to 5.3.0 in
  `deploy/docker/cedar-vale/app` (`package.json` and `package-lock.json`),
  which pulls in `proxy-addr` 2.0.8 and closes its IPv4-mapped-IPv6
  trust-subnet spoofing gap. Neither package is reachable from the server,
  agent or gateway build.
