- **The reference gateway compose template's agent now loads its plugins.**
  `deploy/docker/docker-compose.reference-gateway.yml`'s `agent` service sets
  its own `command:`, which replaces the image's default and dropped
  `--plugin-dir /usr/lib/yuzu/plugins`. The agent then fell back to
  `<binary dir>/../plugins` (`/usr/local/plugins` in that image), loaded no
  plugins, and rejected every command with `plugin not found: <name>`.
  The template now passes `--plugin-dir=/usr/lib/yuzu/plugins`. If you copied
  this template, add the same line to your agent service (#5134).
