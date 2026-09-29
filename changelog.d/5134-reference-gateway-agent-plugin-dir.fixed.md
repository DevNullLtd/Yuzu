- **The reference gateway compose template's agent now loads its plugins.**
  `deploy/docker/docker-compose.reference-gateway.yml`'s `agent` service sets
  its own `command:`, which replaces the image's default and dropped
  `--plugin-dir /usr/lib/yuzu/plugins`. The agent then looked for plugins beside
  its binary, loaded none, and answered every command with "No plugin found".
  The template now passes `--plugin-dir=/usr/lib/yuzu/plugins`. If you copied
  this template, add the same line to your agent service (#5134).
