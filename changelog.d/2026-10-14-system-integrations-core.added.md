- **Settings gains an Integrations page.** `/settings/integrations` hosts the MCP and Gateway
  panels (same fragment URLs and ids as on `/settings`, where both also stay). The MCP panel is one
  form with a Save and a confirmation that names the state being saved; refused requests show the
  server's message instead of failing silently. The page is admin-only and additive, and adds no
  REST route or MCP tool. The Gateway panel's "Active Sessions" row is now "Agents via gateway".
