- **The dashboard tag setter now refuses a value outside a closed category.** `POST /api/tags/set`
  (used by the Hardware record's Tags lens and the bulk tag bar) stored `environment=foo` verbatim,
  while `PUT /api/v1/tags` and the MCP `set_tag` tool already answered 400 with the allowed values
  (Dev, UAT, Production). The dashboard route now goes through the same checked setter, so all three
  surfaces agree. Values already stored out of set, for example by an agent sync, still display and
  can still be removed.
