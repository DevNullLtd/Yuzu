# Resource Ledger: SAM-51 software title and vendor normaliser fixes

New or modified owned resources introduced in `server/core/src/product_normalize.cpp`,
`product_normalize.hpp`, `product_registry_store.cpp` and `software_normalization_pack.cpp`.

## Resources

None. The change adds no fd, HANDLE, SOCKET, `FILE*`, `sqlite3*` or `sqlite3_stmt*`, OpenSSL or
BCrypt object, allocated C string, mapped library, temp path, subprocess, callback context or
thread. The normalisers are pure functions over `std::string_view` and return `std::string`
values, so every allocation is owned by a standard container and released by its destructor. The
tests read one committed fixture file once, through a `std::ifstream` that closes at scope exit.

## Borrowed-data and lifetime check (the one place a view is rebound)

### `token` and `t` in `normalize_title`
- **Site:** the `name@version` branch, `product_normalize.cpp` (`token = std::string{t.substr(0, at)};
  t = trim_wrapping(token);`).
- **Owner:** the `std::vector<std::string>` returned by `split_tokens(ascii_lower(raw))`, bound by
  the range-for, which extends its lifetime to the end of the loop. `token` is an element of it.
- **Borrow:** `t` is a `std::string_view` into `token`. `take_version(t.substr(at + 1))` copies the
  version into `out.version` before `token` is reassigned. The replacement `std::string` is built
  completely from the old view before it is assigned, and `t` is rebound to the new contents
  straight after, so no view outlives the buffer it points into.
- **Failure cleanup:** none needed. A `std::bad_alloc` unwinds through the vector's destructor.
- **Transfer:** `kept.push_back(std::move(token))` moves the element out; `token` is not read
  again in that iteration.

### `tokens` in `normalize_vendor`
- **Site:** the trailing-run strip, `while (tokens.size() > 1 && is_legal_suffix_token(tokens.back()))
  tokens.pop_back();`.
- **Owner:** the local `std::vector<std::string> tokens`. `is_legal_suffix_token` takes a view for
  the duration of the call only; `pop_back` runs after the call returns, so the view is never used
  after the element is destroyed.

### `normalize_edition`
- **Site:** new function in `product_normalize.cpp`. The only owned value is the returned
  `std::string`; `t` is a view into the loop's `const std::string& token`, valid for the iteration.

## Not covered / limitation

Pure-function code on the server; no platform-specific call, so no per-OS leg differs. The server
suite and the `[pg]` shards run on a Linux lane, not on the authoring Mac.
