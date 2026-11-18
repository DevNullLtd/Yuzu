- **Breaking - `device.filesystem.search_dir` is bounded, refuses a regex lookahead and reports what it
  skipped (#6478).** Affected: a regex that uses a lookahead (`(?=...)` or `(?!...)`) now ends with
  `error|regex lookahead is not supported (use (?: to group)`; a root or `base_dir` on a network mount,
  a UNC share, a Windows drive that is not a fixed disk or a `\\?\`-prefixed path is refused; a symlink
  is no longer reported as a match; and a raw dispatch with an unknown `match_type` or a glob over 256
  bytes is an error. To do: rewrite such a regex without the lookahead (or filter the rows afterwards),
  search local fixed disks by their plain drive spelling, and read the new `truncated|...` row. The
  walk now stops after 20 seconds (checked between entries: a single blocked read or directory listing
  is not interrupted), 400,000 entries visited or `max_results` matches, ends on agent shutdown, and
  refuses a root or `base_dir` on a network mount before touching it (return code 0 with
  `skipped_network_mount=1`, `total_matches|0` and `CONSTRAINED`, not an error); on macOS and Linux it
  also skips a mount below the root, and on Linux it never enters a pseudo-filesystem such as `/proc`
  or `/sys` (an unreadable directory). A symlink or junction below the root no longer matches (the old
  walk reported a link by its target's type) and is never followed, and a directory at `max_depth` is
  matched but not opened (the old walk listed it and discarded the children). Result paths are now
  escaped: a pipe character is escaped, CR and LF show as a space and a trailing backslash shows as a
  slash. On Windows, names are now compared and reported as UTF-8, as on macOS and Linux (the earlier
  walk converted them through the system ANSI code page), so a glob `?` or `[...]` matches one byte of
  a non-ASCII name, not the whole character. When anything was skipped or the walk stopped early, a
  `truncated|...` row precedes `total_matches|N`; the result is `CONSTRAINED`/`PARTIAL` when a bound
  tripped, a directory could not be read, a network mount was refused or the mount table was
  unreadable, and stays `UNDECLARED` when the only skips are by design (a symlink, junction or FIFO). A
  result set built with a column matcher on a declared column does not read a partly searched
  device as a clean non-match: a device whose `CONSTRAINED` answer holds no matching row is
  counted in the set's `agents_failed`, so the set reads `partial` (the server reads the new result key
  `partialWhenConstrained`, set by definition 0.5.0; `find_by_hash` sets are unchanged). In regex
  mode a pattern too costly for a file name ends the run with an error row and no count (with no
  lookahead, a match on Linux takes time linear in the name's length). A name byte that is not valid
  UTF-8 now shows as `?` in `search_dir`, `find_by_hash` and `get_acl` rows instead of making the whole
  response unreadable. Definition `device.filesystem.search_dir` is now 0.5.0 (columns `row_kind`,
  `path`, `entry_type`); an existing server keeps 0.4.0 until the definition is replaced (see the
  upgrade note).
- **Breaking - a result-set `matcher` over 64 KiB is refused (#6478).** Affected: a caller of
  `POST /api/v1/result-sets/from-instruction-result` or the MCP tool
  `create_result_set_from_instruction_result` that sends a `matcher` over 65,536 bytes of compact
  JSON (about 970 SHA-256 values in a `value_set`). It was accepted before and is now refused with
  `400` / `-32602` and `matcher exceeds 65536 bytes as compact JSON`, before anything is
  dispatched. To do: divide a longer value list over more than one result set. The limit bounds
  the cost of evaluating a large matcher.
- **Breaking - REST refuses a result-set `matcher` field over its bound (#6478).** Affected: a
  caller of `POST /api/v1/result-sets/from-instruction-result` that sends a `matcher` whose
  `column` is over 128 bytes, whose `op` is over 32 or whose `value` is over 512. It was accepted
  before and is now refused with `400` and
  `a matcher field exceeds its bound (column<=128, op<=32, value<=512 bytes)`,
  before anything is dispatched or stored. These are the bounds the MCP tool
  `create_result_set_from_instruction_result` already applied; they bound the size of a matcher
  field a caller supplies. To do: send a shorter field; an exact match on a longer value can be
  written as `"op":"in"` with that value in `value_set`, whose entries have no bound of their own.
