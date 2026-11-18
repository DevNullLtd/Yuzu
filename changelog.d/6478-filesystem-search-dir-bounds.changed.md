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
  or `/sys` (counted as unreadable). A symlink or junction below the root no longer matches (the old
  walk reported a link by its target's type) and is never followed, and a directory at `max_depth` is
  matched but not opened (the old walk listed it and discarded the children). Result paths are now
  escaped: a pipe character is escaped, CR and LF show as a space and a trailing backslash shows as a
  slash. On Windows, names are now compared and reported as UTF-8, as on macOS and Linux (the earlier
  walk converted them through the system ANSI code page), so a glob `?` or `[...]` matches one byte of
  a non-ASCII name, not the whole character. When anything was skipped or the walk stopped early, a
  `truncated|...` row precedes `total_matches|N`; the result is `CONSTRAINED`/`PARTIAL` when a bound
  tripped, a directory could not be read, a network mount was refused or the mount table was
  unreadable, and stays `UNDECLARED` when the only skips are by design (a symlink, junction or FIFO). A
  result-set column matcher cannot tell a partly searched device from a fully searched one: a device
  whose partial search found nothing is left out of the set, which is not marked partial. In regex
  mode a pattern too costly for a file name ends the run with an error row and no count (with no
  lookahead, a match on Linux takes time linear in the name's length). A name byte that is not valid
  UTF-8 now shows as `?` in `search_dir`, `find_by_hash` and `get_acl` rows instead of making the whole
  response unreadable. Definition `device.filesystem.search_dir` is now 0.5.0 (columns `row_kind`,
  `path`, `entry_type`).
