- **`device.filesystem.search_dir` is bounded and reports what it skipped (#6478).** The walk now stops
  after 20 seconds, 400,000 entries visited or `max_results` matches, ends on agent shutdown, refuses a
  root or `base_dir` on a network mount before touching it and skips a mount below the root. It no
  longer follows or matches a symlink or junction below the root, and a directory at `max_depth` is
  matched but not opened (the old walk listed it and discarded the children). Result paths are now
  escaped: a pipe character is escaped, CR and LF show as a space and a trailing backslash shows as a
  slash. When anything was skipped or the walk stopped early, a `truncated|...` row precedes
  `total_matches|N`; the result is `CONSTRAINED`/`PARTIAL` when a bound tripped, a directory could not
  be read, a network mount was refused or the mount table was unreadable, and stays `UNDECLARED` when
  the only skips are by design (a symlink, junction or FIFO). A pattern over 256 bytes is refused in
  glob mode too, an unknown `match_type` is an error, and in regex mode a pattern too costly for a
  file name ends the run with an error row (Linux runs regexes in linear time). A name byte that is not
  valid UTF-8 now shows as `?` in `search_dir`, `find_by_hash` and `get_acl` rows instead of making the
  whole response unreadable. Definition `device.filesystem.search_dir` is now 0.5.0 (columns
  `row_kind`, `path`, `entry_type`).
