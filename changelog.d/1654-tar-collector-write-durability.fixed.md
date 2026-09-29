- **TAR snapshot-diff collectors commit events and baseline atomically** (#1654).
  Events and the baseline now land in one transaction, so a failed baseline save can
  no longer cause a double-emit on the next tick. The existing
  `error|<source> insert failed` line covers a rolled-back batch; a new
  `error|<source> state_save_failed` line covers a failed baseline-only save (the
  software cold-start seed reports `tar|collect_software|0|state_save_failed` on its
  own line). The
  per-source enable/disable transition is all-or-nothing.
