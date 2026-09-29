- **Fixed — `POST /api/v1/result-sets` now validates that every `device_ids` entry exists and is
  visible to the caller** (#4983). Previously this route accepted an arbitrary caller-supplied
  `device_ids` array with only a type check (`is_string()`) and an array-size cap — a nonexistent
  id, or a real id outside the caller's own management-group/service-scope confinement, was
  silently accepted as a member, so `device_count`/lineage on the created result set were
  unverified and a per-owner quota could be padded with junk entries that named no real device.
  A `device_ids` entry that does not exist, or that exists but is outside the caller's own scope,
  now rejects the WHOLE request with `400 RESULT_SET_UNKNOWN_DEVICE_ID` — never a silent drop and
  never a partial create — with the offending id(s) named in the error (the caller's own submitted
  list, so this is not a disclosure of someone else's device existence). The existence check is
  presence-merged (the same fleet-wide domain a real dispatch uses, not just this replica's local
  connections), so a device known only via cross-replica presence is never wrongly rejected as
  nonexistent. A request that omits `device_ids`, or supplies an empty array, is completely
  unaffected — no new gate, no new cost.
