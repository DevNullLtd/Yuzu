- **Stored data removal on the Hardware record.** The Overview tab of a device record has a
  Stored data panel, shown on click, that erases the device's stored rows through the existing
  audited `DELETE /api/v1/sle/agents/{agent_id}` route after you type the hostname and confirm.
  It says what is and is not removed, lists per-store outcomes when a removal is incomplete, and
  needs the `Decommission:Delete` permission for the device.
