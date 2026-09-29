- **Breaking — a config that lists local users but none holding the admin role now fails to
  boot.** Every boot (not only first boot) checks the loaded config's local user list; previously
  this shape silently promoted the first configured user to Administrator regardless of its
  declared role. Fix before upgrading if your config was hand-edited to this shape (e.g. after
  migrating to SSO): mark one entry `role=admin`, or remove all local entries for an SSO-only
  fleet. See "Upgrade Notes" in `docs/user-manual/server-admin.md`.
