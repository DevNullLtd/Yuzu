- **RBAC documentation counts corrected against the seeded store.** Every count in
  `docs/user-manual/rbac.md` had drifted as securables and roles were added: the authorization
  topology floor lists ten reads, not five (the four Settings read-twins from #4028 and
  `Forensics:Read` from Wave 7 PR7.2 were missing, so the doc understated which reads stay
  admin-gated with RBAC off); seven system roles are seeded, not six (`Reviewer` was absent from
  the count, the role table and the List Roles example); Administrator holds 193 permissions
  across 38 securable types, not 118 across 23; ITServiceOwner holds 93, not 92 (`Workflow:Read`
  from #4030 was uncounted); and Viewer reads 24 securable types, not 21 — and its grant is an
  explicit allow-list, not "everything except Infrastructure and AccessReview". The Securable
  Types table gained the 15 rows it was missing and now matches `rbac_store.cpp`'s seeded set
  exactly.
