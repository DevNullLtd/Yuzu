- **Compliance page re-rendered on the slate components, with policy fragments and tag
  compliance on the page.** The summary shows enabled-policy and failing-check readouts
  (failing = non-compliant plus error, the same definition as each row's status pill), a
  status pill per policy, and a note when the 100-policy list cap is reached. The per-policy
  detail gains an Applies to / Check / Remediation panel, escapes every status string, and
  reads the agent registry once per render instead of once per row. A new
  `GET /fragments/policy-fragments` lists policy fragments with how many policies use each.
  The tag-compliance table (Display Name and the Free-form marker kept) moved here from
  Settings, so the Tag Compliance panel on the Settings page is gone; the
  `GET /api/v1/tag-compliance` API is unchanged.
