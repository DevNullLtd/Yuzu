- **REST API reference: corrected four wrong permission gates on the Policies routes.**
  `DELETE /api/policy-fragments/{id}` and `DELETE /api/policies/{id}` require `Policy:Delete`, and
  `POST /api/policies/{id}/invalidate` and `POST /api/policies/invalidate-all` require
  `Policy:Execute` — all four were documented as `Policy:Write`. These are separately-granted
  operations, so the error was actionable: the default `Operator` role holds `Policy:Execute` but
  not `Policy:Write`, and an operator provisioned from the doc would have been denied on routes
  they are entitled to use (and over-granted `Policy:Write` for routes that never needed it). The
  two `invalidate` response examples also showed `"status": "invalidated"`; the handlers emit
  `"status": "ok"`.
