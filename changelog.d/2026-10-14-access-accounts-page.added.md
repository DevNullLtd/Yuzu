- **Access section with a read-only Users page.** The sidebar gains an **Access** group whose
  **Users** entry (`/access/users`) lists the server's accounts (name, source, account role)
  beside a panel for the selected account. It re-surfaces what Settings shows today without
  adding any action: adding, removing and changing accounts stays in Settings. An account
  store that does not answer is shown as a red "could not be read" message with Retry, never
  as an empty list. Opening the page as a non-administrator writes no audit row; the panels
  are refused quietly. A refused API or MCP token is still recorded as an administrator-required denial.
