- **Fresh-install RBAC bootstrap.** A brand-new Postgres database's first boot now atomically
  grants the config-file admin a durable, fleet-wide Administrator role alongside seeding the
  account itself (`RbacStore::provision_first_admin`), closing a gap where RBAC's own
  enable/assignment routes had no way to authorize themselves on a database that had never run
  before. A config file with no admin-role entry now fails the boot loudly instead of silently
  promoting the wrong account to Administrator.
