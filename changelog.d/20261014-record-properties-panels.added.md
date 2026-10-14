- **The device record's Tags lens is now "Tags and properties" and lists custom properties and
  property schemas.** A new fragment, `GET /fragments/hardware/ci/properties?id=`, renders the
  device's `props.<key>` values and the fleet-wide schemas read from the existing dashboard routes.
  A denied read names the missing permission and a degraded store says so instead of showing an
  empty list. Remove on a tag is now offered only to a caller holding `Tag:Delete` (previously any
  `Tag:Write` holder saw a control that could only be refused).
