- **Digital Employee Experience: the Apps tab now shows fleet application usage.** A new **Usage** view,
  beside **Stability** in a **View** row, lists each application with the devices that ran it, its run time
  and launches over the last 30 days, and its crashes and hangs per hour of use, marked *estimated from
  30-day usage*. It shows the same figures as `GET /api/v1/dex/apps/usage`, can be split by platform, by
  management group or by a device tag, and reads every withheld, below-floor, ambiguous or failed state in
  words, with the reporting population beside every device count. It needs `Forensics:Read` as well as
  `GuaranteedState:Read`; without `Forensics:Read` the **Usage** chip shows the Stability page and one line
  saying why. Each Usage view is audited as `dex.apps.usage.view` before it is read, and if that record
  cannot be stored nothing is read.
