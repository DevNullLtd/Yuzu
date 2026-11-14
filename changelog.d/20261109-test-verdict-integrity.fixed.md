- Make test verdicts reflect recorded execution: validate terminal results for
  every reached instruction agent, reject cancelled gateway runs consistently,
  keep gateway deadlines active after output closes, and refuse successful perf
  evidence when requested scale work or result persistence fails. Preserve local
  gate observations and external failure decisions in test-history schema v4,
  and prevent manual run IDs from reassigning old evidence to a new revision.
