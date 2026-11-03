- **Gateway: the per-agent owner keeps the agent's hostname, not its whole
  AgentInfo.** The owner process read only the hostname of the AgentInfo it
  kept for the life of the session (about 26 KB of live heap for an agent with
  69 plugins). It now keeps the hostname alone; `yuzu_gw_agent:get_info/1` no
  longer returns the AgentInfo (GetAgent never read it), and a hot code upgrade
  reduces an old owner's AgentInfo to its hostname. Measured at 3,000 agents
  with 69 plugins: live memory 122.4 to 99.5 KiB per agent.
