# Example policies

| File | Use |
|---|---|
| `basic-agent.yaml` | minimum bar, design controls, declarations accepted (builtin profile copy) |
| `enterprise-agent.yaml` | multi-user enterprise data; identity, memory, supply chain, egress flows; POTENTIAL HIGH blocks |
| `mcp-integrated-agent.yaml` | every MCP control mandatory |
| `high-risk-autonomous-agent.yaml` | declarations not accepted; behavioral (sandbox) controls mandatory; MEDIUM blocks |
| `enterprise-secure-agent.yaml` | enterprise profile + one accepted, expiring exception → READY_WITH_RISKS |
| `invalid-policy.yaml` | deliberately invalid, shows schema validation (`policy validate` → exit 78) |

The four profile files are byte-identical copies of the builtin profiles (a test enforces it).
Version policies in Git next to the agent; every report records the policy SHA-256.
