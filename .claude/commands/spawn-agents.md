# Spawn Claude-Flow Agents

Spawn specialized AI agents for coordinated development tasks.

## Usage
```
/spawn-agents [types] [count]
```

## Parameters
- `types` (optional): researcher,coder,analyst,tester,coordinator,architect (default: mixed)
- `count` (optional): number of agents to spawn (default: 3)

## Steps

1. Analyze current project needs
2. Spawn agents with appropriate specializations
3. Set up agent coordination protocols
4. Configure memory sharing between agents
5. Display active agent roster

## Agent Types
- **researcher**: Investigation and analysis
- **coder**: Implementation and development
- **analyst**: Performance and quality analysis
- **tester**: Testing and validation
- **coordinator**: Task orchestration
- **architect**: System design and planning

## Examples
```bash
# Spawn mixed team of 5 agents
npx claude-flow@alpha agent spawn --type researcher --name "Research Lead"
npx claude-flow@alpha agent spawn --type coder --name "Backend Dev"
npx claude-flow@alpha agent spawn --type coder --name "Frontend Dev"
npx claude-flow@alpha agent spawn --type tester --name "QA Engineer"
npx claude-flow@alpha agent spawn --type coordinator --name "Tech Lead"

# Check agent status
npx claude-flow@alpha agent list
```

Agents work together using shared memory and coordination protocols.