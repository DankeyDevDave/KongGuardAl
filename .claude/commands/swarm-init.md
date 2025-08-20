# Initialize Claude-Flow Swarm

Initialize a Claude-Flow swarm for coordinated AI development.

## Usage
```
/swarm-init [topology] [agents]
```

## Parameters
- `topology` (optional): mesh, hierarchical, ring, star (default: hierarchical)
- `agents` (optional): number of agents 1-12 (default: 5)

## Steps

1. Initialize Claude-Flow swarm with specified topology
2. Set up coordination framework
3. Spawn initial agents for the project
4. Store initialization context in memory
5. Display swarm status and capabilities

## Examples
```bash
# Initialize with default settings
npx claude-flow@alpha swarm init --topology hierarchical --max-agents 5

# Initialize mesh topology with 8 agents
npx claude-flow@alpha swarm init --topology mesh --max-agents 8

# Check swarm status
npx claude-flow@alpha swarm status
```

This command sets up the foundation for AI-coordinated development workflows.