# Orchestrate Development Task

Coordinate a complex development task across multiple AI agents.

## Usage
```
/orchestrate [task description]
```

## Parameters
- `task description`: Detailed description of what needs to be accomplished

## Steps

1. Analyze task complexity and requirements
2. Break down task into coordinated subtasks
3. Assign subtasks to appropriate agents
4. Set up parallel execution strategy
5. Monitor progress and coordinate handoffs
6. Synthesize results from all agents

## Examples
```bash
# Orchestrate feature development
npx claude-flow@alpha task orchestrate \
  --task "Implement user authentication with JWT, bcrypt, and session management" \
  --strategy parallel

# Orchestrate system analysis
npx claude-flow@alpha task orchestrate \
  --task "Analyze codebase performance bottlenecks and recommend optimizations" \
  --strategy adaptive

# Check orchestration status
npx claude-flow@alpha task status
```

## Task Strategies
- **parallel**: Execute subtasks simultaneously
- **sequential**: Execute subtasks in order
- **adaptive**: Dynamically adjust based on dependencies

This enables complex multi-agent coordination for large development tasks.