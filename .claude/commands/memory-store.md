# Store Memory Context

Store important context and decisions in Claude-Flow persistent memory.

## Usage
```
/memory-store [key] [value] [namespace]
```

## Parameters
- `key`: Memory key identifier
- `value`: Content to store
- `namespace` (optional): Memory namespace (default: project)

## Steps

1. Validate memory key and content
2. Store content in persistent memory
3. Set appropriate TTL if needed
4. Index content for searchability
5. Confirm storage success

## Examples
```bash
# Store project decision
npx claude-flow@alpha memory store "architecture-choice" \
  "Selected microservices with Kong Gateway for scalability" \
  --namespace decisions

# Store implementation notes
npx claude-flow@alpha memory store "auth-implementation" \
  "Using JWT with bcrypt hashing, 24hr expiry, refresh tokens" \
  --namespace implementation

# Store performance metrics
npx claude-flow@alpha memory store "baseline-metrics" \
  "API latency: 45ms avg, Throughput: 1000 req/s" \
  --namespace metrics

# Retrieve memory
npx claude-flow@alpha memory retrieve "architecture-choice" \
  --namespace decisions

# Search memory
npx claude-flow@alpha memory search "authentication" \
  --namespace implementation
```

## Namespaces
- **decisions**: Architectural and design decisions
- **implementation**: Code implementation details
- **metrics**: Performance and quality metrics
- **issues**: Problems and solutions
- **research**: Investigation findings

Memory enables knowledge persistence across sessions and agents.