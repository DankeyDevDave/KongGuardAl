# Generate Performance Report

Create comprehensive performance analysis of Claude-Flow operations.

## Usage
```
/performance-report [timeframe] [format]
```

## Parameters
- `timeframe` (optional): 24h, 7d, 30d (default: 24h)
- `format` (optional): summary, detailed, json (default: summary)

## Steps

1. Collect performance metrics from specified timeframe
2. Analyze coordination efficiency trends
3. Identify bottlenecks and optimization opportunities
4. Generate neural model performance summary
5. Create actionable recommendations
6. Export report in requested format

## Examples
```bash
# Daily performance summary
npx claude-flow@alpha performance report --timeframe 24h

# Weekly detailed analysis
npx claude-flow@alpha performance report --timeframe 7d --format detailed

# Export metrics as JSON
npx claude-flow@alpha performance report --format json > metrics.json

# Analyze bottlenecks
npx claude-flow@alpha bottleneck analyze --auto-optimize

# Token usage analysis
npx claude-flow@alpha token usage --timeframe 24h
```

## Report Sections
- **Coordination Efficiency**: Agent collaboration metrics
- **Task Completion**: Success rates and timing
- **Neural Performance**: Model accuracy and training
- **Resource Usage**: Memory, compute, and token consumption
- **Bottleneck Analysis**: Performance constraints
- **Optimization Recommendations**: Actionable improvements

## Key Metrics
- **Tasks/Hour**: Throughput measurement
- **Coordination Latency**: Agent handoff timing
- **Success Rate**: Task completion percentage
- **Neural Accuracy**: Model prediction quality
- **Token Efficiency**: Cost optimization metrics

Performance reports help optimize swarm operations over time.