# Train Neural Patterns

Train Claude-Flow neural models for improved coordination and predictions.

## Usage
```
/neural-train [pattern] [data]
```

## Parameters
- `pattern` (optional): coordination, optimization, prediction (default: coordination)
- `data` (optional): training data source (default: recent project history)

## Steps

1. Analyze current neural model performance
2. Prepare training data from project context
3. Train neural patterns with specified focus
4. Validate model improvements
5. Update coordination algorithms
6. Store trained models for future use

## Pattern Types
- **coordination**: Improve agent coordination efficiency
- **optimization**: Enhance performance optimization
- **prediction**: Better task complexity prediction

## Examples
```bash
# Train coordination patterns
npx claude-flow@alpha neural train --pattern coordination --epochs 25

# Train with custom data
npx claude-flow@alpha neural train --pattern prediction \
  --training-data "project-metrics.json" --epochs 50

# Check neural status
npx claude-flow@alpha neural status

# Get neural predictions
npx claude-flow@alpha neural predict --model "coordination" \
  --input "complex refactoring task"
```

Neural training improves swarm intelligence over time.