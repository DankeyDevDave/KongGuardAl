# Check Swarm Status

Monitor Claude-Flow swarm health, agent activity, and performance metrics.

## Usage
```
/swarm-status [detailed]
```

## Parameters
- `detailed` (optional): include detailed agent metrics (default: summary)

## Steps

1. Check swarm initialization status
2. List active agents and their roles
3. Monitor task execution progress
4. Display performance metrics
5. Show memory usage and health
6. Report any issues or bottlenecks

## Examples
```bash
# Quick status check
npx claude-flow@alpha swarm status

# Detailed status with metrics
npx claude-flow@alpha swarm status --verbose

# Monitor in real-time
npx claude-flow@alpha swarm monitor --interval 5

# Check agent performance
npx claude-flow@alpha agent metrics

# View task progress
npx claude-flow@alpha task status
```

## Status Information
- **Swarm Health**: Active/Idle/Error states
- **Agent Count**: Total/Active/Busy/Idle
- **Task Queue**: Pending/Running/Completed
- **Memory Usage**: Storage/Cache utilization
- **Performance**: Coordination efficiency
- **Neural Models**: Training status and accuracy

## Health Indicators
- 🟢 **Healthy**: All systems operational
- 🟡 **Warning**: Performance degradation detected
- 🔴 **Critical**: Coordination failures or errors
- 🔧 **Maintenance**: Retraining or optimization needed

This provides comprehensive visibility into swarm operations.