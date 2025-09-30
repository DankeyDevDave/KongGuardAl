# Claude-Flow Slash Commands for Claude Code

## 🚀 Quick Reference Guide

### Core Swarm Operations
```bash
/swarm-init [topology] [agents]     # Initialize coordination swarm
/spawn-agents [types] [count]       # Create specialized AI agents  
/swarm-status [detailed]            # Check swarm health and metrics
/orchestrate [task description]     # Coordinate complex development tasks
```

### Neural Intelligence
```bash
/neural-train [pattern] [data]      # Train coordination patterns
```

### Memory Management
```bash
/memory-store [key] [value] [ns]    # Store persistent context and decisions
```

### Performance & Security
```bash
/performance-report [time] [format] # Generate analytics and optimization
/kong-security [operation]          # Manage Kong Guard AI security
```

### Help & Documentation
```bash
/claude-flow-help [category]        # Show available commands and usage
```

## 📋 Common Workflows

### 1. **Initialize Development Swarm**
```bash
/swarm-init hierarchical 5
/spawn-agents researcher,coder,tester 3
/swarm-status
```

### 2. **Coordinate Feature Development**
```bash
/orchestrate "Implement user authentication with JWT and bcrypt"
/memory-store "auth-decision" "Using JWT with 24hr expiry" decisions
/neural-train coordination
```

### 3. **Security Operations**
```bash
/kong-security status
/kong-security threats
/spawn-agents security 2
```

### 4. **Performance Analysis**
```bash
/performance-report 24h detailed
/neural-train optimization "performance-data.json"
```

### 5. **Project Memory**
```bash
/memory-store "architecture" "Microservices with Kong Gateway" decisions
/memory-store "performance" "API latency <10ms validated" metrics
/memory-store "security" "All threats blocked successfully" incidents
```

## 🎯 Integration Features

### **Claude Code Native**
- Slash commands work directly in Claude Code
- No additional setup required
- Full tool allowlist configured

### **Kong Guard AI Integration**
- Security operations coordination
- Threat response automation
- Performance monitoring

### **Task Master Sync**
- Project task coordination
- Progress tracking integration
- Development workflow optimization

### **GitHub Actions**
- Automated deployment workflows
- CI/CD coordination with agents
- Performance validation

## 🔧 Configuration

Commands are automatically available in Claude Code with:
- **Settings**: `.claude/settings.json` configured
- **Commands**: `.claude/commands/` directory populated
- **Tool Allowlist**: Claude-Flow MCP tools enabled
- **Integration**: Kong Guard AI + Task Master coordination

## 📊 Example Usage Session

```bash
# 1. Start development session
/swarm-init mesh 6
/spawn-agents researcher,coder,analyst,tester 4

# 2. Coordinate API development  
/orchestrate "Build REST API with authentication and rate limiting"

# 3. Monitor progress
/swarm-status detailed
/performance-report 1h summary

# 4. Store decisions
/memory-store "api-design" "RESTful with OpenAPI spec" architecture
/memory-store "rate-limiting" "100 req/min per user" policies

# 5. Security validation
/kong-security metrics
/neural-train prediction "threat-patterns.json"

# 6. Final status
/swarm-status
/performance-report 24h json > session-metrics.json
```

## 🚨 Emergency Operations

```bash
# Security incident response
/kong-security incidents
/spawn-agents security,analyst 3
/memory-store "incident-$(date)" "Details..." security-incidents

# Performance issues
/performance-report 1h detailed
/neural-train optimization
/spawn-agents optimizer 2
```

---

**🌊 Powered by Claude-Flow v2.0.0 Alpha**

All commands integrate seamlessly with Kong Guard AI security operations and Task Master project management.