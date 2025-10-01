# Kong Guard AI - Quick Start Guide (Port 12345)

## **Dashboard is Running!**

The Kong Guard AI Unified Dashboard is now running on **port 12345** for quick development access.

---

## **Access URLs**

### **Primary Dashboard**
```
http://localhost:12345/
```
*Automatically redirects to the unified dashboard*

### **Unified Dashboard (Direct)**
```
http://localhost:12345/unified_dashboard.html
```
*Main tabbed interface with all dashboards*

### **Individual Dashboards**
- **Enterprise Demo**: `http://localhost:12345/enterprise_demo_dashboard.html`
- **Attack Simulation**: `http://localhost:12345/enterprise_attack_dashboard.html`
- **Kong Dashboard**: `http://localhost:12345/kong-dashboard.html`
- **Attack Reports**: `http://localhost:12345/attack_reports.html`
- **Protection Test**: `http://localhost:12345/protection-module-test.html`
- **AI Insights**: `http://localhost:12345/visualization/ai-insights.html`
- **Visualization**: `http://localhost:12345/visualization/simple-ai-dashboard.html`

---

## **New Features Available**

### ** AI Model Selection**
- **OpenAI** (GPT-4, GPT-3.5-turbo)
- **Claude** (Anthropic models)
- **Ollama** (Local models)
- **Local** (On-premise models)

### ** Protection Tier Selection**
- **Unprotected Kong** (Baseline testing)
- **Cloud AI Protection** (Cloud-based analysis)
- **Local AI Protection** (Local processing)

### ** Smart Features**
- **Multi-select**: Choose one, multiple, or all models/tiers
- **Validation**: Prevents errors with invalid configurations
- **Connectivity Testing**: Verify model availability
- **Real-time Status**: Visual feedback on selections

---

## **Quick Start Steps**

1. **Open Dashboard**
   ```
   http://localhost:12345/
   ```

2. **Configure Models & Tiers**
   - Select desired AI models (one or more)
   - Select protection tiers to attack (one or more)
   - Use "All" or "None" buttons for quick selection

3. **Test Connectivity** (Optional)
   - Click " Test Connectivity" to verify model availability

4. **Launch Attacks**
   - Navigate to Enterprise Demo or Attack Simulation tabs
   - Launch attacks with confidence - validation prevents errors

---

## **Server Management**

### **Check Server Status**
```bash
lsof -i :12345
```

### **Stop Server**
```bash
# Find the process
ps aux | grep serve_dashboard

# Kill the process
kill <PID>
```

### **Restart Server**
```bash
python3 serve_dashboard.py
```

---

## **Dashboard Features**

### **Unified Interface**
- **Single Header**: Consistent branding across all dashboards
- **Tabbed Navigation**: Easy switching between views
- **Global Configuration**: Settings apply to all dashboards
- **Responsive Design**: Works on desktop and mobile

### **Enhanced Multi-Select**
- **Error Prevention**: Validates before execution
- **Visual Feedback**: Color-coded status indicators
- **Quick Actions**: One-click select all/none
- **Smart Notifications**: Context-aware messages

---

## **Troubleshooting**

### **Dashboard Not Loading**
```bash
# Check if server is running
lsof -i :12345

# Restart if needed
python3 serve_dashboard.py
```

### **Port Already in Use**
```bash
# Find what's using the port
lsof -i :12345

# Kill the process
kill <PID>
```

### **Configuration Issues**
- Ensure at least one model is selected
- Ensure at least one tier is selected
- Use "Test Connectivity" to verify model availability

---

## **Mobile Access**

The dashboard is fully responsive and works on mobile devices:
```
http://localhost:12345/
```

---

## **Next Steps**

1. **Explore Dashboards**: Try different tabs to see all features
2. **Configure Models**: Select your preferred AI models
3. **Test Attacks**: Launch attack simulations with different configurations
4. **Monitor Results**: View real-time metrics and analytics

---

** Ready to go! Open http://localhost:12345/ to start using Kong Guard AI**

*Port 12345 - Development Quick Start*
