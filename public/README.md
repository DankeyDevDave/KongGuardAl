# Kong Guard AI Public Assets

This directory contains all static web assets for Kong Guard AI dashboards and visualizations.

## 📁 Directory Structure

### 📊 Dashboards (`dashboards/`)
HTML dashboard files for monitoring and demonstrations:
- `unified_dashboard.html` - Main unified dashboard
- `enterprise_demo_dashboard.html` - Enterprise demo dashboard
- `enterprise_attack_dashboard.html` - Attack visualization dashboard
- `enterprise_attack_dashboard_with_protection.html` - Protected attack dashboard
- `kong-dashboard.html` - Kong Gateway dashboard
- `protection-module-test.html` - Protection module testing interface
- `test-ai-direct.html` - Direct AI testing interface
- `test-dashboard.html` - General testing dashboard
- `attack_reports.html` - Attack reports viewer

### 🎨 Assets (`assets/`)
Static assets used by dashboards:

**CSS (`assets/css/`):**
- `kongguard.css` - Main Kong Guard AI styles

**JavaScript (`assets/js/`):**
- `realtime_dashboard.js` - Real-time dashboard functionality

**Images (`assets/images/`):**
- `kong-guard-logo.png` - Kong Guard AI logo

### 🎨 Design Files (`design/`)
Source design files:
- `attack-dashboard.afdesign` - Affinity Designer source file

## 🚀 Usage

### Serving Dashboards

**Using Python HTTP server:**
```bash
cd public/dashboards
python3 -m http.server 8080
# Access at http://localhost:8080
```

**Using the provided server script:**
```bash
python serve_dashboard.py
# Access at configured port
```

**With Nginx:**
Configure nginx to serve from `public/` directory:
```nginx
server {
    listen 8080;
    server_name localhost;
    
    location / {
        root /path/to/KongGuardAI/public/dashboards;
        index unified_dashboard.html;
    }
    
    location /assets {
        alias /path/to/KongGuardAI/public/assets;
    }
}
```

### Accessing Dashboards

**Main unified dashboard:**
```
http://localhost:8080/unified_dashboard.html
```

**Enterprise demo:**
```
http://localhost:8080/enterprise_demo_dashboard.html
```

**Attack visualization:**
```
http://localhost:8080/enterprise_attack_dashboard.html
```

## 🔧 Dashboard Features

### Unified Dashboard
- Real-time threat monitoring
- Attack analytics
- Protection status
- System health metrics

### Enterprise Demo Dashboard
- Live attack simulations
- Protection demonstrations
- Performance metrics
- Interactive controls

### Attack Visualization
- Real-time attack flow visualization
- Threat categorization
- Geographic mapping
- Timeline analysis

## 🎨 Customization

### Modifying Styles
Edit `assets/css/kongguard.css` to customize appearance:
```css
/* Example: Change primary color */
:root {
    --primary-color: #your-color;
}
```

### Extending JavaScript
Modify `assets/js/realtime_dashboard.js` for custom functionality:
```javascript
// Add custom event handlers
// Extend chart configurations
// Add new data sources
```

## 📝 Development

### Testing Changes
1. Make changes to HTML/CSS/JS files
2. Refresh browser to see updates
3. Check browser console for errors
4. Test with live data connections

### Adding New Dashboards
1. Create new HTML file in `dashboards/`
2. Link to shared CSS: `../assets/css/kongguard.css`
3. Link to shared JS: `../assets/js/realtime_dashboard.js`
4. Update this README with description

## 🔗 Related Documentation

- [Demo Guide](../docs/user/comprehensive-demo-guide.md)
- [Presentation Guide](../docs/demo/presentation-guide.md)
- [Visualization Recommendations](../docs/visualization-recommendation.md)

---

**Note:** Dashboards connect to live Kong Guard AI services. Ensure services are running for full functionality.
