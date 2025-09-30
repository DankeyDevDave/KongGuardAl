# ⚠️ DEPRECATED DASHBOARDS

**Date**: 2024-09-30  
**Status**: Archived - Do Not Use  
**Replacement**: `/dashboard/` (Unified Dashboard)

---

## 📢 Important Notice

These dashboards have been **deprecated** and consolidated into a single unified dashboard.

**New Unified Dashboard**: `/dashboard/`  
**Technology**: Next.js 15 + React 19 + shadcn/ui + TypeScript

---

## 🗂️ Archived Dashboards

### Primary Dashboards (Replaced)

**1. visualization/index.html** (407 lines)
- **Type**: React + Chart.js + TailwindCSS
- **Purpose**: Main real-time dashboard
- **Status**: ❌ Deprecated
- **Replaced By**: `/dashboard/` with Demo mode

**2. public-dashboards/kong-dashboard.html** (641 lines)
- **Type**: Vanilla JS + Custom animations
- **Purpose**: Testing and attack simulation
- **Status**: ❌ Deprecated
- **Replaced By**: `/dashboard/` with Control mode

**3. visualization/fixed-dashboard.html**
- **Type**: Static HTML/CSS/JS
- **Purpose**: Stable demo fallback
- **Status**: ❌ Deprecated
- **Replaced By**: `/dashboard/` in Demo mode

### Secondary Dashboards (Replaced)

**Enterprise Dashboards**:
- `public-dashboards/enterprise_demo_dashboard.html`
- `public-dashboards/enterprise_attack_dashboard.html`
- `public-dashboards/enterprise_attack_dashboard_with_protection.html`
- `public-dashboards/unified_dashboard.html`

**Legacy/Test Dashboards**:
- `dashboards/index.html`
- `dashboards/enterprise_demo_dashboard.html`
- `dashboards/kong-dashboard.html`
- `dashboards/test-dashboard.html`

**Specialized Dashboards**:
- `visualization/ai-insights.html`
- `visualization/simple-ai-dashboard.html`
- `kong-guard-ai/branding/dashboard.html`
- `testing-ui/index.html`
- `kong-local-testing/dashboard.html`

**Total Archived**: 19+ dashboard files

---

## 🔄 Migration Guide

### For Developers

**Old URLs**:
```
http://localhost:8080/visualization/index.html
http://localhost:8080/public/dashboards/kong-dashboard.html
```

**New URL**:
```
http://localhost:3000/          (Unified Dashboard)
```

### Mode Switching

The unified dashboard replaces all old dashboards with a single interface that has three modes:

**Demo Mode** (Replaces visualization/index.html):
- Clean presentation view
- Perfect for recordings and demos
- No control panels visible
- Full-width visualization

**Control Mode** (Replaces kong-dashboard.html):
- Full testing and management tools
- Attack simulator
- Configuration panel
- Test controls

**Hybrid Mode** (Default):
- Best of both worlds
- All features visible
- Balanced layout

### Accessing Modes

```typescript
// URL Parameters
http://localhost:3000/?mode=demo
http://localhost:3000/?mode=control
http://localhost:3000/?mode=hybrid

// Keyboard Shortcut
Ctrl+D - Toggle Demo Mode

// UI Toggle
Click mode selector in top bar
```

---

## 🛠️ For Demo Recording

### Old Approach
```python
# hackathon_demo_recorder.py
DEFAULT_URL = "http://localhost:8080/visualization/index.html"
```

### New Approach
```python
# hackathon_demo_recorder.py (Updated)
DEFAULT_URL = "http://localhost:3000/?mode=demo"
```

**Benefits**:
- ✅ Single dashboard URL
- ✅ Clean demo mode built-in
- ✅ Better performance
- ✅ Modern UI components
- ✅ TypeScript safety

---

## 📊 Feature Comparison

| Feature | Old Dashboards | New Unified Dashboard |
|---------|----------------|----------------------|
| **Real-time Updates** | ✅ WebSocket | ✅ WebSocket (improved) |
| **Attack Simulator** | ✅ Separate file | ✅ Built-in (Control mode) |
| **Visual Effects** | ✅ Custom JS | ✅ Animated components |
| **Charts** | ✅ Chart.js | ✅ Recharts (React) |
| **Demo Mode** | ❌ | ✅ Dedicated mode |
| **Dark Theme** | ✅ Fixed | ✅ Toggle support |
| **TypeScript** | ❌ | ✅ Full support |
| **Mobile Responsive** | ⚠️ Partial | ✅ Fully responsive |
| **Keyboard Shortcuts** | ❌ | ✅ Extensive |
| **Export Data** | ⚠️ Limited | ✅ Full export |
| **State Management** | ❌ | ✅ React state |
| **Component Library** | ❌ | ✅ shadcn/ui |
| **Hot Reload** | ❌ | ✅ Next.js HMR |

---

## 🚀 Getting Started with Unified Dashboard

### Installation
```bash
cd /path/to/KongGuardAI/dashboard
npm install
```

### Development
```bash
npm run dev
# Opens at http://localhost:3000
```

### Production Build
```bash
npm run build
npm start
```

### Configuration
```bash
# Environment variables
cp .env.example .env.local

# Edit configuration
NEXT_PUBLIC_WEBSOCKET_URL=ws://localhost:8000/ws
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## 📖 Documentation

### New Documentation
- `/dashboard/README.md` - Dashboard setup and usage
- `/docs/unified-dashboard-guide.md` - Complete guide
- `/docs/dashboard-migration.md` - Migration instructions
- `/UNIFIED_DASHBOARD_PROJECT_PLAN.md` - Project overview

### Deprecated Documentation
- Old dashboard references in docs
- Legacy setup guides
- Outdated API documentation

---

## ⚠️ Breaking Changes

### URLs Changed
All old dashboard URLs no longer work. Use new unified dashboard URL.

### API Updates
Some API endpoints may have changed. Check new API documentation.

### Dependencies
Old dashboards used different dependencies. New dashboard uses:
- Next.js 15
- React 19
- shadcn/ui components
- Recharts for charts

### Configuration
Configuration format changed. Update your config files according to new schema.

---

## 🔍 Why Consolidation?

### Problems with Multiple Dashboards
- ❌ **Maintenance burden**: 19 files to update
- ❌ **Inconsistent UX**: Different look and feel
- ❌ **Code duplication**: Same features implemented multiple times
- ❌ **Hard to test**: Need to test 19 different pages
- ❌ **Confusing**: Users don't know which to use
- ❌ **No TypeScript**: Missing type safety
- ❌ **Poor performance**: Multiple implementations, no optimization

### Benefits of Unified Dashboard
- ✅ **Single source of truth**: One dashboard to maintain
- ✅ **Consistent UX**: Same look and feel everywhere
- ✅ **Modern stack**: Next.js 15 + React 19 + TypeScript
- ✅ **Better performance**: Optimized build, code splitting
- ✅ **Type safety**: TypeScript prevents bugs
- ✅ **Easier testing**: Test one dashboard, not 19
- ✅ **Mode system**: Demo/Control/Hybrid in one interface
- ✅ **Future-proof**: Easy to add new features

---

## 🗑️ Can I Delete These Files?

**Keep for Reference**: These archived dashboards are kept for:
- Historical reference
- Feature comparison
- Visual effect inspiration
- Testing fallback
- Documentation examples

**Do Not Use**: But do not use them for:
- New development
- Production deployments
- Demo recordings
- Documentation examples (use new dashboard)

**Timeline**: These files will be completely removed in a future release after confirming all functionality has been migrated.

---

## 📞 Need Help?

### Migration Issues
If you encounter issues migrating from old dashboards:
1. Check `/docs/dashboard-migration.md`
2. Review new dashboard documentation
3. Check feature comparison table above
4. File an issue with specific questions

### Feature Missing?
If a feature from old dashboards is missing:
1. Check if it's in a different mode (Demo/Control/Hybrid)
2. Check keyboard shortcuts
3. Review new dashboard documentation
4. Request feature addition

### Performance Issues?
If the new dashboard is slower:
1. Check your build configuration
2. Enable production mode
3. Check WebSocket connection
4. Review browser console for errors

---

## 📅 Deprecation Timeline

- **2024-09-30**: Dashboards archived, unified dashboard created
- **2024-10-07**: Feature parity achieved (target)
- **2024-10-14**: Demo recorder updated (target)
- **2024-10-21**: Documentation updated (target)
- **2024-11-01**: Old dashboards marked for removal (target)
- **2024-12-01**: Old dashboards removed from repository (target)

---

## ✅ Checklist for Migration

- [ ] Install unified dashboard dependencies
- [ ] Update demo recorder URL
- [ ] Update documentation references
- [ ] Update CI/CD pipelines
- [ ] Test all three modes
- [ ] Verify WebSocket connection
- [ ] Test attack simulator
- [ ] Test export functionality
- [ ] Update bookmarks/shortcuts
- [ ] Train team on new dashboard

---

## 🎯 Summary

**Status**: ❌ All dashboards in this directory are deprecated  
**Action Required**: Migrate to `/dashboard/` (unified dashboard)  
**Timeline**: Complete migration by 2024-11-01  
**Support**: See documentation in `/docs/`

**The unified dashboard provides all functionality from these 19+ archived dashboards in a single, modern, maintainable interface.**

---

**Archived**: 2024-09-30  
**Unified Dashboard Branch**: `feature/unified-dashboard`  
**Status**: Archived for reference only  
**Do Not Use**: For production or development
