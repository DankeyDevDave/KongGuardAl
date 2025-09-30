# 🎯 Unified Dashboard Project Plan

**Feature Branch**: `feature/unified-dashboard`  
**Started**: 2024-09-30  
**Goal**: Consolidate 19 dashboards into one unified shadcn/ui dashboard

---

## 📊 Current Status

### ✅ Phase 1: Branch Setup & Preparation - STARTED
- [x] Create feature branch `feature/unified-dashboard`
- [x] Document current state
- [ ] Move shadcn dashboard to root level
- [ ] Archive legacy dashboards
- [ ] Update .gitignore

### ⏳ Phase 2: Core Implementation - PENDING
- [ ] Build unified layout component
- [ ] Integrate WebSocket for real-time data
- [ ] Migrate visual effects from old dashboards
- [ ] Add dark theme refinements

### ⏳ Phase 3: Features - PENDING
- [ ] Add attack simulator control panel
- [ ] Add mode switcher (Demo/Control/Hybrid)
- [ ] Add collapsible panels
- [ ] Add keyboard shortcuts
- [ ] Add export functionality

### ⏳ Phase 4: Testing & Documentation - PENDING
- [ ] Test all features
- [ ] Update demo recorder to use new dashboard
- [ ] Write migration guide
- [ ] Update all documentation references

### ⏳ Phase 5: Review & Merge - PENDING
- [ ] Code review
- [ ] Final testing
- [ ] Merge to main

---

## 📁 Project Structure

### New Structure (Target)
```
dashboard/                          # Root dashboard (moved from shadcn-dashboard/shadcn-dashboard/)
├── src/
│   ├── app/
│   │   ├── page.tsx               # Unified dashboard page
│   │   └── layout.tsx
│   ├── components/
│   │   ├── unified/
│   │   │   ├── UnifiedDashboard.tsx
│   │   │   ├── MetricsBar.tsx
│   │   │   ├── ControlPanel.tsx
│   │   │   ├── LiveVisualization.tsx
│   │   │   └── ModeToggle.tsx
│   │   ├── controls/
│   │   │   ├── AttackSimulator.tsx
│   │   │   └── ConfigPanel.tsx
│   │   └── ui/                    # shadcn/ui components
│   ├── lib/
│   │   ├── websocket.ts
│   │   └── api.ts
│   └── hooks/
│       ├── use-websocket.ts
│       └── use-demo-mode.ts
└── package.json

archived-dashboards/                # Legacy files
├── DEPRECATED.md
├── visualization/
├── public/dashboards/
└── dashboards/
```

---

## 🎯 Key Objectives

### 1. Consolidation
- **Before**: 19 separate dashboard files
- **After**: 1 unified dashboard
- **Benefit**: Single source of truth, easier maintenance

### 2. Modern Stack
- Next.js 15 with App Router
- React 19
- TypeScript
- shadcn/ui components
- Dark theme built-in

### 3. Dual Purpose
- **Demo Mode**: Clean presentation view (for recording)
- **Control Mode**: Full testing controls
- **Hybrid Mode**: Both visible (default)

### 4. Real-time Features
- WebSocket live updates
- Threat flow animations
- Live event feed
- Real-time charts

---

## 🔄 Migration Strategy

### Legacy Dashboards to Archive

**Primary Dashboards** (3):
1. `visualization/index.html` - Main React dashboard (407 lines)
2. `public/dashboards/kong-dashboard.html` - Testing dashboard (641 lines)
3. `shadcn-dashboard/` - Will be moved to root as `dashboard/`

**Secondary Dashboards** (16+):
- Enterprise demo versions
- Attack visualization dashboards
- Test interfaces
- Branded versions
- Legacy prototypes

### Files to Update

**Critical**:
- `hackathon_demo_recorder.py` - Update dashboard URL
- `hackathon-prep.sh` - Update dashboard references
- `README.md` - Update dashboard documentation

**Documentation**:
- All `.md` files referencing old dashboards
- API documentation
- Setup guides

---

## 🎨 Unified Dashboard Features

### Layout Design
```
┌─────────────────────────────────────────────────────┐
│ Top Bar: Metrics (Always visible)                  │
├──────────┬──────────────────────────────────────────┤
│ Left:    │ Center: Live Visualization               │
│ Controls │ - Threat flow                           │
│ Panel    │ - Charts                                │
│ (Toggle) │ - Event feed                            │
├──────────┴──────────────────────────────────────────┤
│ Bottom: AI Thinking / Logs (Collapsible)           │
└─────────────────────────────────────────────────────┘
```

### Mode System
- **Demo Mode**: Hide controls, full-width visualization
- **Control Mode**: Show all controls, compact visualization  
- **Hybrid Mode**: Balanced layout (default)

### Key Features
- ✅ Real-time WebSocket updates
- ✅ Interactive attack simulator
- ✅ Live threat flow animation
- ✅ Event feed with filtering
- ✅ Real-time charts (Recharts)
- ✅ AI thinking display
- ✅ Keyboard shortcuts
- ✅ Export functionality
- ✅ Collapsible panels
- ✅ Dark theme

---

## 📋 Implementation Checklist

### Phase 1: Setup ✅ In Progress
- [x] Create feature branch
- [ ] Create project plan document
- [ ] Add new files to git
- [ ] Initial commit
- [ ] Move shadcn-dashboard to root
- [ ] Archive old dashboards
- [ ] Update paths and configs

### Phase 2: Core
- [ ] Create `dashboard/src/components/unified/UnifiedDashboard.tsx`
- [ ] Create `dashboard/src/components/unified/MetricsBar.tsx`
- [ ] Create `dashboard/src/components/unified/ControlPanel.tsx`
- [ ] Create `dashboard/src/components/unified/LiveVisualization.tsx`
- [ ] Create `dashboard/src/lib/websocket.ts`
- [ ] Create `dashboard/src/hooks/use-websocket.ts`
- [ ] Update `dashboard/src/app/page.tsx`

### Phase 3: Features
- [ ] Implement attack simulator
- [ ] Implement mode switcher
- [ ] Implement collapsible panels
- [ ] Add keyboard shortcuts
- [ ] Add export functionality
- [ ] Migrate visual effects

### Phase 4: Integration
- [ ] Test WebSocket connectivity
- [ ] Test demo recorder compatibility
- [ ] Test all three modes
- [ ] Cross-browser testing
- [ ] Mobile responsive testing

### Phase 5: Documentation
- [ ] Write `archived-dashboards/DEPRECATED.md`
- [ ] Write `docs/dashboard-migration.md`
- [ ] Write `docs/unified-dashboard-guide.md`
- [ ] Update `README.md`
- [ ] Update all doc references

### Phase 6: Cleanup
- [ ] Remove unused dependencies
- [ ] Optimize bundle size
- [ ] Run linter
- [ ] Run type check
- [ ] Final testing

---

## 🔗 Dependencies

### Required for Unified Dashboard
```json
{
  "dependencies": {
    "next": "15.5.4",
    "react": "19.1.0",
    "react-dom": "19.1.0",
    "typescript": "^5",
    "@radix-ui/*": "latest",
    "lucide-react": "^0.544.0",
    "tailwindcss": "^3.4.17",
    "recharts": "^2.x", // For charts
    "class-variance-authority": "^0.7.1",
    "tailwind-merge": "^3.3.1"
  }
}
```

### New Dependencies to Add
- `recharts` - For real-time charts
- `ws` or native WebSocket - For real-time updates

---

## 📊 Success Metrics

### Quantitative
- ✅ Reduce from 19 dashboards to 1 unified dashboard
- ✅ Bundle size < 500KB (gzipped)
- ✅ First paint < 1s
- ✅ WebSocket latency < 100ms
- ✅ 100% feature parity with old dashboards

### Qualitative
- ✅ Clean, modern UI with dark theme
- ✅ Intuitive mode switching
- ✅ Smooth animations and transitions
- ✅ Professional appearance for demos
- ✅ Developer-friendly for testing
- ✅ Maintainable codebase

---

## 🚀 Next Steps

### Immediate (Today)
1. ✅ Create feature branch
2. ✅ Create project plan
3. ⏳ Add files to git
4. ⏳ Initial commit with plan
5. ⏳ Move shadcn-dashboard to `dashboard/`
6. ⏳ Create `archived-dashboards/` directory

### This Week
- Day 1-2: Setup and file organization
- Day 3-4: Core implementation
- Day 5: Features and integration
- Day 6: Testing and documentation
- Day 7: Review and merge

### Future Enhancements (Post-Merge)
- Advanced filtering options
- Custom dashboard layouts
- User preferences persistence
- Multi-language support
- Advanced analytics
- Performance monitoring
- Alerting system

---

## 📝 Notes

### Design Decisions
- **Why Next.js?**: Server-side rendering, API routes, better performance
- **Why shadcn/ui?**: Modern, accessible, customizable components
- **Why dark theme?**: Professional look, better for demos, less eye strain
- **Why single page?**: No navigation complexity, better for demos

### Technical Decisions
- **WebSocket over polling**: Real-time updates with lower latency
- **Recharts over Chart.js**: Better React integration, TypeScript support
- **Component library**: Reusable, tested, accessible components
- **TypeScript**: Type safety, better DX, fewer bugs

---

## 🔗 Related Documents

- `DASHBOARD_NAVIGATION_WIREFRAME.md` - Current dashboard analysis
- `MENU_NAVIGATION_FLOW.md` - CLI menu documentation
- `HACKATHON_SYSTEM_COMPLETE.md` - Complete system overview
- `README.md` - Project README

---

**Status**: 🟡 In Progress  
**Branch**: `feature/unified-dashboard`  
**Last Updated**: 2024-09-30  
**Next Milestone**: Complete Phase 1 setup
