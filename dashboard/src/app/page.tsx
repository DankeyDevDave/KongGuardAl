"use client"

import { useEffect, useState } from "react"
import { useRealtimeDashboard } from "@/hooks/useRealtimeDashboard"
import { useDemoMode } from "@/hooks/use-demo-mode"
import { MetricsBar } from "@/components/unified/MetricsBar"
import { ModeToggle } from "@/components/unified/ModeToggle"
import { ControlPanel } from "@/components/unified/ControlPanel"
import { LiveVisualization } from "@/components/unified/LiveVisualization"
import { ActivityLogPanel } from "@/components/unified/ActivityLogPanel"

export default function KongGuardDashboard() {
  const [isControlCollapsed, setIsControlCollapsed] = useState(false)

  // Use the demo mode hook for mode management
  const { mode, setMode, showControls, isFullWidth } = useDemoMode({
    defaultMode: 'hybrid',
    enableKeyboardShortcuts: true
  })

  // Use the real-time dashboard hook
  const { data, activityLog, testAttack, launchAttackFlood, isConnected } = useRealtimeDashboard({
    websocketUrl: 'ws://localhost:18002/ws',
    apiBaseUrls: {
      unprotected: 'http://localhost:8000',
      cloud: 'http://localhost:28100',
      local: 'http://localhost:28101'
    }
  })

  // Apply dark mode on mount (always dark for this dashboard)
  useEffect(() => {
    document.documentElement.classList.add('dark')
  }, [])



  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      {/* Top Metrics Bar with Mode Toggle */}
      <div className="sticky top-0 z-50">
        <div className="relative overflow-visible">
          <MetricsBar
            metrics={data.metrics}
            isConnected={isConnected}
          />
          <div className="border-b border-border bg-kong-surface/50 backdrop-blur-sm">
            <div className="container mx-auto px-6 py-4 flex items-center justify-end">
              <ModeToggle
                currentMode={mode}
                onModeChange={setMode}
              />
            </div>
          </div>
          <div className="pointer-events-none absolute left-6 top-0 translate-y-2 sm:translate-y-2 md:translate-y-3 lg:translate-y-4 xl:translate-y-5 z-20">
            <img
              src="/LogoSet.png"
              alt="Kong Guard AI"
              className="h-16 w-auto sm:h-20 md:h-24 lg:h-28"
              style={{ filter: 'brightness(1.08) contrast(1.08)' }}
            />
          </div>
        </div>
      </div>

      {/* Main Dashboard Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Control Panel - Shown in Control and Hybrid modes */}
        {showControls && (
          <ControlPanel
            onTestAttack={testAttack}
            onLaunchFlood={launchAttackFlood}
            isCollapsed={isControlCollapsed}
            onToggleCollapse={() => setIsControlCollapsed(!isControlCollapsed)}
          />
        )}

        {/* Live Visualization - Always shown, full width in Demo mode */}
        <LiveVisualization
          data={data}
          activeModels={data.activeModels}
          fullWidth={isFullWidth}
        />
      </div>

      {/* Activity Log Panel - Below main content */}
      <ActivityLogPanel 
        activityLog={activityLog}
        className="mx-6 mb-6"
      />
    </div>
  )
}
