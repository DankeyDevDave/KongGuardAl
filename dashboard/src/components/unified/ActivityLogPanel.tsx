import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Activity, Shield, ShieldCheck, AlertTriangle, ChevronLeft, ChevronRight } from "lucide-react"
import { useState } from "react"

export interface ActivityLogEntry {
  id: string
  timestamp: number
  tier: 'unprotected' | 'cloud' | 'local'
  attackType: string
  latencyMs: number
  action: 'blocked' | 'allowed'
  threatScore?: number
  confidence?: number
  method: string
  path: string
}

interface ActivityLogPanelProps {
  activityLog: ActivityLogEntry[]
  className?: string
  isCollapsible?: boolean
  defaultCollapsed?: boolean
}

export function ActivityLogPanel({
  activityLog,
  className = "",
  isCollapsible = false,
  defaultCollapsed = true
}: ActivityLogPanelProps) {
  const [isCollapsed, setIsCollapsed] = useState(defaultCollapsed)
  const tiers = ['unprotected', 'cloud', 'local'] as const

  const tierConfig = {
    unprotected: {
      title: 'Unprotected Gateway',
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-950/20',
      borderColor: 'border-red-900/50'
    },
    cloud: {
      title: 'Cloud AI Protection',
      icon: Shield,
      color: 'text-blue-400',
      bgColor: 'bg-blue-950/20',
      borderColor: 'border-blue-900/50'
    },
    local: {
      title: 'Local AI Protection',
      icon: ShieldCheck,
      color: 'text-green-400',
      bgColor: 'bg-green-950/20',
      borderColor: 'border-green-900/50'
    }
  }

  const getEntriesForTier = (tier: string) => {
    return activityLog
      .filter(entry => entry.tier === tier)
      .slice(0, 20) // Max 20 per tier
  }

  const formatTimestamp = (timestamp: number) => {
    const now = Date.now()
    const diff = (now - timestamp) / 1000
    if (diff < 1) return 'now'
    if (diff < 60) return `${Math.floor(diff)}s ago`
    return new Date(timestamp).toLocaleTimeString()
  }

  if (isCollapsible) {
    return (
      <div className={`fixed right-0 top-1/2 -translate-y-1/2 z-40 transition-all duration-300 ${className}`}>
        {/* Collapsed Tab */}
        {isCollapsed && (
          <button
            onClick={() => setIsCollapsed(false)}
            className="bg-kong-surface border border-kong-line border-r-0 rounded-l-lg p-3 shadow-lg hover:bg-kong-bg/50 transition-colors"
            title="Show Activity Feed"
          >
            <div className="flex flex-col items-center gap-2">
              <Activity className="h-5 w-5 text-kong-steel" />
              <span className="text-xs text-kong-silver writing-mode-vertical-rl text-orientation-mixed">
                Activity
              </span>
            </div>
          </button>
        )}

        {/* Expanded Panel */}
        {!isCollapsed && (
          <div className="bg-kong-surface border border-kong-line rounded-l-lg shadow-lg w-96 max-h-[80vh] flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-kong-line">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-kong-steel" />
                <span className="text-sm font-semibold text-kong-silver">Live Activity Feed</span>
                <Badge variant="outline" className="text-xs">
                  Real-time
                </Badge>
              </div>
              <button
                onClick={() => setIsCollapsed(true)}
                className="p-1 hover:bg-kong-bg/50 rounded transition-colors"
                title="Hide Activity Feed"
              >
                <ChevronRight className="h-4 w-4 text-kong-steel" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-4">
              <div className="space-y-4">
                {tiers.map(tier => {
                  const config = tierConfig[tier]
                  const Icon = config.icon
                  const entries = getEntriesForTier(tier)

                  return (
                    <div key={tier} className={`rounded-lg border ${config.borderColor} ${config.bgColor}`}>
                      {/* Tier Header */}
                      <div className="px-3 py-2 border-b border-kong-line bg-kong-bg/30">
                        <div className="flex items-center gap-2">
                          <Icon className={`h-4 w-4 ${config.color}`} />
                          <span className="text-xs font-semibold text-kong-silver">
                            {config.title}
                          </span>
                        </div>
                      </div>

                      {/* Activity Log Entries */}
                      <div className="h-48 overflow-y-auto p-2 space-y-2 scrollbar-thin scrollbar-thumb-kong-line scrollbar-track-transparent">
                        {entries.length === 0 ? (
                          <div className="text-xs text-muted-foreground text-center py-6">
                            <Activity className="h-6 w-6 mx-auto mb-2 opacity-30" />
                            <p>No activity yet</p>
                            <p className="text-[10px] mt-1">Waiting for requests...</p>
                          </div>
                        ) : (
                          entries.map(entry => (
                            <ActivityLogItem
                              key={entry.id}
                              entry={entry}
                              tierColor={config.color}
                              formatTimestamp={formatTimestamp}
                            />
                          ))
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}
      </div>
    )
  }

  // Original layout for non-collapsible mode
  return (
    <Card className={`border-kong-line bg-kong-surface ${className}`}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Activity className="h-4 w-4 text-kong-steel" />
          Live Activity Feed
          <Badge variant="outline" className="ml-auto text-xs">
            Real-time
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 gap-4">
          {tiers.map(tier => {
            const config = tierConfig[tier]
            const Icon = config.icon
            const entries = getEntriesForTier(tier)

            return (
              <div key={tier} className={`rounded-lg border ${config.borderColor} ${config.bgColor}`}>
                {/* Tier Header */}
                <div className="px-3 py-2 border-b border-kong-line bg-kong-bg/30">
                  <div className="flex items-center gap-2">
                    <Icon className={`h-4 w-4 ${config.color}`} />
                    <span className="text-xs font-semibold text-kong-silver">
                      {config.title}
                    </span>
                  </div>
                </div>

                {/* Activity Log Entries */}
                <div className="h-64 overflow-y-auto p-2 space-y-2 scrollbar-thin scrollbar-thumb-kong-line scrollbar-track-transparent">
                  {entries.length === 0 ? (
                    <div className="text-xs text-muted-foreground text-center py-8">
                      <Activity className="h-8 w-8 mx-auto mb-2 opacity-30" />
                      <p>No activity yet</p>
                      <p className="text-[10px] mt-1">Waiting for requests...</p>
                    </div>
                  ) : (
                    entries.map(entry => (
                      <ActivityLogItem
                        key={entry.id}
                        entry={entry}
                        tierColor={config.color}
                        formatTimestamp={formatTimestamp}
                      />
                    ))
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}

// Sub-component for individual log entries
function ActivityLogItem({
  entry,
  tierColor,
  formatTimestamp
}: {
  entry: ActivityLogEntry
  tierColor: string
  formatTimestamp: (timestamp: number) => string
}) {
  const age = (Date.now() - entry.timestamp) / 1000
  const opacity = age > 30 ? 'opacity-30' : age > 20 ? 'opacity-60' : 'opacity-100'

  const actionIcon = entry.action === 'blocked' ? '✅' : entry.tier === 'unprotected' ? '🔴' : '🟢'
  const actionColor = entry.action === 'blocked' ? 'text-green-400' :
                     entry.tier === 'unprotected' ? 'text-red-400' : 'text-green-300'

  // Format attack type nicely
  const formatAttackType = (type: string) => {
    const typeMap: Record<string, string> = {
      'sql': 'SQL INJ',
      'xss': 'XSS',
      'cmd_injection': 'CMD INJ',
      'path': 'PATH TRAV',
      'ldap_injection': 'LDAP INJ',
      'business_logic': 'BUS LOGIC',
      'ransomware': 'RANSOMWARE',
      'normal': 'NORMAL',
      'none': 'NORMAL'
    }
    return typeMap[type] || type.toUpperCase()
  }

  return (
    <div className={`rounded border border-kong-line bg-kong-bg/50 p-2 text-xs ${opacity} transition-opacity duration-1000 hover:opacity-100 hover:bg-kong-surface/50 cursor-default`}>
      <div className="flex items-center justify-between mb-1">
        <span className={`font-mono font-bold ${tierColor}`}>
          {entry.latencyMs.toFixed(1)}ms
        </span>
        <span className="text-muted-foreground text-[10px]">
          {formatTimestamp(entry.timestamp)}
        </span>
      </div>

      <div className="flex items-center gap-2 mb-1">
        <span className="text-base">{actionIcon}</span>
        <span className={`font-semibold ${actionColor} uppercase text-[10px]`}>
          {entry.action}
        </span>
      </div>

      <div className="text-muted-foreground text-[10px] font-mono">
        {formatAttackType(entry.attackType)}
      </div>

      <div className="text-muted-foreground text-[10px] truncate" title={`${entry.method} ${entry.path}`}>
        {entry.method} {entry.path}
      </div>

      {entry.threatScore !== undefined && (
        <div className="mt-1 text-[10px] flex items-center justify-between">
          <span className="text-muted-foreground">Score:</span>
          <span className={entry.threatScore > 0.7 ? 'text-red-400 font-bold' : 'text-green-400'}>
            {entry.threatScore.toFixed(2)}
          </span>
        </div>
      )}
    </div>
  )
}
