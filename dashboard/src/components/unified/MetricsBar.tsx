import { Badge } from "@/components/ui/badge"
import { Card } from "@/components/ui/card"
import { Wifi, WifiOff, Activity, Shield, AlertTriangle, Clock } from "lucide-react"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"

interface MetricsData {
  unprotected: {
    total: number
    blocked: number
    vulnerable: number
    totalTime: number
    successRate: number
  }
  cloud: {
    total: number
    blocked: number
    totalTime: number
    detectionRate: number
  }
  local: {
    total: number
    blocked: number
    totalTime: number
    detectionRate: number
  }
}

interface MetricsBarProps {
  metrics: MetricsData
  isConnected: boolean
  className?: string
}

export function MetricsBar({ metrics, isConnected, className = "" }: MetricsBarProps) {
  // Calculate aggregate metrics
  const totalRequests = metrics.unprotected.total + metrics.cloud.total + metrics.local.total
  const totalBlocked = metrics.cloud.blocked + metrics.local.blocked
  const avgLatency = totalRequests > 0
    ? Math.round((metrics.unprotected.totalTime + metrics.cloud.totalTime + metrics.local.totalTime) / totalRequests)
    : 0
  const overallDetectionRate = totalRequests > 0
    ? ((totalBlocked / totalRequests) * 100).toFixed(1)
    : '0.0'

  const metricItems = [
    {
      icon: Activity,
      label: 'Total Requests',
      value: totalRequests.toLocaleString(),
      color: 'text-kong-steel',
      tooltip: 'Total requests processed across all tiers'
    },
    {
      icon: Shield,
      label: 'Threats Blocked',
      value: totalBlocked.toLocaleString(),
      color: 'text-kong-critical',
      tooltip: 'Malicious requests blocked by AI protection'
    },
    {
      icon: AlertTriangle,
      label: 'Detection Rate',
      value: `${overallDetectionRate}%`,
      color: 'text-kong-normal',
      tooltip: 'Percentage of threats successfully detected'
    },
    {
      icon: Clock,
      label: 'Avg Latency',
      value: `${avgLatency}ms`,
      color: 'text-kong-accent',
      tooltip: 'Average response time across all tiers'
    }
  ]

  return (
    <Card className={`border-b border-border bg-kong-surface/50 backdrop-blur-sm ${className}`}>
      <div className="w-full px-6 py-3">
        <div className="flex items-center justify-between gap-4">
          {/* Logo and Title */}
          <div className="flex items-center space-x-4">
            <div className="flex flex-col">
              <img
                src="/kong-guard-ai-full-logo.png"
                alt="Kong Guard AI full logo"
                className="h-12 w-auto max-w-[220px] object-contain"
                style={{ filter: 'brightness(1.1) contrast(1.1)' }}
              />
              <p className="text-xs text-muted-foreground">Enterprise Security Dashboard</p>
            </div>
          </div>

          {/* Metrics */}
          <TooltipProvider>
            <div className="ml-auto flex items-center gap-4 lg:gap-6">
              {metricItems.map((metric, index) => {
                const Icon = metric.icon
                return (
                  <Tooltip key={index}>
                    <TooltipTrigger asChild>
                      <div className="flex items-center gap-2 cursor-help">
                        <Icon className={`h-4 w-4 ${metric.color}`} />
                        <div className="hidden sm:block">
                          <p className="text-xs text-muted-foreground leading-none">{metric.label}</p>
                          <p className={`text-sm font-semibold ${metric.color} leading-none mt-1`}>
                            {metric.value}
                          </p>
                        </div>
                        <div className="sm:hidden">
                          <p className={`text-sm font-semibold ${metric.color}`}>{metric.value}</p>
                        </div>
                      </div>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p className="text-xs">{metric.tooltip}</p>
                    </TooltipContent>
                  </Tooltip>
                )
              })}

              {/* Connection Status */}
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant="outline"
                    className={`${
                      isConnected
                        ? 'text-kong-normal border-kong-normal'
                        : 'text-kong-critical border-kong-critical'
                    }`}
                  >
                    {isConnected ? (
                      <>
                        <Wifi className="h-3 w-3 mr-1" />
                        <span className="hidden sm:inline">Live</span>
                      </>
                    ) : (
                      <>
                        <WifiOff className="h-3 w-3 mr-1" />
                        <span className="hidden sm:inline">Offline</span>
                      </>
                    )}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="text-xs">
                    {isConnected
                      ? 'Real-time WebSocket connection active'
                      : 'WebSocket disconnected - attempting to reconnect'}
                  </p>
                </TooltipContent>
              </Tooltip>
            </div>
          </TooltipProvider>
        </div>
      </div>
    </Card>
  )
}
