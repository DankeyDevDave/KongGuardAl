import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Progress } from "@/components/ui/progress"
import { Shield, AlertTriangle, ShieldCheck, Activity, TrendingUp } from "lucide-react"
import { BarChart, Bar, PieChart, Pie, Cell, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend } from 'recharts'

interface AttackResult {
  threat_score: number
  threat_type: string
  recommended_action: string
  reasoning: string
  confidence?: number
  processing_time?: number
  ai_model?: string
}

interface AttackMetrics {
  total: number
  blocked: number
  vulnerable: number
  totalTime: number
  totalConfidence: number
  detectionRate: number
  successRate: number
}

interface LiveVisualizationProps {
  data: {
    metrics: {
      unprotected: AttackMetrics
      cloud: AttackMetrics
      local: AttackMetrics
    }
    attackResults: Record<string, Record<string, AttackResult>>
  }
  activeModels?: Partial<Record<'unprotected' | 'cloud' | 'local', string | null>>
  fullWidth?: boolean
  className?: string
}

export function LiveVisualization({ data, activeModels = {}, fullWidth = false, className = "" }: LiveVisualizationProps) {
  const resolveTitle = (tierId: string, baseTitle: string) => {
    const activeModel = activeModels[tierId as keyof typeof activeModels]
    if (!activeModel) {
      return baseTitle
    }
    return `${baseTitle} (${activeModel})`
  }

  const getModelDescription = (tierId: string, fallbackText: string) => {
    const activeModel = activeModels[tierId as keyof typeof activeModels]

    if (!activeModel) {
      // Model is offline - show offline status with failover info
      if (tierId === 'cloud') {
        return 'Model Offline - Failover to Local AI'
      } else if (tierId === 'local') {
        return 'Model Offline - Failover to Cloud AI'
      }
      return fallbackText
    }

    // Model is online - show full provider/model name
    return activeModel
  }

  const getModelStatusColor = (tierId: string) => {
    const activeModel = activeModels[tierId as keyof typeof activeModels]

    if (!activeModel) {
      // Model is offline - use caution color
      return 'text-kong-caution'
    }

    // Model is online - use normal colors
    if (tierId === 'cloud') {
      return 'text-kong-steel'
    } else if (tierId === 'local') {
      return 'text-kong-normal'
    }
    return 'text-muted-foreground'
  }

  const protectionTiers = [
    {
      id: 'unprotected',
      title: resolveTitle('unprotected', 'Unprotected Kong Gateway'),
      description: 'No AI Protection',
      descriptionColor: 'text-muted-foreground',
      icon: AlertTriangle,
      statusColor: 'text-kong-critical',
      borderColor: 'border-kong-critical',
    },
    {
      id: 'cloud',
      title: resolveTitle('cloud', 'Cloud AI Protection'),
      description: getModelDescription('cloud', 'Gemini/GPT Analysis'),
      descriptionColor: getModelStatusColor('cloud'),
      icon: Shield,
      statusColor: 'text-kong-steel',
      borderColor: 'border-kong-steel',
    },
    {
      id: 'local',
      title: resolveTitle('local', 'Local AI Protection'),
      description: getModelDescription('local', 'Private Local AI'),
      descriptionColor: getModelStatusColor('local'),
      icon: ShieldCheck,
      statusColor: 'text-kong-normal',
      borderColor: 'border-kong-normal',
    },
  ]

  // Prepare chart data
  const tierComparisonData = protectionTiers.map(tier => ({
    name: tier.id === 'unprotected' ? 'Unprotected' : tier.id === 'cloud' ? 'Cloud AI' : 'Local AI',
    requests: data.metrics[tier.id as keyof typeof data.metrics].total,
    blocked: data.metrics[tier.id as keyof typeof data.metrics].blocked,
    vulnerable: data.metrics[tier.id as keyof typeof data.metrics].vulnerable || 0
  }))

  const detectionRateData = protectionTiers
    .filter(t => t.id !== 'unprotected')
    .map(tier => {
      const metrics = data.metrics[tier.id as keyof typeof data.metrics]
      return {
        name: tier.id === 'cloud' ? 'Cloud AI' : 'Local AI',
        rate: metrics.detectionRate || 0
      }
    })

  const COLORS = ['#ff4444', '#4a9eff', '#44ff44']

  return (
    <div className={`flex-1 overflow-y-auto ${className}`}>
      <div className={fullWidth ? "container mx-auto px-6 py-6" : "px-6 py-6"}>
        {/* Protection Tiers Overview */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {protectionTiers.map((tier) => {
            const tierMetrics = data.metrics[tier.id as keyof typeof data.metrics]
            const Icon = tier.icon

            return (
              <Card key={tier.id} className={`${tier.borderColor} border-2 bg-kong-surface`}>
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center space-x-2">
                    <Icon className={`h-5 w-5 ${tier.statusColor}`} />
                    <span className="text-kong-silver text-sm">{tier.title}</span>
                  </CardTitle>
                  <p className={`text-xs ${tier.descriptionColor}`}>{tier.description}</p>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-muted-foreground">Requests:</span>
                      <span className="text-kong-silver font-medium text-sm">{tierMetrics.total}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-muted-foreground">Blocked:</span>
                      <span className="text-kong-silver font-medium text-sm">{tierMetrics.blocked}</span>
                    </div>
                    {tier.id === 'unprotected' ? (
                      <>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-muted-foreground">Vulnerable:</span>
                          <Badge variant="outline" className="text-kong-critical border-kong-critical text-xs">
                            {tierMetrics.vulnerable}
                          </Badge>
                        </div>
                        <Progress
                          value={tierMetrics.successRate || 0}
                          className="h-2"
                        />
                        <p className="text-xs text-muted-foreground text-right">
                          {(tierMetrics.successRate || 0).toFixed(1)}% pass rate
                        </p>
                      </>
                    ) : (
                      <>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-muted-foreground">Detection:</span>
                          <Badge variant="outline" className="text-kong-normal border-kong-normal text-xs">
                            {(tierMetrics.detectionRate || 0).toFixed(1)}%
                          </Badge>
                        </div>
                        <Progress
                          value={tierMetrics.detectionRate || 0}
                          className="h-2"
                        />
                        <p className="text-xs text-muted-foreground text-right">
                          Avg: {tierMetrics.total > 0 ? (tierMetrics.totalTime / tierMetrics.total).toFixed(0) : 0}ms
                        </p>
                      </>
                    )}
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Tier Comparison Chart */}
          <Card className="bg-kong-surface">
            <CardHeader>
              <CardTitle className="text-kong-silver text-sm flex items-center gap-2">
                <Activity className="h-4 w-4" />
                Tier Performance Comparison
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={tierComparisonData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#2a3037" />
                  <XAxis dataKey="name" stroke="#aeb4bd" style={{ fontSize: '12px' }} />
                  <YAxis stroke="#aeb4bd" style={{ fontSize: '12px' }} />
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: '#171a1f',
                      border: '1px solid #2a3037',
                      borderRadius: '8px'
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px' }} />
                  <Bar dataKey="requests" fill="#4a9eff" name="Total Requests" />
                  <Bar dataKey="blocked" fill="#44ff44" name="Blocked" />
                  <Bar dataKey="vulnerable" fill="#ff4444" name="Vulnerable" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Detection Rate Chart */}
          <Card className="bg-kong-surface">
            <CardHeader>
              <CardTitle className="text-kong-silver text-sm flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                AI Detection Effectiveness
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={detectionRateData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={(entry: any) => `${entry.name}: ${entry.rate.toFixed(1)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="rate"
                  >
                    {detectionRateData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index + 1]} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: '#171a1f',
                      border: '1px solid #2a3037',
                      borderRadius: '8px'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>

        {/* Attack Results Table */}
        <Card className="bg-kong-surface">
          <CardHeader>
            <CardTitle className="text-kong-silver text-sm">Live Attack Test Results</CardTitle>
            <p className="text-xs text-muted-foreground">
              Real-time comparison of protection effectiveness across all tiers
            </p>
          </CardHeader>
          <CardContent>
            {Object.keys(data.attackResults).length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-kong-steel text-xs">Attack Type</TableHead>
                    <TableHead className="text-kong-critical text-xs">Unprotected</TableHead>
                    <TableHead className="text-kong-steel text-xs">Cloud AI</TableHead>
                    <TableHead className="text-kong-normal text-xs">Local AI</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {Object.entries(data.attackResults).map(([attackType, results]) => (
                    <TableRow key={attackType}>
                      <TableCell className="font-medium text-kong-silver text-xs capitalize">
                        {attackType.replace(/_/g, ' ')}
                      </TableCell>
                      {protectionTiers.map((tier) => {
                        const result = results[tier.id]
                        if (!result) {
                          return <TableCell key={tier.id} className="text-muted-foreground text-xs">-</TableCell>
                        }

                        const status = result.recommended_action === 'block' ? 'BLOCKED' :
                                     result.recommended_action === 'monitor' ? 'MONITORED' :
                                     tier.id === 'unprotected' ? 'VULNERABLE' : 'ALLOWED'

                        const colorClass = result.recommended_action === 'block' ? 'text-kong-critical' :
                                          result.recommended_action === 'monitor' ? 'text-kong-caution' :
                                          tier.id === 'unprotected' ? 'text-kong-critical' : 'text-kong-normal'

                        return (
                          <TableCell key={tier.id} className={`${colorClass} text-xs`}>
                            <div className="flex flex-col">
                              <span className="font-medium">{status}</span>
                              <span className="text-xs opacity-75">
                                {(result.threat_score * 100).toFixed(0)}% threat
                              </span>
                            </div>
                          </TableCell>
                        )
                      })}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="text-center py-12 text-muted-foreground">
                <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p className="text-sm">No attack tests run yet</p>
                <p className="text-xs mt-2">Use the control panel to launch attack tests</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
