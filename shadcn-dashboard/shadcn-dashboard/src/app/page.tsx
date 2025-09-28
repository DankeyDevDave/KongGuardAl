"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Label } from "@/components/ui/label"
import { Shield, Activity, AlertTriangle, BarChart3, Target, Zap, Eye, ShieldCheck, Wifi, WifiOff } from "lucide-react"
import { useRealtimeDashboard } from "@/hooks/useRealtimeDashboard"

export default function KongGuardDashboard() {
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [isAttackActive, setIsAttackActive] = useState(false)
  const [attackProgress, setAttackProgress] = useState(0)
  const [attackIntensity, setAttackIntensity] = useState("medium")
  const [attackStrategy, setAttackStrategy] = useState("sustained")
  const [attackDuration, setAttackDuration] = useState(60)

  // Use the real-time dashboard hook
  const { data, testAttack, launchAttackFlood, isConnected } = useRealtimeDashboard({
    websocketUrl: 'ws://localhost:8000/ws',
    apiBaseUrls: {
      unprotected: 'http://localhost:8000',
      cloud: 'http://localhost:18002',
      local: 'http://localhost:18003'
    }
  })

  // Apply dark mode on mount
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [isDarkMode])

  const protectionTiers = [
    {
      id: 'unprotected',
      title: 'Unprotected Kong Gateway',
      description: 'Raw Kong Gateway with No AI Protection',
      icon: AlertTriangle,
      status: 'online',
      statusColor: 'text-kong-critical',
      borderColor: 'border-kong-critical',
    },
    {
      id: 'cloud',
      title: 'Cloud AI Protection',
      description: 'Kong + Guard AI with Gemini/GPT Analysis',
      icon: Shield,
      status: 'online',
      statusColor: 'text-kong-steel',
      borderColor: 'border-kong-steel',
    },
    {
      id: 'local',
      title: 'Local AI Protection',
      description: 'Kong + Guard AI with Private Mistral/Llama',
      icon: ShieldCheck,
      status: 'online',
      statusColor: 'text-kong-normal',
      borderColor: 'border-kong-normal',
    },
  ]

  const attackTypes = [
    { id: 'sql', name: 'SQL Injection', icon: Target },
    { id: 'xss', name: 'XSS Attack', icon: Zap },
    { id: 'cmd_injection', name: 'Command Injection', icon: AlertTriangle },
    { id: 'path', name: 'Path Traversal', icon: Eye },
    { id: 'ldap_injection', name: 'LDAP Injection', icon: Target },
    { id: 'business_logic', name: 'Business Logic Attack', icon: BarChart3 },
    { id: 'ransomware', name: 'Ransomware C2', icon: AlertTriangle },
    { id: 'normal', name: 'Normal Traffic', icon: Activity },
  ]

  const handleAttackTest = async (attackType: string, tier: string) => {
    try {
      await testAttack(attackType, tier)
    } catch (error) {
      console.error('Attack test failed:', error)
    }
  }

  const handleAttackFlood = async () => {
    try {
      setIsAttackActive(true)
      setAttackProgress(0)

      // Simulate attack progress (replace with real progress updates from WebSocket)
      const interval = setInterval(() => {
        setAttackProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval)
            setIsAttackActive(false)
            return 100
          }
          return prev + 2
        })
      }, 100)

      // Launch the actual attack flood
      await launchAttackFlood({
        intensity: attackIntensity,
        strategy: attackStrategy,
        duration: attackDuration,
        targets: ['unprotected', 'cloud', 'local']
      })

    } catch (error) {
      console.error('Attack flood failed:', error)
      setIsAttackActive(false)
      setAttackProgress(0)
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="border-b border-border bg-kong-surface">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <img
                src="/kong-guard-ai-logo.webp"
                alt="Kong Guard AI"
                className="h-12 w-auto"
                style={{filter: 'brightness(1.1) contrast(1.1)'}}
              />
              <div>
                <p className="text-sm text-muted-foreground">Enterprise Three-Tier Protection Dashboard</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant="outline" className={`${isConnected ? 'text-kong-normal border-kong-normal' : 'text-kong-critical border-kong-critical'}`}>
                {isConnected ? (
                  <>
                    <Wifi className="h-3 w-3 mr-1" />
                    Real-time Active
                  </>
                ) : (
                  <>
                    <WifiOff className="h-3 w-3 mr-1" />
                    Disconnected
                  </>
                )}
              </Badge>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsDarkMode(!isDarkMode)}
              >
                {isDarkMode ? 'Light' : 'Dark'} Mode
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-6">
        {/* Protection Tiers Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {protectionTiers.map((tier) => {
            const tierMetrics = data.metrics[tier.id as keyof typeof data.metrics]
            const Icon = tier.icon

            return (
              <Card key={tier.id} className={`${tier.borderColor} border-2 bg-kong-surface`}>
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center space-x-2">
                    <Icon className={`h-5 w-5 ${tier.statusColor}`} />
                    <span className="text-kong-silver">{tier.title}</span>
                  </CardTitle>
                  <p className="text-sm text-muted-foreground">{tier.description}</p>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Status:</span>
                      <Badge variant="outline" className={`${tier.statusColor} border-current`}>
                        {tier.status}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Requests:</span>
                      <span className="text-kong-silver font-medium">{tierMetrics.total}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Blocked:</span>
                      <span className="text-kong-silver font-medium">{tierMetrics.blocked}</span>
                    </div>
                    {tier.id === 'unprotected' ? (
                      <>
                        <div className="flex justify-between">
                          <span className="text-sm text-muted-foreground">Vulnerable:</span>
                          <span className="text-kong-critical font-medium">{tierMetrics.vulnerable}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm text-muted-foreground">Success Rate:</span>
                          <span className="text-kong-silver font-medium">{tierMetrics.successRate.toFixed(1)}%</span>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="flex justify-between">
                          <span className="text-sm text-muted-foreground">Detection:</span>
                          <span className="text-kong-normal font-medium">{tierMetrics.detectionRate.toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm text-muted-foreground">Avg Response:</span>
                          <span className="text-kong-silver font-medium">
                            {tierMetrics.total > 0 ? (tierMetrics.totalTime / tierMetrics.total).toFixed(0) : 0}ms
                          </span>
                        </div>
                      </>
                    )}
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Attack Testing Interface */}
        <Card className="mb-8 bg-kong-surface">
          <CardHeader>
            <CardTitle className="text-kong-silver">Enterprise Attack Scenarios</CardTitle>
            <p className="text-muted-foreground">
              Click any attack type to test against all three protection tiers simultaneously
            </p>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {attackTypes.map((attack) => {
                const Icon = attack.icon
                return (
                  <Card key={attack.id} className="bg-background">
                    <CardHeader className="pb-2">
                      <CardTitle className="flex items-center space-x-2 text-sm">
                        <Icon className="h-4 w-4 text-kong-steel" />
                        <span>{attack.name}</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {protectionTiers.map((tier) => (
                          <Button
                            key={`${attack.id}-${tier.id}`}
                            variant="outline"
                            size="sm"
                            className={`w-full justify-start ${tier.borderColor} border-l-4`}
                            onClick={() => handleAttackTest(attack.id, tier.id)}
                          >
                            Test {tier.id === 'unprotected' ? 'Unprotected' : tier.id === 'cloud' ? 'Cloud AI' : 'Local AI'}
                          </Button>
                        ))}

                        {/* Show results if available */}
                        {data.attackResults[attack.id] && (
                          <div className="mt-2 p-2 bg-muted rounded text-xs">
                            {Object.entries(data.attackResults[attack.id]).map(([tier, result]) => (
                              <div key={tier} className="flex justify-between">
                                <span className="capitalize">{tier}:</span>
                                <span className={
                                  result.recommended_action === 'block' ? 'text-kong-critical' :
                                  result.recommended_action === 'monitor' ? 'text-kong-caution' :
                                  tier === 'unprotected' ? 'text-kong-critical' : 'text-kong-normal'
                                }>
                                  {result.recommended_action === 'block' ? 'BLOCKED' :
                                   result.recommended_action === 'monitor' ? 'MONITORED' :
                                   tier === 'unprotected' ? 'VULNERABLE' : 'ALLOWED'}
                                  ({(result.threat_score * 100).toFixed(0)}%)
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </CardContent>
        </Card>

        {/* Attack Flood Control */}
        <Card className="mb-8 bg-kong-surface border-kong-critical">
          <CardHeader>
            <CardTitle className="text-kong-critical">Penetration Testing Control</CardTitle>
            <p className="text-muted-foreground">
              Configure and launch simulated attack floods for comprehensive testing
            </p>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
              <div>
                <Label htmlFor="intensity">Attack Intensity</Label>
                <Select value={attackIntensity} onValueChange={setAttackIntensity}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low (10 req/s)</SelectItem>
                    <SelectItem value="medium">Medium (50 req/s)</SelectItem>
                    <SelectItem value="high">High (200 req/s)</SelectItem>
                    <SelectItem value="extreme">EXTREME (1000+ req/s)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="strategy">Attack Strategy</Label>
                <Select value={attackStrategy} onValueChange={setAttackStrategy}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sustained">Sustained Pressure</SelectItem>
                    <SelectItem value="wave">Wave Attacks</SelectItem>
                    <SelectItem value="stealth">Stealth Mode</SelectItem>
                    <SelectItem value="blended">Blended Traffic</SelectItem>
                    <SelectItem value="escalation">Escalation Mode</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="duration">Duration (seconds)</Label>
                <Input
                  type="number"
                  value={attackDuration}
                  onChange={(e) => setAttackDuration(parseInt(e.target.value))}
                  min="10"
                  max="300"
                />
              </div>

              <div className="flex items-end">
                <Button
                  className="w-full bg-kong-critical hover:bg-kong-critical/80"
                  disabled={isAttackActive}
                  onClick={handleAttackFlood}
                >
                  {isAttackActive ? 'ATTACK ACTIVE' : 'LAUNCH ATTACK FLOOD'}
                </Button>
              </div>
            </div>

            {isAttackActive && (
              <div className="space-y-2">
                <Progress value={attackProgress} className="w-full" />
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Attack flood in progress... {attackProgress.toFixed(0)}% complete
                  </AlertDescription>
                </Alert>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Comparison Matrix */}
        <Card className="bg-kong-surface">
          <CardHeader>
            <CardTitle className="text-kong-silver">Live Comparison Matrix</CardTitle>
            <p className="text-muted-foreground">
              Real-time comparison of protection effectiveness across all tiers
            </p>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-kong-steel">Attack Type</TableHead>
                  <TableHead className="text-kong-critical">Unprotected</TableHead>
                  <TableHead className="text-kong-steel">Cloud AI</TableHead>
                  <TableHead className="text-kong-normal">Local AI</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {attackTypes.map((attack) => (
                  <TableRow key={attack.id}>
                    <TableCell className="font-medium text-kong-silver">{attack.name}</TableCell>
                    {protectionTiers.map((tier) => {
                      const result = data.attackResults[attack.id]?.[tier.id]
                      if (!result) {
                        return <TableCell key={tier.id} className="text-muted-foreground">-</TableCell>
                      }

                      const status = result.recommended_action === 'block' ? 'BLOCKED' :
                                   result.recommended_action === 'monitor' ? 'MONITORED' :
                                   tier.id === 'unprotected' ? 'VULNERABLE' : 'ALLOWED'

                      const colorClass = result.recommended_action === 'block' ? 'text-kong-critical' :
                                        result.recommended_action === 'monitor' ? 'text-kong-caution' :
                                        tier.id === 'unprotected' ? 'text-kong-critical' : 'text-kong-normal'

                      return (
                        <TableCell key={tier.id} className={colorClass}>
                          {status}<br />
                          <small>({(result.threat_score * 100).toFixed(0)}%)</small>
                        </TableCell>
                      )
                    })}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {Object.keys(data.attackResults).length === 0 && (
              <div className="text-center py-8 text-muted-foreground">
                Click attack buttons above to populate comparison data...
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
