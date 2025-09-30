import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import {
  Target, Zap, AlertTriangle, Eye, BarChart3, Activity,
  Play, Settings, ChevronLeft, ChevronRight
} from "lucide-react"

interface AttackFloodConfig {
  intensity: string
  strategy: string
  duration: number
  targets: string[]
}

interface ControlPanelProps {
  onTestAttack: (attackType: string, tier: string) => Promise<unknown>
  onLaunchFlood: (config: AttackFloodConfig) => Promise<unknown>
  isCollapsed?: boolean
  onToggleCollapse?: () => void
  className?: string
}

export function ControlPanel({
  onTestAttack,
  onLaunchFlood,
  isCollapsed = false,
  onToggleCollapse,
  className = ""
}: ControlPanelProps) {
  const [isAttackActive, setIsAttackActive] = useState(false)
  const [attackProgress, setAttackProgress] = useState(0)
  const [attackIntensity, setAttackIntensity] = useState("medium")
  const [attackStrategy, setAttackStrategy] = useState("sustained")
  const [attackDuration, setAttackDuration] = useState(60)
  const [selectedTier, setSelectedTier] = useState<string>("cloud")

  const attackTypes = [
    { id: 'sql', name: 'SQL Injection', icon: Target, color: 'text-red-400' },
    { id: 'xss', name: 'XSS Attack', icon: Zap, color: 'text-orange-400' },
    { id: 'cmd_injection', name: 'Command Injection', icon: AlertTriangle, color: 'text-yellow-400' },
    { id: 'path', name: 'Path Traversal', icon: Eye, color: 'text-blue-400' },
    { id: 'ldap_injection', name: 'LDAP Injection', icon: Target, color: 'text-purple-400' },
    { id: 'business_logic', name: 'Business Logic', icon: BarChart3, color: 'text-pink-400' },
    { id: 'ransomware', name: 'Ransomware C2', icon: AlertTriangle, color: 'text-red-500' },
    { id: 'normal', name: 'Normal Traffic', icon: Activity, color: 'text-green-400' },
  ]

  const handleQuickAttack = async (attackType: string) => {
    try {
      await onTestAttack(attackType, selectedTier)
    } catch (error) {
      console.error('Quick attack failed:', error)
    }
  }

  const handleAttackFlood = async () => {
    try {
      setIsAttackActive(true)
      setAttackProgress(0)

      const interval = setInterval(() => {
        setAttackProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval)
            setIsAttackActive(false)
            return 100
          }
          return prev + 2
        })
      }, (attackDuration * 1000) / 50)

      await onLaunchFlood({
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

  if (isCollapsed) {
    return (
      <div className={`bg-kong-surface border-r border-border ${className}`}>
        <div className="p-2 flex flex-col items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={onToggleCollapse}
            className="w-full"
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Separator className="w-full" />
          {attackTypes.slice(0, 4).map((attack) => {
            const Icon = attack.icon
            return (
              <Button
                key={attack.id}
                variant="ghost"
                size="sm"
                className="w-full p-2"
                title={attack.name}
                onClick={() => handleQuickAttack(attack.id)}
              >
                <Icon className={`h-4 w-4 ${attack.color}`} />
              </Button>
            )
          })}
        </div>
      </div>
    )
  }

  return (
    <div className={`w-80 bg-kong-surface border-r border-border overflow-y-auto ${className}`}>
      <div className="p-4 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-kong-silver">Control Panel</h2>
            <p className="text-xs text-muted-foreground">Attack Testing & Simulation</p>
          </div>
          {onToggleCollapse && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onToggleCollapse}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
          )}
        </div>

        <Separator />

        {/* Tier Selection */}
        <div className="space-y-2">
          <Label>Target Tier</Label>
          <Select value={selectedTier} onValueChange={setSelectedTier}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="unprotected">Unprotected Gateway</SelectItem>
              <SelectItem value="cloud">Cloud AI Protection</SelectItem>
              <SelectItem value="local">Local AI Protection</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Quick Attack Buttons */}
        <Card className="bg-background/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Zap className="h-4 w-4 text-kong-steel" />
              Quick Attack Tests
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {attackTypes.map((attack) => {
              const Icon = attack.icon
              return (
                <Button
                  key={attack.id}
                  variant="outline"
                  size="sm"
                  className="w-full justify-start gap-2"
                  onClick={() => handleQuickAttack(attack.id)}
                >
                  <Icon className={`h-4 w-4 ${attack.color}`} />
                  <span className="text-xs">{attack.name}</span>
                </Button>
              )
            })}
          </CardContent>
        </Card>

        <Separator />

        {/* Attack Flood Configuration */}
        <Card className="bg-background/50 border-kong-critical/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-kong-critical">
              <Settings className="h-4 w-4" />
              Attack Flood Control
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label htmlFor="intensity" className="text-xs">Intensity</Label>
              <Select value={attackIntensity} onValueChange={setAttackIntensity}>
                <SelectTrigger className="h-8 text-xs">
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
              <Label htmlFor="strategy" className="text-xs">Strategy</Label>
              <Select value={attackStrategy} onValueChange={setAttackStrategy}>
                <SelectTrigger className="h-8 text-xs">
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
              <Label htmlFor="duration" className="text-xs">Duration (seconds)</Label>
              <Input
                type="number"
                value={attackDuration}
                onChange={(e) => setAttackDuration(parseInt(e.target.value))}
                min="10"
                max="300"
                className="h-8 text-xs"
              />
            </div>

            <Button
              className="w-full bg-kong-critical hover:bg-kong-critical/80 text-white"
              disabled={isAttackActive}
              onClick={handleAttackFlood}
              size="sm"
            >
              <Play className="h-4 w-4 mr-2" />
              {isAttackActive ? 'ATTACK ACTIVE' : 'LAUNCH ATTACK FLOOD'}
            </Button>

            {isAttackActive && (
              <div className="space-y-2">
                <Progress value={attackProgress} className="w-full h-2" />
                <Alert className="py-2">
                  <AlertTriangle className="h-3 w-3" />
                  <AlertDescription className="text-xs">
                    Attack flood in progress... {attackProgress.toFixed(0)}%
                  </AlertDescription>
                </Alert>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Status Info */}
        <div className="pt-2 space-y-1">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Selected Tier:</span>
            <Badge variant="outline" className="text-xs">
              {selectedTier === 'unprotected' ? 'Unprotected' :
               selectedTier === 'cloud' ? 'Cloud AI' : 'Local AI'}
            </Badge>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Status:</span>
            <Badge variant="outline" className={isAttackActive ? 'text-kong-critical' : 'text-kong-normal'}>
              {isAttackActive ? 'Testing' : 'Ready'}
            </Badge>
          </div>
        </div>
      </div>
    </div>
  )
}
