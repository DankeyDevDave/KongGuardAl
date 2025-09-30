import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { Eye, Settings, Layers } from "lucide-react"
import { DashboardMode } from "@/hooks/use-demo-mode"

interface ModeToggleProps {
  currentMode: DashboardMode
  onModeChange: (mode: DashboardMode) => void
  className?: string
}

export function ModeToggle({ currentMode, onModeChange, className = "" }: ModeToggleProps) {
  const modes = [
    {
      id: 'demo' as DashboardMode,
      label: 'Demo',
      icon: Eye,
      description: 'Clean presentation view for recordings',
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10 border-blue-500/50'
    },
    {
      id: 'control' as DashboardMode,
      label: 'Control',
      icon: Settings,
      description: 'Full testing and management tools',
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10 border-orange-500/50'
    },
    {
      id: 'hybrid' as DashboardMode,
      label: 'Hybrid',
      icon: Layers,
      description: 'Both demo and control features',
      color: 'text-purple-400',
      bgColor: 'bg-purple-500/10 border-purple-500/50'
    }
  ]

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <span className="text-sm text-muted-foreground mr-1">Mode:</span>

      <TooltipProvider>
        <div className="flex gap-1 border border-border rounded-lg p-1 bg-background/50">
          {modes.map((mode) => {
            const Icon = mode.icon
            const isActive = currentMode === mode.id

            return (
              <Tooltip key={mode.id}>
                <TooltipTrigger asChild>
                  <Button
                    variant={isActive ? "default" : "ghost"}
                    size="sm"
                    onClick={() => onModeChange(mode.id)}
                    className={`
                      gap-2 transition-all
                      ${isActive ? `${mode.bgColor} border ${mode.color}` : 'hover:bg-muted'}
                    `}
                  >
                    <Icon className={`h-4 w-4 ${isActive ? mode.color : ''}`} />
                    <span className="hidden sm:inline">{mode.label}</span>
                    {isActive && (
                      <Badge
                        variant="outline"
                        className="ml-1 h-5 px-1.5 text-xs bg-background/50"
                      >
                        Active
                      </Badge>
                    )}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="font-medium">{mode.label} Mode</p>
                  <p className="text-xs text-muted-foreground">{mode.description}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Shortcut: <kbd className="px-1 py-0.5 bg-muted rounded">Ctrl+Shift+{modes.indexOf(mode) + 1}</kbd>
                  </p>
                </TooltipContent>
              </Tooltip>
            )
          })}
        </div>
      </TooltipProvider>

      <Tooltip>
        <TooltipTrigger asChild>
          <Badge variant="outline" className="text-xs cursor-help">
            Ctrl+D
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          <p className="text-xs">Press Ctrl+D to cycle through modes</p>
        </TooltipContent>
      </Tooltip>
    </div>
  )
}
