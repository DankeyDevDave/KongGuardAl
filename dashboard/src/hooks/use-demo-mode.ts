import { useState, useEffect, useCallback } from 'react'

export type DashboardMode = 'demo' | 'control' | 'hybrid'

interface UseDemoModeOptions {
  defaultMode?: DashboardMode
  enableKeyboardShortcuts?: boolean
}

export function useDemoMode(options: UseDemoModeOptions = {}) {
  const { defaultMode = 'hybrid', enableKeyboardShortcuts = true } = options

  const [mode, setMode] = useState<DashboardMode>(defaultMode)

  // Initialize mode from URL params or localStorage
  useEffect(() => {
    if (typeof window === 'undefined') return

    // Check URL params first
    const params = new URLSearchParams(window.location.search)
    const urlMode = params.get('mode') as DashboardMode | null

    if (urlMode && ['demo', 'control', 'hybrid'].includes(urlMode)) {
      setMode(urlMode)
      return
    }

    // Fall back to localStorage
    const savedMode = localStorage.getItem('kongguard-dashboard-mode') as DashboardMode | null
    if (savedMode && ['demo', 'control', 'hybrid'].includes(savedMode)) {
      setMode(savedMode)
    }
  }, [])

  // Save mode to localStorage when it changes
  useEffect(() => {
    if (typeof window === 'undefined') return
    localStorage.setItem('kongguard-dashboard-mode', mode)
  }, [mode])

  // Cycle through modes
  const cycleMode = useCallback(() => {
    setMode(current => {
      switch (current) {
        case 'demo': return 'control'
        case 'control': return 'hybrid'
        case 'hybrid': return 'demo'
        default: return 'hybrid'
      }
    })
  }, [])

  // Set specific mode
  const setDemoMode = useCallback((newMode: DashboardMode) => {
    if (['demo', 'control', 'hybrid'].includes(newMode)) {
      setMode(newMode)

      // Update URL without page reload
      if (typeof window !== 'undefined') {
        const url = new URL(window.location.href)
        url.searchParams.set('mode', newMode)
        window.history.replaceState({}, '', url.toString())
      }
    }
  }, [])

  // Keyboard shortcuts
  useEffect(() => {
    if (!enableKeyboardShortcuts || typeof window === 'undefined') return

    const handleKeyPress = (e: KeyboardEvent) => {
      // Ctrl+D to cycle modes
      if (e.ctrlKey && e.key === 'd') {
        e.preventDefault()
        cycleMode()
      }

      // Ctrl+Shift+1/2/3 for specific modes
      if (e.ctrlKey && e.shiftKey) {
        if (e.key === '1') {
          e.preventDefault()
          setDemoMode('demo')
        } else if (e.key === '2') {
          e.preventDefault()
          setDemoMode('control')
        } else if (e.key === '3') {
          e.preventDefault()
          setDemoMode('hybrid')
        }
      }
    }

    window.addEventListener('keydown', handleKeyPress)
    return () => window.removeEventListener('keydown', handleKeyPress)
  }, [enableKeyboardShortcuts, cycleMode, setDemoMode])

  // Helper functions for conditional rendering
  const showControls = mode === 'control' || mode === 'hybrid'
  const showVisualization = true // Always shown
  const isFullWidth = mode === 'demo'
  const isDemoRecording = typeof window !== 'undefined' &&
    new URLSearchParams(window.location.search).get('recording') === 'true'

  return {
    mode,
    setMode: setDemoMode,
    cycleMode,
    showControls,
    showVisualization,
    isFullWidth,
    isDemoRecording,
    isDemo: mode === 'demo',
    isControl: mode === 'control',
    isHybrid: mode === 'hybrid'
  }
}
