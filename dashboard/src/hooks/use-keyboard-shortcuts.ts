import { useEffect, useState } from 'react'

interface KeyboardShortcut {
  key: string
  ctrlKey?: boolean
  shiftKey?: boolean
  altKey?: boolean
  description: string
  action: () => void
}

export function useKeyboardShortcuts(shortcuts: KeyboardShortcut[]) {
  const [showHelp, setShowHelp] = useState(false)

  useEffect(() => {
    if (typeof window === 'undefined') return

    const handleKeyPress = (e: KeyboardEvent) => {
      // Show help with '?' key
      if (e.key === '?' && !e.ctrlKey && !e.shiftKey && !e.altKey) {
        e.preventDefault()
        setShowHelp(prev => !prev)
        return
      }

      // Check all registered shortcuts
      for (const shortcut of shortcuts) {
        const ctrlMatch = shortcut.ctrlKey ? e.ctrlKey : !e.ctrlKey
        const shiftMatch = shortcut.shiftKey ? e.shiftKey : !e.shiftKey
        const altMatch = shortcut.altKey ? e.altKey : !e.altKey
        const keyMatch = e.key.toLowerCase() === shortcut.key.toLowerCase()

        if (ctrlMatch && shiftMatch && altMatch && keyMatch) {
          e.preventDefault()
          shortcut.action()
          break
        }
      }
    }

    window.addEventListener('keydown', handleKeyPress)
    return () => window.removeEventListener('keydown', handleKeyPress)
  }, [shortcuts])

  return {
    showHelp,
    setShowHelp
  }
}

// Helper to format keyboard shortcut display
export function formatShortcut(shortcut: KeyboardShortcut): string {
  const parts: string[] = []

  if (shortcut.ctrlKey) parts.push('Ctrl')
  if (shortcut.shiftKey) parts.push('Shift')
  if (shortcut.altKey) parts.push('Alt')
  parts.push(shortcut.key.toUpperCase())

  return parts.join(' + ')
}
