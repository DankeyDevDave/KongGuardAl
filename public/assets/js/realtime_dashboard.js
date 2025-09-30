/**
 * Kong Guard AI - Real-time Dashboard Integration
 * Supports both WebSocket (SQLite) and Supabase Real-time subscriptions
 */

class RealtimeDashboard {
    constructor(config = {}) {
        this.config = {
            // Database type: 'sqlite' or 'supabase'
            dbType: config.dbType || 'sqlite',

            // WebSocket configuration (for SQLite)
            websocketUrl: config.websocketUrl || 'ws://localhost:8000/ws',

            // Supabase configuration
            supabaseUrl: config.supabaseUrl,
            supabaseKey: config.supabaseKey,

            // Dashboard update settings
            updateInterval: config.updateInterval || 1000, // ms
            maxDataPoints: config.maxDataPoints || 100,

            ...config
        };

        this.isConnected = false;
        this.subscriptions = new Map();
        this.dataBuffer = new Map();
        this.eventHandlers = new Map();

        this.init();
    }

    async init() {
        console.log(`🚀 Initializing Kong Guard AI Real-time Dashboard (${this.config.dbType})`);

        if (this.config.dbType === 'supabase' && this.config.supabaseUrl) {
            await this.initSupabaseConnection();
        } else {
            await this.initWebSocketConnection();
        }
    }

    // ==========================================
    // SUPABASE REAL-TIME CONNECTION
    // ==========================================

    async initSupabaseConnection() {
        try {
            // Import Supabase client (assumes it's loaded)
            const { createClient } = window.supabase || require('@supabase/supabase-js');

            this.supabase = createClient(this.config.supabaseUrl, this.config.supabaseKey);

            console.log('✅ Connected to self-hosted Supabase');
            this.isConnected = true;

            // Set up real-time subscriptions
            this.setupSupabaseSubscriptions();

        } catch (error) {
            console.error('❌ Supabase connection failed:', error);
            this.fallbackToWebSocket();
        }
    }

    setupSupabaseSubscriptions() {
        // Subscribe to attack runs
        const attackRunsChannel = this.supabase
            .channel('attack-runs-changes')
            .on('postgres_changes', {
                event: '*',
                schema: 'public',
                table: 'attack_runs'
            }, (payload) => {
                this.handleAttackRunChange(payload);
            })
            .subscribe();

        this.subscriptions.set('attack_runs', attackRunsChannel);

        // Subscribe to attack metrics (for real-time stats)
        const metricsChannel = this.supabase
            .channel('attack-metrics-changes')
            .on('postgres_changes', {
                event: 'INSERT',
                schema: 'public',
                table: 'attack_metrics'
            }, (payload) => {
                this.handleAttackMetricInsert(payload);
            })
            .subscribe();

        this.subscriptions.set('attack_metrics', metricsChannel);

        // Subscribe to tier statistics updates
        const statsChannel = this.supabase
            .channel('tier-stats-changes')
            .on('postgres_changes', {
                event: '*',
                schema: 'public',
                table: 'tier_statistics'
            }, (payload) => {
                this.handleTierStatsChange(payload);
            })
            .subscribe();

        this.subscriptions.set('tier_statistics', statsChannel);

        console.log('📡 Supabase real-time subscriptions active');
    }

    // ==========================================
    // WEBSOCKET CONNECTION (SQLite FALLBACK)
    // ==========================================

    async initWebSocketConnection() {
        try {
            this.websocket = new WebSocket(this.config.websocketUrl);

            this.websocket.onopen = () => {
                console.log('✅ WebSocket connected to Kong Guard AI service');
                this.isConnected = true;
                this.emit('connected');
            };

            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('❌ WebSocket message parsing error:', error);
                }
            };

            this.websocket.onclose = () => {
                console.log('🔌 WebSocket connection closed');
                this.isConnected = false;
                this.emit('disconnected');

                // Attempt reconnection
                setTimeout(() => {
                    console.log('🔄 Attempting WebSocket reconnection...');
                    this.initWebSocketConnection();
                }, 5000);
            };

            this.websocket.onerror = (error) => {
                console.error('❌ WebSocket error:', error);
            };

        } catch (error) {
            console.error('❌ WebSocket connection failed:', error);
        }
    }

    // ==========================================
    // DATA HANDLERS
    // ==========================================

    handleAttackRunChange(payload) {
        console.log('📊 Attack run update:', payload);

        const { eventType, new: newRecord, old: oldRecord } = payload;

        switch (eventType) {
            case 'INSERT':
                this.emit('attackRunStarted', newRecord);
                break;
            case 'UPDATE':
                this.emit('attackRunUpdated', newRecord);
                if (newRecord.end_time && !oldRecord.end_time) {
                    this.emit('attackRunCompleted', newRecord);
                }
                break;
            case 'DELETE':
                this.emit('attackRunDeleted', oldRecord);
                break;
        }
    }

    handleAttackMetricInsert(payload) {
        const metric = payload.new;

        // Buffer metrics for batch processing
        const runId = metric.run_id;
        if (!this.dataBuffer.has(runId)) {
            this.dataBuffer.set(runId, []);
        }

        this.dataBuffer.get(runId).push(metric);

        // Emit real-time metric update
        this.emit('attackMetric', metric);

        // Process buffered metrics periodically
        this.processMetricsBuffer(runId);
    }

    handleTierStatsChange(payload) {
        console.log('📈 Tier statistics update:', payload);
        this.emit('tierStatsUpdated', payload.new);
    }

    handleWebSocketMessage(data) {
        console.log('📨 WebSocket message:', data);

        switch (data.type) {
            case 'attack_flood_started':
                this.emit('attackRunStarted', data);
                break;
            case 'attack_flood_progress':
                this.emit('attackProgress', data);
                break;
            case 'attack_flood_completed':
                this.emit('attackRunCompleted', data);
                break;
            case 'attack_metric':
                this.handleAttackMetricInsert({ new: data.metric });
                break;
            case 'tier_statistics':
                this.emit('tierStatsUpdated', data.stats);
                break;
            default:
                console.log('🔍 Unknown WebSocket message type:', data.type);
        }
    }

    // ==========================================
    // METRICS PROCESSING
    // ==========================================

    processMetricsBuffer(runId) {
        const buffer = this.dataBuffer.get(runId);
        if (!buffer || buffer.length === 0) return;

        // Calculate real-time statistics
        const stats = this.calculateRealTimeStats(buffer);

        // Emit updates
        this.emit('realTimeStats', {
            runId: runId,
            totalAttacks: buffer.length,
            stats: stats,
            latestMetrics: buffer.slice(-10) // Last 10 attacks
        });

        // Keep buffer size manageable
        if (buffer.length > this.config.maxDataPoints) {
            buffer.splice(0, buffer.length - this.config.maxDataPoints);
        }
    }

    calculateRealTimeStats(metrics) {
        if (metrics.length === 0) return {};

        const byTier = {};

        metrics.forEach(metric => {
            if (!byTier[metric.tier]) {
                byTier[metric.tier] = {
                    total: 0,
                    blocked: 0,
                    totalResponseTime: 0,
                    minResponseTime: Infinity,
                    maxResponseTime: -Infinity
                };
            }

            const tier = byTier[metric.tier];
            tier.total++;
            if (metric.blocked) tier.blocked++;
            tier.totalResponseTime += metric.response_time_ms;
            tier.minResponseTime = Math.min(tier.minResponseTime, metric.response_time_ms);
            tier.maxResponseTime = Math.max(tier.maxResponseTime, metric.response_time_ms);
        });

        // Calculate final statistics
        Object.keys(byTier).forEach(tier => {
            const stats = byTier[tier];
            stats.detectionRate = (stats.blocked / stats.total) * 100;
            stats.avgResponseTime = stats.totalResponseTime / stats.total;
            stats.successRate = ((stats.total - stats.blocked) / stats.total) * 100;
        });

        return byTier;
    }

    // ==========================================
    // EVENT SYSTEM
    // ==========================================

    on(event, handler) {
        if (!this.eventHandlers.has(event)) {
            this.eventHandlers.set(event, []);
        }
        this.eventHandlers.get(event).push(handler);
    }

    off(event, handler) {
        const handlers = this.eventHandlers.get(event);
        if (handlers) {
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        }
    }

    emit(event, data) {
        const handlers = this.eventHandlers.get(event);
        if (handlers) {
            handlers.forEach(handler => {
                try {
                    handler(data);
                } catch (error) {
                    console.error(`❌ Event handler error (${event}):`, error);
                }
            });
        }
    }

    // ==========================================
    // API METHODS
    // ==========================================

    async getAttackRuns(limit = 50) {
        if (this.config.dbType === 'supabase' && this.supabase) {
            const { data, error } = await this.supabase
                .from('attack_runs')
                .select('*')
                .order('start_time', { ascending: false })
                .limit(limit);

            if (error) throw error;
            return data;
        } else {
            // Fallback to REST API
            const response = await fetch('/api/attack/runs');
            return await response.json();
        }
    }

    async getRunStatistics(runId) {
        if (this.config.dbType === 'supabase' && this.supabase) {
            // Get run data
            const { data: runData, error: runError } = await this.supabase
                .from('attack_runs')
                .select('*')
                .eq('run_id', runId)
                .single();

            if (runError) throw runError;

            // Get tier statistics
            const { data: tierStats, error: statsError } = await this.supabase
                .from('tier_statistics')
                .select('*')
                .eq('run_id', runId);

            if (statsError) throw statsError;

            return {
                ...runData,
                tierStatistics: tierStats
            };
        } else {
            // Fallback to REST API
            const response = await fetch(`/api/attack/runs/${runId}/stats`);
            return await response.json();
        }
    }

    async startAttackFlood(config) {
        const response = await fetch('/api/attack/flood', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (!response.ok) {
            throw new Error(`Attack flood failed: ${response.statusText}`);
        }

        return await response.json();
    }

    // ==========================================
    // CLEANUP
    // ==========================================

    disconnect() {
        console.log('🔌 Disconnecting Kong Guard AI Real-time Dashboard');

        // Close Supabase subscriptions
        this.subscriptions.forEach((subscription, key) => {
            if (this.config.dbType === 'supabase') {
                subscription.unsubscribe();
            }
            console.log(`📡 Unsubscribed from ${key}`);
        });

        // Close WebSocket
        if (this.websocket) {
            this.websocket.close();
        }

        this.isConnected = false;
        this.subscriptions.clear();
        this.dataBuffer.clear();
    }
}

// ==========================================
// DASHBOARD UI INTEGRATION HELPERS
// ==========================================

class DashboardUI {
    constructor(realtimeDashboard) {
        this.dashboard = realtimeDashboard;
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        // Attack run events
        this.dashboard.on('attackRunStarted', (run) => {
            this.updateAttackStatus('ACTIVE', `Attack Run ${run.run_id} Started`);
            this.showNotification(`🚀 Attack flood started (${run.intensity_level} intensity)`, 'info');
        });

        this.dashboard.on('attackRunCompleted', (run) => {
            this.updateAttackStatus('COMPLETED', `Attack Run ${run.run_id} Completed`);
            this.showNotification(`✅ Attack flood completed (${run.total_attacks} attacks)`, 'success');
            this.refreshDashboardData();
        });

        // Real-time metrics
        this.dashboard.on('realTimeStats', (data) => {
            this.updateRealTimeCharts(data.stats);
            this.updateAttackCounter(data.totalAttacks);
        });

        // Connection status
        this.dashboard.on('connected', () => {
            this.updateConnectionStatus(true);
        });

        this.dashboard.on('disconnected', () => {
            this.updateConnectionStatus(false);
        });
    }

    updateAttackStatus(status, message) {
        const statusElement = document.getElementById('attackStatus');
        if (statusElement) {
            statusElement.textContent = message;
            statusElement.className = `status ${status.toLowerCase()}`;
        }
    }

    updateConnectionStatus(connected) {
        const indicator = document.getElementById('connectionIndicator');
        if (indicator) {
            indicator.className = connected ? 'connected' : 'disconnected';
            indicator.title = connected ? 'Real-time connected' : 'Real-time disconnected';
        }
    }

    updateRealTimeCharts(stats) {
        // Update Chart.js charts with real-time data
        Object.keys(stats).forEach(tier => {
            const tierStats = stats[tier];
            this.updateTierChart(tier, tierStats);
        });
    }

    updateTierChart(tier, stats) {
        // Implementation depends on your Chart.js setup
        console.log(`📊 Updating ${tier} chart:`, stats);
    }

    updateAttackCounter(count) {
        const counter = document.getElementById('attackCounter');
        if (counter) {
            counter.textContent = count.toLocaleString();
        }
    }

    showNotification(message, type = 'info') {
        // Create a simple notification system
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;

        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 5000);
    }

    async refreshDashboardData() {
        try {
            const runs = await this.dashboard.getAttackRuns(10);
            this.updateRunsTable(runs);
        } catch (error) {
            console.error('❌ Failed to refresh dashboard data:', error);
        }
    }

    updateRunsTable(runs) {
        // Update the runs table/list in the UI
        console.log('📋 Updating runs table with', runs.length, 'runs');
    }
}

// ==========================================
// USAGE EXAMPLE
// ==========================================

// Auto-detect configuration and initialize
function initializeRealtimeDashboard() {
    // Check if Supabase configuration is available
    const supabaseUrl = window.SUPABASE_URL || localStorage.getItem('supabaseUrl');
    const supabaseKey = window.SUPABASE_KEY || localStorage.getItem('supabaseKey');

    const config = {
        dbType: (supabaseUrl && supabaseKey) ? 'supabase' : 'sqlite',
        supabaseUrl: supabaseUrl,
        supabaseKey: supabaseKey,
        websocketUrl: 'ws://localhost:8000/ws',
        updateInterval: 1000,
        maxDataPoints: 500
    };

    // Initialize dashboard
    const realtimeDashboard = new RealtimeDashboard(config);
    const dashboardUI = new DashboardUI(realtimeDashboard);

    // Make globally available
    window.kongGuardDashboard = realtimeDashboard;
    window.dashboardUI = dashboardUI;

    console.log('🎯 Kong Guard AI Real-time Dashboard initialized');

    return { realtimeDashboard, dashboardUI };
}

// Auto-initialize if in browser environment
if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeRealtimeDashboard);
    } else {
        initializeRealtimeDashboard();
    }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { RealtimeDashboard, DashboardUI, initializeRealtimeDashboard };
}
