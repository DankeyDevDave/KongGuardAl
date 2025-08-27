// src/components/Dashboard.tsx — React variant using fetch
import React, { useEffect, useState } from 'react';
import './kongguard.css';

type ThreatEvent = {
  id: string; timestamp: string; threat_level: number; threat_type: string;
  client_ip: string; request_method: string; request_path: string;
  action_taken: string; confidence: number;
};
type Summary = {
  total_requests: number; total_threats: number;
  response_actions?: { blocked: number; rate_limited: number; };
  average_processing_time?: number; ai_accuracy?: number; avg_confidence?: number;
};

const BASE = (import.meta as any).env.VITE_KONG_BASE || '';

const dotClass = (lvl: number) => lvl >= 80 ? 'dot-critical' : (lvl >= 50 ? 'dot-caution' : 'dot-normal');

export default function Dashboard() {
  const [status, setStatus] = useState('Connecting…');
  const [sum, setSum] = useState<Summary | null>(null);
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [detail, setDetail] = useState<any>(null);

  useEffect(() => {
    (async () => {
      try {
        const h = await fetch(BASE + '/kong-guard-ai/health').then(r => r.json());
        setStatus((h.status === 'healthy' ? 'Connected' : 'Degraded') + (h.version ? ' • v'+h.version : ''));
      } catch { setStatus('Offline'); }

      try {
        const a = await fetch(BASE + '/kong-guard-ai/analytics/summary?period=24h&group_by=hour').then(r => r.json());
        setSum(a);
      } catch {}

      try {
        const l = await fetch(BASE + '/kong-guard-ai/threats?limit=20').then(r => r.json());
        setEvents(l.threats || []);
        if (l.threats?.[0]) {
          const d = await fetch(BASE + '/kong-guard-ai/threats/' + l.threats[0].id).then(r => r.json());
          setDetail(d);
        }
      } catch {}
    })();
  }, []);

  return (
    <div>
      <div className="topbar card">
        <div className="brand">
          <img src="/static/brand/kongguard-mark-silver.svg" alt="KongGuard AI" onError={(e)=>{(e.target as HTMLImageElement).style.display='none'}} />
          <h1>KongGuard AI</h1>
        </div>
        <div className="status">{status}</div>
      </div>

      <div className="container">
        <section className="grid kpis">
          <div className="kpi"><div className="label">Total Analyzed</div><div className="value">{sum?.total_requests ?? 0}</div></div>
          <div className="kpi"><div className="label">Attacks Blocked</div><div className="value">{sum?.response_actions?.blocked ?? 0}</div></div>
          <div className="kpi"><div className="label">Avg Confidence</div><div className="value">{sum?.avg_confidence ?? 0}%</div></div>
          <div className="kpi"><div className="label">Avg Processing</div><div className="value">{sum?.average_processing_time ?? 0}ms</div></div>
          <div className="kpi"><div className="label">AI Accuracy</div><div className="value">{sum?.ai_accuracy?.toFixed?.(1) ?? '—'}%</div></div>
        </section>

        <section className="grid panels">
          <div className="card panel">
            <div className="panel-title">Current AI Analysis</div>
            <hr className="hr" />
            <div className="progress"><div className="bar" style={{ width: (detail?.confidence || 0) + '%' }} /></div>
            <div className="subcards" style={{ marginTop: 12 }}>
              <div className="subcard">
                <div className="sub-label">AI Reasoning</div>
                <div style={{ fontSize: 14, color: 'var(--txt-muted)' }}>{detail?.ai_analysis?.result || '—'}</div>
              </div>
              <div className="subcard">
                <div className="sub-label">Threat Indicators</div>
                <div style={{ fontSize: 14, color: 'var(--txt-muted)' }}>{(detail?.pattern_matches || []).map((p:any)=>p.pattern).join(', ') || 'None detected'}</div>
              </div>
              <div className="subcard">
                <div className="sub-label">Recommendation</div>
                <div style={{ fontSize: 14, color: 'var(--txt-muted)' }}>{detail?.action_taken || '—'}</div>
              </div>
            </div>
          </div>

          <div className="card panel">
            <div className="panel-title">Test Attacks</div>
            <hr className="hr" />
            <div className="list">
              <div className="list-item critical"><span className="name">SQL Injection</span><span className="meta">/api/v1/login</span></div>
              <div className="list-item caution"><span className="name">XSS</span><span className="meta">/search</span></div>
              <div className="list-item caution"><span className="name">Path Traversal</span><span className="meta">/files</span></div>
              <div className="list-item normal"><span className="name">Normal Traffic</span><span className="meta">baseline</span></div>
            </div>
          </div>
        </section>

        <div className="card panel" style={{ marginTop: 14 }}>
          <div className="panel-title">Recent Analysis</div>
          <hr className="hr" />
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Time</th><th>Path</th><th>Verdict</th><th>Action</th></tr></thead>
              <tbody>
                {events.length === 0 && (
                  <tr><td colSpan={4} style={{ color: 'var(--txt-subtle)' }}>No analysis yet</td></tr>
                )}
                {events.map(e => (
                  <tr key={e.id}>
                    <td>{new Date(e.timestamp).toLocaleTimeString()}</td>
                    <td>{e.request_path || e.request_method}</td>
                    <td><span className={`status-dot ${dotClass(e.threat_level)}`}></span>{e.threat_type || '—'}</td>
                    <td>{e.action_taken || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="footer-note">© KongGuard AI</div>
      </div>
    </div>
  );
}
