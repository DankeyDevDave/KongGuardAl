// src/lib/kongGuard.ts — tiny client (fetch version)
const BASE = (import.meta as any).env.VITE_KONG_BASE || '';

async function get<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, { ...init, headers: {Accept:'application/json', ...(init?.headers||{})}});
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getHealth() { return get('/kong-guard-ai/health'); }
export async function getAnalyticsSummary(period='24h', group_by='hour') {
  return get(`/kong-guard-ai/analytics/summary?period=${period}&group_by=${group_by}`);
}
export async function listThreats(limit=50) {
  return get(`/kong-guard-ai/threats?limit=${limit}`);
}
export async function getThreatDetails(id: string) {
  return get(`/kong-guard-ai/threats/${id}`);
}
export async function getMetricsRaw(): Promise<string> {
  const res = await fetch(BASE + '/kong-guard-ai/metrics', { headers: {Accept: 'text/plain'} });
  if (!res.ok) throw new Error(await res.text());
  return res.text();
}
