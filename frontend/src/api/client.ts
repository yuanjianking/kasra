const API_BASE = '';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }

  // Add API key from localStorage if available
  const apiKey = typeof window !== 'undefined' ? localStorage.getItem('kasra_api_key') : null
  if (apiKey) {
    headers['X-API-Key'] = apiKey
  }

  const res = await fetch(`${API_BASE}${path}`, {
    headers: { ...headers, ...options?.headers as Record<string, string> },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json();
}

// ── Types ──

export interface ScanResult {
  blocked: boolean;
  action: string;
  severity: string;
  triggered_rules: TriggeredRule[];
  warnings: string[];
  execution_time_ms: number;
}

export interface TriggeredRule {
  rule_id: string;
  rule_name: string;
  severity: string;
  action: string;
  match_count: number;
  matched_text: string | null;
  evidence: { source_layer: string; reason: string }[];
}

export interface AuditLogPage {
  items: AuditLogEntry[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  user_id: string | null;
  rule_id: string;
  rule_name: string;
  severity: string;
  action: string;
  direction: string;
  matched_text: string | null;
  file_path: string | null;
  match_count: number;
  status: string;
  metadata: Record<string, unknown> | null;
}

export interface DashboardSummary {
  total_requests_24h: number;
  blocked_count_24h: number;
  warning_count_24h: number;
  total_users_active_24h: number;
  block_rate_percent: number;
  top_triggered_rules: { rule_id: string; rule_name: string; count: number }[];
  top_users: { user_id: string; requests: number; blocks: number }[];
  p0_triggers_24h: number;
  p1_triggers_24h: number;
  p2_triggers_24h: number;
}

export interface DashboardTrend {
  period: string;
  data: { date: string; total: number; blocked: number; warned: number }[];
}

export interface RuleListResponse {
  items: RuleItem[];
  total: number;
}

export interface RuleItem {
  id: string;
  name: string;
  severity: string;
  action: string;
  enabled: boolean;
  is_custom: boolean;
  category: string | null;
}

export interface UserBehaviorPage {
  items: UserBehaviorItem[];
  total: number;
}

export interface UserBehaviorItem {
  user_id: string;
  date: string;
  total_requests: number;
  blocked_requests: number;
  anomaly_score: number;
  warned_requests: number;
  top_triggers: { rule_id: string; count: number }[];
}

// ── API Functions ──

export async function getHealth() {
  return request<{ status: string; rules_loaded: number }>('/health');
}

export async function scanInput(content: string, userId?: string) {
  return request<ScanResult>('/v1/scan/input', {
    method: 'POST',
    body: JSON.stringify({ content, user_id: userId }),
  });
}

export async function getAuditLogs(params: {
  page?: number; page_size?: number; severity?: string;
  direction?: string; rule_id?: string;
}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, String(v)); });
  return request<AuditLogPage>(`/v1/audit/logs?${qs}`);
}

export async function getDashboardSummary() {
  return request<DashboardSummary>('/v1/dashboard/summary');
}

export async function getDashboardTrend(period = '7d') {
  return request<DashboardTrend>(`/v1/dashboard/trend?period=${period}`);
}

export async function getRules(params: { page?: number; page_size?: number; severity?: string }) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, String(v)); });
  return request<RuleListResponse>(`/v1/rules?${qs}`);
}

export async function getUserBehavior(params: { page?: number; user_id?: string }) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, String(v)); });
  return request<UserBehaviorPage>(`/v1/dashboard/users/behavior?${qs}`);
}

export async function updateRule(ruleId: string, data: { enabled?: boolean }): Promise<RuleItem> {
  return request<RuleItem>(`/v1/rules/${ruleId}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}
