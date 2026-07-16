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
  group: string | null;
  source?: string | null;
  pattern_type?: string | null;
  pattern_value?: string | null;
  pattern_confidence?: string | null;
  applicable_stages?: string[] | null;
  target_files?: string[] | null;
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
  direction?: string; rule_id?: string; user_id?: string;
  start_time?: string; end_time?: string; status?: string;
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

export async function getRules(params: { page?: number; page_size?: number; severity?: string; group?: string }) {
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

export async function scanOutput(content: string, userId?: string) {
  return request<ScanResult>('/v1/scan/output', {
    method: 'POST',
    body: JSON.stringify({ content, user_id: userId }),
  });
}

export async function scanBatch(path: string, userId?: string) {
  return request<{ results: BatchScanResult[]; summary: { total_findings: number; files_scanned: number } }>('/v1/scan/batch', {
    method: 'POST',
    body: JSON.stringify({ path, user_id: userId }),
  });
}

export interface BatchScanResult {
  file: string;
  triggered_rules: TriggeredRule[];
  error: string | null;
}

export interface ComplianceReport {
  report_type: string;
  generated_at: string;
  total_events: number;
  total_blocked: number;
  total_warnings: number;
  p0_count: number;
  p1_count: number;
  p2_count: number;
  unique_users: number;
  unique_rules: number;
  date_range: { start: string; end: string };
  top_rules: { rule_id: string; rule_name: string; count: number }[];
}

export async function getComplianceReport(start_time?: string, end_time?: string) {
  const qs = new URLSearchParams();
  if (start_time) qs.set('start_time', start_time);
  if (end_time) qs.set('end_time', end_time);
  return request<ComplianceReport>(`/v1/audit/report?${qs}`);
}

export async function exportAuditLogs(params: { page_size?: number; severity?: string; direction?: string }) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, String(v)); });
  const apiKey = typeof window !== 'undefined' ? localStorage.getItem('kasra_api_key') : null;
  const res = await fetch(`/v1/audit/export?${qs}`, {
    headers: { 'X-API-Key': apiKey || '' },
  });
  if (!res.ok) throw new Error(`Export failed: ${res.status}`);
  return res.text();
}

export async function createRule(data: {
  id: string; name: string; severity: string; action: string;
  pattern_type?: string; pattern_value?: string;
  applicable_stages?: string[]; target_files?: string[];
}): Promise<RuleItem> {
  return request<RuleItem>('/v1/rules', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export interface ImportStats {
  total: number;
  created: number;
  updated: number;
  errors: string[];
}

export async function exportRules(series?: string, category?: string, source: string = 'sdk') {
  const qs = new URLSearchParams();
  if (series) qs.set('series', series);
  if (category) qs.set('category', category);
  qs.set('source', source);
  const apiKey = typeof window !== 'undefined' ? localStorage.getItem('kasra_api_key') : null;
  const res = await fetch(`/v1/rules/export?${qs}`, {
    headers: { 'X-API-Key': apiKey || '' },
  });
  if (!res.ok) throw new Error(`Export failed: ${res.status}`);
  return res.blob();
}

export async function importRules(file: File, target: string = 'sdk') {
  const apiKey = typeof window !== 'undefined' ? localStorage.getItem('kasra_api_key') : null;
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`/v1/rules/import?target=${target}`, {
    method: 'POST',
    headers: { 'X-API-Key': apiKey || '' },
    body: formData,
  });
  if (!res.ok) throw new Error(`Import failed: ${await res.text()}`);
  return res.json() as Promise<ImportStats>;
}

export async function deleteRule(ruleId: string): Promise<void> {
  await fetch(`/v1/rules/${ruleId}`, {
    method: 'DELETE',
    headers: { 'X-API-Key': localStorage.getItem('kasra_api_key') || '' },
  });
}

export interface HealthDetail {
  status: string;
  version: string;
  database: { status: string; type: string; version: string; error: string | null };
  https_proxy: { enabled: boolean; port: number };
  rules_loaded: number;
  rules_total: number;
  cr_rules_loaded: number;
  audit_enabled: boolean;
}

export async function getHealthDetail() {
  return request<HealthDetail>('/health');
}

export async function updateAuditLogStatus(logId: number, status: string) {
  return request(`/v1/audit/logs/${logId}`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
}

export async function batchUpdateAuditLogStatus(ids: number[], status: string) {
  return request<{ updated: number }>('/v1/audit/logs/batch-update', {
    method: 'POST',
    body: JSON.stringify({ ids, status }),
  });
}

// ── Dictionary API ──

export interface DictionaryItem {
  id: number;
  code: string;
  name: string;
  description: string | null;
  entries: string[];
  category_id: number | null;
  is_active: boolean;
  version: number;
  created_at: string | null;
  updated_at: string | null;
}

export async function getDictionaries(params: { category_id?: number; is_active?: boolean } = {}) {
  const qs = new URLSearchParams();
  if (params.category_id) qs.set('category_id', String(params.category_id));
  if (params.is_active !== undefined) qs.set('is_active', String(params.is_active));
  const query = qs.toString();
  return request<DictionaryItem[]>(`/v1/dictionaries${query ? `?${query}` : ''}`);
}

export async function getDictionary(id: number) {
  return request<DictionaryItem>(`/v1/dictionaries/${id}`);
}

export async function createDictionary(data: { code: string; name: string; description?: string; entries?: string[]; category_id?: number }) {
  return request<DictionaryItem>('/v1/dictionaries', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateDictionary(id: number, data: { name?: string; description?: string; entries?: string[]; category_id?: number | null; is_active?: boolean }) {
  return request<DictionaryItem>(`/v1/dictionaries/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteDictionary(id: number) {
  await fetch(`/v1/dictionaries/${id}`, {
    method: 'DELETE',
    headers: { 'X-API-Key': localStorage.getItem('kasra_api_key') || '' },
  });
}

export async function addDictionaryEntries(id: number, entries: string[]) {
  return request<DictionaryItem>(`/v1/dictionaries/${id}/entries`, {
    method: 'POST',
    body: JSON.stringify({ entries }),
  });
}

export async function removeDictionaryEntries(id: number, entries: string[]) {
  return request<DictionaryItem>(`/v1/dictionaries/${id}/entries`, {
    method: 'DELETE',
    body: JSON.stringify({ entries }),
  });
}
