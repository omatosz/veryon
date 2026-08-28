const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const TOKEN_KEY = 'soc_siem_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers = new Headers(options.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (options.body && !(options.body instanceof URLSearchParams)) {
    headers.set('Content-Type', 'application/json')
  }

  let res: Response
  try {
    res = await fetch(`${API_URL}${path}`, { ...options, headers })
  } catch {
    throw new ApiError(0, 'Não foi possível conectar ao servidor')
  }

  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail ?? detail
    } catch {
      // corpo sem JSON, mantém o statusText
    }
    // Token expirado (o JWT dura 1h) devolve 401 em toda chamada. Sem isso a
    // tela mostrava "erro ao carregar" e o usuário ficava preso: o certo é
    // descartar o token e voltar pro login. O próprio /auth/login fica de
    // fora, senão senha errada viraria um recarregamento em vez de mensagem.
    if (res.status === 401 && !path.startsWith('/auth/')) {
      clearToken()
      if (window.location.pathname !== '/') window.location.assign('/')
    }
    throw new ApiError(res.status, detail)
  }

  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

// --- Auth ---

interface TokenResponse {
  access_token: string
  token_type: string
}

export async function login(username: string, password: string, honeypot = ''): Promise<string> {
  const body = new URLSearchParams({ username, password, website: honeypot })
  const data = await request<TokenResponse>('/auth/login', { method: 'POST', body })
  return data.access_token
}

// --- Events ---

export interface ApiEvent {
  id: number
  ts: string
  source: string
  host: string | null
  event_type: string
  src_ip: string | null
  payload: Record<string, unknown>
}

export function listEvents(params: { source?: string; limit?: number } = {}) {
  const qs = new URLSearchParams()
  if (params.source) qs.set('source', params.source)
  qs.set('limit', String(params.limit ?? 100))
  return request<ApiEvent[]>(`/events?${qs}`)
}

// --- Alerts ---

export interface ApiAlert {
  id: number
  ts: string
  rule_id: string
  title: string
  level: string
  mitre_technique: string | null
  source_event_id: number | null
  source_event_type: string | null
  source_host: string | null
  source_ip: string | null
  description: string | null
  status: string
  payload: Record<string, unknown>
}

export function listAlerts(params: { level?: string; status?: string; limit?: number } = {}) {
  const qs = new URLSearchParams()
  if (params.level) qs.set('level', params.level)
  if (params.status) qs.set('status', params.status)
  qs.set('limit', String(params.limit ?? 200))
  return request<ApiAlert[]>(`/alerts?${qs}`)
}

export function updateAlertStatus(id: number, status: string) {
  return request<ApiAlert>(`/alerts/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  })
}

// --- Blocklist ---

export interface ApiBlockedIP {
  id: number
  ip: string
  alert_id: number | null
  reason: string | null
  blocked_by: string
  blocked_at: string
  unblocked_at: string | null
  unblocked_by: string | null
  /** null = bloqueio sem prazo, só sai na mão */
  expires_at: string | null
  /** 'manual' ou 'policy' */
  source: string
  policy_id: number | null
}

export function listBlocklist() {
  return request<ApiBlockedIP[]>('/blocklist')
}

export function blockAlertIp(alertId: number, ttlMinutes?: number) {
  const qs = ttlMinutes ? `?ttl_minutes=${ttlMinutes}` : ''
  return request<ApiBlockedIP>(`/alerts/${alertId}/block${qs}`, { method: 'POST' })
}

export function blockIp(ip: string, reason: string, ttlMinutes?: number) {
  return request<ApiBlockedIP>('/blocklist', {
    method: 'POST',
    body: JSON.stringify({ ip, reason, ttl_minutes: ttlMinutes ?? null }),
  })
}

export function unblockIp(ip: string) {
  return request<ApiBlockedIP>(`/blocklist/${encodeURIComponent(ip)}/unblock`, { method: 'POST' })
}

// --- Allowlist ---

export interface ApiAllowlistEntry {
  id: number
  cidr: string
  reason: string | null
  added_by: string
  created_at: string
}

export function listAllowlist() {
  return request<ApiAllowlistEntry[]>('/blocklist/allowlist')
}

export function addToAllowlist(cidr: string, reason?: string) {
  return request<ApiAllowlistEntry>('/blocklist/allowlist', {
    method: 'POST',
    body: JSON.stringify({ cidr, reason: reason ?? null }),
  })
}

export function removeFromAllowlist(id: number) {
  return request<void>(`/blocklist/allowlist/${id}`, { method: 'DELETE' })
}

// --- Enrichment ---

export interface ApiEnrichment {
  ip: string
  checked_at: string
  abuseipdb_score: number | null
  abuseipdb_country: string | null
  abuseipdb_isp: string | null
  abuseipdb_total_reports: number | null
  virustotal_malicious: number | null
  virustotal_total_engines: number | null
  virustotal_reputation: number | null
  otx_pulse_count: number | null
}

export function getEnrichment(ip: string) {
  return request<ApiEnrichment>(`/enrichment/${encodeURIComponent(ip)}`)
}

// --- Vulnerabilidades ---

export type VulnStatus = 'open' | 'in_progress' | 'remediated' | 'accepted_risk'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface ApiVulnerability {
  id: number
  asset: string
  asset_type: string
  signature: string
  title: string
  description: string | null
  severity: Severity
  cvss: number | null
  cve: string | null
  port: number | null
  service: string | null
  evidence: Record<string, unknown>
  source: string
  status: VulnStatus
  first_seen: string
  last_seen: string
  resolved_at: string | null
  updated_by: string | null
  justification: string | null
  review_at: string | null
  /** quantas vezes voltou depois de marcada como corrigida */
  reopened_count: number
  source_event_id: number | null
}

export interface ApiScanJob {
  id: number
  status: 'queued' | 'running' | 'done' | 'failed'
  requested_by: string
  targets: Record<string, unknown> | null
  created_at: string
  started_at: string | null
  finished_at: string | null
  error: string | null
  stats: { achados?: number; novos?: number; reabertos?: number; atualizados?: number; sumiram?: number } | null
}

export interface ApiVulnSummary {
  by_severity: Record<string, number>
  by_status: Record<string, number>
  total_open: number
  risk_score: number
  last_scan: ApiScanJob | null
}

export function listVulnerabilities(
  params: { status?: string; severity?: string; asset_type?: string; limit?: number } = {},
) {
  const qs = new URLSearchParams()
  if (params.status) qs.set('status', params.status)
  if (params.severity) qs.set('severity', params.severity)
  if (params.asset_type) qs.set('asset_type', params.asset_type)
  qs.set('limit', String(params.limit ?? 200))
  return request<ApiVulnerability[]>(`/vulnerabilities?${qs}`)
}

export function getVulnSummary() {
  return request<ApiVulnSummary>('/vulnerabilities/summary')
}

export function updateVulnerability(
  id: number,
  body: { status: VulnStatus; justification?: string; review_at?: string },
) {
  return request<ApiVulnerability>(`/vulnerabilities/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      status: body.status,
      justification: body.justification ?? null,
      review_at: body.review_at ?? null,
    }),
  })
}

// --- Varreduras ---

export function requestScan() {
  return request<ApiScanJob>('/scans', { method: 'POST' })
}

export function listScans(limit = 10) {
  return request<ApiScanJob[]>(`/scans?limit=${limit}`)
}

// --- Análise de API ---

export type APIFindingStatus = 'open' | 'investigating' | 'benign' | 'escalated' | 'resolved'

export interface ApiSignal {
  id: string
  label: string
  weight: number
  evidence: string
}

export interface ApiRouteCount {
  route: string
  count: number
}

export interface ApiFinding {
  id: number
  client_ip: string
  score: number
  severity: Severity
  signals: ApiSignal[]
  request_count: number
  distinct_routes: number
  top_routes: ApiRouteCount[] | null
  window_start: string
  window_end: string
  first_seen: string
  last_seen: string
  status: APIFindingStatus
  updated_by: string | null
  note: string | null
  muted_until: string | null
  alert_id: number | null
}

export interface ApiEndpoint {
  id: number
  method: string
  route: string
  is_documented: boolean
  is_sensitive: boolean
  first_seen: string
  last_seen: string
  request_count: number
  error_count: number
  avg_response_bytes: number | null
}

export interface ApiRequestRow {
  id: number
  ts: string
  source: string
  client_ip: string | null
  method: string
  path: string
  route: string
  status_code: number | null
  duration_ms: number | null
  response_bytes: number | null
  user_agent: string | null
  query: string | null
  flags: Record<string, unknown>
}

export interface ApiAnalysisSummary {
  window_minutes: number
  total_requests: number
  error_rate: number
  distinct_callers: number
  open_findings: number
  critical_findings: number
  shadow_endpoints: number
  documented_endpoints: number
  top_findings: ApiFinding[]
  queue: { queued: number; dropped: number }
}

export function getApiSummary() {
  return request<ApiAnalysisSummary>('/api-analysis/summary')
}

export function listApiFindings(params: { status?: string; severity?: string } = {}) {
  const qs = new URLSearchParams()
  if (params.status) qs.set('status', params.status)
  if (params.severity) qs.set('severity', params.severity)
  return request<ApiFinding[]>(`/api-analysis/findings?${qs}`)
}

export function getFindingRequests(findingId: number) {
  return request<ApiRequestRow[]>(`/api-analysis/findings/${findingId}/requests`)
}

export function updateApiFinding(id: number, body: { status: APIFindingStatus; note?: string }) {
  return request<ApiFinding>(`/api-analysis/findings/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ status: body.status, note: body.note ?? null }),
  })
}

export function listApiEndpoints(params: { shadow_only?: boolean; sensitive_only?: boolean } = {}) {
  const qs = new URLSearchParams()
  if (params.shadow_only) qs.set('shadow_only', 'true')
  if (params.sensitive_only) qs.set('sensitive_only', 'true')
  return request<ApiEndpoint[]>(`/api-analysis/endpoints?${qs}`)
}

export function markEndpointDocumented(id: number) {
  return request<ApiEndpoint>(`/api-analysis/endpoints/${id}/document`, { method: 'POST' })
}

export interface ApiTimelinePoint {
  ts: string
  total: number
  errors: number
}

export function getApiTimeline(minutes = 60) {
  return request<ApiTimelinePoint[]>(`/api-analysis/timeline?minutes=${minutes}`)
}

// --- Prevenção de ameaça ---

export type PolicyMode = 'observe' | 'enforce'

export interface ApiPolicy {
  id: number
  code: string
  name: string
  description: string
  kind: string
  params: Record<string, unknown>
  action: 'block_ip' | 'escalate'
  ttl_minutes: number | null
  mode: PolicyMode
  enabled: boolean
  priority: number
  cooldown_minutes: number
  match_count: number
  action_count: number
  last_match_at: string | null
  updated_at: string | null
  updated_by: string | null
}

export interface ApiPreventionAction {
  id: number
  ts: string
  policy_id: number | null
  policy_code: string | null
  action_type: string
  target: string
  reason: string
  evidence: Record<string, unknown>
  mode: string
  status: 'simulated' | 'applied' | 'held' | 'undone' | 'failed'
  rail: string | null
  blocked_ip_id: number | null
  source_kind: string | null
  source_id: number | null
  undone_at: string | null
  undone_by: string | null
  created_by: string
}

export interface ApiSimulatedCase {
  target: string
  reason: string
  acao: string
  seria_segurado: string | null
}

export interface ApiQueueItem {
  kind: 'alert' | 'api_finding' | 'vulnerability'
  id: number
  title: string
  severity: string
  target: string | null
  ts: string
  status: string
  detail: string | null
}

export interface ApiPreventionSummary {
  policies_total: number
  policies_enforcing: number
  policies_observing: number
  actions_24h: number
  applied_24h: number
  held_24h: number
  blocks_last_hour: number
  blocks_ceiling: number
  queue_size: number
}

export function listPolicies() {
  return request<ApiPolicy[]>('/prevention/policies')
}

export function updatePolicy(
  id: number,
  body: { mode?: PolicyMode; enabled?: boolean; ttl_minutes?: number; cooldown_minutes?: number },
) {
  return request<ApiPolicy>(`/prevention/policies/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  })
}

export function simulatePolicy(id: number) {
  return request<{ simulacao: ApiSimulatedCase[]; total: number }>(
    `/prevention/policies/${id}/simulate`,
    { method: 'POST' },
  )
}

export function listPreventionActions(params: { status?: string; policy_id?: number } = {}) {
  const qs = new URLSearchParams()
  if (params.status) qs.set('status', params.status)
  if (params.policy_id) qs.set('policy_id', String(params.policy_id))
  return request<ApiPreventionAction[]>(`/prevention/actions?${qs}`)
}

export function undoPreventionAction(id: number) {
  return request<ApiPreventionAction>(`/prevention/actions/${id}/undo`, { method: 'POST' })
}

export function getCriticalQueue() {
  return request<ApiQueueItem[]>('/prevention/queue')
}

export function getPreventionSummary() {
  return request<ApiPreventionSummary>('/prevention/summary')
}

// --- Stats ---

export interface ApiSummary {
  total_events: number
  total_alerts: number
  events_by_source: Record<string, number>
  alerts_by_level: Record<string, number>
  top_src_ips: { src_ip: string; count: number }[]
}

export function getSummary() {
  return request<ApiSummary>('/stats/summary')
}

export interface ApiSeriesPoint {
  ts: string
  category: string
  level: string
  count: number
}

export function getTimeseries(days = 14, bucket: 'day' | 'hour' = 'day') {
  return request<ApiSeriesPoint[]>(`/stats/timeseries?days=${days}&bucket=${bucket}`)
}

export interface ApiGeoPoint {
  country: string
  events: number
  ips: number
  blocked: number
  worst_score: number
}

export interface ApiGeoSummary {
  points: ApiGeoPoint[]
  internal_events: number
  unidentified_events: number
  total_ips: number
}

export function getGeo(days = 7) {
  return request<ApiGeoSummary>(`/stats/geo?days=${days}`)
}
