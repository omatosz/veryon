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
