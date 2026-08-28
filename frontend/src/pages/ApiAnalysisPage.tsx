import { useEffect, useState } from 'react'
import { AlertTriangle, Check, Ghost, Loader2, Radar, ShieldQuestion, X } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { FilterPill } from '@/components/ui/filter-pill'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { StatPill } from '@/components/ui/stat-pill'
import { cn } from '@/lib/utils'
import {
  getApiSummary,
  getApiTimeline,
  getFindingRequests,
  listApiEndpoints,
  listApiFindings,
  markEndpointDocumented,
  updateApiFinding,
  type ApiAnalysisSummary,
  type ApiEndpoint,
  type ApiFinding,
  type ApiRequestRow,
  type ApiTimelinePoint,
  type APIFindingStatus,
  type Severity,
} from '@/lib/api'
import { formatTime } from '@/lib/format'

const POLL_INTERVAL_MS = 5000

const severityMeta: Record<Severity, { label: string; color: string; bg: string; dot: string }> = {
  critical: { label: 'crítico', color: 'text-[#FF8080]', bg: 'bg-destructive/16', dot: '#EF4444' },
  high: { label: 'alto', color: 'text-warning', bg: 'bg-warning/16', dot: '#F59E0B' },
  medium: { label: 'médio', color: 'text-[#7FB0FF]', bg: 'bg-[#3B82F6]/16', dot: '#3B82F6' },
  low: { label: 'baixo', color: 'text-success', bg: 'bg-success/14', dot: '#22C55E' },
  info: { label: 'info', color: 'text-muted-foreground', bg: 'bg-white/[0.06]', dot: '#8E8EA3' },
}

const findingStatusMeta: Record<APIFindingStatus, { label: string; color: string }> = {
  open: { label: 'Aberto', color: 'text-destructive' },
  investigating: { label: 'Investigando', color: 'text-primary' },
  benign: { label: 'Benigno', color: 'text-success' },
  escalated: { label: 'Escalado', color: 'text-[#A78BFA]' },
  resolved: { label: 'Resolvido', color: 'text-muted-foreground' },
}

type Tab = 'findings' | 'endpoints'

export function ApiAnalysisPage() {
  const [tab, setTab] = useState<Tab>('findings')
  const [summary, setSummary] = useState<ApiAnalysisSummary | null>(null)
  const [timeline, setTimeline] = useState<ApiTimelinePoint[]>([])
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    function load(isInitial: boolean) {
      if (isInitial) setLoading(true)
      Promise.all([getApiSummary(), listApiFindings(), getApiTimeline(60)])
        .then(([sum, list, tl]) => {
          if (cancelled) return
          setSummary(sum)
          setFindings(list)
          setTimeline(tl)
          setError(null)
        })
        .catch((err) => {
          if (cancelled) return
          setError(err instanceof Error ? err.message : 'Erro ao carregar a análise de API')
        })
        .finally(() => {
          if (!cancelled && isInitial) setLoading(false)
        })
    }

    load(true)
    const id = setInterval(() => load(false), POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  const selected = findings.find((f) => f.id === selectedId) ?? null

  function applyUpdate(updated: ApiFinding) {
    setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)))
  }

  return (
    <AppShell title="Análise de API">
      <div className="flex shrink-0 flex-wrap items-center gap-3 px-4 pt-5 sm:px-8">
        <StatPill
          icon={AlertTriangle}
          tone="text-destructive"
          bg="bg-destructive/12"
          value={summary?.critical_findings ?? 0}
          label="críticos"
          hint="para tratar"
        />
        <StatPill
          icon={ShieldQuestion}
          tone="text-warning"
          bg="bg-warning/12"
          value={summary?.open_findings ?? 0}
          label="achados abertos"
          hint="na janela"
        />
        <StatPill
          icon={Ghost}
          tone="text-[#A78BFA]"
          bg="bg-[#A78BFA]/12"
          value={summary?.shadow_endpoints ?? 0}
          label="rotas fantasma"
          hint="não documentadas"
        />
        <StatPill
          icon={Radar}
          tone="text-primary"
          bg="bg-primary/12"
          value={summary?.total_requests ?? 0}
          label="requisições"
          hint={`últimos ${summary?.window_minutes ?? 10} min`}
        />
        <div className="ml-auto">
          <TrafficSpark points={timeline} errorRate={summary?.error_rate ?? 0} />
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2.5 px-4 pt-4 sm:px-8">
        <FilterPill active={tab === 'findings'} onClick={() => setTab('findings')}>
          Achados
        </FilterPill>
        <FilterPill active={tab === 'endpoints'} onClick={() => setTab('endpoints')}>
          Inventário de rotas
        </FilterPill>
        {summary && summary.queue.dropped > 0 && (
          <span className="ml-auto font-mono text-[11px] text-warning">
            coleta descartou {summary.queue.dropped} sob carga
          </span>
        )}
      </div>

      {loading ? (
        <LoadingState label="Carregando análise de API…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : tab === 'findings' ? (
        <FindingsList findings={findings} selectedId={selectedId} onSelect={setSelectedId} />
      ) : (
        <EndpointsList />
      )}

      {selected && <div onClick={() => setSelectedId(null)} className="fixed inset-0 z-10 bg-black/45 backdrop-blur-[1px]" />}
      <div
        className={cn(
          'fixed right-0 top-0 z-20 flex h-screen w-full flex-col border-l border-border bg-card shadow-[-20px_0_50px_rgba(0,0,0,0.4)] transition-transform duration-300 ease-out sm:w-[460px]',
          selected ? 'translate-x-0' : 'translate-x-full',
        )}
      >
        {selected && <FindingDetail finding={selected} onClose={() => setSelectedId(null)} onUpdated={applyUpdate} />}
      </div>
    </AppShell>
  )
}

function FindingsList({
  findings,
  selectedId,
  onSelect,
}: {
  findings: ApiFinding[]
  selectedId: number | null
  onSelect: (id: number) => void
}) {
  return (
    <div className="flex min-h-0 grow flex-col overflow-x-auto px-4 pb-10 sm:px-8">
      <div className="flex min-w-[820px] grow flex-col">
        <div className="grid shrink-0 grid-cols-[150px_70px_1fr_84px_92px_110px] border-b border-border px-2 pb-2.5 pt-4">
          {['Chamador', 'Score', 'Sinais', 'Requis.', 'Visto', 'Status'].map((h) => (
            <span key={h} className="text-[10.5px] uppercase tracking-wide text-muted-foreground">
              {h}
            </span>
          ))}
        </div>

        <div className="grow overflow-y-auto">
          {findings.length === 0 && (
            <div className="flex flex-col items-center gap-1.5 py-14 text-center">
              <span className="text-sm text-foreground">Nenhum comportamento suspeito na janela</span>
              <span className="text-xs text-muted-foreground">
                O analisador observa o tráfego da API em tempo real. Um ataque aparece aqui em segundos.
              </span>
            </div>
          )}
          {findings.map((f) => {
            const s = severityMeta[f.severity]
            const st = findingStatusMeta[f.status]
            return (
              <div
                key={f.id}
                onClick={() => onSelect(f.id)}
                className={cn(
                  'grid cursor-pointer grid-cols-[150px_70px_1fr_84px_92px_110px] items-center border-b border-border/60 px-2 py-3 hover:bg-white/[0.035]',
                  selectedId === f.id && 'bg-primary/[0.06]',
                )}
              >
                <span className="flex items-center gap-2 pr-3">
                  <span className="h-5 w-[3px] shrink-0 rounded-sm" style={{ background: s.dot }} />
                  <span className="truncate font-mono text-[12px] text-foreground">{f.client_ip}</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <ScoreDot score={f.score} sev={f.severity} />
                </span>
                <span className="flex min-w-0 flex-wrap gap-1 pr-4">
                  {f.signals.slice(0, 3).map((sig) => (
                    <span key={sig.id} className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      {sig.label}
                    </span>
                  ))}
                  {f.signals.length > 3 && (
                    <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      +{f.signals.length - 3}
                    </span>
                  )}
                </span>
                <span className="font-mono text-[11.5px] text-muted-foreground">{f.request_count}</span>
                <span className="font-mono text-[11px] text-muted-foreground">{formatTime(f.last_seen)}</span>
                <span className={`flex items-center gap-1.5 text-[11px] ${st.color}`}>
                  <span className={cn('h-1.5 w-1.5 rounded-full', st.color.replace('text-', 'bg-'))} />
                  {st.label}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function EndpointsList() {
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([])
  const [shadowOnly, setShadowOnly] = useState(false)
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState<number | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    listApiEndpoints({ shadow_only: shadowOnly })
      .then((rows) => !cancelled && setEndpoints(rows))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [shadowOnly])

  async function handleDocument(id: number) {
    setBusyId(id)
    try {
      const updated = await markEndpointDocumented(id)
      setEndpoints((prev) => prev.map((e) => (e.id === id ? updated : e)))
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="flex min-h-0 grow flex-col overflow-x-auto px-4 pb-10 sm:px-8">
      <div className="flex shrink-0 items-center gap-2.5 py-3">
        <FilterPill active={!shadowOnly} onClick={() => setShadowOnly(false)}>
          Todas
        </FilterPill>
        <FilterPill active={shadowOnly} onClick={() => setShadowOnly(true)} activeColor="#A78BFA">
          Só fantasmas
        </FilterPill>
        <span className="ml-auto font-mono text-xs text-muted-foreground">{endpoints.length} rota(s)</span>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 py-10 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> carregando rotas…
        </div>
      ) : (
        <div className="flex min-w-[760px] grow flex-col">
          <div className="grid shrink-0 grid-cols-[64px_1fr_96px_96px_96px_130px] border-b border-border px-2 pb-2.5 pt-1">
            {['Método', 'Rota', 'Requis.', 'Erros', 'Estado', ''].map((h, i) => (
              <span key={i} className="text-[10.5px] uppercase tracking-wide text-muted-foreground">
                {h}
              </span>
            ))}
          </div>
          <div className="grow overflow-y-auto">
            {endpoints.map((e) => (
              <div
                key={e.id}
                className="grid grid-cols-[64px_1fr_96px_96px_96px_130px] items-center border-b border-border/60 px-2 py-2.5"
              >
                <span className="font-mono text-[11px] font-semibold text-primary">{e.method}</span>
                <span className="flex min-w-0 items-center gap-2 pr-3">
                  <span className="truncate font-mono text-[12px] text-foreground">{e.route}</span>
                  {e.is_sensitive && (
                    <span className="shrink-0 rounded bg-warning/16 px-1.5 py-0.5 text-[9.5px] uppercase text-warning">sensível</span>
                  )}
                </span>
                <span className="font-mono text-[11.5px] text-muted-foreground">{e.request_count}</span>
                <span className={cn('font-mono text-[11.5px]', e.error_count > 0 ? 'text-warning' : 'text-muted-foreground')}>
                  {e.error_count}
                </span>
                <span>
                  {e.is_documented ? (
                    <span className="flex items-center gap-1 text-[11px] text-success">
                      <Check className="h-3 w-3" /> conhecida
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[11px] text-[#A78BFA]">
                      <Ghost className="h-3 w-3" /> fantasma
                    </span>
                  )}
                </span>
                <span>
                  {!e.is_documented && (
                    <button
                      type="button"
                      disabled={busyId === e.id}
                      onClick={() => handleDocument(e.id)}
                      className="flex h-7 items-center gap-1.5 rounded-md border border-border px-2.5 text-[11px] text-foreground transition-colors hover:bg-white/[0.06] disabled:opacity-50"
                    >
                      {busyId === e.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
                      Marcar conhecida
                    </button>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function FindingDetail({
  finding,
  onClose,
  onUpdated,
}: {
  finding: ApiFinding
  onClose: () => void
  onUpdated: (f: ApiFinding) => void
}) {
  const [saving, setSaving] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [benignForm, setBenignForm] = useState(false)
  const [note, setNote] = useState(finding.note ?? '')
  const [requests, setRequests] = useState<ApiRequestRow[] | null>(null)

  useEffect(() => {
    let cancelled = false
    setRequests(null)
    getFindingRequests(finding.id)
      .then((rows) => !cancelled && setRequests(rows))
      .catch(() => !cancelled && setRequests([]))
    return () => {
      cancelled = true
    }
  }, [finding.id])

  const s = severityMeta[finding.severity]

  async function apply(status: APIFindingStatus, noteText?: string) {
    if (saving) return
    setSaving(true)
    setActionError(null)
    try {
      const updated = await updateApiFinding(finding.id, { status, note: noteText })
      onUpdated(updated)
      setBenignForm(false)
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Não foi possível salvar')
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <div className="flex shrink-0 items-center justify-between border-b border-border px-5.5 py-5">
        <span className="font-mono text-[11.5px] uppercase tracking-wide text-muted-foreground">Detalhe do achado</span>
        <button
          type="button"
          onClick={onClose}
          className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-white/[0.08]"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex grow flex-col gap-5 overflow-y-auto p-5.5">
        <div className="flex items-center gap-2.5">
          <span className={`rounded-md px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wide ${s.color} ${s.bg}`}>
            {s.label}
          </span>
          <span className="font-mono text-[12px] text-foreground">score {finding.score}/100</span>
          {finding.alert_id && (
            <span className="rounded-md bg-primary/12 px-2 py-1 text-[10.5px] text-primary">alerta #{finding.alert_id}</span>
          )}
        </div>

        <div>
          <div className="font-heading text-[17px] font-semibold leading-snug text-foreground">{finding.client_ip}</div>
          <div className="mt-0.5 text-[12px] text-muted-foreground">
            {finding.request_count} requisições em {finding.distinct_routes} rota(s) distintas na janela
          </div>
        </div>

        <div>
          <div className="mb-2 text-[11.5px] text-muted-foreground">Sinais detectados</div>
          <div className="flex flex-col gap-2">
            {finding.signals.map((sig) => (
              <div key={sig.id} className="rounded-lg border border-border bg-background p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[12.5px] font-medium text-foreground">{sig.label}</span>
                  <span className="shrink-0 rounded bg-destructive/12 px-1.5 py-0.5 font-mono text-[10.5px] text-destructive">
                    +{sig.weight}
                  </span>
                </div>
                <div className="mt-1 break-words text-[11.5px] leading-relaxed text-muted-foreground">{sig.evidence}</div>
              </div>
            ))}
          </div>
        </div>

        {finding.top_routes && finding.top_routes.length > 0 && (
          <div>
            <div className="mb-2 text-[11.5px] text-muted-foreground">Rotas mais batidas</div>
            <div className="flex flex-col gap-1">
              {finding.top_routes.map((r) => (
                <div key={r.route} className="flex items-center justify-between gap-3 text-[11.5px]">
                  <span className="truncate font-mono text-foreground">{r.route}</span>
                  <span className="shrink-0 font-mono text-muted-foreground">{r.count}x</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div>
          <div className="mb-2 text-[11.5px] text-muted-foreground">Tratativa</div>
          <div className="grid grid-cols-2 gap-2">
            <StatusButton active={finding.status === 'investigating'} color="var(--primary)" onClick={() => apply('investigating')}>
              Investigar
            </StatusButton>
            <StatusButton active={finding.status === 'escalated'} color="#A78BFA" onClick={() => apply('escalated')}>
              Escalar
            </StatusButton>
            <StatusButton active={finding.status === 'benign'} color="var(--success)" onClick={() => setBenignForm(true)}>
              Benigno
            </StatusButton>
            <StatusButton active={finding.status === 'open'} color="var(--destructive)" onClick={() => apply('open')}>
              Reabrir
            </StatusButton>
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
            Escalar manda o caso pra fila de prevenção de ameaça. Marcar como benigno silencia esse chamador por 6 horas.
          </p>
        </div>

        {benignForm && (
          <div className="flex flex-col gap-3 rounded-lg border border-success/30 bg-success/[0.06] p-4">
            <div className="text-[12px] text-success">
              Marcar como benigno silencia esse IP por 6 horas. Escreva o motivo pra o próximo analista entender a decisão.
            </div>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              rows={3}
              placeholder="Por que esse tráfego é legítimo?"
              className="rounded-md border border-border bg-background p-2.5 text-[12.5px] text-foreground outline-none focus:border-success/50"
            />
            <div className="flex gap-2">
              <button
                type="button"
                disabled={saving || !note.trim()}
                onClick={() => apply('benign', note)}
                className="flex h-8 flex-1 items-center justify-center gap-1.5 rounded-md bg-success text-xs font-semibold text-[#0A0A0F] transition-opacity hover:opacity-90 disabled:opacity-40"
              >
                {saving && <Loader2 className="h-3 w-3 animate-spin" />}
                Confirmar
              </button>
              <button
                type="button"
                onClick={() => setBenignForm(false)}
                className="h-8 rounded-md border border-border px-3 text-xs text-muted-foreground hover:bg-white/[0.05]"
              >
                Cancelar
              </button>
            </div>
          </div>
        )}

        {finding.status === 'benign' && !benignForm && finding.note && (
          <div className="rounded-lg border border-success/25 bg-success/[0.06] p-3.5">
            <div className="mb-1 text-[10.5px] uppercase tracking-wide text-success">Marcado benigno por {finding.updated_by}</div>
            <div className="text-[12.5px] text-foreground">{finding.note}</div>
          </div>
        )}

        {actionError && <div className="text-[11px] text-destructive">{actionError}</div>}

        <div>
          <div className="mb-2 text-[11.5px] text-muted-foreground">Requisições da janela</div>
          {requests === null ? (
            <div className="flex items-center gap-2 py-4 text-[11.5px] text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> carregando…
            </div>
          ) : requests.length === 0 ? (
            <div className="py-3 text-[11.5px] text-muted-foreground">Sem requisições retidas para esse chamador.</div>
          ) : (
            <div className="flex flex-col gap-1 rounded-lg border border-border bg-background p-2">
              {requests.map((r) => {
                const injected = Array.isArray((r.flags as { injection?: unknown[] }).injection)
                  ? ((r.flags as { injection: unknown[] }).injection.length > 0)
                  : false
                return (
                  <div key={r.id} className="flex items-center gap-2 py-0.5 font-mono text-[10.5px]">
                    <span className={cn('w-8 shrink-0', (r.status_code ?? 0) >= 400 ? 'text-warning' : 'text-muted-foreground')}>
                      {r.status_code ?? '—'}
                    </span>
                    <span className="w-10 shrink-0 text-primary">{r.method}</span>
                    <span className="min-w-0 flex-1 truncate text-foreground">{r.path}</span>
                    {injected && <span className="shrink-0 rounded bg-destructive/16 px-1 text-[9px] text-destructive">inj</span>}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </>
  )
}

function ScoreDot({ score, sev }: { score: number; sev: Severity }) {
  const color = severityMeta[sev].dot
  return (
    <span className="flex items-center gap-1.5">
      <span className="flex h-6 w-9 items-center justify-center rounded-md font-mono text-[11.5px] font-semibold" style={{ color, background: `${color}22` }}>
        {score}
      </span>
    </span>
  )
}

function TrafficSpark({ points, errorRate }: { points: ApiTimelinePoint[]; errorRate: number }) {
  const max = Math.max(1, ...points.map((p) => p.total))
  const bars = points.slice(-40)
  return (
    <div className="flex items-center gap-3 rounded-xl border border-border bg-card px-4 py-2.5">
      <div className="flex h-9 items-end gap-[2px]">
        {bars.length === 0 && <span className="text-[11px] text-muted-foreground">sem tráfego ainda</span>}
        {bars.map((p, i) => {
          const h = Math.max(2, (p.total / max) * 34)
          const hasErr = p.errors > 0
          return <span key={i} className="w-[3px] rounded-sm" style={{ height: h, background: hasErr ? '#F59E0B' : 'var(--primary)' }} />
        })}
      </div>
      <div className="leading-tight">
        <div className="font-heading text-[15px] font-semibold text-foreground">{errorRate}%</div>
        <div className="text-[10.5px] text-muted-foreground">taxa de erro</div>
      </div>
    </div>
  )
}

function StatusButton({
  active,
  color,
  onClick,
  children,
}: {
  active: boolean
  color: string
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={
        active
          ? { background: color, borderColor: color, color: 'var(--primary-foreground)' }
          : { borderColor: 'rgba(255,255,255,0.16)', color }
      }
      className="h-[34px] rounded-md border text-xs font-medium transition-opacity hover:opacity-85"
    >
      {children}
    </button>
  )
}
