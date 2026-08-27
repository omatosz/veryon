import { useEffect, useMemo, useRef, useState } from 'react'
import { Ban, Loader2, Radar, ShieldAlert, ShieldCheck, X } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { FilterPill } from '@/components/ui/filter-pill'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { StatPill } from '@/components/ui/stat-pill'
import { cn } from '@/lib/utils'
import {
  blockAlertIp,
  getEnrichment,
  listAlerts,
  listBlocklist,
  unblockIp,
  updateAlertStatus,
  type ApiAlert,
  type ApiBlockedIP,
  type ApiEnrichment,
} from '@/lib/api'
import { countryFlag, formatTime } from '@/lib/format'
import { severityMeta, sourceMeta, statusMeta, type AlertStatus, type EventSource, type Severity } from '@/lib/mock-data'

type SeverityFilter = Severity | 'all'
type StatusFilter = AlertStatus | 'all'

const POLL_INTERVAL_MS = 5000

function alertSource(a: ApiAlert): EventSource | null {
  const prefix = a.source_event_type?.split('.')[0]
  return prefix && prefix in sourceMeta ? (prefix as EventSource) : null
}

export function AlertsPage() {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [alerts, setAlerts] = useState<ApiAlert[]>([])
  const [ipInfo, setIpInfo] = useState<Record<string, ApiEnrichment | null>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [updatingStatus, setUpdatingStatus] = useState(false)
  const [blocklist, setBlocklist] = useState<ApiBlockedIP[]>([])
  const [blockActionError, setBlockActionError] = useState<string | null>(null)
  const [blocking, setBlocking] = useState(false)

  function refreshBlocklist() {
    listBlocklist()
      .then(setBlocklist)
      .catch(() => {
        // se a lista de bloqueio falhar, so nao mostra o estado (nao trava a tela de alertas)
      })
  }

  useEffect(() => {
    refreshBlocklist()
  }, [])

  useEffect(() => {
    let cancelled = false

    function load(isInitial: boolean) {
      if (isInitial) setLoading(true)
      listAlerts({
        level: severityFilter === 'all' ? undefined : severityFilter,
        status: statusFilter === 'all' ? undefined : statusFilter,
      })
        .then((data) => {
          if (cancelled) return
          setAlerts(data)
          setError(null)
        })
        .catch((err) => {
          if (cancelled) return
          setError(err instanceof Error ? err.message : 'Erro ao carregar alertas')
        })
        .finally(() => {
          if (!cancelled && isInitial) setLoading(false)
        })
      if (!isInitial) refreshBlocklist()
    }

    load(true)
    const id = setInterval(() => load(false), POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [severityFilter, statusFilter])

  const fetchedIps = useRef(new Set<string>())

  useEffect(() => {
    const uniqueIps = [...new Set(alerts.map((a) => a.source_ip).filter((ip): ip is string => !!ip))].slice(0, 15)
    const toFetch = uniqueIps.filter((ip) => !fetchedIps.current.has(ip))
    if (toFetch.length === 0) return
    toFetch.forEach((ip) => fetchedIps.current.add(ip))
    let cancelled = false
    Promise.allSettled(toFetch.map((ip) => getEnrichment(ip))).then((results) => {
      if (cancelled) return
      setIpInfo((prev) => {
        const next = { ...prev }
        toFetch.forEach((ip, i) => {
          const r = results[i]
          next[ip] = r.status === 'fulfilled' ? r.value : null
        })
        return next
      })
    })
    return () => {
      cancelled = true
    }
  }, [alerts])

  const selected = alerts.find((a) => a.id === selectedId) ?? null

  const stats = useMemo(
    () => ({
      open: alerts.filter((a) => a.status === 'open').length,
      high: alerts.filter((a) => a.level === 'high').length,
      total: alerts.length,
    }),
    [alerts],
  )

  async function setStatus(status: AlertStatus) {
    if (selectedId === null || updatingStatus) return
    setUpdatingStatus(true)
    try {
      const updated = await updateAlertStatus(selectedId, status)
      setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)))
    } catch {
      // se a chamada falhar, mantém o estado anterior
    } finally {
      setUpdatingStatus(false)
    }
  }

  function blockedEntryFor(ip: string | null): ApiBlockedIP | null {
    if (!ip) return null
    return blocklist.find((b) => b.ip === ip) ?? null
  }

  async function handleBlock() {
    if (selectedId === null || blocking) return
    setBlocking(true)
    setBlockActionError(null)
    try {
      await blockAlertIp(selectedId)
      refreshBlocklist()
    } catch (err) {
      setBlockActionError(err instanceof Error ? err.message : 'Não foi possível bloquear o IP')
    } finally {
      setBlocking(false)
    }
  }

  async function handleUnblock(ip: string) {
    if (blocking) return
    setBlocking(true)
    setBlockActionError(null)
    try {
      await unblockIp(ip)
      refreshBlocklist()
    } catch (err) {
      setBlockActionError(err instanceof Error ? err.message : 'Não foi possível desbloquear o IP')
    } finally {
      setBlocking(false)
    }
  }

  return (
    <AppShell title="Alertas">
      <div className="flex shrink-0 flex-wrap gap-3 px-4 pt-5 sm:px-8">
        <StatPill icon={ShieldAlert} tone="text-destructive" bg="bg-destructive/12" value={stats.open} label="abertos" hint="requer triagem" />
        <StatPill icon={Radar} tone="text-warning" bg="bg-warning/12" value={stats.high} label="high" hint="nesse filtro" />
        <StatPill icon={ShieldCheck} tone="text-primary" bg="bg-primary/12" value={stats.total} label="no total" hint="nesse filtro" />
      </div>

      <div className="flex shrink-0 flex-col gap-3.5 px-4 pt-3.5 sm:px-8">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="mr-1 text-[11.5px] uppercase tracking-wide text-muted-foreground">Severidade</span>
          <FilterPill active={severityFilter === 'all'} onClick={() => setSeverityFilter('all')}>
            Todas
          </FilterPill>
          <FilterPill active={severityFilter === 'high'} onClick={() => setSeverityFilter('high')} activeColor="var(--destructive)">
            High
          </FilterPill>
          <FilterPill active={severityFilter === 'medium'} onClick={() => setSeverityFilter('medium')} activeColor="var(--warning)">
            Medium
          </FilterPill>
          <FilterPill active={severityFilter === 'low'} onClick={() => setSeverityFilter('low')} activeColor="var(--success)">
            Low
          </FilterPill>

          <span className="mx-1.5 h-5 w-px bg-border" />

          <span className="mr-1 text-[11.5px] uppercase tracking-wide text-muted-foreground">Status</span>
          <FilterPill active={statusFilter === 'all'} onClick={() => setStatusFilter('all')}>
            Todos
          </FilterPill>
          <FilterPill active={statusFilter === 'open'} onClick={() => setStatusFilter('open')} activeColor="var(--destructive)">
            Aberto
          </FilterPill>
          <FilterPill active={statusFilter === 'acknowledged'} onClick={() => setStatusFilter('acknowledged')} activeColor="var(--warning)">
            Reconhecido
          </FilterPill>

          <span className="ml-auto font-mono text-xs text-muted-foreground">{loading ? '…' : `${alerts.length} resultado(s)`}</span>
        </div>
      </div>

      {loading ? (
        <LoadingState label="Carregando alertas…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : (
        <div className="flex min-h-0 grow flex-col overflow-x-auto px-4 pb-10 sm:px-8">
          <div className="flex min-w-[980px] grow flex-col">
            <div className="grid shrink-0 grid-cols-[96px_84px_70px_1fr_92px_100px_130px_112px] gap-0 border-b border-border px-2 pb-2.5 pt-4">
              {['Quando', 'Fonte', 'Nível', 'Alerta', 'MITRE', 'Host', 'IP origem', 'Status'].map((h) => (
                <span key={h} className="text-[10.5px] uppercase tracking-wide text-muted-foreground">
                  {h}
                </span>
              ))}
            </div>

            <div className="grow overflow-y-auto">
              {alerts.length === 0 && (
                <div className="flex flex-col items-center gap-1.5 py-14 text-center">
                  <span className="text-sm text-foreground">Nenhum alerta encontrado</span>
                  <span className="text-xs text-muted-foreground">Ajuste os filtros ou aguarde novos eventos.</span>
                </div>
              )}
              {alerts.map((a) => {
                const sev = severityMeta[a.level as Severity]
                const st = statusMeta[a.status as AlertStatus]
                const src = alertSource(a)
                const flag = a.source_ip ? countryFlag(ipInfo[a.source_ip]?.abuseipdb_country) : null
                const isBlocked = blockedEntryFor(a.source_ip) !== null
                return (
                  <div
                    key={a.id}
                    onClick={() => setSelectedId(a.id)}
                    className={cn(
                      'grid cursor-pointer grid-cols-[96px_84px_70px_1fr_92px_100px_130px_112px] items-center gap-0 rounded-md border-b border-border/60 px-2 py-3 hover:bg-white/[0.035]',
                      selectedId === a.id && 'bg-primary/[0.06]',
                    )}
                  >
                    <span className="font-mono text-[11.5px] text-muted-foreground">{formatTime(a.ts)}</span>
                    <span className={cn('font-mono text-[11px]', src ? sourceMeta[src].color : 'text-muted-foreground')}>
                      {src ? sourceMeta[src].label : '—'}
                    </span>
                    <span className={`w-14 rounded-md py-[3px] text-center text-[10px] font-semibold uppercase tracking-wide ${sev?.color ?? 'text-muted-foreground'} ${sev?.bg ?? ''}`}>
                      {sev?.label ?? a.level}
                    </span>
                    <span className="truncate pr-4 text-[13px] text-foreground">{a.title}</span>
                    <span className="w-fit rounded-md bg-primary/10 px-2 py-[3px] font-mono text-[10.5px] text-primary">{a.mitre_technique ?? '—'}</span>
                    <span className="truncate text-[12.5px] text-muted-foreground">{a.source_host ?? '—'}</span>
                    <span className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                      {flag && <span className="leading-none">{flag}</span>}
                      <span className="truncate">{a.source_ip ?? '—'}</span>
                      {isBlocked && <Ban className="h-3 w-3 shrink-0 text-destructive" />}
                    </span>
                    <span className={`flex items-center gap-1.5 text-[11px] ${st?.color ?? 'text-muted-foreground'}`}>
                      <span className={cn('h-1.5 w-1.5 rounded-full', st ? st.color.replace('text-', 'bg-') : 'bg-muted-foreground')} />
                      {st?.label ?? a.status}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {selected && <div onClick={() => setSelectedId(null)} className="fixed inset-0 z-10 bg-black/45 backdrop-blur-[1px]" />}

      <div
        className={cn(
          'fixed right-0 top-0 z-20 flex h-screen w-full flex-col border-l border-border bg-card shadow-[-20px_0_50px_rgba(0,0,0,0.4)] transition-transform duration-300 ease-out sm:w-[420px]',
          selected ? 'translate-x-0' : 'translate-x-full',
        )}
      >
        {selected && (
          <>
            <div className="flex shrink-0 items-center justify-between border-b border-border px-5.5 py-5">
              <span className="font-mono text-[11.5px] uppercase tracking-wide text-muted-foreground">Detalhe do alerta</span>
              <button
                type="button"
                onClick={() => setSelectedId(null)}
                className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-white/[0.08]"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex grow flex-col gap-5 overflow-y-auto p-5.5">
              <div className="flex items-center gap-2.5">
                {severityMeta[selected.level as Severity] && (
                  <span
                    className={`rounded-md px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wide ${severityMeta[selected.level as Severity].color} ${severityMeta[selected.level as Severity].bg}`}
                  >
                    {selected.level}
                  </span>
                )}
                <span className="font-mono text-[11px] text-muted-foreground">{formatTime(selected.ts)}</span>
              </div>

              <div className="font-heading text-[17px] font-semibold leading-snug text-foreground">{selected.title}</div>
              {selected.description && <div className="text-[13px] leading-relaxed text-muted-foreground">{selected.description}</div>}

              <div className="flex flex-col gap-2.5 rounded-lg border border-border bg-background p-4">
                <Row label="Técnica MITRE ATT&CK">
                  <span className="font-mono text-xs text-primary">{selected.mitre_technique ?? '—'}</span>
                </Row>
                <Row label="Host">
                  <span className="font-mono text-xs text-foreground">{selected.source_host ?? '—'}</span>
                </Row>
                <Row label="IP de origem">
                  <span className="flex items-center gap-1.5 font-mono text-xs text-foreground">
                    {selected.source_ip && countryFlag(ipInfo[selected.source_ip]?.abuseipdb_country)}
                    {selected.source_ip ?? '—'}
                  </span>
                </Row>
              </div>

              <div>
                <div className="mb-2 text-[11.5px] text-muted-foreground">Status</div>
                <div className="flex gap-2">
                  <StatusButton active={selected.status === 'open'} color="var(--destructive)" onClick={() => setStatus('open')}>
                    Aberto
                  </StatusButton>
                  <StatusButton active={selected.status === 'acknowledged'} color="var(--warning)" onClick={() => setStatus('acknowledged')}>
                    Reconhecido
                  </StatusButton>
                  <StatusButton active={selected.status === 'closed'} color="var(--muted-foreground)" onClick={() => setStatus('closed')}>
                    Fechado
                  </StatusButton>
                </div>
              </div>

              <div>
                <div className="mb-2 text-[11.5px] text-muted-foreground">Resposta</div>
                {(() => {
                  const entry = blockedEntryFor(selected.source_ip)
                  if (entry) {
                    return (
                      <div className="flex flex-col gap-2 rounded-lg border border-destructive/30 bg-destructive/[0.07] p-3.5">
                        <div className="flex items-center gap-2 text-[12.5px] text-destructive">
                          <Ban className="h-3.5 w-3.5 shrink-0" />
                          IP bloqueado no honeypot por {entry.blocked_by}
                        </div>
                        <button
                          type="button"
                          disabled={blocking}
                          onClick={() => handleUnblock(entry.ip)}
                          className="flex h-8 items-center justify-center gap-1.5 rounded-md border border-border text-xs font-medium text-foreground transition-opacity hover:opacity-85 disabled:opacity-50"
                        >
                          {blocking && <Loader2 className="h-3 w-3 animate-spin" />}
                          Desbloquear
                        </button>
                      </div>
                    )
                  }
                  return (
                    <div className="flex flex-col gap-2">
                      <button
                        type="button"
                        disabled={!selected.source_ip || blocking}
                        onClick={handleBlock}
                        className="flex h-9 items-center justify-center gap-1.5 rounded-md border border-destructive/40 text-xs font-medium text-destructive transition-opacity hover:opacity-85 disabled:opacity-40"
                      >
                        {blocking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Ban className="h-3.5 w-3.5" />}
                        Bloquear IP no honeypot
                      </button>
                      {!selected.source_ip && (
                        <span className="text-[11px] text-muted-foreground">Este alerta não tem IP de origem pra bloquear.</span>
                      )}
                    </div>
                  )
                })()}
                {blockActionError && <div className="mt-2 text-[11px] text-destructive">{blockActionError}</div>}
              </div>

              <div>
                <div className="mb-2 text-[11.5px] text-muted-foreground">Payload do evento correspondente</div>
                <pre className="whitespace-pre-wrap break-all rounded-lg border border-border bg-background p-3.5 font-mono text-[11px] leading-relaxed text-primary/80">
                  {JSON.stringify(selected.payload, null, 2)}
                </pre>
              </div>
            </div>
          </>
        )}
      </div>
    </AppShell>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between">
      <span className="text-[11.5px] text-muted-foreground">{label}</span>
      {children}
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
      style={active ? { background: color, borderColor: color, color: 'var(--primary-foreground)' } : { borderColor: 'rgba(255,255,255,0.16)', color }}
      className="h-[34px] flex-1 rounded-md border text-xs font-medium transition-opacity hover:opacity-85"
    >
      {children}
    </button>
  )
}
