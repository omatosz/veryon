import { useEffect, useMemo, useRef, useState } from 'react'
import { Activity, Radio, Search, Server, X } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { FilterPill } from '@/components/ui/filter-pill'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { StatPill } from '@/components/ui/stat-pill'
import { cn } from '@/lib/utils'
import { getEnrichment, listEvents, type ApiEnrichment, type ApiEvent } from '@/lib/api'
import { countryFlag, formatTime } from '@/lib/format'
import { sourceMeta, type EventSource } from '@/lib/mock-data'

type SourceFilter = EventSource | 'all'

const POLL_INTERVAL_MS = 5000

export function EventsPage() {
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all')
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [events, setEvents] = useState<ApiEvent[]>([])
  const [ipInfo, setIpInfo] = useState<Record<string, ApiEnrichment | null>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    function load(isInitial: boolean) {
      if (isInitial) setLoading(true)
      listEvents({ source: sourceFilter === 'all' ? undefined : sourceFilter, limit: 200 })
        .then((data) => {
          if (cancelled) return
          setEvents(data)
          setError(null)
        })
        .catch((err) => {
          if (cancelled) return
          setError(err instanceof Error ? err.message : 'Erro ao carregar eventos')
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
  }, [sourceFilter])

  const fetchedIps = useRef(new Set<string>())

  useEffect(() => {
    const uniqueIps = [...new Set(events.map((e) => e.src_ip).filter((ip): ip is string => !!ip))].slice(0, 15)
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
  }, [events])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return events
    return events.filter(
      (e) =>
        e.event_type.toLowerCase().includes(q) ||
        (e.host ?? '').toLowerCase().includes(q) ||
        (e.src_ip ?? '').toLowerCase().includes(q),
    )
  }, [events, query])

  const selected = events.find((e) => e.id === selectedId) ?? null

  const stats = useMemo(() => {
    const sources = new Set(events.map((e) => e.source))
    const withIp = events.filter((e) => e.src_ip).length
    return { total: events.length, sources: sources.size, withIp }
  }, [events])

  return (
    <AppShell title="Eventos">
      <div className="flex shrink-0 flex-wrap gap-3 px-4 pt-5 sm:px-8">
        <StatPill icon={Activity} tone="text-primary" bg="bg-primary/12" value={stats.total} label="eventos" hint="nesse filtro" />
        <StatPill icon={Server} tone="text-chart-4" bg="bg-chart-4/12" value={stats.sources} label="fontes ativas" hint="linux/windows/cowrie/scanner" />
        <StatPill icon={Radio} tone="text-warning" bg="bg-warning/12" value={stats.withIp} label="com IP de origem" hint="nesse filtro" />
      </div>

      <div className="flex shrink-0 flex-col gap-3.5 px-4 pt-3.5 sm:px-8">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="mr-1 text-[11.5px] uppercase tracking-wide text-muted-foreground">Fonte</span>
          <FilterPill active={sourceFilter === 'all'} onClick={() => setSourceFilter('all')}>
            Todas
          </FilterPill>
          <FilterPill active={sourceFilter === 'linux'} onClick={() => setSourceFilter('linux')} activeColor="var(--chart-2)">
            linux
          </FilterPill>
          <FilterPill active={sourceFilter === 'windows'} onClick={() => setSourceFilter('windows')} activeColor="var(--chart-3)">
            windows
          </FilterPill>
          <FilterPill active={sourceFilter === 'cowrie'} onClick={() => setSourceFilter('cowrie')} activeColor="var(--destructive)">
            cowrie
          </FilterPill>
          <FilterPill active={sourceFilter === 'scanner'} onClick={() => setSourceFilter('scanner')} activeColor="var(--chart-4)">
            scanner
          </FilterPill>

          <div className="relative ml-0 flex items-center sm:ml-2">
            <Search className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Buscar por tipo, host ou IP…"
              className="h-[30px] w-[220px] rounded-full border border-white/10 bg-transparent pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground outline-none focus-visible:border-ring"
            />
          </div>

          <span className="ml-auto font-mono text-xs text-muted-foreground">{loading ? '…' : `${filtered.length} resultado(s)`}</span>
        </div>
      </div>

      {loading ? (
        <LoadingState label="Carregando eventos…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : (
        <div className="flex min-h-0 grow flex-col overflow-x-auto px-4 pb-10 sm:px-8">
          <div className="flex min-w-[760px] grow flex-col">
            <div className="grid shrink-0 grid-cols-[120px_100px_1fr_120px_130px] gap-0 border-b border-border px-2 pb-2.5 pt-4">
              {['Quando', 'Fonte', 'Tipo de evento', 'Host', 'IP origem'].map((h) => (
                <span key={h} className="text-[10.5px] uppercase tracking-wide text-muted-foreground">
                  {h}
                </span>
              ))}
            </div>

            <div className="grow overflow-y-auto">
              {filtered.map((e) => {
                const src = sourceMeta[e.source as EventSource]
                const flag = e.src_ip ? countryFlag(ipInfo[e.src_ip]?.abuseipdb_country) : null
                return (
                  <div
                    key={e.id}
                    onClick={() => setSelectedId(e.id)}
                    className={cn(
                      'grid cursor-pointer grid-cols-[120px_100px_1fr_120px_130px] items-center gap-0 rounded-md border-b border-border/60 px-2 py-3 hover:bg-white/[0.035]',
                      selectedId === e.id && 'bg-primary/[0.06]',
                    )}
                  >
                    <span className="font-mono text-[11.5px] text-muted-foreground">{formatTime(e.ts)}</span>
                    <span className={cn('font-mono text-[11.5px]', src?.color ?? 'text-muted-foreground')}>{src?.label ?? e.source}</span>
                    <span className="truncate pr-4 font-mono text-[12.5px] text-foreground">{e.event_type}</span>
                    <span className="truncate text-[12.5px] text-muted-foreground">{e.host ?? '—'}</span>
                    <span className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                      {flag && <span className="leading-none">{flag}</span>}
                      <span className="truncate">{e.src_ip ?? '—'}</span>
                    </span>
                  </div>
                )
              })}

              {filtered.length === 0 && (
                <div className="flex flex-col items-center gap-1.5 py-14 text-center">
                  <span className="text-sm text-foreground">Nenhum evento encontrado</span>
                  <span className="text-xs text-muted-foreground">Ajuste os filtros ou o termo de busca.</span>
                </div>
              )}
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
              <span className="font-mono text-[11.5px] uppercase tracking-wide text-muted-foreground">Detalhe do evento</span>
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
                <span className={cn('font-mono text-[11.5px]', sourceMeta[selected.source as EventSource]?.color ?? 'text-muted-foreground')}>
                  {sourceMeta[selected.source as EventSource]?.label ?? selected.source}
                </span>
                <span className="font-mono text-[11px] text-muted-foreground">{formatTime(selected.ts)}</span>
              </div>

              <div className="font-heading text-[17px] font-semibold leading-snug text-foreground">{selected.event_type}</div>

              <div className="flex flex-col gap-2.5 rounded-lg border border-border bg-background p-4">
                <Row label="Host">
                  <span className="font-mono text-xs text-foreground">{selected.host ?? '—'}</span>
                </Row>
                <Row label="IP de origem">
                  <span className="flex items-center gap-1.5 font-mono text-xs text-foreground">
                    {selected.src_ip && countryFlag(ipInfo[selected.src_ip]?.abuseipdb_country)}
                    {selected.src_ip ?? '—'}
                  </span>
                </Row>
              </div>

              <div>
                <div className="mb-2 text-[11.5px] text-muted-foreground">Payload bruto</div>
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
