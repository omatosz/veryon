import { useEffect, useMemo, useState } from 'react'
import { Activity, Lock, Radar, ShieldAlert } from 'lucide-react'
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import { AppShell } from '@/components/layout/AppShell'
import { AlertsChartCard } from '@/components/dashboard/AlertsChartCard'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { StatPill } from '@/components/ui/stat-pill'
import { getEnrichment, getSummary, listAlerts, type ApiAlert, type ApiEnrichment, type ApiSummary } from '@/lib/api'
import { countryFlag } from '@/lib/format'

const POLL_INTERVAL_MS = 5000

export function DashboardPage() {
  const [summary, setSummary] = useState<ApiSummary | null>(null)
  const [alerts, setAlerts] = useState<ApiAlert[]>([])
  const [attackerInfo, setAttackerInfo] = useState<Record<string, ApiEnrichment | null>>({})
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    function load(isInitial: boolean) {
      if (isInitial) setLoading(true)
      Promise.all([getSummary(), listAlerts({ limit: 500 })])
        .then(([s, a]) => {
          if (cancelled) return
          setSummary(s)
          setAlerts(a)
          setError(null)
        })
        .catch((err) => {
          if (cancelled) return
          setError(err instanceof Error ? err.message : 'Erro ao carregar dados')
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

  useEffect(() => {
    if (!summary) return
    let cancelled = false
    const topIps = summary.top_src_ips.slice(0, 6)
    Promise.allSettled(topIps.map((ip) => getEnrichment(ip.src_ip))).then((results) => {
      if (cancelled) return
      const map: Record<string, ApiEnrichment | null> = {}
      topIps.forEach((ip, i) => {
        const r = results[i]
        map[ip.src_ip] = r.status === 'fulfilled' ? r.value : null
      })
      setAttackerInfo(map)
    })
    return () => {
      cancelled = true
    }
  }, [summary])

  const mitreBreakdown = useMemo(() => buildMitreBreakdown(alerts), [alerts])
  const topHosts = useMemo(() => buildTopHosts(alerts), [alerts])

  if (loading) {
    return (
      <AppShell title="Dashboard">
        <LoadingState />
      </AppShell>
    )
  }

  if (error || !summary) {
    return (
      <AppShell title="Dashboard">
        <ErrorState message={error ?? 'Erro desconhecido'} />
      </AppShell>
    )
  }

  const openAlertCount = alerts.filter((a) => a.status !== 'closed').length
  const highCount = summary.alerts_by_level.high ?? 0
  const eventsBySource = Object.entries(summary.events_by_source)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
  const maxSourceCount = Math.max(1, ...eventsBySource.map((s) => s.count))

  return (
    <AppShell title="Dashboard">
      <div className="grow overflow-y-auto px-4 pb-14 pt-6 sm:px-8">
        <div className="flex flex-wrap gap-3">
          <StatPill icon={ShieldAlert} tone="text-destructive" bg="bg-destructive/12" value={openAlertCount} label="alertas abertos" hint="no momento" />
          <StatPill icon={Radar} tone="text-warning" bg="bg-warning/12" value={highCount} label="alertas high" hint="no total" />
          <StatPill icon={Activity} tone="text-primary" bg="bg-primary/12" value={summary.total_events} label="eventos ingeridos" hint="total no banco" />
        </div>

        <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-[1.9fr_1fr]">
          <AlertsChartCard />

          <div className="rounded-xl border border-border bg-card p-5.5">
            <h2 className="mb-3.5 font-heading text-[14.5px] font-semibold text-foreground">Principais atacantes</h2>
            {summary.top_src_ips.length === 0 ? (
              <EmptyHint text="Nenhum IP de origem registrado ainda." />
            ) : (
              <div className="flex flex-col">
                {summary.top_src_ips.slice(0, 6).map((ip) => {
                  const info = attackerInfo[ip.src_ip]
                  const flag = countryFlag(info?.abuseipdb_country)
                  return (
                    <div key={ip.src_ip} className="flex items-center gap-2.5 border-b border-border/60 py-2.5 last:border-b-0">
                      {flag ? (
                        <span className="text-base leading-none">{flag}</span>
                      ) : (
                        <Lock className="h-3.5 w-3.5 shrink-0 text-muted-foreground" strokeWidth={1.75} />
                      )}
                      <div className="min-w-0 grow">
                        <div className="truncate font-mono text-[12.5px] text-foreground">{ip.src_ip}</div>
                        <div className="mt-0.5 truncate text-[10.5px] text-muted-foreground">
                          {info?.abuseipdb_isp ?? 'IP privado / sem reputação pública'}
                        </div>
                      </div>
                      <span className="shrink-0 font-mono text-[11.5px] text-muted-foreground">{ip.count}</span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-3">
          <div className="rounded-xl border border-border bg-card p-5.5">
            <h2 className="mb-3.5 font-heading text-[14.5px] font-semibold text-foreground">Padrões (técnica MITRE)</h2>
            {mitreBreakdown.length === 0 ? (
              <EmptyHint text="Nenhum alerta gerado ainda." />
            ) : (
              <div style={{ height: Math.max(140, mitreBreakdown.length * 30) }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={mitreBreakdown} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                    <XAxis type="number" allowDecimals={false} tick={{ fill: '#8E8EA3', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis
                      type="category"
                      dataKey="technique"
                      tick={{ fill: '#8E8EA3', fontSize: 10.5 }}
                      axisLine={false}
                      tickLine={false}
                      width={78}
                    />
                    <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                    <Bar dataKey="count" fill="var(--primary)" radius={[0, 4, 4, 0]} barSize={12} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          <div className="rounded-xl border border-border bg-card p-5.5">
            <h2 className="mb-3.5 font-heading text-[14.5px] font-semibold text-foreground">Principais alvos</h2>
            {topHosts.length === 0 ? (
              <EmptyHint text="Nenhum alerta gerado ainda." />
            ) : (
              <div className="flex flex-col">
                {topHosts.map((h) => (
                  <div key={h.host} className="flex items-center justify-between border-b border-border/60 py-2 last:border-b-0">
                    <span className="truncate font-mono text-[12px] text-foreground">{h.host}</span>
                    <span className="shrink-0 text-[11.5px] text-muted-foreground">{h.count} alertas</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="rounded-xl border border-border bg-card p-5.5">
            <h2 className="mb-4 font-heading text-[14.5px] font-semibold text-foreground">Eventos por fonte</h2>
            {eventsBySource.length === 0 ? (
              <EmptyHint text="Nenhum evento ingerido ainda." />
            ) : (
              <div className="flex flex-col gap-3.5">
                {eventsBySource.map((s) => (
                  <div key={s.name}>
                    <div className="mb-1.5 flex justify-between text-xs">
                      <span className="font-mono text-muted-foreground">{s.name}</span>
                      <span className="text-foreground">{s.count}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                      <div className="h-full rounded-full bg-primary" style={{ width: `${(s.count / maxSourceCount) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  )
}

function buildMitreBreakdown(alerts: ApiAlert[]) {
  const counts = new Map<string, number>()
  for (const a of alerts) {
    const key = a.mitre_technique ?? 'sem técnica'
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([technique, count]) => ({ technique, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 7)
}

function buildTopHosts(alerts: ApiAlert[]) {
  const counts = new Map<string, number>()
  for (const a of alerts) {
    if (!a.source_host) continue
    counts.set(a.source_host, (counts.get(a.source_host) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([host, count]) => ({ host, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6)
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-white/10 bg-[#161620] px-3 py-2 text-[11px] shadow-lg">
      {label && <div className="mb-1 font-mono text-muted-foreground">{label}</div>}
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color }} />
          <span className="text-foreground">{p.name}:</span>
          <span className="font-mono text-foreground">{p.value}</span>
        </div>
      ))}
    </div>
  )
}

function EmptyHint({ text }: { text: string }) {
  return <div className="py-6 text-center text-xs text-muted-foreground">{text}</div>
}
