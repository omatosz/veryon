import { useEffect, useState } from 'react'
import {
  Ban,
  CheckCircle2,
  Eye,
  FlaskConical,
  Gauge,
  Loader2,
  ShieldCheck,
  ShieldOff,
  Undo2,
  Zap,
} from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { FilterPill } from '@/components/ui/filter-pill'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { StatPill } from '@/components/ui/stat-pill'
import { cn } from '@/lib/utils'
import {
  blockIp,
  getCriticalQueue,
  getPreventionSummary,
  listPolicies,
  listPreventionActions,
  simulatePolicy,
  undoPreventionAction,
  updatePolicy,
  type ApiPolicy,
  type ApiPreventionAction,
  type ApiPreventionSummary,
  type ApiQueueItem,
  type ApiSimulatedCase,
} from '@/lib/api'
import { formatDateTime, formatTime } from '@/lib/format'

const POLL_INTERVAL_MS = 5000

const severityColor: Record<string, string> = {
  critical: '#EF4444',
  high: '#F59E0B',
  medium: '#3B82F6',
  low: '#22C55E',
}

const kindLabel: Record<ApiQueueItem['kind'], string> = {
  alert: 'Alerta',
  api_finding: 'API',
  vulnerability: 'Vulnerabilidade',
}

const statusMeta: Record<ApiPreventionAction['status'], { label: string; color: string }> = {
  applied: { label: 'aplicada', color: 'text-destructive' },
  simulated: { label: 'simulada', color: 'text-muted-foreground' },
  held: { label: 'segurada', color: 'text-warning' },
  undone: { label: 'desfeita', color: 'text-primary' },
  failed: { label: 'falhou', color: 'text-destructive' },
}

type Tab = 'queue' | 'policies' | 'trail'

export function PreventionPage() {
  const [tab, setTab] = useState<Tab>('queue')
  const [summary, setSummary] = useState<ApiPreventionSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    function load(isInitial: boolean) {
      if (isInitial) setLoading(true)
      getPreventionSummary()
        .then((s) => {
          if (cancelled) return
          setSummary(s)
          setError(null)
        })
        .catch((err) => {
          if (cancelled) return
          setError(err instanceof Error ? err.message : 'Erro ao carregar a prevenção')
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

  return (
    <AppShell title="Prevenção de ameaça">
      <div className="flex shrink-0 flex-wrap items-center gap-3 px-4 pt-5 sm:px-8">
        <StatPill
          icon={Zap}
          tone="text-destructive"
          bg="bg-destructive/12"
          value={summary?.queue_size ?? 0}
          label="na fila"
          hint="críticos e altos"
        />
        <StatPill
          icon={ShieldCheck}
          tone="text-success"
          bg="bg-success/12"
          value={summary?.policies_enforcing ?? 0}
          label="em vigor"
          hint={`de ${summary?.policies_total ?? 0} políticas`}
        />
        <StatPill
          icon={Eye}
          tone="text-primary"
          bg="bg-primary/12"
          value={summary?.policies_observing ?? 0}
          label="observando"
          hint="só registram"
        />
        <CeilingGauge used={summary?.blocks_last_hour ?? 0} ceiling={summary?.blocks_ceiling ?? 10} />
      </div>

      <div className="flex shrink-0 items-center gap-2.5 px-4 pt-4 sm:px-8">
        <FilterPill active={tab === 'queue'} onClick={() => setTab('queue')} activeColor="var(--destructive)">
          Fila crítica
        </FilterPill>
        <FilterPill active={tab === 'policies'} onClick={() => setTab('policies')}>
          Políticas
        </FilterPill>
        <FilterPill active={tab === 'trail'} onClick={() => setTab('trail')}>
          Trilha de ações
        </FilterPill>
        {summary && summary.held_24h > 0 && (
          <span className="ml-auto font-mono text-[11px] text-warning">
            {summary.held_24h} ação(ões) segurada(s) por trilho em 24h
          </span>
        )}
      </div>

      {loading ? (
        <LoadingState label="Carregando prevenção…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : tab === 'queue' ? (
        <CriticalQueue />
      ) : tab === 'policies' ? (
        <PolicyList />
      ) : (
        <ActionTrail />
      )}
    </AppShell>
  )
}

function CriticalQueue() {
  const [items, setItems] = useState<ApiQueueItem[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState<string | null>(null)
  const [feedback, setFeedback] = useState<{ key: string; msg: string; ok: boolean } | null>(null)

  useEffect(() => {
    let cancelled = false
    function load() {
      getCriticalQueue()
        .then((rows) => !cancelled && setItems(rows))
        .finally(() => !cancelled && setLoading(false))
    }
    load()
    const id = setInterval(load, POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  async function handleBlock(item: ApiQueueItem) {
    if (!item.target) return
    const key = `${item.kind}-${item.id}`
    setBusy(key)
    setFeedback(null)
    try {
      await blockIp(item.target, `Bloqueio manual pela fila crítica: ${item.title}`.slice(0, 200), 60)
      setFeedback({ key, msg: `${item.target} bloqueado por 60 min`, ok: true })
    } catch (err) {
      setFeedback({ key, msg: err instanceof Error ? err.message : 'Falhou', ok: false })
    } finally {
      setBusy(null)
    }
  }

  if (loading) return <LoadingState label="Carregando fila…" />

  return (
    <div className="flex min-h-0 grow flex-col overflow-y-auto px-4 pb-10 pt-4 sm:px-8">
      {items.length === 0 && (
        <div className="flex flex-col items-center gap-1.5 py-14 text-center">
          <CheckCircle2 className="mb-1 h-7 w-7 text-success" strokeWidth={1.5} />
          <span className="text-sm text-foreground">Nada crítico esperando tratativa</span>
          <span className="text-xs text-muted-foreground">
            Alertas críticos, chamadores perigosos de API e vulnerabilidades críticas caem aqui.
          </span>
        </div>
      )}

      <div className="flex flex-col gap-2">
        {items.map((item) => {
          const key = `${item.kind}-${item.id}`
          const cor = severityColor[item.severity] ?? '#8E8EA3'
          const podeBloquear = Boolean(item.target) && item.kind !== 'vulnerability'
          return (
            <div
              key={key}
              className="flex items-start gap-3 rounded-xl border border-border bg-card p-4"
              style={{ borderLeftColor: cor, borderLeftWidth: 3 }}
            >
              <div className="flex min-w-0 grow flex-col gap-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className="rounded px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-wide"
                    style={{ color: cor, background: `${cor}1F` }}
                  >
                    {item.severity}
                  </span>
                  <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide text-muted-foreground">
                    {kindLabel[item.kind]}
                  </span>
                  {item.target && <span className="font-mono text-[11px] text-muted-foreground">{item.target}</span>}
                  <span className="font-mono text-[10.5px] text-muted-foreground/70">{formatDateTime(item.ts)}</span>
                </div>
                <span className="text-[13.5px] leading-snug text-foreground">{item.title}</span>
                {item.detail && (
                  <span className="line-clamp-2 text-[11.5px] leading-relaxed text-muted-foreground">{item.detail}</span>
                )}
                {feedback?.key === key && (
                  <span className={cn('mt-0.5 text-[11px]', feedback.ok ? 'text-success' : 'text-destructive')}>
                    {feedback.msg}
                  </span>
                )}
              </div>

              {podeBloquear && (
                <button
                  type="button"
                  disabled={busy === key}
                  onClick={() => handleBlock(item)}
                  className="flex h-8 shrink-0 items-center gap-1.5 rounded-md border border-destructive/40 px-3 text-[12px] font-medium text-destructive transition-colors hover:bg-destructive/10 disabled:opacity-50"
                >
                  {busy === key ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Ban className="h-3.5 w-3.5" />}
                  Bloquear 60 min
                </button>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function PolicyList() {
  const [policies, setPolicies] = useState<ApiPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [errorById, setErrorById] = useState<Record<number, string>>({})
  const [simById, setSimById] = useState<Record<number, ApiSimulatedCase[] | 'loading'>>({})

  useEffect(() => {
    listPolicies()
      .then(setPolicies)
      .finally(() => setLoading(false))
  }, [])

  async function toggleMode(p: ApiPolicy) {
    setBusyId(p.id)
    setErrorById((prev) => ({ ...prev, [p.id]: '' }))
    try {
      const next = await updatePolicy(p.id, { mode: p.mode === 'enforce' ? 'observe' : 'enforce' })
      setPolicies((prev) => prev.map((x) => (x.id === p.id ? next : x)))
    } catch (err) {
      setErrorById((prev) => ({
        ...prev,
        [p.id]: err instanceof Error ? err.message : 'Não foi possível mudar o modo',
      }))
    } finally {
      setBusyId(null)
    }
  }

  async function toggleEnabled(p: ApiPolicy) {
    setBusyId(p.id)
    try {
      const next = await updatePolicy(p.id, { enabled: !p.enabled })
      setPolicies((prev) => prev.map((x) => (x.id === p.id ? next : x)))
    } finally {
      setBusyId(null)
    }
  }

  async function runSimulation(p: ApiPolicy) {
    setSimById((prev) => ({ ...prev, [p.id]: 'loading' }))
    try {
      const res = await simulatePolicy(p.id)
      setSimById((prev) => ({ ...prev, [p.id]: res.simulacao }))
    } catch {
      setSimById((prev) => ({ ...prev, [p.id]: [] }))
    }
  }

  if (loading) return <LoadingState label="Carregando políticas…" />

  return (
    <div className="flex min-h-0 grow flex-col overflow-y-auto px-4 pb-10 pt-4 sm:px-8">
      <p className="mb-3 max-w-[760px] text-[12px] leading-relaxed text-muted-foreground">
        Toda política nasce observando. Nesse modo ela reconhece os casos e registra o que teria feito, sem tocar em nada.
        Antes de colocar uma em vigor, rode a simulação: ela mostra os alvos de agora e quais seriam segurados pelos
        trilhos de segurança.
      </p>

      <div className="flex flex-col gap-2">
        {policies.map((p) => {
          const emVigor = p.mode === 'enforce'
          const sim = simById[p.id]
          return (
            <div key={p.id} className={cn('rounded-xl border bg-card p-4', emVigor ? 'border-success/35' : 'border-border')}>
              <div className="flex flex-wrap items-start gap-3">
                <div className="flex min-w-0 grow flex-col gap-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-primary/12 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary">
                      {p.code}
                    </span>
                    <span className="text-[13.5px] font-medium text-foreground">{p.name}</span>
                    <span
                      className={cn(
                        'rounded px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-wide',
                        p.action === 'block_ip' ? 'bg-destructive/14 text-destructive' : 'bg-[#A78BFA]/14 text-[#A78BFA]',
                      )}
                    >
                      {p.action === 'block_ip' ? `bloqueia ${p.ttl_minutes} min` : 'escala'}
                    </span>
                    {!p.enabled && (
                      <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[9.5px] uppercase text-muted-foreground">
                        desligada
                      </span>
                    )}
                  </div>
                  <span className="text-[12px] leading-relaxed text-muted-foreground">{p.description}</span>
                  <span className="font-mono text-[10.5px] text-muted-foreground/70">
                    {p.match_count} caso(s) reconhecido(s)
                    {p.last_match_at && ` · último às ${formatTime(p.last_match_at)}`}
                    {p.updated_by && ` · alterada por ${p.updated_by}`}
                  </span>
                  {errorById[p.id] && <span className="text-[11px] text-destructive">{errorById[p.id]}</span>}
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => runSimulation(p)}
                    className="flex h-8 items-center gap-1.5 rounded-md border border-border px-2.5 text-[11.5px] text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground"
                  >
                    {sim === 'loading' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="h-3.5 w-3.5" />}
                    Simular
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleEnabled(p)}
                    disabled={busyId === p.id}
                    title={p.enabled ? 'Desligar a política' : 'Ligar a política'}
                    className="flex h-8 w-8 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:bg-white/[0.06] disabled:opacity-50"
                  >
                    <ShieldOff className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleMode(p)}
                    disabled={busyId === p.id || !p.enabled}
                    className={cn(
                      'flex h-8 items-center gap-1.5 rounded-md px-3 text-[12px] font-semibold transition-opacity hover:opacity-90 disabled:opacity-40',
                      emVigor ? 'bg-success text-[#0A0A0F]' : 'border border-border text-foreground',
                    )}
                  >
                    {busyId === p.id ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : emVigor ? (
                      <ShieldCheck className="h-3.5 w-3.5" />
                    ) : (
                      <Eye className="h-3.5 w-3.5" />
                    )}
                    {emVigor ? 'Em vigor' : 'Observando'}
                  </button>
                </div>
              </div>

              {Array.isArray(sim) && (
                <div className="mt-3 rounded-lg border border-border bg-background p-3">
                  <div className="mb-1.5 text-[11px] uppercase tracking-wide text-muted-foreground">
                    Simulação · {sim.length} caso(s) com os dados de agora
                  </div>
                  {sim.length === 0 ? (
                    <div className="text-[11.5px] text-muted-foreground">
                      Nenhum caso se encaixa nessa política no momento.
                    </div>
                  ) : (
                    <div className="flex flex-col gap-1">
                      {sim.map((c, i) => (
                        <div key={i} className="flex flex-wrap items-center gap-2 text-[11.5px]">
                          <span className="font-mono text-foreground">{c.target}</span>
                          {c.seria_segurado ? (
                            <span className="rounded bg-warning/14 px-1.5 py-0.5 text-[10px] text-warning">
                              seria segurado: {c.seria_segurado}
                            </span>
                          ) : (
                            <span className="rounded bg-destructive/14 px-1.5 py-0.5 text-[10px] text-destructive">
                              {c.acao === 'block_ip' ? 'seria bloqueado' : 'seria escalado'}
                            </span>
                          )}
                          <span className="min-w-0 truncate text-muted-foreground">{c.reason}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ActionTrail() {
  const [actions, setActions] = useState<ApiPreventionAction[]>([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [erro, setErro] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    function load() {
      listPreventionActions()
        .then((rows) => !cancelled && setActions(rows))
        .finally(() => !cancelled && setLoading(false))
    }
    load()
    const id = setInterval(load, POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  async function handleUndo(a: ApiPreventionAction) {
    setBusyId(a.id)
    setErro(null)
    try {
      const next = await undoPreventionAction(a.id)
      setActions((prev) => prev.map((x) => (x.id === a.id ? next : x)))
    } catch (err) {
      setErro(err instanceof Error ? err.message : 'Não foi possível desfazer')
    } finally {
      setBusyId(null)
    }
  }

  if (loading) return <LoadingState label="Carregando trilha…" />

  return (
    <div className="flex min-h-0 grow flex-col overflow-x-auto px-4 pb-10 pt-4 sm:px-8">
      <p className="mb-3 max-w-[760px] text-[12px] leading-relaxed text-muted-foreground">
        Tudo que a prevenção fez, simulou ou deixou de fazer, e o motivo. Ação segurada por trilho aparece com o trilho
        que a segurou. Desfazer não apaga a linha, marca ela.
      </p>
      {erro && <div className="mb-2 text-[11.5px] text-destructive">{erro}</div>}

      <div className="flex min-w-[880px] grow flex-col">
        <div className="grid shrink-0 grid-cols-[86px_100px_130px_1fr_96px_100px] border-b border-border px-2 pb-2.5">
          {['Hora', 'Política', 'Alvo', 'Motivo', 'Desfecho', ''].map((h, i) => (
            <span key={i} className="text-[10.5px] uppercase tracking-wide text-muted-foreground">
              {h}
            </span>
          ))}
        </div>
        <div className="grow overflow-y-auto">
          {actions.length === 0 && (
            <div className="py-12 text-center text-sm text-muted-foreground">Nenhuma ação registrada ainda.</div>
          )}
          {actions.map((a) => {
            const st = statusMeta[a.status]
            return (
              <div
                key={a.id}
                className="grid grid-cols-[86px_100px_130px_1fr_96px_100px] items-center border-b border-border/60 px-2 py-2.5"
              >
                <span className="font-mono text-[11px] text-muted-foreground">{formatTime(a.ts)}</span>
                <span className="font-mono text-[10.5px] text-primary">{a.policy_code ?? 'manual'}</span>
                <span className="truncate pr-2 font-mono text-[11.5px] text-foreground">{a.target}</span>
                <span className="min-w-0 pr-3">
                  <span className="block truncate text-[11.5px] text-muted-foreground">{a.reason}</span>
                  {a.rail && <span className="block truncate text-[10px] text-warning">trilho: {a.rail}</span>}
                  {a.undone_by && <span className="block text-[10px] text-primary">desfeita por {a.undone_by}</span>}
                </span>
                <span className={cn('text-[11px]', st.color)}>{st.label}</span>
                <span>
                  {a.status === 'applied' && (
                    <button
                      type="button"
                      disabled={busyId === a.id}
                      onClick={() => handleUndo(a)}
                      className="flex h-7 items-center gap-1.5 rounded-md border border-border px-2.5 text-[11px] text-foreground transition-colors hover:bg-white/[0.06] disabled:opacity-50"
                    >
                      {busyId === a.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Undo2 className="h-3 w-3" />}
                      Desfazer
                    </button>
                  )}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function CeilingGauge({ used, ceiling }: { used: number; ceiling: number }) {
  const pct = Math.min(100, (used / Math.max(ceiling, 1)) * 100)
  const cor = pct >= 80 ? '#EF4444' : pct >= 50 ? '#F59E0B' : '#22C55E'
  return (
    <div className="flex items-center gap-3 rounded-xl border border-border bg-card px-4 py-2.5">
      <Gauge className="h-4 w-4 shrink-0" style={{ color: cor }} strokeWidth={2} />
      <div className="leading-tight">
        <div className="font-heading text-[14px] font-semibold text-foreground">
          {used}
          <span className="text-[11px] font-medium text-muted-foreground">/{ceiling}</span>
        </div>
        <div className="text-[10.5px] text-muted-foreground">bloqueios automáticos na última hora</div>
      </div>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-white/[0.08]">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: cor }} />
      </div>
    </div>
  )
}
