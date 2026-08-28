import { useEffect, useState } from 'react'
import { Bug, Loader2, RotateCw, ShieldAlert, X } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { FilterPill } from '@/components/ui/filter-pill'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { StatPill } from '@/components/ui/stat-pill'
import { cn } from '@/lib/utils'
import {
  getVulnSummary,
  listVulnerabilities,
  requestScan,
  updateVulnerability,
  type ApiVulnerability,
  type ApiVulnSummary,
  type Severity,
  type VulnStatus,
} from '@/lib/api'
import { formatTime } from '@/lib/format'

const POLL_INTERVAL_MS = 5000

const severityMeta: Record<Severity, { label: string; color: string; bg: string; dot: string }> = {
  critical: { label: 'crítica', color: 'text-[#FF8080]', bg: 'bg-destructive/16', dot: '#EF4444' },
  high: { label: 'alta', color: 'text-warning', bg: 'bg-warning/16', dot: '#F59E0B' },
  medium: { label: 'média', color: 'text-[#7FB0FF]', bg: 'bg-[#3B82F6]/16', dot: '#3B82F6' },
  low: { label: 'baixa', color: 'text-success', bg: 'bg-success/14', dot: '#22C55E' },
  info: { label: 'info', color: 'text-muted-foreground', bg: 'bg-white/[0.06]', dot: '#8E8EA3' },
}

const statusMeta: Record<VulnStatus, { label: string; color: string }> = {
  open: { label: 'Aberta', color: 'text-destructive' },
  in_progress: { label: 'Em tratamento', color: 'text-primary' },
  remediated: { label: 'Corrigida', color: 'text-success' },
  accepted_risk: { label: 'Risco aceito', color: 'text-[#A78BFA]' },
}

type StatusFilter = VulnStatus | 'all'
type TypeFilter = 'all' | 'web' | 'rede'

export function VulnerabilitiesPage() {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')
  const [vulns, setVulns] = useState<ApiVulnerability[]>([])
  const [summary, setSummary] = useState<ApiVulnSummary | null>(null)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const [requestingScan, setRequestingScan] = useState(false)

  useEffect(() => {
    let cancelled = false

    function load(isInitial: boolean) {
      if (isInitial) setLoading(true)
      Promise.all([
        listVulnerabilities({
          status: statusFilter === 'all' ? undefined : statusFilter,
          asset_type: typeFilter === 'all' ? undefined : typeFilter,
        }),
        getVulnSummary(),
      ])
        .then(([list, sum]) => {
          if (cancelled) return
          setVulns(list)
          setSummary(sum)
          setError(null)
        })
        .catch((err) => {
          if (cancelled) return
          setError(err instanceof Error ? err.message : 'Erro ao carregar vulnerabilidades')
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
  }, [statusFilter, typeFilter])

  const selected = vulns.find((v) => v.id === selectedId) ?? null
  const lastScan = summary?.last_scan ?? null
  // Enquanto tem varredura na fila ou rodando, o botão fica travado. O poll de
  // 5s destrava sozinho quando ela termina.
  const scanRunning = lastScan?.status === 'queued' || lastScan?.status === 'running'

  async function handleScan() {
    if (requestingScan || scanRunning) return
    setRequestingScan(true)
    setScanError(null)
    try {
      const job = await requestScan()
      setSummary((prev) => (prev ? { ...prev, last_scan: job } : prev))
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Não foi possível pedir a varredura')
    } finally {
      setRequestingScan(false)
    }
  }

  function applyUpdate(updated: ApiVulnerability) {
    setVulns((prev) => prev.map((v) => (v.id === updated.id ? updated : v)))
  }

  const sev = summary?.by_severity ?? {}

  return (
    <AppShell title="Vulnerabilidades">
      <div className="flex shrink-0 flex-wrap items-center gap-3 px-4 pt-5 sm:px-8">
        <StatPill
          icon={ShieldAlert}
          tone="text-destructive"
          bg="bg-destructive/12"
          value={(sev.critical ?? 0) + (sev.high ?? 0)}
          label="críticas e altas"
          hint="em aberto"
        />
        <StatPill icon={Bug} tone="text-primary" bg="bg-primary/12" value={summary?.total_open ?? 0} label="em aberto" hint="no total" />
        <RiskGauge score={summary?.risk_score ?? 0} />

        <div className="ml-auto flex flex-col items-end gap-1.5">
          <button
            type="button"
            onClick={handleScan}
            disabled={requestingScan || scanRunning}
            className="flex h-9 items-center gap-2 rounded-lg bg-primary px-4 font-heading text-[13px] font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {requestingScan || scanRunning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCw className="h-3.5 w-3.5" />}
            {scanRunning ? 'Varredura em andamento…' : 'Rodar varredura agora'}
          </button>
          <ScanHint job={lastScan} error={scanError} />
        </div>
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-2.5 px-4 pt-4 sm:px-8">
        <span className="mr-1 text-[11.5px] uppercase tracking-wide text-muted-foreground">Status</span>
        <FilterPill active={statusFilter === 'all'} onClick={() => setStatusFilter('all')}>
          Todas
        </FilterPill>
        <FilterPill active={statusFilter === 'open'} onClick={() => setStatusFilter('open')} activeColor="var(--destructive)">
          Abertas
        </FilterPill>
        <FilterPill active={statusFilter === 'in_progress'} onClick={() => setStatusFilter('in_progress')}>
          Em tratamento
        </FilterPill>
        <FilterPill active={statusFilter === 'remediated'} onClick={() => setStatusFilter('remediated')} activeColor="var(--success)">
          Corrigidas
        </FilterPill>
        <FilterPill active={statusFilter === 'accepted_risk'} onClick={() => setStatusFilter('accepted_risk')}>
          Risco aceito
        </FilterPill>

        <span className="mx-1.5 h-5 w-px bg-border" />

        <span className="mr-1 text-[11.5px] uppercase tracking-wide text-muted-foreground">Tipo</span>
        <FilterPill active={typeFilter === 'all'} onClick={() => setTypeFilter('all')}>
          Todos
        </FilterPill>
        <FilterPill active={typeFilter === 'web'} onClick={() => setTypeFilter('web')}>
          Web
        </FilterPill>
        <FilterPill active={typeFilter === 'rede'} onClick={() => setTypeFilter('rede')}>
          Rede
        </FilterPill>

        <span className="ml-auto font-mono text-xs text-muted-foreground">{loading ? '…' : `${vulns.length} resultado(s)`}</span>
      </div>

      {loading ? (
        <LoadingState label="Carregando vulnerabilidades…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : (
        <div className="flex min-h-0 grow flex-col overflow-x-auto px-4 pb-10 sm:px-8">
          <div className="flex min-w-[900px] grow flex-col">
            <div className="grid shrink-0 grid-cols-[168px_1fr_82px_58px_72px_92px_120px] border-b border-border px-2 pb-2.5 pt-4">
              {['Ativo', 'Vulnerabilidade', 'Severidade', 'CVSS', 'Fonte', 'Vista', 'Status'].map((h) => (
                <span key={h} className="text-[10.5px] uppercase tracking-wide text-muted-foreground">
                  {h}
                </span>
              ))}
            </div>

            <div className="grow overflow-y-auto">
              {vulns.length === 0 && (
                <div className="flex flex-col items-center gap-1.5 py-14 text-center">
                  <span className="text-sm text-foreground">Nenhuma vulnerabilidade nesse filtro</span>
                  <span className="text-xs text-muted-foreground">Rode uma varredura ou troque os filtros.</span>
                </div>
              )}
              {vulns.map((v) => {
                const s = severityMeta[v.severity]
                const st = statusMeta[v.status]
                return (
                  <div
                    key={v.id}
                    onClick={() => setSelectedId(v.id)}
                    className={cn(
                      'grid cursor-pointer grid-cols-[168px_1fr_82px_58px_72px_92px_120px] items-center border-b border-border/60 px-2 py-3 hover:bg-white/[0.035]',
                      selectedId === v.id && 'bg-primary/[0.06]',
                    )}
                  >
                    <span className="flex items-center gap-2 pr-3">
                      <span className="h-5 w-[3px] shrink-0 rounded-sm" style={{ background: s.dot }} />
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-[12px] text-foreground">{v.asset}</span>
                        <span className="block text-[10px] text-muted-foreground">{v.asset_type}</span>
                      </span>
                    </span>
                    <span className="min-w-0 pr-4">
                      <span className="block truncate text-[13px] text-foreground">{v.title}</span>
                      <span className="block truncate text-[10.5px] text-muted-foreground">
                        {v.cve ?? 'sem CVE'}
                        {v.reopened_count > 0 && ` · reabriu ${v.reopened_count}x`}
                      </span>
                    </span>
                    <span className={`w-fit rounded-md px-2 py-[3px] text-[10px] font-semibold uppercase tracking-wide ${s.color} ${s.bg}`}>
                      {s.label}
                    </span>
                    <span className="font-mono text-[11.5px] text-muted-foreground">{v.cvss?.toFixed(1) ?? '—'}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">{v.source}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">{formatTime(v.last_seen)}</span>
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
      )}

      {selected && <div onClick={() => setSelectedId(null)} className="fixed inset-0 z-10 bg-black/45 backdrop-blur-[1px]" />}

      <div
        className={cn(
          'fixed right-0 top-0 z-20 flex h-screen w-full flex-col border-l border-border bg-card shadow-[-20px_0_50px_rgba(0,0,0,0.4)] transition-transform duration-300 ease-out sm:w-[440px]',
          selected ? 'translate-x-0' : 'translate-x-full',
        )}
      >
        {selected && <VulnDetail vuln={selected} onClose={() => setSelectedId(null)} onUpdated={applyUpdate} />}
      </div>
    </AppShell>
  )
}

function VulnDetail({
  vuln,
  onClose,
  onUpdated,
}: {
  vuln: ApiVulnerability
  onClose: () => void
  onUpdated: (v: ApiVulnerability) => void
}) {
  const [saving, setSaving] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  // Aceitar risco abre um formulário no lugar de aplicar direto, porque a API
  // exige justificativa e data de revisão pra esse estado.
  const [acceptForm, setAcceptForm] = useState(false)
  const [justification, setJustification] = useState(vuln.justification ?? '')
  const [reviewAt, setReviewAt] = useState(vuln.review_at?.slice(0, 10) ?? '')

  const s = severityMeta[vuln.severity]

  async function apply(status: VulnStatus, extra?: { justification: string; review_at: string }) {
    if (saving) return
    setSaving(true)
    setActionError(null)
    try {
      const updated = await updateVulnerability(vuln.id, { status, ...extra })
      onUpdated(updated)
      setAcceptForm(false)
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Não foi possível salvar')
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <div className="flex shrink-0 items-center justify-between border-b border-border px-5.5 py-5">
        <span className="font-mono text-[11.5px] uppercase tracking-wide text-muted-foreground">Detalhe da vulnerabilidade</span>
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
          {vuln.cvss !== null && <span className="font-mono text-[11px] text-muted-foreground">CVSS {vuln.cvss.toFixed(1)}</span>}
          {vuln.reopened_count > 0 && (
            <span className="rounded-md bg-warning/14 px-2 py-1 text-[10.5px] text-warning">reabriu {vuln.reopened_count}x</span>
          )}
        </div>

        <div className="font-heading text-[17px] font-semibold leading-snug text-foreground">{vuln.title}</div>
        {vuln.description && <div className="text-[13px] leading-relaxed text-muted-foreground">{vuln.description}</div>}

        <div className="flex flex-col gap-2.5 rounded-lg border border-border bg-background p-4">
          <Row label="Ativo">
            <span className="font-mono text-xs text-foreground">{vuln.asset}</span>
          </Row>
          <Row label="CVE">
            <span className="font-mono text-xs text-primary">{vuln.cve ?? '—'}</span>
          </Row>
          <Row label="Achado por">
            <span className="font-mono text-xs text-foreground">{vuln.source}</span>
          </Row>
          <Row label="Vista primeiro">
            <span className="font-mono text-xs text-muted-foreground">{formatTime(vuln.first_seen)}</span>
          </Row>
          <Row label="Vista por último">
            <span className="font-mono text-xs text-muted-foreground">{formatTime(vuln.last_seen)}</span>
          </Row>
        </div>

        <div>
          <div className="mb-2 text-[11.5px] text-muted-foreground">Tratativa</div>
          <div className="grid grid-cols-2 gap-2">
            <StatusButton active={vuln.status === 'open'} color="var(--destructive)" onClick={() => apply('open')}>
              Aberta
            </StatusButton>
            <StatusButton active={vuln.status === 'in_progress'} color="var(--primary)" onClick={() => apply('in_progress')}>
              Em tratamento
            </StatusButton>
            <StatusButton active={vuln.status === 'remediated'} color="var(--success)" onClick={() => apply('remediated')}>
              Corrigida
            </StatusButton>
            <StatusButton active={vuln.status === 'accepted_risk'} color="#A78BFA" onClick={() => setAcceptForm(true)}>
              Risco aceito
            </StatusButton>
          </div>
        </div>

        {acceptForm && (
          <div className="flex flex-col gap-3 rounded-lg border border-[#A78BFA]/30 bg-[#A78BFA]/[0.07] p-4">
            <div className="text-[12px] text-[#C4B5FD]">
              Aceitar o risco exige justificativa e uma data pra revisitar. Sem os dois, isso vira desculpa pra nunca corrigir.
            </div>
            <textarea
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              rows={3}
              placeholder="Por que esse risco é aceitável agora?"
              className="rounded-md border border-border bg-background p-2.5 text-[12.5px] text-foreground outline-none focus:border-[#A78BFA]/50"
            />
            <label className="flex items-center justify-between text-[11.5px] text-muted-foreground">
              Revisar em
              <input
                type="date"
                value={reviewAt}
                onChange={(e) => setReviewAt(e.target.value)}
                className="rounded-md border border-border bg-background px-2.5 py-1.5 text-[12px] text-foreground outline-none focus:border-[#A78BFA]/50"
              />
            </label>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={saving || !justification.trim() || !reviewAt}
                onClick={() => apply('accepted_risk', { justification, review_at: new Date(reviewAt).toISOString() })}
                className="flex h-8 flex-1 items-center justify-center gap-1.5 rounded-md bg-[#A78BFA] text-xs font-semibold text-[#0A0A0F] transition-opacity hover:opacity-90 disabled:opacity-40"
              >
                {saving && <Loader2 className="h-3 w-3 animate-spin" />}
                Confirmar
              </button>
              <button
                type="button"
                onClick={() => setAcceptForm(false)}
                className="h-8 rounded-md border border-border px-3 text-xs text-muted-foreground hover:bg-white/[0.05]"
              >
                Cancelar
              </button>
            </div>
          </div>
        )}

        {vuln.status === 'accepted_risk' && !acceptForm && vuln.justification && (
          <div className="rounded-lg border border-[#A78BFA]/25 bg-[#A78BFA]/[0.06] p-3.5">
            <div className="mb-1 text-[10.5px] uppercase tracking-wide text-[#A78BFA]">Risco aceito por {vuln.updated_by}</div>
            <div className="text-[12.5px] text-foreground">{vuln.justification}</div>
            {vuln.review_at && (
              <div className="mt-1.5 font-mono text-[11px] text-muted-foreground">Revisar em {formatTime(vuln.review_at)}</div>
            )}
          </div>
        )}

        {actionError && <div className="text-[11px] text-destructive">{actionError}</div>}

        <div>
          <div className="mb-2 text-[11.5px] text-muted-foreground">Evidência do scanner</div>
          <pre className="whitespace-pre-wrap break-all rounded-lg border border-border bg-background p-3.5 font-mono text-[11px] leading-relaxed text-primary/80">
            {JSON.stringify(vuln.evidence, null, 2)}
          </pre>
        </div>
      </div>
    </>
  )
}

function RiskGauge({ score }: { score: number }) {
  const color = score >= 70 ? '#EF4444' : score >= 40 ? '#F59E0B' : '#22C55E'
  const circumference = 2 * Math.PI * 19
  return (
    <div className="flex items-center gap-3 rounded-xl border border-border bg-card px-4 py-3">
      <svg width="46" height="46" viewBox="0 0 46 46" className="shrink-0">
        <circle cx="23" cy="23" r="19" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="5" />
        <circle
          cx="23"
          cy="23"
          r="19"
          fill="none"
          stroke={color}
          strokeWidth="5"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - Math.min(100, score) / 100)}
          transform="rotate(-90 23 23)"
        />
      </svg>
      <div className="leading-tight">
        <div className="font-heading text-[20px] font-semibold text-foreground">
          {score}
          <span className="text-[12px] font-medium text-muted-foreground">/100</span>
        </div>
        <div className="text-[11.5px] text-muted-foreground">risco do parque</div>
      </div>
    </div>
  )
}

function ScanHint({ job, error }: { job: { status: string; stats: Record<string, number> | null } | null; error: string | null }) {
  if (error) return <span className="text-[11px] text-destructive">{error}</span>
  if (!job) return <span className="text-[11px] text-muted-foreground">Nenhuma varredura registrada ainda</span>
  if (job.status === 'queued') return <span className="text-[11px] text-muted-foreground">Na fila, o scanner pega em instantes</span>
  if (job.status === 'running') return <span className="text-[11px] text-muted-foreground">Rodando, isso leva alguns minutos</span>
  if (job.status === 'failed') return <span className="text-[11px] text-destructive">A última varredura falhou</span>
  const s = job.stats ?? {}
  return (
    <span className="font-mono text-[11px] text-muted-foreground">
      última: {s.achados ?? 0} achado(s) · {s.novos ?? 0} novo(s) · {s.reabertos ?? 0} reaberto(s)
    </span>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-3">
      <span className="shrink-0 text-[11.5px] text-muted-foreground">{label}</span>
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
