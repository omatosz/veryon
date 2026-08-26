import { useEffect, useState, type FormEvent } from 'react'
import { Building2, FlaskConical, Info, Lock, MapPin, Radar, Search } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { cn } from '@/lib/utils'
import { ApiError, getEnrichment, getSummary, type ApiEnrichment } from '@/lib/api'
import { countryFlag, formatDateTime } from '@/lib/format'

function isPrivateIp(ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return false
  const [a, b] = parts
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 127) return true
  if (a === 169 && b === 254) return true
  return false
}

type LookupState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'result'; data: ApiEnrichment }
  | { kind: 'not-found'; ip: string }
  | { kind: 'error'; message: string }

export function ThreatIntelPage() {
  const [query, setQuery] = useState('')
  const [state, setState] = useState<LookupState>({ kind: 'idle' })
  const [quickIps, setQuickIps] = useState<string[]>([])

  useEffect(() => {
    getSummary()
      .then((s) => setQuickIps(s.top_src_ips.map((ip) => ip.src_ip)))
      .catch(() => setQuickIps([]))
  }, [])

  async function runLookup(ip: string) {
    const trimmed = ip.trim()
    if (!trimmed) return
    setQuery(trimmed)
    setState({ kind: 'loading' })
    try {
      const data = await getEnrichment(trimmed)
      setState({ kind: 'result', data })
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setState({ kind: 'not-found', ip: trimmed })
      } else {
        setState({ kind: 'error', message: err instanceof Error ? err.message : 'Erro ao consultar' })
      }
    }
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    runLookup(query)
  }

  return (
    <AppShell title="Threat Intel">
      <div className="grow overflow-y-auto px-4 pb-14 pt-7 sm:px-8">
        <form onSubmit={handleSubmit} className="flex gap-2.5">
          <div className="relative flex grow items-center sm:max-w-[420px]">
            <Search className="pointer-events-none absolute left-3 h-4 w-4 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Consultar IP, ex: 203.0.113.44"
              className="h-11 w-full rounded-lg border border-white/10 bg-card pl-9 pr-3 font-mono text-sm text-foreground placeholder:text-muted-foreground outline-none focus-visible:border-ring"
            />
          </div>
          <button
            type="submit"
            className="flex h-11 items-center justify-center rounded-lg bg-primary px-5 font-heading text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Consultar
          </button>
        </form>

        {quickIps.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span className="mr-1 text-[11.5px] uppercase tracking-wide text-muted-foreground">IPs recentes</span>
            {quickIps.map((ip) => (
              <button
                key={ip}
                type="button"
                onClick={() => runLookup(ip)}
                className={cn(
                  'h-[26px] rounded-full border px-3 font-mono text-[11px] transition-colors',
                  query === ip ? 'border-primary bg-primary/10 text-primary' : 'border-white/10 text-muted-foreground hover:border-white/25',
                )}
              >
                {ip}
              </button>
            ))}
          </div>
        )}

        <div className="mt-7">
          {state.kind === 'idle' && (
            <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-white/10 py-16 text-center">
              <Radar className="h-7 w-7 text-muted-foreground" strokeWidth={1.5} />
              <span className="text-sm text-foreground">Consulte um IP pra ver a reputação dele</span>
              <span className="max-w-sm text-xs text-muted-foreground">
                Combina dados de AbuseIPDB, VirusTotal e AlienVault OTX pra cada IP visto nos eventos ingeridos.
              </span>
            </div>
          )}

          {state.kind === 'loading' && (
            <div className="flex flex-col items-center gap-2 py-16 text-center text-muted-foreground">
              <span className="text-sm">Consultando {query}…</span>
            </div>
          )}

          {state.kind === 'error' && (
            <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-white/10 py-16 text-center">
              <Info className="h-7 w-7 text-destructive" strokeWidth={1.5} />
              <span className="text-sm text-foreground">Erro ao consultar {query}</span>
              <span className="max-w-sm text-xs text-muted-foreground">{state.message}</span>
            </div>
          )}

          {state.kind === 'not-found' && (
            <NotFoundPanel ip={state.ip} />
          )}

          {state.kind === 'result' && <ResultPanel result={state.data} />}
        </div>
      </div>
    </AppShell>
  )
}

function NotFoundPanel({ ip }: { ip: string }) {
  const isPrivate = isPrivateIp(ip)
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-heading text-xl font-semibold text-foreground">{ip}</span>
        {isPrivate && (
          <span className="flex items-center gap-1.5 rounded-full bg-white/[0.06] px-2.5 py-1 text-[10.5px] font-medium text-muted-foreground">
            <Lock className="h-3 w-3" /> IP privado
          </span>
        )}
      </div>

      {isPrivate ? (
        <div className="rounded-xl border border-border bg-card p-5.5 text-sm leading-relaxed text-muted-foreground">
          Esse IP está numa faixa privada (RFC 1918) da rede do laboratório, então não existe reputação pública associada
          a ele — provedores como AbuseIPDB e VirusTotal só indexam endereços roteáveis na internet. O serviço de threat
          intel do projeto pula IPs privados automaticamente ao decidir o que enriquecer.
        </div>
      ) : (
        <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-white/10 py-14 text-center">
          <Info className="h-7 w-7 text-muted-foreground" strokeWidth={1.5} />
          <span className="text-sm text-foreground">Sem dados de threat intel para {ip}</span>
          <span className="max-w-sm text-xs text-muted-foreground">
            Esse IP ainda não foi enriquecido — o serviço processa até 5 IPs públicos novos por ciclo (a cada 60s).
          </span>
        </div>
      )}
    </div>
  )
}

function ResultPanel({ result }: { result: ApiEnrichment }) {
  const flag = countryFlag(result.abuseipdb_country)
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3">
        {flag && <span className="text-2xl leading-none">{flag}</span>}
        <span className="font-heading text-xl font-semibold text-foreground">{result.ip}</span>
        <RiskBadge score={result.abuseipdb_score} />
        <span className="font-mono text-[11px] text-muted-foreground">consultado {formatDateTime(result.checked_at)}</span>
      </div>

      <div className="grid grid-cols-1 gap-4.5 lg:grid-cols-3">
        <div className="rounded-xl border border-border bg-card p-5.5">
          <h3 className="mb-4 font-heading text-[13.5px] font-semibold text-foreground">AbuseIPDB</h3>
          <ScoreBar label="Score de abuso" value={result.abuseipdb_score ?? 0} />
          <div className="mt-4 flex flex-col gap-2.5">
            <MetaRow icon={MapPin} label="País" value={result.abuseipdb_country ?? '—'} />
            <MetaRow icon={Building2} label="ISP" value={result.abuseipdb_isp ?? '—'} />
            <MetaRow icon={Info} label="Denúncias" value={String(result.abuseipdb_total_reports ?? 0)} />
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-5.5">
          <h3 className="mb-4 font-heading text-[13.5px] font-semibold text-foreground">VirusTotal</h3>
          <ScoreBar
            label="Engines maliciosas"
            value={
              result.virustotal_total_engines
                ? Math.round(((result.virustotal_malicious ?? 0) / result.virustotal_total_engines) * 100)
                : 0
            }
            detail={`${result.virustotal_malicious ?? 0} / ${result.virustotal_total_engines ?? 0}`}
          />
          <div className="mt-4 flex flex-col gap-2.5">
            <MetaRow icon={Info} label="Reputação" value={String(result.virustotal_reputation ?? 0)} />
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-5.5">
          <h3 className="mb-4 font-heading text-[13.5px] font-semibold text-foreground">AlienVault OTX</h3>
          <div className="flex flex-col items-center justify-center gap-1 py-4">
            <span className="font-heading text-3xl font-semibold text-foreground">{result.otx_pulse_count ?? 0}</span>
            <span className="text-[11.5px] text-muted-foreground">pulses associados</span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <FlaskConical className="h-3 w-3" />
        Valores nulos indicam que a fonte não retornou dado pra esse IP (ex: chave de API ausente ou limite de taxa).
      </div>
    </div>
  )
}

function RiskBadge({ score }: { score: number | null }) {
  if (score === null) return null
  const level = score >= 70 ? { label: 'alto risco', color: 'text-destructive', bg: 'bg-destructive/14' } : score >= 25 ? { label: 'risco médio', color: 'text-warning', bg: 'bg-warning/14' } : { label: 'limpo', color: 'text-success', bg: 'bg-success/14' }
  return (
    <span className={cn('rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide', level.color, level.bg)}>{level.label}</span>
  )
}

function ScoreBar({ label, value, detail }: { label: string; value: number; detail?: string }) {
  const color = value >= 70 ? 'bg-destructive' : value >= 25 ? 'bg-warning' : 'bg-success'
  return (
    <div>
      <div className="mb-1.5 flex justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-mono text-foreground">{detail ?? `${value}/100`}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${Math.min(value, 100)}%` }} />
      </div>
    </div>
  )
}

function MetaRow({ icon: Icon, label, value }: { icon: typeof MapPin; label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
        <Icon className="h-3.5 w-3.5" strokeWidth={1.75} />
        {label}
      </span>
      <span className="text-[12.5px] text-foreground">{value}</span>
    </div>
  )
}
