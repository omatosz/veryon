import { useCallback, useEffect, useState } from 'react'
import {
  Ban,
  Fingerprint,
  Loader2,
  Radar,
  ShieldAlert,
  Unlink,
  X,
} from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { Button } from '@/components/ui/button'
import { FilterPill } from '@/components/ui/filter-pill'
import { StatPill } from '@/components/ui/stat-pill'
import { useAuth } from '@/lib/auth-context'
import {
  blockActor,
  detachActorIp,
  getActor,
  getActorTimeline,
  listActors,
  updateActor,
  type ApiActor,
  type ApiActorDetail,
  type ApiActorEvent,
} from '@/lib/api'
import { formatDateTime } from '@/lib/format'

/** A cor sai da ação recomendada, nunca do score. Score cru na tela transfere a
 *  decisão para quem está lendo, e às três da manhã ninguém sabe se 82 é muito. */
const ACAO = {
  bloquear: { rotulo: 'Bloquear', cor: 'var(--destructive)', icone: Ban },
  investigar: { rotulo: 'Investigar', cor: 'var(--warning)', icone: Radar },
  observar: { rotulo: 'Observar', cor: 'var(--muted-foreground)', icone: Fingerprint },
} as const

const CONFIANCA: Record<string, string> = { high: 'alta', medium: 'média', low: 'baixa' }

const FONTE: Record<string, { rotulo: string; cor: string }> = {
  honeypot: { rotulo: 'honeypot', cor: '#F59E0B' },
  alerta: { rotulo: 'alerta', cor: '#EF4444' },
  api: { rotulo: 'API', cor: '#3B82F6' },
  resposta: { rotulo: 'resposta', cor: '#22C55E' },
}

function Selo({ acao }: { acao: ApiActor['decisao']['acao'] }) {
  const meta = ACAO[acao]
  const Icone = meta.icone
  return (
    <span
      className="flex h-6 shrink-0 items-center gap-1.5 rounded-full px-2.5 text-[11px] font-semibold"
      style={{ color: meta.cor, background: `color-mix(in srgb, ${meta.cor} 14%, transparent)` }}
    >
      <Icone className="h-3 w-3" />
      {meta.rotulo}
    </span>
  )
}

function Evidencia({ ator, onMudou }: { ator: ApiActorDetail; onMudou: () => void }) {
  const [ocupado, setOcupado] = useState<string | null>(null)
  const [erro, setErro] = useState<string | null>(null)

  async function separar(ip: string) {
    setOcupado(ip)
    setErro(null)
    try {
      await detachActorIp(ator.ref, ip)
      onMudou()
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Não foi possível separar')
    } finally {
      setOcupado(null)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div>
        <div className="mb-2 text-[11.5px] text-muted-foreground">
          O que sustenta a identidade
        </div>
        <div className="rounded-lg border border-border bg-background p-3 text-[12px]">
          {Object.entries(ator.traits).map(([chave, valor]) => (
            <div key={chave} className="flex gap-2 py-0.5">
              <span className="w-24 shrink-0 text-muted-foreground">{chave}</span>
              <span className="min-w-0 break-all font-mono text-[11px] text-foreground">
                {String(valor)}
              </span>
            </div>
          ))}
        </div>
        <p className="mt-1.5 text-[11px] text-muted-foreground">
          Distintividade {ator.distinctiveness.toFixed(2)}. Abaixo de 0,35 o Veryon não junta
          endereço nenhum: comportamento comum demais junta todo mundo no mesmo ator.
        </p>
      </div>

      <div>
        <div className="mb-2 text-[11.5px] text-muted-foreground">
          Endereços, e com quanta semelhança cada um entrou
        </div>
        <div className="flex flex-col gap-1.5">
          {ator.ips.map((ip) => (
            <div key={ip.client_ip} className="rounded-lg border border-border bg-background p-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[12.5px] text-foreground">{ip.client_ip}</span>
                {ip.bloqueado && (
                  <span className="rounded-full border border-destructive/40 px-1.5 py-0.5 text-[10px] text-destructive">
                    bloqueado
                  </span>
                )}
                {ip.manual && (
                  <span className="rounded-full border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">
                    decidido à mão
                  </span>
                )}
                <span className="ml-auto text-[11px] text-muted-foreground">
                  semelhança {ip.similarity.toFixed(2)} · {ip.request_count} requisições
                </span>
                <button
                  type="button"
                  disabled={ocupado === ip.client_ip}
                  onClick={() => void separar(ip.client_ip)}
                  title="Este endereço não é do mesmo ator"
                  className="flex h-7 items-center gap-1 rounded-md border border-border px-2 text-[11px] text-muted-foreground transition-colors hover:text-foreground disabled:opacity-40"
                >
                  {ocupado === ip.client_ip ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Unlink className="h-3 w-3" />
                  )}
                  Separar
                </button>
              </div>
              {ip.match_detail && (
                <pre className="mt-1.5 whitespace-pre-wrap break-all font-mono text-[10.5px] leading-relaxed text-primary/70">
                  {JSON.stringify(ip.match_detail)}
                </pre>
              )}
            </div>
          ))}
        </div>
        {erro && <p className="mt-2 text-[12px] text-destructive">{erro}</p>}
      </div>
    </div>
  )
}

function Gaveta({ ref_, onFechar }: { ref_: string; onFechar: () => void }) {
  const { isAdmin } = useAuth()
  const [ator, setAtor] = useState<ApiActorDetail | null>(null)
  const [eventos, setEventos] = useState<ApiActorEvent[]>([])
  const [aba, setAba] = useState<'timeline' | 'evidencia'>('timeline')
  const [nota, setNota] = useState('')
  const [aviso, setAviso] = useState<string | null>(null)
  const [ocupado, setOcupado] = useState(false)

  const carregar = useCallback(async () => {
    const d = await getActor(ref_)
    setAtor(d)
    setNota(d.note ?? '')
    setEventos(await getActorTimeline(ref_, 365))
  }, [ref_])

  useEffect(() => {
    void carregar()
  }, [carregar])

  if (!ator) return <LoadingState />

  const meta = ACAO[ator.decisao.acao]

  async function salvarNota() {
    setOcupado(true)
    setAviso(null)
    try {
      await updateActor(ref_, { note: nota })
      setAviso('Nota salva.')
    } catch (e) {
      setAviso(e instanceof Error ? e.message : 'Não foi possível salvar')
    } finally {
      setOcupado(false)
    }
  }

  async function bloquear() {
    setOcupado(true)
    setAviso(null)
    try {
      const r = await blockActor(ref_)
      const recusados = r.recusados?.length
        ? ` Ficaram de fora: ${r.recusados.map((x) => `${x.ip} (${x.motivo})`).join('; ')}`
        : ''
      setAviso(
        r.bloqueados.length
          ? `Bloqueados: ${r.bloqueados.join(', ')}.${recusados}`
          : (r.detalhe ?? 'Nada a bloquear.'),
      )
      await carregar()
    } catch (e) {
      setAviso(e instanceof Error ? e.message : 'Não foi possível bloquear')
    } finally {
      setOcupado(false)
    }
  }

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-5">
      <div className="flex items-start gap-3">
        <div className="min-w-0">
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Ator</div>
          <h2 className="font-mono font-heading text-lg font-semibold text-foreground">
            {ator.ref}
          </h2>
        </div>
        <button
          type="button"
          onClick={onFechar}
          className="ml-auto text-muted-foreground transition-colors hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Camada 1, o que fazer com isto. Vem antes de qualquer número porque é
          a única coisa que alguém de plantão precisa ler. */}
      <div
        className="rounded-xl border p-3.5"
        style={{
          borderColor: `color-mix(in srgb, ${meta.cor} 40%, transparent)`,
          background: `color-mix(in srgb, ${meta.cor} 7%, transparent)`,
        }}
      >
        <Selo acao={ator.decisao.acao} />
        <p className="mt-2 text-[12.5px] leading-relaxed" style={{ color: meta.cor }}>
          {ator.decisao.porque}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-2 text-[12px] sm:grid-cols-4">
        {[
          ['Confiança', CONFIANCA[ator.confidence] ?? ator.confidence],
          ['Endereços', String(ator.ip_count)],
          ['Requisições', ator.request_count.toLocaleString('pt-BR')],
          ['Situação', ator.status === 'active' ? 'ativo' : 'dormente'],
        ].map(([rotulo, valor]) => (
          <div key={rotulo} className="rounded-lg border border-border bg-card px-3 py-2">
            <div className="text-[10.5px] text-muted-foreground">{rotulo}</div>
            <div className="text-[13px] font-medium text-foreground">{valor}</div>
          </div>
        ))}
      </div>

      {ator.agente && (
        <div className="text-[11.5px] text-muted-foreground">
          Ferramenta: <span className="font-mono text-foreground">{ator.agente}</span>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <FilterPill active={aba === 'timeline'} onClick={() => setAba('timeline')}>
          O que fez ({eventos.length})
        </FilterPill>
        <FilterPill active={aba === 'evidencia'} onClick={() => setAba('evidencia')}>
          Por que é o mesmo
        </FilterPill>
      </div>

      {aba === 'timeline' ? (
        eventos.length === 0 ? (
          <p className="rounded-xl border border-dashed border-border p-5 text-center text-[12.5px] text-muted-foreground">
            Nada registrado no último ano para os endereços deste ator.
          </p>
        ) : (
          <div className="flex flex-col">
            {/* A junção é o ponto. Cada tela do Veryon já mostra a sua parte, e
                é por isso que ninguém enxerga a sequência. */}
            {eventos.map((e, i) => {
              const f = FONTE[e.fonte] ?? { rotulo: e.fonte, cor: '#94A3B8' }
              return (
                <div key={i} className="flex gap-3 border-l border-border pl-3">
                  <div className="relative -ml-[17px] mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: f.cor }} />
                  <div className="min-w-0 pb-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[10.5px] font-medium uppercase tracking-wider" style={{ color: f.cor }}>
                        {f.rotulo}
                      </span>
                      <span className="text-[11px] text-muted-foreground">{formatDateTime(e.ts)}</span>
                      {e.ip && <span className="font-mono text-[11px] text-muted-foreground">{e.ip}</span>}
                    </div>
                    <div className="text-[12.5px] text-foreground">{e.titulo}</div>
                    {e.detalhe && (
                      <div className="break-all font-mono text-[11px] text-muted-foreground">{e.detalhe}</div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )
      ) : (
        <Evidencia ator={ator} onMudou={() => void carregar()} />
      )}

      <div>
        <div className="mb-2 text-[11.5px] text-muted-foreground">Nota do analista</div>
        <textarea
          value={nota}
          onChange={(e) => setNota(e.target.value)}
          rows={3}
          maxLength={2000}
          placeholder="O que você concluiu sobre este ator."
          className="w-full resize-y rounded-lg border border-border bg-background px-3 py-2 text-[12.5px] text-foreground placeholder:text-muted-foreground/70 focus:border-primary focus:outline-none"
        />
        <div className="mt-2 flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => void salvarNota()} disabled={ocupado}>
            {ocupado && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Salvar nota
          </Button>

          {/* O botão só existe quando o próprio Veryon recomenda. A API recusa
              de qualquer jeito, com 422; esconder aqui evita oferecer uma ação
              que vai ser negada. */}
          {ator.decisao.acao === 'bloquear' && (
            <Button
              variant="destructive"
              size="sm"
              onClick={() => void bloquear()}
              disabled={ocupado || !isAdmin}
              title={isAdmin ? undefined : 'Bloquear é ação de administrador'}
            >
              <Ban className="h-3.5 w-3.5" />
              Bloquear os {ator.ip_count} endereços
            </Button>
          )}
        </div>
        {!isAdmin && ator.decisao.acao === 'bloquear' && (
          <p className="mt-1.5 text-[11px] text-muted-foreground">
            Bloquear é ação de administrador. Você pode anotar e separar endereços.
          </p>
        )}
        {aviso && <p className="mt-2 text-[12px] text-muted-foreground">{aviso}</p>}
      </div>
    </div>
  )
}

export function ActorsPage() {
  const [atores, setAtores] = useState<ApiActor[] | null>(null)
  const [erro, setErro] = useState<string | null>(null)
  const [filtro, setFiltro] = useState<string | null>(null)
  const [aberto, setAberto] = useState<string | null>(null)

  const carregar = useCallback(async () => {
    try {
      setAtores(await listActors())
      setErro(null)
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Falha ao carregar')
    }
  }, [])

  useEffect(() => {
    void carregar()
  }, [carregar])

  if (erro && !atores) return <ErrorState message={erro} />
  if (!atores) return <LoadingState />

  const visiveis = filtro ? atores.filter((a) => a.decisao.acao === filtro) : atores
  const conta = (acao: string) => atores.filter((a) => a.decisao.acao === acao).length

  return (
    <AppShell title="Atores">
      <p className="text-[13px] text-muted-foreground">
        Quem está atacando, quando o IP deixa de servir como identidade. O Veryon afirma mesma
        ferramenta com o mesmo padrão de uso, nunca mesma pessoa.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <StatPill
          icon={Ban}
          tone="text-destructive"
          bg="bg-destructive/12"
          value={conta('bloquear')}
          label="pedem bloqueio"
          hint="padrão confirmado e grave"
        />
        <StatPill
          icon={Radar}
          tone="text-warning"
          bg="bg-warning/12"
          value={conta('investigar')}
          label="pedem olhada"
          hint="grave, ou trocando de IP"
        />
        <StatPill
          icon={ShieldAlert}
          tone="text-primary"
          bg="bg-primary/12"
          value={atores.reduce((n, a) => n + a.ip_count, 0)}
          label="endereços mapeados"
          hint={`em ${atores.length} atores`}
        />
      </div>

      <div className="flex flex-wrap gap-1.5">
        <FilterPill active={filtro === null} onClick={() => setFiltro(null)}>
          Todos
        </FilterPill>
        {(Object.keys(ACAO) as (keyof typeof ACAO)[]).map((a) => (
          <FilterPill
            key={a}
            active={filtro === a}
            onClick={() => setFiltro(a)}
            activeColor={ACAO[a].cor}
          >
            {ACAO[a].rotulo}
          </FilterPill>
        ))}
      </div>

      {visiveis.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border bg-card/40 p-8 text-center">
          <Fingerprint className="mx-auto h-8 w-8 text-muted-foreground" strokeWidth={1.5} />
          <p className="mt-3 text-sm font-medium text-foreground">Nenhum ator neste recorte</p>
          <p className="mt-1 text-[13px] text-muted-foreground">
            Um ator só nasce quando um chamador já tem achado de API aberto. Isto não é
            identificação de visitante.
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {visiveis.map((a) => (
            <button
              key={a.ref}
              type="button"
              onClick={() => setAberto(a.ref)}
              className="rounded-xl border border-border bg-card p-4 text-left transition-colors hover:bg-white/[0.03]"
            >
              <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                <Selo acao={a.decisao.acao} />
                <span className="font-mono text-[13px] font-medium text-foreground">{a.ref}</span>
                <span className="text-[11.5px] text-muted-foreground">
                  {a.ip_count} {a.ip_count === 1 ? 'endereço' : 'endereços'} · confiança{' '}
                  {CONFIANCA[a.confidence] ?? a.confidence}
                  {a.status !== 'active' && ' · dormente'}
                </span>
                <span className="ml-auto text-[11px] text-muted-foreground">
                  visto por último {formatDateTime(a.last_seen)}
                </span>
              </div>
              {a.agente && (
                <div className="mt-1.5 truncate font-mono text-[11px] text-muted-foreground">
                  {a.agente}
                </div>
              )}
              <p className="mt-1.5 text-[12px] text-muted-foreground">{a.decisao.porque}</p>
            </button>
          ))}
        </div>
      )}

      {aberto && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/50"
            onClick={() => {
              setAberto(null)
              void carregar()
            }}
          />
          <div className="fixed right-0 top-0 z-50 h-full w-full max-w-[620px] border-l border-border bg-card">
            <Gaveta
              ref_={aberto}
              onFechar={() => {
                setAberto(null)
                void carregar()
              }}
            />
          </div>
        </>
      )}
    </AppShell>
  )
}
