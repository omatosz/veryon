import { useCallback, useEffect, useState } from 'react'
import {
  AlarmClock,
  Bell,
  BellOff,
  CheckCircle2,
  Loader2,
  Mail,
  Plus,
  Send,
  Trash2,
  Webhook,
  XCircle,
} from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { Button } from '@/components/ui/button'
import { FilterPill } from '@/components/ui/filter-pill'
import { Input } from '@/components/ui/input'
import { StatPill } from '@/components/ui/stat-pill'
import { cn } from '@/lib/utils'
import {
  createNotifyChannel,
  deleteNotifyChannel,
  listNotifyChannels,
  listNotifyQueue,
  runNotifyDigest,
  testNotifyChannel,
  updateNotifyChannel,
  type ApiNotifyChannel,
  type ApiNotifyQueueItem,
  type NotifyKind,
  type NotifyLevel,
} from '@/lib/api'
import { formatDateTime } from '@/lib/format'

const NIVEIS: NotifyLevel[] = ['informational', 'low', 'medium', 'high', 'critical']

const corDoNivel: Record<string, string> = {
  critical: '#EF4444',
  high: '#F59E0B',
  medium: '#3B82F6',
  low: '#22C55E',
  informational: '#94A3B8',
}

const rotuloDoStatus: Record<string, { texto: string; cor: string }> = {
  sent: { texto: 'entregue', cor: '#22C55E' },
  pending: { texto: 'na fila', cor: '#F59E0B' },
  digest: { texto: 'no resumo', cor: '#3B82F6' },
  failed: { texto: 'falhou', cor: '#EF4444' },
  suppressed: { texto: 'barrada', cor: '#94A3B8' },
}

const TIPOS: { valor: NotifyKind; nome: string; dica: string }[] = [
  { valor: 'email', nome: 'E-mail', dica: 'um ou mais endereços separados por vírgula' },
  { valor: 'discord', nome: 'Discord', dica: 'URL do webhook do canal' },
  { valor: 'slack', nome: 'Slack', dica: 'URL do webhook do app' },
  { valor: 'teams', nome: 'Teams', dica: 'URL do conector do canal' },
  { valor: 'generic', nome: 'Genérico', dica: 'qualquer endpoint que aceite JSON' },
]

const POLL_MS = 8000

/** Descreve, em palavras, o que cai no resumo daquele canal.
 *
 *  Existem três casos e cada um precisa de uma frase diferente. Com os níveis
 *  iguais não sobra faixa nenhuma no meio, e a distância de um nível só deixa
 *  exatamente um nível no resumo, então nomear os dois extremos confundiria
 *  mais do que ajudaria. */
function faixaDoResumo(canal: ApiNotifyChannel): string {
  const min = NIVEIS.indexOf(canal.min_level)
  const ime = NIVEIS.indexOf(canal.immediate_level)

  if (min >= ime) return 'nada vai pro resumo'
  if (ime - min === 1) return `${canal.min_level} vai pro resumo`
  return `de ${canal.min_level} a ${NIVEIS[ime - 1]} vai pro resumo`
}

export function NotificationsPage() {
  const [canais, setCanais] = useState<ApiNotifyChannel[] | null>(null)
  const [fila, setFila] = useState<ApiNotifyQueueItem[]>([])
  const [erro, setErro] = useState<string | null>(null)
  const [filtro, setFiltro] = useState<string | null>(null)
  const [criando, setCriando] = useState(false)
  const [ocupado, setOcupado] = useState<number | null>(null)
  // Resultado do último teste, por canal. Fica na tela até o próximo teste,
  // porque a mensagem de erro é justamente o que a pessoa usa pra corrigir.
  const [resultado, setResultado] = useState<Record<number, { ok: boolean; detalhe: string }>>({})

  const carregar = useCallback(async () => {
    try {
      const [c, f] = await Promise.all([listNotifyChannels(), listNotifyQueue()])
      setCanais(c)
      setFila(f)
      setErro(null)
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Falha ao carregar')
    }
  }, [])

  useEffect(() => {
    void carregar()
    const t = setInterval(() => void carregar(), POLL_MS)
    return () => clearInterval(t)
  }, [carregar])

  async function alternar(canal: ApiNotifyChannel) {
    setOcupado(canal.id)
    try {
      await updateNotifyChannel(canal.id, { enabled: !canal.enabled })
      await carregar()
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Falha ao alterar')
    } finally {
      setOcupado(null)
    }
  }

  async function testar(canal: ApiNotifyChannel) {
    setOcupado(canal.id)
    try {
      const r = await testNotifyChannel(canal.id)
      setResultado((atual) => ({ ...atual, [canal.id]: r }))
    } catch (e) {
      setResultado((atual) => ({
        ...atual,
        [canal.id]: { ok: false, detalhe: e instanceof Error ? e.message : 'Falha' },
      }))
    } finally {
      setOcupado(null)
    }
  }

  async function remover(canal: ApiNotifyChannel) {
    setOcupado(canal.id)
    try {
      await deleteNotifyChannel(canal.id)
      await carregar()
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Falha ao remover')
    } finally {
      setOcupado(null)
    }
  }

  async function resumoAgora() {
    setOcupado(-1)
    try {
      await runNotifyDigest()
      await carregar()
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Falha ao enviar resumo')
    } finally {
      setOcupado(null)
    }
  }

  const filaVisivel = filtro ? fila.filter((f) => f.status === filtro) : fila
  const ligados = canais?.filter((c) => c.enabled).length ?? 0
  const aguardandoResumo = fila.filter((f) => f.status === 'digest').length
  const falhas = fila.filter((f) => f.status === 'failed').length

  return (
    <AppShell title="Notificações">
      <p className="text-[13px] text-muted-foreground">
        Para onde os alertas vão quando ninguém está olhando a tela.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <StatPill
          icon={Bell}
          tone="text-success"
          bg="bg-success/12"
          value={ligados}
          label="canais ligados"
          hint={`${canais?.length ?? 0} cadastrados`}
        />
        <StatPill
          icon={AlarmClock}
          tone="text-primary"
          bg="bg-primary/12"
          value={aguardandoResumo}
          label="no resumo"
          hint="aguardam o próximo envio"
        />
        <StatPill
          icon={XCircle}
          tone="text-destructive"
          bg="bg-destructive/12"
          value={falhas}
          label="falhas"
          hint="esgotaram as tentativas"
        />
        <div className="ml-auto flex gap-2">
          <Button variant="outline" onClick={() => void resumoAgora()} disabled={ocupado === -1}>
            {ocupado === -1 ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <AlarmClock className="h-4 w-4" />
            )}
            Enviar resumo agora
          </Button>
          <Button onClick={() => setCriando((v) => !v)}>
            <Plus className="h-4 w-4" />
            Novo canal
          </Button>
        </div>
      </div>

      {erro && <ErrorState message={erro} />}

      {criando && (
        <FormularioCanal
          onPronto={async () => {
            setCriando(false)
            await carregar()
          }}
          onErro={setErro}
        />
      )}

      {canais === null ? (
        <LoadingState />
      ) : canais.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border bg-card/40 p-8 text-center">
          <BellOff className="mx-auto h-8 w-8 text-muted-foreground" strokeWidth={1.5} />
          <p className="mt-3 text-sm font-medium text-foreground">Nenhum canal cadastrado</p>
          <p className="mt-1 text-[13px] text-muted-foreground">
            Sem canal, um alerta crítico só existe se alguém estiver com esta aba aberta.
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {canais.map((canal) => (
            <LinhaCanal
              key={canal.id}
              canal={canal}
              ocupado={ocupado === canal.id}
              resultado={resultado[canal.id]}
              onAlternar={() => void alternar(canal)}
              onTestar={() => void testar(canal)}
              onRemover={() => void remover(canal)}
            />
          ))}
        </div>
      )}

      <div className="mt-6">
        <div className="mb-2.5 flex flex-wrap items-center gap-2">
          <h2 className="font-heading text-sm font-semibold text-foreground">Fila de mensagens</h2>
          <span className="text-[12px] text-muted-foreground">
            por que o alerta chegou, ou por que não chegou
          </span>
          <div className="ml-auto flex flex-wrap gap-1.5">
            <FilterPill active={filtro === null} onClick={() => setFiltro(null)}>
              Todas
            </FilterPill>
            {(['pending', 'digest', 'sent', 'failed'] as const).map((s) => (
              <FilterPill
                key={s}
                active={filtro === s}
                onClick={() => setFiltro(s)}
                activeColor={rotuloDoStatus[s]?.cor}
              >
                {rotuloDoStatus[s]?.texto ?? s}
              </FilterPill>
            ))}
          </div>
        </div>

        {filaVisivel.length === 0 ? (
          <p className="rounded-xl border border-dashed border-border bg-card/40 p-6 text-center text-[13px] text-muted-foreground">
            Nada na fila. Quando um alerta passar pelos filtros de um canal, ele aparece aqui.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-border bg-card">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-3 py-2 font-medium">Situação</th>
                  <th className="px-3 py-2 font-medium">Canal</th>
                  <th className="px-3 py-2 font-medium">Estado</th>
                  <th className="px-3 py-2 font-medium">Alertas</th>
                  <th className="px-3 py-2 font-medium">Quando</th>
                </tr>
              </thead>
              <tbody>
                {filaVisivel.map((item) => {
                  const st = rotuloDoStatus[item.status] ?? { texto: item.status, cor: '#94A3B8' }
                  return (
                    <tr key={item.id} className="border-b border-border/60 last:border-0">
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span
                            className="h-1.5 w-1.5 shrink-0 rounded-full"
                            style={{ background: corDoNivel[item.level] }}
                          />
                          <span className="text-foreground">{item.title}</span>
                        </div>
                        {item.last_error && (
                          <p className="mt-0.5 font-mono text-[11px] text-destructive">
                            {item.last_error}
                          </p>
                        )}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">{item.canal}</td>
                      <td className="px-3 py-2">
                        <span
                          className="rounded-full px-2 py-0.5 text-[11px]"
                          style={{ color: st.cor, background: `${st.cor}22` }}
                        >
                          {st.texto}
                          {item.attempts > 1 && ` (${item.attempts}x)`}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-muted-foreground">
                        {item.alert_count}
                      </td>
                      <td className="px-3 py-2 text-[12px] text-muted-foreground">
                        {formatDateTime(item.sent_at ?? item.created_at)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AppShell>
  )
}

function LinhaCanal({
  canal,
  ocupado,
  resultado,
  onAlternar,
  onTestar,
  onRemover,
}: {
  canal: ApiNotifyChannel
  ocupado: boolean
  resultado?: { ok: boolean; detalhe: string }
  onAlternar: () => void
  onTestar: () => void
  onRemover: () => void
}) {
  const Icone = canal.kind === 'email' ? Mail : Webhook

  return (
    <div className="rounded-xl border border-border bg-card p-3.5">
      <div className="flex flex-wrap items-center gap-3">
        <div
          className={cn(
            'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg',
            canal.enabled ? 'bg-primary/14 text-primary' : 'bg-muted text-muted-foreground',
          )}
        >
          <Icone className="h-[18px] w-[18px]" strokeWidth={1.75} />
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-medium text-foreground">{canal.name}</span>
            {!canal.enabled && (
              <span className="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">
                desligado
              </span>
            )}
          </div>
          <p className="truncate font-mono text-[12px] text-muted-foreground">{canal.target}</p>
        </div>

        {/* As duas faixas são o coração da tela: dizem em uma linha o que
            interrompe, o que espera o resumo e o que nem aparece.
            Quando os dois níveis são iguais não existe faixa de resumo, e
            dizer "high a high vai pro resumo" seria mentira. */}
        <div className="flex items-center gap-1.5 text-[11px]">
          <span
            className="rounded-full px-2 py-0.5"
            style={{
              color: corDoNivel[canal.immediate_level],
              background: `${corDoNivel[canal.immediate_level]}22`,
            }}
          >
            {canal.immediate_level}+ interrompe
          </span>
          <span className="rounded-full bg-muted px-2 py-0.5 text-muted-foreground">
            {faixaDoResumo(canal)}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" onClick={onTestar} disabled={ocupado}>
            {ocupado ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            Testar
          </Button>
          <Button variant={canal.enabled ? 'secondary' : 'default'} size="sm" onClick={onAlternar} disabled={ocupado}>
            {canal.enabled ? 'Desligar' : 'Ligar'}
          </Button>
          <Button variant="destructive" size="sm" onClick={onRemover} disabled={ocupado}>
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {resultado && (
        <div
          className={cn(
            'mt-2.5 flex items-start gap-2 rounded-lg px-3 py-2 text-[12.5px]',
            resultado.ok ? 'bg-primary/10 text-primary' : 'bg-destructive/10 text-destructive',
          )}
        >
          {resultado.ok ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
          ) : (
            <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
          )}
          <span className="font-mono">{resultado.detalhe}</span>
        </div>
      )}
    </div>
  )
}

function FormularioCanal({
  onPronto,
  onErro,
}: {
  onPronto: () => Promise<void>
  onErro: (m: string) => void
}) {
  const [nome, setNome] = useState('')
  const [tipo, setTipo] = useState<NotifyKind>('email')
  const [destino, setDestino] = useState('')
  const [minimo, setMinimo] = useState<NotifyLevel>('high')
  const [imediato, setImediato] = useState<NotifyLevel>('critical')
  const [salvando, setSalvando] = useState(false)

  const dica = TIPOS.find((t) => t.valor === tipo)?.dica ?? ''

  async function salvar() {
    setSalvando(true)
    try {
      await createNotifyChannel({
        name: nome,
        kind: tipo,
        target: destino,
        min_level: minimo,
        immediate_level: imediato,
        enabled: false,
      })
      setNome('')
      setDestino('')
      await onPronto()
    } catch (e) {
      onErro(e instanceof Error ? e.message : 'Falha ao criar canal')
    } finally {
      setSalvando(false)
    }
  }

  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-[12px] text-muted-foreground">Nome</label>
          <Input value={nome} onChange={(e) => setNome(e.target.value)} placeholder="plantão-soc" />
        </div>
        <div>
          <label className="mb-1 block text-[12px] text-muted-foreground">Tipo</label>
          <div className="flex flex-wrap gap-1.5">
            {TIPOS.map((t) => (
              <FilterPill key={t.valor} active={tipo === t.valor} onClick={() => setTipo(t.valor)}>
                {t.nome}
              </FilterPill>
            ))}
          </div>
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-[12px] text-muted-foreground">Destino</label>
          <Input value={destino} onChange={(e) => setDestino(e.target.value)} placeholder={dica} />
          <p className="mt-1 text-[11.5px] text-muted-foreground">{dica}</p>
        </div>
        <div>
          <label className="mb-1 block text-[12px] text-muted-foreground">
            Mínimo para aparecer
          </label>
          <div className="flex flex-wrap gap-1.5">
            {NIVEIS.map((n) => (
              <FilterPill key={n} active={minimo === n} onClick={() => setMinimo(n)} activeColor={corDoNivel[n]}>
                {n}
              </FilterPill>
            ))}
          </div>
        </div>
        <div>
          <label className="mb-1 block text-[12px] text-muted-foreground">
            A partir daqui interrompe
          </label>
          <div className="flex flex-wrap gap-1.5">
            {NIVEIS.map((n) => (
              <FilterPill key={n} active={imediato === n} onClick={() => setImediato(n)} activeColor={corDoNivel[n]}>
                {n}
              </FilterPill>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-3">
        <Button onClick={() => void salvar()} disabled={salvando || !nome || !destino}>
          {salvando && <Loader2 className="h-4 w-4 animate-spin" />}
          Criar canal
        </Button>
        <p className="text-[12px] text-muted-foreground">
          O canal nasce desligado. Teste o envio antes de ligar.
        </p>
      </div>
    </div>
  )
}
