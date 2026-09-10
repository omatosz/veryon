import { useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle,
  Archive,
  Database,
  HardDrive,
  Infinity as InfinityIcon,
  Loader2,
  RefreshCw,
  Trash2,
} from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { Button } from '@/components/ui/button'
import { StatPill } from '@/components/ui/stat-pill'
import {
  applyRetention,
  getRetentionStatus,
  runRetention,
  type ApiRetentionStatus,
  type ApiRetentionTable,
} from '@/lib/api'
import { useAuth } from '@/lib/auth-context'
import { formatDateTime } from '@/lib/format'

const NOME_DA_TABELA: Record<string, string> = {
  api_requests: 'Tráfego de API',
  raw_events: 'Eventos crus',
  alerts: 'Alertas',
}

function formatarBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const unidades = ['kB', 'MB', 'GB', 'TB']
  let valor = n / 1024
  let i = 0
  while (valor >= 1024 && i < unidades.length - 1) {
    valor /= 1024
    i += 1
  }
  return `${valor.toFixed(valor < 10 ? 1 : 0).replace('.', ',')} ${unidades[i]}`
}

function formatarNumero(n: number): string {
  return n.toLocaleString('pt-BR')
}

function diasDesde(iso: string | null): number | null {
  if (!iso) return null
  const dias = (Date.now() - new Date(iso).getTime()) / 86_400_000
  return dias < 0 ? 0 : Math.floor(dias)
}

/**
 * A régua do tempo de uma tabela, da esquerda para a direita: dado que acabou
 * de chegar, dado já comprimido, e o ponto em que ele deixa de existir.
 *
 * É a resposta visual para "quanto tempo esse dado fica", que em número
 * solto ninguém consegue comparar entre as três tabelas.
 */
function Regua({ tabela }: { tabela: ApiRetentionTable }) {
  const comprime = tabela.politicas.compress.dias_no_banco
  const apaga = tabela.politicas.drop.dias_no_banco
  const idade = diasDesde(tabela.dado_mais_antigo)

  // Sem nenhuma das duas políticas não existe régua para desenhar: a tabela
  // cresce reta até o disco acabar, e é isso que a faixa precisa dizer.
  if (!comprime && !apaga) {
    return (
      <div className="mt-3 rounded-lg border border-dashed border-destructive/40 bg-destructive/5 px-3 py-2">
        <p className="text-[12px] text-destructive">
          Sem política nenhuma. Esta tabela cresce até o disco encher.
        </p>
      </div>
    )
  }

  // Quando não há retenção, a régua precisa de um fim visual mesmo sem prazo.
  // O dobro do prazo de compressão dá espaço para a faixa fria aparecer.
  const fim = apaga ?? (comprime ? comprime * 2 : 1)
  const quente = comprime ? Math.min(comprime / fim, 1) : 0
  const frio = 1 - quente

  return (
    <div className="mt-3">
      <div className="flex h-7 overflow-hidden rounded-lg border border-border">
        {quente > 0 && (
          <div
            className="flex items-center justify-center bg-warning/15 text-[10.5px] font-medium text-warning"
            style={{ width: `${quente * 100}%` }}
            title={`Os primeiros ${comprime} dias ficam sem compressão`}
          >
            {quente > 0.16 ? `${comprime}d sem comprimir` : ''}
          </div>
        )}
        {frio > 0 && (
          <div
            className="flex items-center justify-center border-l border-border bg-primary/12 text-[10.5px] font-medium text-primary"
            style={{ width: `${frio * 100}%` }}
            title={
              apaga
                ? `Comprimido do dia ${comprime ?? 0} ao ${apaga}`
                : 'Comprimido e guardado para sempre'
            }
          >
            {apaga ? `comprimido até ${apaga}d` : 'comprimido, sem prazo para apagar'}
          </div>
        )}
      </div>

      <div className="mt-1 flex items-center justify-between text-[10.5px] text-muted-foreground">
        {/* Repetido aqui porque em tabela de retenção longa a faixa quente fica
            estreita demais para caber o texto dentro dela. */}
        <span>{comprime ? `comprime aos ${comprime}d` : 'sem compressão'}</span>
        {idade !== null && (
          <span>
            o mais antigo aqui tem {idade} {idade === 1 ? 'dia' : 'dias'}
          </span>
        )}
        <span className="flex items-center gap-1">
          {apaga ? (
            <>
              <Trash2 className="h-3 w-3" />
              apaga em {apaga}d
            </>
          ) : (
            <>
              <InfinityIcon className="h-3 w-3" />
              nunca apaga
            </>
          )}
        </span>
      </div>
    </div>
  )
}

function CartaoDaTabela({ tabela }: { tabela: ApiRetentionTable }) {
  const { compress, drop } = tabela.politicas
  const divergindo = !compress.em_dia || !drop.em_dia
  const proxima = compress.proxima_execucao ?? drop.proxima_execucao

  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <div className="flex flex-wrap items-start gap-x-3 gap-y-1">
        <div className="min-w-0">
          <h2 className="font-heading text-sm font-semibold text-foreground">
            {NOME_DA_TABELA[tabela.tabela] ?? tabela.tabela}
          </h2>
          <p className="text-[12px] text-muted-foreground">{tabela.resumo}</p>
        </div>

        <div className="ml-auto text-right">
          <div className="font-heading text-base font-semibold text-foreground">
            {formatarBytes(tabela.bytes)}
          </div>
          <div className="text-[11px] text-muted-foreground">
            {formatarNumero(tabela.linhas)} {tabela.linhas === 1 ? 'linha' : 'linhas'}
          </div>
        </div>
      </div>

      <Regua tabela={tabela} />

      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-muted-foreground">
        <span>
          {tabela.chunks_comprimidos} de {tabela.chunks}{' '}
          {tabela.chunks === 1 ? 'bloco comprimido' : 'blocos comprimidos'}
        </span>

        {tabela.economia ? (
          <span className="text-success">
            {String(tabela.economia).replace('.', ',')}x menor no que já comprimiu, de{' '}
            {formatarBytes(tabela.bytes_antes_da_compressao ?? 0)} para{' '}
            {formatarBytes(tabela.bytes_depois_da_compressao ?? 0)}
          </span>
        ) : (
          <span>nada comprimido ainda, o dado é novo demais</span>
        )}

        {proxima && <span className="ml-auto">próxima passada {formatDateTime(proxima)}</span>}
      </div>

      {divergindo && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/5 px-3 py-2">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" />
          <p className="text-[12px] text-warning">
            O banco não bate com o arquivo de configuração. No banco:{' '}
            {compress.dias_no_banco ?? 'sem compressão'}
            {compress.dias_no_banco ? 'd para comprimir' : ''} e{' '}
            {drop.dias_no_banco ? `${drop.dias_no_banco}d para apagar` : 'sem retenção'}. Use
            Reaplicar configuração para corrigir.
          </p>
        </div>
      )}
    </div>
  )
}

export function RetentionPage() {
  const { isAdmin } = useAuth()
  const [dados, setDados] = useState<ApiRetentionStatus | null>(null)
  const [erro, setErro] = useState<string | null>(null)
  const [ocupado, setOcupado] = useState<string | null>(null)
  const [aviso, setAviso] = useState<string | null>(null)

  const carregar = useCallback(async () => {
    try {
      setDados(await getRetentionStatus())
      setErro(null)
    } catch (e) {
      setErro(e instanceof Error ? e.message : 'Falha ao carregar')
    }
  }, [])

  useEffect(() => {
    void carregar()
  }, [carregar])

  async function comprimirAgora() {
    setOcupado('run')
    setAviso(null)
    try {
      const r = await runRetention(false)
      const falharam = r.execucoes.filter((e) => !e.ok)
      setAviso(
        falharam.length
          ? `Falhou em ${falharam.map((e) => e.tabela).join(', ')}`
          : `Compressão executada em ${r.execucoes.length} ${
              r.execucoes.length === 1 ? 'tabela' : 'tabelas'
            }. O que estava no prazo foi comprimido.`,
      )
      await carregar()
    } catch (e) {
      setAviso(e instanceof Error ? e.message : 'Falha ao executar')
    } finally {
      setOcupado(null)
    }
  }

  async function reaplicar() {
    setOcupado('apply')
    setAviso(null)
    try {
      const r = await applyRetention()
      setAviso(
        r.mudancas.length
          ? r.mudancas.join(' | ')
          : 'Nada a mudar: o banco já está igual à configuração.',
      )
      await carregar()
    } catch (e) {
      setAviso(e instanceof Error ? e.message : 'Falha ao aplicar')
    } finally {
      setOcupado(null)
    }
  }

  if (erro && !dados) return <ErrorState message={erro} />
  if (!dados) return <LoadingState />

  const semPolitica = dados.tabelas.filter(
    (t) => !t.politicas.compress.dias_no_banco && !t.politicas.drop.dias_no_banco,
  ).length

  return (
    <AppShell title="Armazenamento">
      <p className="text-[13px] text-muted-foreground">
        Quanto o banco está ocupando e quando ele para de crescer. Comprimir não apaga nada: o
        dado continua consultável, só ocupa menos.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <StatPill
          icon={HardDrive}
          tone="text-primary"
          bg="bg-primary/12"
          value={formatarBytes(dados.bytes_total)}
          label="no disco"
          hint="as três tabelas que crescem"
        />
        <StatPill
          icon={Archive}
          tone="text-success"
          bg="bg-success/12"
          value={formatarBytes(dados.bytes_economizados)}
          label="economizados"
          hint="medido, não estimado"
        />
        <StatPill
          icon={semPolitica ? AlertTriangle : Database}
          tone={semPolitica ? 'text-destructive' : 'text-success'}
          bg={semPolitica ? 'bg-destructive/12' : 'bg-success/12'}
          value={dados.ligada ? dados.tabelas.length - semPolitica : 0}
          label="tabelas protegidas"
          hint={dados.ligada ? `de ${dados.tabelas.length}` : 'retenção desligada no .env'}
        />

        {/* Só admin: as duas ações mexem em política que apaga dado. O
            analista continua vendo a tela inteira, que é o que responde
            "o banco vai encher?". */}
        <div className="ml-auto flex gap-2">
          {!isAdmin && (
            <span className="self-center text-[11.5px] text-muted-foreground">
              Mudar política é ação de administrador.
            </span>
          )}
          <Button
            variant="outline"
            onClick={() => void reaplicar()}
            disabled={ocupado !== null || !isAdmin}
          >
            {ocupado === 'apply' ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Reaplicar configuração
          </Button>
          <Button onClick={() => void comprimirAgora()} disabled={ocupado !== null || !isAdmin}>
            {ocupado === 'run' ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Archive className="h-4 w-4" />
            )}
            Comprimir agora
          </Button>
        </div>
      </div>

      {aviso && (
        <div className="rounded-lg border border-border bg-card px-3 py-2 text-[12.5px] text-muted-foreground">
          {aviso}
        </div>
      )}

      {!dados.ligada && (
        <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/5 px-3 py-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
          <p className="text-[12.5px] text-warning">
            RETENTION_ENABLED está falso no .env. Nada é comprimido nem apagado automaticamente, e
            as políticas foram removidas do banco. O dado que já foi comprimido continua comprimido
            e consultável.
          </p>
        </div>
      )}

      <div className="flex flex-col gap-2">
        {dados.tabelas.map((t) => (
          <CartaoDaTabela key={t.tabela} tabela={t} />
        ))}
      </div>

      <p className="text-[11.5px] text-muted-foreground">
        Os prazos ficam no .env e são aplicados a cada vez que o backend sobe. O botão Reaplicar
        faz o mesmo sem reiniciar. A retenção apaga bloco inteiro, nunca linha solta, então ela
        sempre erra para mais: um bloco só sai quando o registro mais novo dentro dele passa do
        prazo. É por isso que o dado mais antigo aqui costuma ser mais velho que o prazo.
      </p>
    </AppShell>
  )
}
