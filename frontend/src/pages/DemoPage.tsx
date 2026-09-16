import { useEffect, useRef, useState } from 'react'
import { CheckCircle2, Loader2, PlayCircle, ShieldAlert } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { ErrorState, LoadingState } from '@/components/ui/async-state'
import { Button } from '@/components/ui/button'
import { getDemoStatus, runFullDemo, ApiError } from '@/lib/api'

const POLL_ANDAMENTO_MS = 4000

const PASSOS = [
  'Enfileira a varredura de vulnerabilidade (roda em segundo plano, minutos).',
  'Login bem-sucedido no honeypot SSH.',
  'Força bruta no honeypot: seis tentativas recusadas.',
  'Injeção contra a própria API: SQLi, XSS e path traversal.',
  'Varredura de 25 rotas inexistentes, mais rajada de 15 falhas de login.',
  'Ingestão externa simulada em dois IPs com a mesma assinatura, para fundir em um ator.',
  'Espera o motor de detecção processar, depois bloqueia o IP do alerta de força bruta.',
  'Liga a política SSH-BRUTE em vigor.',
]

export function DemoPage() {
  const [disponivel, setDisponivel] = useState<boolean | null>(null)
  const [emAndamento, setEmAndamento] = useState(false)
  const [disparando, setDisparando] = useState(false)
  const [mensagem, setMensagem] = useState<string | null>(null)
  const [erro, setErro] = useState<string | null>(null)
  const poll = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    getDemoStatus()
      .then((s) => {
        setDisponivel(true)
        setEmAndamento(s.em_andamento)
      })
      .catch(() => setDisponivel(false))
  }, [])

  useEffect(() => {
    if (!emAndamento) {
      if (poll.current) clearInterval(poll.current)
      return
    }
    poll.current = setInterval(() => {
      getDemoStatus()
        .then((s) => setEmAndamento(s.em_andamento))
        .catch(() => {
          /* mantém o último estado conhecido se uma sondagem falhar */
        })
    }, POLL_ANDAMENTO_MS)
    return () => {
      if (poll.current) clearInterval(poll.current)
    }
  }, [emAndamento])

  async function disparar() {
    setDisparando(true)
    setErro(null)
    setMensagem(null)
    try {
      const resp = await runFullDemo()
      setMensagem(resp.mensagem)
      setEmAndamento(true)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setEmAndamento(true)
        setErro('Já tem uma demonstração em andamento.')
      } else {
        setErro(e instanceof Error ? e.message : 'Não foi possível disparar')
      }
    } finally {
      setDisparando(false)
    }
  }

  if (disponivel === null) return <LoadingState />
  if (disponivel === false) {
    return (
      <ErrorState message="Este ambiente não tem a demonstração ligada (DEMO_MODE_ENABLED=false no .env)." />
    )
  }

  return (
    <AppShell title="Demonstração">
      <p className="text-[13px] text-muted-foreground">
        Dispara de uma vez os ataques do guia em <code>docs/ATAQUES.md</code>: honeypot, injeção
        contra a própria API, varredura de rotas e ingestão externa. No final, bloqueia o IP do
        alerta de força bruta e liga a política correspondente, para a demonstração terminar com o
        Veryon já reagindo, não só recebendo ataque.
      </p>

      <div className="flex items-start gap-2 rounded-xl border border-warning/30 bg-warning/10 p-3 text-[12.5px] text-foreground">
        <ShieldAlert className="mt-0.5 h-4 w-4 flex-shrink-0 text-warning" />
        <p>
          O IP de origem de tudo isto é sempre interno (o gateway da rede Docker). A política, em
          vigor, não bloqueia esse IP de verdade: os trilhos de segurança recusam bloquear
          incerto, e a trilha de ações mostra <b>held</b> em vez de <b>applied</b>. É o motor
          funcionando como deveria.
        </p>
      </div>

      <div className="rounded-xl border border-border bg-card p-4">
        <ol className="ml-4 list-decimal space-y-1.5 text-[12.5px] text-muted-foreground">
          {PASSOS.map((passo) => (
            <li key={passo}>{passo}</li>
          ))}
        </ol>

        <div className="mt-4 flex items-center gap-3">
          <Button onClick={() => void disparar()} disabled={disparando || emAndamento}>
            {disparando || emAndamento ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <PlayCircle className="h-4 w-4" />
            )}
            {emAndamento ? 'Em andamento' : 'Disparar demonstração completa'}
          </Button>

          {emAndamento && (
            <span className="text-[12px] text-muted-foreground">
              Acompanhe pelas telas de Eventos e Alertas. Isto some sozinho quando terminar.
            </span>
          )}
        </div>

        {mensagem && !erro && (
          <p className="mt-3 flex items-center gap-1.5 text-[12.5px] text-success">
            <CheckCircle2 className="h-4 w-4" />
            {mensagem}
          </p>
        )}
        {erro && <p className="mt-3 text-[12.5px] text-destructive">{erro}</p>}
      </div>
    </AppShell>
  )
}
