import { useState } from 'react'
import { motion } from 'motion/react'

import { cn } from '@/lib/utils'
import { useDragScroll } from '@/lib/use-drag-scroll'
import { SectionHeading } from '@/components/section-heading'

interface Stage {
  name: string
  fact: string
  desc: string
}

const STAGES: Stage[] = [
  {
    name: 'Honeypot',
    fact: 'cowrie · portas 2222/2223',
    desc: 'Cowrie simula um servidor SSH/Telnet vulnerável, isolado numa rede própria sem rota pro resto da stack. Ninguém legítimo tem motivo pra logar ali, então todo login é, por definição, um ataque.',
  },
  {
    name: 'Coleta de logs',
    fact: 'Windows Event Log · auth.log',
    desc: 'Coletores leves leem o log de segurança do Windows e o auth.log do Linux, o mesmo sinal que um SOC recebe de um servidor de produção de verdade.',
  },
  {
    name: 'Detecção',
    fact: '7 regras Sigma · MITRE ATT&CK',
    desc: 'Um motor próprio avalia regras no formato Sigma, o padrão da indústria pra detecção, mapeadas ao MITRE ATT&CK. Cobre força bruta, execução de comando, uso indevido de privilégio e mais.',
  },
  {
    name: 'Threat intel',
    fact: 'AbuseIPDB · VirusTotal · OTX',
    desc: 'IPs suspeitos são cruzados com três fontes públicas de reputação, a mesma pergunta que um analista faria: esse IP já apareceu fazendo coisa ruim em outro lugar?',
  },
  {
    name: 'Dashboard',
    fact: 'FastAPI + JWT',
    desc: 'Uma API própria expõe tudo isso autenticado com JWT pra um dashboard real: fila de alertas com triagem, feed de eventos, consulta de reputação de IP.',
  },
  {
    name: 'Resposta',
    fact: 'bloqueio no honeypot',
    desc: 'O analista revisa o alerta e decide bloquear o IP de origem. O Cowrie passa a rejeitar aquele IP de verdade, direto no namespace de rede do container, até alguém desbloquear.',
  },
  {
    name: 'Relatório',
    fact: 'PDF/HTML',
    desc: 'Gera um resumo de segurança em PDF com alertas por severidade, técnicas observadas e IPs mais ativos, o tipo de documento que sairia de um SOC de verdade pra um cliente.',
  },
]

export function Pipeline() {
  const [active, setActive] = useState(0)
  const stage = STAGES[active]
  const { ref: navRef, dragging } = useDragScroll<HTMLDivElement>()

  return (
    <section id="pipeline" className="mx-auto max-w-6xl px-6 py-24">
      <SectionHeading
        eyebrow="o que o veryon prova"
        title="Do ataque até o alerta, sem pular etapa"
        description="Cada estágio abaixo é um serviço de verdade rodando, não uma ilustração."
      />

      <div className="mx-auto mt-10 max-w-3xl">
        <div
          ref={navRef}
          className={cn('scrollbar-none flex gap-2 overflow-x-auto pb-2 cursor-grab', dragging && 'cursor-grabbing select-none')}
        >
          {STAGES.map((s, i) => (
            <button
              key={s.name}
              type="button"
              onClick={() => !dragging && setActive(i)}
              className={cn(
                'glass flex shrink-0 items-center gap-2.5 rounded-xl px-4 py-3 transition-colors',
                active === i ? 'border-primary/50 bg-primary/10' : 'hover:border-white/20',
                dragging && 'pointer-events-none',
              )}
            >
              <span
                className={cn(
                  'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border font-mono text-[11px]',
                  active === i ? 'border-primary text-primary' : 'border-white/20 text-white/40',
                )}
              >
                {i + 1}
              </span>
              <span className={cn('whitespace-nowrap font-heading text-[13.5px] font-semibold', active === i ? 'text-primary' : 'text-foreground')}>
                {s.name}
              </span>
            </button>
          ))}
        </div>

        <div className="glass-strong mt-4 min-h-[10.5rem] overflow-hidden rounded-2xl p-7">
          <motion.div key={stage.name} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
            <h3 className="font-heading text-xl font-semibold text-foreground">{stage.name}</h3>
            <p className="mt-2.5 text-[14.5px] leading-relaxed text-muted-foreground">{stage.desc}</p>
            <span className="mt-4 inline-block rounded-lg border border-primary/25 bg-primary/10 px-3 py-1 font-mono text-[12px] text-primary">
              {stage.fact}
            </span>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
