import { useState } from 'react'
import { motion } from 'motion/react'

import { cn } from '@/lib/utils'
import { SectionHeading } from '@/components/section-heading'

type PanelState = 'off' | 'on'

export function WhyMonitor() {
  const [state, setState] = useState<PanelState>('off')

  return (
    <section className="mx-auto max-w-6xl px-6 py-24">
      <SectionHeading
        eyebrow="por que monitorar"
        title="Ataque sem monitoramento é ataque sem consequência"
        description="A maioria dos ataques que dão certo não é sofisticada. É ignorada. Um log de força bruta se perde no meio de milhares de linhas, um sudo estranho não vira alerta pra ninguém, um IP conhecido volta a bater na porta sem que ninguém tenha cruzado essa informação antes."
      />

      <div className="glass mx-auto mt-10 max-w-2xl rounded-2xl p-6 sm:p-8">
        <div className="glass mb-6 inline-flex gap-1 rounded-full p-1">
          <button
            type="button"
            onClick={() => setState('off')}
            className={cn(
              'rounded-full px-4 py-2 font-heading text-[13px] font-semibold transition-colors',
              state === 'off' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            Sem monitoramento
          </button>
          <button
            type="button"
            onClick={() => setState('on')}
            className={cn(
              'rounded-full px-4 py-2 font-heading text-[13px] font-semibold transition-colors',
              state === 'on' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            Com o Veryon
          </button>
        </div>

        <div className="relative min-h-[9.5rem] overflow-hidden">
          {state === 'off' ? (
            <motion.div
              key="off"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25 }}
              className="rounded-xl border border-dashed border-white/15 bg-black/20 p-5"
            >
              <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-white/40">raw_events · linha 84.192</div>
              <div className="font-mono text-[13px] text-white/50">
                2026-08-26T03:14:07Z ssh[31022]: Accepted password for root from 172.28.0.1 port 51422
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="on"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25 }}
              className="glass rounded-xl border-primary/25 p-5"
            >
              <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-primary">alerts · triagem</div>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <span className="rounded-md border border-red-400/40 bg-red-400/10 px-2 py-0.5 font-mono text-[11px] text-red-300">high</span>
                <span className="rounded-md border border-primary/35 bg-primary/10 px-2 py-0.5 font-mono text-[11px] text-primary">T1110 · força bruta</span>
              </div>
              <p className="text-[14px] leading-relaxed text-muted-foreground">
                <strong className="text-foreground">Login bem-sucedido no honeypot,</strong> origem 172.28.0.1, regra Sigma
                disparada, IP já cruzado com threat intel. Pronto pra um analista reconhecer, agir e bloquear.
              </p>
            </motion.div>
          )}
        </div>
      </div>
    </section>
  )
}
