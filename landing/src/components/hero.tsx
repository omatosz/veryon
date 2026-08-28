import { motion, useReducedMotion, type Variants } from 'motion/react'
import Balancer from 'react-wrap-balancer'
import { ArrowRight } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { LiveFeed } from '@/components/live-feed'

const REPO_URL = 'https://github.com/omatosz/veryon'

const container: Variants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.12, delayChildren: 0.05 } },
}

const item: Variants = {
  hidden: { opacity: 0, y: 14, filter: 'blur(6px)' },
  visible: {
    opacity: 1,
    y: 0,
    filter: 'blur(0px)',
    transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] },
  },
}

export function Hero() {
  const reduced = useReducedMotion()
  const animate = !reduced

  return (
    <section id="top" className="relative overflow-hidden pb-20 pt-20 sm:pb-28 sm:pt-28">
      <motion.div
        className="mx-auto flex max-w-6xl flex-col items-start gap-10 px-6"
        variants={animate ? container : undefined}
        initial={animate ? 'hidden' : false}
        animate={animate ? 'visible' : undefined}
      >
        <motion.div variants={item} className="glass inline-flex items-center gap-2 rounded-full px-4 py-1.5 font-mono text-[11.5px] uppercase tracking-[0.14em] text-primary">
          laboratório soc / siem
        </motion.div>

        <motion.h1 variants={item} className="max-w-3xl font-heading text-[2.6rem] font-semibold leading-[1.08] tracking-tight text-foreground sm:text-6xl">
          <Balancer>Todo ataque deixa rastro. A pergunta é se tem alguém olhando.</Balancer>
        </motion.h1>

        <motion.p variants={item} className="max-w-xl text-lg leading-relaxed text-muted-foreground">
          <Balancer>
            Veryon é um SOC completo construído do zero: honeypot recebendo ataque de verdade, análise de
            vulnerabilidade e de comportamento de API, detecção com regras Sigma mapeadas ao MITRE ATT&amp;CK, e
            prevenção de ameaça que age sozinha com trilhos de segurança.
          </Balancer>
        </motion.p>

        <motion.div variants={item} className="flex flex-wrap items-center gap-4">
          <Button size="lg" asChild>
            <a href={REPO_URL} target="_blank" rel="noopener">
              Ver o código
              <ArrowRight className="ml-1.5 h-4 w-4" />
            </a>
          </Button>
          <Button size="lg" variant="outline" asChild>
            <a href="#pipeline">Como funciona</a>
          </Button>
        </motion.div>

        <motion.div variants={item}>
          <LiveFeed />
        </motion.div>
      </motion.div>
    </section>
  )
}
