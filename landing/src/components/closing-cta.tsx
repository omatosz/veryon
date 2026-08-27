import { motion, useReducedMotion } from 'motion/react'
import { ArrowRight } from 'lucide-react'
import Balancer from 'react-wrap-balancer'

import { Button } from '@/components/ui/button'

const REPO_URL = 'https://github.com/omatosz/veryon'

export function ClosingCta() {
  const reduced = useReducedMotion()

  return (
    <section className="mx-auto max-w-4xl px-6 py-24">
      <motion.div
        initial={reduced ? false : { opacity: 0, y: 18 }}
        whileInView={reduced ? undefined : { opacity: 1, y: 0 }}
        viewport={{ once: true, margin: '-60px' }}
        transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
        className="glass-strong rounded-3xl px-8 py-14 text-center sm:px-14"
      >
        <div className="mb-4 font-mono text-[11.5px] uppercase tracking-[0.14em] text-primary">projeto de portfólio</div>
        <h2 className="font-heading text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
          <Balancer>Um SOC de laboratório, mas com ataque de verdade</Balancer>
        </h2>
        <p className="mx-auto mt-4 max-w-lg text-[15.5px] leading-relaxed text-muted-foreground">
          <Balancer>
            Nada aqui é maquete: o honeypot recebe sessão real, a regra Sigma casa contra evento real, o alerta grava
            no banco de verdade. O código inteiro está aberto, do honeypot ao dashboard.
          </Balancer>
        </p>
        <div className="mt-8 flex justify-center">
          <Button size="lg" asChild>
            <a href={REPO_URL} target="_blank" rel="noopener">
              github.com/omatosz/veryon
              <ArrowRight className="ml-1.5 h-4 w-4" />
            </a>
          </Button>
        </div>
      </motion.div>
    </section>
  )
}
