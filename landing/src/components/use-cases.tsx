import { motion, useReducedMotion } from 'motion/react'
import { Building2, Globe } from 'lucide-react'

import { SectionHeading } from '@/components/section-heading'

const CASES = [
  {
    icon: Building2,
    title: 'Infraestrutura de empresa',
    desc: 'Servidor, VPN, estação de trabalho, ambiente interno. É onde um invasor tenta força bruta de SSH, escala privilégio com sudo, ou usa uma credencial que vazou em outro lugar. É exatamente o que os coletores de log do Veryon enxergam, do jeito que um agente de produção enxergaria.',
    tags: ['T1110 força bruta', 'T1548.003 privilégio', 'T1078 conta válida'],
  },
  {
    icon: Globe,
    title: 'Aplicações web e APIs',
    desc: 'Todo site ou API pública recebe atenção automatizada o tempo inteiro: bot testando login, ferramenta procurando vulnerabilidade conhecida, cliente suspeito enumerando rotas ou puxando objeto atrás de objeto. O scanner do Veryon (Nmap + Nuclei) rastreia a vulnerabilidade com ciclo de vida, e a análise de comportamento de API pontua quem age como atacante antes do estrago.',
    tags: ['T1595 varredura', 'T1190 injeção', 'BOLA / IDOR'],
  },
]

export function UseCases() {
  const reduced = useReducedMotion()

  return (
    <section id="casos" className="mx-auto max-w-6xl px-6 py-24">
      <SectionHeading
        eyebrow="onde isso se aplica"
        title="A mesma lógica vale pra servidor ou pra site"
        description="Monitoramento de ataque não é só coisa de empresa grande com SOC montado. Todo site exposto na internet recebe atenção de gente que você não conhece."
      />

      <div className="mx-auto mt-10 grid max-w-4xl gap-5 sm:grid-cols-2">
        {CASES.map((c, i) => (
          <motion.div
            key={c.title}
            initial={reduced ? false : { opacity: 0, y: 18 }}
            whileInView={reduced ? undefined : { opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: i * 0.1, ease: [0.22, 1, 0.36, 1] }}
            className="glass rounded-2xl p-7"
          >
            <c.icon className="h-7 w-7 text-primary" strokeWidth={1.6} />
            <h3 className="mt-4 font-heading text-lg font-semibold text-foreground">{c.title}</h3>
            <p className="mt-2.5 text-[14px] leading-relaxed text-muted-foreground">{c.desc}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              {c.tags.map((t) => (
                <span key={t} className="rounded-md border border-white/12 px-2.5 py-1 font-mono text-[11px] text-white/50">
                  {t}
                </span>
              ))}
            </div>
          </motion.div>
        ))}
      </div>
    </section>
  )
}
