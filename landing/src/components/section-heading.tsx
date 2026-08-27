import { motion, useReducedMotion } from 'motion/react'
import Balancer from 'react-wrap-balancer'

export function SectionHeading({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description?: string
}) {
  const reduced = useReducedMotion()

  return (
    <motion.div
      initial={reduced ? false : { opacity: 0, y: 16 }}
      whileInView={reduced ? undefined : { opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className="mx-auto max-w-2xl text-center"
    >
      <div className="mb-4 font-mono text-[11.5px] uppercase tracking-[0.14em] text-primary">{eyebrow}</div>
      <h2 className="font-heading text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
        <Balancer>{title}</Balancer>
      </h2>
      {description && (
        <p className="mt-4 text-[15.5px] leading-relaxed text-muted-foreground">
          <Balancer>{description}</Balancer>
        </p>
      )}
    </motion.div>
  )
}
