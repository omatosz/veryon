import { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion, AnimatePresence } from 'motion/react'

interface FeedLine {
  id: number
  t: string
  tag: string
  msg: string
}

const POOL: Omit<FeedLine, 'id'>[] = [
  { t: '12:04:07', tag: 'cowrie', msg: 'login bem-sucedido · 172.28.0.1 · T1110' },
  { t: '12:04:09', tag: 'detection', msg: 'regra disparada · força bruta ssh · high' },
  { t: '12:05:41', tag: 'linux', msg: 'sudo comando sensível · T1548.003' },
  { t: '12:06:02', tag: 'threatintel', msg: 'consulta 8.8.8.8 · reputação limpa' },
  { t: '12:07:15', tag: 'windows', msg: 'logon privilégio admin · T1078' },
  { t: '12:08:30', tag: 'scanner', msg: 'nuclei finding · severidade média · T1595' },
  { t: '12:09:02', tag: 'cowrie', msg: 'comando executado · whoami; id · T1059' },
  { t: '12:10:12', tag: 'enforcement', msg: 'ip bloqueado após triagem · 172.28.0.1' },
]

const MAX_LINES = 6

export function LiveFeed() {
  const reduced = useReducedMotion()
  const [lines, setLines] = useState<FeedLine[]>(() => POOL.slice(0, MAX_LINES).map((l, i) => ({ ...l, id: i })))
  const idxRef = useRef(MAX_LINES)

  useEffect(() => {
    if (reduced) return
    const interval = setInterval(() => {
      setLines((prev) => {
        const next = POOL[idxRef.current % POOL.length]
        idxRef.current += 1
        const withNew = [...prev, { ...next, id: idxRef.current }]
        return withNew.slice(-MAX_LINES)
      })
    }, 1900)
    return () => clearInterval(interval)
  }, [reduced])

  return (
    <div className="glass-strong w-full max-w-xl rounded-2xl">
      <div className="flex items-center justify-between border-b border-white/10 px-5 py-3">
        <span className="font-mono text-[11px] tracking-wide text-muted-foreground">feed do laboratório (simulado)</span>
        <span className="flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          ao vivo
        </span>
      </div>
      <div className="flex h-[13.5rem] flex-col justify-end gap-2 overflow-hidden px-5 py-4 font-mono text-[12.5px]">
        <AnimatePresence initial={false}>
          {lines.map((l) => (
            <motion.div
              key={l.id}
              initial={reduced ? false : { opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
              className="flex gap-2.5 text-muted-foreground"
            >
              <span className="shrink-0 text-white/30">{l.t}</span>
              <span className="shrink-0 text-primary">{l.tag}</span>
              <span className="truncate">{l.msg}</span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  )
}
