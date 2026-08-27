import { ShieldCheck } from 'lucide-react'

const REPO_URL = 'https://github.com/omatosz/veryon'

export function Nav() {
  return (
    <header className="glass sticky top-0 z-50 border-x-0 border-t-0">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
        <a href="#top" className="flex items-center gap-2 font-heading text-[15px] font-semibold tracking-tight text-foreground">
          <ShieldCheck className="h-[18px] w-[18px] text-primary" strokeWidth={1.9} />
          Veryon
        </a>
        <nav className="hidden items-center gap-8 font-mono text-[12.5px] uppercase tracking-wide text-muted-foreground sm:flex">
          <a href="#pipeline" className="transition-colors hover:text-foreground">
            Como funciona
          </a>
          <a href="#casos" className="transition-colors hover:text-foreground">
            Onde se aplica
          </a>
        </nav>
        <a
          href={REPO_URL}
          target="_blank"
          rel="noopener"
          className="glass rounded-full px-4 py-2 font-mono text-[12.5px] text-foreground transition-colors hover:border-primary/40"
        >
          Ver no GitHub
        </a>
      </div>
    </header>
  )
}
