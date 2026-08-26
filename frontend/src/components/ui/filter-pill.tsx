import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

interface FilterPillProps {
  active: boolean
  onClick: () => void
  children: ReactNode
  activeColor?: string
}

export function FilterPill({ active, onClick, children, activeColor }: FilterPillProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={active && activeColor ? { background: activeColor, borderColor: activeColor, color: 'var(--primary-foreground)' } : undefined}
      className={cn(
        'h-[30px] rounded-full border px-3.5 text-xs font-medium transition-colors',
        active
          ? activeColor
            ? ''
            : 'border-primary bg-primary text-primary-foreground'
          : 'border-white/10 text-muted-foreground hover:border-white/25',
      )}
    >
      {children}
    </button>
  )
}
