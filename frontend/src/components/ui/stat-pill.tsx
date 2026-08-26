interface StatPillProps {
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>
  tone: string
  bg: string
  value: number | string
  label: string
  hint: string
}

export function StatPill({ icon: Icon, tone, bg, value, label, hint }: StatPillProps) {
  return (
    <div className="flex items-center gap-2.5 rounded-full border border-border bg-card py-1.5 pl-1.5 pr-4">
      <div className={`flex h-7 w-7 items-center justify-center rounded-full ${bg}`}>
        <Icon className={`h-3.5 w-3.5 ${tone}`} strokeWidth={2} />
      </div>
      <div className="leading-tight">
        <div className="text-[12.5px] font-semibold text-foreground">
          {value} <span className="font-normal text-muted-foreground">{label}</span>
        </div>
        <div className="text-[10px] text-muted-foreground/70">{hint}</div>
      </div>
    </div>
  )
}
