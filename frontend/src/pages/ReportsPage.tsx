import { CalendarClock, FileDown, FileText, Layers, Sparkles } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { StatPill } from '@/components/ui/stat-pill'
import { reports } from '@/lib/mock-data'

export function ReportsPage() {
  const latest = reports[0]
  return (
    <AppShell title="Relatórios">
      <div className="grow overflow-y-auto px-4 pb-14 pt-7 sm:px-8">
        <div className="flex flex-wrap gap-3">
          <StatPill icon={FileText} tone="text-primary" bg="bg-primary/12" value={reports.length} label="relatórios gerados" hint="ao total" />
          <StatPill icon={CalendarClock} tone="text-chart-4" bg="bg-chart-4/12" value={latest?.generatedAt ?? '—'} label="último gerado" hint={latest?.periodLabel ?? ''} />
          <StatPill icon={Layers} tone="text-warning" bg="bg-warning/12" value={latest?.totalAlerts ?? 0} label="alertas no último" hint={`${latest?.highCount ?? 0} high`} />
        </div>

        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-card p-5.5">
          <div>
            <h2 className="font-heading text-[14.5px] font-semibold text-foreground">Gerar novo relatório</h2>
            <p className="mt-1 text-[12.5px] text-muted-foreground">
              Consolida eventos, alertas, técnicas MITRE e achados de scanner do período em PDF/HTML.
            </p>
          </div>
          <button
            type="button"
            disabled
            title="Disponível quando o backend estiver conectado"
            className="flex h-10 shrink-0 items-center gap-2 rounded-lg bg-primary px-4 font-heading text-sm font-semibold text-primary-foreground opacity-50"
          >
            <Sparkles className="h-4 w-4" />
            Gerar relatório
          </button>
        </div>

        <div className="mt-5 flex flex-col gap-3.5">
          {reports.map((r) => (
            <div key={r.id} className="flex flex-col gap-4 rounded-xl border border-border bg-card p-5.5 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-3.5">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                  <FileText className="h-[18px] w-[18px] text-primary" strokeWidth={1.75} />
                </div>
                <div>
                  <div className="font-heading text-[13.5px] font-semibold text-foreground">{r.periodLabel}</div>
                  <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">gerado em {r.generatedAt}</div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <StatChip label="eventos" value={r.totalEvents} />
                <StatChip label="alertas" value={r.totalAlerts} />
                <StatChip label="high" value={r.highCount} tone="text-destructive" />
                <StatChip label="medium" value={r.mediumCount} tone="text-warning" />
              </div>

              <div className="flex items-center gap-2">
                <DownloadButton label="HTML" />
                <DownloadButton label="PDF" />
              </div>
            </div>
          ))}
        </div>

        <p className="mt-5 text-[11.5px] text-muted-foreground">
          Os relatórios são gerados pelo script de Fase 7 (Jinja2 + WeasyPrint). Os botões de download serão
          habilitados quando essa página estiver conectada à API do backend.
        </p>
      </div>
    </AppShell>
  )
}

function StatChip({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <span className="rounded-md bg-white/[0.05] px-2.5 py-1 text-[11px]">
      <span className={tone ?? 'text-foreground'}>{value}</span> <span className="text-muted-foreground">{label}</span>
    </span>
  )
}

function DownloadButton({ label }: { label: string }) {
  return (
    <button
      type="button"
      disabled
      title="Disponível quando o backend estiver conectado"
      className="flex h-8 items-center gap-1.5 rounded-md border border-white/10 px-3 text-xs text-muted-foreground opacity-60"
    >
      <FileDown className="h-3.5 w-3.5" />
      {label}
    </button>
  )
}
