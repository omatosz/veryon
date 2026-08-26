export type Severity = 'high' | 'medium' | 'low'
export type AlertStatus = 'open' | 'acknowledged' | 'closed'
export type EventSource = 'linux' | 'windows' | 'cowrie' | 'scanner'

export const severityMeta: Record<Severity, { label: string; color: string; bg: string }> = {
  high: { label: 'high', color: 'text-destructive', bg: 'bg-destructive/14' },
  medium: { label: 'medium', color: 'text-warning', bg: 'bg-warning/14' },
  low: { label: 'low', color: 'text-success', bg: 'bg-success/14' },
}

export const statusMeta: Record<AlertStatus, { label: string; color: string }> = {
  open: { label: 'Aberto', color: 'text-destructive' },
  acknowledged: { label: 'Reconhecido', color: 'text-warning' },
  closed: { label: 'Fechado', color: 'text-muted-foreground' },
}

export const sourceMeta: Record<EventSource, { label: string; color: string }> = {
  linux: { label: 'linux', color: 'text-chart-2' },
  windows: { label: 'windows', color: 'text-chart-3' },
  cowrie: { label: 'cowrie', color: 'text-destructive' },
  scanner: { label: 'scanner', color: 'text-chart-4' },
}

// --- Relatórios: o backend ainda não expõe uma API de relatórios (Fase 7 é
// um script standalone que gera PDF/HTML direto em reports/output/), então
// essa lista continua mockada até essa página ser conectada. ---

export interface ReportEntry {
  id: number
  periodLabel: string
  generatedAt: string
  totalEvents: number
  totalAlerts: number
  highCount: number
  mediumCount: number
}

export const reports: ReportEntry[] = [
  {
    id: 2,
    periodLabel: '19/08/2026 – 26/08/2026',
    generatedAt: '26/08/2026 01:27',
    totalEvents: 97,
    totalAlerts: 12,
    highCount: 3,
    mediumCount: 7,
  },
  {
    id: 1,
    periodLabel: '12/08/2026 – 19/08/2026',
    generatedAt: '19/08/2026 08:56',
    totalEvents: 141,
    totalAlerts: 19,
    highCount: 5,
    mediumCount: 10,
  },
]
