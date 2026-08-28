import { useEffect, useMemo, useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Globe, RotateCcw } from 'lucide-react'

import { cn } from '@/lib/utils'
import { getGeo, getTimeseries, type ApiGeoSummary, type ApiSeriesPoint } from '@/lib/api'
import { formatDay } from '@/lib/format'
import { WorldMap } from './WorldMap'

const DAYS = 14

/** As categorias vêm do tipo do evento que originou o alerta. 'origem' não é
 *  uma categoria de verdade: é o filtro que vira o cartão pro mapa. */
const FILTROS = [
  { id: 'todos', label: 'Todos' },
  { id: 'honeypot', label: 'Honeypot' },
  { id: 'api', label: 'API' },
  { id: 'scanner', label: 'Scanner' },
  { id: 'host', label: 'Host' },
  { id: 'origem', label: 'Origem dos IPs', icon: Globe },
] as const

type FiltroId = (typeof FILTROS)[number]['id']

const NIVEIS = [
  { key: 'critical', label: 'crítico', color: '#EF4444' },
  { key: 'high', label: 'alto', color: '#F59E0B' },
  { key: 'medium', label: 'médio', color: '#3B82F6' },
  { key: 'low', label: 'baixo', color: '#22C55E' },
] as const

interface Barra {
  label: string
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

export function AlertsChartCard() {
  const [filtro, setFiltro] = useState<FiltroId>('todos')
  const [serie, setSerie] = useState<ApiSeriesPoint[]>([])
  const [geo, setGeo] = useState<ApiGeoSummary | null>(null)
  const [carregando, setCarregando] = useState(true)

  const virado = filtro === 'origem'

  useEffect(() => {
    let cancelado = false
    function carregar() {
      Promise.all([getTimeseries(DAYS), getGeo(30)])
        .then(([s, g]) => {
          if (cancelado) return
          setSerie(s)
          setGeo(g)
        })
        .finally(() => !cancelado && setCarregando(false))
    }
    carregar()
    const id = setInterval(carregar, 5000)
    return () => {
      cancelado = true
      clearInterval(id)
    }
  }, [])

  const barras = useMemo(() => montarBarras(serie, filtro), [serie, filtro])
  const totalNoFiltro = barras.reduce((s, b) => s + b.total, 0)

  return (
    <div className="rounded-xl border border-border bg-card p-5.5">
      <div className="mb-3.5 flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-heading text-[14.5px] font-semibold text-foreground">
          {virado ? 'Origem dos IPs' : 'Alertas por dia'}
        </h2>
        <div className="flex flex-wrap items-center gap-1.5">
          {FILTROS.map((f) => {
            const Icone = 'icon' in f ? f.icon : null
            const ativo = filtro === f.id
            return (
              <button
                key={f.id}
                type="button"
                onClick={() => setFiltro(f.id)}
                className={cn(
                  'flex h-6.5 items-center gap-1 rounded-md px-2 text-[11px] font-medium transition-colors',
                  ativo
                    ? f.id === 'origem'
                      ? 'bg-[#A78BFA]/16 text-[#A78BFA]'
                      : 'bg-primary/16 text-primary'
                    : 'text-muted-foreground hover:bg-white/[0.05] hover:text-foreground',
                )}
              >
                {Icone && <Icone className="h-3 w-3" strokeWidth={2} />}
                {f.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* A perspectiva fica no pai e o giro no filho: sem isso o navegador
          achata a transformação e a virada vira um corte seco. */}
      <div style={{ perspective: 1400 }}>
        <div
          className="relative transition-transform duration-700 ease-out motion-reduce:transition-none"
          style={{
            transformStyle: 'preserve-3d',
            transform: virado ? 'rotateY(180deg)' : 'rotateY(0deg)',
            height: 268,
          }}
        >
          <Face oculto={virado}>
            {carregando ? (
              <Vazio texto="Carregando…" />
            ) : totalNoFiltro === 0 ? (
              <Vazio texto="Nenhum alerta nesse filtro nos últimos 14 dias." />
            ) : (
              <>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={barras} margin={{ top: 4, right: 8, left: -22, bottom: 0 }}>
                    <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                    <XAxis
                      dataKey="label"
                      tick={{ fill: '#8E8EA3', fontSize: 10.5 }}
                      axisLine={{ stroke: 'rgba(255,255,255,0.08)' }}
                      tickLine={false}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fill: '#8E8EA3', fontSize: 10.5 }}
                      axisLine={false}
                      tickLine={false}
                      width={28}
                    />
                    <Tooltip content={<DicaGrafico />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                    {NIVEIS.map((n, i) => (
                      <Bar
                        key={n.key}
                        dataKey={n.key}
                        stackId="niveis"
                        fill={n.color}
                        name={n.label}
                        // Só a barra do topo arredonda, senão a pilha fica com
                        // cantos no meio e parece quebrada.
                        radius={i === 0 ? [3, 3, 0, 0] : [0, 0, 0, 0]}
                        maxBarSize={26}
                      />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
                <div className="mt-1 flex flex-wrap items-center gap-3 text-[10.5px]">
                  {NIVEIS.map((n) => (
                    <span key={n.key} className="flex items-center gap-1.5 text-muted-foreground">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: n.color }} />
                      {n.label}
                    </span>
                  ))}
                  <span className="ml-auto font-mono text-muted-foreground">
                    {totalNoFiltro} alerta(s) no período
                  </span>
                </div>
              </>
            )}
          </Face>

          <Face verso oculto={!virado}>
            <WorldMap geo={geo} />
          </Face>
        </div>
      </div>
    </div>
  )
}

/** Uma face do cartão. `verso` já nasce girada, então quando o pai vira ela
 *  fica de frente. `oculto` tira a face de trás do caminho do teclado e do
 *  leitor de tela: backface-visibility esconde da vista, não da navegação. */
function Face({
  children,
  verso = false,
  oculto,
}: {
  children: React.ReactNode
  verso?: boolean
  oculto: boolean
}) {
  return (
    <div
      aria-hidden={oculto}
      inert={oculto ? true : undefined}
      className="absolute inset-0 flex flex-col"
      style={{
        backfaceVisibility: 'hidden',
        WebkitBackfaceVisibility: 'hidden',
        transform: verso ? 'rotateY(180deg)' : undefined,
      }}
    >
      {children}
    </div>
  )
}

function montarBarras(serie: ApiSeriesPoint[], filtro: FiltroId): Barra[] {
  const dias = new Map<string, Barra>()
  const hoje = new Date()
  for (let i = DAYS - 1; i >= 0; i--) {
    const d = new Date(hoje)
    d.setDate(d.getDate() - i)
    const chave = d.toISOString().slice(0, 10)
    dias.set(chave, { label: formatDay(chave), critical: 0, high: 0, medium: 0, low: 0, total: 0 })
  }

  for (const p of serie) {
    if (filtro !== 'todos' && filtro !== 'origem' && p.category !== filtro) continue
    const barra = dias.get(p.ts.slice(0, 10))
    if (!barra) continue
    if (p.level === 'critical' || p.level === 'high' || p.level === 'medium' || p.level === 'low') {
      barra[p.level] += p.count
      barra.total += p.count
    }
  }

  return [...dias.values()]
}

function DicaGrafico({
  active,
  payload,
  label,
}: {
  active?: boolean
  payload?: { name: string; value: number; color: string }[]
  label?: string
}) {
  if (!active || !payload?.length) return null
  const comValor = payload.filter((p) => p.value > 0)
  if (!comValor.length) return null
  return (
    <div className="rounded-lg border border-white/10 bg-[#161620] px-3 py-2 text-[11px] shadow-lg">
      {label && <div className="mb-1 font-mono text-muted-foreground">{label}</div>}
      {comValor.map((p) => (
        <div key={p.name} className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color }} />
          <span className="text-foreground">{p.name}:</span>
          <span className="font-mono text-foreground">{p.value}</span>
        </div>
      ))}
    </div>
  )
}

function Vazio({ texto }: { texto: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-1.5 text-center">
      <RotateCcw className="h-5 w-5 text-muted-foreground/50" strokeWidth={1.5} />
      <span className="text-xs text-muted-foreground">{texto}</span>
    </div>
  )
}
