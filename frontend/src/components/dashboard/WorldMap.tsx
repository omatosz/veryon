import { useMemo } from 'react'
import { geoNaturalEarth1, geoPath, geoGraticule10 } from 'd3-geo'
import { feature } from 'topojson-client'
import type { FeatureCollection, Geometry } from 'geojson'
import type { Topology } from 'topojson-specification'
import worldData from 'world-atlas/countries-110m.json'
import { Building2, HelpCircle } from 'lucide-react'

import { COUNTRY_CENTROIDS, countryLabel } from '@/lib/country-centroids'
import type { ApiGeoSummary } from '@/lib/api'

const LARGURA = 780
const ALTURA = 340

// O topojson é convertido uma vez só, no carregamento do módulo. Fazer isso a
// cada render custaria alguns milissegundos por quadro durante a virada do
// cartão, que é justamente quando não pode engasgar.
const topo = worldData as unknown as Topology
const terra = feature(topo, topo.objects.countries) as unknown as FeatureCollection<Geometry>

const projecao = geoNaturalEarth1().fitExtent(
  [
    [6, 6],
    [LARGURA - 6, ALTURA - 6],
  ],
  terra,
)
const caminho = geoPath(projecao)
const caminhoTerra = caminho(terra) ?? ''
const caminhoGrade = caminho(geoGraticule10()) ?? ''

export function WorldMap({ geo }: { geo: ApiGeoSummary | null }) {
  const pontos = useMemo(() => {
    if (!geo) return []
    const max = Math.max(1, ...geo.points.map((p) => p.events))
    return geo.points
      .map((p) => {
        const centro = COUNTRY_CENTROIDS[p.country]
        if (!centro) return null
        const xy = projecao(centro)
        if (!xy) return null
        return {
          ...p,
          x: xy[0],
          y: xy[1],
          // Raiz quadrada em vez de proporção direta: com proporção, um país
          // com dez vezes mais tráfego vira um círculo de área cem vezes
          // maior e engole o mapa inteiro.
          r: 3 + Math.sqrt(p.events / max) * 11,
        }
      })
      .filter((p): p is NonNullable<typeof p> => p !== null)
  }, [geo])

  const semOrigemExterna = pontos.length === 0

  return (
    <div className="flex h-full min-h-0 gap-4">
      <div className="relative min-w-0 grow">
        <svg viewBox={`0 0 ${LARGURA} ${ALTURA}`} className="h-full w-full" role="img" aria-label="Mapa de origem dos IPs">
          <path d={caminhoGrade} fill="none" stroke="rgba(255,255,255,0.045)" strokeWidth={0.5} />
          <path d={caminhoTerra} fill="rgba(255,255,255,0.055)" stroke="rgba(255,255,255,0.12)" strokeWidth={0.5} />

          {pontos.map((p) => {
            const cor = p.blocked > 0 ? '#EF4444' : p.worst_score >= 50 ? '#F59E0B' : 'var(--primary)'
            return (
              <g key={p.country}>
                <circle cx={p.x} cy={p.y} r={p.r} fill={cor} opacity={0.18} />
                <circle cx={p.x} cy={p.y} r={p.r * 0.45} fill={cor}>
                  <title>
                    {countryLabel(p.country)}: {p.events} evento(s), {p.ips} IP(s)
                    {p.blocked > 0 ? `, ${p.blocked} bloqueado(s)` : ''}
                  </title>
                </circle>
              </g>
            )
          })}
        </svg>

        {semOrigemExterna && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <div className="max-w-[300px] rounded-lg border border-border bg-card/90 px-4 py-3 text-center backdrop-blur-sm">
              <div className="text-[12.5px] text-foreground">Nenhuma origem externa localizada</div>
              <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                O país vem do enriquecimento de threat intel, que só responde para IP público. Tráfego de rede
                interna não tem país a descobrir.
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="flex w-[186px] shrink-0 flex-col gap-2 overflow-y-auto">
        {pontos.slice(0, 6).map((p) => (
          <div key={p.country} className="flex items-center gap-2">
            <span className="w-7 shrink-0 rounded bg-white/[0.06] px-1 py-0.5 text-center font-mono text-[10px] text-foreground">
              {p.country}
            </span>
            <span className="min-w-0 grow truncate text-[11.5px] text-foreground">{countryLabel(p.country)}</span>
            <span className="shrink-0 font-mono text-[11px] text-muted-foreground">{p.events}</span>
          </div>
        ))}

        {geo && (
          <div className="mt-auto flex flex-col gap-1.5 border-t border-border pt-2.5">
            <Linha
              icone={Building2}
              rotulo="rede interna"
              valor={geo.internal_events}
              dica="Tráfego de dentro do laboratório. Não tem país."
            />
            <Linha
              icone={HelpCircle}
              rotulo="não identificado"
              valor={geo.unidentified_events}
              dica="IP público que o enriquecimento ainda não resolveu."
            />
            <span className="text-[10px] text-muted-foreground/70">{geo.total_ips} IP(s) distinto(s) em 30 dias</span>
          </div>
        )}
      </div>
    </div>
  )
}

function Linha({
  icone: Icone,
  rotulo,
  valor,
  dica,
}: {
  icone: typeof Building2
  rotulo: string
  valor: number
  dica: string
}) {
  return (
    <div className="flex items-center gap-1.5" title={dica}>
      <Icone className="h-3 w-3 shrink-0 text-muted-foreground" strokeWidth={1.75} />
      <span className="grow text-[11px] text-muted-foreground">{rotulo}</span>
      <span className="font-mono text-[11px] text-foreground">{valor}</span>
    </div>
  )
}
