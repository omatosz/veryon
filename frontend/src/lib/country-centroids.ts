/**
 * Centro aproximado de cada país, em [longitude, latitude].
 *
 * Existe pra plotar o ponto no mapa a partir do código de duas letras que o
 * enriquecimento devolve. A alternativa seria casar o código com os países do
 * topojson, mas ali a chave é o número ISO e o casamento falharia calado
 * sempre que um código não batesse. Aqui, país que não está na tabela some da
 * lista de forma visível em vez de virar ponto no lugar errado.
 *
 * Precisão de centro de país basta: o ponto marca origem de tráfego, não
 * posição de alguém.
 */
export const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  AD: [1.6, 42.5], AE: [54.0, 24.0], AF: [66.0, 33.0], AL: [20.0, 41.0], AM: [45.0, 40.0],
  AO: [17.9, -12.5], AR: [-64.0, -34.0], AT: [13.3, 47.3], AU: [133.0, -27.0], AZ: [47.5, 40.5],
  BA: [18.0, 44.0], BD: [90.0, 24.0], BE: [4.5, 50.8], BF: [-2.0, 13.0], BG: [25.0, 43.0],
  BH: [50.5, 26.0], BI: [30.0, -3.5], BJ: [2.2, 9.5], BO: [-65.0, -17.0], BR: [-51.9, -14.2],
  BW: [24.0, -22.0], BY: [28.0, 53.0], BZ: [-88.8, 17.2], CA: [-106.3, 56.1], CD: [25.0, -2.9],
  CF: [21.0, 7.0], CG: [15.0, -1.0], CH: [8.2, 46.8], CI: [-5.5, 7.5], CL: [-71.0, -30.0],
  CM: [12.0, 6.0], CN: [104.2, 35.9], CO: [-74.0, 4.0], CR: [-84.0, 10.0], CU: [-80.0, 21.5],
  CY: [33.0, 35.0], CZ: [15.5, 49.8], DE: [10.5, 51.2], DK: [10.0, 56.0], DO: [-70.7, 19.0],
  DZ: [3.0, 28.0], EC: [-78.0, -1.5], EE: [26.0, 59.0], EG: [30.0, 27.0], ER: [39.0, 15.0],
  ES: [-3.7, 40.5], ET: [39.0, 8.0], FI: [26.0, 64.0], FJ: [178.0, -18.0], FR: [2.2, 46.6],
  GA: [11.8, -0.6], GB: [-1.5, 54.0], GE: [43.5, 42.0], GH: [-1.0, 8.0], GN: [-10.0, 11.0],
  GR: [22.0, 39.0], GT: [-90.3, 15.5], GY: [-59.0, 5.0], HK: [114.1, 22.3], HN: [-86.5, 15.0],
  HR: [15.5, 45.1], HT: [-72.3, 19.0], HU: [19.5, 47.2], ID: [113.9, -0.8], IE: [-8.0, 53.4],
  IL: [35.0, 31.5], IN: [78.9, 20.6], IQ: [44.0, 33.0], IR: [53.0, 32.0], IS: [-18.0, 65.0],
  IT: [12.6, 42.8], JM: [-77.3, 18.1], JO: [36.0, 31.0], JP: [138.3, 36.2], KE: [38.0, 1.0],
  KG: [75.0, 41.0], KH: [105.0, 12.5], KP: [127.0, 40.0], KR: [127.8, 35.9], KW: [47.7, 29.3],
  KZ: [67.0, 48.0], LA: [102.5, 18.0], LB: [35.9, 33.9], LK: [81.0, 7.5], LR: [-9.5, 6.5],
  LT: [24.0, 55.2], LU: [6.1, 49.8], LV: [25.0, 56.9], LY: [17.0, 27.0], MA: [-6.0, 32.0],
  MD: [29.0, 47.0], ME: [19.3, 42.7], MG: [47.0, -19.0], MK: [21.7, 41.6], ML: [-4.0, 17.0],
  MM: [96.0, 21.0], MN: [105.0, 46.0], MO: [113.5, 22.2], MR: [-12.0, 20.0], MT: [14.4, 35.9],
  MU: [57.5, -20.3], MW: [34.0, -13.5], MX: [-102.6, 23.6], MY: [102.0, 4.2], MZ: [35.0, -18.3],
  NA: [17.0, -22.0], NE: [8.0, 16.0], NG: [8.0, 10.0], NI: [-85.0, 13.0], NL: [5.3, 52.1],
  NO: [10.0, 62.0], NP: [84.0, 28.0], NZ: [174.0, -41.0], OM: [57.0, 21.0], PA: [-80.0, 9.0],
  PE: [-76.0, -10.0], PH: [122.0, 12.9], PK: [70.0, 30.4], PL: [19.1, 52.0], PR: [-66.5, 18.2],
  PS: [35.2, 31.9], PT: [-8.2, 39.4], PY: [-58.0, -23.5], QA: [51.2, 25.3], RO: [25.0, 46.0],
  RS: [21.0, 44.0], RU: [98.0, 61.5], RW: [30.0, -2.0], SA: [45.0, 24.0], SD: [30.0, 15.0],
  SE: [16.0, 62.0], SG: [103.8, 1.35], SI: [15.0, 46.1], SK: [19.5, 48.7], SN: [-14.5, 14.5],
  SO: [46.0, 6.0], SS: [30.0, 7.0], SV: [-89.0, 13.8], SY: [38.0, 35.0], TD: [19.0, 15.0],
  TG: [1.2, 8.6], TH: [101.0, 15.0], TJ: [71.0, 39.0], TM: [59.0, 39.0], TN: [9.5, 34.0],
  TR: [35.0, 39.0], TT: [-61.2, 10.7], TW: [121.0, 23.7], TZ: [35.0, -6.4], UA: [32.0, 49.0],
  UG: [32.0, 1.4], US: [-98.5, 39.8], UY: [-56.0, -33.0], UZ: [64.0, 41.4], VE: [-66.0, 7.0],
  VN: [106.0, 16.2], YE: [48.0, 15.5], ZA: [24.0, -29.0], ZM: [28.0, -13.5], ZW: [30.0, -19.0],
}

/** Nome legível pra quem não decora código de país. Só os mais frequentes em
 *  dado de ameaça; o resto cai no próprio código, que já é informação. */
export const COUNTRY_NAMES: Record<string, string> = {
  AR: 'Argentina', AU: 'Austrália', BR: 'Brasil', CA: 'Canadá', CH: 'Suíça',
  CL: 'Chile', CN: 'China', CO: 'Colômbia', CZ: 'Tchéquia', DE: 'Alemanha',
  DK: 'Dinamarca', EG: 'Egito', ES: 'Espanha', FI: 'Finlândia', FR: 'França',
  GB: 'Reino Unido', HK: 'Hong Kong', ID: 'Indonésia', IN: 'Índia', IR: 'Irã',
  IT: 'Itália', JP: 'Japão', KR: 'Coreia do Sul', MX: 'México', MY: 'Malásia',
  NG: 'Nigéria', NL: 'Países Baixos', PL: 'Polônia', PT: 'Portugal', RO: 'Romênia',
  RU: 'Rússia', SE: 'Suécia', SG: 'Singapura', TH: 'Tailândia', TR: 'Turquia',
  TW: 'Taiwan', UA: 'Ucrânia', US: 'Estados Unidos', VN: 'Vietnã', ZA: 'África do Sul',
}

export function countryLabel(code: string): string {
  return COUNTRY_NAMES[code] ?? code
}
