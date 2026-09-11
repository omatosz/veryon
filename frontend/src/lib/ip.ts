/**
 * Diz se vale perguntar reputação pública sobre um IP.
 *
 * Segue a regra do serviço threatintel: endereço privado, loopback, link-local,
 * reservado ou multicast nunca é consultado nos provedores, então nunca tem dado
 * para mostrar. As telas perguntavam mesmo assim, para até 15 IPs por carga, e
 * cada pergunta voltava 404 no console do navegador e no log do backend.
 */
const FAIXAS_V4: [number, number][] = [
  [0x00000000, 8], // 0.0.0.0/8
  [0x0a000000, 8], // 10.0.0.0/8
  [0x64400000, 10], // 100.64.0.0/10, NAT de operadora
  [0x7f000000, 8], // 127.0.0.0/8
  [0xa9fe0000, 16], // 169.254.0.0/16
  [0xac100000, 12], // 172.16.0.0/12, onde moram as redes do Docker
  [0xc0000000, 24], // 192.0.0.0/24
  [0xc0000200, 24], // 192.0.2.0/24, documentação
  [0xc0a80000, 16], // 192.168.0.0/16
  [0xc6120000, 15], // 198.18.0.0/15
  [0xc6336400, 24], // 198.51.100.0/24, documentação
  [0xcb007100, 24], // 203.0.113.0/24, documentação
  [0xe0000000, 4], // 224.0.0.0/4, multicast
  [0xf0000000, 4], // 240.0.0.0/4, reservado
]

function paraNumero(ip: string): number | null {
  const partes = ip.split('.')
  if (partes.length !== 4) return null
  let n = 0
  for (const p of partes) {
    if (!/^\d{1,3}$/.test(p)) return null
    const v = Number(p)
    if (v > 255) return null
    n = n * 256 + v
  }
  return n
}

export function temReputacaoPublica(ip: string): boolean {
  const alvo = ip.trim().toLowerCase()

  if (alvo.includes(':')) {
    const v4 = alvo.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (v4) return temReputacaoPublica(v4[1])
    if (alvo === '::' || alvo === '::1') return false
    // fc00::/7 privada, fe80::/10 link-local, ff00::/8 multicast, 2001:db8::/32 documentação
    if (/^f[cd]/.test(alvo) || /^fe[89ab]/.test(alvo) || alvo.startsWith('ff') || alvo.startsWith('2001:db8:')) {
      return false
    }
    return true
  }

  const n = paraNumero(alvo)
  if (n === null) return false
  return !FAIXAS_V4.some(([rede, bits]) => {
    const mascara = (0xffffffff << (32 - bits)) >>> 0
    return ((n & mascara) >>> 0) === rede
  })
}
