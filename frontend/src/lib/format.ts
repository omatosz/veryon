export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatDay(iso: string): string {
  return new Date(`${iso}T00:00:00`).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })
}

export function countryFlag(countryCode: string | null | undefined): string | null {
  if (!countryCode || countryCode.length !== 2) return null
  const codePoints = [...countryCode.toUpperCase()].map((c) => 127397 + c.charCodeAt(0))
  return String.fromCodePoint(...codePoints)
}
