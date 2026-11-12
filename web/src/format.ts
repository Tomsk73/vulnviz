export function compact(n: number): string {
  if (!isFinite(n)) return '–'
  const a = Math.abs(n)
  if (a >= 1e6) return (n / 1e6).toFixed(a >= 1e7 ? 0 : 1) + 'M'
  if (a >= 1e3) return (n / 1e3).toFixed(a >= 1e4 ? 0 : 1) + 'K'
  return String(Math.round(n))
}
export function int(n: number): string { return n.toLocaleString() }
export function days(d: number | null | undefined, digits = 1): string {
  if (d == null || !isFinite(d)) return '–'
  if (Math.abs(d) >= 100) return Math.round(d).toLocaleString()
  return d.toFixed(digits)
}
export function monthLabel(ym: string, short = false): string {
  const [y, m] = ym.split('-').map(Number)
  const d = new Date(Date.UTC(y, m - 1, 1))
  return d.toLocaleDateString(undefined, short ? { month: 'short', year: '2-digit', timeZone: 'UTC' } : { month: 'short', year: 'numeric', timeZone: 'UTC' })
}
export function monthsBetween(from: string, to: string): string[] {
  const out: string[] = []
  let [y, m] = from.split('-').map(Number)
  const [ty, tm] = to.split('-').map(Number)
  while (y < ty || (y === ty && m <= tm)) {
    out.push(`${y}-${String(m).padStart(2, '0')}`)
    m++; if (m > 12) { m = 1; y++ }
  }
  return out
}
export function ymAdd(ym: string, months: number): string {
  let [y, m] = ym.split('-').map(Number)
  m += months
  while (m > 12) { m -= 12; y++ }
  while (m < 1) { m += 12; y-- }
  return `${y}-${String(m).padStart(2, '0')}`
}
export function thisMonth(): string {
  const d = new Date()
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`
}
export function dateTime(s: string | null | undefined): string {
  if (!s) return '–'
  return new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
export function date(s: string | null | undefined): string {
  if (!s) return '–'
  return new Date(s).toLocaleDateString(undefined, { dateStyle: 'medium' })
}
