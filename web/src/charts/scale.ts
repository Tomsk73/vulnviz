export function niceTicks(max: number, count = 4, integer = true): number[] {
  if (max <= 0) return [0]
  if (integer && max <= count) return Array.from({ length: Math.ceil(max) + 1 }, (_, i) => i)
  const raw = max / count
  const pow = Math.pow(10, Math.floor(Math.log10(raw)))
  const step = [1, 2, 2.5, 5, 10].map(m => m * pow).find(s => s >= raw) ?? pow * 10
  const ticks: number[] = []
  for (let v = 0; v <= max + 1e-9; v += step) ticks.push(+v.toFixed(10))
  if (ticks[ticks.length - 1] < max) ticks.push(ticks[ticks.length - 1] + step)
  return ticks
}

export function linear(domainMax: number, rangePx: number): (v: number) => number {
  return v => (domainMax === 0 ? 0 : (v / domainMax) * rangePx)
}

/** Picks which x categories get a label so they never collide. */
export function labelEvery(n: number, widthPx: number, minPx = 54): number {
  if (n === 0) return 1
  return Math.max(1, Math.ceil(n / Math.max(1, Math.floor(widthPx / minPx))))
}
