import { useState } from 'react'
import { useSize } from './useSize'
import { niceTicks } from './scale'
import { Tooltip } from './Tooltip'
import { compact, int } from '../format'

export interface HGroup { key: string; label: string; color: string; values: number[] }

const labelPx = 12.5, labelGap = 10, labelLine = 13.5
let measurer: CanvasRenderingContext2D | null | undefined
/** Rendered width of a row label, or an estimate where canvas is unavailable. */
function labelWidth(s: string): number {
  if (measurer === undefined) measurer = document.createElement('canvas').getContext('2d')
  if (!measurer) return s.length * labelPx * 0.56
  measurer.font = `${labelPx}px ${getComputedStyle(document.body).fontFamily}`
  return measurer.measureText(s).width
}
/** Break a label at the space nearest its middle; a single word stays whole. */
function twoLines(s: string): string[] {
  let at = -1
  for (let i = s.indexOf(' '); i >= 0; i = s.indexOf(' ', i + 1)) {
    if (at < 0 || Math.abs(i - s.length / 2) < Math.abs(at - s.length / 2)) at = i
  }
  return at < 0 ? [s] : [s.slice(0, at), s.slice(at + 1)]
}

/**
 * Horizontal bars, one row per category with one bar per group (grouped) or
 * stacked segments (stacked). Bars never exceed 24px; a 2px surface gap
 * separates neighbours.
 *
 * With onSelect the marks act as buttons: it receives the category index and
 * the group index of the bar or segment, or no group when a whole stacked row
 * is chosen (from the keyboard, or by clicking beside the bar).
 */
export function HBars({ categories, groups, mode, title, percent, onSelect, selectHint }: {
  categories: string[]; groups: HGroup[]; mode: 'grouped' | 'stacked'; title: string; percent?: boolean
  onSelect?: (category: number, group?: number) => void; selectHint?: string
}) {
  const [ref, width] = useSize<HTMLDivElement>()
  const [hover, setHover] = useState<{ c: number; g?: number } | null>(null)
  const button = (c: number, g?: number) => onSelect ? {
    role: 'button', className: 'mark selectable',
    onClick: () => onSelect(c, g),
    onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(c, g) } },
  } : { className: 'mark' }
  // The label column fits the longest row label, up to 42% of the chart; a
  // label that would need more than that wraps onto two lines.
  const labelCap = Math.max(128, Math.floor(width * 0.42))
  const labels = categories.map(cat => {
    const lines = labelWidth(cat) + labelGap + 6 <= labelCap ? [cat] : twoLines(cat)
    return { lines, width: Math.max(...lines.map(labelWidth)) }
  })
  const labelCol = Math.ceil(Math.max(0, ...labels.map(l => l.width))) + labelGap + 6
  const m = { top: 4, right: 56, bottom: 22, left: Math.min(labelCap, Math.max(128, labelCol)) }
  const innerW = Math.max(0, width - m.left - m.right)
  const barH = 16, gap = 2
  const rowH = mode === 'grouped' ? groups.length * (barH + gap) + 14 : barH + 14
  const innerH = categories.length * rowH
  const height = innerH + m.top + m.bottom
  const rowTotals = categories.map((_, ci) => groups.reduce((s, g) => s + (g.values[ci] ?? 0), 0))
  const max = mode === 'stacked' ? Math.max(1, ...rowTotals) : Math.max(1, ...groups.flatMap(g => g.values))
  const ticks = niceTicks(percent ? 100 : max, 4, !percent)
  const xMax = percent ? 100 : ticks[ticks.length - 1]
  const x = (v: number) => (v / xMax) * innerW
  const fmt = (v: number) => (percent ? `${v.toFixed(0)}%` : compact(v))

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      {width > 0 && (
        <svg height={height} viewBox={`0 0 ${width} ${height}`} role={onSelect ? 'group' : 'img'} aria-label={title} onMouseLeave={() => setHover(null)}>
          <g transform={`translate(${m.left},${m.top})`}>
            <g className="grid">{ticks.map(t => <line key={t} x1={x(percent ? t : t)} x2={x(t)} y1={0} y2={innerH} />)}</g>
            {ticks.map(t => <text key={t} x={x(t)} y={innerH + 14} textAnchor="middle">{fmt(t)}</text>)}
            <g className="axis"><line x1={0} x2={0} y1={0} y2={innerH} /></g>
            {categories.map((cat, ci) => {
              const y0 = ci * rowH
              return (
                <g key={cat}>
                  <text textAnchor="end" style={{ fill: 'var(--ink-2)', fontSize: labelPx }}>
                    {labels[ci].lines.map((line, li, all) => (
                      <tspan key={li} x={-labelGap} y={y0 + rowH / 2 - 7 + (li - (all.length - 1) / 2) * labelLine} dy="0.35em">{line}</tspan>
                    ))}
                  </text>
                  {mode === 'grouped' && groups.map((g, gi) => {
                    const v = g.values[ci] ?? 0
                    const w = Math.max(v > 0 ? 2 : 0, x(v))
                    const yy = y0 + gi * (barH + gap)
                    const r = Math.min(4, w / 2)
                    return (
                      <g key={g.key} {...button(ci, gi)} tabIndex={0} onMouseEnter={() => setHover({ c: ci, g: gi })} onFocus={() => setHover({ c: ci, g: gi })} aria-label={`${cat}, ${g.label}: ${int(v)}`}>
                        <rect x={0} y={yy - 1} width={innerW} height={barH + 2} fill="transparent" />
                        {w > 0 && <path d={`M0,${yy} H${w - r} Q${w},${yy} ${w},${yy + r} V${yy + barH - r} Q${w},${yy + barH} ${w - r},${yy + barH} H0 Z`} fill={g.color} />}
                      </g>
                    )
                  })}
                  {mode === 'stacked' && (() => {
                    let acc = 0
                    const yy = y0
                    const segs = groups.map((g, gi) => { const v = g.values[ci] ?? 0; const s = { g, gi, v, x0: x(acc), x1: x(acc + v) }; acc += v; return s }).filter(s => s.v > 0)
                    return (
                      <g {...button(ci)} tabIndex={0} onMouseEnter={() => setHover({ c: ci })} onFocus={() => setHover({ c: ci })} aria-label={`${cat}: ${int(rowTotals[ci])}`}>
                        <rect x={0} y={yy - 1} width={innerW} height={barH + 2} fill="transparent" />
                        {segs.map((s, j) => {
                          const last = j === segs.length - 1
                          const xs = s.x0 + (j > 0 ? gap : 0)
                          const w = Math.max(0, s.x1 - xs)
                          const r = last ? Math.min(4, w / 2) : 0
                          return <path key={s.g.key} d={last ? `M${xs},${yy} H${xs + w - r} Q${xs + w},${yy} ${xs + w},${yy + r} V${yy + barH - r} Q${xs + w},${yy + barH} ${xs + w - r},${yy + barH} H${xs} Z` : `M${xs},${yy} H${xs + w} V${yy + barH} H${xs} Z`} fill={s.g.color}
                            onClick={onSelect && (e => { e.stopPropagation(); onSelect(ci, s.gi) })} />
                        })}
                        <text x={x(rowTotals[ci]) + 8} y={yy + barH / 2} dy="0.35em" style={{ fill: 'var(--ink-2)', fontSize: 12, fontWeight: 600 }}>{percent ? '' : compact(rowTotals[ci])}</text>
                      </g>
                    )
                  })()}
                </g>
              )
            })}
          </g>
        </svg>
      )}
      {hover && (
        <Tooltip x={m.left + innerW / 2} y={m.top + hover.c * rowH} width={width} title={categories[hover.c]} hint={onSelect && selectHint}
          rows={(hover.g != null ? [groups[hover.g]] : groups).map(g => ({ label: g.label, value: percent ? `${(g.values[hover.c] ?? 0).toFixed(1)}%` : int(g.values[hover.c] ?? 0), color: g.color, square: true }))} />
      )}
    </div>
  )
}
