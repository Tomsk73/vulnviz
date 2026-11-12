import { useState } from 'react'
import { useSize } from './useSize'
import { niceTicks, labelEvery } from './scale'
import { Tooltip } from './Tooltip'
import { compact, int, monthLabel } from '../format'

export interface Series { key: string; label: string; color: string }

/**
 * Stacked columns over months. Marks are capped at 24px, segments separated by
 * a 2px surface gap, hover lifts the column and shows every series at that X.
 */
export function StackedColumns({ months, series, values, height = 220, maxY, title }: {
  months: string[]; series: Series[]; values: Record<string, Record<string, number>>; height?: number; maxY?: number; title: string
}) {
  const [ref, width] = useSize<HTMLDivElement>()
  const [hover, setHover] = useState<number | null>(null)
  const m = { top: 10, right: 8, bottom: 26, left: 40 }
  const innerW = Math.max(0, width - m.left - m.right)
  const innerH = height - m.top - m.bottom
  const totals = months.map(mo => series.reduce((s, se) => s + (values[mo]?.[se.key] ?? 0), 0))
  const top = maxY ?? Math.max(1, ...totals)
  const ticks = niceTicks(top)
  const yMax = ticks[ticks.length - 1]
  const y = (v: number) => innerH - (v / yMax) * innerH
  const band = months.length ? innerW / months.length : 0
  const barW = Math.min(24, Math.max(2, band - 4))
  const every = labelEvery(months.length, innerW)
  const gap = 2

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      {width > 0 && (
        <svg height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={title} onMouseLeave={() => setHover(null)}>
          <g transform={`translate(${m.left},${m.top})`}>
            <g className="grid">{ticks.map(t => <line key={t} x1={0} x2={innerW} y1={y(t)} y2={y(t)} />)}</g>
            <g className="tick-y">{ticks.map(t => <text key={t} x={-8} y={y(t)} dy="0.35em" textAnchor="end">{compact(t)}</text>)}</g>
            <g className="axis"><line x1={0} x2={innerW} y1={innerH} y2={innerH} /></g>
            {months.map((mo, i) => {
              const cx = i * band + band / 2
              let acc = 0
              const segs = series.map(se => {
                const v = values[mo]?.[se.key] ?? 0
                const y0 = y(acc), y1 = y(acc + v)
                acc += v
                return { se, v, y0, y1 }
              }).filter(s => s.v > 0)
              return (
                <g key={mo} className="mark" tabIndex={0} onMouseEnter={() => setHover(i)} onFocus={() => setHover(i)} onBlur={() => setHover(null)} aria-label={`${monthLabel(mo)}: ${int(totals[i])}`}>
                  <rect x={cx - band / 2} y={0} width={band} height={innerH} fill="transparent" />
                  {segs.map((s, j) => {
                    const isTop = j === segs.length - 1
                    const h = Math.max(0, s.y0 - s.y1 - (j > 0 ? gap : 0))
                    const yy = s.y1 + (j > 0 ? gap : 0)
                    const r = isTop ? Math.min(4, h / 2) : 0
                    const w = barW, x0 = cx - barW / 2
                    const d = isTop
                      ? `M${x0},${yy + h} V${yy + r} Q${x0},${yy} ${x0 + r},${yy} H${x0 + w - r} Q${x0 + w},${yy} ${x0 + w},${yy + r} V${yy + h} Z`
                      : `M${x0},${yy} H${x0 + w} V${yy + h} H${x0} Z`
                    return <path key={s.se.key} d={d} fill={s.se.color} opacity={hover === null || hover === i ? 1 : 0.55} />
                  })}
                  {i % every === 0 && <text x={cx} y={innerH + 16} textAnchor="middle">{monthLabel(mo, true)}</text>}
                </g>
              )
            })}
          </g>
        </svg>
      )}
      {hover !== null && months[hover] && (
        <Tooltip x={m.left + hover * band + band / 2} y={m.top} width={width} title={monthLabel(months[hover])}
          rows={[...series].reverse().map(se => ({ label: se.label, value: int(values[months[hover]]?.[se.key] ?? 0), color: se.color, square: true }))}
          foot={<><span>Total</span><b>{int(totals[hover])}</b></>} />
      )}
    </div>
  )
}
