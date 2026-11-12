import { useState } from 'react'
import { useSize } from './useSize'
import { niceTicks, labelEvery } from './scale'
import { Tooltip } from './Tooltip'
import { monthLabel } from '../format'

export interface LineSeries { key: string; label: string; color: string; points: Record<string, number | null>; counts?: Record<string, number> }

/** Multi-series line chart with a crosshair that snaps to the nearest month. */
export function MultiLine({ months, series, height = 260, format, unit, title, emphasis }: {
  months: string[]; series: LineSeries[]; height?: number; format: (v: number) => string; unit: string; title: string; emphasis?: string | null
}) {
  const [ref, width] = useSize<HTMLDivElement>()
  const [hover, setHover] = useState<number | null>(null)
  const m = { top: 12, right: 92, bottom: 26, left: 44 }
  const innerW = Math.max(0, width - m.left - m.right)
  const innerH = height - m.top - m.bottom
  let max = 0
  for (const s of series) for (const mo of months) { const v = s.points[mo]; if (v != null && v > max) max = v }
  const ticks = niceTicks(Math.max(1, max))
  const yMax = ticks[ticks.length - 1]
  const y = (v: number) => innerH - (v / yMax) * innerH
  const x = (i: number) => (months.length <= 1 ? innerW / 2 : (i / (months.length - 1)) * innerW)
  const every = labelEvery(months.length, innerW)

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const px = e.clientX - rect.left - m.left
    if (months.length === 0) return
    const i = Math.round((px / Math.max(1, innerW)) * (months.length - 1))
    setHover(Math.max(0, Math.min(months.length - 1, i)))
  }

  // End labels: place at the last defined point; nudge apart only when they collide.
  const ends = series.map(s => {
    let last = -1
    for (let i = months.length - 1; i >= 0; i--) if (s.points[months[i]] != null) { last = i; break }
    return { s, i: last, y: last >= 0 ? y(s.points[months[last]] as number) : 0 }
  }).filter(e => e.i >= 0).sort((a, b) => a.y - b.y)
  for (let i = 1; i < ends.length; i++) if (ends[i].y - ends[i - 1].y < 14) ends[i].y = ends[i - 1].y + 14

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      {width > 0 && (
        <svg height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={title} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
          <g transform={`translate(${m.left},${m.top})`}>
            <g className="grid">{ticks.map(t => <line key={t} x1={0} x2={innerW} y1={y(t)} y2={y(t)} />)}</g>
            <g className="tick-y">{ticks.map(t => <text key={t} x={-8} y={y(t)} dy="0.35em" textAnchor="end">{format(t)}</text>)}</g>
            <g className="axis"><line x1={0} x2={innerW} y1={innerH} y2={innerH} /></g>
            {months.map((mo, i) => i % every === 0 && <text key={mo} x={x(i)} y={innerH + 16} textAnchor="middle">{monthLabel(mo, true)}</text>)}
            {hover !== null && <line className="crosshair" x1={x(hover)} x2={x(hover)} y1={0} y2={innerH} />}
            {series.map(s => {
              const dim = emphasis && emphasis !== s.key
              const color = dim ? 'var(--de-emphasis)' : s.color
              let d = ''
              let pen = false
              months.forEach((mo, i) => {
                const v = s.points[mo]
                if (v == null) { pen = false; return }
                d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)} `
                pen = true
              })
              return (
                <g key={s.key}>
                  <path d={d} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
                  {months.map((mo, i) => {
                    const v = s.points[mo]
                    if (v == null) return null
                    const lone = (i === 0 || s.points[months[i - 1]] == null) && (i === months.length - 1 || s.points[months[i + 1]] == null)
                    if (!lone && hover !== i) return null
                    return <circle key={mo} cx={x(i)} cy={y(v)} r={4} fill={color} stroke="var(--surface)" strokeWidth={2} />
                  })}
                </g>
              )
            })}
            {ends.map(e => {
              const dim = emphasis && emphasis !== e.s.key
              return (
                <g key={e.s.key}>
                  <line x1={x(e.i) + 4} x2={innerW + 10} y1={y(e.s.points[months[e.i]] as number)} y2={e.y} stroke={dim ? 'var(--grid)' : 'var(--axis)'} strokeWidth={1} />
                  <text className="end-label" x={innerW + 14} y={e.y} dy="0.35em" style={{ opacity: dim ? 0.5 : 1 }}>{e.s.label}</text>
                </g>
              )
            })}
          </g>
        </svg>
      )}
      {hover !== null && months[hover] && (
        <Tooltip x={m.left + x(hover)} y={m.top} width={width} title={monthLabel(months[hover])}
          rows={series.map(s => {
            const v = s.points[months[hover]]
            const n = s.counts?.[months[hover]]
            return { label: s.label + (n != null ? ` (${n.toLocaleString()})` : ''), value: v == null ? '–' : `${format(v)} ${unit}`, color: s.color }
          })} />
      )}
    </div>
  )
}
