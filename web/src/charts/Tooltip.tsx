import { ReactNode } from 'react'

export interface TipRow { label: string; value: string; color?: string; square?: boolean }

export function Tooltip({ x, y, width, title, rows, foot }: { x: number; y: number; width: number; title: ReactNode; rows: TipRow[]; foot?: ReactNode }) {
  // Flip to the left of the pointer when near the right edge.
  const left = x > width * 0.62 ? undefined : x + 14
  const right = x > width * 0.62 ? width - x + 14 : undefined
  return (
    <div className="tooltip" role="status" style={{ left, right, top: Math.max(0, y - 12) }}>
      <div className="t-head">{title}</div>
      {rows.map((r, i) => (
        <div className="t-row" key={i}>
          <span>{r.color && <i className={r.square ? 'sq' : ''} style={{ ['--c' as string]: r.color }} />}{r.label}</span>
          <b>{r.value}</b>
        </div>
      ))}
      {foot && <div className="t-row" style={{ marginTop: 4 }}>{foot}</div>}
    </div>
  )
}
