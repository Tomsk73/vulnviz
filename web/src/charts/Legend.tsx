export interface LegendItem { label: string; color: string; line?: boolean }

export function Legend({ items }: { items: LegendItem[] }) {
  if (items.length < 2) return null
  return (
    <div className="legend" aria-label="Legend">
      {items.map(it => (
        <span key={it.label}><i className={it.line ? 'line' : ''} style={{ ['--c' as string]: it.color }} />{it.label}</span>
      ))}
    </div>
  )
}
