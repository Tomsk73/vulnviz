export interface Column { key: string; label: string; num?: boolean; format?: (v: unknown) => string }

export function DataTable({ columns, rows, caption }: { columns: Column[]; rows: Record<string, unknown>[]; caption: string }) {
  return (
    <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
      <table className="data">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>{columns.map(c => <th key={c.key} className={c.num ? 'num' : ''} scope="col">{c.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>{columns.map(c => <td key={c.key} className={c.num ? 'num' : ''}>{c.format ? c.format(r[c.key]) : String(r[c.key] ?? '–')}</td>)}</tr>
          ))}
          {rows.length === 0 && <tr><td colSpan={columns.length} style={{ color: 'var(--ink-3)' }}>No rows for this selection.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
