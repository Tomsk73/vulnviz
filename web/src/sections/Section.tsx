import { ReactNode, useState } from 'react'

export function Section({ id, title, lede, tools, table, children }: {
  id: string; title: string; lede: ReactNode; tools?: ReactNode; table?: ReactNode; children: ReactNode
}) {
  const [showTable, setShowTable] = useState(false)
  return (
    <section className="section" aria-labelledby={`${id}-h`}>
      <div className="section-head">
        <div><h2 id={`${id}-h`}>{title}</h2><p>{lede}</p></div>
        <div className="tools">
          {tools}
          {table && <button type="button" className="btn" aria-pressed={showTable} onClick={() => setShowTable(s => !s)}>{showTable ? 'Show chart' : 'Show table'}</button>}
        </div>
      </div>
      {showTable && table ? table : children}
    </section>
  )
}
