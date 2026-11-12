import { FormEvent, useState } from 'react'
import { CVEDetail, DistroInfo, get } from '../api'
import { distroColor, severityLabel } from '../palette'
import { date, dateTime, days } from '../format'

export function CveLookup({ distros }: { distros: DistroInfo[] }) {
  const [q, setQ] = useState('')
  const [detail, setDetail] = useState<CVEDetail | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const name = (id: string) => distros.find(d => d.id === id)?.name ?? id

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const id = q.trim().toUpperCase().replace(/^(?!CVE-)/, 'CVE-')
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) { setErr('Enter a CVE ID such as CVE-2024-3094.'); return }
    setBusy(true); setErr(null)
    try { setDetail((await get<CVEDetail>(`/api/v1/cve/${id}`)).data) } catch (ex) { setDetail(null); setErr((ex as Error).message) } finally { setBusy(false) }
  }

  return (
    <section className="section lookup" aria-labelledby="lookup-h">
      <div className="section-head"><div><h2 id="lookup-h">Look up one CVE</h2><p>See when each distribution fixed it, and where it is still open.</p></div></div>
      <form onSubmit={submit}>
        <input value={q} onChange={e => setQ(e.target.value)} placeholder="CVE-2024-3094" aria-label="CVE ID" />
        <button type="submit" className="btn primary" disabled={busy}>Look up</button>
        {err && <span className="error">{err}</span>}
      </form>
      {detail && (
        <div className="cve-card">
          <h3>{detail.id} <span className={`sev ${detail.severity}`}>{severityLabel[detail.severity]}{detail.cvss_score != null ? ` ${detail.cvss_score}` : ''}</span>{detail.kev && <span className="sev" style={{ background: 'var(--danger)', marginLeft: 6 }}>Known exploited</span>}</h3>
          <div className="meta">
            <span>Published {dateTime(detail.published)}</span>
            {detail.cvss_source && <span>Score from {detail.cvss_source}</span>}
            {detail.cwes.length > 0 && <span>{detail.cwes.join(', ')}</span>}
            <span>{detail.state.toLowerCase()}</span>
          </div>
          {detail.title && <p><b>{detail.title}</b></p>}
          {detail.description && <p>{detail.description}</p>}
          <div className="table-wrap">
            <table className="data">
              <caption className="sr-only">Fixes by distribution</caption>
              <thead><tr><th>Distribution</th><th>Release</th><th>Package</th><th>Advisory</th><th>Fixed</th><th className="num">Days after publication</th></tr></thead>
              <tbody>
                {detail.fixes.map((f, i) => (
                  <tr key={i}>
                    <td><span className="chip" style={{ ['--c' as string]: distroColor(f.distro), border: 0, padding: 0, cursor: 'default' }}><i />{name(f.distro)}</span></td>
                    <td>{f.ecosystem}</td><td>{f.package}</td><td>{f.advisory_id}</td><td>{date(f.fix_time)}</td>
                    <td className="num">{f.fix_time_trusted ? days(f.ttr_days) : <span title="This record's date is not a remediation date">–</span>}</td>
                  </tr>
                ))}
                {detail.open.map((o, i) => (
                  <tr key={'o' + i} style={{ color: 'var(--ink-3)' }}>
                    <td><span className="chip" style={{ ['--c' as string]: distroColor(o.distro), border: 0, padding: 0, cursor: 'default' }}><i />{name(o.distro)}</span></td>
                    <td>{o.ecosystem}</td><td>{o.package}</td><td>{o.advisory_id}</td><td>not fixed</td><td className="num">–</td>
                  </tr>
                ))}
                {detail.fixes.length + detail.open.length === 0 && <tr><td colSpan={6} style={{ color: 'var(--ink-3)' }}>No tracked distribution lists this CVE.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  )
}
