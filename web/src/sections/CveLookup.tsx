import { FormEvent, useState } from 'react'
import { CVEDetail, DistroInfo, get } from '../api'
import { CveCard } from './CveCard'

export function CveLookup({ distros }: { distros: DistroInfo[] }) {
  const [q, setQ] = useState('')
  const [detail, setDetail] = useState<CVEDetail | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

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
      {detail && <CveCard detail={detail} distros={distros} />}
    </section>
  )
}
