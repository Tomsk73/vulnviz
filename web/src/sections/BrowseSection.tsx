import { Fragment, InputHTMLAttributes, useEffect, useRef, useState } from 'react'
import { CVEDetail, DistroInfo, RecordPage, RecordRow, useGet } from '../api'
import { Filters, apiParams } from '../filters'
import { Browse, SortKey, isDefaultBrowse } from '../browse'
import { distroColor, severities, severityLabel } from '../palette'
import { date, days, int, monthLabel } from '../format'
import { Section } from './Section'
import { CveCard } from './CveCard'

const PAGE = 50

/** A text or number input that reports its value once typing pauses, on Enter, or on blur. */
function DebouncedInput({ value, onCommit, ...rest }: { value: string; onCommit: (v: string) => void } & Omit<InputHTMLAttributes<HTMLInputElement>, 'value' | 'onChange'>) {
  const [draft, setDraft] = useState(value)
  const timer = useRef<number>()
  useEffect(() => setDraft(value), [value])
  useEffect(() => () => window.clearTimeout(timer.current), [])
  const commit = (v: string) => { window.clearTimeout(timer.current); if (v !== value) onCommit(v) }
  return (
    <input {...rest} value={draft}
      onChange={e => { const v = e.target.value; setDraft(v); window.clearTimeout(timer.current); timer.current = window.setTimeout(() => commit(v), 350) }}
      onKeyDown={e => { if (e.key === 'Enter') commit(draft) }}
      onBlur={() => commit(draft)} />
  )
}

function CveDetailRow({ id, distros }: { id: string; distros: DistroInfo[] }) {
  const { data, error } = useGet<CVEDetail>(`/api/v1/cve/${id}`, {})
  if (error) return <p className="error">Could not load {id}: {error}</p>
  if (!data) return <p className="chart-sub">Loading {id}…</p>
  return <CveCard detail={data} distros={distros} embedded />
}

const rowKey = (r: RecordRow) => [r.distro, r.cve_id, r.severity, r.ecosystem ?? '', r.package ?? ''].join('|')

export function BrowseSection({ f, distros, selected, b, set, reset }: {
  f: Filters; distros: DistroInfo[]; selected: string[]; b: Browse; set: (patch: Partial<Browse>) => void; reset: () => void
}) {
  const name = (id: string) => distros.find(d => d.id === id)?.name ?? id
  const base = apiParams(f, selected)
  const fixed = b.status === 'fixed'
  const byPackage = f.unit === 'package'
  // The browser narrows the page-wide filters: a distribution outside the
  // selection is ignored, and a page-wide severity takes precedence.
  const distro = selected.length > 1 && selected.includes(b.distro) ? b.distro : ''
  const sevLocked = f.severity !== 'all'
  const severity = sevLocked ? f.severity : b.severity
  const sort: SortKey = !fixed && b.sort === 'fixed' ? 'days' : b.sort
  const rangeBad = !b.undated && b.min !== '' && b.max !== '' && Number(b.min) >= Number(b.max)

  const params: Record<string, string | undefined> = {
    status: b.status,
    distros: distro || base.distros,
    severity: severity === 'all' ? undefined : severity,
    unit: f.unit,
    ecosystem: base.ecosystem,
    // Open CVEs are a snapshot: the date range, month basis and CVE scope only apply to fixes.
    ...(fixed ? { from: f.from, to: f.to, basis: f.basis, scope: f.scope, month: b.month || undefined } : {}),
    min_days: b.undated ? undefined : b.min || undefined,
    max_days: b.undated ? undefined : b.max || undefined,
    undated: b.undated ? 'true' : undefined,
    q: b.q.trim() || undefined,
    sort, order: b.dir,
    limit: String(PAGE), offset: String(b.page * PAGE),
  }
  const { data, loading, error } = useGet<RecordPage>('/api/v1/records', params, !rangeBad)
  const rows = error || rangeBad ? [] : data?.rows ?? []
  const total = error || rangeBad ? 0 : data?.total ?? 0
  // A filter changed elsewhere can leave the page index past the end of the list.
  useEffect(() => {
    if (data && !loading && b.page > 0 && data.offset >= data.total) set({ page: 0 })
  }, [data, loading]) // eslint-disable-line react-hooks/exhaustive-deps

  const [openKey, setOpenKey] = useState<string | null>(null)
  const sortBy = (k: SortKey) => set(b.sort === k ? { dir: b.dir === 'desc' ? 'asc' : 'desc' } : { sort: k, dir: 'desc' })
  const setStatus = (status: Browse['status']) => {
    // The month and undated filters come from one chart each and do not carry over.
    if (status !== b.status) set({ status, month: '', undated: false, sort: status === 'open' && b.sort === 'fixed' ? 'days' : b.sort })
  }

  const cols: { key: string; label: string; sort?: SortKey; num?: boolean }[] = [
    { key: 'distro', label: 'Distribution' },
    { key: 'cve', label: 'CVE' },
    { key: 'severity', label: 'Severity', sort: 'severity' },
    { key: 'published', label: 'CVE published', sort: 'published' },
    ...(fixed ? [{ key: 'fixed', label: 'Fixed', sort: 'fixed' as const }] : []),
    { key: 'days', label: fixed ? 'Days to fix' : 'Days open', sort: 'days', num: true },
    ...(byPackage ? [{ key: 'release', label: 'Release' }, { key: 'package', label: 'Package' }] : [{ key: 'packages', label: 'Packages' }]),
    { key: 'advisory', label: 'Advisory' },
  ]

  // A plain-language statement of what the list holds, page-wide filters included.
  const noun = fixed
    ? (byPackage ? (total === 1 ? 'package fix' : 'package fixes') : (total === 1 ? 'CVE fixed' : 'CVEs fixed'))
    : (byPackage ? (total === 1 ? 'unfixed package' : 'unfixed packages') : (total === 1 ? 'open CVE' : 'open CVEs'))
  const range = `${monthLabel(f.from)} to ${monthLabel(f.to)}`
  const span = fixed ? 'to fix' : 'open'
  const scope: string[] = [distro ? name(distro) : selected.length === 1 ? name(selected[0]) : `${selected.length} distributions`]
  if (base.ecosystem) scope.push(base.ecosystem)
  if (severity !== 'all') scope.push(`${severityLabel[severity] ?? severity} severity`)
  if (b.undated) scope.push('CVE has no publication date')
  else if (b.min !== '' && b.max !== '') scope.push(`${b.min} to ${b.max} days ${span}`)
  else if (b.min !== '') scope.push(`${b.min} days or more ${span}`)
  else if (b.max !== '') scope.push(fixed && Number(b.max) === 0 ? 'fixed before the CVE was published' : `under ${b.max} days ${span}`)
  if (b.q.trim()) scope.push(`matching “${b.q.trim()}”`)
  if (fixed) {
    if (f.basis === 'cve_month') scope.push(b.month ? `CVE published in ${monthLabel(b.month)}` : `CVE published ${range}`)
    else {
      scope.push(b.month ? `fixed in ${monthLabel(b.month)}` : `fixed ${range}`)
      if (f.scope === 'recent') scope.push(`CVE published ${range}`)
    }
  }
  const caveat = !fixed
    ? 'Open as of the last feed refresh; the date range above does not apply. Days open run from the CVE’s publication to now.'
    : f.basis === 'fix_month'
      ? 'Only fixes with a real fix date are listed; switch to “By CVE month” to include the rest.'
      : 'Fixes whose feed gives no real fix date are listed without a duration (see “How each feed is read”).'

  const first = b.page * PAGE + 1
  const last = Math.min(total, b.page * PAGE + rows.length)

  return (
    <Section id="browse" title="Browse the CVEs behind the charts"
      lede="Every CVE a distribution fixed or still lists, one row each. Select a bar in a chart above to open its CVEs here, or filter directly. The filters at the top of the page apply here too."
      tools={!isDefaultBrowse(b) ? <button type="button" className="btn" onClick={reset}>Reset list filters</button> : undefined}>
      <div className="browse-controls" role="group" aria-label="List filters">
        <span className="seg" role="group" aria-label="Status">
          <button type="button" aria-pressed={fixed} onClick={() => setStatus('fixed')}>Fixed</button>
          <button type="button" aria-pressed={!fixed} onClick={() => setStatus('open')}>Still open</button>
        </span>
        <label>
          <span className="sr-only">Distribution</span>
          <select className="select" value={distro} disabled={selected.length < 2} onChange={e => set({ distro: e.target.value })}>
            <option value="">{selected.length === 1 ? name(selected[0]) : 'Every selected distribution'}</option>
            {selected.length > 1 && selected.map(id => <option key={id} value={id}>{name(id)}</option>)}
          </select>
        </label>
        <label>
          <span className="sr-only">Severity</span>
          <select className="select" value={severity} disabled={sevLocked} title={sevLocked ? 'Set by the severity filter at the top of the page' : undefined} onChange={e => set({ severity: e.target.value })}>
            <option value="all">All severities</option>
            {severities.map(s => <option key={s} value={s}>{severityLabel[s]}</option>)}
          </select>
        </label>
        {b.undated
          ? <button type="button" className="tag" onClick={() => set({ undated: false })} title="Remove this filter">No CVE publication date<span aria-hidden>×</span></button>
          : (
            <span className="days-range">
              <label>at least <DebouncedInput type="number" inputMode="decimal" className="input num" value={b.min} onCommit={v => set({ min: v })} aria-label={`Minimum days ${span}`} placeholder="any" /></label>
              <label>and under <DebouncedInput type="number" inputMode="decimal" className="input num" value={b.max} onCommit={v => set({ max: v })} aria-label={`Maximum days ${span}`} placeholder="any" /> days {span}</label>
            </span>
          )}
        {fixed && b.month && (
          <button type="button" className="tag" onClick={() => set({ month: '' })} title="Remove this filter">
            {f.basis === 'cve_month' ? 'CVE published' : 'Fixed'} in {monthLabel(b.month)}<span aria-hidden>×</span>
          </button>
        )}
        <label className="grow">
          <span className="sr-only">Search by CVE ID or package name</span>
          <DebouncedInput type="search" className="input" value={b.q} onCommit={v => set({ q: v })} placeholder="CVE ID or package name" />
        </label>
      </div>

      {rangeBad && <p className="error">The lower bound must be below the upper bound.</p>}
      {error && <p className="error">Could not load the list: {error}</p>}
      <p className="browse-summary" aria-live="polite">
        <b>{int(total)}</b> {noun}<span> · {scope.join(' · ')}</span>
        <small>{caveat}</small>
      </p>

      <div className={`table-wrap browse-table${loading ? ' loading' : ''}`}>
        <table className="data">
          <caption className="sr-only">{noun}, {scope.join(', ')}</caption>
          <thead>
            <tr>
              {cols.map(c => (
                <th key={c.key} scope="col" className={c.num ? 'num' : ''}
                  aria-sort={c.sort ? (sort === c.sort ? (b.dir === 'asc' ? 'ascending' : 'descending') : 'none') : undefined}>
                  {c.sort
                    ? <button type="button" className="th-sort" onClick={() => sortBy(c.sort!)} title={`Sort by ${c.label.toLowerCase()}`}>{c.label}<span aria-hidden>{sort === c.sort ? (b.dir === 'asc' ? '▲' : '▼') : ''}</span></button>
                    : c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(r => {
              const k = rowKey(r)
              const expanded = openKey === k
              const names = r.package_names ?? []
              return (
                <Fragment key={k}>
                  <tr className={expanded ? 'expanded' : undefined}>
                    <td><span className="dname" style={{ ['--c' as string]: distroColor(r.distro) }}><i />{name(r.distro)}</span></td>
                    <td><button type="button" className="link" aria-expanded={expanded} onClick={() => setOpenKey(expanded ? null : k)} title="Show this CVE across every distribution">{r.cve_id}</button></td>
                    <td><span className={`sev ${r.severity}`}>{severityLabel[r.severity] ?? r.severity}{r.cvss_score != null ? ` ${r.cvss_score}` : ''}</span></td>
                    <td>{date(r.cve_published)}</td>
                    {fixed && <td>{date(r.fix_time)}</td>}
                    <td className="num">{r.days != null ? days(r.days) : <span title={fixed ? "This record's date is not a remediation date" : 'The CVE has no publication date'}>–</span>}</td>
                    {byPackage
                      ? <><td>{r.ecosystem}</td><td>{r.package}</td></>
                      : <td>
                          <span className="clip" title={names.length < r.packages ? `${names.join(', ')} and ${int(r.packages - names.length)} more` : names.join(', ')}>
                            {names.join(', ')}{r.packages > names.length && <span className="more"> +{int(r.packages - names.length)}</span>}
                          </span>
                        </td>}
                    <td>{r.advisory_id}</td>
                  </tr>
                  {expanded && <tr className="detail-row"><td colSpan={cols.length}><CveDetailRow id={r.cve_id} distros={distros} /></td></tr>}
                </Fragment>
              )
            })}
            {rows.length === 0 && !loading && !error && !rangeBad && (
              <tr><td colSpan={cols.length} className="none">
                Nothing matches these filters.
                {fixed && (b.min !== '' || b.max !== '') && ' Only fixes with a real fix date have a duration, so feeds without one never match a days filter (see “How each feed is read”).'}
                {!fixed && ' Feeds that list shipped fixes only, such as Red Hat’s, have no open list.'}
              </td></tr>
            )}
            {rows.length === 0 && loading && <tr><td colSpan={cols.length} className="none">Loading…</td></tr>}
          </tbody>
        </table>
      </div>

      {total > 0 && (
        <div className="pager">
          <span>{int(first)} to {int(last)} of {int(total)}</span>
          <span className="spacer" />
          <button type="button" className="btn" disabled={b.page === 0 || loading} onClick={() => set({ page: b.page - 1 })}>Previous</button>
          <button type="button" className="btn" disabled={last >= total || loading} onClick={() => set({ page: b.page + 1 })}>Next</button>
        </div>
      )}
    </Section>
  )
}
