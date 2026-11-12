import { useMemo } from 'react'
import { DistroInfo, OpenRow, useGet } from '../api'
import { Filters, apiParams } from '../filters'
import { severities, severityColor, severityLabel } from '../palette'
import { int } from '../format'
import { Section } from './Section'
import { HBars } from '../charts/HBars'
import { Legend } from '../charts/Legend'
import { DataTable } from '../charts/DataTable'

const ageColors = ['var(--sev-low)', 'var(--sev-medium)', 'var(--sev-high)', 'var(--sev-critical)', 'var(--sev-unknown)']

export function BacklogSection({ f, distros, selected }: { f: Filters; distros: DistroInfo[]; selected: string[] }) {
  const p = apiParams(f, selected)
  const params = { distros: p.distros, severity: p.severity, ecosystem: p.ecosystem }
  const { data, loading, error } = useGet<{ rows: OpenRow[] }>('/api/v1/backlog', params)
  // A feed that only lists shipped errata (Red Hat's OSV) has no open state to show.
  const present = selected.filter(id => (data?.rows ?? []).some(r => r.distro === id))
  const absent = selected.filter(id => !present.includes(id)).map(id => distros.find(d => d.id === id)?.name ?? id)
  const names = present.map(id => distros.find(d => d.id === id)?.name ?? id)
  const ages = useMemo(() => {
    const a: string[] = []
    for (const r of data?.rows ?? []) a[r.order] = r.age
    return a.map((n, i) => ({ name: n, order: i })).filter(x => x.name)
  }, [data])
  const byAge = ages.map(a => ({
    key: String(a.order), label: a.name, color: ageColors[a.order] ?? 'var(--sev-unknown)',
    values: present.map(id => (data?.rows ?? []).filter(r => r.distro === id && r.order === a.order).reduce((s, r) => s + r.n, 0)),
  }))
  const sevs = [...severities].reverse()
  const bySev = sevs.map(s => ({
    key: s, label: severityLabel[s], color: severityColor(s),
    values: present.map(id => (data?.rows ?? []).filter(r => r.distro === id && r.severity === s).reduce((x, r) => x + r.n, 0)),
  })).filter(g => g.values.some(v => v > 0))
  const tableRows = (data?.rows ?? []).map(r => ({ distro: distros.find(d => d.id === r.distro)?.name ?? r.distro, severity: severityLabel[r.severity], age: r.age, n: r.n }))

  return (
    <Section id="backlog" title="Open CVEs right now"
      lede="CVEs each distribution lists as affecting a package with no fixed version yet, as of the last feed refresh. Age is counted from the CVE's publication. The date range above does not apply here."
      table={<DataTable caption="Open CVEs" rows={tableRows} columns={[{ key: 'distro', label: 'Distribution' }, { key: 'severity', label: 'Severity' }, { key: 'age', label: 'Age' }, { key: 'n', label: 'Open CVEs', num: true, format: v => int(v as number) }]} />}>
      {error && <p className="error">Could not load the backlog: {error}</p>}
      {absent.length > 0 && !loading && <p className="chart-sub" style={{ marginBottom: 12 }}>{absent.join(', ')}: the feed lists shipped fixes only, so there is no open list to count.</p>}
      <div className="grid-two">
        <div className={`chart${loading ? ' loading' : ''}`}>
          <p className="chart-title">By age since CVE publication</p>
          <p className="chart-sub">Older open CVEs sit to the right of each bar.</p>
          <HBars title="Open CVEs by age" categories={names} groups={byAge} mode="stacked" />
          <Legend items={byAge.map(g => ({ label: g.label, color: g.color }))} />
        </div>
        <div className={`chart${loading ? ' loading' : ''}`}>
          <p className="chart-title">By severity</p>
          <p className="chart-sub">{f.severity === 'all' ? 'Every severity, darkest is critical.' : `Only ${severityLabel[f.severity].toLowerCase()} CVEs, per the filter.`}</p>
          <HBars title="Open CVEs by severity" categories={names} groups={bySev} mode="stacked" />
          <Legend items={bySev.map(g => ({ label: g.label, color: g.color }))} />
        </div>
      </div>
    </Section>
  )
}
