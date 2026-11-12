import { useMemo, useState } from 'react'
import { DistroInfo, MTTRPoint, useGet } from '../api'
import { Filters, apiParams } from '../filters'
import { distroColor } from '../palette'
import { days, int, monthLabel, monthsBetween } from '../format'
import { Section } from './Section'
import { MultiLine } from '../charts/MultiLine'
import { Legend } from '../charts/Legend'
import { DataTable } from '../charts/DataTable'

const stats = [
  { key: 'median', label: 'Median' }, { key: 'p25', label: '25th percentile' }, { key: 'p75', label: '75th percentile' }, { key: 'p90', label: '90th percentile' }, { key: 'mean', label: 'Mean' },
] as const
type StatKey = typeof stats[number]['key']

export function MttrSection({ f, distros, selected }: { f: Filters; distros: DistroInfo[]; selected: string[] }) {
  const params = apiParams(f, selected)
  const { data, loading, error } = useGet<{ rows: MTTRPoint[] }>('/api/v1/mttr/monthly', params)
  const [stat, setStat] = useState<StatKey>('median')
  const [emphasis, setEmphasis] = useState<string | null>(null)
  const months = useMemo(() => monthsBetween(f.from, f.to), [f.from, f.to])
  const want = f.severity === 'all' ? 'all' : f.severity

  const series = useMemo(() => selected.map(id => {
    const points: Record<string, number | null> = {}
    const counts: Record<string, number> = {}
    for (const r of data?.rows ?? []) if (r.distro === id && r.severity === want && r.month) {
      // A percentile over one or two fixes is noise, not a trend; leave those months blank.
      points[r.month] = r.n >= 3 ? r[stat] : null
      counts[r.month] = r.n
    }
    return { key: id, label: distros.find(d => d.id === id)?.name ?? id, color: distroColor(id), points, counts }
  }).filter(s => Object.keys(s.points).length > 0), [data, selected, distros, stat, want])

  const tableRows = (data?.rows ?? []).filter(r => r.severity === want).map(r => ({
    distro: distros.find(d => d.id === r.distro)?.name ?? r.distro, month: monthLabel(r.month!), n: r.n, median: r.median, p25: r.p25, p75: r.p75, p90: r.p90, mean: r.mean,
  }))

  return (
    <Section id="mttr" title="Time to remediate, by month"
      lede={`Days between a CVE's publication and the first fix, for ${f.unit === 'cve' ? 'each CVE' : 'each package fix'} ${f.basis === 'fix_month' ? 'grouped by the month the fix shipped' : 'grouped by the month the CVE was published'}. Negative values mean the fix shipped before the CVE record did.`}
      tools={
        <>
          <select className="select" value={stat} onChange={e => setStat(e.target.value as StatKey)} aria-label="Statistic">
            {stats.map(s => <option key={s.key} value={s.key}>{s.label}</option>)}
          </select>
          <select className="select" value={emphasis ?? ''} onChange={e => setEmphasis(e.target.value || null)} aria-label="Highlight">
            <option value="">Highlight none</option>
            {series.map(s => <option key={s.key} value={s.key}>Highlight {s.label}</option>)}
          </select>
        </>
      }
      table={<DataTable caption="Time to remediate by month" rows={tableRows} columns={[
        { key: 'distro', label: 'Distribution' }, { key: 'month', label: 'Month' }, { key: 'n', label: 'Fixes', num: true, format: v => int(v as number) },
        { key: 'median', label: 'Median', num: true, format: v => days(v as number) }, { key: 'p25', label: 'p25', num: true, format: v => days(v as number) },
        { key: 'p75', label: 'p75', num: true, format: v => days(v as number) }, { key: 'p90', label: 'p90', num: true, format: v => days(v as number) }, { key: 'mean', label: 'Mean', num: true, format: v => days(v as number) }]} />}>
      {error && <p className="error">Could not load time to remediate: {error}</p>}
      <div className={`chart${loading ? ' loading' : ''}`}>
        <p className="chart-title">{stats.find(s => s.key === stat)?.label} days to fix</p>
        <p className="chart-sub">Hover a month to see every distribution and how many fixes the figure rests on. Months with fewer than three fixes are left blank.</p>
        {series.length === 0 && !loading ? <p className="empty-note">No measurable fix times for this selection.</p>
          : <MultiLine title="Time to remediate by month" months={months} series={series} format={v => days(v, 0)} unit="days" emphasis={emphasis} />}
        <Legend items={series.map(s => ({ label: s.label, color: s.color, line: true }))} />
      </div>
    </Section>
  )
}
