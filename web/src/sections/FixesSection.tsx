import { useMemo, useState } from 'react'
import { DistroInfo, MonthlyFix, useGet } from '../api'
import { Filters, apiParams } from '../filters'
import { severities, severityColor, severityLabel } from '../palette'
import { int, monthLabel, monthsBetween } from '../format'
import { Section } from './Section'
import { StackedColumns } from '../charts/StackedColumns'
import { Legend } from '../charts/Legend'
import { DataTable } from '../charts/DataTable'

export function FixesSection({ f, distros, selected }: { f: Filters; distros: DistroInfo[]; selected: string[] }) {
  const params = apiParams(f, selected)
  const { data, loading, error } = useGet<{ rows: MonthlyFix[] }>('/api/v1/fixes/monthly', params)
  const [sameScale, setSameScale] = useState(false)
  const months = useMemo(() => monthsBetween(f.from, f.to), [f.from, f.to])
  const sevs = f.severity === 'all' ? [...severities].reverse() : [f.severity]
  const series = sevs.map(s => ({ key: s, label: severityLabel[s], color: severityColor(s) }))

  const perDistro = useMemo(() => {
    const out: Record<string, Record<string, Record<string, number>>> = {}
    for (const r of data?.rows ?? []) ((out[r.distro] ??= {})[r.month] ??= {})[r.severity] = r.fixes
    return out
  }, [data])
  const globalMax = useMemo(() => {
    let m = 0
    for (const d of Object.values(perDistro)) for (const mo of Object.values(d)) m = Math.max(m, Object.values(mo).reduce((a, b) => a + b, 0))
    return m
  }, [perDistro])

  const unitWord = f.unit === 'cve' ? 'CVEs fixed' : 'package fixes'
  const tableRows = (data?.rows ?? []).map(r => ({ distro: distros.find(d => d.id === r.distro)?.name ?? r.distro, month: monthLabel(r.month), severity: severityLabel[r.severity], fixes: r.fixes }))

  return (
    <Section id="fixes" title={`${f.unit === 'cve' ? 'CVEs fixed' : 'Package fixes shipped'} per month, by severity`}
      lede={f.basis === 'fix_month'
        ? `How many  each distribution shipped in each month, split by the CVE's own CVSS rating (the distribution's rating when cve.org has none). Only advisories with a real fix date are placed here; switch to "By CVE month" to include tracker-only fixes.`
        : `${unitWord[0].toUpperCase() + unitWord.slice(1)}, placed in the month the CVE was published rather than the month the fix shipped.`}
      tools={<button type="button" className="btn" aria-pressed={sameScale} onClick={() => setSameScale(s => !s)}>Same scale</button>}
      table={<DataTable caption="Fixes per month by severity" rows={tableRows} columns={[{ key: 'distro', label: 'Distribution' }, { key: 'month', label: 'Month' }, { key: 'severity', label: 'Severity' }, { key: 'fixes', label: 'Fixes', num: true, format: v => int(v as number) }]} />}>
      {error && <p className="error">Could not load fixes: {error}</p>}
      <Legend items={series.map(s => ({ label: s.label, color: s.color }))} />
      <div className="grid-multiples">
        {selected.map(id => {
          const d = distros.find(x => x.id === id)
          const total = Object.values(perDistro[id] ?? {}).reduce((a, mo) => a + Object.values(mo).reduce((x, y) => x + y, 0), 0)
          return (
            <div key={id} className={`chart${loading ? ' loading' : ''}`}>
              <p className="chart-title">{d?.name ?? id}</p>
              <p className="chart-sub">{int(total)} {unitWord} in range</p>
              {total === 0 && !loading
                ? <p className="empty-note">{f.basis === 'fix_month' ? 'No advisories with a dated fix in this range. Switch to "By CVE month" to count tracker-only fixes.' : 'No fixes in this range.'}</p>
                : <StackedColumns title={`${d?.name ?? id} fixes per month`} months={months} series={series} values={perDistro[id] ?? {}} maxY={sameScale ? globalMax : undefined} />}
            </div>
          )
        })}
      </div>
    </Section>
  )
}
