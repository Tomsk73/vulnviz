import { useMemo } from 'react'
import { CVEMonth, useGet } from '../api'
import { Filters } from '../filters'
import { severities, severityColor, severityLabel } from '../palette'
import { int, monthLabel, monthsBetween } from '../format'
import { Section } from './Section'
import { StackedColumns } from '../charts/StackedColumns'
import { Legend } from '../charts/Legend'
import { DataTable } from '../charts/DataTable'

export function CveFlowSection({ f }: { f: Filters }) {
  const { data, loading, error } = useGet<{ rows: CVEMonth[] }>('/api/v1/cves/monthly', { from: f.from, to: f.to })
  const months = useMemo(() => monthsBetween(f.from, f.to), [f.from, f.to])
  const sevs = [...severities].reverse()
  const series = sevs.map(s => ({ key: s, label: severityLabel[s], color: severityColor(s) }))
  const values = useMemo(() => {
    const out: Record<string, Record<string, number>> = {}
    for (const r of data?.rows ?? []) if (r.severity !== 'all') (out[r.month] ??= {})[r.severity] = r.cves
    return out
  }, [data])
  const total = (data?.rows ?? []).filter(r => r.severity === 'all').reduce((s, r) => s + r.cves, 0)
  const tableRows = (data?.rows ?? []).filter(r => r.severity !== 'all').map(r => ({ month: monthLabel(r.month), severity: severityLabel[r.severity], cves: r.cves }))

  return (
    <Section id="cves" title="CVEs published per month"
      lede="Everything published at cve.org in the range, by headline CVSS rating. This is the demand every distribution is working against; a rising unrated share usually means recent CVEs still waiting for a score."
      table={<DataTable caption="CVEs published per month" rows={tableRows} columns={[{ key: 'month', label: 'Month' }, { key: 'severity', label: 'Severity' }, { key: 'cves', label: 'CVEs', num: true, format: v => int(v as number) }]} />}>
      {error && <p className="error">Could not load CVE volume: {error}</p>}
      <div className={`chart${loading ? ' loading' : ''}`}>
        <p className="chart-title">{int(total)} CVEs published</p>
        <p className="chart-sub">Severity is the CNA's CVSS rating, falling back to CISA's enrichment.</p>
        <StackedColumns title="CVEs published per month" months={months} series={series} values={values} height={240} />
        <Legend items={series.map(s => ({ label: s.label, color: s.color }))} />
      </div>
    </Section>
  )
}
