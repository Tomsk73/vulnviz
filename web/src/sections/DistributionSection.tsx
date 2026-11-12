import { useMemo, useState } from 'react'
import { Bucket, DistroInfo, useGet } from '../api'
import { Filters, apiParams } from '../filters'
import { distroColor } from '../palette'
import { int } from '../format'
import { Section } from './Section'
import { HBars } from '../charts/HBars'
import { Legend } from '../charts/Legend'
import { DataTable } from '../charts/DataTable'

export function DistributionSection({ f, distros, selected }: { f: Filters; distros: DistroInfo[]; selected: string[] }) {
  const params = apiParams(f, selected)
  const { data, loading, error } = useGet<{ rows: Bucket[] }>('/api/v1/mttr/distribution', params)
  const [percent, setPercent] = useState(true)
  const buckets = useMemo(() => {
    const names: string[] = []
    for (const r of data?.rows ?? []) names[r.order] = r.bucket
    return names.map((n, i) => ({ name: n, order: i })).filter(b => b.name)
  }, [data])
  const groups = useMemo(() => selected.map(id => {
    const rows = (data?.rows ?? []).filter(r => r.distro === id)
    const total = rows.reduce((s, r) => s + r.n, 0)
    return {
      key: id, label: distros.find(d => d.id === id)?.name ?? id, color: distroColor(id), total,
      values: buckets.map(b => { const n = rows.find(r => r.order === b.order)?.n ?? 0; return percent ? (total ? (n / total) * 100 : 0) : n }),
    }
  }).filter(g => g.total > 0), [data, selected, distros, buckets, percent])

  const tableRows = (data?.rows ?? []).map(r => ({ distro: distros.find(d => d.id === r.distro)?.name ?? r.distro, bucket: r.bucket, n: r.n }))

  return (
    <Section id="dist" title="How long fixes take"
      lede="Share of fixes in the range that shipped within each window after the CVE was published. A distribution that fixes most things in under a week has its weight on the left."
      tools={<span className="seg" role="group" aria-label="Scale"><button type="button" aria-pressed={percent} onClick={() => setPercent(true)}>Share</button><button type="button" aria-pressed={!percent} onClick={() => setPercent(false)}>Count</button></span>}
      table={<DataTable caption="Fix time distribution" rows={tableRows} columns={[{ key: 'distro', label: 'Distribution' }, { key: 'bucket', label: 'Time to fix' }, { key: 'n', label: 'Fixes', num: true, format: v => int(v as number) }]} />}>
      {error && <p className="error">Could not load the distribution: {error}</p>}
      <div className={`chart${loading ? ' loading' : ''}`}>
        {groups.length === 0 && !loading ? <p className="empty-note">No measurable fix times for this selection.</p>
          : <HBars title="Fix time distribution" categories={buckets.map(b => b.name)} groups={groups} mode="grouped" percent={percent} />}
        <Legend items={groups.map(g => ({ label: `${g.label} (${int(g.total)})`, color: g.color }))} />
      </div>
    </Section>
  )
}
