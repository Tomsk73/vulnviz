import { useMemo, useState } from 'react'
import { Bucket, DistroInfo, useGet } from '../api'
import { Filters, apiParams } from '../filters'
import { Drill, bucketRange } from '../browse'
import { distroColor } from '../palette'
import { int } from '../format'
import { Section } from './Section'
import { HBars } from '../charts/HBars'
import { Legend } from '../charts/Legend'
import { DataTable } from '../charts/DataTable'

export function DistributionSection({ f, distros, selected, onDrill }: { f: Filters; distros: DistroInfo[]; selected: string[]; onDrill: Drill }) {
  const params = apiParams(f, selected)
  const { data, loading, error } = useGet<{ rows: Bucket[] }>('/api/v1/mttr/distribution', params)
  const [percent, setPercent] = useState(true)
  const buckets = useMemo(() => {
    const seen: Bucket[] = []
    for (const r of data?.rows ?? []) seen[r.order] = r
    return seen.map((r, i) => ({ name: r?.bucket, order: i, range: r && bucketRange(r) })).filter(b => b.name)
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
        <p className="chart-sub">Select a bar to list the CVEs behind it.</p>
        {groups.length === 0 && !loading ? <p className="empty-note">No measurable fix times for this selection.</p>
          : <HBars title="Fix time distribution" categories={buckets.map(b => b.name)} groups={groups} mode="grouped" percent={percent}
              selectHint="Select to list these CVEs"
              onSelect={(c, g) => { if (g != null) onDrill({ status: 'fixed', distro: groups[g].key, ...buckets[c].range }) }} />}
        <Legend items={groups.map(g => ({ label: `${g.label} (${int(g.total)})`, color: g.color }))} />
      </div>
    </Section>
  )
}
