import { useMemo } from 'react'
import { DistroInfo, MTTRPoint, useGet } from '../api'
import { Filters, apiParams } from '../filters'
import { distroColor, severityLabel } from '../palette'
import { days, int, monthLabel } from '../format'

export function Hero({ f, distros, selected }: { f: Filters; distros: DistroInfo[]; selected: string[] }) {
  const params = apiParams(f, selected)
  const { data, loading, error } = useGet<{ rows: MTTRPoint[] }>('/api/v1/mttr/summary', params)
  const rows = useMemo(() => {
    const want = f.severity === 'all' ? 'all' : f.severity
    const byDistro = new Map((data?.rows ?? []).filter(r => r.severity === want).map(r => [r.distro, r]))
    return selected.map(id => ({ id, name: distros.find(d => d.id === id)?.name ?? id, r: byDistro.get(id) }))
      .sort((a, b) => (a.r?.median ?? Infinity) - (b.r?.median ?? Infinity))
  }, [data, selected, distros, f.severity])
  // The scale follows the medians; a long tail is clipped at the right edge
  // rather than squashing every median into a sliver.
  const max = Math.max(1, ...rows.map(r => r.r?.median ?? 0)) * 1.2
  const pct = (v: number) => `${Math.min(100, (Math.max(0, v) / max) * 100)}%`
  const sevText = f.severity === 'all' ? 'a CVE' : `a ${severityLabel[f.severity].toLowerCase()} CVE`
  const eco = f.ecosystem.includes('|') ? f.ecosystem.split('|')[1] : ''
  const range = `${monthLabel(f.from)} to ${monthLabel(f.to)}`

  return (
    <section className="hero" aria-labelledby="hero-h">
      <h2 id="hero-h">Median days to fix {sevText} {f.scope === 'recent' ? 'published' : 'fixed'} {range}{eco ? `, ${eco}` : ''}</h2>
      <p className="lede">
        Days from the CVE's publication at cve.org to the first advisory that shipped a fix. The wide bar is the median; the thin bar
        reaches the 90th percentile and is cut off when the tail runs past the scale. Only advisories whose date is a real remediation
        date are timed{f.scope === 'recent' ? ', and only CVEs published inside the range count' : ', including fixes for CVEs published long before the range'}.
      </p>
      {error && <p className="error">Could not load the summary: {error}</p>}
      <div className="rank" style={loading ? { opacity: 0.55 } : undefined}>
        {rows.map(({ id, name, r }) => (
          <div key={id} style={{ display: 'contents' }}>
            <div className="name" style={{ ['--c' as string]: distroColor(id) }}><i />{name}<small>{r ? `${int(r.n)} timed fixes` : ''}</small></div>
            <div className="bar" style={{ ['--c' as string]: distroColor(id) }}>
              <span className="track" />
              {r && r.median != null ? (
                <>
                  {r.p90 != null && <span className="fill p90" style={{ width: pct(r.p90) }} aria-hidden />}
                  <span className="fill" style={{ width: pct(r.median) }} title={`median ${days(r.median)} days`} />
                  <span className="val">{days(r.median)}<small>days median</small>{r.p90 != null && <small>· p90 {days(r.p90, 0)}</small>}</span>
                </>
              ) : <span className="empty">No measurable fix times in this range</span>}
            </div>
          </div>
        ))}
      </div>
      <p className="rank-foot">Distributions whose feeds carry no fix timestamps show no bar; see "How each feed is read" below.</p>
    </section>
  )
}
