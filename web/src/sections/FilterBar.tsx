import { useMemo } from 'react'
import { DistroInfo, Ecosystem, useGet } from '../api'
import { Filters, presets } from '../filters'
import { distroColor, severities, severityLabel } from '../palette'
import { thisMonth, ymAdd } from '../format'

function EcosystemOptions({ distro }: { distro: DistroInfo }) {
  const { data } = useGet<Ecosystem[]>('/api/v1/ecosystems', { distro: distro.id })
  const list = useMemo(() => (data ?? []).filter(e => e.fixes >= 50).slice(0, 40), [data])
  if (!list.length) return null
  return (
    <optgroup label={distro.name}>
      {list.map(e => <option key={e.ecosystem} value={`${distro.id}|${e.ecosystem}`}>{e.ecosystem}</option>)}
    </optgroup>
  )
}

export function FilterBar({ f, update, distros }: { f: Filters; update: (p: Partial<Filters>) => void; distros: DistroInfo[] }) {
  const now = thisMonth()
  const preset = presets.find(p => f.to === now && f.from === ymAdd(now, -(p.months - 1)))?.id ?? 'custom'
  const ecoLocked = f.ecosystem.includes('|')
  const selected = f.distros.length ? f.distros : distros.map(d => d.id)

  const toggleDistro = (id: string) => {
    const next = selected.includes(id) ? selected.filter(d => d !== id) : [...selected, id]
    if (next.length === 0) return
    update({ distros: next.length === distros.length ? [] : next, ecosystem: '' })
  }

  return (
    <div className="filters" role="region" aria-label="Filters">
      <label>
        <span className="sr-only">Date range</span>
        <select className="select" value={preset} onChange={e => {
          const p = presets.find(x => x.id === e.target.value)
          if (p) update({ from: ymAdd(now, -(p.months - 1)), to: now })
        }}>
          {presets.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
          <option value="custom">Custom range</option>
        </select>
      </label>
      <label>from <input type="month" className="select" style={{ paddingRight: 10, backgroundImage: 'none' }} value={f.from} max={f.to} onChange={e => e.target.value && update({ from: e.target.value })} /></label>
      <label>to <input type="month" className="select" style={{ paddingRight: 10, backgroundImage: 'none' }} value={f.to} min={f.from} max={now} onChange={e => e.target.value && update({ to: e.target.value })} /></label>
      <span className="divider" />
      <span className="group" role="group" aria-label="Distributions">
        {distros.map(d => (
          <button key={d.id} type="button" className="chip" aria-pressed={selected.includes(d.id) && (!ecoLocked || f.ecosystem.startsWith(d.id + '|'))}
            style={{ ['--c' as string]: distroColor(d.id) }} onClick={() => toggleDistro(d.id)} disabled={ecoLocked}>
            <i />{d.name}
          </button>
        ))}
      </span>
      <span className="divider" />
      <label>
        <span className="sr-only">Severity</span>
        <select className="select" value={f.severity} onChange={e => update({ severity: e.target.value })}>
          <option value="all">All severities</option>
          {severities.map(s => <option key={s} value={s}>{severityLabel[s]}</option>)}
        </select>
      </label>
      <label>
        <span className="sr-only">Release</span>
        <select className="select" value={f.ecosystem} onChange={e => update({ ecosystem: e.target.value })}>
          <option value="">Every release</option>
          {distros.map(d => <EcosystemOptions key={d.id} distro={d} />)}
        </select>
      </label>
      <span className="spacer" />
      <span className="seg" role="group" aria-label="CVE scope">
        <button type="button" aria-pressed={f.scope === 'recent'} onClick={() => update({ scope: 'recent' })} title="Only CVEs published inside the date range">CVEs published in range</button>
        <button type="button" aria-pressed={f.scope === 'all'} onClick={() => update({ scope: 'all' })} title="Every CVE fixed in the range, however old">Any CVE age</button>
      </span>
      <span className="seg" role="group" aria-label="Count by">
        <button type="button" aria-pressed={f.unit === 'cve'} onClick={() => update({ unit: 'cve' })} title="One fix per CVE per distribution">CVEs</button>
        <button type="button" aria-pressed={f.unit === 'package'} onClick={() => update({ unit: 'package' })} title="One fix per CVE per package per release">Package fixes</button>
      </span>
      <span className="seg" role="group" aria-label="Month basis">
        <button type="button" aria-pressed={f.basis === 'fix_month'} onClick={() => update({ basis: 'fix_month' })} title="Group by the month the fix shipped">By fix month</button>
        <button type="button" aria-pressed={f.basis === 'cve_month'} onClick={() => update({ basis: 'cve_month' })} title="Group by the month the CVE was published">By CVE month</button>
      </span>
    </div>
  )
}
