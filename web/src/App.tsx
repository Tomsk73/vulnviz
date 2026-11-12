import { useMemo } from 'react'
import { DistroInfo, useGet } from './api'
import { useFilters, useSelectedDistros } from './filters'
import { dateTime } from './format'
import { FilterBar } from './sections/FilterBar'
import { Hero } from './sections/Hero'
import { FixesSection } from './sections/FixesSection'
import { MttrSection } from './sections/MttrSection'
import { DistributionSection } from './sections/DistributionSection'
import { BacklogSection } from './sections/BacklogSection'
import { CveFlowSection } from './sections/CveFlowSection'
import { CveLookup } from './sections/CveLookup'
import { NotesSection } from './sections/NotesSection'

export default function App() {
  const [f, update] = useFilters()
  const { data: distrosRaw, error, asOf } = useGet<DistroInfo[]>('/api/v1/distros', {})
  // Only distributions with data take part; the config may list disabled ones.
  const distros = useMemo(() => (distrosRaw ?? []).filter(d => d.advisories > 0), [distrosRaw])
  const ids = useMemo(() => distros.map(d => d.id), [distros])
  const selected = useSelectedDistros(f, ids)

  return (
    <main className="page">
      <header className="masthead">
        <h1>vulnviz<span>Linux distribution remediation telemetry</span></h1>
        <div className="asof">{asOf ? <>Data as of <b>{dateTime(asOf)}</b></> : error ? <span className="error">API unavailable: {error}</span> : 'Loading…'}</div>
      </header>
      {distros.length > 0 && (
        <>
          <FilterBar f={f} update={update} distros={distros} />
          <Hero f={f} distros={distros} selected={selected} />
          <FixesSection f={f} distros={distros} selected={selected} />
          <MttrSection f={f} distros={distros} selected={selected} />
          <DistributionSection f={f} distros={distros} selected={selected} />
          <BacklogSection f={f} distros={distros} selected={selected} />
          <CveFlowSection f={f} />
          <CveLookup distros={distros} />
          <NotesSection distros={distros} />
        </>
      )}
      {distrosRaw && distros.length === 0 && (
        <p className="empty-note">No advisory data has been loaded yet. Run the ingest job, then reload this page.</p>
      )}
    </main>
  )
}
